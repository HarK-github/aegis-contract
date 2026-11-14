import os
import json
import pytest
from pathlib import Path
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from src.edge.gateway import app, CONTRACT_REGISTRY, load_contracts_from_directory
from src.edge.contract_loader import compile_contract_from_dict, compile_contract_from_yaml
from src.edge.dlq_router import QuarantineDLQRouter
from src.edge.replay import DLQReplayWorker, ReplayStateStore


@pytest.fixture
def clean_client():
    load_contracts_from_directory("contracts")
    return TestClient(app)


def test_dlq_and_response_strip_input_and_ctx(clean_client, tmp_path, monkeypatch):
    """0.1 Verifies input and ctx are completely stripped from both HTTP 202 response and DLQ record."""
    sensitive_token = "secret_raw_token_that_must_not_leak"
    payload = {
        "event_id": "c73a21b3-a270-4e62-b10a-05b07254856a",
        "tenant_id": "org_a912bc01",
        "customer_id": sensitive_token,  # Invalid: string instead of int
        "amount_cents": 12500,
        "currency": "USD",
        "event_timestamp": "2026-11-17T14:30:00Z"
    }

    resp = clean_client.post(
        "/ingest/contracts.finance.orders",
        content=json.dumps(payload),
        headers={"Content-Type": "application/json"}
    )
    assert resp.status_code == 202
    data = resp.json()
    assert "errors" in data
    # Verify HTTP 202 body errors do not contain 'input' or 'ctx'
    for err in data["errors"]:
        assert "input" not in err, f"Found leaked 'input' in HTTP response: {err}"
        assert "ctx" not in err, f"Found leaked 'ctx' in HTTP response: {err}"

    # Verify DLQ record does not contain 'input' or 'ctx' in validation_errors
    import src.edge.gateway as gw
    records = gw.DLQ_ROUTER.read_quarantined_records()
    assert len(records) > 0
    latest_record = records[-1]
    for err in latest_record["validation_errors"]:
        assert "input" not in err, f"Found leaked 'input' in DLQ record: {err}"
        assert "ctx" not in err, f"Found leaked 'ctx' in DLQ record: {err}"


def test_dlq_encrypts_replay_payload_with_fernet(clean_client, monkeypatch):
    """0.1 Verifies replay payload is encrypted with Fernet using AEGIS_REPLAY_KEY."""
    test_key = Fernet.generate_key().decode()
    monkeypatch.setenv("AEGIS_REPLAY_KEY", test_key)

    raw_payload = {
        "event_id": "c73a21b3-a270-4e62-b10a-05b07254856a",
        "tenant_id": "org_a912bc01",
        "customer_id": "NOT_AN_INT",
        "amount_cents": 500,
        "currency": "USD",
        "event_timestamp": "2026-11-17T14:30:00Z"
    }
    raw_bytes = json.dumps(raw_payload).encode("utf-8")

    resp = clean_client.post(
        "/ingest/contracts.finance.orders",
        content=raw_bytes,
        headers={"Content-Type": "application/json"}
    )
    assert resp.status_code == 202

    import src.edge.gateway as gw
    records = gw.DLQ_ROUTER.read_quarantined_records()
    latest_record = records[-1]
    assert "replay_payload_enc" in latest_record
    encrypted_token = latest_record["replay_payload_enc"]

    # Decrypt with correct key
    f = Fernet(test_key.encode("utf-8"))
    decrypted_bytes = f.decrypt(encrypted_token.encode("ascii"))
    assert decrypted_bytes == raw_bytes

    # Assert decryption fails with wrong key
    wrong_key = Fernet.generate_key()
    f_wrong = Fernet(wrong_key)
    with pytest.raises(Exception):
        f_wrong.decrypt(encrypted_token.encode("ascii"))


def test_gateway_startup_fails_if_replay_key_missing(monkeypatch):
    """0.1 Gateway startup fails when AEGIS_REPLAY_KEY is missing."""
    monkeypatch.delenv("AEGIS_REPLAY_KEY", raising=False)
    with pytest.raises(RuntimeError, match="AEGIS_REPLAY_KEY environment variable is required"):
        with TestClient(app):
            pass


def test_gateway_startup_fails_closed_if_hmac_or_salt_missing(monkeypatch):
    """0.2 Gateway fails closed if AEGIS_HMAC_SECRET or AEGIS_PAYLOAD_SALT is missing unless auth is disabled."""
    monkeypatch.setenv("AEGIS_AUTH_DISABLED", "0")
    monkeypatch.delenv("AEGIS_HMAC_SECRET", raising=False)
    monkeypatch.delenv("AEGIS_PAYLOAD_SALT", raising=False)

    with pytest.raises(RuntimeError, match="AEGIS_HMAC_SECRET is required"):
        with TestClient(app):
            pass

    monkeypatch.setenv("AEGIS_HMAC_SECRET", "test_secret")
    with pytest.raises(RuntimeError, match="AEGIS_PAYLOAD_SALT is required"):
        with TestClient(app):
            pass


def test_version_explicitly_requested_missing_returns_404(clean_client):
    """0.3 When version is explicitly requested and missing, return 404 (no silent fallback)."""
    payload = json.dumps({
        "event_id": "c73a21b3-a270-4e62-b10a-05b07254856a",
        "tenant_id": "org_a912bc01",
        "customer_id": 9921,
        "amount_cents": 12500,
        "currency": "USD",
        "event_timestamp": "2026-11-17T14:30:00Z"
    })

    # Query param missing version
    resp1 = clean_client.post(
        "/ingest/contracts.finance.orders?version=99.9.9",
        content=payload,
        headers={"Content-Type": "application/json"}
    )
    assert resp1.status_code == 404
    assert "not found" in resp1.json()["error"].lower()

    # Header missing version
    resp2 = clean_client.post(
        "/ingest/contracts.finance.orders",
        content=payload,
        headers={"Content-Type": "application/json", "X-Contract-Version": "88.8.8"}
    )
    assert resp2.status_code == 404
    assert "not found" in resp2.json()["error"].lower()


def test_contract_loader_rejects_unknown_type_and_unsupported_keywords():
    """0.4 Contract loader raises ValueError on unknown types or unsupported keywords."""
    # 1. Unknown type
    spec_unknown_type = {
        "contract_id": "test.unknown_type",
        "edge_schema": {
            "type": "object",
            "properties": {
                "field_a": {"type": "unknown_blob"}
            }
        }
    }
    with pytest.raises(ValueError, match="Unknown or unsupported property type 'unknown_blob'"):
        compile_contract_from_dict(spec_unknown_type)

    # 2. Unsupported keyword maxLength
    spec_max_length = {
        "contract_id": "test.unsupported_keyword",
        "edge_schema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "maxLength": 50}
            }
        }
    }
    with pytest.raises(ValueError, match="Unsupported keyword.*maxLength"):
        compile_contract_from_dict(spec_max_length)

    # 3. Unsupported keyword minLength
    spec_min_length = {
        "contract_id": "test.unsupported_keyword2",
        "edge_schema": {
            "type": "object",
            "properties": {
                "code": {"type": "string", "minLength": 5}
            }
        }
    }
    with pytest.raises(ValueError, match="Unsupported keyword.*minLength"):
        compile_contract_from_dict(spec_min_length)

    # 4. Unsupported keyword exclusiveMinimum
    spec_exclusive_min = {
        "contract_id": "test.unsupported_keyword3",
        "edge_schema": {
            "type": "object",
            "properties": {
                "count": {"type": "integer", "exclusiveMinimum": 0}
            }
        }
    }
    with pytest.raises(ValueError, match="Unsupported keyword.*exclusiveMinimum"):
        compile_contract_from_dict(spec_exclusive_min)


def test_end_to_end_replay_workflow(clean_client, tmp_path, monkeypatch):
    """0.6 End-to-end replay: POST drifted event, read DLQ, decrypt, correct field, replay once (accepted), replay twice (skipped)."""
    replay_key = Fernet.generate_key().decode()
    monkeypatch.setenv("AEGIS_REPLAY_KEY", replay_key)

    import src.edge.gateway as gw
    contract = compile_contract_from_yaml("contracts/finance/orders_v1.yaml")

    # Step 1: POST drifted event (customer_id is invalid string)
    event_id = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
    drifted_payload = {
        "event_id": event_id,
        "tenant_id": "org_a912bc01",
        "customer_id": "INVALID_CUSTOMER_ID",
        "amount_cents": 8999,
        "currency": "USD",
        "event_timestamp": "2026-11-17T16:00:00Z"
    }
    resp = clean_client.post(
        "/ingest/contracts.finance.orders",
        content=json.dumps(drifted_payload),
        headers={"Content-Type": "application/json"}
    )
    assert resp.status_code == 202

    # Step 2: Read DLQ record
    records = gw.DLQ_ROUTER.read_quarantined_records("contracts.finance.orders")
    assert len(records) > 0
    target_record = next(r for r in reversed(records) if r.get("replay_payload_enc"))

    # Step 3: Decrypt replay payload
    fernet = Fernet(replay_key.encode("utf-8"))
    decrypted_raw = fernet.decrypt(target_record["replay_payload_enc"].encode("ascii"))
    payload_data = json.loads(decrypted_raw.decode("utf-8"))
    assert payload_data["event_id"] == event_id

    # Step 4: Correct field in payload and re-encrypt as a healed DLQ record
    payload_data["customer_id"] = 10042
    healed_raw_bytes = json.dumps(payload_data).encode("utf-8")
    healed_record = dict(target_record)
    healed_record["replay_payload_enc"] = fernet.encrypt(healed_raw_bytes).decode("ascii")

    # Step 5: Setup ReplayWorker
    replay_store_db = tmp_path / "replay_e2e_state.db"
    store = ReplayStateStore(db_path=str(replay_store_db))
    worker = DLQReplayWorker(state_store=store)

    sink_events = []
    def target_sink(event):
        sink_events.append(event)

    # Step 6: Replay once -> assert accepted
    res1 = worker.replay(
        dlq_records=[healed_record],
        contract_validator_fn=contract.validate_bytes,
        target_sink_fn=target_sink,
        dry_run=False
    )
    assert res1["healed"] == 1
    assert res1["skipped_duplicates"] == 0
    assert res1["still_failing"] == 0
    assert len(sink_events) == 1
    assert sink_events[0]["customer_id"] == 10042
    assert sink_events[0]["_replayed_metadata"]["is_replayed"] is True

    # Step 7: Replay second time -> assert skipped
    res2 = worker.replay(
        dlq_records=[healed_record],
        contract_validator_fn=contract.validate_bytes,
        target_sink_fn=target_sink,
        dry_run=False
    )
    assert res2["healed"] == 0
    assert res2["skipped_duplicates"] == 1
    assert len(sink_events) == 1  # No duplicate write
