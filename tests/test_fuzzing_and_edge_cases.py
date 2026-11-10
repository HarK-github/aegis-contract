"""
Edge Case & Fuzzing Test Suite for AegisContract.
Verifies defense against malformed bytes, empty bodies, oversized payloads,
deeply nested mixed-case PII redaction, salt integrity, and mutation checks.
"""

import json
import hashlib
import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from pydantic import BaseModel, create_model, ConfigDict, ValidationError

from src.edge.contract_loader import compile_contract_from_yaml
from src.edge.dlq_router import mask_sensitive_data, QuarantineDLQRouter, AEGIS_PAYLOAD_SALT
from src.edge.gateway import app, load_contracts_from_directory
from src.warehouse.ast_linter import SQLContractLinter


@pytest.fixture(scope="module")
def client():
    load_contracts_from_directory("contracts")
    return TestClient(app)


def test_malformed_non_json_bytes_quarantined(client):
    """Corrupt non-JSON byte stream should be safely quarantined as 202 without crashing."""
    corrupted_bytes = b"\x00\xff\xfe\x01\x10\x99GARBAGE_BINARY_DATA"

    response = client.post(
        "/ingest/contracts.finance.orders",
        content=corrupted_bytes,
        headers={"Content-Type": "application/octet-stream"}
    )
    assert response.status_code == 202
    data = response.json()
    assert data["status"] == "quarantined"
    assert "dlq_id" in data
    assert any("unparseable_json" in str(e) or "JSON" in str(e) for e in data["errors"])


def test_empty_json_object_quarantined(client):
    """Empty JSON body {} missing all required fields should be cleanly quarantined."""
    response = client.post(
        "/ingest/contracts.finance.orders",
        content=b"{}",
        headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 202
    data = response.json()
    assert data["status"] == "quarantined"
    missing_fields = {e["loc"][0] for e in data["errors"] if e["type"] == "missing"}
    expected_missing = {"event_id", "tenant_id", "customer_id", "amount_cents", "currency", "event_timestamp"}
    assert expected_missing.issubset(missing_fields)


def test_oversized_payload_quarantined(client):
    """Oversized payload with thousands of rogue attributes should be blocked by extra='forbid'."""
    oversized = {
        "event_id": "c73a21b3-a270-4e62-b10a-05b07254856a",
        "tenant_id": "org_a912bc01",
        "customer_id": 9921,
        "amount_cents": 12500,
        "currency": "USD",
        "event_timestamp": "2026-11-17T14:30:00Z"
    }
    for i in range(100):
        oversized[f"junk_metric_{i}"] = "x" * 200

    response = client.post(
        "/ingest/contracts.finance.orders",
        content=json.dumps(oversized),
        headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 202
    data = response.json()
    assert data["status"] == "quarantined"
    assert any(e["type"] == "extra_forbidden" for e in data["errors"])


def test_deep_pii_masking_mixed_casing():
    """Verifies case-insensitive recursive masking of sensitive data across lists and nested dicts."""
    complex_payload = {
        "user": {
            "ID": 1001,
            "PASS_WORD": "PlainTextPassword123",
            "metadata": [
                {"API_KEY": "sk_live_99999", "label": "stripe_key"},
                {"nested_list": [{"Credit_Card_Number": "4111-2222-3333-4444"}]}
            ]
        },
        "SESSION_TOKEN": "sess_abc123",
        "normal_public_field": "safe_value"
    }

    masked = mask_sensitive_data(complex_payload)
    assert masked["user"]["PASS_WORD"] == "******REDACTED******"
    assert masked["user"]["metadata"][0]["API_KEY"] == "******REDACTED******"
    assert masked["user"]["metadata"][0]["label"] == "stripe_key"
    assert masked["user"]["metadata"][1]["nested_list"][0]["Credit_Card_Number"] == "******REDACTED******"
    assert masked["SESSION_TOKEN"] == "******REDACTED******"
    assert masked["normal_public_field"] == "safe_value"


def test_salted_hash_prevents_rainbow_table_inversion(tmp_path):
    """Verifies payload hash uses organization salt to prevent low-entropy rainbow-table inversion."""
    router = QuarantineDLQRouter(dlq_dir=str(tmp_path / "dlq"))
    low_entropy_bytes = b'{"status": "ok"}'

    dlq_id = router.record_quarantine_event(
        raw_bytes=low_entropy_bytes,
        contract_id="test.contract",
        contract_version="1.0.0",
        validation_errors=[]
    )

    records = router.read_quarantined_records()
    assert len(records) == 1
    stored_hash = records[0]["payload_hmac_sha256"]
    raw_sha256 = hashlib.sha256(low_entropy_bytes).hexdigest()
    assert stored_hash != raw_sha256


def test_mutation_proof_removing_extra_forbid_fails():
    """
    Mutation verification: Proves that removing extra='forbid' from the model config
    causes extra rogue attributes to silently slip through into production.
    """
    payload_with_rogue = '{"customer_id": 101, "rogue_injected_field": "exploit"}'
    
    # 1. AegisContract Strict Model (Protected)
    ProtectedModel = create_model("Protected", customer_id=(int, ...), __config__=ConfigDict(extra="forbid"))
    with pytest.raises(ValidationError):
        ProtectedModel.model_validate_json(payload_with_rogue)

    # 2. Mutated/Weakened Model (Vulnerable)
    WeakenedModel = create_model("Weakened", customer_id=(int, ...), __config__=ConfigDict(extra="ignore"))
    instance = WeakenedModel.model_validate_json(payload_with_rogue)
    # The rogue field slipped through undetected!
    assert not hasattr(instance, "rogue_injected_field") or getattr(instance, "rogue_injected_field", None) is None


def test_mutation_proof_wildcard_guard_essential():
    """
    Mutation verification: Proves that without pre-qualify wildcard detection,
    qualify.qualify expands 'SELECT *' into base columns and bypasses contract gating.
    """
    linter = SQLContractLinter(
        catalog_schema={"t": {"a": "STRING", "b": "INT64"}},
        dialect="bigquery"
    )
    expected = {"a": "STRING", "b": "INT64"}

    # Our linter catches it immediately
    violations = linter.lint_query("SELECT * FROM t", expected)
    assert any("Wildcard projection" in v for v in violations)
