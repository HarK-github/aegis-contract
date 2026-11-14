import json
import hmac
import hashlib
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from src.edge.gateway import app, CONTRACT_REGISTRY, load_contracts_from_directory, verify_hmac_signature
from src.edge.dlq_router import QuarantineDLQRouter, mask_sensitive_data


@pytest.fixture(scope="module")
def client():
    load_contracts_from_directory("contracts")
    return TestClient(app)


def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert any("contracts.finance.orders" in c for c in data["loaded_contracts"])


def test_ingest_valid_event(client, tmp_path):
    payload = {
        "event_id": "c73a21b3-a270-4e62-b10a-05b07254856a",
        "tenant_id": "org_a912bc01",
        "customer_id": 9921,
        "amount_cents": 12500,
        "currency": "USD",
        "event_timestamp": "2026-11-17T14:30:00Z"
    }

    response = client.post(
        "/ingest/contracts.finance.orders",
        content=json.dumps(payload),
        headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "accepted"
    assert data["event_id"] == "c73a21b3-a270-4e62-b10a-05b07254856a"


def test_ingest_drifted_event_quarantined_202(client):
    drifted_payload = {
        "event_id": "c73a21b3-a270-4e62-b10a-05b07254856a",
        "tenant_id": "org_a912bc01",
        "customer_id": "CUST_9921",
        "amount_cents": 12500,
        "currency": "USD",
        "event_timestamp": "2026-11-17T14:30:00Z",
        "unannounced_field": "rogue_value"
    }

    response = client.post(
        "/ingest/contracts.finance.orders",
        content=json.dumps(drifted_payload),
        headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 202
    data = response.json()
    assert data["status"] == "quarantined"
    assert "dlq_id" in data
    assert data["dlq_id"].startswith("dlq_")
    assert len(data["errors"]) >= 1


def test_hmac_signature_verification_and_timing_safety(monkeypatch, client):
    """Verifies HMAC authentication: rejects missing or forged headers, passes valid digest."""
    test_secret = "test_shared_secret_key_2026"
    monkeypatch.setattr("src.edge.gateway.HMAC_SECRET", test_secret)

    payload = json.dumps({
        "event_id": "c73a21b3-a270-4e62-b10a-05b07254856a",
        "tenant_id": "org_a912bc01",
        "customer_id": 9921,
        "amount_cents": 12500,
        "currency": "USD",
        "event_timestamp": "2026-11-17T14:30:00Z"
    }).encode("utf-8")

    # 1. Missing HMAC header -> 401 Unauthorized
    resp_no_header = client.post(
        "/ingest/contracts.finance.orders",
        content=payload,
        headers={"Content-Type": "application/json"}
    )
    assert resp_no_header.status_code == 401

    # 2. Forged / Tampered HMAC header -> 401 Unauthorized
    resp_tampered = client.post(
        "/ingest/contracts.finance.orders",
        content=payload,
        headers={
            "Content-Type": "application/json",
            "X-Signature-SHA256": "sha256=0000000000000000000000000000000000000000000000000000000000000000"
        }
    )
    assert resp_tampered.status_code == 401

    # 3. Valid HMAC header -> 200 OK
    valid_digest = hmac.new(test_secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    resp_valid = client.post(
        "/ingest/contracts.finance.orders",
        content=payload,
        headers={
            "Content-Type": "application/json",
            "X-Signature-SHA256": f"sha256={valid_digest}"
        }
    )
    assert resp_valid.status_code == 200

    # 4. Direct timing-safe comparison verification
    assert verify_hmac_signature(payload, f"sha256={valid_digest}", test_secret) is True
    assert verify_hmac_signature(payload, "sha256=wrong", test_secret) is False
