import json
import hmac
import hashlib
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from src.edge.gateway import app, CONTRACT_REGISTRY, load_contracts_from_directory
from src.edge.dlq_router import QuarantineDLQRouter, mask_sensitive_data


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    # Ensure contracts are loaded
    load_contracts_from_directory("contracts")
    return TestClient(app)


def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "contracts.finance.orders" in data["loaded_contracts"]


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
    # Schema drift: customer_id is a string, and rogue field is included
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
    # Crucial enterprise ack semantic: 202 Accepted + quarantine DLQ tracking
    assert response.status_code == 202
    data = response.json()
    assert data["status"] == "quarantined"
    assert "dlq_id" in data
    assert data["dlq_id"].startswith("dlq_")
    assert len(data["errors"]) >= 1


def test_dlq_pii_masking():
    sensitive_payload = {
        "user_id": 123,
        "card_number": "4111-2222-3333-4444",
        "auth_token": "secret_token_12345",
        "nested": {
            "password": "super_secret_password",
            "normal_field": "visible_data"
        }
    }
    masked = mask_sensitive_data(sensitive_payload)
    assert masked["card_number"] == "******REDACTED******"
    assert masked["auth_token"] == "******REDACTED******"
    assert masked["nested"]["password"] == "******REDACTED******"
    assert masked["nested"]["normal_field"] == "visible_data"
