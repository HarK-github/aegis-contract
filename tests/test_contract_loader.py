import json
import pytest
from src.edge.contract_loader import compile_contract_from_yaml

CONTRACT_PATH = "contracts/finance/orders_v1.yaml"


@pytest.fixture
def compiled_contract():
    return compile_contract_from_yaml(CONTRACT_PATH)


def test_valid_payload_parsing(compiled_contract):
    payload = json.dumps({
        "event_id": "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11",
        "tenant_id": "org_a912bc01",
        "customer_id": 10042,
        "amount_cents": 5999,
        "currency": "USD",
        "event_timestamp": "2026-11-17T12:00:00Z"
    }).encode("utf-8")

    is_valid, data, errors = compiled_contract.validate_bytes(payload)
    assert is_valid is True
    assert errors is None
    assert data["customer_id"] == 10042
    assert data["currency"] == "USD"
    # Verify ISO datetime parsed cleanly into string/iso format in model_dump
    assert "2026-11-17T12:00:00" in data["event_timestamp"]


def test_strict_mode_rejects_string_coercion(compiled_contract):
    payload = json.dumps({
        "event_id": "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11",
        "tenant_id": "org_a912bc01",
        "customer_id": "10042",  # String instead of integer
        "amount_cents": 5999,
        "currency": "USD",
        "event_timestamp": "2026-11-17T12:00:00Z"
    }).encode("utf-8")

    is_valid, data, errors = compiled_contract.validate_bytes(payload)
    assert is_valid is False
    assert errors is not None
    assert any(e["type"] == "int_type" for e in errors)


def test_extra_field_forbidden(compiled_contract):
    payload = json.dumps({
        "event_id": "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11",
        "tenant_id": "org_a912bc01",
        "customer_id": 10042,
        "amount_cents": 5999,
        "currency": "USD",
        "event_timestamp": "2026-11-17T12:00:00Z",
        "rogue_field": "injected_data"
    }).encode("utf-8")

    is_valid, data, errors = compiled_contract.validate_bytes(payload)
    assert is_valid is False
    assert any(e["type"] == "extra_forbidden" for e in errors)


def test_invalid_enum_rejected(compiled_contract):
    payload = json.dumps({
        "event_id": "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11",
        "tenant_id": "org_a912bc01",
        "customer_id": 10042,
        "amount_cents": 5999,
        "currency": "BITCOIN",  # Not in ["USD", "EUR", "GBP", "INR"]
        "event_timestamp": "2026-11-17T12:00:00Z"
    }).encode("utf-8")

    is_valid, data, errors = compiled_contract.validate_bytes(payload)
    assert is_valid is False
    assert any(e["type"] == "literal_error" for e in errors)


def test_negative_amount_rejected(compiled_contract):
    payload = json.dumps({
        "event_id": "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11",
        "tenant_id": "org_a912bc01",
        "customer_id": 10042,
        "amount_cents": -500,  # Below minimum 1
        "currency": "USD",
        "event_timestamp": "2026-11-17T12:00:00Z"
    }).encode("utf-8")

    is_valid, data, errors = compiled_contract.validate_bytes(payload)
    assert is_valid is False
    assert any(e["type"] == "greater_than_equal" for e in errors)
