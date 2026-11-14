import yaml
import pytest
from src.warehouse.diff_engine import compare_contracts


def load_yaml(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def test_additive_change_classified_as_minor():
    v1 = load_yaml("contracts/finance/orders_v1.yaml")
    v1_1 = load_yaml("contracts/finance/orders_v1_1_additive.yaml")

    diff = compare_contracts(v1, v1_1)
    assert diff.bump_type == "MINOR"
    assert diff.is_breaking_for_producer is False
    assert diff.is_breaking_for_consumer is False
    assert any("discount_code" in r for r in diff.producer_additive_reasons)

    # Check markdown rendering
    md = diff.to_markdown_report()
    assert "MINOR ADDITIVE" in md
    assert "discount_code" in md


def test_breaking_change_classified_as_major():
    v1 = load_yaml("contracts/finance/orders_v1.yaml")
    v2 = load_yaml("contracts/finance/orders_v2_breaking.yaml")

    diff = compare_contracts(v1, v2)
    assert diff.bump_type == "MAJOR"
    assert diff.is_breaking_for_producer is True
    assert diff.is_breaking_for_consumer is True
    assert any("currency" in r for r in diff.producer_breaking_reasons)

    md = diff.to_markdown_report()
    assert "MAJOR BREAKING CHANGE" in md
