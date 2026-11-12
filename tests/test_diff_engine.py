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
    assert diff.is_breaking is False
    assert len(diff.breaking_reasons) == 0
    assert any("discount_code" in r for r in diff.additive_reasons)

    # Check markdown rendering
    md = diff.to_markdown_report()
    assert "ADDITIVE CHANGE" in md
    assert "discount_code" in md


def test_breaking_change_classified_as_major():
    v1 = load_yaml("contracts/finance/orders_v1.yaml")
    v2 = load_yaml("contracts/finance/orders_v2_breaking.yaml")

    diff = compare_contracts(v1, v2)
    assert diff.bump_type == "MAJOR"
    assert diff.is_breaking is True
    assert len(diff.breaking_reasons) >= 1
    # Check that deleted currency field or changed amount is captured
    assert any("currency" in r for r in diff.breaking_reasons)

    md = diff.to_markdown_report()
    assert "BREAKING CHANGE" in md
