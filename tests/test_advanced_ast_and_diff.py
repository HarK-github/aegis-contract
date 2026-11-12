"""
Advanced SQL AST & Semantic Diff Engine Edge-Case Test Suite.
Verifies complex multi-CTE queries with JOINs, column shadowing,
multi-line dbt Jinja macros, and contract diff edge cases.
"""

import pytest
from src.warehouse.ast_linter import SQLContractLinter
from src.warehouse.diff_engine import compare_contracts

CATALOG = {
    "raw_orders": {
        "order_id": "STRING",
        "tenant_id": "STRING",
        "customer_id": "INT64",
        "amount_cents": "INT64",
        "created_at": "TIMESTAMP"
    },
    "raw_customers": {
        "id": "INT64",
        "tenant_id": "STRING",
        "email": "STRING",
        "signup_date": "DATE"
    }
}

EXPECTED_CONTRACT = {
    "order_id": "STRING",
    "tenant_id": "STRING",
    "gross_revenue": "NUMERIC",
    "order_timestamp": "TIMESTAMP"
}


@pytest.fixture
def linter():
    return SQLContractLinter(catalog_schema=CATALOG, dialect="bigquery")


def test_complex_multi_cte_with_joins_passes(linter):
    """Verifies that queries with multiple nested CTEs and explicit JOINs pass AST linting."""
    sql = """
    WITH filtered_customers AS (
        SELECT id, tenant_id, email
        FROM raw_customers
        WHERE signup_date >= '2024-01-01'
    ),
    enriched_orders AS (
        SELECT 
            o.order_id,
            o.tenant_id,
            o.amount_cents / 100.0 AS gross_revenue,
            o.created_at AS order_timestamp,
            c.email AS customer_email
        FROM raw_orders o
        INNER JOIN filtered_customers c 
            ON o.customer_id = c.id AND o.tenant_id = c.tenant_id
    )
    SELECT 
        eo.order_id,
        eo.tenant_id,
        eo.gross_revenue,
        eo.order_timestamp
    FROM enriched_orders eo
    """
    violations = linter.lint_query(sql, EXPECTED_CONTRACT, model_name="fct_enriched_orders.sql")
    assert len(violations) == 0, f"Expected 0 violations, got: {violations}"


def test_multiline_dbt_jinja_control_blocks_stripped(linter):
    """Verifies that multi-line Jinja control structures like {% set %} and {% if %} parse cleanly."""
    sql = """
    {{ config(materialized='incremental', unique_key='order_id') }}

    {% set lookback_days = 30 %}
    {% set tenant_filter = var('tenant', 'default_org') %}

    WITH staged_data AS (
        SELECT 
            order_id,
            tenant_id,
            amount_cents / 100.0 AS gross_revenue,
            created_at AS order_timestamp
        FROM {{ ref('raw_orders') }}
        WHERE created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {{ lookback_days }} DAY)
        {% if is_incremental() %}
            AND created_at > (SELECT MAX(order_timestamp) FROM {{ this }})
        {% endif %}
    )
    SELECT 
        order_id,
        tenant_id,
        gross_revenue,
        order_timestamp
    FROM staged_data
    """
    violations = linter.lint_query(sql, EXPECTED_CONTRACT, model_name="incremental_orders.sql")
    assert len(violations) == 0, f"Expected clean pass on complex Jinja dbt model, got: {violations}"


def test_diff_field_made_optional_is_additive():
    """Relaxing a required field to optional is an additive, non-breaking MINOR change."""
    old_spec = {
        "version": "1.0.0",
        "edge_schema": {
            "properties": {"user_id": {"type": "integer"}, "nickname": {"type": "string"}},
            "required": ["user_id", "nickname"]
        }
    }
    new_spec = {
        "version": "1.1.0",
        "edge_schema": {
            "properties": {"user_id": {"type": "integer"}, "nickname": {"type": "string"}},
            "required": ["user_id"]  # nickname is now OPTIONAL
        }
    }

    diff = compare_contracts(old_spec, new_spec)
    assert diff.bump_type == "MINOR"
    assert diff.is_breaking is False
    assert any("relaxed to OPTIONAL" in r for r in diff.additive_reasons)


def test_diff_enum_removal_is_breaking():
    """Removing an allowed value from an enum narrows input validity and is BREAKING (MAJOR)."""
    old_spec = {
        "version": "1.0.0",
        "edge_schema": {
            "properties": {
                "currency": {"type": "string", "enum": ["USD", "EUR", "GBP", "JPY"]}
            },
            "required": ["currency"]
        }
    }
    new_spec = {
        "version": "2.0.0",
        "edge_schema": {
            "properties": {
                "currency": {"type": "string", "enum": ["USD", "EUR"]}  # GBP and JPY removed!
            },
            "required": ["currency"]
        }
    }

    diff = compare_contracts(old_spec, new_spec)
    assert diff.bump_type == "MAJOR"
    assert diff.is_breaking is True
    assert any("removed allowed enum values" in r for r in diff.breaking_reasons)


def test_diff_enum_expansion_is_additive():
    """Adding an allowed value to an enum expands input validity and is ADDITIVE (MINOR)."""
    old_spec = {
        "version": "1.0.0",
        "edge_schema": {
            "properties": {
                "currency": {"type": "string", "enum": ["USD", "EUR"]}
            },
            "required": ["currency"]
        }
    }
    new_spec = {
        "version": "1.1.0",
        "edge_schema": {
            "properties": {
                "currency": {"type": "string", "enum": ["USD", "EUR", "CAD"]}  # CAD added!
            },
            "required": ["currency"]
        }
    }

    diff = compare_contracts(old_spec, new_spec)
    assert diff.bump_type == "MINOR"
    assert diff.is_breaking is False
    assert any("added new allowed enum values" in r for r in diff.additive_reasons)
