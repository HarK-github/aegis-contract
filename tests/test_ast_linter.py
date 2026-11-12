import pytest
from src.warehouse.ast_linter import SQLContractLinter

CATALOG = {
    "raw_orders": {
        "order_id": "STRING",
        "tenant_id": "STRING",
        "amount_cents": "INT64",
        "created_at": "TIMESTAMP"
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


def test_valid_cte_query_passes(linter):
    sql = """
    WITH staged AS (
        SELECT 
            order_id,
            tenant_id,
            amount_cents / 100.0 AS gross_revenue,
            created_at AS order_timestamp
        FROM raw_orders
    )
    SELECT 
        s.order_id,
        s.tenant_id,
        s.gross_revenue,
        s.order_timestamp
    FROM staged s
    """
    violations = linter.lint_query(sql, EXPECTED_CONTRACT, model_name="fct_orders.sql")
    assert len(violations) == 0, f"Expected 0 violations, got: {violations}"


def test_prohibits_raw_star_wildcard(linter):
    sql = "SELECT * FROM raw_orders"
    violations = linter.lint_query(sql, EXPECTED_CONTRACT, model_name="bad_star.sql")
    assert any("Wildcard projection" in v for v in violations)


def test_prohibits_qualified_star_wildcard(linter):
    sql = "SELECT t.* FROM raw_orders t"
    violations = linter.lint_query(sql, EXPECTED_CONTRACT, model_name="bad_qualified_star.sql")
    assert any("Wildcard projection" in v for v in violations)


def test_catches_missing_contract_column(linter):
    # Forgot gross_revenue
    sql = """
    SELECT 
        order_id,
        tenant_id,
        created_at AS order_timestamp
    FROM raw_orders
    """
    violations = linter.lint_query(sql, EXPECTED_CONTRACT, model_name="missing_col.sql")
    assert any("Missing declared column 'gross_revenue'" in v for v in violations)


def test_catches_type_mismatch(linter):
    # Cast order_id as INT64 instead of STRING
    sql = """
    SELECT 
        CAST(12345 AS INT64) AS order_id,
        tenant_id,
        amount_cents / 100.0 AS gross_revenue,
        created_at AS order_timestamp
    FROM raw_orders
    """
    violations = linter.lint_query(sql, EXPECTED_CONTRACT, model_name="type_mismatch.sql")
    assert any("Type Mismatch on 'order_id'" in v for v in violations)


def test_parses_dbt_jinja_macros(linter):
    # Uses real dbt {{ ref('raw_orders') }} macro
    sql = """
    {{ config(materialized='table') }}

    WITH source_data AS (
        SELECT 
            order_id,
            tenant_id,
            amount_cents / 100.0 AS gross_revenue,
            created_at AS order_timestamp
        FROM {{ ref('raw_orders') }}
    )
    SELECT 
        sd.order_id,
        sd.tenant_id,
        sd.gross_revenue,
        sd.order_timestamp
    FROM source_data sd
    """
    violations = linter.lint_query(sql, EXPECTED_CONTRACT, model_name="dbt_model.sql")
    assert len(violations) == 0, f"Expected clean pass on dbt model, got: {violations}"
