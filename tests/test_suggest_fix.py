"""
Tests for Phase 2: AI-Assisted SQL Fix Loop and Deterministic Verifier.
All tests run offline in REPLAY mode or with in-memory FakeClient.
"""

import json
import pytest
from pathlib import Path
from pydantic import ValidationError

from src.ai.llm import (
    LLMRequest,
    LLMFixResponse,
    DataMinimizationPayload,
    ReplayClient,
    MissingFixtureError
)
from src.ai.fix_loop import run_suggest_fix, verify_proposal, load_system_prompt
from src.warehouse.ast_linter import SQLContractLinter


class FakeSequenceClient:
    """Fake LLM client that returns responses in order for deterministic testing."""
    def __init__(self, responses: list[str]):
        self.responses = list(responses)
        self.calls = []

    def generate(self, request: LLMRequest) -> str:
        self.calls.append(request)
        if not self.responses:
            raise RuntimeError("No more fake responses configured")
        return self.responses.pop(0)


CONTRACT_PATH = Path("contracts/finance/orders_v1.yaml")
CATALOG_PATH = Path("demo/catalog.json")
BAD_SQL_PATH = Path("demo/sample_queries/bad_missing_col.sql")


def test_verified_fix_in_replay_mode():
    """2.6 Verifies successful fix verification in replay mode using recorded fixture."""
    client = ReplayClient(fixtures_dir="fixtures/llm")
    result = run_suggest_fix(
        sql_path=BAD_SQL_PATH,
        contract_path=CONTRACT_PATH,
        catalog_path=CATALOG_PATH,
        client=client
    )

    assert result["status"] == "verified"
    assert result["attempts"] == 1
    assert result["failed_checks"] == []
    assert result["fixed_sql"] is not None
    assert "gross_revenue" in result["fixed_sql"]
    assert result["unified_diff"] is not None
    assert "+    amount_cents / 100.0 AS gross_revenue" in result["unified_diff"]


def test_unparseable_response_fails_check_a():
    """2.6 Verifies unparseable LLM responses (markdown, malformed JSON) fail check 2.4(a)."""
    # LLM outputs markdown backticks or bad JSON
    bad_responses = [
        "```json\n{\"fixed_sql\": \"SELECT 1\"}\n```",
        "{\"fixed_sql\": \"SELECT 1\", \"extra_field\": \"forbidden\"}"  # extra="forbid"
    ]
    client = FakeSequenceClient(bad_responses)

    result = run_suggest_fix(
        sql_path=BAD_SQL_PATH,
        contract_path=CONTRACT_PATH,
        catalog_path=CATALOG_PATH,
        client=client,
        max_attempts=2
    )

    assert result["status"] == "unverified"
    assert result["attempts"] == 2
    assert "CHECK_2_4_A_SCHEMA_PARSE" in result["failed_checks"]
    assert result["fixed_sql"] is None
    assert result["unified_diff"] is None


def test_fix_that_deletes_ref_fails_check_c():
    """2.6 Verifies proposed fix that deletes a {{ ref() }} call fails check 2.4(c)."""
    # Create temp query with a ref()
    orig_sql_with_ref = """
    SELECT 
        order_id,
        tenant_id,
        created_at AS order_timestamp
    FROM {{ ref('raw_orders') }}
    """
    tmp_sql = Path("/tmp/test_ref_query.sql")
    tmp_sql.write_text(orig_sql_with_ref, encoding="utf-8")

    # Proposal replaces {{ ref('raw_orders') }} with raw_orders table directly (deleting ref!)
    proposed_sql_deleted_ref = """
    SELECT 
        order_id,
        tenant_id,
        amount_cents / 100.0 AS gross_revenue,
        created_at AS order_timestamp
    FROM raw_orders
    """
    client = FakeSequenceClient([
        json.dumps({"fixed_sql": proposed_sql_deleted_ref}),
        json.dumps({"fixed_sql": proposed_sql_deleted_ref})
    ])

    result = run_suggest_fix(
        sql_path=tmp_sql,
        contract_path=CONTRACT_PATH,
        catalog_path=CATALOG_PATH,
        client=client
    )

    assert result["status"] == "unverified"
    assert "CHECK_2_4_C_REF_SOURCE_MISMATCH" in result["failed_checks"]
    assert result["fixed_sql"] is None


def test_fix_that_adds_new_table_fails_check_d():
    """2.6 Verifies proposed fix that references an extra unexpected table fails check 2.4(d)."""
    # Proposal introduces rogue_table
    proposed_with_extra_table = """
    SELECT 
        r.order_id,
        r.tenant_id,
        r.amount_cents / 100.0 AS gross_revenue,
        r.created_at AS order_timestamp
    FROM raw_orders r
    JOIN unexpected_rogue_table u ON r.order_id = u.order_id
    """
    client = FakeSequenceClient([
        json.dumps({"fixed_sql": proposed_with_extra_table}),
        json.dumps({"fixed_sql": proposed_with_extra_table})
    ])

    result = run_suggest_fix(
        sql_path=BAD_SQL_PATH,
        contract_path=CONTRACT_PATH,
        catalog_path=CATALOG_PATH,
        client=client
    )

    assert result["status"] == "unverified"
    assert "CHECK_2_4_D_SOURCE_TABLES_MISMATCH" in result["failed_checks"]


def test_fix_that_exceeds_30_changed_lines_fails_check_e():
    """2.6 Verifies proposed fix that modifies > 30 lines fails check 2.4(e)."""
    # Add 35 lines of extra comments/padding to blow past 30 changed lines
    padding = "\n".join([f"    -- padding line {i}" for i in range(35)])
    huge_diff_sql = f"""SELECT 
    order_id,
    tenant_id,
    amount_cents / 100.0 AS gross_revenue,
    created_at AS order_timestamp,
{padding}
FROM raw_orders"""

    client = FakeSequenceClient([
        json.dumps({"fixed_sql": huge_diff_sql}),
        json.dumps({"fixed_sql": huge_diff_sql})
    ])

    result = run_suggest_fix(
        sql_path=BAD_SQL_PATH,
        contract_path=CONTRACT_PATH,
        catalog_path=CATALOG_PATH,
        client=client
    )

    assert result["status"] == "unverified"
    assert "CHECK_2_4_E_DIFF_EXCEEDS_30_LINES" in result["failed_checks"]


def test_fix_that_still_has_violations_fails_check_f():
    """2.6 Verifies proposed fix that fails to resolve contract violations fails check 2.4(f)."""
    # Proposes SQL that still misses gross_revenue
    still_broken_sql = """
    SELECT 
        order_id,
        tenant_id,
        'wrong_unannounced_field' AS rogue_field,
        created_at AS order_timestamp
    FROM raw_orders
    """
    client = FakeSequenceClient([
        json.dumps({"fixed_sql": still_broken_sql}),
        json.dumps({"fixed_sql": still_broken_sql})
    ])

    result = run_suggest_fix(
        sql_path=BAD_SQL_PATH,
        contract_path=CONTRACT_PATH,
        catalog_path=CATALOG_PATH,
        client=client
    )

    assert result["status"] == "unverified"
    assert "CHECK_2_4_F_LINTER_VIOLATIONS_REMAIN" in result["failed_checks"]


def test_second_attempt_succeeds():
    """2.6 Verifies that if attempt 1 fails check, attempt 2 can succeed."""
    # Attempt 1 has remaining violation; Attempt 2 provides full valid fix
    attempt1_sql = """
    SELECT 
        order_id,
        tenant_id,
        created_at AS order_timestamp
    FROM raw_orders
    """
    attempt2_sql = """
    SELECT 
        order_id,
        tenant_id,
        amount_cents / 100.0 AS gross_revenue,
        created_at AS order_timestamp
    FROM raw_orders
    """
    client = FakeSequenceClient([
        json.dumps({"fixed_sql": attempt1_sql}),
        json.dumps({"fixed_sql": attempt2_sql})
    ])

    result = run_suggest_fix(
        sql_path=BAD_SQL_PATH,
        contract_path=CONTRACT_PATH,
        catalog_path=CATALOG_PATH,
        client=client,
        max_attempts=2
    )

    assert result["status"] == "verified"
    assert result["attempts"] == 2
    assert "CHECK_2_4_F_LINTER_VIOLATIONS_REMAIN" in result["failed_checks"]
    assert result["fixed_sql"] is not None


def test_missing_fixture_error_path():
    """2.6 Verifies ReplayClient raises MissingFixtureError when fixture is absent."""
    client = ReplayClient(fixtures_dir="/tmp/empty_nonexistent_fixtures")
    req = LLMRequest(
        model_name="gemini-1.5-pro",
        prompt_version="v1",
        system="test",
        user="test"
    )

    with pytest.raises(MissingFixtureError, match="Missing LLM fixture"):
        client.generate(req)


def test_request_hash_stability():
    """2.6 Verifies identical request produces identical sha256 hash across two runs."""
    payload = DataMinimizationPayload(
        sql_text="SELECT 1",
        violations=[{"rule": "WILDCARD", "column": "*"}],
        contract_columns={"a": "STRING"},
        catalog={"t": {"a": "STRING"}}
    )

    req1 = LLMRequest(
        model_name="gemini-1.5-pro",
        prompt_version="v1",
        system="System prompt test",
        user=payload.to_canonical_json()
    )

    req2 = LLMRequest(
        model_name="gemini-1.5-pro",
        prompt_version="v1",
        system="System prompt test",
        user=payload.to_canonical_json()
    )

    assert req1.request_hash == req2.request_hash
    assert len(req1.request_hash) == 64


def test_data_minimization_enforcement():
    """2.3 Verifies only the 4 allowed fields can enter the LLM request; any extra is forbidden."""
    valid_data = {
        "sql_text": "SELECT *",
        "violations": [],
        "contract_columns": {"x": "STRING"},
        "catalog": {"tbl": {"x": "STRING"}}
    }
    payload = DataMinimizationPayload(**valid_data)
    assert payload.sql_text == "SELECT *"

    # Attempt to inject extra unauthorized fields (e.g. owner, contract_id, PII)
    invalid_data = dict(valid_data)
    invalid_data["unauthorized_secret_key"] = "leak_this"
    with pytest.raises(ValidationError):
        DataMinimizationPayload(**invalid_data)

    invalid_data2 = dict(valid_data)
    invalid_data2["contract_id"] = "contracts.finance.orders"
    with pytest.raises(ValidationError):
        DataMinimizationPayload(**invalid_data2)


def test_replay_client_never_falls_back_to_live():
    """Proves ReplayClient never falls back to live; fallback_live must be None."""
    client = ReplayClient(fixtures_dir="fixtures/llm")
    assert client.fallback_live is None
