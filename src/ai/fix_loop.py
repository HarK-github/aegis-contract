"""
Deterministic 6-Check Verification Loop for AI-assisted SQL Fix Proposals.
Checks:
2.4(a) Strict Pydantic schema validation (no markdown, no extra keys)
2.4(b) Exactly one SELECT/WITH statement parsed with sqlglot (no DDL/DML)
2.4(c) Identical set of {{ ref() }} and {{ source() }} calls
2.4(d) Identical set of source tables referenced
2.4(e) Unified diff touches <= 30 lines
2.4(f) Zero AST contract linter violations on re-run
"""

import re
import json
import difflib
from pathlib import Path
from typing import Optional, Any
import sqlglot
from sqlglot import exp

from src.warehouse.ast_linter import SQLContractLinter
from src.ai.llm import (
    LLMClient,
    LLMRequest,
    DataMinimizationPayload,
    LLMFixResponse,
    ReplayClient,
    RecordingClient,
    VertexGeminiClient
)

DEFAULT_SYSTEM_PROMPT_PATH = Path("src/ai/prompts/fix_sql_v1.txt")


def load_system_prompt(prompt_path: Optional[Path] = None) -> str:
    path = prompt_path or DEFAULT_SYSTEM_PROMPT_PATH
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()


def extract_ref_and_source_calls(sql: str) -> tuple[set[str], set[str]]:
    """2.4(c) Extracts normalized sets of ref(...) and source(..., ...) calls."""
    refs = set(re.findall(r"\{\{\s*ref\(['\"](.*?)['\"]\)\s*\}\}", sql))
    sources = set(re.findall(r"\{\{\s*source\(['\"](.*?)['\"],\s*['\"](.*?)['\"]\)\s*\}\}", sql))
    sources_normalized = {f"{s[0]}.{s[1]}" for s in sources}
    return refs, sources_normalized


def extract_source_tables(sql: str, linter: SQLContractLinter, dialect: str) -> set[str]:
    """2.4(d) Extracts set of base source tables referenced (excluding CTE aliases)."""
    clean = linter.mock_dbt_jinja(sql)
    try:
        ast = sqlglot.parse_one(clean, read=dialect)
        if not ast:
            return set()
        cte_names = {cte.alias for cte in ast.find_all(exp.CTE) if cte.alias}
        tables = set()
        for t in ast.find_all(exp.Table):
            t_name = t.name
            if t_name and t_name not in cte_names and t_name != "this_target":
                tables.add(t_name)
        return tables
    except Exception:
        return set()


def calculate_diff(original_sql: str, proposed_sql: str) -> tuple[int, str]:
    """2.4(e) Calculates line diff count and unified diff string."""
    orig_lines = original_sql.splitlines(keepends=True)
    prop_lines = proposed_sql.splitlines(keepends=True)
    diff = list(difflib.unified_diff(
        orig_lines, prop_lines, fromfile="original.sql", tofile="proposed.sql"
    ))
    changed_lines = [
        l for l in diff
        if (l.startswith("+") or l.startswith("-")) and not (l.startswith("+++") or l.startswith("---"))
    ]
    return len(changed_lines), "".join(diff)


def verify_proposal(
    original_sql: str,
    raw_response: str,
    expected_columns: dict[str, str],
    catalog: dict[str, dict[str, str]],
    dialect: str = "bigquery",
    model_name: str = "model.sql"
) -> tuple[bool, Optional[str], Optional[str], list[str], list[dict]]:
    """
    Executes the 6 deterministic checks against a single proposed fix.
    Returns: (is_accepted, fixed_sql, unified_diff, failed_checks, new_violations)
    """
    failed_checks: list[str] = []
    linter = SQLContractLinter(catalog_schema=catalog, dialect=dialect)

    # 2.4(a) Response parses to strict schema
    try:
        parsed = LLMFixResponse.model_validate_json(raw_response)
        proposed_sql = parsed.fixed_sql
    except Exception:
        failed_checks.append("CHECK_2_4_A_SCHEMA_PARSE")
        return False, None, None, failed_checks, []

    # 2.4(b) Exactly one SELECT/WITH statement, no DDL/DML
    mocked_sql = linter.mock_dbt_jinja(proposed_sql)
    try:
        stmts = sqlglot.parse(mocked_sql, read=dialect)
        if len(stmts) != 1 or stmts[0] is None:
            failed_checks.append("CHECK_2_4_B_NOT_SINGLE_STMT")
            return False, None, None, failed_checks, []

        stmt = stmts[0]
        if not isinstance(stmt, (exp.Select, exp.Union)):
            failed_checks.append("CHECK_2_4_B_NOT_SELECT_OR_UNION")
            return False, None, None, failed_checks, []

        has_ddl_dml = any(
            isinstance(node, (exp.Create, exp.Drop, exp.Alter, exp.Insert, exp.Update, exp.Delete))
            for node in stmt.walk()
        )
        if has_ddl_dml:
            failed_checks.append("CHECK_2_4_B_DDL_DML_PROHIBITED")
            return False, None, None, failed_checks, []
    except Exception:
        failed_checks.append("CHECK_2_4_B_SQLGLOT_PARSE_FAILED")
        return False, None, None, failed_checks, []

    # 2.4(c) Identical set of {{ ref() }} and {{ source() }} calls
    orig_refs, orig_sources = extract_ref_and_source_calls(original_sql)
    prop_refs, prop_sources = extract_ref_and_source_calls(proposed_sql)
    if orig_refs != prop_refs or orig_sources != prop_sources:
        failed_checks.append("CHECK_2_4_C_REF_SOURCE_MISMATCH")
        return False, None, None, failed_checks, []

    # 2.4(d) Identical set of source tables referenced
    orig_tables = extract_source_tables(original_sql, linter, dialect)
    prop_tables = extract_source_tables(proposed_sql, linter, dialect)
    if orig_tables != prop_tables:
        failed_checks.append("CHECK_2_4_D_SOURCE_TABLES_MISMATCH")
        return False, None, None, failed_checks, []

    # 2.4(e) Line-level diff touches at most 30 lines
    changed_count, diff_str = calculate_diff(original_sql, proposed_sql)
    if changed_count > 30:
        failed_checks.append("CHECK_2_4_E_DIFF_EXCEEDS_30_LINES")
        return False, None, None, failed_checks, []

    # 2.4(f) Re-running the same linter on the proposal returns ZERO violations
    new_violations = linter.lint_query_structured(proposed_sql, expected_columns, model_name=model_name)
    if len(new_violations) != 0:
        failed_checks.append("CHECK_2_4_F_LINTER_VIOLATIONS_REMAIN")
        return False, None, None, failed_checks, new_violations

    return True, proposed_sql, diff_str, [], []


def run_suggest_fix(
    sql_path: Path,
    contract_path: Path,
    catalog_path: Optional[Path] = None,
    client: Optional[LLMClient] = None,
    model_name: str = "gemini-1.5-pro",
    prompt_version: str = "v1",
    max_attempts: int = 2
) -> dict[str, Any]:
    """
    Executes the 2-attempt AI-assisted fix loop against a target SQL file.
    Output: stable dictionary conforming to 2.5 schema.
    """
    import yaml
    with open(contract_path, "r", encoding="utf-8") as f:
        contract_spec = yaml.safe_load(f)

    expected_cols = contract_spec.get("warehouse_model", {}).get("columns", {})
    dialect = contract_spec.get("warehouse_model", {}).get("dialect", "bigquery")

    catalog = {}
    if catalog_path and catalog_path.exists():
        with open(catalog_path, "r", encoding="utf-8") as f:
            catalog = json.load(f)

    with open(sql_path, "r", encoding="utf-8") as f:
        original_sql = f.read()

    linter = SQLContractLinter(catalog_schema=catalog, dialect=dialect)
    current_violations = linter.lint_query_structured(original_sql, expected_cols, model_name=sql_path.name)

    # Relative posix path
    cwd = Path.cwd().resolve()
    try:
        rel_path = sql_path.resolve().relative_to(cwd).as_posix()
    except Exception:
        rel_path = sql_path.as_posix()

    if not current_violations:
        # Already clean
        return {
            "attempts": 0,
            "failed_checks": [],
            "fixed_sql": original_sql,
            "path": rel_path,
            "schema_version": 1,
            "status": "verified",
            "unified_diff": ""
        }

    system_prompt = load_system_prompt()
    if client is None:
        client = ReplayClient()

    all_failed_checks = []
    attempt = 0

    while attempt < max_attempts:
        attempt += 1

        # 2.3 Data minimization: only sql_text, violations, contract_columns, catalog
        min_payload = DataMinimizationPayload(
            sql_text=original_sql,
            violations=current_violations,
            contract_columns=expected_cols,
            catalog=catalog
        )

        request = LLMRequest(
            model_name=model_name,
            prompt_version=prompt_version,
            system=system_prompt,
            user=min_payload.to_canonical_json()
        )

        raw_response = client.generate(request)

        passed, fixed_sql, unified_diff, failed_checks, next_violations = verify_proposal(
            original_sql=original_sql,
            raw_response=raw_response,
            expected_columns=expected_cols,
            catalog=catalog,
            dialect=dialect,
            model_name=sql_path.name
        )

        if passed:
            return {
                "attempts": attempt,
                "failed_checks": all_failed_checks,
                "fixed_sql": fixed_sql,
                "path": rel_path,
                "schema_version": 1,
                "status": "verified",
                "unified_diff": unified_diff
            }
        else:
            all_failed_checks.extend(failed_checks)
            # If linter violations remained, feed only the new violation list into next attempt
            if next_violations:
                current_violations = next_violations

    return {
        "attempts": attempt,
        "failed_checks": all_failed_checks,
        "fixed_sql": None,
        "path": rel_path,
        "schema_version": 1,
        "status": "unverified",
        "unified_diff": None
    }
