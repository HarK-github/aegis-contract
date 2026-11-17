"""Evaluation runner for Aegis SQL fix suggestions.

Evaluates 20 benchmark test cases across 5 categories:
- missing column (4)
- renamed column (4)
- wildcard (4)
- type mismatch (4)
- other (4)

Emits evals/results/fix_eval.csv with columns:
case,category,status,attempts,failed_checks,request_hash,faithful
"""

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.ai.fix_loop import run_suggest_fix
from src.ai.llm import LLMClient, LLMRequest, ReplayClient


class FakeEvalClient:
    """
    Deterministic simulated client for self-testing the evaluation suite offline
    without requiring pre-recorded Vertex AI fixtures.
    """

    CANNED_PROPOSALS: Dict[str, List[str]] = {
        "case_01_missing_col_simple": [
            json.dumps({"fixed_sql": "SELECT order_id, customer_id, total_amount FROM orders"})
        ],
        "case_02_missing_col_cte": [
            json.dumps({"fixed_sql": "WITH base AS (SELECT order_id, amount FROM orders)\nSELECT order_id, amount FROM base"})
        ],
        "case_03_missing_col_multitable": [
            json.dumps({"fixed_sql": "SELECT o.order_id, c.customer_name, o.status FROM orders o JOIN customers c ON o.customer_id = c.customer_id"})
        ],
        "case_04_missing_col_aggregate": [
            json.dumps({"fixed_sql": "SELECT department_id, COUNT(employee_id) AS headcount FROM employees GROUP BY department_id"})
        ],
        "case_05_renamed_col_user": [
            json.dumps({"fixed_sql": "SELECT user_ident AS id, email FROM users"})
        ],
        "case_06_renamed_col_amount": [
            json.dumps({"fixed_sql": "SELECT order_id, price AS total_price FROM sales"})
        ],
        "case_07_renamed_col_date": [
            json.dumps({"fixed_sql": "SELECT event_id, created_at AS occurred_at FROM events"})
        ],
        "case_08_renamed_col_status": [
            json.dumps({"fixed_sql": "SELECT item_id, state AS status FROM inventory"})
        ],
        "case_09_wildcard_raw_star": [
            json.dumps({"fixed_sql": "SELECT product_id, name, price FROM products"})
        ],
        "case_10_wildcard_table_star": [
            json.dumps({"fixed_sql": "SELECT p.product_id, p.sku FROM products p"})
        ],
        "case_11_wildcard_cte_star": [
            json.dumps({"fixed_sql": "WITH sub AS (SELECT id, code FROM items)\nSELECT id, code FROM sub"})
        ],
        "case_12_wildcard_join_star": [
            json.dumps({"fixed_sql": "SELECT a.id, a.name, b.val FROM t1 a JOIN t2 b ON a.id = b.id"})
        ],
        "case_13_type_mismatch_int_to_str": [
            json.dumps({"fixed_sql": "SELECT account_id, CAST(balance_cents AS VARCHAR) AS balance_cents FROM accounts"})
        ],
        "case_14_type_mismatch_float_to_int": [
            json.dumps({"fixed_sql": "SELECT metric_id, CAST(score AS BIGINT) AS score FROM metrics"})
        ],
        "case_15_type_mismatch_date_to_timestamp": [
            # Attempt 1 fails, Attempt 2 succeeds
            json.dumps({"fixed_sql": "SELECT session_id, log_date FROM logs"}),
            json.dumps({"fixed_sql": "SELECT session_id, CAST(log_date AS TIMESTAMP) AS log_date FROM logs"})
        ],
        "case_16_type_mismatch_bool_to_varchar": [
            json.dumps({"fixed_sql": "SELECT user_id, CAST(is_active AS VARCHAR) AS is_active FROM user_profiles"})
        ],
        # Intentionally unfixable / failing checks for edge evaluation
        "case_17_other_broken_cte_reference": [
            # References non-existent / new table -> fails check d
            json.dumps({"fixed_sql": "SELECT id, val FROM rogue_unreferenced_table"})
        ],
        "case_18_other_wrong_column_alias": [
            # Still misses revenue -> fails check f
            json.dumps({"fixed_sql": "SELECT client_id, revenue AS misnamed_profit FROM client_records"})
        ],
        "case_19_other_extra_unannounced_column": [
            # Fixed by selecting only contracted columns
            json.dumps({"fixed_sql": "SELECT transaction_id, user_id FROM transactions"})
        ],
        "case_20_other_cte_syntax_missing_with": [
            # Unparseable proposal -> fails check a
            "This is not valid JSON"
        ]
    }

    def __init__(self) -> None:
        self.call_counts: Dict[str, int] = {}

    def generate(self, request: LLMRequest) -> str:
        # Determine case from payload sql_text or request
        for case_name, responses in self.CANNED_PROPOSALS.items():
            case_sql_file = Path("evals/fix_cases") / case_name / "broken.sql"
            if case_sql_file.exists():
                sql_content = case_sql_file.read_text(encoding="utf-8").strip()
                if sql_content in request.user:
                    idx = self.call_counts.get(case_name, 0)
                    self.call_counts[case_name] = idx + 1
                    resp_idx = min(idx, len(responses) - 1)
                    return responses[resp_idx]

        # Default fallback
        return json.dumps({"fixed_sql": "SELECT 1"})


def run_eval(
    cases_dir: Path,
    output_csv: Path,
    client: Optional[LLMClient] = None,
    fixtures_dir: str = "fixtures/llm"
) -> Dict[str, Any]:
    output_csv.parent.mkdir(parents=True, exist_ok=True)

    case_dirs = sorted([d for d in cases_dir.iterdir() if d.is_dir() and d.name.startswith("case_")])
    if not case_dirs:
        raise ValueError(f"No case directories found in {cases_dir}")

    rows: List[Dict[str, Any]] = []

    for cdir in case_dirs:
        case_name = cdir.name
        meta_file = cdir / "case.json"
        category = "unknown"
        if meta_file.exists():
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)
                category = meta.get("category", "unknown")

        sql_path = cdir / "broken.sql"
        contract_path = cdir / "contract.yaml"
        catalog_path = cdir / "catalog.json"

        # Determine client
        eval_client = client or ReplayClient(fixtures_dir=fixtures_dir)

        result = run_suggest_fix(
            sql_path=sql_path,
            contract_path=contract_path,
            catalog_path=catalog_path,
            client=eval_client,
            max_attempts=2
        )

        # Hash calculation for the initial request
        import yaml
        from src.ai.fix_loop import load_system_prompt
        from src.ai.llm import DataMinimizationPayload
        from src.warehouse.ast_linter import SQLContractLinter

        with open(contract_path, "r", encoding="utf-8") as f:
            contract_spec = yaml.safe_load(f)
        expected_cols = contract_spec.get("warehouse_model", {}).get("columns", {})
        dialect = contract_spec.get("warehouse_model", {}).get("dialect", "bigquery")
        catalog_data = {}
        if catalog_path and catalog_path.exists():
            with open(catalog_path, "r", encoding="utf-8") as f:
                catalog_data = json.load(f)

        orig_sql = sql_path.read_text(encoding="utf-8")
        linter = SQLContractLinter(catalog_schema=catalog_data, dialect=dialect)
        initial_violations = linter.lint_query_structured(orig_sql, expected_cols, model_name=sql_path.name)
        system_prompt = load_system_prompt()
        min_payload = DataMinimizationPayload(
            sql_text=orig_sql,
            violations=initial_violations,
            contract_columns=expected_cols,
            catalog=catalog_data
        )
        req = LLMRequest(
            model_name="gemini-1.5-pro",
            prompt_version="v1",
            system=system_prompt,
            user=min_payload.to_canonical_json()
        )

        rows.append({
            "case": case_name,
            "category": category,
            "status": result["status"],
            "attempts": result["attempts"],
            "failed_checks": ";".join(result["failed_checks"]) if result["failed_checks"] else "none",
            "request_hash": req.request_hash,
            "faithful": ""  # Explicitly left empty for human review
        })

    # Sort rows strictly by case name
    rows.sort(key=lambda r: r["case"])

    # Write CSV with LF line endings
    fieldnames = ["case", "category", "status", "attempts", "failed_checks", "request_hash", "faithful"]
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    # Compute summary metrics
    total_cases = len(rows)
    verified_count = sum(1 for r in rows if r["status"] == "verified")
    unverified_count = sum(1 for r in rows if r["status"] == "unverified")
    mean_attempts = sum(r["attempts"] for r in rows) / total_cases if total_cases > 0 else 0.0

    categories = sorted(list(set(r["category"] for r in rows)))
    cat_summary = {}
    for cat in categories:
        cat_rows = [r for r in rows if r["category"] == cat]
        cat_verified = sum(1 for r in cat_rows if r["status"] == "verified")
        cat_summary[cat] = {"verified": cat_verified, "total": len(cat_rows)}

    summary = {
        "total_cases": total_cases,
        "verified_count": verified_count,
        "unverified_count": unverified_count,
        "mean_attempts": round(mean_attempts, 2),
        "category_summary": cat_summary
    }

    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Aegis SQL fix evaluation suite")
    parser.add_argument(
        "--cases-dir",
        default="evals/fix_cases",
        help="Path to evaluation cases directory"
    )
    parser.add_argument(
        "--output-csv",
        default="evals/results/fix_eval.csv",
        help="Path to output results CSV"
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run self-test using deterministic FakeEvalClient"
    )
    parser.add_argument(
        "--fixtures-dir",
        default="fixtures/llm",
        help="Directory containing LLM fixtures (for replay mode)"
    )

    args = parser.parse_args()

    client: Optional[LLMClient] = None
    if args.self_test:
        client = FakeEvalClient()

    summary = run_eval(
        cases_dir=Path(args.cases_dir),
        output_csv=Path(args.output_csv),
        client=client,
        fixtures_dir=args.fixtures_dir
    )

    print("==================================================")
    print("           AEGIS SQL FIX EVALUATION SUMMARY       ")
    print("==================================================")
    print(f"Total Cases:       {summary['total_cases']}")
    print(f"Verified Fixes:    {summary['verified_count']}")
    print(f"Unverified Fixes:  {summary['unverified_count']}")
    print(f"Mean Attempts:     {summary['mean_attempts']:.2f}")
    print("--------------------------------------------------")
    print("Per-Category Breakdown:")
    for cat, stats in summary["category_summary"].items():
        print(f"  - {cat:<18}: {stats['verified']}/{stats['total']} verified")
    print("==================================================")
    print(f"Results written to: {args.output_csv}")


if __name__ == "__main__":
    main()
