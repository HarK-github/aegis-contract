"""
AegisContract Command Line Interface (CLI).
Provides CLI tooling for CI/CD gating, SQL AST validation,
contract diff classification, and DLQ replay orchestration.
"""

import sys
import json
import yaml
import argparse
from pathlib import Path

from src.warehouse.ast_linter import SQLContractLinter
from src.warehouse.diff_engine import compare_contracts
from src.warehouse.runtime_assertions import WarehouseAssertionRunner
from src.edge.contract_loader import compile_contract_from_yaml
from src.edge.dlq_router import QuarantineDLQRouter
from src.edge.replay import DLQReplayWorker

import duckdb


def cmd_validate_sql(args):
    """Validates a SQL transformation file against a contract warehouse_model."""
    sql_path = Path(args.sql)
    contract_path = Path(args.contract)

    if not sql_path.exists():
        print(f"❌ Error: SQL file not found at {sql_path}", file=sys.stderr)
        sys.exit(1)
    if not contract_path.exists():
        print(f"❌ Error: Contract file not found at {contract_path}", file=sys.stderr)
        sys.exit(1)

    with open(contract_path, "r", encoding="utf-8") as f:
        contract_spec = yaml.safe_load(f)

    expected_cols = contract_spec.get("warehouse_model", {}).get("columns", {})
    dialect = contract_spec.get("warehouse_model", {}).get("dialect", "bigquery")

    catalog = {}
    if args.catalog and Path(args.catalog).exists():
        with open(args.catalog, "r", encoding="utf-8") as f:
            catalog = json.load(f)

    with open(sql_path, "r", encoding="utf-8") as f:
        sql_content = f.read()

    linter = SQLContractLinter(catalog_schema=catalog, dialect=dialect)
    violations = linter.lint_query(sql_content, expected_cols, model_name=sql_path.name)

    if violations:
        print(f"❌ AegisContract Gating Failed: {len(violations)} violation(s) found in {sql_path.name}:")
        for v in violations:
            print(f"   • {v}")
        sys.exit(1)
    else:
        print(f"✅ AegisContract Passed: SQL model '{sql_path.name}' strictly complies with '{contract_spec.get('contract_id')}'.")
        sys.exit(0)


def cmd_diff_contract(args):
    """Compares two contracts and classifies changes into SemVer tiers."""
    with open(args.old, "r", encoding="utf-8") as f:
        old_spec = yaml.safe_load(f)
    with open(args.new, "r", encoding="utf-8") as f:
        new_spec = yaml.safe_load(f)

    result = compare_contracts(old_spec, new_spec)
    report = result.to_markdown_report()

    print(report)

    if args.report_file:
        with open(args.report_file, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"\n📄 Written report to {args.report_file}")

    if result.is_breaking and not args.allow_breaking:
        print("\n❌ CI Check Failed: Breaking changes detected in contract without --allow-breaking flag.")
        sys.exit(1)
    else:
        sys.exit(0)


def cmd_replay(args):
    """Replays quarantined DLQ events against a contract."""
    dlq_path = Path(args.dlq)
    contract_path = Path(args.contract)

    if not dlq_path.exists():
        print(f"❌ Error: DLQ file not found at {dlq_path}", file=sys.stderr)
        sys.exit(1)

    compiled = compile_contract_from_yaml(str(contract_path))
    worker = DLQReplayWorker()

    records = []
    with open(dlq_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))

    print(f"Loaded {len(records)} quarantined records. Executing replay (dry_run={args.dry_run})...")

    def validator_fn(raw_bytes):
        return compiled.validate_bytes(raw_bytes)

    result = worker.replay(
        dlq_records=records,
        contract_validator_fn=validator_fn,
        dry_run=args.dry_run
    )

    print("\n--- Replay Summary Report ---")
    print(f"• Total Processed:    {result['total_processed']}")
    print(f"• Successfully Healed:{result['healed']}")
    print(f"• Skipped Duplicates: {result['skipped_duplicates']}")
    print(f"• Still Failing:      {result['still_failing']}")
    print(f"• Dry Run Mode:       {result['dry_run']}")


def cmd_run_assertions(args):
    """Executes in-warehouse runtime assertions against a DuckDB file."""
    with open(args.contract, "r", encoding="utf-8") as f:
        contract_spec = yaml.safe_load(f)

    con = duckdb.connect(args.db)
    runner = WarehouseAssertionRunner(connection=con)
    results = runner.run_assertions_for_contract(contract_spec, target_table_override=args.table)

    failed = [r for r in results if not r.passed]
    print(f"--- Runtime Assertions for {contract_spec.get('contract_id')} ---")
    for r in results:
        status_icon = "✅" if r.passed else "❌"
        print(f"{status_icon} Assertion '{r.assertion_name}': Expected {r.expected_value}, got {r.actual_value}")
        if r.error_message:
            print(f"   Error: {r.error_message}")

    if failed:
        sys.exit(1)
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(prog="aegis", description="AegisContract Dual-Boundary Data Contract Engine")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # validate-sql
    p_val = subparsers.add_parser("validate-sql", help="Lint SQL model against contract schema via AST")
    p_val.add_argument("--sql", required=True, help="Path to .sql transformation file")
    p_val.add_argument("--contract", required=True, help="Path to contract .yaml")
    p_val.add_argument("--catalog", default=None, help="Optional path to warehouse schema catalog JSON")
    p_val.set_defaults(func=cmd_validate_sql)

    # diff-contract
    p_diff = subparsers.add_parser("diff-contract", help="Compare two contracts and classify SemVer bump")
    p_diff.add_argument("--old", required=True, help="Path to existing contract .yaml")
    p_diff.add_argument("--new", required=True, help="Path to proposed contract .yaml")
    p_diff.add_argument("--report-file", default=None, help="Output markdown report file")
    p_diff.add_argument("--allow-breaking", action="store_true", help="Do not exit 1 on breaking changes")
    p_diff.set_defaults(func=cmd_diff_contract)

    # replay
    p_rep = subparsers.add_parser("replay", help="Replay quarantined DLQ events")
    p_rep.add_argument("--dlq", required=True, help="Path to quarantine_events.jsonl")
    p_rep.add_argument("--contract", required=True, help="Path to updated contract .yaml")
    p_rep.add_argument("--dry-run", action="store_true", help="Simulate replay without writing")
    p_rep.set_defaults(func=cmd_replay)

    # run-assertions
    p_ass = subparsers.add_parser("run-assertions", help="Run database runtime assertions (PK uniqueness, bounds)")
    p_ass.add_argument("--contract", required=True, help="Path to contract .yaml")
    p_ass.add_argument("--db", required=True, help="Path to DuckDB database file")
    p_ass.add_argument("--table", default=None, help="Target table name override")
    p_ass.set_defaults(func=cmd_run_assertions)

    parsed_args = parser.parse_args()
    parsed_args.func(parsed_args)


if __name__ == "__main__":
    main()
