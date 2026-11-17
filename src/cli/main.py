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
from src.ai.fix_loop import run_suggest_fix
from src.ai.llm import ReplayClient, RecordingClient, VertexGeminiClient, MissingFixtureError

import duckdb


def resolve_sql_paths(sql_args: list[str]) -> list[Path]:
    """Resolves a list of files or directories into a sorted, unique list of SQL Path objects."""
    resolved = []
    for arg in sql_args:
        p = Path(arg)
        if not p.exists():
            raise FileNotFoundError(f"SQL path not found: '{arg}'")
        if p.is_dir():
            sql_files = sorted(list(p.rglob("*.sql")))
            if not sql_files:
                raise FileNotFoundError(f"No .sql files found in directory: '{arg}'")
            resolved.extend(sql_files)
        elif p.is_file():
            resolved.append(p)
        else:
            raise ValueError(f"Unsupported path type: '{arg}'")
    return sorted(list(set(resolved)))


def to_repo_relative_path(path: Path) -> str:
    """Converts a Path to a repo-relative POSIX string."""
    cwd = Path.cwd().resolve()
    resolved = path.resolve()
    try:
        return resolved.relative_to(cwd).as_posix()
    except ValueError:
        return path.as_posix()


def cmd_validate_sql(args):
    """Validates SQL transformation file(s) against a contract warehouse_model."""
    try:
        contract_path = Path(args.contract)
        if not contract_path.exists():
            print(f"Error: Contract file not found at '{contract_path}'", file=sys.stderr)
            sys.exit(2)

        try:
            with open(contract_path, "r", encoding="utf-8") as f:
                contract_spec = yaml.safe_load(f)
        except Exception as e:
            print(f"Error: Failed to parse contract YAML: {e}", file=sys.stderr)
            sys.exit(2)

        expected_cols = contract_spec.get("warehouse_model", {}).get("columns", {})
        dialect = contract_spec.get("warehouse_model", {}).get("dialect", "bigquery")
        contract_id = contract_spec.get("contract_id", "unnamed_contract")

        catalog = {}
        if args.catalog:
            cat_path = Path(args.catalog)
            if not cat_path.exists():
                print(f"Error: Catalog file not found at '{args.catalog}'", file=sys.stderr)
                sys.exit(2)
            try:
                with open(cat_path, "r", encoding="utf-8") as f:
                    catalog = json.load(f)
            except Exception as e:
                print(f"Error: Failed to parse catalog JSON: {e}", file=sys.stderr)
                sys.exit(2)

        sql_paths = resolve_sql_paths(args.sql)
    except FileNotFoundError as fnf:
        print(f"Error: {fnf}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)

    linter = SQLContractLinter(catalog_schema=catalog, dialect=dialect)

    file_results = []
    total_violations = 0

    for sql_path in sql_paths:
        try:
            with open(sql_path, "r", encoding="utf-8") as f:
                sql_content = f.read()
        except Exception as e:
            print(f"Error reading SQL file '{sql_path}': {e}", file=sys.stderr)
            sys.exit(2)

        model_name = sql_path.name
        rel_path = to_repo_relative_path(sql_path)
        violations = linter.lint_query_structured(sql_content, expected_cols, model_name=model_name)
        total_violations += len(violations)

        file_results.append({
            "path": rel_path,
            "violations": violations
        })

    # Sort files deterministically by repo-relative posix path
    file_results.sort(key=lambda x: x["path"])

    if getattr(args, "format", "text") == "json":
        doc = {
            "schema_version": 1,
            "files": file_results,
            "summary": {
                "files": len(file_results),
                "violations": total_violations
            }
        }
        json_output = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        print(json_output)
        sys.exit(1 if total_violations > 0 else 0)
    else:
        # Default text format
        for f_res in file_results:
            p_name = Path(f_res["path"]).name
            viols = f_res["violations"]
            if viols:
                print(f"❌ AegisContract Gating Failed: {len(viols)} violation(s) found in {p_name}:")
                for v in viols:
                    print(f"   • {v['message']}")
            else:
                print(f"✅ AegisContract Passed: SQL model '{p_name}' strictly complies with '{contract_id}'.")

        sys.exit(1 if total_violations > 0 else 0)


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


def cmd_suggest_fix(args):
    """Proposes an AI-assisted SQL fix and deterministically verifies it."""
    try:
        sql_path = Path(args.sql)
        contract_path = Path(args.contract)
        catalog_path = Path(args.catalog) if args.catalog else None

        if not sql_path.exists():
            print(f"Error: SQL file not found at '{sql_path}'", file=sys.stderr)
            sys.exit(2)
        if not contract_path.exists():
            print(f"Error: Contract file not found at '{contract_path}'", file=sys.stderr)
            sys.exit(2)
        if catalog_path and not catalog_path.exists():
            print(f"Error: Catalog file not found at '{catalog_path}'", file=sys.stderr)
            sys.exit(2)

        # Select LLM client
        llm_mode = getattr(args, "llm_mode", "replay")
        fixtures_dir = getattr(args, "fixtures_dir", "fixtures/llm")

        if llm_mode == "replay":
            client = ReplayClient(fixtures_dir=fixtures_dir)
        elif llm_mode == "record":
            live = VertexGeminiClient()
            client = RecordingClient(live_client=live, fixtures_dir=fixtures_dir)
        elif llm_mode == "live":
            client = VertexGeminiClient()
        else:
            print(f"Error: Unknown llm_mode '{llm_mode}'", file=sys.stderr)
            sys.exit(2)

        model_name = getattr(args, "model", "gemini-1.5-pro")

        result = run_suggest_fix(
            sql_path=sql_path,
            contract_path=contract_path,
            catalog_path=catalog_path,
            client=client,
            model_name=model_name
        )

        output_json = json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        print(output_json)

        if result["status"] == "verified":
            sys.exit(0)
        else:
            sys.exit(1)

    except MissingFixtureError as mfe:
        print(f"Error: {mfe}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)


def main():
    parser = argparse.ArgumentParser(prog="aegis", description="AegisContract Dual-Boundary Data Contract Engine")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # validate-sql
    p_val = subparsers.add_parser("validate-sql", help="Lint SQL model against contract schema via AST")
    p_val.add_argument("--sql", nargs="+", required=True, help="Path(s) to .sql transformation file(s) or directory")
    p_val.add_argument("--contract", required=True, help="Path to contract .yaml")
    p_val.add_argument("--catalog", default=None, help="Optional path to warehouse schema catalog JSON")
    p_val.add_argument("--format", choices=["text", "json"], default="text", help="Output format: text (default) or json")
    p_val.set_defaults(func=cmd_validate_sql)

    # suggest-fix
    p_sug = subparsers.add_parser("suggest-fix", help="Propose and deterministically verify an AI-assisted SQL contract fix")
    p_sug.add_argument("--sql", required=True, help="Path to .sql transformation file to fix")
    p_sug.add_argument("--contract", required=True, help="Path to contract .yaml")
    p_sug.add_argument("--catalog", default=None, help="Optional path to warehouse schema catalog JSON")
    p_sug.add_argument("--llm-mode", choices=["live", "record", "replay"], default="replay", help="LLM interaction mode (default: replay)")
    p_sug.add_argument("--model", default="gemini-1.5-pro", help="Model name (default: gemini-1.5-pro)")
    p_sug.add_argument("--fixtures-dir", default="fixtures/llm", help="Directory for LLM fixtures (default: fixtures/llm)")
    p_sug.set_defaults(func=cmd_suggest_fix)

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
