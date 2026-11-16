import io
import sys
import pytest
from pathlib import Path

from src.cli.main import main


def run_cli_capture(argv: list[str]) -> tuple[int, str, str]:
    """Runs CLI with given arguments, capturing stdout, stderr, and exit code."""
    old_stdout, old_stderr, old_argv = sys.stdout, sys.stderr, sys.argv
    captured_stdout, captured_stderr = io.StringIO(), io.StringIO()
    exit_code = 0
    try:
        sys.stdout, sys.stderr, sys.argv = captured_stdout, captured_stderr, ["aegis"] + argv
        main()
    except SystemExit as se:
        exit_code = se.code if isinstance(se.code, int) else 1
    finally:
        sys.stdout, sys.stderr, sys.argv = old_stdout, old_stderr, old_argv

    return exit_code, captured_stdout.getvalue(), captured_stderr.getvalue()


@pytest.mark.parametrize("query_name,golden_filename,expected_exit", [
    ("clean_fct_orders.sql", "clean_fct_orders.json", 0),
    ("bad_missing_col.sql", "bad_missing_col.json", 1),
    ("bad_wildcard.sql", "bad_wildcard.json", 1),
])
def test_validate_sql_json_golden_byte_for_byte(query_name, golden_filename, expected_exit):
    """1.3 Verifies validate-sql --format json matches golden files byte-for-byte."""
    sql_path = f"demo/sample_queries/{query_name}"
    golden_path = Path("tests/golden") / golden_filename

    assert golden_path.exists(), f"Golden file not found: {golden_path}"
    with open(golden_path, "r", encoding="utf-8") as f:
        expected_golden_bytes = f.read().encode("utf-8")

    exit_code, stdout, stderr = run_cli_capture([
        "validate-sql",
        "--sql", sql_path,
        "--contract", "contracts/finance/orders_v1.yaml",
        "--catalog", "demo/catalog.json",
        "--format", "json"
    ])

    assert exit_code == expected_exit
    assert stderr == ""
    # Byte-for-byte comparison of stdout against golden file
    actual_bytes = stdout.encode("utf-8")
    assert actual_bytes == expected_golden_bytes, (
        f"Byte-for-byte mismatch for {query_name}!\nExpected:\n{expected_golden_bytes.decode()}\nActual:\n{actual_bytes.decode()}"
    )


def test_validate_sql_multiple_paths_and_directory():
    """1.2 Verifies validate-sql accepts multiple paths and directory."""
    # 1. Directory input
    exit_code_dir, stdout_dir, stderr_dir = run_cli_capture([
        "validate-sql",
        "--sql", "demo/sample_queries",
        "--contract", "contracts/finance/orders_v1.yaml",
        "--catalog", "demo/catalog.json",
        "--format", "json"
    ])
    assert exit_code_dir == 1
    assert '"files":3' in stdout_dir
    assert '"violations":6' in stdout_dir

    # 2. Multiple explicit files
    exit_code_multi, stdout_multi, stderr_multi = run_cli_capture([
        "validate-sql",
        "--sql", "demo/sample_queries/clean_fct_orders.sql", "demo/sample_queries/bad_missing_col.sql",
        "--contract", "contracts/finance/orders_v1.yaml",
        "--catalog", "demo/catalog.json",
        "--format", "json"
    ])
    assert exit_code_multi == 1
    assert '"files":2' in stdout_multi
    assert '"violations":1' in stdout_multi


def test_validate_sql_usage_and_internal_errors_exit_2():
    """1.2 Usage or internal errors exit with code 2 and print to stderr without tracebacks."""
    # Missing SQL path
    exit_code1, stdout1, stderr1 = run_cli_capture([
        "validate-sql",
        "--sql", "does_not_exist.sql",
        "--contract", "contracts/finance/orders_v1.yaml"
    ])
    assert exit_code1 == 2
    assert stdout1 == ""
    assert "Error:" in stderr1
    assert "Traceback" not in stderr1

    # Missing contract path
    exit_code2, stdout2, stderr2 = run_cli_capture([
        "validate-sql",
        "--sql", "demo/sample_queries/clean_fct_orders.sql",
        "--contract", "missing_contract.yaml"
    ])
    assert exit_code2 == 2
    assert stdout2 == ""
    assert "Error:" in stderr2
    assert "Traceback" not in stderr2


def test_validate_sql_default_text_format():
    """1.3 Verifies default format is text."""
    exit_clean, stdout_clean, _ = run_cli_capture([
        "validate-sql",
        "--sql", "demo/sample_queries/clean_fct_orders.sql",
        "--contract", "contracts/finance/orders_v1.yaml",
        "--catalog", "demo/catalog.json"
    ])
    assert exit_clean == 0
    assert "✅ AegisContract Passed" in stdout_clean

    exit_bad, stdout_bad, _ = run_cli_capture([
        "validate-sql",
        "--sql", "demo/sample_queries/bad_missing_col.sql",
        "--contract", "contracts/finance/orders_v1.yaml",
        "--catalog", "demo/catalog.json"
    ])
    assert exit_bad == 1
    assert "❌ AegisContract Gating Failed" in stdout_bad
