"""Tests for Phase 4 evaluation harness and self-test."""

import csv
import subprocess
import sys
from pathlib import Path

import pytest
from evals.run_fix_eval import FakeEvalClient, run_eval


def test_eval_runner_self_test(tmp_path: Path):
    """Verifies that run_eval with FakeEvalClient processes all 20 cases deterministically."""
    cases_dir = Path("evals/fix_cases")
    output_csv = tmp_path / "fix_eval.csv"

    client = FakeEvalClient()
    summary = run_eval(cases_dir=cases_dir, output_csv=output_csv, client=client)

    assert summary["total_cases"] == 20
    assert summary["verified_count"] >= 15
    assert summary["unverified_count"] >= 1
    assert 1.0 <= summary["mean_attempts"] <= 2.0

    # Verify CSV structure
    assert output_csv.exists()
    with open(output_csv, "r", encoding="utf-8") as f:
        reader = list(csv.DictReader(f))
        assert len(reader) == 20

        # Verify headers
        expected_headers = ["case", "category", "status", "attempts", "failed_checks", "request_hash", "faithful"]
        assert list(reader[0].keys()) == expected_headers

        # Verify sorting
        case_names = [r["case"] for r in reader]
        assert case_names == sorted(case_names)

        # Verify faithful column is empty
        for r in reader:
            assert r["faithful"] == ""
            assert len(r["request_hash"]) == 64
            assert r["status"] in ["verified", "unverified"]
            assert int(r["attempts"]) in [1, 2]
