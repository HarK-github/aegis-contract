"""
In-Warehouse Runtime Assertion Runner for AegisContract.
Verifies runtime invariants (such as primary key uniqueness and numerical value ranges)
that cannot be proven statically by AST analysis alone.

Uses native DuckDB cursor extraction to avoid requiring pandas or numpy dependencies.
"""

from dataclasses import dataclass
from typing import List, Dict, Any, Optional
import duckdb


@dataclass
class AssertionResult:
    assertion_name: str
    passed: bool
    expected_value: Any
    actual_value: Any
    error_message: Optional[str] = None


class WarehouseAssertionRunner:
    """Runs data contract runtime assertions against target database tables."""

    def __init__(self, connection: Optional[duckdb.DuckDBPyConnection] = None):
        self.con = connection or duckdb.connect()

    def run_assertions_for_contract(
        self,
        contract_spec: Dict[str, Any],
        target_table_override: Optional[str] = None
    ) -> List[AssertionResult]:
        """
        Executes all declared runtime assertions for the given contract.
        Replaces {{ target }} with the actual table name.
        Uses pure native cursor fetching without pandas/numpy.
        """
        results = []
        target_table = target_table_override or contract_spec.get("warehouse_model", {}).get("target_table", "target")
        assertions = contract_spec.get("runtime_assertions", [])

        for assertion in assertions:
            name = assertion.get("name", "unnamed_assertion")
            raw_query = assertion.get("query", "")
            exp_field = assertion.get("expected_field", "result")
            exp_val = assertion.get("expected_value", 0)

            templated_query = raw_query.replace("{{ target }}", target_table)

            try:
                rel = self.con.execute(templated_query)
                cols = [desc[0] for desc in rel.description] if rel.description else []
                row = rel.fetchone()

                if row is None or not cols:
                    results.append(AssertionResult(
                        assertion_name=name,
                        passed=False,
                        expected_value=exp_val,
                        actual_value=None,
                        error_message="Query returned empty result set"
                    ))
                    continue

                row_dict = dict(zip(cols, row))
                if exp_field not in row_dict:
                    results.append(AssertionResult(
                        assertion_name=name,
                        passed=False,
                        expected_value=exp_val,
                        actual_value=None,
                        error_message=f"Expected column '{exp_field}' not in query result columns: {cols}"
                    ))
                    continue

                actual_val = row_dict[exp_field]
                passed = bool(actual_val == exp_val)

                results.append(AssertionResult(
                    assertion_name=name,
                    passed=passed,
                    expected_value=exp_val,
                    actual_value=actual_val,
                    error_message=None if passed else f"Assertion failed: expected {exp_field} == {exp_val}, got {actual_val}"
                ))

            except Exception as e:
                results.append(AssertionResult(
                    assertion_name=name,
                    passed=False,
                    expected_value=exp_val,
                    actual_value=None,
                    error_message=f"Execution error: {str(e)}"
                ))

        return results
