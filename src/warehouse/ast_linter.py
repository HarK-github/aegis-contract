"""
Catalog-Aware SQL AST Contract Linter for AegisContract.
Uses sqlglot to parse transformation queries (CTEs, joins, subqueries),
strip common dbt Jinja macros via regex approximation, detect wildcards, and verify projected columns and data types.
"""

import re
from typing import Optional, Dict, List, Set
import sqlglot
from sqlglot import exp
from sqlglot.optimizer import qualify, annotate_types

# Standard logical type equivalence classes
TYPE_EQUIVALENCES = {
    "STRING": {"STRING", "VARCHAR", "TEXT"},
    "NUMERIC": {"NUMERIC", "DECIMAL", "DOUBLE", "FLOAT", "FLOAT64", "REAL"},
    "INTEGER": {"INT64", "INTEGER", "INT", "BIGINT"},
    "TIMESTAMP": {"TIMESTAMP", "DATETIME"},
    "BOOLEAN": {"BOOLEAN", "BOOL"},
    "DATE": {"DATE"}
}


def are_types_compatible(inferred_type: str, expected_type: str) -> bool:
    """Checks if inferred SQL AST type is compatible with expected contract type."""
    inf_clean = inferred_type.upper().split("(")[0].strip()
    exp_clean = expected_type.upper().split("(")[0].strip()

    if inf_clean == exp_clean or inf_clean == "UNKNOWN":
        return True

    for _, eq_set in TYPE_EQUIVALENCES.items():
        if inf_clean in eq_set and exp_clean in eq_set:
            return True

    return False


class SQLContractLinter:
    """Statically lints transformation SQL queries against declared contract schemas."""

    def __init__(self, catalog_schema: Optional[Dict[str, Dict[str, str]]] = None, dialect: str = "bigquery"):
        self.catalog = catalog_schema or {}
        self.dialect = dialect

    def mock_dbt_jinja(self, sql: str) -> str:
        """
        Strips common dbt Jinja macros and tags using regex substitutions.
        Provides a best-effort static approximation so sqlglot can parse SQL models
        without requiring a full dbt compiler runtime.
        """
        # 1. Strip {{ config(...) }} blocks
        sql = re.sub(r"\{\{\s*config\(.*?\)\s*\}\}", "", sql, flags=re.DOTALL)
        # 2. Replace {{ ref('my_table') }} -> my_table
        sql = re.sub(r"\{\{\s*ref\(['\"](.*?)['\"]\)\s*\}\}", r"\1", sql)
        # 3. Replace {{ source('src', 'tbl') }} -> src.tbl
        sql = re.sub(r"\{\{\s*source\(['\"](.*?)['\"],\s*['\"](.*?)['\"]\)\s*\}\}", r"\1.\2", sql)
        # 4. Replace {{ var('param', 'default') }} or {{ var('param') }}
        sql = re.sub(r"\{\{\s*var\(['\"].*?['\"](?:,\s*['\"].*?['\"])?\)\s*\}\}", "'mock_var'", sql)
        # 5. Replace {{ this }} -> this_target
        sql = re.sub(r"\{\{\s*this\s*\}\}", "this_target", sql)
        # 6. Replace scalar variable interpolations like {{ lookback_days }} -> 1
        sql = re.sub(r"\{\{\s*[a-zA-Z0-9_]+\s*\}\}", "1", sql)
        # 7. Strip {% set ... %} blocks
        sql = re.sub(r"\{%\s*set\s+.*?\s*%\}", "", sql)
        # 8. Strip Jinja control tags like {% if ... %}, {% endif %}, {% for ... %}, {% endfor %}
        sql = re.sub(r"\{%.*?%\}", "", sql)
        # 9. Clean any remaining stray {{ ... }}
        sql = re.sub(r"\{\{.*?\}\}", "", sql)
        return sql

    def lint_query(
        self,
        raw_sql: str,
        expected_columns: Dict[str, str],
        model_name: str = "unnamed_model"
    ) -> List[str]:
        violations = []
        clean_sql = self.mock_dbt_jinja(raw_sql)

        try:
            ast = sqlglot.parse_one(clean_sql, read=self.dialect)
            if ast is None:
                return [f"Model '{model_name}': SQL parsed to empty AST."]

            # 1. Prohibit Wildcards (SELECT *, SELECT t.*, SELECT schema.t.*) BEFORE qualify expands them!
            for select_exp in ast.selects:
                if select_exp.find(exp.Star) is not None:
                    violations.append(
                        f"Model '{model_name}': Wildcard projection '{select_exp.sql()}' is prohibited in contract-governed models."
                    )

            # 2. Qualify query against warehouse schema catalog (resolves CTEs, table names, aliases, and JOINs)
            # Register this_target automatically from expected contract columns to support incremental models
            effective_catalog = dict(self.catalog)
            if "this_target" not in effective_catalog:
                effective_catalog["this_target"] = expected_columns

            try:
                ast = qualify.qualify(ast, schema=effective_catalog, dialect=self.dialect, validate_qualify_columns=False)
                ast = annotate_types.annotate_types(ast, schema=effective_catalog)
            except Exception as q_err:
                violations.append(f"Model '{model_name}': Qualification warning: {str(q_err)}")

        except Exception as e:
            return [f"Model '{model_name}': Syntax / AST Parse Failure: {str(e)}"]

        # 3. Extract top-level projected columns and inferred types
        projected_columns: Dict[str, str] = {}
        for select_exp in ast.selects:
            col_name = select_exp.alias_or_name
            if col_name and col_name != "*":
                col_type = select_exp.type.sql(dialect=self.dialect) if select_exp.type else "UNKNOWN"
                projected_columns[col_name] = col_type

        # 4. Check for missing required columns and type compatibility
        for exp_col, exp_type in expected_columns.items():
            if exp_col not in projected_columns:
                violations.append(
                    f"Model '{model_name}': Contract Violation - Missing declared column '{exp_col}' (expected {exp_type})."
                )
            else:
                inferred_type = projected_columns[exp_col]
                if not are_types_compatible(inferred_type, exp_type):
                    violations.append(
                        f"Model '{model_name}': Type Mismatch on '{exp_col}' - Expected {exp_type}, but SQL inferred {inferred_type}."
                    )

        # 5. Check for undeclared extra columns
        extra_columns = set(projected_columns.keys()) - set(expected_columns.keys())
        if extra_columns:
            violations.append(
                f"Model '{model_name}': Contract Violation - Undeclared extra columns projected: {sorted(list(extra_columns))}."
            )

        return violations
