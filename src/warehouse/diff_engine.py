"""
Structural Contract Diff Engine for AegisContract.
Analyzes differences between two contract versions across two distinct perspectives:
1. Producer API SemVer: What emitters are allowed to send (MAJOR = breaking, MINOR = additive, PATCH = metadata)
2. Downstream Consumer Blast Radius: Highlights when producer additions (e.g. newly optional fields or expanded enums)
   could break downstream ETL transforms, SQL queries, or ML models expecting exhaustive schemas.
"""

from dataclasses import dataclass
from typing import Dict, Any, List, Set


@dataclass
class ContractDiffResult:
    old_version: str
    new_version: str
    bump_type: str  # "MAJOR", "MINOR", "PATCH", or "NONE"
    is_breaking_for_producer: bool
    is_breaking_for_consumer: bool
    producer_breaking_reasons: List[str]
    producer_additive_reasons: List[str]
    consumer_breaking_warnings: List[str]
    metadata_reasons: List[str]

    @property
    def is_breaking(self) -> bool:
        """Conservative breaking check: True if breaking for either producer or consumer."""
        return self.is_breaking_for_producer or self.is_breaking_for_consumer

    @property
    def breaking_reasons(self) -> List[str]:
        return self.producer_breaking_reasons + self.consumer_breaking_warnings

    @property
    def additive_reasons(self) -> List[str]:
        return self.producer_additive_reasons

    def to_markdown_report(self) -> str:
        """Renders an executive markdown summary for GitHub PR comments."""
        if self.is_breaking_for_producer:
            status_emoji = "🚨 MAJOR BREAKING CHANGE (Producer & Consumer Incompatible)"
        elif self.is_breaking_for_consumer:
            status_emoji = "⚠️ MINOR PRODUCER (Downstream Consumer Attention Required)"
        elif self.bump_type == "MINOR":
            status_emoji = "✨ MINOR ADDITIVE (Backward-Compatible)"
        else:
            status_emoji = "📝 PATCH (Metadata / Documentation Only)"

        lines = [
            f"### AegisContract Diff Analysis: {status_emoji}",
            f"- **Old Version:** `{self.old_version}` | **New Version:** `{self.new_version}`",
            f"- **Producer SemVer Bump:** `{self.bump_type}`",
            f"- **Consumer Breaking Risk:** `{'YES - Review Downstream Models' if self.is_breaking_for_consumer else 'NONE'}`",
            ""
        ]

        if self.producer_breaking_reasons:
            lines.append("#### ❌ Producer Breaking Changes (Upstream Emitters Must Update):")
            for r in self.producer_breaking_reasons:
                lines.append(f"- {r}")
            lines.append("")

        if self.consumer_breaking_warnings:
            lines.append("#### ⚠️ Consumer Breaking Warnings (Downstream SQL / ML Models May Break):")
            for r in self.consumer_breaking_warnings:
                lines.append(f"- {r}")
            lines.append("")

        if self.producer_additive_reasons:
            lines.append("#### ✅ Producer Additive Changes (Backward-Compatible for Emitters):")
            for r in self.producer_additive_reasons:
                lines.append(f"- {r}")
            lines.append("")

        if self.metadata_reasons:
            lines.append("#### ℹ️ Metadata / Documentation Updates:")
            for r in self.metadata_reasons:
                lines.append(f"- {r}")
            lines.append("")

        return "\n".join(lines)


def compare_contracts(old_spec: Dict[str, Any], new_spec: Dict[str, Any]) -> ContractDiffResult:
    """Performs structural schema comparison between two data contracts across producer & consumer vectors."""
    old_ver = str(old_spec.get("version", "0.0.0"))
    new_ver = str(new_spec.get("version", "0.0.0"))

    prod_breaking: List[str] = []
    prod_additive: List[str] = []
    consumer_warnings: List[str] = []
    metadata: List[str] = []

    # 1. Compare Edge Schema Properties
    old_edge_props = old_spec.get("edge_schema", {}).get("properties", {})
    new_edge_props = new_spec.get("edge_schema", {}).get("properties", {})
    old_edge_req = set(old_spec.get("edge_schema", {}).get("required", []))
    new_edge_req = set(new_spec.get("edge_schema", {}).get("required", []))

    # Check deleted edge fields
    for col, old_rule in old_edge_props.items():
        if col not in new_edge_props:
            prod_breaking.append(f"Edge field '{col}' was deleted.")
            consumer_warnings.append(f"Downstream Consumer Impact: Field '{col}' removed, breaking downstream pipelines.")
        else:
            new_rule = new_edge_props[col]
            # Check type changes
            if old_rule.get("type") != new_rule.get("type"):
                prod_breaking.append(
                    f"Edge field '{col}' changed type from '{old_rule.get('type')}' to '{new_rule.get('type')}'."
                )
                consumer_warnings.append(
                    f"Downstream Consumer Impact: Field '{col}' type changed to '{new_rule.get('type')}'."
                )
            # Check enum expansions / contractions
            old_enum = set(old_rule.get("enum") or [])
            new_enum = set(new_rule.get("enum") or [])
            if old_enum and new_enum:
                removed_enums = old_enum - new_enum
                added_enums = new_enum - old_enum
                if removed_enums:
                    prod_breaking.append(f"Edge field '{col}' removed allowed enum values: {sorted(list(removed_enums))}.")
                if added_enums:
                    prod_additive.append(f"Edge field '{col}' added new allowed enum values: {sorted(list(added_enums))}.")
                    # Note: Enum expansion is additive for producer, but can BREAK non-exhaustive consumer CASE / match statements!
                    consumer_warnings.append(
                        f"Downstream Consumer Risk: Field '{col}' added enum variants {sorted(list(added_enums))}, which may break exhaustive consumer transforms."
                    )

    # Check newly required edge fields (Breaking for Producer)
    newly_required = new_edge_req - old_edge_req
    for col in newly_required:
        prod_breaking.append(f"Field '{col}' is now REQUIRED (previously optional or absent).")

    # Check fields made optional (Additive for Producer, but potentially BREAKING for Consumer!)
    made_optional = old_edge_req - new_edge_req
    for col in made_optional:
        if col in new_edge_props:
            prod_additive.append(f"Field '{col}' was relaxed to OPTIONAL for emitters.")
            consumer_warnings.append(
                f"Downstream Consumer Risk: Field '{col}' is now nullable/optional; downstream queries assuming NOT NULL may encounter NULLs."
            )

    # Check newly added optional edge fields (Additive for Producer)
    newly_added_edge = set(new_edge_props.keys()) - set(old_edge_props.keys())
    for col in newly_added_edge:
        if col not in newly_required:
            prod_additive.append(f"New optional edge field '{col}' added.")

    # 2. Compare Warehouse Columns
    old_wh_cols = old_spec.get("warehouse_model", {}).get("columns", {})
    new_wh_cols = new_spec.get("warehouse_model", {}).get("columns", {})

    for col, old_type in old_wh_cols.items():
        if col not in new_wh_cols:
            consumer_warnings.append(f"Warehouse mart column '{col}' was deleted.")
        elif old_type != new_wh_cols[col]:
            consumer_warnings.append(f"Warehouse mart column '{col}' changed type from '{old_type}' to '{new_wh_cols[col]}'.")

    new_wh_added = set(new_wh_cols.keys()) - set(old_wh_cols.keys())
    for col in new_wh_added:
        prod_additive.append(f"New warehouse mart column '{col}' added to target table.")

    # 3. Check Metadata
    for meta_key in ["owner", "status", "target_table"]:
        old_val = old_spec.get(meta_key) or old_spec.get("warehouse_model", {}).get(meta_key)
        new_val = new_spec.get(meta_key) or new_spec.get("warehouse_model", {}).get(meta_key)
        if old_val != new_val and old_val is not None and new_val is not None:
            metadata.append(f"Contract {meta_key} changed from '{old_val}' to '{new_val}'.")

    # Determine SemVer classification
    is_breaking_prod = len(prod_breaking) > 0
    is_breaking_cons = len(consumer_warnings) > 0

    if is_breaking_prod:
        bump = "MAJOR"
    elif prod_additive:
        bump = "MINOR"
    elif metadata or old_ver != new_ver:
        bump = "PATCH"
    else:
        bump = "NONE"

    return ContractDiffResult(
        old_version=old_ver,
        new_version=new_ver,
        bump_type=bump,
        is_breaking_for_producer=is_breaking_prod,
        is_breaking_for_consumer=is_breaking_cons,
        producer_breaking_reasons=prod_breaking,
        producer_additive_reasons=prod_additive,
        consumer_breaking_warnings=consumer_warnings,
        metadata_reasons=metadata
    )
