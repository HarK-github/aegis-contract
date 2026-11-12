"""
Structural Contract Diff Engine for AegisContract.
Analyzes differences between two contract versions and classifies them into:
- MAJOR: Breaking changes (dropped columns, changed types, newly required fields, narrowed enums)
- MINOR: Additive non-breaking changes (new optional fields, fields made optional, expanded enums)
- PATCH: Metadata / non-functional documentation updates
"""

from dataclasses import dataclass
from typing import Dict, Any, List, Set


@dataclass
class ContractDiffResult:
    old_version: str
    new_version: str
    bump_type: str  # "MAJOR", "MINOR", "PATCH", or "NONE"
    is_breaking: bool
    breaking_reasons: List[str]
    additive_reasons: List[str]
    metadata_reasons: List[str]

    def to_markdown_report(self) -> str:
        """Renders an executive markdown summary for GitHub PR comments."""
        status_emoji = "🚨 BREAKING CHANGE" if self.is_breaking else ("✨ ADDITIVE CHANGE" if self.bump_type == "MINOR" else "📝 METADATA UPDATE")
        lines = [
            f"### AegisContract Diff Analysis: {status_emoji}",
            f"- **Old Version:** `{self.old_version}` | **New Version:** `{self.new_version}`",
            f"- **Recommended SemVer Bump:** `{self.bump_type}`",
            ""
        ]

        if self.breaking_reasons:
            lines.append("#### ❌ Breaking Changes (Requires Downstream Consumer Sign-off):")
            for r in self.breaking_reasons:
                lines.append(f"- {r}")
            lines.append("")

        if self.additive_reasons:
            lines.append("#### ✅ Additive / Backward-Compatible Changes:")
            for r in self.additive_reasons:
                lines.append(f"- {r}")
            lines.append("")

        if self.metadata_reasons:
            lines.append("#### ℹ️ Metadata / Documentation Updates:")
            for r in self.metadata_reasons:
                lines.append(f"- {r}")
            lines.append("")

        return "\n".join(lines)


def compare_contracts(old_spec: Dict[str, Any], new_spec: Dict[str, Any]) -> ContractDiffResult:
    """Performs deep semantic comparison between two data contracts."""
    old_ver = str(old_spec.get("version", "0.0.0"))
    new_ver = str(new_spec.get("version", "0.0.0"))

    breaking: List[str] = []
    additive: List[str] = []
    metadata: List[str] = []

    # 1. Compare Edge Schema Properties
    old_edge_props = old_spec.get("edge_schema", {}).get("properties", {})
    new_edge_props = new_spec.get("edge_schema", {}).get("properties", {})
    old_edge_req = set(old_spec.get("edge_schema", {}).get("required", []))
    new_edge_req = set(new_spec.get("edge_schema", {}).get("required", []))

    # Check deleted edge fields
    for col, old_rule in old_edge_props.items():
        if col not in new_edge_props:
            breaking.append(f"Edge field '{col}' was deleted.")
        else:
            new_rule = new_edge_props[col]
            # Check type changes
            if old_rule.get("type") != new_rule.get("type"):
                breaking.append(
                    f"Edge field '{col}' changed type from '{old_rule.get('type')}' to '{new_rule.get('type')}'."
                )
            # Check enum expansions / contractions
            old_enum = set(old_rule.get("enum") or [])
            new_enum = set(new_rule.get("enum") or [])
            if old_enum and new_enum:
                removed_enums = old_enum - new_enum
                added_enums = new_enum - old_enum
                if removed_enums:
                    breaking.append(f"Edge field '{col}' removed allowed enum values: {sorted(list(removed_enums))}.")
                if added_enums:
                    additive.append(f"Edge field '{col}' added new allowed enum values: {sorted(list(added_enums))}.")

    # Check newly required edge fields (Breaking)
    newly_required = new_edge_req - old_edge_req
    for col in newly_required:
        breaking.append(f"Field '{col}' is now REQUIRED (previously optional or absent).")

    # Check fields made optional (Additive)
    made_optional = old_edge_req - new_edge_req
    for col in made_optional:
        if col in new_edge_props:
            additive.append(f"Field '{col}' was relaxed to OPTIONAL.")

    # Check newly added optional edge fields (Additive)
    newly_added_edge = set(new_edge_props.keys()) - set(old_edge_props.keys())
    for col in newly_added_edge:
        if col not in newly_required:
            additive.append(f"New optional edge field '{col}' added.")

    # 2. Compare Warehouse Columns
    old_wh_cols = old_spec.get("warehouse_model", {}).get("columns", {})
    new_wh_cols = new_spec.get("warehouse_model", {}).get("columns", {})

    for col, old_type in old_wh_cols.items():
        if col not in new_wh_cols:
            breaking.append(f"Warehouse mart column '{col}' was deleted.")
        elif old_type != new_wh_cols[col]:
            breaking.append(f"Warehouse mart column '{col}' changed type from '{old_type}' to '{new_wh_cols[col]}'.")

    new_wh_added = set(new_wh_cols.keys()) - set(old_wh_cols.keys())
    for col in new_wh_added:
        additive.append(f"New warehouse mart column '{col}' added.")

    # 3. Check Metadata
    for meta_key in ["owner", "status", "target_table"]:
        old_val = old_spec.get(meta_key) or old_spec.get("warehouse_model", {}).get(meta_key)
        new_val = new_spec.get(meta_key) or new_spec.get("warehouse_model", {}).get(meta_key)
        if old_val != new_val and old_val is not None and new_val is not None:
            metadata.append(f"Contract {meta_key} changed from '{old_val}' to '{new_val}'.")

    # Determine SemVer classification
    if breaking:
        bump = "MAJOR"
        is_breaking = True
    elif additive:
        bump = "MINOR"
        is_breaking = False
    elif metadata or old_ver != new_ver:
        bump = "PATCH"
        is_breaking = False
    else:
        bump = "NONE"
        is_breaking = False

    return ContractDiffResult(
        old_version=old_ver,
        new_version=new_ver,
        bump_type=bump,
        is_breaking=is_breaking,
        breaking_reasons=breaking,
        additive_reasons=additive,
        metadata_reasons=metadata
    )
