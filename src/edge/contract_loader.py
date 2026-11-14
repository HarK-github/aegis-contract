"""
Dynamic Contract Loader for AegisContract.
Compiles declarative YAML data contracts into strict Pydantic V2 models at runtime,
avoiding schema duplication while enforcing zero-trust type validation.
"""

import uuid
import yaml
from datetime import datetime
from typing import Any, Type, Optional, Literal
from pydantic import BaseModel, Field, create_model, ConfigDict, ValidationError

TYPE_MAP = {
    ("string", None): str,
    ("string", "uuid"): uuid.UUID,
    ("string", "date-time"): datetime,
    ("integer", None): int,
    ("number", None): float,
    ("float", None): float,
    ("boolean", None): bool,
}


def sanitize_validation_errors(errors: list[dict]) -> list[dict]:
    """Strips sensitive raw input and ctx keys from Pydantic ValidationError dicts."""
    return [{k: v for k, v in err.items() if k not in ("input", "ctx")} for err in errors]


class CompiledContract:
    """Wrapper holding a compiled Pydantic model and its parent contract specification."""

    def __init__(self, spec: dict, model: Type[BaseModel]):
        self.spec = spec
        self.contract_id = spec.get("contract_id", "unknown.contract")
        self.version = spec.get("version", "0.0.0")
        self.model = model
        self.edge_schema = spec.get("edge_schema", {})
        self.warehouse_model = spec.get("warehouse_model", {})
        self.runtime_assertions = spec.get("runtime_assertions", [])

    def validate_bytes(self, raw_bytes: bytes) -> tuple[bool, Optional[dict], Optional[list[dict]]]:
        """
        Validates raw HTTP request body bytes strictly.
        Using model_validate_json allows ISO date-time strings and UUID strings
        to be parsed into datetime and UUID objects even with strict=True,
        while strictly rejecting invalid type casting (e.g. "123" into int).
        """
        try:
            instance = self.model.model_validate_json(raw_bytes)
            # Dump to serializable dictionary
            return True, instance.model_dump(mode="json"), None
        except ValidationError as err:
            return False, None, sanitize_validation_errors(err.errors())
        except Exception as e:
            return False, None, [{"type": "unparseable_json", "msg": str(e), "loc": ["body"]}]


def compile_contract_from_yaml(yaml_path: str) -> CompiledContract:
    """Reads a contract YAML and dynamically compiles its edge_schema into a Pydantic V2 model."""
    with open(yaml_path, "r", encoding="utf-8") as f:
        spec = yaml.safe_load(f)

    return compile_contract_from_dict(spec)


SUPPORTED_PROPERTY_KEYWORDS = {
    "type", "format", "enum", "minimum", "maximum", "pattern", "description"
}
SUPPORTED_BASE_TYPES = {"string", "integer", "number", "float", "boolean"}


def compile_contract_from_dict(spec: dict) -> CompiledContract:
    """Compiles contract dictionary spec into a CompiledContract."""
    properties = spec.get("edge_schema", {}).get("properties", {})
    required = set(spec.get("edge_schema", {}).get("required", []))
    fields: dict[str, Any] = {}

    for name, prop in properties.items():
        if not isinstance(prop, dict):
            raise ValueError(f"Property '{name}' definition must be a mapping")

        # Check for unsupported keywords
        unsupported = sorted(list(set(prop.keys()) - SUPPORTED_PROPERTY_KEYWORDS))
        if unsupported:
            raise ValueError(
                f"Unsupported keyword(s) {unsupported} in property '{name}'. "
                f"Supported: {sorted(list(SUPPORTED_PROPERTY_KEYWORDS))}"
            )

        prop_type = prop.get("type")
        if prop_type not in SUPPORTED_BASE_TYPES:
            raise ValueError(
                f"Unknown or unsupported property type '{prop_type}' in property '{name}'. "
                f"Supported types: {sorted(list(SUPPORTED_BASE_TYPES))}"
            )

        prop_format = prop.get("format")
        if prop_format is not None:
            if prop_type != "string" or prop_format not in ("uuid", "date-time"):
                raise ValueError(
                    f"Unsupported format '{prop_format}' for type '{prop_type}' in property '{name}'"
                )

        enum_values = prop.get("enum")

        # 1. Resolve Python typing
        if enum_values and isinstance(enum_values, list) and len(enum_values) > 0:
            # Dynamically build Literal[tuple(enum_values)]
            py_type = Literal[tuple(enum_values)]  # type: ignore
        else:
            if (prop_type, prop_format) not in TYPE_MAP:
                raise ValueError(
                    f"No type mapping found for property '{name}' (type='{prop_type}', format='{prop_format}')"
                )
            py_type = TYPE_MAP[(prop_type, prop_format)]

        is_required = name in required
        default_val = ... if is_required else None

        # 2. Build constraint attributes for Field(...)
        field_kwargs: dict[str, Any] = {"default": default_val}
        if "minimum" in prop:
            field_kwargs["ge"] = prop["minimum"]
        if "maximum" in prop:
            field_kwargs["le"] = prop["maximum"]
        if "pattern" in prop:
            field_kwargs["pattern"] = prop["pattern"]

        fields[name] = (py_type, Field(**field_kwargs))

    # 3. Create model dynamically with strict mode and forbidden extra fields
    model_name = spec.get("contract_id", "DynamicContract").replace(".", "_")
    pydantic_model = create_model(
        model_name,
        __config__=ConfigDict(strict=True, extra="forbid"),
        **fields
    )

    return CompiledContract(spec=spec, model=pydantic_model)
