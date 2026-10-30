"""Declarative rule validator for OSIRIS Detection Engine.

Enforces strict schema validation, safe parsing, and bounds checking.
Guarantees zero dynamic code execution (no eval, no exec).
"""
from __future__ import annotations

from typing import Any
import yaml
from pydantic import ValidationError

from backend.services.detection.models import RuleDefinition, RuleValidationError


def validate_rule_dict(data: dict[str, Any]) -> RuleDefinition:
    """Validate a raw dictionary containing a declarative rule definition.

    Raises:
        RuleValidationError: If the structure, operators, or values are invalid.
    """
    if not isinstance(data, dict):
        raise RuleValidationError(f"Rule definition must be a dictionary, got {type(data).__name__}.")

    try:
        return RuleDefinition.model_validate(data)
    except ValidationError as exc:
        # Flatten Pydantic errors into readable, actionable error messages
        details = []
        for err in exc.errors():
            loc = " -> ".join(str(p) for p in err["loc"])
            msg = err["msg"]
            details.append(f"[{loc}]: {msg}")
        raise RuleValidationError(f"Rule validation failed:\n" + "\n".join(details)) from exc


def validate_rule_yaml(yaml_content: str) -> RuleDefinition:
    """Safely parse and validate a YAML declarative rule definition.

    Security guarantees:
    - Strictly uses `yaml.safe_load` to prevent arbitrary code execution / object instantiation.
    - Prohibits custom Python tags and deserialization attacks.
    - Enforces structure bounds.

    Raises:
        RuleValidationError: On YAML syntax errors or rule schema violations.
    """
    if not isinstance(yaml_content, str):
        raise RuleValidationError(f"YAML content must be a string, got {type(yaml_content).__name__}.")

    if not yaml_content.strip():
        raise RuleValidationError("Rule definition cannot be empty.")

    try:
        data = yaml.safe_load(yaml_content)
    except yaml.YAMLError as exc:
        raise RuleValidationError(f"Malformed YAML syntax: {exc}") from exc

    return validate_rule_dict(data)
