"""Detection Engine domain models and data contracts.

Defines the declarative rule structure, condition AST, sequence definitions,
and evaluation results.
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any, Literal, Optional, Union
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


VALID_RULE_SEVERITIES = ("info", "low", "medium", "high", "critical")
VALID_RULE_TYPES = ("single_event", "sequence")
VALID_CATEGORIES = (
    "privilege_escalation",
    "suspicious_authentication",
    "reconnaissance",
    "lateral_movement",
    "persistence",
    "defense_evasion",
    "execution",
    "file_integrity",
)

VALID_OPERATORS = frozenset({
    "==", "eq",
    "!=", "neq",
    ">", "gt",
    ">=", "gte",
    "<", "lt",
    "<=", "lte",
    "in", "not_in",
    "contains",
    "startswith",
    "endswith",
    "regex",
    "exists",
    "not_exists",
})

ALLOWED_FIELDS = frozenset({
    "event_type",
    "action",
    "source",
    "severity",
    "uid",
    "username",
    "pid",
    "ppid",
    "command",
    "process_id",
    "session_id",
    "object_type",
    "object_path",
    "success",
    "result",
    "host_id",
    "timestamp",
})


class RuleValidationError(ValueError):
    """Raised when a declarative detection rule fails validation."""
    pass


class ConditionNode(BaseModel):
    """AST node for declarative conditions supporting nested boolean logic and leaf predicates."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    # Boolean combinators
    all_: Optional[list[ConditionNode]] = Field(default=None, alias="all")
    any_: Optional[list[ConditionNode]] = Field(default=None, alias="any")
    not_: Optional[ConditionNode] = Field(default=None, alias="not")

    # Leaf predicate fields
    field: Optional[str] = None
    operator: Optional[str] = None
    value: Optional[Any] = None

    @model_validator(mode="after")
    def validate_node(self) -> ConditionNode:
        has_all = self.all_ is not None
        has_any = self.any_ is not None
        has_not = self.not_ is not None
        has_leaf = self.field is not None or self.operator is not None

        active_modes = sum([has_all, has_any, has_not, has_leaf])
        if active_modes == 0:
            raise RuleValidationError("Condition node must define either 'all', 'any', 'not', or a leaf predicate ('field' + 'operator').")
        if active_modes > 1:
            raise RuleValidationError("Condition node cannot combine boolean combinators ('all', 'any', 'not') with each other or with leaf predicates in the same node.")

        if has_leaf:
            if not self.field:
                raise RuleValidationError("Leaf condition predicate requires 'field'.")
            if not self.operator:
                raise RuleValidationError("Leaf condition predicate requires 'operator'.")

            op = self.operator.lower()
            if op not in VALID_OPERATORS:
                raise RuleValidationError(f"Unsupported operator '{self.operator}'. Must be one of: {sorted(VALID_OPERATORS)}.")

            # Validate field name: either standard field or payload.<key>
            field_name = self.field
            if not (field_name in ALLOWED_FIELDS or field_name.startswith("payload.")):
                raise RuleValidationError(
                    f"Unsupported field '{self.field}'. Allowed fields are: {sorted(ALLOWED_FIELDS)} or 'payload.<key>'."
                )

            # Bound value types for specific operators
            if op in ("in", "not_in") and not isinstance(self.value, (list, tuple, set)):
                raise RuleValidationError(f"Operator '{self.operator}' requires a list/array value.")
            if op in (">", "gt", ">=", "gte", "<", "lt", "<=", "lte") and not isinstance(self.value, (int, float)):
                raise RuleValidationError(f"Numeric comparison '{self.operator}' requires a numeric value.")
            if op in ("startswith", "endswith", "contains", "regex") and not isinstance(self.value, str):
                raise RuleValidationError(f"String operator '{self.operator}' requires a string value.")
            if op == "regex":
                try:
                    re.compile(str(self.value))
                except re.error as exc:
                    raise RuleValidationError(f"Invalid regular expression '{self.value}': {exc}") from exc

        if has_all and len(self.all_ or []) == 0:
            raise RuleValidationError("'all' list cannot be empty.")
        if has_any and len(self.any_ or []) == 0:
            raise RuleValidationError("'any' list cannot be empty.")

        return self


class SequenceStage(BaseModel):
    """A single stage in a multi-event sequence rule."""

    model_config = ConfigDict(extra="forbid")

    stage_id: str
    conditions: ConditionNode
    min_count: int = Field(default=1, ge=1, le=100)
    match_fields: list[str] = Field(default_factory=list)

    @field_validator("match_fields")
    @classmethod
    def validate_match_fields(cls, v: list[str]) -> list[str]:
        for f in v:
            if not (f in ALLOWED_FIELDS or f.startswith("payload.")):
                raise RuleValidationError(f"Invalid match_field '{f}' in sequence stage.")
        return v


class SequenceDefinition(BaseModel):
    """Container for sequence-based detection rules."""

    model_config = ConfigDict(extra="forbid")

    time_window_seconds: int = Field(..., ge=1, le=86400)
    stages: list[SequenceStage] = Field(..., min_length=2, max_length=20)


class RuleDefinition(BaseModel):
    """Complete declarative security detection rule definition."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(..., min_length=3, max_length=100)
    name: str = Field(..., min_length=3, max_length=255)
    description: Optional[str] = None
    category: str
    severity: str
    enabled: bool = True
    version: int = Field(default=1, ge=1)
    rule_type: str = Field(default="single_event")
    explanation: Optional[str] = None
    conditions: Optional[ConditionNode] = None
    sequence: Optional[SequenceDefinition] = None
    metadata: Optional[dict[str, Any]] = None

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        v_lower = v.lower()
        if v_lower not in VALID_RULE_SEVERITIES:
            raise RuleValidationError(f"Invalid severity '{v}'. Must be one of: {VALID_RULE_SEVERITIES}.")
        return v_lower

    @field_validator("rule_type")
    @classmethod
    def validate_rule_type(cls, v: str) -> str:
        v_lower = v.lower()
        if v_lower not in VALID_RULE_TYPES:
            raise RuleValidationError(f"Invalid rule_type '{v}'. Must be one of: {VALID_RULE_TYPES}.")
        return v_lower

    @model_validator(mode="after")
    def validate_rule_structure(self) -> RuleDefinition:
        if self.rule_type == "single_event":
            if self.conditions is None:
                raise RuleValidationError("Single-event rule requires 'conditions'.")
            if self.sequence is not None:
                raise RuleValidationError("Single-event rule cannot include 'sequence'.")
        elif self.rule_type == "sequence":
            if self.sequence is None:
                raise RuleValidationError("Sequence rule requires 'sequence' configuration.")
            if self.conditions is not None:
                raise RuleValidationError("Sequence rule must define conditions inside sequence stages, not top-level 'conditions'.")

        return self


class DetectionMatch(BaseModel):
    """Forensically sound detection match record generated by the engine."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str
    rule_version: int
    host_id: uuid.UUID
    timestamp: datetime
    severity: str
    title: str
    description: Optional[str] = None
    category: str
    explanation: Optional[str] = None
    matched_conditions: dict[str, Any]
    evidence: dict[str, Any]
    triggering_event_ids: list[uuid.UUID]
    primary_event_id: Optional[uuid.UUID] = None
    process_id: Optional[uuid.UUID] = None
    session_id: Optional[uuid.UUID] = None
    dedup_hash: str
