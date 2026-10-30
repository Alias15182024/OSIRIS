"""Condition evaluation and matching engine for declarative detection rules.

Performs deterministic, explainable condition evaluation against normalized OSIRIS
observations (NormalizedEvent, Event model, or dictionary context).
Never uses eval() or dynamic code execution.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Sequence
import uuid

from backend.services.detection.models import ConditionNode


@dataclass
class MatchResult:
    """Outcome of evaluating a condition node against an observation."""

    matched: bool
    details: list[dict[str, Any]] = field(default_factory=list)


def extract_field_value(obs: Any, field_name: str) -> Any:
    """Extract a field or payload path from an observation object or dict."""
    if field_name.startswith("payload."):
        sub_key = field_name[len("payload."):]
        payload = None
        if isinstance(obs, dict):
            payload = obs.get("payload")
        else:
            payload = getattr(obs, "payload", None)

        if isinstance(payload, dict):
            return payload.get(sub_key)
        return None

    if isinstance(obs, dict):
        return obs.get(field_name)

    return getattr(obs, field_name, None)


def _compare_values(actual: Any, operator: str, expected: Any) -> bool:
    """Safely compare actual vs expected value without raising exceptions."""
    op = operator.lower()

    if op in ("exists",):
        return actual is not None
    if op in ("not_exists",):
        return actual is None

    # For other operators, if actual is None, they evaluate to False
    if actual is None:
        return False

    # Ensure boolean types are compared as booleans, not numbers (since in Python bool subclasses int)
    if isinstance(actual, bool) or isinstance(expected, bool):
        if op in ("==", "eq"):
            if isinstance(expected, bool) and isinstance(actual, bool):
                return actual is expected
            return str(actual).lower() == str(expected).lower()
        if op in ("!=", "neq"):
            if isinstance(expected, bool) and isinstance(actual, bool):
                return actual is not expected
            return str(actual).lower() != str(expected).lower()
        return False

    if op in ("==", "eq"):
        # Support string/numeric flexibility where safe (e.g. uid="1000" vs 1000)
        if isinstance(expected, (int, float)) and isinstance(actual, (int, float)):
            return actual == expected
        return str(actual) == str(expected) if (isinstance(expected, str) or isinstance(actual, str)) else actual == expected

    if op in ("!=", "neq"):
        if isinstance(expected, (int, float)) and isinstance(actual, (int, float)):
            return actual != expected
        return str(actual) != str(expected) if (isinstance(expected, str) or isinstance(actual, str)) else actual != expected

    if op in (">", "gt", ">=", "gte", "<", "lt", "<=", "lte"):
        try:
            num_actual = float(actual)
            num_expected = float(expected)
            if op in (">", "gt"):
                return num_actual > num_expected
            if op in (">=", "gte"):
                return num_actual >= num_expected
            if op in ("<", "lt"):
                return num_actual < num_expected
            if op in ("<=", "lte"):
                return num_actual <= num_expected
        except (ValueError, TypeError):
            return False

    if op == "in":
        if isinstance(expected, (list, tuple, set)):
            # If actual is in the collection
            if actual in expected:
                return True
            # Also check string conversions for mixed type resilience
            str_actual = str(actual)
            return any(str(item) == str_actual for item in expected)
        return False

    if op == "not_in":
        if isinstance(expected, (list, tuple, set)):
            if actual in expected:
                return False
            str_actual = str(actual)
            return not any(str(item) == str_actual for item in expected)
        return True

    str_actual = str(actual)
    str_expected = str(expected)

    if op == "contains":
        return str_expected in str_actual

    if op == "startswith":
        return str_actual.startswith(str_expected)

    if op == "endswith":
        return str_actual.endswith(str_expected)

    if op == "regex":
        try:
            # Safe regex search without arbitrary backtracking hazards
            return bool(re.search(str_expected, str_actual))
        except re.error:
            return False

    return False


def evaluate_condition_node(node: ConditionNode, obs: Any) -> MatchResult:
    """Evaluate a ConditionNode AST against an observation.

    Returns a MatchResult with boolean outcome and forensic explainability details.
    """
    # 1. 'all' conjunction (logical AND)
    if node.all_ is not None:
        all_details = []
        for child in node.all_:
            child_res = evaluate_condition_node(child, obs)
            all_details.extend(child_res.details)
            if not child_res.matched:
                return MatchResult(matched=False, details=all_details)
        return MatchResult(matched=True, details=all_details)

    # 2. 'any' disjunction (logical OR)
    if node.any_ is not None:
        any_details = []
        matched_any = False
        matched_details = []
        for child in node.any_:
            child_res = evaluate_condition_node(child, obs)
            any_details.extend(child_res.details)
            if child_res.matched:
                matched_any = True
                matched_details.extend(child_res.details)

        # Include matching details if any matched
        return MatchResult(
            matched=matched_any,
            details=matched_details if matched_any else any_details,
        )

    # 3. 'not' negation (logical NOT)
    if node.not_ is not None:
        child_res = evaluate_condition_node(node.not_, obs)
        inverted = not child_res.matched
        explanation = {
            "operator": "not",
            "passed": inverted,
            "child_details": child_res.details,
        }
        return MatchResult(matched=inverted, details=[explanation])

    # 4. Leaf predicate
    assert node.field is not None and node.operator is not None
    actual = extract_field_value(obs, node.field)
    is_match = _compare_values(actual, node.operator, node.value)

    detail = {
        "field": node.field,
        "operator": node.operator,
        "expected": node.value,
        "actual": actual,
        "passed": is_match,
    }
    return MatchResult(matched=is_match, details=[detail])
