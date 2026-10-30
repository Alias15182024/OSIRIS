"""Unit tests for the Single-Event Detection Engine (Phase 2 Milestone 2.4).

Verifies:
- All comparison operators (==, !=, >, >=, <, <=, in, not_in, contains, startswith, endswith, regex, exists, not_exists).
- Complex nested boolean combinators (all, any, not).
- Missing context and safe null handling.
- Input polymorphism (NormalizedEvent, Event model, raw dict).
- Explainable matched conditions and forensic provenance.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
import pytest

from backend.db.models.event import Event
from backend.services.detection.engine import DetectionEngine
from backend.services.detection.matcher import evaluate_condition_node, extract_field_value
from backend.services.detection.models import ConditionNode, RuleDefinition
from backend.services.detection.validator import validate_rule_yaml
from backend.services.events.schemas import NormalizedEvent


def _make_normalized_event(
    host_id: uuid.UUID | None = None,
    event_type: str = "proc:exec",
    action: str = "start",
    command: str = "/bin/bash",
    uid: int = 1000,
    username: str = "alice",
    object_path: str | None = None,
    payload: dict | None = None,
) -> NormalizedEvent:
    now = datetime.now(timezone.utc)
    return NormalizedEvent(
        id=uuid.uuid4(),
        host_id=host_id or uuid.uuid4(),
        timestamp=now,
        ingested_at=now,
        source="proc",
        event_type=event_type,
        action=action,
        severity="info",
        uid=uid,
        username=username,
        command=command,
        object_path=object_path,
        payload=payload,
    )


class TestSingleEventMatching:
    """Test single-event declarative condition evaluation."""

    def test_equality_and_inequality(self) -> None:
        ev = _make_normalized_event(command="sudo su", uid=0, username="root")

        # Equal
        node_eq = ConditionNode(field="username", operator="==", value="root")
        assert evaluate_condition_node(node_eq, ev).matched is True

        # Not equal
        node_neq = ConditionNode(field="username", operator="!=", value="root")
        assert evaluate_condition_node(node_neq, ev).matched is False

    def test_numeric_comparisons(self) -> None:
        ev_user = _make_normalized_event(uid=1001)
        ev_root = _make_normalized_event(uid=0)

        node_gt = ConditionNode(field="uid", operator=">", value=1000)
        assert evaluate_condition_node(node_gt, ev_user).matched is True
        assert evaluate_condition_node(node_gt, ev_root).matched is False

        node_lte = ConditionNode(field="uid", operator="<=", value=1000)
        assert evaluate_condition_node(node_lte, ev_user).matched is False
        assert evaluate_condition_node(node_lte, ev_root).matched is True

    def test_string_operators(self) -> None:
        ev = _make_normalized_event(command="/usr/bin/cat /etc/shadow")

        node_startswith = ConditionNode(field="command", operator="startswith", value="/usr/bin/")
        assert evaluate_condition_node(node_startswith, ev).matched is True

        node_endswith = ConditionNode(field="command", operator="endswith", value="/etc/shadow")
        assert evaluate_condition_node(node_endswith, ev).matched is True

        node_contains = ConditionNode(field="command", operator="contains", value="cat")
        assert evaluate_condition_node(node_contains, ev).matched is True

        node_regex = ConditionNode(field="command", operator="regex", value=r"cat\s+/etc/\w+")
        assert evaluate_condition_node(node_regex, ev).matched is True

    def test_collection_operators(self) -> None:
        ev_login = _make_normalized_event(event_type="auth:login:fail")
        ev_other = _make_normalized_event(event_type="fs:read")

        node_in = ConditionNode(
            field="event_type",
            operator="in",
            value=["auth:login:fail", "auth:ssh:fail"]
        )
        assert evaluate_condition_node(node_in, ev_login).matched is True
        assert evaluate_condition_node(node_in, ev_other).matched is False

        node_not_in = ConditionNode(
            field="event_type",
            operator="not_in",
            value=["fs:read", "fs:write"]
        )
        assert evaluate_condition_node(node_not_in, ev_login).matched is True
        assert evaluate_condition_node(node_not_in, ev_other).matched is False

    def test_null_and_existence_operators(self) -> None:
        ev_with_path = _make_normalized_event(object_path="/var/log/auth.log")
        ev_without_path = _make_normalized_event(object_path=None)

        node_exists = ConditionNode(field="object_path", operator="exists")
        assert evaluate_condition_node(node_exists, ev_with_path).matched is True
        assert evaluate_condition_node(node_exists, ev_without_path).matched is False

        node_not_exists = ConditionNode(field="object_path", operator="not_exists")
        assert evaluate_condition_node(node_not_exists, ev_with_path).matched is False
        assert evaluate_condition_node(node_not_exists, ev_without_path).matched is True

    def test_payload_subfield_lookup(self) -> None:
        ev = _make_normalized_event(payload={"remote_host": "192.168.1.100", "terminal": "pts/1"})

        node_payload = ConditionNode(field="payload.remote_host", operator="==", value="192.168.1.100")
        assert evaluate_condition_node(node_payload, ev).matched is True

        node_missing_payload = ConditionNode(field="payload.nonexistent", operator="exists")
        assert evaluate_condition_node(node_missing_payload, ev).matched is False

    def test_complex_boolean_logic(self) -> None:
        # Rule: (event_type == 'proc:exec' AND (command contains 'sudo' OR uid == 0)) AND NOT (username == 'root')
        raw_yaml = """
        rule_id: TEST-BOOL-001
        name: Boolean Test
        category: privilege_escalation
        severity: high
        rule_type: single_event
        conditions:
          all:
            - field: event_type
              operator: "=="
              value: "proc:exec"
            - any:
                - field: command
                  operator: contains
                  value: "sudo"
                - field: uid
                  operator: "=="
                  value: 0
            - not:
                field: username
                operator: "=="
                value: "root"
        """
        rule = validate_rule_yaml(raw_yaml)
        engine = DetectionEngine([rule])

        # Match: user alice running sudo
        ev_match = _make_normalized_event(event_type="proc:exec", command="sudo id", uid=1000, username="alice")
        matches = engine.evaluate_event(ev_match)
        assert len(matches) == 1
        assert matches[0].rule_id == "TEST-BOOL-001"

        # Non-match: user root running sudo (excluded by NOT condition)
        ev_root = _make_normalized_event(event_type="proc:exec", command="sudo id", uid=0, username="root")
        assert len(engine.evaluate_event(ev_root)) == 0

        # Non-match: user alice running normal command (doesn't satisfy ANY)
        ev_normal = _make_normalized_event(event_type="proc:exec", command="ls -la", uid=1000, username="alice")
        assert len(engine.evaluate_event(ev_normal)) == 0

    def test_explainability_payload(self) -> None:
        raw_yaml = """
        rule_id: TEST-EXPLAIN-001
        name: Explain Test
        category: reconnaissance
        severity: low
        rule_type: single_event
        conditions:
          all:
            - field: command
              operator: startswith
              value: "whoami"
        """
        rule = validate_rule_yaml(raw_yaml)
        engine = DetectionEngine([rule])

        ev = _make_normalized_event(command="whoami")
        matches = engine.evaluate_event(ev)
        assert len(matches) == 1
        m = matches[0]
        assert "conditions" in m.matched_conditions
        detail = m.matched_conditions["conditions"][0]
        assert detail["field"] == "command"
        assert detail["operator"] == "startswith"
        assert detail["actual"] == "whoami"
        assert detail["expected"] == "whoami"
        assert detail["passed"] is True

    def test_sqlalchemy_model_input(self) -> None:
        """Test engine directly against SQLAlchemy Event model instance."""
        host_id = uuid.uuid4()
        now = datetime.now(timezone.utc)
        ev_model = Event(
            id=uuid.uuid4(),
            host_id=host_id,
            timestamp=now,
            ingested_at=now,
            source="proc",
            event_type="proc:exec",
            action="start",
            severity="info",
            uid=1000,
            username="bob",
            command="sudo su",
        )

        raw_yaml = """
        rule_id: TEST-ORM-001
        name: ORM Event Test
        category: privilege_escalation
        severity: high
        rule_type: single_event
        conditions:
          all:
            - field: command
              operator: contains
              value: "sudo su"
        """
        rule = validate_rule_yaml(raw_yaml)
        engine = DetectionEngine([rule])

        matches = engine.evaluate_event(ev_model)
        assert len(matches) == 1
        assert matches[0].host_id == host_id
        assert matches[0].primary_event_id == ev_model.id

    def test_boolean_comparison_safety(self) -> None:
        """Booleans should not be confused with numeric 0/1."""
        ev_root = _make_normalized_event(uid=0)
        node_bool_check = ConditionNode(field="uid", operator="==", value=False)
        # uid=0 should NOT match value=False
        assert evaluate_condition_node(node_bool_check, ev_root).matched is False

        ev_success = _make_normalized_event(payload={"is_admin": True})
        node_true_check = ConditionNode(field="payload.is_admin", operator="==", value=True)
        assert evaluate_condition_node(node_true_check, ev_success).matched is True

    def test_idempotent_rule_registration(self) -> None:
        """Adding a rule multiple times must not duplicate internal rule instances."""
        raw_yaml = """
        rule_id: DUP-TEST-001
        name: Dup Test
        category: reconnaissance
        severity: low
        rule_type: single_event
        conditions:
          all:
            - field: command
              operator: "=="
              value: "id"
        """
        rule = validate_rule_yaml(raw_yaml)
        engine = DetectionEngine()
        engine.add_rule(rule)
        engine.add_rule(rule)

        assert len(engine._single_event_rules) == 1
        assert len(engine._rules) == 1

