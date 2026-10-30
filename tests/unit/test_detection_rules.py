"""Unit tests for declarative detection rule definitions and validation (Phase 2 Milestone 2.4).

Verifies:
- Valid declarative single-event and sequence rules.
- Malformed YAML / syntax errors.
- Rejection of unknown operators.
- Rejection of unsupported fields.
- Rejection of missing required conditions.
- Bounded sequence time windows (1 <= seconds <= 86400).
- Rejection of arbitrary code execution / unsafe deserialization tags.
- Explainable error messages without crashing.
"""
from __future__ import annotations

import pytest
from backend.services.detection.models import (
    ConditionNode,
    RuleDefinition,
    RuleValidationError,
    SequenceDefinition,
    SequenceStage,
)
from backend.services.detection.validator import validate_rule_dict, validate_rule_yaml


class TestDetectionRuleValidation:
    """Test validation of declarative detection rules."""

    def test_valid_single_event_rule(self) -> None:
        raw_yaml = """
        rule_id: TEST-RULE-001
        name: Test Single Event Rule
        description: A test rule for validation.
        category: privilege_escalation
        severity: high
        enabled: true
        version: 1
        rule_type: single_event
        explanation: This is a test explanation.
        conditions:
          all:
            - field: command
              operator: startswith
              value: "sudo "
            - field: uid
              operator: ">"
              value: 1000
        """
        rule = validate_rule_yaml(raw_yaml)
        assert rule.rule_id == "TEST-RULE-001"
        assert rule.rule_type == "single_event"
        assert rule.severity == "high"
        assert rule.conditions is not None
        assert rule.conditions.all_ is not None
        assert len(rule.conditions.all_) == 2

    def test_valid_sequence_rule(self) -> None:
        raw_yaml = """
        rule_id: TEST-SEQ-001
        name: Test Sequence Rule
        description: A sequence test rule.
        category: suspicious_authentication
        severity: critical
        enabled: true
        version: 2
        rule_type: sequence
        explanation: Sequence explanation.
        sequence:
          time_window_seconds: 300
          stages:
            - stage_id: stage_1
              conditions:
                all:
                  - field: event_type
                    operator: "=="
                    value: "auth:login:fail"
              min_count: 3
              match_fields: ["username"]
            - stage_id: stage_2
              conditions:
                all:
                  - field: event_type
                    operator: "=="
                    value: "auth:login:success"
              min_count: 1
              match_fields: ["username"]
        """
        rule = validate_rule_yaml(raw_yaml)
        assert rule.rule_id == "TEST-SEQ-001"
        assert rule.rule_type == "sequence"
        assert rule.sequence is not None
        assert rule.sequence.time_window_seconds == 300
        assert len(rule.sequence.stages) == 2
        assert rule.sequence.stages[0].min_count == 3

    def test_malformed_yaml_syntax(self) -> None:
        malformed = """
        rule_id: TEST-001
        name: [unclosed bracket
        category: privilege_escalation
        """
        with pytest.raises(RuleValidationError, match="Malformed YAML syntax"):
            validate_rule_yaml(malformed)

    def test_empty_content_rejected(self) -> None:
        with pytest.raises(RuleValidationError, match="Rule definition cannot be empty"):
            validate_rule_yaml("   \n  ")

    def test_non_dict_yaml_rejected(self) -> None:
        with pytest.raises(RuleValidationError, match="Rule definition must be a dictionary"):
            validate_rule_yaml("- item 1\n- item 2")

    def test_unknown_operator_rejected(self) -> None:
        raw_yaml = """
        rule_id: TEST-RULE-002
        name: Unknown Operator
        category: reconnaissance
        severity: medium
        rule_type: single_event
        conditions:
          all:
            - field: command
              operator: fuzzy_like_sql
              value: "%test%"
        """
        with pytest.raises(RuleValidationError, match="Unsupported operator 'fuzzy_like_sql'"):
            validate_rule_yaml(raw_yaml)

    def test_unsupported_field_rejected(self) -> None:
        raw_yaml = """
        rule_id: TEST-RULE-003
        name: Unsupported Field
        category: reconnaissance
        severity: medium
        rule_type: single_event
        conditions:
          all:
            - field: unapproved_internal_state
              operator: "=="
              value: "foo"
        """
        with pytest.raises(RuleValidationError, match="Unsupported field 'unapproved_internal_state'"):
            validate_rule_yaml(raw_yaml)

    def test_payload_field_permitted(self) -> None:
        raw_yaml = """
        rule_id: TEST-RULE-004
        name: Payload Subfield
        category: reconnaissance
        severity: low
        rule_type: single_event
        conditions:
          all:
            - field: payload.remote_host
              operator: exists
        """
        rule = validate_rule_yaml(raw_yaml)
        assert rule.rule_id == "TEST-RULE-004"

    def test_missing_conditions_in_single_event_rejected(self) -> None:
        raw_yaml = """
        rule_id: TEST-RULE-005
        name: Missing Conditions
        category: privilege_escalation
        severity: low
        rule_type: single_event
        """
        with pytest.raises(RuleValidationError, match="Single-event rule requires 'conditions'"):
            validate_rule_yaml(raw_yaml)

    def test_single_event_with_sequence_rejected(self) -> None:
        raw_yaml = """
        rule_id: TEST-RULE-006
        name: Single Event With Sequence
        category: privilege_escalation
        severity: low
        rule_type: single_event
        conditions:
          all:
            - field: command
              operator: "=="
              value: "id"
        sequence:
          time_window_seconds: 60
          stages:
            - stage_id: s1
              conditions:
                all:
                  - field: command
                    operator: "=="
                    value: "id"
            - stage_id: s2
              conditions:
                all:
                  - field: command
                    operator: "=="
                    value: "whoami"
        """
        with pytest.raises(RuleValidationError, match="Single-event rule cannot include 'sequence'"):
            validate_rule_yaml(raw_yaml)

    def test_invalid_severity_rejected(self) -> None:
        raw_yaml = """
        rule_id: TEST-RULE-007
        name: Invalid Severity
        category: reconnaissance
        severity: super_urgent
        rule_type: single_event
        conditions:
          all:
            - field: command
              operator: "=="
              value: "id"
        """
        with pytest.raises(RuleValidationError, match="Invalid severity 'super_urgent'"):
            validate_rule_yaml(raw_yaml)

    def test_invalid_sequence_window_rejected(self) -> None:
        # Window must be between 1 and 86400 (max 24h)
        raw_yaml = """
        rule_id: TEST-RULE-008
        name: Invalid Window
        category: reconnaissance
        severity: medium
        rule_type: sequence
        sequence:
          time_window_seconds: 0
          stages:
            - stage_id: s1
              conditions:
                all:
                  - field: command
                    operator: "=="
                    value: "id"
            - stage_id: s2
              conditions:
                all:
                  - field: command
                    operator: "=="
                    value: "whoami"
        """
        with pytest.raises(RuleValidationError, match="time_window_seconds"):
            validate_rule_yaml(raw_yaml)

        # Window exceeding 86400 seconds (24h)
        raw_yaml_too_large = raw_yaml.replace("time_window_seconds: 0", "time_window_seconds: 100000")
        with pytest.raises(RuleValidationError, match="time_window_seconds"):
            validate_rule_yaml(raw_yaml_too_large)

    def test_arbitrary_python_code_rejected(self) -> None:
        # Dangerous YAML tags must be rejected by safe_load
        malicious_yaml = """
        rule_id: EXPLOIT-001
        name: Exploit Attempt
        category: privilege_escalation
        severity: critical
        rule_type: single_event
        conditions: !!python/object/apply:os.system ["echo hacked"]
        """
        with pytest.raises(RuleValidationError, match="could not determine a constructor|Malformed YAML syntax"):
            validate_rule_yaml(malicious_yaml)

    def test_invalid_regex_syntax_rejected(self) -> None:
        raw_yaml = """
        rule_id: TEST-REGEX-001
        name: Invalid Regex Rule
        category: reconnaissance
        severity: medium
        rule_type: single_event
        conditions:
          all:
            - field: command
              operator: regex
              value: "[unclosed-bracket("
        """
        with pytest.raises(RuleValidationError, match="Invalid regular expression"):
            validate_rule_yaml(raw_yaml)

