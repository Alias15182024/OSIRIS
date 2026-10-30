"""Unit tests for the Sequence Detection Engine (Phase 2 Milestone 2.4).

Verifies:
- Multi-stage sequence detection.
- Timestamp ordering resilience (out-of-order event streams).
- Sliding time-window bounds (events outside window do not match).
- Missing sequence elements do not produce false alerts.
- Match-field correlation (e.g. matching username across stages).
- Cross-host isolation (events on host A never correlate with events on host B).
- Deduplication and idempotency.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
import pytest

from backend.services.detection.engine import DetectionEngine
from backend.services.detection.validator import validate_rule_yaml
from backend.services.events.schemas import NormalizedEvent


def _make_event(
    host_id: uuid.UUID,
    event_type: str,
    timestamp: datetime,
    username: str = "alice",
    command: str | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        id=uuid.uuid4(),
        host_id=host_id,
        timestamp=timestamp,
        ingested_at=datetime.now(timezone.utc),
        source="auth" if "auth" in event_type else "proc",
        event_type=event_type,
        action="execute",
        severity="info",
        uid=1000,
        username=username,
        command=command,
    )


class TestSequenceDetection:
    """Test sequence correlation engine."""

    @pytest.fixture
    def auth_brute_force_rule(self):
        raw_yaml = """
        rule_id: SEQ-TEST-001
        name: Brute Force Followed by Success
        category: suspicious_authentication
        severity: high
        rule_type: sequence
        explanation: Failed attempts followed by success.
        sequence:
          time_window_seconds: 300
          stages:
            - stage_id: failures
              conditions:
                all:
                  - field: event_type
                    operator: "=="
                    value: "auth:login:fail"
              min_count: 2
              match_fields: ["username"]
            - stage_id: success
              conditions:
                all:
                  - field: event_type
                    operator: "=="
                    value: "auth:login:success"
              min_count: 1
              match_fields: ["username"]
        """
        return validate_rule_yaml(raw_yaml)

    def test_successful_sequence_matching(self, auth_brute_force_rule) -> None:
        host_id = uuid.uuid4()
        base_time = datetime(2026, 10, 30, 12, 0, 0, tzinfo=timezone.utc)

        events = [
            _make_event(host_id, "auth:login:fail", base_time, username="charlie"),
            _make_event(host_id, "auth:login:fail", base_time + timedelta(seconds=10), username="charlie"),
            _make_event(host_id, "auth:login:success", base_time + timedelta(seconds=25), username="charlie"),
        ]

        engine = DetectionEngine([auth_brute_force_rule])
        matches = engine.evaluate_batch(events)

        assert len(matches) == 1
        m = matches[0]
        assert m.rule_id == "SEQ-TEST-001"
        assert m.host_id == host_id
        assert len(m.triggering_event_ids) == 3
        assert m.evidence["correlated_fields"]["username"] == "charlie"

    def test_out_of_order_stream_resilience(self, auth_brute_force_rule) -> None:
        """Events arriving out of order must be sorted chronologically by timestamp."""
        host_id = uuid.uuid4()
        base_time = datetime(2026, 10, 30, 12, 0, 0, tzinfo=timezone.utc)

        ev1 = _make_event(host_id, "auth:login:fail", base_time, username="david")
        ev2 = _make_event(host_id, "auth:login:fail", base_time + timedelta(seconds=15), username="david")
        ev3 = _make_event(host_id, "auth:login:success", base_time + timedelta(seconds=30), username="david")

        # Ingest in shuffled order: ev3, ev1, ev2
        shuffled = [ev3, ev1, ev2]

        engine = DetectionEngine([auth_brute_force_rule])
        matches = engine.evaluate_batch(shuffled)

        assert len(matches) == 1
        assert matches[0].evidence["correlated_fields"]["username"] == "david"
        assert matches[0].primary_event_id == ev3.id

    def test_expired_time_window_fails(self, auth_brute_force_rule) -> None:
        """Events separated by more than time_window_seconds must NOT match."""
        host_id = uuid.uuid4()
        base_time = datetime(2026, 10, 30, 12, 0, 0, tzinfo=timezone.utc)

        # Failures at T=0 and T=10, but success at T=301 (window is 300s)
        events = [
            _make_event(host_id, "auth:login:fail", base_time, username="eve"),
            _make_event(host_id, "auth:login:fail", base_time + timedelta(seconds=10), username="eve"),
            _make_event(host_id, "auth:login:success", base_time + timedelta(seconds=301), username="eve"),
        ]

        engine = DetectionEngine([auth_brute_force_rule])
        matches = engine.evaluate_batch(events)
        assert len(matches) == 0

    def test_missing_stage_fails(self, auth_brute_force_rule) -> None:
        """If stage 2 (successful login) does not occur, no sequence alert is produced."""
        host_id = uuid.uuid4()
        base_time = datetime(2026, 10, 30, 12, 0, 0, tzinfo=timezone.utc)

        events = [
            _make_event(host_id, "auth:login:fail", base_time, username="frank"),
            _make_event(host_id, "auth:login:fail", base_time + timedelta(seconds=10), username="frank"),
        ]

        engine = DetectionEngine([auth_brute_force_rule])
        matches = engine.evaluate_batch(events)
        assert len(matches) == 0

    def test_mismatched_match_fields_fails(self, auth_brute_force_rule) -> None:
        """If failures are for user A but success is for user B, no alert is produced."""
        host_id = uuid.uuid4()
        base_time = datetime(2026, 10, 30, 12, 0, 0, tzinfo=timezone.utc)

        events = [
            _make_event(host_id, "auth:login:fail", base_time, username="target_alice"),
            _make_event(host_id, "auth:login:fail", base_time + timedelta(seconds=10), username="target_alice"),
            _make_event(host_id, "auth:login:success", base_time + timedelta(seconds=20), username="different_bob"),
        ]

        engine = DetectionEngine([auth_brute_force_rule])
        matches = engine.evaluate_batch(events)
        assert len(matches) == 0

    def test_strict_cross_host_isolation(self, auth_brute_force_rule) -> None:
        """Events occurring across different hosts must NEVER correlate."""
        host_a = uuid.uuid4()
        host_b = uuid.uuid4()
        base_time = datetime(2026, 10, 30, 12, 0, 0, tzinfo=timezone.utc)

        # 2 failures on Host A, but success on Host B
        events = [
            _make_event(host_a, "auth:login:fail", base_time, username="mallory"),
            _make_event(host_a, "auth:login:fail", base_time + timedelta(seconds=10), username="mallory"),
            _make_event(host_b, "auth:login:success", base_time + timedelta(seconds=20), username="mallory"),
        ]

        engine = DetectionEngine([auth_brute_force_rule])
        matches = engine.evaluate_batch(events)
        assert len(matches) == 0, "Host A events must never correlate with Host B events!"

    def test_idempotent_dedup_hash(self, auth_brute_force_rule) -> None:
        """Repeated evaluation of the exact same event stream yields identical dedup_hash."""
        host_id = uuid.uuid4()
        base_time = datetime(2026, 10, 30, 12, 0, 0, tzinfo=timezone.utc)

        events = [
            _make_event(host_id, "auth:login:fail", base_time, username="heidi"),
            _make_event(host_id, "auth:login:fail", base_time + timedelta(seconds=5), username="heidi"),
            _make_event(host_id, "auth:login:success", base_time + timedelta(seconds=10), username="heidi"),
        ]

        engine = DetectionEngine([auth_brute_force_rule])
        matches1 = engine.evaluate_batch(events)
        matches2 = engine.evaluate_batch(events)

        assert len(matches1) == 1
        assert len(matches2) == 1
        assert matches1[0].dedup_hash == matches2[0].dedup_hash

    def test_interleaved_users_correlate_correct_attacker(self, auth_brute_force_rule) -> None:
        """Events for benign users must not cause false negatives for the true attacker."""
        host_id = uuid.uuid4()
        base_time = datetime(2026, 10, 30, 12, 0, 0, tzinfo=timezone.utc)

        events = [
            _make_event(host_id, "auth:login:fail", base_time, username="alice"),
            _make_event(host_id, "auth:login:fail", base_time + timedelta(seconds=1), username="bob"),
            _make_event(host_id, "auth:login:fail", base_time + timedelta(seconds=2), username="bob"),
            _make_event(host_id, "auth:login:success", base_time + timedelta(seconds=3), username="bob"),
        ]

        engine = DetectionEngine([auth_brute_force_rule])
        matches = engine.evaluate_batch(events)

        assert len(matches) == 1
        assert matches[0].evidence["correlated_fields"]["username"] == "bob"

    def test_cross_user_split_failures_no_false_positive(self, auth_brute_force_rule) -> None:
        """Failures across different users must NOT be summed to reach a stage threshold."""
        host_id = uuid.uuid4()
        base_time = datetime(2026, 10, 30, 12, 0, 0, tzinfo=timezone.utc)

        # Alice 1 fail, Bob 1 fail, Alice success (neither had 2 fails)
        events = [
            _make_event(host_id, "auth:login:fail", base_time, username="alice"),
            _make_event(host_id, "auth:login:fail", base_time + timedelta(seconds=1), username="bob"),
            _make_event(host_id, "auth:login:success", base_time + timedelta(seconds=2), username="alice"),
        ]

        engine = DetectionEngine([auth_brute_force_rule])
        matches = engine.evaluate_batch(events)

        assert len(matches) == 0

    def test_zero_event_reuse_across_stages(self) -> None:
        """An event satisfying multiple stage conditions cannot be reused across stages."""
        raw_yaml = """
        rule_id: SEQ-NO-REUSE-001
        name: No Reuse Test
        category: suspicious_authentication
        severity: medium
        rule_type: sequence
        sequence:
          time_window_seconds: 300
          stages:
            - stage_id: s1
              conditions:
                all:
                  - field: event_type
                    operator: "=="
                    value: "auth:login:fail"
              min_count: 3
              match_fields: []
            - stage_id: s2
              conditions:
                all:
                  - field: event_type
                    operator: "=="
                    value: "auth:login:fail"
              min_count: 1
              match_fields: []
        """
        rule = validate_rule_yaml(raw_yaml)
        engine = DetectionEngine([rule])

        host_id = uuid.uuid4()
        base_time = datetime(2026, 10, 30, 12, 0, 0, tzinfo=timezone.utc)

        # 3 events cannot satisfy 3 + 1 = 4 required distinct events
        three_events = [
            _make_event(host_id, "auth:login:fail", base_time + timedelta(seconds=i), username="target")
            for i in range(3)
        ]
        assert len(engine.evaluate_batch(three_events)) == 0

        # 4 events satisfy 3 + 1 = 4 distinct events
        four_events = [
            _make_event(host_id, "auth:login:fail", base_time + timedelta(seconds=i), username="target")
            for i in range(4)
        ]
        matches = engine.evaluate_batch(four_events)
        assert len(matches) == 1
        assert len(matches[0].triggering_event_ids) == 4
        # Verify all triggering event IDs are strictly distinct
        assert len(set(matches[0].triggering_event_ids)) == 4

    def test_identical_timestamps_preserve_ordering(self, auth_brute_force_rule) -> None:
        """Events sharing identical timestamps order deterministically and match properly."""
        host_id = uuid.uuid4()
        same_time = datetime(2026, 10, 30, 12, 0, 0, tzinfo=timezone.utc)

        # 2 failures followed by 1 success, all at the same microsecond timestamp
        ev1 = _make_event(host_id, "auth:login:fail", same_time, username="victor")
        ev2 = _make_event(host_id, "auth:login:fail", same_time, username="victor")
        ev3 = _make_event(host_id, "auth:login:success", same_time, username="victor")

        engine = DetectionEngine([auth_brute_force_rule])
        matches = engine.evaluate_batch([ev1, ev2, ev3])
        assert len(matches) == 1
        assert len(matches[0].triggering_event_ids) == 3

