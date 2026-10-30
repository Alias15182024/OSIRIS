"""Unit tests for the Initial Security Detection Rules catalogue (Phase 2 Milestone 2.4).

Verifies each seeded rule against:
1. Positive attack fixtures that MUST trigger alerts.
2. Ordinary administrative fixtures that MUST NOT trigger false positives.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
import pytest

from backend.services.detection.engine import DetectionEngine
from backend.services.detection.rules_loader import load_rules_from_directory
from backend.services.events.schemas import NormalizedEvent


def _make_event(
    host_id: uuid.UUID,
    event_type: str = "proc:exec",
    action: str = "start",
    command: str = "ls",
    uid: int = 1000,
    username: str = "admin",
    object_path: str | None = None,
    payload: dict | None = None,
    timestamp: datetime | None = None,
) -> NormalizedEvent:
    now = timestamp or datetime.now(timezone.utc)
    return NormalizedEvent(
        id=uuid.uuid4(),
        host_id=host_id,
        timestamp=now,
        ingested_at=now,
        source="proc" if "proc" in event_type else "auth",
        event_type=event_type,
        action=action,
        severity="info",
        uid=uid,
        username=username,
        command=command,
        object_path=object_path,
        payload=payload,
    )


class TestInitialSecurityRules:
    """Validate all seeded declarative rules."""

    @pytest.fixture(scope="class")
    @classmethod
    def engine(cls) -> DetectionEngine:
        rules = load_rules_from_directory()
        return DetectionEngine(rules)

    # --- Category A: Privilege Escalation ---

    def test_priv_001_suspicious_sudo_triggers(self, engine: DetectionEngine) -> None:
        host_id = uuid.uuid4()
        # Positive: user running interactive sudo shell
        ev = _make_event(host_id, command="sudo -i", uid=1000, username="user1")
        matches = engine.evaluate_event(ev)
        matched_rule_ids = {m.rule_id for m in matches}
        assert "OSIRIS-PRIV-001" in matched_rule_ids

    def test_priv_001_ordinary_admin_no_false_positive(self, engine: DetectionEngine) -> None:
        host_id = uuid.uuid4()
        # Ordinary administrative command: service status
        ev = _make_event(host_id, command="sudo systemctl status nginx", uid=1000, username="user1")
        matches = engine.evaluate_event(ev)
        matched_rule_ids = {m.rule_id for m in matches}
        assert "OSIRIS-PRIV-001" not in matched_rule_ids

    def test_priv_002_privilege_binary_triggers(self, engine: DetectionEngine) -> None:
        host_id = uuid.uuid4()
        ev = _make_event(host_id, command="pkexec /bin/sh", uid=1000, username="user1")
        matches = engine.evaluate_event(ev)
        matched_rule_ids = {m.rule_id for m in matches}
        assert "OSIRIS-PRIV-002" in matched_rule_ids

    def test_priv_002_benign_command_no_alert(self, engine: DetectionEngine) -> None:
        host_id = uuid.uuid4()
        ev = _make_event(host_id, command="cat /etc/os-release", uid=1000, username="user1")
        matches = engine.evaluate_event(ev)
        matched_rule_ids = {m.rule_id for m in matches}
        assert "OSIRIS-PRIV-002" not in matched_rule_ids

    def test_priv_003_sudoers_tampering_triggers(self, engine: DetectionEngine) -> None:
        host_id = uuid.uuid4()
        ev1 = _make_event(host_id, command="visudo", uid=0, username="root")
        ev2 = _make_event(host_id, command="chmod 777 /etc/sudoers", uid=1000, username="user1")
        assert "OSIRIS-PRIV-003" in {m.rule_id for m in engine.evaluate_event(ev1)}
        assert "OSIRIS-PRIV-003" in {m.rule_id for m in engine.evaluate_event(ev2)}

    def test_priv_003_benign_config_no_alert(self, engine: DetectionEngine) -> None:
        host_id = uuid.uuid4()
        ev = _make_event(host_id, command="cat /etc/resolv.conf", uid=1000, username="user1")
        matches = engine.evaluate_event(ev)
        matched_rule_ids = {m.rule_id for m in matches}
        assert "OSIRIS-PRIV-003" not in matched_rule_ids

    # --- Category B: Suspicious Authentication ---

    def test_auth_001_repeated_failed_logins(self, engine: DetectionEngine) -> None:
        host_id = uuid.uuid4()
        now = datetime(2026, 10, 30, 14, 0, 0, tzinfo=timezone.utc)
        events = [
            _make_event(host_id, event_type="auth:login:fail", timestamp=now, username="target"),
            _make_event(host_id, event_type="auth:login:fail", timestamp=now + timedelta(seconds=5), username="target"),
            _make_event(host_id, event_type="auth:login:fail", timestamp=now + timedelta(seconds=10), username="target"),
            _make_event(host_id, event_type="auth:login:fail", timestamp=now + timedelta(seconds=15), username="target"),
        ]
        matches = engine.evaluate_batch(events)
        matched_rule_ids = {m.rule_id for m in matches}
        assert "OSIRIS-AUTH-001" in matched_rule_ids

    def test_auth_001_single_failure_no_false_positive(self, engine: DetectionEngine) -> None:
        host_id = uuid.uuid4()
        now = datetime(2026, 10, 30, 14, 0, 0, tzinfo=timezone.utc)
        # Just 1 failed attempt (e.g. accidental typo)
        events = [
            _make_event(host_id, event_type="auth:login:fail", timestamp=now, username="normal_user"),
        ]
        matches = engine.evaluate_batch(events)
        matched_rule_ids = {m.rule_id for m in matches}
        assert "OSIRIS-AUTH-001" not in matched_rule_ids

    def test_auth_002_failed_then_successful_login(self, engine: DetectionEngine) -> None:
        host_id = uuid.uuid4()
        now = datetime(2026, 10, 30, 14, 0, 0, tzinfo=timezone.utc)
        events = [
            _make_event(host_id, event_type="auth:login:fail", timestamp=now, username="victim"),
            _make_event(host_id, event_type="auth:login:fail", timestamp=now + timedelta(seconds=5), username="victim"),
            _make_event(host_id, event_type="auth:login:success", timestamp=now + timedelta(seconds=12), username="victim"),
        ]
        matches = engine.evaluate_batch(events)
        matched_rule_ids = {m.rule_id for m in matches}
        assert "OSIRIS-AUTH-002" in matched_rule_ids

    def test_auth_002_normal_login_no_false_positive(self, engine: DetectionEngine) -> None:
        host_id = uuid.uuid4()
        now = datetime(2026, 10, 30, 14, 0, 0, tzinfo=timezone.utc)
        events = [
            _make_event(host_id, event_type="auth:login:success", timestamp=now, username="normal_user"),
        ]
        matches = engine.evaluate_batch(events)
        matched_rule_ids = {m.rule_id for m in matches}
        assert "OSIRIS-AUTH-002" not in matched_rule_ids

    def test_auth_003_remote_root_login(self, engine: DetectionEngine) -> None:
        host_id = uuid.uuid4()
        # Remote root login
        ev = _make_event(
            host_id,
            event_type="auth:ssh:success",
            username="root",
            payload={"remote_host": "198.51.100.42"}
        )
        matches = engine.evaluate_event(ev)
        matched_rule_ids = {m.rule_id for m in matches}
        assert "OSIRIS-AUTH-003" in matched_rule_ids

    def test_auth_003_remote_standard_user_no_alert(self, engine: DetectionEngine) -> None:
        host_id = uuid.uuid4()
        ev = _make_event(
            host_id,
            event_type="auth:ssh:success",
            username="alice",
            payload={"remote_host": "198.51.100.42"}
        )
        matches = engine.evaluate_event(ev)
        matched_rule_ids = {m.rule_id for m in matches}
        assert "OSIRIS-AUTH-003" not in matched_rule_ids

    # --- Category C: Reconnaissance ---

    def test_recon_001_rapid_discovery_chain(self, engine: DetectionEngine) -> None:
        host_id = uuid.uuid4()
        now = datetime(2026, 10, 30, 15, 0, 0, tzinfo=timezone.utc)
        events = [
            _make_event(host_id, command="uname -a", timestamp=now),
            _make_event(host_id, command="whoami", timestamp=now + timedelta(seconds=2)),
            _make_event(host_id, command="ip addr", timestamp=now + timedelta(seconds=5)),
        ]
        matches = engine.evaluate_batch(events)
        matched_rule_ids = {m.rule_id for m in matches}
        assert "OSIRIS-RECON-001" in matched_rule_ids

    def test_recon_001_isolated_command_no_alert(self, engine: DetectionEngine) -> None:
        host_id = uuid.uuid4()
        now = datetime(2026, 10, 30, 15, 0, 0, tzinfo=timezone.utc)
        events = [
            _make_event(host_id, command="uname -a", timestamp=now),
        ]
        matches = engine.evaluate_batch(events)
        matched_rule_ids = {m.rule_id for m in matches}
        assert "OSIRIS-RECON-001" not in matched_rule_ids

    def test_recon_002_user_account_enumeration(self, engine: DetectionEngine) -> None:
        host_id = uuid.uuid4()
        ev1 = _make_event(host_id, command="cat /etc/passwd")
        ev2 = _make_event(host_id, command="getent passwd")
        ev3 = _make_event(host_id, command="lastlog")
        ev4 = _make_event(host_id, command="w")
        ev5 = _make_event(host_id, command="who -a")
        assert "OSIRIS-RECON-002" in {m.rule_id for m in engine.evaluate_event(ev1)}
        assert "OSIRIS-RECON-002" in {m.rule_id for m in engine.evaluate_event(ev2)}
        assert "OSIRIS-RECON-002" in {m.rule_id for m in engine.evaluate_event(ev3)}
        assert "OSIRIS-RECON-002" in {m.rule_id for m in engine.evaluate_event(ev4)}
        assert "OSIRIS-RECON-002" in {m.rule_id for m in engine.evaluate_event(ev5)}

    def test_recon_002_benign_process_no_alert(self, engine: DetectionEngine) -> None:
        host_id = uuid.uuid4()
        # Non-enumeration commands starting with 'w' must NOT trigger false alerts
        for benign_cmd in ["nginx -t", "which python", "wc -l /var/log/syslog", "wget https://example.com", "watch ls"]:
            ev = _make_event(host_id, command=benign_cmd)
            matches = engine.evaluate_event(ev)
            matched_rule_ids = {m.rule_id for m in matches}
            assert "OSIRIS-RECON-002" not in matched_rule_ids, f"False positive on benign command '{benign_cmd}'"

    def test_recon_003_sensitive_file_inspection(self, engine: DetectionEngine) -> None:
        host_id = uuid.uuid4()
        ev_cmd = _make_event(host_id, command="cat /etc/shadow")
        ev_obj = _make_event(host_id, object_path="/etc/shadow")
        assert "OSIRIS-RECON-003" in {m.rule_id for m in engine.evaluate_event(ev_cmd)}
        assert "OSIRIS-RECON-003" in {m.rule_id for m in engine.evaluate_event(ev_obj)}

    def test_recon_003_benign_file_no_alert(self, engine: DetectionEngine) -> None:
        host_id = uuid.uuid4()
        ev = _make_event(host_id, object_path="/etc/hosts", command="cat /etc/hosts")
        matches = engine.evaluate_event(ev)
        matched_rule_ids = {m.rule_id for m in matches}
        assert "OSIRIS-RECON-003" not in matched_rule_ids
