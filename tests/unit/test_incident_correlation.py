"""Unit tests for Detection Correlator & Automated Incident Creation (Phase 2 Milestone 2.6)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.db.models.detection import Detection
from backend.db.models.detection_rule import DetectionRule
from backend.db.models.event import Event
from backend.db.models.host import Host
from backend.db.models.incident import Incident
from backend.db.models.incident_evidence import IncidentEvidence
from backend.db.models.incident_history import IncidentHistory
from backend.db.models.process import Process
from backend.db.models.user_session import UserSession
from backend.services.incidents.correlator import (
    DEFAULT_CORRELATION_WINDOW_SECONDS,
    DetectionCorrelator,
)
from backend.services.incidents.evidence_manager import EvidenceManager
from backend.services.incidents.models import (
    EvidenceType,
    HistoryChangeType,
    IncidentSeverity,
    IncidentStatus,
)


@pytest.fixture
def host_a(db_session: Session) -> Host:
    host = Host(id=uuid.uuid4(), hostname="victim-host-alpha")
    db_session.add(host)
    db_session.flush()
    return host


@pytest.fixture
def host_b(db_session: Session) -> Host:
    host = Host(id=uuid.uuid4(), hostname="unrelated-host-beta")
    db_session.add(host)
    db_session.flush()
    return host


@pytest.fixture
def detection_rule(db_session: Session) -> DetectionRule:
    rule = DetectionRule(
        id=uuid.uuid4(),
        rule_id="RULE-CORR-001",
        name="Correlation Test Rule",
        category="execution",
        severity="medium",
        enabled=True,
        version=1,
        rule_type="single_event",
        conditions={},
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(rule)
    db_session.flush()
    return rule


@pytest.fixture
def correlator() -> DetectionCorrelator:
    return DetectionCorrelator(window_seconds=DEFAULT_CORRELATION_WINDOW_SECONDS)


class TestDetectionCorrelator:
    """Validate detection correlation, automated incident creation, deduplication, and escalation."""

    def test_correlate_new_incident_from_detection(
        self,
        db_session: Session,
        host_a: Host,
        detection_rule: DetectionRule,
        correlator: DetectionCorrelator,
    ) -> None:
        now = datetime.now(timezone.utc)
        detection = Detection(
            id=uuid.uuid4(),
            rule_id=detection_rule.id,
            host_id=host_a.id,
            timestamp=now,
            severity="medium",
            title="Suspicious Shell Spawn",
            description="bash executed with suspicious arguments",
            category="execution",
            status="open",
            notification_status="pending",
            matched_conditions={"cmd": "/bin/bash -i"},
            evidence={"pid": 1234},
        )
        db_session.add(detection)
        db_session.flush()

        incident, is_new = correlator.correlate_detection(db_session, detection)

        assert is_new is True
        assert incident is not None
        assert incident.host_id == host_a.id
        assert incident.status == IncidentStatus.OPEN.value
        assert incident.severity == IncidentSeverity.MEDIUM.value
        assert incident.category == "execution"
        assert incident.title == "Incident: Suspicious Shell Spawn"

        # Verify evidence attached
        evidence_list = db_session.execute(
            select(IncidentEvidence).where(IncidentEvidence.incident_id == incident.id)
        ).scalars().all()
        assert len(evidence_list) == 1
        assert evidence_list[0].evidence_type == EvidenceType.DETECTION.value
        assert evidence_list[0].detection_id == detection.id

        # Verify history
        histories = db_session.execute(
            select(IncidentHistory).where(IncidentHistory.incident_id == incident.id)
        ).scalars().all()
        assert any(h.change_type == HistoryChangeType.INCIDENT_CREATED.value for h in histories)

    def test_correlate_shared_session_within_window(
        self,
        db_session: Session,
        host_a: Host,
        detection_rule: DetectionRule,
        correlator: DetectionCorrelator,
    ) -> None:
        now = datetime.now(timezone.utc)
        session = UserSession(
            id=uuid.uuid4(),
            host_id=host_a.id,
            session_type="ssh",
            terminal="pts/0",
            started_at=now - timedelta(minutes=10),
        )
        db_session.add(session)
        db_session.flush()

        det1 = Detection(
            id=uuid.uuid4(),
            rule_id=detection_rule.id,
            host_id=host_a.id,
            session_id=session.id,
            timestamp=now - timedelta(minutes=5),
            severity="low",
            title="Initial Probe",
            category="reconnaissance",
            status="open",
            notification_status="pending",
            matched_conditions={},
            evidence={},
        )
        db_session.add(det1)
        db_session.flush()

        inc1, is_new1 = correlator.correlate_detection(db_session, det1)
        assert is_new1 is True

        # Link session evidence to inc1 explicitly so cand_evidence has session_id
        em = EvidenceManager()
        em.link_session(db_session, inc1, session, reason="Associated session")

        # Second detection in same session
        det2 = Detection(
            id=uuid.uuid4(),
            rule_id=detection_rule.id,
            host_id=host_a.id,
            session_id=session.id,
            timestamp=now,
            severity="high",
            title="Privilege Escalation Attempt",
            category="privilege_escalation",
            status="open",
            notification_status="pending",
            matched_conditions={},
            evidence={},
        )
        db_session.add(det2)
        db_session.flush()

        inc2, is_new2 = correlator.correlate_detection(db_session, det2)
        assert is_new2 is False
        assert inc2.id == inc1.id
        # Check severity escalation from low to high
        assert inc2.severity == IncidentSeverity.HIGH.value

    def test_correlate_shared_process_within_window(
        self,
        db_session: Session,
        host_a: Host,
        detection_rule: DetectionRule,
        correlator: DetectionCorrelator,
    ) -> None:
        now = datetime.now(timezone.utc)
        proc = Process(
            id=uuid.uuid4(),
            host_id=host_a.id,
            pid=4321,
            ppid=1,
            command="nc -lvp 4444",
            executable="/bin/nc",
            started_at=now - timedelta(minutes=8),
        )
        db_session.add(proc)
        db_session.flush()

        det1 = Detection(
            id=uuid.uuid4(),
            rule_id=detection_rule.id,
            host_id=host_a.id,
            process_id=proc.id,
            timestamp=now - timedelta(minutes=5),
            severity="medium",
            title="Netcat Listener",
            category="execution",
            status="open",
            notification_status="pending",
            matched_conditions={},
            evidence={},
        )
        db_session.add(det1)
        db_session.flush()

        inc1, is_new1 = correlator.correlate_detection(db_session, det1)
        assert is_new1 is True

        # Link process evidence
        em = EvidenceManager()
        em.link_process(db_session, inc1, proc, reason="Target process")

        # Second detection on same process
        det2 = Detection(
            id=uuid.uuid4(),
            rule_id=detection_rule.id,
            host_id=host_a.id,
            process_id=proc.id,
            timestamp=now,
            severity="medium",
            title="Outbound Shell Traffic",
            category="command_and_control",
            status="open",
            notification_status="pending",
            matched_conditions={},
            evidence={},
        )
        db_session.add(det2)
        db_session.flush()

        inc2, is_new2 = correlator.correlate_detection(db_session, det2)
        assert is_new2 is False
        assert inc2.id == inc1.id

    def test_correlate_category_match_within_window(
        self,
        db_session: Session,
        host_a: Host,
        detection_rule: DetectionRule,
        correlator: DetectionCorrelator,
    ) -> None:
        now = datetime.now(timezone.utc)
        det1 = Detection(
            id=uuid.uuid4(),
            rule_id=detection_rule.id,
            host_id=host_a.id,
            timestamp=now - timedelta(minutes=20),
            severity="low",
            title="Recon Command 1",
            category="reconnaissance",
            status="open",
            notification_status="pending",
            matched_conditions={},
            evidence={},
        )
        db_session.add(det1)
        db_session.flush()

        inc1, is_new1 = correlator.correlate_detection(db_session, det1)
        assert is_new1 is True
        assert inc1.category == "reconnaissance"

        det2 = Detection(
            id=uuid.uuid4(),
            rule_id=detection_rule.id,
            host_id=host_a.id,
            timestamp=now,
            severity="low",
            title="Recon Command 2",
            category="reconnaissance",
            status="open",
            notification_status="pending",
            matched_conditions={},
            evidence={},
        )
        db_session.add(det2)
        db_session.flush()

        inc2, is_new2 = correlator.correlate_detection(db_session, det2)
        assert is_new2 is False
        assert inc2.id == inc1.id

    def test_time_window_expiry_creates_new_incident(
        self,
        db_session: Session,
        host_a: Host,
        detection_rule: DetectionRule,
    ) -> None:
        correlator = DetectionCorrelator(window_seconds=1800)  # 30 minute window
        now = datetime.now(timezone.utc)

        det1 = Detection(
            id=uuid.uuid4(),
            rule_id=detection_rule.id,
            host_id=host_a.id,
            timestamp=now - timedelta(hours=2),
            severity="medium",
            title="Old Detection",
            category="execution",
            status="open",
            notification_status="pending",
            matched_conditions={},
            evidence={},
        )
        db_session.add(det1)
        db_session.flush()

        inc1, is_new1 = correlator.correlate_detection(db_session, det1)
        assert is_new1 is True

        # det2 occurs 2 hours later, outside the 30-minute window
        det2 = Detection(
            id=uuid.uuid4(),
            rule_id=detection_rule.id,
            host_id=host_a.id,
            timestamp=now,
            severity="medium",
            title="Recent Detection",
            category="execution",
            status="open",
            notification_status="pending",
            matched_conditions={},
            evidence={},
        )
        db_session.add(det2)
        db_session.flush()

        inc2, is_new2 = correlator.correlate_detection(db_session, det2)
        assert is_new2 is True
        assert inc2.id != inc1.id

    def test_deduplication_idempotency(
        self,
        db_session: Session,
        host_a: Host,
        detection_rule: DetectionRule,
        correlator: DetectionCorrelator,
    ) -> None:
        now = datetime.now(timezone.utc)
        det = Detection(
            id=uuid.uuid4(),
            rule_id=detection_rule.id,
            host_id=host_a.id,
            timestamp=now,
            severity="high",
            title="Repeated Alert",
            category="persistence",
            status="open",
            notification_status="pending",
            matched_conditions={},
            evidence={},
        )
        db_session.add(det)
        db_session.flush()

        inc1, is_new1 = correlator.correlate_detection(db_session, det)
        assert is_new1 is True

        # Process exact same detection again
        inc2, is_new2 = correlator.correlate_detection(db_session, det)
        assert is_new2 is False
        assert inc2.id == inc1.id

        # Verify only 1 evidence link was created
        evidence_count = db_session.execute(
            select(IncidentEvidence).where(
                IncidentEvidence.incident_id == inc1.id,
                IncidentEvidence.evidence_type == EvidenceType.DETECTION.value,
                IncidentEvidence.source_id == str(det.id),
            )
        ).scalars().all()
        assert len(evidence_count) == 1

    def test_cross_host_isolation(
        self,
        db_session: Session,
        host_a: Host,
        host_b: Host,
        detection_rule: DetectionRule,
        correlator: DetectionCorrelator,
    ) -> None:
        now = datetime.now(timezone.utc)

        # Host A detection
        det_a = Detection(
            id=uuid.uuid4(),
            rule_id=detection_rule.id,
            host_id=host_a.id,
            timestamp=now,
            severity="high",
            title="Attack on Host A",
            category="execution",
            status="open",
            notification_status="pending",
            matched_conditions={},
            evidence={},
        )
        db_session.add(det_a)
        db_session.flush()

        inc_a, is_new_a = correlator.correlate_detection(db_session, det_a)
        assert is_new_a is True
        assert inc_a.host_id == host_a.id

        # Host B detection with same category and timestamp
        det_b = Detection(
            id=uuid.uuid4(),
            rule_id=detection_rule.id,
            host_id=host_b.id,
            timestamp=now,
            severity="high",
            title="Attack on Host B",
            category="execution",
            status="open",
            notification_status="pending",
            matched_conditions={},
            evidence={},
        )
        db_session.add(det_b)
        db_session.flush()

        inc_b, is_new_b = correlator.correlate_detection(db_session, det_b)
        assert is_new_b is True
        assert inc_b.id != inc_a.id
        assert inc_b.host_id == host_b.id

    def test_severity_escalation_and_non_downgrade(
        self,
        db_session: Session,
        host_a: Host,
        detection_rule: DetectionRule,
        correlator: DetectionCorrelator,
    ) -> None:
        now = datetime.now(timezone.utc)

        # 1. Start with LOW
        det_low = Detection(
            id=uuid.uuid4(),
            rule_id=detection_rule.id,
            host_id=host_a.id,
            timestamp=now - timedelta(minutes=10),
            severity="low",
            title="Low Severity Probe",
            category="reconnaissance",
            status="open",
            notification_status="pending",
            matched_conditions={},
            evidence={},
        )
        db_session.add(det_low)
        db_session.flush()

        inc, is_new = correlator.correlate_detection(db_session, det_low)
        assert is_new is True
        assert inc.severity == IncidentSeverity.LOW.value

        # 2. Correlate CRITICAL -> Escalates
        det_crit = Detection(
            id=uuid.uuid4(),
            rule_id=detection_rule.id,
            host_id=host_a.id,
            timestamp=now - timedelta(minutes=5),
            severity="critical",
            title="Ransomware Encryption",
            category="reconnaissance",
            status="open",
            notification_status="pending",
            matched_conditions={},
            evidence={},
        )
        db_session.add(det_crit)
        db_session.flush()

        inc_crit, is_new_crit = correlator.correlate_detection(db_session, det_crit)
        assert is_new_crit is False
        assert inc.severity == IncidentSeverity.CRITICAL.value

        # 3. Correlate MEDIUM -> Remains CRITICAL
        det_med = Detection(
            id=uuid.uuid4(),
            rule_id=detection_rule.id,
            host_id=host_a.id,
            timestamp=now,
            severity="medium",
            title="Secondary Recon",
            category="reconnaissance",
            status="open",
            notification_status="pending",
            matched_conditions={},
            evidence={},
        )
        db_session.add(det_med)
        db_session.flush()

        inc_med, is_new_med = correlator.correlate_detection(db_session, det_med)
        assert is_new_med is False
        assert inc.severity == IncidentSeverity.CRITICAL.value

    def test_detection_acknowledgment_does_not_resolve_incident(
        self,
        db_session: Session,
        host_a: Host,
        detection_rule: DetectionRule,
        correlator: DetectionCorrelator,
    ) -> None:
        now = datetime.now(timezone.utc)
        det = Detection(
            id=uuid.uuid4(),
            rule_id=detection_rule.id,
            host_id=host_a.id,
            timestamp=now,
            severity="high",
            title="Alert",
            category="execution",
            status="open",
            notification_status="pending",
            matched_conditions={},
            evidence={},
        )
        db_session.add(det)
        db_session.flush()

        inc, _ = correlator.correlate_detection(db_session, det)
        assert inc.status == IncidentStatus.OPEN.value

        # Acknowledge detection
        det.status = "acknowledged"
        db_session.flush()

        # Incident status is unchanged
        db_session.refresh(inc)
        assert inc.status == IncidentStatus.OPEN.value

    def test_correlate_batch_chronological(
        self,
        db_session: Session,
        host_a: Host,
        detection_rule: DetectionRule,
        correlator: DetectionCorrelator,
    ) -> None:
        now = datetime.now(timezone.utc)
        # Create 3 detections out of chronological order
        d1 = Detection(
            id=uuid.uuid4(),
            rule_id=detection_rule.id,
            host_id=host_a.id,
            timestamp=now - timedelta(minutes=5),
            severity="low",
            title="Mid Event",
            category="reconnaissance",
            status="open",
            notification_status="pending",
            matched_conditions={},
            evidence={},
        )
        d2 = Detection(
            id=uuid.uuid4(),
            rule_id=detection_rule.id,
            host_id=host_a.id,
            timestamp=now - timedelta(minutes=15),
            severity="low",
            title="Earliest Event",
            category="reconnaissance",
            status="open",
            notification_status="pending",
            matched_conditions={},
            evidence={},
        )
        d3 = Detection(
            id=uuid.uuid4(),
            rule_id=detection_rule.id,
            host_id=host_a.id,
            timestamp=now,
            severity="high",
            title="Latest Event",
            category="reconnaissance",
            status="open",
            notification_status="pending",
            matched_conditions={},
            evidence={},
        )
        db_session.add_all([d1, d2, d3])
        db_session.flush()

        results = correlator.correlate_batch(db_session, [d1, d2, d3])
        assert len(results) == 3
        # Earliest event d2 should have created the incident
        inc_first, is_new_first = results[0]
        assert is_new_first is True
        assert inc_first.title == "Incident: Earliest Event"

        # Subsequent events attached to the same incident
        assert results[1][1] is False
        assert results[2][1] is False
        assert results[2][0].id == inc_first.id
        assert results[2][0].severity == IncidentSeverity.HIGH.value

    def test_unrelated_sessions_never_combined_even_with_matching_timestamp_and_category(
        self,
        db_session: Session,
        host_a: Host,
        detection_rule: DetectionRule,
        correlator: DetectionCorrelator,
    ) -> None:
        """Requirement 7: Ensure unrelated users/sessions are never combined merely because timestamps match."""
        now = datetime.now(timezone.utc)
        sess_alice = UserSession(
            id=uuid.uuid4(),
            host_id=host_a.id,
            session_type="ssh",
            terminal="pts/1",
            started_at=now - timedelta(minutes=5),
        )
        sess_bob = UserSession(
            id=uuid.uuid4(),
            host_id=host_a.id,
            session_type="ssh",
            terminal="pts/2",
            started_at=now - timedelta(minutes=3),
        )
        db_session.add_all([sess_alice, sess_bob])
        db_session.flush()

        # Detection 1: Alice's session
        det_alice = Detection(
            id=uuid.uuid4(),
            rule_id=detection_rule.id,
            host_id=host_a.id,
            session_id=sess_alice.id,
            timestamp=now - timedelta(minutes=2),
            severity="medium",
            title="Alice Reconnaissance",
            category="reconnaissance",
            status="open",
            notification_status="pending",
            matched_conditions={},
            evidence={},
        )
        db_session.add(det_alice)
        db_session.flush()

        inc_alice, is_new_alice = correlator.correlate_detection(db_session, det_alice)
        assert is_new_alice is True

        # Detection 2: Bob's session, 1 minute later, same category
        det_bob = Detection(
            id=uuid.uuid4(),
            rule_id=detection_rule.id,
            host_id=host_a.id,
            session_id=sess_bob.id,
            timestamp=now - timedelta(minutes=1),
            severity="medium",
            title="Bob Reconnaissance",
            category="reconnaissance",
            status="open",
            notification_status="pending",
            matched_conditions={},
            evidence={},
        )
        db_session.add(det_bob)
        db_session.flush()

        inc_bob, is_new_bob = correlator.correlate_detection(db_session, det_bob)
        # MUST NOT combine Alice and Bob's unrelated sessions
        assert is_new_bob is True
        assert inc_bob.id != inc_alice.id

    def test_unrelated_categories_without_shared_context_never_combined_merely_by_timestamp(
        self,
        db_session: Session,
        host_a: Host,
        detection_rule: DetectionRule,
        correlator: DetectionCorrelator,
    ) -> None:
        """Requirement 7: Do not merge detections without shared evidence merely because time difference is small."""
        now = datetime.now(timezone.utc)
        rule2 = DetectionRule(
            id=uuid.uuid4(),
            rule_id="RULE-CORR-002",
            name="Different Category Rule",
            category="impact",
            severity="high",
            enabled=True,
            version=1,
            rule_type="single_event",
            conditions={},
            created_at=now,
        )
        db_session.add(rule2)
        db_session.flush()

        # Det 1: discovery
        det1 = Detection(
            id=uuid.uuid4(),
            rule_id=detection_rule.id,
            host_id=host_a.id,
            timestamp=now - timedelta(minutes=3),
            severity="low",
            title="Discovery Alert",
            category="discovery",
            status="open",
            notification_status="pending",
            matched_conditions={},
            evidence={},
        )
        # Det 2: impact (different category, different rule, no session, no process, no FIM) 2 minutes later
        det2 = Detection(
            id=uuid.uuid4(),
            rule_id=rule2.id,
            host_id=host_a.id,
            timestamp=now - timedelta(minutes=1),
            severity="high",
            title="Impact Alert",
            category="impact",
            status="open",
            notification_status="pending",
            matched_conditions={},
            evidence={},
        )
        db_session.add_all([det1, det2])
        db_session.flush()

        inc1, is_new1 = correlator.correlate_detection(db_session, det1)
        inc2, is_new2 = correlator.correlate_detection(db_session, det2)

        assert is_new1 is True
        assert is_new2 is True
        assert inc1.id != inc2.id

    def test_correlate_shared_source_event(
        self,
        db_session: Session,
        host_a: Host,
        detection_rule: DetectionRule,
        correlator: DetectionCorrelator,
    ) -> None:
        """Detections triggered by the same forensic source event are correlated."""
        now = datetime.now(timezone.utc)
        shared_event_id = uuid.uuid4()

        source_event = Event(
            id=shared_event_id,
            host_id=host_a.id,
            timestamp=now - timedelta(minutes=5),
            source="auditd",
            event_type="process",
            action="exec",
            severity="medium",
        )
        db_session.add(source_event)
        db_session.flush()

        det1 = Detection(
            id=uuid.uuid4(),
            rule_id=detection_rule.id,
            host_id=host_a.id,
            event_id=shared_event_id,
            timestamp=now - timedelta(minutes=5),
            severity="medium",
            title="Primary Alert from Event",
            category="execution",
            status="open",
            notification_status="pending",
            matched_conditions={},
            evidence={},
        )
        db_session.add(det1)
        db_session.flush()

        inc1, is_new1 = correlator.correlate_detection(db_session, det1)
        assert is_new1 is True

        rule2 = DetectionRule(
            id=uuid.uuid4(),
            rule_id="RULE-CORR-003",
            name="Secondary Rule",
            category="persistence",
            severity="high",
            enabled=True,
            version=1,
            rule_type="single_event",
            conditions={},
            created_at=now,
        )
        db_session.add(rule2)
        db_session.flush()

        det2 = Detection(
            id=uuid.uuid4(),
            rule_id=rule2.id,
            host_id=host_a.id,
            event_id=shared_event_id,
            timestamp=now,
            severity="high",
            title="Secondary Alert from Same Event",
            category="persistence",
            status="open",
            notification_status="pending",
            matched_conditions={},
            evidence={},
        )
        db_session.add(det2)
        db_session.flush()

        inc2, is_new2 = correlator.correlate_detection(db_session, det2)
        assert is_new2 is False
        assert inc2.id == inc1.id

    def test_correlate_recurring_detection_rule(
        self,
        db_session: Session,
        host_a: Host,
        detection_rule: DetectionRule,
        correlator: DetectionCorrelator,
    ) -> None:
        """Repeated triggers of the same detection rule on a host correlate within the window."""
        now = datetime.now(timezone.utc)

        det1 = Detection(
            id=uuid.uuid4(),
            rule_id=detection_rule.id,
            host_id=host_a.id,
            timestamp=now - timedelta(minutes=15),
            severity="medium",
            title="SSH Brute Force",
            category="credential_access",
            status="open",
            notification_status="pending",
            matched_conditions={},
            evidence={},
        )
        db_session.add(det1)
        db_session.flush()

        inc1, is_new1 = correlator.correlate_detection(db_session, det1)
        assert is_new1 is True

        det2 = Detection(
            id=uuid.uuid4(),
            rule_id=detection_rule.id,
            host_id=host_a.id,
            timestamp=now,
            severity="high",
            title="SSH Brute Force Recurrence",
            category="credential_access",
            status="open",
            notification_status="pending",
            matched_conditions={},
            evidence={},
        )
        db_session.add(det2)
        db_session.flush()

        inc2, is_new2 = correlator.correlate_detection(db_session, det2)
        assert is_new2 is False
        assert inc2.id == inc1.id
        assert inc2.severity == "high"
