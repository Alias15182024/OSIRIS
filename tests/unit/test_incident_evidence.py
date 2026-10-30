"""Unit tests for Forensic Evidence Linking & Provenance (Phase 2 Milestone 2.6)."""

from __future__ import annotations

from datetime import datetime, timezone
import uuid

import pytest
from sqlalchemy.orm import Session

from backend.db.models.app_user import AppUser
from backend.db.models.detection import Detection
from backend.db.models.detection_rule import DetectionRule
from backend.db.models.event import Event
from backend.db.models.file import File
from backend.db.models.fim_baseline import FimBaseline
from backend.db.models.fim_deviation import FimDeviation
from backend.db.models.host import Host
from backend.db.models.incident import Incident
from backend.db.models.process import Process
from backend.db.models.snapshot import Snapshot
from backend.db.models.user_session import UserSession
from backend.services.incidents.evidence_manager import EvidenceManager
from backend.services.incidents.models import (
    EvidenceDuplicateError,
    EvidenceType,
    HostMismatchError,
)
from backend.services.incidents.service import IncidentService


@pytest.fixture
def test_host_a(db_session: Session) -> Host:
    host = Host(id=uuid.uuid4(), hostname="victim-host-a")
    db_session.add(host)
    db_session.flush()
    return host


@pytest.fixture
def test_host_b(db_session: Session) -> Host:
    host = Host(id=uuid.uuid4(), hostname="unrelated-host-b")
    db_session.add(host)
    db_session.flush()
    return host


@pytest.fixture
def test_incident(db_session: Session, test_host_a: Host) -> Incident:
    inc = Incident(
        id=uuid.uuid4(),
        title="Active Attack on Host A",
        severity="high",
        status="open",
        category="reconnaissance",
        host_id=test_host_a.id,
    )
    db_session.add(inc)
    db_session.flush()
    return inc


@pytest.fixture
def evidence_manager() -> EvidenceManager:
    return EvidenceManager()


class TestEvidenceLinking:
    """Verify evidence association across all supported forensic entities."""

    def test_link_detection_evidence(
        self,
        db_session: Session,
        test_host_a: Host,
        test_incident: Incident,
        evidence_manager: EvidenceManager,
    ) -> None:
        now = datetime.now(timezone.utc)
        rule = DetectionRule(
            id=uuid.uuid4(),
            rule_id="RULE-EXEC-001",
            name="Suspicious Binary Execution",
            category="execution",
            severity="high",
            enabled=True,
            version=1,
            rule_type="single_event",
            conditions={},
            created_at=now,
        )
        db_session.add(rule)
        db_session.flush()

        det = Detection(
            id=uuid.uuid4(),
            rule_id=rule.id,
            rule_version=1,
            host_id=test_host_a.id,
            timestamp=now,
            severity="high",
            title="Suspicious Binary Executed",
            category="execution",
            matched_conditions={"matched": True},
            evidence={"cmd": "/tmp/nc -e /bin/sh"},
            created_at=now,
        )
        db_session.add(det)
        db_session.flush()

        ev = evidence_manager.link_detection(
            db=db_session,
            incident=test_incident,
            detection=det,
            reason="Correlated reverse shell tool",
        )

        assert ev.evidence_type == EvidenceType.DETECTION.value
        assert ev.source_id == str(det.id)
        assert ev.detection_id == det.id
        assert ev.provenance["subsystem"] == "detection_engine"
        assert ev.provenance["severity"] == "high"
        assert ev.provenance["rule_title"] == "Suspicious Binary Executed"

    def test_link_event_and_incident_events(
        self,
        db_session: Session,
        test_host_a: Host,
        test_incident: Incident,
        evidence_manager: EvidenceManager,
    ) -> None:
        now = datetime.now(timezone.utc)
        event = Event(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            timestamp=now,
            ingested_at=now,
            source="process_collector",
            event_type="process_spawn",
            action="spawn",
            severity="high",
            uid=0,
            username="root",
            pid=7744,
            command="/bin/bash -i",
            created_at=now,
        )
        db_session.add(event)
        db_session.flush()

        inc_evt, inc_ev = evidence_manager.link_event(
            db=db_session,
            incident=test_incident,
            event=event,
            relationship="triggering_spawn",
            notes="Interactive shell spawned by root",
        )

        assert inc_evt.incident_id == test_incident.id
        assert inc_evt.event_id == event.id
        assert inc_evt.relationship_role == "triggering_spawn"
        assert inc_ev.evidence_type == EvidenceType.EVENT.value
        assert inc_ev.source_id == str(event.id)
        assert inc_ev.provenance["subsystem"] == "event_stream"
        assert inc_ev.provenance["command"] == "/bin/bash -i"

    def test_link_fim_deviation(
        self,
        db_session: Session,
        test_host_a: Host,
        test_incident: Incident,
        evidence_manager: EvidenceManager,
    ) -> None:
        now = datetime.now(timezone.utc)
        baseline = FimBaseline(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            version=1,
            path_scope=["/etc"],
            created_at=now,
        )
        db_session.add(baseline)
        db_session.flush()

        deviation = FimDeviation(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            baseline_id=baseline.id,
            file_path="/etc/sudoers",
            file_type="file",
            deviation_type="modified_file",
            severity="critical",
            is_content_modified=True,
            is_metadata_modified=False,
            expected_values={"sha256": "1111"},
            observed_values={"sha256": "2222"},
            detected_at=now,
            created_at=now,
        )
        db_session.add(deviation)
        db_session.flush()

        ev = evidence_manager.link_fim_deviation(
            db=db_session,
            incident=test_incident,
            deviation=deviation,
            reason="Unauthorized alteration of sudoers configuration",
        )

        assert ev.evidence_type == EvidenceType.FIM_DEVIATION.value
        assert ev.fim_deviation_id == deviation.id
        assert ev.provenance["file_path"] == "/etc/sudoers"
        assert ev.provenance["deviation_type"] == "modified_file"

    def test_link_session_evidence(
        self,
        db_session: Session,
        test_host_a: Host,
        test_incident: Incident,
        evidence_manager: EvidenceManager,
    ) -> None:
        now = datetime.now(timezone.utc)
        session = UserSession(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            terminal="pts/3",
            remote_host="192.168.1.50",
            session_type="ssh",
            started_at=now,
            created_at=now,
        )
        db_session.add(session)
        db_session.flush()

        ev = evidence_manager.link_session(
            db=db_session,
            incident=test_incident,
            session=session,
            reason="SSH session from untrusted subnet",
        )

        assert ev.evidence_type == EvidenceType.SESSION.value
        assert ev.session_id == session.id
        assert ev.provenance["remote_host"] == "192.168.1.50"

    def test_link_snapshot_evidence(
        self,
        db_session: Session,
        test_host_a: Host,
        test_incident: Incident,
        evidence_manager: EvidenceManager,
    ) -> None:
        now = datetime.now(timezone.utc)
        snap = Snapshot(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            timestamp=now,
            snapshot_type="system_state",
            data={"process_count": 142},
            created_at=now,
        )
        db_session.add(snap)
        db_session.flush()

        ev = evidence_manager.link_snapshot(
            db=db_session,
            incident=test_incident,
            snapshot=snap,
        )

        assert ev.evidence_type == EvidenceType.SNAPSHOT.value
        assert ev.snapshot_id == snap.id

    def test_link_process_and_file_evidence(
        self,
        db_session: Session,
        test_host_a: Host,
        test_incident: Incident,
        evidence_manager: EvidenceManager,
    ) -> None:
        now = datetime.now(timezone.utc)
        proc = Process(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            pid=3344,
            ppid=1,
            command="/usr/local/bin/malware --silent",
            executable="/usr/local/bin/malware",
            started_at=now,
            created_at=now,
        )
        db_session.add(proc)

        file_rec = File(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            path="/usr/local/bin/malware",
            file_type="file",
            first_seen_at=now,
            created_at=now,
        )
        db_session.add(file_rec)
        db_session.flush()

        ev_proc = evidence_manager.link_process(db_session, test_incident, proc)
        ev_file = evidence_manager.link_file(db_session, test_incident, file_rec)

        assert ev_proc.evidence_type == EvidenceType.PROCESS.value
        assert ev_proc.process_id == proc.id
        assert ev_file.evidence_type == EvidenceType.FILE.value
        assert ev_file.file_id == file_rec.id

    def test_prevent_cross_host_contamination(
        self,
        db_session: Session,
        test_host_b: Host,
        test_incident: Incident,
        evidence_manager: EvidenceManager,
    ) -> None:
        now = datetime.now(timezone.utc)
        # Event originating from Host B
        event_b = Event(
            id=uuid.uuid4(),
            host_id=test_host_b.id,
            timestamp=now,
            ingested_at=now,
            source="process_collector",
            event_type="process_spawn",
            action="spawn",
            severity="low",
            created_at=now,
        )
        db_session.add(event_b)
        db_session.flush()

        # Attempting to link Host B event to Host A incident must raise HostMismatchError
        with pytest.raises(HostMismatchError, match="Cross-host evidence contamination rejected"):
            evidence_manager.link_event(
                db=db_session,
                incident=test_incident,
                event=event_b,
            )

    def test_prevent_duplicate_evidence_association(
        self,
        db_session: Session,
        test_host_a: Host,
        test_incident: Incident,
        evidence_manager: EvidenceManager,
    ) -> None:
        now = datetime.now(timezone.utc)
        event = Event(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            timestamp=now,
            ingested_at=now,
            source="process_collector",
            event_type="exec",
            action="exec",
            severity="medium",
            created_at=now,
        )
        db_session.add(event)
        db_session.flush()

        # Link first time
        evidence_manager.link_event(db_session, test_incident, event)

        # Linking second time with raise_if_duplicate=True raises EvidenceDuplicateError
        with pytest.raises(EvidenceDuplicateError, match="already linked"):
            evidence_manager.link_event(db_session, test_incident, event, raise_if_duplicate=True)

        # Linking second time with raise_if_duplicate=False returns existing records cleanly
        inc_evt, inc_ev = evidence_manager.link_event(
            db_session, test_incident, event, raise_if_duplicate=False
        )
        assert inc_evt.event_id == event.id
        assert inc_ev.source_id == str(event.id)
