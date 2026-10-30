"""Unit tests for Forensic Incident Report Generator (Phase 2 Milestone 2.6)."""

from __future__ import annotations

from datetime import datetime, timezone
import uuid

import pytest
from sqlalchemy.orm import Session

from backend.db.models.app_user import AppUser
from backend.db.models.detection import Detection
from backend.db.models.detection_rule import DetectionRule
from backend.db.models.event import Event
from backend.db.models.fim_baseline import FimBaseline
from backend.db.models.fim_deviation import FimDeviation
from backend.db.models.host import Host
from backend.db.models.incident import Incident
from backend.db.models.incident_evidence import IncidentEvidence
from backend.db.models.snapshot import Snapshot
from backend.db.models.user_session import UserSession
from backend.services.incidents.evidence_manager import EvidenceManager
from backend.services.incidents.models import IncidentNotFoundError
from backend.services.incidents.report import ReportGenerator
from backend.services.incidents.service import IncidentService


@pytest.fixture
def host(db_session: Session) -> Host:
    h = Host(id=uuid.uuid4(), hostname="compromised-server-01", ip_address="10.0.0.15")
    db_session.add(h)
    db_session.flush()
    return h


@pytest.fixture
def analyst_user(db_session: Session) -> AppUser:
    u = AppUser(
        id=uuid.uuid4(),
        username="lead_analyst",
        password_hash="fakehash",
        display_name="Lead Analyst Jane",
        role="analyst",
        is_active=True,
    )
    db_session.add(u)
    db_session.flush()
    return u


@pytest.fixture
def detection_rule(db_session: Session) -> DetectionRule:
    rule = DetectionRule(
        id=uuid.uuid4(),
        rule_id="RULE-REPORT-001",
        name="Suspicious Privilege Escalation",
        category="privilege_escalation",
        severity="high",
        enabled=True,
        version=1,
        rule_type="single_event",
        conditions={},
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(rule)
    db_session.flush()
    return rule


class TestReportGenerator:
    """Validate structured forensic report generation and markdown export."""

    def test_generate_report_not_found(self, db_session: Session) -> None:
        generator = ReportGenerator()
        with pytest.raises(IncidentNotFoundError):
            generator.generate_report(db_session, uuid.uuid4())

    def test_generate_report_structure(
        self,
        db_session: Session,
        host: Host,
        analyst_user: AppUser,
        detection_rule: DetectionRule,
    ) -> None:
        service = IncidentService()
        em = EvidenceManager()
        generator = ReportGenerator()
        now = datetime.now(timezone.utc)

        # 1. Create incident
        incident = service.create_incident(
            db=db_session,
            title="Unauthorized Root Access Detected",
            severity="high",
            category="privilege_escalation",
            host_id=host.id,
            description="Investigating suspicious root shell spawn.",
            created_by_id=analyst_user.id,
        )

        # 2. Add an analyst note and assign
        service.assign_incident(db_session, incident.id, analyst_user.id, acting_user_id=analyst_user.id)
        service.add_note(db_session, incident.id, "Initial review confirms rogue sudoers entry.", acting_user_id=analyst_user.id)

        # 3. Add detection evidence
        det = Detection(
            id=uuid.uuid4(),
            rule_id=detection_rule.id,
            host_id=host.id,
            timestamp=now,
            severity="high",
            title="Sudo PrivEsc",
            description="sudo command without valid password",
            category="privilege_escalation",
            status="open",
            notification_status="pending",
            matched_conditions={"command": "sudo -u root /bin/bash"},
            evidence={"pid": 9999},
        )
        db_session.add(det)
        db_session.flush()
        em.link_detection(db_session, incident, det, acting_user_id=analyst_user.id)

        # 4. Add session evidence
        sess = UserSession(
            id=uuid.uuid4(),
            host_id=host.id,
            session_type="ssh",
            terminal="pts/1",
            remote_host="192.168.100.55",
            started_at=now,
        )
        db_session.add(sess)
        db_session.flush()
        em.link_session(db_session, incident, sess, acting_user_id=analyst_user.id)

        # 5. Add FIM deviation evidence
        baseline = FimBaseline(
            id=uuid.uuid4(),
            host_id=host.id,
            version=1,
            path_scope=["/etc"],
            created_at=now,
        )
        db_session.add(baseline)
        db_session.flush()
        dev = FimDeviation(
            id=uuid.uuid4(),
            baseline_id=baseline.id,
            host_id=host.id,
            file_path="/etc/sudoers.d/backdoor",
            file_type="file",
            deviation_type="modified_file",
            severity="critical",
            is_content_modified=True,
            is_metadata_modified=False,
            expected_values={},
            observed_values={"size": 42},
            detected_at=now,
            created_at=now,
        )
        db_session.add(dev)
        db_session.flush()
        em.link_fim_deviation(db_session, incident, dev, acting_user_id=analyst_user.id)

        # 6. Add snapshot evidence
        snap = Snapshot(
            id=uuid.uuid4(),
            host_id=host.id,
            snapshot_type="post_containment",
            timestamp=now,
            data={"process_count": 50},
            created_at=now,
        )
        db_session.add(snap)
        db_session.flush()
        em.link_snapshot(db_session, incident, snap, acting_user_id=analyst_user.id)

        # 7. Add forensic event
        evt = Event(
            id=uuid.uuid4(),
            host_id=host.id,
            timestamp=now,
            event_type="exec",
            action="spawn",
            source="auditd",
            command="chmod +s /tmp/backdoor",
            success=True,
        )
        db_session.add(evt)
        db_session.flush()
        em.link_event(db_session, incident, evt, notes="Suspicious chmod SUID", acting_user_id=analyst_user.id)

        # 8. Generate report
        report = generator.generate_report(db_session, incident.id)

        assert report["incident"]["id"] == str(incident.id)
        assert report["incident"]["title"] == "Unauthorized Root Access Detected"
        assert report["incident"]["host"]["hostname"] == "compromised-server-01"
        assert report["incident"]["assigned_to"]["username"] == "lead_analyst"

        # Check evidence collections
        assert len(report["detections"]) == 1
        assert report["detections"][0]["status"] == "available"
        assert report["detections"][0]["details"]["title"] == "Sudo PrivEsc"

        assert len(report["sessions"]) == 1
        assert report["sessions"][0]["details"]["terminal"] == "pts/1"

        assert len(report["fim_deviations"]) == 1
        assert report["fim_deviations"][0]["details"]["file_path"] == "/etc/sudoers.d/backdoor"

        assert len(report["snapshots"]) == 1
        assert report["snapshots"][0]["details"]["snapshot_type"] == "post_containment"

        assert len(report["evidence_inventory"]) >= 4

        # Verify timeline facts vs interpretations
        timeline = report["timeline"]
        assert len(timeline) > 0
        facts = [t for t in timeline if t.get("nature") == "observed_fact"]
        interps = [t for t in timeline if t.get("nature") in ("analyst_interpretation", "system_lifecycle")]

        assert len(facts) >= 4  # detection, session, fim, snapshot, event
        assert len(interps) >= 2  # creation, assignment, note

        # Verify linked events collection
        assert "events" in report
        assert len(report["events"]) == 1
        assert report["events"][0]["relationship"] == "related"
        assert report["events"][0]["investigation_notes"] == "Suspicious chmod SUID"

        # Verify export to markdown
        md = generator.export_markdown(report)
        assert "# OSIRIS Forensic Incident Report: Unauthorized Root Access Detected" in md
        assert "**Monitored Host:** `compromised-server-01`" in md
        assert "## 1. Executive Summary" in md
        assert "## 6. Relevant System Snapshots" in md
        assert "post_containment" in md
        assert "## 7. Chronological Forensic Timeline" in md
        assert "[FACT]" in md
        assert "## 8. Evidence Inventory & Provenance" in md

    def test_generate_report_handles_missing_source_entity(
        self,
        db_session: Session,
        host: Host,
    ) -> None:
        service = IncidentService()
        generator = ReportGenerator()

        incident = service.create_incident(
            db=db_session,
            title="Incident with Deleted Artifacts",
            severity="low",
            category="reconnaissance",
            host_id=host.id,
        )

        # Manually create evidence pointing to a non-existent detection UUID
        missing_uuid = uuid.uuid4()
        orphan_evidence = IncidentEvidence(
            id=uuid.uuid4(),
            incident_id=incident.id,
            evidence_type="detection",
            source_id=str(missing_uuid),
            title="Orphan Detection Evidence",
            description="Cached evidence metadata",
            provenance={"cached_rule": "RULE-OLD", "note": "Purged during retention sweep"},
            detection_id=None,
            created_at=datetime.now(timezone.utc),
        )
        db_session.add(orphan_evidence)
        db_session.flush()

        # Generate report — must not raise an exception
        report = generator.generate_report(db_session, incident.id)
        assert len(report["detections"]) == 1
        det_entry = report["detections"][0]
        assert det_entry["status"] == "missing_source"
        assert det_entry["details"]["cached_rule"] == "RULE-OLD"

        # Markdown output handles missing sources gracefully
        md = generator.export_markdown(report)
        assert "[SOURCE MISSING]" in md

    def test_export_markdown_bare_incident(self, db_session: Session) -> None:
        service = IncidentService()
        generator = ReportGenerator()

        incident = service.create_incident(
            db=db_session,
            title="Bare Incident Without Host or Evidence",
            severity="info",
            category="general",
            host_id=None,
        )

        report = generator.generate_report(db_session, incident.id)
        assert report["incident"]["host"] is None
        assert report["incident"]["assigned_to"] is None
        assert len(report["evidence_inventory"]) == 0

        md = generator.export_markdown(report)
        assert "Bare Incident Without Host or Evidence" in md
        assert "**Monitored Host:** `N/A` (N/A)" in md
        assert "**Assigned Analyst:** Unassigned" in md
        assert "No automated security detections linked to this incident." in md
        assert "No file integrity deviations linked to this incident." in md
        assert "No user login sessions linked to this incident." in md

    def test_report_read_only_safety(self, db_session: Session, host: Host) -> None:
        service = IncidentService()
        generator = ReportGenerator()

        incident = service.create_incident(
            db=db_session,
            title="Read Only Verification",
            severity="medium",
            category="general",
            host_id=host.id,
        )

        # Clear session dirtiness
        db_session.commit()

        # Run report generation
        _ = generator.generate_report(db_session, incident.id)

        # Verify nothing dirty or pending
        assert not db_session.dirty
        assert not db_session.new
        assert not db_session.deleted

    def test_report_detects_missing_process_and_file_sources(
        self,
        db_session: Session,
        host: Host,
    ) -> None:
        service = IncidentService()
        generator = ReportGenerator()
        now = datetime.now(timezone.utc)

        incident = service.create_incident(
            db=db_session,
            title="Incident with Missing Process and File",
            severity="medium",
            host_id=host.id,
        )

        missing_proc_id = uuid.uuid4()
        missing_file_id = uuid.uuid4()

        ev_proc = IncidentEvidence(
            id=uuid.uuid4(),
            incident_id=incident.id,
            evidence_type="process",
            source_id=str(missing_proc_id),
            title="Terminated Malware Process",
            process_id=None,
            provenance={"pid": 6666, "command": "/tmp/evil"},
            created_at=now,
        )
        ev_file = IncidentEvidence(
            id=uuid.uuid4(),
            incident_id=incident.id,
            evidence_type="file",
            source_id=str(missing_file_id),
            title="Deleted Dropper File",
            file_id=None,
            provenance={"path": "/tmp/evil"},
            created_at=now,
        )
        db_session.add_all([ev_proc, ev_file])
        db_session.flush()

        report = generator.generate_report(db_session, incident.id)
        ev_inv = {e["id"]: e for e in report["evidence_inventory"]}

        assert ev_inv[str(ev_proc.id)]["source_available"] is False
        assert ev_inv[str(ev_file.id)]["source_available"] is False
