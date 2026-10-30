"""Unit tests for Incident Lifecycle Management Service (Phase 2 Milestone 2.6)."""

from __future__ import annotations

from datetime import datetime, timezone
import uuid

import pytest
from sqlalchemy.orm import Session

from backend.db.models.app_user import AppUser
from backend.db.models.host import Host
from backend.db.models.incident import Incident
from backend.services.incidents.lifecycle import (
    compare_severities,
    validate_severity_change,
    validate_transition,
)
from backend.services.incidents.models import (
    HistoryChangeType,
    IncidentNotFoundError,
    IncidentSeverity,
    IncidentStatus,
    InvalidSeverityError,
    InvalidTransitionError,
    SeverityDowngradeError,
    UserNotFoundError,
)
from backend.services.incidents.service import IncidentService


@pytest.fixture
def test_host(db_session: Session) -> Host:
    host = Host(id=uuid.uuid4(), hostname="lifecycle-host")
    db_session.add(host)
    db_session.flush()
    return host


@pytest.fixture
def analyst_user(db_session: Session) -> AppUser:
    user = AppUser(
        id=uuid.uuid4(),
        username="analyst_alice",
        password_hash="fakehash",
        role="analyst",
        is_active=True,
    )
    db_session.add(user)
    db_session.flush()
    return user


@pytest.fixture
def incident_service() -> IncidentService:
    return IncidentService()


class TestIncidentLifecycleStateMachine:
    """Verify validation logic of the lifecycle state machine."""

    def test_valid_forward_transitions(self) -> None:
        # OPEN -> INVESTIGATING -> CONTAINED -> RESOLVED -> CLOSED
        validate_transition("open", "investigating")
        validate_transition("investigating", "contained")
        validate_transition("contained", "resolved")
        validate_transition("resolved", "closed")

    def test_valid_shortcuts(self) -> None:
        # OPEN -> CLOSED (e.g. false positive dismissal)
        validate_transition("open", "closed")
        # OPEN -> RESOLVED
        validate_transition("open", "resolved")
        # INVESTIGATING -> CLOSED
        validate_transition("investigating", "closed")
        # CONTAINED -> CLOSED
        validate_transition("contained", "closed")

    def test_reopening_requires_reason(self) -> None:
        # Reopening without reason must fail
        with pytest.raises(InvalidTransitionError, match="requires an explicit reason"):
            validate_transition("closed", "open", reason="")

        with pytest.raises(InvalidTransitionError, match="requires an explicit reason"):
            validate_transition("closed", "investigating", reason=None)

        with pytest.raises(InvalidTransitionError, match="requires an explicit reason"):
            validate_transition("resolved", "open", reason="   ")

        # Reopening with reason succeeds
        validate_transition("closed", "open", reason="New malicious activity detected")
        validate_transition("closed", "investigating", reason="Re-evaluating persistence")
        validate_transition("resolved", "investigating", reason="Persistence mechanism resurfaced")

    def test_invalid_transitions(self) -> None:
        # Same status transition
        with pytest.raises(InvalidTransitionError, match="already in status 'open'"):
            validate_transition("open", "open")

        with pytest.raises(InvalidTransitionError, match="already in status 'closed'"):
            validate_transition("closed", "closed")

        # Invalid jump: CLOSED -> CONTAINED is not allowed directly
        with pytest.raises(InvalidTransitionError, match="Invalid lifecycle transition"):
            validate_transition("closed", "contained", reason="Invalid")

        # Invalid jump: CLOSED -> RESOLVED is not allowed directly
        with pytest.raises(InvalidTransitionError, match="Invalid lifecycle transition"):
            validate_transition("closed", "resolved", reason="Invalid")

    def test_severity_comparison_and_escalation(self) -> None:
        assert compare_severities("low", "high") == -1
        assert compare_severities("high", "low") == 1
        assert compare_severities("medium", "medium") == 0
        assert compare_severities("critical", "high") == 1
        assert compare_severities("info", "low") == -1

        with pytest.raises(InvalidSeverityError):
            compare_severities("unknown", "high")

        # Escalation is allowed without downgrade flag
        validate_severity_change("medium", "critical")

        # Downgrade without flag raises SeverityDowngradeError
        with pytest.raises(SeverityDowngradeError, match="Cannot silently downgrade"):
            validate_severity_change("critical", "medium", allow_downgrade=False)

        # Downgrade with flag but empty reason raises SeverityDowngradeError
        with pytest.raises(SeverityDowngradeError, match="requires an explicit explanation"):
            validate_severity_change("critical", "medium", allow_downgrade=True, reason="")

        # Downgrade with flag and reason succeeds
        validate_severity_change(
            "critical", "medium", allow_downgrade=True, reason="De-escalated after verifying sandboxed environment"
        )


class TestIncidentServiceOperations:
    """Verify IncidentService operations, transactions, and audit history."""

    def test_create_and_get_incident(
        self,
        db_session: Session,
        incident_service: IncidentService,
        test_host: Host,
        analyst_user: AppUser,
    ) -> None:
        inc = incident_service.create_incident(
            db=db_session,
            title="Unauthorized Execution",
            description="Investigating suspicious sudo run",
            severity="high",
            category="privilege_escalation",
            host_id=test_host.id,
            assigned_to_id=analyst_user.id,
            created_by_id=analyst_user.id,
        )

        assert inc.id is not None
        assert inc.title == "Unauthorized Execution"
        assert inc.severity == "high"
        assert inc.status == IncidentStatus.OPEN.value
        assert inc.assigned_to_id == analyst_user.id

        # Check audit history was created
        history = incident_service.get_history(db_session, inc.id)
        assert len(history) == 1
        assert history[0].change_type == HistoryChangeType.INCIDENT_CREATED.value
        assert history[0].to_status == "open"
        assert history[0].to_severity == "high"

        # Fetch incident with joined loads
        fetched = incident_service.get_incident(db_session, inc.id)
        assert fetched is not None
        assert fetched.host.hostname == "lifecycle-host"
        assert fetched.assigned_to.username == "analyst_alice"

    def test_transition_status_and_timestamps(
        self,
        db_session: Session,
        incident_service: IncidentService,
        test_host: Host,
        analyst_user: AppUser,
    ) -> None:
        inc = incident_service.create_incident(
            db=db_session,
            title="Data Exfiltration",
            severity="critical",
            host_id=test_host.id,
        )

        # 1. Open -> Investigating
        inc = incident_service.transition_status(
            db=db_session,
            incident_id=inc.id,
            new_status="investigating",
            notes="Assigning triage analyst",
            acting_user_id=analyst_user.id,
        )
        assert inc.status == "investigating"

        # 2. Investigating -> Contained
        inc = incident_service.transition_status(
            db=db_session,
            incident_id=inc.id,
            new_status="contained",
            notes="Host network quarantined",
            containment_summary="Isolated veth interface",
            acting_user_id=analyst_user.id,
        )
        assert inc.status == "contained"
        assert inc.contained_at is not None
        assert inc.containment_summary == "Isolated veth interface"

        # 3. Contained -> Resolved
        inc = incident_service.transition_status(
            db=db_session,
            incident_id=inc.id,
            new_status="resolved",
            notes="Malicious process killed and persistence removed",
            resolution_summary="Terminated PID 8899 and removed cronjob",
            acting_user_id=analyst_user.id,
        )
        assert inc.status == "resolved"
        assert inc.resolved_at is not None
        assert inc.resolution_summary == "Terminated PID 8899 and removed cronjob"

        # 4. Resolved -> Closed
        inc = incident_service.transition_status(
            db=db_session,
            incident_id=inc.id,
            new_status="closed",
            notes="Post-incident review complete",
            closure_summary="Confirmed no data loss occurred",
            acting_user_id=analyst_user.id,
        )
        assert inc.status == "closed"
        assert inc.closed_at is not None
        assert inc.closure_summary == "Confirmed no data loss occurred"

        # Check complete history
        hist = incident_service.get_history(db_session, inc.id)
        # 1 create + 4 status transitions = 5 records
        assert len(hist) == 5

    def test_reopening_closed_incident(
        self,
        db_session: Session,
        incident_service: IncidentService,
        test_host: Host,
        analyst_user: AppUser,
    ) -> None:
        inc = incident_service.create_incident(
            db=db_session,
            title="Credential Dumping",
            severity="critical",
            host_id=test_host.id,
        )
        incident_service.transition_status(
            db=db_session,
            incident_id=inc.id,
            new_status="closed",
            closure_summary="Resolved immediately",
        )

        # Attempt reopen without notes fails
        with pytest.raises(InvalidTransitionError, match="requires an explicit reason"):
            incident_service.transition_status(
                db=db_session,
                incident_id=inc.id,
                new_status="open",
                notes="",
            )

        # Reopen with notes succeeds
        inc = incident_service.transition_status(
            db=db_session,
            incident_id=inc.id,
            new_status="open",
            notes="Reopened: Secondary mimikatz payload detected",
            acting_user_id=analyst_user.id,
        )
        assert inc.status == "open"
        assert inc.closed_at is None

    def test_severity_escalation_and_downgrade(
        self,
        db_session: Session,
        incident_service: IncidentService,
        test_host: Host,
        analyst_user: AppUser,
    ) -> None:
        inc = incident_service.create_incident(
            db=db_session,
            title="Suspicious SSH",
            severity="low",
            host_id=test_host.id,
        )

        # Escalate low -> high
        inc = incident_service.escalate_severity(
            db=db_session,
            incident_id=inc.id,
            new_severity="high",
            reason="Multiple failed root logins followed by successful key auth",
            acting_user_id=analyst_user.id,
        )
        assert inc.severity == "high"

        # Attempt silent downgrade fails
        with pytest.raises(SeverityDowngradeError, match="Cannot silently downgrade"):
            incident_service.escalate_severity(
                db=db_session,
                incident_id=inc.id,
                new_severity="low",
                reason="Downgrading without permission",
                allow_downgrade=False,
            )

        # Authorized downgrade succeeds
        inc = incident_service.escalate_severity(
            db=db_session,
            incident_id=inc.id,
            new_severity="low",
            reason="Confirmed authorized penetration test activity",
            allow_downgrade=True,
            acting_user_id=analyst_user.id,
        )
        assert inc.severity == "low"

    def test_analyst_assignment_and_notes(
        self,
        db_session: Session,
        incident_service: IncidentService,
        test_host: Host,
        analyst_user: AppUser,
    ) -> None:
        inc = incident_service.create_incident(
            db=db_session,
            title="Rootkit Probe",
            severity="medium",
            host_id=test_host.id,
        )
        assert inc.assigned_to_id is None

        # Assign to analyst
        inc = incident_service.assign_incident(
            db=db_session,
            incident_id=inc.id,
            assigned_to_id=analyst_user.id,
            notes="Assigned to lead analyst Alice",
        )
        assert inc.assigned_to_id == analyst_user.id

        # Add investigation note
        note_entry = incident_service.add_note(
            db=db_session,
            incident_id=inc.id,
            notes="Analyzed /proc memory maps; no inline hooks detected.",
            acting_user_id=analyst_user.id,
        )
        assert note_entry.change_type == HistoryChangeType.NOTE_ADDED.value
        assert "no inline hooks" in note_entry.notes

        # Empty note rejected
        with pytest.raises(ValueError, match="cannot be empty"):
            incident_service.add_note(
                db=db_session,
                incident_id=inc.id,
                notes="   ",
            )

    def test_reopening_resolved_incident_clears_resolution_metadata(
        self,
        db_session: Session,
        incident_service: IncidentService,
        test_host: Host,
        analyst_user: AppUser,
    ) -> None:
        inc = incident_service.create_incident(
            db=db_session,
            title="Resolvable Threat",
            severity="medium",
            host_id=test_host.id,
        )

        # Transition to resolved
        inc = incident_service.transition_status(
            db=db_session,
            incident_id=inc.id,
            new_status="resolved",
            resolution_summary="Remediation applied successfully",
        )
        assert inc.status == "resolved"
        assert inc.resolved_at is not None
        assert inc.resolution_summary == "Remediation applied successfully"

        # Reopen to investigating with reason
        inc = incident_service.transition_status(
            db=db_session,
            incident_id=inc.id,
            new_status="investigating",
            notes="New indicators discovered, reopening investigation",
            acting_user_id=analyst_user.id,
        )
        assert inc.status == "investigating"
        assert inc.resolved_at is None
        assert inc.resolution_summary is None

    def test_update_incident_empty_title_and_category_rejected(
        self,
        db_session: Session,
        incident_service: IncidentService,
        test_host: Host,
    ) -> None:
        inc = incident_service.create_incident(
            db=db_session,
            title="Valid Initial Title",
            severity="low",
            category="reconnaissance",
            host_id=test_host.id,
        )

        with pytest.raises(ValueError, match="Incident title cannot be empty"):
            incident_service.update_incident(db_session, inc.id, title="   ")

        with pytest.raises(ValueError, match="Incident category cannot be empty"):
            incident_service.update_incident(db_session, inc.id, category="   ")
