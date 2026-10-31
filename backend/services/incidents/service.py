"""Core Incident Service implementing lifecycle, queries, and audit management."""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Optional, Sequence
import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from backend.db.base import utcnow
from backend.db.models.app_user import AppUser
from backend.db.models.host import Host
from backend.db.models.incident import Incident, VALID_INCIDENT_SEVERITIES, VALID_INCIDENT_STATUSES
from backend.db.models.incident_event import IncidentEvent
from backend.db.models.incident_evidence import IncidentEvidence
from backend.db.models.incident_history import IncidentHistory
from backend.services.incidents.lifecycle import (
    compare_severities,
    validate_severity_change,
    validate_transition,
)
from backend.services.incidents.models import (
    HistoryChangeType,
    HostMismatchError,
    IncidentNotFoundError,
    IncidentSeverity,
    IncidentStatus,
    InvalidSeverityError,
    InvalidTransitionError,
    UserNotFoundError,
)

logger = logging.getLogger("osiris.services.incidents.service")


def _ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class IncidentService:
    """Authoritative service for incident creation, lifecycle transitions, and queries."""

    def create_incident(
        self,
        db: Session,
        title: str,
        description: Optional[str] = None,
        severity: str = IncidentSeverity.MEDIUM.value,
        category: str = "general",
        host_id: Optional[uuid.UUID] = None,
        assigned_to_id: Optional[uuid.UUID] = None,
        created_by_id: Optional[uuid.UUID] = None,
        first_observed_at: Optional[datetime] = None,
        last_observed_at: Optional[datetime] = None,
    ) -> Incident:
        """Create a new incident manually or programmatically."""
        sev_norm = severity.lower()
        if sev_norm not in VALID_INCIDENT_SEVERITIES:
            raise InvalidSeverityError(f"Invalid severity value: '{severity}'")

        if host_id is not None and db.get(Host, host_id) is None:
            raise HostMismatchError(f"Host '{host_id}' does not exist.")

        if assigned_to_id is not None and db.get(AppUser, assigned_to_id) is None:
            raise UserNotFoundError(f"Assigned user '{assigned_to_id}' not found.")

        if created_by_id is not None and db.get(AppUser, created_by_id) is None:
            raise UserNotFoundError(f"Created-by user '{created_by_id}' not found.")

        now = utcnow()
        first_obs = _ensure_utc(first_observed_at) or now
        last_obs = _ensure_utc(last_observed_at) or first_obs

        incident = Incident(
            title=title.strip(),
            description=description.strip() if description else None,
            severity=sev_norm,
            status=IncidentStatus.OPEN.value,
            category=category.strip(),
            host_id=host_id,
            created_by_id=created_by_id,
            assigned_to_id=assigned_to_id,
            first_observed_at=first_obs,
            last_observed_at=last_obs,
            created_at=now,
            updated_at=None,
        )
        db.add(incident)
        db.flush()

        # Record creation in history
        history = IncidentHistory(
            incident_id=incident.id,
            change_type=HistoryChangeType.INCIDENT_CREATED.value,
            to_status=IncidentStatus.OPEN.value,
            to_severity=sev_norm,
            user_id=created_by_id,
            notes="Incident created",
            history_metadata={"category": category, "host_id": str(host_id) if host_id else None},
            created_at=now,
        )
        db.add(history)
        db.flush()

        return incident

    def get_incident(
        self,
        db: Session,
        incident_id: uuid.UUID,
        *,
        eager_load: bool = True,
        for_update: bool = False,
    ) -> Incident | None:
        """Retrieve a single incident by ID with optional eager loaded relationships and row-level locking."""
        stmt = select(Incident).where(Incident.id == incident_id)
        if eager_load:
            stmt = stmt.options(
                joinedload(Incident.host),
                joinedload(Incident.created_by),
                joinedload(Incident.assigned_to),
                joinedload(Incident.evidence),
                joinedload(Incident.events).joinedload(IncidentEvent.event),
                joinedload(Incident.history).joinedload(IncidentHistory.user),
            )
        if for_update:
            stmt = stmt.with_for_update()
        return db.execute(stmt).unique().scalar_one_or_none()

    def get_incident_or_404(
        self,
        db: Session,
        incident_id: uuid.UUID,
        *,
        eager_load: bool = True,
        for_update: bool = False,
    ) -> Incident:
        """Retrieve incident by ID or raise IncidentNotFoundError."""
        inc = self.get_incident(db, incident_id, eager_load=eager_load, for_update=for_update)
        if inc is None:
            raise IncidentNotFoundError(f"Incident '{incident_id}' not found.")
        return inc

    def list_incidents(
        self,
        db: Session,
        host_id: Optional[uuid.UUID] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        category: Optional[str] = None,
        assigned_to_id: Optional[uuid.UUID] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Incident], int]:
        """Fetch paginated incidents with structured filters and deterministic ordering."""
        stmt = select(Incident).options(
            joinedload(Incident.host),
            joinedload(Incident.assigned_to),
            joinedload(Incident.created_by),
        )

        conditions = []
        if host_id is not None:
            conditions.append(Incident.host_id == host_id)
        if severity is not None:
            conditions.append(Incident.severity == severity.lower())
        if status is not None:
            conditions.append(Incident.status == status.lower())
        if category is not None:
            conditions.append(Incident.category == category.lower())
        if assigned_to_id is not None:
            conditions.append(Incident.assigned_to_id == assigned_to_id)
        if start_time is not None:
            conditions.append(Incident.created_at >= _ensure_utc(start_time))
        if end_time is not None:
            conditions.append(Incident.created_at <= _ensure_utc(end_time))

        if conditions:
            stmt = stmt.where(*conditions)

        count_stmt = select(func.count(Incident.id))
        if conditions:
            count_stmt = count_stmt.where(*conditions)
        total = db.execute(count_stmt).scalar() or 0

        # Deterministic ordering: latest created_at first, then id ascending
        stmt = stmt.order_by(Incident.created_at.desc(), Incident.id.asc())
        stmt = stmt.limit(limit).offset(offset)

        items = list(db.execute(stmt).scalars().unique().all())
        return items, total

    def update_incident(
        self,
        db: Session,
        incident_id: uuid.UUID,
        title: Optional[str] = None,
        description: Optional[str] = None,
        category: Optional[str] = None,
        assigned_to_id: Optional[uuid.UUID] = None,
        acting_user_id: Optional[uuid.UUID] = None,
    ) -> Incident:
        """Update incident descriptive attributes and analyst assignment."""
        incident = self.get_incident_or_404(db, incident_id, eager_load=False, for_update=True)
        now = utcnow()
        changes = []

        if title is not None:
            clean_title = title.strip()
            if not clean_title:
                raise ValueError("Incident title cannot be empty.")
            if clean_title != incident.title:
                changes.append(f"Title changed from '{incident.title}' to '{clean_title}'")
                incident.title = clean_title

        if description is not None and description.strip() != (incident.description or ""):
            changes.append("Description updated")
            incident.description = description.strip()

        if category is not None:
            clean_cat = category.strip()
            if not clean_cat:
                raise ValueError("Incident category cannot be empty.")
            if clean_cat != incident.category:
                changes.append(f"Category changed from '{incident.category}' to '{clean_cat}'")
                incident.category = clean_cat

        if assigned_to_id is not None and assigned_to_id != incident.assigned_to_id:
            user = db.get(AppUser, assigned_to_id)
            if user is None:
                raise UserNotFoundError(f"Assigned user '{assigned_to_id}' not found.")
            changes.append(f"Assigned to user '{user.username}'")
            incident.assigned_to_id = assigned_to_id

        if changes:
            incident.updated_at = now
            history = IncidentHistory(
                incident_id=incident.id,
                change_type=HistoryChangeType.INCIDENT_UPDATED.value,
                user_id=acting_user_id,
                notes="; ".join(changes),
                created_at=now,
            )
            db.add(history)
            db.flush()

        return incident

    def transition_status(
        self,
        db: Session,
        incident_id: uuid.UUID,
        new_status: str,
        notes: Optional[str] = None,
        containment_summary: Optional[str] = None,
        resolution_summary: Optional[str] = None,
        closure_summary: Optional[str] = None,
        acting_user_id: Optional[uuid.UUID] = None,
    ) -> Incident:
        """Transition an incident to a new lifecycle state with strict validation."""
        incident = self.get_incident_or_404(db, incident_id, eager_load=False, for_update=True)
        old_status = incident.status
        target_status = new_status.lower()

        # Validate transition using the lifecycle state machine
        validate_transition(old_status, target_status, reason=notes)

        now = utcnow()
        incident.status = target_status
        incident.updated_at = now

        # Record timestamps and summaries based on new status
        if target_status == IncidentStatus.CONTAINED.value:
            incident.contained_at = now
            if containment_summary:
                incident.containment_summary = containment_summary.strip()
        elif target_status == IncidentStatus.RESOLVED.value:
            incident.resolved_at = now
            if resolution_summary:
                incident.resolution_summary = resolution_summary.strip()
        elif target_status == IncidentStatus.CLOSED.value:
            incident.closed_at = now
            if closure_summary:
                incident.closure_summary = closure_summary.strip()
        elif target_status in (IncidentStatus.OPEN.value, IncidentStatus.INVESTIGATING.value):
            # Reopening or ongoing investigation: clear closed and resolved metadata if previously closed or resolved
            if old_status == IncidentStatus.CLOSED.value:
                incident.closed_at = None
                incident.closure_summary = None
            if old_status in (IncidentStatus.RESOLVED.value, IncidentStatus.CLOSED.value):
                incident.resolved_at = None
                incident.resolution_summary = None

        # Build history entry
        summary_text = notes or ""
        if containment_summary:
            summary_text += f" [Containment: {containment_summary}]"
        if resolution_summary:
            summary_text += f" [Resolution: {resolution_summary}]"
        if closure_summary:
            summary_text += f" [Closure: {closure_summary}]"

        history = IncidentHistory(
            incident_id=incident.id,
            change_type=HistoryChangeType.STATUS_CHANGE.value,
            from_status=old_status,
            to_status=target_status,
            user_id=acting_user_id,
            notes=summary_text.strip() or f"Status transitioned from '{old_status}' to '{target_status}'",
            history_metadata={
                "containment_summary": containment_summary,
                "resolution_summary": resolution_summary,
                "closure_summary": closure_summary,
            },
            created_at=now,
        )
        db.add(history)
        db.flush()

        return incident

    def escalate_severity(
        self,
        db: Session,
        incident_id: uuid.UUID,
        new_severity: str,
        reason: str,
        allow_downgrade: bool = False,
        acting_user_id: Optional[uuid.UUID] = None,
    ) -> Incident:
        """Change incident severity with strict validation and audit tracking."""
        incident = self.get_incident_or_404(db, incident_id, eager_load=False, for_update=True)
        old_severity = incident.severity
        sev_norm = new_severity.lower()

        validate_severity_change(
            current_severity=old_severity,
            new_severity=sev_norm,
            allow_downgrade=allow_downgrade,
            reason=reason,
        )

        now = utcnow()
        incident.severity = sev_norm
        incident.updated_at = now

        history = IncidentHistory(
            incident_id=incident.id,
            change_type=HistoryChangeType.SEVERITY_CHANGE.value,
            from_severity=old_severity,
            to_severity=sev_norm,
            user_id=acting_user_id,
            notes=reason.strip(),
            created_at=now,
        )
        db.add(history)
        db.flush()

        return incident

    def assign_incident(
        self,
        db: Session,
        incident_id: uuid.UUID,
        assigned_to_id: Optional[uuid.UUID],
        notes: Optional[str] = None,
        acting_user_id: Optional[uuid.UUID] = None,
    ) -> Incident:
        """Assign or reassign an incident to an analyst."""
        incident = self.get_incident_or_404(db, incident_id)
        old_assigned = incident.assigned_to_id

        if assigned_to_id is not None:
            user = db.get(AppUser, assigned_to_id)
            if user is None:
                raise UserNotFoundError(f"Analyst user '{assigned_to_id}' not found.")
            assignee_name = user.username
        else:
            assignee_name = "Unassigned"

        now = utcnow()
        incident.assigned_to_id = assigned_to_id
        incident.updated_at = now

        history = IncidentHistory(
            incident_id=incident.id,
            change_type=HistoryChangeType.ASSIGNMENT.value,
            user_id=acting_user_id,
            notes=notes or f"Assigned to {assignee_name}",
            history_metadata={
                "previous_assigned_to": str(old_assigned) if old_assigned else None,
                "new_assigned_to": str(assigned_to_id) if assigned_to_id else None,
            },
            created_at=now,
        )
        db.add(history)
        db.flush()

        return incident

    def add_note(
        self,
        db: Session,
        incident_id: uuid.UUID,
        notes: str,
        acting_user_id: Optional[uuid.UUID] = None,
    ) -> IncidentHistory:
        """Add an analyst investigation note to the incident history."""
        incident = self.get_incident_or_404(db, incident_id)
        if not notes or not notes.strip():
            raise ValueError("Investigation notes cannot be empty.")

        now = utcnow()
        history = IncidentHistory(
            incident_id=incident.id,
            change_type=HistoryChangeType.NOTE_ADDED.value,
            user_id=acting_user_id,
            notes=notes.strip(),
            created_at=now,
        )
        db.add(history)
        incident.updated_at = now
        db.flush()

        return history

    def get_history(
        self,
        db: Session,
        incident_id: uuid.UUID,
    ) -> list[IncidentHistory]:
        """Fetch all chronological change and note entries for an incident."""
        self.get_incident_or_404(db, incident_id)
        stmt = (
            select(IncidentHistory)
            .options(joinedload(IncidentHistory.user))
            .where(IncidentHistory.incident_id == incident_id)
            .order_by(IncidentHistory.created_at.desc(), IncidentHistory.id.desc())
        )
        return list(db.execute(stmt).scalars().all())

    def get_evidence(
        self,
        db: Session,
        incident_id: uuid.UUID,
        evidence_type: Optional[str] = None,
    ) -> list[IncidentEvidence]:
        """Fetch all evidence items associated with an incident."""
        self.get_incident_or_404(db, incident_id)
        stmt = (
            select(IncidentEvidence)
            .where(IncidentEvidence.incident_id == incident_id)
            .order_by(IncidentEvidence.created_at.asc(), IncidentEvidence.id.asc())
        )
        if evidence_type is not None:
            stmt = stmt.where(IncidentEvidence.evidence_type == evidence_type.lower())
        return list(db.execute(stmt).scalars().all())

    def get_events(
        self,
        db: Session,
        incident_id: uuid.UUID,
    ) -> list[IncidentEvent]:
        """Fetch all linked forensic events for an incident."""
        self.get_incident_or_404(db, incident_id)
        stmt = (
            select(IncidentEvent)
            .options(joinedload(IncidentEvent.event))
            .where(IncidentEvent.incident_id == incident_id)
            .order_by(IncidentEvent.association_timestamp.asc(), IncidentEvent.id.asc())
        )
        return list(db.execute(stmt).scalars().all())
