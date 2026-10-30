"""Pydantic schemas for Incident Management API (Phase 2 Milestone 2.6)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class IncidentQueryParams(BaseModel):
    """Query parameters for listing and filtering incidents."""

    host_id: Optional[UUID] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    category: Optional[str] = None
    assigned_to_id: Optional[UUID] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0)


class IncidentCreateRequest(BaseModel):
    """Payload to create a new incident manually."""

    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    severity: str = Field(default="medium")
    category: str = Field(default="general", max_length=100)
    host_id: Optional[UUID] = None
    assigned_to_id: Optional[UUID] = None
    first_observed_at: Optional[datetime] = None
    last_observed_at: Optional[datetime] = None


class IncidentUpdateRequest(BaseModel):
    """Payload to update incident metadata or assignee."""

    title: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    category: Optional[str] = Field(None, min_length=1, max_length=100)
    assigned_to_id: Optional[UUID] = None


class IncidentStatusUpdateRequest(BaseModel):
    """Payload to transition incident lifecycle status."""

    status: str = Field(..., description="Target status ('open', 'investigating', 'contained', 'resolved', 'closed')")
    notes: Optional[str] = Field(None, description="Reason or justification for the status transition")
    containment_summary: Optional[str] = None
    resolution_summary: Optional[str] = None
    closure_summary: Optional[str] = None


class IncidentSeverityUpdateRequest(BaseModel):
    """Payload to update incident severity."""

    severity: str = Field(..., description="Target severity ('info', 'low', 'medium', 'high', 'critical')")
    reason: str = Field(..., min_length=1, description="Justification for severity change")
    allow_downgrade: bool = Field(default=False, description="Explicit approval flag required for downgrades")


class IncidentAssignRequest(BaseModel):
    """Payload to assign an incident to an analyst."""

    assigned_to_id: Optional[UUID] = Field(None, description="User ID of the assigned analyst (null to unassign)")
    notes: Optional[str] = None


class IncidentNoteRequest(BaseModel):
    """Payload to append an investigation note."""

    notes: str = Field(..., min_length=1, description="Analyst investigation commentary")


class IncidentEvidenceCreateRequest(BaseModel):
    """Payload to manually associate evidence with an incident."""

    evidence_type: str = Field(..., description="Type of evidence ('detection', 'event', 'fim_deviation', etc.)")
    source_id: str = Field(..., min_length=1, description="Identifier of the source forensic entity")
    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    provenance: Optional[dict[str, Any]] = None
    detection_id: Optional[UUID] = None
    event_id: Optional[UUID] = None
    fim_deviation_id: Optional[UUID] = None
    session_id: Optional[UUID] = None
    snapshot_id: Optional[UUID] = None
    process_id: Optional[UUID] = None
    file_id: Optional[UUID] = None


class IncidentEventCreateRequest(BaseModel):
    """Payload to link a forensic event to an incident."""

    event_id: UUID = Field(..., description="UUID of the forensic event")
    relationship: str = Field(default="related", max_length=100)
    investigation_notes: Optional[str] = None


class IncidentResponse(BaseModel):
    """Representation of an incident."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    title: str
    description: Optional[str] = None
    severity: str
    status: str
    category: str
    host_id: Optional[UUID] = None
    hostname: Optional[str] = None
    created_by_id: Optional[UUID] = None
    created_by_username: Optional[str] = None
    assigned_to_id: Optional[UUID] = None
    assigned_to_username: Optional[str] = None
    first_observed_at: Optional[datetime] = None
    last_observed_at: Optional[datetime] = None
    contained_at: Optional[datetime] = None
    containment_summary: Optional[str] = None
    resolved_at: Optional[datetime] = None
    resolution_summary: Optional[str] = None
    closed_at: Optional[datetime] = None
    closure_summary: Optional[str] = None
    created_at: datetime
    updated_at: Optional[datetime] = None

    @classmethod
    def from_orm_model(cls, incident: Any) -> IncidentResponse:
        """Construct response with resolved host and user usernames."""
        hostname = getattr(incident.host, "hostname", None) if getattr(incident, "host", None) else None
        created_user = getattr(incident.created_by, "username", None) if getattr(incident, "created_by", None) else None
        assigned_user = getattr(incident.assigned_to, "username", None) if getattr(incident, "assigned_to", None) else None

        return cls(
            id=incident.id,
            title=incident.title,
            description=incident.description,
            severity=incident.severity,
            status=incident.status,
            category=incident.category,
            host_id=incident.host_id,
            hostname=hostname,
            created_by_id=incident.created_by_id,
            created_by_username=created_user,
            assigned_to_id=incident.assigned_to_id,
            assigned_to_username=assigned_user,
            first_observed_at=incident.first_observed_at,
            last_observed_at=incident.last_observed_at,
            contained_at=incident.contained_at,
            containment_summary=incident.containment_summary,
            resolved_at=incident.resolved_at,
            resolution_summary=incident.resolution_summary,
            closed_at=incident.closed_at,
            closure_summary=incident.closure_summary,
            created_at=incident.created_at,
            updated_at=incident.updated_at,
        )


class IncidentDetailResponse(IncidentResponse):
    """Detailed incident response including entity counts."""

    evidence_count: int = 0
    events_count: int = 0
    history_count: int = 0

    @classmethod
    def from_orm_model(cls, incident: Any) -> IncidentDetailResponse:
        base = IncidentResponse.from_orm_model(incident)
        ev_count = len(getattr(incident, "evidence", []))
        evt_count = len(getattr(incident, "events", []))
        hist_count = len(getattr(incident, "history", []))

        return cls(
            **base.model_dump(),
            evidence_count=ev_count,
            events_count=evt_count,
            history_count=hist_count,
        )


class IncidentEvidenceResponse(BaseModel):
    """Representation of an associated forensic evidence item."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    incident_id: UUID
    evidence_type: str
    source_id: str
    title: str
    description: Optional[str] = None
    provenance: dict[str, Any]
    detection_id: Optional[UUID] = None
    event_id: Optional[UUID] = None
    fim_deviation_id: Optional[UUID] = None
    session_id: Optional[UUID] = None
    snapshot_id: Optional[UUID] = None
    process_id: Optional[UUID] = None
    file_id: Optional[UUID] = None
    created_by_id: Optional[UUID] = None
    created_at: datetime


class IncidentEventResponse(BaseModel):
    """Representation of an associated forensic event."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    incident_id: UUID
    event_id: UUID
    relationship: str
    association_timestamp: datetime
    investigation_notes: Optional[str] = None
    event_type: Optional[str] = None
    action: Optional[str] = None
    source: Optional[str] = None
    severity: Optional[str] = None

    @classmethod
    def from_orm_model(cls, inc_event: Any) -> IncidentEventResponse:
        evt = getattr(inc_event, "event", None)
        return cls(
            id=inc_event.id,
            incident_id=inc_event.incident_id,
            event_id=inc_event.event_id,
            relationship=inc_event.relationship_role,
            association_timestamp=inc_event.association_timestamp,
            investigation_notes=inc_event.investigation_notes,
            event_type=getattr(evt, "event_type", None) if evt else None,
            action=getattr(evt, "action", None) if evt else None,
            source=getattr(evt, "source", None) if evt else None,
            severity=getattr(evt, "severity", None) if evt else None,
        )


class IncidentHistoryResponse(BaseModel):
    """Representation of an auditable history change entry."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    incident_id: UUID
    change_type: str
    from_status: Optional[str] = None
    to_status: Optional[str] = None
    from_severity: Optional[str] = None
    to_severity: Optional[str] = None
    user_id: Optional[UUID] = None
    username: Optional[str] = None
    notes: Optional[str] = None
    history_metadata: Optional[dict[str, Any]] = None
    created_at: datetime

    @classmethod
    def from_orm_model(cls, history: Any) -> IncidentHistoryResponse:
        username = getattr(history.user, "username", None) if getattr(history, "user", None) else None
        return cls(
            id=history.id,
            incident_id=history.incident_id,
            change_type=history.change_type,
            from_status=history.from_status,
            to_status=history.to_status,
            from_severity=history.from_severity,
            to_severity=history.to_severity,
            user_id=history.user_id,
            username=username,
            notes=history.notes,
            history_metadata=history.history_metadata,
            created_at=history.created_at,
        )


class PaginatedIncidentResponse(BaseModel):
    """Paginated list of incidents."""

    items: list[IncidentResponse]
    total: int
    limit: int
    offset: int
