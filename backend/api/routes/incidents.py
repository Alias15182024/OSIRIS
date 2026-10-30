"""Incident route handlers for OSIRIS (Phase 2 Milestone 2.6)."""

from __future__ import annotations

import logging
from typing import Any, Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from backend.api.deps import get_current_user, get_db, require_roles
from backend.api.schemas.incident import (
    IncidentAssignRequest,
    IncidentCreateRequest,
    IncidentDetailResponse,
    IncidentEventCreateRequest,
    IncidentEventResponse,
    IncidentEvidenceCreateRequest,
    IncidentEvidenceResponse,
    IncidentHistoryResponse,
    IncidentNoteRequest,
    IncidentQueryParams,
    IncidentResponse,
    IncidentSeverityUpdateRequest,
    IncidentStatusUpdateRequest,
    IncidentUpdateRequest,
    PaginatedIncidentResponse,
)
from backend.db.models.app_user import AppUser
from backend.db.models.detection import Detection
from backend.db.models.event import Event
from backend.db.models.file import File
from backend.db.models.fim_deviation import FimDeviation
from backend.db.models.process import Process
from backend.db.models.snapshot import Snapshot
from backend.db.models.user_session import UserSession
from backend.services.detection.service import _ensure_utc
from backend.services.incidents.evidence_manager import EvidenceManager
from backend.services.incidents.models import (
    EvidenceDuplicateError,
    EvidenceNotFoundError,
    EvidenceType,
    HostMismatchError,
    IncidentError,
    IncidentNotFoundError,
    InvalidSeverityError,
    InvalidTransitionError,
    SeverityDowngradeError,
    UserNotFoundError,
)
from backend.services.incidents.report import ReportGenerator
from backend.services.incidents.service import IncidentService

logger = logging.getLogger("osiris.api.routes.incidents")

router = APIRouter()
_incident_service = IncidentService()
_evidence_manager = EvidenceManager()
_report_generator = ReportGenerator()


@router.get("", response_model=PaginatedIncidentResponse)
def list_incidents(
    params: IncidentQueryParams = Depends(),
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
) -> PaginatedIncidentResponse:
    """List security incidents with structured filtering and pagination."""
    if params.start_time and params.end_time:
        st = _ensure_utc(params.start_time)
        et = _ensure_utc(params.end_time)
        if st is not None and et is not None and st > et:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="start_time must be less than or equal to end_time",
            )

    items, total = _incident_service.list_incidents(
        db=db,
        host_id=params.host_id,
        severity=params.severity,
        status=params.status,
        category=params.category,
        assigned_to_id=params.assigned_to_id,
        start_time=params.start_time,
        end_time=params.end_time,
        limit=params.limit,
        offset=params.offset,
    )

    return PaginatedIncidentResponse(
        items=[IncidentResponse.from_orm_model(inc) for inc in items],
        total=total,
        limit=params.limit,
        offset=params.offset,
    )


@router.post("", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
def create_incident(
    payload: IncidentCreateRequest,
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(require_roles("admin", "analyst")),
) -> IncidentResponse:
    """Create a new incident manually (analyst or admin required)."""
    try:
        incident = _incident_service.create_incident(
            db=db,
            title=payload.title,
            description=payload.description,
            severity=payload.severity,
            category=payload.category,
            host_id=payload.host_id,
            assigned_to_id=payload.assigned_to_id,
            created_by_id=current_user.id,
            first_observed_at=payload.first_observed_at,
            last_observed_at=payload.last_observed_at,
        )
        db.commit()
    except (InvalidSeverityError, HostMismatchError, UserNotFoundError) as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        db.rollback()
        logger.exception("Failed to create incident")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create incident",
        )

    # Re-fetch with relationships
    return IncidentResponse.from_orm_model(_incident_service.get_incident(db, incident.id))


@router.get("/{incident_id}", response_model=IncidentDetailResponse)
def get_incident(
    incident_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
) -> IncidentDetailResponse:
    """Retrieve full details of an incident including counts."""
    inc = _incident_service.get_incident(db, incident_id)
    if inc is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found.",
        )
    return IncidentDetailResponse.from_orm_model(inc)


@router.patch("/{incident_id}", response_model=IncidentResponse)
def update_incident(
    incident_id: uuid.UUID,
    payload: IncidentUpdateRequest,
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(require_roles("admin", "analyst")),
) -> IncidentResponse:
    """Update incident metadata or analyst assignment."""
    try:
        inc = _incident_service.update_incident(
            db=db,
            incident_id=incident_id,
            title=payload.title,
            description=payload.description,
            category=payload.category,
            assigned_to_id=payload.assigned_to_id,
            acting_user_id=current_user.id,
        )
        db.commit()
    except IncidentNotFoundError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except (UserNotFoundError, ValueError) as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    return IncidentResponse.from_orm_model(_incident_service.get_incident(db, inc.id))


@router.post("/{incident_id}/status", response_model=IncidentResponse)
def transition_status(
    incident_id: uuid.UUID,
    payload: IncidentStatusUpdateRequest,
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(require_roles("admin", "analyst")),
) -> IncidentResponse:
    """Transition incident lifecycle state."""
    try:
        inc = _incident_service.transition_status(
            db=db,
            incident_id=incident_id,
            new_status=payload.status,
            notes=payload.notes,
            containment_summary=payload.containment_summary,
            resolution_summary=payload.resolution_summary,
            closure_summary=payload.closure_summary,
            acting_user_id=current_user.id,
        )
        db.commit()
    except IncidentNotFoundError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except InvalidTransitionError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    return IncidentResponse.from_orm_model(_incident_service.get_incident(db, inc.id))


@router.post("/{incident_id}/severity", response_model=IncidentResponse)
def escalate_severity(
    incident_id: uuid.UUID,
    payload: IncidentSeverityUpdateRequest,
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(require_roles("admin", "analyst")),
) -> IncidentResponse:
    """Escalate or update incident severity."""
    try:
        inc = _incident_service.escalate_severity(
            db=db,
            incident_id=incident_id,
            new_severity=payload.severity,
            reason=payload.reason,
            allow_downgrade=payload.allow_downgrade,
            acting_user_id=current_user.id,
        )
        db.commit()
    except IncidentNotFoundError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except (InvalidSeverityError, SeverityDowngradeError) as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    return IncidentResponse.from_orm_model(_incident_service.get_incident(db, inc.id))


@router.post("/{incident_id}/assign", response_model=IncidentResponse)
def assign_incident(
    incident_id: uuid.UUID,
    payload: IncidentAssignRequest,
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(require_roles("admin", "analyst")),
) -> IncidentResponse:
    """Assign incident to an analyst."""
    try:
        inc = _incident_service.assign_incident(
            db=db,
            incident_id=incident_id,
            assigned_to_id=payload.assigned_to_id,
            notes=payload.notes,
            acting_user_id=current_user.id,
        )
        db.commit()
    except IncidentNotFoundError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except UserNotFoundError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    return IncidentResponse.from_orm_model(_incident_service.get_incident(db, inc.id))


@router.post("/{incident_id}/notes", response_model=IncidentHistoryResponse)
def add_note(
    incident_id: uuid.UUID,
    payload: IncidentNoteRequest,
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(require_roles("admin", "analyst")),
) -> IncidentHistoryResponse:
    """Add an analyst investigation note to the incident."""
    try:
        history = _incident_service.add_note(
            db=db,
            incident_id=incident_id,
            notes=payload.notes,
            acting_user_id=current_user.id,
        )
        db.commit()
    except IncidentNotFoundError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    return IncidentHistoryResponse.from_orm_model(history)


@router.get("/{incident_id}/history", response_model=list[IncidentHistoryResponse])
def get_incident_history(
    incident_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
) -> list[IncidentHistoryResponse]:
    """Retrieve complete audit history and investigation notes for an incident."""
    try:
        histories = _incident_service.get_history(db, incident_id)
    except IncidentNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))

    return [IncidentHistoryResponse.from_orm_model(h) for h in histories]


@router.get("/{incident_id}/evidence", response_model=list[IncidentEvidenceResponse])
def list_incident_evidence(
    incident_id: uuid.UUID,
    evidence_type: Optional[str] = Query(None, description="Filter by evidence type"),
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
) -> list[IncidentEvidenceResponse]:
    """List all evidence associated with an incident."""
    try:
        evs = _incident_service.get_evidence(db, incident_id, evidence_type=evidence_type)
    except IncidentNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))

    return [IncidentEvidenceResponse.model_validate(e) for e in evs]


@router.post(
    "/{incident_id}/evidence",
    response_model=IncidentEvidenceResponse,
    status_code=status.HTTP_201_CREATED,
)
def add_evidence(
    incident_id: uuid.UUID,
    payload: IncidentEvidenceCreateRequest,
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(require_roles("admin", "analyst")),
) -> IncidentEvidenceResponse:
    """Manually link forensic evidence to an incident."""
    try:
        incident = _incident_service.get_incident_or_404(db, incident_id)
        ev_type = payload.evidence_type.lower()

        if ev_type == EvidenceType.DETECTION.value:
            det_uuid = payload.detection_id or uuid.UUID(payload.source_id)
            det = db.get(Detection, det_uuid)
            if not det:
                raise EvidenceNotFoundError(f"Detection '{det_uuid}' not found.")
            ev = _evidence_manager.link_detection(
                db=db, incident=incident, detection=det, reason=payload.description, acting_user_id=current_user.id
            )
        elif ev_type == EvidenceType.FIM_DEVIATION.value:
            dev_uuid = payload.fim_deviation_id or uuid.UUID(payload.source_id)
            dev = db.get(FimDeviation, dev_uuid)
            if not dev:
                raise EvidenceNotFoundError(f"FIM deviation '{dev_uuid}' not found.")
            ev = _evidence_manager.link_fim_deviation(
                db=db, incident=incident, deviation=dev, reason=payload.description, acting_user_id=current_user.id
            )
        elif ev_type == EvidenceType.EVENT.value:
            evt_uuid = payload.event_id or uuid.UUID(payload.source_id)
            evt = db.get(Event, evt_uuid)
            if not evt:
                raise EvidenceNotFoundError(f"Event '{evt_uuid}' not found.")
            _, ev = _evidence_manager.link_event(
                db=db, incident=incident, event=evt, notes=payload.description, acting_user_id=current_user.id
            )
        elif ev_type == EvidenceType.SESSION.value:
            sess_uuid = payload.session_id or uuid.UUID(payload.source_id)
            sess = db.get(UserSession, sess_uuid)
            if not sess:
                raise EvidenceNotFoundError(f"Session '{sess_uuid}' not found.")
            ev = _evidence_manager.link_session(
                db=db, incident=incident, session=sess, reason=payload.description, acting_user_id=current_user.id
            )
        elif ev_type == EvidenceType.SNAPSHOT.value:
            snap_uuid = payload.snapshot_id or uuid.UUID(payload.source_id)
            snap = db.get(Snapshot, snap_uuid)
            if not snap:
                raise EvidenceNotFoundError(f"Snapshot '{snap_uuid}' not found.")
            ev = _evidence_manager.link_snapshot(
                db=db, incident=incident, snapshot=snap, reason=payload.description, acting_user_id=current_user.id
            )
        elif ev_type == EvidenceType.PROCESS.value:
            proc_uuid = payload.process_id or uuid.UUID(payload.source_id)
            proc = db.get(Process, proc_uuid)
            if not proc:
                raise EvidenceNotFoundError(f"Process '{proc_uuid}' not found.")
            ev = _evidence_manager.link_process(
                db=db, incident=incident, process=proc, reason=payload.description, acting_user_id=current_user.id
            )
        elif ev_type == EvidenceType.FILE.value:
            file_uuid = payload.file_id or uuid.UUID(payload.source_id)
            f_rec = db.get(File, file_uuid)
            if not f_rec:
                raise EvidenceNotFoundError(f"File record '{file_uuid}' not found.")
            ev = _evidence_manager.link_file(
                db=db, incident=incident, file_record=f_rec, reason=payload.description, acting_user_id=current_user.id
            )
        else:
            ev = _evidence_manager.link_custom_evidence(
                db=db,
                incident=incident,
                source_id=payload.source_id,
                title=payload.title,
                description=payload.description,
                provenance=payload.provenance or {},
                acting_user_id=current_user.id,
            )

        db.commit()
    except IncidentNotFoundError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except EvidenceNotFoundError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except (ValueError, HostMismatchError) as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except EvidenceDuplicateError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))

    return IncidentEvidenceResponse.model_validate(ev)


@router.get("/{incident_id}/events", response_model=list[IncidentEventResponse])
def list_incident_events(
    incident_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
) -> list[IncidentEventResponse]:
    """List forensic events associated with an incident."""
    try:
        events = _incident_service.get_events(db, incident_id)
    except IncidentNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))

    return [IncidentEventResponse.from_orm_model(e) for e in events]


@router.post(
    "/{incident_id}/events",
    response_model=IncidentEventResponse,
    status_code=status.HTTP_201_CREATED,
)
def link_event(
    incident_id: uuid.UUID,
    payload: IncidentEventCreateRequest,
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(require_roles("admin", "analyst")),
) -> IncidentEventResponse:
    """Link a forensic event to an incident."""
    try:
        incident = _incident_service.get_incident_or_404(db, incident_id)
        event = db.get(Event, payload.event_id)
        if event is None:
            raise EvidenceNotFoundError(f"Event '{payload.event_id}' not found.")

        inc_evt, _ = _evidence_manager.link_event(
            db=db,
            incident=incident,
            event=event,
            relationship=payload.relationship,
            notes=payload.investigation_notes,
            acting_user_id=current_user.id,
        )
        db.commit()
    except IncidentNotFoundError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except EvidenceNotFoundError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except HostMismatchError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except EvidenceDuplicateError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))

    return IncidentEventResponse.from_orm_model(inc_evt)


@router.get("/{incident_id}/report")
def export_incident_report(
    incident_id: uuid.UUID,
    format: str = Query("json", description="Export format: 'json' or 'markdown'"),
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
) -> Any:
    """Export forensic investigation report in JSON or Markdown."""
    try:
        report_data = _report_generator.generate_report(db, incident_id)
    except IncidentNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))

    if format.lower() == "markdown":
        md_text = _report_generator.export_markdown(report_data)
        return Response(
            content=md_text,
            media_type="text/markdown",
            headers={
                "Content-Disposition": f'attachment; filename="incident-{incident_id}-report.md"'
            },
        )

    return report_data
