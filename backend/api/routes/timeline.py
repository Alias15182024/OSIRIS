"""Timeline route handlers for OSIRIS Phase 2 Milestone 2.2 Backend API."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.api.deps import get_current_user, get_db
from backend.api.schemas.timeline import (
    PaginatedTimelineResponse,
    TimelineQueryParams,
)
from backend.db.models.app_user import AppUser
from backend.services.timeline.correlator import _ensure_utc
from backend.services.timeline.service import (
    HostNotFoundError,
    InvalidTimeRangeError,
    TimelineService,
)

router = APIRouter()


@router.get("", response_model=PaginatedTimelineResponse)
def get_timeline(
    params: TimelineQueryParams = Depends(),
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
) -> PaginatedTimelineResponse:
    """Reconstruct a unified chronological forensic timeline with filtering and pagination.

    Supported query parameters:
    - host_id: UUID of monitored host
    - start_time: Earliest timestamp (inclusive, UTC)
    - end_time: Latest timestamp (inclusive, UTC)
    - record_type: Filter by record type ('event', 'process', 'session', 'snapshot', 'resource', 'file')
    - event_type: Filter by event type identifier (e.g. 'process.start')
    - source: Filter by source identifier (e.g. 'proc', 'fs', 'resource')
    - process_id: Filter by internal OSIRIS process UUID
    - pid: Filter by Linux PID
    - user_id: Filter by LinuxUser UUID
    - uid: Filter by Linux UID
    - username: Filter by Linux username
    - order: 'asc' (chronological, oldest first) or 'desc' (newest first)
    - limit: Page size (default 50, minimum 1, maximum 100)
    - offset: Page offset (default 0, minimum 0)
    """
    start_utc = _ensure_utc(params.start_time)
    end_utc = _ensure_utc(params.end_time)
    if start_utc and end_utc:
        if start_utc > end_utc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="start_time must be less than or equal to end_time",
            )

    service = TimelineService(session=db)
    try:
        items, total = service.reconstruct_timeline(
            host_id=params.host_id,
            start_time=params.start_time,
            end_time=params.end_time,
            record_type=params.record_type,
            event_type=params.event_type,
            source=params.source,
            process_id=params.process_id,
            pid=params.pid,
            user_id=params.user_id,
            uid=params.uid,
            username=params.username,
            order=params.order,
            limit=params.limit,
            offset=params.offset,
        )
    except HostNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Host not found",
        )
    except InvalidTimeRangeError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    return PaginatedTimelineResponse(
        total=total,
        items=items,
        limit=params.limit,
        offset=params.offset,
    )
