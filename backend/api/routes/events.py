"""Event route handlers for OSIRIS Phase 1.5 Backend API."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.api.deps import get_current_user, get_db
from backend.api.schemas.events import (
    EventQueryParams,
    EventResponse,
    PaginatedEventResponse,
)
from backend.db.models.app_user import AppUser
from backend.db.models.event import Event

router = APIRouter()


@router.get("", response_model=PaginatedEventResponse)
def list_events(
    params: EventQueryParams = Depends(),
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
) -> PaginatedEventResponse:
    """List and filter historical events with pagination.

    Supported query parameters:
    - host_id: UUID of monitored host
    - start_time: Earliest event timestamp (inclusive)
    - end_time: Latest event timestamp (inclusive)
    - source: Collector source identifier (e.g. 'proc', 'resource', 'fs')
    - event_type: Event type identifier (e.g. 'process.start')
    - severity: Canonical severity level (info, low, medium, high, critical)
    - process_id: Internal OSIRIS process UUID
    - pid: Source-level Linux process ID
    - limit: Page size (default 50, minimum 1)
    - offset: Page offset (default 0, minimum 0)
    """
    if params.start_time and params.end_time:
        try:
            if params.start_time > params.end_time:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="start_time must be less than or equal to end_time",
                )
        except TypeError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot compare timezone-aware and naive datetimes",
            )

    conditions = []
    if params.host_id is not None:
        conditions.append(Event.host_id == params.host_id)
    if params.start_time is not None:
        conditions.append(Event.timestamp >= params.start_time)
    if params.end_time is not None:
        conditions.append(Event.timestamp <= params.end_time)
    if params.source is not None:
        conditions.append(Event.source == params.source)
    if params.event_type is not None:
        conditions.append(Event.event_type == params.event_type)
    if params.severity is not None:
        conditions.append(Event.severity == params.severity)
    if params.process_id is not None:
        conditions.append(Event.process_id == params.process_id)
    if params.pid is not None:
        conditions.append(Event.pid == params.pid)

    # 1. Total count query over filtered records
    count_stmt = select(func.count(Event.id))
    if conditions:
        count_stmt = count_stmt.where(*conditions)
    total = db.scalar(count_stmt) or 0

    # 2. Paged items query with deterministic ordering
    stmt = select(Event)
    if conditions:
        stmt = stmt.where(*conditions)
    stmt = (
        stmt.order_by(Event.timestamp.asc(), Event.id.asc())
        .offset(params.offset)
        .limit(params.limit)
    )

    orm_events = db.execute(stmt).scalars().all()
    items = [EventResponse.model_validate(e) for e in orm_events]

    return PaginatedEventResponse(
        total=total,
        items=items,
        limit=params.limit,
        offset=params.offset,
    )


@router.get("/{event_id}", response_model=EventResponse)
def get_event(
    event_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
) -> EventResponse:
    """Retrieve a single normalized event by UUID."""
    event = db.get(Event, event_id)
    if event is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Event not found",
        )
    return EventResponse.model_validate(event)
