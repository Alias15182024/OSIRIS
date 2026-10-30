"""User session route handlers for OSIRIS (Phase 2 Milestone 2.3)."""

from __future__ import annotations

import uuid
from datetime import timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.api.deps import get_current_user, get_db
from backend.api.schemas.session import (
    PaginatedSessionResponse,
    ProcessSummary,
    SessionDetailResponse,
    SessionQueryParams,
    SessionResponse,
)
from backend.db.models.app_user import AppUser
from backend.services.sessions.service import SessionReconstructionService

router = APIRouter()
_session_service = SessionReconstructionService()


@router.get("", response_model=PaginatedSessionResponse)
def list_sessions(
    params: SessionQueryParams = Depends(),
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
) -> PaginatedSessionResponse:
    """List reconstructed user sessions with filtering and pagination.

    Supported query parameters:
    - host_id: UUID of monitored host
    - linux_user_id: UUID of Linux user account
    - username: Linux username
    - session_type: Session type (e.g. 'ssh', 'tty', 'pts', 'local')
    - terminal: Terminal identifier (e.g. 'pts/0', 'tty1')
    - remote_host: Remote connection IP or hostname
    - start_time: Earliest session start timestamp (inclusive)
    - end_time: Latest session start timestamp (inclusive)
    - is_active: Filter by active (True) vs ended/completed (False) sessions
    - limit: Page size (default 50, minimum 1, maximum 100)
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

    start_time = params.start_time
    if start_time is not None and start_time.tzinfo is not None:
        start_time = start_time.astimezone(timezone.utc)

    end_time = params.end_time
    if end_time is not None and end_time.tzinfo is not None:
        end_time = end_time.astimezone(timezone.utc)

    total, items = _session_service.list_sessions(
        db=db,
        host_id=params.host_id,
        linux_user_id=params.linux_user_id,
        username=params.username,
        session_type=params.session_type,
        terminal=params.terminal,
        remote_host=params.remote_host,
        start_time=start_time,
        end_time=end_time,
        is_active=params.is_active,
        limit=params.limit,
        offset=params.offset,
    )

    serialized_items = [SessionResponse.model_validate(item) for item in items]

    return PaginatedSessionResponse(
        total=total,
        items=serialized_items,
        limit=params.limit,
        offset=params.offset,
    )


@router.get("/{session_id}", response_model=SessionDetailResponse)
def get_session(
    session_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
) -> SessionDetailResponse:
    """Retrieve details of a single user session including associated process execution."""
    session_obj = _session_service.get_session_by_id(db, session_id)
    if session_obj is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found",
        )

    # Correlate processes executed during this session
    processes = _session_service.get_session_processes(db, session_id)
    proc_summaries = [ProcessSummary.model_validate(p) for p in processes]

    # Convert session_obj to SessionResponse base dict
    base_response = SessionResponse.model_validate(session_obj)

    return SessionDetailResponse(
        id=base_response.id,
        host_id=base_response.host_id,
        linux_user_id=base_response.linux_user_id,
        username=base_response.username,
        uid=base_response.uid,
        session_type=base_response.session_type,
        terminal=base_response.terminal,
        remote_host=base_response.remote_host,
        started_at=base_response.started_at,
        ended_at=base_response.ended_at,
        is_active=base_response.is_active,
        duration_seconds=base_response.duration_seconds,
        created_at=base_response.created_at,
        process_count=len(proc_summaries),
        processes=proc_summaries,
    )
