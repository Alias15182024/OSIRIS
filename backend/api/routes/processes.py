"""Process route handlers for OSIRIS Phase 1.5 Backend API."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.api.deps import get_current_user, get_db
from backend.api.schemas.processes import (
    PaginatedProcessResponse,
    ProcessQueryParams,
    ProcessResponse,
)
from backend.db.models.app_user import AppUser
from backend.db.models.process import Process

router = APIRouter()


@router.get("", response_model=PaginatedProcessResponse)
def list_processes(
    params: ProcessQueryParams = Depends(),
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
) -> PaginatedProcessResponse:
    """List observed historical processes with filtering and pagination.

    Supported query parameters:
    - host_id: UUID of monitored host
    - pid: Source-level Linux process ID (subject to kernel reuse)
    - is_active: True for currently running processes (ended_at is NULL),
                 False for terminated processes (ended_at is set)
    - limit: Page size (default 50, minimum 1)
    - offset: Page offset (default 0, minimum 0)
    """
    conditions = []
    if params.host_id is not None:
        conditions.append(Process.host_id == params.host_id)
    if params.pid is not None:
        conditions.append(Process.pid == params.pid)
    if params.is_active is True:
        conditions.append(Process.ended_at.is_(None))
    elif params.is_active is False:
        conditions.append(Process.ended_at.is_not(None))

    # 1. Total count query over filtered records
    count_stmt = select(func.count(Process.id))
    if conditions:
        count_stmt = count_stmt.where(*conditions)
    total = db.scalar(count_stmt) or 0

    # 2. Paged items query with deterministic ordering
    stmt = select(Process)
    if conditions:
        stmt = stmt.where(*conditions)
    stmt = (
        stmt.order_by(Process.started_at.asc(), Process.id.asc())
        .offset(params.offset)
        .limit(params.limit)
    )

    orm_processes = db.execute(stmt).scalars().all()
    items = [ProcessResponse.model_validate(p) for p in orm_processes]

    return PaginatedProcessResponse(
        total=total,
        items=items,
        limit=params.limit,
        offset=params.offset,
    )


@router.get("/{process_id}", response_model=ProcessResponse)
def get_process(
    process_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
) -> ProcessResponse:
    """Retrieve a single observed process record by its OSIRIS UUID primary key.

    Note: The process_id path parameter is the internal OSIRIS UUID identity,
    NOT the ephemeral Linux PID.
    """
    process = db.get(Process, process_id)
    if process is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Process not found",
        )
    return ProcessResponse.model_validate(process)
