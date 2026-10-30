"""Snapshot route handlers for OSIRIS Phase 2 Milestone 2.1 Backend API."""

from __future__ import annotations

import uuid
from datetime import timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.api.deps import get_current_user, get_db
from backend.api.schemas.snapshots import (
    PaginatedSnapshotResponse,
    SnapshotQueryParams,
    SnapshotResponse,
)
from backend.db.models.app_user import AppUser
from backend.db.models.snapshot import Snapshot

router = APIRouter()


@router.get("", response_model=PaginatedSnapshotResponse)
def list_snapshots(
    params: SnapshotQueryParams = Depends(),
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
) -> PaginatedSnapshotResponse:
    """List point-in-time system-state snapshots with filtering and pagination.

    Supported query parameters:
    - host_id: UUID of monitored host
    - snapshot_type: Snapshot type identifier (e.g. 'system_state')
    - start_time: Earliest snapshot timestamp (inclusive)
    - end_time: Latest snapshot timestamp (inclusive)
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

    conditions = []
    if params.host_id is not None:
        conditions.append(Snapshot.host_id == params.host_id)
    if params.snapshot_type is not None:
        conditions.append(Snapshot.snapshot_type == params.snapshot_type)
    if start_time is not None:
        conditions.append(Snapshot.timestamp >= start_time)
    if end_time is not None:
        conditions.append(Snapshot.timestamp <= end_time)

    # 1. Total count query over filtered records
    count_stmt = select(func.count(Snapshot.id))
    if conditions:
        count_stmt = count_stmt.where(*conditions)
    total = db.scalar(count_stmt) or 0

    # 2. Paged items query with deterministic ordering: newest snapshots first,
    # with a stable secondary ordering by id descending.
    stmt = select(Snapshot)
    if conditions:
        stmt = stmt.where(*conditions)
    stmt = (
        stmt.order_by(Snapshot.timestamp.desc(), Snapshot.id.desc())
        .offset(params.offset)
        .limit(params.limit)
    )

    orm_snapshots = db.execute(stmt).scalars().all()
    items = [SnapshotResponse.model_validate(s) for s in orm_snapshots]

    return PaginatedSnapshotResponse(
        total=total,
        items=items,
        limit=params.limit,
        offset=params.offset,
    )


@router.get("/{snapshot_id}", response_model=SnapshotResponse)
def get_snapshot(
    snapshot_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
) -> SnapshotResponse:
    """Retrieve a single point-in-time system-state snapshot by UUID."""
    snapshot = db.get(Snapshot, snapshot_id)
    if snapshot is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Snapshot not found",
        )
    return SnapshotResponse.model_validate(snapshot)
