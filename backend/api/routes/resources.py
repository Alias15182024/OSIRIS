"""Resource snapshot route handlers for OSIRIS Phase 1.5 Backend API."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.api.deps import get_current_user, get_db
from backend.api.schemas.resources import (
    PaginatedResourceSnapshotResponse,
    ResourceSnapshotQueryParams,
    ResourceSnapshotResponse,
)
from backend.db.models.app_user import AppUser
from backend.db.models.resource_snapshot import ResourceSnapshot

router = APIRouter()


@router.get("", response_model=PaginatedResourceSnapshotResponse)
def list_resource_snapshots(
    params: ResourceSnapshotQueryParams = Depends(),
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
) -> PaginatedResourceSnapshotResponse:
    """List point-in-time system resource snapshots with filtering and pagination.

    Supported query parameters:
    - host_id: UUID of monitored host
    - start_time: Earliest snapshot timestamp (inclusive)
    - end_time: Latest snapshot timestamp (inclusive)
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
        conditions.append(ResourceSnapshot.host_id == params.host_id)
    if params.start_time is not None:
        conditions.append(ResourceSnapshot.timestamp >= params.start_time)
    if params.end_time is not None:
        conditions.append(ResourceSnapshot.timestamp <= params.end_time)

    # 1. Total count query over filtered records
    count_stmt = select(func.count(ResourceSnapshot.id))
    if conditions:
        count_stmt = count_stmt.where(*conditions)
    total = db.scalar(count_stmt) or 0

    # 2. Paged items query with deterministic ordering
    stmt = select(ResourceSnapshot)
    if conditions:
        stmt = stmt.where(*conditions)
    stmt = (
        stmt.order_by(ResourceSnapshot.timestamp.asc(), ResourceSnapshot.id.asc())
        .offset(params.offset)
        .limit(params.limit)
    )

    orm_snapshots = db.execute(stmt).scalars().all()
    items = [ResourceSnapshotResponse.model_validate(s) for s in orm_snapshots]

    return PaginatedResourceSnapshotResponse(
        total=total,
        items=items,
        limit=params.limit,
        offset=params.offset,
    )
