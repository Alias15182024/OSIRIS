"""File monitoring route handlers for OSIRIS Phase 1.5 Backend API."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from backend.api.deps import get_current_user, get_db
from backend.api.schemas.files import (
    FileQueryParams,
    FileResponse,
    PaginatedFileResponse,
)
from backend.db.models.app_user import AppUser
from backend.db.models.file import File

router = APIRouter()


@router.get("", response_model=PaginatedFileResponse)
def list_files(
    params: FileQueryParams = Depends(),
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
) -> PaginatedFileResponse:
    """List observed filesystem entries with filtering and pagination.

    Supported query parameters:
    - host_id: UUID of monitored host
    - path: Path prefix filter (matches exact path or entries within that directory tree;
            escapes SQL wildcards like '%' and '_')
    - file_type: Exact file type (e.g. 'file', 'directory')
    - limit: Page size (default 50, minimum 1)
    - offset: Page offset (default 0, minimum 0)
    """
    conditions = []
    if params.host_id is not None:
        conditions.append(File.host_id == params.host_id)
    if params.file_type is not None:
        conditions.append(File.file_type == params.file_type)
    if params.path is not None:
        if params.path.endswith("/"):
            conditions.append(File.path.startswith(params.path, autoescape=True))
        else:
            conditions.append(
                or_(
                    File.path == params.path,
                    File.path.startswith(params.path + "/", autoescape=True),
                )
            )

    # 1. Total count query over filtered records
    count_stmt = select(func.count(File.id))
    if conditions:
        count_stmt = count_stmt.where(*conditions)
    total = db.scalar(count_stmt) or 0

    # 2. Paged items query with deterministic ordering
    stmt = select(File)
    if conditions:
        stmt = stmt.where(*conditions)
    stmt = (
        stmt.order_by(File.first_seen_at.asc(), File.id.asc())
        .offset(params.offset)
        .limit(params.limit)
    )

    orm_files = db.execute(stmt).scalars().all()
    items = [FileResponse.model_validate(f) for f in orm_files]

    return PaginatedFileResponse(
        total=total,
        items=items,
        limit=params.limit,
        offset=params.offset,
    )
