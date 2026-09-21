"""File monitoring Pydantic schemas for OSIRIS Phase 1.5 Backend API."""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class FileQueryParams(BaseModel):
    """Query parameters for filtering and paginating observed files."""

    host_id: Optional[UUID] = None
    path: Optional[str] = None
    file_type: Optional[str] = None
    limit: int = Field(default=50, ge=1)
    offset: int = Field(default=0, ge=0)


class FileResponse(BaseModel):
    """Single observed file record matching File ORM fields."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    host_id: UUID
    path: str
    inode: Optional[int] = None
    file_type: Optional[str] = None
    first_seen_at: datetime
    last_seen_at: Optional[datetime] = None
    created_at: datetime


class PaginatedFileResponse(BaseModel):
    """Paginated collection of file responses."""

    total: int
    items: list[FileResponse]
    limit: int
    offset: int
