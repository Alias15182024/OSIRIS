"""Resource snapshot Pydantic schemas for OSIRIS Phase 1.5 Backend API."""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class ResourceSnapshotQueryParams(BaseModel):
    """Query parameters for filtering and paginating resource snapshots."""

    host_id: Optional[UUID] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    limit: int = Field(default=50, ge=1)
    offset: int = Field(default=0, ge=0)


class ResourceSnapshotResponse(BaseModel):
    """Single point-in-time resource snapshot matching ResourceSnapshot ORM fields."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    host_id: UUID
    timestamp: datetime
    cpu_percent: Optional[float] = None
    memory_total: Optional[int] = None
    memory_used: Optional[int] = None
    memory_percent: Optional[float] = None
    disk_read_bytes: Optional[int] = None
    disk_write_bytes: Optional[int] = None
    disk_usage_percent: Optional[float] = None
    created_at: datetime


class PaginatedResourceSnapshotResponse(BaseModel):
    """Paginated collection of resource snapshot responses."""

    total: int
    items: list[ResourceSnapshotResponse]
    limit: int
    offset: int
