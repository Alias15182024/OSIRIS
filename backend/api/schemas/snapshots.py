"""Snapshot Pydantic schemas for OSIRIS Phase 2 Milestone 2.1 Backend API."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class SnapshotQueryParams(BaseModel):
    """Query parameters for filtering and paginating system-state snapshots."""

    host_id: Optional[UUID] = None
    snapshot_type: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    limit: int = Field(default=50, ge=1, le=100)
    offset: int = Field(default=0, ge=0)


class SnapshotResponse(BaseModel):
    """Single point-in-time system-state snapshot matching Snapshot ORM fields."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    host_id: UUID
    timestamp: datetime
    snapshot_type: str
    data: dict[str, Any]
    created_at: datetime


class PaginatedSnapshotResponse(BaseModel):
    """Paginated collection of snapshot responses."""

    total: int
    items: list[SnapshotResponse]
    limit: int
    offset: int
