"""Event Pydantic schemas for OSIRIS Phase 1.5 Backend API."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class EventQueryParams(BaseModel):
    """Query parameters for filtering and paginating events."""

    host_id: Optional[UUID] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    source: Optional[str] = None
    event_type: Optional[str] = None
    severity: Optional[str] = None
    process_id: Optional[UUID] = None
    pid: Optional[int] = None
    limit: int = Field(default=50, ge=1, le=100)
    offset: int = Field(default=0, ge=0)


class EventResponse(BaseModel):
    """Single normalized event response matching Event ORM fields."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    host_id: UUID
    process_id: Optional[UUID] = None
    timestamp: datetime
    ingested_at: datetime
    source: str
    event_type: str
    action: str
    severity: str
    uid: Optional[int] = None
    username: Optional[str] = None
    pid: Optional[int] = None
    ppid: Optional[int] = None
    command: Optional[str] = None
    object_type: Optional[str] = None
    object_path: Optional[str] = None
    success: Optional[bool] = None
    result: Optional[str] = None
    payload: Optional[dict[str, Any]] = None
    created_at: datetime


class PaginatedEventResponse(BaseModel):
    """Paginated collection of event responses."""

    total: int
    items: list[EventResponse]
    limit: int
    offset: int
