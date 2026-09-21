"""Process Pydantic schemas for OSIRIS Phase 1.5 Backend API."""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class ProcessQueryParams(BaseModel):
    """Query parameters for filtering and paginating observed processes."""

    host_id: Optional[UUID] = None
    pid: Optional[int] = None
    is_active: Optional[bool] = None
    limit: int = Field(default=50, ge=1)
    offset: int = Field(default=0, ge=0)


class ProcessResponse(BaseModel):
    """Single observed process response matching Process ORM fields."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    host_id: UUID
    pid: int
    ppid: Optional[int] = None
    command: str
    executable: Optional[str] = None
    linux_user_id: Optional[UUID] = None
    started_at: datetime
    ended_at: Optional[datetime] = None
    created_at: datetime


class PaginatedProcessResponse(BaseModel):
    """Paginated collection of process responses."""

    total: int
    items: list[ProcessResponse]
    limit: int
    offset: int
