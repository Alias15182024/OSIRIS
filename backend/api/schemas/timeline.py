"""Timeline Pydantic schemas for OSIRIS Phase 2 Milestone 2.2 Backend API."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class ProcessContext(BaseModel):
    """Contextual process information correlated with a timeline entry."""

    model_config = ConfigDict(from_attributes=True)

    process_id: Optional[UUID] = None
    pid: Optional[int] = None
    ppid: Optional[int] = None
    command: Optional[str] = None
    executable: Optional[str] = None


class UserContext(BaseModel):
    """Contextual Linux user identity correlated with a timeline entry."""

    model_config = ConfigDict(from_attributes=True)

    user_id: Optional[UUID] = None
    uid: Optional[int] = None
    username: Optional[str] = None


class SessionContext(BaseModel):
    """Contextual user session correlated with a timeline entry."""

    model_config = ConfigDict(from_attributes=True)

    session_id: Optional[UUID] = None
    session_type: Optional[str] = None
    terminal: Optional[str] = None
    remote_host: Optional[str] = None


class FileContext(BaseModel):
    """Contextual filesystem object correlated with a timeline entry."""

    model_config = ConfigDict(from_attributes=True)

    file_id: Optional[UUID] = None
    path: Optional[str] = None
    file_type: Optional[str] = None
    inode: Optional[int] = None


class ResourceContext(BaseModel):
    """Contextual system resource telemetry correlated with a timeline entry."""

    model_config = ConfigDict(from_attributes=True)

    resource_snapshot_id: Optional[UUID] = None
    cpu_percent: Optional[float] = None
    memory_percent: Optional[float] = None
    disk_usage_percent: Optional[float] = None


class SnapshotContext(BaseModel):
    """Contextual system-state snapshot correlated with a timeline entry."""

    model_config = ConfigDict(from_attributes=True)

    snapshot_id: Optional[UUID] = None
    snapshot_type: Optional[str] = None
    time_delta_seconds: Optional[float] = None
    process_captured: Optional[bool] = None


class TimelineEntryResponse(BaseModel):
    """Single normalized timeline entry with correlated forensic entity context."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    timestamp: datetime
    host_id: UUID
    source: str
    source_id: UUID
    record_type: str
    event_type: str
    action: str
    severity: str = "info"
    description: Optional[str] = None

    # Correlated entity contexts
    process_context: Optional[ProcessContext] = None
    user_context: Optional[UserContext] = None
    session_context: Optional[SessionContext] = None
    file_context: Optional[FileContext] = None
    resource_context: Optional[ResourceContext] = None
    snapshot_context: Optional[SnapshotContext] = None

    payload: Optional[dict[str, Any]] = None


class TimelineQueryParams(BaseModel):
    """Query parameters for timeline reconstruction, filtering, and pagination."""

    host_id: Optional[UUID] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    record_type: Optional[str] = None
    event_type: Optional[str] = None
    source: Optional[str] = None
    process_id: Optional[UUID] = None
    pid: Optional[int] = Field(default=None, ge=0)
    user_id: Optional[UUID] = None
    uid: Optional[int] = Field(default=None, ge=0)
    username: Optional[str] = None
    order: str = Field(default="asc", pattern="^(asc|desc)$")
    limit: int = Field(default=50, ge=1, le=100)
    offset: int = Field(default=0, ge=0)


class PaginatedTimelineResponse(BaseModel):
    """Paginated collection of unified chronological timeline entries."""

    total: int
    items: list[TimelineEntryResponse]
    limit: int
    offset: int
