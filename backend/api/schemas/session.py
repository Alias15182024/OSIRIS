"""User session Pydantic schemas for OSIRIS (Phase 2 Milestone 2.3)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ProcessSummary(BaseModel):
    """Summary of a process associated with a user session."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    pid: int
    ppid: Optional[int] = None
    command: str
    executable: Optional[str] = None
    started_at: datetime
    ended_at: Optional[datetime] = None


class SessionQueryParams(BaseModel):
    """Query parameters for filtering and paginating user sessions."""

    host_id: Optional[UUID] = None
    linux_user_id: Optional[UUID] = None
    username: Optional[str] = None
    session_type: Optional[str] = None
    terminal: Optional[str] = None
    remote_host: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    is_active: Optional[bool] = None
    limit: int = Field(default=50, ge=1, le=100)
    offset: int = Field(default=0, ge=0)


class SessionResponse(BaseModel):
    """Single observed user login session matching Session ORM entity."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    host_id: UUID
    linux_user_id: Optional[UUID] = None
    username: Optional[str] = None
    uid: Optional[int] = None
    session_type: Optional[str] = None
    terminal: Optional[str] = None
    remote_host: Optional[str] = None
    started_at: datetime
    ended_at: Optional[datetime] = None
    is_active: bool = True
    duration_seconds: Optional[float] = None
    created_at: datetime

    @model_validator(mode="before")
    @classmethod
    def populate_computed_and_user_fields(cls, data: Any) -> Any:
        if hasattr(data, "host_id") and hasattr(data, "started_at"):
            # ORM UserSession object
            ended_at = getattr(data, "ended_at", None)
            started_at = getattr(data, "started_at", None)
            linux_user = getattr(data, "linux_user", None)

            duration = None
            if started_at is not None and ended_at is not None:
                duration = round((ended_at - started_at).total_seconds(), 3)

            return {
                "id": getattr(data, "id"),
                "host_id": getattr(data, "host_id"),
                "linux_user_id": getattr(data, "linux_user_id", None),
                "username": getattr(linux_user, "username", None) if linux_user else None,
                "uid": getattr(linux_user, "uid", None) if linux_user else None,
                "session_type": getattr(data, "session_type", None),
                "terminal": getattr(data, "terminal", None),
                "remote_host": getattr(data, "remote_host", None),
                "started_at": started_at,
                "ended_at": ended_at,
                "is_active": ended_at is None,
                "duration_seconds": duration,
                "created_at": getattr(data, "created_at", None),
            }
        elif isinstance(data, dict):
            ended = data.get("ended_at")
            started = data.get("started_at")
            if "is_active" not in data:
                data["is_active"] = ended is None
            if "duration_seconds" not in data and started and ended:
                st = (
                    datetime.fromisoformat(started)
                    if isinstance(started, str)
                    else started
                )
                en = (
                    datetime.fromisoformat(ended)
                    if isinstance(ended, str)
                    else ended
                )
                data["duration_seconds"] = round((en - st).total_seconds(), 3)
        return data


class SessionDetailResponse(SessionResponse):
    """Detailed user session response including associated process execution."""

    process_count: int = 0
    processes: list[ProcessSummary] = Field(default_factory=list)


class PaginatedSessionResponse(BaseModel):
    """Paginated collection of session responses."""

    total: int
    items: list[SessionResponse]
    limit: int
    offset: int
