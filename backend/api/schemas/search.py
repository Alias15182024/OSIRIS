"""Pydantic schemas for Advanced Forensic Search (Phase 2 Milestone 2.7)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class SearchFilter(BaseModel):
    """Structured search criteria across multiple forensic entities."""

    model_config = ConfigDict(extra="ignore")

    host_id: Optional[UUID] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    uid: Optional[int] = None
    pid: Optional[int] = None
    process_id: Optional[UUID] = None
    command: Optional[str] = None
    executable: Optional[str] = None
    file_path: Optional[str] = None
    event_type: Optional[str] = None
    event_category: Optional[str] = None
    session_type: Optional[str] = None
    remote_host: Optional[str] = None
    rule_id: Optional[str] = None
    rule_severity: Optional[str] = None
    deviation_type: Optional[str] = None
    incident_status: Optional[str] = None
    incident_severity: Optional[str] = None
    severity: Optional[str] = None
    tags: Optional[list[str]] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    entity_types: Optional[list[str]] = Field(
        default=None,
        description="Filter specific entities: hosts, users, processes, sessions, events, detections, fim_deviations, incidents, files, snapshots",
    )
    query: Optional[str] = Field(None, description="General text search query")
    logic: str = Field(default="and", pattern="^(and|or)$")
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0)


class SearchResultItem(BaseModel):
    """Normalized search result item from any forensic subsystem."""

    model_config = ConfigDict(extra="allow")

    entity_type: str
    entity_id: str
    title: str
    description: Optional[str] = None
    timestamp: Optional[datetime] = None
    host_id: Optional[UUID] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    provenance: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)


class SearchResultResponse(BaseModel):
    """Paginated collection of multi-entity forensic search results."""

    items: list[SearchResultItem]
    total: int
    limit: int
    offset: int
    query_summary: dict[str, Any] = Field(default_factory=dict)
