"""Pydantic schemas for Workspace persistence (Phase 2 Milestone 2.7)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class WorkspaceConfig(BaseModel):
    """Structured configuration object preserved within a workspace."""

    model_config = ConfigDict(extra="allow")

    active_panels: list[str] = Field(
        default_factory=lambda: ["overview", "graph", "timeline", "search"]
    )
    layout_preferences: dict[str, Any] = Field(default_factory=dict)
    selected_entities: list[dict[str, Any]] = Field(default_factory=list)
    pinned_evidence: list[dict[str, Any]] = Field(default_factory=list)
    saved_search_filters: dict[str, Any] = Field(default_factory=dict)
    graph_config: dict[str, Any] = Field(default_factory=dict)
    breadcrumbs: list[dict[str, Any]] = Field(default_factory=list)


class WorkspaceCreateRequest(BaseModel):
    """Payload to create a new analyst workspace."""

    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    host_id: Optional[UUID] = None
    incident_id: Optional[UUID] = None
    configuration: Optional[WorkspaceConfig] = None


class WorkspaceUpdateRequest(BaseModel):
    """Payload to update an existing workspace."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    host_id: Optional[UUID] = None
    incident_id: Optional[UUID] = None
    status: Optional[str] = Field(None, pattern="^(active|archived)$")
    configuration: Optional[WorkspaceConfig] = None


class WorkspaceQueryParams(BaseModel):
    """Query parameters for listing accessible workspaces."""

    status: Optional[str] = None
    host_id: Optional[UUID] = None
    incident_id: Optional[UUID] = None
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0)


class WorkspaceResponse(BaseModel):
    """Detailed workspace response representation."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    description: Optional[str] = None
    owner_id: Optional[UUID] = None
    host_id: Optional[UUID] = None
    incident_id: Optional[UUID] = None
    status: str
    configuration: dict[str, Any]
    created_at: datetime
    updated_at: Optional[datetime] = None


class PaginatedWorkspaceResponse(BaseModel):
    """Paginated collection of workspaces."""

    items: list[WorkspaceResponse]
    total: int
    limit: int
    offset: int
