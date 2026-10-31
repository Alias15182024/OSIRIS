"""Pydantic schemas for Interactive Entity Relationship Graph (Phase 2 Milestone 2.7)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class GraphNode(BaseModel):
    """A node in the forensic entity graph."""

    model_config = ConfigDict(extra="allow")

    id: str  # Format: "entity_type:entity_id"
    entity_type: str  # e.g. "host", "user", "process", "session", "event", "snapshot", "detection", "fim_deviation", "file", "incident"
    entity_id: str
    label: str
    subtitle: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    timestamp: Optional[datetime] = None
    host_id: Optional[UUID] = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)


class GraphEdge(BaseModel):
    """A directed relationship edge in the entity graph."""

    model_config = ConfigDict(extra="allow")

    id: str  # Format: "source->target:relationship"
    source: str
    target: str
    relationship: str
    label: str
    edge_type: str = Field(default="direct_database")  # "direct_database" or "inferred_correlation"
    provenance: dict[str, Any] = Field(default_factory=dict)


class GraphDataResponse(BaseModel):
    """Payload representing a bounded forensic entity subgraph."""

    nodes: list[GraphNode]
    edges: list[GraphEdge]
    total_nodes: int
    total_edges: int
    truncated: bool = False
    max_limit_reached: bool = False
    root_node_id: Optional[str] = None


class GraphQueryRequest(BaseModel):
    """Parameters to query or initiate a graph view."""

    host_id: Optional[UUID] = None
    root_entity_type: Optional[str] = None
    root_entity_id: Optional[str] = None
    depth: int = Field(default=1, ge=1, le=3)
    max_nodes: int = Field(default=50, ge=5, le=150)


class GraphExpandRequest(BaseModel):
    """Parameters to expand relationships from an existing node."""

    node_type: str
    node_id: str
    host_id: Optional[UUID] = None
    depth: int = Field(default=1, ge=1, le=2)
    max_nodes: int = Field(default=30, ge=1, le=100)
    existing_node_ids: list[str] = Field(default_factory=list)


class EntityPivotResponse(BaseModel):
    """Cross-entity pivoting details for a selected entity."""

    entity_type: str
    entity_id: str
    label: str
    host_id: Optional[UUID] = None
    related_entities: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    breadcrumbs: list[dict[str, str]] = Field(default_factory=list)
