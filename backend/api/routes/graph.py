"""FastAPI route handlers for Interactive Entity Relationship Graph (Phase 2 Milestone 2.7)."""

from __future__ import annotations

import logging
from typing import Optional
import uuid

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from backend.api.deps import get_current_user, get_db
from backend.api.schemas.graph import (
    EntityPivotResponse,
    GraphDataResponse,
    GraphExpandRequest,
)
from backend.db.models.app_user import AppUser
from backend.services.workspace import EntityGraphService

logger = logging.getLogger("osiris.api.graph")
router = APIRouter()
graph_service = EntityGraphService()


@router.get(
    "",
    response_model=GraphDataResponse,
    summary="Query initial or entity-centric forensic graph",
)
def get_graph(
    host_id: Optional[uuid.UUID] = Query(None, description="Scope graph to specific host"),
    root_entity_type: Optional[str] = Query(None, description="Starting node type (e.g. process, incident)"),
    root_entity_id: Optional[str] = Query(None, description="Starting node ID"),
    depth: int = Query(1, ge=1, le=3, description="Traversal depth"),
    max_nodes: int = Query(50, ge=5, le=150, description="Maximum nodes returned"),
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
) -> GraphDataResponse:
    """Retrieve an interactive forensic entity graph centered around a host or specific entity."""
    return graph_service.build_initial_graph(
        db=db,
        host_id=host_id,
        root_entity_type=root_entity_type,
        root_entity_id=root_entity_id,
        depth=depth,
        max_nodes=max_nodes,
    )


@router.post(
    "/expand",
    response_model=GraphDataResponse,
    summary="Expand relationships from an existing graph node",
)
def expand_graph_node(
    request: GraphExpandRequest,
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
) -> GraphDataResponse:
    """Expand adjacent neighbors for a specific entity node with strict bounds and provenance."""
    return graph_service.expand_node(
        db=db,
        node_type=request.node_type,
        node_id=request.node_id,
        host_id=request.host_id,
        depth=request.depth,
        max_nodes=request.max_nodes,
        existing_node_ids=request.existing_node_ids,
    )


@router.get(
    "/pivot/{entity_type}/{entity_id}",
    response_model=EntityPivotResponse,
    summary="Retrieve cross-entity pivot records for a specific entity",
)
def get_entity_pivots(
    entity_type: str,
    entity_id: str,
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
) -> EntityPivotResponse:
    """Retrieve direct cross-entity navigation links and contextual relationships."""
    return graph_service.get_entity_pivots(
        db=db,
        entity_type=entity_type,
        entity_id=entity_id,
    )
