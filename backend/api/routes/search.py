"""FastAPI route handlers for Advanced Forensic Search (Phase 2 Milestone 2.7)."""

from __future__ import annotations

import logging
from typing import Optional
import uuid

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from backend.api.deps import get_current_user, get_db
from backend.api.schemas.search import (
    SearchFilter,
    SearchResultResponse,
)
from backend.db.models.app_user import AppUser
from backend.services.workspace import AdvancedSearchService

logger = logging.getLogger("osiris.api.search")
router = APIRouter()
search_service = AdvancedSearchService()


@router.post(
    "/advanced",
    response_model=SearchResultResponse,
    summary="Execute multi-criteria advanced forensic search",
)
def advanced_search(
    criteria: SearchFilter,
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
) -> SearchResultResponse:
    """Execute multi-entity parameterized search across all supported forensic repositories."""
    return search_service.execute_search(db=db, criteria=criteria)


@router.get(
    "",
    response_model=SearchResultResponse,
    summary="Execute quick text search across forensic sources",
)
def quick_search(
    q: Optional[str] = Query(None, description="Free text search query"),
    host_id: Optional[uuid.UUID] = Query(None, description="Scope search to specific host"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
) -> SearchResultResponse:
    """Convenience search endpoint for quick queries across forensic entities."""
    criteria = SearchFilter(
        query=q,
        host_id=host_id,
        limit=limit,
        offset=offset,
    )
    return search_service.execute_search(db=db, criteria=criteria)
