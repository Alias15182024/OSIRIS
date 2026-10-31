"""FastAPI route handlers for Analyst Workspaces (Phase 2 Milestone 2.7)."""

from __future__ import annotations

import logging
from typing import Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.api.deps import get_current_user, get_db, require_roles
from backend.api.schemas.workspace import (
    PaginatedWorkspaceResponse,
    WorkspaceCreateRequest,
    WorkspaceResponse,
    WorkspaceUpdateRequest,
)
from backend.db.models.app_user import AppUser
from backend.services.workspace import (
    HostIsolationError,
    WorkspaceNotFoundError,
    WorkspacePermissionError,
    WorkspaceService,
)

logger = logging.getLogger("osiris.api.workspaces")
router = APIRouter()
workspace_service = WorkspaceService()


@router.post(
    "",
    response_model=WorkspaceResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new investigation workspace",
)
def create_workspace(
    request: WorkspaceCreateRequest,
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(require_roles("admin", "analyst")),
) -> WorkspaceResponse:
    """Create a new investigation workspace associated with the current user."""
    try:
        workspace = workspace_service.create_workspace(db, request, current_user)
        db.commit()
        db.refresh(workspace)
        return WorkspaceResponse.model_validate(workspace)
    except (ValueError, HostIsolationError) as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception as exc:
        db.rollback()
        logger.exception("Failed to create workspace")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create investigation workspace.",
        ) from exc


@router.get(
    "",
    response_model=PaginatedWorkspaceResponse,
    summary="List accessible investigation workspaces",
)
def list_workspaces(
    status_filter: Optional[str] = Query(None, alias="status"),
    host_id: Optional[uuid.UUID] = Query(None),
    incident_id: Optional[uuid.UUID] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
) -> PaginatedWorkspaceResponse:
    """List workspaces accessible to the authenticated analyst."""
    items, total = workspace_service.list_workspaces(
        db=db,
        user=current_user,
        status=status_filter,
        host_id=host_id,
        incident_id=incident_id,
        limit=limit,
        offset=offset,
    )
    return PaginatedWorkspaceResponse(
        items=[WorkspaceResponse.model_validate(w) for w in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{workspace_id}",
    response_model=WorkspaceResponse,
    summary="Retrieve workspace by ID",
)
def get_workspace(
    workspace_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(get_current_user),
) -> WorkspaceResponse:
    """Retrieve full details and configuration of a specific workspace."""
    try:
        workspace = workspace_service.get_workspace(db, workspace_id, current_user)
        return WorkspaceResponse.model_validate(workspace)
    except WorkspaceNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except WorkspacePermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc


@router.patch(
    "/{workspace_id}",
    response_model=WorkspaceResponse,
    summary="Update workspace details or configuration",
)
def update_workspace(
    workspace_id: uuid.UUID,
    request: WorkspaceUpdateRequest,
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(require_roles("admin", "analyst")),
) -> WorkspaceResponse:
    """Update metadata, scope, or preserved configuration of a workspace."""
    try:
        workspace = workspace_service.update_workspace(db, workspace_id, current_user, request)
        db.commit()
        db.refresh(workspace)
        return WorkspaceResponse.model_validate(workspace)
    except WorkspaceNotFoundError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except WorkspacePermissionError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except (ValueError, HostIsolationError) as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception as exc:
        db.rollback()
        logger.exception("Failed to update workspace %s", workspace_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update workspace.",
        ) from exc


@router.post(
    "/{workspace_id}/archive",
    response_model=WorkspaceResponse,
    summary="Archive an investigation workspace",
)
def archive_workspace(
    workspace_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(require_roles("admin", "analyst")),
) -> WorkspaceResponse:
    """Archive an active workspace."""
    try:
        workspace = workspace_service.archive_workspace(db, workspace_id, current_user)
        db.commit()
        db.refresh(workspace)
        return WorkspaceResponse.model_validate(workspace)
    except WorkspaceNotFoundError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except WorkspacePermissionError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc


@router.delete(
    "/{workspace_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete an investigation workspace",
)
def delete_workspace(
    workspace_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: AppUser = Depends(require_roles("admin", "analyst")),
) -> None:
    """Permanently delete an investigation workspace."""
    try:
        workspace_service.delete_workspace(db, workspace_id, current_user)
        db.commit()
    except WorkspaceNotFoundError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except WorkspacePermissionError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
