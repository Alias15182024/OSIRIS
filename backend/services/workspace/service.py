"""Workspace persistence and management service (Phase 2 Milestone 2.7)."""

from __future__ import annotations

import logging
from typing import Any, Optional
import uuid

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from backend.api.schemas.workspace import (
    WorkspaceConfig,
    WorkspaceCreateRequest,
    WorkspaceUpdateRequest,
)
from backend.db.base import utcnow
from backend.db.models.app_user import AppUser
from backend.db.models.host import Host
from backend.db.models.incident import Incident
from backend.db.models.workspace import Workspace
from backend.services.workspace.models import (
    HostIsolationError,
    WorkspaceNotFoundError,
    WorkspacePermissionError,
)

logger = logging.getLogger("osiris.services.workspace")


class WorkspaceService:
    """Manages creation, query, updating, archiving, and deletion of analyst workspaces."""

    @staticmethod
    def _validate_host_and_incident(
        db: Session, host_id: Optional[uuid.UUID], incident_id: Optional[uuid.UUID]
    ) -> None:
        """Validate foreign keys and ensure host boundary alignment."""
        if host_id is not None:
            host = db.get(Host, host_id)
            if host is None:
                raise ValueError(f"Host with ID '{host_id}' does not exist.")

        if incident_id is not None:
            incident = db.get(Incident, incident_id)
            if incident is None:
                raise ValueError(f"Incident with ID '{incident_id}' does not exist.")
            if host_id is not None and incident.host_id is not None and incident.host_id != host_id:
                raise HostIsolationError(
                    f"Cross-host mismatch: Incident '{incident_id}' belongs to host '{incident.host_id}', "
                    f"which does not match workspace host '{host_id}'."
                )

    def create_workspace(
        self,
        db: Session,
        request: WorkspaceCreateRequest,
        user: AppUser,
    ) -> Workspace:
        """Create a new analyst workspace."""
        target_host = request.host_id
        if target_host is None and request.incident_id is not None:
            inc = db.get(Incident, request.incident_id)
            if inc and inc.host_id is not None:
                target_host = inc.host_id

        self._validate_host_and_incident(db, target_host, request.incident_id)

        config_dict = (
            request.configuration.model_dump()
            if request.configuration is not None
            else WorkspaceConfig().model_dump()
        )

        workspace = Workspace(
            name=request.name.strip(),
            description=request.description.strip() if request.description else None,
            owner_id=user.id,
            host_id=target_host,
            incident_id=request.incident_id,
            status="active",
            configuration=config_dict,
            created_at=utcnow(),
        )

        db.add(workspace)
        db.flush()
        db.refresh(workspace)
        logger.info("Workspace created: id=%s name='%s' owner=%s", workspace.id, workspace.name, user.username)
        return workspace

    def list_workspaces(
        self,
        db: Session,
        user: AppUser,
        status: Optional[str] = None,
        host_id: Optional[uuid.UUID] = None,
        incident_id: Optional[uuid.UUID] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Workspace], int]:
        """List accessible workspaces with deterministic sorting and pagination."""
        query = select(Workspace)

        # Access control:
        # Admins see all workspaces.
        # Analysts and viewers see workspaces they own, or unowned workspaces.
        if user.role != "admin":
            query = query.where(
                or_(
                    Workspace.owner_id == user.id,
                    Workspace.owner_id.is_(None),
                )
            )

        if status:
            query = query.where(Workspace.status == status)
        if host_id:
            query = query.where(Workspace.host_id == host_id)
        if incident_id:
            query = query.where(Workspace.incident_id == incident_id)

        # Total count query
        count_query = select(func.count()).select_from(query.subquery())
        total = db.scalar(count_query) or 0

        # Execute paginated query
        stmt = query.order_by(Workspace.created_at.desc(), Workspace.id.desc()).limit(limit).offset(offset)
        workspaces = list(db.scalars(stmt).all())
        return workspaces, total

    def get_workspace(
        self,
        db: Session,
        workspace_id: uuid.UUID,
        user: AppUser,
    ) -> Workspace:
        """Retrieve a specific workspace, checking authorization."""
        workspace = db.get(Workspace, workspace_id)
        if workspace is None:
            raise WorkspaceNotFoundError(f"Workspace '{workspace_id}' not found.")

        if user.role != "admin" and workspace.owner_id is not None and workspace.owner_id != user.id:
            raise WorkspacePermissionError("You do not have access to this private workspace.")

        return workspace

    def update_workspace(
        self,
        db: Session,
        workspace_id: uuid.UUID,
        user: AppUser,
        update_req: WorkspaceUpdateRequest,
    ) -> Workspace:
        """Update workspace details or configuration."""
        workspace = self.get_workspace(db, workspace_id, user)
        if user.role != "admin" and workspace.owner_id != user.id:
            raise WorkspacePermissionError("You do not have permission to modify this workspace.")

        if update_req.host_id is not None or update_req.incident_id is not None:
            target_host = update_req.host_id if update_req.host_id is not None else workspace.host_id
            target_incident = update_req.incident_id if update_req.incident_id is not None else workspace.incident_id
            self._validate_host_and_incident(db, target_host, target_incident)

        if update_req.name is not None:
            workspace.name = update_req.name.strip()
        if update_req.description is not None:
            workspace.description = update_req.description.strip()
        if update_req.host_id is not None:
            workspace.host_id = update_req.host_id
        if update_req.incident_id is not None:
            workspace.incident_id = update_req.incident_id
        if update_req.status is not None:
            workspace.status = update_req.status
        if update_req.configuration is not None:
            workspace.configuration = update_req.configuration.model_dump()

        workspace.updated_at = utcnow()
        db.flush()
        db.refresh(workspace)
        logger.info("Workspace updated: id=%s user=%s", workspace.id, user.username)
        return workspace

    def archive_workspace(
        self,
        db: Session,
        workspace_id: uuid.UUID,
        user: AppUser,
    ) -> Workspace:
        """Archive an active workspace."""
        workspace = self.get_workspace(db, workspace_id, user)
        if user.role != "admin" and workspace.owner_id != user.id:
            raise WorkspacePermissionError("You do not have permission to archive this workspace.")
        workspace.status = "archived"
        workspace.updated_at = utcnow()
        db.flush()
        db.refresh(workspace)
        logger.info("Workspace archived: id=%s user=%s", workspace.id, user.username)
        return workspace

    def delete_workspace(
        self,
        db: Session,
        workspace_id: uuid.UUID,
        user: AppUser,
    ) -> None:
        """Permanently delete an analyst workspace."""
        workspace = self.get_workspace(db, workspace_id, user)
        if user.role != "admin" and workspace.owner_id != user.id:
            raise WorkspacePermissionError("You do not have permission to delete this workspace.")
        db.delete(workspace)
        db.flush()
        logger.info("Workspace deleted: id=%s user=%s", workspace_id, user.username)
