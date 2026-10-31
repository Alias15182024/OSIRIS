"""Unit tests for WorkspaceService (Phase 2 Milestone 2.7)."""

from __future__ import annotations

import uuid
import pytest
from sqlalchemy.orm import Session

from backend.api.schemas.workspace import (
    WorkspaceConfig,
    WorkspaceCreateRequest,
    WorkspaceUpdateRequest,
)
from backend.db.models.app_user import AppUser
from backend.db.models.host import Host
from backend.db.models.incident import Incident
from backend.services.workspace import (
    HostIsolationError,
    WorkspaceNotFoundError,
    WorkspacePermissionError,
    WorkspaceService,
)


@pytest.fixture
def workspace_service() -> WorkspaceService:
    return WorkspaceService()


@pytest.fixture
def test_host(contract_db_session: Session) -> Host:
    host = Host(
        hostname="investigation-host-1",
        ip_address="192.168.1.100",
        os_info="Ubuntu 22.04 LTS",
    )
    contract_db_session.add(host)
    contract_db_session.flush()
    contract_db_session.refresh(host)
    return host


@pytest.fixture
def other_host(contract_db_session: Session) -> Host:
    host = Host(
        hostname="foreign-host-2",
        ip_address="10.0.0.50",
        os_info="Debian 12",
    )
    contract_db_session.add(host)
    contract_db_session.flush()
    contract_db_session.refresh(host)
    return host


@pytest.fixture
def test_incident(contract_db_session: Session, test_host: Host) -> Incident:
    inc = Incident(
        title="APT Intrusion Investigation",
        severity="high",
        status="open",
        category="apt",
        host_id=test_host.id,
    )
    contract_db_session.add(inc)
    contract_db_session.flush()
    contract_db_session.refresh(inc)
    return inc


@pytest.fixture
def analyst_user(contract_db_session: Session) -> AppUser:
    user = AppUser(
        username="analyst_alice",
        password_hash="fakehash",
        display_name="Analyst Alice",
        role="analyst",
        is_active=True,
    )
    contract_db_session.add(user)
    contract_db_session.flush()
    contract_db_session.refresh(user)
    return user


@pytest.fixture
def other_analyst_user(contract_db_session: Session) -> AppUser:
    user = AppUser(
        username="analyst_bob",
        password_hash="fakehash",
        display_name="Analyst Bob",
        role="analyst",
        is_active=True,
    )
    contract_db_session.add(user)
    contract_db_session.flush()
    contract_db_session.refresh(user)
    return user


@pytest.fixture
def admin_user(contract_db_session: Session) -> AppUser:
    user = AppUser(
        username="admin_super",
        password_hash="fakehash",
        display_name="Super Admin",
        role="admin",
        is_active=True,
    )
    contract_db_session.add(user)
    contract_db_session.flush()
    contract_db_session.refresh(user)
    return user


class TestWorkspaceService:
    """Validate core business logic and authorization in WorkspaceService."""

    def test_create_workspace_success(
        self,
        contract_db_session: Session,
        workspace_service: WorkspaceService,
        test_host: Host,
        test_incident: Incident,
        analyst_user: AppUser,
    ) -> None:
        req = WorkspaceCreateRequest(
            name="Host 1 Compromise Case",
            description="Investigating suspicious persistence and privilege escalation",
            host_id=test_host.id,
            incident_id=test_incident.id,
            configuration=WorkspaceConfig(
                active_panels=["overview", "graph", "timeline"],
                layout_preferences={"sidebar_collapsed": False},
                selected_entities=[{"type": "incident", "id": str(test_incident.id)}],
            ),
        )

        ws = workspace_service.create_workspace(contract_db_session, req, analyst_user)
        assert ws.id is not None
        assert ws.name == "Host 1 Compromise Case"
        assert ws.owner_id == analyst_user.id
        assert ws.host_id == test_host.id
        assert ws.incident_id == test_incident.id
        assert ws.status == "active"
        assert ws.configuration["active_panels"] == ["overview", "graph", "timeline"]
        assert ws.configuration["selected_entities"][0]["id"] == str(test_incident.id)

    def test_create_workspace_rejects_cross_host_incident(
        self,
        contract_db_session: Session,
        workspace_service: WorkspaceService,
        other_host: Host,
        test_incident: Incident,
        analyst_user: AppUser,
    ) -> None:
        """A workspace assigned to Host B cannot be linked to an incident on Host A."""
        req = WorkspaceCreateRequest(
            name="Conflicting Scope Case",
            host_id=other_host.id,
            incident_id=test_incident.id,
        )
        with pytest.raises(HostIsolationError, match="Cross-host mismatch"):
            workspace_service.create_workspace(contract_db_session, req, analyst_user)

    def test_list_workspaces_enforces_ownership_isolation(
        self,
        contract_db_session: Session,
        workspace_service: WorkspaceService,
        analyst_user: AppUser,
        other_analyst_user: AppUser,
        admin_user: AppUser,
    ) -> None:
        # Alice creates a private workspace
        req_alice = WorkspaceCreateRequest(name="Alice Private Workspace")
        ws_alice = workspace_service.create_workspace(contract_db_session, req_alice, analyst_user)

        # Bob creates a private workspace
        req_bob = WorkspaceCreateRequest(name="Bob Private Workspace")
        ws_bob = workspace_service.create_workspace(contract_db_session, req_bob, other_analyst_user)

        # Alice's view: sees only her own
        alice_workspaces, total_alice = workspace_service.list_workspaces(
            contract_db_session, user=analyst_user
        )
        alice_ids = [w.id for w in alice_workspaces]
        assert ws_alice.id in alice_ids
        assert ws_bob.id not in alice_ids

        # Bob's view: sees only his own
        bob_workspaces, total_bob = workspace_service.list_workspaces(
            contract_db_session, user=other_analyst_user
        )
        bob_ids = [w.id for w in bob_workspaces]
        assert ws_bob.id in bob_ids
        assert ws_alice.id not in bob_ids

        # Admin's view: sees all workspaces
        admin_workspaces, total_admin = workspace_service.list_workspaces(
            contract_db_session, user=admin_user
        )
        admin_ids = [w.id for w in admin_workspaces]
        assert ws_alice.id in admin_ids
        assert ws_bob.id in admin_ids

    def test_get_workspace_enforces_permissions(
        self,
        contract_db_session: Session,
        workspace_service: WorkspaceService,
        analyst_user: AppUser,
        other_analyst_user: AppUser,
        admin_user: AppUser,
    ) -> None:
        req = WorkspaceCreateRequest(name="Confidential Workspace")
        ws = workspace_service.create_workspace(contract_db_session, req, analyst_user)

        # Owner can retrieve
        fetched = workspace_service.get_workspace(contract_db_session, ws.id, analyst_user)
        assert fetched.id == ws.id

        # Admin can retrieve
        admin_fetched = workspace_service.get_workspace(contract_db_session, ws.id, admin_user)
        assert admin_fetched.id == ws.id

        # Unauthorized analyst is denied
        with pytest.raises(WorkspacePermissionError, match="access to this private workspace"):
            workspace_service.get_workspace(contract_db_session, ws.id, other_analyst_user)

        # Nonexistent ID raises 404
        with pytest.raises(WorkspaceNotFoundError):
            workspace_service.get_workspace(contract_db_session, uuid.uuid4(), analyst_user)

    def test_update_and_archive_workspace(
        self,
        contract_db_session: Session,
        workspace_service: WorkspaceService,
        analyst_user: AppUser,
    ) -> None:
        req = WorkspaceCreateRequest(name="Original Name", description="Old desc")
        ws = workspace_service.create_workspace(contract_db_session, req, analyst_user)

        update_req = WorkspaceUpdateRequest(
            name="Renamed Investigation",
            description="Updated description",
            configuration=WorkspaceConfig(active_panels=["graph", "detections"]),
        )
        updated = workspace_service.update_workspace(
            contract_db_session, ws.id, analyst_user, update_req
        )
        assert updated.name == "Renamed Investigation"
        assert updated.description == "Updated description"
        assert updated.configuration["active_panels"] == ["graph", "detections"]
        assert updated.updated_at is not None

        # Archive
        archived = workspace_service.archive_workspace(contract_db_session, ws.id, analyst_user)
        assert archived.status == "archived"

    def test_delete_workspace(
        self,
        contract_db_session: Session,
        workspace_service: WorkspaceService,
        analyst_user: AppUser,
        other_analyst_user: AppUser,
    ) -> None:
        req = WorkspaceCreateRequest(name="Deletable Workspace")
        ws = workspace_service.create_workspace(contract_db_session, req, analyst_user)

        # Other analyst cannot delete
        with pytest.raises(WorkspacePermissionError):
            workspace_service.delete_workspace(contract_db_session, ws.id, other_analyst_user)

        # Owner deletes
        workspace_service.delete_workspace(contract_db_session, ws.id, analyst_user)

        with pytest.raises(WorkspaceNotFoundError):
            workspace_service.get_workspace(contract_db_session, ws.id, analyst_user)

    def test_create_workspace_auto_derives_host_from_incident(
        self,
        contract_db_session: Session,
        workspace_service: WorkspaceService,
        test_host: Host,
        test_incident: Incident,
        analyst_user: AppUser,
    ) -> None:
        """When host_id is omitted but incident_id is given, host_id is inherited from the incident."""
        req = WorkspaceCreateRequest(
            name="Incident Scope Auto Host",
            incident_id=test_incident.id,
            host_id=None,
        )
        ws = workspace_service.create_workspace(contract_db_session, req, analyst_user)
        assert ws.id is not None
        assert ws.host_id == test_host.id
        assert ws.incident_id == test_incident.id

    def test_unowned_workspace_modification_and_deletion_rejected_for_regular_analyst(
        self,
        contract_db_session: Session,
        workspace_service: WorkspaceService,
        analyst_user: AppUser,
        admin_user: AppUser,
    ) -> None:
        """Unowned (global) workspaces can be viewed by analysts, but only modified or deleted by admins."""
        from backend.db.models.workspace import Workspace
        ws_unowned = Workspace(
            name="Global Operational Workspace",
            owner_id=None,
            status="active",
            configuration={},
        )
        contract_db_session.add(ws_unowned)
        contract_db_session.flush()

        # Analyst can view it
        fetched = workspace_service.get_workspace(contract_db_session, ws_unowned.id, analyst_user)
        assert fetched.id == ws_unowned.id

        # Analyst CANNOT update it
        with pytest.raises(WorkspacePermissionError, match="permission to modify"):
            workspace_service.update_workspace(
                contract_db_session,
                ws_unowned.id,
                analyst_user,
                WorkspaceUpdateRequest(name="Hacked Title"),
            )

        # Analyst CANNOT archive it
        with pytest.raises(WorkspacePermissionError, match="permission to archive"):
            workspace_service.archive_workspace(contract_db_session, ws_unowned.id, analyst_user)

        # Analyst CANNOT delete it
        with pytest.raises(WorkspacePermissionError, match="permission to delete"):
            workspace_service.delete_workspace(contract_db_session, ws_unowned.id, analyst_user)

        # Admin CAN update and delete it
        updated = workspace_service.update_workspace(
            contract_db_session,
            ws_unowned.id,
            admin_user,
            WorkspaceUpdateRequest(name="Admin Renamed"),
        )
        assert updated.name == "Admin Renamed"
        workspace_service.delete_workspace(contract_db_session, ws_unowned.id, admin_user)


