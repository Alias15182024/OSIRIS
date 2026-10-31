"""Unit tests for OSIRIS Workspace API routes (Phase 2 Milestone 2.7)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Generator
import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from starlette.testclient import TestClient

from backend.api.deps import get_db
from backend.api.security import create_access_token
from backend.db.base import Base
from backend.db.models.app_user import AppUser
from backend.db.models.host import Host
from backend.db.models.incident import Incident
from backend.db.models.workspace import Workspace
from backend.main import app


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture
def api_session() -> Generator[Session, None, None]:
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = Session(engine)

    yield session

    session.close()
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture
def client(api_session: Session) -> Generator[TestClient, None, None]:
    app.dependency_overrides[get_db] = lambda: api_session
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def admin_user(api_session: Session) -> AppUser:
    user = AppUser(
        id=uuid.uuid4(),
        username="admin_alice",
        password_hash="fakehash",
        display_name="Alice Admin",
        role="admin",
        is_active=True,
        created_at=utcnow(),
    )
    api_session.add(user)
    api_session.commit()
    return user


@pytest.fixture
def analyst_user(api_session: Session) -> AppUser:
    user = AppUser(
        id=uuid.uuid4(),
        username="analyst_bob",
        password_hash="fakehash",
        display_name="Bob Analyst",
        role="analyst",
        is_active=True,
        created_at=utcnow(),
    )
    api_session.add(user)
    api_session.commit()
    return user


@pytest.fixture
def other_analyst(api_session: Session) -> AppUser:
    user = AppUser(
        id=uuid.uuid4(),
        username="analyst_charlie",
        password_hash="fakehash",
        display_name="Charlie Analyst",
        role="analyst",
        is_active=True,
        created_at=utcnow(),
    )
    api_session.add(user)
    api_session.commit()
    return user


@pytest.fixture
def viewer_user(api_session: Session) -> AppUser:
    user = AppUser(
        id=uuid.uuid4(),
        username="viewer_david",
        password_hash="fakehash",
        display_name="David Viewer",
        role="viewer",
        is_active=True,
        created_at=utcnow(),
    )
    api_session.add(user)
    api_session.commit()
    return user


@pytest.fixture
def admin_headers(admin_user: AppUser) -> dict[str, str]:
    token = create_access_token(user_id=admin_user.id, username=admin_user.username, role=admin_user.role)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def analyst_headers(analyst_user: AppUser) -> dict[str, str]:
    token = create_access_token(user_id=analyst_user.id, username=analyst_user.username, role=analyst_user.role)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def other_analyst_headers(other_analyst: AppUser) -> dict[str, str]:
    token = create_access_token(user_id=other_analyst.id, username=other_analyst.username, role=other_analyst.role)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def viewer_headers(viewer_user: AppUser) -> dict[str, str]:
    token = create_access_token(user_id=viewer_user.id, username=viewer_user.username, role=viewer_user.role)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def host_a(api_session: Session) -> Host:
    host = Host(id=uuid.uuid4(), hostname="srv-alpha", ip_address="192.168.1.10", created_at=utcnow())
    api_session.add(host)
    api_session.commit()
    return host


@pytest.fixture
def host_b(api_session: Session) -> Host:
    host = Host(id=uuid.uuid4(), hostname="srv-beta", ip_address="192.168.1.20", created_at=utcnow())
    api_session.add(host)
    api_session.commit()
    return host


class TestWorkspaceApi:
    def test_unauthenticated_request_rejected(self, client: TestClient) -> None:
        resp = client.get("/api/workspaces")
        assert resp.status_code == 401

    def test_viewer_cannot_create_workspace(
        self, client: TestClient, viewer_headers: dict[str, str]
    ) -> None:
        payload = {"name": "Viewer Workspace"}
        resp = client.post("/api/workspaces", json=payload, headers=viewer_headers)
        assert resp.status_code == 403

    def test_create_workspace_success(
        self, client: TestClient, analyst_headers: dict[str, str], host_a: Host
    ) -> None:
        payload = {
            "name": "Investigation Alpha",
            "description": "Investigating potential persistence",
            "host_id": str(host_a.id),
            "is_shared": False,
            "configuration": {
                "active_tab": "graph",
                "filters": {"severity": "high"},
            },
        }
        resp = client.post("/api/workspaces", json=payload, headers=analyst_headers)
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "Investigation Alpha"
        assert data["host_id"] == str(host_a.id)
        assert data["status"] == "active"
        assert data["configuration"]["active_tab"] == "graph"

    def test_create_workspace_rejects_cross_host_incident(
        self,
        client: TestClient,
        analyst_headers: dict[str, str],
        api_session: Session,
        analyst_user: AppUser,
        host_a: Host,
        host_b: Host,
    ) -> None:
        incident = Incident(
            title="Breach Beta",
            host_id=host_b.id,
            created_by_id=analyst_user.id,
            status="open",
            severity="critical",
        )
        api_session.add(incident)
        api_session.commit()

        # Workspace scoped to host_a but incident scoped to host_b
        payload = {
            "name": "Invalid Workspace",
            "host_id": str(host_a.id),
            "incident_id": str(incident.id),
        }
        resp = client.post("/api/workspaces", json=payload, headers=analyst_headers)
        assert resp.status_code == 400
        assert "Cross-host mismatch" in resp.json()["detail"]

    def test_list_and_get_workspace(
        self, client: TestClient, analyst_headers: dict[str, str], other_analyst_headers: dict[str, str]
    ) -> None:
        # Create private workspace by analyst
        resp1 = client.post(
            "/api/workspaces",
            json={"name": "Private WS 1", "is_shared": False},
            headers=analyst_headers,
        )
        assert resp1.status_code == 201
        ws_id = resp1.json()["id"]

        # Analyst can list it
        list_resp = client.get("/api/workspaces", headers=analyst_headers)
        assert list_resp.status_code == 200
        assert list_resp.json()["total"] >= 1
        assert any(w["id"] == ws_id for w in list_resp.json()["items"])

        # Other analyst cannot see private workspace in listing
        other_list = client.get("/api/workspaces", headers=other_analyst_headers)
        assert other_list.status_code == 200
        assert not any(w["id"] == ws_id for w in other_list.json()["items"])

        # Other analyst cannot get private workspace by ID (403)
        other_get = client.get(f"/api/workspaces/{ws_id}", headers=other_analyst_headers)
        assert other_get.status_code == 403

        # Owner can get workspace by ID
        get_resp = client.get(f"/api/workspaces/{ws_id}", headers=analyst_headers)
        assert get_resp.status_code == 200
        assert get_resp.json()["name"] == "Private WS 1"

    def test_update_and_archive_workspace(
        self, client: TestClient, analyst_headers: dict[str, str]
    ) -> None:
        resp = client.post(
            "/api/workspaces",
            json={"name": "WS to Update"},
            headers=analyst_headers,
        )
        ws_id = resp.json()["id"]

        # Update
        patch_resp = client.patch(
            f"/api/workspaces/{ws_id}",
            json={"name": "WS Updated Name", "configuration": {"active_tab": "timeline"}},
            headers=analyst_headers,
        )
        assert patch_resp.status_code == 200
        assert patch_resp.json()["name"] == "WS Updated Name"
        assert patch_resp.json()["configuration"]["active_tab"] == "timeline"

        # Archive
        arch_resp = client.post(f"/api/workspaces/{ws_id}/archive", headers=analyst_headers)
        assert arch_resp.status_code == 200
        assert arch_resp.json()["status"] == "archived"

    def test_delete_workspace(
        self, client: TestClient, analyst_headers: dict[str, str], admin_headers: dict[str, str]
    ) -> None:
        resp = client.post(
            "/api/workspaces",
            json={"name": "WS to Delete"},
            headers=analyst_headers,
        )
        ws_id = resp.json()["id"]

        # Admin can delete it
        del_resp = client.delete(f"/api/workspaces/{ws_id}", headers=admin_headers)
        assert del_resp.status_code == 204

        # Confirm 404
        get_resp = client.get(f"/api/workspaces/{ws_id}", headers=admin_headers)
        assert get_resp.status_code == 404

    def test_create_workspace_with_incident_derives_host(
        self,
        client: TestClient,
        api_session: Session,
        analyst_headers: dict[str, str],
    ) -> None:
        host = Host(id=uuid.uuid4(), hostname="incident-host", ip_address="10.8.8.8", created_at=utcnow())
        inc = Incident(
            id=uuid.uuid4(),
            title="Auto Host Incident",
            severity="high",
            status="open",
            category="apt",
            host_id=host.id,
            created_at=utcnow(),
        )
        api_session.add_all([host, inc])
        api_session.commit()

        resp = client.post(
            "/api/workspaces",
            json={"name": "Derive Host Case", "incident_id": str(inc.id)},
            headers=analyst_headers,
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["host_id"] == str(host.id)
        assert data["incident_id"] == str(inc.id)

