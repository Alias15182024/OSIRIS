"""Unit tests for OSIRIS Sessions API routes (Phase 2 Milestone 2.3)."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

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
from backend.db.models.linux_user import LinuxUser
from backend.db.models.process import Process
from backend.db.models.user_session import UserSession
from backend.main import app


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture
def api_session() -> Session:
    """Provide a thread-safe in-memory SQLite session for TestClient."""
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
def client(api_session: Session) -> TestClient:
    """TestClient with get_db dependency overridden to use api_session."""
    app.dependency_overrides[get_db] = lambda: api_session
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def test_user(api_session: Session) -> AppUser:
    user = AppUser(
        id=uuid.uuid4(),
        username="admin",
        password_hash="pbkdf2_sha256$100000$mock$mock",
        display_name="Admin",
        role="admin",
        is_active=True,
    )
    api_session.add(user)
    api_session.commit()
    return user


@pytest.fixture
def inactive_user(api_session: Session) -> AppUser:
    user = AppUser(
        id=uuid.uuid4(),
        username="disabled",
        password_hash="pbkdf2_sha256$100000$mock$mock",
        display_name="Disabled",
        role="viewer",
        is_active=False,
    )
    api_session.add(user)
    api_session.commit()
    return user


@pytest.fixture
def auth_headers(test_user: AppUser) -> dict[str, str]:
    token = create_access_token(user_id=test_user.id, username=test_user.username, role=test_user.role)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def test_host(api_session: Session) -> Host:
    host = Host(id=uuid.uuid4(), hostname="test-node-01")
    api_session.add(host)
    api_session.commit()
    return host


@pytest.fixture
def test_linux_user(api_session: Session, test_host: Host) -> LinuxUser:
    user = LinuxUser(
        id=uuid.uuid4(),
        host_id=test_host.id,
        uid=1000,
        username="alice",
        first_seen_at=utcnow(),
    )
    api_session.add(user)
    api_session.commit()
    return user


class TestSessionsApiAuthentication:
    """Test auth requirements on sessions endpoints."""

    def test_list_sessions_unauthenticated_returns_401(self, client: TestClient) -> None:
        resp = client.get("/api/sessions")
        assert resp.status_code == 401

    def test_get_session_unauthenticated_returns_401(self, client: TestClient) -> None:
        resp = client.get(f"/api/sessions/{uuid.uuid4()}")
        assert resp.status_code == 401

    def test_inactive_user_returns_403(
        self, client: TestClient, inactive_user: AppUser
    ) -> None:
        token = create_access_token(
            user_id=inactive_user.id,
            username=inactive_user.username,
            role=inactive_user.role,
        )
        resp = client.get("/api/sessions", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403


class TestSessionsApiListingAndFiltering:
    """Test GET /api/sessions filtering and pagination."""

    def test_list_empty_sessions(self, client: TestClient, auth_headers: dict[str, str]) -> None:
        resp = client.get("/api/sessions", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["items"] == []
        assert data["limit"] == 50
        assert data["offset"] == 0

    def test_list_sessions_pagination_and_ordering(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        api_session: Session,
        test_host: Host,
        test_linux_user: LinuxUser,
    ) -> None:
        t0 = utcnow()
        s1 = UserSession(
            id=uuid.uuid4(),
            host_id=test_host.id,
            linux_user_id=test_linux_user.id,
            session_type="ssh",
            terminal="pts/0",
            started_at=t0 - timedelta(hours=2),
            ended_at=t0 - timedelta(hours=1),
        )
        s2 = UserSession(
            id=uuid.uuid4(),
            host_id=test_host.id,
            linux_user_id=test_linux_user.id,
            session_type="tty",
            terminal="tty1",
            started_at=t0 - timedelta(minutes=30),
            ended_at=None,
        )
        api_session.add_all([s1, s2])
        api_session.commit()

        # Should order newest first (s2 before s1)
        resp = client.get("/api/sessions", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert len(data["items"]) == 2
        assert data["items"][0]["id"] == str(s2.id)
        assert data["items"][1]["id"] == str(s1.id)
        assert data["items"][0]["username"] == "alice"
        assert data["items"][0]["is_active"] is True
        assert data["items"][1]["is_active"] is False

    def test_filter_by_active_status(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        api_session: Session,
        test_host: Host,
        test_linux_user: LinuxUser,
    ) -> None:
        t0 = utcnow()
        s_closed = UserSession(
            id=uuid.uuid4(),
            host_id=test_host.id,
            linux_user_id=test_linux_user.id,
            started_at=t0 - timedelta(hours=1),
            ended_at=t0 - timedelta(minutes=30),
        )
        s_active = UserSession(
            id=uuid.uuid4(),
            host_id=test_host.id,
            linux_user_id=test_linux_user.id,
            started_at=t0 - timedelta(minutes=10),
            ended_at=None,
        )
        api_session.add_all([s_closed, s_active])
        api_session.commit()

        # is_active=true
        resp_act = client.get("/api/sessions?is_active=true", headers=auth_headers)
        assert resp_act.status_code == 200
        data_act = resp_act.json()
        assert data_act["total"] == 1
        assert data_act["items"][0]["id"] == str(s_active.id)

        # is_active=false
        resp_closed = client.get("/api/sessions?is_active=false", headers=auth_headers)
        assert resp_closed.status_code == 200
        data_closed = resp_closed.json()
        assert data_closed["total"] == 1
        assert data_closed["items"][0]["id"] == str(s_closed.id)

    def test_filter_by_username(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        api_session: Session,
        test_host: Host,
        test_linux_user: LinuxUser,
    ) -> None:
        s = UserSession(
            id=uuid.uuid4(),
            host_id=test_host.id,
            linux_user_id=test_linux_user.id,
            started_at=utcnow(),
        )
        api_session.add(s)
        api_session.commit()

        resp = client.get("/api/sessions?username=alice", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

        resp_non = client.get("/api/sessions?username=nonexistent", headers=auth_headers)
        assert resp_non.status_code == 200
        assert resp_non.json()["total"] == 0

    def test_inverted_time_range_returns_400(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        t_start = "2026-10-30T15:00:00Z"
        t_end = "2026-10-30T14:00:00Z"
        resp = client.get(
            f"/api/sessions?start_time={t_start}&end_time={t_end}",
            headers=auth_headers,
        )
        assert resp.status_code == 400
        assert "start_time must be less than or equal to end_time" in resp.json()["detail"]


class TestSessionsApiSingleRetrieval:
    """Test GET /api/sessions/{session_id} single lookup and process association."""

    def test_get_session_by_id_success(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        api_session: Session,
        test_host: Host,
        test_linux_user: LinuxUser,
    ) -> None:
        t0 = utcnow() - timedelta(minutes=20)
        session = UserSession(
            id=uuid.uuid4(),
            host_id=test_host.id,
            linux_user_id=test_linux_user.id,
            session_type="ssh",
            terminal="pts/0",
            remote_host="192.168.1.50",
            started_at=t0,
            ended_at=t0 + timedelta(minutes=15),
        )
        proc = Process(
            id=uuid.uuid4(),
            host_id=test_host.id,
            pid=4321,
            command="/bin/bash",
            linux_user_id=test_linux_user.id,
            started_at=t0 + timedelta(minutes=1),
        )
        api_session.add_all([session, proc])
        api_session.commit()

        resp = client.get(f"/api/sessions/{session.id}", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == str(session.id)
        assert data["host_id"] == str(test_host.id)
        assert data["username"] == "alice"
        assert data["session_type"] == "ssh"
        assert data["terminal"] == "pts/0"
        assert data["remote_host"] == "192.168.1.50"
        assert data["is_active"] is False
        assert data["duration_seconds"] == 900.0
        assert data["process_count"] == 1
        assert len(data["processes"]) == 1
        assert data["processes"][0]["pid"] == 4321
        assert data["processes"][0]["command"] == "/bin/bash"

    def test_get_session_not_found_returns_404(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        nonexistent_id = uuid.uuid4()
        resp = client.get(f"/api/sessions/{nonexistent_id}", headers=auth_headers)
        assert resp.status_code == 404
        assert resp.json()["detail"] == "Session not found"

    def test_get_session_invalid_uuid_returns_422(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        resp = client.get("/api/sessions/invalid-uuid-string", headers=auth_headers)
        assert resp.status_code == 422


class TestSessionsApiOpenApiRegistration:
    """Verify route registration in OpenAPI schema."""

    def test_openapi_schema_contains_sessions_endpoints(self, client: TestClient) -> None:
        resp = client.get("/openapi.json")
        assert resp.status_code == 200
        schema = resp.json()
        paths = schema.get("paths", {})
        assert "/api/sessions" in paths
        assert "get" in paths["/api/sessions"]
        assert "/api/sessions/{session_id}" in paths
        assert "get" in paths["/api/sessions/{session_id}"]
