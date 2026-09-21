"""Unit tests for OSIRIS Phase 1.5 Process API routes (/api/processes, /api/processes/{process_id}).

Tests:
- Authentication enforcement (401 when unauthenticated).
- Empty result returns 200 with total=0.
- Paginated listing with limit and offset.
- Filtering by host_id, pid, and is_active (running vs terminated).
- Multiple filters combined.
- Deterministic ordering (started_at ASC, id ASC).
- Single process retrieval by OSIRIS UUID (200 found, 404 not found, 422 malformed UUID).
- Distinction between OSIRIS UUID identity and Linux PID.
- Data correctness: nullable ppid, executable, linux_user_id, ended_at.
"""

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
from backend.main import app


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture
def proc_db_session() -> Session:
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
def client(proc_db_session: Session) -> TestClient:
    """TestClient with get_db dependency overridden to use proc_db_session."""
    app.dependency_overrides[get_db] = lambda: proc_db_session
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def auth_user(proc_db_session: Session) -> AppUser:
    """Create an active application user and return it."""
    user = AppUser(
        id=uuid.uuid4(),
        username="proc_analyst",
        password_hash="pbkdf2_sha256$...",
        role="analyst",
        is_active=True,
        created_at=utcnow(),
    )
    proc_db_session.add(user)
    proc_db_session.commit()
    return user


@pytest.fixture
def auth_headers(auth_user: AppUser) -> dict[str, str]:
    """Generate valid Bearer Authorization headers for auth_user."""
    token = create_access_token(
        user_id=auth_user.id,
        username=auth_user.username,
        role=auth_user.role,
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def sample_host(proc_db_session: Session) -> Host:
    """Create a sample monitored host in the database."""
    host = Host(
        id=uuid.uuid4(),
        hostname="monitored-server-02",
        os_info="Linux 6.1 Debian",
        ip_address="192.168.1.101",
        created_at=utcnow(),
    )
    proc_db_session.add(host)
    proc_db_session.commit()
    return host


@pytest.fixture
def sample_linux_user(proc_db_session: Session, sample_host: Host) -> LinuxUser:
    """Create a sample Linux user in the database."""
    u = LinuxUser(
        id=uuid.uuid4(),
        host_id=sample_host.id,
        uid=1000,
        username="analyst_user",
        first_seen_at=utcnow(),
        created_at=utcnow(),
    )
    proc_db_session.add(u)
    proc_db_session.commit()
    return u


@pytest.fixture
def populated_processes(
    proc_db_session: Session,
    sample_host: Host,
    sample_linux_user: LinuxUser,
) -> list[Process]:
    """Create a deterministic series of processes with active and terminated states."""
    t0 = datetime(2026, 3, 1, 10, 0, 0, tzinfo=timezone.utc)

    # Process 0: Active system init
    p0 = Process(
        id=uuid.UUID("11111111-1111-4111-8111-111111111111"),
        host_id=sample_host.id,
        pid=1,
        ppid=0,
        command="/sbin/init",
        executable="/sbin/init",
        linux_user_id=None,
        started_at=t0,
        ended_at=None,
        created_at=t0,
    )

    # Process 1: Active python daemon
    p1 = Process(
        id=uuid.UUID("22222222-2222-4222-8222-222222222222"),
        host_id=sample_host.id,
        pid=500,
        ppid=1,
        command="/usr/bin/python worker.py",
        executable="/usr/bin/python",
        linux_user_id=sample_linux_user.id,
        started_at=t0 + timedelta(minutes=5),
        ended_at=None,
        created_at=t0 + timedelta(minutes=5),
    )

    # Process 2: Terminated short-lived job with reused PID (pid=500 earlier or later)
    p2 = Process(
        id=uuid.UUID("33333333-3333-4333-8333-333333333333"),
        host_id=sample_host.id,
        pid=500,
        ppid=1,
        command="ls -la /tmp",
        executable="/bin/ls",
        linux_user_id=sample_linux_user.id,
        started_at=t0 + timedelta(minutes=10),
        ended_at=t0 + timedelta(minutes=10, seconds=2),
        created_at=t0 + timedelta(minutes=10),
    )

    # Process 3: Terminated cron job with nullable ppid and executable
    p3 = Process(
        id=uuid.UUID("44444444-4444-4444-8444-444444444444"),
        host_id=sample_host.id,
        pid=800,
        ppid=None,
        command="cron_job.sh",
        executable=None,
        linux_user_id=None,
        started_at=t0 + timedelta(minutes=15),
        ended_at=t0 + timedelta(minutes=16),
        created_at=t0 + timedelta(minutes=15),
    )

    proc_db_session.add_all([p0, p1, p2, p3])
    proc_db_session.commit()
    return [p0, p1, p2, p3]


# ============================================================================
# Authentication Enforcement Tests
# ============================================================================


class TestProcessAuthEnforcement:
    """Tests authentication requirement on process endpoints."""

    def test_list_processes_unauthenticated_returns_401(self, client: TestClient) -> None:
        resp = client.get("/api/processes")
        assert resp.status_code == 401
        assert resp.headers.get("WWW-Authenticate") == "Bearer"

    def test_get_process_unauthenticated_returns_401(self, client: TestClient) -> None:
        random_id = uuid.uuid4()
        resp = client.get(f"/api/processes/{random_id}")
        assert resp.status_code == 401
        assert resp.headers.get("WWW-Authenticate") == "Bearer"


# ============================================================================
# GET /api/processes Tests
# ============================================================================


class TestListProcessesEndpoint:
    """Tests for GET /api/processes listing, filtering, and pagination."""

    def test_list_processes_empty_returns_200(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
    ) -> None:
        resp = client.get("/api/processes", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["items"] == []
        assert data["limit"] == 50
        assert data["offset"] == 0

    def test_list_processes_pagination(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_processes: list[Process],
    ) -> None:
        resp = client.get("/api/processes?limit=2&offset=0", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 4
        assert len(data["items"]) == 2
        assert data["limit"] == 2
        assert data["offset"] == 0
        assert data["items"][0]["id"] == str(populated_processes[0].id)
        assert data["items"][1]["id"] == str(populated_processes[1].id)

        resp2 = client.get("/api/processes?limit=2&offset=2", headers=auth_headers)
        assert resp2.status_code == 200
        data2 = resp2.json()
        assert data2["total"] == 4
        assert len(data2["items"]) == 2
        assert data2["items"][0]["id"] == str(populated_processes[2].id)
        assert data2["items"][1]["id"] == str(populated_processes[3].id)

    def test_filter_by_host_id(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        sample_host: Host,
        populated_processes: list[Process],
    ) -> None:
        resp = client.get(f"/api/processes?host_id={sample_host.id}", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 4

        # Non-matching host
        other_host_id = uuid.uuid4()
        resp2 = client.get(f"/api/processes?host_id={other_host_id}", headers=auth_headers)
        assert resp2.status_code == 200
        assert resp2.json()["total"] == 0

    def test_filter_by_pid(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_processes: list[Process],
    ) -> None:
        # PID 500 has two distinct processes (demonstrating PID reuse)
        resp = client.get("/api/processes?pid=500", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        for item in data["items"]:
            assert item["pid"] == 500
        # Check that both unique OSIRIS UUIDs are returned
        returned_ids = {item["id"] for item in data["items"]}
        assert str(populated_processes[1].id) in returned_ids
        assert str(populated_processes[2].id) in returned_ids

    def test_filter_by_is_active_true(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_processes: list[Process],
    ) -> None:
        resp = client.get("/api/processes?is_active=true", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        for item in data["items"]:
            assert item["ended_at"] is None

    def test_filter_by_is_active_false(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_processes: list[Process],
    ) -> None:
        resp = client.get("/api/processes?is_active=false", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        for item in data["items"]:
            assert item["ended_at"] is not None

    def test_combined_filters(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        sample_host: Host,
        populated_processes: list[Process],
    ) -> None:
        # PID 500 and active=true -> returns only p1
        resp = client.get(
            f"/api/processes?host_id={sample_host.id}&pid=500&is_active=true",
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["id"] == str(populated_processes[1].id)
        assert data["items"][0]["command"] == "/usr/bin/python worker.py"

    def test_deterministic_ordering(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_processes: list[Process],
    ) -> None:
        resp = client.get("/api/processes?limit=10", headers=auth_headers)
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 4
        # Ordered by started_at ASC, id ASC
        assert items[0]["id"] == str(populated_processes[0].id)
        assert items[1]["id"] == str(populated_processes[1].id)
        assert items[2]["id"] == str(populated_processes[2].id)
        assert items[3]["id"] == str(populated_processes[3].id)


# ============================================================================
# GET /api/processes/{process_id} Tests
# ============================================================================


class TestGetProcessEndpoint:
    """Tests for GET /api/processes/{process_id}."""

    def test_get_process_by_uuid_success(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_processes: list[Process],
    ) -> None:
        target = populated_processes[1]
        resp = client.get(f"/api/processes/{target.id}", headers=auth_headers)

        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == str(target.id)
        assert data["host_id"] == str(target.host_id)
        assert data["pid"] == target.pid
        assert data["ppid"] == target.ppid
        assert data["command"] == target.command
        assert data["executable"] == target.executable
        assert data["linux_user_id"] == str(target.linux_user_id)
        assert data["started_at"] is not None
        assert data["ended_at"] is None

    def test_get_process_nullable_fields_preserved(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_processes: list[Process],
    ) -> None:
        target = populated_processes[3]
        resp = client.get(f"/api/processes/{target.id}", headers=auth_headers)

        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == str(target.id)
        assert data["ppid"] is None
        assert data["executable"] is None
        assert data["linux_user_id"] is None
        assert data["ended_at"] is not None

    def test_get_process_not_found_returns_404(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
    ) -> None:
        random_id = uuid.uuid4()
        resp = client.get(f"/api/processes/{random_id}", headers=auth_headers)
        assert resp.status_code == 404
        assert resp.json()["detail"] == "Process not found"

    def test_get_process_malformed_uuid_returns_422(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
    ) -> None:
        # Passing an integer PID instead of a UUID primary key must fail validation
        resp = client.get("/api/processes/500", headers=auth_headers)
        assert resp.status_code == 422
