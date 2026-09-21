"""Unit tests for OSIRIS Phase 1.5 Event API routes (/api/events, /api/events/{event_id}).

Tests:
- Authentication enforcement (401 when unauthenticated).
- Empty result returns 200 with total=0.
- Paginated listing with limit and offset.
- Filtering by host_id, start_time, end_time, source, event_type, severity, process_id, pid.
- Multiple filters combined.
- Deterministic chronological ordering.
- Single event retrieval by UUID (200 found, 404 not found, 422 malformed UUID).
- Input validation (limit < 1, offset < 0, start_time > end_time).
- Data correctness: nullable fields, nested JSON payload, timezone-aware timestamps.
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
from backend.db.models.event import Event
from backend.db.models.host import Host
from backend.db.models.process import Process
from backend.main import app


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture
def events_db_session() -> Session:
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
def client(events_db_session: Session) -> TestClient:
    """TestClient with get_db dependency overridden to use events_db_session."""
    app.dependency_overrides[get_db] = lambda: events_db_session
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def auth_user(events_db_session: Session) -> AppUser:
    """Create an active application user and return it."""
    user = AppUser(
        id=uuid.uuid4(),
        username="event_analyst",
        password_hash="pbkdf2_sha256$...",
        role="analyst",
        is_active=True,
        created_at=utcnow(),
    )
    events_db_session.add(user)
    events_db_session.commit()
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
def sample_host(events_db_session: Session) -> Host:
    """Create a sample monitored host in the database."""
    host = Host(
        id=uuid.uuid4(),
        hostname="monitored-server-01",
        os_info="Linux 5.15 Ubuntu",
        ip_address="192.168.1.100",
        created_at=utcnow(),
    )
    events_db_session.add(host)
    events_db_session.commit()
    return host


@pytest.fixture
def sample_process(events_db_session: Session, sample_host: Host) -> Process:
    """Create a sample process in the database."""
    proc = Process(
        id=uuid.uuid4(),
        host_id=sample_host.id,
        pid=1001,
        ppid=1,
        command="/usr/bin/python worker.py",
        executable="/usr/bin/python",
        started_at=utcnow(),
        created_at=utcnow(),
    )
    events_db_session.add(proc)
    events_db_session.commit()
    return proc


@pytest.fixture
def populated_events(
    events_db_session: Session,
    sample_host: Host,
    sample_process: Process,
) -> list[Event]:
    """Populate the database with a deterministic series of realistic events."""
    base_time = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
    events: list[Event] = []

    # Event 0: process start
    e0 = Event(
        id=uuid.UUID("11111111-1111-4111-8111-111111111111"),
        host_id=sample_host.id,
        process_id=sample_process.id,
        timestamp=base_time,
        ingested_at=base_time + timedelta(milliseconds=10),
        source="proc",
        event_type="process.start",
        action="start",
        severity="info",
        uid=1000,
        username="student",
        pid=1001,
        ppid=1,
        command="/usr/bin/python worker.py",
        object_type="process",
        object_path=None,
        success=True,
        result="started",
        payload={"args": ["worker.py"]},
        created_at=base_time,
    )
    # Event 1: filesystem write
    e1 = Event(
        id=uuid.UUID("22222222-2222-4222-8222-222222222222"),
        host_id=sample_host.id,
        process_id=sample_process.id,
        timestamp=base_time + timedelta(seconds=10),
        ingested_at=base_time + timedelta(seconds=10, milliseconds=5),
        source="fs",
        event_type="filesystem.modify",
        action="modify",
        severity="info",
        uid=1000,
        username="student",
        pid=1001,
        ppid=1,
        command="/usr/bin/python worker.py",
        object_type="file",
        object_path="/var/log/worker.log",
        success=True,
        result="written",
        payload={"mask": 2, "cookie": 0},
        created_at=base_time + timedelta(seconds=10),
    )
    # Event 2: resource high CPU alert
    e2 = Event(
        id=uuid.UUID("33333333-3333-4333-8333-333333333333"),
        host_id=sample_host.id,
        process_id=None,
        timestamp=base_time + timedelta(seconds=20),
        ingested_at=base_time + timedelta(seconds=20, milliseconds=2),
        source="resource",
        event_type="resource.snapshot",
        action="snapshot",
        severity="high",
        uid=None,
        username=None,
        pid=None,
        ppid=None,
        command=None,
        object_type="system",
        object_path=None,
        success=True,
        result=None,
        payload={"cpu_percent": 95.5, "memory_percent": 82.0},
        created_at=base_time + timedelta(seconds=20),
    )

    events_db_session.add_all([e0, e1, e2])
    events_db_session.commit()
    return [e0, e1, e2]


# ============================================================================
# Authentication Enforcement Tests
# ============================================================================


class TestEventAuthEnforcement:
    """Tests authentication requirement on event endpoints."""

    def test_list_events_unauthenticated_returns_401(self, client: TestClient) -> None:
        resp = client.get("/api/events")
        assert resp.status_code == 401
        assert resp.headers.get("WWW-Authenticate") == "Bearer"

    def test_get_event_unauthenticated_returns_401(self, client: TestClient) -> None:
        random_id = uuid.uuid4()
        resp = client.get(f"/api/events/{random_id}")
        assert resp.status_code == 401
        assert resp.headers.get("WWW-Authenticate") == "Bearer"


# ============================================================================
# GET /api/events Tests
# ============================================================================


class TestListEventsEndpoint:
    """Tests for GET /api/events listing, filtering, and pagination."""

    def test_list_events_empty_database_returns_200(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
    ) -> None:
        resp = client.get("/api/events", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["items"] == []
        assert data["limit"] == 50
        assert data["offset"] == 0

    def test_list_events_pagination(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_events: list[Event],
    ) -> None:
        # Request limit=2, offset=0
        resp = client.get("/api/events?limit=2&offset=0", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 3
        assert len(data["items"]) == 2
        assert data["limit"] == 2
        assert data["offset"] == 0
        assert data["items"][0]["id"] == str(populated_events[0].id)
        assert data["items"][1]["id"] == str(populated_events[1].id)

        # Request offset=2
        resp2 = client.get("/api/events?limit=2&offset=2", headers=auth_headers)
        assert resp2.status_code == 200
        data2 = resp2.json()
        assert data2["total"] == 3
        assert len(data2["items"]) == 1
        assert data2["items"][0]["id"] == str(populated_events[2].id)

    def test_filter_by_source(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_events: list[Event],
    ) -> None:
        resp = client.get("/api/events?source=fs", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert len(data["items"]) == 1
        assert data["items"][0]["source"] == "fs"
        assert data["items"][0]["event_type"] == "filesystem.modify"

    def test_filter_by_event_type(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_events: list[Event],
    ) -> None:
        resp = client.get("/api/events?event_type=process.start", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["event_type"] == "process.start"

    def test_filter_by_severity(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_events: list[Event],
    ) -> None:
        resp = client.get("/api/events?severity=high", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["severity"] == "high"

    def test_filter_by_pid(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_events: list[Event],
    ) -> None:
        resp = client.get("/api/events?pid=1001", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        for item in data["items"]:
            assert item["pid"] == 1001

    def test_filter_by_process_id(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        sample_process: Process,
        populated_events: list[Event],
    ) -> None:
        resp = client.get(f"/api/events?process_id={sample_process.id}", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        for item in data["items"]:
            assert item["process_id"] == str(sample_process.id)

    def test_filter_by_time_range(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_events: list[Event],
    ) -> None:
        t_start = "2026-03-01T12:00:05Z"
        t_end = "2026-03-01T12:00:15Z"
        resp = client.get(
            f"/api/events?start_time={t_start}&end_time={t_end}",
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["id"] == str(populated_events[1].id)

    def test_combined_filters(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        sample_host: Host,
        populated_events: list[Event],
    ) -> None:
        resp = client.get(
            f"/api/events?host_id={sample_host.id}&source=proc&severity=info&pid=1001",
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["id"] == str(populated_events[0].id)

    def test_deterministic_ordering(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_events: list[Event],
    ) -> None:
        resp = client.get("/api/events?limit=10", headers=auth_headers)
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 3
        # Chronological order
        assert items[0]["id"] == str(populated_events[0].id)
        assert items[1]["id"] == str(populated_events[1].id)
        assert items[2]["id"] == str(populated_events[2].id)


# ============================================================================
# GET /api/events/{event_id} Tests
# ============================================================================


class TestGetEventEndpoint:
    """Tests for GET /api/events/{event_id}."""

    def test_get_event_by_id_success(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_events: list[Event],
    ) -> None:
        target = populated_events[0]
        resp = client.get(f"/api/events/{target.id}", headers=auth_headers)

        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == str(target.id)
        assert data["host_id"] == str(target.host_id)
        assert data["source"] == "proc"
        assert data["event_type"] == "process.start"
        assert data["payload"] == {"args": ["worker.py"]}

    def test_get_event_not_found_returns_404(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
    ) -> None:
        nonexistent_id = uuid.uuid4()
        resp = client.get(f"/api/events/{nonexistent_id}", headers=auth_headers)
        assert resp.status_code == 404
        assert resp.json()["detail"] == "Event not found"


# ============================================================================
# Validation & Error Tests
# ============================================================================


class TestEventValidation:
    """Tests query parameter and path validation."""

    def test_malformed_event_id_returns_422(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
    ) -> None:
        resp = client.get("/api/events/not-a-valid-uuid", headers=auth_headers)
        assert resp.status_code == 422

    def test_invalid_limit_returns_422(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
    ) -> None:
        resp = client.get("/api/events?limit=0", headers=auth_headers)
        assert resp.status_code == 422

    def test_invalid_offset_returns_422(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
    ) -> None:
        resp = client.get("/api/events?offset=-1", headers=auth_headers)
        assert resp.status_code == 422

    def test_invalid_time_range_returns_400(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
    ) -> None:
        t_start = "2026-03-02T00:00:00Z"
        t_end = "2026-03-01T00:00:00Z"  # Earlier than start
        resp = client.get(
            f"/api/events?start_time={t_start}&end_time={t_end}",
            headers=auth_headers,
        )
        assert resp.status_code == 400
        assert "start_time must be less than or equal to end_time" in resp.json()["detail"]
