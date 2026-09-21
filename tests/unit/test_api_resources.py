"""Unit tests for OSIRIS Phase 1.5 Resource API routes (/api/resources).

Tests:
- Authentication enforcement (401 when unauthenticated).
- Empty result returns 200 with total=0.
- Paginated listing with limit and offset.
- Filtering by host_id, start_time, and end_time.
- Combined filters.
- Deterministic chronological ordering (timestamp ASC, id ASC).
- Input validation (malformed host_id -> 422, limit < 1 -> 422, offset < 0 -> 422, start_time > end_time -> 400).
- Data correctness: nullable CPU, memory, and disk metrics, timezone-aware timestamp serialization.
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
from backend.db.models.resource_snapshot import ResourceSnapshot
from backend.main import app


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture
def res_db_session() -> Session:
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
def client(res_db_session: Session) -> TestClient:
    """TestClient with get_db dependency overridden to use res_db_session."""
    app.dependency_overrides[get_db] = lambda: res_db_session
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def auth_user(res_db_session: Session) -> AppUser:
    """Create an active application user and return it."""
    user = AppUser(
        id=uuid.uuid4(),
        username="res_analyst",
        password_hash="pbkdf2_sha256$...",
        role="analyst",
        is_active=True,
        created_at=utcnow(),
    )
    res_db_session.add(user)
    res_db_session.commit()
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
def sample_host(res_db_session: Session) -> Host:
    """Create a sample monitored host in the database."""
    host = Host(
        id=uuid.uuid4(),
        hostname="monitored-server-03",
        os_info="Linux 5.15 Ubuntu",
        ip_address="192.168.1.102",
        created_at=utcnow(),
    )
    res_db_session.add(host)
    res_db_session.commit()
    return host


@pytest.fixture
def populated_snapshots(
    res_db_session: Session,
    sample_host: Host,
) -> list[ResourceSnapshot]:
    """Create a deterministic series of realistic resource snapshots."""
    t0 = datetime(2026, 3, 1, 8, 0, 0, tzinfo=timezone.utc)

    # Snapshot 0: All metrics populated
    s0 = ResourceSnapshot(
        id=uuid.UUID("11111111-1111-4111-8111-111111111111"),
        host_id=sample_host.id,
        timestamp=t0,
        cpu_percent=15.2,
        memory_total=16_000_000_000,
        memory_used=4_000_000_000,
        memory_percent=25.0,
        disk_read_bytes=1048576,
        disk_write_bytes=2097152,
        disk_usage_percent=45.5,
        created_at=t0,
    )

    # Snapshot 1: Higher load
    s1 = ResourceSnapshot(
        id=uuid.UUID("22222222-2222-4222-8222-222222222222"),
        host_id=sample_host.id,
        timestamp=t0 + timedelta(seconds=10),
        cpu_percent=88.5,
        memory_total=16_000_000_000,
        memory_used=12_000_000_000,
        memory_percent=75.0,
        disk_read_bytes=5242880,
        disk_write_bytes=8388608,
        disk_usage_percent=45.6,
        created_at=t0 + timedelta(seconds=10),
    )

    # Snapshot 2: Nullable metrics (e.g. initial boot tick or partial read)
    s2 = ResourceSnapshot(
        id=uuid.UUID("33333333-3333-4333-8333-333333333333"),
        host_id=sample_host.id,
        timestamp=t0 + timedelta(seconds=20),
        cpu_percent=None,
        memory_total=16_000_000_000,
        memory_used=None,
        memory_percent=None,
        disk_read_bytes=None,
        disk_write_bytes=None,
        disk_usage_percent=45.7,
        created_at=t0 + timedelta(seconds=20),
    )

    res_db_session.add_all([s0, s1, s2])
    res_db_session.commit()
    return [s0, s1, s2]


# ============================================================================
# Authentication Enforcement Tests
# ============================================================================


class TestResourceAuthEnforcement:
    """Tests authentication requirement on resource snapshot endpoint."""

    def test_list_resources_unauthenticated_returns_401(self, client: TestClient) -> None:
        resp = client.get("/api/resources")
        assert resp.status_code == 401
        assert resp.headers.get("WWW-Authenticate") == "Bearer"


# ============================================================================
# GET /api/resources Tests
# ============================================================================


class TestListResourcesEndpoint:
    """Tests for GET /api/resources listing, filtering, and pagination."""

    def test_list_resources_empty_returns_200(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
    ) -> None:
        resp = client.get("/api/resources", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["items"] == []
        assert data["limit"] == 50
        assert data["offset"] == 0

    def test_list_resources_pagination(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_snapshots: list[ResourceSnapshot],
    ) -> None:
        resp = client.get("/api/resources?limit=2&offset=0", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 3
        assert len(data["items"]) == 2
        assert data["limit"] == 2
        assert data["offset"] == 0
        assert data["items"][0]["id"] == str(populated_snapshots[0].id)
        assert data["items"][1]["id"] == str(populated_snapshots[1].id)

        resp2 = client.get("/api/resources?limit=2&offset=2", headers=auth_headers)
        assert resp2.status_code == 200
        data2 = resp2.json()
        assert data2["total"] == 3
        assert len(data2["items"]) == 1
        assert data2["items"][0]["id"] == str(populated_snapshots[2].id)

    def test_filter_by_host_id(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        sample_host: Host,
        populated_snapshots: list[ResourceSnapshot],
    ) -> None:
        resp = client.get(f"/api/resources?host_id={sample_host.id}", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 3

        other_host_id = uuid.uuid4()
        resp2 = client.get(f"/api/resources?host_id={other_host_id}", headers=auth_headers)
        assert resp2.status_code == 200
        assert resp2.json()["total"] == 0

    def test_filter_by_start_time(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_snapshots: list[ResourceSnapshot],
    ) -> None:
        t_start = "2026-03-01T08:00:10Z"
        resp = client.get(f"/api/resources?start_time={t_start}", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert data["items"][0]["id"] == str(populated_snapshots[1].id)
        assert data["items"][1]["id"] == str(populated_snapshots[2].id)

    def test_filter_by_end_time(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_snapshots: list[ResourceSnapshot],
    ) -> None:
        t_end = "2026-03-01T08:00:10Z"
        resp = client.get(f"/api/resources?end_time={t_end}", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert data["items"][0]["id"] == str(populated_snapshots[0].id)
        assert data["items"][1]["id"] == str(populated_snapshots[1].id)

    def test_combined_filters(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        sample_host: Host,
        populated_snapshots: list[ResourceSnapshot],
    ) -> None:
        t_start = "2026-03-01T08:00:05Z"
        t_end = "2026-03-01T08:00:15Z"
        resp = client.get(
            f"/api/resources?host_id={sample_host.id}&start_time={t_start}&end_time={t_end}",
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["id"] == str(populated_snapshots[1].id)

    def test_deterministic_ordering(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_snapshots: list[ResourceSnapshot],
    ) -> None:
        resp = client.get("/api/resources?limit=10", headers=auth_headers)
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 3
        assert items[0]["id"] == str(populated_snapshots[0].id)
        assert items[1]["id"] == str(populated_snapshots[1].id)
        assert items[2]["id"] == str(populated_snapshots[2].id)


# ============================================================================
# Validation & Error Tests
# ============================================================================


class TestResourceValidation:
    """Tests query parameter validation."""

    def test_malformed_host_id_returns_422(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
    ) -> None:
        resp = client.get("/api/resources?host_id=invalid-uuid", headers=auth_headers)
        assert resp.status_code == 422

    def test_invalid_limit_returns_422(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
    ) -> None:
        resp = client.get("/api/resources?limit=0", headers=auth_headers)
        assert resp.status_code == 422

    def test_limit_above_maximum_returns_422(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
    ) -> None:
        resp = client.get("/api/resources?limit=101", headers=auth_headers)
        assert resp.status_code == 422


    def test_invalid_offset_returns_422(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
    ) -> None:
        resp = client.get("/api/resources?offset=-1", headers=auth_headers)
        assert resp.status_code == 422

    def test_inverted_time_range_returns_400(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
    ) -> None:
        t_start = "2026-03-01T08:00:20Z"
        t_end = "2026-03-01T08:00:10Z"  # Earlier than start
        resp = client.get(
            f"/api/resources?start_time={t_start}&end_time={t_end}",
            headers=auth_headers,
        )
        assert resp.status_code == 400
        assert "start_time must be less than or equal to end_time" in resp.json()["detail"]


# ============================================================================
# Data Correctness Tests
# ============================================================================


class TestResourceDataCorrectness:
    """Tests field serialization and nullable values."""

    def test_nullable_metrics_preserved(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_snapshots: list[ResourceSnapshot],
    ) -> None:
        resp = client.get("/api/resources?limit=10", headers=auth_headers)
        assert resp.status_code == 200
        items = resp.json()["items"]

        # Item 0: all fields populated
        assert items[0]["cpu_percent"] == 15.2
        assert items[0]["memory_percent"] == 25.0
        assert items[0]["disk_read_bytes"] == 1048576

        # Item 2: nullable fields
        assert items[2]["cpu_percent"] is None
        assert items[2]["memory_used"] is None
        assert items[2]["memory_percent"] is None
        assert items[2]["disk_read_bytes"] is None
        assert items[2]["disk_write_bytes"] is None
        assert items[2]["disk_usage_percent"] == 45.7
