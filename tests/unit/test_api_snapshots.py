"""Unit tests for OSIRIS Phase 2 Milestone 2.1 Snapshot API routes.

Covers:
- GET /api/snapshots (listing, filtering, pagination, ordering, counts)
- GET /api/snapshots/{snapshot_id} (retrieval, 404, invalid UUID, payload serialization)
- Security & authorization (unauthenticated 401, inactive 403, malformed token)
- Edge cases (inverted timestamp ranges, naive vs aware comparisons, empty data, large payloads, multi-host isolation)
- OpenAPI schema integration
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
from backend.db.models.snapshot import Snapshot
from backend.main import app


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture
def snap_db_session() -> Session:
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
def client(snap_db_session: Session) -> TestClient:
    """TestClient with get_db dependency overridden to use snap_db_session."""
    app.dependency_overrides[get_db] = lambda: snap_db_session
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def auth_user(snap_db_session: Session) -> AppUser:
    """Create an active application user and return it."""
    user = AppUser(
        id=uuid.uuid4(),
        username="snapshot_analyst",
        password_hash="pbkdf2_sha256$100000$salt$hash",
        role="analyst",
        is_active=True,
        created_at=utcnow(),
    )
    snap_db_session.add(user)
    snap_db_session.commit()
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
def inactive_user(snap_db_session: Session) -> AppUser:
    """Create an inactive application user."""
    user = AppUser(
        id=uuid.uuid4(),
        username="inactive_analyst",
        password_hash="pbkdf2_sha256$100000$salt$hash",
        role="analyst",
        is_active=False,
        created_at=utcnow(),
    )
    snap_db_session.add(user)
    snap_db_session.commit()
    return user


@pytest.fixture
def inactive_auth_headers(inactive_user: AppUser) -> dict[str, str]:
    """Generate Bearer Authorization headers for inactive_user."""
    token = create_access_token(
        user_id=inactive_user.id,
        username=inactive_user.username,
        role=inactive_user.role,
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def sample_host_a(snap_db_session: Session) -> Host:
    """Create primary monitored host."""
    host = Host(
        id=uuid.UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
        hostname="monitored-srv-alpha",
        os_info="Linux 5.15 Ubuntu 22.04",
        ip_address="10.0.0.1",
        created_at=utcnow(),
    )
    snap_db_session.add(host)
    snap_db_session.commit()
    return host


@pytest.fixture
def sample_host_b(snap_db_session: Session) -> Host:
    """Create secondary monitored host."""
    host = Host(
        id=uuid.UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
        hostname="monitored-srv-bravo",
        os_info="Linux 5.15 Ubuntu 22.04",
        ip_address="10.0.0.2",
        created_at=utcnow(),
    )
    snap_db_session.add(host)
    snap_db_session.commit()
    return host


@pytest.fixture
def populated_snapshots(
    snap_db_session: Session,
    sample_host_a: Host,
    sample_host_b: Host,
) -> list[Snapshot]:
    """Create a deterministic series of snapshots across hosts and timestamps."""
    # Base timestamp: 2026-03-01T12:00:00Z
    t0 = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)

    # Snapshot 0: Host A, t0, system_state
    s0 = Snapshot(
        id=uuid.UUID("11111111-1111-4111-8111-111111111111"),
        host_id=sample_host_a.id,
        timestamp=t0,
        snapshot_type="system_state",
        data={
            "processes": [{"pid": 101, "command": "/usr/bin/python3"}],
            "resources": {"cpu_percent": 12.5, "memory_percent": 30.0},
        },
        created_at=t0,
    )

    # Snapshot 1: Host A, t0 + 10s, system_state
    s1 = Snapshot(
        id=uuid.UUID("22222222-2222-4222-8222-222222222222"),
        host_id=sample_host_a.id,
        timestamp=t0 + timedelta(seconds=10),
        snapshot_type="system_state",
        data={
            "processes": [
                {"pid": 101, "command": "/usr/bin/python3"},
                {"pid": 102, "command": "/usr/sbin/sshd"},
            ],
            "resources": {"cpu_percent": 45.0, "memory_percent": 32.5},
        },
        created_at=t0 + timedelta(seconds=10),
    )

    # Snapshot 2: Host A, t0 + 20s, custom_inspection
    s2 = Snapshot(
        id=uuid.UUID("33333333-3333-4333-8333-333333333333"),
        host_id=sample_host_a.id,
        timestamp=t0 + timedelta(seconds=20),
        snapshot_type="custom_inspection",
        data={
            "processes": [],
            "resources": None,
        },
        created_at=t0 + timedelta(seconds=20),
    )

    # Snapshot 3: Host A, t0 + 20s, same timestamp as s2 for tie-breaker check, higher UUID
    s3 = Snapshot(
        id=uuid.UUID("44444444-4444-4444-8444-444444444444"),
        host_id=sample_host_a.id,
        timestamp=t0 + timedelta(seconds=20),
        snapshot_type="system_state",
        data={"processes": [{"pid": 1, "command": "systemd"}], "resources": None},
        created_at=t0 + timedelta(seconds=20),
    )

    # Snapshot 4: Host B, t0 + 30s, system_state
    s4 = Snapshot(
        id=uuid.UUID("55555555-5555-4555-8555-555555555555"),
        host_id=sample_host_b.id,
        timestamp=t0 + timedelta(seconds=30),
        snapshot_type="system_state",
        data={
            "processes": [{"pid": 500, "command": "nginx"}],
            "resources": {"cpu_percent": 5.0, "memory_percent": 15.0},
        },
        created_at=t0 + timedelta(seconds=30),
    )

    snap_db_session.add_all([s0, s1, s2, s3, s4])
    snap_db_session.commit()
    return [s0, s1, s2, s3, s4]


# ============================================================================
# Security & Authentication Tests
# ============================================================================


class TestSnapshotAuthEnforcement:
    """Tests authentication requirement on snapshot endpoints."""

    def test_list_snapshots_unauthenticated_returns_401(self, client: TestClient) -> None:
        resp = client.get("/api/snapshots")
        assert resp.status_code == 401
        assert resp.headers.get("WWW-Authenticate") == "Bearer"

    def test_get_snapshot_unauthenticated_returns_401(self, client: TestClient) -> None:
        random_id = uuid.uuid4()
        resp = client.get(f"/api/snapshots/{random_id}")
        assert resp.status_code == 401
        assert resp.headers.get("WWW-Authenticate") == "Bearer"

    def test_inactive_user_returns_403(
        self,
        client: TestClient,
        inactive_auth_headers: dict[str, str],
    ) -> None:
        resp = client.get("/api/snapshots", headers=inactive_auth_headers)
        assert resp.status_code == 403
        assert resp.json()["detail"] == "Inactive user account"

    def test_malformed_token_returns_401(self, client: TestClient) -> None:
        resp = client.get(
            "/api/snapshots",
            headers={"Authorization": "Bearer not-a-valid-token"},
        )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid or malformed token"

    def test_non_bearer_scheme_returns_401(self, client: TestClient) -> None:
        resp = client.get(
            "/api/snapshots",
            headers={"Authorization": "Basic dXNlcjpwYXNz"},
        )
        assert resp.status_code == 401
        assert resp.headers.get("WWW-Authenticate") == "Bearer"


# ============================================================================
# GET /api/snapshots Listing & Filtering Tests
# ============================================================================


class TestListSnapshotsEndpoint:
    """Tests for GET /api/snapshots listing, filtering, pagination, and ordering."""

    def test_list_snapshots_empty_returns_200(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
    ) -> None:
        resp = client.get("/api/snapshots", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["items"] == []
        assert data["limit"] == 50
        assert data["offset"] == 0

    def test_list_snapshots_all(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_snapshots: list[Snapshot],
    ) -> None:
        resp = client.get("/api/snapshots", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 5
        assert len(data["items"]) == 5

    def test_filter_by_host_id(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        sample_host_a: Host,
        sample_host_b: Host,
        populated_snapshots: list[Snapshot],
    ) -> None:
        # Host A has 4 snapshots
        resp_a = client.get(f"/api/snapshots?host_id={sample_host_a.id}", headers=auth_headers)
        assert resp_a.status_code == 200
        data_a = resp_a.json()
        assert data_a["total"] == 4
        assert len(data_a["items"]) == 4
        for item in data_a["items"]:
            assert item["host_id"] == str(sample_host_a.id)

        # Host B has 1 snapshot
        resp_b = client.get(f"/api/snapshots?host_id={sample_host_b.id}", headers=auth_headers)
        assert resp_b.status_code == 200
        data_b = resp_b.json()
        assert data_b["total"] == 1
        assert len(data_b["items"]) == 1
        assert data_b["items"][0]["host_id"] == str(sample_host_b.id)

        # Nonexistent host returns 0 items
        other_host = uuid.uuid4()
        resp_other = client.get(f"/api/snapshots?host_id={other_host}", headers=auth_headers)
        assert resp_other.status_code == 200
        assert resp_other.json()["total"] == 0
        assert resp_other.json()["items"] == []

    def test_filter_by_snapshot_type(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_snapshots: list[Snapshot],
    ) -> None:
        # 4 snapshots are 'system_state'
        resp_sys = client.get("/api/snapshots?snapshot_type=system_state", headers=auth_headers)
        assert resp_sys.status_code == 200
        data_sys = resp_sys.json()
        assert data_sys["total"] == 4
        for item in data_sys["items"]:
            assert item["snapshot_type"] == "system_state"

        # 1 snapshot is 'custom_inspection'
        resp_custom = client.get("/api/snapshots?snapshot_type=custom_inspection", headers=auth_headers)
        assert resp_custom.status_code == 200
        data_custom = resp_custom.json()
        assert data_custom["total"] == 1
        assert data_custom["items"][0]["snapshot_type"] == "custom_inspection"

        # Unknown snapshot type
        resp_none = client.get("/api/snapshots?snapshot_type=nonexistent", headers=auth_headers)
        assert resp_none.status_code == 200
        assert resp_none.json()["total"] == 0

    def test_filter_by_start_time(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_snapshots: list[Snapshot],
    ) -> None:
        # t0 + 20s includes s2, s3 (both at t0+20s) and s4 (t0+30s) -> 3 snapshots
        t_start = "2026-03-01T12:00:20Z"
        resp = client.get(f"/api/snapshots?start_time={t_start}", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 3
        returned_ids = [item["id"] for item in data["items"]]
        assert str(populated_snapshots[4].id) in returned_ids
        assert str(populated_snapshots[3].id) in returned_ids
        assert str(populated_snapshots[2].id) in returned_ids

    def test_filter_by_end_time(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_snapshots: list[Snapshot],
    ) -> None:
        # t0 + 10s includes s0 (t0) and s1 (t0+10s) -> 2 snapshots
        t_end = "2026-03-01T12:00:10Z"
        resp = client.get(f"/api/snapshots?end_time={t_end}", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        returned_ids = [item["id"] for item in data["items"]]
        assert str(populated_snapshots[0].id) in returned_ids
        assert str(populated_snapshots[1].id) in returned_ids

    def test_combined_filters(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        sample_host_a: Host,
        populated_snapshots: list[Snapshot],
    ) -> None:
        # Host A, snapshot_type=system_state, between t0+05s and t0+25s -> s1 (t0+10s) and s3 (t0+20s)
        t_start = "2026-03-01T12:00:05Z"
        t_end = "2026-03-01T12:00:25Z"
        resp = client.get(
            f"/api/snapshots?host_id={sample_host_a.id}&snapshot_type=system_state&start_time={t_start}&end_time={t_end}",
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        returned_ids = [item["id"] for item in data["items"]]
        assert str(populated_snapshots[1].id) in returned_ids
        assert str(populated_snapshots[3].id) in returned_ids
        # s2 is excluded because snapshot_type is custom_inspection
        assert str(populated_snapshots[2].id) not in returned_ids
        # s4 is excluded because host_id is Host B
        assert str(populated_snapshots[4].id) not in returned_ids

    def test_pagination_limit_and_offset(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_snapshots: list[Snapshot],
    ) -> None:
        # First page: limit=2, offset=0
        resp1 = client.get("/api/snapshots?limit=2&offset=0", headers=auth_headers)
        assert resp1.status_code == 200
        data1 = resp1.json()
        assert data1["total"] == 5
        assert len(data1["items"]) == 2
        assert data1["limit"] == 2
        assert data1["offset"] == 0

        # Second page: limit=2, offset=2
        resp2 = client.get("/api/snapshots?limit=2&offset=2", headers=auth_headers)
        assert resp2.status_code == 200
        data2 = resp2.json()
        assert data2["total"] == 5
        assert len(data2["items"]) == 2
        assert data2["offset"] == 2

        # Third page: limit=2, offset=4
        resp3 = client.get("/api/snapshots?limit=2&offset=4", headers=auth_headers)
        assert resp3.status_code == 200
        data3 = resp3.json()
        assert data3["total"] == 5
        assert len(data3["items"]) == 1
        assert data3["offset"] == 4

        # Disjoint verification: items across pages should be distinct
        ids1 = {item["id"] for item in data1["items"]}
        ids2 = {item["id"] for item in data2["items"]}
        ids3 = {item["id"] for item in data3["items"]}
        assert ids1.isdisjoint(ids2)
        assert ids2.isdisjoint(ids3)
        assert len(ids1 | ids2 | ids3) == 5

    def test_deterministic_ordering_newest_first_with_stable_secondary(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_snapshots: list[Snapshot],
    ) -> None:
        """Newest snapshots first (timestamp DESC), with stable secondary ordering (id DESC)."""
        resp = client.get("/api/snapshots?limit=10", headers=auth_headers)
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 5

        # Item 0 should be s4 (t0 + 30s)
        assert items[0]["id"] == str(populated_snapshots[4].id)

        # Items 1 & 2 share timestamp t0 + 20s (s2 and s3).
        # s3 UUID ("4444...") > s2 UUID ("3333..."), so s3 must appear before s2
        assert items[1]["id"] == str(populated_snapshots[3].id)
        assert items[2]["id"] == str(populated_snapshots[2].id)

        # Item 3 should be s1 (t0 + 10s)
        assert items[3]["id"] == str(populated_snapshots[1].id)

        # Item 4 should be s0 (t0)
        assert items[4]["id"] == str(populated_snapshots[0].id)

    def test_identical_filters_applied_to_count_and_results(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        sample_host_a: Host,
        populated_snapshots: list[Snapshot],
    ) -> None:
        """Verify total count matches the filter, even when limit restricts result items."""
        resp = client.get(
            f"/api/snapshots?host_id={sample_host_a.id}&limit=1&offset=0",
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 4  # Total matching host_a is 4
        assert len(data["items"]) == 1  # But only 1 returned due to limit=1

    def test_filter_by_exact_timestamp(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_snapshots: list[Snapshot],
    ) -> None:
        """When start_time == end_time, returns only snapshots with that exact timestamp."""
        t_exact = "2026-03-01T12:00:10Z"
        resp = client.get(
            f"/api/snapshots?start_time={t_exact}&end_time={t_exact}",
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["id"] == str(populated_snapshots[1].id)

    def test_pagination_offset_exceeds_total(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_snapshots: list[Snapshot],
    ) -> None:
        """When offset exceeds total count, returns empty items with correct total."""
        resp = client.get("/api/snapshots?limit=50&offset=100", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 5
        assert data["items"] == []
        assert data["offset"] == 100
        assert data["limit"] == 50

    def test_filter_by_start_time_future_returns_empty(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_snapshots: list[Snapshot],
    ) -> None:
        """When start_time is in the future beyond all records, returns 0 items."""
        resp = client.get("/api/snapshots?start_time=2099-01-01T00:00:00Z", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["items"] == []

    def test_filter_by_end_time_past_returns_empty(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_snapshots: list[Snapshot],
    ) -> None:
        """When end_time is in the past before all records, returns 0 items."""
        resp = client.get("/api/snapshots?end_time=2020-01-01T00:00:00Z", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["items"] == []


# ============================================================================
# GET /api/snapshots/{snapshot_id} Single Retrieval Tests
# ============================================================================


class TestGetSnapshotEndpoint:
    """Tests for GET /api/snapshots/{snapshot_id}."""

    def test_get_snapshot_success(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        sample_host_a: Host,
        populated_snapshots: list[Snapshot],
    ) -> None:
        target = populated_snapshots[1]
        resp = client.get(f"/api/snapshots/{target.id}", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()

        assert data["id"] == str(target.id)
        assert data["host_id"] == str(sample_host_a.id)
        assert data["snapshot_type"] == "system_state"
        assert isinstance(data["timestamp"], str)
        assert isinstance(data["created_at"], str)

        # Check full data payload preservation
        snap_data = data["data"]
        assert "processes" in snap_data
        assert len(snap_data["processes"]) == 2
        assert snap_data["processes"][0]["pid"] == 101
        assert snap_data["processes"][1]["command"] == "/usr/sbin/sshd"
        assert snap_data["resources"]["cpu_percent"] == 45.0

    def test_get_snapshot_nonexistent_returns_404(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
    ) -> None:
        random_id = uuid.uuid4()
        resp = client.get(f"/api/snapshots/{random_id}", headers=auth_headers)
        assert resp.status_code == 404
        assert resp.json()["detail"] == "Snapshot not found"

    def test_get_snapshot_invalid_uuid_returns_422(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
    ) -> None:
        resp = client.get("/api/snapshots/not-a-valid-uuid", headers=auth_headers)
        assert resp.status_code == 422

    def test_no_unrelated_information_exposed(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_snapshots: list[Snapshot],
    ) -> None:
        target = populated_snapshots[0]
        resp = client.get(f"/api/snapshots/{target.id}", headers=auth_headers)
        assert resp.status_code == 200
        keys = set(resp.json().keys())
        # Response should strictly contain the 6 Snapshot model fields, nothing more
        expected_keys = {"id", "host_id", "timestamp", "snapshot_type", "data", "created_at"}
        assert keys == expected_keys

    def test_get_snapshot_uppercase_uuid(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_snapshots: list[Snapshot],
    ) -> None:
        """UUID path parameter should be case-insensitive."""
        target = populated_snapshots[0]
        upper_uuid = str(target.id).upper()
        resp = client.get(f"/api/snapshots/{upper_uuid}", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["id"] == str(target.id)


# ============================================================================
# Validation & Error Handling Tests
# ============================================================================


class TestSnapshotValidation:
    """Tests query parameter validation and error responses."""

    def test_malformed_host_id_returns_422(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
    ) -> None:
        resp = client.get("/api/snapshots?host_id=not-a-uuid", headers=auth_headers)
        assert resp.status_code == 422

    def test_limit_zero_returns_422(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
    ) -> None:
        resp = client.get("/api/snapshots?limit=0", headers=auth_headers)
        assert resp.status_code == 422

    def test_limit_above_100_returns_422(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
    ) -> None:
        resp = client.get("/api/snapshots?limit=101", headers=auth_headers)
        assert resp.status_code == 422

    def test_limit_maximum_100_accepted(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
    ) -> None:
        resp = client.get("/api/snapshots?limit=100", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["limit"] == 100

    def test_offset_negative_returns_422(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
    ) -> None:
        resp = client.get("/api/snapshots?offset=-1", headers=auth_headers)
        assert resp.status_code == 422

    def test_inverted_time_range_returns_400(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
    ) -> None:
        t_start = "2026-03-01T12:00:30Z"
        t_end = "2026-03-01T12:00:10Z"  # Earlier than start
        resp = client.get(
            f"/api/snapshots?start_time={t_start}&end_time={t_end}",
            headers=auth_headers,
        )
        assert resp.status_code == 400
        assert resp.json()["detail"] == "start_time must be less than or equal to end_time"

    def test_mixed_timezone_aware_and_naive_returns_400(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
    ) -> None:
        # Naive datetime and UTC-aware datetime
        t_start = "2026-03-01T12:00:00"  # Naive (no timezone)
        t_end = "2026-03-01T12:00:10Z"   # UTC-aware
        resp = client.get(
            f"/api/snapshots?start_time={t_start}&end_time={t_end}",
            headers=auth_headers,
        )
        assert resp.status_code == 400
        assert resp.json()["detail"] == "Cannot compare timezone-aware and naive datetimes"


# ============================================================================
# Edge Cases Tests
# ============================================================================


class TestSnapshotEdgeCases:
    """Tests edge cases: empty JSON, large JSON payload, timezones, multi-host."""

    def test_empty_json_data_snapshot(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        snap_db_session: Session,
        sample_host_a: Host,
    ) -> None:
        snap = Snapshot(
            id=uuid.uuid4(),
            host_id=sample_host_a.id,
            timestamp=utcnow(),
            snapshot_type="system_state",
            data={},
            created_at=utcnow(),
        )
        snap_db_session.add(snap)
        snap_db_session.commit()

        resp = client.get(f"/api/snapshots/{snap.id}", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["data"] == {}

    def test_large_json_snapshot_payload(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        snap_db_session: Session,
        sample_host_a: Host,
    ) -> None:
        # Simulate a snapshot with 200 processes and deep telemetry trees
        processes = [
            {
                "id": str(uuid.uuid4()),
                "pid": idx,
                "ppid": 1,
                "command": f"/usr/bin/worker_{idx} --flag-{idx}",
                "executable": f"/usr/bin/worker_{idx}",
                "environment": {"VAR": f"val_{idx}"},
                "threads": [idx * 10 + i for i in range(5)],
            }
            for idx in range(1, 201)
        ]
        large_data = {
            "processes": processes,
            "resources": {
                "cpu_percent": 99.9,
                "per_core_percent": [10.0 + i for i in range(16)],
                "memory_total": 64_000_000_000,
                "memory_used": 32_000_000_000,
            },
            "network": {
                "interfaces": [{"name": f"eth{i}", "rx_bytes": i * 1024} for i in range(4)],
            },
        }

        snap = Snapshot(
            id=uuid.uuid4(),
            host_id=sample_host_a.id,
            timestamp=utcnow(),
            snapshot_type="system_state",
            data=large_data,
            created_at=utcnow(),
        )
        snap_db_session.add(snap)
        snap_db_session.commit()

        resp = client.get(f"/api/snapshots/{snap.id}", headers=auth_headers)
        assert resp.status_code == 200
        payload = resp.json()["data"]
        assert len(payload["processes"]) == 200
        assert payload["processes"][199]["pid"] == 200
        assert len(payload["resources"]["per_core_percent"]) == 16
        assert len(payload["network"]["interfaces"]) == 4

    def test_timezone_offset_handling(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        snap_db_session: Session,
        sample_host_a: Host,
    ) -> None:
        """Test timestamp with non-UTC offset (+02:00) queries against stored UTC timestamp."""
        # 2026-03-01T12:00:00Z == 2026-03-01T14:00:00+02:00
        snap_ts = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
        snap = Snapshot(
            id=uuid.uuid4(),
            host_id=sample_host_a.id,
            timestamp=snap_ts,
            snapshot_type="system_state",
            data={"status": "tz_test"},
            created_at=snap_ts,
        )
        snap_db_session.add(snap)
        snap_db_session.commit()

        # Query using +02:00 offset: start_time=13:59:00+02:00 (11:59:00 UTC), end_time=14:01:00+02:00 (12:01:00 UTC)
        # Note: URL-encoded '+' is %2B
        resp = client.get(
            "/api/snapshots?start_time=2026-03-01T13:59:00%2B02:00&end_time=2026-03-01T14:01:00%2B02:00",
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["id"] == str(snap.id)

    def test_multi_host_separate_snapshots_isolation(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        snap_db_session: Session,
    ) -> None:
        """Verify strict isolation across multiple monitored hosts."""
        host1 = Host(id=uuid.uuid4(), hostname="host-1", created_at=utcnow())
        host2 = Host(id=uuid.uuid4(), hostname="host-2", created_at=utcnow())
        host3 = Host(id=uuid.uuid4(), hostname="host-3", created_at=utcnow())
        snap_db_session.add_all([host1, host2, host3])
        snap_db_session.commit()

        # Add 3 snapshots to host1, 2 to host2, 0 to host3
        for i in range(3):
            snap_db_session.add(
                Snapshot(
                    id=uuid.uuid4(),
                    host_id=host1.id,
                    timestamp=utcnow() + timedelta(seconds=i),
                    snapshot_type="system_state",
                    data={"idx": i},
                    created_at=utcnow(),
                )
            )
        for i in range(2):
            snap_db_session.add(
                Snapshot(
                    id=uuid.uuid4(),
                    host_id=host2.id,
                    timestamp=utcnow() + timedelta(seconds=i),
                    snapshot_type="system_state",
                    data={"idx": i},
                    created_at=utcnow(),
                )
            )
        snap_db_session.commit()

        r1 = client.get(f"/api/snapshots?host_id={host1.id}", headers=auth_headers).json()
        r2 = client.get(f"/api/snapshots?host_id={host2.id}", headers=auth_headers).json()
        r3 = client.get(f"/api/snapshots?host_id={host3.id}", headers=auth_headers).json()

        assert r1["total"] == 3
        assert r2["total"] == 2
        assert r3["total"] == 0


# ============================================================================
# OpenAPI Schema Registration Tests
# ============================================================================


class TestSnapshotOpenAPIRegistration:
    """Verifies routes appear in the generated OpenAPI documentation."""

    def test_snapshot_routes_in_openapi_schema(self, client: TestClient) -> None:
        resp = client.get("/openapi.json")
        assert resp.status_code == 200
        schema = resp.json()
        paths = schema["paths"]

        assert "/api/snapshots" in paths
        assert "get" in paths["/api/snapshots"]
        assert "snapshots" in paths["/api/snapshots"]["get"]["tags"]

        assert "/api/snapshots/{snapshot_id}" in paths
        assert "get" in paths["/api/snapshots/{snapshot_id}"]
        assert "snapshots" in paths["/api/snapshots/{snapshot_id}"]["get"]["tags"]


# ============================================================================
# PostgreSQL Integration Tests (Active when PostgreSQL is reachable)
# ============================================================================


class TestPostgreSQLSnapshotAPIIntegration:
    """End-to-end integration tests for snapshot API endpoints on PostgreSQL (JSONB & TIMESTAMPTZ)."""

    def test_postgres_snapshot_api_lifecycle(self) -> None:
        """Verify full lifecycle against real PostgreSQL database with rollback."""
        from backend.config import settings
        from backend.services.snapshots.service import SnapshotService
        import sqlalchemy as sa
        from sqlalchemy import text

        try:
            pg_engine = sa.create_engine(settings.database_url, echo=False)
            with pg_engine.connect() as conn:
                conn.execute(text("SELECT 1"))
        except Exception as exc:
            pytest.skip(f"PostgreSQL not accessible: {exc}")

        connection = pg_engine.connect()
        transaction = connection.begin()
        session = Session(bind=connection, join_transaction_mode="create_savepoint")

        try:
            # 1. Create user and host in PostgreSQL
            u = AppUser(
                id=uuid.uuid4(),
                username="pg_analyst",
                password_hash="pbkdf2_sha256$100000$salt$hash",
                role="analyst",
                is_active=True,
                created_at=utcnow(),
            )
            h = Host(
                id=uuid.uuid4(),
                hostname="pg-srv-snap",
                created_at=utcnow(),
            )
            session.add_all([u, h])
            session.flush()

            # 2. Persist snapshot using SnapshotService
            svc = SnapshotService(session)
            t0 = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
            snap = svc.create_snapshot(h.id, timestamp=t0)
            session.flush()

            # 3. Test API via TestClient with session override
            app.dependency_overrides[get_db] = lambda: session
            with TestClient(app) as test_client:
                token = create_access_token(user_id=u.id, username=u.username, role=u.role)
                headers = {"Authorization": f"Bearer {token}"}

                # Listing with host filter
                r_list = test_client.get(f"/api/snapshots?host_id={h.id}", headers=headers)
                assert r_list.status_code == 200
                data_list = r_list.json()
                assert data_list["total"] == 1
                assert data_list["items"][0]["id"] == str(snap.id)
                assert data_list["items"][0]["host_id"] == str(h.id)
                assert "processes" in data_list["items"][0]["data"]

                # Single retrieval
                r_get = test_client.get(f"/api/snapshots/{snap.id}", headers=headers)
                assert r_get.status_code == 200
                data_get = r_get.json()
                assert data_get["id"] == str(snap.id)
                assert data_get["snapshot_type"] == "system_state"

                # Time range filtering
                r_time = test_client.get(
                    "/api/snapshots?start_time=2026-03-01T11:00:00Z&end_time=2026-03-01T13:00:00Z",
                    headers=headers,
                )
                assert r_time.status_code == 200
                assert r_time.json()["total"] >= 1
        finally:
            app.dependency_overrides.clear()
            session.close()
            if transaction.is_active:
                transaction.rollback()
            connection.close()
            pg_engine.dispose()
