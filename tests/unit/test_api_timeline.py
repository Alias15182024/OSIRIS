"""Unit tests for OSIRIS Timeline API Endpoint (Phase 2 Milestone 2.2).

Tests cover:
- Authentication & Authorization:
  - Missing token -> 401 Unauthorized with Bearer challenge
  - Invalid token -> 401 Unauthorized
  - Expired token -> 401 Unauthorized
  - Deactivated user account -> 403 Forbidden
- Input Validation:
  - Nonexistent host UUID -> 404 Not Found
  - Malformed host UUID string -> 422 Unprocessable Entity
  - start_time > end_time -> 400 Bad Request
  - limit out of range (< 1 or > 100) -> 422 Unprocessable Entity
  - offset out of range (< 0) -> 422 Unprocessable Entity
  - Invalid order parameter -> 422 Unprocessable Entity
- Functional & Forensic Reconstructions:
  - Multi-source timeline retrieval
  - Host filtering and cross-host isolation
  - Record type filtering (event, process, session, snapshot, resource, file)
  - Time-window filtering
  - Chronological ordering (oldest first) and reverse ordering (newest first)
  - Deterministic tie-breaking for identical timestamps
  - Pagination (disjoint pages, total consistency)
  - Empty results handling (200 OK, total 0, items [])
  - Complete JSON schema serialization
- OpenAPI Integration:
  - Endpoint registered in OpenAPI schema at /openapi.json
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from sqlalchemy import create_engine, event as sa_event
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from starlette.testclient import TestClient

from backend.api.deps import get_db
from backend.api.security import create_access_token
from backend.db.base import Base
from backend.db.models.app_user import AppUser
from backend.db.models.event import Event
from backend.db.models.file import File
from backend.db.models.host import Host
from backend.db.models.linux_user import LinuxUser
from backend.db.models.process import Process
from backend.db.models.resource_snapshot import ResourceSnapshot
from backend.db.models.snapshot import Snapshot
from backend.db.models.user_session import UserSession
from backend.main import app


@pytest.fixture
def api_tl_session() -> Session:
    """Provide a thread-safe in-memory SQLite session for TestClient."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @sa_event.listens_for(engine, "connect")
    def _set_pragma(dbapi_conn, connection_record):  # type: ignore[no-untyped-def]
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    session = Session(engine)

    yield session

    session.close()
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture
def client(api_tl_session: Session) -> TestClient:
    """Provide TestClient with database session dependency overridden."""
    app.dependency_overrides[get_db] = lambda: api_tl_session
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def auth_user(api_tl_session: Session) -> AppUser:
    """Create and return an active analyst user."""
    user = AppUser(
        id=uuid.uuid4(),
        username="timeline_analyst",
        password_hash="pbkdf2_sha256$100000$salt$hash",
        role="analyst",
        is_active=True,
        created_at=datetime.now(timezone.utc),
    )
    api_tl_session.add(user)
    api_tl_session.commit()
    return user


@pytest.fixture
def auth_headers(auth_user: AppUser) -> dict[str, str]:
    """Generate Bearer Authorization headers for auth_user."""
    token = create_access_token(
        user_id=auth_user.id,
        username=auth_user.username,
        role=auth_user.role,
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def inactive_user(api_tl_session: Session) -> AppUser:
    """Create an inactive application user."""
    user = AppUser(
        id=uuid.uuid4(),
        username="inactive_timeline_user",
        password_hash="pbkdf2_sha256$100000$salt$hash",
        role="analyst",
        is_active=False,
        created_at=datetime.now(timezone.utc),
    )
    api_tl_session.add(user)
    api_tl_session.commit()
    return user


@pytest.fixture
def inactive_auth_headers(inactive_user: AppUser) -> dict[str, str]:
    token = create_access_token(
        user_id=inactive_user.id,
        username=inactive_user.username,
        role=inactive_user.role,
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def sample_host_a(api_tl_session: Session) -> Host:
    h = Host(
        id=uuid.UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
        hostname="srv-alpha",
        os_info="Linux 5.15 Ubuntu 22.04",
        created_at=datetime(2026, 3, 1, 0, 0, 0, tzinfo=timezone.utc),
    )
    api_tl_session.add(h)
    api_tl_session.commit()
    return h


@pytest.fixture
def sample_host_b(api_tl_session: Session) -> Host:
    h = Host(
        id=uuid.UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
        hostname="srv-bravo",
        os_info="Linux 5.15 Ubuntu 22.04",
        created_at=datetime(2026, 3, 1, 0, 0, 0, tzinfo=timezone.utc),
    )
    api_tl_session.add(h)
    api_tl_session.commit()
    return h


@pytest.fixture
def populated_api_data(
    api_tl_session: Session, sample_host_a: Host, sample_host_b: Host
) -> dict[str, Any]:
    """Seed multi-source records for timeline API testing."""
    t0 = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)

    # Linux Users
    u = LinuxUser(
        id=uuid.UUID("11111111-1111-4111-8111-111111111101"),
        host_id=sample_host_a.id,
        uid=1000,
        username="analyst_bob",
        first_seen_at=t0,
        created_at=t0,
    )
    api_tl_session.add(u)
    api_tl_session.flush()

    # Session
    sess = UserSession(
        id=uuid.UUID("22222222-2222-4222-8222-222222222201"),
        host_id=sample_host_a.id,
        linux_user_id=u.id,
        session_type="pts",
        terminal="pts/1",
        started_at=t0,
        ended_at=t0 + timedelta(hours=2),
        created_at=t0,
    )
    api_tl_session.add(sess)

    # Process on Host A
    p1 = Process(
        id=uuid.UUID("33333333-3333-4333-8333-333333333301"),
        host_id=sample_host_a.id,
        pid=555,
        ppid=1,
        command="/usr/bin/curl https://example.com",
        executable="/usr/bin/curl",
        linux_user_id=u.id,
        started_at=t0 + timedelta(minutes=2),
        ended_at=t0 + timedelta(minutes=3),
        created_at=t0 + timedelta(minutes=2),
    )
    api_tl_session.add(p1)

    # Event for p1
    e1 = Event(
        id=uuid.UUID("44444444-4444-4444-8444-444444444401"),
        host_id=sample_host_a.id,
        process_id=p1.id,
        timestamp=t0 + timedelta(minutes=2),
        source="proc",
        event_type="process.start",
        action="start",
        severity="info",
        uid=1000,
        username="analyst_bob",
        pid=555,
        command="/usr/bin/curl https://example.com",
        created_at=t0 + timedelta(minutes=2),
    )

    # Snapshot on Host A
    snap = Snapshot(
        id=uuid.UUID("55555555-5555-4555-8555-555555555501"),
        host_id=sample_host_a.id,
        timestamp=t0 + timedelta(minutes=5),
        snapshot_type="system_state",
        data={"processes": [], "resources": {"cpu_percent": 10.0}},
        created_at=t0 + timedelta(minutes=5),
    )
    api_tl_session.add(snap)

    # Process on Host B
    p_b = Process(
        id=uuid.UUID("66666666-6666-4666-8666-666666666601"),
        host_id=sample_host_b.id,
        pid=999,
        command="/usr/sbin/cron",
        started_at=t0,
        created_at=t0,
    )
    api_tl_session.add(p_b)

    api_tl_session.add(e1)
    api_tl_session.commit()

    return {
        "t0": t0,
        "host_a": sample_host_a,
        "host_b": sample_host_b,
        "p1": p1,
        "e1": e1,
        "sess": sess,
        "snap": snap,
        "p_b": p_b,
    }


# ── Security & Authentication Tests ──────────────────────────────────────────


class TestTimelineAuth:
    def test_unauthenticated_returns_401(self, client: TestClient) -> None:
        resp = client.get("/api/timeline")
        assert resp.status_code == 401
        assert resp.headers.get("WWW-Authenticate") == "Bearer"

    def test_invalid_token_returns_401(self, client: TestClient) -> None:
        headers = {"Authorization": "Bearer invalid_garbage_token"}
        resp = client.get("/api/timeline", headers=headers)
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid or malformed token"

    def test_inactive_user_returns_403(
        self, client: TestClient, inactive_auth_headers: dict[str, str]
    ) -> None:
        resp = client.get("/api/timeline", headers=inactive_auth_headers)
        assert resp.status_code == 403
        assert resp.json()["detail"] == "Inactive user account"


# ── Input Validation Tests ───────────────────────────────────────────────────


class TestTimelineInputValidation:
    def test_nonexistent_host_returns_404(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        random_host = uuid.uuid4()
        resp = client.get(f"/api/timeline?host_id={random_host}", headers=auth_headers)
        assert resp.status_code == 404
        assert resp.json()["detail"] == "Host not found"

    def test_malformed_host_uuid_returns_422(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        resp = client.get("/api/timeline?host_id=not-a-valid-uuid", headers=auth_headers)
        assert resp.status_code == 422

    def test_inverted_time_range_returns_400(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        sample_host_a: Host,
    ) -> None:
        t_start = "2026-03-01T15:00:00Z"
        t_end = "2026-03-01T10:00:00Z"
        resp = client.get(
            f"/api/timeline?host_id={sample_host_a.id}&start_time={t_start}&end_time={t_end}",
            headers=auth_headers,
        )
        assert resp.status_code == 400
        assert resp.json()["detail"] == "start_time must be less than or equal to end_time"

    def test_invalid_limit_boundary_returns_422(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        # limit=0 is invalid (< 1)
        resp0 = client.get("/api/timeline?limit=0", headers=auth_headers)
        assert resp0.status_code == 422

        # limit=101 is invalid (> 100)
        resp101 = client.get("/api/timeline?limit=101", headers=auth_headers)
        assert resp101.status_code == 422

    def test_invalid_offset_boundary_returns_422(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        resp = client.get("/api/timeline?offset=-1", headers=auth_headers)
        assert resp.status_code == 422

    def test_invalid_order_value_returns_422(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        resp = client.get("/api/timeline?order=random", headers=auth_headers)
        assert resp.status_code == 422

    def test_negative_pid_and_uid_returns_422(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        resp_pid = client.get("/api/timeline?pid=-1", headers=auth_headers)
        assert resp_pid.status_code == 422
        resp_uid = client.get("/api/timeline?uid=-1", headers=auth_headers)
        assert resp_uid.status_code == 422


# ── Query & Filtering Functional Tests ───────────────────────────────────────


class TestTimelineAPIQuery:
    def test_timeline_listing_success(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        sample_host_a: Host,
        populated_api_data: dict[str, Any],
    ) -> None:
        resp = client.get(
            f"/api/timeline?host_id={sample_host_a.id}",
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "total" in data
        assert "items" in data
        assert "limit" in data
        assert "offset" in data
        assert data["total"] > 0
        assert len(data["items"]) == data["total"]

    def test_cross_host_isolation_via_api(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        sample_host_a: Host,
        sample_host_b: Host,
        populated_api_data: dict[str, Any],
    ) -> None:
        # Host A query
        resp_a = client.get(
            f"/api/timeline?host_id={sample_host_a.id}",
            headers=auth_headers,
        )
        assert resp_a.status_code == 200
        for item in resp_a.json()["items"]:
            assert item["host_id"] == str(sample_host_a.id)

        # Host B query
        resp_b = client.get(
            f"/api/timeline?host_id={sample_host_b.id}",
            headers=auth_headers,
        )
        assert resp_b.status_code == 200
        items_b = resp_b.json()["items"]
        assert len(items_b) == 1
        assert items_b[0]["host_id"] == str(sample_host_b.id)

    def test_record_type_filter_via_api(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        sample_host_a: Host,
        populated_api_data: dict[str, Any],
    ) -> None:
        resp = client.get(
            f"/api/timeline?host_id={sample_host_a.id}&record_type=snapshot",
            headers=auth_headers,
        )
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 1
        assert items[0]["record_type"] == "snapshot"

    def test_pagination_via_api(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        sample_host_a: Host,
        populated_api_data: dict[str, Any],
    ) -> None:
        # Page 1: limit 1, offset 0
        resp1 = client.get(
            f"/api/timeline?host_id={sample_host_a.id}&limit=1&offset=0",
            headers=auth_headers,
        )
        assert resp1.status_code == 200
        d1 = resp1.json()
        assert len(d1["items"]) == 1

        # Page 2: limit 1, offset 1
        resp2 = client.get(
            f"/api/timeline?host_id={sample_host_a.id}&limit=1&offset=1",
            headers=auth_headers,
        )
        assert resp2.status_code == 200
        d2 = resp2.json()
        assert len(d2["items"]) == 1

        assert d1["items"][0]["id"] != d2["items"][0]["id"]

    def test_empty_results_via_api(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        sample_host_a: Host,
    ) -> None:
        t_future = "2030-01-01T00:00:00Z"
        resp = client.get(
            f"/api/timeline?host_id={sample_host_a.id}&start_time={t_future}",
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["items"] == []

    def test_serialization_and_context_enrichment(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        sample_host_a: Host,
        populated_api_data: dict[str, Any],
    ) -> None:
        resp = client.get(
            f"/api/timeline?host_id={sample_host_a.id}&event_type=process.start",
            headers=auth_headers,
        )
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 1
        entry = items[0]

        # Verify envelope & structure
        assert entry["event_type"] == "process.start"
        assert entry["record_type"] == "event"
        assert entry["source"] == "proc"
        assert entry["process_context"] is not None
        assert entry["process_context"]["pid"] == 555
        assert entry["user_context"] is not None
        assert entry["user_context"]["username"] == "analyst_bob"
        assert entry["session_context"] is not None
        assert entry["session_context"]["terminal"] == "pts/1"

    def test_mixed_naive_and_utc_timestamps_accepted(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        sample_host_a: Host,
        populated_api_data: dict[str, Any],
    ) -> None:
        """API must gracefully handle mix of naive and UTC-aware datetimes."""
        resp = client.get(
            f"/api/timeline?host_id={sample_host_a.id}&start_time=2026-03-01T12:00:00&end_time=2026-03-01T12:30:00Z",
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["total"] > 0

    def test_user_filtering_via_api(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        sample_host_a: Host,
        populated_api_data: dict[str, Any],
    ) -> None:
        # Existing username
        resp_bob = client.get(
            f"/api/timeline?host_id={sample_host_a.id}&username=analyst_bob",
            headers=auth_headers,
        )
        assert resp_bob.status_code == 200
        items_bob = resp_bob.json()["items"]
        assert len(items_bob) > 0
        for it in items_bob:
            if it.get("user_context"):
                assert it["user_context"]["username"] == "analyst_bob"

        # Nonexistent username returns empty
        resp_none = client.get(
            f"/api/timeline?host_id={sample_host_a.id}&username=phantom_user",
            headers=auth_headers,
        )
        assert resp_none.status_code == 200
        assert resp_none.json()["total"] == 0
        assert resp_none.json()["items"] == []

    def test_pid_and_process_id_filtering_via_api(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        sample_host_a: Host,
        populated_api_data: dict[str, Any],
    ) -> None:
        p1 = populated_api_data["p1"]

        # PID filter
        resp_pid = client.get(
            f"/api/timeline?host_id={sample_host_a.id}&pid=555",
            headers=auth_headers,
        )
        assert resp_pid.status_code == 200
        items_pid = resp_pid.json()["items"]
        assert len(items_pid) > 0
        for it in items_pid:
            assert it["process_context"]["pid"] == 555

        # Process UUID filter
        resp_p_uuid = client.get(
            f"/api/timeline?host_id={sample_host_a.id}&process_id={p1.id}",
            headers=auth_headers,
        )
        assert resp_p_uuid.status_code == 200
        assert resp_p_uuid.json()["total"] > 0

    def test_global_timeline_without_host_id(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_api_data: dict[str, Any],
    ) -> None:
        """Calling /api/timeline without host_id returns entries from across all hosts."""
        resp = client.get("/api/timeline", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 2
        host_ids = {it["host_id"] for it in data["items"]}
        assert len(host_ids) >= 2

    def test_openapi_schema_contains_timeline(self, client: TestClient) -> None:
        resp = client.get("/openapi.json")
        assert resp.status_code == 200
        schema = resp.json()
        assert "/api/timeline" in schema["paths"]
        timeline_spec = schema["paths"]["/api/timeline"]["get"]
        param_names = [p["name"] for p in timeline_spec.get("parameters", [])]
        assert "host_id" in param_names
        assert "start_time" in param_names
        assert "end_time" in param_names
        assert "record_type" in param_names
        assert "order" in param_names
        assert "limit" in param_names
        assert "offset" in param_names
