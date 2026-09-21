"""Unit tests for OSIRIS Phase 1.5 File API routes (/api/files).

Tests:
- Authentication enforcement (401 when unauthenticated).
- Empty result returns 200 with total=0.
- Paginated listing with limit and offset.
- Filtering by host_id, exact file_type, and path prefix.
- Path prefix matching behavior:
  - "/tmp" matches "/tmp", "/tmp/file.txt", and "/tmp/sub/file.txt"
  - "/tmp" does not match "/tmp2/file.txt"
  - SQL wildcards ('%', '_') in path query are safely escaped and not treated as wildcards
  - Paths are queried verbatim without normalization or symlink resolution
- Combined filters.
- Deterministic ordering (first_seen_at ASC, id ASC).
- Input validation (malformed host_id -> 422, limit < 1 -> 422, offset < 0 -> 422).
- Data correctness: nullable inode, file_type, last_seen_at, datetime serialization.
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
from backend.db.models.file import File
from backend.db.models.host import Host
from backend.main import app


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture
def files_db_session() -> Session:
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
def client(files_db_session: Session) -> TestClient:
    """TestClient with get_db dependency overridden to use files_db_session."""
    app.dependency_overrides[get_db] = lambda: files_db_session
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def auth_user(files_db_session: Session) -> AppUser:
    """Create an active application user and return it."""
    user = AppUser(
        id=uuid.uuid4(),
        username="files_analyst",
        password_hash="pbkdf2_sha256$...",
        role="analyst",
        is_active=True,
        created_at=utcnow(),
    )
    files_db_session.add(user)
    files_db_session.commit()
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
def sample_host(files_db_session: Session) -> Host:
    """Create a sample monitored host in the database."""
    host = Host(
        id=uuid.uuid4(),
        hostname="monitored-server-04",
        os_info="Linux 5.15 Ubuntu",
        ip_address="192.168.1.103",
        created_at=utcnow(),
    )
    files_db_session.add(host)
    files_db_session.commit()
    return host


@pytest.fixture
def populated_files(
    files_db_session: Session,
    sample_host: Host,
) -> list[File]:
    """Create a deterministic series of realistic file records."""
    t0 = datetime(2026, 3, 1, 9, 0, 0, tzinfo=timezone.utc)

    # File 0: /tmp directory
    f0 = File(
        id=uuid.UUID("11111111-1111-4111-8111-111111111111"),
        host_id=sample_host.id,
        path="/tmp",
        inode=10001,
        file_type="directory",
        first_seen_at=t0,
        last_seen_at=t0 + timedelta(hours=1),
        created_at=t0,
    )

    # File 1: /tmp/file.txt
    f1 = File(
        id=uuid.UUID("22222222-2222-4222-8222-222222222222"),
        host_id=sample_host.id,
        path="/tmp/file.txt",
        inode=10002,
        file_type="file",
        first_seen_at=t0 + timedelta(minutes=1),
        last_seen_at=t0 + timedelta(minutes=5),
        created_at=t0 + timedelta(minutes=1),
    )

    # File 2: /tmp/sub/file.txt
    f2 = File(
        id=uuid.UUID("33333333-3333-4333-8333-333333333333"),
        host_id=sample_host.id,
        path="/tmp/sub/file.txt",
        inode=10003,
        file_type="file",
        first_seen_at=t0 + timedelta(minutes=2),
        last_seen_at=None,
        created_at=t0 + timedelta(minutes=2),
    )

    # File 3: /tmp2/file.txt (MUST NOT match prefix /tmp)
    f3 = File(
        id=uuid.UUID("44444444-4444-4444-8444-444444444444"),
        host_id=sample_host.id,
        path="/tmp2/file.txt",
        inode=10004,
        file_type="file",
        first_seen_at=t0 + timedelta(minutes=3),
        last_seen_at=None,
        created_at=t0 + timedelta(minutes=3),
    )

    # File 4: File with special SQL wildcard characters in name: /var/log/app_100%/trace.log
    f4 = File(
        id=uuid.UUID("55555555-5555-4555-8555-555555555555"),
        host_id=sample_host.id,
        path="/var/log/app_100%/trace.log",
        inode=None,
        file_type=None,
        first_seen_at=t0 + timedelta(minutes=4),
        last_seen_at=None,
        created_at=t0 + timedelta(minutes=4),
    )

    # File 5: Similar path that WOULD match unescaped wildcard: /var/log/appX100Y/trace.log
    f5 = File(
        id=uuid.UUID("66666666-6666-4666-8666-666666666666"),
        host_id=sample_host.id,
        path="/var/log/appX100Y/trace.log",
        inode=20002,
        file_type="file",
        first_seen_at=t0 + timedelta(minutes=5),
        last_seen_at=None,
        created_at=t0 + timedelta(minutes=5),
    )

    files_db_session.add_all([f0, f1, f2, f3, f4, f5])
    files_db_session.commit()
    return [f0, f1, f2, f3, f4, f5]


# ============================================================================
# Authentication Enforcement Tests
# ============================================================================


class TestFilesAuthEnforcement:
    """Tests authentication requirement on file endpoint."""

    def test_list_files_unauthenticated_returns_401(self, client: TestClient) -> None:
        resp = client.get("/api/files")
        assert resp.status_code == 401
        assert resp.headers.get("WWW-Authenticate") == "Bearer"


# ============================================================================
# GET /api/files Tests
# ============================================================================


class TestListFilesEndpoint:
    """Tests for GET /api/files listing, pagination, and path prefix filtering."""

    def test_list_files_empty_returns_200(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
    ) -> None:
        resp = client.get("/api/files", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["items"] == []
        assert data["limit"] == 50
        assert data["offset"] == 0

    def test_list_files_pagination(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_files: list[File],
    ) -> None:
        resp = client.get("/api/files?limit=3&offset=0", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 6
        assert len(data["items"]) == 3
        assert data["limit"] == 3
        assert data["offset"] == 0
        assert data["items"][0]["id"] == str(populated_files[0].id)
        assert data["items"][1]["id"] == str(populated_files[1].id)
        assert data["items"][2]["id"] == str(populated_files[2].id)

        resp2 = client.get("/api/files?limit=3&offset=3", headers=auth_headers)
        assert resp2.status_code == 200
        data2 = resp2.json()
        assert data2["total"] == 6
        assert len(data2["items"]) == 3
        assert data2["items"][0]["id"] == str(populated_files[3].id)

    def test_filter_by_host_id(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        sample_host: Host,
        populated_files: list[File],
    ) -> None:
        resp = client.get(f"/api/files?host_id={sample_host.id}", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 6

        other_host_id = uuid.uuid4()
        resp2 = client.get(f"/api/files?host_id={other_host_id}", headers=auth_headers)
        assert resp2.status_code == 200
        assert resp2.json()["total"] == 0

    def test_filter_by_exact_file_type(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_files: list[File],
    ) -> None:
        resp = client.get("/api/files?file_type=directory", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["path"] == "/tmp"
        assert data["items"][0]["file_type"] == "directory"

    def test_path_prefix_matching(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_files: list[File],
    ) -> None:
        # /tmp must match /tmp, /tmp/file.txt, and /tmp/sub/file.txt
        # /tmp MUST NOT match /tmp2/file.txt
        resp = client.get("/api/files?path=/tmp", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 3
        paths = [item["path"] for item in data["items"]]
        assert "/tmp" in paths
        assert "/tmp/file.txt" in paths
        assert "/tmp/sub/file.txt" in paths
        assert "/tmp2/file.txt" not in paths

    def test_path_prefix_with_trailing_slash(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_files: list[File],
    ) -> None:
        resp = client.get("/api/files?path=/tmp/", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        paths = [item["path"] for item in data["items"]]
        assert "/tmp/file.txt" in paths
        assert "/tmp/sub/file.txt" in paths
        assert "/tmp2/file.txt" not in paths

    def test_path_sql_wildcards_escaped(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_files: list[File],
    ) -> None:
        # Query path with literal '%' and '_': /var/log/app_100%
        # Must match only /var/log/app_100%/trace.log and NOT /var/log/appX100Y/trace.log
        resp = client.get("/api/files?path=/var/log/app_100%", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["path"] == "/var/log/app_100%/trace.log"

    def test_combined_filters(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        sample_host: Host,
        populated_files: list[File],
    ) -> None:
        resp = client.get(
            f"/api/files?host_id={sample_host.id}&path=/tmp&file_type=file",
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        for item in data["items"]:
            assert item["file_type"] == "file"
            assert item["path"].startswith("/tmp/")

    def test_deterministic_ordering(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_files: list[File],
    ) -> None:
        resp = client.get("/api/files?limit=10", headers=auth_headers)
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 6
        # Ordered by first_seen_at ASC, id ASC
        for i in range(6):
            assert items[i]["id"] == str(populated_files[i].id)


# ============================================================================
# Validation & Data Correctness Tests
# ============================================================================


class TestFilesValidationAndDataCorrectness:
    """Tests query parameter validation and nullable field serialization."""

    def test_malformed_host_id_returns_422(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
    ) -> None:
        resp = client.get("/api/files?host_id=invalid-uuid", headers=auth_headers)
        assert resp.status_code == 422

    def test_invalid_limit_returns_422(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
    ) -> None:
        resp = client.get("/api/files?limit=0", headers=auth_headers)
        assert resp.status_code == 422

    def test_limit_above_maximum_returns_422(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
    ) -> None:
        resp = client.get("/api/files?limit=101", headers=auth_headers)
        assert resp.status_code == 422

    def test_invalid_file_type_returns_422(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
    ) -> None:
        resp1 = client.get("/api/files?file_type=invalid_type", headers=auth_headers)
        assert resp1.status_code == 422
        resp2 = client.get("/api/files?file_type=symlink", headers=auth_headers)
        assert resp2.status_code == 422

    def test_valid_file_types_accepted(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
    ) -> None:
        resp_file = client.get("/api/files?file_type=file", headers=auth_headers)
        assert resp_file.status_code == 200
        resp_dir = client.get("/api/files?file_type=directory", headers=auth_headers)
        assert resp_dir.status_code == 200


    def test_invalid_offset_returns_422(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
    ) -> None:
        resp = client.get("/api/files?offset=-1", headers=auth_headers)
        assert resp.status_code == 422

    def test_nullable_fields_preserved(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        populated_files: list[File],
    ) -> None:
        resp = client.get("/api/files?path=/var/log/app_100%", headers=auth_headers)
        assert resp.status_code == 200
        item = resp.json()["items"][0]

        assert item["inode"] is None
        assert item["file_type"] is None
        assert item["last_seen_at"] is None
        assert item["first_seen_at"] is not None
        assert item["created_at"] is not None
