"""Unit tests for OSIRIS Phase 1.5 authentication routes (/api/auth/login, /api/auth/me).

Tests:
- Successful login returns HTTP 200, bearer token, and UserResponse.
- Incorrect password returns HTTP 401.
- Nonexistent username returns HTTP 401 (without username enumeration).
- Deactivated/inactive user returns HTTP 403.
- Successful login creates exactly one AppAuditLog entry with action="login",
  target_type="app_user", user_id, and client IP address.
- GET /api/auth/me with valid bearer token returns UserResponse.
- GET /api/auth/me without token returns HTTP 401.
- GET /api/auth/me with invalid token returns HTTP 401.
- GET /api/auth/me with inactive account returns HTTP 403.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from starlette.testclient import TestClient

from backend.api.deps import get_db
from backend.api.security import create_access_token, hash_password
from backend.db.base import Base
from backend.db.models.app_audit_log import AppAuditLog
from backend.db.models.app_user import AppUser
from backend.main import app


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture
def auth_db_session() -> Session:
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
def client(auth_db_session: Session) -> TestClient:
    """TestClient with get_db dependency overridden to use auth_db_session."""
    app.dependency_overrides[get_db] = lambda: auth_db_session
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def active_user(auth_db_session: Session) -> AppUser:
    """Create an active test user in the database."""
    now = utcnow()
    user = AppUser(
        id=uuid.uuid4(),
        username="alice_analyst",
        password_hash=hash_password("ValidPassword123!"),
        display_name="Alice Analyst",
        role="analyst",
        is_active=True,
        created_at=now,
    )
    auth_db_session.add(user)
    auth_db_session.commit()
    return user


@pytest.fixture
def inactive_user(auth_db_session: Session) -> AppUser:
    """Create an inactive test user in the database."""
    now = utcnow()
    user = AppUser(
        id=uuid.uuid4(),
        username="inactive_bob",
        password_hash=hash_password("BobSecretPassword123!"),
        display_name="Bob Inactive",
        role="viewer",
        is_active=False,
        created_at=now,
    )
    auth_db_session.add(user)
    auth_db_session.commit()
    return user


# ============================================================================
# POST /api/auth/login Tests
# ============================================================================


class TestLoginEndpoint:
    """Tests for POST /api/auth/login."""

    def test_login_success_returns_token_and_user(
        self,
        client: TestClient,
        auth_db_session: Session,
        active_user: AppUser,
    ) -> None:
        payload = {
            "username": "alice_analyst",
            "password": "ValidPassword123!",
        }
        resp = client.post("/api/auth/login", json=payload)

        assert resp.status_code == 200
        data = resp.json()

        # Token verification
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert len(data["access_token"].split(".")) == 3

        # User profile verification
        user_data = data["user"]
        assert user_data["id"] == str(active_user.id)
        assert user_data["username"] == "alice_analyst"
        assert user_data["display_name"] == "Alice Analyst"
        assert user_data["role"] == "analyst"
        assert user_data["is_active"] is True

        # Exactly one audit log entry created
        stmt = select(AppAuditLog).where(AppAuditLog.user_id == active_user.id)
        logs = auth_db_session.execute(stmt).scalars().all()
        assert len(logs) == 1
        log = logs[0]
        assert log.action == "login"
        assert log.target_type == "app_user"
        assert log.target_id == active_user.id
        assert log.ip_address is not None
        assert log.created_at is not None

    def test_login_incorrect_password_returns_401(
        self,
        client: TestClient,
        auth_db_session: Session,
        active_user: AppUser,
    ) -> None:
        payload = {
            "username": "alice_analyst",
            "password": "WrongPassword!",
        }
        resp = client.post("/api/auth/login", json=payload)

        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid username or password"
        assert resp.headers.get("WWW-Authenticate") == "Bearer"

        # No successful audit log created
        stmt = select(AppAuditLog).where(AppAuditLog.user_id == active_user.id)
        logs = auth_db_session.execute(stmt).scalars().all()
        assert len(logs) == 0

    def test_login_nonexistent_user_returns_401(
        self,
        client: TestClient,
    ) -> None:
        payload = {
            "username": "nonexistent_ghost",
            "password": "AnyPassword123!",
        }
        resp = client.post("/api/auth/login", json=payload)

        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid username or password"
        assert resp.headers.get("WWW-Authenticate") == "Bearer"

    def test_login_inactive_user_returns_403(
        self,
        client: TestClient,
        auth_db_session: Session,
        inactive_user: AppUser,
    ) -> None:
        payload = {
            "username": "inactive_bob",
            "password": "BobSecretPassword123!",
        }
        resp = client.post("/api/auth/login", json=payload)

        assert resp.status_code == 403
        assert resp.json()["detail"] == "Inactive user account"

        stmt = select(AppAuditLog).where(AppAuditLog.action == "login_failed")
        logs = auth_db_session.execute(stmt).scalars().all()
        assert len(logs) == 1
        log = logs[0]
        assert log.action == "login_failed"
        assert log.user_id is None
        assert log.target_type == "app_user"
        assert log.target_id == inactive_user.id
        assert log.ip_address == "testclient"
        assert log.details == {"attempted_username": "inactive_bob"}
        assert "BobSecretPassword123!" not in str(log.details)

    def test_login_inactive_user_audit_persistence_failure_returns_500(
        self,
        client: TestClient,
        auth_db_session: Session,
        inactive_user: AppUser,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        caplog.set_level(logging.DEBUG)
        sentinel_disk = "SENTINEL_INACTIVE_DISK_SECRET_KEY_999"
        payload = {
            "username": "inactive_bob",
            "password": "BobSecretPassword123!",
        }
        with patch.object(
            auth_db_session,
            "commit",
            side_effect=OperationalError(
                f"INSERT INTO app_audit_logs ... {sentinel_disk}",
                params={"secret": sentinel_disk},
                orig=Exception(f"Disk full: {sentinel_disk}"),
            ),
        ):
            resp = client.post("/api/auth/login", json=payload)

        assert resp.status_code == 500
        data = resp.json()
        assert data["detail"] == "Authentication service unavailable"
        assert sentinel_disk not in str(data)
        assert sentinel_disk not in caplog.text
        assert "Failed to persist login_failed audit log: [OperationalError]" in caplog.text

    def test_login_incorrect_password_records_failed_audit_log(
        self,
        client: TestClient,
        auth_db_session: Session,
        active_user: AppUser,
    ) -> None:
        payload = {
            "username": "alice_analyst",
            "password": "WrongPassword!",
        }
        resp = client.post("/api/auth/login", json=payload)

        assert resp.status_code == 401
        assert resp.headers.get("WWW-Authenticate") == "Bearer"

        # Verify login_failed audit log entry created before 401 was returned
        stmt = select(AppAuditLog).where(AppAuditLog.action == "login_failed")
        logs = auth_db_session.execute(stmt).scalars().all()
        assert len(logs) == 1
        log = logs[0]
        assert log.action == "login_failed"
        assert log.user_id is None
        assert log.target_type == "app_user"
        assert log.target_id == active_user.id
        assert log.ip_address == "testclient"
        assert log.details == {"attempted_username": "alice_analyst"}
        # Ensure password secret is never stored in details or anywhere in the record
        assert "WrongPassword!" not in str(log.details)

    def test_login_nonexistent_user_records_failed_audit_log(
        self,
        client: TestClient,
        auth_db_session: Session,
    ) -> None:
        payload = {
            "username": "nonexistent_ghost",
            "password": "AnyPassword123!",
        }
        resp = client.post("/api/auth/login", json=payload)

        assert resp.status_code == 401
        assert resp.headers.get("WWW-Authenticate") == "Bearer"

        # Verify anonymous login_failed audit log entry created
        stmt = select(AppAuditLog).where(AppAuditLog.action == "login_failed")
        logs = auth_db_session.execute(stmt).scalars().all()
        assert len(logs) == 1
        log = logs[0]
        assert log.action == "login_failed"
        assert log.user_id is None
        assert log.target_type == "app_user"
        assert log.target_id is None
        assert log.ip_address == "testclient"
        assert log.details == {"attempted_username": "nonexistent_ghost"}
        assert "AnyPassword123!" not in str(log.details)

    def test_login_failed_records_direct_client_ip_and_ignores_untrusted_forwarded_for(
        self,
        auth_db_session: Session,
        active_user: AppUser,
    ) -> None:
        """Verify direct connection IP is recorded and untrusted X-Forwarded-For is ignored."""
        app.dependency_overrides[get_db] = lambda: auth_db_session
        direct_ip = "198.51.100.99"
        try:
            with TestClient(app, client=(direct_ip, 54321)) as direct_client:
                resp = direct_client.post(
                    "/api/auth/login",
                    json={
                        "username": "alice_analyst",
                        "password": "WrongPassword!",
                    },
                    headers={"X-Forwarded-For": "203.0.113.195, 10.0.0.1"},
                )
        finally:
            app.dependency_overrides.clear()

        assert resp.status_code == 401
        stmt = select(AppAuditLog).where(AppAuditLog.action == "login_failed")
        logs = auth_db_session.execute(stmt).scalars().all()
        assert len(logs) == 1
        # Direct connection host is authoritative; client-forged X-Forwarded-For is ignored
        assert logs[0].ip_address == direct_ip

    def test_login_failed_audit_persistence_failure_returns_500(
        self,
        client: TestClient,
        auth_db_session: Session,
        active_user: AppUser,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        caplog.set_level(logging.DEBUG)
        sentinel_secret = "SENTINEL_DB_SECRET_DISK_FULL_PW"
        payload = {
            "username": "alice_analyst",
            "password": "WrongPassword!",
        }
        with patch.object(
            auth_db_session,
            "commit",
            side_effect=OperationalError(
                f"INSERT INTO app_audit_logs ... {sentinel_secret}",
                params={"secret": sentinel_secret},
                orig=Exception(f"Disk full: {sentinel_secret}"),
            ),
        ):
            resp = client.post("/api/auth/login", json=payload)

        assert resp.status_code == 500
        data = resp.json()
        assert data["detail"] == "Authentication service unavailable"
        assert sentinel_secret not in str(data)
        assert sentinel_secret not in caplog.text
        assert "Failed to persist login_failed audit log: [OperationalError]" in caplog.text

    def test_login_success_audit_persistence_failure_returns_500(
        self,
        client: TestClient,
        auth_db_session: Session,
        active_user: AppUser,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        caplog.set_level(logging.DEBUG)
        sentinel_uri = "SENTINEL_DB_URI_POSTGRES_PASS"
        payload = {
            "username": "alice_analyst",
            "password": "ValidPassword123!",
        }
        with patch.object(
            auth_db_session,
            "commit",
            side_effect=OperationalError(
                f"INSERT INTO app_audit_logs ... {sentinel_uri}",
                params={"token": "SENTINEL_BEARER_TOKEN"},
                orig=Exception(f"connection lost to {sentinel_uri}"),
            ),
        ):
            resp = client.post("/api/auth/login", json=payload)

        assert resp.status_code == 500
        data = resp.json()
        assert data["detail"] == "Authentication service unavailable"
        assert "access_token" not in data
        assert sentinel_uri not in str(data)
        assert "SENTINEL_BEARER_TOKEN" not in str(data)
        assert sentinel_uri not in caplog.text
        assert "SENTINEL_BEARER_TOKEN" not in caplog.text
        assert "Failed to persist login audit log: [OperationalError]" in caplog.text

    def test_login_database_lookup_failure_returns_500(
        self,
        client: TestClient,
        auth_db_session: Session,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        caplog.set_level(logging.DEBUG)
        sentinel_pass = "SENTINEL_SECRET_PASSWORD"
        sentinel_query = "SENTINEL_SELECT_SECRET_PARAM"
        payload = {
            "username": "alice_analyst",
            "password": "ValidPassword123!",
        }
        with patch.object(
            auth_db_session,
            "execute",
            side_effect=OperationalError(
                f"SELECT * FROM app_users WHERE username = '{sentinel_query}'",
                params={"pwd": sentinel_pass},
                orig=Exception(f"FATAL: password auth failed for user: {sentinel_pass}"),
            ),
        ):
            resp = client.post("/api/auth/login", json=payload)

        assert resp.status_code == 500
        data = resp.json()
        assert data["detail"] == "Authentication service unavailable"
        assert sentinel_pass not in str(data)
        assert sentinel_query not in str(data)
        assert sentinel_pass not in caplog.text
        assert sentinel_query not in caplog.text
        assert "Database query error during login user lookup: [OperationalError]" in caplog.text

    def test_login_inactive_user_with_incorrect_password_records_login_failed(
        self,
        client: TestClient,
        auth_db_session: Session,
        inactive_user: AppUser,
    ) -> None:
        payload = {
            "username": "inactive_bob",
            "password": "WrongPassword123!",
        }
        resp = client.post("/api/auth/login", json=payload)

        # 401 Unauthorized precedes 403 Forbidden on invalid credentials
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid username or password"

        stmt = select(AppAuditLog).where(AppAuditLog.action == "login_failed")
        logs = auth_db_session.execute(stmt).scalars().all()
        assert len(logs) == 1
        log = logs[0]
        assert log.action == "login_failed"
        assert log.target_id == inactive_user.id
        assert log.user_id is None

    def test_login_failed_with_overlong_direct_client_ip(
        self,
        auth_db_session: Session,
        active_user: AppUser,
    ) -> None:
        overlong_ip = "198.51.100.25" + "x" * 60
        app.dependency_overrides[get_db] = lambda: auth_db_session
        try:
            with TestClient(app, client=(overlong_ip, 54321)) as direct_client:
                resp = direct_client.post(
                    "/api/auth/login",
                    json={
                        "username": "alice_analyst",
                        "password": "WrongPassword!",
                    },
                )
        finally:
            app.dependency_overrides.clear()

        assert resp.status_code == 401
        stmt = select(AppAuditLog).where(AppAuditLog.action == "login_failed")
        logs = auth_db_session.execute(stmt).scalars().all()
        assert len(logs) == 1
        assert len(logs[0].ip_address) <= 45
        assert logs[0].ip_address == overlong_ip[:45]

    def test_login_failed_with_whitespace_direct_client_ip_stripped(
        self,
        auth_db_session: Session,
        active_user: AppUser,
    ) -> None:
        app.dependency_overrides[get_db] = lambda: auth_db_session
        try:
            with TestClient(app, client=("  192.0.2.77  ", 54321)) as direct_client:
                resp = direct_client.post(
                    "/api/auth/login",
                    json={
                        "username": "alice_analyst",
                        "password": "WrongPassword!",
                    },
                )
        finally:
            app.dependency_overrides.clear()

        assert resp.status_code == 401
        stmt = select(AppAuditLog).where(AppAuditLog.action == "login_failed")
        logs = auth_db_session.execute(stmt).scalars().all()
        assert len(logs) == 1
        assert logs[0].ip_address == "192.0.2.77"

    def test_login_failed_when_request_client_is_none(
        self,
        auth_db_session: Session,
        active_user: AppUser,
    ) -> None:
        from unittest.mock import PropertyMock
        from fastapi import Request

        app.dependency_overrides[get_db] = lambda: auth_db_session
        try:
            with patch.object(Request, "client", new_callable=PropertyMock, return_value=None):
                with TestClient(app) as test_client:
                    resp = test_client.post(
                        "/api/auth/login",
                        json={
                            "username": "alice_analyst",
                            "password": "WrongPassword!",
                        },
                    )
        finally:
            app.dependency_overrides.clear()

        assert resp.status_code == 401
        stmt = select(AppAuditLog).where(AppAuditLog.action == "login_failed")
        logs = auth_db_session.execute(stmt).scalars().all()
        assert len(logs) == 1
        assert logs[0].ip_address is None

    def test_login_failed_with_null_bytes_in_username(
        self,
        client: TestClient,
        auth_db_session: Session,
    ) -> None:
        payload = {
            "username": "ghost\x00_user",
            "password": "AnyPassword123!",
        }
        resp = client.post("/api/auth/login", json=payload)

        assert resp.status_code == 401
        stmt = select(AppAuditLog).where(AppAuditLog.action == "login_failed")
        logs = auth_db_session.execute(stmt).scalars().all()
        assert len(logs) == 1
        assert "\x00" not in logs[0].details["attempted_username"]
        assert logs[0].details == {"attempted_username": "ghost_user"}

    def test_login_failed_database_rollback_failure_still_returns_500(
        self,
        client: TestClient,
        auth_db_session: Session,
        active_user: AppUser,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        caplog.set_level(logging.DEBUG)
        sentinel_commit = "SENTINEL_AUDIT_COMMIT_FAIL_SECRET"
        sentinel_rollback = "SENTINEL_AUDIT_ROLLBACK_FAIL_SECRET"
        payload = {
            "username": "alice_analyst",
            "password": "WrongPassword!",
        }
        with patch.object(
            auth_db_session,
            "commit",
            side_effect=OperationalError(
                "INSERT INTO app_audit_logs",
                params={"secret": sentinel_commit},
                orig=Exception(f"commit failed: {sentinel_commit}"),
            ),
        ):
            with patch.object(
                auth_db_session,
                "rollback",
                side_effect=OperationalError(
                    "ROLLBACK",
                    params={"secret": sentinel_rollback},
                    orig=Exception(f"rollback failed: {sentinel_rollback}"),
                ),
            ):
                resp = client.post("/api/auth/login", json=payload)

        assert resp.status_code == 500
        assert resp.json()["detail"] == "Authentication service unavailable"
        assert sentinel_commit not in resp.text
        assert sentinel_rollback not in resp.text
        assert sentinel_commit not in caplog.text
        assert sentinel_rollback not in caplog.text
        audit_err_msg = "Failed to persist login_failed audit log: [OperationalError]"
        rollback_err_msg = "Database rollback failed after login_failed audit error: [OperationalError]"
        assert audit_err_msg in caplog.text
        assert rollback_err_msg in caplog.text
        assert caplog.text.index(audit_err_msg) < caplog.text.index(rollback_err_msg)

    def test_login_inactive_user_database_rollback_failure_still_returns_500(
        self,
        client: TestClient,
        auth_db_session: Session,
        inactive_user: AppUser,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        caplog.set_level(logging.DEBUG)
        sentinel_commit = "SENTINEL_INACTIVE_AUDIT_COMMIT_SECRET"
        sentinel_rollback = "SENTINEL_INACTIVE_AUDIT_ROLLBACK_SECRET"
        payload = {
            "username": "inactive_bob",
            "password": "BobSecretPassword123!",
        }
        with patch.object(
            auth_db_session,
            "commit",
            side_effect=OperationalError(
                "INSERT INTO app_audit_logs",
                params={"secret": sentinel_commit},
                orig=Exception(f"commit failed: {sentinel_commit}"),
            ),
        ):
            with patch.object(
                auth_db_session,
                "rollback",
                side_effect=OperationalError(
                    "ROLLBACK",
                    params={"secret": sentinel_rollback},
                    orig=Exception(f"rollback failed: {sentinel_rollback}"),
                ),
            ):
                resp = client.post("/api/auth/login", json=payload)

        assert resp.status_code == 500
        assert resp.json()["detail"] == "Authentication service unavailable"
        assert sentinel_commit not in resp.text
        assert sentinel_rollback not in resp.text
        assert sentinel_commit not in caplog.text
        assert sentinel_rollback not in caplog.text
        audit_err_msg = "Failed to persist login_failed audit log: [OperationalError]"
        rollback_err_msg = "Database rollback failed after login_failed audit error: [OperationalError]"
        assert audit_err_msg in caplog.text
        assert rollback_err_msg in caplog.text
        assert caplog.text.index(audit_err_msg) < caplog.text.index(rollback_err_msg)

    def test_login_user_lookup_database_rollback_failure_still_returns_500(
        self,
        client: TestClient,
        auth_db_session: Session,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        caplog.set_level(logging.DEBUG)
        sentinel_lookup = "SENTINEL_LOOKUP_QUERY_SECRET"
        sentinel_rollback = "SENTINEL_LOOKUP_ROLLBACK_SECRET"
        payload = {
            "username": "alice_analyst",
            "password": "ValidPassword123!",
        }
        with patch.object(
            auth_db_session,
            "execute",
            side_effect=OperationalError(
                "SELECT * FROM app_users",
                params={"secret": sentinel_lookup},
                orig=Exception(f"query failed: {sentinel_lookup}"),
            ),
        ):
            with patch.object(
                auth_db_session,
                "rollback",
                side_effect=OperationalError(
                    "ROLLBACK",
                    params={"secret": sentinel_rollback},
                    orig=Exception(f"rollback failed: {sentinel_rollback}"),
                ),
            ):
                resp = client.post("/api/auth/login", json=payload)

        assert resp.status_code == 500
        assert resp.json()["detail"] == "Authentication service unavailable"
        assert sentinel_lookup not in resp.text
        assert sentinel_rollback not in resp.text
        assert sentinel_lookup not in caplog.text
        assert sentinel_rollback not in caplog.text
        lookup_err_msg = "Database query error during login user lookup: [OperationalError]"
        rollback_err_msg = "Database rollback failed after user lookup error: [OperationalError]"
        assert lookup_err_msg in caplog.text
        assert rollback_err_msg in caplog.text
        assert caplog.text.index(lookup_err_msg) < caplog.text.index(rollback_err_msg)

    def test_login_success_database_rollback_failure_still_returns_500(
        self,
        client: TestClient,
        auth_db_session: Session,
        active_user: AppUser,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        caplog.set_level(logging.DEBUG)
        sentinel_commit = "SENTINEL_SUCCESS_AUDIT_COMMIT_SECRET"
        sentinel_rollback = "SENTINEL_SUCCESS_AUDIT_ROLLBACK_SECRET"
        payload = {
            "username": "alice_analyst",
            "password": "ValidPassword123!",
        }
        with patch.object(
            auth_db_session,
            "commit",
            side_effect=OperationalError(
                "INSERT INTO app_audit_logs",
                params={"secret": sentinel_commit},
                orig=Exception(f"commit failed: {sentinel_commit}"),
            ),
        ):
            with patch.object(
                auth_db_session,
                "rollback",
                side_effect=OperationalError(
                    "ROLLBACK",
                    params={"secret": sentinel_rollback},
                    orig=Exception(f"rollback failed: {sentinel_rollback}"),
                ),
            ):
                resp = client.post("/api/auth/login", json=payload)

        assert resp.status_code == 500
        data = resp.json()
        assert data["detail"] == "Authentication service unavailable"
        assert "access_token" not in data
        assert sentinel_commit not in resp.text
        assert sentinel_rollback not in resp.text
        assert sentinel_commit not in caplog.text
        assert sentinel_rollback not in caplog.text
        audit_err_msg = "Failed to persist login audit log: [OperationalError]"
        rollback_err_msg = "Database rollback failed after login audit error: [OperationalError]"
        assert audit_err_msg in caplog.text
        assert rollback_err_msg in caplog.text
        assert caplog.text.index(audit_err_msg) < caplog.text.index(rollback_err_msg)


# ============================================================================
# GET /api/auth/me Tests
# ============================================================================


class TestAuthMeEndpoint:
    """Tests for GET /api/auth/me."""

    def test_auth_me_valid_token_returns_user_profile(
        self,
        client: TestClient,
        active_user: AppUser,
    ) -> None:
        token = create_access_token(
            user_id=active_user.id,
            username=active_user.username,
            role=active_user.role,
        )
        resp = client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == str(active_user.id)
        assert data["username"] == "alice_analyst"
        assert data["display_name"] == "Alice Analyst"
        assert data["role"] == "analyst"
        assert data["is_active"] is True

    def test_auth_me_missing_token_returns_401(
        self,
        client: TestClient,
    ) -> None:
        resp = client.get("/api/auth/me")
        assert resp.status_code == 401
        assert resp.headers.get("WWW-Authenticate") == "Bearer"

    def test_auth_me_invalid_token_returns_401(
        self,
        client: TestClient,
    ) -> None:
        resp = client.get(
            "/api/auth/me",
            headers={"Authorization": "Bearer bad.token.here"},
        )
        assert resp.status_code == 401
        assert resp.headers.get("WWW-Authenticate") == "Bearer"

    def test_auth_me_inactive_user_returns_403(
        self,
        client: TestClient,
        inactive_user: AppUser,
    ) -> None:
        token = create_access_token(
            user_id=inactive_user.id,
            username=inactive_user.username,
        )
        resp = client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403
        assert resp.json()["detail"] == "Inactive user account"
