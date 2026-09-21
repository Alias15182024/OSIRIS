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

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, select
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
        inactive_user: AppUser,
    ) -> None:
        payload = {
            "username": "inactive_bob",
            "password": "BobSecretPassword123!",
        }
        resp = client.post("/api/auth/login", json=payload)

        assert resp.status_code == 403
        assert resp.json()["detail"] == "Inactive user account"


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
