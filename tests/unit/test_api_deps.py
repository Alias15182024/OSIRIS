"""Unit tests for OSIRIS Phase 1.5 FastAPI dependencies (get_db, get_current_user).

Tests:
- get_db() session lifecycle: yields active session and closes it in finally.
- get_current_user() bearer token authentication:
  - Valid token resolves correct active AppUser.
  - Missing Authorization header -> 401 with WWW-Authenticate: Bearer.
  - Malformed/non-bearer Authorization header -> 401 with WWW-Authenticate: Bearer.
  - Tampered/invalid token -> 401 with WWW-Authenticate: Bearer.
  - Expired token -> 401 with WWW-Authenticate: Bearer.
  - Token for nonexistent user UUID -> 401 with WWW-Authenticate: Bearer.
  - Deactivated (inactive) user -> 403 Forbidden.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from starlette.testclient import TestClient

from backend.api.deps import get_current_user, get_db
from backend.api.security import create_access_token
from backend.db.base import Base
from backend.db.models.app_user import AppUser


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ============================================================================
# get_db Tests
# ============================================================================


class TestGetDbDependency:
    """Tests for database session dependency lifecycle."""

    def test_get_db_yields_session_and_closes_it(self) -> None:
        gen = get_db()
        session = next(gen)

        assert isinstance(session, Session)

        # Verify close is called when generator completes
        with patch.object(session, "close", wraps=session.close) as mock_close:
            with pytest.raises(StopIteration):
                next(gen)
            mock_close.assert_called_once()


# ============================================================================
# get_current_user Direct Tests
# ============================================================================


class TestGetCurrentUserDirect:
    """Direct unit tests for get_current_user logic without HTTP server."""

    def test_valid_credentials_returns_user(
        self,
        db_session: Session,
        sample_app_user: AppUser,
    ) -> None:
        token = create_access_token(
            user_id=sample_app_user.id,
            username=sample_app_user.username,
            role=sample_app_user.role,
        )
        auth = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

        user = get_current_user(auth=auth, db=db_session)
        assert user.id == sample_app_user.id
        assert user.username == sample_app_user.username

    def test_missing_auth_raises_401(self, db_session: Session) -> None:
        with pytest.raises(HTTPException) as exc_info:
            get_current_user(auth=None, db=db_session)

        assert exc_info.value.status_code == 401
        assert exc_info.value.headers.get("WWW-Authenticate") == "Bearer"

    def test_wrong_scheme_raises_401(self, db_session: Session) -> None:
        auth = HTTPAuthorizationCredentials(scheme="Basic", credentials="dGVzdA==")
        with pytest.raises(HTTPException) as exc_info:
            get_current_user(auth=auth, db=db_session)

        assert exc_info.value.status_code == 401
        assert exc_info.value.headers.get("WWW-Authenticate") == "Bearer"

    def test_empty_token_raises_401(self, db_session: Session) -> None:
        auth = HTTPAuthorizationCredentials(scheme="Bearer", credentials="")
        with pytest.raises(HTTPException) as exc_info:
            get_current_user(auth=auth, db=db_session)

        assert exc_info.value.status_code == 401

    def test_expired_token_raises_401(
        self,
        db_session: Session,
        sample_app_user: AppUser,
    ) -> None:
        expired_token = create_access_token(
            user_id=sample_app_user.id,
            username=sample_app_user.username,
            expires_delta=timedelta(seconds=-10),
        )
        auth = HTTPAuthorizationCredentials(scheme="Bearer", credentials=expired_token)

        with pytest.raises(HTTPException) as exc_info:
            get_current_user(auth=auth, db=db_session)

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Token has expired"
        assert exc_info.value.headers.get("WWW-Authenticate") == "Bearer"

    def test_tampered_token_raises_401(self, db_session: Session) -> None:
        auth = HTTPAuthorizationCredentials(scheme="Bearer", credentials="bad.token.signature")
        with pytest.raises(HTTPException) as exc_info:
            get_current_user(auth=auth, db=db_session)

        assert exc_info.value.status_code == 401
        assert exc_info.value.headers.get("WWW-Authenticate") == "Bearer"

    def test_nonexistent_user_raises_401(self, db_session: Session) -> None:
        ghost_id = uuid.uuid4()
        token = create_access_token(user_id=ghost_id, username="ghost")
        auth = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

        with pytest.raises(HTTPException) as exc_info:
            get_current_user(auth=auth, db=db_session)

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "User not found"

    def test_inactive_user_raises_403(self, db_session: Session) -> None:
        inactive_user = AppUser(
            id=uuid.uuid4(),
            username="deactivated_user",
            password_hash="hash",
            is_active=False,
            role="viewer",
            created_at=utcnow(),
        )
        db_session.add(inactive_user)
        db_session.flush()

        token = create_access_token(
            user_id=inactive_user.id,
            username=inactive_user.username,
        )
        auth = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

        with pytest.raises(HTTPException) as exc_info:
            get_current_user(auth=auth, db=db_session)

        assert exc_info.value.status_code == 403
        assert exc_info.value.detail == "Inactive user account"


# ============================================================================
# get_current_user HTTP Integration Tests
# ============================================================================


class TestGetCurrentUserViaHttp:
    """HTTP integration tests for get_current_user in a FastAPI route."""

    @pytest.fixture
    def http_db_session(self) -> Session:
        """Dedicated multi-thread compatible SQLite session for TestClient."""
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
    def test_client(self, http_db_session: Session) -> TestClient:
        app = FastAPI()

        @app.get("/api/test-me")
        def protected_route(user: AppUser = Depends(get_current_user)) -> dict:
            return {"user_id": str(user.id), "username": user.username}

        app.dependency_overrides[get_db] = lambda: http_db_session
        return TestClient(app)

    def test_http_valid_bearer_token(
        self,
        test_client: TestClient,
        http_db_session: Session,
    ) -> None:
        user = AppUser(
            id=uuid.uuid4(),
            username="http_user",
            password_hash="hash",
            is_active=True,
            role="viewer",
            created_at=utcnow(),
        )
        http_db_session.add(user)
        http_db_session.commit()

        token = create_access_token(
            user_id=user.id,
            username=user.username,
        )
        resp = test_client.get(
            "/api/test-me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["user_id"] == str(user.id)
        assert data["username"] == user.username

    def test_http_missing_authorization_header(self, test_client: TestClient) -> None:
        resp = test_client.get("/api/test-me")
        assert resp.status_code == 401
        assert resp.headers.get("WWW-Authenticate") == "Bearer"

    def test_http_malformed_non_bearer_header(self, test_client: TestClient) -> None:
        resp = test_client.get(
            "/api/test-me",
            headers={"Authorization": "Basic dXNlcjpwYXNz"},
        )
        assert resp.status_code == 401
        assert resp.headers.get("WWW-Authenticate") == "Bearer"

    def test_http_invalid_token(self, test_client: TestClient) -> None:
        resp = test_client.get(
            "/api/test-me",
            headers={"Authorization": "Bearer not.a.valid.token"},
        )
        assert resp.status_code == 401
        assert resp.headers.get("WWW-Authenticate") == "Bearer"

    def test_http_expired_token(
        self,
        test_client: TestClient,
        http_db_session: Session,
    ) -> None:
        user = AppUser(
            id=uuid.uuid4(),
            username="expired_user",
            password_hash="hash",
            is_active=True,
            role="viewer",
            created_at=utcnow(),
        )
        http_db_session.add(user)
        http_db_session.commit()

        expired_token = create_access_token(
            user_id=user.id,
            username=user.username,
            expires_delta=timedelta(seconds=-60),
        )
        resp = test_client.get(
            "/api/test-me",
            headers={"Authorization": f"Bearer {expired_token}"},
        )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Token has expired"
        assert resp.headers.get("WWW-Authenticate") == "Bearer"

    def test_http_nonexistent_user(self, test_client: TestClient) -> None:
        ghost_id = uuid.uuid4()
        token = create_access_token(user_id=ghost_id, username="ghost")
        resp = test_client.get(
            "/api/test-me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "User not found"
        assert resp.headers.get("WWW-Authenticate") == "Bearer"

    def test_http_inactive_user(
        self,
        test_client: TestClient,
        http_db_session: Session,
    ) -> None:
        inactive_user = AppUser(
            id=uuid.uuid4(),
            username="inactive_bob",
            password_hash="hash",
            is_active=False,
            role="viewer",
            created_at=utcnow(),
        )
        http_db_session.add(inactive_user)
        http_db_session.commit()

        token = create_access_token(
            user_id=inactive_user.id,
            username=inactive_user.username,
        )
        resp = test_client.get(
            "/api/test-me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403
        assert resp.json()["detail"] == "Inactive user account"
