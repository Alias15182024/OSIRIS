"""Integration tests for authentication audit logging against local PostgreSQL (osiris_dev).

Verifies that AppAuditLog instances for successful and failed logins are
persisted to PostgreSQL with genuine JSONB, foreign keys, and indexes.
Ensures tests roll back cleanly without altering persistent development records.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Generator

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session
from starlette.testclient import TestClient

from backend.api.deps import get_db
from backend.api.security import hash_password
from backend.config import settings
from backend.db.models.app_audit_log import AppAuditLog
from backend.db.models.app_user import AppUser
from backend.main import app

DIRECT_TEST_CLIENT_IP = "192.0.2.100"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture(scope="module")
def pg_engine():
    """Engine connected to the PostgreSQL development database."""
    engine = create_engine(settings.database_url, echo=False)
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:
        pytest.skip(f"PostgreSQL not accessible at {settings.database_url}: {exc}")
    yield engine
    engine.dispose()


@pytest.fixture
def pg_session(pg_engine) -> Generator[Session, None, None]:
    """Transactional session against PostgreSQL using savepoints.

    Runs within a transaction that is rolled back after the test so
    the database records remain unaltered.
    """
    connection = pg_engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection, join_transaction_mode="create_savepoint")

    yield session

    session.close()
    if transaction.is_active:
        transaction.rollback()
    connection.close()


@pytest.fixture
def pg_client(pg_session: Session) -> Generator[TestClient, None, None]:
    """TestClient wired to the transactional PostgreSQL session with fixed client IP."""
    app.dependency_overrides[get_db] = lambda: pg_session
    with TestClient(app, client=(DIRECT_TEST_CLIENT_IP, 54321)) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def pg_test_user(pg_session: Session) -> AppUser:
    """Create a temporary test user within the transactional PostgreSQL session."""
    user = AppUser(
        id=uuid.uuid4(),
        username=f"pg_test_{uuid.uuid4().hex[:8]}",
        password_hash=hash_password("IntegrationSecret123!"),
        display_name="PG Integration User",
        role="analyst",
        is_active=True,
        created_at=utcnow(),
    )
    pg_session.add(user)
    pg_session.flush()
    return user


class TestPostgresAuthAuditPersistence:
    """Integration tests for auth audit persistence against real PostgreSQL."""

    def test_pg_login_failed_persisted_to_app_audit_log(
        self,
        pg_client: TestClient,
        pg_session: Session,
        pg_test_user: AppUser,
    ) -> None:
        """Verify failed login persists to PostgreSQL with direct connection IP, ignoring forged XFF."""
        payload = {
            "username": pg_test_user.username,
            "password": "WrongPasswordForPG!",
        }
        resp = pg_client.post(
            "/api/auth/login",
            json=payload,
            headers={"X-Forwarded-For": "203.0.113.195"},
        )

        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid username or password"

        stmt = select(AppAuditLog).where(
            AppAuditLog.action == "login_failed",
            AppAuditLog.target_id == pg_test_user.id,
        )
        log = pg_session.execute(stmt).scalar_one_or_none()
        assert log is not None
        assert log.action == "login_failed"
        assert log.user_id is None
        assert log.target_type == "app_user"
        assert log.target_id == pg_test_user.id
        # Authoritative direct connection IP is used; forged XFF header is ignored
        assert log.ip_address == DIRECT_TEST_CLIENT_IP
        assert log.details == {"attempted_username": pg_test_user.username}
        assert isinstance(log.created_at, datetime)

    def test_pg_login_failed_nonexistent_user_persisted(
        self,
        pg_client: TestClient,
        pg_session: Session,
    ) -> None:
        ghost_username = f"ghost_{uuid.uuid4().hex[:8]}"
        payload = {
            "username": ghost_username,
            "password": "AnyPassword123!",
        }
        resp = pg_client.post(
            "/api/auth/login",
            json=payload,
            headers={"X-Forwarded-For": "203.0.113.195"},
        )

        assert resp.status_code == 401

        stmt = select(AppAuditLog).where(
            AppAuditLog.action == "login_failed",
            AppAuditLog.target_id.is_(None),
        )
        logs = pg_session.execute(stmt).scalars().all()
        matching = [l for l in logs if l.details and l.details.get("attempted_username") == ghost_username]
        assert len(matching) == 1
        log = matching[0]
        assert log.action == "login_failed"
        assert log.user_id is None
        assert log.target_type == "app_user"
        assert log.target_id is None
        assert log.ip_address == DIRECT_TEST_CLIENT_IP

    def test_pg_login_inactive_user_persisted_to_app_audit_log(
        self,
        pg_client: TestClient,
        pg_session: Session,
    ) -> None:
        """Verify inactive user submitting correct password is audited and returns 403."""
        inactive_username = f"pg_inactive_{uuid.uuid4().hex[:8]}"
        inactive_user = AppUser(
            id=uuid.uuid4(),
            username=inactive_username,
            password_hash=hash_password("InactiveSecret123!"),
            display_name="PG Inactive User",
            role="viewer",
            is_active=False,
            created_at=utcnow(),
        )
        pg_session.add(inactive_user)
        pg_session.flush()

        resp = pg_client.post(
            "/api/auth/login",
            json={
                "username": inactive_username,
                "password": "InactiveSecret123!",
            },
        )

        assert resp.status_code == 403
        assert resp.json()["detail"] == "Inactive user account"

        stmt = select(AppAuditLog).where(
            AppAuditLog.action == "login_failed",
            AppAuditLog.target_id == inactive_user.id,
        )
        log = pg_session.execute(stmt).scalar_one_or_none()
        assert log is not None
        assert log.action == "login_failed"
        assert log.user_id is None
        assert log.target_type == "app_user"
        assert log.target_id == inactive_user.id
        assert log.ip_address == DIRECT_TEST_CLIENT_IP
        assert log.details == {"attempted_username": inactive_username}
        assert "InactiveSecret123!" not in str(log.details)

    def test_pg_login_success_persisted_to_app_audit_log(
        self,
        pg_client: TestClient,
        pg_session: Session,
        pg_test_user: AppUser,
    ) -> None:
        payload = {
            "username": pg_test_user.username,
            "password": "IntegrationSecret123!",
        }
        resp = pg_client.post(
            "/api/auth/login",
            json=payload,
            headers={"X-Forwarded-For": "203.0.113.195"},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data

        stmt = select(AppAuditLog).where(
            AppAuditLog.action == "login",
            AppAuditLog.user_id == pg_test_user.id,
        )
        log = pg_session.execute(stmt).scalar_one_or_none()
        assert log is not None
        assert log.action == "login"
        assert log.user_id == pg_test_user.id
        assert log.target_type == "app_user"
        assert log.target_id == pg_test_user.id
        assert log.ip_address == DIRECT_TEST_CLIENT_IP

    def test_pg_login_failed_overlong_ip_persisted_without_truncation_error(
        self,
        pg_session: Session,
        pg_test_user: AppUser,
    ) -> None:
        overlong_ip = "192.0.2.40" + "x" * 60
        app.dependency_overrides[get_db] = lambda: pg_session
        try:
            with TestClient(app, client=(overlong_ip, 54321)) as custom_client:
                resp = custom_client.post(
                    "/api/auth/login",
                    json={
                        "username": pg_test_user.username,
                        "password": "WrongPasswordForPG!",
                    },
                )
        finally:
            app.dependency_overrides.clear()

        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid username or password"

        stmt = select(AppAuditLog).where(
            AppAuditLog.action == "login_failed",
            AppAuditLog.target_id == pg_test_user.id,
        )
        logs = pg_session.execute(stmt).scalars().all()
        matching = [l for l in logs if l.ip_address == overlong_ip[:45]]
        assert len(matching) == 1
        log = matching[0]
        assert len(log.ip_address) <= 45
        assert log.ip_address == overlong_ip[:45]

    def test_pg_login_failed_with_null_byte_in_username(
        self,
        pg_client: TestClient,
        pg_session: Session,
    ) -> None:
        ghost_username = f"ghost_\x00_{uuid.uuid4().hex[:8]}"
        expected_cleaned = ghost_username.replace("\x00", "")
        payload = {
            "username": ghost_username,
            "password": "AnyPassword123!",
        }
        resp = pg_client.post(
            "/api/auth/login",
            json=payload,
            headers={"X-Forwarded-For": "203.0.113.195"},
        )

        assert resp.status_code == 401
        stmt = select(AppAuditLog).where(
            AppAuditLog.action == "login_failed",
            AppAuditLog.target_id.is_(None),
        )
        logs = pg_session.execute(stmt).scalars().all()
        matching = [l for l in logs if l.details and l.details.get("attempted_username") == expected_cleaned]
        assert len(matching) == 1
        log = matching[0]
        assert log.details == {"attempted_username": expected_cleaned}
