from __future__ import annotations

"""Shared pytest fixtures for OSIRIS database tests.

Uses a dedicated test database (SQLite in-memory for unit tests, or a
PostgreSQL test database for integration tests controlled by environment).

The test database is created fresh for each test session and torn down after.
"""

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker

from backend.db.base import Base

# Import all models so they register with Base.metadata
import backend.db.models  # noqa: F401
from backend.db.models.host import Host
from backend.db.models.linux_user import LinuxUser
from backend.db.models.process import Process
from backend.db.models.app_user import AppUser


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# Fixed UUIDs for reproducible test fixtures
TEST_HOST_ID = uuid.UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
TEST_ROOT_USER_ID = uuid.UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbb01")
TEST_REGULAR_USER_ID = uuid.UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbb02")
TEST_PROCESS_ID = uuid.UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
TEST_APP_USER_ID = uuid.UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")


@pytest.fixture(scope="session")
def db_engine():
    """Create a test database engine.

    Uses SQLite in-memory for fast unit tests. For full PostgreSQL
    integration tests, set OSIRIS_TEST_DATABASE_URL in the environment.
    """
    import os

    test_url = os.environ.get("OSIRIS_TEST_DATABASE_URL")
    if test_url:
        eng = create_engine(test_url, echo=False)
    else:
        eng = create_engine("sqlite:///:memory:", echo=False)
        # Enable foreign key enforcement in SQLite
        @event.listens_for(eng, "connect")
        def set_sqlite_pragma(dbapi_conn, connection_record):  # type: ignore[no-untyped-def]
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    # Create all tables
    Base.metadata.create_all(eng)

    yield eng

    # Cleanup
    Base.metadata.drop_all(eng)
    eng.dispose()


@pytest.fixture(scope="function")
def db_session(db_engine):
    """Provide a transactional database session for a test.

    Each test runs in a transaction that is rolled back after the test,
    ensuring test isolation.
    """
    connection = db_engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection)

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def sample_host(db_session: Session) -> Host:
    """Create and return a sample host."""
    now = utcnow()
    host = Host(
        id=TEST_HOST_ID,
        hostname="test-host",
        os_info="Ubuntu 22.04",
        ip_address="10.0.0.1",
        created_at=now,
    )
    db_session.add(host)
    db_session.flush()
    return host


@pytest.fixture
def sample_linux_users(db_session: Session, sample_host: Host) -> dict:
    """Create and return sample Linux users keyed by name."""
    now = utcnow()
    root = LinuxUser(
        id=TEST_ROOT_USER_ID,
        host_id=sample_host.id,
        uid=0,
        username="root",
        first_seen_at=now,
        created_at=now,
    )
    student = LinuxUser(
        id=TEST_REGULAR_USER_ID,
        host_id=sample_host.id,
        uid=1000,
        username="student",
        first_seen_at=now,
        created_at=now,
    )
    db_session.add_all([root, student])
    db_session.flush()
    return {"root": root, "student": student}


@pytest.fixture
def sample_process(
    db_session: Session,
    sample_host: Host,
    sample_linux_users: dict,
) -> Process:
    """Create and return a sample process."""
    now = utcnow()
    proc = Process(
        id=TEST_PROCESS_ID,
        host_id=sample_host.id,
        pid=1,
        ppid=0,
        command="/sbin/init",
        executable="/sbin/init",
        linux_user_id=sample_linux_users["root"].id,
        started_at=now,
        created_at=now,
    )
    db_session.add(proc)
    db_session.flush()
    return proc


@pytest.fixture
def sample_app_user(db_session: Session) -> AppUser:
    """Create and return a sample application user."""
    now = utcnow()
    user = AppUser(
        id=TEST_APP_USER_ID,
        username="testadmin",
        password_hash="$2b$12$TEST_HASH_NOT_REAL",
        display_name="Test Admin",
        role="admin",
        is_active=True,
        created_at=now,
    )
    db_session.add(user)
    db_session.flush()
    return user


@pytest.fixture
def sample_event() -> dict:
    """Provide a minimal sample event for testing."""
    return {
        "event_id": "test-0001",
        "host_id": "test-host",
        "timestamp": "2026-01-01T00:00:00Z",
        "source": "test",
        "event_type": "test.sample",
        "action": "test",
        "severity": "info",
    }
