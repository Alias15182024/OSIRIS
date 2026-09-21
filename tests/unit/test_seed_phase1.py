"""Unit tests for Phase 1 database seeding (database.seeds.seed_phase1).

Verifies that seed_phase1 correctly inserts initial records with a valid
PBKDF2-HMAC-SHA256 password hash for the development admin user, and that
re-running seed() is idempotent.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from backend.api.security import verify_password
from backend.db.base import Base
from backend.db.models.app_user import AppUser
from backend.db.models.file import File
from backend.db.models.host import Host
from backend.db.models.linux_user import LinuxUser
from backend.db.models.process import Process
from backend.db.models.resource_snapshot import ResourceSnapshot
import database.seeds.seed_phase1 as seed_module
from database.seeds.seed_phase1 import ADMIN_USER_ID, HOST_ID, seed


@pytest.fixture
def test_seed_session(monkeypatch: pytest.MonkeyPatch) -> Session:
    """Create an isolated in-memory SQLite database and monkeypatch SessionLocal."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    test_session_factory = sessionmaker(bind=engine)

    # Patch SessionLocal in the seed module so it operates in-memory
    monkeypatch.setattr(seed_module, "SessionLocal", test_session_factory)

    session = test_session_factory()
    yield session
    session.close()
    Base.metadata.drop_all(engine)
    engine.dispose()


def test_seed_creates_expected_records_and_authenticable_admin(
    test_seed_session: Session,
) -> None:
    """seed() should create all Phase 1 records with an authenticable admin user."""
    # Execute seeding
    seed()

    # Verify Host
    host = test_seed_session.execute(
        select(Host).where(Host.id == HOST_ID)
    ).scalar_one()
    assert host.hostname == "osiris-dev-vm"

    # Verify Linux Users
    linux_users = test_seed_session.execute(select(LinuxUser)).scalars().all()
    assert len(linux_users) == 3
    usernames = {u.username for u in linux_users}
    assert usernames == {"root", "student", "nobody"}

    # Verify Process, File, ResourceSnapshot
    proc = test_seed_session.execute(select(Process)).scalar_one()
    assert proc.command == "/sbin/init"

    file_entry = test_seed_session.execute(select(File)).scalar_one()
    assert file_entry.path == "/etc/passwd"

    snapshot = test_seed_session.execute(select(ResourceSnapshot)).scalar_one()
    assert snapshot.cpu_percent == 12.5

    # Verify Admin AppUser
    admin = test_seed_session.execute(
        select(AppUser).where(AppUser.id == ADMIN_USER_ID)
    ).scalar_one()
    assert admin.username == "admin"
    assert admin.display_name == "OSIRIS Administrator"
    assert admin.role == "admin"
    assert admin.is_active is True

    # Critical Phase 1.5 authentication compatibility check:
    # "changeme" must verify against the stored hash
    assert verify_password("changeme", admin.password_hash) is True
    assert verify_password("wrong_password", admin.password_hash) is False
    assert admin.password_hash.startswith("pbkdf2_sha256$")


def test_seed_is_idempotent(test_seed_session: Session) -> None:
    """Running seed() a second time should detect existing data and skip."""
    seed()

    # Call seed() again
    seed()

    # Ensure no duplicate records were inserted
    hosts = test_seed_session.execute(select(Host)).scalars().all()
    assert len(hosts) == 1
    users = test_seed_session.execute(select(AppUser)).scalars().all()
    assert len(users) == 1
