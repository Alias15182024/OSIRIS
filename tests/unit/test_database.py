from __future__ import annotations

"""Phase 1 database schema tests for OSIRIS.

Tests cover:
  - Table creation
  - NOT NULL constraints
  - Foreign key integrity
  - Unique constraints
  - Check constraints
  - Relationships
  - Seed data loading
"""

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.db.base import Base
from backend.db.models.app_audit_log import AppAuditLog
from backend.db.models.app_user import AppUser
from backend.db.models.event import Event
from backend.db.models.file import File
from backend.db.models.host import Host
from backend.db.models.linux_user import LinuxUser
from backend.db.models.process import Process
from backend.db.models.resource_snapshot import ResourceSnapshot


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ========================================================================
# TABLE CREATION TESTS
# ========================================================================


class TestTableCreation:
    """Verify all Phase 1 tables exist."""

    def test_all_tables_created(self, db_engine):  # type: ignore[no-untyped-def]
        """All 8 Phase 1 tables must be present."""
        inspector = inspect(db_engine)
        tables = set(inspector.get_table_names())
        expected = {
            "hosts",
            "linux_users",
            "processes",
            "files",
            "resource_snapshots",
            "events",
            "app_users",
            "app_audit_log",
        }
        assert expected.issubset(tables), (
            f"Missing tables: {expected - tables}"
        )


# ========================================================================
# HOST TESTS
# ========================================================================


class TestHost:
    """Tests for the hosts table."""

    def test_create_host(self, db_session: Session) -> None:
        host = Host(
            hostname="test-server",
            os_info="Debian 12",
            ip_address="10.0.0.5",
            created_at=utcnow(),
        )
        db_session.add(host)
        db_session.flush()
        assert host.id is not None
        assert host.hostname == "test-server"

    def test_host_hostname_required(self, db_session: Session) -> None:
        host = Host(
            hostname=None,  # type: ignore[arg-type]
            created_at=utcnow(),
        )
        db_session.add(host)
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_host_created_at_required(self, db_session: Session) -> None:
        host = Host(hostname="test")
        db_session.add(host)
        # Should succeed with default
        db_session.flush()
        assert host.created_at is not None


# ========================================================================
# LINUX USER TESTS
# ========================================================================


class TestLinuxUser:
    """Tests for the linux_users table."""

    def test_create_linux_user(
        self, db_session: Session, sample_host: Host
    ) -> None:
        user = LinuxUser(
            host_id=sample_host.id,
            uid=1001,
            username="testuser",
            first_seen_at=utcnow(),
            created_at=utcnow(),
        )
        db_session.add(user)
        db_session.flush()
        assert user.id is not None

    def test_host_id_required(self, db_session: Session) -> None:
        user = LinuxUser(
            host_id=None,  # type: ignore[arg-type]
            uid=1001,
            first_seen_at=utcnow(),
            created_at=utcnow(),
        )
        db_session.add(user)
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_uid_required(
        self, db_session: Session, sample_host: Host
    ) -> None:
        user = LinuxUser(
            host_id=sample_host.id,
            uid=None,  # type: ignore[arg-type]
            first_seen_at=utcnow(),
            created_at=utcnow(),
        )
        db_session.add(user)
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_unique_host_uid(
        self, db_session: Session, sample_host: Host
    ) -> None:
        """UNIQUE(host_id, uid) must be enforced."""
        now = utcnow()
        user1 = LinuxUser(
            host_id=sample_host.id,
            uid=9999,
            username="user1",
            first_seen_at=now,
            created_at=now,
        )
        user2 = LinuxUser(
            host_id=sample_host.id,
            uid=9999,  # Duplicate uid on same host
            username="user2",
            first_seen_at=now,
            created_at=now,
        )
        db_session.add(user1)
        db_session.flush()
        db_session.add(user2)
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_same_uid_different_hosts(self, db_session: Session) -> None:
        """Same UID on different hosts is allowed."""
        now = utcnow()
        host1 = Host(hostname="host1", created_at=now)
        host2 = Host(hostname="host2", created_at=now)
        db_session.add_all([host1, host2])
        db_session.flush()

        user1 = LinuxUser(
            host_id=host1.id,
            uid=1000,
            first_seen_at=now,
            created_at=now,
        )
        user2 = LinuxUser(
            host_id=host2.id,
            uid=1000,  # Same UID, different host
            first_seen_at=now,
            created_at=now,
        )
        db_session.add_all([user1, user2])
        db_session.flush()
        assert user1.id != user2.id

    def test_username_is_optional(
        self, db_session: Session, sample_host: Host
    ) -> None:
        user = LinuxUser(
            host_id=sample_host.id,
            uid=65534,
            username=None,
            first_seen_at=utcnow(),
            created_at=utcnow(),
        )
        db_session.add(user)
        db_session.flush()
        assert user.username is None

    def test_foreign_key_host(self, db_session: Session) -> None:
        """host_id must reference a valid host."""
        fake_host_id = uuid.uuid4()
        user = LinuxUser(
            host_id=fake_host_id,
            uid=1001,
            first_seen_at=utcnow(),
            created_at=utcnow(),
        )
        db_session.add(user)
        with pytest.raises(IntegrityError):
            db_session.flush()


# ========================================================================
# PROCESS TESTS
# ========================================================================


class TestProcess:
    """Tests for the processes table."""

    def test_create_process(
        self, db_session: Session, sample_host: Host
    ) -> None:
        proc = Process(
            host_id=sample_host.id,
            pid=100,
            ppid=1,
            command="/usr/bin/test",
            started_at=utcnow(),
            created_at=utcnow(),
        )
        db_session.add(proc)
        db_session.flush()
        assert proc.id is not None

    def test_command_required(
        self, db_session: Session, sample_host: Host
    ) -> None:
        proc = Process(
            host_id=sample_host.id,
            pid=100,
            command=None,  # type: ignore[arg-type]
            started_at=utcnow(),
            created_at=utcnow(),
        )
        db_session.add(proc)
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_linux_user_relationship(
        self, db_session: Session, sample_host: Host, sample_linux_users: dict
    ) -> None:
        proc = Process(
            host_id=sample_host.id,
            pid=200,
            command="/bin/bash",
            linux_user_id=sample_linux_users["root"].id,
            started_at=utcnow(),
            created_at=utcnow(),
        )
        db_session.add(proc)
        db_session.flush()
        assert proc.linux_user is not None
        assert proc.linux_user.uid == 0

    def test_process_without_user(
        self, db_session: Session, sample_host: Host
    ) -> None:
        proc = Process(
            host_id=sample_host.id,
            pid=300,
            command="[kthread]",
            linux_user_id=None,
            started_at=utcnow(),
            created_at=utcnow(),
        )
        db_session.add(proc)
        db_session.flush()
        assert proc.linux_user_id is None


# ========================================================================
# FILE TESTS
# ========================================================================


class TestFile:
    """Tests for the files table."""

    def test_create_file(
        self, db_session: Session, sample_host: Host
    ) -> None:
        f = File(
            host_id=sample_host.id,
            path="/etc/shadow",
            file_type="regular",
            first_seen_at=utcnow(),
            created_at=utcnow(),
        )
        db_session.add(f)
        db_session.flush()
        assert f.id is not None

    def test_path_required(
        self, db_session: Session, sample_host: Host
    ) -> None:
        f = File(
            host_id=sample_host.id,
            path=None,  # type: ignore[arg-type]
            first_seen_at=utcnow(),
            created_at=utcnow(),
        )
        db_session.add(f)
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_path_not_globally_unique(
        self, db_session: Session, sample_host: Host
    ) -> None:
        """Same path can appear multiple times (deleted and recreated)."""
        now = utcnow()
        f1 = File(
            host_id=sample_host.id,
            path="/tmp/test.txt",
            first_seen_at=now,
            created_at=now,
        )
        f2 = File(
            host_id=sample_host.id,
            path="/tmp/test.txt",
            first_seen_at=now,
            created_at=now,
        )
        db_session.add_all([f1, f2])
        db_session.flush()
        assert f1.id != f2.id


# ========================================================================
# RESOURCE SNAPSHOT TESTS
# ========================================================================


class TestResourceSnapshot:
    """Tests for the resource_snapshots table."""

    def test_create_snapshot(
        self, db_session: Session, sample_host: Host
    ) -> None:
        snap = ResourceSnapshot(
            host_id=sample_host.id,
            timestamp=utcnow(),
            cpu_percent=25.5,
            memory_total=8_589_934_592,
            memory_used=4_294_967_296,
            memory_percent=50.0,
            created_at=utcnow(),
        )
        db_session.add(snap)
        db_session.flush()
        assert snap.id is not None

    def test_nullable_metrics(
        self, db_session: Session, sample_host: Host
    ) -> None:
        """All metric fields are nullable."""
        snap = ResourceSnapshot(
            host_id=sample_host.id,
            timestamp=utcnow(),
            created_at=utcnow(),
        )
        db_session.add(snap)
        db_session.flush()
        assert snap.cpu_percent is None
        assert snap.memory_total is None

    @pytest.mark.skipif(
        True,  # Only run on PostgreSQL (CHECK constraints not enforced in SQLite)
        reason="CHECK constraints require PostgreSQL",
    )
    def test_negative_cpu_percent_rejected(
        self, db_session: Session, sample_host: Host
    ) -> None:
        snap = ResourceSnapshot(
            host_id=sample_host.id,
            timestamp=utcnow(),
            cpu_percent=-1.0,
            created_at=utcnow(),
        )
        db_session.add(snap)
        with pytest.raises(IntegrityError):
            db_session.flush()


# ========================================================================
# EVENT TESTS
# ========================================================================


class TestEvent:
    """Tests for the events table."""

    def test_create_event(
        self, db_session: Session, sample_host: Host
    ) -> None:
        ev = Event(
            host_id=sample_host.id,
            timestamp=utcnow(),
            ingested_at=utcnow(),
            source="proc",
            event_type="process.start",
            action="start",
            severity="info",
            pid=1234,
            command="/usr/bin/test",
            created_at=utcnow(),
        )
        db_session.add(ev)
        db_session.flush()
        assert ev.id is not None

    def test_event_with_process_reference(
        self,
        db_session: Session,
        sample_host: Host,
        sample_process: Process,
    ) -> None:
        """Events can reference a valid process via process_id."""
        ev = Event(
            host_id=sample_host.id,
            process_id=sample_process.id,
            timestamp=utcnow(),
            ingested_at=utcnow(),
            source="proc",
            event_type="process.start",
            action="start",
            severity="info",
            created_at=utcnow(),
        )
        db_session.add(ev)
        db_session.flush()
        assert ev.process_id == sample_process.id
        assert ev.process is not None

    def test_event_without_process(
        self, db_session: Session, sample_host: Host
    ) -> None:
        """Events can exist without a process_id."""
        ev = Event(
            host_id=sample_host.id,
            process_id=None,
            timestamp=utcnow(),
            ingested_at=utcnow(),
            source="resource",
            event_type="resource.cpu",
            action="snapshot",
            severity="info",
            created_at=utcnow(),
        )
        db_session.add(ev)
        db_session.flush()
        assert ev.process_id is None

    def test_event_invalid_process_id_rejected(
        self, db_session: Session, sample_host: Host
    ) -> None:
        """Invalid process_id must be rejected by FK constraint."""
        fake_process_id = uuid.uuid4()
        ev = Event(
            host_id=sample_host.id,
            process_id=fake_process_id,
            timestamp=utcnow(),
            ingested_at=utcnow(),
            source="proc",
            event_type="process.start",
            action="start",
            severity="info",
            created_at=utcnow(),
        )
        db_session.add(ev)
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_event_host_id_required(self, db_session: Session) -> None:
        ev = Event(
            host_id=None,  # type: ignore[arg-type]
            timestamp=utcnow(),
            ingested_at=utcnow(),
            source="test",
            event_type="test.sample",
            action="test",
            severity="info",
            created_at=utcnow(),
        )
        db_session.add(ev)
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_event_source_required(
        self, db_session: Session, sample_host: Host
    ) -> None:
        ev = Event(
            host_id=sample_host.id,
            timestamp=utcnow(),
            ingested_at=utcnow(),
            source=None,  # type: ignore[arg-type]
            event_type="test.sample",
            action="test",
            severity="info",
            created_at=utcnow(),
        )
        db_session.add(ev)
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_event_payload_jsonb(
        self, db_session: Session, sample_host: Host
    ) -> None:
        payload = {
            "raw_cpu": {"user": 50, "system": 25, "idle": 25},
            "source_version": "1.0",
        }
        ev = Event(
            host_id=sample_host.id,
            timestamp=utcnow(),
            ingested_at=utcnow(),
            source="resource",
            event_type="resource.cpu",
            action="snapshot",
            severity="info",
            payload=payload,
            created_at=utcnow(),
        )
        db_session.add(ev)
        db_session.flush()
        assert ev.payload == payload

    def test_event_default_severity(
        self, db_session: Session, sample_host: Host
    ) -> None:
        ev = Event(
            host_id=sample_host.id,
            timestamp=utcnow(),
            ingested_at=utcnow(),
            source="test",
            event_type="test.sample",
            action="test",
            created_at=utcnow(),
        )
        db_session.add(ev)
        db_session.flush()
        assert ev.severity == "info"


# ========================================================================
# APPLICATION USER TESTS
# ========================================================================


class TestAppUser:
    """Tests for the app_users table."""

    def test_create_app_user(self, db_session: Session) -> None:
        user = AppUser(
            username="viewer1",
            password_hash="$2b$12$HASH",
            role="viewer",
            created_at=utcnow(),
        )
        db_session.add(user)
        db_session.flush()
        assert user.id is not None
        assert user.is_active is True

    def test_username_unique(self, db_session: Session) -> None:
        """app_users.username must be unique."""
        now = utcnow()
        user1 = AppUser(
            username="duplicate",
            password_hash="$2b$12$HASH1",
            created_at=now,
        )
        user2 = AppUser(
            username="duplicate",
            password_hash="$2b$12$HASH2",
            created_at=now,
        )
        db_session.add(user1)
        db_session.flush()
        db_session.add(user2)
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_password_hash_required(self, db_session: Session) -> None:
        user = AppUser(
            username="nopassword",
            password_hash=None,  # type: ignore[arg-type]
            created_at=utcnow(),
        )
        db_session.add(user)
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_default_role(self, db_session: Session) -> None:
        user = AppUser(
            username="default_role_user",
            password_hash="$2b$12$HASH",
            created_at=utcnow(),
        )
        db_session.add(user)
        db_session.flush()
        assert user.role == "viewer"


# ========================================================================
# APPLICATION AUDIT LOG TESTS
# ========================================================================


class TestAppAuditLog:
    """Tests for the app_audit_log table."""

    def test_create_audit_log(
        self, db_session: Session, sample_app_user: AppUser
    ) -> None:
        log = AppAuditLog(
            user_id=sample_app_user.id,
            action="login",
            ip_address="127.0.0.1",
            created_at=utcnow(),
        )
        db_session.add(log)
        db_session.flush()
        assert log.id is not None

    def test_audit_log_without_user(self, db_session: Session) -> None:
        """Audit log entries can exist without a user (system actions)."""
        log = AppAuditLog(
            user_id=None,
            action="system.startup",
            created_at=utcnow(),
        )
        db_session.add(log)
        db_session.flush()
        assert log.user_id is None

    def test_audit_log_with_details(
        self, db_session: Session, sample_app_user: AppUser
    ) -> None:
        log = AppAuditLog(
            user_id=sample_app_user.id,
            action="config.update",
            target_type="host",
            target_id=uuid.uuid4(),
            details={"field": "hostname", "old": "old-name", "new": "new-name"},
            created_at=utcnow(),
        )
        db_session.add(log)
        db_session.flush()
        assert log.details["field"] == "hostname"


# ========================================================================
# RELATIONSHIP TESTS
# ========================================================================


class TestRelationships:
    """Tests for Phase 1 entity relationships."""

    def test_host_has_many_linux_users(
        self, db_session: Session, sample_host: Host, sample_linux_users: dict
    ) -> None:
        db_session.refresh(sample_host)
        assert len(sample_host.linux_users) == 2

    def test_host_has_many_processes(
        self,
        db_session: Session,
        sample_host: Host,
        sample_process: Process,
    ) -> None:
        db_session.refresh(sample_host)
        assert len(sample_host.processes) >= 1

    def test_host_has_many_events(
        self, db_session: Session, sample_host: Host
    ) -> None:
        now = utcnow()
        ev1 = Event(
            host_id=sample_host.id,
            timestamp=now,
            ingested_at=now,
            source="test",
            event_type="test.1",
            action="test",
            severity="info",
            created_at=now,
        )
        ev2 = Event(
            host_id=sample_host.id,
            timestamp=now,
            ingested_at=now,
            source="test",
            event_type="test.2",
            action="test",
            severity="info",
            created_at=now,
        )
        db_session.add_all([ev1, ev2])
        db_session.flush()
        db_session.refresh(sample_host)
        assert len(sample_host.events) == 2

    def test_process_has_many_events(
        self,
        db_session: Session,
        sample_host: Host,
        sample_process: Process,
    ) -> None:
        now = utcnow()
        ev = Event(
            host_id=sample_host.id,
            process_id=sample_process.id,
            timestamp=now,
            ingested_at=now,
            source="proc",
            event_type="process.start",
            action="start",
            severity="info",
            created_at=now,
        )
        db_session.add(ev)
        db_session.flush()
        db_session.refresh(sample_process)
        assert len(sample_process.events) >= 1

    def test_linux_user_has_many_processes(
        self,
        db_session: Session,
        sample_host: Host,
        sample_linux_users: dict,
    ) -> None:
        root = sample_linux_users["root"]
        now = utcnow()
        p1 = Process(
            host_id=sample_host.id,
            pid=500,
            command="/bin/sh",
            linux_user_id=root.id,
            started_at=now,
            created_at=now,
        )
        p2 = Process(
            host_id=sample_host.id,
            pid=501,
            command="/bin/ls",
            linux_user_id=root.id,
            started_at=now,
            created_at=now,
        )
        db_session.add_all([p1, p2])
        db_session.flush()
        db_session.refresh(root)
        assert len(root.processes) >= 2

    def test_app_user_has_many_audit_logs(
        self, db_session: Session, sample_app_user: AppUser
    ) -> None:
        now = utcnow()
        log1 = AppAuditLog(
            user_id=sample_app_user.id,
            action="login",
            created_at=now,
        )
        log2 = AppAuditLog(
            user_id=sample_app_user.id,
            action="logout",
            created_at=now,
        )
        db_session.add_all([log1, log2])
        db_session.flush()
        db_session.refresh(sample_app_user)
        assert len(sample_app_user.audit_logs) == 2
