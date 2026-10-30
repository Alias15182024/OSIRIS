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
from backend.db.models.snapshot import Snapshot
from backend.db.models.user_session import UserSession


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

    def test_phase2_tables_created(self, db_engine):  # type: ignore[no-untyped-def]
        """Phase 2 Milestone 2.1 tables must be present."""
        inspector = inspect(db_engine)
        tables = set(inspector.get_table_names())
        expected = {"snapshots", "sessions"}
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

    def test_create_file_canonical_types(
        self, db_session: Session, sample_host: Host
    ) -> None:
        """Verify files table persists canonical types ('file', 'directory', 'symlink') and preserves legacy values."""
        now = utcnow()
        f_file = File(
            host_id=sample_host.id,
            path="/bin/ls",
            file_type="file",
            first_seen_at=now,
            created_at=now,
        )
        f_dir = File(
            host_id=sample_host.id,
            path="/usr/local",
            file_type="directory",
            first_seen_at=now,
            created_at=now,
        )
        f_sym_file = File(
            host_id=sample_host.id,
            path="/bin/sh",
            file_type="symlink",
            first_seen_at=now,
            created_at=now,
        )
        f_sym_dir = File(
            host_id=sample_host.id,
            path="/var/run",
            file_type="symlink",
            first_seen_at=now,
            created_at=now,
        )
        f_legacy = File(
            host_id=sample_host.id,
            path="/etc/passwd.old",
            file_type="regular",
            first_seen_at=now,
            created_at=now,
        )
        db_session.add_all([f_file, f_dir, f_sym_file, f_sym_dir, f_legacy])
        db_session.flush()
        assert f_file.id is not None
        assert f_dir.id is not None
        assert f_sym_file.id is not None
        assert f_sym_dir.id is not None
        assert f_legacy.id is not None
        assert f_file.file_type == "file"
        assert f_dir.file_type == "directory"
        assert f_sym_file.file_type == "symlink"
        assert f_sym_dir.file_type == "symlink"
        assert f_legacy.file_type == "regular"

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

    def test_host_has_many_snapshots(
        self, db_session: Session, sample_host: Host
    ) -> None:
        now = utcnow()
        s1 = Snapshot(
            host_id=sample_host.id,
            timestamp=now,
            snapshot_type="system",
            data={"test": 1},
            created_at=now,
        )
        s2 = Snapshot(
            host_id=sample_host.id,
            timestamp=now,
            snapshot_type="process",
            data={"test": 2},
            created_at=now,
        )
        db_session.add_all([s1, s2])
        db_session.flush()
        db_session.refresh(sample_host)
        assert len(sample_host.snapshots) == 2
        assert s1.host is sample_host

    def test_host_has_many_sessions(
        self,
        db_session: Session,
        sample_host: Host,
        sample_linux_users: dict,
    ) -> None:
        root = sample_linux_users["root"]
        now = utcnow()
        sess1 = UserSession(
            host_id=sample_host.id,
            linux_user_id=root.id,
            session_type="tty",
            terminal="tty1",
            started_at=now,
            created_at=now,
        )
        sess2 = UserSession(
            host_id=sample_host.id,
            linux_user_id=None,
            session_type="ssh",
            terminal="pts/0",
            remote_host="10.0.0.99",
            started_at=now,
            created_at=now,
        )
        db_session.add_all([sess1, sess2])
        db_session.flush()
        db_session.refresh(sample_host)
        assert len(sample_host.sessions) == 2
        assert sess1.host is sample_host

    def test_linux_user_has_many_sessions(
        self,
        db_session: Session,
        sample_host: Host,
        sample_linux_users: dict,
    ) -> None:
        root = sample_linux_users["root"]
        now = utcnow()
        sess1 = UserSession(
            host_id=sample_host.id,
            linux_user_id=root.id,
            session_type="ssh",
            terminal="pts/1",
            started_at=now,
            created_at=now,
        )
        sess2 = UserSession(
            host_id=sample_host.id,
            linux_user_id=root.id,
            session_type="pts",
            terminal="pts/2",
            started_at=now,
            created_at=now,
        )
        db_session.add_all([sess1, sess2])
        db_session.flush()
        db_session.refresh(root)
        assert len(root.sessions) >= 2
        assert sess1.linux_user is root


# ========================================================================
# SNAPSHOT TESTS (PHASE 2 MILESTONE 2.1)
# ========================================================================


class TestSnapshot:
    """Tests for the snapshots table."""

    def test_create_snapshot(
        self, db_session: Session, sample_host: Host
    ) -> None:
        now = utcnow()
        payload = {"system": {"load": [0.1, 0.2, 0.3]}, "meta": {"version": 1}}
        snapshot = Snapshot(
            host_id=sample_host.id,
            timestamp=now,
            snapshot_type="system",
            data=payload,
            created_at=now,
        )
        db_session.add(snapshot)
        db_session.flush()

        assert snapshot.id is not None
        assert snapshot.host_id == sample_host.id
        assert snapshot.snapshot_type == "system"
        assert snapshot.data == payload
        assert snapshot.timestamp == now
        assert snapshot.created_at is not None

    def test_snapshot_host_id_required(
        self, db_session: Session
    ) -> None:
        now = utcnow()
        snapshot = Snapshot(
            host_id=None,  # type: ignore[arg-type]
            timestamp=now,
            snapshot_type="system",
            data={"test": True},
            created_at=now,
        )
        db_session.add(snapshot)
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_snapshot_timestamp_required(
        self, db_session: Session, sample_host: Host
    ) -> None:
        snapshot = Snapshot(
            host_id=sample_host.id,
            timestamp=None,  # type: ignore[arg-type]
            snapshot_type="system",
            data={"test": True},
            created_at=utcnow(),
        )
        db_session.add(snapshot)
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_snapshot_type_required(
        self, db_session: Session, sample_host: Host
    ) -> None:
        snapshot = Snapshot(
            host_id=sample_host.id,
            timestamp=utcnow(),
            snapshot_type=None,  # type: ignore[arg-type]
            data={"test": True},
            created_at=utcnow(),
        )
        db_session.add(snapshot)
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_snapshot_data_required(
        self, db_session: Session, sample_host: Host
    ) -> None:
        snapshot = Snapshot(
            host_id=sample_host.id,
            timestamp=utcnow(),
            snapshot_type="system",
            data=None,  # type: ignore[arg-type]
            created_at=utcnow(),
        )
        db_session.add(snapshot)
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_snapshot_json_data_storage(
        self, db_session: Session, sample_host: Host
    ) -> None:
        now = utcnow()
        complex_data = {
            "processes": [
                {"pid": 1, "name": "systemd"},
                {"pid": 2, "name": "kthreadd"},
            ],
            "metrics": {
                "cpu_total": 4,
                "memory_free_bytes": 1073741824,
            },
            "flags": [True, False, None],
        }
        snapshot = Snapshot(
            host_id=sample_host.id,
            timestamp=now,
            snapshot_type="full_state",
            data=complex_data,
        )
        db_session.add(snapshot)
        db_session.flush()
        db_session.expire(snapshot)

        fetched = db_session.get(Snapshot, snapshot.id)
        assert fetched is not None
        assert fetched.data["processes"][0]["name"] == "systemd"
        assert fetched.data["metrics"]["cpu_total"] == 4
        assert fetched.data["flags"] == [True, False, None]

    def test_snapshot_foreign_key_violation(
        self, db_session: Session
    ) -> None:
        non_existent_host_id = uuid.uuid4()
        snapshot = Snapshot(
            host_id=non_existent_host_id,
            timestamp=utcnow(),
            snapshot_type="system",
            data={"test": 1},
        )
        db_session.add(snapshot)
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_snapshot_empty_dict_data_allowed(
        self, db_session: Session, sample_host: Host
    ) -> None:
        now = utcnow()
        snapshot = Snapshot(
            host_id=sample_host.id,
            timestamp=now,
            snapshot_type="empty_state",
            data={},
        )
        db_session.add(snapshot)
        db_session.flush()
        db_session.expire(snapshot)

        fetched = db_session.get(Snapshot, snapshot.id)
        assert fetched is not None
        assert fetched.data == {}

    def test_snapshot_list_data_storage(
        self, db_session: Session, sample_host: Host
    ) -> None:
        now = utcnow()
        list_data = [{"pid": 1, "cmd": "init"}, {"pid": 2, "cmd": "kworker"}]
        snapshot = Snapshot(
            host_id=sample_host.id,
            timestamp=now,
            snapshot_type="proc_list",
            data=list_data,
        )
        db_session.add(snapshot)
        db_session.flush()
        db_session.expire(snapshot)

        fetched = db_session.get(Snapshot, snapshot.id)
        assert fetched is not None
        assert fetched.data == list_data


# ========================================================================
# USER SESSION TESTS (PHASE 2 MILESTONE 2.1)
# ========================================================================


class TestUserSession:
    """Tests for the sessions table."""

    def test_create_session(
        self,
        db_session: Session,
        sample_host: Host,
        sample_linux_users: dict,
    ) -> None:
        root = sample_linux_users["root"]
        started = utcnow()
        ended = utcnow()
        session = UserSession(
            host_id=sample_host.id,
            linux_user_id=root.id,
            session_type="ssh",
            terminal="pts/3",
            remote_host="192.168.1.120",
            started_at=started,
            ended_at=ended,
            created_at=started,
        )
        db_session.add(session)
        db_session.flush()

        assert session.id is not None
        assert session.host_id == sample_host.id
        assert session.linux_user_id == root.id
        assert session.session_type == "ssh"
        assert session.terminal == "pts/3"
        assert session.remote_host == "192.168.1.120"
        assert session.started_at == started
        assert session.ended_at == ended
        assert session.created_at is not None

    def test_create_session_with_null_user(
        self, db_session: Session, sample_host: Host
    ) -> None:
        started = utcnow()
        session = UserSession(
            host_id=sample_host.id,
            linux_user_id=None,
            session_type=None,
            terminal=None,
            remote_host=None,
            started_at=started,
            ended_at=None,
        )
        db_session.add(session)
        db_session.flush()

        assert session.id is not None
        assert session.linux_user_id is None
        assert session.session_type is None
        assert session.terminal is None
        assert session.remote_host is None
        assert session.ended_at is None
        assert session.created_at is not None

    def test_session_host_id_required(
        self, db_session: Session
    ) -> None:
        session = UserSession(
            host_id=None,  # type: ignore[arg-type]
            started_at=utcnow(),
        )
        db_session.add(session)
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_session_started_at_required(
        self, db_session: Session, sample_host: Host
    ) -> None:
        session = UserSession(
            host_id=sample_host.id,
            started_at=None,  # type: ignore[arg-type]
        )
        db_session.add(session)
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_session_foreign_key_host_violation(
        self, db_session: Session
    ) -> None:
        non_existent_host_id = uuid.uuid4()
        session = UserSession(
            host_id=non_existent_host_id,
            started_at=utcnow(),
        )
        db_session.add(session)
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_session_foreign_key_linux_user_violation(
        self, db_session: Session, sample_host: Host
    ) -> None:
        non_existent_user_id = uuid.uuid4()
        session = UserSession(
            host_id=sample_host.id,
            linux_user_id=non_existent_user_id,
            started_at=utcnow(),
        )
        db_session.add(session)
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_session_deletion_removes_from_host_and_user(
        self,
        db_session: Session,
        sample_host: Host,
        sample_linux_users: dict,
    ) -> None:
        root = sample_linux_users["root"]
        now = utcnow()
        session = UserSession(
            host_id=sample_host.id,
            linux_user_id=root.id,
            session_type="console",
            terminal="tty2",
            started_at=now,
        )
        db_session.add(session)
        db_session.flush()
        db_session.refresh(sample_host)
        db_session.refresh(root)
        assert session in sample_host.sessions
        assert session in root.sessions

        db_session.delete(session)
        db_session.flush()
        db_session.refresh(sample_host)
        db_session.refresh(root)
        assert session not in sample_host.sessions
        assert session not in root.sessions
