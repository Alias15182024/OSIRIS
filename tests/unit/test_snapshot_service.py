"""Unit tests for OSIRIS Snapshot Creation Service (Phase 2 Milestone 2.1).

Tests cover:
  - Successful snapshot creation with process and resource data.
  - Correct host association and snapshot_type.
  - Active process data capture (only processes with ended_at IS NULL).
  - Latest resource telemetry capture (most recent by timestamp).
  - Empty process lists are captured faithfully (not treated as errors).
  - Missing resource telemetry is captured as null (not treated as error).
  - Multiple snapshots for the same host preserve forensic history.
  - Invalid host_id raises HostNotFoundError.
  - Database transaction semantics and caller rollback ownership.
  - Persistence failure preserves caller-owned session and transaction boundaries.
  - JSON serialization round-trip correctness with SQLite and PostgreSQL.
  - Custom timestamp override.
  - Snapshot data structure validation.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest
from sqlalchemy import create_engine, event as sa_event
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from backend.db.base import Base
from backend.db.models.host import Host
from backend.db.models.linux_user import LinuxUser
from backend.db.models.process import Process
from backend.db.models.resource_snapshot import ResourceSnapshot
from backend.db.models.snapshot import Snapshot
from backend.services.snapshots.service import (
    SNAPSHOT_TYPE_SYSTEM_STATE,
    HostNotFoundError,
    SnapshotError,
    SnapshotPersistenceError,
    SnapshotService,
)


# ── Helpers ─────────────────────────────────────────────────────────────

def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# Fixed UUIDs for reproducible test fixtures
_HOST_ID = uuid.UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
_HOST_ID_2 = uuid.UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaab")
_USER_ID = uuid.UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbb01")
_PROC_ID_1 = uuid.UUID("cccccccc-cccc-4ccc-8ccc-cccccccccc01")
_PROC_ID_2 = uuid.UUID("cccccccc-cccc-4ccc-8ccc-cccccccccc02")
_PROC_ID_3 = uuid.UUID("cccccccc-cccc-4ccc-8ccc-cccccccccc03")
_RES_ID_1 = uuid.UUID("dddddddd-dddd-4ddd-8ddd-dddddddddd01")
_RES_ID_2 = uuid.UUID("dddddddd-dddd-4ddd-8ddd-dddddddddd02")


# ── Fixtures ────────────────────────────────────────────────────────────


@pytest.fixture
def snap_engine():
    """Create an in-memory SQLite engine with FK enforcement."""
    eng = create_engine("sqlite:///:memory:", echo=False)

    @sa_event.listens_for(eng, "connect")
    def _set_pragma(dbapi_conn, connection_record):  # type: ignore[no-untyped-def]
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(eng)
    yield eng
    Base.metadata.drop_all(eng)
    eng.dispose()


@pytest.fixture
def snap_session(snap_engine):
    """Provide a transactional session, rolled back after each test."""
    connection = snap_engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection, join_transaction_mode="create_savepoint")
    yield session
    session.close()
    if transaction.is_active:
        transaction.rollback()
    connection.close()


@pytest.fixture
def host(snap_session: Session) -> Host:
    """Insert and return a sample host."""
    h = Host(
        id=_HOST_ID,
        hostname="snapshot-test-host",
        os_info="Ubuntu 22.04 LTS",
        ip_address="10.0.0.1",
        created_at=utcnow(),
    )
    snap_session.add(h)
    snap_session.flush()
    return h


@pytest.fixture
def host2(snap_session: Session) -> Host:
    """Insert and return a second host for isolation tests."""
    h = Host(
        id=_HOST_ID_2,
        hostname="snapshot-test-host-2",
        os_info="Debian 12",
        ip_address="10.0.0.2",
        created_at=utcnow(),
    )
    snap_session.add(h)
    snap_session.flush()
    return h


@pytest.fixture
def linux_user(snap_session: Session, host: Host) -> LinuxUser:
    """Insert a sample Linux user for the host."""
    lu = LinuxUser(
        id=_USER_ID,
        host_id=host.id,
        uid=0,
        username="root",
        first_seen_at=utcnow(),
        created_at=utcnow(),
    )
    snap_session.add(lu)
    snap_session.flush()
    return lu


@pytest.fixture
def active_processes(
    snap_session: Session, host: Host, linux_user: LinuxUser
) -> list[Process]:
    """Insert two active processes (ended_at=NULL) for the host."""
    now = utcnow()
    p1 = Process(
        id=_PROC_ID_1,
        host_id=host.id,
        pid=1,
        ppid=0,
        command="/sbin/init",
        executable="/sbin/init",
        linux_user_id=linux_user.id,
        started_at=now - timedelta(hours=1),
        ended_at=None,
        created_at=now,
    )
    p2 = Process(
        id=_PROC_ID_2,
        host_id=host.id,
        pid=42,
        ppid=1,
        command="/usr/bin/sshd",
        executable="/usr/sbin/sshd",
        linux_user_id=linux_user.id,
        started_at=now - timedelta(minutes=30),
        ended_at=None,
        created_at=now,
    )
    snap_session.add_all([p1, p2])
    snap_session.flush()
    return [p1, p2]


@pytest.fixture
def terminated_process(
    snap_session: Session, host: Host, linux_user: LinuxUser
) -> Process:
    """Insert a terminated process (ended_at is set) for the host."""
    now = utcnow()
    p = Process(
        id=_PROC_ID_3,
        host_id=host.id,
        pid=99,
        ppid=1,
        command="/tmp/old_script.sh",
        executable="/bin/bash",
        linux_user_id=linux_user.id,
        started_at=now - timedelta(hours=2),
        ended_at=now - timedelta(hours=1),
        created_at=now,
    )
    snap_session.add(p)
    snap_session.flush()
    return p


@pytest.fixture
def resource_snapshots(snap_session: Session, host: Host) -> list[ResourceSnapshot]:
    """Insert two resource snapshots for the host (older + newer)."""
    now = utcnow()
    older = ResourceSnapshot(
        id=_RES_ID_1,
        host_id=host.id,
        timestamp=now - timedelta(minutes=10),
        cpu_percent=15.0,
        memory_total=8_000_000_000,
        memory_used=4_000_000_000,
        memory_percent=50.0,
        disk_read_bytes=100_000,
        disk_write_bytes=50_000,
        disk_usage_percent=30.0,
        created_at=now - timedelta(minutes=10),
    )
    newer = ResourceSnapshot(
        id=_RES_ID_2,
        host_id=host.id,
        timestamp=now - timedelta(seconds=30),
        cpu_percent=72.5,
        memory_total=8_000_000_000,
        memory_used=6_400_000_000,
        memory_percent=80.0,
        disk_read_bytes=500_000,
        disk_write_bytes=250_000,
        disk_usage_percent=55.0,
        created_at=now - timedelta(seconds=30),
    )
    snap_session.add_all([older, newer])
    snap_session.flush()
    return [older, newer]


def _service(session: Session) -> SnapshotService:
    """Helper to construct a SnapshotService."""
    return SnapshotService(session)


# ========================================================================
# SUCCESSFUL SNAPSHOT CREATION
# ========================================================================


class TestSnapshotCreation:
    """Tests for successful snapshot creation with full data."""

    def test_create_snapshot_with_processes_and_resources(
        self,
        snap_session: Session,
        host: Host,
        active_processes: list[Process],
        resource_snapshots: list[ResourceSnapshot],
    ) -> None:
        """Service creates a snapshot capturing active processes and latest resource data."""
        svc = _service(snap_session)
        snapshot = svc.create_snapshot(host.id)

        assert snapshot.id is not None
        assert snapshot.host_id == host.id
        assert snapshot.snapshot_type == SNAPSHOT_TYPE_SYSTEM_STATE
        assert snapshot.timestamp is not None
        assert snapshot.created_at is not None

        # Data structure validation
        data = snapshot.data
        assert "processes" in data
        assert "resources" in data

    def test_snapshot_captures_active_processes_only(
        self,
        snap_session: Session,
        host: Host,
        active_processes: list[Process],
        terminated_process: Process,
    ) -> None:
        """Only processes with ended_at=NULL are included in the snapshot."""
        svc = _service(snap_session)
        snapshot = svc.create_snapshot(host.id)

        procs = snapshot.data["processes"]
        assert len(procs) == 2
        pids = {p["pid"] for p in procs}
        assert pids == {1, 42}
        # The terminated process (pid=99) must not appear
        assert 99 not in pids

    def test_process_data_fields(
        self,
        snap_session: Session,
        host: Host,
        active_processes: list[Process],
    ) -> None:
        """Each process entry contains the expected fields."""
        svc = _service(snap_session)
        snapshot = svc.create_snapshot(host.id)

        for proc_data in snapshot.data["processes"]:
            assert "id" in proc_data
            assert "pid" in proc_data
            assert "ppid" in proc_data
            assert "command" in proc_data
            assert "executable" in proc_data
            assert "linux_user_id" in proc_data
            assert "started_at" in proc_data

    def test_processes_ordered_by_pid(
        self,
        snap_session: Session,
        host: Host,
        active_processes: list[Process],
    ) -> None:
        """Processes in the snapshot are ordered by PID ascending."""
        svc = _service(snap_session)
        snapshot = svc.create_snapshot(host.id)

        pids = [p["pid"] for p in snapshot.data["processes"]]
        assert pids == sorted(pids)

    def test_snapshot_captures_latest_resource(
        self,
        snap_session: Session,
        host: Host,
        resource_snapshots: list[ResourceSnapshot],
    ) -> None:
        """The snapshot contains only the most recent resource telemetry."""
        svc = _service(snap_session)
        snapshot = svc.create_snapshot(host.id)

        res = snapshot.data["resources"]
        assert res is not None
        # Should match the newer resource snapshot (72.5% CPU)
        assert res["cpu_percent"] == 72.5
        assert res["memory_percent"] == 80.0
        assert res["disk_usage_percent"] == 55.0

    def test_resource_data_fields(
        self,
        snap_session: Session,
        host: Host,
        resource_snapshots: list[ResourceSnapshot],
    ) -> None:
        """The resource entry contains the expected fields."""
        svc = _service(snap_session)
        snapshot = svc.create_snapshot(host.id)

        res = snapshot.data["resources"]
        expected_keys = {
            "id", "timestamp", "cpu_percent",
            "memory_total", "memory_used", "memory_percent",
            "disk_read_bytes", "disk_write_bytes", "disk_usage_percent",
        }
        assert set(res.keys()) == expected_keys


# ========================================================================
# HOST ASSOCIATION
# ========================================================================


class TestHostAssociation:
    """Tests for correct host association and isolation."""

    def test_snapshot_bound_to_correct_host(
        self,
        snap_session: Session,
        host: Host,
        active_processes: list[Process],
    ) -> None:
        """The snapshot's host_id matches the requested host."""
        svc = _service(snap_session)
        snapshot = svc.create_snapshot(host.id)
        assert snapshot.host_id == host.id

    def test_snapshot_host_relationship(
        self,
        snap_session: Session,
        host: Host,
        active_processes: list[Process],
    ) -> None:
        """The snapshot's ORM relationship resolves to the correct host."""
        svc = _service(snap_session)
        snapshot = svc.create_snapshot(host.id)
        snap_session.flush()
        assert snapshot.host.hostname == "snapshot-test-host"

    def test_snapshot_does_not_capture_other_host_processes(
        self,
        snap_session: Session,
        host: Host,
        host2: Host,
        active_processes: list[Process],
    ) -> None:
        """Creating a snapshot for host2 does not include host1's processes."""
        svc = _service(snap_session)
        snapshot = svc.create_snapshot(host2.id)

        assert snapshot.data["processes"] == []
        assert snapshot.data["resources"] is None


# ========================================================================
# EMPTY AND MISSING DATA
# ========================================================================


class TestEmptyAndMissingData:
    """Tests for graceful handling of empty process lists and missing resources."""

    def test_empty_process_list(
        self,
        snap_session: Session,
        host: Host,
    ) -> None:
        """A host with no processes produces a snapshot with an empty process list."""
        svc = _service(snap_session)
        snapshot = svc.create_snapshot(host.id)

        assert snapshot.data["processes"] == []
        assert snapshot.host_id == host.id
        assert snapshot.snapshot_type == SNAPSHOT_TYPE_SYSTEM_STATE

    def test_missing_resource_telemetry(
        self,
        snap_session: Session,
        host: Host,
        active_processes: list[Process],
    ) -> None:
        """A host with processes but no resource snapshots gets resources=null."""
        svc = _service(snap_session)
        snapshot = svc.create_snapshot(host.id)

        assert len(snapshot.data["processes"]) == 2
        assert snapshot.data["resources"] is None

    def test_no_processes_no_resources(
        self,
        snap_session: Session,
        host: Host,
    ) -> None:
        """A host with neither processes nor resources still creates a valid snapshot."""
        svc = _service(snap_session)
        snapshot = svc.create_snapshot(host.id)

        assert snapshot.id is not None
        assert snapshot.data == {"processes": [], "resources": None}


# ========================================================================
# MULTIPLE SNAPSHOTS (FORENSIC HISTORY)
# ========================================================================


class TestForensicHistory:
    """Tests that every snapshot creates a new record, never overwriting."""

    def test_multiple_snapshots_for_same_host(
        self,
        snap_session: Session,
        host: Host,
        active_processes: list[Process],
        resource_snapshots: list[ResourceSnapshot],
    ) -> None:
        """Multiple create_snapshot calls produce distinct Snapshot records."""
        svc = _service(snap_session)

        snap1 = svc.create_snapshot(host.id)
        snap2 = svc.create_snapshot(host.id)
        snap3 = svc.create_snapshot(host.id)

        # Each snapshot has a unique ID
        ids = {snap1.id, snap2.id, snap3.id}
        assert len(ids) == 3

        # All are for the same host
        assert snap1.host_id == snap2.host_id == snap3.host_id == host.id

    def test_snapshots_have_distinct_timestamps(
        self,
        snap_session: Session,
        host: Host,
    ) -> None:
        """Each snapshot gets its own timestamp (or at least its own record)."""
        svc = _service(snap_session)

        t1 = utcnow()
        snap1 = svc.create_snapshot(host.id, timestamp=t1)

        t2 = t1 + timedelta(minutes=5)
        snap2 = svc.create_snapshot(host.id, timestamp=t2)

        assert snap1.timestamp == t1
        assert snap2.timestamp == t2
        assert snap1.id != snap2.id

    def test_previous_snapshot_preserved_after_new_one(
        self,
        snap_session: Session,
        host: Host,
        active_processes: list[Process],
    ) -> None:
        """Creating a new snapshot does not alter or delete the previous one."""
        svc = _service(snap_session)

        snap1 = svc.create_snapshot(host.id)
        snap1_id = snap1.id
        snap1_data_copy = dict(snap1.data)

        _snap2 = svc.create_snapshot(host.id)

        # Re-fetch snap1 from the database
        snap1_refetched = snap_session.get(Snapshot, snap1_id)
        assert snap1_refetched is not None
        assert snap1_refetched.data["processes"] == snap1_data_copy["processes"]


# ========================================================================
# INVALID HOST HANDLING
# ========================================================================


class TestInvalidHost:
    """Tests for invalid host identifiers."""

    def test_nonexistent_host_raises_error(
        self,
        snap_session: Session,
    ) -> None:
        """Requesting a snapshot for a non-existent host_id raises HostNotFoundError."""
        svc = _service(snap_session)
        fake_id = uuid.uuid4()

        with pytest.raises(HostNotFoundError) as exc_info:
            svc.create_snapshot(fake_id)

        assert exc_info.value.host_id == fake_id
        assert str(fake_id) in str(exc_info.value)

    def test_host_not_found_is_snapshot_error(
        self,
        snap_session: Session,
    ) -> None:
        """HostNotFoundError is a subclass of SnapshotError."""
        svc = _service(snap_session)

        with pytest.raises(SnapshotError):
            svc.create_snapshot(uuid.uuid4())


# ========================================================================
# DATABASE TRANSACTION BEHAVIOUR
# ========================================================================


class TestTransactionBehaviour:
    """Tests for database transaction semantics, boundaries, and caller rollback ownership."""

    def test_snapshot_flushed_not_committed(
        self,
        snap_session: Session,
        host: Host,
    ) -> None:
        """Service flushes but does not commit — snapshot visible in session."""
        svc = _service(snap_session)
        snapshot = svc.create_snapshot(host.id)

        # Snapshot should be queryable within the same session
        found = snap_session.get(Snapshot, snapshot.id)
        assert found is not None
        assert found.host_id == host.id

    def test_rollback_removes_snapshot(self, snap_engine) -> None:
        """If the caller rolls back, the snapshot is not persisted."""
        # Use a fresh session outside the fixture's savepoint
        session = Session(bind=snap_engine.connect())
        try:
            h = Host(
                id=uuid.uuid4(),
                hostname="rollback-test",
                created_at=utcnow(),
            )
            session.add(h)
            session.flush()

            svc = SnapshotService(session)
            snapshot = svc.create_snapshot(h.id)
            snap_id = snapshot.id

            # Rollback the entire transaction
            session.rollback()

            # The snapshot should be gone
            assert session.get(Snapshot, snap_id) is None
        finally:
            session.close()

    def test_persistence_error_raises_snapshot_persistence_error(
        self,
        snap_engine,
    ) -> None:
        """A database error during flush raises SnapshotPersistenceError with cause attached.

        We simulate this by dropping the snapshots table before snapshot creation.
        """
        from sqlalchemy import text as sa_text

        session = Session(bind=snap_engine.connect())
        try:
            h = Host(
                id=uuid.uuid4(),
                hostname="error-test",
                created_at=utcnow(),
            )
            session.add(h)
            session.commit()

            # Drop the snapshots table to force an error on flush
            session.execute(sa_text("DROP TABLE IF EXISTS snapshots"))
            session.commit()

            svc = SnapshotService(session)

            with pytest.raises(SnapshotPersistenceError) as exc_info:
                svc.create_snapshot(h.id)

            assert "error persisting snapshot" in str(exc_info.value).lower()
            assert exc_info.value.cause is not None
            assert exc_info.value.__cause__ is not None
        finally:
            session.close()
            # Recreate the table for subsequent tests
            Base.metadata.create_all(snap_engine)

    def test_persistence_failure_does_not_rollback_caller_session(
        self,
        snap_engine,
    ) -> None:
        """Persistence failure does NOT roll back the caller's session or unrelated staged work."""
        from sqlalchemy import text as sa_text

        session = Session(bind=snap_engine.connect())
        try:
            # 1. Caller stages an unrelated host entity in their transaction
            caller_host = Host(
                id=uuid.uuid4(),
                hostname="caller-staged-work",
                created_at=utcnow(),
            )
            session.add(caller_host)
            session.flush()

            # 2. Target host for the snapshot
            target_host = Host(
                id=uuid.uuid4(),
                hostname="target-monitored-host",
                created_at=utcnow(),
            )
            session.add(target_host)
            session.flush()

            # 3. Caller creates a savepoint around the snapshot attempt
            sp = session.begin_nested()

            # Simulate persistence failure by dropping the snapshots table
            session.execute(sa_text("DROP TABLE IF EXISTS snapshots"))

            svc = SnapshotService(session)
            with pytest.raises(SnapshotPersistenceError):
                svc.create_snapshot(target_host.id)

            # 4. Caller rolls back only the inner savepoint
            sp.rollback()

            # Recreate table so future writes within transaction work
            Base.metadata.create_all(snap_engine)

            # 5. Caller's staged work is STILL intact in the outer transaction!
            # If SnapshotService had invoked session.rollback(), caller_host would have been discarded.
            found = session.get(Host, caller_host.id)
            assert found is not None
            assert found.hostname == "caller-staged-work"

            # 6. Caller commits the outer transaction successfully
            session.commit()
            persisted = session.get(Host, caller_host.id)
            assert persisted is not None
            assert persisted.hostname == "caller-staged-work"
        finally:
            session.close()
            Base.metadata.create_all(snap_engine)

    def test_service_does_not_call_session_rollback_on_integrity_error(self) -> None:
        """Verify that SnapshotService never invokes session.rollback() on IntegrityError."""
        mock_session = MagicMock(spec=Session)
        mock_host_id = uuid.uuid4()
        mock_session.get.return_value = MagicMock(spec=Host)
        mock_session.execute.return_value.scalars.return_value.all.return_value = []
        mock_session.execute.return_value.scalars.return_value.first.return_value = None

        mock_session.flush.side_effect = IntegrityError(
            statement="INSERT INTO snapshots",
            params={},
            orig=Exception("FOREIGN KEY constraint failed"),
        )

        svc = SnapshotService(mock_session)
        with pytest.raises(SnapshotPersistenceError) as exc_info:
            svc.create_snapshot(mock_host_id)

        assert "Integrity error" in str(exc_info.value)
        assert isinstance(exc_info.value.cause, IntegrityError)
        # CRITICAL ASSERTION: session.rollback() must NOT be called by the service
        mock_session.rollback.assert_not_called()

    def test_service_does_not_call_session_rollback_on_sqlalchemy_error(self) -> None:
        """Verify that SnapshotService never invokes session.rollback() on generic SQLAlchemyError."""
        mock_session = MagicMock(spec=Session)
        mock_host_id = uuid.uuid4()
        mock_session.get.return_value = MagicMock(spec=Host)
        mock_session.execute.return_value.scalars.return_value.all.return_value = []
        mock_session.execute.return_value.scalars.return_value.first.return_value = None

        mock_session.flush.side_effect = SQLAlchemyError("Database connection lost")

        svc = SnapshotService(mock_session)
        with pytest.raises(SnapshotPersistenceError) as exc_info:
            svc.create_snapshot(mock_host_id)

        assert "Database error" in str(exc_info.value)
        assert isinstance(exc_info.value.cause, SQLAlchemyError)
        # CRITICAL ASSERTION: session.rollback() must NOT be called by the service
        mock_session.rollback.assert_not_called()

    def test_caller_manages_transaction_rollback(self, snap_engine) -> None:
        """Verify the caller can catch SnapshotPersistenceError and manage rollback explicitly."""
        from sqlalchemy import text as sa_text

        session = Session(bind=snap_engine.connect())
        try:
            h = Host(
                id=uuid.uuid4(),
                hostname="caller-rollback-mgr",
                created_at=utcnow(),
            )
            session.add(h)
            session.commit()

            # Force failure on next flush
            session.execute(sa_text("DROP TABLE IF EXISTS snapshots"))
            session.commit()

            svc = SnapshotService(session)

            # Standard caller transaction management pattern:
            # Caller opens unit-of-work, tries operations, catches error, rolls back
            try:
                svc.create_snapshot(h.id)
                session.commit()
            except SnapshotPersistenceError:
                session.rollback()

            # Recreate table and verify session is clean and functional after caller rollback
            Base.metadata.create_all(snap_engine)
            h2 = Host(
                id=uuid.uuid4(),
                hostname="after-rollback-host",
                created_at=utcnow(),
            )
            session.add(h2)
            session.commit()

            assert session.get(Host, h2.id) is not None
        finally:
            session.close()
            Base.metadata.create_all(snap_engine)

    def test_caller_atomic_transaction_with_snapshot(
        self,
        snap_session: Session,
        host: Host,
    ) -> None:
        """Caller can bundle snapshot creation with other operations in an atomic transaction."""
        svc = _service(snap_session)

        # Stage a new user session alongside snapshot
        new_user = LinuxUser(
            id=uuid.uuid4(),
            host_id=host.id,
            uid=1001,
            username="analyst",
            first_seen_at=utcnow(),
            created_at=utcnow(),
        )
        snap_session.add(new_user)

        # Create snapshot in the same transaction
        snapshot = svc.create_snapshot(host.id)

        # Both exist uncommitted in the session
        assert snap_session.get(LinuxUser, new_user.id) is not None
        assert snap_session.get(Snapshot, snapshot.id) is not None

    def test_service_session_lifecycle_and_rebinding(
        self,
        snap_session: Session,
        host: Host,
    ) -> None:
        """SnapshotService supports unbound initialization, session properties, and rebinding."""
        # Unbound service raises RuntimeError on attempt to create snapshot
        svc = SnapshotService()
        assert svc.session is None

        with pytest.raises(RuntimeError, match="no active database session"):
            svc.create_snapshot(host.id)

        # Property setter binding
        svc.session = snap_session
        assert svc.session is snap_session
        snapshot = svc.create_snapshot(host.id)
        assert snapshot.host_id == host.id

        # Method setter rebinding
        svc.set_session(None)
        assert svc.session is None
        with pytest.raises(RuntimeError, match="no active database session"):
            svc.create_snapshot(host.id)

    def test_real_foreign_key_integrity_error_without_table_drop(
        self,
        snap_engine,
    ) -> None:
        """A genuine foreign key IntegrityError surfaces as SnapshotPersistenceError without rollback."""
        session = Session(bind=snap_engine.connect())
        try:
            h = Host(
                id=uuid.uuid4(),
                hostname="fk-violation-test",
                created_at=utcnow(),
            )
            session.add(h)
            session.flush()

            svc = SnapshotService(session)

            # Stage host deletion in session so foreign key fails on snapshot flush
            session.delete(h)

            with pytest.raises(SnapshotPersistenceError) as exc_info:
                svc.create_snapshot(h.id)

            assert "Integrity error persisting snapshot" in str(exc_info.value)
            assert isinstance(exc_info.value.cause, IntegrityError)
            assert exc_info.value.__cause__ is exc_info.value.cause

            # Service did NOT execute rollback — caller still controls session state
            assert session.is_active is False  # Flush failed; awaiting caller rollback
            session.rollback()
            assert session.is_active is True   # Caller rolled back and restored session cleanly
        finally:
            session.close()

    def test_string_host_id_resolution(
        self,
        snap_session: Session,
        host: Host,
    ) -> None:
        """SnapshotService accepts host_id as UUID string and validates non-existent string ID."""
        svc = SnapshotService(snap_session)

        # Valid string UUID succeeds
        snap = svc.create_snapshot(str(host.id))
        assert snap.host_id == host.id

        # Non-existent string UUID raises HostNotFoundError
        fake_uuid_str = str(uuid.uuid4())
        with pytest.raises(HostNotFoundError) as exc_info:
            svc.create_snapshot(fake_uuid_str)
        assert exc_info.value.host_id == fake_uuid_str

    def test_persistence_error_cause_property_fallback(self) -> None:
        """SnapshotPersistenceError.cause falls back to __cause__ when cause is not explicitly passed."""
        # 1. Cause passed explicitly
        err1 = SnapshotPersistenceError("detail", cause=ValueError("foo"))
        assert isinstance(err1.cause, ValueError)
        assert err1.__cause__ is err1.cause

        # 2. No cause provided
        err2 = SnapshotPersistenceError("detail")
        assert err2.cause is None
        assert err2.__cause__ is None

        # 3. Fallback via exception chaining (`from exc`)
        try:
            raise KeyError("missing key")
        except KeyError as k_err:
            try:
                raise SnapshotPersistenceError("wrapped error") from k_err
            except SnapshotPersistenceError as caught:
                assert caught.cause is k_err
                assert caught.__cause__ is k_err

        # 4. Cause setter works
        new_cause = RuntimeError("setter test")
        err2.cause = new_cause
        assert err2.cause is new_cause


# ========================================================================
# JSON SERIALIZATION AND COMPATIBILITY
# ========================================================================


class TestJsonSerialization:
    """Tests for JSON round-trip and SQLite/PostgreSQL compatibility."""

    def test_data_round_trip(
        self,
        snap_session: Session,
        host: Host,
        active_processes: list[Process],
        resource_snapshots: list[ResourceSnapshot],
    ) -> None:
        """Snapshot data survives a flush + expire + re-read cycle."""
        svc = _service(snap_session)
        snapshot = svc.create_snapshot(host.id)

        snap_session.expire(snapshot)
        refetched = snap_session.get(Snapshot, snapshot.id)

        assert refetched is not None
        assert isinstance(refetched.data, dict)
        assert isinstance(refetched.data["processes"], list)
        assert len(refetched.data["processes"]) == 2

    def test_process_ids_are_strings_in_json(
        self,
        snap_session: Session,
        host: Host,
        active_processes: list[Process],
    ) -> None:
        """UUIDs and datetimes are serialized as strings for JSON compatibility."""
        svc = _service(snap_session)
        snapshot = svc.create_snapshot(host.id)

        for proc_data in snapshot.data["processes"]:
            assert isinstance(proc_data["id"], str)
            # Verify it's a valid UUID string
            uuid.UUID(proc_data["id"])
            if proc_data["started_at"] is not None:
                assert isinstance(proc_data["started_at"], str)

    def test_resource_values_are_json_safe(
        self,
        snap_session: Session,
        host: Host,
        resource_snapshots: list[ResourceSnapshot],
    ) -> None:
        """Resource telemetry values are JSON-safe native types (float, int, str, None)."""
        svc = _service(snap_session)
        snapshot = svc.create_snapshot(host.id)

        res = snapshot.data["resources"]
        assert res is not None
        assert isinstance(res["cpu_percent"], float)
        assert isinstance(res["memory_total"], int)
        assert isinstance(res["timestamp"], str)

    def test_empty_data_round_trip(
        self,
        snap_session: Session,
        host: Host,
    ) -> None:
        """A snapshot with empty processes and null resources survives round-trip."""
        svc = _service(snap_session)
        snapshot = svc.create_snapshot(host.id)

        snap_session.expire(snapshot)
        refetched = snap_session.get(Snapshot, snapshot.id)

        assert refetched is not None
        assert refetched.data["processes"] == []
        assert refetched.data["resources"] is None


# ========================================================================
# CUSTOM TIMESTAMP
# ========================================================================


class TestCustomTimestamp:
    """Tests for timestamp handling."""

    def test_default_timestamp_is_utc(
        self,
        snap_session: Session,
        host: Host,
    ) -> None:
        """Without an explicit timestamp, the snapshot uses UTC now."""
        before = utcnow()
        svc = _service(snap_session)
        snapshot = svc.create_snapshot(host.id)
        after = utcnow()

        assert snapshot.timestamp >= before
        assert snapshot.timestamp <= after

    def test_custom_timestamp_accepted(
        self,
        snap_session: Session,
        host: Host,
    ) -> None:
        """A caller-provided timestamp is used verbatim."""
        custom_ts = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        svc = _service(snap_session)
        snapshot = svc.create_snapshot(host.id, timestamp=custom_ts)

        assert snapshot.timestamp == custom_ts

    def test_created_at_independent_of_timestamp(
        self,
        snap_session: Session,
        host: Host,
    ) -> None:
        """created_at is always the wall-clock time, not the custom timestamp."""
        past = datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        before = utcnow()
        svc = _service(snap_session)
        snapshot = svc.create_snapshot(host.id, timestamp=past)

        assert snapshot.timestamp == past
        assert snapshot.created_at >= before


# ========================================================================
# SNAPSHOT TYPE
# ========================================================================


class TestSnapshotType:
    """Tests for the snapshot_type field."""

    def test_snapshot_type_is_system_state(
        self,
        snap_session: Session,
        host: Host,
    ) -> None:
        """All snapshots created by the service use the 'system_state' type."""
        svc = _service(snap_session)
        snapshot = svc.create_snapshot(host.id)
        assert snapshot.snapshot_type == "system_state"

    def test_snapshot_type_constant(self) -> None:
        """The constant matches the expected string."""
        assert SNAPSHOT_TYPE_SYSTEM_STATE == "system_state"
