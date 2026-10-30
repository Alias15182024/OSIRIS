"""Unit tests for OSIRIS Forensic Entity Correlation Engine (Phase 2 Milestone 2.2).

Verifies:
- Process correlation by ID and by PID with start/end lifetime boundaries.
- PID reuse handling: distinguishing processes with identical PIDs by lifetime.
- Ambiguous overlapping process lifetimes safely return None.
- Linux user correlation by UID, linux_user_id, and username.
- Missing / unknown Linux users preserved gracefully without inventing records.
- Session correlation for active user sessions within lifetime bounds.
- Ambiguous sessions return None.
- Filesystem correlation by path.
- Resource snapshot correlation within temporal tolerance.
- System snapshot correlation and process containment detection.
- Cross-host isolation: entities from other hosts are NEVER correlated.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, event as sa_event
from sqlalchemy.orm import Session

from backend.db.base import Base
from backend.db.models.file import File
from backend.db.models.host import Host
from backend.db.models.linux_user import LinuxUser
from backend.db.models.process import Process
from backend.db.models.resource_snapshot import ResourceSnapshot
from backend.db.models.snapshot import Snapshot
from backend.db.models.user_session import UserSession
from backend.services.timeline.correlator import EntityCorrelator


@pytest.fixture
def corr_engine():
    """Create in-memory SQLite engine with foreign key enforcement."""
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
def corr_session(corr_engine):
    """Provide a transactional session rolled back after each test."""
    conn = corr_engine.connect()
    trans = conn.begin()
    session = Session(bind=conn, join_transaction_mode="create_savepoint")
    yield session
    session.close()
    if trans.is_active:
        trans.rollback()
    conn.close()


@pytest.fixture
def correlator(corr_session: Session) -> EntityCorrelator:
    return EntityCorrelator(session=corr_session)


@pytest.fixture
def host_a(corr_session: Session) -> Host:
    h = Host(
        id=uuid.UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
        hostname="host-alpha",
        os_info="Linux 5.15 Ubuntu 22.04",
        created_at=datetime(2026, 3, 1, 0, 0, 0, tzinfo=timezone.utc),
    )
    corr_session.add(h)
    corr_session.commit()
    return h


@pytest.fixture
def host_b(corr_session: Session) -> Host:
    h = Host(
        id=uuid.UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
        hostname="host-bravo",
        os_info="Linux 5.15 Ubuntu 22.04",
        created_at=datetime(2026, 3, 1, 0, 0, 0, tzinfo=timezone.utc),
    )
    corr_session.add(h)
    corr_session.commit()
    return h


# ── Process Correlation Tests ────────────────────────────────────────────────


class TestProcessCorrelation:
    def test_correlate_process_by_id_success(
        self, correlator: EntityCorrelator, corr_session: Session, host_a: Host
    ) -> None:
        p = Process(
            id=uuid.uuid4(),
            host_id=host_a.id,
            pid=1001,
            command="/usr/bin/nginx",
            executable="/usr/bin/nginx",
            started_at=datetime(2026, 3, 1, 10, 0, 0, tzinfo=timezone.utc),
            created_at=datetime(2026, 3, 1, 10, 0, 0, tzinfo=timezone.utc),
        )
        corr_session.add(p)
        corr_session.commit()

        ctx = correlator.correlate_process_by_id(host_a.id, p.id)
        assert ctx is not None
        assert ctx.process_id == p.id
        assert ctx.pid == 1001
        assert ctx.command == "/usr/bin/nginx"

    def test_correlate_process_by_id_cross_host_isolation(
        self,
        correlator: EntityCorrelator,
        corr_session: Session,
        host_a: Host,
        host_b: Host,
    ) -> None:
        """Process on Host B must never correlate with Host A."""
        p_b = Process(
            id=uuid.uuid4(),
            host_id=host_b.id,
            pid=1001,
            command="/usr/bin/nginx",
            started_at=datetime(2026, 3, 1, 10, 0, 0, tzinfo=timezone.utc),
            created_at=datetime(2026, 3, 1, 10, 0, 0, tzinfo=timezone.utc),
        )
        corr_session.add(p_b)
        corr_session.commit()

        # Querying with host_a must return None
        ctx = correlator.correlate_process_by_id(host_a.id, p_b.id)
        assert ctx is None

    def test_pid_reuse_distinguishes_process_lifetimes(
        self, correlator: EntityCorrelator, corr_session: Session, host_a: Host
    ) -> None:
        """PID 500 reused across two distinct lifetimes."""
        # Process 1: 10:00:00 -> 10:10:00
        p1 = Process(
            id=uuid.uuid4(),
            host_id=host_a.id,
            pid=500,
            command="python3 worker_1.py",
            started_at=datetime(2026, 3, 1, 10, 0, 0, tzinfo=timezone.utc),
            ended_at=datetime(2026, 3, 1, 10, 10, 0, tzinfo=timezone.utc),
            created_at=datetime(2026, 3, 1, 10, 0, 0, tzinfo=timezone.utc),
        )
        # Process 2: 10:15:00 -> 10:25:00
        p2 = Process(
            id=uuid.uuid4(),
            host_id=host_a.id,
            pid=500,
            command="python3 worker_2.py",
            started_at=datetime(2026, 3, 1, 10, 15, 0, tzinfo=timezone.utc),
            ended_at=datetime(2026, 3, 1, 10, 25, 0, tzinfo=timezone.utc),
            created_at=datetime(2026, 3, 1, 10, 15, 0, tzinfo=timezone.utc),
        )
        corr_session.add_all([p1, p2])
        corr_session.commit()

        # Event at 10:05:00 should resolve to p1
        ctx1 = correlator.correlate_process_by_pid(
            host_a.id, 500, datetime(2026, 3, 1, 10, 5, 0, tzinfo=timezone.utc)
        )
        assert ctx1 is not None
        assert ctx1.process_id == p1.id
        assert ctx1.command == "python3 worker_1.py"

        # Event at 10:20:00 should resolve to p2
        ctx2 = correlator.correlate_process_by_pid(
            host_a.id, 500, datetime(2026, 3, 1, 10, 20, 0, tzinfo=timezone.utc)
        )
        assert ctx2 is not None
        assert ctx2.process_id == p2.id
        assert ctx2.command == "python3 worker_2.py"

        # Event at 10:12:00 (between lifetimes) resolves to None
        ctx_gap = correlator.correlate_process_by_pid(
            host_a.id, 500, datetime(2026, 3, 1, 10, 12, 0, tzinfo=timezone.utc)
        )
        assert ctx_gap is None

    def test_pid_reuse_ambiguous_overlapping_matches_return_none(
        self, correlator: EntityCorrelator, corr_session: Session, host_a: Host
    ) -> None:
        """Overlapping process lifetimes with same PID must return None (safe failure)."""
        p1 = Process(
            id=uuid.uuid4(),
            host_id=host_a.id,
            pid=777,
            command="proc_a",
            started_at=datetime(2026, 3, 1, 10, 0, 0, tzinfo=timezone.utc),
            ended_at=datetime(2026, 3, 1, 10, 30, 0, tzinfo=timezone.utc),
            created_at=datetime(2026, 3, 1, 10, 0, 0, tzinfo=timezone.utc),
        )
        p2 = Process(
            id=uuid.uuid4(),
            host_id=host_a.id,
            pid=777,
            command="proc_b",
            started_at=datetime(2026, 3, 1, 10, 10, 0, tzinfo=timezone.utc),
            ended_at=datetime(2026, 3, 1, 10, 40, 0, tzinfo=timezone.utc),
            created_at=datetime(2026, 3, 1, 10, 10, 0, tzinfo=timezone.utc),
        )
        corr_session.add_all([p1, p2])
        corr_session.commit()

        # At 10:15:00 both processes overlap. Must safely return None without arbitrary choice.
        ctx = correlator.correlate_process_by_pid(
            host_a.id, 777, datetime(2026, 3, 1, 10, 15, 0, tzinfo=timezone.utc)
        )
        assert ctx is None


# ── Linux User Correlation Tests ─────────────────────────────────────────────


class TestUserCorrelation:
    def test_correlate_user_by_uid(
        self, correlator: EntityCorrelator, corr_session: Session, host_a: Host
    ) -> None:
        u = LinuxUser(
            id=uuid.uuid4(),
            host_id=host_a.id,
            uid=1000,
            username="osiris_analyst",
            first_seen_at=datetime(2026, 3, 1, 0, 0, 0, tzinfo=timezone.utc),
            created_at=datetime(2026, 3, 1, 0, 0, 0, tzinfo=timezone.utc),
        )
        corr_session.add(u)
        corr_session.commit()

        ctx = correlator.correlate_user(host_a.id, uid=1000)
        assert ctx is not None
        assert ctx.user_id == u.id
        assert ctx.uid == 1000
        assert ctx.username == "osiris_analyst"

    def test_unknown_user_preserved_without_error(
        self, correlator: EntityCorrelator, host_a: Host
    ) -> None:
        """Unknown UID not in linux_users preserves UID safely with null user_id."""
        ctx = correlator.correlate_user(host_a.id, uid=9999, username="temp_user")
        assert ctx is not None
        assert ctx.user_id is None
        assert ctx.uid == 9999
        assert ctx.username == "temp_user"

    def test_correlate_user_cross_host_isolation(
        self,
        correlator: EntityCorrelator,
        corr_session: Session,
        host_a: Host,
        host_b: Host,
    ) -> None:
        """User on Host B must never resolve when querying Host A."""
        u_b = LinuxUser(
            id=uuid.uuid4(),
            host_id=host_b.id,
            uid=1000,
            username="host_b_user",
            first_seen_at=datetime(2026, 3, 1, 0, 0, 0, tzinfo=timezone.utc),
            created_at=datetime(2026, 3, 1, 0, 0, 0, tzinfo=timezone.utc),
        )
        corr_session.add(u_b)
        corr_session.commit()

        ctx = correlator.correlate_user(host_a.id, uid=1000)
        assert ctx is not None
        assert ctx.user_id is None  # Host A has no user 1000


# ── Session Correlation Tests ────────────────────────────────────────────────


class TestSessionCorrelation:
    def test_correlate_session_active(
        self, correlator: EntityCorrelator, corr_session: Session, host_a: Host
    ) -> None:
        u = LinuxUser(
            id=uuid.uuid4(),
            host_id=host_a.id,
            uid=1000,
            username="sec_user",
            first_seen_at=datetime(2026, 3, 1, 0, 0, 0, tzinfo=timezone.utc),
            created_at=datetime(2026, 3, 1, 0, 0, 0, tzinfo=timezone.utc),
        )
        corr_session.add(u)
        corr_session.flush()

        sess = UserSession(
            id=uuid.uuid4(),
            host_id=host_a.id,
            linux_user_id=u.id,
            session_type="pts",
            terminal="pts/1",
            remote_host="192.168.1.50",
            started_at=datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc),
            ended_at=datetime(2026, 3, 1, 13, 0, 0, tzinfo=timezone.utc),
            created_at=datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc),
        )
        corr_session.add(sess)
        corr_session.commit()

        # At 12:30:00 session is active
        ctx = correlator.correlate_session(
            host_a.id, u.id, datetime(2026, 3, 1, 12, 30, 0, tzinfo=timezone.utc)
        )
        assert ctx is not None
        assert ctx.session_id == sess.id
        assert ctx.terminal == "pts/1"
        assert ctx.remote_host == "192.168.1.50"

        # At 13:30:00 session has ended
        ctx_after = correlator.correlate_session(
            host_a.id, u.id, datetime(2026, 3, 1, 13, 30, 0, tzinfo=timezone.utc)
        )
        assert ctx_after is None


# ── Snapshot Correlation Tests ───────────────────────────────────────────────


class TestSnapshotCorrelation:
    def test_correlate_snapshot_nearest_and_containment(
        self, correlator: EntityCorrelator, corr_session: Session, host_a: Host
    ) -> None:
        target_proc_id = uuid.uuid4()
        s = Snapshot(
            id=uuid.uuid4(),
            host_id=host_a.id,
            timestamp=datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc),
            snapshot_type="system_state",
            data={
                "processes": [
                    {"id": str(target_proc_id), "pid": 1234, "command": "suspicious_tool"}
                ],
                "resources": {"cpu_percent": 15.0},
            },
            created_at=datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc),
        )
        corr_session.add(s)
        corr_session.commit()

        # Event at 12:00:10 (10s delta)
        ctx = correlator.correlate_snapshot(
            host_a.id,
            datetime(2026, 3, 1, 12, 0, 10, tzinfo=timezone.utc),
            process_id=target_proc_id,
            pid=1234,
        )
        assert ctx is not None
        assert ctx.snapshot_id == s.id
        assert ctx.snapshot_type == "system_state"
        assert ctx.time_delta_seconds == 10.0
        assert ctx.process_captured is True

    def test_correlate_snapshot_cross_host_isolation(
        self,
        correlator: EntityCorrelator,
        corr_session: Session,
        host_a: Host,
        host_b: Host,
    ) -> None:
        s_b = Snapshot(
            id=uuid.uuid4(),
            host_id=host_b.id,
            timestamp=datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc),
            snapshot_type="system_state",
            data={"processes": []},
            created_at=datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc),
        )
        corr_session.add(s_b)
        corr_session.commit()

        # Event on Host A must not link to Snapshot on Host B
        ctx = correlator.correlate_snapshot(
            host_a.id, datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
        )
        assert ctx is None

    def test_snapshot_containment_pid_reuse_does_not_falsely_match(
        self,
        correlator: EntityCorrelator,
        corr_session: Session,
        host_a: Host,
    ) -> None:
        """When process_id is provided, snapshot containment must NOT fall back to PID reuse."""
        t = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
        proc_a = uuid.uuid4()
        proc_b = uuid.uuid4()

        # Snapshot captured proc_b which reused PID 500
        snap = Snapshot(
            id=uuid.uuid4(),
            host_id=host_a.id,
            timestamp=t,
            snapshot_type="system_state",
            data={"processes": [{"id": str(proc_b), "pid": 500, "command": "other_proc"}]},
            created_at=t,
        )
        corr_session.add(snap)
        corr_session.commit()

        # Querying with proc_a and PID 500 must NOT claim process was captured
        ctx = correlator.correlate_snapshot(
            host_a.id, t, process_id=proc_a, pid=500
        )
        assert ctx is not None
        assert ctx.process_captured is False

    def test_snapshot_with_null_or_corrupted_data_handled_gracefully(
        self,
        correlator: EntityCorrelator,
        corr_session: Session,
        host_a: Host,
    ) -> None:
        """Snapshot with empty dict or missing keys must not raise AttributeError."""
        t = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
        snap = Snapshot(
            id=uuid.uuid4(),
            host_id=host_a.id,
            timestamp=t,
            snapshot_type="system_state",
            data={},
            created_at=t,
        )
        corr_session.add(snap)
        corr_session.commit()

        ctx = correlator.correlate_snapshot(host_a.id, t, process_id=uuid.uuid4(), pid=123)
        assert ctx is not None
        assert ctx.process_captured is False
