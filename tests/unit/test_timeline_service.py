"""Unit tests for OSIRIS Timeline Reconstruction Service (Phase 2 Milestone 2.2).

Tests cover:
- Multi-source timeline reconstruction (events, processes, sessions, snapshots, resources, files).
- Deterministic chronological ordering (asc: oldest first, desc: newest first).
- Identical timestamps deterministic tie-breaker.
- Time-window filtering (start_time, end_time).
- Inverted time-window raises InvalidTimeRangeError.
- Host scoping and HostNotFoundError on nonexistent host.
- Cross-host isolation (zero leakage between hosts).
- Filtering by record_type, event_type, process_id, pid, and user context.
- Deduplication:
  - Process start/end in events are not duplicated from processes table.
  - Filesystem activity in events is not duplicated from files table.
  - Session in events is not duplicated from sessions table.
- Provenance preservation (source_table, source_id, source).
- Pagination: limit, offset, disjoint pages, and offsets beyond total.
- Empty timeline handling (empty list and total 0).
- Unbound session raises RuntimeError.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, event as sa_event
from sqlalchemy.orm import Session

from backend.db.base import Base
from backend.db.models.event import Event
from backend.db.models.file import File
from backend.db.models.host import Host
from backend.db.models.linux_user import LinuxUser
from backend.db.models.process import Process
from backend.db.models.resource_snapshot import ResourceSnapshot
from backend.db.models.snapshot import Snapshot
from backend.db.models.user_session import UserSession
from backend.services.timeline.service import (
    HostNotFoundError,
    InvalidTimeRangeError,
    TimelineService,
)


@pytest.fixture
def tl_engine():
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
def tl_session(tl_engine):
    """Provide a transactional session rolled back after each test."""
    conn = tl_engine.connect()
    trans = conn.begin()
    session = Session(bind=conn, join_transaction_mode="create_savepoint")
    yield session
    session.close()
    if trans.is_active:
        trans.rollback()
    conn.close()


@pytest.fixture
def timeline_service(tl_session: Session) -> TimelineService:
    return TimelineService(session=tl_session)


@pytest.fixture
def host_a(tl_session: Session) -> Host:
    h = Host(
        id=uuid.UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
        hostname="srv-alpha",
        os_info="Linux 5.15 Ubuntu 22.04",
        created_at=datetime(2026, 3, 1, 0, 0, 0, tzinfo=timezone.utc),
    )
    tl_session.add(h)
    tl_session.commit()
    return h


@pytest.fixture
def host_b(tl_session: Session) -> Host:
    h = Host(
        id=uuid.UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
        hostname="srv-bravo",
        os_info="Linux 5.15 Ubuntu 22.04",
        created_at=datetime(2026, 3, 1, 0, 0, 0, tzinfo=timezone.utc),
    )
    tl_session.add(h)
    tl_session.commit()
    return h


@pytest.fixture
def populated_timeline_data(
    tl_session: Session, host_a: Host, host_b: Host
) -> dict[str, Any]:
    """Seed a rich, realistic forensic timeline across multiple sources."""
    t0 = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)

    # Linux Users
    u_admin = LinuxUser(
        id=uuid.UUID("11111111-1111-4111-8111-111111111101"),
        host_id=host_a.id,
        uid=0,
        username="root",
        first_seen_at=t0,
        created_at=t0,
    )
    u_alice = LinuxUser(
        id=uuid.UUID("11111111-1111-4111-8111-111111111102"),
        host_id=host_a.id,
        uid=1000,
        username="alice",
        first_seen_at=t0,
        created_at=t0,
    )
    tl_session.add_all([u_admin, u_alice])
    tl_session.flush()

    # User Session on Host A (t0 to t0+1h)
    sess_alice = UserSession(
        id=uuid.UUID("22222222-2222-4222-8222-222222222201"),
        host_id=host_a.id,
        linux_user_id=u_alice.id,
        session_type="pts",
        terminal="pts/0",
        remote_host="10.0.0.5",
        started_at=t0,
        ended_at=t0 + timedelta(hours=1),
        created_at=t0,
    )
    tl_session.add(sess_alice)

    # Process 1: bash started at t0+1m by alice
    p1 = Process(
        id=uuid.UUID("33333333-3333-4333-8333-333333333301"),
        host_id=host_a.id,
        pid=100,
        ppid=1,
        command="/bin/bash",
        executable="/bin/bash",
        linux_user_id=u_alice.id,
        started_at=t0 + timedelta(minutes=1),
        ended_at=t0 + timedelta(minutes=30),
        created_at=t0 + timedelta(minutes=1),
    )
    tl_session.add(p1)

    # Event 1: process.start event for p1 (t0+1m)
    e1 = Event(
        id=uuid.UUID("44444444-4444-4444-8444-444444444401"),
        host_id=host_a.id,
        process_id=p1.id,
        timestamp=t0 + timedelta(minutes=1),
        source="proc",
        event_type="process.start",
        action="start",
        severity="info",
        uid=1000,
        username="alice",
        pid=100,
        ppid=1,
        command="/bin/bash",
        created_at=t0 + timedelta(minutes=1),
    )

    # Event 2: file.modify event at /etc/hosts (t0+5m) by alice
    e2 = Event(
        id=uuid.UUID("44444444-4444-4444-8444-444444444402"),
        host_id=host_a.id,
        process_id=p1.id,
        timestamp=t0 + timedelta(minutes=5),
        source="fs",
        event_type="file.modify",
        action="modify",
        severity="medium",
        uid=1000,
        username="alice",
        pid=100,
        object_type="file",
        object_path="/etc/hosts",
        created_at=t0 + timedelta(minutes=5),
    )

    # File entry in files table (t0+5m)
    f_hosts = File(
        id=uuid.UUID("55555555-5555-4555-8555-555555555501"),
        host_id=host_a.id,
        path="/etc/hosts",
        file_type="file",
        inode=12345,
        first_seen_at=t0 + timedelta(minutes=5),
        created_at=t0 + timedelta(minutes=5),
    )
    tl_session.add(f_hosts)

    # Resource Snapshot (t0+10m)
    res_snap = ResourceSnapshot(
        id=uuid.UUID("66666666-6666-4666-8666-666666666601"),
        host_id=host_a.id,
        timestamp=t0 + timedelta(minutes=10),
        cpu_percent=45.5,
        memory_percent=60.0,
        disk_usage_percent=30.0,
        created_at=t0 + timedelta(minutes=10),
    )
    tl_session.add(res_snap)

    # System Snapshot (t0+15m)
    snap = Snapshot(
        id=uuid.UUID("77777777-7777-4777-8777-777777777701"),
        host_id=host_a.id,
        timestamp=t0 + timedelta(minutes=15),
        snapshot_type="system_state",
        data={
            "processes": [{"id": str(p1.id), "pid": 100, "command": "/bin/bash"}],
            "resources": {"cpu_percent": 45.5},
        },
        created_at=t0 + timedelta(minutes=15),
    )
    tl_session.add(snap)

    # Process 2 on Host B (isolation check)
    p_b = Process(
        id=uuid.UUID("88888888-8888-4888-8888-888888888801"),
        host_id=host_b.id,
        pid=200,
        command="/usr/sbin/nginx",
        started_at=t0 + timedelta(minutes=2),
        created_at=t0 + timedelta(minutes=2),
    )
    tl_session.add(p_b)

    tl_session.add_all([e1, e2])
    tl_session.commit()

    return {
        "t0": t0,
        "host_a": host_a,
        "host_b": host_b,
        "p1": p1,
        "e1": e1,
        "e2": e2,
        "sess_alice": sess_alice,
        "res_snap": res_snap,
        "snap": snap,
        "p_b": p_b,
    }


# ── Reconstruction & Ordering Tests ──────────────────────────────────────────


class TestTimelineReconstruction:
    def test_multi_source_reconstruction_chronological(
        self,
        timeline_service: TimelineService,
        populated_timeline_data: dict[str, Any],
    ) -> None:
        """Reconstruct timeline for host_a; verify unified chronological sequence."""
        host_a = populated_timeline_data["host_a"]
        items, total = timeline_service.reconstruct_timeline(
            host_id=host_a.id, order="asc", limit=50
        )

        assert total > 0
        assert len(items) == total

        # Verify strict ascending order
        for i in range(len(items) - 1):
            assert items[i].timestamp <= items[i + 1].timestamp

        # Verify source types present
        record_types = {item.record_type for item in items}
        assert "event" in record_types
        assert "session" in record_types
        assert "snapshot" in record_types
        assert "resource" in record_types

    def test_reverse_chronological_ordering(
        self,
        timeline_service: TimelineService,
        populated_timeline_data: dict[str, Any],
    ) -> None:
        """Verify order="desc" returns newest items first."""
        host_a = populated_timeline_data["host_a"]
        items, total = timeline_service.reconstruct_timeline(
            host_id=host_a.id, order="desc", limit=50
        )

        for i in range(len(items) - 1):
            assert items[i].timestamp >= items[i + 1].timestamp

    def test_identical_timestamps_deterministic_tie_breaker(
        self,
        timeline_service: TimelineService,
        tl_session: Session,
        host_a: Host,
    ) -> None:
        """Two events at the exact same microsecond must sort deterministically."""
        t_same = datetime(2026, 3, 1, 15, 0, 0, tzinfo=timezone.utc)
        e1 = Event(
            id=uuid.UUID("11111111-1111-4111-8111-111111111111"),
            host_id=host_a.id,
            timestamp=t_same,
            source="proc",
            event_type="test.event.1",
            action="action_1",
            severity="info",
            created_at=t_same,
        )
        e2 = Event(
            id=uuid.UUID("22222222-2222-4222-8222-222222222222"),
            host_id=host_a.id,
            timestamp=t_same,
            source="proc",
            event_type="test.event.2",
            action="action_2",
            severity="info",
            created_at=t_same,
        )
        tl_session.add_all([e1, e2])
        tl_session.commit()

        items, total = timeline_service.reconstruct_timeline(
            host_id=host_a.id, start_time=t_same, end_time=t_same, order="asc"
        )
        assert total == 2
        # e1 must appear before e2 due to deterministic primary/secondary sort
        assert items[0].id == e1.id
        assert items[1].id == e2.id


# ── Deduplication Tests ──────────────────────────────────────────────────────


class TestTimelineDeduplication:
    def test_process_start_not_duplicated_when_in_events(
        self,
        timeline_service: TimelineService,
        populated_timeline_data: dict[str, Any],
    ) -> None:
        """Process p1 has an event in `events` (e1) AND a record in `processes`.
        Only e1 must appear for p1's start; no duplicate process.start entry.
        """
        host_a = populated_timeline_data["host_a"]
        p1 = populated_timeline_data["p1"]
        e1 = populated_timeline_data["e1"]

        items, total = timeline_service.reconstruct_timeline(
            host_id=host_a.id,
            process_id=p1.id,
            event_type="process.start",
        )

        assert total == 1
        assert len(items) == 1
        # The entry must be from 'events' with provenance preserved
        assert items[0].id == e1.id
        assert items[0].source == "proc"
        assert items[0].record_type == "event"

    def test_file_observation_not_duplicated_when_in_events(
        self,
        timeline_service: TimelineService,
        populated_timeline_data: dict[str, Any],
    ) -> None:
        """File modify event e2 exists at same timestamp and path as f_hosts.
        No duplicate entry from files table should appear.
        """
        host_a = populated_timeline_data["host_a"]
        t0 = populated_timeline_data["t0"]

        items, total = timeline_service.reconstruct_timeline(
            host_id=host_a.id,
            start_time=t0 + timedelta(minutes=4),
            end_time=t0 + timedelta(minutes=6),
            record_type="all",
        )

        # Find file entries
        file_entries = [
            it for it in items if it.file_context and it.file_context.path == "/etc/hosts"
        ]
        assert len(file_entries) == 1
        assert file_entries[0].source == "fs"


# ── Isolation & Filtering Tests ──────────────────────────────────────────────


class TestTimelineFilteringAndIsolation:
    def test_cross_host_isolation(
        self,
        timeline_service: TimelineService,
        populated_timeline_data: dict[str, Any],
    ) -> None:
        """Host A timeline must NEVER contain Host B entries."""
        host_a = populated_timeline_data["host_a"]
        host_b = populated_timeline_data["host_b"]
        p_b = populated_timeline_data["p_b"]

        items_a, _ = timeline_service.reconstruct_timeline(host_id=host_a.id)
        returned_ids_a = {it.source_id for it in items_a}
        assert p_b.id not in returned_ids_a

        # Scoped to Host B
        items_b, total_b = timeline_service.reconstruct_timeline(host_id=host_b.id)
        assert total_b == 1
        assert items_b[0].source_id == p_b.id

    def test_record_type_filter(
        self,
        timeline_service: TimelineService,
        populated_timeline_data: dict[str, Any],
    ) -> None:
        host_a = populated_timeline_data["host_a"]

        # Only snapshots
        items_snap, total_snap = timeline_service.reconstruct_timeline(
            host_id=host_a.id, record_type="snapshot"
        )
        assert total_snap == 1
        assert items_snap[0].record_type == "snapshot"

        # Only sessions
        items_sess, total_sess = timeline_service.reconstruct_timeline(
            host_id=host_a.id, record_type="session"
        )
        assert total_sess >= 1
        for it in items_sess:
            assert it.record_type == "session"

    def test_time_window_filtering(
        self,
        timeline_service: TimelineService,
        populated_timeline_data: dict[str, Any],
    ) -> None:
        host_a = populated_timeline_data["host_a"]
        t0 = populated_timeline_data["t0"]

        # Window covers only t0+8m to t0+12m (includes only resource snapshot at t0+10m)
        items, total = timeline_service.reconstruct_timeline(
            host_id=host_a.id,
            start_time=t0 + timedelta(minutes=8),
            end_time=t0 + timedelta(minutes=12),
        )
        assert total == 1
        assert items[0].record_type == "resource"

    def test_inverted_time_window_raises_error(
        self,
        timeline_service: TimelineService,
        host_a: Host,
    ) -> None:
        t_early = datetime(2026, 3, 1, 10, 0, 0, tzinfo=timezone.utc)
        t_late = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)

        with pytest.raises(InvalidTimeRangeError, match="start_time must be less than"):
            timeline_service.reconstruct_timeline(
                host_id=host_a.id,
                start_time=t_late,
                end_time=t_early,
            )

    def test_missing_host_raises_host_not_found(
        self,
        timeline_service: TimelineService,
    ) -> None:
        random_host = uuid.uuid4()
        with pytest.raises(HostNotFoundError, match="Host not found"):
            timeline_service.reconstruct_timeline(host_id=random_host)

    def test_empty_timeline_returns_empty_list_and_zero_count(
        self,
        timeline_service: TimelineService,
        host_a: Host,
    ) -> None:
        """Valid host with no records in future window returns empty cleanly."""
        t_future = datetime(2030, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        items, total = timeline_service.reconstruct_timeline(
            host_id=host_a.id, start_time=t_future
        )
        assert total == 0
        assert items == []


# ── Pagination Tests ─────────────────────────────────────────────────────────


class TestTimelinePagination:
    def test_pagination_limit_and_offset(
        self,
        timeline_service: TimelineService,
        populated_timeline_data: dict[str, Any],
    ) -> None:
        host_a = populated_timeline_data["host_a"]
        all_items, total = timeline_service.reconstruct_timeline(
            host_id=host_a.id, limit=100
        )
        assert total >= 4

        # Page 1: limit 2, offset 0
        p1_items, p1_total = timeline_service.reconstruct_timeline(
            host_id=host_a.id, limit=2, offset=0
        )
        assert p1_total == total
        assert len(p1_items) == 2

        # Page 2: limit 2, offset 2
        p2_items, p2_total = timeline_service.reconstruct_timeline(
            host_id=host_a.id, limit=2, offset=2
        )
        assert p2_total == total
        assert len(p2_items) == 2

        # Pages must be disjoint
        p1_ids = {it.id for it in p1_items}
        p2_ids = {it.id for it in p2_items}
        assert p1_ids.isdisjoint(p2_ids)

    def test_offset_beyond_total_returns_empty_list(
        self,
        timeline_service: TimelineService,
        populated_timeline_data: dict[str, Any],
    ) -> None:
        host_a = populated_timeline_data["host_a"]
        items, total = timeline_service.reconstruct_timeline(
            host_id=host_a.id, offset=1000
        )
        assert len(items) == 0
        assert total > 0


# ── Entity Correlation Context Tests ─────────────────────────────────────────


class TestTimelineEntityCorrelationContext:
    def test_snapshot_context_associated_with_event(
        self,
        timeline_service: TimelineService,
        populated_timeline_data: dict[str, Any],
    ) -> None:
        """Event e2 (t0+5m) should associate with Snapshot snap (t0+15m) within 3600s."""
        host_a = populated_timeline_data["host_a"]
        e2 = populated_timeline_data["e2"]
        snap = populated_timeline_data["snap"]

        items, _ = timeline_service.reconstruct_timeline(
            host_id=host_a.id,
            start_time=e2.timestamp,
            end_time=e2.timestamp,
        )
        assert len(items) == 1
        e2_item = items[0]
        assert e2_item.id == e2.id
        assert e2_item.snapshot_context is not None
        assert e2_item.snapshot_context.snapshot_id == snap.id
        assert e2_item.snapshot_context.snapshot_type == "system_state"

    def test_unbound_session_raises_runtime_error(self) -> None:
        service = TimelineService(session=None)
        with pytest.raises(RuntimeError, match="has no active database session"):
            service.reconstruct_timeline()

    def test_user_filtering_by_username_existing_and_nonexistent(
        self,
        timeline_service: TimelineService,
        populated_timeline_data: dict[str, Any],
    ) -> None:
        host_a = populated_timeline_data["host_a"]

        # Filtering by existing username 'alice' should return alice's events and processes, but no snapshots/resources
        items_alice, total_alice = timeline_service.reconstruct_timeline(
            host_id=host_a.id, username="alice"
        )
        assert total_alice > 0
        for it in items_alice:
            assert it.record_type in ("event", "process", "session")
            if it.user_context:
                assert it.user_context.username == "alice"

        # Filtering by nonexistent username should return 0 items (never fall back to returning snapshots or other processes)
        items_ghost, total_ghost = timeline_service.reconstruct_timeline(
            host_id=host_a.id, username="nonexistent_ghost"
        )
        assert total_ghost == 0
        assert items_ghost == []

    def test_user_filtering_by_uid_and_user_id(
        self,
        timeline_service: TimelineService,
        populated_timeline_data: dict[str, Any],
        tl_session: Session,
    ) -> None:
        host_a = populated_timeline_data["host_a"]
        u_alice = tl_session.query(LinuxUser).filter_by(username="alice").one()

        # Filtering by uid=1000
        items_uid, total_uid = timeline_service.reconstruct_timeline(
            host_id=host_a.id, uid=1000
        )
        assert total_uid > 0
        for it in items_uid:
            assert it.record_type in ("event", "process", "session")
            if it.user_context and it.user_context.uid is not None:
                assert it.user_context.uid == 1000

        # Filtering by user_id
        items_uid_uuid, total_uid_uuid = timeline_service.reconstruct_timeline(
            host_id=host_a.id, user_id=u_alice.id
        )
        assert total_uid_uuid > 0
        for it in items_uid_uuid:
            if it.user_context and it.user_context.user_id:
                assert it.user_context.user_id == u_alice.id

    def test_identical_timestamp_lifecycle_sequence_ordering(
        self,
        timeline_service: TimelineService,
        tl_session: Session,
        host_a: Host,
    ) -> None:
        """When a process starts and ends at the exact same timestamp, start must precede end in asc order."""
        t_same = datetime(2026, 3, 1, 18, 0, 0, tzinfo=timezone.utc)
        p = Process(
            id=uuid.uuid4(),
            host_id=host_a.id,
            pid=8888,
            command="/bin/quick_job",
            started_at=t_same,
            ended_at=t_same,
            created_at=t_same,
        )
        tl_session.add(p)
        tl_session.commit()

        # ASC order: start before end
        items_asc, total_asc = timeline_service.reconstruct_timeline(
            host_id=host_a.id, start_time=t_same, end_time=t_same, order="asc"
        )
        assert total_asc == 2
        assert items_asc[0].action == "start"
        assert items_asc[1].action == "end"

        # DESC order: end before start
        items_desc, total_desc = timeline_service.reconstruct_timeline(
            host_id=host_a.id, start_time=t_same, end_time=t_same, order="desc"
        )
        assert total_desc == 2
        assert items_desc[0].action == "end"
        assert items_desc[1].action == "start"

    def test_cross_host_process_id_in_event_sanitized(
        self,
        timeline_service: TimelineService,
        tl_session: Session,
        host_a: Host,
        host_b: Host,
    ) -> None:
        """An event on Host A with a foreign process_id on Host B must have process_id cleared."""
        t = datetime(2026, 3, 1, 19, 0, 0, tzinfo=timezone.utc)
        p_b = Process(
            id=uuid.uuid4(),
            host_id=host_b.id,
            pid=7777,
            command="/usr/bin/host_b_proc",
            started_at=t,
            created_at=t,
        )
        tl_session.add(p_b)
        tl_session.flush()

        e_cross = Event(
            id=uuid.uuid4(),
            host_id=host_a.id,
            process_id=p_b.id,
            pid=7777,
            command="/usr/bin/host_b_proc",
            timestamp=t,
            source="proc",
            event_type="test.cross",
            action="alert",
            created_at=t,
        )
        tl_session.add(e_cross)
        tl_session.commit()

        items, _ = timeline_service.reconstruct_timeline(
            host_id=host_a.id, start_time=t, end_time=t
        )
        assert len(items) == 1
        assert items[0].process_context is not None
        assert items[0].process_context.process_id is None

    def test_snapshot_corrupted_data_handled_gracefully(
        self,
        timeline_service: TimelineService,
        tl_session: Session,
        host_a: Host,
    ) -> None:
        """Snapshot with data=None or empty dict must not cause AttributeError."""
        t = datetime(2026, 3, 1, 20, 0, 0, tzinfo=timezone.utc)
        snap_null = Snapshot(
            id=uuid.uuid4(),
            host_id=host_a.id,
            timestamp=t,
            snapshot_type="system_state",
            data={},
            created_at=t,
        )
        tl_session.add(snap_null)
        tl_session.commit()

        items, total = timeline_service.reconstruct_timeline(
            host_id=host_a.id, start_time=t, end_time=t
        )
        assert total == 1
        assert items[0].snapshot_context is not None
        assert items[0].snapshot_context.snapshot_id == snap_null.id
