"""Unit tests for OSIRIS M-2: Identity Resolution.

Tests cover:
1. Successful UID-to-username resolution.
2. Same UID present on different hosts.
3. Unresolved UID.
4. Successful PID-to-process UUID resolution.
5. PID reuse across process lifetimes.
6. Host-scoped PID resolution.
7. Events before process start.
8. Events at process start and end boundaries.
9. Events after process termination.
10. Overlapping or ambiguous process matches.
11. Missing process records.
12. Cache hits, expiry/invalidation, and PID reuse safety.
13. Production processing-path wiring.
14. Existing pure unit-processing behavior with a no-op resolver.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from sqlalchemy.orm import Session

from backend.db.models.host import Host
from backend.db.models.linux_user import LinuxUser
from backend.db.models.process import Process
from backend.services.events.process_lifecycle import ProcessLifecycleService
from backend.services.events.processor import EventProcessor
from backend.services.events.repository import EventRepository
from backend.services.events.resolver import (
    DatabaseIdentityResolver,
    IdentityResolver,
    NoOpIdentityResolver,
    _ensure_utc,
)
from backend.services.events.schemas import RawObservation
from collectors.filesystem.inotify import MockInotifyBackend
from collectors.orchestrator import CollectorOrchestrator, OrchestratorConfig
from tests.fixtures.event_fixtures import (
    FIXTURE_HOST_ID,
    FIXTURE_PROCESS_ID,
    FIXTURE_TS,
    make_process_start_observation,
)


# ── Helper Fixtures ───────────────────────────────────────────────────


@pytest.fixture
def test_host_a(db_session: Session) -> Host:
    """Create a primary test host."""
    host = Host(
        id=uuid.uuid4(),
        hostname="monitored-host-a",
        os_info="Ubuntu 22.04 LTS",
        ip_address="192.168.1.10",
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(host)
    db_session.flush()
    return host


@pytest.fixture
def test_host_b(db_session: Session) -> Host:
    """Create a secondary test host for multi-host isolation tests."""
    host = Host(
        id=uuid.uuid4(),
        hostname="monitored-host-b",
        os_info="Debian 12",
        ip_address="192.168.1.20",
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(host)
    db_session.flush()
    return host


# ── 1. Successful UID-to-username resolution ─────────────────────────


class TestUIDResolutionSuccess:
    """Requirement 4.1: Successful UID-to-username resolution."""

    def test_uid_resolves_to_username(self, db_session: Session, test_host_a: Host):
        user = LinuxUser(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            uid=1000,
            username="alice",
            first_seen_at=datetime.now(timezone.utc),
        )
        db_session.add(user)
        db_session.flush()

        resolver = DatabaseIdentityResolver(db_session, cache_ttl=0)
        resolved = resolver.resolve_user(test_host_a.id, 1000)
        assert resolved == "alice"

    def test_uid_resolves_through_event_processor(
        self, db_session: Session, test_host_a: Host
    ):
        user = LinuxUser(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            uid=1000,
            username="alice",
            first_seen_at=datetime.now(timezone.utc),
        )
        db_session.add(user)
        db_session.flush()

        processor = EventProcessor.with_database(db_session)
        obs = make_process_start_observation(
            host_id=test_host_a.id,
            uid=1000,
            username=None,
            process_id=None,
        )
        res = processor.process(obs)
        assert res.success
        assert res.event is not None
        assert res.event.username == "alice"
        assert res.event.uid == 1000

    def test_uid_resolves_whitespace_stripped(
        self, db_session: Session, test_host_a: Host
    ):
        user = LinuxUser(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            uid=1001,
            username="   bob   ",
            first_seen_at=datetime.now(timezone.utc),
        )
        db_session.add(user)
        db_session.flush()

        resolver = DatabaseIdentityResolver(db_session, cache_ttl=0)
        assert resolver.resolve_user(test_host_a.id, 1001) == "bob"


# ── 2. Same UID present on different hosts ───────────────────────────


class TestUIDMultiHostIsolation:
    """Requirement 4.2: Same UID present on different hosts."""

    def test_same_uid_different_hosts_resolve_independently(
        self, db_session: Session, test_host_a: Host, test_host_b: Host
    ):
        now = datetime.now(timezone.utc)
        user_a = LinuxUser(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            uid=1000,
            username="alice_on_a",
            first_seen_at=now,
        )
        user_b = LinuxUser(
            id=uuid.uuid4(),
            host_id=test_host_b.id,
            uid=1000,
            username="bob_on_b",
            first_seen_at=now,
        )
        db_session.add_all([user_a, user_b])
        db_session.flush()

        resolver = DatabaseIdentityResolver(db_session)
        # Host A gets Alice, Host B gets Bob
        assert resolver.resolve_user(test_host_a.id, 1000) == "alice_on_a"
        assert resolver.resolve_user(test_host_b.id, 1000) == "bob_on_b"

        # Unrelated third host with UID 1000 must NOT resolve to either
        unrelated_host_id = uuid.uuid4()
        assert resolver.resolve_user(unrelated_host_id, 1000) is None

    def test_never_resolves_uid_from_another_host(
        self, db_session: Session, test_host_a: Host, test_host_b: Host
    ):
        now = datetime.now(timezone.utc)
        # UID 1050 exists ONLY on Host B
        user_b = LinuxUser(
            id=uuid.uuid4(),
            host_id=test_host_b.id,
            uid=1050,
            username="charlie",
            first_seen_at=now,
        )
        db_session.add(user_b)
        db_session.flush()

        resolver = DatabaseIdentityResolver(db_session)
        # Querying on Host A must be None
        assert resolver.resolve_user(test_host_a.id, 1050) is None
        # Querying on Host B resolves
        assert resolver.resolve_user(test_host_b.id, 1050) == "charlie"


# ── 3. Unresolved UID ────────────────────────────────────────────────


class TestUIDUnresolved:
    """Requirement 4.3: Unresolved UID."""

    def test_missing_user_record_resolves_to_none(
        self, db_session: Session, test_host_a: Host
    ):
        resolver = DatabaseIdentityResolver(db_session, cache_ttl=0)
        assert resolver.resolve_user(test_host_a.id, 9999) is None

    def test_null_username_in_db_resolves_to_none(
        self, db_session: Session, test_host_a: Host
    ):
        user = LinuxUser(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            uid=2000,
            username=None,
            first_seen_at=datetime.now(timezone.utc),
        )
        db_session.add(user)
        db_session.flush()

        resolver = DatabaseIdentityResolver(db_session, cache_ttl=0)
        assert resolver.resolve_user(test_host_a.id, 2000) is None

    def test_empty_or_whitespace_username_in_db_resolves_to_none(
        self, db_session: Session, test_host_a: Host
    ):
        user = LinuxUser(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            uid=2001,
            username="   ",
            first_seen_at=datetime.now(timezone.utc),
        )
        db_session.add(user)
        db_session.flush()

        resolver = DatabaseIdentityResolver(db_session, cache_ttl=0)
        assert resolver.resolve_user(test_host_a.id, 2001) is None

    def test_deleted_user_record_resolves_to_none(
        self, db_session: Session, test_host_a: Host
    ):
        user = LinuxUser(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            uid=2002,
            username="temporary_user",
            first_seen_at=datetime.now(timezone.utc),
        )
        db_session.add(user)
        db_session.flush()

        resolver = DatabaseIdentityResolver(db_session, cache_ttl=0)
        assert resolver.resolve_user(test_host_a.id, 2002) == "temporary_user"

        # Simulate user deletion
        db_session.delete(user)
        db_session.flush()

        assert resolver.resolve_user(test_host_a.id, 2002) is None

    def test_negative_uid_resolves_to_none(
        self, db_session: Session, test_host_a: Host
    ):
        resolver = DatabaseIdentityResolver(db_session)
        assert resolver.resolve_user(test_host_a.id, -1) is None

    def test_event_processing_preserves_null_username_for_unresolved_uid(
        self, db_session: Session, test_host_a: Host
    ):
        processor = EventProcessor.with_database(db_session)
        obs = make_process_start_observation(
            host_id=test_host_a.id,
            uid=9999,
            username=None,
            process_id=None,
        )
        res = processor.process(obs)
        assert res.success
        assert res.event is not None
        assert res.event.username is None
        assert res.event.uid == 9999


# ── 4. Successful PID-to-process UUID resolution ─────────────────────


class TestPIDResolutionSuccess:
    """Requirement 4.4: Successful PID-to-process UUID resolution."""

    def test_pid_resolves_to_process_uuid(
        self, db_session: Session, test_host_a: Host
    ):
        base_time = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        proc = Process(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            pid=1234,
            ppid=1,
            command="/usr/bin/nginx",
            started_at=base_time,
            ended_at=base_time + timedelta(hours=2),
            created_at=base_time,
        )
        db_session.add(proc)
        db_session.flush()

        resolver = DatabaseIdentityResolver(db_session, cache_ttl=0)
        event_time = base_time + timedelta(minutes=30)
        resolved_id = resolver.resolve_process(test_host_a.id, 1234, event_time)
        assert resolved_id == proc.id

    def test_pid_resolves_in_event_processor_and_preserves_pid_ppid(
        self, db_session: Session, test_host_a: Host
    ):
        base_time = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        proc = Process(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            pid=1234,
            ppid=10,
            command="/usr/bin/nginx",
            started_at=base_time,
            ended_at=None,
            created_at=base_time,
        )
        db_session.add(proc)
        db_session.flush()

        processor = EventProcessor.with_database(db_session)
        obs = make_process_start_observation(
            host_id=test_host_a.id,
            pid=1234,
            ppid=10,
            observed_at=base_time + timedelta(minutes=5),
            process_id=None,
        )
        res = processor.process(obs)
        assert res.success
        assert res.event is not None
        assert res.event.process_id == proc.id
        assert res.event.pid == 1234
        assert res.event.ppid == 10


# ── 5. PID reuse across process lifetimes ─────────────────────────────


class TestPIDReuseAcrossLifetimes:
    """Requirement 4.5: PID reuse across process lifetimes."""

    def test_pid_reuse_sequences(
        self, db_session: Session, test_host_a: Host
    ):
        t0 = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        t1 = datetime(2026, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 1, 15, 11, 0, 0, tzinfo=timezone.utc)
        t3 = datetime(2026, 1, 15, 11, 30, 0, tzinfo=timezone.utc)
        t4 = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

        # Process 1: PID 5000 running from 10:00 to 10:30
        proc1 = Process(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            pid=5000,
            ppid=1,
            command="/usr/bin/worker-v1",
            started_at=t0,
            ended_at=t1,
            created_at=t0,
        )
        # Process 2: PID 5000 reused, running from 11:00 to 11:30
        proc2 = Process(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            pid=5000,
            ppid=1,
            command="/usr/bin/worker-v2",
            started_at=t2,
            ended_at=t3,
            created_at=t2,
        )
        # Process 3: PID 5000 reused again, running from 12:00 onwards (open-ended)
        proc3 = Process(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            pid=5000,
            ppid=1,
            command="/usr/bin/worker-v3",
            started_at=t4,
            ended_at=None,
            created_at=t4,
        )
        db_session.add_all([proc1, proc2, proc3])
        db_session.flush()

        resolver = DatabaseIdentityResolver(db_session, cache_ttl=300.0)

        # 1. Event during Process 1 lifetime -> proc1
        ev_p1 = resolver.resolve_process(
            test_host_a.id, 5000, t0 + timedelta(minutes=15)
        )
        assert ev_p1 == proc1.id

        # 2. Event in dead window between Process 1 and Process 2 (10:45) -> None
        ev_gap1 = resolver.resolve_process(
            test_host_a.id, 5000, t1 + timedelta(minutes=15)
        )
        assert ev_gap1 is None

        # 3. Event during Process 2 lifetime (11:15) -> proc2
        ev_p2 = resolver.resolve_process(
            test_host_a.id, 5000, t2 + timedelta(minutes=15)
        )
        assert ev_p2 == proc2.id

        # 4. Event in dead window between Process 2 and Process 3 (11:45) -> None
        ev_gap2 = resolver.resolve_process(
            test_host_a.id, 5000, t3 + timedelta(minutes=15)
        )
        assert ev_gap2 is None

        # 5. Event during Process 3 lifetime (12:30) -> proc3
        ev_p3 = resolver.resolve_process(
            test_host_a.id, 5000, t4 + timedelta(minutes=30)
        )
        assert ev_p3 == proc3.id


# ── 6. Host-scoped PID resolution ────────────────────────────────────


class TestPIDHostScopedResolution:
    """Requirement 4.6: Host-scoped PID resolution."""

    def test_same_pid_on_different_hosts_resolves_to_correct_host_process(
        self, db_session: Session, test_host_a: Host, test_host_b: Host
    ):
        base_time = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        proc_a = Process(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            pid=777,
            command="service_a",
            started_at=base_time,
            ended_at=base_time + timedelta(hours=1),
            created_at=base_time,
        )
        proc_b = Process(
            id=uuid.uuid4(),
            host_id=test_host_b.id,
            pid=777,
            command="service_b",
            started_at=base_time,
            ended_at=base_time + timedelta(hours=1),
            created_at=base_time,
        )
        db_session.add_all([proc_a, proc_b])
        db_session.flush()

        resolver = DatabaseIdentityResolver(db_session)
        ts = base_time + timedelta(minutes=20)

        # Host A query gets Process A, never Process B
        assert resolver.resolve_process(test_host_a.id, 777, ts) == proc_a.id
        # Host B query gets Process B, never Process A
        assert resolver.resolve_process(test_host_b.id, 777, ts) == proc_b.id

        # Third host with same PID and timestamp must return None
        unrelated_host = uuid.uuid4()
        assert resolver.resolve_process(unrelated_host, 777, ts) is None


# ── 7. Events before process start ───────────────────────────────────


class TestEventsBeforeProcessStart:
    """Requirement 4.7: Events before process start."""

    def test_event_strictly_before_started_at_resolves_to_none(
        self, db_session: Session, test_host_a: Host
    ):
        t_start = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        proc = Process(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            pid=888,
            command="daemon",
            started_at=t_start,
            ended_at=t_start + timedelta(hours=1),
            created_at=t_start,
        )
        db_session.add(proc)
        db_session.flush()

        resolver = DatabaseIdentityResolver(db_session, cache_ttl=0)

        # 1 microsecond before start
        just_before = t_start - timedelta(microseconds=1)
        assert resolver.resolve_process(test_host_a.id, 888, just_before) is None

        # 1 hour before start
        way_before = t_start - timedelta(hours=1)
        assert resolver.resolve_process(test_host_a.id, 888, way_before) is None


# ── 8. Events at process start and end boundaries ─────────────────────


class TestEventsAtProcessBoundaries:
    """Requirement 4.8: Events at process start and end boundaries."""

    def test_exact_start_and_end_boundaries_resolve_successfully(
        self, db_session: Session, test_host_a: Host
    ):
        t_start = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        t_end = datetime(2026, 1, 15, 11, 0, 0, tzinfo=timezone.utc)

        proc = Process(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            pid=999,
            command="batch-job",
            started_at=t_start,
            ended_at=t_end,
            created_at=t_start,
        )
        db_session.add(proc)
        db_session.flush()

        resolver = DatabaseIdentityResolver(db_session, cache_ttl=0)

        # Exact start boundary: process.started_at <= event.timestamp
        assert resolver.resolve_process(test_host_a.id, 999, t_start) == proc.id

        # Exact end boundary: event.timestamp <= process.ended_at
        assert resolver.resolve_process(test_host_a.id, 999, t_end) == proc.id


# ── 9. Events after process termination ──────────────────────────────


class TestEventsAfterProcessTermination:
    """Requirement 4.9: Events after process termination."""

    def test_event_strictly_after_ended_at_resolves_to_none(
        self, db_session: Session, test_host_a: Host
    ):
        t_start = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        t_end = datetime(2026, 1, 15, 11, 0, 0, tzinfo=timezone.utc)

        proc = Process(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            pid=1111,
            command="short-task",
            started_at=t_start,
            ended_at=t_end,
            created_at=t_start,
        )
        db_session.add(proc)
        db_session.flush()

        resolver = DatabaseIdentityResolver(db_session, cache_ttl=0)

        # 1 microsecond after termination
        just_after = t_end + timedelta(microseconds=1)
        assert resolver.resolve_process(test_host_a.id, 1111, just_after) is None

        # 1 hour after termination
        way_after = t_end + timedelta(hours=1)
        assert resolver.resolve_process(test_host_a.id, 1111, way_after) is None


# ── 10. Overlapping or ambiguous process matches ──────────────────────


class TestOverlappingAmbiguousMatches:
    """Requirement 4.10: Overlapping or ambiguous process matches."""

    def test_overlapping_processes_resolve_safely_to_none(
        self, db_session: Session, test_host_a: Host
    ):
        t0 = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        t1 = datetime(2026, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 1, 15, 11, 0, 0, tzinfo=timezone.utc)
        t3 = datetime(2026, 1, 15, 11, 30, 0, tzinfo=timezone.utc)

        # Process 1: 10:00 to 11:00
        proc1 = Process(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            pid=2222,
            command="overlap1",
            started_at=t0,
            ended_at=t2,
            created_at=t0,
        )
        # Process 2: 10:30 to 11:30 (overlaps with proc1 between 10:30 and 11:00)
        proc2 = Process(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            pid=2222,
            command="overlap2",
            started_at=t1,
            ended_at=t3,
            created_at=t1,
        )
        db_session.add_all([proc1, proc2])
        db_session.flush()

        resolver = DatabaseIdentityResolver(db_session, cache_ttl=0)

        # Event in unambiguous proc1 window (10:15) -> proc1
        assert resolver.resolve_process(
            test_host_a.id, 2222, t0 + timedelta(minutes=15)
        ) == proc1.id

        # Event in overlapping ambiguous window (10:45) -> None (never arbitrarily picks)
        assert resolver.resolve_process(
            test_host_a.id, 2222, t1 + timedelta(minutes=15)
        ) is None

        # Event in unambiguous proc2 window (11:15) -> proc2
        assert resolver.resolve_process(
            test_host_a.id, 2222, t2 + timedelta(minutes=15)
        ) == proc2.id


# ── 11. Missing process records ──────────────────────────────────────


class TestMissingProcessRecords:
    """Requirement 4.11: Missing process records."""

    def test_missing_pid_resolves_to_none_and_preserves_pid(
        self, db_session: Session, test_host_a: Host
    ):
        processor = EventProcessor.with_database(db_session)
        obs = make_process_start_observation(
            host_id=test_host_a.id,
            pid=99999,
            ppid=88888,
            observed_at=datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
            process_id=None,
        )
        res = processor.process(obs)
        assert res.success
        assert res.event is not None
        assert res.event.process_id is None
        assert res.event.pid == 99999
        assert res.event.ppid == 88888

    def test_none_pid_resolves_to_none(
        self, db_session: Session, test_host_a: Host
    ):
        resolver = DatabaseIdentityResolver(db_session)
        assert resolver.resolve_process(
            test_host_a.id, -1, datetime.now(timezone.utc)
        ) is None


# ── 12. Cache hits, expiry/invalidation, and PID reuse safety ─────────


class TestCacheBehaviorAndInvalidation:
    """Requirement 4.12: Cache hits, expiry/invalidation, and PID reuse safety."""

    def test_user_cache_hits_misses_and_expiry(
        self, db_session: Session, test_host_a: Host
    ):
        user = LinuxUser(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            uid=3000,
            username="cached_user",
            first_seen_at=datetime.now(timezone.utc),
        )
        db_session.add(user)
        db_session.flush()

        current_time = 1000.0

        def mock_clock() -> float:
            return current_time

        resolver = DatabaseIdentityResolver(
            db_session, cache_ttl=10.0, clock=mock_clock
        )

        # 1. First lookup: cache miss
        assert resolver.resolve_user(test_host_a.id, 3000) == "cached_user"
        assert resolver.user_cache_misses == 1
        assert resolver.user_cache_hits == 0

        # 2. Second lookup at t=1005: cache hit
        current_time = 1005.0
        assert resolver.resolve_user(test_host_a.id, 3000) == "cached_user"
        assert resolver.user_cache_misses == 1
        assert resolver.user_cache_hits == 1

        # 3. Third lookup at t=1015 (> 10s TTL): expired, cache miss
        current_time = 1015.0
        assert resolver.resolve_user(test_host_a.id, 3000) == "cached_user"
        assert resolver.user_cache_misses == 2
        assert resolver.user_cache_hits == 1

    def test_user_cache_manual_invalidation(
        self, db_session: Session, test_host_a: Host
    ):
        user = LinuxUser(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            uid=3001,
            username="invalidate_me",
            first_seen_at=datetime.now(timezone.utc),
        )
        db_session.add(user)
        db_session.flush()

        resolver = DatabaseIdentityResolver(db_session, cache_ttl=60.0)
        assert resolver.resolve_user(test_host_a.id, 3001) == "invalidate_me"
        assert resolver.user_cache_misses == 1

        # Explicit invalidation
        resolver.invalidate_user(test_host_a.id, 3001)
        assert resolver.resolve_user(test_host_a.id, 3001) == "invalidate_me"
        assert resolver.user_cache_misses == 2

        # Clear entire cache
        resolver.clear_cache()
        assert resolver.user_cache_misses == 0
        assert resolver.user_cache_hits == 0

    def test_process_cache_pid_reuse_safety_and_hits(
        self, db_session: Session, test_host_a: Host
    ):
        t0 = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        t1 = datetime(2026, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 1, 15, 11, 0, 0, tzinfo=timezone.utc)
        t3 = datetime(2026, 1, 15, 11, 30, 0, tzinfo=timezone.utc)

        proc1 = Process(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            pid=4000,
            command="proc-early",
            started_at=t0,
            ended_at=t1,
            created_at=t0,
        )
        proc2 = Process(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            pid=4000,
            command="proc-later",
            started_at=t2,
            ended_at=t3,
            created_at=t2,
        )
        db_session.add_all([proc1, proc2])
        db_session.flush()

        current_time = 1000.0

        def mock_clock() -> float:
            return current_time

        resolver = DatabaseIdentityResolver(
            db_session, cache_ttl=60.0, clock=mock_clock
        )

        # Lookup 1: Event for proc1 at 10:15 -> cache miss, resolves proc1
        res1 = resolver.resolve_process(
            test_host_a.id, 4000, t0 + timedelta(minutes=15)
        )
        assert res1 == proc1.id
        assert resolver.process_cache_misses == 1
        assert resolver.process_cache_hits == 0

        # Lookup 2: Event for proc1 at 10:20 -> cache hit!
        res2 = resolver.resolve_process(
            test_host_a.id, 4000, t0 + timedelta(minutes=20)
        )
        assert res2 == proc1.id
        assert resolver.process_cache_misses == 1
        assert resolver.process_cache_hits == 1

        # Lookup 3: Event for reused PID at 11:15 (Process 2) ->
        # Cached Process 1 does NOT match 11:15 because of lifetime bounds.
        # Must NOT return proc1! Must query DB and return proc2!
        res3 = resolver.resolve_process(
            test_host_a.id, 4000, t2 + timedelta(minutes=15)
        )
        assert res3 == proc2.id
        assert resolver.process_cache_misses == 2

        # Lookup 4: Event for proc2 at 11:20 -> cache hit for proc2!
        res4 = resolver.resolve_process(
            test_host_a.id, 4000, t2 + timedelta(minutes=20)
        )
        assert res4 == proc2.id
        assert resolver.process_cache_hits == 2

    def test_process_cache_manual_invalidation(
        self, db_session: Session, test_host_a: Host
    ):
        t0 = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        proc = Process(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            pid=4001,
            command="cmd",
            started_at=t0,
            ended_at=None,
            created_at=t0,
        )
        db_session.add(proc)
        db_session.flush()

        resolver = DatabaseIdentityResolver(db_session, cache_ttl=60.0)
        resolver.resolve_process(test_host_a.id, 4001, t0 + timedelta(minutes=5))
        assert resolver.process_cache_misses == 1

        # Cache hit
        resolver.resolve_process(test_host_a.id, 4001, t0 + timedelta(minutes=6))
        assert resolver.process_cache_hits == 1

        # Invalidate specific PID
        resolver.invalidate_process(test_host_a.id, 4001)
        resolver.resolve_process(test_host_a.id, 4001, t0 + timedelta(minutes=7))
        assert resolver.process_cache_misses == 2

    def test_process_cache_entry_updated_when_process_ends(
        self, db_session: Session, test_host_a: Host
    ):
        """Verify that when a process terminates via the production lifecycle service,
        subsequent resolutions update/refetch without retaining stale open-ended state."""
        t0 = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        proc = Process(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            pid=4002,
            command="lifecycle-cmd",
            started_at=t0,
            ended_at=None,
            created_at=t0,
        )
        db_session.add(proc)
        db_session.flush()

        resolver = DatabaseIdentityResolver(db_session, cache_ttl=60.0)

        # 1. First resolution: open-ended process cached
        res1 = resolver.resolve_process(test_host_a.id, 4002, t0 + timedelta(minutes=5))
        assert res1 == proc.id

        # 2. Process exits via lifecycle observation at 10:10 (automatic invalidation, no artificial test calls)
        t_exit = t0 + timedelta(minutes=10)
        lifecycle = ProcessLifecycleService()
        end_obs = RawObservation(
            source="proc",
            host_id=test_host_a.id,
            event_type="process.end",
            action="exit",
            severity="info",
            observed_at=t_exit,
            pid=4002,
            command="lifecycle-cmd",
        )
        lifecycle.apply_observations(
            db_session, [end_obs], test_host_a.id, resolver=resolver, now=t_exit
        )

        # 3. Query within lifetime: fetches from DB and updates cache with ended_at
        res2 = resolver.resolve_process(test_host_a.id, 4002, t0 + timedelta(minutes=8))
        assert res2 == proc.id

        # 4. Verify cache entry now has ended_at set
        key = (test_host_a.id, 4002)
        cached = resolver._process_cache[key]
        assert len(cached) == 1
        assert cached[0].ended_at == t_exit

        # 5. Query after termination (10:15): cache check ts <= ended_at fails, falls through to DB -> None
        res3 = resolver.resolve_process(test_host_a.id, 4002, t0 + timedelta(minutes=15))
        assert res3 is None

    def test_process_start_event_does_not_resolve_to_stale_cached_process(
        self, db_session: Session, test_host_a: Host
    ):
        """A process.start event for a newly started process must not resolve to a stale cached process."""
        t0 = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        proc_a = Process(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            pid=4003,
            command="worker_a",
            started_at=t0,
            ended_at=None,
            created_at=t0,
        )
        db_session.add(proc_a)
        db_session.flush()

        resolver = DatabaseIdentityResolver(db_session, cache_ttl=60.0)

        # Cache Process A with ended_at=None
        res_a = resolver.resolve_process(test_host_a.id, 4003, t0 + timedelta(minutes=5))
        assert res_a == proc_a.id

        # Now Process B starts at 10:20 reusing PID 4003
        t_b = datetime(2026, 1, 15, 10, 20, 0, tzinfo=timezone.utc)
        proc_b = Process(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            pid=4003,
            command="worker_b",
            started_at=t_b,
            ended_at=None,
            created_at=t_b,
        )
        # End proc_a in DB
        proc_a.ended_at = t_b
        db_session.add(proc_b)
        db_session.flush()

        # Without manual invalidation, process.start at t_b must resolve to Process B, not Process A!
        res_start = resolver.resolve_process(
            test_host_a.id, 4003, t_b, event_type="process.start"
        )
        assert res_start == proc_b.id

    def test_pid_reuse_resolves_to_new_process_within_cache_ttl(
        self, db_session: Session, test_host_a: Host
    ):
        """Events for Process B resolve to Process B even within cache TTL."""
        service = ProcessLifecycleService()
        resolver = DatabaseIdentityResolver(db_session, cache_ttl=60.0)

        t0 = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        obs_start_a = RawObservation(
            source="proc",
            host_id=test_host_a.id,
            event_type="process.start",
            action="start",
            observed_at=t0,
            pid=4004,
            command="alpha",
        )
        procs_a = service.apply_observations(
            db_session, [obs_start_a], test_host_a.id, resolver=resolver, now=t0
        )
        id_a = procs_a[0].id

        # Resolve during Process A's run -> cached
        assert resolver.resolve_process(test_host_a.id, 4004, t0 + timedelta(minutes=2)) == id_a

        # Process A ends and Process B starts at 10:10
        t1 = datetime(2026, 1, 15, 10, 10, 0, tzinfo=timezone.utc)
        obs_end_a = RawObservation(
            source="proc",
            host_id=test_host_a.id,
            event_type="process.end",
            action="exit",
            observed_at=t1,
            pid=4004,
            command="alpha",
        )
        obs_start_b = RawObservation(
            source="proc",
            host_id=test_host_a.id,
            event_type="process.start",
            action="start",
            observed_at=t1,
            pid=4004,
            command="beta",
        )
        procs_b = service.apply_observations(
            db_session, [obs_end_a, obs_start_b], test_host_a.id, resolver=resolver, now=t1
        )
        id_b = procs_b[1].id

        assert id_a != id_b

        # Resolving Process B's events within cache TTL must resolve to Process B!
        res_b1 = resolver.resolve_process(test_host_a.id, 4004, t1, event_type="process.start")
        assert res_b1 == id_b

        res_b2 = resolver.resolve_process(test_host_a.id, 4004, t1 + timedelta(minutes=2))
        assert res_b2 == id_b

    def test_out_of_order_events_no_cross_attribution(
        self, db_session: Session, test_host_a: Host
    ):
        """Out of order events do not resolve to incorrect process instance."""
        t0 = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        t1 = datetime(2026, 1, 15, 10, 10, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 1, 15, 10, 20, 0, tzinfo=timezone.utc)

        proc_a = Process(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            pid=4005,
            command="first",
            started_at=t0,
            ended_at=t1,
            created_at=t0,
        )
        proc_b = Process(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            pid=4005,
            command="second",
            started_at=t2,
            ended_at=None,
            created_at=t2,
        )
        db_session.add_all([proc_a, proc_b])
        db_session.flush()

        resolver = DatabaseIdentityResolver(db_session, cache_ttl=60.0)

        # 1. Process B event arrives first and is cached
        res_b = resolver.resolve_process(test_host_a.id, 4005, t2 + timedelta(minutes=5))
        assert res_b == proc_b.id

        # 2. Out-of-order event from Process A's lifetime arrives
        res_a = resolver.resolve_process(test_host_a.id, 4005, t0 + timedelta(minutes=5))
        assert res_a == proc_a.id
        assert res_a != proc_b.id

        # 3. Out-of-order event in dead window between A and B
        res_dead = resolver.resolve_process(test_host_a.id, 4005, t1 + timedelta(minutes=5))
        assert res_dead is None

    def test_missing_termination_records_ambiguous_returns_none(
        self, db_session: Session, test_host_a: Host
    ):
        """When multiple un-ended process records exist for a PID, resolver safely returns None."""
        t0 = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        t1 = datetime(2026, 1, 15, 10, 20, 0, tzinfo=timezone.utc)

        # Both records have ended_at=None (missing termination anomaly)
        proc1 = Process(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            pid=4006,
            command="missing_exit_1",
            started_at=t0,
            ended_at=None,
            created_at=t0,
        )
        proc2 = Process(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            pid=4006,
            command="missing_exit_2",
            started_at=t1,
            ended_at=None,
            created_at=t1,
        )
        db_session.add_all([proc1, proc2])
        db_session.flush()

        resolver = DatabaseIdentityResolver(db_session, cache_ttl=60.0)

        # Generic event at 10:25 matches both lifetimes -> ambiguous -> None
        res = resolver.resolve_process(test_host_a.id, 4006, t1 + timedelta(minutes=5))
        assert res is None

    def test_exact_boundary_disambiguation_start_and_end(
        self, db_session: Session, test_host_a: Host
    ):
        """When Process A ends and Process B starts at the exact same timestamp,
        event_type correctly routes process.start to B and process.end to A."""
        t_boundary = datetime(2026, 1, 15, 11, 0, 0, tzinfo=timezone.utc)
        proc_a = Process(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            pid=4007,
            command="terminating",
            started_at=t_boundary - timedelta(minutes=30),
            ended_at=t_boundary,
            created_at=t_boundary - timedelta(minutes=30),
        )
        proc_b = Process(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            pid=4007,
            command="starting",
            started_at=t_boundary,
            ended_at=None,
            created_at=t_boundary,
        )
        db_session.add_all([proc_a, proc_b])
        db_session.flush()

        resolver = DatabaseIdentityResolver(db_session, cache_ttl=60.0)

        # process.start at boundary -> proc_b
        assert (
            resolver.resolve_process(
                test_host_a.id, 4007, t_boundary, event_type="process.start"
            )
            == proc_b.id
        )

        # process.end at boundary -> proc_a
        assert (
            resolver.resolve_process(
                test_host_a.id, 4007, t_boundary, event_type="process.end"
            )
            == proc_a.id
        )

        # Arbitrary event at exact boundary without event_type is ambiguous -> None
        assert resolver.resolve_process(test_host_a.id, 4007, t_boundary) is None

    def test_short_lived_process_same_start_and_end_timestamp(
        self, db_session: Session, test_host_a: Host
    ):
        """A short-lived process starting and ending at the exact same timestamp resolves correctly."""
        t0 = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        proc = Process(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            pid=4008,
            command="/bin/true",
            started_at=t0,
            ended_at=t0,
            created_at=t0,
        )
        db_session.add(proc)
        db_session.flush()

        resolver = DatabaseIdentityResolver(db_session, cache_ttl=60.0)

        # resolve process.start at t0
        assert (
            resolver.resolve_process(
                test_host_a.id, 4008, t0, event_type="process.start"
            )
            == proc.id
        )

        # resolve process.end at t0
        assert (
            resolver.resolve_process(
                test_host_a.id, 4008, t0, event_type="process.end"
            )
            == proc.id
        )


# ── 13. Production processing-path wiring ─────────────────────────────


class TestProductionPipelineWiring:
    """Requirement 4.13: Production processing-path wiring."""

    def test_orchestrator_repository_session_property(
        self, db_session: Session, test_host_a: Host
    ):
        repo = EventRepository(db_session)
        assert repo.session is db_session

    def test_orchestrator_automatically_wires_database_resolver_with_repository(
        self, db_session: Session, test_host_a: Host
    ):
        repo = EventRepository(db_session)
        config = OrchestratorConfig(
            host_id=test_host_a.id,
            fs_backend=MockInotifyBackend(),
        )
        orchestrator = CollectorOrchestrator(config, event_repository=repo)

        # Verify that processor was automatically configured with DatabaseIdentityResolver
        assert isinstance(orchestrator.processor, EventProcessor)
        assert isinstance(
            orchestrator.processor.resolver, DatabaseIdentityResolver
        )
        # Verify it uses the caller's database session
        assert orchestrator.processor.resolver._session is db_session

    def test_orchestrator_custom_identity_resolver_injection(
        self, test_host_a: Host
    ):
        class CustomResolver(IdentityResolver):
            def resolve_user(self, host_id, uid):
                return "custom_user"

            def resolve_process(self, host_id, pid, timestamp):
                return FIXTURE_PROCESS_ID

            def resolve_event(self, event):
                return event.model_copy(
                    update={"username": "custom_user", "process_id": FIXTURE_PROCESS_ID}
                )

        custom = CustomResolver()
        config = OrchestratorConfig(
            host_id=test_host_a.id,
            fs_backend=MockInotifyBackend(),
        )
        orchestrator = CollectorOrchestrator(config, identity_resolver=custom)

        assert orchestrator.processor.resolver is custom

    def test_orchestrator_cycle_resolves_identities(
        self, db_session: Session, test_host_a: Host
    ):
        base_time = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        user = LinuxUser(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            uid=1000,
            username="orchestrator_user",
            first_seen_at=base_time,
        )
        proc = Process(
            id=uuid.uuid4(),
            host_id=test_host_a.id,
            pid=6000,
            command="/usr/bin/test",
            started_at=base_time,
            ended_at=None,
            created_at=base_time,
        )
        db_session.add_all([user, proc])
        db_session.flush()

        repo = EventRepository(db_session)
        config = OrchestratorConfig(
            host_id=test_host_a.id,
            fs_backend=MockInotifyBackend(),
        )
        orchestrator = CollectorOrchestrator(config, event_repository=repo)

        # Inject a mock observation through the processor
        obs = make_process_start_observation(
            host_id=test_host_a.id,
            uid=1000,
            username=None,
            pid=6000,
            process_id=None,
            observed_at=base_time + timedelta(minutes=5),
        )
        res = orchestrator.processor.process(obs)
        assert res.success
        assert res.event is not None
        assert res.event.username == "orchestrator_user"
        assert res.event.process_id == proc.id


# ── 14. Existing pure unit-processing behavior with a no-op resolver ──


class TestNoOpResolverBehavior:
    """Requirement 4.14: Existing pure unit-processing behavior with a no-op resolver."""

    def test_default_event_processor_uses_noop_resolver(self):
        processor = EventProcessor()
        assert isinstance(processor.resolver, NoOpIdentityResolver)

    def test_noop_resolver_methods_return_none(self):
        resolver = NoOpIdentityResolver()
        host_id = uuid.uuid4()
        now = datetime.now(timezone.utc)

        assert resolver.resolve_user(host_id, 1000) is None
        assert resolver.resolve_process(host_id, 500, now) is None

    def test_pure_unit_processing_preserves_preset_identities(self):
        """In unit tests without database access, pre-set values are untouched."""
        processor = EventProcessor()
        obs = make_process_start_observation(
            uid=1000,
            username="preset_student",
            pid=5555,
            process_id=FIXTURE_PROCESS_ID,
        )
        res = processor.process(obs)
        assert res.success
        assert res.event is not None
        assert res.event.username == "preset_student"
        assert res.event.process_id == FIXTURE_PROCESS_ID
        assert res.event.pid == 5555
