"""Unit tests for OSIRIS Process Lifecycle Entity Management.

Tests cover:
1. Creation of `Process` records on `process.start` observations.
2. Linking of `linux_user_id` FK when user exists, leaving None when unknown.
3. Updating of `ended_at` on `process.end` observations.
4. PID reuse across cycles creating distinct internal UUIDs.
5. Batch ordering resilience: when `process.start` appears before `process.end` in one batch.
6. Implicit termination when a new process starts on a reused PID without a prior exit.
7. Automatic invalidation of the resolver cache without manual intervention.
8. Initial collection cycle registration of already running processes.
9. Transactional discipline: changes are flushed without committing.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.db.models.host import Host
from backend.db.models.linux_user import LinuxUser
from backend.db.models.process import Process
from backend.services.events.process_lifecycle import (
    ProcessLifecycleService,
    _ensure_utc,
)
from backend.services.events.resolver import DatabaseIdentityResolver
from backend.services.events.schemas import RawObservation


@pytest.fixture
def test_host(db_session: Session) -> Host:
    host = Host(
        id=uuid.uuid4(),
        hostname="lifecycle-host",
        os_info="Ubuntu 22.04 LTS",
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(host)
    db_session.flush()
    return host


@pytest.fixture
def alice_user(db_session: Session, test_host: Host) -> LinuxUser:
    user = LinuxUser(
        id=uuid.uuid4(),
        host_id=test_host.id,
        uid=1000,
        username="alice",
        first_seen_at=datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc),
    )
    db_session.add(user)
    db_session.flush()
    return user


class TestProcessLifecycleService:
    def test_process_start_creates_process_record(
        self, db_session: Session, test_host: Host, alice_user: LinuxUser
    ):
        t0 = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        obs = RawObservation(
            source="proc",
            host_id=test_host.id,
            event_type="process.start",
            action="start",
            severity="info",
            observed_at=t0,
            pid=5001,
            ppid=1,
            uid=1000,
            command="/usr/bin/python3 app.py",
            object_type="process",
            object_path="/usr/bin/python3",
        )

        service = ProcessLifecycleService()
        procs = service.apply_observations(
            db_session, [obs], test_host.id, now=t0
        )
        assert len(procs) == 1
        proc = procs[0]

        assert isinstance(proc.id, uuid.UUID)
        assert proc.host_id == test_host.id
        assert proc.pid == 5001
        assert proc.ppid == 1
        assert proc.command == "/usr/bin/python3 app.py"
        assert proc.executable == "/usr/bin/python3"
        assert proc.linux_user_id == alice_user.id
        assert _ensure_utc(proc.started_at) == t0
        assert proc.ended_at is None

        # Verify queryable in database
        db_session.expire_all()
        fetched = db_session.get(Process, proc.id)
        assert fetched is not None
        assert fetched.command == "/usr/bin/python3 app.py"
        assert fetched.linux_user_id == alice_user.id

    def test_process_start_unknown_user_leaves_linux_user_id_none(
        self, db_session: Session, test_host: Host
    ):
        t0 = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        obs = RawObservation(
            source="proc",
            host_id=test_host.id,
            event_type="process.start",
            action="start",
            severity="info",
            observed_at=t0,
            pid=5002,
            ppid=1,
            uid=9999,  # Unknown UID
            command="/usr/bin/guest",
            object_type="process",
        )

        service = ProcessLifecycleService()
        procs = service.apply_observations(
            db_session, [obs], test_host.id, now=t0
        )
        assert len(procs) == 1
        assert procs[0].linux_user_id is None

    def test_process_end_updates_ended_at(
        self, db_session: Session, test_host: Host
    ):
        t0 = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        start_obs = RawObservation(
            source="proc",
            host_id=test_host.id,
            event_type="process.start",
            action="start",
            severity="info",
            observed_at=t0,
            pid=5003,
            command="task",
        )
        service = ProcessLifecycleService()
        procs = service.apply_observations(
            db_session, [start_obs], test_host.id, now=t0
        )
        proc_id = procs[0].id

        t_end = datetime(2026, 1, 15, 10, 10, 0, tzinfo=timezone.utc)
        end_obs = RawObservation(
            source="proc",
            host_id=test_host.id,
            event_type="process.end",
            action="exit",
            severity="info",
            observed_at=t_end,
            pid=5003,
            command="task",
        )
        service.apply_observations(db_session, [end_obs], test_host.id, now=t_end)

        db_session.expire_all()
        fetched = db_session.get(Process, proc_id)
        assert fetched is not None
        assert _ensure_utc(fetched.ended_at) == t_end

    def test_pid_reuse_across_cycles_preserves_distinct_uuids(
        self, db_session: Session, test_host: Host
    ):
        service = ProcessLifecycleService()

        # Cycle 1: Process A starts at 10:00
        t0 = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        start_a = RawObservation(
            source="proc",
            host_id=test_host.id,
            event_type="process.start",
            action="start",
            observed_at=t0,
            pid=5004,
            command="process_a",
        )
        procs_a = service.apply_observations(
            db_session, [start_a], test_host.id, now=t0
        )
        id_a = procs_a[0].id

        # Cycle 2: Process A exits at 10:10
        t1 = datetime(2026, 1, 15, 10, 10, 0, tzinfo=timezone.utc)
        end_a = RawObservation(
            source="proc",
            host_id=test_host.id,
            event_type="process.end",
            action="exit",
            observed_at=t1,
            pid=5004,
            command="process_a",
        )
        service.apply_observations(db_session, [end_a], test_host.id, now=t1)

        # Cycle 3: Process B starts with same PID at 10:20
        t2 = datetime(2026, 1, 15, 10, 20, 0, tzinfo=timezone.utc)
        start_b = RawObservation(
            source="proc",
            host_id=test_host.id,
            event_type="process.start",
            action="start",
            observed_at=t2,
            pid=5004,
            command="process_b",
        )
        procs_b = service.apply_observations(
            db_session, [start_b], test_host.id, now=t2
        )
        id_b = procs_b[0].id

        assert id_a != id_b

        # Verify both records in DB
        db_session.expire_all()
        proc_a = db_session.get(Process, id_a)
        proc_b = db_session.get(Process, id_b)

        assert proc_a.command == "process_a"
        assert _ensure_utc(proc_a.ended_at) == t1

        assert proc_b.command == "process_b"
        assert _ensure_utc(proc_b.started_at) == t2
        assert proc_b.ended_at is None

    def test_batch_ordering_start_before_end_in_same_cycle(
        self, db_session: Session, test_host: Host
    ):
        """When process.start appears before process.end in the raw array,
        batch ordering ensures old process ends and new process is a separate instance."""
        service = ProcessLifecycleService()
        t0 = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        # Pre-seed active process A
        start_a = RawObservation(
            source="proc",
            host_id=test_host.id,
            event_type="process.start",
            action="start",
            observed_at=t0,
            pid=5005,
            command="old_worker",
        )
        procs_a = service.apply_observations(
            db_session, [start_a], test_host.id, now=t0
        )
        id_a = procs_a[0].id

        # In cycle 2: array has start_b BEFORE end_a
        t1 = datetime(2026, 1, 15, 10, 10, 0, tzinfo=timezone.utc)
        start_b = RawObservation(
            source="proc",
            host_id=test_host.id,
            event_type="process.start",
            action="start",
            observed_at=t1,
            pid=5005,
            command="new_worker",
        )
        end_a = RawObservation(
            source="proc",
            host_id=test_host.id,
            event_type="process.end",
            action="exit",
            observed_at=t1,
            pid=5005,
            command="old_worker",
        )

        # Pass in unordered array: [start_b, end_a]
        service.apply_observations(
            db_session, [start_b, end_a], test_host.id, now=t1
        )

        db_session.expire_all()
        all_procs = (
            db_session.execute(
                select(Process)
                .where(Process.host_id == test_host.id, Process.pid == 5005)
                .order_by(Process.started_at.asc())
            )
            .scalars()
            .all()
        )
        assert len(all_procs) == 2

        old_p, new_p = all_procs
        assert old_p.id == id_a
        assert old_p.command == "old_worker"
        assert _ensure_utc(old_p.ended_at) == t1

        assert new_p.id != id_a
        assert new_p.command == "new_worker"
        assert _ensure_utc(new_p.started_at) == t1
        assert new_p.ended_at is None

    def test_automatic_resolver_cache_invalidation(
        self, db_session: Session, test_host: Host
    ):
        """apply_observations automatically invalidates the resolver cache for affected PIDs."""
        service = ProcessLifecycleService()
        resolver = DatabaseIdentityResolver(db_session, cache_ttl=60.0)

        t0 = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        start_obs = RawObservation(
            source="proc",
            host_id=test_host.id,
            event_type="process.start",
            action="start",
            observed_at=t0,
            pid=5006,
            command="cached_worker",
        )
        procs = service.apply_observations(
            db_session, [start_obs], test_host.id, resolver=resolver, now=t0
        )
        id_1 = procs[0].id

        # Cache hit in resolver
        res = resolver.resolve_process(
            test_host.id, 5006, t0 + timedelta(minutes=2)
        )
        assert res == id_1
        assert (test_host.id, 5006) in resolver._process_cache

        # Terminate process via lifecycle service with resolver passed
        t1 = datetime(2026, 1, 15, 10, 10, 0, tzinfo=timezone.utc)
        end_obs = RawObservation(
            source="proc",
            host_id=test_host.id,
            event_type="process.end",
            action="exit",
            observed_at=t1,
            pid=5006,
            command="cached_worker",
        )
        service.apply_observations(
            db_session, [end_obs], test_host.id, resolver=resolver, now=t1
        )

        # Cache must have been automatically invalidated by apply_observations
        assert (test_host.id, 5006) not in resolver._process_cache

    def test_initial_cycle_already_running_processes_registered(
        self, db_session: Session, test_host: Host, alice_user: LinuxUser
    ):
        """A process already running when observation begins is registered appropriately."""
        service = ProcessLifecycleService()
        t_init = datetime(2026, 1, 15, 9, 30, 0, tzinfo=timezone.utc)

        # Initial collector cycle emits observations for pre-existing system processes
        init_obs_1 = RawObservation(
            source="proc",
            host_id=test_host.id,
            event_type="process.start",
            action="start",
            observed_at=t_init,
            pid=1,
            ppid=0,
            uid=0,
            command="/sbin/init",
            object_type="process",
            object_path="/sbin/init",
        )
        init_obs_2 = RawObservation(
            source="proc",
            host_id=test_host.id,
            event_type="process.start",
            action="start",
            observed_at=t_init,
            pid=5007,
            ppid=1,
            uid=1000,
            command="/usr/bin/daemon",
            object_type="process",
            object_path="/usr/bin/daemon",
        )

        procs = service.apply_observations(
            db_session, [init_obs_1, init_obs_2], test_host.id, now=t_init
        )
        assert len(procs) == 2

        db_session.expire_all()
        init_proc = (
            db_session.execute(
                select(Process).where(
                    Process.host_id == test_host.id, Process.pid == 1
                )
            )
            .scalars()
            .one()
        )
        assert init_proc.command == "/sbin/init"
        assert _ensure_utc(init_proc.started_at) == t_init
        assert init_proc.ended_at is None

        daemon_proc = (
            db_session.execute(
                select(Process).where(
                    Process.host_id == test_host.id, Process.pid == 5007
                )
            )
            .scalars()
            .one()
        )
        assert daemon_proc.command == "/usr/bin/daemon"
        assert daemon_proc.linux_user_id == alice_user.id
        assert _ensure_utc(daemon_proc.started_at) == t_init
        assert daemon_proc.ended_at is None

    def test_implicit_termination_on_pid_reuse_without_prior_exit(
        self, db_session: Session, test_host: Host
    ):
        """When a new process starts on a reused PID without a prior exit, older process is terminated."""
        service = ProcessLifecycleService()
        t0 = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        obs_a = RawObservation(
            source="proc",
            host_id=test_host.id,
            event_type="process.start",
            action="start",
            observed_at=t0,
            pid=5008,
            command="first_run",
        )
        procs_a = service.apply_observations(
            db_session, [obs_a], test_host.id, now=t0
        )
        id_a = procs_a[0].id

        # At 10:10, PID 5008 starts a new command without an exit event being observed
        t1 = datetime(2026, 1, 15, 10, 10, 0, tzinfo=timezone.utc)
        obs_b = RawObservation(
            source="proc",
            host_id=test_host.id,
            event_type="process.start",
            action="start",
            observed_at=t1,
            pid=5008,
            command="second_run",
        )
        procs_b = service.apply_observations(
            db_session, [obs_b], test_host.id, now=t1
        )
        id_b = procs_b[0].id

        assert id_a != id_b

        db_session.expire_all()
        proc_a = db_session.get(Process, id_a)
        proc_b = db_session.get(Process, id_b)

        assert _ensure_utc(proc_a.ended_at) == t1
        assert _ensure_utc(proc_b.started_at) == t1
        assert proc_b.ended_at is None

    def test_out_of_order_exit_does_not_terminate_future_running_process(
        self, db_session: Session, test_host: Host
    ):
        """An out-of-order exit event from the past must not terminate a newer running process on the same PID."""
        service = ProcessLifecycleService()
        t_newer = datetime(2026, 1, 15, 10, 20, 0, tzinfo=timezone.utc)

        # Process B starts at 10:20
        obs_b = RawObservation(
            source="proc",
            host_id=test_host.id,
            event_type="process.start",
            action="start",
            observed_at=t_newer,
            pid=5009,
            command="current_process_b",
        )
        procs_b = service.apply_observations(
            db_session, [obs_b], test_host.id, now=t_newer
        )
        id_b = procs_b[0].id

        # Now an out-of-order exit event from 10:05 arrives for PID 5009
        t_older = datetime(2026, 1, 15, 10, 5, 0, tzinfo=timezone.utc)
        obs_older_exit = RawObservation(
            source="proc",
            host_id=test_host.id,
            event_type="process.end",
            action="exit",
            observed_at=t_older,
            pid=5009,
            command="past_process_a",
        )
        service.apply_observations(
            db_session, [obs_older_exit], test_host.id, now=t_older
        )

        db_session.expire_all()
        proc_b = db_session.get(Process, id_b)
        # Process B must STILL BE RUNNING!
        assert proc_b.ended_at is None
        assert _ensure_utc(proc_b.started_at) == t_newer

    def test_start_idempotency_does_not_duplicate_records(
        self, db_session: Session, test_host: Host
    ):
        """Re-applying the exact same start observation does not duplicate Process records."""
        service = ProcessLifecycleService()
        t0 = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        obs = RawObservation(
            source="proc",
            host_id=test_host.id,
            event_type="process.start",
            action="start",
            observed_at=t0,
            pid=5010,
            command="idempotent_app",
        )

        res1 = service.apply_observations(db_session, [obs], test_host.id, now=t0)
        res2 = service.apply_observations(db_session, [obs], test_host.id, now=t0)

        assert len(res1) == 1
        assert len(res2) == 1
        assert res1[0].id == res2[0].id

        db_session.expire_all()
        records = (
            db_session.execute(
                select(Process).where(
                    Process.host_id == test_host.id, Process.pid == 5010
                )
            )
            .scalars()
            .all()
        )
        assert len(records) == 1

    def test_transactional_discipline_flushes_without_commit(
        self, db_session: Session, test_host: Host
    ):
        """apply_observations flushes changes so they are visible in-session, but does not commit."""
        service = ProcessLifecycleService()
        t0 = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        obs = RawObservation(
            source="proc",
            host_id=test_host.id,
            event_type="process.start",
            action="start",
            observed_at=t0,
            pid=5011,
            command="tx_test",
        )
        procs = service.apply_observations(
            db_session, [obs], test_host.id, now=t0
        )
        proc_id = procs[0].id

        # Visible in current transaction
        fetched = db_session.get(Process, proc_id)
        assert fetched is not None

        # Rollback discards it because apply_observations did not commit
        db_session.rollback()
        assert db_session.get(Process, proc_id) is None
