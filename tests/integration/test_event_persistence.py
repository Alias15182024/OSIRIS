"""Integration tests for event persistence against local PostgreSQL (osiris_dev).

Verifies that NormalizedEvent instances are correctly saved, retrieved,
and queryable in PostgreSQL with JSONB support, foreign keys, and transactions.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.config import settings
from backend.db.models.event import Event
from backend.db.models.host import Host
from backend.db.models.linux_user import LinuxUser
from backend.db.models.process import Process
from backend.services.events.processor import EventProcessor
from backend.services.events.repository import EventRepository
from backend.services.events.resolver import DatabaseIdentityResolver, _ensure_utc
from backend.services.events.schemas import RawObservation
from collectors.filesystem.inotify import MockInotifyBackend
from collectors.orchestrator import CollectorOrchestrator, OrchestratorConfig
from tests.fixtures.event_fixtures import (
    FIXTURE_TS,
    make_filesystem_modify_observation,
    make_process_start_observation,
    make_resource_cpu_observation,
)


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
def pg_session(pg_engine):
    """Transactional session against PostgreSQL.

    Runs within a transaction that is rolled back after the test so
    the database remains clean.
    """
    connection = pg_engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection)

    yield session

    session.close()
    if transaction.is_active:
        transaction.rollback()
    connection.close()


@pytest.fixture
def pg_host(pg_session: Session) -> Host:
    """Retrieve existing host or insert one if missing."""
    host = pg_session.execute(select(Host)).scalars().first()
    if not host:
        now = datetime.now(timezone.utc)
        host = Host(
            id=uuid.uuid4(),
            hostname="test-pg-host",
            os_info="Linux 6.x",
            ip_address="127.0.0.1",
            created_at=now,
        )
        pg_session.add(host)
        pg_session.flush()
    return host


@pytest.fixture
def pg_process(pg_session: Session, pg_host: Host) -> Process:
    """Retrieve existing process or insert one if missing."""
    proc = pg_session.execute(select(Process)).scalars().first()
    if not proc:
        now = datetime.now(timezone.utc)
        proc = Process(
            id=uuid.uuid4(),
            host_id=pg_host.id,
            pid=100,
            ppid=1,
            command="/usr/bin/test-daemon",
            started_at=now,
            created_at=now,
        )
        pg_session.add(proc)
        pg_session.flush()
    return proc


@pytest.fixture
def processor() -> EventProcessor:
    return EventProcessor()


class TestPostgreSQLEventPersistence:

    def test_pg_persist_and_read_back(
        self, pg_session: Session, pg_host: Host, processor: EventProcessor
    ):
        """Persist a normalized event to PostgreSQL and read it back."""
        obs = make_process_start_observation(
            host_id=pg_host.id,
            process_id=None,
            observed_at=FIXTURE_TS,
            uid=1000,
            username="student",
            pid=5001,
            command="/usr/bin/test-app",
        )
        res = processor.process(obs)
        assert res.success
        assert res.event is not None

        repo = EventRepository(pg_session)
        orm_event = repo.save(res.event)
        assert orm_event.id == res.event.id

        # Evict from session cache to force real SQL SELECT from PostgreSQL
        pg_session.expire_all()

        stmt = select(Event).where(Event.id == res.event.id)
        fetched = pg_session.execute(stmt).scalar_one()

        assert fetched.id == res.event.id
        assert fetched.host_id == pg_host.id
        assert fetched.source == "proc"
        assert fetched.event_type == "process.start"
        assert fetched.action == "start"
        assert fetched.severity == "info"
        assert fetched.uid == 1000
        assert fetched.username == "student"
        assert fetched.pid == 5001
        assert fetched.command == "/usr/bin/test-app"
        assert fetched.process_id is None
        assert fetched.timestamp.tzinfo is not None

    def test_pg_persist_event_process_id_nullable(
        self, pg_session: Session, pg_host: Host, processor: EventProcessor
    ):
        """Events can be persisted with process_id=None."""
        obs = make_resource_cpu_observation(host_id=pg_host.id)
        res = processor.process(obs)
        assert res.success

        repo = EventRepository(pg_session)
        repo.save(res.event)

        pg_session.expire_all()
        fetched = pg_session.execute(
            select(Event).where(Event.id == res.event.id)
        ).scalar_one()
        assert fetched.process_id is None

    def test_pg_persist_event_with_valid_process_id(
        self,
        pg_session: Session,
        pg_host: Host,
        pg_process: Process,
        processor: EventProcessor,
    ):
        """Events can reference an existing process via foreign key."""
        obs = make_process_start_observation(
            host_id=pg_host.id,
            process_id=pg_process.id,
        )
        res = processor.process(obs)
        assert res.success

        repo = EventRepository(pg_session)
        repo.save(res.event)

        pg_session.expire_all()
        fetched = pg_session.execute(
            select(Event).where(Event.id == res.event.id)
        ).scalar_one()
        assert fetched.process_id == pg_process.id
        assert fetched.process.id == pg_process.id

    def test_pg_persist_event_with_invalid_process_id_fails(
        self, pg_session: Session, pg_host: Host, processor: EventProcessor
    ):
        """Invalid process_id foreign key is rejected by PostgreSQL."""
        fake_process_id = uuid.uuid4()
        obs = make_process_start_observation(
            host_id=pg_host.id,
            process_id=fake_process_id,
        )
        res = processor.process(obs)
        assert res.success

        repo = EventRepository(pg_session)
        with pytest.raises(IntegrityError):
            repo.save(res.event)
        pg_session.rollback()

    def test_pg_jsonb_payload_roundtrip_and_query(
        self, pg_session: Session, pg_host: Host, processor: EventProcessor
    ):
        """Payload is stored as JSONB and queryable via PostgreSQL JSON operators."""
        payload_data = {
            "environment": "testing",
            "metrics": {"cpu_spike": True, "load": 4.5},
            "subsystem": "kernel",
        }
        obs = make_filesystem_modify_observation(
            host_id=pg_host.id,
            payload=payload_data,
        )
        res = processor.process(obs)
        assert res.success

        repo = EventRepository(pg_session)
        repo.save(res.event)

        pg_session.expire_all()

        # Query back and verify exact dictionary match
        fetched = pg_session.execute(
            select(Event).where(Event.id == res.event.id)
        ).scalar_one()
        assert fetched.payload == payload_data
        assert fetched.payload["metrics"]["cpu_spike"] is True

        # Query using PostgreSQL JSONB ->> operator
        stmt_jsonb = select(Event).where(
            Event.id == res.event.id,
            text("payload->'metrics'->>'load' = '4.5'"),
        )
        matched = pg_session.execute(stmt_jsonb).scalar_one_or_none()
        assert matched is not None
        assert matched.id == res.event.id

    def test_pg_batch_persistence(
        self, pg_session: Session, pg_host: Host, processor: EventProcessor
    ):
        """Multiple normalized events can be persisted in a single batch."""
        obs1 = make_process_start_observation(host_id=pg_host.id, process_id=None)
        obs2 = make_filesystem_modify_observation(host_id=pg_host.id)
        obs3 = make_resource_cpu_observation(host_id=pg_host.id)

        batch_res = processor.process_batch([obs1, obs2, obs3])
        assert batch_res.succeeded == 3
        assert len(batch_res.events) == 3

        repo = EventRepository(pg_session)
        saved = repo.save_batch(batch_res.events)
        assert len(saved) == 3

        pg_session.expire_all()
        ids = [e.id for e in batch_res.events]
        rows = (
            pg_session.execute(select(Event).where(Event.id.in_(ids)))
            .scalars()
            .all()
        )
        assert len(rows) == 3

    def test_pg_transaction_rollback_on_failure(
        self, pg_session: Session, processor: EventProcessor
    ):
        """Failed persistence rolls back cleanly without partial writes."""
        # Non-existent host causes FK violation
        obs = make_process_start_observation(
            host_id=uuid.uuid4(),
            process_id=None,
        )
        res = processor.process(obs)
        assert res.success

        repo = EventRepository(pg_session)
        with pytest.raises(IntegrityError):
            repo.save(res.event)

        # Rollback and confirm nothing was written
        pg_session.rollback()
        check = pg_session.execute(
            select(Event).where(Event.id == res.event.id)
        ).scalar_one_or_none()
        assert check is None

    def test_pg_persist_with_database_identity_resolution(
        self, pg_session: Session, pg_host: Host
    ):
        """Verify DatabaseIdentityResolver correctly resolves identities and persists to PostgreSQL."""
        base_time = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        user = LinuxUser(
            id=uuid.uuid4(),
            host_id=pg_host.id,
            uid=3000,
            username="pg_alice",
            first_seen_at=base_time,
        )
        proc = Process(
            id=uuid.uuid4(),
            host_id=pg_host.id,
            pid=6500,
            ppid=1,
            command="/usr/bin/pg-worker",
            started_at=base_time,
            ended_at=None,
            created_at=base_time,
        )
        pg_session.add_all([user, proc])
        pg_session.flush()

        processor = EventProcessor.with_database(pg_session)
        obs = make_process_start_observation(
            host_id=pg_host.id,
            uid=3000,
            username=None,
            pid=6500,
            ppid=1,
            command="/usr/bin/pg-worker",
            process_id=None,
            observed_at=base_time + timedelta(minutes=5),
        )
        res = processor.process(obs)
        assert res.success
        assert res.event is not None
        assert res.event.username == "pg_alice"
        assert res.event.process_id == proc.id

        repo = EventRepository(pg_session)
        orm_event = repo.save(res.event)
        assert orm_event.id == res.event.id

        pg_session.expire_all()
        fetched = pg_session.execute(
            select(Event).where(Event.id == res.event.id)
        ).scalar_one()

        assert fetched.username == "pg_alice"
        assert fetched.process_id == proc.id
        assert fetched.uid == 3000
        assert fetched.pid == 6500
        assert fetched.ppid == 1

    def test_pg_persist_with_orchestrator_database_resolver(
        self, pg_session: Session, pg_host: Host
    ):
        """Verify CollectorOrchestrator automatically wires DatabaseIdentityResolver with pg_session."""
        base_time = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        user = LinuxUser(
            id=uuid.uuid4(),
            host_id=pg_host.id,
            uid=3001,
            username="orchestrator_pg_user",
            first_seen_at=base_time,
        )
        proc = Process(
            id=uuid.uuid4(),
            host_id=pg_host.id,
            pid=6501,
            command="/usr/bin/pg-orch",
            started_at=base_time,
            ended_at=None,
            created_at=base_time,
        )
        pg_session.add_all([user, proc])
        pg_session.flush()

        repo = EventRepository(pg_session)
        config = OrchestratorConfig(
            host_id=pg_host.id,
            fs_backend=MockInotifyBackend(),
        )
        orchestrator = CollectorOrchestrator(config, event_repository=repo)

        assert isinstance(
            orchestrator.processor.resolver, DatabaseIdentityResolver
        )

        obs = make_process_start_observation(
            host_id=pg_host.id,
            uid=3001,
            username=None,
            pid=6501,
            process_id=None,
            observed_at=base_time + timedelta(minutes=5),
        )
        res = orchestrator.processor.process(obs)
        assert res.success
        assert res.event is not None
        assert res.event.username == "orchestrator_pg_user"
        assert res.event.process_id == proc.id

        repo.save(res.event)
        pg_session.expire_all()

        fetched = pg_session.execute(
            select(Event).where(Event.id == res.event.id)
        ).scalar_one()
        assert fetched.username == "orchestrator_pg_user"
        assert fetched.process_id == proc.id

    def test_pg_persist_unresolved_identities(
        self, pg_session: Session, pg_host: Host
    ):
        """Verify unresolvable identities persist cleanly with nulls to PostgreSQL."""
        processor = EventProcessor.with_database(pg_session)
        obs = make_process_start_observation(
            host_id=pg_host.id,
            uid=9999,
            username=None,
            pid=99999,
            ppid=1,
            process_id=None,
            observed_at=FIXTURE_TS,
        )
        res = processor.process(obs)
        assert res.success
        assert res.event is not None
        assert res.event.username is None
        assert res.event.process_id is None

        repo = EventRepository(pg_session)
        repo.save(res.event)
        pg_session.expire_all()

        fetched = pg_session.execute(
            select(Event).where(Event.id == res.event.id)
        ).scalar_one()
        assert fetched.username is None
        assert fetched.process_id is None
        assert fetched.uid == 9999
        assert fetched.pid == 99999

    def test_pg_orchestrator_live_pipeline_full_cycle(
        self, pg_session: Session, pg_host: Host
    ):
        """End-to-end integration test of the live production pipeline with newly generated observations.

        Exercises:
        1. User account discovery from configured account provider into linux_users.
        2. Process creation from raw process observation into processes.
        3. Identity resolution (UID -> username, PID -> process UUID).
        4. Event persistence to PostgreSQL.
        5. PID reuse across cycles: Process A terminates, Process B reuses PID with new UUID.
        6. Subsequent events for Process B resolve to Process B even within cache TTL.
        All without ANY pre-seeded user or process rows!
        """
        t0 = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        current_clock = t0

        repo = EventRepository(pg_session)
        config = OrchestratorConfig(
            host_id=pg_host.id,
            fs_backend=MockInotifyBackend(),
            user_provider=lambda: [(4500, "pg_live_user")],
            wall_clock=lambda: current_clock,
        )
        orchestrator = CollectorOrchestrator(config, event_repository=repo)

        # ── Cycle 1: Process A starts ─────────────────────────────────
        obs_start_a = RawObservation(
            source="proc",
            host_id=pg_host.id,
            event_type="process.start",
            action="start",
            severity="info",
            observed_at=t0,
            uid=4500,
            pid=7701,
            ppid=1,
            command="/usr/bin/live_service_a",
            object_type="process",
            object_path="/usr/bin/live_service_a",
        )

        # Mock the collectors to inject our raw observation into the cycle
        orchestrator.process_collector.collect_observations = lambda diff=True: [obs_start_a]
        orchestrator.resource_collector.collect_observations = lambda granular=False: []
        orchestrator.filesystem_collector.collect_observations = lambda: []

        cycle1 = orchestrator.run_cycle(force_all=True)
        assert cycle1.success
        assert len(cycle1.events) == 1

        ev1 = cycle1.events[0]
        assert ev1.username == "pg_live_user"
        assert ev1.process_id is not None
        id_a = ev1.process_id

        # Verify DB records created by the live pipeline
        pg_session.expire_all()

        # 1. User discovered
        user_record = pg_session.execute(
            select(LinuxUser).where(
                LinuxUser.host_id == pg_host.id, LinuxUser.uid == 4500
            )
        ).scalar_one()
        assert user_record.username == "pg_live_user"

        # 2. Process A created
        proc_a = pg_session.get(Process, id_a)
        assert proc_a is not None
        assert proc_a.pid == 7701
        assert proc_a.command == "/usr/bin/live_service_a"
        assert proc_a.linux_user_id == user_record.id
        assert _ensure_utc(proc_a.started_at) == t0
        assert proc_a.ended_at is None

        # 3. Event persisted in PostgreSQL
        event_a = pg_session.get(Event, ev1.id)
        assert event_a is not None
        assert event_a.process_id == id_a
        assert event_a.username == "pg_live_user"

        # ── Cycle 2: Process A exits and Process B reuses PID 7701 ────
        t1 = t0 + timedelta(minutes=10)
        current_clock = t1

        obs_end_a = RawObservation(
            source="proc",
            host_id=pg_host.id,
            event_type="process.end",
            action="exit",
            severity="info",
            observed_at=t1,
            uid=4500,
            pid=7701,
            command="/usr/bin/live_service_a",
            object_type="process",
        )
        obs_start_b = RawObservation(
            source="proc",
            host_id=pg_host.id,
            event_type="process.start",
            action="start",
            severity="info",
            observed_at=t1,
            uid=4500,
            pid=7701,
            ppid=1,
            command="/usr/bin/live_service_b",
            object_type="process",
        )

        orchestrator.process_collector.collect_observations = lambda diff=True: [
            obs_end_a,
            obs_start_b,
        ]

        cycle2 = orchestrator.run_cycle(force_all=True)
        assert cycle2.success
        assert len(cycle2.events) == 2

        end_ev = [e for e in cycle2.events if e.event_type == "process.end"][0]
        start_ev = [e for e in cycle2.events if e.event_type == "process.start"][0]

        assert end_ev.process_id == id_a  # Old process
        assert start_ev.process_id != id_a  # New process has distinct UUID!
        id_b = start_ev.process_id

        # Verify DB records after Cycle 2
        pg_session.expire_all()
        proc_a = pg_session.get(Process, id_a)
        assert _ensure_utc(proc_a.ended_at) == t1

        proc_b = pg_session.get(Process, id_b)
        assert proc_b is not None
        assert proc_b.command == "/usr/bin/live_service_b"
        assert _ensure_utc(proc_b.started_at) == t1
        assert proc_b.ended_at is None

        # ── Cycle 3: File event for PID 7701 within cache TTL ────────
        t2 = t1 + timedelta(minutes=2)
        current_clock = t2

        obs_fs = RawObservation(
            source="fs",
            host_id=pg_host.id,
            event_type="file.modify",
            action="modify",
            severity="info",
            observed_at=t2,
            uid=4500,
            pid=7701,
            object_type="file",
            object_path="/var/log/app.log",
        )

        orchestrator.process_collector.collect_observations = lambda diff=True: []
        orchestrator.filesystem_collector.collect_observations = lambda: [obs_fs]

        cycle3 = orchestrator.run_cycle(force_all=False)
        assert cycle3.success
        assert len(cycle3.events) == 1

        fs_ev = cycle3.events[0]
        # Must resolve to Process B (the currently active process), not Process A!
        assert fs_ev.process_id == id_b
        assert fs_ev.username == "pg_live_user"

        pg_session.expire_all()
        persisted_fs = pg_session.get(Event, fs_ev.id)
        assert persisted_fs is not None
        assert persisted_fs.process_id == id_b
        assert persisted_fs.username == "pg_live_user"

    def test_pg_orchestrator_initial_cycle_preexisting_process(
        self, pg_session: Session, pg_host: Host
    ):
        """Verify that when observation begins, a process already running on the host
        is registered appropriately and enriched with its newly generated process UUID."""
        t_init = datetime(2026, 1, 15, 8, 0, 0, tzinfo=timezone.utc)
        repo = EventRepository(pg_session)
        config = OrchestratorConfig(
            host_id=pg_host.id,
            fs_backend=MockInotifyBackend(),
            user_provider=lambda: [(4800, "pg_init_user")],
            wall_clock=lambda: t_init,
        )
        orchestrator = CollectorOrchestrator(config, event_repository=repo)

        # Initial collector cycle emits an observation for pre-existing process 8800
        obs_init = RawObservation(
            source="proc",
            host_id=pg_host.id,
            event_type="process.start",
            action="start",
            severity="info",
            observed_at=t_init,
            uid=4800,
            pid=8800,
            ppid=1,
            command="/usr/sbin/init_daemon",
            object_type="process",
            object_path="/usr/sbin/init_daemon",
        )
        orchestrator.process_collector.collect_observations = lambda diff=True: [obs_init]
        orchestrator.resource_collector.collect_observations = lambda granular=False: []
        orchestrator.filesystem_collector.collect_observations = lambda: []

        cycle = orchestrator.run_cycle(force_all=True)
        assert cycle.success
        assert len(cycle.events) == 1

        ev = cycle.events[0]
        assert ev.username == "pg_init_user"
        assert ev.process_id is not None

        # Verify DB records
        pg_session.expire_all()
        proc = pg_session.get(Process, ev.process_id)
        assert proc is not None
        assert proc.pid == 8800
        assert proc.command == "/usr/sbin/init_daemon"
        assert _ensure_utc(proc.started_at) == t_init
        assert proc.ended_at is None

    def test_pg_orchestrator_session_factory_atomicity_and_rollback(
        self, pg_session: Session, pg_host: Host
    ):
        """Verify PostgreSQL transaction boundaries using session_factory:
        Successful cycle commits entities and events atomically; failure rolls back all cycle changes."""
        t0 = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        factory = lambda: Session(bind=pg_session.connection(), join_transaction_mode="create_savepoint")

        # ── 1. Successful Cycle ──
        config = OrchestratorConfig(
            host_id=pg_host.id,
            fs_backend=MockInotifyBackend(),
            session_factory=factory,
            user_provider=lambda: [(4901, "pg_tx_user_ok")],
            wall_clock=lambda: t0,
        )
        orchestrator = CollectorOrchestrator(config)
        assert orchestrator.is_session_owned is True

        obs_ok = RawObservation(
            source="proc",
            host_id=pg_host.id,
            event_type="process.start",
            action="start",
            severity="info",
            observed_at=t0,
            uid=4901,
            pid=8901,
            command="/usr/bin/pg_tx_worker",
            object_type="process",
        )
        orchestrator.process_collector.collect_observations = lambda diff=True: [obs_ok]
        orchestrator.resource_collector.collect_observations = lambda **kw: []
        orchestrator.filesystem_collector.collect_observations = lambda: []

        cycle_ok = orchestrator.run_cycle(force_all=True)
        assert cycle_ok.success is True
        assert len(cycle_ok.events) == 1
        ev_id = cycle_ok.events[0].id
        proc_id = cycle_ok.events[0].process_id

        # Verify PostgreSQL database contains committed rows
        with factory() as verify_s:
            user = verify_s.execute(
                select(LinuxUser).where(LinuxUser.host_id == pg_host.id, LinuxUser.uid == 4901)
            ).scalar_one_or_none()
            assert user is not None
            assert user.username == "pg_tx_user_ok"

            proc = verify_s.get(Process, proc_id)
            assert proc is not None
            assert proc.pid == 8901

            ev = verify_s.get(Event, ev_id)
            assert ev is not None
            assert ev.username == "pg_tx_user_ok"
            assert ev.process_id == proc_id

        # ── 2. Failed Cycle (processing error) ──
        t1 = t0 + timedelta(minutes=5)
        config_fail = OrchestratorConfig(
            host_id=pg_host.id,
            fs_backend=MockInotifyBackend(),
            session_factory=factory,
            user_provider=lambda: [(4902, "pg_tx_user_fail")],
            wall_clock=lambda: t1,
        )
        orchestrator_fail = CollectorOrchestrator(config_fail)

        obs_valid = RawObservation(
            source="proc",
            host_id=pg_host.id,
            event_type="process.start",
            action="start",
            severity="info",
            observed_at=t1,
            uid=4902,
            pid=8902,
            command="/usr/bin/pg_tx_fail",
            object_type="process",
        )
        obs_invalid = RawObservation(
            source="proc",
            host_id=pg_host.id,
            event_type="process.start",
            action="start",
            severity="INVALID_SEVERITY_PG",
            observed_at=t1,
        )
        orchestrator_fail.process_collector.collect_observations = lambda diff=True: [obs_valid, obs_invalid]
        orchestrator_fail.resource_collector.collect_observations = lambda **kw: []
        orchestrator_fail.filesystem_collector.collect_observations = lambda: []

        cycle_fail = orchestrator_fail.run_cycle(force_all=True)
        assert cycle_fail.success is False

        # Verify rollback in PostgreSQL
        with factory() as verify_s:
            user_rolled = verify_s.execute(
                select(LinuxUser).where(LinuxUser.host_id == pg_host.id, LinuxUser.uid == 4902)
            ).scalar_one_or_none()
            assert user_rolled is None, "Failed cycle user must be rolled back from PostgreSQL"

            proc_rolled = verify_s.execute(
                select(Process).where(Process.host_id == pg_host.id, Process.pid == 8902)
            ).scalar_one_or_none()
            assert proc_rolled is None, "Failed cycle process must be rolled back from PostgreSQL"

    def test_pg_orchestrator_rollback_preserves_previous_cycle(
        self, pg_session: Session, pg_host: Host
    ):
        """Verify that a rollback in cycle 2 does not erase data committed in cycle 1 on PostgreSQL."""
        t0 = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        factory = lambda: Session(bind=pg_session.connection(), join_transaction_mode="create_savepoint")

        config = OrchestratorConfig(
            host_id=pg_host.id,
            fs_backend=MockInotifyBackend(),
            session_factory=factory,
            user_provider=lambda: [(4910, "pg_preserved_user")],
            wall_clock=lambda: t0,
        )
        orchestrator = CollectorOrchestrator(config)

        # Cycle 1
        obs1 = RawObservation(
            source="proc",
            host_id=pg_host.id,
            event_type="process.start",
            action="start",
            severity="info",
            observed_at=t0,
            uid=4910,
            pid=8910,
            command="/usr/bin/pg_preserved_app",
            object_type="process",
        )
        orchestrator.process_collector.collect_observations = lambda diff=True: [obs1]
        orchestrator.resource_collector.collect_observations = lambda **kw: []
        orchestrator.filesystem_collector.collect_observations = lambda: []

        res1 = orchestrator.run_cycle(force_all=True)
        assert res1.success is True

        # Cycle 2 fails during event persistence
        broken_repo = EventRepository(session=None)
        broken_repo.save_batch = MagicMock(side_effect=RuntimeError("PG Persistence Failure"))

        orchestrator_c2 = CollectorOrchestrator(
            config,
            event_repository=broken_repo,
        )
        obs2 = RawObservation(
            source="proc",
            host_id=pg_host.id,
            event_type="process.start",
            action="start",
            severity="info",
            observed_at=t0 + timedelta(minutes=10),
            uid=4910,
            pid=8911,
            command="/usr/bin/pg_fail_app",
            object_type="process",
        )
        orchestrator_c2.process_collector.collect_observations = lambda diff=True: [obs2]
        orchestrator_c2.resource_collector.collect_observations = lambda **kw: []
        orchestrator_c2.filesystem_collector.collect_observations = lambda: []

        res2 = orchestrator_c2.run_cycle(force_all=True)
        assert res2.success is False

        # Verify Cycle 1 data is still intact in PostgreSQL
        with factory() as verify_s:
            u = verify_s.execute(
                select(LinuxUser).where(LinuxUser.host_id == pg_host.id, LinuxUser.uid == 4910)
            ).scalar_one_or_none()
            assert u is not None
            assert u.username == "pg_preserved_user"

            p1 = verify_s.execute(
                select(Process).where(Process.host_id == pg_host.id, Process.pid == 8910)
            ).scalar_one_or_none()
            assert p1 is not None

            # Cycle 2 process must NOT exist
            p2 = verify_s.execute(
                select(Process).where(Process.host_id == pg_host.id, Process.pid == 8911)
            ).scalar_one_or_none()
            assert p2 is None

    def test_pg_orchestrator_external_session_savepoint_rollback(
        self, pg_session: Session, pg_host: Host
    ):
        """Verify that on PostgreSQL, an external session's outer transaction survives an inner cycle failure."""
        t0 = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

        # Outer caller adds an entity before the collection cycle
        outer_user = LinuxUser(
            id=uuid.uuid4(),
            host_id=pg_host.id,
            uid=7150,
            username="pg_outer_user",
            first_seen_at=t0,
        )
        pg_session.add(outer_user)
        pg_session.flush()

        config = OrchestratorConfig(
            host_id=pg_host.id,
            user_provider=lambda: [(7151, "pg_inner_user")],
            wall_clock=lambda: t0,
            fs_backend=MockInotifyBackend(),
        )
        orchestrator = CollectorOrchestrator(config, session=pg_session)

        # Trigger a real Postgres foreign key failure during repository.save_batch
        broken_obs = RawObservation(
            source="proc",
            host_id=pg_host.id,
            event_type="process.start",
            action="start",
            severity="info",
            observed_at=t0,
            uid=7151,
            pid=9992,
            command="/bin/pg_broken_app",
        )
        orchestrator.process_collector.collect_observations = lambda diff=True: [broken_obs]
        orchestrator.resource_collector.collect_observations = lambda **kw: []
        orchestrator.filesystem_collector.collect_observations = lambda: []

        # Inject invalid foreign key into event batch to trigger PostgreSQL FK error
        orig_process_batch = orchestrator.processor.process_batch

        def bad_batch(obs):
            res = orig_process_batch(obs)
            if res.events:
                res.events[0] = res.events[0].model_copy(
                    update={"process_id": uuid.uuid4()}
                )
            return res

        orchestrator.processor.process_batch = bad_batch

        res = orchestrator.run_cycle(force_all=True)
        assert res.success is False
        assert "repository" in res.sink_errors

        # The savepoint rollback must prevent InFailedSqlTransaction (25P02) on PostgreSQL!
        # The outer user must still be accessible and queryable
        ou = pg_session.execute(
            select(LinuxUser).where(LinuxUser.id == outer_user.id)
        ).scalar_one_or_none()
        assert ou is not None
        assert ou.username == "pg_outer_user"

        # The failed cycle user must have been rolled back
        iu = pg_session.execute(
            select(LinuxUser).where(
                LinuxUser.host_id == pg_host.id, LinuxUser.uid == 7151
            )
        ).scalar_one_or_none()
        assert iu is None, "Failed cycle user must be rolled back on PostgreSQL"

    def test_pg_orchestrator_collector_error_isolation_persists_valid_events(
        self, pg_session: Session, pg_host: Host
    ):
        """On PostgreSQL: collector error alone does not roll back valid database writes from healthy collectors."""
        t0 = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        factory = lambda: Session(bind=pg_session.connection(), join_transaction_mode="create_savepoint")

        config = OrchestratorConfig(
            host_id=pg_host.id,
            fs_backend=MockInotifyBackend(),
            session_factory=factory,
            user_provider=lambda: [(4920, "pg_survivor_user")],
            wall_clock=lambda: t0,
        )
        orchestrator = CollectorOrchestrator(config)

        # Filesystem collector raises an error
        orchestrator.filesystem_collector.collect_observations = MagicMock(
            side_effect=RuntimeError("PG simulated inotify crash")
        )
        # Process collector produces a valid observation
        proc_obs = RawObservation(
            source="proc",
            host_id=pg_host.id,
            event_type="process.start",
            action="start",
            severity="info",
            observed_at=t0,
            uid=4920,
            pid=8920,
            command="/usr/bin/pg_survivor_app",
            object_type="process",
        )
        orchestrator.process_collector.collect_observations = lambda diff=True: [proc_obs]
        orchestrator.resource_collector.collect_observations = lambda **kw: []

        delivered = []
        orchestrator.callback = lambda evs: delivered.extend(evs)

        res = orchestrator.run_cycle(force_all=True)

        assert res.success is False
        assert "fs" in res.collector_errors
        assert not res.sink_errors
        assert len(res.events) == 1
        assert len(delivered) == 1
        assert orchestrator.get_status()["total_events"] == 1

        # Verify PostgreSQL database contains the committed rows
        with factory() as verify_s:
            user = verify_s.execute(
                select(LinuxUser).where(LinuxUser.host_id == pg_host.id, LinuxUser.uid == 4920)
            ).scalar_one_or_none()
            assert user is not None
            assert user.username == "pg_survivor_user"

            proc = verify_s.execute(
                select(Process).where(Process.host_id == pg_host.id, Process.pid == 8920)
            ).scalar_one_or_none()
            assert proc is not None
            assert proc.command == "/usr/bin/pg_survivor_app"

    def test_pg_orchestrator_callback_failure_preserves_committed_records(
        self, pg_session: Session, pg_host: Host
    ):
        """On PostgreSQL: callback failure after successful commit preserves committed records in the database."""
        t0 = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        factory = lambda: Session(bind=pg_session.connection(), join_transaction_mode="create_savepoint")

        def bad_callback(evs):
            raise RuntimeError("Postgres webhook connection dropped")

        config = OrchestratorConfig(
            host_id=pg_host.id,
            fs_backend=MockInotifyBackend(),
            session_factory=factory,
            user_provider=lambda: [(4925, "pg_callback_user")],
            wall_clock=lambda: t0,
        )
        orchestrator = CollectorOrchestrator(config, event_callback=bad_callback)

        proc_obs = RawObservation(
            source="proc",
            host_id=pg_host.id,
            event_type="process.start",
            action="start",
            severity="info",
            observed_at=t0,
            uid=4925,
            pid=8925,
            command="/usr/bin/pg_callback_app",
            object_type="process",
        )
        orchestrator.process_collector.collect_observations = lambda diff=True: [proc_obs]
        orchestrator.resource_collector.collect_observations = lambda **kw: []
        orchestrator.filesystem_collector.collect_observations = lambda: []

        res = orchestrator.run_cycle(force_all=True)

        assert res.success is False
        assert "callback" in res.sink_errors
        assert "Postgres webhook connection dropped" in res.sink_errors["callback"]
        assert len(res.events) == 1
        assert orchestrator.get_status()["total_events"] == 1

        # Verify PostgreSQL database still has the committed rows
        with factory() as verify_s:
            user = verify_s.execute(
                select(LinuxUser).where(LinuxUser.host_id == pg_host.id, LinuxUser.uid == 4925)
            ).scalar_one_or_none()
            assert user is not None
            assert user.username == "pg_callback_user"

            proc = verify_s.execute(
                select(Process).where(Process.host_id == pg_host.id, Process.pid == 8925)
            ).scalar_one_or_none()
            assert proc is not None

    def test_pg_orchestrator_entity_flush_error_does_not_pollute_transaction(
        self, pg_session: Session, pg_host: Host
    ):
        """On PostgreSQL: entity flush failure does not query the aborted session and rolls back savepoint cleanly."""
        t0 = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        factory = lambda: Session(bind=pg_session.connection(), join_transaction_mode="create_savepoint")

        # Mock user synchronizer to trigger a flush error
        mock_sync = MagicMock()
        mock_sync.sync_users.side_effect = IntegrityError(
            "INSERT INTO linux_users", {}, Exception("PG simulated user flush error")
        )

        config = OrchestratorConfig(
            host_id=pg_host.id,
            fs_backend=MockInotifyBackend(),
            session_factory=factory,
            wall_clock=lambda: t0,
        )
        orchestrator = CollectorOrchestrator(config, user_synchronizer=mock_sync)

        proc_obs = RawObservation(
            source="proc",
            host_id=pg_host.id,
            event_type="process.start",
            action="start",
            severity="info",
            observed_at=t0,
            uid=4930,
            pid=8930,
            command="/usr/bin/pg_flush_fail_app",
            object_type="process",
        )
        orchestrator.process_collector.collect_observations = lambda diff=True: [proc_obs]
        orchestrator.resource_collector.collect_observations = lambda **kw: []
        orchestrator.filesystem_collector.collect_observations = lambda: []

        orchestrator.process_lifecycle_service.apply_observations = MagicMock()

        res = orchestrator.run_cycle(force_all=True)

        assert res.success is False
        assert "user_sync" in res.sink_errors
        # Must not query aborted PG transaction
        assert orchestrator.process_lifecycle_service.apply_observations.call_count == 0
        assert orchestrator.session is None

        # Verify savepoint rolled back cleanly on PostgreSQL without InFailedSqlTransaction
        with factory() as verify_s:
            p = verify_s.execute(
                select(Process).where(Process.host_id == pg_host.id, Process.pid == 8930)
            ).scalar_one_or_none()
            assert p is None
