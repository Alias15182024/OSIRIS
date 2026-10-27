"""Integration tests for event persistence against local PostgreSQL (osiris_dev).

Verifies that NormalizedEvent instances are correctly saved, retrieved,
and queryable in PostgreSQL with JSONB support, foreign keys, and transactions.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

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
