"""Integration tests for event persistence against local PostgreSQL (osiris_dev).

Verifies that NormalizedEvent instances are correctly saved, retrieved,
and queryable in PostgreSQL with JSONB support, foreign keys, and transactions.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.config import settings
from backend.db.models.event import Event
from backend.db.models.host import Host
from backend.db.models.process import Process
from backend.services.events.processor import EventProcessor
from backend.services.events.repository import EventRepository
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
