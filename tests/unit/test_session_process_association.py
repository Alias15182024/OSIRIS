"""Unit tests for Session-Process Association (Phase 2 Milestone 2.3)."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from backend.db.base import Base
from backend.db.models.host import Host
from backend.db.models.linux_user import LinuxUser
from backend.db.models.process import Process
from backend.db.models.user_session import UserSession
from backend.services.sessions.service import SessionReconstructionService


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture
def db_session() -> Session:
    """Provide an in-memory SQLite database session."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = Session(engine)

    yield session

    session.close()
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture
def host1(db_session: Session) -> Host:
    host = Host(id=uuid.uuid4(), hostname="host-01")
    db_session.add(host)
    db_session.commit()
    return host


@pytest.fixture
def host2(db_session: Session) -> Host:
    host = Host(id=uuid.uuid4(), hostname="host-02")
    db_session.add(host)
    db_session.commit()
    return host


@pytest.fixture
def user_alice(db_session: Session, host1: Host) -> LinuxUser:
    user = LinuxUser(
        id=uuid.uuid4(),
        host_id=host1.id,
        uid=1000,
        username="alice",
        first_seen_at=utcnow() - timedelta(days=1),
    )
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture
def user_root(db_session: Session, host1: Host) -> LinuxUser:
    user = LinuxUser(
        id=uuid.uuid4(),
        host_id=host1.id,
        uid=0,
        username="root",
        first_seen_at=utcnow() - timedelta(days=1),
    )
    db_session.add(user)
    db_session.commit()
    return user


class TestSessionProcessAssociation:
    """Test process-to-session and session-to-processes correlation."""

    def test_associate_processes_within_session_lifetime(
        self,
        db_session: Session,
        host1: Host,
        user_alice: LinuxUser,
    ) -> None:
        service = SessionReconstructionService()
        sess_start = utcnow() - timedelta(minutes=30)
        sess_end = utcnow() - timedelta(minutes=10)

        session = UserSession(
            id=uuid.uuid4(),
            host_id=host1.id,
            linux_user_id=user_alice.id,
            session_type="ssh",
            terminal="pts/0",
            started_at=sess_start,
            ended_at=sess_end,
        )
        db_session.add(session)

        # Process 1: started before session -> should NOT be associated
        p_before = Process(
            id=uuid.uuid4(),
            host_id=host1.id,
            pid=101,
            command="/bin/sleep 100",
            linux_user_id=user_alice.id,
            started_at=sess_start - timedelta(minutes=5),
        )
        # Process 2: started inside session -> SHOULD be associated
        p_inside = Process(
            id=uuid.uuid4(),
            host_id=host1.id,
            pid=102,
            command="/bin/bash",
            linux_user_id=user_alice.id,
            started_at=sess_start + timedelta(minutes=1),
        )
        # Process 3: started after session -> should NOT be associated
        p_after = Process(
            id=uuid.uuid4(),
            host_id=host1.id,
            pid=103,
            command="/bin/ls",
            linux_user_id=user_alice.id,
            started_at=sess_end + timedelta(minutes=5),
        )
        db_session.add_all([p_before, p_inside, p_after])
        db_session.commit()

        procs = service.get_session_processes(db_session, session.id)
        assert len(procs) == 1
        assert procs[0].id == p_inside.id

    def test_pid_reuse_protection(
        self,
        db_session: Session,
        host1: Host,
        user_alice: LinuxUser,
    ) -> None:
        """Distinct process lifetimes sharing the same PID are properly segregated."""
        service = SessionReconstructionService()
        sess_start = utcnow() - timedelta(hours=2)
        sess_end = utcnow() - timedelta(hours=1)

        session = UserSession(
            id=uuid.uuid4(),
            host_id=host1.id,
            linux_user_id=user_alice.id,
            session_type="ssh",
            started_at=sess_start,
            ended_at=sess_end,
        )
        db_session.add(session)

        # Process A with PID 5000 inside session
        proc_a = Process(
            id=uuid.uuid4(),
            host_id=host1.id,
            pid=5000,
            command="/usr/bin/make",
            linux_user_id=user_alice.id,
            started_at=sess_start + timedelta(minutes=10),
            ended_at=sess_start + timedelta(minutes=20),
        )

        # Process B with reused PID 5000 long after session ended
        proc_b = Process(
            id=uuid.uuid4(),
            host_id=host1.id,
            pid=5000,
            command="/usr/bin/curl https://example.com",
            linux_user_id=user_alice.id,
            started_at=utcnow() - timedelta(minutes=5),
            ended_at=utcnow(),
        )

        db_session.add_all([proc_a, proc_b])
        db_session.commit()

        procs = service.get_session_processes(db_session, session.id)
        proc_ids = [p.id for p in procs]
        assert proc_a.id in proc_ids
        assert proc_b.id not in proc_ids

    def test_cross_host_isolation_in_process_association(
        self,
        db_session: Session,
        host1: Host,
        host2: Host,
        user_alice: LinuxUser,
    ) -> None:
        service = SessionReconstructionService()
        sess_start = utcnow() - timedelta(minutes=30)

        session1 = UserSession(
            id=uuid.uuid4(),
            host_id=host1.id,
            linux_user_id=user_alice.id,
            session_type="ssh",
            started_at=sess_start,
        )
        db_session.add(session1)

        # Process on host 2 at the exact same timestamp
        proc_host2 = Process(
            id=uuid.uuid4(),
            host_id=host2.id,
            pid=1234,
            command="/bin/bash",
            linux_user_id=None,
            started_at=sess_start + timedelta(minutes=2),
        )
        db_session.add(proc_host2)
        db_session.commit()

        procs = service.get_session_processes(db_session, session1.id)
        assert len(procs) == 0

    def test_privilege_escalation_process_association(
        self,
        db_session: Session,
        host1: Host,
        user_alice: LinuxUser,
        user_root: LinuxUser,
    ) -> None:
        """Root process executed inside session window is correlated with the session."""
        service = SessionReconstructionService()
        sess_start = utcnow() - timedelta(minutes=40)
        sess_end = utcnow() - timedelta(minutes=10)

        session = UserSession(
            id=uuid.uuid4(),
            host_id=host1.id,
            linux_user_id=user_alice.id,
            session_type="ssh",
            started_at=sess_start,
            ended_at=sess_end,
        )
        db_session.add(session)

        # User process
        p_user = Process(
            id=uuid.uuid4(),
            host_id=host1.id,
            pid=2000,
            command="/bin/bash",
            linux_user_id=user_alice.id,
            started_at=sess_start + timedelta(minutes=1),
        )
        # Root process spawned via sudo
        p_root = Process(
            id=uuid.uuid4(),
            host_id=host1.id,
            pid=2005,
            command="/usr/bin/apt update",
            linux_user_id=user_root.id,
            started_at=sess_start + timedelta(minutes=5),
        )
        db_session.add_all([p_user, p_root])
        db_session.commit()

        procs = service.get_session_processes(db_session, session.id)
        assert len(procs) == 2
        pids = [p.pid for p in procs]
        assert 2000 in pids
        assert 2005 in pids

    def test_correlate_process_to_session(
        self,
        db_session: Session,
        host1: Host,
        user_alice: LinuxUser,
    ) -> None:
        service = SessionReconstructionService()
        t0 = utcnow() - timedelta(hours=1)
        session = UserSession(
            id=uuid.uuid4(),
            host_id=host1.id,
            linux_user_id=user_alice.id,
            session_type="ssh",
            started_at=t0,
        )
        db_session.add(session)

        proc = Process(
            id=uuid.uuid4(),
            host_id=host1.id,
            pid=3000,
            command="/usr/bin/python script.py",
            linux_user_id=user_alice.id,
            started_at=t0 + timedelta(minutes=10),
        )
        db_session.add(proc)
        db_session.commit()

        matched_sess = service.correlate_process_to_session(db_session, proc)
        assert matched_sess is not None
        assert matched_sess.id == session.id

    def test_nonexistent_session_returns_empty_processes(
        self, db_session: Session
    ) -> None:
        service = SessionReconstructionService()
        procs = service.get_session_processes(db_session, uuid.uuid4())
        assert procs == []

    def test_root_process_correlated_to_parent_session(
        self,
        db_session: Session,
        host1: Host,
        user_alice: LinuxUser,
        user_root: LinuxUser,
    ) -> None:
        """Root process with PPID pointing to user shell correlates to user session."""
        service = SessionReconstructionService()
        t0 = utcnow() - timedelta(minutes=30)
        session = UserSession(
            id=uuid.uuid4(),
            host_id=host1.id,
            linux_user_id=user_alice.id,
            session_type="ssh",
            started_at=t0,
        )
        db_session.add(session)

        p_shell = Process(
            id=uuid.uuid4(),
            host_id=host1.id,
            pid=4000,
            command="/bin/bash",
            linux_user_id=user_alice.id,
            started_at=t0 + timedelta(minutes=1),
        )
        p_root = Process(
            id=uuid.uuid4(),
            host_id=host1.id,
            pid=4005,
            ppid=4000,
            command="/usr/bin/cat /etc/shadow",
            linux_user_id=user_root.id,
            started_at=t0 + timedelta(minutes=5),
        )
        db_session.add_all([p_shell, p_root])
        db_session.commit()

        matched = service.correlate_process_to_session(db_session, p_root)
        assert matched is not None
        assert matched.id == session.id

    def test_cross_user_sudo_root_process_segregation(
        self,
        db_session: Session,
        host1: Host,
        user_alice: LinuxUser,
        user_root: LinuxUser,
    ) -> None:
        """Root commands from one user are not attributed to a concurrent user's session."""
        service = SessionReconstructionService()
        t0 = utcnow() - timedelta(minutes=40)

        user_bob = LinuxUser(
            id=uuid.uuid4(),
            host_id=host1.id,
            uid=1001,
            username="bob",
            first_seen_at=utcnow() - timedelta(days=1),
        )
        db_session.add(user_bob)

        s_alice = UserSession(
            id=uuid.uuid4(),
            host_id=host1.id,
            linux_user_id=user_alice.id,
            session_type="ssh",
            started_at=t0,
        )
        s_bob = UserSession(
            id=uuid.uuid4(),
            host_id=host1.id,
            linux_user_id=user_bob.id,
            session_type="ssh",
            started_at=t0,
        )
        db_session.add_all([s_alice, s_bob])

        # Bob shell and Bob sudo command
        p_bob_shell = Process(
            id=uuid.uuid4(),
            host_id=host1.id,
            pid=6000,
            command="/bin/bash",
            linux_user_id=user_bob.id,
            started_at=t0 + timedelta(minutes=2),
        )
        p_bob_root = Process(
            id=uuid.uuid4(),
            host_id=host1.id,
            pid=6001,
            ppid=6000,
            command="/usr/bin/cat /etc/shadow",
            linux_user_id=user_root.id,
            started_at=t0 + timedelta(minutes=5),
        )
        db_session.add_all([p_bob_shell, p_bob_root])
        db_session.commit()

        alice_procs = service.get_session_processes(db_session, s_alice.id)
        assert len(alice_procs) == 0

        bob_procs = service.get_session_processes(db_session, s_bob.id)
        assert len(bob_procs) == 2
        assert p_bob_root.id in [p.id for p in bob_procs]
