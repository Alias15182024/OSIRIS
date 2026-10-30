"""Unit tests for OSIRIS Session Reconstruction Service (Phase 2 Milestone 2.3)."""

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
from backend.db.models.user_session import UserSession
from backend.services.sessions.service import SessionReconstructionService, _ensure_utc


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
def default_host(db_session: Session) -> Host:
    host = Host(
        id=uuid.uuid4(),
        hostname="test-host-01",
        ip_address="10.0.0.1",
    )
    db_session.add(host)
    db_session.commit()
    return host


@pytest.fixture
def default_user(db_session: Session, default_host: Host) -> LinuxUser:
    user = LinuxUser(
        id=uuid.uuid4(),
        host_id=default_host.id,
        uid=1000,
        username="alice",
        first_seen_at=utcnow() - timedelta(days=1),
    )
    db_session.add(user)
    db_session.commit()
    return user


class TestSessionLifecycleCreation:
    """Test session creation and user resolution."""

    def test_create_session_from_ssh_login(
        self, db_session: Session, default_host: Host, default_user: LinuxUser
    ) -> None:
        service = SessionReconstructionService()
        login_ts = utcnow() - timedelta(minutes=10)

        event = {
            "host_id": default_host.id,
            "event_type": "auth.login_success",
            "action": "login",
            "timestamp": login_ts,
            "username": "alice",
            "payload": {
                "remote_host": "192.168.1.100",
                "service": "sshd",
                "terminal": "pts/0",
            },
        }

        sess = service.process_event(db_session, event)
        assert sess is not None
        assert sess.host_id == default_host.id
        assert sess.linux_user_id == default_user.id
        assert sess.session_type == "ssh"
        assert sess.terminal == "pts/0"
        assert sess.remote_host == "192.168.1.100"
        assert sess.started_at == login_ts
        assert sess.ended_at is None

    def test_create_session_from_local_tty_login(
        self, db_session: Session, default_host: Host, default_user: LinuxUser
    ) -> None:
        service = SessionReconstructionService()
        login_ts = utcnow() - timedelta(minutes=5)

        event = {
            "host_id": default_host.id,
            "event_type": "auth.login_success",
            "action": "login",
            "timestamp": login_ts,
            "uid": 1000,
            "payload": {
                "terminal": "tty1",
            },
        }

        sess = service.process_event(db_session, event)
        assert sess is not None
        assert sess.linux_user_id == default_user.id
        assert sess.session_type == "tty"
        assert sess.terminal == "tty1"
        assert sess.ended_at is None

    def test_create_session_missing_user_preserves_null_linux_user_id(
        self, db_session: Session, default_host: Host
    ) -> None:
        service = SessionReconstructionService()
        login_ts = utcnow()

        event = {
            "host_id": default_host.id,
            "event_type": "auth.login_success",
            "action": "login",
            "timestamp": login_ts,
            "username": "unknown_user",
            "payload": {"terminal": "pts/2"},
        }

        sess = service.process_event(db_session, event)
        assert sess is not None
        assert sess.linux_user_id is None
        assert sess.terminal == "pts/2"


class TestSessionCompletionAndLogout:
    """Test session closure and matching rules."""

    def test_complete_session_on_logout(
        self, db_session: Session, default_host: Host, default_user: LinuxUser
    ) -> None:
        service = SessionReconstructionService()
        start_ts = utcnow() - timedelta(minutes=20)
        end_ts = utcnow() - timedelta(minutes=5)

        # 1. Login
        login_event = {
            "host_id": default_host.id,
            "event_type": "auth.login_success",
            "action": "login",
            "timestamp": start_ts,
            "username": "alice",
            "payload": {"terminal": "pts/0", "remote_host": "192.168.1.100"},
        }
        sess = service.process_event(db_session, login_event)
        assert sess is not None
        assert sess.ended_at is None

        # 2. Logout
        logout_event = {
            "host_id": default_host.id,
            "event_type": "auth.logout",
            "action": "session_close",
            "timestamp": end_ts,
            "username": "alice",
            "payload": {"terminal": "pts/0"},
        }
        closed_sess = service.process_event(db_session, logout_event)
        assert closed_sess is not None
        assert closed_sess.id == sess.id
        assert closed_sess.ended_at == end_ts

    def test_unclosed_session_remains_active(
        self, db_session: Session, default_host: Host, default_user: LinuxUser
    ) -> None:
        service = SessionReconstructionService()
        start_ts = utcnow() - timedelta(hours=2)

        login_event = {
            "host_id": default_host.id,
            "event_type": "auth.login_success",
            "action": "login",
            "timestamp": start_ts,
            "username": "alice",
            "payload": {"terminal": "pts/1"},
        }
        sess = service.process_event(db_session, login_event)
        assert sess is not None
        assert sess.ended_at is None

        total, items = service.list_sessions(db_session, host_id=default_host.id, is_active=True)
        assert total == 1
        assert items[0].id == sess.id

    def test_terminal_collision_closes_prior_unclosed_session(
        self, db_session: Session, default_host: Host, default_user: LinuxUser
    ) -> None:
        service = SessionReconstructionService()
        t1 = utcnow() - timedelta(hours=1)
        t2 = utcnow() - timedelta(minutes=10)

        # First session on pts/0 (never received logout)
        ev1 = {
            "host_id": default_host.id,
            "event_type": "auth.login_success",
            "action": "login",
            "timestamp": t1,
            "username": "alice",
            "payload": {"terminal": "pts/0"},
        }
        s1 = service.process_event(db_session, ev1)
        assert s1.ended_at is None

        # New session on same terminal pts/0
        ev2 = {
            "host_id": default_host.id,
            "event_type": "auth.login_success",
            "action": "login",
            "timestamp": t2,
            "username": "alice",
            "payload": {"terminal": "pts/0"},
        }
        s2 = service.process_event(db_session, ev2)

        # s1 should have been closed at t2
        db_session.refresh(s1)
        assert s1.ended_at is not None
        assert _ensure_utc(s1.ended_at) == t2
        assert s2.ended_at is None


class TestSessionPrivilegeTransitions:
    """Verify that sudo and su are tracked as privilege escalations, not login sessions."""

    def test_sudo_does_not_create_session(
        self, db_session: Session, default_host: Host, default_user: LinuxUser
    ) -> None:
        service = SessionReconstructionService()
        sudo_event = {
            "host_id": default_host.id,
            "event_type": "auth.sudo",
            "action": "sudo",
            "timestamp": utcnow(),
            "username": "alice",
            "command": "/usr/bin/cat /etc/shadow",
            "payload": {
                "terminal": "pts/0",
                "target_user": "root",
                "source_user": "alice",
                "command": "/usr/bin/cat /etc/shadow",
            },
        }

        res = service.process_event(db_session, sudo_event)
        assert res is None

        # Verify no sessions exist in DB
        total, items = service.list_sessions(db_session, host_id=default_host.id)
        assert total == 0

    def test_su_does_not_create_session(
        self, db_session: Session, default_host: Host, default_user: LinuxUser
    ) -> None:
        service = SessionReconstructionService()
        su_event = {
            "host_id": default_host.id,
            "event_type": "auth.su",
            "action": "su",
            "timestamp": utcnow(),
            "username": "alice",
            "payload": {"terminal": "pts/0", "target_user": "root"},
        }

        res = service.process_event(db_session, su_event)
        assert res is None

        total, _ = service.list_sessions(db_session, host_id=default_host.id)
        assert total == 0

    def test_pam_cron_does_not_create_session(
        self, db_session: Session, default_host: Host
    ) -> None:
        service = SessionReconstructionService()
        cron_event = {
            "host_id": default_host.id,
            "event_type": "auth.login_success",
            "action": "session_open",
            "timestamp": utcnow(),
            "username": "root",
            "payload": {"pam_service": "cron"},
        }
        res = service.process_event(db_session, cron_event)
        assert res is None


class TestSessionIdempotencyAndIsolation:
    """Test idempotency and cross-host isolation."""

    def test_repeated_login_processing_is_idempotent(
        self, db_session: Session, default_host: Host, default_user: LinuxUser
    ) -> None:
        service = SessionReconstructionService()
        ts = utcnow() - timedelta(minutes=15)
        event = {
            "host_id": default_host.id,
            "event_type": "auth.login_success",
            "action": "login",
            "timestamp": ts,
            "username": "alice",
            "payload": {"terminal": "pts/0"},
        }

        s1 = service.process_event(db_session, event)
        s2 = service.process_event(db_session, event)

        assert s1 is not None and s2 is not None
        assert s1.id == s2.id

        total, items = service.list_sessions(db_session, host_id=default_host.id)
        assert total == 1

    def test_repeated_logout_processing_is_idempotent(
        self, db_session: Session, default_host: Host, default_user: LinuxUser
    ) -> None:
        service = SessionReconstructionService()
        start_ts = utcnow() - timedelta(minutes=30)
        end_ts = utcnow() - timedelta(minutes=10)

        login = {
            "host_id": default_host.id,
            "event_type": "auth.login_success",
            "action": "login",
            "timestamp": start_ts,
            "username": "alice",
            "payload": {"terminal": "pts/0"},
        }
        service.process_event(db_session, login)

        logout = {
            "host_id": default_host.id,
            "event_type": "auth.logout",
            "action": "session_close",
            "timestamp": end_ts,
            "username": "alice",
            "payload": {"terminal": "pts/0"},
        }
        c1 = service.process_event(db_session, logout)
        c2 = service.process_event(db_session, logout)

        assert c1 is not None and c2 is not None
        assert c1.id == c2.id
        assert c1.ended_at == end_ts

    def test_cross_host_isolation(
        self, db_session: Session, default_host: Host, default_user: LinuxUser
    ) -> None:
        host2 = Host(id=uuid.uuid4(), hostname="host-02")
        db_session.add(host2)
        db_session.commit()

        service = SessionReconstructionService()
        ts = utcnow()

        ev1 = {
            "host_id": default_host.id,
            "event_type": "auth.login_success",
            "action": "login",
            "timestamp": ts,
            "username": "alice",
            "payload": {"terminal": "pts/0"},
        }
        ev2 = {
            "host_id": host2.id,
            "event_type": "auth.login_success",
            "action": "login",
            "timestamp": ts,
            "username": "alice",
            "payload": {"terminal": "pts/0"},
        }

        s1 = service.process_event(db_session, ev1)
        s2 = service.process_event(db_session, ev2)

        assert s1.id != s2.id
        assert s1.host_id == default_host.id
        assert s2.host_id == host2.id

        # Query host 1
        t1, items1 = service.list_sessions(db_session, host_id=default_host.id)
        assert t1 == 1
        assert items1[0].host_id == default_host.id

        # Query host 2
        t2, items2 = service.list_sessions(db_session, host_id=host2.id)
        assert t2 == 1
        assert items2[0].host_id == host2.id

    def test_multi_user_same_remote_host_within_window(
        self, db_session: Session, default_host: Host, default_user: LinuxUser
    ) -> None:
        """Two distinct users logging in from same IP within 10s must not collide."""
        service = SessionReconstructionService()
        t0 = utcnow()

        bob = LinuxUser(
            id=uuid.uuid4(),
            host_id=default_host.id,
            uid=1001,
            username="bob",
            first_seen_at=utcnow(),
        )
        db_session.add(bob)
        db_session.commit()

        ev_alice = {
            "host_id": default_host.id,
            "event_type": "auth.login_success",
            "action": "login",
            "timestamp": t0,
            "username": "alice",
            "payload": {"remote_host": "192.168.1.50", "terminal": "pts/0"},
        }
        ev_bob = {
            "host_id": default_host.id,
            "event_type": "auth.login_success",
            "action": "login",
            "timestamp": t0 + timedelta(seconds=2),
            "username": "bob",
            "payload": {"remote_host": "192.168.1.50", "terminal": "pts/1"},
        }

        s_alice = service.process_event(db_session, ev_alice)
        s_bob = service.process_event(db_session, ev_bob)

        assert s_alice is not None and s_bob is not None
        assert s_alice.id != s_bob.id
        assert s_alice.linux_user_id == default_user.id
        assert s_bob.linux_user_id == bob.id

    def test_unrelated_user_logout_does_not_close_active_session(
        self, db_session: Session, default_host: Host, default_user: LinuxUser
    ) -> None:
        """Logout event for a user with no active session must never close other users' sessions."""
        service = SessionReconstructionService()
        t0 = utcnow()

        ev_login = {
            "host_id": default_host.id,
            "event_type": "auth.login_success",
            "action": "login",
            "timestamp": t0,
            "username": "alice",
            "payload": {"terminal": "pts/0"},
        }
        s_alice = service.process_event(db_session, ev_login)
        assert s_alice.ended_at is None

        # Logout for unknown / unrelated user 'mallory'
        ev_logout = {
            "host_id": default_host.id,
            "event_type": "auth.logout",
            "action": "session_close",
            "timestamp": t0 + timedelta(minutes=5),
            "username": "mallory",
            "payload": {},
        }
        res = service.process_event(db_session, ev_logout)
        assert res is None

        db_session.refresh(s_alice)
        assert s_alice.ended_at is None
