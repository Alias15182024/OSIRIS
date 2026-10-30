"""Integration tests for Session Reconstruction & Tracking lifecycle (Phase 2 Milestone 2.3).

Verifies the complete end-to-end pipeline:
1. Synthetic auth.log entries
2. SyslogCollector parsing to RawObservation
3. EventProcessor normalization and identity resolution
4. EventRepository persistence
5. SessionReconstructionService session lifecycle and process association
6. TimelineService timeline integration with session_context
7. Sessions API endpoints (/api/sessions, /api/sessions/{session_id})
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from starlette.testclient import TestClient

from backend.api.deps import get_db
from backend.api.security import create_access_token
from backend.db.base import Base
from backend.db.models.app_user import AppUser
from backend.db.models.host import Host
from backend.db.models.linux_user import LinuxUser
from backend.db.models.process import Process
from backend.db.models.user_session import UserSession
from backend.main import app
from backend.services.events.processor import EventProcessor
from backend.services.events.repository import EventRepository
from backend.services.sessions.service import SessionReconstructionService
from backend.services.timeline.service import TimelineService
from collectors.syslog.collector import SyslogCollector


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture
def test_db() -> Session:
    """Thread-safe in-memory SQLite session."""
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
def client(test_db: Session) -> TestClient:
    app.dependency_overrides[get_db] = lambda: test_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def auth_headers(test_db: Session) -> dict[str, str]:
    user = AppUser(
        id=uuid.uuid4(),
        username="admin",
        password_hash="pbkdf2_sha256$100000$mock$mock",
        display_name="Admin",
        role="admin",
        is_active=True,
    )
    test_db.add(user)
    test_db.commit()
    token = create_access_token(user_id=user.id, username=user.username, role=user.role)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def monitored_host(test_db: Session) -> Host:
    host = Host(id=uuid.uuid4(), hostname="server-01", ip_address="192.168.1.10")
    test_db.add(host)
    test_db.commit()
    return host


@pytest.fixture
def linux_alice(test_db: Session, monitored_host: Host) -> LinuxUser:
    user = LinuxUser(
        id=uuid.uuid4(),
        host_id=monitored_host.id,
        uid=1000,
        username="alice",
        first_seen_at=utcnow() - timedelta(days=7),
    )
    test_db.add(user)
    test_db.commit()
    return user


class TestSessionLifecycleEndToEnd:
    """Comprehensive end-to-end integration test."""

    def test_full_auth_log_to_session_and_timeline_pipeline(
        self,
        test_db: Session,
        client: TestClient,
        auth_headers: dict[str, str],
        monitored_host: Host,
        linux_alice: LinuxUser,
        tmp_path: Path,
    ) -> None:
        # Step 1: Write synthetic auth.log
        auth_log = tmp_path / "auth.log"
        auth_log.write_text(
            "Oct 30 14:00:00 server-01 sshd[1001]: Accepted publickey for alice from 192.168.1.50 port 55432 ssh2: RSA\n"
            "Oct 30 14:00:01 server-01 sshd[1001]: pam_unix(sshd:session): session opened for user alice(uid=1000) by (uid=0)\n"
            "Oct 30 14:05:00 server-01 sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update\n"
            "Oct 30 14:20:00 server-01 sshd[1001]: pam_unix(sshd:session): session closed for user alice\n"
        )

        # Step 2: Collect with SyslogCollector
        collector = SyslogCollector(
            host_id=monitored_host.id,
            log_path=auth_log,
            default_year=2026,
        )
        observations = collector.collect_observations()
        assert len(observations) == 4

        # Step 3: Process through EventProcessor & persist with EventRepository
        processor = EventProcessor.with_database(test_db)
        repo = EventRepository(test_db)
        reconstruction = SessionReconstructionService()

        for obs in observations:
            p_res = processor.process(obs)
            assert p_res.success
            assert p_res.event is not None
            repo.save(p_res.event)
            # Step 4: Feed into SessionReconstructionService
            reconstruction.process_event(test_db, p_res.event, host_id=monitored_host.id)

        test_db.commit()

        # Step 5: Verify UserSession was created and completed
        total, sessions = reconstruction.list_sessions(test_db, host_id=monitored_host.id)
        assert total == 1
        sess = sessions[0]
        assert sess.linux_user_id == linux_alice.id
        assert sess.session_type == "ssh"
        assert sess.remote_host == "192.168.1.50"
        assert sess.ended_at is not None

        # Step 6: Create interactive process executed during session
        proc = Process(
            id=uuid.uuid4(),
            host_id=monitored_host.id,
            pid=2048,
            command="/bin/bash",
            linux_user_id=linux_alice.id,
            started_at=sess.started_at + timedelta(seconds=10),
            ended_at=sess.started_at + timedelta(minutes=15),
        )
        test_db.add(proc)
        test_db.commit()

        # Verify process association
        session_procs = reconstruction.get_session_processes(test_db, sess.id)
        assert len(session_procs) == 1
        assert session_procs[0].id == proc.id

        # Step 7: Verify TimelineService integration
        timeline_service = TimelineService(test_db)
        tl_items, tl_total = timeline_service.reconstruct_timeline(
            host_id=monitored_host.id,
            start_time=sess.started_at - timedelta(minutes=5),
            end_time=sess.ended_at + timedelta(minutes=5),
            limit=50,
        )
        assert tl_total > 0

        # Verify session records exist in timeline
        record_types = [item.record_type for item in tl_items]
        assert "session" in record_types or "event" in record_types

        # Step 8: Verify REST API endpoints
        # GET /api/sessions
        resp_list = client.get(
            f"/api/sessions?host_id={monitored_host.id}", headers=auth_headers
        )
        assert resp_list.status_code == 200
        list_data = resp_list.json()
        assert list_data["total"] == 1
        assert list_data["items"][0]["id"] == str(sess.id)
        assert list_data["items"][0]["username"] == "alice"
        assert list_data["items"][0]["is_active"] is False

        # GET /api/sessions/{session_id}
        resp_detail = client.get(
            f"/api/sessions/{sess.id}", headers=auth_headers
        )
        assert resp_detail.status_code == 200
        detail_data = resp_detail.json()
        assert detail_data["id"] == str(sess.id)
        assert detail_data["username"] == "alice"
        assert detail_data["process_count"] == 1
        assert detail_data["processes"][0]["pid"] == 2048
        assert detail_data["processes"][0]["command"] == "/bin/bash"
