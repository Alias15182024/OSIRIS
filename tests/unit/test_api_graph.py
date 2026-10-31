"""Unit tests for OSIRIS Entity Graph API routes (Phase 2 Milestone 2.7)."""

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
from backend.db.models.linux_user import LinuxUser
from backend.db.models.process import Process
from backend.db.models.snapshot import Snapshot
from backend.db.models.user_session import UserSession
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
def sample_graph_data(api_session: Session) -> dict:
    host = Host(id=uuid.uuid4(), hostname="graph-host", ip_address="10.0.0.1", created_at=utcnow())
    user = LinuxUser(id=uuid.uuid4(), host_id=host.id, uid=1000, username="testuser", first_seen_at=utcnow())
    session = UserSession(id=uuid.uuid4(), host_id=host.id, linux_user_id=user.id, session_type="ssh", started_at=utcnow())
    proc = Process(
        id=uuid.uuid4(),
        host_id=host.id,
        linux_user_id=user.id,
        pid=1234,
        command="/bin/bash",
        started_at=utcnow(),
    )
    event = Event(
        id=uuid.uuid4(),
        host_id=host.id,
        process_id=proc.id,
        timestamp=utcnow(),
        source="auditd",
        event_type="process",
        action="fork",
    )
    api_session.add_all([host, user, session, proc, event])
    api_session.commit()
    return {"host": host, "user": user, "session": session, "process": proc, "event": event}


class TestEntityGraphApi:
    def test_unauthenticated_request_rejected(self, client: TestClient) -> None:
        resp = client.get("/api/graph")
        assert resp.status_code == 401

    def test_get_initial_host_graph(
        self, client: TestClient, analyst_headers: dict[str, str], sample_graph_data: dict
    ) -> None:
        host = sample_graph_data["host"]
        resp = client.get(f"/api/graph?host_id={host.id}&depth=2", headers=analyst_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["nodes"]) >= 2
        assert len(data["edges"]) >= 1
        assert any(n["id"] == f"host:{host.id}" for n in data["nodes"])

    def test_expand_graph_node(
        self, client: TestClient, analyst_headers: dict[str, str], sample_graph_data: dict
    ) -> None:
        proc = sample_graph_data["process"]
        payload = {
            "node_type": "process",
            "node_id": str(proc.id),
            "depth": 1,
            "max_nodes": 50,
            "existing_node_ids": [f"process:{proc.id}"],
        }
        resp = client.post("/api/graph/expand", json=payload, headers=analyst_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "nodes" in data
        assert "edges" in data

    def test_get_entity_pivots(
        self, client: TestClient, analyst_headers: dict[str, str], sample_graph_data: dict
    ) -> None:
        proc = sample_graph_data["process"]
        resp = client.get(f"/api/graph/pivot/process/{proc.id}", headers=analyst_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["entity_type"] == "process"
        assert data["entity_id"] == str(proc.id)
        assert "events" in data["related_entities"]
        assert len(data["related_entities"]["events"]) >= 1

    def test_snapshot_expansion_and_pivot_endpoints(
        self,
        client: TestClient,
        api_session: Session,
        analyst_headers: dict[str, str],
        sample_graph_data: dict,
    ) -> None:
        host = sample_graph_data["host"]
        snap = Snapshot(
            id=uuid.uuid4(),
            host_id=host.id,
            timestamp=utcnow(),
            snapshot_type="system_profile",
            data={},
        )
        api_session.add(snap)
        api_session.commit()

        # Expansion
        expand_payload = {
            "node_type": "snapshot",
            "node_id": str(snap.id),
            "depth": 1,
            "max_nodes": 20,
            "existing_node_ids": [f"snapshot:{snap.id}"],
        }
        exp_resp = client.post("/api/graph/expand", json=expand_payload, headers=analyst_headers)
        assert exp_resp.status_code == 200
        assert any(n["id"] == f"snapshot:{snap.id}" for n in exp_resp.json()["nodes"])

        # Pivot
        piv_resp = client.get(f"/api/graph/pivot/snapshot/{snap.id}", headers=analyst_headers)
        assert piv_resp.status_code == 200
        piv_data = piv_resp.json()
        assert piv_data["entity_type"] == "snapshot"
        assert "host" in piv_data["related_entities"]

