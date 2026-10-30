"""Unit tests for OSIRIS Incident API routes (Phase 2 Milestone 2.6)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
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
from backend.db.models.detection import Detection
from backend.db.models.detection_rule import DetectionRule
from backend.db.models.event import Event
from backend.db.models.host import Host
from backend.db.models.incident import Incident
from backend.main import app


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture
def api_session() -> Generator[Session, None, None]:
    """Provide an in-memory SQLite session for TestClient."""
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
    """TestClient with overridden database session."""
    app.dependency_overrides[get_db] = lambda: api_session
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def admin_user(api_session: Session) -> AppUser:
    user = AppUser(
        id=uuid.uuid4(),
        username="admin_alice",
        password_hash="fakehash",
        display_name="Alice Admin",
        role="admin",
        is_active=True,
        created_at=utcnow(),
    )
    api_session.add(user)
    api_session.commit()
    return user


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
def viewer_user(api_session: Session) -> AppUser:
    user = AppUser(
        id=uuid.uuid4(),
        username="viewer_carol",
        password_hash="fakehash",
        display_name="Carol Viewer",
        role="viewer",
        is_active=True,
        created_at=utcnow(),
    )
    api_session.add(user)
    api_session.commit()
    return user


@pytest.fixture
def admin_headers(admin_user: AppUser) -> dict[str, str]:
    token = create_access_token(user_id=admin_user.id, username=admin_user.username, role=admin_user.role)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def analyst_headers(analyst_user: AppUser) -> dict[str, str]:
    token = create_access_token(user_id=analyst_user.id, username=analyst_user.username, role=analyst_user.role)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def viewer_headers(viewer_user: AppUser) -> dict[str, str]:
    token = create_access_token(user_id=viewer_user.id, username=viewer_user.username, role=viewer_user.role)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def host_a(api_session: Session) -> Host:
    host = Host(id=uuid.uuid4(), hostname="srv-alpha", ip_address="192.168.1.10", created_at=utcnow())
    api_session.add(host)
    api_session.commit()
    return host


@pytest.fixture
def host_b(api_session: Session) -> Host:
    host = Host(id=uuid.uuid4(), hostname="srv-beta", ip_address="192.168.1.20", created_at=utcnow())
    api_session.add(host)
    api_session.commit()
    return host


@pytest.fixture
def test_incident(api_session: Session, host_a: Host, analyst_user: AppUser) -> Incident:
    inc = Incident(
        id=uuid.uuid4(),
        title="Unauthorized Sudo Elevation",
        description="Suspicious binary executed with root privileges",
        severity="high",
        status="open",
        category="privilege_escalation",
        host_id=host_a.id,
        created_by_id=analyst_user.id,
        first_observed_at=utcnow(),
        last_observed_at=utcnow(),
        created_at=utcnow(),
    )
    api_session.add(inc)
    api_session.commit()
    return inc


class TestIncidentsApiAuthAndRbac:
    """Validate authentication and role-based access control for Incidents API."""

    def test_unauthenticated_requests_fail(self, client: TestClient, test_incident: Incident) -> None:
        res = client.get("/api/incidents")
        assert res.status_code == 401

        res = client.post("/api/incidents", json={"title": "Test"})
        assert res.status_code == 401

        res = client.get(f"/api/incidents/{test_incident.id}")
        assert res.status_code == 401

    def test_viewer_can_read_but_cannot_mutate(
        self,
        client: TestClient,
        viewer_headers: dict[str, str],
        test_incident: Incident,
        host_a: Host,
    ) -> None:
        # Viewer CAN read
        res = client.get("/api/incidents", headers=viewer_headers)
        assert res.status_code == 200

        res = client.get(f"/api/incidents/{test_incident.id}", headers=viewer_headers)
        assert res.status_code == 200

        res = client.get(f"/api/incidents/{test_incident.id}/report", headers=viewer_headers)
        assert res.status_code == 200

        # Viewer CANNOT create
        res = client.post(
            "/api/incidents",
            json={"title": "Forbidden Creation", "severity": "low", "category": "execution", "host_id": str(host_a.id)},
            headers=viewer_headers,
        )
        assert res.status_code == 403

        # Viewer CANNOT update status
        res = client.post(
            f"/api/incidents/{test_incident.id}/status",
            json={"status": "investigating"},
            headers=viewer_headers,
        )
        assert res.status_code == 403

        # Viewer CANNOT add notes
        res = client.post(
            f"/api/incidents/{test_incident.id}/notes",
            json={"notes": "My thoughts"},
            headers=viewer_headers,
        )
        assert res.status_code == 403


class TestIncidentsApiEndpoints:
    """Validate CRUD, lifecycle operations, evidence, and reporting via HTTP."""

    def test_list_incidents_filtering_and_pagination(
        self,
        client: TestClient,
        analyst_headers: dict[str, str],
        test_incident: Incident,
        host_a: Host,
    ) -> None:
        # 1. Base list
        res = client.get("/api/incidents", headers=analyst_headers)
        assert res.status_code == 200
        data = res.json()
        assert data["total"] >= 1
        assert len(data["items"]) >= 1

        # 2. Filter by matching status
        res = client.get("/api/incidents?status=open", headers=analyst_headers)
        assert res.status_code == 200
        assert res.json()["total"] >= 1

        # 3. Filter by non-matching status
        res = client.get("/api/incidents?status=closed", headers=analyst_headers)
        assert res.status_code == 200
        assert res.json()["total"] == 0

        # 4. Filter by severity
        res = client.get("/api/incidents?severity=high", headers=analyst_headers)
        assert res.status_code == 200
        assert res.json()["total"] >= 1

        # 5. Invalid date bounds (start_time > end_time)
        st = (utcnow() + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        et = utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        res = client.get(f"/api/incidents?start_time={st}&end_time={et}", headers=analyst_headers)
        assert res.status_code == 400

    def test_create_and_get_incident(
        self,
        client: TestClient,
        analyst_headers: dict[str, str],
        host_a: Host,
    ) -> None:
        payload = {
            "title": "Lateral Movement Detected",
            "description": "Port scanning internal subnet",
            "severity": "critical",
            "category": "lateral_movement",
            "host_id": str(host_a.id),
        }
        res = client.post("/api/incidents", json=payload, headers=analyst_headers)
        assert res.status_code == 201
        inc = res.json()
        assert inc["title"] == payload["title"]
        assert inc["severity"] == "critical"
        assert inc["status"] == "open"
        inc_id = inc["id"]

        # GET detail
        detail_res = client.get(f"/api/incidents/{inc_id}", headers=analyst_headers)
        assert detail_res.status_code == 200
        detail = detail_res.json()
        assert detail["id"] == inc_id
        assert detail["hostname"] == "srv-alpha"
        assert detail["evidence_count"] == 0

    def test_patch_incident(
        self,
        client: TestClient,
        analyst_headers: dict[str, str],
        test_incident: Incident,
    ) -> None:
        patch_payload = {
            "title": "Updated Title for Elevation",
            "category": "credential_access",
        }
        res = client.patch(f"/api/incidents/{test_incident.id}", json=patch_payload, headers=analyst_headers)
        assert res.status_code == 200
        updated = res.json()
        assert updated["title"] == "Updated Title for Elevation"
        assert updated["category"] == "credential_access"

        # Empty title rejected with 422
        res_empty = client.patch(f"/api/incidents/{test_incident.id}", json={"title": ""}, headers=analyst_headers)
        assert res_empty.status_code == 422

        # Empty category rejected with 422
        res_empty_cat = client.patch(f"/api/incidents/{test_incident.id}", json={"category": ""}, headers=analyst_headers)
        assert res_empty_cat.status_code == 422

    def test_status_transitions_valid_and_invalid(
        self,
        client: TestClient,
        analyst_headers: dict[str, str],
        test_incident: Incident,
    ) -> None:
        # Valid: open -> investigating
        res = client.post(
            f"/api/incidents/{test_incident.id}/status",
            json={"status": "investigating", "notes": "Beginning triage"},
            headers=analyst_headers,
        )
        assert res.status_code == 200
        assert res.json()["status"] == "investigating"

        # Valid: investigating -> contained
        res = client.post(
            f"/api/incidents/{test_incident.id}/status",
            json={"status": "contained", "containment_summary": "Network isolated"},
            headers=analyst_headers,
        )
        assert res.status_code == 200
        assert res.json()["status"] == "contained"

        # Valid: contained -> resolved
        res = client.post(
            f"/api/incidents/{test_incident.id}/status",
            json={"status": "resolved", "resolution_summary": "Malicious binary removed"},
            headers=analyst_headers,
        )
        assert res.status_code == 200
        assert res.json()["status"] == "resolved"

        # Valid: resolved -> closed
        res = client.post(
            f"/api/incidents/{test_incident.id}/status",
            json={"status": "closed", "closure_summary": "Incident concluded"},
            headers=analyst_headers,
        )
        assert res.status_code == 200
        assert res.json()["status"] == "closed"

        # Invalid: closed -> investigating without reason -> 400
        res = client.post(
            f"/api/incidents/{test_incident.id}/status",
            json={"status": "investigating"},
            headers=analyst_headers,
        )
        assert res.status_code == 400

    def test_severity_escalation_and_downgrade(
        self,
        client: TestClient,
        analyst_headers: dict[str, str],
        test_incident: Incident,
    ) -> None:
        # Escalate high -> critical
        res = client.post(
            f"/api/incidents/{test_incident.id}/severity",
            json={"severity": "critical", "reason": "Impact expanded"},
            headers=analyst_headers,
        )
        assert res.status_code == 200
        assert res.json()["severity"] == "critical"

        # Downgrade without allow_downgrade flag -> 400
        res = client.post(
            f"/api/incidents/{test_incident.id}/severity",
            json={"severity": "low", "reason": "False alarm on secondary targets", "allow_downgrade": False},
            headers=analyst_headers,
        )
        assert res.status_code == 400

        # Downgrade with allow_downgrade flag -> 200
        res = client.post(
            f"/api/incidents/{test_incident.id}/severity",
            json={"severity": "low", "reason": "False alarm on secondary targets", "allow_downgrade": True},
            headers=analyst_headers,
        )
        assert res.status_code == 200
        assert res.json()["severity"] == "low"

    def test_assign_analyst_and_add_notes(
        self,
        client: TestClient,
        analyst_headers: dict[str, str],
        test_incident: Incident,
        analyst_user: AppUser,
    ) -> None:
        # Assign
        res = client.post(
            f"/api/incidents/{test_incident.id}/assign",
            json={"assigned_to_id": str(analyst_user.id), "notes": "Handing off to Bob"},
            headers=analyst_headers,
        )
        assert res.status_code == 200
        assert res.json()["assigned_to_id"] == str(analyst_user.id)

        # Add note
        res = client.post(
            f"/api/incidents/{test_incident.id}/notes",
            json={"notes": "Examined memory dump, beacon active"},
            headers=analyst_headers,
        )
        assert res.status_code == 200
        assert res.json()["change_type"] == "note_added"

        # Check history
        hist_res = client.get(f"/api/incidents/{test_incident.id}/history", headers=analyst_headers)
        assert hist_res.status_code == 200
        hist_list = hist_res.json()
        assert len(hist_list) >= 2

    def test_evidence_and_event_linking(
        self,
        api_session: Session,
        client: TestClient,
        analyst_headers: dict[str, str],
        test_incident: Incident,
        host_a: Host,
        host_b: Host,
    ) -> None:
        # Create event on host A
        now = utcnow()
        evt_a = Event(
            id=uuid.uuid4(),
            host_id=host_a.id,
            timestamp=now,
            event_type="exec",
            action="spawn",
            source="auditd",
            command="/usr/bin/whoami",
            success=True,
        )
        evt_b = Event(
            id=uuid.uuid4(),
            host_id=host_b.id,
            timestamp=now,
            event_type="exec",
            action="spawn",
            source="auditd",
            command="/usr/bin/id",
            success=True,
        )
        api_session.add_all([evt_a, evt_b])
        api_session.commit()

        # Link event on Host A -> 201
        res = client.post(
            f"/api/incidents/{test_incident.id}/events",
            json={"event_id": str(evt_a.id), "relationship": "initial_recon", "investigation_notes": "First recon command"},
            headers=analyst_headers,
        )
        assert res.status_code == 201
        assert res.json()["event_id"] == str(evt_a.id)

        # Duplicate link -> 409
        res = client.post(
            f"/api/incidents/{test_incident.id}/events",
            json={"event_id": str(evt_a.id)},
            headers=analyst_headers,
        )
        assert res.status_code == 409

        # Cross-host link attempt (Host B event on Host A incident) -> 400
        res = client.post(
            f"/api/incidents/{test_incident.id}/events",
            json={"event_id": str(evt_b.id)},
            headers=analyst_headers,
        )
        assert res.status_code == 400

        # List events
        list_res = client.get(f"/api/incidents/{test_incident.id}/events", headers=analyst_headers)
        assert list_res.status_code == 200
        assert len(list_res.json()) == 1

        # Generic evidence link
        res = client.post(
            f"/api/incidents/{test_incident.id}/evidence",
            json={
                "evidence_type": "custom",
                "source_id": "cust-999",
                "title": "Network PCAP Extraction",
                "description": "Captured TLS handshake to C2",
                "provenance": {"packet_count": 42},
            },
            headers=analyst_headers,
        )
        assert res.status_code == 201
        assert res.json()["title"] == "Network PCAP Extraction"

        # List evidence (includes event evidence + custom evidence)
        ev_res = client.get(f"/api/incidents/{test_incident.id}/evidence", headers=analyst_headers)
        assert ev_res.status_code == 200
        assert len(ev_res.json()) == 2

    def test_report_export_json_and_markdown(
        self,
        client: TestClient,
        analyst_headers: dict[str, str],
        test_incident: Incident,
    ) -> None:
        # JSON format
        res_json = client.get(f"/api/incidents/{test_incident.id}/report?format=json", headers=analyst_headers)
        assert res_json.status_code == 200
        report = res_json.json()
        assert report["incident"]["id"] == str(test_incident.id)
        assert "timeline" in report

        # Markdown format
        res_md = client.get(f"/api/incidents/{test_incident.id}/report?format=markdown", headers=analyst_headers)
        assert res_md.status_code == 200
        assert "text/markdown" in res_md.headers["content-type"]
        assert f"incident-{test_incident.id}-report.md" in res_md.headers["content-disposition"]
        assert f"# OSIRIS Forensic Incident Report: {test_incident.title}" in res_md.text

    def test_not_found_errors(
        self,
        client: TestClient,
        analyst_headers: dict[str, str],
    ) -> None:
        random_id = str(uuid.uuid4())
        assert client.get(f"/api/incidents/{random_id}", headers=analyst_headers).status_code == 404
        assert client.patch(f"/api/incidents/{random_id}", json={"title": "Test"}, headers=analyst_headers).status_code == 404
        assert client.post(f"/api/incidents/{random_id}/status", json={"status": "open"}, headers=analyst_headers).status_code == 404
        assert client.post(f"/api/incidents/{random_id}/severity", json={"severity": "high", "reason": "Test non-existent"}, headers=analyst_headers).status_code == 404
        assert client.get(f"/api/incidents/{random_id}/report", headers=analyst_headers).status_code == 404

    def test_add_evidence_malformed_uuid_returns_400(
        self,
        client: TestClient,
        analyst_headers: dict[str, str],
        test_incident: Incident,
    ) -> None:
        # Invalid UUID in source_id for typed evidence returns 400
        res = client.post(
            f"/api/incidents/{test_incident.id}/evidence",
            json={
                "evidence_type": "detection",
                "source_id": "not-a-valid-uuid",
                "title": "Bad Detection Link",
            },
            headers=analyst_headers,
        )
        assert res.status_code == 400
