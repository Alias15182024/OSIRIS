"""Unit tests for OSIRIS Detections API routes (Phase 2 Milestone 2.4)."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Generator

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
from backend.db.models.host import Host
from backend.main import app
from backend.services.detection.service import DetectionService


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture
def api_session() -> Generator[Session, None, None]:
    """Provide a thread-safe in-memory SQLite session for TestClient."""
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
    """TestClient with get_db dependency overridden to use api_session."""
    app.dependency_overrides[get_db] = lambda: api_session
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def test_user(api_session: Session) -> AppUser:
    user = AppUser(
        id=uuid.uuid4(),
        username="secops_analyst",
        password_hash="fakehash123",
        role="admin",
        is_active=True,
        created_at=utcnow(),
    )
    api_session.add(user)
    api_session.commit()
    return user


@pytest.fixture
def auth_headers(test_user: AppUser) -> dict[str, str]:
    token = create_access_token(
        user_id=test_user.id,
        username=test_user.username,
        role=test_user.role,
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def test_host(api_session: Session) -> Host:
    host = Host(
        id=uuid.uuid4(),
        hostname="monitored-srv-01",
        created_at=utcnow(),
    )
    api_session.add(host)
    api_session.commit()
    return host


@pytest.fixture
def test_rule(api_session: Session) -> DetectionRule:
    rule = DetectionRule(
        id=uuid.uuid4(),
        rule_id="RULE-API-001",
        name="API Test Rule",
        description="Rule used for API testing",
        category="privilege_escalation",
        severity="high",
        enabled=True,
        version=1,
        rule_type="single_event",
        conditions={"all": [{"field": "command", "operator": "==", "value": "sudo -i"}]},
        created_at=utcnow(),
    )
    api_session.add(rule)
    api_session.commit()
    return rule


@pytest.fixture
def test_detection(api_session: Session, test_host: Host, test_rule: DetectionRule) -> Detection:
    det = Detection(
        id=uuid.uuid4(),
        rule_id=test_rule.id,
        rule_version=1,
        host_id=test_host.id,
        timestamp=utcnow(),
        severity="high",
        title="Interactive Sudo Shell",
        description="User escalated via sudo -i",
        category="privilege_escalation",
        status="open",
        notification_status="pending",
        matched_conditions={"conditions": [{"field": "command", "actual": "sudo -i", "expected": "sudo -i", "passed": True}]},
        evidence={"user": "attacker", "command": "sudo -i"},
        dedup_hash="apihash123456",
        created_at=utcnow(),
    )
    api_session.add(det)
    api_session.commit()
    return det


class TestDetectionsApi:
    """Test suite for Detections API endpoints."""

    def test_unauthenticated_endpoints_return_401(self, client: TestClient) -> None:
        random_id = str(uuid.uuid4())
        assert client.get("/api/detections").status_code == 401
        assert client.get("/api/detections/rules").status_code == 401
        assert client.get(f"/api/detections/rules/{random_id}").status_code == 401
        assert client.get(f"/api/detections/{random_id}").status_code == 401
        assert client.post(f"/api/detections/{random_id}/acknowledge").status_code == 401

    def test_list_detections(
        self, client: TestClient, auth_headers: dict[str, str], test_detection: Detection, test_host: Host
    ) -> None:
        res = client.get("/api/detections", headers=auth_headers)
        assert res.status_code == 200
        data = res.json()
        assert data["total"] == 1
        assert len(data["items"]) == 1
        item = data["items"][0]
        assert item["id"] == str(test_detection.id)
        assert item["title"] == "Interactive Sudo Shell"
        assert item["severity"] == "high"
        assert item["status"] == "open"
        assert item["rule_code"] == "RULE-API-001"
        assert item["hostname"] == test_host.hostname

    def test_filter_detections(
        self, client: TestClient, auth_headers: dict[str, str], test_detection: Detection, test_host: Host
    ) -> None:
        # Match filter
        res1 = client.get(
            f"/api/detections?host_id={test_host.id}&severity=high&category=privilege_escalation&status=open",
            headers=auth_headers,
        )
        assert res1.status_code == 200
        assert res1.json()["total"] == 1

        # Non-matching filter
        res2 = client.get("/api/detections?severity=low", headers=auth_headers)
        assert res2.status_code == 200
        assert res2.json()["total"] == 0

    def test_timestamp_ordering_validation(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        t_start = "2026-10-30T15:00:00Z"
        t_end = "2026-10-30T14:00:00Z"
        res = client.get(f"/api/detections?start_time={t_start}&end_time={t_end}", headers=auth_headers)
        assert res.status_code == 400
        assert "start_time must be less than or equal to end_time" in res.json()["detail"]

    def test_pagination(
        self, client: TestClient, auth_headers: dict[str, str], test_detection: Detection
    ) -> None:
        res = client.get("/api/detections?limit=10&offset=0", headers=auth_headers)
        assert res.status_code == 200
        data = res.json()
        assert data["limit"] == 10
        assert data["offset"] == 0
        assert data["total"] == 1

    def test_get_single_detection(
        self, client: TestClient, auth_headers: dict[str, str], test_detection: Detection
    ) -> None:
        res = client.get(f"/api/detections/{test_detection.id}", headers=auth_headers)
        assert res.status_code == 200
        data = res.json()
        assert data["id"] == str(test_detection.id)
        assert data["title"] == test_detection.title
        assert "evidence" in data

    def test_get_nonexistent_detection_returns_404(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        random_id = str(uuid.uuid4())
        res = client.get(f"/api/detections/{random_id}", headers=auth_headers)
        assert res.status_code == 404

    def test_acknowledge_detection(
        self, client: TestClient, auth_headers: dict[str, str], test_detection: Detection, test_user: AppUser
    ) -> None:
        payload = {"notes": "Verified legitimate test"}
        res = client.post(
            f"/api/detections/{test_detection.id}/acknowledge",
            json=payload,
            headers=auth_headers,
        )
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "acknowledged"
        assert data["acknowledged_by_id"] == str(test_user.id)
        assert data["acknowledged_by_username"] == test_user.username
        assert data["acknowledged_at"] is not None

    def test_list_and_get_rules(
        self, client: TestClient, auth_headers: dict[str, str], test_rule: DetectionRule
    ) -> None:
        # List rules
        res = client.get("/api/detections/rules", headers=auth_headers)
        assert res.status_code == 200
        rules = res.json()
        assert len(rules) >= 1
        assert any(r["rule_id"] == "RULE-API-001" for r in rules)

        # Get rule by rule_id string
        res_by_code = client.get("/api/detections/rules/RULE-API-001", headers=auth_headers)
        assert res_by_code.status_code == 200
        assert res_by_code.json()["name"] == test_rule.name

        # Get rule by UUID
        res_by_uuid = client.get(f"/api/detections/rules/{test_rule.id}", headers=auth_headers)
        assert res_by_uuid.status_code == 200
        assert res_by_uuid.json()["rule_id"] == "RULE-API-001"

    def test_openapi_documentation_registered(self, client: TestClient) -> None:
        schema = app.openapi()
        assert "/api/detections" in schema["paths"]
        assert "/api/detections/rules" in schema["paths"]
        assert "/api/detections/{detection_id}" in schema["paths"]
        assert "/api/detections/{detection_id}/acknowledge" in schema["paths"]
