"""Unit tests for OSIRIS FIM REST API endpoints (Phase 2 Milestone 2.5)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Generator
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from starlette.testclient import TestClient

from backend.api.deps import get_db
from backend.api.security import create_access_token
from backend.db.base import Base, utcnow
from backend.db.models.app_user import AppUser
from backend.db.models.fim_baseline import FimBaseline
from backend.db.models.fim_baseline_file import FimBaselineFile
from backend.db.models.fim_deviation import FimDeviation
from backend.db.models.host import Host
from backend.main import app


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
        username="fim_auditor",
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
        hostname="fim-prod-host-01",
        created_at=utcnow(),
    )
    api_session.add(host)
    api_session.commit()
    return host


class TestFimApiEndpoints:
    """Test FIM baselines, deviations, and verification endpoints."""

    def test_auth_required_for_fim_routes(self, client: TestClient) -> None:
        resp = client.get("/api/fim/baselines")
        assert resp.status_code == 401

        resp = client.get("/api/fim/deviations")
        assert resp.status_code == 401

        resp = client.post("/api/fim/baselines", json={"host_id": str(uuid.uuid4()), "paths": ["/etc"]})
        assert resp.status_code == 401

        resp = client.post("/api/fim/verify", json={"host_id": str(uuid.uuid4())})
        assert resp.status_code == 401

    def test_list_baselines_empty(self, client: TestClient, auth_headers: dict[str, str]) -> None:
        resp = client.get("/api/fim/baselines", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["items"] == []

    def test_create_and_get_baseline(
        self, client: TestClient, auth_headers: dict[str, str], test_host: Host, tmp_path: Path
    ) -> None:
        scan_dir = tmp_path / "baseline_scan"
        scan_dir.mkdir()
        (scan_dir / "sample.conf").write_text("setting=1", encoding="utf-8")

        payload = {
            "host_id": str(test_host.id),
            "paths": [str(scan_dir)],
            "exclude_patterns": [".git"],
        }

        # 1. Create baseline
        create_resp = client.post("/api/fim/baselines", json=payload, headers=auth_headers)
        assert create_resp.status_code == 201
        base_data = create_resp.json()
        assert base_data["host_id"] == str(test_host.id)
        assert base_data["version"] == 1
        assert base_data["status"] == "completed"
        assert base_data["total_files"] >= 1
        baseline_id = base_data["id"]

        # 2. Get baseline detail
        detail_resp = client.get(f"/api/fim/baselines/{baseline_id}", headers=auth_headers)
        assert detail_resp.status_code == 200
        detail_data = detail_resp.json()
        assert detail_data["id"] == baseline_id
        assert detail_data["baseline_metadata"] is not None

        # 3. Get baseline files
        files_resp = client.get(f"/api/fim/baselines/{baseline_id}/files", headers=auth_headers)
        assert files_resp.status_code == 200
        files_data = files_resp.json()
        assert files_data["total"] >= 1
        assert any("sample.conf" in f["file_path"] for f in files_data["items"])

    def test_create_baseline_nonexistent_host_returns_404(
        self, client: TestClient, auth_headers: dict[str, str], tmp_path: Path
    ) -> None:
        payload = {
            "host_id": str(uuid.uuid4()),
            "paths": [str(tmp_path)],
        }
        resp = client.post("/api/fim/baselines", json=payload, headers=auth_headers)
        assert resp.status_code == 404

    def test_get_baseline_invalid_uuid_returns_422(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        resp = client.get("/api/fim/baselines/not-a-valid-uuid", headers=auth_headers)
        assert resp.status_code == 422

    def test_get_baseline_nonexistent_returns_404(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        resp = client.get(f"/api/fim/baselines/{uuid.uuid4()}", headers=auth_headers)
        assert resp.status_code == 404

    def test_list_deviations_and_filter(
        self, client: TestClient, auth_headers: dict[str, str], api_session: Session, test_host: Host
    ) -> None:
        now = utcnow()
        baseline = FimBaseline(
            host_id=test_host.id,
            version=1,
            status="completed",
            path_scope=["/etc"],
            total_files=10,
            total_bytes=5000,
            baseline_at=now,
            created_at=now,
        )
        api_session.add(baseline)
        api_session.flush()

        dev1 = FimDeviation(
            host_id=test_host.id,
            baseline_id=baseline.id,
            file_path="/etc/pam.d/common-auth",
            deviation_type="modified_file",
            severity="critical",
            is_content_modified=True,
            detected_at=now,
            created_at=now,
        )
        dev2 = FimDeviation(
            host_id=test_host.id,
            baseline_id=baseline.id,
            file_path="/etc/motd",
            deviation_type="metadata_changed",
            severity="low",
            is_content_modified=False,
            detected_at=now,
            created_at=now,
        )
        api_session.add_all([dev1, dev2])
        api_session.commit()

        # List all
        resp = client.get("/api/fim/deviations", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["total"] == 2

        # Filter by severity
        resp_crit = client.get("/api/fim/deviations?severity=critical", headers=auth_headers)
        assert resp_crit.status_code == 200
        crit_items = resp_crit.json()["items"]
        assert len(crit_items) == 1
        assert crit_items[0]["file_path"] == "/etc/pam.d/common-auth"

        # Filter by deviation_type
        resp_meta = client.get("/api/fim/deviations?deviation_type=metadata_changed", headers=auth_headers)
        assert resp_meta.status_code == 200
        assert len(resp_meta.json()["items"]) == 1

        # Single deviation detail
        resp_single = client.get(f"/api/fim/deviations/{dev1.id}", headers=auth_headers)
        assert resp_single.status_code == 200
        assert resp_single.json()["id"] == str(dev1.id)

    def test_verify_integrity_endpoint(
        self, client: TestClient, auth_headers: dict[str, str], test_host: Host, tmp_path: Path
    ) -> None:
        scan_dir = tmp_path / "verify_dir"
        scan_dir.mkdir()
        target = scan_dir / "target.txt"
        target.write_text("initial content", encoding="utf-8")

        # Create baseline first
        create_resp = client.post(
            "/api/fim/baselines",
            json={"host_id": str(test_host.id), "paths": [str(scan_dir)]},
            headers=auth_headers,
        )
        assert create_resp.status_code == 201

        # Modify file
        target.write_text("modified content", encoding="utf-8")

        # Execute verify endpoint
        verify_resp = client.post(
            "/api/fim/verify",
            json={"host_id": str(test_host.id)},
            headers=auth_headers,
        )
        assert verify_resp.status_code == 200
        data = verify_resp.json()
        assert data["host_id"] == str(test_host.id)
        assert data["deviations_count"] >= 1
        assert any("target.txt" in d["file_path"] for d in data["deviations"])

    def test_create_baseline_rejects_relative_or_invalid_paths(
        self, client: TestClient, auth_headers: dict[str, str], test_host: Host
    ) -> None:
        # Relative path
        resp = client.post(
            "/api/fim/baselines",
            json={"host_id": str(test_host.id), "paths": ["relative/path"]},
            headers=auth_headers,
        )
        assert resp.status_code == 422

        # Empty string path
        resp = client.post(
            "/api/fim/baselines",
            json={"host_id": str(test_host.id), "paths": ["   "]},
            headers=auth_headers,
        )
        assert resp.status_code == 422

        # Null byte in path
        resp = client.post(
            "/api/fim/baselines",
            json={"host_id": str(test_host.id), "paths": ["/etc/pass\x00wd"]},
            headers=auth_headers,
        )
        assert resp.status_code == 422

    def test_verify_integrity_rejects_out_of_scope_paths(
        self, client: TestClient, auth_headers: dict[str, str], test_host: Host, tmp_path: Path
    ) -> None:
        scope_a = tmp_path / "scope_a"
        scope_a.mkdir()
        (scope_a / "f1.txt").write_text("a", encoding="utf-8")

        scope_b = tmp_path / "scope_b"
        scope_b.mkdir()
        (scope_b / "f2.txt").write_text("b", encoding="utf-8")

        # Create baseline for scope_a only
        create_resp = client.post(
            "/api/fim/baselines",
            json={"host_id": str(test_host.id), "paths": [str(scope_a)]},
            headers=auth_headers,
        )
        assert create_resp.status_code == 201

        # Attempt verification on scope_b
        verify_resp = client.post(
            "/api/fim/verify",
            json={"host_id": str(test_host.id), "paths": [str(scope_b)]},
            headers=auth_headers,
        )
        assert verify_resp.status_code == 400
        assert "outside baseline path scope" in verify_resp.json()["detail"]

    def test_openapi_route_registration(self, client: TestClient) -> None:
        resp = client.get("/openapi.json")
        assert resp.status_code == 200
        spec = resp.json()
        paths = spec.get("paths", {})
        assert "/api/fim/baselines" in paths
        assert "/api/fim/baselines/{baseline_id}" in paths
        assert "/api/fim/baselines/{baseline_id}/files" in paths
        assert "/api/fim/deviations" in paths
        assert "/api/fim/deviations/{deviation_id}" in paths
        assert "/api/fim/verify" in paths
