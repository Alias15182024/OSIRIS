"""Unit tests for OSIRIS Phase 1.5 status routes (/health, /api/status).

Tests:
- GET /health returns basic liveness response.
- GET /api/status returns StatusResponse when database is connected.
- GET /api/status safely handles database connectivity failures (returning degraded status
  without leaking connection strings or stack traces).
- OpenAPI documentation (/openapi.json) registers newly added endpoints.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from starlette.testclient import TestClient

from backend.api.deps import get_db
from backend.config import settings
from backend.db.base import Base
from backend.main import app


@pytest.fixture
def status_db_session() -> Session:
    """Provide a thread-safe in-memory SQLite session for status testing."""
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
def client(status_db_session: Session) -> TestClient:
    """TestClient with get_db dependency overridden to use status_db_session."""
    app.dependency_overrides[get_db] = lambda: status_db_session
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


class TestStatusEndpoints:
    """Tests for system status and health endpoints."""

    def test_health_liveness_check(self, client: TestClient) -> None:
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data == {"status": "ok", "system": "osiris"}

    def test_api_status_healthy_when_database_connected(
        self,
        client: TestClient,
    ) -> None:
        resp = client.get("/api/status")
        assert resp.status_code == 200
        data = resp.json()

        assert data["status"] == "healthy"
        assert data["system"] == "osiris"
        assert data["database"] == "connected"
        assert data["host_id"] == settings.host_id

    def test_api_status_degraded_when_database_fails(self) -> None:
        # Create a mock session that fails query execution
        mock_session = MagicMock(spec=Session)
        mock_session.execute.side_effect = OperationalError(
            "connection failed", params={}, orig=Exception("DB down")
        )

        app.dependency_overrides[get_db] = lambda: mock_session
        try:
            with TestClient(app) as mock_client:
                resp = mock_client.get("/api/status")

            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "degraded"
            assert data["system"] == "osiris"
            assert data["database"] == "disconnected"
            assert data["host_id"] == settings.host_id

            # Ensure sensitive database details are not leaked in the response
            resp_str = resp.text.lower()
            assert "postgresql://" not in resp_str
            assert "password" not in resp_str
            assert "sqlite" not in resp_str
            assert "traceback" not in resp_str
        finally:
            app.dependency_overrides.clear()

    def test_openapi_schema_includes_all_endpoints(
        self,
        client: TestClient,
    ) -> None:
        resp = client.get("/openapi.json")
        assert resp.status_code == 200
        paths = resp.json()["paths"]

        assert "/health" in paths
        assert "/api/status" in paths
        assert "/api/auth/login" in paths
        assert "/api/auth/me" in paths
