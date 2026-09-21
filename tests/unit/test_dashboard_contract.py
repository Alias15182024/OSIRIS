"""Unit tests and contract verification for OSIRIS Phase 1.6 Dashboard Overview View.

Verifies:
- GET /static/js/views/dashboard.js serves 200 with JavaScript MIME type.
- index.html references dashboard.js and contains required dashboard DOM targets.
- dashboard.js source code contracts:
  - References /api/status, /api/resources?limit=1, /api/events?limit=5
  - References inventory queries: /api/events?limit=1, /api/processes?is_active=true&limit=1, /api/files?limit=1
  - Uses centralized window.OsirisApi helper
  - Contains no hardcoded credentials or tokens
  - Does not use localStorage
  - Does not use innerHTML for API-derived values
- JavaScriptCore syntax validation.
- Operational status of all dashboard API endpoints.
"""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess

import pytest
from starlette.testclient import TestClient

from backend.api.security import create_access_token
from backend.main import app

DASHBOARD_JS_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "frontend"
    / "static"
    / "js"
    / "views"
    / "dashboard.js"
)


@pytest.fixture
def client() -> TestClient:
    """Provide a TestClient for testing static routes and API integrity."""
    return TestClient(app)


@pytest.fixture
def auth_headers() -> dict[str, str]:
    """Generate authenticated bearer headers for dashboard API calls."""
    # Using seeded admin user UUID from Phase 1.2 / 1.5
    token = create_access_token(
        user_id="00000000-0000-4000-8000-000000000100", username="admin"
    )
    return {"Authorization": f"Bearer {token}"}


class TestDashboardServing:
    """Verify delivery of dashboard JavaScript and DOM structure."""

    def test_dashboard_js_serves_200(self, client: TestClient) -> None:
        """GET /static/js/views/dashboard.js must return 200 with JavaScript content-type."""
        resp = client.get("/static/js/views/dashboard.js")
        assert resp.status_code == 200
        content_type = resp.headers.get("content-type", "")
        assert "javascript" in content_type

        body = resp.text
        assert "OsirisDashboard" in body
        assert "loadDashboard" in body
        assert "resetDashboard" in body

    def test_index_html_references_dashboard_js(self, client: TestClient) -> None:
        """GET / must include deferred script tag for dashboard.js."""
        resp = client.get("/")
        assert resp.status_code == 200
        assert 'src="/static/js/views/dashboard.js"' in resp.text

    def test_index_html_contains_dashboard_dom_elements(
        self, client: TestClient
    ) -> None:
        """GET / must contain semantic DOM containers for all dashboard cards."""
        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.text

        # Dashboard View Panel and Actions
        assert 'id="view-dashboard"' in html
        assert 'id="dashboard-refresh-btn"' in html
        assert 'id="dashboard-refresh-time"' in html

        # Platform Status Card
        assert 'id="dashboard-system-card"' in html
        assert 'id="system-status-badge"' in html
        assert 'id="status-host-id"' in html
        assert 'id="status-system"' in html
        assert 'id="status-database"' in html
        assert 'id="system-db-badge"' in html
        assert 'id="status-operational"' in html
        assert 'id="status-card-error"' in html

        # Resource Utilization Card
        assert 'id="dashboard-resource-card"' in html
        assert 'id="resource-snapshot-time"' in html
        assert 'id="res-cpu-percent"' in html
        assert 'id="res-memory-percent"' in html
        assert 'id="res-memory-used"' in html
        assert 'id="res-memory-total"' in html
        assert 'id="res-disk-usage"' in html
        assert 'id="resource-card-error"' in html

        # Observational Inventory Card
        assert 'id="dashboard-metrics-card"' in html
        assert 'id="inv-events-count"' in html
        assert 'id="inv-processes-count"' in html
        assert 'id="inv-files-count"' in html

        # Recent Events Card
        assert 'id="dashboard-recent-events-card"' in html
        assert 'id="recent-events-count-badge"' in html
        assert 'id="dashboard-recent-events-table"' in html
        assert 'id="dashboard-recent-events-tbody"' in html
        assert 'id="dashboard-recent-events-empty"' in html
        assert 'id="dashboard-recent-events-error"' in html


class TestDashboardSourceSecurity:
    """Verify static code rules and security boundaries in dashboard.js."""

    @pytest.fixture(autouse=True)
    def load_code(self) -> None:
        assert DASHBOARD_JS_PATH.exists(), f"{DASHBOARD_JS_PATH} must exist"
        self.code = DASHBOARD_JS_PATH.read_text(encoding="utf-8")

    def test_references_required_endpoints(self) -> None:
        """dashboard.js must reference all required Phase 1.5 endpoints."""
        assert "/api/status" in self.code
        assert "/api/resources?limit=1" in self.code
        assert "/api/events?limit=5" in self.code
        assert "/api/events?limit=1" in self.code
        assert "/api/processes?is_active=true&limit=1" in self.code
        assert "/api/files?limit=1" in self.code

    def test_uses_centralized_api_helper(self) -> None:
        """dashboard.js must use OsirisApi helper methods."""
        assert "OsirisApi" in self.code
        assert "fetchWithAuth" in self.code
        assert "getStatus" in self.code

    def test_contains_no_secrets(self) -> None:
        """dashboard.js must not contain embedded passwords, tokens, or private credentials."""
        lower_code = self.code.lower()
        assert "changeme" not in lower_code
        assert "password123" not in lower_code
        assert "bearer ey" not in lower_code
        assert "secret_key" not in lower_code

    def test_does_not_use_localstorage(self) -> None:
        """dashboard.js must not use localStorage for persistence."""
        assert "localStorage" not in self.code

    def test_does_not_use_innerhtml(self) -> None:
        """dashboard.js must not use innerHTML to avoid XSS vulnerabilities."""
        assert "innerHTML" not in self.code

    def test_syntax_with_javascriptcore(self) -> None:
        """dashboard.js must parse cleanly in macOS JavaScriptCore runtime."""
        jsc_bin = (
            "/System/Library/Frameworks/JavaScriptCore.framework/Versions/A/Helpers/jsc"
        )
        if not Path(jsc_bin).exists():
            pytest.skip("JavaScriptCore CLI not available on this system")

        result = subprocess.run(
            [jsc_bin, "-e", f"checkSyntax('{DASHBOARD_JS_PATH}')"],
            capture_output=True,
            text=True,
        )
        assert (
            result.returncode == 0
        ), f"jsc syntax check failed:\n{result.stdout}\n{result.stderr}"


class TestDashboardApiEndpointsOperational:
    """Verify backend endpoints consumed by Dashboard remain operational."""

    def test_status_endpoint_operational(self, client: TestClient) -> None:
        """GET /api/status returns 200 with status schema."""
        resp = client.get("/api/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "status" in data
        assert "system" in data
        assert "database" in data
        assert "host_id" in data

    def test_unauthenticated_endpoints_return_401(
        self, client: TestClient
    ) -> None:
        """Protected dashboard endpoints return 401 when unauthenticated."""
        for path in [
            "/api/resources?limit=1",
            "/api/events?limit=5",
            "/api/events?limit=1",
            "/api/processes?is_active=true&limit=1",
            "/api/files?limit=1",
        ]:
            resp = client.get(path)
            assert resp.status_code == 401

    def test_authenticated_endpoints_operational(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        """Protected dashboard endpoints return 200 with expected paginated structure when authenticated."""
        # Resources limit=1
        r_res = client.get("/api/resources?limit=1", headers=auth_headers)
        assert r_res.status_code == 200
        data_res = r_res.json()
        assert "items" in data_res
        assert "total" in data_res

        # Events limit=5
        r_ev5 = client.get("/api/events?limit=5", headers=auth_headers)
        assert r_ev5.status_code == 200
        data_ev5 = r_ev5.json()
        assert "items" in data_ev5
        assert "total" in data_ev5

        # Events limit=1
        r_ev1 = client.get("/api/events?limit=1", headers=auth_headers)
        assert r_ev1.status_code == 200
        assert "total" in r_ev1.json()

        # Processes active limit=1
        r_proc = client.get(
            "/api/processes?is_active=true&limit=1", headers=auth_headers
        )
        assert r_proc.status_code == 200
        assert "total" in r_proc.json()

        # Files limit=1
        r_files = client.get("/api/files?limit=1", headers=auth_headers)
        assert r_files.status_code == 200
        assert "total" in r_files.json()
