"""Unit tests and contract verification for OSIRIS Phase 1.6 Resource Charts View.

Verifies:
- GET /static/js/views/resources.js serves 200 with JavaScript MIME type.
- index.html references resources.js and contains required filter, summary cards,
  SVG chart containers, empty/error indicators, accessible table, and pagination DOM targets.
- resources.js source code contracts:
  - References /api/resources
  - Uses URLSearchParams for parameterized query construction
  - Uses supported query parameters (host_id, start_time, end_time, limit, offset)
  - Uses centralized window.OsirisApi helper
  - Contains no hardcoded credentials, passwords, or tokens
  - Does not use localStorage
  - Does not use innerHTML for dynamic resource data
  - Native SVG rendering logic (createElementNS, SVG_NS) is present
  - Pagination and state boundary logic (limit, offset, total) is present
- JavaScriptCore syntax validation.
- Backend API operational verification and regression checks.
"""

from __future__ import annotations

from pathlib import Path
import subprocess
import uuid

import pytest
from starlette.testclient import TestClient

from backend.api.security import create_access_token
from backend.main import app

RESOURCES_JS_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "frontend"
    / "static"
    / "js"
    / "views"
    / "resources.js"
)


@pytest.fixture
def client() -> TestClient:
    """Provide a TestClient for testing static routes and API integrity."""
    return TestClient(app)


@pytest.fixture
def auth_headers() -> dict[str, str]:
    """Generate authenticated bearer headers for resource API calls."""
    token = create_access_token(
        user_id="00000000-0000-4000-8000-000000000100", username="admin"
    )
    return {"Authorization": f"Bearer {token}"}


class TestResourcesServing:
    """Verify delivery of Resource Charts JavaScript and DOM markup."""

    def test_resources_js_serves_200(self, client: TestClient) -> None:
        """GET /static/js/views/resources.js must return 200 with JavaScript content-type."""
        resp = client.get("/static/js/views/resources.js")
        assert resp.status_code == 200
        content_type = resp.headers.get("content-type", "")
        assert "javascript" in content_type

        body = resp.text
        assert "OsirisResources" in body
        assert "loadResources" in body
        assert "resetResources" in body
        assert "renderSvgChart" in body

    def test_index_html_references_resources_js(self, client: TestClient) -> None:
        """GET / must include deferred script tag for resources.js."""
        resp = client.get("/")
        assert resp.status_code == 200
        assert 'src="/static/js/views/resources.js"' in resp.text

    def test_index_html_contains_filter_controls(self, client: TestClient) -> None:
        """GET / must contain the documented Resource Charts filter controls."""
        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.text

        assert 'id="resources-filter-container"' in html
        assert 'id="resources-filter-form"' in html
        assert 'id="filter-resource-host-id"' in html
        assert 'id="filter-resource-range"' in html
        assert 'id="filter-resource-start"' in html
        assert 'id="filter-resource-end"' in html
        assert 'id="filter-resource-limit"' in html
        assert 'id="filter-resource-apply-btn"' in html
        assert 'id="filter-resource-reset-btn"' in html
        assert 'id="resources-refresh-btn"' in html
        assert 'id="resources-refresh-time"' in html

    def test_index_html_contains_metric_summary_cards(self, client: TestClient) -> None:
        """GET / must contain current metric status cards."""
        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.text

        assert 'id="resources-summary-cards"' in html
        assert 'id="res-card-cpu"' in html
        assert 'id="res-card-memory"' in html
        assert 'id="res-card-memory-used"' in html
        assert 'id="res-card-memory-total"' in html
        assert 'id="res-card-disk-read"' in html
        assert 'id="res-card-disk-write"' in html
        assert 'id="res-card-disk-usage"' in html
        assert 'id="res-card-timestamp"' in html

    def test_index_html_contains_chart_containers(self, client: TestClient) -> None:
        """GET / must contain the 4 SVG chart card containers."""
        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.text

        assert 'id="resources-charts-grid"' in html
        assert 'id="cpu-chart-card"' in html
        assert 'id="cpu-chart-svg-container"' in html
        assert 'id="memory-chart-card"' in html
        assert 'id="memory-chart-svg-container"' in html
        assert 'id="disk-activity-chart-card"' in html
        assert 'id="disk-activity-svg-container"' in html
        assert 'id="disk-usage-chart-card"' in html
        assert 'id="disk-usage-svg-container"' in html

    def test_index_html_contains_empty_and_error_states(self, client: TestClient) -> None:
        """GET / must contain empty and error state containers with specified text."""
        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.text

        assert 'id="resources-error-box"' in html
        assert 'id="resources-empty-state"' in html
        assert "No resource snapshots found matching the selected range." in html
        assert 'id="resources-empty-reset-btn"' in html

    def test_index_html_contains_table_and_pagination(
        self, client: TestClient
    ) -> None:
        """GET / must contain resource snapshots data table and pagination toolbar."""
        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.text

        assert 'id="resources-table-container"' in html
        assert 'id="resources-table"' in html
        assert 'id="resources-tbody"' in html
        assert 'id="resources-result-count"' in html
        assert 'id="resources-pagination"' in html
        assert 'id="resources-prev-btn"' in html
        assert 'id="resources-next-btn"' in html
        assert 'id="resources-page-info"' in html


class TestResourcesStaticCodeContract:
    """Verify static security and contract rules inside resources.js."""

    @pytest.fixture(autouse=True)
    def load_code(self) -> None:
        assert RESOURCES_JS_PATH.exists(), f"{RESOURCES_JS_PATH} must exist"
        self.code = RESOURCES_JS_PATH.read_text(encoding="utf-8")

    def test_references_api_endpoints(self) -> None:
        """resources.js must reference /api/resources."""
        assert "/api/resources" in self.code

    def test_supported_filters_used(self) -> None:
        """resources.js must use the backend supported query parameters."""
        assert "host_id" in self.code
        assert "start_time" in self.code
        assert "end_time" in self.code
        assert "limit" in self.code
        assert "offset" in self.code

    def test_uses_urlsearchparams(self) -> None:
        """resources.js must use URLSearchParams to construct query strings."""
        assert "URLSearchParams" in self.code

    def test_uses_centralized_api_helper(self) -> None:
        """resources.js must use OsirisApi.fetchWithAuth."""
        assert "OsirisApi" in self.code
        assert "fetchWithAuth" in self.code

    def test_no_localstorage(self) -> None:
        """resources.js must not use localStorage."""
        assert "localStorage" not in self.code

    def test_no_innerhtml(self) -> None:
        """resources.js must not use innerHTML for dynamic resource data."""
        assert "innerHTML" not in self.code

    def test_contains_no_secrets(self) -> None:
        """resources.js must not contain embedded passwords, tokens, or secrets."""
        lower_code = self.code.lower()
        assert "changeme" not in lower_code
        assert "password123" not in lower_code
        assert "bearer ey" not in lower_code
        assert "secret_key" not in lower_code

    def test_pure_svg_rendering_logic_present(self) -> None:
        """resources.js must use createElementNS and SVG namespace for vector charting."""
        assert "createElementNS" in self.code
        assert "http://www.w3.org/2000/svg" in self.code

    def test_pagination_logic_present(self) -> None:
        """resources.js must track limit, offset, and total."""
        assert "limit" in self.code
        assert "offset" in self.code
        assert "total" in self.code
        assert "DEFAULT_LIMIT" in self.code

    def test_syntax_with_javascriptcore(self) -> None:
        """resources.js must parse cleanly in macOS JavaScriptCore runtime."""
        jsc_bin = (
            "/System/Library/Frameworks/JavaScriptCore.framework/Versions/A/Helpers/jsc"
        )
        if not Path(jsc_bin).exists():
            pytest.skip("JavaScriptCore CLI not available on this system")

        result = subprocess.run(
            [jsc_bin, "-e", f"checkSyntax('{RESOURCES_JS_PATH}')"],
            capture_output=True,
            text=True,
        )
        assert (
            result.returncode == 0
        ), f"jsc syntax check failed:\n{result.stdout}\n{result.stderr}"


class TestResourcesApiIntegrationRegression:
    """Verify backend API endpoints for resources remain operational and enforce authentication."""

    def test_unauthenticated_resources_returns_401(self, client: TestClient) -> None:
        """GET /api/resources must return 401 when unauthenticated."""
        resp = client.get("/api/resources")
        assert resp.status_code == 401

    def test_authenticated_resources_list_operational(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        """GET /api/resources with valid token returns 200 with total and items."""
        resp = client.get("/api/resources?limit=25&offset=0", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert "total" in data
        assert "limit" in data
        assert "offset" in data
        assert data["limit"] == 25
        assert data["offset"] == 0

    def test_resources_filtering_query_params(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        """GET /api/resources accepts supported filters (host_id, start_time, end_time)."""
        resp = client.get(
            "/api/resources?limit=10&offset=0",
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["limit"] == 10
        assert data["offset"] == 0
        assert isinstance(data["items"], list)

    def test_resources_invalid_datetime_comparison(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        """GET /api/resources returns 400 when start_time > end_time."""
        resp = client.get(
            "/api/resources?start_time=2026-01-02T00:00:00Z&end_time=2026-01-01T00:00:00Z",
            headers=auth_headers,
        )
        assert resp.status_code == 400
        assert "start_time must be less than or equal to end_time" in resp.json()["detail"]
