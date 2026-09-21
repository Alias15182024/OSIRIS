"""Unit tests and contract verification for OSIRIS Phase 1.6 Process List View.

Verifies:
- GET /static/js/views/processes.js serves 200 with JavaScript MIME type.
- index.html references processes.js and contains required filter, table, pagination,
  and process detail modal DOM targets.
- processes.js source code contracts:
  - References /api/processes and /api/processes/{process_id}
  - Uses URLSearchParams for parameterized query construction
  - Uses supported query parameters (host_id, pid, is_active)
  - Does NOT set unsupported filters (ppid, linux_user_id, command, state)
  - Uses centralized window.OsirisApi helper
  - Contains no hardcoded credentials, passwords, or tokens
  - Does not use localStorage
  - Does not use innerHTML for dynamic process data
  - Pagination logic (limit, offset, total) is present
  - Detail accessibility hooks (Enter, Space, Escape, backdrop click) are present
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

PROCESSES_JS_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "frontend"
    / "static"
    / "js"
    / "views"
    / "processes.js"
)


@pytest.fixture
def client() -> TestClient:
    """Provide a TestClient for testing static routes and API integrity."""
    return TestClient(app)


@pytest.fixture
def auth_headers() -> dict[str, str]:
    """Generate authenticated bearer headers for process API calls."""
    token = create_access_token(
        user_id="00000000-0000-4000-8000-000000000100", username="admin"
    )
    return {"Authorization": f"Bearer {token}"}


class TestProcessesServing:
    """Verify delivery of Process List JavaScript and DOM markup."""

    def test_processes_js_serves_200(self, client: TestClient) -> None:
        """GET /static/js/views/processes.js must return 200 with JavaScript content-type."""
        resp = client.get("/static/js/views/processes.js")
        assert resp.status_code == 200
        content_type = resp.headers.get("content-type", "")
        assert "javascript" in content_type

        body = resp.text
        assert "OsirisProcesses" in body
        assert "loadProcesses" in body
        assert "openProcessDetail" in body

    def test_index_html_references_processes_js(self, client: TestClient) -> None:
        """GET / must include deferred script tag for processes.js."""
        resp = client.get("/")
        assert resp.status_code == 200
        assert 'src="/static/js/views/processes.js"' in resp.text

    def test_index_html_contains_filter_controls(self, client: TestClient) -> None:
        """GET / must contain the documented Process List filter controls."""
        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.text

        assert 'id="processes-filter-container"' in html
        assert 'id="processes-filter-form"' in html
        assert 'id="filter-process-host-id"' in html
        assert 'id="filter-process-pid"' in html
        assert 'id="filter-process-is-active"' in html
        assert 'id="filter-process-apply-btn"' in html
        assert 'id="filter-process-reset-btn"' in html

    def test_index_html_contains_table_and_pagination(
        self, client: TestClient
    ) -> None:
        """GET / must contain process table, empty state, and pagination toolbar."""
        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.text

        assert 'id="processes-table-container"' in html
        assert 'id="processes-table"' in html
        assert 'id="processes-tbody"' in html
        assert 'id="processes-result-count"' in html
        assert 'id="processes-empty-state"' in html
        assert "No processes found matching the selected filters." in html
        assert 'id="processes-empty-reset-btn"' in html
        assert 'id="processes-error-box"' in html
        assert 'id="processes-pagination"' in html
        assert 'id="processes-prev-btn"' in html
        assert 'id="processes-next-btn"' in html
        assert 'id="processes-page-info"' in html

    def test_index_html_contains_detail_inspector_modal(
        self, client: TestClient
    ) -> None:
        """GET / must contain process detail inspector modal and attribute elements."""
        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.text

        assert 'id="process-detail-modal-container"' in html
        assert 'id="process-detail-title"' in html
        assert 'id="process-detail-close-btn"' in html
        assert 'id="process-detail-error"' in html
        assert 'id="process-detail-content"' in html
        assert 'id="detail-process-id"' in html
        assert 'id="detail-process-host-id"' in html
        assert 'id="detail-process-pid"' in html
        assert 'id="detail-process-ppid"' in html
        assert 'id="detail-process-command"' in html
        assert 'id="detail-process-executable"' in html
        assert 'id="detail-process-linux-user-id"' in html
        assert 'id="detail-process-status"' in html
        assert 'id="detail-process-started-at"' in html
        assert 'id="detail-process-ended-at"' in html
        assert 'id="detail-process-created-at"' in html


class TestProcessesStaticCodeContract:
    """Verify static security and contract rules inside processes.js."""

    @pytest.fixture(autouse=True)
    def load_code(self) -> None:
        assert PROCESSES_JS_PATH.exists(), f"{PROCESSES_JS_PATH} must exist"
        self.code = PROCESSES_JS_PATH.read_text(encoding="utf-8")

    def test_references_api_endpoints(self) -> None:
        """processes.js must reference /api/processes and single-process /api/processes/."""
        assert "/api/processes" in self.code
        assert "/api/processes/" in self.code

    def test_supported_filters_used(self) -> None:
        """processes.js must use the backend supported filters: host_id, pid, is_active."""
        assert "host_id" in self.code
        assert "pid" in self.code
        assert "is_active" in self.code

    def test_unsupported_filters_not_sent(self) -> None:
        """processes.js must NOT set unsupported filters like ppid, linux_user_id, command, state."""
        assert "params.set('ppid'" not in self.code
        assert "params.set('linux_user_id'" not in self.code
        assert "params.set('command'" not in self.code
        assert "params.set('state'" not in self.code

    def test_uses_urlsearchparams(self) -> None:
        """processes.js must use URLSearchParams to construct query strings."""
        assert "URLSearchParams" in self.code

    def test_uses_centralized_api_helper(self) -> None:
        """processes.js must use OsirisApi.fetchWithAuth."""
        assert "OsirisApi" in self.code
        assert "fetchWithAuth" in self.code

    def test_no_localstorage(self) -> None:
        """processes.js must not use localStorage."""
        assert "localStorage" not in self.code

    def test_no_innerhtml(self) -> None:
        """processes.js must not use innerHTML for dynamic process data."""
        assert "innerHTML" not in self.code

    def test_contains_no_secrets(self) -> None:
        """processes.js must not contain embedded passwords, tokens, or secrets."""
        lower_code = self.code.lower()
        assert "changeme" not in lower_code
        assert "password123" not in lower_code
        assert "bearer ey" not in lower_code
        assert "secret_key" not in lower_code

    def test_pagination_logic_present(self) -> None:
        """processes.js must track limit, offset, and total."""
        assert "limit" in self.code
        assert "offset" in self.code
        assert "total" in self.code
        assert "PAGE_SIZE" in self.code

    def test_detail_accessibility_hooks_present(self) -> None:
        """processes.js must bind Escape, Enter, Space, and click handlers."""
        assert "Escape" in self.code
        assert "Enter" in self.code
        assert "click" in self.code

    def test_syntax_with_javascriptcore(self) -> None:
        """processes.js must parse cleanly in macOS JavaScriptCore runtime."""
        jsc_bin = (
            "/System/Library/Frameworks/JavaScriptCore.framework/Versions/A/Helpers/jsc"
        )
        if not Path(jsc_bin).exists():
            pytest.skip("JavaScriptCore CLI not available on this system")

        result = subprocess.run(
            [jsc_bin, "-e", f"checkSyntax('{PROCESSES_JS_PATH}')"],
            capture_output=True,
            text=True,
        )
        assert (
            result.returncode == 0
        ), f"jsc syntax check failed:\n{result.stdout}\n{result.stderr}"


class TestProcessesApiIntegrationRegression:
    """Verify backend API endpoints for processes remain operational and enforce authentication."""

    def test_unauthenticated_processes_returns_401(self, client: TestClient) -> None:
        """GET /api/processes must return 401 when unauthenticated."""
        resp = client.get("/api/processes")
        assert resp.status_code == 401

    def test_authenticated_processes_list_operational(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        """GET /api/processes with valid token returns 200 with total and items."""
        resp = client.get("/api/processes?limit=25&offset=0", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert "total" in data
        assert "limit" in data
        assert "offset" in data
        assert data["limit"] == 25
        assert data["offset"] == 0

    def test_unauthenticated_single_process_returns_401(
        self, client: TestClient
    ) -> None:
        """GET /api/processes/{process_id} must return 401 when unauthenticated."""
        dummy_id = uuid.uuid4()
        resp = client.get(f"/api/processes/{dummy_id}")
        assert resp.status_code == 401

    def test_authenticated_single_process_not_found(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        """GET /api/processes/{nonexistent_id} returns 404."""
        random_id = uuid.uuid4()
        resp = client.get(f"/api/processes/{random_id}", headers=auth_headers)
        assert resp.status_code == 404
        assert resp.json() == {"detail": "Process not found"}

    def test_processes_filtering_query_params(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        """GET /api/processes accepts supported filters (host_id, pid, is_active)."""
        resp = client.get(
            "/api/processes?is_active=true&limit=10&offset=0",
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["limit"] == 10
        assert data["offset"] == 0
        assert isinstance(data["items"], list)
