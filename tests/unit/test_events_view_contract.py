"""Unit tests and contract verification for OSIRIS Phase 1.6 Event Explorer View.

Verifies:
- GET /static/js/views/events.js serves 200 with JavaScript MIME type.
- index.html references events.js and contains required filter, table, pagination,
  and detail modal DOM targets.
- events.js source code contracts:
  - References /api/events and /api/events/{event_id}
  - Uses URLSearchParams for parameterized query construction
  - Uses centralized window.OsirisApi helper
  - Contains no hardcoded credentials, passwords, or tokens
  - Does not use localStorage
  - Does not use innerHTML for dynamic event data
  - Pagination logic (limit, offset, total) is present
  - Severity badge mapping is present
  - JSON detail rendering via JSON.stringify is present
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

EVENTS_JS_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "frontend"
    / "static"
    / "js"
    / "views"
    / "events.js"
)


@pytest.fixture
def client() -> TestClient:
    """Provide a TestClient for testing static routes and API integrity."""
    return TestClient(app)


@pytest.fixture
def auth_headers() -> dict[str, str]:
    """Generate authenticated bearer headers for events API calls."""
    token = create_access_token(
        user_id="00000000-0000-4000-8000-000000000100", username="admin"
    )
    return {"Authorization": f"Bearer {token}"}


class TestEventsServing:
    """Verify delivery of Event Explorer JavaScript and DOM markup."""

    def test_events_js_serves_200(self, client: TestClient) -> None:
        """GET /static/js/views/events.js must return 200 with JavaScript content-type."""
        resp = client.get("/static/js/views/events.js")
        assert resp.status_code == 200
        content_type = resp.headers.get("content-type", "")
        assert "javascript" in content_type

        body = resp.text
        assert "OsirisEvents" in body
        assert "loadEvents" in body
        assert "openEventDetail" in body

    def test_index_html_references_events_js(self, client: TestClient) -> None:
        """GET / must include deferred script tag for events.js."""
        resp = client.get("/")
        assert resp.status_code == 200
        assert 'src="/static/js/views/events.js"' in resp.text

    def test_index_html_contains_filter_controls(self, client: TestClient) -> None:
        """GET / must contain the documented Event Explorer filter controls."""
        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.text

        assert 'id="events-filter-container"' in html
        assert 'id="events-filter-form"' in html
        assert 'id="filter-event-host-id"' in html
        assert 'id="filter-event-start-time"' in html
        assert 'id="filter-event-end-time"' in html
        assert 'id="filter-event-source"' in html
        assert 'id="filter-event-event-type"' in html
        assert 'id="filter-event-severity"' in html
        assert 'id="filter-event-process-id"' in html
        assert 'id="filter-event-pid"' in html
        assert 'id="filter-event-apply-btn"' in html
        assert 'id="filter-event-reset-btn"' in html

    def test_index_html_contains_table_and_pagination(
        self, client: TestClient
    ) -> None:
        """GET / must contain event table, empty state, and pagination toolbar."""
        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.text

        assert 'id="events-table-container"' in html
        assert 'id="events-table"' in html
        assert 'id="events-tbody"' in html
        assert 'id="events-result-count"' in html
        assert 'id="events-empty-state"' in html
        assert "No events found matching the selected filters." in html
        assert 'id="events-empty-reset-btn"' in html
        assert 'id="events-error-box"' in html
        assert 'id="events-pagination"' in html
        assert 'id="events-prev-btn"' in html
        assert 'id="events-next-btn"' in html
        assert 'id="events-page-info"' in html

    def test_index_html_contains_detail_inspector_modal(
        self, client: TestClient
    ) -> None:
        """GET / must contain event detail inspector modal and attribute elements."""
        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.text

        assert 'id="event-detail-modal-container"' in html
        assert 'id="event-detail-title"' in html
        assert 'id="event-detail-close-btn"' in html
        assert 'id="event-detail-error"' in html
        assert 'id="event-detail-content"' in html
        assert 'id="detail-event-id"' in html
        assert 'id="detail-timestamp"' in html
        assert 'id="detail-source"' in html
        assert 'id="detail-event-type"' in html
        assert 'id="detail-action"' in html
        assert 'id="detail-severity"' in html
        assert 'id="detail-uid"' in html
        assert 'id="detail-username"' in html
        assert 'id="detail-pid"' in html
        assert 'id="detail-ppid"' in html
        assert 'id="detail-command"' in html
        assert 'id="detail-object-type"' in html
        assert 'id="detail-object-path"' in html
        assert 'id="detail-success"' in html
        assert 'id="detail-result"' in html
        assert 'id="detail-payload"' in html


class TestEventsStaticCodeContract:
    """Verify static security and contract rules inside events.js."""

    @pytest.fixture(autouse=True)
    def load_code(self) -> None:
        assert EVENTS_JS_PATH.exists(), f"{EVENTS_JS_PATH} must exist"
        self.code = EVENTS_JS_PATH.read_text(encoding="utf-8")

    def test_references_api_endpoints(self) -> None:
        """events.js must reference /api/events and single-event /api/events/."""
        assert "/api/events" in self.code
        assert "/api/events/" in self.code

    def test_uses_urlsearchparams(self) -> None:
        """events.js must use URLSearchParams to construct query strings."""
        assert "URLSearchParams" in self.code

    def test_uses_centralized_api_helper(self) -> None:
        """events.js must use OsirisApi.fetchWithAuth."""
        assert "OsirisApi" in self.code
        assert "fetchWithAuth" in self.code

    def test_no_localstorage(self) -> None:
        """events.js must not use localStorage."""
        assert "localStorage" not in self.code

    def test_no_innerhtml(self) -> None:
        """events.js must not use innerHTML for dynamic event data."""
        assert "innerHTML" not in self.code

    def test_contains_no_secrets(self) -> None:
        """events.js must not contain embedded passwords, tokens, or secrets."""
        lower_code = self.code.lower()
        assert "changeme" not in lower_code
        assert "password123" not in lower_code
        assert "bearer ey" not in lower_code
        assert "secret_key" not in lower_code

    def test_pagination_logic_present(self) -> None:
        """events.js must track limit, offset, and total."""
        assert "limit" in self.code
        assert "offset" in self.code
        assert "total" in self.code
        assert "PAGE_SIZE" in self.code

    def test_severity_handling_present(self) -> None:
        """events.js must map severity badges."""
        assert "badge-info" in self.code
        assert "badge-warning" in self.code
        assert "badge-danger" in self.code

    def test_json_detail_rendering_present(self) -> None:
        """events.js must use JSON.stringify for safe payload rendering."""
        assert "JSON.stringify" in self.code

    def test_syntax_with_javascriptcore(self) -> None:
        """events.js must parse cleanly in macOS JavaScriptCore runtime."""
        jsc_bin = (
            "/System/Library/Frameworks/JavaScriptCore.framework/Versions/A/Helpers/jsc"
        )
        if not Path(jsc_bin).exists():
            pytest.skip("JavaScriptCore CLI not available on this system")

        result = subprocess.run(
            [jsc_bin, "-e", f"checkSyntax('{EVENTS_JS_PATH}')"],
            capture_output=True,
            text=True,
        )
        assert (
            result.returncode == 0
        ), f"jsc syntax check failed:\n{result.stdout}\n{result.stderr}"


class TestEventsApiIntegrationRegression:
    """Verify backend API endpoints for events remain operational and enforce authentication."""

    def test_unauthenticated_events_returns_401(self, client: TestClient) -> None:
        """GET /api/events must return 401 when unauthenticated."""
        resp = client.get("/api/events")
        assert resp.status_code == 401

    def test_authenticated_events_list_operational(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        """GET /api/events with valid token returns 200 with total and items."""
        resp = client.get("/api/events?limit=25&offset=0", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert "total" in data
        assert "limit" in data
        assert "offset" in data
        assert data["limit"] == 25
        assert data["offset"] == 0

    def test_unauthenticated_single_event_returns_401(
        self, client: TestClient
    ) -> None:
        """GET /api/events/{event_id} must return 401 when unauthenticated."""
        dummy_id = uuid.uuid4()
        resp = client.get(f"/api/events/{dummy_id}")
        assert resp.status_code == 401

    def test_authenticated_single_event_not_found(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        """GET /api/events/{nonexistent_id} returns 404."""
        random_id = uuid.uuid4()
        resp = client.get(f"/api/events/{random_id}", headers=auth_headers)
        assert resp.status_code == 404
        assert resp.json() == {"detail": "Event not found"}

    def test_events_filtering_query_params(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        """GET /api/events accepts documented query filters without error."""
        resp = client.get(
            "/api/events?severity=info&source=auditd&limit=10&offset=0",
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["limit"] == 10
        assert data["offset"] == 0
        assert isinstance(data["items"], list)
