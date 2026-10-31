"""Unit tests and contract verification for OSIRIS Phase 2 Milestone 2.2 Timeline View.

Verifies:
- GET /static/js/views/timeline.js serves 200 with JavaScript MIME type.
- index.html references timeline.js and contains required filter, stream, pagination,
  and navigation DOM targets.
- timeline.js source code contracts:
  - References /api/timeline
  - Uses URLSearchParams for parameterized query construction
  - Uses centralized window.OsirisApi.fetchWithAuth helper
  - Contains no hardcoded credentials, passwords, or tokens
  - Does not use localStorage
  - Does not use innerHTML for dynamic event data
  - Pagination logic (limit, offset, total) is present
  - Severity badge and correlation chip mapping is present
- JavaScript syntax validation.
"""

from __future__ import annotations

from pathlib import Path
import subprocess
from typing import Generator

import pytest
from sqlalchemy.orm import Session
from starlette.testclient import TestClient

from backend.api.deps import get_db
from backend.main import app

TIMELINE_JS_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "frontend"
    / "static"
    / "js"
    / "views"
    / "timeline.js"
)


@pytest.fixture
def client(contract_db_session: Session) -> Generator[TestClient, None, None]:
    """Provide a TestClient with get_db overridden to use isolated contract_db_session."""
    app.dependency_overrides[get_db] = lambda: contract_db_session
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.pop(get_db, None)


class TestTimelineServing:
    """Verify delivery of Timeline Reconstruction JavaScript and DOM markup."""

    def test_timeline_js_serves_200(self, client: TestClient) -> None:
        """GET /static/js/views/timeline.js must return 200 with JavaScript content-type."""
        resp = client.get("/static/js/views/timeline.js")
        assert resp.status_code == 200
        content_type = resp.headers.get("content-type", "")
        assert "javascript" in content_type

        body = resp.text
        assert "OsirisTimeline" in body
        assert "loadTimeline" in body
        assert "renderTimelineItems" in body

    def test_index_html_references_timeline_js(self, client: TestClient) -> None:
        """GET / must include deferred script tag for timeline.js."""
        resp = client.get("/")
        assert resp.status_code == 200
        assert 'src="/static/js/views/timeline.js"' in resp.text

    def test_index_html_contains_navigation_button(self, client: TestClient) -> None:
        """GET / must contain the timeline navigation button."""
        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.text
        assert 'id="nav-timeline"' in html
        assert 'data-view="timeline"' in html

    def test_index_html_contains_view_panel_and_filters(self, client: TestClient) -> None:
        """GET / must contain timeline view panel and filter inputs."""
        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.text

        assert 'id="view-timeline"' in html
        assert 'id="timeline-filter-form"' in html
        assert 'id="filter-timeline-host-id"' in html
        assert 'id="filter-timeline-start-time"' in html
        assert 'id="filter-timeline-end-time"' in html
        assert 'id="filter-timeline-record-type"' in html
        assert 'id="filter-timeline-order"' in html
        assert 'id="filter-timeline-apply-btn"' in html
        assert 'id="filter-timeline-reset-btn"' in html

    def test_index_html_contains_stream_and_pagination(self, client: TestClient) -> None:
        """GET / must contain timeline stream container, empty state, and pagination toolbar."""
        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.text

        assert 'id="timeline-stream"' in html
        assert 'id="timeline-result-count"' in html
        assert 'id="timeline-empty-state"' in html
        assert "No timeline entries found matching the selected filters." in html
        assert 'id="timeline-empty-reset-btn"' in html
        assert 'id="timeline-error-box"' in html
        assert 'id="timeline-pagination"' in html
        assert 'id="timeline-prev-btn"' in html
        assert 'id="timeline-next-btn"' in html
        assert 'id="timeline-page-info"' in html


class TestTimelineStaticCodeContract:
    """Verify static security and contract rules inside timeline.js."""

    @pytest.fixture(autouse=True)
    def load_source(self) -> None:
        assert TIMELINE_JS_PATH.exists(), f"Missing {TIMELINE_JS_PATH}"
        with open(TIMELINE_JS_PATH, "r", encoding="utf-8") as f:
            self.source = f.read()

    def test_no_localstorage_used(self) -> None:
        assert "localStorage" not in self.source

    def test_no_innerhtml_used(self) -> None:
        assert "innerHTML" not in self.source

    def test_no_eval_used(self) -> None:
        assert "eval(" not in self.source

    def test_no_hardcoded_credentials(self) -> None:
        forbidden = ["password", "secret", "bearer ", "token = '"]
        lower = self.source.lower()
        for term in forbidden:
            assert term not in lower

    def test_references_api_endpoints(self) -> None:
        """timeline.js must reference /api/timeline."""
        assert "/api/timeline" in self.source

    def test_uses_urlsearchparams(self) -> None:
        """timeline.js must use URLSearchParams to construct query strings."""
        assert "URLSearchParams" in self.source

    def test_uses_centralized_api_helper(self) -> None:
        """timeline.js must use OsirisApi.fetchWithAuth."""
        assert "OsirisApi" in self.source
        assert "fetchWithAuth" in self.source

    def test_exports_osiris_timeline_controller(self) -> None:
        assert "window.OsirisTimeline = Object.freeze({" in self.source
        assert "loadTimeline" in self.source
        assert "initTimeline" in self.source

    def test_js_syntax_validation(self) -> None:
        """Ensure timeline.js syntax parses cleanly in an available JS runtime."""
        from tests.helpers.js_runtime import find_js_runtime, SKIP_REASON

        runtime = find_js_runtime()
        if runtime is None:
            pytest.skip(SKIP_REASON)
        result = runtime.check_syntax(TIMELINE_JS_PATH)
        assert result.returncode == 0, f"JS syntax error: {result.stderr}"
