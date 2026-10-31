"""Unit tests and contract verification for OSIRIS Incident Management View (Phase 2 Milestone 2.6)."""

from __future__ import annotations

from pathlib import Path
from typing import Generator
import pytest
from starlette.testclient import TestClient

from backend.main import app

INCIDENTS_JS_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "frontend"
    / "static"
    / "js"
    / "views"
    / "incidents.js"
)

INDEX_HTML_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "frontend"
    / "templates"
    / "index.html"
)


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    with TestClient(app) as test_client:
        yield test_client


class TestIncidentsServing:
    """Verify static serving of incidents.js and DOM structure in index.html."""

    def test_incidents_js_serves_200(self, client: TestClient) -> None:
        resp = client.get("/static/js/views/incidents.js")
        assert resp.status_code == 200
        content_type = resp.headers.get("content-type", "")
        assert "javascript" in content_type

    def test_index_html_contains_incidents_markup(self) -> None:
        assert INDEX_HTML_PATH.exists()
        content = INDEX_HTML_PATH.read_text(encoding="utf-8")

        # Navigation button
        assert 'id="nav-incidents"' in content
        assert 'data-view="incidents"' in content

        # Main view panel & Header actions
        assert 'id="view-incidents"' in content
        assert 'id="incidents-refresh-btn"' in content
        assert 'id="incident-create-trigger-btn"' in content

        # Stat cards
        assert 'id="incident-stat-open"' in content
        assert 'id="incident-stat-investigating"' in content
        assert 'id="incident-stat-contained"' in content
        assert 'id="incident-stat-resolved"' in content
        assert 'id="incident-stat-closed"' in content

        # Filter controls
        assert 'id="incidents-filter-form"' in content
        assert 'id="filter-incident-status"' in content
        assert 'id="filter-incident-severity"' in content
        assert 'id="filter-incident-category"' in content
        assert 'id="filter-incident-host-id"' in content
        assert 'id="incidents-filter-apply-btn"' in content
        assert 'id="incidents-filter-reset-btn"' in content

        # Table & Pagination
        assert 'id="incidents-tbody"' in content
        assert 'id="incidents-prev-btn"' in content
        assert 'id="incidents-next-btn"' in content
        assert 'id="incidents-page-info"' in content

        # Detail Modal
        assert 'id="incident-detail-modal"' in content
        assert 'id="incident-modal-close"' in content
        assert 'id="detail-incident-title"' in content
        assert 'id="detail-incident-severity"' in content
        assert 'id="detail-incident-status"' in content
        assert 'id="incident-export-md-btn"' in content
        assert 'id="incident-export-json-btn"' in content
        assert 'id="incident-new-status"' in content
        assert 'id="incident-transition-submit-btn"' in content
        assert 'id="incident-add-note-btn"' in content
        assert 'id="incident-detail-evidence-list"' in content
        assert 'id="incident-detail-timeline-list"' in content

        # Create Modal
        assert 'id="incident-create-modal"' in content
        assert 'id="incident-create-modal-close"' in content
        assert 'id="incident-create-form"' in content
        assert 'id="create-incident-title"' in content
        assert 'id="create-incident-severity"' in content
        assert 'id="create-incident-category"' in content
        assert 'id="create-incident-host-id"' in content
        assert 'id="incident-create-submit-btn"' in content

        # Script inclusion
        assert 'src="/static/js/views/incidents.js"' in content


class TestIncidentsJsContract:
    """Verify security constraints and structural requirements of incidents.js."""

    @pytest.fixture(autouse=True)
    def load_source(self) -> None:
        assert INCIDENTS_JS_PATH.exists()
        self.source = INCIDENTS_JS_PATH.read_text(encoding="utf-8")

    def test_no_localstorage_used(self) -> None:
        assert "localStorage" not in self.source

    def test_no_innerhtml_used(self) -> None:
        assert "innerHTML" not in self.source

    def test_no_eval_used(self) -> None:
        assert "eval(" not in self.source
        assert "Function(" not in self.source

    def test_no_hardcoded_credentials(self) -> None:
        forbidden = ["password =", "secret =", "bearer ", "token = '"]
        lower = self.source.lower()
        for term in forbidden:
            assert term not in lower

    def test_uses_centralized_api_helper(self) -> None:
        assert "OsirisApi" in self.source

    def test_exports_osiris_incidents_controller(self) -> None:
        assert "OsirisIncidents" in self.source
        assert "loadIncidents" in self.source
        assert "openDetailModal" in self.source
        assert "openCreateModal" in self.source

    def test_js_syntax_validation(self) -> None:
        """incidents.js must parse without syntax errors on any available runtime."""
        from tests.helpers.js_runtime import SKIP_REASON, find_js_runtime

        runtime = find_js_runtime()
        if runtime is None:
            pytest.skip(SKIP_REASON)
        result = runtime.check_syntax(INCIDENTS_JS_PATH)
        assert result.returncode == 0, f"JS syntax error: {result.stderr}"
