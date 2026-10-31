"""Unit tests and contract verification for OSIRIS Sessions View (Phase 2 Milestone 2.3)."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Generator
import pytest
from starlette.testclient import TestClient

from backend.main import app

SESSIONS_JS_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "frontend"
    / "static"
    / "js"
    / "views"
    / "sessions.js"
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


class TestSessionsServing:
    """Verify delivery of Sessions JavaScript and DOM markup."""

    def test_sessions_js_serves_200(self, client: TestClient) -> None:
        resp = client.get("/static/js/views/sessions.js")
        assert resp.status_code == 200
        content_type = resp.headers.get("content-type", "")
        assert "javascript" in content_type

    def test_index_html_contains_sessions_markup(self) -> None:
        assert INDEX_HTML_PATH.exists()
        content = INDEX_HTML_PATH.read_text(encoding="utf-8")

        # Nav button
        assert 'id="nav-sessions"' in content
        assert 'data-view="sessions"' in content

        # View panel
        assert 'id="view-sessions"' in content
        assert 'id="sessions-filter-form"' in content
        assert 'id="sessions-table"' in content
        assert 'id="sessions-tbody"' in content
        assert 'id="sessions-pagination"' in content

        # Detail modal
        assert 'id="session-detail-modal-container"' in content
        assert 'id="session-detail-close-btn"' in content
        assert 'id="detail-session-processes-tbody"' in content

        # Script inclusion
        assert 'src="/static/js/views/sessions.js"' in content


class TestSessionsJsContract:
    """Verify security constraints and structural requirements of sessions.js."""

    @pytest.fixture(autouse=True)
    def load_source(self) -> None:
        assert SESSIONS_JS_PATH.exists()
        self.source = SESSIONS_JS_PATH.read_text(encoding="utf-8")

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

    def test_uses_urlsearchparams(self) -> None:
        assert "URLSearchParams" in self.source

    def test_uses_centralized_api_helper(self) -> None:
        assert "OsirisApi" in self.source

    def test_exports_osiris_sessions_controller(self) -> None:
        assert "OsirisSessions" in self.source
        assert "loadSessions" in self.source
        assert "openSessionModal" in self.source

    def test_js_syntax_validation(self) -> None:
        """sessions.js must parse without syntax errors on any available runtime."""
        from tests.helpers.js_runtime import find_js_runtime, SKIP_REASON

        runtime = find_js_runtime()
        if runtime is None:
            pytest.skip(SKIP_REASON)
        result = runtime.check_syntax(SESSIONS_JS_PATH)
        assert result.returncode == 0, f"JS syntax error: {result.stderr}"
