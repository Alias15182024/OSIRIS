"""Unit tests and contract verification for OSIRIS Detections View (Phase 2 Milestone 2.4)."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Generator
import pytest
from starlette.testclient import TestClient

from backend.main import app

DETECTIONS_JS_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "frontend"
    / "static"
    / "js"
    / "views"
    / "detections.js"
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


class TestDetectionsServing:
    """Verify delivery of Detections JavaScript and DOM markup."""

    def test_detections_js_serves_200(self, client: TestClient) -> None:
        resp = client.get("/static/js/views/detections.js")
        assert resp.status_code == 200
        content_type = resp.headers.get("content-type", "")
        assert "javascript" in content_type

    def test_index_html_contains_detections_markup(self) -> None:
        assert INDEX_HTML_PATH.exists()
        content = INDEX_HTML_PATH.read_text(encoding="utf-8")

        # Nav button & badge
        assert 'id="nav-detections"' in content
        assert 'data-view="detections"' in content
        assert 'id="nav-detections-badge"' in content

        # View panel
        assert 'id="view-detections"' in content
        assert 'id="detections-filter-form"' in content
        assert 'id="detections-table"' in content
        assert 'id="detections-tbody"' in content
        assert 'id="detections-prev-btn"' in content
        assert 'id="detections-next-btn"' in content
        assert 'id="detections-page-info"' in content

        # Summary stats
        assert 'id="detection-stat-critical"' in content
        assert 'id="detection-stat-high"' in content
        assert 'id="detection-stat-medium"' in content
        assert 'id="detection-stat-low"' in content

        # Detail modal
        assert 'id="detection-detail-modal"' in content
        assert 'id="detection-modal-close"' in content
        assert 'id="detail-detection-title"' in content
        assert 'id="detail-detection-rule-code"' in content
        assert 'id="detail-detection-severity"' in content
        assert 'id="detail-detection-conditions"' in content
        assert 'id="detail-detection-evidence"' in content
        assert 'id="detection-ack-btn"' in content

        # Script inclusion
        assert 'src="/static/js/views/detections.js"' in content


class TestDetectionsJsContract:
    """Verify security constraints and structural requirements of detections.js."""

    @pytest.fixture(autouse=True)
    def load_source(self) -> None:
        assert DETECTIONS_JS_PATH.exists()
        self.source = DETECTIONS_JS_PATH.read_text(encoding="utf-8")

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

    def test_uses_urlsearchparams(self) -> None:
        assert "URLSearchParams" in self.source

    def test_uses_centralized_api_helper(self) -> None:
        assert "OsirisApi" in self.source

    def test_exports_osiris_detections_controller(self) -> None:
        assert "OsirisDetections" in self.source
        assert "loadDetections" in self.source
        assert "openDetailModal" in self.source

    def test_jsc_syntax_validation(self) -> None:
        jsc_bin = "/System/Library/Frameworks/JavaScriptCore.framework/Versions/Current/Helpers/jsc"
        if not Path(jsc_bin).exists():
            pytest.skip("jsc binary not available on this platform")

        proc = subprocess.run(
            [jsc_bin, str(DETECTIONS_JS_PATH)],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, f"JSC syntax error: {proc.stderr}"
