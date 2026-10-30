"""Unit tests and contract verification for OSIRIS File Integrity Monitoring (FIM) View (Phase 2 Milestone 2.5)."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Generator
import pytest
from starlette.testclient import TestClient

from backend.main import app

FIM_JS_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "frontend"
    / "static"
    / "js"
    / "views"
    / "fim.js"
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


class TestFimServing:
    """Verify delivery of FIM JavaScript and DOM markup."""

    def test_fim_js_serves_200(self, client: TestClient) -> None:
        resp = client.get("/static/js/views/fim.js")
        assert resp.status_code == 200
        content_type = resp.headers.get("content-type", "")
        assert "javascript" in content_type

    def test_index_html_contains_fim_markup(self) -> None:
        assert INDEX_HTML_PATH.exists()
        content = INDEX_HTML_PATH.read_text(encoding="utf-8")

        # Nav button & badge
        assert 'id="nav-fim"' in content
        assert 'data-view="fim"' in content
        assert 'id="nav-fim-badge"' in content

        # View panel & header
        assert 'id="view-fim"' in content
        assert 'id="heading-fim"' in content
        assert 'id="fim-verify-trigger-btn"' in content
        assert 'id="fim-refresh-btn"' in content
        assert 'id="fim-refresh-time"' in content

        # Stat cards
        assert 'id="fim-stat-baselines"' in content
        assert 'id="fim-stat-deviations"' in content
        assert 'id="fim-stat-critical"' in content
        assert 'id="fim-stat-files"' in content

        # Sub-nav tabs & panels
        assert 'id="fim-tab-deviations"' in content
        assert 'id="fim-tab-baselines"' in content
        assert 'id="fim-panel-deviations"' in content
        assert 'id="fim-panel-baselines"' in content

        # Deviations filter & table
        assert 'id="fim-deviations-filter-form"' in content
        assert 'id="filter-fim-host-id"' in content
        assert 'id="filter-fim-baseline-id"' in content
        assert 'id="filter-fim-file-path"' in content
        assert 'id="filter-fim-deviation-type"' in content
        assert 'id="filter-fim-severity"' in content
        assert 'id="fim-deviations-apply-btn"' in content
        assert 'id="fim-deviations-reset-btn"' in content
        assert 'id="fim-deviations-table"' in content
        assert 'id="fim-deviations-tbody"' in content
        assert 'id="fim-deviations-prev-btn"' in content
        assert 'id="fim-deviations-next-btn"' in content
        assert 'id="fim-deviations-page-info"' in content

        # Baselines filter & table
        assert 'id="fim-baselines-filter-form"' in content
        assert 'id="filter-fim-baseline-host-id"' in content
        assert 'id="filter-fim-baseline-status"' in content
        assert 'id="fim-baselines-apply-btn"' in content
        assert 'id="fim-baselines-reset-btn"' in content
        assert 'id="fim-baselines-table"' in content
        assert 'id="fim-baselines-tbody"' in content
        assert 'id="fim-baselines-prev-btn"' in content
        assert 'id="fim-baselines-next-btn"' in content
        assert 'id="fim-baselines-page-info"' in content

        # Modals
        assert 'id="fim-deviation-detail-modal"' in content
        assert 'id="fim-deviation-modal-close"' in content
        assert 'id="detail-fim-deviation-path"' in content
        assert 'id="detail-fim-deviation-type"' in content
        assert 'id="detail-fim-deviation-severity"' in content
        assert 'id="detail-fim-deviation-explanation"' in content
        assert 'id="detail-fim-deviation-diff"' in content

        assert 'id="fim-baseline-detail-modal"' in content
        assert 'id="fim-baseline-modal-close"' in content
        assert 'id="detail-fim-baseline-id"' in content
        assert 'id="detail-fim-baseline-scope"' in content
        assert 'id="detail-fim-baseline-files-tbody"' in content

        assert 'id="fim-verify-modal"' in content
        assert 'id="fim-verify-modal-close"' in content
        assert 'id="verify-fim-host-id"' in content
        assert 'id="verify-fim-submit-btn"' in content
        assert 'id="verify-fim-result"' in content

        # Script inclusion
        assert 'src="/static/js/views/fim.js"' in content


class TestFimJsContract:
    """Verify security constraints and structural requirements of fim.js."""

    @pytest.fixture(autouse=True)
    def load_source(self) -> None:
        assert FIM_JS_PATH.exists()
        self.source = FIM_JS_PATH.read_text(encoding="utf-8")

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

    def test_exports_osiris_fim_controller(self) -> None:
        assert "OsirisFim" in self.source
        assert "loadFim" in self.source
        assert "loadDeviations" in self.source
        assert "loadBaselines" in self.source
        assert "openDeviationModal" in self.source
        assert "openBaselineModal" in self.source

    def test_jsc_syntax_validation(self) -> None:
        jsc_bin = "/System/Library/Frameworks/JavaScriptCore.framework/Versions/Current/Helpers/jsc"
        if not Path(jsc_bin).exists():
            pytest.skip("jsc binary not available on this platform")

        proc = subprocess.run(
            [jsc_bin, str(FIM_JS_PATH)],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, f"JSC syntax error: {proc.stderr}"
