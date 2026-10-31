"""Unit tests and contract verification for OSIRIS Investigation Workspace View (Phase 2 Milestone 2.7)."""

from __future__ import annotations

from pathlib import Path
import subprocess
from typing import Generator
import pytest
from starlette.testclient import TestClient

from backend.main import app

WORKSPACE_JS_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "frontend"
    / "static"
    / "js"
    / "views"
    / "workspace.js"
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


class TestWorkspaceServing:
    """Verify static serving of workspace.js and DOM structure in index.html."""

    def test_workspace_js_serves_200(self, client: TestClient) -> None:
        resp = client.get("/static/js/views/workspace.js")
        assert resp.status_code == 200
        content_type = resp.headers.get("content-type", "")
        assert "javascript" in content_type

    def test_index_html_contains_workspace_markup(self) -> None:
        assert INDEX_HTML_PATH.exists()
        content = INDEX_HTML_PATH.read_text(encoding="utf-8")

        # Navigation button
        assert 'id="nav-workspace"' in content
        assert 'data-view="workspace"' in content

        # Main view panel & Header actions
        assert 'id="view-workspace"' in content
        assert 'id="workspace-select"' in content
        assert 'id="workspace-new-btn"' in content
        assert 'id="workspace-rename-btn"' in content
        assert 'id="workspace-save-btn"' in content
        assert 'id="workspace-archive-btn"' in content
        assert 'id="workspace-delete-btn"' in content
        assert 'id="workspace-host-badge"' in content
        assert 'id="workspace-status-badge"' in content
        assert 'id="workspace-alert-box"' in content

        # Sub-tabs
        assert 'id="ws-tab-overview"' in content
        assert 'id="ws-tab-unified"' in content
        assert 'id="ws-tab-graph"' in content
        assert 'id="ws-tab-search"' in content
        assert 'id="ws-tab-evidence"' in content

        # Sub-panels
        assert 'id="ws-panel-overview"' in content
        assert 'id="ws-panel-unified"' in content
        assert 'id="ws-panel-graph"' in content
        assert 'id="ws-panel-search"' in content
        assert 'id="ws-panel-evidence"' in content

        # Overview items
        assert 'id="ws-overview-name"' in content
        assert 'id="ws-overview-desc"' in content
        assert 'id="ws-overview-host"' in content
        assert 'id="ws-overview-status"' in content
        assert 'id="ws-overview-created"' in content
        assert 'id="ws-stat-nodes"' in content
        assert 'id="ws-stat-evidence"' in content
        assert 'id="ws-stat-notes"' in content
        assert 'id="ws-jump-graph-btn"' in content
        assert 'id="ws-jump-search-btn"' in content

        # Graph items
        assert 'id="workspace-graph-svg"' in content
        assert 'id="workspace-graph-container"' in content
        assert 'id="graph-zoom-in-btn"' in content
        assert 'id="graph-zoom-out-btn"' in content
        assert 'id="graph-reset-btn"' in content
        assert 'id="graph-depth-select"' in content
        assert 'id="graph-max-nodes-select"' in content
        assert 'id="graph-type-filter"' in content
        assert 'id="graph-search-input"' in content
        assert 'id="graph-search-btn"' in content
        assert 'id="graph-status-text"' in content

        # Graph drawer
        assert 'id="graph-drawer"' in content
        assert 'id="graph-drawer-close-btn"' in content
        assert 'id="graph-drawer-title"' in content
        assert 'id="graph-drawer-type-badge"' in content
        assert 'id="graph-drawer-severity-badge"' in content
        assert 'id="graph-drawer-properties"' in content
        assert 'id="graph-drawer-pivots"' in content
        assert 'id="graph-drawer-expand-btn"' in content
        assert 'id="graph-drawer-pin-btn"' in content
        assert 'id="graph-drawer-tag-btn"' in content
        assert 'id="graph-drawer-note-btn"' in content

        # Search items
        assert 'id="ws-search-form"' in content
        assert 'id="ws-search-query-input"' in content
        assert 'id="ws-search-cmd-input"' in content
        assert 'id="ws-search-path-input"' in content
        assert 'id="ws-search-severity-select"' in content
        assert 'id="ws-search-logic-select"' in content
        assert 'id="ws-search-tag-input"' in content
        assert 'id="ws-search-start-input"' in content
        assert 'id="ws-search-end-input"' in content
        assert 'id="ws-search-chk-events"' in content
        assert 'id="ws-search-chk-procs"' in content
        assert 'id="ws-search-chk-sessions"' in content
        assert 'id="ws-search-chk-detections"' in content
        assert 'id="ws-search-chk-fim"' in content
        assert 'id="ws-search-chk-files"' in content
        assert 'id="ws-search-chk-incidents"' in content
        assert 'id="ws-search-submit-btn"' in content
        assert 'id="ws-search-reset-btn"' in content
        assert 'id="ws-search-page-info"' in content
        assert 'id="ws-search-empty"' in content
        assert 'id="ws-search-table"' in content
        assert 'id="ws-search-tbody"' in content

        # Evidence & Tag items
        assert 'id="ws-pinned-evidence-list"' in content
        assert 'id="ws-tags-list"' in content
        assert 'id="ws-create-tag-name"' in content
        assert 'id="ws-create-tag-color"' in content
        assert 'id="ws-create-tag-category"' in content
        assert 'id="ws-create-tag-btn"' in content

        # Unified Investigation View items
        assert 'id="ws-unified-layout-select"' in content
        assert 'id="ws-unified-refresh-btn"' in content
        assert 'id="ws-unified-grid"' in content
        assert 'id="ws-subpanel-timeline"' in content
        assert 'id="ws-subpanel-processes"' in content
        assert 'id="ws-subpanel-sessions"' in content
        assert 'id="ws-subpanel-detections"' in content
        assert 'id="ws-subpanel-fim"' in content
        assert 'id="ws-subpanel-incidents"' in content

        # Modals
        assert 'id="modal-workspace-create"' in content
        assert 'id="modal-ws-title"' in content
        assert 'id="modal-ws-close-btn"' in content
        assert 'id="modal-ws-form"' in content
        assert 'id="modal-ws-name"' in content
        assert 'id="modal-ws-desc"' in content
        assert 'id="modal-ws-host"' in content
        assert 'id="modal-ws-incident"' in content
        assert 'id="modal-ws-shared"' in content
        assert 'id="modal-ws-submit-btn"' in content

        assert 'id="modal-workspace-rename"' in content
        assert 'id="modal-ws-rename-title"' in content
        assert 'id="modal-ws-rename-close-btn"' in content
        assert 'id="modal-ws-rename-form"' in content
        assert 'id="modal-ws-rename-name"' in content
        assert 'id="modal-ws-rename-submit-btn"' in content

        assert 'id="modal-workspace-tag"' in content
        assert 'id="modal-tag-title"' in content
        assert 'id="modal-tag-close-btn"' in content
        assert 'id="modal-tag-form"' in content
        assert 'id="modal-tag-evidence-info"' in content
        assert 'id="modal-tag-select"' in content
        assert 'id="modal-tag-submit-btn"' in content

        assert 'id="modal-workspace-note"' in content
        assert 'id="modal-note-title"' in content
        assert 'id="modal-note-close-btn"' in content
        assert 'id="modal-note-form"' in content
        assert 'id="modal-note-evidence-info"' in content
        assert 'id="modal-note-textarea"' in content
        assert 'id="modal-note-submit-btn"' in content

        # Script inclusion
        assert 'src="/static/js/views/workspace.js"' in content

    def test_unified_investigation_view_elements_and_layout(self) -> None:
        content = INDEX_HTML_PATH.read_text(encoding="utf-8")
        assert 'id="ws-unified-layout-select"' in content
        assert 'id="ws-unified-refresh-btn"' in content
        assert 'id="ws-subpanel-timeline"' in content
        assert 'id="ws-subpanel-processes"' in content
        assert 'id="ws-subpanel-sessions"' in content
        assert 'id="ws-subpanel-detections"' in content
        assert 'id="ws-subpanel-fim"' in content
        assert 'id="ws-subpanel-incidents"' in content
        css_content = (INDEX_HTML_PATH.parent.parent / "static" / "css" / "style.css").read_text(encoding="utf-8")
        assert "unified-panels-grid" in css_content
        assert "layout-stacked" in css_content
        assert "layout-single" in css_content



class TestWorkspaceJsContract:
    """Verify security constraints and structural requirements of workspace.js."""

    @pytest.fixture(autouse=True)
    def load_source(self) -> None:
        assert WORKSPACE_JS_PATH.exists()
        self.source = WORKSPACE_JS_PATH.read_text(encoding="utf-8")

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

    def test_exports_osiris_workspace_controller(self) -> None:
        assert "OsirisWorkspace" in self.source
        assert "loadWorkspaces" in self.source
        assert "selectWorkspace" in self.source
        assert "saveWorkspace" in self.source
        assert "loadGraph" in self.source
        assert "expandNode" in self.source
        assert "executeSearch" in self.source
        assert "openRenameWorkspaceModal" in self.source
        assert "closeRenameWorkspaceModal" in self.source

    def test_jsc_syntax_validation(self) -> None:
        jsc_bin = "/System/Library/Frameworks/JavaScriptCore.framework/Versions/Current/Helpers/jsc"
        if not Path(jsc_bin).exists():
            pytest.skip("jsc binary not available on this platform")

        proc = subprocess.run(
            [jsc_bin, str(WORKSPACE_JS_PATH)],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, f"JSC syntax error: {proc.stderr}"
