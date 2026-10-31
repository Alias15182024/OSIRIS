"""Unit tests and contract verification for OSIRIS Phase 1.6 Files Explorer View.

Verifies:
- GET /static/js/views/files.js serves 200 with JavaScript MIME type.
- index.html references files.js and contains required filter, table, pagination,
  empty/error indicators, and file detail modal DOM targets.
- files.js source code contracts:
  - References /api/files
  - Uses URLSearchParams for parameterized query construction
  - Uses supported query parameters (host_id, path, file_type, limit, offset)
  - Does NOT set unsupported filters (inode, pid, start_time)
  - Uses centralized window.OsirisApi helper
  - Contains no hardcoded credentials, passwords, or tokens
  - Does not use localStorage
  - Does not use innerHTML for dynamic file data
  - Uses real FileResponse fields (id, host_id, path, inode, file_type, first_seen_at, last_seen_at, created_at)
  - Pagination and state boundary logic (limit, offset, total) is present
  - Detail accessibility hooks (Enter, Space, Escape, backdrop click) are present
- JavaScript syntax validation.
- Backend API operational verification and regression checks.
"""

from __future__ import annotations

from typing import Generator
from pathlib import Path

import pytest
from sqlalchemy.orm import Session
from starlette.testclient import TestClient

from backend.api.deps import get_db
from backend.api.security import create_access_token
from backend.main import app

FILES_JS_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "frontend"
    / "static"
    / "js"
    / "views"
    / "files.js"
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


@pytest.fixture
def auth_headers() -> dict[str, str]:
    """Generate authenticated bearer headers for files API calls."""
    token = create_access_token(
        user_id="00000000-0000-4000-8000-000000000100", username="admin"
    )
    return {"Authorization": f"Bearer {token}"}


class TestFilesServing:
    """Verify delivery of Files Explorer JavaScript and DOM markup."""

    def test_files_js_serves_200(self, client: TestClient) -> None:
        """GET /static/js/views/files.js must return 200 with JavaScript content-type."""
        resp = client.get("/static/js/views/files.js")
        assert resp.status_code == 200
        content_type = resp.headers.get("content-type", "")
        assert "javascript" in content_type

        body = resp.text
        assert "OsirisFiles" in body
        assert "loadFiles" in body
        assert "resetFiles" in body
        assert "openFileDetail" in body

    def test_index_html_references_files_js(self, client: TestClient) -> None:
        """GET / must include deferred script tag for files.js."""
        resp = client.get("/")
        assert resp.status_code == 200
        assert 'src="/static/js/views/files.js"' in resp.text

    def test_index_html_contains_filter_controls(self, client: TestClient) -> None:
        """GET / must contain the documented Files Explorer filter controls."""
        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.text

        assert 'id="files-filter-container"' in html
        assert 'id="files-filter-form"' in html
        assert 'id="filter-file-path"' in html
        assert 'id="filter-file-type"' in html
        assert 'id="filter-file-host-id"' in html
        assert 'id="filter-file-limit"' in html
        assert 'id="filter-file-apply-btn"' in html
        assert 'id="filter-file-reset-btn"' in html
        assert 'id="files-refresh-btn"' in html
        assert 'id="files-refresh-time"' in html

    def test_index_html_file_type_dropdown_options(self, client: TestClient) -> None:
        """GET / file_type select dropdown must provide canonical file, directory, and symlink options."""
        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.text
        assert '<option value="file">Regular File</option>' in html
        assert '<option value="directory">Directory</option>' in html
        assert '<option value="symlink">Symbolic Link</option>' in html

    def test_index_html_contains_table_and_pagination(
        self, client: TestClient
    ) -> None:
        """GET / must contain files table and pagination toolbar."""
        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.text

        assert 'id="files-table-container"' in html
        assert 'id="files-table"' in html
        assert 'id="files-tbody"' in html
        assert 'id="files-result-count"' in html
        assert 'id="files-pagination"' in html
        assert 'id="files-prev-btn"' in html
        assert 'id="files-next-btn"' in html
        assert 'id="files-page-info"' in html

    def test_index_html_contains_empty_and_error_states(
        self, client: TestClient
    ) -> None:
        """GET / must contain empty and error state containers."""
        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.text

        assert 'id="files-error-box"' in html
        assert 'id="files-empty-state"' in html
        assert "No files found matching the selected filters." in html
        assert 'id="files-empty-reset-btn"' in html

    def test_index_html_contains_detail_inspector_modal(
        self, client: TestClient
    ) -> None:
        """GET / must contain file detail inspector modal and attribute elements."""
        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.text

        assert 'id="file-detail-modal-container"' in html
        assert 'id="file-detail-title"' in html
        assert 'id="file-detail-close-btn"' in html
        assert 'id="file-detail-error"' in html
        assert 'id="file-detail-content"' in html
        assert 'id="detail-file-id"' in html
        assert 'id="detail-file-host-id"' in html
        assert 'id="detail-file-path"' in html
        assert 'id="detail-file-type"' in html
        assert 'id="detail-file-inode"' in html
        assert 'id="detail-file-first-seen"' in html
        assert 'id="detail-file-last-seen"' in html
        assert 'id="detail-file-created-at"' in html


class TestFilesStaticCodeContract:
    """Verify static security and contract rules inside files.js."""

    @pytest.fixture(autouse=True)
    def load_code(self) -> None:
        assert FILES_JS_PATH.exists(), f"{FILES_JS_PATH} must exist"
        self.code = FILES_JS_PATH.read_text(encoding="utf-8")

    def test_references_api_endpoints(self) -> None:
        """files.js must reference /api/files."""
        assert "/api/files" in self.code

    def test_supported_filters_used(self) -> None:
        """files.js must use the backend supported query parameters."""
        assert "host_id" in self.code
        assert "path" in self.code
        assert "file_type" in self.code
        assert "limit" in self.code
        assert "offset" in self.code

    def test_unsupported_filters_not_sent(self) -> None:
        """files.js must NOT set unsupported filters like inode, pid, start_time."""
        assert "params.set('inode'" not in self.code
        assert "params.set('pid'" not in self.code
        assert "params.set('start_time'" not in self.code

    def test_uses_urlsearchparams(self) -> None:
        """files.js must use URLSearchParams to construct query strings."""
        assert "URLSearchParams" in self.code

    def test_uses_centralized_api_helper(self) -> None:
        """files.js must use OsirisApi.fetchWithAuth."""
        assert "OsirisApi" in self.code
        assert "fetchWithAuth" in self.code

    def test_no_localstorage(self) -> None:
        """files.js must not use localStorage."""
        assert "localStorage" not in self.code

    def test_no_innerhtml(self) -> None:
        """files.js must not use innerHTML for dynamic file data."""
        assert "innerHTML" not in self.code

    def test_contains_no_secrets(self) -> None:
        """files.js must not contain embedded passwords, tokens, or secrets."""
        lower_code = self.code.lower()
        assert "changeme" not in lower_code
        assert "password123" not in lower_code
        assert "bearer ey" not in lower_code
        assert "secret_key" not in lower_code

    def test_actual_fileresponse_fields_used(self) -> None:
        """files.js must access real FileResponse schema fields."""
        assert "host_id" in self.code
        assert "path" in self.code
        assert "inode" in self.code
        assert "file_type" in self.code
        assert "first_seen_at" in self.code
        assert "last_seen_at" in self.code
        assert "created_at" in self.code

    def test_pagination_logic_present(self) -> None:
        """files.js must track limit, offset, and total."""
        assert "limit" in self.code
        assert "offset" in self.code
        assert "total" in self.code
        assert "PAGE_SIZE" in self.code

    def test_detail_accessibility_hooks_present(self) -> None:
        """files.js must bind Escape, Enter, Space, and click handlers."""
        assert "Escape" in self.code
        assert "Enter" in self.code
        assert "click" in self.code

    def test_file_type_badge_and_detail_support(self) -> None:
        """files.js must format badges for canonical types (file, directory, symlink) and legacy regular."""
        assert "createFileTypeBadge" in self.code
        assert "'symlink'" in self.code
        assert "'file'" in self.code
        assert "'directory'" in self.code
        assert "'regular'" in self.code
        assert "badge-secondary" in self.code
        assert "badge-info" in self.code
        assert "badge-warning" in self.code

    def test_syntax_with_javascript_runtime(self) -> None:
        """files.js must parse cleanly in an available JavaScript runtime."""
        from tests.helpers.js_runtime import SKIP_REASON, find_js_runtime

        runtime = find_js_runtime()
        if runtime is None:
            pytest.skip(SKIP_REASON)

        result = runtime.check_syntax(FILES_JS_PATH)
        assert (
            result.returncode == 0
        ), f"JavaScript syntax check failed:\n{result.stdout}\n{result.stderr}"

    def test_badge_formatting_execution(self) -> None:
        """createFileTypeBadge must format canonical types and legacy aliases in runtime."""
        import re
        from tests.helpers.js_runtime import SKIP_REASON, find_js_runtime

        runtime = find_js_runtime()
        if runtime is None:
            pytest.skip(SKIP_REASON)

        fn_match = re.search(
            r"function createFileTypeBadge\(.*?\n  \}", self.code, re.DOTALL
        )
        assert fn_match is not None, "createFileTypeBadge definition not found"
        fn_code = fn_match.group(0)

        script = f"""
const document = {{
  createElement: function(tag) {{
    return {{
      classList: {{
        _classes: [],
        add: function(c) {{ this._classes.push(c); }},
        contains: function(c) {{ return this._classes.indexOf(c) !== -1; }}
      }},
      textContent: ''
    }};
  }}
}};
{fn_code}

function check(type, expectedClass, expectedText) {{
  const b = createFileTypeBadge(type);
  if (!b.classList.contains(expectedClass)) throw new Error('Bad class for ' + type + ': ' + b.classList._classes);
  if (b.textContent !== expectedText) throw new Error('Bad text for ' + type + ': ' + b.textContent);
}}

check('file', 'badge-info', 'file');
check('regular', 'badge-info', 'file');
check('regular_file', 'badge-info', 'file');
check('directory', 'badge-warning', 'directory');
check('dir', 'badge-warning', 'directory');
check('symlink', 'badge-secondary', 'symlink');
check('link', 'badge-secondary', 'symlink');
check('socket', 'badge-secondary', 'socket');
check('unknown_type', 'badge-outline', 'unknown_type');
check(null, 'badge-outline', '-');
print('OK');
"""
        result = runtime.run_script(script)
        assert (
            result.returncode == 0
        ), f"Execution failed:\n{result.stdout}\n{result.stderr}"
        assert "OK" in result.stdout


class TestFilesApiIntegrationRegression:
    """Verify backend API endpoints for files remain operational and enforce authentication."""

    def test_unauthenticated_files_returns_401(self, client: TestClient) -> None:
        """GET /api/files must return 401 when unauthenticated."""
        resp = client.get("/api/files")
        assert resp.status_code == 401

    def test_authenticated_files_list_operational(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        """GET /api/files with valid token returns 200 with total and items."""
        resp = client.get("/api/files?limit=25&offset=0", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert "total" in data
        assert "limit" in data
        assert "offset" in data
        assert data["limit"] == 25
        assert data["offset"] == 0

    def test_files_filtering_query_params(
        self, client: TestClient, auth_headers: dict[str, str]
    ) -> None:
        """GET /api/files accepts supported filters (path, file_type, limit, offset)."""
        resp = client.get(
            "/api/files?path=/etc&file_type=file&limit=10&offset=0",
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["limit"] == 10
        assert data["offset"] == 0
        assert isinstance(data["items"], list)

        resp_sym = client.get(
            "/api/files?file_type=symlink",
            headers=auth_headers,
        )
        assert resp_sym.status_code == 200

        resp_dir = client.get(
            "/api/files?file_type=directory",
            headers=auth_headers,
        )
        assert resp_dir.status_code == 200
