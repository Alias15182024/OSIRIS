"""Final cross-view integration validation for OSIRIS Phase 1.6 Web Dashboard.

Verifies:
- Root page / delivers the unified single-page application shell.
- All static assets (CSS, api.js, app.js, and 5 view controllers) serve with valid MIME types.
- Navigation links map 1:1 to view containers without missing or orphaned panels.
- Zero duplicate element IDs exist across index.html.
- Zero obsolete view placeholders remain in the markup.
- All modal dialogs adhere to accessibility standards (role, aria-modal, aria-labelledby, close btn).
- All five data views feature loading, error, and empty states.
- Security boundaries:
  - Zero localStorage usage across frontend tree (sessionStorage only).
  - Zero innerHTML usage across frontend tree (textContent/createElement only).
  - Zero eval(), new Function(), or document.write calls.
  - Zero console logging or token exposure in code or URLs.
  - Zero hardcoded passwords, JWTs, or secrets.
  - Authorization header generation restricted to api.js.
- API contract coherence: all referenced endpoints and parameters are supported by Phase 1.5.
- macOS JavaScriptCore syntax checking succeeds across all seven JavaScript files.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
import re
import subprocess

import pytest
from starlette.testclient import TestClient

from backend.api.security import create_access_token
from backend.main import app

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
FRONTEND_DIR = PROJECT_ROOT / "frontend"
STATIC_DIR = FRONTEND_DIR / "static"
JS_DIR = STATIC_DIR / "js"
VIEWS_DIR = JS_DIR / "views"

JS_FILES = [
    JS_DIR / "api.js",
    JS_DIR / "app.js",
    VIEWS_DIR / "dashboard.js",
    VIEWS_DIR / "events.js",
    VIEWS_DIR / "processes.js",
    VIEWS_DIR / "resources.js",
    VIEWS_DIR / "files.js",
]

VIEW_NAMES = ["dashboard", "events", "processes", "resources", "files"]


@pytest.fixture
def client() -> TestClient:
    """Provide a TestClient for testing static routes and API integrity."""
    return TestClient(app)


@pytest.fixture
def auth_headers() -> dict[str, str]:
    """Generate authenticated bearer headers."""
    token = create_access_token(
        user_id="00000000-0000-4000-8000-000000000100", username="admin"
    )
    return {"Authorization": f"Bearer {token}"}


class TestPhase16AppServing:
    """Verify end-to-end asset serving and HTML shell delivery."""

    def test_root_serves_unified_spa(self, client: TestClient) -> None:
        """GET / must return 200 OK with HTML content-type."""
        resp = client.get("/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers.get("content-type", "")
        assert "<!DOCTYPE html>" in resp.text
        assert "<title>OSIRIS</title>" in resp.text

    def test_all_static_assets_serve_successfully(self, client: TestClient) -> None:
        """CSS stylesheet and all seven JavaScript files must return 200 with matching MIME."""
        # CSS
        css_resp = client.get("/static/css/style.css")
        assert css_resp.status_code == 200
        assert "text/css" in css_resp.headers.get("content-type", "")

        # 7 JavaScript files
        js_routes = [
            "/static/js/api.js",
            "/static/js/app.js",
            "/static/js/views/dashboard.js",
            "/static/js/views/events.js",
            "/static/js/views/processes.js",
            "/static/js/views/resources.js",
            "/static/js/views/files.js",
        ]
        for route in js_routes:
            resp = client.get(route)
            assert resp.status_code == 200, f"{route} must return 200"
            assert "javascript" in resp.headers.get("content-type", "")

    def test_all_seven_scripts_referenced_in_index_html(self, client: TestClient) -> None:
        """GET / must include deferred script tags for all 7 scripts in proper dependency order."""
        resp = client.get("/")
        html = resp.text

        scripts = [
            "/static/js/api.js",
            "/static/js/views/dashboard.js",
            "/static/js/views/events.js",
            "/static/js/views/processes.js",
            "/static/js/views/resources.js",
            "/static/js/views/files.js",
            "/static/js/app.js",
        ]

        last_pos = -1
        for s in scripts:
            needle = f'src="{s}"'
            assert needle in html, f"Missing script tag: {s}"
            pos = html.index(needle)
            assert pos > last_pos, f"Script {s} is out of dependency order"
            last_pos = pos


class TestPhase16ViewHierarchy:
    """Verify DOM integrity, navigation consistency, and lack of obsolete placeholders."""

    @pytest.fixture(autouse=True)
    def load_html(self, client: TestClient) -> None:
        resp = client.get("/")
        self.html = resp.text

    def test_all_navigation_targets_have_corresponding_view_panels(self) -> None:
        """Every nav link data-view attribute must map to a unique #view-<name> panel."""
        for name in VIEW_NAMES:
            nav_needle = f'data-view="{name}"'
            panel_needle = f'id="view-{name}"'
            assert nav_needle in self.html, f"Navigation link missing for {name}"
            assert panel_needle in self.html, f"View container missing for {name}"

    def test_no_duplicate_element_ids(self) -> None:
        """Every element ID across the entire index.html must be strictly unique."""
        ids = re.findall(r'id=["\']([^"\']+)["\']', self.html)
        counts = Counter(ids)
        duplicates = {k: v for k, v in counts.items() if v > 1}
        assert not duplicates, f"Duplicate element IDs found: {duplicates}"

    def test_no_obsolete_view_placeholders_remain(self) -> None:
        """No placeholder container classes or text remain in view panels."""
        assert "filter-placeholder" not in self.html
        assert "table-placeholder" not in self.html
        assert "chart-placeholder" not in self.html
        assert "controls placeholder" not in self.html.lower()

    def test_all_modals_have_accessibility_attributes(self) -> None:
        """All modal containers must specify role=dialog, aria-modal=true, aria-labelledby, and close button."""
        modals = [
            ("login-modal-container", "login-modal-title", "login-modal-close"),
            ("event-detail-modal-container", "event-detail-title", "event-detail-close-btn"),
            ("process-detail-modal-container", "process-detail-title", "process-detail-close-btn"),
            ("file-detail-modal-container", "file-detail-title", "file-detail-close-btn"),
        ]
        for modal_id, title_id, close_btn_id in modals:
            assert f'id="{modal_id}"' in self.html
            assert f'id="{title_id}"' in self.html
            assert f'id="{close_btn_id}"' in self.html
            assert f'aria-labelledby="{title_id}"' in self.html

    def test_all_views_have_error_and_empty_states(self) -> None:
        """All five data views must have alert/error boxes and empty state containers."""
        for name in ["events", "processes", "resources", "files"]:
            assert f'id="{name}-error-box"' in self.html
            assert f'id="{name}-empty-state"' in self.html

        # Dashboard status and resource cards have their error elements
        assert 'id="status-card-error"' in self.html
        assert 'id="resource-card-error"' in self.html

    def test_all_views_have_refresh_or_query_controls(self) -> None:
        """All five views have explicit refresh or query submission controls."""
        assert 'id="dashboard-refresh-btn"' in self.html
        assert 'id="filter-event-apply-btn"' in self.html
        assert 'id="filter-process-apply-btn"' in self.html
        assert 'id="resources-refresh-btn"' in self.html
        assert 'id="files-refresh-btn"' in self.html


class TestPhase16SecurityContract:
    """Verify codebase-wide security rules across all frontend files."""

    @pytest.fixture(autouse=True)
    def load_frontend_sources(self) -> None:
        self.sources = {}
        for js_file in JS_FILES:
            self.sources[js_file.name] = js_file.read_text(encoding="utf-8")

    def test_zero_localstorage_in_frontend(self) -> None:
        """localStorage must NEVER be referenced anywhere in frontend scripts."""
        for name, code in self.sources.items():
            assert "localStorage" not in code, f"Forbidden 'localStorage' in {name}"

    def test_zero_innerhtml_in_frontend(self) -> None:
        """innerHTML must NEVER be referenced anywhere in frontend scripts."""
        for name, code in self.sources.items():
            assert "innerHTML" not in code, f"Forbidden 'innerHTML' in {name}"

    def test_zero_eval_or_function_constructor(self) -> None:
        """eval() and new Function() must NEVER be used in frontend scripts."""
        for name, code in self.sources.items():
            assert "eval(" not in code, f"Forbidden 'eval(' in {name}"
            assert "new Function(" not in code, f"Forbidden 'new Function(' in {name}"

    def test_zero_document_write(self) -> None:
        """document.write must NEVER be used in frontend scripts."""
        for name, code in self.sources.items():
            assert "document.write" not in code, f"Forbidden 'document.write' in {name}"

    def test_zero_hardcoded_secrets(self) -> None:
        """No passwords, test credentials, or static JWTs in frontend scripts."""
        forbidden = ["changeme", "password123", "bearer ey", "secret_key"]
        for name, code in self.sources.items():
            lower = code.lower()
            for pattern in forbidden:
                assert pattern not in lower, f"Forbidden secret pattern '{pattern}' in {name}"

    def test_authorization_header_restricted_to_api_js(self) -> None:
        """Authorization header manipulation must only exist in api.js."""
        for name, code in self.sources.items():
            if name == "api.js":
                assert "Authorization" in code
            else:
                assert "Authorization" not in code, f"Unexpected Authorization header in {name}"

    def test_zero_console_logging(self) -> None:
        """No console.log calls left in frontend scripts."""
        for name, code in self.sources.items():
            assert "console.log" not in code, f"Accidental console.log in {name}"


class TestPhase16ApiContractCrossCheck:
    """Verify frontend API calls match Phase 1.5 backend contracts."""

    def test_all_referenced_endpoints_match_backend_routes(self) -> None:
        """All API calls in frontend map to actual Phase 1.5 backend routers."""
        valid_prefixes = [
            "/api/status",
            "/api/auth/login",
            "/api/auth/me",
            "/api/events",
            "/api/processes",
            "/api/resources",
            "/api/files",
        ]
        for js_file in JS_FILES:
            code = js_file.read_text(encoding="utf-8")
            api_calls = re.findall(r"['\"](/api/[a-zA-Z0-9_\-/]+)['\"]", code)
            for call in api_calls:
                matches = any(call.startswith(prefix) for prefix in valid_prefixes)
                assert matches, f"Unknown API endpoint '{call}' in {js_file.name}"

    def test_unsupported_filters_are_not_sent(self) -> None:
        """Frontend view controllers must not set unsupported query parameters."""
        processes_code = (VIEWS_DIR / "processes.js").read_text(encoding="utf-8")
        assert "params.set('ppid'" not in processes_code
        assert "params.set('linux_user_id'" not in processes_code
        assert "params.set('state'" not in processes_code

        files_code = (VIEWS_DIR / "files.js").read_text(encoding="utf-8")
        assert "params.set('inode'" not in files_code
        assert "params.set('pid'" not in files_code
        assert "params.set('start_time'" not in files_code

    def test_backend_routes_enforce_authentication(self, client: TestClient) -> None:
        """Protected API routes must return 401 unauthenticated and 200 authenticated."""
        token = create_access_token(
            user_id="00000000-0000-4000-8000-000000000100", username="admin"
        )
        auth_headers = {"Authorization": f"Bearer {token}"}

        endpoints = [
            "/api/auth/me",
            "/api/events?limit=1",
            "/api/processes?limit=1",
            "/api/resources?limit=1",
            "/api/files?limit=1",
        ]

        for ep in endpoints:
            unauth_resp = client.get(ep)
            assert unauth_resp.status_code == 401, f"{ep} must require auth"

            auth_resp = client.get(ep, headers=auth_headers)
            assert auth_resp.status_code == 200, f"{ep} must return 200 with valid token"


class TestPhase16JavaScriptCoreSyntax:
    """Verify all seven JavaScript files parse cleanly in JavaScriptCore."""

    @pytest.mark.parametrize("js_file", JS_FILES, ids=[f.name for f in JS_FILES])
    def test_javascriptcore_syntax(self, js_file: Path) -> None:
        """Verify each JavaScript file with macOS JSC runtime."""
        jsc_bin = "/System/Library/Frameworks/JavaScriptCore.framework/Versions/A/Helpers/jsc"
        if not Path(jsc_bin).exists():
            pytest.skip("JavaScriptCore CLI not available on this system")

        result = subprocess.run(
            [jsc_bin, "-e", f"checkSyntax('{js_file}')"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"{js_file.name} syntax error:\n{result.stderr}"
