"""Unit tests for OSIRIS Phase 1.6 Frontend Static Mount and Base Scaffold.

Verifies:
- GET / serves the HTML5 SPA index.html shell with text/html content-type.
- GET /static/css/style.css serves the base stylesheet with text/css content-type.
- Semantic regions and view container shells exist in index.html.
- Existing API routes (/health, /api/status, /api/events, etc.) are not shadowed.
- Public endpoints remain accessible without authentication.
"""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from backend.main import app


@pytest.fixture
def client() -> TestClient:
    """Provide a TestClient for testing static routes and API integrity."""
    return TestClient(app)


class TestFrontendServing:
    """Test suite for root SPA page and static CSS asset serving."""

    def test_get_root_serves_index_html(self, client: TestClient) -> None:
        """GET / must return 200 OK with HTML content-type and OSIRIS shell."""
        resp = client.get("/")
        assert resp.status_code == 200
        content_type = resp.headers.get("content-type", "")
        assert "text/html" in content_type

        body = resp.text
        # Document declaration and title
        assert "<!DOCTYPE html>" in body
        assert "<title>OSIRIS</title>" in body

        # Semantic regions
        assert '<header class="app-header"' in body
        assert '<nav class="app-nav"' in body
        assert '<main id="main-content"' in body
        assert '<footer class="app-footer"' in body

        # View containers for all 5 Phase 1.6 domains
        assert 'id="view-dashboard"' in body
        assert 'id="view-events"' in body
        assert 'id="view-processes"' in body
        assert 'id="view-resources"' in body
        assert 'id="view-files"' in body

        # Authentication / user area placeholders
        assert 'id="user-profile-area"' in body
        assert 'id="login-modal-container"' in body
        assert 'id="login-trigger-btn"' in body
        assert 'id="logout-btn"' in body

        # Stylesheet link
        assert 'href="/static/css/style.css"' in body

    def test_get_static_css_serves_stylesheet(self, client: TestClient) -> None:
        """GET /static/css/style.css must return 200 with text/css and base design tokens."""
        resp = client.get("/static/css/style.css")
        assert resp.status_code == 200
        content_type = resp.headers.get("content-type", "")
        assert "text/css" in content_type

        css_body = resp.text
        # Verify core design tokens and visual rules
        assert "--bg-canvas" in css_body
        assert "--bg-primary" in css_body
        assert "--text-primary" in css_body
        assert "--border-accent" in css_body
        assert ".app-header" in css_body
        assert ".card" in css_body
        assert ".modal-dialog" in css_body
        assert ".placeholder-skeleton" in css_body

    def test_get_static_js_api_serves_script(self, client: TestClient) -> None:
        """GET /static/js/api.js must return 200 with JavaScript content-type and core exports."""
        resp = client.get("/static/js/api.js")
        assert resp.status_code == 200
        content_type = resp.headers.get("content-type", "")
        assert "javascript" in content_type

        js_body = resp.text
        assert "TOKEN_STORAGE_KEY" in js_body
        assert "fetchWithAuth" in js_body
        assert "login" in js_body
        assert "getCurrentUser" in js_body
        assert "onAuthExpired" in js_body
        assert "sessionStorage" in js_body
        assert "localStorage" not in js_body

    def test_get_static_js_app_serves_script(self, client: TestClient) -> None:
        """GET /static/js/app.js must return 200 with JavaScript content-type and app controller."""
        resp = client.get("/static/js/app.js")
        assert resp.status_code == 200
        content_type = resp.headers.get("content-type", "")
        assert "javascript" in content_type

        js_body = resp.text
        assert "switchView" in js_body
        assert "handleLoginSubmit" in js_body
        assert "handleLogout" in js_body
        assert "setAuthenticatedState" in js_body
        assert "setUnauthenticatedState" in js_body

    def test_index_html_includes_scripts_and_login_form(self, client: TestClient) -> None:
        """GET / must include script tags for api.js and app.js as well as login form elements."""
        resp = client.get("/")
        assert resp.status_code == 200
        body = resp.text

        # Verify script inclusions
        assert 'src="/static/js/api.js"' in body
        assert 'src="/static/js/app.js"' in body

        # Verify login form elements
        assert 'id="login-form"' in body
        assert 'id="login-username"' in body
        assert 'id="login-password"' in body
        assert 'id="login-submit-btn"' in body
        assert 'id="login-error"' in body

        # Verify navigation controls
        for view in ["dashboard", "events", "processes", "resources", "files"]:
            assert f'data-view="{view}"' in body

    def test_static_js_files_contain_no_secrets(self, client: TestClient) -> None:
        """Client JS files must not contain embedded passwords, tokens, or secret keys."""
        for js_path in ["/static/js/api.js", "/static/js/app.js"]:
            resp = client.get(js_path)
            assert resp.status_code == 200
            body = resp.text.lower()
            assert "changeme" not in body
            assert "password123" not in body
            assert "bearer ey" not in body
            assert "secret_key" not in body

    def test_static_nonexistent_file_returns_404(self, client: TestClient) -> None:
        """Nonexistent static asset must return 404."""
        resp = client.get("/static/css/nonexistent.css")
        assert resp.status_code == 404



class TestApiRoutingIntegrity:
    """Ensure static mounts do not shadow or break existing API routes."""

    def test_health_check_remains_operational(self, client: TestClient) -> None:
        """GET /health must return 200 without being shadowed by static routing."""
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok", "system": "osiris"}

    def test_api_status_remains_public_and_operational(self, client: TestClient) -> None:
        """GET /api/status must remain public and return 200."""
        resp = client.get("/api/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "status" in data
        assert data["system"] == "osiris"

    def test_api_routes_not_shadowed(self, client: TestClient) -> None:
        """Protected API routes must return 401 (not 404 or index.html) when unauthenticated."""
        for path in [
            "/api/auth/me",
            "/api/events",
            "/api/processes",
            "/api/resources",
            "/api/files",
        ]:
            resp = client.get(path)
            assert resp.status_code == 401, f"Expected 401 on {path}, got {resp.status_code}"
            assert resp.headers.get("content-type", "").startswith("application/json")
            assert "detail" in resp.json()

    def test_openapi_schema_remains_available(self, client: TestClient) -> None:
        """GET /openapi.json and documentation routes must remain accessible."""
        resp = client.get("/openapi.json")
        assert resp.status_code == 200
        assert resp.headers.get("content-type", "").startswith("application/json")
        paths = resp.json()["paths"]
        assert "/" in paths
        assert "/health" in paths
        assert "/api/status" in paths
        assert "/api/events" in paths
