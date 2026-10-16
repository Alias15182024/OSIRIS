"""Unit and integration tests for Phase 1.7N Security Hardening.

Covers:
1. Strict loopback base URL enforcement and reject-by-default remote policy.
2. Explicit --allow-remote opt-in mechanism for HTTPS remote endpoints.
3. In-memory authentication token scrubbing upon logout, close, and HTTP 401.
4. Root execution detection logic (UID 0 check) and cross-platform safety.
5. Persistent root security warning banner presentation independent of API health.
6. CLI argument parsing and base URL pre-flight validation in desktop entrypoint.
7. Worker request sequence invalidation on logout preventing stale UI population.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
import respx
from PySide6.QtWidgets import QApplication

from desktop.client.api_client import (
    DEFAULT_BASE_URL,
    APIClient,
    validate_base_url,
)
from desktop.client.exceptions import (
    AuthenticationError,
    ValidationError,
)
from desktop.client.models import (
    EventCollection,
    HealthStatus,
    SystemStatus,
    User,
)
from desktop.main import main, parse_args
from desktop.ui.components.root_warning_banner import (
    DEFAULT_ROOT_WARNING_TEXT,
    RootWarningBanner,
)
from desktop.ui.main_window import (
    MainWindow,
    OperationalStatusResult,
    is_root_execution,
)


def _sample_user() -> User:
    """Return a representative authenticated User instance for tests."""
    return User(
        id="usr-sec-01",
        username="secops_auditor",
        display_name="Security Auditor",
        role="analyst",
        is_active=True,
        created_at="2026-01-01T00:00:00Z",
    )


# ==============================================================================
# 1. Loopback Base URL & Remote Host Constraints
# ==============================================================================


class TestLoopbackBaseURLEnforcement:
    """Tests for default loopback enforcement and remote authorization."""

    def test_default_loopback_urls_permitted(self) -> None:
        """Verify default configuration allows IPv4/IPv6 loopback and localhost."""
        assert validate_base_url(DEFAULT_BASE_URL) == "http://127.0.0.1:8001"
        assert validate_base_url("http://127.0.0.1:8000") == "http://127.0.0.1:8000"
        assert validate_base_url("http://localhost:8000") == "http://localhost:8000"
        assert validate_base_url("http://localhost") == "http://localhost"
        assert validate_base_url("http://127.0.0.2:8080") == "http://127.0.0.2:8080"
        assert validate_base_url("http://[::1]:8000") == "http://[::1]:8000"
        assert validate_base_url("https://[::1]:8443") == "https://[::1]:8443"

    def test_reject_all_remote_and_lan_hosts_by_default(self) -> None:
        """Verify non-loopback URLs fail closed without allow_remote=True."""
        remote_targets = [
            "http://0.0.0.0:8000",
            "http://192.168.1.1:8000",
            "http://10.0.0.1:8000",
            "http://172.16.0.1:8000",
            "https://api.osiris.security:8443",
            "https://soc.company.internal",
            "https://8.8.8.8:8443",
            "https://localhost.attacker.com",
            "https://127.0.0.1.attacker.com",
        ]
        for target in remote_targets:
            with pytest.raises(
                ValidationError, match="Remote API base URL.*not permitted"
            ):
                validate_base_url(target)

    def test_allow_remote_permits_valid_https(self) -> None:
        """Verify allow_remote=True permits HTTPS endpoints."""
        assert (
            validate_base_url("https://api.osiris.security", allow_remote=True)
            == "https://api.osiris.security"
        )
        assert (
            validate_base_url("https://soc.internal:8443/api", allow_remote=True)
            == "https://soc.internal:8443/api"
        )
        assert (
            validate_base_url("https://10.0.0.5:8443", allow_remote=True)
            == "https://10.0.0.5:8443"
        )

    def test_allow_remote_still_rejects_insecure_http_for_remote(self) -> None:
        """Verify allow_remote=True still requires HTTPS on remote hosts."""
        insecure_targets = [
            "http://api.osiris.security",
            "http://192.168.1.10:8000",
            "http://10.0.0.1:8000",
        ]
        for target in insecure_targets:
            with pytest.raises(
                ValidationError, match="Insecure plain HTTP is only permitted"
            ):
                validate_base_url(target, allow_remote=True)

    def test_reject_embedded_credentials(self) -> None:
        """Verify embedded credentials fail closed on loopback and remote."""
        with pytest.raises(
            ValidationError, match="embedded user credentials"
        ):
            validate_base_url("http://user:pass@127.0.0.1:8001")

        with pytest.raises(
            ValidationError, match="embedded user credentials"
        ):
            validate_base_url(
                "https://user:pass@api.osiris.io", allow_remote=True
            )


# ==============================================================================
# 2. APIClient Remote Opt-in & In-Memory Token Lifecycle
# ==============================================================================


class TestAPIClientSecurityHardening:
    """Tests for APIClient remote validation and token scrubbing."""

    def test_apiclient_rejects_remote_by_default(self) -> None:
        """Verify APIClient constructor rejects remote URL without flag."""
        with pytest.raises(
            ValidationError, match="Remote API base URL.*not permitted"
        ):
            APIClient(base_url="https://api.osiris.security:8443")

    def test_apiclient_accepts_remote_with_flag(self) -> None:
        """Verify APIClient accepts remote HTTPS URL when allow_remote=True."""
        client = APIClient(
            base_url="https://api.osiris.security:8443",
            allow_remote=True,
        )
        assert client.allow_remote is True
        assert client.base_url == "https://api.osiris.security:8443"
        client.close()

    @respx.mock
    def test_token_scrubbed_on_logout(self) -> None:
        """Verify logout clears in-memory token and authorization header."""
        respx.post("http://127.0.0.1:8001/api/auth/login").respond(
            200,
            json={
                "access_token": "secret_jwt_token_12345",
                "token_type": "bearer",
                "user": {
                    "id": "u-01",
                    "username": "admin",
                    "role": "admin",
                    "is_active": True,
                    "created_at": "2026-01-01T00:00:00Z",
                },
            },
        )
        client = APIClient()
        client.login("admin", "password123")
        assert client.is_authenticated is True

        # Manually verify client internal token state
        assert client._token == "secret_jwt_token_12345"

        client.logout()

        assert client.is_authenticated is False
        assert client._token is None
        if client._client is not None:
            assert "Authorization" not in client._client.headers
        client.close()

    @respx.mock
    def test_token_scrubbed_on_close(self) -> None:
        """Verify close clears in-memory token and session state."""
        respx.post("http://127.0.0.1:8001/api/auth/login").respond(
            200,
            json={
                "access_token": "secret_jwt_token_67890",
                "token_type": "bearer",
                "user": {
                    "id": "u-01",
                    "username": "admin",
                    "role": "admin",
                    "is_active": True,
                    "created_at": "2026-01-01T00:00:00Z",
                },
            },
        )
        client = APIClient()
        client.login("admin", "password123")
        assert client.is_authenticated is True

        client.close()

        assert client.is_authenticated is False
        assert client.is_closed is True
        assert client._token is None
        assert client._client is None

    @respx.mock
    def test_token_scrubbed_on_http_401(self) -> None:
        """Verify 401 response on authenticated endpoint clears token."""
        respx.post("http://127.0.0.1:8001/api/auth/login").respond(
            200,
            json={
                "access_token": "token_about_to_expire",
                "token_type": "bearer",
                "user": {
                    "id": "u-01",
                    "username": "admin",
                    "role": "admin",
                    "is_active": True,
                    "created_at": "2026-01-01T00:00:00Z",
                },
            },
        )
        respx.get("http://127.0.0.1:8001/api/auth/me").respond(
            401, json={"detail": "Token expired or revoked"}
        )

        client = APIClient()
        client.login("admin", "password123")
        assert client.is_authenticated is True

        with pytest.raises(AuthenticationError, match="Token expired"):
            client.get_current_user()

        assert client.is_authenticated is False
        assert client._token is None
        client.close()

    @respx.mock
    def test_token_retained_on_http_403(self) -> None:
        """Verify 403 authorization failure does not scrub valid token."""
        respx.post("http://127.0.0.1:8001/api/auth/login").respond(
            200,
            json={
                "access_token": "valid_token_unauthorized_action",
                "token_type": "bearer",
                "user": {
                    "id": "u-01",
                    "username": "admin",
                    "role": "admin",
                    "is_active": True,
                    "created_at": "2026-01-01T00:00:00Z",
                },
            },
        )
        respx.get("http://127.0.0.1:8001/api/auth/me").respond(
            403, json={"detail": "Account inactive or unauthorized"}
        )

        client = APIClient()
        client.login("admin", "password123")
        assert client.is_authenticated is True

        with pytest.raises(Exception):
            client.get_current_user()

        # Token should be retained on 403
        assert client.is_authenticated is True
        assert client._token == "valid_token_unauthorized_action"
        client.close()


# ==============================================================================
# 3. Root Execution UID Check Logic
# ==============================================================================


class TestRootExecutionDetection:
    """Tests for root execution (UID 0) detection and platform safety."""

    def test_is_root_execution_true_when_uid_zero(self) -> None:
        """Verify is_root_execution returns True when os.geteuid is 0."""
        with patch("os.geteuid", return_value=0):
            assert is_root_execution() is True

    def test_is_root_execution_false_when_uid_nonzero(self) -> None:
        """Verify is_root_execution returns False for normal unprivileged UIDs."""
        with patch("os.geteuid", return_value=1000):
            assert is_root_execution() is False

        with patch("os.geteuid", return_value=501):
            assert is_root_execution() is False

    def test_is_root_execution_false_when_geteuid_missing(self) -> None:
        """Verify graceful fallback on platforms lacking os.geteuid (Windows)."""
        with patch.object(os, "geteuid", create=True):
            delattr(os, "geteuid")
            assert is_root_execution() is False

    def test_is_root_execution_false_on_os_error(self) -> None:
        """Verify is_root_execution handles exceptions from geteuid safely."""
        with patch("os.geteuid", side_effect=OSError("Permission denied")):
            assert is_root_execution() is False


# ==============================================================================
# 4. Root Warning Banner Component & MainWindow Integration
# ==============================================================================


class TestRootWarningBannerUI:
    """Tests for RootWarningBanner and MainWindow security posture presentation."""

    def test_root_warning_banner_component(self, qapp: QApplication) -> None:
        """Verify standalone RootWarningBanner visibility and message mutation."""
        banner = RootWarningBanner(is_root=False)
        assert banner.objectName() == "RootWarningBanner"
        assert banner.is_root is False
        assert banner.isHidden() is True
        assert banner.indicator_label.text() == "SECURITY WARNING"
        assert banner.message == DEFAULT_ROOT_WARNING_TEXT

        # Activate root warning
        banner.set_root_warning(True)
        assert banner.is_root is True
        assert banner.isVisible() is True

        # Update message
        banner.set_root_warning(True, message="Custom root warning message")
        assert banner.message == "Custom root warning message"
        assert banner.message_label.text() == "Custom root warning message"

        # Deactivate
        banner.set_root_warning(False)
        assert banner.is_root is False
        assert banner.isHidden() is True

    def test_mainwindow_root_banner_presentation(
        self, qapp: QApplication
    ) -> None:
        """Verify MainWindow presents root banner when is_root=True."""
        window = MainWindow(is_root=True)
        window.show()
        try:
            assert window.is_root is True
            assert isinstance(window.root_warning_banner, RootWarningBanner)
            assert window.root_warning_banner.isVisible() is True
            assert (
                window.root_warning_banner.indicator_label.text()
                == "SECURITY WARNING"
            )
            assert "violates least-privilege" in window.root_warning_banner.message
        finally:
            window.close()

    def test_mainwindow_unprivileged_hides_root_banner(
        self, qapp: QApplication
    ) -> None:
        """Verify MainWindow hides root banner when is_root=False."""
        window = MainWindow(is_root=False)
        window.show()
        try:
            assert window.is_root is False
            assert window.root_warning_banner.isHidden() is True
        finally:
            window.close()

    def test_root_banner_persists_across_operational_status_clears(
        self, qapp: QApplication
    ) -> None:
        """Verify root warning is NOT cleared when operational health banner clears."""
        window = MainWindow(is_root=True)
        window.show()
        try:
            assert window.root_warning_banner.isVisible() is True

            # Trigger operational degraded banner
            window.shell.show_degraded_warning("Backend degraded: Database down")
            assert window.shell.error_banner.isVisible() is True
            assert window.root_warning_banner.isVisible() is True

            # Clear operational error banner
            window.shell.clear_global_warning()
            assert window.shell.error_banner.isHidden() is True

            # Root security warning MUST remain visible and persistent
            assert window.root_warning_banner.isVisible() is True

            # Simulate operational status result recovery
            op_result = OperationalStatusResult(
                health=HealthStatus(status="healthy", system="operational"),
                health_error=None,
                system_status=SystemStatus(
                    status="healthy",
                    system="operational",
                    database="connected",
                    host_id="00000000-0000-0000-0000-000000000001",
                ),
                status_error=None,
                timestamp=datetime.now(timezone.utc),
            )
            window._on_status_result(op_result, seq=window._status_request_seq)

            # Error banner stays clear, root warning stays visible
            assert window.shell.error_banner.isHidden() is True
            assert window.root_warning_banner.isVisible() is True
        finally:
            window.close()


# ==============================================================================
# 5. CLI Arguments & Main Entrypoint Hardening
# ==============================================================================


class TestCLIArgumentSecurity:
    """Tests for CLI arguments validation and entrypoint security."""

    def test_parse_args_defaults(self) -> None:
        """Verify parse_args defaults to loopback and no remote authorization."""
        args = parse_args([])
        assert args.api_url == DEFAULT_BASE_URL
        assert args.allow_remote is False

    def test_parse_args_custom_values(self) -> None:
        """Verify parse_args accepts --api-url and --allow-remote."""
        args = parse_args([
            "--api-url",
            "https://soc.company.internal:8443",
            "--allow-remote",
        ])
        assert args.api_url == "https://soc.company.internal:8443"
        assert args.allow_remote is True

    def test_main_rejects_unauthorized_remote_url(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Verify main() exits with code 2 when remote URL lacks flag."""
        exit_code = main(["--api-url", "https://api.remote-soc.org:8443"])
        assert exit_code == 2
        captured = capsys.readouterr()
        assert "Configuration error" in captured.err
        assert "Remote API base URL" in captured.err


# ==============================================================================
# 6. Logout Worker Guarding & Sequence Invalidation
# ==============================================================================


class TestLogoutWorkerGuards:
    """Tests for worker cancellation and sequence invalidation on logout."""

    def test_logout_invalidates_request_sequences_and_cleans_session(
        self, qapp: QApplication
    ) -> None:
        """Verify _handle_logout invalidates sequences, timers, and session."""
        client = APIClient()
        user = _sample_user()
        window = MainWindow(client=client, user=user, is_root=False)
        try:
            # Set initial sequences
            window._events_request_seq = 10
            window._processes_request_seq = 20
            window._resources_request_seq = 30
            window._files_request_seq = 40
            window._status_request_seq = 50

            window.start_live_refresh()
            window.start_status_polling()
            assert window.is_status_polling_active is True

            window._handle_logout()

            # Sequences bumped
            assert window._events_request_seq == 11
            assert window._processes_request_seq == 21
            assert window._resources_request_seq == 31
            assert window._files_request_seq == 41
            assert window._status_request_seq == 51

            # Timers stopped
            assert window.is_live_refresh_active is False
            assert window.is_status_polling_active is False

            # Session cleared
            assert window.client is None
            assert window.user is None
            assert window.shell.user is None

            # Test that a superseded in-flight event result arriving now is discarded
            mock_collection = MagicMock(spec=EventCollection)
            window._on_events_result(mock_collection, seq=10)
            # Events view was not updated because seq 10 != 11 and client is None
            assert window.events_view.model.rowCount() == 0
        finally:
            window.close()
            client.close()
