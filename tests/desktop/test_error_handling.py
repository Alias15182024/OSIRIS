"""Unit and integration tests for error and degraded states handling (Phase 1.7M).

Verifies:
1. Typed API client error mapping (NotFoundError, ServerError, ConnectionError,
   AuthenticationError, AuthorizationError, ConnectionTimeoutError).
2. GlobalErrorBanner widget presentation, states, flicker-free updates, and retry.
3. AppShell layout integration, property exposure, and signal forwarding.
4. MainWindow operational status error handling, unreachable banner, and backoff.
5. MainWindow degraded state handling and automatic recovery.
6. View connection error propagation to global banner and retained data.
7. Authentication expiration (HTTP 401) stopping live monitoring refresh.
8. Sanitized user-facing messages for 404, 5xx, timeouts, and network loss.
9. Coordinated, non-blocking shutdown with active error states.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import httpx
import pytest
import respx
from PySide6.QtWidgets import QApplication

from desktop.client.api_client import APIClient
from desktop.client.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ClientConnectionError,
    ConnectionTimeoutError,
    HTTPResponseError,
    NotFoundError,
    OSIRISClientError,
    ServerError,
    ValidationError,
)
from desktop.client.models import (
    HealthStatus,
    SystemStatus,
    User,
)
from desktop.ui.app_shell import AppShell
from desktop.ui.components.error_banner import (
    STATE_DEGRADED,
    STATE_DISCONNECTED,
    ErrorBanner,
)
from desktop.ui.main_window import (
    MainWindow,
    OperationalStatusResult,
)


def _sample_user() -> User:
    """Return a representative authenticated User instance for tests."""
    return User(
        id="usr-error-001",
        username="sec_auditor",
        display_name="Security Auditor",
        role="analyst",
        is_active=True,
        created_at="2026-01-01T00:00:00Z",
    )


# ==============================================================================
# 1. API Client Error Classification Tests
# ==============================================================================


@respx.mock
def test_api_client_maps_404_to_not_found_error() -> None:
    """HTTP 404 response raises NotFoundError which inherits HTTPResponseError."""
    respx.get(
        "http://127.0.0.1:8001/api/processes/550e8400-e29b-41d4-a716-446655440000"
    ).mock(
        return_value=httpx.Response(404, json={"detail": "Process not found"})
    )
    client = APIClient(base_url="http://127.0.0.1:8001")
    client._token = "valid-token"

    with pytest.raises(NotFoundError) as exc_info:
        client.get_process("550e8400-e29b-41d4-a716-446655440000")

    err = exc_info.value
    assert isinstance(err, HTTPResponseError)
    assert isinstance(err, OSIRISClientError)
    assert err.status_code == 404
    assert "Process not found" in str(err)
    client.close()


@respx.mock
@pytest.mark.parametrize("status_code", [500, 502, 503, 504])
def test_api_client_maps_5xx_to_server_error(status_code: int) -> None:
    """HTTP 5xx responses raise ServerError which inherits HTTPResponseError."""
    respx.get("http://127.0.0.1:8001/api/events").mock(
        return_value=httpx.Response(
            status_code, json={"detail": "Service unavailable"}
        )
    )
    client = APIClient(base_url="http://127.0.0.1:8001")
    client._token = "valid-token"

    with pytest.raises(ServerError) as exc_info:
        client.get_events()

    err = exc_info.value
    assert isinstance(err, HTTPResponseError)
    assert err.status_code == status_code
    client.close()


@respx.mock
def test_api_client_maps_connection_drop_to_client_connection_error() -> None:
    """Network connection failure raises ClientConnectionError."""
    respx.get("http://127.0.0.1:8001/api/status").mock(
        side_effect=httpx.ConnectError("Connection refused")
    )
    client = APIClient(base_url="http://127.0.0.1:8001")

    with pytest.raises(ClientConnectionError):
        client.get_status()

    client.close()


@respx.mock
def test_api_client_maps_timeout_to_connection_timeout_error() -> None:
    """Read or connect timeout raises ConnectionTimeoutError."""
    respx.get("http://127.0.0.1:8001/health").mock(
        side_effect=httpx.ReadTimeout("Read timed out")
    )
    client = APIClient(base_url="http://127.0.0.1:8001")

    with pytest.raises(ConnectionTimeoutError):
        client.get_health()

    client.close()


@respx.mock
def test_api_client_401_clears_stored_token() -> None:
    """HTTP 401 on authenticated request raises AuthenticationError and clears token."""
    respx.get("http://127.0.0.1:8001/api/events").mock(
        return_value=httpx.Response(401, json={"detail": "Token expired"})
    )
    client = APIClient(base_url="http://127.0.0.1:8001")
    client._token = "expired-token"
    assert client.is_authenticated

    with pytest.raises(AuthenticationError):
        client.get_events()

    assert not client.is_authenticated
    assert client._token is None
    client.close()


@respx.mock
def test_api_client_403_preserves_token() -> None:
    """HTTP 403 authorization failure raises AuthorizationError and keeps token."""
    respx.get("http://127.0.0.1:8001/api/events").mock(
        return_value=httpx.Response(403, json={"detail": "Forbidden action"})
    )
    client = APIClient(base_url="http://127.0.0.1:8001")
    client._token = "valid-token-limited-scope"

    with pytest.raises(AuthorizationError):
        client.get_events()

    assert client.is_authenticated
    assert client._token == "valid-token-limited-scope"
    client.close()


# ==============================================================================
# 2. ErrorBanner Component Tests
# ==============================================================================


def test_error_banner_initial_state(qapp: QApplication) -> None:
    """ErrorBanner defaults to hidden, empty type, and empty message."""
    banner = ErrorBanner()
    assert banner.objectName() == "GlobalErrorBanner"
    assert not banner.isVisible()
    assert banner.banner_type == ""
    assert banner.message == ""
    assert banner.indicator_label.objectName() == "ErrorBannerIndicator"
    assert banner.message_label.objectName() == "ErrorBannerMessage"
    assert banner.retry_button.objectName() == "ErrorBannerRetryButton"


def test_error_banner_show_connection_error(qapp: QApplication) -> None:
    """show_connection_error activates disconnected state and visible banner."""
    banner = ErrorBanner()
    banner.show_connection_error("API server connection lost.")

    assert banner.isVisible()
    assert banner.banner_type == STATE_DISCONNECTED
    assert banner.property("bannerType") == STATE_DISCONNECTED
    assert banner.indicator_label.text() == "DISCONNECTED"
    assert banner.message == "API server connection lost."
    assert banner.message_label.text() == "API server connection lost."


def test_error_banner_show_degraded(qapp: QApplication) -> None:
    """show_degraded activates degraded state and visible banner."""
    banner = ErrorBanner()
    banner.show_degraded("Database connectivity offline.")

    assert banner.isVisible()
    assert banner.banner_type == STATE_DEGRADED
    assert banner.property("bannerType") == STATE_DEGRADED
    assert banner.indicator_label.text() == "DEGRADED"
    assert banner.message == "Database connectivity offline."
    assert banner.message_label.text() == "Database connectivity offline."


def test_error_banner_clear(qapp: QApplication) -> None:
    """clear resets properties and hides the banner."""
    banner = ErrorBanner()
    banner.show_connection_error("Failure")
    assert banner.isVisible()

    banner.clear()
    assert not banner.isVisible()
    assert banner.banner_type == ""
    assert banner.message == ""
    assert banner.property("bannerType") == ""
    assert banner.indicator_label.text() == ""
    assert banner.message_label.text() == ""


def test_error_banner_flicker_free_repeated_calls(qapp: QApplication) -> None:
    """Calling update methods repeatedly does not alter properties unnecessarily."""
    banner = ErrorBanner()
    banner.show_connection_error("Server down")
    assert banner.isVisible()

    # Re-call with same parameters
    banner.show_connection_error("Server down")
    assert banner.isVisible()
    assert banner.banner_type == STATE_DISCONNECTED
    assert banner.message == "Server down"

    # Clear when already cleared
    banner.clear()
    assert not banner.isVisible()
    banner.clear()  # No-op guard
    assert not banner.isVisible()


def test_error_banner_retry_requested_signal(qapp: QApplication) -> None:
    """Clicking retry button emits retry_requested signal."""
    banner = ErrorBanner()
    received: list[bool] = []
    banner.retry_requested.connect(lambda: received.append(True))

    banner.retry_button.click()
    assert len(received) == 1


# ==============================================================================
# 3. AppShell Layout Integration Tests
# ==============================================================================


def test_app_shell_has_error_banner(qapp: QApplication) -> None:
    """AppShell embeds ErrorBanner directly below top header."""
    shell = AppShell()
    banner = shell.error_banner
    assert isinstance(banner, ErrorBanner)
    assert banner.objectName() == "GlobalErrorBanner"
    assert not banner.isVisible()


def test_app_shell_forwards_banner_methods_and_signal(
    qapp: QApplication,
) -> None:
    """AppShell forwards warning methods and retry signal."""
    shell = AppShell()
    received: list[bool] = []
    shell.error_banner_retry_requested.connect(lambda: received.append(True))

    shell.show_connection_error("Connection failure")
    assert shell.error_banner.is_visible
    assert shell.error_banner.banner_type == STATE_DISCONNECTED

    shell.error_banner.retry_button.click()
    assert len(received) == 1

    shell.show_degraded_warning("Degraded")
    assert shell.error_banner.banner_type == STATE_DEGRADED

    shell.clear_global_warning()
    assert not shell.error_banner.is_visible


# ==============================================================================
# 4. MainWindow Operational Status & Recovery Tests
# ==============================================================================


def test_main_window_unreachable_api_shows_connection_banner(
    qapp: QApplication,
) -> None:
    """Unreachable health in _on_status_result activates connection banner."""
    window = MainWindow()
    res = OperationalStatusResult(
        health=None,
        health_error="Connection refused: 127.0.0.1:8001",
        system_status=None,
        status_error="Connection refused",
    )
    window._on_status_result(res, seq=window._status_request_seq)

    assert window.shell.error_banner.is_visible
    assert window.shell.error_banner.banner_type == STATE_DISCONNECTED
    assert "Connection refused" in window.shell.error_banner.message
    assert window.shell.status_api_label.property("apiState") == "unavailable"
    assert window._consecutive_status_failures == 1
    window.close()


def test_main_window_status_poll_backoff(qapp: QApplication) -> None:
    """Consecutive status errors apply backoff to status poll timer."""
    window = MainWindow()
    window._status_poll_timer.start(15000)

    # 1st failure -> 2s (2000ms)
    res = OperationalStatusResult(health=None, health_error="Err1")
    window._on_status_result(res, seq=window._status_request_seq)
    assert window._status_poll_timer.interval() == 2000

    # 2nd failure -> 4s (4000ms)
    window._on_status_result(res, seq=window._status_request_seq)
    assert window._status_poll_timer.interval() == 4000

    # 3rd failure -> 8s (8000ms)
    window._on_status_result(res, seq=window._status_request_seq)
    assert window._status_poll_timer.interval() == 8000

    # 4th failure -> 16s (16000ms)
    window._on_status_result(res, seq=window._status_request_seq)
    assert window._status_poll_timer.interval() == 16000

    # 5th failure -> max 30s (30000ms)
    window._on_status_result(res, seq=window._status_request_seq)
    assert window._status_poll_timer.interval() == 30000
    window.close()


def test_main_window_degraded_backend_shows_degraded_banner(
    qapp: QApplication,
) -> None:
    """Reachable API with disconnected DB or degraded status shows degraded banner."""
    window = MainWindow()
    res = OperationalStatusResult(
        health=HealthStatus(status="ok", system="osiris-api"),
        health_error=None,
        system_status=SystemStatus(
            status="degraded",
            system="osiris-api",
            database="disconnected",
            host_id="test-host",
        ),
        status_error=None,
    )
    window._on_status_result(res, seq=window._status_request_seq)

    assert window.shell.error_banner.is_visible
    assert window.shell.error_banner.banner_type == STATE_DEGRADED
    assert "Database: disconnected" in window.shell.error_banner.message
    assert window.shell.status_api_label.property("apiState") == "reachable"
    assert window.shell.status_database_label.property("dbState") == "disconnected"
    window.close()


def test_main_window_recovery_clears_banner_and_resets_backoff(
    qapp: QApplication,
) -> None:
    """Verified healthy recovery clears error banner and resets poll interval."""
    window = MainWindow()
    window._status_poll_timer.start(15000)

    # Put into disconnected state
    fail_res = OperationalStatusResult(health=None, health_error="Down")
    window._on_status_result(fail_res, seq=window._status_request_seq)
    assert window.shell.error_banner.is_visible
    assert window._status_poll_timer.interval() == 2000

    # Now recover to healthy
    recover_res = OperationalStatusResult(
        health=HealthStatus(status="ok", system="osiris-api"),
        health_error=None,
        system_status=SystemStatus(
            status="healthy",
            system="osiris-api",
            database="connected",
            host_id="test-host",
        ),
        status_error=None,
    )
    window._on_status_result(recover_res, seq=window._status_request_seq)

    assert not window.shell.error_banner.is_visible
    assert window._consecutive_status_failures == 0
    assert window._status_poll_timer.interval() == 15000
    window.close()


def test_main_window_on_status_error_applies_connection_banner(
    qapp: QApplication,
) -> None:
    """Unexpected exception in _on_status_error triggers connection banner."""
    window = MainWindow()
    window._on_status_error(
        ClientConnectionError("Transport failed"),
        seq=window._status_request_seq,
    )

    assert window.shell.error_banner.is_visible
    assert window.shell.error_banner.banner_type == STATE_DISCONNECTED
    assert "Transport failed" in window.shell.error_banner.message
    window.close()


# ==============================================================================
# 5. View Error Handling & Token Invalidation Tests
# ==============================================================================


def test_main_window_events_error_connection_loss(qapp: QApplication) -> None:
    """Connection failure during event load sets view error and connection banner."""
    window = MainWindow()
    window._on_events_error(
        ClientConnectionError("Network down"),
        seq=window._events_request_seq,
    )

    assert window.shell.error_banner.is_visible
    assert window.shell.error_banner.banner_type == STATE_DISCONNECTED
    assert "Operating with retained data" in window.shell.error_banner.message
    assert "Unable to connect" in window.events_view._banner_msg.text()
    window.close()


def test_main_window_events_error_401_stops_live_refresh(
    qapp: QApplication,
) -> None:
    """AuthenticationError during event load stops live refresh timer."""
    window = MainWindow()
    window._shell.navigate_to("Events")
    window._refresh_timer.start(5000)
    assert window.is_live_refresh_active

    window._on_events_error(
        AuthenticationError("Session expired"),
        seq=window._events_request_seq,
    )

    assert not window.is_live_refresh_active
    assert "expired or invalid" in window.events_view._banner_msg.text()
    window.close()


def test_main_window_processes_error_401_stops_live_refresh(
    qapp: QApplication,
) -> None:
    """AuthenticationError during process load stops live refresh timer."""
    window = MainWindow()
    window._shell.navigate_to("Processes")
    window._refresh_timer.start(5000)
    assert window.is_live_refresh_active

    window._on_processes_error(
        AuthenticationError("Session expired"),
        seq=window._processes_request_seq,
    )

    assert not window.is_live_refresh_active
    assert "expired or invalid" in window.processes_view._banner_msg.text()
    window.close()


def test_main_window_retry_button_triggers_status_and_view_refresh(
    qapp: QApplication,
) -> None:
    """Clicking banner retry button triggers check_operational_status and view."""
    window = MainWindow()
    mock_client = MagicMock(spec=APIClient)
    window._client = mock_client
    window._shell.navigate_to("Events")

    checked: list[str] = []
    window.check_operational_status = lambda: checked.append("status")  # type: ignore[method-assign]
    window.load_events = lambda *a, **k: checked.append("events")  # type: ignore[method-assign]

    window._shell.error_banner.retry_button.click()
    assert "status" in checked
    assert "events" in checked
    window.close()


# ==============================================================================
# 6. Error Sanitization Formats
# ==============================================================================


def test_error_sanitizers_format_all_exception_types() -> None:
    """Sanitizers return readable, safe strings for 404, 5xx, and network errors."""
    sanitizers = [
        MainWindow._sanitize_event_error,
        MainWindow._sanitize_process_error,
        MainWindow._sanitize_resource_error,
        MainWindow._sanitize_file_error,
    ]

    for sanitize in sanitizers:
        not_found = sanitize(NotFoundError("Resource missing", status_code=404))
        assert "404" in not_found
        assert "Resource missing" in not_found

        server_err = sanitize(ServerError("Internal failure", status_code=500))
        assert "500" in server_err
        assert "Internal failure" in server_err

        net_err = sanitize(ClientConnectionError("Network drop"))
        assert "Unable to connect" in net_err

        timeout_err = sanitize(ConnectionTimeoutError("Timed out"))
        assert "timed out" in timeout_err.lower()

        auth_err = sanitize(AuthenticationError("Bad credentials"))
        assert "expired or invalid" in auth_err.lower()

        val_err = sanitize(ValidationError("Corrupt field"))
        assert "Invalid" in val_err


# ==============================================================================
# 7. Safe Window Closure with Active Errors
# ==============================================================================


def test_main_window_close_with_active_error_banner(
    qapp: QApplication,
) -> None:
    """Closing MainWindow while error banner is active closes cleanly."""
    window = MainWindow()
    window.shell.show_connection_error("Fatal connection drop")
    assert window.shell.error_banner.is_visible

    window.close()
    assert not window.isVisible()
