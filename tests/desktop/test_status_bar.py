"""Unit and integration tests for the OSIRIS native Qt StatusBar component.

Validates:
1. StatusBar construction, object hierarchy, and styling properties.
2. Initial visual prototype and authenticated session states.
3. Checking state indicator updates.
4. Healthy, degraded, disconnected, and partial failure presentations.
5. Flicker-free updates and timestamp formatting.
6. User transition and clear behavior.
7. Integration with AppShell and forwarding properties.
8. MainWindow 15-second status polling timer, lifecycle, and view independence.
9. Non-overlapping status check and request sequence protection.
10. APIClient get_health alias.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
import respx
from PySide6.QtCore import QThreadPool
from PySide6.QtWidgets import QApplication, QFrame

from desktop.client.api_client import APIClient
from desktop.client.models import HealthStatus, SystemStatus, User
from desktop.ui.app_shell import AppShell
from desktop.ui.components.status_bar import StatusBar
from desktop.ui.design_tokens import STATUS_BAR_HEIGHT
from desktop.ui.main_window import (
    DEFAULT_STATUS_POLL_INTERVAL_MS,
    MainWindow,
)


def _sample_user() -> User:
    """Return a representative authenticated User for tests."""
    return User(
        id="usr-status-bar-001",
        username="lead_analyst",
        display_name="Lead Analyst",
        role="analyst",
        is_active=True,
        created_at="2026-01-01T00:00:00Z",
    )


# ==============================================================================
# 1. StatusBar Construction & Hierarchy
# ==============================================================================


def test_status_bar_construction_and_hierarchy(qapp: QApplication) -> None:
    """StatusBar is a QFrame with object name BottomStatusBar and child labels."""
    bar = StatusBar()
    assert isinstance(bar, QFrame)
    assert bar.objectName() == "BottomStatusBar"
    assert bar.height() == STATUS_BAR_HEIGHT

    # Check child labels exist with expected object names
    assert bar.mode_label.objectName() == "StatusModeLabel"
    assert bar.api_label.objectName() == "StatusApiLabel"
    assert bar.system_label.objectName() == "StatusSystemLabel"
    assert bar.database_label.objectName() == "StatusDatabaseLabel"
    assert bar.last_updated_label.objectName() == "StatusLastUpdatedLabel"
    assert bar.security_notice.objectName() == "StatusSecurityNotice"


def test_status_bar_initial_prototype_state(qapp: QApplication) -> None:
    """Without an authenticated user, StatusBar reflects visual prototype mode."""
    bar = StatusBar(user=None)
    assert bar.mode_label.text() == "Mode: Visual Prototype"
    assert bar.api_label.text() == "API: Disconnected (Integration Pending)"
    assert bar.api_label.property("apiState") == "disconnected"
    assert bar.system_label.text() == "System: Offline (Preview)"
    assert bar.system_label.property("systemState") == "offline"
    assert bar.database_label.text() == "Database: Offline (Preview)"
    assert bar.database_label.property("dbState") == "offline"
    assert bar.last_updated_label.text() == "Updated: Never"
    assert bar.last_updated_time is None
    assert "Standalone Prototype" in bar.security_notice.text()


def test_status_bar_initial_authenticated_state(qapp: QApplication) -> None:
    """With an authenticated user, StatusBar reflects authenticated session mode."""
    bar = StatusBar(user=_sample_user())
    assert bar.mode_label.text() == "Mode: Authenticated Session"
    assert bar.api_label.text() == "API: Unknown"
    assert bar.api_label.property("apiState") == "unknown"
    assert bar.system_label.text() == "System: Unknown"
    assert bar.system_label.property("systemState") == "unknown"
    assert bar.database_label.text() == "Database: Unknown"
    assert bar.database_label.property("dbState") == "unknown"
    assert bar.last_updated_label.text() == "Updated: Never"
    assert "Session authenticated" in bar.security_notice.text()


# ==============================================================================
# 2. State Indicator Transitions
# ==============================================================================


def test_status_bar_set_checking(qapp: QApplication) -> None:
    """set_checking updates API, System, and Database labels to checking state."""
    bar = StatusBar(user=_sample_user())
    bar.set_checking()

    assert bar.api_label.text() == "API: Checking..."
    assert bar.api_label.property("apiState") == "checking"
    assert "Checking API" in bar.api_label.toolTip()

    assert bar.system_label.text() == "System: Checking..."
    assert bar.system_label.property("systemState") == "checking"
    assert "Checking backend system" in bar.system_label.toolTip()

    assert bar.database_label.text() == "Database: Checking..."
    assert bar.database_label.property("dbState") == "checking"
    assert "Checking database" in bar.database_label.toolTip()


def test_status_bar_apply_status_healthy(qapp: QApplication) -> None:
    """apply_status with healthy responses updates labels to fresh states."""
    bar = StatusBar(user=_sample_user())
    ts = datetime(2026, 10, 15, 14, 30, 0, tzinfo=timezone.utc)
    health = HealthStatus(status="ok", system="osiris")
    system = SystemStatus(
        status="healthy",
        system="osiris",
        database="connected",
        host_id="prod-host-1",
    )

    bar.apply_status(
        health=health,
        health_error=None,
        system=system,
        system_error=None,
        timestamp=ts,
    )

    assert bar.api_label.text() == "API: Reachable"
    assert bar.api_label.property("apiState") == "reachable"
    assert "API is reachable" in bar.api_label.toolTip()

    assert bar.system_label.text() == "System: Healthy"
    assert bar.system_label.property("systemState") == "healthy"
    assert "prod-host-1" in bar.system_label.toolTip()

    assert bar.database_label.text() == "Database: Connected"
    assert bar.database_label.property("dbState") == "connected"

    assert bar.last_updated_label.text() == "Updated: 14:30:00 UTC"
    assert bar.last_updated_time == ts


def test_status_bar_apply_status_degraded_database(qapp: QApplication) -> None:
    """apply_status reflects degraded system and disconnected database."""
    bar = StatusBar(user=_sample_user())
    health = HealthStatus(status="ok", system="osiris")
    system = SystemStatus(
        status="degraded",
        system="osiris",
        database="disconnected",
        host_id="prod-host-2",
    )

    bar.apply_status(
        health=health,
        health_error=None,
        system=system,
        system_error=None,
    )

    assert bar.api_label.text() == "API: Reachable"
    assert bar.api_label.property("apiState") == "reachable"

    assert bar.system_label.text() == "System: Degraded"
    assert bar.system_label.property("systemState") == "degraded"

    assert bar.database_label.text() == "Database: Disconnected"
    assert bar.database_label.property("dbState") == "disconnected"


def test_status_bar_apply_status_disconnected_backend(
    qapp: QApplication,
) -> None:
    """apply_status reflects disconnected backend when checks fail."""
    bar = StatusBar(user=_sample_user())
    bar.apply_status(
        health=None,
        health_error="Connection refused",
        system=None,
        system_error="Connection refused",
    )

    assert bar.api_label.text() == "API: Unavailable"
    assert bar.api_label.property("apiState") == "unavailable"
    assert "Connection refused" in bar.api_label.toolTip()

    assert bar.system_label.text() == "System: Unavailable"
    assert bar.system_label.property("systemState") == "unavailable"

    assert bar.database_label.text() == "Database: Unavailable"
    assert bar.database_label.property("dbState") == "unavailable"


def test_status_bar_apply_status_partial_failure(qapp: QApplication) -> None:
    """apply_status handles case where API health is ok but system status fails."""
    bar = StatusBar(user=_sample_user())
    health = HealthStatus(status="ok", system="osiris")

    bar.apply_status(
        health=health,
        health_error=None,
        system=None,
        system_error="500 Internal Server Error",
    )

    assert bar.api_label.text() == "API: Reachable"
    assert bar.api_label.property("apiState") == "reachable"

    assert bar.system_label.text() == "System: Unavailable"
    assert bar.system_label.property("systemState") == "unavailable"

    assert bar.database_label.text() == "Database: Unavailable"
    assert bar.database_label.property("dbState") == "unavailable"


def test_status_bar_flicker_free_duplicate_update(qapp: QApplication) -> None:
    """Repeated updates with identical data avoid unnecessary style changes."""
    bar = StatusBar(user=_sample_user())
    health = HealthStatus(status="ok", system="osiris")
    system = SystemStatus(
        status="healthy", system="osiris", database="connected", host_id="host"
    )

    bar.apply_status(health=health, health_error=None, system=system, system_error=None)
    prev_api_state = bar.api_label.property("apiState")

    # Second call with identical status
    bar.apply_status(health=health, health_error=None, system=system, system_error=None)
    assert bar.api_label.property("apiState") == prev_api_state
    assert bar.api_label.text() == "API: Reachable"


def test_status_bar_string_timestamp_formatting(qapp: QApplication) -> None:
    """apply_status correctly handles string timestamp argument."""
    bar = StatusBar(user=_sample_user())
    bar.apply_status(
        health=HealthStatus(status="ok", system="osiris"),
        health_error=None,
        system=None,
        system_error=None,
        timestamp="2026-10-15 12:00:00 UTC",
    )
    assert bar.last_updated_label.text() == "Updated: 2026-10-15 12:00:00 UTC"
    assert bar.last_updated_time == "2026-10-15 12:00:00 UTC"


def test_status_bar_user_transitions_and_clear(qapp: QApplication) -> None:
    """Transitions between user states and clear reset status appropriately."""
    bar = StatusBar(user=None)
    assert bar.mode_label.text() == "Mode: Visual Prototype"

    bar.set_user(_sample_user())
    assert bar.mode_label.text() == "Mode: Authenticated Session"

    bar.clear()
    assert bar.mode_label.text() == "Mode: Visual Prototype"
    assert bar.api_label.property("apiState") == "disconnected"
    assert bar.last_updated_label.text() == "Updated: Never"


# ==============================================================================
# 3. AppShell Integration
# ==============================================================================


def test_app_shell_status_bar_integration(qapp: QApplication) -> None:
    """AppShell embeds StatusBar and forwards properties seamlessly."""
    shell = AppShell(user=_sample_user())
    assert isinstance(shell.status_bar, StatusBar)
    assert shell.isAncestorOf(shell.status_bar) is True

    assert shell.status_api_label is shell.status_bar.api_label
    assert shell.status_system_label is shell.status_bar.system_label
    assert shell.status_database_label is shell.status_bar.database_label
    assert shell.status_mode_label is shell.status_bar.mode_label
    assert shell.status_security_notice is shell.status_bar.security_notice

    # apply_operational_status forwards to status_bar
    health = HealthStatus(status="ok", system="osiris")
    system = SystemStatus(
        status="healthy",
        system="osiris",
        database="connected",
        host_id="shell-host",
    )
    shell.apply_operational_status(
        health=health,
        health_error=None,
        system=system,
        system_error=None,
    )
    assert shell.status_api_label.text() == "API: Reachable"
    assert shell.status_system_label.text() == "System: Healthy"
    assert shell.status_database_label.text() == "Database: Connected"


def test_app_shell_set_status_checking_delegation(qapp: QApplication) -> None:
    """AppShell set_status_checking updates status_bar and button."""
    shell = AppShell(user=_sample_user())
    shell.set_status_checking()

    assert shell.check_status_button.isEnabled() is False
    assert shell.check_status_button.text() == "Checking..."
    assert shell.status_api_label.text() == "API: Checking..."
    assert shell.status_system_label.text() == "System: Checking..."
    assert shell.status_database_label.text() == "Database: Checking..."


# ==============================================================================
# 4. MainWindow Status Polling Timer & View Independence
# ==============================================================================


def test_main_window_status_poll_timer_defaults(qapp: QApplication) -> None:
    """MainWindow initializes status poll timer with 15000ms default interval."""
    window = MainWindow(client=None, user=None)
    assert window.status_poll_interval_ms == DEFAULT_STATUS_POLL_INTERVAL_MS
    assert window.status_poll_interval_ms == 15000
    assert window.status_poll_timer.objectName() == "StatusPollTimer"
    assert window.is_status_polling_active is False


def test_main_window_status_poll_interval_validation(
    qapp: QApplication,
) -> None:
    """status_poll_interval_ms setter validates positive integers."""
    window = MainWindow(client=None, user=None)
    window.status_poll_interval_ms = 30000
    assert window.status_poll_interval_ms == 30000

    with pytest.raises(ValueError, match="positive integer"):
        window.status_poll_interval_ms = 0

    with pytest.raises(ValueError, match="positive integer"):
        window.status_poll_interval_ms = -5000


@respx.mock
def test_main_window_status_poll_timer_starts_with_session(
    qapp: QApplication,
) -> None:
    """Setting an authenticated session starts status polling timer."""
    respx.get("http://localhost:8000/health").respond(
        status_code=200, json={"status": "ok", "system": "osiris"}
    )
    respx.get("http://localhost:8000/api/status").respond(
        status_code=200,
        json={
            "status": "healthy",
            "system": "osiris",
            "database": "connected",
            "host_id": "test-host",
        },
    )

    client = APIClient(base_url="http://localhost:8000")
    window = MainWindow(client=None, user=None)
    assert window.is_status_polling_active is False

    window.set_session(client=client, user=_sample_user())
    assert window.is_status_polling_active is True

    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    # Clearing session stops timer
    window.set_session(client=None, user=None)
    assert window.is_status_polling_active is False
    client.close()


@respx.mock
def test_main_window_status_polling_view_independence(
    qapp: QApplication,
) -> None:
    """Status polling timer remains active across Overview and data views."""
    respx.get("http://localhost:8000/health").respond(
        status_code=200, json={"status": "ok", "system": "osiris"}
    )
    respx.get("http://localhost:8000/api/status").respond(
        status_code=200,
        json={
            "status": "healthy",
            "system": "osiris",
            "database": "connected",
            "host_id": "test-host",
        },
    )

    client = APIClient(base_url="http://localhost:8000")
    window = MainWindow(client=client, user=_sample_user())
    window.start_status_polling()
    assert window.is_status_polling_active is True

    # Navigate to Overview (where live data refresh is inactive)
    window.shell.navigate_to("Overview")
    assert window.is_live_refresh_active is False
    assert window.is_status_polling_active is True

    # Navigate to Events (where live data refresh is active)
    window.shell.navigate_to("Events")
    assert window.is_live_refresh_active is True
    assert window.is_status_polling_active is True

    # Navigate to Processes
    window.shell.navigate_to("Processes")
    assert window.is_live_refresh_active is True
    assert window.is_status_polling_active is True

    # Navigate back to Overview
    window.shell.navigate_to("Overview")
    assert window.is_live_refresh_active is False
    assert window.is_status_polling_active is True

    client.close()


def test_main_window_status_polling_tick_non_overlapping(
    qapp: QApplication,
) -> None:
    """Timer tick suppresses duplicate status check when check is in flight."""
    client = MagicMock(spec=APIClient)
    window = MainWindow(client=client, user=_sample_user())
    window._is_checking_status = True

    # Trigger timer tick while checking is True
    window._on_status_poll_tick()

    # Should not have called health_check
    assert client.health_check.call_count == 0


@respx.mock
def test_main_window_status_stale_response_discarded(
    qapp: QApplication,
) -> None:
    """Superseded status check result does not overwrite newer result."""
    client = APIClient(base_url="http://localhost:8000")
    window = MainWindow(client=client, user=_sample_user())

    # Simulate sequence advancement
    window._status_request_seq = 5
    stale_result = MagicMock()
    stale_result.health = HealthStatus(status="ok", system="osiris")
    stale_result.health_error = None
    stale_result.system_status = SystemStatus(
        status="healthy",
        system="osiris",
        database="connected",
        host_id="stale",
    )
    stale_result.status_error = None
    stale_result.timestamp = None

    # Call result with stale seq 4
    window._on_status_result(stale_result, seq=4)

    # Status labels must not be updated to stale data
    assert window.shell.status_api_label.text() != "API: Reachable"
    client.close()


def test_main_window_logout_stops_status_poll_timer(
    qapp: QApplication,
) -> None:
    """Logging out stops the status polling timer."""
    client = MagicMock(spec=APIClient)
    window = MainWindow(client=client, user=_sample_user())
    window.start_status_polling()
    assert window.is_status_polling_active is True

    window._handle_logout()
    assert window.is_status_polling_active is False


def test_main_window_close_stops_status_poll_timer(
    qapp: QApplication,
) -> None:
    """Closing the window stops the status polling timer."""
    client = MagicMock(spec=APIClient)
    window = MainWindow(client=client, user=_sample_user())
    window.start_status_polling()
    assert window.is_status_polling_active is True

    window.close()
    assert window.is_status_polling_active is False


# ==============================================================================
# 5. APIClient get_health Alias Verification
# ==============================================================================


@respx.mock
def test_api_client_get_health_alias() -> None:
    """APIClient.get_health() is an alias for health_check()."""
    respx.get("http://localhost:8000/health").respond(
        status_code=200,
        json={"status": "ok", "system": "osiris"},
    )
    client = APIClient(base_url="http://localhost:8000")
    health = client.get_health()
    assert isinstance(health, HealthStatus)
    assert health.status == "ok"
    assert health.system == "osiris"
    client.close()
