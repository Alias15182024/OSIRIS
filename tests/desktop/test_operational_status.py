"""Tests for asynchronous API health and operational system status integration.

Validates the background worker execution, independent endpoint handling,
truthful UI representation, and safe shutdown lifecycle.
"""

from __future__ import annotations

import time
from dataclasses import FrozenInstanceError
from unittest.mock import MagicMock

import httpx
import pytest
import respx
from PySide6.QtCore import QThread, QThreadPool
from PySide6.QtWidgets import QApplication

from desktop.client.api_client import APIClient
from desktop.client.exceptions import ClientConnectionError, HTTPResponseError
from desktop.client.models import HealthStatus, SystemStatus, User
from desktop.ui.app_shell import AppShell
from desktop.ui.main_window import (
    MainWindow,
    OperationalStatusResult,
    fetch_operational_status,
)
from desktop.workers.api_worker import ApiWorker


def _sample_user() -> User:
    """Return a representative authenticated User for tests."""
    return User(
        id="usr-operational-001",
        username="sec_analyst",
        display_name="Security Analyst",
        role="analyst",
        is_active=True,
        created_at="2026-01-01T00:00:00Z",
    )


# ==============================================================================
# 1. OperationalStatusResult Data Transfer Object
# ==============================================================================


def test_operational_status_result_defaults() -> None:
    """OperationalStatusResult defaults all attributes to None."""
    result = OperationalStatusResult()
    assert result.health is None
    assert result.health_error is None
    assert result.system_status is None
    assert result.status_error is None


def test_operational_status_result_immutability() -> None:
    """OperationalStatusResult is a frozen dataclass and prevents mutation."""
    result = OperationalStatusResult()
    with pytest.raises(FrozenInstanceError):
        result.health = HealthStatus(status="ok", system="osiris")  # type: ignore[misc]


# ==============================================================================
# 2. Worker Task Callable: fetch_operational_status
# ==============================================================================


def test_fetch_operational_status_both_succeed() -> None:
    """When both endpoints succeed, result contains both models with no errors."""
    client = MagicMock(spec=APIClient)
    expected_health = HealthStatus(status="ok", system="osiris")
    expected_status = SystemStatus(
        status="healthy",
        system="osiris",
        database="connected",
        host_id="srv-node-1",
    )
    client.health_check.return_value = expected_health
    client.get_status.return_value = expected_status

    result = fetch_operational_status(client)

    assert result.health == expected_health
    assert result.health_error is None
    assert result.system_status == expected_status
    assert result.status_error is None
    client.health_check.assert_called_once()
    client.get_status.assert_called_once()


def test_fetch_operational_status_health_fails_status_succeeds() -> None:
    """Health failure does not suppress successful system status check."""
    client = MagicMock(spec=APIClient)
    client.health_check.side_effect = ClientConnectionError("Connection refused")
    expected_status = SystemStatus(
        status="healthy",
        system="osiris",
        database="connected",
        host_id="srv-node-1",
    )
    client.get_status.return_value = expected_status

    result = fetch_operational_status(client)

    assert result.health is None
    assert result.health_error is not None
    assert "Connection refused" in result.health_error
    assert result.system_status == expected_status
    assert result.status_error is None


def test_fetch_operational_status_health_succeeds_status_fails() -> None:
    """System status failure does not suppress successful health check."""
    client = MagicMock(spec=APIClient)
    expected_health = HealthStatus(status="ok", system="osiris")
    client.health_check.return_value = expected_health
    client.get_status.side_effect = HTTPResponseError("500 Internal Server Error", 500)

    result = fetch_operational_status(client)

    assert result.health == expected_health
    assert result.health_error is None
    assert result.system_status is None
    assert result.status_error is not None
    assert "500" in result.status_error


def test_fetch_operational_status_both_fail() -> None:
    """When both endpoints fail, both errors are captured independently."""
    client = MagicMock(spec=APIClient)
    client.health_check.side_effect = ClientConnectionError("Network unreachable")
    client.get_status.side_effect = ClientConnectionError("Network unreachable")

    result = fetch_operational_status(client)

    assert result.health is None
    assert result.health_error is not None
    assert "Network unreachable" in result.health_error
    assert result.system_status is None
    assert result.status_error is not None
    assert "Network unreachable" in result.status_error


# ==============================================================================
# 3. Off-GUI Thread Worker Execution
# ==============================================================================


def test_worker_executes_off_gui_thread(qapp: QApplication) -> None:
    """ApiWorker executing fetch_operational_status runs in a background thread."""
    main_thread = qapp.thread()
    worker_threads: list[QThread] = []

    def task(c: APIClient) -> OperationalStatusResult:
        worker_threads.append(QThread.currentThread())
        return fetch_operational_status(c)

    client = MagicMock(spec=APIClient)
    client.health_check.return_value = HealthStatus(status="ok", system="osiris")
    client.get_status.return_value = SystemStatus(
        status="healthy",
        system="osiris",
        database="connected",
        host_id="srv-1",
    )

    worker = ApiWorker(task, client)
    QThreadPool.globalInstance().start(worker)
    QThreadPool.globalInstance().waitForDone(2000)
    qapp.processEvents()

    assert len(worker_threads) == 1
    assert worker_threads[0] is not main_thread


# ==============================================================================
# 4. AppShell Status Presentation & Truthfulness
# ==============================================================================


def test_app_shell_initial_status_labels_with_user(qapp: QApplication) -> None:
    """AppShell initialized with an authenticated user has honest unknown states."""
    shell = AppShell(user=_sample_user())

    assert shell.status_api_label.text() == "API: Unknown"
    assert shell.status_api_label.property("apiState") == "unknown"

    assert shell.status_system_label.text() == "System: Unknown"
    assert shell.status_system_label.property("systemState") == "unknown"

    assert shell.status_database_label.text() == "Database: Unknown"
    assert shell.status_database_label.property("dbState") == "unknown"

    assert shell.check_status_button.isEnabled() is True
    assert shell.check_status_button.text() == "Check Status"


def test_app_shell_set_status_checking_state(qapp: QApplication) -> None:
    """set_status_checking updates all three labels and disables the button."""
    shell = AppShell(user=_sample_user())
    shell.set_status_checking()

    assert shell.check_status_button.isEnabled() is False
    assert shell.check_status_button.text() == "Checking..."

    assert shell.status_api_label.text() == "API: Checking..."
    assert shell.status_api_label.property("apiState") == "checking"

    assert shell.status_system_label.text() == "System: Checking..."
    assert shell.status_system_label.property("systemState") == "checking"

    assert shell.status_database_label.text() == "Database: Checking..."
    assert shell.status_database_label.property("dbState") == "checking"


def test_app_shell_apply_reachable_healthy_connected(qapp: QApplication) -> None:
    """AppShell accurately shows reachable API, healthy system, connected DB."""
    shell = AppShell(user=_sample_user())
    shell.apply_operational_status(
        health=HealthStatus(status="ok", system="osiris"),
        health_error=None,
        system=SystemStatus(
            status="healthy",
            system="osiris",
            database="connected",
            host_id="node-alpha",
        ),
        system_error=None,
    )

    assert shell.status_api_label.text() == "API: Reachable"
    assert shell.status_api_label.property("apiState") == "reachable"

    assert shell.status_system_label.text() == "System: Healthy"
    assert shell.status_system_label.property("systemState") == "healthy"

    assert shell.status_database_label.text() == "Database: Connected"
    assert shell.status_database_label.property("dbState") == "connected"


def test_app_shell_apply_reachable_degraded_disconnected(qapp: QApplication) -> None:
    """API reachable does NOT imply database connected (independent status)."""
    shell = AppShell(user=_sample_user())
    shell.apply_operational_status(
        health=HealthStatus(status="ok", system="osiris"),
        health_error=None,
        system=SystemStatus(
            status="degraded",
            system="osiris",
            database="disconnected",
            host_id="node-beta",
        ),
        system_error=None,
    )

    assert shell.status_api_label.text() == "API: Reachable"
    assert shell.status_api_label.property("apiState") == "reachable"

    assert shell.status_system_label.text() == "System: Degraded"
    assert shell.status_system_label.property("systemState") == "degraded"

    assert shell.status_database_label.text() == "Database: Disconnected"
    assert shell.status_database_label.property("dbState") == "disconnected"


def test_app_shell_apply_unavailable_states(qapp: QApplication) -> None:
    """Failed status check accurately marks components unavailable."""
    shell = AppShell(user=_sample_user())
    shell.apply_operational_status(
        health=None,
        health_error="Connection refused",
        system=None,
        system_error="503 Service Unavailable",
    )

    assert shell.status_api_label.text() == "API: Unavailable"
    assert shell.status_api_label.property("apiState") == "unavailable"

    assert shell.status_system_label.text() == "System: Unavailable"
    assert shell.status_system_label.property("systemState") == "unavailable"

    assert shell.status_database_label.text() == "Database: Unavailable"
    assert shell.status_database_label.property("dbState") == "unavailable"


# ==============================================================================
# 5. End-to-End Integration with Real APIClient & respx Mock
# ==============================================================================


@respx.mock
def test_main_window_operational_status_check_e2e_healthy(
    qapp: QApplication,
) -> None:
    """MainWindow completes operational check against mocked endpoints."""
    respx.get("http://localhost:8000/health").respond(
        status_code=200,
        json={"status": "ok", "system": "osiris"},
    )
    respx.get("http://localhost:8000/api/status").respond(
        status_code=200,
        json={
            "status": "healthy",
            "system": "osiris",
            "database": "connected",
            "host_id": "integration-host-1",
        },
    )

    client = APIClient(base_url="http://localhost:8000")
    window = MainWindow(client=client, user=_sample_user())

    window.check_operational_status()
    assert window.is_checking_status is True

    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    assert window.is_checking_status is False
    assert window.shell.status_api_label.text() == "API: Reachable"
    assert window.shell.status_system_label.text() == "System: Healthy"
    assert window.shell.status_database_label.text() == "Database: Connected"
    assert window.shell.check_status_button.isEnabled() is True
    client.close()


@respx.mock
def test_main_window_operational_status_degraded_database(
    qapp: QApplication,
) -> None:
    """MainWindow displays API reachable but database disconnected."""
    respx.get("http://localhost:8000/health").respond(
        status_code=200,
        json={"status": "ok", "system": "osiris"},
    )
    respx.get("http://localhost:8000/api/status").respond(
        status_code=200,
        json={
            "status": "degraded",
            "system": "osiris",
            "database": "disconnected",
            "host_id": "integration-host-2",
        },
    )

    client = APIClient(base_url="http://localhost:8000")
    window = MainWindow(client=client, user=_sample_user())

    window.check_operational_status()
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    assert window.shell.status_api_label.text() == "API: Reachable"
    assert window.shell.status_system_label.text() == "System: Degraded"
    assert window.shell.status_database_label.text() == "Database: Disconnected"
    client.close()


@respx.mock
def test_main_window_operational_status_backend_down(
    qapp: QApplication,
) -> None:
    """MainWindow displays unavailable status when backend is unreachable."""
    respx.get("http://localhost:8000/health").mock(
        side_effect=httpx.ConnectError("Connection refused")
    )
    respx.get("http://localhost:8000/api/status").mock(
        side_effect=httpx.ConnectError("Connection refused")
    )

    client = APIClient(base_url="http://localhost:8000")
    window = MainWindow(client=client, user=_sample_user())

    window.check_operational_status()
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    assert window.shell.status_api_label.text() == "API: Unavailable"
    assert window.shell.status_system_label.text() == "System: Unavailable"
    assert window.shell.status_database_label.text() == "Database: Unavailable"
    client.close()


@respx.mock
def test_main_window_manual_retry_after_failure(
    qapp: QApplication,
) -> None:
    """User can retry manually via Check Status button after an initial failure."""
    health_route = respx.get("http://localhost:8000/health")
    status_route = respx.get("http://localhost:8000/api/status")

    # First attempt: connection fails
    health_route.mock(side_effect=httpx.ConnectError("Offline"))
    status_route.mock(side_effect=httpx.ConnectError("Offline"))

    client = APIClient(base_url="http://localhost:8000")
    window = MainWindow(client=client, user=_sample_user())

    window.check_operational_status()
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    assert window.shell.status_api_label.text() == "API: Unavailable"
    assert window.shell.check_status_button.isEnabled() is True

    # Second attempt: backend recovers
    health_route.mock(
        return_value=httpx.Response(200, json={"status": "ok", "system": "osiris"})
    )
    status_route.mock(
        return_value=httpx.Response(
            200,
            json={
                "status": "healthy",
                "system": "osiris",
                "database": "connected",
                "host_id": "host-recovered",
            },
        )
    )

    # Click Check Status button to retry
    window.shell.check_status_button.click()
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    assert window.shell.status_api_label.text() == "API: Reachable"
    assert window.shell.status_system_label.text() == "System: Healthy"
    assert window.shell.status_database_label.text() == "Database: Connected"
    client.close()


def test_main_window_duplicate_check_suppressed(qapp: QApplication) -> None:
    """Duplicate concurrent check requests are safely ignored."""
    client = MagicMock(spec=APIClient)

    def slow_health() -> HealthStatus:
        time.sleep(0.05)
        return HealthStatus(status="ok", system="osiris")

    client.health_check.side_effect = slow_health
    client.get_status.return_value = SystemStatus(
        status="healthy", system="osiris", database="connected", host_id="test"
    )

    window = MainWindow(client=client, user=_sample_user())

    window.check_operational_status()
    assert window.is_checking_status is True

    # Immediate second call must be ignored
    window.check_operational_status()
    assert window.is_checking_status is True

    QThreadPool.globalInstance().waitForDone(2000)
    qapp.processEvents()

    # Health check should only have been invoked once
    assert client.health_check.call_count == 1


# ==============================================================================
# 6. Shutdown and Logout Lifecycle Safety
# ==============================================================================


def test_main_window_logout_during_active_status_check(
    qapp: QApplication,
) -> None:
    """Logging out while check is active clears token immediately and defers close."""
    client = MagicMock(spec=APIClient)

    def slow_health() -> HealthStatus:
        time.sleep(0.05)
        return HealthStatus(status="ok", system="osiris")

    client.health_check.side_effect = slow_health
    client.get_status.return_value = SystemStatus(
        status="healthy", system="osiris", database="connected", host_id="test"
    )

    window = MainWindow(client=client, user=_sample_user())
    window.show()
    assert window.isVisible() is True

    # Start status check
    window.check_operational_status()
    assert window.is_checking_status is True

    emitted_logout: list[bool] = []
    window.logout_requested.connect(lambda: emitted_logout.append(True))

    # User clicks logout while check is running
    window.shell.logout_button.click()

    # 1. Token must be cleared immediately
    client.logout.assert_called_once()
    # 2. Logout signal emitted
    assert emitted_logout == [True]
    # 3. Window is hidden immediately from user
    assert window.isVisible() is False
    # 4. Window close is pending until worker thread finishes
    assert window._pending_close is True

    # Allow worker thread to finish
    QThreadPool.globalInstance().waitForDone(2000)
    qapp.processEvents()

    assert window.is_checking_status is False
