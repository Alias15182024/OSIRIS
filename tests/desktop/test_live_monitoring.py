"""Tests for OSIRIS Phase 1.7K View-Aware Live Monitoring.

Verifies:
- LiveRefreshTimer lifecycle: active on refreshable views, stopped on Overview.
- View transition deactivation and active target switching.
- Signal dispatch and zero polling for background/hidden views.
- In-flight request protection (tick skipping).
- Preservation of query filters and pagination offset across ticks.
- Manual refresh and query application timer reset (cooldown).
- Logout, close, and session lifecycle coordination.
- Configurable refresh interval validation and update behavior.
- Resilient recovery on subsequent periodic ticks following errors.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from PySide6.QtCore import QThreadPool, QTimer
from PySide6.QtWidgets import QApplication, QLabel

from desktop.client.api_client import APIClient
from desktop.client.exceptions import ClientConnectionError
from desktop.client.models import (
    EventCollection,
    FileCollection,
    ProcessCollection,
    ResourceSnapshotCollection,
    User,
)
from desktop.ui.main_window import (
    DEFAULT_LIVE_REFRESH_INTERVAL_MS,
    MainWindow,
)
from desktop.ui.views.events_view import EventsQuery
from desktop.ui.views.files_view import FilesQuery
from desktop.ui.views.processes_view import ProcessesQuery
from desktop.ui.views.resources_view import ResourcesQuery


def _sample_user() -> User:
    """Return a representative authenticated User instance for tests."""
    return User(
        id="usr-test-1",
        username="secops_analyst",
        display_name="SecOps Analyst",
        role="analyst",
        is_active=True,
        created_at="2026-01-01T00:00:00Z",
    )


def _mock_client() -> MagicMock:
    """Return an APIClient mock returning typed collections for all views."""
    client = MagicMock(spec=APIClient)
    client.get_events.return_value = EventCollection(
        total=0, items=(), limit=50, offset=0
    )
    client.get_processes.return_value = ProcessCollection(
        total=0, items=(), limit=50, offset=0
    )
    client.get_resources.return_value = ResourceSnapshotCollection(
        total=0, items=(), limit=50, offset=0
    )
    client.get_files.return_value = FileCollection(
        total=0, items=(), limit=50, offset=0
    )
    return client


def test_timer_initial_state_on_overview(qapp: QApplication) -> None:
    """LiveRefreshTimer is instantiated but inactive on initial Overview page."""
    client = _mock_client()
    user = _sample_user()
    window = MainWindow(client=client, user=user)

    assert window.refresh_timer is not None
    assert isinstance(window.refresh_timer, QTimer)
    assert window.refresh_timer.objectName() == "LiveRefreshTimer"
    assert window.refresh_interval_ms == DEFAULT_LIVE_REFRESH_INTERVAL_MS
    assert window.is_live_refresh_active is False
    assert window.shell.current_page_name == "Overview"
    assert window.events_view.is_active is False
    assert window.processes_view.is_active is False
    assert window.resources_view.is_active is False
    assert window.files_view.is_active is False


@pytest.mark.parametrize("page_name", ["Events", "Processes", "Resources", "Files"])
def test_timer_activates_on_entering_refreshable_view(
    qapp: QApplication, page_name: str
) -> None:
    """Entering any refreshable view activates the live monitoring timer."""
    client = _mock_client()
    user = _sample_user()
    window = MainWindow(client=client, user=user)

    window.shell.navigate_to(page_name)
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    assert window.shell.current_page_name == page_name
    assert window.is_live_refresh_active is True
    assert window.refresh_timer.isActive() is True


def test_timer_deactivates_on_entering_overview(qapp: QApplication) -> None:
    """Navigating from a refreshable view to Overview stops the timer."""
    client = _mock_client()
    user = _sample_user()
    window = MainWindow(client=client, user=user)

    window.shell.navigate_to("Events")
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()
    assert window.is_live_refresh_active is True

    window.shell.navigate_to("Overview")
    assert window.shell.current_page_name == "Overview"
    assert window.is_live_refresh_active is False


def test_view_transition_updates_active_properties(qapp: QApplication) -> None:
    """Switching views updates view is_active properties correctly."""
    client = _mock_client()
    user = _sample_user()
    window = MainWindow(client=client, user=user)

    assert window.events_view.is_active is False
    assert window.processes_view.is_active is False

    window.shell.navigate_to("Events")
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()
    assert window.events_view.is_active is True
    assert window.processes_view.is_active is False

    window.shell.navigate_to("Processes")
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()
    assert window.events_view.is_active is False
    assert window.processes_view.is_active is True

    window.shell.navigate_to("Resources")
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()
    assert window.processes_view.is_active is False
    assert window.resources_view.is_active is True

    window.shell.navigate_to("Files")
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()
    assert window.resources_view.is_active is False
    assert window.files_view.is_active is True

    window.shell.navigate_to("Overview")
    assert window.files_view.is_active is False


def test_live_refresh_tick_refreshes_events_when_active(
    qapp: QApplication,
) -> None:
    """A timer tick while on Events view triggers load_events."""
    client = _mock_client()
    user = _sample_user()
    window = MainWindow(client=client, user=user)

    window.shell.navigate_to("Events")
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()
    client.get_events.reset_mock()

    # Trigger timer tick
    window.refresh_timer.timeout.emit()
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    client.get_events.assert_called_once()
    assert client.get_processes.call_count == 0
    assert client.get_resources.call_count == 0
    assert client.get_files.call_count == 0


def test_live_refresh_tick_refreshes_processes_when_active(
    qapp: QApplication,
) -> None:
    """A timer tick while on Processes view triggers load_processes."""
    client = _mock_client()
    user = _sample_user()
    window = MainWindow(client=client, user=user)

    window.shell.navigate_to("Processes")
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()
    client.get_processes.reset_mock()

    # Trigger timer tick
    window.refresh_timer.timeout.emit()
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    client.get_processes.assert_called_once()
    assert client.get_events.call_count == 0
    assert client.get_resources.call_count == 0
    assert client.get_files.call_count == 0


def test_live_refresh_tick_refreshes_resources_when_active(
    qapp: QApplication,
) -> None:
    """A timer tick while on Resources view triggers load_resources."""
    client = _mock_client()
    user = _sample_user()
    window = MainWindow(client=client, user=user)

    window.shell.navigate_to("Resources")
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()
    client.get_resources.reset_mock()

    # Trigger timer tick
    window.refresh_timer.timeout.emit()
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    client.get_resources.assert_called_once()
    assert client.get_events.call_count == 0
    assert client.get_processes.call_count == 0
    assert client.get_files.call_count == 0


def test_live_refresh_tick_refreshes_files_when_active(
    qapp: QApplication,
) -> None:
    """A timer tick while on Files view triggers load_files."""
    client = _mock_client()
    user = _sample_user()
    window = MainWindow(client=client, user=user)

    window.shell.navigate_to("Files")
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()
    client.get_files.reset_mock()

    # Trigger timer tick
    window.refresh_timer.timeout.emit()
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    client.get_files.assert_called_once()
    assert client.get_events.call_count == 0
    assert client.get_processes.call_count == 0
    assert client.get_resources.call_count == 0


def test_zero_requests_for_hidden_views_across_page_switches(
    qapp: QApplication,
) -> None:
    """Switching active views leaves background views completely idle."""
    client = _mock_client()
    user = _sample_user()
    window = MainWindow(client=client, user=user)

    # Go to Events
    window.shell.navigate_to("Events")
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()
    client.get_events.reset_mock()

    # Switch to Processes
    window.shell.navigate_to("Processes")
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()
    client.get_processes.reset_mock()

    # Timer ticks while on Processes
    window.refresh_timer.timeout.emit()
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    # Only processes called, events received zero requests
    assert client.get_processes.call_count == 1
    assert client.get_events.call_count == 0


def test_in_flight_request_skips_timer_tick(qapp: QApplication) -> None:
    """A timer tick is safely skipped if an async request is already in flight."""
    client = _mock_client()
    user = _sample_user()
    window = MainWindow(client=client, user=user)

    window.shell.navigate_to("Events")
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    # Simulate in-flight loading flag
    window._is_loading_events = True

    refresh_spy: list[bool] = []
    window.events_view.refresh_requested.connect(lambda: refresh_spy.append(True))

    # Trigger timer tick
    window.refresh_timer.timeout.emit()

    # Nothing emitted because request was in flight
    assert len(refresh_spy) == 0


def test_query_and_pagination_preserved_during_events_live_refresh(
    qapp: QApplication,
) -> None:
    """Events filter and pagination offset are preserved on periodic tick."""
    client = _mock_client()
    client.get_events.return_value = EventCollection(
        total=100, items=(), limit=25, offset=50
    )
    user = _sample_user()
    window = MainWindow(client=client, user=user)

    window.shell.navigate_to("Events")
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    custom_query = EventsQuery(severity="critical", limit=25, offset=50)
    window.load_events(custom_query)
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()
    client.get_events.reset_mock()

    # Timer tick occurs
    window.refresh_timer.timeout.emit()
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    client.get_events.assert_called_once_with(
        severity="critical",
        limit=25,
        offset=50,
    )


def test_query_and_pagination_preserved_during_processes_live_refresh(
    qapp: QApplication,
) -> None:
    """Processes filter and pagination offset are preserved on periodic tick."""
    client = _mock_client()
    client.get_processes.return_value = ProcessCollection(
        total=50, items=(), limit=10, offset=20
    )
    user = _sample_user()
    window = MainWindow(client=client, user=user)

    window.shell.navigate_to("Processes")
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    custom_query = ProcessesQuery(pid=1024, is_active=True, limit=10, offset=20)
    window.load_processes(custom_query)
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()
    client.get_processes.reset_mock()

    window.refresh_timer.timeout.emit()
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    client.get_processes.assert_called_once_with(
        pid=1024,
        is_active=True,
        limit=10,
        offset=20,
    )


def test_query_and_pagination_preserved_during_resources_live_refresh(
    qapp: QApplication,
) -> None:
    """Resources filter and pagination offset are preserved on periodic tick."""
    client = _mock_client()
    client.get_resources.return_value = ResourceSnapshotCollection(
        total=30, items=(), limit=15, offset=15
    )
    user = _sample_user()
    window = MainWindow(client=client, user=user)

    window.shell.navigate_to("Resources")
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    host_uuid = "12345678-1234-5678-1234-567812345678"
    custom_query = ResourcesQuery(host_id=host_uuid, limit=15, offset=15)
    window.load_resources(custom_query)
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()
    client.get_resources.reset_mock()

    window.refresh_timer.timeout.emit()
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    client.get_resources.assert_called_once_with(
        host_id=host_uuid,
        limit=15,
        offset=15,
    )


def test_query_and_pagination_preserved_during_files_live_refresh(
    qapp: QApplication,
) -> None:
    """Files filter and pagination offset are preserved on periodic tick."""
    client = _mock_client()
    client.get_files.return_value = FileCollection(
        total=40, items=(), limit=20, offset=20
    )
    user = _sample_user()
    window = MainWindow(client=client, user=user)

    window.shell.navigate_to("Files")
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    custom_query = FilesQuery(file_type="file", limit=20, offset=20)
    window.load_files(custom_query)
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()
    client.get_files.reset_mock()

    window.refresh_timer.timeout.emit()
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    client.get_files.assert_called_once_with(
        file_type="file",
        limit=20,
        offset=20,
    )


def test_manual_load_restarts_refresh_timer_countdown(
    qapp: QApplication,
) -> None:
    """Executing a manual load restarts the refresh timer to avoid rapid overlap."""
    client = _mock_client()
    user = _sample_user()
    window = MainWindow(client=client, user=user)

    window.shell.navigate_to("Events")
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()
    assert window.refresh_timer.isActive() is True

    # Call load_events manually (e.g. user clicked refresh or applied filter)
    window.load_events()
    assert window.refresh_timer.isActive() is True
    # Timer was restarted with refresh_interval_ms
    assert window.refresh_timer.interval() == DEFAULT_LIVE_REFRESH_INTERVAL_MS


def test_logout_stops_live_monitoring_timer(qapp: QApplication) -> None:
    """Logging out stops the live monitoring timer."""
    client = _mock_client()
    user = _sample_user()
    window = MainWindow(client=client, user=user)

    window.shell.navigate_to("Events")
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()
    assert window.is_live_refresh_active is True

    window._handle_logout()
    assert window.is_live_refresh_active is False
    assert window.refresh_timer.isActive() is False


def test_close_event_stops_live_monitoring_timer(qapp: QApplication) -> None:
    """Closing the window stops the live monitoring timer."""
    client = _mock_client()
    user = _sample_user()
    window = MainWindow(client=client, user=user)

    window.shell.navigate_to("Processes")
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()
    assert window.is_live_refresh_active is True

    window.close()
    assert window.is_live_refresh_active is False


def test_session_lifecycle_with_set_session(qapp: QApplication) -> None:
    """set_session dynamically activates or deactivates the live timer."""
    # Window created without client
    window = MainWindow(client=None)
    window.shell.navigate_to("Events")
    assert window.is_live_refresh_active is False

    # Injected authenticated session
    client = _mock_client()
    user = _sample_user()
    window.set_session(client, user)
    assert window.is_live_refresh_active is True
    assert window.client is client
    assert window.user is user

    # Clear session
    window.set_session(None, None)
    assert window.is_live_refresh_active is False


def test_configurable_refresh_interval(qapp: QApplication) -> None:
    """refresh_interval_ms can be configured via constructor and property setter."""
    client = _mock_client()
    user = _sample_user()

    # Custom interval in constructor
    window = MainWindow(client=client, user=user, refresh_interval_ms=10000)
    assert window.refresh_interval_ms == 10000

    window.shell.navigate_to("Resources")
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()
    assert window.refresh_timer.interval() == 10000

    # Update via property setter while running
    window.refresh_interval_ms = 3000
    assert window.refresh_interval_ms == 3000
    assert window.refresh_timer.interval() == 3000

    # Negative or zero rejected
    with pytest.raises(ValueError, match="positive integer"):
        window.refresh_interval_ms = 0

    with pytest.raises(ValueError, match="positive integer"):
        window.refresh_interval_ms = -500


def test_transient_error_preserves_data_and_retries_on_next_tick(
    qapp: QApplication,
) -> None:
    """A transient error during periodic refresh retains data and retries next tick."""
    client = _mock_client()
    initial_events = EventCollection(total=1, items=(), limit=50, offset=0)
    client.get_events.return_value = initial_events
    user = _sample_user()
    window = MainWindow(client=client, user=user)

    window.shell.navigate_to("Events")
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    # First load was successful
    assert window.events_view.state == "empty"
    assert window.is_live_refresh_active is True

    # Next tick fails with a transient connection error
    client.get_events.side_effect = ClientConnectionError("Connection dropped")
    window.refresh_timer.timeout.emit()
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    # Error banner shown, timer remains active for subsequent recovery
    assert window.events_view.state == "failed"
    banner_lbl = window.events_view.findChild(QLabel, "EventsStatusBannerMessage")
    assert banner_lbl is not None
    assert "Unable to connect" in banner_lbl.text()
    assert window.is_live_refresh_active is True

    # Next tick succeeds
    client.get_events.side_effect = None
    recovered_events = EventCollection(total=2, items=(), limit=50, offset=0)
    client.get_events.return_value = recovered_events

    window.refresh_timer.timeout.emit()
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    assert window.events_view.state == "empty"
    assert window.events_view.model.total_count == 2
