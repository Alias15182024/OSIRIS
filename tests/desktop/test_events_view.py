"""Unit and integration tests for OSIRIS EventsView and MainWindow integration.

Verifies:
1. EventsView construction, layout, and stable object names.
2. QTableView integration with EventsTableModel.
3. No API client constructed inside visual view.
4. View state transitions: not_loaded, loading, loaded, empty, and failed.
5. Lazy loading contract: initial activation requests load; revisits do not duplicate.
6. Guarding against duplicate concurrent refreshes.
7. Real EventCollection presentation, pagination metadata, and order preservation.
8. Empty response handling and honest empty messaging.
9. Retained records distinguished from fresh results upon failed refresh.
10. Sanitized user-facing error messages for all typed exceptions.
11. Asynchronous MainWindow integration using ApiWorker and respx.
12. Thread safety: API calls off GUI thread, widget updates on GUI thread.
13. Lifecycle safety: in-flight workers prevent premature transport close.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest
import respx
from PySide6.QtCore import QDateTime, Qt, QThreadPool
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFrame,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableView,
    QWidget,
)

from desktop.client.api_client import APIClient
from desktop.client.models import Event, EventCollection, User
from desktop.models.events_model import EventRole, EventsTableModel
from desktop.ui.app_shell import AppShell
from desktop.ui.components import EventInspectorPanel
from desktop.ui.main_window import MainWindow
from desktop.ui.views.events_view import (
    STATE_EMPTY,
    STATE_FAILED,
    STATE_LOADED,
    STATE_LOADING,
    STATE_NOT_LOADED,
    EventsQuery,
    EventsView,
)

SAMPLE_EVENT_ID_1 = "11111111-1111-4111-8111-111111111111"
SAMPLE_EVENT_ID_2 = "22222222-2222-4222-8222-222222222222"
SAMPLE_HOST_ID = "33333333-3333-4333-8333-333333333333"
SAMPLE_PROCESS_ID = "44444444-4444-4444-8444-444444444444"
SAMPLE_TIME_1 = "2026-03-01T12:00:00Z"
SAMPLE_TIME_2 = "2026-03-01T12:01:00Z"


def _sample_user() -> User:
    """Return a representative authenticated User instance."""
    return User(
        id="usr-events-001",
        username="lead_analyst",
        display_name="Lead Analyst",
        role="admin",
        is_active=True,
        created_at="2026-01-01T00:00:00Z",
    )


def _make_event(
    event_id: str = SAMPLE_EVENT_ID_1,
    severity: str = "info",
    source: str = "proc",
    event_type: str = "process.start",
    action: str = "start",
    username: str | None = "analyst",
    pid: int | None = 1234,
    command: str | None = "/bin/ls",
    object_type: str | None = "process",
    object_path: str | None = None,
    result: str | None = "success",
    timestamp: str = SAMPLE_TIME_1,
) -> Event:
    """Create a valid Event instance for view tests."""
    return Event(
        id=event_id,
        host_id=SAMPLE_HOST_ID,
        timestamp=timestamp,
        ingested_at=timestamp,
        source=source,
        event_type=event_type,
        action=action,
        severity=severity,
        created_at=timestamp,
        process_id=SAMPLE_PROCESS_ID,
        uid=1000,
        username=username,
        pid=pid,
        ppid=1,
        command=command,
        object_type=object_type,
        object_path=object_path,
        success=True,
        result=result,
        payload={"args": []},
    )


def _make_collection(
    items: tuple[Event, ...] = (),
    total: int = 0,
    limit: int = 50,
    offset: int = 0,
) -> EventCollection:
    """Create a valid EventCollection instance."""
    return EventCollection(
        total=total if total >= len(items) else len(items),
        items=items,
        limit=limit,
        offset=offset,
    )


def _label_text(parent: QWidget, name: str) -> str:
    """Return text of a child QLabel, asserting that it exists."""
    lbl = parent.findChild(QLabel, name)
    assert lbl is not None, f"Child QLabel {name!r} not found on {parent!r}"
    return lbl.text()


# ==============================================================================
# 1. View Construction and Structure
# ==============================================================================


def test_events_view_instantiation(qapp: QApplication) -> None:
    """EventsView constructs successfully with required child widgets."""
    view = EventsView()
    assert view is not None
    assert isinstance(view, QWidget)
    assert view.objectName() == "Page_Events"
    assert view.state == STATE_NOT_LOADED
    assert view.model.rowCount() == 0


def test_events_view_stable_object_names(qapp: QApplication) -> None:
    """EventsView exposes stable object names across all key child controls."""
    view = EventsView()

    assert view.findChild(QLabel, "PageTitle") is not None
    assert view.findChild(QLabel, "PageDescription") is not None
    assert view.findChild(QFrame, "EventsFilterBar") is not None
    assert view.findChild(QComboBox, "SeverityFilterComboBox") is not None
    assert view.findChild(QLineEdit, "SourceFilterInput") is not None
    assert view.findChild(QLineEdit, "EventTypeFilterInput") is not None
    assert view.findChild(QLineEdit, "PidFilterInput") is not None
    assert view.findChild(QLineEdit, "HostIdFilterInput") is not None
    assert view.findChild(QPushButton, "ApplyFiltersButton") is not None
    assert view.findChild(QPushButton, "ClearFiltersButton") is not None
    assert view.findChild(QLabel, "FilterValidationLabel") is not None
    assert view.findChild(QFrame, "EventsToolbar") is not None
    assert view.findChild(QPushButton, "RefreshEventsButton") is not None
    assert view.findChild(QLabel, "RecordCountSummary") is not None
    assert view.findChild(QFrame, "EventsStatusBanner") is not None
    assert view.findChild(QLabel, "EventsStatusBannerTitle") is not None
    assert view.findChild(QLabel, "EventsStatusBannerMessage") is not None
    assert view.findChild(QPushButton, "RetryEventsButton") is not None
    assert view.findChild(QTableView, "EventsTable") is not None
    assert view.findChild(QFrame, "EventsPaginationFrame") is not None
    assert view.findChild(QPushButton, "PrevPageButton") is not None
    assert view.findChild(QPushButton, "NextPageButton") is not None
    assert view.findChild(QLabel, "PageRangeLabel") is not None


def test_events_view_does_not_instantiate_api_client(qapp: QApplication) -> None:
    """EventsView contains no APIClient instance or HTTP transport."""
    view = EventsView()
    assert not hasattr(view, "client")
    assert not hasattr(view, "_client")


def test_events_table_backed_by_events_table_model(qapp: QApplication) -> None:
    """EventsView table uses EventsTableModel with row selection and no edits."""
    view = EventsView()
    table = view.table
    assert isinstance(table.model(), EventsTableModel)
    assert table.isSortingEnabled() is False
    assert (
        table.selectionBehavior() == QTableView.SelectionBehavior.SelectRows
    )
    assert (
        table.editTriggers() == QTableView.EditTrigger.NoEditTriggers
    )


def test_refresh_events_button_emits_signal(qapp: QApplication) -> None:
    """Clicking Refresh Events emits the refresh_requested signal."""
    view = EventsView()
    emitted: list[bool] = []
    view.refresh_requested.connect(lambda: emitted.append(True))

    view.refresh_button.click()
    assert emitted == [True]


# ==============================================================================
# 2. View States and Transitions
# ==============================================================================


def test_initial_not_loaded_state(qapp: QApplication) -> None:
    """Initial state is not_loaded with descriptive banner and 0 count."""
    view = EventsView()
    view.show()
    assert view.state == STATE_NOT_LOADED
    assert view.status_banner.isVisible() is True
    assert "Not Loaded" in _label_text(view, "EventsStatusBannerTitle")
    assert "not loaded" in view.record_count_label.text()
    assert view.refresh_button.isEnabled() is True
    view.close()


def test_set_loading_disables_refresh_button(qapp: QApplication) -> None:
    """set_loading() disables refresh button and shows honest loading message."""
    view = EventsView()
    view.show()
    view.set_loading()

    assert view.state == STATE_LOADING
    assert view.refresh_button.isEnabled() is False
    assert view.status_banner.isVisible() is True
    assert "Loading" in _label_text(view, "EventsStatusBannerTitle")
    assert "Loading" in view.record_count_label.text()
    view.close()


def test_set_collection_with_results(qapp: QApplication) -> None:
    """set_collection() with events populates table, hides banner, restores button."""
    view = EventsView()
    view.show()
    e1 = _make_event(SAMPLE_EVENT_ID_1)
    e2 = _make_event(SAMPLE_EVENT_ID_2)
    col = _make_collection((e1, e2), total=150)

    view.set_loading()
    view.set_collection(col)

    assert view.state == STATE_LOADED
    assert view.model.rowCount() == 2
    assert view.status_banner.isVisible() is False
    assert view.status_banner.isHidden() is True
    assert view.refresh_button.isEnabled() is True
    assert "Showing 2 of 150 events" in view.record_count_label.text()
    assert view.event_at(0) is e1
    assert view.event_at(1) is e2
    view.close()


def test_set_collection_empty_results(qapp: QApplication) -> None:
    """set_collection() with 0 events enters empty state with honest banner."""
    view = EventsView()
    view.show()
    empty_col = _make_collection((), total=0)

    view.set_loading()
    view.set_collection(empty_col)

    assert view.state == STATE_EMPTY
    assert view.model.rowCount() == 0
    assert view.status_banner.isVisible() is True
    assert "No Security Events Found" in (
        _label_text(view, "EventsStatusBannerTitle")
    )
    assert view.refresh_button.isEnabled() is True
    assert "0 displayed" in view.record_count_label.text()
    view.close()


def test_set_error_failed_state(qapp: QApplication) -> None:
    """set_error() enters failed state, displays message, and enables retry."""
    view = EventsView()
    view.show()
    view.set_loading()
    view.set_error("Connection timed out while querying API")

    assert view.state == STATE_FAILED
    assert view.status_banner.isVisible() is True
    assert view.retry_button.isVisible() is True
    assert view.refresh_button.isEnabled() is True
    assert "Connection timed out" in (
        _label_text(view, "EventsStatusBannerMessage")
    )
    assert "load failed" in view.record_count_label.text()
    view.close()


def test_retry_button_emits_refresh_requested(qapp: QApplication) -> None:
    """Clicking Retry button in error banner emits refresh_requested."""
    view = EventsView()
    view.set_error("Temporary failure")

    emitted: list[bool] = []
    view.refresh_requested.connect(lambda: emitted.append(True))
    view.retry_button.click()

    assert emitted == [True]


def test_set_not_loaded_clears_data_and_resets_ui(qapp: QApplication) -> None:
    """set_not_loaded() clears table records and resets view state."""
    view = EventsView()
    view.show()
    e = _make_event()
    view.set_collection(_make_collection((e,), total=1))
    assert view.model.rowCount() == 1

    view.set_not_loaded()
    assert view.state == STATE_NOT_LOADED
    assert view.model.rowCount() == 0
    assert view.status_banner.isVisible() is True
    assert "not loaded" in view.record_count_label.text()
    view.close()


def test_failed_refresh_preserves_older_records_distinctly(
    qapp: QApplication,
) -> None:
    """Failed refresh retains older records while explicitly marking them retained."""
    view = EventsView()
    e = _make_event(SAMPLE_EVENT_ID_1)
    view.set_collection(_make_collection((e,), total=1))
    assert view.model.rowCount() == 1

    # Refresh starts
    view.set_loading()
    assert "refreshing..." in view.record_count_label.text()
    assert view.model.rowCount() == 1  # Records retained during load

    # Refresh fails
    view.set_error("Server error 500")
    assert view.state == STATE_FAILED
    assert view.model.rowCount() == 1  # Records retained
    # Retained records must NOT be labeled as freshly current
    assert "Retained 1 events (refresh failed)" in view.record_count_label.text()
    assert "Displaying retained records" in (
        _label_text(view, "EventsStatusBannerMessage")
    )


def test_public_methods_reject_invalid_arguments(qapp: QApplication) -> None:
    """set_collection and set_error reject invalid types with TypeError."""
    view = EventsView()
    with pytest.raises(TypeError, match="Expected EventCollection"):
        view.set_collection({"total": 1, "items": []})  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="Expected str message"):
        view.set_error(12345)  # type: ignore[arg-type]


# ==============================================================================
# 3. Lazy Loading Navigation Contract
# ==============================================================================


def test_first_navigation_to_events_requests_initial_load(
    qapp: QApplication,
) -> None:
    """Navigating to Events from Overview triggers load_requested on first visit."""
    shell = AppShell()
    emitted: list[bool] = []
    shell.events_load_requested.connect(lambda: emitted.append(True))

    # Shell begins at Overview
    assert shell.current_page_name == "Overview"
    assert emitted == []

    # First navigation to Events
    shell.navigate_to("Events")
    assert shell.current_page_name == "Events"
    assert emitted == [True]


def test_revisiting_events_does_not_duplicate_load(
    qapp: QApplication,
) -> None:
    """Switching between pages does not re-trigger load_requested after loaded."""
    shell = AppShell()
    emitted: list[bool] = []
    shell.events_load_requested.connect(lambda: emitted.append(True))

    shell.navigate_to("Events")
    assert len(emitted) == 1

    # Mark as loaded
    e = _make_event()
    shell.events_view.set_collection(_make_collection((e,), total=1))

    # Switch away and return
    shell.navigate_to("Overview")
    shell.navigate_to("Events")
    shell.navigate_to("Processes")
    shell.navigate_to("Events")

    # Still only the original request was emitted
    assert len(emitted) == 1


# ==============================================================================
# 4. Asynchronous MainWindow Integration
# ==============================================================================


@respx.mock
def test_main_window_loads_events_asynchronously(qapp: QApplication) -> None:
    """MainWindow fetches events off GUI thread and populates EventsView."""
    respx.get("http://localhost:8000/api/events").respond(
        status_code=200,
        json={
            "total": 2,
            "items": [
                {
                    "id": SAMPLE_EVENT_ID_1,
                    "host_id": SAMPLE_HOST_ID,
                    "timestamp": SAMPLE_TIME_1,
                    "ingested_at": SAMPLE_TIME_1,
                    "source": "proc",
                    "event_type": "process.start",
                    "action": "start",
                    "severity": "info",
                    "created_at": SAMPLE_TIME_1,
                    "process_id": SAMPLE_PROCESS_ID,
                    "username": "analyst",
                    "pid": 5001,
                    "command": "/bin/ps",
                },
                {
                    "id": SAMPLE_EVENT_ID_2,
                    "host_id": SAMPLE_HOST_ID,
                    "timestamp": SAMPLE_TIME_2,
                    "ingested_at": SAMPLE_TIME_2,
                    "source": "fs",
                    "event_type": "filesystem.write",
                    "action": "write",
                    "severity": "high",
                    "created_at": SAMPLE_TIME_2,
                    "process_id": SAMPLE_PROCESS_ID,
                    "username": "root",
                    "pid": 5002,
                    "command": "/bin/cat",
                },
            ],
            "limit": 50,
            "offset": 0,
        },
    )

    client = APIClient(base_url="http://localhost:8000")
    client._token = "test-token"
    window = MainWindow(client=client, user=_sample_user())

    assert window.events_view.state == STATE_NOT_LOADED

    # Trigger events loading
    window.load_events()
    assert window.is_loading_events is True
    assert window.events_view.state == STATE_LOADING

    # Wait for threadpool and process Qt events
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    assert window.is_loading_events is False
    assert window.events_view.state == STATE_LOADED
    assert window.events_view.model.rowCount() == 2
    assert window.events_view.model.total_count == 2
    assert window.events_view.event_at(0).id == SAMPLE_EVENT_ID_1
    assert window.events_view.event_at(1).id == SAMPLE_EVENT_ID_2
    client.close()


@respx.mock
def test_main_window_handles_empty_events_response(qapp: QApplication) -> None:
    """MainWindow updates view to empty state when API returns 0 items."""
    respx.get("http://localhost:8000/api/events").respond(
        status_code=200,
        json={"total": 0, "items": [], "limit": 50, "offset": 0},
    )

    client = APIClient(base_url="http://localhost:8000")
    client._token = "test-token"
    window = MainWindow(client=client, user=_sample_user())

    window.load_events()
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    assert window.is_loading_events is False
    assert window.events_view.state == STATE_EMPTY
    assert window.events_view.model.rowCount() == 0
    client.close()


@respx.mock
def test_main_window_handles_connection_error(qapp: QApplication) -> None:
    """MainWindow handles connection failure with sanitized error message."""
    respx.get("http://localhost:8000/api/events").mock(
        side_effect=httpx.ConnectError("Offline")
    )

    client = APIClient(base_url="http://localhost:8000")
    client._token = "test-token"
    window = MainWindow(client=client, user=_sample_user())

    window.load_events()
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    assert window.is_loading_events is False
    assert window.events_view.state == STATE_FAILED
    assert "Unable to connect" in (
        _label_text(window.events_view, "EventsStatusBannerMessage")
    )
    client.close()


@respx.mock
def test_main_window_handles_timeout_error(qapp: QApplication) -> None:
    """MainWindow handles timeout with sanitized error message."""
    respx.get("http://localhost:8000/api/events").mock(
        side_effect=httpx.ReadTimeout("Timeout")
    )

    client = APIClient(base_url="http://localhost:8000")
    client._token = "test-token"
    window = MainWindow(client=client, user=_sample_user())

    window.load_events()
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    assert window.events_view.state == STATE_FAILED
    assert "timed out" in (
        _label_text(window.events_view, "EventsStatusBannerMessage")
    )
    client.close()


@respx.mock
def test_main_window_handles_401_authentication_error(
    qapp: QApplication,
) -> None:
    """HTTP 401 clears client token and displays session expired message."""
    respx.get("http://localhost:8000/api/events").respond(
        status_code=401,
        json={"detail": "Token expired"},
    )

    client = APIClient(base_url="http://localhost:8000")
    client._token = "expired-token"
    window = MainWindow(client=client, user=_sample_user())

    window.load_events()
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    # Token must have been cleared by client
    assert client.is_authenticated is False
    assert window.events_view.state == STATE_FAILED
    assert "Authentication session expired" in (
        _label_text(window.events_view, "EventsStatusBannerMessage")
    )
    client.close()


@respx.mock
def test_main_window_handles_403_authorization_error(
    qapp: QApplication,
) -> None:
    """HTTP 403 displays permission denied message without clearing token."""
    respx.get("http://localhost:8000/api/events").respond(
        status_code=403,
        json={"detail": "Insufficient permissions"},
    )

    client = APIClient(base_url="http://localhost:8000")
    client._token = "valid-token"
    window = MainWindow(client=client, user=_sample_user())

    window.load_events()
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    # Token preserved
    assert client.is_authenticated is True
    assert window.events_view.state == STATE_FAILED
    assert "Access denied" in (
        _label_text(window.events_view, "EventsStatusBannerMessage")
    )
    client.close()


def test_duplicate_concurrent_event_requests_suppressed(
    qapp: QApplication,
) -> None:
    """Duplicate load_events() calls while request in flight are ignored."""
    client = MagicMock(spec=APIClient)

    def slow_fetch(*args: Any, **kwargs: Any) -> EventCollection:
        time.sleep(0.05)
        return _make_collection((), total=0)

    client.get_events.side_effect = slow_fetch
    window = MainWindow(client=client, user=_sample_user())

    window.load_events()
    assert window.is_loading_events is True

    # Immediate second call
    window.load_events()
    assert window.is_loading_events is True

    QThreadPool.globalInstance().waitForDone(2000)
    qapp.processEvents()

    assert client.get_events.call_count == 1


# ==============================================================================
# 5. Worker Lifetime, Shutdown, and Logout Safety
# ==============================================================================


def test_logout_during_active_events_request(qapp: QApplication) -> None:
    """Logging out while events request is in flight defers window closure safely."""
    client = MagicMock(spec=APIClient)

    def slow_fetch(*args: Any, **kwargs: Any) -> EventCollection:
        time.sleep(0.05)
        return _make_collection((), total=0)

    client.get_events.side_effect = slow_fetch
    window = MainWindow(client=client, user=_sample_user())
    window.show()

    window.load_events()
    assert window.is_loading_events is True

    emitted: list[bool] = []
    window.logout_requested.connect(lambda: emitted.append(True))

    # Click logout on header
    window.shell.logout_button.click()

    # Client logged out immediately
    client.logout.assert_called_once()
    assert emitted == [True]
    # Window hidden immediately
    assert window.isVisible() is False
    # Window close pending
    assert window._pending_close is True

    QThreadPool.globalInstance().waitForDone(2000)
    qapp.processEvents()

    assert window.is_loading_events is False


def test_concurrent_status_and_events_workers_lifecycle(
    qapp: QApplication,
) -> None:
    """Status check and events workers can execute in parallel without conflict."""
    client = MagicMock(spec=APIClient)

    def slow_status(*args: Any, **kwargs: Any) -> Any:
        time.sleep(0.04)
        return MagicMock(status="ok", system="osiris")

    def slow_events(*args: Any, **kwargs: Any) -> EventCollection:
        time.sleep(0.04)
        return _make_collection((), total=0)

    client.health_check.side_effect = slow_status
    client.get_status.return_value = MagicMock(
        status="healthy", system="osiris", database="connected", host_id="test"
    )
    client.get_events.side_effect = slow_events

    window = MainWindow(client=client, user=_sample_user())

    window.check_operational_status()
    window.load_events()

    assert window.is_checking_status is True
    assert window.is_loading_events is True
    assert window.has_active_workers is True

    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    assert window.is_checking_status is False
    assert window.is_loading_events is False
    assert window.has_active_workers is False


# ==============================================================================
# 6. Filter Toolbar Controls and Local Validation
# ==============================================================================


def test_filter_toolbar_initial_state(qapp: QApplication) -> None:
    """Filter toolbar initializes with default choices and empty inputs."""
    view = EventsView()
    assert view.severity_combo.currentIndex() == 0
    assert view.severity_combo.currentText() == "All severities"
    assert view.severity_combo.currentData() is None
    assert view.source_input.text() == ""
    assert view.event_type_input.text() == ""
    assert view.pid_input.text() == ""
    assert view.host_id_input.text() == ""
    assert view.filter_validation_label.text() == ""
    assert view.current_query == EventsQuery(limit=50, offset=0)


def test_severity_filter_options(qapp: QApplication) -> None:
    """Severity combo box exposes All severities plus all 5 canonical severities."""
    view = EventsView()
    combo = view.severity_combo
    expected = [
        ("All severities", None),
        ("Critical", "critical"),
        ("High", "high"),
        ("Medium", "medium"),
        ("Low", "low"),
        ("Info", "info"),
    ]
    assert combo.count() == len(expected)
    for idx, (expected_text, expected_data) in enumerate(expected):
        assert combo.itemText(idx) == expected_text
        assert combo.itemData(idx) == expected_data


def test_apply_filters_with_valid_criteria(qapp: QApplication) -> None:
    """Applying valid filters emits query_requested with normalized EventsQuery."""
    view = EventsView()
    emitted: list[EventsQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    # Set inputs with surrounding whitespace to verify stripping
    view.severity_combo.setCurrentIndex(1)  # Critical
    view.source_input.setText("   proc   ")
    view.event_type_input.setText("  process.start  ")
    view.pid_input.setText("  1024  ")
    view.host_id_input.setText(f"  {SAMPLE_HOST_ID}  ")

    view.apply_filters_button.click()

    assert len(emitted) == 1
    query = emitted[0]
    assert query.severity == "critical"
    assert query.source == "proc"
    assert query.event_type == "process.start"
    assert query.pid == 1024
    assert query.host_id == SAMPLE_HOST_ID
    assert query.offset == 0
    assert query.limit == 50
    assert query.has_active_filters is True
    assert view.filter_validation_label.text() == ""


def test_apply_filters_preserves_pid_zero(qapp: QApplication) -> None:
    """PID 0 is a valid Linux process ID and is preserved faithfully."""
    view = EventsView()
    emitted: list[EventsQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    view.pid_input.setText("0")
    view.apply_filters_button.click()

    assert len(emitted) == 1
    assert emitted[0].pid == 0
    assert emitted[0].pid is not None
    assert emitted[0].to_client_kwargs()["pid"] == 0


def test_apply_filters_rejects_negative_and_non_numeric_pid(
    qapp: QApplication,
) -> None:
    """Negative and non-integer PID values trigger local validation error."""
    view = EventsView()
    emitted: list[EventsQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    # Negative PID
    view.pid_input.setText("-1")
    view.apply_filters_button.click()
    assert len(emitted) == 0
    assert (
        "PID must be a non-negative integer"
        in view.filter_validation_label.text()
    )

    # Non-numeric PID
    view.pid_input.setText("abc")
    view.apply_filters_button.click()
    assert len(emitted) == 0
    assert (
        "PID must be a non-negative integer"
        in view.filter_validation_label.text()
    )


def test_apply_filters_rejects_invalid_host_id_uuid(
    qapp: QApplication,
) -> None:
    """Malformed host_id strings trigger local validation without network requests."""
    view = EventsView()
    emitted: list[EventsQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    view.host_id_input.setText("not-a-valid-uuid")
    view.apply_filters_button.click()

    assert len(emitted) == 0
    assert "Host ID must be a valid UUID" in view.filter_validation_label.text()


def test_clear_filters_resets_inputs_and_query(qapp: QApplication) -> None:
    """Clear Filters resets all controls and emits query with offset 0."""
    view = EventsView()
    emitted: list[EventsQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    # First apply some filters
    view.severity_combo.setCurrentIndex(2)  # High
    view.source_input.setText("fs")
    view.apply_filters_button.click()
    assert len(emitted) == 1
    assert emitted[0].severity == "high"

    # Now clear filters
    view.clear_filters_button.click()
    assert len(emitted) == 2
    cleared_query = emitted[1]
    assert cleared_query.severity is None
    assert cleared_query.source is None
    assert cleared_query.offset == 0
    assert cleared_query.has_active_filters is False

    assert view.severity_combo.currentIndex() == 0
    assert view.source_input.text() == ""
    assert view.filter_validation_label.text() == ""


def test_keystrokes_do_not_dispatch_query_requests(
    qapp: QApplication,
) -> None:
    """Typing into filter line edits does not emit query_requested."""
    view = EventsView()
    emitted: list[EventsQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    view.source_input.setText("proc")
    view.event_type_input.setText("process.start")
    view.pid_input.setText("500")

    assert len(emitted) == 0


# ==============================================================================
# 7. Server-Side Pagination and Range Calculation
# ==============================================================================


def test_pagination_controls_initial_state(qapp: QApplication) -> None:
    """On not_loaded state, Prev and Next buttons are disabled."""
    view = EventsView()
    assert view.prev_page_button.isEnabled() is False
    assert view.next_page_button.isEnabled() is False
    assert view.page_range_label.text() == "0 of 0 events"


def test_pagination_next_and_previous_navigation(qapp: QApplication) -> None:
    """Next and Previous buttons navigate between pages preserving active filters."""
    view = EventsView()
    emitted: list[EventsQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    # Apply a filter first
    view.source_input.setText("proc")
    view.apply_filters_button.click()
    assert len(emitted) == 1

    # Simulate server returning page 1 of 3 (total 125, limit 50, offset 0)
    events_p1 = tuple(_make_event(f"e-{i}") for i in range(50))
    view.set_collection(
        _make_collection(events_p1, total=125, limit=50, offset=0)
    )

    assert view.prev_page_button.isEnabled() is False
    assert view.next_page_button.isEnabled() is True
    assert "Showing 1–50 of 125 events" in view.page_range_label.text()

    # Click Next
    view.next_page_button.click()
    assert len(emitted) == 2
    p2_query = emitted[1]
    assert p2_query.offset == 50
    assert p2_query.limit == 50
    assert p2_query.source == "proc"  # Filter preserved

    # Simulate server returning page 2 of 3 (offset 50, total 125)
    events_p2 = tuple(_make_event(f"e-p2-{i}") for i in range(50))
    view.set_collection(
        _make_collection(events_p2, total=125, limit=50, offset=50)
    )

    assert view.prev_page_button.isEnabled() is True
    assert view.next_page_button.isEnabled() is True
    assert "Showing 51–100 of 125 events" in view.page_range_label.text()

    # Click Next again to reach last page
    view.next_page_button.click()
    assert len(emitted) == 3
    p3_query = emitted[2]
    assert p3_query.offset == 100

    # Simulate server returning final page (25 items, offset 100, total 125)
    events_p3 = tuple(_make_event(f"e-p3-{i}") for i in range(25))
    view.set_collection(
        _make_collection(events_p3, total=125, limit=50, offset=100)
    )

    assert view.prev_page_button.isEnabled() is True
    assert view.next_page_button.isEnabled() is False  # Reached end!
    assert "Showing 101–125 of 125 events" in view.page_range_label.text()

    # Click Previous to go back to page 2
    view.prev_page_button.click()
    assert len(emitted) == 4
    back_query = emitted[3]
    assert back_query.offset == 50
    assert back_query.source == "proc"


def test_pagination_empty_collection_never_shows_nonsensical_range(
    qapp: QApplication,
) -> None:
    """Empty collection displays 0 of 0 events without invalid 1-0 range."""
    view = EventsView()
    view.set_collection(_make_collection((), total=0, limit=50, offset=0))

    assert view.page_range_label.text() == "0 of 0 events"
    assert view.prev_page_button.isEnabled() is False
    assert view.next_page_button.isEnabled() is False


def test_applying_filter_resets_offset_to_zero(qapp: QApplication) -> None:
    """Applying new filter on page 2 resets offset back to zero."""
    view = EventsView()
    emitted: list[EventsQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    # Put view on offset 50
    view.set_collection(
        _make_collection(
            tuple(_make_event(f"e-{i}") for i in range(50)),
            total=100,
            limit=50,
            offset=50,
        )
    )
    assert view.current_query.offset == 50

    # Apply new filter
    view.severity_combo.setCurrentIndex(1)  # Critical
    view.apply_filters_button.click()

    assert len(emitted) == 1
    assert emitted[0].offset == 0
    assert emitted[0].severity == "critical"


def test_empty_results_differentiates_filtered_from_unfiltered(
    qapp: QApplication,
) -> None:
    """Empty results banner communicates whether filters were active."""
    view = EventsView()

    # 1. Unfiltered empty response
    view.set_collection(_make_collection((), total=0))
    assert _label_text(view, "EventsStatusBannerTitle") == "No Security Events Found"
    assert "zero security events" in _label_text(view, "EventsStatusBannerMessage")

    # 2. Filtered empty response
    view.source_input.setText("unknown_source")
    view.apply_filters()
    view.set_collection(_make_collection((), total=0))
    assert _label_text(view, "EventsStatusBannerTitle") == "No Matching Security Events"
    assert "match the active filter criteria" in (
        _label_text(view, "EventsStatusBannerMessage")
    )


# ==============================================================================
# 8. Asynchronous Filtering Integration with MainWindow
# ==============================================================================


@respx.mock
def test_main_window_loads_events_with_filter_params(
    qapp: QApplication,
) -> None:
    """MainWindow passes normalized query filters as GET /api/events params."""
    route = respx.get("http://localhost:8000/api/events").respond(
        status_code=200,
        json={"total": 0, "items": [], "limit": 50, "offset": 0},
    )

    client = APIClient(base_url="http://localhost:8000")
    client._token = "test-token"
    window = MainWindow(client=client, user=_sample_user())

    query = EventsQuery(
        severity="high",
        source="proc",
        pid=1234,
        limit=50,
        offset=0,
    )
    window.load_events(query)

    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    assert route.called
    req = route.calls.last.request
    assert req.url.params["severity"] == "high"
    assert req.url.params["source"] == "proc"
    assert req.url.params["pid"] == "1234"
    assert req.url.params["limit"] == "50"
    assert req.url.params["offset"] == "0"
    client.close()


def test_stale_response_ignored_when_sequence_advanced(
    qapp: QApplication,
) -> None:
    """Responses from earlier requests are dropped if a newer query was issued."""
    client = MagicMock(spec=APIClient)
    window = MainWindow(client=client, user=_sample_user())

    # Simulate sequence 1 and sequence 2
    window._events_request_seq = 2

    # A delayed callback from sequence 1 arrives
    stale_col = _make_collection(
        (_make_event(SAMPLE_EVENT_ID_1),), total=1, limit=50, offset=0
    )
    window._on_events_result(stale_col, seq=1)

    # Model was NOT updated by stale result
    assert window.events_view.model.rowCount() == 0


# ==============================================================================
# 9. Events Table Row Selection and Inspector Integration
# ==============================================================================


def test_inspector_panel_initial_unselected_state(qapp: QApplication) -> None:
    """Inspector is present on EventsView, initially hidden, with no event."""
    view = EventsView()
    assert isinstance(view.inspector, EventInspectorPanel)
    assert view.inspector is view.inspector_panel
    assert view.inspector.isVisible() is False
    assert view.selected_event is None
    assert view.inspector.current_event is None


def test_row_selection_displays_original_event_in_inspector(
    qapp: QApplication,
) -> None:
    """Selecting a valid table row shows details for its original Event object."""
    view = EventsView()
    view.show()
    e1 = _make_event(SAMPLE_EVENT_ID_1, command="/bin/echo 1")
    e2 = _make_event(SAMPLE_EVENT_ID_2, command="/bin/echo 2")
    view.set_collection(_make_collection((e1, e2), total=2))

    assert view.inspector.isVisible() is False

    # Select row 0
    view.table.selectRow(0)
    qapp.processEvents()

    assert view.inspector.isVisible() is True
    assert view.selected_event is e1
    assert view.inspector.current_event is e1
    assert view.inspector.get_field_value("id") == SAMPLE_EVENT_ID_1
    assert view.inspector.get_field_value("command") == "/bin/echo 1"

    # Verify model data returns exact same object
    idx = view.table.model().index(0, 0)
    assert view.table.model().data(idx, EventRole) is e1
    view.close()


def test_selecting_different_row_updates_inspector(
    qapp: QApplication,
) -> None:
    """Selecting a different table row updates the inspector to the new Event."""
    view = EventsView()
    view.show()
    e1 = _make_event(SAMPLE_EVENT_ID_1, command="/bin/echo 1")
    e2 = _make_event(SAMPLE_EVENT_ID_2, command="/bin/echo 2")
    view.set_collection(_make_collection((e1, e2), total=2))

    view.table.selectRow(0)
    assert view.selected_event is e1

    # Select row 1
    view.table.selectRow(1)
    qapp.processEvents()

    assert view.selected_event is e2
    assert view.inspector.current_event is e2
    assert view.inspector.get_field_value("id") == SAMPLE_EVENT_ID_2
    assert view.inspector.get_field_value("command") == "/bin/echo 2"
    view.close()


def test_clearing_selection_hides_inspector(qapp: QApplication) -> None:
    """Clearing row selection hides the inspector and resets selected_event."""
    view = EventsView()
    view.show()
    e = _make_event()
    view.set_collection(_make_collection((e,), total=1))

    view.table.selectRow(0)
    assert view.inspector.isVisible() is True
    assert view.selected_event is e

    view.table.clearSelection()
    qapp.processEvents()

    assert view.inspector.isVisible() is False
    assert view.selected_event is None
    assert view.inspector.current_event is None
    view.close()


def test_closing_inspector_clears_row_selection_and_hides(
    qapp: QApplication,
) -> None:
    """Clicking close button on inspector clears table selection and hides panel."""
    view = EventsView()
    view.show()
    e = _make_event()
    view.set_collection(_make_collection((e,), total=1))

    view.table.selectRow(0)
    assert view.inspector.isVisible() is True
    assert view.table.selectionModel().hasSelection() is True

    # Click close button on inspector
    view.inspector.close_button.click()
    qapp.processEvents()

    assert view.inspector.isVisible() is False
    assert view.table.selectionModel().hasSelection() is False
    assert view.selected_event is None
    view.close()


def test_reselecting_row_after_close_reopens_inspector(
    qapp: QApplication,
) -> None:
    """Reselecting a table row after closing restores inspector details."""
    view = EventsView()
    view.show()
    e = _make_event()
    view.set_collection(_make_collection((e,), total=1))

    view.table.selectRow(0)
    view.inspector.close_button.click()
    assert view.inspector.isVisible() is False

    # Select again
    view.table.selectRow(0)
    qapp.processEvents()

    assert view.inspector.isVisible() is True
    assert view.selected_event is e
    view.close()


def test_filter_changes_clear_inspector_selection(
    qapp: QApplication,
) -> None:
    """Applying or clearing filters clears table selection and inspector."""
    view = EventsView()
    e = _make_event()
    view.set_collection(_make_collection((e,), total=1))

    view.table.selectRow(0)
    assert view.selected_event is e

    # Apply filter clears selection and inspector
    view.source_input.setText("proc")
    view.apply_filters()
    assert view.selected_event is None
    assert view.inspector.isVisible() is False
    assert view.table.selectionModel().hasSelection() is False

    # Reselect and clear filters
    view.table.selectRow(0)
    assert view.selected_event is e

    view.clear_filters()
    assert view.selected_event is None
    assert view.inspector.isVisible() is False
    assert view.table.selectionModel().hasSelection() is False


def test_pagination_collection_replacement_clears_inspector(
    qapp: QApplication,
) -> None:
    """Replacing collection on page change clears stale inspector details."""
    view = EventsView()
    e1 = _make_event(SAMPLE_EVENT_ID_1)
    view.set_collection(_make_collection((e1,), total=50, limit=1, offset=0))

    view.table.selectRow(0)
    assert view.selected_event is e1

    # Simulate new page arriving
    e2 = _make_event(SAMPLE_EVENT_ID_2)
    view.set_collection(_make_collection((e2,), total=50, limit=1, offset=1))

    assert view.selected_event is None
    assert view.inspector.isVisible() is False
    assert view.table.selectionModel().hasSelection() is False


def test_selection_changes_make_no_api_or_query_requests(
    qapp: QApplication,
) -> None:
    """Selecting rows or closing inspector never triggers API queries."""
    view = EventsView()
    e1 = _make_event(SAMPLE_EVENT_ID_1)
    e2 = _make_event(SAMPLE_EVENT_ID_2)
    view.set_collection(_make_collection((e1, e2), total=2))

    emitted: list[EventsQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))
    initial_query = view.current_query

    # Select row 0, select row 1, clear, close
    view.table.selectRow(0)
    view.table.selectRow(1)
    view.table.clearSelection()
    view.table.selectRow(0)
    view.inspector.close_button.click()

    # Zero queries were dispatched
    assert emitted == []
    assert view.current_query == initial_query


def test_refresh_failure_clears_inspector(qapp: QApplication) -> None:
    """Failed refresh clears inspector rather than showing stale selection."""
    view = EventsView()
    e = _make_event()
    view.set_collection(_make_collection((e,), total=1))

    view.table.selectRow(0)
    assert view.selected_event is e

    view.set_error("Connection error")
    assert view.selected_event is None
    assert view.inspector.isVisible() is False
    view.close()


# ==============================================================================
# 9. Event Time-Range Filters (0.4.10)
# ==============================================================================


def test_time_filters_default_state(qapp: QApplication) -> None:
    """Verify default time filter controls are disabled and unset."""
    view = EventsView()
    assert view.start_time_label.text() == "Start Time (UTC)"
    assert view.end_time_label.text() == "End Time (UTC)"
    assert view.start_time_check.isChecked() is False
    assert view.start_time_checkbox.isChecked() is False
    assert view.end_time_check.isChecked() is False
    assert view.end_time_checkbox.isChecked() is False
    assert view.start_time_edit.isEnabled() is False
    assert view.end_time_edit.isEnabled() is False
    assert view.start_time is None
    assert view.end_time is None
    assert view.current_query.start_time is None
    assert view.current_query.end_time is None
    assert view.current_query.has_active_filters is False

    # Toggling checkboxes toggles edit enablement
    view.start_time_check.setChecked(True)
    assert view.start_time_edit.isEnabled() is True
    view.start_time_check.setChecked(False)
    assert view.start_time_edit.isEnabled() is False

    view.end_time_check.setChecked(True)
    assert view.end_time_edit.isEnabled() is True
    view.end_time_check.setChecked(False)
    assert view.end_time_edit.isEnabled() is False
    view.close()


def test_time_filters_enable_start_time_only(qapp: QApplication) -> None:
    """Enabling start time only emits query with start_time and no end_time."""
    view = EventsView()
    emitted: list[EventsQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    view.set_start_time("2026-03-01T10:00:00Z")
    assert view.start_time_check.isChecked() is True
    assert view.start_time_edit.isEnabled() is True
    assert view.start_time == "2026-03-01T10:00:00Z"
    assert view.end_time is None

    view.apply_filters()
    assert len(emitted) == 1
    q = emitted[0]
    assert q.start_time == "2026-03-01T10:00:00Z"
    assert q.end_time is None
    assert q.has_active_filters is True

    kwargs = q.to_client_kwargs()
    assert kwargs["start_time"] == "2026-03-01T10:00:00Z"
    assert "end_time" not in kwargs
    view.close()


def test_time_filters_enable_end_time_only(qapp: QApplication) -> None:
    """Enabling end time only emits query with end_time and no start_time."""
    view = EventsView()
    emitted: list[EventsQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    view.set_end_time("2026-03-01T18:00:00Z")
    assert view.end_time_check.isChecked() is True
    assert view.end_time_edit.isEnabled() is True
    assert view.start_time is None
    assert view.end_time == "2026-03-01T18:00:00Z"

    view.apply_filters()
    assert len(emitted) == 1
    q = emitted[0]
    assert q.start_time is None
    assert q.end_time == "2026-03-01T18:00:00Z"
    assert q.has_active_filters is True

    kwargs = q.to_client_kwargs()
    assert kwargs["end_time"] == "2026-03-01T18:00:00Z"
    assert "start_time" not in kwargs
    view.close()


def test_time_filters_enable_both_boundaries(qapp: QApplication) -> None:
    """Enabling both boundaries emits query with both ISO-8601 strings."""
    view = EventsView()
    emitted: list[EventsQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    view.set_start_time("2026-03-01T10:00:00Z")
    view.set_end_time("2026-03-01T18:00:00Z")

    view.apply_filters()
    assert len(emitted) == 1
    q = emitted[0]
    assert q.start_time == "2026-03-01T10:00:00Z"
    assert q.end_time == "2026-03-01T18:00:00Z"
    assert q.has_active_filters is True

    kwargs = q.to_client_kwargs()
    assert kwargs["start_time"] == "2026-03-01T10:00:00Z"
    assert kwargs["end_time"] == "2026-03-01T18:00:00Z"
    view.close()


def test_time_filters_equal_boundaries_valid(qapp: QApplication) -> None:
    """Equal start and end times represent a valid instant query."""
    view = EventsView()
    emitted: list[EventsQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    view.set_start_time("2026-03-01T12:00:00Z")
    view.set_end_time("2026-03-01T12:00:00Z")

    view.apply_filters()
    assert len(emitted) == 1
    q = emitted[0]
    assert q.start_time == "2026-03-01T12:00:00Z"
    assert q.end_time == "2026-03-01T12:00:00Z"
    assert view.filter_validation_label.text() == ""
    view.close()


def test_time_filters_reversed_boundaries_error(qapp: QApplication) -> None:
    """Start time after end time shows inline validation error without query."""
    view = EventsView()
    emitted: list[EventsQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    view.set_start_time("2026-03-01T18:00:00Z")
    view.set_end_time("2026-03-01T10:00:00Z")

    view.apply_filters()
    assert len(emitted) == 0
    assert (
        view.filter_validation_label.text()
        == "Start time must be earlier than or equal to end time"
    )
    view.close()


def test_time_filters_clear_resets_both_boundaries(qapp: QApplication) -> None:
    """Clear filters unchecks both checkboxes, clears validation, and queries."""
    view = EventsView()
    emitted: list[EventsQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    # First set invalid range
    view.set_start_time("2026-03-01T18:00:00Z")
    view.set_end_time("2026-03-01T10:00:00Z")
    view.apply_filters()
    assert view.filter_validation_label.text() != ""
    assert len(emitted) == 0

    # Clear filters
    view.clear_filters()
    assert view.start_time_check.isChecked() is False
    assert view.end_time_check.isChecked() is False
    assert view.start_time_edit.isEnabled() is False
    assert view.end_time_edit.isEnabled() is False
    assert view.start_time is None
    assert view.end_time is None
    assert view.filter_validation_label.text() == ""

    assert len(emitted) == 1
    q = emitted[0]
    assert q.start_time is None
    assert q.end_time is None
    assert q.offset == 0
    view.close()


def test_time_filters_pagination_preserves_boundaries(
    qapp: QApplication,
) -> None:
    """Pagination preserves active time-range query filters across pages."""
    view = EventsView()
    emitted: list[EventsQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    view.set_start_time("2026-03-01T08:00:00Z")
    view.set_end_time("2026-03-01T16:00:00Z")
    view.apply_filters()
    assert len(emitted) == 1
    assert emitted[0].offset == 0

    # Simulate arrival of page 1 with 100 total items
    events = tuple(_make_event(f"evt-{i:03d}") for i in range(50))
    view.set_collection(
        EventCollection(total=100, items=events, limit=50, offset=0)
    )

    assert view.next_page_button.isEnabled() is True
    view.go_next_page()

    assert len(emitted) == 2
    q2 = emitted[1]
    assert q2.offset == 50
    assert q2.start_time == "2026-03-01T08:00:00Z"
    assert q2.end_time == "2026-03-01T16:00:00Z"

    # Simulate arrival of page 2
    view.set_collection(
        EventCollection(total=100, items=events, limit=50, offset=50)
    )
    assert view.prev_page_button.isEnabled() is True
    view.go_prev_page()

    assert len(emitted) == 3
    q3 = emitted[2]
    assert q3.offset == 0
    assert q3.start_time == "2026-03-01T08:00:00Z"
    assert q3.end_time == "2026-03-01T16:00:00Z"
    view.close()


def test_time_filters_loading_state_disables_controls(
    qapp: QApplication,
) -> None:
    """Loading state disables checkboxes and edits; loaded state re-enables."""
    view = EventsView()
    view.set_start_time("2026-03-01T10:00:00Z")
    # start_time_check is checked (edit enabled);
    # end_time_check is unchecked (edit disabled)
    assert view.start_time_check.isEnabled() is True
    assert view.start_time_edit.isEnabled() is True
    assert view.end_time_check.isEnabled() is True
    assert view.end_time_edit.isEnabled() is False

    view.set_loading()
    assert view.start_time_check.isEnabled() is False
    assert view.start_time_edit.isEnabled() is False
    assert view.end_time_check.isEnabled() is False
    assert view.end_time_edit.isEnabled() is False

    # After loaded: start_time_edit is enabled (since checked);
    # end_time_edit remains disabled
    view.set_collection(_make_collection((_make_event(),), total=1))
    assert view.start_time_check.isEnabled() is True
    assert view.start_time_edit.isEnabled() is True
    assert view.end_time_check.isEnabled() is True
    assert view.end_time_edit.isEnabled() is False

    # Test error recovery re-enables
    view.set_loading()
    assert view.start_time_check.isEnabled() is False
    view.set_error("Network failure")
    assert view.start_time_check.isEnabled() is True
    assert view.start_time_edit.isEnabled() is True
    assert view.end_time_check.isEnabled() is True
    assert view.end_time_edit.isEnabled() is False
    view.close()


def test_time_filters_timezone_handling_and_iso_utc(
    qapp: QApplication,
) -> None:
    """Datetime with non-UTC timezone converts accurately to UTC ISO ending with Z."""
    view = EventsView()
    # Datetime at UTC+2 (e.g. 14:00 at +02:00 = 12:00 UTC)
    tz_plus_2 = timezone(timedelta(hours=2))
    dt_with_tz = datetime(2026, 3, 1, 14, 0, 0, tzinfo=tz_plus_2)

    view.set_start_time(dt_with_tz)
    assert view.start_time == "2026-03-01T12:00:00Z"

    # Datetime via QDateTime
    qdt = QDateTime(
        QDateTime.fromString("2026-03-01T15:30:00Z", Qt.DateFormat.ISODate)
    )
    view.set_end_time(qdt)
    assert view.end_time == "2026-03-01T15:30:00Z"
    view.close()


def test_time_filters_main_window_request_flow(
    qapp: QApplication, respx_mock: respx.MockRouter
) -> None:
    """MainWindow correctly passes start_time and end_time through ApiWorker."""
    client = APIClient(base_url="http://127.0.0.1:8000")
    client._token = "test-token"

    window = MainWindow(client=client)
    window.show()

    route = respx_mock.get("http://127.0.0.1:8000/api/events").respond(
        status_code=200,
        json={
            "total": 1,
            "items": [
                {
                    "id": SAMPLE_EVENT_ID_1,
                    "host_id": SAMPLE_HOST_ID,
                    "timestamp": SAMPLE_TIME_1,
                    "ingested_at": SAMPLE_TIME_1,
                    "source": "proc",
                    "event_type": "process.start",
                    "action": "start",
                    "severity": "info",
                    "created_at": SAMPLE_TIME_1,
                    "process_id": SAMPLE_PROCESS_ID,
                    "uid": 1000,
                    "username": "analyst",
                    "pid": 1234,
                    "ppid": 1,
                    "command": "/bin/ls",
                    "object_type": "process",
                    "object_path": None,
                    "success": True,
                    "result": "success",
                    "payload": {},
                }
            ],
            "limit": 50,
            "offset": 0,
        },
    )

    query = EventsQuery(
        start_time="2026-03-01T10:00:00Z",
        end_time="2026-03-01T18:00:00Z",
        limit=50,
        offset=0,
    )
    window.load_events(query)

    # Wait for background worker
    QThreadPool.globalInstance().waitForDone(5000)
    qapp.processEvents()

    assert route.called is True
    request = route.calls.last.request
    assert request.url.params["start_time"] == "2026-03-01T10:00:00Z"
    assert request.url.params["end_time"] == "2026-03-01T18:00:00Z"
    assert window.shell.events_view.model.rowCount() == 1

    window.close()
    client.close()


def test_events_query_to_client_kwargs_full() -> None:
    """EventsQuery exports all query parameters to client kwargs."""
    query = EventsQuery(
        severity="high",
        source="proc",
        event_type="process.spawn",
        pid=1234,
        host_id="11111111-1111-4111-8111-111111111111",
        start_time="2026-03-01T00:00:00Z",
        end_time="2026-03-01T23:59:59Z",
        limit=25,
        offset=5,
    )
    kwargs = query.to_client_kwargs()
    assert kwargs["event_type"] == "process.spawn"
    assert kwargs["host_id"] == "11111111-1111-4111-8111-111111111111"
    assert kwargs["limit"] == 25
    assert kwargs["offset"] == 5


def test_events_view_datetime_conversion_and_validation_gaps(
    qapp: QApplication,
) -> None:
    """_coerce_qdatetime handles complex ISO strings and raises on invalid."""
    view = EventsView()

    # Space separated ISO string handled by datetime.fromisoformat fallback
    qdt = view._coerce_qdatetime("2026-03-01 12:00:00+00:00")
    assert qdt.isValid()

    # Unsupported type raises TypeError
    with pytest.raises(TypeError, match="Unsupported datetime type"):
        view._coerce_qdatetime(12345)  # type: ignore[arg-type]

    # Validate inputs with invalid severity
    view._severity_combo.addItem("FakeSeverity", "super_critical")
    view._severity_combo.setCurrentIndex(view._severity_combo.count() - 1)
    res = view._validate_and_extract_filters()
    assert res is None
    assert "Invalid severity selected" in view._validation_label.text()

    # Table selection when selectedRows is empty
    view._handle_selection_changed()
    assert view._inspector.current_event is None


def test_events_view_properties_loading_guards_and_selection_fallbacks(
    qapp: QApplication,
) -> None:
    """EventsView exposes property aliases, guards in loading, and cell select."""
    from PySide6.QtCore import QItemSelectionModel
    from PySide6.QtWidgets import QCheckBox

    from desktop.client.models import EventCollection

    view = EventsView()

    # set_query TypeError
    with pytest.raises(TypeError, match="Expected EventsQuery"):
        view.set_query(42)  # type: ignore[arg-type]

    # Properties
    assert view.page_size == 50
    assert isinstance(view.filter_bar, QFrame)
    assert isinstance(view.pagination_bar, QFrame)
    assert isinstance(view.apply_filters_button, QPushButton)
    assert isinstance(view.clear_filters_button, QPushButton)
    assert isinstance(view.filter_validation_label, QLabel)
    assert isinstance(view.start_time_label, QLabel)
    assert isinstance(view.start_time_checkbox, QCheckBox)
    assert isinstance(view.end_time_label, QLabel)
    assert isinstance(view.end_time_checkbox, QCheckBox)
    assert isinstance(view.prev_page_button, QPushButton)
    assert isinstance(view.next_page_button, QPushButton)
    assert isinstance(view.page_range_label, QLabel)
    assert view.inspector_panel is view.inspector
    assert view.status_banner is not None

    # Loading guards
    view._state = "loading"
    emitted: list[Any] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    view.apply_filters()
    assert len(emitted) == 0

    view.clear_filters()
    assert len(emitted) == 0

    view.go_next_page()
    assert len(emitted) == 0

    view.go_prev_page()
    assert len(emitted) == 0

    # Cell selection fallback
    sample_evt = _make_event("evt-123", severity="critical")
    col = EventCollection(
        items=(sample_evt,), total=1, limit=50, offset=0
    )
    view.set_collection(col)

    # Select single cell (not full row)
    sel_model = view.table.selectionModel()
    idx = view.model.index(0, 1)
    sel_model.select(idx, QItemSelectionModel.SelectionFlag.Select)
    view._handle_selection_changed()
    assert view.selected_event == sample_evt

