"""Unit and integration tests for OSIRIS ProcessesView and Application Shell.

Verifies:
1. ProcessesView construction, layout, and stable object names.
2. QTableView integration with ProcessesTableModel.
3. No API client constructed inside visual view.
4. View state transitions: not_loaded, loading, loaded, empty, and failed.
5. Lazy loading contract: initial activation requests load; revisits do not.
6. Guarding against duplicate concurrent refreshes.
7. Real ProcessCollection presentation and metadata based on total.
8. Empty response handling and honest empty messaging.
9. Retained records distinguished from fresh results upon failed refresh.
10. Sanitized user-facing error messages for all typed exceptions.
11. Asynchronous MainWindow integration using ApiWorker and APIClient.get_processes.
12. Thread safety: API calls off GUI thread, widget updates on GUI thread.
13. Lifecycle safety: in-flight workers prevent premature close.
14. Regression: EventsView and other navigation items remain intact.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import FrozenInstanceError
from typing import Any
from unittest.mock import MagicMock

import pytest
from PySide6.QtCore import Qt, QThreadPool
from PySide6.QtGui import QCloseEvent
from PySide6.QtTest import QTest
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

from desktop.assets import load_stylesheet
from desktop.client.api_client import APIClient
from desktop.client.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ClientConnectionError,
    ConnectionTimeoutError,
    HTTPResponseError,
    OSIRISClientError,
    ValidationError,
)
from desktop.client.models import (
    EventCollection,
    Process,
    ProcessCollection,
    User,
)
from desktop.models.processes_model import ProcessesTableModel, ProcessRole
from desktop.ui.app_shell import AppShell
from desktop.ui.components import ProcessInspectorPanel
from desktop.ui.main_window import MainWindow
from desktop.ui.views.events_view import EventsView
from desktop.ui.views.processes_view import (
    ACTIVE_STATUS_CHOICES,
    DEFAULT_PAGE_SIZE,
    STATE_EMPTY,
    STATE_FAILED,
    STATE_LOADED,
    STATE_LOADING,
    STATE_NOT_LOADED,
    ProcessesQuery,
    ProcessesView,
)

SAMPLE_PROC_ID_1 = "11111111-1111-4111-8111-111111111111"
SAMPLE_PROC_ID_2 = "22222222-2222-4222-8222-222222222222"
SAMPLE_HOST_ID = "33333333-3333-4333-8333-333333333333"
SAMPLE_TIME_1 = "2026-03-01T12:00:00Z"
SAMPLE_TIME_2 = "2026-03-01T12:01:00Z"


def _sample_user() -> User:
    """Return a representative authenticated User instance."""
    return User(
        id="usr-proc-001",
        username="lead_analyst",
        display_name="Lead Analyst",
        role="admin",
        is_active=True,
        created_at="2026-01-01T00:00:00Z",
    )


def _make_process(
    process_id: str = SAMPLE_PROC_ID_1,
    host_id: str = SAMPLE_HOST_ID,
    pid: int = 1234,
    command: str = "/usr/bin/python3 -m app",
    started_at: str = SAMPLE_TIME_1,
    created_at: str = SAMPLE_TIME_1,
    ppid: int | None = 1,
    executable: str | None = "/usr/bin/python3",
    linux_user_id: str | None = None,
    ended_at: str | None = None,
) -> Process:
    """Create a valid Process instance for view tests."""
    return Process(
        id=process_id,
        host_id=host_id,
        pid=pid,
        command=command,
        started_at=started_at,
        created_at=created_at,
        ppid=ppid,
        executable=executable,
        linux_user_id=linux_user_id,
        ended_at=ended_at,
    )


def _make_collection(
    items: tuple[Process, ...] = (),
    total: int = 0,
    limit: int = 50,
    offset: int = 0,
) -> ProcessCollection:
    """Create a valid ProcessCollection instance."""
    return ProcessCollection(
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


def test_processes_view_instantiation(qapp: QApplication) -> None:
    """ProcessesView constructs successfully with required child widgets."""
    view = ProcessesView()
    assert view is not None
    assert isinstance(view, QWidget)
    assert view.objectName() == "Page_Processes"
    assert view.state == STATE_NOT_LOADED
    assert view.model.rowCount() == 0


def test_processes_view_stable_object_names(qapp: QApplication) -> None:
    """ProcessesView exposes stable object names across all key child controls."""
    view = ProcessesView()

    assert view.findChild(QLabel, "PageTitle") is not None
    assert view.findChild(QLabel, "PageDescription") is not None
    assert view.findChild(QFrame, "ProcessesFilterBar") is not None
    assert view.findChild(QLabel, "ProcessesActiveFilterLabel") is not None
    assert view.findChild(QComboBox, "ProcessesActiveFilterCombo") is not None
    assert view.findChild(QLabel, "ProcessesPidFilterLabel") is not None
    assert view.findChild(QLineEdit, "ProcessesPidFilterInput") is not None
    assert view.findChild(QLabel, "ProcessesHostIdFilterLabel") is not None
    assert view.findChild(QLineEdit, "ProcessesHostIdFilterInput") is not None
    assert view.findChild(QPushButton, "ApplyProcessesFiltersButton") is not None
    assert view.findChild(QPushButton, "ResetProcessesFiltersButton") is not None
    assert (
        view.findChild(QLabel, "ProcessesFilterValidationLabel") is not None
    )
    assert view.findChild(QFrame, "ProcessesToolbar") is not None
    assert view.findChild(QPushButton, "RefreshProcessesButton") is not None
    assert view.findChild(QLabel, "RecordCountSummary") is not None
    assert view.findChild(QFrame, "ProcessesStatusBanner") is not None
    assert view.findChild(QLabel, "ProcessesStatusBannerTitle") is not None
    assert view.findChild(QLabel, "ProcessesStatusBannerMessage") is not None
    assert (
        view.findChild(QPushButton, "QuickResetProcessesFiltersButton")
        is not None
    )
    assert view.findChild(QPushButton, "RetryProcessesButton") is not None
    assert view.findChild(QTableView, "ProcessesTable") is not None
    assert view.findChild(QFrame, "ProcessesPaginationFrame") is not None
    assert view.findChild(QPushButton, "PrevProcessesPageButton") is not None
    assert view.findChild(QPushButton, "NextProcessesPageButton") is not None
    assert view.findChild(QLabel, "ProcessesPageRangeLabel") is not None


def test_processes_view_does_not_instantiate_api_client(
    qapp: QApplication,
) -> None:
    """ProcessesView contains no APIClient instance or HTTP transport."""
    view = ProcessesView()
    assert not hasattr(view, "client")
    assert not hasattr(view, "_client")


def test_processes_table_backed_by_processes_table_model(
    qapp: QApplication,
) -> None:
    """ProcessesView table uses ProcessesTableModel with row selection."""
    view = ProcessesView()
    table = view.table
    assert isinstance(table.model(), ProcessesTableModel)
    assert table.isSortingEnabled() is False
    assert (
        table.selectionBehavior() == QTableView.SelectionBehavior.SelectRows
    )
    assert (
        table.editTriggers() == QTableView.EditTrigger.NoEditTriggers
    )


def test_refresh_processes_button_emits_signal(qapp: QApplication) -> None:
    """Clicking Refresh Processes emits the refresh_requested signal."""
    view = ProcessesView()
    emitted: list[bool] = []
    view.refresh_requested.connect(lambda: emitted.append(True))

    view.refresh_button.click()
    assert emitted == [True]


# ==============================================================================
# 2. View States and Transitions
# ==============================================================================


def test_initial_not_loaded_state(qapp: QApplication) -> None:
    """Initial state is not_loaded with descriptive banner and 0 count."""
    view = ProcessesView()
    view.show()
    assert view.state == STATE_NOT_LOADED
    assert view.status_banner.isVisible() is True
    assert "Not Loaded" in _label_text(view, "ProcessesStatusBannerTitle")
    assert "not loaded" in view.record_count_label.text()
    assert view.refresh_button.isEnabled() is True
    view.close()


def test_set_loading_disables_refresh_button(qapp: QApplication) -> None:
    """set_loading() disables refresh button and shows honest loading message."""
    view = ProcessesView()
    view.show()
    view.set_loading()

    assert view.state == STATE_LOADING
    assert view.refresh_button.isEnabled() is False
    assert view.status_banner.isVisible() is True
    assert "Loading" in _label_text(view, "ProcessesStatusBannerTitle")
    assert "Loading" in view.record_count_label.text()
    view.close()


def test_set_collection_with_results(qapp: QApplication) -> None:
    """set_collection() populates table, hides banner, restores button."""
    view = ProcessesView()
    view.show()
    p1 = _make_process(SAMPLE_PROC_ID_1, pid=101)
    p2 = _make_process(SAMPLE_PROC_ID_2, pid=102)
    col = _make_collection((p1, p2), total=2)

    view.set_loading()
    view.set_collection(col)

    assert view.state == STATE_LOADED
    assert view.model.rowCount() == 2
    assert view.status_banner.isVisible() is False
    assert view.refresh_button.isEnabled() is True
    assert "Showing 2 of 2 processes" in view.record_count_label.text()
    assert view.process_at(0) is p1
    assert view.process_at(1) is p2
    view.close()


def test_set_collection_empty_results(qapp: QApplication) -> None:
    """set_collection() with 0 processes enters empty state with honest banner."""
    view = ProcessesView()
    view.show()
    empty_col = _make_collection((), total=0)

    view.set_loading()
    view.set_collection(empty_col)

    assert view.state == STATE_EMPTY
    assert view.model.rowCount() == 0
    assert view.status_banner.isVisible() is True
    assert "No Processes Found" in (
        _label_text(view, "ProcessesStatusBannerTitle")
    )
    assert view.refresh_button.isEnabled() is True
    assert "0 displayed" in view.record_count_label.text()
    view.close()


def test_set_error_failed_state(qapp: QApplication) -> None:
    """set_error() enters failed state, displays message, and enables retry."""
    view = ProcessesView()
    view.show()
    view.set_loading()
    view.set_error("Connection timed out while querying API")

    assert view.state == STATE_FAILED
    assert view.status_banner.isVisible() is True
    assert view.retry_button.isVisible() is True
    assert view.refresh_button.isEnabled() is True
    assert "Connection timed out" in (
        _label_text(view, "ProcessesStatusBannerMessage")
    )
    assert "load failed" in view.record_count_label.text()
    view.close()


def test_retry_button_emits_refresh_requested(qapp: QApplication) -> None:
    """Clicking Retry button in error banner emits refresh_requested."""
    view = ProcessesView()
    view.set_error("Temporary failure")

    emitted: list[bool] = []
    view.refresh_requested.connect(lambda: emitted.append(True))
    view.retry_button.click()

    assert emitted == [True]


def test_set_not_loaded_clears_data_and_resets_ui(qapp: QApplication) -> None:
    """set_not_loaded() clears table records and resets query state."""
    view = ProcessesView()
    view.show()
    p = _make_process()
    view.set_collection(_make_collection((p,), total=100, limit=50, offset=50))
    assert view.model.rowCount() == 1
    assert view.current_query.offset == 50

    view.set_not_loaded()
    assert view.state == STATE_NOT_LOADED
    assert view.model.rowCount() == 0
    assert view.current_query.offset == 0
    assert view.current_query.has_active_filters is False
    assert view.status_banner.isVisible() is True
    assert "not loaded" in view.record_count_label.text()
    view.close()


def test_failed_refresh_preserves_older_records_distinctly(
    qapp: QApplication,
) -> None:
    """Failed refresh retains older records while explicitly marking them."""
    view = ProcessesView()
    p = _make_process(SAMPLE_PROC_ID_1)
    view.set_collection(_make_collection((p,), total=1))
    assert view.model.rowCount() == 1

    # Refresh starts
    view.set_loading()
    assert "refreshing..." in view.record_count_label.text()
    assert view.model.rowCount() == 1

    # Refresh fails
    view.set_error("Server error 500")
    assert view.state == STATE_FAILED
    assert view.model.rowCount() == 1
    assert "refresh failed" in view.record_count_label.text()
    assert "Retained 1 processes" in view.record_count_label.text()
    assert "retained records" in (
        _label_text(view, "ProcessesStatusBannerMessage").lower()
    )


def test_recovery_from_failed_state(qapp: QApplication) -> None:
    """Recovering from failed state transitions to loaded and clears error banner."""
    view = ProcessesView()
    view.set_error("Initial network failure")
    assert view.state == STATE_FAILED

    p = _make_process()
    view.set_collection(_make_collection((p,), total=1))
    assert view.state == STATE_LOADED
    assert view.status_banner.isVisible() is False
    assert view.model.rowCount() == 1


def test_set_collection_invalid_type_raises(qapp: QApplication) -> None:
    """Passing a non-ProcessCollection instance raises TypeError."""
    view = ProcessesView()
    with pytest.raises(TypeError, match="Expected ProcessCollection"):
        view.set_collection("invalid"  # type: ignore[arg-type]
        )


def test_set_error_invalid_type_raises(qapp: QApplication) -> None:
    """Passing a non-string message to set_error raises TypeError."""
    view = ProcessesView()
    with pytest.raises(TypeError, match="Expected str message"):
        view.set_error(12345  # type: ignore[arg-type]
        )


# ==============================================================================
# 3. Lazy-Loading & Shell Integration
# ==============================================================================


def test_no_api_request_during_view_construction(qapp: QApplication) -> None:
    """Constructing ProcessesView emits zero signals and triggers no loads."""
    load_emitted: list[bool] = []
    refresh_emitted: list[bool] = []

    view = ProcessesView()
    view.load_requested.connect(lambda: load_emitted.append(True))
    view.refresh_requested.connect(lambda: refresh_emitted.append(True))

    assert load_emitted == []
    assert refresh_emitted == []


def test_first_navigation_triggers_load_requested(qapp: QApplication) -> None:
    """First navigation to Processes triggers exactly one load_requested."""
    shell = AppShell()
    emitted: list[bool] = []
    shell.processes_load_requested.connect(lambda: emitted.append(True))

    shell.navigate_to("Processes")
    assert emitted == [True]


def test_repeated_navigation_does_not_redundantly_reload(
    qapp: QApplication,
) -> None:
    """Repeated navigation to Processes does not issue redundant requests."""
    shell = AppShell()
    emitted: list[bool] = []
    shell.processes_load_requested.connect(lambda: emitted.append(True))

    shell.navigate_to("Processes")
    assert len(emitted) == 1

    # Simulate loaded state
    shell.processes_view.set_collection(_make_collection((), total=0))

    # Navigate away and back
    shell.navigate_to("Overview")
    shell.navigate_to("Processes")
    assert len(emitted) == 1  # No duplicate load request


def test_app_shell_exposes_processes_view(qapp: QApplication) -> None:
    """AppShell exposes processes_view property returning the integrated view."""
    shell = AppShell()
    view = shell.processes_view
    assert isinstance(view, ProcessesView)
    assert shell.get_page_widget("Processes") is view


def test_app_shell_signals_forwarded(qapp: QApplication) -> None:
    """AppShell forwards processes load and refresh signals."""
    shell = AppShell()
    load_emitted: list[bool] = []
    refresh_emitted: list[bool] = []
    shell.processes_load_requested.connect(lambda: load_emitted.append(True))
    shell.processes_refresh_requested.connect(
        lambda: refresh_emitted.append(True)
    )

    shell.processes_view.load_requested.emit()
    assert load_emitted == [True]

    shell.processes_view.refresh_requested.emit()
    assert refresh_emitted == [True]


# ==============================================================================
# 4. API Worker and MainWindow Integration
# ==============================================================================


def test_main_window_loads_processes_via_api_worker(
    qapp: QApplication,
) -> None:
    """MainWindow dispatches process requests through ApiWorker and get_processes."""
    client = MagicMock(spec=APIClient)
    client.get_processes.return_value = _make_collection((), total=0)

    window = MainWindow(client=client, user=_sample_user())
    assert window.is_loading_processes is False

    window.load_processes()
    assert window.is_loading_processes is True

    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    assert window.is_loading_processes is False
    client.get_processes.assert_called_once_with(limit=50, offset=0)


def test_main_window_prevents_duplicate_in_flight_processes_requests(
    qapp: QApplication,
) -> None:
    """MainWindow ignores duplicate load_processes calls while one is running."""
    client = MagicMock(spec=APIClient)

    def slow_fetch() -> ProcessCollection:
        time.sleep(0.05)
        return _make_collection((), total=0)

    client.get_processes.side_effect = slow_fetch

    window = MainWindow(client=client, user=_sample_user())
    window.load_processes()
    assert window.is_loading_processes is True

    # Attempt second request while first is in flight
    window.load_processes()

    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    assert client.get_processes.call_count == 1


def test_main_window_handles_missing_client_gracefully(
    qapp: QApplication,
) -> None:
    """MainWindow sets error state when client is None."""
    window = MainWindow(client=None)
    window.load_processes()

    assert window.is_loading_processes is False
    assert window.processes_view.state == STATE_FAILED
    assert "No API client configured" in (
        _label_text(window.processes_view, "ProcessesStatusBannerMessage")
    )


def test_main_window_successful_processes_load(qapp: QApplication) -> None:
    """MainWindow applies retrieved ProcessCollection to the ProcessesView."""
    client = MagicMock(spec=APIClient)
    p = _make_process(pid=42, command="/usr/bin/daemon")
    client.get_processes.return_value = _make_collection((p,), total=1)

    window = MainWindow(client=client, user=_sample_user())
    window.load_processes()

    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    assert window.processes_view.state == STATE_LOADED
    assert window.processes_view.model.rowCount() == 1
    assert "Showing 1 of 1 processes" in (
        window.processes_view.record_count_label.text()
    )


def test_main_window_handles_empty_processes_collection(
    qapp: QApplication,
) -> None:
    """MainWindow handles empty collection with STATE_EMPTY."""
    client = MagicMock(spec=APIClient)
    client.get_processes.return_value = _make_collection((), total=0)

    window = MainWindow(client=client, user=_sample_user())
    window.load_processes()

    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    assert window.processes_view.state == STATE_EMPTY
    assert window.processes_view.model.rowCount() == 0


def test_main_window_superseded_request_sequence_guard_ignores_stale_result(
    qapp: QApplication,
) -> None:
    """Outdated process results from older request sequences are ignored."""
    client = MagicMock(spec=APIClient)
    window = MainWindow(client=client, user=_sample_user())
    initial = _make_collection((), total=0)
    window.shell.processes_view.set_collection(initial)

    window._processes_request_seq = 2

    # Receive result tagged with seq=1 (stale)
    p = _make_process()
    stale_collection = _make_collection((p,), total=1)
    window._on_processes_result(stale_collection, seq=1)

    assert window.shell.processes_view.model.rowCount() == 0


def test_main_window_superseded_request_sequence_guard_ignores_stale_error(
    qapp: QApplication,
) -> None:
    """Outdated process errors from older request sequences are ignored."""
    client = MagicMock(spec=APIClient)
    window = MainWindow(client=client, user=_sample_user())
    initial = _make_collection((), total=0)
    window.shell.processes_view.set_collection(initial)
    assert window.shell.processes_view.state == STATE_EMPTY

    window._processes_request_seq = 2

    # Receive error tagged with seq=1 (stale)
    window._on_processes_error(RuntimeError("Stale process error"), seq=1)

    assert window.shell.processes_view.state == STATE_EMPTY


@pytest.mark.parametrize(
    "exception, expected_fragment",
    [
        (
            AuthenticationError("Session expired"),
            "Authentication session expired",
        ),
        (
            AuthorizationError("Forbidden"),
            "Access denied",
        ),
        (
            ConnectionTimeoutError("Timed out"),
            "timed out",
        ),
        (
            ClientConnectionError("Network down"),
            "Unable to connect",
        ),
        (
            HTTPResponseError("Server error", status_code=500),
            "API request failed (HTTP 500)",
        ),
        (
            ValidationError("Bad data"),
            "Invalid process data",
        ),
        (
            OSIRISClientError("Client error message"),
            "Client error message",
        ),
        (
            ValueError("Unexpected problem"),
            "An unexpected error occurred: ValueError",
        ),
    ],
)
def test_main_window_handles_processes_error_sanitization(
    qapp: QApplication,
    exception: Exception,
    expected_fragment: str,
) -> None:
    """MainWindow sanitizes typed exceptions into safe user-facing text."""
    client = MagicMock(spec=APIClient)
    client.get_processes.side_effect = exception

    window = MainWindow(client=client, user=_sample_user())
    window.load_processes()

    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    assert window.processes_view.state == STATE_FAILED
    msg = _label_text(window.processes_view, "ProcessesStatusBannerMessage")
    assert expected_fragment in msg


def test_main_window_deferred_close_with_active_processes_worker(
    qapp: QApplication,
) -> None:
    """Closing MainWindow while process worker is active defers close safely."""
    client = MagicMock(spec=APIClient)

    def slow_fetch() -> ProcessCollection:
        time.sleep(0.05)
        return _make_collection((), total=0)

    client.get_processes.side_effect = slow_fetch

    window = MainWindow(client=client, user=_sample_user())
    window.show()
    window.load_processes()

    assert window.is_loading_processes is True
    assert window.has_active_workers is True

    # Send closeEvent
    event = QCloseEvent()
    window.closeEvent(event)

    assert not event.isAccepted()
    assert window._pending_close is True
    assert window.isVisible() is False

    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    assert window.is_loading_processes is False


def test_main_window_logout_defers_close_if_processes_worker_active(
    qapp: QApplication,
) -> None:
    """Logging out while process worker is active defers close until completion."""
    client = MagicMock(spec=APIClient)

    def slow_fetch() -> ProcessCollection:
        time.sleep(0.05)
        return _make_collection((), total=0)

    client.get_processes.side_effect = slow_fetch

    window = MainWindow(client=client, user=_sample_user())
    window.show()
    window.load_processes()

    assert window.is_loading_processes is True

    emitted: list[bool] = []
    window.logout_requested.connect(lambda: emitted.append(True))

    window.shell.logout_button.click()

    client.logout.assert_called_once()
    assert emitted == [True]
    assert window._pending_close is True
    assert window.isVisible() is False

    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    assert window.is_loading_processes is False


def test_process_request_sequencing_isolated_from_events_and_status(
    qapp: QApplication,
) -> None:
    """Process requests do not collide with event sequences or status checks."""
    client = MagicMock(spec=APIClient)
    client.get_processes.return_value = _make_collection((), total=0)
    client.get_events.return_value = EventCollection(
        total=0, items=(), limit=50, offset=0
    )
    client.health_check.return_value = MagicMock(status="ok", system="osiris")
    client.get_status.return_value = MagicMock(
        status="healthy", system="osiris", database="connected", host_id="test"
    )

    window = MainWindow(client=client, user=_sample_user())

    window.check_operational_status()
    window.load_events()
    window.load_processes()

    assert window.is_checking_status is True
    assert window.is_loading_events is True
    assert window.is_loading_processes is True
    assert window.has_active_workers is True

    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    assert window.is_checking_status is False
    assert window.is_loading_events is False
    assert window.is_loading_processes is False
    assert window.has_active_workers is False


# ==============================================================================
# 5. Regression & Style Verification
# ==============================================================================


def test_stylesheet_contains_processes_view_selectors() -> None:
    """Verify Section 21 processes view and toolbar selectors exist in QSS."""
    qss = load_stylesheet()
    assert "QFrame#ProcessesToolbar" in qss
    assert "QPushButton#RefreshProcessesButton" in qss
    assert "QFrame#ProcessesStatusBanner" in qss
    assert 'QFrame#ProcessesStatusBanner[state="loading"]' in qss
    assert 'QFrame#ProcessesStatusBanner[state="empty"]' in qss
    assert 'QFrame#ProcessesStatusBanner[state="failed"]' in qss
    assert 'QFrame#ProcessesStatusBanner[state="not_loaded"]' in qss
    assert "QLabel#ProcessesStatusBannerTitle" in qss
    assert "QLabel#ProcessesStatusBannerMessage" in qss
    assert "QPushButton#RetryProcessesButton" in qss
    assert "QTableView#ProcessesTable" in qss

    # Filter toolbar
    assert "QFrame#ProcessesFilterBar" in qss
    assert "QLabel#ProcessesActiveFilterLabel" in qss
    assert "QComboBox#ProcessesActiveFilterCombo" in qss
    assert "QLabel#ProcessesPidFilterLabel" in qss
    assert "QLineEdit#ProcessesPidFilterInput" in qss
    assert "QLabel#ProcessesHostIdFilterLabel" in qss
    assert "QLineEdit#ProcessesHostIdFilterInput" in qss
    assert "QPushButton#ApplyProcessesFiltersButton" in qss
    assert "QPushButton#ResetProcessesFiltersButton" in qss
    assert "QLabel#ProcessesFilterValidationLabel" in qss
    assert 'QLabel#ProcessesFilterValidationLabel[error="true"]' in qss
    assert "QPushButton#QuickResetProcessesFiltersButton" in qss

    # Pagination bar
    assert "QFrame#ProcessesPaginationFrame" in qss
    assert "QPushButton#PrevProcessesPageButton" in qss
    assert "QPushButton#NextProcessesPageButton" in qss
    assert "QLabel#ProcessesPageRangeLabel" in qss


def test_events_view_behavior_unaffected(qapp: QApplication) -> None:
    """EventsView remains functional alongside ProcessesView in AppShell."""
    shell = AppShell()
    assert isinstance(shell.events_view, EventsView)
    assert isinstance(shell.processes_view, ProcessesView)

    shell.navigate_to("Events")
    assert shell.current_page_name == "Events"
    assert shell.toolbar_context_label.text() == "Security Events"

    shell.navigate_to("Processes")
    assert shell.current_page_name == "Processes"
    assert shell.toolbar_context_label.text() == "Process Activity"


# ==============================================================================
# 6. ProcessesQuery Model Tests
# ==============================================================================


def test_processes_query_defaults() -> None:
    """ProcessesQuery defaults to unconstrained filters and limit 50 offset 0."""
    query = ProcessesQuery()
    assert query.is_active is None
    assert query.pid is None
    assert query.host_id is None
    assert query.limit == DEFAULT_PAGE_SIZE
    assert query.offset == 0
    assert query.has_active_filters is False
    assert query.to_client_kwargs() == {"limit": 50, "offset": 0}


def test_processes_query_immutability() -> None:
    """ProcessesQuery instances are frozen and reject in-place attribute mutation."""
    query = ProcessesQuery()
    with pytest.raises(FrozenInstanceError):
        query.offset = 10  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        query.is_active = True  # type: ignore[misc]


def test_processes_query_active_status_choices() -> None:
    """ProcessesQuery supports None, True, and False for status filtering."""
    q_all = ProcessesQuery(is_active=None)
    assert "is_active" not in q_all.to_client_kwargs()
    assert q_all.has_active_filters is False

    q_active = ProcessesQuery(is_active=True)
    assert q_active.to_client_kwargs()["is_active"] is True
    assert q_active.has_active_filters is True

    q_term = ProcessesQuery(is_active=False)
    assert q_term.to_client_kwargs()["is_active"] is False
    assert q_term.has_active_filters is True

    with pytest.raises(ValueError, match="is_active must be a boolean or None"):
        ProcessesQuery(is_active="active")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="is_active must be a boolean or None"):
        ProcessesQuery(is_active=1)  # type: ignore[arg-type]


def test_processes_query_pid_validation() -> None:
    """ProcessesQuery preserves pid=0, allows positive ints, rejects booleans."""
    q_zero = ProcessesQuery(pid=0)
    assert q_zero.pid == 0
    assert q_zero.to_client_kwargs()["pid"] == 0
    assert q_zero.has_active_filters is True

    q_pos = ProcessesQuery(pid=12345)
    assert q_pos.pid == 12345
    assert q_pos.to_client_kwargs()["pid"] == 12345

    with pytest.raises(ValueError, match="pid must be a non-negative integer"):
        ProcessesQuery(pid=-1)
    with pytest.raises(ValueError, match="pid must be a non-negative integer"):
        ProcessesQuery(pid=True)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="pid must be a non-negative integer"):
        ProcessesQuery(pid=False)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="pid must be a non-negative integer"):
        ProcessesQuery(pid="100")  # type: ignore[arg-type]


def test_processes_query_host_id_validation() -> None:
    """ProcessesQuery validates host_id as UUID and normalizes canonical string."""
    q_uuid = ProcessesQuery(host_id=SAMPLE_HOST_ID)
    assert q_uuid.host_id == SAMPLE_HOST_ID
    assert q_uuid.has_active_filters is True
    assert q_uuid.to_client_kwargs()["host_id"] == SAMPLE_HOST_ID

    # Accept uuid.UUID instance
    raw_uuid = uuid.UUID(SAMPLE_HOST_ID)
    q_obj = ProcessesQuery(host_id=raw_uuid)
    assert q_obj.host_id == SAMPLE_HOST_ID

    # Normalize uppercase UUID
    upper_uuid = SAMPLE_HOST_ID.upper()
    q_upper = ProcessesQuery(host_id=upper_uuid)
    assert q_upper.host_id == SAMPLE_HOST_ID

    with pytest.raises(ValueError, match="host_id must be a valid UUID"):
        ProcessesQuery(host_id="not-a-uuid")
    with pytest.raises(ValueError, match="host_id must be a UUID string or None"):
        ProcessesQuery(host_id=True)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="host_id must be a UUID string or None"):
        ProcessesQuery(host_id=1234)  # type: ignore[arg-type]


def test_processes_query_page_index() -> None:
    """ProcessesQuery calculates 0-based page_index from offset and limit."""
    assert ProcessesQuery(limit=50, offset=0).page_index == 0
    assert ProcessesQuery(limit=50, offset=50).page_index == 1
    assert ProcessesQuery(limit=50, offset=120).page_index == 2
    assert ProcessesQuery(limit=25, offset=100).page_index == 4


def test_processes_query_limit_offset_validation() -> None:
    """ProcessesQuery enforces limit 1..100 and offset >= 0, rejecting booleans."""
    q_valid = ProcessesQuery(limit=1, offset=0)
    assert q_valid.limit == 1
    assert q_valid.offset == 0

    q_max = ProcessesQuery(limit=100, offset=500)
    assert q_max.limit == 100
    assert q_max.offset == 500

    with pytest.raises(
        ValueError, match="limit must be an integer between 1 and 100"
    ):
        ProcessesQuery(limit=0)
    with pytest.raises(
        ValueError, match="limit must be an integer between 1 and 100"
    ):
        ProcessesQuery(limit=101)
    with pytest.raises(
        ValueError, match="limit must be an integer between 1 and 100"
    ):
        ProcessesQuery(limit=True)  # type: ignore[arg-type]
    with pytest.raises(
        ValueError, match="offset must be a non-negative integer"
    ):
        ProcessesQuery(offset=-1)
    with pytest.raises(
        ValueError, match="offset must be a non-negative integer"
    ):
        ProcessesQuery(offset=False)  # type: ignore[arg-type]


def test_processes_query_to_client_kwargs_omission_and_preservation() -> None:
    """Unset filters are omitted while is_active=False and pid=0 are preserved."""
    q_empty = ProcessesQuery()
    assert q_empty.to_client_kwargs() == {"limit": 50, "offset": 0}

    q_false_zero = ProcessesQuery(is_active=False, pid=0)
    kwargs = q_false_zero.to_client_kwargs()
    assert kwargs == {"limit": 50, "offset": 0, "is_active": False, "pid": 0}


def test_processes_query_equality_and_deterministic_hash() -> None:
    """Queries with matching attributes evaluate equal and produce identical hashes."""
    q1 = ProcessesQuery(is_active=True, pid=42, host_id=SAMPLE_HOST_ID)
    q2 = ProcessesQuery(is_active=True, pid=42, host_id=SAMPLE_HOST_ID)
    q3 = ProcessesQuery(is_active=False, pid=42, host_id=SAMPLE_HOST_ID)

    assert q1 == q2
    assert hash(q1) == hash(q2)
    assert q1 != q3


# ==============================================================================
# 7. ProcessesFilterBar UI Tests
# ==============================================================================


def test_filter_bar_structure_and_defaults(qapp: QApplication) -> None:
    """ProcessesFilterBar exposes status dropdown, inputs, and action buttons."""
    view = ProcessesView()
    assert view.filter_bar is not None
    assert view.active_filter_combo.count() == 3

    choices = [
        (
            view.active_filter_combo.itemText(i),
            view.active_filter_combo.itemData(i),
        )
        for i in range(view.active_filter_combo.count())
    ]
    assert choices == list(ACTIVE_STATUS_CHOICES)
    assert view.active_filter_combo.currentIndex() == 0
    assert view.pid_input.text() == ""
    assert view.host_id_input.text() == ""
    assert view.filter_validation_label.text() == ""
    assert view.current_query == ProcessesQuery(limit=50, offset=0)


def test_apply_filters_with_valid_criteria(qapp: QApplication) -> None:
    """Applying valid filters emits query_requested with normalized ProcessesQuery."""
    view = ProcessesView()
    emitted: list[ProcessesQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    view.active_filter_combo.setCurrentIndex(1)  # Active Only (True)
    view.pid_input.setText("   1024   ")
    view.host_id_input.setText(f"   {SAMPLE_HOST_ID}   ")

    view.apply_filters_button.click()

    assert len(emitted) == 1
    query = emitted[0]
    assert query.is_active is True
    assert query.pid == 1024
    assert query.host_id == SAMPLE_HOST_ID
    assert query.offset == 0
    assert query.limit == 50
    assert query.has_active_filters is True
    assert view.filter_validation_label.text() == ""


def test_apply_filters_preserves_pid_zero(qapp: QApplication) -> None:
    """PID 0 is a valid process ID and is preserved faithfully."""
    view = ProcessesView()
    emitted: list[ProcessesQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    view.pid_input.setText("0")
    view.apply_filters_button.click()

    assert len(emitted) == 1
    assert emitted[0].pid == 0
    assert emitted[0].to_client_kwargs()["pid"] == 0


def test_apply_filters_terminated_status(qapp: QApplication) -> None:
    """Selecting Terminated Only emits query with is_active=False."""
    view = ProcessesView()
    emitted: list[ProcessesQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    view.active_filter_combo.setCurrentIndex(2)  # Terminated Only (False)
    view.apply_filters_button.click()

    assert len(emitted) == 1
    assert emitted[0].is_active is False
    assert emitted[0].to_client_kwargs()["is_active"] is False


def test_apply_filters_rejects_negative_pid(qapp: QApplication) -> None:
    """Negative PID triggers validation error without emitting a query."""
    view = ProcessesView()
    emitted: list[ProcessesQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    view.pid_input.setText("-10")
    view.apply_filters_button.click()

    assert emitted == []
    assert "non-negative integer" in view.filter_validation_label.text()


def test_apply_filters_rejects_non_numeric_pid(qapp: QApplication) -> None:
    """Non-numeric PID triggers validation error without emitting a query."""
    view = ProcessesView()
    emitted: list[ProcessesQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    view.pid_input.setText("process_abc")
    view.apply_filters_button.click()

    assert emitted == []
    assert "non-negative integer" in view.filter_validation_label.text()


def test_apply_filters_rejects_malformed_host_uuid(qapp: QApplication) -> None:
    """Malformed host UUID triggers validation error without emitting a query."""
    view = ProcessesView()
    emitted: list[ProcessesQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    view.host_id_input.setText("invalid-uuid-format")
    view.apply_filters_button.click()

    assert emitted == []
    assert "valid UUID" in view.filter_validation_label.text()


def test_apply_filters_invalid_input_preserves_committed_query(
    qapp: QApplication,
) -> None:
    """Invalid filter attempts retain the previously committed query."""
    view = ProcessesView()
    view.pid_input.setText("42")
    view.apply_filters_button.click()
    committed = view.current_query
    assert committed.pid == 42

    # Attempt invalid PID
    view.pid_input.setText("-99")
    view.apply_filters_button.click()

    assert view.current_query == committed
    assert view.current_query.pid == 42


def test_filter_validation_label_accessibility(qapp: QApplication) -> None:
    """ProcessesFilterValidationLabel exposes accessible name and dynamic error.
    """
    view = ProcessesView()
    label = view.filter_validation_label
    assert label.accessibleName() == "Filter Validation Message"
    assert label.accessibleDescription() == ""
    assert label.property("error") == "false"

    view.pid_input.setText("-5")
    view.apply_filters_button.click()

    assert "non-negative integer" in label.text()
    assert label.accessibleDescription() == label.text()
    assert label.property("error") == "true"

    view.clear_filters_button.click()
    assert label.text() == ""
    assert label.accessibleDescription() == ""
    assert label.property("error") == "false"


def test_clear_filters_restores_defaults_and_resets_offset(
    qapp: QApplication,
) -> None:
    """Clear Filters restores all fields to default and emits query with offset 0."""
    view = ProcessesView()
    emitted: list[ProcessesQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    # Set initial filter values
    view.active_filter_combo.setCurrentIndex(1)
    view.pid_input.setText("1234")
    view.host_id_input.setText(SAMPLE_HOST_ID)
    view.apply_filters_button.click()
    assert len(emitted) == 1

    # Simulate navigating to page 2
    view.go_next_page()

    # Clear filters
    view.clear_filters_button.click()

    assert view.active_filter_combo.currentIndex() == 0
    assert view.pid_input.text() == ""
    assert view.host_id_input.text() == ""
    assert view.filter_validation_label.text() == ""
    assert view.current_query.offset == 0
    assert view.current_query.has_active_filters is False


def test_filter_enter_key_triggers_apply(qapp: QApplication) -> None:
    """Pressing return on PID or Host ID line edit executes apply_filters."""
    view = ProcessesView()
    emitted: list[ProcessesQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    view.pid_input.setText("555")
    view.pid_input.returnPressed.emit()

    assert len(emitted) == 1
    assert emitted[0].pid == 555

    view.host_id_input.setText(SAMPLE_HOST_ID)
    view.host_id_input.returnPressed.emit()

    assert len(emitted) == 2
    assert emitted[1].host_id == SAMPLE_HOST_ID


def test_changing_filter_widgets_does_not_dispatch_query(
    qapp: QApplication,
) -> None:
    """Modifying widgets without clicking Apply triggers zero queries."""
    view = ProcessesView()
    emitted: list[ProcessesQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    view.active_filter_combo.setCurrentIndex(1)
    view.pid_input.setText("789")
    view.host_id_input.setText(SAMPLE_HOST_ID)

    assert emitted == []


# ==============================================================================
# 8. Pagination Tests
# ==============================================================================


def test_pagination_bar_structure_and_defaults(qapp: QApplication) -> None:
    """Pagination bar exposes prev/next buttons and page range label."""
    view = ProcessesView()
    assert view.pagination_bar is not None
    assert view.prev_page_button.isEnabled() is False
    assert view.next_page_button.isEnabled() is False
    assert view.page_range_label.text() == "0 of 0 processes"


def test_pagination_first_page_of_multi_page(qapp: QApplication) -> None:
    """First page disables Previous and enables Next when more items exist."""
    view = ProcessesView()
    p_items = tuple(_make_process(f"id-{i}", pid=1000 + i) for i in range(50))
    col = _make_collection(p_items, total=120, limit=50, offset=0)

    view.set_collection(col)

    assert view.prev_page_button.isEnabled() is False
    assert view.next_page_button.isEnabled() is True
    assert "Showing 1–50 of 120 processes" in view.page_range_label.text()


def test_pagination_middle_page(qapp: QApplication) -> None:
    """Middle page enables both Previous and Next."""
    view = ProcessesView()
    p_items = tuple(_make_process(f"id-{i}", pid=1000 + i) for i in range(50))
    col = _make_collection(p_items, total=120, limit=50, offset=50)

    view.set_collection(col)

    assert view.prev_page_button.isEnabled() is True
    assert view.next_page_button.isEnabled() is True
    assert "Showing 51–100 of 120 processes" in view.page_range_label.text()


def test_pagination_last_page(qapp: QApplication) -> None:
    """Last page enables Previous and disables Next."""
    view = ProcessesView()
    p_items = tuple(_make_process(f"id-{i}", pid=1000 + i) for i in range(20))
    col = _make_collection(p_items, total=120, limit=50, offset=100)

    view.set_collection(col)

    assert view.prev_page_button.isEnabled() is True
    assert view.next_page_button.isEnabled() is False
    assert "Showing 101–120 of 120 processes" in view.page_range_label.text()


def test_pagination_single_page(qapp: QApplication) -> None:
    """Single page result set disables both Previous and Next."""
    view = ProcessesView()
    p_items = tuple(_make_process(f"id-{i}", pid=1000 + i) for i in range(20))
    col = _make_collection(p_items, total=20, limit=50, offset=0)

    view.set_collection(col)

    assert view.prev_page_button.isEnabled() is False
    assert view.next_page_button.isEnabled() is False
    assert "Showing 1–20 of 20 processes" in view.page_range_label.text()


def test_pagination_empty_results(qapp: QApplication) -> None:
    """Empty result set disables both Previous and Next and shows 0 of 0."""
    view = ProcessesView()
    col = _make_collection((), total=0, limit=50, offset=0)

    view.set_collection(col)

    assert view.prev_page_button.isEnabled() is False
    assert view.next_page_button.isEnabled() is False
    assert view.page_range_label.text() == "0 of 0 processes"


def test_pagination_empty_page_with_positive_total_disables_next(
    qapp: QApplication,
) -> None:
    """Empty result set with positive total disables Next button."""
    view = ProcessesView()
    col = _make_collection((), total=120, limit=50, offset=100)

    view.set_collection(col)

    assert view.prev_page_button.isEnabled() is True
    assert view.next_page_button.isEnabled() is False


def test_pagination_next_button_advances_offset(qapp: QApplication) -> None:
    """Clicking Next emits query with offset advanced by limit."""
    view = ProcessesView()
    p_items = tuple(_make_process(f"id-{i}", pid=1000 + i) for i in range(50))
    view.set_collection(
        _make_collection(p_items, total=120, limit=50, offset=0)
    )

    emitted: list[ProcessesQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    view.next_page_button.click()

    assert len(emitted) == 1
    assert emitted[0].offset == 50
    assert emitted[0].limit == 50


def test_pagination_prev_button_decrements_offset(qapp: QApplication) -> None:
    """Clicking Previous emits query with offset decremented by limit."""
    view = ProcessesView()
    p_items = tuple(_make_process(f"id-{i}", pid=1000 + i) for i in range(50))
    view.set_collection(
        _make_collection(p_items, total=120, limit=50, offset=50)
    )

    emitted: list[ProcessesQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    view.prev_page_button.click()

    assert len(emitted) == 1
    assert emitted[0].offset == 0
    assert emitted[0].limit == 50


def test_pagination_preserves_active_filters(qapp: QApplication) -> None:
    """Moving pages preserves active filter values without clearing them."""
    view = ProcessesView()
    view.pid_input.setText("999")
    view.apply_filters_button.click()

    p_items = tuple(_make_process(f"id-{i}", pid=999) for i in range(50))
    view.set_collection(
        _make_collection(p_items, total=120, limit=50, offset=0)
    )

    emitted: list[ProcessesQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    view.next_page_button.click()

    assert len(emitted) == 1
    assert emitted[0].pid == 999
    assert emitted[0].offset == 50


def test_apply_filters_resets_pagination_offset(qapp: QApplication) -> None:
    """Applying new or changed filters resets offset to 0."""
    view = ProcessesView()
    p_items = tuple(_make_process(f"id-{i}", pid=1000 + i) for i in range(50))
    view.set_collection(
        _make_collection(p_items, total=120, limit=50, offset=50)
    )
    assert view.current_query.offset == 50

    emitted: list[ProcessesQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    view.pid_input.setText("2000")
    view.apply_filters_button.click()

    assert len(emitted) == 1
    assert emitted[0].offset == 0
    assert emitted[0].pid == 2000


def test_clear_filters_resets_pagination_offset(qapp: QApplication) -> None:
    """Clearing filters resets pagination offset to 0."""
    view = ProcessesView()
    p_items = tuple(_make_process(f"id-{i}", pid=1000 + i) for i in range(50))
    view.set_collection(
        _make_collection(p_items, total=120, limit=50, offset=50)
    )

    emitted: list[ProcessesQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    view.clear_filters_button.click()

    assert len(emitted) == 1
    assert emitted[0].offset == 0
    assert emitted[0].has_active_filters is False


def test_disabled_pagination_buttons_do_not_dispatch_query(
    qapp: QApplication,
) -> None:
    """Disabled pagination buttons ignore clicks and emit zero queries."""
    view = ProcessesView()
    emitted: list[ProcessesQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    # At offset 0, prev is disabled
    view.go_prev_page()
    assert emitted == []

    # Single page results, next is disabled
    view.set_collection(_make_collection((_make_process(),), total=1))
    view.go_next_page()
    assert emitted == []


# ==============================================================================
# 9. Empty Filtered State & Quick Reset
# ==============================================================================


def test_empty_filtered_state_messaging_and_quick_reset(
    qapp: QApplication,
) -> None:
    """Empty response with active filters displays filter message and quick reset."""
    view = ProcessesView()
    view.show()
    view.pid_input.setText("99999")
    view.apply_filters_button.click()

    view.set_loading()
    view.set_collection(_make_collection((), total=0))

    assert view.state == STATE_EMPTY
    assert "No processes found matching the selected filters" in (
        _label_text(view, "ProcessesStatusBannerMessage")
    )
    assert view.quick_reset_button.isVisible() is True

    # Click quick reset button on banner
    emitted: list[ProcessesQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    view.quick_reset_button.click()

    assert len(emitted) == 1
    assert emitted[0].has_active_filters is False
    assert emitted[0].offset == 0
    assert view.pid_input.text() == ""
    view.close()


def test_empty_unfiltered_state_messaging(qapp: QApplication) -> None:
    """Empty response without active filters displays system empty banner."""
    view = ProcessesView()
    view.show()
    view.set_loading()
    view.set_collection(_make_collection((), total=0))

    assert view.state == STATE_EMPTY
    assert "The server returned zero processes for this system." in (
        _label_text(view, "ProcessesStatusBannerMessage")
    )
    assert view.quick_reset_button.isVisible() is False
    view.close()


# ==============================================================================
# 10. Integration & Query Dispatch Tests
# ==============================================================================


def test_main_window_load_processes_with_query_passes_kwargs(
    qapp: QApplication,
) -> None:
    """MainWindow passes normalized query kwargs to APIClient.get_processes."""
    client = MagicMock(spec=APIClient)
    client.get_processes.return_value = _make_collection((), total=0)
    window = MainWindow(client=client)

    query = ProcessesQuery(
        is_active=False,
        pid=0,
        host_id=SAMPLE_HOST_ID,
        limit=25,
        offset=50,
    )
    window.load_processes(query)

    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    client.get_processes.assert_called_once_with(
        limit=25,
        offset=50,
        is_active=False,
        pid=0,
        host_id=SAMPLE_HOST_ID,
    )


def test_main_window_processes_view_query_requested_signal_wired(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Emitting query_requested on ProcessesView invokes MainWindow.load_processes."""
    client = MagicMock(spec=APIClient)
    window = MainWindow(client=client)
    mock_load = MagicMock()
    monkeypatch.setattr(window, "load_processes", mock_load)

    query = ProcessesQuery(is_active=True, pid=123, limit=50, offset=0)
    window.shell.processes_view.query_requested.emit(query)

    mock_load.assert_called_once_with(query)


def test_main_window_refresh_repeats_current_committed_query(
    qapp: QApplication,
) -> None:
    """Refresh button on ProcessesView re-dispatches active query with all filters."""
    client = MagicMock(spec=APIClient)
    client.get_processes.return_value = _make_collection((), total=0)
    window = MainWindow(client=client, user=_sample_user())

    # Set committed query
    committed_query = ProcessesQuery(
        is_active=True,
        pid=42,
        host_id=SAMPLE_HOST_ID,
        limit=50,
        offset=0,
    )
    window.shell.processes_view._current_query = committed_query

    # Click refresh
    window.shell.processes_view.refresh_button.click()

    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    client.get_processes.assert_called_once_with(
        limit=50,
        offset=0,
        is_active=True,
        pid=42,
        host_id=SAMPLE_HOST_ID,
    )


def test_main_window_failed_request_preserves_records_and_query(
    qapp: QApplication,
) -> None:
    """Failed request preserves both previous records and the active query."""
    client = MagicMock(spec=APIClient)
    p = _make_process()
    client.get_processes.return_value = _make_collection((p,), total=1)
    window = MainWindow(client=client, user=_sample_user())

    # Initial successful load
    window.load_processes()
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()
    assert window.processes_view.state == STATE_LOADED
    assert window.processes_view.model.rowCount() == 1

    # Second request fails
    client.get_processes.side_effect = ConnectionTimeoutError("Timed out")
    window.load_processes()
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    assert window.processes_view.state == STATE_FAILED
    assert window.processes_view.model.rowCount() == 1
    assert "refresh failed" in window.processes_view.record_count_label.text()
    assert window.processes_view.current_query.offset == 0


def test_app_shell_processes_query_requested_signal_forwarded(
    qapp: QApplication,
) -> None:
    """AppShell forwards processes_query_requested when view emits query_requested."""
    shell = AppShell()
    emitted: list[ProcessesQuery] = []
    shell.processes_query_requested.connect(lambda q: emitted.append(q))

    query = ProcessesQuery(pid=777, limit=50, offset=0)
    shell.processes_view.query_requested.emit(query)

    assert len(emitted) == 1
    assert emitted[0] == query


# ==============================================================================
# 11. Process Details Inspector Panel & Row Selection (Task 0.4.15)
# ==============================================================================


def test_inspector_panel_initial_unselected_state(qapp: QApplication) -> None:
    """Inspector is present on ProcessesView, initially hidden, with no process."""
    view = ProcessesView()
    assert isinstance(view.inspector, ProcessInspectorPanel)
    assert view.inspector is view.inspector_panel
    assert view.inspector.isVisible() is False
    assert view.selected_process is None
    assert view.inspector.current_process is None


def test_row_selection_displays_original_process_in_inspector(
    qapp: QApplication,
) -> None:
    """Selecting a valid table row shows details for its original Process object."""
    view = ProcessesView()
    view.show()
    p1 = _make_process(SAMPLE_PROC_ID_1, command="/usr/bin/app1")
    p2 = _make_process(SAMPLE_PROC_ID_2, command="/usr/bin/app2")
    view.set_collection(_make_collection((p1, p2), total=2))

    assert view.inspector.isVisible() is False

    # Select row 0
    view.table.selectRow(0)
    qapp.processEvents()

    assert view.inspector.isVisible() is True
    assert view.selected_process is p1
    assert view.inspector.current_process is p1
    assert view.inspector.get_field_value("id") == SAMPLE_PROC_ID_1
    assert view.inspector.get_field_value("command") == "/usr/bin/app1"

    # Verify model data returns exact same object via ProcessRole
    idx = view.table.model().index(0, 0)
    assert view.table.model().data(idx, ProcessRole) is p1
    view.close()


def test_selecting_different_row_updates_inspector(
    qapp: QApplication,
) -> None:
    """Selecting a different table row updates the inspector to the new Process."""
    view = ProcessesView()
    view.show()
    p1 = _make_process(SAMPLE_PROC_ID_1, command="/usr/bin/app1")
    p2 = _make_process(SAMPLE_PROC_ID_2, command="/usr/bin/app2")
    view.set_collection(_make_collection((p1, p2), total=2))

    view.table.selectRow(0)
    assert view.selected_process is p1

    # Select row 1
    view.table.selectRow(1)
    qapp.processEvents()

    assert view.selected_process is p2
    assert view.inspector.current_process is p2
    assert view.inspector.get_field_value("id") == SAMPLE_PROC_ID_2
    assert view.inspector.get_field_value("command") == "/usr/bin/app2"
    view.close()


def test_arrow_key_selection_updates_inspector(qapp: QApplication) -> None:
    """Keyboard navigation with arrow keys updates the inspector details."""
    view = ProcessesView()
    view.show()
    p1 = _make_process(SAMPLE_PROC_ID_1, command="/usr/bin/app1")
    p2 = _make_process(SAMPLE_PROC_ID_2, command="/usr/bin/app2")
    view.set_collection(_make_collection((p1, p2), total=2))

    view.table.selectRow(0)
    qapp.processEvents()
    assert view.selected_process is p1

    # Send down arrow key click
    view.table.setFocus()
    QTest.keyClick(view.table, Qt.Key.Key_Down)
    qapp.processEvents()

    assert view.selected_process is p2
    assert view.inspector.current_process is p2

    # Send up arrow key click
    QTest.keyClick(view.table, Qt.Key.Key_Up)
    qapp.processEvents()

    assert view.selected_process is p1
    assert view.inspector.current_process is p1
    view.close()


def test_clearing_selection_hides_inspector(qapp: QApplication) -> None:
    """Clearing row selection hides the inspector and resets selected_process."""
    view = ProcessesView()
    view.show()
    p = _make_process()
    view.set_collection(_make_collection((p,), total=1))

    view.table.selectRow(0)
    assert view.inspector.isVisible() is True
    assert view.selected_process is p

    view.table.clearSelection()
    qapp.processEvents()

    assert view.inspector.isVisible() is False
    assert view.selected_process is None
    assert view.inspector.current_process is None
    view.close()


def test_closing_inspector_clears_row_selection_and_hides(
    qapp: QApplication,
) -> None:
    """Clicking close button on inspector clears table selection and hides."""
    view = ProcessesView()
    view.show()
    p = _make_process()
    view.set_collection(_make_collection((p,), total=1))

    view.table.selectRow(0)
    assert view.inspector.isVisible() is True
    assert view.table.selectionModel().hasSelection() is True

    # Click close button on inspector
    view.inspector.close_button.click()
    qapp.processEvents()

    assert view.inspector.isVisible() is False
    assert view.table.selectionModel().hasSelection() is False
    assert view.selected_process is None
    view.close()


def test_reselecting_row_after_close_reopens_inspector(
    qapp: QApplication,
) -> None:
    """Reselecting a table row after closing restores inspector details."""
    view = ProcessesView()
    view.show()
    p = _make_process()
    view.set_collection(_make_collection((p,), total=1))

    view.table.selectRow(0)
    view.inspector.close_button.click()
    assert view.inspector.isVisible() is False

    # Select again
    view.table.selectRow(0)
    qapp.processEvents()

    assert view.inspector.isVisible() is True
    assert view.selected_process is p
    view.close()


def test_filter_changes_clear_inspector_selection(
    qapp: QApplication,
) -> None:
    """Applying or clearing filters clears table selection and inspector."""
    view = ProcessesView()
    p = _make_process()
    view.set_collection(_make_collection((p,), total=1))

    view.table.selectRow(0)
    assert view.selected_process is p

    # Apply filter clears selection and inspector
    view.pid_input.setText("1234")
    view.apply_filters()
    assert view.selected_process is None
    assert view.inspector.isVisible() is False
    assert view.table.selectionModel().hasSelection() is False

    # Reselect and clear filters
    view.table.selectRow(0)
    assert view.selected_process is p

    view.clear_filters()
    assert view.selected_process is None
    assert view.inspector.isVisible() is False
    assert view.table.selectionModel().hasSelection() is False


def test_pagination_collection_replacement_clears_inspector(
    qapp: QApplication,
) -> None:
    """Replacing collection on page change clears stale inspector details."""
    view = ProcessesView()
    p1 = _make_process(SAMPLE_PROC_ID_1)
    view.set_collection(_make_collection((p1,), total=50, limit=1, offset=0))

    view.table.selectRow(0)
    assert view.selected_process is p1

    # Simulate new page arriving
    p2 = _make_process(SAMPLE_PROC_ID_2)
    view.set_collection(_make_collection((p2,), total=50, limit=1, offset=1))

    assert view.selected_process is None
    assert view.inspector.isVisible() is False
    assert view.table.selectionModel().hasSelection() is False


def test_selection_changes_make_no_api_or_query_requests(
    qapp: QApplication,
) -> None:
    """Selecting rows or closing inspector never triggers API queries."""
    view = ProcessesView()
    p1 = _make_process(SAMPLE_PROC_ID_1)
    p2 = _make_process(SAMPLE_PROC_ID_2)
    view.set_collection(_make_collection((p1, p2), total=2))

    emitted: list[ProcessesQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))
    initial_query = view.current_query

    # Select row 0, select row 1, clear, select row 0, close
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
    view = ProcessesView()
    p = _make_process()
    view.set_collection(_make_collection((p,), total=1))

    view.table.selectRow(0)
    assert view.selected_process is p

    view.set_error("Connection error")
    assert view.selected_process is None
    assert view.inspector.isVisible() is False
    view.close()


def test_model_reset_clears_inspector(qapp: QApplication) -> None:
    """Direct model reset clears table selection and hides the inspector."""
    view = ProcessesView()
    view.show()
    p = _make_process()
    view.set_collection(_make_collection((p,), total=1))

    view.table.selectRow(0)
    assert view.inspector.isVisible() is True
    assert view.selected_process is p

    # Direct model clear triggers modelReset
    view.model.clear()
    assert view.selected_process is None
    assert view.inspector.isVisible() is False
    assert view.table.selectionModel().hasSelection() is False
    view.close()


def test_invalid_selection_clears_inspector(qapp: QApplication) -> None:
    """Selecting an invalid row clears inspector and does not show stale data."""
    view = ProcessesView()
    view.show()
    p = _make_process()
    view.set_collection(_make_collection((p,), total=1))

    view.table.selectRow(0)
    assert view.inspector.isVisible() is True
    assert view.selected_process is p

    view.table.setCurrentIndex(view.table.model().index(999, 999))
    view.table.clearSelection()
    qapp.processEvents()

    assert view.selected_process is None
    assert view.inspector.isVisible() is False
    view.close()


def test_processes_view_properties_loading_guards_and_selection_fallbacks(
    qapp: QApplication,
) -> None:
    """ProcessesView exposes aliases, guards in loading, and cell selection."""
    from PySide6.QtCore import QItemSelectionModel

    # 1. ProcessesQuery page_index edge branch
    q = ProcessesQuery(limit=10, offset=20)
    assert q.page_index == 2
    object.__setattr__(q, "limit", 0)
    assert q.page_index == 0

    view = ProcessesView()

    # 2. set_query TypeError
    with pytest.raises(TypeError, match="Expected ProcessesQuery"):
        view.set_query("invalid")  # type: ignore[arg-type]

    # 3. Properties and aliases
    assert view.page_size == 50
    assert isinstance(view.filter_bar, QFrame)
    assert view.status_combo is view.active_filter_combo
    assert isinstance(view.pid_input, QLineEdit)
    assert isinstance(view.host_id_input, QLineEdit)
    assert isinstance(view.apply_filters_button, QPushButton)
    assert view.reset_filters_button is view.clear_filters_button
    assert isinstance(view.filter_validation_label, QLabel)
    assert isinstance(view.pagination_bar, QFrame)
    assert isinstance(view.prev_page_button, QPushButton)
    assert isinstance(view.next_page_button, QPushButton)
    assert isinstance(view.page_range_label, QLabel)
    assert view.inspector_panel is view.inspector
    assert isinstance(view.quick_reset_button, QPushButton)
    assert isinstance(view.record_count_label, QLabel)
    assert isinstance(view.status_banner, QFrame)
    assert view.state == "not_loaded"

    # 4. Loading guards
    view._state = "loading"
    emitted: list[Any] = []
    view.query_requested.connect(lambda query: emitted.append(query))

    view.apply_filters()
    assert len(emitted) == 0

    view.clear_filters()
    assert len(emitted) == 0

    view.go_next_page()
    assert len(emitted) == 0

    view.go_prev_page()
    assert len(emitted) == 0

    # 5. Cell selection fallback in _handle_selection_changed
    p = _make_process()
    col = _make_collection((p,), total=1)
    view.set_collection(col)

    sel_model = view.table.selectionModel()
    idx = view.model.index(0, 2)
    sel_model.select(idx, QItemSelectionModel.SelectionFlag.Select)
    view._handle_selection_changed()
    assert view.selected_process == p

    view.close()



