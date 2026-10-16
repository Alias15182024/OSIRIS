"""Unit and integration tests for OSIRIS ResourcesView and Application Shell.

Verifies:
1. ResourcesView construction, layout, and stable object names.
2. QTableView integration with ResourcesTableModel.
3. No API client constructed inside visual view.
4. View state transitions: not_loaded, loading, loaded, empty, and failed.
5. Lazy loading contract: initial activation requests load; revisits do not.
6. Guarding against duplicate concurrent refreshes.
7. Real ResourceSnapshotCollection presentation and order preservation without
   fabricating data.
8. Empty response handling and honest empty messaging.
9. Retained records distinguished from fresh results upon failed refresh.
10. Sanitized user-facing error messages for all typed exceptions.
11. Asynchronous MainWindow integration using ApiWorker and APIClient.get_resources.
12. Thread safety: API calls off GUI thread, widget updates on GUI thread.
13. Lifecycle safety: in-flight workers prevent premature close.
14. Regression: EventsView and ProcessesView navigation items remain intact.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest
from PySide6.QtCore import Qt, QThreadPool
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDateTimeEdit,
    QFrame,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableView,
    QWidget,
)

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
    FileCollection,
    ProcessCollection,
    ResourceSnapshot,
    ResourceSnapshotCollection,
    User,
)
from desktop.models.resources_model import (
    COLUMN_CPU_PERCENT,
    COLUMN_DISK_READ,
    COLUMN_DISK_USAGE_PERCENT,
    COLUMN_DISK_WRITE,
    COLUMN_MEMORY_PERCENT,
    COLUMN_MEMORY_TOTAL,
    COLUMN_MEMORY_USED,
    COLUMN_TIMESTAMP,
    COLUMNS,
    EMPTY_PLACEHOLDER,
    ResourcesTableModel,
)
from desktop.ui.app_shell import AppShell
from desktop.ui.main_window import MainWindow
from desktop.ui.views.resources_view import (
    DEFAULT_PAGE_SIZE,
    STATE_EMPTY,
    STATE_FAILED,
    STATE_LOADED,
    STATE_LOADING,
    STATE_NOT_LOADED,
    ResourceInspectorPanel,
    ResourcesFilterBar,
    ResourcesPaginationBar,
    ResourcesQuery,
    ResourcesSummaryCardsFrame,
    ResourcesView,
    ResourceTrendChartsWidget,
)

SAMPLE_SNAPSHOT_ID_1 = "11111111-1111-4111-8111-111111111111"
SAMPLE_SNAPSHOT_ID_2 = "22222222-2222-4222-8222-222222222222"
SAMPLE_SNAPSHOT_ID_3 = "33333333-3333-4333-8333-333333333333"
SAMPLE_HOST_ID = "44444444-4444-4444-8444-444444444444"
SAMPLE_TIME_1 = "2026-03-01T08:00:00Z"
SAMPLE_TIME_2 = "2026-03-01T08:05:00Z"
SAMPLE_TIME_3 = "2026-03-01T08:10:00Z"


def _sample_user() -> User:
    """Return a representative authenticated User instance."""
    return User(
        id="usr-res-001",
        username="lead_analyst",
        display_name="Lead Analyst",
        role="admin",
        is_active=True,
        created_at="2026-01-01T00:00:00Z",
    )


def _make_snapshot(
    snapshot_id: str = SAMPLE_SNAPSHOT_ID_1,
    host_id: str = SAMPLE_HOST_ID,
    timestamp: str = SAMPLE_TIME_1,
    created_at: str = SAMPLE_TIME_1,
    cpu_percent: float | None = 15.2,
    memory_total: int | None = 16_000_000_000,
    memory_used: int | None = 4_000_000_000,
    memory_percent: float | None = 25.0,
    disk_read_bytes: int | None = 1048576,
    disk_write_bytes: int | None = 2097152,
    disk_usage_percent: float | None = 45.5,
) -> ResourceSnapshot:
    """Create a valid ResourceSnapshot instance for view tests."""
    return ResourceSnapshot(
        id=snapshot_id,
        host_id=host_id,
        timestamp=timestamp,
        created_at=created_at,
        cpu_percent=cpu_percent,
        memory_total=memory_total,
        memory_used=memory_used,
        memory_percent=memory_percent,
        disk_read_bytes=disk_read_bytes,
        disk_write_bytes=disk_write_bytes,
        disk_usage_percent=disk_usage_percent,
    )


def _make_collection(
    items: tuple[ResourceSnapshot, ...] = (),
    total: int = 0,
    limit: int = 50,
    offset: int = 0,
) -> ResourceSnapshotCollection:
    """Create a valid ResourceSnapshotCollection instance."""
    return ResourceSnapshotCollection(
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


def test_resources_view_instantiation(qapp: QApplication) -> None:
    """ResourcesView constructs successfully with required child widgets."""
    view = ResourcesView()
    assert view is not None
    assert isinstance(view, QWidget)
    assert view.objectName() == "Page_Resources"
    assert view.state == STATE_NOT_LOADED
    assert view.model.rowCount() == 0


def test_resources_view_stable_object_names(qapp: QApplication) -> None:
    """ResourcesView exposes stable object names across all key child controls."""
    view = ResourcesView()

    assert view.findChild(QLabel, "PageTitle") is not None
    assert view.findChild(QLabel, "PageDescription") is not None
    assert view.findChild(QFrame, "ResourcesFilterBar") is not None
    assert view.findChild(QLineEdit, "ResourcesHostIdFilterInput") is not None
    assert view.findChild(QComboBox, "ResourcesLimitFilterCombo") is not None
    assert view.findChild(QLineEdit, "ResourcesLimitFilterInput") is not None
    assert (
        view.findChild(QCheckBox, "ResourcesStartTimeFilterCheckBox")
        is not None
    )
    assert (
        view.findChild(QDateTimeEdit, "ResourcesStartTimeFilterEdit")
        is not None
    )
    assert (
        view.findChild(QCheckBox, "ResourcesEndTimeFilterCheckBox")
        is not None
    )
    assert (
        view.findChild(QDateTimeEdit, "ResourcesEndTimeFilterEdit")
        is not None
    )
    assert (
        view.findChild(QPushButton, "ApplyResourcesFiltersButton") is not None
    )
    assert (
        view.findChild(QPushButton, "ResetResourcesFiltersButton") is not None
    )
    assert (
        view.findChild(QLabel, "ResourcesFilterValidationLabel") is not None
    )
    assert view.findChild(QFrame, "ResourcesToolbar") is not None
    assert view.findChild(QPushButton, "RefreshResourcesButton") is not None
    assert view.findChild(QLabel, "RecordCountSummary") is not None
    assert view.findChild(QFrame, "ResourcesStatusBanner") is not None
    assert view.findChild(QLabel, "ResourcesStatusBannerTitle") is not None
    assert view.findChild(QLabel, "ResourcesStatusBannerMessage") is not None
    assert view.findChild(QPushButton, "RetryResourcesButton") is not None
    assert (
        view.findChild(QPushButton, "QuickResetResourcesFiltersButton")
        is not None
    )
    assert view.findChild(QTableView, "ResourcesTable") is not None
    assert (
        view.findChild(QFrame, "ResourcesSummaryCardsFrame") is not None
    )
    assert (
        view.findChild(QFrame, "ResourceTrendChartsWidget") is not None
    )
    assert (
        view.findChild(QFrame, "ResourceInspectorPanel") is not None
    )
    assert view.findChild(QFrame, "ResourcesPaginationBar") is not None
    assert view.findChild(QPushButton, "ResourcesPrevPageButton") is not None
    assert view.findChild(QPushButton, "ResourcesNextPageButton") is not None
    assert view.findChild(QLabel, "ResourcesPageRangeSummary") is not None



def test_resources_view_does_not_instantiate_api_client(
    qapp: QApplication,
) -> None:
    """ResourcesView contains no APIClient instance or HTTP transport."""
    view = ResourcesView()
    assert not hasattr(view, "client")
    assert not hasattr(view, "_client")


def test_resources_table_backed_by_resources_table_model(
    qapp: QApplication,
) -> None:
    """ResourcesView table uses ResourcesTableModel with row selection."""
    view = ResourcesView()
    table = view.table
    assert isinstance(table.model(), ResourcesTableModel)
    assert table.isSortingEnabled() is False
    assert (
        table.selectionBehavior() == QTableView.SelectionBehavior.SelectRows
    )
    assert (
        table.editTriggers() == QTableView.EditTrigger.NoEditTriggers
    )


def test_resources_table_presents_eight_columns_in_order(
    qapp: QApplication,
) -> None:
    """ResourcesView table presents all 8 columns in established order."""
    view = ResourcesView()
    model = view.model
    assert model.columnCount() == 8
    expected = (
        "Timestamp",
        "CPU %",
        "Memory %",
        "Memory Used",
        "Memory Total",
        "Disk Read",
        "Disk Write",
        "Disk Usage %",
    )
    assert COLUMNS == expected
    for idx, name in enumerate(expected):
        assert model.headerData(idx, Qt.Orientation.Horizontal) == name


def test_refresh_resources_button_emits_signal(qapp: QApplication) -> None:
    """Clicking Refresh Resources emits the refresh_requested signal."""
    view = ResourcesView()
    emitted: list[bool] = []
    view.refresh_requested.connect(lambda: emitted.append(True))

    view.refresh_button.click()
    assert emitted == [True]


def test_retry_button_emits_refresh_requested_signal(
    qapp: QApplication,
) -> None:
    """Clicking Retry on the status banner emits refresh_requested."""
    view = ResourcesView()
    emitted: list[bool] = []
    view.refresh_requested.connect(lambda: emitted.append(True))

    view.set_error("Network connection refused")
    view.retry_button.click()
    assert emitted == [True]


# ==============================================================================
# 2. View States and Transitions
# ==============================================================================


def test_initial_not_loaded_state(qapp: QApplication) -> None:
    """Initial state is not_loaded with descriptive banner and 0 count."""
    view = ResourcesView()
    view.show()
    assert view.state == STATE_NOT_LOADED
    assert view.status_banner.isVisible() is True
    assert "Not Loaded" in _label_text(view, "ResourcesStatusBannerTitle")
    assert "not loaded" in view.record_count_label.text()
    assert view.refresh_button.isEnabled() is True
    assert view.retry_button.isVisible() is False
    view.close()


def test_set_loading_disables_refresh_button(qapp: QApplication) -> None:
    """set_loading() disables refresh button and shows loading state."""
    view = ResourcesView()
    view.show()
    view.set_loading()

    assert view.state == STATE_LOADING
    assert view.refresh_button.isEnabled() is False
    assert view.retry_button.isEnabled() is False
    assert "Loading resource telemetry" in view.record_count_label.text()
    assert view.status_banner.isVisible() is True
    assert view.status_banner.property("state") == "loading"
    view.close()


def test_set_loading_with_retained_records_updates_count_label(
    qapp: QApplication,
) -> None:
    """set_loading() preserves row count label when records are already loaded."""
    view = ResourcesView()
    view.show()
    s = _make_snapshot()
    view.set_collection(_make_collection((s,), total=1))

    view.set_loading()
    assert view.state == STATE_LOADING
    assert "Retained 1 snapshots (refreshing...)" in (
        view.record_count_label.text()
    )
    view.close()


def test_set_collection_loaded_state_and_table_contents(
    qapp: QApplication,
) -> None:
    """set_collection() populates table, updates count, and hides banner."""
    view = ResourcesView()
    view.show()
    s1 = _make_snapshot(snapshot_id=SAMPLE_SNAPSHOT_ID_1, cpu_percent=12.5)
    s2 = _make_snapshot(snapshot_id=SAMPLE_SNAPSHOT_ID_2, cpu_percent=88.1)
    col = _make_collection((s1, s2), total=2)

    view.set_collection(col)

    assert view.state == STATE_LOADED
    assert view.model.rowCount() == 2
    assert view.status_banner.isVisible() is False
    assert "Showing 2 of 2 snapshots" in view.record_count_label.text()
    assert view.refresh_button.isEnabled() is True

    # Order preserved without synthetic reordering
    assert view.snapshot_at(0) == s1
    assert view.snapshot_at(1) == s2
    assert view.resource_at(0) == s1
    assert view.model.data(view.model.index(0, COLUMN_CPU_PERCENT)) == "12.5%"
    assert view.model.data(view.model.index(1, COLUMN_CPU_PERCENT)) == "88.1%"
    view.close()


def test_set_collection_empty_state_and_banner_message(
    qapp: QApplication,
) -> None:
    """set_collection() with 0 items displays empty state banner."""
    view = ResourcesView()
    view.show()
    col = _make_collection((), total=0)

    view.set_collection(col)

    assert view.state == STATE_EMPTY
    assert view.model.rowCount() == 0
    assert view.status_banner.isVisible() is True
    assert view.status_banner.property("state") == "empty"
    assert "No Resource Telemetry Found" in (
        _label_text(view, "ResourcesStatusBannerTitle")
    )
    assert "0 snapshots" in view.record_count_label.text()
    assert view.retry_button.isVisible() is False
    view.close()


def test_set_collection_rejects_invalid_type(qapp: QApplication) -> None:
    """set_collection() raises TypeError if not a ResourceSnapshotCollection."""
    view = ResourcesView()
    with pytest.raises(TypeError, match="Expected ResourceSnapshotCollection"):
        view.set_collection("invalid")  # type: ignore[arg-type]


def test_set_error_initial_failure(qapp: QApplication) -> None:
    """set_error() transitions to failed state and shows retry action."""
    view = ResourcesView()
    view.show()
    view.set_error("Connection timed out")

    assert view.state == STATE_FAILED
    assert view.model.rowCount() == 0
    assert view.status_banner.isVisible() is True
    assert view.status_banner.property("state") == "failed"
    assert "Failed to Load Resources" in (
        _label_text(view, "ResourcesStatusBannerTitle")
    )
    assert "Connection timed out" in (
        _label_text(view, "ResourcesStatusBannerMessage")
    )
    assert view.retry_button.isVisible() is True
    assert view.retry_button.isEnabled() is True
    assert view.refresh_button.isEnabled() is True
    view.close()


def test_set_error_preserves_retained_rows_on_refresh_failure(
    qapp: QApplication,
) -> None:
    """set_error() with existing records retains them and warns user."""
    view = ResourcesView()
    view.show()
    s = _make_snapshot(cpu_percent=42.0)
    view.set_collection(_make_collection((s,), total=1))

    view.set_error("Gateway 504")

    assert view.state == STATE_FAILED
    assert view.model.rowCount() == 1
    assert "Resources Refresh Failed" in (
        _label_text(view, "ResourcesStatusBannerTitle")
    )
    assert "retained records" in (
        _label_text(view, "ResourcesStatusBannerMessage")
    )
    assert "Retained 1 snapshots (refresh failed)" in (
        view.record_count_label.text()
    )
    view.close()


def test_set_error_rejects_non_string(qapp: QApplication) -> None:
    """set_error() raises TypeError if message is not a string."""
    view = ResourcesView()
    with pytest.raises(TypeError, match="Expected str message"):
        view.set_error(12345)  # type: ignore[arg-type]


def test_set_not_loaded_resets_view_completely(qapp: QApplication) -> None:
    """set_not_loaded() clears model rows and restores initial state."""
    view = ResourcesView()
    view.show()
    s = _make_snapshot()
    view.set_collection(_make_collection((s,), total=1))

    view.set_not_loaded()
    assert view.state == STATE_NOT_LOADED
    assert view.model.rowCount() == 0
    assert view.status_banner.isVisible() is True
    assert "Not Loaded" in _label_text(view, "ResourcesStatusBannerTitle")
    view.close()


# ==============================================================================
# 3. Lazy Loading and Signal Forwarding
# ==============================================================================


def test_notify_page_activated_emits_load_requested_when_not_loaded(
    qapp: QApplication,
) -> None:
    """notify_page_activated() emits load_requested on first activation."""
    view = ResourcesView()
    emitted: list[bool] = []
    view.load_requested.connect(lambda: emitted.append(True))

    view.notify_page_activated()
    assert emitted == [True]


def test_notify_page_activated_does_not_emit_when_loaded(
    qapp: QApplication,
) -> None:
    """notify_page_activated() suppresses load_requested once loaded."""
    view = ResourcesView()
    s = _make_snapshot()
    view.set_collection(_make_collection((s,), total=1))

    emitted: list[bool] = []
    view.load_requested.connect(lambda: emitted.append(True))

    view.notify_page_activated()
    assert emitted == []


def test_notify_page_activated_does_not_emit_when_loading(
    qapp: QApplication,
) -> None:
    """notify_page_activated() suppresses load_requested while loading."""
    view = ResourcesView()
    view.set_loading()

    emitted: list[bool] = []
    view.load_requested.connect(lambda: emitted.append(True))

    view.notify_page_activated()
    assert emitted == []


def test_refresh_ignored_while_loading(qapp: QApplication) -> None:
    """Manual refresh() call is ignored while in STATE_LOADING."""
    view = ResourcesView()
    view.set_loading()

    emitted: list[bool] = []
    view.refresh_requested.connect(lambda: emitted.append(True))

    view.refresh()
    assert emitted == []


# ==============================================================================
# 4. ResourcesQuery Data Class
# ==============================================================================


def test_resources_query_defaults() -> None:
    """ResourcesQuery initializes with default limit and offset."""
    q = ResourcesQuery()
    assert q.limit == DEFAULT_PAGE_SIZE
    assert q.offset == 0
    assert q.host_id is None
    assert q.start_time is None
    assert q.end_time is None
    assert q.to_client_kwargs() == {"limit": 50, "offset": 0}


def test_resources_query_validation() -> None:
    """ResourcesQuery rejects invalid limit and offset."""
    with pytest.raises(ValueError, match="limit must be an integer"):
        ResourcesQuery(limit=0)

    with pytest.raises(ValueError, match="limit must be an integer"):
        ResourcesQuery(limit=101)

    with pytest.raises(ValueError, match="offset must be a non-negative"):
        ResourcesQuery(offset=-1)

    with pytest.raises(ValueError, match="host_id must be a valid UUID"):
        ResourcesQuery(host_id="not-a-uuid")


# ==============================================================================
# 5. MainWindow Asynchronous Worker Integration
# ==============================================================================


def test_main_window_loads_resources_via_api_worker(
    qapp: QApplication,
) -> None:
    """MainWindow dispatches resource requests through ApiWorker and get_resources."""
    client = MagicMock(spec=APIClient)
    client.get_resources.return_value = _make_collection((), total=0)

    window = MainWindow(client=client, user=_sample_user())
    assert window.is_loading_resources is False

    window.load_resources()
    assert window.is_loading_resources is True

    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    assert window.is_loading_resources is False
    client.get_resources.assert_called_once_with(limit=50, offset=0)
    window.close()
    QThreadPool.globalInstance().waitForDone(1000)


def test_main_window_prevents_duplicate_in_flight_resources_requests(
    qapp: QApplication,
) -> None:
    """MainWindow ignores duplicate load_resources calls while one is running."""
    client = MagicMock(spec=APIClient)

    def slow_fetch(**kwargs: Any) -> ResourceSnapshotCollection:
        time.sleep(0.05)
        return _make_collection((), total=0)

    client.get_resources.side_effect = slow_fetch

    window = MainWindow(client=client, user=_sample_user())
    window.load_resources()
    assert window.is_loading_resources is True

    # Second call while in flight
    window.load_resources()

    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    assert client.get_resources.call_count == 1
    window.close()
    QThreadPool.globalInstance().waitForDone(1000)


def test_main_window_handles_missing_client_gracefully(
    qapp: QApplication,
) -> None:
    """MainWindow sets error state when client is None."""
    window = MainWindow(client=None)
    window.load_resources()

    assert window.is_loading_resources is False
    assert window.resources_view.state == STATE_FAILED
    assert "No API client configured" in (
        _label_text(window.resources_view, "ResourcesStatusBannerMessage")
    )
    window.close()


def test_main_window_successful_resources_load(qapp: QApplication) -> None:
    """MainWindow applies retrieved ResourceSnapshotCollection to ResourcesView."""
    client = MagicMock(spec=APIClient)
    s = _make_snapshot(cpu_percent=55.5)
    client.get_resources.return_value = _make_collection((s,), total=1)

    window = MainWindow(client=client, user=_sample_user())
    window.load_resources()

    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    assert window.resources_view.state == STATE_LOADED
    assert window.resources_view.model.rowCount() == 1
    assert "Showing 1 of 1 snapshots" in (
        window.resources_view.record_count_label.text()
    )
    window.close()
    QThreadPool.globalInstance().waitForDone(1000)


def test_main_window_handles_empty_resources_collection(
    qapp: QApplication,
) -> None:
    """MainWindow handles empty collection with STATE_EMPTY."""
    client = MagicMock(spec=APIClient)
    client.get_resources.return_value = _make_collection((), total=0)

    window = MainWindow(client=client, user=_sample_user())
    window.load_resources()

    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    assert window.resources_view.state == STATE_EMPTY
    assert window.resources_view.model.rowCount() == 0
    window.close()
    QThreadPool.globalInstance().waitForDone(1000)


def test_main_window_superseded_request_guard_ignores_stale_result(
    qapp: QApplication,
) -> None:
    """Outdated resource results from older request sequences are ignored."""
    client = MagicMock(spec=APIClient)
    window = MainWindow(client=client, user=_sample_user())
    initial = _make_collection((), total=0)
    window.shell.resources_view.set_collection(initial)

    window._resources_request_seq = 2

    # Stale result with seq=1
    s = _make_snapshot()
    stale_collection = _make_collection((s,), total=1)
    window._on_resources_result(stale_collection, seq=1)

    assert window.shell.resources_view.model.rowCount() == 0
    window.close()


def test_main_window_superseded_request_guard_ignores_stale_error(
    qapp: QApplication,
) -> None:
    """Outdated resource errors from older request sequences are ignored."""
    client = MagicMock(spec=APIClient)
    window = MainWindow(client=client, user=_sample_user())
    s = _make_snapshot()
    window.shell.resources_view.set_collection(_make_collection((s,), total=1))

    window._resources_request_seq = 2

    # Stale error with seq=1
    window._on_resources_error(Exception("Stale failure"), seq=1)

    assert window.shell.resources_view.state == STATE_LOADED
    assert window.shell.resources_view.model.rowCount() == 1
    window.close()


@pytest.mark.parametrize(
    "exception_cls, kwargs, expected_substring",
    [
        (
            AuthenticationError,
            {"message": "Unauthorized"},
            "Authentication session expired or invalid",
        ),
        (
            AuthorizationError,
            {"message": "Forbidden"},
            "Access denied: you do not have permission",
        ),
        (
            ConnectionTimeoutError,
            {"message": "Timed out"},
            "Connection timed out",
        ),
        (
            ClientConnectionError,
            {"message": "Connection refused"},
            "Unable to connect to the OSIRIS API server",
        ),
        (
            HTTPResponseError,
            {"status_code": 500, "message": "Server error"},
            "API request failed (HTTP 500)",
        ),
        (
            ValidationError,
            {"message": "Bad field"},
            "Invalid resource data received",
        ),
        (
            OSIRISClientError,
            {"message": "Generic error"},
            "Generic error",
        ),
        (
            RuntimeError,
            {"args": ("Unexpected crash",)},
            "An unexpected error occurred: RuntimeError",
        ),
    ],
)
def test_main_window_sanitizes_resource_errors(
    qapp: QApplication,
    exception_cls: type[Exception],
    kwargs: dict[str, Any],
    expected_substring: str,
) -> None:
    """MainWindow sanitizes typed exceptions into safe user-facing text."""
    client = MagicMock(spec=APIClient)
    if "args" in kwargs:
        exc = exception_cls(*kwargs["args"])
    else:
        exc = exception_cls(**kwargs)
    client.get_resources.side_effect = exc

    window = MainWindow(client=client, user=_sample_user())
    window.load_resources()

    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    assert window.resources_view.state == STATE_FAILED
    msg = _label_text(window.resources_view, "ResourcesStatusBannerMessage")
    assert expected_substring in msg
    window.close()
    QThreadPool.globalInstance().waitForDone(1000)


def test_main_window_close_deferred_while_resources_worker_active(
    qapp: QApplication,
) -> None:
    """Closing MainWindow while resource worker is active defers close safely."""
    client = MagicMock(spec=APIClient)

    def slow_resources(**kwargs: Any) -> ResourceSnapshotCollection:
        time.sleep(0.05)
        return _make_collection((), total=0)

    client.get_resources.side_effect = slow_resources

    window = MainWindow(client=client, user=_sample_user())
    window.load_resources()
    assert window.has_active_workers is True

    close_event = QCloseEvent()
    window.closeEvent(close_event)
    assert close_event.isAccepted() is False
    assert window.isVisible() is False
    assert window._pending_close is True

    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    assert window.has_active_workers is False
    window.close()
    QThreadPool.globalInstance().waitForDone(1000)


# ==============================================================================
# 6. Application Shell Navigation and Integration
# ==============================================================================


def test_app_shell_navigates_to_resources(qapp: QApplication) -> None:
    """AppShell navigation switches to ResourcesView."""
    shell = AppShell()
    shell.navigate_to("Resources")

    assert shell.current_page_name == "Resources"
    assert isinstance(shell.resources_view, ResourcesView)
    assert shell.content_stack.currentWidget() is shell.resources_view


def test_app_shell_navigation_round_trip(qapp: QApplication) -> None:
    """Navigating between Resources and other views works cleanly."""
    shell = AppShell()

    shell.navigate_to("Resources")
    assert shell.current_page_name == "Resources"

    shell.navigate_to("Events")
    assert shell.current_page_name == "Events"

    shell.navigate_to("Processes")
    assert shell.current_page_name == "Processes"

    shell.navigate_to("Resources")
    assert shell.current_page_name == "Resources"


def test_app_shell_signals_forwarded(qapp: QApplication) -> None:
    """AppShell forwards resources view signals correctly."""
    shell = AppShell()

    load_emitted: list[bool] = []
    refresh_emitted: list[bool] = []
    query_emitted: list[Any] = []

    shell.resources_load_requested.connect(lambda: load_emitted.append(True))
    shell.resources_refresh_requested.connect(
        lambda: refresh_emitted.append(True)
    )
    shell.resources_query_requested.connect(
        lambda q: query_emitted.append(q)
    )

    shell.resources_view.load_requested.emit()
    assert load_emitted == [True]

    shell.resources_view.refresh_requested.emit()
    assert refresh_emitted == [True]

    test_q = ResourcesQuery(limit=25, offset=5)
    shell.resources_view.query_requested.emit(test_q)
    assert query_emitted == [test_q]


def test_main_window_wires_shell_resources_signals(
    qapp: QApplication,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MainWindow connects AppShell resources signals to load_resources."""
    window = MainWindow(client=MagicMock(spec=APIClient), user=_sample_user())

    called_with: list[Any] = []

    def mock_load(query: Any = None) -> None:
        called_with.append(query)

    monkeypatch.setattr(window, "load_resources", mock_load)

    window.shell.resources_load_requested.emit()
    assert len(called_with) == 1

    window.shell.resources_refresh_requested.emit()
    assert len(called_with) == 2

    q = ResourcesQuery(limit=10)
    window.shell.resources_view.query_requested.emit(q)
    assert len(called_with) == 3
    assert called_with[2] == q
    window.close()


# ==============================================================================
# 7. Regressions: Existing Views Remain Operational
# ==============================================================================


def test_regression_events_and_processes_views_intact(
    qapp: QApplication,
) -> None:
    """Integration of ResourcesView does not disrupt EventsView or ProcessesView."""
    shell = AppShell()

    assert shell.events_view is not None
    assert shell.processes_view is not None
    assert shell.resources_view is not None

    assert shell.events_view.objectName() == "Page_Events"
    assert shell.processes_view.objectName() == "Page_Processes"
    assert shell.resources_view.objectName() == "Page_Resources"


# ==============================================================================
# 8. Resources View Robustness, Percentages, and Lifecycle Transitions
# ==============================================================================


def test_set_collection_handles_limit_greater_than_100(
    qapp: QApplication,
) -> None:
    """set_collection() clamps limit without crashing when server limit > 100."""
    view = ResourcesView()
    view.show()
    col = _make_collection((), total=0, limit=200, offset=0)

    # Must not raise ValueError: limit must be an integer between 1 and 100
    view.set_collection(col)
    assert view.state == STATE_EMPTY
    assert view.current_query.limit == 100
    assert view.current_query.offset == 0
    view.close()


def test_resources_table_percentage_formatting_one_decimal_place(
    qapp: QApplication,
) -> None:
    """Table formats percentages to 1 decimal place with real API numbers."""
    view = ResourcesView()
    view.show()

    # Snapshot 1: zero values, multi-decimal, and large values
    s1 = _make_snapshot(
        snapshot_id=SAMPLE_SNAPSHOT_ID_1,
        cpu_percent=0.0,
        memory_percent=0.0,
        memory_used=0,
        memory_total=16_000_000_000,
        disk_read_bytes=0,
        disk_write_bytes=1048576,
        disk_usage_percent=99.96,
    )
    # Snapshot 2: 15.249% formatted as 15.2%, and 100.0%
    s2 = _make_snapshot(
        snapshot_id=SAMPLE_SNAPSHOT_ID_2,
        cpu_percent=15.249,
        memory_percent=100.0,
        memory_used=4_294_967_296,
        memory_total=4_294_967_296,
        disk_read_bytes=512,
        disk_write_bytes=0,
        disk_usage_percent=100.0,
    )
    # Snapshot 3: missing / None values rendered as EMPTY_PLACEHOLDER
    s3 = _make_snapshot(
        snapshot_id=SAMPLE_SNAPSHOT_ID_3,
        cpu_percent=None,
        memory_percent=None,
        memory_used=None,
        memory_total=None,
        disk_read_bytes=None,
        disk_write_bytes=None,
        disk_usage_percent=None,
    )

    col = _make_collection((s1, s2, s3), total=3)
    view.set_collection(col)

    model = view.model
    # Row 0: zero preservation
    assert model.data(model.index(0, COLUMN_TIMESTAMP)) == SAMPLE_TIME_1
    assert model.data(model.index(0, COLUMN_CPU_PERCENT)) == "0.0%"
    assert model.data(model.index(0, COLUMN_MEMORY_PERCENT)) == "0.0%"
    assert model.data(model.index(0, COLUMN_MEMORY_USED)) == "0 B"
    assert model.data(model.index(0, COLUMN_MEMORY_TOTAL)) == "14.9 GiB"
    assert model.data(model.index(0, COLUMN_DISK_READ)) == "0 B"
    assert model.data(model.index(0, COLUMN_DISK_WRITE)) == "1.0 MiB"
    assert model.data(model.index(0, COLUMN_DISK_USAGE_PERCENT)) == "100.0%"

    # Row 1: 1 decimal place rounding
    assert model.data(model.index(1, COLUMN_CPU_PERCENT)) == "15.2%"
    assert model.data(model.index(1, COLUMN_MEMORY_PERCENT)) == "100.0%"
    assert model.data(model.index(1, COLUMN_MEMORY_USED)) == "4.0 GiB"
    assert model.data(model.index(1, COLUMN_DISK_READ)) == "512 B"
    assert model.data(model.index(1, COLUMN_DISK_USAGE_PERCENT)) == "100.0%"

    # Row 2: None placeholders
    assert model.data(model.index(2, COLUMN_CPU_PERCENT)) == EMPTY_PLACEHOLDER
    assert model.data(model.index(2, COLUMN_MEMORY_PERCENT)) == EMPTY_PLACEHOLDER
    assert model.data(model.index(2, COLUMN_MEMORY_USED)) == EMPTY_PLACEHOLDER
    assert model.data(model.index(2, COLUMN_MEMORY_TOTAL)) == EMPTY_PLACEHOLDER
    assert model.data(model.index(2, COLUMN_DISK_READ)) == EMPTY_PLACEHOLDER
    assert model.data(model.index(2, COLUMN_DISK_WRITE)) == EMPTY_PLACEHOLDER
    assert (
        model.data(model.index(2, COLUMN_DISK_USAGE_PERCENT))
        == EMPTY_PLACEHOLDER
    )
    view.close()


def test_resources_view_selected_snapshot_accessor(
    qapp: QApplication,
) -> None:
    """selected_snapshot returns selected snapshot or None when unselected."""
    view = ResourcesView()
    view.show()
    s1 = _make_snapshot(snapshot_id=SAMPLE_SNAPSHOT_ID_1)
    s2 = _make_snapshot(snapshot_id=SAMPLE_SNAPSHOT_ID_2)
    view.set_collection(_make_collection((s1, s2), total=2))

    assert view.selected_snapshot is None
    assert view.selected_resource is None

    view.table.selectRow(0)
    assert view.selected_snapshot == s1
    assert view.selected_resource == s1

    view.table.selectRow(1)
    assert view.selected_snapshot == s2

    view.table.clearSelection()
    assert view.selected_snapshot is None
    view.close()


def test_resources_query_properties_and_helpers() -> None:
    """ResourcesQuery exposes has_active_filters and page_index properties."""
    q_default = ResourcesQuery()
    assert q_default.has_active_filters is False
    assert q_default.page_index == 0

    q_filtered = ResourcesQuery(host_id=SAMPLE_HOST_ID, limit=20, offset=40)
    assert q_filtered.has_active_filters is True
    assert q_filtered.page_index == 2


def test_main_window_repeated_sequential_refreshes(
    qapp: QApplication,
) -> None:
    """Sequential refreshes update model and increment sequence cleanly."""
    client = MagicMock(spec=APIClient)
    s1 = _make_snapshot(snapshot_id=SAMPLE_SNAPSHOT_ID_1)
    s2 = _make_snapshot(snapshot_id=SAMPLE_SNAPSHOT_ID_2)

    client.get_resources.side_effect = [
        _make_collection((s1,), total=1),
        _make_collection((s1, s2), total=2),
    ]

    window = MainWindow(client=client, user=_sample_user())
    window.load_resources()

    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    assert window.resources_view.state == STATE_LOADED
    assert window.resources_view.model.rowCount() == 1
    assert window._resources_request_seq == 1

    # Second refresh
    window.resources_view.refresh_button.click()
    assert window.is_loading_resources is True

    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    assert window.resources_view.state == STATE_LOADED
    assert window.resources_view.model.rowCount() == 2
    assert window._resources_request_seq == 2
    assert client.get_resources.call_count == 2
    window.close()


def test_main_window_rapid_tab_switching_during_active_request(
    qapp: QApplication,
) -> None:
    """Switching tabs while request is in flight does not corrupt state."""
    client = MagicMock(spec=APIClient)
    client.get_events = lambda **kwargs: EventCollection(
        total=0, items=(), limit=50, offset=0
    )
    client.get_processes = lambda **kwargs: ProcessCollection(
        total=0, items=(), limit=50, offset=0
    )
    client.get_files = lambda **kwargs: FileCollection(
        total=0, items=(), limit=50, offset=0
    )
    client.get_status = lambda: None
    client.get_health = lambda: True
    s = _make_snapshot(snapshot_id=SAMPLE_SNAPSHOT_ID_1)

    def slow_fetch(**kwargs: Any) -> ResourceSnapshotCollection:
        time.sleep(0.05)
        return _make_collection((s,), total=1)

    client.get_resources.side_effect = slow_fetch

    window = MainWindow(client=client, user=_sample_user())
    window.load_resources()
    assert window.is_loading_resources is True

    # User rapidly navigates to other tabs while request in flight
    window.shell.navigate_to("Events")
    assert window.shell.current_page_name == "Events"

    window.shell.navigate_to("Processes")
    assert window.shell.current_page_name == "Processes"

    window.shell.navigate_to("Overview")
    assert window.shell.current_page_name == "Overview"

    # Wait for background request to complete
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    assert window.is_loading_resources is False

    # Switch back to Resources
    window.shell.navigate_to("Resources")
    assert window.shell.current_page_name == "Resources"
    assert window.resources_view.state == STATE_LOADED
    assert window.resources_view.model.rowCount() == 1
    assert "Showing 1 of 1 snapshots" in (
        window.resources_view.record_count_label.text()
    )

    # Calling notify_page_activated does not trigger duplicate load
    call_count_before = client.get_resources.call_count
    window.resources_view.notify_page_activated()
    assert client.get_resources.call_count == call_count_before
    window.close()
    QThreadPool.globalInstance().waitForDone(1000)


def test_main_window_logout_during_active_resources_worker(
    qapp: QApplication,
) -> None:
    """Logging out while resources worker is in flight defers close cleanly."""
    client = MagicMock(spec=APIClient)

    def slow_fetch(**kwargs: Any) -> ResourceSnapshotCollection:
        time.sleep(0.05)
        return _make_collection((), total=0)

    client.get_resources.side_effect = slow_fetch

    window = MainWindow(client=client, user=_sample_user())
    window.load_resources()
    assert window.has_active_workers is True

    # User clicks logout
    window.shell.logout_button.click()
    assert window.isVisible() is False
    assert window._pending_close is True
    client.logout.assert_called_once()

    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    assert window.has_active_workers is False
    window.close()
    QThreadPool.globalInstance().waitForDone(1000)


# ==============================================================================
# 15. Resources Query State, Validation & Filter Bar
# ==============================================================================


def test_resources_query_initial_state_and_defaults() -> None:
    """ResourcesQuery initializes with defaults and expected constraints."""
    q = ResourcesQuery()
    assert q.host_id is None
    assert q.start_time is None
    assert q.end_time is None
    assert q.limit == DEFAULT_PAGE_SIZE
    assert q.limit == 50
    assert q.offset == 0
    assert q.has_active_filters is False
    assert q.page_index == 0
    assert q.to_client_kwargs() == {"limit": 50, "offset": 0}


def test_resources_query_immutability() -> None:
    """ResourcesQuery is frozen and raises on attribute assignment."""
    q = ResourcesQuery()
    with pytest.raises(Exception):
        q.offset = 50  # type: ignore[misc]


def test_resources_query_host_id_validation() -> None:
    """ResourcesQuery validates host_id format and normalizes to UUID string."""
    q = ResourcesQuery(host_id=SAMPLE_HOST_ID)
    assert q.host_id == SAMPLE_HOST_ID

    # Accept uuid.UUID instance
    u = uuid.UUID(SAMPLE_HOST_ID)
    q2 = ResourcesQuery(host_id=u)
    assert q2.host_id == SAMPLE_HOST_ID

    with pytest.raises(ValueError, match="host_id must be a valid UUID"):
        ResourcesQuery(host_id="invalid-uuid")

    with pytest.raises(ValueError, match="host_id must be a UUID string or None"):
        ResourcesQuery(host_id=12345)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="host_id must be a UUID string or None"):
        ResourcesQuery(host_id=True)  # type: ignore[arg-type]


def test_resources_query_limit_validation() -> None:
    """ResourcesQuery enforces integer limit between 1 and 100."""
    q_min = ResourcesQuery(limit=1)
    assert q_min.limit == 1

    q_max = ResourcesQuery(limit=100)
    assert q_max.limit == 100

    with pytest.raises(ValueError, match="limit must be an integer"):
        ResourcesQuery(limit=0)

    with pytest.raises(ValueError, match="limit must be an integer"):
        ResourcesQuery(limit=101)

    with pytest.raises(ValueError, match="limit must be an integer"):
        ResourcesQuery(limit=True)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="limit must be an integer"):
        ResourcesQuery(limit="50")  # type: ignore[arg-type]


def test_resources_query_offset_validation() -> None:
    """ResourcesQuery enforces non-negative integer offset."""
    q = ResourcesQuery(offset=0)
    assert q.offset == 0

    q_pos = ResourcesQuery(offset=100)
    assert q_pos.offset == 100

    with pytest.raises(ValueError, match="offset must be a non-negative integer"):
        ResourcesQuery(offset=-1)

    with pytest.raises(ValueError, match="offset must be a non-negative integer"):
        ResourcesQuery(offset=True)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="offset must be a non-negative integer"):
        ResourcesQuery(offset="0")  # type: ignore[arg-type]


def test_resources_query_time_range_validation() -> None:
    """ResourcesQuery validates ISO timestamps and verifies start_time <= end_time."""
    q = ResourcesQuery(
        start_time="2026-03-01T10:00:00Z", end_time="2026-03-01T18:00:00Z"
    )
    assert q.start_time == "2026-03-01T10:00:00Z"
    assert q.end_time == "2026-03-01T18:00:00Z"

    # Datetime instances accepted
    dt1 = datetime(2026, 3, 1, 10, 0, 0, tzinfo=timezone.utc)
    dt2 = datetime(2026, 3, 1, 18, 0, 0, tzinfo=timezone.utc)
    q_dt = ResourcesQuery(start_time=dt1, end_time=dt2)
    assert q_dt.start_time == dt1
    assert q_dt.end_time == dt2

    # Equal timestamps are valid
    q_eq = ResourcesQuery(
        start_time="2026-03-01T12:00:00Z", end_time="2026-03-01T12:00:00Z"
    )
    assert q_eq.start_time == q_eq.end_time

    # Reversed timestamps raise ValueError
    with pytest.raises(
        ValueError, match="start_time must be less than or equal to end_time"
    ):
        ResourcesQuery(
            start_time="2026-03-01T18:00:00Z",
            end_time="2026-03-01T10:00:00Z",
        )

    # Invalid timestamp strings raise ValueError
    with pytest.raises(ValueError, match="Invalid start_time ISO timestamp"):
        ResourcesQuery(start_time="not-a-date")

    with pytest.raises(ValueError, match="Invalid end_time ISO timestamp"):
        ResourcesQuery(end_time="bad-date")

    with pytest.raises(ValueError, match="start_time must not be empty"):
        ResourcesQuery(start_time="   ")

    with pytest.raises(ValueError, match="end_time must not be empty"):
        ResourcesQuery(end_time="   ")


def test_resources_query_page_index() -> None:
    """ResourcesQuery calculates page_index correctly from offset and limit."""
    assert ResourcesQuery(limit=50, offset=0).page_index == 0
    assert ResourcesQuery(limit=50, offset=50).page_index == 1
    assert ResourcesQuery(limit=50, offset=120).page_index == 2
    assert ResourcesQuery(limit=25, offset=75).page_index == 3


def test_resources_query_to_client_kwargs() -> None:
    """ResourcesQuery to_client_kwargs omits None filters and includes active ones."""
    q_empty = ResourcesQuery()
    assert q_empty.to_client_kwargs() == {"limit": 50, "offset": 0}

    q_full = ResourcesQuery(
        host_id=SAMPLE_HOST_ID,
        start_time="2026-03-01T10:00:00Z",
        end_time="2026-03-01T18:00:00Z",
        limit=25,
        offset=50,
    )
    assert q_full.to_client_kwargs() == {
        "host_id": SAMPLE_HOST_ID,
        "start_time": "2026-03-01T10:00:00Z",
        "end_time": "2026-03-01T18:00:00Z",
        "limit": 25,
        "offset": 50,
    }


def test_resources_filter_bar_structure_and_defaults(
    qapp: QApplication,
) -> None:
    """ResourcesFilterBar contains required controls initialized to clean defaults."""
    view = ResourcesView()
    assert view.filter_bar is not None
    assert isinstance(view.filter_bar, ResourcesFilterBar)
    assert view.filter_bar.objectName() == "ResourcesFilterBar"

    # Host ID
    assert view.host_input.text() == ""
    assert view.host_id is None
    assert view.host_input.placeholderText() == "UUID..."

    # Limit
    assert view.limit == 50
    assert view.limit_combo.currentText() == "50"
    if view.limit_input is not None:
        assert view.limit_input.text() == "50"

    # Time filters
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

    # Actions and validation
    assert view.apply_filters_button.text() == "Apply Filters"
    assert view.clear_filters_button.text() == "Clear Filters"
    assert view.filter_validation_label.text() == ""
    assert view.filter_validation_label.property("error") == "false"
    view.close()


def test_resources_pagination_bar_structure_and_defaults(
    qapp: QApplication,
) -> None:
    """ResourcesPaginationBar contains navigation controls initialized disabled."""
    view = ResourcesView()
    assert view.pagination_bar is not None
    assert isinstance(view.pagination_bar, ResourcesPaginationBar)
    assert view.pagination_bar.objectName() == "ResourcesPaginationBar"
    assert view.pagination_frame is view.pagination_bar
    assert view.prev_page_button.isEnabled() is False
    assert view.prev_button.isEnabled() is False
    assert view.next_page_button.isEnabled() is False
    assert view.next_button.isEnabled() is False
    assert view.page_range_label.text() == "0 of 0 snapshots"
    assert view.page_range_summary.text() == "0 of 0 snapshots"
    view.close()


def test_resources_apply_filters_with_valid_criteria(
    qapp: QApplication,
) -> None:
    """Applying valid filter criteria emits query_requested with normalized query."""
    view = ResourcesView()
    emitted: list[ResourcesQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    view.set_host_id(SAMPLE_HOST_ID)
    view.set_limit(25)
    view.set_start_time("2026-03-01T10:00:00Z")
    view.set_end_time("2026-03-01T18:00:00Z")

    view.apply_filters()
    assert len(emitted) == 1
    q = emitted[0]
    assert q.host_id == SAMPLE_HOST_ID
    assert q.limit == 25
    assert q.offset == 0
    assert q.start_time == "2026-03-01T10:00:00Z"
    assert q.end_time == "2026-03-01T18:00:00Z"
    assert q.has_active_filters is True
    assert view.filter_validation_label.text() == ""
    assert view.current_query == q
    view.close()


def test_resources_apply_filters_omits_empty_host_id(
    qapp: QApplication,
) -> None:
    """Applying filters with empty or whitespace host ID treats it as None."""
    view = ResourcesView()
    emitted: list[ResourcesQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    view.host_input.setText("   ")
    view.apply_filters()
    assert len(emitted) == 1
    assert emitted[0].host_id is None
    assert "host_id" not in emitted[0].to_client_kwargs()
    view.close()


def test_resources_apply_filters_rejects_invalid_host_uuid(
    qapp: QApplication,
) -> None:
    """Non-UUID host ID displays inline validation error and suppresses request."""
    view = ResourcesView()
    emitted: list[ResourcesQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    view.host_input.setText("not-a-valid-uuid")
    view.apply_filters()
    assert len(emitted) == 0
    assert "Host ID must be a valid UUID" in view.filter_validation_label.text()
    assert view.filter_validation_label.property("error") == "true"
    assert (
        view.filter_validation_label.accessibleDescription()
        == view.filter_validation_label.text()
    )
    view.close()


def test_resources_apply_filters_rejects_invalid_limit(
    qapp: QApplication,
) -> None:
    """Limit outside 1-100, empty, or non-integer displays inline validation error."""
    view = ResourcesView()
    emitted: list[ResourcesQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    # Limit = 0
    view.set_limit(0)
    view.apply_filters()
    assert len(emitted) == 0
    assert "Limit must be an integer" in view.filter_validation_label.text()

    # Limit = 101
    view.set_limit(101)
    view.apply_filters()
    assert len(emitted) == 0
    assert "Limit must be an integer" in view.filter_validation_label.text()

    # Non-numeric
    view.set_limit("abc")
    view.apply_filters()
    assert len(emitted) == 0
    assert "Limit must be an integer" in view.filter_validation_label.text()

    # Empty string
    view.set_limit("")
    view.apply_filters()
    assert len(emitted) == 0
    assert "Limit must be an integer" in view.filter_validation_label.text()

    # Whitespace only
    view.set_limit("   ")
    view.apply_filters()
    assert len(emitted) == 0
    assert "Limit must be an integer" in view.filter_validation_label.text()
    view.close()


def test_resources_apply_filters_rejects_reversed_time_range(
    qapp: QApplication,
) -> None:
    """Start time later than end time displays inline validation error."""
    view = ResourcesView()
    emitted: list[ResourcesQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    view.set_start_time("2026-03-01T18:00:00Z")
    view.set_end_time("2026-03-01T10:00:00Z")

    view.apply_filters()
    assert len(emitted) == 0
    assert (
        "Start time must be earlier than or equal to end time"
        in view.filter_validation_label.text()
    )
    view.close()


def test_resources_apply_filters_enter_key_triggers_apply(
    qapp: QApplication,
) -> None:
    """Pressing return key in host_input triggers apply_filters."""
    view = ResourcesView()
    emitted: list[ResourcesQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    view.set_host_id(SAMPLE_HOST_ID)
    view.host_input.returnPressed.emit()
    assert len(emitted) == 1
    assert emitted[0].host_id == SAMPLE_HOST_ID
    view.close()


def test_resources_clear_filters_resets_inputs_and_query(
    qapp: QApplication,
) -> None:
    """Clear Filters resets controls and emits query with offset 0 and default limit."""
    view = ResourcesView()
    emitted: list[ResourcesQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    # Apply some filters first
    view.set_host_id(SAMPLE_HOST_ID)
    view.set_limit(25)
    view.set_start_time("2026-03-01T10:00:00Z")
    view.set_end_time("2026-03-01T18:00:00Z")
    view.apply_filters()
    assert len(emitted) == 1

    # Now clear filters
    view.clear_filters()
    assert len(emitted) == 2
    q = emitted[1]
    assert q.host_id is None
    assert q.start_time is None
    assert q.end_time is None
    assert q.limit == DEFAULT_PAGE_SIZE
    assert q.offset == 0
    assert q.has_active_filters is False

    # Verify UI controls reset
    assert view.host_input.text() == ""
    assert view.limit_combo.currentText() == "50"
    assert view.start_time_check.isChecked() is False
    assert view.end_time_check.isChecked() is False
    assert view.filter_validation_label.text() == ""
    view.close()


def test_resources_pagination_next_and_prev(qapp: QApplication) -> None:
    """Previous and Next buttons advance and backtrack pages accurately."""
    view = ResourcesView()
    emitted: list[ResourcesQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    s_items = tuple(_make_snapshot(snapshot_id=f"snap-{i:03d}") for i in range(50))
    col_p1 = _make_collection(s_items, total=120, limit=50, offset=0)
    view.set_collection(col_p1)

    assert view.prev_page_button.isEnabled() is False
    assert view.next_page_button.isEnabled() is True
    assert "Showing 1–50 of 120 snapshots" in view.page_range_label.text()

    # Click Next
    view.next_page_button.click()
    assert len(emitted) == 1
    assert emitted[0].offset == 50
    assert emitted[0].limit == 50

    # Simulate arrival of page 2
    col_p2 = _make_collection(s_items, total=120, limit=50, offset=50)
    view.set_collection(col_p2)

    assert view.prev_page_button.isEnabled() is True
    assert view.next_page_button.isEnabled() is True
    assert "Showing 51–100 of 120 snapshots" in view.page_range_label.text()

    # Click Next again for page 3
    view.next_page_button.click()
    assert len(emitted) == 2
    assert emitted[1].offset == 100

    # Simulate arrival of last page (20 items)
    s_last = tuple(_make_snapshot(snapshot_id=f"snap-last-{i}") for i in range(20))
    col_p3 = _make_collection(s_last, total=120, limit=50, offset=100)
    view.set_collection(col_p3)

    assert view.prev_page_button.isEnabled() is True
    assert view.next_page_button.isEnabled() is False
    assert "Showing 101–120 of 120 snapshots" in view.page_range_label.text()

    # Click Prev to backtrack
    view.prev_page_button.click()
    assert len(emitted) == 3
    assert emitted[2].offset == 50
    view.close()


def test_resources_pagination_preserves_filters_and_limit(
    qapp: QApplication,
) -> None:
    """Pagination preserves active host_id, start_time, end_time, and limit."""
    view = ResourcesView()
    emitted: list[ResourcesQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    view.set_host_id(SAMPLE_HOST_ID)
    view.set_limit(25)
    view.set_start_time("2026-03-01T10:00:00Z")
    view.set_end_time("2026-03-01T18:00:00Z")
    view.apply_filters()
    assert len(emitted) == 1

    s_items = tuple(_make_snapshot(snapshot_id=f"snap-{i}") for i in range(25))
    col = _make_collection(s_items, total=60, limit=25, offset=0)
    view.set_collection(col)

    view.next_page_button.click()
    assert len(emitted) == 2
    q_next = emitted[1]
    assert q_next.offset == 25
    assert q_next.limit == 25
    assert q_next.host_id == SAMPLE_HOST_ID
    assert q_next.start_time == "2026-03-01T10:00:00Z"
    assert q_next.end_time == "2026-03-01T18:00:00Z"
    view.close()


def test_resources_filter_change_resets_offset_to_zero(
    qapp: QApplication,
) -> None:
    """Applying new filters or clearing filters resets offset to 0."""
    view = ResourcesView()
    emitted: list[ResourcesQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    # Set page 2 collection
    s_items = tuple(_make_snapshot(snapshot_id=f"snap-{i}") for i in range(50))
    col = _make_collection(s_items, total=150, limit=50, offset=50)
    view.set_collection(col)
    assert view.current_query.offset == 50

    # Change host ID filter and apply
    view.set_host_id(SAMPLE_HOST_ID)
    view.apply_filters()
    assert len(emitted) == 1
    assert emitted[0].offset == 0
    assert emitted[0].host_id == SAMPLE_HOST_ID
    view.close()


def test_resources_refresh_preserves_query_and_active_offset(
    qapp: QApplication,
) -> None:
    """Refresh action preserves the active query and offset rather than resetting."""
    view = ResourcesView()
    refresh_emitted: list[bool] = []
    view.refresh_requested.connect(lambda: refresh_emitted.append(True))

    s_items = tuple(_make_snapshot(snapshot_id=f"snap-{i}") for i in range(25))
    col = _make_collection(s_items, total=100, limit=25, offset=50)
    view.set_collection(col)
    view.set_host_id(SAMPLE_HOST_ID)

    # Click Refresh Resources
    view.refresh_button.click()
    assert refresh_emitted == [True]
    assert view.current_query.offset == 50
    assert view.current_query.limit == 25
    view.close()


def test_resources_pagination_empty_results_and_short_last_page(
    qapp: QApplication,
) -> None:
    """Empty results and short final pages update pagination controls gracefully."""
    view = ResourcesView()

    # 1. Zero total results
    col_empty = _make_collection((), total=0, limit=50, offset=0)
    view.set_collection(col_empty)
    assert view.state == STATE_EMPTY
    assert view.prev_page_button.isEnabled() is False
    assert view.next_page_button.isEnabled() is False
    assert view.page_range_label.text() == "0 of 0 snapshots"
    assert "0 snapshots (0 total, 0 displayed)" in view.record_count_label.text()

    # 2. Short final page (5 items out of 55 total)
    s_5 = tuple(_make_snapshot(snapshot_id=f"snap-{i}") for i in range(5))
    col_short = _make_collection(s_5, total=55, limit=50, offset=50)
    view.set_collection(col_short)
    assert view.state == STATE_LOADED
    assert view.prev_page_button.isEnabled() is True
    assert view.next_page_button.isEnabled() is False
    assert "Showing 51–55 of 55 snapshots" in view.page_range_label.text()
    view.close()


def test_resources_pagination_out_of_bounds_offset_recovery(
    qapp: QApplication,
) -> None:
    """Out-of-bounds offset with empty results enables previous navigation."""
    view = ResourcesView()
    col_oob = _make_collection((), total=30, limit=50, offset=50)
    view.set_collection(col_oob)
    assert view.state == STATE_EMPTY
    assert view.prev_page_button.isEnabled() is True
    assert view.next_page_button.isEnabled() is False
    assert view.page_range_label.text() == "0 of 30 snapshots"
    view.close()


def test_resources_set_query_synchronizes_ui_controls(
    qapp: QApplication,
) -> None:
    """set_query synchronizes visible input controls with the provided query."""
    view = ResourcesView()
    q = ResourcesQuery(
        host_id=SAMPLE_HOST_ID,
        start_time="2026-03-01T10:00:00Z",
        end_time="2026-03-01T18:00:00Z",
        limit=25,
        offset=0,
    )
    view.set_query(q)
    assert view.host_input.text() == SAMPLE_HOST_ID
    assert view.limit_combo.currentText() == "25"
    assert view.start_time_check.isChecked() is True
    assert view.start_time == "2026-03-01T10:00:00Z"
    assert view.end_time_check.isChecked() is True
    assert view.end_time == "2026-03-01T18:00:00Z"
    assert view.current_query == q

    with pytest.raises(TypeError, match="Expected ResourcesQuery"):
        view.set_query("not-a-query")  # type: ignore[arg-type]
    view.close()


def test_resources_view_enablement_during_loading_state(
    qapp: QApplication,
) -> None:
    """Filter inputs and buttons are disabled during loading and re-enabled after."""
    view = ResourcesView()
    view.set_host_id(SAMPLE_HOST_ID)
    view.set_start_time("2026-03-01T10:00:00Z")

    view.set_loading()
    assert view.refresh_button.isEnabled() is False
    assert view.apply_filters_button.isEnabled() is False
    assert view.clear_filters_button.isEnabled() is False
    assert view.host_input.isEnabled() is False
    assert view.limit_combo.isEnabled() is False
    assert view.start_time_check.isEnabled() is False
    assert view.start_time_edit.isEnabled() is False
    assert view.prev_page_button.isEnabled() is False
    assert view.next_page_button.isEnabled() is False

    # After loaded: controls re-enabled
    s = _make_snapshot()
    view.set_collection(_make_collection((s,), total=1))
    assert view.refresh_button.isEnabled() is True
    assert view.apply_filters_button.isEnabled() is True
    assert view.clear_filters_button.isEnabled() is True
    assert view.host_input.isEnabled() is True
    assert view.limit_combo.isEnabled() is True
    assert view.start_time_check.isEnabled() is True
    assert view.start_time_edit.isEnabled() is True
    view.close()


def test_resources_quick_reset_button_on_empty_state(
    qapp: QApplication,
) -> None:
    """Filtered empty state displays quick-reset button which clears filters."""
    view = ResourcesView()
    view.show()
    view.set_host_id(SAMPLE_HOST_ID)
    view.apply_filters()

    # Empty result with active filters
    view.set_collection(_make_collection((), total=0))
    assert view.state == STATE_EMPTY
    assert view.quick_reset_button.isVisible() is True
    assert "No Matching Resource Telemetry" in view.banner_title_label.text()

    # Click quick reset button
    view.quick_reset_button.click()
    assert view.host_input.text() == ""
    assert view.current_query.has_active_filters is False
    view.close()


def test_resources_datetime_coercion_and_utc_preservation(
    qapp: QApplication,
) -> None:
    """set_start_time coerces datetime and strings preserving UTC timestamp."""
    view = ResourcesView()

    # Python datetime with timezone
    dt = datetime(2026, 3, 1, 14, 30, 0, tzinfo=timezone.utc)
    view.set_start_time(dt)
    assert view.start_time == "2026-03-01T14:30:00Z"
    assert view.start_time_check.isChecked() is True

    # None clears checkbox
    view.set_start_time(None)
    assert view.start_time_check.isChecked() is False
    assert view.start_time is None

    # End time coercion
    view.set_end_time(dt)
    assert view.end_time == "2026-03-01T14:30:00Z"
    assert view.end_time_check.isChecked() is True
    view.close()


# ==============================================================================
# 16. MainWindow Integration & Request Sequencing
# ==============================================================================


def test_resources_main_window_query_requested_dispatches_api_worker(
    qapp: QApplication,
) -> None:
    """Emitting query_requested on view dispatches get_resources with query args."""
    client = MagicMock(spec=APIClient)
    s = _make_snapshot(snapshot_id=SAMPLE_SNAPSHOT_ID_1)
    client.get_resources.return_value = _make_collection(
        (s,), total=1, limit=25, offset=0
    )

    window = MainWindow(client=client, user=_sample_user())
    query = ResourcesQuery(
        host_id=SAMPLE_HOST_ID,
        start_time="2026-03-01T10:00:00Z",
        end_time="2026-03-01T18:00:00Z",
        limit=25,
        offset=0,
    )

    window.shell.resources_view.query_requested.emit(query)
    assert window.is_loading_resources is True

    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    assert window.is_loading_resources is False
    assert window.resources_view.state == STATE_LOADED
    assert window.resources_view.model.rowCount() == 1
    client.get_resources.assert_called_once_with(
        host_id=SAMPLE_HOST_ID,
        start_time="2026-03-01T10:00:00Z",
        end_time="2026-03-01T18:00:00Z",
        limit=25,
        offset=0,
    )
    window.close()


def test_resources_main_window_stale_response_ignored(
    qapp: QApplication,
) -> None:
    """Superseded request results are discarded by request sequence guards."""
    client = MagicMock(spec=APIClient)
    s1 = _make_snapshot(snapshot_id=SAMPLE_SNAPSHOT_ID_1)
    s2 = _make_snapshot(snapshot_id=SAMPLE_SNAPSHOT_ID_2)

    window = MainWindow(client=client, user=_sample_user())

    # Manually simulate sequence guard:
    # seq 1 launched
    window._resources_request_seq = 1
    # seq 2 launched
    window._resources_request_seq = 2

    # Stale result from seq 1 arrives
    window._on_resources_result(
        _make_collection((s1,), total=1), seq=1
    )
    # Stale result ignored: model row count remains 0
    assert window.resources_view.model.rowCount() == 0

    # Fresh result from seq 2 arrives
    window._on_resources_result(
        _make_collection((s2,), total=1), seq=2
    )
    assert window.resources_view.model.rowCount() == 1
    snap = window.resources_view.snapshot_at(0)
    assert snap is not None
    assert snap.id == SAMPLE_SNAPSHOT_ID_2
    window.close()


def test_resources_main_window_retry_after_error_recovers_state(
    qapp: QApplication,
) -> None:
    """Failed request followed by Retry button re-executes query and recovers."""
    client = MagicMock(spec=APIClient)
    s = _make_snapshot(snapshot_id=SAMPLE_SNAPSHOT_ID_1)
    client.get_resources.side_effect = [
        ClientConnectionError("Connection refused"),
        _make_collection((s,), total=1),
    ]

    window = MainWindow(client=client, user=_sample_user())
    window.show()
    window.shell.navigate_to("Resources")
    window.load_resources()

    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    assert window.resources_view.state == STATE_FAILED
    assert window.resources_view.retry_button.isVisible() is True
    assert (
        "Unable to connect"
        in window.resources_view.banner_message_label.text()
    )

    # User clicks Retry
    window.resources_view.retry_button.click()
    assert window.is_loading_resources is True

    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    assert window.resources_view.state == STATE_LOADED
    assert window.resources_view.model.rowCount() == 1
    assert client.get_resources.call_count == 2
    window.close()


def test_resources_pagination_clears_selection(qapp: QApplication) -> None:
    """Pagination navigation via Previous and Next clears table selection."""
    view = ResourcesView()
    s_items = tuple(_make_snapshot(snapshot_id=f"snap-{i}") for i in range(50))
    col = _make_collection(s_items, total=100, limit=50, offset=0)
    view.set_collection(col)

    # Select row 2
    view.table.selectRow(2)
    assert view.table.selectionModel().hasSelection() is True
    assert view.selected_snapshot is not None
    assert view.selected_snapshot.id == "snap-2"

    # Click Next
    view.next_page_button.click()
    assert view.table.selectionModel().hasSelection() is False
    assert view.selected_snapshot is None

    # Load page 2
    col_p2 = _make_collection(s_items, total=100, limit=50, offset=50)
    view.set_collection(col_p2)
    view.table.selectRow(5)
    assert view.selected_snapshot is not None

    # Click Prev
    view.prev_page_button.click()
    assert view.table.selectionModel().hasSelection() is False
    assert view.selected_snapshot is None
    view.close()


def test_resources_main_window_load_resources_with_query_synchronizes_view(
    qapp: QApplication,
) -> None:
    """Calling MainWindow.load_resources with a query synchronizes view query and UI."""
    client = MagicMock(spec=APIClient)
    s = _make_snapshot(snapshot_id=SAMPLE_SNAPSHOT_ID_1)
    client.get_resources.return_value = _make_collection(
        (s,), total=1, limit=25, offset=0
    )

    window = MainWindow(client=client, user=_sample_user())
    query = ResourcesQuery(
        host_id=SAMPLE_HOST_ID,
        start_time="2026-03-01T10:00:00Z",
        end_time="2026-03-01T18:00:00Z",
        limit=25,
        offset=0,
    )

    window.load_resources(query)
    assert window.resources_view.current_query == query
    assert window.resources_view.host_input.text() == SAMPLE_HOST_ID
    assert window.resources_view.limit_combo.currentText() == "25"
    assert window.resources_view.start_time == "2026-03-01T10:00:00Z"
    assert window.resources_view.end_time == "2026-03-01T18:00:00Z"

    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    assert window.resources_view.state == STATE_LOADED
    window.close()
    QThreadPool.globalInstance().waitForDone(1000)


# ==============================================================================
# 14. Resource Utilization Summary Cards & Detailed Snapshot Inspector (0.4.20)
# ==============================================================================


def test_summary_cards_derived_from_latest_snapshot_in_collection(
    qapp: QApplication,
) -> None:
    """Summary cards derive metrics from the newest ResourceSnapshot in collection."""
    s1 = _make_snapshot(
        snapshot_id=SAMPLE_SNAPSHOT_ID_1,
        timestamp=SAMPLE_TIME_1,
        cpu_percent=10.0,
        memory_percent=30.0,
        disk_usage_percent=40.0,
        memory_used=4_294_967_296,    # 4 GiB
        memory_total=17_179_869_184,  # 16 GiB
    )
    s2 = _make_snapshot(
        snapshot_id=SAMPLE_SNAPSHOT_ID_2,
        timestamp=SAMPLE_TIME_2,
        cpu_percent=20.0,
        memory_percent=50.0,
        disk_usage_percent=60.0,
        memory_used=8_589_934_592,    # 8 GiB
        memory_total=17_179_869_184,
    )
    s3 = _make_snapshot(
        snapshot_id=SAMPLE_SNAPSHOT_ID_3,
        timestamp=SAMPLE_TIME_3,
        cpu_percent=35.0,
        memory_percent=70.0,
        disk_usage_percent=80.0,
        memory_used=12_884_901_888,   # 12 GiB
        memory_total=17_179_869_184,
    )

    view = ResourcesView()
    assert isinstance(view.summary_cards, ResourcesSummaryCardsFrame)
    assert isinstance(view.inspector, ResourceInspectorPanel)
    col = _make_collection((s1, s2, s3), total=3)
    view.set_collection(col)

    assert view.summary_cards.current_snapshot is s3
    assert view.cpu_card.value == "35.0%"
    assert view.memory_card.value == "70.0%"
    assert view.disk_card.value == "80.0%"
    assert view.memory_used_total_card.value == "12.0 GiB / 16.0 GiB"
    assert view.cpu_card.detail == "Latest snapshot"
    view.close()


def test_summary_cards_non_chronological_order(qapp: QApplication) -> None:
    """Summary cards correctly pick newest snapshot even if data is out of order."""
    s_early = _make_snapshot(
        snapshot_id=SAMPLE_SNAPSHOT_ID_1,
        timestamp=SAMPLE_TIME_1,
        cpu_percent=15.0,
    )
    s_late = _make_snapshot(
        snapshot_id=SAMPLE_SNAPSHOT_ID_2,
        timestamp=SAMPLE_TIME_3,
        cpu_percent=88.5,
    )
    s_mid = _make_snapshot(
        snapshot_id=SAMPLE_SNAPSHOT_ID_3,
        timestamp=SAMPLE_TIME_2,
        cpu_percent=45.0,
    )

    view = ResourcesView()
    # Out of order: early, late, mid
    col = _make_collection((s_early, s_late, s_mid), total=3)
    view.set_collection(col)

    assert view.summary_cards.current_snapshot is s_late
    assert view.cpu_card.value == "88.5%"

    # Reverse order: late, mid, early
    col2 = _make_collection((s_late, s_mid, s_early), total=3)
    view.set_collection(col2)

    assert view.summary_cards.current_snapshot is s_late
    assert view.cpu_card.value == "88.5%"
    view.close()


def test_summary_cards_nullable_and_zero_values(qapp: QApplication) -> None:
    """Nullable metrics show '—' while zero values (0.0%, 0 B) are preserved."""
    view = ResourcesView()

    # Nullable metrics
    s_null = _make_snapshot(
        cpu_percent=None,
        memory_percent=None,
        disk_usage_percent=None,
        memory_used=None,
        memory_total=None,
    )
    col_null = _make_collection((s_null,), total=1)
    view.set_collection(col_null)

    assert view.cpu_card.value == EMPTY_PLACEHOLDER
    assert view.memory_card.value == EMPTY_PLACEHOLDER
    assert view.disk_card.value == EMPTY_PLACEHOLDER
    assert view.memory_used_total_card.value == EMPTY_PLACEHOLDER

    # Zero metrics
    s_zero = _make_snapshot(
        cpu_percent=0.0,
        memory_percent=0.0,
        disk_usage_percent=0.0,
        memory_used=0,
        memory_total=1073741824,
    )
    col_zero = _make_collection((s_zero,), total=1)
    view.set_collection(col_zero)

    assert view.cpu_card.value == "0.0%"
    assert view.memory_card.value == "0.0%"
    assert view.disk_card.value == "0.0%"
    assert view.memory_used_total_card.value == "0 B / 1.0 GiB"
    view.close()


def test_summary_cards_memory_used_total_partial_availability(
    qapp: QApplication,
) -> None:
    """Memory used vs total handles partial nullability cleanly."""
    view = ResourcesView()

    # Used only
    s1 = _make_snapshot(memory_used=1073741824, memory_total=None)
    view.set_collection(_make_collection((s1,), total=1))
    assert view.memory_used_total_card.value == f"1.0 GiB / {EMPTY_PLACEHOLDER}"

    # Total only
    s2 = _make_snapshot(memory_used=None, memory_total=2147483648)
    view.set_collection(_make_collection((s2,), total=1))
    assert view.memory_used_total_card.value == f"{EMPTY_PLACEHOLDER} / 2.0 GiB"
    view.close()


def test_summary_cards_empty_collection_and_reset(
    qapp: QApplication,
) -> None:
    """Empty collection or set_not_loaded resets cards to placeholders."""
    s = _make_snapshot(cpu_percent=50.0)
    view = ResourcesView()
    view.set_collection(_make_collection((s,), total=1))
    assert view.cpu_card.value == "50.0%"

    # Empty collection resets
    view.set_collection(_make_collection((), total=0))
    assert view.summary_cards.current_snapshot is None
    assert view.cpu_card.value == EMPTY_PLACEHOLDER
    assert view.cpu_card.detail is None

    # Load again then set_not_loaded resets
    view.set_collection(_make_collection((s,), total=1))
    assert view.cpu_card.value == "50.0%"
    view.set_not_loaded()
    assert view.summary_cards.current_snapshot is None
    assert view.cpu_card.value == EMPTY_PLACEHOLDER
    view.close()


def test_summary_cards_update_on_page_change_and_query(
    qapp: QApplication,
) -> None:
    """Summary cards update when pagination or query delivers new snapshots."""
    view = ResourcesView()
    s_p1 = _make_snapshot(
        snapshot_id=SAMPLE_SNAPSHOT_ID_1,
        timestamp=SAMPLE_TIME_1,
        cpu_percent=12.0,
    )
    col_p1 = _make_collection((s_p1,), total=100, limit=50, offset=0)
    view.set_collection(col_p1)
    assert view.cpu_card.value == "12.0%"

    s_p2 = _make_snapshot(
        snapshot_id=SAMPLE_SNAPSHOT_ID_2,
        timestamp=SAMPLE_TIME_2,
        cpu_percent=64.0,
    )
    col_p2 = _make_collection((s_p2,), total=100, limit=50, offset=50)
    view.set_collection(col_p2)
    assert view.cpu_card.value == "64.0%"
    view.close()


def test_summary_cards_no_misleading_aggregates(qapp: QApplication) -> None:
    """Summary cards display the single latest snapshot, not misleading averages."""
    s1 = _make_snapshot(
        snapshot_id=SAMPLE_SNAPSHOT_ID_1,
        timestamp=SAMPLE_TIME_1,
        cpu_percent=10.0,
        memory_used=1000,
    )
    s2 = _make_snapshot(
        snapshot_id=SAMPLE_SNAPSHOT_ID_2,
        timestamp=SAMPLE_TIME_2,
        cpu_percent=30.0,
        memory_used=2000,
    )
    view = ResourcesView()
    view.set_collection(_make_collection((s1, s2), total=2))

    # Should be 30.0% (from s2), NOT 20.0% (average)
    assert view.cpu_card.value == "30.0%"
    assert (
        "2000 B" in view.memory_used_total_card.value
        or "1.9 KiB" in view.memory_used_total_card.value
        or "2.0 KiB" in view.memory_used_total_card.value
    )
    view.close()


def test_inspector_selection_displays_exact_snapshot(
    qapp: QApplication,
) -> None:
    """Selecting a table row displays the exact ResourceSnapshot in inspector."""
    s1 = _make_snapshot(
        snapshot_id=SAMPLE_SNAPSHOT_ID_1,
        timestamp=SAMPLE_TIME_1,
        cpu_percent=15.0,
    )
    s2 = _make_snapshot(
        snapshot_id=SAMPLE_SNAPSHOT_ID_2,
        timestamp=SAMPLE_TIME_2,
        cpu_percent=45.0,
    )
    view = ResourcesView()
    view.show()
    view.set_collection(_make_collection((s1, s2), total=2))

    assert view.inspector.isVisible() is False
    assert view.inspector.current_snapshot is None

    # Select row 0
    view.table.selectRow(0)
    assert view.inspector.isVisible() is True
    assert view.inspector.current_snapshot is s1
    assert view.selected_snapshot is s1
    assert view.inspector.get_field_value("id") == SAMPLE_SNAPSHOT_ID_1
    assert view.inspector.get_field_value("cpu_percent") == "15.0%"

    # Select row 1
    view.table.selectRow(1)
    assert view.inspector.isVisible() is True
    assert view.inspector.current_snapshot is s2
    assert view.selected_snapshot is s2
    assert view.inspector.get_field_value("id") == SAMPLE_SNAPSHOT_ID_2
    assert view.inspector.get_field_value("cpu_percent") == "45.0%"
    view.close()


def test_inspector_all_fields_represented(qapp: QApplication) -> None:
    """Inspector displays all 11 fields with non-lossy byte representation."""
    s = _make_snapshot(
        snapshot_id=SAMPLE_SNAPSHOT_ID_1,
        host_id=SAMPLE_HOST_ID,
        timestamp=SAMPLE_TIME_1,
        created_at=SAMPLE_TIME_2,
        cpu_percent=25.0,
        memory_percent=50.0,
        disk_usage_percent=75.0,
        memory_used=8_589_934_592,    # 8 GiB
        memory_total=17_179_869_184,  # 16 GiB
        disk_read_bytes=1048576,      # 1 MiB
        disk_write_bytes=2097152,     # 2 MiB
    )
    view = ResourcesView()
    view.show()
    view.set_collection(_make_collection((s,), total=1))
    view.table.selectRow(0)

    assert view.inspector.get_field_value("id") == SAMPLE_SNAPSHOT_ID_1
    assert view.inspector.get_field_value("host_id") == SAMPLE_HOST_ID
    assert view.inspector.get_field_value("timestamp") == SAMPLE_TIME_1
    assert view.inspector.get_field_value("created_at") == SAMPLE_TIME_2
    assert view.inspector.get_field_value("cpu_percent") == "25.0%"
    assert view.inspector.get_field_value("memory_percent") == "50.0%"
    assert view.inspector.get_field_value("disk_usage_percent") == "75.0%"

    # Byte metrics have both human-readable unit and exact byte count
    mem_used_txt = view.inspector.get_field_value("memory_used")
    assert "8.0 GiB" in mem_used_txt
    assert "8,589,934,592 bytes" in mem_used_txt

    mem_total_txt = view.inspector.get_field_value("memory_total")
    assert "16.0 GiB" in mem_total_txt
    assert "17,179,869,184 bytes" in mem_total_txt

    disk_read_txt = view.inspector.get_field_value("disk_read_bytes")
    assert "1.0 MiB" in disk_read_txt
    assert "1,048,576 bytes" in disk_read_txt

    disk_write_txt = view.inspector.get_field_value("disk_write_bytes")
    assert "2.0 MiB" in disk_write_txt
    assert "2,097,152 bytes" in disk_write_txt
    view.close()


def test_inspector_nullable_values_displayed_as_unavailable(
    qapp: QApplication,
) -> None:
    """Inspector displays nullable values as '—' and never 'None' or 0."""
    s = _make_snapshot(
        cpu_percent=None,
        memory_percent=None,
        disk_usage_percent=None,
        memory_used=None,
        memory_total=None,
        disk_read_bytes=None,
        disk_write_bytes=None,
    )
    view = ResourcesView()
    view.show()
    view.set_collection(_make_collection((s,), total=1))
    view.table.selectRow(0)

    for key in (
        "cpu_percent",
        "memory_percent",
        "disk_usage_percent",
        "memory_used",
        "memory_total",
        "disk_read_bytes",
        "disk_write_bytes",
    ):
        val = view.inspector.get_field_value(key)
        assert val == EMPTY_PLACEHOLDER
        assert val != "None"
        assert val != "0"
    view.close()


def test_inspector_clearing_selection_hides_inspector(
    qapp: QApplication,
) -> None:
    """Clearing row selection or clicking close hides the inspector."""
    s = _make_snapshot()
    view = ResourcesView()
    view.show()
    view.set_collection(_make_collection((s,), total=1))

    # Select row -> visible
    view.table.selectRow(0)
    assert view.inspector.isVisible() is True

    # Clear selection -> hidden
    view.table.clearSelection()
    assert view.inspector.isVisible() is False
    assert view.inspector.current_snapshot is None

    # Select row again -> visible
    view.table.selectRow(0)
    assert view.inspector.isVisible() is True

    # Click close button -> hidden and selection cleared
    view.inspector.close_button.click()
    assert view.inspector.isVisible() is False
    assert view.table.selectionModel().hasSelection() is False
    view.close()


def test_inspector_collection_replacement_clears_stale_details(
    qapp: QApplication,
) -> None:
    """Replacing the collection prevents displaying stale snapshot details."""
    s1 = _make_snapshot(snapshot_id=SAMPLE_SNAPSHOT_ID_1)
    s2 = _make_snapshot(snapshot_id=SAMPLE_SNAPSHOT_ID_2)

    view = ResourcesView()
    view.show()
    view.set_collection(_make_collection((s1,), total=1))
    view.table.selectRow(0)
    assert view.inspector.current_snapshot is s1

    # Replace collection with collection 2
    view.set_collection(_make_collection((s2,), total=1))
    assert view.table.selectionModel().hasSelection() is False
    assert view.inspector.isVisible() is False
    assert view.inspector.current_snapshot is None
    view.close()


def test_inspector_pagination_and_query_clears_selection(
    qapp: QApplication,
) -> None:
    """Pagination and query operations clear selection and reset inspector."""
    s_items = tuple(
        _make_snapshot(snapshot_id=str(uuid.uuid4())) for _ in range(55)
    )
    view = ResourcesView()
    view.show()
    col = _make_collection(s_items[:50], total=55, limit=50, offset=0)
    view.set_collection(col)

    # 1. apply_filters clears selection
    view.table.selectRow(0)
    assert view.inspector.isVisible() is True
    view.apply_filters()
    assert view.inspector.isVisible() is False

    # 2. clear_filters clears selection
    view.table.selectRow(0)
    assert view.inspector.isVisible() is True
    view.clear_filters()
    assert view.inspector.isVisible() is False

    # 3. go_next_page clears selection
    view.table.selectRow(0)
    assert view.inspector.isVisible() is True
    view.go_next_page()
    assert view.inspector.isVisible() is False

    # Load page 2
    col_p2 = _make_collection(s_items[50:], total=55, limit=50, offset=50)
    view.set_collection(col_p2)
    view.table.selectRow(0)
    assert view.inspector.isVisible() is True

    # 4. go_prev_page clears selection
    view.go_prev_page()
    assert view.inspector.isVisible() is False
    view.close()


def test_inspector_failed_refresh_with_retained_rows_preserves_semantics(
    qapp: QApplication,
) -> None:
    """Failed refresh retains records; inspector cleared until retained row selected."""
    s = _make_snapshot(
        snapshot_id=SAMPLE_SNAPSHOT_ID_1,
        cpu_percent=42.0,
    )
    view = ResourcesView()
    view.show()
    view.set_collection(_make_collection((s,), total=1))
    view.table.selectRow(0)
    assert view.inspector.isVisible() is True

    # Refresh begins
    view.set_loading()
    assert view.table.selectionModel().hasSelection() is False
    assert view.inspector.isVisible() is False

    # Refresh fails
    view.set_error("Connection timed out")
    assert view.table.selectionModel().hasSelection() is False
    assert view.inspector.isVisible() is False

    # Retained rows are still accessible; selecting one displays it
    assert view.model.rowCount() == 1
    view.table.selectRow(0)
    assert view.inspector.isVisible() is True
    assert view.inspector.current_snapshot is s
    assert view.inspector.get_field_value("cpu_percent") == "42.0%"
    view.close()


def test_row_selection_does_not_issue_api_requests(
    qapp: QApplication,
) -> None:
    """Selecting table rows never emits load, refresh, or query signals."""
    s1 = _make_snapshot(snapshot_id=SAMPLE_SNAPSHOT_ID_1)
    s2 = _make_snapshot(snapshot_id=SAMPLE_SNAPSHOT_ID_2)

    view = ResourcesView()
    view.set_collection(_make_collection((s1, s2), total=2))

    load_spy: list[bool] = []
    refresh_spy: list[bool] = []
    query_spy: list[Any] = []

    view.load_requested.connect(lambda: load_spy.append(True))
    view.refresh_requested.connect(lambda: refresh_spy.append(True))
    view.query_requested.connect(lambda q: query_spy.append(q))

    # User interactions: selecting rows, deselecting, reselecting
    view.table.selectRow(0)
    view.table.selectRow(1)
    view.table.clearSelection()
    view.table.selectRow(0)
    view.inspector.close_button.click()

    assert len(load_spy) == 0
    assert len(refresh_spy) == 0
    assert len(query_spy) == 0
    view.close()


def test_resources_view_prepopulated_model_preserves_data(
    qapp: QApplication,
) -> None:
    """Initializing ResourcesView with a preloaded model preserves records."""
    s1 = _make_snapshot(snapshot_id=SAMPLE_SNAPSHOT_ID_1, cpu_percent=22.0)
    col = _make_collection((s1,), total=1)
    model = ResourcesTableModel(collection=col)
    view = ResourcesView(model=model)

    assert view.model.rowCount() == 1
    assert view.summary_cards.current_snapshot is s1
    assert view.cpu_card.value == "22.0%"
    assert view.state == STATE_LOADED
    view.close()


def test_resources_view_set_query_clears_selection_and_inspector(
    qapp: QApplication,
) -> None:
    """Calling set_query directly clears table selection and inspector panel."""
    s = _make_snapshot()
    view = ResourcesView()
    view.show()
    view.set_collection(_make_collection((s,), total=1))
    view.table.selectRow(0)
    assert view.inspector.isVisible() is True
    assert view.inspector.current_snapshot is s

    new_query = ResourcesQuery(limit=25, offset=0)
    view.set_query(new_query)

    assert view.table.selectionModel().hasSelection() is False
    assert view.inspector.isVisible() is False
    assert view.inspector.current_snapshot is None
    view.close()


def test_resources_view_rapid_table_arrow_key_navigation(
    qapp: QApplication,
) -> None:
    """Rapid row selection updates inspector accurately without signal noise."""
    snapshots = tuple(
        _make_snapshot(
            snapshot_id=f"00000000-0000-0000-0000-{i:012d}",
            cpu_percent=float(i + 1),
        )
        for i in range(10)
    )
    col = _make_collection(snapshots, total=10)
    view = ResourcesView()
    view.show()
    view.set_collection(col)

    load_spy: list[bool] = []
    view.load_requested.connect(lambda: load_spy.append(True))

    for idx in range(10):
        view.table.selectRow(idx)
        assert view.inspector.isVisible() is True
        assert view.inspector.current_snapshot is snapshots[idx]
        assert (
            view.inspector.get_field_value("cpu_percent")
            == f"{float(idx + 1):.1f}%"
        )

    assert len(load_spy) == 0
    view.close()


def test_resources_view_trend_charts_integration(
    qapp: QApplication,
) -> None:
    """ResourcesView coordinates ResourceTrendChartsWidget lifecycle and state."""
    view = ResourcesView()
    assert isinstance(view.trend_charts, ResourceTrendChartsWidget)
    assert view.trend_charts_widget is view.trend_charts
    assert view.trend_charts.state == STATE_NOT_LOADED

    # Loading state
    view.set_loading()
    assert view.trend_charts.state == STATE_LOADING

    # Loaded state
    s1 = _make_snapshot(timestamp=SAMPLE_TIME_1, cpu_percent=25.0)
    s2 = _make_snapshot(timestamp=SAMPLE_TIME_2, cpu_percent=50.0)
    col = _make_collection((s1, s2), total=2)
    view.set_collection(col)
    assert view.trend_charts.state == STATE_LOADED
    assert len(view.trend_charts.trend_points) == 2

    # Error state retains telemetry
    view.set_error("Connection refused")
    assert view.trend_charts.state == STATE_FAILED
    assert len(view.trend_charts.trend_points) == 2
    assert "Refresh failed" in view.trend_charts.scope_text

    # Reset to not loaded
    view.set_not_loaded()
    assert view.trend_charts.state == STATE_NOT_LOADED
    assert len(view.trend_charts.trend_points) == 0
    view.close()


def test_resources_view_table_and_chart_selection_synchronization(
    qapp: QApplication,
) -> None:
    """Table selection and chart selection stay strictly synchronized."""
    s1 = _make_snapshot(timestamp=SAMPLE_TIME_1, cpu_percent=10.0)
    s2 = _make_snapshot(timestamp=SAMPLE_TIME_2, cpu_percent=20.0)
    col = _make_collection((s1, s2), total=2)

    view = ResourcesView()
    view.show()
    view.set_collection(col)

    # 1. Select row in table -> chart highlight updates
    view.table.selectRow(1)
    assert view.selected_snapshot is s2
    assert view.trend_charts.selected_snapshot is s2
    assert view.inspector.current_snapshot is s2

    # 2. Select snapshot via chart -> table and inspector update
    view.trend_charts.snapshot_selected.emit(s1)
    assert view.selected_snapshot is s1
    assert view.trend_charts.selected_snapshot is s1
    assert view.inspector.current_snapshot is s1

    # 3. Clear table selection -> chart highlight clears
    view.table.clearSelection()
    assert view.selected_snapshot is None
    assert view.trend_charts.selected_snapshot is None
    assert view.inspector.current_snapshot is None

    # 4. Chart selects None -> table selection clears
    view.table.selectRow(0)
    assert view.selected_snapshot is s1
    view.trend_charts.snapshot_selected.emit(None)
    assert view.selected_snapshot is None
    assert view.trend_charts.selected_snapshot is None
    assert view.inspector.current_snapshot is None
    view.close()


def test_resources_view_query_validation_properties_and_selection_fallbacks(
    qapp: QApplication,
) -> None:
    """ResourcesQuery and ResourcesView handle validation, aliases, and fallbacks."""
    from PySide6.QtCore import QItemSelectionModel

    # 1. ResourcesQuery validation
    with pytest.raises(ValueError, match="start_time must be an ISO timestamp"):
        ResourcesQuery(start_time=True)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="start_time must not be empty"):
        ResourcesQuery(start_time="   ")

    with pytest.raises(ValueError, match="end_time must be an ISO timestamp"):
        ResourcesQuery(end_time=True)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="end_time must not be empty"):
        ResourcesQuery(end_time="   ")

    with pytest.raises(ValueError, match="limit must be an integer"):
        ResourcesQuery(limit=0)

    q = ResourcesQuery(limit=10, offset=40)
    assert q.page_index == 4
    object.__setattr__(q, "limit", 0)
    assert q.page_index == 0

    view = ResourcesView()

    # 2. Host ID & limit helpers
    view.set_host_id(None)
    assert view.host_id is None
    view.set_host_id("11111111-1111-4111-8111-111111111111")
    assert view.host_id == "11111111-1111-4111-8111-111111111111"
    view.set_limit(25)
    assert view.limit == 25

    # 3. Aliases
    assert view.host_id_input is view.host_input
    assert view.apply_button is view.apply_filters_button
    assert view.clear_button is view.clear_filters_button
    assert view.reset_button is view.clear_filters_button
    assert view.validation_label is view.filter_validation_label
    assert view.pagination_frame is view.pagination_bar
    assert view.prev_button is view.prev_page_button
    assert view.next_button is view.next_page_button
    assert view.page_range_summary is view.page_range_label
    assert view.summary_cards_frame is view.summary_cards

    # 4. Cell selection fallback in selected_snapshot
    s1 = _make_snapshot(timestamp=SAMPLE_TIME_1)
    col = _make_collection((s1,), total=1)
    view.set_collection(col)

    sel_model = view.table.selectionModel()
    idx = view.model.index(0, 1)
    sel_model.select(idx, QItemSelectionModel.SelectionFlag.Select)
    assert view.selected_snapshot is s1
    assert view.selected_resource is s1
    assert view.resource_at(0) is s1

    view.close()






