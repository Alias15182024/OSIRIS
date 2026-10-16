"""Unit and integration tests for OSIRIS FilesView and Application Shell.

Verifies:
1. FilesView construction, layout, and stable object names.
2. QTableView integration with FilesTableModel.
3. No API client constructed inside visual view.
4. View state transitions: not_loaded, loading, loaded, empty, and failed.
5. Lazy loading contract: initial activation requests load; revisits do not.
6. Guarding against duplicate concurrent refreshes.
7. Real FileCollection presentation and metadata based on total.
8. Empty response handling and honest empty messaging.
9. Retained records distinguished from fresh results upon failed refresh.
10. Sanitized user-facing error messages for all typed exceptions.
11. Asynchronous MainWindow integration using ApiWorker and APIClient.get_files.
12. Thread safety: API calls off GUI thread, widget updates on GUI thread.
13. Lifecycle safety: in-flight workers prevent premature close.
14. Server-side path, file_type, and host_id filtering and input validation.
15. Server-side pagination (previous/next page boundaries).
16. Shell navigation between Files, Events, Processes, and Resources.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from typing import Any
from unittest.mock import MagicMock

import pytest
from PySide6.QtCore import QThreadPool
from PySide6.QtGui import QCloseEvent
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
    ValidationError,
)
from desktop.client.models import (
    FileCollection,
    FileRecord,
    User,
)
from desktop.models.files_model import (
    COLUMN_FILE_TYPE,
    COLUMN_FIRST_SEEN,
    COLUMN_HOST_ID,
    COLUMN_INODE,
    COLUMN_LAST_SEEN,
    COLUMN_PATH,
    FilesTableModel,
)
from desktop.ui.app_shell import AppShell
from desktop.ui.main_window import MainWindow
from desktop.ui.views.files_view import (
    STATE_EMPTY,
    STATE_FAILED,
    STATE_LOADED,
    STATE_LOADING,
    STATE_NOT_LOADED,
    FilesQuery,
    FilesView,
)

SAMPLE_FILE_ID_1 = "11111111-1111-4111-8111-111111111111"
SAMPLE_FILE_ID_2 = "22222222-2222-4222-8222-222222222222"
SAMPLE_HOST_ID = "33333333-3333-4333-8333-333333333333"
SAMPLE_TIME_1 = "2026-03-01T12:00:00Z"
SAMPLE_TIME_2 = "2026-03-01T12:01:00Z"


def _sample_user() -> User:
    """Return a representative authenticated User instance."""
    return User(
        id="usr-files-001",
        username="lead_analyst",
        display_name="Lead Analyst",
        role="admin",
        is_active=True,
        created_at="2026-01-01T00:00:00Z",
    )


def _make_file(
    file_id: str = SAMPLE_FILE_ID_1,
    host_id: str = SAMPLE_HOST_ID,
    path: str = "/etc/osiris/config.yaml",
    file_type: str | None = "file",
    inode: int | None = 1048576,
    first_seen_at: str = SAMPLE_TIME_1,
    last_seen_at: str | None = SAMPLE_TIME_2,
    created_at: str = SAMPLE_TIME_1,
) -> FileRecord:
    """Create a valid FileRecord instance for view tests."""
    return FileRecord(
        id=file_id,
        host_id=host_id,
        path=path,
        file_type=file_type,
        inode=inode,
        first_seen_at=first_seen_at,
        last_seen_at=last_seen_at,
        created_at=created_at,
    )


def _make_collection(
    items: tuple[FileRecord, ...] = (),
    total: int = 0,
    limit: int = 50,
    offset: int = 0,
) -> FileCollection:
    """Create a valid FileCollection instance."""
    return FileCollection(
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


def test_files_view_instantiation(qapp: QApplication) -> None:
    """FilesView constructs successfully with required child widgets."""
    view = FilesView()
    assert view is not None
    assert isinstance(view, QWidget)
    assert view.objectName() == "Page_Files"
    assert view.state == STATE_NOT_LOADED
    assert view.model.rowCount() == 0


def test_files_view_stable_object_names(qapp: QApplication) -> None:
    """FilesView exposes stable object names across all key child controls."""
    view = FilesView()

    assert view.findChild(QLabel, "PageTitle") is not None
    assert view.findChild(QLabel, "PageDescription") is not None
    assert view.findChild(QFrame, "FilesFilterBar") is not None
    assert view.findChild(QLabel, "FilesPathFilterLabel") is not None
    assert view.findChild(QLineEdit, "FilesPathFilterInput") is not None
    assert view.findChild(QLabel, "FilesTypeFilterLabel") is not None
    assert view.findChild(QComboBox, "FilesTypeFilterCombo") is not None
    assert view.findChild(QLabel, "FilesHostIdFilterLabel") is not None
    assert view.findChild(QLineEdit, "FilesHostIdFilterInput") is not None
    assert view.findChild(QPushButton, "ApplyFilesFiltersButton") is not None
    assert view.findChild(QPushButton, "ResetFilesFiltersButton") is not None
    assert view.findChild(QLabel, "FilesFilterValidationLabel") is not None
    assert view.findChild(QFrame, "FilesToolbar") is not None
    assert view.findChild(QPushButton, "RefreshFilesButton") is not None
    assert view.findChild(QLabel, "RecordCountSummary") is not None
    assert view.findChild(QFrame, "FilesStatusBanner") is not None
    assert view.findChild(QLabel, "FilesStatusBannerTitle") is not None
    assert view.findChild(QLabel, "FilesStatusBannerMessage") is not None
    assert view.findChild(QPushButton, "QuickResetFilesFiltersButton") is not None
    assert view.findChild(QPushButton, "RetryFilesButton") is not None
    assert view.findChild(QTableView, "FilesTable") is not None
    assert view.findChild(QFrame, "FilesPaginationFrame") is not None
    assert view.findChild(QPushButton, "PrevFilesPageButton") is not None
    assert view.findChild(QPushButton, "NextFilesPageButton") is not None
    assert view.findChild(QLabel, "FilesPageRangeLabel") is not None


def test_files_view_does_not_instantiate_api_client(
    qapp: QApplication,
) -> None:
    """FilesView contains no APIClient instance or HTTP transport."""
    view = FilesView()
    assert not hasattr(view, "client")
    assert not hasattr(view, "_client")


def test_files_view_uses_files_table_model(qapp: QApplication) -> None:
    """FilesView table is backed by FilesTableModel."""
    view = FilesView()
    assert isinstance(view.model, FilesTableModel)
    assert view.table.model() is view.model


def test_files_view_table_configuration(qapp: QApplication) -> None:
    """FilesView table has correct headers, sizing, and selection properties."""
    view = FilesView()
    table = view.table
    assert table.selectionBehavior() == QTableView.SelectionBehavior.SelectRows
    assert table.selectionMode() == QTableView.SelectionMode.SingleSelection
    assert table.editTriggers() == QTableView.EditTrigger.NoEditTriggers
    assert not table.isSortingEnabled()


# ==============================================================================
# 2. State Transitions
# ==============================================================================


def test_files_view_initial_state_is_not_loaded(qapp: QApplication) -> None:
    """FilesView starts in STATE_NOT_LOADED."""
    view = FilesView()
    view.show()
    assert view.state == STATE_NOT_LOADED
    assert view.refresh_button.isEnabled()
    assert not view.retry_button.isVisible()
    assert not view.quick_reset_button.isVisible()
    assert not view.prev_page_button.isEnabled()
    assert not view.next_page_button.isEnabled()
    assert view.status_banner.isVisible()
    view.close()


def test_files_view_loading_state(qapp: QApplication) -> None:
    """set_loading disables action controls and updates banner."""
    view = FilesView()
    view.show()
    view.set_loading()

    assert view.state == STATE_LOADING
    assert not view.refresh_button.isEnabled()
    assert not view.retry_button.isEnabled()
    assert not view.apply_filters_button.isEnabled()
    assert not view.clear_filters_button.isEnabled()
    assert not view.prev_page_button.isEnabled()
    assert not view.next_page_button.isEnabled()
    assert view.status_banner.isVisible()
    view.close()


def test_files_view_loaded_state_with_records(qapp: QApplication) -> None:
    """set_collection with items transitions to STATE_LOADED and hides banner."""
    view = FilesView()
    view.show()
    f1 = _make_file(path="/etc/passwd", file_type="file")
    f2 = _make_file(path="/etc/shadow", file_type="file")
    col = _make_collection(items=(f1, f2), total=2, limit=50, offset=0)

    view.set_collection(col)

    assert view.state == STATE_LOADED
    assert view.model.rowCount() == 2
    assert not view.status_banner.isVisible()
    assert view.refresh_button.isEnabled()
    assert "Showing 2 of 2 files" in view.record_count_label.text()
    assert "1–2 of 2" in view.page_range_label.text()
    view.close()


def test_files_view_empty_state_without_filters(qapp: QApplication) -> None:
    """set_collection with 0 items transitions to STATE_EMPTY."""
    view = FilesView()
    view.show()
    col = _make_collection(items=(), total=0, limit=50, offset=0)

    view.set_collection(col)

    assert view.state == STATE_EMPTY
    assert view.model.rowCount() == 0
    assert view.status_banner.isVisible()
    assert not view.quick_reset_button.isVisible()
    assert "No Files Found" in _label_text(view, "FilesStatusBannerTitle")
    view.close()


def test_files_view_empty_state_with_filters(qapp: QApplication) -> None:
    """set_collection with 0 items and active filters shows quick reset button."""
    view = FilesView()
    view.show()
    view.path_input.setText("/var/log")
    view.apply_filters()

    col = _make_collection(items=(), total=0, limit=50, offset=0)
    view.set_collection(col)

    assert view.state == STATE_EMPTY
    assert view.status_banner.isVisible()
    assert view.quick_reset_button.isVisible()
    assert "No Matching Files" in _label_text(view, "FilesStatusBannerTitle")
    view.close()


def test_files_view_failed_state_empty(qapp: QApplication) -> None:
    """set_error with empty model displays error and enables retry button."""
    view = FilesView()
    view.show()
    view.set_error("Connection refused")

    assert view.state == STATE_FAILED
    assert view.status_banner.isVisible()
    assert view.retry_button.isVisible()
    assert view.retry_button.isEnabled()
    assert "Connection refused" in _label_text(view, "FilesStatusBannerMessage")
    view.close()


def test_files_view_failed_state_retains_records(qapp: QApplication) -> None:
    """set_error with existing rows retains data and clarifies refresh failure."""
    view = FilesView()
    view.show()
    f1 = _make_file(path="/usr/bin/python3")
    col = _make_collection(items=(f1,), total=1)
    view.set_collection(col)

    view.set_error("Timeout occurred")

    assert view.state == STATE_FAILED
    assert view.model.rowCount() == 1
    assert view.status_banner.isVisible()
    assert view.retry_button.isVisible()
    msg = _label_text(view, "FilesStatusBannerMessage")
    assert "retained records" in msg.lower()
    view.close()


def test_files_view_set_not_loaded_resets_view(qapp: QApplication) -> None:
    """set_not_loaded clears records, resets query, and restores initial banner."""
    view = FilesView()
    view.show()
    col = _make_collection(items=(_make_file(),), total=1)
    view.set_collection(col)

    view.set_not_loaded()

    assert view.state == STATE_NOT_LOADED
    assert view.model.rowCount() == 0
    assert view.status_banner.isVisible()
    view.close()


# ==============================================================================
# 3. Table Presentation and Ordering
# ==============================================================================


def test_files_table_presentation_order(qapp: QApplication) -> None:
    """Table preserves backend result order across columns."""
    view = FilesView()
    f1 = _make_file(
        file_id=SAMPLE_FILE_ID_1,
        path="/etc/hosts",
        file_type="file",
        inode=1234,
        first_seen_at=SAMPLE_TIME_1,
        last_seen_at=SAMPLE_TIME_2,
        host_id=SAMPLE_HOST_ID,
    )
    f2 = _make_file(
        file_id=SAMPLE_FILE_ID_2,
        path="/var/log",
        file_type="directory",
        inode=5678,
        first_seen_at=SAMPLE_TIME_2,
        last_seen_at=None,
        host_id=SAMPLE_HOST_ID,
    )
    col = _make_collection(items=(f1, f2), total=2)
    view.set_collection(col)

    m = view.model
    assert m.data(m.index(0, COLUMN_PATH)) == "/etc/hosts"
    assert m.data(m.index(0, COLUMN_FILE_TYPE)) == "file"
    assert m.data(m.index(0, COLUMN_INODE)) == "1234"
    assert m.data(m.index(0, COLUMN_FIRST_SEEN)) == SAMPLE_TIME_1
    assert m.data(m.index(0, COLUMN_LAST_SEEN)) == SAMPLE_TIME_2
    assert m.data(m.index(0, COLUMN_HOST_ID)) == SAMPLE_HOST_ID

    assert m.data(m.index(1, COLUMN_PATH)) == "/var/log"
    assert m.data(m.index(1, COLUMN_FILE_TYPE)) == "directory"
    assert m.data(m.index(1, COLUMN_INODE)) == "5678"
    assert m.data(m.index(1, COLUMN_FIRST_SEEN)) == SAMPLE_TIME_2
    assert m.data(m.index(1, COLUMN_LAST_SEEN)) == "—"
    assert m.data(m.index(1, COLUMN_HOST_ID)) == SAMPLE_HOST_ID


def test_files_view_file_at_accessor(qapp: QApplication) -> None:
    """file_at returns the FileRecord at the specified row."""
    view = FilesView()
    f1 = _make_file(path="/bin/sh")
    view.set_collection(_make_collection(items=(f1,), total=1))

    assert view.file_at(0) == f1
    assert view.file_at(1) is None
    assert view.file_at(-1) is None


# ==============================================================================
# 4. Filter & Query Handling
# ==============================================================================


def test_files_query_validation() -> None:
    """FilesQuery strictly validates attributes upon creation."""
    q = FilesQuery(path="/etc", file_type="file", limit=25, offset=10)
    assert q.path == "/etc"
    assert q.file_type == "file"
    assert q.limit == 25
    assert q.offset == 10
    assert q.page_index == 0

    with pytest.raises(ValueError, match="path"):
        FilesQuery(path="   ")

    with pytest.raises(ValueError, match="file_type"):
        FilesQuery(file_type="invalid_type")

    with pytest.raises(ValueError, match="host_id"):
        FilesQuery(host_id="not-a-uuid")

    with pytest.raises(ValueError, match="limit"):
        FilesQuery(limit=0)

    with pytest.raises(ValueError, match="limit"):
        FilesQuery(limit=101)

    with pytest.raises(ValueError, match="offset"):
        FilesQuery(offset=-1)


def test_files_query_immutability() -> None:
    """FilesQuery is frozen and immutable."""
    q = FilesQuery(path="/tmp")
    with pytest.raises(FrozenInstanceError):
        q.path = "/var"  # type: ignore[misc]


def test_files_query_to_client_kwargs() -> None:
    """to_client_kwargs formats parameters correctly for APIClient."""
    q = FilesQuery(
        path="/etc",
        file_type="directory",
        host_id=SAMPLE_HOST_ID,
        limit=25,
        offset=50,
    )
    kwargs = q.to_client_kwargs()
    assert kwargs["path"] == "/etc"
    assert kwargs["file_type"] == "directory"
    assert kwargs["host_id"] == SAMPLE_HOST_ID
    assert kwargs["limit"] == 25
    assert kwargs["offset"] == 50


def test_files_view_apply_filters_valid(qapp: QApplication) -> None:
    """apply_filters extracts inputs, resets offset to 0, and emits signal."""
    view = FilesView()
    emitted: list[FilesQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    view.path_input.setText("/var/log")
    idx = view.type_filter_combo.findData("directory")
    view.type_filter_combo.setCurrentIndex(idx)
    view.host_id_input.setText(SAMPLE_HOST_ID)

    view.apply_filters()

    assert len(emitted) == 1
    query = emitted[0]
    assert query.path == "/var/log"
    assert query.file_type == "directory"
    assert query.host_id == SAMPLE_HOST_ID
    assert query.offset == 0
    assert view.filter_validation_label.text() == ""


def test_files_view_apply_filters_invalid_host_id(qapp: QApplication) -> None:
    """apply_filters rejects invalid host UUID without emitting signal."""
    view = FilesView()
    emitted: list[FilesQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    view.host_id_input.setText("not-a-valid-uuid")
    view.apply_filters()

    assert len(emitted) == 0
    assert "valid UUID" in view.filter_validation_label.text()


def test_files_view_clear_filters(qapp: QApplication) -> None:
    """clear_filters resets all filter inputs and emits empty query with offset 0."""
    view = FilesView()
    view.path_input.setText("/var")
    view.host_id_input.setText(SAMPLE_HOST_ID)

    emitted: list[FilesQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    view.clear_filters()

    assert view.path_input.text() == ""
    assert view.type_filter_combo.currentIndex() == 0
    assert view.host_id_input.text() == ""
    assert len(emitted) == 1
    assert emitted[0].path is None
    assert emitted[0].offset == 0


def test_files_view_set_query(qapp: QApplication) -> None:
    """set_query synchronizes UI input controls with the query object."""
    view = FilesView()
    query = FilesQuery(
        path="/usr/bin",
        file_type="file",
        host_id=SAMPLE_HOST_ID,
        limit=25,
        offset=0,
    )
    view.set_query(query)

    assert view.path_input.text() == "/usr/bin"
    assert view.type_filter_combo.currentData() == "file"
    assert view.host_id_input.text() == SAMPLE_HOST_ID
    assert view.current_query == query


# ==============================================================================
# 5. Pagination Controls
# ==============================================================================


def test_files_view_pagination_navigation(qapp: QApplication) -> None:
    """go_next_page and go_prev_page update offset and emit query_requested."""
    view = FilesView()
    # 120 total items, limit 50, offset 0 -> next page should be offset 50
    f_list = tuple(_make_file(path=f"/file_{i}") for i in range(50))
    col = _make_collection(items=f_list, total=120, limit=50, offset=0)
    view.set_collection(col)

    assert not view.prev_page_button.isEnabled()
    assert view.next_page_button.isEnabled()

    emitted: list[FilesQuery] = []
    view.query_requested.connect(lambda q: emitted.append(q))

    view.go_next_page()

    assert len(emitted) == 1
    assert emitted[0].offset == 50
    assert emitted[0].limit == 50

    # Simulate arrival of page 2 (offset 50)
    col_p2 = _make_collection(items=f_list, total=120, limit=50, offset=50)
    view.set_collection(col_p2)

    assert view.prev_page_button.isEnabled()
    assert view.next_page_button.isEnabled()

    emitted.clear()
    view.go_prev_page()

    assert len(emitted) == 1
    assert emitted[0].offset == 0


# ==============================================================================
# 6. Signals and Refresh Triggering
# ==============================================================================


def test_files_view_notify_page_activated_emits_load_once(
    qapp: QApplication,
) -> None:
    """notify_page_activated emits load_requested only from STATE_NOT_LOADED."""
    view = FilesView()
    emitted: list[bool] = []
    view.load_requested.connect(lambda: emitted.append(True))

    view.notify_page_activated()
    assert len(emitted) == 1

    # Simulate transition to loading
    view.set_loading()
    view.notify_page_activated()
    assert len(emitted) == 1

    # Simulate transition to loaded
    view.set_collection(_make_collection())
    view.notify_page_activated()
    assert len(emitted) == 1


def test_files_view_refresh_button_emits_signal(qapp: QApplication) -> None:
    """Clicking RefreshFilesButton emits refresh_requested."""
    view = FilesView()
    emitted: list[bool] = []
    view.refresh_requested.connect(lambda: emitted.append(True))

    view.refresh_button.click()
    assert len(emitted) == 1


def test_files_view_retry_button_emits_signal(qapp: QApplication) -> None:
    """Clicking RetryFilesButton emits refresh_requested."""
    view = FilesView()
    view.set_error("Failed to connect")

    emitted: list[bool] = []
    view.refresh_requested.connect(lambda: emitted.append(True))

    view.retry_button.click()
    assert len(emitted) == 1


# ==============================================================================
# 7. AppShell Integration
# ==============================================================================


def test_app_shell_has_files_view(qapp: QApplication) -> None:
    """AppShell mounts FilesView on the 'Files' page."""
    shell = AppShell()
    files_page = shell.get_page_widget("Files")
    assert isinstance(files_page, FilesView)
    assert shell.files_view is files_page
    assert files_page.objectName() == "Page_Files"
    shell.close()


def test_app_shell_files_signals_wired(qapp: QApplication) -> None:
    """AppShell forwards load, refresh, and query signals from FilesView."""
    shell = AppShell()

    load_emitted: list[bool] = []
    refresh_emitted: list[bool] = []
    query_emitted: list[FilesQuery] = []

    shell.files_load_requested.connect(lambda: load_emitted.append(True))
    shell.files_refresh_requested.connect(lambda: refresh_emitted.append(True))
    shell.files_query_requested.connect(lambda q: query_emitted.append(q))

    shell.files_view.load_requested.emit()
    assert len(load_emitted) == 1

    shell.files_view.refresh_requested.emit()
    assert len(refresh_emitted) == 1

    q = FilesQuery(path="/test", limit=50, offset=0)
    shell.files_view.query_requested.emit(q)
    assert len(query_emitted) == 1
    assert query_emitted[0] == q
    shell.close()


def test_app_shell_navigation_round_trip(qapp: QApplication) -> None:
    """Navigating between Files and other pages maintains proper active state."""
    shell = AppShell()

    # Default is Overview
    assert shell.current_page_name == "Overview"

    # Navigate to Files
    shell.navigate_to("Files")
    assert shell.current_page_name == "Files"
    assert shell.current_page_index == 4

    btn = shell.get_nav_button("Files")
    assert btn is not None
    assert btn.isChecked()

    # Navigate to Events
    shell.navigate_to("Events")
    assert shell.current_page_name == "Events"
    assert shell.current_page_index == 1

    # Navigate back to Files
    shell.navigate_to("Files")
    assert shell.current_page_name == "Files"
    shell.close()


# ==============================================================================
# 8. MainWindow Asynchronous Worker Integration
# ==============================================================================


def test_main_window_has_files_view_property(qapp: QApplication) -> None:
    """MainWindow.files_view property returns the shell's FilesView."""
    window = MainWindow()
    assert window.files_view is window.shell.files_view
    assert window.files_view.objectName() == "Page_Files"
    window.close()


def test_main_window_load_files_async_success(qapp: QApplication) -> None:
    """MainWindow.load_files fetches records asynchronously via ApiWorker."""
    client = MagicMock(spec=APIClient)
    f1 = _make_file(path="/var/log/syslog")
    f2 = _make_file(path="/var/log/auth.log")
    col = _make_collection(items=(f1, f2), total=2)
    client.get_files.return_value = col

    window = MainWindow(client=client)
    window.load_files()

    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    assert window.files_view.state == STATE_LOADED
    assert window.files_view.model.rowCount() == 2
    assert not window.is_loading_files
    window.close()


def test_main_window_load_files_with_query_passes_kwargs(
    qapp: QApplication,
) -> None:
    """MainWindow passes normalized query kwargs to APIClient.get_files."""
    client = MagicMock(spec=APIClient)
    client.get_files.return_value = _make_collection()
    window = MainWindow(client=client)

    query = FilesQuery(
        path="/etc",
        file_type="file",
        host_id=SAMPLE_HOST_ID,
        limit=25,
        offset=50,
    )
    window.load_files(query)

    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    client.get_files.assert_called_once_with(
        path="/etc",
        file_type="file",
        host_id=SAMPLE_HOST_ID,
        limit=25,
        offset=50,
    )
    window.close()


def test_main_window_load_files_async_error(qapp: QApplication) -> None:
    """MainWindow.load_files handles exceptions and displays sanitized message."""
    client = MagicMock(spec=APIClient)
    client.get_files.side_effect = ConnectionTimeoutError("Timed out")

    window = MainWindow(client=client)
    window.load_files()

    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    assert window.files_view.state == STATE_FAILED
    msg = _label_text(window.files_view, "FilesStatusBannerMessage")
    assert "timed out" in msg.lower()
    assert not window.is_loading_files
    window.close()


def test_main_window_has_active_workers_tracks_files(
    qapp: QApplication,
) -> None:
    """MainWindow.has_active_workers returns True while files are loading."""
    window = MainWindow()
    assert window.has_active_workers is False
    window._is_loading_files = True
    assert window.has_active_workers is True
    window._is_loading_files = False
    assert window.has_active_workers is False
    window.close()


def test_main_window_stale_response_discarded(qapp: QApplication) -> None:
    """Responses from older sequence requests are discarded when new query runs."""
    client = MagicMock(spec=APIClient)
    window = MainWindow(client=client)

    col1 = _make_collection(items=(_make_file(path="/old"),), total=1)
    col2 = _make_collection(items=(_make_file(path="/new"),), total=1)

    # Dispatched sequence 1
    window._files_request_seq = 1
    # User triggers sequence 2
    window._files_request_seq = 2

    # Sequence 1 finishes late
    window._on_files_result(col1, seq=1)
    assert window.files_view.model.rowCount() == 0

    # Sequence 2 finishes
    window._on_files_result(col2, seq=2)
    assert window.files_view.model.rowCount() == 1
    assert window.files_view.model.data(
        window.files_view.model.index(0, COLUMN_PATH)
    ) == "/new"
    window.close()


def test_main_window_files_error_sanitization() -> None:
    """_sanitize_file_error produces user-friendly messages safely."""
    sanitize = MainWindow._sanitize_file_error
    assert "session expired" in sanitize(AuthenticationError("401")).lower()
    assert "access denied" in sanitize(AuthorizationError("403")).lower()
    assert "timed out" in sanitize(ConnectionTimeoutError("timeout")).lower()
    assert "unable to connect" in sanitize(ClientConnectionError("refused")).lower()
    assert "invalid file data" in sanitize(ValidationError("bad field")).lower()
    assert "unexpected error" in sanitize(RuntimeError("crash")).lower()


def test_main_window_close_deferred_while_loading_files(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    """closeEvent is ignored and deferred if files are actively loading."""
    window = MainWindow()
    window._is_loading_files = True

    event = QCloseEvent()
    window.closeEvent(event)

    assert not event.isAccepted()
    assert window._pending_close is True

    # When worker finishes
    window._is_loading_files = False
    mock_close = MagicMock()
    monkeypatch.setattr(window, "close", mock_close)
    window._on_files_finished(seq=window._files_request_seq)

    mock_close.assert_called_once()


# ==============================================================================
# 9. QSS Styling Verification
# ==============================================================================


def test_files_view_qss_styling(qapp: QApplication) -> None:
    """FilesView controls correctly resolve QSS stylesheets."""
    view = FilesView()
    stylesheet = load_stylesheet()
    view.setStyleSheet(stylesheet)
    assert view.styleSheet() != ""


def test_files_view_query_validation_properties_and_loading_guards(
    qapp: QApplication,
) -> None:
    """FilesView and FilesQuery handle validation, aliases, and loading guards."""
    # 1. FilesQuery validation
    with pytest.raises(ValueError, match="file_type must be a non-empty string"):
        FilesQuery(file_type="")

    with pytest.raises(ValueError, match="file_type must be one of"):
        FilesQuery(file_type="invalid_type")

    with pytest.raises(ValueError, match="host_id must be a UUID"):
        FilesQuery(host_id=True)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="limit must be an integer"):
        FilesQuery(limit=0)

    q = FilesQuery(limit=10, offset=30)
    assert q.page_index == 3
    object.__setattr__(q, "limit", 0)
    assert q.page_index == 0

    view = FilesView()

    # 2. TypeErrors on set_query, set_collection, and set_error
    with pytest.raises(TypeError, match="Expected FilesQuery"):
        view.set_query(123)  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="Expected FileCollection"):
        view.set_collection([123])  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="Expected str message"):
        view.set_error(123)  # type: ignore[arg-type]

    # 3. Properties and aliases
    assert view.page_size == 50
    assert isinstance(view.title_label, QLabel)
    assert isinstance(view.refresh_button, QPushButton)
    assert isinstance(view.retry_button, QPushButton)
    assert isinstance(view.quick_reset_button, QPushButton)
    assert isinstance(view.record_count_label, QLabel)
    assert isinstance(view.status_banner, QFrame)
    assert view.state == "not_loaded"
    assert isinstance(view.filter_bar, QFrame)
    assert isinstance(view.path_input, QLineEdit)
    assert view.file_type_combo is view.type_filter_combo
    assert isinstance(view.host_id_input, QLineEdit)
    assert isinstance(view.apply_filters_button, QPushButton)
    assert view.reset_filters_button is view.clear_filters_button
    assert isinstance(view.filter_validation_label, QLabel)
    assert isinstance(view.pagination_bar, QFrame)
    assert isinstance(view.prev_page_button, QPushButton)
    assert isinstance(view.next_page_button, QPushButton)
    assert isinstance(view.page_range_label, QLabel)

    # 4. Loading guards
    view._state = "loading"
    emitted: list[Any] = []
    view.query_requested.connect(lambda query: emitted.append(query))

    view.apply_filters()
    assert len(emitted) == 0

    view.clear_filters()
    assert len(emitted) == 0

    view.reset_filters()
    assert len(emitted) == 0

    view.go_next_page()
    assert len(emitted) == 0

    view.go_prev_page()
    assert len(emitted) == 0

    # 5. set_loading with retained rows
    file_rec = _make_file(path="/etc/passwd")
    col = _make_collection(items=(file_rec,), total=1)
    view.set_collection(col)
    assert view.model.rowCount() == 1
    assert view.file_at(0) == file_rec

    view.set_loading()
    assert "Retained 1 files" in view.record_count_label.text()

    view.close()

