"""Tests for the OSIRIS Desktop main window foundation."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from PySide6.QtCore import QThreadPool
from PySide6.QtWidgets import QApplication, QLabel, QPushButton, QWidget

from desktop.client.api_client import APIClient
from desktop.client.exceptions import (
    AuthenticationError,
    HTTPResponseError,
    NotFoundError,
    OSIRISClientError,
    ServerError,
    ValidationError,
)
from desktop.client.models import (
    Event,
    EventCollection,
    FileCollection,
    ProcessCollection,
    ResourceSnapshotCollection,
    User,
)
from desktop.ui.app_shell import AppShell
from desktop.ui.main_window import MainWindow
from desktop.ui.views.events_view import EventsQuery
from desktop.ui.views.files_view import FilesQuery
from desktop.ui.views.processes_view import ProcessesQuery
from desktop.ui.views.resources_view import ResourcesQuery


def _sample_user() -> User:
    """Return a representative authenticated User instance for tests."""
    return User(
        id="usr-789",
        username="lead_analyst",
        display_name="Lead Analyst",
        role="admin",
        is_active=True,
        created_at="2026-01-01T00:00:00Z",
    )


def test_main_window_instantiation(qapp: QApplication) -> None:
    """MainWindow can be created without errors."""
    window = MainWindow()
    assert window is not None
    assert window.client is None
    assert window.user is None


def test_main_window_title(qapp: QApplication) -> None:
    """Window title is exactly 'OSIRIS Desktop'."""
    window = MainWindow()
    assert window.windowTitle() == "OSIRIS Desktop"


def test_main_window_object_name(qapp: QApplication) -> None:
    """Object name is exactly 'MainWindow'."""
    window = MainWindow()
    assert window.objectName() == "MainWindow"


def test_main_window_has_central_widget(qapp: QApplication) -> None:
    """A central widget exists and is an AppShell."""
    window = MainWindow()
    central = window.centralWidget()
    assert central is not None
    assert isinstance(central, QWidget)
    assert isinstance(central, AppShell)


def test_main_window_central_widget_is_app_shell(qapp: QApplication) -> None:
    """Central widget is an AppShell with the expected object name."""
    window = MainWindow()
    central = window.centralWidget()
    assert isinstance(central, AppShell)
    assert central.objectName() == "AppShell"


def test_main_window_shell_property(qapp: QApplication) -> None:
    """MainWindow.shell property returns the AppShell instance."""
    window = MainWindow()
    assert window.shell is window.centralWidget()
    assert isinstance(window.shell, AppShell)


def test_main_window_default_size(qapp: QApplication) -> None:
    """MainWindow defaults to 1440x900 with a 1024x640 minimum."""
    window = MainWindow()
    assert window.width() == 1440
    assert window.height() == 900
    assert window.minimumWidth() == 1024
    assert window.minimumHeight() == 640


def test_main_window_receives_injected_session(qapp: QApplication) -> None:
    """MainWindow receives APIClient and User without replacing them."""
    client = MagicMock(spec=APIClient)
    user = _sample_user()

    window = MainWindow(client=client, user=user)

    assert window.client is client
    assert window.user is user
    assert window.shell.user is user


def test_main_window_does_not_display_access_token(qapp: QApplication) -> None:
    """MainWindow and AppShell never display access token in UI elements."""
    secret_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.super-secret-token"
    client = MagicMock(spec=APIClient)
    client._token = secret_token
    user = _sample_user()

    window = MainWindow(client=client, user=user)
    window.show()

    # Verify no labels display the access token in text or tooltip
    labels = window.findChildren(QLabel)
    for lbl in labels:
        assert secret_token not in lbl.text()
        assert secret_token not in lbl.toolTip()

    buttons = window.findChildren(QPushButton)
    for btn in buttons:
        assert secret_token not in btn.text()
        assert secret_token not in btn.toolTip()

    window.close()


def test_main_window_logout_handling(qapp: QApplication) -> None:
    """Clicking Logout clears authentication, emits signal, and closes window."""
    client = MagicMock(spec=APIClient)
    user = _sample_user()

    window = MainWindow(client=client, user=user)
    window.show()
    assert window.isVisible() is True

    emitted: list[bool] = []
    window.logout_requested.connect(lambda: emitted.append(True))

    # Activate logout through the visual shell button
    window.shell.logout_button.click()

    client.logout.assert_called_once()
    assert emitted == [True]
    assert window.isVisible() is False


def test_main_window_status_check_without_client(qapp: QApplication) -> None:
    """MainWindow handles check_operational_status without client safely."""
    window = MainWindow(client=None)
    window.check_operational_status()

    assert window.is_checking_status is False
    assert "Unavailable" in window.shell.status_api_label.text()
    assert "Unavailable" in window.shell.status_system_label.text()
    assert "Unavailable" in window.shell.status_database_label.text()


def test_main_window_shell_status_check_signal_wired(qapp: QApplication) -> None:
    """Shell status_check_requested signal triggers MainWindow check."""
    client = MagicMock(spec=APIClient)
    client.health_check.return_value = MagicMock(status="ok", system="osiris")
    client.get_status.return_value = MagicMock(
        status="healthy", system="osiris", database="connected", host_id="test-host"
    )

    window = MainWindow(client=client)
    assert window.is_checking_status is False

    # Trigger via shell button
    window.shell.check_status_button.click()
    assert window.is_checking_status is True
    # Let event loop and thread pool finish
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()


def test_main_window_load_events_with_query_passes_kwargs(
    qapp: QApplication,
) -> None:
    """MainWindow passes normalized query parameters to APIClient.get_events."""
    client = MagicMock(spec=APIClient)
    client.get_events.return_value = EventCollection(
        total=0, items=(), limit=25, offset=50
    )
    window = MainWindow(client=client)
    query = EventsQuery(severity="high", limit=25, offset=50)

    window.load_events(query)
    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    client.get_events.assert_called_once_with(
        limit=25,
        offset=50,
        severity="high",
    )


def test_main_window_events_sequence_guard_ignores_stale_result(
    qapp: QApplication,
) -> None:
    """Outdated worker results from older request sequences are ignored."""
    client = MagicMock(spec=APIClient)
    window = MainWindow(client=client)
    initial_collection = EventCollection(
        total=0, items=(), limit=50, offset=0
    )
    window.shell.events_view.set_collection(initial_collection)

    # Advance sequence to 2
    window._events_request_seq = 2

    # Receive result tagged with seq=1 (stale)
    mock_event = MagicMock(spec=Event)
    stale_collection = EventCollection(
        total=1, items=(mock_event,), limit=50, offset=0
    )
    window._on_events_result(stale_collection, seq=1)

    assert window.shell.events_view.model.rowCount() == 0


def test_main_window_events_sequence_guard_ignores_stale_error(
    qapp: QApplication,
) -> None:
    """Outdated worker errors from older request sequences are ignored."""
    client = MagicMock(spec=APIClient)
    window = MainWindow(client=client)
    initial_collection = EventCollection(
        total=0, items=(), limit=50, offset=0
    )
    window.shell.events_view.set_collection(initial_collection)
    assert window.shell.events_view.state == "empty"

    # Advance sequence to 2
    window._events_request_seq = 2

    # Receive error tagged with seq=1 (stale)
    window._on_events_error(RuntimeError("Stale failure"), seq=1)

    assert window.shell.events_view.state == "empty"


def test_main_window_events_view_query_requested_signal_wired(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Emitting query_requested on EventsView invokes MainWindow.load_events."""
    client = MagicMock(spec=APIClient)
    window = MainWindow(client=client)
    mock_load = MagicMock()
    monkeypatch.setattr(window, "load_events", mock_load)

    query = EventsQuery(severity="critical", limit=50, offset=0)
    window.shell.events_view.query_requested.emit(query)

    mock_load.assert_called_once_with(query)


def test_main_window_load_events_forwards_time_filters(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MainWindow.load_events passes start_time and end_time to APIClient.get_events."""
    client = MagicMock(spec=APIClient)
    window = MainWindow(client=client)

    captured_kwargs: dict[str, Any] = {}

    def mock_worker_init(fn: Any, **kwargs: Any) -> MagicMock:
        captured_kwargs.update(kwargs)
        worker = MagicMock()
        worker.signals.result.connect = MagicMock()
        worker.signals.error.connect = MagicMock()
        worker.signals.finished.connect = MagicMock()
        return worker

    monkeypatch.setattr("desktop.ui.main_window.ApiWorker", mock_worker_init)
    mock_start = MagicMock()
    monkeypatch.setattr(QThreadPool.globalInstance(), "start", mock_start)

    query = EventsQuery(
        start_time="2026-03-01T10:00:00Z",
        end_time="2026-03-01T18:00:00Z",
        limit=50,
        offset=0,
    )
    window.load_events(query)

    assert captured_kwargs["start_time"] == "2026-03-01T10:00:00Z"
    assert captured_kwargs["end_time"] == "2026-03-01T18:00:00Z"
    assert captured_kwargs["limit"] == 50
    assert captured_kwargs["offset"] == 0
    mock_start.assert_called_once()
    window.close()


def test_main_window_load_processes_with_query_passes_kwargs(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MainWindow passes normalized query kwargs to APIClient.get_processes."""
    client = MagicMock(spec=APIClient)
    client.get_processes.return_value = ProcessCollection(
        total=0, items=(), limit=25, offset=50
    )
    window = MainWindow(client=client)

    captured_kwargs: dict[str, Any] = {}

    def mock_worker_init(fn: Any, **kwargs: Any) -> MagicMock:
        captured_kwargs.update(kwargs)
        worker = MagicMock()
        worker.signals.result.connect = MagicMock()
        worker.signals.error.connect = MagicMock()
        worker.signals.finished.connect = MagicMock()
        return worker

    monkeypatch.setattr("desktop.ui.main_window.ApiWorker", mock_worker_init)
    mock_start = MagicMock()
    monkeypatch.setattr(QThreadPool.globalInstance(), "start", mock_start)

    query = ProcessesQuery(
        is_active=False,
        pid=0,
        host_id="33333333-3333-4333-8333-333333333333",
        limit=25,
        offset=50,
    )
    window.load_processes(query)

    assert captured_kwargs["is_active"] is False
    assert captured_kwargs["pid"] == 0
    assert captured_kwargs["host_id"] == "33333333-3333-4333-8333-333333333333"
    assert captured_kwargs["limit"] == 25
    assert captured_kwargs["offset"] == 50
    mock_start.assert_called_once()
    window.close()


def test_main_window_processes_view_query_requested_signal_wired(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Emitting query_requested on ProcessesView invokes MainWindow.load_processes."""
    client = MagicMock(spec=APIClient)
    window = MainWindow(client=client)
    mock_load = MagicMock()
    monkeypatch.setattr(window, "load_processes", mock_load)

    query = ProcessesQuery(is_active=True, pid=42, limit=50, offset=0)
    window.shell.processes_view.query_requested.emit(query)

    mock_load.assert_called_once_with(query)
    window.close()


def test_main_window_app_shell_processes_query_requested_wired(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AppShell.processes_query_requested invokes MainWindow.load_processes."""
    client = MagicMock(spec=APIClient)
    window = MainWindow(client=client)
    mock_load = MagicMock()
    monkeypatch.setattr(window, "load_processes", mock_load)

    query = ProcessesQuery(is_active=False, pid=999, limit=25, offset=0)
    window.shell.processes_query_requested.emit(query)

    mock_load.assert_called_once_with(query)
    window.close()


def test_main_window_has_resources_view_property(qapp: QApplication) -> None:
    """MainWindow.resources_view property returns the shell's ResourcesView."""
    window = MainWindow()
    assert window.resources_view is window.shell.resources_view
    assert window.resources_view.objectName() == "Page_Resources"
    window.close()


def test_main_window_load_resources_with_query_passes_kwargs(
    qapp: QApplication,
) -> None:
    """MainWindow passes normalized query kwargs to APIClient.get_resources."""
    client = MagicMock(spec=APIClient)
    client.get_resources.return_value = ResourceSnapshotCollection(
        total=0, items=(), limit=15, offset=0
    )
    window = MainWindow(client=client)
    query = ResourcesQuery(limit=15, offset=0)

    window.load_resources(query)

    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    client.get_resources.assert_called_once_with(limit=15, offset=0)
    window.close()


def test_main_window_resources_view_query_requested_signal_wired(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Emitting query_requested on ResourcesView invokes load_resources."""
    client = MagicMock(spec=APIClient)
    window = MainWindow(client=client)
    mock_load = MagicMock()
    monkeypatch.setattr(window, "load_resources", mock_load)

    query = ResourcesQuery(limit=25, offset=5)
    window.shell.resources_view.query_requested.emit(query)

    mock_load.assert_called_once_with(query)
    window.close()


def test_main_window_app_shell_resources_query_requested_wired(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AppShell.resources_query_requested invokes MainWindow.load_resources."""
    client = MagicMock(spec=APIClient)
    window = MainWindow(client=client)
    mock_load = MagicMock()
    monkeypatch.setattr(window, "load_resources", mock_load)

    query = ResourcesQuery(limit=20, offset=10)
    window.shell.resources_query_requested.emit(query)

    mock_load.assert_called_once_with(query)
    window.close()


def test_main_window_has_active_workers_tracks_resources_loading(
    qapp: QApplication,
) -> None:
    """MainWindow.has_active_workers returns True while loading resources."""
    window = MainWindow()
    assert window.has_active_workers is False
    window._is_loading_resources = True
    assert window.has_active_workers is True
    window._is_loading_resources = False
    assert window.has_active_workers is False
    window.close()


def test_main_window_has_files_view_property(qapp: QApplication) -> None:
    """MainWindow.files_view property returns the shell's FilesView."""
    window = MainWindow()
    assert window.files_view is window.shell.files_view
    assert window.files_view.objectName() == "Page_Files"
    window.close()


def test_main_window_load_files_with_query_passes_kwargs(
    qapp: QApplication,
) -> None:
    """MainWindow passes normalized query kwargs to APIClient.get_files."""
    client = MagicMock(spec=APIClient)
    client.get_files.return_value = FileCollection(
        total=0, items=(), limit=15, offset=0
    )
    window = MainWindow(client=client)
    query = FilesQuery(path="/etc", limit=15, offset=0)

    window.load_files(query)

    QThreadPool.globalInstance().waitForDone(3000)
    qapp.processEvents()

    client.get_files.assert_called_once_with(
        path="/etc", limit=15, offset=0
    )
    window.close()


def test_main_window_files_view_query_requested_signal_wired(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Emitting query_requested on FilesView invokes load_files."""
    client = MagicMock(spec=APIClient)
    window = MainWindow(client=client)
    mock_load = MagicMock()
    monkeypatch.setattr(window, "load_files", mock_load)

    query = FilesQuery(path="/var", limit=25, offset=5)
    window.shell.files_view.query_requested.emit(query)

    mock_load.assert_called_once_with(query)
    window.close()


def test_main_window_app_shell_files_query_requested_wired(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AppShell.files_query_requested invokes MainWindow.load_files."""
    client = MagicMock(spec=APIClient)
    window = MainWindow(client=client)
    mock_load = MagicMock()
    monkeypatch.setattr(window, "load_files", mock_load)

    query = FilesQuery(file_type="file", limit=20, offset=10)
    window.shell.files_query_requested.emit(query)

    mock_load.assert_called_once_with(query)
    window.close()


def test_main_window_has_active_workers_tracks_files_loading(
    qapp: QApplication,
) -> None:
    """MainWindow.has_active_workers returns True while loading files."""
    window = MainWindow()
    assert window.has_active_workers is False
    window._is_loading_files = True
    assert window.has_active_workers is True
    window._is_loading_files = False
    assert window.has_active_workers is False
    window.close()


def test_main_window_retry_requested_across_views(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MainWindow._on_retry_requested dispatches to view loaders."""
    client = MagicMock(spec=APIClient)
    window = MainWindow(client=client)

    mock_proc = MagicMock()
    mock_res = MagicMock()
    mock_files = MagicMock()
    mock_status = MagicMock()
    monkeypatch.setattr(window, "load_processes", mock_proc)
    monkeypatch.setattr(window, "load_resources", mock_res)
    monkeypatch.setattr(window, "load_files", mock_files)
    monkeypatch.setattr(window, "check_operational_status", mock_status)

    window.shell.navigate_to("processes")
    mock_proc.reset_mock()
    window._on_retry_requested()
    mock_proc.assert_called_once()
    assert mock_status.call_count >= 1

    window.shell.navigate_to("resources")
    mock_res.reset_mock()
    window._on_retry_requested()
    mock_res.assert_called_once()

    window.shell.navigate_to("files")
    mock_files.reset_mock()
    window._on_retry_requested()
    mock_files.assert_called_once()

    # When client is None, retry returns early
    window._client = None
    window._on_retry_requested()

    window.close()
    QThreadPool.globalInstance().waitForDone(1000)


def test_main_window_timer_and_refresh_edge_cases(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MainWindow timers and refresh guards handle boundary conditions."""
    client = MagicMock(spec=APIClient)
    window = MainWindow(client=client)
    mock_status = MagicMock()
    monkeypatch.setattr(window, "check_operational_status", mock_status)

    # Active status poll timer restarts with new interval
    window._status_poll_timer.start(5000)
    window.status_poll_interval_ms = 10000
    assert window._status_poll_interval_ms == 10000
    assert window._status_poll_timer.isActive()

    # Start polling when client is None stops timer
    window._client = None
    window.start_status_polling()
    assert not window._status_poll_timer.isActive()

    # Tick when pending close or client is None stops timer
    window._client = None
    window._on_status_poll_tick()

    # Tick when checking status skips check
    window._client = client
    window._is_checking_status = True
    window._on_status_poll_tick()
    window._is_checking_status = False

    # Start live refresh when pending close stops timer
    window._pending_close = True
    window.start_live_refresh()
    assert not window.is_live_refresh_active
    window._pending_close = False

    # Live refresh tick when pending close
    window._pending_close = True
    window._on_live_refresh_tick()
    window._pending_close = False

    # Live refresh tick when page not refreshable
    window.shell.navigate_to("overview")
    window._on_live_refresh_tick()
    assert not window.is_live_refresh_active

    # Loading check for unknown page
    assert window._is_loading_for_page("NonExistent") is False

    # Status error backoff with active timer
    window._status_poll_timer.start(5000)
    window._on_status_error(
        Exception("network drop"), window._status_request_seq
    )
    assert window._consecutive_status_failures >= 1

    window.close()
    QThreadPool.globalInstance().waitForDone(1000)


def test_main_window_error_formatting_branches(qapp: QApplication) -> None:
    """_sanitize_event_error and _sanitize_file_error format all error types."""
    # _sanitize_event_error branches
    assert "502" in MainWindow._sanitize_event_error(
        HTTPResponseError("bad gateway", status_code=502)
    )
    assert "raw error" in MainWindow._sanitize_event_error(
        OSIRISClientError("raw error")
    )
    assert "unexpected" in MainWindow._sanitize_event_error(ValueError("crash"))

    # _sanitize_file_error branches
    assert "502" in MainWindow._sanitize_file_error(
        HTTPResponseError("bad gateway", status_code=502)
    )
    assert "raw error" in MainWindow._sanitize_file_error(
        OSIRISClientError("raw error")
    )
    assert "unexpected" in MainWindow._sanitize_file_error(ValueError("crash"))
    assert "404" in MainWindow._sanitize_file_error(
        NotFoundError("missing", status_code=404)
    )
    assert "500" in MainWindow._sanitize_file_error(
        ServerError("oops", status_code=500)
    )
    assert "Invalid file data" in MainWindow._sanitize_file_error(
        ValidationError("bad schema")
    )


def test_main_window_files_loading_guards(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    """load_files guards against concurrent requests and missing client."""
    window = MainWindow(client=None)

    # Missing client
    window.load_files()
    assert window.shell.files_view.state == "failed"

    # Concurrent request guard
    client = MagicMock(spec=APIClient)
    mock_status = MagicMock()
    monkeypatch.setattr(window, "check_operational_status", mock_status)
    window.set_session(client, _sample_user())
    window._is_loading_files = True
    window.load_files()  # Returns early without spawning worker

    # On files error with AuthenticationError stops live refresh
    window.start_live_refresh()
    window._on_files_error(
        AuthenticationError("expired", status_code=401),
        window._files_request_seq,
    )
    assert not window.is_live_refresh_active

    # On files error with stale sequence ignored
    window._on_files_error(Exception("stale"), window._files_request_seq - 999)

    window.close()
    QThreadPool.globalInstance().waitForDone(1000)


def test_main_window_status_result_and_worker_edge_cases(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MainWindow handles operational status edge branches and stale seqs."""
    from desktop.client.models import HealthStatus
    from desktop.ui.main_window import OperationalStatusResult

    client = MagicMock(spec=APIClient)
    window = MainWindow(client=client)
    window.show()

    # 1. _on_status_poll_tick triggers check_operational_status
    mock_check = MagicMock()
    monkeypatch.setattr(window, "check_operational_status", mock_check)
    window._is_checking_status = False
    window._pending_close = False
    window._on_status_poll_tick()
    mock_check.assert_called_once()

    # 2. _on_status_result with status_error triggers degraded banner
    seq = window._status_request_seq
    res_degraded = OperationalStatusResult(
        health=HealthStatus(status="ok", system="ok"),
        system_status=None,
        status_error="Database slow or unreachable",
    )
    window._on_status_result(res_degraded, seq)
    assert window.shell.error_banner.isVisible() is True

    # 3. _on_status_result with stale seq returns early
    window.shell.clear_global_warning()
    window._on_status_result(res_degraded, seq - 999)
    assert window.shell.error_banner.isVisible() is False

    # 4. _on_status_error with stale seq or pending close returns early
    mock_apply = MagicMock()
    monkeypatch.setattr(window.shell, "apply_operational_status", mock_apply)

    window._on_status_error(Exception("stale"), seq - 999)
    mock_apply.assert_not_called()

    window._pending_close = True
    window._on_status_error(Exception("closing"), seq)
    mock_apply.assert_not_called()
    window._pending_close = False

    # 5. _on_status_finished edge cases
    window._is_checking_status = True
    window._is_logged_out = False
    window._on_status_finished(seq - 999)
    assert window._is_checking_status is True  # Stale seq did not reset

    mock_close = MagicMock()
    monkeypatch.setattr(window, "close", mock_close)
    monkeypatch.setattr(MainWindow, "has_active_workers", property(lambda self: False))
    window._pending_close = True
    window._on_status_finished(seq)
    mock_close.assert_called_once()

    window.close()
    QThreadPool.globalInstance().waitForDone(1000)


