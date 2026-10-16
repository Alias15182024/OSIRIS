"""OSIRIS Desktop main window."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone

from PySide6.QtCore import QThreadPool, QTimer, Signal
from PySide6.QtGui import QCloseEvent, QShowEvent
from PySide6.QtWidgets import QMainWindow, QWidget
from typing_extensions import override

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
    EventCollection,
    FileCollection,
    HealthStatus,
    ProcessCollection,
    ResourceSnapshotCollection,
    SystemStatus,
    User,
)
from desktop.ui.app_shell import AppShell
from desktop.ui.components.root_warning_banner import RootWarningBanner
from desktop.ui.views.events_view import EventsQuery, EventsView
from desktop.ui.views.files_view import FilesQuery, FilesView
from desktop.ui.views.processes_view import ProcessesQuery, ProcessesView
from desktop.ui.views.resources_view import ResourcesQuery, ResourcesView
from desktop.workers.api_worker import ApiWorker

DEFAULT_LIVE_REFRESH_INTERVAL_MS: int = 5000
DEFAULT_STATUS_POLL_INTERVAL_MS: int = 15000
REFRESHABLE_PAGES: frozenset[str] = frozenset(
    {"Events", "Processes", "Resources", "Files"}
)


def is_root_execution() -> bool:
    """Return True if the current process is running with root privileges (UID 0).

    Gracefully handles platforms without os.geteuid (e.g. Windows).
    """
    if hasattr(os, "geteuid"):
        try:
            return os.geteuid() == 0
        except Exception:
            return False
    return False


@dataclass(frozen=True)
class OperationalStatusResult:
    """Aggregated result of API health and system status checks."""

    health: HealthStatus | None = None
    health_error: str | None = None
    system_status: SystemStatus | None = None
    status_error: str | None = None
    timestamp: datetime | None = None


def fetch_operational_status(client: APIClient) -> OperationalStatusResult:
    """Execute API health and system status checks off the GUI thread.

    Performs health_check() and get_status() sequentially in background worker.
    Catches errors independently so failure of one endpoint does not suppress
    the other.
    """
    health: HealthStatus | None = None
    health_err: str | None = None
    try:
        health = client.health_check()
    except Exception as exc:
        health_err = str(exc)

    system: SystemStatus | None = None
    sys_err: str | None = None
    try:
        system = client.get_status()
    except Exception as exc:
        sys_err = str(exc)

    return OperationalStatusResult(
        health=health,
        health_error=health_err,
        system_status=system,
        status_error=sys_err,
        timestamp=datetime.now(timezone.utc),
    )


class MainWindow(QMainWindow):
    """Top-level application window for the OSIRIS Desktop console."""

    logout_requested = Signal()

    def __init__(
        self,
        client: APIClient | None = None,
        user: User | None = None,
        parent: QWidget | None = None,
        refresh_interval_ms: int = DEFAULT_LIVE_REFRESH_INTERVAL_MS,
        status_poll_interval_ms: int = DEFAULT_STATUS_POLL_INTERVAL_MS,
        is_root: bool | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("OSIRIS Desktop")
        self.setObjectName("MainWindow")

        self._client = client
        self._user = user
        self._is_root: bool = (
            is_root_execution() if is_root is None else bool(is_root)
        )
        self._refresh_interval_ms: int = refresh_interval_ms
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setObjectName("LiveRefreshTimer")
        self._refresh_timer.timeout.connect(self._on_live_refresh_tick)

        self._status_poll_interval_ms: int = status_poll_interval_ms
        self._status_poll_timer = QTimer(self)
        self._status_poll_timer.setObjectName("StatusPollTimer")
        self._status_poll_timer.timeout.connect(self._on_status_poll_tick)
        self._status_request_seq: int = 0

        self._status_worker: ApiWorker | None = None
        self._is_checking_status: bool = False
        self._events_worker: ApiWorker | None = None
        self._is_loading_events: bool = False
        self._events_request_seq: int = 0
        self._processes_worker: ApiWorker | None = None
        self._is_loading_processes: bool = False
        self._processes_request_seq: int = 0
        self._resources_worker: ApiWorker | None = None
        self._is_loading_resources: bool = False
        self._resources_request_seq: int = 0
        self._files_worker: ApiWorker | None = None
        self._is_loading_files: bool = False
        self._files_request_seq: int = 0
        self._pending_close: bool = False
        self._initial_check_scheduled: bool = False
        self._consecutive_status_failures: int = 0
        self._is_logged_out: bool = False

        # Proportions: 1440x900 default desktop size, 1024x640 minimum bound
        self.resize(1440, 900)
        self.setMinimumSize(1024, 640)

        # Coordinate the primary application visual shell
        self._shell = AppShell(
            user=self._user, parent=self, is_root=self._is_root
        )
        self._shell.logout_requested.connect(self._handle_logout)
        self._shell.status_check_requested.connect(self.check_operational_status)
        self._shell.error_banner_retry_requested.connect(
            self._on_retry_requested
        )
        self._shell.page_changed.connect(self._on_page_changed)
        self._shell.events_load_requested.connect(self.load_events)
        self._shell.events_refresh_requested.connect(self.load_events)
        self._shell.events_view.query_requested.connect(self.load_events)
        self._shell.processes_load_requested.connect(self.load_processes)
        self._shell.processes_refresh_requested.connect(self.load_processes)
        self._shell.processes_query_requested.connect(self.load_processes)
        self._shell.resources_load_requested.connect(self.load_resources)
        self._shell.resources_refresh_requested.connect(self.load_resources)
        self._shell.resources_query_requested.connect(self.load_resources)
        self._shell.files_load_requested.connect(self.load_files)
        self._shell.files_refresh_requested.connect(self.load_files)
        self._shell.files_query_requested.connect(self.load_files)
        self.setCentralWidget(self._shell)

    @property
    def client(self) -> APIClient | None:
        """Return the injected REST API client instance."""
        return self._client

    @property
    def user(self) -> User | None:
        """Return the authenticated user profile."""
        return self._user

    @property
    def is_root(self) -> bool:
        """Return True if running in root-execution security posture."""
        return self._is_root

    @property
    def root_warning_banner(self) -> RootWarningBanner:
        """Return the persistent root execution security warning banner."""
        return self._shell.root_warning_banner

    @property
    def shell(self) -> AppShell:
        """Return the core visual application shell."""
        return self._shell

    @property
    def events_view(self) -> EventsView:
        """Return the integrated EventsView instance."""
        return self._shell.events_view

    @property
    def processes_view(self) -> ProcessesView:
        """Return the integrated ProcessesView instance."""
        return self._shell.processes_view

    @property
    def resources_view(self) -> ResourcesView:
        """Return the integrated ResourcesView instance."""
        return self._shell.resources_view

    @property
    def files_view(self) -> FilesView:
        """Return the integrated FilesView instance."""
        return self._shell.files_view

    @property
    def is_checking_status(self) -> bool:
        """Return whether an operational status check is currently in flight."""
        return self._is_checking_status

    @property
    def is_loading_events(self) -> bool:
        """Return whether an events load operation is currently in flight."""
        return self._is_loading_events

    @property
    def is_loading_processes(self) -> bool:
        """Return whether a processes load operation is currently in flight."""
        return self._is_loading_processes

    @property
    def is_loading_resources(self) -> bool:
        """Return whether a resources load operation is currently in flight."""
        return self._is_loading_resources

    @property
    def is_loading_files(self) -> bool:
        """Return whether a files load operation is currently in flight."""
        return self._is_loading_files

    @property
    def has_active_workers(self) -> bool:
        """Return True if any background worker is currently active."""
        return (
            self._is_checking_status
            or self._is_loading_events
            or self._is_loading_processes
            or self._is_loading_resources
            or self._is_loading_files
        )

    @property
    def refresh_interval_ms(self) -> int:
        """Return the live monitoring refresh interval in milliseconds."""
        return self._refresh_interval_ms

    @refresh_interval_ms.setter
    def refresh_interval_ms(self, interval_ms: int) -> None:
        """Set the live monitoring refresh interval in milliseconds."""
        if interval_ms <= 0:
            raise ValueError("Refresh interval must be a positive integer.")
        self._refresh_interval_ms = interval_ms
        if self._refresh_timer.isActive():
            self._refresh_timer.start(self._refresh_interval_ms)

    @property
    def refresh_timer(self) -> QTimer:
        """Return the underlying live refresh QTimer instance."""
        return self._refresh_timer

    @property
    def is_live_refresh_active(self) -> bool:
        """Return True if the live monitoring timer is currently running."""
        return self._refresh_timer.isActive()

    @property
    def status_poll_interval_ms(self) -> int:
        """Return the status polling interval in milliseconds."""
        return self._status_poll_interval_ms

    @status_poll_interval_ms.setter
    def status_poll_interval_ms(self, interval_ms: int) -> None:
        """Set the status polling interval in milliseconds."""
        if interval_ms <= 0:
            raise ValueError("Status poll interval must be a positive integer.")
        self._status_poll_interval_ms = interval_ms
        if self._status_poll_timer.isActive():
            self._status_poll_timer.start(self._status_poll_interval_ms)

    @property
    def status_poll_timer(self) -> QTimer:
        """Return the underlying status polling QTimer instance."""
        return self._status_poll_timer

    @property
    def is_status_polling_active(self) -> bool:
        """Return True if the status polling timer is currently active."""
        return self._status_poll_timer.isActive()

    def start_status_polling(self, restart: bool = False) -> None:
        """Start or restart the periodic background status polling timer."""
        if self._client is None or self._pending_close:
            self.stop_status_polling()
            return
        if not self._status_poll_timer.isActive() or restart:
            self._status_poll_timer.start(self._status_poll_interval_ms)

    def stop_status_polling(self) -> None:
        """Stop the periodic background status polling timer."""
        if self._status_poll_timer.isActive():
            self._status_poll_timer.stop()

    def _on_status_poll_tick(self) -> None:
        """Handle periodic timeout by requesting operational status."""
        if self._pending_close or self._client is None:
            self.stop_status_polling()
            return
        if self._is_checking_status:
            return
        self.check_operational_status()

    def _on_retry_requested(self) -> None:
        """Handle manual retry requested from global error banner."""
        if self._pending_close or self._client is None:
            return
        self.check_operational_status()
        current_page = self._shell.current_page_name
        if current_page == "Events":
            self.load_events()
        elif current_page == "Processes":
            self.load_processes()
        elif current_page == "Resources":
            self.load_resources()
        elif current_page == "Files":
            self.load_files()

    def set_session(
        self,
        client: APIClient | None,
        user: User | None = None,
    ) -> None:
        """Update authenticated API client and user profile, syncing timers."""
        self._client = client
        self._user = user
        self._shell.set_user(user)
        if self._client is not None and not self._pending_close:
            self.start_status_polling(restart=True)
            self.check_operational_status()
        else:
            self.stop_status_polling()
        self.update_refresh_schedule()

    def start_live_refresh(self, restart: bool = False) -> None:
        """Start or restart the periodic live refresh timer."""
        if self._client is None or self._pending_close:
            self.stop_live_refresh()
            return

        current_page = self._shell.current_page_name
        if current_page not in REFRESHABLE_PAGES:
            self.stop_live_refresh()
            return

        if not self._refresh_timer.isActive() or restart:
            self._refresh_timer.start(self._refresh_interval_ms)

    def stop_live_refresh(self) -> None:
        """Stop the periodic live refresh timer."""
        if self._refresh_timer.isActive():
            self._refresh_timer.stop()

    def update_refresh_schedule(self) -> None:
        """Synchronize live refresh timer state with current page and session."""
        if self._client is not None and not self._pending_close:
            current_page = self._shell.current_page_name
            if current_page in REFRESHABLE_PAGES:
                self.start_live_refresh()
                return
        self.stop_live_refresh()

    def _on_page_changed(self, page_id: str) -> None:
        """Handle page change notification from shell."""
        if page_id in REFRESHABLE_PAGES and self._client is not None:
            self.start_live_refresh(restart=True)
        else:
            self.stop_live_refresh()

    def _is_loading_for_page(self, page_name: str) -> bool:
        """Return True if an async request is currently in flight for page."""
        if page_name == "Events":
            return self._is_loading_events
        if page_name == "Processes":
            return self._is_loading_processes
        if page_name == "Resources":
            return self._is_loading_resources
        if page_name == "Files":
            return self._is_loading_files
        return False

    def _on_live_refresh_tick(self) -> None:
        """Handle periodic timeout by refreshing the active data view."""
        if self._pending_close or self._client is None:
            self.stop_live_refresh()
            return

        current_page = self._shell.current_page_name
        if current_page not in REFRESHABLE_PAGES:
            self.stop_live_refresh()
            return

        if self._is_loading_for_page(current_page):
            return

        if current_page == "Events":
            self._shell.events_view.refresh()
        elif current_page == "Processes":
            self._shell.processes_view.refresh()
        elif current_page == "Resources":
            self._shell.resources_view.refresh()
        elif current_page == "Files":
            self._shell.files_view.refresh()

    @override
    def showEvent(self, event: QShowEvent) -> None:
        """Schedule initial status check and sync refresh upon presentation."""
        super().showEvent(event)
        if not self._initial_check_scheduled and self._client is not None:
            self._initial_check_scheduled = True
            QTimer.singleShot(0, self.check_operational_status)
        if self._client is not None and not self._pending_close:
            self.start_status_polling()
        self.update_refresh_schedule()

    def check_operational_status(self) -> None:
        """Trigger an asynchronous check of API health and system status.

        Runs outside the GUI thread via ApiWorker and QThreadPool.
        Guards against concurrent/duplicate requests and stale responses.
        """
        if self._is_checking_status or self._pending_close:
            return
        if self._client is None:
            self._shell.apply_operational_status(
                health=None,
                health_error="No API client configured",
                system=None,
                system_error="No API client configured",
            )
            return

        self._is_checking_status = True
        self._shell.set_status_checking()

        self._status_request_seq += 1
        seq = self._status_request_seq

        worker = ApiWorker(fetch_operational_status, self._client)
        self._status_worker = worker
        worker.signals.result.connect(
            lambda res, s=seq: self._on_status_result(res, s)
        )
        worker.signals.error.connect(
            lambda exc, s=seq: self._on_status_error(exc, s)
        )
        worker.signals.finished.connect(
            lambda s=seq: self._on_status_finished(s)
        )

        QThreadPool.globalInstance().start(worker)

    def _on_status_result(
        self, result: OperationalStatusResult, seq: int
    ) -> None:
        """Apply received operational status to the visual shell."""
        if (
            self._pending_close
            or self._is_logged_out
            or seq != self._status_request_seq
        ):
            return
        self._shell.apply_operational_status(
            health=result.health,
            health_error=result.health_error,
            system=result.system_status,
            system_error=result.status_error,
            timestamp=result.timestamp,
        )

        # 1. API reachability check (/health)
        if result.health is None or result.health_error:
            self._consecutive_status_failures += 1
            backoff_ms = min(
                30000,
                2000 * (2 ** min(self._consecutive_status_failures - 1, 4)),
            )
            if self._status_poll_timer.isActive():
                self._status_poll_timer.setInterval(backoff_ms)
            err = result.health_error or "Service health check failed"
            self._shell.show_connection_error(
                f"API connection unreachable: {err}"
            )
        else:
            self._consecutive_status_failures = 0
            if self._status_poll_timer.isActive():
                self._status_poll_timer.setInterval(
                    self._status_poll_interval_ms
                )

            # 2. Operational degradation check (/api/status)
            is_degraded = False
            degraded_reasons: list[str] = []
            if result.system_status is not None:
                if result.system_status.status == "degraded":
                    is_degraded = True
                    degraded_reasons.append("System status: degraded")
                if result.system_status.database != "connected":
                    is_degraded = True
                    degraded_reasons.append(
                        f"Database: {result.system_status.database}"
                    )
            elif result.status_error:
                is_degraded = True
                degraded_reasons.append(result.status_error)

            if is_degraded:
                reason_text = "; ".join(degraded_reasons)
                self._shell.show_degraded_warning(
                    f"Backend degraded: {reason_text}"
                )
            else:
                self._shell.clear_global_warning()

    def _on_status_error(self, exc: Exception, seq: int) -> None:
        """Handle unexpected background worker error."""
        if self._pending_close or seq != self._status_request_seq:
            return
        err_msg = str(exc)
        self._shell.apply_operational_status(
            health=None,
            health_error=err_msg,
            system=None,
            system_error=err_msg,
            timestamp=datetime.now(timezone.utc),
        )
        self._consecutive_status_failures += 1
        backoff_ms = min(
            30000,
            2000 * (2 ** min(self._consecutive_status_failures - 1, 4)),
        )
        if self._status_poll_timer.isActive():
            self._status_poll_timer.setInterval(backoff_ms)
        self._shell.show_connection_error(f"API connection error: {err_msg}")

    def _on_status_finished(self, seq: int) -> None:
        """Reset checking state and finalize pending window close if queued."""
        if seq == self._status_request_seq or self._is_logged_out:
            self._is_checking_status = False
            self._status_worker = None
            self._shell.set_status_check_enabled(True)

        if self._pending_close and not self.has_active_workers:
            self.close()

    def load_events(self, query: EventsQuery | None = None) -> None:
        """Trigger an asynchronous fetch of security events via ApiWorker.

        Runs outside the GUI thread. Guards against duplicate in-flight requests,
        passes normalized query parameters, and tracks request sequence IDs.
        """
        if self._is_loading_events:
            return
        if self._client is None:
            self._shell.events_view.set_error("No API client configured")
            return

        if isinstance(query, EventsQuery):
            self._shell.events_view.set_query(query)
            active_query = query
        else:
            active_query = self._shell.events_view.current_query
        self._is_loading_events = True
        self._shell.events_view.set_loading()
        if self._refresh_timer.isActive():
            self._refresh_timer.start(self._refresh_interval_ms)

        self._events_request_seq += 1
        seq = self._events_request_seq

        kwargs = active_query.to_client_kwargs()
        worker = ApiWorker(self._client.get_events, **kwargs)
        self._events_worker = worker
        worker.signals.result.connect(
            lambda col, s=seq: self._on_events_result(col, s)
        )
        worker.signals.error.connect(
            lambda exc, s=seq: self._on_events_error(exc, s)
        )
        worker.signals.finished.connect(
            lambda s=seq: self._on_events_finished(s)
        )

        QThreadPool.globalInstance().start(worker)

    def _on_events_result(self, collection: EventCollection, seq: int) -> None:
        """Update the Events view with the received EventCollection."""
        if (
            self._pending_close
            or self._is_logged_out
            or seq != self._events_request_seq
        ):
            return
        self._shell.events_view.set_collection(collection)

    def _on_events_error(self, exc: Exception, seq: int) -> None:
        """Handle error from events background worker with a sanitized message."""
        if self._pending_close or seq != self._events_request_seq:
            return
        sanitized_msg = self._sanitize_event_error(exc)
        self._shell.events_view.set_error(sanitized_msg)
        if isinstance(exc, (ClientConnectionError, ConnectionTimeoutError)):
            self._shell.show_connection_error(
                "API connection failure. Operating with retained data."
            )
        elif isinstance(exc, AuthenticationError):
            self.stop_live_refresh()

    def _on_events_finished(self, seq: int) -> None:
        """Reset events loading state and finalize pending close if requested."""
        if seq == self._events_request_seq or self._is_logged_out:
            self._is_loading_events = False
            self._events_worker = None

        if self._pending_close and not self.has_active_workers:
            self.close()

    @staticmethod
    def _sanitize_event_error(exc: Exception) -> str:
        """Format an exception into a safe, informative user-facing message."""
        if isinstance(exc, AuthenticationError):
            return "Authentication session expired or invalid. Please log in again."
        if isinstance(exc, AuthorizationError):
            return "Access denied: you do not have permission to view security events."
        if isinstance(exc, ConnectionTimeoutError):
            return (
                "Connection timed out while requesting security events. "
                "Please try again."
            )
        if isinstance(exc, ClientConnectionError):
            return (
                "Unable to connect to the OSIRIS API server. "
                "Check network connection."
            )
        if isinstance(exc, NotFoundError):
            return f"Resource not found (HTTP 404): {exc.message}"
        if isinstance(exc, ServerError):
            status = f" (HTTP {exc.status_code})" if exc.status_code else ""
            return f"Internal server error{status}: {exc.message}"
        if isinstance(exc, HTTPResponseError):
            status = f" (HTTP {exc.status_code})" if exc.status_code else ""
            return f"API request failed{status}: {exc.message}"
        if isinstance(exc, ValidationError):
            return f"Invalid event data received: {exc.message}"
        if isinstance(exc, OSIRISClientError):
            return str(exc.message)
        return f"An unexpected error occurred: {type(exc).__name__}"

    def load_processes(self, query: ProcessesQuery | None = None) -> None:
        """Trigger an asynchronous fetch of processes via ApiWorker.

        Runs outside the GUI thread. Guards against duplicate in-flight requests,
        passes normalized query parameters, and tracks request sequence IDs.
        """
        if self._is_loading_processes:
            return
        if self._client is None:
            self._shell.processes_view.set_error("No API client configured")
            return

        if isinstance(query, ProcessesQuery):
            self._shell.processes_view.set_query(query)
            active_query = query
        else:
            active_query = self._shell.processes_view.current_query
        self._is_loading_processes = True
        self._shell.processes_view.set_loading()
        if self._refresh_timer.isActive():
            self._refresh_timer.start(self._refresh_interval_ms)

        self._processes_request_seq += 1
        seq = self._processes_request_seq

        kwargs = active_query.to_client_kwargs()
        worker = ApiWorker(self._client.get_processes, **kwargs)
        self._processes_worker = worker
        worker.signals.result.connect(
            lambda col, s=seq: self._on_processes_result(col, s)
        )
        worker.signals.error.connect(
            lambda exc, s=seq: self._on_processes_error(exc, s)
        )
        worker.signals.finished.connect(
            lambda s=seq: self._on_processes_finished(s)
        )

        QThreadPool.globalInstance().start(worker)

    def _on_processes_result(
        self, collection: ProcessCollection, seq: int
    ) -> None:
        """Update the Processes view with the received ProcessCollection."""
        if (
            self._pending_close
            or self._is_logged_out
            or seq != self._processes_request_seq
        ):
            return
        self._shell.processes_view.set_collection(collection)

    def _on_processes_error(self, exc: Exception, seq: int) -> None:
        """Handle error from processes worker with a sanitized message."""
        if self._pending_close or seq != self._processes_request_seq:
            return
        sanitized_msg = self._sanitize_process_error(exc)
        self._shell.processes_view.set_error(sanitized_msg)
        if isinstance(exc, (ClientConnectionError, ConnectionTimeoutError)):
            self._shell.show_connection_error(
                "API connection failure. Operating with retained data."
            )
        elif isinstance(exc, AuthenticationError):
            self.stop_live_refresh()

    def _on_processes_finished(self, seq: int) -> None:
        """Reset processes loading state and finalize close if requested."""
        if seq == self._processes_request_seq or self._is_logged_out:
            self._is_loading_processes = False
            self._processes_worker = None

        if self._pending_close and not self.has_active_workers:
            self.close()

    @staticmethod
    def _sanitize_process_error(exc: Exception) -> str:
        """Format an exception into a safe, informative user-facing message."""
        if isinstance(exc, AuthenticationError):
            return "Authentication session expired or invalid. Please log in again."
        if isinstance(exc, AuthorizationError):
            return "Access denied: you do not have permission to view processes."
        if isinstance(exc, ConnectionTimeoutError):
            return (
                "Connection timed out while requesting processes. "
                "Please try again."
            )
        if isinstance(exc, ClientConnectionError):
            return (
                "Unable to connect to the OSIRIS API server. "
                "Check network connection."
            )
        if isinstance(exc, NotFoundError):
            return f"Resource not found (HTTP 404): {exc.message}"
        if isinstance(exc, ServerError):
            status = f" (HTTP {exc.status_code})" if exc.status_code else ""
            return f"Internal server error{status}: {exc.message}"
        if isinstance(exc, HTTPResponseError):
            status = f" (HTTP {exc.status_code})" if exc.status_code else ""
            return f"API request failed{status}: {exc.message}"
        if isinstance(exc, ValidationError):
            return f"Invalid process data received: {exc.message}"
        if isinstance(exc, OSIRISClientError):
            return str(exc.message)
        return f"An unexpected error occurred: {type(exc).__name__}"

    def load_resources(self, query: ResourcesQuery | None = None) -> None:
        """Trigger an asynchronous fetch of resource snapshots via ApiWorker.

        Runs outside the GUI thread. Guards against duplicate in-flight requests,
        passes normalized query parameters, and tracks request sequence IDs.
        """
        if self._is_loading_resources:
            return
        if self._client is None:
            self._shell.resources_view.set_error("No API client configured")
            return

        if isinstance(query, ResourcesQuery):
            self._shell.resources_view.set_query(query)
            active_query = query
        else:
            active_query = self._shell.resources_view.current_query
        self._is_loading_resources = True
        self._shell.resources_view.set_loading()
        if self._refresh_timer.isActive():
            self._refresh_timer.start(self._refresh_interval_ms)

        self._resources_request_seq += 1
        seq = self._resources_request_seq

        kwargs = active_query.to_client_kwargs()
        worker = ApiWorker(self._client.get_resources, **kwargs)
        self._resources_worker = worker
        worker.signals.result.connect(
            lambda col, s=seq: self._on_resources_result(col, s)
        )
        worker.signals.error.connect(
            lambda exc, s=seq: self._on_resources_error(exc, s)
        )
        worker.signals.finished.connect(
            lambda s=seq: self._on_resources_finished(s)
        )

        QThreadPool.globalInstance().start(worker)

    def _on_resources_result(
        self, collection: ResourceSnapshotCollection, seq: int
    ) -> None:
        """Update Resources view with received ResourceSnapshotCollection."""
        if (
            self._pending_close
            or self._is_logged_out
            or seq != self._resources_request_seq
        ):
            return
        self._shell.resources_view.set_collection(collection)

    def _on_resources_error(self, exc: Exception, seq: int) -> None:
        """Handle error from resources worker with a sanitized message."""
        if self._pending_close or seq != self._resources_request_seq:
            return
        sanitized_msg = self._sanitize_resource_error(exc)
        self._shell.resources_view.set_error(sanitized_msg)
        if isinstance(exc, (ClientConnectionError, ConnectionTimeoutError)):
            self._shell.show_connection_error(
                "API connection failure. Operating with retained data."
            )
        elif isinstance(exc, AuthenticationError):
            self.stop_live_refresh()

    def _on_resources_finished(self, seq: int) -> None:
        """Reset resources loading state and finalize close if requested."""
        if seq == self._resources_request_seq or self._is_logged_out:
            self._is_loading_resources = False
            self._resources_worker = None

        if self._pending_close and not self.has_active_workers:
            self.close()

    @staticmethod
    def _sanitize_resource_error(exc: Exception) -> str:
        """Format an exception into a safe, informative user-facing message."""
        if isinstance(exc, AuthenticationError):
            return (
                "Authentication session expired or invalid. Please log in "
                "again."
            )
        if isinstance(exc, AuthorizationError):
            return (
                "Access denied: you do not have permission to view resource "
                "telemetry."
            )
        if isinstance(exc, ConnectionTimeoutError):
            return (
                "Connection timed out while requesting resource telemetry. "
                "Please try again."
            )
        if isinstance(exc, ClientConnectionError):
            return (
                "Unable to connect to the OSIRIS API server. "
                "Check network connection."
            )
        if isinstance(exc, NotFoundError):
            return f"Resource not found (HTTP 404): {exc.message}"
        if isinstance(exc, ServerError):
            status = f" (HTTP {exc.status_code})" if exc.status_code else ""
            return f"Internal server error{status}: {exc.message}"
        if isinstance(exc, HTTPResponseError):
            status = f" (HTTP {exc.status_code})" if exc.status_code else ""
            return f"API request failed{status}: {exc.message}"
        if isinstance(exc, ValidationError):
            return f"Invalid resource data received: {exc.message}"
        if isinstance(exc, OSIRISClientError):
            return str(exc.message)
        return f"An unexpected error occurred: {type(exc).__name__}"

    def load_files(self, query: FilesQuery | None = None) -> None:
        """Trigger an asynchronous fetch of observed files via ApiWorker.

        Runs outside the GUI thread. Guards against duplicate in-flight requests,
        passes normalized query parameters, and tracks request sequence IDs.
        """
        if self._is_loading_files:
            return
        if self._client is None:
            self._shell.files_view.set_error("No API client configured")
            return

        if isinstance(query, FilesQuery):
            self._shell.files_view.set_query(query)
            active_query = query
        else:
            active_query = self._shell.files_view.current_query
        self._is_loading_files = True
        self._shell.files_view.set_loading()
        if self._refresh_timer.isActive():
            self._refresh_timer.start(self._refresh_interval_ms)

        self._files_request_seq += 1
        seq = self._files_request_seq

        kwargs = active_query.to_client_kwargs()
        worker = ApiWorker(self._client.get_files, **kwargs)
        self._files_worker = worker
        worker.signals.result.connect(
            lambda col, s=seq: self._on_files_result(col, s)
        )
        worker.signals.error.connect(
            lambda exc, s=seq: self._on_files_error(exc, s)
        )
        worker.signals.finished.connect(
            lambda s=seq: self._on_files_finished(s)
        )

        QThreadPool.globalInstance().start(worker)

    def _on_files_result(
        self, collection: FileCollection, seq: int
    ) -> None:
        """Update Files view with received FileCollection."""
        if (
            self._pending_close
            or self._is_logged_out
            or seq != self._files_request_seq
        ):
            return
        self._shell.files_view.set_collection(collection)

    def _on_files_error(self, exc: Exception, seq: int) -> None:
        """Handle error from files worker with a sanitized message."""
        if self._pending_close or seq != self._files_request_seq:
            return
        sanitized_msg = self._sanitize_file_error(exc)
        self._shell.files_view.set_error(sanitized_msg)
        if isinstance(exc, (ClientConnectionError, ConnectionTimeoutError)):
            self._shell.show_connection_error(
                "API connection failure. Operating with retained data."
            )
        elif isinstance(exc, AuthenticationError):
            self.stop_live_refresh()

    def _on_files_finished(self, seq: int) -> None:
        """Reset files loading state and finalize close if requested."""
        if seq == self._files_request_seq or self._is_logged_out:
            self._is_loading_files = False
            self._files_worker = None

        if self._pending_close and not self.has_active_workers:
            self.close()

    @staticmethod
    def _sanitize_file_error(exc: Exception) -> str:
        """Format an exception into a safe, informative user-facing message."""
        if isinstance(exc, AuthenticationError):
            return (
                "Authentication session expired or invalid. Please log in "
                "again."
            )
        if isinstance(exc, AuthorizationError):
            return (
                "Access denied: you do not have permission to view observed "
                "files."
            )
        if isinstance(exc, ConnectionTimeoutError):
            return (
                "Connection timed out while requesting observed files. "
                "Please try again."
            )
        if isinstance(exc, ClientConnectionError):
            return (
                "Unable to connect to the OSIRIS API server. "
                "Check network connection."
            )
        if isinstance(exc, NotFoundError):
            return f"Resource not found (HTTP 404): {exc.message}"
        if isinstance(exc, ServerError):
            status = f" (HTTP {exc.status_code})" if exc.status_code else ""
            return f"Internal server error{status}: {exc.message}"
        if isinstance(exc, HTTPResponseError):
            status = f" (HTTP {exc.status_code})" if exc.status_code else ""
            return f"API request failed{status}: {exc.message}"
        if isinstance(exc, ValidationError):
            return f"Invalid file data received: {exc.message}"
        if isinstance(exc, OSIRISClientError):
            return str(exc.message)
        return f"An unexpected error occurred: {type(exc).__name__}"

    def _handle_logout(self) -> None:
        """Handle logout by clearing client session and closing the window."""
        self.stop_live_refresh()
        self.stop_status_polling()
        # Invalidate in-flight request sequences to drop pending responses
        self._events_request_seq += 1
        self._processes_request_seq += 1
        self._resources_request_seq += 1
        self._files_request_seq += 1
        self._status_request_seq += 1
        self._is_logged_out = True
        if self._client is not None:
            self._client.logout()
        self._client = None
        self._user = None
        self._shell.set_user(None)
        self.logout_requested.emit()
        if self.has_active_workers:
            self._pending_close = True
            self.hide()
        else:
            self.close()

    @override
    def closeEvent(self, event: QCloseEvent) -> None:
        """Handle window close event, deferring if any worker is in flight."""
        self.stop_live_refresh()
        self.stop_status_polling()
        if self.has_active_workers:
            self._pending_close = True
            self.hide()
            event.ignore()
        else:
            event.accept()
