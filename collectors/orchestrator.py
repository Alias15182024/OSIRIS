"""Collector Orchestration Layer for OSIRIS.

Coordinates the lifecycle, scheduling, error containment, and data routing for
all active Phase 1 collectors:
- ``ProcessCollector`` (source: "proc")
- ``ResourceCollector`` (source: "resource")
- ``FilesystemCollector`` (source: "fs")

Pipes all collected ``RawObservation`` instances into ``EventProcessor.process_batch()``
for authoritative validation, UTC timestamp normalization, UUID assignment, and enrichment.
Optionally persists normalized events to an externally configured ``EventRepository``
or passes them to an event callback.
"""

from __future__ import annotations

import enum
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from backend.services.events.processor import BatchResult, EventProcessor
from backend.services.events.repository import EventRepository
from backend.services.events.schemas import NormalizedEvent, RawObservation
from collectors.filesystem.collector import FilesystemCollector
from collectors.filesystem.inotify import InotifyBackend
from collectors.process.collector import ProcessCollector
from collectors.resource.collector import ResourceCollector

logger = logging.getLogger("osiris.collectors.orchestrator")


class OrchestratorError(Exception):
    """Base exception for orchestrator errors."""


class CollectorStartupError(OrchestratorError):
    """Raised when collector startup or watch registration fails."""


class OrchestratorState(enum.Enum):
    """Lifecycle states of the collector orchestrator."""

    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"


@dataclass
class OrchestratorConfig:
    """Configuration for the Collector Orchestrator.

    Parameters
    ----------
    host_id:
        UUID or string identifying the monitored host.
    process_interval:
        Interval in seconds between process collector polling runs. Default: 2.0s.
    resource_interval:
        Interval in seconds between resource collector polling runs. Default: 5.0s.
    tick_interval:
        Interval in seconds for the background worker loop sleep/wake cycle. Default: 0.5s.
    filesystem_paths:
        List of directory or file paths to register for inotify monitoring.
    filesystem_recursive:
        Whether to recursively watch subdirectories. Default: True.
    resource_granular:
        Whether resource collector also emits granular cpu/memory/disk events. Default: False.
    proc_dir:
        Path to proc filesystem. Injected for unit testing. Default: "/proc".
    fs_backend:
        Optional custom inotify backend (e.g. MockInotifyBackend for testing).
    statvfs_fn:
        Optional custom statvfs callable for testing.
    monotonic_clock:
        Injectable monotonic clock function for interval calculations. Default: time.monotonic.
    wall_clock:
        Injectable wall clock function for cycle timestamps. Default: UTC datetime.now.
    """

    host_id: uuid.UUID | str
    process_interval: float = 2.0
    resource_interval: float = 5.0
    tick_interval: float = 0.5
    filesystem_paths: list[Path | str] = field(default_factory=list)
    filesystem_recursive: bool = True
    resource_granular: bool = False
    proc_dir: Path | str = "/proc"
    fs_backend: InotifyBackend | None = None
    statvfs_fn: Callable[[str], Any] | None = None
    monotonic_clock: Callable[[], float] = time.monotonic
    wall_clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)


@dataclass
class CycleResult:
    """Outcome of a single orchestration cycle."""

    timestamp: datetime
    observations_count: int
    events: list[NormalizedEvent]
    collector_errors: dict[str, str] = field(default_factory=dict)
    processing_errors: list[tuple[int, list[str]]] = field(default_factory=list)
    sink_errors: dict[str, str] = field(default_factory=dict)
    duration_ms: float = 0.0

    @property
    def success(self) -> bool:
        """True if all collectors, processors, and sinks succeeded without errors."""
        return (
            not self.collector_errors
            and not self.processing_errors
            and not self.sink_errors
        )


class CollectorOrchestrator:
    """Orchestrator coordinating all Phase 1 collectors and piping observations into EventProcessor.

    Parameters
    ----------
    config:
        Orchestration configuration object.
    process_collector:
        Optional injected ProcessCollector instance.
    resource_collector:
        Optional injected ResourceCollector instance.
    filesystem_collector:
        Optional injected FilesystemCollector instance.
    event_processor:
        Optional injected EventProcessor instance.
    event_repository:
        Optional injected EventRepository instance for persistence.
    event_callback:
        Optional callback invoked with normalized events.
    """

    def __init__(
        self,
        config: OrchestratorConfig,
        *,
        process_collector: ProcessCollector | None = None,
        resource_collector: ResourceCollector | None = None,
        filesystem_collector: FilesystemCollector | None = None,
        event_processor: EventProcessor | None = None,
        event_repository: EventRepository | None = None,
        event_callback: Callable[[list[NormalizedEvent]], None] | None = None,
    ) -> None:
        self.config = config
        self.host_uuid = (
            config.host_id
            if isinstance(config.host_id, uuid.UUID)
            else uuid.UUID(str(config.host_id))
        )

        # Injectable clocks
        self._monotonic_clock = config.monotonic_clock
        self._wall_clock = config.wall_clock

        # Concurrency & Lifecycle
        self._state = OrchestratorState.STOPPED
        self._state_lock = threading.Lock()
        self._cycle_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._worker_thread: threading.Thread | None = None

        # Timing tracking for interval scheduling
        self._last_process_time: float | None = None
        self._last_resource_time: float | None = None

        # Telemetry & Status
        self._cycle_count: int = 0
        self._total_observations: int = 0
        self._total_events: int = 0
        self._last_cycle_timestamp: datetime | None = None
        self._collector_status: dict[str, dict[str, Any]] = {
            "proc": {"healthy": True, "last_error": None, "observations": 0},
            "resource": {"healthy": True, "last_error": None, "observations": 0},
            "fs": {"healthy": True, "last_error": None, "observations": 0},
        }

        # Event Processing & Output
        self.processor = event_processor or EventProcessor()
        self.repository = event_repository
        self.callback = event_callback

        # Collectors
        self.process_collector = process_collector or ProcessCollector(
            self.host_uuid, proc_dir=config.proc_dir
        )
        self.resource_collector = resource_collector or ResourceCollector(
            self.host_uuid,
            proc_dir=config.proc_dir,
            statvfs_fn=config.statvfs_fn,
        )
        self.filesystem_collector = filesystem_collector or FilesystemCollector(
            self.host_uuid,
            watch_paths=None,
            recursive=config.filesystem_recursive,
            backend=config.fs_backend,
        )

    @property
    def state(self) -> OrchestratorState:
        """Current lifecycle state."""
        with self._state_lock:
            return self._state

    def is_running(self) -> bool:
        """True if the orchestrator is in the RUNNING state."""
        with self._state_lock:
            return self._state == OrchestratorState.RUNNING

    def _cleanup_collectors(self, collectors: list[Any] | None = None) -> None:
        """Idempotently clean up collectors without throwing secondary exceptions."""
        targets = collectors if collectors is not None else [
            self.filesystem_collector,
            self.process_collector,
            self.resource_collector,
        ]
        for col in targets:
            try:
                if hasattr(col, "stop"):
                    col.stop()
            except Exception as exc:
                logger.warning("Error stopping %s during cleanup: %s", col, exc)
            try:
                if hasattr(col, "close"):
                    col.close()
            except Exception as exc:
                logger.warning("Error closing %s during cleanup: %s", col, exc)

    def start(self, background: bool = True) -> None:
        """Start the orchestrator.

        Executes the explicit 4-step startup sequence:
        1. Verify/construct collectors.
        2. Register configured filesystem watch paths.
        3. Start collectors.
        4. Transition to RUNNING state and optionally launch background worker thread.

        If watch registration or collector startup fails, rolls back cleanly
        without leaking descriptors.
        """
        with self._state_lock:
            if self._state != OrchestratorState.STOPPED:
                raise OrchestratorError(
                    f"Cannot start orchestrator from state '{self._state.value}'"
                )
            self._state = OrchestratorState.STARTING

        started_collectors: list[Any] = []
        try:
            # Step 2: Register configured filesystem watches
            for path in self.config.filesystem_paths:
                p = Path(path)
                success = self.filesystem_collector.add_watch(p)
                if not success:
                    raise CollectorStartupError(
                        f"Failed to register filesystem watch for path: {p}"
                    )

            # Step 3: Start collectors
            for col in (
                self.filesystem_collector,
                self.process_collector,
                self.resource_collector,
            ):
                col.start()
                started_collectors.append(col)

            # Step 4: Enter RUNNING state
            with self._state_lock:
                self._state = OrchestratorState.RUNNING

            # Step 5: Start background worker if requested
            if background:
                self._stop_event.clear()
                self._worker_thread = threading.Thread(
                    target=self._run_loop,
                    name="osiris-collector-orchestrator",
                    daemon=True,
                )
                self._worker_thread.start()

        except Exception as exc:
            # Startup rollback: clean up all initialized/started collectors
            self._cleanup_collectors()
            with self._state_lock:
                self._state = OrchestratorState.STOPPED
            if isinstance(exc, OrchestratorError):
                raise
            raise CollectorStartupError(
                f"Collector orchestrator startup failed: {exc}"
            ) from exc

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the orchestrator gracefully and clean up all resources."""
        with self._state_lock:
            if self._state not in (
                OrchestratorState.RUNNING,
                OrchestratorState.STARTING,
            ):
                return
            self._state = OrchestratorState.STOPPING

        # 1. Signal background worker to wake and stop
        self._stop_event.set()

        # 2. Join worker thread
        if self._worker_thread is not None and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=timeout)
            if self._worker_thread.is_alive():
                logger.warning(
                    "Collector orchestrator worker thread did not terminate within %s seconds",
                    timeout,
                )

        # 3. Clean up collectors
        self._cleanup_collectors()

        with self._state_lock:
            self._state = OrchestratorState.STOPPED

    def _run_loop(self) -> None:
        """Background continuous worker loop."""
        logger.info("Collector orchestrator background loop started.")
        while not self._stop_event.is_set():
            try:
                self.run_cycle(force_all=False)
            except Exception as exc:
                logger.error(
                    "Unexpected error in collector orchestration loop: %s",
                    exc,
                    exc_info=True,
                )

            # Wait for tick interval or immediate wakeup on stop event
            if self._stop_event.wait(timeout=self.config.tick_interval):
                break

        logger.info("Collector orchestrator background loop exited.")

    def run_cycle(self, force_all: bool = False) -> CycleResult:
        """Execute a single synchronous collection and normalization cycle.

        Parameters
        ----------
        force_all:
            If True, runs process and resource collection immediately, bypassing
            interval gating. Filesystem collection always runs on every cycle.

        Returns
        -------
        CycleResult
            Summary of collected observations, normalized events, and errors.
        """
        with self._cycle_lock:
            now_mono = self._monotonic_clock()
            now_wall = self._wall_clock()
            t_start = now_mono

            raw_observations: list[RawObservation] = []
            collector_errors: dict[str, str] = {}
            sink_errors: dict[str, str] = {}

            # 1. Filesystem Collector: drains inotify queue on every cycle
            try:
                fs_obs = self.filesystem_collector.collect_observations()
                raw_observations.extend(fs_obs)
                self._collector_status["fs"]["healthy"] = True
                self._collector_status["fs"]["observations"] += len(fs_obs)
            except Exception as exc:
                msg = f"FilesystemCollector error: {exc}"
                logger.error(msg, exc_info=True)
                collector_errors["fs"] = msg
                self._collector_status["fs"]["healthy"] = False
                self._collector_status["fs"]["last_error"] = msg

            # 2. Process Collector: interval-gated or forced
            proc_due = force_all or (
                self._last_process_time is None
                or (now_mono - self._last_process_time) >= self.config.process_interval
            )
            if proc_due:
                try:
                    proc_obs = self.process_collector.collect_observations()
                    raw_observations.extend(proc_obs)
                    self._last_process_time = now_mono
                    self._collector_status["proc"]["healthy"] = True
                    self._collector_status["proc"]["observations"] += len(proc_obs)
                except Exception as exc:
                    msg = f"ProcessCollector error: {exc}"
                    logger.error(msg, exc_info=True)
                    collector_errors["proc"] = msg
                    self._collector_status["proc"]["healthy"] = False
                    self._collector_status["proc"]["last_error"] = msg

            # 3. Resource Collector: interval-gated or forced
            res_due = force_all or (
                self._last_resource_time is None
                or (now_mono - self._last_resource_time) >= self.config.resource_interval
            )
            if res_due:
                try:
                    res_obs = self.resource_collector.collect_observations(
                        granular=self.config.resource_granular
                    )
                    raw_observations.extend(res_obs)
                    self._last_resource_time = now_mono
                    self._collector_status["resource"]["healthy"] = True
                    self._collector_status["resource"]["observations"] += len(res_obs)
                except Exception as exc:
                    msg = f"ResourceCollector error: {exc}"
                    logger.error(msg, exc_info=True)
                    collector_errors["resource"] = msg
                    self._collector_status["resource"]["healthy"] = False
                    self._collector_status["resource"]["last_error"] = msg

            # 4. Authoritative Event Normalization
            batch_result = self.processor.process_batch(raw_observations)
            normalized_events = batch_result.events

            # 5. Optional Persistence & Callback Dispatch
            if normalized_events:
                if self.repository is not None:
                    try:
                        self.repository.save_batch(normalized_events)
                    except Exception as exc:
                        msg = f"EventRepository save_batch error: {exc}"
                        logger.error(msg, exc_info=True)
                        sink_errors["repository"] = msg

                if self.callback is not None:
                    try:
                        self.callback(normalized_events)
                    except Exception as exc:
                        msg = f"Event callback error: {exc}"
                        logger.error(msg, exc_info=True)
                        sink_errors["callback"] = msg

            # 6. Telemetry and Result
            duration_ms = round((self._monotonic_clock() - t_start) * 1000.0, 3)
            self._cycle_count += 1
            self._total_observations += len(raw_observations)
            self._total_events += len(normalized_events)
            self._last_cycle_timestamp = now_wall

            return CycleResult(
                timestamp=now_wall,
                observations_count=len(raw_observations),
                events=normalized_events,
                collector_errors=collector_errors,
                processing_errors=batch_result.errors,
                sink_errors=sink_errors,
                duration_ms=duration_ms,
            )

    def get_status(self) -> dict[str, Any]:
        """Return diagnostic health and status metrics for the orchestrator."""
        with self._state_lock:
            state_str = self._state.value

        return {
            "state": state_str,
            "host_id": str(self.host_uuid),
            "cycle_count": self._cycle_count,
            "total_observations": self._total_observations,
            "total_events": self._total_events,
            "last_cycle_timestamp": (
                self._last_cycle_timestamp.isoformat()
                if self._last_cycle_timestamp
                else None
            ),
            "collectors": {k: dict(v) for k, v in self._collector_status.items()},
        }

    def __enter__(self) -> CollectorOrchestrator:
        """Context manager entry starts the orchestrator."""
        self.start(background=True)
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit guarantees complete teardown."""
        self.stop()
