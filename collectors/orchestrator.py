"""Collector Orchestration Layer for OSIRIS.

Coordinates the lifecycle, scheduling, error containment, and data routing for
all active Phase 1 collectors:
- ``ProcessCollector`` (source: "proc")
- ``ResourceCollector`` (source: "resource")
- ``FilesystemCollector`` (source: "fs")

Pipes all collected ``RawObservation`` instances into ``EventProcessor.process_batch()``
for authoritative validation, UTC timestamp normalization, UUID assignment, and enrichment.
Persists normalized events to an ``EventRepository`` within atomic transaction boundaries,
or passes them to an event callback.

Session & Transaction Ownership Models:
----------------------------------------
1. Orchestrator-Owned Session Lifecycle (via `session_factory`):
   When `session_factory` is provided (or configured in `OrchestratorConfig`), the orchestrator
   owns the database session lifecycle. For each collection cycle, a fresh, cycle-scoped session
   is created. All operations (Linux user sync, process lifecycle, event normalization with identity
   resolution, and event persistence) execute within an atomic transaction. On cycle success,
   the unit of work is committed. On any error, changes are rolled back and identity resolution
   caches are invalidated. In all execution paths, the cycle-scoped session is guaranteed to be closed.

2. Externally-Owned Session:
   When an active `Session` or an `EventRepository` with an existing session is passed, the caller owns
   the session. The orchestrator never silently commits the top-level transaction or closes the session.
   Cycle atomicity is isolated using savepoints (`session.begin_nested()`), ensuring that failed cycles
   roll back partial entity and event changes without aborting or closing the caller's outer transaction.
   Note on `session.begin_nested()` pre-flush behavior:
   In SQLAlchemy, creating a savepoint via `session.begin_nested()` performs a flush of all currently
   pending changes in the Session (if autoflush is enabled). Any caller-added entities already pending
   in the session will be flushed to the database in the outer transaction before the inner savepoint
   is established. If an inner cycle subsequently fails, only the savepoint (`savepoint.rollback()`)
   is rolled back, preserving the caller's unflushed/pre-flushed work and outer transaction.

3. In-Memory / No-Database Mode:
   When neither a session factory nor a database session is configured, the orchestrator operates
   in pure in-memory mode without database queries, using `NoOpIdentityResolver`.

Collector Error Isolation vs. Transaction Atomicity Policy:
------------------------------------------------------------
Collector health failure alone does not force rollback of valid database writes.
If one collector fails but other collectors produce valid observations:
- Continue with healthy observations where safe.
- Persist valid normalized observations if required database operations succeed.
- Report collector errors in CycleResult.collector_errors and degraded cycle status (success=False).
- Do not dispatch events that failed to persist.
- Do not count failed or uncommitted events as persisted events.

Database integrity failures, user synchronization failures, process lifecycle persistence failures,
event repository failures, and unexpected fatal processing exceptions must still cause appropriate
transaction rollback.

On rollback or failed commit, restore collector internal state (such as ProcessCollector._known_processes)
and clear identity resolution caches to prevent state inconsistency with persisted database records.
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

from sqlalchemy.orm import Session

from backend.services.events.process_lifecycle import ProcessLifecycleService
from backend.services.events.processor import BatchResult, EventProcessor
from backend.services.events.repository import EventRepository
from backend.services.events.resolver import (
    DatabaseIdentityResolver,
    IdentityResolver,
    NoOpIdentityResolver,
    resolve_host_uuid,
)
from backend.services.events.schemas import NormalizedEvent, RawObservation
from backend.services.events.user_sync import LinuxUserSynchronizer
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
    passwd_file:
        Path to `/etc/passwd` file for user synchronization. Default: "/etc/passwd".
    user_provider:
        Optional callable returning `list[tuple[int, str]]` for isolated user sync tests.
    fs_backend:
        Optional custom inotify backend (e.g. MockInotifyBackend for testing).
    statvfs_fn:
        Optional custom statvfs callable for testing.
    monotonic_clock:
        Injectable monotonic clock function for interval calculations. Default: time.monotonic.
    wall_clock:
        Injectable wall clock function for cycle timestamps. Default: UTC datetime.now.
    session_factory:
        Optional factory returning a new SQLAlchemy Session. When provided,
        the orchestrator owns the session lifecycle, creating a cycle-scoped
        session for each collection cycle, committing on success, rolling back
        on failure, and closing the session in all execution paths.
    """

    host_id: uuid.UUID | str
    process_interval: float = 2.0
    resource_interval: float = 5.0
    tick_interval: float = 0.5
    filesystem_paths: list[Path | str] = field(default_factory=list)
    filesystem_recursive: bool = True
    resource_granular: bool = False
    proc_dir: Path | str = "/proc"
    passwd_file: Path | str | None = "/etc/passwd"
    user_provider: Callable[[], list[tuple[int, str]]] | None = None
    fs_backend: InotifyBackend | None = None
    statvfs_fn: Callable[[str], Any] | None = None
    monotonic_clock: Callable[[], float] = time.monotonic
    wall_clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)
    session_factory: Callable[[], Session] | None = None


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
    identity_resolver:
        Optional injected IdentityResolver instance.
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
        identity_resolver: IdentityResolver | None = None,
        user_synchronizer: LinuxUserSynchronizer | None = None,
        process_lifecycle_service: ProcessLifecycleService | None = None,
        event_callback: Callable[[list[NormalizedEvent]], None] | None = None,
        session_factory: Callable[[], Session] | None = None,
        session: Session | None = None,
    ) -> None:
        self.config = config
        self.host_uuid = resolve_host_uuid(config.host_id)

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

        # Resolve session factory and ownership mode
        resolved_factory = session_factory or config.session_factory
        if session is not None and resolved_factory is not None:
            raise ValueError("Cannot specify both session and session_factory")

        # Inspect sessions from passed components to prevent session mismatch
        repo_session = getattr(event_repository, "session", None) or getattr(
            event_repository, "_session", None
        )
        passed_resolver = identity_resolver
        if passed_resolver is None and event_processor is not None:
            passed_resolver = getattr(event_processor, "resolver", None)
        resolver_session = getattr(passed_resolver, "session", None) or getattr(
            passed_resolver, "_session", None
        )

        # Enforce consistency across components
        if resolved_factory is not None:
            if repo_session is not None:
                raise ValueError(
                    "Cannot specify event_repository with an active session when session_factory is configured"
                )
            if resolver_session is not None:
                raise ValueError(
                    "Cannot specify identity_resolver or event_processor with an active session when session_factory is configured"
                )
        elif session is not None:
            if repo_session is not None and repo_session is not session:
                raise ValueError("event_repository session does not match provided session")
            if resolver_session is not None and resolver_session is not session:
                raise ValueError("identity_resolver session does not match provided session")
        else:
            # session is None and resolved_factory is None
            if repo_session is not None and resolver_session is not None and repo_session is not resolver_session:
                raise ValueError("Conflicting sessions between event_repository and identity_resolver")
            session = repo_session or resolver_session

        # Check resolver / processor compatibility
        if identity_resolver is not None and event_processor is not None:
            ep_resolver = getattr(event_processor, "resolver", None)
            if (
                ep_resolver is not None
                and not isinstance(ep_resolver, NoOpIdentityResolver)
                and ep_resolver is not identity_resolver
            ):
                raise ValueError(
                    "Cannot specify both identity_resolver and event_processor with conflicting resolvers"
                )

        self._session_factory = resolved_factory
        self._session = session
        self._is_session_owned = resolved_factory is not None
        self._current_session: Session | None = None

        # Event Processing & Output: production pipeline uses DatabaseIdentityResolver
        # when an active database session or session factory is supplied.
        if event_processor is not None:
            self.processor = event_processor
            if identity_resolver is not None and isinstance(
                getattr(event_processor, "resolver", None), NoOpIdentityResolver
            ):
                event_processor.resolver = identity_resolver
            self.resolver = getattr(event_processor, "resolver", None)
        elif identity_resolver is not None:
            self.resolver = identity_resolver
            self.processor = EventProcessor(resolver=identity_resolver)
        elif self._is_session_owned:
            self.resolver = DatabaseIdentityResolver(session=None)
            self.processor = EventProcessor(resolver=self.resolver)
        elif self._session is not None:
            self.resolver = DatabaseIdentityResolver(session=self._session)
            self.processor = EventProcessor(resolver=self.resolver)
        else:
            self.resolver = NoOpIdentityResolver()
            self.processor = EventProcessor(resolver=self.resolver)

        self.user_synchronizer = user_synchronizer or LinuxUserSynchronizer(
            passwd_file=config.passwd_file,
            user_provider=config.user_provider,
        )
        self.process_lifecycle_service = (
            process_lifecycle_service or ProcessLifecycleService()
        )

        if event_repository is not None:
            self.repository = event_repository
        elif self._is_session_owned:
            self.repository = EventRepository(session=None)
        elif self._session is not None:
            self.repository = EventRepository(session=self._session)
        else:
            self.repository = None

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
    def is_session_owned(self) -> bool:
        """True if the orchestrator owns the database session lifecycle."""
        return self._is_session_owned

    @property
    def session_factory(self) -> Callable[[], Session] | None:
        """The configured session factory, if any."""
        return self._session_factory

    @property
    def session(self) -> Session | None:
        """The active database session (if externally provided or currently in-cycle)."""
        if self._is_session_owned:
            return self._current_session
        return self._session

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

    def _bind_session(self, session: Session) -> None:
        """Bind active session to all pipeline components to ensure transaction consistency."""
        if self.resolver is not None:
            if hasattr(self.resolver, "session"):
                self.resolver.session = session
            elif hasattr(self.resolver, "set_session"):
                self.resolver.set_session(session)
            elif hasattr(self.resolver, "_session"):
                self.resolver._session = session

        if hasattr(self.processor, "resolver") and self.processor.resolver is not None:
            res = self.processor.resolver
            if hasattr(res, "session"):
                res.session = session
            elif hasattr(res, "set_session"):
                res.set_session(session)
            elif hasattr(res, "_session"):
                res._session = session

        if self.repository is not None:
            if hasattr(self.repository, "session"):
                self.repository.session = session
            elif hasattr(self.repository, "set_session"):
                self.repository.set_session(session)
            elif hasattr(self.repository, "_session"):
                self.repository._session = session

    def _unbind_session(self) -> None:
        """Clear active session from pipeline components after cycle completion."""
        if self.resolver is not None:
            if hasattr(self.resolver, "session"):
                self.resolver.session = None
            elif hasattr(self.resolver, "set_session"):
                self.resolver.set_session(None)
            elif hasattr(self.resolver, "_session"):
                self.resolver._session = None

        if hasattr(self.processor, "resolver") and self.processor.resolver is not None:
            res = self.processor.resolver
            if hasattr(res, "session"):
                res.session = None
            elif hasattr(res, "set_session"):
                res.set_session(None)
            elif hasattr(res, "_session"):
                res._session = None

        if self.repository is not None:
            if hasattr(self.repository, "session"):
                self.repository.session = None
            elif hasattr(self.repository, "set_session"):
                self.repository.set_session(None)
            elif hasattr(self.repository, "_session"):
                self.repository._session = None

    def _clear_identity_caches(self) -> None:
        """Clear identity resolution caches."""
        if self.resolver is not None and hasattr(self.resolver, "clear_cache"):
            try:
                self.resolver.clear_cache()
            except Exception as exc:
                logger.error("Error clearing resolver cache: %s", exc)
        if (
            hasattr(self.processor, "resolver")
            and self.processor.resolver is not None
            and self.processor.resolver is not self.resolver
            and hasattr(self.processor.resolver, "clear_cache")
        ):
            try:
                self.processor.resolver.clear_cache()
            except Exception as exc:
                logger.error("Error clearing processor resolver cache: %s", exc)

    def _restore_collector_state(
        self,
        saved_proc_state: Any = None,
        saved_proc_time: float | None = None,
        saved_res_time: float | None = None,
    ) -> None:
        """Restore collector internal state if cycle rolled back."""
        if saved_proc_state is not None and hasattr(self.process_collector, "_known_processes"):
            try:
                self.process_collector._known_processes = dict(saved_proc_state)
            except Exception as exc:
                logger.error("Error restoring ProcessCollector _known_processes: %s", exc)
        self._last_process_time = saved_proc_time
        self._last_resource_time = saved_res_time

    def _commit_cycle(
        self,
        session: Session,
        savepoint: Any | None,
        saved_proc_state: Any = None,
        saved_proc_time: float | None = None,
        saved_res_time: float | None = None,
        sink_errors: dict[str, str] | None = None,
    ) -> str | None:
        """Commit all cycle changes at the appropriate boundary.

        Returns an error message string if commit fails, or None on success.
        """
        if self._is_session_owned:
            try:
                session.commit()
                return None
            except Exception as exc:
                msg = f"Session commit error: {exc}"
                logger.error(msg, exc_info=True)
                try:
                    session.rollback()
                except Exception as rb_exc:
                    rb_msg = f"Session rollback after commit error: {rb_exc}"
                    logger.error(rb_msg, exc_info=True)
                    if sink_errors is not None:
                        sink_errors["rollback"] = rb_msg
                self._clear_identity_caches()
                self._restore_collector_state(saved_proc_state, saved_proc_time, saved_res_time)
                return msg
        elif savepoint is not None:
            try:
                savepoint.commit()
                return None
            except Exception as exc:
                msg = f"Savepoint commit error: {exc}"
                logger.error(msg, exc_info=True)
                try:
                    savepoint.rollback()
                except Exception as rb_exc:
                    rb_msg = f"Savepoint rollback after commit error: {rb_exc}"
                    logger.error(rb_msg, exc_info=True)
                    if sink_errors is not None:
                        sink_errors["rollback"] = rb_msg
                self._clear_identity_caches()
                self._restore_collector_state(saved_proc_state, saved_proc_time, saved_res_time)
                return msg
        return None

    def _rollback_cycle(
        self,
        session: Session | None,
        savepoint: Any | None,
        saved_proc_state: Any = None,
        saved_proc_time: float | None = None,
        saved_res_time: float | None = None,
        sink_errors: dict[str, str] | None = None,
    ) -> None:
        """Roll back all database changes made during the cycle, restore collector state, and clear identity caches."""
        if session is not None:
            if self._is_session_owned:
                try:
                    session.rollback()
                except Exception as exc:
                    rb_msg = f"Session rollback error: {exc}"
                    logger.error(rb_msg, exc_info=True)
                    if sink_errors is not None:
                        sink_errors["rollback"] = rb_msg
            elif savepoint is not None:
                try:
                    savepoint.rollback()
                except Exception as exc:
                    rb_msg = f"Savepoint rollback error: {exc}"
                    logger.error(rb_msg, exc_info=True)
                    if sink_errors is not None:
                        sink_errors["rollback"] = rb_msg

        self._restore_collector_state(saved_proc_state, saved_proc_time, saved_res_time)
        self._clear_identity_caches()

    def _close_session(self, session: Session) -> None:
        """Close orchestrator-owned session."""
        try:
            session.close()
        except Exception as exc:
            logger.warning("Error closing cycle session: %s", exc)

    def run_cycle(self, force_all: bool = False) -> CycleResult:
        """Execute a single synchronous collection and normalization cycle.

        All database modifications within the cycle (Linux user synchronization,
        process lifecycle tracking, event normalization identity queries, and
        event persistence) are executed within an atomic transaction boundary.

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
            batch_result = BatchResult()
            normalized_events: list[NormalizedEvent] = []

            # Save collector state for rollback restoration if database operations fail
            saved_proc_state: dict[Any, Any] | None = None
            if hasattr(self.process_collector, "_known_processes") and isinstance(
                self.process_collector._known_processes, dict
            ):
                saved_proc_state = dict(self.process_collector._known_processes)
            saved_proc_time = self._last_process_time
            saved_res_time = self._last_resource_time

            # Acquire cycle session
            session: Session | None = None
            savepoint: Any | None = None

            if self._is_session_owned:
                if self._session_factory is not None:
                    try:
                        session = self._session_factory()
                        self._current_session = session
                    except Exception as exc:
                        msg = f"Failed to acquire session from factory: {exc}"
                        logger.error(msg, exc_info=True)
                        sink_errors["transaction"] = msg
                        self._restore_collector_state(saved_proc_state, saved_proc_time, saved_res_time)
                        self._clear_identity_caches()
                        return CycleResult(
                            timestamp=now_wall,
                            observations_count=0,
                            events=[],
                            sink_errors=sink_errors,
                            duration_ms=round((self._monotonic_clock() - t_start) * 1000.0, 3),
                        )
            elif self._session is not None:
                session = self._session

            try:
                # Bind cycle session to components so all queries and writes use the same transaction
                if session is not None:
                    self._bind_session(session)

                    if not self._is_session_owned and hasattr(session, "begin_nested"):
                        try:
                            savepoint = session.begin_nested()
                        except Exception as exc:
                            msg = f"Savepoint error: {exc}"
                            logger.error("Failed to begin savepoint on external session: %s", exc)
                            sink_errors["transaction"] = msg
                            self._restore_collector_state(saved_proc_state, saved_proc_time, saved_res_time)
                            self._clear_identity_caches()
                            self._unbind_session()
                            return CycleResult(
                                timestamp=now_wall,
                                observations_count=0,
                                events=[],
                                sink_errors=sink_errors,
                                duration_ms=round((self._monotonic_clock() - t_start) * 1000.0, 3),
                            )

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

                db_failed = False

                # 4. Synchronize user-account information for the monitored host
                if session is not None and self.user_synchronizer is not None:
                    try:
                        self.user_synchronizer.sync_users(
                            self.host_uuid,
                            session,
                            resolver=self.resolver,
                            now=now_wall,
                        )
                    except Exception as exc:
                        msg = f"User synchronization error: {exc}"
                        logger.error(msg, exc_info=True)
                        sink_errors["user_sync"] = msg
                        db_failed = True

                # 5. Apply process start/end lifecycle changes using the real observations
                # If user sync failed, stop subsequent database-dependent processing to avoid querying aborted transaction
                if not db_failed and session is not None and self.process_lifecycle_service is not None:
                    try:
                        self.process_lifecycle_service.apply_observations(
                            session,
                            raw_observations,
                            self.host_uuid,
                            resolver=self.resolver,
                            now=now_wall,
                        )
                    except Exception as exc:
                        msg = f"Process lifecycle error: {exc}"
                        logger.error(msg, exc_info=True)
                        sink_errors["process_lifecycle"] = msg
                        db_failed = True

                # 6. Authoritative Event Normalization & Identity Enrichment
                # If an entity flush failed, unbind session and skip subsequent database-dependent processing
                if db_failed:
                    self._unbind_session()
                else:
                    try:
                        batch_result = self.processor.process_batch(raw_observations)
                        normalized_events = batch_result.events
                    except Exception as exc:
                        msg = f"Event processing error: {exc}"
                        logger.error(msg, exc_info=True)
                        sink_errors["processing"] = msg
                        db_failed = True

                # 7. Persistence (only if database operations have not failed and events exist)
                if not db_failed and normalized_events and self.repository is not None:
                    try:
                        self.repository.save_batch(normalized_events)
                    except Exception as exc:
                        msg = f"EventRepository save_batch error: {exc}"
                        logger.error(msg, exc_info=True)
                        sink_errors["repository"] = msg
                        db_failed = True

                duration_ms = round((self._monotonic_clock() - t_start) * 1000.0, 3)
                self._cycle_count += 1
                self._total_observations += len(raw_observations)
                self._last_cycle_timestamp = now_wall

                # Policy:
                # Collector health failure alone DOES NOT force rollback of valid database writes.
                # Rollback is required if:
                # - Any database operation failed (db_failed is True)
                # - Any observation was malformed or processing error occurred (batch_result.errors)
                # - Any fatal processing or sink error occurred (sink_errors is non-empty)
                should_commit = (
                    not db_failed
                    and not batch_result.errors
                    and not sink_errors
                )

                committed = False
                if session is not None:
                    if should_commit:
                        commit_err = self._commit_cycle(
                            session,
                            savepoint,
                            saved_proc_state,
                            saved_proc_time,
                            saved_res_time,
                            sink_errors,
                        )
                        if commit_err:
                            sink_errors["transaction"] = commit_err
                        else:
                            committed = True
                    else:
                        self._rollback_cycle(
                            session,
                            savepoint,
                            saved_proc_state,
                            saved_proc_time,
                            saved_res_time,
                            sink_errors,
                        )
                else:
                    # In-memory mode (no database session):
                    committed = not db_failed and not sink_errors

                # 8. Post-commit operations:
                # Only increment _total_events and dispatch callbacks AFTER successful commit!
                if committed and normalized_events:
                    self._total_events += len(normalized_events)
                    if self.callback is not None:
                        try:
                            self.callback(normalized_events)
                        except Exception as exc:
                            msg = f"Event callback error: {exc}"
                            logger.error("Event callback error after successful commit: %s", exc, exc_info=True)
                            sink_errors["callback"] = msg

                return CycleResult(
                    timestamp=now_wall,
                    observations_count=len(raw_observations),
                    events=normalized_events if committed else [],
                    collector_errors=collector_errors,
                    processing_errors=batch_result.errors,
                    sink_errors=sink_errors,
                    duration_ms=duration_ms,
                )

            except (KeyboardInterrupt, SystemExit):
                if session is not None:
                    self._rollback_cycle(
                        session,
                        savepoint,
                        saved_proc_state,
                        saved_proc_time,
                        saved_res_time,
                        sink_errors,
                    )
                raise
            except Exception as exc:
                msg = f"Unexpected orchestration error: {exc}"
                logger.error(msg, exc_info=True)
                sink_errors.setdefault("fatal", msg)
                if session is not None:
                    self._rollback_cycle(
                        session,
                        savepoint,
                        saved_proc_state,
                        saved_proc_time,
                        saved_res_time,
                        sink_errors,
                    )
                else:
                    self._restore_collector_state(saved_proc_state, saved_proc_time, saved_res_time)
                    self._clear_identity_caches()
                duration_ms = round((self._monotonic_clock() - t_start) * 1000.0, 3)
                return CycleResult(
                    timestamp=now_wall,
                    observations_count=len(raw_observations),
                    events=[],
                    collector_errors=collector_errors,
                    processing_errors=batch_result.errors,
                    sink_errors=sink_errors,
                    duration_ms=duration_ms,
                )
            finally:
                if session is not None and self._is_session_owned:
                    self._close_session(session)
                    self._current_session = None
                    self._unbind_session()

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
