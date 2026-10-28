"""Unit tests for the OSIRIS Collector Orchestrator.

Tests run deterministically on any operating system (including macOS)
using mock collectors, injected fake clocks, and temporary filesystem paths.
"""

from __future__ import annotations

import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from backend.services.events.processor import BatchResult, EventProcessor
from backend.services.events.schemas import NormalizedEvent, RawObservation
from collectors.filesystem.collector import FilesystemCollector
from collectors.filesystem.inotify import InotifyBackend, InotifyEvent
from collectors.orchestrator import (
    CollectorOrchestrator,
    CollectorStartupError,
    CycleResult,
    OrchestratorConfig,
    OrchestratorError,
    OrchestratorState,
)
from collectors.process.collector import ProcessCollector
from collectors.resource.collector import ResourceCollector

TEST_HOST_ID = uuid.UUID("11111111-1111-4111-8111-111111111111")


class FakeClock:
    """Deterministic monotonic and wall clock for testing."""

    def __init__(self, start_mono: float = 1000.0, start_wall: datetime | None = None) -> None:
        self.mono = start_mono
        self.wall = start_wall or datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)

    def monotonic(self) -> float:
        return self.mono

    def wall_clock(self) -> datetime:
        return self.wall

    def advance(self, seconds: float) -> None:
        self.mono += seconds
        from datetime import timedelta
        self.wall += timedelta(seconds=seconds)


class DummyMockBackend(InotifyBackend):
    """In-memory mock inotify backend for orchestrator unit testing."""

    def __init__(self) -> None:
        self.watches: dict[Path, int] = {}
        self.events_queue: list[InotifyEvent] = []
        self._next_wd = 1
        self.closed = False

    def add_watch(self, path: Path, mask: int = 0) -> int:
        wd = self._next_wd
        self._next_wd += 1
        self.watches[path.resolve()] = wd
        return wd

    def rm_watch(self, wd: int) -> None:
        for p, w in list(self.watches.items()):
            if w == wd:
                del self.watches[p]

    def read_events(self) -> list[InotifyEvent]:
        events = list(self.events_queue)
        self.events_queue.clear()
        return events

    def close(self) -> None:
        self.closed = True
        self.watches.clear()

    def get_path_for_wd(self, wd: int) -> Path | None:
        for p, w in self.watches.items():
            if w == wd:
                return p
        return None

    def get_wd_for_path(self, path: Path) -> int | None:
        return self.watches.get(path.resolve())

    def update_watch_path(self, old_path: Path, new_path: Path) -> None:
        if old_path.resolve() in self.watches:
            wd = self.watches.pop(old_path.resolve())
            self.watches[new_path.resolve()] = wd

    def remove_watch_by_path(self, path: Path, recursive: bool = True) -> list[int]:
        removed = []
        resolved = path.resolve()
        for p, wd in list(self.watches.items()):
            if p == resolved or (recursive and p.is_relative_to(resolved)):
                removed.append(wd)
                del self.watches[p]
        return removed


def make_mock_observation(
    source: str = "proc",
    event_type: str = "process.start",
    action: str = "start",
    host_id: uuid.UUID = TEST_HOST_ID,
) -> RawObservation:
    """Helper creating a valid RawObservation."""
    return RawObservation(
        source=source,
        host_id=host_id,
        event_type=event_type,
        action=action,
        severity="info",
        observed_at=datetime.now(timezone.utc),
        payload={"test": True, "timestamp_source": "collection_time"},
    )


# ========================================================================
# 1. CONFIGURATION & INITIALIZATION TESTS
# ========================================================================


class TestOrchestratorInit:
    def test_default_config(self):
        config = OrchestratorConfig(host_id=TEST_HOST_ID)
        assert config.process_interval == 2.0
        assert config.resource_interval == 5.0
        assert config.tick_interval == 0.5
        assert config.filesystem_paths == []
        assert config.filesystem_recursive is True
        assert config.resource_granular is False

    def test_host_id_string_conversion(self):
        backend = DummyMockBackend()
        config = OrchestratorConfig(host_id=str(TEST_HOST_ID), fs_backend=backend)
        orchestrator = CollectorOrchestrator(config)
        assert orchestrator.host_uuid == TEST_HOST_ID

    def test_initial_state(self):
        backend = DummyMockBackend()
        config = OrchestratorConfig(host_id=TEST_HOST_ID, fs_backend=backend)
        orchestrator = CollectorOrchestrator(config)
        assert orchestrator.state == OrchestratorState.STOPPED
        assert orchestrator.is_running() is False


# ========================================================================
# 2. STARTUP SEQUENCE & ROLLBACK TESTS
# ========================================================================


class TestOrchestratorStartup:
    def test_startup_registers_watches_and_starts_collectors(self, tmp_path: Path):
        watch_dir = tmp_path / "watched"
        watch_dir.mkdir()

        backend = DummyMockBackend()
        config = OrchestratorConfig(
            host_id=TEST_HOST_ID,
            filesystem_paths=[watch_dir],
            fs_backend=backend,
        )
        orchestrator = CollectorOrchestrator(config)

        # Start without background thread
        orchestrator.start(background=False)
        assert orchestrator.is_running() is True
        assert orchestrator.state == OrchestratorState.RUNNING

        # Watch must be registered
        assert watch_dir.resolve() in backend.watches

        orchestrator.stop()
        assert orchestrator.is_running() is False
        assert orchestrator.state == OrchestratorState.STOPPED
        assert backend.closed is True

    def test_startup_failure_rolls_back_and_closes_resources(self, tmp_path: Path):
        nonexistent = tmp_path / "does_not_exist"
        backend = DummyMockBackend()

        config = OrchestratorConfig(
            host_id=TEST_HOST_ID,
            filesystem_paths=[nonexistent],
            fs_backend=backend,
        )
        orchestrator = CollectorOrchestrator(config)

        # Startup must fail because path does not exist
        with pytest.raises(CollectorStartupError, match="Failed to register filesystem watch"):
            orchestrator.start(background=False)

        # State must roll back to STOPPED
        assert orchestrator.state == OrchestratorState.STOPPED
        assert orchestrator.is_running() is False
        # Backend closed, zero watches leaked
        assert backend.closed is True
        assert len(backend.watches) == 0

    def test_cannot_start_while_already_running(self, tmp_path: Path):
        backend = DummyMockBackend()
        config = OrchestratorConfig(host_id=TEST_HOST_ID, fs_backend=backend)
        orchestrator = CollectorOrchestrator(config)

        orchestrator.start(background=False)
        with pytest.raises(OrchestratorError, match="Cannot start orchestrator"):
            orchestrator.start(background=False)

        orchestrator.stop()


# ========================================================================
# 3. DETERMINISTIC CYCLE EXECUTION & INTERVAL GATING TESTS
# ========================================================================


class TestOrchestratorCycleExecution:
    def test_run_cycle_with_injected_collectors_and_clock(self):
        fake_clock = FakeClock(start_mono=100.0)

        # Mock collectors
        mock_proc = MagicMock()
        mock_proc.collect_observations.return_value = [
            make_mock_observation(source="proc", event_type="process.start")
        ]

        mock_res = MagicMock()
        mock_res.collect_observations.return_value = [
            make_mock_observation(source="resource", event_type="resource.snapshot")
        ]

        mock_fs = MagicMock()
        mock_fs.collect_observations.return_value = [
            make_mock_observation(source="fs", event_type="filesystem.create")
        ]

        config = OrchestratorConfig(
            host_id=TEST_HOST_ID,
            process_interval=2.0,
            resource_interval=5.0,
            monotonic_clock=fake_clock.monotonic,
            wall_clock=fake_clock.wall_clock,
        )

        orchestrator = CollectorOrchestrator(
            config,
            process_collector=mock_proc,
            resource_collector=mock_res,
            filesystem_collector=mock_fs,
        )

        # Cycle 1: initial run -> all 3 collectors run
        res1 = orchestrator.run_cycle(force_all=False)
        assert res1.success is True
        assert res1.observations_count == 3
        assert len(res1.events) == 3
        assert mock_fs.collect_observations.call_count == 1
        assert mock_proc.collect_observations.call_count == 1
        assert mock_res.collect_observations.call_count == 1

        # Cycle 2: clock has not advanced -> only filesystem collector runs!
        res2 = orchestrator.run_cycle(force_all=False)
        assert res2.observations_count == 1
        assert len(res2.events) == 1
        assert res2.events[0].source == "fs"
        assert mock_fs.collect_observations.call_count == 2
        assert mock_proc.collect_observations.call_count == 1
        assert mock_res.collect_observations.call_count == 1

        # Cycle 3: advance clock by 2.0s -> process collector runs, resource does not
        fake_clock.advance(2.0)
        res3 = orchestrator.run_cycle(force_all=False)
        assert res3.observations_count == 2
        sources = {e.source for e in res3.events}
        assert sources == {"fs", "proc"}
        assert mock_fs.collect_observations.call_count == 3
        assert mock_proc.collect_observations.call_count == 2
        assert mock_res.collect_observations.call_count == 1

        # Cycle 4: advance clock by 3.0s (total 5.0s elapsed for resource) -> resource runs!
        fake_clock.advance(3.0)
        res4 = orchestrator.run_cycle(force_all=False)
        assert mock_res.collect_observations.call_count == 2

    def test_run_cycle_force_all_bypasses_interval_gating(self):
        fake_clock = FakeClock(start_mono=500.0)

        mock_proc = MagicMock()
        mock_proc.collect_observations.return_value = [make_mock_observation(source="proc")]
        mock_res = MagicMock()
        mock_res.collect_observations.return_value = [make_mock_observation(source="resource")]
        mock_fs = MagicMock()
        mock_fs.collect_observations.return_value = [make_mock_observation(source="fs")]

        config = OrchestratorConfig(
            host_id=TEST_HOST_ID,
            process_interval=100.0,
            resource_interval=100.0,
            monotonic_clock=fake_clock.monotonic,
            wall_clock=fake_clock.wall_clock,
        )

        orchestrator = CollectorOrchestrator(
            config,
            process_collector=mock_proc,
            resource_collector=mock_res,
            filesystem_collector=mock_fs,
        )

        # Initial run
        orchestrator.run_cycle(force_all=False)
        assert mock_proc.collect_observations.call_count == 1
        assert mock_res.collect_observations.call_count == 1

        # Next run with force_all=True without advancing clock
        res = orchestrator.run_cycle(force_all=True)
        assert mock_proc.collect_observations.call_count == 2
        assert mock_res.collect_observations.call_count == 2
        assert res.observations_count == 3


# ========================================================================
# 4. ERROR ISOLATION TESTS
# ========================================================================


class TestOrchestratorErrorIsolation:
    def test_collector_failure_does_not_abort_other_collectors(self):
        # Process collector raises RuntimeError
        mock_proc = MagicMock()
        mock_proc.collect_observations.side_effect = RuntimeError("procfs disk read failed")

        mock_res = MagicMock()
        mock_res.collect_observations.return_value = [
            make_mock_observation(source="resource", event_type="resource.snapshot")
        ]

        mock_fs = MagicMock()
        mock_fs.collect_observations.return_value = [
            make_mock_observation(source="fs", event_type="filesystem.modify")
        ]

        config = OrchestratorConfig(host_id=TEST_HOST_ID)
        orchestrator = CollectorOrchestrator(
            config,
            process_collector=mock_proc,
            resource_collector=mock_res,
            filesystem_collector=mock_fs,
        )

        res = orchestrator.run_cycle(force_all=True)
        # Cycle completes without raising
        assert res.success is False
        assert "proc" in res.collector_errors
        assert "procfs disk read failed" in res.collector_errors["proc"]

        # Other 2 collectors succeeded
        assert res.observations_count == 2
        assert len(res.events) == 2
        sources = {e.source for e in res.events}
        assert sources == {"fs", "resource"}

        # Health tracking updated
        status = orchestrator.get_status()
        assert status["collectors"]["proc"]["healthy"] is False
        assert status["collectors"]["resource"]["healthy"] is True
        assert status["collectors"]["fs"]["healthy"] is True

    def test_processor_batch_error_isolation(self):
        """Malformed observation reports error in processing_errors without losing valid events."""
        valid_obs = make_mock_observation(source="proc", event_type="process.start")
        # Observation with invalid severity
        invalid_obs = RawObservation(
            source="proc",
            host_id=TEST_HOST_ID,
            event_type="process.start",
            action="start",
            severity="INVALID_SEVERITY",  # will fail EventValidator
            observed_at=datetime.now(timezone.utc),
        )

        mock_proc = MagicMock()
        mock_proc.collect_observations.return_value = [valid_obs, invalid_obs]

        config = OrchestratorConfig(host_id=TEST_HOST_ID)
        orchestrator = CollectorOrchestrator(
            config,
            process_collector=mock_proc,
            resource_collector=MagicMock(collect_observations=lambda **kw: []),
            filesystem_collector=MagicMock(collect_observations=lambda: []),
        )

        res = orchestrator.run_cycle(force_all=True)
        assert res.success is False
        assert len(res.processing_errors) == 1
        idx, errors = res.processing_errors[0]
        assert idx == 1
        assert any("severity" in err.lower() for err in errors)

        # Valid observation was normalized successfully
        assert len(res.events) == 1
        assert isinstance(res.events[0], NormalizedEvent)


# ========================================================================
# 5. PERSISTENCE & CALLBACK TESTS
# ========================================================================


class TestOrchestratorPersistenceAndCallback:
    def test_optional_repository_save_batch(self):
        mock_repo = MagicMock()
        mock_proc = MagicMock()
        mock_proc.collect_observations.return_value = [make_mock_observation(source="proc")]

        config = OrchestratorConfig(host_id=TEST_HOST_ID)
        orchestrator = CollectorOrchestrator(
            config,
            process_collector=mock_proc,
            resource_collector=MagicMock(collect_observations=lambda **kw: []),
            filesystem_collector=MagicMock(collect_observations=lambda: []),
            event_repository=mock_repo,
        )

        res = orchestrator.run_cycle(force_all=True)
        assert res.success is True
        assert mock_repo.save_batch.call_count == 1
        assert len(mock_repo.save_batch.call_args[0][0]) == 1

    def test_repository_error_does_not_crash_cycle(self):
        mock_repo = MagicMock()
        mock_repo.save_batch.side_effect = Exception("DB Connection Timeout")

        mock_proc = MagicMock()
        mock_proc.collect_observations.return_value = [make_mock_observation(source="proc")]

        config = OrchestratorConfig(host_id=TEST_HOST_ID)
        orchestrator = CollectorOrchestrator(
            config,
            process_collector=mock_proc,
            resource_collector=MagicMock(collect_observations=lambda **kw: []),
            filesystem_collector=MagicMock(collect_observations=lambda: []),
            event_repository=mock_repo,
        )

        res = orchestrator.run_cycle(force_all=True)
        assert res.success is False
        assert "repository" in res.sink_errors
        assert "DB Connection Timeout" in res.sink_errors["repository"]
        assert "repository" not in res.collector_errors
        assert not res.collector_errors

    def test_callback_error_does_not_crash_cycle(self):
        def bad_callback(events: list[NormalizedEvent]) -> None:
            raise RuntimeError("Callback Handler Crash")

        mock_proc = MagicMock()
        mock_proc.collect_observations.return_value = [make_mock_observation(source="proc")]

        config = OrchestratorConfig(host_id=TEST_HOST_ID)
        orchestrator = CollectorOrchestrator(
            config,
            process_collector=mock_proc,
            resource_collector=MagicMock(collect_observations=lambda **kw: []),
            filesystem_collector=MagicMock(collect_observations=lambda: []),
            event_callback=bad_callback,
        )

        res = orchestrator.run_cycle(force_all=True)
        assert res.success is False
        assert "callback" in res.sink_errors
        assert "Callback Handler Crash" in res.sink_errors["callback"]
        assert "callback" not in res.collector_errors
        assert not res.collector_errors

    def test_optional_callback_invoked(self):
        delivered = []

        def callback(events: list[NormalizedEvent]) -> None:
            delivered.extend(events)

        mock_proc = MagicMock()
        mock_proc.collect_observations.return_value = [make_mock_observation(source="proc")]

        config = OrchestratorConfig(host_id=TEST_HOST_ID)
        orchestrator = CollectorOrchestrator(
            config,
            process_collector=mock_proc,
            resource_collector=MagicMock(collect_observations=lambda **kw: []),
            filesystem_collector=MagicMock(collect_observations=lambda: []),
            event_callback=callback,
        )

        res = orchestrator.run_cycle(force_all=True)
        assert res.success is True
        assert len(delivered) == 1
        assert delivered[0].source == "proc"


# ========================================================================
# 6. THREADED LIFECYCLE & CONTEXT MANAGER TESTS
# ========================================================================


class TestOrchestratorLifecycle:
    def test_background_thread_start_and_stop(self):
        backend = DummyMockBackend()
        config = OrchestratorConfig(
            host_id=TEST_HOST_ID,
            tick_interval=0.05,
            fs_backend=backend,
        )

        mock_fs = MagicMock(collect_observations=lambda: [])
        orchestrator = CollectorOrchestrator(
            config,
            filesystem_collector=mock_fs,
            process_collector=MagicMock(collect_observations=lambda: []),
            resource_collector=MagicMock(collect_observations=lambda **kw: []),
        )

        orchestrator.start(background=True)
        assert orchestrator.is_running() is True
        assert orchestrator._worker_thread is not None
        assert orchestrator._worker_thread.is_alive()

        # Let worker run for several ticks
        time.sleep(0.15)
        assert orchestrator._cycle_count >= 2

        orchestrator.stop(timeout=1.0)
        assert orchestrator.is_running() is False
        assert orchestrator.state == OrchestratorState.STOPPED
        assert not orchestrator._worker_thread.is_alive()

    def test_context_manager(self):
        backend = DummyMockBackend()
        config = OrchestratorConfig(
            host_id=TEST_HOST_ID,
            tick_interval=0.05,
            fs_backend=backend,
        )

        orchestrator = CollectorOrchestrator(
            config,
            filesystem_collector=MagicMock(collect_observations=lambda: []),
            process_collector=MagicMock(collect_observations=lambda: []),
            resource_collector=MagicMock(collect_observations=lambda **kw: []),
        )

        with orchestrator:
            assert orchestrator.is_running() is True

        assert orchestrator.is_running() is False
        assert orchestrator.state == OrchestratorState.STOPPED

    def test_telemetry_status(self):
        fake_clock = FakeClock()
        config = OrchestratorConfig(
            host_id=TEST_HOST_ID,
            monotonic_clock=fake_clock.monotonic,
            wall_clock=fake_clock.wall_clock,
        )
        orchestrator = CollectorOrchestrator(
            config,
            filesystem_collector=MagicMock(collect_observations=lambda: [make_mock_observation(source="fs")]),
            process_collector=MagicMock(collect_observations=lambda: [make_mock_observation(source="proc")]),
            resource_collector=MagicMock(collect_observations=lambda **kw: [make_mock_observation(source="resource")]),
        )

        orchestrator.run_cycle(force_all=True)
        status = orchestrator.get_status()

        assert status["state"] == "stopped"
        assert status["host_id"] == str(TEST_HOST_ID)
        assert status["cycle_count"] == 1
        assert status["total_observations"] == 3
        assert status["total_events"] == 3
        assert status["last_cycle_timestamp"] is not None
        assert status["collectors"]["proc"]["observations"] == 1
        assert status["collectors"]["resource"]["observations"] == 1
        assert status["collectors"]["fs"]["observations"] == 1

    def test_cleanup_collectors_is_idempotent_and_handles_exceptions_gracefully(self):
        """Cleanup handles broken collectors raising exceptions without propagating."""
        broken_fs = MagicMock()
        broken_fs.stop.side_effect = RuntimeError("Broken stop")
        broken_fs.close.side_effect = RuntimeError("Broken close")

        config = OrchestratorConfig(host_id=TEST_HOST_ID, fs_backend=DummyMockBackend())
        orchestrator = CollectorOrchestrator(
            config,
            filesystem_collector=broken_fs,
            process_collector=MagicMock(),
            resource_collector=MagicMock(),
        )

        # _cleanup_collectors must not raise
        orchestrator._cleanup_collectors()
        assert broken_fs.stop.call_count == 1
        assert broken_fs.close.call_count == 1

    def test_stop_when_already_stopped_is_safe_noop(self):
        config = OrchestratorConfig(host_id=TEST_HOST_ID, fs_backend=DummyMockBackend())
        orchestrator = CollectorOrchestrator(config)
        assert orchestrator.state == OrchestratorState.STOPPED
        # Calling stop on already stopped orchestrator is a no-op
        orchestrator.stop()
        assert orchestrator.state == OrchestratorState.STOPPED

    def test_run_cycle_granular_resource(self):
        mock_proc = MagicMock(collect_observations=lambda: [])
        mock_fs = MagicMock(collect_observations=lambda: [])
        mock_res = MagicMock()
        mock_res.collect_observations.return_value = [
            make_mock_observation(source="resource", event_type="resource.snapshot"),
            make_mock_observation(source="resource", event_type="resource.cpu"),
            make_mock_observation(source="resource", event_type="resource.memory"),
            make_mock_observation(source="resource", event_type="resource.disk"),
        ]

        config = OrchestratorConfig(host_id=TEST_HOST_ID, resource_granular=True)
        orchestrator = CollectorOrchestrator(
            config,
            process_collector=mock_proc,
            resource_collector=mock_res,
            filesystem_collector=mock_fs,
        )

        res = orchestrator.run_cycle(force_all=True)
        assert res.success is True
        assert res.observations_count == 4
        assert len(res.events) == 4
        mock_res.collect_observations.assert_called_once_with(granular=True)


# ========================================================================
# 7. CONCURRENCY & SERIALIZATION TESTS
# ========================================================================


class TestOrchestratorConcurrency:
    def test_concurrent_run_cycle_is_serialized(self):
        """Concurrent run_cycle() calls are strictly serialized so execution paths cannot interleave."""
        active_in_cycle = 0
        max_concurrent_in_cycle = 0
        cycle_concurrency_lock = threading.Lock()

        t1_in_fs = threading.Event()
        release_t1 = threading.Event()
        call_count = 0

        def instrumented_collect():
            nonlocal active_in_cycle, max_concurrent_in_cycle, call_count
            with cycle_concurrency_lock:
                call_count += 1
                current_call = call_count
                active_in_cycle += 1
                if active_in_cycle > max_concurrent_in_cycle:
                    max_concurrent_in_cycle = active_in_cycle

            if current_call == 1:
                # Signal that Thread 1 has acquired the cycle lock and reached collector
                t1_in_fs.set()
                # Hold until Thread 2 has definitely attempted to run_cycle
                assert release_t1.wait(timeout=2.0), "Timed out waiting for t1 release"

            with cycle_concurrency_lock:
                active_in_cycle -= 1

            return [make_mock_observation(source="fs")]

        mock_fs = MagicMock(collect_observations=instrumented_collect)
        config = OrchestratorConfig(host_id=TEST_HOST_ID)
        orchestrator = CollectorOrchestrator(
            config,
            filesystem_collector=mock_fs,
            process_collector=MagicMock(collect_observations=lambda: []),
            resource_collector=MagicMock(collect_observations=lambda **kw: []),
        )

        results: list[CycleResult] = []
        threads_exceptions: list[Exception] = []

        def run_thread(tid: int):
            try:
                res = orchestrator.run_cycle(force_all=False)
                results.append(res)
            except Exception as e:
                threads_exceptions.append(e)

        t1 = threading.Thread(target=run_thread, args=(1,))
        t2 = threading.Thread(target=run_thread, args=(2,))

        # Start Thread 1
        t1.start()
        # Wait until Thread 1 is inside the collector holding _cycle_lock
        assert t1_in_fs.wait(timeout=2.0), "Thread 1 did not reach collector"

        # Start Thread 2 while Thread 1 is holding the lock
        t2.start()

        # Give Thread 2 time to attempt entering run_cycle and block on _cycle_lock
        time.sleep(0.05)

        # Thread 2 MUST NOT have entered instrumented_collect yet
        with cycle_concurrency_lock:
            assert call_count == 1, "Thread 2 entered collector while Thread 1 held cycle lock!"
            assert active_in_cycle == 1

        # Release Thread 1 to finish
        release_t1.set()

        # Join both threads
        t1.join(timeout=2.0)
        t2.join(timeout=2.0)

        assert not threads_exceptions
        assert len(results) == 2
        assert max_concurrent_in_cycle == 1
        assert call_count == 2
        assert orchestrator._cycle_count == 2


# ========================================================================
# 8. M-4: ATOMIC COLLECTION-CYCLE TRANSACTION BOUNDARIES
# ========================================================================

from sqlalchemy import create_engine, event as sa_event, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from unittest.mock import patch

from sqlalchemy.exc import IntegrityError

from backend.db.base import Base
from backend.db.models.host import Host
from backend.db.models.linux_user import LinuxUser
from backend.db.models.process import Process
from backend.db.models.event import Event
from backend.services.events.repository import EventRepository
from backend.services.events.resolver import DatabaseIdentityResolver
from backend.services.events.user_sync import LinuxUserSynchronizer


class TestOrchestratorTransactionBoundaries:
    """Requirement M-4: Atomic collection-cycle transactions and ownership contracts."""

    @pytest.fixture
    def isolated_db(self):
        """Create an isolated, schema-ready in-memory SQLite database."""
        engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )

        @sa_event.listens_for(engine, "connect")
        def set_sqlite_pragma(dbapi_conn, connection_record):
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        Base.metadata.create_all(engine)

        # Seed test host
        host_uuid = uuid.UUID("22222222-2222-4222-8222-222222222222")
        with Session(engine) as s:
            host = Host(
                id=host_uuid,
                hostname="tx-test-host",
                os_info="Linux 6.x",
                ip_address="127.0.0.1",
                created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            )
            s.add(host)
            s.commit()

        yield engine, host_uuid

        Base.metadata.drop_all(engine)
        engine.dispose()

    def test_successful_cycle_commits_process_user_and_events(self, isolated_db):
        """1. Successful cycle commits process, user, and event records atomically."""
        engine, host_uuid = isolated_db
        session_factory = sessionmaker(bind=engine)
        t0 = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

        config = OrchestratorConfig(
            host_id=host_uuid,
            session_factory=session_factory,
            user_provider=lambda: [(1001, "tx_alice")],
            wall_clock=lambda: t0,
            fs_backend=DummyMockBackend(),
        )
        orchestrator = CollectorOrchestrator(config)
        assert orchestrator.is_session_owned is True

        obs_proc = RawObservation(
            source="proc",
            host_id=host_uuid,
            event_type="process.start",
            action="start",
            severity="info",
            observed_at=t0,
            uid=1001,
            pid=4100,
            ppid=1,
            command="/usr/bin/tx_worker",
            object_type="process",
            object_path="/usr/bin/tx_worker",
        )
        orchestrator.process_collector.collect_observations = lambda diff=True: [obs_proc]
        orchestrator.resource_collector.collect_observations = lambda **kw: []
        orchestrator.filesystem_collector.collect_observations = lambda: []

        res = orchestrator.run_cycle(force_all=True)
        assert res.success is True
        assert len(res.events) == 1
        ev = res.events[0]
        assert ev.username == "tx_alice"
        assert ev.process_id is not None

        # Verify that changes were truly COMMITTED to the database in a fresh session
        with session_factory() as verify_session:
            user = verify_session.execute(
                select(LinuxUser).where(LinuxUser.host_id == host_uuid, LinuxUser.uid == 1001)
            ).scalar_one_or_none()
            assert user is not None
            assert user.username == "tx_alice"

            proc = verify_session.get(Process, ev.process_id)
            assert proc is not None
            assert proc.pid == 4100
            assert proc.command == "/usr/bin/tx_worker"
            assert proc.linux_user_id == user.id

            db_event = verify_session.get(Event, ev.id)
            assert db_event is not None
            assert db_event.username == "tx_alice"
            assert db_event.process_id == proc.id

    def test_processing_failure_rolls_back_all_cycle_changes(self, isolated_db):
        """2. A failure during processing rolls back all cycle changes (users, processes, events)."""
        engine, host_uuid = isolated_db
        session_factory = sessionmaker(bind=engine)
        t0 = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

        config = OrchestratorConfig(
            host_id=host_uuid,
            session_factory=session_factory,
            user_provider=lambda: [(1002, "tx_bob")],
            wall_clock=lambda: t0,
            fs_backend=DummyMockBackend(),
        )
        orchestrator = CollectorOrchestrator(config)

        valid_obs = RawObservation(
            source="proc",
            host_id=host_uuid,
            event_type="process.start",
            action="start",
            severity="info",
            observed_at=t0,
            uid=1002,
            pid=4200,
            ppid=1,
            command="/usr/bin/tx_failing_proc",
            object_type="process",
        )
        invalid_obs = RawObservation(
            source="proc",
            host_id=host_uuid,
            event_type="process.start",
            action="start",
            severity="CORRUPTED_SEVERITY",  # Validation failure in EventProcessor
            observed_at=t0,
        )
        orchestrator.process_collector.collect_observations = lambda diff=True: [valid_obs, invalid_obs]
        orchestrator.resource_collector.collect_observations = lambda **kw: []
        orchestrator.filesystem_collector.collect_observations = lambda: []

        res = orchestrator.run_cycle(force_all=True)
        assert res.success is False
        assert len(res.processing_errors) > 0

        # Verify rollback: neither user nor process nor event exists in the database
        with session_factory() as verify_session:
            user = verify_session.execute(
                select(LinuxUser).where(LinuxUser.host_id == host_uuid, LinuxUser.uid == 1002)
            ).scalar_one_or_none()
            assert user is None, "User should have been rolled back"

            procs = verify_session.execute(
                select(Process).where(Process.host_id == host_uuid, Process.pid == 4200)
            ).scalars().all()
            assert len(procs) == 0, "Process should have been rolled back"

            events = verify_session.execute(
                select(Event).where(Event.host_id == host_uuid)
            ).scalars().all()
            assert len(events) == 0, "Events should have been rolled back"

    def test_persistence_failure_rolls_back_entity_changes(self, isolated_db):
        """3. A failure during event persistence rolls back entity changes (processes & users) as well."""
        engine, host_uuid = isolated_db
        session_factory = sessionmaker(bind=engine)
        t0 = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

        # Mock repository that fails during save_batch
        broken_repo = EventRepository(session=None)
        broken_repo.save_batch = MagicMock(side_effect=RuntimeError("Simulated Disk Write Failure"))

        config = OrchestratorConfig(
            host_id=host_uuid,
            session_factory=session_factory,
            user_provider=lambda: [(1003, "tx_charlie")],
            wall_clock=lambda: t0,
            fs_backend=DummyMockBackend(),
        )
        orchestrator = CollectorOrchestrator(config, event_repository=broken_repo)

        obs = RawObservation(
            source="proc",
            host_id=host_uuid,
            event_type="process.start",
            action="start",
            severity="info",
            observed_at=t0,
            uid=1003,
            pid=4300,
            command="/usr/bin/tx_save_fail",
            object_type="process",
        )
        orchestrator.process_collector.collect_observations = lambda diff=True: [obs]
        orchestrator.resource_collector.collect_observations = lambda **kw: []
        orchestrator.filesystem_collector.collect_observations = lambda: []

        res = orchestrator.run_cycle(force_all=True)
        assert res.success is False
        assert "repository" in res.sink_errors
        assert "Simulated Disk Write Failure" in res.sink_errors["repository"]

        # Verify entity changes are completely rolled back
        with session_factory() as verify_session:
            user = verify_session.execute(
                select(LinuxUser).where(LinuxUser.host_id == host_uuid, LinuxUser.uid == 1003)
            ).scalar_one_or_none()
            assert user is None, "User creation must be rolled back on repository failure"

            proc = verify_session.execute(
                select(Process).where(Process.host_id == host_uuid, Process.pid == 4300)
            ).scalar_one_or_none()
            assert proc is None, "Process creation must be rolled back on repository failure"

    def test_failed_cycle_does_not_erase_previously_committed_cycle(self, isolated_db):
        """4. A failed cycle does not erase or roll back a previously committed cycle."""
        engine, host_uuid = isolated_db
        session_factory = sessionmaker(bind=engine)
        t0 = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        t1 = datetime(2026, 1, 15, 11, 0, 0, tzinfo=timezone.utc)
        current_time = t0

        config = OrchestratorConfig(
            host_id=host_uuid,
            session_factory=session_factory,
            user_provider=lambda: [(1004, "tx_cycle1_user")],
            wall_clock=lambda: current_time,
            fs_backend=DummyMockBackend(),
        )
        orchestrator = CollectorOrchestrator(config)

        # ── Cycle 1: Successful ───────────────────────────────────────
        obs1 = RawObservation(
            source="proc",
            host_id=host_uuid,
            event_type="process.start",
            action="start",
            severity="info",
            observed_at=t0,
            uid=1004,
            pid=4401,
            command="/usr/bin/cycle1_svc",
            object_type="process",
        )
        orchestrator.process_collector.collect_observations = lambda diff=True: [obs1]
        orchestrator.resource_collector.collect_observations = lambda **kw: []
        orchestrator.filesystem_collector.collect_observations = lambda: []

        res1 = orchestrator.run_cycle(force_all=True)
        assert res1.success is True

        # Verify Cycle 1 committed
        with session_factory() as s:
            u1 = s.execute(select(LinuxUser).where(LinuxUser.uid == 1004)).scalar_one()
            assert u1.username == "tx_cycle1_user"
            p1 = s.execute(select(Process).where(Process.pid == 4401)).scalar_one()
            assert p1 is not None

        # ── Cycle 2: Fails during processing ──────────────────────────
        current_time = t1
        config.user_provider = lambda: [(1004, "tx_cycle1_user"), (1005, "tx_cycle2_user")]
        bad_obs = RawObservation(
            source="proc",
            host_id=host_uuid,
            event_type="process.start",
            action="start",
            severity="INVALID_SEVERITY_CYCLE2",
            observed_at=t1,
            uid=1005,
            pid=4402,
        )
        orchestrator.process_collector.collect_observations = lambda diff=True: [bad_obs]

        res2 = orchestrator.run_cycle(force_all=True)
        assert res2.success is False

        # Verify Cycle 1 data persists untouched while Cycle 2 data was rolled back
        with session_factory() as s:
            u1 = s.execute(select(LinuxUser).where(LinuxUser.uid == 1004)).scalar_one_or_none()
            assert u1 is not None, "Cycle 1 user must still exist"

            p1 = s.execute(select(Process).where(Process.pid == 4401)).scalar_one_or_none()
            assert p1 is not None, "Cycle 1 process must still exist"

            u2 = s.execute(select(LinuxUser).where(LinuxUser.uid == 1005)).scalar_one_or_none()
            assert u2 is None, "Cycle 2 user must have been rolled back"

            p2 = s.execute(select(Process).where(Process.pid == 4402)).scalar_one_or_none()
            assert p2 is None, "Cycle 2 process must have been rolled back"

    def test_sessions_closed_after_both_success_and_failure(self, isolated_db):
        """5. Sessions owned by the orchestrator are always closed on success and failure."""
        engine, host_uuid = isolated_db
        raw_factory = sessionmaker(bind=engine)
        sessions_created = []

        def tracking_session_factory():
            s = raw_factory()
            original_close = s.close
            close_mock = MagicMock(side_effect=original_close)
            s.close = close_mock
            sessions_created.append(s)
            return s

        config = OrchestratorConfig(
            host_id=host_uuid,
            session_factory=tracking_session_factory,
            fs_backend=DummyMockBackend(),
        )
        orchestrator = CollectorOrchestrator(config)
        assert orchestrator.is_session_owned is True

        # Cycle 1: Success path
        orchestrator.process_collector.collect_observations = lambda diff=True: []
        orchestrator.resource_collector.collect_observations = lambda **kw: []
        orchestrator.filesystem_collector.collect_observations = lambda: []

        res1 = orchestrator.run_cycle(force_all=True)
        assert res1.success is True
        assert len(sessions_created) == 1
        assert sessions_created[0].close.call_count == 1, "Session 1 must be closed on success"

        # Cycle 2: Collector failure path
        orchestrator.filesystem_collector.collect_observations = MagicMock(side_effect=RuntimeError("FS Crash"))
        res2 = orchestrator.run_cycle(force_all=True)
        assert res2.success is False
        assert len(sessions_created) == 2
        assert sessions_created[1].close.call_count == 1, "Session 2 must be closed on collector error"

        # Cycle 3: Persistence failure path
        orchestrator.filesystem_collector.collect_observations = lambda: []
        broken_obs = RawObservation(
            source="proc",
            host_id=host_uuid,
            event_type="process.start",
            action="start",
            severity="info",
            observed_at=datetime.now(timezone.utc),
            uid=0,
            pid=9999,
            command="/bin/crash",
        )
        orchestrator.process_collector.collect_observations = lambda diff=True: [broken_obs]
        orchestrator.repository.save_batch = MagicMock(side_effect=RuntimeError("Persistence error"))

        res3 = orchestrator.run_cycle(force_all=True)
        assert res3.success is False
        assert len(sessions_created) == 3
        assert sessions_created[2].close.call_count == 1, "Session 3 must be closed on persistence error"

    def test_externally_owned_sessions_not_unexpectedly_committed_or_closed(self, isolated_db):
        """6. Externally owned sessions are not unexpectedly committed or closed."""
        engine, host_uuid = isolated_db
        ext_session = Session(engine)
        try:
            # Wrap commit and close with spies
            real_commit = ext_session.commit
            real_close = ext_session.close
            commit_spy = MagicMock(side_effect=real_commit)
            close_spy = MagicMock(side_effect=real_close)
            ext_session.commit = commit_spy
            ext_session.close = close_spy

            repo = EventRepository(ext_session)
            config = OrchestratorConfig(host_id=host_uuid, fs_backend=DummyMockBackend())
            orchestrator = CollectorOrchestrator(config, event_repository=repo)

            assert orchestrator.is_session_owned is False
            assert orchestrator.session is ext_session

            # 1. Run successful cycle
            orchestrator.process_collector.collect_observations = lambda diff=True: []
            orchestrator.resource_collector.collect_observations = lambda **kw: []
            orchestrator.filesystem_collector.collect_observations = lambda: []

            res = orchestrator.run_cycle(force_all=True)
            assert res.success is True

            # External session must NOT be closed and top-level commit must NOT be called
            assert close_spy.call_count == 0, "External session should not be closed"
            assert commit_spy.call_count == 0, "External session should not have top-level commit called"

            # 2. Run failing cycle
            orchestrator.filesystem_collector.collect_observations = MagicMock(side_effect=RuntimeError("FS err"))
            res_fail = orchestrator.run_cycle(force_all=True)
            assert res_fail.success is False

            assert close_spy.call_count == 0, "External session should not be closed on error"
            assert commit_spy.call_count == 0, "External session should not have top-level commit called"

        finally:
            real_close()

    def test_multiple_cycles_use_correct_transaction_boundaries(self, isolated_db):
        """7. Multiple collection cycles use distinct transaction boundaries."""
        engine, host_uuid = isolated_db
        session_factory = sessionmaker(bind=engine)
        t_base = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        config = OrchestratorConfig(
            host_id=host_uuid,
            session_factory=session_factory,
            user_provider=lambda: [(1010, "tx_user_multi")],
            wall_clock=lambda: t_base,
            fs_backend=DummyMockBackend(),
        )
        orchestrator = CollectorOrchestrator(config)

        # Execute 3 separate cycles
        for cycle_idx in range(1, 4):
            pid = 5000 + cycle_idx
            obs = RawObservation(
                source="proc",
                host_id=host_uuid,
                event_type="process.start",
                action="start",
                severity="info",
                observed_at=t_base,
                uid=1010,
                pid=pid,
                command=f"/usr/bin/service_{cycle_idx}",
                object_type="process",
            )
            orchestrator.process_collector.collect_observations = lambda diff=True, o=obs: [o]
            orchestrator.resource_collector.collect_observations = lambda **kw: []
            orchestrator.filesystem_collector.collect_observations = lambda: []

            res = orchestrator.run_cycle(force_all=True)
            assert res.success is True
            assert len(res.events) == 1

        # Verify all 3 processes were committed independently
        with session_factory() as s:
            for cycle_idx in range(1, 4):
                pid = 5000 + cycle_idx
                p = s.execute(select(Process).where(Process.pid == pid)).scalar_one_or_none()
                assert p is not None
                assert p.command == f"/usr/bin/service_{cycle_idx}"

    def test_identity_resolution_shares_exact_cycle_session(self, isolated_db):
        """8. Identity resolution uses the exact same session as process and user persistence."""
        engine, host_uuid = isolated_db
        session_factory = sessionmaker(bind=engine)
        t0 = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

        captured_sessions = {}

        class SpyingUserSync(LinuxUserSynchronizer):
            def sync_users(self, host_id, session, **kw):
                captured_sessions["user_sync"] = session
                return super().sync_users(host_id, session, **kw)

        config = OrchestratorConfig(
            host_id=host_uuid,
            session_factory=session_factory,
            user_provider=lambda: [(1020, "tx_shared_user")],
            wall_clock=lambda: t0,
            fs_backend=DummyMockBackend(),
        )
        orchestrator = CollectorOrchestrator(
            config,
            user_synchronizer=SpyingUserSync(user_provider=lambda: [(1020, "tx_shared_user")]),
        )

        obs = RawObservation(
            source="proc",
            host_id=host_uuid,
            event_type="process.start",
            action="start",
            severity="info",
            observed_at=t0,
            uid=1020,
            pid=6001,
            command="/usr/bin/shared_app",
            object_type="process",
        )
        orchestrator.process_collector.collect_observations = lambda diff=True: [obs]
        orchestrator.resource_collector.collect_observations = lambda **kw: []
        orchestrator.filesystem_collector.collect_observations = lambda: []

        # Before cycle, resolver has no active session
        assert orchestrator.resolver.session is None

        res = orchestrator.run_cycle(force_all=True)
        assert res.success is True

        # During the cycle, user_sync received the active session
        active_sess = captured_sessions["user_sync"]
        assert active_sess is not None

        # After cycle, components are cleanly unbound
        assert orchestrator.session is None
        assert orchestrator.resolver.session is None
        assert orchestrator.repository.session is None

        # The event resolved username from the user synced during the cycle
        assert res.events[0].username == "tx_shared_user"
        assert res.events[0].process_id is not None

    def test_conflicting_session_and_factory_raises_value_error(self, isolated_db):
        """Specifying both session and session_factory raises ValueError."""
        engine, host_uuid = isolated_db
        factory = sessionmaker(bind=engine)
        sess = Session(engine)
        try:
            config = OrchestratorConfig(host_id=host_uuid, fs_backend=DummyMockBackend())
            with pytest.raises(ValueError, match="Cannot specify both"):
                CollectorOrchestrator(config, session=sess, session_factory=factory)
        finally:
            sess.close()

    def test_conflicting_component_sessions_raise_value_error(self, isolated_db):
        """Specifying conflicting sessions across repository, resolver, and orchestrator raises ValueError."""
        engine, host_uuid = isolated_db
        factory = sessionmaker(bind=engine)
        sess1 = Session(engine)
        sess2 = Session(engine)
        try:
            config = OrchestratorConfig(host_id=host_uuid, fs_backend=DummyMockBackend())

            # 1. session_factory + active repository session
            repo_bound = EventRepository(session=sess1)
            with pytest.raises(ValueError, match="Cannot specify event_repository with an active session"):
                CollectorOrchestrator(config, session_factory=factory, event_repository=repo_bound)

            # 2. session_factory + active resolver session
            resolver_bound = DatabaseIdentityResolver(session=sess1)
            with pytest.raises(ValueError, match="Cannot specify identity_resolver or event_processor with an active session"):
                CollectorOrchestrator(config, session_factory=factory, identity_resolver=resolver_bound)

            # 3. session mismatch with repository
            with pytest.raises(ValueError, match="event_repository session does not match provided session"):
                CollectorOrchestrator(config, session=sess2, event_repository=repo_bound)

            # 4. session mismatch with resolver
            with pytest.raises(ValueError, match="identity_resolver session does not match provided session"):
                CollectorOrchestrator(config, session=sess2, identity_resolver=resolver_bound)

            # 5. Conflicting sessions between repository and resolver when orchestrator session is omitted
            repo_s1 = EventRepository(session=sess1)
            res_s2 = DatabaseIdentityResolver(session=sess2)
            with pytest.raises(ValueError, match="Conflicting sessions between event_repository and identity_resolver"):
                CollectorOrchestrator(config, event_repository=repo_s1, identity_resolver=res_s2)

            # 6. Conflicting event_processor and identity_resolver
            ep = EventProcessor(resolver=DatabaseIdentityResolver(session=None))
            custom_res = DatabaseIdentityResolver(session=None)
            with pytest.raises(ValueError, match="Cannot specify both identity_resolver and event_processor"):
                CollectorOrchestrator(config, identity_resolver=custom_res, event_processor=ep)

        finally:
            sess1.close()
            sess2.close()

    def test_session_factory_creation_failure_handled_gracefully(self, isolated_db):
        """If session_factory raises an exception, run_cycle catches it and reports failure cleanly."""
        engine, host_uuid = isolated_db

        def failing_factory():
            raise RuntimeError("DB pool exhausted")

        config = OrchestratorConfig(
            host_id=host_uuid,
            session_factory=failing_factory,
            fs_backend=DummyMockBackend(),
        )
        orchestrator = CollectorOrchestrator(config)
        res = orchestrator.run_cycle(force_all=True)

        assert res.success is False
        assert "transaction" in res.sink_errors
        assert "Failed to acquire session from factory" in res.sink_errors["transaction"]
        assert orchestrator.session is None

    def test_savepoint_creation_failure_does_not_mutate_external_session(self, isolated_db):
        """If savepoint creation fails on an external session, cycle aborts before mutating database."""
        engine, host_uuid = isolated_db
        ext_session = Session(engine)
        try:
            ext_session.begin_nested = MagicMock(side_effect=RuntimeError("Savepoint failure"))

            config = OrchestratorConfig(
                host_id=host_uuid,
                user_provider=lambda: [(9001, "leak_user")],
                fs_backend=DummyMockBackend(),
            )
            orchestrator = CollectorOrchestrator(config, session=ext_session)
            res = orchestrator.run_cycle(force_all=True)

            assert res.success is False
            assert "transaction" in res.sink_errors
            assert "Savepoint error" in res.sink_errors["transaction"]

            # Verify no entities were flushed into the external session
            assert ext_session.query(LinuxUser).filter_by(uid=9001).first() is None
            assert len(ext_session.dirty) == 0
            assert len(ext_session.new) == 0
        finally:
            ext_session.close()

    def test_external_session_remains_usable_after_cycle_flush_error(self, isolated_db):
        """External session's outer transaction can still commit after an inner cycle savepoint error."""
        engine, host_uuid = isolated_db
        ext_session = Session(engine)
        try:
            # Caller starts an outer transaction
            t0 = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
            caller_user = LinuxUser(
                id=uuid.uuid4(),
                host_id=host_uuid,
                uid=8888,
                username="outer_caller_user",
                first_seen_at=t0,
            )
            ext_session.add(caller_user)

            # Configure orchestrator with external session
            config = OrchestratorConfig(
                host_id=host_uuid,
                user_provider=lambda: [(7777, "inner_cycle_user")],
                wall_clock=lambda: t0,
                fs_backend=DummyMockBackend(),
            )
            orchestrator = CollectorOrchestrator(config, session=ext_session)

            # Cycle fails due to an event persistence foreign key or integrity failure
            bad_obs = RawObservation(
                source="proc",
                host_id=host_uuid,
                event_type="process.start",
                action="start",
                severity="info",
                observed_at=t0,
                uid=7777,
                pid=7777,
                command="/bin/fail",
                object_type="process",
            )
            orchestrator.process_collector.collect_observations = lambda diff=True: [bad_obs]
            orchestrator.resource_collector.collect_observations = lambda **kw: []
            orchestrator.filesystem_collector.collect_observations = lambda: []

            # Mock repository to trigger an IntegrityError during save_batch flush
            from sqlalchemy.exc import IntegrityError
            failing_repo = EventRepository(session=ext_session)
            failing_repo.save_batch = MagicMock(
                side_effect=IntegrityError("INSERT", {}, Exception("Duplicate key"))
            )
            orchestrator.repository = failing_repo

            res = orchestrator.run_cycle(force_all=True)
            assert res.success is False
            assert "repository" in res.sink_errors

            # The cycle's savepoint must be rolled back, and the external session must REMAIN USABLE!
            # The caller can now commit their outer transaction without PendingRollbackError!
            ext_session.commit()

            # Verify caller_user was committed while inner_cycle_user was rolled back
            with Session(engine) as verify_s:
                cu = verify_s.execute(select(LinuxUser).where(LinuxUser.uid == 8888)).scalar_one_or_none()
                assert cu is not None
                assert cu.username == "outer_caller_user"

                iu = verify_s.execute(select(LinuxUser).where(LinuxUser.uid == 7777)).scalar_one_or_none()
                assert iu is None, "Failed cycle user must be rolled back"
        finally:
            ext_session.close()

    def test_pid_reuse_across_consecutive_cycles(self, isolated_db):
        """PID reuse across multiple cycles is correctly resolved and transactionally isolated."""
        engine, host_uuid = isolated_db
        session_factory = sessionmaker(bind=engine)
        t0 = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        t1 = t0 + timedelta(seconds=1)
        t2 = t0 + timedelta(seconds=2)
        t3 = t0 + timedelta(seconds=3)

        config = OrchestratorConfig(
            host_id=host_uuid,
            session_factory=session_factory,
            user_provider=lambda: [(1050, "pid_reuse_user")],
            wall_clock=lambda: t0,
            fs_backend=DummyMockBackend(),
        )
        orchestrator = CollectorOrchestrator(config)

        # ── Cycle 1: PID 7500 starts ──
        obs1 = RawObservation(
            source="proc",
            host_id=host_uuid,
            event_type="process.start",
            action="start",
            severity="info",
            observed_at=t0,
            uid=1050,
            pid=7500,
            command="/bin/first_proc",
            object_type="process",
        )
        orchestrator.process_collector.collect_observations = lambda diff=True: [obs1]
        orchestrator.resource_collector.collect_observations = lambda **kw: []
        orchestrator.filesystem_collector.collect_observations = lambda: []

        r1 = orchestrator.run_cycle(force_all=True)
        assert r1.success is True
        proc1_id = r1.events[0].process_id
        assert proc1_id is not None

        # ── Cycle 2: PID 7500 ends and re-starts as second_proc ──
        obs_exit = RawObservation(
            source="proc",
            host_id=host_uuid,
            event_type="process.end",
            action="exit",
            severity="info",
            observed_at=t1,
            uid=1050,
            pid=7500,
            command="/bin/first_proc",
            object_type="process",
        )
        obs_start = RawObservation(
            source="proc",
            host_id=host_uuid,
            event_type="process.start",
            action="start",
            severity="info",
            observed_at=t2,
            uid=1050,
            pid=7500,
            command="/bin/second_proc",
            object_type="process",
        )
        # Process collector returns unordered observations
        orchestrator.process_collector.collect_observations = lambda diff=True: [obs_start, obs_exit]

        r2 = orchestrator.run_cycle(force_all=True)
        assert r2.success is True
        assert len(r2.events) == 2

        # Verify process IDs: exit resolves to proc1_id, start resolves to new proc2_id
        start_ev = next(e for e in r2.events if e.event_type == "process.start")
        end_ev = next(e for e in r2.events if e.event_type == "process.end")
        assert end_ev.process_id == proc1_id
        assert start_ev.process_id is not None
        assert start_ev.process_id != proc1_id
        proc2_id = start_ev.process_id

        # ── Cycle 3: Failure rolls back without affecting Cycle 1 & 2 ──
        obs_fail = RawObservation(
            source="proc",
            host_id=host_uuid,
            event_type="process.start",
            action="start",
            severity="info",
            observed_at=t3,
            uid=1050,
            pid=7500,
            command="/bin/third_failing_proc",
            object_type="process",
        )
        orchestrator.process_collector.collect_observations = lambda diff=True: [obs_fail]
        orchestrator.repository.save_batch = MagicMock(side_effect=RuntimeError("Disk failure"))

        r3 = orchestrator.run_cycle(force_all=True)
        assert r3.success is False

        # Verify DB state: exactly 2 processes committed, 3rd process rolled back
        with session_factory() as s:
            procs = s.execute(
                select(Process).where(Process.host_id == host_uuid, Process.pid == 7500).order_by(Process.started_at)
            ).scalars().all()
            assert len(procs) == 2
            assert procs[0].id == proc1_id
            assert procs[0].command == "/bin/first_proc"
            assert procs[0].ended_at is not None
            assert procs[1].id == proc2_id
            assert procs[1].command == "/bin/second_proc"
            assert procs[1].ended_at is None

    def test_entity_flush_failure_does_not_query_aborted_session(self, isolated_db):
        """Entity flush failure does not query the aborted session and rolls back cleanly."""
        engine, host_uuid = isolated_db
        session_factory = sessionmaker(bind=engine)
        t0 = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

        # Mock user synchronizer to trigger a flush failure
        mock_sync = MagicMock()
        mock_sync.sync_users.side_effect = IntegrityError(
            "INSERT INTO linux_users", {}, Exception("User sync flush error")
        )

        config = OrchestratorConfig(
            host_id=host_uuid,
            session_factory=session_factory,
            wall_clock=lambda: t0,
            fs_backend=DummyMockBackend(),
        )
        orchestrator = CollectorOrchestrator(
            config,
            user_synchronizer=mock_sync,
        )

        obs = RawObservation(
            source="proc",
            host_id=host_uuid,
            event_type="process.start",
            action="start",
            severity="info",
            observed_at=t0,
            uid=1055,
            pid=7555,
            command="/bin/flush_fail",
            object_type="process",
        )
        orchestrator.process_collector.collect_observations = lambda diff=True: [obs]
        orchestrator.resource_collector.collect_observations = lambda **kw: []
        orchestrator.filesystem_collector.collect_observations = lambda: []

        # Spy on process lifecycle service to verify it is NOT called after user sync flush error
        orchestrator.process_lifecycle_service.apply_observations = MagicMock()

        res = orchestrator.run_cycle(force_all=True)

        assert res.success is False
        assert "user_sync" in res.sink_errors
        # Process lifecycle service must NOT have been called on the aborted transaction
        assert orchestrator.process_lifecycle_service.apply_observations.call_count == 0
        # Session must be closed
        assert orchestrator.session is None

    def test_commit_failure_cleans_caches_and_closes_session(self, isolated_db):
        """Commit failure rolls back changes, clears identity caches, and closes session."""
        engine, host_uuid = isolated_db
        t0 = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

        closed_sessions = []
        rolled_back_sessions = []

        def custom_factory():
            s = Session(engine)
            orig_rollback = s.rollback
            orig_close = s.close

            def failing_commit():
                raise RuntimeError("Disk flush I/O error on commit")

            def tracking_rollback():
                rolled_back_sessions.append(s)
                return orig_rollback()

            def tracking_close():
                closed_sessions.append(s)
                return orig_close()

            s.commit = failing_commit
            s.rollback = tracking_rollback
            s.close = tracking_close
            return s

        config = OrchestratorConfig(
            host_id=host_uuid,
            session_factory=custom_factory,
            user_provider=lambda: [(1060, "tx_commit_fail_user")],
            wall_clock=lambda: t0,
            fs_backend=DummyMockBackend(),
        )
        callback_mock = MagicMock()
        orchestrator = CollectorOrchestrator(
            config,
            event_callback=callback_mock,
        )

        obs = RawObservation(
            source="proc",
            host_id=host_uuid,
            event_type="process.start",
            action="start",
            severity="info",
            observed_at=t0,
            uid=1060,
            pid=7560,
            command="/bin/commit_fail_proc",
            object_type="process",
        )
        orchestrator.process_collector.collect_observations = lambda diff=True: [obs]
        orchestrator.resource_collector.collect_observations = lambda **kw: []
        orchestrator.filesystem_collector.collect_observations = lambda: []

        res = orchestrator.run_cycle(force_all=True)

        assert res.success is False
        assert "transaction" in res.sink_errors
        assert "Disk flush I/O error on commit" in res.sink_errors["transaction"]

        # Session was rolled back and closed
        assert len(rolled_back_sessions) == 1
        assert len(closed_sessions) == 1
        assert orchestrator.session is None

        # Callback must NOT be invoked when commit fails
        assert callback_mock.call_count == 0
        # Total events must NOT increment
        assert orchestrator.get_status()["total_events"] == 0

        # Identity caches cleared
        assert len(orchestrator.resolver._user_cache) == 0
        assert len(orchestrator.resolver._process_cache) == 0

        # DB has no committed rows
        with Session(engine) as verify_s:
            user = verify_s.execute(
                select(LinuxUser).where(LinuxUser.uid == 1060)
            ).scalar_one_or_none()
            assert user is None

    def test_rollback_failure_preserves_original_error_and_cleans_up(self, isolated_db):
        """Rollback failure preserves the original sink error, reports rollback error, and attempts cleanup."""
        engine, host_uuid = isolated_db
        t0 = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

        closed_sessions = []

        def custom_factory():
            s = Session(engine)
            orig_close = s.close

            def failing_rollback():
                raise RuntimeError("Secondary rollback network disconnect")

            def tracking_close():
                closed_sessions.append(s)
                return orig_close()

            s.rollback = failing_rollback
            s.close = tracking_close
            return s

        config = OrchestratorConfig(
            host_id=host_uuid,
            session_factory=custom_factory,
            user_provider=lambda: [(1070, "tx_rollback_fail_user")],
            wall_clock=lambda: t0,
            fs_backend=DummyMockBackend(),
        )
        failing_repo = EventRepository(session=None)
        failing_repo.save_batch = MagicMock(
            side_effect=RuntimeError("Primary repository database error")
        )

        orchestrator = CollectorOrchestrator(
            config,
            event_repository=failing_repo,
        )

        obs = RawObservation(
            source="proc",
            host_id=host_uuid,
            event_type="process.start",
            action="start",
            severity="info",
            observed_at=t0,
            uid=1070,
            pid=7570,
            command="/bin/rollback_fail_proc",
            object_type="process",
        )
        orchestrator.process_collector.collect_observations = lambda diff=True: [obs]
        orchestrator.resource_collector.collect_observations = lambda **kw: []
        orchestrator.filesystem_collector.collect_observations = lambda: []

        res = orchestrator.run_cycle(force_all=True)

        assert res.success is False
        # Primary error is preserved
        assert "repository" in res.sink_errors
        assert "Primary repository database error" in res.sink_errors["repository"]
        # Rollback error is reported without masking primary error
        assert "rollback" in res.sink_errors
        assert "Secondary rollback network disconnect" in res.sink_errors["rollback"]

        # Cleanup still attempted: session closed and caches cleared
        assert len(closed_sessions) == 1
        assert orchestrator.session is None

    def test_collector_failure_with_healthy_observations_persists_valid_writes(self, isolated_db):
        """Collector health failure alone does not force rollback of valid database writes."""
        engine, host_uuid = isolated_db
        session_factory = sessionmaker(bind=engine)
        t0 = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

        config = OrchestratorConfig(
            host_id=host_uuid,
            session_factory=session_factory,
            user_provider=lambda: [(1080, "tx_collector_fail_user")],
            wall_clock=lambda: t0,
            fs_backend=DummyMockBackend(),
        )
        orchestrator = CollectorOrchestrator(config)

        # Filesystem collector raises an error
        orchestrator.filesystem_collector.collect_observations = MagicMock(
            side_effect=RuntimeError("Inotify queue overflow")
        )
        # Process collector produces valid observation
        proc_obs = RawObservation(
            source="proc",
            host_id=host_uuid,
            event_type="process.start",
            action="start",
            severity="info",
            observed_at=t0,
            uid=1080,
            pid=7580,
            command="/bin/surviving_proc",
            object_type="process",
        )
        orchestrator.process_collector.collect_observations = lambda diff=True: [proc_obs]
        orchestrator.resource_collector.collect_observations = lambda **kw: []

        callback_events = []
        orchestrator.callback = lambda evs: callback_events.extend(evs)

        res = orchestrator.run_cycle(force_all=True)

        # Cycle reports degraded status due to collector error
        assert res.success is False
        assert "fs" in res.collector_errors
        assert "Inotify queue overflow" in res.collector_errors["fs"]
        assert not res.sink_errors
        assert not res.processing_errors

        # But valid observations persisted and committed!
        assert len(res.events) == 1
        assert res.events[0].process_id is not None
        assert orchestrator.get_status()["total_events"] == 1
        assert len(callback_events) == 1

        # Verify database state in a fresh session
        with session_factory() as verify_s:
            user = verify_s.execute(
                select(LinuxUser).where(LinuxUser.host_id == host_uuid, LinuxUser.uid == 1080)
            ).scalar_one_or_none()
            assert user is not None
            assert user.username == "tx_collector_fail_user"

            proc = verify_s.execute(
                select(Process).where(Process.host_id == host_uuid, Process.pid == 7580)
            ).scalar_one_or_none()
            assert proc is not None
            assert proc.command == "/bin/surviving_proc"

            ev = verify_s.execute(
                select(Event).where(Event.host_id == host_uuid)
            ).scalar_one_or_none()
            assert ev is not None
            assert ev.process_id == proc.id

    def test_callback_not_invoked_before_commit_and_skipped_on_commit_failure(self, isolated_db):
        """Callback is never invoked before commit, and is not called if commit fails."""
        engine, host_uuid = isolated_db
        t0 = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

        events_order = []

        def failing_commit_factory():
            s = Session(engine)

            def failing_commit():
                events_order.append("commit_attempt")
                raise RuntimeError("Commit aborted")

            s.commit = failing_commit
            return s

        def callback(events):
            events_order.append("callback_invoked")

        config = OrchestratorConfig(
            host_id=host_uuid,
            session_factory=failing_commit_factory,
            user_provider=lambda: [(1085, "callback_order_user")],
            wall_clock=lambda: t0,
            fs_backend=DummyMockBackend(),
        )
        orchestrator = CollectorOrchestrator(config, event_callback=callback)

        obs = RawObservation(
            source="proc",
            host_id=host_uuid,
            event_type="process.start",
            action="start",
            severity="info",
            observed_at=t0,
            uid=1085,
            pid=7585,
            command="/bin/callback_order_proc",
            object_type="process",
        )
        orchestrator.process_collector.collect_observations = lambda diff=True: [obs]
        orchestrator.resource_collector.collect_observations = lambda **kw: []
        orchestrator.filesystem_collector.collect_observations = lambda: []

        res = orchestrator.run_cycle(force_all=True)
        assert res.success is False
        assert "transaction" in res.sink_errors
        assert events_order == ["commit_attempt"]
        assert "callback_invoked" not in events_order

    def test_callback_failure_after_commit_preserves_persisted_data(self, isolated_db):
        """Callback failure after successful commit preserves persisted database records."""
        engine, host_uuid = isolated_db
        session_factory = sessionmaker(bind=engine)
        t0 = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

        def failing_callback(events):
            raise RuntimeError("Downstream webhook connection refused")

        config = OrchestratorConfig(
            host_id=host_uuid,
            session_factory=session_factory,
            user_provider=lambda: [(1090, "tx_callback_fail_user")],
            wall_clock=lambda: t0,
            fs_backend=DummyMockBackend(),
        )
        orchestrator = CollectorOrchestrator(
            config,
            event_callback=failing_callback,
        )

        obs = RawObservation(
            source="proc",
            host_id=host_uuid,
            event_type="process.start",
            action="start",
            severity="info",
            observed_at=t0,
            uid=1090,
            pid=7590,
            command="/bin/callback_fail_proc",
            object_type="process",
        )
        orchestrator.process_collector.collect_observations = lambda diff=True: [obs]
        orchestrator.resource_collector.collect_observations = lambda **kw: []
        orchestrator.filesystem_collector.collect_observations = lambda: []

        res = orchestrator.run_cycle(force_all=True)

        assert res.success is False
        assert "callback" in res.sink_errors
        assert "Downstream webhook connection refused" in res.sink_errors["callback"]
        assert len(res.events) == 1

        # Even though callback failed, database commit succeeded and data is preserved!
        with session_factory() as verify_s:
            user = verify_s.execute(
                select(LinuxUser).where(LinuxUser.host_id == host_uuid, LinuxUser.uid == 1090)
            ).scalar_one_or_none()
            assert user is not None
            assert user.username == "tx_callback_fail_user"

            proc = verify_s.execute(
                select(Process).where(Process.host_id == host_uuid, Process.pid == 7590)
            ).scalar_one_or_none()
            assert proc is not None

            ev = verify_s.execute(
                select(Event).where(Event.host_id == host_uuid)
            ).scalar_one_or_none()
            assert ev is not None

        # Total events count was incremented because commit succeeded
        assert orchestrator.get_status()["total_events"] == 1

    def test_persisted_event_totals_change_only_after_successful_commit(self, isolated_db):
        """_total_events increments only for events whose database persistence committed successfully."""
        engine, host_uuid = isolated_db
        session_factory = sessionmaker(bind=engine)
        t0 = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

        config = OrchestratorConfig(
            host_id=host_uuid,
            session_factory=session_factory,
            user_provider=lambda: [(1095, "tx_totals_user")],
            wall_clock=lambda: t0,
            fs_backend=DummyMockBackend(),
        )
        orchestrator = CollectorOrchestrator(config)
        assert orchestrator.get_status()["total_events"] == 0

        # Cycle 1: Success -> _total_events becomes 1
        obs1 = RawObservation(
            source="proc",
            host_id=host_uuid,
            event_type="process.start",
            action="start",
            severity="info",
            observed_at=t0,
            uid=1095,
            pid=7595,
            command="/bin/totals_proc_1",
            object_type="process",
        )
        orchestrator.process_collector.collect_observations = lambda diff=True: [obs1]
        orchestrator.resource_collector.collect_observations = lambda **kw: []
        orchestrator.filesystem_collector.collect_observations = lambda: []

        r1 = orchestrator.run_cycle(force_all=True)
        assert r1.success is True
        assert orchestrator.get_status()["total_events"] == 1

        # Cycle 2: Repository failure -> _total_events remains 1
        orchestrator.repository.save_batch = MagicMock(side_effect=RuntimeError("Disk full"))
        obs2 = RawObservation(
            source="proc",
            host_id=host_uuid,
            event_type="process.start",
            action="start",
            severity="info",
            observed_at=t0 + timedelta(seconds=1),
            uid=1095,
            pid=7596,
            command="/bin/totals_proc_2",
            object_type="process",
        )
        orchestrator.process_collector.collect_observations = lambda diff=True: [obs2]

        r2 = orchestrator.run_cycle(force_all=True)
        assert r2.success is False
        assert orchestrator.get_status()["total_events"] == 1

        # Cycle 3: Restore repository -> success -> _total_events becomes 2
        del orchestrator.repository.save_batch
        r3 = orchestrator.run_cycle(force_all=True)
        assert r3.success is True
        assert orchestrator.get_status()["total_events"] == 2

    def test_collector_known_processes_restored_on_database_rollback(self, isolated_db):
        """Database failure restores ProcessCollector._known_processes so observations are re-emitted next cycle."""
        engine, host_uuid = isolated_db
        session_factory = sessionmaker(bind=engine)
        t0 = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

        config = OrchestratorConfig(
            host_id=host_uuid,
            session_factory=session_factory,
            user_provider=lambda: [(1099, "tx_state_restore_user")],
            wall_clock=lambda: t0,
            fs_backend=DummyMockBackend(),
        )
        orchestrator = CollectorOrchestrator(config)
        orchestrator.resource_collector.collect_observations = lambda **kw: []

        # Real ProcessCollector behavior with mock proc data
        proc_data = [
            {
                "pid": 8800,
                "ppid": 1,
                "uid": 1099,
                "command": "/bin/daemon_a",
                "starttime": 100,
                "executable": "/bin/daemon_a",
                "state": "S",
                "comm": "daemon_a",
            }
        ]
        orchestrator.process_collector.collect = lambda: proc_data

        # Force failure in repository during cycle 1
        orchestrator.repository.save_batch = MagicMock(
            side_effect=RuntimeError("Database write error")
        )

        r1 = orchestrator.run_cycle(force_all=True)
        assert r1.success is False

        # In DB, daemon_a was rolled back
        with session_factory() as s:
            p = s.execute(select(Process).where(Process.pid == 8800)).scalar_one_or_none()
            assert p is None

        # Because _known_processes was restored, Cycle 2 re-observes daemon_a as a new process!
        del orchestrator.repository.save_batch
        r2 = orchestrator.run_cycle(force_all=True)
        assert r2.success is True
        assert len(r2.events) == 1
        assert r2.events[0].event_type == "process.start"

        # Now daemon_a is successfully committed to DB!
        with session_factory() as s:
            p = s.execute(select(Process).where(Process.pid == 8800)).scalar_one_or_none()
            assert p is not None
            assert p.command == "/bin/daemon_a"

    def test_savepoint_rollback_failure_does_not_abort_outer_session(self, isolated_db):
        """Savepoint rollback failure logs error without executing outer session rollback."""
        engine, host_uuid = isolated_db
        ext_session = Session(engine)
        try:
            t0 = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
            caller_user = LinuxUser(
                id=uuid.uuid4(),
                host_id=host_uuid,
                uid=9911,
                username="outer_savepoint_user",
                first_seen_at=t0,
            )
            ext_session.add(caller_user)

            config = OrchestratorConfig(
                host_id=host_uuid,
                user_provider=lambda: [(9912, "inner_savepoint_user")],
                wall_clock=lambda: t0,
                fs_backend=DummyMockBackend(),
            )
            orchestrator = CollectorOrchestrator(config, session=ext_session)

            # Spy on ext_session.rollback: must NOT be called!
            real_rollback = ext_session.rollback
            rollback_spy = MagicMock(side_effect=real_rollback)
            ext_session.rollback = rollback_spy

            # Inner cycle fails
            orchestrator.repository.save_batch = MagicMock(
                side_effect=RuntimeError("Inner repo failure")
            )
            obs = RawObservation(
                source="proc",
                host_id=host_uuid,
                event_type="process.start",
                action="start",
                severity="info",
                observed_at=t0,
                uid=9912,
                pid=9912,
                command="/bin/sp_fail",
                object_type="process",
            )
            orchestrator.process_collector.collect_observations = lambda diff=True: [obs]
            orchestrator.resource_collector.collect_observations = lambda **kw: []
            orchestrator.filesystem_collector.collect_observations = lambda: []

            res = orchestrator.run_cycle(force_all=True)
            assert res.success is False
            assert (
                rollback_spy.call_count == 0
            ), "Outer session.rollback() must never be called on external session"
        finally:
            ext_session.close()

    def test_process_lifecycle_flush_failure_does_not_query_aborted_session(self, isolated_db):
        """Process lifecycle flush failure stops subsequent processing, does not query aborted session, and rolls back cleanly."""
        engine, host_uuid = isolated_db
        session_factory = sessionmaker(bind=engine)
        t0 = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

        mock_lifecycle = MagicMock()
        mock_lifecycle.apply_observations.side_effect = IntegrityError(
            "INSERT INTO processes", {}, Exception("Process lifecycle entity flush error")
        )

        config = OrchestratorConfig(
            host_id=host_uuid,
            session_factory=session_factory,
            user_provider=lambda: [(1056, "lifecycle_flush_user")],
            wall_clock=lambda: t0,
            fs_backend=DummyMockBackend(),
        )
        orchestrator = CollectorOrchestrator(
            config,
            process_lifecycle_service=mock_lifecycle,
        )

        obs = RawObservation(
            source="proc",
            host_id=host_uuid,
            event_type="process.start",
            action="start",
            severity="info",
            observed_at=t0,
            uid=1056,
            pid=7556,
            command="/bin/proc_flush_fail",
            object_type="process",
        )
        orchestrator.process_collector.collect_observations = lambda diff=True: [obs]
        orchestrator.resource_collector.collect_observations = lambda **kw: []
        orchestrator.filesystem_collector.collect_observations = lambda: []

        # Spy on event processor: must NOT process batch after process lifecycle flush error
        orchestrator.processor.process_batch = MagicMock()

        res = orchestrator.run_cycle(force_all=True)

        assert res.success is False
        assert "process_lifecycle" in res.sink_errors
        assert orchestrator.processor.process_batch.call_count == 0
        assert orchestrator.session is None
        assert len(res.events) == 0

        # Verify database rollback: user was not committed
        with session_factory() as verify_s:
            user = verify_s.execute(
                select(LinuxUser).where(LinuxUser.host_id == host_uuid, LinuxUser.uid == 1056)
            ).scalar_one_or_none()
            assert user is None

    def test_external_session_begin_nested_pre_flush_behavior(self, isolated_db):
        """Verify session.begin_nested() pre-flush contract: caller pending changes are flushed into outer transaction."""
        engine, host_uuid = isolated_db
        ext_session = Session(engine)
        try:
            t0 = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
            caller_user = LinuxUser(
                id=uuid.uuid4(),
                host_id=host_uuid,
                uid=9950,
                username="pre_flush_caller_user",
                first_seen_at=t0,
            )
            # Add but do NOT flush
            ext_session.add(caller_user)
            assert caller_user in ext_session.new

            config = OrchestratorConfig(
                host_id=host_uuid,
                user_provider=lambda: [(9951, "cycle_user")],
                wall_clock=lambda: t0,
                fs_backend=DummyMockBackend(),
            )
            orchestrator = CollectorOrchestrator(config, session=ext_session)

            # Force failure in repository during cycle
            orchestrator.repository.save_batch = MagicMock(
                side_effect=RuntimeError("Inner repo failure")
            )
            obs = RawObservation(
                source="proc",
                host_id=host_uuid,
                event_type="process.start",
                action="start",
                severity="info",
                observed_at=t0,
                uid=9951,
                pid=9951,
                command="/bin/preflush_proc",
                object_type="process",
            )
            orchestrator.process_collector.collect_observations = lambda diff=True: [obs]
            orchestrator.resource_collector.collect_observations = lambda **kw: []
            orchestrator.filesystem_collector.collect_observations = lambda: []

            res = orchestrator.run_cycle(force_all=True)
            assert res.success is False

            # Outer caller's user was pre-flushed by begin_nested() and survived savepoint rollback
            # Now caller can commit their outer transaction!
            ext_session.commit()

            with Session(engine) as verify_s:
                cu = verify_s.execute(
                    select(LinuxUser).where(LinuxUser.uid == 9950)
                ).scalar_one_or_none()
                assert cu is not None
                assert cu.username == "pre_flush_caller_user"

                iu = verify_s.execute(
                    select(LinuxUser).where(LinuxUser.uid == 9951)
                ).scalar_one_or_none()
                assert iu is None, "Inner cycle user must have rolled back with the savepoint"
        finally:
            ext_session.close()

    def test_external_session_savepoint_commit_failure_isolates_outer_session(self, isolated_db):
        """Savepoint commit failure on external session rolls back savepoint without calling outer session rollback."""
        engine, host_uuid = isolated_db
        ext_session = Session(engine)
        try:
            t0 = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
            caller_user = LinuxUser(
                id=uuid.uuid4(),
                host_id=host_uuid,
                uid=9960,
                username="sp_commit_fail_caller",
                first_seen_at=t0,
            )
            ext_session.add(caller_user)

            config = OrchestratorConfig(
                host_id=host_uuid,
                user_provider=lambda: [(9961, "sp_commit_fail_cycle_user")],
                wall_clock=lambda: t0,
                fs_backend=DummyMockBackend(),
            )
            orchestrator = CollectorOrchestrator(config, session=ext_session)

            real_begin_nested = ext_session.begin_nested
            def failing_savepoint():
                sp = real_begin_nested()
                def fail_commit():
                    raise RuntimeError("Savepoint commit failed at disk flush")
                sp.commit = fail_commit
                return sp

            ext_session.begin_nested = failing_savepoint

            real_rollback = ext_session.rollback
            rollback_spy = MagicMock(side_effect=real_rollback)
            ext_session.rollback = rollback_spy

            obs = RawObservation(
                source="proc",
                host_id=host_uuid,
                event_type="process.start",
                action="start",
                severity="info",
                observed_at=t0,
                uid=9961,
                pid=9961,
                command="/bin/sp_commit_fail_proc",
                object_type="process",
            )
            orchestrator.process_collector.collect_observations = lambda diff=True: [obs]
            orchestrator.resource_collector.collect_observations = lambda **kw: []
            orchestrator.filesystem_collector.collect_observations = lambda: []

            res = orchestrator.run_cycle(force_all=True)
            assert res.success is False
            assert "transaction" in res.sink_errors
            assert "Savepoint commit error" in res.sink_errors["transaction"]
            assert rollback_spy.call_count == 0, "Outer session rollback must not be called"

            # Caller can still commit their outer transaction
            ext_session.commit()
            with Session(engine) as verify_s:
                cu = verify_s.execute(
                    select(LinuxUser).where(LinuxUser.uid == 9960)
                ).scalar_one_or_none()
                assert cu is not None
        finally:
            ext_session.close()

    def test_unexpected_fatal_exception_returns_failure_result(self, isolated_db):
        """Unexpected exception in run_cycle returns meaningful failure result instead of leaking to caller."""
        engine, host_uuid = isolated_db
        session_factory = sessionmaker(bind=engine)
        t0 = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

        config = OrchestratorConfig(
            host_id=host_uuid,
            session_factory=session_factory,
            wall_clock=lambda: t0,
            fs_backend=DummyMockBackend(),
        )
        orchestrator = CollectorOrchestrator(config)

        # Inject an unexpected exception during session binding
        orchestrator._bind_session = MagicMock(side_effect=RuntimeError("Catastrophic connection pool blowout"))

        res = orchestrator.run_cycle(force_all=True)

        assert res.success is False
        assert "fatal" in res.sink_errors
        assert "Catastrophic connection pool blowout" in res.sink_errors["fatal"]
        assert orchestrator.session is None

    def test_collector_timing_restored_to_none_on_initial_cycle_rollback(self, isolated_db):
        """When initial collection cycle fails and rolls back, _last_process_time and _last_resource_time revert to None."""
        engine, host_uuid = isolated_db
        session_factory = sessionmaker(bind=engine)
        t0 = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

        config = OrchestratorConfig(
            host_id=host_uuid,
            session_factory=session_factory,
            user_provider=lambda: [(1097, "timing_user")],
            wall_clock=lambda: t0,
            fs_backend=DummyMockBackend(),
        )
        orchestrator = CollectorOrchestrator(config)

        assert orchestrator._last_process_time is None
        assert orchestrator._last_resource_time is None

        # Force failure in repository during cycle 1
        orchestrator.repository.save_batch = MagicMock(
            side_effect=RuntimeError("Disk failure during initial cycle")
        )

        obs = RawObservation(
            source="proc",
            host_id=host_uuid,
            event_type="process.start",
            action="start",
            severity="info",
            observed_at=t0,
            uid=1097,
            pid=7597,
            command="/bin/timing_proc",
            object_type="process",
        )
        orchestrator.process_collector.collect_observations = lambda diff=True: [obs]

        res = orchestrator.run_cycle(force_all=True)
        assert res.success is False

        # Timing states must revert to None so the next non-forced cycle runs immediately
        assert orchestrator._last_process_time is None
        assert orchestrator._last_resource_time is None
