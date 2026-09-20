"""Unit tests for the OSIRIS Collector Orchestrator.

Tests run deterministically on any operating system (including macOS)
using mock collectors, injected fake clocks, and temporary filesystem paths.
"""

from __future__ import annotations

import threading
import time
import uuid
from datetime import datetime, timezone
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

