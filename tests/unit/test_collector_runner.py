"""Unit tests for the OSIRIS Standalone Collector Runner.

Verifies:
1. CLI argument parsing and validation semantics (L-1 contract).
2. Deterministic execution behavior (bounded, single-cycle, continuous with signals).
3. Degraded cycle handling with accurate healthy event accounting.
4. M-4 database session isolation contract (caller-owned vs orchestrator-owned).
5. Clean decoupling from the FastAPI web application lifespan.
"""

from __future__ import annotations

import logging
import signal
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy.orm import Session

from backend.config import settings
from backend.main import app, lifespan
from backend.services.events.schemas import NormalizedEvent
from collectors.orchestrator import (
    CollectorOrchestrator,
    CollectorStartupError,
    CycleResult,
    OrchestratorConfig,
    OrchestratorState,
    resolve_host_uuid,
)
from collectors.runner import (
    CollectorRunner,
    create_parser,
    main,
    parse_args,
    validate_args,
)

TEST_HOST_UUID = uuid.UUID("11111111-1111-4111-8111-111111111111")


def make_dummy_event(
    event_type: str = "process.start",
    host_id: uuid.UUID = TEST_HOST_UUID,
) -> NormalizedEvent:
    """Create a minimal valid NormalizedEvent for runner tests."""
    return NormalizedEvent(
        id=uuid.uuid4(),
        host_id=host_id,
        timestamp=datetime.now(timezone.utc),
        ingested_at=datetime.now(timezone.utc),
        source="proc",
        event_type=event_type,
        action="start",
        severity="info",
        payload={"pid": 1234, "comm": "test"},
    )


# ========================================================================
# 1. HOST UUID RESOLUTION TESTS
# ========================================================================


class TestHostUuidResolution:
    def test_resolve_uuid_instance(self):
        uid = uuid.UUID("12345678-1234-5678-1234-567812345678")
        assert resolve_host_uuid(uid) == uid

    def test_resolve_valid_uuid_string(self):
        raw = "12345678-1234-5678-1234-567812345678"
        expected = uuid.UUID(raw)
        assert resolve_host_uuid(raw) == expected

    def test_resolve_valid_uuid_string_without_hyphens(self):
        raw = "12345678123456781234567812345678"
        expected = uuid.UUID(raw)
        assert resolve_host_uuid(raw) == expected

    def test_resolve_non_uuid_hostname_string(self):
        hostname = "osiris-dev-host"
        resolved = resolve_host_uuid(hostname)
        assert isinstance(resolved, uuid.UUID)
        expected = uuid.uuid5(uuid.NAMESPACE_DNS, hostname)
        assert resolved == expected

    def test_resolve_deterministic_and_unique(self):
        id1 = resolve_host_uuid("osiris-dev-host")
        id2 = resolve_host_uuid("osiris-dev-host")
        id3 = resolve_host_uuid("osiris-prod-worker-1")
        assert id1 == id2
        assert id1 != id3

    def test_resolve_strips_whitespace(self):
        assert resolve_host_uuid("  osiris-dev-host  ") == resolve_host_uuid("osiris-dev-host")


# ========================================================================
# 2. CLI ARGUMENT PARSING & VALIDATION TESTS
# ========================================================================


class TestCliArgumentParsing:
    def test_default_arguments(self):
        args = parse_args([])
        assert args.once is False
        assert args.cycles is None
        assert args.watch is True
        assert args.interval == 2.0
        assert args.host_id == settings.host_id
        assert args.proc_dir is None
        assert args.passwd_file is None
        assert args.watch_paths == []

    def test_once_mode(self):
        args = parse_args(["--once"])
        assert args.once is True
        assert args.watch is False
        assert args.cycles is None

    def test_cycles_mode(self):
        args1 = parse_args(["--cycles", "1"])
        assert args1.cycles == 1
        assert args1.watch is False

        args5 = parse_args(["--cycles", "5"])
        assert args5.cycles == 5
        assert args5.watch is False

    def test_custom_interval(self):
        args = parse_args(["--interval", "2.5"])
        assert args.interval == 2.5

    def test_custom_host_id(self):
        custom_id = "test-agent-host-01"
        args = parse_args(["--host-id", custom_id])
        assert args.host_id == custom_id

    def test_custom_proc_and_passwd_and_watch_paths(self):
        args = parse_args([
            "--proc-dir", "/custom/proc",
            "--passwd-file", "/custom/passwd",
            "--watch-path", "/var/log",
            "--watch-path", "/etc",
        ])
        assert args.proc_dir == "/custom/proc"
        assert args.passwd_file == "/custom/passwd"
        assert args.watch_paths == ["/var/log", "/etc"]

    def test_rejection_invalid_cycles_zero(self):
        with pytest.raises(SystemExit) as exc:
            parse_args(["--cycles", "0"])
        assert exc.value.code == 2

    def test_rejection_invalid_cycles_negative(self):
        with pytest.raises(SystemExit) as exc:
            parse_args(["--cycles", "-1"])
        assert exc.value.code == 2

    def test_rejection_invalid_interval_zero(self):
        with pytest.raises(SystemExit) as exc:
            parse_args(["--interval", "0"])
        assert exc.value.code == 2

    def test_rejection_invalid_interval_negative(self):
        with pytest.raises(SystemExit) as exc:
            parse_args(["--interval", "-2.0"])
        assert exc.value.code == 2

    def test_rejection_invalid_interval_non_finite(self):
        with pytest.raises(SystemExit) as exc:
            parse_args(["--interval", "inf"])
        assert exc.value.code == 2

        with pytest.raises(SystemExit) as exc:
            parse_args(["--interval", "nan"])
        assert exc.value.code == 2

    def test_rejection_conflicting_once_and_watch(self):
        with pytest.raises(SystemExit) as exc:
            parse_args(["--once", "--watch"])
        assert exc.value.code == 2

    def test_rejection_conflicting_cycles_and_watch(self):
        with pytest.raises(SystemExit) as exc:
            parse_args(["--cycles", "5", "--watch"])
        assert exc.value.code == 2

    def test_rejection_conflicting_once_and_cycles_not_one(self):
        with pytest.raises(SystemExit) as exc:
            parse_args(["--once", "--cycles", "2"])
        assert exc.value.code == 2

    def test_allowed_once_and_cycles_one(self):
        args = parse_args(["--once", "--cycles", "1"])
        assert args.once is True
        assert args.cycles == 1
        assert args.watch is False


# ========================================================================
# 3. DIRECT INSTANTIATION VALIDATION TESTS
# ========================================================================


class TestCollectorRunnerValidation:
    def test_runner_rejects_cycles_zero(self):
        with pytest.raises(ValueError, match="cycles must be an integer >= 1"):
            CollectorRunner(cycles=0, session_factory=None)

    def test_runner_rejects_cycles_negative(self):
        with pytest.raises(ValueError, match="cycles must be an integer >= 1"):
            CollectorRunner(cycles=-3, session_factory=None)

    def test_runner_rejects_interval_zero(self):
        with pytest.raises(ValueError, match="interval must be a positive finite number"):
            CollectorRunner(interval=0.0, session_factory=None)

    def test_runner_rejects_interval_negative(self):
        with pytest.raises(ValueError, match="interval must be a positive finite number"):
            CollectorRunner(interval=-1.5, session_factory=None)

    def test_runner_rejects_interval_non_finite(self):
        with pytest.raises(ValueError, match="interval must be a positive finite number"):
            CollectorRunner(interval=float("inf"), session_factory=None)

        with pytest.raises(ValueError, match="interval must be a positive finite number"):
            CollectorRunner(interval=float("nan"), session_factory=None)

    def test_runner_rejects_conflicting_once_and_watch(self):
        with pytest.raises(ValueError, match="Cannot combine once and watch modes"):
            CollectorRunner(once=True, watch=True, session_factory=None)

    def test_runner_rejects_conflicting_cycles_and_watch(self):
        with pytest.raises(ValueError, match="Cannot combine cycles and watch modes"):
            CollectorRunner(cycles=5, watch=True, session_factory=None)

    def test_runner_rejects_conflicting_once_and_cycles_two(self):
        with pytest.raises(ValueError, match="Cannot combine once with cycles != 1"):
            CollectorRunner(once=True, cycles=2, session_factory=None)


# ========================================================================
# 4. EXECUTION BEHAVIOR TESTS
# ========================================================================


class TestCollectorRunnerExecution:
    def test_one_cycle_execution_exits_zero(self):
        mock_orch = MagicMock(spec=CollectorOrchestrator)
        mock_orch.state = OrchestratorState.STOPPED
        mock_orch.host_uuid = TEST_HOST_UUID
        event = make_dummy_event()
        mock_orch.run_cycle.return_value = CycleResult(
            timestamp=datetime.now(timezone.utc),
            observations_count=1,
            events=[event],
            collector_errors={},
            processing_errors=[],
            sink_errors={},
            duration_ms=1.5,
        )

        runner = CollectorRunner(orchestrator=mock_orch, once=True)
        exit_code = runner.run()

        assert exit_code == 0
        mock_orch.start.assert_called_once_with(background=False)
        mock_orch.run_cycle.assert_called_once_with(force_all=True)
        mock_orch.stop.assert_called_once()
        assert runner.cycle_count == 1
        assert runner.total_persisted_events == 1

    def test_bounded_execution_cycles_three_exits_zero(self):
        mock_orch = MagicMock(spec=CollectorOrchestrator)
        mock_orch.state = OrchestratorState.STOPPED
        mock_orch.host_uuid = TEST_HOST_UUID
        event = make_dummy_event()
        mock_orch.run_cycle.return_value = CycleResult(
            timestamp=datetime.now(timezone.utc),
            observations_count=2,
            events=[event, event],
            collector_errors={},
            processing_errors=[],
            sink_errors={},
            duration_ms=2.0,
        )

        runner = CollectorRunner(
            orchestrator=mock_orch,
            cycles=3,
            interval=0.001,
        )
        exit_code = runner.run()

        assert exit_code == 0
        assert mock_orch.run_cycle.call_count == 3
        mock_orch.stop.assert_called_once()
        assert runner.cycle_count == 3
        assert runner.total_persisted_events == 6

    def test_continuous_mode_interrupted_by_shutdown_event_exits_zero(self):
        mock_orch = MagicMock(spec=CollectorOrchestrator)
        mock_orch.state = OrchestratorState.STOPPED
        mock_orch.host_uuid = TEST_HOST_UUID

        call_count = 0

        def fake_run_cycle(force_all=True):
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                # Signal shutdown on cycle 2
                runner.stop()
            return CycleResult(
                timestamp=datetime.now(timezone.utc),
                observations_count=1,
                events=[make_dummy_event()],
                collector_errors={},
                processing_errors=[],
                sink_errors={},
                duration_ms=1.0,
            )

        mock_orch.run_cycle.side_effect = fake_run_cycle

        runner = CollectorRunner(
            orchestrator=mock_orch,
            watch=True,
            interval=10.0,  # Large interval: verify it unblocks immediately without sleeping 10s
        )
        exit_code = runner.run()

        assert exit_code == 0
        assert call_count == 2
        mock_orch.stop.assert_called()
        assert runner.cycle_count == 2

    def test_continuous_mode_interrupted_by_signal_handler(self):
        mock_orch = MagicMock(spec=CollectorOrchestrator)
        mock_orch.state = OrchestratorState.STOPPED
        mock_orch.host_uuid = TEST_HOST_UUID

        def fake_run_cycle(force_all=True):
            # Simulate SIGTERM receipt
            runner._handle_signal(signal.SIGTERM, None)
            return CycleResult(
                timestamp=datetime.now(timezone.utc),
                observations_count=1,
                events=[],
                collector_errors={},
                processing_errors=[],
                sink_errors={},
                duration_ms=0.5,
            )

        mock_orch.run_cycle.side_effect = fake_run_cycle

        runner = CollectorRunner(orchestrator=mock_orch, watch=True, interval=5.0)
        exit_code = runner.run()

        assert exit_code == 0
        assert runner.shutdown_event.is_set()
        mock_orch.stop.assert_called()

    def test_degraded_cycle_handling(self, caplog: pytest.LogCaptureFixture):
        mock_orch = MagicMock(spec=CollectorOrchestrator)
        mock_orch.state = OrchestratorState.STOPPED
        mock_orch.host_uuid = TEST_HOST_UUID

        # Cycle 1: resource collector failed, but 2 healthy process events persisted!
        res_error = {"resource": "ResourceCollector error: Permission denied on /proc/stat"}
        healthy_events = [make_dummy_event(), make_dummy_event()]
        mock_orch.run_cycle.return_value = CycleResult(
            timestamp=datetime.now(timezone.utc),
            observations_count=2,
            events=healthy_events,
            collector_errors=res_error,
            processing_errors=[],
            sink_errors={},
            duration_ms=2.1,
        )

        runner = CollectorRunner(orchestrator=mock_orch, once=True)
        with caplog.at_level(logging.WARNING):
            exit_code = runner.run()

        assert exit_code == 0
        assert runner.cycle_count == 1
        # Runner accurately reports healthy events persisted, not 0!
        assert runner.total_persisted_events == 2
        assert "degraded" in caplog.text.lower()
        assert "Persisted 2 healthy events" in caplog.text

    def test_fatal_startup_failure_exits_one(self, caplog: pytest.LogCaptureFixture):
        mock_orch = MagicMock(spec=CollectorOrchestrator)
        mock_orch.state = OrchestratorState.STOPPED
        mock_orch.start.side_effect = CollectorStartupError("Watch descriptor exhausted")

        runner = CollectorRunner(orchestrator=mock_orch, once=True)
        with caplog.at_level(logging.CRITICAL):
            exit_code = runner.run()

        assert exit_code == 1
        assert "Fatal failure during collector startup" in caplog.text
        mock_orch.stop.assert_called_once()

    def test_unrecoverable_cycle_error_exits_one(self, caplog: pytest.LogCaptureFixture):
        mock_orch = MagicMock(spec=CollectorOrchestrator)
        mock_orch.state = OrchestratorState.STOPPED
        mock_orch.run_cycle.side_effect = RuntimeError("Fatal unhandled exception in cycle")

        runner = CollectorRunner(orchestrator=mock_orch, once=True)
        with caplog.at_level(logging.CRITICAL):
            exit_code = runner.run()

        assert exit_code == 1
        assert "Unrecoverable runtime error during collector cycle" in caplog.text


# ========================================================================
# 5. CLI ENTRYPOINT (main) INVOCATION TESTS
# ========================================================================


class TestMainEntrypoint:
    def test_main_clean_once_execution(self):
        mock_orch = MagicMock(spec=CollectorOrchestrator)
        mock_orch.state = OrchestratorState.STOPPED
        mock_orch.host_uuid = TEST_HOST_UUID
        mock_orch.run_cycle.return_value = CycleResult(
            timestamp=datetime.now(timezone.utc),
            observations_count=1,
            events=[make_dummy_event()],
            collector_errors={},
            processing_errors=[],
            sink_errors={},
            duration_ms=1.0,
        )

        code = main(["--once"], orchestrator=mock_orch)
        assert code == 0
        assert mock_orch.run_cycle.call_count == 1

    def test_main_clean_bounded_execution(self):
        mock_orch = MagicMock(spec=CollectorOrchestrator)
        mock_orch.state = OrchestratorState.STOPPED
        mock_orch.host_uuid = TEST_HOST_UUID
        mock_orch.run_cycle.return_value = CycleResult(
            timestamp=datetime.now(timezone.utc),
            observations_count=1,
            events=[],
            collector_errors={},
            processing_errors=[],
            sink_errors={},
            duration_ms=1.0,
        )

        code = main(["--cycles", "2", "--interval", "0.001"], orchestrator=mock_orch)
        assert code == 0
        assert mock_orch.run_cycle.call_count == 2

    def test_main_cli_arg_error_raises_system_exit_two(self):
        with pytest.raises(SystemExit) as exc:
            main(["--cycles", "0"])
        assert exc.value.code == 2

    def test_main_conflicting_flags_raises_system_exit_two(self):
        with pytest.raises(SystemExit) as exc:
            main(["--once", "--watch"])
        assert exc.value.code == 2

    def test_main_startup_failure_returns_one(self):
        mock_orch = MagicMock(spec=CollectorOrchestrator)
        mock_orch.state = OrchestratorState.STOPPED
        mock_orch.start.side_effect = RuntimeError("Fatal hardware initialization error")

        code = main(["--once"], orchestrator=mock_orch)
        assert code == 1


# ========================================================================
# 6. M-4 CONTRACT & DATABASE SESSION ISOLATION TESTS
# ========================================================================


class TestM4SessionContract:
    def test_caller_owned_session_is_not_closed_or_committed(self):
        """M-4 Contract: An injected caller-owned session must NEVER be closed

        or committed at the top level by the runner or orchestrator.
        """
        mock_session = MagicMock(spec=Session)
        mock_savepoint = MagicMock()
        mock_session.begin_nested.return_value = mock_savepoint

        runner = CollectorRunner(
            session=mock_session,
            once=True,
            host_id=TEST_HOST_UUID,
        )

        # Mock collectors to avoid touching live /proc
        runner.orchestrator.process_collector = MagicMock()
        runner.orchestrator.process_collector.collect_observations.return_value = []
        runner.orchestrator.resource_collector = MagicMock()
        runner.orchestrator.resource_collector.collect_observations.return_value = []
        runner.orchestrator.filesystem_collector = MagicMock()
        runner.orchestrator.filesystem_collector.collect_observations.return_value = []
        runner.orchestrator.user_synchronizer = None
        runner.orchestrator.process_lifecycle_service = None

        exit_code = runner.run()

        assert exit_code == 0
        # Caller session must NEVER be closed or committed by runner or orchestrator
        mock_session.close.assert_not_called()
        mock_session.commit.assert_not_called()
        # The inner savepoint was committed, isolating cycle work
        mock_savepoint.commit.assert_called_once()

    def test_session_factory_creates_and_closes_cycle_sessions(self):
        """M-4 Contract: When session_factory is supplied, the runner/orchestrator

        creates a fresh session per cycle and closes it in all paths.
        """
        created_sessions: list[MagicMock] = []

        def fake_session_factory():
            s = MagicMock(spec=Session)
            created_sessions.append(s)
            return s

        runner = CollectorRunner(
            session_factory=fake_session_factory,
            cycles=2,
            interval=0.001,
            host_id=TEST_HOST_UUID,
        )

        # Mock collectors
        runner.orchestrator.process_collector = MagicMock()
        runner.orchestrator.process_collector.collect_observations.return_value = []
        runner.orchestrator.resource_collector = MagicMock()
        runner.orchestrator.resource_collector.collect_observations.return_value = []
        runner.orchestrator.filesystem_collector = MagicMock()
        runner.orchestrator.filesystem_collector.collect_observations.return_value = []
        runner.orchestrator.user_synchronizer = None
        runner.orchestrator.process_lifecycle_service = None

        exit_code = runner.run()

        assert exit_code == 0
        assert len(created_sessions) == 2
        for s in created_sessions:
            s.commit.assert_called_once()
            s.close.assert_called_once()


# ========================================================================
# 7. FASTAPI DECOUPLING TESTS
# ========================================================================


class TestFastApiDecoupling:
    @pytest.mark.anyio
    async def test_fastapi_lifespan_does_not_launch_collector_runner(self):
        """Verify that starting FastAPI application and running its lifespan

        does NOT instantiate or execute CollectorRunner.
        """
        with patch("collectors.runner.CollectorRunner.__init__") as mock_init:
            async with lifespan(app):
                # Verify app startup completed
                pass
            mock_init.assert_not_called()

    def test_fastapi_app_routes_do_not_import_or_launch_runner(self):
        """Verify that importing backend.main does not instantiate CollectorRunner."""
        from backend import main as backend_main

        assert hasattr(backend_main, "app")
        assert not hasattr(backend_main, "CollectorRunner")
