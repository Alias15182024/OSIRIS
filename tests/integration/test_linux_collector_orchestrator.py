"""Live Linux integration tests for CollectorOrchestrator.

These tests execute directly against the Linux host `/proc` filesystem and
the Linux kernel `inotify` subsystem.
On non-Linux platforms (such as macOS development machines), these tests
are skipped cleanly.
"""

from __future__ import annotations

import sys
import time
import uuid
from pathlib import Path

import pytest

from backend.services.events.schemas import NormalizedEvent
from collectors.orchestrator import (
    CollectorOrchestrator,
    OrchestratorConfig,
    OrchestratorState,
)

# Skip entire module on non-Linux platforms
pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="Live CollectorOrchestrator integration tests require Linux /proc and inotify",
)

TEST_HOST_ID = uuid.UUID("22222222-2222-4222-8222-222222222222")


class TestLiveLinuxCollectorOrchestrator:
    def test_live_linux_orchestrator_single_cycle(self, tmp_path: Path):
        """Single live cycle gathers and normalizes process, resource, and filesystem events."""
        watch_dir = tmp_path / "live_watch"
        watch_dir.mkdir()

        config = OrchestratorConfig(
            host_id=TEST_HOST_ID,
            filesystem_paths=[watch_dir],
            proc_dir="/proc",
        )
        orchestrator = CollectorOrchestrator(config)

        # Start to register inotify watches
        orchestrator.start(background=False)
        assert orchestrator.is_running() is True

        try:
            # Generate a real filesystem event in watched directory
            test_file = watch_dir / "sample.txt"
            test_file.write_text("testing live orchestration\n")

            # Brief pause for inotify buffer
            time.sleep(0.05)

            # Execute a full cycle forcing all collectors
            res = orchestrator.run_cycle(force_all=True)

            assert res.success is True, f"Cycle had errors: {res.collector_errors}, {res.processing_errors}"
            assert res.observations_count > 0
            assert len(res.events) > 0

            sources = {e.source for e in res.events}
            # All 3 collectors must have produced events
            assert "proc" in sources
            assert "resource" in sources
            assert "fs" in sources

            # Verify normalized event properties
            for event in res.events:
                assert isinstance(event, NormalizedEvent)
                assert event.id is not None
                assert event.host_id == TEST_HOST_ID
                assert event.timestamp is not None
                assert event.ingested_at is not None

        finally:
            orchestrator.stop()
            assert orchestrator.is_running() is False

    def test_live_linux_orchestrator_continuous_lifecycle(self, tmp_path: Path):
        """Continuous background execution collects events and shuts down cleanly."""
        watch_dir = tmp_path / "continuous_watch"
        watch_dir.mkdir()

        config = OrchestratorConfig(
            host_id=TEST_HOST_ID,
            filesystem_paths=[watch_dir],
            proc_dir="/proc",
            tick_interval=0.1,
            process_interval=0.2,
            resource_interval=0.2,
        )

        orchestrator = CollectorOrchestrator(config)
        orchestrator.start(background=True)
        assert orchestrator.is_running() is True

        try:
            # Perform file operations
            file1 = watch_dir / "act1.txt"
            file1.write_text("continuous activity\n")
            time.sleep(0.3)

            file1.write_text("more activity\n")
            time.sleep(0.3)

            # Status check
            status = orchestrator.get_status()
            assert status["state"] == "running"
            assert status["cycle_count"] >= 2
            assert status["total_events"] > 0

        finally:
            orchestrator.stop(timeout=2.0)
            assert orchestrator.is_running() is False
            assert orchestrator.state == OrchestratorState.STOPPED
            if orchestrator._worker_thread:
                assert not orchestrator._worker_thread.is_alive()

    def test_live_linux_orchestrator_context_manager(self, tmp_path: Path):
        """Context manager protocol works cleanly on live Linux."""
        watch_dir = tmp_path / "cm_watch"
        watch_dir.mkdir()

        config = OrchestratorConfig(
            host_id=TEST_HOST_ID,
            filesystem_paths=[watch_dir],
            proc_dir="/proc",
            tick_interval=0.1,
        )

        with CollectorOrchestrator(config) as orchestrator:
            assert orchestrator.is_running() is True
            assert orchestrator.state == OrchestratorState.RUNNING

        assert orchestrator.is_running() is False
        assert orchestrator.state == OrchestratorState.STOPPED
