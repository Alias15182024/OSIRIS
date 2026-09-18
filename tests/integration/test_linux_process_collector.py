"""Live Linux integration tests for ProcessCollector.

These tests execute directly against the host Linux `/proc` filesystem.
On non-Linux platforms (such as macOS development machines), these tests
are skipped cleanly.
"""

from __future__ import annotations

import os
import sys
import uuid

import pytest

from backend.services.events.processor import EventProcessor
from backend.services.events.schemas import NormalizedEvent
from collectors.process import ProcessCollector

# Skip entire module on non-Linux platforms
pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="Live ProcessCollector integration tests require Linux /proc",
)

TEST_HOST_ID = uuid.UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")


class TestLiveLinuxProcessCollector:

    def test_live_linux_discovers_processes(self):
        """Live collection on Linux discovers running processes including current PID."""
        collector = ProcessCollector(TEST_HOST_ID, proc_dir="/proc")
        raw_list = collector.collect()

        assert len(raw_list) > 0

        # Current test process must be discovered
        current_pid = os.getpid()
        pids = {p["pid"] for p in raw_list}
        assert current_pid in pids

        current_proc = next(p for p in raw_list if p["pid"] == current_pid)
        assert current_proc["pid"] == current_pid
        assert current_proc["ppid"] >= 0
        assert current_proc["comm"] is not None
        assert current_proc["command"] is not None
        # On Linux, UID must match current user ID
        assert current_proc["uid"] == os.getuid()

    def test_live_linux_produces_valid_raw_observations(self):
        """Live collection on Linux produces valid RawObservation objects."""
        collector = ProcessCollector(TEST_HOST_ID, proc_dir="/proc")
        observations = collector.collect_observations(diff=False)

        assert len(observations) > 0

        # Find observation for this test process
        current_pid = os.getpid()
        matching = [o for o in observations if o.pid == current_pid]
        assert len(matching) == 1

        obs = matching[0]
        assert obs.source == "proc"
        assert obs.event_type == "process.start"
        assert obs.action == "start"
        assert obs.host_id == TEST_HOST_ID
        assert obs.observed_at is not None
        assert obs.process_id is None  # Preserved boundary

    def test_live_linux_observations_normalize_through_processor(self):
        """Live observations successfully pass through EventProcessor."""
        collector = ProcessCollector(TEST_HOST_ID, proc_dir="/proc")
        observations = collector.collect_observations(diff=False)

        processor = EventProcessor()
        # Process a slice of live observations
        for obs in observations[:10]:
            res = processor.process(obs)
            assert res.success, f"Failed to normalize live observation: {res.errors}"
            assert isinstance(res.event, NormalizedEvent)
            assert res.event.source == "proc"
            assert res.event.pid is not None
            assert res.event.pid >= 0
            assert res.event.timestamp.tzinfo is not None
