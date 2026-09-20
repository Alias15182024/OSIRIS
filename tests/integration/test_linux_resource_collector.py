"""Live Linux integration tests for ResourceCollector.

These tests execute directly against the host Linux `/proc` filesystem
and `os.statvfs("/")`.
On non-Linux platforms (such as macOS development machines), these tests
are skipped cleanly.
"""

from __future__ import annotations

import sys
import time
import uuid

import pytest

from backend.services.events.processor import EventProcessor
from backend.services.events.schemas import NormalizedEvent, RawObservation
from collectors.resource import ResourceCollector

# Skip entire module on non-Linux platforms
pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="Live ResourceCollector integration tests require Linux /proc",
)

TEST_HOST_ID = uuid.UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")


class TestLiveLinuxResourceCollector:
    def test_live_linux_collects_metrics(self):
        """Live collection on Linux retrieves valid metrics from /proc and statvfs."""
        collector = ResourceCollector(TEST_HOST_ID, proc_dir="/proc", mount_point="/")
        data = collector.collect()

        assert "timestamp" in data
        # Memory metrics
        assert data.get("memory_total") is not None
        assert data["memory_total"] > 0
        assert data.get("memory_used") is not None
        assert data["memory_used"] >= 0
        assert data.get("memory_percent") is not None
        assert 0.0 <= data["memory_percent"] <= 100.0

        # Load averages
        assert data.get("load_avg_1m") is not None
        assert data["load_avg_1m"] >= 0.0
        assert data.get("load_avg_5m") is not None
        assert data["load_avg_5m"] >= 0.0
        assert data.get("load_avg_15m") is not None
        assert data["load_avg_15m"] >= 0.0

        # Disk usage
        assert data.get("disk_total_bytes") is not None
        assert data["disk_total_bytes"] > 0
        assert data.get("disk_usage_percent") is not None
        assert 0.0 <= data["disk_usage_percent"] <= 100.0

    def test_live_linux_cpu_differential(self):
        """Live collection verifies two-cycle differential CPU utilization calculation."""
        collector = ResourceCollector(TEST_HOST_ID, proc_dir="/proc", mount_point="/")

        # 1. First cycle: stores baseline ticks and returns cpu_percent=None
        data1 = collector.collect()
        assert data1["cpu_percent"] is None

        # Short sleep to allow CPU ticks to advance
        time.sleep(0.2)

        # 2. Second cycle: calculates utilization
        data2 = collector.collect()
        assert data2["cpu_percent"] is not None
        assert isinstance(data2["cpu_percent"], float)
        assert 0.0 <= data2["cpu_percent"] <= 100.0

    def test_live_linux_produces_raw_observations(self):
        """Live collection produces valid RawObservation objects."""
        collector = ResourceCollector(TEST_HOST_ID, proc_dir="/proc", mount_point="/")

        # Canonical snapshot
        observations = collector.collect_observations(granular=False)
        assert len(observations) == 1
        obs = observations[0]
        assert isinstance(obs, RawObservation)
        assert obs.source == "resource"
        assert obs.event_type == "resource.snapshot"
        assert obs.action == "snapshot"
        assert obs.host_id == TEST_HOST_ID
        assert obs.process_id is None
        assert obs.payload["timestamp_source"] == "collection_time"

        # Granular snapshots
        granular_obs = collector.collect_observations(granular=True)
        assert len(granular_obs) == 4
        types = [o.event_type for o in granular_obs]
        assert types == [
            "resource.snapshot",
            "resource.cpu",
            "resource.memory",
            "resource.disk",
        ]

    def test_live_linux_observations_normalize_through_processor(self):
        """Live resource observations normalize cleanly through EventProcessor."""
        collector = ResourceCollector(TEST_HOST_ID, proc_dir="/proc", mount_point="/")
        observations = collector.collect_observations(granular=True)

        processor = EventProcessor()
        for obs in observations:
            res = processor.process(obs)
            assert res.success is True, f"Failed to normalize {obs.event_type}: {res.errors}"
            assert res.event is not None
            assert isinstance(res.event, NormalizedEvent)
            assert res.event.id is not None
            assert res.event.source == "resource"
            assert res.event.host_id == TEST_HOST_ID
            assert res.event.action == "snapshot"
            assert res.event.timestamp is not None
