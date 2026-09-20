"""Unit tests for the OSIRIS Linux Resource Collector.

Tests run on any operating system (including macOS) using temporary
mock `/proc` filesystem fixtures and mock `statvfs` callables.
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from backend.services.events.processor import EventProcessor
from backend.services.events.schemas import NormalizedEvent, RawObservation
from collectors.resource import (
    PlatformError,
    ResourceCollector,
    SECTOR_SIZE_BYTES,
    WHOLE_DISK_PATTERN,
    calculate_cpu_percent,
    calculate_memory_metrics,
    parse_cpu_ticks,
    parse_diskstats,
    parse_loadavg,
    parse_meminfo,
    query_disk_usage,
)

TEST_HOST_ID = uuid.UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")

# Sample /proc/stat content
SAMPLE_PROC_STAT_1 = """cpu  1000 200 300 8000 100 50 20 10 0 0
cpu0 500 100 150 4000 50 25 10 5 0 0
cpu1 500 100 150 4000 50 25 10 5 0 0
intr 123456 0 0 0
ctxt 654321
btime 1700000000
processes 5000
procs_running 2
procs_blocked 0
"""

SAMPLE_PROC_STAT_2 = """cpu  1100 220 330 8400 110 55 22 11 0 0
cpu0 550 110 165 4200 55 27 11 5 0 0
cpu1 550 110 165 4200 55 28 11 6 0 0
"""

# Sample /proc/loadavg content
SAMPLE_PROC_LOADAVG = "0.52 0.48 0.45 1/342 12345\n"

# Sample /proc/meminfo content (in kB)
SAMPLE_PROC_MEMINFO = """MemTotal:       16384000 kB
MemFree:         4096000 kB
MemAvailable:    8192000 kB
Buffers:          512000 kB
Cached:          2048000 kB
SwapTotal:       2048000 kB
SwapFree:        1024000 kB
"""

# Sample /proc/diskstats content
SAMPLE_PROC_DISKSTATS = """   8       0 sda 100 20 2000 500 200 40 4000 1000 0 200 1500
   8       1 sda1 50 10 1000 250 100 20 2000 500 0 100 750
 259       0 nvme0n1 300 0 6000 800 400 0 8000 1200 0 300 2000
 259       1 nvme0n1p1 100 0 2000 300 150 0 3000 400 0 100 700
   7       0 loop0 10 0 50 10 0 0 0 0 0 5 10
 254       0 dm-0 500 0 10000 1000 600 0 12000 1500 0 400 2500
   1       0 ram0 0 0 0 0 0 0 0 0 0 0 0
"""


def create_mock_proc_dir(
    tmp_path: Path,
    stat: str | None = SAMPLE_PROC_STAT_1,
    loadavg: str | None = SAMPLE_PROC_LOADAVG,
    meminfo: str | None = SAMPLE_PROC_MEMINFO,
    diskstats: str | None = SAMPLE_PROC_DISKSTATS,
) -> Path:
    """Helper to create a temporary mock /proc directory."""
    proc = tmp_path / "proc"
    proc.mkdir(parents=True, exist_ok=True)
    if stat is not None:
        (proc / "stat").write_text(stat, encoding="utf-8")
    if loadavg is not None:
        (proc / "loadavg").write_text(loadavg, encoding="utf-8")
    if meminfo is not None:
        (proc / "meminfo").write_text(meminfo, encoding="utf-8")
    if diskstats is not None:
        (proc / "diskstats").write_text(diskstats, encoding="utf-8")
    return proc


def mock_statvfs_call(
    total_gb: int = 100, free_gb: int = 40, avail_gb: int = 35, frsize: int = 4096
):
    """Return a mock function simulating os.statvfs."""
    def _statvfs(path: str):
        total_blocks = (total_gb * 1024**3) // frsize
        free_blocks = (free_gb * 1024**3) // frsize
        avail_blocks = (avail_gb * 1024**3) // frsize
        return SimpleNamespace(
            f_blocks=total_blocks,
            f_bfree=free_blocks,
            f_bavail=avail_blocks,
            f_frsize=frsize,
            f_bsize=frsize,
        )

    return _statvfs


# ========================================================================
# 1. PARSER TESTS
# ========================================================================


class TestResourceParsers:
    def test_parse_cpu_ticks_standard(self):
        ticks = parse_cpu_ticks(SAMPLE_PROC_STAT_1)
        assert ticks is not None
        assert ticks["user"] == 1000
        assert ticks["nice"] == 200
        assert ticks["system"] == 300
        assert ticks["idle"] == 8000
        assert ticks["iowait"] == 100
        assert ticks["irq"] == 50
        assert ticks["softirq"] == 20
        assert ticks["steal"] == 10
        assert ticks["guest"] == 0
        assert ticks["guest_nice"] == 0
        assert ticks["idle_all"] == 8100  # 8000 + 100
        assert ticks["total"] == 9680

    def test_parse_cpu_ticks_older_kernel_fewer_fields(self):
        # Only 4 fields: user, nice, system, idle
        stat = "cpu 100 20 30 500\n"
        ticks = parse_cpu_ticks(stat)
        assert ticks is not None
        assert ticks["user"] == 100
        assert ticks["nice"] == 20
        assert ticks["system"] == 30
        assert ticks["idle"] == 500
        assert ticks["iowait"] == 0
        assert ticks["idle_all"] == 500
        assert ticks["total"] == 650

    def test_parse_cpu_ticks_missing_or_corrupt(self):
        assert parse_cpu_ticks("") is None
        assert parse_cpu_ticks("invalid content") is None
        assert parse_cpu_ticks("cpu abc def") is None
        assert parse_cpu_ticks("cpu 1 2") is None  # fewer than 4 fields

    def test_calculate_cpu_percent(self):
        # 1. First collection (prev is None) -> returns None
        t1 = parse_cpu_ticks(SAMPLE_PROC_STAT_1)
        assert calculate_cpu_percent(None, t1) is None

        # 2. Second collection -> computes delta
        t2 = parse_cpu_ticks(SAMPLE_PROC_STAT_2)
        assert t1 is not None and t2 is not None
        # t1: idle_all=8100, total=9680
        # t2: user=1100, nice=220, system=330, idle=8400, iowait=110, irq=55, softirq=22, steal=11, guest=0, guest_nice=0
        # t2: idle_all=8510, total=10248
        # delta_total = 10248 - 9680 = 568
        # delta_idle = 8510 - 8100 = 410
        # utilization = (1.0 - 410/568) * 100 = 27.8169... -> 27.82
        pct = calculate_cpu_percent(t1, t2)
        assert pct is not None
        assert 0.0 <= pct <= 100.0
        assert pct == 27.82

    def test_calculate_cpu_percent_zero_delta(self):
        t1 = parse_cpu_ticks(SAMPLE_PROC_STAT_1)
        pct = calculate_cpu_percent(t1, t1)
        assert pct == 0.0

    def test_parse_loadavg_standard(self):
        load = parse_loadavg(SAMPLE_PROC_LOADAVG)
        assert load is not None
        assert load["load_avg_1m"] == 0.52
        assert load["load_avg_5m"] == 0.48
        assert load["load_avg_15m"] == 0.45

    def test_parse_loadavg_invalid(self):
        assert parse_loadavg("") is None
        assert parse_loadavg("0.1 0.2") is None  # fewer than 3 values
        assert parse_loadavg("abc def ghi") is None

    def test_parse_meminfo_and_metrics(self):
        raw = parse_meminfo(SAMPLE_PROC_MEMINFO)
        assert raw["MemTotal"] == 16384000
        assert raw["MemAvailable"] == 8192000
        assert raw["MemFree"] == 4096000

        metrics = calculate_memory_metrics(raw)
        assert metrics is not None
        assert metrics["memory_total"] == 16384000 * 1024
        # used = (MemTotal - MemAvailable) = (16384000 - 8192000) * 1024
        assert metrics["memory_used"] == 8192000 * 1024
        # percent = (8192000 / 16384000) * 100 = 50.0
        assert metrics["memory_percent"] == 50.0
        assert metrics["memory_available"] == 8192000 * 1024
        assert metrics["memory_free"] == 4096000 * 1024
        assert metrics["buffers"] == 512000 * 1024
        assert metrics["cached"] == 2048000 * 1024
        assert metrics["swap_total"] == 2048000 * 1024
        assert metrics["swap_used"] == 1024000 * 1024
        assert metrics["swap_percent"] == 50.0

    def test_calculate_memory_metrics_missing_memavailable_fallback(self):
        # Older kernel without MemAvailable: fallback uses Free + Buffers + Cached
        raw = {
            "MemTotal": 10000000,
            "MemFree": 2000000,
            "Buffers": 1000000,
            "Cached": 3000000,
        }
        metrics = calculate_memory_metrics(raw)
        assert metrics is not None
        # used = 10000000 - (2000000 + 1000000 + 3000000) = 4000000 kB
        assert metrics["memory_total"] == 10000000 * 1024
        assert metrics["memory_used"] == 4000000 * 1024
        assert metrics["memory_percent"] == 40.0
        assert metrics["memory_available"] is None

    def test_calculate_memory_metrics_missing_total(self):
        assert calculate_memory_metrics({}) is None
        assert calculate_memory_metrics({"MemFree": 1000}) is None

    def test_parse_diskstats_filtering(self):
        disk_data = parse_diskstats(SAMPLE_PROC_DISKSTATS)
        assert disk_data is not None
        # Whole devices: sda and nvme0n1. Excluded: sda1, nvme0n1p1, loop0, dm-0, ram0
        assert sorted(disk_data["matched_devices"]) == ["nvme0n1", "sda"]

        # sda: read sectors = 2000, write sectors = 4000
        # nvme0n1: read sectors = 6000, write sectors = 8000
        # total read sectors = 8000, total write sectors = 12000
        assert disk_data["disk_read_bytes"] == 8000 * SECTOR_SIZE_BYTES
        assert disk_data["disk_write_bytes"] == 12000 * SECTOR_SIZE_BYTES

    def test_parse_diskstats_no_matching_devices(self):
        # Only loop devices and partitions
        content = """   7       0 loop0 10 0 50 10 0 0 0 0 0 5 10
   8       1 sda1 50 10 1000 250 100 20 2000 500 0 100 750
"""
        assert parse_diskstats(content) is None

    def test_query_disk_usage_mock(self):
        statvfs_fn = mock_statvfs_call(total_gb=100, free_gb=40, avail_gb=35)
        usage = query_disk_usage("/", statvfs_fn=statvfs_fn)

        assert usage["disk_total_bytes"] is not None
        assert usage["disk_used_bytes"] is not None
        assert usage["disk_available_bytes"] is not None
        assert usage["disk_usage_percent"] is not None
        assert 0.0 <= usage["disk_usage_percent"] <= 100.0

    def test_query_disk_usage_error_handling(self):
        def bad_statvfs(path: str):
            raise PermissionError("Access denied")

        usage = query_disk_usage("/protected", statvfs_fn=bad_statvfs)
        assert usage["disk_total_bytes"] is None
        assert usage["disk_usage_percent"] is None


# ========================================================================
# 2. COLLECTOR UNIT TESTS
# ========================================================================


class TestResourceCollector:
    def test_source_name(self, tmp_path: Path):
        proc_dir = create_mock_proc_dir(tmp_path)
        collector = ResourceCollector(TEST_HOST_ID, proc_dir=proc_dir)
        assert collector.get_source_name() == "resource"

    def test_platform_guard_on_non_linux(self):
        """Default /proc on non-Linux platform must raise PlatformError."""
        with patch("sys.platform", "darwin"):
            collector = ResourceCollector(TEST_HOST_ID, proc_dir="/proc")
            with pytest.raises(PlatformError, match="ResourceCollector requires Linux /proc"):
                collector.collect()

    def test_platform_guard_permits_mock_proc_on_non_linux(self, tmp_path: Path):
        """Custom proc_dir passes platform check even on non-Linux."""
        proc_dir = create_mock_proc_dir(tmp_path)
        with patch("sys.platform", "darwin"):
            collector = ResourceCollector(
                TEST_HOST_ID,
                proc_dir=proc_dir,
                statvfs_fn=mock_statvfs_call(),
            )
            raw = collector.collect()
            assert raw is not None

    def test_first_collection_returns_none_for_cpu_percent(self, tmp_path: Path):
        """First collection cycle stores baseline and returns cpu_percent=None."""
        proc_dir = create_mock_proc_dir(tmp_path, stat=SAMPLE_PROC_STAT_1)
        collector = ResourceCollector(
            TEST_HOST_ID,
            proc_dir=proc_dir,
            statvfs_fn=mock_statvfs_call(),
        )

        data = collector.collect()
        assert data["cpu_percent"] is None
        assert collector._prev_cpu_ticks is not None
        assert collector._prev_cpu_ticks["user"] == 1000

    def test_second_collection_calculates_cpu_percent(self, tmp_path: Path):
        """Subsequent collection cycle calculates differential CPU utilization."""
        proc_dir = create_mock_proc_dir(tmp_path, stat=SAMPLE_PROC_STAT_1)
        collector = ResourceCollector(
            TEST_HOST_ID,
            proc_dir=proc_dir,
            statvfs_fn=mock_statvfs_call(),
        )

        # 1. Baseline cycle
        d1 = collector.collect()
        assert d1["cpu_percent"] is None

        # 2. Update /proc/stat
        (proc_dir / "stat").write_text(SAMPLE_PROC_STAT_2, encoding="utf-8")

        # 3. Second cycle
        d2 = collector.collect()
        assert d2["cpu_percent"] is not None
        assert d2["cpu_percent"] == 27.82

    def test_reset_clears_cpu_baseline(self, tmp_path: Path):
        """Reset clears previous ticks so next cycle is again baseline (None)."""
        proc_dir = create_mock_proc_dir(tmp_path, stat=SAMPLE_PROC_STAT_1)
        collector = ResourceCollector(
            TEST_HOST_ID,
            proc_dir=proc_dir,
            statvfs_fn=mock_statvfs_call(),
        )

        collector.collect()
        assert collector._prev_cpu_ticks is not None

        collector.reset()
        assert collector._prev_cpu_ticks is None

        # Next collect must return None again
        d3 = collector.collect()
        assert d3["cpu_percent"] is None

    def test_parse_creates_valid_observation_dict(self, tmp_path: Path):
        proc_dir = create_mock_proc_dir(tmp_path)
        collector = ResourceCollector(
            TEST_HOST_ID,
            proc_dir=proc_dir,
            statvfs_fn=mock_statvfs_call(),
        )
        raw = collector.collect()
        parsed = collector.parse(raw)

        assert parsed["source"] == "resource"
        assert parsed["host_id"] == TEST_HOST_ID
        assert parsed["event_type"] == "resource.snapshot"
        assert parsed["action"] == "snapshot"
        assert parsed["severity"] == "info"
        assert parsed["object_type"] == "system"
        assert parsed["object_path"] == "/"
        assert parsed["process_id"] is None
        assert parsed["pid"] is None
        assert parsed["uid"] is None

        # Payload validation
        payload = parsed["payload"]
        assert payload["timestamp_source"] == "collection_time"
        assert payload["memory_total"] == 16384000 * 1024
        assert payload["memory_used"] == 8192000 * 1024
        assert payload["memory_percent"] == 50.0
        assert payload["load_avg_1m"] == 0.52
        assert payload["disk_read_bytes"] == 8000 * SECTOR_SIZE_BYTES
        assert payload["disk_write_bytes"] == 12000 * SECTOR_SIZE_BYTES

    def test_collect_observations_canonical(self, tmp_path: Path):
        """Canonical collection produces one RawObservation with event_type='resource.snapshot'."""
        proc_dir = create_mock_proc_dir(tmp_path)
        collector = ResourceCollector(
            TEST_HOST_ID,
            proc_dir=proc_dir,
            statvfs_fn=mock_statvfs_call(),
        )

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

    def test_collect_observations_granular(self, tmp_path: Path):
        """Granular collection produces canonical snapshot plus cpu, memory, disk events."""
        proc_dir = create_mock_proc_dir(tmp_path)
        collector = ResourceCollector(
            TEST_HOST_ID,
            proc_dir=proc_dir,
            statvfs_fn=mock_statvfs_call(),
        )

        observations = collector.collect_observations(granular=True)
        assert len(observations) == 4

        event_types = [o.event_type for o in observations]
        assert event_types == [
            "resource.snapshot",
            "resource.cpu",
            "resource.memory",
            "resource.disk",
        ]
        for obs in observations:
            assert obs.source == "resource"
            assert obs.action == "snapshot"
            assert obs.host_id == TEST_HOST_ID
            assert obs.payload["timestamp_source"] == "collection_time"

    def test_missing_proc_files_resilience(self, tmp_path: Path):
        """Empty mock /proc directory does not crash collector; missing values are None."""
        empty_proc = tmp_path / "empty_proc"
        empty_proc.mkdir(parents=True)

        collector = ResourceCollector(
            TEST_HOST_ID,
            proc_dir=empty_proc,
            statvfs_fn=mock_statvfs_call(),
        )
        raw = collector.collect()
        assert raw["cpu_percent"] is None
        assert raw["load_avg_1m"] is None
        assert raw["memory_total"] is None
        assert raw["disk_read_bytes"] is None

        observations = collector.collect_observations(granular=False)
        assert len(observations) == 1
        assert observations[0].event_type == "resource.snapshot"
        assert observations[0].payload["cpu_percent"] is None

    def test_context_manager(self, tmp_path: Path):
        proc_dir = create_mock_proc_dir(tmp_path)
        with ResourceCollector(
            TEST_HOST_ID,
            proc_dir=proc_dir,
            statvfs_fn=mock_statvfs_call(),
        ) as col:
            obs = col.collect_observations()
            assert len(obs) == 1
        # reset was called on exit
        assert col._prev_cpu_ticks is None


# ========================================================================
# 3. EVENT PROCESSING INTEGRATION (NORMALIZATION)
# ========================================================================


class TestResourceEventProcessing:
    def test_resource_observations_normalize_through_event_processor(
        self, tmp_path: Path
    ):
        """Verify RawObservation from ResourceCollector flows through EventProcessor."""
        proc_dir = create_mock_proc_dir(tmp_path, stat=SAMPLE_PROC_STAT_1)
        collector = ResourceCollector(
            TEST_HOST_ID,
            proc_dir=proc_dir,
            statvfs_fn=mock_statvfs_call(),
        )

        # 1. First collection (cpu_percent=None)
        obs_list1 = collector.collect_observations(granular=True)
        processor = EventProcessor()

        for obs in obs_list1:
            res = processor.process(obs)
            assert res.success is True, f"Failed on {obs.event_type}: {res.errors}"
            assert res.event is not None
            assert isinstance(res.event, NormalizedEvent)
            assert res.event.id is not None
            assert res.event.source == "resource"
            assert res.event.host_id == TEST_HOST_ID
            assert res.event.action == "snapshot"
            assert res.event.timestamp is not None
            assert res.event.process_id is None

        # 2. Second collection with updated CPU ticks (cpu_percent is calculated float)
        (proc_dir / "stat").write_text(SAMPLE_PROC_STAT_2, encoding="utf-8")
        obs_list2 = collector.collect_observations(granular=False)
        assert len(obs_list2) == 1

        res2 = processor.process(obs_list2[0])
        assert res2.success is True
        assert res2.event is not None
        assert res2.event.payload["cpu_percent"] == 27.82
        assert res2.event.payload["memory_percent"] == 50.0
        assert res2.event.payload["timestamp_source"] == "collection_time"
