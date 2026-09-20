"""Linux Resource Collector for OSIRIS.

Collects point-in-time CPU, memory, and disk metrics from the Linux `/proc` filesystem
and filesystem geometry via `os.statvfs`.
Produces ``RawObservation`` instances for the Event Processing Layer.

Architecture:
-------------
- Source identifier: ``"resource"``
- Notification mechanism: Linux `/proc/stat`, `/proc/loadavg`, `/proc/meminfo`,
  `/proc/diskstats`, and `os.statvfs` (zero external dependencies).
- Event type: ``resource.snapshot`` (canonical snapshot event) and optional
  granular events (``resource.cpu``, ``resource.memory``, ``resource.disk``).
- Action: ``"snapshot"``.
- CPU differential behavior: On the first collection cycle, records baseline ticks
  and returns ``cpu_percent = None``. On subsequent cycles, computes system-wide
  utilization within ``[0.0, 100.0]``.
- Memory calculation: Computes `memory_total`, `memory_used` (`MemTotal - MemAvailable`),
  and `memory_percent`. Supplementary metrics remain strictly inside `payload`.
- Disk I/O: Aggregates whole physical/virtual block devices (excluding partitions, loop,
  ram, and dm devices), converting sectors to bytes via standard 512 bytes/sector.
- Platform Policy: Real collection requires Linux `/proc`. Non-Linux OS (macOS) raises
  ``PlatformError`` unless a custom `proc_dir` is injected.
- Invariants: Does not assign event UUIDs, does not normalize UTC timestamps,
  does not assign internal `process_id` (`None`), does not persist directly to PostgreSQL.
"""

from __future__ import annotations

import logging
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from backend.services.events.schemas import RawObservation
from collectors.base import BaseCollector
from collectors.resource.parser import (
    calculate_cpu_percent,
    calculate_memory_metrics,
    parse_cpu_ticks,
    parse_diskstats,
    parse_loadavg,
    parse_meminfo,
    query_disk_usage,
)

logger = logging.getLogger("osiris.collectors.resource")
DEFAULT_PROC_DIR = "/proc"


class PlatformError(RuntimeError):
    """Raised when live resource collection is attempted on an unsupported OS."""


class ResourceCollector(BaseCollector):
    """Linux system resource collector reading from `/proc` and `statvfs`.

    Parameters
    ----------
    host_id:
        UUID or string identifying the monitored host.
    proc_dir:
        Path to the proc filesystem. Defaults to `/proc`. Non-default
        paths are intended exclusively for mock unit testing.
    mount_point:
        Root or mount directory to inspect for filesystem disk usage.
        Defaults to `/`.
    statvfs_fn:
        Optional callable override for `os.statvfs` (for unit testing).
    """

    def __init__(
        self,
        host_id: uuid.UUID | str,
        *,
        proc_dir: str | Path = DEFAULT_PROC_DIR,
        mount_point: str | Path = "/",
        statvfs_fn: Callable[[str], Any] | None = None,
    ) -> None:
        super().__init__(str(host_id))
        self.host_uuid = (
            host_id if isinstance(host_id, uuid.UUID) else uuid.UUID(str(host_id))
        )
        self.proc_dir = Path(proc_dir)
        self.mount_point = Path(mount_point)
        self.statvfs_fn = statvfs_fn

        # Track previous CPU ticks for differential utilization calculation
        self._prev_cpu_ticks: dict[str, int] | None = None

    def get_source_name(self) -> str:
        """Return the source identifier for resource observations."""
        return "resource"

    def _check_platform(self) -> None:
        """Ensure live collection is only executed on Linux."""
        if str(self.proc_dir) == DEFAULT_PROC_DIR and sys.platform != "linux":
            raise PlatformError(
                f"ResourceCollector requires Linux /proc (running on {sys.platform}). "
                "Real collection cannot be performed on non-Linux platforms."
            )

    def _read_proc_file(self, filename: str) -> str | None:
        """Safely read a file within `proc_dir`."""
        target = self.proc_dir / filename
        if not target.exists():
            return None
        try:
            return target.read_text(encoding="utf-8", errors="replace")
        except (PermissionError, FileNotFoundError, OSError) as exc:
            logger.warning("Failed to read %s: %s", target, exc)
            return None

    def collect(self) -> dict[str, Any]:
        """Collect current resource metrics from the system.

        Returns
        -------
        dict[str, Any]
            Raw metrics dictionary.
        """
        self._check_platform()
        now = datetime.now(timezone.utc)
        data: dict[str, Any] = {"timestamp": now}

        # 1. CPU Ticks & Differential Utilization from /proc/stat
        stat_content = self._read_proc_file("stat")
        if stat_content is not None:
            curr_ticks = parse_cpu_ticks(stat_content)
            if curr_ticks is not None:
                # First collection returns None and records baseline; subsequent calculate delta
                data["cpu_percent"] = calculate_cpu_percent(
                    self._prev_cpu_ticks, curr_ticks
                )
                self._prev_cpu_ticks = curr_ticks
            else:
                data["cpu_percent"] = None
        else:
            data["cpu_percent"] = None

        # 2. System Load Averages from /proc/loadavg
        loadavg_content = self._read_proc_file("loadavg")
        if loadavg_content is not None:
            load_data = parse_loadavg(loadavg_content)
            if load_data is not None:
                data.update(load_data)
            else:
                data["load_avg_1m"] = None
                data["load_avg_5m"] = None
                data["load_avg_15m"] = None
        else:
            data["load_avg_1m"] = None
            data["load_avg_5m"] = None
            data["load_avg_15m"] = None

        # 3. Memory Metrics from /proc/meminfo
        meminfo_content = self._read_proc_file("meminfo")
        if meminfo_content is not None:
            raw_mem = parse_meminfo(meminfo_content)
            mem_metrics = calculate_memory_metrics(raw_mem)
            if mem_metrics is not None:
                data.update(mem_metrics)
            else:
                data["memory_total"] = None
                data["memory_used"] = None
                data["memory_percent"] = None
        else:
            data["memory_total"] = None
            data["memory_used"] = None
            data["memory_percent"] = None

        # 4. Disk I/O Bytes from /proc/diskstats
        diskstats_content = self._read_proc_file("diskstats")
        if diskstats_content is not None:
            diskstats_data = parse_diskstats(diskstats_content)
            if diskstats_data is not None:
                data.update(diskstats_data)
            else:
                data["disk_read_bytes"] = None
                data["disk_write_bytes"] = None
        else:
            data["disk_read_bytes"] = None
            data["disk_write_bytes"] = None

        # 5. Filesystem Usage from statvfs
        disk_usage = query_disk_usage(self.mount_point, self.statvfs_fn)
        data.update(disk_usage)

        return data

    def parse(self, raw_data: dict[str, Any]) -> dict[str, Any]:
        """Convert raw metrics dict into an OSIRIS observation dict."""
        ts = raw_data.get("timestamp") or datetime.now(timezone.utc)

        payload: dict[str, Any] = {
            "cpu_percent": raw_data.get("cpu_percent"),
            "load_avg_1m": raw_data.get("load_avg_1m"),
            "load_avg_5m": raw_data.get("load_avg_5m"),
            "load_avg_15m": raw_data.get("load_avg_15m"),
            "memory_total": raw_data.get("memory_total"),
            "memory_used": raw_data.get("memory_used"),
            "memory_percent": raw_data.get("memory_percent"),
            "memory_available": raw_data.get("memory_available"),
            "memory_free": raw_data.get("memory_free"),
            "buffers": raw_data.get("buffers"),
            "cached": raw_data.get("cached"),
            "swap_total": raw_data.get("swap_total"),
            "swap_used": raw_data.get("swap_used"),
            "swap_percent": raw_data.get("swap_percent"),
            "disk_read_bytes": raw_data.get("disk_read_bytes"),
            "disk_write_bytes": raw_data.get("disk_write_bytes"),
            "disk_usage_percent": raw_data.get("disk_usage_percent"),
            "disk_total_bytes": raw_data.get("disk_total_bytes"),
            "disk_used_bytes": raw_data.get("disk_used_bytes"),
            "timestamp_source": "collection_time",
        }

        return {
            "source": self.get_source_name(),
            "host_id": self.host_uuid,
            "event_type": "resource.snapshot",
            "action": "snapshot",
            "severity": "info",
            "observed_at": ts,
            "uid": None,
            "username": None,
            "pid": None,
            "ppid": None,
            "command": None,
            "process_id": None,
            "object_type": "system",
            "object_path": str(self.mount_point),
            "payload": payload,
        }

    def collect_observations(
        self, granular: bool = False
    ) -> list[RawObservation]:
        """Collect metrics and return ``RawObservation`` objects.

        Parameters
        ----------
        granular:
            If True, additionally produces separate `resource.cpu`, `resource.memory`,
            and `resource.disk` events matching `docs/event-model.md` §2.
            Defaults to False (producing the canonical consolidated `resource.snapshot`).

        Returns
        -------
        list[RawObservation]
            Observations ready for the Event Processing Layer.
        """
        raw_data = self.collect()
        obs_dict = self.parse(raw_data)
        observations = [RawObservation(**obs_dict)]

        if granular:
            ts = obs_dict["observed_at"]
            # 1. CPU granular event
            observations.append(
                RawObservation(
                    source=self.get_source_name(),
                    host_id=self.host_uuid,
                    event_type="resource.cpu",
                    action="snapshot",
                    severity="info",
                    observed_at=ts,
                    object_type="resource",
                    object_path="cpu",
                    payload={
                        "cpu_percent": raw_data.get("cpu_percent"),
                        "load_avg_1m": raw_data.get("load_avg_1m"),
                        "load_avg_5m": raw_data.get("load_avg_5m"),
                        "load_avg_15m": raw_data.get("load_avg_15m"),
                        "timestamp_source": "collection_time",
                    },
                )
            )
            # 2. Memory granular event
            observations.append(
                RawObservation(
                    source=self.get_source_name(),
                    host_id=self.host_uuid,
                    event_type="resource.memory",
                    action="snapshot",
                    severity="info",
                    observed_at=ts,
                    object_type="resource",
                    object_path="memory",
                    payload={
                        "memory_total": raw_data.get("memory_total"),
                        "memory_used": raw_data.get("memory_used"),
                        "memory_percent": raw_data.get("memory_percent"),
                        "memory_available": raw_data.get("memory_available"),
                        "timestamp_source": "collection_time",
                    },
                )
            )
            # 3. Disk granular event
            observations.append(
                RawObservation(
                    source=self.get_source_name(),
                    host_id=self.host_uuid,
                    event_type="resource.disk",
                    action="snapshot",
                    severity="info",
                    observed_at=ts,
                    object_type="resource",
                    object_path=str(self.mount_point),
                    payload={
                        "disk_read_bytes": raw_data.get("disk_read_bytes"),
                        "disk_write_bytes": raw_data.get("disk_write_bytes"),
                        "disk_usage_percent": raw_data.get("disk_usage_percent"),
                        "timestamp_source": "collection_time",
                    },
                )
            )

        return observations

    def reset(self) -> None:
        """Reset CPU baseline ticks and state."""
        self._prev_cpu_ticks = None

    def __enter__(self) -> ResourceCollector:
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()
        self.reset()
