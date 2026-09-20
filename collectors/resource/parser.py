"""Source-specific parsing utilities for OSIRIS Resource Collector.

Parses Linux `/proc` pseudo-filesystem files and standard library `os.statvfs`:
- `/proc/stat` -> system CPU tick counters and CPU utilization calculation
- `/proc/loadavg` -> 1m, 5m, 15m system load averages
- `/proc/meminfo` -> total, available, used memory and usage percentage
- `/proc/diskstats` -> whole block-device I/O sectors converted to bytes (512 bytes/sector)
- `os.statvfs` -> root filesystem disk usage percentage

Responsibilities:
- Strictly standard library (no `psutil`).
- Filters whole block devices (excludes partitions, loop, ram, and dm devices).
- Never fabricates values; returns `None` on missing or unreadable files.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger("osiris.collectors.resource")

# Linux standard: 512 bytes per sector for `/proc/diskstats`
SECTOR_SIZE_BYTES = 512

# Regex matching whole block devices (excluding partitions, loop devices, ramdisks, device-mapper)
WHOLE_DISK_PATTERN = re.compile(
    r"^(sd[a-z]+|nvme[0-9]+n[0-9]+|vd[a-z]+|xvd[a-z]+|hd[a-z]+|mmcblk[0-9]+)$"
)


def parse_cpu_ticks(content: str) -> dict[str, int] | None:
    """Parse aggregate CPU ticks from `/proc/stat`.

    Format of first line:
    cpu  user nice system idle iowait irq softirq steal guest guest_nice
    """
    for line in content.splitlines():
        if line.startswith("cpu "):
            parts = line.split()[1:]
            if len(parts) < 4:
                return None
            try:
                ticks = [int(p) for p in parts]
            except ValueError:
                return None

            # Pad to 10 fields if older kernel has fewer fields
            while len(ticks) < 10:
                ticks.append(0)

            user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice = ticks[
                :10
            ]

            idle_all = idle + iowait
            total = (
                user
                + nice
                + system
                + idle
                + iowait
                + irq
                + softirq
                + steal
                + guest
                + guest_nice
            )

            return {
                "user": user,
                "nice": nice,
                "system": system,
                "idle": idle,
                "iowait": iowait,
                "irq": irq,
                "softirq": softirq,
                "steal": steal,
                "guest": guest,
                "guest_nice": guest_nice,
                "idle_all": idle_all,
                "total": total,
            }

    return None


def calculate_cpu_percent(
    prev: dict[str, int] | None,
    curr: dict[str, int] | None,
) -> float | None:
    """Calculate system-wide CPU utilization percentage over [0.0, 100.0].

    Returns None if either sample is missing (e.g. on first collection).
    """
    if prev is None or curr is None:
        return None

    delta_total = curr["total"] - prev["total"]
    delta_idle = curr["idle_all"] - prev["idle_all"]

    if delta_total <= 0:
        return 0.0

    utilization = (1.0 - (delta_idle / delta_total)) * 100.0
    return round(max(0.0, min(100.0, utilization)), 2)


def parse_loadavg(content: str) -> dict[str, float] | None:
    """Parse 1m, 5m, and 15m system load averages from `/proc/loadavg`."""
    parts = content.strip().split()
    if len(parts) < 3:
        return None

    try:
        return {
            "load_avg_1m": float(parts[0]),
            "load_avg_5m": float(parts[1]),
            "load_avg_15m": float(parts[2]),
        }
    except ValueError:
        return None


def parse_meminfo(content: str) -> dict[str, int]:
    """Extract raw memory metrics (in kB) from `/proc/meminfo`."""
    metrics: dict[str, int] = {}
    for line in content.splitlines():
        if ":" not in line:
            continue
        key, rest = line.split(":", 1)
        tokens = rest.strip().split()
        if not tokens:
            continue
        try:
            metrics[key.strip()] = int(tokens[0])
        except ValueError:
            continue
    return metrics


def calculate_memory_metrics(raw: dict[str, int]) -> dict[str, Any] | None:
    """Calculate core DB memory columns and supplementary payload metrics.

    Units in returned dict: bytes (except percentages).
    """
    mem_total_kb = raw.get("MemTotal")
    if mem_total_kb is None or mem_total_kb <= 0:
        return None

    memory_total = mem_total_kb * 1024

    # Use MemAvailable if present (Linux 3.14+), otherwise fallback
    mem_available_kb = raw.get("MemAvailable")
    if mem_available_kb is not None:
        mem_used_kb = max(0, mem_total_kb - mem_available_kb)
    else:
        free_kb = raw.get("MemFree", 0)
        buf_kb = raw.get("Buffers", 0)
        cached_kb = raw.get("Cached", 0)
        mem_used_kb = max(0, mem_total_kb - free_kb - buf_kb - cached_kb)

    memory_used = mem_used_kb * 1024
    memory_percent = round((memory_used / memory_total) * 100.0, 2)

    # Supplementary payload metrics
    supp: dict[str, Any] = {
        "memory_total": memory_total,
        "memory_used": memory_used,
        "memory_percent": memory_percent,
        "memory_available": (mem_available_kb * 1024) if mem_available_kb is not None else None,
        "memory_free": (raw["MemFree"] * 1024) if "MemFree" in raw else None,
        "buffers": (raw["Buffers"] * 1024) if "Buffers" in raw else None,
        "cached": (raw["Cached"] * 1024) if "Cached" in raw else None,
    }

    swap_total_kb = raw.get("SwapTotal")
    swap_free_kb = raw.get("SwapFree")
    if swap_total_kb is not None and swap_total_kb > 0:
        swap_total = swap_total_kb * 1024
        swap_free = (swap_free_kb or 0) * 1024
        swap_used = max(0, swap_total - swap_free)
        supp["swap_total"] = swap_total
        supp["swap_used"] = swap_used
        supp["swap_percent"] = round((swap_used / swap_total) * 100.0, 2)
    else:
        supp["swap_total"] = 0
        supp["swap_used"] = 0
        supp["swap_percent"] = 0.0

    return supp


def parse_diskstats(content: str) -> dict[str, Any] | None:
    """Parse disk I/O metrics from `/proc/diskstats`.

    Filters for whole block devices only (excludes individual partitions,
    loop devices, ramdisks, and device-mapper entries).
    Multiplies sector counts by 512 bytes per sector.
    """
    total_sectors_read = 0
    total_sectors_written = 0
    matched_devices: list[str] = []

    for line in content.splitlines():
        parts = line.split()
        if len(parts) < 14:
            continue

        dev_name = parts[2]
        if not WHOLE_DISK_PATTERN.match(dev_name):
            continue

        try:
            sectors_read = int(parts[5])
            sectors_written = int(parts[9])
        except ValueError:
            continue

        matched_devices.append(dev_name)
        total_sectors_read += sectors_read
        total_sectors_written += sectors_written

    if not matched_devices:
        return None

    return {
        "disk_read_bytes": total_sectors_read * SECTOR_SIZE_BYTES,
        "disk_write_bytes": total_sectors_written * SECTOR_SIZE_BYTES,
        "matched_devices": matched_devices,
    }


def query_disk_usage(
    mount_point: str | Path = "/",
    statvfs_fn: Callable[[str], Any] | None = None,
) -> dict[str, Any]:
    """Query filesystem disk usage using standard library `os.statvfs`."""
    fn = statvfs_fn or os.statvfs
    path_str = str(mount_point)

    try:
        st = fn(path_str)
    except (PermissionError, OSError, ValueError) as exc:
        logger.warning("statvfs failed for %s: %s", path_str, exc)
        return {
            "disk_total_bytes": None,
            "disk_used_bytes": None,
            "disk_available_bytes": None,
            "disk_usage_percent": None,
        }

    total = st.f_blocks * st.f_frsize
    free = st.f_bfree * st.f_frsize
    available = st.f_bavail * st.f_frsize
    used = max(0, total - free)

    if total > 0:
        usage_percent = round(((total - available) / total) * 100.0, 2)
    else:
        usage_percent = 0.0

    return {
        "disk_total_bytes": total,
        "disk_used_bytes": used,
        "disk_available_bytes": available,
        "disk_usage_percent": usage_percent,
    }
