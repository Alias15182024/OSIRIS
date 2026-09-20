"""Linux Resource Collector package for OSIRIS.

Exports:
- ``ResourceCollector``: Main collector measuring CPU, memory, load, and disk from ``/proc`` and ``os.statvfs``.
- ``PlatformError``: Exception raised when running live collection on non-Linux OS.
- Parsing utilities: ``parse_cpu_ticks``, ``calculate_cpu_percent``, ``parse_loadavg``,
  ``parse_meminfo``, ``calculate_memory_metrics``, ``parse_diskstats``, ``query_disk_usage``.
"""

from collectors.resource.collector import PlatformError, ResourceCollector
from collectors.resource.parser import (
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

__all__ = [
    "PlatformError",
    "ResourceCollector",
    "SECTOR_SIZE_BYTES",
    "WHOLE_DISK_PATTERN",
    "calculate_cpu_percent",
    "calculate_memory_metrics",
    "parse_cpu_ticks",
    "parse_diskstats",
    "parse_loadavg",
    "parse_meminfo",
    "query_disk_usage",
]
