"""Linux Process Collector package for OSIRIS.

Exports:
- ``ProcessCollector``: Main collector discovering process activity from ``/proc``.
- ``PlatformError``: Exception raised when running live collection on non-Linux OS.
- ``parse_stat``, ``parse_cmdline``, ``parse_status``, ``read_process_info``: Parsing utilities.
"""

from collectors.process.collector import PlatformError, ProcessCollector
from collectors.process.parser import (
    parse_cmdline,
    parse_stat,
    parse_status,
    read_process_info,
)

__all__ = [
    "PlatformError",
    "ProcessCollector",
    "parse_cmdline",
    "parse_stat",
    "parse_status",
    "read_process_info",
]
