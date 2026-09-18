"""Linux Process Collector for OSIRIS.

Discovers and monitors running processes via the Linux ``/proc`` filesystem.
Produces ``RawObservation`` instances for the Event Processing Layer.

Lifecycle Strategy:
-------------------
The collector tracks running processes using a composite identity key:
``(pid, starttime)``, where ``starttime`` is the process boot-relative start
tick count from ``/proc/<pid>/stat``. This ensures that Linux PID reuse
cannot cause two separate processes to be conflated.

In differential polling mode (the default):
- Newly observed ``(pid, starttime)`` keys emit ``process.start`` events.
- Disappeared ``(pid, starttime)`` keys emit ``process.end`` events,
  preserving the last known process context from memory without attempting
  to read dead `/proc` entries.

Platform Policy:
----------------
Linux is the only supported operating system for real collection.
Attempting live collection against the default ``/proc`` on non-Linux
platforms (such as macOS) explicitly raises ``PlatformError``.
A custom ``proc_dir`` is supported strictly for deterministic unit tests
against mock directory trees.
"""

from __future__ import annotations

import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from backend.services.events.schemas import RawObservation
from collectors.base import BaseCollector
from collectors.process.parser import read_process_info

DEFAULT_PROC_DIR = "/proc"


class PlatformError(RuntimeError):
    """Raised when live collection is attempted on an unsupported OS."""


class ProcessCollector(BaseCollector):
    """Linux process activity collector reading from ``/proc``.

    Parameters
    ----------
    host_id:
        UUID or string identifying the monitored host.
    proc_dir:
        Path to the proc filesystem. Defaults to ``/proc``. Non-default
        paths are intended exclusively for mock unit testing.
    """

    def __init__(
        self,
        host_id: uuid.UUID | str,
        *,
        proc_dir: str | Path = DEFAULT_PROC_DIR,
    ) -> None:
        super().__init__(str(host_id))
        self.host_uuid = (
            host_id if isinstance(host_id, uuid.UUID) else uuid.UUID(str(host_id))
        )
        self.proc_dir = Path(proc_dir)

        # Process lifecycle tracking: (pid, starttime) -> last_known_info_dict
        self._known_processes: dict[tuple[int, Optional[int]], dict[str, Any]] = {}

    def get_source_name(self) -> str:
        """Return the source identifier for process observations."""
        return "proc"

    def _check_platform(self) -> None:
        """Ensure live collection is only executed on Linux."""
        if str(self.proc_dir) == DEFAULT_PROC_DIR and sys.platform != "linux":
            raise PlatformError(
                f"ProcessCollector requires Linux /proc (running on {sys.platform}). "
                "Real collection cannot be performed on non-Linux platforms."
            )

    def collect(self) -> list[dict[str, Any]]:
        """Scan the proc directory and return raw process info dictionaries.

        Returns
        -------
        list[dict[str, Any]]
            List of successfully read process metadata dictionaries.
        """
        self._check_platform()

        if not self.proc_dir.is_dir():
            return []

        processes: list[dict[str, Any]] = []

        try:
            entries = os.listdir(self.proc_dir)
        except (PermissionError, FileNotFoundError, OSError):
            return []

        for entry in entries:
            # PID directories are strictly digits
            if not entry.isdigit():
                continue

            pid_dir = self.proc_dir / entry
            info = read_process_info(pid_dir)
            if info is not None:
                processes.append(info)

        return processes

    def parse(self, raw_data: dict[str, Any]) -> dict[str, Any]:
        """Convert a raw process info dict into an observation dictionary.

        Maps Linux `/proc` fields to the OSIRIS observation contract.
        Does NOT assign event IDs, internal `process_id`, or normalize UTC.
        """
        return {
            "source": self.get_source_name(),
            "host_id": self.host_uuid,
            "event_type": "process.start",
            "action": "start",
            "severity": "info",
            "observed_at": datetime.now(timezone.utc),
            "uid": raw_data.get("uid"),
            "pid": raw_data.get("pid"),
            "ppid": raw_data.get("ppid"),
            "command": raw_data.get("command"),
            "process_id": None,  # OSIRIS identity: owned by Event Processing, not collector
            "object_type": "process",
            "object_path": raw_data.get("executable"),
            "payload": {
                "comm": raw_data.get("comm"),
                "state": raw_data.get("state"),
                "starttime": raw_data.get("starttime"),
                "executable": raw_data.get("executable"),
            },
        }

    def collect_observations(self, diff: bool = True) -> list[RawObservation]:
        """Perform a collection cycle and return ``RawObservation`` objects.

        Parameters
        ----------
        diff:
            When True (default), tracks process lifecycle across cycles.
            Emits ``process.start`` for newly observed processes and
            ``process.end`` for disappeared processes.
            When False, emits observations for all currently visible processes.

        Returns
        -------
        list[RawObservation]
            Observations ready for the Event Processing Layer.
        """
        raw_list = self.collect()
        now = datetime.now(timezone.utc)

        if not diff:
            # Snapshot mode: emit observations for all currently visible processes
            observations: list[RawObservation] = []
            for proc in raw_list:
                obs_dict = self.parse(proc)
                obs_dict["observed_at"] = now
                observations.append(RawObservation(**obs_dict))
            return observations

        # Differential polling mode: key by (pid, starttime)
        current_map: dict[tuple[int, Optional[int]], dict[str, Any]] = {
            (p["pid"], p.get("starttime")): p for p in raw_list
        }

        current_keys = set(current_map.keys())
        known_keys = set(self._known_processes.keys())

        new_keys = current_keys - known_keys
        exited_keys = known_keys - current_keys

        observations = []

        # 1. New processes -> process.start
        for key in sorted(new_keys, key=lambda k: k[0]):
            proc = current_map[key]
            obs_dict = self.parse(proc)
            obs_dict["observed_at"] = now
            observations.append(RawObservation(**obs_dict))

        # 2. Exited processes -> process.end (using preserved context)
        for key in sorted(exited_keys, key=lambda k: k[0]):
            old_proc = self._known_processes[key]
            exit_obs = RawObservation(
                source=self.get_source_name(),
                host_id=self.host_uuid,
                event_type="process.end",
                action="exit",
                severity="info",
                observed_at=now,
                uid=old_proc.get("uid"),
                pid=old_proc.get("pid"),
                ppid=old_proc.get("ppid"),
                command=old_proc.get("command"),
                process_id=None,
                object_type="process",
                object_path=old_proc.get("executable"),
                payload={
                    "comm": old_proc.get("comm"),
                    "state": old_proc.get("state"),
                    "starttime": old_proc.get("starttime"),
                    "last_known_executable": old_proc.get("executable"),
                },
            )
            observations.append(exit_obs)

        # Update known processes state for the next cycle
        self._known_processes = current_map

        return observations

    def reset(self) -> None:
        """Clear known processes state cache."""
        self._known_processes.clear()
