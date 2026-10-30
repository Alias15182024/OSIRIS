"""Security and System Log Collector for OSIRIS (Phase 2 Milestone 2.3).

Collects authentication, privilege escalation, and security-relevant
system log events from `/var/log/auth.log`, `/var/log/secure`, or syslog.

Conforms to the ``BaseCollector`` interface:
- Collects raw log lines using cursor-based incremental checkpoints.
- Parses records via ``SyslogParser`` into structured observations.
- Handles missing or inaccessible log files gracefully without crashing.
- Emits structured ``RawObservation`` instances for the Event Processing Layer.
"""

from __future__ import annotations

import logging
import os
import uuid
from pathlib import Path
from typing import Any, Optional

from backend.services.events.schemas import RawObservation
from collectors.base import BaseCollector
from collectors.syslog.checkpoint import CheckpointManager, LogCursor
from collectors.syslog.parser import SyslogParser

logger = logging.getLogger("osiris.collectors.syslog")

# Standard distribution log paths to check in order
DEFAULT_LOG_CANDIDATES = [
    Path("/var/log/auth.log"),  # Debian, Ubuntu, Kali
    Path("/var/log/secure"),    # RHEL, CentOS, Fedora, Rocky, Alma
    Path("/var/log/syslog"),    # General Debian/Ubuntu syslog fallback
    Path("/var/log/messages"),  # General RHEL/CentOS messages fallback
]


class SyslogCollector(BaseCollector):
    """Collector for Linux authentication and syslog event streams."""

    def __init__(
        self,
        host_id: str | uuid.UUID,
        log_path: Path | str | None = None,
        checkpoint_manager: CheckpointManager | None = None,
        default_year: int | None = None,
    ) -> None:
        super().__init__(str(host_id))
        self.host_uuid = (
            host_id if isinstance(host_id, uuid.UUID) else uuid.UUID(str(host_id))
        )
        self.log_path = Path(log_path) if log_path else self._detect_log_path()
        self.checkpoint_mgr = checkpoint_manager or CheckpointManager()
        self.parser = SyslogParser(default_year=default_year)
        self._last_error: Optional[str] = None

    def _detect_log_path(self) -> Path:
        """Autodetect available authentication log path on current system."""
        for candidate in DEFAULT_LOG_CANDIDATES:
            if candidate.is_file():
                return candidate
        # Default fallback even if not currently created
        return DEFAULT_LOG_CANDIDATES[0]

    def get_source_name(self) -> str:
        """Return the source identifier for syslog events."""
        return "syslog"

    def collect(self) -> list[dict[str, Any]]:
        """Collect raw log lines since last checkpoint.

        Returns a list of raw line observation dictionaries:
        ``[{"raw_line": str, "source_file": str}]``.
        """
        self._last_error = None
        if not self.log_path or not self.log_path.exists():
            return []

        # Check read permissions safely
        if not os.access(self.log_path, os.R_OK):
            msg = f"Cannot read log file {self.log_path}: permission denied"
            logger.warning(msg)
            self._last_error = msg
            return []

        raw_observations: list[dict[str, Any]] = []
        try:
            for line in self.checkpoint_mgr.read_new_lines(self.log_path):
                stripped = line.strip()
                if stripped:
                    raw_observations.append({
                        "raw_line": stripped,
                        "source_file": str(self.log_path),
                    })
            self.checkpoint_mgr.save()
        except OSError as e:
            msg = f"Error reading log file {self.log_path}: {e}"
            logger.warning(msg)
            self._last_error = msg
            return []

        return raw_observations

    def parse(self, raw_data: dict[str, Any]) -> dict[str, Any]:
        """Parse a single raw line observation into a structured observation dict."""
        raw_line = raw_data.get("raw_line", "")
        parsed = self.parser.parse_line(raw_line)
        if parsed is None:
            return {}

        obs_dict = parsed.to_observation_dict(str(self.host_uuid))
        if "source_file" in raw_data:
            obs_dict.setdefault("payload", {})["source_file"] = raw_data["source_file"]

        return obs_dict

    def collect_observations(self) -> list[RawObservation]:
        """High-level method returning validated RawObservation instances."""
        raw_items = self.collect()
        observations: list[RawObservation] = []

        for item in raw_items:
            parsed_dict = self.parse(item)
            if not parsed_dict:
                continue

            try:
                obs = RawObservation(
                    source=parsed_dict.get("source", "syslog"),
                    host_id=self.host_uuid,
                    event_type=parsed_dict.get("event_type", "syslog.event"),
                    action=parsed_dict.get("action", "syslog"),
                    severity=parsed_dict.get("severity", "info"),
                    observed_at=parsed_dict.get("observed_at"),
                    uid=parsed_dict.get("uid"),
                    username=parsed_dict.get("username"),
                    pid=parsed_dict.get("pid"),
                    command=parsed_dict.get("command"),
                    success=parsed_dict.get("success"),
                    payload=parsed_dict.get("payload"),
                )
                observations.append(obs)
            except Exception as e:
                logger.warning("Failed to validate RawObservation for log line: %s", e)

        return observations

    @property
    def last_error(self) -> Optional[str]:
        """Return the last encountered collection error, if any."""
        return self._last_error
