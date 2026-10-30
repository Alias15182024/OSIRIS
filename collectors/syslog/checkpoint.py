"""Log checkpoint and rotation cursor management for OSIRIS (Phase 2 Milestone 2.3).

Provides robust file cursor tracking to support:
- Incremental log reading without re-ingesting already-processed lines.
- Safe log rotation detection via inode and device identification.
- Truncation detection (e.g. copytruncate).
- Rotated file draining (e.g. reading remainder of .1 file before switching to active log).
- Serialization/deserialization for cursor persistence across collector restarts.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, Optional

logger = logging.getLogger("osiris.collectors.syslog.checkpoint")


@dataclass
class LogCursor:
    """Tracks position and file identity for incremental log ingestion."""

    path: str
    inode: Optional[int] = None
    device: Optional[int] = None
    offset: int = 0
    lines_read: int = 0
    last_read_at: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> LogCursor:
        return cls(
            path=data["path"],
            inode=data.get("inode"),
            device=data.get("device"),
            offset=data.get("offset", 0),
            lines_read=data.get("lines_read", 0),
            last_read_at=data.get("last_read_at"),
        )


class CheckpointManager:
    """Manages incremental log file reading, rotation detection, and checkpoint state."""

    def __init__(
        self,
        cursor: LogCursor | None = None,
        checkpoint_file: Path | str | None = None,
    ) -> None:
        self.cursor = cursor
        self.checkpoint_file = Path(checkpoint_file) if checkpoint_file else None

        if self.cursor is None and self.checkpoint_file and self.checkpoint_file.is_file():
            self.load()

    def load(self) -> None:
        """Load cursor state from the checkpoint file."""
        if not self.checkpoint_file or not self.checkpoint_file.is_file():
            return
        try:
            with open(self.checkpoint_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.cursor = LogCursor.from_dict(data)
        except Exception as e:
            logger.warning(
                "Failed to load syslog checkpoint from %s: %s",
                self.checkpoint_file,
                e,
            )

    def save(self) -> None:
        """Persist current cursor state to the checkpoint file."""
        if not self.checkpoint_file or self.cursor is None:
            return
        try:
            self.checkpoint_file.parent.mkdir(parents=True, exist_ok=True)
            tmp_file = self.checkpoint_file.with_name(f"{self.checkpoint_file.name}.tmp")
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump(self.cursor.to_dict(), f, indent=2)
            os.replace(tmp_file, self.checkpoint_file)
        except Exception as e:
            logger.warning(
                "Failed to save syslog checkpoint to %s: %s",
                self.checkpoint_file,
                e,
            )

    def read_new_lines(
        self, target_path: Path | str
    ) -> Generator[str, None, None]:
        """Read new lines from target_path since last checkpoint.

        Detects file rotation (inode change) and file truncation, reading the
        remainder of any rotated file (`target_path.1`) when available.
        Updates internal cursor offset and metadata as lines are yielded.
        """
        path = Path(target_path)
        if not path.exists():
            return

        try:
            stat_res = path.stat()
        except OSError as e:
            logger.warning("Failed to stat log file %s: %s", path, e)
            return

        current_ino = stat_res.st_ino
        current_dev = stat_res.st_dev
        current_size = stat_res.st_size

        if self.cursor is None or self.cursor.path != str(path):
            self.cursor = LogCursor(
                path=str(path),
                inode=current_ino,
                device=current_dev,
                offset=0,
                lines_read=0,
            )

        # 1. Detect rotation (inode or device changed)
        if self.cursor.inode is not None and (
            self.cursor.inode != current_ino or self.cursor.device != current_dev
        ):
            # File rotated. Check if old file was renamed (e.g. auth.log.1, auth.log-YYYYMMDD)
            candidates = [path.with_name(f"{path.name}.1")]
            if path.parent.is_dir():
                try:
                    for sibling in path.parent.glob(f"{path.name}*"):
                        if sibling != path and sibling not in candidates:
                            candidates.append(sibling)
                except OSError:
                    pass

            for cand in candidates:
                if cand.is_file():
                    try:
                        rot_stat = cand.stat()
                        if (
                            rot_stat.st_ino == self.cursor.inode
                            and rot_stat.st_dev == self.cursor.device
                        ):
                            # Drain remainder of rotated file
                            yield from self._drain_file_from_offset(
                                cand, self.cursor.offset
                            )
                            break
                    except OSError:
                        pass

            # Reset cursor for new file
            self.cursor.inode = current_ino
            self.cursor.device = current_dev
            self.cursor.offset = 0

        # 2. Detect truncation (size < offset)
        elif current_size < self.cursor.offset:
            logger.info(
                "Log file %s truncated (size %d < offset %d); resetting cursor",
                path,
                current_size,
                self.cursor.offset,
            )
            self.cursor.offset = 0

        # 3. Read active file from cursor offset
        yield from self._read_active_file(path)

    def _drain_file_from_offset(
        self, path: Path, offset: int
    ) -> Generator[str, None, None]:
        """Read remainder of a rotated file from offset to EOF."""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(offset)
                for line in f:
                    self.cursor.lines_read += 1
                    yield line
        except OSError as e:
            logger.warning("Failed to drain rotated log %s: %s", path, e)

    def _read_active_file(self, path: Path) -> Generator[str, None, None]:
        """Read lines from active file, updating cursor offset after each line."""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(self.cursor.offset)
                while True:
                    line_start = f.tell()
                    line = f.readline()
                    if not line:
                        break
                    # If line does not end with newline, it is an incomplete in-flight write at EOF
                    if not line.endswith(("\n", "\r\n", "\r")):
                        f.seek(line_start)
                        break
                    self.cursor.offset = f.tell()
                    self.cursor.lines_read += 1
                    self.cursor.last_read_at = datetime.now(timezone.utc).isoformat()
                    yield line
        except OSError as e:
            logger.warning("Failed to read log file %s: %s", path, e)
