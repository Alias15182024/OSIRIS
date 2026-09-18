"""Source-specific parsing utilities for OSIRIS Filesystem Collector.

Transforms raw Linux inotify events into structured observation dictionaries
conforming to the OSIRIS RawObservation schema.

Responsibilities:
- Determine filesystem object type (file vs directory).
- Safely extract inode information when available without assuming path permanence.
- Map inotify mask bits to canonical event types (filesystem.create, filesystem.modify,
  filesystem.delete, filesystem.move) and actions (create, modify, delete, move).
- Construct paired rename/move observations containing both from_path and to_path.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from collectors.filesystem.inotify import (
    IN_ATTRIB,
    IN_CREATE,
    IN_DELETE,
    IN_DELETE_SELF,
    IN_ISDIR,
    IN_MODIFY,
    IN_MOVE_SELF,
    IN_MOVED_FROM,
    IN_MOVED_TO,
    InotifyEvent,
)


def determine_object_type(mask: int, path: Path | str | None = None) -> str:
    """Determine whether the observed entity is a file or directory.

    Checks the inotify mask flag first (``IN_ISDIR``). If not indicated by mask,
    checks the filesystem if the path is currently accessible. Defaults to ``"file"``.
    """
    if mask & IN_ISDIR:
        return "directory"

    if path is not None:
        try:
            p = Path(path)
            if p.is_dir():
                return "directory"
        except (OSError, ValueError):
            pass

    return "file"


def get_inode(path: Path | str | None) -> int | None:
    """Safely obtain the inode number for a given path.

    Returns None if the path does not exist, has been deleted, or is inaccessible.
    Never raises an exception.
    """
    if path is None:
        return None

    try:
        # Avoid following symlinks so we observe the actual symlink inode
        stat_res = os.stat(path, follow_symlinks=False)
        return stat_res.st_ino
    except (FileNotFoundError, PermissionError, OSError, ValueError):
        return None


def map_action_and_event_type(mask: int) -> tuple[str, str]:
    """Map inotify mask bits to an OSIRIS (action, event_type) tuple.

    Priority is given to primary lifecycle events:
    - Create: (create, filesystem.create)
    - Delete: (delete, filesystem.delete)
    - Move: (move, filesystem.move)
    - Modify: (modify, filesystem.modify)
    """
    if mask & IN_CREATE:
        return "create", "filesystem.create"
    if mask & (IN_DELETE | IN_DELETE_SELF):
        return "delete", "filesystem.delete"
    if mask & (IN_MOVED_FROM | IN_MOVED_TO | IN_MOVE_SELF):
        return "move", "filesystem.move"
    if mask & (IN_MODIFY | IN_ATTRIB):
        return "modify", "filesystem.modify"

    return "unknown", "filesystem.unknown"


def parse_inotify_event(
    event: InotifyEvent,
    host_id: uuid.UUID,
    observed_at: datetime | None = None,
) -> dict[str, Any]:
    """Convert an individual InotifyEvent into a RawObservation dictionary."""
    action, event_type = map_action_and_event_type(event.mask)
    obj_type = determine_object_type(event.mask, event.full_path)
    inode = get_inode(event.full_path)

    ts = observed_at or datetime.now(timezone.utc)

    payload: dict[str, Any] = {
        "name": event.name,
        "watch_path": str(event.dir_path),
        "inode": inode,
        "is_dir": event.is_dir,
        "mask": event.mask,
        "cookie": event.cookie,
        "timestamp_source": "collection_time",
    }

    # If it is a standalone move (e.g. moved out of watch tree)
    if event.mask & IN_MOVED_FROM:
        payload["from_path"] = str(event.full_path)
        payload["to_path"] = None
    elif event.mask & IN_MOVED_TO:
        payload["from_path"] = None
        payload["to_path"] = str(event.full_path)

    return {
        "source": "fs",
        "host_id": host_id,
        "event_type": event_type,
        "action": action,
        "severity": "info",
        "observed_at": ts,
        "uid": None,
        "username": None,
        "pid": None,
        "ppid": None,
        "command": None,
        "process_id": None,
        "object_type": obj_type,
        "object_path": str(event.full_path),
        "payload": payload,
    }


def parse_move_pair(
    from_event: InotifyEvent,
    to_event: InotifyEvent,
    host_id: uuid.UUID,
    observed_at: datetime | None = None,
) -> dict[str, Any]:
    """Combine paired IN_MOVED_FROM and IN_MOVED_TO events into a single move observation."""
    obj_type = determine_object_type(to_event.mask, to_event.full_path)
    inode = get_inode(to_event.full_path)
    ts = observed_at or datetime.now(timezone.utc)

    payload: dict[str, Any] = {
        "from_path": str(from_event.full_path),
        "to_path": str(to_event.full_path),
        "cookie": to_event.cookie,
        "inode": inode,
        "is_dir": to_event.is_dir,
        "mask": to_event.mask,
        "timestamp_source": "collection_time",
    }

    return {
        "source": "fs",
        "host_id": host_id,
        "event_type": "filesystem.move",
        "action": "move",
        "severity": "info",
        "observed_at": ts,
        "uid": None,
        "username": None,
        "pid": None,
        "ppid": None,
        "command": None,
        "process_id": None,
        "object_type": obj_type,
        "object_path": str(to_event.full_path),
        "payload": payload,
    }
