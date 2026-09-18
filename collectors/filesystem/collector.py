"""Linux Filesystem Activity Collector for OSIRIS.

Observes filesystem activity using Linux inotify notifications.
Produces ``RawObservation`` instances for the Event Processing Layer.

Architecture:
-------------
- Source identifier: ``"fs"``
- Notification mechanism: Linux inotify (standard library ctypes wrapper, no third-party deps).
- Event types: ``filesystem.create``, ``filesystem.modify``, ``filesystem.delete``, ``filesystem.move``.
- Actions: ``create``, ``modify``, ``delete``, ``move``.
- Rename correlation: Tracks inotify cookies across ``IN_MOVED_FROM`` and ``IN_MOVED_TO``
  to emit a unified ``filesystem.move`` observation containing both ``from_path`` and ``to_path``.
  Unpaired moves are safely preserved and emitted deterministically.
- Recursive watch management: Automatically registers new directories on creation or when moved
  into the watched tree; updates logical paths across subtrees when directories are renamed;
  and cleans up watches when directories are deleted or moved out.
- Platform Policy: Real collection requires Linux inotify. Non-Linux OS (macOS) raises
  ``PlatformError`` unless a custom backend (such as ``MockInotifyBackend``) is injected.
- Resource cleanup: Watches and file descriptors are properly closed on ``stop()``,
  ``close()``, or context manager exit.
"""

from __future__ import annotations

import logging
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.services.events.schemas import RawObservation
from collectors.base import BaseCollector
from collectors.filesystem.inotify import (
    DEFAULT_WATCH_MASK,
    IN_CREATE,
    IN_DELETE_SELF,
    IN_IGNORED,
    IN_ISDIR,
    IN_MOVED_FROM,
    IN_MOVED_TO,
    InotifyBackend,
    InotifyEvent,
    LinuxInotifyBackend,
)
from collectors.filesystem.parser import (
    determine_object_type,
    get_inode,
    map_action_and_event_type,
    parse_inotify_event,
    parse_move_pair,
)

logger = logging.getLogger("osiris.collectors.filesystem")


class PlatformError(RuntimeError):
    """Raised when live filesystem collection is attempted on an unsupported OS."""


class FilesystemCollector(BaseCollector):
    """Linux filesystem activity collector observing directory events via inotify.

    Parameters
    ----------
    host_id:
        UUID or string identifying the monitored host.
    watch_paths:
        Single path or list of paths (directories or files) to monitor.
    recursive:
        Whether to recursively monitor subdirectories within watched paths.
    backend:
        Optional ``InotifyBackend`` instance. If omitted, defaults to
        ``LinuxInotifyBackend`` (which requires Linux). Custom backends
        (e.g., ``MockInotifyBackend``) are used for cross-platform unit testing.
    """

    def __init__(
        self,
        host_id: uuid.UUID | str,
        watch_paths: list[str | Path] | str | Path | None = None,
        *,
        recursive: bool = False,
        backend: InotifyBackend | None = None,
    ) -> None:
        super().__init__(str(host_id))
        self.host_uuid = (
            host_id if isinstance(host_id, uuid.UUID) else uuid.UUID(str(host_id))
        )
        self.recursive = recursive

        self._check_platform(backend)
        self.backend = backend if backend is not None else LinuxInotifyBackend()

        # Track configured paths to watch
        self._initial_paths: list[Path] = []
        if watch_paths is not None:
            if isinstance(watch_paths, (str, Path)):
                self._initial_paths = [Path(watch_paths)]
            else:
                self._initial_paths = [Path(p) for p in watch_paths]

        # Active watch descriptor tracking: Path -> wd
        self._watches: dict[Path, int] = {}

        # If any paths were provided at initialization, add watches now
        for p in self._initial_paths:
            self.add_watch(p)

    @staticmethod
    def _check_platform(backend: InotifyBackend | None) -> None:
        """Ensure live collection is only executed on Linux."""
        if backend is None and sys.platform != "linux":
            raise PlatformError(
                f"FilesystemCollector requires Linux inotify (running on {sys.platform}). "
                "Real collection cannot be performed on non-Linux platforms."
            )

    def get_source_name(self) -> str:
        """Return the source identifier for filesystem observations."""
        return "fs"

    def add_watch(self, path: str | Path) -> bool:
        """Add a path to be monitored.

        Handles nonexistent paths and permission errors gracefully without crashing.
        If recursive=True and path is a directory, recursively watches all subdirectories.

        Returns
        -------
        bool
            True if the watch was successfully added, False otherwise.
        """
        p = Path(path).resolve()
        if not p.exists():
            logger.warning("Cannot watch nonexistent path: %s", p)
            return False

        try:
            wd = self.backend.add_watch(p, DEFAULT_WATCH_MASK)
            self._watches[p] = wd
        except (PermissionError, OSError) as exc:
            logger.warning("Failed to watch %s: %s", p, exc)
            return False

        if self.recursive and p.is_dir():
            try:
                for root, dirs, _ in os.walk(p):
                    for d in dirs:
                        sub = (Path(root) / d).resolve()
                        try:
                            sub_wd = self.backend.add_watch(sub, DEFAULT_WATCH_MASK)
                            self._watches[sub] = sub_wd
                        except (PermissionError, OSError):
                            continue
            except (PermissionError, OSError):
                pass

        return True

    def remove_watch(self, path: str | Path) -> bool:
        """Remove a watch on a path and any descendants."""
        p = Path(path).resolve()
        removed_wds = self.backend.remove_watch_by_path(p, recursive=self.recursive)
        if removed_wds:
            self._watches.pop(p, None)
            descendants = [
                sp for sp in list(self._watches.keys())
                if sp != p and sp.is_relative_to(p)
            ]
            for sp in descendants:
                self._watches.pop(sp, None)
            return True
        return False

    def _handle_directory_rename(self, old_path: Path, new_path: Path) -> None:
        """Update logical path mappings for a renamed or moved watched directory."""
        old_resolved = old_path.resolve()
        new_resolved = new_path.resolve()

        # 1. Update backend paths so subsequent inotify events resolve to new_path
        self.backend.update_watch_path(old_resolved, new_resolved)

        # 2. Update self._watches mapping
        if old_resolved in self._watches:
            wd = self._watches.pop(old_resolved)
            self._watches[new_resolved] = wd

        # Update descendant paths in self._watches
        descendants = [
            (p, wd)
            for p, wd in list(self._watches.items())
            if p != old_resolved and p.is_relative_to(old_resolved)
        ]
        for sub_old, sub_wd in descendants:
            rel = sub_old.relative_to(old_resolved)
            sub_new = (new_resolved / rel).resolve()
            self._watches.pop(sub_old, None)
            self._watches[sub_new] = sub_wd

        # 3. If recursive, ensure newly visible subdirectories are watched
        if self.recursive and new_resolved.is_dir():
            self.add_watch(new_resolved)

    def _handle_directory_moved_out(self, path: Path) -> None:
        """Clean up watches when a directory moves out of the watched tree."""
        resolved = path.resolve()
        self.backend.remove_watch_by_path(resolved, recursive=True)
        self._watches.pop(resolved, None)
        descendants = [
            p for p in list(self._watches.keys())
            if p != resolved and p.is_relative_to(resolved)
        ]
        for p in descendants:
            self._watches.pop(p, None)

    def _handle_directory_deleted(self, path: Path) -> None:
        """Clean up watches when a directory is deleted."""
        resolved = path.resolve()
        self.backend.remove_watch_by_path(resolved, recursive=True)
        self._watches.pop(resolved, None)
        descendants = [
            p for p in list(self._watches.keys())
            if p != resolved and p.is_relative_to(resolved)
        ]
        for p in descendants:
            self._watches.pop(p, None)

    def collect(self) -> list[dict[str, Any]]:
        """Drain raw inotify events from the backend and return as raw event dicts.

        Returns
        -------
        list[dict[str, Any]]
            Raw inotify event dictionaries.
        """
        raw_events = self.backend.read_events()
        results: list[dict[str, Any]] = []

        for ev in raw_events:
            # Automatic recursive directory registration (creation or moved-in)
            if self.recursive and (ev.mask & IN_ISDIR) and (ev.mask & (IN_CREATE | IN_MOVED_TO)):
                if ev.full_path.exists():
                    self.add_watch(ev.full_path)

            # Cleanup watches if directory was deleted
            if ev.mask & (IN_DELETE_SELF | IN_IGNORED):
                self._handle_directory_deleted(ev.full_path)

            results.append(
                {
                    "wd": ev.wd,
                    "mask": ev.mask,
                    "cookie": ev.cookie,
                    "name": ev.name,
                    "dir_path": str(ev.dir_path),
                    "full_path": str(ev.full_path),
                    "is_dir": ev.is_dir,
                }
            )

        return results

    def parse(self, raw_data: dict[str, Any]) -> dict[str, Any]:
        """Convert a raw filesystem event dict into an OSIRIS observation dict.

        Handles both single events and paired move dictionaries.
        Does NOT assign event IDs or normalize timestamps to UTC.
        """
        if raw_data.get("action") == "move" and "from_path" in raw_data.get(
            "payload", {}
        ):
            return raw_data

        mask = raw_data.get("mask", 0)
        action, event_type = map_action_and_event_type(mask)
        full_path = raw_data.get("full_path")
        obj_type = determine_object_type(mask, full_path)
        inode = get_inode(full_path)

        payload: dict[str, Any] = {
            "name": raw_data.get("name", ""),
            "watch_path": raw_data.get("dir_path", ""),
            "inode": inode,
            "is_dir": raw_data.get("is_dir", False),
            "mask": mask,
            "cookie": raw_data.get("cookie", 0),
            "timestamp_source": "collection_time",
        }

        if mask & IN_MOVED_FROM:
            payload["from_path"] = full_path
            payload["to_path"] = None
        elif mask & IN_MOVED_TO:
            payload["from_path"] = None
            payload["to_path"] = full_path

        return {
            "source": self.get_source_name(),
            "host_id": self.host_uuid,
            "event_type": event_type,
            "action": action,
            "severity": "info",
            "observed_at": datetime.now(timezone.utc),
            "uid": None,
            "username": None,
            "pid": None,
            "ppid": None,
            "command": None,
            "process_id": None,
            "object_type": obj_type,
            "object_path": full_path,
            "payload": payload,
        }

    def collect_observations(self) -> list[RawObservation]:
        """Collect and convert filesystem notifications into ``RawObservation`` objects.

        Correlates inotify ``cookie`` identifiers across ``IN_MOVED_FROM`` and
        ``IN_MOVED_TO`` into a single ``filesystem.move`` observation containing
        both ``from_path`` and ``to_path``.

        Returns
        -------
        list[RawObservation]
            Observations ready for the Event Processing Layer.
        """
        raw_events = self.backend.read_events()
        now = datetime.now(timezone.utc)
        observations: list[RawObservation] = []

        # Cookie correlation buffer: cookie -> IN_MOVED_FROM event
        pending_moves: dict[int, InotifyEvent] = {}

        for ev in raw_events:
            # Handle automatic recursion for newly created or moved-in directories
            if self.recursive and (ev.mask & IN_ISDIR) and (ev.mask & (IN_CREATE | IN_MOVED_TO)):
                if ev.full_path.exists():
                    self.add_watch(ev.full_path)

            # Cleanup watch mapping if watched directory was deleted
            if ev.mask & (IN_DELETE_SELF | IN_IGNORED):
                self._handle_directory_deleted(ev.full_path)

            # Move pairing logic
            if (ev.mask & IN_MOVED_FROM) and ev.cookie > 0:
                pending_moves[ev.cookie] = ev
                continue

            if (ev.mask & IN_MOVED_TO) and ev.cookie > 0:
                if ev.cookie in pending_moves:
                    from_ev = pending_moves.pop(ev.cookie)
                    # If this move involves a watched directory, update logical watch paths
                    if (ev.mask & IN_ISDIR) or (from_ev.mask & IN_ISDIR):
                        self._handle_directory_rename(from_ev.full_path, ev.full_path)
                    obs_dict = parse_move_pair(
                        from_ev, ev, self.host_uuid, observed_at=now
                    )
                    observations.append(RawObservation(**obs_dict))
                else:
                    # Unpaired move-to (moved in from outside watched paths)
                    obs_dict = parse_inotify_event(
                        ev, self.host_uuid, observed_at=now
                    )
                    observations.append(RawObservation(**obs_dict))
                continue

            # Standard events (create, modify, delete, etc.)
            obs_dict = parse_inotify_event(ev, self.host_uuid, observed_at=now)
            observations.append(RawObservation(**obs_dict))

        # Emit any remaining unpaired IN_MOVED_FROM (moved out of watched paths)
        for _, from_ev in pending_moves.items():
            if from_ev.mask & IN_ISDIR:
                self._handle_directory_moved_out(from_ev.full_path)
            obs_dict = parse_inotify_event(from_ev, self.host_uuid, observed_at=now)
            observations.append(RawObservation(**obs_dict))

        return observations

    def close(self) -> None:
        """Close backend and release resources."""
        self.backend.close()
        self._watches.clear()

    def __enter__(self) -> FilesystemCollector:
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()
        self.close()
