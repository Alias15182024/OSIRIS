"""Linux inotify interface for OSIRIS Filesystem Collector.

Provides low-level access to Linux inotify syscalls via ctypes and Python standard
library facilities, without third-party dependencies.

Supports:
- Standard inotify event mask constants.
- ``InotifyEvent`` structured dataclass.
- ``LinuxInotifyBackend``: Direct Linux kernel inotify via libc.
- ``MockInotifyBackend``: In-memory deterministic event queue for cross-platform
  testing (macOS, Windows, CI).
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import select
import struct
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# ============================================================================
# 1. INOTIFY CONSTANTS (Linux sys/inotify.h)
# ============================================================================

IN_ACCESS = 0x00000001
IN_MODIFY = 0x00000002
IN_ATTRIB = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_CLOSE_NOWRITE = 0x00000010
IN_OPEN = 0x00000020
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_UNMOUNT = 0x00002000
IN_Q_OVERFLOW = 0x00004000
IN_IGNORED = 0x00008000
IN_ISDIR = 0x40000000

# Default events observed by OSIRIS Phase 1.4B
DEFAULT_WATCH_MASK = (
    IN_CREATE
    | IN_DELETE
    | IN_MODIFY
    | IN_ATTRIB
    | IN_MOVED_FROM
    | IN_MOVED_TO
    | IN_DELETE_SELF
    | IN_MOVE_SELF
)

# Struct header size: int wd (4), uint32 mask (4), uint32 cookie (4), uint32 len (4) = 16 bytes
INOTIFY_EVENT_HEADER_FORMAT = "=iIII"
INOTIFY_EVENT_HEADER_SIZE = struct.calcsize(INOTIFY_EVENT_HEADER_FORMAT)


@dataclass(frozen=True)
class InotifyEvent:
    """Structured inotify event.

    Attributes
    ----------
    wd:
        Watch descriptor associated with the event.
    mask:
        Bitmask describing the observed filesystem event.
    cookie:
        Correlation ID connecting paired rename/move events (IN_MOVED_FROM / IN_MOVED_TO).
    name:
        Relative file or directory name within the watched directory.
    dir_path:
        Path of the watched directory.
    full_path:
        Fully resolved path of the target file or directory.
    """

    wd: int
    mask: int
    cookie: int
    name: str
    dir_path: Path
    full_path: Path

    @property
    def is_dir(self) -> bool:
        """Whether this event targets a directory."""
        return bool(self.mask & IN_ISDIR)


class InotifyBackend(ABC):
    """Abstract interface for inotify event providers."""

    @abstractmethod
    def add_watch(self, path: Path, mask: int = DEFAULT_WATCH_MASK) -> int:
        """Register a path for filesystem notifications.

        Returns the allocated watch descriptor.
        """

    @abstractmethod
    def rm_watch(self, wd: int) -> None:
        """Remove a watch descriptor."""

    @abstractmethod
    def read_events(self) -> list[InotifyEvent]:
        """Read currently available inotify events without blocking indefinitely."""

    @abstractmethod
    def close(self) -> None:
        """Clean up and close any open resources."""

    @abstractmethod
    def get_path_for_wd(self, wd: int) -> Path | None:
        """Return the directory path associated with a watch descriptor."""

    @abstractmethod
    def get_wd_for_path(self, path: Path) -> int | None:
        """Return the watch descriptor associated with a directory path."""

    @abstractmethod
    def update_watch_path(self, old_path: Path, new_path: Path) -> None:
        """Update path mapping for a watched directory and any descendants."""

    @abstractmethod
    def remove_watch_by_path(self, path: Path, recursive: bool = True) -> list[int]:
        """Remove watch descriptor(s) for a path and optionally its descendants."""


class LinuxInotifyBackend(InotifyBackend):
    """Real Linux inotify backend communicating with libc."""

    def __init__(self) -> None:
        if sys.platform != "linux":
            raise RuntimeError(
                f"LinuxInotifyBackend requires Linux (running on {sys.platform})"
            )

        libc_name = ctypes.util.find_library("c") or "libc.so.6"
        self._libc = ctypes.CDLL(libc_name, use_errno=True)

        # inotify_init1(int flags)
        self._libc.inotify_init1.argtypes = [ctypes.c_int]
        self._libc.inotify_init1.restype = ctypes.c_int

        # inotify_add_watch(int fd, const char *pathname, uint32_t mask)
        self._libc.inotify_add_watch.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint32,
        ]
        self._libc.inotify_add_watch.restype = ctypes.c_int

        # inotify_rm_watch(int fd, int wd)
        self._libc.inotify_rm_watch.argtypes = [ctypes.c_int, ctypes.c_int]
        self._libc.inotify_rm_watch.restype = ctypes.c_int

        # Flags: O_NONBLOCK (0x800) | O_CLOEXEC (0x80000)
        flags = getattr(os, "O_NONBLOCK", 0x800) | getattr(os, "O_CLOEXEC", 0x80000)
        self._fd = self._libc.inotify_init1(flags)
        if self._fd < 0:
            errno = ctypes.get_errno()
            raise OSError(errno, f"inotify_init1 failed: {os.strerror(errno)}")

        self._wd_to_path: dict[int, Path] = {}
        self._path_to_wd: dict[Path, int] = {}
        self._closed = False

    def add_watch(self, path: Path, mask: int = DEFAULT_WATCH_MASK) -> int:
        """Register a path for filesystem notifications."""
        if self._closed:
            raise RuntimeError("Cannot add watch to closed inotify backend")

        resolved_path = path.resolve()
        if resolved_path in self._path_to_wd:
            return self._path_to_wd[resolved_path]

        path_bytes = str(resolved_path).encode("utf-8")

        wd = self._libc.inotify_add_watch(self._fd, path_bytes, mask)
        if wd < 0:
            errno = ctypes.get_errno()
            raise OSError(
                errno,
                f"inotify_add_watch failed for {resolved_path}: {os.strerror(errno)}",
            )

        self._wd_to_path[wd] = resolved_path
        self._path_to_wd[resolved_path] = wd
        return wd

    def rm_watch(self, wd: int) -> None:
        """Remove a watch descriptor."""
        if self._closed:
            return

        if wd in self._wd_to_path:
            resolved_path = self._wd_to_path.pop(wd)
            self._path_to_wd.pop(resolved_path, None)
            self._libc.inotify_rm_watch(self._fd, wd)

    def get_path_for_wd(self, wd: int) -> Path | None:
        """Return the directory path associated with a watch descriptor."""
        return self._wd_to_path.get(wd)

    def get_wd_for_path(self, path: Path) -> int | None:
        """Return the watch descriptor associated with a directory path."""
        return self._path_to_wd.get(path.resolve())

    def update_watch_path(self, old_path: Path, new_path: Path) -> None:
        """Update path mapping for a watched directory and any descendants."""
        old_resolved = old_path.resolve()
        new_resolved = new_path.resolve()

        if old_resolved in self._path_to_wd:
            wd = self._path_to_wd.pop(old_resolved)
            self._path_to_wd[new_resolved] = wd
            self._wd_to_path[wd] = new_resolved

        descendants = [
            (p, wd)
            for p, wd in list(self._path_to_wd.items())
            if p != old_resolved and p.is_relative_to(old_resolved)
        ]
        for sub_old, sub_wd in descendants:
            rel = sub_old.relative_to(old_resolved)
            sub_new = new_resolved / rel
            self._path_to_wd.pop(sub_old, None)
            self._path_to_wd[sub_new] = sub_wd
            self._wd_to_path[sub_wd] = sub_new

    def remove_watch_by_path(self, path: Path, recursive: bool = True) -> list[int]:
        """Remove watch descriptor(s) for a path and optionally its descendants."""
        resolved = path.resolve()
        targets: list[tuple[Path, int]] = []
        if resolved in self._path_to_wd:
            targets.append((resolved, self._path_to_wd[resolved]))

        if recursive:
            for p, wd in list(self._path_to_wd.items()):
                if p != resolved and p.is_relative_to(resolved):
                    targets.append((p, wd))

        removed_wds: list[int] = []
        for _, wd in targets:
            self.rm_watch(wd)
            removed_wds.append(wd)

        return removed_wds

    def read_events(self) -> list[InotifyEvent]:
        """Read currently available inotify events without blocking."""
        if self._closed:
            return []

        # Check if fd is readable without blocking
        r, _, _ = select.select([self._fd], [], [], 0.0)
        if not r:
            return []

        events: list[InotifyEvent] = []
        try:
            # Read up to 64KB buffer of inotify events
            buf = os.read(self._fd, 65536)
        except (BlockingIOError, InterruptedError):
            return []
        except OSError:
            return []

        offset = 0
        buf_len = len(buf)

        while offset + INOTIFY_EVENT_HEADER_SIZE <= buf_len:
            wd, mask, cookie, name_len = struct.unpack_from(
                INOTIFY_EVENT_HEADER_FORMAT, buf, offset
            )
            offset += INOTIFY_EVENT_HEADER_SIZE

            name = ""
            if name_len > 0:
                raw_name = buf[offset : offset + name_len]
                offset += name_len
                name = raw_name.rstrip(b"\x00").decode("utf-8", errors="replace")

            dir_path = self._wd_to_path.get(wd, Path("."))
            full_path = (dir_path / name) if name else dir_path

            events.append(
                InotifyEvent(
                    wd=wd,
                    mask=mask,
                    cookie=cookie,
                    name=name,
                    dir_path=dir_path,
                    full_path=full_path,
                )
            )

            # If the watch was removed by the kernel (e.g. IN_IGNORED), clean up internal tracking
            if mask & IN_IGNORED:
                if wd in self._wd_to_path:
                    p = self._wd_to_path.pop(wd)
                    self._path_to_wd.pop(p, None)

        return events

    def close(self) -> None:
        """Close inotify file descriptor and clear watches."""
        if not self._closed:
            self._closed = True
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._wd_to_path.clear()
            self._path_to_wd.clear()


class MockInotifyBackend(InotifyBackend):
    """In-memory inotify backend for cross-platform deterministic unit tests."""

    def __init__(self) -> None:
        self._next_wd = 1
        self._wd_to_path: dict[int, Path] = {}
        self._path_to_wd: dict[Path, int] = {}
        self._queue: list[InotifyEvent] = []
        self._closed = False

    def add_watch(self, path: Path, mask: int = DEFAULT_WATCH_MASK) -> int:
        """Simulate adding a watch."""
        if self._closed:
            raise RuntimeError("Cannot add watch to closed inotify backend")

        resolved = path.resolve()
        if resolved in self._path_to_wd:
            return self._path_to_wd[resolved]

        wd = self._next_wd
        self._next_wd += 1
        self._wd_to_path[wd] = resolved
        self._path_to_wd[resolved] = wd
        return wd

    def rm_watch(self, wd: int) -> None:
        """Simulate removing a watch."""
        if wd in self._wd_to_path:
            p = self._wd_to_path.pop(wd)
            self._path_to_wd.pop(p, None)

    def get_path_for_wd(self, wd: int) -> Path | None:
        """Return directory path for watch descriptor."""
        return self._wd_to_path.get(wd)

    def get_wd_for_path(self, path: Path) -> int | None:
        """Return watch descriptor for directory path."""
        return self._path_to_wd.get(path.resolve())

    def update_watch_path(self, old_path: Path, new_path: Path) -> None:
        """Update path mapping for a watched directory and any descendants."""
        old_resolved = old_path.resolve()
        new_resolved = new_path.resolve()

        if old_resolved in self._path_to_wd:
            wd = self._path_to_wd.pop(old_resolved)
            self._path_to_wd[new_resolved] = wd
            self._wd_to_path[wd] = new_resolved

        descendants = [
            (p, wd)
            for p, wd in list(self._path_to_wd.items())
            if p != old_resolved and p.is_relative_to(old_resolved)
        ]
        for sub_old, sub_wd in descendants:
            rel = sub_old.relative_to(old_resolved)
            sub_new = new_resolved / rel
            self._path_to_wd.pop(sub_old, None)
            self._path_to_wd[sub_new] = sub_wd
            self._wd_to_path[sub_wd] = sub_new

    def remove_watch_by_path(self, path: Path, recursive: bool = True) -> list[int]:
        """Remove watch descriptor(s) for a path and optionally its descendants."""
        resolved = path.resolve()
        targets: list[tuple[Path, int]] = []
        if resolved in self._path_to_wd:
            targets.append((resolved, self._path_to_wd[resolved]))

        if recursive:
            for p, wd in list(self._path_to_wd.items()):
                if p != resolved and p.is_relative_to(resolved):
                    targets.append((p, wd))

        removed_wds: list[int] = []
        for _, wd in targets:
            self.rm_watch(wd)
            removed_wds.append(wd)

        return removed_wds

    def inject_event(
        self,
        *,
        wd: int,
        mask: int,
        name: str = "",
        cookie: int = 0,
        dir_path: Path | None = None,
        full_path: Path | None = None,
    ) -> InotifyEvent:
        """Convenience method for unit tests to inject a synthetic event."""
        resolved_dir = dir_path or self._wd_to_path.get(wd, Path("/mock/watch"))
        resolved_full = full_path or ((resolved_dir / name) if name else resolved_dir)

        event = InotifyEvent(
            wd=wd,
            mask=mask,
            cookie=cookie,
            name=name,
            dir_path=resolved_dir,
            full_path=resolved_full,
        )
        self._queue.append(event)
        return event

    def read_events(self) -> list[InotifyEvent]:
        """Drain and return queued synthetic events."""
        if self._closed:
            return []
        events = list(self._queue)
        self._queue.clear()
        return events

    def close(self) -> None:
        """Clean up mock backend state."""
        self._closed = True
        self._queue.clear()
        self._wd_to_path.clear()
        self._path_to_wd.clear()
