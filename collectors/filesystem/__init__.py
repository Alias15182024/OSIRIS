"""Linux Filesystem Collector package for OSIRIS.

Exports:
- ``FilesystemCollector``: Main collector observing filesystem activity via Linux inotify.
- ``PlatformError``: Exception raised when running live collection on non-Linux OS.
- ``InotifyBackend``, ``LinuxInotifyBackend``, ``MockInotifyBackend``: Low-level backends.
- ``InotifyEvent``: Event representation dataclass.
- Inotify constants (``IN_CREATE``, ``IN_MODIFY``, ``IN_DELETE``, ``IN_MOVED_FROM``, ``IN_MOVED_TO``, etc.).
- Parsing utilities (``determine_object_type``, ``get_inode``, ``map_action_and_event_type``, ``parse_inotify_event``, ``parse_move_pair``).
"""

from collectors.filesystem.collector import FilesystemCollector, PlatformError
from collectors.filesystem.inotify import (
    DEFAULT_WATCH_MASK,
    IN_ACCESS,
    IN_ATTRIB,
    IN_CLOSE_NOWRITE,
    IN_CLOSE_WRITE,
    IN_CREATE,
    IN_DELETE,
    IN_DELETE_SELF,
    IN_IGNORED,
    IN_ISDIR,
    IN_MODIFY,
    IN_MOVE_SELF,
    IN_MOVED_FROM,
    IN_MOVED_TO,
    IN_OPEN,
    IN_Q_OVERFLOW,
    IN_UNMOUNT,
    InotifyBackend,
    InotifyEvent,
    LinuxInotifyBackend,
    MockInotifyBackend,
)
from collectors.filesystem.parser import (
    determine_object_type,
    get_inode,
    map_action_and_event_type,
    parse_inotify_event,
    parse_move_pair,
)

__all__ = [
    "DEFAULT_WATCH_MASK",
    "FilesystemCollector",
    "IN_ACCESS",
    "IN_ATTRIB",
    "IN_CLOSE_NOWRITE",
    "IN_CLOSE_WRITE",
    "IN_CREATE",
    "IN_DELETE",
    "IN_DELETE_SELF",
    "IN_IGNORED",
    "IN_ISDIR",
    "IN_MODIFY",
    "IN_MOVED_FROM",
    "IN_MOVED_TO",
    "IN_MOVE_SELF",
    "IN_OPEN",
    "IN_Q_OVERFLOW",
    "IN_UNMOUNT",
    "InotifyBackend",
    "InotifyEvent",
    "LinuxInotifyBackend",
    "MockInotifyBackend",
    "PlatformError",
    "determine_object_type",
    "get_inode",
    "map_action_and_event_type",
    "parse_inotify_event",
    "parse_move_pair",
]
