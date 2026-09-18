"""Linux /proc process filesystem parser.

Small, focused parsing utilities for extracting process metadata from
Linux ``/proc/<pid>/`` entries:

- ``stat``: PID, comm (process name), state, PPID, starttime.
- ``cmdline``: Full command-line invocation (null-separated argv).
- ``status``: Process UIDs (real, effective).
- ``exe``: Symlink to executable binary.

All functions are written to be safe against transient process exits
and permission errors common in Linux process monitoring.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional


def parse_stat(stat_content: str) -> dict[str, Any]:
    """Parse the content of a Linux ``/proc/<pid>/stat`` file.

    Process names (``comm``) are enclosed in parentheses and may contain
    spaces and nested parentheses (e.g. ``(Web Content)`` or ``(app (1))``).
    This function locates the first ``(`` and the last ``)`` to extract
    the process name reliably before splitting the remaining numeric fields.

    Parameters
    ----------
    stat_content:
        The raw string content of ``/proc/<pid>/stat``.

    Returns
    -------
    dict[str, Any]
        Dictionary containing ``pid``, ``comm``, ``state``, ``ppid``,
        and ``starttime`` (ticks after boot).

    Raises
    ------
    ValueError
        If the content is malformed or lacks parentheses around ``comm``.
    """
    first_paren = stat_content.find("(")
    last_paren = stat_content.rfind(")")

    if first_paren == -1 or last_paren == -1 or last_paren <= first_paren:
        raise ValueError(f"Malformed /proc/<pid>/stat content: {stat_content!r}")

    pid_str = stat_content[:first_paren].strip()
    try:
        pid = int(pid_str)
    except ValueError as exc:
        raise ValueError(f"Invalid PID in stat: {pid_str!r}") from exc

    comm = stat_content[first_paren + 1 : last_paren]

    # Fields after the closing parenthesis are space-delimited
    rest = stat_content[last_paren + 1 :].strip().split()
    if len(rest) < 2:
        raise ValueError(f"Insufficient fields in stat: {stat_content!r}")

    state = rest[0]

    try:
        ppid = int(rest[1])
    except ValueError as exc:
        raise ValueError(f"Invalid PPID in stat: {rest[1]!r}") from exc

    # Field 22 (index 19 in rest) is starttime in clock ticks after boot
    starttime: Optional[int] = None
    if len(rest) >= 20:
        try:
            starttime = int(rest[19])
        except ValueError:
            starttime = None

    return {
        "pid": pid,
        "comm": comm,
        "state": state,
        "ppid": ppid,
        "starttime": starttime,
    }


def parse_cmdline(cmdline_bytes: bytes) -> Optional[str]:
    """Parse null-delimited ``/proc/<pid>/cmdline`` bytes into a string.

    Kernel threads (e.g. ``[kthreadd]``) and zombie processes have empty
    cmdlines. In those cases, ``None`` is returned.

    Parameters
    ----------
    cmdline_bytes:
        The raw bytes read from ``/proc/<pid>/cmdline``.

    Returns
    -------
    str | None
        Space-separated command-line arguments, or ``None`` if empty.
    """
    if not cmdline_bytes:
        return None

    tokens = [
        tok.decode("utf-8", errors="replace")
        for tok in cmdline_bytes.split(b"\x00")
        if tok
    ]
    if not tokens:
        return None

    return " ".join(tokens)


def parse_status(status_content: str) -> dict[str, Any]:
    """Extract UID information from ``/proc/<pid>/status``.

    Looks for lines starting with ``Uid:`` which list:
    ``Uid:  <real>  <effective>  <saved>  <fs>``

    Returns
    -------
    dict[str, Any]
        Dictionary with keys ``uid`` (real UID) and ``euid`` (effective UID).
    """
    info: dict[str, Any] = {"uid": None, "euid": None}

    for line in status_content.splitlines():
        if line.startswith("Uid:"):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    info["uid"] = int(parts[1])
                except ValueError:
                    pass
            if len(parts) >= 3:
                try:
                    info["euid"] = int(parts[2])
                except ValueError:
                    pass
            break

    return info


def read_process_info(pid_dir: Path) -> Optional[dict[str, Any]]:
    """Safely read metadata for a single process directory in ``/proc``.

    Handles typical `/proc` race conditions:
    - Process exits while being read (``FileNotFoundError``, ``ProcessLookupError``)
    - Permission denied on restricted processes (``PermissionError``)
    - Symlink errors on ``/proc/<pid>/exe``

    Returns
    -------
    dict[str, Any] | None
        Process metadata dict, or ``None`` if the process could not be read.
    """
    try:
        pid = int(pid_dir.name)
    except ValueError:
        return None

    # 1. Read /proc/<pid>/stat (mandatory)
    stat_file = pid_dir / "stat"
    try:
        stat_content = stat_file.read_text(encoding="utf-8", errors="replace")
        stat_data = parse_stat(stat_content)
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return None
    except (ValueError, OSError):
        return None

    # 2. Read /proc/<pid>/cmdline (optional)
    cmdline_file = pid_dir / "cmdline"
    cmdline: Optional[str] = None
    try:
        cmdline_bytes = cmdline_file.read_bytes()
        cmdline = parse_cmdline(cmdline_bytes)
    except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
        pass

    # 3. Read /proc/<pid>/status (optional, for UID)
    status_file = pid_dir / "status"
    uid: Optional[int] = None
    try:
        status_content = status_file.read_text(encoding="utf-8", errors="replace")
        status_data = parse_status(status_content)
        uid = status_data.get("uid")
    except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
        pass

    # 4. Resolve /proc/<pid>/exe symlink (optional)
    exe_link = pid_dir / "exe"
    executable: Optional[str] = None
    try:
        executable = os.readlink(exe_link)
    except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
        pass

    # Final command representation: cmdline preferred, fallback to comm
    command = cmdline or stat_data["comm"]

    return {
        "pid": pid,
        "ppid": stat_data["ppid"],
        "comm": stat_data["comm"],
        "state": stat_data["state"],
        "starttime": stat_data["starttime"],
        "command": command,
        "executable": executable,
        "uid": uid,
    }
