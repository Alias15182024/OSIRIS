"""Cryptographic file fingerprinting service for OSIRIS FIM.

Provides secure, deterministic file fingerprinting with:
- SHA-256 as primary cryptographic hash.
- Optional SHA-1 and MD5 compatibility digests.
- Chunked streaming for large files (constant memory overhead).
- Safe symlink handling without following directory traversal.
- TOCTOU concurrent modification detection.
- Unicode and unusual filename safety.
- Graceful error isolation (unreadable, disappearing, or special files).
"""
from __future__ import annotations

import dataclasses
import errno
import hashlib
import logging
import os
from pathlib import Path
import stat
from datetime import datetime, timezone
from typing import Any, Optional

try:
    import pwd
    import grp
except ImportError:
    pwd = None  # type: ignore[assignment]
    grp = None  # type: ignore[assignment]

logger = logging.getLogger("osiris.services.fim.fingerprint")

DEFAULT_CHUNK_SIZE = 64 * 1024  # 64 KB
DEFAULT_MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB


def _safe_opener(file_path: str, flags: int) -> int:
    """Open files securely without following symlinks and non-blocking for special files."""
    open_flags = flags
    if hasattr(os, "O_NOFOLLOW"):
        open_flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        open_flags |= os.O_NONBLOCK
    return os.open(file_path, open_flags)


def normalize_path(path: str | Path) -> str:
    """Normalize a filesystem path deterministically without trailing slash.

    Resolves relative path elements ('.', '..') while preserving the exact
    canonical target. Preserves the root '/' path.
    """
    raw_str = str(path)
    # Expand user if applicable, but normalize deterministically
    resolved = os.path.abspath(os.path.normpath(raw_str))
    if len(resolved) > 1 and resolved.endswith(os.sep):
        resolved = resolved.rstrip(os.sep)
    return resolved


@dataclasses.dataclass
class FileFingerprint:
    """Structured representation of a file's cryptographic and metadata state."""

    path: str
    file_name: str
    file_type: str  # 'file', 'directory', 'symlink', 'special'
    sha256: Optional[str] = None
    sha1: Optional[str] = None
    md5: Optional[str] = None
    size: Optional[int] = None
    permissions: Optional[str] = None  # Octal string (e.g., '0644')
    mode: Optional[int] = None  # Raw stat st_mode integer
    owner_uid: Optional[int] = None
    owner_gid: Optional[int] = None
    owner_user: Optional[str] = None
    owner_group: Optional[str] = None
    mtime: Optional[datetime] = None
    ctime: Optional[datetime] = None
    inode: Optional[int] = None
    device_id: Optional[int] = None
    symlink_target: Optional[str] = None
    is_suid: bool = False
    is_sgid: bool = False
    is_executable: bool = False
    fingerprint_metadata: dict[str, Any] = dataclasses.field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert fingerprint into a dictionary suitable for JSON serialization."""
        return {
            "path": self.path,
            "file_name": self.file_name,
            "file_type": self.file_type,
            "sha256": self.sha256,
            "sha1": self.sha1,
            "md5": self.md5,
            "size": self.size,
            "permissions": self.permissions,
            "mode": self.mode,
            "owner_uid": self.owner_uid,
            "owner_gid": self.owner_gid,
            "owner_user": self.owner_user,
            "owner_group": self.owner_group,
            "mtime": self.mtime.isoformat() if self.mtime else None,
            "ctime": self.ctime.isoformat() if self.ctime else None,
            "inode": self.inode,
            "device_id": self.device_id,
            "symlink_target": self.symlink_target,
            "is_suid": self.is_suid,
            "is_sgid": self.is_sgid,
            "is_executable": self.is_executable,
            "fingerprint_metadata": self.fingerprint_metadata,
            "error": self.error,
        }


def _resolve_user_group(uid: int, gid: int) -> tuple[Optional[str], Optional[str]]:
    """Safely resolve user and group names without failing if unmapped."""
    user_name: Optional[str] = None
    group_name: Optional[str] = None

    if pwd is not None:
        try:
            user_name = pwd.getpwuid(uid).pw_name
        except (KeyError, OverflowError, OSError):
            user_name = str(uid)

    if grp is not None:
        try:
            group_name = grp.getgrgid(gid).gr_name
        except (KeyError, OverflowError, OSError):
            group_name = str(gid)

    return user_name, group_name


def fingerprint_file(
    path: str | Path,
    include_sha1: bool = False,
    include_md5: bool = False,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> FileFingerprint:
    """Compute cryptographic fingerprint and metadata for a single filesystem entity.

    Safety guarantees:
    - Uses `os.lstat` so directory symlinks are never followed.
    - Captures symlink target strings safely and hashes target destination.
    - Streams file contents in chunks to prevent memory spikes on large files.
    - Detects concurrent file modifications during hashing (TOCTOU).
    - Ignores special device nodes and FIFOs from content reading to prevent blocking.
    - Catches permissions and disappearing file errors gracefully without throwing.
    """
    norm_path = normalize_path(path)
    file_name = os.path.basename(norm_path) or norm_path

    # Initial lstat: Never follow symlinks
    try:
        st = os.lstat(norm_path)
    except FileNotFoundError:
        return FileFingerprint(
            path=norm_path,
            file_name=file_name,
            file_type="unknown",
            error="file_not_found",
        )
    except PermissionError:
        return FileFingerprint(
            path=norm_path,
            file_name=file_name,
            file_type="unknown",
            error="permission_denied",
            fingerprint_metadata={"unreadable": True},
        )
    except OSError as exc:
        return FileFingerprint(
            path=norm_path,
            file_name=file_name,
            file_type="unknown",
            error=str(exc),
        )

    mode = st.st_mode
    size = st.st_size
    inode = st.st_ino
    device_id = st.st_dev
    mtime = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
    ctime = datetime.fromtimestamp(st.st_ctime, tz=timezone.utc)
    uid = st.st_uid
    gid = st.st_gid
    perms = f"{stat.S_IMODE(mode):04o}"

    is_suid = bool(mode & stat.S_ISUID)
    is_sgid = bool(mode & stat.S_ISGID)
    is_exec = bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))

    user_name, group_name = _resolve_user_group(uid, gid)

    # 1. Symlink handling: inspect target without traversing
    if stat.S_ISLNK(mode):
        try:
            target = os.readlink(norm_path)
        except OSError as exc:
            return FileFingerprint(
                path=norm_path,
                file_name=file_name,
                file_type="symlink",
                size=size,
                permissions=perms,
                mode=mode,
                owner_uid=uid,
                owner_gid=gid,
                owner_user=user_name,
                owner_group=group_name,
                mtime=mtime,
                ctime=ctime,
                inode=inode,
                device_id=device_id,
                error=f"readlink_error: {exc}",
            )

        target_bytes = target.encode("utf-8", errors="surrogateescape")
        sha256_hash = hashlib.sha256(target_bytes).hexdigest()
        sha1_hash = hashlib.sha1(target_bytes).hexdigest() if include_sha1 else None
        md5_hash = hashlib.md5(target_bytes).hexdigest() if include_md5 else None

        return FileFingerprint(
            path=norm_path,
            file_name=file_name,
            file_type="symlink",
            sha256=sha256_hash,
            sha1=sha1_hash,
            md5=md5_hash,
            size=len(target_bytes),
            permissions=perms,
            mode=mode,
            owner_uid=uid,
            owner_gid=gid,
            owner_user=user_name,
            owner_group=group_name,
            mtime=mtime,
            ctime=ctime,
            inode=inode,
            device_id=device_id,
            symlink_target=target,
            is_suid=is_suid,
            is_sgid=is_sgid,
            is_executable=is_exec,
        )

    # 2. Directory handling: no content checksum
    if stat.S_ISDIR(mode):
        return FileFingerprint(
            path=norm_path,
            file_name=file_name,
            file_type="directory",
            size=size,
            permissions=perms,
            mode=mode,
            owner_uid=uid,
            owner_gid=gid,
            owner_user=user_name,
            owner_group=group_name,
            mtime=mtime,
            ctime=ctime,
            inode=inode,
            device_id=device_id,
            is_suid=is_suid,
            is_sgid=is_sgid,
            is_executable=is_exec,
        )

    # 3. Special file handling (FIFO, Socket, Device Nodes): DO NOT READ
    if not stat.S_ISREG(mode):
        special_type = "special"
        if stat.S_ISFIFO(mode):
            special_type = "fifo"
        elif stat.S_ISSOCK(mode):
            special_type = "socket"
        elif stat.S_ISCHR(mode):
            special_type = "character_device"
        elif stat.S_ISBLK(mode):
            special_type = "block_device"

        return FileFingerprint(
            path=norm_path,
            file_name=file_name,
            file_type="special",
            size=size,
            permissions=perms,
            mode=mode,
            owner_uid=uid,
            owner_gid=gid,
            owner_user=user_name,
            owner_group=group_name,
            mtime=mtime,
            ctime=ctime,
            inode=inode,
            device_id=device_id,
            fingerprint_metadata={"special_kind": special_type},
        )

    # 4. Regular file handling: stream hashes safely
    metadata_extra: dict[str, Any] = {}

    if size > max_file_size:
        metadata_extra["oversized"] = True
        metadata_extra["hash_skipped_reason"] = "size_exceeds_max_limit"
        return FileFingerprint(
            path=norm_path,
            file_name=file_name,
            file_type="file",
            size=size,
            permissions=perms,
            mode=mode,
            owner_uid=uid,
            owner_gid=gid,
            owner_user=user_name,
            owner_group=group_name,
            mtime=mtime,
            ctime=ctime,
            inode=inode,
            device_id=device_id,
            is_suid=is_suid,
            is_sgid=is_sgid,
            is_executable=is_exec,
            fingerprint_metadata=metadata_extra,
        )

    hasher_sha256 = hashlib.sha256()
    hasher_sha1 = hashlib.sha1() if include_sha1 else None
    hasher_md5 = hashlib.md5() if include_md5 else None
    err: Optional[str] = None

    try:
        with open(norm_path, "rb", opener=_safe_opener) as f:
            fd = f.fileno()
            try:
                fd_st = os.fstat(fd)
                if fd_st.st_ino != st.st_ino or fd_st.st_dev != st.st_dev:
                    metadata_extra["concurrent_modification_detected"] = True
                    err = "concurrent_modification_detected"
                if not stat.S_ISREG(fd_st.st_mode):
                    metadata_extra["unreadable"] = True
                    return FileFingerprint(
                        path=norm_path,
                        file_name=file_name,
                        file_type="special",
                        error="not_a_regular_file",
                        fingerprint_metadata=metadata_extra,
                    )
            except OSError:
                pass

            bytes_read = 0
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                bytes_read += len(chunk)
                if bytes_read > max_file_size:
                    metadata_extra["oversized"] = True
                    metadata_extra["hash_skipped_reason"] = "size_exceeds_max_limit"
                    return FileFingerprint(
                        path=norm_path,
                        file_name=file_name,
                        file_type="file",
                        size=bytes_read,
                        permissions=perms,
                        mode=mode,
                        owner_uid=uid,
                        owner_gid=gid,
                        owner_user=user_name,
                        owner_group=group_name,
                        mtime=mtime,
                        ctime=ctime,
                        inode=inode,
                        device_id=device_id,
                        is_suid=is_suid,
                        is_sgid=is_sgid,
                        is_executable=is_exec,
                        fingerprint_metadata=metadata_extra,
                    )
                hasher_sha256.update(chunk)
                if hasher_sha1 is not None:
                    hasher_sha1.update(chunk)
                if hasher_md5 is not None:
                    hasher_md5.update(chunk)

            try:
                post_fd = os.fstat(fd)
                if (
                    post_fd.st_mtime != st.st_mtime
                    or post_fd.st_size != st.st_size
                    or post_fd.st_ino != st.st_ino
                ):
                    metadata_extra["concurrent_modification_detected"] = True
                    err = "concurrent_modification_detected"
            except OSError:
                pass
    except FileNotFoundError:
        return FileFingerprint(
            path=norm_path,
            file_name=file_name,
            file_type="file",
            error="file_disappeared_during_read",
        )
    except PermissionError:
        return FileFingerprint(
            path=norm_path,
            file_name=file_name,
            file_type="file",
            size=size,
            permissions=perms,
            mode=mode,
            owner_uid=uid,
            owner_gid=gid,
            owner_user=user_name,
            owner_group=group_name,
            mtime=mtime,
            ctime=ctime,
            inode=inode,
            device_id=device_id,
            is_suid=is_suid,
            is_sgid=is_sgid,
            is_executable=is_exec,
            error="permission_denied_during_read",
            fingerprint_metadata={"unreadable": True},
        )
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            return FileFingerprint(
                path=norm_path,
                file_name=file_name,
                file_type="file",
                size=size,
                permissions=perms,
                mode=mode,
                owner_uid=uid,
                owner_gid=gid,
                owner_user=user_name,
                owner_group=group_name,
                mtime=mtime,
                ctime=ctime,
                inode=inode,
                device_id=device_id,
                error="symlink_swap_detected",
                fingerprint_metadata={"unreadable": True, "symlink_swap": True},
            )
        return FileFingerprint(
            path=norm_path,
            file_name=file_name,
            file_type="file",
            size=size,
            permissions=perms,
            mode=mode,
            owner_uid=uid,
            owner_gid=gid,
            owner_user=user_name,
            owner_group=group_name,
            mtime=mtime,
            ctime=ctime,
            inode=inode,
            device_id=device_id,
            is_suid=is_suid,
            is_sgid=is_sgid,
            is_executable=is_exec,
            error=f"read_error: {exc}",
        )

    # Post-read stat check: detect TOCTOU modification while hashing
    try:
        post_st = os.lstat(norm_path)
        if (
            post_st.st_mtime != st.st_mtime
            or post_st.st_size != st.st_size
            or post_st.st_ino != st.st_ino
        ):
            metadata_extra["concurrent_modification_detected"] = True
            err = "concurrent_modification_detected"
    except FileNotFoundError:
        err = "file_disappeared_after_hashing"
    except OSError:
        pass

    return FileFingerprint(
        path=norm_path,
        file_name=file_name,
        file_type="file",
        sha256=hasher_sha256.hexdigest(),
        sha1=hasher_sha1.hexdigest() if hasher_sha1 else None,
        md5=hasher_md5.hexdigest() if hasher_md5 else None,
        size=size,
        permissions=perms,
        mode=mode,
        owner_uid=uid,
        owner_gid=gid,
        owner_user=user_name,
        owner_group=group_name,
        mtime=mtime,
        ctime=ctime,
        inode=inode,
        device_id=device_id,
        is_suid=is_suid,
        is_sgid=is_sgid,
        is_executable=is_exec,
        fingerprint_metadata=metadata_extra,
        error=err,
    )
