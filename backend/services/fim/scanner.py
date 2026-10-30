"""Filesystem baseline scanner for OSIRIS FIM.

Safely traverses authorized directories, collects cryptographic fingerprints,
applies inclusion/exclusion filters, prevents symlink traversal attacks,
and enforces resource bounds against DoS.
"""
from __future__ import annotations

import dataclasses
import fnmatch
import logging
import os
from pathlib import Path
import time
from typing import Any, Optional

from backend.services.fim.fingerprint import (
    DEFAULT_MAX_FILE_SIZE,
    FileFingerprint,
    fingerprint_file,
    normalize_path,
)

logger = logging.getLogger("osiris.services.fim.scanner")

DEFAULT_EXCLUDE_PATTERNS = [
    "/proc*",
    "/sys*",
    "/dev*",
    "/run*",
    "/tmp*",
    "/var/tmp*",
    "/var/run*",
    "*/.git",
    "*/.git/*",
    "*/.venv",
    "*/.venv/*",
    "*/__pycache__",
    "*/__pycache__/*",
]

DEFAULT_MAX_FILES = 50_000


@dataclasses.dataclass
class ScanSummary:
    """Statistical and diagnostic summary of a filesystem scan execution."""

    total_files: int = 0
    total_bytes: int = 0
    duration_ms: int = 0
    is_complete: bool = True
    scanned_scope: list[str] = dataclasses.field(default_factory=list)
    errors: list[dict[str, str]] = dataclasses.field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_files": self.total_files,
            "total_bytes": self.total_bytes,
            "duration_ms": self.duration_ms,
            "is_complete": self.is_complete,
            "scanned_scope": self.scanned_scope,
            "errors": self.errors,
        }


class FimScanner:
    """Security-focused baseline filesystem scanner."""

    def __init__(
        self,
        paths: list[str | Path],
        include_patterns: Optional[list[str]] = None,
        exclude_patterns: Optional[list[str]] = None,
        max_files: int = DEFAULT_MAX_FILES,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        follow_symlinks: bool = False,
    ) -> None:
        self.raw_paths = [str(p) for p in paths]
        self.include_patterns = include_patterns or []
        self.exclude_patterns = (
            exclude_patterns if exclude_patterns is not None else list(DEFAULT_EXCLUDE_PATTERNS)
        )
        self.max_files = max_files
        self.max_file_size = max_file_size
        self.follow_symlinks = follow_symlinks

    def is_excluded(self, path: str) -> bool:
        """Check if a path matches any exclusion rule or virtual filesystem pattern."""
        norm = normalize_path(path)
        path_parts = [p for p in norm.split(os.sep) if p]
        basename = os.path.basename(norm)

        for raw_pattern in self.exclude_patterns:
            pattern = raw_pattern.rstrip(os.sep) if len(raw_pattern) > 1 and raw_pattern.endswith(os.sep) else raw_pattern
            if pattern.startswith("/") and not pattern.endswith("*"):
                # Exact or prefix match
                if norm == pattern or norm.startswith(pattern + "/"):
                    return True
            if fnmatch.fnmatch(norm, pattern):
                return True
            if fnmatch.fnmatch(basename, pattern):
                return True
            # Segment matching: if pattern is a folder/file name without slashes, check all path components
            if "/" not in pattern and any(fnmatch.fnmatch(part, pattern) for part in path_parts):
                return True
        return False

    def is_included(self, path: str) -> bool:
        """Check if a path matches inclusion rules (if any are defined)."""
        if not self.include_patterns:
            return True
        norm = normalize_path(path)
        basename = os.path.basename(norm)
        for pattern in self.include_patterns:
            if fnmatch.fnmatch(norm, pattern) or fnmatch.fnmatch(basename, pattern):
                return True
        return False

    def scan(self) -> tuple[dict[str, FileFingerprint], ScanSummary]:
        """Execute filesystem scan over configured path scopes.

        Guarantees:
        - Strict symlink traversal protection (directory symlinks are never followed).
        - Inaccessible paths or files record errors and mark scan incomplete to prevent false deletions.
        - Strict bounds on total scanned files to prevent resource exhaustion.
        - Deterministic path sorting.
        """
        start_time = time.monotonic()
        results: dict[str, FileFingerprint] = {}
        errors: list[dict[str, str]] = []
        scanned_roots: list[str] = []
        is_complete = True
        total_bytes = 0

        for raw_root in self.raw_paths:
            norm_root = normalize_path(raw_root)
            scanned_roots.append(norm_root)

            if self.is_excluded(norm_root):
                logger.debug(f"Root path {norm_root} is excluded; skipping.")
                continue

            try:
                root_st = os.lstat(norm_root)
            except FileNotFoundError:
                is_complete = False
                errors.append({"path": norm_root, "error": "root_path_not_found"})
                continue
            except PermissionError:
                is_complete = False
                errors.append({"path": norm_root, "error": "root_permission_denied"})
                continue
            except OSError as exc:
                is_complete = False
                errors.append({"path": norm_root, "error": f"root_os_error: {exc}"})
                continue

            # If the configured path is a single regular file or symlink
            if not os.path.isdir(norm_root) or os.path.islink(norm_root):
                if self.is_included(norm_root):
                    fp = fingerprint_file(
                        norm_root,
                        max_file_size=self.max_file_size,
                    )
                    results[norm_root] = fp
                    total_bytes += fp.size or 0
                    if fp.error:
                        errors.append({"path": norm_root, "error": fp.error})
                continue

            # Root path is a directory: traverse safely
            # Record directory itself
            if self.is_included(norm_root):
                dir_fp = fingerprint_file(norm_root, max_file_size=self.max_file_size)
                results[norm_root] = dir_fp
                if dir_fp.error:
                    errors.append({"path": norm_root, "error": dir_fp.error})

            def _on_walk_error(exc: OSError) -> None:
                nonlocal is_complete
                is_complete = False
                err_path = exc.filename or norm_root
                errors.append({"path": str(err_path), "error": str(exc)})

            for root, dirnames, filenames in os.walk(
                norm_root,
                topdown=True,
                onerror=_on_walk_error,
                followlinks=self.follow_symlinks,
            ):
                if not is_complete:
                    break

                # Prune excluded directories in-place so os.walk does not descend into them
                dirnames[:] = [
                    d
                    for d in dirnames
                    if not self.is_excluded(os.path.join(root, d))
                ]

                # Fingerprint subdirectories with resource bounds
                for dirname in dirnames:
                    dir_path = normalize_path(os.path.join(root, dirname))
                    if self.is_included(dir_path):
                        dfp = fingerprint_file(dir_path, max_file_size=self.max_file_size)
                        results[dir_path] = dfp
                        if dfp.error:
                            errors.append({"path": dir_path, "error": dfp.error})

                        if len(results) >= self.max_files:
                            logger.warning(
                                f"FIM scan reached maximum file limit ({self.max_files}); halting traversal."
                            )
                            is_complete = False
                            errors.append({
                                "path": norm_root,
                                "error": f"max_files_limit_reached_{self.max_files}",
                            })
                            break

                if not is_complete:
                    break

                # Fingerprint files
                for filename in filenames:
                    file_path = normalize_path(os.path.join(root, filename))

                    if self.is_excluded(file_path):
                        continue

                    if not self.is_included(file_path):
                        continue

                    fp = fingerprint_file(
                        file_path,
                        max_file_size=self.max_file_size,
                    )
                    results[file_path] = fp
                    total_bytes += fp.size or 0

                    if fp.error:
                        errors.append({"path": file_path, "error": fp.error})

                    if len(results) >= self.max_files:
                        logger.warning(
                            f"FIM scan reached maximum file limit ({self.max_files}); halting traversal."
                        )
                        is_complete = False
                        errors.append({
                            "path": norm_root,
                            "error": f"max_files_limit_reached_{self.max_files}",
                        })
                        break

                if not is_complete:
                    break

            if not is_complete:
                break

        duration_ms = int((time.monotonic() - start_time) * 1000)

        summary = ScanSummary(
            total_files=len(results),
            total_bytes=total_bytes,
            duration_ms=duration_ms,
            is_complete=is_complete,
            scanned_scope=scanned_roots,
            errors=errors,
        )

        return results, summary
