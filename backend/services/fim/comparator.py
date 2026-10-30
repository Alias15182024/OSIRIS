"""Differential integrity comparison engine for OSIRIS FIM.

Compares a trusted baseline against a subsequent scan to identify:
- New files
- Deleted files
- Content modifications (cryptographic hash mismatch)
- Permission changes (octal mode and SUID/SGID grants)
- Ownership changes (UID/GID)
- Symlink target changes
- Metadata-only changes

Guarantees:
- Deterministic evaluation.
- Clean distinction between content and metadata changes.
- Partial scan safety: incomplete scans never generate deletion alerts.
- Threat severity classification based on target file sensitivity.
"""
from __future__ import annotations

import dataclasses
import logging
from typing import Any, Optional
import uuid

from backend.services.fim.fingerprint import FileFingerprint, normalize_path

logger = logging.getLogger("osiris.services.fim.comparator")

CRITICAL_PATHS = (
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/etc/passwd",
    "/etc/pam.d",
    "/etc/security",
    "/etc/master.passwd",
    "authorized_keys",
    "/etc/ssh/ssh_host_",
    "/etc/ssh/sshd_config",
)

EXECUTABLE_DIRS = (
    "/bin/",
    "/sbin/",
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/local/bin/",
    "/usr/local/sbin/",
)

STARTUP_DIRS = (
    "/etc/systemd/system",
    "/etc/init.d",
    "/etc/crontab",
    "/etc/cron.",
)


@dataclasses.dataclass
class DeviationResult:
    """Detailed record of an observed integrity difference."""

    file_path: str
    deviation_type: str  # 'new_file', 'deleted_file', 'modified_file', 'permission_changed', 'ownership_changed', 'metadata_changed', 'symlink_changed'
    severity: str  # 'info', 'low', 'medium', 'high', 'critical'
    is_content_modified: bool
    is_metadata_modified: bool
    expected_values: Optional[dict[str, Any]]
    observed_values: Optional[dict[str, Any]]
    summary: str
    explanation: str
    file_type: Optional[str] = None
    baseline_file_id: Optional[uuid.UUID] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "file_type": self.file_type,
            "deviation_type": self.deviation_type,
            "severity": self.severity,
            "is_content_modified": self.is_content_modified,
            "is_metadata_modified": self.is_metadata_modified,
            "expected_values": self.expected_values,
            "observed_values": self.observed_values,
            "summary": self.summary,
            "explanation": self.explanation,
            "baseline_file_id": str(self.baseline_file_id) if self.baseline_file_id else None,
        }


def _classify_severity(
    path: str,
    deviation_type: str,
    is_content: bool,
    is_suid_added: bool,
    is_executable: bool,
) -> str:
    """Classify threat severity based on file location and nature of deviation."""
    norm = normalize_path(path)

    # 1. Critical: sensitive auth/sudoers/pam files or SUID added
    if is_suid_added:
        return "critical"

    for crit in CRITICAL_PATHS:
        if crit in norm:
            if deviation_type in ("modified_file", "permission_changed", "ownership_changed", "deleted_file"):
                return "critical"
            return "high"

    # 2. High: System executable or startup persistence modified
    for exec_dir in EXECUTABLE_DIRS:
        if norm.startswith(exec_dir):
            if deviation_type == "modified_file" or deviation_type == "deleted_file":
                return "high"
            if deviation_type == "new_file" and is_executable:
                return "high"

    for sdir in STARTUP_DIRS:
        if sdir in norm:
            return "high"

    # 3. Medium: /etc config modified or general executable modification
    if norm.startswith("/etc/"):
        return "medium"

    if is_content:
        return "medium"

    if deviation_type == "permission_changed":
        return "medium" if is_executable else "low"

    # 4. Low: metadata changes, general additions
    if deviation_type == "metadata_changed" or deviation_type == "ownership_changed":
        return "low"

    if deviation_type == "new_file":
        return "low"

    return "info"


def _extract_base_val(record: Any, attr: str) -> Any:
    """Extract attribute from ORM model or dict."""
    if isinstance(record, dict):
        return record.get(attr)
    return getattr(record, attr, None)


class FimComparator:
    """Compares baseline file inventory with current scan results."""

    @staticmethod
    def compare(
        baseline_files: dict[str, Any],
        current_files: dict[str, FileFingerprint],
        scanned_scope: list[str],
        is_complete: bool = True,
    ) -> list[DeviationResult]:
        """Perform deterministic differential comparison.

        Args:
            baseline_files: Map of normalized path -> FimBaselineFile (or dict).
            current_files: Map of normalized path -> FileFingerprint from scanner.
            scanned_scope: List of root directories included in current scan.
            is_complete: Whether the current scan completed without early termination or error.

        Returns:
            List of DeviationResult objects sorted by file_path.
        """
        deviations: list[DeviationResult] = []
        norm_scanned_scope = [normalize_path(p) for p in scanned_scope]

        # 1. Detect New Files & Modifications in Current Scan
        for path, curr in current_files.items():
            if path not in baseline_files:
                # Discovered a new file or directory not present in baseline
                is_exec = curr.is_executable
                is_suid = curr.is_suid
                sev = _classify_severity(path, "new_file", False, is_suid, is_exec)

                obs_vals = {
                    "sha256": curr.sha256,
                    "size": curr.size,
                    "permissions": curr.permissions,
                    "owner_uid": curr.owner_uid,
                    "owner_gid": curr.owner_gid,
                    "is_executable": curr.is_executable,
                    "is_suid": curr.is_suid,
                    "file_type": curr.file_type,
                }
                deviations.append(
                    DeviationResult(
                        file_path=path,
                        file_type=curr.file_type,
                        deviation_type="new_file",
                        severity=sev,
                        is_content_modified=False,
                        is_metadata_modified=False,
                        expected_values=None,
                        observed_values=obs_vals,
                        summary=f"New {curr.file_type} observed: {path}",
                        explanation=(
                            f"The {curr.file_type} {path} was discovered during the integrity scan but "
                            "was not present in the reference baseline."
                        ),
                    )
                )
            else:
                # Existing file or directory: Compare content and metadata
                base = baseline_files[path]
                base_id = _extract_base_val(base, "id")
                base_type = _extract_base_val(base, "file_type")
                base_sha = _extract_base_val(base, "hash_sha256")
                base_size = _extract_base_val(base, "file_size")
                base_perms = _extract_base_val(base, "permissions")
                base_uid = _extract_base_val(base, "owner_uid")
                base_gid = _extract_base_val(base, "owner_gid")
                base_suid = bool(_extract_base_val(base, "is_suid"))
                base_symlink = _extract_base_val(base, "symlink_target")

                content_changed = False
                symlink_changed = False
                perm_changed = False
                owner_changed = False
                meta_changed = False

                changes_desc: list[str] = []

                # File type change comparison
                if base_type is not None and curr.file_type != base_type:
                    meta_changed = True
                    if curr.file_type == "file" or base_type == "file":
                        content_changed = True
                    changes_desc.append(f"file type changed ('{base_type}' -> '{curr.file_type}')")

                # Symlink target comparison
                if curr.file_type == "symlink" or base_type == "symlink":
                    if curr.symlink_target != base_symlink:
                        symlink_changed = True
                        content_changed = True
                        changes_desc.append(
                            f"symlink target changed ('{base_symlink}' -> '{curr.symlink_target}')"
                        )

                # Regular file content hash comparison
                if curr.file_type == "file" and base_type == "file":
                    if curr.sha256 is not None and base_sha is not None and curr.sha256 != base_sha:
                        content_changed = True
                        changes_desc.append(
                            f"SHA-256 hash mismatch (expected {base_sha[:10]}..., observed {curr.sha256[:10]}...)"
                        )
                    elif curr.sha256 is None and base_sha is not None and curr.error:
                        meta_changed = True
                        changes_desc.append(f"file became unreadable ({curr.error})")

                # Permission comparison
                if base_perms is not None and curr.permissions is not None:
                    if str(base_perms) != str(curr.permissions):
                        perm_changed = True
                        changes_desc.append(
                            f"permissions changed ({base_perms} -> {curr.permissions})"
                        )

                # Ownership comparison
                if (base_uid is not None and curr.owner_uid is not None and base_uid != curr.owner_uid) or (
                    base_gid is not None and curr.owner_gid is not None and base_gid != curr.owner_gid
                ):
                    owner_changed = True
                    changes_desc.append(
                        f"ownership changed (uid:gid {base_uid}:{base_gid} -> {curr.owner_uid}:{curr.owner_gid})"
                    )

                # Size change without hash change (or oversized)
                if base_size is not None and curr.size is not None and base_size != curr.size and not content_changed:
                    meta_changed = True
                    changes_desc.append(f"file size changed ({base_size} -> {curr.size} bytes)")

                # If any deviation occurred
                if content_changed or symlink_changed or perm_changed or owner_changed or meta_changed:
                    is_suid_added = not base_suid and curr.is_suid

                    if content_changed:
                        dev_type = "symlink_changed" if symlink_changed else "modified_file"
                    elif perm_changed:
                        dev_type = "permission_changed"
                    elif owner_changed:
                        dev_type = "ownership_changed"
                    else:
                        dev_type = "metadata_changed"

                    sev = _classify_severity(
                        path,
                        dev_type,
                        content_changed,
                        is_suid_added,
                        curr.is_executable,
                    )

                    expected = {
                        "sha256": base_sha,
                        "size": base_size,
                        "permissions": base_perms,
                        "owner_uid": base_uid,
                        "owner_gid": base_gid,
                        "symlink_target": base_symlink,
                        "file_type": base_type,
                        "is_suid": base_suid,
                    }
                    observed = {
                        "sha256": curr.sha256,
                        "size": curr.size,
                        "permissions": curr.permissions,
                        "owner_uid": curr.owner_uid,
                        "owner_gid": curr.owner_gid,
                        "symlink_target": curr.symlink_target,
                        "file_type": curr.file_type,
                        "is_suid": curr.is_suid,
                    }

                    summary = f"File deviation detected on {path}: {', '.join(changes_desc)}"
                    explanation = (
                        f"Integrity check detected modifications on {path}. Differences: "
                        f"{'; '.join(changes_desc)}."
                    )

                    deviations.append(
                        DeviationResult(
                            file_path=path,
                            file_type=curr.file_type,
                            deviation_type=dev_type,
                            severity=sev,
                            is_content_modified=content_changed,
                            is_metadata_modified=perm_changed or owner_changed or meta_changed,
                            expected_values=expected,
                            observed_values=observed,
                            summary=summary,
                            explanation=explanation,
                            baseline_file_id=base_id,
                        )
                    )

        # 2. Detect Deleted Files & Directories (Only if scan coverage was complete!)
        if is_complete:
            for path, base in baseline_files.items():
                base_type = _extract_base_val(base, "file_type")

                # Verify whether the baseline file's location was inside the scanned scope
                in_scope = False
                for sroot in norm_scanned_scope:
                    if path == sroot or path.startswith(sroot + "/"):
                        in_scope = True
                        break

                if in_scope and path not in current_files:
                    base_id = _extract_base_val(base, "id")
                    base_sha = _extract_base_val(base, "hash_sha256")
                    base_size = _extract_base_val(base, "file_size")
                    base_perms = _extract_base_val(base, "permissions")
                    base_uid = _extract_base_val(base, "owner_uid")
                    base_gid = _extract_base_val(base, "owner_gid")
                    base_suid = bool(_extract_base_val(base, "is_suid"))

                    sev = _classify_severity(path, "deleted_file", False, False, False)

                    expected = {
                        "sha256": base_sha,
                        "size": base_size,
                        "permissions": base_perms,
                        "owner_uid": base_uid,
                        "owner_gid": base_gid,
                        "file_type": base_type,
                        "is_suid": base_suid,
                    }

                    deviations.append(
                        DeviationResult(
                            file_path=path,
                            file_type=base_type,
                            deviation_type="deleted_file",
                            severity=sev,
                            is_content_modified=False,
                            is_metadata_modified=False,
                            expected_values=expected,
                            observed_values=None,
                            summary=f"Baseline file deleted: {path}",
                            explanation=(
                                f"The file {path} was present in the baseline reference but was "
                                "not found during the current integrity scan."
                            ),
                            baseline_file_id=base_id,
                        )
                    )
        else:
            logger.info(
                "Scan coverage was incomplete; skipping file deletion checks to prevent mass false-positive alerts."
            )

        # Sort deterministically by file_path
        deviations.sort(key=lambda d: d.file_path)
        return deviations
