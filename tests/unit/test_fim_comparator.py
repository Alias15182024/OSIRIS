"""Unit tests for OSIRIS FIM differential comparator."""

from __future__ import annotations

import uuid
import pytest

from backend.services.fim.comparator import DeviationResult, FimComparator
from backend.services.fim.fingerprint import FileFingerprint


class TestFimComparator:
    """Test differential integrity detection rules and safety."""

    def test_new_file_detected(self) -> None:
        baseline_files = {}
        current_files = {
            "/etc/new_service.conf": FileFingerprint(
                path="/etc/new_service.conf",
                file_name="new_service.conf",
                file_type="file",
                sha256="abc123hash",
                size=120,
                permissions="0644",
                owner_uid=0,
                owner_gid=0,
            )
        }

        deviations = FimComparator.compare(
            baseline_files=baseline_files,
            current_files=current_files,
            scanned_scope=["/etc"],
            is_complete=True,
        )

        assert len(deviations) == 1
        dev = deviations[0]
        assert dev.file_path == "/etc/new_service.conf"
        assert dev.deviation_type == "new_file"
        assert dev.is_content_modified is False
        assert dev.expected_values is None
        assert dev.observed_values is not None
        assert dev.observed_values["sha256"] == "abc123hash"

    def test_deleted_file_detected(self) -> None:
        baseline_files = {
            "/etc/old_config.conf": {
                "id": uuid.uuid4(),
                "file_path": "/etc/old_config.conf",
                "file_type": "file",
                "hash_sha256": "def456hash",
                "file_size": 250,
                "permissions": "0644",
                "owner_uid": 0,
                "owner_gid": 0,
                "is_suid": False,
            }
        }
        current_files = {}

        deviations = FimComparator.compare(
            baseline_files=baseline_files,
            current_files=current_files,
            scanned_scope=["/etc"],
            is_complete=True,
        )

        assert len(deviations) == 1
        dev = deviations[0]
        assert dev.file_path == "/etc/old_config.conf"
        assert dev.deviation_type == "deleted_file"
        assert dev.is_content_modified is False
        assert dev.expected_values is not None
        assert dev.observed_values is None

    def test_incomplete_scan_prevents_mass_deletion(self) -> None:
        # If is_complete is False, missing files MUST NOT generate deletion alerts
        baseline_files = {
            "/etc/conf1.conf": {"id": uuid.uuid4(), "file_type": "file", "hash_sha256": "h1"},
            "/etc/conf2.conf": {"id": uuid.uuid4(), "file_type": "file", "hash_sha256": "h2"},
            "/etc/conf3.conf": {"id": uuid.uuid4(), "file_type": "file", "hash_sha256": "h3"},
        }
        current_files = {}  # Empty because scan failed or aborted

        deviations = FimComparator.compare(
            baseline_files=baseline_files,
            current_files=current_files,
            scanned_scope=["/etc"],
            is_complete=False,  # Incomplete!
        )

        assert len(deviations) == 0

    def test_out_of_scope_baseline_files_not_marked_deleted(self) -> None:
        # Baseline covers /etc and /bin. We only scan /etc this cycle.
        baseline_files = {
            "/etc/config.conf": {"id": uuid.uuid4(), "file_type": "file", "hash_sha256": "h1"},
            "/bin/ls": {"id": uuid.uuid4(), "file_type": "file", "hash_sha256": "h2"},
        }
        current_files = {
            "/etc/config.conf": FileFingerprint(
                path="/etc/config.conf",
                file_name="config.conf",
                file_type="file",
                sha256="h1",
                size=100,
                permissions="0644",
            )
        }

        deviations = FimComparator.compare(
            baseline_files=baseline_files,
            current_files=current_files,
            scanned_scope=["/etc"],  # /bin is not in current scope
            is_complete=True,
        )

        assert len(deviations) == 0  # /bin/ls is not marked deleted because it wasn't scanned

    def test_content_modification_detected(self) -> None:
        baseline_files = {
            "/etc/hosts": {
                "id": uuid.uuid4(),
                "file_path": "/etc/hosts",
                "file_type": "file",
                "hash_sha256": "original_hash",
                "file_size": 100,
                "permissions": "0644",
                "owner_uid": 0,
                "owner_gid": 0,
                "is_suid": False,
            }
        }
        current_files = {
            "/etc/hosts": FileFingerprint(
                path="/etc/hosts",
                file_name="hosts",
                file_type="file",
                sha256="tampered_hash",
                size=150,
                permissions="0644",
                owner_uid=0,
                owner_gid=0,
            )
        }

        deviations = FimComparator.compare(
            baseline_files=baseline_files,
            current_files=current_files,
            scanned_scope=["/etc"],
            is_complete=True,
        )

        assert len(deviations) == 1
        dev = deviations[0]
        assert dev.file_path == "/etc/hosts"
        assert dev.deviation_type == "modified_file"
        assert dev.is_content_modified is True
        assert dev.expected_values["sha256"] == "original_hash"
        assert dev.observed_values["sha256"] == "tampered_hash"

    def test_permission_change_detected(self) -> None:
        baseline_files = {
            "/etc/secure.conf": {
                "id": uuid.uuid4(),
                "file_path": "/etc/secure.conf",
                "file_type": "file",
                "hash_sha256": "same_hash",
                "file_size": 100,
                "permissions": "0600",
                "owner_uid": 0,
                "owner_gid": 0,
                "is_suid": False,
            }
        }
        current_files = {
            "/etc/secure.conf": FileFingerprint(
                path="/etc/secure.conf",
                file_name="secure.conf",
                file_type="file",
                sha256="same_hash",
                size=100,
                permissions="0666",  # World writable now!
                owner_uid=0,
                owner_gid=0,
            )
        }

        deviations = FimComparator.compare(
            baseline_files=baseline_files,
            current_files=current_files,
            scanned_scope=["/etc"],
            is_complete=True,
        )

        assert len(deviations) == 1
        dev = deviations[0]
        assert dev.file_path == "/etc/secure.conf"
        assert dev.deviation_type == "permission_changed"
        assert dev.is_content_modified is False
        assert dev.is_metadata_modified is True
        assert dev.expected_values["permissions"] == "0600"
        assert dev.observed_values["permissions"] == "0666"

    def test_suid_bit_grant_escalates_severity_to_critical(self) -> None:
        baseline_files = {
            "/bin/test_tool": {
                "id": uuid.uuid4(),
                "file_path": "/bin/test_tool",
                "file_type": "file",
                "hash_sha256": "same_hash",
                "file_size": 100,
                "permissions": "0755",
                "owner_uid": 0,
                "owner_gid": 0,
                "is_suid": False,
            }
        }
        current_files = {
            "/bin/test_tool": FileFingerprint(
                path="/bin/test_tool",
                file_name="test_tool",
                file_type="file",
                sha256="same_hash",
                size=100,
                permissions="4755",
                owner_uid=0,
                owner_gid=0,
                is_suid=True,  # SUID added!
                is_executable=True,
            )
        }

        deviations = FimComparator.compare(
            baseline_files=baseline_files,
            current_files=current_files,
            scanned_scope=["/bin"],
            is_complete=True,
        )

        assert len(deviations) == 1
        dev = deviations[0]
        assert dev.deviation_type == "permission_changed"
        assert dev.severity == "critical"

    def test_ownership_change_detected(self) -> None:
        baseline_files = {
            "/etc/daemon.conf": {
                "id": uuid.uuid4(),
                "file_path": "/etc/daemon.conf",
                "file_type": "file",
                "hash_sha256": "same_hash",
                "file_size": 100,
                "permissions": "0644",
                "owner_uid": 0,  # root
                "owner_gid": 0,
                "is_suid": False,
            }
        }
        current_files = {
            "/etc/daemon.conf": FileFingerprint(
                path="/etc/daemon.conf",
                file_name="daemon.conf",
                file_type="file",
                sha256="same_hash",
                size=100,
                permissions="0644",
                owner_uid=1000,  # changed to normal user
                owner_gid=1000,
            )
        }

        deviations = FimComparator.compare(
            baseline_files=baseline_files,
            current_files=current_files,
            scanned_scope=["/etc"],
            is_complete=True,
        )

        assert len(deviations) == 1
        dev = deviations[0]
        assert dev.deviation_type == "ownership_changed"
        assert dev.is_metadata_modified is True

    def test_symlink_target_change_detected(self) -> None:
        baseline_files = {
            "/etc/ssl/cert.pem": {
                "id": uuid.uuid4(),
                "file_path": "/etc/ssl/cert.pem",
                "file_type": "symlink",
                "symlink_target": "/etc/ssl/certs/trusted.crt",
                "permissions": "0777",
                "owner_uid": 0,
                "owner_gid": 0,
            }
        }
        current_files = {
            "/etc/ssl/cert.pem": FileFingerprint(
                path="/etc/ssl/cert.pem",
                file_name="cert.pem",
                file_type="symlink",
                symlink_target="/tmp/evil_cert.crt",  # Tampered target
                permissions="0777",
                owner_uid=0,
                owner_gid=0,
            )
        }

        deviations = FimComparator.compare(
            baseline_files=baseline_files,
            current_files=current_files,
            scanned_scope=["/etc/ssl"],
            is_complete=True,
        )

        assert len(deviations) == 1
        dev = deviations[0]
        assert dev.deviation_type == "symlink_changed"
        assert dev.is_content_modified is True
        assert dev.expected_values["symlink_target"] == "/etc/ssl/certs/trusted.crt"
        assert dev.observed_values["symlink_target"] == "/tmp/evil_cert.crt"

    def test_directory_permission_change_detected(self) -> None:
        baseline_files = {
            "/etc/cron.d": {
                "id": uuid.uuid4(),
                "file_path": "/etc/cron.d",
                "file_type": "directory",
                "permissions": "0755",
                "owner_uid": 0,
                "owner_gid": 0,
            }
        }
        current_files = {
            "/etc/cron.d": FileFingerprint(
                path="/etc/cron.d",
                file_name="cron.d",
                file_type="directory",
                permissions="0777",  # World writable directory!
                owner_uid=0,
                owner_gid=0,
            )
        }

        deviations = FimComparator.compare(
            baseline_files=baseline_files,
            current_files=current_files,
            scanned_scope=["/etc"],
            is_complete=True,
        )

        assert len(deviations) == 1
        dev = deviations[0]
        assert dev.file_path == "/etc/cron.d"
        assert dev.file_type == "directory"
        assert dev.deviation_type == "permission_changed"
        assert dev.expected_values["permissions"] == "0755"
        assert dev.observed_values["permissions"] == "0777"

    def test_directory_ownership_change_detected(self) -> None:
        baseline_files = {
            "/etc/sudoers.d": {
                "id": uuid.uuid4(),
                "file_path": "/etc/sudoers.d",
                "file_type": "directory",
                "permissions": "0750",
                "owner_uid": 0,
                "owner_gid": 0,
            }
        }
        current_files = {
            "/etc/sudoers.d": FileFingerprint(
                path="/etc/sudoers.d",
                file_name="sudoers.d",
                file_type="directory",
                permissions="0750",
                owner_uid=1001,
                owner_gid=1001,
            )
        }

        deviations = FimComparator.compare(
            baseline_files=baseline_files,
            current_files=current_files,
            scanned_scope=["/etc"],
            is_complete=True,
        )

        assert len(deviations) == 1
        dev = deviations[0]
        assert dev.file_path == "/etc/sudoers.d"
        assert dev.deviation_type == "ownership_changed"
        assert dev.expected_values["owner_uid"] == 0
        assert dev.observed_values["owner_uid"] == 1001

    def test_file_type_change_detected(self) -> None:
        baseline_files = {
            "/etc/service.conf": {
                "id": uuid.uuid4(),
                "file_path": "/etc/service.conf",
                "file_type": "file",
                "hash_sha256": "h123",
                "file_size": 100,
                "permissions": "0644",
                "owner_uid": 0,
                "owner_gid": 0,
            }
        }
        current_files = {
            "/etc/service.conf": FileFingerprint(
                path="/etc/service.conf",
                file_name="service.conf",
                file_type="symlink",  # Replaced with a symlink!
                symlink_target="/tmp/evil.conf",
                permissions="0644",
                owner_uid=0,
                owner_gid=0,
            )
        }

        deviations = FimComparator.compare(
            baseline_files=baseline_files,
            current_files=current_files,
            scanned_scope=["/etc"],
            is_complete=True,
        )

        assert len(deviations) == 1
        dev = deviations[0]
        assert dev.file_path == "/etc/service.conf"
        assert "file type changed" in dev.summary

    def test_file_becoming_unreadable_detected(self) -> None:
        baseline_files = {
            "/etc/ssl/private.key": {
                "id": uuid.uuid4(),
                "file_path": "/etc/ssl/private.key",
                "file_type": "file",
                "hash_sha256": "hash_sec",
                "file_size": 1024,
                "permissions": "0600",
                "owner_uid": 0,
                "owner_gid": 0,
            }
        }
        current_files = {
            "/etc/ssl/private.key": FileFingerprint(
                path="/etc/ssl/private.key",
                file_name="private.key",
                file_type="file",
                sha256=None,
                permissions="0000",
                owner_uid=0,
                owner_gid=0,
                error="permission_denied_during_read",
            )
        }

        deviations = FimComparator.compare(
            baseline_files=baseline_files,
            current_files=current_files,
            scanned_scope=["/etc"],
            is_complete=True,
        )

        assert len(deviations) == 1
        dev = deviations[0]
        assert dev.file_path == "/etc/ssl/private.key"
        assert "file became unreadable" in dev.summary or dev.deviation_type in ("permission_changed", "metadata_changed")
