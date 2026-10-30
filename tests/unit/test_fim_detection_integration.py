"""Unit tests for FIM deviations integration with OSIRIS Detection Engine."""

from __future__ import annotations

import os
from pathlib import Path
import uuid
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from backend.db.base import Base
from backend.db.models.detection import Detection
from backend.db.models.fim_baseline import FimBaseline
from backend.db.models.fim_deviation import FimDeviation
from backend.db.models.host import Host
from backend.services.detection.service import DetectionService
from backend.services.fim.service import FimService


@pytest.fixture
def db_session(tmp_path: Path) -> Session:
    """Create a temporary in-memory/file SQLite database with all tables created."""
    db_file = tmp_path / "fim_detection_test.db"
    engine = create_engine(f"sqlite:///{db_file}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    yield session
    session.close()
    engine.dispose()


@pytest.fixture
def test_host(db_session: Session) -> Host:
    host = Host(hostname="fim-detection-test-host")
    db_session.add(host)
    db_session.commit()
    db_session.refresh(host)
    return host


class TestFimDetectionIntegration:
    """Verify FIM deviations evaluate against detection rules and link to detections."""

    def test_protected_config_tampering_triggers_fim_001(
        self, db_session: Session, test_host: Host, tmp_path: Path
    ) -> None:
        scan_dir = tmp_path / "etc"
        scan_dir.mkdir()
        sudoers_file = scan_dir / "sudoers"
        sudoers_file.write_text("root ALL=(ALL) ALL", encoding="utf-8")

        fim_service = FimService()

        # Step 1: Create baseline
        baseline = fim_service.create_baseline(
            db=db_session,
            host_id=test_host.id,
            paths=[str(scan_dir)],
        )
        assert baseline.version == 1
        assert baseline.total_files >= 1

        # Step 2: Tamper with sudoers
        sudoers_file.write_text("root ALL=(ALL) ALL\nevil ALL=(ALL) NOPASSWD: ALL", encoding="utf-8")

        # Step 3: Run integrity verification
        _, deviations, detections = fim_service.verify_host_integrity(
            db=db_session,
            host_id=test_host.id,
            baseline_id=baseline.id,
        )

        assert len(deviations) == 1
        dev = deviations[0]
        assert dev.deviation_type == "modified_file"

        assert len(detections) >= 1
        det = next((d for d in detections if d.title == "Protected System Configuration Tampering" or "OSIRIS-FIM-001" in str(d.rule.rule_id)), None)
        assert det is not None
        assert det.severity == "critical"
        assert dev.detection_id in [d.id for d in detections]
        assert det.evidence is not None
        assert "expected" in det.evidence
        assert "observed" in det.evidence
        assert det.evidence["baseline_id"] == str(baseline.id)
        assert det.evidence["deviation_id"] == str(dev.id)

    def test_sensitive_auth_tampering_triggers_fim_002(
        self, db_session: Session, test_host: Host, tmp_path: Path
    ) -> None:
        scan_dir = tmp_path / "auth_etc"
        scan_dir.mkdir()
        shadow_file = scan_dir / "shadow"
        shadow_file.write_text("root:$6$hash:19000:0:99999:7:::", encoding="utf-8")

        fim_service = FimService()
        baseline = fim_service.create_baseline(
            db=db_session,
            host_id=test_host.id,
            paths=[str(scan_dir)],
        )

        # Modify shadow file
        shadow_file.write_text("root:$6$tampered:19000:0:99999:7:::\nbackdoor:$6$evil:19000:0:99999:7:::", encoding="utf-8")

        _, deviations, detections = fim_service.verify_host_integrity(
            db=db_session,
            host_id=test_host.id,
            baseline_id=baseline.id,
        )

        assert len(deviations) == 1
        det = next((d for d in detections if "OSIRIS-FIM-002" in str(d.rule.rule_id)), None)
        assert det is not None
        assert det.severity == "critical"
        assert det.fim_deviation_id == deviations[0].id

    def test_system_executable_tampering_triggers_fim_003(
        self, db_session: Session, test_host: Host, tmp_path: Path
    ) -> None:
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        exec_file = bin_dir / "login"
        exec_file.write_text("#!/bin/sh\nexec /bin/true", encoding="utf-8")
        os.chmod(exec_file, 0o755)

        fim_service = FimService()
        baseline = fim_service.create_baseline(
            db=db_session,
            host_id=test_host.id,
            paths=[str(bin_dir)],
        )

        # Replace executable
        exec_file.write_text("#!/bin/sh\n# trojaned\nexec /bin/sh", encoding="utf-8")

        _, deviations, detections = fim_service.verify_host_integrity(
            db=db_session,
            host_id=test_host.id,
            baseline_id=baseline.id,
        )

        assert len(deviations) == 1
        det = next((d for d in detections if "OSIRIS-FIM-003" in str(d.rule.rule_id)), None)
        assert det is not None
        assert det.severity == "high"

    def test_permission_tampering_triggers_fim_004(
        self, db_session: Session, test_host: Host, tmp_path: Path
    ) -> None:
        scan_dir = tmp_path / "perms"
        scan_dir.mkdir()
        target_file = scan_dir / "util"
        target_file.write_text("echo util", encoding="utf-8")
        os.chmod(target_file, 0o644)

        fim_service = FimService()
        baseline = fim_service.create_baseline(
            db=db_session,
            host_id=test_host.id,
            paths=[str(scan_dir)],
        )

        # Change permission
        os.chmod(target_file, 0o777)

        _, deviations, detections = fim_service.verify_host_integrity(
            db=db_session,
            host_id=test_host.id,
            baseline_id=baseline.id,
        )

        assert len(deviations) == 1
        det = next((d for d in detections if "OSIRIS-FIM-004" in str(d.rule.rule_id)), None)
        assert det is not None
        assert det.severity == "high"

    def test_ssh_keys_tampering_triggers_fim_005(
        self, db_session: Session, test_host: Host, tmp_path: Path
    ) -> None:
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        auth_keys = ssh_dir / "authorized_keys"
        auth_keys.write_text("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC user@corp", encoding="utf-8")

        fim_service = FimService()
        baseline = fim_service.create_baseline(
            db=db_session,
            host_id=test_host.id,
            paths=[str(ssh_dir)],
        )

        # Tamper with authorized_keys
        auth_keys.write_text("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC user@corp\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI evil@attacker", encoding="utf-8")

        _, deviations, detections = fim_service.verify_host_integrity(
            db=db_session,
            host_id=test_host.id,
            baseline_id=baseline.id,
        )

        assert len(deviations) == 1
        det = next((d for d in detections if "OSIRIS-FIM-005" in str(d.rule.rule_id)), None)
        assert det is not None
        assert det.severity == "critical"

    def test_deduplication_on_repeated_verification(
        self, db_session: Session, test_host: Host, tmp_path: Path
    ) -> None:
        scan_dir = tmp_path / "dedup"
        scan_dir.mkdir()
        conf_file = scan_dir / "shadow"
        conf_file.write_text("root:initial", encoding="utf-8")

        fim_service = FimService()
        baseline = fim_service.create_baseline(
            db=db_session,
            host_id=test_host.id,
            paths=[str(scan_dir)],
        )

        conf_file.write_text("root:tampered", encoding="utf-8")

        # First verification run
        _, devs_1, dets_1 = fim_service.verify_host_integrity(
            db=db_session, host_id=test_host.id, baseline_id=baseline.id
        )
        assert len(devs_1) == 1
        assert len(dets_1) >= 1

        # Second verification run with the same filesystem state
        _, devs_2, dets_2 = fim_service.verify_host_integrity(
            db=db_session, host_id=test_host.id, baseline_id=baseline.id
        )
        # Reuses existing deviation record, zero new detections created
        assert len(devs_2) == 1
        assert devs_2[0].id == devs_1[0].id
        assert len(dets_2) == 0  # Deduplicated!
