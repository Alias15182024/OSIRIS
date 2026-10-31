"""File Integrity Monitoring service managing baselines, deviations, and detection integration."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional, Sequence
import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.db.base import utcnow
from backend.db.models.detection import Detection
from backend.db.models.fim_baseline import FimBaseline
from backend.db.models.fim_baseline_file import FimBaselineFile
from backend.db.models.fim_deviation import FimDeviation
from backend.db.models.host import Host
from backend.services.detection.service import DetectionService, _ensure_utc
from backend.services.fim.comparator import DeviationResult, FimComparator
from backend.services.fim.fingerprint import FileFingerprint, normalize_path
from backend.services.fim.scanner import FimScanner

logger = logging.getLogger("osiris.services.fim.service")


class FimError(Exception):
    """Base exception for FIM operations."""
    pass


class HostNotFoundError(FimError):
    """Raised when the specified host does not exist."""
    pass


class BaselineNotFoundError(FimError):
    """Raised when the requested baseline is not found."""
    pass


class FimService:
    """Authoritative service managing FIM lifecycle, baselines, and deviations."""

    def __init__(self, detection_service: Optional[DetectionService] = None) -> None:
        self.detection_service = detection_service if detection_service is not None else DetectionService()

    def create_baseline(
        self,
        db: Session,
        host_id: uuid.UUID,
        paths: list[str],
        include_patterns: Optional[list[str]] = None,
        exclude_patterns: Optional[list[str]] = None,
    ) -> FimBaseline:
        """Create a new, immutable file integrity baseline for a host.

        Traverses configured filesystem directories safely, computes cryptographic
        checksums, and records baseline state with incremented version.
        """
        host = db.get(Host, host_id)
        if host is None:
            raise HostNotFoundError(f"Host with id '{host_id}' not found.")

        # Determine next baseline version
        max_ver = db.execute(
            select(func.max(FimBaseline.version)).where(FimBaseline.host_id == host_id)
        ).scalar() or 0
        new_version = max_ver + 1

        norm_paths = [normalize_path(p) for p in paths]
        scanner = FimScanner(
            paths=norm_paths,
            include_patterns=include_patterns,
            exclude_patterns=exclude_patterns,
        )

        now = utcnow()
        files_map, summary = scanner.scan()
        completed_at = utcnow()

        status = "completed" if summary.is_complete else "failed"

        baseline = FimBaseline(
            host_id=host_id,
            version=new_version,
            status=status,
            path_scope=norm_paths,
            include_patterns=include_patterns,
            exclude_patterns=exclude_patterns,
            total_files=summary.total_files,
            total_bytes=summary.total_bytes,
            scan_duration_ms=summary.duration_ms,
            error_message="; ".join(err["error"] for err in summary.errors) if summary.errors else None,
            baseline_metadata={"scanner": "FimScanner_v1", "summary": summary.to_dict()},
            baseline_at=now,
            completed_at=completed_at,
            created_at=now,
        )
        db.add(baseline)
        db.flush()

        # Persist individual baseline file records
        for file_path, fp in files_map.items():
            base_file = FimBaselineFile(
                baseline_id=baseline.id,
                host_id=host_id,
                file_path=file_path,
                file_name=fp.file_name,
                file_type=fp.file_type,
                hash_sha256=fp.sha256,
                hash_sha1=fp.sha1,
                hash_md5=fp.md5,
                file_size=fp.size,
                permissions=fp.permissions,
                mode=fp.mode,
                owner_uid=fp.owner_uid,
                owner_gid=fp.owner_gid,
                owner_user=fp.owner_user,
                owner_group=fp.owner_group,
                mtime=fp.mtime,
                ctime=fp.ctime,
                inode=fp.inode,
                device_id=fp.device_id,
                symlink_target=fp.symlink_target,
                is_suid=fp.is_suid,
                is_sgid=fp.is_sgid,
                is_executable=fp.is_executable,
                fingerprint_metadata=fp.fingerprint_metadata,
                created_at=now,
            )
            db.add(base_file)

        db.flush()
        db.refresh(baseline)
        return baseline

    def verify_host_integrity(
        self,
        db: Session,
        host_id: uuid.UUID,
        baseline_id: Optional[uuid.UUID] = None,
        paths: Optional[list[str]] = None,
    ) -> tuple[FimBaseline, list[FimDeviation], list[Detection]]:
        """Verify host filesystem integrity against trusted baseline.

        Returns:
            Tuple of (baseline, deviations, detections).
        """
        host = db.get(Host, host_id)
        if host is None:
            raise HostNotFoundError(f"Host with id '{host_id}' not found.")

        if baseline_id is not None:
            baseline = db.get(FimBaseline, baseline_id)
            if baseline is None or baseline.host_id != host_id:
                raise BaselineNotFoundError(f"Baseline '{baseline_id}' not found for host '{host_id}'.")
        else:
            baseline = db.execute(
                select(FimBaseline)
                .where(FimBaseline.host_id == host_id, FimBaseline.status == "completed")
                .order_by(FimBaseline.version.desc())
            ).scalars().first()
            if baseline is None:
                raise BaselineNotFoundError(f"No completed baseline exists for host '{host_id}'.")

        # Load baseline files map
        baseline_files: dict[str, FimBaselineFile] = {
            bf.file_path: bf for bf in baseline.files
        }

        # Determine target paths to scan with scope validation
        if paths:
            norm_req_paths = [normalize_path(p) for p in paths]
            baseline_scope = [normalize_path(p) for p in (baseline.path_scope or [])]
            for rp in norm_req_paths:
                in_scope = any(rp == sp or rp.startswith(sp + "/") for sp in baseline_scope)
                if not in_scope:
                    raise FimError(f"Requested verification path '{rp}' is outside baseline path scope.")
            paths_to_scan = norm_req_paths
        else:
            paths_to_scan = [normalize_path(p) for p in (baseline.path_scope or [])]

        scanner = FimScanner(
            paths=paths_to_scan,
            include_patterns=baseline.include_patterns,
            exclude_patterns=baseline.exclude_patterns,
        )

        current_files, summary = scanner.scan()

        # Run differential comparison
        dev_results = FimComparator.compare(
            baseline_files=baseline_files,
            current_files=current_files,
            scanned_scope=paths_to_scan,
            is_complete=summary.is_complete,
        )

        now = utcnow()
        persisted_deviations: list[FimDeviation] = []

        # Cache existing deviations for this baseline to prevent duplicate active rows
        existing_devs = db.execute(
            select(FimDeviation).where(FimDeviation.baseline_id == baseline.id)
        ).scalars().all()

        existing_map: dict[tuple[str, str], FimDeviation] = {
            (d.file_path, d.deviation_type): d for d in existing_devs
        }

        for r in dev_results:
            key = (r.file_path, r.deviation_type)
            existing = existing_map.get(key)

            if existing is not None and existing.observed_values == r.observed_values:
                # Duplicate deviation with identical values already recorded
                persisted_deviations.append(existing)
                continue

            deviation = FimDeviation(
                host_id=host_id,
                baseline_id=baseline.id,
                baseline_file_id=r.baseline_file_id,
                detection_id=None,
                file_path=r.file_path,
                file_type=r.file_type,
                deviation_type=r.deviation_type,
                severity=r.severity,
                is_content_modified=r.is_content_modified,
                is_metadata_modified=r.is_metadata_modified,
                expected_values=r.expected_values,
                observed_values=r.observed_values,
                summary=r.summary,
                explanation=r.explanation,
                detected_at=now,
                created_at=now,
            )
            db.add(deviation)
            persisted_deviations.append(deviation)
            existing_map[key] = deviation

        db.flush()

        # Evaluate deviations against detection engine rules
        new_detections: list[Detection] = []
        for dev in persisted_deviations:
            obs = {
                "id": dev.id,
                "host_id": host_id,
                "event_type": "fim:deviation",
                "action": dev.deviation_type,
                "source": "fim",
                "object_type": dev.file_type or "file",
                "object_path": dev.file_path,
                "severity": dev.severity,
                "timestamp": dev.detected_at,
                "payload": {
                    "deviation_id": str(dev.id),
                    "baseline_id": str(baseline.id),
                    "file_path": dev.file_path,
                    "deviation_type": dev.deviation_type,
                    "is_content_modified": dev.is_content_modified,
                    "is_metadata_modified": dev.is_metadata_modified,
                    "expected": dev.expected_values or {},
                    "observed": dev.observed_values or {},
                    "permissions": (dev.observed_values or {}).get("permissions"),
                    "is_suid": (dev.observed_values or {}).get("is_suid", False),
                    "is_executable": (dev.observed_values or {}).get("is_executable", False),
                },
            }

            dets = self.detection_service.evaluate_and_persist(db, [obs])
            for d in dets:
                d.fim_deviation_id = dev.id
                if dev.detection_id is None:
                    dev.detection_id = d.id
                if d.evidence is not None:
                    ev_dict = dict(d.evidence)
                    ev_dict["expected"] = dev.expected_values
                    ev_dict["observed"] = dev.observed_values
                    ev_dict["baseline_id"] = str(baseline.id)
                    ev_dict["deviation_id"] = str(dev.id)
                    ev_dict["file_path"] = dev.file_path
                    d.evidence = ev_dict
                new_detections.append(d)

        db.flush()
        return baseline, persisted_deviations, new_detections

    def get_baselines(
        self,
        db: Session,
        host_id: Optional[uuid.UUID] = None,
        status: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[FimBaseline], int]:
        """Query baselines with filtering and deterministic pagination."""
        query = select(FimBaseline)

        if host_id:
            query = query.where(FimBaseline.host_id == host_id)
        if status:
            query = query.where(FimBaseline.status == status)
        if start_time:
            st = _ensure_utc(start_time)
            if st:
                query = query.where(FimBaseline.baseline_at >= st)
        if end_time:
            et = _ensure_utc(end_time)
            if et:
                query = query.where(FimBaseline.baseline_at <= et)

        total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
        items = db.execute(
            query.order_by(FimBaseline.created_at.desc(), FimBaseline.id.desc())
            .offset(offset)
            .limit(limit)
        ).scalars().all()

        return list(items), total

    def get_baseline_by_id(self, db: Session, baseline_id: uuid.UUID) -> Optional[FimBaseline]:
        """Retrieve baseline by UUID."""
        return db.get(FimBaseline, baseline_id)

    def get_baseline_files(
        self,
        db: Session,
        baseline_id: uuid.UUID,
        path_prefix: Optional[str] = None,
        file_type: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[FimBaselineFile], int]:
        """Query individual files in a baseline."""
        query = select(FimBaselineFile).where(FimBaselineFile.baseline_id == baseline_id)

        if path_prefix:
            query = query.where(FimBaselineFile.file_path.startswith(path_prefix))
        if file_type:
            query = query.where(FimBaselineFile.file_type == file_type)

        total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
        items = db.execute(
            query.order_by(FimBaselineFile.file_path.asc())
            .offset(offset)
            .limit(limit)
        ).scalars().all()

        return list(items), total

    def get_deviations(
        self,
        db: Session,
        host_id: Optional[uuid.UUID] = None,
        baseline_id: Optional[uuid.UUID] = None,
        file_path: Optional[str] = None,
        deviation_type: Optional[str] = None,
        severity: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[FimDeviation], int]:
        """Query integrity deviations with filtering and deterministic pagination."""
        query = select(FimDeviation)

        if host_id:
            query = query.where(FimDeviation.host_id == host_id)
        if baseline_id:
            query = query.where(FimDeviation.baseline_id == baseline_id)
        if file_path:
            query = query.where(FimDeviation.file_path.contains(file_path))
        if deviation_type:
            query = query.where(FimDeviation.deviation_type == deviation_type)
        if severity:
            query = query.where(FimDeviation.severity == severity)
        if start_time:
            st = _ensure_utc(start_time)
            if st:
                query = query.where(FimDeviation.detected_at >= st)
        if end_time:
            et = _ensure_utc(end_time)
            if et:
                query = query.where(FimDeviation.detected_at <= et)

        total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
        items = db.execute(
            query.order_by(FimDeviation.detected_at.desc(), FimDeviation.id.desc())
            .offset(offset)
            .limit(limit)
        ).scalars().all()

        return list(items), total

    def get_deviation_by_id(self, db: Session, deviation_id: uuid.UUID) -> Optional[FimDeviation]:
        """Retrieve deviation by UUID."""
        return db.get(FimDeviation, deviation_id)
