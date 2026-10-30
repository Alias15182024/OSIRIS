"""Detection persistence and lifecycle service.

Handles:
- Declarative rule database synchronization.
- Event evaluation with persistent detection record creation.
- Alert deduplication via deterministic SHA-256 fingerprints.
- Forensic evidence and entity association preservation.
- Status and acknowledgment lifecycle updates.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional, Sequence
import uuid

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, joinedload

from backend.db.base import utcnow
from backend.db.models.detection import Detection
from backend.db.models.detection_rule import DetectionRule
from backend.services.detection.engine import DetectionEngine
from backend.services.detection.models import DetectionMatch, RuleDefinition
from backend.services.detection.rules_loader import load_rules_from_directory

logger = logging.getLogger("osiris.services.detection.service")


def _ensure_utc(dt: datetime | None) -> datetime | None:
    """Ensure datetime is UTC timezone-aware."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class DetectionService:
    """Authoritative detection persistence and alert management service."""

    def __init__(self, engine: DetectionEngine | None = None) -> None:
        self.engine = engine if engine is not None else DetectionEngine()

    def sync_rules(
        self, db: Session, rules: Sequence[RuleDefinition] | None = None
    ) -> list[DetectionRule]:
        """Synchronize declarative file-based rules into the detection_rules table."""
        if rules is None:
            rules = load_rules_from_directory()

        db_rules: list[DetectionRule] = []
        now = utcnow()

        for r_def in rules:
            existing = db.execute(
                select(DetectionRule).where(DetectionRule.rule_id == r_def.rule_id)
            ).scalar_one_or_none()

            cond_dict = r_def.conditions.model_dump(by_alias=True, exclude_none=True) if r_def.conditions else {}
            seq_dict = r_def.sequence.model_dump(by_alias=True, exclude_none=True) if r_def.sequence else None
            window = r_def.sequence.time_window_seconds if r_def.sequence else None

            if existing is None:
                new_rule = DetectionRule(
                    rule_id=r_def.rule_id,
                    name=r_def.name,
                    description=r_def.description or r_def.explanation,
                    category=r_def.category,
                    severity=r_def.severity,
                    enabled=r_def.enabled,
                    version=r_def.version,
                    rule_type=r_def.rule_type,
                    conditions=cond_dict,
                    sequence_conditions=seq_dict,
                    time_window_seconds=window,
                    rule_metadata=r_def.metadata,
                    created_at=now,
                    updated_at=None,
                )
                db.add(new_rule)
                db_rules.append(new_rule)
            else:
                existing.name = r_def.name
                existing.description = r_def.description or r_def.explanation
                existing.category = r_def.category
                existing.severity = r_def.severity
                existing.enabled = r_def.enabled
                existing.version = r_def.version
                existing.rule_type = r_def.rule_type
                existing.conditions = cond_dict
                existing.sequence_conditions = seq_dict
                existing.time_window_seconds = window
                existing.rule_metadata = r_def.metadata
                existing.updated_at = now
                db_rules.append(existing)

            # Also register rule with in-memory engine
            self.engine.add_rule(r_def)

        db.flush()
        return db_rules

    def evaluate_and_persist(
        self,
        db: Session,
        events: Sequence[Any],
        rules: Sequence[RuleDefinition] | None = None,
    ) -> list[Detection]:
        """Evaluate events against active rules and persist new detections.

        Guarantees idempotency and deduplication: if a detection with the same
        dedup_hash already exists, it is NOT recreated.
        """
        if not events:
            return []

        # Ensure rules are loaded in engine and synchronized in DB
        if not self.engine.rules:
            self.sync_rules(db, rules)

        matches = self.engine.evaluate_batch(events)
        if not matches:
            return []

        # Cache rule UUIDs by rule_id string
        rule_db_map: dict[str, uuid.UUID] = {}
        for r_row in db.execute(select(DetectionRule.rule_id, DetectionRule.id)).all():
            rule_db_map[r_row[0]] = r_row[1]

        # Query existing dedup_hashes in the database
        dedup_hashes = [m.dedup_hash for m in matches]
        existing_hashes = set(
            db.execute(
                select(Detection.dedup_hash).where(Detection.dedup_hash.in_(dedup_hashes))
            ).scalars().all()
        )

        persisted: list[Detection] = []
        now = utcnow()

        for match in matches:
            if match.dedup_hash in existing_hashes:
                logger.debug(f"Skipping duplicate detection with hash {match.dedup_hash}")
                continue

            rule_db_id = rule_db_map.get(match.rule_id)
            if not rule_db_id:
                # Rule not found in DB; flush sync
                self.sync_rules(db)
                rule_row = db.execute(
                    select(DetectionRule.id).where(DetectionRule.rule_id == match.rule_id)
                ).scalar_one_or_none()
                if not rule_row:
                    logger.error(f"Cannot persist detection: rule '{match.rule_id}' not found in database.")
                    continue
                rule_db_id = rule_row

            detection = Detection(
                rule_id=rule_db_id,
                rule_version=match.rule_version,
                host_id=match.host_id,
                event_id=match.primary_event_id,
                process_id=match.process_id,
                session_id=match.session_id,
                timestamp=_ensure_utc(match.timestamp) or now,
                severity=match.severity,
                title=match.title,
                description=match.description,
                category=match.category,
                status="open",
                notification_status="pending",
                matched_conditions=match.matched_conditions,
                evidence=match.evidence,
                dedup_hash=match.dedup_hash,
                created_at=now,
            )
            db.add(detection)
            persisted.append(detection)
            existing_hashes.add(match.dedup_hash)

        if persisted:
            db.flush()

        return persisted

    def get_detections(
        self,
        db: Session,
        host_id: Optional[uuid.UUID] = None,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        rule_id: Optional[str] = None,
        status: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Detection], int]:
        """Fetch paginated detections with structured filters and deterministic ordering."""
        stmt = select(Detection).options(
            joinedload(Detection.rule),
            joinedload(Detection.host),
            joinedload(Detection.acknowledged_by),
        )

        conditions = []
        if host_id is not None:
            conditions.append(Detection.host_id == host_id)
        if severity is not None:
            conditions.append(Detection.severity == severity.lower())
        if category is not None:
            conditions.append(Detection.category == category.lower())
        if status is not None:
            conditions.append(Detection.status == status.lower())
        if rule_id is not None:
            stmt = stmt.join(Detection.rule)
            conditions.append(DetectionRule.rule_id == rule_id)
        if start_time is not None:
            conditions.append(Detection.timestamp >= _ensure_utc(start_time))
        if end_time is not None:
            conditions.append(Detection.timestamp <= _ensure_utc(end_time))

        if conditions:
            stmt = stmt.where(*conditions)

        # Count total
        count_stmt = select(func.count(Detection.id))
        if rule_id is not None:
            count_stmt = count_stmt.join(Detection.rule)
        if conditions:
            count_stmt = count_stmt.where(*conditions)
        total = db.execute(count_stmt).scalar() or 0

        # Deterministic ordering: latest timestamp first, then id ascending
        stmt = stmt.order_by(Detection.timestamp.desc(), Detection.id.asc())
        stmt = stmt.limit(limit).offset(offset)

        items = list(db.execute(stmt).scalars().unique().all())
        return items, total

    def get_detection(self, db: Session, detection_id: uuid.UUID) -> Detection | None:
        """Fetch a single detection record with joined relationships."""
        stmt = (
            select(Detection)
            .options(
                joinedload(Detection.rule),
                joinedload(Detection.host),
                joinedload(Detection.acknowledged_by),
            )
            .where(Detection.id == detection_id)
        )
        return db.execute(stmt).scalars().first()

    def acknowledge_detection(
        self,
        db: Session,
        detection_id: uuid.UUID,
        user_id: uuid.UUID,
        notes: Optional[str] = None,
    ) -> Detection:
        """Acknowledge a detection alert, recording timestamp and acting user."""
        detection = self.get_detection(db, detection_id)
        if detection is None:
            raise ValueError(f"Detection with ID '{detection_id}' not found.")

        detection.status = "acknowledged"
        detection.acknowledged_at = utcnow()
        detection.acknowledged_by_id = user_id

        if notes:
            current_evidence = dict(detection.evidence or {})
            current_evidence["acknowledgment_notes"] = notes
            detection.evidence = current_evidence

        db.flush()
        return detection

    def get_rules(
        self,
        db: Session,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        enabled: Optional[bool] = None,
    ) -> list[DetectionRule]:
        """Fetch all stored detection rules with optional filters."""
        stmt = select(DetectionRule)
        conditions = []
        if category:
            conditions.append(DetectionRule.category == category.lower())
        if severity:
            conditions.append(DetectionRule.severity == severity.lower())
        if enabled is not None:
            conditions.append(DetectionRule.enabled == enabled)

        if conditions:
            stmt = stmt.where(*conditions)

        stmt = stmt.order_by(DetectionRule.rule_id.asc())
        return list(db.execute(stmt).scalars().all())
