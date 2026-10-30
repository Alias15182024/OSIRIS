"""Detection correlation and automatic incident creation engine."""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Optional, Sequence
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.db.base import utcnow
from backend.db.models.detection import Detection
from backend.db.models.incident import Incident
from backend.db.models.incident_evidence import IncidentEvidence
from backend.db.models.incident_history import IncidentHistory
from backend.services.incidents.evidence_manager import EvidenceManager
from backend.services.incidents.models import (
    EvidenceType,
    HistoryChangeType,
    IncidentStatus,
    SEVERITY_ORDER,
)

logger = logging.getLogger("osiris.services.incidents.correlator")

# Default active correlation window: 2 hours (7200 seconds)
DEFAULT_CORRELATION_WINDOW_SECONDS = 7200


def _ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class DetectionCorrelator:
    """Correlates security detections into coherent, host-isolated incidents."""

    def __init__(
        self,
        window_seconds: int = DEFAULT_CORRELATION_WINDOW_SECONDS,
        evidence_manager: Optional[EvidenceManager] = None,
    ) -> None:
        self.window_seconds = window_seconds
        self.evidence_manager = evidence_manager or EvidenceManager()

    def find_incident_for_detection(
        self, db: Session, detection_id: uuid.UUID
    ) -> Incident | None:
        """Find the incident to which a detection is already attached, if any."""
        source_id = str(detection_id)
        stmt = (
            select(Incident)
            .join(IncidentEvidence, IncidentEvidence.incident_id == Incident.id)
            .where(
                IncidentEvidence.evidence_type == EvidenceType.DETECTION.value,
                IncidentEvidence.source_id == source_id,
            )
        )
        return db.execute(stmt).scalar_one_or_none()

    def correlate_detection(
        self,
        db: Session,
        detection: Detection,
    ) -> tuple[Incident, bool]:
        """Correlate a single detection to an existing incident or create a new one.

        Returns
        -------
        tuple[Incident, bool]
            (incident, is_new) where is_new is True if a new incident was created.
        """
        # 1. Idempotency Check: if detection is already linked to an incident, do not duplicate
        existing_incident = self.find_incident_for_detection(db, detection.id)
        if existing_incident is not None:
            logger.debug(
                f"Detection '{detection.id}' already associated with incident '{existing_incident.id}'. Skipping."
            )
            return existing_incident, False

        det_time = _ensure_utc(detection.timestamp) or _ensure_utc(utcnow())

        # 2. Host-isolated Candidate Search: Find open or investigating incidents on the SAME host
        candidate_stmt = (
            select(Incident)
            .where(
                Incident.host_id == detection.host_id,
                Incident.status.in_([
                    IncidentStatus.OPEN.value,
                    IncidentStatus.INVESTIGATING.value,
                ]),
            )
            .order_by(Incident.last_observed_at.desc(), Incident.created_at.desc())
        )
        candidates = list(db.execute(candidate_stmt).scalars().all())

        matched_incident: Optional[Incident] = None
        correlation_reason: str = ""

        # 3. Evaluate correlation criteria
        for cand in candidates:
            cand_last = _ensure_utc(cand.last_observed_at) or _ensure_utc(cand.created_at)
            time_diff = abs((det_time - cand_last).total_seconds())

            # Candidate must be within investigation time window
            if time_diff > self.window_seconds:
                continue

            # Query existing evidence IDs for this candidate to check context overlap
            cand_evidence = db.execute(
                select(IncidentEvidence).where(IncidentEvidence.incident_id == cand.id)
            ).scalars().all()

            cand_sessions = {
                e.session_id for e in cand_evidence if e.session_id is not None
            }

            # Enforce user session isolation (Part 4 Requirement 7):
            # If the candidate has linked session(s) and the incoming detection is from
            # a different specific session, do NOT combine unrelated user sessions.
            if (
                detection.session_id is not None
                and cand_sessions
                and detection.session_id not in cand_sessions
            ):
                continue

            # Rule A: Shared session context
            if detection.session_id is not None and detection.session_id in cand_sessions:
                matched_incident = cand
                correlation_reason = f"Correlated via shared session context '{detection.session_id}'"
                break

            # Rule B: Shared process context
            if detection.process_id is not None:
                has_process = any(
                    e.process_id == detection.process_id
                    for e in cand_evidence
                    if e.process_id is not None
                )
                if has_process:
                    matched_incident = cand
                    correlation_reason = f"Correlated via shared process context '{detection.process_id}'"
                    break

            # Rule C: Shared FIM deviation context
            if detection.fim_deviation_id is not None:
                has_fim = any(
                    e.fim_deviation_id == detection.fim_deviation_id
                    for e in cand_evidence
                    if e.fim_deviation_id is not None
                )
                if has_fim:
                    matched_incident = cand
                    correlation_reason = f"Correlated via shared FIM deviation '{detection.fim_deviation_id}'"
                    break

            # Rule D: Shared source event context
            if detection.event_id is not None:
                has_event = any(
                    e.event_id == detection.event_id
                    for e in cand_evidence
                    if e.event_id is not None
                )
                if not has_event:
                    # Also check cand.events (incident_events association table)
                    has_event = any(
                        ie.event_id == detection.event_id
                        for ie in cand.events
                    )
                if has_event:
                    matched_incident = cand
                    correlation_reason = f"Correlated via shared source event '{detection.event_id}'"
                    break

            # Rule E: Recurring detection rule on host within investigation window
            if detection.rule_id is not None:
                has_rule = any(
                    e.evidence_type == EvidenceType.DETECTION.value
                    and isinstance(e.provenance, dict)
                    and e.provenance.get("rule_id") == str(detection.rule_id)
                    for e in cand_evidence
                )
                if has_rule:
                    matched_incident = cand
                    correlation_reason = (
                        f"Correlated via recurring detection rule '{detection.rule_id}' "
                        f"within active window ({int(time_diff)}s <= {self.window_seconds}s)"
                    )
                    break

            # Rule F: Matching attack category within active window (when no session conflict)
            if detection.category == cand.category:
                matched_incident = cand
                correlation_reason = (
                    f"Correlated via matching category '{detection.category}' within active "
                    f"investigation window ({int(time_diff)}s <= {self.window_seconds}s)"
                )
                break

        # 4. Attach to matched incident or create new incident
        now = utcnow()
        if matched_incident is not None:
            # Attach detection to existing incident
            self.evidence_manager.link_detection(
                db=db,
                incident=matched_incident,
                detection=detection,
                reason=correlation_reason,
                raise_if_duplicate=False,
            )

            # Update observation timestamps
            if matched_incident.first_observed_at is None or det_time < _ensure_utc(matched_incident.first_observed_at):
                matched_incident.first_observed_at = det_time
            if matched_incident.last_observed_at is None or det_time > _ensure_utc(matched_incident.last_observed_at):
                matched_incident.last_observed_at = det_time
            matched_incident.updated_at = now

            # Check severity escalation
            det_rank = SEVERITY_ORDER.get(detection.severity.lower(), 0)
            cur_rank = SEVERITY_ORDER.get(matched_incident.severity.lower(), 0)
            if det_rank > cur_rank:
                old_sev = matched_incident.severity
                matched_incident.severity = detection.severity
                history_esc = IncidentHistory(
                    incident_id=matched_incident.id,
                    change_type=HistoryChangeType.SEVERITY_CHANGE.value,
                    from_severity=old_sev,
                    to_severity=detection.severity,
                    notes=(
                        f"Automatic severity escalation triggered by detection '{detection.title}' "
                        f"({detection.severity.upper()})"
                    ),
                    history_metadata={
                        "triggering_detection_id": str(detection.id),
                        "reason": correlation_reason,
                    },
                    created_at=now,
                )
                db.add(history_esc)

            db.flush()
            return matched_incident, False

        # 5. Create new Incident
        new_incident = Incident(
            title=f"Incident: {detection.title}",
            description=detection.description or f"Automated incident generated from detection rule {detection.rule_id}.",
            severity=detection.severity,
            status=IncidentStatus.OPEN.value,
            category=detection.category,
            host_id=detection.host_id,
            first_observed_at=det_time,
            last_observed_at=det_time,
            created_at=now,
            updated_at=None,
        )
        db.add(new_incident)
        db.flush()

        # Record incident creation history
        creation_history = IncidentHistory(
            incident_id=new_incident.id,
            change_type=HistoryChangeType.INCIDENT_CREATED.value,
            to_status=IncidentStatus.OPEN.value,
            to_severity=detection.severity,
            notes=f"Incident automatically created from detection '{detection.title}'",
            history_metadata={
                "triggering_detection_id": str(detection.id),
                "rule_id": str(detection.rule_id),
                "category": detection.category,
            },
            created_at=now,
        )
        db.add(creation_history)

        # Attach initial detection as primary evidence
        self.evidence_manager.link_detection(
            db=db,
            incident=new_incident,
            detection=detection,
            reason="Initial triggering detection",
            raise_if_duplicate=False,
        )

        db.flush()
        return new_incident, True

    def correlate_batch(
        self,
        db: Session,
        detections: Sequence[Detection],
    ) -> list[tuple[Incident, bool]]:
        """Correlate a batch of detections in chronological sequence."""
        if not detections:
            return []

        # Sort detections chronologically by timestamp ascending
        sorted_detections = sorted(
            detections,
            key=lambda d: _ensure_utc(d.timestamp) or datetime.min.replace(tzinfo=timezone.utc),
        )

        results: list[tuple[Incident, bool]] = []
        for det in sorted_detections:
            res = self.correlate_detection(db, det)
            results.append(res)

        return results
