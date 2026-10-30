"""Unified forensic evidence linking and provenance management."""

from __future__ import annotations

import logging
from typing import Any, Optional
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.db.base import utcnow
from backend.db.models.detection import Detection
from backend.db.models.event import Event
from backend.db.models.file import File
from backend.db.models.fim_deviation import FimDeviation
from backend.db.models.incident import Incident
from backend.db.models.incident_event import IncidentEvent
from backend.db.models.incident_evidence import IncidentEvidence
from backend.db.models.incident_history import IncidentHistory
from backend.db.models.process import Process
from backend.db.models.snapshot import Snapshot
from backend.db.models.user_session import UserSession
from backend.services.incidents.models import (
    EvidenceDuplicateError,
    EvidenceType,
    HistoryChangeType,
    HostMismatchError,
)

logger = logging.getLogger("osiris.services.incidents.evidence")


class EvidenceManager:
    """Manages association, provenance, and integrity of incident evidence."""

    @staticmethod
    def _check_host_isolation(incident: Incident, entity_host_id: Optional[uuid.UUID], entity_name: str) -> None:
        """Prevent cross-host contamination.

        If the incident is bound to a specific host, all attached evidence must
        originate from that same host.
        """
        if incident.host_id is not None and entity_host_id is not None:
            if incident.host_id != entity_host_id:
                raise HostMismatchError(
                    f"Cross-host evidence contamination rejected: {entity_name} host '{entity_host_id}' "
                    f"does not match incident host '{incident.host_id}'."
                )

    @staticmethod
    def _find_existing_evidence(
        db: Session,
        incident_id: uuid.UUID,
        evidence_type: str,
        source_id: str,
    ) -> IncidentEvidence | None:
        """Check if an evidence item is already linked to the incident."""
        stmt = select(IncidentEvidence).where(
            IncidentEvidence.incident_id == incident_id,
            IncidentEvidence.evidence_type == evidence_type,
            IncidentEvidence.source_id == source_id,
        )
        return db.execute(stmt).scalar_one_or_none()

    def link_detection(
        self,
        db: Session,
        incident: Incident,
        detection: Detection,
        reason: Optional[str] = None,
        acting_user_id: Optional[uuid.UUID] = None,
        raise_if_duplicate: bool = True,
    ) -> IncidentEvidence:
        """Link a security detection alert as evidence to an incident."""
        self._check_host_isolation(incident, detection.host_id, "Detection")

        source_id = str(detection.id)
        existing = self._find_existing_evidence(db, incident.id, EvidenceType.DETECTION.value, source_id)
        if existing is not None:
            if raise_if_duplicate:
                raise EvidenceDuplicateError(
                    f"Detection '{detection.id}' is already associated with incident '{incident.id}'."
                )
            return existing

        now = utcnow()
        provenance = {
            "subsystem": "detection_engine",
            "detection_id": source_id,
            "rule_id": str(detection.rule_id),
            "rule_version": detection.rule_version,
            "rule_title": detection.title,
            "severity": detection.severity,
            "category": detection.category,
            "timestamp": detection.timestamp.isoformat() if detection.timestamp else None,
            "host_id": str(detection.host_id),
            "dedup_hash": detection.dedup_hash,
            "matched_conditions": detection.matched_conditions,
            "correlation_reason": reason or "Detection correlated with incident",
        }

        evidence = IncidentEvidence(
            incident_id=incident.id,
            evidence_type=EvidenceType.DETECTION.value,
            source_id=source_id,
            title=f"Detection: {detection.title}",
            description=detection.description or f"Rule {detection.rule_id} triggered on host {detection.host_id}.",
            provenance=provenance,
            detection_id=detection.id,
            event_id=detection.event_id,
            fim_deviation_id=detection.fim_deviation_id,
            session_id=detection.session_id,
            process_id=detection.process_id,
            created_by_id=acting_user_id,
            created_at=now,
        )
        db.add(evidence)

        # If detection is associated with a primary event, ensure it is linked in incident_events
        if detection.event_id is not None:
            self.link_event_by_id(
                db=db,
                incident=incident,
                event_id=detection.event_id,
                relationship="detection_trigger",
                notes=f"Triggering event for detection '{detection.title}'",
                acting_user_id=acting_user_id,
            )

        # Record history
        history = IncidentHistory(
            incident_id=incident.id,
            change_type=HistoryChangeType.EVIDENCE_ADDED.value,
            user_id=acting_user_id,
            notes=f"Associated detection '{detection.title}' ({detection.severity}): {reason or 'Correlated evidence'}",
            history_metadata={"evidence_type": "detection", "detection_id": source_id},
            created_at=now,
        )
        db.add(history)
        db.flush()

        return evidence

    def link_fim_deviation(
        self,
        db: Session,
        incident: Incident,
        deviation: FimDeviation,
        reason: Optional[str] = None,
        acting_user_id: Optional[uuid.UUID] = None,
        raise_if_duplicate: bool = True,
    ) -> IncidentEvidence:
        """Link a File Integrity Monitoring deviation as evidence to an incident."""
        self._check_host_isolation(incident, deviation.host_id, "FIM Deviation")

        source_id = str(deviation.id)
        existing = self._find_existing_evidence(db, incident.id, EvidenceType.FIM_DEVIATION.value, source_id)
        if existing is not None:
            if raise_if_duplicate:
                raise EvidenceDuplicateError(
                    f"FIM deviation '{deviation.id}' is already associated with incident '{incident.id}'."
                )
            return existing

        now = utcnow()
        provenance = {
            "subsystem": "file_integrity_monitoring",
            "deviation_id": source_id,
            "baseline_id": str(deviation.baseline_id) if deviation.baseline_id else None,
            "file_path": deviation.file_path,
            "deviation_type": deviation.deviation_type,
            "severity": deviation.severity,
            "is_content_modified": deviation.is_content_modified,
            "is_metadata_modified": deviation.is_metadata_modified,
            "expected_values": deviation.expected_values,
            "observed_values": deviation.observed_values,
            "detected_at": deviation.detected_at.isoformat() if deviation.detected_at else None,
            "host_id": str(deviation.host_id),
            "correlation_reason": reason or "FIM deviation associated with incident",
        }

        evidence = IncidentEvidence(
            incident_id=incident.id,
            evidence_type=EvidenceType.FIM_DEVIATION.value,
            source_id=source_id,
            title=f"FIM Deviation: {deviation.file_path} ({deviation.deviation_type})",
            description=deviation.summary or f"Integrity change detected in {deviation.file_path}",
            provenance=provenance,
            detection_id=deviation.detection_id,
            fim_deviation_id=deviation.id,
            created_by_id=acting_user_id,
            created_at=now,
        )
        db.add(evidence)

        # Record history
        history = IncidentHistory(
            incident_id=incident.id,
            change_type=HistoryChangeType.EVIDENCE_ADDED.value,
            user_id=acting_user_id,
            notes=f"Associated FIM deviation on '{deviation.file_path}' ({deviation.deviation_type})",
            history_metadata={"evidence_type": "fim_deviation", "deviation_id": source_id},
            created_at=now,
        )
        db.add(history)
        db.flush()

        return evidence

    def link_event(
        self,
        db: Session,
        incident: Incident,
        event: Event,
        relationship: str = "related",
        notes: Optional[str] = None,
        acting_user_id: Optional[uuid.UUID] = None,
        raise_if_duplicate: bool = True,
    ) -> tuple[IncidentEvent, IncidentEvidence]:
        """Link a forensic event to an incident in both incident_events and incident_evidence."""
        self._check_host_isolation(incident, event.host_id, "Event")

        source_id = str(event.id)
        # Check incident_events
        evt_stmt = select(IncidentEvent).where(
            IncidentEvent.incident_id == incident.id,
            IncidentEvent.event_id == event.id,
        )
        existing_event = db.execute(evt_stmt).scalar_one_or_none()

        # Check incident_evidence
        existing_evidence = self._find_existing_evidence(
            db, incident.id, EvidenceType.EVENT.value, source_id
        )

        if existing_event is not None and existing_evidence is not None:
            if raise_if_duplicate:
                raise EvidenceDuplicateError(
                    f"Event '{event.id}' is already linked to incident '{incident.id}'."
                )
            return existing_event, existing_evidence

        now = utcnow()
        if existing_event is None:
            inc_event = IncidentEvent(
                incident_id=incident.id,
                event_id=event.id,
                relationship_role=relationship,
                association_timestamp=now,
                investigation_notes=notes,
            )
            db.add(inc_event)
        else:
            inc_event = existing_event

        if existing_evidence is None:
            provenance = {
                "subsystem": "event_stream",
                "event_id": source_id,
                "event_type": event.event_type,
                "action": event.action,
                "source": event.source,
                "severity": event.severity,
                "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                "pid": event.pid,
                "ppid": event.ppid,
                "uid": event.uid,
                "username": event.username,
                "command": event.command,
                "object_path": event.object_path,
                "host_id": str(event.host_id),
                "relationship": relationship,
            }
            inc_evidence = IncidentEvidence(
                incident_id=incident.id,
                evidence_type=EvidenceType.EVENT.value,
                source_id=source_id,
                title=f"Event: {event.event_type} ({event.action})",
                description=f"Source: {event.source}, Command: {event.command or 'N/A'}",
                provenance=provenance,
                event_id=event.id,
                process_id=event.process_id,
                created_by_id=acting_user_id,
                created_at=now,
            )
            db.add(inc_evidence)
        else:
            inc_evidence = existing_evidence

        history = IncidentHistory(
            incident_id=incident.id,
            change_type=HistoryChangeType.EVENT_LINKED.value,
            user_id=acting_user_id,
            notes=f"Linked event '{event.id}' ({event.event_type}): {notes or relationship}",
            history_metadata={"event_id": source_id, "relationship": relationship},
            created_at=now,
        )
        db.add(history)
        db.flush()

        return inc_event, inc_evidence

    def link_event_by_id(
        self,
        db: Session,
        incident: Incident,
        event_id: uuid.UUID,
        relationship: str = "related",
        notes: Optional[str] = None,
        acting_user_id: Optional[uuid.UUID] = None,
    ) -> Optional[IncidentEvent]:
        """Safely link an event by its ID if not already linked."""
        evt_stmt = select(IncidentEvent).where(
            IncidentEvent.incident_id == incident.id,
            IncidentEvent.event_id == event_id,
        )
        if db.execute(evt_stmt).scalar_one_or_none() is not None:
            return None

        event = db.get(Event, event_id)
        if event is None:
            logger.warning(
                "Event %s not found in database; cannot link to incident %s",
                event_id,
                incident.id,
            )
            return None

        inc_event, _ = self.link_event(
            db=db,
            incident=incident,
            event=event,
            relationship=relationship,
            notes=notes,
            acting_user_id=acting_user_id,
            raise_if_duplicate=False,
        )
        return inc_event

    def link_session(
        self,
        db: Session,
        incident: Incident,
        session: UserSession,
        reason: Optional[str] = None,
        acting_user_id: Optional[uuid.UUID] = None,
        raise_if_duplicate: bool = True,
    ) -> IncidentEvidence:
        """Link a user login session as evidence to an incident."""
        self._check_host_isolation(incident, session.host_id, "Session")

        source_id = str(session.id)
        existing = self._find_existing_evidence(db, incident.id, EvidenceType.SESSION.value, source_id)
        if existing is not None:
            if raise_if_duplicate:
                raise EvidenceDuplicateError(
                    f"Session '{session.id}' is already associated with incident '{incident.id}'."
                )
            return existing

        now = utcnow()
        provenance = {
            "subsystem": "session_reconstruction",
            "session_id": source_id,
            "session_type": session.session_type,
            "terminal": session.terminal,
            "remote_host": session.remote_host,
            "started_at": session.started_at.isoformat() if session.started_at else None,
            "ended_at": session.ended_at.isoformat() if session.ended_at else None,
            "linux_user_id": str(session.linux_user_id) if session.linux_user_id else None,
            "host_id": str(session.host_id),
            "correlation_reason": reason or "User session active during incident window",
        }

        user_label = session.terminal or session.session_type or "Session"
        evidence = IncidentEvidence(
            incident_id=incident.id,
            evidence_type=EvidenceType.SESSION.value,
            source_id=source_id,
            title=f"User Session: {user_label}",
            description=f"Terminal: {session.terminal or 'N/A'}, Remote: {session.remote_host or 'local'}",
            provenance=provenance,
            session_id=session.id,
            created_by_id=acting_user_id,
            created_at=now,
        )
        db.add(evidence)

        history = IncidentHistory(
            incident_id=incident.id,
            change_type=HistoryChangeType.EVIDENCE_ADDED.value,
            user_id=acting_user_id,
            notes=f"Linked session '{session.id}' ({user_label})",
            history_metadata={"evidence_type": "session", "session_id": source_id},
            created_at=now,
        )
        db.add(history)
        db.flush()

        return evidence

    def link_snapshot(
        self,
        db: Session,
        incident: Incident,
        snapshot: Snapshot,
        reason: Optional[str] = None,
        acting_user_id: Optional[uuid.UUID] = None,
        raise_if_duplicate: bool = True,
    ) -> IncidentEvidence:
        """Link a point-in-time system snapshot as evidence to an incident."""
        self._check_host_isolation(incident, snapshot.host_id, "Snapshot")

        source_id = str(snapshot.id)
        existing = self._find_existing_evidence(db, incident.id, EvidenceType.SNAPSHOT.value, source_id)
        if existing is not None:
            if raise_if_duplicate:
                raise EvidenceDuplicateError(
                    f"Snapshot '{snapshot.id}' is already associated with incident '{incident.id}'."
                )
            return existing

        now = utcnow()
        provenance = {
            "subsystem": "snapshot_service",
            "snapshot_id": source_id,
            "snapshot_type": snapshot.snapshot_type,
            "timestamp": snapshot.timestamp.isoformat() if snapshot.timestamp else None,
            "host_id": str(snapshot.host_id),
            "correlation_reason": reason or "Snapshot captured during incident timeframe",
        }

        evidence = IncidentEvidence(
            incident_id=incident.id,
            evidence_type=EvidenceType.SNAPSHOT.value,
            source_id=source_id,
            title=f"Snapshot: {snapshot.snapshot_type}",
            description=f"Point-in-time snapshot ({snapshot.snapshot_type}) captured at {snapshot.timestamp}",
            provenance=provenance,
            snapshot_id=snapshot.id,
            created_by_id=acting_user_id,
            created_at=now,
        )
        db.add(evidence)

        history = IncidentHistory(
            incident_id=incident.id,
            change_type=HistoryChangeType.EVIDENCE_ADDED.value,
            user_id=acting_user_id,
            notes=f"Linked snapshot '{snapshot.id}' ({snapshot.snapshot_type})",
            history_metadata={"evidence_type": "snapshot", "snapshot_id": source_id},
            created_at=now,
        )
        db.add(history)
        db.flush()

        return evidence

    def link_process(
        self,
        db: Session,
        incident: Incident,
        process: Process,
        reason: Optional[str] = None,
        acting_user_id: Optional[uuid.UUID] = None,
        raise_if_duplicate: bool = True,
    ) -> IncidentEvidence:
        """Link a process record as evidence to an incident."""
        self._check_host_isolation(incident, process.host_id, "Process")

        source_id = str(process.id)
        existing = self._find_existing_evidence(db, incident.id, EvidenceType.PROCESS.value, source_id)
        if existing is not None:
            if raise_if_duplicate:
                raise EvidenceDuplicateError(
                    f"Process '{process.id}' is already associated with incident '{incident.id}'."
                )
            return existing

        now = utcnow()
        cmd = getattr(process, "command", "") or ""
        exe = getattr(process, "executable", None) or getattr(process, "exe", None) or ""
        start_t = getattr(process, "started_at", None) or getattr(process, "start_time", None)
        end_t = getattr(process, "ended_at", None) or getattr(process, "end_time", None)
        proc_name = getattr(process, "name", None) or (cmd.split()[0] if cmd else "process")

        provenance = {
            "subsystem": "process_collector",
            "process_id": source_id,
            "pid": process.pid,
            "ppid": process.ppid,
            "command": cmd,
            "executable": exe,
            "started_at": start_t.isoformat() if start_t else None,
            "ended_at": end_t.isoformat() if end_t else None,
            "host_id": str(process.host_id),
            "correlation_reason": reason or "Process involved in incident activity",
        }

        evidence = IncidentEvidence(
            incident_id=incident.id,
            evidence_type=EvidenceType.PROCESS.value,
            source_id=source_id,
            title=f"Process: {proc_name} (PID {process.pid})",
            description=f"Command: {cmd or exe or 'N/A'}",
            provenance=provenance,
            process_id=process.id,
            created_by_id=acting_user_id,
            created_at=now,
        )
        db.add(evidence)

        history = IncidentHistory(
            incident_id=incident.id,
            change_type=HistoryChangeType.EVIDENCE_ADDED.value,
            user_id=acting_user_id,
            notes=f"Linked process '{proc_name}' (PID {process.pid})",
            history_metadata={"evidence_type": "process", "process_id": source_id},
            created_at=now,
        )
        db.add(history)
        db.flush()

        return evidence

    def link_file(
        self,
        db: Session,
        incident: Incident,
        file_record: File,
        reason: Optional[str] = None,
        acting_user_id: Optional[uuid.UUID] = None,
        raise_if_duplicate: bool = True,
    ) -> IncidentEvidence:
        """Link a file record as evidence to an incident."""
        self._check_host_isolation(incident, file_record.host_id, "File")

        source_id = str(file_record.id)
        existing = self._find_existing_evidence(db, incident.id, EvidenceType.FILE.value, source_id)
        if existing is not None:
            if raise_if_duplicate:
                raise EvidenceDuplicateError(
                    f"File '{file_record.id}' is already associated with incident '{incident.id}'."
                )
            return existing

        now = utcnow()
        file_size = getattr(file_record, "size", None)
        file_sha256 = getattr(file_record, "sha256", None)
        provenance = {
            "subsystem": "filesystem_collector",
            "file_id": source_id,
            "path": file_record.path,
            "file_type": file_record.file_type,
            "size": file_size,
            "sha256": file_sha256,
            "host_id": str(file_record.host_id),
            "correlation_reason": reason or "File implicated in incident activity",
        }

        evidence = IncidentEvidence(
            incident_id=incident.id,
            evidence_type=EvidenceType.FILE.value,
            source_id=source_id,
            title=f"File: {file_record.path}",
            description=f"Type: {file_record.file_type}, SHA256: {file_sha256 or 'N/A'}",
            provenance=provenance,
            file_id=file_record.id,
            created_by_id=acting_user_id,
            created_at=now,
        )
        db.add(evidence)

        history = IncidentHistory(
            incident_id=incident.id,
            change_type=HistoryChangeType.EVIDENCE_ADDED.value,
            user_id=acting_user_id,
            notes=f"Linked file '{file_record.path}'",
            history_metadata={"evidence_type": "file", "file_id": source_id},
            created_at=now,
        )
        db.add(history)
        db.flush()

        return evidence

    def link_custom_evidence(
        self,
        db: Session,
        incident: Incident,
        source_id: str,
        title: str,
        description: Optional[str] = None,
        provenance: Optional[dict[str, Any]] = None,
        acting_user_id: Optional[uuid.UUID] = None,
        raise_if_duplicate: bool = True,
    ) -> IncidentEvidence:
        """Link arbitrary custom forensic evidence to an incident."""
        existing = self._find_existing_evidence(db, incident.id, EvidenceType.CUSTOM.value, source_id)
        if existing is not None:
            if raise_if_duplicate:
                raise EvidenceDuplicateError(
                    f"Custom evidence '{source_id}' is already associated with incident '{incident.id}'."
                )
            return existing

        now = utcnow()
        prov_dict = provenance or {}
        # Check host isolation if host_id provided in provenance
        if "host_id" in prov_dict:
            try:
                host_uuid = uuid.UUID(str(prov_dict["host_id"]))
                self._check_host_isolation(incident, host_uuid, "Custom Evidence")
            except (ValueError, TypeError):
                pass

        evidence = IncidentEvidence(
            incident_id=incident.id,
            evidence_type=EvidenceType.CUSTOM.value,
            source_id=source_id,
            title=title,
            description=description,
            provenance=prov_dict,
            created_by_id=acting_user_id,
            created_at=now,
        )
        db.add(evidence)

        history = IncidentHistory(
            incident_id=incident.id,
            change_type=HistoryChangeType.EVIDENCE_ADDED.value,
            user_id=acting_user_id,
            notes=f"Linked custom evidence: '{title}' ({source_id})",
            history_metadata={"evidence_type": "custom", "source_id": source_id},
            created_at=now,
        )
        db.add(history)
        db.flush()

        return evidence
