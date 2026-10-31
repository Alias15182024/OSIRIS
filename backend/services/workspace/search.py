"""Structured advanced forensic search service (Phase 2 Milestone 2.7)."""

from __future__ import annotations

import logging
from typing import Any, Optional
import uuid

from sqlalchemy import and_, false, func, or_, select
from sqlalchemy.orm import Session

from backend.api.schemas.search import (
    SearchFilter,
    SearchResultItem,
    SearchResultResponse,
)
from backend.db.models.detection import Detection
from backend.db.models.detection_rule import DetectionRule
from backend.db.models.event import Event
from backend.db.models.evidence_tag import EvidenceTag
from backend.db.models.evidence_tag_association import EvidenceTagAssociation
from backend.db.models.file import File
from backend.db.models.fim_deviation import FimDeviation
from backend.db.models.host import Host
from backend.db.models.incident import Incident
from backend.db.models.linux_user import LinuxUser
from backend.db.models.process import Process
from backend.db.models.snapshot import Snapshot
from backend.db.models.user_session import UserSession

logger = logging.getLogger("osiris.services.search")


class AdvancedSearchService:
    """Performs unified, host-isolated multi-entity queries across forensic evidence repositories."""

    def execute_search(
        self,
        db: Session,
        criteria: SearchFilter,
    ) -> SearchResultResponse:
        """Execute multi-entity search and return bounded, deterministically sorted results."""
        selected_entities = set(criteria.entity_types) if criteria.entity_types else None
        results: list[SearchResultItem] = []

        # 1. Events
        if selected_entities is None or "events" in selected_entities:
            results.extend(self._search_events(db, criteria))

        # 2. Processes
        if selected_entities is None or "processes" in selected_entities:
            results.extend(self._search_processes(db, criteria))

        # 3. User Sessions
        if selected_entities is None or "sessions" in selected_entities:
            results.extend(self._search_sessions(db, criteria))

        # 4. Detections
        if selected_entities is None or "detections" in selected_entities:
            results.extend(self._search_detections(db, criteria))

        # 5. FIM Deviations
        if selected_entities is None or "fim_deviations" in selected_entities:
            results.extend(self._search_fim_deviations(db, criteria))

        # 6. Incidents
        if selected_entities is None or "incidents" in selected_entities:
            results.extend(self._search_incidents(db, criteria))

        # 7. Files
        if selected_entities is None or "files" in selected_entities:
            results.extend(self._search_files(db, criteria))

        # 8. Linux Users
        if selected_entities is None or "users" in selected_entities:
            results.extend(self._search_users(db, criteria))

        # 9. Hosts
        if selected_entities is None or "hosts" in selected_entities:
            results.extend(self._search_hosts(db, criteria))

        # 10. Snapshots
        if selected_entities is None or "snapshots" in selected_entities:
            results.extend(self._search_snapshots(db, criteria))

        # Deterministic sorting: newest timestamp first, then entity_id
        def sort_key(item: SearchResultItem) -> tuple[int, str, str]:
            ts_epoch = int(item.timestamp.timestamp()) if item.timestamp else 0
            return (ts_epoch, str(item.entity_type), str(item.entity_id))

        results.sort(key=sort_key, reverse=True)

        total = len(results)
        paged_items = results[criteria.offset : criteria.offset + criteria.limit]

        # Attach tags to paged items
        self._attach_tags(db, paged_items)

        query_summary = {
            "entity_types": list(selected_entities) if selected_entities else "all",
            "host_id": str(criteria.host_id) if criteria.host_id else None,
            "query": criteria.query,
            "logic": criteria.logic,
        }

        return SearchResultResponse(
            items=paged_items,
            total=total,
            limit=criteria.limit,
            offset=criteria.offset,
            query_summary=query_summary,
        )

    def _attach_tags(self, db: Session, items: list[SearchResultItem]) -> None:
        """Query and populate evidence tags onto search result items in a single batch."""
        if not items:
            return

        evidence_keys = [(it.entity_type, it.entity_id) for it in items]
        type_to_ids: dict[str, list[str]] = {}
        for etype, eid in evidence_keys:
            type_to_ids.setdefault(etype, []).append(eid)

        or_clauses = [
            and_(
                EvidenceTagAssociation.evidence_type == etype,
                EvidenceTagAssociation.evidence_id.in_(eids),
            )
            for etype, eids in type_to_ids.items()
        ]

        if not or_clauses:
            return

        stmt = (
            select(
                EvidenceTagAssociation.evidence_type,
                EvidenceTagAssociation.evidence_id,
                EvidenceTag.name,
            )
            .join(EvidenceTag, EvidenceTagAssociation.tag_id == EvidenceTag.id)
            .where(or_(*or_clauses))
        )

        rows = db.execute(stmt).all()
        tag_map: dict[tuple[str, str], list[str]] = {}
        for etype, eid, tname in rows:
            tag_map.setdefault((etype, eid), []).append(tname)

        for item in items:
            item.tags = tag_map.get((item.entity_type, item.entity_id), [])

    @staticmethod
    def _try_uuid(val: Any) -> Optional[uuid.UUID]:
        try:
            return uuid.UUID(str(val))
        except (ValueError, TypeError, AttributeError):
            return None

    def _get_tagged_ids(self, db: Session, evidence_type: str, tags: list[str]) -> set[str]:
        """Fetch all evidence IDs matching any of the specified tag names in batch."""
        stmt = (
            select(EvidenceTagAssociation.evidence_id)
            .join(EvidenceTag, EvidenceTagAssociation.tag_id == EvidenceTag.id)
            .where(
                EvidenceTagAssociation.evidence_type == evidence_type,
                EvidenceTag.name.in_(tags),
            )
        )
        return set(db.scalars(stmt).all())

    # ── Subsystem Search Implementations ─────────────────────────────────────

    def _search_events(self, db: Session, criteria: SearchFilter) -> list[SearchResultItem]:
        stmt = select(Event)
        if criteria.host_id:
            stmt = stmt.where(Event.host_id == criteria.host_id)
        if criteria.start_time:
            stmt = stmt.where(Event.timestamp >= criteria.start_time)
        if criteria.end_time:
            stmt = stmt.where(Event.timestamp <= criteria.end_time)

        conditions = []
        if criteria.username:
            conditions.append(Event.username == criteria.username)
        if criteria.uid is not None:
            conditions.append(Event.uid == criteria.uid)
        if criteria.pid is not None:
            conditions.append(Event.pid == criteria.pid)
        if criteria.process_id:
            conditions.append(Event.process_id == criteria.process_id)
        if criteria.command:
            conditions.append(Event.command.ilike(f"%{criteria.command}%"))
        if criteria.file_path:
            conditions.append(Event.object_path.ilike(f"%{criteria.file_path}%"))
        if criteria.event_type:
            conditions.append(Event.event_type == criteria.event_type)
        if criteria.event_category:
            conditions.append(Event.source == criteria.event_category)
        eff_sev = criteria.severity or criteria.rule_severity
        if eff_sev:
            conditions.append(Event.severity == eff_sev)

        if criteria.query:
            q_pat = f"%{criteria.query}%"
            conditions.append(
                or_(
                    Event.command.ilike(q_pat),
                    Event.object_path.ilike(q_pat),
                    Event.event_type.ilike(q_pat),
                    Event.action.ilike(q_pat),
                    Event.username.ilike(q_pat),
                )
            )

        if criteria.tags:
            tagged_ids = self._get_tagged_ids(db, "event", criteria.tags)
            if criteria.logic == "and" and not tagged_ids:
                return []
            tagged_uuids = [self._try_uuid(tid) for tid in tagged_ids]
            tagged_uuids = [u for u in tagged_uuids if u is not None]
            if tagged_uuids:
                conditions.append(Event.id.in_(tagged_uuids))
            elif criteria.logic == "and":
                return []
            else:
                conditions.append(false())

        if conditions:
            comb = or_(*conditions) if criteria.logic == "or" else and_(*conditions)
            stmt = stmt.where(comb)

        stmt = stmt.order_by(Event.timestamp.desc()).limit(100)
        events = db.scalars(stmt).all()

        items = []
        for e in events:
            items.append(
                SearchResultItem(
                    entity_type="event",
                    entity_id=str(e.id),
                    title=f"{e.event_type} ({e.action})",
                    description=e.command or e.object_path or f"Action: {e.action}",
                    timestamp=e.timestamp,
                    host_id=e.host_id,
                    severity=e.severity,
                    metadata={"source": e.source, "uid": e.uid, "pid": e.pid},
                    provenance={"source_table": "events"},
                )
            )
        return items

    def _search_processes(self, db: Session, criteria: SearchFilter) -> list[SearchResultItem]:
        stmt = select(Process)
        if criteria.host_id:
            stmt = stmt.where(Process.host_id == criteria.host_id)
        if criteria.start_time:
            stmt = stmt.where(Process.started_at >= criteria.start_time)
        if criteria.end_time:
            stmt = stmt.where(Process.started_at <= criteria.end_time)

        conditions = []
        if criteria.pid is not None:
            conditions.append(Process.pid == criteria.pid)
        if criteria.process_id:
            conditions.append(Process.id == criteria.process_id)
        if criteria.command:
            conditions.append(Process.command.ilike(f"%{criteria.command}%"))
        if criteria.executable:
            conditions.append(Process.executable.ilike(f"%{criteria.executable}%"))

        if criteria.query:
            q_pat = f"%{criteria.query}%"
            conditions.append(
                or_(
                    Process.command.ilike(q_pat),
                    Process.executable.ilike(q_pat),
                )
            )

        if criteria.tags:
            tagged_ids = self._get_tagged_ids(db, "process", criteria.tags)
            if criteria.logic == "and" and not tagged_ids:
                return []
            tagged_uuids = [self._try_uuid(tid) for tid in tagged_ids]
            tagged_uuids = [u for u in tagged_uuids if u is not None]
            if tagged_uuids:
                conditions.append(Process.id.in_(tagged_uuids))
            elif criteria.logic == "and":
                return []
            else:
                conditions.append(false())

        if conditions:
            comb = or_(*conditions) if criteria.logic == "or" else and_(*conditions)
            stmt = stmt.where(comb)

        stmt = stmt.order_by(Process.started_at.desc()).limit(100)
        procs = db.scalars(stmt).all()

        items = []
        for p in procs:
            items.append(
                SearchResultItem(
                    entity_type="process",
                    entity_id=str(p.id),
                    title=f"Process PID {p.pid}: {p.command[:40]}",
                    description=p.command,
                    timestamp=p.started_at,
                    host_id=p.host_id,
                    metadata={"pid": p.pid, "ppid": p.ppid, "executable": p.executable},
                    provenance={"source_table": "processes"},
                )
            )
        return items

    def _search_sessions(self, db: Session, criteria: SearchFilter) -> list[SearchResultItem]:
        stmt = select(UserSession)
        if criteria.host_id:
            stmt = stmt.where(UserSession.host_id == criteria.host_id)
        if criteria.start_time:
            stmt = stmt.where(UserSession.started_at >= criteria.start_time)
        if criteria.end_time:
            stmt = stmt.where(UserSession.started_at <= criteria.end_time)

        conditions = []
        if criteria.session_type:
            conditions.append(UserSession.session_type == criteria.session_type)
        if criteria.remote_host:
            conditions.append(UserSession.remote_host.ilike(f"%{criteria.remote_host}%"))

        if criteria.query:
            q_pat = f"%{criteria.query}%"
            conditions.append(
                or_(
                    UserSession.session_type.ilike(q_pat),
                    UserSession.terminal.ilike(q_pat),
                    UserSession.remote_host.ilike(q_pat),
                )
            )

        if criteria.tags:
            tagged_ids = self._get_tagged_ids(db, "session", criteria.tags)
            if criteria.logic == "and" and not tagged_ids:
                return []
            tagged_uuids = [self._try_uuid(tid) for tid in tagged_ids]
            tagged_uuids = [u for u in tagged_uuids if u is not None]
            if tagged_uuids:
                conditions.append(UserSession.id.in_(tagged_uuids))
            elif criteria.logic == "and":
                return []
            else:
                conditions.append(false())

        if conditions:
            comb = or_(*conditions) if criteria.logic == "or" else and_(*conditions)
            stmt = stmt.where(comb)

        stmt = stmt.order_by(UserSession.started_at.desc()).limit(100)
        sessions = db.scalars(stmt).all()

        items = []
        for s in sessions:
            items.append(
                SearchResultItem(
                    entity_type="session",
                    entity_id=str(s.id),
                    title=f"Session ({s.session_type.upper()}) on {s.terminal or 'console'}",
                    description=f"Remote: {s.remote_host or 'local'}",
                    timestamp=s.started_at,
                    host_id=s.host_id,
                    status="active" if s.ended_at is None else "closed",
                    metadata={"session_type": s.session_type, "terminal": s.terminal},
                    provenance={"source_table": "sessions"},
                )
            )
        return items

    def _search_detections(self, db: Session, criteria: SearchFilter) -> list[SearchResultItem]:
        stmt = select(Detection).outerjoin(DetectionRule, Detection.rule_id == DetectionRule.id)
        if criteria.host_id:
            stmt = stmt.where(Detection.host_id == criteria.host_id)
        if criteria.start_time:
            stmt = stmt.where(Detection.timestamp >= criteria.start_time)
        if criteria.end_time:
            stmt = stmt.where(Detection.timestamp <= criteria.end_time)

        conditions = []
        if criteria.rule_id:
            try:
                parsed_uuid = uuid.UUID(criteria.rule_id)
                conditions.append(or_(Detection.rule_id == parsed_uuid, DetectionRule.rule_id == criteria.rule_id))
            except (ValueError, AttributeError):
                conditions.append(DetectionRule.rule_id == criteria.rule_id)
        eff_sev = criteria.severity or criteria.rule_severity
        if eff_sev:
            conditions.append(Detection.severity == eff_sev)

        if criteria.query:
            q_pat = f"%{criteria.query}%"
            conditions.append(
                or_(
                    Detection.title.ilike(q_pat),
                    Detection.category.ilike(q_pat),
                    DetectionRule.rule_id.ilike(q_pat),
                    DetectionRule.name.ilike(q_pat),
                )
            )

        if criteria.tags:
            tagged_ids = self._get_tagged_ids(db, "detection", criteria.tags)
            if criteria.logic == "and" and not tagged_ids:
                return []
            tagged_uuids = [self._try_uuid(tid) for tid in tagged_ids]
            tagged_uuids = [u for u in tagged_uuids if u is not None]
            if tagged_uuids:
                conditions.append(Detection.id.in_(tagged_uuids))
            elif criteria.logic == "and":
                return []
            else:
                conditions.append(false())

        if conditions:
            comb = or_(*conditions) if criteria.logic == "or" else and_(*conditions)
            stmt = stmt.where(comb)

        stmt = stmt.order_by(Detection.timestamp.desc()).limit(100)
        detections = db.scalars(stmt).all()

        items = []
        for d in detections:
            rule_id_str = d.rule.rule_id if d.rule else str(d.rule_id)
            items.append(
                SearchResultItem(
                    entity_type="detection",
                    entity_id=str(d.id),
                    title=d.title,
                    description=f"Rule: {rule_id_str} ({d.category})",
                    timestamp=d.timestamp,
                    host_id=d.host_id,
                    severity=d.severity,
                    status=d.status,
                    metadata={"rule_id": rule_id_str, "category": d.category},
                    provenance={"source_table": "detections"},
                )
            )
        return items

    def _search_fim_deviations(self, db: Session, criteria: SearchFilter) -> list[SearchResultItem]:
        stmt = select(FimDeviation)
        if criteria.host_id:
            stmt = stmt.where(FimDeviation.host_id == criteria.host_id)
        if criteria.start_time:
            stmt = stmt.where(FimDeviation.detected_at >= criteria.start_time)
        if criteria.end_time:
            stmt = stmt.where(FimDeviation.detected_at <= criteria.end_time)

        conditions = []
        if criteria.deviation_type:
            conditions.append(FimDeviation.deviation_type == criteria.deviation_type)
        if criteria.file_path:
            conditions.append(FimDeviation.file_path.ilike(f"%{criteria.file_path}%"))
        eff_sev = criteria.severity or criteria.rule_severity
        if eff_sev:
            conditions.append(FimDeviation.severity == eff_sev)

        if criteria.query:
            q_pat = f"%{criteria.query}%"
            conditions.append(
                or_(
                    FimDeviation.file_path.ilike(q_pat),
                    FimDeviation.deviation_type.ilike(q_pat),
                )
            )

        if criteria.tags:
            tagged_ids = self._get_tagged_ids(db, "fim_deviation", criteria.tags)
            if criteria.logic == "and" and not tagged_ids:
                return []
            tagged_uuids = [self._try_uuid(tid) for tid in tagged_ids]
            tagged_uuids = [u for u in tagged_uuids if u is not None]
            if tagged_uuids:
                conditions.append(FimDeviation.id.in_(tagged_uuids))
            elif criteria.logic == "and":
                return []
            else:
                conditions.append(false())

        if conditions:
            comb = or_(*conditions) if criteria.logic == "or" else and_(*conditions)
            stmt = stmt.where(comb)

        stmt = stmt.order_by(FimDeviation.detected_at.desc()).limit(100)
        deviations = db.scalars(stmt).all()

        items = []
        for dev in deviations:
            items.append(
                SearchResultItem(
                    entity_type="fim_deviation",
                    entity_id=str(dev.id),
                    title=f"FIM {dev.deviation_type.capitalize()}: {dev.file_path}",
                    description=f"Type: {dev.deviation_type} on {dev.file_path}",
                    timestamp=dev.detected_at,
                    host_id=dev.host_id,
                    severity=dev.severity,
                    metadata={"deviation_type": dev.deviation_type, "file_path": dev.file_path},
                    provenance={"source_table": "fim_deviations"},
                )
            )
        return items

    def _search_incidents(self, db: Session, criteria: SearchFilter) -> list[SearchResultItem]:
        stmt = select(Incident)
        if criteria.host_id:
            stmt = stmt.where(Incident.host_id == criteria.host_id)
        if criteria.start_time:
            stmt = stmt.where(Incident.created_at >= criteria.start_time)
        if criteria.end_time:
            stmt = stmt.where(Incident.created_at <= criteria.end_time)

        conditions = []
        if criteria.incident_status:
            conditions.append(Incident.status == criteria.incident_status)
        eff_inc_sev = criteria.severity or criteria.incident_severity
        if eff_inc_sev:
            conditions.append(Incident.severity == eff_inc_sev)

        if criteria.query:
            q_pat = f"%{criteria.query}%"
            conditions.append(
                or_(
                    Incident.title.ilike(q_pat),
                    Incident.description.ilike(q_pat),
                    Incident.category.ilike(q_pat),
                )
            )

        if criteria.tags:
            tagged_ids = self._get_tagged_ids(db, "incident", criteria.tags)
            if criteria.logic == "and" and not tagged_ids:
                return []
            tagged_uuids = [self._try_uuid(tid) for tid in tagged_ids]
            tagged_uuids = [u for u in tagged_uuids if u is not None]
            if tagged_uuids:
                conditions.append(Incident.id.in_(tagged_uuids))
            elif criteria.logic == "and":
                return []
            else:
                conditions.append(false())

        if conditions:
            comb = or_(*conditions) if criteria.logic == "or" else and_(*conditions)
            stmt = stmt.where(comb)

        stmt = stmt.order_by(Incident.created_at.desc()).limit(100)
        incidents = db.scalars(stmt).all()

        items = []
        for inc in incidents:
            items.append(
                SearchResultItem(
                    entity_type="incident",
                    entity_id=str(inc.id),
                    title=inc.title,
                    description=inc.description or f"Category: {inc.category}",
                    timestamp=inc.created_at,
                    host_id=inc.host_id,
                    severity=inc.severity,
                    status=inc.status,
                    metadata={"category": inc.category, "status": inc.status},
                    provenance={"source_table": "incidents"},
                )
            )
        return items

    def _search_files(self, db: Session, criteria: SearchFilter) -> list[SearchResultItem]:
        stmt = select(File)
        if criteria.host_id:
            stmt = stmt.where(File.host_id == criteria.host_id)
        if criteria.start_time:
            stmt = stmt.where(File.first_seen_at >= criteria.start_time)
        if criteria.end_time:
            stmt = stmt.where(File.first_seen_at <= criteria.end_time)

        conditions = []
        if criteria.file_path:
            conditions.append(File.path.ilike(f"%{criteria.file_path}%"))

        if criteria.query:
            conditions.append(File.path.ilike(f"%{criteria.query}%"))

        if criteria.tags:
            tagged_ids = self._get_tagged_ids(db, "file", criteria.tags)
            if criteria.logic == "and" and not tagged_ids:
                return []
            tagged_uuids = [self._try_uuid(tid) for tid in tagged_ids]
            tagged_uuids = [u for u in tagged_uuids if u is not None]
            if tagged_uuids:
                conditions.append(File.id.in_(tagged_uuids))
            elif criteria.logic == "and":
                return []
            else:
                conditions.append(false())

        if conditions:
            comb = or_(*conditions) if criteria.logic == "or" else and_(*conditions)
            stmt = stmt.where(comb)

        stmt = stmt.order_by(File.first_seen_at.desc()).limit(100)
        files = db.scalars(stmt).all()

        items = []
        for f in files:
            items.append(
                SearchResultItem(
                    entity_type="file",
                    entity_id=str(f.id),
                    title=f.path,
                    description=f"Type: {f.file_type}",
                    timestamp=f.first_seen_at,
                    host_id=f.host_id,
                    metadata={"path": f.path, "file_type": f.file_type},
                    provenance={"source_table": "files"},
                )
            )
        return items

    def _search_users(self, db: Session, criteria: SearchFilter) -> list[SearchResultItem]:
        stmt = select(LinuxUser)
        if criteria.host_id:
            stmt = stmt.where(LinuxUser.host_id == criteria.host_id)
        if criteria.start_time:
            stmt = stmt.where(LinuxUser.first_seen_at >= criteria.start_time)
        if criteria.end_time:
            stmt = stmt.where(LinuxUser.first_seen_at <= criteria.end_time)

        conditions = []
        if criteria.username:
            conditions.append(LinuxUser.username == criteria.username)
        if criteria.uid is not None:
            conditions.append(LinuxUser.uid == criteria.uid)
        if criteria.query:
            conditions.append(LinuxUser.username.ilike(f"%{criteria.query}%"))

        if criteria.tags:
            tagged_ids = self._get_tagged_ids(db, "user", criteria.tags)
            if criteria.logic == "and" and not tagged_ids:
                return []
            tagged_uuids = [self._try_uuid(tid) for tid in tagged_ids]
            tagged_uuids = [u for u in tagged_uuids if u is not None]
            if tagged_uuids:
                conditions.append(LinuxUser.id.in_(tagged_uuids))
            elif criteria.logic == "and":
                return []
            else:
                conditions.append(false())

        if conditions:
            comb = or_(*conditions) if criteria.logic == "or" else and_(*conditions)
            stmt = stmt.where(comb)

        stmt = stmt.order_by(LinuxUser.first_seen_at.desc()).limit(50)
        users = db.scalars(stmt).all()

        items = []
        for u in users:
            items.append(
                SearchResultItem(
                    entity_type="user",
                    entity_id=str(u.id),
                    title=f"{u.username} (UID {u.uid})",
                    description=f"Linux user account on host",
                    timestamp=u.first_seen_at,
                    host_id=u.host_id,
                    metadata={"username": u.username, "uid": u.uid},
                    provenance={"source_table": "linux_users"},
                )
            )
        return items

    def _search_hosts(self, db: Session, criteria: SearchFilter) -> list[SearchResultItem]:
        stmt = select(Host)
        if criteria.host_id:
            stmt = stmt.where(Host.id == criteria.host_id)
        if criteria.start_time:
            stmt = stmt.where(Host.created_at >= criteria.start_time)
        if criteria.end_time:
            stmt = stmt.where(Host.created_at <= criteria.end_time)

        conditions = []
        if criteria.hostname:
            conditions.append(Host.hostname.ilike(f"%{criteria.hostname}%"))
        if criteria.query:
            q_pat = f"%{criteria.query}%"
            conditions.append(
                or_(
                    Host.hostname.ilike(q_pat),
                    Host.ip_address.ilike(q_pat),
                    Host.os_info.ilike(q_pat),
                )
            )

        if criteria.tags:
            tagged_ids = self._get_tagged_ids(db, "host", criteria.tags)
            if criteria.logic == "and" and not tagged_ids:
                return []
            tagged_uuids = [self._try_uuid(tid) for tid in tagged_ids]
            tagged_uuids = [u for u in tagged_uuids if u is not None]
            if tagged_uuids:
                conditions.append(Host.id.in_(tagged_uuids))
            elif criteria.logic == "and":
                return []
            else:
                conditions.append(false())

        if conditions:
            comb = or_(*conditions) if criteria.logic == "or" else and_(*conditions)
            stmt = stmt.where(comb)

        stmt = stmt.order_by(Host.created_at.desc()).limit(20)
        hosts = db.scalars(stmt).all()

        items = []
        for h in hosts:
            items.append(
                SearchResultItem(
                    entity_type="host",
                    entity_id=str(h.id),
                    title=h.hostname,
                    description=f"IP: {h.ip_address or 'Unknown'} | OS: {h.os_info or 'Linux'}",
                    timestamp=h.created_at,
                    host_id=h.id,
                    metadata={"hostname": h.hostname, "ip_address": h.ip_address},
                    provenance={"source_table": "hosts"},
                )
            )
        return items

    def _search_snapshots(self, db: Session, criteria: SearchFilter) -> list[SearchResultItem]:
        stmt = select(Snapshot)
        if criteria.host_id:
            stmt = stmt.where(Snapshot.host_id == criteria.host_id)
        if criteria.start_time:
            stmt = stmt.where(Snapshot.timestamp >= criteria.start_time)
        if criteria.end_time:
            stmt = stmt.where(Snapshot.timestamp <= criteria.end_time)

        conditions = []
        if criteria.query:
            conditions.append(Snapshot.snapshot_type.ilike(f"%{criteria.query}%"))

        if criteria.tags:
            tagged_ids = self._get_tagged_ids(db, "snapshot", criteria.tags)
            if criteria.logic == "and" and not tagged_ids:
                return []
            tagged_uuids = [self._try_uuid(tid) for tid in tagged_ids]
            tagged_uuids = [u for u in tagged_uuids if u is not None]
            if tagged_uuids:
                conditions.append(Snapshot.id.in_(tagged_uuids))
            elif criteria.logic == "and":
                return []
            else:
                conditions.append(false())

        if conditions:
            comb = or_(*conditions) if criteria.logic == "or" else and_(*conditions)
            stmt = stmt.where(comb)

        stmt = stmt.order_by(Snapshot.timestamp.desc()).limit(50)
        snapshots = db.scalars(stmt).all()

        items = []
        for sn in snapshots:
            items.append(
                SearchResultItem(
                    entity_type="snapshot",
                    entity_id=str(sn.id),
                    title=f"{sn.snapshot_type.capitalize()} Snapshot",
                    description=f"Snapshot at {sn.timestamp.isoformat() if sn.timestamp else '--'}",
                    timestamp=sn.timestamp,
                    host_id=sn.host_id,
                    metadata={"snapshot_type": sn.snapshot_type},
                    provenance={"source_table": "snapshots"},
                )
            )
        return items
