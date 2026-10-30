"""Timeline Reconstruction Service for OSIRIS Phase 2 Milestone 2.2.

Correlates forensic records from events, processes, files, sessions, snapshots,
and resource telemetry into a unified, chronologically ordered sequence.

Design principles:
1. Forensic integrity: Original timestamps, source identifiers, and provenance
   are strictly preserved.
2. Deduplication: Entries present in the core events log are not duplicated
   from secondary tables (e.g. process starts/ends, file observations).
3. Cross-host isolation: Records from different hosts are never correlated.
4. Database efficiency: Leverages existing indexes; performs pagination and
   ordering inside SQL without loading massive historical datasets into memory.
5. Graceful handling: Missing relationships, empty results, and unknown users
   are handled safely without raising unhandled errors.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import (
    Integer,
    case,
    exists,
    func,
    literal,
    not_,
    or_,
    select,
    union_all,
)
from sqlalchemy.orm import Session

from backend.api.schemas.timeline import (
    FileContext,
    ProcessContext,
    ResourceContext,
    SessionContext,
    SnapshotContext,
    TimelineEntryResponse,
    UserContext,
)
from backend.db.models.event import Event
from backend.db.models.file import File
from backend.db.models.host import Host
from backend.db.models.linux_user import LinuxUser
from backend.db.models.process import Process
from backend.db.models.resource_snapshot import ResourceSnapshot
from backend.db.models.snapshot import Snapshot
from backend.db.models.user_session import UserSession
from backend.services.events.resolver import resolve_host_uuid
from backend.services.timeline.correlator import EntityCorrelator, _ensure_utc

logger = logging.getLogger("osiris.services.timeline.service")


# ── Exceptions ──────────────────────────────────────────────────────────────


class TimelineError(Exception):
    """Base exception for timeline reconstruction service errors."""


class HostNotFoundError(TimelineError):
    """Raised when the specified host does not exist."""

    def __init__(self, host_id: uuid.UUID | str) -> None:
        self.host_id = host_id
        super().__init__(f"Host not found: {host_id}")


class InvalidTimeRangeError(TimelineError):
    """Raised when start_time > end_time or timezone comparisons fail."""


# ── Service ─────────────────────────────────────────────────────────────────


class TimelineService:
    """Forensic timeline reconstruction service."""

    def __init__(
        self,
        session: Session | None = None,
        correlator: EntityCorrelator | None = None,
    ) -> None:
        self._session = session
        self._correlator = correlator or EntityCorrelator(session=session)

    @property
    def session(self) -> Session | None:
        return self._session

    @session.setter
    def session(self, s: Session | None) -> None:
        self._session = s
        self._correlator.set_session(s)

    def set_session(self, session: Session | None) -> None:
        self._session = session
        self._correlator.set_session(session)

    # ── Public API ──────────────────────────────────────────────────────────

    def reconstruct_timeline(
        self,
        host_id: uuid.UUID | str | None = None,
        *,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        record_type: str | None = None,
        event_type: str | None = None,
        source: str | None = None,
        process_id: uuid.UUID | None = None,
        pid: int | None = None,
        user_id: uuid.UUID | None = None,
        uid: int | None = None,
        username: str | None = None,
        order: str = "asc",
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[TimelineEntryResponse], int]:
        """Reconstruct a unified chronological forensic timeline.

        Parameters
        ----------
        host_id:
            Optional host UUID or string. If provided, validates host exists
            and scopes all queries and correlations strictly to this host.
        start_time:
            Earliest timestamp (inclusive).
        end_time:
            Latest timestamp (inclusive).
        record_type:
            Filter by record type ('event', 'process', 'session', 'snapshot',
            'resource', 'file', or 'all').
        event_type:
            Filter by specific event type (e.g. 'process.start', 'file.modify').
        source:
            Filter by collector or table source.
        process_id:
            Filter by OSIRIS internal process UUID.
        pid:
            Filter by Linux PID.
        user_id:
            Filter by LinuxUser UUID.
        uid:
            Filter by Linux UID.
        username:
            Filter by Linux username.
        order:
            'asc' (chronological, oldest first) or 'desc' (newest first).
        limit:
            Page size (default: 50).
        offset:
            Page offset (default: 0).

        Returns
        -------
        tuple[list[TimelineEntryResponse], int]
            The list of reconstructed timeline entries and the total matching count.

        Raises
        ------
        RuntimeError:
            If no active database session is bound.
        HostNotFoundError:
            If host_id is specified but does not exist.
        InvalidTimeRangeError:
            If start_time > end_time or datetimes cannot be compared.
        """
        if self._session is None:
            raise RuntimeError("TimelineService has no active database session")

        # 1. Host Validation
        host_uuid: uuid.UUID | None = None
        if host_id is not None:
            host_uuid = (
                resolve_host_uuid(host_id)
                if not isinstance(host_id, uuid.UUID)
                else host_id
            )
            host = self._session.get(Host, host_uuid)
            if host is None:
                raise HostNotFoundError(host_id)

        # 2. Time Range Validation & Normalization
        start_utc = _ensure_utc(start_time)
        end_utc = _ensure_utc(end_time)

        if start_utc and end_utc:
            if start_utc > end_utc:
                raise InvalidTimeRangeError(
                    "start_time must be less than or equal to end_time"
                )

        # 3. Resolve user filters if provided
        user_filter_applied = (
            user_id is not None or uid is not None or (username is not None and bool(username.strip()))
        )
        target_user_ids: set[uuid.UUID] = set()
        target_uids: set[int] = set()
        target_usernames: set[str] = set()

        if user_filter_applied:
            u_stmt = select(LinuxUser)
            if host_uuid is not None:
                u_stmt = u_stmt.where(LinuxUser.host_id == host_uuid)
            if user_id is not None:
                u_stmt = u_stmt.where(LinuxUser.id == user_id)
            if uid is not None:
                u_stmt = u_stmt.where(LinuxUser.uid == uid)
            if username is not None and username.strip():
                u_stmt = u_stmt.where(LinuxUser.username == username.strip())

            matching_users = self._session.execute(u_stmt).scalars().all()
            for u in matching_users:
                target_user_ids.add(u.id)
                target_uids.add(u.uid)
                if u.username:
                    target_usernames.add(u.username)

            if not matching_users:
                if user_id is not None:
                    target_user_ids.add(user_id)
                if uid is not None:
                    target_uids.add(uid)
                if username is not None and username.strip():
                    target_usernames.add(username.strip())

        # 4. Construct SQL Union Branches for supported sources
        branches = self._build_query_branches(
            host_uuid=host_uuid,
            start_utc=start_utc,
            end_utc=end_utc,
            record_type=record_type,
            event_type=event_type,
            source=source,
            process_id=process_id,
            pid=pid,
            target_user_ids=target_user_ids,
            target_uids=target_uids,
            target_usernames=target_usernames,
            user_filter_applied=user_filter_applied,
        )

        if not branches:
            return [], 0

        # 5. Execute Count & Paged Selection via Database UNION ALL
        union_subq = union_all(*branches).subquery("timeline_records")

        count_stmt = select(func.count()).select_from(union_subq)
        total = self._session.scalar(count_stmt) or 0

        if total == 0 or offset >= total:
            return [], total

        # Deterministic ordering
        if order.lower() == "desc":
            order_clause = [
                union_subq.c.timestamp.desc(),
                union_subq.c.sequence_order.desc(),
                union_subq.c.source_table.desc(),
                union_subq.c.source_id.desc(),
                union_subq.c.action.desc(),
            ]
        else:
            order_clause = [
                union_subq.c.timestamp.asc(),
                union_subq.c.sequence_order.asc(),
                union_subq.c.source_table.asc(),
                union_subq.c.source_id.asc(),
                union_subq.c.action.asc(),
            ]

        paged_stmt = (
            select(
                union_subq.c.source_table,
                union_subq.c.source_id,
                union_subq.c.timestamp,
                union_subq.c.host_id,
                union_subq.c.record_type,
                union_subq.c.event_type,
                union_subq.c.action,
                union_subq.c.severity,
            )
            .order_by(*order_clause)
            .offset(offset)
            .limit(limit)
        )
        rows = self._session.execute(paged_stmt).all()

        # 6. Hydrate and Correlate Paged Items
        entries = self._hydrate_and_correlate(rows)
        return entries, total

    # ── Internal Query Construction ─────────────────────────────────────────

    def _build_query_branches(
        self,
        host_uuid: uuid.UUID | None,
        start_utc: datetime | None,
        end_utc: datetime | None,
        record_type: str | None,
        event_type: str | None,
        source: str | None,
        process_id: uuid.UUID | None,
        pid: int | None,
        target_user_ids: set[uuid.UUID],
        target_uids: set[int],
        target_usernames: set[str],
        user_filter_applied: bool,
    ) -> list[Any]:
        """Construct the SQL SELECT branches for the UNION ALL query."""
        rtype = (record_type or "").lower().strip()
        branches = []

        # ── Branch 1: events ──────────────────────────────────────────────
        include_events = rtype in ("", "all", "event") or (
            rtype == "process" and (event_type is None or "process" in event_type)
        ) or (
            rtype == "file" and (event_type is None or "file" in event_type)
        ) or (
            rtype == "resource" and (event_type is None or "resource" in event_type)
        ) or (
            rtype == "session" and (event_type is None or "session" in event_type)
        )

        if include_events:
            conds = []
            if host_uuid is not None:
                conds.append(Event.host_id == host_uuid)
            if start_utc is not None:
                conds.append(Event.timestamp >= start_utc)
            if end_utc is not None:
                conds.append(Event.timestamp <= end_utc)
            if source is not None and source not in ("events", "all"):
                conds.append(Event.source == source)
            if event_type is not None:
                conds.append(Event.event_type == event_type)
            if process_id is not None:
                conds.append(Event.process_id == process_id)
            if pid is not None:
                conds.append(Event.pid == pid)

            if user_filter_applied:
                u_conds = []
                if target_uids:
                    u_conds.append(Event.uid.in_(target_uids))
                if target_usernames:
                    u_conds.append(Event.username.in_(target_usernames))
                if u_conds:
                    conds.append(or_(*u_conds))
                else:
                    conds.append(literal(False))

            if rtype == "process":
                conds.append(
                    or_(
                        Event.source == "proc",
                        Event.event_type.startswith("process."),
                    )
                )
            elif rtype == "file":
                conds.append(
                    or_(
                        Event.source == "fs",
                        Event.event_type.startswith("file."),
                    )
                )
            elif rtype == "resource":
                conds.append(
                    or_(
                        Event.source == "resource",
                        Event.event_type.startswith("resource."),
                    )
                )
            elif rtype == "session":
                conds.append(
                    or_(
                        Event.event_type.startswith("session."),
                        Event.action.in_(["login", "logout"]),
                    )
                )

            seq_expr = case(
                (Event.action.in_(["start", "login", "create"]), 1),
                (Event.action.in_(["end", "exit", "logout", "stop", "delete"]), 3),
                else_=2,
            ).label("sequence_order")

            stmt_events = select(
                literal("events").label("source_table"),
                Event.id.label("source_id"),
                Event.timestamp.label("timestamp"),
                Event.host_id.label("host_id"),
                literal("event").label("record_type"),
                Event.event_type.label("event_type"),
                Event.action.label("action"),
                Event.severity.label("severity"),
                seq_expr,
            )
            if conds:
                stmt_events = stmt_events.where(*conds)
            branches.append(stmt_events)

        # ── Branch 2: processes (start & end) ──────────────────────────────
        include_processes = rtype in ("", "all", "process")
        if include_processes and source in (None, "processes", "all"):
            # Process Starts
            if event_type in (None, "process.start"):
                conds_pstart = []
                if host_uuid is not None:
                    conds_pstart.append(Process.host_id == host_uuid)
                if start_utc is not None:
                    conds_pstart.append(Process.started_at >= start_utc)
                if end_utc is not None:
                    conds_pstart.append(Process.started_at <= end_utc)
                if process_id is not None:
                    conds_pstart.append(Process.id == process_id)
                if pid is not None:
                    conds_pstart.append(Process.pid == pid)

                if user_filter_applied:
                    if target_user_ids:
                        conds_pstart.append(Process.linux_user_id.in_(target_user_ids))
                    else:
                        conds_pstart.append(literal(False))

                # Deduplicate against events
                conds_pstart.append(
                    not_(
                        exists(
                            select(Event.id).where(
                                Event.process_id == Process.id,
                                or_(
                                    Event.action == "start",
                                    Event.event_type == "process.start",
                                ),
                            )
                        )
                    )
                )

                stmt_pstart = select(
                    literal("processes").label("source_table"),
                    Process.id.label("source_id"),
                    Process.started_at.label("timestamp"),
                    Process.host_id.label("host_id"),
                    literal("process").label("record_type"),
                    literal("process.start").label("event_type"),
                    literal("start").label("action"),
                    literal("info").label("severity"),
                    literal(1, Integer).label("sequence_order"),
                ).where(*conds_pstart)
                branches.append(stmt_pstart)

            # Process Terminations
            if event_type in (None, "process.end"):
                conds_pend = [Process.ended_at.is_not(None)]
                if host_uuid is not None:
                    conds_pend.append(Process.host_id == host_uuid)
                if start_utc is not None:
                    conds_pend.append(Process.ended_at >= start_utc)
                if end_utc is not None:
                    conds_pend.append(Process.ended_at <= end_utc)
                if process_id is not None:
                    conds_pend.append(Process.id == process_id)
                if pid is not None:
                    conds_pend.append(Process.pid == pid)

                if user_filter_applied:
                    if target_user_ids:
                        conds_pend.append(Process.linux_user_id.in_(target_user_ids))
                    else:
                        conds_pend.append(literal(False))

                # Deduplicate against events
                conds_pend.append(
                    not_(
                        exists(
                            select(Event.id).where(
                                Event.process_id == Process.id,
                                or_(
                                    Event.action.in_(["end", "exit"]),
                                    Event.event_type == "process.end",
                                ),
                            )
                        )
                    )
                )

                stmt_pend = select(
                    literal("processes").label("source_table"),
                    Process.id.label("source_id"),
                    Process.ended_at.label("timestamp"),
                    Process.host_id.label("host_id"),
                    literal("process").label("record_type"),
                    literal("process.end").label("event_type"),
                    literal("end").label("action"),
                    literal("info").label("severity"),
                    literal(3, Integer).label("sequence_order"),
                ).where(*conds_pend)
                branches.append(stmt_pend)

        # ── Branch 3: sessions (start & end) ──────────────────────────────
        include_sessions = (
            rtype in ("", "all", "session")
            and process_id is None
            and pid is None
            and source in (None, "sessions", "all")
        )
        if include_sessions:
            if event_type in (None, "session.start"):
                conds_sstart = []
                if host_uuid is not None:
                    conds_sstart.append(UserSession.host_id == host_uuid)
                if start_utc is not None:
                    conds_sstart.append(UserSession.started_at >= start_utc)
                if end_utc is not None:
                    conds_sstart.append(UserSession.started_at <= end_utc)

                if user_filter_applied:
                    if target_user_ids:
                        conds_sstart.append(UserSession.linux_user_id.in_(target_user_ids))
                    else:
                        conds_sstart.append(literal(False))

                conds_sstart.append(
                    not_(
                        exists(
                            select(Event.id).where(
                                Event.host_id == UserSession.host_id,
                                Event.timestamp == UserSession.started_at,
                                or_(
                                    Event.event_type == "session.start",
                                    Event.action.in_(["login", "start"]),
                                ),
                            )
                        )
                    )
                )

                stmt_sstart = select(
                    literal("sessions").label("source_table"),
                    UserSession.id.label("source_id"),
                    UserSession.started_at.label("timestamp"),
                    UserSession.host_id.label("host_id"),
                    literal("session").label("record_type"),
                    literal("session.start").label("event_type"),
                    literal("start").label("action"),
                    literal("info").label("severity"),
                    literal(1, Integer).label("sequence_order"),
                ).where(*conds_sstart)
                branches.append(stmt_sstart)

            if event_type in (None, "session.end"):
                conds_send = [UserSession.ended_at.is_not(None)]
                if host_uuid is not None:
                    conds_send.append(UserSession.host_id == host_uuid)
                if start_utc is not None:
                    conds_send.append(UserSession.ended_at >= start_utc)
                if end_utc is not None:
                    conds_send.append(UserSession.ended_at <= end_utc)

                if user_filter_applied:
                    if target_user_ids:
                        conds_send.append(UserSession.linux_user_id.in_(target_user_ids))
                    else:
                        conds_send.append(literal(False))

                conds_send.append(
                    not_(
                        exists(
                            select(Event.id).where(
                                Event.host_id == UserSession.host_id,
                                Event.timestamp == UserSession.ended_at,
                                or_(
                                    Event.event_type == "session.end",
                                    Event.action.in_(["logout", "end", "exit"]),
                                ),
                            )
                        )
                    )
                )

                stmt_send = select(
                    literal("sessions").label("source_table"),
                    UserSession.id.label("source_id"),
                    UserSession.ended_at.label("timestamp"),
                    UserSession.host_id.label("host_id"),
                    literal("session").label("record_type"),
                    literal("session.end").label("event_type"),
                    literal("end").label("action"),
                    literal("info").label("severity"),
                    literal(3, Integer).label("sequence_order"),
                ).where(*conds_send)
                branches.append(stmt_send)

        # ── Branch 4: snapshots ───────────────────────────────────────────
        include_snapshots = (
            rtype in ("", "all", "snapshot")
            and process_id is None
            and pid is None
            and not user_filter_applied
            and source in (None, "snapshots", "all")
        )
        if include_snapshots:
            conds_snap = []
            if host_uuid is not None:
                conds_snap.append(Snapshot.host_id == host_uuid)
            if start_utc is not None:
                conds_snap.append(Snapshot.timestamp >= start_utc)
            if end_utc is not None:
                conds_snap.append(Snapshot.timestamp <= end_utc)
            if event_type is not None:
                if event_type.startswith("snapshot."):
                    stype = event_type.removeprefix("snapshot.")
                    conds_snap.append(Snapshot.snapshot_type == stype)
                else:
                    conds_snap.append(Snapshot.snapshot_type == event_type)

            stmt_snap = select(
                literal("snapshots").label("source_table"),
                Snapshot.id.label("source_id"),
                Snapshot.timestamp.label("timestamp"),
                Snapshot.host_id.label("host_id"),
                literal("snapshot").label("record_type"),
                literal("snapshot.system_state").label("event_type"),
                literal("snapshot").label("action"),
                literal("info").label("severity"),
                literal(2, Integer).label("sequence_order"),
            )
            if conds_snap:
                stmt_snap = stmt_snap.where(*conds_snap)
            branches.append(stmt_snap)

        # ── Branch 5: resource_snapshots ──────────────────────────────────
        include_resources = (
            rtype in ("", "all", "resource", "resource_snapshot")
            and process_id is None
            and pid is None
            and not user_filter_applied
            and source in (None, "resource_snapshots", "resource", "all")
        )
        if include_resources and event_type in (None, "resource.telemetry"):
            conds_res = []
            if host_uuid is not None:
                conds_res.append(ResourceSnapshot.host_id == host_uuid)
            if start_utc is not None:
                conds_res.append(ResourceSnapshot.timestamp >= start_utc)
            if end_utc is not None:
                conds_res.append(ResourceSnapshot.timestamp <= end_utc)

            # Deduplicate against events
            conds_res.append(
                not_(
                    exists(
                        select(Event.id).where(
                            Event.host_id == ResourceSnapshot.host_id,
                            Event.timestamp == ResourceSnapshot.timestamp,
                            Event.source == "resource",
                        )
                    )
                )
            )

            stmt_res = select(
                literal("resource_snapshots").label("source_table"),
                ResourceSnapshot.id.label("source_id"),
                ResourceSnapshot.timestamp.label("timestamp"),
                ResourceSnapshot.host_id.label("host_id"),
                literal("resource").label("record_type"),
                literal("resource.telemetry").label("event_type"),
                literal("observation").label("action"),
                literal("info").label("severity"),
                literal(2, Integer).label("sequence_order"),
            ).where(*conds_res)
            branches.append(stmt_res)

        # ── Branch 6: files ───────────────────────────────────────────────
        include_files = (
            rtype in ("", "all", "file")
            and process_id is None
            and pid is None
            and not user_filter_applied
            and source in (None, "files", "all")
        )
        if include_files and event_type in (None, "file.observed"):
            conds_file = []
            if host_uuid is not None:
                conds_file.append(File.host_id == host_uuid)
            if start_utc is not None:
                conds_file.append(File.first_seen_at >= start_utc)
            if end_utc is not None:
                conds_file.append(File.first_seen_at <= end_utc)

            # Deduplicate against events
            conds_file.append(
                not_(
                    exists(
                        select(Event.id).where(
                            Event.host_id == File.host_id,
                            Event.object_path == File.path,
                            Event.timestamp == File.first_seen_at,
                        )
                    )
                )
            )

            stmt_file = select(
                literal("files").label("source_table"),
                File.id.label("source_id"),
                File.first_seen_at.label("timestamp"),
                File.host_id.label("host_id"),
                literal("file").label("record_type"),
                literal("file.observed").label("event_type"),
                literal("observation").label("action"),
                literal("info").label("severity"),
                literal(2, Integer).label("sequence_order"),
            ).where(*conds_file)
            branches.append(stmt_file)

        return branches

    # ── Hydration & Entity Correlation ──────────────────────────────────────

    def _hydrate_and_correlate(
        self, rows: list[Any]
    ) -> list[TimelineEntryResponse]:
        """Hydrate raw union rows with their source ORM entities and apply correlation."""
        if not rows or self._session is None:
            return []

        # Group source IDs by source table
        table_ids: dict[str, set[uuid.UUID]] = {
            "events": set(),
            "processes": set(),
            "sessions": set(),
            "snapshots": set(),
            "resource_snapshots": set(),
            "files": set(),
        }
        for r in rows:
            table_ids[r.source_table].add(r.source_id)

        # Batch fetch source entities
        events_map: dict[uuid.UUID, Event] = {}
        if table_ids["events"]:
            e_stmt = select(Event).where(Event.id.in_(table_ids["events"]))
            for e in self._session.execute(e_stmt).scalars():
                events_map[e.id] = e

        procs_map: dict[uuid.UUID, Process] = {}
        if table_ids["processes"]:
            p_stmt = select(Process).where(Process.id.in_(table_ids["processes"]))
            for p in self._session.execute(p_stmt).scalars():
                procs_map[p.id] = p

        sessions_map: dict[uuid.UUID, UserSession] = {}
        if table_ids["sessions"]:
            s_stmt = select(UserSession).where(
                UserSession.id.in_(table_ids["sessions"])
            )
            for s in self._session.execute(s_stmt).scalars():
                sessions_map[s.id] = s

        snapshots_map: dict[uuid.UUID, Snapshot] = {}
        if table_ids["snapshots"]:
            snap_stmt = select(Snapshot).where(
                Snapshot.id.in_(table_ids["snapshots"])
            )
            for snap in self._session.execute(snap_stmt).scalars():
                snapshots_map[snap.id] = snap

        resources_map: dict[uuid.UUID, ResourceSnapshot] = {}
        if table_ids["resource_snapshots"]:
            res_stmt = select(ResourceSnapshot).where(
                ResourceSnapshot.id.in_(table_ids["resource_snapshots"])
            )
            for res in self._session.execute(res_stmt).scalars():
                resources_map[res.id] = res

        files_map: dict[uuid.UUID, File] = {}
        if table_ids["files"]:
            f_stmt = select(File).where(File.id.in_(table_ids["files"]))
            for f in self._session.execute(f_stmt).scalars():
                files_map[f.id] = f

        # Build responses in exact row order
        results: list[TimelineEntryResponse] = []

        for r in rows:
            ts = _ensure_utc(r.timestamp)
            assert ts is not None

            if r.source_table == "events":
                event = events_map.get(r.source_id)
                if event is None:
                    continue
                item = self._build_event_entry(event)
                results.append(item)

            elif r.source_table == "processes":
                proc = procs_map.get(r.source_id)
                if proc is None:
                    continue
                item = self._build_process_entry(proc, action=r.action)
                results.append(item)

            elif r.source_table == "sessions":
                sess = sessions_map.get(r.source_id)
                if sess is None:
                    continue
                item = self._build_session_entry(sess, action=r.action)
                results.append(item)

            elif r.source_table == "snapshots":
                snap = snapshots_map.get(r.source_id)
                if snap is None:
                    continue
                item = self._build_snapshot_entry(snap)
                results.append(item)

            elif r.source_table == "resource_snapshots":
                res = resources_map.get(r.source_id)
                if res is None:
                    continue
                item = self._build_resource_entry(res)
                results.append(item)

            elif r.source_table == "files":
                f = files_map.get(r.source_id)
                if f is None:
                    continue
                item = self._build_file_entry(f)
                results.append(item)

        return results

    # ── Entry Builders ──────────────────────────────────────────────────────

    def _build_event_entry(self, event: Event) -> TimelineEntryResponse:
        """Hydrate and correlate an Event record."""
        # Correlate process
        proc_ctx: ProcessContext | None = None
        if event.process_id is not None:
            proc_ctx = self._correlator.correlate_process_by_id(
                event.host_id, event.process_id
            )
        elif event.pid is not None and event.pid >= 0:
            proc_ctx = self._correlator.correlate_process_by_pid(
                event.host_id,
                event.pid,
                event.timestamp,
                event_type=event.event_type,
            )

        if proc_ctx is None and (event.pid is not None or event.command is not None):
            valid_proc_id = event.process_id
            if valid_proc_id is not None and self._session is not None:
                p_check = self._session.get(Process, valid_proc_id)
                if p_check is not None and p_check.host_id != event.host_id:
                    valid_proc_id = None

            proc_ctx = ProcessContext(
                process_id=valid_proc_id,
                pid=event.pid,
                ppid=event.ppid,
                command=event.command,
            )

        # Correlate user
        user_ctx = self._correlator.correlate_user(
            event.host_id, uid=event.uid, username=event.username
        )

        # Correlate session
        user_id = user_ctx.user_id if user_ctx else None
        session_ctx = self._correlator.correlate_session(
            event.host_id, user_id=user_id, timestamp=event.timestamp
        )

        # Correlate file
        file_ctx: FileContext | None = None
        if event.object_type == "file" or event.source == "fs" or event.object_path:
            file_ctx = self._correlator.correlate_file(
                event.host_id, event.object_path
            )

        # Correlate resource
        resource_ctx: ResourceContext | None = None
        if event.source == "resource":
            resource_ctx = self._correlator.correlate_resource(
                event.host_id, event.timestamp
            )

        # Correlate snapshot
        snapshot_ctx = self._correlator.correlate_snapshot(
            event.host_id,
            event.timestamp,
            process_id=event.process_id,
            pid=event.pid,
        )

        # Description
        description = self._format_event_description(event)

        return TimelineEntryResponse(
            id=event.id,
            timestamp=_ensure_utc(event.timestamp),  # type: ignore[arg-type]
            host_id=event.host_id,
            source=event.source,
            source_id=event.id,
            record_type="event",
            event_type=event.event_type,
            action=event.action,
            severity=event.severity,
            description=description,
            process_context=proc_ctx,
            user_context=user_ctx,
            session_context=session_ctx,
            file_context=file_ctx,
            resource_context=resource_ctx,
            snapshot_context=snapshot_ctx,
            payload=event.payload,
        )

    def _build_process_entry(
        self, proc: Process, action: str
    ) -> TimelineEntryResponse:
        """Hydrate and correlate a Process lifecycle entry."""
        if action == "end":
            entry_id = uuid.uuid5(proc.id, "end")
            ts = _ensure_utc(proc.ended_at)
            event_type = "process.end"
            desc = f"Process terminated: {proc.command} (PID {proc.pid})"
        else:
            entry_id = proc.id
            ts = _ensure_utc(proc.started_at)
            event_type = "process.start"
            desc = f"Process started: {proc.command} (PID {proc.pid})"

        assert ts is not None

        proc_ctx = ProcessContext(
            process_id=proc.id,
            pid=proc.pid,
            ppid=proc.ppid,
            command=proc.command,
            executable=proc.executable,
        )
        user_ctx = self._correlator.correlate_user(
            proc.host_id, linux_user_id=proc.linux_user_id
        )
        user_id = user_ctx.user_id if user_ctx else None
        session_ctx = self._correlator.correlate_session(
            proc.host_id, user_id=user_id, timestamp=ts
        )
        snapshot_ctx = self._correlator.correlate_snapshot(
            proc.host_id, ts, process_id=proc.id, pid=proc.pid
        )

        return TimelineEntryResponse(
            id=entry_id,
            timestamp=ts,
            host_id=proc.host_id,
            source="processes",
            source_id=proc.id,
            record_type="process",
            event_type=event_type,
            action=action,
            severity="info",
            description=desc,
            process_context=proc_ctx,
            user_context=user_ctx,
            session_context=session_ctx,
            file_context=None,
            resource_context=None,
            snapshot_context=snapshot_ctx,
            payload={
                "pid": proc.pid,
                "ppid": proc.ppid,
                "executable": proc.executable,
            },
        )

    def _build_session_entry(
        self, sess: UserSession, action: str
    ) -> TimelineEntryResponse:
        """Hydrate and correlate a UserSession entry."""
        if action == "end":
            entry_id = uuid.uuid5(sess.id, "end")
            ts = _ensure_utc(sess.ended_at)
            event_type = "session.end"
            desc = f"User session ended on {sess.terminal or 'console'}"
        else:
            entry_id = sess.id
            ts = _ensure_utc(sess.started_at)
            event_type = "session.start"
            desc = f"User session started ({sess.session_type or 'session'}) on {sess.terminal or 'console'}"

        assert ts is not None

        sess_ctx = SessionContext(
            session_id=sess.id,
            session_type=sess.session_type,
            terminal=sess.terminal,
            remote_host=sess.remote_host,
        )
        user_ctx = self._correlator.correlate_user(
            sess.host_id, linux_user_id=sess.linux_user_id
        )

        return TimelineEntryResponse(
            id=entry_id,
            timestamp=ts,
            host_id=sess.host_id,
            source="sessions",
            source_id=sess.id,
            record_type="session",
            event_type=event_type,
            action=action,
            severity="info",
            description=desc,
            process_context=None,
            user_context=user_ctx,
            session_context=sess_ctx,
            file_context=None,
            resource_context=None,
            snapshot_context=None,
            payload={
                "terminal": sess.terminal,
                "remote_host": sess.remote_host,
                "session_type": sess.session_type,
            },
        )

    def _build_snapshot_entry(self, snap: Snapshot) -> TimelineEntryResponse:
        """Hydrate and correlate a Snapshot entry."""
        ts = _ensure_utc(snap.timestamp)
        assert ts is not None

        snap_ctx = SnapshotContext(
            snapshot_id=snap.id,
            snapshot_type=snap.snapshot_type,
            time_delta_seconds=0.0,
        )

        data_dict = snap.data if isinstance(snap.data, dict) else {}
        procs_list = data_dict.get("processes", [])
        procs_count = len(procs_list) if isinstance(procs_list, list) else 0
        desc = f"System state snapshot captured ({snap.snapshot_type}, {procs_count} processes)"

        return TimelineEntryResponse(
            id=snap.id,
            timestamp=ts,
            host_id=snap.host_id,
            source="snapshots",
            source_id=snap.id,
            record_type="snapshot",
            event_type=f"snapshot.{snap.snapshot_type}",
            action="snapshot",
            severity="info",
            description=desc,
            process_context=None,
            user_context=None,
            session_context=None,
            file_context=None,
            resource_context=None,
            snapshot_context=snap_ctx,
            payload={
                "snapshot_type": snap.snapshot_type,
                "process_count": procs_count,
                "has_resources": data_dict.get("resources") is not None,
            },
        )

    def _build_resource_entry(
        self, res: ResourceSnapshot
    ) -> TimelineEntryResponse:
        """Hydrate and correlate a ResourceSnapshot entry."""
        ts = _ensure_utc(res.timestamp)
        assert ts is not None

        res_ctx = ResourceContext(
            resource_snapshot_id=res.id,
            cpu_percent=res.cpu_percent,
            memory_percent=res.memory_percent,
            disk_usage_percent=res.disk_usage_percent,
        )
        cpu_val = res.cpu_percent if res.cpu_percent is not None else 0.0
        mem_val = res.memory_percent if res.memory_percent is not None else 0.0
        desc = f"Resource telemetry: CPU {cpu_val:.1f}%, Memory {mem_val:.1f}%"

        return TimelineEntryResponse(
            id=res.id,
            timestamp=ts,
            host_id=res.host_id,
            source="resource_snapshots",
            source_id=res.id,
            record_type="resource",
            event_type="resource.telemetry",
            action="observation",
            severity="info",
            description=desc,
            process_context=None,
            user_context=None,
            session_context=None,
            file_context=None,
            resource_context=res_ctx,
            snapshot_context=None,
            payload={
                "cpu_percent": res.cpu_percent,
                "memory_percent": res.memory_percent,
                "disk_usage_percent": res.disk_usage_percent,
            },
        )

    def _build_file_entry(self, f: File) -> TimelineEntryResponse:
        """Hydrate and correlate a File observation entry."""
        ts = _ensure_utc(f.first_seen_at)
        assert ts is not None

        file_ctx = FileContext(
            file_id=f.id,
            path=f.path,
            file_type=f.file_type,
            inode=f.inode,
        )
        desc = f"File observed: {f.path} ({f.file_type or 'file'})"

        return TimelineEntryResponse(
            id=f.id,
            timestamp=ts,
            host_id=f.host_id,
            source="files",
            source_id=f.id,
            record_type="file",
            event_type="file.observed",
            action="observation",
            severity="info",
            description=desc,
            process_context=None,
            user_context=None,
            session_context=None,
            file_context=file_ctx,
            resource_context=None,
            snapshot_context=None,
            payload={
                "path": f.path,
                "file_type": f.file_type,
                "inode": f.inode,
            },
        )

    def _format_event_description(self, event: Event) -> str:
        """Produce a human-readable summary description for an event."""
        if event.command:
            return f"{event.event_type} {event.action}: {event.command}"
        if event.object_path:
            return f"{event.event_type} {event.action}: {event.object_path}"
        if event.result:
            return f"{event.event_type} {event.action}: {event.result}"
        return f"{event.event_type} {event.action}"
