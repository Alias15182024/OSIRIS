"""Entity correlation engine for OSIRIS Phase 2 Milestone 2.2 Timeline Reconstruction.

Provides deterministic, forensically sound entity correlation to link timeline
entries with:
- Processes (handling PID reuse, lifetime boundaries, and ambiguous matches).
- Linux users (host-scoped resolution by UID, username, or linux_user_id).
- User sessions (active login session matching by user, host, and timestamp).
- Filesystem references (path-to-file lookup within host).
- Resource telemetry (nearest point-in-time metrics within temporal tolerance).
- System snapshots (closest snapshot on host and process containment verification).

Core forensic principles:
1. Cross-host isolation: Records from different hosts are NEVER correlated.
2. Lifetime bounding: Processes and sessions are only correlated if the event
   timestamp falls strictly within the entity's active lifetime.
3. PID reuse safety: Ambiguous or overlapping process lifetimes return None
   instead of generating false or speculative associations.
4. No invented identities: Missing or unresolved entities are left as None.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from backend.api.schemas.timeline import (
    FileContext,
    ProcessContext,
    ResourceContext,
    SessionContext,
    SnapshotContext,
    UserContext,
)
from backend.db.models.file import File
from backend.db.models.linux_user import LinuxUser
from backend.db.models.process import Process
from backend.db.models.resource_snapshot import ResourceSnapshot
from backend.db.models.snapshot import Snapshot
from backend.db.models.user_session import UserSession

logger = logging.getLogger("osiris.services.timeline.correlator")


def _ensure_utc(dt: datetime | None) -> datetime | None:
    """Ensure a datetime is timezone-aware UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class EntityCorrelator:
    """Forensic correlation engine for timeline reconstruction."""

    def __init__(self, session: Session | None = None) -> None:
        self._session = session
        self._clear_caches()

    def _clear_caches(self) -> None:
        self._proc_id_cache: dict[tuple[uuid.UUID, uuid.UUID], Optional[ProcessContext]] = {}
        self._proc_pid_cache: dict[tuple[uuid.UUID, int, datetime, Optional[str]], Optional[ProcessContext]] = {}
        self._user_cache: dict[tuple[uuid.UUID, Optional[int], Optional[str], Optional[uuid.UUID]], Optional[UserContext]] = {}
        self._file_cache: dict[tuple[uuid.UUID, str], Optional[FileContext]] = {}
        self._resource_cache: dict[tuple[uuid.UUID, datetime, float], Optional[ResourceContext]] = {}
        self._snapshot_cache: dict[tuple[uuid.UUID, datetime, Optional[uuid.UUID], Optional[int], float], Optional[SnapshotContext]] = {}
        self._prefetched_sessions: list[UserSession] = []
        self._sessions_prefetched: bool = False
        self._prefetched_snapshots: list[Snapshot] = []
        self._snapshots_prefetched: bool = False
        self._prefetched_resources: list[ResourceSnapshot] = []
        self._resources_prefetched: bool = False

    def prefetch_users(self, host_ids: set[uuid.UUID]) -> None:
        """Batch prefetch all Linux users for given hosts to avoid N+1 queries during timeline hydration."""
        if not host_ids or self._session is None:
            return
        stmt = select(LinuxUser).where(LinuxUser.host_id.in_(host_ids))
        for u in self._session.execute(stmt).scalars().all():
            ctx = UserContext(user_id=u.id, uid=u.uid, username=u.username)
            self._user_cache[(u.host_id, u.uid, None, None)] = ctx
            self._user_cache[(u.host_id, None, u.username, None)] = ctx
            self._user_cache[(u.host_id, u.uid, u.username, None)] = ctx
            self._user_cache[(u.host_id, None, None, u.id)] = ctx
            self._user_cache[(u.host_id, u.uid, None, u.id)] = ctx
            self._user_cache[(u.host_id, None, u.username, u.id)] = ctx
            self._user_cache[(u.host_id, u.uid, u.username, u.id)] = ctx

    def prefetch_processes(self, process_ids: set[uuid.UUID]) -> None:
        """Batch prefetch processes by UUID to populate process cache."""
        if not process_ids or self._session is None:
            return
        uncached = [pid for pid in process_ids if not any(k[1] == pid for k in self._proc_id_cache)]
        if not uncached:
            return
        stmt = select(Process).where(Process.id.in_(uncached))
        found = set()
        for p in self._session.execute(stmt).scalars().all():
            found.add(p.id)
            self._proc_id_cache[(p.host_id, p.id)] = ProcessContext(
                process_id=p.id,
                pid=p.pid,
                ppid=p.ppid,
                command=p.command,
                executable=p.executable,
            )

    def prefetch_files(self, paths_by_host: dict[uuid.UUID, set[str]]) -> None:
        """Batch prefetch observed files by host and path to eliminate N+1 queries during timeline hydration."""
        if not paths_by_host or self._session is None:
            return
        for host_id, paths in paths_by_host.items():
            uncached = [p for p in paths if (host_id, p) not in self._file_cache]
            if not uncached:
                continue
            stmt = select(File).where(File.host_id == host_id, File.path.in_(uncached))
            found_paths = set()
            for f in self._session.execute(stmt).scalars().all():
                found_paths.add(f.path)
                self._file_cache[(f.host_id, f.path)] = FileContext(
                    file_id=f.id,
                    path=f.path,
                    file_type=f.file_type,
                    inode=f.inode,
                )
            for p in uncached:
                if p not in found_paths:
                    self._file_cache[(host_id, p)] = FileContext(
                        file_id=None,
                        path=p,
                        file_type=None,
                        inode=None,
                    )

    def prefetch_sessions(
        self, host_ids: set[uuid.UUID], min_ts: datetime, max_ts: datetime
    ) -> None:
        """Batch prefetch candidate sessions active during the given time window."""
        if not host_ids or self._session is None:
            return
        min_utc = _ensure_utc(min_ts)
        max_utc = _ensure_utc(max_ts)
        if min_utc is None or max_utc is None:
            return
        stmt = (
            select(UserSession)
            .where(
                UserSession.host_id.in_(host_ids),
                UserSession.started_at <= max_utc,
                or_(UserSession.ended_at.is_(None), UserSession.ended_at >= min_utc),
            )
            .order_by(UserSession.started_at.desc())
        )
        self._prefetched_sessions = list(self._session.execute(stmt).scalars().all())
        self._sessions_prefetched = True

    def prefetch_snapshots(
        self,
        host_ids: set[uuid.UUID],
        min_ts: datetime,
        max_ts: datetime,
        tolerance_seconds: float = 3600.0,
    ) -> None:
        """Batch prefetch system snapshots within temporal tolerance of page window."""
        if not host_ids or self._session is None:
            return
        min_utc = _ensure_utc(min_ts)
        max_utc = _ensure_utc(max_ts)
        if min_utc is None or max_utc is None:
            return
        start_bound = min_utc - timedelta(seconds=tolerance_seconds)
        end_bound = max_utc + timedelta(seconds=tolerance_seconds)
        stmt = (
            select(Snapshot)
            .where(
                Snapshot.host_id.in_(host_ids),
                Snapshot.timestamp >= start_bound,
                Snapshot.timestamp <= end_bound,
            )
            .order_by(Snapshot.timestamp.asc())
        )
        self._prefetched_snapshots = list(self._session.execute(stmt).scalars().all())
        self._snapshots_prefetched = True

    def prefetch_resources(
        self,
        host_ids: set[uuid.UUID],
        min_ts: datetime,
        max_ts: datetime,
        tolerance_seconds: float = 300.0,
    ) -> None:
        """Batch prefetch resource snapshots within temporal tolerance of page window."""
        if not host_ids or self._session is None:
            return
        min_utc = _ensure_utc(min_ts)
        max_utc = _ensure_utc(max_ts)
        if min_utc is None or max_utc is None:
            return
        start_bound = min_utc - timedelta(seconds=tolerance_seconds)
        end_bound = max_utc + timedelta(seconds=tolerance_seconds)
        stmt = (
            select(ResourceSnapshot)
            .where(
                ResourceSnapshot.host_id.in_(host_ids),
                ResourceSnapshot.timestamp >= start_bound,
                ResourceSnapshot.timestamp <= end_bound,
            )
            .order_by(ResourceSnapshot.timestamp.asc())
        )
        self._prefetched_resources = list(self._session.execute(stmt).scalars().all())
        self._resources_prefetched = True

    @property
    def session(self) -> Session | None:
        return self._session

    @session.setter
    def session(self, s: Session | None) -> None:
        self._session = s
        self._clear_caches()

    def set_session(self, session: Session | None) -> None:
        self._session = session
        self._clear_caches()

    # ── Process Correlation ──────────────────────────────────────────────────

    def correlate_process_by_id(
        self, host_id: uuid.UUID, process_id: uuid.UUID
    ) -> Optional[ProcessContext]:
        """Correlate a known OSIRIS process UUID with its process entity.

        Enforces cross-host isolation: if the process belongs to another host,
        returns None.
        """
        key = (host_id, process_id)
        if key in self._proc_id_cache:
            return self._proc_id_cache[key]

        if self._session is None:
            return None

        proc = self._session.get(Process, process_id)
        if proc is None or proc.host_id != host_id:
            self._proc_id_cache[key] = None
            return None

        res = ProcessContext(
            process_id=proc.id,
            pid=proc.pid,
            ppid=proc.ppid,
            command=proc.command,
            executable=proc.executable,
        )
        self._proc_id_cache[key] = res
        return res

    def correlate_process_by_pid(
        self,
        host_id: uuid.UUID,
        pid: int,
        timestamp: datetime,
        event_type: str | None = None,
    ) -> Optional[ProcessContext]:
        """Resolve a Linux PID to a ProcessContext enforcing lifetime bounds.

        Respects:
        - Host scoping: only processes where ``host_id == host_id``.
        - Lifetime: ``started_at <= timestamp`` and
          ``(ended_at IS NULL or timestamp <= ended_at)``.
        - PID reuse: if multiple processes match (overlapping anomalies),
          attempts exact boundary disambiguation (started_at == ts for process.start,
          ended_at == ts for process.end). If still ambiguous, returns None.
        """
        if self._session is None or pid < 0:
            return None

        ts = _ensure_utc(timestamp)
        if ts is None:
            return None

        cache_key = (host_id, pid, ts, event_type)
        if cache_key in self._proc_pid_cache:
            return self._proc_pid_cache[cache_key]

        stmt = (
            select(Process)
            .where(
                Process.host_id == host_id,
                Process.pid == pid,
                Process.started_at <= ts,
                or_(Process.ended_at.is_(None), ts <= Process.ended_at),
            )
            .order_by(Process.started_at.desc())
            .limit(4)
        )
        procs = self._session.execute(stmt).scalars().all()

        if not procs:
            self._proc_pid_cache[cache_key] = None
            return None

        if len(procs) == 1:
            proc = procs[0]
            res = ProcessContext(
                process_id=proc.id,
                pid=proc.pid,
                ppid=proc.ppid,
                command=proc.command,
                executable=proc.executable,
            )
            self._proc_pid_cache[cache_key] = res
            return res

        # Disambiguate if event_type matches boundary exactly
        if event_type == "process.start":
            start_m = [p for p in procs if _ensure_utc(p.started_at) == ts]
            if len(start_m) == 1:
                proc = start_m[0]
                res = ProcessContext(
                    process_id=proc.id,
                    pid=proc.pid,
                    ppid=proc.ppid,
                    command=proc.command,
                    executable=proc.executable,
                )
                self._proc_pid_cache[cache_key] = res
                return res
        elif event_type == "process.end":
            end_m = [
                p
                for p in procs
                if p.ended_at is not None and _ensure_utc(p.ended_at) == ts
            ]
            if len(end_m) == 1:
                proc = end_m[0]
                res = ProcessContext(
                    process_id=proc.id,
                    pid=proc.pid,
                    ppid=proc.ppid,
                    command=proc.command,
                    executable=proc.executable,
                )
                self._proc_pid_cache[cache_key] = res
                return res

        logger.warning(
            "Ambiguous PID %s on host %s at %s (%d matches); returning None",
            pid,
            host_id,
            ts,
            len(procs),
        )
        self._proc_pid_cache[cache_key] = None
        return None

    # ── User Correlation ────────────────────────────────────────────────────

    def correlate_user(
        self,
        host_id: uuid.UUID,
        uid: int | None = None,
        username: str | None = None,
        linux_user_id: uuid.UUID | None = None,
    ) -> Optional[UserContext]:
        """Correlate Linux user identity against ``linux_users`` table.

        Preserves observed UID and username even if no LinuxUser row exists.
        Never associates users across hosts.
        """
        key = (host_id, uid, username, linux_user_id)
        if key in self._user_cache:
            return self._user_cache[key]

        if self._session is None:
            if uid is not None or username is not None or linux_user_id is not None:
                res = UserContext(user_id=linux_user_id, uid=uid, username=username)
                self._user_cache[key] = res
                return res
            self._user_cache[key] = None
            return None

        if linux_user_id is not None:
            user = self._session.get(LinuxUser, linux_user_id)
            if user is not None and user.host_id == host_id:
                res = UserContext(
                    user_id=user.id,
                    uid=user.uid,
                    username=user.username,
                )
                self._user_cache[key] = res
                return res

        if uid is not None and uid >= 0:
            stmt = select(LinuxUser).where(
                LinuxUser.host_id == host_id,
                LinuxUser.uid == uid,
            )
            user = self._session.execute(stmt).scalars().first()
            if user is not None:
                res = UserContext(
                    user_id=user.id,
                    uid=user.uid,
                    username=user.username or username,
                )
                self._user_cache[key] = res
                return res
            res = UserContext(user_id=None, uid=uid, username=username)
            self._user_cache[key] = res
            return res

        if username is not None and username.strip():
            stripped = username.strip()
            stmt = select(LinuxUser).where(
                LinuxUser.host_id == host_id,
                LinuxUser.username == stripped,
            )
            user = self._session.execute(stmt).scalars().first()
            if user is not None:
                res = UserContext(
                    user_id=user.id,
                    uid=user.uid,
                    username=user.username,
                )
                self._user_cache[key] = res
                return res
            res = UserContext(user_id=None, uid=None, username=stripped)
            self._user_cache[key] = res
            return res

        self._user_cache[key] = None
        return None

    # ── Session Correlation ─────────────────────────────────────────────────

    def correlate_session(
        self,
        host_id: uuid.UUID,
        user_id: uuid.UUID | None,
        timestamp: datetime,
    ) -> Optional[SessionContext]:
        """Correlate active user login session for user and host at timestamp.

        Enforces:
        - Host scoping: ``host_id == host_id``.
        - User scoping: ``linux_user_id == user_id``.
        - Time bounding: ``started_at <= timestamp`` and
          ``(ended_at IS NULL or timestamp <= ended_at)``.
        - Ambiguity: if multiple sessions match, returns None.
        """
        if self._session is None or user_id is None:
            return None

        ts = _ensure_utc(timestamp)
        if ts is None:
            return None

        if self._sessions_prefetched:
            matching = [
                s
                for s in self._prefetched_sessions
                if s.host_id == host_id
                and s.linux_user_id == user_id
                and _ensure_utc(s.started_at) <= ts  # type: ignore[operator]
                and (s.ended_at is None or ts <= _ensure_utc(s.ended_at))  # type: ignore[operator]
            ]
            if len(matching) == 1:
                sess = matching[0]
                return SessionContext(
                    session_id=sess.id,
                    session_type=sess.session_type,
                    terminal=sess.terminal,
                    remote_host=sess.remote_host,
                )
            return None

        stmt = (
            select(UserSession)
            .where(
                UserSession.host_id == host_id,
                UserSession.linux_user_id == user_id,
                UserSession.started_at <= ts,
                or_(UserSession.ended_at.is_(None), ts <= UserSession.ended_at),
            )
            .order_by(UserSession.started_at.desc())
            .limit(3)
        )
        sessions = self._session.execute(stmt).scalars().all()

        if len(sessions) == 1:
            sess = sessions[0]
            return SessionContext(
                session_id=sess.id,
                session_type=sess.session_type,
                terminal=sess.terminal,
                remote_host=sess.remote_host,
            )

        return None

    # ── File Correlation ────────────────────────────────────────────────────

    def correlate_file(
        self,
        host_id: uuid.UUID,
        path: str | None,
    ) -> Optional[FileContext]:
        """Correlate observed file path with ``files`` table on host."""
        if not path:
            return None

        key = (host_id, path)
        if key in self._file_cache:
            return self._file_cache[key]

        if self._session is None:
            res = FileContext(path=path)
            self._file_cache[key] = res
            return res

        stmt = select(File).where(
            File.host_id == host_id,
            File.path == path,
        )
        file_rec = self._session.execute(stmt).scalars().first()

        if file_rec is not None:
            res = FileContext(
                file_id=file_rec.id,
                path=file_rec.path,
                file_type=file_rec.file_type,
                inode=file_rec.inode,
            )
            self._file_cache[key] = res
            return res

        res = FileContext(file_id=None, path=path, file_type=None, inode=None)
        self._file_cache[key] = res
        return res

    # ── Resource Snapshot Correlation ───────────────────────────────────────

    def correlate_resource(
        self,
        host_id: uuid.UUID,
        timestamp: datetime,
        max_delta_seconds: float = 300.0,
    ) -> Optional[ResourceContext]:
        """Find the nearest resource snapshot on host within temporal tolerance."""
        if self._session is None:
            return None

        ts = _ensure_utc(timestamp)
        if ts is None:
            return None

        cache_key = (host_id, ts, max_delta_seconds)
        if cache_key in self._resource_cache:
            return self._resource_cache[cache_key]

        if self._resources_prefetched:
            host_res = [r for r in self._prefetched_resources if r.host_id == host_id]
            if not host_res:
                self._resource_cache[cache_key] = None
                return None
            prev_cand = None
            next_cand = None
            for r in host_res:
                r_ts = _ensure_utc(r.timestamp)
                if r_ts <= ts:
                    if prev_cand is None or r_ts > _ensure_utc(prev_cand.timestamp):
                        prev_cand = r
                elif r_ts > ts:
                    if next_cand is None or r_ts < _ensure_utc(next_cand.timestamp):
                        next_cand = r
            candidates = [c for c in (prev_cand, next_cand) if c is not None]
            if not candidates:
                self._resource_cache[cache_key] = None
                return None
            candidates.sort(
                key=lambda r: abs((_ensure_utc(r.timestamp) - ts).total_seconds())  # type: ignore[operator]
            )
            best = candidates[0]
            delta = abs((_ensure_utc(best.timestamp) - ts).total_seconds())  # type: ignore[operator]
            if delta <= max_delta_seconds:
                res = ResourceContext(
                    resource_snapshot_id=best.id,
                    cpu_percent=best.cpu_percent,
                    memory_percent=best.memory_percent,
                    disk_usage_percent=best.disk_usage_percent,
                )
                self._resource_cache[cache_key] = res
                return res
            self._resource_cache[cache_key] = None
            return None

        # Fetch up to 2 closest snapshots (one preceding/at, one succeeding)
        stmt_prev = (
            select(ResourceSnapshot)
            .where(
                ResourceSnapshot.host_id == host_id,
                ResourceSnapshot.timestamp <= ts,
            )
            .order_by(ResourceSnapshot.timestamp.desc())
            .limit(1)
        )
        stmt_next = (
            select(ResourceSnapshot)
            .where(
                ResourceSnapshot.host_id == host_id,
                ResourceSnapshot.timestamp > ts,
            )
            .order_by(ResourceSnapshot.timestamp.asc())
            .limit(1)
        )

        candidates: list[ResourceSnapshot] = []
        prev_res = self._session.execute(stmt_prev).scalars().first()
        if prev_res is not None:
            candidates.append(prev_res)
        next_res = self._session.execute(stmt_next).scalars().first()
        if next_res is not None:
            candidates.append(next_res)

        if not candidates:
            self._resource_cache[cache_key] = None
            return None

        candidates.sort(
            key=lambda r: abs((_ensure_utc(r.timestamp) - ts).total_seconds())  # type: ignore[operator]
        )
        best = candidates[0]
        delta = abs((_ensure_utc(best.timestamp) - ts).total_seconds())  # type: ignore[operator]

        if delta <= max_delta_seconds:
            res = ResourceContext(
                resource_snapshot_id=best.id,
                cpu_percent=best.cpu_percent,
                memory_percent=best.memory_percent,
                disk_usage_percent=best.disk_usage_percent,
            )
            self._resource_cache[cache_key] = res
            return res

        self._resource_cache[cache_key] = None
        return None

    # ── System Snapshot Correlation ─────────────────────────────────────────

    def correlate_snapshot(
        self,
        host_id: uuid.UUID,
        timestamp: datetime,
        process_id: uuid.UUID | None = None,
        pid: int | None = None,
        max_delta_seconds: float = 3600.0,
    ) -> Optional[SnapshotContext]:
        """Find the nearest system snapshot on host and check process containment."""
        if self._session is None:
            return None

        ts = _ensure_utc(timestamp)
        if ts is None:
            return None

        cache_key = (host_id, ts, process_id, pid, max_delta_seconds)
        if cache_key in self._snapshot_cache:
            return self._snapshot_cache[cache_key]

        if self._snapshots_prefetched:
            host_snaps = [s for s in self._prefetched_snapshots if s.host_id == host_id]
            if not host_snaps:
                self._snapshot_cache[cache_key] = None
                return None
            prev_cand = None
            next_cand = None
            for s in host_snaps:
                s_ts = _ensure_utc(s.timestamp)
                if s_ts <= ts:
                    if prev_cand is None or s_ts > _ensure_utc(prev_cand.timestamp):
                        prev_cand = s
                elif s_ts > ts:
                    if next_cand is None or s_ts < _ensure_utc(next_cand.timestamp):
                        next_cand = s
            candidates = [c for c in (prev_cand, next_cand) if c is not None]
            if not candidates:
                self._snapshot_cache[cache_key] = None
                return None
            candidates.sort(
                key=lambda s: abs((_ensure_utc(s.timestamp) - ts).total_seconds())  # type: ignore[operator]
            )
            best = candidates[0]
            delta = abs((_ensure_utc(best.timestamp) - ts).total_seconds())  # type: ignore[operator]
            if delta > max_delta_seconds:
                self._snapshot_cache[cache_key] = None
                return None
            process_captured = None
            if process_id is not None or pid is not None:
                processes_data = (
                    best.data.get("processes", [])
                    if isinstance(best.data, dict)
                    else []
                )
                matched = False
                for p_dict in processes_data:
                    if not isinstance(p_dict, dict):
                        continue
                    if process_id is not None:
                        if p_dict.get("id") == str(process_id):
                            matched = True
                            break
                    elif pid is not None:
                        if p_dict.get("pid") == pid:
                            matched = True
                            break
                process_captured = matched

            res = SnapshotContext(
                snapshot_id=best.id,
                snapshot_type=best.snapshot_type,
                time_delta_seconds=round(delta, 3),
                process_captured=process_captured,
            )
            self._snapshot_cache[cache_key] = res
            return res

        stmt_prev = (
            select(Snapshot)
            .where(
                Snapshot.host_id == host_id,
                Snapshot.timestamp <= ts,
            )
            .order_by(Snapshot.timestamp.desc())
            .limit(1)
        )
        stmt_next = (
            select(Snapshot)
            .where(
                Snapshot.host_id == host_id,
                Snapshot.timestamp > ts,
            )
            .order_by(Snapshot.timestamp.asc())
            .limit(1)
        )

        candidates: list[Snapshot] = []
        prev_snap = self._session.execute(stmt_prev).scalars().first()
        if prev_snap is not None:
            candidates.append(prev_snap)
        next_snap = self._session.execute(stmt_next).scalars().first()
        if next_snap is not None:
            candidates.append(next_snap)

        if not candidates:
            self._snapshot_cache[cache_key] = None
            return None

        candidates.sort(
            key=lambda s: abs((_ensure_utc(s.timestamp) - ts).total_seconds())  # type: ignore[operator]
        )
        best = candidates[0]
        delta = abs((_ensure_utc(best.timestamp) - ts).total_seconds())  # type: ignore[operator]

        if delta > max_delta_seconds:
            self._snapshot_cache[cache_key] = None
            return None

        process_captured: bool | None = None
        if process_id is not None or pid is not None:
            processes_data = (
                best.data.get("processes", [])
                if isinstance(best.data, dict)
                else []
            )
            matched = False
            for p_dict in processes_data:
                if not isinstance(p_dict, dict):
                    continue
                if process_id is not None:
                    if p_dict.get("id") == str(process_id):
                        matched = True
                        break
                elif pid is not None:
                    if p_dict.get("pid") == pid:
                        matched = True
                        break
            process_captured = matched

        res = SnapshotContext(
            snapshot_id=best.id,
            snapshot_type=best.snapshot_type,
            time_delta_seconds=round(delta, 3),
            process_captured=process_captured,
        )
        self._snapshot_cache[cache_key] = res
        return res
