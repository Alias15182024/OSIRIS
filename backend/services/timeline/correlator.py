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
from datetime import datetime, timezone
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
        self._user_cache: dict[tuple[uuid.UUID, Optional[int], Optional[str], Optional[uuid.UUID]], Optional[UserContext]] = {}
        self._file_cache: dict[tuple[uuid.UUID, str], Optional[FileContext]] = {}

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
            return None

        if len(procs) == 1:
            proc = procs[0]
            return ProcessContext(
                process_id=proc.id,
                pid=proc.pid,
                ppid=proc.ppid,
                command=proc.command,
                executable=proc.executable,
            )

        # Disambiguate if event_type matches boundary exactly
        if event_type == "process.start":
            start_m = [p for p in procs if _ensure_utc(p.started_at) == ts]
            if len(start_m) == 1:
                proc = start_m[0]
                return ProcessContext(
                    process_id=proc.id,
                    pid=proc.pid,
                    ppid=proc.ppid,
                    command=proc.command,
                    executable=proc.executable,
                )
        elif event_type == "process.end":
            end_m = [
                p
                for p in procs
                if p.ended_at is not None and _ensure_utc(p.ended_at) == ts
            ]
            if len(end_m) == 1:
                proc = end_m[0]
                return ProcessContext(
                    process_id=proc.id,
                    pid=proc.pid,
                    ppid=proc.ppid,
                    command=proc.command,
                    executable=proc.executable,
                )

        logger.warning(
            "Ambiguous PID %s on host %s at %s (%d matches); returning None",
            pid,
            host_id,
            ts,
            len(procs),
        )
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
            return None

        candidates.sort(
            key=lambda r: abs((_ensure_utc(r.timestamp) - ts).total_seconds())  # type: ignore[operator]
        )
        best = candidates[0]
        delta = abs((_ensure_utc(best.timestamp) - ts).total_seconds())  # type: ignore[operator]

        if delta <= max_delta_seconds:
            return ResourceContext(
                resource_snapshot_id=best.id,
                cpu_percent=best.cpu_percent,
                memory_percent=best.memory_percent,
                disk_usage_percent=best.disk_usage_percent,
            )

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
            return None

        candidates.sort(
            key=lambda s: abs((_ensure_utc(s.timestamp) - ts).total_seconds())  # type: ignore[operator]
        )
        best = candidates[0]
        delta = abs((_ensure_utc(best.timestamp) - ts).total_seconds())  # type: ignore[operator]

        if delta > max_delta_seconds:
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

        return SnapshotContext(
            snapshot_id=best.id,
            snapshot_type=best.snapshot_type,
            time_delta_seconds=round(delta, 3),
            process_captured=process_captured,
        )
