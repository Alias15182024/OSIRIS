"""Process lifecycle entity maintenance for OSIRIS.

Maintains the authoritative `processes` table based on real process observations
produced by the ProcessCollector.

Follows the OSIRIS process model contract:
- Creates a `Process` record when a new process is observed (`process.start`).
- Populates host, PID, PPID, command, executable, Linux-user reference (FK to `linux_users`),
  and `started_at` from actual observation data.
- Updates `ended_at` when that process terminates (`process.end`).
- Handles batch ordering: ensures exited processes are ended before new processes
  with the same PID are started, even if observations are unordered.
- Handles PID reuse by preserving distinct internal UUIDs for each process lifetime.
- Handles the initial collector cycle where pre-existing processes are observed.
- Invalidates the resolver cache so subsequent identity resolution sees current state.
- Flushes changes to the caller's session without committing or closing.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.db.models.linux_user import LinuxUser
from backend.db.models.process import Process
from backend.services.events.resolver import _ensure_uuid, resolve_host_uuid
from backend.services.events.schemas import RawObservation


def _ensure_utc(dt: datetime | None) -> datetime:
    """Ensure a datetime is timezone-aware UTC."""
    if dt is None:
        return datetime.now(timezone.utc)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class ProcessLifecycleService:
    """Maintains `Process` database records from raw process observations."""

    def __init__(self) -> None:
        pass

    def apply_observations(
        self,
        session: Session,
        observations: list[RawObservation],
        host_id: uuid.UUID | str,
        *,
        resolver: IdentityResolver | None = None,
        now: datetime | None = None,
    ) -> list[Process]:
        """Apply process start and end lifecycle events from raw observations.

        Parameters
        ----------
        session:
            Active SQLAlchemy Session.
        observations:
            List of raw observations collected in the current cycle.
        host_id:
            UUID of the monitored host.
        resolver:
            Optional IdentityResolver instance to invalidate on lifecycle changes.
        now:
            Optional current timestamp.

        Returns
        -------
        list[Process]
            List of created or updated Process instances.
        """
        host_uuid = _ensure_uuid(host_id)
        current_ts = _ensure_utc(now)

        # Filter process observations
        proc_obs = [
            o
            for o in observations
            if o.source == "proc"
            or o.object_type == "process"
            or o.event_type in ("process.start", "process.end")
        ]
        if not proc_obs:
            return []

        # Enforce batch ordering: process exits BEFORE starts.
        # This guarantees that if a PID was reused in one collection cycle,
        # the terminating process is ended before the new process instance is created.
        exit_obs = [
            o
            for o in proc_obs
            if o.event_type == "process.end" or o.action == "exit"
        ]
        start_obs = [
            o
            for o in proc_obs
            if o.event_type == "process.start" or o.action == "start"
        ]

        affected_pids: set[int] = set()
        modified_processes: list[Process] = []

        # 1. Process terminations (process.end)
        for obs in exit_obs:
            if obs.pid is None:
                continue

            ts = _ensure_utc(obs.observed_at) or current_ts

            # Find active process for this host and pid that started at or before ts (ended_at IS NULL)
            stmt = select(Process).where(
                Process.host_id == host_uuid,
                Process.pid == obs.pid,
                Process.started_at <= ts,
                Process.ended_at.is_(None),
            )
            active_procs = session.execute(stmt).scalars().all()

            if active_procs:
                for proc in active_procs:
                    proc.ended_at = ts
                    modified_processes.append(proc)
            else:
                # Check if a process record with this exact ended_at already exists (idempotency)
                stmt_existing = select(Process).where(
                    Process.host_id == host_uuid,
                    Process.pid == obs.pid,
                    Process.ended_at == ts,
                )
                already_ended = session.execute(stmt_existing).scalars().first()
                if already_ended is not None:
                    modified_processes.append(already_ended)
                else:
                    # Process was not previously seen running (e.g. short-lived process).
                    # To allow the termination event to resolve to an entity, create a terminated record.
                    cmd = (
                        obs.command
                        or (obs.payload and obs.payload.get("comm"))
                        or f"[pid {obs.pid}]"
                    )
                    exe = (
                        obs.object_path
                        or (
                            obs.payload
                            and (
                                obs.payload.get("executable")
                                or obs.payload.get("last_known_executable")
                            )
                        )
                    )
                    user_id = self._lookup_user_id(session, host_uuid, obs.uid)
                    proc = Process(
                        id=uuid.uuid4(),
                        host_id=host_uuid,
                        pid=obs.pid,
                        ppid=obs.ppid,
                        command=str(cmd)[:4096],
                        executable=str(exe)[:4096] if exe else None,
                        linux_user_id=user_id,
                        started_at=ts,
                        ended_at=ts,
                        created_at=current_ts,
                    )
                    session.add(proc)
                    modified_processes.append(proc)

            affected_pids.add(obs.pid)

        # 2. Process starts (process.start)
        for obs in start_obs:
            if obs.pid is None:
                continue

            ts = _ensure_utc(obs.observed_at) or current_ts

            # Check if an active process already exists for this PID with ended_at IS NULL
            # that started strictly BEFORE ts.
            # If so, the PID was reused without a prior process.end; terminate the older process.
            stmt = select(Process).where(
                Process.host_id == host_uuid,
                Process.pid == obs.pid,
                Process.started_at < ts,
                Process.ended_at.is_(None),
            )
            existing_active = session.execute(stmt).scalars().all()
            for old_proc in existing_active:
                old_proc.ended_at = ts

            # Check if this process start was already registered (idempotency)
            stmt_current = select(Process).where(
                Process.host_id == host_uuid,
                Process.pid == obs.pid,
                Process.started_at == ts,
            )
            current_proc = session.execute(stmt_current).scalars().first()
            if current_proc is not None:
                modified_processes.append(current_proc)
                affected_pids.add(obs.pid)
                continue

            cmd = (
                obs.command
                or (obs.payload and obs.payload.get("comm"))
                or f"[pid {obs.pid}]"
            )
            exe = (
                obs.object_path
                or (obs.payload and obs.payload.get("executable"))
            )
            user_id = self._lookup_user_id(session, host_uuid, obs.uid)

            new_proc = Process(
                id=uuid.uuid4(),
                host_id=host_uuid,
                pid=obs.pid,
                ppid=obs.ppid,
                command=str(cmd)[:4096],
                executable=str(exe)[:4096] if exe else None,
                linux_user_id=user_id,
                started_at=ts,
                ended_at=None,
                created_at=current_ts,
            )
            session.add(new_proc)
            modified_processes.append(new_proc)
            affected_pids.add(obs.pid)

        # Flush entity changes so resolver can see them immediately in this transaction
        session.flush()

        # Invalidate resolver cache for all affected PIDs
        if resolver is not None:
            for pid in affected_pids:
                resolver.invalidate_process(host_uuid, pid)

        return modified_processes

    def _lookup_user_id(
        self, session: Session, host_uuid: uuid.UUID, uid: int | None
    ) -> uuid.UUID | None:
        """Resolve a host-scoped UID to a LinuxUser primary key UUID."""
        if uid is None or uid < 0:
            return None
        stmt = select(LinuxUser.id).where(
            LinuxUser.host_id == host_uuid,
            LinuxUser.uid == uid,
        )
        return session.execute(stmt).scalar_one_or_none()
