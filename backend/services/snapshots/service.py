"""Snapshot creation service — capture point-in-time system state.

``SnapshotService`` queries the OSIRIS database for a host's currently
active processes and latest resource telemetry, then persists a new
``Snapshot`` record combining both into a single JSON-compatible ``data``
payload.

Design principles:
  - **Forensic history**: every call to ``create_snapshot`` produces a new
    record.  Previous snapshots are never overwritten or deleted.
  - **Transaction discipline**: the service calls ``session.flush()`` to
    surface constraint violations immediately but does **not** call
    ``session.commit()`` or ``session.rollback()`` — the caller owns the
    transaction boundary and decides when to commit or roll back.
  - **Graceful degradation**: empty process lists and missing resource
    telemetry are captured faithfully (empty list / ``null``); they are
    not treated as errors.
  - **No duplicate collection**: the service queries existing OSIRIS data
    tables directly.  It does not invoke Linux collectors or create a
    second event-processing pipeline.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from backend.db.base import new_uuid, utcnow
from backend.db.models.host import Host
from backend.db.models.process import Process
from backend.db.models.resource_snapshot import ResourceSnapshot
from backend.db.models.snapshot import Snapshot
from backend.services.events.resolver import resolve_host_uuid


# ── Snapshot type constant ──────────────────────────────────────────────
SNAPSHOT_TYPE_SYSTEM_STATE = "system_state"


# ── Exceptions ──────────────────────────────────────────────────────────


class SnapshotError(Exception):
    """Base exception for snapshot service errors."""


class HostNotFoundError(SnapshotError):
    """Raised when the specified host does not exist."""

    def __init__(self, host_id: uuid.UUID | str) -> None:
        self.host_id = host_id
        super().__init__(f"Host not found: {host_id}")


class SnapshotPersistenceError(SnapshotError):
    """Raised when the snapshot cannot be persisted due to a database error."""

    def __init__(self, detail: str, cause: Exception | None = None) -> None:
        self.detail = detail
        self._cause = cause
        super().__init__(detail)
        if cause is not None:
            self.__cause__ = cause

    @property
    def cause(self) -> Exception | None:
        """The underlying database exception that caused this error."""
        return self._cause if self._cause is not None else self.__cause__

    @cause.setter
    def cause(self, value: Exception | None) -> None:
        self._cause = value


# ── Service ─────────────────────────────────────────────────────────────


class SnapshotService:
    """Create and persist point-in-time system-state snapshots.

    Parameters
    ----------
    session:
        An active SQLAlchemy ``Session`` (optional during instantiation).
        The caller is responsible for committing or rolling back the
        transaction.
    """

    def __init__(self, session: Session | None = None) -> None:
        self._session = session

    @property
    def session(self) -> Session | None:
        """The active database session."""
        return self._session

    @session.setter
    def session(self, s: Session | None) -> None:
        """Update or bind the active database session."""
        self._session = s

    def set_session(self, session: Session | None) -> None:
        """Bind service to an active database session."""
        self._session = session

    # ── Public API ──────────────────────────────────────────────────────

    def create_snapshot(
        self,
        host_id: uuid.UUID | str,
        *,
        timestamp: datetime | None = None,
    ) -> Snapshot:
        """Capture and persist a system-state snapshot for *host_id*.

        The snapshot ``data`` payload has the structure::

            {
                "processes": [ ... ],   # active processes (ended_at IS NULL)
                "resources": { ... }    # latest resource snapshot (or null)
            }

        Parameters
        ----------
        host_id:
            UUID (or string representation) of the monitored host.
            Must reference an existing ``hosts`` row.
        timestamp:
            Optional snapshot timestamp.  Defaults to the current UTC
            time if not supplied.

        Returns
        -------
        Snapshot
            The persisted ``Snapshot`` ORM instance.

        Raises
        ------
        RuntimeError
            If no active database session is bound to the service.
        HostNotFoundError
            If *host_id* does not reference an existing host.
        SnapshotPersistenceError
            If the database rejects the insert for any reason.
        """
        if self._session is None:
            raise RuntimeError("SnapshotService has no active database session")

        # 1. Resolve and validate host exists
        host_uuid = (
            resolve_host_uuid(host_id)
            if not isinstance(host_id, uuid.UUID)
            else host_id
        )
        host = self._session.get(Host, host_uuid)
        if host is None:
            raise HostNotFoundError(host_id)

        # 2. Determine snapshot timestamp
        snap_ts = timestamp if timestamp is not None else utcnow()

        # 3. Gather data
        processes_data = self._collect_active_processes(host_uuid)
        resource_data = self._collect_latest_resource(host_uuid)

        # 4. Build snapshot
        snapshot = Snapshot(
            id=new_uuid(),
            host_id=host_uuid,
            timestamp=snap_ts,
            snapshot_type=SNAPSHOT_TYPE_SYSTEM_STATE,
            data={
                "processes": processes_data,
                "resources": resource_data,
            },
            created_at=utcnow(),
        )

        # 5. Persist — flush to surface constraint errors, don't commit.
        # Transaction commit and rollback remain the caller's responsibility.
        # If flush fails, SQLAlchemy marks the transaction or savepoint as failed,
        # requiring the caller to handle rollback or savepoint recovery.
        # The service does not unilaterally roll back the session, preserving
        # the caller's transaction management and savepoint control.
        try:
            self._session.add(snapshot)
            self._session.flush()
        except IntegrityError as exc:
            raise SnapshotPersistenceError(
                f"Integrity error persisting snapshot for host {host_id}",
                cause=exc,
            ) from exc
        except SQLAlchemyError as exc:
            raise SnapshotPersistenceError(
                f"Database error persisting snapshot for host {host_id}",
                cause=exc,
            ) from exc

        return snapshot

    # ── Internal helpers ────────────────────────────────────────────────

    def _collect_active_processes(
        self, host_id: uuid.UUID
    ) -> list[dict[str, Any]]:
        """Return serializable list of active processes for *host_id*.

        Active processes are those where ``ended_at IS NULL``.
        """
        stmt = (
            select(Process)
            .where(Process.host_id == host_id, Process.ended_at.is_(None))
            .order_by(Process.pid.asc())
        )
        processes = self._session.execute(stmt).scalars().all()
        return [self._serialize_process(p) for p in processes]

    def _collect_latest_resource(
        self, host_id: uuid.UUID
    ) -> Optional[dict[str, Any]]:
        """Return the latest resource snapshot for *host_id*, or ``None``."""
        stmt = (
            select(ResourceSnapshot)
            .where(ResourceSnapshot.host_id == host_id)
            .order_by(ResourceSnapshot.timestamp.desc())
            .limit(1)
        )
        resource = self._session.execute(stmt).scalars().first()
        if resource is None:
            return None
        return self._serialize_resource(resource)

    # ── Serializers ─────────────────────────────────────────────────────

    @staticmethod
    def _serialize_process(proc: Process) -> dict[str, Any]:
        """Convert a ``Process`` ORM instance to a JSON-safe dict."""
        return {
            "id": str(proc.id),
            "pid": proc.pid,
            "ppid": proc.ppid,
            "command": proc.command,
            "executable": proc.executable,
            "linux_user_id": str(proc.linux_user_id) if proc.linux_user_id else None,
            "started_at": proc.started_at.isoformat() if proc.started_at else None,
        }

    @staticmethod
    def _serialize_resource(res: ResourceSnapshot) -> dict[str, Any]:
        """Convert a ``ResourceSnapshot`` ORM instance to a JSON-safe dict."""
        return {
            "id": str(res.id),
            "timestamp": res.timestamp.isoformat() if res.timestamp else None,
            "cpu_percent": res.cpu_percent,
            "memory_total": res.memory_total,
            "memory_used": res.memory_used,
            "memory_percent": res.memory_percent,
            "disk_read_bytes": res.disk_read_bytes,
            "disk_write_bytes": res.disk_write_bytes,
            "disk_usage_percent": res.disk_usage_percent,
        }
