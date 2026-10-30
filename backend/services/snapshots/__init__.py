"""OSIRIS Snapshot Creation Service — Phase 2 Milestone 2.1.

Provides ``SnapshotService`` for capturing point-in-time system-state
snapshots that combine active process data and latest resource telemetry.
"""

from backend.services.snapshots.service import (
    SNAPSHOT_TYPE_SYSTEM_STATE,
    HostNotFoundError,
    SnapshotError,
    SnapshotPersistenceError,
    SnapshotService,
)

__all__ = [
    "HostNotFoundError",
    "SNAPSHOT_TYPE_SYSTEM_STATE",
    "SnapshotError",
    "SnapshotPersistenceError",
    "SnapshotService",
]
