"""OSIRIS native Qt table model for system resource snapshots.

Provides ResourcesTableModel, a QAbstractTableModel subclass for presenting
validated resource telemetry snapshots in a dense, investigator-oriented table.
"""

from __future__ import annotations

import math
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QObject,
    QPersistentModelIndex,
    Qt,
)
from typing_extensions import override

from desktop.client.models import ResourceSnapshot, ResourceSnapshotCollection

# Ordered, stable column headers for investigator table views
COLUMNS: tuple[str, ...] = (
    "Timestamp",
    "CPU %",
    "Memory %",
    "Memory Used",
    "Memory Total",
    "Disk Read",
    "Disk Write",
    "Disk Usage %",
)

RESOURCE_COLUMNS: tuple[str, ...] = COLUMNS

COLUMN_TIMESTAMP: int = 0
COLUMN_CPU_PERCENT: int = 1
COLUMN_MEMORY_PERCENT: int = 2
COLUMN_MEMORY_USED: int = 3
COLUMN_MEMORY_TOTAL: int = 4
COLUMN_DISK_READ: int = 5
COLUMN_DISK_WRITE: int = 6
COLUMN_DISK_USAGE_PERCENT: int = 7

RESOURCE_COLUMN_TIMESTAMP: int = COLUMN_TIMESTAMP
RESOURCE_COLUMN_CPU_PERCENT: int = COLUMN_CPU_PERCENT
RESOURCE_COLUMN_MEMORY_PERCENT: int = COLUMN_MEMORY_PERCENT
RESOURCE_COLUMN_MEMORY_USED: int = COLUMN_MEMORY_USED
RESOURCE_COLUMN_MEMORY_TOTAL: int = COLUMN_MEMORY_TOTAL
RESOURCE_COLUMN_DISK_READ: int = COLUMN_DISK_READ
RESOURCE_COLUMN_DISK_WRITE: int = COLUMN_DISK_WRITE
RESOURCE_COLUMN_DISK_USAGE_PERCENT: int = COLUMN_DISK_USAGE_PERCENT

EMPTY_PLACEHOLDER: str = "—"

# Custom Qt ItemDataRoles for extended data access and styling
ResourceSnapshotRole: int = int(Qt.ItemDataRole.UserRole) + 1
ResourceRole: int = ResourceSnapshotRole


def format_percent(val: float | int | None) -> str:
    """Format a percentage value to one decimal place, preserving 0.0.

    Args:
        val: Numeric percentage (0.0 to 100.0) or None.

    Returns:
        Formatted percentage string (e.g. '15.2%', '0.0%') or EMPTY_PLACEHOLDER.
    """
    if isinstance(val, bool) or val is None:
        return EMPTY_PLACEHOLDER
    try:
        fval = float(val)
    except (ValueError, TypeError):
        return EMPTY_PLACEHOLDER
    if math.isnan(fval) or math.isinf(fval) or fval < 0.0:
        return EMPTY_PLACEHOLDER
    if abs(fval) < 1e-9:
        fval = 0.0
    return f"{fval:.1f}%"


def format_bytes(num_bytes: int | None) -> str:
    """Format a byte count into binary units (B, KiB, MiB, GiB, TiB, PiB, EiB).

    Preserves 0 as '0 B' and uses one decimal place for scaled binary units.
    Handles None and non-valid counters explicitly by returning EMPTY_PLACEHOLDER.

    Args:
        num_bytes: Non-negative byte counter, or None.

    Returns:
        Formatted string (e.g. '0 B', '512 B', '1.0 MiB', '14.9 GiB')
        or EMPTY_PLACEHOLDER.
    """
    if (
        isinstance(num_bytes, bool)
        or not isinstance(num_bytes, int)
        or num_bytes < 0
    ):
        return EMPTY_PLACEHOLDER
    if num_bytes < 1024:
        return f"{num_bytes} B"

    units = ("B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB")
    val = float(num_bytes)
    unit_idx = 0
    while val >= 1024.0 and unit_idx < len(units) - 1:
        val /= 1024.0
        unit_idx += 1

    if round(val, 1) >= 1024.0 and unit_idx < len(units) - 1:
        val /= 1024.0
        unit_idx += 1

    return f"{val:.1f} {units[unit_idx]}"


class ResourcesTableModel(QAbstractTableModel):
    """Qt table model representing a collection of OSIRIS resource snapshots.

    Accepts a ResourceSnapshotCollection and exposes resource telemetry records
    through standard Qt model/view roles without storing widgets or mutating raw
    records.
    """

    COLUMNS = COLUMNS
    RESOURCE_COLUMNS = RESOURCE_COLUMNS

    COLUMN_TIMESTAMP = COLUMN_TIMESTAMP
    COLUMN_CPU_PERCENT = COLUMN_CPU_PERCENT
    COLUMN_MEMORY_PERCENT = COLUMN_MEMORY_PERCENT
    COLUMN_MEMORY_USED = COLUMN_MEMORY_USED
    COLUMN_MEMORY_TOTAL = COLUMN_MEMORY_TOTAL
    COLUMN_DISK_READ = COLUMN_DISK_READ
    COLUMN_DISK_WRITE = COLUMN_DISK_WRITE
    COLUMN_DISK_USAGE_PERCENT = COLUMN_DISK_USAGE_PERCENT

    RESOURCE_COLUMN_TIMESTAMP = RESOURCE_COLUMN_TIMESTAMP
    RESOURCE_COLUMN_CPU_PERCENT = RESOURCE_COLUMN_CPU_PERCENT
    RESOURCE_COLUMN_MEMORY_PERCENT = RESOURCE_COLUMN_MEMORY_PERCENT
    RESOURCE_COLUMN_MEMORY_USED = RESOURCE_COLUMN_MEMORY_USED
    RESOURCE_COLUMN_MEMORY_TOTAL = RESOURCE_COLUMN_MEMORY_TOTAL
    RESOURCE_COLUMN_DISK_READ = RESOURCE_COLUMN_DISK_READ
    RESOURCE_COLUMN_DISK_WRITE = RESOURCE_COLUMN_DISK_WRITE
    RESOURCE_COLUMN_DISK_USAGE_PERCENT = RESOURCE_COLUMN_DISK_USAGE_PERCENT

    def __init__(
        self,
        collection: ResourceSnapshotCollection | None = None,
        parent: QObject | None = None,
    ) -> None:
        """Initialize ResourcesTableModel with an optional collection.

        Args:
            collection: Optional initial ResourceSnapshotCollection.
            parent: Optional parent QObject.

        Raises:
            TypeError: If collection is provided but not a ResourceSnapshotCollection.
        """
        super().__init__(parent)
        self._collection: ResourceSnapshotCollection | None = None
        self._snapshots: list[ResourceSnapshot] = []

        if collection is not None:
            if not isinstance(collection, ResourceSnapshotCollection):
                raise TypeError(
                    "Expected ResourceSnapshotCollection, got "
                    f"{type(collection).__name__}"
                )
            self._collection = collection
            self._snapshots = list(collection.items)

    # ----------------------------------------------------------------------
    # QAbstractTableModel interface implementation
    # ----------------------------------------------------------------------

    @override
    def rowCount(
        self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()
    ) -> int:
        """Return the number of snapshot rows for the top-level index.

        Child indexes return 0 per Qt flat table model conventions.
        """
        if parent.isValid():
            return 0
        return len(self._snapshots)

    @override
    def columnCount(
        self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()
    ) -> int:
        """Return the number of columns for the top-level index.

        Child indexes return 0 per Qt flat table model conventions.
        """
        if parent.isValid():
            return 0
        return len(self.COLUMNS)

    @override
    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = int(Qt.ItemDataRole.DisplayRole),
    ) -> Any:
        """Return header labels for columns or row numbers."""
        if orientation == Qt.Orientation.Horizontal:
            if role == int(Qt.ItemDataRole.DisplayRole):
                if 0 <= section < len(self.COLUMNS):
                    return self.COLUMNS[section]
        elif orientation == Qt.Orientation.Vertical:
            if role == int(Qt.ItemDataRole.DisplayRole):
                if 0 <= section < len(self._snapshots):
                    return str(section + 1)
        return None

    @override
    def data(
        self,
        index: QModelIndex | QPersistentModelIndex,
        role: int = int(Qt.ItemDataRole.DisplayRole),
    ) -> Any:
        """Return cell data for the given index and item data role."""
        if not index.isValid():
            return None

        row = index.row()
        col = index.column()

        if row < 0 or row >= len(self._snapshots):
            return None
        if col < 0 or col >= len(self.COLUMNS):
            return None

        snapshot = self._snapshots[row]

        if role == int(Qt.ItemDataRole.DisplayRole):
            return self._format_cell_display(snapshot, col)

        if role == int(Qt.ItemDataRole.ToolTipRole):
            cell_text = self._format_cell_display(snapshot, col)
            return cell_text if cell_text != EMPTY_PLACEHOLDER else None

        if role == int(Qt.ItemDataRole.TextAlignmentRole):
            if col == COLUMN_TIMESTAMP:
                return int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        if role in (ResourceSnapshotRole, int(Qt.ItemDataRole.UserRole)):
            return snapshot

        return None

    # ----------------------------------------------------------------------
    # Collection management and update methods
    # ----------------------------------------------------------------------

    def set_collection(self, collection: ResourceSnapshotCollection | None) -> None:
        """Replace model contents with a new collection or clear with None.

        Uses Qt's beginResetModel/endResetModel sequence to notify views.

        Args:
            collection: The new ResourceSnapshotCollection to display, or None
                to clear the model.

        Raises:
            TypeError: If collection is neither a ResourceSnapshotCollection nor None.
        """
        if collection is not None and not isinstance(
            collection, ResourceSnapshotCollection
        ):
            raise TypeError(
                "Expected ResourceSnapshotCollection or None, got "
                f"{type(collection).__name__}"
            )

        self.beginResetModel()
        if collection is None:
            self._collection = None
            self._snapshots = []
        else:
            self._collection = collection
            self._snapshots = list(collection.items)
        self.endResetModel()

    def clear(self) -> None:
        """Clear all snapshot rows and reset pagination metadata."""
        self.beginResetModel()
        self._collection = None
        self._snapshots = []
        self.endResetModel()

    # ----------------------------------------------------------------------
    # Snapshot and metadata accessors
    # ----------------------------------------------------------------------

    def snapshot_at(self, row: int) -> ResourceSnapshot | None:
        """Return the original ResourceSnapshot instance at the specified row.

        Args:
            row: 0-based row index.

        Returns:
            The ResourceSnapshot instance, or None if the row index is out of bounds.
        """
        if 0 <= row < len(self._snapshots):
            return self._snapshots[row]
        return None

    def get_snapshot(self, row: int) -> ResourceSnapshot | None:
        """Alias for snapshot_at(row)."""
        return self.snapshot_at(row)

    def resource_at(self, row: int) -> ResourceSnapshot | None:
        """Alias for snapshot_at(row)."""
        return self.snapshot_at(row)

    def get_resource(self, row: int) -> ResourceSnapshot | None:
        """Alias for snapshot_at(row)."""
        return self.snapshot_at(row)

    def row_for_snapshot(
        self, snapshot: ResourceSnapshot | str | None
    ) -> int:
        """Return the 0-based row index for a given snapshot or snapshot ID.

        Args:
            snapshot: ResourceSnapshot instance, snapshot ID string, or None.

        Returns:
            0-based integer row index, or -1 if snapshot is None or not found.
        """
        if snapshot is None:
            return -1
        target_id = (
            snapshot.id
            if isinstance(snapshot, ResourceSnapshot)
            else str(snapshot)
        )
        for idx, snap in enumerate(self._snapshots):
            if snap.id == target_id:
                return idx
        return -1

    def find_row_by_snapshot(
        self, snapshot: ResourceSnapshot | str | None
    ) -> int:
        """Alias for row_for_snapshot(snapshot)."""
        return self.row_for_snapshot(snapshot)

    @property
    def total_count(self) -> int:
        """Total matching snapshots count reported by the server."""
        if self._collection is not None:
            return self._collection.total
        return 0

    @property
    def total(self) -> int:
        """Alias for total_count."""
        return self.total_count

    @property
    def limit(self) -> int:
        """Pagination limit reported by the server, or default 50."""
        if self._collection is not None:
            return self._collection.limit
        return 50

    @property
    def offset(self) -> int:
        """Pagination offset reported by the server, or 0."""
        if self._collection is not None:
            return self._collection.offset
        return 0

    @property
    def collection(self) -> ResourceSnapshotCollection | None:
        """Return the current ResourceSnapshotCollection, or None if empty."""
        return self._collection

    @property
    def snapshots(self) -> tuple[ResourceSnapshot, ...]:
        """Return an immutable snapshot of all snapshots in current page."""
        return tuple(self._snapshots)

    @property
    def resources(self) -> tuple[ResourceSnapshot, ...]:
        """Alias for snapshots."""
        return self.snapshots

    # ----------------------------------------------------------------------
    # Internal cell formatting helper
    # ----------------------------------------------------------------------

    def _format_cell_display(self, snapshot: ResourceSnapshot, column: int) -> str:
        """Format a resource snapshot field into a cell display string.

        Preserves numeric 0 and 0.0 values, and uses EMPTY_PLACEHOLDER for None.
        Never mutates the underlying ResourceSnapshot record.
        """
        if column == COLUMN_TIMESTAMP:
            return (
                snapshot.timestamp
                if snapshot.timestamp and snapshot.timestamp.strip()
                else EMPTY_PLACEHOLDER
            )

        if column == COLUMN_CPU_PERCENT:
            return format_percent(snapshot.cpu_percent)

        if column == COLUMN_MEMORY_PERCENT:
            return format_percent(snapshot.memory_percent)

        if column == COLUMN_MEMORY_USED:
            return format_bytes(snapshot.memory_used)

        if column == COLUMN_MEMORY_TOTAL:
            return format_bytes(snapshot.memory_total)

        if column == COLUMN_DISK_READ:
            return format_bytes(snapshot.disk_read_bytes)

        if column == COLUMN_DISK_WRITE:
            return format_bytes(snapshot.disk_write_bytes)

        if column == COLUMN_DISK_USAGE_PERCENT:
            return format_percent(snapshot.disk_usage_percent)

        return EMPTY_PLACEHOLDER


def _parse_iso_utc(ts_str: Any) -> datetime | None:
    """Safely parse an ISO-8601 timestamp string into a UTC-aware datetime."""
    if not ts_str or not isinstance(ts_str, str):
        return None
    cleaned = ts_str.strip()
    if not cleaned:
        return None
    try:
        dt = datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def find_latest_resource_snapshot(
    snapshots: Iterable[ResourceSnapshot] | None,
) -> ResourceSnapshot | None:
    """Determine the most recent ResourceSnapshot from a sequence of snapshots.

    Does not assume chronological order. Parses ISO-8601 timestamps safely,
    normalizing timezone offsets to UTC. If primary timestamps are identical,
    breaks ties using created_at, then lexical order, and finally snapshot ID.
    Handles empty sequences, generators, and None safely.

    Args:
        snapshots: Iterable of ResourceSnapshot objects, or None.

    Returns:
        The ResourceSnapshot with the newest timestamp, or None.
    """
    if snapshots is None:
        return None

    dt_min = datetime.min.replace(tzinfo=timezone.utc)

    def _snapshot_timestamp_key(
        snap: ResourceSnapshot,
    ) -> tuple[datetime, datetime, str, str, str]:
        primary_dt = _parse_iso_utc(snap.timestamp) or dt_min
        secondary_dt = _parse_iso_utc(snap.created_at) or dt_min
        lex_primary = str(snap.timestamp or "")
        lex_secondary = str(snap.created_at or "")
        snap_id = str(snap.id or "")
        return (primary_dt, secondary_dt, lex_primary, lex_secondary, snap_id)

    try:
        return max(snapshots, key=_snapshot_timestamp_key, default=None)
    except (TypeError, ValueError):
        return None


__all__ = [
    "COLUMNS",
    "COLUMN_CPU_PERCENT",
    "COLUMN_DISK_READ",
    "COLUMN_DISK_USAGE_PERCENT",
    "COLUMN_DISK_WRITE",
    "COLUMN_MEMORY_PERCENT",
    "COLUMN_MEMORY_TOTAL",
    "COLUMN_MEMORY_USED",
    "COLUMN_TIMESTAMP",
    "EMPTY_PLACEHOLDER",
    "RESOURCE_COLUMNS",
    "RESOURCE_COLUMN_CPU_PERCENT",
    "RESOURCE_COLUMN_DISK_READ",
    "RESOURCE_COLUMN_DISK_USAGE_PERCENT",
    "RESOURCE_COLUMN_DISK_WRITE",
    "RESOURCE_COLUMN_MEMORY_PERCENT",
    "RESOURCE_COLUMN_MEMORY_TOTAL",
    "RESOURCE_COLUMN_MEMORY_USED",
    "RESOURCE_COLUMN_TIMESTAMP",
    "ResourceRole",
    "ResourceSnapshotRole",
    "ResourcesTableModel",
    "find_latest_resource_snapshot",
    "format_bytes",
    "format_percent",
]
