"""OSIRIS native Qt table model for processes.

Provides ProcessesTableModel, a QAbstractTableModel subclass for presenting
validated process records in a dense, investigator-oriented table.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QObject,
    QPersistentModelIndex,
    Qt,
)
from typing_extensions import override

from desktop.client.models import Process, ProcessCollection

# Ordered, stable column headers for investigator table views
COLUMNS: tuple[str, ...] = (
    "PID",
    "PPID",
    "Command",
    "Executable",
    "Linux User ID",
    "Status",
    "Started At",
    "Ended At",
)

PROCESS_COLUMNS: tuple[str, ...] = COLUMNS

COLUMN_PID: int = 0
COLUMN_PPID: int = 1
COLUMN_COMMAND: int = 2
COLUMN_EXECUTABLE: int = 3
COLUMN_LINUX_USER_ID: int = 4
COLUMN_STATUS: int = 5
COLUMN_STARTED_AT: int = 6
COLUMN_ENDED_AT: int = 7

PROCESS_COLUMN_PID: int = COLUMN_PID
PROCESS_COLUMN_PPID: int = COLUMN_PPID
PROCESS_COLUMN_COMMAND: int = COLUMN_COMMAND
PROCESS_COLUMN_EXECUTABLE: int = COLUMN_EXECUTABLE
PROCESS_COLUMN_LINUX_USER_ID: int = COLUMN_LINUX_USER_ID
PROCESS_COLUMN_STATUS: int = COLUMN_STATUS
PROCESS_COLUMN_STARTED_AT: int = COLUMN_STARTED_AT
PROCESS_COLUMN_ENDED_AT: int = COLUMN_ENDED_AT

EMPTY_PLACEHOLDER: str = "—"

STATUS_ACTIVE: str = "active"
STATUS_TERMINATED: str = "terminated"
STATUS_DISPLAY_ACTIVE: str = "Active"
STATUS_DISPLAY_TERMINATED: str = "Terminated"

# Custom Qt ItemDataRoles for extended data access and styling
ProcessRole: int = int(Qt.ItemDataRole.UserRole) + 1
ProcessStatusRole: int = int(Qt.ItemDataRole.UserRole) + 2


class ProcessesTableModel(QAbstractTableModel):
    """Qt table model representing a collection of OSIRIS process records.

    Accepts a ProcessCollection and exposes process records through standard
    Qt model/view roles without storing widgets or mutating raw records.
    """

    COLUMNS = COLUMNS
    COLUMN_PID = COLUMN_PID
    COLUMN_PPID = COLUMN_PPID
    COLUMN_COMMAND = COLUMN_COMMAND
    COLUMN_EXECUTABLE = COLUMN_EXECUTABLE
    COLUMN_LINUX_USER_ID = COLUMN_LINUX_USER_ID
    COLUMN_STATUS = COLUMN_STATUS
    COLUMN_STARTED_AT = COLUMN_STARTED_AT
    COLUMN_ENDED_AT = COLUMN_ENDED_AT

    def __init__(
        self,
        collection: ProcessCollection | None = None,
        parent: QObject | None = None,
    ) -> None:
        """Initialize ProcessesTableModel with an optional ProcessCollection.

        Args:
            collection: Optional initial ProcessCollection.
            parent: Optional parent QObject.

        Raises:
            TypeError: If collection is provided but not a ProcessCollection.
        """
        super().__init__(parent)
        self._collection: ProcessCollection | None = None
        self._processes: list[Process] = []

        if collection is not None:
            if not isinstance(collection, ProcessCollection):
                raise TypeError(
                    f"Expected ProcessCollection, got {type(collection).__name__}"
                )
            self._collection = collection
            self._processes = list(collection.items)

    # ----------------------------------------------------------------------
    # QAbstractTableModel interface implementation
    # ----------------------------------------------------------------------

    @override
    def rowCount(
        self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()
    ) -> int:
        """Return the number of process rows for the top-level index.

        Child indexes return 0 per Qt flat table model conventions.
        """
        if parent.isValid():
            return 0
        return len(self._processes)

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
                if 0 <= section < len(self._processes):
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

        if row < 0 or row >= len(self._processes):
            return None
        if col < 0 or col >= len(self.COLUMNS):
            return None

        process = self._processes[row]

        if role == int(Qt.ItemDataRole.DisplayRole):
            return self._format_cell_display(process, col)

        if role == int(Qt.ItemDataRole.ToolTipRole):
            cell_text = self._format_cell_display(process, col)
            return cell_text if cell_text != EMPTY_PLACEHOLDER else None

        if role == int(Qt.ItemDataRole.TextAlignmentRole):
            if col in (COLUMN_PID, COLUMN_PPID):
                return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            return int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)

        if role == ProcessStatusRole:
            return STATUS_ACTIVE if process.is_active else STATUS_TERMINATED

        if role in (ProcessRole, int(Qt.ItemDataRole.UserRole)):
            return process

        return None

    # ----------------------------------------------------------------------
    # Collection management and update methods
    # ----------------------------------------------------------------------

    def set_collection(self, collection: ProcessCollection) -> None:
        """Replace model contents with a new ProcessCollection.

        Uses Qt's beginResetModel/endResetModel sequence to notify views.

        Args:
            collection: The new ProcessCollection to display.

        Raises:
            TypeError: If collection is not a ProcessCollection instance.
        """
        if not isinstance(collection, ProcessCollection):
            raise TypeError(
                f"Expected ProcessCollection, got {type(collection).__name__}"
            )

        self.beginResetModel()
        self._collection = collection
        self._processes = list(collection.items)
        self.endResetModel()

    def clear(self) -> None:
        """Clear all process rows and reset pagination metadata."""
        self.beginResetModel()
        self._collection = None
        self._processes = []
        self.endResetModel()

    # ----------------------------------------------------------------------
    # Process and metadata accessors
    # ----------------------------------------------------------------------

    def process_at(self, row: int) -> Process | None:
        """Return the original Process instance at the specified row index.

        Args:
            row: 0-based row index.

        Returns:
            The Process instance, or None if the row index is out of bounds.
        """
        if 0 <= row < len(self._processes):
            return self._processes[row]
        return None

    def get_process(self, row: int) -> Process | None:
        """Alias for process_at(row)."""
        return self.process_at(row)

    @property
    def total_count(self) -> int:
        """Total matching processes count reported by the server."""
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
    def collection(self) -> ProcessCollection | None:
        """Return the current ProcessCollection, or None if empty."""
        return self._collection

    @property
    def processes(self) -> tuple[Process, ...]:
        """Return an immutable snapshot of all processes in the current page."""
        return tuple(self._processes)

    # ----------------------------------------------------------------------
    # Internal cell formatting helper
    # ----------------------------------------------------------------------

    def _format_cell_display(self, process: Process, column: int) -> str:
        """Format a process field into a cell display string.

        Preserves numeric 0 for PID and PPID, and uses EMPTY_PLACEHOLDER for None.
        Never mutates the underlying Process record.
        """
        if column == COLUMN_PID:
            return str(process.pid)

        if column == COLUMN_PPID:
            if process.ppid is not None:
                return str(process.ppid)
            return EMPTY_PLACEHOLDER

        if column == COLUMN_COMMAND:
            if process.command and process.command.strip():
                return process.command
            return EMPTY_PLACEHOLDER

        if column == COLUMN_EXECUTABLE:
            if process.executable is not None and process.executable.strip():
                return process.executable
            return EMPTY_PLACEHOLDER

        if column == COLUMN_LINUX_USER_ID:
            if process.linux_user_id is not None and process.linux_user_id.strip():
                return process.linux_user_id
            return EMPTY_PLACEHOLDER

        if column == COLUMN_STATUS:
            return (
                STATUS_DISPLAY_ACTIVE
                if process.is_active
                else STATUS_DISPLAY_TERMINATED
            )

        if column == COLUMN_STARTED_AT:
            if process.started_at and process.started_at.strip():
                return process.started_at
            return EMPTY_PLACEHOLDER

        if column == COLUMN_ENDED_AT:
            if process.ended_at is not None and process.ended_at.strip():
                return process.ended_at
            return EMPTY_PLACEHOLDER

        return EMPTY_PLACEHOLDER


__all__ = [
    "COLUMNS",
    "COLUMN_COMMAND",
    "COLUMN_ENDED_AT",
    "COLUMN_EXECUTABLE",
    "COLUMN_LINUX_USER_ID",
    "COLUMN_PID",
    "COLUMN_PPID",
    "COLUMN_STARTED_AT",
    "COLUMN_STATUS",
    "EMPTY_PLACEHOLDER",
    "PROCESS_COLUMNS",
    "PROCESS_COLUMN_COMMAND",
    "PROCESS_COLUMN_ENDED_AT",
    "PROCESS_COLUMN_EXECUTABLE",
    "PROCESS_COLUMN_LINUX_USER_ID",
    "PROCESS_COLUMN_PID",
    "PROCESS_COLUMN_PPID",
    "PROCESS_COLUMN_STARTED_AT",
    "PROCESS_COLUMN_STATUS",
    "ProcessRole",
    "ProcessStatusRole",
    "ProcessesTableModel",
    "STATUS_ACTIVE",
    "STATUS_DISPLAY_ACTIVE",
    "STATUS_DISPLAY_TERMINATED",
    "STATUS_TERMINATED",
]
