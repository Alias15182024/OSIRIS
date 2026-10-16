"""OSIRIS native Qt table model for security events.

Provides EventsTableModel, a QAbstractTableModel subclass for presenting
validated security events in a dense, investigator-oriented table.
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

from desktop.client.models import Event, EventCollection

# Ordered, stable column headers for investigator table views
COLUMNS: tuple[str, ...] = (
    "Timestamp",
    "Severity",
    "Source",
    "Event Type",
    "Action",
    "User",
    "PID",
    "Command",
    "Object",
    "Result",
)

COLUMN_TIMESTAMP: int = 0
COLUMN_SEVERITY: int = 1
COLUMN_SOURCE: int = 2
COLUMN_EVENT_TYPE: int = 3
COLUMN_ACTION: int = 4
COLUMN_USER: int = 5
COLUMN_PID: int = 6
COLUMN_COMMAND: int = 7
COLUMN_OBJECT: int = 8
COLUMN_RESULT: int = 9

EMPTY_PLACEHOLDER: str = "—"

# Canonical human-readable severity representations
_SEVERITY_DISPLAY: dict[str, str] = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}

# Custom Qt ItemDataRoles for extended data access and styling
SeverityRole: int = int(Qt.ItemDataRole.UserRole) + 1
EventRole: int = int(Qt.ItemDataRole.UserRole) + 2


class EventsTableModel(QAbstractTableModel):
    """Qt table model representing a collection of OSIRIS security events.

    Accepts an EventCollection and exposes event records through standard
    Qt model/view roles without storing widgets or mutating raw records.
    """

    COLUMNS = COLUMNS

    def __init__(
        self,
        collection: EventCollection | None = None,
        parent: QObject | None = None,
    ) -> None:
        """Initialize EventsTableModel with an optional EventCollection.

        Args:
            collection: Optional initial EventCollection.
            parent: Optional parent QObject.

        Raises:
            TypeError: If collection is provided but not an EventCollection.
        """
        super().__init__(parent)
        self._collection: EventCollection | None = None
        self._events: list[Event] = []

        if collection is not None:
            if not isinstance(collection, EventCollection):
                raise TypeError(
                    f"Expected EventCollection, got {type(collection).__name__}"
                )
            self._collection = collection
            self._events = list(collection.items)

    # ----------------------------------------------------------------------
    # QAbstractTableModel interface implementation
    # ----------------------------------------------------------------------

    @override
    def rowCount(
        self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()
    ) -> int:
        """Return the number of event rows for the top-level index.

        Child indexes return 0 per Qt flat table model conventions.
        """
        if parent.isValid():
            return 0
        return len(self._events)

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
                if 0 <= section < len(self._events):
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

        if row < 0 or row >= len(self._events):
            return None
        if col < 0 or col >= len(self.COLUMNS):
            return None

        event = self._events[row]

        if role == int(Qt.ItemDataRole.DisplayRole):
            return self._format_cell_display(event, col)

        if role == int(Qt.ItemDataRole.ToolTipRole):
            cell_text = self._format_cell_display(event, col)
            return cell_text if cell_text != EMPTY_PLACEHOLDER else None

        if role == int(Qt.ItemDataRole.TextAlignmentRole):
            if col == COLUMN_PID:
                return int(
                    Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
                )
            return int(
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
            )

        if role == SeverityRole:
            return event.severity

        if role in (EventRole, int(Qt.ItemDataRole.UserRole)):
            return event

        return None

    # ----------------------------------------------------------------------
    # Collection management and update methods
    # ----------------------------------------------------------------------

    def set_collection(self, collection: EventCollection) -> None:
        """Replace model contents with a new EventCollection.

        Uses Qt's beginResetModel/endResetModel sequence to notify views.

        Args:
            collection: The new EventCollection to display.

        Raises:
            TypeError: If collection is not an EventCollection instance.
        """
        if not isinstance(collection, EventCollection):
            raise TypeError(
                f"Expected EventCollection, got {type(collection).__name__}"
            )

        self.beginResetModel()
        self._collection = collection
        self._events = list(collection.items)
        self.endResetModel()

    def clear(self) -> None:
        """Clear all event rows and reset pagination metadata."""
        self.beginResetModel()
        self._collection = None
        self._events = []
        self.endResetModel()

    # ----------------------------------------------------------------------
    # Event and metadata accessors
    # ----------------------------------------------------------------------

    def event_at(self, row: int) -> Event | None:
        """Return the original Event instance at the specified row index.

        Args:
            row: 0-based row index.

        Returns:
            The Event instance, or None if the row index is out of bounds.
        """
        if 0 <= row < len(self._events):
            return self._events[row]
        return None

    def get_event(self, row: int) -> Event | None:
        """Alias for event_at(row)."""
        return self.event_at(row)

    @property
    def total_count(self) -> int:
        """Total matching events count reported by the server."""
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
    def collection(self) -> EventCollection | None:
        """Return the current EventCollection, or None if empty."""
        return self._collection

    @property
    def events(self) -> tuple[Event, ...]:
        """Return an immutable snapshot of all events in the current page."""
        return tuple(self._events)

    # ----------------------------------------------------------------------
    # Internal cell formatting helper
    # ----------------------------------------------------------------------

    def _format_cell_display(self, event: Event, column: int) -> str:
        """Format an event field into a cell display string.

        Preserves numeric 0 for PID and uses EMPTY_PLACEHOLDER for None.
        Never mutates the underlying Event record.
        """
        if column == COLUMN_TIMESTAMP:
            return event.timestamp if event.timestamp else EMPTY_PLACEHOLDER

        if column == COLUMN_SEVERITY:
            sev_key = event.severity.strip().lower()
            return _SEVERITY_DISPLAY.get(sev_key, sev_key.title())

        if column == COLUMN_SOURCE:
            return event.source if event.source else EMPTY_PLACEHOLDER

        if column == COLUMN_EVENT_TYPE:
            return event.event_type if event.event_type else EMPTY_PLACEHOLDER

        if column == COLUMN_ACTION:
            return event.action if event.action else EMPTY_PLACEHOLDER

        if column == COLUMN_USER:
            if event.username is not None and event.username.strip():
                return event.username
            return EMPTY_PLACEHOLDER

        if column == COLUMN_PID:
            if event.pid is not None:
                return str(event.pid)
            return EMPTY_PLACEHOLDER

        if column == COLUMN_COMMAND:
            if event.command is not None and event.command.strip():
                return event.command
            return EMPTY_PLACEHOLDER

        if column == COLUMN_OBJECT:
            if event.object_path is not None and event.object_path.strip():
                return event.object_path
            if event.object_type is not None and event.object_type.strip():
                return event.object_type
            return EMPTY_PLACEHOLDER

        if column == COLUMN_RESULT:
            if event.result is not None and event.result.strip():
                return event.result
            return EMPTY_PLACEHOLDER

        return EMPTY_PLACEHOLDER
