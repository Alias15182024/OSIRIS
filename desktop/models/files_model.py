"""OSIRIS native Qt table model for observed files.

Provides FilesTableModel, a QAbstractTableModel subclass for presenting
validated FileRecord instances in a dense, investigator-oriented table.
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

from desktop.client.models import FileCollection, FileRecord

# Ordered, stable column headers for investigator table views
COLUMNS: tuple[str, ...] = (
    "Path",
    "File Type",
    "Inode",
    "First Seen",
    "Last Seen",
    "Host ID",
)

FILE_COLUMNS: tuple[str, ...] = COLUMNS

COLUMN_PATH: int = 0
COLUMN_FILE_TYPE: int = 1
COLUMN_INODE: int = 2
COLUMN_FIRST_SEEN: int = 3
COLUMN_LAST_SEEN: int = 4
COLUMN_HOST_ID: int = 5

COLUMN_FIRST_SEEN_AT: int = COLUMN_FIRST_SEEN
COLUMN_LAST_SEEN_AT: int = COLUMN_LAST_SEEN

FILE_COLUMN_PATH: int = COLUMN_PATH
FILE_COLUMN_FILE_TYPE: int = COLUMN_FILE_TYPE
FILE_COLUMN_INODE: int = COLUMN_INODE
FILE_COLUMN_FIRST_SEEN: int = COLUMN_FIRST_SEEN
FILE_COLUMN_LAST_SEEN: int = COLUMN_LAST_SEEN
FILE_COLUMN_HOST_ID: int = COLUMN_HOST_ID
FILE_COLUMN_FIRST_SEEN_AT: int = COLUMN_FIRST_SEEN
FILE_COLUMN_LAST_SEEN_AT: int = COLUMN_LAST_SEEN

EMPTY_PLACEHOLDER: str = "—"

# Custom Qt ItemDataRoles for extended data access and styling
FileRole: int = int(Qt.ItemDataRole.UserRole) + 1
FileRecordRole: int = FileRole
FileIdRole: int = int(Qt.ItemDataRole.UserRole) + 2


class FilesTableModel(QAbstractTableModel):
    """Qt table model representing a collection of OSIRIS file records.

    Accepts a FileCollection and exposes file records through standard
    Qt model/view roles without storing widgets or mutating raw records.
    """

    COLUMNS = COLUMNS
    FILE_COLUMNS = FILE_COLUMNS

    COLUMN_PATH = COLUMN_PATH
    COLUMN_FILE_TYPE = COLUMN_FILE_TYPE
    COLUMN_INODE = COLUMN_INODE
    COLUMN_FIRST_SEEN = COLUMN_FIRST_SEEN
    COLUMN_LAST_SEEN = COLUMN_LAST_SEEN
    COLUMN_HOST_ID = COLUMN_HOST_ID
    COLUMN_FIRST_SEEN_AT = COLUMN_FIRST_SEEN_AT
    COLUMN_LAST_SEEN_AT = COLUMN_LAST_SEEN_AT

    FILE_COLUMN_PATH = FILE_COLUMN_PATH
    FILE_COLUMN_FILE_TYPE = FILE_COLUMN_FILE_TYPE
    FILE_COLUMN_INODE = FILE_COLUMN_INODE
    FILE_COLUMN_FIRST_SEEN = FILE_COLUMN_FIRST_SEEN
    FILE_COLUMN_LAST_SEEN = FILE_COLUMN_LAST_SEEN
    FILE_COLUMN_HOST_ID = FILE_COLUMN_HOST_ID
    FILE_COLUMN_FIRST_SEEN_AT = FILE_COLUMN_FIRST_SEEN_AT
    FILE_COLUMN_LAST_SEEN_AT = FILE_COLUMN_LAST_SEEN_AT

    def __init__(
        self,
        collection: FileCollection | None = None,
        parent: QObject | None = None,
    ) -> None:
        """Initialize FilesTableModel with an optional FileCollection.

        Args:
            collection: Optional initial FileCollection.
            parent: Optional parent QObject.

        Raises:
            TypeError: If collection is provided but not a FileCollection.
        """
        super().__init__(parent)
        self._collection: FileCollection | None = None
        self._files: list[FileRecord] = []

        if collection is not None:
            if not isinstance(collection, FileCollection):
                raise TypeError(
                    f"Expected FileCollection, got {type(collection).__name__}"
                )
            self._collection = collection
            self._files = list(collection.items)

    # ----------------------------------------------------------------------
    # QAbstractTableModel interface implementation
    # ----------------------------------------------------------------------

    @override
    def rowCount(
        self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()
    ) -> int:
        """Return the number of file rows for the top-level index.

        Child indexes return 0 per Qt flat table model conventions.
        """
        if parent.isValid():
            return 0
        return len(self._files)

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
                if 0 <= section < len(self._files):
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

        if row < 0 or row >= len(self._files):
            return None
        if col < 0 or col >= len(self.COLUMNS):
            return None

        file_record = self._files[row]

        if role == int(Qt.ItemDataRole.DisplayRole):
            return self._format_cell_display(file_record, col)

        if role == int(Qt.ItemDataRole.ToolTipRole):
            cell_text = self._format_cell_display(file_record, col)
            return cell_text if cell_text != EMPTY_PLACEHOLDER else None

        if role == int(Qt.ItemDataRole.TextAlignmentRole):
            if col == COLUMN_INODE:
                return int(
                    Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
                )
            return int(
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
            )

        if role in (FileRole, FileRecordRole, int(Qt.ItemDataRole.UserRole)):
            return file_record

        if role == FileIdRole:
            return file_record.id

        return None

    # ----------------------------------------------------------------------
    # Collection management and update methods
    # ----------------------------------------------------------------------

    def set_collection(self, collection: FileCollection) -> None:
        """Replace model contents with a new FileCollection.

        Uses Qt's beginResetModel/endResetModel sequence to notify views.

        Args:
            collection: The new FileCollection to display.

        Raises:
            TypeError: If collection is not a FileCollection instance.
        """
        if not isinstance(collection, FileCollection):
            raise TypeError(
                f"Expected FileCollection, got {type(collection).__name__}"
            )

        self.beginResetModel()
        self._collection = collection
        self._files = list(collection.items)
        self.endResetModel()

    def clear(self) -> None:
        """Clear all file rows and reset pagination metadata."""
        self.beginResetModel()
        self._collection = None
        self._files = []
        self.endResetModel()

    # ----------------------------------------------------------------------
    # File record and metadata accessors
    # ----------------------------------------------------------------------

    def file_at(self, row: int) -> FileRecord | None:
        """Return the original FileRecord instance at the specified row index.

        Args:
            row: 0-based row index.

        Returns:
            The FileRecord instance, or None if the row index is out of bounds.
        """
        if 0 <= row < len(self._files):
            return self._files[row]
        return None

    def get_file(self, row: int) -> FileRecord | None:
        """Alias for file_at(row)."""
        return self.file_at(row)

    def file_record_at(self, row: int) -> FileRecord | None:
        """Alias for file_at(row)."""
        return self.file_at(row)

    def get_file_record(self, row: int) -> FileRecord | None:
        """Alias for file_at(row)."""
        return self.file_at(row)

    @property
    def total_count(self) -> int:
        """Total matching files count reported by the server."""
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
    def collection(self) -> FileCollection | None:
        """Return the current FileCollection, or None if empty."""
        return self._collection

    @property
    def files(self) -> tuple[FileRecord, ...]:
        """Return an immutable snapshot of all files in current page."""
        return tuple(self._files)

    @property
    def file_records(self) -> tuple[FileRecord, ...]:
        """Alias for files."""
        return self.files

    @property
    def items(self) -> tuple[FileRecord, ...]:
        """Alias for files."""
        return self.files

    # ----------------------------------------------------------------------
    # Internal cell formatting helper
    # ----------------------------------------------------------------------

    def _format_cell_display(self, file_record: FileRecord, column: int) -> str:
        """Format a file record field into a cell display string.

        Preserves numeric 0 for inode, and uses EMPTY_PLACEHOLDER for None.
        Never mutates the underlying FileRecord record.
        """
        if column == COLUMN_PATH:
            if file_record.path and file_record.path.strip():
                return file_record.path
            return EMPTY_PLACEHOLDER

        if column == COLUMN_FILE_TYPE:
            if file_record.file_type and file_record.file_type.strip():
                return file_record.file_type
            return EMPTY_PLACEHOLDER

        if column == COLUMN_INODE:
            if file_record.inode is not None:
                return str(file_record.inode)
            return EMPTY_PLACEHOLDER

        if column == COLUMN_FIRST_SEEN:
            if file_record.first_seen_at and file_record.first_seen_at.strip():
                return file_record.first_seen_at
            return EMPTY_PLACEHOLDER

        if column == COLUMN_LAST_SEEN:
            if (
                file_record.last_seen_at is not None
                and file_record.last_seen_at.strip()
            ):
                return file_record.last_seen_at
            return EMPTY_PLACEHOLDER

        if column == COLUMN_HOST_ID:
            if file_record.host_id and file_record.host_id.strip():
                return file_record.host_id
            return EMPTY_PLACEHOLDER

        return EMPTY_PLACEHOLDER


__all__ = [
    "COLUMN_FILE_TYPE",
    "COLUMN_FIRST_SEEN",
    "COLUMN_FIRST_SEEN_AT",
    "COLUMN_HOST_ID",
    "COLUMN_INODE",
    "COLUMN_LAST_SEEN",
    "COLUMN_LAST_SEEN_AT",
    "COLUMN_PATH",
    "COLUMNS",
    "EMPTY_PLACEHOLDER",
    "FILE_COLUMN_FILE_TYPE",
    "FILE_COLUMN_FIRST_SEEN",
    "FILE_COLUMN_FIRST_SEEN_AT",
    "FILE_COLUMN_HOST_ID",
    "FILE_COLUMN_INODE",
    "FILE_COLUMN_LAST_SEEN",
    "FILE_COLUMN_LAST_SEEN_AT",
    "FILE_COLUMN_PATH",
    "FILE_COLUMNS",
    "FileIdRole",
    "FileRecordRole",
    "FileRole",
    "FilesTableModel",
]
