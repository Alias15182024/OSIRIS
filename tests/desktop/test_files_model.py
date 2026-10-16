"""Unit tests for OSIRIS FilesTableModel.

Verifies:
1. Construction, structure, row/column counts, and headerData.
2. Qt flat-model child-index conventions (rowCount/columnCount return 0 for parent).
3. Data presentation for all 6 columns: Path, File Type, Inode, First Seen,
   Last Seen, Host ID, and placeholders.
4. Handling of optional/None fields and preservation of inode 0.
5. Safe display of long paths, file types, and UUIDs without modifying records.
6. Qt roles: DisplayRole, ToolTipRole, TextAlignmentRole, FileRole,
   FileRecordRole, FileIdRole.
7. Original FileRecord retrieval via file_at() and get_file().
8. Model reset signals and metadata updates when replacing or clearing collections.
9. Pagination semantics: current page row count vs. server-reported total count.
10. Strict input validation and rejection of invalid collection types with TypeError.
11. Purity: no backend, HTTP, database, or collector dependencies.
"""

from __future__ import annotations

from typing import Any

import pytest
from PySide6.QtCore import QModelIndex, Qt
from PySide6.QtTest import QAbstractItemModelTester
from PySide6.QtWidgets import QApplication

from desktop.client.models import (
    FileCollection,
    FileRecord,
)
from desktop.models import (
    COLUMN_FILE_TYPE,
    COLUMN_FIRST_SEEN,
    COLUMN_FIRST_SEEN_AT,
    COLUMN_HOST_ID,
    COLUMN_INODE,
    COLUMN_LAST_SEEN,
    COLUMN_LAST_SEEN_AT,
    COLUMN_PATH,
    EMPTY_PLACEHOLDER,
    FILE_COLUMN_FILE_TYPE,
    FILE_COLUMN_FIRST_SEEN,
    FILE_COLUMN_FIRST_SEEN_AT,
    FILE_COLUMN_HOST_ID,
    FILE_COLUMN_INODE,
    FILE_COLUMN_LAST_SEEN,
    FILE_COLUMN_LAST_SEEN_AT,
    FILE_COLUMN_PATH,
    FILE_COLUMNS,
    FileIdRole,
    FileRecordRole,
    FileRole,
    FilesTableModel,
)
from desktop.models.files_model import (
    COLUMNS,
)

SAMPLE_FILE_ID_1 = "11111111-1111-4111-8111-111111111111"
SAMPLE_FILE_ID_2 = "22222222-2222-4222-8222-222222222222"
SAMPLE_HOST_ID_1 = "33333333-3333-4333-8333-333333333333"
SAMPLE_HOST_ID_2 = "44444444-4444-4444-8444-444444444444"
SAMPLE_TIME_1 = "2026-03-01T10:00:00Z"
SAMPLE_TIME_2 = "2026-03-01T10:15:00Z"


def _make_sample_file(
    file_id: str = SAMPLE_FILE_ID_1,
    host_id: str = SAMPLE_HOST_ID_1,
    path: str = "/var/log/syslog",
    first_seen_at: str = SAMPLE_TIME_1,
    created_at: str = SAMPLE_TIME_1,
    inode: int | None = 123456,
    file_type: str | None = "file",
    last_seen_at: str | None = SAMPLE_TIME_2,
    **kwargs: Any,
) -> FileRecord:
    """Create a valid FileRecord instance with customizable test parameters."""
    return FileRecord(
        id=file_id,
        host_id=host_id,
        path=path,
        first_seen_at=first_seen_at,
        created_at=created_at,
        inode=inode,
        file_type=file_type,
        last_seen_at=last_seen_at,
    )


def _make_sample_collection(
    items: list[FileRecord] | tuple[FileRecord, ...] | None = None,
    total: int | None = None,
    limit: int = 50,
    offset: int = 0,
) -> FileCollection:
    """Create a valid FileCollection instance for model tests."""
    if items is None:
        items = (_make_sample_file(),)
    items_tuple = tuple(items)
    return FileCollection(
        total=len(items_tuple) if total is None else total,
        items=items_tuple,
        limit=limit,
        offset=offset,
    )


@pytest.fixture(scope="session")
def qapp() -> Any:
    """Provide a headless QApplication session fixture."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


# ==============================================================================
# 1. Construction, Dimensions, and Headers
# ==============================================================================


class TestFilesTableModelStructure:
    """Verify table model initialization, dimensions, and header data."""

    def test_default_construction_is_empty(self, qapp: QApplication) -> None:
        """Model constructed with no arguments has 0 rows and 6 columns."""
        model = FilesTableModel()
        assert model.rowCount() == 0
        assert model.columnCount() == 6
        assert model.total_count == 0
        assert model.total == 0
        assert model.limit == 50
        assert model.offset == 0
        assert model.collection is None
        assert model.files == ()

    def test_construction_with_collection(self, qapp: QApplication) -> None:
        """Model initialized with collection exposes its items and metadata."""
        f1 = _make_sample_file(file_id=SAMPLE_FILE_ID_1)
        f2 = _make_sample_file(file_id=SAMPLE_FILE_ID_2)
        col = _make_sample_collection(items=(f1, f2), total=10, limit=25, offset=5)

        model = FilesTableModel(collection=col)
        assert model.rowCount() == 2
        assert model.columnCount() == 6
        assert model.total_count == 10
        assert model.total == 10
        assert model.limit == 25
        assert model.offset == 5
        assert model.collection is col
        assert len(model.files) == 2
        assert model.files[0] == f1
        assert model.files[1] == f2

    def test_columns_constant_exact_order(self) -> None:
        """Column names match the expected order and count."""
        expected = (
            "Path",
            "File Type",
            "Inode",
            "First Seen",
            "Last Seen",
            "Host ID",
        )
        assert COLUMNS == expected
        assert FILE_COLUMNS == expected
        assert FilesTableModel.COLUMNS == expected
        assert FilesTableModel.FILE_COLUMNS == expected

    def test_column_indexes_constants(self) -> None:
        """Column integer indexes match expected values."""
        assert COLUMN_PATH == 0
        assert COLUMN_FILE_TYPE == 1
        assert COLUMN_INODE == 2
        assert COLUMN_FIRST_SEEN == 3
        assert COLUMN_LAST_SEEN == 4
        assert COLUMN_HOST_ID == 5

        assert FILE_COLUMN_PATH == 0
        assert FILE_COLUMN_FILE_TYPE == 1
        assert FILE_COLUMN_INODE == 2
        assert FILE_COLUMN_FIRST_SEEN == 3
        assert FILE_COLUMN_LAST_SEEN == 4
        assert FILE_COLUMN_HOST_ID == 5

        assert COLUMN_FIRST_SEEN_AT == 3
        assert COLUMN_LAST_SEEN_AT == 4
        assert FILE_COLUMN_FIRST_SEEN_AT == 3
        assert FILE_COLUMN_LAST_SEEN_AT == 4

    def test_horizontal_header_data(self, qapp: QApplication) -> None:
        """Horizontal header returns exact column names for DisplayRole."""
        model = FilesTableModel()
        for col_idx, expected_name in enumerate(COLUMNS):
            header = model.headerData(
                col_idx,
                Qt.Orientation.Horizontal,
                int(Qt.ItemDataRole.DisplayRole),
            )
            assert header == expected_name

    def test_horizontal_header_out_of_bounds(self, qapp: QApplication) -> None:
        """Out-of-bounds sections return None."""
        model = FilesTableModel()
        assert (
            model.headerData(
                -1,
                Qt.Orientation.Horizontal,
                int(Qt.ItemDataRole.DisplayRole),
            )
            is None
        )
        assert (
            model.headerData(
                6,
                Qt.Orientation.Horizontal,
                int(Qt.ItemDataRole.DisplayRole),
            )
            is None
        )

    def test_vertical_header_data(self, qapp: QApplication) -> None:
        """Vertical header returns 1-based row numbers for DisplayRole."""
        f1 = _make_sample_file()
        f2 = _make_sample_file(file_id=SAMPLE_FILE_ID_2)
        model = FilesTableModel(_make_sample_collection((f1, f2)))

        role = int(Qt.ItemDataRole.DisplayRole)
        assert model.headerData(0, Qt.Orientation.Vertical, role) == "1"
        assert model.headerData(1, Qt.Orientation.Vertical, role) == "2"
        assert model.headerData(2, Qt.Orientation.Vertical, role) is None

    def test_flat_model_parent_index_conventions(self, qapp: QApplication) -> None:
        """rowCount and columnCount return 0 for valid parent indexes."""
        model = FilesTableModel(_make_sample_collection())
        valid_parent = model.index(0, 0)
        assert model.rowCount(valid_parent) == 0
        assert model.columnCount(valid_parent) == 0


# ==============================================================================
# 2. Data Presentation and Formatting
# ==============================================================================


class TestFilesTableModelData:
    """Verify cell formatting, placeholders, and null value handling."""

    def test_all_columns_display_full_record(self, qapp: QApplication) -> None:
        """Fully populated record displays all fields verbatim."""
        rec = _make_sample_file(
            path="/usr/local/bin/agent",
            file_type="file",
            inode=987654,
            first_seen_at="2026-03-01T12:00:00Z",
            last_seen_at="2026-03-01T12:30:00Z",
            host_id=SAMPLE_HOST_ID_1,
        )
        model = FilesTableModel(_make_sample_collection((rec,)))

        assert model.data(model.index(0, COLUMN_PATH)) == "/usr/local/bin/agent"
        assert model.data(model.index(0, COLUMN_FILE_TYPE)) == "file"
        assert model.data(model.index(0, COLUMN_INODE)) == "987654"
        assert model.data(model.index(0, COLUMN_FIRST_SEEN)) == "2026-03-01T12:00:00Z"
        assert model.data(model.index(0, COLUMN_LAST_SEEN)) == "2026-03-01T12:30:00Z"
        assert model.data(model.index(0, COLUMN_HOST_ID)) == SAMPLE_HOST_ID_1

    def test_nullable_fields_display_em_dash(self, qapp: QApplication) -> None:
        """Optional/None fields (inode, file_type, last_seen_at) show em dash."""
        rec = _make_sample_file(
            inode=None,
            file_type=None,
            last_seen_at=None,
        )
        model = FilesTableModel(_make_sample_collection((rec,)))

        assert model.data(model.index(0, COLUMN_INODE)) == EMPTY_PLACEHOLDER
        assert model.data(model.index(0, COLUMN_FILE_TYPE)) == EMPTY_PLACEHOLDER
        assert model.data(model.index(0, COLUMN_LAST_SEEN)) == EMPTY_PLACEHOLDER

    def test_inode_zero_preserved_and_not_placeholder(
        self, qapp: QApplication
    ) -> None:
        """Inode equal to 0 is preserved as '0' and not treated as missing."""
        rec = _make_sample_file(inode=0)
        model = FilesTableModel(_make_sample_collection((rec,)))

        assert model.data(model.index(0, COLUMN_INODE)) == "0"
        assert model.data(model.index(0, COLUMN_INODE)) != EMPTY_PLACEHOLDER

    def test_long_paths_and_ids_preserved(self, qapp: QApplication) -> None:
        """Long directory paths and UUIDs are not truncated by the model."""
        long_path = "/var/lib/docker/overlay2/" + ("a" * 64) + "/diff/usr/bin/python"
        rec = _make_sample_file(path=long_path, host_id=SAMPLE_HOST_ID_2)
        model = FilesTableModel(_make_sample_collection((rec,)))

        assert model.data(model.index(0, COLUMN_PATH)) == long_path
        assert model.data(model.index(0, COLUMN_HOST_ID)) == SAMPLE_HOST_ID_2


# ==============================================================================
# 3. Qt Roles (Display, ToolTip, Alignment, Custom FileRole, FileIdRole)
# ==============================================================================


class TestFilesTableModelRoles:
    """Verify standard and custom item data roles."""

    def test_tooltip_role_returns_cell_text(self, qapp: QApplication) -> None:
        """ToolTipRole returns cell text when populated, and None for placeholder."""
        rec = _make_sample_file(
            path="/etc/passwd",
            inode=None,
        )
        model = FilesTableModel(_make_sample_collection((rec,)))

        # Populated cell gives text as tooltip
        tip_role = int(Qt.ItemDataRole.ToolTipRole)
        path_tip = model.data(model.index(0, COLUMN_PATH), tip_role)
        assert path_tip == "/etc/passwd"

        # Placeholder cell gives None as tooltip
        inode_tip = model.data(
            model.index(0, COLUMN_INODE), int(Qt.ItemDataRole.ToolTipRole)
        )
        assert inode_tip is None

    def test_text_alignment_role(self, qapp: QApplication) -> None:
        """Inode is right-aligned; all other columns are left-aligned."""
        rec = _make_sample_file(inode=42)
        model = FilesTableModel(_make_sample_collection((rec,)))

        # Inode right-aligned
        inode_align = model.data(
            model.index(0, COLUMN_INODE), int(Qt.ItemDataRole.TextAlignmentRole)
        )
        expected_right = int(
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        )
        assert inode_align == expected_right

        # Other columns left-aligned
        for col in (
            COLUMN_PATH,
            COLUMN_FILE_TYPE,
            COLUMN_FIRST_SEEN,
            COLUMN_LAST_SEEN,
            COLUMN_HOST_ID,
        ):
            align = model.data(
                model.index(0, col), int(Qt.ItemDataRole.TextAlignmentRole)
            )
            expected_left = int(
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
            )
            assert align == expected_left, f"Column {col} alignment mismatch"

    def test_custom_file_role_returns_original_record(
        self, qapp: QApplication
    ) -> None:
        """FileRole and FileRecordRole return the exact immutable FileRecord."""
        rec = _make_sample_file()
        model = FilesTableModel(_make_sample_collection((rec,)))

        role_record = model.data(model.index(0, 0), FileRole)
        assert role_record is rec

        alias_record = model.data(model.index(0, 0), FileRecordRole)
        assert alias_record is rec

        user_record = model.data(model.index(0, 0), int(Qt.ItemDataRole.UserRole))
        assert user_record is rec

    def test_custom_file_id_role(self, qapp: QApplication) -> None:
        """FileIdRole returns the UUID string of the file record."""
        rec = _make_sample_file(file_id=SAMPLE_FILE_ID_1)
        model = FilesTableModel(_make_sample_collection((rec,)))

        file_id = model.data(model.index(0, 0), FileIdRole)
        assert file_id == SAMPLE_FILE_ID_1

    def test_invalid_index_and_unsupported_roles(self, qapp: QApplication) -> None:
        """Invalid index or unsupported roles return None safely."""
        model = FilesTableModel(_make_sample_collection())

        # Invalid indexes
        assert model.data(QModelIndex()) is None
        assert model.data(model.index(-1, 0)) is None
        assert model.data(model.index(0, -1)) is None
        assert model.data(model.index(100, 0)) is None
        assert model.data(model.index(0, 100)) is None

        # Unsupported roles
        assert model.data(model.index(0, 0), int(Qt.ItemDataRole.EditRole)) is None
        assert model.data(model.index(0, 0), 99999) is None


# ==============================================================================
# 4. Accessors & Collection Ordering
# ==============================================================================


class TestFilesTableModelAccessors:
    """Verify public accessors and preservation of backend collection order."""

    def test_file_at_and_aliases(self, qapp: QApplication) -> None:
        """file_at(), get_file(), file_record_at() return correct FileRecord."""
        f1 = _make_sample_file(file_id=SAMPLE_FILE_ID_1)
        f2 = _make_sample_file(file_id=SAMPLE_FILE_ID_2)
        model = FilesTableModel(_make_sample_collection((f1, f2)))

        assert model.file_at(0) is f1
        assert model.file_at(1) is f2
        assert model.file_at(-1) is None
        assert model.file_at(2) is None

        # Aliases
        assert model.get_file(0) is f1
        assert model.file_record_at(0) is f1
        assert model.get_file_record(0) is f1

    def test_backend_order_strictly_preserved(self, qapp: QApplication) -> None:
        """Collection order is preserved exactly as received from backend."""
        # Intentionally non-alphabetical and mixed timestamps
        f_b = _make_sample_file(path="/b", first_seen_at="2026-03-01T12:00:00Z")
        f_a = _make_sample_file(path="/a", first_seen_at="2026-03-01T08:00:00Z")
        f_c = _make_sample_file(path="/c", first_seen_at="2026-03-01T10:00:00Z")

        model = FilesTableModel(_make_sample_collection((f_b, f_a, f_c)))
        assert model.rowCount() == 3
        assert model.data(model.index(0, COLUMN_PATH)) == "/b"
        assert model.data(model.index(1, COLUMN_PATH)) == "/a"
        assert model.data(model.index(2, COLUMN_PATH)) == "/c"
        assert model.file_at(0) is f_b
        assert model.file_at(1) is f_a
        assert model.file_at(2) is f_c


# ==============================================================================
# 5. Lifecycle, Set Collection, Clear & Model Reset Signals
# ==============================================================================


class TestFilesTableModelLifecycle:
    """Verify collection replacement, clearing, and reset signals."""

    def test_set_collection_emits_model_reset(self, qapp: QApplication) -> None:
        """set_collection emits beginResetModel and endResetModel signals."""
        model = FilesTableModel()

        about_to_reset_emitted = False
        reset_emitted = False

        def on_about_to_reset() -> None:
            nonlocal about_to_reset_emitted
            about_to_reset_emitted = True

        def on_reset() -> None:
            nonlocal reset_emitted
            reset_emitted = True

        model.modelAboutToBeReset.connect(on_about_to_reset)
        model.modelReset.connect(on_reset)

        f1 = _make_sample_file()
        col = _make_sample_collection((f1,), total=42, limit=10, offset=20)
        model.set_collection(col)

        assert about_to_reset_emitted is True
        assert reset_emitted is True
        assert model.rowCount() == 1
        assert model.total_count == 42
        assert model.limit == 10
        assert model.offset == 20
        assert model.collection is col

    def test_clear_emits_model_reset_and_clears_data(
        self, qapp: QApplication
    ) -> None:
        """clear() emits modelReset, clears rows and resets metadata."""
        f1 = _make_sample_file()
        model = FilesTableModel(_make_sample_collection((f1,), total=5))
        assert model.rowCount() == 1
        assert model.total_count == 5

        about_to_reset_emitted = False
        reset_emitted = False

        def on_about() -> None:
            nonlocal about_to_reset_emitted
            about_to_reset_emitted = True

        def on_reset() -> None:
            nonlocal reset_emitted
            reset_emitted = True

        model.modelAboutToBeReset.connect(on_about)
        model.modelReset.connect(on_reset)

        model.clear()

        assert about_to_reset_emitted is True
        assert reset_emitted is True
        assert model.rowCount() == 0
        assert model.total_count == 0
        assert model.collection is None
        assert model.files == ()

    def test_reject_invalid_collection_types(self, qapp: QApplication) -> None:
        """Rejects non-FileCollection arguments with TypeError."""
        model = FilesTableModel()

        # Constructor validation
        with pytest.raises(TypeError, match="Expected FileCollection"):
            FilesTableModel(collection=["not", "a", "collection"])  # type: ignore[arg-type]

        with pytest.raises(TypeError, match="Expected FileCollection"):
            FilesTableModel(collection=123)  # type: ignore[arg-type]

        # set_collection validation
        with pytest.raises(TypeError, match="Expected FileCollection"):
            model.set_collection(["invalid"])  # type: ignore[arg-type]

        with pytest.raises(TypeError, match="Expected FileCollection"):
            model.set_collection(None)  # type: ignore[arg-type]


# ==============================================================================
# 6. QAbstractItemModelTester Compliance
# ==============================================================================


class TestFilesTableModelTesterCompliance:
    """Verify model compliance with Qt architecture using QAbstractItemModelTester."""

    def test_model_tester_empty(self, qapp: QApplication) -> None:
        """Empty model passes all Qt model-tester invariants."""
        model = FilesTableModel()
        tester = QAbstractItemModelTester(model)
        assert tester is not None

    def test_model_tester_populated(self, qapp: QApplication) -> None:
        """Populated model passes all Qt model-tester invariants."""
        f1 = _make_sample_file(file_id=SAMPLE_FILE_ID_1)
        f2 = _make_sample_file(file_id=SAMPLE_FILE_ID_2)
        model = FilesTableModel(_make_sample_collection((f1, f2)))
        tester = QAbstractItemModelTester(model)
        assert tester is not None

    def test_model_tester_during_updates(self, qapp: QApplication) -> None:
        """Model transitions pass model-tester invariants when reset."""
        model = FilesTableModel()
        tester = QAbstractItemModelTester(model)
        assert tester is not None

        col = _make_sample_collection()
        model.set_collection(col)
        assert model.rowCount() == 1

        model.clear()
        assert model.rowCount() == 0


# ==============================================================================
# 7. Non-Regression with Neighboring Table Models
# ==============================================================================


class TestFilesTableModelNonRegression:
    """Verify that Events, Processes, and Resources models remain unaffected."""

    def test_neighboring_models_remain_functional(self, qapp: QApplication) -> None:
        """Events, Processes, and Resources models instantiate and work normally."""
        from desktop.models import (
            EventsTableModel,
            ProcessesTableModel,
            ResourcesTableModel,
        )

        events_model = EventsTableModel()
        assert events_model.rowCount() == 0
        assert events_model.columnCount() == 10

        processes_model = ProcessesTableModel()
        assert processes_model.rowCount() == 0
        assert processes_model.columnCount() == 8

        resources_model = ResourcesTableModel()
        assert resources_model.rowCount() == 0
        assert resources_model.columnCount() == 8

    def test_files_model_properties_and_cell_formatting_fallbacks(
        self, qapp: QApplication
    ) -> None:
        """FilesTableModel handles aliases, out-of-range bounds, and empty fields."""
        from desktop.models.files_model import (
            COLUMN_FIRST_SEEN,
            COLUMN_HOST_ID,
            COLUMN_PATH,
            EMPTY_PLACEHOLDER,
        )

        record = _make_sample_file(
            file_id=SAMPLE_FILE_ID_1,
            host_id="",
            path="  ",
            first_seen_at="",
        )
        col = _make_sample_collection((record,), total=1)
        model = FilesTableModel(col)

        # Aliases
        assert len(model.file_records) == 1
        assert len(model.items) == 1
        assert model.file_records == model.files

        # Out-of-bounds row and col
        assert model.data(model.createIndex(-1, 0)) is None
        assert model.data(model.createIndex(5, 0)) is None
        assert model.data(model.createIndex(0, -1)) is None
        assert model.data(model.createIndex(0, 99)) is None

        # Empty field fallbacks
        assert model._format_cell_display(record, COLUMN_PATH) == EMPTY_PLACEHOLDER
        assert (
            model._format_cell_display(record, COLUMN_FIRST_SEEN)
            == EMPTY_PLACEHOLDER
        )
        assert (
            model._format_cell_display(record, COLUMN_HOST_ID)
            == EMPTY_PLACEHOLDER
        )
        assert model._format_cell_display(record, 99) == EMPTY_PLACEHOLDER

