"""Unit tests for OSIRIS ResourcesTableModel.

Verifies:
1. Construction, structure, row/column counts, and headerData.
2. Qt flat-model child-index conventions (rowCount/columnCount return 0 for parent).
3. Data presentation for all 8 columns, percentages, byte units, and placeholders.
4. Handling of optional/None fields and preservation of numeric 0 and 0.0 values.
5. Display of ISO timestamps without altering timezones.
6. Qt roles: DisplayRole, ToolTipRole, TextAlignmentRole, ResourceSnapshotRole,
   and UserRole.
7. Original ResourceSnapshot retrieval via snapshot_at(), get_snapshot(), and
   resource_at().
8. Model reset signals and metadata updates when replacing or clearing collections.
9. Pagination semantics: current page row count vs. server-reported total count.
10. Strict input validation and rejection of invalid collection types with TypeError.
11. Purity: no backend, HTTP, database, or collector dependencies.
12. Compliance with QAbstractItemModelTester.
"""

from __future__ import annotations

from typing import Any

import pytest
from PySide6.QtCore import QModelIndex, Qt
from PySide6.QtTest import QAbstractItemModelTester
from PySide6.QtWidgets import QApplication

from desktop.client.models import (
    Event,
    EventCollection,
    Process,
    ProcessCollection,
    ResourceSnapshot,
    ResourceSnapshotCollection,
)
from desktop.models import (
    COLUMN_CPU_PERCENT,
    COLUMN_DISK_READ,
    COLUMN_DISK_USAGE_PERCENT,
    COLUMN_DISK_WRITE,
    COLUMN_MEMORY_PERCENT,
    COLUMN_MEMORY_TOTAL,
    COLUMN_MEMORY_USED,
    COLUMN_TIMESTAMP,
    EMPTY_PLACEHOLDER,
    RESOURCE_COLUMN_CPU_PERCENT,
    RESOURCE_COLUMN_DISK_READ,
    RESOURCE_COLUMN_DISK_USAGE_PERCENT,
    RESOURCE_COLUMN_DISK_WRITE,
    RESOURCE_COLUMN_MEMORY_PERCENT,
    RESOURCE_COLUMN_MEMORY_TOTAL,
    RESOURCE_COLUMN_MEMORY_USED,
    RESOURCE_COLUMN_TIMESTAMP,
    RESOURCE_COLUMNS,
    ResourceRole,
    ResourceSnapshotRole,
    ResourcesTableModel,
    format_bytes,
    format_percent,
)
from desktop.models.resources_model import (
    ResourcesTableModel as DirectResourcesTableModel,
)

SAMPLE_SNAPSHOT_ID_1 = "11111111-1111-4111-8111-111111111111"
SAMPLE_SNAPSHOT_ID_2 = "22222222-2222-4222-8222-222222222222"
SAMPLE_SNAPSHOT_ID_3 = "33333333-3333-4333-8333-333333333333"
SAMPLE_HOST_ID = "44444444-4444-4444-8444-444444444444"
SAMPLE_TIME_1 = "2026-03-01T08:00:00Z"
SAMPLE_TIME_2 = "2026-03-01T08:05:00Z"
SAMPLE_TIME_3 = "2026-03-01T08:10:00Z"


def _make_sample_snapshot(
    snapshot_id: str = SAMPLE_SNAPSHOT_ID_1,
    host_id: str = SAMPLE_HOST_ID,
    timestamp: str = SAMPLE_TIME_1,
    created_at: str = SAMPLE_TIME_1,
    cpu_percent: float | None = 15.2,
    memory_total: int | None = 16_000_000_000,
    memory_used: int | None = 4_000_000_000,
    memory_percent: float | None = 25.0,
    disk_read_bytes: int | None = 1048576,
    disk_write_bytes: int | None = 2097152,
    disk_usage_percent: float | None = 45.5,
    **kwargs: Any,
) -> ResourceSnapshot:
    """Create a valid ResourceSnapshot instance with customizable parameters."""
    return ResourceSnapshot(
        id=snapshot_id,
        host_id=host_id,
        timestamp=timestamp,
        created_at=created_at,
        cpu_percent=cpu_percent,
        memory_total=memory_total,
        memory_used=memory_used,
        memory_percent=memory_percent,
        disk_read_bytes=disk_read_bytes,
        disk_write_bytes=disk_write_bytes,
        disk_usage_percent=disk_usage_percent,
    )


def _make_sample_collection(
    items: tuple[ResourceSnapshot, ...] = (),
    total: int = 0,
    limit: int = 50,
    offset: int = 0,
) -> ResourceSnapshotCollection:
    """Create a valid ResourceSnapshotCollection instance."""
    return ResourceSnapshotCollection(
        total=total if total >= len(items) else len(items),
        items=items,
        limit=limit,
        offset=offset,
    )


# ==============================================================================
# Public API and Structural Tests
# ==============================================================================


def test_public_export_matches_direct_import() -> None:
    """desktop.models exports ResourcesTableModel identical to direct module."""
    assert ResourcesTableModel is DirectResourcesTableModel


def test_initial_empty_model_structure(qapp: QApplication) -> None:
    """ResourcesTableModel starts empty with 0 rows and 8 expected columns."""
    model = ResourcesTableModel()
    assert model.rowCount() == 0
    assert model.columnCount() == len(RESOURCE_COLUMNS)
    assert model.columnCount() == 8
    assert model.total_count == 0
    assert model.total == 0
    assert model.limit == 50
    assert model.offset == 0
    assert model.collection is None
    assert model.snapshots == ()
    assert model.resources == ()


def test_ordered_column_headers(qapp: QApplication) -> None:
    """Horizontal headerData returns stable ordered human-readable names."""
    model = ResourcesTableModel()
    expected_headers = [
        "Timestamp",
        "CPU %",
        "Memory %",
        "Memory Used",
        "Memory Total",
        "Disk Read",
        "Disk Write",
        "Disk Usage %",
    ]
    for col_idx, expected_title in enumerate(expected_headers):
        assert model.headerData(
            col_idx, Qt.Orientation.Horizontal, int(Qt.ItemDataRole.DisplayRole)
        ) == expected_title

    assert list(RESOURCE_COLUMNS) == expected_headers
    assert list(model.COLUMNS) == expected_headers
    assert list(model.RESOURCE_COLUMNS) == expected_headers


def test_column_constants_match_indices() -> None:
    """Verify column index constants match expected column positions."""
    assert COLUMN_TIMESTAMP == 0
    assert COLUMN_CPU_PERCENT == 1
    assert COLUMN_MEMORY_PERCENT == 2
    assert COLUMN_MEMORY_USED == 3
    assert COLUMN_MEMORY_TOTAL == 4
    assert COLUMN_DISK_READ == 5
    assert COLUMN_DISK_WRITE == 6
    assert COLUMN_DISK_USAGE_PERCENT == 7

    assert RESOURCE_COLUMN_TIMESTAMP == 0
    assert RESOURCE_COLUMN_CPU_PERCENT == 1
    assert RESOURCE_COLUMN_MEMORY_PERCENT == 2
    assert RESOURCE_COLUMN_MEMORY_USED == 3
    assert RESOURCE_COLUMN_MEMORY_TOTAL == 4
    assert RESOURCE_COLUMN_DISK_READ == 5
    assert RESOURCE_COLUMN_DISK_WRITE == 6
    assert RESOURCE_COLUMN_DISK_USAGE_PERCENT == 7

    assert ResourcesTableModel.COLUMN_TIMESTAMP == 0
    assert ResourcesTableModel.RESOURCE_COLUMN_TIMESTAMP == 0
    assert ResourcesTableModel.COLUMN_CPU_PERCENT == 1
    assert ResourcesTableModel.RESOURCE_COLUMN_CPU_PERCENT == 1
    assert ResourcesTableModel.COLUMN_MEMORY_PERCENT == 2
    assert ResourcesTableModel.RESOURCE_COLUMN_MEMORY_PERCENT == 2
    assert ResourcesTableModel.COLUMN_MEMORY_USED == 3
    assert ResourcesTableModel.RESOURCE_COLUMN_MEMORY_USED == 3
    assert ResourcesTableModel.COLUMN_MEMORY_TOTAL == 4
    assert ResourcesTableModel.RESOURCE_COLUMN_MEMORY_TOTAL == 4
    assert ResourcesTableModel.COLUMN_DISK_READ == 5
    assert ResourcesTableModel.RESOURCE_COLUMN_DISK_READ == 5
    assert ResourcesTableModel.COLUMN_DISK_WRITE == 6
    assert ResourcesTableModel.RESOURCE_COLUMN_DISK_WRITE == 6
    assert ResourcesTableModel.COLUMN_DISK_USAGE_PERCENT == 7
    assert ResourcesTableModel.RESOURCE_COLUMN_DISK_USAGE_PERCENT == 7


def test_vertical_header_data(qapp: QApplication) -> None:
    """Vertical headerData returns 1-based string row numbers."""
    s1 = _make_sample_snapshot(SAMPLE_SNAPSHOT_ID_1)
    s2 = _make_sample_snapshot(SAMPLE_SNAPSHOT_ID_2)
    col = _make_sample_collection((s1, s2), total=2)
    model = ResourcesTableModel(col)

    assert model.headerData(
        0, Qt.Orientation.Vertical, int(Qt.ItemDataRole.DisplayRole)
    ) == "1"
    assert model.headerData(
        1, Qt.Orientation.Vertical, int(Qt.ItemDataRole.DisplayRole)
    ) == "2"
    assert model.headerData(
        2, Qt.Orientation.Vertical, int(Qt.ItemDataRole.DisplayRole)
    ) is None


def test_header_data_out_of_bounds_and_unsupported_roles(
    qapp: QApplication,
) -> None:
    """headerData returns None for invalid sections or unsupported roles."""
    model = ResourcesTableModel()
    assert model.headerData(
        -1, Qt.Orientation.Horizontal, int(Qt.ItemDataRole.DisplayRole)
    ) is None
    assert model.headerData(
        100, Qt.Orientation.Horizontal, int(Qt.ItemDataRole.DisplayRole)
    ) is None
    assert model.headerData(
        0, Qt.Orientation.Horizontal, int(Qt.ItemDataRole.EditRole)
    ) is None
    assert model.headerData(
        -1, Qt.Orientation.Vertical, int(Qt.ItemDataRole.DisplayRole)
    ) is None


def test_child_index_convention(qapp: QApplication) -> None:
    """rowCount() and columnCount() return 0 for valid child parent indices."""
    snap = _make_sample_snapshot()
    col = _make_sample_collection((snap,), total=1)
    model = ResourcesTableModel(col)

    top_level_index = model.index(0, 0)
    assert top_level_index.isValid()
    assert model.rowCount(top_level_index) == 0
    assert model.columnCount(top_level_index) == 0


# ==============================================================================
# Display and Formatting Tests
# ==============================================================================


def test_populated_model_display_values(qapp: QApplication) -> None:
    """Model displays all 8 columns with formatted telemetry data."""
    snap = _make_sample_snapshot(
        timestamp="2026-03-01T08:00:00Z",
        cpu_percent=15.2,
        memory_percent=25.0,
        memory_used=4_000_000_000,
        memory_total=16_000_000_000,
        disk_read_bytes=1048576,
        disk_write_bytes=2097152,
        disk_usage_percent=45.5,
    )
    col = _make_sample_collection((snap,), total=1)
    model = ResourcesTableModel(col)

    assert model.rowCount() == 1
    assert model.columnCount() == 8

    # Col 0: Timestamp
    assert model.data(model.index(0, 0)) == "2026-03-01T08:00:00Z"
    # Col 1: CPU %
    assert model.data(model.index(0, 1)) == "15.2%"
    # Col 2: Memory %
    assert model.data(model.index(0, 2)) == "25.0%"
    # Col 3: Memory Used (4 GB in binary units = 3.7 GiB)
    assert model.data(model.index(0, 3)) == "3.7 GiB"
    # Col 4: Memory Total (16 GB in binary units = 14.9 GiB)
    assert model.data(model.index(0, 4)) == "14.9 GiB"
    # Col 5: Disk Read (1048576 = 1.0 MiB)
    assert model.data(model.index(0, 5)) == "1.0 MiB"
    # Col 6: Disk Write (2097152 = 2.0 MiB)
    assert model.data(model.index(0, 6)) == "2.0 MiB"
    # Col 7: Disk Usage %
    assert model.data(model.index(0, 7)) == "45.5%"


def test_nullable_metrics_display_em_dash_placeholder(
    qapp: QApplication,
) -> None:
    """Nullable telemetry metrics display em dash (—) and never 'None'."""
    snap = _make_sample_snapshot(
        cpu_percent=None,
        memory_total=None,
        memory_used=None,
        memory_percent=None,
        disk_read_bytes=None,
        disk_write_bytes=None,
        disk_usage_percent=None,
    )
    col = _make_sample_collection((snap,), total=1)
    model = ResourcesTableModel(col)

    assert model.data(model.index(0, COLUMN_TIMESTAMP)) == SAMPLE_TIME_1
    assert model.data(model.index(0, COLUMN_CPU_PERCENT)) == EMPTY_PLACEHOLDER
    assert model.data(model.index(0, COLUMN_MEMORY_PERCENT)) == EMPTY_PLACEHOLDER
    assert model.data(model.index(0, COLUMN_MEMORY_USED)) == EMPTY_PLACEHOLDER
    assert model.data(model.index(0, COLUMN_MEMORY_TOTAL)) == EMPTY_PLACEHOLDER
    assert model.data(model.index(0, COLUMN_DISK_READ)) == EMPTY_PLACEHOLDER
    assert model.data(model.index(0, COLUMN_DISK_WRITE)) == EMPTY_PLACEHOLDER
    assert model.data(model.index(0, COLUMN_DISK_USAGE_PERCENT)) == EMPTY_PLACEHOLDER

    for col_idx in range(1, 8):
        val = model.data(model.index(0, col_idx))
        assert val == "—"
        assert "None" not in str(val)


def test_preserves_zero_valued_metrics(qapp: QApplication) -> None:
    """Preserves numeric zero values without collapsing to placeholders."""
    snap = _make_sample_snapshot(
        cpu_percent=0.0,
        memory_percent=0.0,
        memory_used=0,
        memory_total=0,
        disk_read_bytes=0,
        disk_write_bytes=0,
        disk_usage_percent=0.0,
    )
    col = _make_sample_collection((snap,), total=1)
    model = ResourcesTableModel(col)

    assert model.data(model.index(0, COLUMN_CPU_PERCENT)) == "0.0%"
    assert model.data(model.index(0, COLUMN_MEMORY_PERCENT)) == "0.0%"
    assert model.data(model.index(0, COLUMN_MEMORY_USED)) == "0 B"
    assert model.data(model.index(0, COLUMN_MEMORY_TOTAL)) == "0 B"
    assert model.data(model.index(0, COLUMN_DISK_READ)) == "0 B"
    assert model.data(model.index(0, COLUMN_DISK_WRITE)) == "0 B"
    assert model.data(model.index(0, COLUMN_DISK_USAGE_PERCENT)) == "0.0%"


def test_percentage_formatting_standalone() -> None:
    """format_percent correctly formats numeric percentages and None."""
    assert format_percent(None) == "—"
    assert format_percent(True) == "—"
    assert format_percent(False) == "—"
    assert format_percent(0) == "0.0%"
    assert format_percent(0.0) == "0.0%"
    assert format_percent(-0.0) == "0.0%"
    assert format_percent(15.2) == "15.2%"
    assert format_percent(25.0) == "25.0%"
    assert format_percent(99.9) == "99.9%"
    assert format_percent(100.0) == "100.0%"


def test_byte_formatting_standalone() -> None:
    """format_bytes formats byte values into explicit binary units."""
    assert format_bytes(None) == "—"
    assert format_bytes(True) == "—"
    assert format_bytes(False) == "—"
    assert format_bytes(-1) == "—"
    assert format_bytes(-1024) == "—"
    assert format_bytes(0) == "0 B"
    assert format_bytes(1) == "1 B"
    assert format_bytes(512) == "512 B"
    assert format_bytes(1023) == "1023 B"
    assert format_bytes(1024) == "1.0 KiB"
    assert format_bytes(1536) == "1.5 KiB"
    assert format_bytes(1048576) == "1.0 MiB"
    assert format_bytes(2097152) == "2.0 MiB"
    assert format_bytes(1073741824) == "1.0 GiB"
    assert format_bytes(4_000_000_000) == "3.7 GiB"
    assert format_bytes(16_000_000_000) == "14.9 GiB"
    assert format_bytes(1099511627776) == "1.0 TiB"
    assert format_bytes(1125899906842624) == "1.0 PiB"
    assert format_bytes(1152921504606846976) == "1.0 EiB"

    # Boundary rollover: 1048575 B (~1023.999 KiB -> rounds to 1024.0 KiB -> 1.0 MiB)
    assert format_bytes(1048575) == "1.0 MiB"


def test_timestamp_preserves_original_representation(
    qapp: QApplication,
) -> None:
    """Timestamp is rendered exactly as in validated model without timezone shift."""
    timestamps = [
        "2026-03-01T08:00:00Z",
        "2026-03-01T08:00:00+00:00",
        "2026-03-01T03:00:00-05:00",
        "2026-03-01T13:30:00+05:30",
    ]
    for ts in timestamps:
        snap = _make_sample_snapshot(timestamp=ts)
        col = _make_sample_collection((snap,), total=1)
        model = ResourcesTableModel(col)
        assert model.data(model.index(0, COLUMN_TIMESTAMP)) == ts


# ==============================================================================
# Qt Roles and Invariants Tests
# ==============================================================================


def test_alignment_roles(qapp: QApplication) -> None:
    """Timestamp is left-aligned; all numeric telemetry columns are right-aligned."""
    snap = _make_sample_snapshot()
    col = _make_sample_collection((snap,), total=1)
    model = ResourcesTableModel(col)

    expected_left = int(
        Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
    )
    expected_right = int(
        Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
    )

    # Col 0: Timestamp
    assert model.data(
        model.index(0, COLUMN_TIMESTAMP), int(Qt.ItemDataRole.TextAlignmentRole)
    ) == expected_left

    # Cols 1-7: Telemetry numbers
    for col_idx in range(1, 8):
        assert model.data(
            model.index(0, col_idx), int(Qt.ItemDataRole.TextAlignmentRole)
        ) == expected_right


def test_tooltip_role(qapp: QApplication) -> None:
    """ToolTipRole returns cell text if populated, None if placeholder."""
    snap_full = _make_sample_snapshot(cpu_percent=15.2, memory_percent=None)
    col = _make_sample_collection((snap_full,), total=1)
    model = ResourcesTableModel(col)

    assert model.data(
        model.index(0, COLUMN_CPU_PERCENT), int(Qt.ItemDataRole.ToolTipRole)
    ) == "15.2%"
    assert model.data(
        model.index(0, COLUMN_MEMORY_PERCENT), int(Qt.ItemDataRole.ToolTipRole)
    ) is None


def test_resource_snapshot_role_returns_original_object(
    qapp: QApplication,
) -> None:
    """ResourceSnapshotRole and UserRole return original snapshot by identity."""
    snap = _make_sample_snapshot()
    col = _make_sample_collection((snap,), total=1)
    model = ResourcesTableModel(col)

    for c in range(8):
        retrieved_snap = model.data(model.index(0, c), ResourceSnapshotRole)
        assert retrieved_snap is snap
        assert retrieved_snap.id == snap.id

        retrieved_alias = model.data(model.index(0, c), ResourceRole)
        assert retrieved_alias is snap

        retrieved_user = model.data(
            model.index(0, c), int(Qt.ItemDataRole.UserRole)
        )
        assert retrieved_user is snap


def test_invalid_index_and_unsupported_role(qapp: QApplication) -> None:
    """Invalid indices and unsupported data roles return None safely."""
    snap = _make_sample_snapshot()
    col = _make_sample_collection((snap,), total=1)
    model = ResourcesTableModel(col)

    # Invalid indices
    assert model.data(QModelIndex()) is None
    assert model.data(model.index(-1, 0)) is None
    assert model.data(model.index(10, 0)) is None
    assert model.data(model.index(0, -1)) is None
    assert model.data(model.index(0, 10)) is None

    # Unsupported roles
    assert model.data(
        model.index(0, 0), int(Qt.ItemDataRole.DecorationRole)
    ) is None
    assert model.data(model.index(0, 0), 999999) is None


def test_qabstract_item_model_tester_compliance(qapp: QApplication) -> None:
    """Model passes Qt's official QAbstractItemModelTester contract tests."""
    s1 = _make_sample_snapshot(SAMPLE_SNAPSHOT_ID_1)
    s2 = _make_sample_snapshot(SAMPLE_SNAPSHOT_ID_2)
    col = _make_sample_collection((s1, s2), total=2)
    model = ResourcesTableModel(col)

    # QAbstractItemModelTester validates internal Qt model invariants
    tester = QAbstractItemModelTester(model)
    assert tester is not None

    model.clear()
    assert model.rowCount() == 0

    model.set_collection(col)
    assert model.rowCount() == 2


# ==============================================================================
# Collection Lifecycle Tests
# ==============================================================================


def test_set_collection_updates_rows_and_emits_reset_signals(
    qapp: QApplication,
) -> None:
    """set_collection() replaces data and emits modelAboutToBeReset & modelReset."""
    model = ResourcesTableModel()
    assert model.rowCount() == 0

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

    s1 = _make_sample_snapshot(SAMPLE_SNAPSHOT_ID_1)
    s2 = _make_sample_snapshot(SAMPLE_SNAPSHOT_ID_2)
    col = _make_sample_collection((s1, s2), total=100, limit=2, offset=0)

    model.set_collection(col)

    assert about_to_reset_emitted is True
    assert reset_emitted is True
    assert model.rowCount() == 2
    assert model.total_count == 100
    assert model.total == 100
    assert model.limit == 2
    assert model.offset == 0
    assert model.collection is col
    assert model.snapshots == (s1, s2)
    assert model.resources == (s1, s2)


def test_set_collection_with_none_clears_model(qapp: QApplication) -> None:
    """set_collection(None) clears model and emits reset signals."""
    s1 = _make_sample_snapshot()
    col = _make_sample_collection((s1,), total=1)
    model = ResourcesTableModel(col)
    assert model.rowCount() == 1

    reset_called = False

    def on_reset() -> None:
        nonlocal reset_called
        reset_called = True

    model.modelReset.connect(on_reset)
    model.set_collection(None)

    assert reset_called is True
    assert model.rowCount() == 0
    assert model.total_count == 0
    assert model.total == 0
    assert model.limit == 50
    assert model.offset == 0
    assert model.collection is None
    assert model.snapshots == ()


def test_clear_model_resets_rows_and_metadata(qapp: QApplication) -> None:
    """clear() empties rows, resets metadata, and emits reset signals."""
    snap = _make_sample_snapshot()
    col = _make_sample_collection((snap,), total=50)
    model = ResourcesTableModel(col)
    assert model.rowCount() == 1
    assert model.total_count == 50

    reset_called = False

    def on_reset() -> None:
        nonlocal reset_called
        reset_called = True

    model.modelReset.connect(on_reset)
    model.clear()

    assert reset_called is True
    assert model.rowCount() == 0
    assert model.total_count == 0
    assert model.total == 0
    assert model.limit == 50
    assert model.offset == 0
    assert model.collection is None
    assert model.snapshots == ()


def test_snapshot_at_and_aliases(qapp: QApplication) -> None:
    """snapshot_at(), get_snapshot(), resource_at(), and get_resource() return items."""
    s1 = _make_sample_snapshot(SAMPLE_SNAPSHOT_ID_1)
    s2 = _make_sample_snapshot(SAMPLE_SNAPSHOT_ID_2)
    col = _make_sample_collection((s1, s2), total=2)
    model = ResourcesTableModel(col)

    assert model.snapshot_at(0) is s1
    assert model.get_snapshot(0) is s1
    assert model.resource_at(0) is s1
    assert model.get_resource(0) is s1

    assert model.snapshot_at(1) is s2
    assert model.get_snapshot(1) is s2
    assert model.resource_at(1) is s2
    assert model.get_resource(1) is s2

    assert model.snapshot_at(-1) is None
    assert model.snapshot_at(2) is None
    assert model.get_snapshot(99) is None
    assert model.resource_at(99) is None
    assert model.get_resource(99) is None


def test_empty_or_whitespace_timestamp_renders_placeholder(
    qapp: QApplication,
) -> None:
    """Empty or whitespace timestamps render canonical em dash placeholder."""
    s_empty = _make_sample_snapshot(timestamp="")
    col_empty = _make_sample_collection((s_empty,), total=1)
    model_empty = ResourcesTableModel(col_empty)
    assert model_empty.data(model_empty.index(0, COLUMN_TIMESTAMP)) == "—"

    s_ws = _make_sample_snapshot(timestamp="   ")
    col_ws = _make_sample_collection((s_ws,), total=1)
    model_ws = ResourcesTableModel(col_ws)
    assert model_ws.data(model_ws.index(0, COLUMN_TIMESTAMP)) == "—"


def test_constructor_with_parent_qobject(qapp: QApplication) -> None:
    """ResourcesTableModel correctly accepts parent QObject."""
    parent_obj = QApplication.instance()
    col = _make_sample_collection()
    model = ResourcesTableModel(collection=col, parent=parent_obj)
    assert model.parent() is parent_obj


def test_underlying_collection_order_and_immutability(
    qapp: QApplication,
) -> None:
    """Underlying collection order is preserved without sorting or mutating."""
    s1 = _make_sample_snapshot(SAMPLE_SNAPSHOT_ID_1, timestamp=SAMPLE_TIME_1)
    s2 = _make_sample_snapshot(SAMPLE_SNAPSHOT_ID_2, timestamp=SAMPLE_TIME_2)
    s3 = _make_sample_snapshot(SAMPLE_SNAPSHOT_ID_3, timestamp=SAMPLE_TIME_3)
    col = _make_sample_collection((s1, s2, s3), total=3)
    model = ResourcesTableModel(col)

    assert model.rowCount() == 3
    assert model.snapshots == (s1, s2, s3)
    assert model.snapshot_at(0) is s1
    assert model.snapshot_at(1) is s2
    assert model.snapshot_at(2) is s3


# ==============================================================================
# Strict Type Validation Tests
# ==============================================================================


def test_constructor_rejects_invalid_collection_types(
    qapp: QApplication,
) -> None:
    """Constructor rejects non-ResourceSnapshotCollection objects with TypeError."""
    with pytest.raises(TypeError, match="Expected ResourceSnapshotCollection"):
        ResourcesTableModel("not-a-collection")  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="Expected ResourceSnapshotCollection"):
        ResourcesTableModel([1, 2, 3])  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="Expected ResourceSnapshotCollection"):
        ResourcesTableModel({"total": 0, "items": []})  # type: ignore[arg-type]


def test_set_collection_rejects_invalid_types(qapp: QApplication) -> None:
    """set_collection() rejects non-ResourceSnapshotCollection with TypeError."""
    model = ResourcesTableModel()

    with pytest.raises(
        TypeError, match="Expected ResourceSnapshotCollection or None"
    ):
        model.set_collection("invalid")  # type: ignore[arg-type]

    with pytest.raises(
        TypeError, match="Expected ResourceSnapshotCollection or None"
    ):
        model.set_collection([1, 2, 3])  # type: ignore[arg-type]

    with pytest.raises(
        TypeError, match="Expected ResourceSnapshotCollection or None"
    ):
        model.set_collection({"total": 0})  # type: ignore[arg-type]


def test_rejects_event_and_process_collections(qapp: QApplication) -> None:
    """ResourcesTableModel strictly rejects EventCollection and ProcessCollection."""
    event = Event(
        id=SAMPLE_SNAPSHOT_ID_1,
        host_id=SAMPLE_HOST_ID,
        timestamp=SAMPLE_TIME_1,
        ingested_at=SAMPLE_TIME_1,
        source="proc",
        event_type="test",
        action="test",
        severity="info",
        created_at=SAMPLE_TIME_1,
    )
    event_col = EventCollection(total=1, items=(event,), limit=50, offset=0)

    proc = Process(
        id=SAMPLE_SNAPSHOT_ID_1,
        host_id=SAMPLE_HOST_ID,
        pid=100,
        command="test",
        started_at=SAMPLE_TIME_1,
        created_at=SAMPLE_TIME_1,
    )
    proc_col = ProcessCollection(total=1, items=(proc,), limit=50, offset=0)

    with pytest.raises(TypeError):
        ResourcesTableModel(event_col)  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        ResourcesTableModel(proc_col)  # type: ignore[arg-type]

    model = ResourcesTableModel()

    with pytest.raises(TypeError):
        model.set_collection(event_col)  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        model.set_collection(proc_col)  # type: ignore[arg-type]


def test_resources_model_formatting_and_bounds_edge_cases(
    qapp: QApplication,
) -> None:
    """ResourcesTableModel handles format fallbacks, bounds, and aliases."""
    from datetime import timezone

    from desktop.models.resources_model import (
        EMPTY_PLACEHOLDER,
        _parse_iso_utc,
        find_latest_resource_snapshot,
        format_percent,
    )

    # format_percent with non-number string
    assert format_percent("invalid") == EMPTY_PLACEHOLDER  # type: ignore[arg-type]

    # _parse_iso_utc edge cases
    assert _parse_iso_utc("   ") is None
    dt_naive = _parse_iso_utc("2026-01-01T12:00:00")
    assert dt_naive is not None
    assert dt_naive.tzinfo == timezone.utc

    # find_latest_resource_snapshot with TypeError items
    assert find_latest_resource_snapshot(123) is None  # type: ignore[arg-type]

    s = _make_sample_snapshot(snapshot_id=SAMPLE_SNAPSHOT_ID_1)
    col = _make_sample_collection((s,), total=1)
    model = ResourcesTableModel(col)

    # Valid data
    assert model.data(model.index(0, 0)) is not None

    # Invalid bounds
    assert model.data(model.createIndex(-1, 0)) is None
    assert model.data(model.createIndex(5, 0)) is None
    assert model.data(model.createIndex(0, -1)) is None
    assert model.data(model.createIndex(0, 99)) is None

    # row_for_snapshot edge cases and alias
    assert model.row_for_snapshot(None) == -1
    assert model.row_for_snapshot("missing-uuid") == -1
    assert model.find_row_by_snapshot(s) == 0
    assert model.find_row_by_snapshot(None) == -1

    # Formatting helper fallback with invalid column
    assert model._format_cell_display(s, 99) == EMPTY_PLACEHOLDER

