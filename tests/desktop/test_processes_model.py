"""Unit tests for OSIRIS ProcessesTableModel.

Verifies:
1. Construction, structure, row/column counts, and headerData.
2. Qt flat-model child-index conventions (rowCount/columnCount return 0 for parent).
3. Data presentation for all 8 columns, active/terminated status, and placeholders.
4. Handling of optional/None fields and preservation of PID and PPID 0.
5. Safe display of long commands and executables without modifying records.
6. Qt roles: DisplayRole, ToolTipRole, TextAlignmentRole, ProcessRole,
   ProcessStatusRole.
7. Original Process retrieval via process_at() and get_process(), including
   hidden fields.
8. Model reset signals and metadata updates when replacing or clearing collections.
9. Pagination semantics: current page row count vs. server-reported total count.
10. Strict input validation and rejection of invalid collection types with TypeError.
11. Purity: no backend, HTTP, database, or collector dependencies.
"""

from __future__ import annotations

import sys
from typing import Any

import pytest
from PySide6.QtCore import QModelIndex, QObject, Qt
from PySide6.QtTest import QAbstractItemModelTester
from PySide6.QtWidgets import QApplication

from desktop.client.models import (
    Event,
    EventCollection,
    Process,
    ProcessCollection,
)
from desktop.models import (
    COLUMN_ENDED_AT,
    COLUMN_EXECUTABLE,
    COLUMN_LINUX_USER_ID,
    COLUMN_PPID,
    COLUMN_STARTED_AT,
    COLUMN_STATUS,
    EMPTY_PLACEHOLDER,
    PROCESS_COLUMN_COMMAND,
    PROCESS_COLUMN_ENDED_AT,
    PROCESS_COLUMN_EXECUTABLE,
    PROCESS_COLUMN_LINUX_USER_ID,
    PROCESS_COLUMN_PID,
    PROCESS_COLUMN_PPID,
    PROCESS_COLUMN_STARTED_AT,
    PROCESS_COLUMN_STATUS,
    PROCESS_COLUMNS,
    STATUS_ACTIVE,
    STATUS_DISPLAY_ACTIVE,
    STATUS_DISPLAY_TERMINATED,
    STATUS_TERMINATED,
    ProcessesTableModel,
    ProcessRole,
    ProcessStatusRole,
)
from desktop.models.processes_model import (
    COLUMN_COMMAND,
    COLUMN_PID,
    COLUMNS,
)
from desktop.models.processes_model import (
    ProcessesTableModel as DirectProcessesTableModel,
)

SAMPLE_PROCESS_ID_1 = "11111111-1111-4111-8111-111111111111"
SAMPLE_PROCESS_ID_2 = "22222222-2222-4222-8222-222222222222"
SAMPLE_HOST_ID = "33333333-3333-4333-8333-333333333333"
SAMPLE_LINUX_USER_ID = "44444444-4444-4444-8444-444444444444"
SAMPLE_TIME_1 = "2026-03-01T10:00:00Z"
SAMPLE_TIME_2 = "2026-03-01T10:15:00Z"


def _make_sample_process(
    process_id: str = SAMPLE_PROCESS_ID_1,
    host_id: str = SAMPLE_HOST_ID,
    pid: int = 1001,
    command: str = "/usr/bin/python worker.py",
    started_at: str = SAMPLE_TIME_1,
    created_at: str = SAMPLE_TIME_1,
    ppid: int | None = 1,
    executable: str | None = "/usr/bin/python",
    linux_user_id: str | None = SAMPLE_LINUX_USER_ID,
    ended_at: str | None = None,
    **kwargs: Any,
) -> Process:
    """Create a valid Process instance with customizable test parameters."""
    return Process(
        id=process_id,
        host_id=host_id,
        pid=pid,
        command=command,
        started_at=started_at,
        created_at=created_at,
        ppid=ppid,
        executable=executable,
        linux_user_id=linux_user_id,
        ended_at=ended_at,
    )


def _make_sample_collection(
    items: tuple[Process, ...] = (),
    total: int = 0,
    limit: int = 50,
    offset: int = 0,
) -> ProcessCollection:
    """Create a valid ProcessCollection instance."""
    return ProcessCollection(
        total=total if total >= len(items) else len(items),
        items=items,
        limit=limit,
        offset=offset,
    )


# ==============================================================================
# Public API and Structural Tests
# ==============================================================================


def test_public_export_matches_direct_import() -> None:
    """desktop.models exports ProcessesTableModel identical to direct module."""
    assert ProcessesTableModel is DirectProcessesTableModel


def test_initial_empty_model_structure(qapp: QApplication) -> None:
    """ProcessesTableModel starts empty with 0 rows and 8 expected columns."""
    model = ProcessesTableModel()
    assert model.rowCount() == 0
    assert model.columnCount() == len(COLUMNS)
    assert model.columnCount() == 8
    assert model.total_count == 0
    assert model.total == 0
    assert model.limit == 50
    assert model.offset == 0
    assert model.collection is None
    assert model.processes == ()


def test_ordered_column_headers(qapp: QApplication) -> None:
    """Horizontal headerData returns stable ordered human-readable names."""
    model = ProcessesTableModel()
    expected_headers = [
        "PID",
        "PPID",
        "Command",
        "Executable",
        "Linux User ID",
        "Status",
        "Started At",
        "Ended At",
    ]
    for col_idx, expected_title in enumerate(expected_headers):
        header_val = model.headerData(
            col_idx,
            Qt.Orientation.Horizontal,
            int(Qt.ItemDataRole.DisplayRole),
        )
        assert header_val == expected_title
        assert model.COLUMNS[col_idx] == expected_title
        assert PROCESS_COLUMNS[col_idx] == expected_title

    # Out of range horizontal column
    assert (
        model.headerData(
            99,
            Qt.Orientation.Horizontal,
            int(Qt.ItemDataRole.DisplayRole),
        )
        is None
    )
    assert (
        model.headerData(
            -1,
            Qt.Orientation.Horizontal,
            int(Qt.ItemDataRole.DisplayRole),
        )
        is None
    )


def test_column_constants_indexing() -> None:
    """Column index constants strictly match the 8 defined columns."""
    assert COLUMN_PID == 0
    assert COLUMN_PPID == 1
    assert COLUMN_COMMAND == 2
    assert COLUMN_EXECUTABLE == 3
    assert COLUMN_LINUX_USER_ID == 4
    assert COLUMN_STATUS == 5
    assert COLUMN_STARTED_AT == 6
    assert COLUMN_ENDED_AT == 7

    assert PROCESS_COLUMN_PID == 0
    assert PROCESS_COLUMN_PPID == 1
    assert PROCESS_COLUMN_COMMAND == 2
    assert PROCESS_COLUMN_EXECUTABLE == 3
    assert PROCESS_COLUMN_LINUX_USER_ID == 4
    assert PROCESS_COLUMN_STATUS == 5
    assert PROCESS_COLUMN_STARTED_AT == 6
    assert PROCESS_COLUMN_ENDED_AT == 7

    assert ProcessesTableModel.COLUMN_PID == 0
    assert ProcessesTableModel.COLUMN_PPID == 1
    assert ProcessesTableModel.COLUMN_COMMAND == 2
    assert ProcessesTableModel.COLUMN_EXECUTABLE == 3
    assert ProcessesTableModel.COLUMN_LINUX_USER_ID == 4
    assert ProcessesTableModel.COLUMN_STATUS == 5
    assert ProcessesTableModel.COLUMN_STARTED_AT == 6
    assert ProcessesTableModel.COLUMN_ENDED_AT == 7


def test_vertical_header_row_numbers(qapp: QApplication) -> None:
    """Vertical headerData returns 1-based string row numbers."""
    p1 = _make_sample_process(SAMPLE_PROCESS_ID_1)
    p2 = _make_sample_process(SAMPLE_PROCESS_ID_2)
    col = _make_sample_collection(items=(p1, p2), total=2)
    model = ProcessesTableModel(col)

    assert (
        model.headerData(0, Qt.Orientation.Vertical, int(Qt.ItemDataRole.DisplayRole))
        == "1"
    )
    assert (
        model.headerData(1, Qt.Orientation.Vertical, int(Qt.ItemDataRole.DisplayRole))
        == "2"
    )
    # Out of range row numbers
    assert (
        model.headerData(99, Qt.Orientation.Vertical, int(Qt.ItemDataRole.DisplayRole))
        is None
    )
    assert (
        model.headerData(-1, Qt.Orientation.Vertical, int(Qt.ItemDataRole.DisplayRole))
        is None
    )


def test_child_index_conventions(qapp: QApplication) -> None:
    """Flat table model convention: child indexes return 0 rows and columns."""
    p = _make_sample_process()
    model = ProcessesTableModel(_make_sample_collection((p,), total=1))

    parent_idx = model.index(0, 0)
    assert parent_idx.isValid()
    assert model.rowCount(parent_idx) == 0
    assert model.columnCount(parent_idx) == 0


def test_invalid_index_handling(qapp: QApplication) -> None:
    """model.data() returns None for invalid or out-of-range indexes."""
    p = _make_sample_process()
    model = ProcessesTableModel(_make_sample_collection((p,), total=1))

    invalid_idx = QModelIndex()
    assert model.data(invalid_idx) is None

    out_row_idx = model.index(99, 0)
    assert model.data(out_row_idx) is None

    out_col_idx = model.index(0, 99)
    assert model.data(out_col_idx) is None

    neg_row_idx = model.index(-1, 0)
    assert model.data(neg_row_idx) is None


# ==============================================================================
# Data Presentation Tests
# ==============================================================================


def test_display_values_for_active_process(qapp: QApplication) -> None:
    """model.data(DisplayRole) formats active process columns correctly."""
    process = _make_sample_process(
        process_id=SAMPLE_PROCESS_ID_1,
        pid=1001,
        ppid=1,
        command="/usr/bin/python worker.py",
        executable="/usr/bin/python",
        linux_user_id=SAMPLE_LINUX_USER_ID,
        started_at=SAMPLE_TIME_1,
        ended_at=None,
    )
    model = ProcessesTableModel(_make_sample_collection((process,), total=1))

    assert model.data(model.index(0, COLUMN_PID)) == "1001"
    assert model.data(model.index(0, COLUMN_PPID)) == "1"
    assert model.data(model.index(0, COLUMN_COMMAND)) == "/usr/bin/python worker.py"
    assert model.data(model.index(0, COLUMN_EXECUTABLE)) == "/usr/bin/python"
    assert model.data(model.index(0, COLUMN_LINUX_USER_ID)) == SAMPLE_LINUX_USER_ID
    assert model.data(model.index(0, COLUMN_STATUS)) == STATUS_DISPLAY_ACTIVE
    assert model.data(model.index(0, COLUMN_STARTED_AT)) == SAMPLE_TIME_1
    assert model.data(model.index(0, COLUMN_ENDED_AT)) == EMPTY_PLACEHOLDER


def test_display_values_for_terminated_process(qapp: QApplication) -> None:
    """model.data(DisplayRole) formats terminated process columns correctly."""
    process = _make_sample_process(
        process_id=SAMPLE_PROCESS_ID_2,
        pid=2048,
        ppid=1001,
        command="/bin/ls -la /tmp",
        executable="/bin/ls",
        linux_user_id=None,
        started_at=SAMPLE_TIME_1,
        ended_at=SAMPLE_TIME_2,
    )
    model = ProcessesTableModel(_make_sample_collection((process,), total=1))

    assert model.data(model.index(0, COLUMN_PID)) == "2048"
    assert model.data(model.index(0, COLUMN_PPID)) == "1001"
    assert model.data(model.index(0, COLUMN_COMMAND)) == "/bin/ls -la /tmp"
    assert model.data(model.index(0, COLUMN_EXECUTABLE)) == "/bin/ls"
    assert model.data(model.index(0, COLUMN_LINUX_USER_ID)) == EMPTY_PLACEHOLDER
    assert model.data(model.index(0, COLUMN_STATUS)) == STATUS_DISPLAY_TERMINATED
    assert model.data(model.index(0, COLUMN_STARTED_AT)) == SAMPLE_TIME_1
    assert model.data(model.index(0, COLUMN_ENDED_AT)) == SAMPLE_TIME_2


def test_optional_missing_fields_display_placeholder(
    qapp: QApplication,
) -> None:
    """None or empty optional fields display the em dash placeholder."""
    process = _make_sample_process(
        ppid=None,
        executable=None,
        linux_user_id=None,
        ended_at=None,
    )
    model = ProcessesTableModel(_make_sample_collection((process,), total=1))

    assert model.data(model.index(0, COLUMN_PPID)) == EMPTY_PLACEHOLDER
    assert model.data(model.index(0, COLUMN_EXECUTABLE)) == EMPTY_PLACEHOLDER
    assert model.data(model.index(0, COLUMN_LINUX_USER_ID)) == EMPTY_PLACEHOLDER
    assert model.data(model.index(0, COLUMN_ENDED_AT)) == EMPTY_PLACEHOLDER

    # Verify no stringified 'None' is displayed across any column
    for col in range(len(COLUMNS)):
        cell_val = model.data(model.index(0, col))
        assert cell_val != "None"
        assert "None" not in str(cell_val)


def test_pid_and_ppid_zero_preserved(qapp: QApplication) -> None:
    """PID 0 (idle/swapper) and PPID 0 are preserved as '0' and not placeholders."""
    process = _make_sample_process(pid=0, ppid=0)
    model = ProcessesTableModel(_make_sample_collection((process,), total=1))

    pid_val = model.data(model.index(0, COLUMN_PID))
    ppid_val = model.data(model.index(0, COLUMN_PPID))

    assert pid_val == "0"
    assert ppid_val == "0"
    assert pid_val != EMPTY_PLACEHOLDER
    assert ppid_val != EMPTY_PLACEHOLDER


def test_status_display_derivation(qapp: QApplication) -> None:
    """Status displays Active when is_active is True and Terminated otherwise."""
    active_proc = _make_sample_process(ended_at=None)
    assert active_proc.is_active is True
    term_proc = _make_sample_process(ended_at=SAMPLE_TIME_2)
    assert term_proc.is_active is False

    model = ProcessesTableModel(
        _make_sample_collection((active_proc, term_proc), total=2)
    )

    assert model.data(model.index(0, COLUMN_STATUS)) == STATUS_DISPLAY_ACTIVE
    assert model.data(model.index(1, COLUMN_STATUS)) == STATUS_DISPLAY_TERMINATED


def test_timestamps_rendered_without_mutation(qapp: QApplication) -> None:
    """Timestamps are rendered verbatim without altering timezone or content."""
    ts1 = "2026-03-01T14:30:00+02:00"
    ts2 = "2026-03-01T15:00:00+02:00"
    proc = _make_sample_process(started_at=ts1, ended_at=ts2)
    model = ProcessesTableModel(_make_sample_collection((proc,), total=1))

    assert model.data(model.index(0, COLUMN_STARTED_AT)) == ts1
    assert model.data(model.index(0, COLUMN_ENDED_AT)) == ts2


def test_long_values_safely_represented_without_modifying_source(
    qapp: QApplication,
) -> None:
    """Long command strings are represented without altering original Process."""
    long_cmd = "/usr/bin/daemon " + " ".join(f"--flag{i}" for i in range(200))
    proc = _make_sample_process(command=long_cmd)
    model = ProcessesTableModel(_make_sample_collection((proc,), total=1))

    cell_val = model.data(model.index(0, COLUMN_COMMAND))
    assert cell_val == long_cmd

    retrieved = model.process_at(0)
    assert retrieved is not None
    assert retrieved.command == long_cmd
    assert retrieved.command is proc.command


# ==============================================================================
# Qt Roles Tests
# ==============================================================================


def test_unsupported_data_roles_return_none(qapp: QApplication) -> None:
    """Unsupported Qt item data roles return None."""
    proc = _make_sample_process()
    model = ProcessesTableModel(_make_sample_collection((proc,), total=1))
    idx = model.index(0, 0)

    assert model.data(idx, int(Qt.ItemDataRole.EditRole)) is None
    assert model.data(idx, int(Qt.ItemDataRole.DecorationRole)) is None
    assert model.data(idx, int(Qt.ItemDataRole.CheckStateRole)) is None
    assert model.data(idx, 99999) is None


def test_tooltip_role_returns_display_text_or_none(qapp: QApplication) -> None:
    """ToolTipRole returns the cell string, or None if placeholder."""
    proc = _make_sample_process(
        command="/usr/bin/test",
        ended_at=None,  # placeholder
    )
    model = ProcessesTableModel(_make_sample_collection((proc,), total=1))

    tt_cmd = model.data(
        model.index(0, COLUMN_COMMAND), int(Qt.ItemDataRole.ToolTipRole)
    )
    assert tt_cmd == "/usr/bin/test"

    tt_ended = model.data(
        model.index(0, COLUMN_ENDED_AT), int(Qt.ItemDataRole.ToolTipRole)
    )
    assert tt_ended is None


def test_text_alignment_role(qapp: QApplication) -> None:
    """PID and PPID columns are right-aligned; all other columns are left-aligned."""
    proc = _make_sample_process(pid=1001, ppid=1)
    model = ProcessesTableModel(_make_sample_collection((proc,), total=1))

    expected_right_align = int(
        Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
    )
    expected_left_align = int(
        Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
    )

    # PID and PPID are right-aligned
    assert (
        model.data(model.index(0, COLUMN_PID), int(Qt.ItemDataRole.TextAlignmentRole))
        == expected_right_align
    )
    assert (
        model.data(model.index(0, COLUMN_PPID), int(Qt.ItemDataRole.TextAlignmentRole))
        == expected_right_align
    )

    # Other columns are left-aligned
    for col in (
        COLUMN_COMMAND,
        COLUMN_EXECUTABLE,
        COLUMN_LINUX_USER_ID,
        COLUMN_STATUS,
        COLUMN_STARTED_AT,
        COLUMN_ENDED_AT,
    ):
        align = model.data(model.index(0, col), int(Qt.ItemDataRole.TextAlignmentRole))
        assert align == expected_left_align


def test_process_status_role(qapp: QApplication) -> None:
    """ProcessStatusRole returns 'active' or 'terminated' on any column."""
    active_proc = _make_sample_process(ended_at=None)
    term_proc = _make_sample_process(ended_at=SAMPLE_TIME_2)
    model = ProcessesTableModel(
        _make_sample_collection((active_proc, term_proc), total=2)
    )

    assert model.data(model.index(0, COLUMN_STATUS), ProcessStatusRole) == STATUS_ACTIVE
    # Available on any column index for convenience
    assert model.data(model.index(0, COLUMN_PID), ProcessStatusRole) == STATUS_ACTIVE

    assert (
        model.data(model.index(1, COLUMN_STATUS), ProcessStatusRole)
        == STATUS_TERMINATED
    )
    assert (
        model.data(model.index(1, COLUMN_COMMAND), ProcessStatusRole)
        == STATUS_TERMINATED
    )


def test_process_role_and_user_role_return_process_object(
    qapp: QApplication,
) -> None:
    """ProcessRole and UserRole return the exact original Process object."""
    proc = _make_sample_process()
    model = ProcessesTableModel(_make_sample_collection((proc,), total=1))

    assert model.data(model.index(0, 0), ProcessRole) is proc
    assert model.data(model.index(0, 0), int(Qt.ItemDataRole.UserRole)) is proc
    # Available across different columns
    assert model.data(model.index(0, COLUMN_COMMAND), ProcessRole) is proc


# ==============================================================================
# Original Process Accessor Tests
# ==============================================================================


def test_process_at_and_get_process(qapp: QApplication) -> None:
    """process_at() and get_process() return exact Process or None if out of bounds."""
    p1 = _make_sample_process(SAMPLE_PROCESS_ID_1)
    p2 = _make_sample_process(SAMPLE_PROCESS_ID_2)
    model = ProcessesTableModel(_make_sample_collection((p1, p2), total=2))

    assert model.process_at(0) is p1
    assert model.get_process(0) is p1
    assert model.process_at(1) is p2
    assert model.get_process(1) is p2

    # Out of range row indexes
    assert model.process_at(-1) is None
    assert model.get_process(-1) is None
    assert model.process_at(2) is None
    assert model.get_process(2) is None


def test_hidden_fields_accessible_on_original_process(
    qapp: QApplication,
) -> None:
    """Hidden/detail fields not rendered in table remain accessible on Process."""
    proc = _make_sample_process(
        process_id=SAMPLE_PROCESS_ID_1,
        host_id=SAMPLE_HOST_ID,
        created_at=SAMPLE_TIME_1,
    )
    model = ProcessesTableModel(_make_sample_collection((proc,), total=1))
    retrieved = model.process_at(0)
    assert retrieved is not None
    assert retrieved.id == SAMPLE_PROCESS_ID_1
    assert retrieved.host_id == SAMPLE_HOST_ID
    assert retrieved.created_at == SAMPLE_TIME_1


# ==============================================================================
# Model Updates, Signals, and Reset Behavior
# ==============================================================================


def test_set_collection_updates_rows_and_emits_reset_signals(
    qapp: QApplication,
) -> None:
    """set_collection() replaces data and emits modelAboutToBeReset & modelReset."""
    model = ProcessesTableModel()
    assert model.rowCount() == 0

    reset_about_to_be_called = False
    reset_called = False

    def on_about_to_reset() -> None:
        nonlocal reset_about_to_be_called
        reset_about_to_be_called = True

    def on_reset() -> None:
        nonlocal reset_called
        reset_called = True

    model.modelAboutToBeReset.connect(on_about_to_reset)
    model.modelReset.connect(on_reset)

    p1 = _make_sample_process(SAMPLE_PROCESS_ID_1)
    p2 = _make_sample_process(SAMPLE_PROCESS_ID_2)
    col = _make_sample_collection((p1, p2), total=100, limit=2, offset=0)

    model.set_collection(col)

    assert reset_about_to_be_called is True
    assert reset_called is True
    assert model.rowCount() == 2
    assert model.total_count == 100
    assert model.limit == 2
    assert model.offset == 0
    assert model.collection is col
    assert model.processes == (p1, p2)


def test_clear_model_resets_rows_and_metadata(qapp: QApplication) -> None:
    """clear() empties rows, resets metadata, and emits reset signals."""
    proc = _make_sample_process()
    col = _make_sample_collection((proc,), total=50)
    model = ProcessesTableModel(col)
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
    assert model.processes == ()


def test_replace_with_empty_collection(qapp: QApplication) -> None:
    """Replacing data with an empty collection succeeds cleanly."""
    proc = _make_sample_process()
    model = ProcessesTableModel(_make_sample_collection((proc,), total=1))
    assert model.rowCount() == 1

    empty_col = _make_sample_collection((), total=0)
    model.set_collection(empty_col)

    assert model.rowCount() == 0
    assert model.total_count == 0
    assert model.processes == ()


def test_set_collection_preserves_exact_record_order(
    qapp: QApplication,
) -> None:
    """set_collection() preserves the exact order of processes without sorting."""
    p1 = _make_sample_process(SAMPLE_PROCESS_ID_1, pid=9999)
    p2 = _make_sample_process(SAMPLE_PROCESS_ID_2, pid=10)
    # Provided out of PID order
    col = _make_sample_collection((p1, p2), total=2)
    model = ProcessesTableModel(col)

    assert model.process_at(0) is p1
    assert model.process_at(1) is p2
    assert model.data(model.index(0, COLUMN_PID)) == "9999"
    assert model.data(model.index(1, COLUMN_PID)) == "10"


# ==============================================================================
# Pagination Semantics Tests
# ==============================================================================


def test_pagination_metadata_preservation(qapp: QApplication) -> None:
    """Row count reflects current page size, total reflects server total."""
    p1 = _make_sample_process(SAMPLE_PROCESS_ID_1)
    p2 = _make_sample_process(SAMPLE_PROCESS_ID_2)
    col = _make_sample_collection(items=(p1, p2), total=250, limit=2, offset=50)
    model = ProcessesTableModel(col)

    assert model.rowCount() == 2
    assert model.total_count == 250
    assert model.total == 250
    assert model.limit == 2
    assert model.offset == 50


def test_empty_page_with_positive_server_total(qapp: QApplication) -> None:
    """Empty items with non-zero server total (e.g., offset past end)."""
    col = _make_sample_collection(items=(), total=15, limit=10, offset=20)
    model = ProcessesTableModel(col)

    assert model.rowCount() == 0
    assert model.total_count == 15
    assert model.offset == 20
    assert model.limit == 10


# ==============================================================================
# Input Validation Tests
# ==============================================================================


@pytest.mark.parametrize(
    "invalid_input",
    [
        "not a collection",
        {"total": 1, "items": []},
        [1, 2, 3],
        123,
        True,
    ],
)
def test_constructor_rejects_invalid_collection_type(
    qapp: QApplication, invalid_input: object
) -> None:
    """Constructor raises TypeError when given invalid collection object."""
    with pytest.raises(TypeError, match="Expected ProcessCollection"):
        ProcessesTableModel(invalid_input)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "invalid_input",
    [
        "not a collection",
        {"total": 1, "items": []},
        [1, 2, 3],
        123,
        None,
    ],
)
def test_set_collection_rejects_invalid_type_and_preserves_state(
    qapp: QApplication, invalid_input: object
) -> None:
    """set_collection() raises TypeError and preserves existing model state."""
    proc = _make_sample_process()
    col = _make_sample_collection((proc,), total=1)
    model = ProcessesTableModel(col)
    assert model.rowCount() == 1

    with pytest.raises(TypeError, match="Expected ProcessCollection"):
        model.set_collection(invalid_input)  # type: ignore[arg-type]

    # Model remains intact and usable
    assert model.rowCount() == 1
    assert model.total_count == 1
    assert model.process_at(0) is proc


# ==============================================================================
# Purity and Dependency Isolation Tests
# ==============================================================================


def test_model_module_has_no_backend_or_network_imports() -> None:
    """desktop.models.processes_model does not import backend, httpx, or DB."""
    import desktop.models.processes_model as mod

    # Verify no httpx, starlette, fastapi, or sqlalchemy in module symbols
    for prohibited in ("httpx", "fastapi", "starlette", "sqlalchemy", "respx"):
        assert not hasattr(mod, prohibited)

    # Check that sys.modules didn't get backend or collectors from this import
    for mod_name in sys.modules:
        if mod_name.startswith("desktop.models"):
            mod_obj = sys.modules[mod_name]
            for forbidden in ("httpx", "sqlalchemy"):
                assert forbidden not in mod_obj.__dict__


# ==============================================================================
# Extended Qt Contract and Edge Case Tests
# ==============================================================================


def test_qt_abstract_item_model_tester_compliance(qapp: QApplication) -> None:
    """Model passes Qt's official QAbstractItemModelTester contract tests."""
    p1 = _make_sample_process(SAMPLE_PROCESS_ID_1)
    p2 = _make_sample_process(SAMPLE_PROCESS_ID_2)
    col = _make_sample_collection((p1, p2), total=2)
    model = ProcessesTableModel(col)

    # QAbstractItemModelTester monitors model invariants and signals
    tester = QAbstractItemModelTester(model)
    assert tester is not None

    # Verify model invariants remain valid across clear and reset
    model.clear()
    assert model.rowCount() == 0

    model.set_collection(col)
    assert model.rowCount() == 2


def test_rejects_event_collection_type(qapp: QApplication) -> None:
    """ProcessesTableModel strictly rejects EventCollection with TypeError."""
    event = Event(
        id=SAMPLE_PROCESS_ID_1,
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

    with pytest.raises(TypeError, match="Expected ProcessCollection"):
        ProcessesTableModel(event_col)  # type: ignore[arg-type]

    model = ProcessesTableModel()
    with pytest.raises(TypeError, match="Expected ProcessCollection"):
        model.set_collection(event_col)  # type: ignore[arg-type]


def test_header_data_edge_cases(qapp: QApplication) -> None:
    """headerData handles unsupported roles and non-standard orientations."""
    model = ProcessesTableModel()

    # Unsupported roles on horizontal headers
    assert (
        model.headerData(0, Qt.Orientation.Horizontal, int(Qt.ItemDataRole.ToolTipRole))
        is None
    )
    assert (
        model.headerData(0, Qt.Orientation.Horizontal, int(Qt.ItemDataRole.EditRole))
        is None
    )

    # Unsupported roles on vertical headers
    assert (
        model.headerData(
            0, Qt.Orientation.Vertical, int(Qt.ItemDataRole.TextAlignmentRole)
        )
        is None
    )

    # Non-standard orientation
    assert (
        model.headerData(
            0,
            Qt.Orientation(99),  # type: ignore[arg-type]
            int(Qt.ItemDataRole.DisplayRole),
        )
        is None
    )


def test_data_out_of_bounds_columns(qapp: QApplication) -> None:
    """data() returns None for out-of-bounds column numbers."""
    proc = _make_sample_process()
    model = ProcessesTableModel(_make_sample_collection((proc,), total=1))

    # Valid row, negative column
    neg_col_idx = model.index(0, -1)
    assert model.data(neg_col_idx) is None

    # Valid row, column 8 (valid columns are 0..7)
    eight_col_idx = model.index(0, 8)
    assert model.data(eight_col_idx) is None


def test_whitespace_strings_treated_as_empty_placeholder(
    qapp: QApplication,
) -> None:
    """Whitespace-only strings for optional fields display EMPTY_PLACEHOLDER."""
    proc = _make_sample_process(
        command="   ",
        executable="   ",
        linux_user_id="   ",
    )
    model = ProcessesTableModel(_make_sample_collection((proc,), total=1))

    assert model.data(model.index(0, COLUMN_COMMAND)) == EMPTY_PLACEHOLDER
    assert model.data(model.index(0, COLUMN_EXECUTABLE)) == EMPTY_PLACEHOLDER
    assert model.data(model.index(0, COLUMN_LINUX_USER_ID)) == EMPTY_PLACEHOLDER


def test_parent_qobject_hierarchy(qapp: QApplication) -> None:
    """ProcessesTableModel correctly attaches to a parent QObject."""
    parent_obj = QObject()
    model = ProcessesTableModel(parent=parent_obj)
    assert model.parent() is parent_obj


def test_processes_model_all_exports() -> None:
    """processes_model module defines and exports __all__ matching public API."""
    import desktop.models.processes_model as mod

    assert hasattr(mod, "__all__")
    for name in mod.__all__:
        assert hasattr(mod, name), f"Missing exported symbol: {name}"


def test_multiple_reset_cycles(qapp: QApplication) -> None:
    """Model handles multiple sequential set_collection and clear calls."""
    model = ProcessesTableModel()
    p1 = _make_sample_process(SAMPLE_PROCESS_ID_1, pid=101)
    p2 = _make_sample_process(SAMPLE_PROCESS_ID_2, pid=202)
    col1 = _make_sample_collection((p1,), total=10, limit=1, offset=0)
    col2 = _make_sample_collection((p1, p2), total=20, limit=2, offset=5)

    about_to_reset_count = 0
    reset_count = 0

    def on_about() -> None:
        nonlocal about_to_reset_count
        about_to_reset_count += 1

    def on_reset() -> None:
        nonlocal reset_count
        reset_count += 1

    model.modelAboutToBeReset.connect(on_about)
    model.modelReset.connect(on_reset)

    model.set_collection(col1)
    assert model.rowCount() == 1
    assert model.total == 10
    assert model.limit == 1
    assert model.offset == 0

    model.set_collection(col2)
    assert model.rowCount() == 2
    assert model.total == 20
    assert model.limit == 2
    assert model.offset == 5

    model.clear()
    assert model.rowCount() == 0
    assert model.total == 0
    assert model.limit == 50
    assert model.offset == 0

    assert about_to_reset_count == 3
    assert reset_count == 3


def test_processes_model_index_boundary_and_invalid_column(
    qapp: QApplication,
) -> None:
    """ProcessesTableModel handles out-of-range bounds and empty started_at."""
    from desktop.models.processes_model import (
        COLUMN_STARTED_AT,
        EMPTY_PLACEHOLDER,
    )

    proc = _make_sample_process(
        SAMPLE_PROCESS_ID_1, started_at="   ", ended_at="   "
    )
    col = _make_sample_collection((proc,), total=1)
    model = ProcessesTableModel(col)

    # Valid row and col
    assert model.data(model.index(0, 0)) is not None

    # Invalid rows
    assert model.data(model.createIndex(-1, 0)) is None
    assert model.data(model.createIndex(5, 0)) is None

    # Invalid cols
    assert model.data(model.createIndex(0, -1)) is None
    assert model.data(model.createIndex(0, 99)) is None

    # Empty field fallbacks
    assert (
        model._format_cell_display(proc, COLUMN_STARTED_AT)
        == EMPTY_PLACEHOLDER
    )
    assert model._format_cell_display(proc, 99) == EMPTY_PLACEHOLDER

