"""Unit tests for OSIRIS EventsTableModel.

Verifies:
1. Construction, structure, row/column counts, and headerData.
2. Qt flat-model child-index conventions (rowCount/columnCount return 0 for parent).
3. Data presentation for all columns, canonical severities, and placeholders.
4. Handling of optional/None fields and preservation of PID 0.
5. Safe display of long commands and objects without modifying Event records.
6. Qt roles: DisplayRole, ToolTipRole, TextAlignmentRole, SeverityRole, EventRole.
7. Original Event retrieval via event_at() and get_event(), including hidden fields.
8. Model reset signals and metadata updates when replacing or clearing collections.
9. Pagination semantics: current page row count vs. server-reported total count.
10. Strict input validation and rejection of invalid collection types with TypeError.
11. Purity: no backend, HTTP, database, or collector dependencies.
"""

from __future__ import annotations

import sys
from typing import Any

import pytest
from PySide6.QtCore import QModelIndex, Qt
from PySide6.QtWidgets import QApplication

from desktop.client.models import Event, EventCollection
from desktop.models import (
    COLUMN_ACTION,
    COLUMN_COMMAND,
    COLUMN_EVENT_TYPE,
    COLUMN_OBJECT,
    COLUMN_PID,
    COLUMN_RESULT,
    COLUMN_SEVERITY,
    COLUMN_SOURCE,
    COLUMN_TIMESTAMP,
    COLUMN_USER,
    COLUMNS,
    EMPTY_PLACEHOLDER,
    EventRole,
    EventsTableModel,
    SeverityRole,
)
from desktop.models.events_model import (
    EventsTableModel as DirectEventsTableModel,
)

# Representative test UUIDs and ISO timestamps
SAMPLE_EVENT_ID_1 = "11111111-1111-4111-8111-111111111111"
SAMPLE_EVENT_ID_2 = "22222222-2222-4222-8222-222222222222"
SAMPLE_HOST_ID = "33333333-3333-4333-8333-333333333333"
SAMPLE_PROCESS_ID = "44444444-4444-4444-8444-444444444444"
SAMPLE_TIME_1 = "2026-03-01T12:00:00Z"
SAMPLE_TIME_2 = "2026-03-01T12:00:15Z"


def _make_sample_event(
    event_id: str = SAMPLE_EVENT_ID_1,
    severity: str = "info",
    source: str = "proc",
    event_type: str = "process.start",
    action: str = "start",
    username: str | None = "sec_analyst",
    pid: int | None = 1001,
    command: str | None = "/usr/bin/python worker.py",
    object_type: str | None = "process",
    object_path: str | None = None,
    result: str | None = "started",
    timestamp: str = SAMPLE_TIME_1,
    **kwargs: Any,
) -> Event:
    """Create a valid Event instance with customizable test parameters."""
    return Event(
        id=event_id,
        host_id=kwargs.get("host_id", SAMPLE_HOST_ID),
        timestamp=timestamp,
        ingested_at=kwargs.get("ingested_at", SAMPLE_TIME_1),
        source=source,
        event_type=event_type,
        action=action,
        severity=severity,
        created_at=kwargs.get("created_at", SAMPLE_TIME_1),
        process_id=kwargs.get("process_id", SAMPLE_PROCESS_ID),
        uid=kwargs.get("uid", 1000),
        username=username,
        pid=pid,
        ppid=kwargs.get("ppid", 1),
        command=command,
        object_type=object_type,
        object_path=object_path,
        success=kwargs.get("success", True),
        result=result,
        payload=kwargs.get("payload", {"key": "val"}),
    )


def _make_sample_collection(
    items: tuple[Event, ...] = (),
    total: int = 0,
    limit: int = 50,
    offset: int = 0,
) -> EventCollection:
    """Create a valid EventCollection instance."""
    return EventCollection(
        total=total if total >= len(items) else len(items),
        items=items,
        limit=limit,
        offset=offset,
    )


# ==============================================================================
# Public API and Structural Tests
# ==============================================================================


def test_public_export_matches_direct_import() -> None:
    """desktop.models exports EventsTableModel identical to direct module."""
    assert EventsTableModel is DirectEventsTableModel


def test_initial_empty_model_structure(qapp: QApplication) -> None:
    """EventsTableModel starts empty with 0 rows and 10 expected columns."""
    model = EventsTableModel()
    assert model.rowCount() == 0
    assert model.columnCount() == len(COLUMNS)
    assert model.columnCount() == 10
    assert model.total_count == 0
    assert model.total == 0
    assert model.limit == 50
    assert model.offset == 0
    assert model.collection is None
    assert model.events == ()


def test_ordered_column_headers(qapp: QApplication) -> None:
    """Horizontal headerData returns stable ordered human-readable names."""
    model = EventsTableModel()
    expected_headers = [
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
    ]
    for col_idx, expected_title in enumerate(expected_headers):
        header_val = model.headerData(
            col_idx,
            Qt.Orientation.Horizontal,
            int(Qt.ItemDataRole.DisplayRole),
        )
        assert header_val == expected_title
        assert model.COLUMNS[col_idx] == expected_title


def test_vertical_header_row_numbers(qapp: QApplication) -> None:
    """Vertical headerData returns 1-based string row numbers."""
    e1 = _make_sample_event(SAMPLE_EVENT_ID_1)
    e2 = _make_sample_event(SAMPLE_EVENT_ID_2)
    col = _make_sample_collection(items=(e1, e2), total=2)
    model = EventsTableModel(col)

    assert (
        model.headerData(
            0, Qt.Orientation.Vertical, int(Qt.ItemDataRole.DisplayRole)
        )
        == "1"
    )
    assert (
        model.headerData(
            1, Qt.Orientation.Vertical, int(Qt.ItemDataRole.DisplayRole)
        )
        == "2"
    )
    # Out of range row number
    assert (
        model.headerData(
            99, Qt.Orientation.Vertical, int(Qt.ItemDataRole.DisplayRole)
        )
        is None
    )


def test_child_index_conventions(qapp: QApplication) -> None:
    """Flat table model convention: child indexes return 0 rows and columns."""
    e = _make_sample_event()
    model = EventsTableModel(_make_sample_collection((e,), total=1))

    parent_idx = model.index(0, 0)
    assert parent_idx.isValid()
    assert model.rowCount(parent_idx) == 0
    assert model.columnCount(parent_idx) == 0


def test_invalid_index_handling(qapp: QApplication) -> None:
    """model.data() returns None for invalid or out-of-range indexes."""
    e = _make_sample_event()
    model = EventsTableModel(_make_sample_collection((e,), total=1))

    invalid_idx = QModelIndex()
    assert model.data(invalid_idx) is None

    out_row_idx = model.index(99, 0)
    assert model.data(out_row_idx) is None

    out_col_idx = model.index(0, 99)
    assert model.data(out_col_idx) is None


# ==============================================================================
# Data Presentation Tests
# ==============================================================================


def test_display_values_for_all_columns(qapp: QApplication) -> None:
    """model.data(DisplayRole) formats all 10 columns correctly."""
    event = _make_sample_event(
        event_id=SAMPLE_EVENT_ID_1,
        severity="critical",
        source="proc",
        event_type="process.spawn",
        action="execute",
        username="sec_admin",
        pid=4242,
        command="/usr/bin/bash -c id",
        object_type="process",
        object_path=None,
        result="success",
        timestamp=SAMPLE_TIME_1,
    )
    model = EventsTableModel(_make_sample_collection((event,), total=1))

    assert model.data(model.index(0, COLUMN_TIMESTAMP)) == SAMPLE_TIME_1
    assert model.data(model.index(0, COLUMN_SEVERITY)) == "Critical"
    assert model.data(model.index(0, COLUMN_SOURCE)) == "proc"
    assert model.data(model.index(0, COLUMN_EVENT_TYPE)) == "process.spawn"
    assert model.data(model.index(0, COLUMN_ACTION)) == "execute"
    assert model.data(model.index(0, COLUMN_USER)) == "sec_admin"
    assert model.data(model.index(0, COLUMN_PID)) == "4242"
    assert model.data(model.index(0, COLUMN_COMMAND)) == "/usr/bin/bash -c id"
    assert model.data(model.index(0, COLUMN_OBJECT)) == "process"
    assert model.data(model.index(0, COLUMN_RESULT)) == "success"


@pytest.mark.parametrize(
    "raw_sev, expected_canonical",
    [
        ("critical", "Critical"),
        ("high", "High"),
        ("medium", "Medium"),
        ("low", "Low"),
        ("info", "Info"),
    ],
)
def test_canonical_severity_display(
    qapp: QApplication, raw_sev: str, expected_canonical: str
) -> None:
    """Severity column displays canonical title-cased values."""
    event = _make_sample_event(severity=raw_sev)
    model = EventsTableModel(_make_sample_collection((event,), total=1))
    display_val = model.data(model.index(0, COLUMN_SEVERITY))
    assert display_val == expected_canonical


def test_optional_missing_fields_display_placeholder(
    qapp: QApplication,
) -> None:
    """None or empty optional fields display the em dash placeholder."""
    event = _make_sample_event(
        username=None,
        pid=None,
        command=None,
        object_type=None,
        object_path=None,
        result=None,
    )
    model = EventsTableModel(_make_sample_collection((event,), total=1))

    assert model.data(model.index(0, COLUMN_USER)) == EMPTY_PLACEHOLDER
    assert model.data(model.index(0, COLUMN_PID)) == EMPTY_PLACEHOLDER
    assert model.data(model.index(0, COLUMN_COMMAND)) == EMPTY_PLACEHOLDER
    assert model.data(model.index(0, COLUMN_OBJECT)) == EMPTY_PLACEHOLDER
    assert model.data(model.index(0, COLUMN_RESULT)) == EMPTY_PLACEHOLDER

    # Verify no stringified 'None' is displayed
    for col in range(len(COLUMNS)):
        cell_val = model.data(model.index(0, col))
        assert cell_val != "None"
        assert "None" not in str(cell_val)


def test_pid_zero_preserved_and_not_treated_as_missing(
    qapp: QApplication,
) -> None:
    """PID 0 (idle/swapper) is preserved and displayed as '0'."""
    event = _make_sample_event(pid=0)
    model = EventsTableModel(_make_sample_collection((event,), total=1))
    display_val = model.data(model.index(0, COLUMN_PID))
    assert display_val == "0"
    assert display_val != EMPTY_PLACEHOLDER


def test_object_column_prefers_object_path_over_type(
    qapp: QApplication,
) -> None:
    """Object column displays object_path when present, falling back to object_type."""
    event_with_path = _make_sample_event(
        object_type="file",
        object_path="/var/log/osiris.log",
    )
    model = EventsTableModel(
        _make_sample_collection((event_with_path,), total=1)
    )
    assert (
        model.data(model.index(0, COLUMN_OBJECT)) == "/var/log/osiris.log"
    )

    event_type_only = _make_sample_event(
        object_type="system",
        object_path=None,
    )
    model.set_collection(
        _make_sample_collection((event_type_only,), total=1)
    )
    assert model.data(model.index(0, COLUMN_OBJECT)) == "system"


def test_long_values_safely_represented_without_modifying_source(
    qapp: QApplication,
) -> None:
    """Long command strings are represented without altering original Event."""
    long_command = "/usr/bin/daemon " + " ".join(f"--flag{i}" for i in range(200))
    event = _make_sample_event(command=long_command)
    model = EventsTableModel(_make_sample_collection((event,), total=1))

    # Cell display
    cell_val = model.data(model.index(0, COLUMN_COMMAND))
    assert cell_val == long_command

    # Source record in model remains intact and identical
    retrieved_event = model.event_at(0)
    assert retrieved_event is not None
    assert retrieved_event.command == long_command
    assert retrieved_event.command is event.command


# ==============================================================================
# Qt Roles Tests
# ==============================================================================


def test_unsupported_data_roles_return_none(qapp: QApplication) -> None:
    """Unsupported Qt item data roles return None."""
    event = _make_sample_event()
    model = EventsTableModel(_make_sample_collection((event,), total=1))
    idx = model.index(0, 0)

    assert model.data(idx, int(Qt.ItemDataRole.EditRole)) is None
    assert model.data(idx, int(Qt.ItemDataRole.DecorationRole)) is None
    assert model.data(idx, int(Qt.ItemDataRole.CheckStateRole)) is None
    assert model.data(idx, 99999) is None


def test_tooltip_role_returns_display_text_or_none(qapp: QApplication) -> None:
    """ToolTipRole returns the cell string, or None if placeholder."""
    event = _make_sample_event(
        command="/usr/bin/test",
        result=None,  # placeholder
    )
    model = EventsTableModel(_make_sample_collection((event,), total=1))

    # Active text has tooltip
    tt_cmd = model.data(
        model.index(0, COLUMN_COMMAND), int(Qt.ItemDataRole.ToolTipRole)
    )
    assert tt_cmd == "/usr/bin/test"

    # Placeholder has no tooltip
    tt_res = model.data(
        model.index(0, COLUMN_RESULT), int(Qt.ItemDataRole.ToolTipRole)
    )
    assert tt_res is None


def test_text_alignment_role(qapp: QApplication) -> None:
    """PID column is right-aligned; all other columns are left-aligned."""
    event = _make_sample_event(pid=1001)
    model = EventsTableModel(_make_sample_collection((event,), total=1))

    # PID is right-aligned
    pid_align = model.data(
        model.index(0, COLUMN_PID), int(Qt.ItemDataRole.TextAlignmentRole)
    )
    expected_pid_align = int(
        Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
    )
    assert pid_align == expected_pid_align

    # Other columns are left-aligned
    for col in (COLUMN_TIMESTAMP, COLUMN_SEVERITY, COLUMN_COMMAND):
        align = model.data(
            model.index(0, col), int(Qt.ItemDataRole.TextAlignmentRole)
        )
        expected_align = int(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        )
        assert align == expected_align


def test_severity_role_returns_lowercase_severity(qapp: QApplication) -> None:
    """SeverityRole returns the normalized lowercase severity."""
    event = _make_sample_event(severity="critical")
    model = EventsTableModel(_make_sample_collection((event,), total=1))
    assert model.data(model.index(0, COLUMN_SEVERITY), SeverityRole) == "critical"
    # Available on any column index for convenience
    assert model.data(model.index(0, COLUMN_TIMESTAMP), SeverityRole) == "critical"


def test_event_role_and_user_role_return_event_object(
    qapp: QApplication,
) -> None:
    """EventRole and UserRole return the exact original Event object."""
    event = _make_sample_event()
    model = EventsTableModel(_make_sample_collection((event,), total=1))

    assert model.data(model.index(0, 0), EventRole) is event
    assert (
        model.data(model.index(0, 0), int(Qt.ItemDataRole.UserRole)) is event
    )


# ==============================================================================
# Original Event Accessor Tests
# ==============================================================================


def test_event_at_and_get_event(qapp: QApplication) -> None:
    """event_at() and get_event() return exact Event or None if out of bounds."""
    e1 = _make_sample_event(SAMPLE_EVENT_ID_1)
    e2 = _make_sample_event(SAMPLE_EVENT_ID_2)
    model = EventsTableModel(_make_sample_collection((e1, e2), total=2))

    assert model.event_at(0) is e1
    assert model.get_event(0) is e1
    assert model.event_at(1) is e2
    assert model.get_event(1) is e2

    # Out of range row indexes
    assert model.event_at(-1) is None
    assert model.get_event(-1) is None
    assert model.event_at(2) is None
    assert model.get_event(2) is None


def test_hidden_fields_accessible_on_original_event(
    qapp: QApplication,
) -> None:
    """Hidden/detail fields not rendered in table remain accessible on Event."""
    event = _make_sample_event(
        event_id=SAMPLE_EVENT_ID_1,
        host_id=SAMPLE_HOST_ID,
        process_id=SAMPLE_PROCESS_ID,
        uid=5001,
        ppid=12,
        success=True,
        payload={"network": {"ip": "192.168.1.100"}},
    )
    model = EventsTableModel(_make_sample_collection((event,), total=1))
    retrieved = model.event_at(0)
    assert retrieved is not None
    assert retrieved.id == SAMPLE_EVENT_ID_1
    assert retrieved.host_id == SAMPLE_HOST_ID
    assert retrieved.process_id == SAMPLE_PROCESS_ID
    assert retrieved.uid == 5001
    assert retrieved.ppid == 12
    assert retrieved.success is True
    assert retrieved.payload == {"network": {"ip": "192.168.1.100"}}


# ==============================================================================
# Model Updates, Signals, and Reset Behavior
# ==============================================================================


def test_set_collection_updates_rows_and_emits_reset_signals(
    qapp: QApplication,
) -> None:
    """set_collection() replaces data and emits modelAboutToBeReset & modelReset."""
    model = EventsTableModel()
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

    e1 = _make_sample_event(SAMPLE_EVENT_ID_1)
    e2 = _make_sample_event(SAMPLE_EVENT_ID_2)
    col = _make_sample_collection((e1, e2), total=100, limit=2, offset=0)

    model.set_collection(col)

    assert reset_about_to_be_called is True
    assert reset_called is True
    assert model.rowCount() == 2
    assert model.total_count == 100
    assert model.limit == 2
    assert model.offset == 0
    assert model.collection is col
    assert model.events == (e1, e2)


def test_clear_model_resets_rows_and_metadata(qapp: QApplication) -> None:
    """clear() empties rows, resets metadata, and emits reset signals."""
    e = _make_sample_event()
    col = _make_sample_collection((e,), total=50)
    model = EventsTableModel(col)
    assert model.rowCount() == 1
    assert model.total_count == 50

    reset_called = False
    model.modelReset.connect(lambda: None)  # Verify connect works

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
    assert model.events == ()


def test_replace_with_empty_collection(qapp: QApplication) -> None:
    """Replacing data with an empty collection succeeds cleanly."""
    e = _make_sample_event()
    model = EventsTableModel(_make_sample_collection((e,), total=1))
    assert model.rowCount() == 1

    empty_col = _make_sample_collection((), total=0)
    model.set_collection(empty_col)

    assert model.rowCount() == 0
    assert model.total_count == 0
    assert model.events == ()


def test_set_collection_preserves_exact_record_order(
    qapp: QApplication,
) -> None:
    """set_collection() preserves the exact order of events without sorting."""
    e1 = _make_sample_event(SAMPLE_EVENT_ID_1, timestamp=SAMPLE_TIME_2)
    e2 = _make_sample_event(SAMPLE_EVENT_ID_2, timestamp=SAMPLE_TIME_1)
    # Provided out of chronological order
    col = _make_sample_collection((e1, e2), total=2)
    model = EventsTableModel(col)

    assert model.event_at(0) is e1
    assert model.event_at(1) is e2
    assert model.data(model.index(0, COLUMN_TIMESTAMP)) == SAMPLE_TIME_2
    assert model.data(model.index(1, COLUMN_TIMESTAMP)) == SAMPLE_TIME_1


# ==============================================================================
# Pagination Semantics Tests
# ==============================================================================


def test_pagination_metadata_preservation(qapp: QApplication) -> None:
    """Row count reflects current page size, total reflects server total."""
    e1 = _make_sample_event(SAMPLE_EVENT_ID_1)
    e2 = _make_sample_event(SAMPLE_EVENT_ID_2)
    # Page size is 2, but server has 250 total items, offset is 50, limit is 2
    col = _make_sample_collection(items=(e1, e2), total=250, limit=2, offset=50)
    model = EventsTableModel(col)

    assert model.rowCount() == 2
    assert model.total_count == 250
    assert model.total == 250
    assert model.limit == 2
    assert model.offset == 50


def test_empty_page_with_positive_server_total(qapp: QApplication) -> None:
    """Empty items with non-zero server total (e.g., offset past end)."""
    col = _make_sample_collection(items=(), total=15, limit=10, offset=20)
    model = EventsTableModel(col)

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
    with pytest.raises(TypeError, match="Expected EventCollection"):
        EventsTableModel(invalid_input)  # type: ignore[arg-type]


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
    event = _make_sample_event()
    col = _make_sample_collection((event,), total=1)
    model = EventsTableModel(col)
    assert model.rowCount() == 1

    with pytest.raises(TypeError, match="Expected EventCollection"):
        model.set_collection(invalid_input)  # type: ignore[arg-type]

    # Model remains intact and usable
    assert model.rowCount() == 1
    assert model.total_count == 1
    assert model.event_at(0) is event


# ==============================================================================
# Purity and Dependency Isolation Tests
# ==============================================================================


def test_model_module_has_no_backend_or_network_imports() -> None:
    """desktop.models.events_model does not import backend, httpx, or DB."""
    import desktop.models.events_model as mod

    # Verify no httpx, starlette, fastapi, or sqlalchemy in module symbols
    for prohibited in ("httpx", "fastapi", "starlette", "sqlalchemy", "respx"):
        assert not hasattr(mod, prohibited)

    # Check that sys.modules didn't get backend or collectors from this import
    for mod_name in sys.modules:
        if mod_name.startswith("desktop.models"):
            # Ensure the module itself doesn't import forbidden packages
            mod_obj = sys.modules[mod_name]
            for forbidden in ("httpx", "sqlalchemy"):
                assert forbidden not in mod_obj.__dict__


def test_events_model_index_boundary_and_invalid_column(
    qapp: QApplication,
) -> None:
    """EventsTableModel handles out-of-range row/col and invalid column index."""
    from desktop.models.events_model import EMPTY_PLACEHOLDER

    event = _make_sample_event()
    col = _make_sample_collection((event,), total=1)
    model = EventsTableModel(col)

    # Valid row, valid col
    assert model.data(model.index(0, 0)) is not None

    # Invalid rows
    assert model.data(model.createIndex(-1, 0)) is None
    assert model.data(model.createIndex(5, 0)) is None

    # Invalid cols
    assert model.data(model.createIndex(0, -1)) is None
    assert model.data(model.createIndex(0, 99)) is None

    # Formatting helper with unknown column returns EMPTY_PLACEHOLDER
    assert model._format_cell_display(event, 99) == EMPTY_PLACEHOLDER

