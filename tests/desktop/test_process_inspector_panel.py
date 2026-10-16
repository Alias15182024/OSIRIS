"""Unit tests for OSIRIS ProcessInspectorPanel.

Verifies:
1. Panel construction succeeds with default and custom parents.
2. Stable object names exist for panel, header, title, close button,
   scroll area, content container, and all field labels and values.
3. An actual Process instance is displayed accurately across all fields.
4. Active status is displayed as 'Active' when is_active is True.
5. Terminated status is displayed as 'Terminated' when is_active is False.
6. Setting None clears the displayed record and hides the panel.
7. Clear method is an exact functional alias for set_process(None).
8. Invalid inputs are rejected with TypeError without corrupting existing state.
9. current_process property returns the original immutable Process object.
10. All 11 defined process fields are represented correctly in value labels.
11. Absent optional fields are displayed with EMPTY_PLACEHOLDER and never 'None'.
12. PID and PPID equal to 0 are preserved and displayed as '0'.
13. Long command strings and executable paths are not truncated in source data.
14. Close button emits close_requested signal and hides the panel.
15. Unknown field keys raise KeyError.
16. No HTTP, backend, database, or network modules are imported.
"""

from __future__ import annotations

import sys

import pytest
from PySide6.QtWidgets import (
    QApplication,
    QLabel,
    QPushButton,
    QScrollArea,
    QWidget,
)

from desktop.client.models import Process
from desktop.models.processes_model import EMPTY_PLACEHOLDER
from desktop.ui.components import ProcessInspectorPanel
from desktop.ui.components.process_inspector_panel import FIELD_DEFINITIONS

SAMPLE_PROCESS_ID = "11111111-1111-4111-8111-111111111111"
SAMPLE_HOST_ID = "22222222-2222-4222-8222-222222222222"
SAMPLE_LINUX_USER_ID = "33333333-3333-4333-8333-333333333333"
SAMPLE_STARTED_AT = "2026-03-01T12:00:00Z"
SAMPLE_ENDED_AT = "2026-03-01T12:05:00Z"
SAMPLE_CREATED_AT = "2026-03-01T12:00:00Z"


def _make_test_process(
    process_id: str = SAMPLE_PROCESS_ID,
    host_id: str = SAMPLE_HOST_ID,
    pid: int = 1234,
    command: str = "/usr/bin/python3 -m app",
    started_at: str = SAMPLE_STARTED_AT,
    created_at: str = SAMPLE_CREATED_AT,
    ppid: int | None = 1,
    executable: str | None = "/usr/bin/python3",
    linux_user_id: str | None = SAMPLE_LINUX_USER_ID,
    ended_at: str | None = None,
) -> Process:
    """Create a valid Process instance for inspector panel testing."""
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


# ==============================================================================
# 1. Construction and Stable Object Names
# ==============================================================================


def test_inspector_panel_construction_empty(qapp: QApplication) -> None:
    """ProcessInspectorPanel constructs cleanly in empty initial state."""
    panel = ProcessInspectorPanel()
    assert panel is not None
    assert panel.objectName() == "ProcessInspectorPanel"
    assert panel.current_process is None
    assert panel.isVisible() is False
    assert panel.width() == 380


def test_inspector_panel_construction_with_parent(qapp: QApplication) -> None:
    """ProcessInspectorPanel constructs cleanly with a custom parent QWidget."""
    parent = QWidget()
    panel = ProcessInspectorPanel(parent=parent)
    assert panel.parent() is parent
    assert panel.current_process is None
    assert panel.isVisible() is False


def test_inspector_panel_construction_with_process(qapp: QApplication) -> None:
    """ProcessInspectorPanel constructs with initial Process populated and visible."""
    process = _make_test_process()
    panel = ProcessInspectorPanel(process=process)
    assert panel.current_process is process
    assert panel.isVisible() is True
    assert panel.get_field_value("id") == SAMPLE_PROCESS_ID
    assert panel.get_field_value("status") == "Active"


def test_inspector_panel_stable_object_names(qapp: QApplication) -> None:
    """All key child widgets have stable, deterministic object names."""
    panel = ProcessInspectorPanel()

    assert panel.findChild(QWidget, "ProcessInspectorHeader") is not None
    assert panel.findChild(QLabel, "ProcessInspectorTitle") is not None
    assert panel.findChild(QPushButton, "ProcessInspectorCloseButton") is not None
    assert panel.findChild(QScrollArea, "ProcessInspectorScrollArea") is not None
    assert panel.findChild(QWidget, "ProcessInspectorContent") is not None

    for key, _ in FIELD_DEFINITIONS:
        assert panel.findChild(QLabel, f"ProcessInspectorLabel_{key}") is not None
        assert panel.findChild(QLabel, f"ProcessInspectorValue_{key}") is not None


# ==============================================================================
# 2. Process Population and Field Display Fidelity
# ==============================================================================


def test_display_actual_process_all_fields(qapp: QApplication) -> None:
    """All fields of a Process instance are accurately displayed."""
    process = _make_test_process(
        process_id=SAMPLE_PROCESS_ID,
        host_id=SAMPLE_HOST_ID,
        pid=4567,
        ppid=100,
        command="/usr/sbin/sshd -D",
        executable="/usr/sbin/sshd",
        linux_user_id=SAMPLE_LINUX_USER_ID,
        started_at=SAMPLE_STARTED_AT,
        ended_at=SAMPLE_ENDED_AT,
        created_at=SAMPLE_CREATED_AT,
    )
    panel = ProcessInspectorPanel()
    panel.set_process(process)

    assert panel.current_process is process
    assert panel.get_field_value("id") == SAMPLE_PROCESS_ID
    assert panel.get_field_value("host_id") == SAMPLE_HOST_ID
    assert panel.get_field_value("pid") == "4567"
    assert panel.get_field_value("ppid") == "100"
    assert panel.get_field_value("command") == "/usr/sbin/sshd -D"
    assert panel.get_field_value("executable") == "/usr/sbin/sshd"
    assert panel.get_field_value("linux_user_id") == SAMPLE_LINUX_USER_ID
    assert panel.get_field_value("status") == "Terminated"
    assert panel.get_field_value("started_at") == SAMPLE_STARTED_AT
    assert panel.get_field_value("ended_at") == SAMPLE_ENDED_AT
    assert panel.get_field_value("created_at") == SAMPLE_CREATED_AT


def test_active_status_presentation(qapp: QApplication) -> None:
    """When ended_at is None, is_active is True and status displays 'Active'."""
    process = _make_test_process(ended_at=None)
    assert process.is_active is True

    panel = ProcessInspectorPanel(process)
    assert panel.get_field_value("status") == "Active"
    assert panel.get_field_value("is_active") == "Active"
    assert panel.status_label.text() == "Active"
    assert panel.status_badge.text() == "Active"
    assert panel.status_label.property("status") == "active"


def test_terminated_status_presentation(qapp: QApplication) -> None:
    """When ended_at is set, is_active is False and status displays 'Terminated'."""
    process = _make_test_process(ended_at=SAMPLE_ENDED_AT)
    assert process.is_active is False

    panel = ProcessInspectorPanel(process)
    assert panel.get_field_value("status") == "Terminated"
    assert panel.get_field_value("is_active") == "Terminated"
    assert panel.status_label.text() == "Terminated"
    assert panel.status_badge.text() == "Terminated"
    assert panel.status_label.property("status") == "terminated"


def test_numeric_zero_values_preserved(qapp: QApplication) -> None:
    """Numeric 0 values for PID and PPID are preserved as '0'."""
    process = _make_test_process(pid=0, ppid=0)
    panel = ProcessInspectorPanel(process)

    assert panel.get_field_value("pid") == "0"
    assert panel.get_field_value("ppid") == "0"


def test_absent_optional_fields_display_placeholder(
    qapp: QApplication,
) -> None:
    """Absent optional fields display the em dash placeholder and never 'None'."""
    process = _make_test_process(
        ppid=None,
        executable=None,
        linux_user_id=None,
        ended_at=None,
    )
    panel = ProcessInspectorPanel(process)

    for key in ("ppid", "executable", "linux_user_id", "ended_at"):
        val = panel.get_field_value(key)
        assert val == EMPTY_PLACEHOLDER
        assert val != "None"
        assert "None" not in val


def test_long_command_and_path_not_truncated(qapp: QApplication) -> None:
    """Long command strings and executable paths are fully retained."""
    long_cmd = (
        "/opt/tools/bin/runner " + " ".join(f"--flag-{i}=val" for i in range(120))
    )
    long_path = "/usr/local/opt/custom/subpath/" + "b" * 180 + "/app.bin"

    process = _make_test_process(command=long_cmd, executable=long_path)
    panel = ProcessInspectorPanel(process)

    assert panel.get_field_value("command") == long_cmd
    assert panel.get_field_value("executable") == long_path
    assert panel.current_process is not None
    assert panel.current_process.command is long_cmd
    assert panel.current_process.executable is long_path


def test_current_process_retains_identity(qapp: QApplication) -> None:
    """current_process returns the exact immutable Process instance without mutation."""
    process = _make_test_process()
    panel = ProcessInspectorPanel(process)
    assert panel.current_process is process


# ==============================================================================
# 3. State Transitions, Clearing, and Signals
# ==============================================================================


def test_set_process_none_clears_and_hides_panel(qapp: QApplication) -> None:
    """set_process(None) clears displayed fields and hides the inspector panel."""
    process = _make_test_process()
    panel = ProcessInspectorPanel(process)
    assert panel.isVisible() is True
    assert panel.current_process is process

    panel.set_process(None)
    assert panel.current_process is None
    assert panel.isVisible() is False
    assert panel.get_field_value("id") == EMPTY_PLACEHOLDER
    assert panel.get_field_value("pid") == EMPTY_PLACEHOLDER
    assert panel.get_field_value("status") == EMPTY_PLACEHOLDER


def test_clear_method_clears_and_hides_panel(qapp: QApplication) -> None:
    """clear() is a clean alias for set_process(None)."""
    process = _make_test_process()
    panel = ProcessInspectorPanel(process)
    assert panel.isVisible() is True

    panel.clear()
    assert panel.current_process is None
    assert panel.isVisible() is False


def test_close_button_emits_signal_and_hides_panel(
    qapp: QApplication,
) -> None:
    """Clicking close button emits close_requested and hides the panel."""
    process = _make_test_process()
    panel = ProcessInspectorPanel(process)
    panel.show()
    assert panel.isVisible() is True

    emitted: list[bool] = []
    panel.close_requested.connect(lambda: emitted.append(True))

    panel.close_button.click()

    assert emitted == [True]
    assert panel.isVisible() is False
    # Original process data retained until clear/new selection
    assert panel.current_process is process


def test_set_process_rejects_invalid_type(qapp: QApplication) -> None:
    """set_process raises TypeError on invalid types and preserves previous state."""
    process = _make_test_process()
    panel = ProcessInspectorPanel(process)

    for invalid in ("not a process", 1234, {"id": "1"}, [process]):
        with pytest.raises(TypeError, match="Expected Process or None"):
            panel.set_process(invalid)  # type: ignore[arg-type]

    # Preserved state
    assert panel.current_process is process


def test_unknown_field_key_raises_keyerror(qapp: QApplication) -> None:
    """get_field_value raises KeyError for unrecognized field keys."""
    panel = ProcessInspectorPanel()
    with pytest.raises(KeyError, match="Unknown field key"):
        panel.get_field_value("non_existent_field")


def test_field_labels_and_values_mappings(qapp: QApplication) -> None:
    """field_labels and field_values properties expose full dict of child labels."""
    process = _make_test_process()
    panel = ProcessInspectorPanel(process)

    labels = panel.field_labels
    values = panel.field_values

    assert len(labels) == len(FIELD_DEFINITIONS)
    assert len(values) == len(FIELD_DEFINITIONS)

    for key, label_text in FIELD_DEFINITIONS:
        assert key in labels
        assert key in values
        assert labels[key].text() == label_text


def test_properties_expose_expected_widgets(qapp: QApplication) -> None:
    """Public properties title_label, close_button, scroll_area expose valid widgets."""
    panel = ProcessInspectorPanel()
    assert isinstance(panel.title_label, QLabel)
    assert panel.title_label.text() == "Process Details"
    assert isinstance(panel.close_button, QPushButton)
    assert isinstance(panel.scroll_area, QScrollArea)


def test_process_inspector_panel_field_fallbacks(qapp: QApplication) -> None:
    """Test get_field_value('process_id') and field formatting fallbacks."""
    proc = _make_test_process()
    panel = ProcessInspectorPanel()
    panel.set_process(proc)

    # get_field_value("process_id") alias
    assert panel.get_field_value("process_id") == SAMPLE_PROCESS_ID

    # Test dummy field formatting
    class DummyProc:
        bool_val = True
        empty_str = "   "
        other_val = 42.5

    dummy = DummyProc()
    assert (
        panel._format_field_value(dummy, "bool_val")  # type: ignore[arg-type]
        == "True"
    )
    assert (
        panel._format_field_value(dummy, "empty_str")  # type: ignore[arg-type]
        == EMPTY_PLACEHOLDER
    )
    assert (
        panel._format_field_value(dummy, "other_val")  # type: ignore[arg-type]
        == "42.5"
    )


# ==============================================================================
# 4. Dependency Purity
# ==============================================================================


def test_inspector_panel_has_no_backend_or_http_imports() -> None:
    """process_inspector_panel has no network or DB dependencies."""
    import desktop.ui.components.process_inspector_panel as mod

    for prohibited in ("httpx", "fastapi", "starlette", "sqlalchemy", "respx"):
        assert not hasattr(mod, prohibited)

    for mod_name in sys.modules:
        if mod_name.startswith("desktop.ui.components.process_inspector_panel"):
            mod_obj = sys.modules[mod_name]
            for forbidden in ("httpx", "sqlalchemy"):
                assert forbidden not in mod_obj.__dict__
