"""Unit tests for OSIRIS EventInspectorPanel.

Verifies:
1. Panel construction succeeds with default and custom parents.
2. Stable object names exist for panel, header, labels, badge, close button,
   and payload controls.
3. An actual Event instance is displayed accurately.
4. Setting None clears the displayed record, hides the badge, and hides panel.
5. Invalid inputs are rejected with TypeError.
6. current_event property returns the original Event object without mutation.
7. Severity is displayed via SeverityBadge with matching normalized severity.
8. All 19 defined event fields are represented correctly in value labels.
9. Absent optional fields are displayed with EMPTY_PLACEHOLDER and never 'None'.
10. PID, UID, and Parent PID equal to 0 are preserved and displayed as '0'.
11. Boolean False and True are displayed explicitly as 'False' and 'True'.
12. Long command strings and object paths are not truncated in source data.
13. Payload is formatted as deterministic read-only JSON.
14. Absent/empty payload is handled cleanly with placeholder.
15. Close button emits close_requested signal and hides the panel.
16. Clear method resets display and hides panel.
17. No HTTP, backend, database, or network modules are imported.
"""

from __future__ import annotations

import json
import sys
from typing import Any

import pytest
from PySide6.QtWidgets import (
    QApplication,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
)

from desktop.client.models import Event
from desktop.models.events_model import EMPTY_PLACEHOLDER
from desktop.ui.components import EventInspectorPanel, SeverityBadge
from desktop.ui.components.inspector_panel import FIELD_DEFINITIONS

SAMPLE_EVENT_ID = "11111111-1111-4111-8111-111111111111"
SAMPLE_HOST_ID = "22222222-2222-4222-8222-222222222222"
SAMPLE_PROCESS_ID = "33333333-3333-4333-8333-333333333333"
SAMPLE_TIMESTAMP = "2026-03-01T12:00:00Z"


_DEFAULT_PAYLOAD = object()


def _make_test_event(
    event_id: str = SAMPLE_EVENT_ID,
    host_id: str = SAMPLE_HOST_ID,
    severity: str = "high",
    source: str = "proc",
    event_type: str = "process.spawn",
    action: str = "execute",
    username: str | None = "investigator",
    uid: int | None = 1000,
    pid: int | None = 2048,
    ppid: int | None = 1,
    process_id: str | None = SAMPLE_PROCESS_ID,
    command: str | None = "/usr/bin/bash -c whoami",
    object_type: str | None = "process",
    object_path: str | None = "/bin/bash",
    success: bool | None = True,
    result: str | None = "success",
    payload: Any = _DEFAULT_PAYLOAD,
    timestamp: str = SAMPLE_TIMESTAMP,
) -> Event:
    """Create a valid Event instance for inspector panel testing."""
    resolved_payload = (
        {"param": "val"} if payload is _DEFAULT_PAYLOAD else payload
    )
    return Event(
        id=event_id,
        host_id=host_id,
        timestamp=timestamp,
        ingested_at=timestamp,
        source=source,
        event_type=event_type,
        action=action,
        severity=severity,
        created_at=timestamp,
        process_id=process_id,
        uid=uid,
        username=username,
        pid=pid,
        ppid=ppid,
        command=command,
        object_type=object_type,
        object_path=object_path,
        success=success,
        result=result,
        payload=resolved_payload,
    )


# ==============================================================================
# 1. Construction and Stable Object Names
# ==============================================================================


def test_inspector_panel_construction_empty(qapp: QApplication) -> None:
    """EventInspectorPanel constructs cleanly in empty initial state."""
    panel = EventInspectorPanel()
    assert panel is not None
    assert panel.objectName() == "EventInspectorPanel"
    assert panel.current_event is None
    assert panel.isVisible() is False
    assert panel.width() == 380
    assert panel.severity_badge.isVisible() is False


def test_inspector_panel_construction_with_event(qapp: QApplication) -> None:
    """EventInspectorPanel constructs with initial Event populated and visible."""
    event = _make_test_event()
    panel = EventInspectorPanel(event=event)
    assert panel.current_event is event
    assert panel.isVisible() is True
    assert panel.severity_badge.isVisible() is True
    assert panel.severity_badge.severity == "High"


def test_inspector_panel_stable_object_names(qapp: QApplication) -> None:
    """All key child widgets have stable, deterministic object names."""
    panel = EventInspectorPanel()

    assert panel.findChild(QLabel, "EventInspectorTitle") is not None
    assert panel.findChild(SeverityBadge, "EventInspectorSeverityBadge") is not None
    assert panel.findChild(QPushButton, "EventInspectorCloseButton") is not None
    assert panel.findChild(QScrollArea, "EventInspectorScrollArea") is not None
    assert panel.findChild(QLabel, "EventInspectorPayloadLabel") is not None
    assert panel.findChild(QPlainTextEdit, "EventInspectorPayloadEdit") is not None

    for key, _ in FIELD_DEFINITIONS:
        assert panel.findChild(QLabel, f"EventInspectorLabel_{key}") is not None
        assert panel.findChild(QLabel, f"EventInspectorValue_{key}") is not None


# ==============================================================================
# 2. Event Population and Data Fidelity
# ==============================================================================


def test_display_actual_event_all_fields(qapp: QApplication) -> None:
    """All fields of an Event instance are accurately displayed."""
    event = _make_test_event(
        severity="critical",
        source="network",
        event_type="connection.open",
        action="connect",
        username="sec_ops",
        uid=501,
        pid=9999,
        ppid=100,
        command="/usr/bin/curl https://api.internal",
        object_type="socket",
        object_path="/dev/tcp/10.0.0.1/443",
        success=True,
        result="established",
        payload={"dest_ip": "10.0.0.1", "dest_port": 443},
    )
    panel = EventInspectorPanel()
    panel.set_event(event)

    assert panel.current_event is event
    assert panel.get_field_value("id") == SAMPLE_EVENT_ID
    assert panel.get_field_value("host_id") == SAMPLE_HOST_ID
    assert panel.get_field_value("timestamp") == SAMPLE_TIMESTAMP
    assert panel.get_field_value("source") == "network"
    assert panel.get_field_value("event_type") == "connection.open"
    assert panel.get_field_value("action") == "connect"
    assert panel.get_field_value("severity") == "Critical"
    assert panel.get_field_value("username") == "sec_ops"
    assert panel.get_field_value("uid") == "501"
    assert panel.get_field_value("pid") == "9999"
    assert panel.get_field_value("ppid") == "100"
    assert panel.get_field_value("process_id") == SAMPLE_PROCESS_ID
    assert (
        panel.get_field_value("command")
        == "/usr/bin/curl https://api.internal"
    )
    assert panel.get_field_value("object_type") == "socket"
    assert panel.get_field_value("object_path") == "/dev/tcp/10.0.0.1/443"
    assert panel.get_field_value("success") == "True"
    assert panel.get_field_value("result") == "established"


def test_severity_badge_reflects_event_severity(qapp: QApplication) -> None:
    """Severity badge text and property update with event severity."""
    for sev in ("critical", "high", "medium", "low", "info"):
        event = _make_test_event(severity=sev)
        panel = EventInspectorPanel()
        panel.set_event(event)

        badge = panel.severity_badge
        assert badge.isVisible() is True
        assert badge.severity_key == sev
        assert badge.text() == sev.capitalize()


def test_numeric_zero_values_preserved(qapp: QApplication) -> None:
    """Numeric 0 values for PID, UID, and PPID are preserved as '0'."""
    event = _make_test_event(
        pid=0,
        uid=0,
        ppid=0,
    )
    panel = EventInspectorPanel(event)

    assert panel.get_field_value("pid") == "0"
    assert panel.get_field_value("uid") == "0"
    assert panel.get_field_value("ppid") == "0"


def test_boolean_values_displayed_explicitly(qapp: QApplication) -> None:
    """Boolean True and False are displayed explicitly, never treated as absent."""
    event_false = _make_test_event(success=False)
    panel = EventInspectorPanel(event_false)
    assert panel.get_field_value("success") == "False"

    event_true = _make_test_event(success=True)
    panel.set_event(event_true)
    assert panel.get_field_value("success") == "True"

    event_none = _make_test_event(success=None)
    panel.set_event(event_none)
    assert panel.get_field_value("success") == EMPTY_PLACEHOLDER


def test_absent_optional_fields_display_placeholder(
    qapp: QApplication,
) -> None:
    """Absent optional fields display the em dash placeholder and never 'None'."""
    event = _make_test_event(
        process_id=None,
        uid=None,
        username=None,
        pid=None,
        ppid=None,
        command=None,
        object_type=None,
        object_path=None,
        success=None,
        result=None,
        payload=None,
    )
    panel = EventInspectorPanel(event)

    for key in (
        "process_id",
        "uid",
        "username",
        "pid",
        "ppid",
        "command",
        "object_type",
        "object_path",
        "success",
        "result",
    ):
        val = panel.get_field_value(key)
        assert val == EMPTY_PLACEHOLDER
        assert val != "None"
        assert "None" not in val


def test_long_command_and_path_not_truncated(qapp: QApplication) -> None:
    """Long command strings and object paths are fully retained without truncation."""
    long_cmd = "/usr/local/bin/agent " + " ".join(f"--opt-{i}=val" for i in range(150))
    long_path = "/var/log/system/archive/subpath/" + "a" * 200 + ".log"

    event = _make_test_event(command=long_cmd, object_path=long_path)
    panel = EventInspectorPanel(event)

    assert panel.get_field_value("command") == long_cmd
    assert panel.get_field_value("object_path") == long_path
    # Source event remains unmodified
    assert panel.current_event is not None
    assert panel.current_event.command is long_cmd


# ==============================================================================
# 3. Payload Viewer Functionality
# ==============================================================================


def test_payload_formatted_deterministic_json(qapp: QApplication) -> None:
    """Populated payload is formatted as deterministic indented JSON."""
    raw_payload = {
        "zeta": 1,
        "alpha": "first",
        "nested": {"beta": True, "unicode": "✓ test"},
    }
    event = _make_test_event(payload=raw_payload)
    panel = EventInspectorPanel(event)

    text = panel.get_payload_text()
    assert text != EMPTY_PLACEHOLDER

    # Deterministic: keys sorted, unicode preserved
    expected = json.dumps(raw_payload, indent=2, sort_keys=True, ensure_ascii=False)
    assert text == expected

    # Payload editor is read-only
    assert panel.payload_edit.isReadOnly() is True


def test_payload_absent_or_empty_handled(qapp: QApplication) -> None:
    """Absent or empty payload dict displays EMPTY_PLACEHOLDER."""
    # None payload
    event_none = _make_test_event(payload=None)
    panel = EventInspectorPanel(event_none)
    assert panel.get_payload_text() == EMPTY_PLACEHOLDER

    # Empty dict payload
    event_empty = _make_test_event(payload={})
    panel.set_event(event_empty)
    assert panel.get_payload_text() == EMPTY_PLACEHOLDER


# ==============================================================================
# 4. State Transitions, Clearing, and Signals
# ==============================================================================


def test_set_event_none_clears_and_hides_panel(qapp: QApplication) -> None:
    """set_event(None) clears displayed fields and hides the inspector panel."""
    event = _make_test_event()
    panel = EventInspectorPanel(event)
    assert panel.isVisible() is True
    assert panel.current_event is event

    panel.set_event(None)
    assert panel.current_event is None
    assert panel.isVisible() is False
    assert panel.severity_badge.isVisible() is False
    assert panel.get_field_value("id") == EMPTY_PLACEHOLDER
    assert panel.get_payload_text() == EMPTY_PLACEHOLDER


def test_clear_method_clears_and_hides_panel(qapp: QApplication) -> None:
    """clear() is a clean alias for set_event(None)."""
    event = _make_test_event()
    panel = EventInspectorPanel(event)
    assert panel.isVisible() is True

    panel.clear()
    assert panel.current_event is None
    assert panel.isVisible() is False


def test_close_button_emits_signal_and_hides_panel(
    qapp: QApplication,
) -> None:
    """Clicking close button emits close_requested and hides the panel."""
    event = _make_test_event()
    panel = EventInspectorPanel(event)
    panel.show()
    assert panel.isVisible() is True

    emitted: list[bool] = []
    panel.close_requested.connect(lambda: emitted.append(True))

    panel.close_button.click()

    assert emitted == [True]
    assert panel.isVisible() is False
    # Original event data remains intact
    assert panel.current_event is event


def test_set_event_rejects_invalid_type(qapp: QApplication) -> None:
    """set_event raises TypeError on invalid types and preserves state."""
    event = _make_test_event()
    panel = EventInspectorPanel(event)

    for invalid in ("not an event", 123, {"id": "1"}, [event]):
        with pytest.raises(TypeError, match="Expected Event or None"):
            panel.set_event(invalid)  # type: ignore[arg-type]

    # Preserved state
    assert panel.current_event is event


def test_unknown_field_key_raises_keyerror(qapp: QApplication) -> None:
    """get_field_value raises KeyError for non-existent field keys."""
    panel = EventInspectorPanel()
    with pytest.raises(KeyError, match="Unknown field key"):
        panel.get_field_value("non_existent_key")


def test_inspector_panel_getters_and_formatting_fallbacks(
    qapp: QApplication,
) -> None:
    """Test title_label, field_labels, field_values, and formatting fallbacks."""
    panel = EventInspectorPanel()
    assert panel.title_label is not None
    assert "id" in panel.field_labels
    assert "id" in panel.field_values

    # Test field value formatting with dummy object
    class DummyEvent:
        empty_str = "   "
        other_val = 12.34

    dummy = DummyEvent()
    assert (
        panel._format_field_value(dummy, "empty_str")  # type: ignore[arg-type]
        == EMPTY_PLACEHOLDER
    )
    assert panel._format_field_value(dummy, "other_val") == "12.34"  # type: ignore[arg-type]

    # Payload with non-serializable object falls back to str(payload)
    bad_payload = {"unserializable": object()}
    res = panel._format_payload(bad_payload)  # type: ignore[arg-type]
    assert "unserializable" in res


# ==============================================================================
# 5. Dependency Purity
# ==============================================================================


def test_inspector_panel_has_no_backend_or_http_imports() -> None:
    """desktop.ui.components.inspector_panel has no network or DB dependencies."""
    import desktop.ui.components.inspector_panel as mod

    for prohibited in ("httpx", "fastapi", "starlette", "sqlalchemy", "respx"):
        assert not hasattr(mod, prohibited)

    for mod_name in sys.modules:
        if mod_name.startswith("desktop.ui.components.inspector_panel"):
            mod_obj = sys.modules[mod_name]
            for forbidden in ("httpx", "sqlalchemy"):
                assert forbidden not in mod_obj.__dict__
