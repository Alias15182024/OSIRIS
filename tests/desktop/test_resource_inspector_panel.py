"""Unit tests for OSIRIS ResourceInspectorPanel.

Verifies:
1. Panel construction succeeds with default and custom parents.
2. Stable object names exist for panel, header, title, close button,
   scroll area, content container, and all field labels and values.
3. An actual ResourceSnapshot instance is displayed accurately across all fields.
4. Non-lossy byte representation alongside human-readable binary units.
5. Numeric zero values (0.0%, 0 bytes) are preserved and never shown as missing.
6. Absent optional fields are displayed with EMPTY_PLACEHOLDER and never 'None' or 0.
7. Setting None clears the displayed record and hides the panel.
8. Clear method is an exact functional alias for set_snapshot(None).
9. Invalid inputs are rejected with TypeError without corrupting existing state.
10. current_snapshot property returns the original immutable ResourceSnapshot object.
11. All 11 defined resource fields are represented correctly in value labels.
12. Field aliases in get_field_value are supported.
13. Close button emits close_requested signal and hides the panel.
14. Unknown field keys raise KeyError.
15. No HTTP, backend, database, or network modules are imported.
"""

from __future__ import annotations

import sys

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QLabel,
    QPushButton,
    QScrollArea,
    QWidget,
)

from desktop.client.models import ResourceSnapshot
from desktop.models.resources_model import EMPTY_PLACEHOLDER
from desktop.ui.components import ResourceInspectorPanel
from desktop.ui.components.resource_inspector_panel import (
    RESOURCE_FIELD_DEFINITIONS,
)

SAMPLE_SNAPSHOT_ID = "11111111-1111-4111-8111-111111111111"
SAMPLE_HOST_ID = "22222222-2222-4222-8222-222222222222"
SAMPLE_TIMESTAMP = "2026-03-01T12:00:00Z"
SAMPLE_CREATED_AT = "2026-03-01T12:00:01Z"


def _make_test_snapshot(
    snapshot_id: str = SAMPLE_SNAPSHOT_ID,
    host_id: str = SAMPLE_HOST_ID,
    timestamp: str = SAMPLE_TIMESTAMP,
    created_at: str = SAMPLE_CREATED_AT,
    cpu_percent: float | None = 25.5,
    memory_total: int | None = 17_179_869_184,  # 16 GiB
    memory_used: int | None = 8_589_934_592,  # 8 GiB
    memory_percent: float | None = 50.0,
    disk_read_bytes: int | None = 1048576,  # 1 MiB
    disk_write_bytes: int | None = 2097152,  # 2 MiB
    disk_usage_percent: float | None = 62.3,
) -> ResourceSnapshot:
    """Create a valid ResourceSnapshot instance for inspector panel testing."""
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


# ==============================================================================
# 1. Construction and Stable Object Names
# ==============================================================================


def test_resource_inspector_construction_empty(qapp: QApplication) -> None:
    """ResourceInspectorPanel constructs cleanly in empty initial state."""
    panel = ResourceInspectorPanel()
    assert panel is not None
    assert panel.objectName() == "ResourceInspectorPanel"
    assert panel.current_snapshot is None
    assert panel.isVisible() is False
    assert panel.width() == 380


def test_resource_inspector_construction_with_parent(
    qapp: QApplication,
) -> None:
    """ResourceInspectorPanel constructs cleanly with a custom parent QWidget."""
    parent = QWidget()
    panel = ResourceInspectorPanel(parent=parent)
    assert panel.parent() is parent
    assert panel.current_snapshot is None
    assert panel.isVisible() is False


def test_resource_inspector_construction_with_snapshot(
    qapp: QApplication,
) -> None:
    """ResourceInspectorPanel constructs with initial snapshot populated and visible."""
    snapshot = _make_test_snapshot()
    panel = ResourceInspectorPanel(snapshot=snapshot)
    assert panel.current_snapshot is snapshot
    assert panel.isVisible() is True
    assert panel.get_field_value("id") == SAMPLE_SNAPSHOT_ID
    assert panel.get_field_value("cpu_percent") == "25.5%"


def test_resource_inspector_stable_object_names(qapp: QApplication) -> None:
    """All key child widgets have stable, deterministic object names."""
    panel = ResourceInspectorPanel()

    assert panel.findChild(QWidget, "ResourceInspectorHeader") is not None
    assert panel.findChild(QLabel, "ResourceInspectorTitle") is not None
    assert panel.findChild(QPushButton, "ResourceInspectorCloseButton") is not None
    assert panel.findChild(QScrollArea, "ResourceInspectorScrollArea") is not None
    assert panel.findChild(QWidget, "ResourceInspectorContent") is not None

    for key, _ in RESOURCE_FIELD_DEFINITIONS:
        assert panel.findChild(QLabel, f"ResourceInspectorLabel_{key}") is not None
        assert panel.findChild(QLabel, f"ResourceInspectorValue_{key}") is not None


# ==============================================================================
# 2. Snapshot Population and Field Display Fidelity
# ==============================================================================


def test_display_actual_snapshot_all_fields(qapp: QApplication) -> None:
    """All 11 fields of a ResourceSnapshot instance are accurately displayed."""
    snapshot = _make_test_snapshot()
    panel = ResourceInspectorPanel()
    panel.set_snapshot(snapshot)

    assert panel.current_snapshot is snapshot
    assert panel.get_field_value("id") == SAMPLE_SNAPSHOT_ID
    assert panel.get_field_value("host_id") == SAMPLE_HOST_ID
    assert panel.get_field_value("timestamp") == SAMPLE_TIMESTAMP
    assert panel.get_field_value("created_at") == SAMPLE_CREATED_AT
    assert panel.get_field_value("cpu_percent") == "25.5%"
    assert panel.get_field_value("memory_percent") == "50.0%"
    assert panel.get_field_value("disk_usage_percent") == "62.3%"
    assert "8.0 GiB" in panel.get_field_value("memory_used")
    assert "8,589,934,592 bytes" in panel.get_field_value("memory_used")
    assert "16.0 GiB" in panel.get_field_value("memory_total")
    assert "17,179,869,184 bytes" in panel.get_field_value("memory_total")
    assert "1.0 MiB" in panel.get_field_value("disk_read_bytes")
    assert "1,048,576 bytes" in panel.get_field_value("disk_read_bytes")
    assert "2.0 MiB" in panel.get_field_value("disk_write_bytes")
    assert "2,097,152 bytes" in panel.get_field_value("disk_write_bytes")


def test_numeric_zero_values_preserved(qapp: QApplication) -> None:
    """Numeric 0 values for percentages and bytes are preserved, not None."""
    snapshot = _make_test_snapshot(
        cpu_percent=0.0,
        memory_percent=0.0,
        disk_usage_percent=0.0,
        memory_used=0,
        disk_read_bytes=0,
        disk_write_bytes=0,
    )
    panel = ResourceInspectorPanel(snapshot)

    assert panel.get_field_value("cpu_percent") == "0.0%"
    assert panel.get_field_value("memory_percent") == "0.0%"
    assert panel.get_field_value("disk_usage_percent") == "0.0%"
    assert "0 B" in panel.get_field_value("memory_used")
    assert "0 bytes" in panel.get_field_value("memory_used")
    assert "0 B" in panel.get_field_value("disk_read_bytes")
    assert "0 bytes" in panel.get_field_value("disk_read_bytes")
    assert "0 B" in panel.get_field_value("disk_write_bytes")
    assert "0 bytes" in panel.get_field_value("disk_write_bytes")


def test_absent_nullable_fields_display_placeholder(
    qapp: QApplication,
) -> None:
    """Absent nullable metrics display EMPTY_PLACEHOLDER ('—') and never 'None' or 0."""
    snapshot = _make_test_snapshot(
        cpu_percent=None,
        memory_total=None,
        memory_used=None,
        memory_percent=None,
        disk_read_bytes=None,
        disk_write_bytes=None,
        disk_usage_percent=None,
    )
    panel = ResourceInspectorPanel(snapshot)

    for key in (
        "cpu_percent",
        "memory_percent",
        "memory_used",
        "memory_total",
        "disk_read_bytes",
        "disk_write_bytes",
        "disk_usage_percent",
    ):
        val = panel.get_field_value(key)
        assert val == EMPTY_PLACEHOLDER
        assert val != "None"
        assert val != "0"
        assert val != "0.0%"


def test_current_snapshot_retains_identity(qapp: QApplication) -> None:
    """current_snapshot returns the exact immutable ResourceSnapshot instance."""
    snapshot = _make_test_snapshot()
    panel = ResourceInspectorPanel(snapshot)
    assert panel.current_snapshot is snapshot
    assert panel.current_resource is snapshot
    assert panel.snapshot is snapshot


def test_field_value_key_aliases(qapp: QApplication) -> None:
    """get_field_value supports recognized field key aliases."""
    snapshot = _make_test_snapshot()
    panel = ResourceInspectorPanel(snapshot)

    assert panel.get_field_value("snapshot_id") == panel.get_field_value("id")
    assert panel.get_field_value("host") == panel.get_field_value("host_id")
    assert panel.get_field_value("created") == panel.get_field_value("created_at")
    assert panel.get_field_value("cpu") == panel.get_field_value("cpu_percent")
    assert panel.get_field_value("memory") == panel.get_field_value("memory_percent")
    assert panel.get_field_value("disk_read") == panel.get_field_value(
        "disk_read_bytes"
    )
    assert panel.get_field_value("disk_write") == panel.get_field_value(
        "disk_write_bytes"
    )
    assert panel.get_field_value("disk_usage") == panel.get_field_value(
        "disk_usage_percent"
    )


def test_unknown_field_key_raises_key_error(qapp: QApplication) -> None:
    """Requesting an unknown field key raises KeyError."""
    panel = ResourceInspectorPanel()
    with pytest.raises(KeyError, match="Unknown field key"):
        panel.get_field_value("nonexistent_key")


# ==============================================================================
# 3. State Transitions, Clearing, and Signals
# ==============================================================================


def test_set_snapshot_none_clears_and_hides_panel(qapp: QApplication) -> None:
    """set_snapshot(None) clears displayed fields and hides the inspector panel."""
    snapshot = _make_test_snapshot()
    panel = ResourceInspectorPanel(snapshot)
    assert panel.isVisible() is True
    assert panel.current_snapshot is snapshot

    panel.set_snapshot(None)
    assert panel.isVisible() is False
    assert panel.current_snapshot is None

    for key, _ in RESOURCE_FIELD_DEFINITIONS:
        assert panel.get_field_value(key) == EMPTY_PLACEHOLDER


def test_clear_method_clears_and_hides_panel(qapp: QApplication) -> None:
    """clear() method is a functional alias for set_snapshot(None)."""
    snapshot = _make_test_snapshot()
    panel = ResourceInspectorPanel(snapshot)
    assert panel.isVisible() is True

    panel.clear()
    assert panel.isVisible() is False
    assert panel.current_snapshot is None


def test_invalid_snapshot_type_raises_type_error(qapp: QApplication) -> None:
    """set_snapshot raises TypeError for non-ResourceSnapshot objects."""
    panel = ResourceInspectorPanel()
    with pytest.raises(TypeError, match="Expected ResourceSnapshot or None"):
        panel.set_snapshot("invalid_snapshot")  # type: ignore[arg-type]


def test_close_button_emits_close_requested(qapp: QApplication) -> None:
    """Clicking close button emits close_requested signal and hides the panel."""
    snapshot = _make_test_snapshot()
    panel = ResourceInspectorPanel(snapshot)
    assert panel.isVisible() is True

    received: list[bool] = []
    panel.close_requested.connect(lambda: received.append(True))

    panel.close_button.click()
    assert len(received) == 1
    assert panel.isVisible() is False


def test_value_labels_text_selectable_by_mouse(qapp: QApplication) -> None:
    """Value labels allow text selection by mouse for investigator copying."""
    panel = ResourceInspectorPanel()
    for key, lbl in panel.field_values.items():
        flags = lbl.textInteractionFlags()
        assert bool(flags & Qt.TextInteractionFlag.TextSelectableByMouse), (
            f"Field {key} value label should be selectable by mouse"
        )


def test_byte_metric_singular_byte(qapp: QApplication) -> None:
    """Byte metric displays singular 'byte' when counter equals 1."""
    snapshot = _make_test_snapshot(
        memory_used=1,
        disk_read_bytes=1,
    )
    panel = ResourceInspectorPanel(snapshot)
    assert panel.get_field_value("memory_used") == "1 B (1 byte)"
    assert panel.get_field_value("disk_read_bytes") == "1 B (1 byte)"


def test_rapid_selection_simulation_no_lag_or_mutation(
    qapp: QApplication,
) -> None:
    """Rapid sequential snapshot updates execute synchronously without errors."""
    panel = ResourceInspectorPanel()
    for i in range(50):
        snap = _make_test_snapshot(
            snapshot_id=f"00000000-0000-0000-0000-{i:012d}",
            cpu_percent=float(i % 100),
        )
        panel.set_snapshot(snap)
        assert panel.get_field_value("id") == f"00000000-0000-0000-0000-{i:012d}"
        assert panel.get_field_value("cpu_percent") == f"{float(i % 100):.1f}%"


def test_resource_inspector_panel_properties_and_fallbacks(
    qapp: QApplication,
) -> None:
    """Test properties, set_resource alias, and formatting fallbacks."""
    panel = ResourceInspectorPanel()
    assert panel.title_label is not None
    assert panel.scroll_area is not None
    assert "id" in panel.field_labels

    snap = _make_test_snapshot()
    panel.set_resource(snap)
    assert panel.current_snapshot is snap

    # Test dummy field formatting
    class DummySnapshot:
        empty_str = "   "
        other_val = 98.76

    dummy = DummySnapshot()
    assert (
        panel._format_field_value(dummy, "empty_str")  # type: ignore[arg-type]
        == EMPTY_PLACEHOLDER
    )
    assert (
        panel._format_field_value(dummy, "other_val")  # type: ignore[arg-type]
        == "98.76"
    )
    assert (
        panel._format_field_value(dummy, "nonexistent")  # type: ignore[arg-type]
        == EMPTY_PLACEHOLDER
    )


def test_inspector_panel_has_no_backend_or_http_imports() -> None:
    """resource_inspector_panel has no network or DB dependencies."""
    import desktop.ui.components.resource_inspector_panel as mod

    for prohibited in (
        "httpx",
        "fastapi",
        "starlette",
        "sqlalchemy",
        "respx",
    ):
        assert not hasattr(mod, prohibited)

    for mod_name in sys.modules:
        if mod_name.startswith("desktop.ui.components.resource_inspector_panel"):
            mod_obj = sys.modules[mod_name]
            for forbidden in ("httpx", "sqlalchemy"):
                assert forbidden not in mod_obj.__dict__
