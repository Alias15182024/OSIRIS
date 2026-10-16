"""OSIRIS Resource Snapshot Details Inspector Panel.

Provides ResourceInspectorPanel, a reusable PySide6 QFrame component for inspecting
the validated details of an immutable OSIRIS ResourceSnapshot record.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from desktop.client.models import ResourceSnapshot
from desktop.models.resources_model import (
    EMPTY_PLACEHOLDER,
    format_bytes,
    format_percent,
)
from desktop.ui.design_tokens import (
    INSPECTOR_PANEL_WIDTH,
    SPACE_1,
    SPACE_2,
    SPACE_3,
)

# Ordered specification of resource snapshot fields presented in inspector
RESOURCE_FIELD_DEFINITIONS: tuple[tuple[str, str], ...] = (
    ("id", "Snapshot ID"),
    ("host_id", "Host ID"),
    ("timestamp", "Timestamp"),
    ("created_at", "Created At"),
    ("cpu_percent", "CPU %"),
    ("memory_percent", "Memory %"),
    ("memory_used", "Memory Used"),
    ("memory_total", "Memory Total"),
    ("disk_read_bytes", "Disk Read Bytes"),
    ("disk_write_bytes", "Disk Write Bytes"),
    ("disk_usage_percent", "Disk Usage %"),
)

FIELD_DEFINITIONS = RESOURCE_FIELD_DEFINITIONS

KEY_ALIASES: dict[str, str] = {
    "snapshot_id": "id",
    "host": "host_id",
    "creation_timestamp": "created_at",
    "created": "created_at",
    "cpu": "cpu_percent",
    "cpu_usage": "cpu_percent",
    "memory": "memory_percent",
    "memory_usage": "memory_percent",
    "disk_read": "disk_read_bytes",
    "disk_write": "disk_write_bytes",
    "disk_usage": "disk_usage_percent",
    "disk_percent": "disk_usage_percent",
}


class ResourceInspectorPanel(QFrame):
    """Reusable investigator panel for inspecting validated resource snapshots.

    Presents all fields of a validated ResourceSnapshot model in a compact,
    readable hierarchy with non-lossy raw byte counters alongside formatted
    binary units, text selection, and close/collapse control.
    """

    close_requested = Signal()

    def __init__(
        self,
        snapshot: ResourceSnapshot | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the ResourceInspectorPanel.

        Args:
            snapshot: Optional initial ResourceSnapshot instance to display.
            parent: Optional parent QWidget.
        """
        super().__init__(parent)
        self.setObjectName("ResourceInspectorPanel")
        self.setFixedWidth(INSPECTOR_PANEL_WIDTH)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Expanding)

        self._current_snapshot: ResourceSnapshot | None = None
        self._title_labels: dict[str, QLabel] = {}
        self._value_labels: dict[str, QLabel] = {}

        # 1. Panel Header
        header = QWidget(self)
        header.setObjectName("ResourceInspectorHeader")
        h_ly = QHBoxLayout(header)
        h_ly.setContentsMargins(SPACE_3, SPACE_3, SPACE_3, SPACE_3)
        h_ly.setSpacing(SPACE_2)

        self._title_label = QLabel("Snapshot Details", header)
        self._title_label.setObjectName("ResourceInspectorTitle")

        self._close_btn = QPushButton("✕", header)
        self._close_btn.setObjectName("ResourceInspectorCloseButton")
        self._close_btn.setToolTip("Close inspector")
        self._close_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._close_btn.clicked.connect(self._handle_close_click)

        h_ly.addWidget(self._title_label)
        h_ly.addStretch(1)
        h_ly.addWidget(self._close_btn)

        # 2. Scrollable Content Area
        self._scroll_area = QScrollArea(self)
        self._scroll_area.setObjectName("ResourceInspectorScrollArea")
        self._scroll_area.setWidgetResizable(True)
        self._scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        self._scroll_area.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )

        self._content = QWidget(self._scroll_area)
        self._content.setObjectName("ResourceInspectorContent")
        c_ly = QVBoxLayout(self._content)
        c_ly.setContentsMargins(SPACE_3, SPACE_3, SPACE_3, SPACE_3)
        c_ly.setSpacing(SPACE_3)

        # 3. Field Rows
        for key, label_text in RESOURCE_FIELD_DEFINITIONS:
            field_box = QWidget(self._content)
            fb_ly = QVBoxLayout(field_box)
            fb_ly.setContentsMargins(0, 0, 0, 0)
            fb_ly.setSpacing(SPACE_1)

            lbl = QLabel(label_text, field_box)
            lbl.setObjectName(f"ResourceInspectorLabel_{key}")
            lbl.setProperty("inspectorLabel", "true")
            self._title_labels[key] = lbl

            val_lbl = QLabel(EMPTY_PLACEHOLDER, field_box)
            val_lbl.setObjectName(f"ResourceInspectorValue_{key}")
            val_lbl.setProperty("inspectorValue", "true")
            val_lbl.setWordWrap(True)
            val_lbl.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse
            )
            self._value_labels[key] = val_lbl

            fb_ly.addWidget(lbl)
            fb_ly.addWidget(val_lbl)
            c_ly.addWidget(field_box)

        c_ly.addStretch(1)
        self._scroll_area.setWidget(self._content)

        # 4. Root Layout
        root_ly = QVBoxLayout(self)
        root_ly.setContentsMargins(0, 0, 0, 0)
        root_ly.setSpacing(0)
        root_ly.addWidget(header)
        root_ly.addWidget(self._scroll_area, 1)

        # Apply initial snapshot or clear
        self.set_snapshot(snapshot)

    # -----------------------------------------------------------------------
    # Public Interface
    # -----------------------------------------------------------------------

    @property
    def current_snapshot(self) -> ResourceSnapshot | None:
        """Return the currently displayed ResourceSnapshot, or None if empty."""
        return self._current_snapshot

    @property
    def current_resource(self) -> ResourceSnapshot | None:
        """Alias for current_snapshot."""
        return self._current_snapshot

    @property
    def snapshot(self) -> ResourceSnapshot | None:
        """Alias for current_snapshot."""
        return self._current_snapshot

    @property
    def title_label(self) -> QLabel:
        """Return the heading title label."""
        return self._title_label

    @property
    def close_button(self) -> QPushButton:
        """Return the close action button."""
        return self._close_btn

    @property
    def scroll_area(self) -> QScrollArea:
        """Return the scroll area containing inspector fields."""
        return self._scroll_area

    @property
    def field_labels(self) -> dict[str, QLabel]:
        """Return a mapping of field keys to their caption QLabels."""
        return dict(self._title_labels)

    @property
    def field_values(self) -> dict[str, QLabel]:
        """Return a mapping of field keys to their value QLabels."""
        return dict(self._value_labels)

    def get_field_value(self, key: str) -> str:
        """Return the formatted display text of a specific field.

        Args:
            key: Field identifier attribute name or recognized alias.

        Returns:
            The formatted string displayed in the corresponding value label.

        Raises:
            KeyError: If key is not recognized.
        """
        resolved_key = KEY_ALIASES.get(key, key)
        if resolved_key in self._value_labels:
            return self._value_labels[resolved_key].text()
        raise KeyError(f"Unknown field key: {key!r}")

    def set_snapshot(self, snapshot: ResourceSnapshot | None) -> None:
        """Set the resource snapshot to inspect and update all child widgets.

        Args:
            snapshot: A validated ResourceSnapshot, or None to clear and hide.

        Raises:
            TypeError: If snapshot is not a ResourceSnapshot instance or None.
        """
        if snapshot is not None and not isinstance(snapshot, ResourceSnapshot):
            raise TypeError(
                f"Expected ResourceSnapshot or None, got {type(snapshot).__name__}"
            )

        self._current_snapshot = snapshot

        if snapshot is None:
            self._clear_display()
            self.setVisible(False)
            return

        self._populate_display(snapshot)
        self.setVisible(True)

    def set_resource(self, resource: ResourceSnapshot | None) -> None:
        """Alias for set_snapshot."""
        self.set_snapshot(resource)

    def clear(self) -> None:
        """Clear displayed snapshot fields and hide the inspector panel."""
        self.set_snapshot(None)

    # -----------------------------------------------------------------------
    # Internal Display Helpers
    # -----------------------------------------------------------------------

    def _clear_display(self) -> None:
        """Reset all field value labels to placeholders."""
        for val_lbl in self._value_labels.values():
            val_lbl.setText(EMPTY_PLACEHOLDER)

    def _populate_display(self, snapshot: ResourceSnapshot) -> None:
        """Populate all field value labels with formatted snapshot data."""
        for key, _ in RESOURCE_FIELD_DEFINITIONS:
            formatted = self._format_field_value(snapshot, key)
            self._value_labels[key].setText(formatted)

    @staticmethod
    def _format_byte_metric(num_bytes: int | None) -> str:
        """Format byte counter with non-lossy exact count and binary units."""
        if (
            isinstance(num_bytes, bool)
            or not isinstance(num_bytes, int)
            or num_bytes < 0
        ):
            return EMPTY_PLACEHOLDER
        unit_str = "byte" if num_bytes == 1 else "bytes"
        return f"{format_bytes(num_bytes)} ({num_bytes:,} {unit_str})"

    @classmethod
    def _format_field_value(cls, snapshot: ResourceSnapshot, key: str) -> str:
        """Format a resource snapshot field into a display string.

        Preserves integer zero, raw non-lossy byte counts, and exact timestamps.
        Never converts None into zero or fabricated telemetry.
        """
        if key in ("cpu_percent", "cpu"):
            return format_percent(snapshot.cpu_percent)

        if key in ("memory_percent", "memory"):
            return format_percent(snapshot.memory_percent)

        if key in ("disk_usage_percent", "disk_usage", "disk_percent"):
            return format_percent(snapshot.disk_usage_percent)

        if key == "memory_used":
            return cls._format_byte_metric(snapshot.memory_used)

        if key == "memory_total":
            return cls._format_byte_metric(snapshot.memory_total)

        if key in ("disk_read_bytes", "disk_read"):
            return cls._format_byte_metric(snapshot.disk_read_bytes)

        if key in ("disk_write_bytes", "disk_write"):
            return cls._format_byte_metric(snapshot.disk_write_bytes)

        val: Any = getattr(snapshot, key, None)
        if val is None:
            return EMPTY_PLACEHOLDER
        if isinstance(val, str):
            s = val.strip()
            if not s:
                return EMPTY_PLACEHOLDER
            return s
        return str(val)

    def _handle_close_click(self) -> None:
        """Handle click on the close button."""
        self.close_requested.emit()
        self.hide()


__all__ = [
    "FIELD_DEFINITIONS",
    "RESOURCE_FIELD_DEFINITIONS",
    "ResourceInspectorPanel",
]
