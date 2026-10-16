"""OSIRIS Event Details Inspector Panel.

Provides EventInspectorPanel, a reusable PySide6 QFrame component for inspecting
the validated details of an OSIRIS security event record from the events table.
"""

from __future__ import annotations

import json
from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from desktop.client.models import Event
from desktop.models.events_model import EMPTY_PLACEHOLDER
from desktop.ui.components.badges import SeverityBadge
from desktop.ui.design_tokens import (
    INSPECTOR_PANEL_WIDTH,
    SPACE_1,
    SPACE_2,
    SPACE_3,
)

# Ordered specification of event fields presented in inspector
FIELD_DEFINITIONS: tuple[tuple[str, str], ...] = (
    ("id", "Event ID"),
    ("host_id", "Host ID"),
    ("timestamp", "Timestamp"),
    ("ingested_at", "Ingested At"),
    ("created_at", "Created At"),
    ("source", "Source"),
    ("event_type", "Event Type"),
    ("severity", "Severity"),
    ("action", "Action"),
    ("username", "Username"),
    ("uid", "UID"),
    ("pid", "PID"),
    ("ppid", "Parent PID"),
    ("process_id", "Process ID"),
    ("command", "Command"),
    ("object_type", "Object Type"),
    ("object_path", "Object Path"),
    ("success", "Success"),
    ("result", "Result"),
)


class EventInspectorPanel(QFrame):
    """Reusable investigator panel for inspecting validated security events.

    Presents all fields of a validated Event model in a compact, readable
    hierarchy with a severity badge, deterministic JSON payload viewer,
    and close/collapse control.
    """

    close_requested = Signal()

    def __init__(
        self,
        event: Event | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the EventInspectorPanel.

        Args:
            event: Optional initial Event instance to display.
            parent: Optional parent QWidget.
        """
        super().__init__(parent)
        self.setObjectName("EventInspectorPanel")
        self.setFixedWidth(INSPECTOR_PANEL_WIDTH)
        self.setSizePolicy(
            QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Expanding
        )

        self._current_event: Event | None = None
        self._title_labels: dict[str, QLabel] = {}
        self._value_labels: dict[str, QLabel] = {}

        # 1. Panel Header
        header = QWidget(self)
        header.setObjectName("EventInspectorHeader")
        h_ly = QHBoxLayout(header)
        h_ly.setContentsMargins(SPACE_3, SPACE_3, SPACE_3, SPACE_3)
        h_ly.setSpacing(SPACE_2)

        self._title_label = QLabel("Event Details", header)
        self._title_label.setObjectName("EventInspectorTitle")

        self._severity_badge = SeverityBadge(severity="Info", parent=header)
        self._severity_badge.setObjectName("EventInspectorSeverityBadge")
        self._severity_badge.setVisible(False)

        self._close_btn = QPushButton("✕", header)
        self._close_btn.setObjectName("EventInspectorCloseButton")
        self._close_btn.setToolTip("Close inspector")
        self._close_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._close_btn.clicked.connect(self._handle_close_click)

        h_ly.addWidget(self._title_label)
        h_ly.addStretch(1)
        h_ly.addWidget(self._severity_badge)
        h_ly.addWidget(self._close_btn)

        # 2. Scrollable Content Area
        self._scroll_area = QScrollArea(self)
        self._scroll_area.setObjectName("EventInspectorScrollArea")
        self._scroll_area.setWidgetResizable(True)
        self._scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        self._scroll_area.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )

        self._content = QWidget(self._scroll_area)
        self._content.setObjectName("EventInspectorContent")
        c_ly = QVBoxLayout(self._content)
        c_ly.setContentsMargins(SPACE_3, SPACE_3, SPACE_3, SPACE_3)
        c_ly.setSpacing(SPACE_3)

        # 3. Field Rows
        for key, label_text in FIELD_DEFINITIONS:
            field_box = QWidget(self._content)
            fb_ly = QVBoxLayout(field_box)
            fb_ly.setContentsMargins(0, 0, 0, 0)
            fb_ly.setSpacing(SPACE_1)

            lbl = QLabel(label_text, field_box)
            lbl.setObjectName(f"EventInspectorLabel_{key}")
            lbl.setProperty("inspectorLabel", "true")
            self._title_labels[key] = lbl

            val_lbl = QLabel(EMPTY_PLACEHOLDER, field_box)
            val_lbl.setObjectName(f"EventInspectorValue_{key}")
            val_lbl.setProperty("inspectorValue", "true")
            val_lbl.setWordWrap(True)
            val_lbl.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse
            )
            self._value_labels[key] = val_lbl

            fb_ly.addWidget(lbl)
            fb_ly.addWidget(val_lbl)
            c_ly.addWidget(field_box)

        # 4. Payload Section
        payload_box = QWidget(self._content)
        pb_ly = QVBoxLayout(payload_box)
        pb_ly.setContentsMargins(0, 0, 0, 0)
        pb_ly.setSpacing(SPACE_1)

        self._payload_title = QLabel("Payload", payload_box)
        self._payload_title.setObjectName("EventInspectorPayloadLabel")

        self._payload_edit = QPlainTextEdit(payload_box)
        self._payload_edit.setObjectName("EventInspectorPayloadEdit")
        self._payload_edit.setReadOnly(True)
        self._payload_edit.setLineWrapMode(
            QPlainTextEdit.LineWrapMode.WidgetWidth
        )

        pb_ly.addWidget(self._payload_title)
        pb_ly.addWidget(self._payload_edit)
        c_ly.addWidget(payload_box)

        self._scroll_area.setWidget(self._content)

        # 5. Root Layout
        root_ly = QVBoxLayout(self)
        root_ly.setContentsMargins(0, 0, 0, 0)
        root_ly.setSpacing(0)
        root_ly.addWidget(header)
        root_ly.addWidget(self._scroll_area, 1)

        # Apply initial event or clear
        self.set_event(event)

    # -----------------------------------------------------------------------
    # Public Interface
    # -----------------------------------------------------------------------

    @property
    def current_event(self) -> Event | None:
        """Return the currently displayed Event instance, or None if empty."""
        return self._current_event

    @property
    def title_label(self) -> QLabel:
        """Return the heading title label."""
        return self._title_label

    @property
    def severity_badge(self) -> SeverityBadge:
        """Return the header severity badge."""
        return self._severity_badge

    @property
    def close_button(self) -> QPushButton:
        """Return the close action button."""
        return self._close_btn

    @property
    def payload_edit(self) -> QPlainTextEdit:
        """Return the read-only JSON payload plain text editor."""
        return self._payload_edit

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
            key: Field identifier attribute name on Event.

        Returns:
            The formatted string displayed in the corresponding value label.

        Raises:
            KeyError: If key is not in FIELD_DEFINITIONS.
        """
        if key in self._value_labels:
            return self._value_labels[key].text()
        raise KeyError(f"Unknown field key: {key!r}")

    def get_payload_text(self) -> str:
        """Return the text currently in the payload viewer."""
        return self._payload_edit.toPlainText()

    def set_event(self, event: Event | None) -> None:
        """Set the security event to inspect and update all child widgets.

        Args:
            event: A validated Event instance, or None to clear and hide.

        Raises:
            TypeError: If event is not an Event instance or None.
        """
        if event is not None and not isinstance(event, Event):
            raise TypeError(
                f"Expected Event or None, got {type(event).__name__}"
            )

        self._current_event = event

        if event is None:
            self._clear_display()
            self.setVisible(False)
            return

        self._populate_display(event)
        self.setVisible(True)

    def clear(self) -> None:
        """Clear displayed event fields and hide the inspector panel."""
        self.set_event(None)

    # -----------------------------------------------------------------------
    # Internal Display Helpers
    # -----------------------------------------------------------------------

    def _clear_display(self) -> None:
        """Reset all field value labels and payload editor to placeholders."""
        self._severity_badge.setVisible(False)
        for val_lbl in self._value_labels.values():
            val_lbl.setText(EMPTY_PLACEHOLDER)
        self._payload_edit.setPlainText(EMPTY_PLACEHOLDER)

    def _populate_display(self, event: Event) -> None:
        """Populate header badge, all field value labels, and payload area."""
        self._severity_badge.set_severity(event.severity)
        self._severity_badge.setVisible(True)

        for key, _ in FIELD_DEFINITIONS:
            formatted = self._format_field_value(event, key)
            self._value_labels[key].setText(formatted)

        self._payload_edit.setPlainText(self._format_payload(event.payload))

    @staticmethod
    def _format_field_value(event: Event, key: str) -> str:
        """Format an event field into a display string.

        Preserves integer zero (PID, UID, PPID) and booleans (success).
        Never returns Python 'None' or object representations.
        """
        val = getattr(event, key, None)
        if val is None:
            return EMPTY_PLACEHOLDER
        if isinstance(val, bool):
            return "True" if val else "False"
        if isinstance(val, int):
            return str(val)
        if isinstance(val, str):
            s = val.strip()
            if not s:
                return EMPTY_PLACEHOLDER
            if key == "severity":
                return s.capitalize()
            return s
        return str(val)

    @staticmethod
    def _format_payload(payload: dict[str, Any] | None) -> str:
        """Format event payload dictionary into readable deterministic JSON.

        Preserves underlying dictionary unchanged and returns EMPTY_PLACEHOLDER
        for absent or empty payloads.
        """
        if not payload:
            return EMPTY_PLACEHOLDER
        try:
            return json.dumps(
                payload,
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            )
        except Exception:
            return str(payload)

    def _handle_close_click(self) -> None:
        """Handle click on the close button."""
        self.close_requested.emit()
        self.hide()


__all__ = [
    "FIELD_DEFINITIONS",
    "EventInspectorPanel",
]
