"""OSIRIS Process Details Inspector Panel.

Provides ProcessInspectorPanel, a reusable PySide6 QFrame component for inspecting
the validated details of an OSIRIS process record from the processes table.
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

from desktop.client.models import Process
from desktop.models.processes_model import (
    EMPTY_PLACEHOLDER,
    STATUS_DISPLAY_ACTIVE,
    STATUS_DISPLAY_TERMINATED,
)
from desktop.ui.design_tokens import (
    INSPECTOR_PANEL_WIDTH,
    SPACE_1,
    SPACE_2,
    SPACE_3,
)

# Ordered specification of process fields presented in inspector
FIELD_DEFINITIONS: tuple[tuple[str, str], ...] = (
    ("id", "Process ID"),
    ("host_id", "Host ID"),
    ("pid", "PID"),
    ("ppid", "Parent PID"),
    ("command", "Command"),
    ("executable", "Executable"),
    ("linux_user_id", "Linux User ID"),
    ("status", "Status"),
    ("started_at", "Started At"),
    ("ended_at", "Ended At"),
    ("created_at", "Created At"),
)


class ProcessInspectorPanel(QFrame):
    """Reusable investigator panel for inspecting validated system processes.

    Presents all fields of a validated Process model in a compact, readable
    hierarchy with lifecycle status presentation, word wrapping, text selection,
    and close/collapse control.
    """

    close_requested = Signal()

    def __init__(
        self,
        process: Process | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the ProcessInspectorPanel.

        Args:
            process: Optional initial Process instance to display.
            parent: Optional parent QWidget.
        """
        super().__init__(parent)
        self.setObjectName("ProcessInspectorPanel")
        self.setFixedWidth(INSPECTOR_PANEL_WIDTH)
        self.setSizePolicy(
            QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Expanding
        )

        self._current_process: Process | None = None
        self._title_labels: dict[str, QLabel] = {}
        self._value_labels: dict[str, QLabel] = {}

        # 1. Panel Header
        header = QWidget(self)
        header.setObjectName("ProcessInspectorHeader")
        h_ly = QHBoxLayout(header)
        h_ly.setContentsMargins(SPACE_3, SPACE_3, SPACE_3, SPACE_3)
        h_ly.setSpacing(SPACE_2)

        self._title_label = QLabel("Process Details", header)
        self._title_label.setObjectName("ProcessInspectorTitle")

        self._close_btn = QPushButton("✕", header)
        self._close_btn.setObjectName("ProcessInspectorCloseButton")
        self._close_btn.setToolTip("Close inspector")
        self._close_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._close_btn.clicked.connect(self._handle_close_click)

        h_ly.addWidget(self._title_label)
        h_ly.addStretch(1)
        h_ly.addWidget(self._close_btn)

        # 2. Scrollable Content Area
        self._scroll_area = QScrollArea(self)
        self._scroll_area.setObjectName("ProcessInspectorScrollArea")
        self._scroll_area.setWidgetResizable(True)
        self._scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        self._scroll_area.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )

        self._content = QWidget(self._scroll_area)
        self._content.setObjectName("ProcessInspectorContent")
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
            lbl.setObjectName(f"ProcessInspectorLabel_{key}")
            lbl.setProperty("inspectorLabel", "true")
            self._title_labels[key] = lbl

            val_lbl = QLabel(EMPTY_PLACEHOLDER, field_box)
            val_lbl.setObjectName(f"ProcessInspectorValue_{key}")
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

        # Apply initial process or clear
        self.set_process(process)

    # -----------------------------------------------------------------------
    # Public Interface
    # -----------------------------------------------------------------------

    @property
    def current_process(self) -> Process | None:
        """Return the currently displayed Process instance, or None if empty."""
        return self._current_process

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
    def status_label(self) -> QLabel:
        """Return the status field value label."""
        return self._value_labels["status"]

    @property
    def status_badge(self) -> QLabel:
        """Return the status label as a badge/label component."""
        return self._value_labels["status"]

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
            key: Field identifier attribute name on Process.

        Returns:
            The formatted string displayed in the corresponding value label.

        Raises:
            KeyError: If key is not recognized.
        """
        if key == "process_id" and "id" in self._value_labels:
            return self._value_labels["id"].text()
        if key == "is_active" and "status" in self._value_labels:
            return self._value_labels["status"].text()
        if key in self._value_labels:
            return self._value_labels[key].text()
        raise KeyError(f"Unknown field key: {key!r}")

    def set_process(self, process: Process | None) -> None:
        """Set the process to inspect and update all child widgets.

        Args:
            process: A validated Process instance, or None to clear and hide.

        Raises:
            TypeError: If process is not a Process instance or None.
        """
        if process is not None and not isinstance(process, Process):
            raise TypeError(
                f"Expected Process or None, got {type(process).__name__}"
            )

        self._current_process = process

        if process is None:
            self._clear_display()
            self.setVisible(False)
            return

        self._populate_display(process)
        self.setVisible(True)

    def clear(self) -> None:
        """Clear displayed process fields and hide the inspector panel."""
        self.set_process(None)

    # -----------------------------------------------------------------------
    # Internal Display Helpers
    # -----------------------------------------------------------------------

    def _clear_display(self) -> None:
        """Reset all field value labels to placeholders."""
        for key, val_lbl in self._value_labels.items():
            val_lbl.setText(EMPTY_PLACEHOLDER)
            if key == "status":
                val_lbl.setProperty("status", "")

    def _populate_display(self, process: Process) -> None:
        """Populate all field value labels with formatted process data."""
        for key, _ in FIELD_DEFINITIONS:
            formatted = self._format_field_value(process, key)
            self._value_labels[key].setText(formatted)
            if key == "status":
                self._value_labels[key].setProperty(
                    "status", "active" if process.is_active else "terminated"
                )

    @staticmethod
    def _format_field_value(process: Process, key: str) -> str:
        """Format a process field into a display string.

        Preserves integer zero (PID, PPID) and presents derived lifecycle status.
        Never returns Python 'None' or object representations.
        """
        if key == "status":
            return (
                STATUS_DISPLAY_ACTIVE
                if process.is_active
                else STATUS_DISPLAY_TERMINATED
            )

        val: Any = getattr(process, key, None)
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
            return s
        return str(val)

    def _handle_close_click(self) -> None:
        """Handle click on the close button."""
        self.close_requested.emit()
        self.hide()


__all__ = [
    "FIELD_DEFINITIONS",
    "ProcessInspectorPanel",
]
