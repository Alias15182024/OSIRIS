"""OSIRIS reusable card components.

Provides MetricCard, a restrained QFrame-based component for presenting
operational metrics (e.g. event counts, process counts, resource measurements)
with high density and a clean visual hierarchy.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtWidgets import QFrame, QLabel, QVBoxLayout, QWidget

from desktop.ui.design_tokens import SPACE_1, SPACE_3


class MetricCard(QFrame):
    """Restrained QFrame component for displaying a single operational metric.

    Layout hierarchy:
        - Title label (small, subdued metadata)
        - Value label (prominent monospace numeric/KPI display)
        - Optional detail label (small, secondary contextual text)

    Absent detail is handled cleanly by hiding the detail label without
    displaying placeholder strings like 'None'.
    """

    def __init__(
        self,
        title: str,
        value: Any = "",
        detail: str | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("MetricCard")
        self.setFrameShape(QFrame.Shape.StyledPanel)

        # Internal child labels with semantic object names and hierarchy properties
        self._title_label = QLabel(self)
        self._title_label.setObjectName("MetricCardTitle")
        self._title_label.setProperty("secondary", "true")

        self._value_label = QLabel(self)
        self._value_label.setObjectName("MetricCardValue")
        self._value_label.setProperty("metric", "true")

        self._detail_label = QLabel(self)
        self._detail_label.setObjectName("MetricCardDetail")
        self._detail_label.setProperty("subdued", "true")

        # Layout using 4px-baseline design token spacing
        layout = QVBoxLayout(self)
        layout.setContentsMargins(SPACE_3, SPACE_3, SPACE_3, SPACE_3)
        layout.setSpacing(SPACE_1)
        layout.addWidget(self._title_label)
        layout.addWidget(self._value_label)
        layout.addWidget(self._detail_label)

        self._title: str = ""
        self._value: str = ""
        self._detail: str | None = None

        self.set_title(title)
        self.set_value(value)
        self.set_detail(detail)

    @property
    def title(self) -> str:
        """Return the metric card title text."""
        return self._title

    @title.setter
    def title(self, value: str) -> None:
        self.set_title(value)

    def get_title(self) -> str:
        """Return the metric card title text."""
        return self._title

    def set_title(self, title: str) -> None:
        """Update the title label text."""
        self._title = str(title) if title is not None else ""
        self._title_label.setText(self._title)

    @property
    def value(self) -> str:
        """Return the primary metric value string."""
        return self._value

    @value.setter
    def value(self, value: Any) -> None:
        self.set_value(value)

    def get_value(self) -> str:
        """Return the primary metric value string."""
        return self._value

    def set_value(self, value: Any) -> None:
        """Update the primary metric displayed value."""
        self._value = str(value) if value is not None else ""
        self._value_label.setText(self._value)

    @property
    def detail(self) -> str | None:
        """Return the secondary detail text, or None if absent."""
        return self._detail

    @detail.setter
    def detail(self, value: str | None) -> None:
        self.set_detail(value)

    def get_detail(self) -> str | None:
        """Return the secondary detail text, or None if absent."""
        return self._detail

    def set_detail(self, detail: str | None) -> None:
        """Update or clear the secondary detail text.

        If detail is None, empty, whitespace, or the literal string 'None',
        the detail label is hidden and cleared, never displaying placeholder
        strings like 'None'.
        """
        if (
            detail is None
            or not str(detail).strip()
            or str(detail).strip().lower() == "none"
        ):
            self._detail = None
            self._detail_label.setText("")
            self._detail_label.setVisible(False)
        else:
            self._detail = str(detail)
            self._detail_label.setText(self._detail)
            self._detail_label.setVisible(True)

    def clear_detail(self) -> None:
        """Clear the secondary detail text and hide the detail label."""
        self.set_detail(None)

    @property
    def title_label(self) -> QLabel:
        """Child QLabel used for the title."""
        return self._title_label

    @property
    def value_label(self) -> QLabel:
        """Child QLabel used for the primary metric value."""
        return self._value_label

    @property
    def detail_label(self) -> QLabel:
        """Child QLabel used for the optional secondary detail."""
        return self._detail_label


__all__ = [
    "MetricCard",
]
