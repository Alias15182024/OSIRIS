"""OSIRIS reusable semantic badge components.

Provides SeverityBadge and StatusBadge, compact QLabel-based visual badges
designed for dense enterprise security console tables and inspector views.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QWidget

from desktop.ui.design_tokens import (
    OPERATIONAL_STATUS_COLORS,
    SEVERITY_COLORS,
)

# Canonical human-readable display mappings
_SEVERITY_CANONICAL: dict[str, str] = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}

_STATUS_CANONICAL: dict[str, str] = {
    "fresh": "Fresh",
    "stale": "Stale",
    "degraded": "Degraded",
    "offline": "Offline",
}


def _normalize_key(value: str) -> str:
    """Normalize input string to lower snake_case key."""
    return value.strip().lower().replace("-", "_").replace(" ", "_")


class SeverityBadge(QLabel):
    """Compact semantic badge displaying incident severity.

    Supported severity values:
        - Critical
        - High
        - Medium
        - Low
        - Info

    Values are accepted case-insensitively and displayed using canonical
    human-readable text. The widget exposes a Qt dynamic property 'severity'
    (normalized lowercase) for QSS styling.
    """

    def __init__(
        self,
        severity: str = "Info",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("SeverityBadge")
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._severity: str = ""
        self._severity_key: str = ""
        self.set_severity(severity)

    @property
    def severity(self) -> str:
        """Return the canonical human-readable severity label."""
        return self._severity

    @severity.setter
    def severity(self, value: str) -> None:
        self.set_severity(value)

    @property
    def severity_key(self) -> str:
        """Return normalized lowercase severity key used for QSS property matching."""
        return self._severity_key

    def get_severity(self) -> str:
        """Return the canonical human-readable severity label."""
        return self._severity

    def set_severity(self, value: str) -> None:
        """Update severity to a supported value.

        Args:
            value: One of 'Critical', 'High', 'Medium', 'Low', 'Info'
                (case-insensitive).

        Raises:
            TypeError: If value is not a string.
            ValueError: If value is not one of the supported severity levels.
        """
        if not isinstance(value, str):
            raise TypeError(f"Severity must be a string, got {type(value).__name__}")
        key = _normalize_key(value)
        if key not in _SEVERITY_CANONICAL or key not in SEVERITY_COLORS:
            valid_options = ", ".join(_SEVERITY_CANONICAL.values())
            raise ValueError(
                f"Invalid severity {value!r}. Supported values are: {valid_options}"
            )
        self._severity = _SEVERITY_CANONICAL[key]
        self._severity_key = key
        self.setText(self._severity)
        self.setProperty("severity", key)

        style = self.style()
        if style is not None:
            style.unpolish(self)
            style.polish(self)


class StatusBadge(QLabel):
    """Compact semantic badge displaying operational status.

    Supported status values:
        - Fresh
        - Stale
        - Degraded
        - Offline

    Values are accepted case-insensitively and displayed using canonical
    human-readable text. The widget exposes a Qt dynamic property 'status'
    (normalized lowercase) for QSS styling.
    """

    def __init__(
        self,
        status: str = "Offline",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("StatusBadge")
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._status: str = ""
        self._status_key: str = ""
        self.set_status(status)

    @property
    def status(self) -> str:
        """Return the canonical human-readable status label."""
        return self._status

    @status.setter
    def status(self, value: str) -> None:
        self.set_status(value)

    @property
    def status_key(self) -> str:
        """Return normalized lowercase status key used for QSS property matching."""
        return self._status_key

    def get_status(self) -> str:
        """Return the canonical human-readable status label."""
        return self._status

    def set_status(self, value: str) -> None:
        """Update status to a supported value.

        Args:
            value: One of 'Fresh', 'Stale', 'Degraded', 'Offline'
                (case-insensitive).

        Raises:
            TypeError: If value is not a string.
            ValueError: If value is not one of the supported status levels.
        """
        if not isinstance(value, str):
            raise TypeError(f"Status must be a string, got {type(value).__name__}")
        key = _normalize_key(value)
        if key not in _STATUS_CANONICAL or key not in OPERATIONAL_STATUS_COLORS:
            valid_options = ", ".join(_STATUS_CANONICAL.values())
            raise ValueError(
                f"Invalid status {value!r}. Supported values are: {valid_options}"
            )
        self._status = _STATUS_CANONICAL[key]
        self._status_key = key
        self.setText(self._status)
        self.setProperty("status", key)

        style = self.style()
        if style is not None:
            style.unpolish(self)
            style.polish(self)


__all__ = [
    "SeverityBadge",
    "StatusBadge",
]
