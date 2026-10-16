"""OSIRIS native Qt root-execution security warning banner.

Displays a persistent warning when the desktop SOC console is launched
with root/superuser privileges (UID 0), advising the operator to adhere
to the principle of least privilege.
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QWidget,
)

from desktop.ui.design_tokens import SPACE_1, SPACE_2, SPACE_4

DEFAULT_ROOT_WARNING_TEXT: str = (
    "Security Warning: Running OSIRIS as root (UID 0) violates least-privilege "
    "practice. Please run as an unprivileged user."
)


class RootWarningBanner(QFrame):
    """Persistent security warning banner displayed when running as root."""

    def __init__(
        self,
        parent: QWidget | None = None,
        is_root: bool = False,
        message: str | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("RootWarningBanner")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(SPACE_4, SPACE_1, SPACE_4, SPACE_1)
        layout.setSpacing(SPACE_2)

        self._indicator_label = QLabel("SECURITY WARNING", self)
        self._indicator_label.setObjectName("RootWarningIndicator")

        msg = message if message is not None else DEFAULT_ROOT_WARNING_TEXT
        self._message_label = QLabel(msg, self)
        self._message_label.setObjectName("RootWarningMessage")
        self._message_label.setWordWrap(True)

        layout.addWidget(self._indicator_label)
        layout.addWidget(self._message_label, 1)

        self._is_root: bool = bool(is_root)
        self.setVisible(self._is_root)

    @property
    def is_root(self) -> bool:
        """Return True if root execution warning is active."""
        return self._is_root

    @property
    def message(self) -> str:
        """Return current warning message string."""
        return self._message_label.text()

    @property
    def indicator_label(self) -> QLabel:
        """Return indicator badge label."""
        return self._indicator_label

    @property
    def message_label(self) -> QLabel:
        """Return message content label."""
        return self._message_label

    def set_root_warning(
        self, is_root: bool, message: str | None = None
    ) -> None:
        """Update root warning visibility and message."""
        self._is_root = bool(is_root)
        if message is not None:
            self._message_label.setText(message)
        self.setVisible(self._is_root)


__all__ = ["DEFAULT_ROOT_WARNING_TEXT", "RootWarningBanner"]
