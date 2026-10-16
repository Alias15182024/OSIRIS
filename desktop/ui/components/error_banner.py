"""OSIRIS native Qt global error and degraded status banner.

Displays high-priority connection loss, service degradation, and operational
recovery notices at the top of the content area without displacing layout.
"""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QWidget,
)

from desktop.ui.design_tokens import SPACE_2, SPACE_4

STATE_HIDDEN: str = "hidden"
STATE_DISCONNECTED: str = "disconnected"
STATE_DEGRADED: str = "degraded"


class ErrorBanner(QFrame):
    """Global warning and error banner for API and operational status issues.

    Placed prominently across the top of the main content stack.
    Flicker-free updates prevent unnecessary layout restyling.
    """

    retry_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("GlobalErrorBanner")
        self.setProperty("bannerType", "")
        self.setVisible(False)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(SPACE_4, SPACE_2, SPACE_4, SPACE_2)
        layout.setSpacing(SPACE_2)

        self._indicator_label = QLabel(self)
        self._indicator_label.setObjectName("ErrorBannerIndicator")

        self._message_label = QLabel(self)
        self._message_label.setObjectName("ErrorBannerMessage")

        self._retry_button = QPushButton("Retry", self)
        self._retry_button.setObjectName("ErrorBannerRetryButton")
        self._retry_button.clicked.connect(self.retry_requested.emit)

        layout.addWidget(self._indicator_label)
        layout.addWidget(self._message_label, 1)
        layout.addWidget(self._retry_button)

        self._current_type: str = ""
        self._current_message: str = ""

    # -----------------------------------------------------------------------
    # Public Accessors & Properties
    # -----------------------------------------------------------------------

    @property
    def banner_type(self) -> str:
        """Return the current banner state type (disconnected, degraded, or empty)."""
        return self._current_type

    @property
    def message(self) -> str:
        """Return the currently displayed banner message string."""
        return self._current_message

    @property
    def is_visible(self) -> bool:
        """Return whether the banner is currently set visible."""
        return not self.isHidden()

    @property
    def indicator_label(self) -> QLabel:
        """Return the indicator status label widget."""
        return self._indicator_label

    @property
    def message_label(self) -> QLabel:
        """Return the main banner message label widget."""
        return self._message_label

    @property
    def retry_button(self) -> QPushButton:
        """Return the interactive retry button widget."""
        return self._retry_button

    # -----------------------------------------------------------------------
    # Banner State Mutations
    # -----------------------------------------------------------------------

    def show_connection_error(self, message: str | None = None) -> None:
        """Display prominent connection loss or API unreachable warning banner.

        Args:
            message: Custom error explanation, or standard default if None.
        """
        msg = (
            message.strip()
            if message and message.strip()
            else "API connection unreachable. Operating with retained data."
        )
        self._update_banner(
            banner_type=STATE_DISCONNECTED,
            indicator_text="DISCONNECTED",
            message_text=msg,
        )

    def show_degraded(self, message: str | None = None) -> None:
        """Display operational degradation warning banner.

        Args:
            message: Custom degradation detail, or standard default if None.
        """
        msg = (
            message.strip()
            if message and message.strip()
            else "Backend operational status is degraded."
        )
        self._update_banner(
            banner_type=STATE_DEGRADED,
            indicator_text="DEGRADED",
            message_text=msg,
        )

    def clear(self) -> None:
        """Clear warning state and hide the banner."""
        if self.isHidden() and self._current_type == "":
            return

        self._current_type = ""
        self._current_message = ""
        self._indicator_label.setText("")
        self._message_label.setText("")

        self.setProperty("bannerType", "")
        self._indicator_label.setProperty("bannerType", "")

        style = self.style()
        if style is not None:
            style.unpolish(self)
            style.polish(self)

        ind_style = self._indicator_label.style()
        if ind_style is not None:
            ind_style.unpolish(self._indicator_label)
            ind_style.polish(self._indicator_label)

        self.setVisible(False)

    # -----------------------------------------------------------------------
    # Internal Helpers
    # -----------------------------------------------------------------------

    def _update_banner(
        self,
        banner_type: str,
        indicator_text: str,
        message_text: str,
    ) -> None:
        """Apply state, text, and dynamic properties in a flicker-free manner."""
        type_changed = self._current_type != banner_type

        self._current_type = banner_type
        self._current_message = message_text

        if self._indicator_label.text() != indicator_text:
            self._indicator_label.setText(indicator_text)

        if self._message_label.text() != message_text:
            self._message_label.setText(message_text)

        if type_changed:
            self.setProperty("bannerType", banner_type)
            self._indicator_label.setProperty("bannerType", banner_type)

            style = self.style()
            if style is not None:
                style.unpolish(self)
                style.polish(self)

            ind_style = self._indicator_label.style()
            if ind_style is not None:
                ind_style.unpolish(self._indicator_label)
                ind_style.polish(self._indicator_label)

        if not self.isVisible():
            self.setVisible(True)


__all__ = [
    "ErrorBanner",
    "STATE_DEGRADED",
    "STATE_DISCONNECTED",
    "STATE_HIDDEN",
]
