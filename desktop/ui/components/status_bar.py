"""OSIRIS native Qt status bar component.

Displays API connectivity, system status, database health, session mode,
and last update timestamp in a compact, persistent bottom bar.
"""

from __future__ import annotations

from datetime import datetime, timezone

from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QWidget

from desktop.client.models import HealthStatus, SystemStatus, User
from desktop.ui.design_tokens import SPACE_3, SPACE_4, STATUS_BAR_HEIGHT


class StatusBar(QFrame):
    """Bottom status bar displaying infrastructure and session health."""

    def __init__(
        self,
        parent: QWidget | None = None,
        user: User | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("BottomStatusBar")
        self.setFixedHeight(STATUS_BAR_HEIGHT)

        self._user: User | None = user
        self._last_updated_time: datetime | str | None = None

        layout = QHBoxLayout(self)
        layout.setContentsMargins(SPACE_4, 0, SPACE_4, 0)
        layout.setSpacing(SPACE_3)

        mode_text = (
            "Mode: Authenticated Session"
            if self._user is not None
            else "Mode: Visual Prototype"
        )
        self._mode_label = QLabel(mode_text, self)
        self._mode_label.setObjectName("StatusModeLabel")

        self._sep1 = QLabel("|", self)
        self._sep1.setObjectName("StatusSeparator")

        api_text = (
            "API: Unknown"
            if self._user is not None
            else "API: Disconnected (Integration Pending)"
        )
        api_state = "unknown" if self._user is not None else "disconnected"
        self._api_label = QLabel(api_text, self)
        self._api_label.setObjectName("StatusApiLabel")
        self._api_label.setProperty("apiState", api_state)

        self._sep2 = QLabel("|", self)
        self._sep2.setObjectName("StatusSeparator")

        sys_text = (
            "System: Unknown"
            if self._user is not None
            else "System: Offline (Preview)"
        )
        sys_state = "unknown" if self._user is not None else "offline"
        self._system_label = QLabel(sys_text, self)
        self._system_label.setObjectName("StatusSystemLabel")
        self._system_label.setProperty("systemState", sys_state)

        self._sep3 = QLabel("|", self)
        self._sep3.setObjectName("StatusSeparator")

        db_text = (
            "Database: Unknown"
            if self._user is not None
            else "Database: Offline (Preview)"
        )
        db_state = "unknown" if self._user is not None else "offline"
        self._database_label = QLabel(db_text, self)
        self._database_label.setObjectName("StatusDatabaseLabel")
        self._database_label.setProperty("dbState", db_state)

        self._sep4 = QLabel("|", self)
        self._sep4.setObjectName("StatusSeparator")

        self._last_updated_label = QLabel("Updated: Never", self)
        self._last_updated_label.setObjectName("StatusLastUpdatedLabel")
        self._last_updated_label.setToolTip(
            "No operational status checks have completed yet."
        )

        layout.addWidget(self._mode_label)
        layout.addWidget(self._sep1)
        layout.addWidget(self._api_label)
        layout.addWidget(self._sep2)
        layout.addWidget(self._system_label)
        layout.addWidget(self._sep3)
        layout.addWidget(self._database_label)
        layout.addWidget(self._sep4)
        layout.addWidget(self._last_updated_label)
        layout.addStretch(1)

        notice_text = (
            "Session authenticated \u2022 Feature integration pending"
            if self._user is not None
            else "Standalone Prototype \u2022 Live telemetry unavailable"
        )
        self._security_notice = QLabel(notice_text, self)
        self._security_notice.setObjectName("StatusSecurityNotice")
        layout.addWidget(self._security_notice)

    # -----------------------------------------------------------------------
    # Public Properties
    # -----------------------------------------------------------------------

    @property
    def mode_label(self) -> QLabel:
        """Return the session mode label."""
        return self._mode_label

    @property
    def api_label(self) -> QLabel:
        """Return the API connectivity status label."""
        return self._api_label

    @property
    def system_label(self) -> QLabel:
        """Return the backend system health label."""
        return self._system_label

    @property
    def database_label(self) -> QLabel:
        """Return the database health label."""
        return self._database_label

    @property
    def last_updated_label(self) -> QLabel:
        """Return the last update timestamp label."""
        return self._last_updated_label

    @property
    def security_notice(self) -> QLabel:
        """Return the trailing security notice label."""
        return self._security_notice

    @property
    def last_updated_time(self) -> datetime | str | None:
        """Return the recorded observation timestamp of the last status update."""
        return self._last_updated_time

    # -----------------------------------------------------------------------
    # Internal Helpers
    # -----------------------------------------------------------------------

    def _set_label_state(
        self,
        label: QLabel,
        text: str,
        prop_name: str,
        prop_val: str,
        tooltip: str = "",
    ) -> None:
        """Update label text, dynamic property, and re-polish stylesheet.

        Avoids style unpolish/polish unless property value actually changed,
        preventing UI flicker and layout thrashing.
        """
        prop_changed = label.property(prop_name) != prop_val
        if prop_changed:
            label.setProperty(prop_name, prop_val)
            style = label.style()
            if style is not None:
                style.unpolish(label)
                style.polish(label)

        if label.text() != text:
            label.setText(text)

        if tooltip and label.toolTip() != tooltip:
            label.setToolTip(tooltip)

    # -----------------------------------------------------------------------
    # Status Mutations
    # -----------------------------------------------------------------------

    def set_checking(self) -> None:
        """Update status bar indicators to indicate an active check in flight."""
        self._set_label_state(
            self._api_label,
            "API: Checking...",
            "apiState",
            "checking",
            "Checking API operational status...",
        )
        self._set_label_state(
            self._system_label,
            "System: Checking...",
            "systemState",
            "checking",
            "Checking backend system status...",
        )
        self._set_label_state(
            self._database_label,
            "Database: Checking...",
            "dbState",
            "checking",
            "Checking database connectivity...",
        )

    def apply_status(
        self,
        health: HealthStatus | None,
        health_error: str | None,
        system: SystemStatus | None,
        system_error: str | None,
        timestamp: datetime | str | None = None,
    ) -> None:
        """Update status bar indicators from actual endpoint responses."""
        # 1. API Reachability (/health)
        if health is not None and health.status == "ok":
            self._set_label_state(
                self._api_label,
                "API: Reachable",
                "apiState",
                "reachable",
                f"API is reachable (system: {health.system}).",
            )
        else:
            err = health_error or "Service unavailable"
            self._set_label_state(
                self._api_label,
                "API: Unavailable",
                "apiState",
                "unavailable",
                f"API health check failed: {err}",
            )

        # 2. System and Database status (/api/status)
        if system is not None:
            sys_state = "healthy" if system.status == "healthy" else "degraded"
            self._set_label_state(
                self._system_label,
                f"System: {system.status.capitalize()}",
                "systemState",
                sys_state,
                (
                    f"System status: {system.status} "
                    f"(host: {system.host_id or 'unknown'})"
                ),
            )

            db_state = (
                "connected" if system.database == "connected" else "disconnected"
            )
            self._set_label_state(
                self._database_label,
                f"Database: {system.database.capitalize()}",
                "dbState",
                db_state,
                f"Database connectivity: {system.database}",
            )
        else:
            err = system_error or "Status unavailable"
            self._set_label_state(
                self._system_label,
                "System: Unavailable",
                "systemState",
                "unavailable",
                f"System status check failed: {err}",
            )
            self._set_label_state(
                self._database_label,
                "Database: Unavailable",
                "dbState",
                "unavailable",
                f"Database status check failed: {err}",
            )

        # 3. Last Updated Timestamp
        actual_ts = (
            timestamp if timestamp is not None else datetime.now(timezone.utc)
        )
        self._last_updated_time = actual_ts
        if isinstance(actual_ts, datetime):
            formatted = actual_ts.strftime("%H:%M:%S UTC")
        else:
            formatted = str(actual_ts).strip()
        self._last_updated_label.setText(f"Updated: {formatted}")
        self._last_updated_label.setToolTip(
            f"Last operational status refresh at {formatted}."
        )

    def set_user(self, user: User | None) -> None:
        """Update authenticated user context and refresh interface messaging."""
        self._user = user
        if self._user is not None:
            self._mode_label.setText("Mode: Authenticated Session")
            self._security_notice.setText(
                "Session authenticated \u2022 Feature integration pending"
            )
        else:
            self._mode_label.setText("Mode: Visual Prototype")
            self._security_notice.setText(
                "Standalone Prototype \u2022 Live telemetry unavailable"
            )
            self._set_label_state(
                self._api_label,
                "API: Disconnected (Integration Pending)",
                "apiState",
                "disconnected",
            )
            self._set_label_state(
                self._system_label,
                "System: Offline (Preview)",
                "systemState",
                "offline",
            )
            self._set_label_state(
                self._database_label,
                "Database: Offline (Preview)",
                "dbState",
                "offline",
            )
            self._last_updated_time = None
            self._last_updated_label.setText("Updated: Never")
            self._last_updated_label.setToolTip(
                "No operational status checks have completed yet."
            )

    def clear(self) -> None:
        """Reset status bar to initial unauthenticated prototype state."""
        self.set_user(None)
