"""OSIRIS visual shell prototype.

Provides AppShell, the primary desktop layout container coordinating the left
navigation, top header, contextual toolbar, stacked content pages, and bottom
status bar.

This is a local visual prototype only.  It does not connect to any API,
database, or collector service.  No fabricated telemetry, incident counts,
or endpoint data is displayed.
"""

from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QButtonGroup,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from desktop.client.models import HealthStatus, SystemStatus, User
from desktop.ui.components.error_banner import ErrorBanner
from desktop.ui.components.root_warning_banner import RootWarningBanner
from desktop.ui.components.status_bar import StatusBar
from desktop.ui.design_tokens import (
    CONTEXTUAL_TOOLBAR_HEIGHT,
    EXPANDED_NAVIGATION_WIDTH,
    SPACE_1,
    SPACE_2,
    SPACE_3,
    SPACE_4,
    SPACE_6,
    TOP_HEADER_HEIGHT,
)
from desktop.ui.views.events_view import EventsView
from desktop.ui.views.files_view import FilesView
from desktop.ui.views.processes_view import ProcessesView
from desktop.ui.views.resources_view import ResourcesView

# ---------------------------------------------------------------------------
# Navigation page definitions
# ---------------------------------------------------------------------------
# Each tuple: (page_id, nav_label, page_title, empty_state_description)

NAV_ITEMS: list[tuple[str, str, str, str]] = [
    (
        "Overview",
        "Overview",
        "System Overview",
        "Operational summary will appear when live integration exists.",
    ),
    (
        "Events",
        "Events",
        "Security Events",
        "Real-time security events from monitored endpoints. "
        "Filtering and detail inspection pending.",
    ),
    (
        "Processes",
        "Processes",
        "Process Activity",
        "Process visibility is not connected yet.",
    ),
    (
        "Resources",
        "Resources",
        "Host Resources",
        "Resource telemetry is not connected yet.",
    ),
    (
        "Files",
        "Files",
        "Filesystem Audit",
        "File visibility is not connected yet.",
    ),
]


class AppShell(QWidget):
    """Primary application shell for the OSIRIS native desktop console.

    Layout structure::

        ┌──────────┬────────────────────────────────────────┐
        │          │  TopHeader (48px)                      │
        │  LeftNav ├────────────────────────────────────────┤
        │  (200px) │  ContextualToolbar (44px)              │
        │          ├────────────────────────────────────────┤
        │  Brand   │                                        │
        │  + 5 nav │  MainContentStack (stretch)            │
        │  buttons │                                        │
        │          ├────────────────────────────────────────┤
        │          │  BottomStatusBar (28px)                │
        └──────────┴────────────────────────────────────────┘
    """

    logout_requested = Signal()
    status_check_requested = Signal()
    events_load_requested = Signal()
    events_refresh_requested = Signal()
    processes_load_requested = Signal()
    processes_refresh_requested = Signal()
    processes_query_requested = Signal(object)
    resources_load_requested = Signal()
    resources_refresh_requested = Signal()
    resources_query_requested = Signal(object)
    files_load_requested = Signal()
    files_refresh_requested = Signal()
    files_query_requested = Signal(object)
    error_banner_retry_requested = Signal()
    page_changed = Signal(str)

    def __init__(
        self,
        user: User | None = None,
        parent: QWidget | None = None,
        is_root: bool = False,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("AppShell")
        self._user = user
        self._is_root: bool = bool(is_root)
        self._current_page_name: str = NAV_ITEMS[0][0]

        # Root: left nav + right content area
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # -- Left navigation ------------------------------------------------
        self._left_nav = self._build_left_nav()
        root.addWidget(self._left_nav)

        # -- Right content container ----------------------------------------
        right = QWidget(self)
        right.setObjectName("ContentArea")
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)

        self._top_header = self._build_top_header()
        self._root_warning_banner = RootWarningBanner(self, is_root=self._is_root)
        self._error_banner = ErrorBanner(self)
        self._error_banner.retry_requested.connect(
            self.error_banner_retry_requested.emit
        )
        self._toolbar = self._build_contextual_toolbar()
        self._content_stack = self._build_content_stack()
        self._status_bar = self._build_status_bar()

        right_layout.addWidget(self._top_header)
        right_layout.addWidget(self._root_warning_banner)
        right_layout.addWidget(self._error_banner)
        right_layout.addWidget(self._toolbar)
        right_layout.addWidget(self._content_stack, 1)
        right_layout.addWidget(self._status_bar)

        root.addWidget(right, 1)

        # Default to the first page
        self.navigate_to("Overview")

    # -----------------------------------------------------------------------
    # Builder helpers
    # -----------------------------------------------------------------------

    def _build_left_nav(self) -> QFrame:
        frame = QFrame(self)
        frame.setObjectName("LeftNav")
        frame.setFixedWidth(EXPANDED_NAVIGATION_WIDTH)

        layout = QVBoxLayout(frame)
        layout.setContentsMargins(SPACE_3, SPACE_4, SPACE_3, SPACE_4)
        layout.setSpacing(SPACE_2)

        # Brand block
        brand = QWidget(frame)
        brand.setObjectName("NavBrandContainer")
        brand_ly = QVBoxLayout(brand)
        brand_ly.setContentsMargins(SPACE_2, 0, SPACE_2, SPACE_4)
        brand_ly.setSpacing(SPACE_1)

        title = QLabel("OSIRIS", brand)
        title.setObjectName("NavBrandTitle")

        subtitle = QLabel("Endpoint Intelligence", brand)
        subtitle.setObjectName("NavBrandSubtitle")

        brand_ly.addWidget(title)
        brand_ly.addWidget(subtitle)
        layout.addWidget(brand)

        # Navigation buttons
        self._nav_btn_group = QButtonGroup(self)
        self._nav_btn_group.setExclusive(True)
        self._nav_buttons: dict[str, QPushButton] = {}

        for idx, (page_id, label, _, _) in enumerate(NAV_ITEMS):
            btn = QPushButton(label, frame)
            btn.setObjectName(f"NavButton_{page_id}")
            btn.setProperty("navItem", page_id.lower())
            btn.setCheckable(True)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda _checked, key=page_id: self.navigate_to(key))
            self._nav_btn_group.addButton(btn, idx)
            layout.addWidget(btn)
            self._nav_buttons[page_id] = btn

        layout.addStretch(1)
        return frame

    def _build_top_header(self) -> QFrame:
        header = QFrame(self)
        header.setObjectName("TopHeader")
        header.setFixedHeight(TOP_HEADER_HEIGHT)

        ly = QHBoxLayout(header)
        ly.setContentsMargins(SPACE_4, 0, SPACE_4, 0)
        ly.setSpacing(SPACE_3)

        header_title = QLabel("OSIRIS Security Console", header)
        header_title.setObjectName("HeaderTitle")

        sep = QLabel("|", header)
        sep.setObjectName("HeaderSeparator")

        context = QLabel("Workspace: Local Console", header)
        context.setObjectName("HeaderContext")

        ly.addWidget(header_title)
        ly.addWidget(sep)
        ly.addWidget(context)
        ly.addStretch(1)

        # Authenticated user identity and role labels
        self._user_identity_label = QLabel(header)
        self._user_identity_label.setObjectName("UserIdentityLabel")
        self._user_identity_label.setMaximumWidth(220)

        self._user_role_badge = QLabel(header)
        self._user_role_badge.setObjectName("UserRoleBadge")

        # Session mode badge
        self._mode_badge = QLabel(header)
        self._mode_badge.setObjectName("HeaderModeBadge")

        # Explicit Logout action button
        self._logout_btn = QPushButton("Log Out", header)
        self._logout_btn.setObjectName("LogoutButton")
        self._logout_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._logout_btn.clicked.connect(self._handle_logout_click)

        ly.addWidget(self._user_identity_label)
        ly.addWidget(self._user_role_badge)
        ly.addWidget(self._mode_badge)
        ly.addWidget(self._logout_btn)

        self._update_header_identity()
        return header

    def _update_header_identity(self) -> None:
        """Update header identity, role, and mode badge from current user context."""
        if self._user is not None:
            raw_name = (
                self._user.display_name.strip()
                if self._user.display_name and self._user.display_name.strip()
                else self._user.username.strip()
            )
            self._user_identity_label.setText(raw_name)
            self._user_identity_label.setToolTip(f"Signed in as {raw_name}")
            self._user_identity_label.setVisible(True)

            if self._user.role and self._user.role.strip():
                role_upper = self._user.role.strip().upper()
                self._user_role_badge.setText(role_upper)
                self._user_role_badge.setProperty(
                    "role", self._user.role.strip().lower()
                )
                self._user_role_badge.setVisible(True)
            else:
                self._user_role_badge.setText("")
                self._user_role_badge.setVisible(False)

            self._mode_badge.setText("AUTHENTICATED SESSION")
            self._mode_badge.setProperty("authenticated", "true")
        else:
            self._user_identity_label.setText("")
            self._user_identity_label.setVisible(False)
            self._user_role_badge.setText("")
            self._user_role_badge.setVisible(False)
            self._mode_badge.setText("PROTOTYPE PREVIEW")
            self._mode_badge.setProperty("authenticated", "false")

        style = self._mode_badge.style()
        if style is not None:
            style.unpolish(self._mode_badge)
            style.polish(self._mode_badge)

    def _build_contextual_toolbar(self) -> QFrame:
        toolbar = QFrame(self)
        toolbar.setObjectName("ContextualToolbar")
        toolbar.setFixedHeight(CONTEXTUAL_TOOLBAR_HEIGHT)

        ly = QHBoxLayout(toolbar)
        ly.setContentsMargins(SPACE_4, 0, SPACE_4, 0)
        ly.setSpacing(SPACE_3)

        self._toolbar_context_label = QLabel("System Overview", toolbar)
        self._toolbar_context_label.setObjectName("ToolbarContextLabel")

        sep = QLabel("|", toolbar)
        sep.setObjectName("ToolbarSeparator")

        sub_text = (
            "Live Data Views: Pending"
            if self._user is not None
            else "Local Console Preview"
        )
        self._toolbar_sub_context_label = QLabel(sub_text, toolbar)
        self._toolbar_sub_context_label.setObjectName("ToolbarSubContextLabel")

        ly.addWidget(self._toolbar_context_label)
        ly.addWidget(sep)
        ly.addWidget(self._toolbar_sub_context_label)
        ly.addStretch(1)

        refresh = QPushButton("Refresh (Offline)", toolbar)
        refresh.setObjectName("ToolbarAction_Refresh")
        refresh.setEnabled(False)

        self._check_status_btn = QPushButton("Check Status", toolbar)
        self._check_status_btn.setObjectName("CheckStatusButton")
        self._check_status_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._check_status_btn.clicked.connect(self._handle_check_status_click)

        ly.addWidget(self._check_status_btn)
        ly.addWidget(refresh)

        return toolbar

    def _build_content_stack(self) -> QStackedWidget:
        stack = QStackedWidget(self)
        stack.setObjectName("MainContentStack")
        self._page_widgets: dict[str, QWidget] = {}

        for page_id, _, page_title, description in NAV_ITEMS:
            if page_id == "Events":
                self._events_view = EventsView(parent=self)
                self._events_view.load_requested.connect(
                    self.events_load_requested
                )
                self._events_view.refresh_requested.connect(
                    self.events_refresh_requested
                )
                stack.addWidget(self._events_view)
                self._page_widgets[page_id] = self._events_view
            elif page_id == "Processes":
                self._processes_view = ProcessesView(parent=self)
                self._processes_view.load_requested.connect(
                    self.processes_load_requested
                )
                self._processes_view.refresh_requested.connect(
                    self.processes_refresh_requested
                )
                self._processes_view.query_requested.connect(
                    self.processes_query_requested
                )
                stack.addWidget(self._processes_view)
                self._page_widgets[page_id] = self._processes_view
            elif page_id == "Resources":
                self._resources_view = ResourcesView(parent=self)
                self._resources_view.load_requested.connect(
                    self.resources_load_requested
                )
                self._resources_view.refresh_requested.connect(
                    self.resources_refresh_requested
                )
                self._resources_view.query_requested.connect(
                    self.resources_query_requested
                )
                stack.addWidget(self._resources_view)
                self._page_widgets[page_id] = self._resources_view
            elif page_id == "Files":
                self._files_view = FilesView(parent=self, title=page_title)
                self._files_view.load_requested.connect(
                    self.files_load_requested
                )
                self._files_view.refresh_requested.connect(
                    self.files_refresh_requested
                )
                self._files_view.query_requested.connect(
                    self.files_query_requested
                )
                stack.addWidget(self._files_view)
                self._page_widgets[page_id] = self._files_view
            else:
                page = self._build_placeholder_page(
                    page_id, page_title, description
                )
                stack.addWidget(page)
                self._page_widgets[page_id] = page

        return stack

    def _build_placeholder_page(
        self,
        page_id: str,
        title: str,
        description: str,
    ) -> QFrame:
        """Build a single placeholder content page with an empty-state card."""
        page = QFrame(self)
        page.setObjectName(f"Page_{page_id}")
        page.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        ly = QVBoxLayout(page)
        ly.setContentsMargins(SPACE_6, SPACE_6, SPACE_6, SPACE_6)
        ly.setSpacing(SPACE_4)

        # Page header
        header = QWidget(page)
        header.setObjectName(f"PageHeader_{page_id}")
        h_ly = QVBoxLayout(header)
        h_ly.setContentsMargins(0, 0, 0, 0)
        h_ly.setSpacing(SPACE_1)

        title_lbl = QLabel(title, header)
        title_lbl.setObjectName("PageTitle")

        desc_lbl = QLabel(description, header)
        desc_lbl.setObjectName("PageDescription")

        h_ly.addWidget(title_lbl)
        h_ly.addWidget(desc_lbl)
        ly.addWidget(header)

        # Empty-state card
        card = QFrame(page)
        card.setObjectName("EmptyStateFrame")
        card_ly = QVBoxLayout(card)
        card_ly.setContentsMargins(SPACE_6, SPACE_6, SPACE_6, SPACE_6)
        card_ly.setSpacing(SPACE_2)
        card_ly.setAlignment(Qt.AlignmentFlag.AlignCenter)

        empty_title = QLabel("Live Telemetry Not Connected", card)
        empty_title.setObjectName("EmptyStateTitle")
        empty_title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        empty_msg = QLabel(
            "This view is operating in visual prototype mode. Live endpoint data, "
            "investigation records, and telemetry streams will populate here once "
            "the API and collector ingestion layers are connected.",
            card,
        )
        empty_msg.setObjectName("EmptyStateMessage")
        empty_msg.setAlignment(Qt.AlignmentFlag.AlignCenter)
        empty_msg.setWordWrap(True)
        empty_msg.setMaximumWidth(580)

        card_ly.addWidget(empty_title)
        card_ly.addWidget(empty_msg)
        ly.addWidget(card, 1)

        return page

    def _build_status_bar(self) -> StatusBar:
        """Build and return the bottom StatusBar component."""
        return StatusBar(parent=self, user=self._user)

    # -----------------------------------------------------------------------
    # Navigation API
    # -----------------------------------------------------------------------

    def navigate_to(self, page_name: str) -> None:
        """Switch the current displayed page and update navigation state.

        Args:
            page_name: One of the defined page IDs (case-insensitive).

        Raises:
            ValueError: If *page_name* does not match any defined page.
        """
        target = None
        for item in NAV_ITEMS:
            if item[0].lower() == page_name.lower():
                target = item
                break

        if target is None:
            valid = ", ".join(i[0] for i in NAV_ITEMS)
            raise ValueError(
                f"Unknown page '{page_name}'. Valid pages are: {valid}"
            )

        page_id, _, page_title, _ = target
        index = [i[0] for i in NAV_ITEMS].index(page_id)

        old_page = self._current_page_name
        if old_page != page_id:
            if old_page == "Events":
                self._events_view.notify_page_deactivated()
            elif old_page == "Processes":
                self._processes_view.notify_page_deactivated()
            elif old_page == "Resources":
                self._resources_view.notify_page_deactivated()
            elif old_page == "Files":
                self._files_view.notify_page_deactivated()

        self._current_page_name = page_id
        self._content_stack.setCurrentIndex(index)

        btn = self._nav_buttons.get(page_id)
        if btn is not None and not btn.isChecked():
            btn.setChecked(True)

        self._toolbar_context_label.setText(page_title)

        if page_id == "Events":
            self._events_view.notify_page_activated()
        elif page_id == "Processes":
            self._processes_view.notify_page_activated()
        elif page_id == "Resources":
            self._resources_view.notify_page_activated()
        elif page_id == "Files":
            self._files_view.notify_page_activated()

        if old_page != page_id:
            self.page_changed.emit(page_id)

    @property
    def events_view(self) -> EventsView:
        """Return the integrated EventsView instance."""
        return self._events_view

    @property
    def processes_view(self) -> ProcessesView:
        """Return the integrated ProcessesView instance."""
        return self._processes_view

    @property
    def resources_view(self) -> ResourcesView:
        """Return the integrated ResourcesView instance."""
        return self._resources_view

    @property
    def files_view(self) -> FilesView:
        """Return the integrated FilesView instance."""
        return self._files_view

    @property
    def current_page_name(self) -> str:
        """Return the ID of the currently visible navigation page."""
        idx = self._content_stack.currentIndex()
        if 0 <= idx < len(NAV_ITEMS):
            return NAV_ITEMS[idx][0]
        return ""

    @property
    def current_page_index(self) -> int:
        """Return the zero-based index of the currently visible page."""
        return self._content_stack.currentIndex()

    def get_nav_button(self, page_name: str) -> QPushButton | None:
        """Return the navigation button for a page (case-insensitive lookup)."""
        for item in NAV_ITEMS:
            if item[0].lower() == page_name.lower():
                return self._nav_buttons.get(item[0])
        return None

    def get_page_widget(self, page_name: str) -> QWidget | None:
        """Return the placeholder page widget (case-insensitive lookup)."""
        for item in NAV_ITEMS:
            if item[0].lower() == page_name.lower():
                return self._page_widgets.get(item[0])
        return None

    @property
    def toolbar_context_label(self) -> QLabel:
        """Return the toolbar's context-title label."""
        return self._toolbar_context_label

    @property
    def content_stack(self) -> QStackedWidget:
        """Return the main content QStackedWidget."""
        return self._content_stack

    def _handle_logout_click(self) -> None:
        """Emit logout_requested signal when Logout button is activated."""
        self.logout_requested.emit()

    def _handle_check_status_click(self) -> None:
        """Emit status_check_requested signal when Check Status is activated."""
        self.status_check_requested.emit()

    def set_status_checking(self) -> None:
        """Update status bar labels and button to indicate check in progress."""
        self._check_status_btn.setEnabled(False)
        self._check_status_btn.setText("Checking...")
        self._status_bar.set_checking()

    def set_status_check_enabled(self, enabled: bool) -> None:
        """Enable or disable the Check Status button."""
        self._check_status_btn.setEnabled(enabled)
        if enabled:
            self._check_status_btn.setText("Check Status")

    def apply_operational_status(
        self,
        health: HealthStatus | None,
        health_error: str | None,
        system: SystemStatus | None,
        system_error: str | None,
        timestamp: datetime | str | None = None,
    ) -> None:
        """Update status bar indicators from actual endpoint responses."""
        self._status_bar.apply_status(
            health=health,
            health_error=health_error,
            system=system,
            system_error=system_error,
            timestamp=timestamp,
        )

    @property
    def user(self) -> User | None:
        """Return the authenticated user profile, if set."""
        return self._user

    @property
    def logout_button(self) -> QPushButton:
        """Return the top header logout button."""
        return self._logout_btn

    @property
    def check_status_button(self) -> QPushButton:
        """Return the manual Check Status toolbar button."""
        return self._check_status_btn

    @property
    def user_identity_label(self) -> QLabel:
        """Return the top header user identity label."""
        return self._user_identity_label

    @property
    def user_role_badge(self) -> QLabel:
        """Return the top header user role badge."""
        return self._user_role_badge

    @property
    def status_bar(self) -> StatusBar:
        """Return the dedicated bottom StatusBar instance."""
        return self._status_bar

    @property
    def status_api_label(self) -> QLabel:
        """Return the API operational status label."""
        return self._status_bar.api_label

    @property
    def status_system_label(self) -> QLabel:
        """Return the system operational status label."""
        return self._status_bar.system_label

    @property
    def status_database_label(self) -> QLabel:
        """Return the database operational status label."""
        return self._status_bar.database_label

    @property
    def status_mode_label(self) -> QLabel:
        """Return the session mode label."""
        return self._status_bar.mode_label

    @property
    def status_security_notice(self) -> QLabel:
        """Return the bottom status security notice label."""
        return self._status_bar.security_notice

    def set_user(self, user: User | None) -> None:
        """Update authenticated user context and refresh interface messaging."""
        self._user = user
        self._update_header_identity()
        self._status_bar.set_user(user)
        if self._user is not None:
            self._toolbar_sub_context_label.setText("Live Data Views: Pending")
        else:
            self._toolbar_sub_context_label.setText("Local Console Preview")

    @property
    def error_banner(self) -> ErrorBanner:
        """Return the global error and degraded warning banner."""
        return self._error_banner

    def show_connection_error(self, message: str | None = None) -> None:
        """Display API connection failure banner across the content area."""
        self._error_banner.show_connection_error(message)

    def show_degraded_warning(self, message: str | None = None) -> None:
        """Display backend degradation warning banner across the content area."""
        self._error_banner.show_degraded(message)

    def clear_global_warning(self) -> None:
        """Clear global error/degraded banner and hide it."""
        self._error_banner.clear()

    @property
    def is_root(self) -> bool:
        """Return True if root execution security warning is active."""
        return self._is_root

    @property
    def root_warning_banner(self) -> RootWarningBanner:
        """Return the root execution security warning banner."""
        return self._root_warning_banner

    def set_root_warning(
        self, is_root: bool, message: str | None = None
    ) -> None:
        """Update root execution security warning banner state."""
        self._is_root = bool(is_root)
        self._root_warning_banner.set_root_warning(self._is_root, message)


