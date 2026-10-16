"""Comprehensive tests for the OSIRIS AppShell visual shell prototype.

Verifies:
1. AppShell instantiation and object naming.
2. Structural layout: left nav, header, toolbar, content stack, status bar.
3. Left navigation: brand block, 5 nav buttons, button group exclusivity.
4. Navigation switching: all 5 pages reachable, toolbar label updates.
5. Case-insensitive navigation and invalid page rejection.
6. Initial state: Overview is the default page.
7. Page placeholder content: titles, descriptions, empty-state cards.
8. Dimensional constraints: header, toolbar, status bar, nav width.
9. Object name conventions across all structural elements.
10. No fabricated telemetry data anywhere in the shell.
"""

from __future__ import annotations

import pytest
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QFrame,
    QLabel,
    QPushButton,
    QStackedWidget,
    QTableView,
    QWidget,
)

from desktop.client.models import User
from desktop.ui.app_shell import NAV_ITEMS, AppShell
from desktop.ui.design_tokens import (
    CONTEXTUAL_TOOLBAR_HEIGHT,
    EXPANDED_NAVIGATION_WIDTH,
    STATUS_BAR_HEIGHT,
    TOP_HEADER_HEIGHT,
)
from desktop.ui.views.files_view import FilesQuery, FilesView
from desktop.ui.views.processes_view import ProcessesQuery
from desktop.ui.views.resources_view import ResourcesQuery, ResourcesView

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture()
def shell(qapp: QApplication) -> AppShell:
    """Create and return a fresh AppShell instance."""
    return AppShell()


# ============================================================================
# 1. Instantiation & Identity
# ============================================================================


def test_shell_instantiation(shell: AppShell) -> None:
    """AppShell can be created without errors."""
    assert shell is not None
    assert isinstance(shell, QWidget)


def test_shell_object_name(shell: AppShell) -> None:
    """AppShell has the expected object name."""
    assert shell.objectName() == "AppShell"


# ============================================================================
# 2. Structural Layout
# ============================================================================


def test_shell_has_left_nav(shell: AppShell) -> None:
    """AppShell contains a LeftNav QFrame."""
    nav = shell.findChild(QFrame, "LeftNav")
    assert nav is not None
    assert isinstance(nav, QFrame)


def test_shell_has_top_header(shell: AppShell) -> None:
    """AppShell contains a TopHeader QFrame."""
    header = shell.findChild(QFrame, "TopHeader")
    assert header is not None
    assert isinstance(header, QFrame)


def test_shell_has_contextual_toolbar(shell: AppShell) -> None:
    """AppShell contains a ContextualToolbar QFrame."""
    toolbar = shell.findChild(QFrame, "ContextualToolbar")
    assert toolbar is not None
    assert isinstance(toolbar, QFrame)


def test_shell_has_content_stack(shell: AppShell) -> None:
    """AppShell contains a MainContentStack QStackedWidget."""
    stack = shell.findChild(QStackedWidget, "MainContentStack")
    assert stack is not None
    assert isinstance(stack, QStackedWidget)


def test_shell_has_status_bar(shell: AppShell) -> None:
    """AppShell contains a BottomStatusBar QFrame."""
    bar = shell.findChild(QFrame, "BottomStatusBar")
    assert bar is not None
    assert isinstance(bar, QFrame)


def test_shell_has_content_area(shell: AppShell) -> None:
    """AppShell contains a ContentArea container widget."""
    area = shell.findChild(QWidget, "ContentArea")
    assert area is not None


# ============================================================================
# 3. Left Navigation
# ============================================================================


def test_nav_brand_title(shell: AppShell) -> None:
    """Left nav contains the OSIRIS brand title."""
    title = shell.findChild(QLabel, "NavBrandTitle")
    assert title is not None
    assert title.text() == "OSIRIS"


def test_nav_brand_subtitle(shell: AppShell) -> None:
    """Left nav contains the brand subtitle."""
    subtitle = shell.findChild(QLabel, "NavBrandSubtitle")
    assert subtitle is not None
    assert subtitle.text() == "Endpoint Intelligence"


def test_nav_has_five_buttons(shell: AppShell) -> None:
    """Left nav contains exactly 5 navigation buttons."""
    for page_id, label, _, _ in NAV_ITEMS:
        btn = shell.findChild(QPushButton, f"NavButton_{page_id}")
        assert btn is not None, f"Missing NavButton_{page_id}"
        assert btn.text() == label


def test_nav_buttons_are_checkable(shell: AppShell) -> None:
    """All nav buttons are checkable for toggle state."""
    for page_id, _, _, _ in NAV_ITEMS:
        btn = shell.findChild(QPushButton, f"NavButton_{page_id}")
        assert btn is not None
        assert btn.isCheckable()


def test_nav_buttons_have_nav_item_property(shell: AppShell) -> None:
    """All nav buttons expose a 'navItem' dynamic property for QSS."""
    for page_id, _, _, _ in NAV_ITEMS:
        btn = shell.findChild(QPushButton, f"NavButton_{page_id}")
        assert btn is not None
        assert btn.property("navItem") == page_id.lower()


def test_nav_button_group_is_exclusive(shell: AppShell) -> None:
    """Nav buttons belong to an exclusive QButtonGroup."""
    group = shell.findChild(QButtonGroup)
    assert group is not None
    assert group.exclusive()
    assert len(group.buttons()) == len(NAV_ITEMS)


# ============================================================================
# 4. Initial State
# ============================================================================


def test_initial_page_is_overview(shell: AppShell) -> None:
    """Default page on construction is Overview."""
    assert shell.current_page_name == "Overview"
    assert shell.current_page_index == 0


def test_initial_overview_button_checked(shell: AppShell) -> None:
    """The Overview nav button is initially checked."""
    btn = shell.get_nav_button("Overview")
    assert btn is not None
    assert btn.isChecked()


def test_initial_toolbar_label(shell: AppShell) -> None:
    """Toolbar context label initially reads 'System Overview'."""
    assert shell.toolbar_context_label.text() == "System Overview"


# ============================================================================
# 5. Navigation Switching
# ============================================================================


@pytest.mark.parametrize(
    "page_id, expected_index, expected_title",
    [
        ("Overview", 0, "System Overview"),
        ("Events", 1, "Security Events"),
        ("Processes", 2, "Process Activity"),
        ("Resources", 3, "Host Resources"),
        ("Files", 4, "Filesystem Audit"),
    ],
)
def test_navigate_to_each_page(
    shell: AppShell,
    page_id: str,
    expected_index: int,
    expected_title: str,
) -> None:
    """Each page can be navigated to by name."""
    shell.navigate_to(page_id)
    assert shell.current_page_name == page_id
    assert shell.current_page_index == expected_index
    assert shell.toolbar_context_label.text() == expected_title

    btn = shell.get_nav_button(page_id)
    assert btn is not None
    assert btn.isChecked()


def test_navigate_case_insensitive(shell: AppShell) -> None:
    """Navigation accepts case-insensitive page names."""
    shell.navigate_to("events")
    assert shell.current_page_name == "Events"

    shell.navigate_to("PROCESSES")
    assert shell.current_page_name == "Processes"

    shell.navigate_to("rEsOuRcEs")
    assert shell.current_page_name == "Resources"


def test_navigate_invalid_page_raises(shell: AppShell) -> None:
    """Navigating to a non-existent page raises ValueError."""
    with pytest.raises(ValueError, match="Unknown page"):
        shell.navigate_to("Dashboard")

    with pytest.raises(ValueError, match="Unknown page"):
        shell.navigate_to("")


def test_navigate_round_trip(shell: AppShell) -> None:
    """Navigation round-trips correctly between pages."""
    shell.navigate_to("Files")
    assert shell.current_page_name == "Files"

    shell.navigate_to("Overview")
    assert shell.current_page_name == "Overview"
    assert shell.current_page_index == 0


def test_only_one_button_checked_after_navigation(shell: AppShell) -> None:
    """Exactly one nav button is checked at any time."""
    for page_id, _, _, _ in NAV_ITEMS:
        shell.navigate_to(page_id)
        checked = [
            pid
            for pid, _, _, _ in NAV_ITEMS
            if (btn := shell.get_nav_button(pid)) is not None and btn.isChecked()
        ]
        assert checked == [page_id], f"Expected only {page_id} checked, got {checked}"


# ============================================================================
# 6. Content Stack & Placeholder Pages
# ============================================================================


def test_content_stack_has_five_pages(shell: AppShell) -> None:
    """Content stack contains exactly 5 pages."""
    assert shell.content_stack.count() == len(NAV_ITEMS)


@pytest.mark.parametrize(
    "page_id, page_title",
    [(item[0], item[2]) for item in NAV_ITEMS],
)
def test_page_has_title_and_description(
    shell: AppShell,
    page_id: str,
    page_title: str,
) -> None:
    """Each page has a PageTitle label with the expected text."""
    page = shell.get_page_widget(page_id)
    assert page is not None
    assert page.objectName() == f"Page_{page_id}"

    title_lbl = page.findChild(QLabel, "PageTitle")
    assert title_lbl is not None
    assert title_lbl.text() == page_title


@pytest.mark.parametrize(
    "page_id", [item[0] for item in NAV_ITEMS if item[0] != "Events"]
)
def test_page_has_empty_state_card(shell: AppShell, page_id: str) -> None:
    """Unintegrated placeholder pages have an EmptyStateFrame with title and message."""
    page = shell.get_page_widget(page_id)
    assert page is not None

    card = page.findChild(QFrame, "EmptyStateFrame")
    assert card is not None

    empty_title = card.findChild(QLabel, "EmptyStateTitle")
    assert empty_title is not None
    assert empty_title.text() == "Live Telemetry Not Connected"

    empty_msg = card.findChild(QLabel, "EmptyStateMessage")
    assert empty_msg is not None
    assert "visual prototype mode" in empty_msg.text()


def test_events_page_is_live_events_view(shell: AppShell) -> None:
    """Events page uses live EventsView rather than an empty placeholder."""
    from desktop.ui.views.events_view import EventsView

    events_page = shell.get_page_widget("Events")
    assert isinstance(events_page, EventsView)
    assert shell.events_view is events_page
    assert events_page.findChild(QTableView, "EventsTable") is not None


def test_resources_page_is_live_resources_view(shell: AppShell) -> None:
    """Resources page uses live ResourcesView rather than an empty placeholder."""
    resources_page = shell.get_page_widget("Resources")
    assert isinstance(resources_page, ResourcesView)
    assert shell.resources_view is resources_page
    assert (
        resources_page.findChild(QTableView, "ResourcesTable") is not None
    )


def test_files_page_is_live_files_view(shell: AppShell) -> None:
    """Files page uses live FilesView rather than an empty placeholder."""
    files_page = shell.get_page_widget("Files")
    assert isinstance(files_page, FilesView)
    assert shell.files_view is files_page
    assert files_page.findChild(QTableView, "FilesTable") is not None


def test_get_page_widget_returns_correct_page(shell: AppShell) -> None:
    """get_page_widget returns the correct page widget for each name."""
    for page_id, _, _, _ in NAV_ITEMS:
        page = shell.get_page_widget(page_id)
        assert page is not None
        assert page.objectName() == f"Page_{page_id}"


def test_get_page_widget_case_insensitive(shell: AppShell) -> None:
    """get_page_widget accepts case-insensitive lookups."""
    assert shell.get_page_widget("overview") is shell.get_page_widget("Overview")
    assert shell.get_page_widget("EVENTS") is shell.get_page_widget("Events")


def test_get_page_widget_returns_none_for_invalid(shell: AppShell) -> None:
    """get_page_widget returns None for non-existent pages."""
    assert shell.get_page_widget("Dashboard") is None
    assert shell.get_page_widget("") is None


def test_get_nav_button_returns_none_for_invalid(shell: AppShell) -> None:
    """get_nav_button returns None for non-existent pages."""
    assert shell.get_nav_button("Dashboard") is None
    assert shell.get_nav_button("") is None


# ============================================================================
# 7. Dimensional Constraints
# ============================================================================


def test_left_nav_width(shell: AppShell) -> None:
    """Left nav has a fixed width matching the design token."""
    nav = shell.findChild(QFrame, "LeftNav")
    assert nav is not None
    assert nav.maximumWidth() == EXPANDED_NAVIGATION_WIDTH
    assert nav.minimumWidth() == EXPANDED_NAVIGATION_WIDTH


def test_top_header_height(shell: AppShell) -> None:
    """Top header has a fixed height matching the design token."""
    header = shell.findChild(QFrame, "TopHeader")
    assert header is not None
    assert header.maximumHeight() == TOP_HEADER_HEIGHT
    assert header.minimumHeight() == TOP_HEADER_HEIGHT


def test_toolbar_height(shell: AppShell) -> None:
    """Contextual toolbar has a fixed height matching the design token."""
    toolbar = shell.findChild(QFrame, "ContextualToolbar")
    assert toolbar is not None
    assert toolbar.maximumHeight() == CONTEXTUAL_TOOLBAR_HEIGHT
    assert toolbar.minimumHeight() == CONTEXTUAL_TOOLBAR_HEIGHT


def test_status_bar_height(shell: AppShell) -> None:
    """Bottom status bar has a fixed height matching the design token."""
    bar = shell.findChild(QFrame, "BottomStatusBar")
    assert bar is not None
    assert bar.maximumHeight() == STATUS_BAR_HEIGHT
    assert bar.minimumHeight() == STATUS_BAR_HEIGHT


# ============================================================================
# 8. Top Header Details
# ============================================================================


def test_header_title_label(shell: AppShell) -> None:
    """Header contains the console title."""
    lbl = shell.findChild(QLabel, "HeaderTitle")
    assert lbl is not None
    assert lbl.text() == "OSIRIS Security Console"


def test_header_context_label(shell: AppShell) -> None:
    """Header contains a workspace context label."""
    lbl = shell.findChild(QLabel, "HeaderContext")
    assert lbl is not None
    assert "Local Console" in lbl.text()


def test_header_mode_badge(shell: AppShell) -> None:
    """Header contains a prototype mode badge."""
    badge = shell.findChild(QLabel, "HeaderModeBadge")
    assert badge is not None
    assert "PROTOTYPE" in badge.text()


# ============================================================================
# 9. Contextual Toolbar Details
# ============================================================================


def test_toolbar_context_label_property(shell: AppShell) -> None:
    """toolbar_context_label property returns the correct QLabel."""
    lbl = shell.toolbar_context_label
    assert isinstance(lbl, QLabel)
    assert lbl.objectName() == "ToolbarContextLabel"


def test_toolbar_has_disabled_refresh_button(shell: AppShell) -> None:
    """Toolbar contains a disabled refresh action button."""
    btn = shell.findChild(QPushButton, "ToolbarAction_Refresh")
    assert btn is not None
    assert not btn.isEnabled()
    assert "Offline" in btn.text()


# ============================================================================
# 10. Bottom Status Bar Details
# ============================================================================


def test_status_bar_mode_label(shell: AppShell) -> None:
    """Status bar displays the prototype mode."""
    lbl = shell.findChild(QLabel, "StatusModeLabel")
    assert lbl is not None
    assert "Visual Prototype" in lbl.text()


def test_status_bar_api_label(shell: AppShell) -> None:
    """Status bar displays API disconnected state."""
    lbl = shell.findChild(QLabel, "StatusApiLabel")
    assert lbl is not None
    assert "Disconnected" in lbl.text()


def test_status_bar_security_notice(shell: AppShell) -> None:
    """Status bar displays a standalone prototype notice."""
    lbl = shell.findChild(QLabel, "StatusSecurityNotice")
    assert lbl is not None
    assert "Standalone Prototype" in lbl.text()


# ============================================================================
# 11. No Fabricated Telemetry
# ============================================================================


def test_no_fabricated_data_in_pages(shell: AppShell) -> None:
    """No placeholder pages contain fabricated statistics or endpoint data."""
    fabricated_patterns = [
        "incident",
        "alert count",
        "endpoint count",
        "CPU usage",
        "memory usage",
        "192.168",
        "10.0.0",
        "critical alert",
        "high severity",
    ]
    for page_id, _, _, _ in NAV_ITEMS:
        page = shell.get_page_widget(page_id)
        assert page is not None
        # Collect all text from labels in the page
        labels = page.findChildren(QLabel)
        all_text = " ".join(lbl.text().lower() for lbl in labels)
        for pattern in fabricated_patterns:
            assert pattern.lower() not in all_text, (
                f"Page '{page_id}' contains fabricated data pattern: '{pattern}'"
            )


# ============================================================================
# 12. NAV_ITEMS Module-Level Data
# ============================================================================


def test_nav_items_has_five_entries() -> None:
    """NAV_ITEMS defines exactly 5 navigation pages."""
    assert len(NAV_ITEMS) == 5


def test_nav_items_structure() -> None:
    """Each NAV_ITEMS entry is a 4-tuple of strings."""
    for item in NAV_ITEMS:
        assert isinstance(item, tuple)
        assert len(item) == 4
        for field in item:
            assert isinstance(field, str)
            assert len(field) > 0


def test_nav_items_unique_ids() -> None:
    """NAV_ITEMS page IDs are all unique."""
    ids = [item[0] for item in NAV_ITEMS]
    assert len(ids) == len(set(ids))


# ============================================================================
# 13. Content Stack Property
# ============================================================================


def test_content_stack_property(shell: AppShell) -> None:
    """content_stack property returns the QStackedWidget."""
    stack = shell.content_stack
    assert isinstance(stack, QStackedWidget)
    assert stack.objectName() == "MainContentStack"
    assert stack is shell.findChild(QStackedWidget, "MainContentStack")


# ============================================================================
# 14. Authenticated Session & Shell Integration (Task 0.4.3)
# ============================================================================


def _create_user(
    username: str = "analyst_1",
    display_name: str | None = "Alex Mercer",
    role: str = "analyst",
) -> User:
    """Helper to construct an authenticated User profile for tests."""
    return User(
        id="usr-test-01",
        username=username,
        display_name=display_name,
        role=role,
        is_active=True,
        created_at="2026-01-01T00:00:00Z",
    )


def test_app_shell_user_display_name_used(qapp: QApplication) -> None:
    """Shell displays user display_name when populated."""
    user = _create_user(username="asmith", display_name="Dr. Alice Smith")
    shell = AppShell(user=user)
    shell.show()

    lbl = shell.findChild(QLabel, "UserIdentityLabel")
    assert lbl is not None
    assert lbl.text() == "Dr. Alice Smith"
    assert lbl.isVisible() is True
    assert "Dr. Alice Smith" in lbl.toolTip()
    shell.close()


def test_app_shell_user_fallback_to_username(qapp: QApplication) -> None:
    """Shell falls back to username when display_name is None."""
    user = _create_user(username="asmith", display_name=None)
    shell = AppShell(user=user)
    shell.show()

    lbl = shell.findChild(QLabel, "UserIdentityLabel")
    assert lbl is not None
    assert lbl.text() == "asmith"
    assert lbl.isVisible() is True
    shell.close()


def test_app_shell_user_whitespace_display_name_fallback(
    qapp: QApplication,
) -> None:
    """Shell falls back to username when display_name is empty or whitespace."""
    user = _create_user(username="operator_9", display_name="   ")
    shell = AppShell(user=user)

    lbl = shell.findChild(QLabel, "UserIdentityLabel")
    assert lbl is not None
    assert lbl.text() == "operator_9"


def test_app_shell_user_role_displayed(qapp: QApplication) -> None:
    """Shell displays user role in uppercase on UserRoleBadge."""
    user = _create_user(role="admin")
    shell = AppShell(user=user)
    shell.show()

    badge = shell.findChild(QLabel, "UserRoleBadge")
    assert badge is not None
    assert badge.text() == "ADMIN"
    assert badge.property("role") == "admin"
    assert badge.isVisible() is True
    shell.close()


def test_app_shell_user_long_name_layout_safety(qapp: QApplication) -> None:
    """Long user display names do not fail layout or expand uncontrollably."""
    long_name = "Very Long Investigator Name " * 5
    user = _create_user(display_name=long_name)
    shell = AppShell(user=user)
    shell.resize(1024, 640)
    shell.show()

    lbl = shell.findChild(QLabel, "UserIdentityLabel")
    assert lbl is not None
    assert lbl.text() == long_name.strip()
    assert lbl.maximumWidth() <= 240
    shell.close()


def test_app_shell_authenticated_messaging(qapp: QApplication) -> None:
    """Shell accurately indicates authenticated session with pending live views."""
    user = _create_user()
    shell = AppShell(user=user)

    mode_badge = shell.findChild(QLabel, "HeaderModeBadge")
    assert mode_badge is not None
    assert mode_badge.text() == "AUTHENTICATED SESSION"
    assert mode_badge.property("authenticated") == "true"

    sub_context = shell.findChild(QLabel, "ToolbarSubContextLabel")
    assert sub_context is not None
    assert "Live Data Views: Pending" in sub_context.text()

    status_mode = shell.findChild(QLabel, "StatusModeLabel")
    assert status_mode is not None
    assert "Mode: Authenticated Session" in status_mode.text()

    status_api = shell.findChild(QLabel, "StatusApiLabel")
    assert status_api is not None
    assert "API: Unknown" in status_api.text()
    assert status_api.property("apiState") == "unknown"

    status_system = shell.findChild(QLabel, "StatusSystemLabel")
    assert status_system is not None
    assert "System: Unknown" in status_system.text()
    assert status_system.property("systemState") == "unknown"

    status_db = shell.findChild(QLabel, "StatusDatabaseLabel")
    assert status_db is not None
    assert "Database: Unknown" in status_db.text()
    assert status_db.property("dbState") == "unknown"

    security_notice = shell.findChild(QLabel, "StatusSecurityNotice")
    assert security_notice is not None
    assert "Session authenticated" in security_notice.text()
    assert "pending" in security_notice.text()


def test_app_shell_logout_button_emits_signal(qapp: QApplication) -> None:
    """LogoutButton click emits logout_requested signal on AppShell."""
    user = _create_user()
    shell = AppShell(user=user)

    btn = shell.findChild(QPushButton, "LogoutButton")
    assert btn is not None
    assert btn.text() == "Log Out"

    emitted: list[bool] = []
    shell.logout_requested.connect(lambda: emitted.append(True))

    btn.click()
    assert emitted == [True]


def test_app_shell_authenticated_navigation_synchronized(
    qapp: QApplication,
) -> None:
    """Navigation across all 5 pages remains functional in authenticated mode."""
    user = _create_user()
    shell = AppShell(user=user)

    for page_id, _, page_title, _ in NAV_ITEMS:
        shell.navigate_to(page_id)
        assert shell.current_page_name == page_id
        assert shell.toolbar_context_label.text() == page_title
        btn = shell.get_nav_button(page_id)
        assert btn is not None
        assert btn.isChecked()


def test_app_shell_set_user_dynamic_update(qapp: QApplication) -> None:
    """set_user() dynamically updates user identity and messaging."""
    shell = AppShell()  # Start unauthenticated
    shell.show()
    assert shell.user is None

    user = _create_user(username="analyst_x", display_name="Analyst X")
    shell.set_user(user)

    assert shell.user is user
    assert shell.user_identity_label.text() == "Analyst X"
    assert shell.user_identity_label.isVisible() is True
    mode_lbl = shell.findChild(QLabel, "HeaderModeBadge")
    assert mode_lbl is not None
    assert mode_lbl.text() == "AUTHENTICATED SESSION"

    # Reset to unauthenticated
    shell.set_user(None)
    assert shell.user is None
    assert shell.user_identity_label.isVisible() is False
    assert mode_lbl.text() == "PROTOTYPE PREVIEW"
    shell.close()


def test_app_shell_check_status_button_emits_signal(qapp: QApplication) -> None:
    """Clicking CheckStatusButton emits status_check_requested signal."""
    shell = AppShell()
    btn = shell.check_status_button
    assert btn is not None
    assert btn.text() == "Check Status"
    assert btn.isEnabled() is True

    emitted: list[bool] = []
    shell.status_check_requested.connect(lambda: emitted.append(True))

    btn.click()
    assert emitted == [True]


def test_app_shell_set_status_checking(qapp: QApplication) -> None:
    """set_status_checking updates button and status label states."""
    shell = AppShell()
    shell.set_status_checking()

    assert shell.check_status_button.isEnabled() is False
    assert shell.check_status_button.text() == "Checking..."
    assert shell.status_api_label.text() == "API: Checking..."
    assert shell.status_api_label.property("apiState") == "checking"
    assert shell.status_system_label.text() == "System: Checking..."
    assert shell.status_system_label.property("systemState") == "checking"
    assert shell.status_database_label.text() == "Database: Checking..."
    assert shell.status_database_label.property("dbState") == "checking"

    shell.set_status_check_enabled(True)
    assert shell.check_status_button.isEnabled() is True
    assert shell.check_status_button.text() == "Check Status"


def test_app_shell_processes_query_requested_forwarded(
    qapp: QApplication,
) -> None:
    """AppShell forwards processes_query_requested when view emits query."""
    shell = AppShell()
    emitted: list[ProcessesQuery] = []
    shell.processes_query_requested.connect(lambda q: emitted.append(q))

    query = ProcessesQuery(is_active=True, pid=123, limit=50, offset=0)
    shell.processes_view.query_requested.emit(query)

    assert len(emitted) == 1
    assert emitted[0] == query


def test_app_shell_resources_query_requested_forwarded(
    qapp: QApplication,
) -> None:
    """AppShell forwards resources_query_requested when view emits query."""
    shell = AppShell()
    emitted: list[ResourcesQuery] = []
    shell.resources_query_requested.connect(lambda q: emitted.append(q))

    query = ResourcesQuery(limit=25, offset=10)
    shell.resources_view.query_requested.emit(query)

    assert len(emitted) == 1
    assert emitted[0] == query


def test_app_shell_files_query_requested_forwarded(
    qapp: QApplication,
) -> None:
    """AppShell forwards files_query_requested when view emits query."""
    shell = AppShell()
    emitted: list[FilesQuery] = []
    shell.files_query_requested.connect(lambda q: emitted.append(q))

    query = FilesQuery(path="/var", limit=25, offset=10)
    shell.files_view.query_requested.emit(query)

    assert len(emitted) == 1
    assert emitted[0] == query


def test_app_shell_root_warning_and_properties(qapp: QApplication) -> None:
    """AppShell exposes root warning, role badge, banners, and edge indices."""
    user = _create_user(role="admin")
    shell = AppShell(user=user, is_root=True)
    shell.show()

    assert shell.is_root is True
    assert shell.root_warning_banner.isVisible() is True
    assert shell.user_role_badge.text() == "ADMIN"
    assert shell.user_role_badge.isVisible() is True

    # Toggle root off
    shell.set_root_warning(False)
    assert shell.is_root is False
    assert shell.root_warning_banner.isVisible() is False

    # Toggle root on with custom message
    shell.set_root_warning(True, "Custom root warning")
    assert shell.is_root is True
    assert shell.root_warning_banner.isVisible() is True

    # User with empty role
    user_no_role = _create_user(role="")
    shell.set_user(user_no_role)
    assert shell.user_role_badge.isVisible() is False
    assert shell.user_role_badge.text() == ""

    # Current page name when index is out of bounds
    shell._content_stack.currentIndex = lambda: -1  # type: ignore[method-assign]
    assert shell.current_page_name == ""

    # Error banner helpers and properties
    assert shell.error_banner is not None
    shell.show_connection_error("API unreachable")
    assert shell.error_banner.isVisible() is True

    shell.show_degraded_warning("Backend slow")
    assert shell.error_banner.isVisible() is True

    shell.clear_global_warning()
    assert shell.error_banner.isVisible() is False

    # Status bar and labels
    assert shell.status_bar is not None
    assert shell.status_mode_label is not None
    assert shell.status_security_notice is not None

    shell.close()

