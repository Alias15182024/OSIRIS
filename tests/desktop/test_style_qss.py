"""Unit tests for OSIRIS Desktop QSS Foundation.

Verifies:
1. Stylesheet asset exists at the expected package-relative location.
2. Stylesheet can be loaded programmatically from the native package.
3. Returned stylesheet is a non-empty string.
4. Stylesheet contains the approved major surface/text/accent/severity/status
   values after token substitution.
5. Stylesheet contains foundational selectors for the approved Qt controls.
6. Stylesheet contains explicit focus/hover/pressed/disabled/selected states.
7. Stylesheet is deterministic across repeated loads.
8. Stylesheet loader works independently of the current working directory.
9. Pure Python tests without requiring PostgreSQL, networks, or daemons.
10. Stylesheet parses cleanly in PySide6 without errors.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from desktop.assets import load_stylesheet as load_stylesheet_from_assets
from desktop.ui import (
    design_tokens,
    get_stylesheet,
    get_stylesheet_path,
    get_token_replacements,
    load_stylesheet,
    substitute_tokens,
)

# The 16 approved Qt controls mandated by microtask 0.3.2
APPROVED_CONTROLS: tuple[str, ...] = (
    "QWidget",
    "QMainWindow",
    "QLabel",
    "QLineEdit",
    "QPushButton",
    "QToolButton",
    "QComboBox",
    "QCheckBox",
    "QRadioButton",
    "QScrollBar",
    "QFrame",
    "QTableView",
    "QHeaderView",
    "QTreeView",
    "QAbstractItemView",
    "QStatusBar",
)

# Unapproved future widget classes that must NOT have selectors yet (0.3.4+)
FORBIDDEN_FUTURE_CLASSES: tuple[str, ...] = (
    "PaginationBar",
    "FilterToolbar",
    "OsirisStatusBar",
)


# ==============================================================================
# 1. Asset Existence & Path Resolution
# ==============================================================================


def test_stylesheet_asset_exists_on_disk() -> None:
    """Verify desktop/assets/style.qss exists as a regular file."""
    path = get_stylesheet_path()
    assert path.is_file(), f"Expected stylesheet asset to exist at {path}"
    assert path.suffix == ".qss"
    assert path.name == "style.qss"


def test_get_stylesheet_path_resolution() -> None:
    """Verify get_stylesheet_path resolves relative to package root."""
    path = get_stylesheet_path()
    assert path.parent.name == "assets"
    assert path.parent.parent.name == "desktop"


def test_get_stylesheet_path_missing_file_raises(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Verify get_stylesheet_path raises FileNotFoundError if style.qss is missing."""
    import desktop.ui as ui_module

    fake_file = tmp_path / "desktop" / "ui" / "__init__.py"
    fake_file.parent.mkdir(parents=True, exist_ok=True)
    fake_file.write_text("# dummy", encoding="utf-8")

    monkeypatch.setattr(ui_module, "__file__", str(fake_file))
    with pytest.raises(
        FileNotFoundError, match="OSIRIS desktop stylesheet asset not found"
    ):
        ui_module.get_stylesheet_path()


# ==============================================================================
# 2. Programmatic Loading & API Surface
# ==============================================================================


def test_load_stylesheet_returns_non_empty_string() -> None:
    """Verify load_stylesheet returns a non-empty string."""
    qss = load_stylesheet()
    assert isinstance(qss, str)
    assert len(qss.strip()) > 0


def test_get_stylesheet_alias_matches_load_stylesheet() -> None:
    """Verify get_stylesheet is an exact alias for load_stylesheet."""
    assert get_stylesheet() == load_stylesheet()


def test_load_stylesheet_from_desktop_assets_package() -> None:
    """Verify desktop.assets exports and returns the identical stylesheet."""
    assert load_stylesheet_from_assets() == load_stylesheet()


def test_stylesheet_is_deterministic() -> None:
    """Verify repeated loads produce character-for-character identical results."""
    first = load_stylesheet()
    for _ in range(10):
        subsequent = load_stylesheet()
        assert subsequent == first
        assert hash(subsequent) == hash(first)


def test_stylesheet_loader_works_regardless_of_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify loading succeeds when cwd is changed to a temporary directory."""
    baseline = load_stylesheet()
    monkeypatch.chdir(tmp_path)
    assert os.getcwd() == str(tmp_path)

    loaded_from_tmp = load_stylesheet()
    assert loaded_from_tmp == baseline


# ==============================================================================
# 3. Approved Palette & Token Substitution
# ==============================================================================


def test_stylesheet_contains_approved_surface_colors() -> None:
    """Verify all 4 surface tiers and border hex values are in the loaded QSS."""
    qss = load_stylesheet()
    assert design_tokens.SURFACE_0 in qss  # #0F1117
    assert design_tokens.SURFACE_1 in qss  # #161922
    assert design_tokens.SURFACE_2 in qss  # #1E222D
    assert design_tokens.SURFACE_3 in qss  # #282D3C
    assert design_tokens.BORDER in qss     # #2E3545


def test_stylesheet_contains_approved_text_colors() -> None:
    """Verify high-contrast primary and secondary text hex values are present."""
    qss = load_stylesheet()
    assert design_tokens.TEXT_PRIMARY in qss    # #F0F3F8
    assert design_tokens.TEXT_SECONDARY in qss  # #94A3B8


def test_stylesheet_contains_approved_accent_and_focus_colors() -> None:
    """Verify interactive accent and keyboard focus ring hex values are present."""
    qss = load_stylesheet()
    assert design_tokens.ACCENT in qss        # #3B82F6
    assert design_tokens.ACCENT_FOCUS in qss  # #60A5FA


def test_stylesheet_contains_approved_severity_colors() -> None:
    """Verify all incident severity semantics hex values are present."""
    qss = load_stylesheet()
    assert design_tokens.SEVERITY_CRITICAL in qss  # #EF4444
    assert design_tokens.SEVERITY_HIGH in qss      # #F97316
    assert design_tokens.SEVERITY_MEDIUM in qss    # #EAB308
    assert design_tokens.SEVERITY_LOW in qss       # #3B82F6
    assert design_tokens.SEVERITY_INFO in qss      # #64748B


def test_stylesheet_contains_approved_operational_status_colors() -> None:
    """Verify all endpoint/collector operational health hex values are present."""
    qss = load_stylesheet()
    assert design_tokens.STATUS_FRESH in qss     # #10B981
    assert design_tokens.STATUS_STALE in qss     # #F59E0B
    assert design_tokens.STATUS_DEGRADED in qss  # #EF4444
    assert design_tokens.STATUS_OFFLINE in qss   # #64748B


def test_no_unsubstituted_placeholders_remain() -> None:
    """Verify no {{TOKEN}} or @TOKEN@ template markers remain in the rendered QSS."""
    qss = load_stylesheet()
    assert "{{" not in qss, "Found unresolved '{{' placeholder marker in rendered QSS"
    assert "}}" not in qss, "Found unresolved '}}' placeholder marker in rendered QSS"
    # Ensure no unresolved @UPPERCASE@ markers
    import re

    unresolved = re.findall(r"@[A-Z0-9_]+@", qss)
    assert not unresolved, (
        f"Found unresolved token markers in rendered QSS: {unresolved}"
    )


# ==============================================================================
# 4. Control Selectors & Hierarchy
# ==============================================================================


@pytest.mark.parametrize("control", APPROVED_CONTROLS)
def test_stylesheet_contains_foundational_selector_for_each_approved_control(
    control: str,
) -> None:
    """Verify each of the 16 approved standard Qt controls has a selector."""
    qss = load_stylesheet()
    assert control in qss, (
        f"Approved control '{control}' selector missing from stylesheet"
    )


@pytest.mark.parametrize("forbidden", FORBIDDEN_FUTURE_CLASSES)
def test_stylesheet_does_not_contain_unapproved_widget_classes(
    forbidden: str,
) -> None:
    """Verify unapproved future widget classes are not styled in microtask 0.3.2."""
    qss = load_stylesheet()
    assert forbidden not in qss, (
        f"Forbidden future widget class '{forbidden}' selector found in "
        "stylesheet foundation"
    )


# ==============================================================================
# 5. Interactive & Visual States
# ==============================================================================


def test_stylesheet_contains_hover_states() -> None:
    """Verify interactive controls implement explicit :hover pseudo-states."""
    qss = load_stylesheet()
    assert ":hover" in qss
    assert "QLineEdit:hover" in qss
    assert "QPushButton:hover" in qss
    assert "QToolButton:hover" in qss
    assert "QComboBox:hover" in qss


def test_stylesheet_contains_pressed_states() -> None:
    """Verify interactive controls implement explicit :pressed pseudo-states."""
    qss = load_stylesheet()
    assert ":pressed" in qss
    assert "QPushButton:pressed" in qss
    assert "QToolButton:pressed" in qss


def test_stylesheet_contains_focus_states() -> None:
    """Verify controls implement explicit :focus pseudo-states with focus color."""
    qss = load_stylesheet()
    assert ":focus" in qss
    assert "QLineEdit:focus" in qss
    assert "QPushButton:focus" in qss
    assert design_tokens.ACCENT_FOCUS in qss


def test_stylesheet_contains_disabled_states() -> None:
    """Verify controls implement explicit :disabled pseudo-states with subdued text."""
    qss = load_stylesheet()
    assert ":disabled" in qss
    assert "QLineEdit:disabled" in qss
    assert "QPushButton:disabled" in qss
    assert "QLabel:disabled" in qss


def test_stylesheet_contains_selected_states() -> None:
    """Verify item views implement explicit :selected states."""
    qss = load_stylesheet()
    assert ":selected" in qss
    assert "QTableView::item:selected" in qss
    assert "QTreeView::item:selected" in qss
    assert "QAbstractItemView::item:selected" in qss


# ==============================================================================
# 6. Dense Investigator Console Table Foundations
# ==============================================================================


def test_table_row_height_metric_applied() -> None:
    """Verify dense investigator table row target height (~28px) is in the QSS."""
    qss = load_stylesheet()
    assert f"{design_tokens.TABLE_ROW_HEIGHT}px" in qss
    assert "QTableView::item" in qss


def test_table_header_foundation_applied() -> None:
    """Verify table header (QHeaderView) styling is present."""
    qss = load_stylesheet()
    assert "QHeaderView" in qss
    assert "QHeaderView::section" in qss


def test_scrollbar_foundation_applied() -> None:
    """Verify restrained scrollbar foundation is present."""
    qss = load_stylesheet()
    assert "QScrollBar:vertical" in qss
    assert "QScrollBar:horizontal" in qss
    assert "QScrollBar::handle:vertical" in qss
    assert "QScrollBar::handle:horizontal" in qss


def test_status_bar_foundation_applied() -> None:
    """Verify QStatusBar foundation is present with STATUS_BAR_HEIGHT."""
    qss = load_stylesheet()
    assert "QStatusBar" in qss
    assert f"{design_tokens.STATUS_BAR_HEIGHT}px" in qss


# ==============================================================================
# 7. Token Substitution & Override Mechanics
# ==============================================================================


def test_substitute_tokens_custom_dict() -> None:
    """Verify substitute_tokens accepts custom mappings."""
    template = "color: {{MY_COLOR}}; background: @MY_BG@;"
    result = substitute_tokens(template, {"MY_COLOR": "#112233", "MY_BG": "#445566"})
    assert result == "color: #112233; background: #445566;"


def test_substitute_tokens_case_insensitive_fallback() -> None:
    """Verify substitute_tokens matches lowercase token keys."""
    template = "color: {{surface_0}};"
    result = substitute_tokens(template, {"SURFACE_0": "#0F1117"})
    assert result == "color: #0F1117;"


def test_load_stylesheet_with_overrides() -> None:
    """Verify load_stylesheet supports token overrides without mutating globals."""
    custom_accent = "#FF00FF"
    overridden = load_stylesheet(token_overrides={"ACCENT": custom_accent})
    assert custom_accent in overridden

    # Verify standard load remains unaffected
    standard = load_stylesheet()
    assert custom_accent not in standard
    assert design_tokens.ACCENT in standard


def test_load_stylesheet_with_case_insensitive_overrides() -> None:
    """Verify load_stylesheet applies overrides even when case differs."""
    custom_surface = "#123456"
    custom_accent = "#654321"

    overridden = load_stylesheet(
        token_overrides={
            # lowercase key overriding uppercase template {{SURFACE_0}}
            "surface_0": custom_surface,
            # lowercase key overriding uppercase template {{ACCENT}}
            "accent": custom_accent,
        }
    )

    assert custom_surface in overridden
    assert custom_accent in overridden

    # Verify default tokens were actually replaced
    assert overridden.count(custom_surface) > 0
    assert overridden.count(custom_accent) > 0


def test_get_token_replacements_contains_core_tokens() -> None:
    """Verify get_token_replacements exports all core tokens."""
    tokens = get_token_replacements()
    assert "SURFACE_0" in tokens
    assert "BORDER" in tokens
    assert "ACCENT" in tokens
    assert "TABLE_ROW_HEIGHT" in tokens
    assert tokens["SURFACE_0"] == design_tokens.SURFACE_0


def test_get_token_replacements_contains_structured_aliases() -> None:
    """Verify get_token_replacements includes structured token aliases."""
    tokens = get_token_replacements()
    # Check normalized aliases without underscores
    assert "SURFACE0" in tokens
    assert "surface0" in tokens
    # Check container aliases
    assert "medium" in tokens or "radius_medium" in tokens or "md" in tokens


def test_substitute_tokens_edge_cases() -> None:
    """Verify substitute_tokens handles edge cases cleanly."""
    # Empty string returns empty string
    assert substitute_tokens("") == ""

    # Non-token string returned untouched
    assert substitute_tokens("color: red;") == "color: red;"

    # Unknown token is preserved
    assert substitute_tokens("color: {{UNKNOWN_KEY}};") == "color: {{UNKNOWN_KEY}};"

    # Hyphenated token substitution
    result = substitute_tokens("color: {{surface-0}};", {"surface_0": "#112233"})
    assert result == "color: #112233;"

    # Type error on non-string template
    with pytest.raises(TypeError, match="Template must be a string"):
        substitute_tokens(None)  # type: ignore[arg-type]


# ==============================================================================
# 8. Interactive Pressed States & Control Sizing Verification
# ==============================================================================


def test_stylesheet_contains_pressed_states_for_all_interactive_controls() -> None:
    """Verify all interactive controls define explicit :pressed / :on states."""
    qss = load_stylesheet()
    assert "QPushButton:pressed" in qss
    assert "QToolButton:pressed" in qss
    assert "QCheckBox::indicator:pressed" in qss
    assert "QRadioButton::indicator:pressed" in qss
    assert "QHeaderView::section:pressed" in qss
    assert "QComboBox:on" in qss or "QComboBox:pressed" in qss
    assert "QScrollBar::handle:vertical:pressed" in qss
    assert "QScrollBar::handle:horizontal:pressed" in qss


def test_separator_horizontal_divider_not_constrained_to_1px_width() -> None:
    """Verify horizontal separators are not clamped to 1px width."""
    qss = load_stylesheet()
    assert "QFrame[frameShape=\"4\"]" in qss

    # Verify horizontal rule specifies height: 1px, max-height: 1px
    assert "max-height: 1px;" in qss
    # Verify vertical rule specifies width: 1px, max-width: 1px
    assert "max-width: 1px;" in qss


def test_radio_button_radius_uses_token() -> None:
    """Verify QRadioButton indicator uses RADIUS_FULL token, not hardcoded 7px."""
    qss = load_stylesheet()
    assert f"border-radius: {design_tokens.RADIUS_FULL}px;" in qss


def test_table_corner_button_styled() -> None:
    """Verify QTableView QTableCornerButton is styled to prevent 3D look."""
    qss = load_stylesheet()
    assert "QTableView QTableCornerButton::section" in qss


def test_scrollbar_disabled_states_present() -> None:
    """Verify scrollbars define disabled states for vertical and horizontal handles."""
    qss = load_stylesheet()
    assert "QScrollBar:vertical:disabled" in qss
    assert "QScrollBar::handle:vertical:disabled" in qss


def test_only_approved_controls_styled() -> None:
    """Verify no unapproved Qt widgets outside the approved 16 controls are styled."""
    import re

    qss = load_stylesheet()
    # Strip comments to avoid matching commented class names
    cleaned = re.sub(r"/\*.*?\*/", "", qss, flags=re.DOTALL)

    # Allowed set includes approved controls plus containers, dialogs,
    # QPlainTextEdit approved for the read-only event inspector payload viewer,
    # and QDateTimeEdit approved for the event time-range filter controls
    allowed_classes = (
        set(APPROVED_CONTROLS)
        | {
            "QTableCornerButton",
            "QStackedWidget",
            "QDialog",
            "QPlainTextEdit",
            "QDateTimeEdit",
        }
    )

    # Find all Qt class names in selector positions
    found_classes = set(re.findall(r"\b(Q[A-Z][a-zA-Z]+)\b", cleaned))

    unapproved = found_classes - allowed_classes
    assert not unapproved, f"Found unapproved Qt classes in stylesheet: {unapproved}"


# ==============================================================================
# 9. PySide6 QApplication Compatibility & Widget Integration
# ==============================================================================


def test_qss_parses_cleanly_in_qapplication(qapp: Any) -> None:
    """Verify PySide6 QApplication successfully accepts and parses the stylesheet."""
    qss = load_stylesheet()
    # setStyleSheet parses the QSS; if severe syntax errors occur, Qt outputs warnings
    qapp.setStyleSheet(qss)
    assert qapp.styleSheet() == qss
    # Clean up to avoid leaking global state into other tests
    qapp.setStyleSheet("")


def test_horizontal_separator_frame_renders_unclamped_in_qapp(qapp: Any) -> None:
    """Verify horizontal QFrame separator maximumWidth is not clamped to 1."""
    from PySide6.QtWidgets import QFrame

    qss = load_stylesheet()
    qapp.setStyleSheet(qss)

    frame = QFrame()
    frame.setFrameShape(QFrame.Shape.HLine)
    frame.show()

    # maximumWidth should be QWIDGETSIZE_MAX (16777215), NOT 1
    assert frame.maximumWidth() > 1000, (
        f"Horizontal separator width is clamped to {frame.maximumWidth()}px!"
    )

    frame.close()
    qapp.setStyleSheet("")


# ==============================================================================
# 10. Reusable Base Component Selectors (0.3.3)
# ==============================================================================


def test_stylesheet_contains_severity_badge_selectors() -> None:
    """Verify QLabel#SeverityBadge and semantic severity property selectors exist."""
    qss = load_stylesheet()
    assert "QLabel#SeverityBadge" in qss
    assert 'QLabel#SeverityBadge[severity="critical"]' in qss
    assert 'QLabel#SeverityBadge[severity="high"]' in qss
    assert 'QLabel#SeverityBadge[severity="medium"]' in qss
    assert 'QLabel#SeverityBadge[severity="low"]' in qss
    assert 'QLabel#SeverityBadge[severity="info"]' in qss


def test_stylesheet_contains_status_badge_selectors() -> None:
    """Verify QLabel#StatusBadge and semantic status property selectors exist."""
    qss = load_stylesheet()
    assert "QLabel#StatusBadge" in qss
    assert 'QLabel#StatusBadge[status="fresh"]' in qss
    assert 'QLabel#StatusBadge[status="stale"]' in qss
    assert 'QLabel#StatusBadge[status="degraded"]' in qss
    assert 'QLabel#StatusBadge[status="offline"]' in qss


def test_stylesheet_contains_metric_card_selectors() -> None:
    """Verify QFrame#MetricCard and internal label hierarchy selectors exist."""
    qss = load_stylesheet()
    assert "QFrame#MetricCard" in qss
    assert "QLabel#MetricCardTitle" in qss
    assert "QLabel#MetricCardValue" in qss
    assert "QLabel#MetricCardDetail" in qss


def test_stylesheet_component_token_substitution() -> None:
    """Verify component styling incorporates approved design token values."""
    qss = load_stylesheet()
    # Badges should have token-substituted colors
    assert design_tokens.SEVERITY_CRITICAL in qss
    assert design_tokens.STATUS_FRESH in qss
    # Numeric metric font family and size
    assert f"{design_tokens.FONT_SIZE_NUMERIC_METRIC}px" in qss


def test_stylesheet_contains_login_dialog_selectors() -> None:
    """Verify LoginDialog and associated control selectors exist in stylesheet."""
    qss = load_stylesheet()
    assert "QDialog#LoginDialog" in qss
    assert "QLabel#LoginBrandTitle" in qss
    assert "QLabel#LoginBrandSubtitle" in qss
    assert "QLineEdit#LoginUsernameInput" in qss
    assert "QLineEdit#LoginPasswordInput" in qss
    assert "QLabel#LoginFeedbackLabel" in qss
    assert 'QLabel#LoginFeedbackLabel[isError="true"]' in qss
    assert "QPushButton#LoginSubmitButton" in qss
    assert "QPushButton#LoginCancelButton" in qss


def test_stylesheet_contains_identity_and_logout_selectors() -> None:
    """Verify authenticated identity, role badge, and logout selectors exist."""
    qss = load_stylesheet()
    assert "QLabel#UserIdentityLabel" in qss
    assert "QLabel#UserRoleBadge" in qss
    assert 'QLabel#UserRoleBadge[role="admin"]' in qss
    assert 'QLabel#HeaderModeBadge[authenticated="true"]' in qss
    assert "QPushButton#LogoutButton" in qss
    assert "QPushButton#LogoutButton:hover" in qss
    assert "QPushButton#LogoutButton:focus" in qss


def test_stylesheet_contains_operational_status_selectors() -> None:
    """Verify CheckStatusButton and operational status label selectors exist."""
    qss = load_stylesheet()
    assert "QPushButton#CheckStatusButton" in qss
    assert "QPushButton#CheckStatusButton:hover" in qss
    assert "QPushButton#CheckStatusButton:disabled" in qss
    assert "QLabel#StatusApiLabel" in qss
    assert 'QLabel#StatusApiLabel[apiState="reachable"]' in qss
    assert 'QLabel#StatusApiLabel[apiState="unavailable"]' in qss
    assert 'QLabel#StatusApiLabel[apiState="checking"]' in qss
    assert "QLabel#StatusSystemLabel" in qss
    assert 'QLabel#StatusSystemLabel[systemState="healthy"]' in qss
    assert 'QLabel#StatusSystemLabel[systemState="degraded"]' in qss
    assert 'QLabel#StatusSystemLabel[systemState="unavailable"]' in qss
    assert "QLabel#StatusDatabaseLabel" in qss
    assert 'QLabel#StatusDatabaseLabel[dbState="connected"]' in qss
    assert 'QLabel#StatusDatabaseLabel[dbState="disconnected"]' in qss
    assert 'QLabel#StatusDatabaseLabel[dbState="unavailable"]' in qss
    assert "QLabel#StatusLastUpdatedLabel" in qss


def test_stylesheet_contains_events_view_and_filter_selectors() -> None:
    """Verify Section 19 security events view and filter selectors exist in QSS."""
    qss = load_stylesheet()
    # Filter toolbar and inputs
    assert "QFrame#EventsFilterBar" in qss
    assert "QLabel#SeverityFilterLabel" in qss
    assert "QComboBox#SeverityFilterComboBox" in qss
    assert "QLineEdit#SourceFilterInput" in qss
    assert "QLineEdit#EventTypeFilterInput" in qss
    assert "QLineEdit#PidFilterInput" in qss
    assert "QLineEdit#HostIdFilterInput" in qss
    assert "QLabel#StartTimeFilterLabel" in qss
    assert "QLabel#EndTimeFilterLabel" in qss
    assert "QCheckBox#StartTimeFilterCheckBox" in qss
    assert "QCheckBox#EndTimeFilterCheckBox" in qss
    assert "QDateTimeEdit#StartTimeFilterEdit" in qss
    assert "QDateTimeEdit#EndTimeFilterEdit" in qss
    assert "QPushButton#ApplyFiltersButton" in qss
    assert "QPushButton#ClearFiltersButton" in qss
    assert "QLabel#FilterValidationLabel" in qss

    # Toolbar and status banner
    assert "QFrame#EventsToolbar" in qss
    assert "QPushButton#RefreshEventsButton" in qss
    assert "QLabel#RecordCountSummary" in qss
    assert "QFrame#EventsStatusBanner" in qss
    assert 'QFrame#EventsStatusBanner[state="loading"]' in qss
    assert 'QFrame#EventsStatusBanner[state="empty"]' in qss
    assert 'QFrame#EventsStatusBanner[state="failed"]' in qss
    assert 'QFrame#EventsStatusBanner[state="not_loaded"]' in qss
    assert "QLabel#EventsStatusBannerTitle" in qss
    assert "QLabel#EventsStatusBannerMessage" in qss
    assert "QPushButton#RetryEventsButton" in qss

    # Pagination bar
    assert "QFrame#EventsPaginationFrame" in qss
    assert "QPushButton#PrevPageButton" in qss
    assert "QPushButton#NextPageButton" in qss
    assert "QLabel#PageRangeLabel" in qss


def test_stylesheet_contains_event_inspector_selectors() -> None:
    """Verify Section 20 event inspector panel selectors exist in QSS."""
    qss = load_stylesheet()
    assert "QFrame#EventInspectorPanel" in qss
    assert "QWidget#EventInspectorHeader" in qss
    assert "QLabel#EventInspectorTitle" in qss
    assert "QPushButton#EventInspectorCloseButton" in qss
    assert "QLabel#EventInspectorPayloadLabel" in qss
    assert "QPlainTextEdit#EventInspectorPayloadEdit" in qss
    assert 'QLabel[inspectorLabel="true"]' in qss
    assert 'QLabel[inspectorValue="true"]' in qss


def test_stylesheet_contains_processes_view_selectors() -> None:
    """Verify Section 21 processes view selectors exist in QSS."""
    qss = load_stylesheet()
    assert "QFrame#ProcessesToolbar" in qss
    assert "QPushButton#RefreshProcessesButton" in qss
    assert "QFrame#ProcessesStatusBanner" in qss
    assert 'QFrame#ProcessesStatusBanner[state="loading"]' in qss
    assert 'QFrame#ProcessesStatusBanner[state="empty"]' in qss
    assert 'QFrame#ProcessesStatusBanner[state="failed"]' in qss
    assert 'QFrame#ProcessesStatusBanner[state="not_loaded"]' in qss
    assert "QLabel#ProcessesStatusBannerTitle" in qss
    assert "QLabel#ProcessesStatusBannerMessage" in qss
    assert "QPushButton#RetryProcessesButton" in qss
    assert "QTableView#ProcessesTable" in qss

    # Filter toolbar
    assert "QFrame#ProcessesFilterBar" in qss
    assert "QLabel#ProcessesActiveFilterLabel" in qss
    assert "QComboBox#ProcessesActiveFilterCombo" in qss
    assert "QLabel#ProcessesPidFilterLabel" in qss
    assert "QLineEdit#ProcessesPidFilterInput" in qss
    assert "QLabel#ProcessesHostIdFilterLabel" in qss
    assert "QLineEdit#ProcessesHostIdFilterInput" in qss
    assert "QPushButton#ApplyProcessesFiltersButton" in qss
    assert "QPushButton#ResetProcessesFiltersButton" in qss
    assert "QLabel#ProcessesFilterValidationLabel" in qss
    assert 'QLabel#ProcessesFilterValidationLabel[error="true"]' in qss
    assert "QPushButton#QuickResetProcessesFiltersButton" in qss

    # Pagination bar
    assert "QFrame#ProcessesPaginationFrame" in qss
    assert "QPushButton#PrevProcessesPageButton" in qss
    assert "QPushButton#NextProcessesPageButton" in qss
    assert "QLabel#ProcessesPageRangeLabel" in qss


def test_stylesheet_contains_process_inspector_selectors() -> None:
    """Verify Section 22 process inspector panel selectors exist in QSS."""
    qss = load_stylesheet()
    assert "QFrame#ProcessInspectorPanel" in qss
    assert "QWidget#ProcessInspectorHeader" in qss
    assert "QLabel#ProcessInspectorTitle" in qss
    assert "QPushButton#ProcessInspectorCloseButton" in qss
    assert 'QLabel[inspectorLabel="true"]' in qss
    assert 'QLabel[inspectorValue="true"]' in qss


def test_stylesheet_contains_resources_view_selectors() -> None:
    """Verify Section 23 resources view selectors exist in QSS."""
    qss = load_stylesheet()
    assert "QFrame#ResourcesToolbar" in qss
    assert "QPushButton#RefreshResourcesButton" in qss
    assert "QPushButton#RefreshResourcesButton:disabled" in qss
    assert "QFrame#ResourcesStatusBanner" in qss
    assert 'QFrame#ResourcesStatusBanner[state="loading"]' in qss
    assert 'QFrame#ResourcesStatusBanner[state="empty"]' in qss
    assert 'QFrame#ResourcesStatusBanner[state="failed"]' in qss
    assert 'QFrame#ResourcesStatusBanner[state="not_loaded"]' in qss
    assert "QLabel#ResourcesStatusBannerTitle" in qss
    assert "QLabel#ResourcesStatusBannerMessage" in qss
    assert "QPushButton#RetryResourcesButton" in qss
    assert "QPushButton#RetryResourcesButton:disabled" in qss
    assert "QTableView#ResourcesTable" in qss

    # Query controls
    assert "QFrame#ResourcesFilterBar" in qss
    assert "QLabel#ResourcesHostIdFilterLabel" in qss
    assert "QLineEdit#ResourcesHostIdFilterInput" in qss
    assert "QLabel#ResourcesLimitFilterLabel" in qss
    assert "QComboBox#ResourcesLimitFilterCombo" in qss
    assert "QLineEdit#ResourcesLimitFilterInput" in qss
    assert "QLabel#ResourcesStartTimeFilterLabel" in qss
    assert "QCheckBox#ResourcesStartTimeFilterCheckBox" in qss
    assert "QDateTimeEdit#ResourcesStartTimeFilterEdit" in qss
    assert "QLabel#ResourcesEndTimeFilterLabel" in qss
    assert "QCheckBox#ResourcesEndTimeFilterCheckBox" in qss
    assert "QDateTimeEdit#ResourcesEndTimeFilterEdit" in qss
    assert "QPushButton#ApplyResourcesFiltersButton" in qss
    assert "QPushButton#ResetResourcesFiltersButton" in qss
    assert "QLabel#ResourcesFilterValidationLabel" in qss
    assert 'QLabel#ResourcesFilterValidationLabel[error="true"]' in qss
    assert "QPushButton#QuickResetResourcesFiltersButton" in qss

    # Pagination bar
    assert "QFrame#ResourcesPaginationFrame" in qss
    assert "QPushButton#ResourcesPrevPageButton" in qss
    assert "QPushButton#ResourcesNextPageButton" in qss
    assert "QLabel#ResourcesPageRangeSummary" in qss


def test_stylesheet_contains_resource_inspector_and_summary_selectors() -> None:
    """Verify Section 24 resource inspector and summary selectors exist in QSS."""
    qss = load_stylesheet()
    assert "QFrame#ResourcesSummaryCardsFrame" in qss
    assert "QFrame#ResourceInspectorPanel" in qss
    assert "QWidget#ResourceInspectorHeader" in qss
    assert "QLabel#ResourceInspectorTitle" in qss
    assert "QPushButton#ResourceInspectorCloseButton" in qss
    assert "QPushButton#ResourceInspectorCloseButton:hover" in qss
    assert "QPushButton#ResourceInspectorCloseButton:pressed" in qss
    assert "QPushButton#ResourceInspectorCloseButton:focus" in qss
    assert "QPushButton#ResourceInspectorCloseButton:disabled" in qss
    assert 'QLabel[inspectorLabel="true"]' in qss
    assert 'QLabel[inspectorValue="true"]' in qss


def test_stylesheet_contains_resource_trend_charts_selectors() -> None:
    """Verify Section 25 resource trend charts selectors exist in QSS."""
    qss = load_stylesheet()
    assert "QFrame#ResourceTrendChartsWidget" in qss
    assert "QWidget#ResourceTrendHeader" in qss
    assert "QLabel#ResourceTrendTitle" in qss
    assert "QLabel#ResourceTrendScopeLabel" in qss
    assert "QLabel#ResourceTrendScopeBadge" in qss
    assert 'QLabel#ResourceTrendScopeBadge[scope="complete"]' in qss
    assert 'QLabel#ResourceTrendScopeBadge[scope="partial"]' in qss
    assert "QComboBox#ResourceTrendModeCombo" in qss
    assert "QComboBox#ResourceTrendModeCombo:focus" in qss
    assert "QWidget#ResourceTrendLegend" in qss
    assert "QLabel#ResourceTrendLegendCpu" in qss
    assert "QLabel#ResourceTrendLegendMemory" in qss
    assert "QLabel#ResourceTrendLegendDisk" in qss
    assert "QWidget#ResourceTrendCanvas" in qss


def test_stylesheet_contains_global_error_banner_selectors() -> None:
    """Verify Section 18 GlobalErrorBanner selectors exist in QSS."""
    qss = load_stylesheet()
    assert "QFrame#GlobalErrorBanner" in qss
    assert 'QFrame#GlobalErrorBanner[bannerType="disconnected"]' in qss
    assert 'QFrame#GlobalErrorBanner[bannerType="degraded"]' in qss
    assert "QLabel#ErrorBannerIndicator" in qss
    assert 'QLabel#ErrorBannerIndicator[bannerType="disconnected"]' in qss
    assert 'QLabel#ErrorBannerIndicator[bannerType="degraded"]' in qss
    assert "QLabel#ErrorBannerMessage" in qss
    assert "QPushButton#ErrorBannerRetryButton" in qss
    assert "QPushButton#ErrorBannerRetryButton:hover" in qss
    assert "QPushButton#ErrorBannerRetryButton:pressed" in qss
    assert "QPushButton#ErrorBannerRetryButton:disabled" in qss


def test_stylesheet_contains_root_warning_banner_selectors() -> None:
    """Verify Section 19 RootWarningBanner selectors exist in QSS."""
    qss = load_stylesheet()
    assert "QFrame#RootWarningBanner" in qss
    assert "QLabel#RootWarningIndicator" in qss
    assert "QLabel#RootWarningMessage" in qss


def test_resolve_stylesheet_tokens_normalization_branches() -> None:
    """substitute_tokens handles hyphen normalization, lower/upper, and errors."""
    from desktop.ui import substitute_tokens

    with pytest.raises(TypeError, match="Template must be a string"):
        substitute_tokens(123)  # type: ignore[arg-type]

    # Test key_lower fallback
    res1 = substitute_tokens(
        "color: {{ custom_token }};", replacements={"custom_token": "#123456"}
    )
    assert res1 == "color: #123456;"

    # Test norm.upper() fallback with hyphens
    res2 = substitute_tokens(
        "color: {{ my-custom-color }};",
        replacements={"MY_CUSTOM_COLOR": "#abcdef"},
    )
    assert res2 == "color: #abcdef;"

    # Test norm.lower() fallback with hyphens
    res3 = substitute_tokens(
        "color: {{ my-other-color }};",
        replacements={"my_other_color": "#fedcba"},
    )
    assert res3 == "color: #fedcba;"




