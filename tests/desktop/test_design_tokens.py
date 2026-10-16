"""Unit tests for OSIRIS Visual Design Tokens.

Verifies:
1. Module imports and symbol exports without Qt dependencies.
2. Pure Python execution without QApplication or external services.
3. Exact hex matching for all approved palette colors (surfaces, text, accents,
   severity, status).
4. Exact severity semantic names, case insensitivity, and color values.
5. Exact operational status semantic names, case insensitivity, and color values.
6. Exact 4px spacing rhythm compliance across named constants, container,
   and scale.
7. Exact key design target metrics compliance.
8. Restrained typography and radius scales.
9. Immutability / read-only guarantees on all token containers and mappings.
10. Robust Mapping protocol compliance (len, dict conversion, keys, values).
11. Defensive lookup behavior (handling non-string keys, internal attributes).
12. Badge and delegate helper functions (get_severity_color, get_status_color).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from desktop.ui import design_tokens
from desktop.ui.design_tokens import (
    ACCENT,
    ACCENT_FOCUS,
    ACCENTS,
    BORDER,
    COLLAPSED_NAVIGATION_WIDTH,
    COLORS,
    CONTEXTUAL_TOOLBAR_HEIGHT,
    EXPANDED_NAVIGATION_WIDTH,
    FONT_FAMILY_MONO,
    FONT_FAMILY_SANS,
    FONT_SIZE_MAJOR_HEADING,
    FONT_SIZE_NUMERIC_METRIC,
    FONT_SIZE_SECTION_TITLE,
    FONT_SIZE_SMALL_METADATA,
    FONT_SIZE_STANDARD_BODY,
    FONT_WEIGHT_BOLD,
    FONT_WEIGHT_MEDIUM,
    FONT_WEIGHT_REGULAR,
    FONT_WEIGHT_SEMIBOLD,
    INSPECTOR_PANEL_WIDTH,
    METRICS,
    OPERATIONAL_STATUS_COLORS,
    RADII,
    RADIUS,
    RADIUS_FULL,
    RADIUS_LARGE,
    RADIUS_MEDIUM,
    RADIUS_NONE,
    RADIUS_SMALL,
    SEVERITY,
    SEVERITY_COLORS,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SPACE_0,
    SPACE_1,
    SPACE_2,
    SPACE_3,
    SPACE_4,
    SPACE_5,
    SPACE_6,
    SPACE_7,
    SPACE_8,
    SPACING,
    SPACING_BASE,
    SPACING_SCALE,
    STATUS,
    STATUS_BAR_HEIGHT,
    STATUS_DEGRADED,
    STATUS_FRESH,
    STATUS_OFFLINE,
    STATUS_STALE,
    SURFACE_0,
    SURFACE_1,
    SURFACE_2,
    SURFACE_3,
    SURFACES,
    TABLE_ROW_HEIGHT,
    TEXT,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    TOP_HEADER_HEIGHT,
    TYPOGRAPHY,
    AccentColors,
    BorderRadius,
    CaseInsensitiveMapping,
    ColorPalette,
    ComponentMetrics,
    FontFamilies,
    FontSizes,
    FontWeights,
    OperationalStatusColors,
    SeverityColors,
    Spacing,
    SurfaceColors,
    TextColors,
    Typography,
    TypographyStyle,
    get_severity_color,
    get_status_color,
)

# ==============================================================================
# 1. Module Import & Export Tests
# ==============================================================================


def test_module_import_and_exports() -> None:
    """Verify all designated design token symbols are exported cleanly."""
    for symbol in design_tokens.__all__:
        assert hasattr(
            design_tokens, symbol
        ), f"Exported symbol '{symbol}' not found in module"


def test_pure_python_no_qapplication() -> None:
    """Verify design_tokens is pure Python and does not import Qt.

    The design_tokens module must be usable without constructing a QApplication.
    We verify this by:
    1. Running an isolated Python subprocess that imports desktop.ui.design_tokens
       and asserts QApplication.instance() is None.
    2. Confirming that design_tokens does not import PySide6 at module scope.
    """
    import importlib
    import subprocess
    import sys

    # 1. Verify in an isolated Python subprocess that importing design_tokens
    # does not instantiate a QApplication or require a Qt display.
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import desktop.ui.design_tokens as dt; "
                "from PySide6.QtWidgets import QApplication; "
                "assert QApplication.instance() is None; "
                "assert len(dt.__all__) > 0; "
                "print('OK')"
            ),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"Isolated import failed: {proc.stderr}"
    assert "OK" in proc.stdout

    # 2. Inspect module source directly to ensure zero PySide6 imports
    mod = importlib.import_module("desktop.ui.design_tokens")
    assert mod.__file__ is not None
    source = Path(mod.__file__).read_text(encoding="utf-8")
    assert "from PySide6" not in source, (
        "design_tokens.py must not import from PySide6"
    )
    assert "import PySide6" not in source, (
        "design_tokens.py must not import PySide6"
    )

    for symbol in design_tokens.__all__:
        assert hasattr(mod, symbol)


def test_dataclass_constructors_instantiable() -> None:
    """Verify all token dataclasses instantiate independently without error."""
    assert isinstance(SurfaceColors(), SurfaceColors)
    assert isinstance(TextColors(), TextColors)
    assert isinstance(AccentColors(), AccentColors)
    assert isinstance(SeverityColors(), SeverityColors)
    assert isinstance(OperationalStatusColors(), OperationalStatusColors)
    assert isinstance(ColorPalette(), ColorPalette)
    assert isinstance(Spacing(), Spacing)
    assert isinstance(ComponentMetrics(), ComponentMetrics)
    assert isinstance(BorderRadius(), BorderRadius)
    assert isinstance(FontSizes(), FontSizes)
    assert isinstance(FontWeights(), FontWeights)
    assert isinstance(FontFamilies(), FontFamilies)
    assert isinstance(Typography(), Typography)


# ==============================================================================
# 2. Approved Palette Verification (Surfaces, Text, Accent)
# ==============================================================================


def test_surface_palette_hex_values() -> None:
    """Verify surface palette exact hex matches."""
    expected_surfaces = {
        "surface_0": "#0F1117",
        "surface_1": "#161922",
        "surface_2": "#1E222D",
        "surface_3": "#282D3C",
        "border": "#2E3545",
    }

    # Module-level raw constants
    assert SURFACE_0 == "#0F1117"
    assert SURFACE_1 == "#161922"
    assert SURFACE_2 == "#1E222D"
    assert SURFACE_3 == "#282D3C"
    assert BORDER == "#2E3545"

    # Container attribute access (snake_case)
    assert SURFACES.surface_0 == expected_surfaces["surface_0"]
    assert SURFACES.surface_1 == expected_surfaces["surface_1"]
    assert SURFACES.surface_2 == expected_surfaces["surface_2"]
    assert SURFACES.surface_3 == expected_surfaces["surface_3"]
    assert SURFACES.border == expected_surfaces["border"]

    # Container attribute access (PascalCase palette specification)
    assert SURFACES.Surface0 == expected_surfaces["surface_0"]
    assert SURFACES.Surface1 == expected_surfaces["surface_1"]
    assert SURFACES.Surface2 == expected_surfaces["surface_2"]
    assert SURFACES.Surface3 == expected_surfaces["surface_3"]
    assert SURFACES.Border == expected_surfaces["border"]

    # Aggregated palette container
    assert COLORS.surfaces.surface_0 == expected_surfaces["surface_0"]
    assert COLORS.surfaces.border == expected_surfaces["border"]

    # Mapping / bracket access
    for key, expected_hex in expected_surfaces.items():
        assert SURFACES[key] == expected_hex
        assert SURFACES.get(key) == expected_hex
        assert key in SURFACES

    # Len and dictionary conversion
    assert len(SURFACES) == 5
    assert dict(SURFACES) == expected_surfaces


def test_text_palette_hex_values() -> None:
    """Verify text hierarchy exact hex matches."""
    assert TEXT_PRIMARY == "#F0F3F8"
    assert TEXT_SECONDARY == "#94A3B8"

    assert TEXT.primary == "#F0F3F8"
    assert TEXT.secondary == "#94A3B8"
    assert TEXT.Primary == "#F0F3F8"
    assert TEXT.Secondary == "#94A3B8"

    assert COLORS.text.primary == "#F0F3F8"
    assert COLORS.text.secondary == "#94A3B8"

    assert TEXT["primary"] == "#F0F3F8"
    assert TEXT["secondary"] == "#94A3B8"
    assert "primary" in TEXT
    assert "secondary" in TEXT

    assert len(TEXT) == 2
    assert dict(TEXT) == {"primary": "#F0F3F8", "secondary": "#94A3B8"}


def test_accent_palette_hex_values() -> None:
    """Verify interactive accent and focus exact hex matches."""
    assert ACCENT == "#3B82F6"
    assert ACCENT_FOCUS == "#60A5FA"

    assert ACCENTS.accent == "#3B82F6"
    assert ACCENTS.focus == "#60A5FA"
    assert ACCENTS.Accent == "#3B82F6"
    assert ACCENTS.Focus == "#60A5FA"

    assert COLORS.accents.accent == "#3B82F6"
    assert COLORS.accents.focus == "#60A5FA"

    assert ACCENTS["accent"] == "#3B82F6"
    assert ACCENTS["focus"] == "#60A5FA"

    assert len(ACCENTS) == 2
    assert dict(ACCENTS) == {"accent": "#3B82F6", "focus": "#60A5FA"}


# ==============================================================================
# 3. Severity Semantic Names & Colors
# ==============================================================================


def test_severity_semantic_names_and_hex_values() -> None:
    """Verify severity names (Critical, High, Medium, Low, Info) and hex values."""
    expected_severity = {
        "critical": "#EF4444",
        "high": "#F97316",
        "medium": "#EAB308",
        "low": "#3B82F6",
        "info": "#64748B",
    }

    # Raw constants
    assert SEVERITY_CRITICAL == "#EF4444"
    assert SEVERITY_HIGH == "#F97316"
    assert SEVERITY_MEDIUM == "#EAB308"
    assert SEVERITY_LOW == "#3B82F6"
    assert SEVERITY_INFO == "#64748B"

    # Container lowercase access
    assert SEVERITY.critical == expected_severity["critical"]
    assert SEVERITY.high == expected_severity["high"]
    assert SEVERITY.medium == expected_severity["medium"]
    assert SEVERITY.low == expected_severity["low"]
    assert SEVERITY.info == expected_severity["info"]

    # Container PascalCase access matching requirements
    assert SEVERITY.Critical == expected_severity["critical"]
    assert SEVERITY.High == expected_severity["high"]
    assert SEVERITY.Medium == expected_severity["medium"]
    assert SEVERITY.Low == expected_severity["low"]
    assert SEVERITY.Info == expected_severity["info"]

    # Container UPPERCASE access
    assert SEVERITY.CRITICAL == expected_severity["critical"]
    assert SEVERITY.HIGH == expected_severity["high"]
    assert SEVERITY.MEDIUM == expected_severity["medium"]
    assert SEVERITY.LOW == expected_severity["low"]
    assert SEVERITY.INFO == expected_severity["info"]

    # Read-only case-insensitive mapping proxy SEVERITY_COLORS
    for name, hex_val in expected_severity.items():
        assert SEVERITY_COLORS[name] == hex_val
        assert SEVERITY_COLORS[name.capitalize()] == hex_val
        assert SEVERITY_COLORS[name.upper()] == hex_val
        assert SEVERITY_COLORS.get(name.capitalize()) == hex_val
        assert name in SEVERITY_COLORS
        assert name.capitalize() in SEVERITY_COLORS

        # SEVERITY container bracket access
        assert SEVERITY[name] == hex_val
        assert SEVERITY[name.capitalize()] == hex_val
        assert SEVERITY[name.upper()] == hex_val
        assert name in SEVERITY
        assert name.capitalize() in SEVERITY

    # Aggregated COLORS container
    assert COLORS.severity.critical == expected_severity["critical"]
    assert COLORS.severity.high == expected_severity["high"]
    assert COLORS.severity.medium == expected_severity["medium"]
    assert COLORS.severity.low == expected_severity["low"]
    assert COLORS.severity.info == expected_severity["info"]

    # Mapping protocol
    assert len(SEVERITY) == 5
    assert len(SEVERITY_COLORS) == 5
    assert dict(SEVERITY) == expected_severity
    assert dict(SEVERITY_COLORS) == expected_severity


# ==============================================================================
# 4. Operational Status Semantic Names & Colors
# ==============================================================================


def test_operational_status_semantic_names_and_hex_values() -> None:
    """Verify status names (Fresh, Stale, Degraded, Offline) and hex values."""
    expected_status = {
        "fresh": "#10B981",
        "stale": "#F59E0B",
        "degraded": "#EF4444",
        "offline": "#64748B",
    }

    # Raw constants
    assert STATUS_FRESH == "#10B981"
    assert STATUS_STALE == "#F59E0B"
    assert STATUS_DEGRADED == "#EF4444"
    assert STATUS_OFFLINE == "#64748B"

    # Container lowercase access
    assert STATUS.fresh == expected_status["fresh"]
    assert STATUS.stale == expected_status["stale"]
    assert STATUS.degraded == expected_status["degraded"]
    assert STATUS.offline == expected_status["offline"]

    # Container PascalCase access matching requirements
    assert STATUS.Fresh == expected_status["fresh"]
    assert STATUS.Stale == expected_status["stale"]
    assert STATUS.Degraded == expected_status["degraded"]
    assert STATUS.Offline == expected_status["offline"]

    # Container UPPERCASE access
    assert STATUS.FRESH == expected_status["fresh"]
    assert STATUS.STALE == expected_status["stale"]
    assert STATUS.DEGRADED == expected_status["degraded"]
    assert STATUS.OFFLINE == expected_status["offline"]

    # Read-only case-insensitive mapping proxy OPERATIONAL_STATUS_COLORS
    for name, hex_val in expected_status.items():
        assert OPERATIONAL_STATUS_COLORS[name] == hex_val
        assert OPERATIONAL_STATUS_COLORS[name.capitalize()] == hex_val
        assert OPERATIONAL_STATUS_COLORS[name.upper()] == hex_val
        assert OPERATIONAL_STATUS_COLORS.get(name.capitalize()) == hex_val
        assert name in OPERATIONAL_STATUS_COLORS
        assert name.capitalize() in OPERATIONAL_STATUS_COLORS

        # STATUS container bracket access
        assert STATUS[name] == hex_val
        assert STATUS[name.capitalize()] == hex_val
        assert STATUS[name.upper()] == hex_val
        assert name in STATUS
        assert name.capitalize() in STATUS

    # Aggregated COLORS container
    assert COLORS.status.fresh == expected_status["fresh"]
    assert COLORS.status.stale == expected_status["stale"]
    assert COLORS.status.degraded == expected_status["degraded"]
    assert COLORS.status.offline == expected_status["offline"]

    # Mapping protocol
    assert len(STATUS) == 4
    assert len(OPERATIONAL_STATUS_COLORS) == 4
    assert dict(STATUS) == expected_status
    assert dict(OPERATIONAL_STATUS_COLORS) == expected_status


# ==============================================================================
# 5. Spacing Scale 4px Rhythm
# ==============================================================================


def test_spacing_scale_follows_4px_rhythm() -> None:
    """Verify spacing scale adheres strictly to the 4px baseline rhythm."""
    expected_scale = [0, 4, 8, 12, 16, 20, 24, 28, 32]

    # Baseline and scale constants
    assert SPACING_BASE == 4
    assert SPACING.baseline == 4
    assert SPACING.step == 4
    assert SPACING_SCALE == tuple(expected_scale)

    # Top-level standalone constants
    assert SPACE_0 == 0
    assert SPACE_1 == 4
    assert SPACE_2 == 8
    assert SPACE_3 == 12
    assert SPACE_4 == 16
    assert SPACE_5 == 20
    assert SPACE_6 == 24
    assert SPACE_7 == 28
    assert SPACE_8 == 32

    # Named attributes on container
    assert SPACING.space_0 == 0
    assert SPACING.space_1 == 4
    assert SPACING.space_2 == 8
    assert SPACING.space_3 == 12
    assert SPACING.space_4 == 16
    assert SPACING.space_5 == 20
    assert SPACING.space_6 == 24
    assert SPACING.space_7 == 28
    assert SPACING.space_8 == 32

    # Short aliases
    assert SPACING.s0 == 0
    assert SPACING.s1 == 4
    assert SPACING.s2 == 8
    assert SPACING.s3 == 12
    assert SPACING.s4 == 16
    assert SPACING.s5 == 20
    assert SPACING.s6 == 24
    assert SPACING.s7 == 28
    assert SPACING.s8 == 32

    # Step aliases and bracket indexing
    for idx, expected_px in enumerate(expected_scale):
        assert getattr(SPACING, f"step_{idx}") == expected_px
        assert SPACING[idx] == expected_px
        assert SPACING[str(idx)] == expected_px
        assert SPACING[f"space_{idx}"] == expected_px
        assert expected_px == idx * 4

    # Length and iterable iteration
    assert len(SPACING) == 9
    assert list(SPACING) == expected_scale

    # Out of range bounds
    with pytest.raises(IndexError):
        _ = SPACING[9]
    with pytest.raises(IndexError):
        _ = SPACING[-1]


# ==============================================================================
# 6. Key Design Target Metrics
# ==============================================================================


def test_key_design_target_metrics() -> None:
    """Verify exact values for key console dimensions and targets."""
    # Top-level standalone constants
    assert TABLE_ROW_HEIGHT == 28
    assert TOP_HEADER_HEIGHT == 48
    assert CONTEXTUAL_TOOLBAR_HEIGHT == 44
    assert STATUS_BAR_HEIGHT == 28
    assert COLLAPSED_NAVIGATION_WIDTH == 72
    assert EXPANDED_NAVIGATION_WIDTH == 200
    assert INSPECTOR_PANEL_WIDTH == 380

    # Target values on container
    assert METRICS.table_row_height == 28
    assert METRICS.top_header_height == 48
    assert METRICS.contextual_toolbar_height == 44
    assert METRICS.status_bar_height == 28
    assert METRICS.collapsed_navigation_width == 72
    assert METRICS.expanded_navigation_width == 200
    assert METRICS.inspector_panel_width == 380

    # Semantic convenience aliases
    assert METRICS.table_row == 28
    assert METRICS.row_height == 28
    assert METRICS.header == 48
    assert METRICS.header_height == 48
    assert METRICS.top_header == 48
    assert METRICS.contextual_toolbar == 44
    assert METRICS.toolbar_height == 44
    assert METRICS.status_bar == 28
    assert METRICS.collapsed_navigation == 72
    assert METRICS.nav_collapsed_width == 72
    assert METRICS.expanded_navigation == 200
    assert METRICS.nav_expanded_width == 200
    assert METRICS.inspector == 380
    assert METRICS.inspector_panel_target_width == 380

    # Bracket indexing
    assert METRICS["table_row_height"] == 28
    assert METRICS["top_header_height"] == 48
    assert METRICS["contextual_toolbar_height"] == 44
    assert METRICS["status_bar_height"] == 28
    assert METRICS["collapsed_navigation_width"] == 72
    assert METRICS["expanded_navigation_width"] == 200
    assert METRICS["inspector_panel_width"] == 380

    # Mapping protocol
    assert len(METRICS) == 7
    assert dict(METRICS)["table_row_height"] == 28


# ==============================================================================
# 7. Restrained Typography Scale & Corner Radii
# ==============================================================================


def test_restrained_typography_scale() -> None:
    """Verify compact security console typography scale."""
    # Top-level standalone constants
    assert FONT_SIZE_SMALL_METADATA == 11
    assert FONT_SIZE_STANDARD_BODY == 13
    assert FONT_SIZE_SECTION_TITLE == 15
    assert FONT_SIZE_MAJOR_HEADING == 20
    assert FONT_SIZE_NUMERIC_METRIC == 18

    assert FONT_WEIGHT_REGULAR == 400
    assert FONT_WEIGHT_MEDIUM == 500
    assert FONT_WEIGHT_SEMIBOLD == 600
    assert FONT_WEIGHT_BOLD == 700

    assert "-apple-system" in FONT_FAMILY_SANS
    assert "JetBrains Mono" in FONT_FAMILY_MONO

    # Role point sizes on container
    assert TYPOGRAPHY.sizes.small_metadata == 11
    assert TYPOGRAPHY.sizes.standard_body == 13
    assert TYPOGRAPHY.sizes.section_title == 15
    assert TYPOGRAPHY.sizes.major_heading == 20
    assert TYPOGRAPHY.sizes.numeric_metric == 18

    # Short aliases
    assert TYPOGRAPHY.sizes.metadata == 11
    assert TYPOGRAPHY.sizes.body == 13
    assert TYPOGRAPHY.sizes.section == 15
    assert TYPOGRAPHY.sizes.heading == 20
    assert TYPOGRAPHY.sizes.metric == 18

    # Weights
    assert TYPOGRAPHY.weights.regular == 400
    assert TYPOGRAPHY.weights.medium == 500
    assert TYPOGRAPHY.weights.semibold == 600
    assert TYPOGRAPHY.weights.bold == 700

    # Composite typography styles
    assert TYPOGRAPHY.small_metadata.size == 11
    assert TYPOGRAPHY.small_metadata.weight == 400

    assert TYPOGRAPHY.standard_body.size == 13
    assert TYPOGRAPHY.standard_body.weight == 400

    assert TYPOGRAPHY.section_title.size == 15
    assert TYPOGRAPHY.section_title.weight == 600

    assert TYPOGRAPHY.major_heading.size == 20
    assert TYPOGRAPHY.major_heading.weight == 700

    assert TYPOGRAPHY.numeric_metric.size == 18
    assert TYPOGRAPHY.numeric_metric.weight == 600
    assert TYPOGRAPHY.numeric_metric.family == "mono"

    # TypographyStyle QSS and family stack properties
    assert "font-size: 13px" in TYPOGRAPHY.standard_body.qss
    assert "font-weight: 400" in TYPOGRAPHY.standard_body.qss
    assert "JetBrains Mono" in TYPOGRAPHY.numeric_metric.family_stack
    assert "-apple-system" in TYPOGRAPHY.standard_body.family_stack


def test_restrained_radius_scale() -> None:
    """Verify restrained corner radius scale avoiding oversized consumer styling."""
    # Top-level standalone constants
    assert RADIUS_NONE == 0
    assert RADIUS_SMALL == 2
    assert RADIUS_MEDIUM == 4
    assert RADIUS_LARGE == 6
    assert RADIUS_FULL == 9999

    # Container values
    assert RADII.none == 0
    assert RADII.small == 2
    assert RADII.medium == 4
    assert RADII.large == 6
    assert RADII.full == 9999

    # Aliases
    assert RADII.sm == 2
    assert RADII.md == 4
    assert RADII.lg == 6
    assert RADII.pill == 9999

    # Bracket indexing
    assert RADII["small"] == 2
    assert RADII["md"] == 4

    # RADIUS alias reference
    assert RADIUS is RADII
    assert len(RADII) == 5
    assert dict(RADII)["medium"] == 4


# ==============================================================================
# 8. Token Container Immutability & Read-Only Guarantees
# ==============================================================================


def test_container_immutability_attribute_assignment() -> None:
    """Verify mutating attributes on token containers raises FrozenInstanceError."""
    # SurfaceColors
    with pytest.raises(FrozenInstanceError):
        SURFACES.surface_0 = "#FFFFFF"  # type: ignore[misc]

    # TextColors
    with pytest.raises(FrozenInstanceError):
        TEXT.primary = "#000000"  # type: ignore[misc]

    # AccentColors
    with pytest.raises(FrozenInstanceError):
        ACCENTS.accent = "#000000"  # type: ignore[misc]

    # SeverityColors
    with pytest.raises(FrozenInstanceError):
        SEVERITY.critical = "#000000"  # type: ignore[misc]

    # OperationalStatusColors
    with pytest.raises(FrozenInstanceError):
        STATUS.fresh = "#000000"  # type: ignore[misc]

    # ColorPalette
    with pytest.raises(FrozenInstanceError):
        COLORS.surfaces = SurfaceColors()  # type: ignore[misc]

    # Spacing
    with pytest.raises(FrozenInstanceError):
        SPACING.space_1 = 100  # type: ignore[misc]

    # ComponentMetrics
    with pytest.raises(FrozenInstanceError):
        METRICS.table_row_height = 100  # type: ignore[misc]

    # BorderRadius
    with pytest.raises(FrozenInstanceError):
        RADII.small = 100  # type: ignore[misc]

    # Typography
    with pytest.raises(FrozenInstanceError):
        TYPOGRAPHY.small_metadata = TypographyStyle(  # type: ignore[misc]
            size=99, weight=99, line_height=99
        )

    # FontSizes
    with pytest.raises(FrozenInstanceError):
        TYPOGRAPHY.sizes.small_metadata = 99  # type: ignore[misc]


def test_container_immutability_attribute_deletion() -> None:
    """Verify deleting attributes on token containers raises FrozenInstanceError."""
    with pytest.raises(FrozenInstanceError):
        del SURFACES.surface_0  # type: ignore[misc]

    with pytest.raises(FrozenInstanceError):
        del SEVERITY.critical  # type: ignore[misc]

    with pytest.raises(FrozenInstanceError):
        del STATUS.fresh  # type: ignore[misc]

    with pytest.raises(FrozenInstanceError):
        del METRICS.table_row_height  # type: ignore[misc]


def test_container_immutability_item_assignment_and_deletion() -> None:
    """Verify that item mutation/deletion on token containers raises TypeError."""
    with pytest.raises(TypeError):
        SURFACES["surface_0"] = "#FFFFFF"  # type: ignore[operator]

    with pytest.raises(TypeError):
        SEVERITY["critical"] = "#FFFFFF"  # type: ignore[operator]

    with pytest.raises(TypeError):
        STATUS["fresh"] = "#FFFFFF"  # type: ignore[operator]

    with pytest.raises(TypeError):
        METRICS["table_row_height"] = 99  # type: ignore[operator]

    with pytest.raises(TypeError):
        RADII["small"] = 99  # type: ignore[operator]

    with pytest.raises(TypeError):
        SPACING[1] = 99  # type: ignore[index]

    with pytest.raises(TypeError):
        del SEVERITY["critical"]  # type: ignore[operator]

    with pytest.raises(TypeError):
        del STATUS["fresh"]  # type: ignore[operator]

    with pytest.raises(TypeError):
        del SURFACES["surface_0"]  # type: ignore[operator]


def test_mapping_proxy_immutability() -> None:
    """Verify that SEVERITY_COLORS and OPERATIONAL_STATUS_COLORS reject mutation."""
    with pytest.raises(TypeError):
        SEVERITY_COLORS["critical"] = "#FFFFFF"  # type: ignore[index]

    with pytest.raises(TypeError):
        OPERATIONAL_STATUS_COLORS["fresh"] = "#FFFFFF"  # type: ignore[index]


# ==============================================================================
# 9. Defensive Key Lookups & Edge Cases
# ==============================================================================


def test_non_string_keys_raise_key_error() -> None:
    """Verify non-string keys raise KeyError rather than crashing with TypeError."""
    for container in (SURFACES, TEXT, ACCENTS, SEVERITY, STATUS, METRICS, RADII):
        with pytest.raises(KeyError):
            _ = container[1]  # type: ignore[index]
        with pytest.raises(KeyError):
            _ = container[None]  # type: ignore[index]
        assert 1 not in container
        assert None not in container
        assert container.get(1, "fallback") == "fallback"  # type: ignore[call-overload]
        assert container.get(None, "fallback") == "fallback"  # type: ignore[call-overload]


def test_internal_attributes_not_leaked_as_tokens() -> None:
    """Verify internal attributes like __doc__ or __module__ raise KeyError."""
    for container in (SURFACES, TEXT, ACCENTS, SEVERITY, STATUS, METRICS, RADII):
        with pytest.raises(KeyError):
            _ = container["__doc__"]
        with pytest.raises(KeyError):
            _ = container["__module__"]
        assert "__doc__" not in container
        assert "__module__" not in container


def test_mapping_abc_inheritance() -> None:
    """Verify all token containers inherit from collections.abc.Mapping."""
    for container in (
        SURFACES,
        TEXT,
        ACCENTS,
        SEVERITY,
        STATUS,
        METRICS,
        RADII,
        SEVERITY_COLORS,
        OPERATIONAL_STATUS_COLORS,
    ):
        assert isinstance(container, Mapping)
        assert hasattr(container, "keys")
        assert hasattr(container, "values")
        assert hasattr(container, "items")
        assert len(list(container.keys())) == len(container)

    assert isinstance(SEVERITY_COLORS, CaseInsensitiveMapping)
    assert isinstance(OPERATIONAL_STATUS_COLORS, CaseInsensitiveMapping)


def test_badge_and_delegate_helper_functions() -> None:
    """Verify get_severity_color and get_status_color helper behavior."""
    # Exact and case variations
    assert get_severity_color("critical") == "#EF4444"
    assert get_severity_color("Critical") == "#EF4444"
    assert get_severity_color("CRITICAL") == "#EF4444"
    assert get_severity_color("  High  ") == "#F97316"
    assert get_severity_color("medium") == "#EAB308"
    assert get_severity_color("low") == "#3B82F6"
    assert get_severity_color("info") == "#64748B"

    # Fallback default for unknown severity
    assert get_severity_color("unknown") == "#64748B"
    assert get_severity_color("custom_fallback", default="#123456") == "#123456"
    assert get_severity_color(None) == "#64748B"  # type: ignore[arg-type]

    # Exact and case variations for status
    assert get_status_color("fresh") == "#10B981"
    assert get_status_color("Fresh") == "#10B981"
    assert get_status_color("FRESH") == "#10B981"
    assert get_status_color("stale") == "#F59E0B"
    assert get_status_color("degraded") == "#EF4444"
    assert get_status_color("offline") == "#64748B"

    # Fallback default for unknown status
    assert get_status_color("unknown") == "#64748B"
    assert get_status_color("custom_fallback", default="#123456") == "#123456"
    assert get_status_color(None) == "#64748B"  # type: ignore[arg-type]
