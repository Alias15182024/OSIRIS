"""OSIRIS Desktop Visual Design Tokens.

Single centralized source of truth for all visual tokens in the OSIRIS Desktop
native Qt console. Defines the dark professional SOC/security-console visual
language: high information density, clear severity and operational status
semantics, deterministic 4px spacing rhythm, compact typography scale, and
restrained corner radii.

Tokens are defined using Python standard library frozen dataclasses and
immutable mappings so they can be safely consumed by QtWidgets, custom QSS
generators, delegates, and badges without risk of runtime mutation.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any

# ==============================================================================
# 1. Raw Approved Palette Hex Constants
# ==============================================================================

# Surfaces
SURFACE_0: str = "#0F1117"  # Deepest application background
SURFACE_1: str = "#161922"  # Sidebar, panels, headers
SURFACE_2: str = "#1E222D"  # Elevated cards, alternate rows
SURFACE_3: str = "#282D3C"  # Hover states, active highlights, modals
BORDER: str = "#2E3545"     # Subtle structural dividers and borders

# Text
TEXT_PRIMARY: str = "#F0F3F8"    # High-contrast primary reading text
TEXT_SECONDARY: str = "#94A3B8"  # Subdued metadata, secondary labels

# Accent
ACCENT: str = "#3B82F6"        # Primary interactive actions, selected tabs
ACCENT_FOCUS: str = "#60A5FA"  # Focus rings, keyboard navigation indicator

# Severity
SEVERITY_CRITICAL: str = "#EF4444"
SEVERITY_HIGH: str = "#F97316"
SEVERITY_MEDIUM: str = "#EAB308"
SEVERITY_LOW: str = "#3B82F6"
SEVERITY_INFO: str = "#64748B"

# Operational Status
STATUS_FRESH: str = "#10B981"
STATUS_STALE: str = "#F59E0B"
STATUS_DEGRADED: str = "#EF4444"
STATUS_OFFLINE: str = "#64748B"


# ==============================================================================
# 2. Spacing Rhythm Constants (4px Baseline)
# ==============================================================================

SPACE_0: int = 0
SPACE_1: int = 4
SPACE_2: int = 8
SPACE_3: int = 12
SPACE_4: int = 16
SPACE_5: int = 20
SPACE_6: int = 24
SPACE_7: int = 28
SPACE_8: int = 32

SPACING_BASE: int = 4
SPACING_SCALE: tuple[int, ...] = (0, 4, 8, 12, 16, 20, 24, 28, 32)


# ==============================================================================
# 3. Component Target Metrics Constants
# ==============================================================================

TABLE_ROW_HEIGHT: int = 28
TOP_HEADER_HEIGHT: int = 48
CONTEXTUAL_TOOLBAR_HEIGHT: int = 44
STATUS_BAR_HEIGHT: int = 28
COLLAPSED_NAVIGATION_WIDTH: int = 72
EXPANDED_NAVIGATION_WIDTH: int = 200
INSPECTOR_PANEL_WIDTH: int = 380


# ==============================================================================
# 4. Corner Radius Constants
# ==============================================================================

RADIUS_NONE: int = 0
RADIUS_SMALL: int = 2
RADIUS_MEDIUM: int = 4
RADIUS_LARGE: int = 6
RADIUS_FULL: int = 9999


# ==============================================================================
# 5. Typography Scale Constants
# ==============================================================================

FONT_SIZE_SMALL_METADATA: int = 11
FONT_SIZE_STANDARD_BODY: int = 13
FONT_SIZE_SECTION_TITLE: int = 15
FONT_SIZE_MAJOR_HEADING: int = 20
FONT_SIZE_NUMERIC_METRIC: int = 18

FONT_WEIGHT_REGULAR: int = 400
FONT_WEIGHT_MEDIUM: int = 500
FONT_WEIGHT_SEMIBOLD: int = 600
FONT_WEIGHT_BOLD: int = 700

FONT_FAMILY_SANS: str = (
    "-apple-system, BlinkMacSystemFont, 'Segoe UI', "
    "Roboto, Helvetica, Arial, sans-serif"
)
FONT_FAMILY_MONO: str = (
    "'JetBrains Mono', 'SF Mono', Monaco, Menlo, Consolas, monospace"
)


# ==============================================================================
# Immutable Case-Insensitive Mapping
# ==============================================================================

class CaseInsensitiveMapping(Mapping[str, str]):
    """Read-only case-insensitive mapping for semantic token lookups."""

    def __init__(self, data: Mapping[str, str] | dict[str, str]) -> None:
        self._canonical: dict[str, str] = dict(data)
        self._lookup: dict[str, str] = {
            k.strip().lower().replace("-", "_").replace(" ", "_"): v
            for k, v in data.items()
        }

    def __getitem__(self, key: Any) -> str:
        if not isinstance(key, str):
            raise KeyError(key)
        norm = key.strip().lower().replace("-", "_").replace(" ", "_")
        if norm in self._lookup:
            return self._lookup[norm]
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return iter(self._canonical)

    def __len__(self) -> int:
        return len(self._canonical)

    def __contains__(self, key: Any) -> bool:
        if not isinstance(key, str):
            return False
        norm = key.strip().lower().replace("-", "_").replace(" ", "_")
        return norm in self._lookup

    def __repr__(self) -> str:
        return f"CaseInsensitiveMapping({self._canonical!r})"


# ==============================================================================
# Immutable Structured Token Containers
# ==============================================================================

@dataclass(frozen=True)
class SurfaceColors(Mapping[str, str]):
    """Surface and border tokens for dark SOC console layout."""

    surface_0: str = SURFACE_0
    surface_1: str = SURFACE_1
    surface_2: str = SURFACE_2
    surface_3: str = SURFACE_3
    border: str = BORDER

    def __getitem__(self, key: Any) -> str:
        if not isinstance(key, str):
            raise KeyError(key)
        norm = key.strip().lower().replace("-", "_").replace(" ", "_")
        if norm in ("surface_0", "surface0"):
            return self.surface_0
        if norm in ("surface_1", "surface1"):
            return self.surface_1
        if norm in ("surface_2", "surface2"):
            return self.surface_2
        if norm in ("surface_3", "surface3"):
            return self.surface_3
        if norm == "border":
            return self.border
        raise KeyError(f"Unknown surface key '{key}'")

    def __iter__(self) -> Iterator[str]:
        yield from ("surface_0", "surface_1", "surface_2", "surface_3", "border")

    def __len__(self) -> int:
        return 5

    def __getattr__(self, name: str) -> str:
        try:
            return self[name]
        except KeyError:
            raise AttributeError(
                f"'{self.__class__.__name__}' object has no attribute '{name}'"
            ) from None


@dataclass(frozen=True)
class TextColors(Mapping[str, str]):
    """High-legibility text hierarchy for long investigation sessions."""

    primary: str = TEXT_PRIMARY
    secondary: str = TEXT_SECONDARY

    def __getitem__(self, key: Any) -> str:
        if not isinstance(key, str):
            raise KeyError(key)
        norm = key.strip().lower().replace("-", "_").replace(" ", "_")
        if norm == "primary":
            return self.primary
        if norm == "secondary":
            return self.secondary
        raise KeyError(f"Unknown text key '{key}'")

    def __iter__(self) -> Iterator[str]:
        yield from ("primary", "secondary")

    def __len__(self) -> int:
        return 2

    def __getattr__(self, name: str) -> str:
        try:
            return self[name]
        except KeyError:
            raise AttributeError(
                f"'{self.__class__.__name__}' object has no attribute '{name}'"
            ) from None


@dataclass(frozen=True)
class AccentColors(Mapping[str, str]):
    """Restrained accent colors for interactive feedback and focus states."""

    accent: str = ACCENT
    focus: str = ACCENT_FOCUS

    def __getitem__(self, key: Any) -> str:
        if not isinstance(key, str):
            raise KeyError(key)
        norm = key.strip().lower().replace("-", "_").replace(" ", "_")
        if norm == "accent":
            return self.accent
        if norm == "focus":
            return self.focus
        raise KeyError(f"Unknown accent key '{key}'")

    def __iter__(self) -> Iterator[str]:
        yield from ("accent", "focus")

    def __len__(self) -> int:
        return 2

    def __getattr__(self, name: str) -> str:
        try:
            return self[name]
        except KeyError:
            raise AttributeError(
                f"'{self.__class__.__name__}' object has no attribute '{name}'"
            ) from None


@dataclass(frozen=True)
class SeverityColors(Mapping[str, str]):
    """Clear, unambiguous incident severity semantics."""

    critical: str = SEVERITY_CRITICAL
    high: str = SEVERITY_HIGH
    medium: str = SEVERITY_MEDIUM
    low: str = SEVERITY_LOW
    info: str = SEVERITY_INFO

    def __getitem__(self, key: Any) -> str:
        if not isinstance(key, str):
            raise KeyError(key)
        norm = key.strip().lower().replace("-", "_").replace(" ", "_")
        if norm == "critical":
            return self.critical
        if norm == "high":
            return self.high
        if norm == "medium":
            return self.medium
        if norm == "low":
            return self.low
        if norm == "info":
            return self.info
        raise KeyError(f"Unknown severity level '{key}'")

    def __iter__(self) -> Iterator[str]:
        yield from ("critical", "high", "medium", "low", "info")

    def __len__(self) -> int:
        return 5

    def __getattr__(self, name: str) -> str:
        try:
            return self[name]
        except KeyError:
            raise AttributeError(
                f"'{self.__class__.__name__}' object has no attribute '{name}'"
            ) from None


@dataclass(frozen=True)
class OperationalStatusColors(Mapping[str, str]):
    """Operational collector and endpoint health indicators."""

    fresh: str = STATUS_FRESH
    stale: str = STATUS_STALE
    degraded: str = STATUS_DEGRADED
    offline: str = STATUS_OFFLINE

    def __getitem__(self, key: Any) -> str:
        if not isinstance(key, str):
            raise KeyError(key)
        norm = key.strip().lower().replace("-", "_").replace(" ", "_")
        if norm == "fresh":
            return self.fresh
        if norm == "stale":
            return self.stale
        if norm == "degraded":
            return self.degraded
        if norm == "offline":
            return self.offline
        raise KeyError(f"Unknown status level '{key}'")

    def __iter__(self) -> Iterator[str]:
        yield from ("fresh", "stale", "degraded", "offline")

    def __len__(self) -> int:
        return 4

    def __getattr__(self, name: str) -> str:
        try:
            return self[name]
        except KeyError:
            raise AttributeError(
                f"'{self.__class__.__name__}' object has no attribute '{name}'"
            ) from None


# Semantic mapping instances (read-only case-insensitive views)
SEVERITY_COLORS: CaseInsensitiveMapping = CaseInsensitiveMapping({
    "critical": SEVERITY_CRITICAL,
    "high": SEVERITY_HIGH,
    "medium": SEVERITY_MEDIUM,
    "low": SEVERITY_LOW,
    "info": SEVERITY_INFO,
})

OPERATIONAL_STATUS_COLORS: CaseInsensitiveMapping = CaseInsensitiveMapping({
    "fresh": STATUS_FRESH,
    "stale": STATUS_STALE,
    "degraded": STATUS_DEGRADED,
    "offline": STATUS_OFFLINE,
})


def get_severity_color(severity: str, default: str = SEVERITY_INFO) -> str:
    """Safely resolve severity string to approved hex color, with default fallback."""
    if not isinstance(severity, str):
        return default
    return SEVERITY_COLORS.get(severity, default)


def get_status_color(status: str, default: str = STATUS_OFFLINE) -> str:
    """Safely resolve status string to approved hex color, with fallback."""
    if not isinstance(status, str):
        return default
    return OPERATIONAL_STATUS_COLORS.get(status, default)


@dataclass(frozen=True)
class ColorPalette:
    """Aggregated color palette providing structured access to all color tokens."""

    surfaces: SurfaceColors = SurfaceColors()
    text: TextColors = TextColors()
    accents: AccentColors = AccentColors()
    severity: SeverityColors = SeverityColors()
    status: OperationalStatusColors = OperationalStatusColors()


# ==============================================================================
# Spacing Rhythm Tokens (4px Baseline)
# ==============================================================================

@dataclass(frozen=True)
class Spacing:
    """Deterministic 4px baseline spacing rhythm for dense console layout."""

    space_0: int = SPACE_0
    space_1: int = SPACE_1
    space_2: int = SPACE_2
    space_3: int = SPACE_3
    space_4: int = SPACE_4
    space_5: int = SPACE_5
    space_6: int = SPACE_6
    space_7: int = SPACE_7
    space_8: int = SPACE_8

    baseline: int = SPACING_BASE
    step: int = SPACING_BASE

    # Short aliases
    @property
    def s0(self) -> int:
        return self.space_0

    @property
    def s1(self) -> int:
        return self.space_1

    @property
    def s2(self) -> int:
        return self.space_2

    @property
    def s3(self) -> int:
        return self.space_3

    @property
    def s4(self) -> int:
        return self.space_4

    @property
    def s5(self) -> int:
        return self.space_5

    @property
    def s6(self) -> int:
        return self.space_6

    @property
    def s7(self) -> int:
        return self.space_7

    @property
    def s8(self) -> int:
        return self.space_8

    @property
    def step_0(self) -> int:
        return self.space_0

    @property
    def step_1(self) -> int:
        return self.space_1

    @property
    def step_2(self) -> int:
        return self.space_2

    @property
    def step_3(self) -> int:
        return self.space_3

    @property
    def step_4(self) -> int:
        return self.space_4

    @property
    def step_5(self) -> int:
        return self.space_5

    @property
    def step_6(self) -> int:
        return self.space_6

    @property
    def step_7(self) -> int:
        return self.space_7

    @property
    def step_8(self) -> int:
        return self.space_8

    def __getitem__(self, index: Any) -> int:
        if isinstance(index, int):
            vals = (
                self.space_0,
                self.space_1,
                self.space_2,
                self.space_3,
                self.space_4,
                self.space_5,
                self.space_6,
                self.space_7,
                self.space_8,
            )
            if 0 <= index <= 8:
                return vals[index]
            raise IndexError(f"Spacing index {index} out of range (0-8)")
        if isinstance(index, str):
            norm = index.strip().lower().replace("-", "_")
            if norm.isdigit():
                idx = int(norm)
                if 0 <= idx <= 8:
                    return self[idx]
                raise IndexError(f"Spacing index {idx} out of range (0-8)")
            name_map: dict[str, int] = {
                "space_0": self.space_0,
                "space_1": self.space_1,
                "space_2": self.space_2,
                "space_3": self.space_3,
                "space_4": self.space_4,
                "space_5": self.space_5,
                "space_6": self.space_6,
                "space_7": self.space_7,
                "space_8": self.space_8,
                "step_0": self.space_0,
                "step_1": self.space_1,
                "step_2": self.space_2,
                "step_3": self.space_3,
                "step_4": self.space_4,
                "step_5": self.space_5,
                "step_6": self.space_6,
                "step_7": self.space_7,
                "step_8": self.space_8,
                "s0": self.space_0,
                "s1": self.space_1,
                "s2": self.space_2,
                "s3": self.space_3,
                "s4": self.space_4,
                "s5": self.space_5,
                "s6": self.space_6,
                "s7": self.space_7,
                "s8": self.space_8,
                "baseline": self.baseline,
                "step": self.step,
            }
            if norm in name_map:
                return name_map[norm]
            raise KeyError(f"Unknown spacing key '{index}'")
        raise KeyError(index)

    def __len__(self) -> int:
        return 9

    def __iter__(self) -> Iterator[int]:
        yield self.space_0
        yield self.space_1
        yield self.space_2
        yield self.space_3
        yield self.space_4
        yield self.space_5
        yield self.space_6
        yield self.space_7
        yield self.space_8


# ==============================================================================
# Restrained Typography Scale
# ==============================================================================

@dataclass(frozen=True)
class TypographyStyle:
    """Typography style combining point size, weight, line height, and font family."""

    size: int
    weight: int
    line_height: int
    family: str = "sans"

    @property
    def family_stack(self) -> str:
        """Full cross-platform font family stack."""
        if self.family == "mono":
            return FONT_FAMILY_MONO
        return FONT_FAMILY_SANS

    @property
    def qss(self) -> str:
        """QSS fragment for font size and font weight styling."""
        return f"font-size: {self.size}px; font-weight: {self.weight};"


@dataclass(frozen=True)
class FontSizes:
    """Restrained font size scale in points/pixels for compact security console."""

    small_metadata: int = FONT_SIZE_SMALL_METADATA  # 11: Small metadata, timestamps
    standard_body: int = FONT_SIZE_STANDARD_BODY   # 13: Standard body, table cells
    section_title: int = FONT_SIZE_SECTION_TITLE   # 15: Panel headers, section dividers
    major_heading: int = FONT_SIZE_MAJOR_HEADING   # 20: Page/view title
    numeric_metric: int = FONT_SIZE_NUMERIC_METRIC # 18: Numerical KPI counters

    @property
    def metadata(self) -> int:
        return self.small_metadata

    @property
    def body(self) -> int:
        return self.standard_body

    @property
    def section(self) -> int:
        return self.section_title

    @property
    def heading(self) -> int:
        return self.major_heading

    @property
    def metric(self) -> int:
        return self.numeric_metric


@dataclass(frozen=True)
class FontWeights:
    """Font weights mapping to standard OpenType / Qt weight integers."""

    regular: int = FONT_WEIGHT_REGULAR   # 400
    medium: int = FONT_WEIGHT_MEDIUM     # 500
    semibold: int = FONT_WEIGHT_SEMIBOLD # 600
    bold: int = FONT_WEIGHT_BOLD         # 700


@dataclass(frozen=True)
class FontFamilies:
    """Clean cross-platform font families for UI and tabular telemetry."""

    sans: str = FONT_FAMILY_SANS
    mono: str = FONT_FAMILY_MONO


@dataclass(frozen=True)
class Typography:
    """Centralized typography system for dense desktop security console."""

    sizes: FontSizes = FontSizes()
    weights: FontWeights = FontWeights()
    families: FontFamilies = FontFamilies()

    small_metadata: TypographyStyle = TypographyStyle(
        size=11, weight=400, line_height=14, family="sans"
    )
    standard_body: TypographyStyle = TypographyStyle(
        size=13, weight=400, line_height=18, family="sans"
    )
    section_title: TypographyStyle = TypographyStyle(
        size=15, weight=600, line_height=20, family="sans"
    )
    major_heading: TypographyStyle = TypographyStyle(
        size=20, weight=700, line_height=26, family="sans"
    )
    numeric_metric: TypographyStyle = TypographyStyle(
        size=18, weight=600, line_height=22, family="mono"
    )

    @property
    def metadata(self) -> TypographyStyle:
        return self.small_metadata

    @property
    def body(self) -> TypographyStyle:
        return self.standard_body

    @property
    def section(self) -> TypographyStyle:
        return self.section_title

    @property
    def heading(self) -> TypographyStyle:
        return self.major_heading

    @property
    def metric(self) -> TypographyStyle:
        return self.numeric_metric


# ==============================================================================
# Component Metrics / Target Dimensions
# ==============================================================================

@dataclass(frozen=True)
class ComponentMetrics(Mapping[str, int]):
    """Design-target dimensions for core OSIRIS desktop chrome and components."""

    table_row_height: int = TABLE_ROW_HEIGHT
    top_header_height: int = TOP_HEADER_HEIGHT
    contextual_toolbar_height: int = CONTEXTUAL_TOOLBAR_HEIGHT
    status_bar_height: int = STATUS_BAR_HEIGHT
    collapsed_navigation_width: int = COLLAPSED_NAVIGATION_WIDTH
    expanded_navigation_width: int = EXPANDED_NAVIGATION_WIDTH
    inspector_panel_width: int = INSPECTOR_PANEL_WIDTH

    # Semantic aliases
    @property
    def table_row(self) -> int:
        return self.table_row_height

    @property
    def row_height(self) -> int:
        return self.table_row_height

    @property
    def header(self) -> int:
        return self.top_header_height

    @property
    def header_height(self) -> int:
        return self.top_header_height

    @property
    def top_header(self) -> int:
        return self.top_header_height

    @property
    def contextual_toolbar(self) -> int:
        return self.contextual_toolbar_height

    @property
    def toolbar_height(self) -> int:
        return self.contextual_toolbar_height

    @property
    def status_bar(self) -> int:
        return self.status_bar_height

    @property
    def collapsed_navigation(self) -> int:
        return self.collapsed_navigation_width

    @property
    def nav_collapsed_width(self) -> int:
        return self.collapsed_navigation_width

    @property
    def expanded_navigation(self) -> int:
        return self.expanded_navigation_width

    @property
    def nav_expanded_width(self) -> int:
        return self.expanded_navigation_width

    @property
    def inspector(self) -> int:
        return self.inspector_panel_width

    @property
    def inspector_panel_target_width(self) -> int:
        return self.inspector_panel_width

    def __getitem__(self, key: Any) -> int:
        if not isinstance(key, str):
            raise KeyError(key)
        norm = (
            key.strip()
            .lower()
            .replace("-", "_")
            .replace(" ", "_")
            .replace("/", "_")
        )
        metric_map: dict[str, int] = {
            "table_row_height": self.table_row_height,
            "table_row": self.table_row_height,
            "row_height": self.table_row_height,
            "top_header_height": self.top_header_height,
            "top_header": self.top_header_height,
            "header_height": self.top_header_height,
            "header": self.top_header_height,
            "contextual_toolbar_height": self.contextual_toolbar_height,
            "contextual_toolbar": self.contextual_toolbar_height,
            "toolbar_height": self.contextual_toolbar_height,
            "status_bar_height": self.status_bar_height,
            "status_bar": self.status_bar_height,
            "collapsed_navigation_width": self.collapsed_navigation_width,
            "collapsed_navigation": self.collapsed_navigation_width,
            "nav_collapsed_width": self.collapsed_navigation_width,
            "expanded_navigation_width": self.expanded_navigation_width,
            "expanded_navigation": self.expanded_navigation_width,
            "nav_expanded_width": self.expanded_navigation_width,
            "inspector_panel_width": self.inspector_panel_width,
            "inspector_panel_target_width": self.inspector_panel_width,
            "inspector": self.inspector_panel_width,
        }
        if norm in metric_map:
            return metric_map[norm]
        raise KeyError(f"Unknown metric key '{key}'")

    def __iter__(self) -> Iterator[str]:
        yield from (
            "table_row_height",
            "top_header_height",
            "contextual_toolbar_height",
            "status_bar_height",
            "collapsed_navigation_width",
            "expanded_navigation_width",
            "inspector_panel_width",
        )

    def __len__(self) -> int:
        return 7

    def __getattr__(self, name: str) -> int:
        try:
            return self[name]
        except KeyError:
            raise AttributeError(
                f"'{self.__class__.__name__}' object has no attribute '{name}'"
            ) from None


# ==============================================================================
# Restrained Radius Scale
# ==============================================================================

@dataclass(frozen=True)
class BorderRadius(Mapping[str, int]):
    """Restrained corner radius values avoiding oversized consumer-app curves."""

    none: int = RADIUS_NONE
    small: int = RADIUS_SMALL   # Badges, tags, nested subcomponents
    medium: int = RADIUS_MEDIUM # Standard buttons, input controls, cards
    large: int = RADIUS_LARGE   # Dialogs, flyouts, floating panels
    full: int = RADIUS_FULL     # Pill badges, status indicator dots

    @property
    def sm(self) -> int:
        return self.small

    @property
    def md(self) -> int:
        return self.medium

    @property
    def lg(self) -> int:
        return self.large

    @property
    def pill(self) -> int:
        return self.full

    def __getitem__(self, key: Any) -> int:
        if not isinstance(key, str):
            raise KeyError(key)
        norm = key.strip().lower().replace("-", "_").replace(" ", "_")
        radius_map: dict[str, int] = {
            "none": self.none,
            "small": self.small,
            "sm": self.small,
            "medium": self.medium,
            "md": self.medium,
            "large": self.large,
            "lg": self.large,
            "full": self.full,
            "pill": self.full,
        }
        if norm in radius_map:
            return radius_map[norm]
        raise KeyError(f"Unknown radius key '{key}'")

    def __iter__(self) -> Iterator[str]:
        yield from ("none", "small", "medium", "large", "full")

    def __len__(self) -> int:
        return 5

    def __getattr__(self, name: str) -> int:
        try:
            return self[name]
        except KeyError:
            raise AttributeError(
                f"'{self.__class__.__name__}' object has no attribute '{name}'"
            ) from None


# ==============================================================================
# Singleton Instances for Global Usage
# ==============================================================================

SURFACES: SurfaceColors = SurfaceColors()
TEXT: TextColors = TextColors()
ACCENTS: AccentColors = AccentColors()
SEVERITY: SeverityColors = SeverityColors()
STATUS: OperationalStatusColors = OperationalStatusColors()

COLORS: ColorPalette = ColorPalette(
    surfaces=SURFACES,
    text=TEXT,
    accents=ACCENTS,
    severity=SEVERITY,
    status=STATUS,
)

SPACING: Spacing = Spacing()
TYPOGRAPHY: Typography = Typography()
METRICS: ComponentMetrics = ComponentMetrics()
RADII: BorderRadius = BorderRadius()
RADIUS: BorderRadius = RADII


__all__ = [
    # Singleton instances
    "SURFACES",
    "TEXT",
    "ACCENTS",
    "SEVERITY",
    "STATUS",
    "COLORS",
    "SPACING",
    "TYPOGRAPHY",
    "METRICS",
    "RADII",
    "RADIUS",
    # Mappings & Helpers
    "SEVERITY_COLORS",
    "OPERATIONAL_STATUS_COLORS",
    "get_severity_color",
    "get_status_color",
    # Palette Constants
    "SURFACE_0",
    "SURFACE_1",
    "SURFACE_2",
    "SURFACE_3",
    "BORDER",
    "TEXT_PRIMARY",
    "TEXT_SECONDARY",
    "ACCENT",
    "ACCENT_FOCUS",
    "SEVERITY_CRITICAL",
    "SEVERITY_HIGH",
    "SEVERITY_MEDIUM",
    "SEVERITY_LOW",
    "SEVERITY_INFO",
    "STATUS_FRESH",
    "STATUS_STALE",
    "STATUS_DEGRADED",
    "STATUS_OFFLINE",
    # Spacing Constants
    "SPACE_0",
    "SPACE_1",
    "SPACE_2",
    "SPACE_3",
    "SPACE_4",
    "SPACE_5",
    "SPACE_6",
    "SPACE_7",
    "SPACE_8",
    "SPACING_BASE",
    "SPACING_SCALE",
    # Component Metrics Constants
    "TABLE_ROW_HEIGHT",
    "TOP_HEADER_HEIGHT",
    "CONTEXTUAL_TOOLBAR_HEIGHT",
    "STATUS_BAR_HEIGHT",
    "COLLAPSED_NAVIGATION_WIDTH",
    "EXPANDED_NAVIGATION_WIDTH",
    "INSPECTOR_PANEL_WIDTH",
    # Radius Constants
    "RADIUS_NONE",
    "RADIUS_SMALL",
    "RADIUS_MEDIUM",
    "RADIUS_LARGE",
    "RADIUS_FULL",
    # Typography Constants
    "FONT_SIZE_SMALL_METADATA",
    "FONT_SIZE_STANDARD_BODY",
    "FONT_SIZE_SECTION_TITLE",
    "FONT_SIZE_MAJOR_HEADING",
    "FONT_SIZE_NUMERIC_METRIC",
    "FONT_WEIGHT_REGULAR",
    "FONT_WEIGHT_MEDIUM",
    "FONT_WEIGHT_SEMIBOLD",
    "FONT_WEIGHT_BOLD",
    "FONT_FAMILY_SANS",
    "FONT_FAMILY_MONO",
    # Classes
    "CaseInsensitiveMapping",
    "SurfaceColors",
    "TextColors",
    "AccentColors",
    "SeverityColors",
    "OperationalStatusColors",
    "ColorPalette",
    "Spacing",
    "Typography",
    "TypographyStyle",
    "FontSizes",
    "FontWeights",
    "FontFamilies",
    "ComponentMetrics",
    "BorderRadius",
]
