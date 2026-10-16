"""Unit tests for OSIRIS reusable semantic badges.

Verifies:
1. Successful instantiation of SeverityBadge and StatusBadge.
2. Every supported semantic value is handled correctly.
3. Case normalization works for all supported values.
4. Canonical human-readable display text is rendered.
5. Correct Qt dynamic properties ('severity', 'status') are set.
6. Dynamic updates update text, properties, and refresh styling.
7. Predictable rejection of invalid string values with ValueError.
8. Predictable rejection of non-string types with TypeError.
9. Invalid updates preserve existing widget state.
10. Stable object names ('SeverityBadge', 'StatusBadge').
11. Text alignment and compact presentation.
12. Semantic QSS selectors and approved token integration.
"""

from __future__ import annotations

from typing import Any

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from desktop.ui import design_tokens, load_stylesheet
from desktop.ui.components import SeverityBadge, StatusBadge
from desktop.ui.components.badges import (
    SeverityBadge as DirectSeverityBadge,
)
from desktop.ui.components.badges import (
    StatusBadge as DirectStatusBadge,
)

# ==============================================================================
# SeverityBadge Tests
# ==============================================================================

SUPPORTED_SEVERITIES = [
    ("Critical", "Critical", "critical"),
    ("High", "High", "high"),
    ("Medium", "Medium", "medium"),
    ("Low", "Low", "low"),
    ("Info", "Info", "info"),
]

SEVERITY_CASE_VARIANTS = [
    ("critical", "Critical", "critical"),
    ("CRITICAL", "Critical", "critical"),
    ("Critical", "Critical", "critical"),
    ("cRiTiCaL", "Critical", "critical"),
    ("  critical  ", "Critical", "critical"),
    ("high", "High", "high"),
    ("HIGH", "High", "high"),
    ("High", "High", "high"),
    ("  High  ", "High", "high"),
    ("medium", "Medium", "medium"),
    ("MEDIUM", "Medium", "medium"),
    ("Medium", "Medium", "medium"),
    ("low", "Low", "low"),
    ("LOW", "Low", "low"),
    ("Low", "Low", "low"),
    ("info", "Info", "info"),
    ("INFO", "Info", "info"),
    ("Info", "Info", "info"),
    ("  info  ", "Info", "info"),
]

INVALID_SEVERITY_STRINGS = [
    "",
    "   ",
    "unknown",
    "fatal",
    "severe",
    "warning",
    "error",
    "critical_alert",
    "notice",
    "debug",
    "123",
]

NON_STRING_VALUES = [
    None,
    123,
    0,
    45.6,
    [],
    {},
    object(),
]


def test_severity_badge_default_instantiation(qapp: QApplication) -> None:
    """SeverityBadge defaults to 'Info' when instantiated without arguments."""
    badge = SeverityBadge()
    assert badge.severity == "Info"
    assert badge.get_severity() == "Info"
    assert badge.text() == "Info"
    assert badge.property("severity") == "info"
    assert badge.severity_key == "info"
    assert badge.objectName() == "SeverityBadge"


def test_severity_badge_direct_import_matches_public_api() -> None:
    """Direct module import matches the public components package export."""
    assert SeverityBadge is DirectSeverityBadge


@pytest.mark.parametrize(
    ("input_val", "expected_canonical", "expected_property"),
    SUPPORTED_SEVERITIES,
)
def test_severity_badge_supported_values(
    qapp: QApplication,
    input_val: str,
    expected_canonical: str,
    expected_property: str,
) -> None:
    """SeverityBadge supports all 5 canonical severity levels."""
    badge = SeverityBadge(input_val)
    assert badge.severity == expected_canonical
    assert badge.get_severity() == expected_canonical
    assert badge.text() == expected_canonical
    assert badge.property("severity") == expected_property
    assert badge.severity_key == expected_property


@pytest.mark.parametrize(
    ("raw_input", "expected_canonical", "expected_property"),
    SEVERITY_CASE_VARIANTS,
)
def test_severity_badge_case_normalization(
    qapp: QApplication,
    raw_input: str,
    expected_canonical: str,
    expected_property: str,
) -> None:
    """SeverityBadge normalizes case and surrounding whitespace cleanly."""
    badge = SeverityBadge(raw_input)
    assert badge.severity == expected_canonical
    assert badge.text() == expected_canonical
    assert badge.property("severity") == expected_property


def test_severity_badge_update_via_property_setter(qapp: QApplication) -> None:
    """Updating severity via property setter updates text and dynamic property."""
    badge = SeverityBadge("Low")
    assert badge.severity == "Low"
    assert badge.text() == "Low"
    assert badge.property("severity") == "low"

    badge.severity = "Critical"
    assert badge.severity == "Critical"
    assert badge.text() == "Critical"
    assert badge.property("severity") == "critical"

    badge.severity = "high"
    assert badge.severity == "High"
    assert badge.text() == "High"
    assert badge.property("severity") == "high"


def test_severity_badge_update_via_method(qapp: QApplication) -> None:
    """Updating severity via set_severity method updates text and dynamic property."""
    badge = SeverityBadge("Info")
    badge.set_severity("Medium")
    assert badge.severity == "Medium"
    assert badge.text() == "Medium"
    assert badge.property("severity") == "medium"


@pytest.mark.parametrize("invalid_str", INVALID_SEVERITY_STRINGS)
def test_severity_badge_rejects_invalid_strings(
    qapp: QApplication,
    invalid_str: str,
) -> None:
    """SeverityBadge predictably raises ValueError for unsupported string values."""
    with pytest.raises(ValueError, match="Invalid severity"):
        SeverityBadge(invalid_str)


@pytest.mark.parametrize("invalid_val", NON_STRING_VALUES)
def test_severity_badge_rejects_non_string_types(
    qapp: QApplication,
    invalid_val: Any,
) -> None:
    """SeverityBadge predictably raises TypeError for non-string input values."""
    with pytest.raises(TypeError, match="Severity must be a string"):
        SeverityBadge(invalid_val)


def test_severity_badge_invalid_update_preserves_state(qapp: QApplication) -> None:
    """Failed updates leave the previous valid severity and styling intact."""
    badge = SeverityBadge("Critical")
    with pytest.raises(ValueError):
        badge.severity = "bogus_severity"

    assert badge.severity == "Critical"
    assert badge.text() == "Critical"
    assert badge.property("severity") == "critical"

    with pytest.raises(TypeError):
        badge.set_severity(None)  # type: ignore[arg-type]

    assert badge.severity == "Critical"
    assert badge.text() == "Critical"
    assert badge.property("severity") == "critical"


def test_severity_badge_object_name_is_stable(qapp: QApplication) -> None:
    """SeverityBadge sets and maintains a stable object name."""
    badge = SeverityBadge("High")
    assert badge.objectName() == "SeverityBadge"


def test_severity_badge_text_alignment(qapp: QApplication) -> None:
    """SeverityBadge text is centered horizontally and vertically."""
    badge = SeverityBadge("Critical")
    assert int(badge.alignment()) & int(Qt.AlignmentFlag.AlignCenter)


def test_severity_badge_qss_integration(qapp: QApplication) -> None:
    """SeverityBadge uses token-driven selectors defined in the rendered stylesheet."""
    qss = load_stylesheet()
    # Ensure badge selector exists
    assert "QLabel#SeverityBadge" in qss

    # Ensure token colors are present for all severities
    assert design_tokens.SEVERITY_CRITICAL in qss
    assert design_tokens.SEVERITY_HIGH in qss
    assert design_tokens.SEVERITY_MEDIUM in qss
    assert design_tokens.SEVERITY_LOW in qss
    assert design_tokens.SEVERITY_INFO in qss


# ==============================================================================
# StatusBadge Tests
# ==============================================================================

SUPPORTED_STATUSES = [
    ("Fresh", "Fresh", "fresh"),
    ("Stale", "Stale", "stale"),
    ("Degraded", "Degraded", "degraded"),
    ("Offline", "Offline", "offline"),
]

STATUS_CASE_VARIANTS = [
    ("fresh", "Fresh", "fresh"),
    ("FRESH", "Fresh", "fresh"),
    ("Fresh", "Fresh", "fresh"),
    ("fReSh", "Fresh", "fresh"),
    ("  fresh  ", "Fresh", "fresh"),
    ("stale", "Stale", "stale"),
    ("STALE", "Stale", "stale"),
    ("Stale", "Stale", "stale"),
    ("degraded", "Degraded", "degraded"),
    ("DEGRADED", "Degraded", "degraded"),
    ("Degraded", "Degraded", "degraded"),
    ("offline", "Offline", "offline"),
    ("OFFLINE", "Offline", "offline"),
    ("Offline", "Offline", "offline"),
    ("  offline  ", "Offline", "offline"),
]

INVALID_STATUS_STRINGS = [
    "",
    "   ",
    "unknown",
    "online",
    "active",
    "dead",
    "alive",
    "healthy",
    "error",
    "running",
]


def test_status_badge_default_instantiation(qapp: QApplication) -> None:
    """StatusBadge defaults to 'Offline' when instantiated without arguments."""
    badge = StatusBadge()
    assert badge.status == "Offline"
    assert badge.get_status() == "Offline"
    assert badge.text() == "Offline"
    assert badge.property("status") == "offline"
    assert badge.status_key == "offline"
    assert badge.objectName() == "StatusBadge"


def test_status_badge_direct_import_matches_public_api() -> None:
    """Direct module import matches the public components package export."""
    assert StatusBadge is DirectStatusBadge


@pytest.mark.parametrize(
    ("input_val", "expected_canonical", "expected_property"),
    SUPPORTED_STATUSES,
)
def test_status_badge_supported_values(
    qapp: QApplication,
    input_val: str,
    expected_canonical: str,
    expected_property: str,
) -> None:
    """StatusBadge supports all 4 canonical operational status levels."""
    badge = StatusBadge(input_val)
    assert badge.status == expected_canonical
    assert badge.get_status() == expected_canonical
    assert badge.text() == expected_canonical
    assert badge.property("status") == expected_property
    assert badge.status_key == expected_property


@pytest.mark.parametrize(
    ("raw_input", "expected_canonical", "expected_property"),
    STATUS_CASE_VARIANTS,
)
def test_status_badge_case_normalization(
    qapp: QApplication,
    raw_input: str,
    expected_canonical: str,
    expected_property: str,
) -> None:
    """StatusBadge normalizes case and surrounding whitespace cleanly."""
    badge = StatusBadge(raw_input)
    assert badge.status == expected_canonical
    assert badge.text() == expected_canonical
    assert badge.property("status") == expected_property


def test_status_badge_update_via_property_setter(qapp: QApplication) -> None:
    """Updating status via property setter updates text and dynamic property."""
    badge = StatusBadge("Offline")
    assert badge.status == "Offline"

    badge.status = "Fresh"
    assert badge.status == "Fresh"
    assert badge.text() == "Fresh"
    assert badge.property("status") == "fresh"

    badge.status = "degraded"
    assert badge.status == "Degraded"
    assert badge.text() == "Degraded"
    assert badge.property("status") == "degraded"


def test_status_badge_update_via_method(qapp: QApplication) -> None:
    """Updating status via set_status method updates text and dynamic property."""
    badge = StatusBadge("Offline")
    badge.set_status("Stale")
    assert badge.status == "Stale"
    assert badge.text() == "Stale"
    assert badge.property("status") == "stale"


@pytest.mark.parametrize("invalid_str", INVALID_STATUS_STRINGS)
def test_status_badge_rejects_invalid_strings(
    qapp: QApplication,
    invalid_str: str,
) -> None:
    """StatusBadge predictably raises ValueError for unsupported string values."""
    with pytest.raises(ValueError, match="Invalid status"):
        StatusBadge(invalid_str)


@pytest.mark.parametrize("invalid_val", NON_STRING_VALUES)
def test_status_badge_rejects_non_string_types(
    qapp: QApplication,
    invalid_val: Any,
) -> None:
    """StatusBadge predictably raises TypeError for non-string input values."""
    with pytest.raises(TypeError, match="Status must be a string"):
        StatusBadge(invalid_val)


def test_status_badge_invalid_update_preserves_state(qapp: QApplication) -> None:
    """Failed updates leave the previous valid status intact."""
    badge = StatusBadge("Fresh")
    with pytest.raises(ValueError):
        badge.status = "invalid_status"

    assert badge.status == "Fresh"
    assert badge.text() == "Fresh"
    assert badge.property("status") == "fresh"

    with pytest.raises(TypeError):
        badge.set_status(None)  # type: ignore[arg-type]

    assert badge.status == "Fresh"
    assert badge.text() == "Fresh"
    assert badge.property("status") == "fresh"


def test_status_badge_object_name_is_stable(qapp: QApplication) -> None:
    """StatusBadge sets and maintains a stable object name."""
    badge = StatusBadge("Fresh")
    assert badge.objectName() == "StatusBadge"


def test_status_badge_text_alignment(qapp: QApplication) -> None:
    """StatusBadge text is centered horizontally and vertically."""
    badge = StatusBadge("Fresh")
    assert int(badge.alignment()) & int(Qt.AlignmentFlag.AlignCenter)


def test_status_badge_qss_integration(qapp: QApplication) -> None:
    """StatusBadge uses token-driven selectors defined in the rendered stylesheet."""
    qss = load_stylesheet()
    assert "QLabel#StatusBadge" in qss
    assert design_tokens.STATUS_FRESH in qss
    assert design_tokens.STATUS_STALE in qss
    assert design_tokens.STATUS_DEGRADED in qss
    assert design_tokens.STATUS_OFFLINE in qss
