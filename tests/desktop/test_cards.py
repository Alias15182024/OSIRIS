"""Unit tests for OSIRIS reusable MetricCard component.

Verifies:
1. Successful instantiation with various title, value, and detail combinations.
2. Title, value, and detail display correctly.
3. No-detail behavior: absent detail is hidden and never displays 'None'.
4. Value updates via property and method.
5. Title updates via property and method.
6. Detail updates and clearing via set_detail, clear_detail, and detail setter.
7. Expected child labels and semantic object names.
8. Sensible layout and widget structure using design token spacing.
9. Stable outer object name ('MetricCard').
10. Style sheet selectors and token substitution for MetricCard.
"""

from __future__ import annotations

from typing import Any

import pytest
from PySide6.QtWidgets import QApplication, QLabel, QVBoxLayout

from desktop.ui import design_tokens, load_stylesheet
from desktop.ui.components import MetricCard
from desktop.ui.components.cards import MetricCard as DirectMetricCard


def test_metric_card_direct_import_matches_public_api() -> None:
    """Direct module import matches the public components package export."""
    assert MetricCard is DirectMetricCard


def test_metric_card_instantiation_full(qapp: QApplication) -> None:
    """MetricCard correctly displays title, value, and detail."""
    card = MetricCard(
        title="Active Incidents",
        value=142,
        detail="3 critical in last 1h",
    )
    assert card.objectName() == "MetricCard"
    assert card.title == "Active Incidents"
    assert card.get_title() == "Active Incidents"
    assert card.value == "142"
    assert card.get_value() == "142"
    assert card.detail == "3 critical in last 1h"
    assert card.get_detail() == "3 critical in last 1h"

    # Child label assertions
    assert card.title_label.text() == "Active Incidents"
    assert card.value_label.text() == "142"
    assert card.detail_label.text() == "3 critical in last 1h"
    assert card.detail_label.isHidden() is False

    card.show()
    assert card.detail_label.isVisible() is True
    card.close()


def test_metric_card_instantiation_no_detail(qapp: QApplication) -> None:
    """MetricCard without detail hides detail label and never displays 'None'."""
    card = MetricCard(title="Total Endpoints", value="1,024")
    assert card.title == "Total Endpoints"
    assert card.value == "1,024"
    assert card.detail is None
    assert card.get_detail() is None

    # Detail label must be hidden and contain empty string
    assert card.detail_label.text() == ""
    assert "None" not in card.detail_label.text()
    assert card.detail_label.isHidden() is True

    card.show()
    assert card.detail_label.isVisible() is False
    card.close()


@pytest.mark.parametrize("absent_detail", [None, "", "   ", "None", "none", "NONE"])
def test_metric_card_absent_detail_clean_handling(
    qapp: QApplication,
    absent_detail: Any,
) -> None:
    """MetricCard suppresses detail for None, empty, whitespace, or 'None' strings."""
    card = MetricCard(title="Telemetry Events", value="45.2k", detail=absent_detail)
    assert card.detail is None
    assert card.detail_label.text() == ""
    assert card.detail_label.isHidden() is True


def test_metric_card_value_updates(qapp: QApplication) -> None:
    """MetricCard value can be updated via property setter or set_value method."""
    card = MetricCard(title="CPU Usage", value="24%")
    assert card.value == "24%"
    assert card.value_label.text() == "24%"

    # Update via property setter with integer
    card.value = 88
    assert card.value == "88"
    assert card.value_label.text() == "88"

    # Update via set_value with float
    card.set_value(99.4)
    assert card.value == "99.4"
    assert card.value_label.text() == "99.4"

    # Update via set_value with formatted string
    card.set_value("100% (saturated)")
    assert card.value == "100% (saturated)"
    assert card.value_label.text() == "100% (saturated)"


def test_metric_card_title_updates(qapp: QApplication) -> None:
    """MetricCard title can be updated via property setter or set_title method."""
    card = MetricCard(title="Initial Title", value=10)
    assert card.title == "Initial Title"
    assert card.title_label.text() == "Initial Title"

    card.title = "Updated Title"
    assert card.title == "Updated Title"
    assert card.title_label.text() == "Updated Title"

    card.set_title("Method Updated")
    assert card.title == "Method Updated"
    assert card.title_label.text() == "Method Updated"


def test_metric_card_detail_updates_and_clearing(qapp: QApplication) -> None:
    """MetricCard detail can be added, updated, and cleared dynamically."""
    card = MetricCard(title="Host Count", value=50)
    assert card.detail is None
    assert card.detail_label.isHidden() is True

    # Set detail
    card.set_detail("42 online")
    assert card.detail == "42 online"
    assert card.detail_label.text() == "42 online"
    assert card.detail_label.isHidden() is False

    # Update detail via property
    card.detail = "48 online (+6)"
    assert card.detail == "48 online (+6)"
    assert card.detail_label.text() == "48 online (+6)"
    assert card.detail_label.isHidden() is False

    # Clear detail via clear_detail
    card.clear_detail()
    assert card.detail is None
    assert card.detail_label.text() == ""
    assert card.detail_label.isHidden() is True

    # Set detail again
    card.detail = "Restored"
    assert card.detail == "Restored"
    assert card.detail_label.isHidden() is False

    # Clear via None setter
    card.detail = None
    assert card.detail is None
    assert card.detail_label.text() == ""
    assert card.detail_label.isHidden() is True


def test_metric_card_child_labels_and_object_names(qapp: QApplication) -> None:
    """MetricCard child labels have semantic object names and hierarchy properties."""
    card = MetricCard(title="Alerts", value=12, detail="Critical only")

    assert card.objectName() == "MetricCard"
    assert card.title_label.objectName() == "MetricCardTitle"
    assert card.value_label.objectName() == "MetricCardValue"
    assert card.detail_label.objectName() == "MetricCardDetail"

    assert card.findChild(QLabel, "MetricCardTitle") is card.title_label
    assert card.findChild(QLabel, "MetricCardValue") is card.value_label
    assert card.findChild(QLabel, "MetricCardDetail") is card.detail_label


def test_metric_card_layout_structure(qapp: QApplication) -> None:
    """MetricCard uses a vertical layout with token-governed margins and spacing."""
    card = MetricCard(title="Memory", value="8 GB")
    layout = card.layout()

    assert layout is not None
    assert isinstance(layout, QVBoxLayout)
    assert layout.count() == 3

    # Layout item order: title, value, detail
    item0 = layout.itemAt(0)
    item1 = layout.itemAt(1)
    item2 = layout.itemAt(2)
    assert item0 is not None and item0.widget() is card.title_label
    assert item1 is not None and item1.widget() is card.value_label
    assert item2 is not None and item2.widget() is card.detail_label

    # Margins and spacing align with tokens
    margins = layout.contentsMargins()
    assert margins.left() == design_tokens.SPACE_3
    assert margins.top() == design_tokens.SPACE_3
    assert margins.right() == design_tokens.SPACE_3
    assert margins.bottom() == design_tokens.SPACE_3
    assert layout.spacing() == design_tokens.SPACE_1


def test_metric_card_displays_caller_supplied_values_faithfully(
    qapp: QApplication,
) -> None:
    """MetricCard displays exact caller supplied values without inventing formatting."""
    test_values = [
        0,
        "0",
        "0.00",
        -5,
        "N/A",
        "--",
        "99.999%",
        "1,234,567",
        "10.0.0.1",
    ]
    for val in test_values:
        card = MetricCard(title="Test", value=val)
        assert card.value == str(val)
        assert card.value_label.text() == str(val)


def test_metric_card_qss_styling_applied(qapp: QApplication) -> None:
    """MetricCard and child labels have deliberate selectors in the stylesheet."""
    qss = load_stylesheet()
    assert "QFrame#MetricCard" in qss
    assert "QLabel#MetricCardTitle" in qss
    assert "QLabel#MetricCardValue" in qss
    assert "QLabel#MetricCardDetail" in qss

    # Approved tokens present in card rules
    assert design_tokens.SURFACE_1 in qss
    assert design_tokens.BORDER in qss
    assert design_tokens.FONT_FAMILY_MONO in qss
    assert f"{design_tokens.FONT_SIZE_NUMERIC_METRIC}px" in qss


