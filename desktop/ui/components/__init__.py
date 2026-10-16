"""OSIRIS reusable UI components package."""

from __future__ import annotations

from desktop.ui.components.badges import SeverityBadge, StatusBadge
from desktop.ui.components.cards import MetricCard
from desktop.ui.components.error_banner import ErrorBanner
from desktop.ui.components.inspector_panel import EventInspectorPanel
from desktop.ui.components.process_inspector_panel import ProcessInspectorPanel
from desktop.ui.components.resource_charts import (
    ResourceTrendChartsWidget,
)
from desktop.ui.components.resource_inspector_panel import (
    ResourceInspectorPanel,
)
from desktop.ui.components.resources_summary_cards import (
    ResourcesSummaryCardsFrame,
)
from desktop.ui.components.root_warning_banner import (
    DEFAULT_ROOT_WARNING_TEXT,
    RootWarningBanner,
)
from desktop.ui.components.status_bar import StatusBar

__all__ = [
    "DEFAULT_ROOT_WARNING_TEXT",
    "ErrorBanner",
    "EventInspectorPanel",
    "MetricCard",
    "ProcessInspectorPanel",
    "ResourceInspectorPanel",
    "ResourceTrendChartsWidget",
    "ResourcesSummaryCardsFrame",
    "RootWarningBanner",
    "SeverityBadge",
    "StatusBar",
    "StatusBadge",
]
