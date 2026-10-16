"""OSIRIS Resource Utilization Summary Cards Component.

Provides ResourcesSummaryCardsFrame, a compact QFrame component hosting four
MetricCard widgets that present the latest meaningful resource metrics from
the currently displayed ResourceSnapshotCollection:
1. Latest CPU utilization percentage
2. Latest Memory utilization percentage
3. Latest Disk utilization percentage
4. Latest Memory used versus memory total
"""

from __future__ import annotations

from collections.abc import Sequence

from PySide6.QtWidgets import QFrame, QHBoxLayout, QWidget

from desktop.client.models import ResourceSnapshot, ResourceSnapshotCollection
from desktop.models.resources_model import (
    EMPTY_PLACEHOLDER,
    find_latest_resource_snapshot,
    format_bytes,
    format_percent,
)
from desktop.ui.components.cards import MetricCard
from desktop.ui.design_tokens import SPACE_3


class ResourcesSummaryCardsFrame(QFrame):
    """Container frame presenting four metric cards for system resource telemetry.

    Derives all displayed metrics from the newest ResourceSnapshot in the active
    collection without fabricating placeholder values, averaging percentages,
    or synthesizing missing measurements.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize ResourcesSummaryCardsFrame with 4 MetricCard instances."""
        super().__init__(parent)
        self.setObjectName("ResourcesSummaryCardsFrame")

        self._current_snapshot: ResourceSnapshot | None = None

        self._cpu_card = MetricCard(
            title="CPU Utilization",
            value=EMPTY_PLACEHOLDER,
            parent=self,
        )
        self._memory_card = MetricCard(
            title="Memory Utilization",
            value=EMPTY_PLACEHOLDER,
            parent=self,
        )
        self._disk_card = MetricCard(
            title="Disk Utilization",
            value=EMPTY_PLACEHOLDER,
            parent=self,
        )
        self._memory_used_total_card = MetricCard(
            title="Memory In-Use / Total",
            value=EMPTY_PLACEHOLDER,
            parent=self,
        )

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(SPACE_3)
        layout.addWidget(self._cpu_card, 1)
        layout.addWidget(self._memory_card, 1)
        layout.addWidget(self._disk_card, 1)
        layout.addWidget(self._memory_used_total_card, 1)

    # -----------------------------------------------------------------------
    # Public Accessors
    # -----------------------------------------------------------------------

    @property
    def current_snapshot(self) -> ResourceSnapshot | None:
        """Return the current snapshot represented by the summary cards."""
        return self._current_snapshot

    @property
    def cpu_card(self) -> MetricCard:
        """Return the CPU utilization MetricCard."""
        return self._cpu_card

    @property
    def memory_card(self) -> MetricCard:
        """Return the memory utilization MetricCard."""
        return self._memory_card

    @property
    def disk_card(self) -> MetricCard:
        """Return the disk utilization MetricCard."""
        return self._disk_card

    @property
    def memory_used_total_card(self) -> MetricCard:
        """Return the memory used vs total MetricCard."""
        return self._memory_used_total_card

    @property
    def memory_allocation_card(self) -> MetricCard:
        """Alias for memory_used_total_card."""
        return self._memory_used_total_card

    # -----------------------------------------------------------------------
    # Snapshot Mutation API
    # -----------------------------------------------------------------------

    def set_snapshot(self, snapshot: ResourceSnapshot | None) -> None:
        """Update displayed summary card values from the given snapshot.

        Args:
            snapshot: Validated ResourceSnapshot instance or None to reset.
        """
        self._current_snapshot = snapshot

        if snapshot is None:
            self._cpu_card.set_value(EMPTY_PLACEHOLDER)
            self._cpu_card.set_detail(None)
            self._memory_card.set_value(EMPTY_PLACEHOLDER)
            self._memory_card.set_detail(None)
            self._disk_card.set_value(EMPTY_PLACEHOLDER)
            self._disk_card.set_detail(None)
            self._memory_used_total_card.set_value(EMPTY_PLACEHOLDER)
            self._memory_used_total_card.set_detail(None)
            return

        # 1. CPU %
        self._cpu_card.set_value(format_percent(snapshot.cpu_percent))
        self._cpu_card.set_detail("Latest snapshot")

        # 2. Memory %
        self._memory_card.set_value(format_percent(snapshot.memory_percent))
        self._memory_card.set_detail("Latest snapshot")

        # 3. Disk %
        self._disk_card.set_value(format_percent(snapshot.disk_usage_percent))
        self._disk_card.set_detail("Latest snapshot")

        # 4. Memory Used vs Total
        mem_used = snapshot.memory_used
        mem_total = snapshot.memory_total
        if mem_used is not None and mem_total is not None:
            val_str = f"{format_bytes(mem_used)} / {format_bytes(mem_total)}"
        elif mem_used is not None and mem_total is None:
            val_str = f"{format_bytes(mem_used)} / {EMPTY_PLACEHOLDER}"
        elif mem_used is None and mem_total is not None:
            val_str = f"{EMPTY_PLACEHOLDER} / {format_bytes(mem_total)}"
        else:
            val_str = EMPTY_PLACEHOLDER

        self._memory_used_total_card.set_value(val_str)
        self._memory_used_total_card.set_detail("Latest snapshot")

    def update_from_collection(
        self, collection: ResourceSnapshotCollection | None
    ) -> None:
        """Extract the latest snapshot from a collection and update cards.

        Args:
            collection: ResourceSnapshotCollection or None to reset.
        """
        if collection is None or not collection.items:
            self.set_snapshot(None)
            return
        latest = find_latest_resource_snapshot(collection.items)
        self.set_snapshot(latest)

    def update_from_snapshots(
        self, snapshots: Sequence[ResourceSnapshot] | None
    ) -> None:
        """Extract the latest snapshot from a sequence and update cards.

        Args:
            snapshots: Sequence of ResourceSnapshot instances or None to reset.
        """
        if not snapshots:
            self.set_snapshot(None)
            return
        latest = find_latest_resource_snapshot(snapshots)
        self.set_snapshot(latest)

    def clear(self) -> None:
        """Reset all cards to neutral placeholders and clear current snapshot."""
        self.set_snapshot(None)


__all__ = [
    "ResourcesSummaryCardsFrame",
]
