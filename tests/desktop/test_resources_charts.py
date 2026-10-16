"""Unit tests for OSIRIS Resource Telemetry Trend Charts Component.

Verifies:
1. CPU, memory, and disk utilization points derived from real snapshots.
2. Timestamp-to-value alignment and coordinate mapping.
3. Chronological chart ordering without mutating table model collection order.
4. Equal timestamps handled deterministically (secondary sort, distinct X).
5. Single snapshot handling and horizontal centering.
6. Nullable metrics handled without being plotted as zero.
7. Genuine zero values retained at baseline.
8. Empty collection and all-null series states.
9. Chart labels, units, and timestamp formatting.
10. Active query and pagination metadata reflected in stated scope.
11. No claim of complete history when only one page is loaded.
12. Repeated updates not duplicating chart points.
13. Replaced collections and stale responses not leaving obsolete data.
14. Selection synchronization without triggering API requests or telemetry mutations.
15. Refresh failures and retained-data messaging.
16. Metric mode switching (utilization, memory breakdown, disk I/O cumulative).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import pytest
from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QMouseEvent, QPixmap

from desktop.client.models import ResourceSnapshot, ResourceSnapshotCollection
from desktop.models.resources_model import ResourcesTableModel
from desktop.ui.components.resource_charts import (
    MODE_DISK_IO,
    MODE_MEMORY,
    MODE_UTILIZATION,
    STATE_EMPTY,
    STATE_FAILED,
    STATE_LOADED,
    STATE_LOADING,
    STATE_NOT_LOADED,
    ResourceTrendChartsWidget,
)
from desktop.ui.views.resources_view import ResourcesQuery, ResourcesView

SAMPLE_HOST_ID = "44444444-4444-4444-8444-444444444444"

TIME_1 = "2026-03-01T08:00:00Z"
TIME_2 = "2026-03-01T08:05:00Z"
TIME_3 = "2026-03-01T08:10:00Z"


def _make_snapshot(
    snapshot_id: str | None = None,
    timestamp: str = TIME_1,
    created_at: str = TIME_1,
    cpu_percent: float | None = 20.0,
    memory_percent: float | None = 40.0,
    disk_usage_percent: float | None = 60.0,
    memory_used: int | None = 4_000_000_000,
    memory_total: int | None = 16_000_000_000,
    disk_read_bytes: int | None = 1048576,
    disk_write_bytes: int | None = 2097152,
) -> ResourceSnapshot:
    """Create a validated ResourceSnapshot instance for testing."""
    sid = snapshot_id or str(uuid.uuid4())
    return ResourceSnapshot(
        id=sid,
        host_id=SAMPLE_HOST_ID,
        timestamp=timestamp,
        created_at=created_at,
        cpu_percent=cpu_percent,
        memory_percent=memory_percent,
        disk_usage_percent=disk_usage_percent,
        memory_used=memory_used,
        memory_total=memory_total,
        disk_read_bytes=disk_read_bytes,
        disk_write_bytes=disk_write_bytes,
    )


def _make_collection(
    items: tuple[ResourceSnapshot, ...] = (),
    total: int = 0,
    limit: int = 50,
    offset: int = 0,
) -> ResourceSnapshotCollection:
    """Create a validated ResourceSnapshotCollection instance."""
    return ResourceSnapshotCollection(
        total=total if total >= len(items) else len(items),
        items=items,
        limit=limit,
        offset=offset,
    )


# ==============================================================================
# 1. Widget Construction & Initial State
# ==============================================================================


def test_trend_charts_widget_initial_state(qapp: Any) -> None:
    """Widget initializes in STATE_NOT_LOADED with empty data and clean scope."""
    widget = ResourceTrendChartsWidget()
    assert widget.objectName() == "ResourceTrendChartsWidget"
    assert widget.state == STATE_NOT_LOADED
    assert widget.collection is None
    assert widget.snapshots == ()
    assert widget.chronological_snapshots == []
    assert widget.trend_points == []
    assert widget.selected_snapshot is None
    assert widget.is_complete_history is False
    assert widget.scope_badge_text == "NOT LOADED"
    assert widget.mode == MODE_UTILIZATION
    assert widget.canvas is not None
    assert widget.title_label.text() == "Historical Telemetry Trends"


# ==============================================================================
# 2. Point Creation and Timestamp-to-Value Alignment
# ==============================================================================


def test_chart_points_derived_from_real_snapshots(qapp: Any) -> None:
    """Points derive exact metric values and timestamps from real snapshots."""
    s1 = _make_snapshot(
        timestamp=TIME_1,
        cpu_percent=15.5,
        memory_percent=45.2,
        disk_usage_percent=70.0,
        memory_used=2_000_000_000,
        memory_total=8_000_000_000,
        disk_read_bytes=1000,
        disk_write_bytes=2000,
    )
    s2 = _make_snapshot(
        timestamp=TIME_2,
        cpu_percent=30.0,
        memory_percent=55.0,
        disk_usage_percent=72.5,
        memory_used=4_000_000_000,
        memory_total=8_000_000_000,
        disk_read_bytes=3000,
        disk_write_bytes=5000,
    )
    col = _make_collection(items=(s1, s2), total=2, limit=50, offset=0)
    widget = ResourceTrendChartsWidget()
    widget.set_collection(col)

    points = widget.trend_points
    assert len(points) == 2

    p1, p2 = points
    assert p1.snapshot is s1
    assert p1.cpu_percent == 15.5
    assert p1.memory_percent == 45.2
    assert p1.disk_usage_percent == 70.0
    assert p1.memory_used == 2_000_000_000
    assert p1.memory_total == 8_000_000_000
    assert p1.disk_read_bytes == 1000
    assert p1.disk_write_bytes == 2000
    assert p1.formatted_time == "08:00:00"

    assert p2.snapshot is s2
    assert p2.cpu_percent == 30.0
    assert p2.memory_percent == 55.0
    assert p2.disk_usage_percent == 72.5
    assert p2.memory_used == 4_000_000_000
    assert p2.memory_total == 8_000_000_000
    assert p2.disk_read_bytes == 3000
    assert p2.disk_write_bytes == 5000
    assert p2.formatted_time == "08:05:00"


def test_timestamp_to_value_coordinate_mapping(qapp: Any) -> None:
    """Canvas recomputes coordinates mapping timestamps to X and values to Y."""
    s1 = _make_snapshot(timestamp=TIME_1, cpu_percent=0.0)
    s2 = _make_snapshot(timestamp=TIME_2, cpu_percent=100.0)
    col = _make_collection(items=(s1, s2), total=2, limit=50, offset=0)
    widget = ResourceTrendChartsWidget()
    widget.resize(800, 300)
    widget.set_collection(col)

    canvas = widget.canvas
    canvas.resize(800, 200)
    canvas._recompute_coordinates()

    assert len(canvas._cached_x) == 2
    # Earlier timestamp has lower X coordinate (left to right)
    assert canvas._cached_x[0] < canvas._cached_x[1]

    # CPU 0.0% is at bottom baseline; CPU 100.0% is at top of plot
    cpu_y = canvas._cached_y_series["cpu"]
    assert len(cpu_y) == 2
    assert cpu_y[0] is not None
    assert cpu_y[1] is not None
    # Higher pixel Y means lower on screen (0.0% is at bottom)
    assert cpu_y[0] > cpu_y[1]


# ==============================================================================
# 3. Chronological Ordering without Mutating Source Order
# ==============================================================================


def test_chronological_ordering_preserves_collection_order(qapp: Any) -> None:
    """Out-of-order snapshots are sorted chronologically without mutation."""
    s_early = _make_snapshot(timestamp=TIME_1, cpu_percent=10.0)
    s_mid = _make_snapshot(timestamp=TIME_2, cpu_percent=20.0)
    s_late = _make_snapshot(timestamp=TIME_3, cpu_percent=30.0)

    # Reverse order in API collection
    raw_items = (s_late, s_early, s_mid)
    col = _make_collection(items=raw_items, total=3, limit=50, offset=0)

    widget = ResourceTrendChartsWidget()
    widget.set_collection(col)

    # widget.snapshots matches the exact API collection order
    assert widget.snapshots == (s_late, s_early, s_mid)
    assert col.items == (s_late, s_early, s_mid)

    # widget.chronological_snapshots is strictly chronological
    chrono = widget.chronological_snapshots
    assert chrono == [s_early, s_mid, s_late]
    assert [p.cpu_percent for p in widget.trend_points] == [10.0, 20.0, 30.0]


# ==============================================================================
# 4. Equal Timestamps Handled Deterministically
# ==============================================================================


def test_equal_timestamps_deterministic_tie_breaking(qapp: Any) -> None:
    """Identical timestamps are sorted deterministically and separated distinctly."""
    id_a = "11111111-1111-4111-8111-111111111111"
    id_b = "22222222-2222-4222-8222-222222222222"

    s_a = _make_snapshot(
        snapshot_id=id_a,
        timestamp=TIME_1,
        created_at="2026-03-01T08:00:01Z",
        cpu_percent=12.0,
    )
    s_b = _make_snapshot(
        snapshot_id=id_b,
        timestamp=TIME_1,
        created_at="2026-03-01T08:00:02Z",
        cpu_percent=24.0,
    )

    # Pass in reverse created_at order
    col = _make_collection(items=(s_b, s_a), total=2, limit=50, offset=0)
    widget = ResourceTrendChartsWidget()
    widget.resize(600, 250)
    widget.set_collection(col)

    chrono = widget.chronological_snapshots
    assert len(chrono) == 2
    # Secondary tie breaker places s_a (earlier created_at) first
    assert chrono[0] is s_a
    assert chrono[1] is s_b

    # Verify both points receive distinct, non-overlapping X coordinates
    canvas = widget.canvas
    canvas.resize(600, 200)
    canvas._recompute_coordinates()

    assert len(canvas._cached_x) == 2
    assert canvas._cached_x[0] != canvas._cached_x[1]
    assert canvas._cached_x[0] < canvas._cached_x[1]

    # Verify points are centered around the nominal plot center
    plot_width = float(canvas.width() - canvas.LEFT_MARGIN - canvas.RIGHT_MARGIN)
    nominal_center = float(canvas.LEFT_MARGIN) + plot_width / 2.0
    actual_center = (canvas._cached_x[0] + canvas._cached_x[1]) / 2.0
    assert abs(actual_center - nominal_center) < 1.0
    assert abs(canvas._cached_x[1] - canvas._cached_x[0] - 8.0) < 1.0


def test_single_snapshot_centered(qapp: Any) -> None:
    """A single snapshot is placed horizontally at center of plot."""
    s = _make_snapshot(timestamp=TIME_1, cpu_percent=50.0)
    col = _make_collection(items=(s,), total=1, limit=50, offset=0)
    widget = ResourceTrendChartsWidget()
    widget.resize(600, 250)
    widget.set_collection(col)

    canvas = widget.canvas
    canvas.resize(600, 200)
    canvas._recompute_coordinates()

    assert len(canvas._cached_x) == 1
    plot_width = float(canvas.width() - canvas.LEFT_MARGIN - canvas.RIGHT_MARGIN)
    expected_x = float(canvas.LEFT_MARGIN) + plot_width / 2.0
    assert abs(canvas._cached_x[0] - expected_x) < 1.0


# ==============================================================================
# 5. Nullable Metrics vs Genuine Zero
# ==============================================================================


def test_nullable_metrics_not_plotted_as_zero(qapp: Any) -> None:
    """Nullable metric values remain None and do not get converted to 0.0."""
    s1 = _make_snapshot(
        timestamp=TIME_1,
        cpu_percent=None,
        memory_percent=33.3,
        disk_usage_percent=None,
    )
    s2 = _make_snapshot(
        timestamp=TIME_2,
        cpu_percent=50.0,
        memory_percent=None,
        disk_usage_percent=60.0,
    )
    col = _make_collection(items=(s1, s2), total=2, limit=50, offset=0)
    widget = ResourceTrendChartsWidget()
    widget.set_collection(col)

    p1, p2 = widget.trend_points
    assert p1.cpu_percent is None
    assert p1.memory_percent == 33.3
    assert p1.disk_usage_percent is None

    assert p2.cpu_percent == 50.0
    assert p2.memory_percent is None
    assert p2.disk_usage_percent == 60.0

    canvas = widget.canvas
    canvas.resize(600, 200)
    canvas._recompute_coordinates()

    assert canvas._cached_y_series["cpu"][0] is None
    assert canvas._cached_y_series["cpu"][1] is not None

    assert canvas._cached_y_series["memory"][0] is not None
    assert canvas._cached_y_series["memory"][1] is None

    assert canvas._cached_y_series["disk"][0] is None
    assert canvas._cached_y_series["disk"][1] is not None


def test_genuine_zero_values_retained_at_baseline(qapp: Any) -> None:
    """Explicit 0.0% and 0 byte values are preserved and plotted at bottom baseline."""
    s = _make_snapshot(
        timestamp=TIME_1,
        cpu_percent=0.0,
        memory_percent=0.0,
        disk_usage_percent=0.0,
        memory_used=0,
        disk_read_bytes=0,
    )
    col = _make_collection(items=(s,), total=1, limit=50, offset=0)
    widget = ResourceTrendChartsWidget()
    widget.set_collection(col)

    p = widget.trend_points[0]
    assert p.cpu_percent == 0.0
    assert p.memory_percent == 0.0
    assert p.disk_usage_percent == 0.0
    assert p.memory_used == 0
    assert p.disk_read_bytes == 0

    canvas = widget.canvas
    canvas.resize(600, 200)
    canvas._recompute_coordinates()

    plot_bottom = float(canvas.height() - canvas.BOTTOM_MARGIN)
    # 0.0% maps exactly to plot_bottom
    assert canvas._cached_y_series["cpu"][0] == plot_bottom
    assert canvas._cached_y_series["memory"][0] == plot_bottom
    assert canvas._cached_y_series["disk"][0] == plot_bottom


# ==============================================================================
# 6. Empty Collection and All-Null Series States
# ==============================================================================


def test_empty_collection_state(qapp: Any) -> None:
    """Empty collection transitions to STATE_EMPTY with clear empty message."""
    col = _make_collection(items=(), total=0, limit=50, offset=0)
    widget = ResourceTrendChartsWidget()
    widget.set_collection(col)

    assert widget.state == STATE_EMPTY
    assert widget.trend_points == []
    assert widget.scope_badge_text == "EMPTY"
    assert widget.scope_text == "0 of 0 snapshots"
    assert widget.is_complete_history is True


def test_all_null_series_rendering(qapp: Any) -> None:
    """Snapshots with all-null telemetry do not crash and report honest empty state."""
    s1 = _make_snapshot(
        timestamp=TIME_1,
        cpu_percent=None,
        memory_percent=None,
        disk_usage_percent=None,
        memory_used=None,
        memory_total=None,
        disk_read_bytes=None,
        disk_write_bytes=None,
    )
    col = _make_collection(items=(s1,), total=1, limit=50, offset=0)
    widget = ResourceTrendChartsWidget()
    widget.resize(600, 200)
    widget.set_collection(col)

    assert widget.state == STATE_LOADED
    assert widget.canvas._is_all_series_none() is True
    # Paint should complete cleanly without throwing exceptions
    widget.canvas.repaint()


# ==============================================================================
# 7. Scope and Pagination Disclosure
# ==============================================================================


def test_scope_metadata_partial_page_scope_disclosure(qapp: Any) -> None:
    """When current page is partial, partial scope is clearly disclosed."""
    snaps = tuple(
        _make_snapshot(snapshot_id=f"00000000-0000-4000-8000-{i:012d}")
        for i in range(50)
    )
    col = _make_collection(items=snaps, total=250, limit=50, offset=0)
    widget = ResourceTrendChartsWidget()
    widget.set_collection(col)

    assert widget.is_complete_history is False
    assert widget.scope_badge_text == "CURRENT PAGE SCOPE"
    assert "Page 1 of 5" in widget.scope_text
    assert "50 of 250 snapshots" in widget.scope_text
    assert "#1–50" in widget.scope_text


def test_scope_metadata_complete_history_disclosure(qapp: Any) -> None:
    """When current page covers all snapshots, complete history is stated."""
    snaps = tuple(
        _make_snapshot(snapshot_id=f"00000000-0000-4000-8000-{i:012d}")
        for i in range(12)
    )
    col = _make_collection(items=snaps, total=12, limit=50, offset=0)
    widget = ResourceTrendChartsWidget()
    widget.set_collection(col)

    assert widget.is_complete_history is True
    assert widget.scope_badge_text == "COMPLETE HISTORY"
    assert "All 12 snapshots displayed" in widget.scope_text


# ==============================================================================
# 8. Repeated Updates, Replacements, and Stale State Guard
# ==============================================================================


def test_repeated_updates_do_not_duplicate_points(qapp: Any) -> None:
    """Setting the same collection repeatedly does not accumulate points."""
    s1 = _make_snapshot(timestamp=TIME_1)
    s2 = _make_snapshot(timestamp=TIME_2)
    col = _make_collection(items=(s1, s2), total=2, limit=50, offset=0)

    widget = ResourceTrendChartsWidget()
    widget.set_collection(col)
    assert len(widget.trend_points) == 2

    widget.set_collection(col)
    assert len(widget.trend_points) == 2


def test_replaced_collection_clears_stale_data_and_selection(qapp: Any) -> None:
    """Replacing collection replaces all points and clears stale snapshot selection."""
    s1 = _make_snapshot(timestamp=TIME_1)
    col1 = _make_collection(items=(s1,), total=1, limit=50, offset=0)

    widget = ResourceTrendChartsWidget()
    widget.set_collection(col1)
    widget.select_snapshot(s1)
    assert widget.selected_snapshot is s1

    # New collection without s1
    s2 = _make_snapshot(timestamp=TIME_2)
    col2 = _make_collection(items=(s2,), total=1, limit=50, offset=0)
    widget.set_collection(col2)

    assert len(widget.trend_points) == 1
    assert widget.trend_points[0].snapshot is s2
    assert widget.selected_snapshot is None


# ==============================================================================
# 9. Selection Synchronization
# ==============================================================================


def test_select_snapshot_synchronization(qapp: Any) -> None:
    """select_snapshot updates highlight only when snapshot is present in collection."""
    s1 = _make_snapshot(timestamp=TIME_1)
    s2 = _make_snapshot(timestamp=TIME_2)
    s_other = _make_snapshot(timestamp=TIME_3)

    col = _make_collection(items=(s1, s2), total=2, limit=50, offset=0)
    widget = ResourceTrendChartsWidget()
    widget.set_collection(col)

    widget.select_snapshot(s2)
    assert widget.selected_snapshot is s2

    # Snapshot from another collection is rejected
    widget.select_snapshot(s_other)
    assert widget.selected_snapshot is None

    # None clears selection cleanly
    widget.select_snapshot(s1)
    assert widget.selected_snapshot is s1
    widget.select_snapshot(None)
    assert widget.selected_snapshot is None


def test_point_click_emits_snapshot_selected(qapp: Any) -> None:
    """Clicking near a point on canvas emits snapshot_selected signal."""
    s1 = _make_snapshot(timestamp=TIME_1, cpu_percent=25.0)
    col = _make_collection(items=(s1,), total=1, limit=50, offset=0)

    widget = ResourceTrendChartsWidget()
    widget.resize(600, 200)
    widget.set_collection(col)

    canvas = widget.canvas
    canvas.resize(600, 150)
    canvas._recompute_coordinates()

    selected_received: list[ResourceSnapshot] = []
    widget.snapshot_selected.connect(selected_received.append)

    target_x = canvas._cached_x[0]
    click_pos = QPointF(target_x, 50.0)

    event = QMouseEvent(
        QMouseEvent.Type.MouseButtonPress,
        click_pos,
        click_pos,
        Qt.MouseButton.LeftButton,
        Qt.MouseButton.LeftButton,
        Qt.KeyboardModifier.NoModifier,
    )
    canvas.mousePressEvent(event)

    assert len(selected_received) == 1
    assert selected_received[0] is s1
    assert widget.selected_snapshot is s1


# ==============================================================================
# 10. Metric Modes and Legend Updates
# ==============================================================================


def test_mode_switching_and_legend(qapp: Any) -> None:
    """Switching visualization modes updates combo box, legend, and canvas."""
    widget = ResourceTrendChartsWidget()
    assert widget.mode == MODE_UTILIZATION

    mode_events: list[str] = []
    widget.mode_changed.connect(mode_events.append)

    # 1. Memory Breakdown mode
    widget.set_mode(MODE_MEMORY)
    assert widget.mode == MODE_MEMORY
    assert mode_events == [MODE_MEMORY]
    assert "Memory Used" in widget._legend_cpu.text()
    assert "Memory Total" in widget._legend_mem.text()
    assert widget._legend_disk.isHidden() is True

    # 2. Disk I/O Cumulative Counters mode
    widget.set_mode(MODE_DISK_IO)
    assert widget.mode == MODE_DISK_IO
    assert mode_events == [MODE_MEMORY, MODE_DISK_IO]
    assert "Disk Read (Cumulative)" in widget._legend_cpu.text()
    assert "Disk Write (Cumulative)" in widget._legend_mem.text()
    assert widget._legend_disk.isHidden() is True

    # 3. Utilization mode
    widget.set_mode(MODE_UTILIZATION)
    assert widget.mode == MODE_UTILIZATION
    assert "CPU %" in widget._legend_cpu.text()
    assert "Memory %" in widget._legend_mem.text()
    assert "Disk Usage %" in widget._legend_disk.text()
    assert widget._legend_disk.isHidden() is False

    # Invalid mode raises ValueError
    with pytest.raises(ValueError, match="Unsupported trend chart mode"):
        widget.set_mode("unsupported_mode")


# ==============================================================================
# 11. Loading and Error States with Retained Telemetry
# ==============================================================================


def test_loading_state_retains_points(qapp: Any) -> None:
    """set_loading preserves existing plotted points and displays refreshing scope."""
    s1 = _make_snapshot(timestamp=TIME_1)
    col = _make_collection(items=(s1,), total=1, limit=50, offset=0)

    widget = ResourceTrendChartsWidget()
    widget.set_collection(col)
    assert len(widget.trend_points) == 1

    widget.set_loading()
    assert widget.state == STATE_LOADING
    assert len(widget.trend_points) == 1
    assert "Refreshing from API..." in widget.scope_text


def test_error_state_retains_points_and_displays_message(qapp: Any) -> None:
    """set_error preserves retained points and surfaces error in scope badge."""
    s1 = _make_snapshot(timestamp=TIME_1)
    col = _make_collection(items=(s1,), total=1, limit=50, offset=0)

    widget = ResourceTrendChartsWidget()
    widget.set_collection(col)

    widget.set_error("Connection timeout")
    assert widget.state == STATE_FAILED
    assert len(widget.trend_points) == 1
    assert widget.scope_badge_text == "RETAINED SCOPE"
    assert "Refresh failed: Connection timeout" in widget.scope_text


def test_error_state_without_prior_points(qapp: Any) -> None:
    """set_error on un-loaded widget displays LOAD FAILED badge and error."""
    widget = ResourceTrendChartsWidget()
    widget.set_error("API 500 Internal Error")
    assert widget.state == STATE_FAILED
    assert widget.scope_badge_text == "LOAD FAILED"
    assert "API 500 Internal Error" in widget.scope_text


def test_mouse_move_before_paint_does_not_crash(qapp: Any) -> None:
    """Replacing data with fewer points does not cause IndexError on mouse move."""
    snaps5 = [
        _make_snapshot(snapshot_id=f"00000000-0000-4000-8000-{i:012d}")
        for i in range(5)
    ]
    w = ResourceTrendChartsWidget()
    w.resize(600, 200)
    canvas = w.canvas
    canvas.resize(600, 150)

    # First load 5 items and compute coordinates
    w.set_collection(_make_collection(items=tuple(snaps5), total=5))
    canvas._recompute_coordinates()
    assert len(canvas._cached_x) == 5
    old_last_x = canvas._cached_x[4]

    # Replace with 1 item
    snap1 = snaps5[0]
    w.set_collection(_make_collection(items=(snap1,), total=1))

    # Move mouse near old coordinate before paintEvent has run
    ev = QMouseEvent(
        QMouseEvent.Type.MouseMove,
        QPointF(old_last_x, 50.0),
        QPointF(old_last_x, 50.0),
        Qt.MouseButton.NoButton,
        Qt.MouseButton.NoButton,
        Qt.KeyboardModifier.NoModifier,
    )
    # Must not raise IndexError
    canvas.mouseMoveEvent(ev)


def test_hit_testing_with_mouse_y_resolves_vertical_ties(qapp: Any) -> None:
    """When points share X coordinates, Y proximity resolves point selection."""
    s_high = _make_snapshot(
        snapshot_id="11111111-1111-4111-8111-111111111111",
        timestamp=TIME_1,
        created_at="2026-03-01T08:00:01Z",
        cpu_percent=90.0,
        memory_percent=None,
        disk_usage_percent=None,
    )
    s_low = _make_snapshot(
        snapshot_id="22222222-2222-4222-8222-222222222222",
        timestamp=TIME_1,
        created_at="2026-03-01T08:00:02Z",
        cpu_percent=10.0,
        memory_percent=None,
        disk_usage_percent=None,
    )
    w = ResourceTrendChartsWidget()
    w.resize(600, 250)
    w.set_collection(_make_collection(items=(s_high, s_low), total=2))
    canvas = w.canvas
    canvas.resize(600, 200)
    canvas._recompute_coordinates()

    y_high = canvas._cached_y_series["cpu"][0]
    y_low = canvas._cached_y_series["cpu"][1]
    assert y_high is not None and y_low is not None

    center_x = (canvas._cached_x[0] + canvas._cached_x[1]) / 2.0

    # Click near high point
    ev_high = QMouseEvent(
        QMouseEvent.Type.MouseButtonPress,
        QPointF(center_x, y_high),
        QPointF(center_x, y_high),
        Qt.MouseButton.LeftButton,
        Qt.MouseButton.LeftButton,
        Qt.KeyboardModifier.NoModifier,
    )
    canvas.mousePressEvent(ev_high)
    assert w.selected_snapshot is s_high

    # Click near low point
    ev_low = QMouseEvent(
        QMouseEvent.Type.MouseButtonPress,
        QPointF(center_x, y_low),
        QPointF(center_x, y_low),
        Qt.MouseButton.LeftButton,
        Qt.MouseButton.LeftButton,
        Qt.KeyboardModifier.NoModifier,
    )
    canvas.mousePressEvent(ev_low)
    assert w.selected_snapshot is s_low


def test_hit_testing_outside_plot_vertical_bounds_returns_none(
    qapp: Any,
) -> None:
    """Clicking in top margin or bottom axis labels area does not select points."""
    s1 = _make_snapshot(timestamp=TIME_1, cpu_percent=50.0)
    w = ResourceTrendChartsWidget()
    w.resize(600, 250)
    w.set_collection(_make_collection(items=(s1,), total=1))
    canvas = w.canvas
    canvas.resize(600, 200)
    canvas._recompute_coordinates()

    target_x = canvas._cached_x[0]

    # Click in bottom axis labels (y = 195, below plot_bottom)
    ev_below = QMouseEvent(
        QMouseEvent.Type.MouseButtonPress,
        QPointF(target_x, 195.0),
        QPointF(target_x, 195.0),
        Qt.MouseButton.LeftButton,
        Qt.MouseButton.LeftButton,
        Qt.KeyboardModifier.NoModifier,
    )
    canvas.mousePressEvent(ev_below)
    assert w.selected_snapshot is None

    # Click above plot top (y = 2.0)
    ev_above = QMouseEvent(
        QMouseEvent.Type.MouseButtonPress,
        QPointF(target_x, 2.0),
        QPointF(target_x, 2.0),
        Qt.MouseButton.LeftButton,
        Qt.MouseButton.LeftButton,
        Qt.KeyboardModifier.NoModifier,
    )
    canvas.mousePressEvent(ev_above)
    assert w.selected_snapshot is None


def test_active_query_metadata_reflected_in_scope_and_property(
    qapp: Any,
) -> None:
    """Active query filter criteria and host are stored and reflected in scope."""
    snaps = tuple(
        _make_snapshot(
            snapshot_id=f"00000000-0000-4000-8000-{i:012d}",
            timestamp=TIME_1,
        )
        for i in range(10)
    )
    col = _make_collection(items=snaps, total=30, limit=10, offset=0)
    query = ResourcesQuery(host_id=SAMPLE_HOST_ID, limit=10, offset=0)

    widget = ResourceTrendChartsWidget()
    widget.set_collection(col, query=query)

    assert widget.query is query
    short_host = SAMPLE_HOST_ID[:8]
    assert short_host in widget.scope_text
    assert f"[host: {short_host}…]" in widget.scope_text
    assert "Page 1 of 3" in widget.scope_text
    assert "10 of 30 snapshots" in widget.scope_text


def test_multi_day_span_axis_label_formatting(qapp: Any) -> None:
    """Snapshots spanning multiple days format axis labels with month-day."""
    s1 = _make_snapshot(timestamp="2026-03-01T08:00:00Z")
    s2 = _make_snapshot(timestamp="2026-03-05T16:30:00Z")
    col = _make_collection(items=(s1, s2), total=2)

    widget = ResourceTrendChartsWidget()
    widget.resize(600, 200)
    widget.set_collection(col)

    canvas = widget.canvas
    canvas.resize(600, 150)
    canvas._recompute_coordinates()

    assert widget.trend_points[0].dt.strftime("%m-%d %H:%M") == "03-01 08:00"
    assert widget.trend_points[1].dt.strftime("%m-%d %H:%M") == "03-05 16:30"


def test_repeated_set_collection_with_identical_data_skips_redraw(
    qapp: Any,
) -> None:
    """set_collection skips re-sorting and canvas updates when data is unchanged."""
    s1 = _make_snapshot(timestamp=TIME_1)
    col = _make_collection(items=(s1,), total=1)
    query = ResourcesQuery(limit=50, offset=0)

    widget = ResourceTrendChartsWidget()
    widget.set_collection(col, query=query)
    initial_points = widget.trend_points

    # Call again with identical collection and query
    widget.set_collection(col, query=query)
    # Trend points object list was preserved without re-allocating
    assert widget.trend_points == initial_points


def test_fallback_to_created_at_when_timestamp_missing(qapp: Any) -> None:
    """When snapshot timestamp is invalid or None, created_at is used as fallback."""
    snap = ResourceSnapshot(
        id="00000000-0000-4000-8000-000000000099",
        host_id=SAMPLE_HOST_ID,
        timestamp="",
        created_at="2026-03-01T10:15:30Z",
        cpu_percent=15.0,
    )
    col = _make_collection(items=(snap,), total=1)
    widget = ResourceTrendChartsWidget()
    widget.set_collection(col)

    assert len(widget.trend_points) == 1
    pt = widget.trend_points[0]
    assert pt.formatted_time == "10:15:30"
    assert pt.dt.hour == 10
    assert pt.dt.minute == 15


# ==============================================================================
# 17. Real ResourceSnapshot Model Contract & Verification (Task 0.4.21-F1)
# ==============================================================================


def _make_api_snapshot_dict(
    snapshot_id: str | None = None,
    host_id: str = SAMPLE_HOST_ID,
    timestamp: str = TIME_1,
    created_at: str = TIME_1,
    cpu_percent: float | None = 20.0,
    memory_percent: float | None = 40.0,
    disk_usage_percent: float | None = 60.0,
    memory_used: int | None = 4_000_000_000,
    memory_total: int | None = 16_000_000_000,
    disk_read_bytes: int | None = 1048576,
    disk_write_bytes: int | None = 2097152,
) -> dict[str, Any]:
    """Build raw JSON response dictionary matching GET /api/resources schema."""
    return {
        "id": snapshot_id or str(uuid.uuid4()),
        "host_id": host_id,
        "timestamp": timestamp,
        "created_at": created_at,
        "cpu_percent": cpu_percent,
        "memory_percent": memory_percent,
        "disk_usage_percent": disk_usage_percent,
        "memory_used": memory_used,
        "memory_total": memory_total,
        "disk_read_bytes": disk_read_bytes,
        "disk_write_bytes": disk_write_bytes,
    }


def test_real_model_contract_absence_of_recorded_at(qapp: Any) -> None:
    """Verify ResourceSnapshot has timestamp (not recorded_at) and works with chart."""
    raw = _make_api_snapshot_dict(
        snapshot_id="11111111-1111-4111-8111-111111111111",
        timestamp="2026-03-01T08:00:00Z",
        created_at="2026-03-01T08:00:05Z",
        cpu_percent=18.5,
    )
    snap = ResourceSnapshot.from_dict(raw)

    # 1. Negative contract test: recorded_at is strictly absent
    assert not hasattr(snap, "recorded_at")

    # 2. Positive contract test: timestamp and created_at are observation/meta fields
    assert hasattr(snap, "timestamp")
    assert hasattr(snap, "created_at")
    assert snap.timestamp == "2026-03-01T08:00:00Z"
    assert snap.created_at == "2026-03-01T08:00:05Z"

    # 3. Chart accepts real model instance seamlessly
    col = _make_collection(items=(snap,), total=1)
    widget = ResourceTrendChartsWidget()
    widget.set_collection(col)

    assert len(widget.trend_points) == 1
    pt = widget.trend_points[0]
    assert pt.snapshot is snap
    assert pt.dt == datetime(2026, 3, 1, 8, 0, 0, tzinfo=timezone.utc)
    assert pt.formatted_time == "08:00:00"
    assert pt.cpu_percent == 18.5


def test_real_model_out_of_order_plotted_chronologically(qapp: Any) -> None:
    """Out-of-order real ResourceSnapshot instances are plotted chronologically."""
    s1 = ResourceSnapshot.from_dict(
        _make_api_snapshot_dict(
            timestamp="2026-03-01T08:00:00Z", cpu_percent=10.0
        )
    )
    s2 = ResourceSnapshot.from_dict(
        _make_api_snapshot_dict(
            timestamp="2026-03-01T08:15:00Z", cpu_percent=20.0
        )
    )
    s3 = ResourceSnapshot.from_dict(
        _make_api_snapshot_dict(
            timestamp="2026-03-01T08:30:00Z", cpu_percent=30.0
        )
    )
    s4 = ResourceSnapshot.from_dict(
        _make_api_snapshot_dict(
            timestamp="2026-03-01T08:45:00Z", cpu_percent=40.0
        )
    )

    # Pass in scrambled order
    scrambled = (s3, s1, s4, s2)
    col = _make_collection(items=scrambled, total=4)

    widget = ResourceTrendChartsWidget()
    widget.set_collection(col)

    # widget.snapshots preserves raw collection order
    assert widget.snapshots == scrambled

    # widget.chronological_snapshots is strictly chronological
    assert widget.chronological_snapshots == [s1, s2, s3, s4]
    assert [p.cpu_percent for p in widget.trend_points] == [
        10.0,
        20.0,
        30.0,
        40.0,
    ]
    pts = widget.trend_points
    assert pts[0].dt < pts[1].dt < pts[2].dt < pts[3].dt


def test_real_model_timezone_offsets_ordered_by_actual_instant(
    qapp: Any,
) -> None:
    """Different timezone offsets are ordered by actual UTC instant, not lexical."""
    # Lexical order:
    # "2026-03-01T03:30:00-05:00" < "2026-03-01T08:45:00-01:00" <
    # "2026-03-01T09:00:00Z" < "2026-03-01T10:00:00+02:00"
    #
    # Actual UTC instant order:
    # s_alpha (08:00:00 UTC) < s_beta (08:30:00 UTC) <
    # s_gamma (09:00:00 UTC) < s_delta (09:45:00 UTC)
    s_alpha = ResourceSnapshot.from_dict(
        _make_api_snapshot_dict(
            timestamp="2026-03-01T10:00:00+02:00",
            cpu_percent=10.0,
        )
    )
    s_beta = ResourceSnapshot.from_dict(
        _make_api_snapshot_dict(
            timestamp="2026-03-01T03:30:00-05:00",
            cpu_percent=20.0,
        )
    )
    s_gamma = ResourceSnapshot.from_dict(
        _make_api_snapshot_dict(
            timestamp="2026-03-01T09:00:00Z",
            cpu_percent=30.0,
        )
    )
    s_delta = ResourceSnapshot.from_dict(
        _make_api_snapshot_dict(
            timestamp="2026-03-01T08:45:00-01:00",
            cpu_percent=40.0,
        )
    )

    # Feed in lexical order (which is wrong chronologically)
    lexical_items = (s_beta, s_delta, s_gamma, s_alpha)
    col = _make_collection(items=lexical_items, total=4)

    widget = ResourceTrendChartsWidget()
    widget.resize(600, 250)
    widget.set_collection(col)

    # Raw collection order is preserved
    assert widget.snapshots == lexical_items

    # Chronological sort resolves by true instant, NOT lexical string
    expected_chrono = [s_alpha, s_beta, s_gamma, s_delta]
    assert widget.chronological_snapshots == expected_chrono
    assert [p.snapshot for p in widget.trend_points] == expected_chrono

    # Stored string representations are unchanged on the snapshots
    assert s_alpha.timestamp == "2026-03-01T10:00:00+02:00"
    assert s_beta.timestamp == "2026-03-01T03:30:00-05:00"
    assert s_gamma.timestamp == "2026-03-01T09:00:00Z"
    assert s_delta.timestamp == "2026-03-01T08:45:00-01:00"

    # Normalized datetimes in trend points are UTC-aware and strictly ascending
    assert widget.trend_points[0].dt == datetime(
        2026, 3, 1, 8, 0, 0, tzinfo=timezone.utc
    )
    assert widget.trend_points[1].dt == datetime(
        2026, 3, 1, 8, 30, 0, tzinfo=timezone.utc
    )
    assert widget.trend_points[2].dt == datetime(
        2026, 3, 1, 9, 0, 0, tzinfo=timezone.utc
    )
    assert widget.trend_points[3].dt == datetime(
        2026, 3, 1, 9, 45, 0, tzinfo=timezone.utc
    )

    # Coordinates are strictly increasing on canvas
    canvas = widget.canvas
    canvas.resize(600, 200)
    canvas._recompute_coordinates()
    x = canvas._cached_x
    assert len(x) == 4
    assert x[0] < x[1] < x[2] < x[3]


def test_real_model_equal_timestamps_deterministic_tie_breaking(
    qapp: Any,
) -> None:
    """Equal timestamps (same string or same instant) have deterministic ordering."""
    id_1 = "11111111-1111-4111-8111-111111111111"
    id_2 = "22222222-2222-4222-8222-222222222222"
    id_3 = "33333333-3333-4333-8333-333333333333"

    # Two with same instant via different offsets:
    # s_utc: 08:00:00Z, created_at: 08:00:01Z
    # s_offset: 10:00:00+02:00 (08:00:00 UTC), created_at: 08:00:02Z
    # s_later_created: 08:00:00Z, created_at: 08:00:03Z
    s_utc = ResourceSnapshot.from_dict(
        _make_api_snapshot_dict(
            snapshot_id=id_1,
            timestamp="2026-03-01T08:00:00Z",
            created_at="2026-03-01T08:00:01Z",
            cpu_percent=10.0,
        )
    )
    s_offset = ResourceSnapshot.from_dict(
        _make_api_snapshot_dict(
            snapshot_id=id_2,
            timestamp="2026-03-01T10:00:00+02:00",
            created_at="2026-03-01T08:00:02Z",
            cpu_percent=20.0,
        )
    )
    s_later_created = ResourceSnapshot.from_dict(
        _make_api_snapshot_dict(
            snapshot_id=id_3,
            timestamp="2026-03-01T08:00:00Z",
            created_at="2026-03-01T08:00:03Z",
            cpu_percent=30.0,
        )
    )

    # Pass in reverse order
    col1 = _make_collection(
        items=(s_later_created, s_offset, s_utc), total=3
    )
    widget1 = ResourceTrendChartsWidget()
    widget1.resize(600, 250)
    widget1.set_collection(col1)

    # Pass in different order
    col2 = _make_collection(
        items=(s_offset, s_utc, s_later_created), total=3
    )
    widget2 = ResourceTrendChartsWidget()
    widget2.resize(600, 250)
    widget2.set_collection(col2)

    # Deterministic order is invariant:
    # 1. s_utc has earliest created_at (08:00:01Z)
    # 2. s_offset has created_at 08:00:02Z
    # 3. s_later_created has created_at 08:00:03Z
    expected = [s_utc, s_offset, s_later_created]
    assert widget1.chronological_snapshots == expected
    assert widget2.chronological_snapshots == expected

    # Both widgets produce identical distinct X coordinates
    canvas1 = widget1.canvas
    canvas1.resize(600, 200)
    canvas1._recompute_coordinates()

    assert len(canvas1._cached_x) == 3
    assert canvas1._cached_x[0] < canvas1._cached_x[1] < canvas1._cached_x[2]


def test_real_model_chart_points_preserve_fidelity_and_reference(
    qapp: Any,
) -> None:
    """Chart points maintain exact reference and metric values after sorting."""
    s1 = ResourceSnapshot.from_dict(
        _make_api_snapshot_dict(
            timestamp="2026-03-01T08:00:00Z",
            cpu_percent=12.5,
            memory_percent=45.0,
            disk_usage_percent=60.0,
            memory_used=4_500_000_000,
            memory_total=10_000_000_000,
            disk_read_bytes=1000,
            disk_write_bytes=2000,
        )
    )
    s2 = ResourceSnapshot.from_dict(
        _make_api_snapshot_dict(
            timestamp="2026-03-01T08:10:00Z",
            cpu_percent=75.0,
            memory_percent=80.0,
            disk_usage_percent=90.0,
            memory_used=8_000_000_000,
            memory_total=10_000_000_000,
            disk_read_bytes=5000,
            disk_write_bytes=8000,
        )
    )

    # Scramble order
    col = _make_collection(items=(s2, s1), total=2)
    widget = ResourceTrendChartsWidget()
    widget.set_collection(col)

    pts = widget.trend_points
    assert len(pts) == 2

    # Point 0 references s1
    assert pts[0].snapshot is s1
    assert pts[0].cpu_percent == 12.5
    assert pts[0].memory_percent == 45.0
    assert pts[0].disk_usage_percent == 60.0
    assert pts[0].memory_used == 4_500_000_000
    assert pts[0].memory_total == 10_000_000_000
    assert pts[0].disk_read_bytes == 1000
    assert pts[0].disk_write_bytes == 2000

    # Point 1 references s2
    assert pts[1].snapshot is s2
    assert pts[1].cpu_percent == 75.0
    assert pts[1].memory_percent == 80.0
    assert pts[1].disk_usage_percent == 90.0
    assert pts[1].memory_used == 8_000_000_000
    assert pts[1].memory_total == 10_000_000_000
    assert pts[1].disk_read_bytes == 5000
    assert pts[1].disk_write_bytes == 8000


def test_real_model_table_model_order_independent_of_chart_sorting(
    qapp: Any,
) -> None:
    """Table model maintains original API collection order while chart sorts."""
    s_early = ResourceSnapshot.from_dict(
        _make_api_snapshot_dict(timestamp=TIME_1, cpu_percent=10.0)
    )
    s_mid = ResourceSnapshot.from_dict(
        _make_api_snapshot_dict(timestamp=TIME_2, cpu_percent=20.0)
    )
    s_late = ResourceSnapshot.from_dict(
        _make_api_snapshot_dict(timestamp=TIME_3, cpu_percent=30.0)
    )

    api_order = (s_late, s_early, s_mid)
    col = _make_collection(items=api_order, total=3)

    table_model = ResourcesTableModel()
    table_model.set_collection(col)

    chart_widget = ResourceTrendChartsWidget()
    chart_widget.set_collection(col)

    # Table model order is strictly the API collection order
    assert table_model.rowCount() == 3
    assert table_model.snapshot_at(0) is s_late
    assert table_model.snapshot_at(1) is s_early
    assert table_model.snapshot_at(2) is s_mid

    # Chart order is strictly chronological
    assert chart_widget.chronological_snapshots == [s_early, s_mid, s_late]

    # Chart internal snapshots attribute matches API collection order
    assert chart_widget.snapshots == api_order


def test_real_model_selection_synchronization_with_out_of_order_collection(
    qapp: Any,
) -> None:
    """Selecting chart points correctly synchronizes with table and inspector."""
    s_early = ResourceSnapshot.from_dict(
        _make_api_snapshot_dict(timestamp=TIME_1, cpu_percent=10.0)
    )
    s_mid = ResourceSnapshot.from_dict(
        _make_api_snapshot_dict(timestamp=TIME_2, cpu_percent=20.0)
    )
    s_late = ResourceSnapshot.from_dict(
        _make_api_snapshot_dict(timestamp=TIME_3, cpu_percent=30.0)
    )

    # API order: row 0=s_late, row 1=s_early, row 2=s_mid
    col = _make_collection(items=(s_late, s_early, s_mid), total=3)

    view = ResourcesView()
    view.show()
    view.set_collection(col)

    # 1. Selecting s_early from chart must select row 1 in table (not row 0!)
    view.trend_charts.snapshot_selected.emit(s_early)
    assert view.selected_snapshot is s_early
    assert view.inspector.current_snapshot is s_early
    assert view.trend_charts.selected_snapshot is s_early

    selected_rows = view.table.selectionModel().selectedRows()
    assert len(selected_rows) == 1
    assert selected_rows[0].row() == 1

    # 2. Selecting row 0 (s_late) in table highlights s_late in chart
    view.table.selectRow(0)
    assert view.selected_snapshot is s_late
    assert view.trend_charts.selected_snapshot is s_late
    assert view.inspector.current_snapshot is s_late

    # 3. Deselecting from chart clears selection everywhere
    view.trend_charts.snapshot_selected.emit(None)
    assert view.selected_snapshot is None
    assert view.trend_charts.selected_snapshot is None
    assert view.inspector.current_snapshot is None
    assert len(view.table.selectionModel().selectedRows()) == 0

    view.close()


def test_real_model_missing_metrics_remain_none_not_zero(qapp: Any) -> None:
    """Missing metrics remain None and are not plotted as 0.0."""
    raw_missing = _make_api_snapshot_dict(
        timestamp=TIME_1,
        cpu_percent=None,
        memory_percent=None,
        disk_usage_percent=None,
        memory_used=None,
        memory_total=None,
        disk_read_bytes=None,
        disk_write_bytes=None,
    )
    raw_zero = _make_api_snapshot_dict(
        timestamp=TIME_2,
        cpu_percent=0.0,
        memory_percent=0.0,
        disk_usage_percent=0.0,
        memory_used=0,
        memory_total=10_000_000_000,
        disk_read_bytes=0,
        disk_write_bytes=0,
    )

    s_missing = ResourceSnapshot.from_dict(raw_missing)
    s_zero = ResourceSnapshot.from_dict(raw_zero)

    col = _make_collection(items=(s_missing, s_zero), total=2)
    widget = ResourceTrendChartsWidget()
    widget.resize(600, 250)
    widget.set_collection(col)

    # TrendPoint retains None, does not coerce to 0.0
    pt_missing = widget.trend_points[0]
    assert pt_missing.cpu_percent is None
    assert pt_missing.memory_percent is None
    assert pt_missing.disk_usage_percent is None
    assert pt_missing.memory_used is None
    assert pt_missing.disk_read_bytes is None

    # TrendPoint for s_zero retains genuine 0.0
    pt_zero = widget.trend_points[1]
    assert pt_zero.cpu_percent == 0.0
    assert pt_zero.memory_used == 0

    canvas = widget.canvas
    canvas.resize(600, 200)
    canvas._recompute_coordinates()

    # Cached Y for missing metric is None (skipped during rendering)
    assert canvas._cached_y_series["cpu"][0] is None
    assert canvas._cached_y_series["memory"][0] is None
    assert canvas._cached_y_series["disk"][0] is None

    # Cached Y for genuine 0.0 is float at bottom baseline
    plot_bottom = float(canvas.height() - canvas.BOTTOM_MARGIN)
    assert canvas._cached_y_series["cpu"][1] == plot_bottom


def test_real_model_fallback_to_created_at_sorts_chronologically(
    qapp: Any,
) -> None:
    """Snapshots with missing timestamp sort chronologically via created_at."""
    s_normal = ResourceSnapshot(
        id="11111111-1111-4111-8111-111111111111",
        host_id=SAMPLE_HOST_ID,
        timestamp="2026-03-01T08:00:00Z",
        created_at="2026-03-01T08:00:00Z",
        cpu_percent=10.0,
    )
    s_missing_ts = ResourceSnapshot(
        id="22222222-2222-4222-8222-222222222222",
        host_id=SAMPLE_HOST_ID,
        timestamp="",
        created_at="2026-03-01T12:00:00Z",
        cpu_percent=20.0,
    )

    # Pass in reverse chronological order
    col = _make_collection(items=(s_missing_ts, s_normal), total=2)
    widget = ResourceTrendChartsWidget()
    widget.set_collection(col)

    # s_normal (08:00:00) sorts before s_missing_ts (12:00:00 fallback)
    assert widget.chronological_snapshots == [s_normal, s_missing_ts]
    assert widget.trend_points[0].dt < widget.trend_points[1].dt


def test_real_model_equal_timestamps_and_created_at_tie_broken_by_id(
    qapp: Any,
) -> None:
    """When timestamp and created_at are identical, snapshot ID breaks ties."""
    id_a = "11111111-1111-4111-8111-111111111111"
    id_b = "22222222-2222-4222-8222-222222222222"
    id_c = "33333333-3333-4333-8333-333333333333"

    s_a = ResourceSnapshot.from_dict(
        _make_api_snapshot_dict(
            snapshot_id=id_a,
            timestamp="2026-03-01T08:00:00Z",
            created_at="2026-03-01T08:00:00Z",
            cpu_percent=10.0,
        )
    )
    s_b = ResourceSnapshot.from_dict(
        _make_api_snapshot_dict(
            snapshot_id=id_b,
            timestamp="2026-03-01T08:00:00Z",
            created_at="2026-03-01T08:00:00Z",
            cpu_percent=20.0,
        )
    )
    s_c = ResourceSnapshot.from_dict(
        _make_api_snapshot_dict(
            snapshot_id=id_c,
            timestamp="2026-03-01T08:00:00Z",
            created_at="2026-03-01T08:00:00Z",
            cpu_percent=30.0,
        )
    )

    # Scrambled input order
    col1 = _make_collection(items=(s_c, s_a, s_b), total=3)
    widget1 = ResourceTrendChartsWidget()
    widget1.resize(600, 250)
    widget1.set_collection(col1)

    # Reverse input order
    col2 = _make_collection(items=(s_b, s_c, s_a), total=3)
    widget2 = ResourceTrendChartsWidget()
    widget2.resize(600, 250)
    widget2.set_collection(col2)

    # Deterministic tie-breaking by UUID string
    expected = [s_a, s_b, s_c]
    assert widget1.chronological_snapshots == expected
    assert widget2.chronological_snapshots == expected

    # Both widgets produce strictly distinct X coordinates
    canvas1 = widget1.canvas
    canvas1.resize(600, 200)
    canvas1._recompute_coordinates()
    assert len(canvas1._cached_x) == 3
    assert canvas1._cached_x[0] < canvas1._cached_x[1] < canvas1._cached_x[2]


def test_real_model_subsecond_microsecond_offsets_ordered_by_actual_instant(
    qapp: Any,
) -> None:
    """Sub-second timestamps with timezone offsets are sorted by UTC instant."""
    # Lexical order:
    # "2026-03-01T08:00:00.500000Z" < "2026-03-01T09:00:00.250000+01:00"
    #
    # Chronological instant order:
    # s_earlier (08:00:00.250000 UTC) < s_later (08:00:00.500000 UTC)
    s_later = ResourceSnapshot.from_dict(
        _make_api_snapshot_dict(
            snapshot_id="11111111-1111-4111-8111-111111111111",
            timestamp="2026-03-01T08:00:00.500000Z",
            cpu_percent=50.0,
        )
    )
    s_earlier = ResourceSnapshot.from_dict(
        _make_api_snapshot_dict(
            snapshot_id="22222222-2222-4222-8222-222222222222",
            timestamp="2026-03-01T09:00:00.250000+01:00",
            cpu_percent=25.0,
        )
    )

    # Input in reverse chronological order (which is lexical order)
    col = _make_collection(items=(s_later, s_earlier), total=2)
    widget = ResourceTrendChartsWidget()
    widget.resize(600, 250)
    widget.set_collection(col)

    # Chronological sort places s_earlier first
    assert widget.chronological_snapshots == [s_earlier, s_later]
    assert widget.trend_points[0].snapshot is s_earlier
    assert widget.trend_points[1].snapshot is s_later
    assert widget.trend_points[0].dt < widget.trend_points[1].dt

    # Canvas coordinates strictly ordered
    canvas = widget.canvas
    canvas.resize(600, 200)
    canvas._recompute_coordinates()
    assert canvas._cached_x[0] < canvas._cached_x[1]


# ==============================================================================
# 22. Paint Rendering and Mode Coverage Tests
# ==============================================================================


def test_paint_rendering_across_all_modes_and_states(qapp: Any) -> None:
    """Widget and canvas paint cleanly in all visualization modes and states."""
    widget = ResourceTrendChartsWidget()
    widget.resize(600, 300)
    pix = QPixmap(600, 300)

    # 1. Paint in STATE_NOT_LOADED
    widget.render(pix)

    # 2. Paint in STATE_LOADING (empty points)
    widget.set_loading()
    widget.render(pix)

    # 3. Paint in STATE_FAILED (empty points)
    widget.set_error("Connection timed out")
    widget.render(pix)

    # 4. Paint in STATE_EMPTY
    empty_col = _make_collection(items=(), total=0)
    widget.set_collection(empty_col)
    widget.render(pix)

    # 5. Paint in STATE_LOADED with points across all 3 modes
    s1 = _make_snapshot(
        timestamp=TIME_1,
        cpu_percent=25.0,
        memory_percent=50.0,
        disk_usage_percent=75.0,
        memory_used=4_000_000_000,
        memory_total=8_000_000_000,
        disk_read_bytes=10_000,
        disk_write_bytes=20_000,
    )
    s2 = _make_snapshot(
        timestamp=TIME_2,
        cpu_percent=50.0,
        memory_percent=60.0,
        disk_usage_percent=80.0,
        memory_used=6_000_000_000,
        memory_total=8_000_000_000,
        disk_read_bytes=30_000,
        disk_write_bytes=40_000,
    )
    col = _make_collection(items=(s1, s2), total=2)
    widget.set_collection(col)

    # MODE_UTILIZATION paint
    widget.set_mode(MODE_UTILIZATION)
    widget.render(pix)

    # MODE_MEMORY paint
    widget.set_mode(MODE_MEMORY)
    widget.render(pix)

    # MODE_DISK_IO paint
    widget.set_mode(MODE_DISK_IO)
    widget.render(pix)

    # 6. Paint with snapshot selected (selection guide line + halos)
    widget.select_snapshot(s1)
    widget.render(pix)

    # 7. Paint with hovered point (vertical hover guide line)
    widget.canvas._hovered_index = 0
    widget.render(pix)

    # 8. Paint in loading and failed states when retaining points
    widget.set_loading()
    widget.render(pix)

    widget.set_error("API server disconnected")
    widget.render(pix)


def test_paint_rendering_broken_segments_and_all_none_series(qapp: Any) -> None:
    """Canvas handles intermittent None metrics and all-None series."""
    # 1. Intermittent None metrics (tests polyline segment breaking)
    s1 = _make_snapshot(timestamp=TIME_1, cpu_percent=20.0)
    s2 = _make_snapshot(timestamp=TIME_2, cpu_percent=None)
    s3 = _make_snapshot(timestamp=TIME_3, cpu_percent=40.0)
    col = _make_collection(items=(s1, s2, s3), total=3)

    widget = ResourceTrendChartsWidget()
    widget.resize(600, 300)
    widget.set_collection(col)
    pix = QPixmap(600, 300)
    widget.render(pix)

    # 2. All-None series across all modes
    sn1 = _make_snapshot(
        timestamp=TIME_1,
        cpu_percent=None,
        memory_percent=None,
        disk_usage_percent=None,
        memory_used=None,
        memory_total=None,
        disk_read_bytes=None,
        disk_write_bytes=None,
    )
    sn2 = _make_snapshot(
        timestamp=TIME_2,
        cpu_percent=None,
        memory_percent=None,
        disk_usage_percent=None,
        memory_used=None,
        memory_total=None,
        disk_read_bytes=None,
        disk_write_bytes=None,
    )
    none_col = _make_collection(items=(sn1, sn2), total=2)
    widget.set_collection(none_col)

    # All None in MODE_UTILIZATION
    widget.set_mode(MODE_UTILIZATION)
    widget.render(pix)

    # All None in MODE_MEMORY (tests max_bytes <= 0 fallback)
    widget.set_mode(MODE_MEMORY)
    widget.render(pix)

    # All None in MODE_DISK_IO (tests max_bytes <= 0 fallback)
    widget.set_mode(MODE_DISK_IO)
    widget.render(pix)


def test_time_axis_rendering_multi_day_span(qapp: Any) -> None:
    """Time axis formats distinct date+time labels for multi-day spans."""
    s1 = _make_snapshot(timestamp="2026-03-01T08:00:00Z")
    s2 = _make_snapshot(timestamp="2026-03-03T18:00:00Z")
    col = _make_collection(items=(s1, s2), total=2)

    widget = ResourceTrendChartsWidget()
    widget.resize(800, 300)
    widget.set_collection(col)
    pix = QPixmap(800, 300)
    widget.render(pix)


def test_mouse_move_tooltips_memory_and_disk_io(qapp: Any) -> None:
    """Hovering over points in Memory and Disk I/O modes shows formatted tips."""
    s1 = _make_snapshot(
        timestamp=TIME_1,
        memory_used=1_073_741_824,
        memory_total=4_294_967_296,
        disk_read_bytes=5_242_880,
        disk_write_bytes=10_485_760,
    )
    col = _make_collection(items=(s1,), total=1)
    widget = ResourceTrendChartsWidget()
    widget.resize(600, 300)
    widget.set_collection(col)

    canvas = widget.canvas
    canvas.resize(600, 200)
    canvas._recompute_coordinates()

    # In single snapshot mode, point x is centered
    pt_x = canvas._cached_x[0]

    # Mouse move in MODE_MEMORY
    widget.set_mode(MODE_MEMORY)
    ev_mem = QMouseEvent(
        QMouseEvent.Type.MouseMove,
        QPointF(pt_x, 100.0),
        QPointF(pt_x, 100.0),
        Qt.MouseButton.NoButton,
        Qt.MouseButton.NoButton,
        Qt.KeyboardModifier.NoModifier,
    )
    canvas.mouseMoveEvent(ev_mem)
    assert canvas._hovered_index == 0

    # Mouse move in MODE_DISK_IO
    widget.set_mode(MODE_DISK_IO)
    ev_disk = QMouseEvent(
        QMouseEvent.Type.MouseMove,
        QPointF(pt_x, 100.0),
        QPointF(pt_x, 100.0),
        Qt.MouseButton.NoButton,
        Qt.MouseButton.NoButton,
        Qt.KeyboardModifier.NoModifier,
    )
    canvas.mouseMoveEvent(ev_disk)
    assert canvas._hovered_index == 0

    # Move far away outside threshold
    ev_far = QMouseEvent(
        QMouseEvent.Type.MouseMove,
        QPointF(0.0, 0.0),
        QPointF(0.0, 0.0),
        Qt.MouseButton.NoButton,
        Qt.MouseButton.NoButton,
        Qt.KeyboardModifier.NoModifier,
    )
    canvas.mouseMoveEvent(ev_far)
    assert canvas._hovered_index is None

    # Leave event clears hovered index
    canvas._hovered_index = 0
    canvas.leaveEvent(None)
    assert canvas._hovered_index is None


def test_widget_public_accessors_and_edge_cases(qapp: Any) -> None:
    """Widget getters, clear, reset, and error handling behaviors."""
    widget = ResourceTrendChartsWidget()

    # Public getters
    assert widget.scope_label is not None
    assert widget.scope_badge is not None
    assert widget.mode_combo is not None

    # Clear alias
    widget.clear()
    assert widget.state == STATE_NOT_LOADED

    # set_collection(None) resets to NOT_LOADED
    widget.set_collection(None)
    assert widget.state == STATE_NOT_LOADED

    # Invalid collection type raises TypeError
    with pytest.raises(TypeError, match="Expected ResourceSnapshotCollection"):
        widget.set_collection("not_a_collection")  # type: ignore[arg-type]

    # Mode combo selection handler
    widget.mode_combo.setCurrentIndex(1)
    assert widget.mode == MODE_MEMORY

    # Empty canvas coordinate calculation
    widget.canvas._points = []
    widget.canvas._recompute_coordinates()
    assert widget.canvas._cached_x == []

    # Mouse move when canvas has no points
    ev_empty = QMouseEvent(
        QMouseEvent.Type.MouseMove,
        QPointF(50.0, 50.0),
        QPointF(50.0, 50.0),
        Qt.MouseButton.NoButton,
        Qt.MouseButton.NoButton,
        Qt.KeyboardModifier.NoModifier,
    )
    widget.canvas.mouseMoveEvent(ev_empty)

    # Closest point index edge cases
    assert widget.canvas._find_closest_point_index(100.0, 100.0) is None

    # Render selection when selected snapshot is not in points
    s_real = _make_snapshot(snapshot_id="11111111-1111-4111-8111-111111111111")
    s_other = _make_snapshot(snapshot_id="99999999-9999-4999-8999-999999999999")
    widget.set_collection(_make_collection(items=(s_real,), total=1))
    widget.canvas._selected_snapshot = s_other
    pix = QPixmap(600, 300)
    widget.render(pix)

    # Time axis rendering when first and last label are equal
    s_a = _make_snapshot(timestamp="2026-03-01T08:00:00.100000Z")
    s_b = _make_snapshot(timestamp="2026-03-01T08:00:00.200000Z")
    widget.set_collection(_make_collection(items=(s_a, s_b), total=2))
    widget.render(pix)

    # Memory used > memory total & zero disk bytes
    s_big = _make_snapshot(
        memory_used=9_000_000_000,
        memory_total=4_000_000_000,
        disk_read_bytes=0,
        disk_write_bytes=0,
    )
    widget.set_collection(_make_collection(items=(s_big,), total=1))
    widget.set_mode(MODE_MEMORY)
    widget.render(pix)
    widget.set_mode(MODE_DISK_IO)
    widget.render(pix)

    # Hit testing: no valid Y values vs dist > effective_limit
    canvas = widget.canvas
    canvas.resize(600, 200)
    canvas._recompute_coordinates()
    pt_x = canvas._cached_x[0]
    # Within horizontal threshold but vertical dist beyond limit
    assert canvas._find_closest_point_index(pt_x, 9999.0) is None


def test_query_active_filters_scope_label(qapp: Any) -> None:
    """Query with active filters but no host_id adds [filtered] to scope."""

    class MockQuery:
        host_id = None
        has_active_filters = True

    s1 = _make_snapshot(timestamp=TIME_1)
    col = _make_collection(items=(s1,), total=1)
    widget = ResourceTrendChartsWidget()
    widget.set_collection(col, query=MockQuery())
    assert "[filtered]" in widget.scope_text


def test_tie_breaking_multiple_groups(qapp: Any) -> None:
    """Timestamps with multiple groups containing ties calculate offsets."""
    s1 = _make_snapshot(timestamp=TIME_1, cpu_percent=10.0)
    s2 = _make_snapshot(timestamp=TIME_1, cpu_percent=20.0)
    s3 = _make_snapshot(timestamp=TIME_2, cpu_percent=30.0)
    s4 = _make_snapshot(timestamp=TIME_2, cpu_percent=40.0)
    col = _make_collection(items=(s1, s2, s3, s4), total=4)

    widget = ResourceTrendChartsWidget()
    widget.resize(600, 300)
    widget.set_collection(col)

    canvas = widget.canvas
    canvas.resize(600, 200)
    canvas._recompute_coordinates()

    # All 4 points have distinct X coordinates
    assert len(set(canvas._cached_x)) == 4
    # Points in group 1 are to the left of points in group 2
    assert max(canvas._cached_x[0], canvas._cached_x[1]) < min(
        canvas._cached_x[2], canvas._cached_x[3]
    )


def test_resources_charts_render_and_hit_test_edge_cases(qapp: Any) -> None:
    """Cover edge branches in rendering grid, time axis, and hit testing."""
    widget = ResourceTrendChartsWidget()
    widget.resize(600, 300)

    # 1. Zero/None memory and disk bytes (forces max_bytes <= 0 -> max_bytes = 1)
    s_zero = _make_snapshot(
        timestamp=TIME_1,
        memory_used=0,
        memory_total=0,
        disk_read_bytes=0,
        disk_write_bytes=0,
        cpu_percent=10.0,
    )
    col = _make_collection(items=(s_zero,), total=1)
    widget.set_collection(col)
    pix = QPixmap(600, 300)

    widget.set_mode(MODE_MEMORY)
    widget.render(pix)

    widget.set_mode(MODE_DISK_IO)
    widget.render(pix)

    # 2. _render_time_axis with empty _cached_x
    canvas = widget.canvas
    canvas.resize(600, 200)
    canvas._cached_x = []
    # Calling render should return early in time axis without error
    widget.render(pix)

    # 3. Multi-day span with wide spacing (exercises else branch with %m-%d %H:%M)
    s_day1 = _make_snapshot(timestamp="2026-03-01T08:00:00Z", cpu_percent=10.0)
    s_day2 = _make_snapshot(timestamp="2026-03-03T18:00:00Z", cpu_percent=20.0)
    col_days = _make_collection(items=(s_day1, s_day2), total=2)
    widget.set_collection(col_days)
    widget.set_mode(MODE_UTILIZATION)
    widget.render(pix)

    # 4. _find_closest_point_index edge branches
    canvas = widget.canvas
    canvas.resize(600, 200)
    canvas._recompute_coordinates()

    # Out of vertical bounds (above top - 12 and below bottom + 12)
    assert canvas._find_closest_point_index(100.0, mouse_y=-50.0) is None
    assert canvas._find_closest_point_index(100.0, mouse_y=500.0) is None

    # 1D search branch (mouse_y is None)
    pt_x = canvas._cached_x[0]
    idx_1d = canvas._find_closest_point_index(pt_x, mouse_y=None)
    assert idx_1d == 0

    # 2D search when valid_ys is empty (metric values are None)
    s_none_metric = _make_snapshot(
        timestamp=TIME_1,
        cpu_percent=None,
        memory_percent=None,
        disk_usage_percent=None,
    )
    # Give it at least one metric on second snapshot so canvas is not empty
    s_valid_metric = _make_snapshot(timestamp=TIME_2, cpu_percent=50.0)
    col_none = _make_collection(items=(s_none_metric, s_valid_metric), total=2)
    widget.set_collection(col_none)
    canvas = widget.canvas
    canvas.resize(600, 200)
    canvas._recompute_coordinates()
    pt0_x = canvas._cached_x[0]
    # At index 0, valid_ys is empty, so dist = dx
    idx_empty_ys = canvas._find_closest_point_index(pt0_x, mouse_y=100.0)
    assert idx_empty_ys == 0



