"""OSIRIS Resource Telemetry Trend Charts Component.

Provides ResourceTrendChartsWidget, a compact, professional native PySide6
QFrame component for presenting historical telemetry trend charts of real
system resource snapshots returned by the authenticated OSIRIS REST API:
1. CPU utilization percentage
2. Memory utilization percentage
3. Disk utilization percentage
4. Optional memory used vs total breakdown
5. Optional cumulative disk I/O read/write counters

Adheres strictly to the dark SOC design language, deterministic 4px spacing
rhythm, accessible contrast standards, and non-interpolated telemetry semantics.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QMouseEvent,
    QPainter,
    QPaintEvent,
    QPen,
)
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QSizePolicy,
    QToolTip,
    QVBoxLayout,
    QWidget,
)

from desktop.client.models import ResourceSnapshot, ResourceSnapshotCollection
from desktop.models.resources_model import (
    _parse_iso_utc,
    format_bytes,
    format_percent,
)
from desktop.ui.design_tokens import (
    ACCENT,
    ACCENT_FOCUS,
    BORDER,
    FONT_FAMILY_MONO,
    FONT_FAMILY_SANS,
    FONT_SIZE_SMALL_METADATA,
    RADIUS_SMALL,
    SEVERITY_HIGH,
    SPACE_1,
    SPACE_2,
    SPACE_3,
    STATUS_FRESH,
    STATUS_STALE,
    SURFACE_0,
    SURFACE_2,
    TEXT_SECONDARY,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MODE_UTILIZATION: str = "utilization"
MODE_MEMORY: str = "memory"
MODE_DISK_IO: str = "disk_io"

MODE_OPTIONS: tuple[tuple[str, str], ...] = (
    ("Utilization (%)", MODE_UTILIZATION),
    ("Memory Breakdown", MODE_MEMORY),
    ("Disk I/O (Cumulative)", MODE_DISK_IO),
)

STATE_NOT_LOADED: str = "not_loaded"
STATE_LOADING: str = "loading"
STATE_LOADED: str = "loaded"
STATE_EMPTY: str = "empty"
STATE_FAILED: str = "failed"

# Series Palette
COLOR_CPU: str = ACCENT
COLOR_MEMORY: str = STATUS_FRESH
COLOR_DISK: str = STATUS_STALE
COLOR_MEM_TOTAL: str = TEXT_SECONDARY
COLOR_DISK_WRITE: str = SEVERITY_HIGH


@dataclass(frozen=True)
class TrendPoint:
    """Normalized point-in-time telemetry point for deterministic plotting."""

    snapshot: ResourceSnapshot
    dt: datetime
    formatted_time: str
    cpu_percent: float | None
    memory_percent: float | None
    disk_usage_percent: float | None
    memory_used: int | None
    memory_total: int | None
    disk_read_bytes: int | None
    disk_write_bytes: int | None


def _snapshot_sort_key(
    snap: ResourceSnapshot,
) -> tuple[datetime, datetime, str, str, str]:
    """Deterministic chronological sort key matching resources_model."""
    dt_min = datetime.min.replace(tzinfo=timezone.utc)
    primary_dt = (
        _parse_iso_utc(snap.timestamp)
        or _parse_iso_utc(snap.created_at)
        or dt_min
    )
    secondary_dt = _parse_iso_utc(snap.created_at) or dt_min
    lex_primary = str(snap.timestamp or "")
    lex_secondary = str(snap.created_at or "")
    snap_id = str(snap.id or "")
    return (primary_dt, secondary_dt, lex_primary, lex_secondary, snap_id)


class _TrendCanvas(QWidget):
    """High-performance vector canvas for drawing telemetry trend lines."""

    point_clicked = Signal(object)

    LEFT_MARGIN: int = 76
    RIGHT_MARGIN: int = 24
    TOP_MARGIN: int = 16
    BOTTOM_MARGIN: int = 28

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("ResourceTrendCanvas")
        self.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        self.setMinimumHeight(130)
        self.setMouseTracking(True)

        self._points: list[TrendPoint] = []
        self._mode: str = MODE_UTILIZATION
        self._state: str = STATE_NOT_LOADED
        self._selected_snapshot: ResourceSnapshot | None = None
        self._hovered_index: int | None = None
        self._error_message: str = ""

        # Cached coordinates for fast paint and hit testing
        self._cached_x: list[float] = []
        self._cached_y_series: dict[str, list[float | None]] = {}
        self._dirty_coords: bool = True

    def set_data(
        self,
        points: list[TrendPoint],
        mode: str,
        state: str,
        selected_snapshot: ResourceSnapshot | None,
        error_message: str = "",
    ) -> None:
        """Update chart display model and invalidate coordinate cache."""
        if (
            self._points == points
            and self._mode == mode
            and self._state == state
            and self._selected_snapshot == selected_snapshot
            and self._error_message == error_message
        ):
            return

        self._points = points
        self._mode = mode
        self._state = state
        self._selected_snapshot = selected_snapshot
        self._error_message = error_message
        self._hovered_index = None
        self._cached_x = []
        self._cached_y_series = {}
        self._dirty_coords = True
        self.update()

    def set_selected_snapshot(
        self, snapshot: ResourceSnapshot | None
    ) -> None:
        """Update selected snapshot highlight without full data invalidation."""
        if self._selected_snapshot != snapshot:
            self._selected_snapshot = snapshot
            self.update()

    def set_mode(self, mode: str) -> None:
        """Change visible metric mode and invalidate Y coordinates."""
        if self._mode != mode:
            self._mode = mode
            self._dirty_coords = True
            self.update()

    # -----------------------------------------------------------------------
    # Coordinate Calculations
    # -----------------------------------------------------------------------

    def _ensure_coordinates(self) -> None:
        """Ensure cached pixel coordinates are computed for current geometry."""
        if self._dirty_coords:
            self._recompute_coordinates()

    def _recompute_coordinates(self) -> None:
        """Recompute pixel coordinates for all points based on current rect."""
        self._cached_x = []
        self._cached_y_series = {}
        self._dirty_coords = False

        num_points = len(self._points)
        if num_points == 0:
            return

        w = self.width()
        h = self.height()
        plot_left = float(self.LEFT_MARGIN)
        plot_right = float(max(plot_left + 10, w - self.RIGHT_MARGIN))
        plot_width = plot_right - plot_left
        plot_top = float(self.TOP_MARGIN)
        plot_bottom = float(max(plot_top + 10, h - self.BOTTOM_MARGIN))
        plot_height = plot_bottom - plot_top

        # 1. Horizontal X coordinates
        if num_points == 1:
            self._cached_x = [plot_left + plot_width / 2.0]
        else:
            t_min = self._points[0].dt.timestamp()
            t_max = self._points[-1].dt.timestamp()
            time_span = t_max - t_min

            if time_span > 0:
                # Group points by equal timestamp for deterministic tie separation
                ts_groups: dict[float, list[int]] = {}
                for idx, pt in enumerate(self._points):
                    ts_val = pt.dt.timestamp()
                    ts_groups.setdefault(ts_val, []).append(idx)

                x_coords: list[float] = [0.0] * num_points
                for ts_val, indices in ts_groups.items():
                    frac = (ts_val - t_min) / time_span
                    nominal_x = plot_left + frac * plot_width
                    group_size = len(indices)
                    if group_size == 1:
                        x_coords[indices[0]] = nominal_x
                    else:
                        step_px = min(8.0, plot_width / (num_points * 2.0))
                        for rank, idx in enumerate(indices):
                            offset = (rank - (group_size - 1) / 2.0) * step_px
                            x_coords[idx] = min(
                                plot_right, max(plot_left, nominal_x + offset)
                            )
                self._cached_x = x_coords
            else:
                # All points have identical timestamps: cluster near center
                # deterministically
                nominal_x = plot_left + plot_width / 2.0
                step_px = min(8.0, plot_width / (num_points * 2.0))
                x_coords = [0.0] * num_points
                for rank in range(num_points):
                    offset = (rank - (num_points - 1) / 2.0) * step_px
                    x_coords[rank] = min(
                        plot_right, max(plot_left, nominal_x + offset)
                    )
                self._cached_x = x_coords

        # 2. Vertical Y coordinates
        if self._mode == MODE_UTILIZATION:
            # Fixed 0.0% to 100.0% scale
            def _calc_pct_y(val: float | None) -> float | None:
                if val is None or math.isnan(val) or math.isinf(val):
                    return None
                clamped = min(100.0, max(0.0, float(val)))
                return plot_bottom - (clamped / 100.0) * plot_height

            self._cached_y_series["cpu"] = [
                _calc_pct_y(p.cpu_percent) for p in self._points
            ]
            self._cached_y_series["memory"] = [
                _calc_pct_y(p.memory_percent) for p in self._points
            ]
            self._cached_y_series["disk"] = [
                _calc_pct_y(p.disk_usage_percent) for p in self._points
            ]

        elif self._mode == MODE_MEMORY:
            # Dynamic byte scale based on max total/used
            max_bytes = 0
            for p in self._points:
                if p.memory_total is not None and p.memory_total > max_bytes:
                    max_bytes = p.memory_total
                if p.memory_used is not None and p.memory_used > max_bytes:
                    max_bytes = p.memory_used
            if max_bytes <= 0:
                max_bytes = 1

            def _calc_mem_y(val: int | None) -> float | None:
                if val is None or val < 0:
                    return None
                ratio = min(1.0, max(0.0, float(val) / float(max_bytes)))
                return plot_bottom - ratio * plot_height

            self._cached_y_series["memory_used"] = [
                _calc_mem_y(p.memory_used) for p in self._points
            ]
            self._cached_y_series["memory_total"] = [
                _calc_mem_y(p.memory_total) for p in self._points
            ]

        elif self._mode == MODE_DISK_IO:
            # Dynamic cumulative byte scale based on max read/write
            max_bytes = 0
            for p in self._points:
                if (
                    p.disk_read_bytes is not None
                    and p.disk_read_bytes > max_bytes
                ):
                    max_bytes = p.disk_read_bytes
                if (
                    p.disk_write_bytes is not None
                    and p.disk_write_bytes > max_bytes
                ):
                    max_bytes = p.disk_write_bytes
            if max_bytes <= 0:
                max_bytes = 1

            def _calc_disk_y(val: int | None) -> float | None:
                if val is None or val < 0:
                    return None
                ratio = min(1.0, max(0.0, float(val) / float(max_bytes)))
                return plot_bottom - ratio * plot_height

            self._cached_y_series["disk_read"] = [
                _calc_disk_y(p.disk_read_bytes) for p in self._points
            ]
            self._cached_y_series["disk_write"] = [
                _calc_disk_y(p.disk_write_bytes) for p in self._points
            ]

    # -----------------------------------------------------------------------
    # Paint Event
    # -----------------------------------------------------------------------

    def paintEvent(self, event: QPaintEvent) -> None:  # noqa: N802
        """Render the chart background, axes, grid, lines, and selection."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.setRenderHint(QPainter.RenderHint.TextAntialiasing, True)

        w = self.width()
        h = self.height()

        # Canvas background container
        painter.fillRect(self.rect(), QColor(SURFACE_0))
        painter.setPen(QPen(QColor(BORDER), 1))
        painter.drawRoundedRect(
            QRectF(0.5, 0.5, float(w - 1), float(h - 1)),
            float(RADIUS_SMALL),
            float(RADIUS_SMALL),
        )

        # Handle empty/non-loaded states without points
        if not self._points:
            self._render_state_message(painter, w, h)
            return

        # Check if all series in active mode are completely None
        if self._dirty_coords:
            self._recompute_coordinates()

        if self._is_all_series_none():
            self._render_empty_series_message(painter, w, h)
            return

        plot_left = float(self.LEFT_MARGIN)
        plot_right = float(max(plot_left + 10, w - self.RIGHT_MARGIN))
        plot_top = float(self.TOP_MARGIN)
        plot_bottom = float(max(plot_top + 10, h - self.BOTTOM_MARGIN))
        plot_height = plot_bottom - plot_top
        plot_width = plot_right - plot_left

        # Draw grid lines and Y-axis labels
        self._render_grid_and_y_labels(
            painter, plot_left, plot_right, plot_top, plot_bottom, plot_height
        )

        # Draw bottom time axis and timestamp labels
        self._render_time_axis(
            painter, plot_left, plot_right, plot_bottom, plot_width
        )

        # Draw series lines and point circles
        self._render_series(painter)

        # Draw selected snapshot indicator
        self._render_selection(painter, plot_top, plot_bottom)

        # Draw hover indicator
        self._render_hover(painter, plot_top, plot_bottom)

    def _is_all_series_none(self) -> bool:
        """Return True if every metric value in the active mode is None."""
        for series_vals in self._cached_y_series.values():
            if any(val is not None for val in series_vals):
                return False
        return True

    def _render_state_message(
        self, painter: QPainter, w: int, h: int
    ) -> None:
        """Render informational status text when no points are available."""
        painter.setFont(QFont(FONT_FAMILY_SANS, FONT_SIZE_SMALL_METADATA))
        painter.setPen(QColor(TEXT_SECONDARY))

        if self._state == STATE_NOT_LOADED:
            msg = (
                "Resource telemetry not loaded. Click Refresh Resources "
                "to load."
            )
        elif self._state == STATE_LOADING:
            msg = "Loading resource telemetry from API..."
        elif self._state == STATE_FAILED:
            msg = (
                f"Failed to load telemetry: {self._error_message}"
                if self._error_message
                else "Failed to load resource telemetry."
            )
        else:
            msg = (
                "No resource snapshots available to plot for the active "
                "filters."
            )

        painter.drawText(
            QRectF(0, 0, float(w), float(h)),
            Qt.AlignmentFlag.AlignCenter,
            msg,
        )

    def _render_empty_series_message(
        self, painter: QPainter, w: int, h: int
    ) -> None:
        """Render honest message when snapshots exist but have no valid metrics."""
        painter.setFont(QFont(FONT_FAMILY_SANS, FONT_SIZE_SMALL_METADATA))
        painter.setPen(QColor(TEXT_SECONDARY))
        painter.drawText(
            QRectF(0, 0, float(w), float(h)),
            Qt.AlignmentFlag.AlignCenter,
            "No telemetry measurements recorded across displayed snapshots.",
        )

    def _render_grid_and_y_labels(
        self,
        painter: QPainter,
        left: float,
        right: float,
        top: float,
        bottom: float,
        height: float,
    ) -> None:
        """Render subtle grid lines and formatted Y-axis ticks."""
        font = QFont(FONT_FAMILY_MONO, FONT_SIZE_SMALL_METADATA)
        painter.setFont(font)

        grid_pen = QPen(QColor(BORDER), 1, Qt.PenStyle.DashLine)
        text_color = QColor(TEXT_SECONDARY)

        if self._mode == MODE_UTILIZATION:
            fractions = (1.0, 0.75, 0.5, 0.25, 0.0)
            labels = ("100%", "75%", "50%", "25%", "0%")
            for frac, lbl in zip(fractions, labels, strict=False):
                y = bottom - frac * height
                painter.setPen(grid_pen)
                painter.drawLine(QPointF(left, y), QPointF(right, y))
                painter.setPen(text_color)
                painter.drawText(
                    QRectF(0, y - 8, left - 8, 16),
                    Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                    lbl,
                )
        elif self._mode == MODE_MEMORY:
            max_bytes = 0
            for p in self._points:
                if p.memory_total is not None and p.memory_total > max_bytes:
                    max_bytes = p.memory_total
                if p.memory_used is not None and p.memory_used > max_bytes:
                    max_bytes = p.memory_used
            if max_bytes <= 0:
                max_bytes = 1

            mem_fractions = (1.0, 0.5, 0.0)
            for frac in mem_fractions:
                y = bottom - frac * height
                painter.setPen(grid_pen)
                painter.drawLine(QPointF(left, y), QPointF(right, y))
                painter.setPen(text_color)
                lbl = format_bytes(int(frac * max_bytes))
                painter.drawText(
                    QRectF(0, y - 8, left - 8, 16),
                    Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                    lbl,
                )
        elif self._mode == MODE_DISK_IO:
            max_bytes = 0
            for p in self._points:
                if (
                    p.disk_read_bytes is not None
                    and p.disk_read_bytes > max_bytes
                ):
                    max_bytes = p.disk_read_bytes
                if (
                    p.disk_write_bytes is not None
                    and p.disk_write_bytes > max_bytes
                ):
                    max_bytes = p.disk_write_bytes
            if max_bytes <= 0:
                max_bytes = 1

            disk_fractions = (1.0, 0.5, 0.0)
            for frac in disk_fractions:
                y = bottom - frac * height
                painter.setPen(grid_pen)
                painter.drawLine(QPointF(left, y), QPointF(right, y))
                painter.setPen(text_color)
                lbl = format_bytes(int(frac * max_bytes))
                painter.drawText(
                    QRectF(0, y - 8, left - 8, 16),
                    Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                    lbl,
                )

    def _render_time_axis(
        self,
        painter: QPainter,
        left: float,
        right: float,
        bottom: float,
        width: float,
    ) -> None:
        """Render baseline and timestamp markers at oldest and newest points."""
        painter.setPen(QPen(QColor(BORDER), 1, Qt.PenStyle.SolidLine))
        painter.drawLine(QPointF(left, bottom), QPointF(right, bottom))

        if not self._points or not self._cached_x:
            return

        font = QFont(FONT_FAMILY_MONO, FONT_SIZE_SMALL_METADATA)
        painter.setFont(font)
        painter.setPen(QColor(TEXT_SECONDARY))

        spans_multiple_days = (
            self._points[0].dt.date() != self._points[-1].dt.date()
        )
        fmt = "%m-%d %H:%M" if spans_multiple_days else "%H:%M:%S"

        first_x = self._cached_x[0]
        first_lbl = self._points[0].dt.strftime(fmt)
        last_lbl = self._points[-1].dt.strftime(fmt)

        if (
            len(self._points) == 1
            or first_lbl == last_lbl
            or (self._cached_x[-1] - first_x < 90)
        ):
            center_x = (first_x + self._cached_x[-1]) / 2.0
            painter.drawText(
                QRectF(center_x - 45, bottom + 4, 90, 20),
                Qt.AlignmentFlag.AlignCenter,
                first_lbl,
            )
        else:
            last_x = self._cached_x[-1]
            painter.drawText(
                QRectF(first_x - 10, bottom + 4, 80, 20),
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                first_lbl,
            )
            painter.drawText(
                QRectF(last_x - 70, bottom + 4, 80, 20),
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                last_lbl,
            )

    def _render_series(self, painter: QPainter) -> None:
        """Render non-interpolated polylines and points for each series."""
        series_specs: list[tuple[str, str]] = []
        if self._mode == MODE_UTILIZATION:
            series_specs = [
                ("cpu", COLOR_CPU),
                ("memory", COLOR_MEMORY),
                ("disk", COLOR_DISK),
            ]
        elif self._mode == MODE_MEMORY:
            series_specs = [
                ("memory_total", COLOR_MEM_TOTAL),
                ("memory_used", COLOR_CPU),
            ]
        elif self._mode == MODE_DISK_IO:
            series_specs = [
                ("disk_read", COLOR_MEMORY),
                ("disk_write", COLOR_DISK_WRITE),
            ]

        for series_key, hex_color in series_specs:
            y_vals = self._cached_y_series.get(series_key, [])
            if not y_vals:
                continue

            color = QColor(hex_color)
            line_pen = QPen(color, 2, Qt.PenStyle.SolidLine)
            point_brush = QBrush(color)

            # Draw contiguous segments (breaks across None to avoid interpolation)
            segments: list[list[QPointF]] = []
            current_segment: list[QPointF] = []

            for x, y in zip(self._cached_x, y_vals, strict=False):
                if y is not None:
                    current_segment.append(QPointF(x, y))
                else:
                    if current_segment:
                        segments.append(current_segment)
                        current_segment = []
            if current_segment:
                segments.append(current_segment)

            # Draw segment lines
            painter.setPen(line_pen)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            for seg in segments:
                if len(seg) >= 2:
                    for i in range(len(seg) - 1):
                        painter.drawLine(seg[i], seg[i + 1])

            # Draw distinct point circles (radius 3.0px)
            painter.setPen(QPen(QColor(SURFACE_0), 1))
            painter.setBrush(point_brush)
            for seg in segments:
                for pt in seg:
                    painter.drawEllipse(pt, 3.0, 3.0)

    def _render_selection(
        self, painter: QPainter, top: float, bottom: float
    ) -> None:
        """Render vertical dashed guide line and halo around selected point."""
        if self._selected_snapshot is None or not self._points:
            return

        target_id = self._selected_snapshot.id
        match_idx = -1
        for idx, pt in enumerate(self._points):
            if pt.snapshot.id == target_id:
                match_idx = idx
                break

        if match_idx < 0 or match_idx >= len(self._cached_x):
            return

        x = self._cached_x[match_idx]

        # Vertical guide line
        guide_pen = QPen(QColor(ACCENT_FOCUS), 1, Qt.PenStyle.DashLine)
        painter.setPen(guide_pen)
        painter.drawLine(QPointF(x, top), QPointF(x, bottom))

        # Halos around valid metric points at this timestamp
        halo_pen = QPen(QColor(ACCENT_FOCUS), 2, Qt.PenStyle.SolidLine)
        painter.setPen(halo_pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)

        for y_vals in self._cached_y_series.values():
            if match_idx < len(y_vals):
                y = y_vals[match_idx]
                if y is not None:
                    painter.drawEllipse(QPointF(x, y), 6.5, 6.5)

    def _render_hover(
        self, painter: QPainter, top: float, bottom: float
    ) -> None:
        """Render subtle vertical indicator line when hovering over points."""
        if (
            self._hovered_index is None
            or self._hovered_index < 0
            or self._hovered_index >= len(self._cached_x)
        ):
            return

        x = self._cached_x[self._hovered_index]
        pen = QPen(QColor(SURFACE_2), 1, Qt.PenStyle.SolidLine)
        painter.setPen(pen)
        painter.drawLine(QPointF(x, top), QPointF(x, bottom))

    # -----------------------------------------------------------------------
    # Mouse & Hit Testing
    # -----------------------------------------------------------------------

    def resizeEvent(self, event: Any) -> None:  # noqa: N802
        """Invalidate coordinates on geometry changes."""
        super().resizeEvent(event)
        self._dirty_coords = True

    def mouseMoveEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        """Track nearest point horizontally and display contextual tooltip."""
        self._ensure_coordinates()
        if not self._points or not self._cached_x:
            super().mouseMoveEvent(event)
            return

        mx = event.position().x()
        my = event.position().y()
        closest_idx = self._find_closest_point_index(mx, my)

        if closest_idx is not None and 0 <= closest_idx < len(self._points):
            if self._hovered_index != closest_idx:
                self._hovered_index = closest_idx
                self.update()

            pt = self._points[closest_idx]
            tip_time = (
                pt.snapshot.timestamp
                or pt.snapshot.created_at
                or pt.formatted_time
            )
            tip_lines = [f"Time: {tip_time}"]
            if self._mode == MODE_UTILIZATION:
                tip_lines.append(f"CPU: {format_percent(pt.cpu_percent)}")
                tip_lines.append(f"Memory: {format_percent(pt.memory_percent)}")
                tip_lines.append(
                    f"Disk: {format_percent(pt.disk_usage_percent)}"
                )
            elif self._mode == MODE_MEMORY:
                tip_lines.append(f"Used: {format_bytes(pt.memory_used)}")
                tip_lines.append(f"Total: {format_bytes(pt.memory_total)}")
                tip_lines.append(
                    f"Utilization: {format_percent(pt.memory_percent)}"
                )
            elif self._mode == MODE_DISK_IO:
                tip_lines.append(
                    f"Disk Read: {format_bytes(pt.disk_read_bytes)} "
                    "(cumulative)"
                )
                tip_lines.append(
                    f"Disk Write: {format_bytes(pt.disk_write_bytes)} "
                    "(cumulative)"
                )
                tip_lines.append(
                    f"Disk Usage: {format_percent(pt.disk_usage_percent)}"
                )

            QToolTip.showText(
                event.globalPosition().toPoint(), "\n".join(tip_lines), self
            )
        else:
            if self._hovered_index is not None:
                self._hovered_index = None
                QToolTip.hideText()
                self.update()

        super().mouseMoveEvent(event)

    def leaveEvent(self, event: Any) -> None:  # noqa: N802
        """Clear hover state on mouse leave."""
        if self._hovered_index is not None:
            self._hovered_index = None
            QToolTip.hideText()
            self.update()
        super().leaveEvent(event)

    def mousePressEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        """Select snapshot on left click within threshold."""
        if (
            event.button() == Qt.MouseButton.LeftButton
            and self._points
        ):
            mx = event.position().x()
            my = event.position().y()
            closest_idx = self._find_closest_point_index(mx, my)
            if closest_idx is not None and 0 <= closest_idx < len(self._points):
                selected_snap = self._points[closest_idx].snapshot
                self.point_clicked.emit(selected_snap)
                return
        super().mousePressEvent(event)

    def _find_closest_point_index(
        self,
        mouse_x: float,
        mouse_y: float | None = None,
        threshold_px: float = 24.0,
    ) -> int | None:
        """Return the index of the closest point within threshold distance.

        When mouse_y is provided, bounds checks the chart canvas and evaluates
        2D distance across visible metric series for accurate resolution of
        clustered or tie-broken points sharing identical timestamps.
        """
        self._ensure_coordinates()
        if not self._cached_x or not self._points:
            return None

        num_points = min(len(self._cached_x), len(self._points))
        if num_points == 0:
            return None

        # Check vertical plot boundaries if mouse_y is provided
        if mouse_y is not None:
            plot_top = float(self.TOP_MARGIN)
            h = self.height()
            plot_bottom = float(max(plot_top + 10, h - self.BOTTOM_MARGIN))
            if mouse_y < plot_top - 12.0 or mouse_y > plot_bottom + 12.0:
                return None

        best_idx: int | None = None
        min_dist = float("inf")

        for idx in range(num_points):
            px = self._cached_x[idx]
            dx = abs(px - mouse_x)
            if dx > threshold_px:
                continue

            if mouse_y is not None:
                valid_ys: list[float] = [
                    float(y_val)
                    for y_list in self._cached_y_series.values()
                    if idx < len(y_list)
                    and (y_val := y_list[idx]) is not None
                ]
                if valid_ys:
                    dy = min(abs(y - mouse_y) for y in valid_ys)
                    dist = math.hypot(dx, dy)
                else:
                    dist = dx
            else:
                dist = dx

            if dist < min_dist:
                min_dist = dist
                best_idx = idx

        effective_limit = (
            threshold_px * 2.5 if mouse_y is not None else threshold_px
        )
        if best_idx is not None and min_dist <= effective_limit:
            return best_idx
        return None


class ResourceTrendChartsWidget(QFrame):
    """Container widget coordinating telemetry trend visualization.

    Manages chronological telemetry sorting, multi-series rendering, scope
    disclosure, mode switching, and deterministic selection synchronization.
    """

    snapshot_selected = Signal(object)
    mode_changed = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("ResourceTrendChartsWidget")
        self.setFrameShape(QFrame.Shape.StyledPanel)

        self._collection: ResourceSnapshotCollection | None = None
        self._query: Any = None
        self._snapshots: list[ResourceSnapshot] = []
        self._points: list[TrendPoint] = []
        self._state: str = STATE_NOT_LOADED
        self._mode: str = MODE_UTILIZATION
        self._selected_snapshot: ResourceSnapshot | None = None
        self._scope_text: str = "Telemetry not loaded"
        self._scope_badge_text: str = "NOT LOADED"
        self._is_complete_history: bool = False

        # Root layout
        root = QVBoxLayout(self)
        root.setContentsMargins(SPACE_3, SPACE_2, SPACE_3, SPACE_2)
        root.setSpacing(SPACE_1)

        # 1. Header Toolbar
        header = QWidget(self)
        header.setObjectName("ResourceTrendHeader")
        h_ly = QHBoxLayout(header)
        h_ly.setContentsMargins(0, 0, 0, 0)
        h_ly.setSpacing(SPACE_2)

        self._title_label = QLabel("Historical Telemetry Trends", header)
        self._title_label.setObjectName("ResourceTrendTitle")

        self._scope_badge = QLabel("NOT LOADED", header)
        self._scope_badge.setObjectName("ResourceTrendScopeBadge")
        self._scope_badge.setProperty("scope", "none")

        self._scope_label = QLabel("Telemetry not loaded", header)
        self._scope_label.setObjectName("ResourceTrendScopeLabel")

        self._mode_combo = QComboBox(header)
        self._mode_combo.setObjectName("ResourceTrendModeCombo")
        for label, val in MODE_OPTIONS:
            self._mode_combo.addItem(label, val)
        self._mode_combo.currentIndexChanged.connect(
            self._handle_mode_selection
        )

        h_ly.addWidget(self._title_label)
        h_ly.addWidget(self._scope_badge)
        h_ly.addWidget(self._scope_label)
        h_ly.addStretch(1)
        h_ly.addWidget(self._mode_combo)
        root.addWidget(header)

        # 2. Vector Canvas
        self._canvas = _TrendCanvas(self)
        self._canvas.point_clicked.connect(self._handle_canvas_click)
        root.addWidget(self._canvas, 1)

        # 3. Legend Bar
        self._legend_widget = QWidget(self)
        self._legend_widget.setObjectName("ResourceTrendLegend")
        leg_ly = QHBoxLayout(self._legend_widget)
        leg_ly.setContentsMargins(0, 0, 0, 0)
        leg_ly.setSpacing(SPACE_3)

        self._legend_cpu = QLabel("■ CPU %", self._legend_widget)
        self._legend_cpu.setObjectName("ResourceTrendLegendCpu")
        self._legend_cpu.setStyleSheet(f"color: {COLOR_CPU};")

        self._legend_mem = QLabel("■ Memory %", self._legend_widget)
        self._legend_mem.setObjectName("ResourceTrendLegendMemory")
        self._legend_mem.setStyleSheet(f"color: {COLOR_MEMORY};")

        self._legend_disk = QLabel("■ Disk Usage %", self._legend_widget)
        self._legend_disk.setObjectName("ResourceTrendLegendDisk")
        self._legend_disk.setStyleSheet(f"color: {COLOR_DISK};")

        leg_ly.addWidget(self._legend_cpu)
        leg_ly.addWidget(self._legend_mem)
        leg_ly.addWidget(self._legend_disk)
        leg_ly.addStretch(1)
        root.addWidget(self._legend_widget)

    # -----------------------------------------------------------------------
    # Public Properties
    # -----------------------------------------------------------------------

    @property
    def collection(self) -> ResourceSnapshotCollection | None:
        """Return the currently bound ResourceSnapshotCollection or None."""
        return self._collection

    @property
    def query(self) -> Any:
        """Return the active query associated with the current collection."""
        return self._query

    @property
    def snapshots(self) -> tuple[ResourceSnapshot, ...]:
        """Return raw snapshots in their original collection order."""
        return tuple(self._snapshots)

    @property
    def chronological_snapshots(self) -> list[ResourceSnapshot]:
        """Return snapshots arranged chronologically without mutating collection."""
        return [p.snapshot for p in self._points]

    @property
    def trend_points(self) -> list[TrendPoint]:
        """Return normalized, sorted trend points."""
        return list(self._points)

    @property
    def selected_snapshot(self) -> ResourceSnapshot | None:
        """Return the currently highlighted snapshot or None."""
        return self._selected_snapshot

    @property
    def mode(self) -> str:
        """Return active metric visualization mode."""
        return self._mode

    @property
    def state(self) -> str:
        """Return active view state."""
        return self._state

    @property
    def is_complete_history(self) -> bool:
        """Return True only if current page covers the entire historical result."""
        return self._is_complete_history

    @property
    def scope_text(self) -> str:
        """Return formatted pagination scope description."""
        return self._scope_text

    @property
    def scope_badge_text(self) -> str:
        """Return short badge descriptor for scope status."""
        return self._scope_badge_text

    @property
    def canvas(self) -> _TrendCanvas:
        """Return vector rendering canvas."""
        return self._canvas

    @property
    def title_label(self) -> QLabel:
        """Return title label."""
        return self._title_label

    @property
    def scope_label(self) -> QLabel:
        """Return scope details label."""
        return self._scope_label

    @property
    def scope_badge(self) -> QLabel:
        """Return scope badge label."""
        return self._scope_badge

    @property
    def mode_combo(self) -> QComboBox:
        """Return mode selection combo box."""
        return self._mode_combo

    # -----------------------------------------------------------------------
    # Public State API
    # -----------------------------------------------------------------------

    def set_collection(
        self,
        collection: ResourceSnapshotCollection | None,
        query: Any = None,
    ) -> None:
        """Populate trend points from an authenticated ResourceSnapshotCollection."""
        if collection is None:
            self.set_not_loaded()
            return

        if not isinstance(collection, ResourceSnapshotCollection):
            raise TypeError(
                f"Expected ResourceSnapshotCollection, got {type(collection).__name__}"
            )

        # Avoid expensive redundant redraws when data and query have not changed
        if (
            self._collection == collection
            and self._query == query
            and self._state == STATE_LOADED
        ):
            return

        self._collection = collection
        self._query = query
        self._snapshots = list(collection.items)
        self._selected_snapshot = None

        total = collection.total
        limit = collection.limit
        offset = collection.offset
        count = len(self._snapshots)

        # 1. Build sorted chronological points without mutating collection
        sorted_snaps = sorted(self._snapshots, key=_snapshot_sort_key)
        points: list[TrendPoint] = []
        dt_min = datetime.min.replace(tzinfo=timezone.utc)
        for snap in sorted_snaps:
            parsed_dt = (
                _parse_iso_utc(snap.timestamp)
                or _parse_iso_utc(snap.created_at)
                or dt_min
            )
            points.append(
                TrendPoint(
                    snapshot=snap,
                    dt=parsed_dt,
                    formatted_time=parsed_dt.strftime("%H:%M:%S"),
                    cpu_percent=snap.cpu_percent,
                    memory_percent=snap.memory_percent,
                    disk_usage_percent=snap.disk_usage_percent,
                    memory_used=snap.memory_used,
                    memory_total=snap.memory_total,
                    disk_read_bytes=snap.disk_read_bytes,
                    disk_write_bytes=snap.disk_write_bytes,
                )
            )
        self._points = points

        # 2. Calculate honest scope metadata
        if count == 0:
            self._state = STATE_EMPTY
            self._is_complete_history = (total == 0)
            self._scope_badge_text = "EMPTY"
            base_scope = f"0 of {total} snapshots"
            self._scope_badge.setProperty("scope", "empty")
        else:
            self._state = STATE_LOADED
            if count >= total:
                self._is_complete_history = True
                self._scope_badge_text = "COMPLETE HISTORY"
                base_scope = f"All {total} snapshots displayed"
                self._scope_badge.setProperty("scope", "complete")
            else:
                self._is_complete_history = False
                self._scope_badge_text = "CURRENT PAGE SCOPE"
                start_idx = offset + 1
                end_idx = offset + count
                page_idx = (offset // limit) + 1 if limit > 0 else 1
                total_pages = math.ceil(total / limit) if limit > 0 else 1
                base_scope = (
                    f"Page {page_idx} of {total_pages} "
                    f"({count} of {total} snapshots, #{start_idx}–{end_idx})"
                )
                self._scope_badge.setProperty("scope", "partial")

        # Reflect active query filters in stated scope (Requirement 9)
        if self._query is not None:
            host_val = getattr(self._query, "host_id", None)
            if host_val:
                short_host = str(host_val)[:8]
                base_scope += f" [host: {short_host}…]"
            elif getattr(self._query, "has_active_filters", False):
                base_scope += " [filtered]"

        self._scope_text = base_scope
        self._scope_badge.setText(self._scope_badge_text)
        self._scope_label.setText(self._scope_text)
        self._repolish_badge()

        self._canvas.set_data(
            points=self._points,
            mode=self._mode,
            state=self._state,
            selected_snapshot=None,
        )

    def set_loading(self) -> None:
        """Transition into loading state while preserving retained telemetry."""
        self._state = STATE_LOADING
        self._selected_snapshot = None

        if self._points:
            self._scope_text = (
                f"{self._scope_text} — Refreshing from API..."
            )
            self._scope_label.setText(self._scope_text)
        else:
            self._scope_badge_text = "LOADING"
            self._scope_text = "Querying backend API..."
            self._scope_badge.setText(self._scope_badge_text)
            self._scope_label.setText(self._scope_text)
            self._scope_badge.setProperty("scope", "loading")
            self._repolish_badge()

        self._canvas.set_data(
            points=self._points,
            mode=self._mode,
            state=self._state,
            selected_snapshot=None,
        )

    def set_error(self, message: str) -> None:
        """Transition into failed state while preserving retained telemetry."""
        self._state = STATE_FAILED
        self._selected_snapshot = None

        if self._points:
            self._scope_badge_text = "RETAINED SCOPE"
            self._scope_text = (
                f"{self._scope_text} — Refresh failed: {message}"
            )
            self._scope_badge.setProperty("scope", "retained")
        else:
            self._scope_badge_text = "LOAD FAILED"
            self._scope_text = message
            self._scope_badge.setProperty("scope", "failed")

        self._scope_badge.setText(self._scope_badge_text)
        self._scope_label.setText(self._scope_text)
        self._repolish_badge()

        self._canvas.set_data(
            points=self._points,
            mode=self._mode,
            state=self._state,
            selected_snapshot=None,
            error_message=message,
        )

    def set_not_loaded(self) -> None:
        """Reset widget to initial un-queried state."""
        self._collection = None
        self._query = None
        self._snapshots = []
        self._points = []
        self._selected_snapshot = None
        self._state = STATE_NOT_LOADED
        self._is_complete_history = False
        self._scope_badge_text = "NOT LOADED"
        self._scope_text = "Telemetry not loaded"

        self._scope_badge.setText(self._scope_badge_text)
        self._scope_label.setText(self._scope_text)
        self._scope_badge.setProperty("scope", "none")
        self._repolish_badge()

        self._canvas.set_data(
            points=[],
            mode=self._mode,
            state=self._state,
            selected_snapshot=None,
        )

    def clear(self) -> None:
        """Alias for set_not_loaded."""
        self.set_not_loaded()

    def select_snapshot(self, snapshot: ResourceSnapshot | None) -> None:
        """Synchronize highlight without triggering signals or mutations."""
        if snapshot is None:
            self._selected_snapshot = None
        else:
            # Only select if snapshot exists in current collection
            target_id = snapshot.id
            if any(p.snapshot.id == target_id for p in self._points):
                self._selected_snapshot = snapshot
            else:
                self._selected_snapshot = None

        self._canvas.set_selected_snapshot(self._selected_snapshot)

    def set_mode(self, mode: str) -> None:
        """Switch active metric mode and update legend accordingly."""
        if mode not in (MODE_UTILIZATION, MODE_MEMORY, MODE_DISK_IO):
            raise ValueError(f"Unsupported trend chart mode: {mode}")

        if self._mode != mode:
            self._mode = mode
            idx = self._mode_combo.findData(mode)
            if idx >= 0:
                self._mode_combo.setCurrentIndex(idx)
            self._update_legend_for_mode()
            self._canvas.set_mode(mode)
            self.mode_changed.emit(mode)

    # -----------------------------------------------------------------------
    # Internal Handlers
    # -----------------------------------------------------------------------

    def _handle_mode_selection(self, index: int) -> None:
        """Handle user mode selection from combo box."""
        mode_val = self._mode_combo.itemData(index)
        if isinstance(mode_val, str) and mode_val != self._mode:
            self.set_mode(mode_val)

    def _update_legend_for_mode(self) -> None:
        """Update legend labels and colors based on active mode."""
        if self._mode == MODE_UTILIZATION:
            self._legend_cpu.setText("■ CPU %")
            self._legend_cpu.setStyleSheet(f"color: {COLOR_CPU};")
            self._legend_mem.setText("■ Memory %")
            self._legend_mem.setStyleSheet(f"color: {COLOR_MEMORY};")
            self._legend_disk.setText("■ Disk Usage %")
            self._legend_disk.setStyleSheet(f"color: {COLOR_DISK};")
            self._legend_disk.setVisible(True)
        elif self._mode == MODE_MEMORY:
            self._legend_cpu.setText("■ Memory Used")
            self._legend_cpu.setStyleSheet(f"color: {COLOR_CPU};")
            self._legend_mem.setText("■ Memory Total")
            self._legend_mem.setStyleSheet(f"color: {COLOR_MEM_TOTAL};")
            self._legend_disk.setVisible(False)
        elif self._mode == MODE_DISK_IO:
            self._legend_cpu.setText("■ Disk Read (Cumulative)")
            self._legend_cpu.setStyleSheet(f"color: {COLOR_MEMORY};")
            self._legend_mem.setText("■ Disk Write (Cumulative)")
            self._legend_mem.setStyleSheet(f"color: {COLOR_DISK_WRITE};")
            self._legend_disk.setVisible(False)

    def _handle_canvas_click(self, snapshot: Any) -> None:
        """Forward canvas point click to snapshot_selected signal."""
        if isinstance(snapshot, ResourceSnapshot):
            self._selected_snapshot = snapshot
            self._canvas.set_selected_snapshot(snapshot)
            self.snapshot_selected.emit(snapshot)

    def _repolish_badge(self) -> None:
        """Trigger QSS repolish on the scope badge."""
        style = self._scope_badge.style()
        if style is not None:
            style.unpolish(self._scope_badge)
            style.polish(self._scope_badge)


__all__ = [
    "COLOR_CPU",
    "COLOR_DISK",
    "COLOR_DISK_WRITE",
    "COLOR_MEMORY",
    "COLOR_MEM_TOTAL",
    "MODE_DISK_IO",
    "MODE_MEMORY",
    "MODE_OPTIONS",
    "MODE_UTILIZATION",
    "ResourceTrendChartsWidget",
    "STATE_EMPTY",
    "STATE_FAILED",
    "STATE_LOADED",
    "STATE_LOADING",
    "STATE_NOT_LOADED",
    "TrendPoint",
]
