"""OSIRIS Live Resources View.

Provides ResourcesView, the native PySide6 widget presenting observed
host resource snapshots retrieved from the REST API in a dense
investigator-oriented table backed by ResourcesTableModel, with
API-backed query controls for host filtering, time-range querying,
result limits, and deterministic pagination.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any

from PySide6.QtCore import (
    QDateTime,
    QItemSelectionModel,
    Qt,
    QTimeZone,
    Signal,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDateTimeEdit,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from desktop.client.models import ResourceSnapshot, ResourceSnapshotCollection
from desktop.models.resources_model import (
    COLUMN_TIMESTAMP,
    ResourceSnapshotRole,
    ResourcesTableModel,
    find_latest_resource_snapshot,
)
from desktop.ui.components.cards import MetricCard
from desktop.ui.components.resource_charts import (
    ResourceTrendChartsWidget,
)
from desktop.ui.components.resource_inspector_panel import (
    ResourceInspectorPanel,
)
from desktop.ui.components.resources_summary_cards import (
    ResourcesSummaryCardsFrame,
)
from desktop.ui.design_tokens import (
    SPACE_1,
    SPACE_2,
    SPACE_3,
    SPACE_4,
    SPACE_6,
    TABLE_ROW_HEIGHT,
)

# Canonical state identifiers
STATE_NOT_LOADED: str = "not_loaded"
STATE_LOADING: str = "loading"
STATE_LOADED: str = "loaded"
STATE_EMPTY: str = "empty"
STATE_FAILED: str = "failed"

DEFAULT_PAGE_SIZE: int = 50


@dataclass(frozen=True)
class ResourcesQuery:
    """Normalized query parameters for server-side resource snapshot requests.

    Captures active query criteria and server-side limit/offset constraints.
    Immutable to guarantee safe cross-thread handling between UI and workers.
    """

    host_id: str | uuid.UUID | None = None
    start_time: str | datetime | None = None
    end_time: str | datetime | None = None
    limit: int = DEFAULT_PAGE_SIZE
    offset: int = 0

    def __post_init__(self) -> None:
        """Validate query attributes upon construction."""
        if self.host_id is not None:
            if isinstance(self.host_id, bool) or not isinstance(
                self.host_id, (str, uuid.UUID)
            ):
                raise ValueError("host_id must be a UUID string or None")
            try:
                uuid_obj = (
                    self.host_id
                    if isinstance(self.host_id, uuid.UUID)
                    else uuid.UUID(str(self.host_id))
                )
            except (ValueError, TypeError, AttributeError) as exc:
                raise ValueError(
                    f"host_id must be a valid UUID: {exc}"
                ) from exc
            object.__setattr__(self, "host_id", str(uuid_obj))

        start_dt: datetime | None = None
        if self.start_time is not None:
            if isinstance(self.start_time, bool) or not isinstance(
                self.start_time, (str, datetime)
            ):
                raise ValueError(
                    "start_time must be an ISO timestamp string or datetime"
                )
            if isinstance(self.start_time, datetime):
                start_dt = (
                    self.start_time
                    if self.start_time.tzinfo is not None
                    else self.start_time.replace(tzinfo=timezone.utc)
                )
            else:
                cleaned = self.start_time.strip()
                if not cleaned:
                    raise ValueError("start_time must not be empty")
                try:
                    p_dt = datetime.fromisoformat(
                        cleaned.replace("Z", "+00:00")
                    )
                    start_dt = (
                        p_dt
                        if p_dt.tzinfo is not None
                        else p_dt.replace(tzinfo=timezone.utc)
                    )
                except (ValueError, TypeError) as exc:
                    raise ValueError(
                        f"Invalid start_time ISO timestamp: {exc}"
                    ) from exc

        end_dt: datetime | None = None
        if self.end_time is not None:
            if isinstance(self.end_time, bool) or not isinstance(
                self.end_time, (str, datetime)
            ):
                raise ValueError(
                    "end_time must be an ISO timestamp string or datetime"
                )
            if isinstance(self.end_time, datetime):
                end_dt = (
                    self.end_time
                    if self.end_time.tzinfo is not None
                    else self.end_time.replace(tzinfo=timezone.utc)
                )
            else:
                cleaned = self.end_time.strip()
                if not cleaned:
                    raise ValueError("end_time must not be empty")
                try:
                    p_dt = datetime.fromisoformat(
                        cleaned.replace("Z", "+00:00")
                    )
                    end_dt = (
                        p_dt
                        if p_dt.tzinfo is not None
                        else p_dt.replace(tzinfo=timezone.utc)
                    )
                except (ValueError, TypeError) as exc:
                    raise ValueError(
                        f"Invalid end_time ISO timestamp: {exc}"
                    ) from exc

        if start_dt is not None and end_dt is not None:
            if start_dt > end_dt:
                raise ValueError(
                    "start_time must be less than or equal to end_time"
                )

        if (
            isinstance(self.limit, bool)
            or not isinstance(self.limit, int)
            or not (1 <= self.limit <= 100)
        ):
            raise ValueError("limit must be an integer between 1 and 100")

        if (
            isinstance(self.offset, bool)
            or not isinstance(self.offset, int)
            or self.offset < 0
        ):
            raise ValueError("offset must be a non-negative integer")

    @property
    def has_active_filters(self) -> bool:
        """Return True if any filter criteria other than pagination are set."""
        return any(
            v is not None
            for v in (
                self.host_id,
                self.start_time,
                self.end_time,
            )
        )

    @property
    def page_index(self) -> int:
        """Return the 0-based page index calculated from offset and limit."""
        if self.limit <= 0:
            return 0
        return self.offset // self.limit

    def to_client_kwargs(self) -> dict[str, Any]:
        """Convert query into validated keyword arguments for API client."""
        kwargs: dict[str, Any] = {
            "limit": self.limit,
            "offset": self.offset,
        }
        if self.host_id is not None:
            kwargs["host_id"] = self.host_id
        if self.start_time is not None:
            kwargs["start_time"] = self.start_time
        if self.end_time is not None:
            kwargs["end_time"] = self.end_time
        return kwargs


class ResourcesFilterBar(QFrame):
    """Filter toolbar widget for the Resources view."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("ResourcesFilterBar")


class ResourcesPaginationBar(QFrame):
    """Pagination toolbar widget for the Resources view."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("ResourcesPaginationBar")
        self.setProperty("pagination", "true")


class ResourcesView(QWidget):
    """Primary visual interface for inspecting host resource telemetry in OSIRIS.

    Coordinates table presentation, query controls for host and time-range
    filtering, limit and pagination handling, record summaries, and
    loading/empty/error states.
    """

    load_requested = Signal()
    refresh_requested = Signal()
    query_requested = Signal(object)

    def __init__(
        self,
        model: ResourcesTableModel | None = None,
        parent: QWidget | None = None,
        page_size: int = DEFAULT_PAGE_SIZE,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("Page_Resources")
        self.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )

        self._state: str = STATE_NOT_LOADED
        self._is_active: bool = False
        self._page_size = page_size
        self._current_query = ResourcesQuery(limit=self._page_size, offset=0)
        self._model = (
            model if model is not None else ResourcesTableModel(parent=self)
        )

        root = QVBoxLayout(self)
        root.setContentsMargins(SPACE_6, SPACE_6, SPACE_6, SPACE_6)
        root.setSpacing(SPACE_4)

        # 1. Page Header
        header = QWidget(self)
        header.setObjectName("PageHeader_Resources")
        h_ly = QVBoxLayout(header)
        h_ly.setContentsMargins(0, 0, 0, 0)
        h_ly.setSpacing(SPACE_1)

        self._title_label = QLabel("Host Resources", header)
        self._title_label.setObjectName("PageTitle")

        self._desc_label = QLabel(
            "System telemetry and resource utilization across monitored "
            "endpoints. Server-side filtering and investigator pagination active.",
            header,
        )
        self._desc_label.setObjectName("PageDescription")

        h_ly.addWidget(self._title_label)
        h_ly.addWidget(self._desc_label)
        root.addWidget(header)

        # 2. Utilization Summary Cards
        self._summary_cards = ResourcesSummaryCardsFrame(parent=self)
        root.addWidget(self._summary_cards)

        # 3. Historical Telemetry Trend Charts
        self._trend_charts = ResourceTrendChartsWidget(parent=self)
        self._trend_charts.snapshot_selected.connect(
            self._handle_chart_snapshot_selected
        )
        root.addWidget(self._trend_charts)

        # 4. Filter Toolbar
        self._filter_bar = self._build_filter_bar()
        root.addWidget(self._filter_bar)

        # 4. Action Toolbar & Summary
        toolbar = QFrame(self)
        toolbar.setObjectName("ResourcesToolbar")
        t_ly = QHBoxLayout(toolbar)
        t_ly.setContentsMargins(0, 0, 0, 0)
        t_ly.setSpacing(SPACE_3)

        self._refresh_btn = QPushButton("Refresh Resources", toolbar)
        self._refresh_btn.setObjectName("RefreshResourcesButton")
        self._refresh_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._refresh_btn.clicked.connect(self._handle_refresh_click)

        self._count_label = QLabel("0 snapshots (not loaded)", toolbar)
        self._count_label.setObjectName("RecordCountSummary")

        t_ly.addWidget(self._refresh_btn)
        t_ly.addWidget(self._count_label)
        t_ly.addStretch(1)

        root.addWidget(toolbar)

        # 5. Status / Message Banner
        self._status_banner = QFrame(self)
        self._status_banner.setObjectName("ResourcesStatusBanner")
        b_ly = QHBoxLayout(self._status_banner)
        b_ly.setContentsMargins(SPACE_4, SPACE_3, SPACE_4, SPACE_3)
        b_ly.setSpacing(SPACE_3)

        banner_text_box = QWidget(self._status_banner)
        bt_ly = QVBoxLayout(banner_text_box)
        bt_ly.setContentsMargins(0, 0, 0, 0)
        bt_ly.setSpacing(SPACE_1)

        self._banner_title = QLabel("Resources Not Loaded", banner_text_box)
        self._banner_title.setObjectName("ResourcesStatusBannerTitle")

        self._banner_msg = QLabel(
            "Resource telemetry records have not been retrieved from the API "
            "yet. Click Refresh Resources to load.",
            banner_text_box,
        )
        self._banner_msg.setObjectName("ResourcesStatusBannerMessage")
        self._banner_msg.setWordWrap(True)

        bt_ly.addWidget(self._banner_title)
        bt_ly.addWidget(self._banner_msg)
        b_ly.addWidget(banner_text_box, 1)

        self._quick_reset_btn = QPushButton(
            "Clear Filters", self._status_banner
        )
        self._quick_reset_btn.setObjectName(
            "QuickResetResourcesFiltersButton"
        )
        self._quick_reset_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._quick_reset_btn.clicked.connect(self.clear_filters)
        self._quick_reset_btn.setVisible(False)
        b_ly.addWidget(self._quick_reset_btn)

        self._retry_btn = QPushButton("Retry", self._status_banner)
        self._retry_btn.setObjectName("RetryResourcesButton")
        self._retry_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._retry_btn.clicked.connect(self._handle_retry_click)
        self._retry_btn.setVisible(False)
        b_ly.addWidget(self._retry_btn)

        root.addWidget(self._status_banner)

        # 6. Dense Resources Table & Snapshot Details Inspector
        self._table = QTableView(self)
        self._table.setObjectName("ResourcesTable")
        self._table.setModel(self._model)
        self._table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self._table.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection
        )
        self._table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self._table.setSortingEnabled(False)
        self._table.setAlternatingRowColors(True)
        self._table.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )

        v_header = self._table.verticalHeader()
        v_header.setDefaultSectionSize(TABLE_ROW_HEIGHT)
        v_header.setVisible(True)

        h_header = self._table.horizontalHeader()
        h_header.setStretchLastSection(False)
        h_header.setDefaultAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        )
        self._configure_header_sections(h_header)

        content_layout = QHBoxLayout()
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(SPACE_3)
        content_layout.addWidget(self._table, 1)

        self._inspector = ResourceInspectorPanel(parent=self)
        self._inspector.close_requested.connect(
            self._handle_inspector_closed
        )
        self._inspector.hide()
        content_layout.addWidget(self._inspector, 0)

        root.addLayout(content_layout, 1)

        # Wire table selection model to update inspector
        sel_model = self._table.selectionModel()
        if sel_model is not None:
            sel_model.selectionChanged.connect(
                self._handle_selection_changed
            )

        # Connect model resets to clear selection, inspector, and update summaries
        self._model.modelReset.connect(self._handle_model_reset)

        # 7. Pagination Bar
        self._pagination_bar = self._build_pagination_bar()
        root.addWidget(self._pagination_bar)

        # Hidden frame for backward-compatible shell test tree inspection
        self._empty_frame = QFrame(self)
        self._empty_frame.setObjectName("EmptyStateFrame")
        self._empty_frame.hide()
        _empty_title = QLabel(
            "Live Telemetry Not Connected", self._empty_frame
        )
        _empty_title.setObjectName("EmptyStateTitle")
        _empty_msg = QLabel(
            "This view is operating in visual prototype mode.",
            self._empty_frame,
        )
        _empty_msg.setObjectName("EmptyStateMessage")

        # Apply initial visual state
        self._apply_state_ui()

    def _build_filter_bar(self) -> ResourcesFilterBar:
        """Construct the compact investigator filter toolbar for resources."""
        bar = ResourcesFilterBar(self)
        bar_ly = QVBoxLayout(bar)
        bar_ly.setContentsMargins(SPACE_3, SPACE_3, SPACE_3, SPACE_3)
        bar_ly.setSpacing(SPACE_2)

        # Row 1: Host ID & Limit
        row1 = QHBoxLayout()
        row1.setSpacing(SPACE_3)

        # Host ID input
        host_box = QVBoxLayout()
        host_box.setSpacing(SPACE_1)
        host_label = QLabel("Host ID", bar)
        host_label.setObjectName("ResourcesHostIdFilterLabel")
        self._host_input = QLineEdit(bar)
        self._host_input.setObjectName("ResourcesHostIdFilterInput")
        self._host_input.setPlaceholderText("UUID...")
        self._host_input.returnPressed.connect(self.apply_filters)
        host_box.addWidget(host_label)
        host_box.addWidget(self._host_input)
        row1.addLayout(host_box, 3)

        # Limit entry/selection
        limit_box = QVBoxLayout()
        limit_box.setSpacing(SPACE_1)
        limit_label = QLabel("Limit", bar)
        limit_label.setObjectName("ResourcesLimitFilterLabel")
        self._limit_combo = QComboBox(bar)
        self._limit_combo.setObjectName("ResourcesLimitFilterCombo")
        self._limit_combo.setEditable(True)
        for opt in (10, 25, 50, 100):
            self._limit_combo.addItem(str(opt), opt)
        self._limit_combo.setCurrentText(str(self._page_size))
        self._limit_input = self._limit_combo.lineEdit()
        if self._limit_input is not None:
            self._limit_input.setObjectName("ResourcesLimitFilterInput")
            self._limit_input.returnPressed.connect(self.apply_filters)
        limit_box.addWidget(limit_label)
        limit_box.addWidget(self._limit_combo)
        row1.addLayout(limit_box, 1)

        bar_ly.addLayout(row1)

        # Row 2: Time-range inputs
        row2 = QHBoxLayout()
        row2.setSpacing(SPACE_3)

        # Start Time Box
        start_box = QHBoxLayout()
        start_box.setSpacing(SPACE_2)
        start_lbl = QLabel("Start Time (UTC)", bar)
        start_lbl.setObjectName("ResourcesStartTimeFilterLabel")
        self._start_time_label = start_lbl

        self._start_time_check = QCheckBox("Enable", bar)
        self._start_time_check.setObjectName(
            "ResourcesStartTimeFilterCheckBox"
        )
        self._start_time_check.setChecked(False)

        self._start_time_edit = QDateTimeEdit(bar)
        self._start_time_edit.setObjectName("ResourcesStartTimeFilterEdit")
        self._start_time_edit.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        self._start_time_edit.setCalendarPopup(True)
        self._start_time_edit.setTimeZone(QTimeZone.utc())
        self._start_time_edit.setDateTime(QDateTime.currentDateTimeUtc())
        self._start_time_edit.setEnabled(False)

        self._start_time_check.toggled.connect(
            self._start_time_edit.setEnabled
        )

        start_box.addWidget(start_lbl)
        start_box.addWidget(self._start_time_check)
        start_box.addWidget(self._start_time_edit, 1)
        row2.addLayout(start_box, 1)

        # End Time Box
        end_box = QHBoxLayout()
        end_box.setSpacing(SPACE_2)
        end_lbl = QLabel("End Time (UTC)", bar)
        end_lbl.setObjectName("ResourcesEndTimeFilterLabel")
        self._end_time_label = end_lbl

        self._end_time_check = QCheckBox("Enable", bar)
        self._end_time_check.setObjectName("ResourcesEndTimeFilterCheckBox")
        self._end_time_check.setChecked(False)

        self._end_time_edit = QDateTimeEdit(bar)
        self._end_time_edit.setObjectName("ResourcesEndTimeFilterEdit")
        self._end_time_edit.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        self._end_time_edit.setCalendarPopup(True)
        self._end_time_edit.setTimeZone(QTimeZone.utc())
        self._end_time_edit.setDateTime(QDateTime.currentDateTimeUtc())
        self._end_time_edit.setEnabled(False)

        self._end_time_check.toggled.connect(
            self._end_time_edit.setEnabled
        )

        end_box.addWidget(end_lbl)
        end_box.addWidget(self._end_time_check)
        end_box.addWidget(self._end_time_edit, 1)
        row2.addLayout(end_box, 1)

        bar_ly.addLayout(row2)

        # Row 3: Action buttons & validation error
        row3 = QHBoxLayout()
        row3.setSpacing(SPACE_2)

        self._apply_btn = QPushButton("Apply Filters", bar)
        self._apply_btn.setObjectName("ApplyResourcesFiltersButton")
        self._apply_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._apply_btn.clicked.connect(self.apply_filters)

        self._clear_btn = QPushButton("Clear Filters", bar)
        self._clear_btn.setObjectName("ResetResourcesFiltersButton")
        self._clear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._clear_btn.clicked.connect(self.clear_filters)

        self._validation_label = QLabel("", bar)
        self._validation_label.setObjectName(
            "ResourcesFilterValidationLabel"
        )
        self._validation_label.setAccessibleName("Filter Validation Message")
        self._validation_label.setProperty("error", "false")
        self._validation_label.setWordWrap(True)

        row3.addWidget(self._apply_btn)
        row3.addWidget(self._clear_btn)
        row3.addWidget(self._validation_label, 1)

        bar_ly.addLayout(row3)
        return bar

    def _build_pagination_bar(self) -> ResourcesPaginationBar:
        """Construct the deterministic server-side pagination bar."""
        p_bar = ResourcesPaginationBar(self)
        p_ly = QHBoxLayout(p_bar)
        p_ly.setContentsMargins(0, SPACE_2, 0, 0)
        p_ly.setSpacing(SPACE_3)

        self._prev_btn = QPushButton("Previous", p_bar)
        self._prev_btn.setObjectName("ResourcesPrevPageButton")
        self._prev_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._prev_btn.clicked.connect(self.go_prev_page)
        self._prev_btn.setEnabled(False)

        self._page_range_label = QLabel("0 of 0 snapshots", p_bar)
        self._page_range_label.setObjectName("ResourcesPageRangeSummary")

        self._next_btn = QPushButton("Next", p_bar)
        self._next_btn.setObjectName("ResourcesNextPageButton")
        self._next_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._next_btn.clicked.connect(self.go_next_page)
        self._next_btn.setEnabled(False)

        p_ly.addWidget(self._prev_btn)
        p_ly.addWidget(self._page_range_label)
        p_ly.addWidget(self._next_btn)
        p_ly.addStretch(1)

        return p_bar

    def _configure_header_sections(self, header: QHeaderView) -> None:
        """Set compact investigator-console column sizing."""
        header.setMinimumSectionSize(60)
        for col_idx in range(len(self._model.COLUMNS)):
            if col_idx == COLUMN_TIMESTAMP:
                header.setSectionResizeMode(
                    col_idx, QHeaderView.ResizeMode.Interactive
                )
                header.resizeSection(col_idx, 180)
            else:
                header.setSectionResizeMode(
                    col_idx, QHeaderView.ResizeMode.ResizeToContents
                )

    # -----------------------------------------------------------------------
    # Public Properties & Accessors
    # -----------------------------------------------------------------------

    @property
    def model(self) -> ResourcesTableModel:
        """Return the underlying ResourcesTableModel instance."""
        return self._model

    @property
    def table(self) -> QTableView:
        """Return the QTableView displaying the resource snapshot records."""
        return self._table

    @property
    def refresh_button(self) -> QPushButton:
        """Return the Refresh Resources action button."""
        return self._refresh_btn

    @property
    def retry_button(self) -> QPushButton:
        """Return the Retry action button on the status banner."""
        return self._retry_btn

    @property
    def quick_reset_button(self) -> QPushButton:
        """Return the quick-reset button on the status banner."""
        return self._quick_reset_btn

    @property
    def status_banner(self) -> QFrame:
        """Return the status banner frame."""
        return self._status_banner

    @property
    def banner_title_label(self) -> QLabel:
        """Return the status banner title label."""
        return self._banner_title

    @property
    def banner_message_label(self) -> QLabel:
        """Return the status banner message label."""
        return self._banner_msg

    @property
    def record_count_label(self) -> QLabel:
        """Return the record count summary label."""
        return self._count_label

    @property
    def state(self) -> str:
        """Return the current view state identifier."""
        return self._state

    @property
    def current_query(self) -> ResourcesQuery:
        """Return the active normalized ResourcesQuery instance."""
        return self._current_query

    @property
    def page_size(self) -> int:
        """Return the configured default page size."""
        return self._page_size

    @property
    def filter_bar(self) -> ResourcesFilterBar:
        """Return the filter toolbar frame."""
        return self._filter_bar

    @property
    def host_input(self) -> QLineEdit:
        """Return the host ID filter input field."""
        return self._host_input

    @property
    def host_id_input(self) -> QLineEdit:
        """Alias for host_input."""
        return self._host_input

    @property
    def host_id(self) -> str | None:
        """Return active host ID text, or None if empty."""
        text = self._host_input.text().strip()
        return text if text else None

    def set_host_id(self, host_id: str | uuid.UUID | None) -> None:
        """Set the host ID filter input field value."""
        if host_id is None:
            self._host_input.clear()
        else:
            self._host_input.setText(str(host_id))

    @property
    def limit_combo(self) -> QComboBox:
        """Return the limit selection combo box."""
        return self._limit_combo

    @property
    def limit_input(self) -> QLineEdit | None:
        """Return the limit text entry field."""
        return self._limit_combo.lineEdit()

    @property
    def limit(self) -> int:
        """Return current limit value parsed from the limit control."""
        raw = self._limit_combo.currentText().strip()
        try:
            val = int(raw)
            if 1 <= val <= 100:
                return val
        except ValueError:
            pass
        return self._current_query.limit

    def set_limit(self, limit: int | str) -> None:
        """Set the limit value in the limit combo box."""
        self._limit_combo.setCurrentText(str(limit))

    @property
    def start_time_label(self) -> QLabel:
        """Return the Start Time filter label."""
        return self._start_time_label

    @property
    def start_time_check(self) -> QCheckBox:
        """Return the Start Time enable checkbox."""
        return self._start_time_check

    @property
    def start_time_checkbox(self) -> QCheckBox:
        """Alias for start_time_check."""
        return self._start_time_check

    @property
    def start_time_edit(self) -> QDateTimeEdit:
        """Return the Start Time QDateTimeEdit control."""
        return self._start_time_edit

    @property
    def end_time_label(self) -> QLabel:
        """Return the End Time filter label."""
        return self._end_time_label

    @property
    def end_time_check(self) -> QCheckBox:
        """Return the End Time enable checkbox."""
        return self._end_time_check

    @property
    def end_time_checkbox(self) -> QCheckBox:
        """Alias for end_time_check."""
        return self._end_time_check

    @property
    def end_time_edit(self) -> QDateTimeEdit:
        """Return the End Time QDateTimeEdit control."""
        return self._end_time_edit

    @property
    def start_time(self) -> str | None:
        """Return active start time ISO string, or None if disabled."""
        if not self._start_time_check.isChecked():
            return None
        return (
            self._start_time_edit.dateTime()
            .toUTC()
            .toString("yyyy-MM-ddTHH:mm:ss")
            + "Z"
        )

    @property
    def end_time(self) -> str | None:
        """Return active end time ISO string, or None if disabled."""
        if not self._end_time_check.isChecked():
            return None
        return (
            self._end_time_edit.dateTime()
            .toUTC()
            .toString("yyyy-MM-ddTHH:mm:ss")
            + "Z"
        )

    def set_start_time(self, dt: str | datetime | QDateTime | None) -> None:
        """Set the Start Time filter value and enable its checkbox."""
        if dt is None:
            self._start_time_check.setChecked(False)
            return
        qdt = self._coerce_qdatetime(dt)
        self._start_time_edit.setDateTime(qdt)
        self._start_time_check.setChecked(True)

    def set_end_time(self, dt: str | datetime | QDateTime | None) -> None:
        """Set the End Time filter value and enable its checkbox."""
        if dt is None:
            self._end_time_check.setChecked(False)
            return
        qdt = self._coerce_qdatetime(dt)
        self._end_time_edit.setDateTime(qdt)
        self._end_time_check.setChecked(True)

    @staticmethod
    def _coerce_qdatetime(val: str | datetime | QDateTime) -> QDateTime:
        """Convert supported datetime representation to UTC QDateTime."""
        if isinstance(val, QDateTime):
            return val.toUTC()
        if isinstance(val, datetime):
            dt_utc = (
                val.astimezone(timezone.utc)
                if val.tzinfo is not None
                else val.replace(tzinfo=timezone.utc)
            )
            return QDateTime.fromSecsSinceEpoch(
                int(dt_utc.timestamp()), QTimeZone.utc()
            )
        if isinstance(val, str):
            qdt = QDateTime.fromString(val, Qt.DateFormat.ISODate)
            if qdt.isValid():
                return qdt.toUTC()
            dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
            dt_utc = (
                dt.astimezone(timezone.utc)
                if dt.tzinfo is not None
                else dt.replace(tzinfo=timezone.utc)
            )
            return QDateTime.fromSecsSinceEpoch(
                int(dt_utc.timestamp()), QTimeZone.utc()
            )
        raise TypeError(f"Unsupported datetime type: {type(val).__name__}")

    @property
    def apply_filters_button(self) -> QPushButton:
        """Return the Apply Filters button."""
        return self._apply_btn

    @property
    def apply_button(self) -> QPushButton:
        """Alias for apply_filters_button."""
        return self._apply_btn

    @property
    def clear_filters_button(self) -> QPushButton:
        """Return the Clear Filters button."""
        return self._clear_btn

    @property
    def clear_button(self) -> QPushButton:
        """Alias for clear_filters_button."""
        return self._clear_btn

    @property
    def reset_button(self) -> QPushButton:
        """Alias for clear_filters_button."""
        return self._clear_btn

    @property
    def filter_validation_label(self) -> QLabel:
        """Return the inline filter validation message label."""
        return self._validation_label

    @property
    def validation_label(self) -> QLabel:
        """Alias for filter_validation_label."""
        return self._validation_label

    @property
    def pagination_bar(self) -> ResourcesPaginationBar:
        """Return the pagination bar frame."""
        return self._pagination_bar

    @property
    def pagination_frame(self) -> ResourcesPaginationBar:
        """Alias for pagination_bar."""
        return self._pagination_bar

    @property
    def prev_page_button(self) -> QPushButton:
        """Return the Previous page button."""
        return self._prev_btn

    @property
    def prev_button(self) -> QPushButton:
        """Alias for prev_page_button."""
        return self._prev_btn

    @property
    def next_page_button(self) -> QPushButton:
        """Return the Next page button."""
        return self._next_btn

    @property
    def next_button(self) -> QPushButton:
        """Alias for next_page_button."""
        return self._next_btn

    @property
    def page_range_label(self) -> QLabel:
        """Return the page range summary label."""
        return self._page_range_label

    @property
    def page_range_summary(self) -> QLabel:
        """Alias for page_range_label."""
        return self._page_range_label

    def snapshot_at(self, row: int) -> ResourceSnapshot | None:
        """Return the ResourceSnapshot at the specified row index."""
        return self._model.snapshot_at(row)

    def resource_at(self, row: int) -> ResourceSnapshot | None:
        """Alias for snapshot_at."""
        return self.snapshot_at(row)

    @property
    def selected_snapshot(self) -> ResourceSnapshot | None:
        """Return the currently selected ResourceSnapshot, or None."""
        sel_model = self._table.selectionModel()
        if sel_model is None or not sel_model.hasSelection():
            return None
        selected_rows = sel_model.selectedRows()
        if selected_rows:
            return self.snapshot_at(selected_rows[0].row())
        selected_indexes = sel_model.selectedIndexes()
        if selected_indexes:
            return self.snapshot_at(selected_indexes[0].row())
        return None

    @property
    def selected_resource(self) -> ResourceSnapshot | None:
        """Alias for selected_snapshot."""
        return self.selected_snapshot

    @property
    def summary_cards(self) -> ResourcesSummaryCardsFrame:
        """Return the resource utilization summary cards frame."""
        return self._summary_cards

    @property
    def summary_cards_frame(self) -> ResourcesSummaryCardsFrame:
        """Alias for summary_cards."""
        return self._summary_cards

    @property
    def cpu_card(self) -> MetricCard:
        """Return the CPU utilization summary metric card."""
        return self._summary_cards.cpu_card

    @property
    def memory_card(self) -> MetricCard:
        """Return the memory utilization summary metric card."""
        return self._summary_cards.memory_card

    @property
    def disk_card(self) -> MetricCard:
        """Return the disk utilization summary metric card."""
        return self._summary_cards.disk_card

    @property
    def memory_used_total_card(self) -> MetricCard:
        """Return the memory used vs total summary metric card."""
        return self._summary_cards.memory_used_total_card

    @property
    def inspector(self) -> ResourceInspectorPanel:
        """Return the snapshot details inspector panel."""
        return self._inspector

    @property
    def inspector_panel(self) -> ResourceInspectorPanel:
        """Alias for inspector."""
        return self._inspector

    @property
    def trend_charts(self) -> ResourceTrendChartsWidget:
        """Return the historical resource telemetry trend charts widget."""
        return self._trend_charts

    @property
    def trend_charts_widget(self) -> ResourceTrendChartsWidget:
        """Alias for trend_charts."""
        return self._trend_charts

    def set_query(self, query: ResourcesQuery) -> None:
        """Synchronize visible input controls with the provided query."""
        if not isinstance(query, ResourcesQuery):
            raise TypeError(
                f"Expected ResourcesQuery, got {type(query).__name__}"
            )
        self._table.clearSelection()
        self._inspector.set_snapshot(None)
        self.set_host_id(query.host_id)
        self.set_limit(query.limit)
        self.set_start_time(query.start_time)
        self.set_end_time(query.end_time)
        self._current_query = query

    # -----------------------------------------------------------------------
    # Filter & Pagination Actions
    # -----------------------------------------------------------------------

    def apply_filters(self) -> None:
        """Validate inputs and emit query_requested with offset reset to 0."""
        if self._state == STATE_LOADING:
            return

        validated = self._validate_and_extract_filters()
        if validated is None:
            return

        host_val, limit_val, start_iso, end_iso = validated
        self._clear_validation_error()
        self._table.clearSelection()
        self._inspector.set_snapshot(None)

        new_query = ResourcesQuery(
            host_id=host_val,
            start_time=start_iso,
            end_time=end_iso,
            limit=limit_val,
            offset=0,
        )
        self._current_query = new_query
        self.query_requested.emit(new_query)

    def clear_filters(self) -> None:
        """Clear all filter inputs and emit query_requested with offset 0."""
        if self._state == STATE_LOADING:
            return

        self._host_input.clear()
        self._limit_combo.setCurrentText(str(self._page_size))
        self._start_time_check.setChecked(False)
        self._end_time_check.setChecked(False)
        self._clear_validation_error()
        self._table.clearSelection()
        self._inspector.set_snapshot(None)

        new_query = ResourcesQuery(
            limit=self._page_size,
            offset=0,
        )
        self._current_query = new_query
        self.query_requested.emit(new_query)

    def go_next_page(self) -> None:
        """Advance to the next page of records using current filters."""
        if self._state == STATE_LOADING or not self._next_btn.isEnabled():
            return

        self._table.clearSelection()
        self._inspector.set_snapshot(None)
        new_offset = self._current_query.offset + self._current_query.limit
        new_query = replace(self._current_query, offset=new_offset)
        self._current_query = new_query
        self.query_requested.emit(new_query)

    def go_prev_page(self) -> None:
        """Navigate to the previous page of records using current filters."""
        if self._state == STATE_LOADING or not self._prev_btn.isEnabled():
            return

        self._table.clearSelection()
        self._inspector.set_snapshot(None)
        new_offset = max(
            0, self._current_query.offset - self._current_query.limit
        )
        new_query = replace(self._current_query, offset=new_offset)
        self._current_query = new_query
        self.query_requested.emit(new_query)

    def _validate_and_extract_filters(
        self,
    ) -> tuple[str | None, int, str | None, str | None] | None:
        """Validate local input fields, returning normalized criteria or None."""
        # 1. Host ID (UUID validation)
        host_raw = self._host_input.text().strip()
        host_val: str | None = None
        if host_raw:
            try:
                host_val = str(uuid.UUID(host_raw))
            except (ValueError, TypeError, AttributeError):
                self._set_validation_error(
                    "Host ID must be a valid UUID (e.g. "
                    "12345678-1234-5678-1234-567812345678)"
                )
                return None

        # 2. Limit (1 to 100)
        limit_raw = self._limit_combo.currentText().strip()
        if not limit_raw:
            self._set_validation_error(
                "Limit must be an integer between 1 and 100"
            )
            return None
        try:
            parsed_limit = int(limit_raw)
            if not (1 <= parsed_limit <= 100):
                raise ValueError
            limit_val = parsed_limit
        except ValueError:
            self._set_validation_error(
                "Limit must be an integer between 1 and 100"
            )
            return None

        # 3. Time Range
        start_iso: str | None = None
        if self._start_time_check.isChecked():
            start_qdt = self._start_time_edit.dateTime().toUTC()
            start_iso = start_qdt.toString("yyyy-MM-ddTHH:mm:ss") + "Z"

        end_iso: str | None = None
        if self._end_time_check.isChecked():
            end_qdt = self._end_time_edit.dateTime().toUTC()
            end_iso = end_qdt.toString("yyyy-MM-ddTHH:mm:ss") + "Z"

        if start_iso is not None and end_iso is not None:
            if (
                self._start_time_edit.dateTime().toUTC()
                > self._end_time_edit.dateTime().toUTC()
            ):
                self._set_validation_error(
                    "Start time must be earlier than or equal to end time"
                )
                return None

        return (host_val, limit_val, start_iso, end_iso)

    def _set_validation_error(self, message: str) -> None:
        """Display an actionable inline validation error message."""
        self._validation_label.setText(message)
        self._validation_label.setAccessibleDescription(message)
        self._validation_label.setProperty("error", "true")
        style = self._validation_label.style()
        if style is not None:
            style.unpolish(self._validation_label)
            style.polish(self._validation_label)

    def _clear_validation_error(self) -> None:
        """Clear active inline validation error message."""
        self._validation_label.setText("")
        self._validation_label.setAccessibleDescription("")
        self._validation_label.setProperty("error", "false")
        style = self._validation_label.style()
        if style is not None:
            style.unpolish(self._validation_label)
            style.polish(self._validation_label)

    @property
    def is_active(self) -> bool:
        """Return True if the view is currently the active page in the shell."""
        return self._is_active

    # -----------------------------------------------------------------------
    # Navigation Lifecycle
    # -----------------------------------------------------------------------

    def notify_page_activated(self) -> None:
        """Handle lazy load notification when Resources page is navigated to."""
        self._is_active = True
        if self._state == STATE_NOT_LOADED:
            self.load_requested.emit()

    def notify_page_deactivated(self) -> None:
        """Handle deactivation notification when leaving Resources page."""
        self._is_active = False

    def refresh(self) -> None:
        """Manually trigger a refresh request if not already loading."""
        if self._state != STATE_LOADING:
            self.refresh_requested.emit()

    # -----------------------------------------------------------------------
    # State Mutation API
    # -----------------------------------------------------------------------

    def set_loading(self) -> None:
        """Transition into the loading state while preserving existing records."""
        self._state = STATE_LOADING
        self._table.clearSelection()
        self._inspector.set_snapshot(None)
        self._trend_charts.set_loading()
        self._refresh_btn.setEnabled(False)
        self._retry_btn.setEnabled(False)
        self._apply_btn.setEnabled(False)
        self._clear_btn.setEnabled(False)
        self._prev_btn.setEnabled(False)
        self._next_btn.setEnabled(False)
        self._host_input.setEnabled(False)
        self._limit_combo.setEnabled(False)
        self._start_time_check.setEnabled(False)
        self._start_time_edit.setEnabled(False)
        self._end_time_check.setEnabled(False)
        self._end_time_edit.setEnabled(False)

        if self._model.rowCount() > 0:
            self._count_label.setText(
                f"Retained {self._model.rowCount()} snapshots (refreshing...)"
            )
            self._page_range_label.setText(
                f"Loading page... (offset {self._current_query.offset})"
            )
        else:
            self._summary_cards.set_snapshot(None)
            self._count_label.setText("Loading resource telemetry from API...")
            self._page_range_label.setText("Loading...")
            self._banner_title.setText("Loading Resources")
            self._banner_msg.setText(
                "Querying backend API for resource telemetry..."
            )
            self._status_banner.setVisible(True)
            self._retry_btn.setVisible(False)
            self._quick_reset_btn.setVisible(False)
            self._update_banner_styling("loading")

    def set_collection(self, collection: ResourceSnapshotCollection) -> None:
        """Populate the table with records and update pagination metadata."""
        if not isinstance(collection, ResourceSnapshotCollection):
            raise TypeError(
                "Expected ResourceSnapshotCollection, got "
                f"{type(collection).__name__}"
            )

        self._table.clearSelection()
        self._inspector.set_snapshot(None)
        self._model.set_collection(collection)
        self._trend_charts.set_collection(collection, self._current_query)
        items_count = len(collection.items)
        total = collection.total
        offset = collection.offset
        limit = collection.limit
        clamped_limit = (
            min(max(1, limit), 100)
            if isinstance(limit, int) and not isinstance(limit, bool)
            else self._page_size
        )
        valid_offset = (
            max(0, offset)
            if isinstance(offset, int) and not isinstance(offset, bool)
            else 0
        )
        try:
            self._current_query = replace(
                self._current_query, offset=valid_offset, limit=clamped_limit
            )
        except ValueError:
            pass

        self._limit_combo.setCurrentText(str(clamped_limit))

        if items_count > 0:
            latest = find_latest_resource_snapshot(collection.items)
            self._summary_cards.set_snapshot(latest)
            self._state = STATE_LOADED
            self._status_banner.setVisible(False)
            self._quick_reset_btn.setVisible(False)
            start_idx = valid_offset + 1
            end_idx = valid_offset + items_count
            self._count_label.setText(
                f"Showing {items_count} of {total} snapshots"
            )
            self._page_range_label.setText(
                f"Showing {start_idx}–{end_idx} of {total} snapshots"
            )
        else:
            self._summary_cards.set_snapshot(None)
            self._state = STATE_EMPTY
            self._count_label.setText(
                f"0 snapshots ({total} total, 0 displayed)"
            )
            self._page_range_label.setText(f"0 of {total} snapshots")
            self._status_banner.setVisible(True)
            self._retry_btn.setVisible(False)

            if self._current_query.has_active_filters:
                self._banner_title.setText("No Matching Resource Telemetry")
                self._banner_msg.setText(
                    "No resource snapshots match the active filter criteria. "
                    "Adjust or clear filters to see more results."
                )
                self._quick_reset_btn.setVisible(True)
            else:
                self._banner_title.setText("No Resource Telemetry Found")
                self._banner_msg.setText(
                    "The server returned zero resource snapshots for this system."
                )
                self._quick_reset_btn.setVisible(False)
            self._update_banner_styling("empty")

        self._refresh_btn.setEnabled(True)
        self._retry_btn.setEnabled(True)
        self._apply_btn.setEnabled(True)
        self._clear_btn.setEnabled(True)
        self._host_input.setEnabled(True)
        self._limit_combo.setEnabled(True)
        self._start_time_check.setEnabled(True)
        self._start_time_edit.setEnabled(self._start_time_check.isChecked())
        self._end_time_check.setEnabled(True)
        self._end_time_edit.setEnabled(self._end_time_check.isChecked())
        self._prev_btn.setEnabled(valid_offset > 0)
        self._next_btn.setEnabled(
            items_count > 0 and (valid_offset + clamped_limit < total)
        )

    def set_error(self, message: str) -> None:
        """Transition into the failed state and display a sanitized message."""
        if not isinstance(message, str):
            raise TypeError(
                f"Expected str message, got {type(message).__name__}"
            )

        self._table.clearSelection()
        self._inspector.set_snapshot(None)
        self._trend_charts.set_error(message)
        self._state = STATE_FAILED
        self._refresh_btn.setEnabled(True)
        self._retry_btn.setEnabled(True)
        self._retry_btn.setVisible(True)
        self._quick_reset_btn.setVisible(False)
        self._apply_btn.setEnabled(True)
        self._clear_btn.setEnabled(True)
        self._host_input.setEnabled(True)
        self._limit_combo.setEnabled(True)
        self._start_time_check.setEnabled(True)
        self._start_time_edit.setEnabled(self._start_time_check.isChecked())
        self._end_time_check.setEnabled(True)
        self._end_time_edit.setEnabled(self._end_time_check.isChecked())
        self._status_banner.setVisible(True)

        if self._model.rowCount() > 0:
            self._banner_title.setText("Resources Refresh Failed")
            self._banner_msg.setText(
                f"{message} — Displaying retained records from previous "
                "query."
            )
            self._count_label.setText(
                f"Retained {self._model.rowCount()} snapshots (refresh failed)"
            )
            self._page_range_label.setText(
                f"Page failed (offset {self._current_query.offset})"
            )
            self._prev_btn.setEnabled(self._current_query.offset > 0)
            self._next_btn.setEnabled(False)
        else:
            self._summary_cards.set_snapshot(None)
            self._banner_title.setText("Failed to Load Resources")
            self._banner_msg.setText(message)
            self._count_label.setText("0 snapshots (load failed)")
            self._page_range_label.setText("0 of 0 snapshots")
            self._prev_btn.setEnabled(False)
            self._next_btn.setEnabled(False)

        self._update_banner_styling("failed")

    def set_not_loaded(self) -> None:
        """Reset the view to the initial un-requested state."""
        self._state = STATE_NOT_LOADED
        self._table.clearSelection()
        self._inspector.set_snapshot(None)
        self._summary_cards.set_snapshot(None)
        self._trend_charts.set_not_loaded()
        self._model.clear()
        self._current_query = ResourcesQuery(limit=self._page_size, offset=0)
        self._host_input.clear()
        self._limit_combo.setCurrentText(str(self._page_size))
        self._start_time_check.setChecked(False)
        self._end_time_check.setChecked(False)
        self._clear_validation_error()

        self._refresh_btn.setEnabled(True)
        self._retry_btn.setEnabled(True)
        self._retry_btn.setVisible(False)
        self._quick_reset_btn.setVisible(False)
        self._apply_btn.setEnabled(True)
        self._clear_btn.setEnabled(True)
        self._host_input.setEnabled(True)
        self._limit_combo.setEnabled(True)
        self._start_time_check.setEnabled(True)
        self._start_time_edit.setEnabled(False)
        self._end_time_check.setEnabled(True)
        self._end_time_edit.setEnabled(False)
        self._prev_btn.setEnabled(False)
        self._next_btn.setEnabled(False)

        self._count_label.setText("0 snapshots (not loaded)")
        self._page_range_label.setText("0 of 0 snapshots")
        self._banner_title.setText("Resources Not Loaded")
        self._banner_msg.setText(
            "Resource telemetry records have not been retrieved from the API "
            "yet. Click Refresh Resources to load."
        )
        self._status_banner.setVisible(True)
        self._update_banner_styling("not_loaded")

    # -----------------------------------------------------------------------
    # Internal Helpers
    # -----------------------------------------------------------------------

    def _apply_state_ui(self) -> None:
        """Apply visual properties corresponding to initial state."""
        if self._model.collection is not None:
            self.set_collection(self._model.collection)
        else:
            self.set_not_loaded()

    def _update_banner_styling(self, state_val: str) -> None:
        """Update Qt dynamic property on banner and trigger repolish."""
        self._status_banner.setProperty("state", state_val)
        style = self._status_banner.style()
        if style is not None:
            style.unpolish(self._status_banner)
            style.polish(self._status_banner)

    def _handle_refresh_click(self) -> None:
        """Forward user click on Refresh Resources button to signals."""
        self.refresh()

    def _handle_retry_click(self) -> None:
        """Forward user click on Retry button to signals."""
        self.refresh()

    def _handle_selection_changed(
        self, selected: Any = None, deselected: Any = None
    ) -> None:
        """Update inspector details when table row selection changes."""
        sel_model = self._table.selectionModel()
        if sel_model is None or not sel_model.hasSelection():
            self._inspector.set_snapshot(None)
            self._trend_charts.select_snapshot(None)
            return

        selected_rows = sel_model.selectedRows()
        if selected_rows:
            row = selected_rows[0].row()
        else:
            selected_indexes = sel_model.selectedIndexes()
            if not selected_indexes:
                self._inspector.set_snapshot(None)
                self._trend_charts.select_snapshot(None)
                return
            row = selected_indexes[0].row()

        snapshot = self._model.snapshot_at(row)
        if snapshot is None and selected_rows:
            val = self._model.data(selected_rows[0], ResourceSnapshotRole)
            if isinstance(val, ResourceSnapshot):
                snapshot = val

        if snapshot is not None:
            self._inspector.set_snapshot(snapshot)
            self._trend_charts.select_snapshot(snapshot)
        else:
            self._inspector.set_snapshot(None)
            self._trend_charts.select_snapshot(None)

    def _handle_chart_snapshot_selected(
        self, snapshot: ResourceSnapshot | None
    ) -> None:
        """Synchronize table and inspector selection when chart point is clicked."""
        if snapshot is None:
            self._table.clearSelection()
            self._inspector.set_snapshot(None)
            return

        row = self._model.row_for_snapshot(snapshot)
        if row >= 0:
            sel_model = self._table.selectionModel()
            if sel_model is not None:
                idx = self._model.index(row, 0)
                sel_model.select(
                    idx,
                    QItemSelectionModel.SelectionFlag.ClearAndSelect
                    | QItemSelectionModel.SelectionFlag.Rows,
                )
                self._table.scrollTo(idx)
            self._inspector.set_snapshot(snapshot)
        else:
            self._table.clearSelection()
            self._inspector.set_snapshot(None)

    def _handle_inspector_closed(self) -> None:
        """Handle inspector close button click by clearing row selection."""
        self._table.clearSelection()
        self._inspector.set_snapshot(None)
        self._trend_charts.select_snapshot(None)

    def _handle_model_reset(self) -> None:
        """Clear selection and inspector when underlying model is reset."""
        self._table.clearSelection()
        self._inspector.set_snapshot(None)
        self._trend_charts.select_snapshot(None)
        if self._model.rowCount() > 0:
            latest = find_latest_resource_snapshot(self._model.snapshots)
            self._summary_cards.set_snapshot(latest)
        else:
            self._summary_cards.set_snapshot(None)


__all__ = [
    "DEFAULT_PAGE_SIZE",
    "STATE_EMPTY",
    "STATE_FAILED",
    "STATE_LOADED",
    "STATE_LOADING",
    "STATE_NOT_LOADED",
    "ResourceInspectorPanel",
    "ResourceTrendChartsWidget",
    "ResourcesFilterBar",
    "ResourcesPaginationBar",
    "ResourcesQuery",
    "ResourcesSummaryCardsFrame",
    "ResourcesView",
]
