"""OSIRIS Live Security Events View with Filtering and Pagination.

Provides EventsView, the native PySide6 widget presenting security events
retrieved from the REST API in a dense investigator-oriented table backed
by EventsTableModel, with server-side filters, query state, and pagination.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any

from PySide6.QtCore import QDateTime, Qt, QTimeZone, Signal
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

from desktop.client.models import VALID_SEVERITIES, Event, EventCollection
from desktop.models.events_model import EventsTableModel
from desktop.ui.components.inspector_panel import EventInspectorPanel
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
SEVERITY_CHOICES: tuple[str, ...] = (
    "critical",
    "high",
    "medium",
    "low",
    "info",
)


@dataclass(frozen=True)
class EventsQuery:
    """Normalized query parameters for server-side security event requests.

    Captures active filter criteria and server-side pagination constraints.
    Immutable to guarantee safe cross-thread handling between UI and workers.
    """

    severity: str | None = None
    source: str | None = None
    event_type: str | None = None
    pid: int | None = None
    host_id: str | None = None
    start_time: str | None = None
    end_time: str | None = None
    limit: int = DEFAULT_PAGE_SIZE
    offset: int = 0

    @property
    def has_active_filters(self) -> bool:
        """Return True if any filter criteria other than pagination are set."""
        return any(
            v is not None
            for v in (
                self.severity,
                self.source,
                self.event_type,
                self.pid,
                self.host_id,
                self.start_time,
                self.end_time,
            )
        )

    def to_client_kwargs(self) -> dict[str, Any]:
        """Convert query into validated keyword arguments for APIClient.get_events."""
        kwargs: dict[str, Any] = {
            "limit": self.limit,
            "offset": self.offset,
        }
        if self.severity is not None:
            kwargs["severity"] = self.severity
        if self.source is not None:
            kwargs["source"] = self.source
        if self.event_type is not None:
            kwargs["event_type"] = self.event_type
        if self.pid is not None:
            kwargs["pid"] = self.pid
        if self.host_id is not None:
            kwargs["host_id"] = self.host_id
        if self.start_time is not None:
            kwargs["start_time"] = self.start_time
        if self.end_time is not None:
            kwargs["end_time"] = self.end_time
        return kwargs


class EventsView(QWidget):
    """Primary visual interface for inspecting security events in OSIRIS.

    Coordinates table presentation, server-side filtering, deterministic
    pagination, record summary, and loading/empty/error states.
    """

    load_requested = Signal()
    refresh_requested = Signal()
    query_requested = Signal(object)

    def __init__(
        self,
        model: EventsTableModel | None = None,
        parent: QWidget | None = None,
        page_size: int = DEFAULT_PAGE_SIZE,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("Page_Events")
        self.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )

        self._state: str = STATE_NOT_LOADED
        self._is_active: bool = False
        self._page_size = page_size
        self._current_query = EventsQuery(limit=self._page_size, offset=0)
        self._model = (
            model if model is not None else EventsTableModel(parent=self)
        )

        root = QVBoxLayout(self)
        root.setContentsMargins(SPACE_6, SPACE_6, SPACE_6, SPACE_6)
        root.setSpacing(SPACE_4)

        # 1. Page Header
        header = QWidget(self)
        header.setObjectName("PageHeader_Events")
        h_ly = QVBoxLayout(header)
        h_ly.setContentsMargins(0, 0, 0, 0)
        h_ly.setSpacing(SPACE_1)

        self._title_label = QLabel("Security Events", header)
        self._title_label.setObjectName("PageTitle")

        self._desc_label = QLabel(
            "Real-time security events from monitored endpoints. "
            "Server-side filtering and investigator pagination active.",
            header,
        )
        self._desc_label.setObjectName("PageDescription")

        h_ly.addWidget(self._title_label)
        h_ly.addWidget(self._desc_label)
        root.addWidget(header)

        # 2. Filter Toolbar
        self._filter_bar = self._build_filter_bar()
        root.addWidget(self._filter_bar)

        # 3. Action Toolbar & Summary
        toolbar = QFrame(self)
        toolbar.setObjectName("EventsToolbar")
        t_ly = QHBoxLayout(toolbar)
        t_ly.setContentsMargins(0, 0, 0, 0)
        t_ly.setSpacing(SPACE_3)

        self._refresh_btn = QPushButton("Refresh Events", toolbar)
        self._refresh_btn.setObjectName("RefreshEventsButton")
        self._refresh_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._refresh_btn.clicked.connect(self._handle_refresh_click)

        self._count_label = QLabel("0 events (not loaded)", toolbar)
        self._count_label.setObjectName("RecordCountSummary")

        t_ly.addWidget(self._refresh_btn)
        t_ly.addWidget(self._count_label)
        t_ly.addStretch(1)

        root.addWidget(toolbar)

        # 4. Status / Message Banner
        self._status_banner = QFrame(self)
        self._status_banner.setObjectName("EventsStatusBanner")
        b_ly = QHBoxLayout(self._status_banner)
        b_ly.setContentsMargins(SPACE_4, SPACE_3, SPACE_4, SPACE_3)
        b_ly.setSpacing(SPACE_3)

        banner_text_box = QWidget(self._status_banner)
        bt_ly = QVBoxLayout(banner_text_box)
        bt_ly.setContentsMargins(0, 0, 0, 0)
        bt_ly.setSpacing(SPACE_1)

        self._banner_title = QLabel("Events Not Loaded", banner_text_box)
        self._banner_title.setObjectName("EventsStatusBannerTitle")

        self._banner_msg = QLabel(
            "Security event records have not been retrieved from the API yet. "
            "Click Refresh Events to load.",
            banner_text_box,
        )
        self._banner_msg.setObjectName("EventsStatusBannerMessage")
        self._banner_msg.setWordWrap(True)

        bt_ly.addWidget(self._banner_title)
        bt_ly.addWidget(self._banner_msg)
        b_ly.addWidget(banner_text_box, 1)

        self._retry_btn = QPushButton("Retry", self._status_banner)
        self._retry_btn.setObjectName("RetryEventsButton")
        self._retry_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._retry_btn.clicked.connect(self._handle_retry_click)
        self._retry_btn.setVisible(False)
        b_ly.addWidget(self._retry_btn)

        root.addWidget(self._status_banner)

        # 5. Dense Events Table
        self._table = QTableView(self)
        self._table.setObjectName("EventsTable")
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

        # 5. Content Region: Dense Events Table & Event Details Inspector
        content_layout = QHBoxLayout()
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(SPACE_3)
        content_layout.addWidget(self._table, 1)

        self._inspector = EventInspectorPanel(parent=self)
        self._inspector.close_requested.connect(self._handle_inspector_closed)
        self._inspector.hide()
        content_layout.addWidget(self._inspector, 0)

        root.addLayout(content_layout, 1)

        # Wire table selection model to update inspector
        sel_model = self._table.selectionModel()
        if sel_model is not None:
            sel_model.selectionChanged.connect(self._handle_selection_changed)

        # 6. Pagination Bar
        self._pagination_bar = self._build_pagination_bar()
        root.addWidget(self._pagination_bar)

        # Apply initial visual state
        self._apply_state_ui()

    def _build_filter_bar(self) -> QFrame:
        """Construct the compact two-row investigator filter toolbar."""
        bar = QFrame(self)
        bar.setObjectName("EventsFilterBar")
        bar_ly = QVBoxLayout(bar)
        bar_ly.setContentsMargins(SPACE_3, SPACE_3, SPACE_3, SPACE_3)
        bar_ly.setSpacing(SPACE_2)

        # Row 1: Filter inputs
        row1 = QHBoxLayout()
        row1.setSpacing(SPACE_3)

        # Severity
        sev_box = QVBoxLayout()
        sev_box.setSpacing(SPACE_1)
        sev_label = QLabel("Severity", bar)
        sev_label.setObjectName("SeverityFilterLabel")
        self._severity_combo = QComboBox(bar)
        self._severity_combo.setObjectName("SeverityFilterComboBox")
        self._severity_combo.addItem("All severities", None)
        for s in SEVERITY_CHOICES:
            self._severity_combo.addItem(s.capitalize(), s)
        sev_box.addWidget(sev_label)
        sev_box.addWidget(self._severity_combo)
        row1.addLayout(sev_box, 1)

        # Source
        src_box = QVBoxLayout()
        src_box.setSpacing(SPACE_1)
        src_label = QLabel("Source", bar)
        src_label.setObjectName("SourceFilterLabel")
        self._source_input = QLineEdit(bar)
        self._source_input.setObjectName("SourceFilterInput")
        self._source_input.setPlaceholderText("e.g. proc, fs")
        src_box.addWidget(src_label)
        src_box.addWidget(self._source_input)
        row1.addLayout(src_box, 1)

        # Event Type
        type_box = QVBoxLayout()
        type_box.setSpacing(SPACE_1)
        type_label = QLabel("Event Type", bar)
        type_label.setObjectName("EventTypeFilterLabel")
        self._type_input = QLineEdit(bar)
        self._type_input.setObjectName("EventTypeFilterInput")
        self._type_input.setPlaceholderText("e.g. process.start")
        type_box.addWidget(type_label)
        type_box.addWidget(self._type_input)
        row1.addLayout(type_box, 1)

        # PID
        pid_box = QVBoxLayout()
        pid_box.setSpacing(SPACE_1)
        pid_label = QLabel("PID", bar)
        pid_label.setObjectName("PidFilterLabel")
        self._pid_input = QLineEdit(bar)
        self._pid_input.setObjectName("PidFilterInput")
        self._pid_input.setPlaceholderText("e.g. 1234")
        pid_box.addWidget(pid_label)
        pid_box.addWidget(self._pid_input)
        row1.addLayout(pid_box, 1)

        # Host ID
        host_box = QVBoxLayout()
        host_box.setSpacing(SPACE_1)
        host_label = QLabel("Host ID", bar)
        host_label.setObjectName("HostIdFilterLabel")
        self._host_input = QLineEdit(bar)
        self._host_input.setObjectName("HostIdFilterInput")
        self._host_input.setPlaceholderText("UUID...")
        host_box.addWidget(host_label)
        host_box.addWidget(self._host_input)
        row1.addLayout(host_box, 2)

        bar_ly.addLayout(row1)

        # Row 2: Time-range inputs
        row2 = QHBoxLayout()
        row2.setSpacing(SPACE_3)

        # Start Time Box
        start_box = QHBoxLayout()
        start_box.setSpacing(SPACE_2)
        start_lbl = QLabel("Start Time (UTC)", bar)
        start_lbl.setObjectName("StartTimeFilterLabel")
        self._start_time_label = start_lbl

        self._start_time_check = QCheckBox("Enable", bar)
        self._start_time_check.setObjectName("StartTimeFilterCheckBox")
        self._start_time_check.setChecked(False)

        self._start_time_edit = QDateTimeEdit(bar)
        self._start_time_edit.setObjectName("StartTimeFilterEdit")
        self._start_time_edit.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        self._start_time_edit.setCalendarPopup(True)
        self._start_time_edit.setTimeZone(QTimeZone.utc())
        self._start_time_edit.setDateTime(QDateTime.currentDateTimeUtc())
        self._start_time_edit.setEnabled(False)

        self._start_time_check.toggled.connect(self._start_time_edit.setEnabled)

        start_box.addWidget(start_lbl)
        start_box.addWidget(self._start_time_check)
        start_box.addWidget(self._start_time_edit, 1)
        row2.addLayout(start_box, 1)

        # End Time Box
        end_box = QHBoxLayout()
        end_box.setSpacing(SPACE_2)
        end_lbl = QLabel("End Time (UTC)", bar)
        end_lbl.setObjectName("EndTimeFilterLabel")
        self._end_time_label = end_lbl

        self._end_time_check = QCheckBox("Enable", bar)
        self._end_time_check.setObjectName("EndTimeFilterCheckBox")
        self._end_time_check.setChecked(False)

        self._end_time_edit = QDateTimeEdit(bar)
        self._end_time_edit.setObjectName("EndTimeFilterEdit")
        self._end_time_edit.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        self._end_time_edit.setCalendarPopup(True)
        self._end_time_edit.setTimeZone(QTimeZone.utc())
        self._end_time_edit.setDateTime(QDateTime.currentDateTimeUtc())
        self._end_time_edit.setEnabled(False)

        self._end_time_check.toggled.connect(self._end_time_edit.setEnabled)

        end_box.addWidget(end_lbl)
        end_box.addWidget(self._end_time_check)
        end_box.addWidget(self._end_time_edit, 1)
        row2.addLayout(end_box, 1)

        bar_ly.addLayout(row2)

        # Row 3: Action buttons & validation error
        row3 = QHBoxLayout()
        row3.setSpacing(SPACE_2)

        self._apply_btn = QPushButton("Apply Filters", bar)
        self._apply_btn.setObjectName("ApplyFiltersButton")
        self._apply_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._apply_btn.clicked.connect(self.apply_filters)

        self._clear_btn = QPushButton("Clear Filters", bar)
        self._clear_btn.setObjectName("ClearFiltersButton")
        self._clear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._clear_btn.clicked.connect(self.clear_filters)

        self._validation_label = QLabel("", bar)
        self._validation_label.setObjectName("FilterValidationLabel")
        self._validation_label.setWordWrap(True)

        row3.addWidget(self._apply_btn)
        row3.addWidget(self._clear_btn)
        row3.addWidget(self._validation_label, 1)

        bar_ly.addLayout(row3)
        return bar

    def _build_pagination_bar(self) -> QFrame:
        """Construct the deterministic server-side pagination bar."""
        p_bar = QFrame(self)
        p_bar.setObjectName("EventsPaginationFrame")
        p_ly = QHBoxLayout(p_bar)
        p_ly.setContentsMargins(0, SPACE_2, 0, 0)
        p_ly.setSpacing(SPACE_3)

        self._prev_btn = QPushButton("Previous", p_bar)
        self._prev_btn.setObjectName("PrevPageButton")
        self._prev_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._prev_btn.clicked.connect(self.go_prev_page)
        self._prev_btn.setEnabled(False)

        self._page_range_label = QLabel("0 of 0 events", p_bar)
        self._page_range_label.setObjectName("PageRangeLabel")

        self._next_btn = QPushButton("Next", p_bar)
        self._next_btn.setObjectName("NextPageButton")
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
        for col_idx in range(len(EventsTableModel.COLUMNS)):
            if col_idx in (7, 8):  # Command, Object
                header.setSectionResizeMode(
                    col_idx, QHeaderView.ResizeMode.Interactive
                )
                header.resizeSection(col_idx, 200)
            else:
                header.setSectionResizeMode(
                    col_idx, QHeaderView.ResizeMode.ResizeToContents
                )

    # -----------------------------------------------------------------------
    # Public Properties & Accessors
    # -----------------------------------------------------------------------

    @property
    def model(self) -> EventsTableModel:
        """Return the underlying EventsTableModel instance."""
        return self._model

    @property
    def table(self) -> QTableView:
        """Return the QTableView displaying the event records."""
        return self._table

    @property
    def refresh_button(self) -> QPushButton:
        """Return the Refresh Events action button."""
        return self._refresh_btn

    @property
    def retry_button(self) -> QPushButton:
        """Return the Retry action button on the error banner."""
        return self._retry_btn

    @property
    def record_count_label(self) -> QLabel:
        """Return the record-count summary label."""
        return self._count_label

    @property
    def status_banner(self) -> QFrame:
        """Return the status and message banner frame."""
        return self._status_banner

    @property
    def state(self) -> str:
        """Return the current view state identifier."""
        return self._state

    @property
    def current_query(self) -> EventsQuery:
        """Return the active normalized EventsQuery instance."""
        return self._current_query

    def set_query(self, query: EventsQuery) -> None:
        """Update active query and synchronize filter input fields."""
        if not isinstance(query, EventsQuery):
            raise TypeError(
                f"Expected EventsQuery, got {type(query).__name__}"
            )
        self._current_query = query
        self._table.clearSelection()
        self._inspector.set_event(None)
        if query.severity is None:
            self._severity_combo.setCurrentIndex(0)
        else:
            idx = self._severity_combo.findData(query.severity)
            if idx >= 0:
                self._severity_combo.setCurrentIndex(idx)
        self._source_input.setText(query.source if query.source is not None else "")
        self._type_input.setText(
            query.event_type if query.event_type is not None else ""
        )
        self._pid_input.setText(str(query.pid) if query.pid is not None else "")
        self._host_input.setText(
            str(query.host_id) if query.host_id is not None else ""
        )
        self.set_start_time(query.start_time)
        self.set_end_time(query.end_time)

    @property
    def page_size(self) -> int:
        """Return the configured page size."""
        return self._page_size

    @property
    def filter_bar(self) -> QFrame:
        """Return the filter toolbar frame."""
        return self._filter_bar

    @property
    def severity_combo(self) -> QComboBox:
        """Return the severity filter combo box."""
        return self._severity_combo

    @property
    def source_input(self) -> QLineEdit:
        """Return the source filter line edit."""
        return self._source_input

    @property
    def event_type_input(self) -> QLineEdit:
        """Return the event type filter line edit."""
        return self._type_input

    @property
    def pid_input(self) -> QLineEdit:
        """Return the process ID filter line edit."""
        return self._pid_input

    @property
    def host_id_input(self) -> QLineEdit:
        """Return the host ID filter line edit."""
        return self._host_input

    @property
    def apply_filters_button(self) -> QPushButton:
        """Return the Apply Filters button."""
        return self._apply_btn

    @property
    def clear_filters_button(self) -> QPushButton:
        """Return the Clear Filters button."""
        return self._clear_btn

    @property
    def filter_validation_label(self) -> QLabel:
        """Return the inline filter validation message label."""
        return self._validation_label

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
    def pagination_bar(self) -> QFrame:
        """Return the pagination bar frame."""
        return self._pagination_bar

    @property
    def prev_page_button(self) -> QPushButton:
        """Return the Previous page button."""
        return self._prev_btn

    @property
    def next_page_button(self) -> QPushButton:
        """Return the Next page button."""
        return self._next_btn

    @property
    def page_range_label(self) -> QLabel:
        """Return the page range summary label."""
        return self._page_range_label

    def event_at(self, row: int) -> Event | None:
        """Return the original Event instance at the specified row index."""
        return self._model.event_at(row)

    @property
    def inspector(self) -> EventInspectorPanel:
        """Return the integrated EventInspectorPanel instance."""
        return self._inspector

    @property
    def inspector_panel(self) -> EventInspectorPanel:
        """Alias for inspector property."""
        return self._inspector

    @property
    def selected_event(self) -> Event | None:
        """Return the currently selected Event, or None if unselected."""
        return self._inspector.current_event

    @property
    def is_active(self) -> bool:
        """Return True if the view is currently the active page in the shell."""
        return self._is_active

    # -----------------------------------------------------------------------
    # Navigation Lifecycle
    # -----------------------------------------------------------------------

    def notify_page_activated(self) -> None:
        """Handle lazy load notification when Events page is navigated to."""
        self._is_active = True
        if self._state == STATE_NOT_LOADED:
            self.load_requested.emit()
            self.query_requested.emit(self._current_query)

    def notify_page_deactivated(self) -> None:
        """Handle deactivation notification when leaving Events page."""
        self._is_active = False

    def refresh(self) -> None:
        """Trigger a refresh request using active query if not loading."""
        if self._state != STATE_LOADING:
            self.refresh_requested.emit()

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

        sev, src, evt, pid_val, host_val, start_iso, end_iso = validated
        self._validation_label.setText("")

        self._table.clearSelection()
        self._inspector.set_event(None)

        new_query = EventsQuery(
            severity=sev,
            source=src,
            event_type=evt,
            pid=pid_val,
            host_id=host_val,
            start_time=start_iso,
            end_time=end_iso,
            limit=self._page_size,
            offset=0,
        )
        self._current_query = new_query
        self.query_requested.emit(new_query)

    def clear_filters(self) -> None:
        """Clear all filter inputs and emit query_requested with offset 0."""
        if self._state == STATE_LOADING:
            return

        self._severity_combo.setCurrentIndex(0)
        self._source_input.clear()
        self._type_input.clear()
        self._pid_input.clear()
        self._host_input.clear()
        self._start_time_check.setChecked(False)
        self._end_time_check.setChecked(False)
        self._validation_label.setText("")

        self._table.clearSelection()
        self._inspector.set_event(None)

        new_query = EventsQuery(
            limit=self._page_size,
            offset=0,
        )
        self._current_query = new_query
        self.query_requested.emit(new_query)

    def go_next_page(self) -> None:
        """Advance to the next page of records using current filters."""
        if self._state == STATE_LOADING or not self._next_btn.isEnabled():
            return

        new_offset = self._current_query.offset + self._current_query.limit
        new_query = replace(self._current_query, offset=new_offset)
        self._current_query = new_query
        self.query_requested.emit(new_query)

    def go_prev_page(self) -> None:
        """Navigate to the previous page of records using current filters."""
        if self._state == STATE_LOADING or not self._prev_btn.isEnabled():
            return

        new_offset = max(0, self._current_query.offset - self._current_query.limit)
        new_query = replace(self._current_query, offset=new_offset)
        self._current_query = new_query
        self.query_requested.emit(new_query)

    def _validate_and_extract_filters(
        self,
    ) -> (
        tuple[
            str | None,
            str | None,
            str | None,
            int | None,
            str | None,
            str | None,
            str | None,
        ]
        | None
    ):
        """Validate all local input fields, returning tuple or None on error."""
        # 1. Severity
        sev = self._severity_combo.currentData()
        if sev is not None and str(sev).lower() not in VALID_SEVERITIES:
            self._validation_label.setText(
                f"Invalid severity selected: {sev}"
            )
            return None

        # 2. Source
        src_raw = self._source_input.text().strip()
        src = src_raw if src_raw else None

        # 3. Event Type
        type_raw = self._type_input.text().strip()
        evt = type_raw if type_raw else None

        # 4. PID (numeric validation, preserving PID 0)
        pid_raw = self._pid_input.text().strip()
        pid_val: int | None = None
        if pid_raw:
            try:
                pid_int = int(pid_raw)
                if pid_int < 0:
                    raise ValueError
                pid_val = pid_int
            except ValueError:
                self._validation_label.setText(
                    "PID must be a non-negative integer (e.g. 0, 1024)"
                )
                return None

        # 5. Host ID (UUID validation)
        host_raw = self._host_input.text().strip()
        host_val: str | None = None
        if host_raw:
            try:
                host_val = str(uuid.UUID(host_raw))
            except (ValueError, TypeError, AttributeError):
                self._validation_label.setText(
                    "Host ID must be a valid UUID (e.g. "
                    "12345678-1234-5678-1234-567812345678)"
                )
                return None

        # 6. Time Range
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
                self._validation_label.setText(
                    "Start time must be earlier than or equal to end time"
                )
                return None

        return (sev, src, evt, pid_val, host_val, start_iso, end_iso)

    # -----------------------------------------------------------------------
    # State Mutation API
    # -----------------------------------------------------------------------

    def set_loading(self) -> None:
        """Transition into the loading state while preserving existing records."""
        self._state = STATE_LOADING
        self._refresh_btn.setEnabled(False)
        self._apply_btn.setEnabled(False)
        self._clear_btn.setEnabled(False)
        self._prev_btn.setEnabled(False)
        self._next_btn.setEnabled(False)
        self._start_time_check.setEnabled(False)
        self._start_time_edit.setEnabled(False)
        self._end_time_check.setEnabled(False)
        self._end_time_edit.setEnabled(False)

        if self._model.rowCount() > 0:
            self._count_label.setText(
                f"Retained {self._model.rowCount()} events (refreshing...)"
            )
            self._page_range_label.setText(
                f"Loading page... (offset {self._current_query.offset})"
            )
        else:
            self._count_label.setText("Loading events from API...")
            self._page_range_label.setText("Loading...")
            self._banner_title.setText("Loading Security Events")
            self._banner_msg.setText("Querying backend API for security events...")
            self._status_banner.setVisible(True)
            self._retry_btn.setVisible(False)
            self._update_banner_styling("loading")

    def set_collection(self, collection: EventCollection) -> None:
        """Populate the table with records and update pagination metadata."""
        if not isinstance(collection, EventCollection):
            raise TypeError(
                f"Expected EventCollection, got {type(collection).__name__}"
            )

        self._table.clearSelection()
        self._inspector.set_event(None)
        self._model.set_collection(collection)
        items_count = len(collection.items)
        total = collection.total
        offset = collection.offset

        # Synchronize query offset/limit with collection response
        self._current_query = replace(
            self._current_query, offset=offset, limit=collection.limit
        )

        if items_count > 0:
            self._state = STATE_LOADED
            self._status_banner.setVisible(False)
            start_idx = offset + 1
            end_idx = offset + items_count
            self._count_label.setText(f"Showing {items_count} of {total} events")
            self._page_range_label.setText(
                f"Showing {start_idx}\u2013{end_idx} of {total} events"
            )
        else:
            self._state = STATE_EMPTY
            self._count_label.setText(f"0 events ({total} total, 0 displayed)")
            self._page_range_label.setText(f"0 of {total} events")
            self._status_banner.setVisible(True)
            self._retry_btn.setVisible(False)

            if self._current_query.has_active_filters:
                self._banner_title.setText("No Matching Security Events")
                self._banner_msg.setText(
                    "No security events match the active filter criteria. "
                    "Adjust or clear filters to see more results."
                )
            else:
                self._banner_title.setText("No Security Events Found")
                self._banner_msg.setText(
                    "The server returned zero security events for this system."
                )
            self._update_banner_styling("empty")

        self._refresh_btn.setEnabled(True)
        self._apply_btn.setEnabled(True)
        self._clear_btn.setEnabled(True)
        self._start_time_check.setEnabled(True)
        self._start_time_edit.setEnabled(self._start_time_check.isChecked())
        self._end_time_check.setEnabled(True)
        self._end_time_edit.setEnabled(self._end_time_check.isChecked())
        self._prev_btn.setEnabled(offset > 0)
        self._next_btn.setEnabled(offset + items_count < total)

    def set_error(self, message: str) -> None:
        """Transition into the failed state and display a sanitized message."""
        if not isinstance(message, str):
            raise TypeError(f"Expected str message, got {type(message).__name__}")

        self._table.clearSelection()
        self._inspector.set_event(None)
        self._state = STATE_FAILED
        self._refresh_btn.setEnabled(True)
        self._apply_btn.setEnabled(True)
        self._clear_btn.setEnabled(True)
        self._start_time_check.setEnabled(True)
        self._start_time_edit.setEnabled(self._start_time_check.isChecked())
        self._end_time_check.setEnabled(True)
        self._end_time_edit.setEnabled(self._end_time_check.isChecked())
        self._retry_btn.setVisible(True)
        self._status_banner.setVisible(True)

        # Retained records logic
        if self._model.rowCount() > 0:
            self._banner_title.setText("Events Refresh Failed")
            self._banner_msg.setText(
                f"{message} \u2014 Displaying retained records from previous query."
            )
            self._count_label.setText(
                f"Retained {self._model.rowCount()} events (refresh failed)"
            )
            self._page_range_label.setText(
                f"Page failed (offset {self._current_query.offset})"
            )
            self._prev_btn.setEnabled(self._current_query.offset > 0)
            self._next_btn.setEnabled(False)
        else:
            self._banner_title.setText("Failed to Load Security Events")
            self._banner_msg.setText(message)
            self._count_label.setText("0 events (load failed)")
            self._page_range_label.setText("0 of 0 events")
            self._prev_btn.setEnabled(False)
            self._next_btn.setEnabled(False)

        self._update_banner_styling("failed")

    def set_not_loaded(self) -> None:
        """Reset the view to the initial un-requested state."""
        self._state = STATE_NOT_LOADED
        self._table.clearSelection()
        self._inspector.set_event(None)
        self._model.clear()
        self._refresh_btn.setEnabled(True)
        self._apply_btn.setEnabled(True)
        self._clear_btn.setEnabled(True)
        self._start_time_check.setEnabled(True)
        self._start_time_edit.setEnabled(self._start_time_check.isChecked())
        self._end_time_check.setEnabled(True)
        self._end_time_edit.setEnabled(self._end_time_check.isChecked())
        self._retry_btn.setVisible(False)
        self._prev_btn.setEnabled(False)
        self._next_btn.setEnabled(False)

        self._count_label.setText("0 events (not loaded)")
        self._page_range_label.setText("0 of 0 events")
        self._banner_title.setText("Events Not Loaded")
        self._banner_msg.setText(
            "Security event records have not been retrieved from the API yet. "
            "Click Refresh Events to load."
        )
        self._status_banner.setVisible(True)
        self._update_banner_styling("not_loaded")

    # -----------------------------------------------------------------------
    # Internal Helpers
    # -----------------------------------------------------------------------

    def _apply_state_ui(self) -> None:
        """Apply visual properties corresponding to current _state."""
        self.set_not_loaded()

    def _update_banner_styling(self, state_val: str) -> None:
        """Update Qt dynamic property on banner and trigger repolish."""
        self._status_banner.setProperty("state", state_val)
        style = self._status_banner.style()
        if style is not None:
            style.unpolish(self._status_banner)
            style.polish(self._status_banner)

    def _handle_refresh_click(self) -> None:
        """Forward user click on Refresh Events button to signals."""
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
            self._inspector.set_event(None)
            return

        selected_rows = sel_model.selectedRows()
        if selected_rows:
            row = selected_rows[0].row()
        else:
            selected_indexes = sel_model.selectedIndexes()
            if not selected_indexes:
                self._inspector.set_event(None)
                return
            row = selected_indexes[0].row()

        event = self._model.event_at(row)
        if event is not None:
            self._inspector.set_event(event)
        else:
            self._inspector.set_event(None)

    def _handle_inspector_closed(self) -> None:
        """Handle inspector close button click by clearing row selection."""
        self._table.clearSelection()
        self._inspector.set_event(None)
