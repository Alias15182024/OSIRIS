/**
 * OSIRIS Platform - Event Explorer View Controller
 * Phase 1.6 Step 4
 *
 * Responsibilities:
 * - Load and render paginated event telemetry via GET /api/events.
 * - Manage filter state across host_id, start_time, end_time, source, event_type, severity, process_id, and pid.
 * - Construct sanitized query strings strictly using URLSearchParams.
 * - Manage pagination state (limit, offset, total) with boundary protections.
 * - Render event detail inspector modal via GET /api/events/{event_id}.
 * - Format JSON payloads safely via JSON.stringify into textContent (strictly textContent, no raw HTML injection).
 * - Handle loading, empty ("No events found matching the selected filters."), and error states.
 * - Avoid redundant network requests during rapid tab switches.
 */

(function (window, document) {
  'use strict';

  const PAGE_SIZE = 25;
  const REFRESH_COOLDOWN_MS = 8000;

  // State management
  const state = {
    limit: PAGE_SIZE,
    offset: 0,
    total: 0,
    isLoading: false,
    lastFetchTime: 0,
    hasLoadedOnce: false,
    filters: {
      host_id: '',
      start_time: '',
      end_time: '',
      source: '',
      event_type: '',
      severity: '',
      process_id: '',
      pid: '',
    },
  };

  // Cached DOM elements
  let dom = {};

  /**
   * Cache DOM element references for Event Explorer.
   */
  function cacheElements() {
    dom = {
      // Filter form & inputs
      filterForm: document.getElementById('events-filter-form'),
      inputHostId: document.getElementById('filter-event-host-id'),
      inputStartTime: document.getElementById('filter-event-start-time'),
      inputEndTime: document.getElementById('filter-event-end-time'),
      inputSource: document.getElementById('filter-event-source'),
      inputEventType: document.getElementById('filter-event-event-type'),
      selectSeverity: document.getElementById('filter-event-severity'),
      inputProcessId: document.getElementById('filter-event-process-id'),
      inputPid: document.getElementById('filter-event-pid'),
      applyFilterBtn: document.getElementById('filter-event-apply-btn'),
      resetFilterBtn: document.getElementById('filter-event-reset-btn'),

      // Table & containers
      tableContainer: document.getElementById('events-table-container'),
      table: document.getElementById('events-table'),
      tbody: document.getElementById('events-tbody'),
      resultCountLabel: document.getElementById('events-result-count'),
      errorBox: document.getElementById('events-error-box'),
      emptyState: document.getElementById('events-empty-state'),
      emptyResetBtn: document.getElementById('events-empty-reset-btn'),

      // Pagination
      paginationToolbar: document.getElementById('events-pagination'),
      prevBtn: document.getElementById('events-prev-btn'),
      nextBtn: document.getElementById('events-next-btn'),
      pageInfo: document.getElementById('events-page-info'),

      // Detail Modal
      detailModal: document.getElementById('event-detail-modal-container'),
      detailCloseBtn: document.getElementById('event-detail-close-btn'),
      detailError: document.getElementById('event-detail-error'),
      detailContent: document.getElementById('event-detail-content'),
      detailEventId: document.getElementById('detail-event-id'),
      detailTimestamp: document.getElementById('detail-timestamp'),
      detailSource: document.getElementById('detail-source'),
      detailEventType: document.getElementById('detail-event-type'),
      detailAction: document.getElementById('detail-action'),
      detailSeverity: document.getElementById('detail-severity'),
      detailUid: document.getElementById('detail-uid'),
      detailUsername: document.getElementById('detail-username'),
      detailPid: document.getElementById('detail-pid'),
      detailPpid: document.getElementById('detail-ppid'),
      detailCommand: document.getElementById('detail-command'),
      detailObjectType: document.getElementById('detail-object-type'),
      detailObjectPath: document.getElementById('detail-object-path'),
      detailSuccess: document.getElementById('detail-success'),
      detailResult: document.getElementById('detail-result'),
      detailPayload: document.getElementById('detail-payload'),
    };
  }

  /**
   * Format ISO timestamps for human reading.
   *
   * @param {string|null} isoString
   * @returns {string}
   */
  function formatTimestamp(isoString) {
    if (!isoString) return '-';
    try {
      const d = new Date(isoString);
      if (isNaN(d.getTime())) return String(isoString);
      return d.toLocaleString();
    } catch {
      return String(isoString);
    }
  }

  /**
   * Map severity to CSS badge class.
   *
   * @param {string|null} severity
   * @returns {string}
   */
  function getSeverityBadgeClass(severity) {
    const s = String(severity || '').toLowerCase();
    switch (s) {
      case 'info':
      case 'low':
        return 'badge-info';
      case 'warning':
      case 'medium':
        return 'badge-warning';
      case 'error':
      case 'danger':
      case 'high':
      case 'critical':
        return 'badge-danger';
      default:
        return 'badge-secondary';
    }
  }

  /**
   * Construct target URL with URLSearchParams strictly from active filters and pagination.
   *
   * @returns {string}
   */
  function buildEventsUrl() {
    const params = new URLSearchParams();

    // Required pagination parameters
    params.set('limit', String(state.limit));
    params.set('offset', String(state.offset));

    // Optional query filters (only include non-empty values)
    if (state.filters.host_id) {
      params.set('host_id', state.filters.host_id.trim());
    }
    if (state.filters.start_time) {
      params.set('start_time', state.filters.start_time.trim());
    }
    if (state.filters.end_time) {
      params.set('end_time', state.filters.end_time.trim());
    }
    if (state.filters.source) {
      params.set('source', state.filters.source.trim());
    }
    if (state.filters.event_type) {
      params.set('event_type', state.filters.event_type.trim());
    }
    if (state.filters.severity) {
      params.set('severity', state.filters.severity.trim());
    }
    if (state.filters.process_id) {
      params.set('process_id', state.filters.process_id.trim());
    }
    if (state.filters.pid !== '' && state.filters.pid !== null && state.filters.pid !== undefined) {
      params.set('pid', String(state.filters.pid).trim());
    }

    return `/api/events?${params.toString()}`;
  }

  /**
   * Clear all table rows safely from the DOM.
   */
  function clearTableRows() {
    if (!dom.tbody) return;
    while (dom.tbody.firstChild) {
      dom.tbody.removeChild(dom.tbody.firstChild);
    }
  }

  /**
   * Render table rows for events.
   *
   * @param {Array<Object>} items
   */
  function renderEventsTable(items) {
    clearTableRows();

    if (!items || items.length === 0) {
      if (dom.table) dom.table.classList.add('hidden');
      if (dom.emptyState) dom.emptyState.classList.remove('hidden');
      return;
    }

    if (dom.emptyState) dom.emptyState.classList.add('hidden');
    if (dom.table) dom.table.classList.remove('hidden');

    items.forEach((event) => {
      const tr = document.createElement('tr');
      tr.className = 'clickable-row';
      tr.setAttribute('data-event-id', event.id);
      tr.setAttribute('tabindex', '0');
      tr.setAttribute('role', 'button');
      tr.setAttribute('aria-label', `Inspect event ${event.id}`);

      // Row click and Enter key to inspect
      tr.addEventListener('click', () => openEventDetail(event.id));
      tr.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          openEventDetail(event.id);
        }
      });

      // 1. Timestamp
      const tdTime = document.createElement('td');
      tdTime.className = 'mono-cell';
      tdTime.textContent = formatTimestamp(event.timestamp);
      tr.appendChild(tdTime);

      // 2. Source
      const tdSource = document.createElement('td');
      tdSource.textContent = event.source || '-';
      tr.appendChild(tdSource);

      // 3. Event Type
      const tdType = document.createElement('td');
      tdType.className = 'mono-cell';
      tdType.textContent = event.event_type || '-';
      tr.appendChild(tdType);

      // 4. Severity Badge
      const tdSeverity = document.createElement('td');
      const badge = document.createElement('span');
      badge.className = `badge ${getSeverityBadgeClass(event.severity)}`;
      badge.textContent = (event.severity || 'UNKNOWN').toUpperCase();
      tdSeverity.appendChild(badge);
      tr.appendChild(tdSeverity);

      // 5. User
      const tdUser = document.createElement('td');
      tdUser.textContent = event.username || '-';
      tr.appendChild(tdUser);

      // 6. PID
      const tdPid = document.createElement('td');
      tdPid.className = 'mono-cell';
      tdPid.textContent = (event.pid !== null && event.pid !== undefined) ? String(event.pid) : '-';
      tr.appendChild(tdPid);

      // 7. Action
      const tdAction = document.createElement('td');
      tdAction.textContent = event.action || '-';
      tr.appendChild(tdAction);

      // 8. Status (derived from success boolean)
      const tdStatus = document.createElement('td');
      if (event.success === true) {
        const successBadge = document.createElement('span');
        successBadge.className = 'badge badge-success';
        successBadge.textContent = 'Success';
        tdStatus.appendChild(successBadge);
      } else if (event.success === false) {
        const failBadge = document.createElement('span');
        failBadge.className = 'badge badge-danger';
        failBadge.textContent = 'Failure';
        tdStatus.appendChild(failBadge);
      } else {
        tdStatus.textContent = '-';
      }
      tr.appendChild(tdStatus);

      dom.tbody.appendChild(tr);
    });
  }

  /**
   * Update pagination controls and result range counters.
   */
  function updatePagination() {
    const total = state.total;
    const offset = state.offset;
    const limit = state.limit;

    // Previous button enabled if offset > 0
    if (dom.prevBtn) {
      dom.prevBtn.disabled = offset === 0 || state.isLoading;
    }

    // Next button enabled if offset + limit < total
    if (dom.nextBtn) {
      dom.nextBtn.disabled = (offset + limit >= total) || state.isLoading;
    }

    // Results range label
    if (dom.resultCountLabel) {
      dom.resultCountLabel.textContent = `${total.toLocaleString()} event${total === 1 ? '' : 's'}`;
    }

    // Page indicator
    if (dom.pageInfo) {
      if (total === 0) {
        dom.pageInfo.textContent = 'Showing 0 of 0 events';
      } else {
        const start = offset + 1;
        const end = Math.min(offset + limit, total);
        dom.pageInfo.textContent = `Showing ${start}-${end} of ${total.toLocaleString()} events`;
      }
    }
  }

  /**
   * Fetch and render event records based on current state.
   *
   * @param {Object} [options={}]
   * @param {boolean} [options.force=false]
   */
  async function loadEvents(options = {}) {
    const force = options && options.force === true;

    // Must be authenticated
    if (!window.OsirisApi || !window.OsirisApi.getToken()) {
      return;
    }

    const now = Date.now();
    if (!force && state.hasLoadedOnce && (now - state.lastFetchTime < REFRESH_COOLDOWN_MS)) {
      return;
    }

    if (state.isLoading) return;
    state.isLoading = true;

    if (dom.errorBox) {
      dom.errorBox.classList.add('hidden');
      dom.errorBox.textContent = '';
    }

    if (dom.applyFilterBtn) {
      dom.applyFilterBtn.disabled = true;
    }

    try {
      const url = buildEventsUrl();
      const data = await window.OsirisApi.fetchWithAuth(url);

      if (!data || !Array.isArray(data.items)) {
        throw new Error('Invalid event list response');
      }

      state.total = typeof data.total === 'number' ? data.total : 0;
      state.lastFetchTime = Date.now();
      state.hasLoadedOnce = true;

      renderEventsTable(data.items);
      updatePagination();
    } catch (err) {
      clearTableRows();
      if (dom.table) dom.table.classList.add('hidden');
      if (dom.emptyState) dom.emptyState.classList.add('hidden');

      if (dom.errorBox) {
        dom.errorBox.textContent = err.message || 'Failed to load events. Please verify filter inputs.';
        dom.errorBox.classList.remove('hidden');
      }
      if (dom.resultCountLabel) {
        dom.resultCountLabel.textContent = 'Unavailable';
      }
      if (dom.pageInfo) {
        dom.pageInfo.textContent = 'Error loading events';
      }
    } finally {
      state.isLoading = false;
      if (dom.applyFilterBtn) {
        dom.applyFilterBtn.disabled = false;
      }
      updatePagination();
    }
  }

  /**
   * Apply filters from input fields and reset to page 1.
   */
  function handleFilterSubmit(e) {
    if (e && typeof e.preventDefault === 'function') {
      e.preventDefault();
    }

    state.filters.host_id = dom.inputHostId ? dom.inputHostId.value.trim() : '';
    state.filters.start_time = dom.inputStartTime ? dom.inputStartTime.value.trim() : '';
    state.filters.end_time = dom.inputEndTime ? dom.inputEndTime.value.trim() : '';
    state.filters.source = dom.inputSource ? dom.inputSource.value.trim() : '';
    state.filters.event_type = dom.inputEventType ? dom.inputEventType.value.trim() : '';
    state.filters.severity = dom.selectSeverity ? dom.selectSeverity.value.trim() : '';
    state.filters.process_id = dom.inputProcessId ? dom.inputProcessId.value.trim() : '';
    state.filters.pid = dom.inputPid ? dom.inputPid.value.trim() : '';

    state.offset = 0;
    loadEvents({ force: true });
  }

  /**
   * Reset filter fields and state, then reload page 1.
   */
  function handleFilterReset() {
    if (dom.filterForm) {
      dom.filterForm.reset();
    }
    if (dom.inputHostId) dom.inputHostId.value = '';
    if (dom.inputStartTime) dom.inputStartTime.value = '';
    if (dom.inputEndTime) dom.inputEndTime.value = '';
    if (dom.inputSource) dom.inputSource.value = '';
    if (dom.inputEventType) dom.inputEventType.value = '';
    if (dom.selectSeverity) dom.selectSeverity.value = '';
    if (dom.inputProcessId) dom.inputProcessId.value = '';
    if (dom.inputPid) dom.inputPid.value = '';

    state.filters = {
      host_id: '',
      start_time: '',
      end_time: '',
      source: '',
      event_type: '',
      severity: '',
      process_id: '',
      pid: '',
    };

    state.offset = 0;
    loadEvents({ force: true });
  }

  /**
   * Navigate to the previous page of events.
   */
  function handlePreviousPage() {
    if (state.offset > 0 && !state.isLoading) {
      state.offset = Math.max(0, state.offset - state.limit);
      loadEvents({ force: true });
    }
  }

  /**
   * Navigate to the next page of events.
   */
  function handleNextPage() {
    if (state.offset + state.limit < state.total && !state.isLoading) {
      state.offset += state.limit;
      loadEvents({ force: true });
    }
  }

  /**
   * Open the Event Detail Inspector modal and load the single event.
   *
   * @param {string} eventId
   */
  async function openEventDetail(eventId) {
    if (!eventId || !dom.detailModal) return;

    dom.detailModal.classList.remove('hidden');
    if (dom.detailError) {
      dom.detailError.classList.add('hidden');
      dom.detailError.textContent = '';
    }

    // Set initial loading state in modal fields
    setDetailFieldsLoading(eventId);

    try {
      const url = `/api/events/${encodeURIComponent(eventId)}`;
      const event = await window.OsirisApi.fetchWithAuth(url);

      if (!event || typeof event !== 'object') {
        throw new Error('Event details could not be retrieved.');
      }

      populateDetailFields(event);
    } catch (err) {
      if (dom.detailError) {
        dom.detailError.textContent = err.message || 'Event not found or failed to load.';
        dom.detailError.classList.remove('hidden');
      }
    }
  }

  /**
   * Put modal fields in a loading placeholder state.
   *
   * @param {string} eventId
   */
  function setDetailFieldsLoading(eventId) {
    if (dom.detailEventId) dom.detailEventId.textContent = eventId;
    if (dom.detailTimestamp) dom.detailTimestamp.textContent = 'Loading...';
    if (dom.detailSource) dom.detailSource.textContent = 'Loading...';
    if (dom.detailEventType) dom.detailEventType.textContent = 'Loading...';
    if (dom.detailAction) dom.detailAction.textContent = 'Loading...';
    if (dom.detailSeverity) dom.detailSeverity.textContent = 'Loading...';
    if (dom.detailUid) dom.detailUid.textContent = '-';
    if (dom.detailUsername) dom.detailUsername.textContent = '-';
    if (dom.detailPid) dom.detailPid.textContent = '-';
    if (dom.detailPpid) dom.detailPpid.textContent = '-';
    if (dom.detailCommand) dom.detailCommand.textContent = '-';
    if (dom.detailObjectType) dom.detailObjectType.textContent = '-';
    if (dom.detailObjectPath) dom.detailObjectPath.textContent = '-';
    if (dom.detailSuccess) dom.detailSuccess.textContent = '-';
    if (dom.detailResult) dom.detailResult.textContent = '-';
    if (dom.detailPayload) dom.detailPayload.textContent = '{\n  "loading": true\n}';
  }

  /**
   * Populate modal with full EventResponse data safely using textContent.
   *
   * @param {Object} event
   */
  function populateDetailFields(event) {
    if (dom.detailEventId) dom.detailEventId.textContent = event.id || '-';
    if (dom.detailTimestamp) dom.detailTimestamp.textContent = formatTimestamp(event.timestamp);
    if (dom.detailSource) dom.detailSource.textContent = event.source || '-';
    if (dom.detailEventType) dom.detailEventType.textContent = event.event_type || '-';
    if (dom.detailAction) dom.detailAction.textContent = event.action || '-';

    if (dom.detailSeverity) {
      dom.detailSeverity.textContent = '';
      const badge = document.createElement('span');
      badge.className = `badge ${getSeverityBadgeClass(event.severity)}`;
      badge.textContent = (event.severity || 'UNKNOWN').toUpperCase();
      dom.detailSeverity.appendChild(badge);
    }

    if (dom.detailUid) dom.detailUid.textContent = (event.uid !== null && event.uid !== undefined) ? String(event.uid) : '-';
    if (dom.detailUsername) dom.detailUsername.textContent = event.username || '-';
    if (dom.detailPid) dom.detailPid.textContent = (event.pid !== null && event.pid !== undefined) ? String(event.pid) : '-';
    if (dom.detailPpid) dom.detailPpid.textContent = (event.ppid !== null && event.ppid !== undefined) ? String(event.ppid) : '-';
    if (dom.detailCommand) dom.detailCommand.textContent = event.command || '-';
    if (dom.detailObjectType) dom.detailObjectType.textContent = event.object_type || '-';
    if (dom.detailObjectPath) dom.detailObjectPath.textContent = event.object_path || '-';

    if (dom.detailSuccess) {
      if (event.success === true) {
        dom.detailSuccess.textContent = 'True (Success)';
      } else if (event.success === false) {
        dom.detailSuccess.textContent = 'False (Failure)';
      } else {
        dom.detailSuccess.textContent = '-';
      }
    }

    if (dom.detailResult) dom.detailResult.textContent = event.result || '-';

    if (dom.detailPayload) {
      try {
        const payloadObj = event.payload !== null && event.payload !== undefined ? event.payload : {};
        dom.detailPayload.textContent = JSON.stringify(payloadObj, null, 2);
      } catch {
        dom.detailPayload.textContent = String(event.payload || '{}');
      }
    }
  }

  /**
   * Close the Event Detail Inspector modal.
   */
  function closeEventDetail() {
    if (dom.detailModal) {
      dom.detailModal.classList.add('hidden');
    }
  }

  /**
   * Reset the Event view state on logout.
   */
  function resetEvents() {
    state.offset = 0;
    state.total = 0;
    state.hasLoadedOnce = false;
    state.lastFetchTime = 0;
    handleFilterReset();
    clearTableRows();
    closeEventDetail();
    if (dom.resultCountLabel) dom.resultCountLabel.textContent = '0 events';
    if (dom.pageInfo) dom.pageInfo.textContent = 'Showing 0 of 0 events';
    if (dom.table) dom.table.classList.add('hidden');
    if (dom.emptyState) dom.emptyState.classList.add('hidden');
  }

  /**
   * Bind event listeners for the Event Explorer.
   */
  function bindEvents() {
    if (dom.filterForm) {
      dom.filterForm.addEventListener('submit', handleFilterSubmit);
    }
    if (dom.resetFilterBtn) {
      dom.resetFilterBtn.addEventListener('click', handleFilterReset);
    }
    if (dom.emptyResetBtn) {
      dom.emptyResetBtn.addEventListener('click', handleFilterReset);
    }

    if (dom.prevBtn) {
      dom.prevBtn.addEventListener('click', handlePreviousPage);
    }
    if (dom.nextBtn) {
      dom.nextBtn.addEventListener('click', handleNextPage);
    }

    // Detail modal close
    if (dom.detailCloseBtn) {
      dom.detailCloseBtn.addEventListener('click', closeEventDetail);
    }
    if (dom.detailModal) {
      dom.detailModal.addEventListener('click', (e) => {
        if (e.target === dom.detailModal) {
          closeEventDetail();
        }
      });
    }

    // Escape key closes modal
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && dom.detailModal && !dom.detailModal.classList.contains('hidden')) {
        closeEventDetail();
      }
    });
  }

  /**
   * Initialize the Event Explorer view.
   */
  function initEvents() {
    cacheElements();
    bindEvents();
  }

  // Initialize when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initEvents);
  } else {
    initEvents();
  }

  // Export view controller to window
  window.OsirisEvents = Object.freeze({
    initEvents,
    loadEvents,
    resetEvents,
    openEventDetail,
    closeEventDetail,
  });

})(typeof window !== 'undefined' ? window : this, typeof document !== 'undefined' ? document : {});
