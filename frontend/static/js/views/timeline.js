/**
 * OSIRIS Platform - Timeline Reconstruction View Controller
 * Phase 2 Milestone 2.2
 *
 * Responsibilities:
 * - Load and render unified chronological timeline entries via GET /api/timeline.
 * - Manage filter state across host_id, start_time, end_time, record_type, and order.
 * - Manage pagination state (limit, offset, total) with boundary protections.
 * - Render chronological timeline cards with source provenance, severity, and entity correlation chips.
 * - Format JSON payloads and entity context strictly via textContent (no raw HTML injection).
 * - Handle loading, empty ("No timeline entries found matching the selected filters."), and error states.
 */

(function (window, document) {
  'use strict';

  const PAGE_SIZE = 25;
  const REFRESH_COOLDOWN_MS = 5000;

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
      record_type: '',
      order: 'asc',
    },
  };

  // Cached DOM elements
  let dom = {};

  /**
   * Cache DOM element references for Timeline Explorer.
   */
  function cacheElements() {
    dom = {
      // Filter form & inputs
      filterForm: document.getElementById('timeline-filter-form'),
      inputHostId: document.getElementById('filter-timeline-host-id'),
      inputStartTime: document.getElementById('filter-timeline-start-time'),
      inputEndTime: document.getElementById('filter-timeline-end-time'),
      selectRecordType: document.getElementById('filter-timeline-record-type'),
      selectOrder: document.getElementById('filter-timeline-order'),
      applyFilterBtn: document.getElementById('filter-timeline-apply-btn'),
      resetFilterBtn: document.getElementById('filter-timeline-reset-btn'),

      // Stream container & indicators
      streamContainer: document.getElementById('timeline-stream'),
      resultCountLabel: document.getElementById('timeline-result-count'),
      errorBox: document.getElementById('timeline-error-box'),
      emptyState: document.getElementById('timeline-empty-state'),
      emptyResetBtn: document.getElementById('timeline-empty-reset-btn'),

      // Pagination
      paginationToolbar: document.getElementById('timeline-pagination'),
      prevBtn: document.getElementById('timeline-prev-btn'),
      nextBtn: document.getElementById('timeline-next-btn'),
      pageInfo: document.getElementById('timeline-page-info'),
    };
  }

  /**
   * Format ISO UTC timestamp for tabular display.
   * @param {string} isoString
   * @returns {string}
   */
  function formatTimestamp(isoString) {
    if (!isoString) return '--';
    try {
      const d = new Date(isoString);
      return d.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
    } catch {
      return String(isoString);
    }
  }

  /**
   * Create an element with textContent and classes.
   * Strictly avoids raw markup insertion for security.
   */
  function createEl(tag, classNames, text) {
    const el = document.createElement(tag);
    if (classNames) {
      if (Array.isArray(classNames)) {
        classNames.forEach(c => el.classList.add(c));
      } else {
        el.className = classNames;
      }
    }
    if (text !== undefined && text !== null) {
      el.textContent = String(text);
    }
    return el;
  }

  /**
   * Render timeline entries into the stream container.
   * @param {Array<Object>} items
   */
  function renderTimelineItems(items) {
    if (!dom.streamContainer) return;

    // Clear previous items safely
    while (dom.streamContainer.firstChild) {
      dom.streamContainer.removeChild(dom.streamContainer.firstChild);
    }

    if (!items || items.length === 0) {
      if (dom.emptyState) dom.emptyState.classList.remove('hidden');
      return;
    }

    if (dom.emptyState) dom.emptyState.classList.add('hidden');

    items.forEach((item, index) => {
      const card = createEl('div', 'timeline-card');
      card.setAttribute('data-entry-id', item.id);

      // Card Header: Timestamp, badges (severity, record_type, source)
      const header = createEl('div', 'timeline-card-header');

      const timeCol = createEl('div', 'timeline-time-col');
      const timeBadge = createEl('span', 'timeline-timestamp mono-cell', formatTimestamp(item.timestamp));
      timeCol.appendChild(timeBadge);

      const badgesCol = createEl('div', 'timeline-badges-col');

      // Severity badge
      const sevClass = 'badge ' + (
        item.severity === 'critical' ? 'badge-danger' :
        item.severity === 'high' ? 'badge-danger' :
        item.severity === 'medium' ? 'badge-warning' :
        item.severity === 'low' ? 'badge-info' : 'badge-secondary'
      );
      badgesCol.appendChild(createEl('span', sevClass, item.severity || 'info'));

      // Record type badge
      badgesCol.appendChild(createEl('span', 'badge badge-outline', item.record_type));

      // Source provenance badge
      badgesCol.appendChild(createEl('span', 'badge badge-secondary mono-cell', 'src: ' + item.source));

      header.appendChild(timeCol);
      header.appendChild(badgesCol);
      card.appendChild(header);

      // Card Body: Event Type, Action, Description
      const body = createEl('div', 'timeline-card-body');

      const titleRow = createEl('div', 'timeline-title-row');
      const eventTypeSpan = createEl('span', 'timeline-event-type mono-cell', item.event_type);
      const actionSpan = createEl('span', 'timeline-action badge badge-info', item.action);
      titleRow.appendChild(eventTypeSpan);
      titleRow.appendChild(actionSpan);
      body.appendChild(titleRow);

      if (item.description) {
        const descRow = createEl('div', 'timeline-description', item.description);
        body.appendChild(descRow);
      }

      // Entity Correlation Context Section
      const contextSection = createEl('div', 'timeline-correlations');

      // Process Context
      if (item.process_context) {
        const pc = item.process_context;
        const chip = createEl('span', 'correlation-chip chip-process');
        const text = 'Process: PID ' + (pc.pid !== null && pc.pid !== undefined ? pc.pid : '--') +
          (pc.command ? ' (' + pc.command + ')' : '');
        chip.textContent = text;
        contextSection.appendChild(chip);
      }

      // User Context
      if (item.user_context) {
        const uc = item.user_context;
        const chip = createEl('span', 'correlation-chip chip-user');
        const text = 'User: ' + (uc.username || (uc.uid !== null ? 'UID ' + uc.uid : 'unknown'));
        chip.textContent = text;
        contextSection.appendChild(chip);
      }

      // Session Context
      if (item.session_context) {
        const sc = item.session_context;
        const chip = createEl('span', 'correlation-chip chip-session');
        const text = 'Session: ' + (sc.terminal || sc.session_type || 'active');
        chip.textContent = text;
        contextSection.appendChild(chip);
      }

      // File Context
      if (item.file_context) {
        const fc = item.file_context;
        const chip = createEl('span', 'correlation-chip chip-file');
        chip.textContent = 'File: ' + fc.path;
        contextSection.appendChild(chip);
      }

      // Resource Context
      if (item.resource_context) {
        const rc = item.resource_context;
        const chip = createEl('span', 'correlation-chip chip-resource');
        chip.textContent = 'Telemetry: CPU ' + (rc.cpu_percent !== null ? rc.cpu_percent + '%' : '--') +
          ', Mem ' + (rc.memory_percent !== null ? rc.memory_percent + '%' : '--');
        contextSection.appendChild(chip);
      }

      // Snapshot Context
      if (item.snapshot_context) {
        const snc = item.snapshot_context;
        const chip = createEl('span', 'correlation-chip chip-snapshot');
        let text = 'Snapshot (' + snc.snapshot_type + ')';
        if (snc.process_captured) {
          text += ' [proc captured]';
        }
        chip.textContent = text;
        contextSection.appendChild(chip);
      }

      body.appendChild(contextSection);
      card.appendChild(body);
      dom.streamContainer.appendChild(card);
    });
  }

  /**
   * Update pagination controls based on state.
   */
  function updatePagination() {
    if (!dom.pageInfo || !dom.prevBtn || !dom.nextBtn) return;

    const start = state.total === 0 ? 0 : state.offset + 1;
    const end = Math.min(state.offset + state.limit, state.total);
    dom.pageInfo.textContent = 'Showing ' + start + '–' + end + ' of ' + state.total;

    dom.prevBtn.disabled = state.offset === 0;
    dom.nextBtn.disabled = state.offset + state.limit >= state.total;

    if (dom.resultCountLabel) {
      dom.resultCountLabel.textContent = state.total + ' entries';
    }
  }

  /**
   * Build parameterized query URL for timeline reconstruction.
   * @returns {string}
   */
  function buildTimelineUrl() {
    const params = new URLSearchParams();
    params.set('limit', String(state.limit));
    params.set('offset', String(state.offset));
    params.set('order', state.filters.order || 'asc');

    if (state.filters.host_id) params.set('host_id', state.filters.host_id);
    if (state.filters.start_time) params.set('start_time', state.filters.start_time);
    if (state.filters.end_time) params.set('end_time', state.filters.end_time);
    if (state.filters.record_type) params.set('record_type', state.filters.record_type);

    return '/api/timeline?' + params.toString();
  }

  /**
   * Fetch and render timeline telemetry.
   * @param {boolean} force - Bypass cooldown check
   */
  async function loadTimeline(force = false) {
    if (state.isLoading) return;

    const now = Date.now();
    if (!force && state.hasLoadedOnce && now - state.lastFetchTime < REFRESH_COOLDOWN_MS) {
      return;
    }

    state.isLoading = true;
    showLoading(true);
    hideError();

    try {
      const url = buildTimelineUrl();
      const data = await window.OsirisApi.fetchWithAuth(url);

      state.total = data.total || 0;
      state.lastFetchTime = Date.now();
      state.hasLoadedOnce = true;

      renderTimelineItems(data.items || []);
      updatePagination();
    } catch (err) {
      showError(err.message || 'Failed to load timeline telemetry');
    } finally {
      state.isLoading = false;
      showLoading(false);
    }
  }

  function showLoading(isLoading) {
    const spinner = document.getElementById('timeline-loading-indicator');
    if (spinner) {
      if (isLoading) spinner.classList.remove('hidden');
      else spinner.classList.add('hidden');
    }
  }

  function showError(msg) {
    if (dom.errorBox) {
      dom.errorBox.textContent = msg;
      dom.errorBox.classList.remove('hidden');
    }
  }

  function hideError() {
    if (dom.errorBox) {
      dom.errorBox.textContent = '';
      dom.errorBox.classList.add('hidden');
    }
  }

  /**
   * Bind event listeners for timeline view.
   */
  function bindEvents() {
    if (dom.filterForm) {
      dom.filterForm.addEventListener('submit', (e) => {
        e.preventDefault();
        state.offset = 0;
        state.filters.host_id = dom.inputHostId ? dom.inputHostId.value.trim() : '';
        state.filters.start_time = dom.inputStartTime ? dom.inputStartTime.value.trim() : '';
        state.filters.end_time = dom.inputEndTime ? dom.inputEndTime.value.trim() : '';
        state.filters.record_type = dom.selectRecordType ? dom.selectRecordType.value : '';
        state.filters.order = dom.selectOrder ? dom.selectOrder.value : 'asc';
        loadTimeline(true);
      });
    }

    if (dom.resetFilterBtn) {
      dom.resetFilterBtn.addEventListener('click', () => {
        if (dom.filterForm) dom.filterForm.reset();
        state.offset = 0;
        state.filters = { host_id: '', start_time: '', end_time: '', record_type: '', order: 'asc' };
        loadTimeline(true);
      });
    }

    if (dom.emptyResetBtn) {
      dom.emptyResetBtn.addEventListener('click', () => {
        if (dom.filterForm) dom.filterForm.reset();
        state.offset = 0;
        state.filters = { host_id: '', start_time: '', end_time: '', record_type: '', order: 'asc' };
        loadTimeline(true);
      });
    }

    if (dom.prevBtn) {
      dom.prevBtn.addEventListener('click', () => {
        if (state.offset > 0) {
          state.offset = Math.max(0, state.offset - state.limit);
          loadTimeline(true);
        }
      });
    }

    if (dom.nextBtn) {
      dom.nextBtn.addEventListener('click', () => {
        if (state.offset + state.limit < state.total) {
          state.offset += state.limit;
          loadTimeline(true);
        }
      });
    }
  }

  function initTimeline() {
    cacheElements();
    bindEvents();
  }

  if (typeof document !== 'undefined' && typeof document.addEventListener === 'function') {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', initTimeline);
    } else {
      initTimeline();
    }
  }

  window.OsirisTimeline = Object.freeze({
    initTimeline,
    loadTimeline,
  });

})(typeof window !== 'undefined' ? window : this, typeof document !== 'undefined' ? document : {});
