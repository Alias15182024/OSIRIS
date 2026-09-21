/**
 * OSIRIS Platform - Process List View Controller
 * Phase 1.6 Step 5
 *
 * Responsibilities:
 * - Load and render paginated observed processes via GET /api/processes.
 * - Manage filter state strictly corresponding to Phase 1.5 API: host_id, pid, is_active.
 * - Construct sanitized query strings strictly using URLSearchParams.
 * - Manage pagination state (limit, offset, total) with boundary protections (PAGE_SIZE = 25).
 * - Render process detail inspector modal via GET /api/processes/{process_id}.
 * - Render dynamic DOM values strictly with createElement/textContent (no raw HTML injection).
 * - Handle loading, empty ("No processes found matching the selected filters."), and error states.
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
      pid: '',
      is_active: '',
    },
  };

  // Cached DOM elements
  let dom = {};

  /**
   * Cache DOM element references for Process List.
   */
  function cacheElements() {
    dom = {
      // Filter form & inputs
      filterForm: document.getElementById('processes-filter-form'),
      inputHostId: document.getElementById('filter-process-host-id'),
      inputPid: document.getElementById('filter-process-pid'),
      selectIsActive: document.getElementById('filter-process-is-active'),
      applyFilterBtn: document.getElementById('filter-process-apply-btn'),
      resetFilterBtn: document.getElementById('filter-process-reset-btn'),

      // Table & containers
      tableContainer: document.getElementById('processes-table-container'),
      table: document.getElementById('processes-table'),
      tbody: document.getElementById('processes-tbody'),
      resultCountLabel: document.getElementById('processes-result-count'),
      errorBox: document.getElementById('processes-error-box'),
      emptyState: document.getElementById('processes-empty-state'),
      emptyResetBtn: document.getElementById('processes-empty-reset-btn'),

      // Pagination
      paginationToolbar: document.getElementById('processes-pagination'),
      prevBtn: document.getElementById('processes-prev-btn'),
      nextBtn: document.getElementById('processes-next-btn'),
      pageInfo: document.getElementById('processes-page-info'),

      // Detail Modal
      detailModal: document.getElementById('process-detail-modal-container'),
      detailCloseBtn: document.getElementById('process-detail-close-btn'),
      detailError: document.getElementById('process-detail-error'),
      detailContent: document.getElementById('process-detail-content'),
      detailProcessId: document.getElementById('detail-process-id'),
      detailHostId: document.getElementById('detail-process-host-id'),
      detailPid: document.getElementById('detail-process-pid'),
      detailPpid: document.getElementById('detail-process-ppid'),
      detailCommand: document.getElementById('detail-process-command'),
      detailExecutable: document.getElementById('detail-process-executable'),
      detailLinuxUserId: document.getElementById('detail-process-linux-user-id'),
      detailStatus: document.getElementById('detail-process-status'),
      detailStartedAt: document.getElementById('detail-process-started-at'),
      detailEndedAt: document.getElementById('detail-process-ended-at'),
      detailCreatedAt: document.getElementById('detail-process-created-at'),
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
   * Construct target URL with URLSearchParams strictly from supported filters and pagination.
   * Does NOT send unsupported filters such as ppid, linux_user_id, command, or state.
   *
   * @returns {string}
   */
  function buildProcessesUrl() {
    const params = new URLSearchParams();

    // Required pagination parameters
    params.set('limit', String(state.limit));
    params.set('offset', String(state.offset));

    // Supported query filters (only include non-empty values)
    if (state.filters.host_id) {
      params.set('host_id', state.filters.host_id.trim());
    }
    if (state.filters.pid !== '' && state.filters.pid !== null && state.filters.pid !== undefined) {
      params.set('pid', String(state.filters.pid).trim());
    }
    if (state.filters.is_active === 'true' || state.filters.is_active === true) {
      params.set('is_active', 'true');
    } else if (state.filters.is_active === 'false' || state.filters.is_active === false) {
      params.set('is_active', 'false');
    }

    return `/api/processes?${params.toString()}`;
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
   * Render table rows for processes.
   *
   * @param {Array<Object>} items
   */
  function renderProcessesTable(items) {
    clearTableRows();

    if (!items || items.length === 0) {
      if (dom.table) dom.table.classList.add('hidden');
      if (dom.emptyState) dom.emptyState.classList.remove('hidden');
      return;
    }

    if (dom.emptyState) dom.emptyState.classList.add('hidden');
    if (dom.table) dom.table.classList.remove('hidden');

    items.forEach((proc) => {
      const tr = document.createElement('tr');
      tr.className = 'clickable-row';
      tr.setAttribute('data-process-id', proc.id);
      tr.setAttribute('tabindex', '0');
      tr.setAttribute('role', 'button');
      tr.setAttribute('aria-label', `Inspect process PID ${proc.pid}`);

      // Row click and Enter/Space key to inspect
      tr.addEventListener('click', () => openProcessDetail(proc.id));
      tr.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          openProcessDetail(proc.id);
        }
      });

      // 1. PID
      const tdPid = document.createElement('td');
      tdPid.className = 'mono-cell';
      tdPid.textContent = String(proc.pid);
      tr.appendChild(tdPid);

      // 2. Process ID (UUID)
      const tdId = document.createElement('td');
      tdId.className = 'mono-cell';
      tdId.textContent = proc.id;
      tr.appendChild(tdId);

      // 3. PPID
      const tdPpid = document.createElement('td');
      tdPpid.className = 'mono-cell';
      tdPpid.textContent = (proc.ppid !== null && proc.ppid !== undefined) ? String(proc.ppid) : '-';
      tr.appendChild(tdPpid);

      // 4. Command
      const tdCmd = document.createElement('td');
      tdCmd.className = 'mono-cell';
      tdCmd.textContent = proc.command || proc.executable || '-';
      tr.appendChild(tdCmd);

      // 5. Linux User ID
      const tdUser = document.createElement('td');
      tdUser.className = 'mono-cell';
      tdUser.textContent = proc.linux_user_id ? String(proc.linux_user_id) : '-';
      tr.appendChild(tdUser);

      // 6. Active State Badge
      const tdStatus = document.createElement('td');
      const badge = document.createElement('span');
      const isActive = proc.ended_at === null || proc.ended_at === undefined;
      badge.className = `badge ${isActive ? 'badge-success' : 'badge-secondary'}`;
      badge.textContent = isActive ? 'ACTIVE' : 'TERMINATED';
      tdStatus.appendChild(badge);
      tr.appendChild(tdStatus);

      // 7. Start Time
      const tdStarted = document.createElement('td');
      tdStarted.className = 'mono-cell';
      tdStarted.textContent = formatTimestamp(proc.started_at);
      tr.appendChild(tdStarted);

      // 8. End Time
      const tdEnded = document.createElement('td');
      tdEnded.className = 'mono-cell';
      tdEnded.textContent = proc.ended_at ? formatTimestamp(proc.ended_at) : '-';
      tr.appendChild(tdEnded);

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
      dom.resultCountLabel.textContent = `${total.toLocaleString()} process${total === 1 ? '' : 'es'}`;
    }

    // Page indicator
    if (dom.pageInfo) {
      if (total === 0) {
        dom.pageInfo.textContent = 'Showing 0 of 0 processes';
      } else {
        const start = offset + 1;
        const end = Math.min(offset + limit, total);
        dom.pageInfo.textContent = `Showing ${start}-${end} of ${total.toLocaleString()} processes`;
      }
    }
  }

  /**
   * Fetch and render process records based on current state.
   *
   * @param {Object} [options={}]
   * @param {boolean} [options.force=false]
   */
  async function loadProcesses(options = {}) {
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
      const url = buildProcessesUrl();
      const data = await window.OsirisApi.fetchWithAuth(url);

      if (!data || !Array.isArray(data.items)) {
        throw new Error('Invalid process list response');
      }

      state.total = typeof data.total === 'number' ? data.total : 0;
      state.lastFetchTime = Date.now();
      state.hasLoadedOnce = true;

      renderProcessesTable(data.items);
      updatePagination();
    } catch (err) {
      clearTableRows();
      if (dom.table) dom.table.classList.add('hidden');
      if (dom.emptyState) dom.emptyState.classList.add('hidden');

      if (dom.errorBox) {
        dom.errorBox.textContent = err.message || 'Failed to load processes. Please verify filter inputs.';
        dom.errorBox.classList.remove('hidden');
      }
      if (dom.resultCountLabel) {
        dom.resultCountLabel.textContent = 'Unavailable';
      }
      if (dom.pageInfo) {
        dom.pageInfo.textContent = 'Error loading processes';
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
    state.filters.pid = dom.inputPid ? dom.inputPid.value.trim() : '';
    state.filters.is_active = dom.selectIsActive ? dom.selectIsActive.value.trim() : '';

    state.offset = 0;
    loadProcesses({ force: true });
  }

  /**
   * Reset filter fields and state, then reload page 1.
   */
  function handleFilterReset() {
    if (dom.filterForm) {
      dom.filterForm.reset();
    }
    if (dom.inputHostId) dom.inputHostId.value = '';
    if (dom.inputPid) dom.inputPid.value = '';
    if (dom.selectIsActive) dom.selectIsActive.value = '';

    state.filters = {
      host_id: '',
      pid: '',
      is_active: '',
    };

    state.offset = 0;
    loadProcesses({ force: true });
  }

  /**
   * Navigate to the previous page of processes.
   */
  function handlePreviousPage() {
    if (state.offset > 0 && !state.isLoading) {
      state.offset = Math.max(0, state.offset - state.limit);
      loadProcesses({ force: true });
    }
  }

  /**
   * Navigate to the next page of processes.
   */
  function handleNextPage() {
    if (state.offset + state.limit < state.total && !state.isLoading) {
      state.offset += state.limit;
      loadProcesses({ force: true });
    }
  }

  /**
   * Open the Process Detail Inspector modal and load the single process.
   *
   * @param {string} processId
   */
  async function openProcessDetail(processId) {
    if (!processId || !dom.detailModal) return;

    dom.detailModal.classList.remove('hidden');
    if (dom.detailError) {
      dom.detailError.classList.add('hidden');
      dom.detailError.textContent = '';
    }

    // Set initial loading state in modal fields
    setDetailFieldsLoading(processId);

    try {
      const url = `/api/processes/${encodeURIComponent(processId)}`;
      const process = await window.OsirisApi.fetchWithAuth(url);

      if (!process || typeof process !== 'object') {
        throw new Error('Process details could not be retrieved.');
      }

      populateDetailFields(process);
    } catch (err) {
      if (dom.detailError) {
        dom.detailError.textContent = err.message || 'Process not found or failed to load.';
        dom.detailError.classList.remove('hidden');
      }
    }
  }

  /**
   * Put modal fields in a loading placeholder state.
   *
   * @param {string} processId
   */
  function setDetailFieldsLoading(processId) {
    if (dom.detailProcessId) dom.detailProcessId.textContent = processId;
    if (dom.detailHostId) dom.detailHostId.textContent = 'Loading...';
    if (dom.detailPid) dom.detailPid.textContent = 'Loading...';
    if (dom.detailPpid) dom.detailPpid.textContent = '-';
    if (dom.detailCommand) dom.detailCommand.textContent = 'Loading...';
    if (dom.detailExecutable) dom.detailExecutable.textContent = '-';
    if (dom.detailLinuxUserId) dom.detailLinuxUserId.textContent = '-';
    if (dom.detailStatus) dom.detailStatus.textContent = 'Loading...';
    if (dom.detailStartedAt) dom.detailStartedAt.textContent = 'Loading...';
    if (dom.detailEndedAt) dom.detailEndedAt.textContent = '-';
    if (dom.detailCreatedAt) dom.detailCreatedAt.textContent = '-';
  }

  /**
   * Populate modal with full ProcessResponse data safely using textContent.
   *
   * @param {Object} process
   */
  function populateDetailFields(process) {
    if (dom.detailProcessId) dom.detailProcessId.textContent = process.id || '-';
    if (dom.detailHostId) dom.detailHostId.textContent = process.host_id || '-';
    if (dom.detailPid) dom.detailPid.textContent = String(process.pid);
    if (dom.detailPpid) dom.detailPpid.textContent = (process.ppid !== null && process.ppid !== undefined) ? String(process.ppid) : '-';
    if (dom.detailCommand) dom.detailCommand.textContent = process.command || '-';
    if (dom.detailExecutable) dom.detailExecutable.textContent = process.executable || '-';
    if (dom.detailLinuxUserId) dom.detailLinuxUserId.textContent = process.linux_user_id ? String(process.linux_user_id) : '-';

    if (dom.detailStatus) {
      dom.detailStatus.textContent = '';
      const badge = document.createElement('span');
      const isActive = process.ended_at === null || process.ended_at === undefined;
      badge.className = `badge ${isActive ? 'badge-success' : 'badge-secondary'}`;
      badge.textContent = isActive ? 'ACTIVE' : 'TERMINATED';
      dom.detailStatus.appendChild(badge);
    }

    if (dom.detailStartedAt) dom.detailStartedAt.textContent = formatTimestamp(process.started_at);
    if (dom.detailEndedAt) dom.detailEndedAt.textContent = process.ended_at ? formatTimestamp(process.ended_at) : 'Still Running (Active)';
    if (dom.detailCreatedAt) dom.detailCreatedAt.textContent = formatTimestamp(process.created_at);
  }

  /**
   * Close the Process Detail Inspector modal.
   */
  function closeProcessDetail() {
    if (dom.detailModal) {
      dom.detailModal.classList.add('hidden');
    }
  }

  /**
   * Reset the Process view state on logout.
   */
  function resetProcesses() {
    state.offset = 0;
    state.total = 0;
    state.hasLoadedOnce = false;
    state.lastFetchTime = 0;
    handleFilterReset();
    clearTableRows();
    closeProcessDetail();
    if (dom.resultCountLabel) dom.resultCountLabel.textContent = '0 processes';
    if (dom.pageInfo) dom.pageInfo.textContent = 'Showing 0 of 0 processes';
    if (dom.table) dom.table.classList.add('hidden');
    if (dom.emptyState) dom.emptyState.classList.add('hidden');
  }

  /**
   * Bind event listeners for the Process List view.
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
      dom.detailCloseBtn.addEventListener('click', closeProcessDetail);
    }
    if (dom.detailModal) {
      dom.detailModal.addEventListener('click', (e) => {
        if (e.target === dom.detailModal) {
          closeProcessDetail();
        }
      });
    }

    // Escape key closes modal
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && dom.detailModal && !dom.detailModal.classList.contains('hidden')) {
        closeProcessDetail();
      }
    });
  }

  /**
   * Initialize the Process List view.
   */
  function initProcesses() {
    cacheElements();
    bindEvents();
  }

  // Initialize when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initProcesses);
  } else {
    initProcesses();
  }

  // Export view controller to window
  window.OsirisProcesses = Object.freeze({
    initProcesses,
    loadProcesses,
    resetProcesses,
    openProcessDetail,
    closeProcessDetail,
  });

})(typeof window !== 'undefined' ? window : this, typeof document !== 'undefined' ? document : {});
