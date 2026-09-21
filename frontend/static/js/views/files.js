/**
 * OSIRIS Platform - Files Explorer View Controller
 * Phase 1.6 Step 7
 *
 * Responsibilities:
 * - Load and render paginated observed files via GET /api/files.
 * - Manage filter state strictly corresponding to Phase 1.5 API: host_id, path, file_type.
 * - Construct sanitized query strings strictly using URLSearchParams.
 * - Manage pagination state (limit, offset, total) with boundary protections (PAGE_SIZE = 25).
 * - Render file detail inspector modal from the returned FileResponse record.
 * - Render dynamic DOM values strictly with createElement/textContent (no raw HTML injection).
 * - Handle loading, empty ("No files found matching the selected filters."), and error states.
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
      path: '',
      file_type: '',
    },
    items: [],
  };

  // Cached DOM elements
  let dom = {};

  /**
   * Cache DOM element references for Files Explorer.
   */
  function cacheElements() {
    dom = {
      // Header controls
      refreshBtn: document.getElementById('files-refresh-btn'),
      refreshTime: document.getElementById('files-refresh-time'),

      // Filter controls
      filterForm: document.getElementById('files-filter-form'),
      inputPath: document.getElementById('filter-file-path'),
      selectFileType: document.getElementById('filter-file-type'),
      inputHostId: document.getElementById('filter-file-host-id'),
      selectLimit: document.getElementById('filter-file-limit'),
      applyFilterBtn: document.getElementById('filter-file-apply-btn'),
      resetFilterBtn: document.getElementById('filter-file-reset-btn'),

      // State containers
      errorBox: document.getElementById('files-error-box'),
      emptyState: document.getElementById('files-empty-state'),
      emptyResetBtn: document.getElementById('files-empty-reset-btn'),

      // Table & containers
      tableContainer: document.getElementById('files-table-container'),
      table: document.getElementById('files-table'),
      tbody: document.getElementById('files-tbody'),
      resultCountLabel: document.getElementById('files-result-count'),

      // Pagination
      paginationToolbar: document.getElementById('files-pagination'),
      prevBtn: document.getElementById('files-prev-btn'),
      nextBtn: document.getElementById('files-next-btn'),
      pageInfo: document.getElementById('files-page-info'),

      // File Detail Modal
      detailModal: document.getElementById('file-detail-modal-container'),
      detailCloseBtn: document.getElementById('file-detail-close-btn'),
      detailError: document.getElementById('file-detail-error'),
      detailContent: document.getElementById('file-detail-content'),
      detailFileId: document.getElementById('detail-file-id'),
      detailHostId: document.getElementById('detail-file-host-id'),
      detailPath: document.getElementById('detail-file-path'),
      detailFileType: document.getElementById('detail-file-type'),
      detailInode: document.getElementById('detail-file-inode'),
      detailFirstSeen: document.getElementById('detail-file-first-seen'),
      detailLastSeen: document.getElementById('detail-file-last-seen'),
      detailCreatedAt: document.getElementById('detail-file-created-at'),
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
   * Build query string using URLSearchParams strictly adhering to Phase 1.5 contract.
   * Supported: host_id, path, file_type, limit, offset.
   *
   * @returns {string}
   */
  function buildFilesUrl() {
    const params = new URLSearchParams();

    params.set('limit', String(state.limit));
    params.set('offset', String(state.offset));

    if (state.filters.host_id) {
      params.set('host_id', state.filters.host_id.trim());
    }

    if (state.filters.path) {
      params.set('path', state.filters.path.trim());
    }

    if (state.filters.file_type) {
      params.set('file_type', state.filters.file_type.trim());
    }

    return `/api/files?${params.toString()}`;
  }

  /**
   * Clear all rows from tbody safely without raw HTML injection.
   */
  function clearTableRows() {
    if (!dom.tbody) return;
    while (dom.tbody.firstChild) {
      dom.tbody.removeChild(dom.tbody.firstChild);
    }
  }

  /**
   * Create a styled badge element representing the file type from backend API.
   *
   * @param {string|null} fileType
   * @returns {HTMLElement}
   */
  function createFileTypeBadge(fileType) {
    const badge = document.createElement('span');
    badge.className = 'badge';

    const normalized = fileType ? String(fileType).toLowerCase().trim() : 'unknown';

    switch (normalized) {
      case 'file':
      case 'regular':
      case 'regular_file':
        badge.classList.add('badge-info');
        badge.textContent = 'file';
        break;
      case 'directory':
      case 'dir':
        badge.classList.add('badge-warning');
        badge.textContent = 'directory';
        break;
      case 'symlink':
      case 'link':
        badge.classList.add('badge-outline');
        badge.textContent = 'symlink';
        break;
      case 'socket':
      case 'fifo':
      case 'pipe':
        badge.classList.add('badge-secondary');
        badge.textContent = normalized;
        break;
      case 'character_device':
      case 'block_device':
      case 'device':
        badge.classList.add('badge-danger');
        badge.textContent = normalized;
        break;
      default:
        badge.classList.add('badge-outline');
        badge.textContent = fileType || '-';
        break;
    }

    return badge;
  }

  /**
   * Render file records in the table body.
   *
   * @param {Array<Object>} files
   */
  function renderFilesTable(files) {
    clearTableRows();
    if (!dom.tbody) return;

    if (!files || files.length === 0) {
      if (dom.table) dom.table.classList.add('hidden');
      if (dom.emptyState) dom.emptyState.classList.remove('hidden');
      return;
    }

    if (dom.table) dom.table.classList.remove('hidden');
    if (dom.emptyState) dom.emptyState.classList.add('hidden');

    files.forEach((file) => {
      const tr = document.createElement('tr');
      tr.className = 'clickable-row';
      tr.setAttribute('tabindex', '0');
      tr.setAttribute('role', 'button');
      tr.setAttribute('aria-label', `View details for file ${file.path}`);

      // 1. Path (visually prominent, primary field)
      const tdPath = document.createElement('td');
      tdPath.className = 'file-path-cell mono-cell';
      tdPath.textContent = file.path;
      tr.appendChild(tdPath);

      // 2. File Type
      const tdType = document.createElement('td');
      tdType.appendChild(createFileTypeBadge(file.file_type));
      tr.appendChild(tdType);

      // 3. Inode
      const tdInode = document.createElement('td');
      tdInode.className = 'mono-cell';
      tdInode.textContent = file.inode !== null && file.inode !== undefined ? String(file.inode) : '-';
      tr.appendChild(tdInode);

      // 4. Host ID
      const tdHost = document.createElement('td');
      tdHost.className = 'mono-cell truncate-cell';
      tdHost.textContent = file.host_id || '-';
      tr.appendChild(tdHost);

      // 5. First Seen
      const tdFirstSeen = document.createElement('td');
      tdFirstSeen.className = 'mono-cell';
      tdFirstSeen.textContent = formatTimestamp(file.first_seen_at);
      tr.appendChild(tdFirstSeen);

      // 6. Last Seen
      const tdLastSeen = document.createElement('td');
      tdLastSeen.className = 'mono-cell';
      tdLastSeen.textContent = formatTimestamp(file.last_seen_at);
      tr.appendChild(tdLastSeen);

      // 7. Actions
      const tdActions = document.createElement('td');
      tdActions.className = 'actions-cell';
      const inspectBtn = document.createElement('button');
      inspectBtn.type = 'button';
      inspectBtn.className = 'btn btn-outline btn-xs';
      inspectBtn.textContent = 'Inspect';
      inspectBtn.setAttribute('aria-label', `Inspect details for ${file.path}`);
      inspectBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        openFileDetail(file.id);
      });
      tdActions.appendChild(inspectBtn);
      tr.appendChild(tdActions);

      // Row interactions
      tr.addEventListener('click', () => {
        openFileDetail(file.id);
      });

      tr.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          openFileDetail(file.id);
        }
      });

      dom.tbody.appendChild(tr);
    });
  }

  /**
   * Update pagination controls and results count label.
   */
  function updatePagination() {
    const total = state.total;
    const offset = state.offset;
    const limit = state.limit;

    if (dom.resultCountLabel) {
      dom.resultCountLabel.textContent = `${total} file${total === 1 ? '' : 's'}`;
    }

    if (dom.pageInfo) {
      if (total === 0) {
        dom.pageInfo.textContent = 'Showing 0–0 of 0 files';
      } else {
        const start = offset + 1;
        const end = Math.min(offset + limit, total);
        dom.pageInfo.textContent = `Showing ${start}–${end} of ${total} files`;
      }
    }

    if (dom.prevBtn) {
      dom.prevBtn.disabled = state.isLoading || offset === 0;
    }

    if (dom.nextBtn) {
      dom.nextBtn.disabled = state.isLoading || (offset + limit >= total);
    }
  }

  /**
   * Fetch observed files from the backend API.
   *
   * @param {Object} [options]
   * @param {boolean} [options.force=false]
   */
  async function loadFiles({ force = false } = {}) {
    if (!window.OsirisApi || typeof window.OsirisApi.fetchWithAuth !== 'function') {
      return;
    }

    const token = window.OsirisApi.getToken();
    if (!token) {
      if (dom.errorBox) {
        dom.errorBox.textContent = 'Authentication required to view filesystem telemetry.';
        dom.errorBox.classList.remove('hidden');
      }
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

    if (dom.applyFilterBtn) dom.applyFilterBtn.disabled = true;
    if (dom.refreshBtn) dom.refreshBtn.disabled = true;

    try {
      const url = buildFilesUrl();
      const data = await window.OsirisApi.fetchWithAuth(url);

      if (!data || !Array.isArray(data.items)) {
        throw new Error('Invalid filesystem response structure');
      }

      state.total = typeof data.total === 'number' ? data.total : 0;
      state.items = data.items;
      state.lastFetchTime = Date.now();
      state.hasLoadedOnce = true;

      if (dom.refreshTime) {
        dom.refreshTime.textContent = `Updated: ${new Date().toLocaleTimeString()}`;
      }

      renderFilesTable(data.items);
      updatePagination();
    } catch (err) {
      clearTableRows();
      if (dom.table) dom.table.classList.add('hidden');
      if (dom.emptyState) dom.emptyState.classList.add('hidden');

      if (dom.errorBox) {
        dom.errorBox.textContent = err.message || 'Failed to load filesystem entries. Please verify filter inputs.';
        dom.errorBox.classList.remove('hidden');
      }
      if (dom.resultCountLabel) {
        dom.resultCountLabel.textContent = 'Unavailable';
      }
      if (dom.pageInfo) {
        dom.pageInfo.textContent = 'Error loading files';
      }
    } finally {
      state.isLoading = false;
      if (dom.applyFilterBtn) dom.applyFilterBtn.disabled = false;
      if (dom.refreshBtn) dom.refreshBtn.disabled = false;
      updatePagination();
    }
  }

  /**
   * Apply filters from input fields and reset to page 1.
   *
   * @param {Event} [e]
   */
  function handleFilterSubmit(e) {
    if (e && typeof e.preventDefault === 'function') {
      e.preventDefault();
    }

    state.filters.host_id = dom.inputHostId ? dom.inputHostId.value.trim() : '';
    state.filters.path = dom.inputPath ? dom.inputPath.value.trim() : '';
    state.filters.file_type = dom.selectFileType ? dom.selectFileType.value.trim() : '';

    if (dom.selectLimit) {
      const lim = parseInt(dom.selectLimit.value, 10);
      if (!isNaN(lim) && lim >= 1) {
        state.limit = lim;
      }
    }

    state.offset = 0;
    loadFiles({ force: true });
  }

  /**
   * Reset filter fields and state, then reload page 1.
   */
  function handleFilterReset() {
    if (dom.filterForm) {
      dom.filterForm.reset();
    }

    state.filters = {
      host_id: '',
      path: '',
      file_type: '',
    };
    state.limit = PAGE_SIZE;
    state.offset = 0;

    loadFiles({ force: true });
  }

  /**
   * Navigate to the previous page of files.
   */
  function handlePreviousPage() {
    if (state.offset > 0 && !state.isLoading) {
      state.offset = Math.max(0, state.offset - state.limit);
      loadFiles({ force: true });
    }
  }

  /**
   * Navigate to the next page of files.
   */
  function handleNextPage() {
    if (state.offset + state.limit < state.total && !state.isLoading) {
      state.offset += state.limit;
      loadFiles({ force: true });
    }
  }

  /**
   * Populate modal with full FileResponse data safely using textContent.
   *
   * @param {Object} file
   */
  function populateDetailFields(file) {
    if (!file) return;

    if (dom.detailFileId) dom.detailFileId.textContent = file.id || '-';
    if (dom.detailHostId) dom.detailHostId.textContent = file.host_id || '-';
    if (dom.detailPath) dom.detailPath.textContent = file.path || '-';
    if (dom.detailFileType) dom.detailFileType.textContent = file.file_type || '-';
    if (dom.detailInode) {
      dom.detailInode.textContent = file.inode !== null && file.inode !== undefined ? String(file.inode) : '-';
    }
    if (dom.detailFirstSeen) dom.detailFirstSeen.textContent = formatTimestamp(file.first_seen_at);
    if (dom.detailLastSeen) dom.detailLastSeen.textContent = formatTimestamp(file.last_seen_at);
    if (dom.detailCreatedAt) dom.detailCreatedAt.textContent = formatTimestamp(file.created_at);
  }

  /**
   * Open the File Detail Inspector modal for a file record.
   *
   * @param {string} fileId
   */
  function openFileDetail(fileId) {
    if (!fileId || !dom.detailModal) return;

    const file = state.items.find((f) => f.id === fileId);
    if (!file) return;

    dom.detailModal.classList.remove('hidden');
    if (dom.detailError) {
      dom.detailError.classList.add('hidden');
      dom.detailError.textContent = '';
    }

    populateDetailFields(file);
  }

  /**
   * Close the File Detail Inspector modal.
   */
  function closeFileDetail() {
    if (dom.detailModal) {
      dom.detailModal.classList.add('hidden');
    }
  }

  /**
   * Reset Files Explorer view state on logout.
   */
  function resetFiles() {
    state.limit = PAGE_SIZE;
    state.offset = 0;
    state.total = 0;
    state.isLoading = false;
    state.lastFetchTime = 0;
    state.hasLoadedOnce = false;
    state.filters = {
      host_id: '',
      path: '',
      file_type: '',
    };
    state.items = [];

    clearTableRows();
    closeFileDetail();

    if (dom.errorBox) {
      dom.errorBox.classList.add('hidden');
      dom.errorBox.textContent = '';
    }

    if (dom.emptyState) {
      dom.emptyState.classList.remove('hidden');
    }

    if (dom.table) {
      dom.table.classList.add('hidden');
    }

    if (dom.filterForm) {
      dom.filterForm.reset();
    }

    if (dom.refreshTime) {
      dom.refreshTime.textContent = '';
    }

    updatePagination();
  }

  /**
   * Bind event listeners for UI interactions.
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
    if (dom.refreshBtn) {
      dom.refreshBtn.addEventListener('click', () => loadFiles({ force: true }));
    }

    if (dom.prevBtn) {
      dom.prevBtn.addEventListener('click', handlePreviousPage);
    }
    if (dom.nextBtn) {
      dom.nextBtn.addEventListener('click', handleNextPage);
    }

    // Detail modal close button
    if (dom.detailCloseBtn) {
      dom.detailCloseBtn.addEventListener('click', closeFileDetail);
    }

    // Close on backdrop click
    if (dom.detailModal) {
      dom.detailModal.addEventListener('click', (e) => {
        if (e.target === dom.detailModal) {
          closeFileDetail();
        }
      });
    }

    // Escape key closes modal
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && dom.detailModal && !dom.detailModal.classList.contains('hidden')) {
        closeFileDetail();
      }
    });
  }

  /**
   * Initialize Files Explorer view.
   */
  function initFiles() {
    cacheElements();
    bindEvents();
  }

  // Initialize when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initFiles);
  } else {
    initFiles();
  }

  // Export view controller to window
  window.OsirisFiles = Object.freeze({
    initFiles,
    loadFiles,
    resetFiles,
    openFileDetail,
    closeFileDetail,
  });

})(typeof window !== 'undefined' ? window : this, typeof document !== 'undefined' ? document : {});
