/**
 * OSIRIS Platform - User Sessions View Controller
 * Phase 2 Milestone 2.3
 *
 * Responsibilities:
 * - Load and render paginated observed user sessions via GET /api/sessions.
 * - Manage filter state: host_id, username, session_type, is_active.
 * - Construct sanitized query strings strictly using URLSearchParams.
 * - Manage pagination state (limit, offset, total) with boundary protections (PAGE_SIZE = 25).
 * - Render session detail inspector modal via GET /api/sessions/{session_id}.
 * - Render dynamic DOM values strictly with createElement/textContent (no raw HTML injection).
 * - Display associated processes executed during the session lifecycle.
 * - Handle loading, empty ("No sessions found matching the selected filters."), and error states.
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
      username: '',
      session_type: '',
      is_active: '',
    },
  };

  // Cached DOM elements
  let dom = {};

  /**
   * Cache DOM element references for Sessions List.
   */
  function cacheElements() {
    dom = {
      // Filter form & inputs
      filterForm: document.getElementById('sessions-filter-form'),
      inputHostId: document.getElementById('filter-session-host-id'),
      inputUsername: document.getElementById('filter-session-username'),
      selectSessionType: document.getElementById('filter-session-type'),
      selectIsActive: document.getElementById('filter-session-is-active'),
      applyFilterBtn: document.getElementById('filter-session-apply-btn'),
      resetFilterBtn: document.getElementById('filter-session-reset-btn'),

      // Table & containers
      tableContainer: document.getElementById('sessions-table-container'),
      table: document.getElementById('sessions-table'),
      tbody: document.getElementById('sessions-tbody'),
      resultCountLabel: document.getElementById('sessions-result-count'),
      errorBox: document.getElementById('sessions-error-box'),
      emptyState: document.getElementById('sessions-empty-state'),
      emptyResetBtn: document.getElementById('sessions-empty-reset-btn'),

      // Pagination
      paginationToolbar: document.getElementById('sessions-pagination'),
      prevBtn: document.getElementById('sessions-prev-btn'),
      nextBtn: document.getElementById('sessions-next-btn'),
      pageInfo: document.getElementById('sessions-page-info'),

      // Detail Modal
      detailModal: document.getElementById('session-detail-modal-container'),
      detailCloseBtn: document.getElementById('session-detail-close-btn'),
      detailError: document.getElementById('session-detail-error'),
      detailContent: document.getElementById('session-detail-content'),
      detailSessionId: document.getElementById('detail-session-id'),
      detailHostId: document.getElementById('detail-session-host-id'),
      detailUser: document.getElementById('detail-session-user'),
      detailType: document.getElementById('detail-session-type'),
      detailTerminal: document.getElementById('detail-session-terminal'),
      detailRemoteHost: document.getElementById('detail-session-remote-host'),
      detailStatus: document.getElementById('detail-session-status'),
      detailStartedAt: document.getElementById('detail-session-started-at'),
      detailEndedAt: document.getElementById('detail-session-ended-at'),
      detailDuration: document.getElementById('detail-session-duration'),
      detailProcessCount: document.getElementById('detail-session-process-count'),
      detailProcessesTbody: document.getElementById('detail-session-processes-tbody'),
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
   * Format duration in seconds into human-readable string.
   *
   * @param {number|null} seconds
   * @param {boolean} [isActive=false]
   * @returns {string}
   */
  function formatDuration(seconds, isActive = false) {
    if (seconds === null || seconds === undefined) {
      return isActive ? 'Active' : '-';
    }
    const s = Math.round(seconds);
    if (s < 60) return `${s}s`;
    const m = Math.floor(s / 60);
    const remS = s % 60;
    if (m < 60) return `${m}m ${remS}s`;
    const h = Math.floor(m / 60);
    const remM = m % 60;
    return `${h}h ${remM}m`;
  }

  /**
   * Create an element with class and text content safely.
   */
  function createEl(tag, className, text) {
    const el = document.createElement(tag);
    if (className) el.className = className;
    if (text !== undefined && text !== null) el.textContent = String(text);
    return el;
  }

  /**
   * Render table rows for sessions.
   *
   * @param {Array<Object>} sessions
   */
  function renderTableRows(sessions) {
    if (!dom.tbody) return;
    dom.tbody.textContent = '';

    if (!sessions || sessions.length === 0) {
      if (dom.emptyState) dom.emptyState.classList.remove('hidden');
      if (dom.tableContainer) dom.tableContainer.classList.add('hidden');
      return;
    }

    if (dom.emptyState) dom.emptyState.classList.add('hidden');
    if (dom.tableContainer) dom.tableContainer.classList.remove('hidden');

    sessions.forEach((sess) => {
      const tr = document.createElement('tr');

      // 1. Status badge
      const tdStatus = document.createElement('td');
      const statusBadge = createEl(
        'span',
        'badge ' + (sess.is_active ? 'badge-success' : 'badge-secondary'),
        sess.is_active ? 'Active' : 'Completed'
      );
      tdStatus.appendChild(statusBadge);
      tr.appendChild(tdStatus);

      // 2. User
      const tdUser = document.createElement('td');
      const userText = sess.username || (sess.uid !== null ? `UID ${sess.uid}` : '-');
      tdUser.appendChild(createEl('span', 'font-medium', userText));
      tr.appendChild(tdUser);

      // 3. Type
      const tdType = document.createElement('td');
      const typeBadge = createEl(
        'span',
        'badge badge-outline',
        sess.session_type || 'local'
      );
      tdType.appendChild(typeBadge);
      tr.appendChild(tdType);

      // 4. Terminal
      const tdTerminal = document.createElement('td');
      tdTerminal.textContent = sess.terminal || '-';
      tr.appendChild(tdTerminal);

      // 5. Remote Host
      const tdRemote = document.createElement('td');
      tdRemote.textContent = sess.remote_host || '-';
      tr.appendChild(tdRemote);

      // 6. Started At
      const tdStarted = document.createElement('td');
      tdStarted.textContent = formatTimestamp(sess.started_at);
      tr.appendChild(tdStarted);

      // 7. Ended At
      const tdEnded = document.createElement('td');
      tdEnded.textContent = formatTimestamp(sess.ended_at);
      tr.appendChild(tdEnded);

      // 8. Duration
      const tdDuration = document.createElement('td');
      tdDuration.textContent = formatDuration(sess.duration_seconds, sess.is_active);
      tr.appendChild(tdDuration);

      // 9. Actions
      const tdActions = document.createElement('td');
      const inspectBtn = createEl('button', 'btn btn-outline btn-xs', 'Inspect');
      inspectBtn.type = 'button';
      inspectBtn.setAttribute('data-session-id', sess.id);
      inspectBtn.addEventListener('click', () => openSessionModal(sess.id));
      tdActions.appendChild(inspectBtn);
      tr.appendChild(tdActions);

      dom.tbody.appendChild(tr);
    });
  }

  /**
   * Open the session detail modal and load data via GET /api/sessions/{session_id}.
   *
   * @param {string} sessionId
   */
  async function openSessionModal(sessionId) {
    if (!dom.detailModal) return;
    dom.detailModal.classList.remove('hidden');

    if (dom.detailError) {
      dom.detailError.textContent = '';
      dom.detailError.classList.add('hidden');
    }
    if (dom.detailContent) {
      dom.detailContent.classList.add('loading-skeleton');
    }

    try {
      const data = await window.OsirisApi.getSession(sessionId);
      if (dom.detailContent) {
        dom.detailContent.classList.remove('loading-skeleton');
      }

      if (dom.detailSessionId) dom.detailSessionId.textContent = data.id || '-';
      if (dom.detailHostId) dom.detailHostId.textContent = data.host_id || '-';
      if (dom.detailUser) {
        dom.detailUser.textContent = data.username
          ? `${data.username} (UID ${data.uid !== null ? data.uid : '?'})`
          : (data.uid !== null ? `UID ${data.uid}` : '-');
      }
      if (dom.detailType) dom.detailType.textContent = data.session_type || 'local';
      if (dom.detailTerminal) dom.detailTerminal.textContent = data.terminal || '-';
      if (dom.detailRemoteHost) dom.detailRemoteHost.textContent = data.remote_host || '-';
      if (dom.detailStatus) {
        dom.detailStatus.textContent = data.is_active ? 'Active' : 'Completed';
        dom.detailStatus.className = 'badge ' + (data.is_active ? 'badge-success' : 'badge-secondary');
      }
      if (dom.detailStartedAt) dom.detailStartedAt.textContent = formatTimestamp(data.started_at);
      if (dom.detailEndedAt) dom.detailEndedAt.textContent = formatTimestamp(data.ended_at);
      if (dom.detailDuration) dom.detailDuration.textContent = formatDuration(data.duration_seconds, data.is_active);
      if (dom.detailProcessCount) {
        dom.detailProcessCount.textContent = String(data.process_count || 0);
      }

      // Populate processes table
      if (dom.detailProcessesTbody) {
        dom.detailProcessesTbody.textContent = '';
        const procs = data.processes || [];
        if (procs.length === 0) {
          const emptyRow = document.createElement('tr');
          const td = document.createElement('td');
          td.colSpan = 5;
          td.className = 'text-center text-muted';
          td.textContent = 'No associated processes recorded during this session.';
          emptyRow.appendChild(td);
          dom.detailProcessesTbody.appendChild(emptyRow);
        } else {
          procs.forEach((p) => {
            const row = document.createElement('tr');
            row.appendChild(createEl('td', 'font-mono', p.pid));
            row.appendChild(createEl('td', 'font-mono', p.ppid !== null ? p.ppid : '-'));
            row.appendChild(createEl('td', 'font-mono truncate-cell', p.command));
            row.appendChild(createEl('td', '', formatTimestamp(p.started_at)));
            row.appendChild(createEl('td', '', formatTimestamp(p.ended_at)));
            dom.detailProcessesTbody.appendChild(row);
          });
        }
      }
    } catch (err) {
      if (dom.detailContent) {
        dom.detailContent.classList.remove('loading-skeleton');
      }
      if (dom.detailError) {
        dom.detailError.textContent = err.message || 'Failed to load session details.';
        dom.detailError.classList.remove('hidden');
      }
    }
  }

  /**
   * Close the session detail modal.
   */
  function closeSessionModal() {
    if (dom.detailModal) {
      dom.detailModal.classList.add('hidden');
    }
  }

  /**
   * Update pagination controls and result counters.
   */
  function updatePagination() {
    const { offset, limit, total } = state;
    const currentStart = total === 0 ? 0 : offset + 1;
    const currentEnd = Math.min(offset + limit, total);

    if (dom.pageInfo) {
      dom.pageInfo.textContent = `Showing ${currentStart}–${currentEnd} of ${total} sessions`;
    }
    if (dom.resultCountLabel) {
      dom.resultCountLabel.textContent = `${total} session${total === 1 ? '' : 's'}`;
    }
    if (dom.prevBtn) {
      dom.prevBtn.disabled = offset === 0;
    }
    if (dom.nextBtn) {
      dom.nextBtn.disabled = offset + limit >= total;
    }
  }

  /**
   * Load sessions from API.
   *
   * @param {boolean} [force=false]
   */
  async function loadSessions(force = false) {
    const now = Date.now();
    if (!force && state.hasLoadedOnce && now - state.lastFetchTime < REFRESH_COOLDOWN_MS) {
      return;
    }
    if (state.isLoading) return;

    state.isLoading = true;
    if (dom.errorBox) {
      dom.errorBox.textContent = '';
      dom.errorBox.classList.add('hidden');
    }

    const params = {
      limit: state.limit,
      offset: state.offset,
    };
    if (state.filters.host_id) params.host_id = state.filters.host_id;
    if (state.filters.username) params.username = state.filters.username;
    if (state.filters.session_type) params.session_type = state.filters.session_type;
    if (state.filters.is_active !== '') params.is_active = state.filters.is_active;

    try {
      const data = await window.OsirisApi.getSessions(params);
      state.total = data.total || 0;
      state.lastFetchTime = Date.now();
      state.hasLoadedOnce = true;

      renderTableRows(data.items || []);
      updatePagination();
    } catch (err) {
      if (dom.errorBox) {
        dom.errorBox.textContent = err.message || 'Failed to load user sessions.';
        dom.errorBox.classList.remove('hidden');
      }
    } finally {
      state.isLoading = false;
    }
  }

  /**
   * Handle filter form submission.
   */
  function handleFilterSubmit(e) {
    if (e) e.preventDefault();
    state.filters.host_id = dom.inputHostId ? dom.inputHostId.value.trim() : '';
    state.filters.username = dom.inputUsername ? dom.inputUsername.value.trim() : '';
    state.filters.session_type = dom.selectSessionType ? dom.selectSessionType.value : '';
    state.filters.is_active = dom.selectIsActive ? dom.selectIsActive.value : '';
    state.offset = 0;
    loadSessions(true);
  }

  /**
   * Reset filter form to defaults.
   */
  function handleFilterReset() {
    if (dom.filterForm) dom.filterForm.reset();
    state.filters.host_id = '';
    state.filters.username = '';
    state.filters.session_type = '';
    state.filters.is_active = '';
    state.offset = 0;
    loadSessions(true);
  }

  /**
   * Bind event listeners.
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
      dom.prevBtn.addEventListener('click', () => {
        if (state.offset >= state.limit) {
          state.offset -= state.limit;
          loadSessions(true);
        }
      });
    }
    if (dom.nextBtn) {
      dom.nextBtn.addEventListener('click', () => {
        if (state.offset + state.limit < state.total) {
          state.offset += state.limit;
          loadSessions(true);
        }
      });
    }
    if (dom.detailCloseBtn) {
      dom.detailCloseBtn.addEventListener('click', closeSessionModal);
    }
    if (dom.detailModal) {
      dom.detailModal.addEventListener('click', (e) => {
        if (e.target === dom.detailModal) closeSessionModal();
      });
    }
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && dom.detailModal && !dom.detailModal.classList.contains('hidden')) {
        closeSessionModal();
      }
    });
  }

  /**
   * Initialize controller.
   */
  function init() {
    cacheElements();
    bindEvents();
  }

  // Auto-initialize when DOM is ready
  if (document && typeof document.addEventListener === 'function') {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', init);
    } else {
      init();
    }
  }

  // Export to global namespace
  const globalObj = typeof window !== 'undefined' ? window : this;
  globalObj.OsirisSessions = Object.freeze({
    init,
    initSessions: init,
    loadSessions,
    openSessionModal,
    closeSessionModal,
  });

})(typeof window !== 'undefined' ? window : this, typeof document !== 'undefined' ? document : {});
