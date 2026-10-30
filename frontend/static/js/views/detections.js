/**
 * OSIRIS Platform - Security Detections & Alerts View Controller
 * Phase 2 Milestone 2.4
 *
 * Responsibilities:
 * - Load and render paginated security detection alerts via GET /api/detections.
 * - Manage filter state: host_id, severity, category, status, rule_id.
 * - Construct sanitized query strings strictly using URLSearchParams.
 * - Manage pagination state (limit, offset, total) with boundary protections (PAGE_SIZE = 25).
 * - Render detection detail inspector modal via GET /api/detections/{detection_id}.
 * - Render dynamic DOM values strictly with createElement/textContent (no raw HTML injection).
 * - Display matched conditions explainability breakdown and forensic evidence provenance.
 * - Handle alert acknowledgment via POST /api/detections/{id}/acknowledge.
 * - Handle loading, empty ("No security detections found matching the selected filters."), and error states.
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
    selectedDetectionId: null,
    filters: {
      host_id: '',
      severity: '',
      category: '',
      status: '',
      rule_id: '',
    },
  };

  // Cached DOM elements
  let dom = {};

  /**
   * Cache DOM element references for Detections View.
   */
  function cacheElements() {
    dom = {
      // Filter form & inputs
      filterForm: document.getElementById('detections-filter-form'),
      inputHostId: document.getElementById('filter-detection-host-id'),
      selectSeverity: document.getElementById('filter-detection-severity'),
      selectCategory: document.getElementById('filter-detection-category'),
      selectStatus: document.getElementById('filter-detection-status'),
      inputRuleId: document.getElementById('filter-detection-rule-id'),
      btnApply: document.getElementById('detections-filter-apply-btn'),
      btnReset: document.getElementById('detections-filter-reset-btn'),

      // Summary stat counters
      statCritical: document.getElementById('detection-stat-critical'),
      statHigh: document.getElementById('detection-stat-high'),
      statMedium: document.getElementById('detection-stat-medium'),
      statLow: document.getElementById('detection-stat-low'),

      // Refresh actions
      btnRefresh: document.getElementById('detections-refresh-btn'),
      refreshTime: document.getElementById('detections-refresh-time'),
      totalBadge: document.getElementById('detections-total-badge'),

      // Table states
      tbody: document.getElementById('detections-tbody'),
      loadingIndicator: document.getElementById('detections-loading'),
      emptyState: document.getElementById('detections-empty-state'),
      errorBox: document.getElementById('detections-error'),

      // Pagination controls
      btnPrev: document.getElementById('detections-prev-btn'),
      btnNext: document.getElementById('detections-next-btn'),
      pageInfo: document.getElementById('detections-page-info'),

      // Detail Modal
      modal: document.getElementById('detection-detail-modal'),
      modalCloseBtn: document.getElementById('detection-modal-close'),
      detailTitle: document.getElementById('detail-detection-title'),
      detailRuleCode: document.getElementById('detail-detection-rule-code'),
      detailSeverity: document.getElementById('detail-detection-severity'),
      detailStatus: document.getElementById('detail-detection-status'),
      detailCategory: document.getElementById('detail-detection-category'),
      detailTimestamp: document.getElementById('detail-detection-timestamp'),
      detailHost: document.getElementById('detail-detection-host'),
      detailDedup: document.getElementById('detail-detection-dedup'),
      detailDescription: document.getElementById('detail-detection-description'),
      detailConditions: document.getElementById('detail-detection-conditions'),
      detailEvidence: document.getElementById('detail-detection-evidence'),
      ackRegion: document.getElementById('detection-ack-region'),
      ackNotesInput: document.getElementById('detection-ack-notes'),
      btnAck: document.getElementById('detection-ack-btn'),

      // Nav badge
      navBadge: document.getElementById('nav-detections-badge'),
    };
  }

  /**
   * Helper to format UTC ISO timestamp.
   */
  function formatTimestamp(isoStr) {
    if (!isoStr) return '--';
    try {
      const d = new Date(isoStr);
      return d.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
    } catch {
      return String(isoStr);
    }
  }

  /**
   * Return severity badge class.
   */
  function getSeverityBadgeClass(sev) {
    const s = String(sev || '').toLowerCase();
    if (s === 'critical') return 'badge badge-danger';
    if (s === 'high') return 'badge badge-warning';
    if (s === 'medium') return 'badge badge-info';
    return 'badge badge-secondary';
  }

  /**
   * Return status badge class.
   */
  function getStatusBadgeClass(status) {
    const s = String(status || '').toLowerCase();
    if (s === 'open') return 'badge badge-danger';
    if (s === 'acknowledged') return 'badge badge-warning';
    if (s === 'resolved' || s === 'closed') return 'badge badge-success';
    return 'badge badge-secondary';
  }

  /**
   * Fetch and render detections with current filters and pagination.
   */
  async function loadDetections(force = false) {
    if (state.isLoading) return;

    const now = Date.now();
    if (!force && state.hasLoadedOnce && (now - state.lastFetchTime < REFRESH_COOLDOWN_MS)) {
      return;
    }

    state.isLoading = true;
    showLoading();

    try {
      const params = {
        limit: state.limit,
        offset: state.offset,
      };

      if (state.filters.host_id) params.host_id = state.filters.host_id;
      if (state.filters.severity) params.severity = state.filters.severity;
      if (state.filters.category) params.category = state.filters.category;
      if (state.filters.status) params.status = state.filters.status;
      if (state.filters.rule_id) params.rule_id = state.filters.rule_id;

      const data = await window.OsirisApi.getDetections(params);
      state.lastFetchTime = Date.now();
      state.hasLoadedOnce = true;

      state.total = data.total || 0;
      renderTable(data.items || []);
      renderPagination();
      updateRefreshTime();

      // Refresh summary stats and nav badge in background
      updateSummaryStats();
    } catch (err) {
      showError(err.message || 'Failed to load security detections.');
    } finally {
      state.isLoading = false;
      hideLoading();
    }
  }

  /**
   * Render table rows safely using textContent and createElement.
   */
  function renderTable(detections) {
    if (!dom.tbody) return;

    // Clear existing table content safely
    while (dom.tbody.firstChild) {
      dom.tbody.removeChild(dom.tbody.firstChild);
    }

    if (!detections || detections.length === 0) {
      if (dom.emptyState) dom.emptyState.classList.remove('hidden');
      if (dom.totalBadge) dom.totalBadge.textContent = '0 Alerts';
      return;
    }

    if (dom.emptyState) dom.emptyState.classList.add('hidden');
    if (dom.totalBadge) dom.totalBadge.textContent = `${state.total} Alert${state.total === 1 ? '' : 's'}`;

    detections.forEach((det) => {
      const tr = document.createElement('tr');
      tr.className = 'table-row-hover';

      // 1. Timestamp
      const tdTs = document.createElement('td');
      tdTs.className = 'font-mono text-xs';
      tdTs.textContent = formatTimestamp(det.timestamp);
      tr.appendChild(tdTs);

      // 2. Severity
      const tdSev = document.createElement('td');
      const sevBadge = document.createElement('span');
      sevBadge.className = getSeverityBadgeClass(det.severity);
      sevBadge.textContent = (det.severity || 'medium').toUpperCase();
      tdSev.appendChild(sevBadge);
      tr.appendChild(tdSev);

      // 3. Title & Rule
      const tdTitle = document.createElement('td');
      const titleSpan = document.createElement('div');
      titleSpan.className = 'font-bold';
      titleSpan.textContent = det.title || 'Security Detection';
      const codeSpan = document.createElement('div');
      codeSpan.className = 'text-xs text-muted font-mono';
      codeSpan.textContent = det.rule_code || det.rule_name || String(det.rule_id);
      tdTitle.appendChild(titleSpan);
      tdTitle.appendChild(codeSpan);
      tr.appendChild(tdTitle);

      // 4. Category
      const tdCat = document.createElement('td');
      tdCat.textContent = (det.category || '--').replace('_', ' ');
      tr.appendChild(tdCat);

      // 5. Host
      const tdHost = document.createElement('td');
      tdHost.className = 'font-mono text-xs';
      tdHost.textContent = det.hostname ? `${det.hostname} (${String(det.host_id).substring(0, 8)}...)` : String(det.host_id);
      tr.appendChild(tdHost);

      // 6. Status
      const tdStat = document.createElement('td');
      const statBadge = document.createElement('span');
      statBadge.className = getStatusBadgeClass(det.status);
      statBadge.textContent = (det.status || 'open').toUpperCase();
      tdStat.appendChild(statBadge);
      tr.appendChild(tdStat);

      // 7. Actions
      const tdActions = document.createElement('td');
      tdActions.className = 'table-actions';

      const btnInspect = document.createElement('button');
      btnInspect.type = 'button';
      btnInspect.className = 'btn btn-outline btn-xs';
      btnInspect.textContent = 'Inspect';
      btnInspect.setAttribute('aria-label', `Inspect alert ${det.title}`);
      btnInspect.addEventListener('click', () => openDetailModal(det.id));
      tdActions.appendChild(btnInspect);

      if (det.status === 'open') {
        const btnQuickAck = document.createElement('button');
        btnQuickAck.type = 'button';
        btnQuickAck.className = 'btn btn-warning btn-xs ml-1';
        btnQuickAck.textContent = 'Ack';
        btnQuickAck.setAttribute('aria-label', `Acknowledge alert ${det.title}`);
        btnQuickAck.addEventListener('click', async (e) => {
          e.stopPropagation();
          await quickAcknowledge(det.id);
        });
        tdActions.appendChild(btnQuickAck);
      }

      tr.appendChild(tdActions);
      dom.tbody.appendChild(tr);
    });
  }

  /**
   * Update pagination indicators and buttons.
   */
  function renderPagination() {
    const totalPages = Math.max(1, Math.ceil(state.total / state.limit));
    const currentPage = Math.floor(state.offset / state.limit) + 1;

    if (dom.pageInfo) {
      dom.pageInfo.textContent = `Page ${currentPage} of ${totalPages}`;
    }

    if (dom.btnPrev) {
      dom.btnPrev.disabled = state.offset === 0;
    }

    if (dom.btnNext) {
      dom.btnNext.disabled = state.offset + state.limit >= state.total;
    }
  }

  /**
   * Fetch counts for summary cards and update nav badge.
   */
  async function updateSummaryStats() {
    try {
      const [critRes, highRes, medRes, lowRes, openRes] = await Promise.all([
        window.OsirisApi.getDetections({ severity: 'critical', limit: 1 }),
        window.OsirisApi.getDetections({ severity: 'high', limit: 1 }),
        window.OsirisApi.getDetections({ severity: 'medium', limit: 1 }),
        window.OsirisApi.getDetections({ severity: 'low', limit: 1 }),
        window.OsirisApi.getDetections({ status: 'open', limit: 1 }),
      ]);

      if (dom.statCritical) dom.statCritical.textContent = String(critRes.total || 0);
      if (dom.statHigh) dom.statHigh.textContent = String(highRes.total || 0);
      if (dom.statMedium) dom.statMedium.textContent = String(medRes.total || 0);
      if (dom.statLow) dom.statLow.textContent = String(lowRes.total || 0);

      const openCount = openRes.total || 0;
      if (dom.navBadge) {
        if (openCount > 0) {
          dom.navBadge.textContent = String(openCount);
          dom.navBadge.classList.remove('hidden');
        } else {
          dom.navBadge.classList.add('hidden');
        }
      }

      const invBadge = document.getElementById('inv-detections-count');
      if (invBadge) {
        invBadge.textContent = String(openCount);
      }
    } catch {
      // Non-fatal background telemetry poll
    }
  }

  /**
   * Open and populate detection detail inspector modal.
   */
  async function openDetailModal(detectionId) {
    if (!detectionId || !dom.modal) return;
    state.selectedDetectionId = detectionId;

    try {
      const det = await window.OsirisApi.getDetection(detectionId);

      if (dom.detailTitle) dom.detailTitle.textContent = det.title || '--';
      if (dom.detailRuleCode) dom.detailRuleCode.textContent = det.rule_code || String(det.rule_id);

      if (dom.detailSeverity) {
        dom.detailSeverity.className = getSeverityBadgeClass(det.severity);
        dom.detailSeverity.textContent = (det.severity || 'medium').toUpperCase();
      }

      if (dom.detailStatus) {
        dom.detailStatus.className = getStatusBadgeClass(det.status);
        dom.detailStatus.textContent = (det.status || 'open').toUpperCase();
        if (det.acknowledged_by_username) {
          dom.detailStatus.textContent += ` (by ${det.acknowledged_by_username})`;
        }
      }

      if (dom.detailCategory) dom.detailCategory.textContent = (det.category || '--').replace('_', ' ');
      if (dom.detailTimestamp) dom.detailTimestamp.textContent = formatTimestamp(det.timestamp);
      if (dom.detailHost) dom.detailHost.textContent = det.hostname ? `${det.hostname} (${det.host_id})` : String(det.host_id);
      if (dom.detailDedup) dom.detailDedup.textContent = det.dedup_hash || '--';
      if (dom.detailDescription) dom.detailDescription.textContent = det.description || 'No description provided for this rule.';

      // Render matched conditions breakdown
      if (dom.detailConditions) {
        while (dom.detailConditions.firstChild) {
          dom.detailConditions.removeChild(dom.detailConditions.firstChild);
        }

        const conditionsList = (det.matched_conditions && det.matched_conditions.conditions) || [];
        if (conditionsList.length > 0) {
          const ul = document.createElement('ul');
          ul.className = 'condition-breakdown-list';
          conditionsList.forEach((c) => {
            const li = document.createElement('li');
            li.className = 'condition-item font-mono text-xs';
            li.textContent = `[${c.field}] ${c.operator} expected: ${JSON.stringify(c.expected)} | observed: ${JSON.stringify(c.actual)}`;
            ul.appendChild(li);
          });
          dom.detailConditions.appendChild(ul);
        } else {
          const span = document.createElement('span');
          span.className = 'text-muted text-sm';
          span.textContent = 'Rule condition logic matched observation context.';
          dom.detailConditions.appendChild(span);
        }
      }

      // Render raw evidence safely
      if (dom.detailEvidence) {
        dom.detailEvidence.textContent = JSON.stringify(det.evidence || {}, null, 2);
      }

      // Acknowledgment region visibility
      if (dom.ackRegion) {
        if (det.status === 'open') {
          dom.ackRegion.classList.remove('hidden');
          if (dom.ackNotesInput) dom.ackNotesInput.value = '';
        } else {
          dom.ackRegion.classList.add('hidden');
        }
      }

      dom.modal.classList.remove('hidden');
    } catch (err) {
      alert(`Failed to load detection details: ${err.message}`);
    }
  }

  /**
   * Close detection detail modal.
   */
  function closeDetailModal() {
    if (dom.modal) {
      dom.modal.classList.add('hidden');
    }
    state.selectedDetectionId = null;
  }

  /**
   * Quick acknowledge an alert without modal notes.
   */
  async function quickAcknowledge(detectionId) {
    try {
      await window.OsirisApi.acknowledgeDetection(detectionId, 'Quick acknowledged from detection list');
      await loadDetections(true);
    } catch (err) {
      alert(`Acknowledgment failed: ${err.message}`);
    }
  }

  /**
   * Acknowledge alert from inside the inspector modal.
   */
  async function handleModalAcknowledge() {
    if (!state.selectedDetectionId) return;
    const notes = dom.ackNotesInput ? dom.ackNotesInput.value.trim() : null;

    try {
      await window.OsirisApi.acknowledgeDetection(state.selectedDetectionId, notes);
      closeDetailModal();
      await loadDetections(true);
    } catch (err) {
      alert(`Acknowledgment failed: ${err.message}`);
    }
  }

  /**
   * Helper: Show loading indicator.
   */
  function showLoading() {
    if (dom.loadingIndicator) dom.loadingIndicator.classList.remove('hidden');
    if (dom.emptyState) dom.emptyState.classList.add('hidden');
    if (dom.errorBox) dom.errorBox.classList.add('hidden');
  }

  /**
   * Helper: Hide loading indicator.
   */
  function hideLoading() {
    if (dom.loadingIndicator) dom.loadingIndicator.classList.add('hidden');
  }

  /**
   * Helper: Show error box.
   */
  function showError(msg) {
    if (dom.errorBox) {
      dom.errorBox.textContent = msg;
      dom.errorBox.classList.remove('hidden');
    }
    if (dom.emptyState) dom.emptyState.classList.add('hidden');
  }

  /**
   * Helper: Update refresh timestamp text.
   */
  function updateRefreshTime() {
    if (dom.refreshTime) {
      const now = new Date();
      dom.refreshTime.textContent = `Updated: ${now.toLocaleTimeString()}`;
    }
  }

  /**
   * Bind DOM event listeners.
   */
  function bindEvents() {
    if (dom.filterForm) {
      dom.filterForm.addEventListener('submit', (e) => {
        e.preventDefault();
        state.offset = 0;
        state.filters.host_id = dom.inputHostId ? dom.inputHostId.value.trim() : '';
        state.filters.severity = dom.selectSeverity ? dom.selectSeverity.value : '';
        state.filters.category = dom.selectCategory ? dom.selectCategory.value : '';
        state.filters.status = dom.selectStatus ? dom.selectStatus.value : '';
        state.filters.rule_id = dom.inputRuleId ? dom.inputRuleId.value.trim() : '';
        loadDetections(true);
      });
    }

    if (dom.btnReset) {
      dom.btnReset.addEventListener('click', () => {
        if (dom.filterForm) dom.filterForm.reset();
        state.offset = 0;
        state.filters = {
          host_id: '',
          severity: '',
          category: '',
          status: '',
          rule_id: '',
        };
        loadDetections(true);
      });
    }

    if (dom.btnRefresh) {
      dom.btnRefresh.addEventListener('click', () => {
        loadDetections(true);
      });
    }

    if (dom.btnPrev) {
      dom.btnPrev.addEventListener('click', () => {
        if (state.offset > 0) {
          state.offset = Math.max(0, state.offset - state.limit);
          loadDetections(true);
        }
      });
    }

    if (dom.btnNext) {
      dom.btnNext.addEventListener('click', () => {
        if (state.offset + state.limit < state.total) {
          state.offset += state.limit;
          loadDetections(true);
        }
      });
    }

    if (dom.modalCloseBtn) {
      dom.modalCloseBtn.addEventListener('click', closeDetailModal);
    }

    if (dom.modal) {
      dom.modal.addEventListener('click', (e) => {
        if (e.target === dom.modal) {
          closeDetailModal();
        }
      });
    }

    if (dom.btnAck) {
      dom.btnAck.addEventListener('click', handleModalAcknowledge);
    }
  }

  /**
   * Public initialize function.
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
  globalObj.OsirisDetections = Object.freeze({
    init,
    loadDetections,
    openDetailModal,
    updateSummaryStats,
  });

})(typeof window !== 'undefined' ? window : this, typeof document !== 'undefined' ? document : {});
