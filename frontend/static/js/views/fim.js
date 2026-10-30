/**
 * OSIRIS Platform - File Integrity Monitoring (FIM) View Controller
 * Phase 2 Milestone 2.5
 *
 * Responsibilities:
 * - Load and render paginated FIM deviations and cryptographic baselines.
 * - Manage sub-navigation tab switching between Deviations and Baselines.
 * - Manage filter states for deviations and baselines with URLSearchParams.
 * - Manage pagination states (limit, offset, total) with boundary protections (PAGE_SIZE = 25).
 * - Render deviation inspection modal with side-by-side expected vs observed values.
 * - Render baseline inspection modal with monitored files preview.
 * - Provide verification modal to trigger on-demand FIM verification runs.
 * - Render dynamic DOM values strictly with createElement and textContent.
 * - Rely strictly on centralized OsirisApi for session persistence.
 * - Handle loading, empty ("No file integrity deviations found matching the selected filters."), and error states.
 */

(function (window, document) {
  'use strict';

  const PAGE_SIZE = 25;
  const REFRESH_COOLDOWN_MS = 5000;

  // View state management
  const state = {
    activeTab: 'deviations',
    isLoading: false,
    lastFetchTime: 0,
    hasLoadedOnce: false,
    selectedDeviationId: null,
    selectedBaselineId: null,
    deviations: {
      limit: PAGE_SIZE,
      offset: 0,
      total: 0,
      isLoading: false,
      items: [],
      filters: {
        host_id: '',
        baseline_id: '',
        file_path: '',
        deviation_type: '',
        severity: '',
      },
    },
    baselines: {
      limit: PAGE_SIZE,
      offset: 0,
      total: 0,
      isLoading: false,
      items: [],
      filters: {
        host_id: '',
        status: '',
      },
    },
    stats: {
      totalBaselines: 0,
      activeDeviations: 0,
      criticalDeviations: 0,
      filesMonitored: 0,
    },
  };

  // Cached DOM elements
  let dom = {};

  /**
   * Cache DOM element references for FIM View.
   */
  function cacheElements() {
    if (!document || typeof document.getElementById !== 'function') return;
    dom = {
      // Header & Global Actions
      btnVerifyTrigger: document.getElementById('fim-verify-trigger-btn'),
      btnRefresh: document.getElementById('fim-refresh-btn'),
      refreshTime: document.getElementById('fim-refresh-time'),
      navBadge: document.getElementById('nav-fim-badge'),

      // Summary Stat Cards
      statBaselines: document.getElementById('fim-stat-baselines'),
      statDeviations: document.getElementById('fim-stat-deviations'),
      statCritical: document.getElementById('fim-stat-critical'),
      statFiles: document.getElementById('fim-stat-files'),

      // Sub-nav Tabs & Panels
      tabDeviations: document.getElementById('fim-tab-deviations'),
      tabBaselines: document.getElementById('fim-tab-baselines'),
      panelDeviations: document.getElementById('fim-panel-deviations'),
      panelBaselines: document.getElementById('fim-panel-baselines'),

      // Deviations Filter Form
      formDeviationsFilter: document.getElementById('fim-deviations-filter-form'),
      inputDevHostId: document.getElementById('filter-fim-host-id'),
      inputDevBaselineId: document.getElementById('filter-fim-baseline-id'),
      inputDevFilePath: document.getElementById('filter-fim-file-path'),
      selectDevType: document.getElementById('filter-fim-deviation-type'),
      selectDevSeverity: document.getElementById('filter-fim-severity'),
      btnDevApply: document.getElementById('fim-deviations-apply-btn'),
      btnDevReset: document.getElementById('fim-deviations-reset-btn'),

      // Deviations Table Elements
      totalBadgeDeviations: document.getElementById('fim-deviations-total-badge'),
      loadingDeviations: document.getElementById('fim-deviations-loading'),
      emptyDeviations: document.getElementById('fim-deviations-empty-state'),
      errorDeviations: document.getElementById('fim-deviations-error'),
      tableDeviations: document.getElementById('fim-deviations-table'),
      tbodyDeviations: document.getElementById('fim-deviations-tbody'),
      btnPrevDeviations: document.getElementById('fim-deviations-prev-btn'),
      btnNextDeviations: document.getElementById('fim-deviations-next-btn'),
      pageInfoDeviations: document.getElementById('fim-deviations-page-info'),

      // Baselines Filter Form
      formBaselinesFilter: document.getElementById('fim-baselines-filter-form'),
      inputBaseHostId: document.getElementById('filter-fim-baseline-host-id'),
      selectBaseStatus: document.getElementById('filter-fim-baseline-status'),
      btnBaseApply: document.getElementById('fim-baselines-apply-btn'),
      btnBaseReset: document.getElementById('fim-baselines-reset-btn'),

      // Baselines Table Elements
      totalBadgeBaselines: document.getElementById('fim-baselines-total-badge'),
      loadingBaselines: document.getElementById('fim-baselines-loading'),
      emptyBaselines: document.getElementById('fim-baselines-empty-state'),
      errorBaselines: document.getElementById('fim-baselines-error'),
      tableBaselines: document.getElementById('fim-baselines-table'),
      tbodyBaselines: document.getElementById('fim-baselines-tbody'),
      btnPrevBaselines: document.getElementById('fim-baselines-prev-btn'),
      btnNextBaselines: document.getElementById('fim-baselines-next-btn'),
      pageInfoBaselines: document.getElementById('fim-baselines-page-info'),

      // Deviation Detail Modal
      modalDeviation: document.getElementById('fim-deviation-detail-modal'),
      modalDeviationCloseBtn: document.getElementById('fim-deviation-modal-close'),
      detailDevPath: document.getElementById('detail-fim-deviation-path'),
      detailDevType: document.getElementById('detail-fim-deviation-type'),
      detailDevSeverity: document.getElementById('detail-fim-deviation-severity'),
      detailDevTimestamp: document.getElementById('detail-fim-deviation-timestamp'),
      detailDevHost: document.getElementById('detail-fim-deviation-host'),
      detailDevBaseline: document.getElementById('detail-fim-deviation-baseline'),
      detailDevDetectionId: document.getElementById('detail-fim-deviation-detection-id'),
      detailDevExplanation: document.getElementById('detail-fim-deviation-explanation'),
      detailDevDiff: document.getElementById('detail-fim-deviation-diff'),

      // Baseline Detail Modal
      modalBaseline: document.getElementById('fim-baseline-detail-modal'),
      modalBaselineCloseBtn: document.getElementById('fim-baseline-modal-close'),
      detailBaseId: document.getElementById('detail-fim-baseline-id'),
      detailBaseHost: document.getElementById('detail-fim-baseline-host'),
      detailBaseVersion: document.getElementById('detail-fim-baseline-version'),
      detailBaseStatus: document.getElementById('detail-fim-baseline-status'),
      detailBaseScope: document.getElementById('detail-fim-baseline-scope'),
      detailBaseRules: document.getElementById('detail-fim-baseline-rules'),
      detailBaseFilesCount: document.getElementById('detail-fim-baseline-files-count'),
      detailBaseTotalSize: document.getElementById('detail-fim-baseline-total-size'),
      detailBaseDuration: document.getElementById('detail-fim-baseline-duration'),
      detailBaseFilesTbody: document.getElementById('detail-fim-baseline-files-tbody'),

      // Verification Modal
      modalVerify: document.getElementById('fim-verify-modal'),
      modalVerifyCloseBtn: document.getElementById('fim-verify-modal-close'),
      formVerify: document.getElementById('fim-verify-form'),
      inputVerifyHostId: document.getElementById('verify-fim-host-id'),
      inputVerifyBaselineId: document.getElementById('verify-fim-baseline-id'),
      inputVerifyPathScope: document.getElementById('verify-fim-path-scope'),
      checkVerifyContents: document.getElementById('verify-fim-check-contents'),
      checkVerifyPermissions: document.getElementById('verify-fim-check-permissions'),
      checkVerifyOwnership: document.getElementById('verify-fim-check-ownership'),
      btnVerifySubmit: document.getElementById('verify-fim-submit-btn'),
      resultVerify: document.getElementById('verify-fim-result'),
    };
  }

  /**
   * Format ISO timestamp string into human-readable UTC display.
   */
  function formatTimestamp(isoStr) {
    if (!isoStr) return '--';
    try {
      const d = new Date(isoStr);
      if (isNaN(d.getTime())) return String(isoStr);
      return d.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
    } catch {
      return String(isoStr);
    }
  }

  /**
   * Format bytes into human-readable size string.
   */
  function formatBytes(bytes) {
    if (bytes === null || bytes === undefined || isNaN(bytes)) return '--';
    const num = Number(bytes);
    if (num < 1024) return `${num} B`;
    if (num < 1024 * 1024) return `${(num / 1024).toFixed(1)} KB`;
    if (num < 1024 * 1024 * 1024) return `${(num / (1024 * 1024)).toFixed(1)} MB`;
    return `${(num / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  }

  /**
   * Return severity badge CSS classes.
   */
  function getSeverityBadgeClass(sev) {
    const s = String(sev || '').toLowerCase();
    if (s === 'critical') return 'badge badge-danger';
    if (s === 'high') return 'badge badge-warning';
    if (s === 'medium') return 'badge badge-info';
    return 'badge badge-secondary';
  }

  /**
   * Return deviation type badge CSS classes.
   */
  function getDeviationTypeBadgeClass(dtype) {
    const t = String(dtype || '').toLowerCase();
    if (t === 'removed') return 'badge badge-danger';
    if (t === 'modified') return 'badge badge-warning';
    if (t === 'added') return 'badge badge-info';
    return 'badge badge-secondary';
  }

  /**
   * Return baseline status badge CSS classes.
   */
  function getBaselineStatusBadgeClass(status) {
    const s = String(status || '').toLowerCase();
    if (s === 'active') return 'badge badge-success';
    if (s === 'revoked') return 'badge badge-danger';
    return 'badge badge-secondary';
  }

  /**
   * Switch between Deviations and Baselines sub-tabs.
   */
  function switchTab(tabName) {
    state.activeTab = tabName;

    if (dom.tabDeviations && dom.tabBaselines) {
      if (tabName === 'deviations') {
        dom.tabDeviations.classList.add('active');
        dom.tabDeviations.setAttribute('aria-selected', 'true');
        dom.tabBaselines.classList.remove('active');
        dom.tabBaselines.setAttribute('aria-selected', 'false');

        if (dom.panelDeviations) dom.panelDeviations.classList.remove('hidden');
        if (dom.panelBaselines) dom.panelBaselines.classList.add('hidden');
        loadDeviations();
      } else {
        dom.tabBaselines.classList.add('active');
        dom.tabBaselines.setAttribute('aria-selected', 'true');
        dom.tabDeviations.classList.remove('active');
        dom.tabDeviations.setAttribute('aria-selected', 'false');

        if (dom.panelBaselines) dom.panelBaselines.classList.remove('hidden');
        if (dom.panelDeviations) dom.panelDeviations.classList.add('hidden');
        loadBaselines();
      }
    }
  }

  /**
   * Refresh timestamp display.
   */
  function updateRefreshTime() {
    if (dom.refreshTime) {
      const now = new Date();
      dom.refreshTime.textContent = `Updated ${now.toISOString().substring(11, 19)} UTC`;
    }
  }

  /**
   * Fetch and calculate summary stats and update badges.
   */
  async function updateSummaryStats() {
    if (!window.OsirisApi) return;

    try {
      // 1. Total Baselines
      const baselinesData = await window.OsirisApi.getFimBaselines({ limit: 1 });
      state.stats.totalBaselines = baselinesData.total || 0;
      if (dom.statBaselines) {
        dom.statBaselines.textContent = String(state.stats.totalBaselines);
      }

      // 2. Total Active Deviations
      const deviationsData = await window.OsirisApi.getFimDeviations({ limit: 1 });
      state.stats.activeDeviations = deviationsData.total || 0;
      if (dom.statDeviations) {
        dom.statDeviations.textContent = String(state.stats.activeDeviations);
      }

      // 3. Critical Deviations
      const critData = await window.OsirisApi.getFimDeviations({ severity: 'critical', limit: 1 });
      state.stats.criticalDeviations = critData.total || 0;
      if (dom.statCritical) {
        dom.statCritical.textContent = String(state.stats.criticalDeviations);
      }

      // 4. Update Navigation Badge
      if (dom.navBadge) {
        if (state.stats.activeDeviations > 0) {
          dom.navBadge.textContent = String(state.stats.activeDeviations);
          dom.navBadge.classList.remove('hidden');
        } else {
          dom.navBadge.textContent = '0';
          dom.navBadge.classList.add('hidden');
        }
      }

      // 5. Total Files Monitored (aggregate across latest active baselines if available)
      if (baselinesData.items && baselinesData.items.length > 0) {
        let totalFiles = 0;
        baselinesData.items.forEach((b) => {
          if (b.total_files) totalFiles += b.total_files;
        });
        state.stats.filesMonitored = totalFiles;
        if (dom.statFiles) {
          dom.statFiles.textContent = String(totalFiles);
        }
      }
    } catch {
      // Non-critical background metric fetch error
    }
  }

  /**
   * Load FIM view data.
   */
  async function loadFim(force = false) {
    const now = Date.now();
    if (!force && state.hasLoadedOnce && now - state.lastFetchTime < REFRESH_COOLDOWN_MS) {
      return;
    }

    state.lastFetchTime = now;
    state.hasLoadedOnce = true;

    await updateSummaryStats();
    if (state.activeTab === 'deviations') {
      await loadDeviations();
    } else {
      await loadBaselines();
    }
    updateRefreshTime();
  }

  // ==========================================
  // DEVIATIONS CONTROLLER
  // ==========================================

  /**
   * Load deviations list based on state and filters.
   */
  async function loadDeviations() {
    if (state.deviations.isLoading || !window.OsirisApi) return;

    state.deviations.isLoading = true;
    if (dom.loadingDeviations) dom.loadingDeviations.classList.remove('hidden');
    if (dom.emptyDeviations) dom.emptyDeviations.classList.add('hidden');
    if (dom.errorDeviations) dom.errorDeviations.classList.add('hidden');

    try {
      const params = {
        limit: state.deviations.limit,
        offset: state.deviations.offset,
      };

      const f = state.deviations.filters;
      if (f.host_id) params.host_id = f.host_id;
      if (f.baseline_id) params.baseline_id = f.baseline_id;
      if (f.file_path) params.file_path = f.file_path;
      if (f.deviation_type) params.deviation_type = f.deviation_type;
      if (f.severity) params.severity = f.severity;

      const data = await window.OsirisApi.getFimDeviations(params);
      state.deviations.total = data.total || 0;
      state.deviations.items = data.items || [];

      renderDeviationsTable(state.deviations.items);
      renderDeviationsPagination();
    } catch (err) {
      if (dom.errorDeviations) {
        dom.errorDeviations.textContent = err.message || 'Failed to load file integrity deviations.';
        dom.errorDeviations.classList.remove('hidden');
      }
    } finally {
      state.deviations.isLoading = false;
      if (dom.loadingDeviations) dom.loadingDeviations.classList.add('hidden');
    }
  }

  /**
   * Render deviations table rows safely using createElement/textContent.
   */
  function renderDeviationsTable(deviations) {
    if (!dom.tbodyDeviations) return;

    while (dom.tbodyDeviations.firstChild) {
      dom.tbodyDeviations.removeChild(dom.tbodyDeviations.firstChild);
    }

    if (!deviations || deviations.length === 0) {
      if (dom.emptyDeviations) dom.emptyDeviations.classList.remove('hidden');
      if (dom.totalBadgeDeviations) dom.totalBadgeDeviations.textContent = '0 Deviations';
      return;
    }

    if (dom.emptyDeviations) dom.emptyDeviations.classList.add('hidden');
    if (dom.totalBadgeDeviations) {
      dom.totalBadgeDeviations.textContent = `${state.deviations.total} Deviation${state.deviations.total === 1 ? '' : 's'}`;
    }

    deviations.forEach((dev) => {
      const tr = document.createElement('tr');
      tr.className = 'table-row-hover';

      // 1. Detected At (UTC)
      const tdTs = document.createElement('td');
      tdTs.className = 'font-mono text-xs';
      tdTs.textContent = formatTimestamp(dev.detected_at);
      tr.appendChild(tdTs);

      // 2. Severity
      const tdSev = document.createElement('td');
      const sevBadge = document.createElement('span');
      sevBadge.className = getSeverityBadgeClass(dev.severity);
      sevBadge.textContent = (dev.severity || 'medium').toUpperCase();
      tdSev.appendChild(sevBadge);
      tr.appendChild(tdSev);

      // 3. Deviation Type
      const tdType = document.createElement('td');
      const typeBadge = document.createElement('span');
      typeBadge.className = getDeviationTypeBadgeClass(dev.deviation_type);
      typeBadge.textContent = (dev.deviation_type || 'modified').replace('_', ' ').toUpperCase();
      tdType.appendChild(typeBadge);
      tr.appendChild(tdType);

      // 4. File Path
      const tdPath = document.createElement('td');
      tdPath.className = 'font-mono font-bold text-xs';
      tdPath.textContent = dev.file_path || '--';
      tr.appendChild(tdPath);

      // 5. Host ID
      const tdHost = document.createElement('td');
      tdHost.className = 'font-mono text-xs text-muted';
      const hostStr = String(dev.host_id || '--');
      tdHost.textContent = hostStr.length > 12 ? `${hostStr.substring(0, 8)}...` : hostStr;
      tr.appendChild(tdHost);

      // 6. Linked Detection ID
      const tdDet = document.createElement('td');
      if (dev.detection_id) {
        const detBadge = document.createElement('span');
        detBadge.className = 'badge badge-outline text-xs font-mono';
        const dStr = String(dev.detection_id);
        detBadge.textContent = dStr.length > 10 ? `${dStr.substring(0, 8)}...` : dStr;
        tdDet.appendChild(detBadge);
      } else {
        tdDet.textContent = '--';
        tdDet.className = 'text-muted text-xs';
      }
      tr.appendChild(tdDet);

      // 7. Actions
      const tdActions = document.createElement('td');
      tdActions.className = 'table-actions';
      const btnInspect = document.createElement('button');
      btnInspect.type = 'button';
      btnInspect.className = 'btn btn-outline btn-xs';
      btnInspect.textContent = 'Inspect';
      btnInspect.setAttribute('aria-label', `Inspect deviation on ${dev.file_path}`);
      btnInspect.addEventListener('click', () => openDeviationModal(dev.id));
      tdActions.appendChild(btnInspect);
      tr.appendChild(tdActions);

      dom.tbodyDeviations.appendChild(tr);
    });
  }

  /**
   * Render deviations pagination controls.
   */
  function renderDeviationsPagination() {
    const total = state.deviations.total;
    const limit = state.deviations.limit;
    const offset = state.deviations.offset;

    const currentPage = Math.floor(offset / limit) + 1;
    const totalPages = Math.max(1, Math.ceil(total / limit));

    if (dom.pageInfoDeviations) {
      dom.pageInfoDeviations.textContent = `Page ${currentPage} of ${totalPages} (${total} total)`;
    }

    if (dom.btnPrevDeviations) {
      dom.btnPrevDeviations.disabled = offset === 0;
    }

    if (dom.btnNextDeviations) {
      dom.btnNextDeviations.disabled = offset + limit >= total;
    }
  }

  /**
   * Open Deviation Detail Inspector Modal.
   */
  async function openDeviationModal(deviationId) {
    if (!deviationId || !window.OsirisApi) return;
    state.selectedDeviationId = deviationId;

    try {
      const dev = await window.OsirisApi.getFimDeviation(deviationId);

      if (dom.detailDevPath) dom.detailDevPath.textContent = dev.file_path || '--';
      if (dom.detailDevType) {
        dom.detailDevType.textContent = (dev.deviation_type || '--').replace('_', ' ').toUpperCase();
        dom.detailDevType.className = `detail-val ${getDeviationTypeBadgeClass(dev.deviation_type)}`;
      }
      if (dom.detailDevSeverity) {
        dom.detailDevSeverity.textContent = (dev.severity || 'medium').toUpperCase();
        dom.detailDevSeverity.className = `detail-val ${getSeverityBadgeClass(dev.severity)}`;
      }
      if (dom.detailDevTimestamp) dom.detailDevTimestamp.textContent = formatTimestamp(dev.detected_at);
      if (dom.detailDevHost) dom.detailDevHost.textContent = String(dev.host_id || '--');
      if (dom.detailDevBaseline) dom.detailDevBaseline.textContent = String(dev.baseline_id || '--');
      if (dom.detailDevDetectionId) {
        dom.detailDevDetectionId.textContent = dev.detection_id ? String(dev.detection_id) : 'None';
      }

      // Forensic explanation
      if (dom.detailDevExplanation) {
        while (dom.detailDevExplanation.firstChild) {
          dom.detailDevExplanation.removeChild(dom.detailDevExplanation.firstChild);
        }
        const p = document.createElement('p');
        let expl = `Integrity deviation detected for ${dev.file_path}. `;
        if (dev.deviation_type === 'modified') {
          expl += 'The cryptographic digest (SHA-256) of this monitored file changed from its established baseline.';
        } else if (dev.deviation_type === 'added') {
          expl += 'A new unexpected file was introduced within the monitored scope.';
        } else if (dev.deviation_type === 'removed') {
          expl += 'A monitored file present in the cryptographic baseline was deleted or moved.';
        } else if (dev.deviation_type === 'permission_changed') {
          expl += 'Filesystem permission bits (mode/SUID/SGID) changed from the baseline recording.';
        } else if (dev.deviation_type === 'ownership_changed') {
          expl += 'The file owner (UID) or group (GID) changed from the baseline recording.';
        }
        p.textContent = expl;
        dom.detailDevExplanation.appendChild(p);
      }

      // Expected vs Observed Forensic Comparison
      if (dom.detailDevDiff) {
        while (dom.detailDevDiff.firstChild) {
          dom.detailDevDiff.removeChild(dom.detailDevDiff.firstChild);
        }

        const lines = [
          '=== FORENSIC INTEGRITY COMPARISON ===',
          `Target File       : ${dev.file_path}`,
          `Deviation Type    : ${dev.deviation_type}`,
          '',
          'ATTRIBUTE            EXPECTED (BASELINE)                  OBSERVED (CURRENT)',
          '----------------------------------------------------------------------------------',
          `SHA-256 Digest     : ${(dev.expected_sha256 || 'N/A').padEnd(36)} ${(dev.observed_sha256 || 'N/A')}`,
          `File Size          : ${String(formatBytes(dev.expected_size)).padEnd(36)} ${formatBytes(dev.observed_size)}`,
          `Permissions (Mode) : ${(dev.expected_mode || 'N/A').padEnd(36)} ${(dev.observed_mode || 'N/A')}`,
          `UID (Owner)        : ${String(dev.expected_uid !== null ? dev.expected_uid : 'N/A').padEnd(36)} ${String(dev.observed_uid !== null ? dev.observed_uid : 'N/A')}`,
          `GID (Group)        : ${String(dev.expected_gid !== null ? dev.expected_gid : 'N/A').padEnd(36)} ${String(dev.observed_gid !== null ? dev.observed_gid : 'N/A')}`,
        ];

        dom.detailDevDiff.textContent = lines.join('\n');
      }

      if (dom.modalDeviation) dom.modalDeviation.classList.remove('hidden');
    } catch {
      // Error fetching deviation details
    }
  }

  function closeDeviationModal() {
    if (dom.modalDeviation) dom.modalDeviation.classList.add('hidden');
    state.selectedDeviationId = null;
  }

  // ==========================================
  // BASELINES CONTROLLER
  // ==========================================

  /**
   * Load baselines list based on state and filters.
   */
  async function loadBaselines() {
    if (state.baselines.isLoading || !window.OsirisApi) return;

    state.baselines.isLoading = true;
    if (dom.loadingBaselines) dom.loadingBaselines.classList.remove('hidden');
    if (dom.emptyBaselines) dom.emptyBaselines.classList.add('hidden');
    if (dom.errorBaselines) dom.errorBaselines.classList.add('hidden');

    try {
      const params = {
        limit: state.baselines.limit,
        offset: state.baselines.offset,
      };

      const f = state.baselines.filters;
      if (f.host_id) params.host_id = f.host_id;
      if (f.status) params.status = f.status;

      const data = await window.OsirisApi.getFimBaselines(params);
      state.baselines.total = data.total || 0;
      state.baselines.items = data.items || [];

      renderBaselinesTable(state.baselines.items);
      renderBaselinesPagination();
    } catch (err) {
      if (dom.errorBaselines) {
        dom.errorBaselines.textContent = err.message || 'Failed to load filesystem baselines.';
        dom.errorBaselines.classList.remove('hidden');
      }
    } finally {
      state.baselines.isLoading = false;
      if (dom.loadingBaselines) dom.loadingBaselines.classList.add('hidden');
    }
  }

  /**
   * Render baselines table rows safely using createElement/textContent.
   */
  function renderBaselinesTable(baselines) {
    if (!dom.tbodyBaselines) return;

    while (dom.tbodyBaselines.firstChild) {
      dom.tbodyBaselines.removeChild(dom.tbodyBaselines.firstChild);
    }

    if (!baselines || baselines.length === 0) {
      if (dom.emptyBaselines) dom.emptyBaselines.classList.remove('hidden');
      if (dom.totalBadgeBaselines) dom.totalBadgeBaselines.textContent = '0 Baselines';
      return;
    }

    if (dom.emptyBaselines) dom.emptyBaselines.classList.add('hidden');
    if (dom.totalBadgeBaselines) {
      dom.totalBadgeBaselines.textContent = `${state.baselines.total} Baseline${state.baselines.total === 1 ? '' : 's'}`;
    }

    baselines.forEach((base) => {
      const tr = document.createElement('tr');
      tr.className = 'table-row-hover';

      // 1. Created At (UTC)
      const tdTs = document.createElement('td');
      tdTs.className = 'font-mono text-xs';
      tdTs.textContent = formatTimestamp(base.created_at);
      tr.appendChild(tdTs);

      // 2. Host ID
      const tdHost = document.createElement('td');
      tdHost.className = 'font-mono text-xs';
      const hostStr = String(base.host_id || '--');
      tdHost.textContent = hostStr.length > 12 ? `${hostStr.substring(0, 8)}...` : hostStr;
      tr.appendChild(tdHost);

      // 3. Version
      const tdVer = document.createElement('td');
      tdVer.className = 'font-mono text-xs';
      tdVer.textContent = `v${base.version || 1}`;
      tr.appendChild(tdVer);

      // 4. Status
      const tdStat = document.createElement('td');
      const statBadge = document.createElement('span');
      statBadge.className = getBaselineStatusBadgeClass(base.status);
      statBadge.textContent = (base.status || 'active').toUpperCase();
      tdStat.appendChild(statBadge);
      tr.appendChild(tdStat);

      // 5. Path Scope
      const tdScope = document.createElement('td');
      tdScope.className = 'font-mono text-xs text-muted';
      tdScope.textContent = base.path_scope || '--';
      tr.appendChild(tdScope);

      // 6. Files Count
      const tdFiles = document.createElement('td');
      tdFiles.className = 'font-bold text-xs';
      tdFiles.textContent = String(base.total_files || 0);
      tr.appendChild(tdFiles);

      // 7. Total Size
      const tdSize = document.createElement('td');
      tdSize.className = 'font-mono text-xs';
      tdSize.textContent = formatBytes(base.total_bytes);
      tr.appendChild(tdSize);

      // 8. Actions
      const tdActions = document.createElement('td');
      tdActions.className = 'table-actions';

      const btnInspect = document.createElement('button');
      btnInspect.type = 'button';
      btnInspect.className = 'btn btn-outline btn-xs';
      btnInspect.textContent = 'Inspect';
      btnInspect.setAttribute('aria-label', `Inspect baseline v${base.version}`);
      btnInspect.addEventListener('click', () => openBaselineModal(base.id));
      tdActions.appendChild(btnInspect);

      const btnVerify = document.createElement('button');
      btnVerify.type = 'button';
      btnVerify.className = 'btn btn-primary btn-xs ml-1';
      btnVerify.textContent = 'Verify';
      btnVerify.setAttribute('aria-label', `Verify baseline v${base.version}`);
      btnVerify.addEventListener('click', () => openVerifyModal(base.host_id, base.id));
      tdActions.appendChild(btnVerify);

      tr.appendChild(tdActions);
      dom.tbodyBaselines.appendChild(tr);
    });
  }

  /**
   * Render baselines pagination controls.
   */
  function renderBaselinesPagination() {
    const total = state.baselines.total;
    const limit = state.baselines.limit;
    const offset = state.baselines.offset;

    const currentPage = Math.floor(offset / limit) + 1;
    const totalPages = Math.max(1, Math.ceil(total / limit));

    if (dom.pageInfoBaselines) {
      dom.pageInfoBaselines.textContent = `Page ${currentPage} of ${totalPages} (${total} total)`;
    }

    if (dom.btnPrevBaselines) {
      dom.btnPrevBaselines.disabled = offset === 0;
    }

    if (dom.btnNextBaselines) {
      dom.btnNextBaselines.disabled = offset + limit >= total;
    }
  }

  /**
   * Open Baseline Detail Inspector Modal.
   */
  async function openBaselineModal(baselineId) {
    if (!baselineId || !window.OsirisApi) return;
    state.selectedBaselineId = baselineId;

    try {
      const base = await window.OsirisApi.getFimBaseline(baselineId);

      if (dom.detailBaseId) dom.detailBaseId.textContent = String(base.id || '--');
      if (dom.detailBaseHost) dom.detailBaseHost.textContent = String(base.host_id || '--');
      if (dom.detailBaseVersion) dom.detailBaseVersion.textContent = `v${base.version || 1}`;
      if (dom.detailBaseStatus) {
        dom.detailBaseStatus.textContent = (base.status || 'active').toUpperCase();
        dom.detailBaseStatus.className = `detail-val ${getBaselineStatusBadgeClass(base.status)}`;
      }
      if (dom.detailBaseScope) dom.detailBaseScope.textContent = base.path_scope || '--';
      if (dom.detailBaseRules) {
        const incl = (base.include_patterns || []).join(', ') || '*';
        const excl = (base.exclude_patterns || []).join(', ') || 'none';
        dom.detailBaseRules.textContent = `Include: [${incl}] | Exclude: [${excl}]`;
      }
      if (dom.detailBaseFilesCount) dom.detailBaseFilesCount.textContent = String(base.total_files || 0);
      if (dom.detailBaseTotalSize) dom.detailBaseTotalSize.textContent = formatBytes(base.total_bytes);
      if (dom.detailBaseDuration) {
        dom.detailBaseDuration.textContent = base.scan_duration_ms ? `${base.scan_duration_ms} ms` : '--';
      }

      // Fetch baseline files sample
      if (dom.detailBaseFilesTbody) {
        while (dom.detailBaseFilesTbody.firstChild) {
          dom.detailBaseFilesTbody.removeChild(dom.detailBaseFilesTbody.firstChild);
        }

        const filesData = await window.OsirisApi.getFimBaselineFiles(baselineId, { limit: 50 });
        const files = filesData.items || [];

        if (files.length === 0) {
          const tr = document.createElement('tr');
          const td = document.createElement('td');
          td.colSpan = 5;
          td.className = 'text-center text-muted';
          td.textContent = 'No file entries in this baseline.';
          tr.appendChild(td);
          dom.detailBaseFilesTbody.appendChild(tr);
        } else {
          files.forEach((f) => {
            const tr = document.createElement('tr');

            const tdPath = document.createElement('td');
            tdPath.className = 'font-mono text-xs';
            tdPath.textContent = f.file_path;
            tr.appendChild(tdPath);

            const tdSha = document.createElement('td');
            tdSha.className = 'font-mono text-xs text-muted';
            const sha = f.sha256_hash || '';
            tdSha.textContent = sha.length > 16 ? `${sha.substring(0, 12)}...` : sha;
            tr.appendChild(tdSha);

            const tdMode = document.createElement('td');
            tdMode.className = 'font-mono text-xs';
            tdMode.textContent = f.file_mode || '--';
            tr.appendChild(tdMode);

            const tdOwner = document.createElement('td');
            tdOwner.className = 'font-mono text-xs';
            tdOwner.textContent = `${f.uid}:${f.gid}`;
            tr.appendChild(tdOwner);

            const tdSize = document.createElement('td');
            tdSize.className = 'font-mono text-xs';
            tdSize.textContent = formatBytes(f.size_bytes);
            tr.appendChild(tdSize);

            dom.detailBaseFilesTbody.appendChild(tr);
          });
        }
      }

      if (dom.modalBaseline) dom.modalBaseline.classList.remove('hidden');
    } catch {
      // Error fetching baseline details
    }
  }

  function closeBaselineModal() {
    if (dom.modalBaseline) dom.modalBaseline.classList.add('hidden');
    state.selectedBaselineId = null;
  }

  // ==========================================
  // VERIFICATION TRIGGER CONTROLLER
  // ==========================================

  /**
   * Open Verification Modal.
   */
  function openVerifyModal(hostId = '', baselineId = '') {
    if (dom.inputVerifyHostId) dom.inputVerifyHostId.value = hostId || '';
    if (dom.inputVerifyBaselineId) dom.inputVerifyBaselineId.value = baselineId || '';
    if (dom.inputVerifyPathScope) dom.inputVerifyPathScope.value = '';
    if (dom.resultVerify) {
      dom.resultVerify.textContent = '';
      dom.resultVerify.classList.add('hidden');
    }

    if (dom.modalVerify) dom.modalVerify.classList.remove('hidden');
  }

  function closeVerifyModal() {
    if (dom.modalVerify) dom.modalVerify.classList.add('hidden');
  }

  /**
   * Submit FIM Verification run.
   */
  async function handleVerifySubmit(e) {
    if (e && typeof e.preventDefault === 'function') e.preventDefault();
    if (!window.OsirisApi) return;

    const hostId = dom.inputVerifyHostId ? dom.inputVerifyHostId.value.trim() : '';
    if (!hostId) {
      if (dom.resultVerify) {
        dom.resultVerify.textContent = 'Host ID is required to run verification.';
        dom.resultVerify.className = 'alert-box alert-error';
        dom.resultVerify.classList.remove('hidden');
      }
      return;
    }

    const payload = {
      host_id: hostId,
      check_contents: dom.checkVerifyContents ? dom.checkVerifyContents.checked : true,
      check_permissions: dom.checkVerifyPermissions ? dom.checkVerifyPermissions.checked : true,
      check_ownership: dom.checkVerifyOwnership ? dom.checkVerifyOwnership.checked : true,
    };

    const bId = dom.inputVerifyBaselineId ? dom.inputVerifyBaselineId.value.trim() : '';
    if (bId) payload.baseline_id = bId;

    const scope = dom.inputVerifyPathScope ? dom.inputVerifyPathScope.value.trim() : '';
    if (scope) payload.path_scope = scope;

    if (dom.btnVerifySubmit) {
      dom.btnVerifySubmit.disabled = true;
      dom.btnVerifySubmit.textContent = 'Verifying...';
    }

    try {
      const res = await window.OsirisApi.verifyFim(payload);
      if (dom.resultVerify) {
        dom.resultVerify.textContent = `Verification completed in ${res.verification_duration_ms} ms. ${res.total_files_checked} files checked. Deviations found: ${res.deviations_found}. Detections triggered: ${res.detections_triggered}.`;
        dom.resultVerify.className = res.deviations_found > 0 ? 'alert-box alert-warning' : 'alert-box alert-success';
        dom.resultVerify.classList.remove('hidden');
      }

      // Refresh FIM data and summary stats
      await loadFim(true);
    } catch (err) {
      if (dom.resultVerify) {
        dom.resultVerify.textContent = err.message || 'Verification failed.';
        dom.resultVerify.className = 'alert-box alert-error';
        dom.resultVerify.classList.remove('hidden');
      }
    } finally {
      if (dom.btnVerifySubmit) {
        dom.btnVerifySubmit.disabled = false;
        dom.btnVerifySubmit.textContent = 'Run Verification';
      }
    }
  }

  // ==========================================
  // EVENT BINDINGS & LIFECYCLE
  // ==========================================

  function bindEvents() {
    // Refresh button
    if (dom.btnRefresh) {
      dom.btnRefresh.addEventListener('click', () => loadFim(true));
    }

    // Verify Trigger button
    if (dom.btnVerifyTrigger) {
      dom.btnVerifyTrigger.addEventListener('click', () => openVerifyModal());
    }

    // Sub-nav tab switching
    if (dom.tabDeviations) {
      dom.tabDeviations.addEventListener('click', () => switchTab('deviations'));
    }
    if (dom.tabBaselines) {
      dom.tabBaselines.addEventListener('click', () => switchTab('baselines'));
    }

    // Deviations Filter Form
    if (dom.formDeviationsFilter) {
      dom.formDeviationsFilter.addEventListener('submit', (e) => {
        e.preventDefault();
        state.deviations.offset = 0;
        state.deviations.filters.host_id = dom.inputDevHostId ? dom.inputDevHostId.value.trim() : '';
        state.deviations.filters.baseline_id = dom.inputDevBaselineId ? dom.inputDevBaselineId.value.trim() : '';
        state.deviations.filters.file_path = dom.inputDevFilePath ? dom.inputDevFilePath.value.trim() : '';
        state.deviations.filters.deviation_type = dom.selectDevType ? dom.selectDevType.value : '';
        state.deviations.filters.severity = dom.selectDevSeverity ? dom.selectDevSeverity.value : '';
        loadDeviations();
      });
    }

    // Deviations Reset Button
    if (dom.btnDevReset) {
      dom.btnDevReset.addEventListener('click', () => {
        if (dom.inputDevHostId) dom.inputDevHostId.value = '';
        if (dom.inputDevBaselineId) dom.inputDevBaselineId.value = '';
        if (dom.inputDevFilePath) dom.inputDevFilePath.value = '';
        if (dom.selectDevType) dom.selectDevType.value = '';
        if (dom.selectDevSeverity) dom.selectDevSeverity.value = '';
        state.deviations.offset = 0;
        state.deviations.filters = {
          host_id: '',
          baseline_id: '',
          file_path: '',
          deviation_type: '',
          severity: '',
        };
        loadDeviations();
      });
    }

    // Deviations Pagination Buttons
    if (dom.btnPrevDeviations) {
      dom.btnPrevDeviations.addEventListener('click', () => {
        if (state.deviations.offset > 0) {
          state.deviations.offset = Math.max(0, state.deviations.offset - state.deviations.limit);
          loadDeviations();
        }
      });
    }
    if (dom.btnNextDeviations) {
      dom.btnNextDeviations.addEventListener('click', () => {
        if (state.deviations.offset + state.deviations.limit < state.deviations.total) {
          state.deviations.offset += state.deviations.limit;
          loadDeviations();
        }
      });
    }

    // Baselines Filter Form
    if (dom.formBaselinesFilter) {
      dom.formBaselinesFilter.addEventListener('submit', (e) => {
        e.preventDefault();
        state.baselines.offset = 0;
        state.baselines.filters.host_id = dom.inputBaseHostId ? dom.inputBaseHostId.value.trim() : '';
        state.baselines.filters.status = dom.selectBaseStatus ? dom.selectBaseStatus.value : '';
        loadBaselines();
      });
    }

    // Baselines Reset Button
    if (dom.btnBaseReset) {
      dom.btnBaseReset.addEventListener('click', () => {
        if (dom.inputBaseHostId) dom.inputBaseHostId.value = '';
        if (dom.selectBaseStatus) dom.selectBaseStatus.value = '';
        state.baselines.offset = 0;
        state.baselines.filters = {
          host_id: '',
          status: '',
        };
        loadBaselines();
      });
    }

    // Baselines Pagination Buttons
    if (dom.btnPrevBaselines) {
      dom.btnPrevBaselines.addEventListener('click', () => {
        if (state.baselines.offset > 0) {
          state.baselines.offset = Math.max(0, state.baselines.offset - state.baselines.limit);
          loadBaselines();
        }
      });
    }
    if (dom.btnNextBaselines) {
      dom.btnNextBaselines.addEventListener('click', () => {
        if (state.baselines.offset + state.baselines.limit < state.baselines.total) {
          state.baselines.offset += state.baselines.limit;
          loadBaselines();
        }
      });
    }

    // Modal Close Buttons & Backdrops
    if (dom.modalDeviationCloseBtn) {
      dom.modalDeviationCloseBtn.addEventListener('click', closeDeviationModal);
    }
    if (dom.modalDeviation) {
      dom.modalDeviation.addEventListener('click', (e) => {
        if (e.target === dom.modalDeviation) closeDeviationModal();
      });
    }

    if (dom.modalBaselineCloseBtn) {
      dom.modalBaselineCloseBtn.addEventListener('click', closeBaselineModal);
    }
    if (dom.modalBaseline) {
      dom.modalBaseline.addEventListener('click', (e) => {
        if (e.target === dom.modalBaseline) closeBaselineModal();
      });
    }

    if (dom.modalVerifyCloseBtn) {
      dom.modalVerifyCloseBtn.addEventListener('click', closeVerifyModal);
    }
    if (dom.modalVerify) {
      dom.modalVerify.addEventListener('click', (e) => {
        if (e.target === dom.modalVerify) closeVerifyModal();
      });
    }

    if (dom.formVerify) {
      dom.formVerify.addEventListener('submit', handleVerifySubmit);
    }
  }

  /**
   * Reset FIM view state (e.g. on user logout).
   */
  function resetFim() {
    state.deviations.offset = 0;
    state.deviations.total = 0;
    state.deviations.items = [];
    state.baselines.offset = 0;
    state.baselines.total = 0;
    state.baselines.items = [];
    state.hasLoadedOnce = false;

    if (dom.tbodyDeviations) {
      while (dom.tbodyDeviations.firstChild) {
        dom.tbodyDeviations.removeChild(dom.tbodyDeviations.firstChild);
      }
    }
    if (dom.tbodyBaselines) {
      while (dom.tbodyBaselines.firstChild) {
        dom.tbodyBaselines.removeChild(dom.tbodyBaselines.firstChild);
      }
    }
    if (dom.statBaselines) dom.statBaselines.textContent = '0';
    if (dom.statDeviations) dom.statDeviations.textContent = '0';
    if (dom.statCritical) dom.statCritical.textContent = '0';
    if (dom.statFiles) dom.statFiles.textContent = '0';
    if (dom.navBadge) {
      dom.navBadge.textContent = '0';
      dom.navBadge.classList.add('hidden');
    }
  }

  /**
   * Initialize FIM controller when DOM is ready.
   */
  function init() {
    cacheElements();
    bindEvents();
  }

  if (document && typeof document.addEventListener === 'function') {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', init);
    } else {
      init();
    }
  }

  // Export public API to window
  window.OsirisFim = Object.freeze({
    loadFim,
    loadDeviations,
    loadBaselines,
    updateSummaryStats,
    resetFim,
    openDeviationModal,
    closeDeviationModal,
    openBaselineModal,
    closeBaselineModal,
    openVerifyModal,
    closeVerifyModal,
  });

})(typeof window !== 'undefined' ? window : this, typeof document !== 'undefined' ? document : {});
