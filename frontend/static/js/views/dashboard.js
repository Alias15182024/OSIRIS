/**
 * OSIRIS Platform - Dashboard Overview View Controller
 * Phase 1.6 Step 3
 *
 * Responsibilities:
 * - Load and render platform system status via /api/status.
 * - Load and render latest point-in-time resource snapshot via /api/resources?limit=1.
 * - Load and render inventory counters via /api/events?limit=1, /api/processes?is_active=true&limit=1, /api/files?limit=1.
 * - Load and render recent events table via /api/events?limit=5.
 * - Handle graceful partial failures per card without breaking sibling sections.
 * - Safe DOM updates via textContent and createElement (strictly textContent, no unescaped injection).
 * - Anti-flood throttling/refresh mechanism.
 */

(function (window, document) {
  'use strict';

  // Throttling and state tracking
  let lastLoadedTime = 0;
  let isLoading = false;
  const REFRESH_COOLDOWN_MS = 15000; // 15-second cache window unless explicitly refreshed

  // DOM Elements cache
  let dom = {};

  /**
   * Cache DOM references for dashboard components.
   */
  function cacheElements() {
    dom = {
      // Header actions
      refreshBtn: document.getElementById('dashboard-refresh-btn'),
      refreshTimeLabel: document.getElementById('dashboard-refresh-time'),

      // Status card
      systemStatusBadge: document.getElementById('system-status-badge'),
      statusHostId: document.getElementById('status-host-id'),
      statusSystem: document.getElementById('status-system'),
      systemDbBadge: document.getElementById('system-db-badge'),
      statusOperational: document.getElementById('status-operational'),
      statusCardError: document.getElementById('status-card-error'),

      // Resource card
      resSnapshotTime: document.getElementById('resource-snapshot-time'),
      resCpuPercent: document.getElementById('res-cpu-percent'),
      resMemoryPercent: document.getElementById('res-memory-percent'),
      resMemoryUsed: document.getElementById('res-memory-used'),
      resMemoryTotal: document.getElementById('res-memory-total'),
      resDiskUsage: document.getElementById('res-disk-usage'),
      resourceCardError: document.getElementById('resource-card-error'),

      // Inventory counters
      invEventsCount: document.getElementById('inv-events-count'),
      invProcessesCount: document.getElementById('inv-processes-count'),
      invFilesCount: document.getElementById('inv-files-count'),

      // Recent events card
      recentEventsTable: document.getElementById('dashboard-recent-events-table'),
      recentEventsTbody: document.getElementById('dashboard-recent-events-tbody'),
      recentEventsEmpty: document.getElementById('dashboard-recent-events-empty'),
      recentEventsCountBadge: document.getElementById('recent-events-count-badge'),
      recentEventsError: document.getElementById('dashboard-recent-events-error'),
    };
  }

  /**
   * Format floating point percentages safely.
   *
   * @param {number|null} value
   * @returns {string}
   */
  function formatPercent(value) {
    if (value === null || value === undefined || typeof value !== 'number' || isNaN(value)) {
      return 'Unavailable';
    }
    return `${value.toFixed(1)}%`;
  }

  /**
   * Format raw byte counts into human-readable units (MB / GB).
   *
   * @param {number|null} bytes
   * @returns {string}
   */
  function formatBytes(bytes) {
    if (bytes === null || bytes === undefined || typeof bytes !== 'number' || isNaN(bytes)) {
      return 'Unavailable';
    }
    if (bytes <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    const val = (bytes / Math.pow(1024, i)).toFixed(2);
    return `${val} ${units[i]}`;
  }

  /**
   * Format an ISO datetime string for display.
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
   * Determine CSS badge class based on event severity.
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
   * Load and render platform system status from /api/status.
   */
  async function loadStatus() {
    if (dom.statusCardError) dom.statusCardError.classList.add('hidden');
    try {
      const data = await window.OsirisApi.getStatus();
      if (!data) throw new Error('Status payload empty');

      if (dom.statusHostId) dom.statusHostId.textContent = data.host_id || 'Unavailable';
      if (dom.statusSystem) dom.statusSystem.textContent = data.system || 'Unavailable';

      const dbConnected = data.database === 'connected';
      if (dom.systemDbBadge) {
        dom.systemDbBadge.textContent = dbConnected ? 'Connected' : (data.database === 'disconnected' ? 'Disconnected' : 'Unavailable');
        dom.systemDbBadge.className = 'badge ' + (dbConnected ? 'badge-success' : 'badge-danger');
      }

      const isHealthy = data.status === 'healthy';
      if (dom.statusOperational) {
        dom.statusOperational.textContent = isHealthy ? 'Operational' : (data.status || 'Unavailable');
      }
      if (dom.systemStatusBadge) {
        dom.systemStatusBadge.textContent = isHealthy ? 'Healthy' : 'Degraded';
        dom.systemStatusBadge.className = 'badge ' + (isHealthy ? 'badge-success' : 'badge-warning');
      }
    } catch {
      if (dom.statusHostId) dom.statusHostId.textContent = 'Unavailable';
      if (dom.statusSystem) dom.statusSystem.textContent = 'Unavailable';
      if (dom.statusOperational) dom.statusOperational.textContent = 'Unavailable';
      if (dom.systemDbBadge) {
        dom.systemDbBadge.textContent = 'Unavailable';
        dom.systemDbBadge.className = 'badge badge-outline';
      }
      if (dom.systemStatusBadge) {
        dom.systemStatusBadge.textContent = 'Unavailable';
        dom.systemStatusBadge.className = 'badge badge-danger';
      }
      if (dom.statusCardError) {
        dom.statusCardError.textContent = 'System status is currently unavailable.';
        dom.statusCardError.classList.remove('hidden');
      }
    }
  }

  /**
   * Set resource metric elements to an explicit Unavailable state.
   */
  function setResourceUnavailable() {
    if (dom.resCpuPercent) dom.resCpuPercent.textContent = 'Unavailable';
    if (dom.resMemoryPercent) dom.resMemoryPercent.textContent = 'Unavailable';
    if (dom.resMemoryUsed) dom.resMemoryUsed.textContent = 'Unavailable';
    if (dom.resMemoryTotal) dom.resMemoryTotal.textContent = 'Unavailable';
    if (dom.resDiskUsage) dom.resDiskUsage.textContent = 'Unavailable';
    if (dom.resSnapshotTime) dom.resSnapshotTime.textContent = '';
  }

  /**
   * Load and render latest point-in-time resource snapshot from /api/resources?limit=1.
   */
  async function loadResources() {
    if (dom.resourceCardError) dom.resourceCardError.classList.add('hidden');
    try {
      const data = await window.OsirisApi.fetchWithAuth('/api/resources?limit=1');
      if (!data || !Array.isArray(data.items) || data.items.length === 0) {
        setResourceUnavailable();
        return;
      }

      const snapshot = data.items[0];
      if (dom.resCpuPercent) dom.resCpuPercent.textContent = formatPercent(snapshot.cpu_percent);
      if (dom.resMemoryPercent) dom.resMemoryPercent.textContent = formatPercent(snapshot.memory_percent);
      if (dom.resMemoryUsed) dom.resMemoryUsed.textContent = formatBytes(snapshot.memory_used);
      if (dom.resMemoryTotal) dom.resMemoryTotal.textContent = formatBytes(snapshot.memory_total);
      if (dom.resDiskUsage) dom.resDiskUsage.textContent = formatPercent(snapshot.disk_usage_percent);
      if (dom.resSnapshotTime && snapshot.timestamp) {
        dom.resSnapshotTime.textContent = formatTimestamp(snapshot.timestamp);
      }
    } catch {
      setResourceUnavailable();
      if (dom.resourceCardError) {
        dom.resourceCardError.textContent = 'Resource telemetry is currently unavailable.';
        dom.resourceCardError.classList.remove('hidden');
      }
    }
  }

  /**
   * Load and render observational inventory counters via paginated totals.
   */
  async function loadInventoryCounters() {
    const [eventsResult, processesResult, filesResult] = await Promise.allSettled([
      window.OsirisApi.fetchWithAuth('/api/events?limit=1'),
      window.OsirisApi.fetchWithAuth('/api/processes?is_active=true&limit=1'),
      window.OsirisApi.fetchWithAuth('/api/files?limit=1'),
    ]);

    // Total events counter
    if (dom.invEventsCount) {
      if (eventsResult.status === 'fulfilled' && eventsResult.value && typeof eventsResult.value.total === 'number') {
        dom.invEventsCount.textContent = eventsResult.value.total.toLocaleString();
      } else {
        dom.invEventsCount.textContent = 'Unavailable';
      }
    }

    // Active processes counter
    if (dom.invProcessesCount) {
      if (processesResult.status === 'fulfilled' && processesResult.value && typeof processesResult.value.total === 'number') {
        dom.invProcessesCount.textContent = processesResult.value.total.toLocaleString();
      } else {
        dom.invProcessesCount.textContent = 'Unavailable';
      }
    }

    // Observed files counter
    if (dom.invFilesCount) {
      if (filesResult.status === 'fulfilled' && filesResult.value && typeof filesResult.value.total === 'number') {
        dom.invFilesCount.textContent = filesResult.value.total.toLocaleString();
      } else {
        dom.invFilesCount.textContent = 'Unavailable';
      }
    }
  }

  /**
   * Clear all rendered rows from the recent events table body.
   */
  function clearRecentEventsTable() {
    if (!dom.recentEventsTbody) return;
    while (dom.recentEventsTbody.firstChild) {
      dom.recentEventsTbody.removeChild(dom.recentEventsTbody.firstChild);
    }
  }

  /**
   * Render recent events into the dashboard data table.
   *
   * @param {Array<Object>} items
   */
  function renderRecentEvents(items) {
    clearRecentEventsTable();

    if (dom.recentEventsCountBadge) {
      dom.recentEventsCountBadge.textContent = `${items.length} event${items.length === 1 ? '' : 's'}`;
    }

    if (items.length === 0) {
      if (dom.recentEventsEmpty) dom.recentEventsEmpty.classList.remove('hidden');
      if (dom.recentEventsTable) dom.recentEventsTable.classList.add('hidden');
      return;
    }

    if (dom.recentEventsEmpty) dom.recentEventsEmpty.classList.add('hidden');
    if (dom.recentEventsTable) dom.recentEventsTable.classList.remove('hidden');

    items.forEach((event) => {
      const tr = document.createElement('tr');

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
      const tdSev = document.createElement('td');
      const badge = document.createElement('span');
      badge.className = `badge ${getSeverityBadgeClass(event.severity)}`;
      badge.textContent = (event.severity || 'UNKNOWN').toUpperCase();
      tdSev.appendChild(badge);
      tr.appendChild(tdSev);

      // 5. Action
      const tdAction = document.createElement('td');
      tdAction.textContent = event.action || '-';
      tr.appendChild(tdAction);

      // 6. Username
      const tdUser = document.createElement('td');
      tdUser.textContent = event.username || '-';
      tr.appendChild(tdUser);

      // 7. PID
      const tdPid = document.createElement('td');
      tdPid.className = 'mono-cell';
      tdPid.textContent = (event.pid !== null && event.pid !== undefined) ? String(event.pid) : '-';
      tr.appendChild(tdPid);

      dom.recentEventsTbody.appendChild(tr);
    });
  }

  /**
   * Load and render recent events from /api/events?limit=5.
   */
  async function loadRecentEvents() {
    if (dom.recentEventsError) dom.recentEventsError.classList.add('hidden');
    try {
      const data = await window.OsirisApi.fetchWithAuth('/api/events?limit=5');
      if (!data || !Array.isArray(data.items)) {
        throw new Error('Invalid events response');
      }

      renderRecentEvents(data.items);
    } catch {
      clearRecentEventsTable();
      if (dom.recentEventsEmpty) dom.recentEventsEmpty.classList.add('hidden');
      if (dom.recentEventsError) {
        dom.recentEventsError.textContent = 'Recent events are currently unavailable.';
        dom.recentEventsError.classList.remove('hidden');
      }
      if (dom.recentEventsCountBadge) dom.recentEventsCountBadge.textContent = 'Unavailable';
    }
  }

  /**
   * Coordinate loading all dashboard sections.
   *
   * @param {Object} [options={}]
   * @param {boolean} [options.force=false]
   */
  async function loadDashboard(options = {}) {
    const force = options && options.force === true;

    // Check that user is authenticated before calling protected API endpoints
    if (!window.OsirisApi || !window.OsirisApi.getToken()) {
      return;
    }

    const now = Date.now();
    if (!force && lastLoadedTime > 0 && (now - lastLoadedTime < REFRESH_COOLDOWN_MS)) {
      return;
    }

    if (isLoading) return;
    isLoading = true;

    if (dom.refreshBtn) {
      dom.refreshBtn.disabled = true;
      dom.refreshBtn.textContent = 'Refreshing...';
    }

    try {
      await Promise.allSettled([
        loadStatus(),
        loadResources(),
        loadInventoryCounters(),
        loadRecentEvents(),
      ]);

      lastLoadedTime = Date.now();
      if (dom.refreshTimeLabel) {
        dom.refreshTimeLabel.textContent = `Updated ${new Date().toLocaleTimeString()}`;
      }
    } finally {
      isLoading = false;
      if (dom.refreshBtn) {
        dom.refreshBtn.disabled = false;
        dom.refreshBtn.textContent = 'Refresh';
      }
    }
  }

  /**
   * Reset all dashboard metrics to blank/placeholder values on logout.
   */
  function resetDashboard() {
    lastLoadedTime = 0;
    if (dom.refreshTimeLabel) dom.refreshTimeLabel.textContent = '';
    if (dom.statusHostId) dom.statusHostId.textContent = '--';
    if (dom.statusSystem) dom.statusSystem.textContent = '--';
    if (dom.statusOperational) dom.statusOperational.textContent = '--';
    if (dom.systemDbBadge) {
      dom.systemDbBadge.textContent = '--';
      dom.systemDbBadge.className = 'badge badge-outline';
    }
    if (dom.systemStatusBadge) {
      dom.systemStatusBadge.textContent = 'Checking...';
      dom.systemStatusBadge.className = 'badge badge-outline';
    }
    setResourceUnavailable();
    if (dom.invEventsCount) dom.invEventsCount.textContent = '--';
    if (dom.invProcessesCount) dom.invProcessesCount.textContent = '--';
    if (dom.invFilesCount) dom.invFilesCount.textContent = '--';
    clearRecentEventsTable();
    if (dom.recentEventsEmpty) dom.recentEventsEmpty.classList.add('hidden');
    if (dom.recentEventsCountBadge) dom.recentEventsCountBadge.textContent = '0 events';
  }

  /**
   * Initialize DOM references and event listeners.
   */
  function initDashboard() {
    cacheElements();
    if (dom.refreshBtn) {
      dom.refreshBtn.addEventListener('click', () => {
        loadDashboard({ force: true });
      });
    }
  }

  // Initialize when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initDashboard);
  } else {
    initDashboard();
  }

  // Export view controller
  window.OsirisDashboard = Object.freeze({
    initDashboard,
    loadDashboard,
    resetDashboard,
  });

})(typeof window !== 'undefined' ? window : this, typeof document !== 'undefined' ? document : {});
