/**
 * OSIRIS Platform - Resource Charts & Metrics View Controller
 * Phase 1.6 Step 6
 *
 * Responsibilities:
 * - Load and render point-in-time resource snapshots via GET /api/resources.
 * - Manage filter state strictly corresponding to Phase 1.5 API: host_id, start_time, end_time, limit, offset.
 * - Construct sanitized query strings strictly using URLSearchParams.
 * - Manage snapshot selection, time range presets (15m, 1h, 6h, 24h, all), and pagination.
 * - Render compact current-value metric summary cards (CPU, Memory %, Memory Used/Total, Disk Activity, Disk Usage %).
 * - Render native, responsive vector charts (SVG) without any external charting libraries.
 * - Render an accessible companion data table of resource snapshots for screen readers and tabular inspection.
 * - Render dynamic DOM values strictly with createElement/textContent (no raw HTML injection).
 * - Handle loading, empty ("No resource snapshots found matching the selected range."), and error states.
 * - Avoid redundant network requests during rapid tab switches.
 */

(function (window, document) {
  'use strict';

  const DEFAULT_LIMIT = 50;
  const REFRESH_COOLDOWN_MS = 8000;
  const SVG_NS = 'http://www.w3.org/2000/svg';

  // State management
  const state = {
    limit: DEFAULT_LIMIT,
    offset: 0,
    total: 0,
    isLoading: false,
    lastFetchTime: 0,
    hasLoadedOnce: false,
    filters: {
      host_id: '',
      range: 'all',
      start_time: '',
      end_time: '',
    },
    snapshots: [],
  };

  // Cached DOM elements
  let dom = {};

  /**
   * Cache DOM element references for Resource Charts view.
   */
  function cacheElements() {
    dom = {
      // Header controls
      refreshBtn: document.getElementById('resources-refresh-btn'),
      refreshTime: document.getElementById('resources-refresh-time'),

      // Filter controls
      filterForm: document.getElementById('resources-filter-form'),
      inputHostId: document.getElementById('filter-resource-host-id'),
      selectRange: document.getElementById('filter-resource-range'),
      inputStartTime: document.getElementById('filter-resource-start'),
      inputEndTime: document.getElementById('filter-resource-end'),
      selectLimit: document.getElementById('filter-resource-limit'),
      applyFilterBtn: document.getElementById('filter-resource-apply-btn'),
      resetFilterBtn: document.getElementById('filter-resource-reset-btn'),

      // Summary Metric Cards
      summaryCardsContainer: document.getElementById('resources-summary-cards'),
      cardCpu: document.getElementById('res-card-cpu'),
      cardMemory: document.getElementById('res-card-memory'),
      cardMemoryUsed: document.getElementById('res-card-memory-used'),
      cardMemoryTotal: document.getElementById('res-card-memory-total'),
      cardDiskUsage: document.getElementById('res-card-disk-usage'),
      cardDiskRead: document.getElementById('res-card-disk-read'),
      cardDiskWrite: document.getElementById('res-card-disk-write'),
      cardTimestamp: document.getElementById('res-card-timestamp'),

      // State containers
      errorBox: document.getElementById('resources-error-box'),
      emptyState: document.getElementById('resources-empty-state'),
      emptyResetBtn: document.getElementById('resources-empty-reset-btn'),

      // Charts Grid & SVG Containers
      chartsGrid: document.getElementById('resources-charts-grid'),
      cpuCard: document.getElementById('cpu-chart-card'),
      cpuSvgContainer: document.getElementById('cpu-chart-svg-container'),
      memoryCard: document.getElementById('memory-chart-card'),
      memorySvgContainer: document.getElementById('memory-chart-svg-container'),
      diskActivityCard: document.getElementById('disk-activity-chart-card'),
      diskActivitySvgContainer: document.getElementById('disk-activity-chart-svg-container'),
      diskUsageCard: document.getElementById('disk-usage-chart-card'),
      diskUsageSvgContainer: document.getElementById('disk-usage-chart-svg-container'),

      // Accessible Snapshots Table
      tableContainer: document.getElementById('resources-table-container'),
      table: document.getElementById('resources-table'),
      tbody: document.getElementById('resources-tbody'),
      resultCountLabel: document.getElementById('resources-result-count'),

      // Pagination
      paginationToolbar: document.getElementById('resources-pagination'),
      prevBtn: document.getElementById('resources-prev-btn'),
      nextBtn: document.getElementById('resources-next-btn'),
      pageInfo: document.getElementById('resources-page-info'),
    };
  }

  /**
   * Format byte count into human-readable units (B, KB, MB, GB, TB).
   *
   * @param {number|null|undefined} bytes
   * @returns {string}
   */
  function formatBytes(bytes) {
    if (bytes === null || bytes === undefined || isNaN(bytes)) return '-';
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(Math.abs(bytes)) / Math.log(k));
    const idx = Math.min(i, sizes.length - 1);
    const value = bytes / Math.pow(k, idx);
    return `${value.toFixed(idx === 0 ? 0 : 1)} ${sizes[idx]}`;
  }

  /**
   * Format percentage values to one decimal place.
   *
   * @param {number|null|undefined} val
   * @returns {string}
   */
  function formatPercent(val) {
    if (val === null || val === undefined || isNaN(val)) return '-';
    return `${Number(val).toFixed(1)}%`;
  }

  /**
   * Format ISO timestamps for human reading in tables and cards.
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
   * Format ISO timestamp to short time string (HH:MM:SS) for chart axis ticks.
   *
   * @param {string|null} isoString
   * @returns {string}
   */
  function formatTimeShort(isoString) {
    if (!isoString) return '';
    try {
      const d = new Date(isoString);
      if (isNaN(d.getTime())) return '';
      return d.toTimeString().split(' ')[0];
    } catch {
      return '';
    }
  }

  /**
   * Show error box with given message.
   *
   * @param {string} message
   */
  function showError(message) {
    if (dom.errorBox) {
      dom.errorBox.textContent = message;
      dom.errorBox.classList.remove('hidden');
    }
  }

  /**
   * Hide error box.
   */
  function hideError() {
    if (dom.errorBox) {
      dom.errorBox.textContent = '';
      dom.errorBox.classList.add('hidden');
    }
  }

  /**
   * Set loading UI state.
   *
   * @param {boolean} loading
   */
  function setLoading(loading) {
    state.isLoading = loading;

    if (dom.applyFilterBtn) dom.applyFilterBtn.disabled = loading;
    if (dom.resetFilterBtn) dom.resetFilterBtn.disabled = loading;
    if (dom.refreshBtn) dom.refreshBtn.disabled = loading;
    if (dom.prevBtn) dom.prevBtn.disabled = loading;
    if (dom.nextBtn) dom.nextBtn.disabled = loading;

    if (dom.refreshBtn) {
      dom.refreshBtn.textContent = loading ? 'Loading...' : 'Refresh';
    }
  }

  /**
   * Calculate ISO start_time string from range preset, or empty string.
   *
   * @param {string} rangePreset - 'all', '15m', '1h', '6h', '24h'
   * @returns {string}
   */
  function calculateStartTimeFromPreset(rangePreset) {
    const now = Date.now();
    switch (rangePreset) {
      case '15m':
        return new Date(now - 15 * 60 * 1000).toISOString();
      case '1h':
        return new Date(now - 60 * 60 * 1000).toISOString();
      case '6h':
        return new Date(now - 6 * 60 * 60 * 1000).toISOString();
      case '24h':
        return new Date(now - 24 * 60 * 60 * 1000).toISOString();
      case 'all':
      default:
        return '';
    }
  }

  /**
   * Build query string using URLSearchParams adhering strictly to Phase 1.5 contract.
   * Supported: host_id, start_time, end_time, limit, offset.
   *
   * @returns {string}
   */
  function buildQueryString() {
    const params = new URLSearchParams();

    params.set('limit', String(state.limit));
    params.set('offset', String(state.offset));

    if (state.filters.host_id) {
      params.set('host_id', state.filters.host_id.trim());
    }

    // Determine start_time: explicit input takes precedence over range preset
    let startTime = state.filters.start_time ? state.filters.start_time.trim() : '';
    if (!startTime && state.filters.range && state.filters.range !== 'all') {
      startTime = calculateStartTimeFromPreset(state.filters.range);
    }
    if (startTime) {
      params.set('start_time', startTime);
    }

    if (state.filters.end_time) {
      params.set('end_time', state.filters.end_time.trim());
    }

    return params.toString();
  }

  /**
   * Update the latest snapshot metric summary cards.
   *
   * @param {Object|null} snapshot
   */
  function updateSummaryCards(snapshot) {
    if (!snapshot) {
      if (dom.cardCpu) dom.cardCpu.textContent = '--';
      if (dom.cardMemory) dom.cardMemory.textContent = '--';
      if (dom.cardMemoryUsed) dom.cardMemoryUsed.textContent = '--';
      if (dom.cardMemoryTotal) dom.cardMemoryTotal.textContent = '--';
      if (dom.cardDiskUsage) dom.cardDiskUsage.textContent = '--';
      if (dom.cardDiskRead) dom.cardDiskRead.textContent = '--';
      if (dom.cardDiskWrite) dom.cardDiskWrite.textContent = '--';
      if (dom.cardTimestamp) dom.cardTimestamp.textContent = 'No snapshots loaded';
      return;
    }

    if (dom.cardCpu) {
      dom.cardCpu.textContent = formatPercent(snapshot.cpu_percent);
    }
    if (dom.cardMemory) {
      dom.cardMemory.textContent = formatPercent(snapshot.memory_percent);
    }
    if (dom.cardMemoryUsed) {
      dom.cardMemoryUsed.textContent = formatBytes(snapshot.memory_used);
    }
    if (dom.cardMemoryTotal) {
      dom.cardMemoryTotal.textContent = formatBytes(snapshot.memory_total);
    }
    if (dom.cardDiskUsage) {
      dom.cardDiskUsage.textContent = formatPercent(snapshot.disk_usage_percent);
    }
    if (dom.cardDiskRead) {
      dom.cardDiskRead.textContent = formatBytes(snapshot.disk_read_bytes);
    }
    if (dom.cardDiskWrite) {
      dom.cardDiskWrite.textContent = formatBytes(snapshot.disk_write_bytes);
    }
    if (dom.cardTimestamp) {
      dom.cardTimestamp.textContent = `Latest: ${formatTimestamp(snapshot.timestamp)}`;
    }
  }

  /**
   * Clear all children from a DOM container safely without raw HTML injection.
   *
   * @param {HTMLElement} element
   */
  function clearContainer(element) {
    if (!element) return;
    while (element.firstChild) {
      element.removeChild(element.firstChild);
    }
  }

  /**
   * Render a responsive SVG line chart into a target container.
   *
   * @param {HTMLElement} container
   * @param {Object} config
   *   - title: string
   *   - ariaLabel: string
   *   - series: Array<{ name: string, color: string, points: Array<{ x: number, y: number, label: string, time: string }> }>
   *   - yMin: number
   *   - yMax: number
   *   - yTicks: number (number of horizontal grid ticks)
   *   - formatY: function(value: number) => string
   */
  function renderSvgChart(container, config) {
    clearContainer(container);
    if (!container) return;

    const width = 600;
    const height = 220;
    const padding = { top: 20, right: 30, bottom: 35, left: 60 };
    const plotWidth = width - padding.left - padding.right;
    const plotHeight = height - padding.top - padding.bottom;

    const svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
    svg.setAttribute('class', 'resource-chart-svg');
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', config.ariaLabel || config.title);

    // Accessibility metadata
    const titleEl = document.createElementNS(SVG_NS, 'title');
    titleEl.textContent = config.title;
    svg.appendChild(titleEl);

    const descEl = document.createElementNS(SVG_NS, 'desc');
    descEl.textContent = `Time series visualization for ${config.title} with ${state.snapshots.length} observations.`;
    svg.appendChild(descEl);

    // Defs for gradients
    const defs = document.createElementNS(SVG_NS, 'defs');
    config.series.forEach((s, sIdx) => {
      const grad = document.createElementNS(SVG_NS, 'linearGradient');
      const gradId = `grad-${config.id || 'chart'}-${sIdx}`;
      grad.setAttribute('id', gradId);
      grad.setAttribute('x1', '0');
      grad.setAttribute('y1', '0');
      grad.setAttribute('x2', '0');
      grad.setAttribute('y2', '1');

      const stop1 = document.createElementNS(SVG_NS, 'stop');
      stop1.setAttribute('offset', '0%');
      stop1.setAttribute('stop-color', s.color);
      stop1.setAttribute('stop-opacity', '0.28');
      grad.appendChild(stop1);

      const stop2 = document.createElementNS(SVG_NS, 'stop');
      stop2.setAttribute('offset', '100%');
      stop2.setAttribute('stop-color', s.color);
      stop2.setAttribute('stop-opacity', '0.02');
      grad.appendChild(stop2);

      defs.appendChild(grad);
    });
    svg.appendChild(defs);

    // Gridlines and Y-axis scale
    const yMin = config.yMin !== undefined ? config.yMin : 0;
    const yMax = config.yMax > yMin ? config.yMax : yMin + 1;
    const yTickCount = config.yTicks || 4;

    for (let i = 0; i <= yTickCount; i++) {
      const frac = i / yTickCount;
      const yVal = yMin + frac * (yMax - yMin);
      const yPos = padding.top + plotHeight - frac * plotHeight;

      // Horizontal grid line
      const gridLine = document.createElementNS(SVG_NS, 'line');
      gridLine.setAttribute('x1', String(padding.left));
      gridLine.setAttribute('y1', String(yPos));
      gridLine.setAttribute('x2', String(width - padding.right));
      gridLine.setAttribute('y2', String(yPos));
      gridLine.setAttribute('class', 'chart-grid-line');
      svg.appendChild(gridLine);

      // Y-axis label text
      const yText = document.createElementNS(SVG_NS, 'text');
      yText.setAttribute('x', String(padding.left - 8));
      yText.setAttribute('y', String(yPos + 4));
      yText.setAttribute('class', 'chart-axis-text chart-y-label');
      yText.textContent = config.formatY ? config.formatY(yVal) : String(Math.round(yVal));
      svg.appendChild(yText);
    }

    // Baseline axis
    const axisX = document.createElementNS(SVG_NS, 'line');
    axisX.setAttribute('x1', String(padding.left));
    axisX.setAttribute('y1', String(padding.top + plotHeight));
    axisX.setAttribute('x2', String(width - padding.right));
    axisX.setAttribute('y2', String(padding.top + plotHeight));
    axisX.setAttribute('class', 'chart-axis-line');
    svg.appendChild(axisX);

    // Render series paths, areas, and dots
    config.series.forEach((s, sIdx) => {
      if (!s.points || s.points.length === 0) return;

      const numPoints = s.points.length;
      const coords = s.points.map((pt, idx) => {
        const xPos = numPoints === 1
          ? padding.left + plotWidth / 2
          : padding.left + (idx / (numPoints - 1)) * plotWidth;
        const normalizedY = (pt.y - yMin) / (yMax - yMin);
        const clampedY = Math.max(0, Math.min(1, normalizedY));
        const yPos = padding.top + plotHeight - clampedY * plotHeight;
        return { x: xPos, y: yPos, pt };
      });

      // Area path
      if (coords.length > 1) {
        const areaPath = document.createElementNS(SVG_NS, 'path');
        let areaD = `M ${coords[0].x} ${coords[0].y}`;
        for (let i = 1; i < coords.length; i++) {
          areaD += ` L ${coords[i].x} ${coords[i].y}`;
        }
        areaD += ` L ${coords[coords.length - 1].x} ${padding.top + plotHeight}`;
        areaD += ` L ${coords[0].x} ${padding.top + plotHeight} Z`;

        areaPath.setAttribute('d', areaD);
        areaPath.setAttribute('fill', `url(#grad-${config.id || 'chart'}-${sIdx})`);
        areaPath.setAttribute('class', 'chart-area-fill');
        svg.appendChild(areaPath);
      }

      // Line path
      const linePath = document.createElementNS(SVG_NS, 'path');
      let lineD = `M ${coords[0].x} ${coords[0].y}`;
      if (coords.length === 1) {
        // Draw small horizontal marker segment for single point
        lineD = `M ${coords[0].x - 15} ${coords[0].y} L ${coords[0].x + 15} ${coords[0].y}`;
      } else {
        for (let i = 1; i < coords.length; i++) {
          lineD += ` L ${coords[i].x} ${coords[i].y}`;
        }
      }
      linePath.setAttribute('d', lineD);
      linePath.setAttribute('fill', 'none');
      linePath.setAttribute('stroke', s.color);
      linePath.setAttribute('stroke-width', '2.5');
      linePath.setAttribute('stroke-linejoin', 'round');
      linePath.setAttribute('stroke-linecap', 'round');
      svg.appendChild(linePath);

      // Data point dots with tooltips
      coords.forEach((c) => {
        const circle = document.createElementNS(SVG_NS, 'circle');
        circle.setAttribute('cx', String(c.x));
        circle.setAttribute('cy', String(c.y));
        circle.setAttribute('r', '4');
        circle.setAttribute('fill', s.color);
        circle.setAttribute('stroke', '#0d1117');
        circle.setAttribute('stroke-width', '1.5');
        circle.setAttribute('class', 'chart-point');

        const tip = document.createElementNS(SVG_NS, 'title');
        tip.textContent = `${s.name}: ${c.pt.label} (${c.pt.time})`;
        circle.appendChild(tip);

        svg.appendChild(circle);
      });
    });

    // X-axis time ticks
    if (config.series[0] && config.series[0].points.length > 0) {
      const pts = config.series[0].points;
      const numPoints = pts.length;
      const tickIndices = [];

      if (numPoints <= 4) {
        for (let i = 0; i < numPoints; i++) tickIndices.push(i);
      } else {
        tickIndices.push(0);
        tickIndices.push(Math.floor((numPoints - 1) * 0.33));
        tickIndices.push(Math.floor((numPoints - 1) * 0.66));
        tickIndices.push(numPoints - 1);
      }

      tickIndices.forEach((idx) => {
        const pt = pts[idx];
        const xPos = numPoints === 1
          ? padding.left + plotWidth / 2
          : padding.left + (idx / (numPoints - 1)) * plotWidth;

        const xText = document.createElementNS(SVG_NS, 'text');
        xText.setAttribute('x', String(xPos));
        xText.setAttribute('y', String(height - 10));
        xText.setAttribute('class', 'chart-axis-text chart-x-label');
        xText.textContent = formatTimeShort(pt.time);
        svg.appendChild(xText);
      });
    }

    container.appendChild(svg);
  }

  /**
   * Render all 4 native resource charts from the current snapshot set.
   *
   * @param {Array<Object>} snapshots - Chronologically sorted snapshot records
   */
  function renderAllCharts(snapshots) {
    if (!snapshots || snapshots.length === 0) {
      clearContainer(dom.cpuSvgContainer);
      clearContainer(dom.memorySvgContainer);
      clearContainer(dom.diskActivitySvgContainer);
      clearContainer(dom.diskUsageSvgContainer);
      return;
    }

    // 1. CPU Utilization Chart (0-100%)
    if (dom.cpuSvgContainer) {
      renderSvgChart(dom.cpuSvgContainer, {
        id: 'cpu',
        title: 'CPU Utilization (%)',
        ariaLabel: 'CPU Utilization percentage over time',
        yMin: 0,
        yMax: 100,
        yTicks: 4,
        formatY: (v) => `${Math.round(v)}%`,
        series: [
          {
            name: 'CPU Utilization',
            color: '#388bfd',
            points: snapshots.map((s) => ({
              x: 0,
              y: s.cpu_percent !== null && s.cpu_percent !== undefined ? s.cpu_percent : 0,
              label: formatPercent(s.cpu_percent),
              time: s.timestamp,
            })),
          },
        ],
      });
    }

    // 2. Memory Utilization Chart (0-100%)
    if (dom.memorySvgContainer) {
      renderSvgChart(dom.memorySvgContainer, {
        id: 'mem',
        title: 'Memory Utilization (%)',
        ariaLabel: 'Memory Utilization percentage over time',
        yMin: 0,
        yMax: 100,
        yTicks: 4,
        formatY: (v) => `${Math.round(v)}%`,
        series: [
          {
            name: 'Memory Utilization',
            color: '#a371f7',
            points: snapshots.map((s) => ({
              x: 0,
              y: s.memory_percent !== null && s.memory_percent !== undefined ? s.memory_percent : 0,
              label: `${formatPercent(s.memory_percent)} (${formatBytes(s.memory_used)} / ${formatBytes(s.memory_total)})`,
              time: s.timestamp,
            })),
          },
        ],
      });
    }

    // 3. Disk Activity Chart (Read & Write Bytes)
    if (dom.diskActivitySvgContainer) {
      let maxBytes = 1024; // baseline 1KB
      snapshots.forEach((s) => {
        if (s.disk_read_bytes && s.disk_read_bytes > maxBytes) maxBytes = s.disk_read_bytes;
        if (s.disk_write_bytes && s.disk_write_bytes > maxBytes) maxBytes = s.disk_write_bytes;
      });

      renderSvgChart(dom.diskActivitySvgContainer, {
        id: 'disk-act',
        title: 'Disk Read & Write Activity (Bytes)',
        ariaLabel: 'Disk read and write activity bytes over time',
        yMin: 0,
        yMax: maxBytes * 1.1,
        yTicks: 4,
        formatY: (v) => formatBytes(v),
        series: [
          {
            name: 'Disk Read',
            color: '#3fb950',
            points: snapshots.map((s) => ({
              x: 0,
              y: s.disk_read_bytes !== null && s.disk_read_bytes !== undefined ? s.disk_read_bytes : 0,
              label: formatBytes(s.disk_read_bytes),
              time: s.timestamp,
            })),
          },
          {
            name: 'Disk Write',
            color: '#d29922',
            points: snapshots.map((s) => ({
              x: 0,
              y: s.disk_write_bytes !== null && s.disk_write_bytes !== undefined ? s.disk_write_bytes : 0,
              label: formatBytes(s.disk_write_bytes),
              time: s.timestamp,
            })),
          },
        ],
      });
    }

    // 4. Disk Usage Chart (0-100%)
    if (dom.diskUsageSvgContainer) {
      renderSvgChart(dom.diskUsageSvgContainer, {
        id: 'disk-use',
        title: 'Disk Usage (%)',
        ariaLabel: 'Disk storage usage percentage over time',
        yMin: 0,
        yMax: 100,
        yTicks: 4,
        formatY: (v) => `${Math.round(v)}%`,
        series: [
          {
            name: 'Disk Usage',
            color: '#2ea043',
            points: snapshots.map((s) => ({
              x: 0,
              y: s.disk_usage_percent !== null && s.disk_usage_percent !== undefined ? s.disk_usage_percent : 0,
              label: formatPercent(s.disk_usage_percent),
              time: s.timestamp,
            })),
          },
        ],
      });
    }
  }

  /**
   * Render accessible table rows for resource snapshots.
   *
   * @param {Array<Object>} snapshots
   */
  function renderSnapshotsTable(snapshots) {
    if (!dom.tbody) return;
    clearContainer(dom.tbody);

    snapshots.forEach((snap) => {
      const row = document.createElement('tr');

      // Timestamp
      const tdTime = document.createElement('td');
      tdTime.className = 'mono-cell';
      tdTime.textContent = formatTimestamp(snap.timestamp);
      row.appendChild(tdTime);

      // CPU %
      const tdCpu = document.createElement('td');
      tdCpu.className = 'mono-cell';
      tdCpu.textContent = formatPercent(snap.cpu_percent);
      row.appendChild(tdCpu);

      // Memory %
      const tdMemPct = document.createElement('td');
      tdMemPct.className = 'mono-cell';
      tdMemPct.textContent = formatPercent(snap.memory_percent);
      row.appendChild(tdMemPct);

      // Memory Used
      const tdMemUsed = document.createElement('td');
      tdMemUsed.className = 'mono-cell';
      tdMemUsed.textContent = formatBytes(snap.memory_used);
      row.appendChild(tdMemUsed);

      // Memory Total
      const tdMemTotal = document.createElement('td');
      tdMemTotal.className = 'mono-cell';
      tdMemTotal.textContent = formatBytes(snap.memory_total);
      row.appendChild(tdMemTotal);

      // Disk Read
      const tdDiskRead = document.createElement('td');
      tdDiskRead.className = 'mono-cell';
      tdDiskRead.textContent = formatBytes(snap.disk_read_bytes);
      row.appendChild(tdDiskRead);

      // Disk Write
      const tdDiskWrite = document.createElement('td');
      tdDiskWrite.className = 'mono-cell';
      tdDiskWrite.textContent = formatBytes(snap.disk_write_bytes);
      row.appendChild(tdDiskWrite);

      // Disk Usage %
      const tdDiskUse = document.createElement('td');
      tdDiskUse.className = 'mono-cell';
      tdDiskUse.textContent = formatPercent(snap.disk_usage_percent);
      row.appendChild(tdDiskUse);

      dom.tbody.appendChild(row);
    });
  }

  /**
   * Update pagination controls and info label.
   */
  function updatePaginationControls() {
    const total = state.total;
    const offset = state.offset;
    const limit = state.limit;

    if (dom.resultCountLabel) {
      dom.resultCountLabel.textContent = `${total} snapshot${total === 1 ? '' : 's'}`;
    }

    if (dom.pageInfo) {
      if (total === 0) {
        dom.pageInfo.textContent = 'Showing 0–0 of 0 snapshots';
      } else {
        const start = offset + 1;
        const end = Math.min(offset + limit, total);
        dom.pageInfo.textContent = `Showing ${start}–${end} of ${total} snapshots`;
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
   * Update UI visibility based on whether items exist.
   *
   * @param {boolean} hasItems
   */
  function updateViewVisibility(hasItems) {
    if (hasItems) {
      if (dom.emptyState) dom.emptyState.classList.add('hidden');
      if (dom.chartsGrid) dom.chartsGrid.classList.remove('hidden');
      if (dom.tableContainer) dom.tableContainer.classList.remove('hidden');
      if (dom.paginationToolbar) dom.paginationToolbar.classList.remove('hidden');
    } else {
      if (dom.emptyState) dom.emptyState.classList.remove('hidden');
      if (dom.chartsGrid) dom.chartsGrid.classList.add('hidden');
      if (dom.tableContainer) dom.tableContainer.classList.add('hidden');
      if (dom.paginationToolbar) dom.paginationToolbar.classList.add('hidden');
    }
  }

  /**
   * Fetch resource snapshots from backend API.
   *
   * @param {boolean} force - Force request bypassing cooldown
   */
  async function fetchResources(force) {
    if (!window.OsirisApi || typeof window.OsirisApi.fetchWithAuth !== 'function') {
      showError('Osiris API helper not available.');
      return;
    }

    const token = window.OsirisApi.getToken();
    if (!token) {
      showError('Authentication required to view resource telemetry.');
      return;
    }

    const now = Date.now();
    if (!force && state.hasLoadedOnce && now - state.lastFetchTime < REFRESH_COOLDOWN_MS) {
      return;
    }

    hideError();
    setLoading(true);

    try {
      const queryString = buildQueryString();
      const endpoint = `/api/resources?${queryString}`;
      const data = await window.OsirisApi.fetchWithAuth(endpoint);

      state.lastFetchTime = Date.now();
      state.hasLoadedOnce = true;
      state.total = (data && typeof data.total === 'number') ? data.total : 0;
      state.snapshots = (data && Array.isArray(data.items)) ? data.items : [];

      if (dom.refreshTime) {
        dom.refreshTime.textContent = `Updated: ${new Date().toLocaleTimeString()}`;
      }

      if (state.snapshots.length > 0) {
        // Latest snapshot is the last one in ascending time order
        const latest = state.snapshots[state.snapshots.length - 1];
        updateSummaryCards(latest);
        renderAllCharts(state.snapshots);
        renderSnapshotsTable(state.snapshots);
        updateViewVisibility(true);
      } else {
        updateSummaryCards(null);
        renderAllCharts([]);
        renderSnapshotsTable([]);
        updateViewVisibility(false);
      }

      updatePaginationControls();
    } catch (err) {
      showError(err.message || 'Failed to load resource snapshots.');
    } finally {
      setLoading(false);
    }
  }

  /**
   * Primary entry point to load or refresh resource metrics.
   *
   * @param {boolean} [force=false]
   */
  function loadResources(force) {
    fetchResources(Boolean(force));
  }

  /**
   * Reset resource view state to initial unauthenticated/clean state.
   */
  function resetResources() {
    state.limit = DEFAULT_LIMIT;
    state.offset = 0;
    state.total = 0;
    state.isLoading = false;
    state.lastFetchTime = 0;
    state.hasLoadedOnce = false;
    state.filters = {
      host_id: '',
      range: 'all',
      start_time: '',
      end_time: '',
    };
    state.snapshots = [];

    hideError();
    updateSummaryCards(null);
    renderAllCharts([]);
    renderSnapshotsTable([]);

    if (dom.filterForm) dom.filterForm.reset();
    if (dom.refreshTime) dom.refreshTime.textContent = '';
    updatePaginationControls();
    updateViewVisibility(false);
  }

  /**
   * Handle filter form submission.
   *
   * @param {Event} e
   */
  function handleFilterSubmit(e) {
    if (e) e.preventDefault();

    state.filters.host_id = dom.inputHostId ? dom.inputHostId.value.trim() : '';
    state.filters.range = dom.selectRange ? dom.selectRange.value : 'all';
    state.filters.start_time = dom.inputStartTime ? dom.inputStartTime.value.trim() : '';
    state.filters.end_time = dom.inputEndTime ? dom.inputEndTime.value.trim() : '';

    const limitVal = dom.selectLimit ? parseInt(dom.selectLimit.value, 10) : DEFAULT_LIMIT;
    state.limit = isNaN(limitVal) || limitVal < 1 ? DEFAULT_LIMIT : limitVal;
    state.offset = 0;

    fetchResources(true);
  }

  /**
   * Handle filter reset button click.
   */
  function handleFilterReset() {
    if (dom.filterForm) dom.filterForm.reset();

    state.filters = {
      host_id: '',
      range: 'all',
      start_time: '',
      end_time: '',
    };
    state.limit = DEFAULT_LIMIT;
    state.offset = 0;

    fetchResources(true);
  }

  /**
   * Handle previous page button click.
   */
  function handlePreviousPage() {
    if (state.offset > 0) {
      state.offset = Math.max(0, state.offset - state.limit);
      fetchResources(true);
    }
  }

  /**
   * Handle next page button click.
   */
  function handleNextPage() {
    if (state.offset + state.limit < state.total) {
      state.offset += state.limit;
      fetchResources(true);
    }
  }

  /**
   * Bind event listeners for resources view controls.
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
      dom.refreshBtn.addEventListener('click', () => fetchResources(true));
    }

    if (dom.prevBtn) {
      dom.prevBtn.addEventListener('click', handlePreviousPage);
    }

    if (dom.nextBtn) {
      dom.nextBtn.addEventListener('click', handleNextPage);
    }
  }

  /**
   * Initialize Resource Charts view.
   */
  function initResources() {
    cacheElements();
    bindEvents();
  }

  // Initialize when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initResources);
  } else {
    initResources();
  }

  // Export controller to window
  window.OsirisResources = Object.freeze({
    initResources,
    loadResources,
    resetResources,
    formatBytes,
    formatPercent,
  });

})(typeof window !== 'undefined' ? window : this, typeof document !== 'undefined' ? document : {});
