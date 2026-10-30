/**
 * OSIRIS Platform - Security Incident Lifecycle & Case Management View Controller
 * Phase 2 Milestone 2.6
 *
 * Responsibilities:
 * - Load and render paginated security incidents via GET /api/incidents.
 * - Manage filter state: host_id, severity, status, category.
 * - Manage pagination state with boundary protections (PAGE_SIZE = 25).
 * - Render incident detail & investigation inspector modal via GET /api/incidents/{incident_id}.
 * - Render dynamic DOM values strictly with createElement/textContent (no raw HTML injection).
 * - Handle lifecycle status transitions via POST /api/incidents/{incident_id}/status.
 * - Handle severity adjustments via POST /api/incidents/{incident_id}/severity.
 * - Handle investigation notes via POST /api/incidents/{incident_id}/notes.
 * - Handle forensic report export in JSON and Markdown via GET /api/incidents/{incident_id}/report.
 * - Handle manual incident creation via POST /api/incidents.
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
    selectedIncidentId: null,
    filters: {
      host_id: '',
      severity: '',
      status: '',
      category: '',
    },
  };

  // Cached DOM elements
  let dom = {};

  function cacheElements() {
    dom = {
      // Filter form & inputs
      filterForm: document.getElementById('incidents-filter-form'),
      inputHostId: document.getElementById('filter-incident-host-id'),
      selectSeverity: document.getElementById('filter-incident-severity'),
      selectStatus: document.getElementById('filter-incident-status'),
      inputCategory: document.getElementById('filter-incident-category'),
      btnApply: document.getElementById('incidents-filter-apply-btn'),
      btnReset: document.getElementById('incidents-filter-reset-btn'),

      // Summary stat counters
      statOpen: document.getElementById('incident-stat-open'),
      statInvestigating: document.getElementById('incident-stat-investigating'),
      statContained: document.getElementById('incident-stat-contained'),
      statResolved: document.getElementById('incident-stat-resolved'),
      statClosed: document.getElementById('incident-stat-closed'),

      // Header actions & badges
      btnCreateTrigger: document.getElementById('incident-create-trigger-btn'),
      btnRefresh: document.getElementById('incidents-refresh-btn'),
      refreshTime: document.getElementById('incidents-refresh-time'),
      totalBadge: document.getElementById('incidents-total-badge'),
      navBadge: document.getElementById('nav-incidents-badge'),

      // Table states
      tbody: document.getElementById('incidents-tbody'),
      loadingIndicator: document.getElementById('incidents-loading'),
      emptyState: document.getElementById('incidents-empty-state'),
      errorBox: document.getElementById('incidents-error'),

      // Pagination controls
      btnPrev: document.getElementById('incidents-prev-btn'),
      btnNext: document.getElementById('incidents-next-btn'),
      pageInfo: document.getElementById('incidents-page-info'),

      // Detail Modal
      detailModal: document.getElementById('incident-detail-modal'),
      detailModalCloseBtn: document.getElementById('incident-modal-close'),
      detailTitle: document.getElementById('detail-incident-title'),
      detailSeverity: document.getElementById('detail-incident-severity'),
      detailStatus: document.getElementById('detail-incident-status'),
      detailCategory: document.getElementById('detail-incident-category'),
      detailHost: document.getElementById('detail-incident-host'),
      detailAssigned: document.getElementById('detail-incident-assigned'),
      detailCreated: document.getElementById('detail-incident-created'),
      detailObserved: document.getElementById('detail-incident-observed'),
      detailDescription: document.getElementById('detail-incident-description'),
      detailContainment: document.getElementById('detail-incident-containment'),
      detailResolution: document.getElementById('detail-incident-resolution'),
      detailClosure: document.getElementById('detail-incident-closure'),

      // Lifecycle controls in modal
      statusForm: document.getElementById('incident-status-form'),
      selectNewStatus: document.getElementById('incident-new-status'),
      inputTransitionNotes: document.getElementById('incident-transition-notes'),
      btnTransitionSubmit: document.getElementById('incident-transition-submit-btn'),

      severityForm: document.getElementById('incident-severity-form'),
      selectNewSeverity: document.getElementById('incident-new-severity'),
      inputSeverityReason: document.getElementById('incident-severity-reason'),
      checkAllowDowngrade: document.getElementById('incident-allow-downgrade'),
      btnSeveritySubmit: document.getElementById('incident-severity-submit-btn'),

      btnExportJson: document.getElementById('incident-export-json-btn'),
      btnExportMd: document.getElementById('incident-export-md-btn'),

      // Sub-lists in modal
      detectionsList: document.getElementById('incident-detail-detections-list'),
      fimList: document.getElementById('incident-detail-fim-list'),
      sessionsList: document.getElementById('incident-detail-sessions-list'),
      evidenceList: document.getElementById('incident-detail-evidence-list'),
      eventsList: document.getElementById('incident-detail-events-list'),
      timelineList: document.getElementById('incident-detail-timeline-list'),
      historyList: document.getElementById('incident-detail-history-list'),

      // Add Note in modal
      addNoteForm: document.getElementById('incident-add-note-form'),
      inputNewNote: document.getElementById('incident-new-note-text'),
      btnAddNote: document.getElementById('incident-add-note-btn'),

      // Create Modal
      createModal: document.getElementById('incident-create-modal'),
      createModalCloseBtn: document.getElementById('incident-create-modal-close'),
      createForm: document.getElementById('incident-create-form'),
      inputCreateTitle: document.getElementById('create-incident-title'),
      inputCreateDesc: document.getElementById('create-incident-description'),
      selectCreateSeverity: document.getElementById('create-incident-severity'),
      inputCreateCategory: document.getElementById('create-incident-category'),
      inputCreateHostId: document.getElementById('create-incident-host-id'),
      createErrorBox: document.getElementById('incident-create-error'),
      btnCreateSubmit: document.getElementById('incident-create-submit-btn'),
    };
  }

  function getSeverityBadgeClass(severity) {
    const s = String(severity || '').toLowerCase();
    switch (s) {
      case 'critical': return 'badge badge-danger';
      case 'high': return 'badge badge-warning';
      case 'medium': return 'badge badge-info';
      case 'low': return 'badge badge-secondary';
      case 'info': return 'badge badge-light';
      default: return 'badge badge-secondary';
    }
  }

  function getStatusBadgeClass(status) {
    const s = String(status || '').toLowerCase();
    switch (s) {
      case 'open': return 'badge badge-danger';
      case 'investigating': return 'badge badge-warning';
      case 'contained': return 'badge badge-info';
      case 'resolved': return 'badge badge-success';
      case 'closed': return 'badge badge-secondary';
      default: return 'badge badge-secondary';
    }
  }

  function formatDate(isoStr) {
    if (!isoStr) return 'N/A';
    try {
      const d = new Date(isoStr);
      return isNaN(d.getTime()) ? String(isoStr) : d.toLocaleString();
    } catch {
      return String(isoStr);
    }
  }

  /**
   * Load incidents from API.
   */
  async function loadIncidents(force = false) {
    if (!window.OsirisApi) return;
    const now = Date.now();
    if (!force && state.isLoading) return;
    if (!force && now - state.lastFetchTime < REFRESH_COOLDOWN_MS && state.hasLoadedOnce) return;

    state.isLoading = true;
    if (dom.loadingIndicator) dom.loadingIndicator.classList.remove('hidden');
    if (dom.emptyState) dom.emptyState.classList.add('hidden');
    if (dom.errorBox) dom.errorBox.classList.add('hidden');

    try {
      const params = {
        limit: state.limit,
        offset: state.offset,
      };
      if (state.filters.host_id) params.host_id = state.filters.host_id;
      if (state.filters.severity) params.severity = state.filters.severity;
      if (state.filters.status) params.status = state.filters.status;
      if (state.filters.category) params.category = state.filters.category;

      const data = await window.OsirisApi.getIncidents(params);

      state.lastFetchTime = Date.now();
      state.hasLoadedOnce = true;
      state.total = data.total || 0;

      renderIncidentsTable(data.items || []);
      updatePaginationControls();
      updateRefreshTime();

      // Refresh overall summary statistics
      fetchSummaryStats();
    } catch (err) {
      if (dom.errorBox) {
        dom.errorBox.textContent = `Error loading incidents: ${err.message || 'Unknown error'}`;
        dom.errorBox.classList.remove('hidden');
      }
    } finally {
      state.isLoading = false;
      if (dom.loadingIndicator) dom.loadingIndicator.classList.add('hidden');
    }
  }

  /**
   * Fetch counts for the stats cards.
   */
  async function fetchSummaryStats() {
    try {
      const [openRes, invRes, conRes, resRes, cloRes] = await Promise.all([
        window.OsirisApi.getIncidents({ status: 'open', limit: 1 }),
        window.OsirisApi.getIncidents({ status: 'investigating', limit: 1 }),
        window.OsirisApi.getIncidents({ status: 'contained', limit: 1 }),
        window.OsirisApi.getIncidents({ status: 'resolved', limit: 1 }),
        window.OsirisApi.getIncidents({ status: 'closed', limit: 1 }),
      ]);

      if (dom.statOpen) dom.statOpen.textContent = String(openRes.total || 0);
      if (dom.statInvestigating) dom.statInvestigating.textContent = String(invRes.total || 0);
      if (dom.statContained) dom.statContained.textContent = String(conRes.total || 0);
      if (dom.statResolved) dom.statResolved.textContent = String(resRes.total || 0);
      if (dom.statClosed) dom.statClosed.textContent = String(cloRes.total || 0);

      // Nav badge shows open + investigating count
      const activeCount = (openRes.total || 0) + (invRes.total || 0);
      if (dom.navBadge) {
        dom.navBadge.textContent = String(activeCount);
        if (activeCount > 0) {
          dom.navBadge.classList.remove('hidden');
        } else {
          dom.navBadge.classList.add('hidden');
        }
      }
    } catch {
      // Non-fatal if stats query fails
    }
  }

  /**
   * Render table rows safely with textContent.
   */
  function renderIncidentsTable(items) {
    if (!dom.tbody) return;
    dom.tbody.textContent = '';

    if (!items || items.length === 0) {
      if (dom.emptyState) dom.emptyState.classList.remove('hidden');
      return;
    }
    if (dom.emptyState) dom.emptyState.classList.add('hidden');

    items.forEach((inc) => {
      const tr = document.createElement('tr');

      // Title
      const tdTitle = document.createElement('td');
      tdTitle.className = 'font-bold';
      tdTitle.textContent = inc.title;
      tr.appendChild(tdTitle);

      // Severity
      const tdSev = document.createElement('td');
      const spanSev = document.createElement('span');
      spanSev.className = getSeverityBadgeClass(inc.severity);
      spanSev.textContent = inc.severity.toUpperCase();
      tdSev.appendChild(spanSev);
      tr.appendChild(tdSev);

      // Status
      const tdStatus = document.createElement('td');
      const spanStatus = document.createElement('span');
      spanStatus.className = getStatusBadgeClass(inc.status);
      spanStatus.textContent = inc.status.toUpperCase();
      tdStatus.appendChild(spanStatus);
      tr.appendChild(tdStatus);

      // Category
      const tdCat = document.createElement('td');
      tdCat.className = 'font-mono text-sm';
      tdCat.textContent = inc.category || 'general';
      tr.appendChild(tdCat);

      // Host
      const tdHost = document.createElement('td');
      tdHost.className = 'font-mono text-xs';
      tdHost.textContent = inc.hostname || (inc.host_id ? String(inc.host_id).substring(0, 8) + '...' : 'All Hosts');
      tr.appendChild(tdHost);

      // First Observed
      const tdFirst = document.createElement('td');
      tdFirst.className = 'text-xs';
      tdFirst.textContent = formatDate(inc.first_observed_at);
      tr.appendChild(tdFirst);

      // Last Observed
      const tdLast = document.createElement('td');
      tdLast.className = 'text-xs';
      tdLast.textContent = formatDate(inc.last_observed_at);
      tr.appendChild(tdLast);

      // Assigned To
      const tdAssigned = document.createElement('td');
      tdAssigned.className = 'text-xs';
      tdAssigned.textContent = inc.assigned_to_username || 'Unassigned';
      tr.appendChild(tdAssigned);

      // Actions
      const tdActions = document.createElement('td');
      const btnView = document.createElement('button');
      btnView.type = 'button';
      btnView.className = 'btn btn-outline btn-sm';
      btnView.textContent = 'Inspect';
      btnView.addEventListener('click', () => {
        openDetailModal(inc.id);
      });
      tdActions.appendChild(btnView);
      tr.appendChild(tdActions);

      dom.tbody.appendChild(tr);
    });
  }

  function updatePaginationControls() {
    const start = state.total === 0 ? 0 : state.offset + 1;
    const end = Math.min(state.offset + state.limit, state.total);
    if (dom.pageInfo) {
      dom.pageInfo.textContent = `Showing ${start}–${end} of ${state.total} incidents`;
    }
    if (dom.totalBadge) {
      dom.totalBadge.textContent = `${state.total} incidents`;
    }
    if (dom.btnPrev) {
      dom.btnPrev.disabled = state.offset === 0;
    }
    if (dom.btnNext) {
      dom.btnNext.disabled = state.offset + state.limit >= state.total;
    }
  }

  function updateRefreshTime() {
    if (dom.refreshTime) {
      dom.refreshTime.textContent = `Updated: ${new Date().toLocaleTimeString()}`;
    }
  }

  /**
   * Open and populate incident detail inspector modal.
   */
  async function openDetailModal(incidentId) {
    state.selectedIncidentId = incidentId;
    if (!dom.detailModal) return;

    dom.detailModal.classList.remove('hidden');

    try {
      const inc = await window.OsirisApi.getIncident(incidentId);

      // Populate meta fields
      if (dom.detailTitle) dom.detailTitle.textContent = inc.title;
      if (dom.detailSeverity) {
        dom.detailSeverity.className = getSeverityBadgeClass(inc.severity);
        dom.detailSeverity.textContent = inc.severity.toUpperCase();
      }
      if (dom.detailStatus) {
        dom.detailStatus.className = getStatusBadgeClass(inc.status);
        dom.detailStatus.textContent = inc.status.toUpperCase();
      }
      if (dom.detailCategory) dom.detailCategory.textContent = inc.category;
      if (dom.detailHost) {
        dom.detailHost.textContent = inc.hostname ? `${inc.hostname} (${inc.host_id})` : (inc.host_id || 'Global / Multi-host');
      }
      if (dom.detailAssigned) dom.detailAssigned.textContent = inc.assigned_to_username || 'Unassigned';
      if (dom.detailCreated) dom.detailCreated.textContent = formatDate(inc.created_at);
      if (dom.detailObserved) {
        dom.detailObserved.textContent = `${formatDate(inc.first_observed_at)} — ${formatDate(inc.last_observed_at)}`;
      }
      if (dom.detailDescription) dom.detailDescription.textContent = inc.description || 'No description provided.';
      if (dom.detailContainment) dom.detailContainment.textContent = inc.containment_summary || 'None recorded.';
      if (dom.detailResolution) dom.detailResolution.textContent = inc.resolution_summary || 'None recorded.';
      if (dom.detailClosure) dom.detailClosure.textContent = inc.closure_summary || 'None recorded.';

      // Pre-select current status in transition form
      if (dom.selectNewStatus) dom.selectNewStatus.value = inc.status;
      if (dom.selectNewSeverity) dom.selectNewSeverity.value = inc.severity;

      // Load sub-lists via report endpoint for completeness
      loadIncidentReportDetails(incidentId);
    } catch (err) {
      alert(`Error loading incident details: ${err.message || 'Unknown error'}`);
      closeDetailModal();
    }
  }

  async function loadIncidentReportDetails(incidentId) {
    try {
      const report = await window.OsirisApi.getIncidentReport(incidentId, 'json');

      // 1. Detections list
      renderSimpleList(
        dom.detectionsList,
        report.detections || [],
        (d) => `${d.title} (Severity: ${d.details?.severity || 'N/A'}, Time: ${formatDate(d.details?.timestamp)})`
      );

      // 2. FIM list
      renderSimpleList(
        dom.fimList,
        report.fim_deviations || [],
        (f) => `${f.title} (Path: ${f.details?.file_path || 'N/A'}, Detected: ${formatDate(f.details?.detected_at)})`
      );

      // 3. Sessions list
      renderSimpleList(
        dom.sessionsList,
        report.sessions || [],
        (s) => `Terminal: ${s.details?.terminal || 'N/A'}, Remote: ${s.details?.remote_host || 'local'}, Started: ${formatDate(s.details?.started_at)}`
      );

      // 4. Evidence Inventory
      renderSimpleList(
        dom.evidenceList,
        report.evidence_inventory || [],
        (e) => `[${e.evidence_type.toUpperCase()}] ${e.title} (Source ID: ${e.source_id})`
      );

      // 5. Linked Forensic Events
      if (dom.eventsList) {
        renderSimpleList(
          dom.eventsList,
          report.events || [],
          (evt) => `[${evt.relationship || 'related'}] Event ${evt.event_id} (${evt.event_type || 'N/A'}${evt.action ? ' - ' + evt.action : ''})`
        );
      }

      // 6. Timeline
      renderTimeline(dom.timelineList, report.timeline || []);

      // 7. History & Notes
      renderHistoryFeed(dom.historyList, report.change_history || []);
    } catch {
      // Non-fatal if detail lists fail
    }
  }

  function renderSimpleList(container, items, labelFn) {
    if (!container) return;
    container.textContent = '';

    if (!items || items.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'text-xs text-muted p-2';
      empty.textContent = 'None associated.';
      container.appendChild(empty);
      return;
    }

    const ul = document.createElement('ul');
    ul.className = 'evidence-ul';
    items.forEach((item) => {
      const li = document.createElement('li');
      li.className = 'text-xs py-1 border-b border-light';
      li.textContent = labelFn(item);
      ul.appendChild(li);
    });
    container.appendChild(ul);
  }

  function renderTimeline(container, entries) {
    if (!container) return;
    container.textContent = '';

    if (!entries || entries.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'text-xs text-muted p-2';
      empty.textContent = 'No timeline entries recorded.';
      container.appendChild(empty);
      return;
    }

    entries.forEach((t) => {
      const item = document.createElement('div');
      item.className = 'timeline-item p-2 mb-2 border rounded';

      const header = document.createElement('div');
      header.className = 'flex justify-between text-xs font-bold';

      const titleSpan = document.createElement('span');
      const badgeSpan = document.createElement('span');
      badgeSpan.className = t.nature === 'observed_fact' ? 'badge badge-primary text-xs' : 'badge badge-secondary text-xs';
      badgeSpan.textContent = t.nature === 'observed_fact' ? 'OBSERVED FACT' : 'ANALYST / SYSTEM';

      titleSpan.appendChild(badgeSpan);
      titleSpan.appendChild(document.createTextNode(` ${t.category}: ${t.summary}`));

      const timeSpan = document.createElement('span');
      timeSpan.className = 'text-muted font-mono';
      timeSpan.textContent = formatDate(t.timestamp);

      header.appendChild(titleSpan);
      header.appendChild(timeSpan);
      item.appendChild(header);

      if (t.details) {
        const desc = document.createElement('div');
        desc.className = 'text-xs text-muted mt-1';
        desc.textContent = t.details;
        item.appendChild(desc);
      }

      container.appendChild(item);
    });
  }

  function renderHistoryFeed(container, historyItems) {
    if (!container) return;
    container.textContent = '';

    if (!historyItems || historyItems.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'text-xs text-muted p-2';
      empty.textContent = 'No change history recorded.';
      container.appendChild(empty);
      return;
    }

    historyItems.forEach((h) => {
      const div = document.createElement('div');
      div.className = 'history-item p-2 mb-2 border-b';

      const top = document.createElement('div');
      top.className = 'flex justify-between text-xs';

      const userSpan = document.createElement('span');
      userSpan.className = 'font-bold';
      userSpan.textContent = `${h.user || 'System'} (${h.change_type.replace(/_/g, ' ')})`;

      const timeSpan = document.createElement('span');
      timeSpan.className = 'text-muted font-mono';
      timeSpan.textContent = formatDate(h.timestamp);

      top.appendChild(userSpan);
      top.appendChild(timeSpan);
      div.appendChild(top);

      if (h.notes) {
        const notesP = document.createElement('p');
        notesP.className = 'text-xs mt-1';
        notesP.textContent = h.notes;
        div.appendChild(notesP);
      }

      container.appendChild(div);
    });
  }

  function closeDetailModal() {
    state.selectedIncidentId = null;
    if (dom.detailModal) dom.detailModal.classList.add('hidden');
  }

  function openCreateModal() {
    if (dom.createModal) {
      if (dom.createErrorBox) dom.createErrorBox.classList.add('hidden');
      if (dom.createForm) dom.createForm.reset();
      dom.createModal.classList.remove('hidden');
    }
  }

  function closeCreateModal() {
    if (dom.createModal) dom.createModal.classList.add('hidden');
  }

  /**
   * Handle status transition submission.
   */
  async function handleStatusTransition() {
    if (!state.selectedIncidentId || !window.OsirisApi) return;
    const newStatus = dom.selectNewStatus ? dom.selectNewStatus.value : '';
    const notes = dom.inputTransitionNotes ? dom.inputTransitionNotes.value.trim() : '';

    if (!newStatus) return;

    try {
      if (dom.btnTransitionSubmit) dom.btnTransitionSubmit.disabled = true;
      await window.OsirisApi.transitionIncidentStatus(state.selectedIncidentId, {
        status: newStatus,
        notes: notes || undefined,
      });
      if (dom.inputTransitionNotes) dom.inputTransitionNotes.value = '';
      openDetailModal(state.selectedIncidentId);
      loadIncidents(true);
    } catch (err) {
      alert(`Status transition failed: ${err.message || 'Unknown error'}`);
    } finally {
      if (dom.btnTransitionSubmit) dom.btnTransitionSubmit.disabled = false;
    }
  }

  /**
   * Handle severity adjustment submission.
   */
  async function handleSeverityAdjustment() {
    if (!state.selectedIncidentId || !window.OsirisApi) return;
    const newSeverity = dom.selectNewSeverity ? dom.selectNewSeverity.value : '';
    const reason = dom.inputSeverityReason ? dom.inputSeverityReason.value.trim() : '';
    const allowDowngrade = dom.checkAllowDowngrade ? dom.checkAllowDowngrade.checked : false;

    if (!reason) {
      alert('A reason is required to adjust incident severity.');
      return;
    }

    try {
      if (dom.btnSeveritySubmit) dom.btnSeveritySubmit.disabled = true;
      await window.OsirisApi.escalateIncidentSeverity(state.selectedIncidentId, {
        severity: newSeverity,
        reason: reason,
        allow_downgrade: allowDowngrade,
      });
      if (dom.inputSeverityReason) dom.inputSeverityReason.value = '';
      openDetailModal(state.selectedIncidentId);
      loadIncidents(true);
    } catch (err) {
      alert(`Severity update failed: ${err.message || 'Unknown error'}`);
    } finally {
      if (dom.btnSeveritySubmit) dom.btnSeveritySubmit.disabled = false;
    }
  }

  /**
   * Handle adding an investigation note.
   */
  async function handleAddNote() {
    if (!state.selectedIncidentId || !window.OsirisApi) return;
    const noteText = dom.inputNewNote ? dom.inputNewNote.value.trim() : '';
    if (!noteText) return;

    try {
      if (dom.btnAddNote) dom.btnAddNote.disabled = true;
      await window.OsirisApi.addIncidentNote(state.selectedIncidentId, {
        notes: noteText,
      });
      if (dom.inputNewNote) dom.inputNewNote.value = '';
      loadIncidentReportDetails(state.selectedIncidentId);
    } catch (err) {
      alert(`Failed to add note: ${err.message || 'Unknown error'}`);
    } finally {
      if (dom.btnAddNote) dom.btnAddNote.disabled = false;
    }
  }

  /**
   * Handle report export.
   */
  async function handleExportReport(format = 'markdown') {
    if (!state.selectedIncidentId || !window.OsirisApi) return;

    try {
      const data = await window.OsirisApi.getIncidentReport(state.selectedIncidentId, format);
      const blob = new Blob(
        [format === 'markdown' ? data : JSON.stringify(data, null, 2)],
        { type: format === 'markdown' ? 'text/markdown;charset=utf-8' : 'application/json;charset=utf-8' }
      );
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `incident-${state.selectedIncidentId}-report.${format === 'markdown' ? 'md' : 'json'}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      alert(`Report export failed: ${err.message || 'Unknown error'}`);
    }
  }

  /**
   * Handle create incident submission.
   */
  async function handleCreateIncident(e) {
    if (e) e.preventDefault();
    if (!window.OsirisApi) return;

    const title = dom.inputCreateTitle ? dom.inputCreateTitle.value.trim() : '';
    const desc = dom.inputCreateDesc ? dom.inputCreateDesc.value.trim() : '';
    const severity = dom.selectCreateSeverity ? dom.selectCreateSeverity.value : 'medium';
    const category = dom.inputCreateCategory ? dom.inputCreateCategory.value.trim() : 'general';
    const hostId = dom.inputCreateHostId ? dom.inputCreateHostId.value.trim() : '';

    if (!title) {
      showCreateError('Incident title is required.');
      return;
    }

    try {
      if (dom.btnCreateSubmit) dom.btnCreateSubmit.disabled = true;
      const payload = {
        title: title,
        description: desc || undefined,
        severity: severity,
        category: category || 'general',
        host_id: hostId || undefined,
      };

      const newInc = await window.OsirisApi.createIncident(payload);
      closeCreateModal();
      loadIncidents(true);
      if (newInc && newInc.id) {
        openDetailModal(newInc.id);
      }
    } catch (err) {
      showCreateError(err.message || 'Failed to create incident');
    } finally {
      if (dom.btnCreateSubmit) dom.btnCreateSubmit.disabled = false;
    }
  }

  function showCreateError(msg) {
    if (dom.createErrorBox) {
      dom.createErrorBox.textContent = msg;
      dom.createErrorBox.classList.remove('hidden');
    }
  }

  /**
   * Bind DOM event listeners.
   */
  function bindEvents() {
    if (dom.btnRefresh) {
      dom.btnRefresh.addEventListener('click', () => loadIncidents(true));
    }

    if (dom.btnApply) {
      dom.btnApply.addEventListener('click', () => {
        state.offset = 0;
        state.filters.host_id = dom.inputHostId ? dom.inputHostId.value.trim() : '';
        state.filters.severity = dom.selectSeverity ? dom.selectSeverity.value : '';
        state.filters.status = dom.selectStatus ? dom.selectStatus.value : '';
        state.filters.category = dom.inputCategory ? dom.inputCategory.value.trim() : '';
        loadIncidents(true);
      });
    }

    if (dom.btnReset) {
      dom.btnReset.addEventListener('click', () => {
        if (dom.filterForm) dom.filterForm.reset();
        state.offset = 0;
        state.filters.host_id = '';
        state.filters.severity = '';
        state.filters.status = '';
        state.filters.category = '';
        loadIncidents(true);
      });
    }

    if (dom.btnPrev) {
      dom.btnPrev.addEventListener('click', () => {
        if (state.offset > 0) {
          state.offset = Math.max(0, state.offset - state.limit);
          loadIncidents(true);
        }
      });
    }

    if (dom.btnNext) {
      dom.btnNext.addEventListener('click', () => {
        if (state.offset + state.limit < state.total) {
          state.offset += state.limit;
          loadIncidents(true);
        }
      });
    }

    if (dom.btnCreateTrigger) {
      dom.btnCreateTrigger.addEventListener('click', openCreateModal);
    }

    if (dom.createModalCloseBtn) {
      dom.createModalCloseBtn.addEventListener('click', closeCreateModal);
    }

    if (dom.createForm) {
      dom.createForm.addEventListener('submit', handleCreateIncident);
    }

    if (dom.detailModalCloseBtn) {
      dom.detailModalCloseBtn.addEventListener('click', closeDetailModal);
    }

    if (dom.btnTransitionSubmit) {
      dom.btnTransitionSubmit.addEventListener('click', handleStatusTransition);
    }

    if (dom.btnSeveritySubmit) {
      dom.btnSeveritySubmit.addEventListener('click', handleSeverityAdjustment);
    }

    if (dom.btnAddNote) {
      dom.btnAddNote.addEventListener('click', handleAddNote);
    }

    if (dom.btnExportJson) {
      dom.btnExportJson.addEventListener('click', () => handleExportReport('json'));
    }

    if (dom.btnExportMd) {
      dom.btnExportMd.addEventListener('click', () => handleExportReport('markdown'));
    }
  }

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
  globalObj.OsirisIncidents = Object.freeze({
    init,
    loadIncidents,
    openDetailModal,
    openCreateModal,
  });

})(typeof window !== 'undefined' ? window : this, typeof document !== 'undefined' ? document : {});
