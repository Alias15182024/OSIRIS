/**
 * OSIRIS Investigation Workspace View Controller (Phase 2 Milestone 2.7)
 *
 * Responsibilities:
 * - Persistent investigation workspaces (create, select, update, archive, delete).
 * - Host-isolated evidence scoping and layout configuration persistence.
 * - Native SVG interactive entity graph rendering with bounded expansion and pivoting.
 * - Multi-criteria structured forensic search with AND/OR logic and tag filtering.
 * - Polymorphic evidence tagging and attribution-tracked analyst notes.
 * - Strict security: createElement DOM building only, memory state, no dynamic code execution.
 */

(function (window, document) {
  'use strict';

  // Component State
  let state = {
    workspaces: [],
    currentWorkspace: null,
    currentHostId: null,
    activeTab: 'overview', // 'overview' | 'unified' | 'graph' | 'search' | 'evidence'
    activePanels: ['timeline', 'processes', 'sessions', 'detections', 'fim', 'incidents'],
    layoutPreference: 'grid', // 'grid' | 'stacked' | 'single'
    graph: {
      nodes: [],
      edges: [],
      nodeMap: new Map(),
      edgeMap: new Map(),
      rootNodeId: null,
      selectedNode: null,
      zoom: 1.0,
      panX: 0,
      panY: 0,
    },
    search: {
      filters: {},
      results: [],
      total: 0,
    },
    unified: {
      timeline: [],
      processes: [],
      sessions: [],
      detections: [],
      fim: [],
      incidents: [],
      isLoading: false,
    },
    tags: [],
    pinnedEvidence: [],
    notes: [],
    modalContext: {
      targetType: null,
      targetId: null,
      hostId: null,
    },
  };

  // Cached DOM elements
  let elements = {};

  const ENTITY_COLORS = {
    host: '#3b82f6',
    process: '#10b981',
    user: '#8b5cf6',
    session: '#ec4899',
    event: '#f59e0b',
    detection: '#ef4444',
    fim_deviation: '#f97316',
    file: '#06b6d4',
    incident: '#e11d48',
    snapshot: '#64748b',
  };

  const SEVERITY_COLORS = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#f59e0b',
    low: '#3b82f6',
    info: '#6b7280',
  };

  /**
   * Cache all DOM references for the workspace panel.
   */
  function cacheElements() {
    elements = {
      // Header controls
      workspaceSelect: document.getElementById('workspace-select'),
      workspaceNewBtn: document.getElementById('workspace-new-btn'),
      workspaceRenameBtn: document.getElementById('workspace-rename-btn'),
      workspaceSaveBtn: document.getElementById('workspace-save-btn'),
      workspaceArchiveBtn: document.getElementById('workspace-archive-btn'),
      workspaceDeleteBtn: document.getElementById('workspace-delete-btn'),
      workspaceHostBadge: document.getElementById('workspace-host-badge'),
      workspaceStatusBadge: document.getElementById('workspace-status-badge'),
      workspaceAlertBox: document.getElementById('workspace-alert-box'),

      // Tabs
      tabs: document.querySelectorAll('.ws-tab-btn[data-ws-tab]'),
      panels: {
        overview: document.getElementById('ws-panel-overview'),
        unified: document.getElementById('ws-panel-unified'),
        graph: document.getElementById('ws-panel-graph'),
        search: document.getElementById('ws-panel-search'),
        evidence: document.getElementById('ws-panel-evidence'),
      },

      // Unified View controls & subpanels
      unifiedLayoutSelect: document.getElementById('ws-unified-layout-select'),
      unifiedRefreshBtn: document.getElementById('ws-unified-refresh-btn'),
      unifiedGrid: document.getElementById('ws-unified-grid'),
      panelCheckboxes: {
        timeline: document.getElementById('ws-panel-chk-timeline'),
        processes: document.getElementById('ws-panel-chk-processes'),
        sessions: document.getElementById('ws-panel-chk-sessions'),
        detections: document.getElementById('ws-panel-chk-detections'),
        fim: document.getElementById('ws-panel-chk-fim'),
        incidents: document.getElementById('ws-panel-chk-incidents'),
      },
      subpanels: {
        timeline: document.getElementById('ws-subpanel-timeline'),
        processes: document.getElementById('ws-subpanel-processes'),
        sessions: document.getElementById('ws-subpanel-sessions'),
        detections: document.getElementById('ws-subpanel-detections'),
        fim: document.getElementById('ws-subpanel-fim'),
        incidents: document.getElementById('ws-subpanel-incidents'),
      },
      panelCollapseBtns: {
        timeline: document.getElementById('ws-timeline-collapse-btn'),
        processes: document.getElementById('ws-processes-collapse-btn'),
        sessions: document.getElementById('ws-sessions-collapse-btn'),
        detections: document.getElementById('ws-detections-collapse-btn'),
        fim: document.getElementById('ws-fim-collapse-btn'),
        incidents: document.getElementById('ws-incidents-collapse-btn'),
      },
      panelContents: {
        timeline: document.getElementById('ws-timeline-content'),
        processes: document.getElementById('ws-processes-content'),
        sessions: document.getElementById('ws-sessions-content'),
        detections: document.getElementById('ws-detections-content'),
        fim: document.getElementById('ws-fim-content'),
        incidents: document.getElementById('ws-incidents-content'),
      },
      panelCounts: {
        timeline: document.getElementById('ws-timeline-count'),
        processes: document.getElementById('ws-processes-count'),
        sessions: document.getElementById('ws-sessions-count'),
        detections: document.getElementById('ws-detections-count'),
        fim: document.getElementById('ws-fim-count'),
        incidents: document.getElementById('ws-incidents-count'),
      },
      panelTables: {
        timeline: document.getElementById('ws-timeline-table'),
        processes: document.getElementById('ws-processes-table'),
        sessions: document.getElementById('ws-sessions-table'),
        detections: document.getElementById('ws-detections-table'),
        fim: document.getElementById('ws-fim-table'),
        incidents: document.getElementById('ws-incidents-table'),
      },
      panelTbodies: {
        timeline: document.getElementById('ws-timeline-tbody'),
        processes: document.getElementById('ws-processes-tbody'),
        sessions: document.getElementById('ws-sessions-tbody'),
        detections: document.getElementById('ws-detections-tbody'),
        fim: document.getElementById('ws-fim-tbody'),
        incidents: document.getElementById('ws-incidents-tbody'),
      },
      panelLoadings: {
        timeline: document.getElementById('ws-timeline-loading'),
        processes: document.getElementById('ws-processes-loading'),
        sessions: document.getElementById('ws-sessions-loading'),
        detections: document.getElementById('ws-detections-loading'),
        fim: document.getElementById('ws-fim-loading'),
        incidents: document.getElementById('ws-incidents-loading'),
      },
      panelEmpties: {
        timeline: document.getElementById('ws-timeline-empty'),
        processes: document.getElementById('ws-processes-empty'),
        sessions: document.getElementById('ws-sessions-empty'),
        detections: document.getElementById('ws-detections-empty'),
        fim: document.getElementById('ws-fim-empty'),
        incidents: document.getElementById('ws-incidents-empty'),
      },

      // Overview panel
      overviewName: document.getElementById('ws-overview-name'),
      overviewDesc: document.getElementById('ws-overview-desc'),
      overviewHost: document.getElementById('ws-overview-host'),
      overviewStatus: document.getElementById('ws-overview-status'),
      overviewCreated: document.getElementById('ws-overview-created'),
      overviewStatNodes: document.getElementById('ws-stat-nodes'),
      overviewStatEvidence: document.getElementById('ws-stat-evidence'),
      overviewStatNotes: document.getElementById('ws-stat-notes'),
      jumpGraphBtn: document.getElementById('ws-jump-graph-btn'),
      jumpSearchBtn: document.getElementById('ws-jump-search-btn'),

      // Graph panel
      graphSvg: document.getElementById('workspace-graph-svg'),
      graphContainer: document.getElementById('workspace-graph-container'),
      graphZoomInBtn: document.getElementById('graph-zoom-in-btn'),
      graphZoomOutBtn: document.getElementById('graph-zoom-out-btn'),
      graphResetBtn: document.getElementById('graph-reset-btn'),
      graphDepthSelect: document.getElementById('graph-depth-select'),
      graphMaxNodesSelect: document.getElementById('graph-max-nodes-select'),
      graphTypeFilter: document.getElementById('graph-type-filter'),
      graphSearchInput: document.getElementById('graph-search-input'),
      graphSearchBtn: document.getElementById('graph-search-btn'),
      graphStatusText: document.getElementById('graph-status-text'),

      // Graph Drawer
      graphDrawer: document.getElementById('graph-drawer'),
      graphDrawerCloseBtn: document.getElementById('graph-drawer-close-btn'),
      graphDrawerTitle: document.getElementById('graph-drawer-title'),
      graphDrawerTypeBadge: document.getElementById('graph-drawer-type-badge'),
      graphDrawerSeverityBadge: document.getElementById('graph-drawer-severity-badge'),
      graphDrawerProperties: document.getElementById('graph-drawer-properties'),
      graphDrawerPivots: document.getElementById('graph-drawer-pivots'),
      graphDrawerExpandBtn: document.getElementById('graph-drawer-expand-btn'),
      graphDrawerPinBtn: document.getElementById('graph-drawer-pin-btn'),
      graphDrawerTagBtn: document.getElementById('graph-drawer-tag-btn'),
      graphDrawerNoteBtn: document.getElementById('graph-drawer-note-btn'),

      // Search panel
      searchForm: document.getElementById('ws-search-form'),
      searchQueryInput: document.getElementById('ws-search-query-input'),
      searchCmdInput: document.getElementById('ws-search-cmd-input'),
      searchPathInput: document.getElementById('ws-search-path-input'),
      searchSeveritySelect: document.getElementById('ws-search-severity-select'),
      searchLogicSelect: document.getElementById('ws-search-logic-select'),
      searchTagInput: document.getElementById('ws-search-tag-input'),
      searchStartInput: document.getElementById('ws-search-start-input'),
      searchEndInput: document.getElementById('ws-search-end-input'),
      searchSubmitBtn: document.getElementById('ws-search-submit-btn'),
      searchResetBtn: document.getElementById('ws-search-reset-btn'),
      searchTbody: document.getElementById('ws-search-tbody'),
      searchPageInfo: document.getElementById('ws-search-page-info'),
      searchEmptyState: document.getElementById('ws-search-empty'),

      // Evidence & Annotations panel
      pinnedList: document.getElementById('ws-pinned-evidence-list'),
      tagsList: document.getElementById('ws-tags-list'),
      notesList: document.getElementById('ws-notes-list'),
      createTagName: document.getElementById('ws-create-tag-name'),
      createTagColor: document.getElementById('ws-create-tag-color'),
      createTagCategory: document.getElementById('ws-create-tag-category'),
      createTagBtn: document.getElementById('ws-create-tag-btn'),

      // Modals
      createModal: document.getElementById('modal-workspace-create'),
      createModalCloseBtn: document.getElementById('modal-ws-close-btn'),
      createModalForm: document.getElementById('modal-ws-form'),
      createModalName: document.getElementById('modal-ws-name'),
      createModalDesc: document.getElementById('modal-ws-desc'),
      createModalHost: document.getElementById('modal-ws-host'),
      createModalIncident: document.getElementById('modal-ws-incident'),
      createModalShared: document.getElementById('modal-ws-shared'),

      renameModal: document.getElementById('modal-workspace-rename'),
      renameModalCloseBtn: document.getElementById('modal-ws-rename-close-btn'),
      renameModalForm: document.getElementById('modal-ws-rename-form'),
      renameModalName: document.getElementById('modal-ws-rename-name'),
      renameModalSubmitBtn: document.getElementById('modal-ws-rename-submit-btn'),

      tagModal: document.getElementById('modal-workspace-tag'),
      tagModalCloseBtn: document.getElementById('modal-tag-close-btn'),
      tagModalForm: document.getElementById('modal-tag-form'),
      tagModalEvidenceInfo: document.getElementById('modal-tag-evidence-info'),
      tagModalSelect: document.getElementById('modal-tag-select'),

      noteModal: document.getElementById('modal-workspace-note'),
      noteModalCloseBtn: document.getElementById('modal-note-close-btn'),
      noteModalForm: document.getElementById('modal-note-form'),
      noteModalEvidenceInfo: document.getElementById('modal-note-evidence-info'),
      noteModalTextarea: document.getElementById('modal-note-textarea'),
    };
  }

  /**
   * Show alert banner in workspace header.
   */
  function showAlert(msg, isError = false) {
    if (!elements.workspaceAlertBox) return;
    elements.workspaceAlertBox.textContent = msg;
    elements.workspaceAlertBox.className = isError
      ? 'alert-box alert-error'
      : 'alert-box alert-success';
    elements.workspaceAlertBox.classList.remove('hidden');
    setTimeout(() => {
      if (elements.workspaceAlertBox) {
        elements.workspaceAlertBox.classList.add('hidden');
      }
    }, 5000);
  }

  // ── Workspaces Lifecycle ───────────────────────────────────────────────────

  /**
   * Load workspaces available to analyst and populate selector.
   */
  async function loadWorkspaces() {
    try {
      const resp = await window.OsirisApi.getWorkspaces({ limit: 100 });
      state.workspaces = resp.items || [];
      renderWorkspaceSelector();
      if (state.workspaces.length > 0 && !state.currentWorkspace) {
        selectWorkspace(state.workspaces[0].id);
      } else if (state.currentWorkspace) {
        // Refresh selected workspace in state
        const refreshed = state.workspaces.find((w) => w.id === state.currentWorkspace.id);
        if (refreshed) {
          state.currentWorkspace = refreshed;
          updateWorkspaceHeader();
        }
      }
    } catch (err) {
      showAlert('Failed to load investigation workspaces: ' + err.message, true);
    }
  }

  /**
   * Render workspace dropdown options.
   */
  function renderWorkspaceSelector() {
    if (!elements.workspaceSelect) return;
    while (elements.workspaceSelect.firstChild) {
      elements.workspaceSelect.removeChild(elements.workspaceSelect.firstChild);
    }

    if (state.workspaces.length === 0) {
      const opt = document.createElement('option');
      opt.value = '';
      opt.textContent = '-- No Workspaces Available --';
      elements.workspaceSelect.appendChild(opt);
      return;
    }

    state.workspaces.forEach((w) => {
      const opt = document.createElement('option');
      opt.value = w.id;
      opt.textContent = `${w.name} (${w.status})`;
      if (state.currentWorkspace && state.currentWorkspace.id === w.id) {
        opt.selected = true;
      }
      elements.workspaceSelect.appendChild(opt);
    });
  }

  /**
   * Select active workspace and restore its preserved configuration.
   */
  async function selectWorkspace(workspaceId) {
    try {
      const ws = await window.OsirisApi.getWorkspace(workspaceId);
      state.currentWorkspace = ws;
      state.currentHostId = ws.host_id || null;

      // Restore configuration
      const config = ws.configuration || {};
      state.activeTab = config.active_tab || 'overview';
      if (config.pinned_nodes) {
        state.pinnedEvidence = config.pinned_nodes;
      } else {
        state.pinnedEvidence = [];
      }
      if (config.zoom) {
        state.graph.zoom = config.zoom.scale || 1.0;
        state.graph.panX = config.zoom.panX || 0;
        state.graph.panY = config.zoom.panY || 0;
      }

      updateWorkspaceHeader();
      switchTab(state.activeTab);
      loadTags();
      loadGraph();
    } catch (err) {
      showAlert('Error selecting workspace: ' + err.message, true);
    }
  }

  /**
   * Update workspace title, badges, and overview panel info.
   */
  function updateWorkspaceHeader() {
    const ws = state.currentWorkspace;
    if (!ws) return;

    if (elements.workspaceHostBadge) {
      elements.workspaceHostBadge.textContent = ws.host_id ? `Host: ${ws.host_id}` : 'Scope: All Hosts';
    }
    if (elements.workspaceStatusBadge) {
      elements.workspaceStatusBadge.textContent = ws.status.toUpperCase();
      elements.workspaceStatusBadge.className = `badge ${
        ws.status === 'active' ? 'badge-success' : 'badge-secondary'
      }`;
    }

    if (elements.overviewName) elements.overviewName.textContent = ws.name;
    if (elements.overviewDesc) elements.overviewDesc.textContent = ws.description || 'No description provided';
    if (elements.overviewHost) elements.overviewHost.textContent = ws.host_id || 'All Monitored Hosts';
    if (elements.overviewStatus) elements.overviewStatus.textContent = ws.status;
    if (elements.overviewCreated) elements.overviewCreated.textContent = new Date(ws.created_at).toLocaleString();
    if (elements.overviewStatEvidence) elements.overviewStatEvidence.textContent = String(state.pinnedEvidence.length);
  }

  /**
   * Persist workspace configuration back to the API.
   */
  async function saveWorkspace() {
    if (!state.currentWorkspace) return;
    try {
      const payload = {
        configuration: {
          active_tab: state.activeTab,
          pinned_nodes: state.pinnedEvidence,
          zoom: {
            scale: state.graph.zoom,
            panX: state.graph.panX,
            panY: state.graph.panY,
          },
          filters: state.search.filters,
        },
      };
      const updated = await window.OsirisApi.updateWorkspace(state.currentWorkspace.id, payload);
      state.currentWorkspace = updated;
      showAlert('Workspace layout & configuration saved successfully.');
    } catch (err) {
      showAlert('Failed to save workspace configuration: ' + err.message, true);
    }
  }

  /**
   * Archive active workspace.
   */
  async function archiveWorkspace() {
    if (!state.currentWorkspace) return;
    try {
      const updated = await window.OsirisApi.archiveWorkspace(state.currentWorkspace.id);
      state.currentWorkspace = updated;
      updateWorkspaceHeader();
      showAlert('Workspace archived.');
    } catch (err) {
      showAlert('Failed to archive workspace: ' + err.message, true);
    }
  }

  /**
   * Delete active workspace.
   */
  async function deleteWorkspace() {
    if (!state.currentWorkspace) return;
    const confirmed = window.confirm(`Permanently delete workspace "${state.currentWorkspace.name}"?`);
    if (!confirmed) return;

    try {
      await window.OsirisApi.deleteWorkspace(state.currentWorkspace.id);
      showAlert('Workspace deleted.');
      state.currentWorkspace = null;
      loadWorkspaces();
    } catch (err) {
      showAlert('Failed to delete workspace: ' + err.message, true);
    }
  }

  // ── Tab Navigation ─────────────────────────────────────────────────────────

  /**
   * Switch between sub-tabs inside workspace.
   */
  function switchTab(tabName) {
    state.activeTab = tabName;
    if (elements.tabs) {
      elements.tabs.forEach((tab) => {
        if (tab.getAttribute('data-ws-tab') === tabName) {
          tab.classList.add('active');
          tab.setAttribute('aria-selected', 'true');
        } else {
          tab.classList.remove('active');
          tab.setAttribute('aria-selected', 'false');
        }
      });
    }

    if (elements.panels) {
      Object.keys(elements.panels).forEach((k) => {
        const panel = elements.panels[k];
        if (panel) {
          if (k === tabName) {
            panel.classList.remove('hidden');
          } else {
            panel.classList.add('hidden');
          }
        }
      });
    }

    if (tabName === 'graph' && state.graph.nodes.length === 0) {
      loadGraph();
    } else if (tabName === 'evidence') {
      renderPinnedEvidence();
      renderTagsList();
    }
  }

  // ── Native SVG Entity Graph ────────────────────────────────────────────────

  /**
   * Load initial graph from API.
   */
  async function loadGraph(rootType, rootId) {
    if (!elements.graphSvg) return;
    try {
      if (elements.graphStatusText) {
        elements.graphStatusText.textContent = 'Loading graph...';
      }

      const params = {
        host_id: state.currentHostId || undefined,
        root_entity_type: rootType || undefined,
        root_entity_id: rootId || undefined,
        depth: parseInt(elements.graphDepthSelect?.value || '1', 10),
        max_nodes: parseInt(elements.graphMaxNodesSelect?.value || '50', 10),
      };

      const data = await window.OsirisApi.getGraph(params);
      state.graph.nodes = data.nodes || [];
      state.graph.edges = data.edges || [];
      state.graph.rootNodeId = data.root_node_id;
      rebuildGraphMaps();
      layoutAndRenderGraph();

      if (elements.graphStatusText) {
        elements.graphStatusText.textContent = `${state.graph.nodes.length} nodes, ${state.graph.edges.length} edges`;
      }
      if (elements.overviewStatNodes) {
        elements.overviewStatNodes.textContent = String(state.graph.nodes.length);
      }
    } catch (err) {
      if (elements.graphStatusText) {
        elements.graphStatusText.textContent = 'Graph load error: ' + err.message;
      }
      showAlert('Failed to load relationship graph: ' + err.message, true);
    }
  }

  /**
   * Expand neighbors from selected node.
   */
  async function expandNode(nodeType, nodeId) {
    try {
      if (elements.graphStatusText) elements.graphStatusText.textContent = 'Expanding node...';
      const payload = {
        node_type: nodeType,
        node_id: nodeId,
        host_id: state.currentHostId || undefined,
        depth: 1,
        max_nodes: 25,
        existing_node_ids: Array.from(state.graph.nodeMap.keys()),
      };

      const data = await window.OsirisApi.expandGraph(payload);
      const newNodes = data.nodes || [];
      const newEdges = data.edges || [];

      newNodes.forEach((n) => {
        if (!state.graph.nodeMap.has(n.id)) {
          state.graph.nodes.push(n);
        }
      });
      newEdges.forEach((e) => {
        if (!state.graph.edgeMap.has(e.id)) {
          state.graph.edges.push(e);
        }
      });

      rebuildGraphMaps();
      layoutAndRenderGraph();

      if (elements.graphStatusText) {
        elements.graphStatusText.textContent = `Expanded +${newNodes.length} nodes, +${newEdges.length} edges (${state.graph.nodes.length} total)`;
      }
    } catch (err) {
      showAlert('Failed to expand node: ' + err.message, true);
    }
  }

  /**
   * Rebuild internal lookup maps for fast edge/node traversal.
   */
  function rebuildGraphMaps() {
    state.graph.nodeMap.clear();
    state.graph.edgeMap.clear();
    state.graph.nodes.forEach((n) => state.graph.nodeMap.set(n.id, n));
    state.graph.edges.forEach((e) => state.graph.edgeMap.set(e.id, e));
  }

  /**
   * Compute positions and render SVG elements.
   * Simple force/radial layout using pure deterministic trigonometry.
   */
  function layoutAndRenderGraph() {
    const svg = elements.graphSvg;
    if (!svg) return;

    // Clear previous SVG content safely
    while (svg.firstChild) {
      svg.removeChild(svg.firstChild);
    }

    const typeFilter = elements.graphTypeFilter?.value || '';
    const visibleNodes = state.graph.nodes.filter(
      (n) => !typeFilter || n.entity_type === typeFilter
    );
    const visibleNodeIds = new Set(visibleNodes.map((n) => n.id));

    const visibleEdges = state.graph.edges.filter(
      (e) => visibleNodeIds.has(e.source) && visibleNodeIds.has(e.target)
    );

    // Compute concentric circle layout
    const width = 1000;
    const height = 650;
    const centerX = width / 2;
    const centerY = height / 2;
    const radius = Math.min(centerX, centerY) * 0.75;

    const count = visibleNodes.length;
    const positions = new Map();

    visibleNodes.forEach((node, i) => {
      if (node.id === state.graph.rootNodeId || count === 1) {
        positions.set(node.id, { x: centerX, y: centerY });
      } else {
        const angle = (2 * Math.PI * i) / count;
        const r = count > 10 ? radius * (0.4 + (i % 3) * 0.3) : radius * 0.7;
        const x = centerX + r * Math.cos(angle);
        const y = centerY + r * Math.sin(angle);
        positions.set(node.id, { x, y });
      }
    });

    // Create defs with arrow marker
    const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
    const marker = document.createElementNS('http://www.w3.org/2000/svg', 'marker');
    marker.setAttribute('id', 'arrow-marker');
    marker.setAttribute('viewBox', '0 0 10 10');
    marker.setAttribute('refX', '18');
    marker.setAttribute('refY', '5');
    marker.setAttribute('markerWidth', '6');
    marker.setAttribute('markerHeight', '6');
    marker.setAttribute('orient', 'auto-start-reverse');
    const arrowPath = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    arrowPath.setAttribute('d', 'M 0 0 L 10 5 L 0 10 z');
    arrowPath.setAttribute('fill', '#94a3b8');
    marker.appendChild(arrowPath);
    defs.appendChild(marker);
    svg.appendChild(defs);

    // Main graph group with zoom/pan transform
    const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    g.setAttribute(
      'transform',
      `translate(${state.graph.panX}, ${state.graph.panY}) scale(${state.graph.zoom})`
    );

    // Render edges
    const edgesGroup = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    edgesGroup.setAttribute('class', 'graph-edges');
    visibleEdges.forEach((edge) => {
      const srcPos = positions.get(edge.source);
      const tgtPos = positions.get(edge.target);
      if (!srcPos || !tgtPos) return;

      const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      line.setAttribute('x1', String(srcPos.x));
      line.setAttribute('y1', String(srcPos.y));
      line.setAttribute('x2', String(tgtPos.x));
      line.setAttribute('y2', String(tgtPos.y));
      line.setAttribute('stroke', '#64748b');
      line.setAttribute('stroke-width', '1.5');
      line.setAttribute('stroke-dasharray', edge.edge_type === 'inferred_correlation' ? '4,4' : 'none');
      line.setAttribute('marker-end', 'url(#arrow-marker)');
      edgesGroup.appendChild(line);
    });
    g.appendChild(edgesGroup);

    // Render nodes
    const nodesGroup = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    nodesGroup.setAttribute('class', 'graph-nodes');
    visibleNodes.forEach((node) => {
      const pos = positions.get(node.id);
      if (!pos) return;

      const nodeG = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      nodeG.setAttribute('class', 'graph-node');
      nodeG.setAttribute('transform', `translate(${pos.x}, ${pos.y})`);
      nodeG.setAttribute('cursor', 'pointer');
      nodeG.setAttribute('role', 'button');
      nodeG.setAttribute('tabindex', '0');
      nodeG.setAttribute('aria-label', `${node.entity_type}: ${node.label}`);

      // Selection ring
      const isSelected = state.graph.selectedNode && state.graph.selectedNode.id === node.id;
      if (isSelected) {
        const ring = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        ring.setAttribute('r', '22');
        ring.setAttribute('fill', 'none');
        ring.setAttribute('stroke', '#38bdf8');
        ring.setAttribute('stroke-width', '3');
        nodeG.appendChild(ring);
      }

      // Severity ring if applicable
      if (node.severity && SEVERITY_COLORS[node.severity]) {
        const sevRing = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        sevRing.setAttribute('r', '18');
        sevRing.setAttribute('fill', 'none');
        sevRing.setAttribute('stroke', SEVERITY_COLORS[node.severity]);
        sevRing.setAttribute('stroke-width', '2');
        nodeG.appendChild(sevRing);
      }

      // Main node circle
      const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('r', '14');
      circle.setAttribute('fill', ENTITY_COLORS[node.entity_type] || '#94a3b8');
      circle.setAttribute('stroke', '#ffffff');
      circle.setAttribute('stroke-width', '1.5');
      nodeG.appendChild(circle);

      // Node label
      const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      text.setAttribute('y', '26');
      text.setAttribute('text-anchor', 'middle');
      text.setAttribute('fill', '#f1f5f9');
      text.setAttribute('font-size', '11');
      text.setAttribute('font-family', 'sans-serif');
      const truncatedLabel = node.label.length > 20 ? node.label.slice(0, 18) + '…' : node.label;
      text.textContent = truncatedLabel;
      nodeG.appendChild(text);

      // Click handler
      nodeG.addEventListener('click', (e) => {
        e.stopPropagation();
        selectGraphNode(node);
      });

      nodesGroup.appendChild(nodeG);
    });
    g.appendChild(nodesGroup);
    svg.appendChild(g);
  }

  /**
   * Handle node click, open drawer and populate details & pivots.
   */
  async function selectGraphNode(node) {
    state.graph.selectedNode = node;
    layoutAndRenderGraph(); // re-render selection ring

    if (!elements.graphDrawer) return;
    elements.graphDrawer.classList.remove('hidden');

    if (elements.graphDrawerTitle) elements.graphDrawerTitle.textContent = node.label;
    if (elements.graphDrawerTypeBadge) {
      elements.graphDrawerTypeBadge.textContent = node.entity_type.toUpperCase();
      elements.graphDrawerTypeBadge.style.backgroundColor = ENTITY_COLORS[node.entity_type] || '#64748b';
    }
    if (elements.graphDrawerSeverityBadge) {
      if (node.severity) {
        elements.graphDrawerSeverityBadge.textContent = node.severity.toUpperCase();
        elements.graphDrawerSeverityBadge.className = `badge badge-${node.severity}`;
        elements.graphDrawerSeverityBadge.classList.remove('hidden');
      } else {
        elements.graphDrawerSeverityBadge.classList.add('hidden');
      }
    }

    // Properties table
    if (elements.graphDrawerProperties) {
      while (elements.graphDrawerProperties.firstChild) {
        elements.graphDrawerProperties.removeChild(elements.graphDrawerProperties.firstChild);
      }
      const props = [
        { label: 'Entity ID', value: node.entity_id },
        { label: 'Type', value: node.entity_type },
        { label: 'Host ID', value: node.host_id || '--' },
        { label: 'Status', value: node.status || '--' },
        { label: 'Timestamp', value: node.timestamp ? new Date(node.timestamp).toLocaleString() : '--' },
      ];
      if (node.metadata) {
        Object.keys(node.metadata).forEach((k) => {
          props.push({ label: k, value: String(node.metadata[k]) });
        });
      }

      props.forEach((p) => {
        const row = document.createElement('div');
        row.className = 'drawer-prop-row';
        const lbl = document.createElement('span');
        lbl.className = 'drawer-prop-label';
        lbl.textContent = p.label;
        const val = document.createElement('span');
        val.className = 'drawer-prop-val mono-cell';
        val.textContent = p.value;
        row.appendChild(lbl);
        row.appendChild(val);
        elements.graphDrawerProperties.appendChild(row);
      });
    }

    // Load pivots from API
    loadNodePivots(node.entity_type, node.entity_id);
  }

  /**
   * Load cross-entity pivot records in drawer.
   */
  async function loadNodePivots(entityType, entityId) {
    if (!elements.graphDrawerPivots) return;
    while (elements.graphDrawerPivots.firstChild) {
      elements.graphDrawerPivots.removeChild(elements.graphDrawerPivots.firstChild);
    }

    try {
      const resp = await window.OsirisApi.getEntityPivots(entityType, entityId);
      const pivots = resp.related_entities || {};
      const keys = Object.keys(pivots);

      if (keys.length === 0) {
        const noPivots = document.createElement('div');
        noPivots.className = 'pivots-empty';
        noPivots.textContent = 'No adjacent pivots found for this entity.';
        elements.graphDrawerPivots.appendChild(noPivots);
        return;
      }

      keys.forEach((groupName) => {
        const groupHeader = document.createElement('h5');
        groupHeader.className = 'pivots-group-title';
        groupHeader.textContent = groupName.replace(/_/g, ' ').toUpperCase();
        elements.graphDrawerPivots.appendChild(groupHeader);

        const items = pivots[groupName] || [];
        items.forEach((item) => {
          const pivotBtn = document.createElement('button');
          pivotBtn.type = 'button';
          pivotBtn.className = 'btn btn-outline btn-xs pivot-btn';
          pivotBtn.textContent = `${item.title || item.type || item.id} (${item.id || item.source_id || ''})`;
          pivotBtn.addEventListener('click', () => {
            expandNode(item.type || groupName, item.id || item.source_id);
          });
          elements.graphDrawerPivots.appendChild(pivotBtn);
        });
      });
    } catch (err) {
      const errEl = document.createElement('div');
      errEl.className = 'alert-box alert-error';
      errEl.textContent = 'Error loading pivots: ' + err.message;
      elements.graphDrawerPivots.appendChild(errEl);
    }
  }

  // ── Advanced Forensic Search ───────────────────────────────────────────────

  /**
   * Execute advanced multi-criteria forensic search.
   */
  async function executeSearch() {
    if (!elements.searchSubmitBtn) return;
    elements.searchSubmitBtn.disabled = true;

    try {
      const entityTypes = [];
      if (document.getElementById('ws-search-chk-events')?.checked) entityTypes.push('events');
      if (document.getElementById('ws-search-chk-procs')?.checked) entityTypes.push('processes');
      if (document.getElementById('ws-search-chk-sessions')?.checked) entityTypes.push('sessions');
      if (document.getElementById('ws-search-chk-detections')?.checked) entityTypes.push('detections');
      if (document.getElementById('ws-search-chk-fim')?.checked) entityTypes.push('fim_deviations');
      if (document.getElementById('ws-search-chk-files')?.checked) entityTypes.push('files');
      if (document.getElementById('ws-search-chk-incidents')?.checked) entityTypes.push('incidents');

      const tags = elements.searchTagInput?.value
        ? elements.searchTagInput.value.split(',').map((t) => t.trim()).filter(Boolean)
        : [];

      const payload = {
        query: elements.searchQueryInput?.value || null,
        command: elements.searchCmdInput?.value || null,
        file_path: elements.searchPathInput?.value || null,
        rule_severity: elements.searchSeveritySelect?.value || null,
        logic: elements.searchLogicSelect?.value || 'and',
        entity_types: entityTypes.length > 0 ? entityTypes : null,
        tags: tags.length > 0 ? tags : null,
        host_id: state.currentHostId || null,
        start_time: elements.searchStartInput?.value ? new Date(elements.searchStartInput.value).toISOString() : null,
        end_time: elements.searchEndInput?.value ? new Date(elements.searchEndInput.value).toISOString() : null,
        limit: 50,
      };

      state.search.filters = payload;
      const resp = await window.OsirisApi.searchAdvanced(payload);
      state.search.results = resp.items || [];
      state.search.total = resp.total;
      renderSearchResults();
    } catch (err) {
      showAlert('Search failed: ' + err.message, true);
    } finally {
      if (elements.searchSubmitBtn) elements.searchSubmitBtn.disabled = false;
    }
  }

  /**
   * Render search results table rows safely.
   */
  function renderSearchResults() {
    const tbody = elements.searchTbody;
    if (!tbody) return;
    while (tbody.firstChild) {
      tbody.removeChild(tbody.firstChild);
    }

    if (elements.searchPageInfo) {
      elements.searchPageInfo.textContent = `Found ${state.search.total} matching forensic records`;
    }

    if (state.search.results.length === 0) {
      if (elements.searchEmptyState) elements.searchEmptyState.classList.remove('hidden');
      return;
    }
    if (elements.searchEmptyState) elements.searchEmptyState.classList.add('hidden');

    state.search.results.forEach((item) => {
      const tr = document.createElement('tr');

      // Type
      const tdType = document.createElement('td');
      const badge = document.createElement('span');
      badge.className = 'badge';
      badge.style.backgroundColor = ENTITY_COLORS[item.entity_type] || '#64748b';
      badge.textContent = item.entity_type;
      tdType.appendChild(badge);
      tr.appendChild(tdType);

      // Title & Description
      const tdDesc = document.createElement('td');
      const titleSpan = document.createElement('strong');
      titleSpan.textContent = item.title;
      const descDiv = document.createElement('div');
      descDiv.className = 'text-muted text-sm mono-cell';
      descDiv.textContent = item.description || '--';
      tdDesc.appendChild(titleSpan);
      tdDesc.appendChild(descDiv);
      tr.appendChild(tdDesc);

      // Timestamp
      const tdTime = document.createElement('td');
      tdTime.className = 'mono-cell text-sm';
      tdTime.textContent = item.timestamp ? new Date(item.timestamp).toLocaleString() : '--';
      tr.appendChild(tdTime);

      // Host
      const tdHost = document.createElement('td');
      tdHost.className = 'mono-cell text-sm';
      tdHost.textContent = item.host_id || '--';
      tr.appendChild(tdHost);

      // Severity / Status
      const tdSev = document.createElement('td');
      if (item.severity) {
        const sBadge = document.createElement('span');
        sBadge.className = `badge badge-${item.severity}`;
        sBadge.textContent = item.severity.toUpperCase();
        tdSev.appendChild(sBadge);
      } else {
        tdSev.textContent = item.status || '--';
      }
      tr.appendChild(tdSev);

      // Actions
      const tdAct = document.createElement('td');
      tdAct.className = 'table-actions';

      const pivotBtn = document.createElement('button');
      pivotBtn.type = 'button';
      pivotBtn.className = 'btn btn-outline btn-xs';
      pivotBtn.textContent = 'Pivot in Graph';
      pivotBtn.addEventListener('click', () => {
        switchTab('graph');
        loadGraph(item.entity_type, item.entity_id);
      });

      const pinBtn = document.createElement('button');
      pinBtn.type = 'button';
      pinBtn.className = 'btn btn-outline btn-xs';
      pinBtn.textContent = 'Pin';
      pinBtn.addEventListener('click', () => pinEvidenceItem(item));

      const tagBtn = document.createElement('button');
      tagBtn.type = 'button';
      tagBtn.className = 'btn btn-outline btn-xs';
      tagBtn.textContent = 'Tag';
      tagBtn.addEventListener('click', () => openTagModal(item.entity_type, item.entity_id, item.host_id));

      const noteBtn = document.createElement('button');
      noteBtn.type = 'button';
      noteBtn.className = 'btn btn-outline btn-xs';
      noteBtn.textContent = 'Note';
      noteBtn.addEventListener('click', () => openNoteModal(item.entity_type, item.entity_id, item.host_id));

      tdAct.appendChild(pivotBtn);
      tdAct.appendChild(pinBtn);
      tdAct.appendChild(tagBtn);
      tdAct.appendChild(noteBtn);
      tr.appendChild(tdAct);

      tbody.appendChild(tr);
    });
  }

  // ── Evidence, Tags & Annotations ───────────────────────────────────────────

  /**
   * Pin an evidence item to active workspace.
   */
  function pinEvidenceItem(item) {
    const existing = state.pinnedEvidence.find(
      (e) => e.entity_type === item.entity_type && e.entity_id === item.entity_id
    );
    if (existing) {
      showAlert('Item is already pinned to this workspace.');
      return;
    }
    state.pinnedEvidence.push({
      entity_type: item.entity_type,
      entity_id: item.entity_id,
      title: item.title,
      description: item.description,
      host_id: item.host_id,
      severity: item.severity,
      pinned_at: new Date().toISOString(),
    });
    saveWorkspace();
    showAlert(`Pinned "${item.title}" to workspace.`);
    updateWorkspaceHeader();
    renderPinnedEvidence();
  }

  /**
   * Unpin an evidence item from active workspace.
   */
  function unpinEvidenceItem(index) {
    state.pinnedEvidence.splice(index, 1);
    saveWorkspace();
    updateWorkspaceHeader();
    renderPinnedEvidence();
  }

  /**
   * Render pinned evidence cards safely.
   */
  function renderPinnedEvidence() {
    const container = elements.pinnedList;
    if (!container) return;
    while (container.firstChild) {
      container.removeChild(container.firstChild);
    }

    if (state.pinnedEvidence.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'text-muted text-sm';
      empty.textContent = 'No evidence pinned yet. Use Search or Graph to pin items.';
      container.appendChild(empty);
      return;
    }

    state.pinnedEvidence.forEach((item, index) => {
      const card = document.createElement('div');
      card.className = 'evidence-card card';

      const hdr = document.createElement('div');
      hdr.className = 'card-header flex-between';

      const typeBadge = document.createElement('span');
      typeBadge.className = 'badge';
      typeBadge.style.backgroundColor = ENTITY_COLORS[item.entity_type] || '#64748b';
      typeBadge.textContent = item.entity_type;

      const title = document.createElement('strong');
      title.textContent = item.title;

      const unpinBtn = document.createElement('button');
      unpinBtn.type = 'button';
      unpinBtn.className = 'btn btn-outline btn-xs';
      unpinBtn.textContent = 'Unpin';
      unpinBtn.addEventListener('click', () => unpinEvidenceItem(index));

      hdr.appendChild(typeBadge);
      hdr.appendChild(title);
      hdr.appendChild(unpinBtn);
      card.appendChild(hdr);

      const body = document.createElement('div');
      body.className = 'card-body';
      const desc = document.createElement('p');
      desc.className = 'text-sm mono-cell';
      desc.textContent = item.description || '--';
      body.appendChild(desc);

      // Card actions (tag & note)
      const actions = document.createElement('div');
      actions.className = 'card-actions flex-gap pt-2';

      const tagBtn = document.createElement('button');
      tagBtn.type = 'button';
      tagBtn.className = 'btn btn-outline btn-xs';
      tagBtn.textContent = 'Tags';
      tagBtn.addEventListener('click', () => openTagModal(item.entity_type, item.entity_id, item.host_id));

      const noteBtn = document.createElement('button');
      noteBtn.type = 'button';
      noteBtn.className = 'btn btn-outline btn-xs';
      noteBtn.textContent = 'Add Note';
      noteBtn.addEventListener('click', () => openNoteModal(item.entity_type, item.entity_id, item.host_id));

      actions.appendChild(tagBtn);
      actions.appendChild(noteBtn);
      body.appendChild(actions);

      card.appendChild(body);
      container.appendChild(card);
    });
  }

  /**
   * Load tags from API and render tags list.
   */
  async function loadTags() {
    try {
      state.tags = await window.OsirisApi.getTags();
      renderTagsList();
      populateTagModalSelect();
    } catch (err) {
      showAlert('Failed to load evidence tags: ' + err.message, true);
    }
  }

  /**
   * Render tag badges in Evidence tab.
   */
  function renderTagsList() {
    const container = elements.tagsList;
    if (!container) return;
    while (container.firstChild) {
      container.removeChild(container.firstChild);
    }

    if (state.tags.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'text-muted text-sm';
      empty.textContent = 'No evidence tags created yet.';
      container.appendChild(empty);
      return;
    }

    state.tags.forEach((t) => {
      const chip = document.createElement('span');
      chip.className = 'tag-chip';
      chip.style.backgroundColor = t.color;
      chip.textContent = `${t.name} (${t.association_count || 0})`;

      const delBtn = document.createElement('button');
      delBtn.type = 'button';
      delBtn.className = 'tag-delete-btn';
      delBtn.textContent = '×';
      delBtn.setAttribute('aria-label', `Delete tag ${t.name}`);
      delBtn.addEventListener('click', async (e) => {
        e.stopPropagation();
        if (window.confirm(`Delete tag "${t.name}"?`)) {
          try {
            await window.OsirisApi.deleteTag(t.id);
            loadTags();
            showAlert(`Tag "${t.name}" deleted.`);
          } catch (err) {
            showAlert('Failed to delete tag: ' + err.message, true);
          }
        }
      });

      chip.appendChild(delBtn);
      container.appendChild(chip);
    });
  }

  /**
   * Handle tag creation form submission.
   */
  async function handleCreateTag() {
    const name = elements.createTagName?.value?.trim();
    if (!name) return;
    const color = elements.createTagColor?.value || '#ef4444';
    const category = elements.createTagCategory?.value?.trim() || 'general';

    try {
      await window.OsirisApi.createTag({ name, color, category });
      if (elements.createTagName) elements.createTagName.value = '';
      loadTags();
      showAlert(`Created tag "${name}".`);
    } catch (err) {
      showAlert('Failed to create tag: ' + err.message, true);
    }
  }

  // ── Modals: Create Workspace, Tag, Note ─────────────────────────────────────

  function openCreateWorkspaceModal() {
    if (!elements.createModal) return;
    elements.createModal.classList.remove('hidden');
    if (elements.createModalName) elements.createModalName.value = '';
    if (elements.createModalDesc) elements.createModalDesc.value = '';
    if (elements.createModalHost) elements.createModalHost.value = '';
  }

  function closeCreateWorkspaceModal() {
    if (elements.createModal) elements.createModal.classList.add('hidden');
  }

  async function handleCreateWorkspaceSubmit(e) {
    if (e) e.preventDefault();
    const name = elements.createModalName?.value?.trim();
    if (!name) return;

    const hostVal = elements.createModalHost?.value?.trim();
    const incidentVal = elements.createModalIncident?.value?.trim();
    const isShared = elements.createModalShared?.checked || false;

    try {
      const payload = {
        name,
        description: elements.createModalDesc?.value?.trim() || null,
        host_id: hostVal || null,
        incident_id: incidentVal || null,
        is_shared: isShared,
        configuration: { active_tab: 'overview' },
      };
      const created = await window.OsirisApi.createWorkspace(payload);
      closeCreateWorkspaceModal();
      showAlert(`Created workspace "${created.name}".`);
      await loadWorkspaces();
      selectWorkspace(created.id);
    } catch (err) {
      showAlert('Failed to create workspace: ' + err.message, true);
    }
  }

  function openRenameWorkspaceModal() {
    if (!state.currentWorkspace || !elements.renameModal) return;
    elements.renameModal.classList.remove('hidden');
    if (elements.renameModalName) {
      elements.renameModalName.value = state.currentWorkspace.name || '';
      elements.renameModalName.focus();
    }
  }

  function closeRenameWorkspaceModal() {
    if (elements.renameModal) elements.renameModal.classList.add('hidden');
  }

  async function handleRenameWorkspaceSubmit(e) {
    if (e) e.preventDefault();
    if (!state.currentWorkspace) return;
    const newName = elements.renameModalName?.value?.trim();
    if (!newName) return;

    try {
      const updated = await window.OsirisApi.updateWorkspace(state.currentWorkspace.id, {
        name: newName,
      });
      state.currentWorkspace = updated;
      closeRenameWorkspaceModal();
      showAlert(`Renamed workspace to "${updated.name}".`);
      await loadWorkspaces();
      selectWorkspace(updated.id);
    } catch (err) {
      showAlert('Failed to rename workspace: ' + err.message, true);
    }
  }

  function openTagModal(entityType, entityId, hostId) {
    state.modalContext = { targetType: entityType, targetId: entityId, hostId };
    if (!elements.tagModal) return;
    elements.tagModal.classList.remove('hidden');
    if (elements.tagModalEvidenceInfo) {
      elements.tagModalEvidenceInfo.textContent = `Target: ${entityType} (${entityId})`;
    }
    populateTagModalSelect();
  }

  function closeTagModal() {
    if (elements.tagModal) elements.tagModal.classList.add('hidden');
  }

  function populateTagModalSelect() {
    if (!elements.tagModalSelect) return;
    while (elements.tagModalSelect.firstChild) {
      elements.tagModalSelect.removeChild(elements.tagModalSelect.firstChild);
    }
    state.tags.forEach((t) => {
      const opt = document.createElement('option');
      opt.value = t.id;
      opt.textContent = `${t.name} (${t.category})`;
      elements.tagModalSelect.appendChild(opt);
    });
  }

  async function handleAssociateTagSubmit(e) {
    if (e) e.preventDefault();
    const tagId = elements.tagModalSelect?.value;
    if (!tagId || !state.modalContext.targetType || !state.modalContext.targetId) return;

    try {
      await window.OsirisApi.associateTag({
        tag_id: tagId,
        evidence_type: state.modalContext.targetType,
        evidence_id: state.modalContext.targetId,
        host_id: state.modalContext.hostId || state.currentHostId || null,
      });
      closeTagModal();
      showAlert('Tag associated successfully.');
      loadTags();
    } catch (err) {
      showAlert('Failed to associate tag: ' + err.message, true);
    }
  }

  function openNoteModal(entityType, entityId, hostId) {
    state.modalContext = { targetType: entityType, targetId: entityId, hostId };
    if (!elements.noteModal) return;
    elements.noteModal.classList.remove('hidden');
    if (elements.noteModalEvidenceInfo) {
      elements.noteModalEvidenceInfo.textContent = `Target: ${entityType} (${entityId})`;
    }
    if (elements.noteModalTextarea) elements.noteModalTextarea.value = '';
  }

  function closeNoteModal() {
    if (elements.noteModal) elements.noteModal.classList.add('hidden');
  }

  async function handleAddNoteSubmit(e) {
    if (e) e.preventDefault();
    const text = elements.noteModalTextarea?.value?.trim();
    if (!text || !state.modalContext.targetType || !state.modalContext.targetId) return;

    try {
      await window.OsirisApi.createNote({
        evidence_type: state.modalContext.targetType,
        evidence_id: state.modalContext.targetId,
        annotation_text: text,
        host_id: state.modalContext.hostId || state.currentHostId || null,
        workspace_id: state.currentWorkspace ? state.currentWorkspace.id : null,
      });
      closeNoteModal();
      showAlert('Analyst note saved.');
    } catch (err) {
      showAlert('Failed to save note: ' + err.message, true);
    }
  }

  // ── Event Bindings ─────────────────────────────────────────────────────────

  function bindEvents() {
    // Workspace dropdown
    elements.workspaceSelect?.addEventListener('change', (e) => {
      const wsId = e.target.value;
      if (wsId) selectWorkspace(wsId);
    });

    // Header buttons
    elements.workspaceNewBtn?.addEventListener('click', openCreateWorkspaceModal);
    elements.workspaceRenameBtn?.addEventListener('click', openRenameWorkspaceModal);
    elements.workspaceSaveBtn?.addEventListener('click', saveWorkspace);
    elements.workspaceArchiveBtn?.addEventListener('click', archiveWorkspace);
    elements.workspaceDeleteBtn?.addEventListener('click', deleteWorkspace);

    // Tab buttons
    elements.tabs.forEach((btn) => {
      btn.addEventListener('click', () => {
        const tab = btn.getAttribute('data-ws-tab');
        if (tab) switchTab(tab);
      });
    });

    // Jump buttons in Overview
    elements.jumpGraphBtn?.addEventListener('click', () => switchTab('graph'));
    elements.jumpSearchBtn?.addEventListener('click', () => switchTab('search'));

    // Graph controls
    elements.graphZoomInBtn?.addEventListener('click', () => {
      state.graph.zoom = Math.min(state.graph.zoom * 1.25, 4.0);
      layoutAndRenderGraph();
    });
    elements.graphZoomOutBtn?.addEventListener('click', () => {
      state.graph.zoom = Math.max(state.graph.zoom / 1.25, 0.25);
      layoutAndRenderGraph();
    });
    elements.graphResetBtn?.addEventListener('click', () => {
      state.graph.zoom = 1.0;
      state.graph.panX = 0;
      state.graph.panY = 0;
      layoutAndRenderGraph();
    });
    elements.graphTypeFilter?.addEventListener('change', () => layoutAndRenderGraph());
    elements.graphDepthSelect?.addEventListener('change', () => loadGraph());
    elements.graphMaxNodesSelect?.addEventListener('change', () => loadGraph());

    elements.graphSearchBtn?.addEventListener('click', () => {
      const q = elements.graphSearchInput?.value?.trim();
      if (q) loadGraph(undefined, q);
    });

    // Graph drawer controls
    elements.graphDrawerCloseBtn?.addEventListener('click', () => {
      elements.graphDrawer?.classList.add('hidden');
      state.graph.selectedNode = null;
      layoutAndRenderGraph();
    });
    elements.graphDrawerExpandBtn?.addEventListener('click', () => {
      if (state.graph.selectedNode) {
        expandNode(state.graph.selectedNode.entity_type, state.graph.selectedNode.entity_id);
      }
    });
    elements.graphDrawerPinBtn?.addEventListener('click', () => {
      if (state.graph.selectedNode) {
        pinEvidenceItem(state.graph.selectedNode);
      }
    });
    elements.graphDrawerTagBtn?.addEventListener('click', () => {
      if (state.graph.selectedNode) {
        openTagModal(
          state.graph.selectedNode.entity_type,
          state.graph.selectedNode.entity_id,
          state.graph.selectedNode.host_id
        );
      }
    });
    elements.graphDrawerNoteBtn?.addEventListener('click', () => {
      if (state.graph.selectedNode) {
        openNoteModal(
          state.graph.selectedNode.entity_type,
          state.graph.selectedNode.entity_id,
          state.graph.selectedNode.host_id
        );
      }
    });

    // Search form
    elements.searchForm?.addEventListener('submit', (e) => {
      e.preventDefault();
      executeSearch();
    });
    elements.searchResetBtn?.addEventListener('click', () => {
      elements.searchForm?.reset();
      state.search.results = [];
      renderSearchResults();
    });

    // Tag manager
    elements.createTagBtn?.addEventListener('click', handleCreateTag);

    // Modals
    elements.createModalCloseBtn?.addEventListener('click', closeCreateWorkspaceModal);
    elements.createModalForm?.addEventListener('submit', handleCreateWorkspaceSubmit);

    elements.renameModalCloseBtn?.addEventListener('click', closeRenameWorkspaceModal);
    elements.renameModalForm?.addEventListener('submit', handleRenameWorkspaceSubmit);

    elements.tagModalCloseBtn?.addEventListener('click', closeTagModal);
    elements.tagModalForm?.addEventListener('submit', handleAssociateTagSubmit);

    elements.noteModalCloseBtn?.addEventListener('click', closeNoteModal);
    elements.noteModalForm?.addEventListener('submit', handleAddNoteSubmit);
  }

  // ── Initialization ─────────────────────────────────────────────────────────

  function init() {
    cacheElements();
    bindEvents();
  }

  // Auto-init when DOM is ready
  if (document && typeof document.addEventListener === 'function') {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', init);
    } else {
      init();
    }
  }

  // Export to global namespace
  const globalObj = typeof window !== 'undefined' ? window : this;
  globalObj.OsirisWorkspace = Object.freeze({
    init,
    loadWorkspaces,
    selectWorkspace,
    saveWorkspace,
    loadGraph,
    expandNode,
    executeSearch,
    openCreateWorkspaceModal,
    closeCreateWorkspaceModal,
    openRenameWorkspaceModal,
    closeRenameWorkspaceModal,
    openTagModal,
    closeTagModal,
    openNoteModal,
    closeNoteModal,
  });

})(typeof window !== 'undefined' ? window : this, typeof document !== 'undefined' ? document : {});
