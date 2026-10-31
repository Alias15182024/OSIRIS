/**
 * OSIRIS Platform - Client API & Authentication Foundation
 * Phase 1.6 Step 2
 *
 * Responsibilities:
 * - Secure sessionStorage token management (strictly session-scoped, no plaintext credentials).
 * - Centralized fetchWithAuth helper with automatic Bearer token injection.
 * - 401 Unauthorized handling and session expiry notification callback.
 * - Login, current-user, health, and status endpoint wrappers.
 * - Centralized endpoint URI constants.
 */

(function (window) {
  'use strict';

  const TOKEN_STORAGE_KEY = 'osiris_access_token';

  const ENDPOINTS = Object.freeze({
    HEALTH: '/health',
    STATUS: '/api/status',
    LOGIN: '/api/auth/login',
    ME: '/api/auth/me',
    EVENTS: '/api/events',
    PROCESSES: '/api/processes',
    RESOURCES: '/api/resources',
    FILES: '/api/files',
    SESSIONS: '/api/sessions',
    TIMELINE: '/api/timeline',
    DETECTIONS: '/api/detections',
    FIM_BASELINES: '/api/fim/baselines',
    FIM_DEVIATIONS: '/api/fim/deviations',
    FIM_VERIFY: '/api/fim/verify',
    INCIDENTS: '/api/incidents',
    WORKSPACES: '/api/workspaces',
    GRAPH: '/api/graph',
    SEARCH: '/api/search',
    ANNOTATIONS: '/api/annotations',
  });

  let authExpiredCallback = null;

  /**
   * Retrieve the current access token from sessionStorage.
   * @returns {string|null}
   */
  function getToken() {
    try {
      return sessionStorage.getItem(TOKEN_STORAGE_KEY);
    } catch {
      return null;
    }
  }

  /**
   * Store the access token in sessionStorage.
   * Never stores passwords or user credentials. Scoped strictly to session.
   * @param {string} token
   */
  function setToken(token) {
    if (typeof token === 'string' && token.length > 0) {
      try {
        sessionStorage.setItem(TOKEN_STORAGE_KEY, token);
      } catch (err) {
        // Storage unavailable or disabled
      }
    }
  }

  /**
   * Remove access token from sessionStorage.
   */
  function clearToken() {
    try {
      sessionStorage.removeItem(TOKEN_STORAGE_KEY);
    } catch {
      // Storage unavailable
    }
  }

  /**
   * Register a callback for authentication expiry (HTTP 401).
   * @param {Function} callback
   */
  function onAuthExpired(callback) {
    if (typeof callback === 'function') {
      authExpiredCallback = callback;
    }
  }

  /**
   * Execute a fetch request with automatic Authorization Bearer header injection.
   *
   * @param {string} url - Target URL path
   * @param {RequestInit} [options={}] - Standard fetch options
   * @returns {Promise<any>} Parsed response data
   */
  async function fetchWithAuth(url, options = {}) {
    const token = getToken();
    const headers = new Headers(options.headers || {});

    // Set JSON Content-Type if body is a string and header is not explicitly set
    if (options.body && typeof options.body === 'string' && !headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json');
    }

    if (token && !headers.has('Authorization')) {
      headers.set('Authorization', `Bearer ${token}`);
    }

    const mergedOptions = {
      ...options,
      headers,
    };

    const response = await fetch(url, mergedOptions);

    // Handle session expiration / invalid token (401)
    if (response.status === 401) {
      clearToken();
      if (typeof authExpiredCallback === 'function') {
        authExpiredCallback();
      }
    }

    const contentType = response.headers.get('content-type') || '';
    let data = null;

    if (contentType.includes('application/json')) {
      try {
        data = await response.json();
      } catch {
        data = null;
      }
    } else {
      try {
        data = await response.text();
      } catch {
        data = null;
      }
    }

    if (!response.ok) {
      let message = `Request failed with status ${response.status}`;
      if (data && typeof data === 'object') {
        if (typeof data.detail === 'string') {
          message = data.detail;
        } else if (Array.isArray(data.detail)) {
          message = data.detail.map(d => d.msg || JSON.stringify(d)).join('; ');
        }
      }
      const error = new Error(message);
      error.status = response.status;
      error.data = data;
      throw error;
    }

    return data;
  }

  /**
   * Submit credentials to authenticate and receive an access token.
   *
   * @param {string} username
   * @param {string} password
   * @returns {Promise<Object>} TokenResponse object
   */
  async function login(username, password) {
    if (!username || !password) {
      throw new Error('Username and password are required');
    }

    const response = await fetch(ENDPOINTS.LOGIN, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ username, password }),
    });

    const contentType = response.headers.get('content-type') || '';
    let data = null;
    if (contentType.includes('application/json')) {
      try {
        data = await response.json();
      } catch {
        data = null;
      }
    } else {
      data = await response.text();
    }

    if (!response.ok) {
      let message = 'Login failed';
      if (data && typeof data === 'object' && typeof data.detail === 'string') {
        message = data.detail;
      }
      const error = new Error(message);
      error.status = response.status;
      error.data = data;
      throw error;
    }

    // Securely persist access token in sessionStorage only
    if (data && data.access_token) {
      setToken(data.access_token);
    }

    return data;
  }

  /**
   * Fetch profile for current authenticated user.
   * @returns {Promise<Object>} UserResponse object
   */
  async function getCurrentUser() {
    return await fetchWithAuth(ENDPOINTS.ME);
  }

  /**
   * Log out the current user by clearing stored credentials.
   */
  function logout() {
    clearToken();
  }

  /**
   * Platform liveness health check.
   * @returns {Promise<Object>}
   */
  async function getHealth() {
    const response = await fetch(ENDPOINTS.HEALTH);
    return await response.json();
  }

  /**
   * Detailed platform status check (database connection status).
   * @returns {Promise<Object>}
   */
  async function getStatus() {
    const response = await fetch(ENDPOINTS.STATUS);
    return await response.json();
  }

  /**
   * Fetch paginated user sessions with optional filtering parameters.
   * @param {Object} [params={}]
   * @returns {Promise<Object>} PaginatedSessionResponse
   */
  async function getSessions(params = {}) {
    const query = new URLSearchParams();
    Object.keys(params).forEach((key) => {
      const val = params[key];
      if (val !== undefined && val !== null && val !== '') {
        query.append(key, String(val));
      }
    });
    const qs = query.toString();
    const url = qs ? `${ENDPOINTS.SESSIONS}?${qs}` : ENDPOINTS.SESSIONS;
    return await fetchWithAuth(url);
  }

  /**
   * Fetch single user session detail by UUID.
   * @param {string} sessionId
   * @returns {Promise<Object>} SessionDetailResponse
   */
  async function getSession(sessionId) {
    if (!sessionId) {
      throw new Error('sessionId is required');
    }
    return await fetchWithAuth(`${ENDPOINTS.SESSIONS}/${encodeURIComponent(sessionId)}`);
  }

  /**
   * Fetch paginated security detections with optional filtering parameters.
   * @param {Object} [params={}]
   * @returns {Promise<Object>} PaginatedDetectionResponse
   */
  async function getDetections(params = {}) {
    const query = new URLSearchParams();
    Object.keys(params).forEach((key) => {
      const val = params[key];
      if (val !== undefined && val !== null && val !== '') {
        query.append(key, String(val));
      }
    });
    const qs = query.toString();
    const url = qs ? `${ENDPOINTS.DETECTIONS}?${qs}` : ENDPOINTS.DETECTIONS;
    return await fetchWithAuth(url);
  }

  /**
   * Fetch single detection record by UUID.
   * @param {string} detectionId
   * @returns {Promise<Object>} DetectionResponse
   */
  async function getDetection(detectionId) {
    if (!detectionId) {
      throw new Error('detectionId is required');
    }
    return await fetchWithAuth(`${ENDPOINTS.DETECTIONS}/${encodeURIComponent(detectionId)}`);
  }

  /**
   * Acknowledge a detection alert.
   * @param {string} detectionId
   * @param {string} [notes]
   * @returns {Promise<Object>} DetectionResponse
   */
  async function acknowledgeDetection(detectionId, notes = null) {
    if (!detectionId) {
      throw new Error('detectionId is required');
    }
    const options = {
      method: 'POST',
      body: JSON.stringify(notes ? { notes } : {}),
    };
    return await fetchWithAuth(`${ENDPOINTS.DETECTIONS}/${encodeURIComponent(detectionId)}/acknowledge`, options);
  }

  /**
   * Fetch registered declarative detection rules.
   * @param {Object} [params={}]
   * @returns {Promise<Array>} List of DetectionRuleResponse
   */
  async function getDetectionRules(params = {}) {
    const query = new URLSearchParams();
    Object.keys(params).forEach((key) => {
      const val = params[key];
      if (val !== undefined && val !== null && val !== '') {
        query.append(key, String(val));
      }
    });
    const qs = query.toString();
    const url = qs ? `${ENDPOINTS.DETECTIONS}/rules?${qs}` : `${ENDPOINTS.DETECTIONS}/rules`;
    return await fetchWithAuth(url);
  }

  /**
   * Fetch paginated FIM baselines.
   * @param {Object} [params={}]
   * @returns {Promise<Object>} BaselineListResponse
   */
  async function getFimBaselines(params = {}) {
    const query = new URLSearchParams();
    Object.keys(params).forEach((key) => {
      const val = params[key];
      if (val !== undefined && val !== null && val !== '') {
        query.append(key, String(val));
      }
    });
    const qs = query.toString();
    const url = qs ? `${ENDPOINTS.FIM_BASELINES}?${qs}` : ENDPOINTS.FIM_BASELINES;
    return await fetchWithAuth(url);
  }

  /**
   * Fetch single FIM baseline by ID.
   * @param {string} baselineId
   * @returns {Promise<Object>} BaselineDetailResponse
   */
  async function getFimBaseline(baselineId) {
    if (!baselineId) {
      throw new Error('baselineId is required');
    }
    return await fetchWithAuth(`${ENDPOINTS.FIM_BASELINES}/${encodeURIComponent(baselineId)}`);
  }

  /**
   * Create a new FIM baseline.
   * @param {Object} payload
   * @returns {Promise<Object>} BaselineResponse
   */
  async function createFimBaseline(payload = {}) {
    const options = {
      method: 'POST',
      body: JSON.stringify(payload),
    };
    return await fetchWithAuth(ENDPOINTS.FIM_BASELINES, options);
  }

  /**
   * Fetch files for a FIM baseline.
   * @param {string} baselineId
   * @param {Object} [params={}]
   * @returns {Promise<Object>} BaselineFileListResponse
   */
  async function getFimBaselineFiles(baselineId, params = {}) {
    if (!baselineId) {
      throw new Error('baselineId is required');
    }
    const query = new URLSearchParams();
    Object.keys(params).forEach((key) => {
      const val = params[key];
      if (val !== undefined && val !== null && val !== '') {
        query.append(key, String(val));
      }
    });
    const qs = query.toString();
    const url = qs
      ? `${ENDPOINTS.FIM_BASELINES}/${encodeURIComponent(baselineId)}/files?${qs}`
      : `${ENDPOINTS.FIM_BASELINES}/${encodeURIComponent(baselineId)}/files`;
    return await fetchWithAuth(url);
  }

  /**
   * Fetch paginated FIM deviations.
   * @param {Object} [params={}]
   * @returns {Promise<Object>} DeviationListResponse
   */
  async function getFimDeviations(params = {}) {
    const query = new URLSearchParams();
    Object.keys(params).forEach((key) => {
      const val = params[key];
      if (val !== undefined && val !== null && val !== '') {
        query.append(key, String(val));
      }
    });
    const qs = query.toString();
    const url = qs ? `${ENDPOINTS.FIM_DEVIATIONS}?${qs}` : ENDPOINTS.FIM_DEVIATIONS;
    return await fetchWithAuth(url);
  }

  /**
   * Fetch single FIM deviation by ID.
   * @param {string} deviationId
   * @returns {Promise<Object>} DeviationDetailResponse
   */
  async function getFimDeviation(deviationId) {
    if (!deviationId) {
      throw new Error('deviationId is required');
    }
    return await fetchWithAuth(`${ENDPOINTS.FIM_DEVIATIONS}/${encodeURIComponent(deviationId)}`);
  }

  /**
   * Trigger FIM verification against a baseline.
   * @param {Object} payload
   * @returns {Promise<Object>} VerifyResponse
   */
  async function verifyFim(payload = {}) {
    const options = {
      method: 'POST',
      body: JSON.stringify(payload),
    };
    return await fetchWithAuth(ENDPOINTS.FIM_VERIFY, options);
  }

  /**
   * Fetch paginated security incidents with optional query filters.
   * @param {Object} [params={}]
   * @returns {Promise<Object>} PaginatedIncidentResponse
   */
  async function getIncidents(params = {}) {
    const searchParams = new URLSearchParams();
    Object.entries(params).forEach(([key, val]) => {
      if (val !== undefined && val !== null && val !== '') {
        searchParams.set(key, String(val));
      }
    });
    const qs = searchParams.toString();
    const url = qs ? `${ENDPOINTS.INCIDENTS}?${qs}` : ENDPOINTS.INCIDENTS;
    return await fetchWithAuth(url);
  }

  /**
   * Fetch single incident detail by ID.
   * @param {string} incidentId
   * @returns {Promise<Object>} IncidentDetailResponse
   */
  async function getIncident(incidentId) {
    return await fetchWithAuth(`${ENDPOINTS.INCIDENTS}/${encodeURIComponent(incidentId)}`);
  }

  /**
   * Create a new incident.
   * @param {Object} payload
   * @returns {Promise<Object>} IncidentResponse
   */
  async function createIncident(payload = {}) {
    const options = {
      method: 'POST',
      body: JSON.stringify(payload),
    };
    return await fetchWithAuth(ENDPOINTS.INCIDENTS, options);
  }

  /**
   * Update incident metadata or assignment.
   * @param {string} incidentId
   * @param {Object} payload
   * @returns {Promise<Object>} IncidentResponse
   */
  async function updateIncident(incidentId, payload = {}) {
    const options = {
      method: 'PATCH',
      body: JSON.stringify(payload),
    };
    return await fetchWithAuth(`${ENDPOINTS.INCIDENTS}/${encodeURIComponent(incidentId)}`, options);
  }

  /**
   * Transition incident status.
   * @param {string} incidentId
   * @param {Object} payload
   * @returns {Promise<Object>} IncidentResponse
   */
  async function transitionIncidentStatus(incidentId, payload = {}) {
    const options = {
      method: 'POST',
      body: JSON.stringify(payload),
    };
    return await fetchWithAuth(`${ENDPOINTS.INCIDENTS}/${encodeURIComponent(incidentId)}/status`, options);
  }

  /**
   * Escalate incident severity.
   * @param {string} incidentId
   * @param {Object} payload
   * @returns {Promise<Object>} IncidentResponse
   */
  async function escalateIncidentSeverity(incidentId, payload = {}) {
    const options = {
      method: 'POST',
      body: JSON.stringify(payload),
    };
    return await fetchWithAuth(`${ENDPOINTS.INCIDENTS}/${encodeURIComponent(incidentId)}/severity`, options);
  }

  /**
   * Assign an incident to an analyst.
   * @param {string} incidentId
   * @param {Object} payload
   * @returns {Promise<Object>} IncidentResponse
   */
  async function assignIncident(incidentId, payload = {}) {
    const options = {
      method: 'POST',
      body: JSON.stringify(payload),
    };
    return await fetchWithAuth(`${ENDPOINTS.INCIDENTS}/${encodeURIComponent(incidentId)}/assign`, options);
  }

  /**
   * Append an investigation note to an incident.
   * @param {string} incidentId
   * @param {Object} payload
   * @returns {Promise<Object>} IncidentHistoryResponse
   */
  async function addIncidentNote(incidentId, payload = {}) {
    const options = {
      method: 'POST',
      body: JSON.stringify(payload),
    };
    return await fetchWithAuth(`${ENDPOINTS.INCIDENTS}/${encodeURIComponent(incidentId)}/notes`, options);
  }

  /**
   * Get audit history for an incident.
   * @param {string} incidentId
   * @returns {Promise<Array>} IncidentHistoryResponse[]
   */
  async function getIncidentHistory(incidentId) {
    return await fetchWithAuth(`${ENDPOINTS.INCIDENTS}/${encodeURIComponent(incidentId)}/history`);
  }

  /**
   * List evidence attached to an incident.
   * @param {string} incidentId
   * @param {Object} [params={}]
   * @returns {Promise<Array>} IncidentEvidenceResponse[]
   */
  async function getIncidentEvidence(incidentId, params = {}) {
    const searchParams = new URLSearchParams();
    Object.entries(params).forEach(([key, val]) => {
      if (val !== undefined && val !== null && val !== '') {
        searchParams.set(key, String(val));
      }
    });
    const qs = searchParams.toString();
    const url = qs
      ? `${ENDPOINTS.INCIDENTS}/${encodeURIComponent(incidentId)}/evidence?${qs}`
      : `${ENDPOINTS.INCIDENTS}/${encodeURIComponent(incidentId)}/evidence`;
    return await fetchWithAuth(url);
  }

  /**
   * Attach evidence to an incident.
   * @param {string} incidentId
   * @param {Object} payload
   * @returns {Promise<Object>} IncidentEvidenceResponse
   */
  async function addIncidentEvidence(incidentId, payload = {}) {
    const options = {
      method: 'POST',
      body: JSON.stringify(payload),
    };
    return await fetchWithAuth(`${ENDPOINTS.INCIDENTS}/${encodeURIComponent(incidentId)}/evidence`, options);
  }

  /**
   * List forensic events attached to an incident.
   * @param {string} incidentId
   * @returns {Promise<Array>} IncidentEventResponse[]
   */
  async function getIncidentEvents(incidentId) {
    return await fetchWithAuth(`${ENDPOINTS.INCIDENTS}/${encodeURIComponent(incidentId)}/events`);
  }

  /**
   * Link an event to an incident.
   * @param {string} incidentId
   * @param {Object} payload
   * @returns {Promise<Object>} IncidentEventResponse
   */
  async function linkIncidentEvent(incidentId, payload = {}) {
    const options = {
      method: 'POST',
      body: JSON.stringify(payload),
    };
    return await fetchWithAuth(`${ENDPOINTS.INCIDENTS}/${encodeURIComponent(incidentId)}/events`, options);
  }

  /**
   * Get or export investigation report.
   * @param {string} incidentId
   * @param {string} [format='json']
   * @returns {Promise<Object|string>}
   */
  async function getIncidentReport(incidentId, format = 'json') {
    return await fetchWithAuth(
      `${ENDPOINTS.INCIDENTS}/${encodeURIComponent(incidentId)}/report?format=${encodeURIComponent(format)}`
    );
  }

  // ── Workspaces ─────────────────────────────────────────────────────────────

  /**
   * List workspaces accessible to current user.
   * @param {Object} [params]
   * @returns {Promise<Object>} PaginatedWorkspaceResponse
   */
  async function getWorkspaces(params = {}) {
    const qs = new URLSearchParams();
    if (params.status) qs.set('status', params.status);
    if (params.host_id) qs.set('host_id', params.host_id);
    if (params.incident_id) qs.set('incident_id', params.incident_id);
    if (params.limit !== undefined) qs.set('limit', params.limit);
    if (params.offset !== undefined) qs.set('offset', params.offset);
    const query = qs.toString();
    const url = query ? `${ENDPOINTS.WORKSPACES}?${query}` : ENDPOINTS.WORKSPACES;
    return await fetchWithAuth(url);
  }

  /**
   * Get workspace by ID.
   * @param {string} workspaceId
   * @returns {Promise<Object>} WorkspaceResponse
   */
  async function getWorkspace(workspaceId) {
    return await fetchWithAuth(`${ENDPOINTS.WORKSPACES}/${encodeURIComponent(workspaceId)}`);
  }

  /**
   * Create an investigation workspace.
   * @param {Object} payload
   * @returns {Promise<Object>} WorkspaceResponse
   */
  async function createWorkspace(payload = {}) {
    return await fetchWithAuth(ENDPOINTS.WORKSPACES, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  /**
   * Update workspace details or configuration.
   * @param {string} workspaceId
   * @param {Object} payload
   * @returns {Promise<Object>} WorkspaceResponse
   */
  async function updateWorkspace(workspaceId, payload = {}) {
    return await fetchWithAuth(`${ENDPOINTS.WORKSPACES}/${encodeURIComponent(workspaceId)}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    });
  }

  /**
   * Archive an investigation workspace.
   * @param {string} workspaceId
   * @returns {Promise<Object>} WorkspaceResponse
   */
  async function archiveWorkspace(workspaceId) {
    return await fetchWithAuth(`${ENDPOINTS.WORKSPACES}/${encodeURIComponent(workspaceId)}/archive`, {
      method: 'POST',
    });
  }

  /**
   * Delete an investigation workspace.
   * @param {string} workspaceId
   * @returns {Promise<null>}
   */
  async function deleteWorkspace(workspaceId) {
    return await fetchWithAuth(`${ENDPOINTS.WORKSPACES}/${encodeURIComponent(workspaceId)}`, {
      method: 'DELETE',
    });
  }

  // ── Entity Graph ────────────────────────────────────────────────────────────

  /**
   * Get initial or entity-centric graph.
   * @param {Object} [params]
   * @returns {Promise<Object>} GraphDataResponse
   */
  async function getGraph(params = {}) {
    const qs = new URLSearchParams();
    if (params.host_id) qs.set('host_id', params.host_id);
    if (params.root_entity_type) qs.set('root_entity_type', params.root_entity_type);
    if (params.root_entity_id) qs.set('root_entity_id', params.root_entity_id);
    if (params.depth !== undefined) qs.set('depth', params.depth);
    if (params.max_nodes !== undefined) qs.set('max_nodes', params.max_nodes);
    const query = qs.toString();
    const url = query ? `${ENDPOINTS.GRAPH}?${query}` : ENDPOINTS.GRAPH;
    return await fetchWithAuth(url);
  }

  /**
   * Expand adjacent relationships from a graph node.
   * @param {Object} payload
   * @returns {Promise<Object>} GraphDataResponse
   */
  async function expandGraph(payload = {}) {
    return await fetchWithAuth(`${ENDPOINTS.GRAPH}/expand`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  /**
   * Get direct cross-entity pivot records for an entity.
   * @param {string} entityType
   * @param {string} entityId
   * @returns {Promise<Object>} EntityPivotResponse
   */
  async function getEntityPivots(entityType, entityId) {
    return await fetchWithAuth(
      `${ENDPOINTS.GRAPH}/pivot/${encodeURIComponent(entityType)}/${encodeURIComponent(entityId)}`
    );
  }

  // ── Advanced Search ─────────────────────────────────────────────────────────

  /**
   * Execute multi-criteria advanced forensic search.
   * @param {Object} payload SearchFilter
   * @returns {Promise<Object>} SearchResultResponse
   */
  async function searchAdvanced(payload = {}) {
    return await fetchWithAuth(`${ENDPOINTS.SEARCH}/advanced`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  /**
   * Convenience quick search.
   * @param {string} query
   * @param {string} [hostId]
   * @param {number} [limit=50]
   * @param {number} [offset=0]
   * @returns {Promise<Object>} SearchResultResponse
   */
  async function quickSearch(query, hostId, limit = 50, offset = 0) {
    const qs = new URLSearchParams();
    if (query) qs.set('q', query);
    if (hostId) qs.set('host_id', hostId);
    if (limit !== undefined) qs.set('limit', limit);
    if (offset !== undefined) qs.set('offset', offset);
    return await fetchWithAuth(`${ENDPOINTS.SEARCH}?${qs.toString()}`);
  }

  // ── Annotations & Tags ──────────────────────────────────────────────────────

  /**
   * List available evidence tags.
   * @param {string} [category]
   * @returns {Promise<Array>} TagResponse[]
   */
  async function getTags(category) {
    const url = category
      ? `${ENDPOINTS.ANNOTATIONS}/tags?category=${encodeURIComponent(category)}`
      : `${ENDPOINTS.ANNOTATIONS}/tags`;
    return await fetchWithAuth(url);
  }

  /**
   * Create a new reusable evidence tag.
   * @param {Object} payload TagCreateRequest
   * @returns {Promise<Object>} TagResponse
   */
  async function createTag(payload = {}) {
    return await fetchWithAuth(`${ENDPOINTS.ANNOTATIONS}/tags`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  /**
   * Delete an evidence tag.
   * @param {string} tagId
   * @returns {Promise<null>}
   */
  async function deleteTag(tagId) {
    return await fetchWithAuth(`${ENDPOINTS.ANNOTATIONS}/tags/${encodeURIComponent(tagId)}`, {
      method: 'DELETE',
    });
  }

  /**
   * Update an evidence tag.
   * @param {string} tagId
   * @param {Object} payload TagUpdateRequest
   * @returns {Promise<Object>} TagResponse
   */
  async function updateTag(tagId, payload = {}) {
    return await fetchWithAuth(`${ENDPOINTS.ANNOTATIONS}/tags/${encodeURIComponent(tagId)}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    });
  }

  /**
   * Attach tag to an evidence item.
   * @param {Object} payload TagAssociateRequest
   * @returns {Promise<Object>} TagAssociationResponse
   */
  async function associateTag(payload = {}) {
    return await fetchWithAuth(`${ENDPOINTS.ANNOTATIONS}/tags/associate`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  /**
   * Remove a tag from an evidence item.
   * @param {Object} payload TagDisassociateRequest
   * @returns {Promise<Object>}
   */
  async function disassociateTag(payload = {}) {
    return await fetchWithAuth(`${ENDPOINTS.ANNOTATIONS}/tags/disassociate`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  /**
   * Get tags and analyst notes for an evidence item.
   * @param {string} evidenceType
   * @param {string} evidenceId
   * @returns {Promise<Object>} EvidenceAnnotationsResponse
   */
  async function getAnnotations(evidenceType, evidenceId) {
    const qs = new URLSearchParams({
      evidence_type: evidenceType,
      evidence_id: evidenceId,
    });
    return await fetchWithAuth(`${ENDPOINTS.ANNOTATIONS}?${qs.toString()}`);
  }

  /**
   * Add an analyst note to an evidence item.
   * @param {Object} payload AnnotationNoteCreateRequest
   * @returns {Promise<Object>} AnnotationNoteResponse
   */
  async function createNote(payload = {}) {
    return await fetchWithAuth(`${ENDPOINTS.ANNOTATIONS}/notes`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  /**
   * Delete an analyst note.
   * @param {string} noteId
   * @returns {Promise<null>}
   */
  async function deleteNote(noteId) {
    return await fetchWithAuth(`${ENDPOINTS.ANNOTATIONS}/notes/${encodeURIComponent(noteId)}`, {
      method: 'DELETE',
    });
  }

  /**
   * Update an analyst note.
   * @param {string} noteId
   * @param {Object} payload AnnotationNoteUpdateRequest
   * @returns {Promise<Object>} AnnotationNoteResponse
   */
  async function updateNote(noteId, payload = {}) {
    return await fetchWithAuth(`${ENDPOINTS.ANNOTATIONS}/notes/${encodeURIComponent(noteId)}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    });
  }

  // Export to global namespace
  window.OsirisApi = Object.freeze({
    ENDPOINTS,
    getToken,
    setToken,
    clearToken,
    onAuthExpired,
    fetchWithAuth,
    login,
    getCurrentUser,
    logout,
    getHealth,
    getStatus,
    getSessions,
    getSession,
    getDetections,
    getDetection,
    acknowledgeDetection,
    getDetectionRules,
    getFimBaselines,
    getFimBaseline,
    createFimBaseline,
    getFimBaselineFiles,
    getFimDeviations,
    getFimDeviation,
    verifyFim,
    getIncidents,
    getIncident,
    createIncident,
    updateIncident,
    transitionIncidentStatus,
    escalateIncidentSeverity,
    assignIncident,
    addIncidentNote,
    getIncidentHistory,
    getIncidentEvidence,
    addIncidentEvidence,
    getIncidentEvents,
    linkIncidentEvent,
    getIncidentReport,
    getWorkspaces,
    getWorkspace,
    createWorkspace,
    updateWorkspace,
    archiveWorkspace,
    deleteWorkspace,
    getGraph,
    expandGraph,
    getEntityPivots,
    searchAdvanced,
    quickSearch,
    getTags,
    createTag,
    updateTag,
    deleteTag,
    associateTag,
    disassociateTag,
    getAnnotations,
    createNote,
    updateNote,
    deleteNote,
  });

})(typeof window !== 'undefined' ? window : this);
