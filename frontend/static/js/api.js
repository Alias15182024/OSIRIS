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
  });

})(typeof window !== 'undefined' ? window : this);
