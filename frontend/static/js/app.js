/**
 * OSIRIS Platform - Main Application Controller
 * Phase 1.6 Step 2
 *
 * Responsibilities:
 * - App initialization & session hydration on page load via /api/auth/me.
 * - Login form handling, submission state, error presentation, and modal controls.
 * - Logout action and client state cleanup.
 * - View navigation switching across Dashboard, Events, Processes, Resources, and Files.
 * - Non-sensitive UI updates (textContent only, no raw HTML injection of untrusted data).
 * - Automatic session-expiry callback handling.
 */

(function (window, document) {
  'use strict';

  // DOM Element References
  let elements = {};

  /**
   * Cache DOM elements used throughout the application.
   */
  function cacheElements() {
    elements = {
      // Header & Auth elements
      userProfileArea: document.getElementById('user-profile-area'),
      userStatusIndicator: document.getElementById('user-status-indicator'),
      userDisplayName: document.getElementById('user-display-name'),
      userRoleBadge: document.getElementById('user-role-badge'),
      loginTriggerBtn: document.getElementById('login-trigger-btn'),
      logoutBtn: document.getElementById('logout-btn'),
      globalAlertContainer: document.getElementById('global-alert-container'),
      globalAlertMessage: document.getElementById('global-alert-message'),

      // Navigation links
      navLinks: document.querySelectorAll('.nav-link[data-view]'),

      // View panels
      viewPanels: {
        dashboard: document.getElementById('view-dashboard'),
        events: document.getElementById('view-events'),
        processes: document.getElementById('view-processes'),
        resources: document.getElementById('view-resources'),
        files: document.getElementById('view-files'),
      },

      // Modal elements
      loginModal: document.getElementById('login-modal-container'),
      loginModalCloseBtn: document.getElementById('login-modal-close'),
      loginForm: document.getElementById('login-form'),
      loginUsernameInput: document.getElementById('login-username'),
      loginPasswordInput: document.getElementById('login-password'),
      loginSubmitBtn: document.getElementById('login-submit-btn'),
      loginErrorBox: document.getElementById('login-error'),
    };
  }

  /**
   * Set UI to an authenticated user state.
   * Uses textContent exclusively to avoid HTML injection risks.
   *
   * @param {Object} user - UserResponse object from /api/auth/me or login
   */
  function setAuthenticatedState(user) {
    if (!user) return;

    if (elements.userStatusIndicator) {
      elements.userStatusIndicator.classList.remove('status-offline');
      elements.userStatusIndicator.classList.add('status-online');
      elements.userStatusIndicator.setAttribute('aria-label', 'Status: Authenticated');
    }

    if (elements.userDisplayName) {
      elements.userDisplayName.textContent = user.display_name || user.username || 'User';
    }

    if (elements.userRoleBadge) {
      elements.userRoleBadge.textContent = user.role || 'viewer';
      elements.userRoleBadge.className = 'badge ' + (user.role === 'admin' ? 'badge-danger' : 'badge-info');
    }

    if (elements.loginTriggerBtn) {
      elements.loginTriggerBtn.classList.add('hidden');
    }

    if (elements.logoutBtn) {
      elements.logoutBtn.classList.remove('hidden');
    }

    closeLoginModal();
    hideGlobalAlert();

    // Hydrate dashboard overview if authenticated
    if (window.OsirisDashboard && typeof window.OsirisDashboard.loadDashboard === 'function') {
      window.OsirisDashboard.loadDashboard();
    }
  }

  /**
   * Set UI to an unauthenticated/guest state.
   */
  function setUnauthenticatedState() {
    if (elements.userStatusIndicator) {
      elements.userStatusIndicator.classList.remove('status-online');
      elements.userStatusIndicator.classList.add('status-offline');
      elements.userStatusIndicator.setAttribute('aria-label', 'Status: Offline');
    }

    if (elements.userDisplayName) {
      elements.userDisplayName.textContent = 'Not Authenticated';
    }

    if (elements.userRoleBadge) {
      elements.userRoleBadge.textContent = 'Guest';
      elements.userRoleBadge.className = 'badge badge-secondary';
    }

    if (elements.loginTriggerBtn) {
      elements.loginTriggerBtn.classList.remove('hidden');
    }

    if (elements.logoutBtn) {
      elements.logoutBtn.classList.add('hidden');
    }

    // Reset dashboard data when unauthenticated
    if (window.OsirisDashboard && typeof window.OsirisDashboard.resetDashboard === 'function') {
      window.OsirisDashboard.resetDashboard();
    }

    // Reset events data when unauthenticated
    if (window.OsirisEvents && typeof window.OsirisEvents.resetEvents === 'function') {
      window.OsirisEvents.resetEvents();
    }

    // Reset processes data when unauthenticated
    if (window.OsirisProcesses && typeof window.OsirisProcesses.resetProcesses === 'function') {
      window.OsirisProcesses.resetProcesses();
    }

    // Reset resources data when unauthenticated
    if (window.OsirisResources && typeof window.OsirisResources.resetResources === 'function') {
      window.OsirisResources.resetResources();
    }

    // Reset files data when unauthenticated
    if (window.OsirisFiles && typeof window.OsirisFiles.resetFiles === 'function') {
      window.OsirisFiles.resetFiles();
    }
  }

  /**
   * Show global notification message.
   * @param {string} message
   */
  function showGlobalAlert(message) {
    if (elements.globalAlertContainer && elements.globalAlertMessage) {
      elements.globalAlertMessage.textContent = message;
      elements.globalAlertContainer.classList.remove('hidden');
    }
  }

  /**
   * Hide global notification banner.
   */
  function hideGlobalAlert() {
    if (elements.globalAlertContainer) {
      elements.globalAlertContainer.classList.add('hidden');
      if (elements.globalAlertMessage) {
        elements.globalAlertMessage.textContent = '';
      }
    }
  }

  /**
   * Open the login modal dialog.
   */
  function openLoginModal() {
    if (elements.loginModal) {
      elements.loginModal.classList.remove('hidden');
      clearLoginError();
      if (elements.loginUsernameInput) {
        elements.loginUsernameInput.focus();
      }
    }
  }

  /**
   * Close the login modal dialog.
   */
  function closeLoginModal() {
    if (elements.loginModal) {
      elements.loginModal.classList.add('hidden');
      clearLoginForm();
      clearLoginError();
    }
  }

  /**
   * Clear login input fields.
   */
  function clearLoginForm() {
    if (elements.loginUsernameInput) elements.loginUsernameInput.value = '';
    if (elements.loginPasswordInput) elements.loginPasswordInput.value = '';
  }

  /**
   * Display an error message in the login dialog.
   * @param {string} message
   */
  function showLoginError(message) {
    if (elements.loginErrorBox) {
      elements.loginErrorBox.textContent = message;
      elements.loginErrorBox.classList.remove('hidden');
    }
  }

  /**
   * Clear error message in the login dialog.
   */
  function clearLoginError() {
    if (elements.loginErrorBox) {
      elements.loginErrorBox.textContent = '';
      elements.loginErrorBox.classList.add('hidden');
    }
  }

  /**
   * Set submitting/loading state on the login submit button.
   * @param {boolean} isSubmitting
   */
  function setLoginSubmitting(isSubmitting) {
    if (elements.loginSubmitBtn) {
      elements.loginSubmitBtn.disabled = isSubmitting;
      const btnText = elements.loginSubmitBtn.querySelector('.btn-text');
      if (btnText) {
        btnText.textContent = isSubmitting ? 'Authenticating...' : 'Sign In';
      }
    }
    if (elements.loginUsernameInput) elements.loginUsernameInput.disabled = isSubmitting;
    if (elements.loginPasswordInput) elements.loginPasswordInput.disabled = isSubmitting;
  }

  /**
   * Handle login form submission.
   * @param {Event} e
   */
  async function handleLoginSubmit(e) {
    e.preventDefault();
    clearLoginError();

    const username = elements.loginUsernameInput ? elements.loginUsernameInput.value.trim() : '';
    const password = elements.loginPasswordInput ? elements.loginPasswordInput.value : '';

    if (!username || !password) {
      showLoginError('Please enter both username and password.');
      return;
    }

    try {
      setLoginSubmitting(true);
      const data = await window.OsirisApi.login(username, password);

      // Authenticated successfully
      if (data && data.user) {
        setAuthenticatedState(data.user);
      } else {
        // Fallback: verify profile via /api/auth/me
        const user = await window.OsirisApi.getCurrentUser();
        setAuthenticatedState(user);
      }
    } catch (err) {
      showLoginError(err.message || 'Invalid username or password.');
    } finally {
      setLoginSubmitting(false);
    }
  }

  /**
   * Handle user logout action.
   */
  function handleLogout() {
    window.OsirisApi.logout();
    setUnauthenticatedState();
    showGlobalAlert('You have been logged out.');
  }

  /**
   * Switch the active view panel in the navigation shell.
   *
   * @param {string} viewName - Target view ID key ('dashboard', 'events', etc.)
   */
  function switchView(viewName) {
    if (!elements.viewPanels[viewName]) return;

    // Update navigation link states
    elements.navLinks.forEach((link) => {
      const isTarget = link.getAttribute('data-view') === viewName;
      if (isTarget) {
        link.classList.add('active');
        link.setAttribute('aria-current', 'page');
      } else {
        link.classList.remove('active');
        link.removeAttribute('aria-current');
      }
    });

    // Toggle view panels
    Object.keys(elements.viewPanels).forEach((key) => {
      const panel = elements.viewPanels[key];
      if (panel) {
        if (key === viewName) {
          panel.classList.remove('hidden');
          panel.classList.add('active');
        } else {
          panel.classList.add('hidden');
          panel.classList.remove('active');
        }
      }
    });

    // Refresh dashboard data when dashboard view becomes active
    if (viewName === 'dashboard' && window.OsirisDashboard && typeof window.OsirisDashboard.loadDashboard === 'function') {
      window.OsirisDashboard.loadDashboard();
    }

    // Load events data when events view becomes active
    if (viewName === 'events' && window.OsirisEvents && typeof window.OsirisEvents.loadEvents === 'function') {
      window.OsirisEvents.loadEvents();
    }

    // Load processes data when processes view becomes active
    if (viewName === 'processes' && window.OsirisProcesses && typeof window.OsirisProcesses.loadProcesses === 'function') {
      window.OsirisProcesses.loadProcesses();
    }

    // Load resources data when resources view becomes active
    if (viewName === 'resources' && window.OsirisResources && typeof window.OsirisResources.loadResources === 'function') {
      window.OsirisResources.loadResources();
    }

    // Load files data when files view becomes active
    if (viewName === 'files' && window.OsirisFiles && typeof window.OsirisFiles.loadFiles === 'function') {
      window.OsirisFiles.loadFiles();
    }
  }

  /**
   * Bind event listeners for UI interactions.
   */
  function bindEvents() {
    // Navigation link clicks
    elements.navLinks.forEach((link) => {
      link.addEventListener('click', () => {
        const view = link.getAttribute('data-view');
        if (view) {
          switchView(view);
        }
      });
    });

    // Login modal trigger & close buttons
    if (elements.loginTriggerBtn) {
      elements.loginTriggerBtn.addEventListener('click', openLoginModal);
    }
    if (elements.loginModalCloseBtn) {
      elements.loginModalCloseBtn.addEventListener('click', closeLoginModal);
    }

    // Close modal when clicking backdrop outside dialog
    if (elements.loginModal) {
      elements.loginModal.addEventListener('click', (e) => {
        if (e.target === elements.loginModal) {
          closeLoginModal();
        }
      });
    }

    // Login form submission
    if (elements.loginForm) {
      elements.loginForm.addEventListener('submit', handleLoginSubmit);
    }

    // Logout button
    if (elements.logoutBtn) {
      elements.logoutBtn.addEventListener('click', handleLogout);
    }

    // Register API authentication expiry callback (401 handler)
    if (window.OsirisApi && typeof window.OsirisApi.onAuthExpired === 'function') {
      window.OsirisApi.onAuthExpired(() => {
        setUnauthenticatedState();
        showGlobalAlert('Your session has expired. Please log in again.');
        openLoginModal();
      });
    }
  }

  /**
   * Initialize application state on page load.
   */
  async function initApp() {
    cacheElements();
    bindEvents();

    // Check for existing session token
    const token = window.OsirisApi ? window.OsirisApi.getToken() : null;

    if (!token) {
      setUnauthenticatedState();
      return;
    }

    // Validate stored token against backend
    try {
      const user = await window.OsirisApi.getCurrentUser();
      setAuthenticatedState(user);
    } catch {
      // Token is expired, tampered, or invalid
      setUnauthenticatedState();
    }
  }

  // Run initialization when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initApp);
  } else {
    initApp();
  }

  // Export minimal app controller for testing/extension
  window.OsirisApp = Object.freeze({
    switchView,
    setAuthenticatedState,
    setUnauthenticatedState,
    openLoginModal,
    closeLoginModal,
  });

})(typeof window !== 'undefined' ? window : this, typeof document !== 'undefined' ? document : {});
