/**
 * Entra Auth Tracer - UI Logic
 * Handles the extension popup interface
 */

import EntraClaimsDecoder from './EntraClaimsDecoder.js';
import OAuthDecoder from './OAuthDecoder.js';
import SamlDecoder from './SamlDecoder.js';
import FlowCorrelator from './FlowCorrelator.js';
import Sanitize from './Sanitize.js';
import Exporters from './Exporters.js';

class EntraAuthTracerUI {
  constructor() {
    this.currentRequests = [];
    this.selectedRequest = null;
    this.viewMode = 'timeline'; // 'list' | 'timeline'
    this.filters = {
      search: '',
      method: '',
      flow: '',
      status: ''
    };
    
    this.init();
  }

  /**
   * Initialize the UI
   */
  init() {
    this.bindEvents();
    this.loadData();
    this.startPeriodicUpdate();
    this.initSplitter();
    this.initPopupResize();
    this.initPopout();

    // Reset the toolbar icon badge whenever the popup is opened
    chrome.runtime.sendMessage({ action: 'resetBadge' });

    // Populate version and GitHub link in the status bar footer
    const manifest = chrome.runtime.getManifest();
    const versionEl = document.getElementById('versionInfo');
    if (versionEl) {
      versionEl.innerHTML =
        `v${this.escapeHtml(manifest.version)} &middot; Created by <a class="repo-link" href="https://blog.darrenjrobinson.com" target="_blank" rel="noopener noreferrer">Darren J Robinson</a> &middot; <a class="repo-link" href="${Exporters.REPO_URL}" target="_blank" rel="noopener noreferrer">GitHub</a>`;
    }
  }

  // ─── Copy helpers ────────────────────────────────────────────────────────────

  /**
   * Return HTML for a small clipboard copy button storing text in a data attribute.
   */
  makeCopyBtn(text, tooltip = 'Copy') {
    const safe = String(text)
      .replace(/&/g, '&amp;')
      .replace(/"/g, '&quot;');
    return `<button class="copy-btn" title="${tooltip}" data-copy="${safe}" aria-label="${tooltip}">` +
      `<svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">` +
      `<path d="M4 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2zm2-1a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V2a1 1 0 0 0-1-1zm-4 4a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1v-1h-1v1H2V6h1V5H2a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2v-1h-1v1a1 1 0 0 1-1 1H2a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h1z"/>` +
      `</svg></button>`;
  }

  /**
   * Copy text to the clipboard, briefly flash the button green on success.
   */
  async copyToClipboard(text, btn) {
    try {
      await navigator.clipboard.writeText(text);
      if (btn) {
        const orig = btn.title;
        btn.classList.add('copied');
        btn.title = 'Copied!';
        setTimeout(() => { btn.classList.remove('copied'); btn.title = orig; }, 1500);
      }
    } catch (err) {
      console.error('Copy failed:', err);
    }
  }

  /**
   * Update a section-header element to show the title h4 and a copy button.
   * @param {string} id   – element ID of the .section-header div
   * @param {string} title – heading text
   * @param {string} copyText – text placed in the copy button
   */
  setSectionHeader(id, title, copyText) {
    const el = document.getElementById(id);
    if (!el) return;
    el.innerHTML = `<h4>${this.escapeHtml(title)}</h4>${this.makeCopyBtn(copyText, 'Copy ' + title)}`;
  }

  // ─────────────────────────────────────────────────────────────────────────────

  /**
   * Bind event listeners
   */
  bindEvents() {
    // Global copy-button delegation (works for dynamically rendered copy buttons)
    document.getElementById('app').addEventListener('click', (e) => {
      const btn = e.target.closest('.copy-btn');
      if (!btn) return;
      e.stopPropagation();
      this.copyToClipboard(btn.dataset.copy || '', btn);
    });

    // View mode toggle (List ↔ Timeline)
    document.getElementById('viewListBtn').addEventListener('click', () => this.setViewMode('list'));
    document.getElementById('viewTimelineBtn').addEventListener('click', () => this.setViewMode('timeline'));

    // Search and filters
    document.getElementById('searchInput').addEventListener('input', (e) => {
      this.filters.search = e.target.value;
      this.filterAndRender();
    });

    document.getElementById('methodFilter').addEventListener('change', (e) => {
      this.filters.method = e.target.value;
      this.filterAndRender();
    });

    document.getElementById('flowFilter').addEventListener('change', (e) => {
      this.filters.flow = e.target.value;
      this.filterAndRender();
    });

    document.getElementById('statusFilter').addEventListener('change', (e) => {
      this.filters.status = e.target.value;
      this.filterAndRender();
    });

    // Popout button
    const popoutBtn = document.getElementById('popoutBtn');
    if (popoutBtn) {
      popoutBtn.addEventListener('click', () => this.popout());
    }

    // Control buttons
    document.getElementById('clearBtn').addEventListener('click', () => {
      this.clearData();
    });

    document.getElementById('exportBtn').addEventListener('click', (e) => {
      e.stopPropagation();
      this.toggleExportMenu();
    });

    document.getElementById('exportMenu').addEventListener('click', (e) => {
      const item = e.target.closest('.export-menu-item');
      if (!item) return;
      this.closeExportMenu();
      this.doExport(item.dataset.format);
    });

    // Close export menu when clicking anywhere else
    document.addEventListener('click', () => this.closeExportMenu());

    // Detail panel
    document.getElementById('closeDetailBtn').addEventListener('click', () => {
      this.closeDetailPanel();
    });

    // Tab navigation
    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        this.switchTab(e.target.dataset.tab);
      });
    });
  }

  /**
   * Load data from background script
   */
  async loadData() {
    try {
      const response = await new Promise((resolve) => {
        chrome.runtime.sendMessage({ action: 'getState' }, resolve);
      });

      if (response) {
        this.currentRequests = response.requests || [];
        // Re-apply any active filters rather than calling renderRequestList() directly,
        // so the user's current filter/search state is respected on every poll.
        this.filterAndRender();
        this.updateStatusBar();
      }
    } catch (error) {
      console.error('Failed to load data:', error);
    }
  }

  /**
   * Start periodic data updates
   */
  startPeriodicUpdate() {
    setInterval(() => {
      this.loadData();
    }, 1000); // Update every second
  }

  /**
   * Clear all data
   */
  async clearData() {
    try {
      await new Promise((resolve) => {
        chrome.runtime.sendMessage({ action: 'clearData' }, resolve);
      });
      
      this.currentRequests = [];
      this.selectedRequest = null;
      this.renderRequestList();
      this.closeDetailPanel();
      this.updateStatusBar();
    } catch (error) {
      console.error('Failed to clear data:', error);
    }
  }

  // ─── Export ──────────────────────────────────────────────────────────────────

  toggleExportMenu() {
    const menu = document.getElementById('exportMenu');
    const btn  = document.getElementById('exportBtn');
    const isOpen = menu.style.display !== 'none';
    menu.style.display = isOpen ? 'none' : 'block';
    btn.setAttribute('aria-expanded', String(!isOpen));
  }

  closeExportMenu() {
    const menu = document.getElementById('exportMenu');
    const btn  = document.getElementById('exportBtn');
    menu.style.display = 'none';
    btn.setAttribute('aria-expanded', 'false');
  }

  /**
   * Export captured requests in the requested format (see Exporters).
   * @param {'json'|'markdown'|'txt'|'pdf'} format
   */
  doExport(format) {
    const requests = this.currentRequests;
    if (!requests || requests.length === 0) {
      alert('No requests to export. Capture some authentication traffic first.');
      return;
    }
    if (!Exporters.EXT[format]) return;

    const now = new Date();
    const version = chrome.runtime.getManifest().version;
    const content = Exporters.build(format, requests, now, version);
    this.downloadFile(content, Exporters.filename(format, now), Exporters.MIME[format]);
  }

  /**
   * Trigger a browser file download with the given content.
   */
  downloadFile(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType + ';charset=utf-8' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = filename;
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      URL.revokeObjectURL(url);
      document.body.removeChild(a);
    }, 1000);
  }

  /**
   * Apply current filters and render.  Used by both loadData and filter change handlers.
   */
  filterAndRender() {
    const requests = FlowCorrelator.applyFilters(this.currentRequests, this.filters);
    if (this.viewMode === 'timeline') {
      this.renderTimeline(requests);
    } else {
      this.renderRequestList(requests);
    }
  }

  // ─── View mode ────────────────────────────────────────────────────────────────

  /**
   * Switch between 'list' and 'timeline' view modes.
   */
  setViewMode(mode) {
    this.viewMode = mode;

    const listBtn = document.getElementById('viewListBtn');
    const timelineBtn = document.getElementById('viewTimelineBtn');
    const listHeader = document.querySelector('.request-list-header');

    listBtn.classList.toggle('active', mode === 'list');
    listBtn.setAttribute('aria-pressed', String(mode === 'list'));
    timelineBtn.classList.toggle('active', mode === 'timeline');
    timelineBtn.setAttribute('aria-pressed', String(mode === 'timeline'));

    if (listHeader) listHeader.style.display = mode === 'timeline' ? 'none' : '';

    this.filterAndRender();
  }

  // ─── Timeline view ────────────────────────────────────────────────────────────

  /**
   * Render a single flow group (multi-request or standalone) in timeline view.
   * Grouping itself lives in FlowCorrelator.computeFlowGroups.
   */
  renderFlowGroup(group) {
    const e = (v) => this.escapeHtml(v);

    if (group.requests.length === 1 && group.type === 'standalone') {
      // Standalone single-item: render like a plain list item but within timeline container
      return `<div class="timeline-standalone">${this.renderRequestItem(group.requests[0])}</div>`;
    }

    const flowBadgeClass = `flow-${group.type === 'device_code' ? 'device_code' : group.type === 'oauth' ? 'oauth' : group.type === 'did' ? 'did' : group.type}`;
    const flowLabel = group.type === 'device_code' ? 'DEVICE CODE' : group.type === 'did' ? 'VERIFIED ID' : group.type.toUpperCase();
    const startTime = group.requests[0] ? new Date(group.requests[0].timestamp || Date.now()).toLocaleTimeString() : '';
    const durationMs = group.requests.length > 1
      ? (group.requests[group.requests.length - 1].timestamp || 0) - (group.requests[0].timestamp || 0)
      : null;
    const durationStr = durationMs !== null ? ` · ${(durationMs / 1000).toFixed(1)}s` : '';

    let html = `
      <div class="flow-group">
        <div class="flow-group-header">
          <span class="flow-badge ${flowBadgeClass}">${flowLabel}</span>
          <span class="flow-group-title">${e(group.label || '')}</span>
          <span class="flow-group-meta">${startTime}${durationStr} · ${group.requests.length} req</span>
        </div>`;

    group.requests.forEach((r, idx) => {
      const time = new Date(r.timestamp || Date.now()).toLocaleTimeString();
      const status = r.status || 'pending';
      const statusIcon = status === 'completed' ? '✓' : status === 'error' ? '✗' : '⧖';
      let shortUrl = r.url || '';
      try { shortUrl = new URL(r.url).pathname; } catch { /* keep */ }
      const stepDesc = FlowCorrelator.getFlowStepDesc(r, idx);
      const selectedClass = this.selectedRequest && this.selectedRequest.id === r.id ? ' selected' : '';

      html += `
        <div class="flow-group-item${selectedClass}" data-request-id="${e(r.id)}">
          <span class="fgi-step">${idx + 1}</span>
          <span class="fgi-time">${time}</span>
          <span class="fgi-method">${e(r.method || 'GET')}</span>
          <span class="fgi-url" title="${e(r.url)}">${e(shortUrl)}</span>
          <span class="fgi-status status-${status}">${statusIcon}</span>
          ${stepDesc ? `<span class="fgi-desc">${e(stepDesc)}</span>` : ''}
        </div>`;
    });

    html += '</div>';
    return html;
  }

  /**
   * Render all requests in Timeline view: grouped flow sections then standalone items.
   */
  renderTimeline(requests = this.currentRequests) {
    const container = document.getElementById('requestList');
    if (!container) return;

    if (!requests || requests.length === 0) {
      container.innerHTML = `
        <div class="no-requests">
          <p>No authentication requests captured yet.</p>
          <p class="hint">Navigate to a Microsoft Entra login or perform SAML authentication to start tracing.</p>
        </div>`;
      return;
    }

    const groups = FlowCorrelator.computeFlowGroups(requests);
    let html = '<div class="timeline-view">';
    for (const group of groups) html += this.renderFlowGroup(group);
    html += '</div>';
    container.innerHTML = html;

    // Bind click events — both flow-group items and fallback standalone list items
    container.querySelectorAll('[data-request-id]').forEach(el => {
      el.addEventListener('click', (evt) => {
        // Prevent the copy-btn inside from triggering a request selection
        if (evt.target.closest('.copy-btn')) return;
        const found = requests.find(r => r.id === el.dataset.requestId);
        if (found) this.selectRequest(found);
      });
    });
  }

  // ─── Flow correlation ────────────────────────────────────────────────────────

  /**
   * After selecting a request, apply .correlated-highlight to other list items
   * that are part of the same flow (see FlowCorrelator.findRelatedRequests).
   */
  highlightCorrelatedRequests(request) {
    // Reset any previous highlights
    document.querySelectorAll('.correlated-highlight').forEach(el => el.classList.remove('correlated-highlight'));

    const related = FlowCorrelator.findRelatedRequests(request, this.currentRequests);
    if (related.length === 0) return;

    related.forEach(r => {
      const el = document.querySelector(`[data-request-id="${CSS.escape(r.id)}"]`);
      if (el && !el.classList.contains('selected')) el.classList.add('correlated-highlight');
    });
  }

  /**
   * Update the Related Requests panel in the detail header.
   */
  updateRelatedRequestsPanel(request) {
    const panel = document.getElementById('relatedRequestsPanel');
    const list  = document.getElementById('relatedRequestsList');
    if (!panel || !list) return;

    const related = FlowCorrelator.findRelatedRequests(request, this.currentRequests);
    const allInFlow = [request, ...related].sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));

    if (allInFlow.length <= 1) {
      panel.style.display = 'none';
      return;
    }

    panel.style.display = 'flex';
    list.innerHTML = allInFlow.map((r, idx) => {
      const isCurrent = r.id === request.id;
      const stepDesc = FlowCorrelator.getFlowStepDesc(r, idx) || r.flowType || '';
      const statusIcon = r.status === 'completed' ? '✓' : r.status === 'error' ? '✗' : '⧖';
      return `<span class="related-item${isCurrent ? ' related-current' : ''}" data-request-id="${this.escapeHtml(r.id)}" title="${this.escapeHtml(r.url)}">
        ${statusIcon} ${idx + 1}${stepDesc ? ': ' + this.escapeHtml(stepDesc) : ''}
      </span>`;
    }).join('');

    // Clicking a related item navigates to that request
    list.querySelectorAll('.related-item:not(.related-current)').forEach(el => {
      el.addEventListener('click', () => {
        const found = this.currentRequests.find(r => r.id === el.dataset.requestId);
        if (found) this.selectRequest(found);
      });
    });
  }
  renderRequestList(requests = this.currentRequests) {
    const container = document.getElementById('requestList');
    if (!container) return;

    if (!requests || requests.length === 0) {
      container.innerHTML = `
        <div class="no-requests">
          <p>No authentication requests captured yet.</p>
          <p class="hint">Navigate to a Microsoft Entra login or perform SAML authentication to start tracing.</p>
        </div>
      `;
      return;
    }

    const items = [];
    for (const req of requests) {
      try {
        items.push(this.renderRequestItem(req));
      } catch (err) {
        console.error('renderRequestItem failed:', err, req);
        const shortUrl = (req && req.url) ? req.url.substring(0, 80) : '(unknown)';
        items.push(`<div class="request-item error-item" title="${this.escapeHtml(err.message)}">&#9888; Error rendering request: ${this.escapeHtml(shortUrl)}</div>`);
      }
    }
    container.innerHTML = items.join('');

    // Bind click events
    container.querySelectorAll('.request-item').forEach(item => {
      item.addEventListener('click', () => {
        const requestId = item.dataset.requestId;
        if (!requestId) return;
        const request = requests.find(r => r.id === requestId);
        if (request) {
          this.selectRequest(request);
        }
      });
    });
  }

  /**
   * Render a single request item
   */
  renderRequestItem(request) {
    const time = new Date(request.timestamp || Date.now()).toLocaleTimeString();
    let hostname = '(unknown)';
    let shortUrl = request.url || '';
    try {
      const parsed = new URL(request.url);
      hostname = parsed.hostname;
      shortUrl = parsed.pathname + (parsed.search ? parsed.search.substring(0, 50) : '');
    } catch { /* keep defaults */ }
    const method = request.method || 'GET';
    const flowCategory = FlowCorrelator.getFlowTypeCategory(request.flowType);
    const status = request.status || 'pending';

    return `
      <div class="request-item" data-request-id="${request.id}">
        <span class="col-timestamp">${time}</span>
        <span class="col-method">${method}</span>
        <span class="col-url" title="${this.escapeHtml(request.url || '')}">
          <span class="url-text">${this.escapeHtml(shortUrl || hostname)}</span>
          ${this.makeCopyBtn(request.url || '', 'Copy URL')}
        </span>
        <span class="col-status status-${status}">${this.formatStatus(status)}</span>
        <span class="col-flow">
          <span class="flow-badge flow-${flowCategory}">${flowCategory.toUpperCase()}</span>
        </span>
      </div>
    `;
  }

  /**
   * Format status for display
   */
  formatStatus(status) {
    switch (status) {
      case 'completed': return '✓ Success';
      case 'error': return '✗ Error';
      case 'pending': return '⧖ Pending';
      default: return status;
    }
  }

  /**
   * Select a request and show details
   */
  selectRequest(request) {
    this.selectedRequest = request;
    
    // Update selection in list
    document.querySelectorAll('.request-item, .flow-group-item').forEach(item => {
      item.classList.remove('selected');
      if (item.dataset.requestId === request.id) {
        item.classList.add('selected');
      }
    });

    // Highlight correlated requests
    this.highlightCorrelatedRequests(request);

    // Show detail panel
    this.showDetailPanel(request);
  }

  /**
   * Show the detail panel with request information
   */
  showDetailPanel(request) {
    const panel = document.getElementById('detailPanel');
    panel.style.display = 'flex';

    // Show the pane splitter and ensure the list container dimensions are
    // correct for the current layout direction (column = height, row = width).
    const splitter = document.getElementById('paneSplitter');
    if (splitter) splitter.style.display = 'flex';

    const mainContent = document.querySelector('.main-content');
    const listContainer = document.querySelector('.request-list-container');
    if (mainContent && listContainer) {
      const isHorizontal = getComputedStyle(mainContent).flexDirection === 'row';
      if (isHorizontal) {
        // Clear any stacked-layout height so the side-by-side flex sizing takes over
        listContainer.style.height = '';
        const savedW = localStorage.getItem('entraTracerSplitW');
        if (savedW) {
          listContainer.style.flex = '0 0 auto';
          listContainer.style.width = parseFloat(savedW) + 'px';
        } else {
          listContainer.style.flex = '';
          listContainer.style.width = '';
        }
      } else {
        // Clear any side-by-side width so the full-width stacked layout takes over
        listContainer.style.width = '';
        const savedH = localStorage.getItem('entraTracerSplitH');
        if (savedH) {
          listContainer.style.flex = '0 0 auto';
          listContainer.style.height = parseFloat(savedH) + 'px';
        } else {
          listContainer.style.flex = '';
          listContainer.style.height = '';
        }
      }
    }

    // Update title
    const url = new URL(request.url);
    document.getElementById('detailTitle').textContent = `${request.method} ${url.pathname}`;

    // Wire the header copy button to copy the full URL
    const copyUrlBtn = document.getElementById('copyDetailUrlBtn');
    if (copyUrlBtn) {
      copyUrlBtn.dataset.copy = request.url;
      copyUrlBtn.style.display = 'inline-flex';
    }

    // Determine which tabs to show
    this.updateTabVisibility(request);

    // Update related requests panel
    this.updateRelatedRequestsPanel(request);

    // Populate tab content
    this.populateHttpTab(request);
    this.populateParametersTab(request);
    this.populateSamlTab(request);
    this.populateEntraTab(request);
  }

  /**
   * Update tab visibility based on request type
   */
  updateTabVisibility(request) {
    const entraTab = document.querySelector('[data-tab="entra"]');
    const samlTab = document.querySelector('[data-tab="saml"]');

    // Show Entra tab for Entra-related requests
    const isEntraRequest = this.isEntraRequest(request);
    entraTab.style.display = isEntraRequest ? 'block' : 'none';

    // Show SAML tab for SAML requests (also catches POST-binding SAMLResponse to any SP ACS URL)
    const isSamlRequest = request.flowType === 'saml' || request.flowType === 'wsfed'
      || SamlDecoder.extract(request) !== null;
    samlTab.style.display = isSamlRequest ? 'block' : 'none';

    // Check for CAE badge
    const caeBadge = entraTab.querySelector('.cae-badge');
    if (caeBadge && isEntraRequest) {
      const hasCAE = this.checkForCAE(request);
      caeBadge.style.display = hasCAE ? 'inline' : 'none';
    }
  }

  /**
   * Check if request is Entra-related
   */
  isEntraRequest(request) {
    const url = new URL(request.url);
    const entraHosts = ['login.microsoftonline.com', 'sts.windows.net', 'login.live.com'];
    if (entraHosts.includes(url.hostname)) return true;
    // Also show Entra tab if this request has oauth analysis (client_assertion JWT available)
    if (request.oauthAnalysis && request.oauthAnalysis.clientAssertion) return true;
    return false;
  }

  /**
   * Check for CAE capability in request by attempting to decode an available JWT.
   */
  checkForCAE(request) {
    const jwt = Sanitize.extractJwtFromRequest(request) ||
                Sanitize.extractJwtFromRequest(request, 'id_token_hint');
    if (!jwt) return false;
    try {
      const decoded = EntraClaimsDecoder.decodeEntraToken(jwt);
      return decoded && decoded.caeEnabled === true;
    } catch {
      return false;
    }
  }

  /**
   * Populate HTTP tab
   */
  populateHttpTab(request) {
    const requestDetails = document.getElementById('requestDetails');
    const responseDetails = document.getElementById('responseDetails');

    // Request details
    const requestCopyText = [
      `URL: ${request.url}`,
      `Method: ${request.method}`,
      `Timestamp: ${new Date(request.timestamp).toISOString()}`,
      `Flow Type: ${request.flowType}`,
    ].join('\n');

    this.setSectionHeader('requestSectionHeader', 'Request', requestCopyText);

    requestDetails.innerHTML = `
      <div class="label">URL:</div>
      <div class="value">${this.escapeHtml(request.url)}</div>
      <div class="label">Method:</div>
      <div class="value">${this.escapeHtml(request.method)}</div>
      <div class="label">Timestamp:</div>
      <div class="value">${new Date(request.timestamp).toISOString()}</div>
      <div class="label">Flow Type:</div>
      <div class="value">${this.escapeHtml(request.flowType)}</div>
    `;

    // Response details
    let responseCopyText;
    if (request.statusCode) {
      responseCopyText = `Status: ${request.statusCode} ${request.status}` +
        (request.error ? `\nError: ${request.error}` : '');
      responseDetails.innerHTML = `
        <div class="label">Status:</div>
        <div class="value">${request.statusCode} ${this.escapeHtml(request.status)}</div>
        ${request.error ? `
          <div class="label">Error:</div>
          <div class="value">${this.escapeHtml(request.error)}</div>
        ` : ''}
      `;
    } else {
      responseCopyText = 'Response pending...';
      responseDetails.innerHTML = '<div class="value">Response pending...</div>';
    }

    this.setSectionHeader('responseSectionHeader', 'Response', responseCopyText);

    // Show FIDO2 section if applicable
    this.populateFido2Section(request);

    // Show Verified ID / DID section if applicable
    this.populateDidSection(request);

    // Show OAuth section if applicable
    this.populateOAuthSection(request);
  }

  /**
   * Determine whether this request is an OAuth flow we can analyse.
   */
  isOAuthRequest(request) {
    if (request.oauthAnalysis) return true;
    return FlowCorrelator.isOAuthFlow(request.flowType);
  }

  /**
   * Populate the OAuth 2.1 section in the HTTP tab.
   */
  populateOAuthSection(request) {
    const section  = document.getElementById('oauthSection');
    const details  = document.getElementById('oauthDetails');
    if (!section || !details) return;

    if (!this.isOAuthRequest(request)) {
      section.style.display = 'none';
      return;
    }

    section.style.display = 'block';
    const analysis = request.oauthAnalysis;

    if (!analysis) {
      this.setSectionHeader('oauthSectionHeader', 'OAuth 2.1 Flow Analysis', '');
      details.innerHTML = '<div class="empty-state">No OAuth analysis available for this request.</div>';
      return;
    }
    if (analysis.error) {
      this.setSectionHeader('oauthSectionHeader', 'OAuth 2.1 Flow Analysis', '');
      details.innerHTML = `<div class="error">⚠ ${this.escapeHtml(analysis.error)}</div>`;
      return;
    }

    this.setSectionHeader('oauthSectionHeader', 'OAuth 2.1 Flow Analysis', this.buildOAuthCopyText(analysis));
    details.innerHTML = this.renderOAuthDetails(analysis, request);
  }

  /**
   * Build a plain-text summary of an OAuth analysis for clipboard copy.
   */
  buildOAuthCopyText(analysis) {
    const lines = [];
    if (analysis.label)            lines.push(`Grant Type: ${analysis.label}`);
    if (analysis.clientId)         lines.push(`Client ID: ${analysis.clientId}`);
    if (analysis.responseType)     lines.push(`Response Type: ${analysis.responseType}`);
    if (analysis.responseMode)     lines.push(`Response Mode: ${analysis.responseMode}`);
    if (analysis.redirectUri)      lines.push(`Redirect URI: ${analysis.redirectUri}`);
    if (analysis.state)            lines.push(`State: ${analysis.state}`);
    if (analysis.nonce)            lines.push(`Nonce: ${analysis.nonce}`);
    if (analysis.prompt)           lines.push(`Prompt: ${analysis.prompt}`);
    if (analysis.loginHint)        lines.push(`Login Hint: ${analysis.loginHint}`);
    if (analysis.domainHint)       lines.push(`Domain Hint: ${analysis.domainHint}`);
    if (analysis.authMethod)       lines.push(`Auth Method: ${analysis.authMethodLabel || analysis.authMethod}`);
    if (analysis.deviceCodePrefix) lines.push(`Device Code: ${analysis.deviceCodePrefix}`);
    if (analysis.pkce) {
      lines.push(`PKCE Method: ${analysis.pkce.codeChallengeMethod}`);
      if (analysis.pkce.codeChallenge) lines.push(`PKCE Challenge: ${analysis.pkce.codeChallenge}`);
    }
    if (analysis.pkceVerifier?.verifier) {
      lines.push(`PKCE Verifier: ${analysis.pkceVerifier.verifier}`);
    }
    if (analysis.scopeLabels && analysis.scopeLabels.length) {
      lines.push(`Scopes: ${analysis.scopeLabels.map(s => s.scope).join(' ')}`);
    }
    if (analysis.warnings && analysis.warnings.length) {
      lines.push('');
      lines.push('Warnings:');
      analysis.warnings.forEach(w => lines.push(`  [${w.severity.toUpperCase()}] ${w.message}`));
    }
    return lines.join('\n');
  }

  /**
   * Render all OAuth analysis into HTML.
   */
  renderOAuthDetails(analysis, _request) {
    const e = (v) => this.escapeHtml(v == null ? '' : String(v));
    let html = '';

    // ── Grant type header ──────────────────────────────────────────────────
    const grantInfo = OAuthDecoder.GRANT_TYPES[analysis.grantType] || {};
    const isDeprecated = grantInfo.oauth21 === false;
    html += `
      <div class="oauth-grant-header">
        <div class="oauth-grant-badge ${isDeprecated ? 'oauth-grant-deprecated' : 'oauth-grant-standard'}">
          ${e(analysis.label)}
        </div>
        ${isDeprecated ? '<span class="oauth-deprecated-notice">⚠ Deprecated in OAuth 2.1</span>' : ''}
      </div>
    `;

    if (grantInfo.description) {
      html += `<div class="oauth-description">${e(grantInfo.description)}</div>`;
    }

    // ── Metadata grid ──────────────────────────────────────────────────────
    html += '<div class="details-grid">';
    if (analysis.clientId)  html += `<div class="label">Client ID:</div><div class="value mono">${e(analysis.clientId)}</div>`;
    if (analysis.responseType) html += `<div class="label">Response Type:</div><div class="value">${e(analysis.responseType)}</div>`;
    if (analysis.redirectUri)  html += `<div class="label">Redirect URI:</div><div class="value">${e(analysis.redirectUri)}</div>`;
    if (analysis.responseMode) html += `<div class="label">Response Mode:</div><div class="value">${e(analysis.responseMode)}</div>`;
    if (analysis.state)        html += `<div class="label">State:</div><div class="value mono">${e(analysis.state.substring(0, 40))}${analysis.state.length > 40 ? '…' : ''}</div>`;
    if (analysis.nonce)        html += `<div class="label">Nonce:</div><div class="value mono">${e(analysis.nonce.substring(0, 40))}${analysis.nonce.length > 40 ? '…' : ''}</div>`;
    if (analysis.prompt)       html += `<div class="label">Prompt:</div><div class="value">${e(analysis.prompt)}</div>`;
    if (analysis.loginHint)    html += `<div class="label">Login Hint:</div><div class="value">${e(analysis.loginHint)}</div>`;
    if (analysis.domainHint)   html += `<div class="label">Domain Hint:</div><div class="value">${e(analysis.domainHint)}</div>`;
    if (analysis.authMethod)   html += `<div class="label">Auth Method:</div><div class="value">${e(analysis.authMethodLabel || analysis.authMethod)}</div>`;
    if (analysis.deviceCodePrefix) html += `<div class="label">Device Code:</div><div class="value mono">${e(analysis.deviceCodePrefix)}</div>`;
    html += '</div>';

    // ── PKCE details ──────────────────────────────────────────────────────
    if (analysis.pkce) {
      html += this.renderPKCEDetails(analysis.pkce);
    }
    if (analysis.pkceVerifier) {
      html += this.renderPKCEVerifierDetails(analysis.pkceVerifier);
    }

    // ── Client assertion JWT ───────────────────────────────────────────────
    if (analysis.clientAssertion && !analysis.clientAssertion.error) {
      html += this.renderClientAssertionDetails(analysis.clientAssertion);
    }

    // ── Scopes ────────────────────────────────────────────────────────────
    if (analysis.scopeLabels && analysis.scopeLabels.length > 0) {
      html += this.renderScopeList(analysis.scopeLabels);
    }

    // ── Security warnings ────────────────────────────────────────────────
    if (analysis.warnings && analysis.warnings.length > 0) {
      html += this.renderOAuthWarnings(analysis.warnings);
    }

    return html;
  }

  /**
   * Render PKCE code_challenge section.
   */
  renderPKCEDetails(pkce) {
    const e = (v) => this.escapeHtml(v == null ? '' : String(v));
    const statusClass = pkce.isS256 ? 'pkce-compliant' : 'pkce-warning';
    const statusIcon  = pkce.isS256 ? '✓' : '⚠';
    return `
      <div class="oauth-section">
        <h5>🔐 PKCE — Code Challenge</h5>
        <div class="pkce-status ${statusClass}">${statusIcon} ${e(pkce.recommendation)}</div>
        <div class="details-grid">
          <div class="label">Method:</div>
          <div class="value">${e(pkce.codeChallengeMethod)}</div>
          <div class="label">Challenge (${pkce.challengeLength} chars):</div>
          <div class="value mono">${e(pkce.codeChallenge ? pkce.codeChallenge.substring(0, 50) + (pkce.codeChallenge.length > 50 ? '…' : '') : '')}</div>
        </div>
      </div>
    `;
  }

  /**
   * Render PKCE code_verifier section.
   */
  renderPKCEVerifierDetails(verifier) {
    const e = (v) => this.escapeHtml(v == null ? '' : String(v));
    if (verifier.error) {
      return `<div class="oauth-section"><h5>🔐 PKCE — Code Verifier</h5><div class="error">${e(verifier.error)}</div></div>`;
    }
    const statusClass = verifier.isCompliant ? 'pkce-compliant' : 'pkce-error';
    const statusIcon  = verifier.isCompliant ? '✓' : '✗';
    return `
      <div class="oauth-section">
        <h5>🔐 PKCE — Code Verifier</h5>
        <div class="pkce-status ${statusClass}">${statusIcon} ${e(verifier.recommendation)}</div>
        <div class="details-grid">
          <div class="label">Length:</div>
          <div class="value">${verifier.length} chars ${verifier.isCompliant ? '✓ RFC 7636' : '✗ out-of-range'}</div>
          <div class="label">Entropy:</div>
          <div class="value">${verifier.isHighEntropy ? 'High (≥64 chars)' : 'Standard'}</div>
        </div>
      </div>
    `;
  }

  /**
   * Render client_assertion JWT section.
   */
  renderClientAssertionDetails(assertion) {
    const e = (v) => this.escapeHtml(v == null ? '' : String(v));
    const expiredNote = assertion.isExpired === true
      ? ' <span class="oauth-expired">⚠ EXPIRED</span>'
      : (assertion.isExpired === false ? ' ✓' : '');
    return `
      <div class="oauth-section">
        <h5>🎫 Client Assertion (JWT)</h5>
        <div class="details-grid">
          ${assertion.algorithm ? `<div class="label">Algorithm:</div><div class="value">${e(assertion.algorithm)}</div>` : ''}
          ${assertion.keyId ? `<div class="label">Key ID (kid):</div><div class="value mono">${e(assertion.keyId.substring(0, 50))}</div>` : ''}
          ${assertion.thumbprint ? `<div class="label">Thumbprint:</div><div class="value mono">${e(assertion.thumbprint.substring(0, 50))}</div>` : ''}
          ${assertion.issuer ? `<div class="label">Issuer:</div><div class="value">${e(assertion.issuer)}</div>` : ''}
          ${assertion.audience ? `<div class="label">Audience:</div><div class="value">${e(Array.isArray(assertion.audience) ? assertion.audience.join(', ') : assertion.audience)}</div>` : ''}
          ${assertion.expiry ? `<div class="label">Expiry:</div><div class="value">${e(assertion.expiry)}${expiredNote}</div>` : ''}
        </div>
      </div>
    `;
  }

  /**
   * Render the list of OAuth scopes with human-readable labels.
   */
  renderScopeList(scopeLabels) {
    const e = (v) => this.escapeHtml(v == null ? '' : String(v));
    const items = scopeLabels.map(({ scope, label }) => `
      <div class="scope-item">
        <span class="scope-name">${e(scope)}</span>
        ${label ? `<span class="scope-label">${e(label)}</span>` : ''}
      </div>
    `).join('');
    return `
      <div class="oauth-section">
        <h5>📍 Requested Scopes (${scopeLabels.length})</h5>
        <div class="scope-list">${items}</div>
      </div>
    `;
  }

  /**
   * Render OAuth security warnings.
   */
  renderOAuthWarnings(warnings) {
    const e = (v) => this.escapeHtml(v == null ? '' : String(v));
    const items = warnings.map(w => `
      <div class="oauth-warning oauth-warning-${w.severity}">
        <span class="oauth-warning-icon">${w.severity === 'error' ? '🔴' : w.severity === 'warning' ? '🟡' : '🔵'}</span>
        <span class="oauth-warning-text">${e(w.message)}</span>
      </div>
    `).join('');
    return `
      <div class="oauth-section">
        <h5>🛡 Security Assessment</h5>
        ${items}
      </div>
    `;
  }

  /**
   * Populate FIDO2 section with full decoding support
   */
  populateFido2Section(request) {
    const fido2Section = document.getElementById('fido2Section');
    const fido2Details = document.getElementById('fido2Details');

    if (request.fido2Analysis && !request.fido2Analysis.error) {
      fido2Section.style.display = 'block';
      fido2Details.innerHTML = this.renderFido2Details(request.fido2Analysis, request.flowType);
    } else if ((request.flowType || '').startsWith('fido2_')) {
      fido2Section.style.display = 'block';
      fido2Details.innerHTML = request.fido2Analysis?.error
        ? `<div class="error">FIDO2 Error: ${this.escapeHtml(request.fido2Analysis.error)}</div>`
        : '<div>No FIDO2 data available for this request</div>';
    } else {
      fido2Section.style.display = 'none';
    }
  }

  /**
   * Populate the Verified ID / DID section in the HTTP tab.
   */
  populateDidSection(request) {
    const section = document.getElementById('didSection');
    const details = document.getElementById('didDetails');
    if (!section || !details) return;

    const isDidFlow = request.flowType &&
      (request.flowType.startsWith('did_') || request.flowType.startsWith('vc_'));

    if (request.didAnalysis && !request.didAnalysis.error) {
      section.style.display = 'block';
      this.setSectionHeader('didSectionHeader', 'Verified ID / DID Analysis', '');
      details.innerHTML = this.renderDidDetails(request.didAnalysis);
    } else if (isDidFlow) {
      section.style.display = 'block';
      this.setSectionHeader('didSectionHeader', 'Verified ID / DID Analysis', '');
      details.innerHTML = request.didAnalysis?.error
        ? `<div class="error">Verified ID Error: ${this.escapeHtml(request.didAnalysis.error)}</div>`
        : '<div>No Verified ID data available for this request</div>';
    } else {
      section.style.display = 'none';
    }
  }

  /**
   * Render Verified ID / DID analysis details.
   */
  renderDidDetails(analysis) {
    const e = (v) => this.escapeHtml(v == null ? '' : String(v));
    let html = '';

    // Operation summary
    html += `
      <div class="oauth-section">
        <div class="details-grid">
          <div class="label">Operation:</div>
          <div class="value"><strong>${e(analysis.operation)}</strong></div>
          <div class="label">Host:</div>
          <div class="value">${e(analysis.host)}</div>
          ${analysis.did ? `<div class="label">DID:</div><div class="value mono" title="${e(analysis.did)}">${e(analysis.did.substring(0, 60))}${analysis.did.length > 60 ? '…' : ''}</div>` : ''}
          ${analysis.requestId ? `<div class="label">Request ID:</div><div class="value mono">${e(analysis.requestId)}</div>` : ''}
        </div>
      </div>`;

    // Issuance details
    if (analysis.credentialType || analysis.manifestUrl || analysis.authority || analysis.pinRequired) {
      html += `
        <div class="oauth-section">
          <h5>📄 Credential Details</h5>
          <div class="details-grid">
            ${analysis.credentialType ? `<div class="label">Credential Type:</div><div class="value">${e(analysis.credentialType)}</div>` : ''}
            ${analysis.authority ? `<div class="label">Authority:</div><div class="value">${e(analysis.authority)}</div>` : ''}
            ${analysis.manifestUrl ? `<div class="label">Manifest URL:</div><div class="value">${e(analysis.manifestUrl)}</div>` : ''}
            ${analysis.pinRequired ? `<div class="label">PIN Required:</div><div class="value">Yes</div>` : ''}
            ${analysis.format ? `<div class="label">Format:</div><div class="value">${e(analysis.format)}</div>` : ''}
            ${analysis.proofPresent ? `<div class="label">Proof:</div><div class="value">Present</div>` : ''}
          </div>
        </div>`;
    }

    // Presentation / verification details
    if (analysis.requestedCredentials && analysis.requestedCredentials.length) {
      html += `
        <div class="oauth-section">
          <h5>🔍 Presentation Request</h5>
          <div class="details-grid">
            <div class="label">Requested Credentials:</div>
            <div class="value">${analysis.requestedCredentials.map(t => e(t)).join('<br>')}</div>
            ${analysis.clientName ? `<div class="label">Verifier Name:</div><div class="value">${e(analysis.clientName)}</div>` : ''}
            ${analysis.includesReceipt !== undefined ? `<div class="label">Includes Receipt:</div><div class="value">${analysis.includesReceipt ? 'Yes' : 'No'}</div>` : ''}
            ${analysis.includeQRCode !== undefined ? `<div class="label">Includes QR Code:</div><div class="value">${analysis.includeQRCode ? 'Yes' : 'No'}</div>` : ''}
          </div>
        </div>`;
    }

    // OpenID4VP
    if (analysis.presentationDefinition) {
      html += `
        <div class="oauth-section">
          <h5>🪪 OpenID4VP Presentation Definition</h5>
          <div class="details-grid">
            ${analysis.inputDescriptors && analysis.inputDescriptors.length ? `<div class="label">Input Descriptors:</div><div class="value">${analysis.inputDescriptors.map(d => e(d)).join(', ')}</div>` : ''}
            ${analysis.vpTokenPresent ? `<div class="label">vp_token:</div><div class="value">Present</div>` : ''}
            ${analysis.idTokenPresent ? `<div class="label">id_token:</div><div class="value">Present</div>` : ''}
          </div>
        </div>`;
    }

    // Callback
    if (analysis.callbackUrl) {
      html += `
        <div class="oauth-section">
          <h5>↩ Callback</h5>
          <div class="details-grid">
            <div class="label">Callback URL:</div>
            <div class="value">${e(analysis.callbackUrl)}</div>
            ${analysis.callbackState ? `<div class="label">State:</div><div class="value mono">${e(analysis.callbackState)}</div>` : ''}
          </div>
        </div>`;
    }

    // Warnings
    if (analysis.warnings && analysis.warnings.length) {
      const items = analysis.warnings.map(w => `
        <div class="oauth-warning oauth-warning-${e(w.severity)}">
          <span class="oauth-warning-icon">${w.severity === 'error' ? '🔴' : w.severity === 'warning' ? '🟡' : '🔵'}</span>
          <span class="oauth-warning-text">${e(w.message)}</span>
        </div>`).join('');
      html += `<div class="oauth-section"><h5>🛡 Notes</h5>${items}</div>`;
    }

    return html;
  }

  /**
   * Render comprehensive FIDO2 details
   */
  renderFido2Details(fido2Data, flowType) {
    let html = '';
    
    // Flow type header
    html += `
      <div class="fido2-section">
        <h5>Flow Type: ${this.getFido2TypeDescription(flowType)}</h5>
      </div>
    `;

    // Client Data JSON section
    if (fido2Data.clientDataJSON) {
      const clientData = fido2Data.clientDataJSON;
      html += `
        <div class="fido2-section">
          <h5>📋 Client Data JSON</h5>
          <div class="details-grid">
            <div class="label">Operation Type:</div>
            <div class="value">${this.escapeHtml(clientData.type)}</div>
            <div class="label">Origin:</div>
            <div class="value">${this.escapeHtml(clientData.origin)}</div>
            <div class="label">Challenge:</div>
            <div class="value" title="${this.escapeHtml(clientData.challenge)}">${this.escapeHtml(String(clientData.challenge || '').substring(0, 40))}...</div>
            <div class="label">Cross Origin:</div>
            <div class="value">${clientData.crossOrigin ? 'Yes' : 'No'}</div>
          </div>
        </div>
      `;
    }

    // Authenticator Data section
    if (fido2Data.authenticatorData) {
      const authData = fido2Data.authenticatorData;
      const flags = authData.flags;
      
      html += `
        <div class="fido2-section">
          <h5>🔐 Authenticator Data</h5>
          <div class="details-grid">
            <div class="label">RP ID Hash:</div>
            <div class="value" title="${this.escapeHtml(authData.rpIdHash)}">${this.escapeHtml(String(authData.rpIdHash || '').substring(0, 40))}...</div>
            <div class="label">Signature Counter:</div>
            <div class="value">${this.escapeHtml(authData.signCount)}</div>
          </div>
          
          <h6>Authenticator Flags:</h6>
          <div class="flags-grid">
            <div class="flag-item ${flags.UP ? 'flag-set' : 'flag-unset'}" title="User Present">
              UP ${flags.UP ? '✓' : '✗'}
            </div>
            <div class="flag-item ${flags.UV ? 'flag-set' : 'flag-unset'}" title="User Verified">
              UV ${flags.UV ? '✓' : '✗'}
            </div>
            <div class="flag-item ${flags.BE ? 'flag-set' : 'flag-unset'}" title="Backup Eligible — credential may be synced (passkey)">
              BE ${flags.BE ? '✓' : '✗'}
            </div>
            <div class="flag-item ${flags.BS ? 'flag-set' : 'flag-unset'}" title="Backup State — credential is currently backed up">
              BS ${flags.BS ? '✓' : '✗'}
            </div>
            <div class="flag-item ${flags.AT ? 'flag-set' : 'flag-unset'}" title="Attested Credential Data">
              AT ${flags.AT ? '✓' : '✗'}
            </div>
            <div class="flag-item ${flags.ED ? 'flag-set' : 'flag-unset'}" title="Extension Data">
              ED ${flags.ED ? '✓' : '✗'}
            </div>
          </div>
        </div>
      `;

      // Attested Credential Data (if AT flag is set)
      if (authData.attestedCredentialData) {
        const credData = authData.attestedCredentialData;
        const authenticator = credData.authenticator;
        const authenticatorLabel = authenticator
          ? `${this.escapeHtml(authenticator.name)}${authenticator.vendor ? ` (${this.escapeHtml(authenticator.vendor)})` : ''}`
          : 'Unknown authenticator';
        html += `
          <div class="fido2-section">
            <h5>🏷️ Attested Credential Data</h5>
            <div class="details-grid">
              <div class="label">AAGUID:</div>
              <div class="value mono">${this.escapeHtml(credData.aaguid)}</div>
              <div class="label">Authenticator:</div>
              <div class="value">${authenticatorLabel}</div>
              <div class="label">Credential ID Length:</div>
              <div class="value">${this.escapeHtml(credData.credentialIdLength)} bytes</div>
              <div class="label">Credential ID:</div>
              <div class="value" title="${this.escapeHtml(credData.credentialId)}">${this.escapeHtml(String(credData.credentialId).substring(0, 40))}...</div>
            </div>

            ${this.renderPublicKeyInfo(credData.credentialPublicKey)}
          </div>
        `;
      }

      // Extensions (if ED flag is set)
      if (authData.extensions) {
        html += `
          <div class="fido2-section">
            <h5>🧩 Authenticator Extensions</h5>
            <pre class="cbor-hex">${this.escapeHtml(JSON.stringify(authData.extensions, null, 2))}</pre>
          </div>
        `;
      }
    }

    // Attestation statement (registration ceremonies)
    if (fido2Data.attestationObject) {
      const att = fido2Data.attestationObject;
      const stmt = att.attStmt || {};
      html += `
        <div class="fido2-section">
          <h5>📜 Attestation Statement</h5>
          <div class="details-grid">
            <div class="label">Format:</div>
            <div class="value">${this.escapeHtml(att.fmt || 'unknown')}</div>
            ${stmt.algorithmDescription ? `<div class="label">Algorithm:</div><div class="value">${this.escapeHtml(stmt.algorithmDescription)}</div>` : ''}
            <div class="label">Certificates (x5c):</div>
            <div class="value">${this.escapeHtml(stmt.x5cCount || 0)}</div>
            ${stmt.sigHex ? `<div class="label">Signature:</div><div class="value mono" title="${this.escapeHtml(stmt.sigHex)}">${this.escapeHtml(stmt.sigHex.substring(0, 40))}...</div>` : ''}
          </div>
        </div>
      `;
    }

    return html;
  }

  /**
   * Render public key information
   */
  renderPublicKeyInfo(publicKeyData) {
    if (!publicKeyData || publicKeyData.error) {
      return `
        <h6>Public Key:</h6>
        <div class="error">${this.escapeHtml(publicKeyData?.error || 'No public key data')}</div>
      `;
    }

    let html = '<h6>🔑 Credential Public Key:</h6>';

    if (publicKeyData.keyInfo && !publicKeyData.keyInfo.error) {
      const keyInfo = publicKeyData.keyInfo;

      html += `
        <div class="details-grid">
          <div class="label">Key Type:</div>
          <div class="value">${this.escapeHtml(keyInfo.keyTypeDescription)}</div>
          <div class="label">Algorithm:</div>
          <div class="value">${this.escapeHtml(keyInfo.algorithmDescription)}</div>
        </div>
      `;

      // EC2 Key parameters
      if (keyInfo.keyType === 2 && keyInfo.parameters.curve) {
        html += `
          <div class="details-grid">
            <div class="label">Curve:</div>
            <div class="value">${this.escapeHtml(keyInfo.parameters.curveDescription)}</div>
            <div class="label">Coordinates:</div>
            <div class="value">x: ${keyInfo.parameters.x ? 'Present' : 'Missing'}, y: ${keyInfo.parameters.y ? 'Present' : 'Missing'}</div>
          </div>
        `;
      }

      // RSA Key parameters
      if (keyInfo.keyType === 3) {
        html += `
          <div class="details-grid">
            <div class="label">Modulus (n):</div>
            <div class="value">${keyInfo.parameters.n ? 'Present' : 'Missing'}</div>
            <div class="label">Exponent (e):</div>
            <div class="value">${keyInfo.parameters.e ? 'Present' : 'Missing'}</div>
          </div>
        `;
      }
    } else {
      html += `<div class="error">${this.escapeHtml(publicKeyData.keyInfo?.error || 'Unable to parse key information')}</div>`;
    }

    // CBOR raw data (collapsible)
    html += `
      <details class="cbor-details">
        <summary>Raw CBOR Data (${this.escapeHtml(publicKeyData.size)} bytes)</summary>
        <pre class="cbor-hex">${this.escapeHtml(publicKeyData.hex)}</pre>
      </details>
    `;

    return html;
  }

  /**
   * Get FIDO2 flow type description
   */
  getFido2TypeDescription(flowType) {
    switch (flowType) {
      case 'fido2_assertion': return 'Authentication (Assertion) - User signing in with existing credential';
      case 'fido2_attestation': return 'Registration (Attestation) - User registering new credential';
      case 'fido2_preflight': return 'Pre-flight Check - Discovering available authenticator options';
      case 'fido2_webauthn': return 'WebAuthn Endpoint - Challenge or session management';
      default: return 'Unknown FIDO2 Flow';
    }
  }

  /**
   * Populate Parameters tab
   */
  populateParametersTab(request) {
    const urlParameters = document.getElementById('urlParameters');
    const requestBody = document.getElementById('requestBody');

    // URL parameters
    const url = new URL(request.url);
    const params = Array.from(url.searchParams.entries());

    const urlParamsCopyText = params.length > 0
      ? params.map(([k, v]) => `${k}: ${Sanitize.redactSensitiveValues(k, v)}`).join('\n')
      : 'No URL parameters';
    this.setSectionHeader('urlParamsSectionHeader', 'URL Parameters', urlParamsCopyText);

    if (params.length > 0) {
      urlParameters.innerHTML = params.map(([key, value]) => `
        <div class="param-name">${this.escapeHtml(key)}:</div>
        <div class="param-value">${this.escapeHtml(Sanitize.redactSensitiveValues(key, value))}</div>
      `).join('');
    } else {
      urlParameters.innerHTML = '<div class="param-value">No URL parameters</div>';
    }

    // Request body
    let bodyCopyText = 'No request body';
    if (request.requestBody) {
      bodyCopyText = this.requestBodyAsText(request.requestBody);
      requestBody.innerHTML = this.renderRequestBody(request.requestBody);
    } else {
      requestBody.innerHTML = '<div class="param-value">No request body</div>';
    }
    this.setSectionHeader('formDataSectionHeader', 'Form Data / Request Body', bodyCopyText);

    // Show device code timeline for device_code flows
    this.populateDeviceCodeTimeline(request);
  }

  /**
   * Populate the Device Code Flow Timeline in the Parameters tab.
   * Correlates all device_code poll requests for the same device_code.
   */
  populateDeviceCodeTimeline(request) {
    const timelineSection = document.getElementById('deviceCodeTimeline');
    const timelineDetails = document.getElementById('deviceCodeDetails');
    if (!timelineSection || !timelineDetails) return;

    const flowType = request.flowType || '';
    if (!flowType.startsWith('device_code')) {
      timelineSection.style.display = 'none';
      return;
    }

    timelineSection.style.display = 'block';

    // Gather related requests: all device_code requests from the full set
    const correlationKey = request.deviceCodeCorrelationKey;
    let relatedIds = [];
    if (correlationKey) {
      // Retrieve IDs from the background's correlation map (passed through via state)
      // In practice they're available via currentRequests filtered by same correlation key
      relatedIds = this.currentRequests
        .filter(r => r.deviceCodeCorrelationKey === correlationKey)
        .map(r => r.id);
    }

    const timelineRequests = relatedIds.length > 1
      ? this.currentRequests.filter(r => relatedIds.includes(r.id))
      : [request];

    timelineDetails.innerHTML = timelineRequests
      .sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0))
      .map((r, idx) => {
        const isInitiation = (r.flowType === 'device_code_initiation');
        const time = new Date(r.timestamp || Date.now()).toLocaleTimeString();
        const markerClass = isInitiation ? 'timeline-initiation'
          : r.status === 'completed' ? 'timeline-success'
          : r.status === 'error'     ? 'timeline-error'
          : 'timeline-poll';
        const label = isInitiation ? 'Device Code Initiation' : `Poll #${idx} — ${r.status || 'pending'}`;
        const isCurrent = r.id === request.id ? ' timeline-current' : '';
        return `
          <div class="timeline-item${isCurrent}">
            <div class="timeline-marker ${markerClass}"></div>
            <div class="timeline-content">
              <div class="timeline-time">${time}</div>
              <div class="timeline-details">${label}${
                r.oauthAnalysis && r.oauthAnalysis.clientId
                  ? ` &mdash; Client: ${this.escapeHtml(r.oauthAnalysis.clientId)}`
                  : ''
              }</div>
            </div>
          </div>
        `;
      }).join('');
  }

  /**
   * Format request body as plain text for clipboard copying.
   */
  requestBodyAsText(body) {
    if (body.type === 'formData') {
      return Object.entries(body.data)
        .map(([k, values]) => `${k}: ${Sanitize.redactSensitiveValues(k, Array.isArray(values) ? values[0] : values)}`)
        .join('\n');
    } else if (body.type === 'json') {
      return JSON.stringify(Sanitize.redactObject(body.data), null, 2);
    }
    return String(body.data);
  }

  /**
   * Render request body — every value is redacted and HTML-escaped.
   */
  renderRequestBody(body) {
    if (body.type === 'formData') {
      return Object.entries(body.data).map(([key, values]) => `
        <div class="param-name">${this.escapeHtml(key)}:</div>
        <div class="param-value">${this.escapeHtml(Sanitize.redactSensitiveValues(key, Array.isArray(values) ? values[0] : values))}</div>
      `).join('');
    } else if (body.type === 'json') {
      return `<div class="param-value"><pre>${this.escapeHtml(JSON.stringify(Sanitize.redactObject(body.data), null, 2))}</pre></div>`;
    } else {
      return `<div class="param-value">${this.escapeHtml(body.data)}</div>`;
    }
  }

  /**
   * Escape a value for safe insertion into HTML (delegates to Sanitize).
   */
  escapeHtml(text) {
    return Sanitize.escapeHtml(text);
  }

  /**
   * Render decoded SAML data as HTML for the SAML tab.
   */
  renderSamlDecoded(decoded) {
    const p = decoded.parsed;
    const e = (v) => this.escapeHtml(v);
    const shortUrn = (v) => (v && v.includes(':')) ? v.split(':').pop() : (v || '');
    let html = '';

    // Summary card
    html += `<div class="saml-summary">
      <div class="saml-meta">
        <span class="saml-type-badge">${e(p.messageType || decoded.messageType)}</span>
        <span class="saml-binding-badge">${e(decoded.binding.toUpperCase())} Binding</span>
      </div>
      <div class="details-grid">
        ${p.id ? `<div class="label">Message ID:</div><div class="value mono">${e(p.id)}</div>` : ''}
        ${p.issueInstant ? `<div class="label">Issue Instant:</div><div class="value">${e(p.issueInstant)}</div>` : ''}
        ${p.issuer ? `<div class="label">Issuer:</div><div class="value">${e(p.issuer)}</div>` : ''}
        ${p.destination ? `<div class="label">Destination:</div><div class="value">${e(p.destination)}</div>` : ''}
        ${p.version ? `<div class="label">Version:</div><div class="value">${e(p.version)}</div>` : ''}
        ${p.inResponseTo ? `<div class="label">In Response To:</div><div class="value mono">${e(p.inResponseTo)}</div>` : ''}
      </div>
    </div>`;

    // AuthnRequest fields
    if (p.messageType === 'AuthnRequest') {
      if (p.assertionConsumerServiceURL || p.protocolBinding || p.forceAuthn || p.providerName) {
        html += `<div class="section"><h5>Request Details</h5><div class="details-grid">
          ${p.assertionConsumerServiceURL ? `<div class="label">ACS URL:</div><div class="value">${e(p.assertionConsumerServiceURL)}</div>` : ''}
          ${p.protocolBinding ? `<div class="label">Protocol Binding:</div><div class="value">${e(shortUrn(p.protocolBinding))}</div>` : ''}
          ${p.forceAuthn ? `<div class="label">Force Authn:</div><div class="value">${e(p.forceAuthn)}</div>` : ''}
          ${p.isPassive ? `<div class="label">Is Passive:</div><div class="value">${e(p.isPassive)}</div>` : ''}
          ${p.providerName ? `<div class="label">Provider Name:</div><div class="value">${e(p.providerName)}</div>` : ''}
        </div></div>`;
      }
      if (p.nameIDPolicy) {
        html += `<div class="section"><h5>NameID Policy</h5><div class="details-grid">
          ${p.nameIDPolicy.format ? `<div class="label">Format:</div><div class="value">${e(shortUrn(p.nameIDPolicy.format))}</div>` : ''}
          ${p.nameIDPolicy.allowCreate ? `<div class="label">Allow Create:</div><div class="value">${e(p.nameIDPolicy.allowCreate)}</div>` : ''}
        </div></div>`;
      }
      if (p.requestedAuthnContext && p.requestedAuthnContext.classRefs && p.requestedAuthnContext.classRefs.length) {
        html += `<div class="section"><h5>Requested AuthnContext</h5><div class="details-grid">
          <div class="label">Comparison:</div><div class="value">${e(p.requestedAuthnContext.comparison || 'exact')}</div>
          <div class="label">Class Refs:</div><div class="value">${p.requestedAuthnContext.classRefs.map(r => e(shortUrn(r))).join('<br>')}</div>
        </div></div>`;
      }
    }

    // Response fields
    if (p.messageType === 'Response') {
      if (p.status) {
        const cls = p.status.isSuccess ? 'success' : 'failure';
        const icon = p.status.isSuccess ? '\u2713' : '\u2717';
        html += `<div class="section"><h5>Status</h5>
          <div class="saml-status ${cls}">${icon} ${e(p.status.code || p.status.fullCode)}
            ${p.status.message ? `<div class="status-message">${e(p.status.message)}</div>` : ''}
          </div></div>`;
      }
      if (p.assertion) {
        const a = p.assertion;
        if (a.nameID) {
          html += `<div class="section"><h5>Subject</h5><div class="details-grid">
            <div class="label">NameID:</div><div class="value">${e(a.nameID.value)}</div>
            ${a.nameID.format ? `<div class="label">Format:</div><div class="value">${e(shortUrn(a.nameID.format))}</div>` : ''}
            ${a.nameID.spNameQualifier ? `<div class="label">SP Qualifier:</div><div class="value">${e(a.nameID.spNameQualifier)}</div>` : ''}
          </div></div>`;
        }
        if (a.conditions) {
          html += `<div class="section"><h5>Conditions</h5><div class="details-grid">
            ${a.conditions.notBefore ? `<div class="label">Not Before:</div><div class="value">${e(a.conditions.notBefore)}</div>` : ''}
            ${a.conditions.notOnOrAfter ? `<div class="label">Not On/After:</div><div class="value">${e(a.conditions.notOnOrAfter)}</div>` : ''}
            ${a.conditions.audiences && a.conditions.audiences.length ? `<div class="label">Audience(s):</div><div class="value">${a.conditions.audiences.map(au => e(au)).join('<br>')}</div>` : ''}
          </div></div>`;
        }
        if (a.authnStatement) {
          html += `<div class="section"><h5>Authentication</h5><div class="details-grid">
            ${a.authnStatement.authnInstant ? `<div class="label">Authn Instant:</div><div class="value">${e(a.authnStatement.authnInstant)}</div>` : ''}
            ${a.authnStatement.sessionIndex ? `<div class="label">Session Index:</div><div class="value">${e(a.authnStatement.sessionIndex)}</div>` : ''}
            ${a.authnStatement.authnContextClassRef ? `<div class="label">AuthnContext:</div><div class="value">${e(shortUrn(a.authnStatement.authnContextClassRef))}</div>` : ''}
          </div></div>`;
        }
        const attrKeys = Object.keys(a.attributes || {});
        if (attrKeys.length > 0) {
          html += `<div class="section"><h5>Attributes (${attrKeys.length})</h5><div class="saml-attributes">`;
          for (const [name, values] of Object.entries(a.attributes)) {
            const shortName = name.includes('/') ? name.split('/').pop() : name;
            html += `<div class="attribute-row">
              <div class="attribute-name" title="${e(name)}">${e(shortName)}</div>
              <div class="attribute-values">${values.map(v => `<span class="attribute-value">${e(v)}</span>`).join('')}</div>
            </div>`;
          }
          html += `</div></div>`;
        }
      }
    }

    // Logout fields
    if (p.messageType === 'LogoutRequest') {
      html += `<div class="section"><h5>Logout Details</h5><div class="details-grid">
        ${p.nameID ? `<div class="label">NameID:</div><div class="value">${e(p.nameID)}</div>` : ''}
        ${p.sessionIndex ? `<div class="label">Session Index:</div><div class="value">${e(p.sessionIndex)}</div>` : ''}
      </div></div>`;
    }
    if (p.messageType === 'LogoutResponse' && p.status) {
      const cls = p.status.isSuccess ? 'success' : 'failure';
      html += `<div class="section"><h5>Status</h5>
        <div class="saml-status ${cls}">${p.status.isSuccess ? '\u2713' : '\u2717'} ${e(p.status.code || p.status.fullCode)}</div>
      </div>`;
    }

    // Raw XML (collapsible)
    html += `<details class="saml-xml-details">
      <summary>Raw XML (${e(decoded.binding)} binding)</summary>
      <pre class="saml-xml">${e(SamlDecoder.prettyPrintXml(decoded.xmlText))}</pre>
    </details>`;

    return html;
  }

  /**
   * Populate SAML tab — decodes SAMLRequest / SAMLResponse from the captured request.
   */
  async populateSamlTab(request) {
    const samlRequestEl = document.getElementById('samlRequest');
    const samlResponseEl = document.getElementById('samlResponse');

    samlRequestEl.innerHTML = '<div class="loading">Decoding SAML…</div>';
    samlResponseEl.innerHTML = '';

    // Set default section headers while loading
    this.setSectionHeader('samlRequestSectionHeader', 'SAML Request', '');
    this.setSectionHeader('samlResponseSectionHeader', 'SAML Response', '');

    const decoded = await SamlDecoder.decodeSamlFromRequest(request);

    if (!decoded) {
      samlRequestEl.innerHTML = '<div class="empty-state">No SAML data in this request.</div>';
      samlResponseEl.innerHTML = '<div class="empty-state">No SAML data in this request.</div>';
      return;
    }

    if (decoded.error) {
      samlRequestEl.innerHTML = `<div class="error">⚠ Decode error: ${this.escapeHtml(decoded.error)}</div>`;
      samlResponseEl.innerHTML = '';
      return;
    }

    if (decoded.parsed && decoded.parsed.error) {
      const rawHtml = `<details class="saml-xml-details" open>
        <summary>Raw XML (${this.escapeHtml(decoded.binding)} binding)</summary>
        <pre class="saml-xml">${this.escapeHtml(decoded.xmlText)}</pre>
      </details>`;
      samlRequestEl.innerHTML = `<div class="error">${this.escapeHtml(decoded.parsed.error)}</div>${rawHtml}`;
      samlResponseEl.innerHTML = '';
      this.setSectionHeader('samlRequestSectionHeader', 'SAML Request', decoded.xmlText || '');
      return;
    }

    const isResponse = decoded.messageType === 'SAMLResponse' || (decoded.parsed && decoded.parsed.messageType === 'Response');
    const primaryEl = isResponse ? samlResponseEl : samlRequestEl;
    const emptyEl = isResponse ? samlRequestEl : samlResponseEl;
    const primaryHeaderId = isResponse ? 'samlResponseSectionHeader' : 'samlRequestSectionHeader';
    const primaryTitle = isResponse ? 'SAML Response' : 'SAML Request';

    primaryEl.innerHTML = this.renderSamlDecoded(decoded);
    emptyEl.innerHTML = `<div class="empty-state">No ${isResponse ? 'SAMLRequest' : 'SAMLResponse'} captured for this request.</div>`;

    // Copy text = pretty-printed XML
    const copyXml = decoded.xmlText ? SamlDecoder.prettyPrintXml(decoded.xmlText) : '';
    this.setSectionHeader(primaryHeaderId, primaryTitle, copyXml);
  }

  /**
   * Populate Entra tab — shows OAuth grant analysis and any available JWT claims.
   * JWT from response bodies is not available in MV3; we decode client_assertion
   * and id_token_hint JWTs present in the request itself.
   */
  populateEntraTab(request) {
    const entraSummary = document.getElementById('entraSummary');
    const entraClaims  = document.getElementById('entraClaims');
    const e = (v) => this.escapeHtml(v == null ? '' : String(v));

    const analysis = request.oauthAnalysis;

    // ── Summary section ────────────────────────────────────────────────────
    if (analysis && !analysis.error) {
      let summaryHtml = `
        <div class="details-grid">
          <div class="label">Grant Type:</div>
          <div class="value">${e(analysis.label)}</div>
          ${analysis.clientId ? `<div class="label">Client ID:</div><div class="value mono">${e(analysis.clientId)}</div>` : ''}
          ${analysis.scopes && analysis.scopes.length ? `<div class="label">Scopes:</div><div class="value">${analysis.scopes.map(s => e(s)).join(', ')}</div>` : ''}
        </div>
      `;
      if (analysis.pkce) {
        summaryHtml += `
          <div class="entra-badge-row">
            <span class="entra-feature-badge pkce-badge">PKCE — ${e(analysis.pkce.codeChallengeMethod)}</span>
            ${analysis.pkce.isS256 ? '<span class="entra-feature-badge compliant-badge">✓ RFC 7636 Compliant</span>' : '<span class="entra-feature-badge warning-badge">⚠ Use S256</span>'}
          </div>
        `;
      }
      if (analysis.authMethod) {
        summaryHtml += `
          <div class="entra-badge-row">
            <span class="entra-feature-badge auth-method-badge">${e(analysis.authMethodLabel || analysis.authMethod)}</span>
          </div>
        `;
      }
      entraSummary.innerHTML = summaryHtml;
      const summaryText = [
        `Grant: ${analysis.label}`,
        analysis.clientId ? `Client ID: ${analysis.clientId}` : '',
        analysis.scopes && analysis.scopes.length ? `Scopes: ${analysis.scopes.join(' ')}` : ''
      ].filter(Boolean).join('\n');
      this.setSectionHeader('entraSummarySectionHeader', 'Summary', summaryText);
    } else {
      entraSummary.innerHTML = '<div class="empty-state">No Entra-specific analysis available for this request.</div>';
      this.setSectionHeader('entraSummarySectionHeader', 'Summary', '');
    }

    // ── JWT Claims section ──────────────────────────────────────────────────
    // Attempt to decode any JWT travelling in request parameters:
    // client_assertion (client credentials / auth code), id_token_hint (authorize)
    const jwtSource = (analysis && analysis.clientAssertion && !analysis.clientAssertion.error)
      ? { jwt: Sanitize.extractJwtFromRequest(request), label: 'client_assertion' }
      : (analysis && analysis.idTokenHint && !analysis.idTokenHint.error)
        ? { jwt: Sanitize.extractJwtFromRequest(request, 'id_token_hint'), label: 'id_token_hint' }
        : null;

    if (jwtSource && jwtSource.jwt) {
      const decoded = EntraClaimsDecoder.decodeEntraToken(jwtSource.jwt);
      if (!decoded.error) {
        entraClaims.innerHTML = this.renderEntraClaims(decoded, jwtSource.label);
        this.setSectionHeader('entraClaimsSectionHeader', 'JWT Claims', `JWT source: ${jwtSource.label}`);

        // Update CAE badge
        const entraTabBtn = document.querySelector('[data-tab="entra"]');
        const caeBadge = entraTabBtn ? entraTabBtn.querySelector('.cae-badge') : null;
        if (caeBadge) caeBadge.style.display = decoded.caeEnabled ? 'inline' : 'none';
        return;
      }
    }

    entraClaims.innerHTML = '<div class="empty-state">JWT claims are decoded from <strong>client_assertion</strong> or <strong>id_token_hint</strong> parameters when present in the captured request.</div>';
    this.setSectionHeader('entraClaimsSectionHeader', 'JWT Claims', '');
  }

  /**
   * Render decoded Entra JWT claims into HTML.
   */
  renderEntraClaims(decoded, source) {
    const e = (v) => this.escapeHtml(v == null ? '' : String(v));
    let html = '';

    // Token summary bar
    if (decoded.summary) {
      const s = decoded.summary;
      html += `
        <div class="entra-token-summary">
          ${s.identityType ? `<span class="entra-feature-badge">${e(s.identityType)}</span>` : ''}
          ${s.tokenVersion ? `<span class="entra-feature-badge">v${e(s.tokenVersion)}</span>` : ''}
          ${decoded.caeEnabled ? '<span class="entra-feature-badge cae-feature">CAE ✓</span>' : ''}
          ${decoded.popBinding ? '<span class="entra-feature-badge pop-feature">PoP Bound</span>' : ''}
          ${s.isExpired ? '<span class="entra-feature-badge expired-feature">⚠ Expired</span>' : ''}
          <span class="entra-source-note">Source: ${e(source)}</span>
        </div>
        <div class="details-grid">
          ${s.tenant ? `<div class="label">Tenant:</div><div class="value mono">${e(s.tenant)}</div>` : ''}
          ${s.audience ? `<div class="label">Audience:</div><div class="value">${e(Array.isArray(s.audience) ? s.audience.join(', ') : s.audience)}</div>` : ''}
          ${s.expiry ? `<div class="label">Expiry:</div><div class="value">${e(s.expiry)}</div>` : ''}
          ${s.scopes ? `<div class="label">Scopes:</div><div class="value">${e(s.scopes)}</div>` : ''}
        </div>
      `;
    }

    // Warnings
    if (decoded.warnings && decoded.warnings.length > 0) {
      html += this.renderOAuthWarnings(decoded.warnings);
    }

    // Claims table
    if (decoded.claims && decoded.claims.length > 0) {
      html += '<div class="claims-table">';
      for (const claim of decoded.claims) {
        const rowClass = claim.isEntraSpecific ? 'claim-entra' : 'claim-standard';
        html += `
          <div class="claim-row ${rowClass}">
            <div class="claim-name" title="${e(claim.detail || '')}">
              ${e(claim.name)}
              ${claim.label ? `<span class="claim-label">${e(claim.label)}</span>` : ''}
            </div>
            <div class="claim-value ${claim.isTimestamp ? 'claim-timestamp' : ''}">` +
              this.makeCopyBtn(String(claim.rawValue), `Copy ${claim.name}`) +
              `${e(claim.value)}</div>
          </div>
        `;
      }
      html += '</div>';
    }

    return html;
  }

  /**
   * Close detail panel
   */
  closeDetailPanel() {
    document.getElementById('detailPanel').style.display = 'none';

    // Hide the pane splitter
    const splitter = document.getElementById('paneSplitter');
    if (splitter) splitter.style.display = 'none';

    // Hide related requests panel
    const relPanel = document.getElementById('relatedRequestsPanel');
    if (relPanel) relPanel.style.display = 'none';

    // Clear correlation highlights
    document.querySelectorAll('.correlated-highlight').forEach(el => el.classList.remove('correlated-highlight'));
    
    // Clear selection
    document.querySelectorAll('.request-item, .flow-group-item').forEach(item => {
      item.classList.remove('selected');
    });
    
    this.selectedRequest = null;
  }

  /**
   * Switch tabs
   */
  switchTab(tabName) {
    // Update tab buttons — maintain aria-selected for screen reader accessibility
    document.querySelectorAll('.tab-btn').forEach(btn => {
      const isActive = btn.dataset.tab === tabName;
      btn.classList.toggle('active', isActive);
      btn.setAttribute('aria-selected', isActive ? 'true' : 'false');
    });

    // Update tab content
    document.querySelectorAll('.tab-pane').forEach(pane => {
      pane.classList.remove('active');
      if (pane.id === tabName + 'Tab') {
        pane.classList.add('active');
      }
    });
  }

  /**
   * Update status bar with total count and per-flow-category breakdown.
   */
  updateStatusBar() {
    const statusText = document.getElementById('statusText');
    const requestCount = document.getElementById('requestCount');

    statusText.textContent = this.currentRequests.length > 0 ? 'Capturing' : 'Ready';

    if (this.currentRequests.length === 0) {
      requestCount.textContent = '0 requests';
      return;
    }

    const { total, byCategory, errors } = FlowCorrelator.countByCategory(this.currentRequests);

    const parts = [`${total} req`];
    const breakdown = FlowCorrelator.CATEGORIES
      .filter(cat => cat !== 'other' && byCategory[cat])
      .map(cat => `${FlowCorrelator.CATEGORY_LABELS[cat]}: ${byCategory[cat]}`)
      .join(', ');
    if (breakdown) parts.push(breakdown);
    if (errors) parts.push(`${errors} error${errors !== 1 ? 's' : ''}`);

    requestCount.textContent = parts.join(' · ');
  }
  /**
   * Draggable splitter — lets the user resize the request-list vs detail-panel split.
   */
  initSplitter() {
    const splitter = document.getElementById('paneSplitter');
    const listContainer = document.querySelector('.request-list-container');
    const mainContent = document.querySelector('.main-content');
    if (!splitter || !listContainer || !mainContent) return;

    // Restore saved split position for the CURRENT layout direction only.
    // If we restore the wrong axis (e.g. a pixel-width from a popout session into
    // the stacked popup layout) the list container ends up the wrong size.
    const isHorizontalNow = () => getComputedStyle(mainContent).flexDirection === 'row';
    if (isHorizontalNow()) {
      const savedW = localStorage.getItem('entraTracerSplitW');
      if (savedW) {
        listContainer.style.flex = '0 0 auto';
        listContainer.style.width = parseFloat(savedW) + 'px';
        listContainer.style.height = '';
      }
    } else {
      const savedH = localStorage.getItem('entraTracerSplitH');
      if (savedH) {
        listContainer.style.flex = '0 0 auto';
        listContainer.style.height = parseFloat(savedH) + 'px';
        listContainer.style.width = '';
      }
    }

    let dragging = false;
    let isHorizontal = false; // true = side-by-side (col-resize), false = stacked (row-resize)
    let startX = 0, startY = 0, startW = 0, startH = 0;

    splitter.addEventListener('mousedown', (e) => {
      // Detect current layout direction at drag-start so mid-resize changes are handled correctly
      isHorizontal = isHorizontalNow();
      dragging = true;
      startX = e.clientX;
      startY = e.clientY;
      startW = listContainer.getBoundingClientRect().width;
      startH = listContainer.getBoundingClientRect().height;
      splitter.classList.add('dragging');
      document.body.classList.add('no-select');
      e.preventDefault();
    });

    document.addEventListener('mousemove', (e) => {
      if (!dragging) return;
      if (isHorizontal) {
        const mainW = mainContent.getBoundingClientRect().width;
        const newW = Math.max(200, Math.min(mainW - 200, startW + (e.clientX - startX)));
        listContainer.style.flex = '0 0 auto';
        listContainer.style.width = newW + 'px';
        listContainer.style.height = '';
        localStorage.setItem('entraTracerSplitW', newW);
      } else {
        const mainH = mainContent.getBoundingClientRect().height;
        const newH = Math.max(60, Math.min(mainH - 80, startH + (e.clientY - startY)));
        listContainer.style.flex = '0 0 auto';
        listContainer.style.height = newH + 'px';
        listContainer.style.width = '';
        localStorage.setItem('entraTracerSplitH', newH);
      }
    });

    document.addEventListener('mouseup', () => {
      if (!dragging) return;
      dragging = false;
      splitter.classList.remove('dragging');
      document.body.classList.remove('no-select');
    });
  }

  /**
   * Open the extension UI in a dedicated, freely-resizable popup window.
   * The button is hidden when we are already running in that standalone window.
   */
  initPopout() {
    const params = new URLSearchParams(window.location.search);
    if (params.get('popout') === 'true') {
      // Add class so CSS overrides the fixed popup dimensions to fill the window
      document.documentElement.classList.add('popout-mode');
      // Hide the popout button so it cannot be re-opened
      const btn = document.getElementById('popoutBtn');
      if (btn) btn.style.display = 'none';
      // Hide the drag-resize handle — not needed in a standalone resizable window
      const resizeHandle = document.getElementById('resizeHandle');
      if (resizeHandle) resizeHandle.style.display = 'none';
    }
  }

  popout() {
    const url = chrome.runtime.getURL('src/ui.html') + '?popout=true';
    const w = Math.min(window.screen.availWidth, 1280);
    const h = Math.min(window.screen.availHeight, 900);
    chrome.windows.create({
      url,
      type: 'popup',
      width: w,
      height: h
    });
  }

  /**
   * Popup resize handle — drag the bottom-right corner to resize both width and height.
   * Maximum dimensions are capped at the available screen area.
   */
  initPopupResize() {
    const handle = document.getElementById('resizeHandle');
    if (!handle) return;

    // In popout mode the window is freely resizable by the OS — skip the fixed-dimension logic
    const params = new URLSearchParams(window.location.search);
    if (params.get('popout') === 'true') return;

    const html = document.documentElement;

    // Restore saved popup dimensions onto the html element (which drives the popup window size)
    const savedH = localStorage.getItem('entraTracerPopupH');
    if (savedH) html.style.height = parseFloat(savedH) + 'px';
    const savedW = localStorage.getItem('entraTracerPopupW');
    if (savedW) html.style.width = parseFloat(savedW) + 'px';

    let dragging = false;
    let startX = 0, startY = 0, startW = 0, startH = 0;

    handle.addEventListener('mousedown', (e) => {
      dragging = true;
      startX = e.clientX;
      startY = e.clientY;
      startW = html.getBoundingClientRect().width;
      startH = html.getBoundingClientRect().height;
      document.body.classList.add('no-select');
      e.preventDefault();
    });

    document.addEventListener('mousemove', (e) => {
      if (!dragging) return;
      const maxH = window.screen.availHeight;
      const maxW = window.screen.availWidth;
      const newH = Math.max(400, Math.min(maxH, startH + (e.clientY - startY)));
      const newW = Math.max(960, Math.min(maxW, startW + (e.clientX - startX)));
      // Setting dimensions on the html element causes Chrome to resize the popup window
      html.style.width = newW + 'px';
      html.style.height = newH + 'px';
      localStorage.setItem('entraTracerPopupH', newH);
      localStorage.setItem('entraTracerPopupW', newW);
    });

    document.addEventListener('mouseup', () => {
      if (!dragging) return;
      dragging = false;
      document.body.classList.remove('no-select');
    });
  }

}

// Initialize UI when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  new EntraAuthTracerUI();
});