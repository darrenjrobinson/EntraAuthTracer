/**
 * Entra Auth Tracer - UI Logic
 * Handles the extension popup interface
 */

import EntraClaimsDecoder from './EntraClaimsDecoder.js';
import Fido2Decoder from './Fido2Decoder.js';
import SamlDecoder from './SamlDecoder.js';

class EntraAuthTracerUI {
  constructor() {
    this.currentRequests = [];
    this.selectedRequest = null;
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
  }

  /**
   * Bind event listeners
   */
  bindEvents() {
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

    // Control buttons
    document.getElementById('clearBtn').addEventListener('click', () => {
      this.clearData();
    });

    document.getElementById('exportBtn').addEventListener('click', () => {
      this.exportData();
    });

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

  /**
   * Export data
   */
  async exportData() {
    try {
      const response = await new Promise((resolve) => {
        chrome.runtime.sendMessage({ action: 'exportData' }, resolve);
      });
      
      if (!response.success) {
        alert('Export functionality not yet implemented');
      }
    } catch (error) {
      console.error('Failed to export data:', error);
    }
  }

  /**
   * Apply current filters and render.  Used by both loadData and filter change handlers.
   */
  filterAndRender() {
    const hasFilters = this.filters.search || this.filters.method || this.filters.flow || this.filters.status;
    if (hasFilters) {
      this.filterRequests();
    } else {
      this.renderRequestList();
    }
  }

  /**
   * Filter requests based on current filters
   */
  filterRequests() {
    const filtered = this.currentRequests.filter(req => {
      // Search filter
      if (this.filters.search && !req.url.toLowerCase().includes(this.filters.search.toLowerCase())) {
        return false;
      }

      // Method filter
      if (this.filters.method && req.method !== this.filters.method) {
        return false;
      }

      // Flow filter
      if (this.filters.flow) {
        const flowType = this.getFlowTypeCategory(req.flowType);
        if (flowType !== this.filters.flow) {
          return false;
        }
      }

      // Status filter
      if (this.filters.status && req.status !== this.filters.status) {
        return false;
      }

      return true;
    });

    this.renderRequestList(filtered);
  }

  /**
   * Get flow type category for filtering
   */
  getFlowTypeCategory(flowType) {
    if (!flowType) return 'other';
    if (flowType.startsWith('fido2_')) return 'fido2';
    if (flowType.startsWith('device_code')) return 'device_code';
    if (flowType.includes('oauth') || flowType.includes('pkce') || flowType.includes('token')) return 'oauth';
    if (flowType === 'saml' || flowType === 'wsfed') return 'saml';
    return 'other';
  }

  /**
   * Render the request list
   */
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
        items.push(`<div class="request-item error-item" title="${err.message}">&#9888; Error rendering request: ${(req && req.url) ? req.url.substring(0, 80) : '(unknown)'}</div>`);
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
    const flowCategory = this.getFlowTypeCategory(request.flowType);
    const status = request.status || 'pending';

    return `
      <div class="request-item" data-request-id="${request.id}">
        <span class="col-timestamp">${time}</span>
        <span class="col-method">${method}</span>
        <span class="col-url" title="${request.url || ''}">${shortUrl || hostname}</span>
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
    document.querySelectorAll('.request-item').forEach(item => {
      item.classList.remove('selected');
      if (item.dataset.requestId === request.id) {
        item.classList.add('selected');
      }
    });

    // Show detail panel
    this.showDetailPanel(request);
  }

  /**
   * Show the detail panel with request information
   */
  showDetailPanel(request) {
    const panel = document.getElementById('detailPanel');
    panel.style.display = 'flex';

    // Show the pane splitter
    const splitter = document.getElementById('paneSplitter');
    if (splitter) splitter.style.display = 'flex';

    // Update title
    const url = new URL(request.url);
    document.getElementById('detailTitle').textContent = `${request.method} ${url.pathname}`;

    // Determine which tabs to show
    this.updateTabVisibility(request);

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

    // Check for JWT tokens in response
    // This will be enhanced when JWT decoding is fully implemented
    return false;
  }

  /**
   * Check for CAE capability in request
   */
  checkForCAE(request) {
    // This will be implemented when JWT decoding is added
    // For now, return false as placeholder
    return false;
  }

  /**
   * Populate HTTP tab
   */
  populateHttpTab(request) {
    const requestDetails = document.getElementById('requestDetails');
    const responseDetails = document.getElementById('responseDetails');

    // Request details
    requestDetails.innerHTML = `
      <div class="label">URL:</div>
      <div class="value">${request.url}</div>
      <div class="label">Method:</div>
      <div class="value">${request.method}</div>
      <div class="label">Timestamp:</div>
      <div class="value">${new Date(request.timestamp).toISOString()}</div>
      <div class="label">Flow Type:</div>
      <div class="value">${request.flowType}</div>
    `;

    // Response details
    if (request.statusCode) {
      responseDetails.innerHTML = `
        <div class="label">Status:</div>
        <div class="value">${request.statusCode} ${request.status}</div>
        ${request.error ? `
          <div class="label">Error:</div>
          <div class="value">${request.error}</div>
        ` : ''}
      `;
    } else {
      responseDetails.innerHTML = '<div class="value">Response pending...</div>';
    }

    // Show FIDO2 section if applicable
    this.populateFido2Section(request);
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
    } else if (request.flowType.startsWith('fido2_')) {
      fido2Section.style.display = 'block';
      fido2Details.innerHTML = request.fido2Analysis?.error ? 
        `<div class="error">FIDO2 Error: ${request.fido2Analysis.error}</div>` :
        '<div>No FIDO2 data available for this request</div>';
    } else {
      fido2Section.style.display = 'none';
    }
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
            <div class="value">${clientData.type}</div>
            <div class="label">Origin:</div>
            <div class="value">${clientData.origin}</div>
            <div class="label">Challenge:</div>
            <div class="value" title="${clientData.challenge}">${clientData.challenge.substring(0, 40)}...</div>
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
            <div class="value" title="${authData.rpIdHash}">${authData.rpIdHash.substring(0, 40)}...</div>
            <div class="label">Signature Counter:</div>
            <div class="value">${authData.signCount}</div>
          </div>
          
          <h6>Authenticator Flags:</h6>
          <div class="flags-grid">
            <div class="flag-item ${flags.UP ? 'flag-set' : 'flag-unset'}" title="User Present">
              UP ${flags.UP ? '✓' : '✗'}
            </div>
            <div class="flag-item ${flags.UV ? 'flag-set' : 'flag-unset'}" title="User Verified">
              UV ${flags.UV ? '✓' : '✗'}
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
        html += `
          <div class="fido2-section">
            <h5>🏷️ Attested Credential Data</h5>
            <div class="details-grid">
              <div class="label">AAGUID:</div>
              <div class="value">${credData.aaguid}</div>
              <div class="label">Credential ID Length:</div>
              <div class="value">${credData.credentialIdLength} bytes</div>
              <div class="label">Credential ID:</div>
              <div class="value" title="${credData.credentialId}">${credData.credentialId.substring(0, 40)}...</div>
            </div>
            
            ${this.renderPublicKeyInfo(credData.credentialPublicKey)}
          </div>
        `;
      }
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
        <div class="error">${publicKeyData?.error || 'No public key data'}</div>
      `;
    }

    let html = '<h6>🔑 Credential Public Key:</h6>';
    
    if (publicKeyData.keyInfo && !publicKeyData.keyInfo.error) {
      const keyInfo = publicKeyData.keyInfo;
      
      html += `
        <div class="details-grid">
          <div class="label">Key Type:</div>
          <div class="value">${keyInfo.keyTypeDescription}</div>
          <div class="label">Algorithm:</div>
          <div class="value">${keyInfo.algorithmDescription}</div>
        </div>
      `;

      // EC2 Key parameters
      if (keyInfo.keyType === 2 && keyInfo.parameters.curve) {
        html += `
          <div class="details-grid">
            <div class="label">Curve:</div>
            <div class="value">${keyInfo.parameters.curveDescription}</div>
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
      html += `<div class="error">${publicKeyData.keyInfo?.error || 'Unable to parse key information'}</div>`;
    }

    // CBOR raw data (collapsible)
    html += `
      <details class="cbor-details">
        <summary>Raw CBOR Data (${publicKeyData.size} bytes)</summary>
        <pre class="cbor-hex">${publicKeyData.hex}</pre>
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
    
    if (params.length > 0) {
      urlParameters.innerHTML = params.map(([key, value]) => `
        <div class="param-name">${key}:</div>
        <div class="param-value">${this.redactSensitiveValues(key, value)}</div>
      `).join('');
    } else {
      urlParameters.innerHTML = '<div class="param-value">No URL parameters</div>';
    }

    // Request body
    if (request.requestBody) {
      requestBody.innerHTML = this.renderRequestBody(request.requestBody);
    } else {
      requestBody.innerHTML = '<div class="param-value">No request body</div>';
    }
  }

  /**
   * Render request body
   */
  renderRequestBody(body) {
    if (body.type === 'formData') {
      return Object.entries(body.data).map(([key, values]) => `
        <div class="param-name">${key}:</div>
        <div class="param-value">${this.redactSensitiveValues(key, values[0])}</div>
      `).join('');
    } else if (body.type === 'json') {
      return `<div class="param-value"><pre>${JSON.stringify(body.data, null, 2)}</pre></div>`;
    } else {
      return `<div class="param-value">${body.data}</div>`;
    }
  }

  /**
   * Escape a value for safe insertion into HTML.
   */
  escapeHtml(text) {
    if (text == null) return '';
    return String(text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
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
   * Redact sensitive values
   */
  redactSensitiveValues(key, value) {
    const sensitiveKeys = ['client_secret', 'password', 'refresh_token'];
    
    if (sensitiveKeys.some(k => key.toLowerCase().includes(k))) {
      return '[REDACTED]';
    }
    
    return String(value).substring(0, 200) + (value.length > 200 ? '...' : '');
  }

  /**
   * Populate SAML tab — decodes SAMLRequest / SAMLResponse from the captured request.
   */
  async populateSamlTab(request) {
    const samlRequestEl = document.getElementById('samlRequest');
    const samlResponseEl = document.getElementById('samlResponse');

    samlRequestEl.innerHTML = '<div class="loading">Decoding SAML…</div>';
    samlResponseEl.innerHTML = '';

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
      return;
    }

    const isResponse = decoded.messageType === 'SAMLResponse' || (decoded.parsed && decoded.parsed.messageType === 'Response');
    const primaryEl = isResponse ? samlResponseEl : samlRequestEl;
    const emptyEl = isResponse ? samlRequestEl : samlResponseEl;

    primaryEl.innerHTML = this.renderSamlDecoded(decoded);
    emptyEl.innerHTML = `<div class="empty-state">No ${isResponse ? 'SAMLRequest' : 'SAMLResponse'} captured for this request.</div>`;
  }

  /**
   * Populate Entra tab
   */
  populateEntraTab(request) {
    const entraSummary = document.getElementById('entraSummary');
    const entraClaims = document.getElementById('entraClaims');

    // This will be fully implemented when JWT decoding is added
    entraSummary.innerHTML = '<div>Entra token decoding not yet implemented</div>';
    entraClaims.innerHTML = '<div>JWT claims analysis not yet implemented</div>';
  }

  /**
   * Close detail panel
   */
  closeDetailPanel() {
    document.getElementById('detailPanel').style.display = 'none';

    // Hide the pane splitter
    const splitter = document.getElementById('paneSplitter');
    if (splitter) splitter.style.display = 'none';
    
    // Clear selection
    document.querySelectorAll('.request-item').forEach(item => {
      item.classList.remove('selected');
    });
    
    this.selectedRequest = null;
  }

  /**
   * Switch tabs
   */
  switchTab(tabName) {
    // Update tab buttons
    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.classList.remove('active');
      if (btn.dataset.tab === tabName) {
        btn.classList.add('active');
      }
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
   * Update status bar
   */
  updateStatusBar() {
    const statusText = document.getElementById('statusText');
    const requestCount = document.getElementById('requestCount');

    statusText.textContent = this.currentRequests.length > 0 ? 'Capturing' : 'Ready';
    requestCount.textContent = `${this.currentRequests.length} requests`;
  }
  /**
   * Draggable splitter — lets the user resize the request-list vs detail-panel split.
   */
  initSplitter() {
    const splitter = document.getElementById('paneSplitter');
    const listContainer = document.querySelector('.request-list-container');
    const mainContent = document.querySelector('.main-content');
    if (!splitter || !listContainer || !mainContent) return;

    // Restore saved split height (stored in pixels)
    const saved = localStorage.getItem('entraTracerSplitH');
    if (saved) {
      listContainer.style.flex = '0 0 auto';
      listContainer.style.height = parseFloat(saved) + 'px';
    }

    let dragging = false;
    let startY = 0;
    let startH = 0;

    splitter.addEventListener('mousedown', (e) => {
      dragging = true;
      startY = e.clientY;
      startH = listContainer.getBoundingClientRect().height;
      splitter.classList.add('dragging');
      document.body.classList.add('no-select');
      e.preventDefault();
    });

    document.addEventListener('mousemove', (e) => {
      if (!dragging) return;
      const mainH = mainContent.getBoundingClientRect().height;
      const newH = Math.max(60, Math.min(mainH - 80, startH + (e.clientY - startY)));
      listContainer.style.flex = '0 0 auto';
      listContainer.style.height = newH + 'px';
      localStorage.setItem('entraTracerSplitH', newH);
    });

    document.addEventListener('mouseup', () => {
      if (!dragging) return;
      dragging = false;
      splitter.classList.remove('dragging');
      document.body.classList.remove('no-select');
    });
  }

  /**
   * Popup height resize handle — drag the bottom-right corner to make the popup taller/shorter.
   */
  initPopupResize() {
    const handle = document.getElementById('resizeHandle');
    if (!handle) return;

    // Restore saved popup height
    const savedH = localStorage.getItem('entraTracerPopupH');
    if (savedH) {
      document.body.style.height = savedH + 'px';
    }

    let dragging = false;
    let startY = 0;
    let startH = 0;

    handle.addEventListener('mousedown', (e) => {
      dragging = true;
      startY = e.clientY;
      startH = document.body.getBoundingClientRect().height;
      document.body.classList.add('no-select');
      e.preventDefault();
    });

    document.addEventListener('mousemove', (e) => {
      if (!dragging) return;
      const newH = Math.max(400, Math.min(1200, startH + (e.clientY - startY)));
      document.body.style.height = newH + 'px';
      localStorage.setItem('entraTracerPopupH', newH);
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