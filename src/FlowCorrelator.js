/**
 * Entra Auth Tracer - Flow Correlator
 *
 * Pure helpers that turn the flat list of captured requests into the shapes the
 * UI (and any other consumer) needs: flow-type categories, filter application,
 * correlated flow groups for the timeline, related-request lookup and
 * per-category counts. No DOM or chrome.* access — usable from the popup, the
 * background service worker and tests alike.
 */

class FlowCorrelator {
  /** Display order of categories. */
  static CATEGORIES = ['saml', 'oauth', 'fido2', 'device_code', 'did', 'other'];

  static CATEGORY_LABELS = {
    saml: 'SAML',
    oauth: 'OAuth',
    fido2: 'FIDO2',
    device_code: 'Device Code',
    did: 'Verified ID',
    other: 'Other'
  };

  /**
   * Explicit flowType → category map for every value SAMLTrace.detectFlowType
   * and OAuthDecoder.detectFlowTypeFromBody can produce. Prefix fallbacks in
   * getFlowTypeCategory cover future additions.
   */
  static FLOW_TYPE_CATEGORY = {
    // SAML / WS-Federation
    saml: 'saml',
    wsfed: 'saml',
    saml_ecp: 'saml',
    adfs_saml: 'saml',
    // FIDO2 / WebAuthn
    fido2_assertion: 'fido2',
    fido2_attestation: 'fido2',
    fido2_preflight: 'fido2',
    fido2_webauthn: 'fido2',
    // Device code
    device_code_initiation: 'device_code',
    device_code_poll: 'device_code',
    // OAuth 2.x / OIDC
    oauth_authorize: 'oauth',
    oauth_token: 'oauth',
    pkce_flow: 'oauth',
    pkce_token_exchange: 'oauth',
    authcode_token_exchange: 'oauth',
    client_credentials: 'oauth',
    refresh_token: 'oauth',
    ropc: 'oauth',
    oidc_discovery: 'oauth',
    oidc_userinfo: 'oauth',
    oidc_introspect: 'oauth',
    oidc_revocation: 'oauth',
    oidc_logout: 'oauth',
    okta_authn: 'oauth',
    okta_idx: 'oauth',
    // Verified ID / DID
    did_issuance_request: 'did',
    did_presentation_request: 'did',
    did_request_fetch: 'did',
    did_callback: 'did',
    did_vc_service: 'did',
    did_resolution: 'did',
    did_status: 'did',
    vc_presentation_openid4vp: 'did',
    vc_issuance_openid4vci: 'did',
    // Fallback
    unknown: 'other'
  };

  /** Requests to the same DID host within this window form one Verified ID flow. */
  static DID_SESSION_WINDOW_MS = 30000;
  /** OAuth requests sharing a client_id within this window form one flow. */
  static OAUTH_SESSION_WINDOW_MS = 60000;

  /**
   * Map a flowType to its display category.
   */
  static getFlowTypeCategory(flowType) {
    if (!flowType) return 'other';
    const known = FlowCorrelator.FLOW_TYPE_CATEGORY[flowType];
    if (known) return known;
    // Forward-compatible prefix fallbacks for flow types added later
    if (flowType.startsWith('fido2_')) return 'fido2';
    if (flowType.startsWith('device_code')) return 'device_code';
    if (flowType.startsWith('did_') || flowType.startsWith('vc_')) return 'did';
    if (flowType.startsWith('oidc_') || flowType.startsWith('okta_') ||
        flowType.includes('oauth') || flowType.includes('pkce') || flowType.includes('authcode')) return 'oauth';
    if (flowType.includes('saml') || flowType.includes('wsfed')) return 'saml';
    return 'other';
  }

  /**
   * True for OAuth-family flows (including device code).
   */
  static isOAuthFlow(flowType) {
    const cat = FlowCorrelator.getFlowTypeCategory(flowType);
    return cat === 'oauth' || cat === 'device_code';
  }

  /**
   * Return the subset of requests matching every active filter.
   * Returns the input array itself when no filter is active.
   *
   * @param {object[]} requests
   * @param {{ search?: string, method?: string, flow?: string, status?: string }} filters
   */
  static applyFilters(requests, filters = {}) {
    const { search = '', method = '', flow = '', status = '' } = filters || {};
    if (!search && !method && !flow && !status) return requests;
    const needle = search.toLowerCase();
    return requests.filter(req => {
      if (needle && !(req.url || '').toLowerCase().includes(needle)) return false;
      if (method && req.method !== method) return false;
      if (flow && FlowCorrelator.getFlowTypeCategory(req.flowType) !== flow) return false;
      if (status && req.status !== status) return false;
      return true;
    });
  }

  /**
   * Group requests into correlated flow groups for the timeline view.
   * Returns an array of { type, key, label, requests[] } sorted by first timestamp.
   *   type: 'device_code' | 'did' | 'oauth' | 'standalone'
   */
  static computeFlowGroups(requests) {
    const groups = [];
    const assignedIds = new Set();

    // 1. Device Code correlation groups (keyed by deviceCodeCorrelationKey)
    const dcMap = new Map();
    for (const r of requests) {
      if (r.deviceCodeCorrelationKey) {
        if (!dcMap.has(r.deviceCodeCorrelationKey)) dcMap.set(r.deviceCodeCorrelationKey, []);
        dcMap.get(r.deviceCodeCorrelationKey).push(r);
        assignedIds.add(r.id);
      }
    }
    for (const [key, reqs] of dcMap) {
      const sorted = reqs.sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));
      const clientId = (sorted[0].oauthAnalysis && sorted[0].oauthAnalysis.clientId)
        ? sorted[0].oauthAnalysis.clientId.substring(0, 8) + '…'
        : key.substring(0, 8) + '…';
      groups.push({ type: 'device_code', key, label: `Device Code — ${clientId}`, requests: sorted });
    }

    // 2. Verified ID / DID flows — group by hostname within a session window
    const didReqs = requests.filter(r =>
      !assignedIds.has(r.id) &&
      (r.flowType && (r.flowType.startsWith('did_') || r.flowType.startsWith('vc_')))
    );
    const byDidHost = new Map();
    for (const r of didReqs) {
      let host = 'did';
      try { host = new URL(r.url).hostname; } catch { /* keep */ }
      if (!byDidHost.has(host)) byDidHost.set(host, []);
      byDidHost.get(host).push(r);
    }
    for (const [host, reqs] of byDidHost) {
      const sorted = reqs.sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));
      let sessionStart = null;
      let session = [];
      const flushDidSession = () => {
        if (session.length === 0) return;
        const firstOp = session[0].didAnalysis && session[0].didAnalysis.operation
          ? session[0].didAnalysis.operation
          : 'Verified ID Request';
        const lbl = session.length === 1 ? firstOp : `Verified ID Flow — ${firstOp}`;
        groups.push({ type: 'did', key: `did_${host}_${sessionStart}`, label: lbl, requests: session });
        session = [];
        sessionStart = null;
      };
      for (const r of sorted) {
        if (sessionStart === null || (r.timestamp - sessionStart) <= FlowCorrelator.DID_SESSION_WINDOW_MS) {
          session.push(r);
          assignedIds.add(r.id);
          if (sessionStart === null) sessionStart = r.timestamp;
        } else {
          flushDidSession();
          session = [r];
          sessionStart = r.timestamp;
          assignedIds.add(r.id);
        }
      }
      flushDidSession();
    }

    // 3. OAuth flows sharing the same clientId within a session window
    const oauthReqs = requests.filter(r =>
      !assignedIds.has(r.id) && r.oauthAnalysis && !r.oauthAnalysis.error && r.oauthAnalysis.clientId
    );
    const byClient = new Map();
    for (const r of oauthReqs) {
      const cid = r.oauthAnalysis.clientId;
      if (!byClient.has(cid)) byClient.set(cid, []);
      byClient.get(cid).push(r);
    }
    for (const [clientId, reqs] of byClient) {
      const sorted = reqs.sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));
      let sessionStart = null;
      let session = [];
      const flushSession = () => {
        if (session.length === 0) return;
        const lbl = session.length === 1
          ? (session[0].oauthAnalysis.label || 'OAuth Request')
          : `OAuth Flow — ${session[0].oauthAnalysis.label || clientId.substring(0, 8) + '…'}`;
        groups.push({ type: 'oauth', key: `oauth_${clientId}_${sessionStart}`, label: lbl, requests: session });
        session = [];
        sessionStart = null;
      };
      for (const r of sorted) {
        if (sessionStart === null || (r.timestamp - sessionStart) <= FlowCorrelator.OAUTH_SESSION_WINDOW_MS) {
          session.push(r);
          assignedIds.add(r.id);
          if (sessionStart === null) sessionStart = r.timestamp;
        } else {
          flushSession();
          session = [r];
          sessionStart = r.timestamp;
          assignedIds.add(r.id);
        }
      }
      flushSession();
    }

    // 4. Remaining requests as standalone (single-item) entries, preserving time order
    const remaining = requests.filter(r => !assignedIds.has(r.id));
    for (const r of remaining) {
      groups.push({ type: 'standalone', key: r.id, label: null, requests: [r] });
    }

    // Sort groups by the timestamp of their first request
    groups.sort((a, b) => ((a.requests[0] && a.requests[0].timestamp) || 0) - ((b.requests[0] && b.requests[0].timestamp) || 0));

    return groups;
  }

  /**
   * Return requests correlated with the given request (same device code session
   * or same OAuth clientId within the OAuth session window), sorted
   * chronologically. The request itself is NOT included.
   */
  static findRelatedRequests(request, allRequests) {
    const results = [];
    if (request.deviceCodeCorrelationKey) {
      allRequests
        .filter(r => r.id !== request.id && r.deviceCodeCorrelationKey === request.deviceCodeCorrelationKey)
        .forEach(r => results.push(r));
    } else if (request.oauthAnalysis && request.oauthAnalysis.clientId) {
      const cid = request.oauthAnalysis.clientId;
      const ts = request.timestamp || 0;
      allRequests
        .filter(r =>
          r.id !== request.id &&
          r.oauthAnalysis && r.oauthAnalysis.clientId === cid &&
          Math.abs((r.timestamp || 0) - ts) <= FlowCorrelator.OAUTH_SESSION_WINDOW_MS
        )
        .forEach(r => results.push(r));
    }
    return results.sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));
  }

  /**
   * Short step description for a request within a flow group.
   */
  static getFlowStepDesc(r, idx) {
    if (r.flowType === 'device_code_initiation') return 'Initiation';
    if (r.flowType && r.flowType.startsWith('device_code') && r.status === 'completed') return 'Token issued';
    if (r.flowType && r.flowType.startsWith('device_code')) return `Poll #${idx}`;
    if (r.didAnalysis && r.didAnalysis.operation) return r.didAnalysis.operation;
    if (r.oauthAnalysis && r.oauthAnalysis.label) return r.oauthAnalysis.label;
    return '';
  }

  /**
   * Count requests per category plus totals and errors.
   * @returns {{ total: number, byCategory: Record<string, number>, errors: number }}
   */
  static countByCategory(requests) {
    const byCategory = {};
    let errors = 0;
    for (const r of requests) {
      const cat = FlowCorrelator.getFlowTypeCategory(r.flowType);
      byCategory[cat] = (byCategory[cat] || 0) + 1;
      if (r.status === 'error') errors++;
    }
    return { total: requests.length, byCategory, errors };
  }
}

export default FlowCorrelator;
