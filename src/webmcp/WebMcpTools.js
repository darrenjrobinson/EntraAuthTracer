/**
 * Entra Auth Tracer - WebMCP tool implementations
 *
 * The six read-only tools, implemented as pure async functions over the captured
 * request list. Nothing here touches chrome.* or the DOM, so the module runs in
 * the background service worker and under Jest alike. Results are plain JSON,
 * newest first, credential-redacted and size-budgeted.
 */

import FlowCorrelator from '../FlowCorrelator.js';
import Sanitize from '../Sanitize.js';
import EntraClaimsDecoder from '../EntraClaimsDecoder.js';
import SamlDecoder from '../SamlDecoder.js';
import ProviderDetector from '../ProviderDetector.js';
import WebMcpToolSchemas from './WebMcpToolSchemas.js';
import { ERROR_CODES } from './protocol.js';

/** Error thrown by tools; `code` is one of ERROR_CODES. */
export class WebMcpToolError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'WebMcpToolError';
    this.code = code;
  }
}

const FIDO2_LABELS = {
  fido2_assertion: 'FIDO2 Authentication (Assertion)',
  fido2_attestation: 'FIDO2 Registration (Attestation)',
  fido2_preflight: 'FIDO2 Pre-flight Check',
  fido2_webauthn: 'WebAuthn Endpoint'
};

/** Request parameters that may carry a JWT sent by the client. */
const JWT_PARAMS = ['client_assertion', 'id_token_hint', 'assertion', 'request', 'token', 'id_token', 'access_token'];

/** Claims consulted, in order, to name the user. */
const USER_CLAIMS = ['preferred_username', 'upn', 'unique_name', 'email', 'sub'];

const SEVERITY_RANK = { error: 0, warning: 1, info: 2 };

/** Keys redacted in tool output on top of the Sanitize policy. */
const EXTRA_SECRET_KEYS = ['code'];

class WebMcpTools {
  static DEFAULT_LIMIT = 20;
  static MAX_LIMIT = 100;
  static MAX_TEXT = 2048;
  static MAX_RAW_BODY = 4096;
  static MAX_XML = 8192;
  static MAX_RESULT_BYTES = 65536;

  static EMPTY_NOTE =
    'No captured sessions — the background worker may have restarted (captures are held in memory only). ' +
    'Perform an authentication flow in the browser and call the tool again.';

  static TOKEN_NOTE =
    'Only JWTs sent by the client are visible (client_assertion, id_token_hint, assertion, request, Authorization: Bearer). ' +
    'Tokens issued by the identity provider travel in responses, which Manifest V3 extensions cannot read.';

  // ─── Dispatch ────────────────────────────────────────────────────────────

  /**
   * Validate arguments, run a tool and apply the size budget.
   * @throws {WebMcpToolError}
   */
  static async run(toolName, args, requests, ctx = {}) {
    if (!WebMcpToolSchemas.TOOLS[toolName]) {
      throw new WebMcpToolError(ERROR_CODES.UNKNOWN_TOOL, `Unknown tool: ${toolName}`);
    }
    const validated = WebMcpToolSchemas.validateArgs(toolName, args);
    if (!validated.ok) throw new WebMcpToolError(ERROR_CODES.INVALID_ARGS, validated.error);

    const list = Array.isArray(requests) ? requests : [];
    const result = await WebMcpTools[toolName](list, validated.value, ctx);
    if (list.length === 0) {
      result.note = result.note ? `${result.note} ${WebMcpTools.EMPTY_NOTE}` : WebMcpTools.EMPTY_NOTE;
    }
    return WebMcpTools.enforceSizeBudget(result);
  }

  // ─── Tools ───────────────────────────────────────────────────────────────

  static async list_auth_sessions(requests, { limit = WebMcpTools.DEFAULT_LIMIT, flowType } = {}) {
    const index = WebMcpTools.buildFlowIndex(requests);
    let items = WebMcpTools.newestFirst(requests);
    if (flowType) items = items.filter(r => WebMcpTools.matchesFlowType(r, flowType));
    const sessions = items.slice(0, limit).map(r => WebMcpTools.summarizeSession(r, index));
    return {
      total: items.length,
      returned: sessions.length,
      limit,
      sessions,
      flows: { count: index.groups.length }
    };
  }

  static async search_sessions(requests, args = {}) {
    const { query, flowType, provider, status, statusCode, since, until } = args;
    const limit = args.limit || WebMcpTools.DEFAULT_LIMIT;
    const index = WebMcpTools.buildFlowIndex(requests);
    const sinceMs = WebMcpTools.parseTime(since);
    const untilMs = WebMcpTools.parseTime(until);
    const needle = query ? query.toLowerCase() : null;
    const providerNeedle = provider ? provider.toLowerCase() : null;

    const rows = WebMcpTools.newestFirst(requests)
      .map(r => WebMcpTools.summarizeSession(r, index))
      .filter(row => {
        if (flowType && !(row.flowCategory === flowType || row.flowType === flowType)) return false;
        if (providerNeedle && !(row.provider.id === providerNeedle || String(row.provider.label || '').toLowerCase().includes(providerNeedle))) return false;
        if (status && row.status !== status) return false;
        if (statusCode !== undefined && row.statusCode !== statusCode) return false;
        if (sinceMs !== null && row.timestampMs < sinceMs) return false;
        if (untilMs !== null && row.timestampMs > untilMs) return false;
        if (needle) {
          const hay = [row.url, row.flowType, row.flowLabel, row.provider.id, row.provider.label, row.clientId, row.user, row.statusCode]
            .filter(v => v !== null && v !== undefined).map(v => String(v).toLowerCase()).join(' ');
          if (!hay.includes(needle)) return false;
        }
        return true;
      });

    return {
      total: rows.length,
      returned: Math.min(rows.length, limit),
      limit,
      criteria: { query: query || null, flowType: flowType || null, provider: provider || null, status: status || null, statusCode: statusCode ?? null, since: since || null, until: until || null },
      sessions: rows.slice(0, limit)
    };
  }

  static async get_session_detail(requests, { sessionId }) {
    const r = WebMcpTools.findSession(requests, sessionId);
    const index = WebMcpTools.buildFlowIndex(requests);
    const group = index.byId.get(r.id);
    const jwtCandidates = WebMcpTools.findJwtCandidates(r);

    let urlParams = {};
    try {
      urlParams = WebMcpTools.sanitizeParams(Object.fromEntries(new URL(r.url).searchParams.entries()));
    } catch { /* keep empty */ }

    return {
      session: WebMcpTools.summarizeSession(r, index),
      request: {
        method: r.method,
        url: Sanitize.redactUrl(r.url),
        urlParams,
        headers: Sanitize.redactHeaders(r.requestHeaders),
        body: WebMcpTools.bodyDetail(r.requestBody)
      },
      response: {
        status: r.status,
        statusCode: r.statusCode ?? null,
        error: r.error ?? null,
        headers: Sanitize.redactHeaders(r.responseHeaders)
      },
      oauth: WebMcpTools.sanitizeOAuth(r.oauthAnalysis),
      fido2: WebMcpTools.fido2Detail(r.fido2Analysis),
      verifiedId: r.didAnalysis ? WebMcpTools.truncateStrings(r.didAnalysis, WebMcpTools.MAX_TEXT) : null,
      saml: await WebMcpTools.samlDetail(r),
      jwt: jwtCandidates.map(c => WebMcpTools.jwtSummary(c)),
      warnings: await WebMcpTools.collectWarnings(r, index),
      related: group
        ? { flowId: group.key, flowType: group.type, stepIndex: group.requests.findIndex(x => x.id === r.id) + 1, stepCount: group.requests.length }
        : { flowId: r.id, flowType: 'standalone', stepIndex: 1, stepCount: 1 }
    };
  }

  static async get_security_warnings(requests, { severity } = {}) {
    const index = WebMcpTools.buildFlowIndex(requests);
    let all = [];
    for (const r of requests) {
      all.push(...await WebMcpTools.collectWarnings(r, index));
    }
    if (severity) all = all.filter(w => w.severity === severity);
    all.sort((a, b) => (SEVERITY_RANK[a.severity] ?? 3) - (SEVERITY_RANK[b.severity] ?? 3) || (b.timestampMs - a.timestampMs));
    const summary = { error: 0, warning: 0, info: 0 };
    for (const w of all) if (summary[w.severity] !== undefined) summary[w.severity]++;
    return { total: all.length, summary, warnings: all };
  }

  static async analyze_flow(requests, { flowId }) {
    const index = WebMcpTools.buildFlowIndex(requests);
    const group = index.groups.find(g => g.key === flowId) || index.byId.get(flowId);
    if (!group) throw new WebMcpToolError(ERROR_CODES.NOT_FOUND, `No flow or session with id ${flowId}`);

    const steps = [];
    const warnings = [];
    for (let i = 0; i < group.requests.length; i++) {
      const r = group.requests[i];
      const w = await WebMcpTools.collectWarnings(r, index);
      warnings.push(...w);
      steps.push({
        step: i + 1,
        sessionId: r.id,
        timestamp: WebMcpTools.iso(r.timestamp),
        timestampMs: r.timestamp ?? null,
        method: r.method,
        url: Sanitize.redactUrl(r.url),
        path: WebMcpTools.pathOf(r.url),
        flowType: r.flowType,
        flowLabel: WebMcpTools.flowLabel(r),
        status: r.status,
        statusCode: r.statusCode ?? null,
        description: FlowCorrelator.getFlowStepDesc(r, i) || null,
        warningCount: w.length
      });
    }

    const first = group.requests[0];
    const last = group.requests[group.requests.length - 1];
    const firstOAuth = group.requests.map(r => r.oauthAnalysis).find(a => a && !a.error);
    const user = WebMcpTools.deriveUserForRequests(group.requests);

    return {
      flowId: group.key,
      type: group.type,
      label: group.label || WebMcpTools.flowLabel(first),
      provider: WebMcpTools.providerOf(first),
      user: user.user,
      userSource: user.userSource,
      startedAt: WebMcpTools.iso(first.timestamp),
      endedAt: WebMcpTools.iso(last.timestamp),
      durationMs: (last.timestamp ?? 0) - (first.timestamp ?? 0),
      stepCount: steps.length,
      steps,
      warnings,
      summary: WebMcpTools.flowSummary(group, firstOAuth)
    };
  }

  static async get_token_claims(requests, { sessionId }) {
    const r = WebMcpTools.findSession(requests, sessionId);
    const tokens = WebMcpTools.findJwtCandidates(r).map(c => WebMcpTools.tokenDetail(c));
    return { sessionId: r.id, tokens, note: WebMcpTools.TOKEN_NOTE };
  }

  // ─── Session rows ────────────────────────────────────────────────────────

  static newestFirst(requests) {
    return [...requests].sort((a, b) => (b.timestamp ?? 0) - (a.timestamp ?? 0));
  }

  static findSession(requests, sessionId) {
    const r = requests.find(x => x.id === sessionId);
    if (!r) throw new WebMcpToolError(ERROR_CODES.NOT_FOUND, `No session with id ${sessionId}`);
    return r;
  }

  static matchesFlowType(r, flowType) {
    return r.flowType === flowType || FlowCorrelator.getFlowTypeCategory(r.flowType) === flowType;
  }

  /** Build the flow groups once and index requests by id. */
  static buildFlowIndex(requests) {
    const groups = FlowCorrelator.computeFlowGroups(requests);
    const byId = new Map();
    for (const g of groups) for (const r of g.requests) byId.set(r.id, g);
    return { groups, byId };
  }

  static summarizeSession(r, index) {
    const group = index && index.byId.get(r.id);
    const warnings = WebMcpTools.syncWarnings(r);
    const user = WebMcpTools.deriveUser(r);
    return {
      sessionId: r.id,
      flowId: group ? group.key : r.id,
      flowType: r.flowType ?? null,
      flowCategory: FlowCorrelator.getFlowTypeCategory(r.flowType),
      flowLabel: WebMcpTools.flowLabel(r),
      provider: WebMcpTools.providerOf(r),
      user: user.user,
      userSource: user.userSource,
      method: r.method ?? null,
      url: Sanitize.redactUrl(r.url),
      host: WebMcpTools.hostOf(r.url),
      path: WebMcpTools.pathOf(r.url),
      status: r.status ?? null,
      statusCode: r.statusCode ?? null,
      error: r.error ?? null,
      timestamp: WebMcpTools.iso(r.timestamp),
      timestampMs: r.timestamp ?? null,
      clientId: (r.oauthAnalysis && r.oauthAnalysis.clientId) || null,
      warningCount: warnings.length,
      maxSeverity: WebMcpTools.maxSeverity(warnings)
    };
  }

  static flowLabel(r) {
    if (r.oauthAnalysis && !r.oauthAnalysis.error && r.oauthAnalysis.label) return r.oauthAnalysis.label;
    if (r.didAnalysis && r.didAnalysis.operation) return r.didAnalysis.operation;
    if (FIDO2_LABELS[r.flowType]) return FIDO2_LABELS[r.flowType];
    return r.flowType || 'unknown';
  }

  static providerOf(r) {
    if (r.provider && r.provider.id) return r.provider;
    return ProviderDetector.detect(r.url);
  }

  /** Best-effort user identification for one request. */
  static deriveUser(r) {
    if (r.oauthAnalysis && r.oauthAnalysis.loginHint) return { user: r.oauthAnalysis.loginHint, userSource: 'login_hint' };
    const form = WebMcpTools.flatForm(r.requestBody);
    if (form.username) return { user: form.username, userSource: 'username' };
    if (form.login_hint) return { user: form.login_hint, userSource: 'login_hint' };
    for (const c of WebMcpTools.findJwtCandidates(r)) {
      try {
        const payload = EntraClaimsDecoder.parseJWT(c.jwt);
        for (const claim of USER_CLAIMS) {
          if (typeof payload[claim] === 'string' && payload[claim]) return { user: payload[claim], userSource: `${c.source}:${claim}` };
        }
      } catch { /* not a decodable JWT */ }
    }
    return { user: null, userSource: null };
  }

  static deriveUserForRequests(list) {
    for (const r of list) {
      const u = WebMcpTools.deriveUser(r);
      if (u.user) return u;
    }
    return { user: null, userSource: null };
  }

  // ─── JWTs ────────────────────────────────────────────────────────────────

  /** JWTs the client sent: form/URL parameters and the Authorization: Bearer header. */
  static findJwtCandidates(r) {
    const out = [];
    const seen = new Set();
    const add = (source, jwt) => {
      if (Sanitize.looksLikeJwt(jwt) && !seen.has(jwt)) { seen.add(jwt); out.push({ source, jwt }); }
    };
    const form = r.requestBody && r.requestBody.type === 'formData' ? (r.requestBody.data || {}) : {};
    for (const key of JWT_PARAMS) {
      const v = form[key];
      if (Array.isArray(v)) v.forEach(x => add(key, x)); else if (v) add(key, v);
    }
    try {
      const params = new URL(r.url).searchParams;
      for (const key of JWT_PARAMS) for (const v of params.getAll(key)) add(key, v);
    } catch { /* ignore */ }
    for (const h of r.requestHeaders || []) {
      if (h && String(h.name).toLowerCase() === 'authorization') {
        const m = /^Bearer\s+(\S+)$/i.exec(String(h.value || '').trim());
        if (m) add('authorization_bearer', m[1]);
      }
    }
    return out;
  }

  static decodeJwtHeader(jwt) {
    try {
      const header = JSON.parse(EntraClaimsDecoder.base64urlDecode(jwt.split('.')[0]));
      return {
        alg: header.alg ?? null,
        typ: header.typ ?? null,
        kid: header.kid ?? null,
        x5t: header.x5t ?? null,
        x5tS256: header['x5t#S256'] ?? null
      };
    } catch {
      return null;
    }
  }

  static jwtSummary(candidate) {
    const decoded = EntraClaimsDecoder.decodeEntraToken(candidate.jwt);
    if (decoded.error) return { source: candidate.source, error: decoded.error };
    return {
      source: candidate.source,
      isEntraToken: decoded.isEntraToken,
      caeEnabled: decoded.caeEnabled,
      summary: decoded.summary,
      claimCount: decoded.claims.length,
      warnings: decoded.warnings.map(w => WebMcpTools.normalizeWarning(w, 'jwt'))
    };
  }

  static tokenDetail(candidate) {
    const decoded = EntraClaimsDecoder.decodeEntraToken(candidate.jwt);
    if (decoded.error) return { source: candidate.source, error: decoded.error };
    let payload = {};
    try { payload = EntraClaimsDecoder.parseJWT(candidate.jwt); } catch { /* keep empty */ }
    const platf = payload.platf;
    return {
      source: candidate.source,
      header: WebMcpTools.decodeJwtHeader(candidate.jwt),
      isEntraToken: decoded.isEntraToken,
      caeEnabled: decoded.caeEnabled,
      popBinding: decoded.popBinding,
      summary: decoded.summary,
      claims: decoded.claims,
      amr: EntraClaimsDecoder.decodeAmrValues(payload.amr),
      devicePlatform: platf !== undefined && platf !== null
        ? { code: String(platf), name: EntraClaimsDecoder.PLATFORM_VALUES[String(platf)] || null }
        : null,
      warnings: decoded.warnings.map(w => WebMcpTools.normalizeWarning(w, 'jwt'))
    };
  }

  // ─── Warnings ────────────────────────────────────────────────────────────

  static normalizeWarning(w, source) {
    return {
      rule: WebMcpTools.ruleFor(w),
      severity: w.severity || 'info',
      message: w.message || '',
      source
    };
  }

  /** Stable rule id: the decoder's rule, a jwt_ prefixed type, or a slug of the message. */
  static ruleFor(w) {
    if (w.rule) return w.rule;
    if (w.type) return `jwt_${w.type}`;
    return String(w.message || 'unknown')
      .toLowerCase()
      .split(/[^a-z0-9]+/)
      .filter(Boolean)
      .slice(0, 6)
      .join('_') || 'unknown';
  }

  /** Warnings that do not need async decoding (OAuth, Verified ID, JWT). */
  static syncWarnings(r) {
    const out = [];
    const seen = new Set();
    const add = (list, source) => {
      for (const w of list || []) {
        const n = WebMcpTools.normalizeWarning(w, source);
        const key = `${n.source}:${n.rule}:${n.message}`;
        if (!seen.has(key)) { seen.add(key); out.push(n); }
      }
    };
    if (r.oauthAnalysis && !r.oauthAnalysis.error) add(r.oauthAnalysis.warnings, 'oauth');
    if (r.didAnalysis && !r.didAnalysis.error) add(r.didAnalysis.warnings, 'verified-id');
    for (const c of WebMcpTools.findJwtCandidates(r)) {
      const decoded = EntraClaimsDecoder.decodeEntraToken(c.jwt);
      if (!decoded.error) add(decoded.warnings, 'jwt');
    }
    return out;
  }

  /** All warnings for a request, including the SAML assessment, tagged with session context. */
  static async collectWarnings(r, index) {
    const out = WebMcpTools.syncWarnings(r);
    const saml = await WebMcpTools.samlDetail(r);
    if (saml && Array.isArray(saml.warnings)) {
      for (const w of saml.warnings) out.push(WebMcpTools.normalizeWarning(w, 'saml'));
    }
    const group = index && index.byId.get(r.id);
    const provider = WebMcpTools.providerOf(r);
    return out.map(w => ({
      sessionId: r.id,
      flowId: group ? group.key : r.id,
      ...w,
      url: Sanitize.redactUrl(r.url),
      provider: provider.id,
      timestamp: WebMcpTools.iso(r.timestamp),
      timestampMs: r.timestamp ?? null
    }));
  }

  static maxSeverity(warnings) {
    let best = null;
    for (const w of warnings) {
      if (best === null || (SEVERITY_RANK[w.severity] ?? 3) < (SEVERITY_RANK[best] ?? 3)) best = w.severity;
    }
    return best;
  }

  // ─── Detail helpers ──────────────────────────────────────────────────────

  static async samlDetail(r) {
    let extracted = null;
    try { extracted = SamlDecoder.extract(r); } catch { return null; }
    if (!extracted) return null;
    const d = await SamlDecoder.decodeSamlFromRequest(r);
    if (!d) return null;
    if (d.error) return { binding: d.binding, messageType: d.messageType, error: d.error };
    return {
      binding: d.binding,
      messageType: d.messageType,
      parser: (d.parsed && d.parsed.parser) || 'dom',
      xmlText: WebMcpTools.truncate(d.xmlText, WebMcpTools.MAX_XML),
      parsed: d.parsed,
      warnings: (d.warnings || []).map(w => WebMcpTools.normalizeWarning(w, 'saml'))
    };
  }

  static bodyDetail(body) {
    if (!body) return null;
    if (body.type === 'formData' && body.data) {
      const flat = {};
      for (const [k, v] of Object.entries(body.data)) flat[k] = Array.isArray(v) && v.length === 1 ? v[0] : v;
      return { type: 'formData', params: WebMcpTools.sanitizeParams(flat) };
    }
    if (body.type === 'json') {
      return { type: 'json', params: WebMcpTools.sanitizeParams(body.data) };
    }
    // Raw (unparsed) bodies follow the same policy as the popup and the exports:
    // parse as form data or JSON and redact field by field; text that cannot be
    // parsed is replaced by a placeholder rather than returned to the agent.
    const type = body.type || 'raw';
    const raw = body.data == null ? '' : String(body.data);
    const form = Sanitize.parseFormUrlEncoded(raw);
    if (form) {
      const params = {};
      for (const [k, v] of form) params[k] = k in params ? [].concat(params[k], v) : v;
      return { type, parsedAs: 'form', params: WebMcpTools.sanitizeParams(params) };
    }
    try {
      const json = JSON.parse(raw);
      if (json && typeof json === 'object') return { type, parsedAs: 'json', params: WebMcpTools.sanitizeParams(json) };
    } catch { /* not JSON */ }
    return { type, parsedAs: null, raw: Sanitize.redactRawText(raw).data };
  }

  static sanitizeOAuth(analysis) {
    if (!analysis) return null;
    const copy = { ...analysis };
    if ('deviceCode' in copy) delete copy.deviceCode; // keep deviceCodePrefix only
    return WebMcpTools.truncateStrings(copy, WebMcpTools.MAX_TEXT);
  }

  static fido2Detail(f) {
    if (!f) return null;
    const copy = { ...f };
    if (copy.clientDataJSON) {
      copy.clientDataJSON = { ...copy.clientDataJSON };
      delete copy.clientDataJSON.raw;
    }
    return copy;
  }

  static flowSummary(group, firstOAuth) {
    const reqs = group.requests;
    const analyses = reqs.map(r => r.oauthAnalysis).filter(a => a && !a.error);
    const tokenAnalyses = analyses.filter(a => a.requestType === 'token_request' || a.requestType === 'device_code_poll');
    const pkceAnalysis = analyses.find(a => a.pkce) || null;
    const verifierAnalysis = analyses.find(a => a.pkceVerifier && !a.pkceVerifier.error) || null;
    const authAnalysis = tokenAnalyses.find(a => a.authMethod) || analyses.find(a => a.authMethod) || null;
    const scopes = [...new Set(analyses.flatMap(a => a.scopes || []))];

    const summary = {
      grantType: firstOAuth ? firstOAuth.grantType ?? null : null,
      grantLabel: firstOAuth ? firstOAuth.label ?? null : null,
      pkce: pkceAnalysis
        ? { present: true, method: pkceAnalysis.pkce.codeChallengeMethod, compliant: !!pkceAnalysis.pkce.isS256 }
        : verifierAnalysis
          ? { present: true, method: null, compliant: !!verifierAnalysis.pkceVerifier.isCompliant }
          : (analyses.length ? { present: false, method: null, compliant: false } : null),
      clientAuthMethod: authAnalysis ? authAnalysis.authMethod : null,
      clientAuthLabel: authAnalysis ? authAnalysis.authMethodLabel || null : null,
      scopes,
      scopeLabels: [...new Map(analyses.flatMap(a => a.scopeLabels || []).map(s => [s.scope, s])).values()],
      deviceCode: null,
      verifiedId: null,
      outcome: WebMcpTools.outcomeOf(reqs)
    };

    if (group.type === 'device_code') {
      const polls = reqs.filter(r => r.flowType === 'device_code_poll');
      summary.deviceCode = {
        initiations: reqs.filter(r => r.flowType === 'device_code_initiation').length,
        polls: polls.length,
        completedPolls: polls.filter(r => r.status === 'completed' && r.statusCode && r.statusCode < 400).length
      };
    }

    if (group.type === 'did') {
      const dids = reqs.map(r => r.didAnalysis).filter(d => d && !d.error);
      summary.verifiedId = {
        operations: dids.map(d => d.operation),
        credentialType: dids.map(d => d.credentialType).find(Boolean) || null,
        authority: dids.map(d => d.authority).find(Boolean) || null,
        requestId: dids.map(d => d.requestId).find(Boolean) || null,
        requestStatus: dids.map(d => d.requestStatus).find(Boolean) || null
      };
    }

    return summary;
  }

  static outcomeOf(reqs) {
    const statuses = new Set(reqs.map(r => r.status));
    if (statuses.has('error')) return 'error';
    if (statuses.size === 1 && statuses.has('completed')) return 'completed';
    if (statuses.has('pending')) return 'pending';
    return 'mixed';
  }

  // ─── Sanitisation / formatting ───────────────────────────────────────────

  /**
   * Redact like Sanitize.redactObject, additionally hiding authorization codes.
   */
  static sanitizeParams(value, key = '') {
    const k = String(key || '').toLowerCase();
    if (EXTRA_SECRET_KEYS.includes(k)) return Sanitize.REDACTED;
    const kind = Sanitize.classifyKey(key);
    if (kind === 'secret') return Sanitize.REDACTED;
    if (kind === 'truncate') return Sanitize.truncateJwt(value == null ? '' : String(value));
    if (Array.isArray(value)) return value.map(v => WebMcpTools.sanitizeParams(v, key));
    if (value && typeof value === 'object') {
      const out = {};
      for (const [ck, cv] of Object.entries(value)) out[ck] = WebMcpTools.sanitizeParams(cv, ck);
      return out;
    }
    if (typeof value === 'string') return WebMcpTools.truncate(value, WebMcpTools.MAX_TEXT);
    return value;
  }

  static truncate(str, max) {
    const s = String(str == null ? '' : str);
    return s.length > max ? `${s.substring(0, max)}…[truncated, ${s.length} chars]` : s;
  }

  /** Deep copy with every string capped at `max` characters. */
  static truncateStrings(value, max) {
    if (typeof value === 'string') return WebMcpTools.truncate(value, max);
    if (Array.isArray(value)) return value.map(v => WebMcpTools.truncateStrings(v, max));
    if (value && typeof value === 'object') {
      const out = {};
      for (const [k, v] of Object.entries(value)) out[k] = WebMcpTools.truncateStrings(v, max);
      return out;
    }
    return value;
  }

  static iso(ts) {
    if (ts === null || ts === undefined) return null;
    const d = new Date(ts);
    return isNaN(d.getTime()) ? null : d.toISOString();
  }

  static hostOf(url) { try { return new URL(url).hostname; } catch { return null; } }
  static pathOf(url) { try { return new URL(url).pathname; } catch { return url ?? null; } }

  static flatForm(body) {
    if (!body || body.type !== 'formData' || !body.data) return {};
    const out = {};
    for (const [k, v] of Object.entries(body.data)) out[k] = Array.isArray(v) ? v[0] : v;
    return out;
  }

  /** ISO-8601 string or epoch milliseconds (number or numeric string) → ms, else null. */
  static parseTime(v) {
    if (v === undefined || v === null || v === '') return null;
    if (typeof v === 'number') return Number.isFinite(v) ? v : null;
    const s = String(v).trim();
    if (/^\d{10,}$/.test(s)) return Number(s);
    const t = Date.parse(s);
    return isNaN(t) ? null : t;
  }

  /**
   * Keep results under MAX_RESULT_BYTES: first drop bulky raw fields, then halve
   * the main arrays. Sets `truncated: true` when anything was removed.
   */
  static enforceSizeBudget(result) {
    const size = () => JSON.stringify(result).length;
    if (size() <= WebMcpTools.MAX_RESULT_BYTES) return result;
    result.truncated = true;

    const stripBulky = (value) => {
      if (Array.isArray(value)) { value.forEach(stripBulky); return; }
      if (!value || typeof value !== 'object') return;
      for (const key of Object.keys(value)) {
        if (['raw', 'xmlText', 'hex', 'decoded'].includes(key) && typeof value[key] === 'string' && value[key].length > 256) {
          value[key] = WebMcpTools.truncate(value[key], 256);
        } else {
          stripBulky(value[key]);
        }
      }
    };
    stripBulky(result);
    if (size() <= WebMcpTools.MAX_RESULT_BYTES) return result;

    let guard = 0;
    while (size() > WebMcpTools.MAX_RESULT_BYTES && guard++ < 12) {
      let shrunk = false;
      for (const key of ['sessions', 'warnings', 'steps', 'tokens', 'jwt']) {
        if (Array.isArray(result[key]) && result[key].length > 1) {
          result[key] = result[key].slice(0, Math.ceil(result[key].length / 2));
          shrunk = true;
        }
      }
      if (result.sessions) result.returned = result.sessions.length;
      if (!shrunk) break;
    }
    return result;
  }
}

export default WebMcpTools;
