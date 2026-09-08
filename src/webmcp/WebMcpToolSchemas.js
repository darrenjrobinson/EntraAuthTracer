/**
 * Entra Auth Tracer - WebMCP tool definitions
 *
 * Names, descriptions, JSON Schemas and annotations for the six read-only tools,
 * plus argument validation. Descriptions are "baked" with live context
 * (session count, armed origin) at registration time, per the WebMCP draft.
 * Pure module — no chrome.* or DOM access.
 */

const TOOL_NAME_RE = /^[A-Za-z0-9_.-]{1,128}$/;

const READ_ONLY_ANNOTATIONS = Object.freeze({
  readOnlyHint: true,
  untrustedContentHint: true,  // the data is captured network traffic
  consequentialHint: false
});

const SEVERITIES = ['error', 'warning', 'info'];
const STATUSES = ['completed', 'error', 'pending'];

const CONTEXT_NOTE =
  'Data is read-only, local to this browser, and reflects only requests SENT by the browser; ' +
  'identity-provider responses (issued tokens) are not visible. Client secrets, passwords, ' +
  'refresh tokens and authorization codes are redacted.';

class WebMcpToolSchemas {
  static TOOL_NAMES = [
    'list_auth_sessions',
    'get_session_detail',
    'get_security_warnings',
    'analyze_flow',
    'get_token_claims',
    'search_sessions'
  ];

  static TOOLS = {
    list_auth_sessions: {
      name: 'list_auth_sessions',
      title: 'List captured authentication sessions',
      baseDescription:
        'List authentication requests captured by Entra Auth Tracer, newest first: flow type and label, ' +
        'identity provider, user (when visible), HTTP method/status, timestamp, correlation flowId and warning counts. ' +
        'Use flowType to restrict to a category (oauth, saml, fido2, device_code, did, other) or an exact flow type.',
      inputSchema: {
        type: 'object',
        properties: {
          limit: { type: 'integer', minimum: 1, maximum: 100, default: 20, description: 'Maximum sessions to return (default 20, max 100).' },
          flowType: { type: 'string', description: 'Category (oauth, saml, fido2, device_code, did, other) or exact flow type such as pkce_flow.' }
        },
        additionalProperties: false
      }
    },
    get_session_detail: {
      name: 'get_session_detail',
      title: 'Get the full decode of one session',
      baseDescription:
        'Return everything decoded for one captured request: sanitised URL parameters, headers and body, response status, ' +
        'OAuth 2.1 analysis (grant, PKCE, client authentication, scopes), FIDO2/WebAuthn data (flags incl. BE/BS, AAGUID and ' +
        'authenticator, sign count, COSE key), Verified ID analysis, SAML message and assessment, JWT summaries, warnings and ' +
        'the flow the session belongs to.',
      inputSchema: {
        type: 'object',
        properties: {
          sessionId: { type: 'string', description: 'The sessionId from list_auth_sessions / search_sessions.' }
        },
        required: ['sessionId'],
        additionalProperties: false
      }
    },
    get_security_warnings: {
      name: 'get_security_warnings',
      title: 'Get security warnings across all sessions',
      baseDescription:
        'Aggregate every security finding across captured traffic (OAuth 2.1 compliance, redirect URIs, client authentication, ' +
        'SAML signatures/validity, Verified ID callbacks, JWT expiry/CAE/public-client), each with a stable rule id, severity, ' +
        'message, the affected sessionId and flowId. Sorted error > warning > info, newest first.',
      inputSchema: {
        type: 'object',
        properties: {
          severity: { type: 'string', enum: SEVERITIES, description: 'Only return findings of this severity.' }
        },
        additionalProperties: false
      }
    },
    analyze_flow: {
      name: 'analyze_flow',
      title: 'Analyse a correlated authentication flow',
      baseDescription:
        'Return the ordered timeline of a correlated flow (device code initiation and polls, authorization code + PKCE ' +
        'authorize/token exchange, OIDC lifecycle, Verified ID issuance/presentation): each step with timing, status and ' +
        'description, aggregated warnings and a summary (grant type, PKCE, client authentication, scopes, poll counts, outcome). ' +
        'flowId comes from list_auth_sessions; a sessionId is also accepted.',
      inputSchema: {
        type: 'object',
        properties: {
          flowId: { type: 'string', description: 'The flowId (or a sessionId) from list_auth_sessions / search_sessions.' }
        },
        required: ['flowId'],
        additionalProperties: false
      }
    },
    get_token_claims: {
      name: 'get_token_claims',
      title: 'Decode JWT claims found in a session',
      baseDescription:
        'Decode every JWT sent by the client in one captured request (client_assertion, id_token_hint, assertion, request, ' +
        'Authorization: Bearer): header (alg, kid, x5t), Entra claim set with labels, AMR methods, device platform, CAE and ' +
        'PoP status, expiry and warnings. Tokens ISSUED by the identity provider travel in responses and are not visible.',
      inputSchema: {
        type: 'object',
        properties: {
          sessionId: { type: 'string', description: 'The sessionId from list_auth_sessions / search_sessions.' }
        },
        required: ['sessionId'],
        additionalProperties: false
      }
    },
    search_sessions: {
      name: 'search_sessions',
      title: 'Search captured sessions',
      baseDescription:
        'Filter captured sessions by free-text query (URL, flow label, provider, client id, user, status code), flow type or ' +
        'category, provider id or name (entra, okta, google, cognito, adfs, shibboleth, identityserver, entra-verified-id ...), ' +
        'status, HTTP status code and time range. Returns the same rows as list_auth_sessions.',
      inputSchema: {
        type: 'object',
        properties: {
          query: { type: 'string', description: 'Case-insensitive substring matched against URL, flow label, provider, client id, user and status code.' },
          flowType: { type: 'string', description: 'Category (oauth, saml, fido2, device_code, did, other) or exact flow type.' },
          provider: { type: 'string', description: 'Provider id (e.g. entra, okta) or a substring of the provider name.' },
          status: { type: 'string', enum: STATUSES, description: 'Request status.' },
          statusCode: { type: 'integer', description: 'Exact HTTP status code.' },
          since: { type: 'string', description: 'Only sessions at or after this time (ISO-8601 or epoch milliseconds).' },
          until: { type: 'string', description: 'Only sessions at or before this time (ISO-8601 or epoch milliseconds).' },
          limit: { type: 'integer', minimum: 1, maximum: 100, default: 20, description: 'Maximum sessions to return (default 20, max 100).' }
        },
        additionalProperties: false
      }
    }
  };

  /** Validate a tool name against the WebMCP grammar. */
  static isValidToolName(name) {
    return typeof name === 'string' && TOOL_NAME_RE.test(name);
  }

  /**
   * Bake live context into a tool description.
   * @param {string} name
   * @param {{ sessionCount?: number, origin?: string }} ctx
   */
  static describe(name, ctx = {}) {
    const tool = WebMcpToolSchemas.TOOLS[name];
    if (!tool) throw new Error(`Unknown tool: ${name}`);
    const count = Number.isFinite(ctx.sessionCount) ? ctx.sessionCount : 0;
    const origin = ctx.origin || 'this tab';
    return `${tool.baseDescription}\n\nContext: ${count} auth session${count === 1 ? '' : 's'} captured — WebMCP mode active on ${origin}. ${CONTEXT_NOTE}`;
  }

  /**
   * The registration manifest the page runtime registers with document.modelContext.
   * Plain, structured-clone-safe objects only (no functions).
   */
  static buildManifest(ctx = {}) {
    return WebMcpToolSchemas.TOOL_NAMES.map(name => {
      const tool = WebMcpToolSchemas.TOOLS[name];
      return {
        name: tool.name,
        title: tool.title,
        description: WebMcpToolSchemas.describe(name, ctx),
        inputSchema: JSON.parse(JSON.stringify(tool.inputSchema)),
        annotations: { ...READ_ONLY_ANNOTATIONS }
      };
    });
  }

  /**
   * Validate and normalise tool arguments against the tool's schema.
   * Integers are coerced from numeric strings and clamped to their bounds;
   * strings are trimmed; enums are enforced; unknown properties are dropped.
   * @returns {{ ok: true, value: object } | { ok: false, error: string }}
   */
  static validateArgs(name, args) {
    const tool = WebMcpToolSchemas.TOOLS[name];
    if (!tool) return { ok: false, error: `Unknown tool: ${name}` };
    if (args == null) args = {};
    if (typeof args !== 'object' || Array.isArray(args)) {
      return { ok: false, error: 'Arguments must be an object' };
    }

    const schema = tool.inputSchema;
    const value = {};
    for (const [key, prop] of Object.entries(schema.properties)) {
      let v = args[key];
      if (v === undefined || v === null || v === '') {
        if (prop.default !== undefined) value[key] = prop.default;
        continue;
      }
      if (prop.type === 'integer') {
        const n = typeof v === 'string' ? Number(v.trim()) : v;
        if (typeof n !== 'number' || !Number.isFinite(n) || Math.floor(n) !== n) {
          return { ok: false, error: `${key} must be an integer` };
        }
        let clamped = n;
        if (prop.minimum !== undefined) clamped = Math.max(prop.minimum, clamped);
        if (prop.maximum !== undefined) clamped = Math.min(prop.maximum, clamped);
        value[key] = clamped;
      } else if (prop.type === 'string') {
        if (typeof v !== 'string') return { ok: false, error: `${key} must be a string` };
        v = v.trim();
        if (prop.enum && !prop.enum.includes(v)) {
          return { ok: false, error: `${key} must be one of: ${prop.enum.join(', ')}` };
        }
        value[key] = v;
      } else {
        value[key] = v;
      }
    }
    for (const req of schema.required || []) {
      if (value[req] === undefined) return { ok: false, error: `${req} is required` };
    }
    return { ok: true, value };
  }
}

export default WebMcpToolSchemas;
