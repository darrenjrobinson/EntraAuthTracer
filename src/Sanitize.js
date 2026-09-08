/**
 * Entra Auth Tracer - Sanitisation helpers
 *
 * HTML escaping, credential redaction and JWT extraction shared by the popup
 * renderers and the exporters. Pure functions — no DOM, no chrome.* access.
 *
 * Redaction policy (documented in PRIVACY.md):
 *  - secrets and bearer credentials are always replaced with [REDACTED]:
 *      client_secret*, *password*, *refresh_token*, and the exact parameters
 *      assertion, access_token, id_token, plus Authorization / Cookie headers
 *  - live JWT credentials that the UI decodes elsewhere (client_assertion,
 *      id_token_hint) are truncated rather than hidden
 *  - single-use / non-secret debugging values (code, code_verifier,
 *      device_code, state, nonce) stay visible
 */

class Sanitize {
  static REDACTED = '[REDACTED]';

  /** Exact parameter names whose value is a JWT the UI decodes — truncate, don't hide. */
  static TRUNCATE_KEYS = ['client_assertion', 'id_token_hint'];

  /** Exact parameter names that carry a credential. */
  static EXACT_SECRET_KEYS = ['assertion', 'access_token', 'id_token'];

  /** Substrings that mark a parameter as a credential wherever they appear. */
  static SUBSTRING_SECRET_KEYS = ['client_secret', 'password', 'refresh_token'];

  /** Header names (lower-case) whose value is redacted. */
  static SENSITIVE_HEADERS = ['authorization', 'proxy-authorization', 'cookie', 'set-cookie'];

  /** Display cap for ordinary values. */
  static MAX_VALUE_LENGTH = 200;

  /** Characters shown from a truncated JWT. */
  static JWT_PREVIEW_LENGTH = 12;

  // ─── HTML ────────────────────────────────────────────────────────────────

  /**
   * Escape a value for safe insertion into HTML.
   */
  static escapeHtml(text) {
    if (text == null) return '';
    return String(text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // ─── Classification ──────────────────────────────────────────────────────

  /**
   * Classify a parameter/field name: 'truncate' | 'secret' | 'plain'.
   */
  static classifyKey(key) {
    // Normalise header-style names (x-client-secret) to parameter style (x_client_secret)
    const k = String(key == null ? '' : key).toLowerCase().replace(/-/g, '_');
    if (Sanitize.TRUNCATE_KEYS.includes(k)) return 'truncate';
    if (Sanitize.EXACT_SECRET_KEYS.includes(k)) return 'secret';
    if (Sanitize.SUBSTRING_SECRET_KEYS.some(s => k.includes(s))) return 'secret';
    return 'plain';
  }

  /**
   * True when a string has the three-segment base64url shape of a compact JWT.
   */
  static looksLikeJwt(value) {
    return typeof value === 'string' && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(value);
  }

  /**
   * Truncated preview of a JWT (or any long credential-like string).
   */
  static truncateJwt(value) {
    const str = String(value);
    if (str.length <= Sanitize.JWT_PREVIEW_LENGTH) return str;
    return `${str.substring(0, Sanitize.JWT_PREVIEW_LENGTH)}…[truncated JWT, ${str.length} chars]`;
  }

  // ─── Values ──────────────────────────────────────────────────────────────

  /**
   * Redact a single parameter value for display: secrets → [REDACTED],
   * decodable JWT credentials → truncated preview, everything else capped at
   * MAX_VALUE_LENGTH characters.
   */
  static redactSensitiveValues(key, value) {
    const str = value == null ? '' : String(value);
    switch (Sanitize.classifyKey(key)) {
      case 'secret':
        return Sanitize.REDACTED;
      case 'truncate':
        return Sanitize.truncateJwt(str);
      default:
        return str.length > Sanitize.MAX_VALUE_LENGTH
          ? str.substring(0, Sanitize.MAX_VALUE_LENGTH) + '...'
          : str;
    }
  }

  /**
   * Deep-copy an object, redacting secret keys and truncating JWT credentials.
   * Plain values are kept intact (no display truncation) so structured data
   * such as FIDO2 payloads survives round-tripping.
   */
  static redactObject(value, key = '') {
    const kind = Sanitize.classifyKey(key);
    if (kind === 'secret') return Sanitize.REDACTED;
    if (kind === 'truncate') return Sanitize.truncateJwt(value == null ? '' : String(value));
    if (Array.isArray(value)) return value.map(v => Sanitize.redactObject(v, key));
    if (value && typeof value === 'object') {
      const out = {};
      for (const [k, v] of Object.entries(value)) out[k] = Sanitize.redactObject(v, k);
      return out;
    }
    return value;
  }

  // ─── Request parts ───────────────────────────────────────────────────────

  /**
   * Redacted copy of a webRequest headers array. Authorization-style headers
   * keep their scheme (`Basic [REDACTED]`); cookies are hidden entirely.
   */
  static redactHeaders(headers) {
    if (!Array.isArray(headers)) return [];
    return headers.map(h => {
      const name = String(h && h.name != null ? h.name : '');
      const lower = name.toLowerCase();
      if (!Sanitize.SENSITIVE_HEADERS.includes(lower)) return { ...h };
      if (lower === 'authorization' || lower === 'proxy-authorization') {
        const scheme = String(h.value || '').trim().split(/\s+/)[0];
        return { ...h, value: scheme ? `${scheme} ${Sanitize.REDACTED}` : Sanitize.REDACTED };
      }
      return { ...h, value: Sanitize.REDACTED };
    });
  }

  /**
   * Redacted copy of a captured requestBody ({ type: 'formData'|'json'|'raw', data }).
   * The raw JSON text of json bodies is dropped because it cannot be redacted.
   */
  static redactBody(requestBody) {
    if (!requestBody || typeof requestBody !== 'object') return requestBody;
    if (requestBody.type === 'formData' && requestBody.data) {
      const data = {};
      for (const [k, values] of Object.entries(requestBody.data)) {
        data[k] = Array.isArray(values)
          ? values.map(v => Sanitize.redactObject(v, k))
          : Sanitize.redactObject(values, k);
      }
      return { ...requestBody, data };
    }
    if (requestBody.type === 'json' && requestBody.data && typeof requestBody.data === 'object') {
      const copy = { ...requestBody, data: Sanitize.redactObject(requestBody.data) };
      delete copy.raw;
      return copy;
    }
    if (requestBody.type === 'raw' || typeof requestBody.data === 'string') {
      // Arbitrary text cannot be field-redacted: parse it into a structured body
      // first (form-urlencoded or JSON) or replace it entirely.
      return { ...requestBody, type: requestBody.type || 'raw', ...Sanitize.redactRawText(requestBody.data) };
    }
    return { ...requestBody };
  }

  /**
   * Redact a raw request body string.
   * @returns {{ data: string, parsedAs: 'form'|'json'|null, redacted?: true }}
   */
  static redactRawText(text) {
    const str = text == null ? '' : String(text);
    const form = Sanitize.parseFormUrlEncoded(str);
    if (form) {
      const params = new URLSearchParams();
      for (const [k, v] of form) params.append(k, String(Sanitize.redactObject(v, k)));
      return { data: params.toString(), parsedAs: 'form' };
    }
    try {
      const json = JSON.parse(str);
      if (json && typeof json === 'object') {
        return { data: JSON.stringify(Sanitize.redactObject(json)), parsedAs: 'json' };
      }
    } catch { /* not JSON */ }
    return {
      data: `[REDACTED raw body — ${str.length} chars could not be parsed as form data or JSON]`,
      parsedAs: null,
      redacted: true
    };
  }

  /**
   * Parse an application/x-www-form-urlencoded string into [key, value] pairs,
   * or return null when the text does not have that shape.
   */
  static parseFormUrlEncoded(str) {
    if (!str || !str.includes('=') || /[<>{}\s]/.test(str)) return null;
    if (!str.split('&').every(pair => /^[^=&]+=[^&]*$/.test(pair))) return null;
    return Array.from(new URLSearchParams(str).entries());
  }

  /**
   * Redact secret query parameters in a URL string. Non-URL input is returned unchanged.
   */
  static redactUrl(urlString) {
    let url;
    try {
      url = new URL(urlString);
    } catch {
      return urlString;
    }
    let changed = false;
    for (const key of Array.from(url.searchParams.keys())) {
      const kind = Sanitize.classifyKey(key);
      if (kind === 'plain') continue;
      const values = url.searchParams.getAll(key);
      url.searchParams.delete(key);
      for (const v of values) {
        url.searchParams.append(key, kind === 'secret' ? Sanitize.REDACTED : Sanitize.truncateJwt(v));
      }
      changed = true;
    }
    return changed ? url.toString() : urlString;
  }

  // ─── JWT extraction ──────────────────────────────────────────────────────

  /**
   * Extract a JWT string from a known request parameter (form body first, then URL).
   */
  static extractJwtFromRequest(request, paramName = 'client_assertion') {
    if (!request) return null;
    // Check request body (form data)
    if (request.requestBody && request.requestBody.type === 'formData' && request.requestBody.data) {
      const vals = request.requestBody.data[paramName];
      if (vals) return Array.isArray(vals) ? vals[0] : vals;
    }
    // Check URL params
    try {
      const url = new URL(request.url);
      const val = url.searchParams.get(paramName);
      if (val) return val;
    } catch { /* ignore */ }
    return null;
  }
}

export default Sanitize;
