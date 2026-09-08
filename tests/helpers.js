/**
 * Shared test helpers for Entra Auth Tracer.
 *
 * Builders for the shapes the extension works with (webRequest details,
 * captured request records, extension state) plus encoders for the binary
 * formats the decoders consume (JWT, COSE keys, WebAuthn authenticator data,
 * attestation objects). Keeping these in one place avoids the copy-pasted
 * base64url incantations and incompatible helper signatures the suites used
 * to carry.
 */

import * as CBOR from 'cbor-web';

let seq = 0;

// ─── Extension state / webRequest details ───────────────────────────────────

/** Build a minimal extensionState object for test isolation. */
export function makeState(overrides = {}) {
  return {
    requests: [],
    deviceCodeCorrelation: new Map(),
    fido2Sessions: [],
    isActive: true,
    badgeCount: 0,
    onNewAuthRequest: jest.fn(),
    ...overrides
  };
}

/** Build a minimal chrome.webRequest details object (with a stable requestId). */
export function makeDetails(url, method = 'GET', extras = {}) {
  return {
    requestId: String(++seq),
    url,
    method,
    tabId: 1,
    type: 'xmlhttprequest',
    timeStamp: Date.now(),
    requestHeaders: [],
    responseHeaders: [],
    requestBody: null,
    ...extras
  };
}

/** Convert a plain object into Chrome's webRequest formData shape (array values). */
export function toChromeFormData(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj)) out[k] = Array.isArray(v) ? v : [v];
  return out;
}

/**
 * Build a captured request record as stored in extensionState.requests.
 *
 * @param {string} url
 * @param {object} [opts]  method, flowType, formData (plain object), json, raw,
 *                         requestBody (verbatim), timestamp, id, status, statusCode,
 *                         plus any extra fields (oauthAnalysis, didAnalysis, ...).
 */
export function makeRequest(url, opts = {}) {
  const {
    method, flowType, formData, json, raw, requestBody,
    timestamp, id, status, statusCode, ...rest
  } = opts;
  const hasBody = !!(formData || json || raw || requestBody);
  const req = {
    id: id || `req_${Date.now()}_${(++seq).toString(36).padStart(9, '0')}`,
    timestamp: timestamp ?? Date.now(),
    url,
    method: method || (hasBody ? 'POST' : 'GET'),
    flowType: flowType ?? 'unknown',
    status: status || 'completed',
    requestHeaders: [],
    responseHeaders: [],
    requestBody: null,
    ...rest
  };
  if (statusCode !== undefined) req.statusCode = statusCode;
  if (requestBody) req.requestBody = requestBody;
  else if (formData) req.requestBody = { type: 'formData', data: toChromeFormData(formData) };
  else if (json) req.requestBody = { type: 'json', data: json };
  else if (raw) req.requestBody = { type: 'raw', data: raw };
  return req;
}

// ─── Encoding helpers ───────────────────────────────────────────────────────

/** Normalise string | Uint8Array | ArrayBuffer to a Buffer. */
function toBuffer(input) {
  if (typeof input === 'string') return Buffer.from(input, 'utf8');
  if (input instanceof ArrayBuffer) return Buffer.from(new Uint8Array(input));
  return Buffer.from(input);
}

/** base64url-encode text (UTF-8) or bytes. */
export function b64url(input) {
  return toBuffer(input).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Standard base64 of a UTF-8 string (POST-binding SAML style). */
export function utf8ToB64(str) {
  return Buffer.from(str, 'utf8').toString('base64');
}

/** Build an unsigned-but-well-formed compact JWT. */
export function buildJwt(payload, header = { alg: 'RS256', typ: 'JWT' }, signature = 'sig') {
  return `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}.${signature}`;
}

/** Bytes filled with a constant. */
export function bytes(length, fill = 0) {
  return new Uint8Array(length).fill(fill);
}

/** UUID string → 16 bytes. */
export function uuidToBytes(uuid) {
  const hex = uuid.replace(/-/g, '');
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// ─── COSE / WebAuthn builders ───────────────────────────────────────────────

/** COSE_Key for an EC2 P-256 / ES256 key, as cbor-web decodes it (integer-keyed Map). */
export function coseEc2P256Key({ x, y } = {}) {
  return new Map([
    [1, 2],                 // kty: EC2
    [3, -7],                // alg: ES256
    [-1, 1],                // crv: P-256
    [-2, x || bytes(32, 0x11)],
    [-3, y || bytes(32, 0x22)]
  ]);
}

/** COSE_Key for an RSA / RS256 key. */
export function coseRsaKey({ n, e } = {}) {
  return new Map([
    [1, 3],                 // kty: RSA
    [3, -257],              // alg: RS256
    [-1, n || bytes(256, 0x33)],
    [-2, e || new Uint8Array([0x01, 0x00, 0x01])]
  ]);
}

/** CBOR-encode any value to a Uint8Array. */
export function cborEncode(value) {
  return new Uint8Array(CBOR.encode(value));
}

const FLAG_BITS = { UP: 0x01, RFU1: 0x02, UV: 0x04, BE: 0x08, BS: 0x10, RFU4: 0x20, AT: 0x40, ED: 0x80 };

/** Compose an authenticator flags byte from a number or an object of booleans. */
export function flagsByte(flags) {
  if (typeof flags === 'number') return flags;
  let b = 0;
  for (const [name, bit] of Object.entries(FLAG_BITS)) if (flags[name]) b |= bit;
  return b;
}

/**
 * Build WebAuthn authenticatorData bytes.
 *
 * @param {object} [opts]
 *   rpIdHash   32 bytes (default 0xab-filled)
 *   flags      number | { UP, UV, BE, BS, AT, ED } — AT/ED are inferred when
 *              coseKey / extensions are supplied and the flag is not explicitly set
 *   signCount  uint32 (default 0)
 *   aaguid     UUID string (default all-zero)
 *   credId     Uint8Array (default 16 × 0x01)
 *   coseKey    Map (default coseEc2P256Key())
 *   extensions plain object (default { credProtect: 2 } when ED is set)
 * @returns {{ bytes: Uint8Array, b64url: string }}
 */
export function buildAuthenticatorData(opts = {}) {
  const flagsIn = opts.flags ?? { UP: true };
  const flagsObj = typeof flagsIn === 'number'
    ? Object.fromEntries(Object.entries(FLAG_BITS).map(([n, bit]) => [n, !!(flagsIn & bit)]))
    : { ...flagsIn };
  if (flagsObj.AT === undefined && opts.coseKey) flagsObj.AT = true;
  if (flagsObj.ED === undefined && opts.extensions) flagsObj.ED = true;

  const parts = [];
  parts.push(opts.rpIdHash || bytes(32, 0xab));
  parts.push(new Uint8Array([flagsByte(flagsObj)]));
  const sc = new Uint8Array(4);
  new DataView(sc.buffer).setUint32(0, opts.signCount ?? 0, false);
  parts.push(sc);

  if (flagsObj.AT) {
    const credId = opts.credId || bytes(16, 0x01);
    const len = new Uint8Array(2);
    new DataView(len.buffer).setUint16(0, credId.length, false);
    parts.push(uuidToBytes(opts.aaguid || '00000000-0000-0000-0000-000000000000'));
    parts.push(len);
    parts.push(credId);
    parts.push(cborEncode(opts.coseKey || coseEc2P256Key()));
  }
  if (flagsObj.ED) {
    parts.push(cborEncode(opts.extensions || { credProtect: 2 }));
  }

  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return { bytes: out, b64url: b64url(out) };
}

/**
 * Build a WebAuthn attestationObject (CBOR { fmt, attStmt, authData }).
 * @returns {{ bytes: Uint8Array, b64url: string }}
 */
export function buildAttestationObject({ fmt = 'packed', attStmt, authDataBytes } = {}) {
  const authData = authDataBytes || buildAuthenticatorData({ flags: { UP: true, UV: true, AT: true } }).bytes;
  const stmt = attStmt || { alg: -7, sig: bytes(64, 0x5a) };
  const out = cborEncode({ fmt, attStmt: stmt, authData });
  return { bytes: out, b64url: b64url(out) };
}

// ─── Chrome mock helpers ────────────────────────────────────────────────────

/** Return the most recently registered listener for each chrome.webRequest event. */
export function captureWebRequestListeners() {
  const pick = (ev) => {
    const calls = chrome.webRequest[ev].addListener.mock.calls;
    return calls.length ? calls[calls.length - 1][0] : null;
  };
  return {
    onBeforeRequest: pick('onBeforeRequest'),
    onBeforeSendHeaders: pick('onBeforeSendHeaders'),
    onHeadersReceived: pick('onHeadersReceived'),
    onCompleted: pick('onCompleted'),
    onErrorOccurred: pick('onErrorOccurred')
  };
}
