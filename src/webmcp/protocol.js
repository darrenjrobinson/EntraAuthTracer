/**
 * Entra Auth Tracer - WebMCP protocol constants
 *
 * Shared by the MAIN-world page runtime, the isolated-world bridge, the
 * background controller and the popup. No chrome.* or DOM access so it can be
 * bundled into every context.
 */

/** `source` tag on every window.postMessage envelope exchanged by page and bridge. */
export const MSG_SOURCE = 'entra-auth-tracer-webmcp';

/** Envelope protocol version. */
export const PROTOCOL_VERSION = 1;

/** MAIN-world idempotency handle (window property). */
export const PAGE_GLOBAL = '__entraAuthTracerWebMcp';

/** Isolated-world idempotency handle (window property). */
export const BRIDGE_GLOBAL = '__entraAuthTracerWebMcpBridge';

/** Directions of page <-> bridge envelopes. */
export const DIR = Object.freeze({
  HELLO: 'hello',          // page -> bridge, once on load
  INIT: 'init',            // bridge -> page, manifest + context
  REFRESH: 'refresh',      // bridge -> page, re-bake descriptions
  READY: 'ready',          // page -> bridge, registration result
  CALL: 'call',            // page -> bridge, tool invocation
  RESULT: 'result',        // bridge -> page, tool result
  TEARDOWN: 'teardown',    // bridge -> page
  TORN_DOWN: 'torn-down'   // page -> bridge
});

/** chrome.runtime / chrome.tabs message actions. */
export const ACTIONS = Object.freeze({
  ENABLE: 'webmcp:enable',      // popup -> background
  DISABLE: 'webmcp:disable',    // popup -> background
  STATUS: 'webmcp:status',      // popup -> background
  CALL: 'webmcp:call',          // bridge -> background
  INIT: 'webmcp:init',          // background -> bridge
  REFRESH: 'webmcp:refresh',    // background -> bridge
  TEARDOWN: 'webmcp:teardown',  // background -> bridge
  PING: 'webmcp:ping'           // background -> bridge
});

/** chrome.storage.session key holding the armed-tab record. */
export const STORAGE_KEY = 'webmcp.armed';

/** User-facing message when the browser has no WebMCP API (PRD US-7, verbatim). */
export const UNSUPPORTED_MESSAGE =
  'WebMCP requires Edge 147+ or Chrome 149+ (Origin Trial). The popup UI works normally.';

/** Message when the page's Permissions-Policy disables the tools feature. */
export const PERMISSIONS_POLICY_MESSAGE =
  "This page's Permissions-Policy disables WebMCP tools, so they cannot be registered here.";

export const TIMEOUTS = Object.freeze({
  READY_MS: 3000,          // wait for the page to register tools
  TEARDOWN_MS: 500,        // wait for the page to unregister
  CALL_MS: 15000,          // page -> bridge -> background round trip
  PING_MS: 500,            // restore() liveness probe
  REFRESH_DEBOUNCE_MS: 1500
});

/** Error codes returned on failed tool calls. */
export const ERROR_CODES = Object.freeze({
  NOT_ARMED: 'not_armed',
  UNKNOWN_TOOL: 'unknown_tool',
  INVALID_ARGS: 'invalid_args',
  NOT_FOUND: 'not_found',
  INTERNAL: 'internal',
  BRIDGE_TIMEOUT: 'bridge_timeout',
  TORN_DOWN: 'torn_down'
});
