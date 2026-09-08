/**
 * Entra Auth Tracer - WebMCP controller (background service worker)
 *
 * Owns the per-tab "WebMCP mode" lifecycle:
 *
 *   idle ──enable──▶ arming ──ready──▶ armed ──disable/navigate/close──▶ idle
 *
 * - enable(): resolves the active tab of the last-focused normal window, requires
 *   https, injects the isolated-world bridge and the MAIN-world page runtime,
 *   sends the tool manifest and waits for the page to report registration.
 * - call(): serves tool invocations relayed by the bridge, only for the armed tab.
 * - The armed record is persisted in chrome.storage.session so it survives
 *   service-worker termination; restore() re-validates it lazily.
 * - Tab navigation (document reload / cross-origin URL) and tab close disarm.
 *
 * `chrome` is injected so the controller is unit-testable without globals.
 */

import WebMcpTools from './WebMcpTools.js';
import WebMcpToolSchemas from './WebMcpToolSchemas.js';
import {
  ACTIONS, STORAGE_KEY, TIMEOUTS, ERROR_CODES,
  UNSUPPORTED_MESSAGE, PERMISSIONS_POLICY_MESSAGE
} from './protocol.js';

const PHASES = Object.freeze({ IDLE: 'idle', ARMING: 'arming', ARMED: 'armed', DISARMING: 'disarming' });

function safeOrigin(url) {
  try { return new URL(url).origin; } catch { return null; }
}

function schemeOf(url) {
  try { return new URL(url).protocol.replace(/:$/, ''); } catch { return null; }
}

class WebMcpController {
  static PHASES = PHASES;
  static BRIDGE_FILE = 'src/webmcp-bridge.js';
  static PAGE_FILE = 'src/webmcp-page.js';

  /**
   * @param {object} deps
   * @param {object} deps.chrome        chrome.* API surface (tabs, scripting, storage, windows, runtime)
   * @param {() => object[]} deps.getRequests  returns the current captured requests
   * @param {object} [deps.tools]       tool implementation (WebMcpTools-compatible `run`)
   * @param {object} [deps.schemas]     schema module (WebMcpToolSchemas-compatible `buildManifest`)
   * @param {() => number} [deps.now]
   */
  constructor({ chrome: chromeApi, getRequests, tools = WebMcpTools, schemas = WebMcpToolSchemas, now = () => Date.now() } = {}) {
    this.chrome = chromeApi;
    this.getRequests = typeof getRequests === 'function' ? getRequests : () => [];
    this.tools = tools;
    this.schemas = schemas;
    this.now = now;

    this.state = this._idleState(null);
    this._arming = null;
    this._restorePromise = null;
    this._refreshTimer = null;
    this._listenersAttached = false;
  }

  // ─── Public API ──────────────────────────────────────────────────────────

  /** Register tab listeners. Call synchronously at service-worker top level. */
  attachListeners() {
    if (this._listenersAttached) return;
    const tabs = this.chrome && this.chrome.tabs;
    if (!tabs) return;
    this._listenersAttached = true;
    if (tabs.onUpdated) tabs.onUpdated.addListener((tabId, changeInfo) => { this.handleTabUpdated(tabId, changeInfo || {}).catch(() => {}); });
    if (tabs.onRemoved) tabs.onRemoved.addListener((tabId) => { this.handleTabRemoved(tabId).catch(() => {}); });
    if (tabs.onReplaced) tabs.onReplaced.addListener((addedTabId, removedTabId) => { this.handleTabRemoved(removedTabId).catch(() => {}); });
  }

  /** Snapshot for the popup (structured-clone safe). */
  status() {
    const s = this.state;
    return {
      phase: s.phase,
      armed: s.phase === PHASES.ARMED,
      tabId: s.tabId,
      url: s.url,
      origin: s.origin,
      host: s.origin ? s.origin.replace(/^https?:\/\//, '') : null,
      toolCount: s.toolCount,
      api: s.api,
      armedAt: s.armedAt,
      supported: s.phase === PHASES.ARMED ? true : (s.lastError === UNSUPPORTED_MESSAGE || s.lastError === PERMISSIONS_POLICY_MESSAGE ? false : null),
      lastError: s.lastError
    };
  }

  /** Route a `webmcp:*` runtime message. */
  async handleMessage(request, sender) {
    switch (request && request.action) {
      case ACTIONS.ENABLE: return this.enable();
      case ACTIONS.DISABLE: return this.disable();
      case ACTIONS.STATUS: await this.ensureRestored(); return { ok: true, status: this.status() };
      case ACTIONS.CALL: return this.call(request.tool, request.args, sender);
      default: return { ok: false, code: ERROR_CODES.INTERNAL, error: `Unknown WebMCP action: ${request && request.action}` };
    }
  }

  /** Arm WebMCP mode on the active tab. Idempotent while arming. */
  async enable() {
    await this.ensureRestored();
    if (this._arming) return this._arming;
    this._arming = this._enable().finally(() => { this._arming = null; });
    return this._arming;
  }

  /** Disarm: ask the page to unregister its tools and forget the tab. */
  async disable() {
    await this.ensureRestored();
    if (this.state.phase === PHASES.IDLE) return { ok: true, status: this.status() };
    const tabId = this.state.tabId;
    this._transition({ phase: PHASES.DISARMING });
    await this._teardownBestEffort(tabId);
    await this._clear(null);
    return { ok: true, status: this.status() };
  }

  /** Serve a tool call relayed by the bridge in the armed tab. */
  async call(tool, args, sender) {
    await this.ensureRestored();
    const senderTabId = sender && sender.tab ? sender.tab.id : null;
    if (this.state.phase !== PHASES.ARMED || senderTabId === null || senderTabId !== this.state.tabId) {
      return { ok: false, code: ERROR_CODES.NOT_ARMED, error: 'WebMCP mode is not active for this tab' };
    }
    try {
      const result = await this.tools.run(tool, args, this.getRequests(), this._context(this.state.origin));
      return { ok: true, result };
    } catch (err) {
      if (err && typeof err.code === 'string') return { ok: false, code: err.code, error: err.message };
      return { ok: false, code: ERROR_CODES.INTERNAL, error: err && err.message ? err.message : 'Tool execution failed' };
    }
  }

  /** Debounced re-bake of tool descriptions after captures change. */
  notifySessionsChanged() {
    if (this.state.phase !== PHASES.ARMED) return;
    if (this._refreshTimer) clearTimeout(this._refreshTimer);
    this._refreshTimer = setTimeout(() => {
      this._refreshTimer = null;
      this._refresh().catch(() => {});
    }, TIMEOUTS.REFRESH_DEBOUNCE_MS);
  }

  /** Lazily restore the armed record after a service-worker restart. */
  ensureRestored() {
    if (!this._restorePromise) this._restorePromise = this.restore().catch(() => {});
    return this._restorePromise;
  }

  async restore() {
    if (this.state.phase !== PHASES.IDLE) return;
    const session = this.chrome && this.chrome.storage && this.chrome.storage.session;
    if (!session) return;
    const stored = await session.get(STORAGE_KEY);
    const rec = stored && stored[STORAGE_KEY];
    if (!rec || typeof rec.tabId !== 'number') return;

    let tab = null;
    try { tab = await this.chrome.tabs.get(rec.tabId); } catch { tab = null; }
    if (!tab || !tab.url || safeOrigin(tab.url) !== rec.origin) {
      await this._clearStorage();
      return;
    }
    try {
      const pong = await this._sendToBridge(rec.tabId, { action: ACTIONS.PING }, TIMEOUTS.PING_MS);
      if (!pong || !pong.ok) throw new Error('bridge did not answer');
      this.state = {
        phase: PHASES.ARMED,
        tabId: rec.tabId,
        url: tab.url,
        origin: rec.origin,
        toolCount: typeof pong.toolCount === 'number' ? pong.toolCount : (rec.toolCount || 0),
        api: rec.api || null,
        armedAt: rec.armedAt || null,
        lastError: null
      };
    } catch {
      await this._clearStorage();
    }
  }

  // ─── Tab lifecycle ───────────────────────────────────────────────────────

  async handleTabUpdated(tabId, changeInfo) {
    await this.ensureRestored();
    if (this.state.phase !== PHASES.ARMED && this.state.phase !== PHASES.ARMING) return;
    if (tabId !== this.state.tabId) return;

    // A new document is loading: the page's ModelContext (and our tools) are gone.
    if (changeInfo.status === 'loading') {
      await this._clear(null);
      return;
    }
    // Same-document URL change (SPA routing) keeps the registration; cross-origin does not.
    if (changeInfo.url) {
      const origin = safeOrigin(changeInfo.url);
      if (origin !== this.state.origin) {
        await this._clear(null);
      } else {
        this.state.url = changeInfo.url;
        await this._persist();
      }
    }
  }

  async handleTabRemoved(tabId) {
    await this.ensureRestored();
    if (this.state.phase === PHASES.IDLE) return;
    if (tabId !== this.state.tabId) return;
    await this._clear(null);
  }

  /**
   * The tab to arm: the active tab of the last-focused normal window. When the
   * popout window itself is focused, fall back to the last focused normal window.
   */
  async resolveTargetTab() {
    const extensionPrefix = this.chrome.runtime && typeof this.chrome.runtime.getURL === 'function'
      ? this.chrome.runtime.getURL('') : null;
    const usable = (t) => !!(t && t.url) && !(extensionPrefix && t.url.startsWith(extensionPrefix));

    let tab = (await this._query({ active: true, lastFocusedWindow: true })).find(usable) || null;
    if (tab && this.chrome.windows && typeof this.chrome.windows.get === 'function' && tab.windowId !== undefined) {
      try {
        const win = await this.chrome.windows.get(tab.windowId);
        if (win && win.type && win.type !== 'normal') tab = null;
      } catch { /* keep tab */ }
    }
    if (!tab && this.chrome.windows && typeof this.chrome.windows.getLastFocused === 'function') {
      try {
        const win = await this.chrome.windows.getLastFocused({ windowTypes: ['normal'] });
        if (win && win.id !== undefined) {
          tab = (await this._query({ active: true, windowId: win.id })).find(usable) || null;
        }
      } catch { /* fall through */ }
    }
    if (!tab) {
      tab = (await this._query({ active: true, windowType: 'normal' })).find(usable) || null;
    }
    return tab;
  }

  // ─── Internals ───────────────────────────────────────────────────────────

  async _enable() {
    const tab = await this.resolveTargetTab();
    if (!tab) return this._fail('No active browser tab found — open the page you want to analyse and try again.');

    const url = tab.url || tab.pendingUrl || '';
    if (!/^https:\/\//i.test(url)) {
      return this._fail(`WebMCP can only be enabled on https:// pages (current page: ${schemeOf(url) || 'unknown'}).`);
    }
    if (tab.status && tab.status !== 'complete') {
      return this._fail('The page is still loading — wait for it to finish, then enable WebMCP.');
    }

    if (this.state.phase === PHASES.ARMED) {
      if (this.state.tabId === tab.id) {
        await this._refresh();
        return { ok: true, status: this.status() };
      }
      await this.disable();
    }

    const origin = safeOrigin(url);
    this.state = { phase: PHASES.ARMING, tabId: tab.id, url, origin, toolCount: 0, api: null, armedAt: null, lastError: null };

    try {
      await this._inject(tab.id);
    } catch (err) {
      return this._fail(`This page does not allow extensions to run scripts (${err && err.message ? err.message : err}).`);
    }

    let resp;
    try {
      resp = await this._sendToBridge(tab.id, { action: ACTIONS.INIT, manifest: this._manifest(origin), context: this._context(origin) }, TIMEOUTS.READY_MS);
    } catch (err) {
      await this._teardownBestEffort(tab.id);
      return this._fail(`The page did not confirm tool registration (${err && err.message ? err.message : err}).`);
    }

    if (!resp || !resp.supported) {
      await this._teardownBestEffort(tab.id);
      const message = resp && resp.reason === 'permissions-policy' ? PERMISSIONS_POLICY_MESSAGE : UNSUPPORTED_MESSAGE;
      return this._fail(message);
    }

    this.state = {
      ...this.state,
      phase: PHASES.ARMED,
      toolCount: typeof resp.toolCount === 'number' ? resp.toolCount : 0,
      api: resp.api || null,
      armedAt: this.now(),
      lastError: null
    };
    await this._persist();
    return { ok: true, status: this.status() };
  }

  async _refresh() {
    if (this.state.phase !== PHASES.ARMED) return;
    const { tabId, origin } = this.state;
    try {
      const resp = await this._sendToBridge(tabId, { action: ACTIONS.REFRESH, manifest: this._manifest(origin), context: this._context(origin) }, TIMEOUTS.READY_MS);
      if (resp && typeof resp.toolCount === 'number') this.state.toolCount = resp.toolCount;
      await this._persist();
    } catch (err) {
      // Tools keep working with stale descriptions; surface the problem without disarming.
      this.state.lastError = `Could not refresh tool descriptions (${err && err.message ? err.message : err}).`;
    }
  }

  async _inject(tabId) {
    await this.chrome.scripting.executeScript({ target: { tabId }, files: [WebMcpController.BRIDGE_FILE], world: 'ISOLATED' });
    await this.chrome.scripting.executeScript({ target: { tabId }, files: [WebMcpController.PAGE_FILE], world: 'MAIN' });
  }

  async _teardownBestEffort(tabId) {
    if (tabId === null || tabId === undefined) return false;
    try {
      const resp = await this._sendToBridge(tabId, { action: ACTIONS.TEARDOWN }, TIMEOUTS.TEARDOWN_MS);
      return !!(resp && resp.tornDown);
    } catch {
      return false;
    }
  }

  _sendToBridge(tabId, message, timeoutMs) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`timed out after ${timeoutMs} ms`)), timeoutMs);
      let pending;
      try {
        pending = this.chrome.tabs.sendMessage(tabId, message);
      } catch (err) {
        clearTimeout(timer);
        reject(err instanceof Error ? err : new Error(String(err)));
        return;
      }
      Promise.resolve(pending).then(
        (resp) => { clearTimeout(timer); resolve(resp); },
        (err) => { clearTimeout(timer); reject(err instanceof Error ? err : new Error(String(err))); }
      );
    });
  }

  async _query(query) {
    try {
      const result = await this.chrome.tabs.query(query);
      return Array.isArray(result) ? result : [];
    } catch {
      return [];
    }
  }

  _manifest(origin) {
    return this.schemas.buildManifest(this._context(origin));
  }

  _context(origin) {
    return { sessionCount: this.getRequests().length, origin: origin || null };
  }

  _transition(patch) {
    this.state = { ...this.state, ...patch };
  }

  _idleState(lastError) {
    return { phase: PHASES.IDLE, tabId: null, url: null, origin: null, toolCount: 0, api: null, armedAt: null, lastError };
  }

  async _fail(message) {
    this.state = this._idleState(message);
    await this._clearStorage();
    return { ok: false, error: message, status: this.status() };
  }

  async _clear(lastError) {
    if (this._refreshTimer) { clearTimeout(this._refreshTimer); this._refreshTimer = null; }
    this.state = this._idleState(lastError);
    await this._clearStorage();
  }

  async _persist() {
    const session = this.chrome && this.chrome.storage && this.chrome.storage.session;
    if (!session || this.state.phase !== PHASES.ARMED) return;
    const { tabId, url, origin, armedAt, toolCount, api } = this.state;
    try { await session.set({ [STORAGE_KEY]: { tabId, url, origin, armedAt, toolCount, api } }); } catch { /* ignore */ }
  }

  async _clearStorage() {
    const session = this.chrome && this.chrome.storage && this.chrome.storage.session;
    if (!session) return;
    try { await session.remove(STORAGE_KEY); } catch { /* ignore */ }
  }
}

export default WebMcpController;
