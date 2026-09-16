/**
 * Entra Auth Tracer - WebMCP bridge (isolated world content script)
 *
 * The bridge is the only injected code with chrome.runtime access. It relays:
 *   background ──chrome.tabs.sendMessage──▶ bridge ──window.postMessage──▶ page   (init / refresh / teardown / ping)
 *   page ──window.postMessage──▶ bridge ──chrome.runtime.sendMessage──▶ background (tool calls)
 *
 * It answers each background message only once the page has replied (or a
 * timeout elapsed), so the controller sees one awaited promise per request.
 */

import { MSG_SOURCE, PROTOCOL_VERSION, BRIDGE_GLOBAL, DIR, ACTIONS, TIMEOUTS, ERROR_CODES } from './protocol.js';

const REPLY_FOR = { [DIR.INIT]: DIR.READY, [DIR.REFRESH]: DIR.READY, [DIR.TEARDOWN]: DIR.TORN_DOWN };

/**
 * Install the bridge on a window. Idempotent — a second call returns the existing handle.
 * @param {Window} win
 * @param {object} chromeApi  chrome.* (runtime.sendMessage / runtime.onMessage)
 */
export function installBridge(win, chromeApi) {
  if (win[BRIDGE_GLOBAL]) return win[BRIDGE_GLOBAL];

  const origin = win.location.origin;
  const state = { pageReady: false, queued: [], waiters: new Map(), seq: 0, toolCount: 0 };

  const post = (payload) => {
    win.postMessage({ source: MSG_SOURCE, v: PROTOCOL_VERSION, ...payload }, origin);
  };
  const newId = () => `b${Date.now().toString(36)}-${(++state.seq).toString(36)}`;

  /** Send a directive to the page and wait for its reply. */
  const sendToPage = (dir, payload, timeoutMs) => new Promise((resolve, reject) => {
    const id = newId();
    const timer = win.setTimeout(() => {
      state.waiters.delete(id);
      state.queued = state.queued.filter(q => q.id !== id);
      reject(new Error(`page runtime did not reply to ${dir} within ${timeoutMs} ms`));
    }, timeoutMs);
    state.waiters.set(id, { dir: REPLY_FOR[dir], resolve, timer });
    const envelope = { dir, id, ...payload };
    if (!state.pageReady && (dir === DIR.INIT || dir === DIR.REFRESH)) {
      // The page script has not announced itself yet — deliver once it does.
      state.queued.push(envelope);
    } else {
      post(envelope);
    }
  });

  /** Relay a tool call from the page to the background and post the result back. */
  const relayCall = async (data) => {
    let response;
    try {
      response = await new Promise((resolve, reject) => {
        let pending;
        try {
          pending = chromeApi.runtime.sendMessage({ action: ACTIONS.CALL, tool: data.tool, args: data.args });
        } catch (err) {
          reject(err);
          return;
        }
        if (pending && typeof pending.then === 'function') pending.then(resolve, reject);
        else resolve(pending);
      });
    } catch (err) {
      post({ dir: DIR.RESULT, id: data.id, ok: false, code: ERROR_CODES.INTERNAL, error: err && err.message ? err.message : String(err) });
      return;
    }
    if (response && response.ok) {
      post({ dir: DIR.RESULT, id: data.id, ok: true, result: response.result });
    } else {
      post({
        dir: DIR.RESULT, id: data.id, ok: false,
        code: (response && response.code) || ERROR_CODES.INTERNAL,
        error: (response && response.error) || 'The extension returned no response'
      });
    }
  };

  const onWindowMessage = (event) => {
    if (event.source !== win || event.origin !== origin) return;
    const data = event.data;
    if (!data || data.source !== MSG_SOURCE || data.v !== PROTOCOL_VERSION) return;

    switch (data.dir) {
      case DIR.HELLO: {
        state.pageReady = true;
        const queued = state.queued;
        state.queued = [];
        for (const envelope of queued) post(envelope);
        break;
      }
      case DIR.READY:
      case DIR.TORN_DOWN: {
        const waiter = state.waiters.get(data.id);
        if (!waiter || waiter.dir !== data.dir) return;
        win.clearTimeout(waiter.timer);
        state.waiters.delete(data.id);
        if (data.dir === DIR.READY) state.toolCount = typeof data.toolCount === 'number' ? data.toolCount : 0;
        if (data.dir === DIR.TORN_DOWN) state.toolCount = 0;
        waiter.resolve(data);
        break;
      }
      case DIR.CALL:
        relayCall(data);
        break;
      default:
        break;
    }
  };

  /** chrome.runtime.onMessage listener for background → bridge directives. */
  const onRuntimeMessage = (message, sender, sendResponse) => {
    if (!message || typeof message.action !== 'string' || !message.action.startsWith('webmcp:')) return false;

    switch (message.action) {
      case ACTIONS.INIT:
      case ACTIONS.REFRESH: {
        const dir = message.action === ACTIONS.INIT ? DIR.INIT : DIR.REFRESH;
        sendToPage(dir, { manifest: message.manifest, context: message.context }, TIMEOUTS.READY_MS)
          .then((ready) => sendResponse({
            ok: true,
            supported: !!ready.supported,
            toolCount: typeof ready.toolCount === 'number' ? ready.toolCount : 0,
            api: ready.api || null,
            reason: ready.reason,
            error: ready.error,
            refreshed: dir === DIR.REFRESH
          }))
          .catch((err) => sendResponse({ ok: false, supported: false, toolCount: 0, api: null, reason: 'no-page-runtime', error: err.message }));
        return true;
      }
      case ACTIONS.TEARDOWN:
        sendToPage(DIR.TEARDOWN, {}, TIMEOUTS.TEARDOWN_MS)
          .then((torn) => sendResponse({ ok: true, tornDown: true, unregistered: torn.unregistered || 0 }))
          .catch(() => sendResponse({ ok: true, tornDown: false, unregistered: 0 }));
        return true;
      case ACTIONS.PING:
        sendResponse({ ok: true, toolCount: state.toolCount, pageReady: state.pageReady });
        return false;
      default:
        return false;
    }
  };

  win.addEventListener('message', onWindowMessage);
  if (chromeApi && chromeApi.runtime && chromeApi.runtime.onMessage) {
    chromeApi.runtime.onMessage.addListener(onRuntimeMessage);
  }

  const handle = {
    getState: () => ({ pageReady: state.pageReady, toolCount: state.toolCount, queued: state.queued.length, waiting: state.waiters.size }),
    handleRuntimeMessage: onRuntimeMessage,
    /** Remove listeners and pending waiters (used when the bridge is replaced or in tests). */
    uninstall: () => {
      win.removeEventListener('message', onWindowMessage);
      if (chromeApi && chromeApi.runtime && chromeApi.runtime.onMessage && typeof chromeApi.runtime.onMessage.removeListener === 'function') {
        chromeApi.runtime.onMessage.removeListener(onRuntimeMessage);
      }
      for (const [, waiter] of state.waiters) win.clearTimeout(waiter.timer);
      state.waiters.clear();
      state.queued = [];
      if (win[BRIDGE_GLOBAL] === handle) delete win[BRIDGE_GLOBAL];
    }
  };
  win[BRIDGE_GLOBAL] = handle;
  return handle;
}
