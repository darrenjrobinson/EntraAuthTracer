/**
 * Entra Auth Tracer - WebMCP page runtime (MAIN world)
 *
 * Injected into the armed tab's main JavaScript world, where the WebMCP API
 * lives (`document.modelContext`, with the older `navigator.modelContext` as a
 * fallback). It registers the tool manifest it receives from the bridge and,
 * when an agent calls a tool, relays the call to the bridge over
 * window.postMessage — the main world has no chrome.* APIs of its own.
 *
 * Lifecycle: install → hello → (init | refresh) → ready → calls… → teardown.
 * Registration uses one AbortController per generation (the spec's
 * unregistration mechanism) and falls back to unregisterTool() on older builds.
 *
 * Only protocol.js may be imported here: this bundle runs as page script.
 */

import { MSG_SOURCE, PROTOCOL_VERSION, PAGE_GLOBAL, DIR, TIMEOUTS, ERROR_CODES } from './protocol.js';

/** Locate the WebMCP API on the document (spec) or navigator (origin-trial builds). */
export function detectModelContext(win, doc) {
  if (doc && doc.modelContext) return { mc: doc.modelContext, api: 'document' };
  if (win && win.navigator && win.navigator.modelContext) return { mc: win.navigator.modelContext, api: 'navigator' };
  return { mc: null, api: null };
}

/** Convert a bridge response into an MCP-style tool result. Never throws. */
export function toMcpResult(resp) {
  if (resp && resp.ok) {
    return { content: [{ type: 'text', text: JSON.stringify(resp.result === undefined ? null : resp.result) }] };
  }
  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        error: (resp && resp.error) || 'Tool call failed',
        code: (resp && resp.code) || ERROR_CODES.INTERNAL
      })
    }],
    isError: true
  };
}

/**
 * Install the runtime on a window. Returns a handle { teardown, getState }.
 * Installing twice tears the previous instance down first.
 */
export function installPageRuntime(win, doc) {
  const previous = win[PAGE_GLOBAL];
  if (previous && typeof previous.teardown === 'function') {
    try { previous.teardown(); } catch { /* ignore */ }
  }

  const origin = win.location.origin;
  const state = {
    generation: 0,
    controller: null,
    abortSupported: true,
    registeredNames: [],
    pending: new Map(),
    seq: 0,
    mc: null,
    api: null,
    tornDown: false
  };

  const post = (payload) => {
    win.postMessage({ source: MSG_SOURCE, v: PROTOCOL_VERSION, ...payload }, origin);
  };

  const newId = () => `p${Date.now().toString(36)}-${(++state.seq).toString(36)}-${Math.random().toString(36).slice(2, 8)}`;

  /** Ask the bridge to run a tool; resolves with the bridge's { ok, result | error, code }. */
  const callBridge = (tool, args) => new Promise((resolve) => {
    const id = newId();
    const timer = win.setTimeout(() => {
      state.pending.delete(id);
      resolve({ ok: false, code: ERROR_CODES.BRIDGE_TIMEOUT, error: 'The Entra Auth Tracer extension did not answer in time' });
    }, TIMEOUTS.CALL_MS);
    state.pending.set(id, { resolve, timer });
    post({ dir: DIR.CALL, id, tool, args: args == null ? {} : args });
  });

  const unregisterAll = async () => {
    const names = state.registeredNames;
    state.registeredNames = [];
    if (state.controller) {
      try { state.controller.abort(); } catch { /* ignore */ }
      state.controller = null;
    }
    if (state.mc && typeof state.mc.unregisterTool === 'function') {
      for (const name of names) {
        try { await state.mc.unregisterTool(name); } catch { /* already gone */ }
      }
    }
    return names.length;
  };

  /** (Re)register the manifest. Returns the `ready` payload. */
  const register = async (manifest) => {
    const detected = detectModelContext(win, doc);
    state.mc = detected.mc;
    state.api = detected.api;
    if (!state.mc || typeof state.mc.registerTool !== 'function') {
      return { supported: false, toolCount: 0, api: null, reason: 'no-api' };
    }

    await unregisterAll();
    state.generation++;
    const controller = typeof win.AbortController === 'function' ? new win.AbortController() : null;
    state.controller = controller;

    const registered = [];
    let reason = null;
    let lastError = null;

    for (const entry of Array.isArray(manifest) ? manifest : []) {
      const tool = {
        name: entry.name,
        title: entry.title,
        description: entry.description,
        inputSchema: entry.inputSchema,
        annotations: entry.annotations,
        execute: async (input) => toMcpResult(await callBridge(entry.name, input))
      };
      const attempt = (withSignal) => (withSignal && controller && state.abortSupported
        ? state.mc.registerTool(tool, { signal: controller.signal })
        : state.mc.registerTool(tool));

      try {
        try {
          await attempt(true);
        } catch (err) {
          if (err && err.name === 'TypeError' && controller && state.abortSupported) {
            // Older builds reject the options argument — register without it and
            // rely on unregisterTool() for teardown.
            state.abortSupported = false;
            await attempt(false);
          } else if (err && err.name === 'InvalidStateError' && typeof state.mc.unregisterTool === 'function') {
            // A tool with this name already exists (e.g. a stale generation) — replace it.
            try { await state.mc.unregisterTool(entry.name); } catch { /* ignore */ }
            await attempt(true);
          } else {
            throw err;
          }
        }
        registered.push(entry.name);
      } catch (err) {
        lastError = err && err.message ? err.message : String(err);
        if (err && (err.name === 'SecurityError' || err.name === 'NotAllowedError')) reason = 'permissions-policy';
      }
    }

    state.registeredNames = registered;
    const supported = registered.length > 0;
    const ready = { supported, toolCount: registered.length, api: state.api };
    if (!supported) {
      ready.reason = reason || 'register-failed';
      if (lastError) ready.error = lastError;
    }
    return ready;
  };

  const teardown = async () => {
    if (state.tornDown) return 0;
    state.tornDown = true;
    const count = await unregisterAll();
    for (const [, p] of state.pending) {
      win.clearTimeout(p.timer);
      p.resolve({ ok: false, code: ERROR_CODES.TORN_DOWN, error: 'WebMCP mode was disabled' });
    }
    state.pending.clear();
    win.removeEventListener('message', onMessage);
    if (win[PAGE_GLOBAL] === handle) delete win[PAGE_GLOBAL];
    return count;
  };

  const onMessage = (event) => {
    if (event.source !== win || event.origin !== origin) return;
    const data = event.data;
    if (!data || data.source !== MSG_SOURCE || data.v !== PROTOCOL_VERSION) return;

    switch (data.dir) {
      case DIR.INIT:
      case DIR.REFRESH:
        register(data.manifest)
          .then((ready) => post({ dir: DIR.READY, id: data.id, ...ready }))
          .catch((err) => post({ dir: DIR.READY, id: data.id, supported: false, toolCount: 0, api: state.api, reason: 'register-failed', error: err && err.message ? err.message : String(err) }));
        break;
      case DIR.RESULT: {
        const p = state.pending.get(data.id);
        if (!p) return;
        win.clearTimeout(p.timer);
        state.pending.delete(data.id);
        p.resolve({ ok: !!data.ok, result: data.result, error: data.error, code: data.code });
        break;
      }
      case DIR.TEARDOWN:
        teardown().then((count) => post({ dir: DIR.TORN_DOWN, id: data.id, unregistered: count }));
        break;
      default:
        break;
    }
  };

  const handle = {
    teardown,
    getState: () => ({
      registered: [...state.registeredNames],
      api: state.api,
      generation: state.generation,
      abortSupported: state.abortSupported,
      pendingCalls: state.pending.size
    })
  };

  win.addEventListener('message', onMessage);
  win[PAGE_GLOBAL] = handle;
  post({ dir: DIR.HELLO });
  return handle;
}
