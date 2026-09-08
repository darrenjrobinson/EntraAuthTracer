/**
 * Tests for the injected WebMCP runtimes: the MAIN-world page runtime that
 * registers tools on document.modelContext, and the isolated-world bridge that
 * relays between page and background.
 *
 * window.postMessage is replaced with a loopback that dispatches a MessageEvent
 * (source = window, origin = location.origin) on the next tick, so both sides
 * see exactly what a browser would deliver.
 */

import { installPageRuntime, detectModelContext, toMcpResult } from '../../src/webmcp/pageRuntime.js';
import { installBridge } from '../../src/webmcp/bridgeRuntime.js';
import WebMcpToolSchemas from '../../src/webmcp/WebMcpToolSchemas.js';
import { MSG_SOURCE, PROTOCOL_VERSION, PAGE_GLOBAL, BRIDGE_GLOBAL, DIR, ACTIONS, TIMEOUTS } from '../../src/webmcp/protocol.js';

const ORIGIN = window.location.origin;
const MANIFEST = WebMcpToolSchemas.buildManifest({ sessionCount: 3, origin: 'https://portal.azure.com' });

let posted;

function envelope(payload) {
  return { source: MSG_SOURCE, v: PROTOCOL_VERSION, ...payload };
}

function deliver(data, { origin = ORIGIN, source = window } = {}) {
  window.dispatchEvent(new MessageEvent('message', { data, origin, source }));
}

async function flush(n = 6) {
  for (let i = 0; i < n; i++) await new Promise(r => setTimeout(r, 0));
}

function fakeModelContext({ unregister = true, rejectDuplicates = true, optionsTypeError = false, securityError = false } = {}) {
  const tools = new Map();
  const signals = [];
  const mc = {
    tools,
    signals,
    registerTool: jest.fn(async (tool, options) => {
      if (securityError) { const e = new Error('Permissions policy'); e.name = 'SecurityError'; throw e; }
      if (optionsTypeError && options !== undefined) throw new TypeError('registerTool: 1 argument expected');
      if (rejectDuplicates && tools.has(tool.name)) { const e = new Error(`Tool ${tool.name} already registered`); e.name = 'InvalidStateError'; throw e; }
      tools.set(tool.name, tool);
      if (options && options.signal) {
        signals.push(options.signal);
        options.signal.addEventListener('abort', () => tools.delete(tool.name));
      }
    }),
    getTools: jest.fn(async () => [...tools.values()])
  };
  if (unregister) mc.unregisterTool = jest.fn(async (name) => { tools.delete(name); });
  return mc;
}

function setDocumentModelContext(mc) {
  Object.defineProperty(document, 'modelContext', { value: mc, configurable: true, writable: true });
}

function fakeChrome({ callResponse } = {}) {
  return {
    runtime: {
      sendMessage: jest.fn(async (msg) => (callResponse ? callResponse(msg) : { ok: true, result: { echoed: msg } })),
      onMessage: { addListener: jest.fn() }
    }
  };
}

beforeEach(() => {
  posted = [];
  jest.spyOn(window, 'postMessage').mockImplementation((data) => {
    posted.push(data);
    setTimeout(() => deliver(data), 0);
  });
});

afterEach(async () => {
  jest.useRealTimers();
  if (window[PAGE_GLOBAL]) await window[PAGE_GLOBAL].teardown();
  if (window[BRIDGE_GLOBAL]) window[BRIDGE_GLOBAL].uninstall();
  delete window[PAGE_GLOBAL];
  delete window[BRIDGE_GLOBAL];
  delete document.modelContext;
  delete window.navigator.modelContext;
  window.postMessage.mockRestore();
});

describe('pageRuntime helpers', () => {
  it('detectModelContext prefers document, then navigator, then nothing', () => {
    const mc = fakeModelContext();
    expect(detectModelContext(window, document)).toEqual({ mc: null, api: null });
    window.navigator.modelContext = mc;
    expect(detectModelContext(window, document)).toEqual({ mc, api: 'navigator' });
    setDocumentModelContext({ registerTool: () => {} });
    expect(detectModelContext(window, document).api).toBe('document');
  });

  it('toMcpResult wraps results and errors in MCP text content', () => {
    expect(toMcpResult({ ok: true, result: { a: 1 } })).toEqual({ content: [{ type: 'text', text: '{"a":1}' }] });
    expect(toMcpResult({ ok: false, error: 'nope', code: 'not_found' })).toEqual({ content: [{ type: 'text', text: '{"error":"nope","code":"not_found"}' }], isError: true });
    expect(toMcpResult(undefined).isError).toBe(true);
    expect(toMcpResult({ ok: true }).content[0].text).toBe('null');
  });
});

describe('page runtime', () => {
  it('announces itself with hello and installs the window handle', () => {
    setDocumentModelContext(fakeModelContext());
    const handle = installPageRuntime(window, document);
    expect(posted).toEqual([envelope({ dir: DIR.HELLO })]);
    expect(window[PAGE_GLOBAL]).toBe(handle);
    expect(handle.getState()).toEqual({ registered: [], api: null, generation: 0, abortSupported: true, pendingCalls: 0 });
  });

  it('registers every manifest tool with an abort signal and reports ready', async () => {
    const mc = fakeModelContext();
    setDocumentModelContext(mc);
    installPageRuntime(window, document);
    deliver(envelope({ dir: DIR.INIT, id: 'i1', manifest: MANIFEST, context: {} }));
    await flush();

    const ready = posted.find(m => m.dir === DIR.READY);
    expect(ready).toMatchObject({ id: 'i1', supported: true, toolCount: 6, api: 'document' });
    expect(mc.registerTool).toHaveBeenCalledTimes(6);
    const [tool, options] = mc.registerTool.mock.calls[0];
    expect(tool.name).toBe('list_auth_sessions');
    expect(tool.description).toContain('3 auth sessions captured — WebMCP mode active on https://portal.azure.com');
    expect(tool.annotations.readOnlyHint).toBe(true);
    expect(typeof tool.execute).toBe('function');
    expect(options.signal).toBeInstanceOf(AbortSignal);
    expect(window[PAGE_GLOBAL].getState().registered).toEqual(WebMcpToolSchemas.TOOL_NAMES);
  });

  it('execute() relays the call to the bridge and returns MCP content', async () => {
    const mc = fakeModelContext();
    setDocumentModelContext(mc);
    installPageRuntime(window, document);
    deliver(envelope({ dir: DIR.INIT, id: 'i1', manifest: MANIFEST }));
    await flush();

    // Fake bridge: answer CALL envelopes with a RESULT
    const unsub = (() => {
      const listener = (event) => {
        const d = event.data;
        if (d && d.source === MSG_SOURCE && d.dir === DIR.CALL) {
          setTimeout(() => deliver(envelope({ dir: DIR.RESULT, id: d.id, ok: true, result: { tool: d.tool, args: d.args } })), 0);
        }
      };
      window.addEventListener('message', listener);
      return () => window.removeEventListener('message', listener);
    })();

    const tool = mc.tools.get('list_auth_sessions');
    const result = await tool.execute({ limit: 2 });
    unsub();
    expect(result).toEqual({ content: [{ type: 'text', text: JSON.stringify({ tool: 'list_auth_sessions', args: { limit: 2 } }) }] });
    const call = posted.find(m => m.dir === DIR.CALL);
    expect(call.args).toEqual({ limit: 2 });
  });

  it('execute() surfaces bridge errors as isError content and never rejects', async () => {
    const mc = fakeModelContext();
    setDocumentModelContext(mc);
    installPageRuntime(window, document);
    deliver(envelope({ dir: DIR.INIT, id: 'i1', manifest: MANIFEST }));
    await flush();
    const listener = (event) => {
      const d = event.data;
      if (d && d.source === MSG_SOURCE && d.dir === DIR.CALL) {
        setTimeout(() => deliver(envelope({ dir: DIR.RESULT, id: d.id, ok: false, code: 'not_armed', error: 'WebMCP mode is not active for this tab' })), 0);
      }
    };
    window.addEventListener('message', listener);
    const result = await mc.tools.get('get_session_detail').execute({ sessionId: 'x' });
    window.removeEventListener('message', listener);
    expect(result.isError).toBe(true);
    expect(JSON.parse(result.content[0].text)).toEqual({ error: 'WebMCP mode is not active for this tab', code: 'not_armed' });
  });

  it('times out a call the bridge never answers', async () => {
    jest.useFakeTimers();
    const mc = fakeModelContext();
    setDocumentModelContext(mc);
    installPageRuntime(window, document);
    deliver(envelope({ dir: DIR.INIT, id: 'i1', manifest: MANIFEST }));
    await jest.advanceTimersByTimeAsync(10);
    const pending = mc.tools.get('list_auth_sessions').execute({});
    await jest.advanceTimersByTimeAsync(TIMEOUTS.CALL_MS + 10);
    const result = await pending;
    expect(result.isError).toBe(true);
    expect(JSON.parse(result.content[0].text).code).toBe('bridge_timeout');
    expect(window[PAGE_GLOBAL].getState().pendingCalls).toBe(0);
  });

  it('replaces a stale tool when registerTool rejects with InvalidStateError', async () => {
    const mc = fakeModelContext();
    await mc.registerTool({ name: 'list_auth_sessions', description: 'stale', execute() {} });
    setDocumentModelContext(mc);
    installPageRuntime(window, document);
    deliver(envelope({ dir: DIR.INIT, id: 'i1', manifest: MANIFEST }));
    await flush();
    expect(posted.find(m => m.dir === DIR.READY)).toMatchObject({ supported: true, toolCount: 6 });
    expect(mc.unregisterTool).toHaveBeenCalledWith('list_auth_sessions');
    expect(mc.tools.get('list_auth_sessions').description).not.toBe('stale');
  });

  it('retries without options on builds that reject the options argument and tears down via unregisterTool', async () => {
    const mc = fakeModelContext({ optionsTypeError: true });
    setDocumentModelContext(mc);
    const handle = installPageRuntime(window, document);
    deliver(envelope({ dir: DIR.INIT, id: 'i1', manifest: MANIFEST }));
    await flush();
    expect(posted.find(m => m.dir === DIR.READY)).toMatchObject({ supported: true, toolCount: 6 });
    expect(handle.getState().abortSupported).toBe(false);
    expect(mc.registerTool.mock.calls.filter(([, o]) => o === undefined)).toHaveLength(6);
    const count = await handle.teardown();
    expect(count).toBe(6);
    expect(mc.unregisterTool).toHaveBeenCalledTimes(6);
    expect(mc.tools.size).toBe(0);
  });

  it('reports no-api when the browser has no WebMCP surface', async () => {
    installPageRuntime(window, document);
    deliver(envelope({ dir: DIR.INIT, id: 'i1', manifest: MANIFEST }));
    await flush();
    expect(posted.find(m => m.dir === DIR.READY)).toEqual(envelope({ dir: DIR.READY, id: 'i1', supported: false, toolCount: 0, api: null, reason: 'no-api' }));
  });

  it('falls back to navigator.modelContext', async () => {
    window.navigator.modelContext = fakeModelContext();
    installPageRuntime(window, document);
    deliver(envelope({ dir: DIR.INIT, id: 'i1', manifest: MANIFEST }));
    await flush();
    expect(posted.find(m => m.dir === DIR.READY)).toMatchObject({ supported: true, toolCount: 6, api: 'navigator' });
  });

  it('reports permissions-policy when registration is blocked by a SecurityError', async () => {
    setDocumentModelContext(fakeModelContext({ securityError: true }));
    installPageRuntime(window, document);
    deliver(envelope({ dir: DIR.INIT, id: 'i1', manifest: MANIFEST }));
    await flush();
    const ready = posted.find(m => m.dir === DIR.READY);
    expect(ready).toMatchObject({ supported: false, toolCount: 0, reason: 'permissions-policy' });
    expect(ready.error).toMatch(/Permissions policy/);
  });

  it('tears down on request: aborts the signal, unregisters, rejects pending calls, posts torn-down', async () => {
    const mc = fakeModelContext();
    setDocumentModelContext(mc);
    installPageRuntime(window, document);
    deliver(envelope({ dir: DIR.INIT, id: 'i1', manifest: MANIFEST }));
    await flush();
    const signal = mc.signals[0];
    const pendingCall = mc.tools.get('search_sessions').execute({});

    deliver(envelope({ dir: DIR.TEARDOWN, id: 't1' }));
    await flush();

    expect(signal.aborted).toBe(true);
    expect(mc.unregisterTool).toHaveBeenCalledTimes(6);
    expect(mc.tools.size).toBe(0);
    expect(posted.find(m => m.dir === DIR.TORN_DOWN)).toEqual(envelope({ dir: DIR.TORN_DOWN, id: 't1', unregistered: 6 }));
    expect(window[PAGE_GLOBAL]).toBeUndefined();
    const result = await pendingCall;
    expect(JSON.parse(result.content[0].text).code).toBe('torn_down');
  });

  it('refresh aborts the previous generation and re-registers with fresh descriptions', async () => {
    const mc = fakeModelContext();
    setDocumentModelContext(mc);
    const handle = installPageRuntime(window, document);
    deliver(envelope({ dir: DIR.INIT, id: 'i1', manifest: MANIFEST }));
    await flush();
    const firstSignal = mc.signals[0];
    const refreshed = WebMcpToolSchemas.buildManifest({ sessionCount: 9, origin: 'https://portal.azure.com' });
    deliver(envelope({ dir: DIR.REFRESH, id: 'r1', manifest: refreshed }));
    await flush();
    expect(firstSignal.aborted).toBe(true);
    expect(handle.getState().generation).toBe(2);
    expect(mc.tools.get('list_auth_sessions').description).toContain('9 auth sessions captured');
    expect(posted.filter(m => m.dir === DIR.READY).at(-1)).toMatchObject({ id: 'r1', supported: true, toolCount: 6 });
  });

  it('ignores messages from other origins, other sources or without the source tag', async () => {
    const mc = fakeModelContext();
    setDocumentModelContext(mc);
    installPageRuntime(window, document);
    deliver(envelope({ dir: DIR.INIT, id: 'x1', manifest: MANIFEST }), { origin: 'https://evil.example' });
    deliver(envelope({ dir: DIR.INIT, id: 'x2', manifest: MANIFEST }), { source: null });
    deliver({ dir: DIR.INIT, id: 'x3', manifest: MANIFEST });
    deliver({ source: MSG_SOURCE, v: 99, dir: DIR.INIT, id: 'x4', manifest: MANIFEST });
    await flush();
    expect(mc.registerTool).not.toHaveBeenCalled();
    expect(posted.filter(m => m.dir === DIR.READY)).toHaveLength(0);
  });

  it('a second install tears down the previous generation first', async () => {
    const mc = fakeModelContext();
    setDocumentModelContext(mc);
    const first = installPageRuntime(window, document);
    deliver(envelope({ dir: DIR.INIT, id: 'i1', manifest: MANIFEST }));
    await flush();
    const firstSignal = mc.signals[0];
    const second = installPageRuntime(window, document);
    await flush();
    expect(second).not.toBe(first);
    expect(firstSignal.aborted).toBe(true);
    expect(window[PAGE_GLOBAL]).toBe(second);
    expect(posted.filter(m => m.dir === DIR.HELLO)).toHaveLength(2);
  });
});

describe('bridge runtime', () => {
  it('installs once and registers a runtime listener', () => {
    const chromeApi = fakeChrome();
    const a = installBridge(window, chromeApi);
    const b = installBridge(window, chromeApi);
    expect(a).toBe(b);
    expect(chromeApi.runtime.onMessage.addListener).toHaveBeenCalledTimes(1);
    expect(a.getState()).toEqual({ pageReady: false, toolCount: 0, queued: 0, waiting: 0 });
  });

  it('uninstall removes the window listener and the global handle', async () => {
    const chromeApi = fakeChrome();
    chromeApi.runtime.onMessage.removeListener = jest.fn();
    const bridge = installBridge(window, chromeApi);
    bridge.uninstall();
    expect(window[BRIDGE_GLOBAL]).toBeUndefined();
    expect(chromeApi.runtime.onMessage.removeListener).toHaveBeenCalledWith(bridge.handleRuntimeMessage);
    deliver(envelope({ dir: DIR.CALL, id: 'c1', tool: 'list_auth_sessions', args: {} }));
    await flush();
    expect(chromeApi.runtime.sendMessage).not.toHaveBeenCalled();
  });

  it('queues init until the page says hello, then resolves the runtime response from ready', async () => {
    const bridge = installBridge(window, fakeChrome());
    const sendResponse = jest.fn();
    const keepOpen = bridge.handleRuntimeMessage({ action: ACTIONS.INIT, manifest: MANIFEST, context: {} }, {}, sendResponse);
    expect(keepOpen).toBe(true);
    await flush();
    expect(posted.filter(m => m.dir === DIR.INIT)).toHaveLength(0);
    expect(bridge.getState().queued).toBe(1);

    deliver(envelope({ dir: DIR.HELLO }));
    await flush();
    const init = posted.find(m => m.dir === DIR.INIT);
    expect(init).toBeDefined();
    expect(init.manifest).toHaveLength(6);

    deliver(envelope({ dir: DIR.READY, id: init.id, supported: true, toolCount: 6, api: 'document' }));
    await flush();
    expect(sendResponse).toHaveBeenCalledWith({ ok: true, supported: true, toolCount: 6, api: 'document', reason: undefined, error: undefined, refreshed: false });
    expect(bridge.getState()).toMatchObject({ pageReady: true, toolCount: 6, queued: 0, waiting: 0 });
  });

  it('sends init immediately when the page is already ready and reports refreshes', async () => {
    const bridge = installBridge(window, fakeChrome());
    deliver(envelope({ dir: DIR.HELLO }));
    await flush();
    const sendResponse = jest.fn();
    bridge.handleRuntimeMessage({ action: ACTIONS.REFRESH, manifest: MANIFEST, context: {} }, {}, sendResponse);
    await flush();
    const refresh = posted.find(m => m.dir === DIR.REFRESH);
    expect(refresh).toBeDefined();
    deliver(envelope({ dir: DIR.READY, id: refresh.id, supported: true, toolCount: 6, api: 'document' }));
    await flush();
    expect(sendResponse).toHaveBeenCalledWith(expect.objectContaining({ ok: true, refreshed: true, toolCount: 6 }));
  });

  it('relays page calls to chrome.runtime.sendMessage and posts the result', async () => {
    const chromeApi = fakeChrome({ callResponse: async () => ({ ok: true, result: { total: 1 } }) });
    installBridge(window, chromeApi);
    deliver(envelope({ dir: DIR.CALL, id: 'c1', tool: 'list_auth_sessions', args: { limit: 1 } }));
    await flush();
    expect(chromeApi.runtime.sendMessage).toHaveBeenCalledWith({ action: ACTIONS.CALL, tool: 'list_auth_sessions', args: { limit: 1 } });
    expect(posted.find(m => m.dir === DIR.RESULT)).toEqual(envelope({ dir: DIR.RESULT, id: 'c1', ok: true, result: { total: 1 } }));
  });

  it('posts error results for failed and rejected background calls', async () => {
    const chromeApi = fakeChrome({ callResponse: async (msg) => (msg.tool === 'boom' ? Promise.reject(new Error('Extension context invalidated')) : { ok: false, code: 'not_armed', error: 'not active' }) });
    installBridge(window, chromeApi);
    deliver(envelope({ dir: DIR.CALL, id: 'c1', tool: 'list_auth_sessions', args: {} }));
    deliver(envelope({ dir: DIR.CALL, id: 'c2', tool: 'boom', args: {} }));
    await flush();
    const results = posted.filter(m => m.dir === DIR.RESULT);
    expect(results.find(r => r.id === 'c1')).toMatchObject({ ok: false, code: 'not_armed', error: 'not active' });
    expect(results.find(r => r.id === 'c2')).toMatchObject({ ok: false, code: 'internal', error: 'Extension context invalidated' });
  });

  it('answers teardown after the page confirms and reports ping state', async () => {
    const bridge = installBridge(window, fakeChrome());
    deliver(envelope({ dir: DIR.HELLO }));
    await flush();
    const sendResponse = jest.fn();
    bridge.handleRuntimeMessage({ action: ACTIONS.TEARDOWN }, {}, sendResponse);
    await flush();
    const teardown = posted.find(m => m.dir === DIR.TEARDOWN);
    deliver(envelope({ dir: DIR.TORN_DOWN, id: teardown.id, unregistered: 6 }));
    await flush();
    expect(sendResponse).toHaveBeenCalledWith({ ok: true, tornDown: true, unregistered: 6 });

    const ping = jest.fn();
    expect(bridge.handleRuntimeMessage({ action: ACTIONS.PING }, {}, ping)).toBe(false);
    expect(ping).toHaveBeenCalledWith({ ok: true, toolCount: 0, pageReady: true });
  });

  it('times out init when no page runtime ever replies', async () => {
    jest.useFakeTimers();
    const bridge = installBridge(window, fakeChrome());
    const sendResponse = jest.fn();
    bridge.handleRuntimeMessage({ action: ACTIONS.INIT, manifest: MANIFEST, context: {} }, {}, sendResponse);
    await jest.advanceTimersByTimeAsync(TIMEOUTS.READY_MS + 10);
    expect(sendResponse).toHaveBeenCalledWith(expect.objectContaining({ ok: false, supported: false, reason: 'no-page-runtime' }));
    expect(bridge.getState().queued).toBe(0);
  });

  it('ignores runtime messages that are not WebMCP directives', () => {
    const bridge = installBridge(window, fakeChrome());
    const sendResponse = jest.fn();
    expect(bridge.handleRuntimeMessage({ action: 'getState' }, {}, sendResponse)).toBe(false);
    expect(bridge.handleRuntimeMessage(null, {}, sendResponse)).toBe(false);
    expect(sendResponse).not.toHaveBeenCalled();
  });
});

describe('bridge + page end to end', () => {
  it('registers tools through the bridge and executes a call through to the background', async () => {
    const mc = fakeModelContext();
    setDocumentModelContext(mc);
    const chromeApi = fakeChrome({ callResponse: async (msg) => ({ ok: true, result: { tool: msg.tool, total: 2 } }) });

    const bridge = installBridge(window, chromeApi);
    installPageRuntime(window, document);
    await flush();
    expect(bridge.getState().pageReady).toBe(true);

    const initResponse = jest.fn();
    bridge.handleRuntimeMessage({ action: ACTIONS.INIT, manifest: MANIFEST, context: { sessionCount: 3 } }, {}, initResponse);
    await flush(10);
    expect(initResponse).toHaveBeenCalledWith(expect.objectContaining({ ok: true, supported: true, toolCount: 6, api: 'document' }));
    expect(mc.tools.size).toBe(6);

    const result = await mc.tools.get('get_security_warnings').execute({ severity: 'error' });
    expect(chromeApi.runtime.sendMessage).toHaveBeenCalledWith({ action: ACTIONS.CALL, tool: 'get_security_warnings', args: { severity: 'error' } });
    expect(JSON.parse(result.content[0].text)).toEqual({ tool: 'get_security_warnings', total: 2 });

    const teardownResponse = jest.fn();
    bridge.handleRuntimeMessage({ action: ACTIONS.TEARDOWN }, {}, teardownResponse);
    await flush(10);
    expect(teardownResponse).toHaveBeenCalledWith({ ok: true, tornDown: true, unregistered: 6 });
    expect(mc.tools.size).toBe(0);
  });
});
