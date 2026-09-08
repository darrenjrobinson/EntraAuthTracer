/**
 * Tests for WebMcpController — the background-side WebMCP lifecycle.
 *
 * A fake chrome API is injected: tabs/windows describe the browser layout, the
 * "bridge" function answers tabs.sendMessage for the injected content script,
 * and storage.session is an in-memory object.
 */

import WebMcpController from '../../src/webmcp/WebMcpController.js';
import { ACTIONS, STORAGE_KEY, TIMEOUTS, UNSUPPORTED_MESSAGE, PERMISSIONS_POLICY_MESSAGE } from '../../src/webmcp/protocol.js';

const EXT = 'chrome-extension://abcdefgh/';

function readyBridge({ supported = true, toolCount = 6, api = 'document', reason } = {}) {
  return async (tabId, msg) => {
    switch (msg.action) {
      case ACTIONS.INIT:
      case ACTIONS.REFRESH:
        return { ok: true, supported, toolCount: supported ? toolCount : 0, api: supported ? api : null, reason, refreshed: msg.action === ACTIONS.REFRESH };
      case ACTIONS.TEARDOWN:
        return { ok: true, tornDown: true };
      case ACTIONS.PING:
        return { ok: true, toolCount };
      default:
        return { ok: false };
    }
  };
}

function fakeChrome({
  tabs = [{ id: 1, windowId: 10, active: true, url: 'https://portal.azure.com/#home', status: 'complete' }],
  windows = [{ id: 10, type: 'normal' }],
  lastFocusedWindowId = 10,
  bridge = readyBridge(),
  session = {}
} = {}) {
  const listeners = { onUpdated: [], onRemoved: [], onReplaced: [] };
  const api = {
    runtime: { getURL: (p) => EXT + p },
    tabs: {
      query: jest.fn(async (q) => tabs.filter(t =>
        (q.active === undefined || t.active === q.active) &&
        (q.windowId === undefined || t.windowId === q.windowId) &&
        (q.lastFocusedWindow === undefined || t.windowId === lastFocusedWindowId) &&
        (q.windowType === undefined || (windows.find(w => w.id === t.windowId) || {}).type === q.windowType)
      )),
      get: jest.fn(async (id) => { const t = tabs.find(x => x.id === id); if (!t) throw new Error('No tab with id'); return t; }),
      sendMessage: jest.fn(async (tabId, msg) => bridge(tabId, msg)),
      onUpdated: { addListener: jest.fn(fn => listeners.onUpdated.push(fn)) },
      onRemoved: { addListener: jest.fn(fn => listeners.onRemoved.push(fn)) },
      onReplaced: { addListener: jest.fn(fn => listeners.onReplaced.push(fn)) }
    },
    windows: {
      get: jest.fn(async (id) => windows.find(w => w.id === id) || { id, type: 'normal' }),
      getLastFocused: jest.fn(async () => windows.find(w => w.type === 'normal') || null)
    },
    scripting: { executeScript: jest.fn(async () => [{ result: null }]) },
    storage: {
      session: {
        get: jest.fn(async (key) => (key in session ? { [key]: session[key] } : {})),
        set: jest.fn(async (obj) => { Object.assign(session, obj); }),
        remove: jest.fn(async (key) => { delete session[key]; })
      }
    },
    _listeners: listeners,
    _session: session,
    _tabs: tabs
  };
  return api;
}

function makeController(chromeApi, overrides = {}) {
  return new WebMcpController({
    chrome: chromeApi,
    getRequests: () => overrides.requests || [{ id: 'r1' }, { id: 'r2' }],
    tools: overrides.tools || { run: jest.fn(async (tool, args) => ({ tool, args })) },
    now: () => 1_757_300_000_000,
    ...overrides.deps
  });
}

describe('WebMcpController', () => {
  afterEach(() => jest.useRealTimers());

  describe('enable', () => {
    it('injects bridge then page, sends the manifest, and becomes armed with persisted state', async () => {
      const chromeApi = fakeChrome();
      const c = makeController(chromeApi);
      const result = await c.enable();

      expect(result.ok).toBe(true);
      expect(c.status()).toMatchObject({ phase: 'armed', armed: true, tabId: 1, origin: 'https://portal.azure.com', host: 'portal.azure.com', toolCount: 6, api: 'document', supported: true, lastError: null });

      const calls = chromeApi.scripting.executeScript.mock.calls.map(([arg]) => arg);
      expect(calls).toEqual([
        { target: { tabId: 1 }, files: ['src/webmcp-bridge.js'], world: 'ISOLATED' },
        { target: { tabId: 1 }, files: ['src/webmcp-page.js'], world: 'MAIN' }
      ]);

      const init = chromeApi.tabs.sendMessage.mock.calls.find(([, m]) => m.action === ACTIONS.INIT)[1];
      expect(init.manifest).toHaveLength(6);
      expect(init.manifest[0].description).toContain('2 auth sessions captured — WebMCP mode active on https://portal.azure.com');
      expect(init.context).toEqual({ sessionCount: 2, origin: 'https://portal.azure.com' });

      expect(chromeApi._session[STORAGE_KEY]).toEqual({ tabId: 1, url: 'https://portal.azure.com/#home', origin: 'https://portal.azure.com', armedAt: 1_757_300_000_000, toolCount: 6, api: 'document' });
    });

    it('refuses http pages with a clear message and stays idle', async () => {
      const chromeApi = fakeChrome({ tabs: [{ id: 1, windowId: 10, active: true, url: 'http://intranet.local/app', status: 'complete' }] });
      const c = makeController(chromeApi);
      const result = await c.enable();
      expect(result.ok).toBe(false);
      expect(result.error).toMatch(/only be enabled on https:\/\/ pages \(current page: http\)/);
      expect(c.status().phase).toBe('idle');
      expect(chromeApi.scripting.executeScript).not.toHaveBeenCalled();
    });

    it('refuses while the page is still loading', async () => {
      const chromeApi = fakeChrome({ tabs: [{ id: 1, windowId: 10, active: true, url: 'https://x.example/', status: 'loading' }] });
      const result = await makeController(chromeApi).enable();
      expect(result.ok).toBe(false);
      expect(result.error).toMatch(/still loading/);
    });

    it('reports when there is no usable tab', async () => {
      const chromeApi = fakeChrome({ tabs: [] });
      const result = await makeController(chromeApi).enable();
      expect(result.ok).toBe(false);
      expect(result.error).toMatch(/No active browser tab/);
    });

    it('ignores the popout window and arms the last focused normal window instead', async () => {
      const chromeApi = fakeChrome({
        tabs: [
          { id: 5, windowId: 20, active: true, url: EXT + 'src/ui.html?popout=true', status: 'complete' },
          { id: 1, windowId: 10, active: true, url: 'https://portal.azure.com/', status: 'complete' }
        ],
        windows: [{ id: 20, type: 'popup' }, { id: 10, type: 'normal' }],
        lastFocusedWindowId: 20
      });
      const c = makeController(chromeApi);
      const result = await c.enable();
      expect(result.ok).toBe(true);
      expect(c.status().tabId).toBe(1);
      expect(chromeApi.windows.getLastFocused).toHaveBeenCalledWith({ windowTypes: ['normal'] });
    });

    it('turns an injection failure into a friendly error', async () => {
      const chromeApi = fakeChrome();
      chromeApi.scripting.executeScript.mockRejectedValueOnce(new Error('Cannot access a chrome:// URL'));
      const c = makeController(chromeApi);
      const result = await c.enable();
      expect(result.ok).toBe(false);
      expect(result.error).toMatch(/does not allow extensions to run scripts/);
      expect(c.status().phase).toBe('idle');
      expect(chromeApi._session[STORAGE_KEY]).toBeUndefined();
    });

    it('reports the US-7 unsupported message, tears down and stays idle when the page has no WebMCP API', async () => {
      const chromeApi = fakeChrome({ bridge: readyBridge({ supported: false, reason: 'no-api' }) });
      const c = makeController(chromeApi);
      const result = await c.enable();
      expect(result.ok).toBe(false);
      expect(result.error).toBe(UNSUPPORTED_MESSAGE);
      expect(c.status()).toMatchObject({ phase: 'idle', supported: false, lastError: UNSUPPORTED_MESSAGE });
      expect(chromeApi.tabs.sendMessage.mock.calls.some(([, m]) => m.action === ACTIONS.TEARDOWN)).toBe(true);
    });

    it('distinguishes a Permissions-Policy block', async () => {
      const chromeApi = fakeChrome({ bridge: readyBridge({ supported: false, reason: 'permissions-policy' }) });
      const result = await makeController(chromeApi).enable();
      expect(result.error).toBe(PERMISSIONS_POLICY_MESSAGE);
    });

    it('times out when the page never confirms registration', async () => {
      jest.useFakeTimers();
      const chromeApi = fakeChrome({ bridge: async (tabId, msg) => (msg.action === ACTIONS.INIT ? new Promise(() => {}) : { ok: true, tornDown: true }) });
      const c = makeController(chromeApi);
      const pending = c.enable();
      await jest.advanceTimersByTimeAsync(TIMEOUTS.READY_MS + 10);
      const result = await pending;
      expect(result.ok).toBe(false);
      expect(result.error).toMatch(/did not confirm tool registration/);
      expect(c.status().phase).toBe('idle');
    });

    it('returns the in-flight promise when enable is called twice while arming', async () => {
      const chromeApi = fakeChrome();
      const c = makeController(chromeApi);
      const [a, b] = await Promise.all([c.enable(), c.enable()]);
      expect(a).toBe(b);
      expect(chromeApi.scripting.executeScript).toHaveBeenCalledTimes(2); // bridge + page, once
    });

    it('refreshes the manifest when enabled again on the same tab', async () => {
      const chromeApi = fakeChrome();
      const c = makeController(chromeApi);
      await c.enable();
      const before = chromeApi.scripting.executeScript.mock.calls.length;
      const result = await c.enable();
      expect(result.ok).toBe(true);
      expect(chromeApi.scripting.executeScript.mock.calls.length).toBe(before);
      expect(chromeApi.tabs.sendMessage.mock.calls.some(([, m]) => m.action === ACTIONS.REFRESH)).toBe(true);
    });

    it('disarms the previous tab before arming a different one', async () => {
      const chromeApi = fakeChrome();
      const c = makeController(chromeApi);
      await c.enable();
      chromeApi._tabs[0].active = false;
      chromeApi._tabs.push({ id: 2, windowId: 10, active: true, url: 'https://myapps.microsoft.com/', status: 'complete' });
      const result = await c.enable();
      expect(result.ok).toBe(true);
      expect(c.status().tabId).toBe(2);
      const teardowns = chromeApi.tabs.sendMessage.mock.calls.filter(([tabId, m]) => m.action === ACTIONS.TEARDOWN && tabId === 1);
      expect(teardowns).toHaveLength(1);
    });
  });

  describe('disable', () => {
    it('sends teardown, clears state and storage', async () => {
      const chromeApi = fakeChrome();
      const c = makeController(chromeApi);
      await c.enable();
      const result = await c.disable();
      expect(result.ok).toBe(true);
      expect(c.status()).toMatchObject({ phase: 'idle', armed: false, tabId: null, lastError: null });
      expect(chromeApi._session[STORAGE_KEY]).toBeUndefined();
      expect(chromeApi.tabs.sendMessage.mock.calls.at(-1)[1].action).toBe(ACTIONS.TEARDOWN);
    });

    it('still goes idle when the bridge is gone', async () => {
      const chromeApi = fakeChrome();
      const c = makeController(chromeApi);
      await c.enable();
      chromeApi.tabs.sendMessage.mockRejectedValue(new Error('Could not establish connection. Receiving end does not exist.'));
      const result = await c.disable();
      expect(result.ok).toBe(true);
      expect(c.status().phase).toBe('idle');
    });

    it('is a no-op when idle', async () => {
      const chromeApi = fakeChrome();
      const c = makeController(chromeApi);
      const result = await c.disable();
      expect(result).toEqual({ ok: true, status: c.status() });
      expect(chromeApi.tabs.sendMessage).not.toHaveBeenCalled();
    });
  });

  describe('tab lifecycle', () => {
    async function armed() {
      const chromeApi = fakeChrome();
      const c = makeController(chromeApi);
      c.attachListeners();
      await c.enable();
      return { chromeApi, c };
    }

    it('registers onUpdated / onRemoved / onReplaced listeners once', async () => {
      const chromeApi = fakeChrome();
      const c = makeController(chromeApi);
      c.attachListeners();
      c.attachListeners();
      expect(chromeApi._listeners.onUpdated).toHaveLength(1);
      expect(chromeApi._listeners.onRemoved).toHaveLength(1);
      expect(chromeApi._listeners.onReplaced).toHaveLength(1);
    });

    it('disarms when the armed tab starts loading a new document', async () => {
      const { chromeApi, c } = await armed();
      chromeApi._listeners.onUpdated[0](1, { status: 'loading' });
      await new Promise(r => setTimeout(r, 0));
      expect(c.status().phase).toBe('idle');
      expect(chromeApi._session[STORAGE_KEY]).toBeUndefined();
    });

    it('keeps the registration on a same-origin SPA route change and updates the url', async () => {
      const { c } = await armed();
      await c.handleTabUpdated(1, { url: 'https://portal.azure.com/#view/other' });
      expect(c.status().phase).toBe('armed');
      expect(c.status().url).toBe('https://portal.azure.com/#view/other');
    });

    it('disarms on a cross-origin url change', async () => {
      const { c } = await armed();
      await c.handleTabUpdated(1, { url: 'https://evil.example/' });
      expect(c.status().phase).toBe('idle');
    });

    it('ignores updates to other tabs', async () => {
      const { c } = await armed();
      await c.handleTabUpdated(99, { status: 'loading' });
      expect(c.status().phase).toBe('armed');
    });

    it('disarms when the armed tab is closed or replaced', async () => {
      const { chromeApi, c } = await armed();
      chromeApi._listeners.onRemoved[0](1);
      await new Promise(r => setTimeout(r, 0));
      expect(c.status().phase).toBe('idle');

      await c.enable();
      chromeApi._listeners.onReplaced[0](77, 1);
      await new Promise(r => setTimeout(r, 0));
      expect(c.status().phase).toBe('idle');
    });
  });

  describe('restore', () => {
    const record = { tabId: 1, url: 'https://portal.azure.com/#home', origin: 'https://portal.azure.com', armedAt: 123, toolCount: 6, api: 'document' };

    it('re-arms from storage when the tab still exists on the same origin and the bridge answers', async () => {
      const chromeApi = fakeChrome({ session: { [STORAGE_KEY]: { ...record } } });
      const c = makeController(chromeApi);
      await c.ensureRestored();
      expect(c.status()).toMatchObject({ phase: 'armed', tabId: 1, origin: 'https://portal.azure.com', toolCount: 6, api: 'document', armedAt: 123 });
      expect(chromeApi.tabs.sendMessage).toHaveBeenCalledWith(1, { action: ACTIONS.PING });
    });

    it('clears the record when the tab is gone', async () => {
      const chromeApi = fakeChrome({ tabs: [], session: { [STORAGE_KEY]: { ...record } } });
      const c = makeController(chromeApi);
      await c.ensureRestored();
      expect(c.status().phase).toBe('idle');
      expect(chromeApi._session[STORAGE_KEY]).toBeUndefined();
    });

    it('clears the record when the tab moved to another origin', async () => {
      const chromeApi = fakeChrome({ tabs: [{ id: 1, windowId: 10, active: true, url: 'https://other.example/' }], session: { [STORAGE_KEY]: { ...record } } });
      const c = makeController(chromeApi);
      await c.ensureRestored();
      expect(c.status().phase).toBe('idle');
    });

    it('clears the record when the bridge does not answer the ping', async () => {
      const chromeApi = fakeChrome({ bridge: async () => { throw new Error('no receiver'); }, session: { [STORAGE_KEY]: { ...record } } });
      const c = makeController(chromeApi);
      await c.ensureRestored();
      expect(c.status().phase).toBe('idle');
      expect(chromeApi._session[STORAGE_KEY]).toBeUndefined();
    });

    it('only restores once', async () => {
      const chromeApi = fakeChrome({ session: { [STORAGE_KEY]: { ...record } } });
      const c = makeController(chromeApi);
      await Promise.all([c.ensureRestored(), c.ensureRestored()]);
      expect(chromeApi.storage.session.get).toHaveBeenCalledTimes(1);
    });
  });

  describe('call', () => {
    it('rejects calls when not armed', async () => {
      const c = makeController(fakeChrome());
      expect(await c.call('list_auth_sessions', {}, { tab: { id: 1 } })).toEqual({ ok: false, code: 'not_armed', error: 'WebMCP mode is not active for this tab' });
    });

    it('rejects calls from a tab other than the armed one', async () => {
      const c = makeController(fakeChrome());
      await c.enable();
      expect((await c.call('list_auth_sessions', {}, { tab: { id: 2 } })).code).toBe('not_armed');
      expect((await c.call('list_auth_sessions', {}, {})).code).toBe('not_armed');
    });

    it('runs the tool with the captured requests and armed context', async () => {
      const tools = { run: jest.fn(async () => ({ sessions: [] })) };
      const c = makeController(fakeChrome(), { tools });
      await c.enable();
      const resp = await c.call('list_auth_sessions', { limit: 5 }, { tab: { id: 1 } });
      expect(resp).toEqual({ ok: true, result: { sessions: [] } });
      expect(tools.run).toHaveBeenCalledWith('list_auth_sessions', { limit: 5 }, [{ id: 'r1' }, { id: 'r2' }], { sessionCount: 2, origin: 'https://portal.azure.com' });
    });

    it('maps typed tool errors to their code and other failures to internal', async () => {
      const tools = { run: jest.fn() };
      const c = makeController(fakeChrome(), { tools });
      await c.enable();
      tools.run.mockRejectedValueOnce(Object.assign(new Error('No session with id x'), { code: 'not_found' }));
      expect(await c.call('get_session_detail', { sessionId: 'x' }, { tab: { id: 1 } })).toEqual({ ok: false, code: 'not_found', error: 'No session with id x' });
      tools.run.mockRejectedValueOnce(new TypeError('boom'));
      expect(await c.call('get_session_detail', { sessionId: 'x' }, { tab: { id: 1 } })).toEqual({ ok: false, code: 'internal', error: 'boom' });
    });

    it('routes runtime messages through handleMessage', async () => {
      const c = makeController(fakeChrome());
      expect((await c.handleMessage({ action: ACTIONS.STATUS }, {})).status.phase).toBe('idle');
      expect((await c.handleMessage({ action: ACTIONS.ENABLE }, {})).ok).toBe(true);
      expect((await c.handleMessage({ action: ACTIONS.CALL, tool: 'list_auth_sessions', args: {} }, { tab: { id: 1 } })).ok).toBe(true);
      expect((await c.handleMessage({ action: ACTIONS.DISABLE }, {})).status.phase).toBe('idle');
      expect((await c.handleMessage({ action: 'webmcp:bogus' }, {})).ok).toBe(false);
    });
  });

  describe('notifySessionsChanged', () => {
    it('debounces description refreshes into one message while armed', async () => {
      jest.useFakeTimers();
      const chromeApi = fakeChrome();
      const c = makeController(chromeApi);
      await c.enable();
      const before = chromeApi.tabs.sendMessage.mock.calls.length;
      c.notifySessionsChanged();
      c.notifySessionsChanged();
      c.notifySessionsChanged();
      await jest.advanceTimersByTimeAsync(TIMEOUTS.REFRESH_DEBOUNCE_MS + 10);
      const refreshes = chromeApi.tabs.sendMessage.mock.calls.slice(before).filter(([, m]) => m.action === ACTIONS.REFRESH);
      expect(refreshes).toHaveLength(1);
      expect(refreshes[0][1].manifest[0].description).toContain('2 auth sessions captured');
    });

    it('does nothing when idle', () => {
      jest.useFakeTimers();
      const chromeApi = fakeChrome();
      const c = makeController(chromeApi);
      c.notifySessionsChanged();
      jest.advanceTimersByTime(TIMEOUTS.REFRESH_DEBOUNCE_MS + 10);
      expect(chromeApi.tabs.sendMessage).not.toHaveBeenCalled();
    });

    it('records a refresh failure without disarming', async () => {
      jest.useFakeTimers();
      let armedOnce = false;
      const chromeApi = fakeChrome({
        bridge: async (tabId, msg) => {
          if (msg.action === ACTIONS.INIT) { armedOnce = true; return { ok: true, supported: true, toolCount: 6, api: 'document' }; }
          if (msg.action === ACTIONS.REFRESH && armedOnce) throw new Error('Receiving end does not exist');
          return { ok: true, tornDown: true };
        }
      });
      const c = makeController(chromeApi);
      await c.enable();
      c.notifySessionsChanged();
      await jest.advanceTimersByTimeAsync(TIMEOUTS.REFRESH_DEBOUNCE_MS + 10);
      expect(c.status().phase).toBe('armed');
      expect(c.status().lastError).toMatch(/Could not refresh tool descriptions/);
    });
  });
});
