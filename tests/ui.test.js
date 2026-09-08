/**
 * Smoke tests for the popup UI (EntraAuthTracerUI) under jsdom.
 *
 * The real ui.html markup is loaded, chrome.runtime.sendMessage is stubbed to
 * return fixtures for getState, and the class is instantiated exactly as the
 * bootstrap does. These tests pin the user-visible behaviours that the pure
 * modules cannot cover on their own: rendering, filtering, view modes, the
 * detail panel, popout mode, splitter persistence and export wiring.
 */

import fs from 'fs';
import path from 'path';
import EntraAuthTracerUI from '../src/ui.js';
import Exporters from '../src/Exporters.js';
import { makeRequest } from './helpers.js';

const HTML = fs.readFileSync(path.join(__dirname, '../src/ui.html'), 'utf8');
const BODY = HTML.match(/<body>([\s\S]*)<\/body>/)[1].replace(/<script[^>]*><\/script>/g, '');

const T0 = 1_700_000_000_000;

function fixtures() {
  return [
    makeRequest('https://adfs.contoso.com/adfs/ls/?client-request-id=1', { id: 'r-saml', flowType: 'adfs_saml', timestamp: T0, status: 'completed', statusCode: 200 }),
    makeRequest('https://auth.example.com/.well-known/openid-configuration', { id: 'r-oidc', flowType: 'oidc_discovery', timestamp: T0 + 1000, status: 'completed', statusCode: 200 }),
    makeRequest('https://resolver.identity.foundation/1.0/identifiers/did:web:contoso.com', { id: 'r-did', flowType: 'did_resolution', timestamp: T0 + 2000, status: 'pending' })
  ];
}

function oauthFlowFixtures() {
  return [
    makeRequest('https://login.microsoftonline.com/t/oauth2/v2.0/authorize?client_id=app&response_type=code&state=s', {
      id: 'o-authz', flowType: 'pkce_flow', timestamp: T0, status: 'completed', statusCode: 302,
      oauthAnalysis: { clientId: 'app', label: 'Authorization Code + PKCE', grantType: 'authorization_code_pkce', requestType: 'authorization_request', warnings: [] }
    }),
    makeRequest('https://login.microsoftonline.com/t/oauth2/v2.0/token', {
      id: 'o-token', flowType: 'pkce_token_exchange', timestamp: T0 + 4000, status: 'completed', statusCode: 200,
      formData: { grant_type: 'authorization_code', client_id: 'app', code: 'c', code_verifier: 'v'.repeat(43), client_secret: 'top-secret' },
      requestHeaders: [{ name: 'Authorization', value: 'Basic ' + btoa('app:top-secret') }],
      oauthAnalysis: { clientId: 'app', label: 'Authorization Code + PKCE (Token Exchange)', grantType: 'authorization_code_pkce', requestType: 'token_request', warnings: [] }
    })
  ];
}

let state;

function installChromeMock(requests) {
  state = { requests };
  chrome.runtime.sendMessage.mockImplementation((msg, cb) => {
    if (msg.action === 'getState') { if (cb) cb({ requests: state.requests, deviceCodeCorrelation: {}, fido2Sessions: [], isActive: true }); }
    else if (msg.action === 'clearData') { state.requests = []; if (cb) cb({ success: true }); }
    else if (cb) cb({ success: true });
  });
}

async function flush() {
  for (let i = 0; i < 6; i++) await Promise.resolve();
}

async function mount(requests = [], { query = '' } = {}) {
  window.history.replaceState({}, '', '/src/ui.html' + query);
  document.documentElement.className = '';
  document.documentElement.removeAttribute('style');
  document.body.innerHTML = BODY;
  installChromeMock(requests);
  const ui = new EntraAuthTracerUI();
  await flush();
  return ui;
}

function dispatch(el, type) {
  el.dispatchEvent(new window.Event(type, { bubbles: true }));
}

describe('EntraAuthTracerUI (popup smoke tests)', () => {
  beforeEach(() => {
    jest.useFakeTimers();
    jest.clearAllMocks();
    localStorage.clear();
    window.alert = jest.fn();
  });

  afterEach(() => {
    jest.useRealTimers();
    document.head.querySelectorAll('style[data-test]').forEach(s => s.remove());
  });

  it('renders the empty state, the footer version/link, and resets the badge on open', async () => {
    await mount([]);
    expect(document.querySelector('#requestList .no-requests')).not.toBeNull();
    const footer = document.getElementById('versionInfo');
    expect(footer.textContent).toContain('v1.1.0-test');
    expect(footer.querySelector('a[href="https://github.com/darrenjrobinson/EntraAuthTracer"]')).not.toBeNull();
    expect(chrome.runtime.sendMessage).toHaveBeenCalledWith({ action: 'resetBadge' });
    expect(document.getElementById('requestCount').textContent).toBe('0 requests');
    expect(document.getElementById('statusText').textContent).toBe('Ready');
  });

  it('shows every category in the status bar breakdown, including Verified ID', async () => {
    await mount(fixtures());
    expect(document.getElementById('requestCount').textContent).toBe('3 req · SAML: 1, OAuth: 1, Verified ID: 1');
    expect(document.getElementById('statusText').textContent).toBe('Capturing');
  });

  it('polls the background every second and re-renders new captures', async () => {
    await mount([]);
    expect(document.querySelectorAll('[data-request-id]')).toHaveLength(0);
    state.requests = fixtures();
    jest.advanceTimersByTime(1000);
    await flush();
    expect(document.querySelectorAll('[data-request-id]')).toHaveLength(3);
  });

  it('filters OIDC discovery under OAuth and ADFS under SAML via the flow dropdown', async () => {
    await mount(fixtures());
    const select = document.getElementById('flowFilter');
    const ids = () => Array.from(document.querySelectorAll('[data-request-id]')).map(el => el.dataset.requestId);

    select.value = 'oauth'; dispatch(select, 'change');
    expect(ids()).toEqual(['r-oidc']);

    select.value = 'saml'; dispatch(select, 'change');
    expect(ids()).toEqual(['r-saml']);

    select.value = 'did'; dispatch(select, 'change');
    expect(ids()).toEqual(['r-did']);

    select.value = ''; dispatch(select, 'change');
    expect(ids()).toHaveLength(3);
  });

  it('applies the search box and status filter together', async () => {
    await mount(fixtures());
    const search = document.getElementById('searchInput');
    search.value = 'contoso'; dispatch(search, 'input');
    expect(Array.from(document.querySelectorAll('[data-request-id]')).map(el => el.dataset.requestId).sort()).toEqual(['r-did', 'r-saml']);

    const status = document.getElementById('statusFilter');
    status.value = 'pending'; dispatch(status, 'change');
    expect(Array.from(document.querySelectorAll('[data-request-id]')).map(el => el.dataset.requestId)).toEqual(['r-did']);
  });

  it('groups correlated OAuth requests into one timeline flow group', async () => {
    await mount(oauthFlowFixtures());
    const groups = document.querySelectorAll('.flow-group');
    expect(groups).toHaveLength(1);
    expect(groups[0].querySelectorAll('.flow-group-item')).toHaveLength(2);
    expect(groups[0].querySelector('.flow-group-title').textContent).toContain('OAuth Flow');
    expect(groups[0].querySelector('.flow-badge').textContent).toBe('OAUTH');
  });

  it('switches to list view with aria-pressed and column header', async () => {
    await mount(fixtures());
    const listBtn = document.getElementById('viewListBtn');
    const timelineBtn = document.getElementById('viewTimelineBtn');
    expect(timelineBtn.getAttribute('aria-pressed')).toBe('true');

    listBtn.click();
    expect(listBtn.getAttribute('aria-pressed')).toBe('true');
    expect(timelineBtn.getAttribute('aria-pressed')).toBe('false');
    expect(document.querySelectorAll('#requestList > .request-item')).toHaveLength(3);
    expect(document.querySelector('.request-list-header').style.display).toBe('');
    expect(document.querySelector('.timeline-standalone')).toBeNull();

    const badges = Array.from(document.querySelectorAll('.flow-badge')).map(b => b.className);
    expect(badges).toEqual(expect.arrayContaining(['flow-badge flow-saml', 'flow-badge flow-oauth', 'flow-badge flow-did']));
  });

  it('opens the detail panel, escapes body values and shows related requests', async () => {
    const reqs = oauthFlowFixtures();
    reqs[1].requestBody = { type: 'formData', data: { state: ['<img src=x onerror="alert(1)">'], client_id: ['app'] } };
    const ui = await mount(reqs);

    ui.selectRequest(reqs[1]);
    expect(document.getElementById('detailPanel').style.display).toBe('flex');
    expect(document.getElementById('detailTitle').textContent).toBe('POST /t/oauth2/v2.0/token');

    const body = document.getElementById('requestBody');
    expect(body.querySelector('img')).toBeNull();
    expect(body.innerHTML).toContain('&lt;img');

    const related = document.getElementById('relatedRequestsPanel');
    expect(related.style.display).toBe('flex');
    expect(related.querySelectorAll('.related-item')).toHaveLength(2);
    expect(document.querySelector('[data-request-id="o-authz"]').classList.contains('correlated-highlight')).toBe(true);

    document.getElementById('closeDetailBtn').click();
    expect(document.getElementById('detailPanel').style.display).toBe('none');
    expect(document.querySelectorAll('.correlated-highlight')).toHaveLength(0);
  });

  it('redacts secrets in the Parameters tab', async () => {
    const reqs = oauthFlowFixtures();
    const ui = await mount(reqs);
    ui.selectRequest(reqs[1]);
    const body = document.getElementById('requestBody').textContent;
    expect(body).toContain('[REDACTED]');
    expect(body).not.toContain('top-secret');
    expect(body).toContain('client_id');
  });

  it('never renders or copies a raw body that could not be parsed', async () => {
    const reqs = oauthFlowFixtures();
    reqs[1].requestBody = { type: 'raw', data: 'client_secret=s3cret&junk=<img src=x onerror="alert(1)">' };
    const ui = await mount(reqs);
    ui.selectRequest(reqs[1]);
    const body = document.getElementById('requestBody');
    expect(body.querySelector('img')).toBeNull();
    expect(body.textContent).toContain('[REDACTED raw body');
    expect(body.textContent).not.toContain('s3cret');
    expect(document.getElementById('formDataSectionHeader').querySelector('.copy-btn').dataset.copy).not.toContain('s3cret');
  });

  it('redacts query-string credentials everywhere a URL is shown or copied', async () => {
    const leaky = 'https://login.microsoftonline.com/t/oauth2/v2.0/token?client_id=app&client_secret=leak-me';
    const reqs = oauthFlowFixtures();
    reqs[1].url = leaky;
    const ui = await mount(reqs);

    // timeline flow-group row (title attribute on the URL cell)
    const rowTitle = document.querySelector('[data-request-id="o-token"] .fgi-url').getAttribute('title');
    expect(rowTitle).not.toContain('leak-me');
    expect(rowTitle).toContain('client_id=app');

    // list view row: visible text, title and copy button
    document.getElementById('viewListBtn').click();
    const item = document.querySelector('#requestList [data-request-id="o-token"]');
    expect(item.textContent).not.toContain('leak-me');
    expect(item.querySelector('.col-url').getAttribute('title')).not.toContain('leak-me');
    expect(item.querySelector('.copy-btn').dataset.copy).not.toContain('leak-me');
    expect(item.querySelector('.copy-btn').dataset.copy).toContain('%5BREDACTED%5D');

    // detail header copy button, HTTP tab value and its copy text, related-request chip
    ui.selectRequest(reqs[1]);
    expect(document.getElementById('copyDetailUrlBtn').dataset.copy).not.toContain('leak-me');
    expect(document.getElementById('requestDetails').textContent).not.toContain('leak-me');
    expect(document.getElementById('requestDetails').textContent).toContain('client_secret=%5BREDACTED%5D');
    expect(document.getElementById('requestSectionHeader').querySelector('.copy-btn').dataset.copy).not.toContain('leak-me');
    const chip = document.querySelector('#relatedRequestsList .related-current');
    expect(chip.getAttribute('title')).not.toContain('leak-me');

    // nothing in the whole popup DOM carries the secret
    expect(document.getElementById('app').innerHTML).not.toContain('leak-me');
  });

  it('hides the popout button and resize handle when running as a popout window', async () => {
    await mount([], { query: '?popout=true' });
    expect(document.documentElement.classList.contains('popout-mode')).toBe(true);
    expect(document.getElementById('popoutBtn').style.display).toBe('none');
    expect(document.getElementById('resizeHandle').style.display).toBe('none');
  });

  it('opens a popout window via chrome.windows.create', async () => {
    await mount([]);
    document.getElementById('popoutBtn').click();
    expect(chrome.windows.create).toHaveBeenCalledWith(expect.objectContaining({
      url: 'chrome-extension://test-extension-id/src/ui.html?popout=true',
      type: 'popup'
    }));
  });

  it('restores the split size for the active layout axis only', async () => {
    const style = document.createElement('style');
    style.setAttribute('data-test', '1');
    style.textContent = '.main-content { display: flex; flex-direction: row; }';
    document.head.appendChild(style);
    localStorage.setItem('entraTracerSplitW', '420');
    localStorage.setItem('entraTracerSplitH', '150');

    const reqs = fixtures();
    const ui = await mount(reqs);
    const list = document.querySelector('.request-list-container');

    ui.selectRequest(reqs[0]);
    expect(list.style.width).toBe('420px');
    expect(list.style.height).toBe('');

    style.textContent = '.main-content { display: flex; flex-direction: column; }';
    ui.closeDetailPanel();
    ui.selectRequest(reqs[1]);
    expect(list.style.height).toBe('150px');
    expect(list.style.width).toBe('');
  });

  it('exports JSON with the manifest version and redacted credentials', async () => {
    const ui = await mount(oauthFlowFixtures());
    const spy = jest.spyOn(ui, 'downloadFile').mockImplementation(() => {});
    ui.doExport('json');
    expect(spy).toHaveBeenCalledTimes(1);
    const [content, filename, mime] = spy.mock.calls[0];
    expect(filename).toMatch(/^entra-auth-trace_.*\.json$/);
    expect(mime).toBe(Exporters.MIME.json);
    const data = JSON.parse(content);
    expect(data.export_metadata.extension_version).toBe('1.1.0-test');
    expect(data.requests[1].request_headers[0].value).toBe('Basic [REDACTED]');
    expect(content).not.toContain('top-secret');
  });

  it('refuses to export when nothing is captured and ignores unknown formats', async () => {
    const ui = await mount([]);
    const spy = jest.spyOn(ui, 'downloadFile').mockImplementation(() => {});
    ui.doExport('json');
    expect(window.alert).toHaveBeenCalled();
    expect(spy).not.toHaveBeenCalled();

    state.requests = fixtures();
    jest.advanceTimersByTime(1000);
    await flush();
    ui.doExport('docx');
    expect(spy).not.toHaveBeenCalled();
  });

  it('clears captures through the background and shows the empty state again', async () => {
    const ui = await mount(fixtures());
    document.getElementById('clearBtn').click();
    await flush();
    expect(chrome.runtime.sendMessage).toHaveBeenCalledWith({ action: 'clearData' }, expect.any(Function));
    expect(ui.currentRequests).toEqual([]);
    expect(document.querySelector('#requestList .no-requests')).not.toBeNull();
  });
});
