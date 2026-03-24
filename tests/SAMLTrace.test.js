/**
 * Tests for SAMLTrace
 *
 * Tests cover the analysis and utility methods that do not require live
 * Chrome webRequest callbacks to fire.  The Chrome API stubs in setup.js
 * prevent real network listeners from being registered.
 */

// We need access to the SAMLTrace CLASS for testing, not the singleton.
// Since the module exports only the singleton we drive it through the class
// by creating a fresh instance using the module under test's internal class.
// The simplest approach: import the default singleton after mocking Chrome.

import samltrace from '../src/SAMLTrace.js';
import Fido2Decoder from '../src/Fido2Decoder.js';

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Build a minimal extensionState object for test isolation */
function makeState(overrides = {}) {
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

/** Build a minimal webRequest details object */
function makeDetails(url, method = 'GET', extras = {}) {
  return {
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

// ─── Test suites ─────────────────────────────────────────────────────────────

describe('SAMLTrace', () => {
  describe('generateRequestId', () => {
    it('should generate unique IDs', () => {
      const id1 = samltrace.generateRequestId();
      const id2 = samltrace.generateRequestId();
      expect(id1).toMatch(/^req_/);
      expect(id2).toMatch(/^req_/);
      expect(id1).not.toBe(id2);
    });
  });

  describe('getState', () => {
    it('should return the current state object', () => {
      const state = makeState({ requests: [{ id: 'r1' }] });
      samltrace.state = state;
      expect(samltrace.getState()).toBe(state);
    });
  });

  describe('getFido2Type', () => {
    it('should describe assertion as Authentication', () => {
      expect(samltrace.getFido2Type('fido2_assertion')).toBe('Authentication (Assertion)');
    });

    it('should describe attestation as Registration', () => {
      expect(samltrace.getFido2Type('fido2_attestation')).toBe('Registration (Attestation)');
    });

    it('should describe preflight correctly', () => {
      expect(samltrace.getFido2Type('fido2_preflight')).toBe('Pre-flight Check');
    });

    it('should return Unknown for unrecognised type', () => {
      expect(samltrace.getFido2Type('something_else')).toBe('Unknown FIDO2 Flow');
    });
  });

  describe('isAuthenticationRequest', () => {
    beforeEach(() => {
      samltrace.state = makeState();
    });

    it('should match login.microsoftonline.com', () => {
      const url = new URL('https://login.microsoftonline.com/common/oauth2/v2.0/token');
      expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href, 'POST'))).toBe(true);
    });

    it('should match sts.windows.net', () => {
      const url = new URL('https://sts.windows.net/tenant/oauth2/token');
      expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href))).toBe(true);
    });

    it('should match login.live.com', () => {
      const url = new URL('https://login.live.com/oauth20_token.srf');
      expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href))).toBe(true);
    });

    it('should match /oauth2 path pattern', () => {
      const url = new URL('https://example.com/oauth2/token');
      expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href))).toBe(true);
    });

    it('should match /authorize path pattern', () => {
      const url = new URL('https://example.com/authorize?client_id=x');
      expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href))).toBe(true);
    });

    it('should match SAML POST body', () => {
      const url = new URL('https://example.com/acs');
      const details = makeDetails(url.href, 'POST', {
        requestBody: { formData: { SAMLResponse: ['base64data'] } }
      });
      expect(samltrace.isAuthenticationRequest(url, details)).toBe(true);
    });

    it('should match WS-Fed wresult POST body', () => {
      const url = new URL('https://example.com/acs');
      const details = makeDetails(url.href, 'POST', {
        requestBody: { formData: { wresult: ['xml'] } }
      });
      expect(samltrace.isAuthenticationRequest(url, details)).toBe(true);
    });

    it('should match /assertion FIDO2 path', () => {
      const url = new URL('https://example.com/webauthn/assertion');
      expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href, 'POST'))).toBe(true);
    });

    it('should return false for an unrelated URL', () => {
      const url = new URL('https://www.google.com/search?q=test');
      expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href))).toBe(false);
    });
  });

  describe('detectFlowType', () => {
    beforeEach(() => {
      samltrace.state = makeState();
    });

    function detect(urlStr, method = 'GET', requestBody = null) {
      const url = new URL(urlStr);
      return samltrace.detectFlowType(url, makeDetails(urlStr, method, { requestBody }));
    }

    it('should detect SAML from query parameter', () => {
      expect(detect('https://idp.example.com/sso?SAMLRequest=abc')).toBe('saml');
    });

    it('should detect SAML response from query parameter', () => {
      expect(detect('https://sp.example.com/acs?SAMLResponse=base64')).toBe('saml');
    });

    it('should detect WS-Fed from wresult query param', () => {
      expect(detect('https://sp.example.com/acs?wresult=xml&wctx=ctx')).toBe('wsfed');
    });

    it('should detect saml from path', () => {
      expect(detect('https://idp.example.com/saml2/sso')).toBe('saml');
    });

    it('should detect FIDO2 assertion', () => {
      expect(detect('https://example.com/webauthn/assertion', 'POST')).toBe('fido2_assertion');
    });

    it('should detect FIDO2 attestation', () => {
      expect(detect('https://example.com/webauthn/attestation', 'POST')).toBe('fido2_attestation');
    });

    it('should detect device code initiation', () => {
      expect(detect('https://login.microsoftonline.com/common/oauth2/v2.0/devicecode', 'POST')).toBe('device_code_initiation');
    });

    it('should detect PKCE authorize from code_challenge param', () => {
      expect(detect('https://login.microsoftonline.com/common/oauth2/v2.0/authorize?code_challenge=abc&code_challenge_method=S256')).toBe('pkce_flow');
    });

    it('should detect generic oauth authorize without PKCE', () => {
      expect(detect('https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=x')).toBe('oauth_authorize');
    });

    it('should detect client credentials from POST body', () => {
      const rb = { formData: { grant_type: ['client_credentials'], client_id: ['x'], client_secret: ['s'] } };
      expect(detect('https://login.microsoftonline.com/common/oauth2/v2.0/token', 'POST', rb)).toBe('client_credentials');
    });

    it('should detect generic token endpoint as oauth_token fallback', () => {
      // No body provided → falls through to generic token fallback
      expect(detect('https://login.microsoftonline.com/common/oauth2/v2.0/token', 'POST')).toBe('oauth_token');
    });
  });

  describe('extractRequestBody', () => {
    it('should extract formData body', () => {
      const requestBody = { formData: { grant_type: ['authorization_code'], code: ['abc123'] } };
      const result = samltrace.extractRequestBody(requestBody);
      expect(result.type).toBe('formData');
      expect(result.data.grant_type).toEqual(['authorization_code']);
    });

    it('should parse raw JSON body', () => {
      const json = JSON.stringify({ clientDataJSON: 'abc', type: 'webauthn.get' });
      // Build raw bytes via Buffer (available in Node.js test env)
      const bytes = Buffer.from(json, 'utf-8');
      const requestBody = { raw: [{ bytes }] };
      const result = samltrace.extractRequestBody(requestBody);
      expect(result.type).toBe('json');
      expect(result.data.type).toBe('webauthn.get');
      expect(result.raw).toBe(json);
    });

    it('should return raw type for non-JSON text body', () => {
      const text = 'plain text body, not json';
      const bytes = Buffer.from(text, 'utf-8');
      const requestBody = { raw: [{ bytes }] };
      const result = samltrace.extractRequestBody(requestBody);
      expect(result.type).toBe('raw');
      expect(result.data).toBe(text);
    });

    it('should return null for null requestBody', () => {
      expect(samltrace.extractRequestBody(null)).toBeNull();
    });
  });

  describe('peekRequestBody', () => {
    it('should return null for null input', () => {
      expect(samltrace.peekRequestBody(null)).toBeNull();
    });

    it('should return formData peek for formData body', () => {
      const rb = { formData: { client_id: ['myapp'] } };
      const result = samltrace.peekRequestBody(rb);
      expect(result.type).toBe('formData');
      expect(result.data.client_id).toEqual(['myapp']);
    });

    it('should return JSON peek for raw JSON bytes', () => {
      const json = JSON.stringify({ grant_type: 'client_credentials' });
      const bytes = Buffer.from(json, 'utf-8');
      const rb = { raw: [{ bytes }] };
      const result = samltrace.peekRequestBody(rb);
      expect(result.type).toBe('json');
      expect(result.data.grant_type).toBe('client_credentials');
    });

    it('should return null when raw bytes are not valid JSON', () => {
      const bytes = Buffer.from('not json', 'utf-8');
      const rb = { raw: [{ bytes }] };
      const result = samltrace.peekRequestBody(rb);
      expect(result).toBeNull();
    });
  });

  describe('findRequest', () => {
    it('should find a matching request by URL, method, and approximate timestamp', () => {
      const now = Date.now();
      const state = makeState({ requests: [{ id: 'r1', url: 'https://example.com/token', method: 'POST', timestamp: now }] });
      samltrace.state = state;
      const details = { url: 'https://example.com/token', method: 'POST', timeStamp: now + 100 };
      expect(samltrace.findRequest(details)).toBeDefined();
      expect(samltrace.findRequest(details).id).toBe('r1');
    });

    it('should not find a request with a different URL', () => {
      const now = Date.now();
      const state = makeState({ requests: [{ id: 'r1', url: 'https://example.com/token', method: 'POST', timestamp: now }] });
      samltrace.state = state;
      const details = { url: 'https://other.example.com/token', method: 'POST', timeStamp: now };
      expect(samltrace.findRequest(details)).toBeUndefined();
    });

    it('should not find a request outside the 1-second time window', () => {
      const now = Date.now();
      const state = makeState({ requests: [{ id: 'r1', url: 'https://example.com/token', method: 'POST', timestamp: now - 5000 }] });
      samltrace.state = state;
      const details = { url: 'https://example.com/token', method: 'POST', timeStamp: now };
      expect(samltrace.findRequest(details)).toBeUndefined();
    });
  });

  describe('handleBeforeRequest – request capture', () => {
    it('should store an auth request and call onNewAuthRequest callback', () => {
      const state = makeState();
      samltrace.state = state;
      const details = makeDetails('https://login.microsoftonline.com/common/oauth2/v2.0/token', 'POST', {
        requestBody: { formData: { grant_type: ['client_credentials'], client_id: ['x'], client_secret: ['s'] } }
      });
      samltrace.handleBeforeRequest(details);
      expect(state.requests).toHaveLength(1);
      expect(state.onNewAuthRequest).toHaveBeenCalled();
    });

    it('should ignore non-auth requests', () => {
      const state = makeState();
      samltrace.state = state;
      const details = makeDetails('https://www.google.com/search?q=hello', 'GET');
      samltrace.handleBeforeRequest(details);
      expect(state.requests).toHaveLength(0);
    });

    it('should not throw externally when state is null (error is caught internally)', () => {
      samltrace.state = null;
      // handleBeforeRequest catches errors internally and logs them; it must not throw
      let threw = false;
      try {
        samltrace.handleBeforeRequest(makeDetails('https://login.microsoftonline.com/token'));
      } catch {
        threw = true;
      }
      expect(threw).toBe(false);
    });
  });

  // ─── initialize / startListening / stopListening ─────────────────────────

  describe('initialize and startListening/stopListening', () => {
    beforeEach(() => {
      samltrace.isListening = false;
    });

    it('should register all webRequest listeners on initialize', () => {
      samltrace.initialize(makeState());
      expect(chrome.webRequest.onBeforeRequest.addListener).toHaveBeenCalled();
      expect(chrome.webRequest.onBeforeSendHeaders.addListener).toHaveBeenCalled();
      expect(chrome.webRequest.onHeadersReceived.addListener).toHaveBeenCalled();
      expect(chrome.webRequest.onCompleted.addListener).toHaveBeenCalled();
      expect(chrome.webRequest.onErrorOccurred.addListener).toHaveBeenCalled();
      expect(samltrace.isListening).toBe(true);
    });

    it('should skip registration when already listening', () => {
      samltrace.isListening = true;
      chrome.webRequest.onBeforeRequest.addListener.mockClear();
      samltrace.startListening();
      expect(chrome.webRequest.onBeforeRequest.addListener).not.toHaveBeenCalled();
    });

    it('should remove all webRequest listeners on stopListening', () => {
      samltrace.isListening = true;
      samltrace.stopListening();
      expect(chrome.webRequest.onBeforeRequest.removeListener).toHaveBeenCalled();
      expect(chrome.webRequest.onBeforeSendHeaders.removeListener).toHaveBeenCalled();
      expect(chrome.webRequest.onHeadersReceived.removeListener).toHaveBeenCalled();
      expect(chrome.webRequest.onCompleted.removeListener).toHaveBeenCalled();
      expect(chrome.webRequest.onErrorOccurred.removeListener).toHaveBeenCalled();
      expect(samltrace.isListening).toBe(false);
    });

    it('should skip removal when not listening', () => {
      samltrace.isListening = false;
      chrome.webRequest.onBeforeRequest.removeListener.mockClear();
      samltrace.stopListening();
      expect(chrome.webRequest.onBeforeRequest.removeListener).not.toHaveBeenCalled();
    });
  });

  // ─── handleFlowSpecifics ─────────────────────────────────────────────────

  describe('handleFlowSpecifics', () => {
    it('should call handleFido2Request for fido2_assertion', () => {
      samltrace.state = makeState();
      const spy = jest.spyOn(samltrace, 'handleFido2Request').mockImplementation(() => {});
      samltrace.handleFlowSpecifics({ flowType: 'fido2_assertion', requestBody: null });
      expect(spy).toHaveBeenCalled();
      spy.mockRestore();
    });

    it('should call handleFido2Request for fido2_attestation', () => {
      samltrace.state = makeState();
      const spy = jest.spyOn(samltrace, 'handleFido2Request').mockImplementation(() => {});
      samltrace.handleFlowSpecifics({ flowType: 'fido2_attestation', requestBody: null });
      expect(spy).toHaveBeenCalled();
      spy.mockRestore();
    });

    it('should call both handleDeviceCodeRequest and handleOAuthRequest for device_code_initiation', () => {
      samltrace.state = makeState();
      const deviceSpy = jest.spyOn(samltrace, 'handleDeviceCodeRequest').mockImplementation(() => {});
      const oauthSpy = jest.spyOn(samltrace, 'handleOAuthRequest').mockImplementation(() => {});
      samltrace.handleFlowSpecifics({ flowType: 'device_code_initiation', requestBody: null, id: 'r1', timestamp: Date.now() });
      expect(deviceSpy).toHaveBeenCalled();
      expect(oauthSpy).toHaveBeenCalled();
      deviceSpy.mockRestore();
      oauthSpy.mockRestore();
    });

    it('should call handleOAuthRequest for oauth_token', () => {
      samltrace.state = makeState();
      const spy = jest.spyOn(samltrace, 'handleOAuthRequest').mockImplementation(() => {});
      samltrace.handleFlowSpecifics({ flowType: 'oauth_token', requestBody: null });
      expect(spy).toHaveBeenCalled();
      spy.mockRestore();
    });
  });

  // ─── handleOAuthRequest ───────────────────────────────────────────────────

  describe('handleOAuthRequest', () => {
    it('should attach oauthAnalysis to requestData on success', () => {
      samltrace.state = makeState();
      const requestData = {
        id: 'r1',
        url: 'https://login.microsoftonline.com/tenant/oauth2/v2.0/token',
        method: 'POST',
        flowType: 'client_credentials',
        requestBody: {
          type: 'formData',
          data: { grant_type: ['client_credentials'], client_id: ['app'], client_secret: ['s'] }
        }
      };
      samltrace.handleOAuthRequest(requestData);
      expect(requestData).toHaveProperty('oauthAnalysis');
    });

    it('should attach error oauthAnalysis when OAuthDecoder throws', () => {
      samltrace.state = makeState();
      // Provide broken data that cannot be analysed and force a thrown error
      const requestData = { flowType: 'oauth_token', requestBody: null, url: null, method: null };
      // This should not throw — the internal try/catch handles it
      expect(() => samltrace.handleOAuthRequest(requestData)).not.toThrow();
      expect(requestData).toHaveProperty('oauthAnalysis');
    });
  });

  // ─── handleFido2Request ───────────────────────────────────────────────────

  describe('handleFido2Request', () => {
    afterEach(() => jest.restoreAllMocks());

    it('should return early (no-op) when requestBody is null', () => {
      samltrace.state = makeState();
      const requestData = { flowType: 'fido2_assertion', requestBody: null };
      expect(() => samltrace.handleFido2Request(requestData)).not.toThrow();
      expect(requestData.fido2Analysis).toBeUndefined();
    });

    it('should return early when requestBody type is not json', () => {
      samltrace.state = makeState();
      const requestData = { flowType: 'fido2_assertion', requestBody: { type: 'formData', data: {} } };
      expect(() => samltrace.handleFido2Request(requestData)).not.toThrow();
      expect(requestData.fido2Analysis).toBeUndefined();
    });

    it('should attach fido2Analysis and push to fido2Sessions on successful decode', () => {
      samltrace.state = makeState();
      jest.spyOn(Fido2Decoder, 'decodeFido2Request').mockReturnValue({
        clientDataJSON: { type: 'webauthn.get' },
        authenticatorData: { rpIdHash: 'abc' }
      });
      const requestData = {
        id: 'r1',
        timestamp: Date.now(),
        flowType: 'fido2_assertion',
        requestBody: { type: 'json', data: { clientDataJSON: 'abc', authenticatorData: 'def' } }
      };
      samltrace.handleFido2Request(requestData);
      expect(requestData.fido2Analysis).toBeDefined();
      expect(samltrace.state.fido2Sessions).toHaveLength(1);
    });

    it('should not set fido2Analysis when decoder returns an error object', () => {
      samltrace.state = makeState();
      jest.spyOn(Fido2Decoder, 'decodeFido2Request').mockReturnValue({ error: 'decode failed' });
      const requestData = {
        id: 'r1',
        timestamp: Date.now(),
        flowType: 'fido2_assertion',
        requestBody: { type: 'json', data: {} }
      };
      samltrace.handleFido2Request(requestData);
      expect(requestData.fido2Analysis).toBeUndefined();
    });

    it('should attach error fido2Analysis when Fido2Decoder throws', () => {
      samltrace.state = makeState();
      jest.spyOn(Fido2Decoder, 'decodeFido2Request').mockImplementation(() => {
        throw new Error('CBOR parse error');
      });
      const requestData = {
        id: 'r1',
        timestamp: Date.now(),
        flowType: 'fido2_assertion',
        requestBody: { type: 'json', data: {} }
      };
      samltrace.handleFido2Request(requestData);
      expect(requestData.fido2Analysis).toBeDefined();
      expect(requestData.fido2Analysis.error).toMatch(/FIDO2 processing failed/);
    });
  });

  // ─── handleDeviceCodeRequest ──────────────────────────────────────────────

  describe('handleDeviceCodeRequest', () => {
    it('should track device_code_initiation with correlation key', () => {
      const state = makeState();
      samltrace.state = state;
      const requestData = {
        id: 'r1',
        timestamp: Date.now(),
        flowType: 'device_code_initiation',
        requestBody: { type: 'formData', data: { client_id: ['myapp'], scope: ['openid'] } }
      };
      samltrace.handleDeviceCodeRequest(requestData);
      expect(requestData.deviceCodeCorrelationKey).toMatch(/^init:myapp:/);
      expect(state.deviceCodeCorrelation.size).toBe(1);
    });

    it('should use "unknown" client_id when requestBody is null at initiation', () => {
      const state = makeState();
      samltrace.state = state;
      const requestData = { id: 'r1', timestamp: Date.now(), flowType: 'device_code_initiation', requestBody: null };
      samltrace.handleDeviceCodeRequest(requestData);
      expect(requestData.deviceCodeCorrelationKey).toMatch(/^init:unknown:/);
    });

    it('should correlate device_code_poll with an existing key', () => {
      const state = makeState();
      samltrace.state = state;
      const dc = 'device-code-abc';
      state.deviceCodeCorrelation.set(`poll:${dc}`, ['r0']);
      const requestData = {
        id: 'r2',
        flowType: 'device_code_poll',
        requestBody: { type: 'formData', data: { device_code: [dc], grant_type: ['urn:ietf:params:oauth:grant-type:device_code'] } }
      };
      samltrace.handleDeviceCodeRequest(requestData);
      expect(state.deviceCodeCorrelation.get(`poll:${dc}`)).toContain('r2');
    });

    it('should create a new poll correlation entry when first poll', () => {
      const state = makeState();
      samltrace.state = state;
      const requestData = {
        id: 'r2',
        flowType: 'device_code_poll',
        requestBody: { type: 'formData', data: { device_code: ['dc_new'], grant_type: ['urn:ietf:params:oauth:grant-type:device_code'] } }
      };
      samltrace.handleDeviceCodeRequest(requestData);
      expect(state.deviceCodeCorrelation.has('poll:dc_new')).toBe(true);
      expect(state.deviceCodeCorrelation.get('poll:dc_new')).toEqual(['r2']);
    });

    it('should skip poll correlation when no device_code in body', () => {
      const state = makeState();
      samltrace.state = state;
      const requestData = { id: 'r2', flowType: 'device_code_poll', requestBody: null };
      samltrace.handleDeviceCodeRequest(requestData);
      expect(state.deviceCodeCorrelation.size).toBe(0);
    });
  });

  // ─── handleBeforeSendHeaders ──────────────────────────────────────────────

  describe('handleBeforeSendHeaders', () => {
    it('should update requestHeaders on a matching request', () => {
      const now = Date.now();
      const state = makeState({
        requests: [{ id: 'r1', url: 'https://login.microsoftonline.com/token', method: 'POST', timestamp: now, requestHeaders: [] }]
      });
      samltrace.state = state;
      samltrace.handleBeforeSendHeaders({
        url: 'https://login.microsoftonline.com/token',
        method: 'POST',
        timeStamp: now + 50,
        requestHeaders: [{ name: 'Authorization', value: 'Bearer tok' }]
      });
      expect(state.requests[0].requestHeaders[0].name).toBe('Authorization');
    });

    it('should return {} and not throw when no matching request', () => {
      samltrace.state = makeState();
      const result = samltrace.handleBeforeSendHeaders({
        url: 'https://example.com/other',
        method: 'GET',
        timeStamp: Date.now(),
        requestHeaders: []
      });
      expect(result).toEqual({});
    });
  });

  // ─── handleHeadersReceived ────────────────────────────────────────────────

  describe('handleHeadersReceived', () => {
    it('should update responseHeaders and statusCode on matching request', () => {
      const now = Date.now();
      const state = makeState({
        requests: [{ id: 'r1', url: 'https://login.microsoftonline.com/token', method: 'POST', timestamp: now }]
      });
      samltrace.state = state;
      samltrace.handleHeadersReceived({
        url: 'https://login.microsoftonline.com/token',
        method: 'POST',
        timeStamp: now + 50,
        responseHeaders: [{ name: 'Content-Type', value: 'application/json' }],
        statusCode: 200
      });
      expect(state.requests[0].responseHeaders).toHaveLength(1);
      expect(state.requests[0].statusCode).toBe(200);
    });

    it('should return {} and not throw when no matching request', () => {
      samltrace.state = makeState();
      const result = samltrace.handleHeadersReceived({
        url: 'https://other.example.com/',
        method: 'GET',
        timeStamp: Date.now(),
        responseHeaders: [],
        statusCode: 200
      });
      expect(result).toEqual({});
    });
  });

  // ─── handleCompleted ──────────────────────────────────────────────────────

  describe('handleCompleted', () => {
    it('should mark request as completed with statusCode', () => {
      const now = Date.now();
      const state = makeState({
        requests: [{ id: 'r1', url: 'https://login.microsoftonline.com/token', method: 'POST', timestamp: now, status: 'pending' }]
      });
      samltrace.state = state;
      samltrace.handleCompleted({
        url: 'https://login.microsoftonline.com/token',
        method: 'POST',
        timeStamp: now + 50,
        statusCode: 200
      });
      expect(state.requests[0].status).toBe('completed');
      expect(state.requests[0].statusCode).toBe(200);
    });

    it('should not throw when no matching request', () => {
      samltrace.state = makeState();
      expect(() => samltrace.handleCompleted({ url: 'https://other.com/', method: 'GET', timeStamp: Date.now(), statusCode: 404 })).not.toThrow();
    });
  });

  // ─── handleError ──────────────────────────────────────────────────────────

  describe('handleError', () => {
    it('should mark request as error with error message', () => {
      const now = Date.now();
      const state = makeState({
        requests: [{ id: 'r1', url: 'https://login.microsoftonline.com/token', method: 'POST', timestamp: now, status: 'pending' }]
      });
      samltrace.state = state;
      samltrace.handleError({
        url: 'https://login.microsoftonline.com/token',
        method: 'POST',
        timeStamp: now + 50,
        error: 'net::ERR_ABORTED'
      });
      expect(state.requests[0].status).toBe('error');
      expect(state.requests[0].error).toBe('net::ERR_ABORTED');
    });

    it('should not throw when no matching request', () => {
      samltrace.state = makeState();
      expect(() => samltrace.handleError({ url: 'https://other.com/', method: 'GET', timeStamp: Date.now(), error: 'net::ERR_FAILED' })).not.toThrow();
    });
  });
});
