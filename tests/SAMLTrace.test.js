/**
 * Tests for SAMLTrace
 *
 * Tests cover the analysis and utility methods that do not require live
 * Chrome webRequest callbacks to fire.  The Chrome API stubs in setup.js
 * prevent real network listeners from being registered.
 */

// The module exports a singleton; the Chrome API stubs in setup.js make its
// module-level listener registration harmless. Every test gets a fresh state
// object (see beforeEach below) so suites cannot leak state into each other.

import samltrace, { MAX_REQUESTS, MAX_FIDO2_SESSIONS, DEVICE_CODE_JOIN_WINDOW_MS } from '../src/SAMLTrace.js';
import Fido2Decoder from '../src/Fido2Decoder.js';
import FlowCorrelator from '../src/FlowCorrelator.js';
import { makeState, makeDetails, captureWebRequestListeners } from './helpers.js';

// ─── Test suites ─────────────────────────────────────────────────────────────

describe('SAMLTrace', () => {
  let savedState;
  beforeEach(() => {
    savedState = samltrace.state;
    samltrace.state = makeState();
  });
  afterEach(() => {
    samltrace.state = savedState;
  });

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

    it('should describe fido2_webauthn as WebAuthn Endpoint', () => {
      expect(samltrace.getFido2Type('fido2_webauthn')).toBe('WebAuthn Endpoint');
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

    it('should match /passkey/ as a standalone path segment', () => {
      const url = new URL('https://example.com/passkey/authenticate');
      expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href, 'POST'))).toBe(true);
    });

    it('should match /passkeys/ as a standalone path segment', () => {
      const url = new URL('https://example.com/passkeys/challenge');
      expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href, 'GET'))).toBe(true);
    });

    it('should NOT false-positive on a repo name containing Passkey (regression)', () => {
      // GitHub repo graph for a repo named "PasskeyProviderAAGUIDs" must NOT be captured
      const url = new URL('https://github.com/darrenjrobinson/PasskeyProviderAAGUIDs/graphs/participation?h=28&type=sparkline&w=155');
      expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href, 'GET'))).toBe(false);
    });

    it('should return false for an unrelated URL', () => {
      const url = new URL('https://www.google.com/search?q=test');
      expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href))).toBe(false);
    });

    // IdentityServer / Duende
    it('should match IdentityServer /connect/token', () => {
      const url = new URL('https://auth.example.com/connect/token');
      expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href, 'POST'))).toBe(true);
    });

    it('should match IdentityServer /connect/authorize', () => {
      const url = new URL('https://auth.example.com/connect/authorize?client_id=x');
      expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href))).toBe(true);
    });

    it('should match IdentityServer /connect/userinfo', () => {
      const url = new URL('https://auth.example.com/connect/userinfo');
      expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href))).toBe(true);
    });

    it('should match IdentityServer /connect/endsession', () => {
      const url = new URL('https://auth.example.com/connect/endsession');
      expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href))).toBe(true);
    });

    it('should match IdentityServer /connect/introspect', () => {
      const url = new URL('https://auth.example.com/connect/introspect');
      expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href, 'POST'))).toBe(true);
    });

    // OIDC discovery
    it('should match OIDC discovery /.well-known/openid-configuration', () => {
      const url = new URL('https://auth.example.com/.well-known/openid-configuration');
      expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href))).toBe(true);
    });

    it('should match JWKS endpoint /.well-known/jwks.json', () => {
      const url = new URL('https://auth.example.com/.well-known/jwks.json');
      expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href))).toBe(true);
    });

    it('should match OAuth authorization server metadata /.well-known/oauth-authorization-server', () => {
      const url = new URL('https://auth.example.com/.well-known/oauth-authorization-server');
      expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href))).toBe(true);
    });

    // Google / GCP known hostname shortcuts
    it('should match accounts.google.com (hostname shortcut)', () => {
      const url = new URL('https://accounts.google.com/o/oauth2/auth?client_id=x');
      expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href))).toBe(true);
    });

    it('should match oauth2.googleapis.com (GCP token endpoint)', () => {
      const url = new URL('https://oauth2.googleapis.com/token');
      expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href, 'POST'))).toBe(true);
    });

    it('should match securetoken.googleapis.com (Firebase Auth)', () => {
      const url = new URL('https://securetoken.googleapis.com/v1/token?key=AIza');
      expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href, 'POST'))).toBe(true);
    });

    // Okta wildcard domain
    it('should match Okta tenant subdomain (wildcard .okta.com)', () => {
      const url = new URL('https://myorg.okta.com/oauth2/v1/token');
      expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href, 'POST'))).toBe(true);
    });

    it('should match Okta preview tenant (wildcard .oktapreview.com)', () => {
      const url = new URL('https://myorg.oktapreview.com/oauth2/v1/authorize?client_id=x');
      expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href))).toBe(true);
    });

    it('should match Okta Classic /api/v1/authn', () => {
      const url = new URL('https://myorg.okta.com/api/v1/authn');
      expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href, 'POST'))).toBe(true);
    });

    it('should match Okta Identity Engine /idp/idx/', () => {
      const url = new URL('https://myorg.okta.com/idp/idx/introspect');
      expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href, 'POST'))).toBe(true);
    });

    // AWS Cognito wildcard domain
    it('should match AWS Cognito user pool domain (wildcard .amazoncognito.com)', () => {
      const url = new URL('https://mypool.auth.us-east-1.amazoncognito.com/oauth2/token');
      expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href, 'POST'))).toBe(true);
    });

    // Shibboleth SP
    it('should match Shibboleth SP ACS endpoint /Shibboleth.sso/SAML2/POST', () => {
      const url = new URL('https://sp.university.edu/Shibboleth.sso/SAML2/POST');
      expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href, 'POST'))).toBe(true);
    });

    it('should match Shibboleth SP logout endpoint /Shibboleth.sso/Logout', () => {
      const url = new URL('https://sp.university.edu/Shibboleth.sso/Logout');
      expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href))).toBe(true);
    });

    // ADFS on-prem
    it('should match ADFS login service /adfs/ls/', () => {
      const url = new URL('https://adfs.contoso.com/adfs/ls/?client-request-id=x');
      expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href))).toBe(true);
    });

    // SAML Artifact binding
    it('should match SAML artifact binding SAMLart query param', () => {
      const url = new URL('https://sp.example.com/acs?SAMLart=AA4AAMTq');
      expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href))).toBe(true);
    });

    // SAML Enhanced Client Profile
    it('should match SAML ECP endpoint /ECP/', () => {
      const url = new URL('https://idp.example.com/idp/profile/SAML2/SOAP/ECP/');
      expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href, 'POST'))).toBe(true);
    });

    // WS-Fed short path
    it('should match WS-Fed short path /wsfed', () => {
      const url = new URL('https://adfs.contoso.com/adfs/wsfed?wa=wsignin1.0');
      expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href))).toBe(true);
    });

    // FIDO2 explicit path
    it('should match explicit /fido2/ path', () => {
      const url = new URL('https://auth.example.com/fido2/assertion/options');
      expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href, 'POST'))).toBe(true);
    });

    it('should match explicit /fido/ path', () => {
      const url = new URL('https://auth.example.com/fido/assertion');
      expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href, 'POST'))).toBe(true);
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

    it('should detect generic webauthn endpoint as fido2_webauthn', () => {
      // e.g. GitHub /webauthn/challenge — not assertion/attestation/well-known
      expect(detect('https://github.com/webauthn/challenge', 'POST')).toBe('fido2_webauthn');
    });

    it('should detect .well-known/webauthn as fido2_preflight over generic fido2_webauthn', () => {
      expect(detect('https://login.microsoftonline.com/.well-known/webauthn', 'GET')).toBe('fido2_preflight');
    });

    it('should detect OIDC discovery endpoint', () => {
      expect(detect('https://auth.example.com/.well-known/openid-configuration')).toBe('oidc_discovery');
    });

    it('should detect JWKS endpoint as oidc_discovery', () => {
      expect(detect('https://auth.example.com/.well-known/jwks.json')).toBe('oidc_discovery');
    });

    it('should detect Okta Classic /api/v1/authn', () => {
      expect(detect('https://myorg.okta.com/api/v1/authn', 'POST')).toBe('okta_authn');
    });

    it('should detect Okta Identity Engine /idp/idx/', () => {
      expect(detect('https://myorg.okta.com/idp/idx/introspect', 'POST')).toBe('okta_idx');
    });

    it('should detect OIDC userinfo endpoint', () => {
      expect(detect('https://auth.example.com/connect/userinfo')).toBe('oidc_userinfo');
    });

    it('should detect token introspection endpoint', () => {
      expect(detect('https://auth.example.com/connect/introspect', 'POST')).toBe('oidc_introspect');
    });

    it('should detect token revocation endpoint', () => {
      expect(detect('https://auth.example.com/connect/revocation', 'POST')).toBe('oidc_revocation');
    });

    it('should detect RP-initiated logout /connect/endsession', () => {
      expect(detect('https://auth.example.com/connect/endsession')).toBe('oidc_logout');
    });

    it('should detect SAML from SAMLart artifact binding query param', () => {
      expect(detect('https://sp.example.com/acs?SAMLart=AA4AAMTq')).toBe('saml');
    });

    it('should detect Shibboleth SP ACS as saml', () => {
      expect(detect('https://sp.university.edu/Shibboleth.sso/SAML2/POST', 'POST')).toBe('saml');
    });

    it('should detect Shibboleth SP Logout as saml', () => {
      expect(detect('https://sp.university.edu/Shibboleth.sso/Logout')).toBe('saml');
    });

    it('should detect SAML ECP endpoint', () => {
      expect(detect('https://idp.example.com/idp/profile/SAML2/SOAP/ECP/', 'POST')).toBe('saml_ecp');
    });

    it('should detect ADFS login service as adfs_saml', () => {
      expect(detect('https://adfs.contoso.com/adfs/ls/?client-request-id=x')).toBe('adfs_saml');
    });

    it('should detect WS-Fed short /wsfed path', () => {
      expect(detect('https://adfs.contoso.com/adfs/wsfed?wa=wsignin1.0')).toBe('wsfed');
    });

    it('should detect /fido2/assertion/options as fido2_assertion (assertion takes priority)', () => {
      expect(detect('https://auth.example.com/fido2/assertion/options', 'POST')).toBe('fido2_assertion');
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

    it('should swallow internal errors, log them, and still return {} when state is null', () => {
      samltrace.state = null;
      const errSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
      const result = samltrace.handleBeforeRequest(makeDetails('https://login.microsoftonline.com/token'));
      expect(result).toEqual({});
      expect(errSpy).toHaveBeenCalledWith(
        expect.stringContaining('Error in handleBeforeRequest'),
        expect.any(Error)
      );
      errSpy.mockRestore();
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

    it('should attach an error oauthAnalysis when the request cannot be analysed', () => {
      samltrace.state = makeState();
      // A null URL makes OAuthDecoder.analyzeRequest fail — the failure must be
      // captured on the request rather than propagated to the webRequest listener.
      const requestData = { flowType: 'oauth_token', requestBody: null, url: null, method: null };
      samltrace.handleOAuthRequest(requestData);
      expect(requestData.oauthAnalysis).toBeDefined();
      expect(requestData.oauthAnalysis.error).toMatch(/OAuth analysis failed/);
    });
  });

  // ─── handleFido2Request ───────────────────────────────────────────────────

  describe('handleFido2Request', () => {
    afterEach(() => jest.restoreAllMocks());

    it('should return early (no-op) when requestBody is null', () => {
      samltrace.state = makeState();
      const decodeSpy = jest.spyOn(Fido2Decoder, 'decodeFido2Request');
      const requestData = { flowType: 'fido2_assertion', requestBody: null };
      samltrace.handleFido2Request(requestData);
      expect(decodeSpy).not.toHaveBeenCalled();
      expect(requestData.fido2Analysis).toBeUndefined();
      expect(samltrace.state.fido2Sessions).toHaveLength(0);
    });

    it('should return early when requestBody type is not json', () => {
      samltrace.state = makeState();
      const decodeSpy = jest.spyOn(Fido2Decoder, 'decodeFido2Request');
      const requestData = { flowType: 'fido2_assertion', requestBody: { type: 'formData', data: {} } };
      samltrace.handleFido2Request(requestData);
      expect(decodeSpy).not.toHaveBeenCalled();
      expect(requestData.fido2Analysis).toBeUndefined();
      expect(samltrace.state.fido2Sessions).toHaveLength(0);
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

    it('should leave stored requests untouched when nothing matches', () => {
      const now = Date.now();
      const state = makeState({
        requests: [{ id: 'r1', url: 'https://login.microsoftonline.com/token', method: 'POST', timestamp: now, status: 'pending' }]
      });
      samltrace.state = state;
      const before = JSON.parse(JSON.stringify(state.requests));
      samltrace.handleCompleted({ url: 'https://other.com/', method: 'GET', timeStamp: now, statusCode: 404 });
      expect(state.requests).toEqual(before);
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

    it('should leave stored requests untouched when nothing matches', () => {
      const now = Date.now();
      const state = makeState({
        requests: [{ id: 'r1', url: 'https://login.microsoftonline.com/token', method: 'POST', timestamp: now, status: 'pending' }]
      });
      samltrace.state = state;
      const before = JSON.parse(JSON.stringify(state.requests));
      samltrace.handleError({ url: 'https://other.com/', method: 'GET', timeStamp: now, error: 'net::ERR_FAILED' });
      expect(state.requests).toEqual(before);
    });
  });

  // ─── analyzeRequest ───────────────────────────────────────────────────────

  describe('analyzeRequest', () => {
    it('returns the full captured-request shape for an auth request', () => {
      const details = makeDetails('https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=x&state=s', 'GET', { tabId: 42, type: 'main_frame' });
      const req = samltrace.analyzeRequest(details);
      expect(req).toEqual(expect.objectContaining({
        url: details.url,
        method: 'GET',
        tabId: 42,
        type: 'main_frame',
        chromeRequestId: details.requestId,
        flowType: 'oauth_authorize',
        status: 'pending',
        error: null,
        requestHeaders: [],
        responseHeaders: [],
        requestBody: null,
        responseBody: null
      }));
      expect(req.id).toMatch(/^req_/);
      expect(typeof req.timestamp).toBe('number');
    });

    it('returns null for a request that is not authentication traffic', () => {
      expect(samltrace.analyzeRequest(makeDetails('https://www.example.com/index.html'))).toBeNull();
    });

    it('extracts the body only for POST requests', () => {
      const body = { formData: { grant_type: ['client_credentials'], client_id: ['x'] } };
      const post = samltrace.analyzeRequest(makeDetails('https://login.microsoftonline.com/t/oauth2/v2.0/token', 'POST', { requestBody: body }));
      expect(post.requestBody).toEqual({ type: 'formData', data: body.formData });
      const get = samltrace.analyzeRequest(makeDetails('https://login.microsoftonline.com/t/oauth2/v2.0/token', 'GET', { requestBody: body }));
      expect(get.requestBody).toBeNull();
    });

    it('records a null chromeRequestId when Chrome does not supply one', () => {
      const details = makeDetails('https://login.microsoftonline.com/t/oauth2/v2.0/authorize');
      delete details.requestId;
      expect(samltrace.analyzeRequest(details).chromeRequestId).toBeNull();
    });
  });

  // ─── findRequest by Chrome requestId ──────────────────────────────────────

  describe('findRequest — requestId matching', () => {
    it('resolves two identical polls captured within the same second by requestId', () => {
      const now = Date.now();
      const url = 'https://login.microsoftonline.com/t/oauth2/v2.0/token';
      samltrace.state = makeState({
        requests: [
          { id: 'r1', chromeRequestId: '1001', url, method: 'POST', timestamp: now },
          { id: 'r2', chromeRequestId: '1002', url, method: 'POST', timestamp: now + 10 }
        ]
      });
      expect(samltrace.findRequest({ requestId: '1002', url, method: 'POST', timeStamp: now + 15 }).id).toBe('r2');
      expect(samltrace.findRequest({ requestId: '1001', url, method: 'POST', timeStamp: now + 15 }).id).toBe('r1');
    });

    it('does not fall back to the heuristic when both sides carry a requestId that does not match', () => {
      const now = Date.now();
      const url = 'https://login.microsoftonline.com/t/oauth2/v2.0/token';
      samltrace.state = makeState({ requests: [{ id: 'r1', chromeRequestId: '1001', url, method: 'POST', timestamp: now }] });
      expect(samltrace.findRequest({ requestId: '9999', url, method: 'POST', timeStamp: now })).toBeUndefined();
    });

    it('uses the url/method/time heuristic when the stored request has no requestId (legacy capture)', () => {
      const now = Date.now();
      const url = 'https://login.microsoftonline.com/t/oauth2/v2.0/token';
      samltrace.state = makeState({ requests: [{ id: 'legacy', url, method: 'POST', timestamp: now }] });
      expect(samltrace.findRequest({ requestId: '1', url, method: 'POST', timeStamp: now + 100 }).id).toBe('legacy');
    });
  });

  // ─── Full webRequest lifecycle through the registered listeners ───────────

  describe('webRequest lifecycle via registered listeners', () => {
    let listeners;

    beforeEach(() => {
      samltrace.isListening = false;
      samltrace.initialize(makeState());
      listeners = captureWebRequestListeners();
    });

    it('registers a function for every event with <all_urls> filters', () => {
      for (const fn of Object.values(listeners)) expect(typeof fn).toBe('function');
      const filterArg = chrome.webRequest.onBeforeRequest.addListener.mock.calls.at(-1)[1];
      expect(filterArg).toEqual({ urls: ['<all_urls>'] });
      expect(chrome.webRequest.onBeforeRequest.addListener.mock.calls.at(-1)[2]).toEqual(['requestBody']);
    });

    it('carries one request from onBeforeRequest to onCompleted by requestId', () => {
      const details = makeDetails('https://login.microsoftonline.com/t/oauth2/v2.0/token', 'POST', {
        requestBody: { formData: { grant_type: ['client_credentials'], client_id: ['svc'] } }
      });
      listeners.onBeforeRequest(details);
      listeners.onBeforeSendHeaders({ ...details, requestHeaders: [{ name: 'Authorization', value: 'Basic ' + btoa('svc:s3cret') }] });
      listeners.onHeadersReceived({ ...details, responseHeaders: [{ name: 'Content-Type', value: 'application/json' }], statusCode: 200 });
      listeners.onCompleted({ ...details, statusCode: 200 });

      const [req] = samltrace.state.requests;
      expect(samltrace.state.requests).toHaveLength(1);
      expect(req.chromeRequestId).toBe(details.requestId);
      expect(req.status).toBe('completed');
      expect(req.statusCode).toBe(200);
      expect(req.requestHeaders[0].name).toBe('Authorization');
      expect(req.responseHeaders[0].value).toBe('application/json');
      // Header enrichment ran: the Basic credential reclassified the client auth method
      expect(req.oauthAnalysis.authMethod).toBe('client_secret_basic');
      expect(req.oauthAnalysis.clientId).toBe('svc');
      expect(req.oauthAnalysis.warnings.map(w => w.rule)).toContain('client_auth_secret_basic');
      expect(samltrace.state.onNewAuthRequest).toHaveBeenCalledTimes(1);
    });

    it('marks a request as errored through onErrorOccurred', () => {
      const details = makeDetails('https://login.microsoftonline.com/t/oauth2/v2.0/authorize?client_id=x');
      listeners.onBeforeRequest(details);
      listeners.onErrorOccurred({ ...details, error: 'net::ERR_CONNECTION_RESET' });
      expect(samltrace.state.requests[0].status).toBe('error');
      expect(samltrace.state.requests[0].error).toBe('net::ERR_CONNECTION_RESET');
    });

    it('attaches headers to the right request when two identical polls are in flight', () => {
      const url = 'https://login.microsoftonline.com/t/oauth2/v2.0/token';
      const body = { formData: { grant_type: ['urn:ietf:params:oauth:grant-type:device_code'], device_code: ['dc-1'], client_id: ['app'] } };
      const first = makeDetails(url, 'POST', { requestBody: body });
      const second = makeDetails(url, 'POST', { requestBody: body });
      listeners.onBeforeRequest(first);
      listeners.onBeforeRequest(second);
      listeners.onHeadersReceived({ ...second, responseHeaders: [], statusCode: 400 });
      listeners.onCompleted({ ...second, statusCode: 400 });
      const [r1, r2] = samltrace.state.requests;
      expect(r1.status).toBe('pending');
      expect(r2.status).toBe('completed');
      expect(r2.statusCode).toBe(400);
    });

    it('stopListening removes exactly the functions that were registered', () => {
      samltrace.stopListening();
      const events = ['onBeforeRequest', 'onBeforeSendHeaders', 'onHeadersReceived', 'onCompleted', 'onErrorOccurred'];
      for (const ev of events) {
        expect(chrome.webRequest[ev].removeListener).toHaveBeenCalledWith(listeners[ev]);
      }
      expect(samltrace.isListening).toBe(false);
    });
  });

  // ─── Bounded buffers ──────────────────────────────────────────────────────

  describe('request buffer limits', () => {
    it('exports sensible caps', () => {
      expect(MAX_REQUESTS).toBeGreaterThanOrEqual(100);
      expect(MAX_FIDO2_SESSIONS).toBeGreaterThanOrEqual(10);
    });

    it('evicts the oldest request once MAX_REQUESTS is reached and prunes its correlation entry', () => {
      const state = makeState();
      for (let i = 0; i < MAX_REQUESTS; i++) {
        state.requests.push({ id: `r${i}`, url: 'https://x/', method: 'GET', timestamp: i, deviceCodeCorrelationKey: i === 0 ? 'poll:old' : undefined });
      }
      state.deviceCodeCorrelation.set('poll:old', ['r0', 'r7']);
      samltrace.state = state;

      samltrace.handleBeforeRequest(makeDetails('https://login.microsoftonline.com/t/oauth2/v2.0/authorize?client_id=x'));

      expect(state.requests).toHaveLength(MAX_REQUESTS);
      expect(state.requests.find(r => r.id === 'r0')).toBeUndefined();
      expect(state.requests.at(-1).flowType).toBe('oauth_authorize');
      expect(state.deviceCodeCorrelation.get('poll:old')).toEqual(['r7']);
    });

    it('deletes a correlation key once its last request is evicted', () => {
      const state = makeState();
      for (let i = 0; i < MAX_REQUESTS; i++) {
        state.requests.push({ id: `r${i}`, url: 'https://x/', method: 'GET', timestamp: i });
      }
      state.deviceCodeCorrelation.set('init:app:1', ['r0']);
      samltrace.state = state;
      samltrace.handleBeforeRequest(makeDetails('https://login.microsoftonline.com/t/oauth2/v2.0/authorize?client_id=x'));
      expect(state.deviceCodeCorrelation.has('init:app:1')).toBe(false);
    });

    it('caps fido2Sessions at MAX_FIDO2_SESSIONS', () => {
      const state = makeState();
      for (let i = 0; i < MAX_FIDO2_SESSIONS; i++) state.fido2Sessions.push({ id: `f${i}` });
      samltrace.state = state;
      jest.spyOn(Fido2Decoder, 'decodeFido2Request').mockReturnValue({ clientDataJSON: { type: 'webauthn.get' } });
      samltrace.handleFido2Request({ id: 'new', timestamp: Date.now(), flowType: 'fido2_assertion', requestBody: { type: 'json', data: {} } });
      Fido2Decoder.decodeFido2Request.mockRestore();
      expect(state.fido2Sessions).toHaveLength(MAX_FIDO2_SESSIONS);
      expect(state.fido2Sessions[0].id).toBe('f1');
      expect(state.fido2Sessions.at(-1).id).toBe('new');
    });
  });

  // ─── Flow dispatch and provider coverage ──────────────────────────────────

  describe('provider and grant coverage', () => {
    function detect(urlStr, method = 'GET', requestBody = null) {
      return samltrace.detectFlowType(new URL(urlStr), makeDetails(urlStr, method, { requestBody }));
    }

    it('dispatches ropc token requests to the OAuth analyser', () => {
      const details = makeDetails('https://login.microsoftonline.com/t/oauth2/v2.0/token', 'POST', {
        requestBody: { formData: { grant_type: ['password'], username: ['u@contoso.com'], password: ['p'], client_id: ['app'] } }
      });
      samltrace.handleBeforeRequest(details);
      const [req] = samltrace.state.requests;
      expect(req.flowType).toBe('ropc');
      expect(req.oauthAnalysis.grantType).toBe('password');
      expect(req.oauthAnalysis.warnings.map(w => w.rule)).toContain('ropc_deprecated');
    });

    it('classifies an AWS Cognito token request from its body', () => {
      const rb = { formData: { grant_type: ['client_credentials'], client_id: ['x'] } };
      expect(detect('https://mypool.auth.us-east-1.amazoncognito.com/oauth2/token', 'POST', rb)).toBe('client_credentials');
    });

    it('classifies Cognito hosted-UI /login as an authentication request', () => {
      const url = new URL('https://mypool.auth.us-east-1.amazoncognito.com/login?client_id=x&redirect_uri=https://app/cb');
      expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href))).toBe(true);
    });

    it('classifies IdentityServer /connect/deviceauthorization as device_code_initiation', () => {
      expect(detect('https://auth.example.com/connect/deviceauthorization', 'POST')).toBe('device_code_initiation');
    });

    it('classifies a Shibboleth redirect-binding request as saml', () => {
      expect(detect('https://sp.university.edu/Shibboleth.sso/SAML2/Redirect?SAMLRequest=abc')).toBe('saml');
    });

    it('classifies Google token and Firebase securetoken endpoints as OAuth', () => {
      expect(detect('https://oauth2.googleapis.com/token', 'POST', { formData: { grant_type: ['refresh_token'] } })).toBe('refresh_token');
      expect(detect('https://securetoken.googleapis.com/v1/token?key=AIza', 'POST')).toBe('oauth_token');
    });
  });

  describe('generateRequestId format', () => {
    it('produces req_<timestamp>_<base36> identifiers', () => {
      expect(samltrace.generateRequestId()).toMatch(/^req_\d{13}_[a-z0-9]{1,9}$/);
    });
  });

  // ─── Device code correlation: initiation ↔ polls ─────────────────────────

  describe('device code correlation between initiation and polls', () => {
    const dcUrl = 'https://login.microsoftonline.com/t/oauth2/v2.0/devicecode';
    const tokenUrl = 'https://login.microsoftonline.com/t/oauth2/v2.0/token';
    const initiation = (clientId) => makeDetails(dcUrl, 'POST', { requestBody: { formData: { client_id: [clientId], scope: ['openid'] } } });
    const poll = (clientId, deviceCode) => makeDetails(tokenUrl, 'POST', {
      requestBody: { formData: { grant_type: ['urn:ietf:params:oauth:grant-type:device_code'], device_code: [deviceCode], client_id: [clientId] } }
    });

    it('joins polls to the initiation of the same client and yields one timeline group', () => {
      samltrace.handleBeforeRequest(initiation('cli-app'));
      samltrace.handleBeforeRequest(poll('cli-app', 'DC-1'));
      samltrace.handleBeforeRequest(poll('cli-app', 'DC-1'));
      const [init, p1, p2] = samltrace.state.requests;
      expect(init.flowType).toBe('device_code_initiation');
      expect(init.deviceCodeCorrelationKey).toMatch(/^init:cli-app:/);
      expect(p1.flowType).toBe('device_code_poll');
      expect(p1.deviceCodeCorrelationKey).toBe(init.deviceCodeCorrelationKey);
      expect(p2.deviceCodeCorrelationKey).toBe(init.deviceCodeCorrelationKey);
      expect(samltrace.state.deviceCodeCorrelation.get(init.deviceCodeCorrelationKey)).toEqual([init.id, p1.id, p2.id]);

      const groups = FlowCorrelator.computeFlowGroups(samltrace.state.requests);
      expect(groups).toHaveLength(1);
      expect(groups[0].type).toBe('device_code');
      expect(groups[0].requests.map(r => r.id)).toEqual([init.id, p1.id, p2.id]);
      expect(groups[0].requests.map((r, i) => FlowCorrelator.getFlowStepDesc(r, i))).toEqual(['Initiation', 'Poll #1', 'Poll #2']);
    });

    it('does not join a poll to another client\'s initiation', () => {
      samltrace.handleBeforeRequest(initiation('cli-a'));
      samltrace.handleBeforeRequest(poll('cli-b', 'DC-2'));
      const [init, p] = samltrace.state.requests;
      expect(p.deviceCodeCorrelationKey).toBe('poll:DC-2');
      expect(p.deviceCodeCorrelationKey).not.toBe(init.deviceCodeCorrelationKey);
      expect(FlowCorrelator.computeFlowGroups(samltrace.state.requests)).toHaveLength(2);
    });

    it('does not join a second device code to an initiation already joined by the first', () => {
      samltrace.handleBeforeRequest(initiation('cli-app'));
      samltrace.handleBeforeRequest(poll('cli-app', 'DC-1'));
      samltrace.handleBeforeRequest(poll('cli-app', 'DC-2'));
      const [init, p1, p2] = samltrace.state.requests;
      expect(p1.deviceCodeCorrelationKey).toBe(init.deviceCodeCorrelationKey);
      expect(p2.deviceCodeCorrelationKey).toBe('poll:DC-2');
    });

    it('prefers the most recent eligible initiation and ignores ones outside the join window', () => {
      samltrace.handleBeforeRequest(initiation('cli-app'));
      samltrace.state.requests[0].timestamp -= DEVICE_CODE_JOIN_WINDOW_MS + 1000;
      samltrace.handleBeforeRequest(initiation('cli-app'));
      samltrace.handleBeforeRequest(poll('cli-app', 'DC-1'));
      const [oldInit, newInit, p] = samltrace.state.requests;
      expect(p.deviceCodeCorrelationKey).toBe(newInit.deviceCodeCorrelationKey);
      expect(p.deviceCodeCorrelationKey).not.toBe(oldInit.deviceCodeCorrelationKey);

      samltrace.state = makeState();
      samltrace.handleBeforeRequest(initiation('cli-app'));
      samltrace.state.requests[0].timestamp -= DEVICE_CODE_JOIN_WINDOW_MS + 1000;
      samltrace.handleBeforeRequest(poll('cli-app', 'DC-9'));
      expect(samltrace.state.requests[1].deviceCodeCorrelationKey).toBe('poll:DC-9');
    });

    it('falls back to a standalone poll key when no initiation was captured', () => {
      samltrace.handleBeforeRequest(poll('cli-app', 'DC-1'));
      samltrace.handleBeforeRequest(poll('cli-app', 'DC-1'));
      const [p1, p2] = samltrace.state.requests;
      expect(p1.deviceCodeCorrelationKey).toBe('poll:DC-1');
      expect(p2.deviceCodeCorrelationKey).toBe('poll:DC-1');
      expect(samltrace.state.deviceCodeCorrelation.get('poll:DC-1')).toEqual([p1.id, p2.id]);
    });
  });
});
