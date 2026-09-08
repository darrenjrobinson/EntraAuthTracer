/**
 * Tests for OAuthDecoder — Phase 3: OAuth 2.1 Extensions
 */

import OAuthDecoder from '../src/OAuthDecoder.js';
import { buildJwt } from './helpers.js';

// ─── Helper: build a minimal requestData object ───────────────────────────────

function makeRequest(url, method = 'GET', formData = null) {
  const req = { url, method, requestBody: null };
  if (formData) {
    // Simulate Chrome webRequest formData format (values as arrays)
    const chromeFmt = {};
    for (const [k, v] of Object.entries(formData)) {
      chromeFmt[k] = [v];
    }
    req.requestBody = { type: 'formData', data: chromeFmt };
  }
  return req;
}

// ─── flattenBody ─────────────────────────────────────────────────────────────

describe('OAuthDecoder.flattenBody', () => {
  it('flattens Chrome formData (array values)', () => {
    const body = { type: 'formData', data: { grant_type: ['client_credentials'], client_id: ['myapp'] } };
    const flat = OAuthDecoder.flattenBody(body);
    expect(flat.grant_type).toBe('client_credentials');
    expect(flat.client_id).toBe('myapp');
  });

  it('returns JSON data as-is', () => {
    const body = { type: 'json', data: { foo: 'bar' } };
    expect(OAuthDecoder.flattenBody(body)).toEqual({ foo: 'bar' });
  });

  it('returns null for null input', () => {
    expect(OAuthDecoder.flattenBody(null)).toBeNull();
  });
});

// ─── Endpoint detection ───────────────────────────────────────────────────────

describe('OAuthDecoder endpoint detection', () => {
  it('detects /oauth2/v2.0/authorize', () => {
    expect(OAuthDecoder.isAuthorizationEndpoint('/common/oauth2/v2.0/authorize')).toBe(true);
  });

  it('detects /oauth2/v2.0/token', () => {
    expect(OAuthDecoder.isTokenEndpoint('/tenant/oauth2/v2.0/token')).toBe(true);
  });

  it('does not confuse /tokeninfo as a token endpoint', () => {
    expect(OAuthDecoder.isTokenEndpoint('/tokeninfo')).toBe(false);
  });

  it('detects /oauth2/v2.0/devicecode', () => {
    expect(OAuthDecoder.isDeviceCodeEndpoint('/tenant/oauth2/v2.0/devicecode')).toBe(true);
  });
});

// ─── detectFlowTypeFromBody ───────────────────────────────────────────────────

describe('OAuthDecoder.detectFlowTypeFromBody', () => {
  it('returns pkce_token_exchange for authorization_code with code_verifier', () => {
    const body = { type: 'formData', data: { grant_type: ['authorization_code'], code_verifier: ['abc'] } };
    expect(OAuthDecoder.detectFlowTypeFromBody(body)).toBe('pkce_token_exchange');
  });

  it('returns authcode_token_exchange for authorization_code without code_verifier', () => {
    const body = { type: 'formData', data: { grant_type: ['authorization_code'] } };
    expect(OAuthDecoder.detectFlowTypeFromBody(body)).toBe('authcode_token_exchange');
  });

  it('returns client_credentials', () => {
    const body = { type: 'formData', data: { grant_type: ['client_credentials'] } };
    expect(OAuthDecoder.detectFlowTypeFromBody(body)).toBe('client_credentials');
  });

  it('returns device_code_poll', () => {
    const body = { type: 'formData', data: { grant_type: ['urn:ietf:params:oauth:grant-type:device_code'] } };
    expect(OAuthDecoder.detectFlowTypeFromBody(body)).toBe('device_code_poll');
  });

  it('returns refresh_token', () => {
    const body = { type: 'formData', data: { grant_type: ['refresh_token'] } };
    expect(OAuthDecoder.detectFlowTypeFromBody(body)).toBe('refresh_token');
  });

  it('returns null for unknown grant_type', () => {
    const body = { type: 'formData', data: { grant_type: ['custom_grant'] } };
    expect(OAuthDecoder.detectFlowTypeFromBody(body)).toBeNull();
  });

  it('returns null when no body', () => {
    expect(OAuthDecoder.detectFlowTypeFromBody(null)).toBeNull();
  });
});

// ─── Authorization request analysis ──────────────────────────────────────────

describe('OAuthDecoder.analyzeAuthorizationRequest', () => {
  function makeParams(obj) {
    return new URLSearchParams(obj);
  }

  it('detects PKCE Authorization Code flow', () => {
    const params = makeParams({
      response_type: 'code',
      client_id: 'test-client',
      code_challenge: 'abc123',
      code_challenge_method: 'S256',
      scope: 'openid profile',
      state: 'random-state'
    });
    const result = OAuthDecoder.analyzeAuthorizationRequest(params, null);
    expect(result.grantType).toBe('authorization_code_pkce');
    expect(result.label).toBe('Authorization Code + PKCE');
    expect(result.pkce).not.toBeNull();
    expect(result.pkce.isS256).toBe(true);
    expect(result.scopes).toEqual(['openid', 'profile']);
    // No warnings (PKCE present + state present)
    const warnMessages = result.warnings.map(w => w.message);
    expect(warnMessages.some(m => m.includes('PKCE'))).toBe(false);
  });

  it('warns when Authorization Code flow has no PKCE', () => {
    const params = makeParams({
      response_type: 'code',
      client_id: 'test-client',
      state: 'random-state'
    });
    const result = OAuthDecoder.analyzeAuthorizationRequest(params, null);
    expect(result.grantType).toBe('authorization_code');
    expect(result.warnings.some(w => w.message.includes('PKCE'))).toBe(true);
  });

  it('warns when state parameter is missing', () => {
    const params = makeParams({
      response_type: 'code',
      client_id: 'test-client',
      code_challenge: 'abc',
      code_challenge_method: 'S256'
    });
    const result = OAuthDecoder.analyzeAuthorizationRequest(params, null);
    expect(result.warnings.some(w => w.message.toLowerCase().includes('state'))).toBe(true);
  });

  it('flags implicit flow as deprecated with error severity', () => {
    const params = makeParams({
      response_type: 'token',
      client_id: 'test-client',
      state: 'xyz'
    });
    const result = OAuthDecoder.analyzeAuthorizationRequest(params, null);
    expect(result.grantType).toBe('implicit');
    expect(result.warnings.some(w => w.severity === 'error' && w.message.includes('Implicit'))).toBe(true);
  });

  it('warns when code_challenge_method is plain', () => {
    const params = makeParams({
      response_type: 'code',
      client_id: 'test-client',
      code_challenge: 'abc',
      code_challenge_method: 'plain',
      state: 'xyz'
    });
    const result = OAuthDecoder.analyzeAuthorizationRequest(params, null);
    expect(result.warnings.some(w => w.message.includes('S256'))).toBe(true);
  });
});

// ─── Token request analysis ───────────────────────────────────────────────────

describe('OAuthDecoder.analyzeTokenRequest — client_credentials', () => {
  it('detects client_secret auth method', () => {
    const req = makeRequest(
      'https://login.microsoftonline.com/tenant/oauth2/v2.0/token',
      'POST',
      { grant_type: 'client_credentials', client_id: 'app-id', client_secret: 'secret', scope: 'https://graph.microsoft.com/.default' }
    );
    const result = OAuthDecoder.analyzeTokenRequest(req.requestBody, new URLSearchParams());
    expect(result.grantType).toBe('client_credentials');
    expect(result.authMethod).toBe('client_secret_post');
    expect(result.scopes).toContain('https://graph.microsoft.com/.default');
    expect(result.warnings.some(w => w.message.includes('client_secret'))).toBe(true);
  });

  it('detects client_assertion auth method', () => {
    // Minimal JWT header.payload.sig
    const fakeJwt = btoa('{"alg":"RS256"}') + '.' + btoa('{"iss":"app","sub":"app","exp":9999999999}') + '.sig';
    const req = makeRequest(
      'https://login.microsoftonline.com/tenant/oauth2/v2.0/token',
      'POST',
      {
        grant_type: 'client_credentials',
        client_id: 'app-id',
        client_assertion: fakeJwt,
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        scope: 'https://graph.microsoft.com/.default'
      }
    );
    const result = OAuthDecoder.analyzeTokenRequest(req.requestBody, new URLSearchParams());
    expect(result.grantType).toBe('client_credentials');
    expect(result.authMethod).toBe('client_assertion');
    expect(result.authMethodLabel).toContain('Certificate');
    expect(result.clientAssertion).not.toBeNull();
    expect(result.clientAssertion.isJWT).toBe(true);
  });
});

describe('OAuthDecoder.analyzeTokenRequest — authorization_code', () => {
  it('detects authorization_code + PKCE token exchange', () => {
    const verifier = 'A'.repeat(64); // 64 chars — high entropy
    const req = makeRequest(
      'https://login.microsoftonline.com/tenant/oauth2/v2.0/token',
      'POST',
      { grant_type: 'authorization_code', client_id: 'app-id', code: 'auth-code', code_verifier: verifier, redirect_uri: 'https://myapp.com/callback' }
    );
    const result = OAuthDecoder.analyzeTokenRequest(req.requestBody, new URLSearchParams());
    expect(result.grantType).toBe('authorization_code_pkce');
    expect(result.pkceVerifier.isCompliant).toBe(true);
    expect(result.pkceVerifier.isHighEntropy).toBe(true);
  });

  it('detects authorization_code without PKCE', () => {
    const req = makeRequest(
      'https://login.microsoftonline.com/tenant/oauth2/v2.0/token',
      'POST',
      { grant_type: 'authorization_code', client_id: 'app-id', code: 'auth-code', redirect_uri: 'https://myapp.com/callback' }
    );
    const result = OAuthDecoder.analyzeTokenRequest(req.requestBody, new URLSearchParams());
    expect(result.grantType).toBe('authorization_code');
    expect(result.pkceVerifier).toBeNull();
    expect(result.warnings.some(w => w.message.includes('code_verifier'))).toBe(true);
  });
});

describe('OAuthDecoder.analyzeTokenRequest — device_code poll', () => {
  it('detects device_code poll', () => {
    const req = makeRequest(
      'https://login.microsoftonline.com/tenant/oauth2/v2.0/token',
      'POST',
      { grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: 'DEVICE12345678901234567890', client_id: 'app-id' }
    );
    const result = OAuthDecoder.analyzeTokenRequest(req.requestBody, new URLSearchParams());
    expect(result.grantType).toBe('device_code');
    expect(result.requestType).toBe('device_code_poll');
    expect(result.deviceCode).toBe('DEVICE12345678901234567890');
    expect(result.deviceCodePrefix).toContain('…');
  });
});

describe('OAuthDecoder.analyzeTokenRequest — refresh_token', () => {
  it('detects refresh_token grant', () => {
    const req = makeRequest(
      'https://login.microsoftonline.com/tenant/oauth2/v2.0/token',
      'POST',
      { grant_type: 'refresh_token', client_id: 'app-id', scope: 'openid offline_access' }
    );
    const result = OAuthDecoder.analyzeTokenRequest(req.requestBody, new URLSearchParams());
    expect(result.grantType).toBe('refresh_token');
    expect(result.scopes).toContain('openid');
    expect(result.scopes).toContain('offline_access');
  });
});

// ─── Device code initiation ───────────────────────────────────────────────────

describe('OAuthDecoder.analyzeDeviceCodeInitiation', () => {
  it('returns device_code_initiation with scopes', () => {
    const body = { type: 'formData', data: { client_id: ['myapp'], scope: ['openid profile'] } };
    const result = OAuthDecoder.analyzeDeviceCodeInitiation(body);
    expect(result.requestType).toBe('device_code_initiation');
    expect(result.grantType).toBe('device_code');
    expect(result.clientId).toBe('myapp');
    expect(result.scopes).toContain('openid');
  });

  it('handles missing body gracefully', () => {
    const result = OAuthDecoder.analyzeDeviceCodeInitiation(null);
    expect(result.requestType).toBe('device_code_initiation');
    expect(result.scopes).toEqual([]);
  });
});

// ─── PKCE analysis ────────────────────────────────────────────────────────────

describe('OAuthDecoder.analyzePKCEChallenge', () => {
  it('marks S256 as compliant', () => {
    const result = OAuthDecoder.analyzePKCEChallenge('abc123', 'S256');
    expect(result.isS256).toBe(true);
    expect(result.status).toBe('compliant');
    expect(result.recommendation).toContain('S256');
  });

  it('warns for plain method', () => {
    const result = OAuthDecoder.analyzePKCEChallenge('abc123', 'plain');
    expect(result.isS256).toBe(false);
    expect(result.status).toBe('warning');
  });

  it('defaults to plain when method is missing', () => {
    const result = OAuthDecoder.analyzePKCEChallenge('abc123', null);
    expect(result.codeChallengeMethod).toBe('plain');
  });
});

describe('OAuthDecoder.analyzePKCEVerifier', () => {
  it('validates compliant high-entropy verifier', () => {
    const verifier = 'a'.repeat(64);
    const result = OAuthDecoder.analyzePKCEVerifier(verifier);
    expect(result.isCompliant).toBe(true);
    expect(result.isHighEntropy).toBe(true);
    expect(result.status).toBe('compliant');
  });

  it('rejects too-short verifier', () => {
    const result = OAuthDecoder.analyzePKCEVerifier('short');
    expect(result.isCompliant).toBe(false);
    expect(result.status).toBe('error');
    expect(result.recommendation).toContain('RFC 7636');
  });

  it('rejects too-long verifier', () => {
    const result = OAuthDecoder.analyzePKCEVerifier('a'.repeat(129));
    expect(result.isCompliant).toBe(false);
  });

  it('handles null input', () => {
    const result = OAuthDecoder.analyzePKCEVerifier(null);
    expect(result.error).toBeDefined();
  });
});

// ─── Scope labelling ─────────────────────────────────────────────────────────

describe('OAuthDecoder.labelScopes', () => {
  it('labels known Microsoft scopes', () => {
    const labels = OAuthDecoder.labelScopes(['openid', 'offline_access']);
    expect(labels[0].label).toContain('OpenID Connect');
    expect(labels[1].label).toContain('refresh token');
  });

  it('returns null label for unknown scope', () => {
    const labels = OAuthDecoder.labelScopes(['urn:custom:scope']);
    expect(labels[0].label).toBeNull();
  });

  it('returns empty array for no scopes', () => {
    expect(OAuthDecoder.labelScopes([])).toEqual([]);
  });
});

// ─── analyzeRequest integration ───────────────────────────────────────────────

describe('OAuthDecoder.analyzeRequest integration', () => {
  it('analyses a PKCE authorization request end-to-end', () => {
    const req = {
      url: 'https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize?response_type=code&client_id=app&code_challenge=abc&code_challenge_method=S256&scope=openid+profile&state=xyz',
      method: 'GET',
      requestBody: null
    };
    const result = OAuthDecoder.analyzeRequest(req);
    expect(result).not.toBeNull();
    expect(result.requestType).toBe('authorization_request');
    expect(result.grantType).toBe('authorization_code_pkce');
    expect(result.pkce.isS256).toBe(true);
    // State is present, so no CSRF warning
    expect(result.warnings.some(w => w.message.includes('state'))).toBe(false);
  });

  it('analyses a client_credentials token request end-to-end', () => {
    const req = makeRequest(
      'https://login.microsoftonline.com/tenant/oauth2/v2.0/token',
      'POST',
      { grant_type: 'client_credentials', client_id: 'svc', client_secret: 'sec', scope: 'https://graph.microsoft.com/.default' }
    );
    const result = OAuthDecoder.analyzeRequest(req);
    expect(result.grantType).toBe('client_credentials');
    expect(result.authMethod).toBe('client_secret_post');
  });

  it('returns null for non-OAuth URLs', () => {
    const req = { url: 'https://login.microsoftonline.com/saml2', method: 'GET', requestBody: null };
    expect(OAuthDecoder.analyzeRequest(req)).toBeNull();
  });
});

// ─── parseAuthorizationHeader ─────────────────────────────────────────────────

describe('OAuthDecoder.parseAuthorizationHeader', () => {
  it('decodes Basic auth header into client_secret_basic', () => {
    const header = 'Basic ' + btoa('myclient:mysecret');
    const result = OAuthDecoder.parseAuthorizationHeader(header);
    expect(result).not.toBeNull();
    expect(result.scheme).toBe('client_secret_basic');
    expect(result.clientId).toBe('myclient');
    expect(result.clientSecret).toBe('mysecret');
    expect(result.schemeLabel).toContain('client_secret_basic');
  });

  it('handles client_id with colon in client_secret (only splits on first colon)', () => {
    const header = 'Basic ' + btoa('clientid:secret:with:colons');
    const result = OAuthDecoder.parseAuthorizationHeader(header);
    expect(result.scheme).toBe('client_secret_basic');
    expect(result.clientId).toBe('clientid');
    expect(result.clientSecret).toBe('secret:with:colons');
  });

  it('decodes Digest auth header and extracts params', () => {
    const header = 'Digest realm="sap.example.com", username="svcacct", uri="/oauth/token", algorithm=MD5, qop=auth';
    const result = OAuthDecoder.parseAuthorizationHeader(header);
    expect(result).not.toBeNull();
    expect(result.scheme).toBe('digest_auth');
    expect(result.clientId).toBe('svcacct');
    expect(result.digestParams.realm).toBe('sap.example.com');
    expect(result.digestParams.uri).toBe('/oauth/token');
    expect(result.digestParams.algorithm).toBe('MD5');
    expect(result.digestParams.qop).toBe('auth');
    expect(result.schemeLabel).toContain('Digest');
  });

  it('Digest auth defaults algorithm to MD5 when absent', () => {
    const header = 'Digest realm="example.com", username="user"';
    const result = OAuthDecoder.parseAuthorizationHeader(header);
    expect(result.scheme).toBe('digest_auth');
    expect(result.digestParams.algorithm).toBe('MD5');
  });

  it('returns bearer scheme for Bearer header', () => {
    const result = OAuthDecoder.parseAuthorizationHeader('Bearer eyJhbGciOiJSUzI1NiJ9.payload.sig');
    expect(result).not.toBeNull();
    expect(result.scheme).toBe('bearer');
    expect(result.schemeLabel).toContain('Bearer');
  });

  it('returns null for null input', () => {
    expect(OAuthDecoder.parseAuthorizationHeader(null)).toBeNull();
  });

  it('returns null for undefined input', () => {
    expect(OAuthDecoder.parseAuthorizationHeader(undefined)).toBeNull();
  });

  it('returns null for unrecognised scheme (NTLM)', () => {
    expect(OAuthDecoder.parseAuthorizationHeader('NTLM TlRMTVNTUAAB')).toBeNull();
  });

  it('is case-insensitive for Basic scheme', () => {
    const header = 'basic ' + btoa('id:sec');
    const result = OAuthDecoder.parseAuthorizationHeader(header);
    expect(result).not.toBeNull();
    expect(result.scheme).toBe('client_secret_basic');
  });

  it('is case-insensitive for Digest scheme', () => {
    const header = 'digest realm="x.com", username="u"';
    const result = OAuthDecoder.parseAuthorizationHeader(header);
    expect(result).not.toBeNull();
    expect(result.scheme).toBe('digest_auth');
  });
});

// ─── enrichWithHeaders ────────────────────────────────────────────────────────

describe('OAuthDecoder.enrichWithHeaders', () => {
  function makeAnalysis(overrides = {}) {
    return {
      requestType: 'token_request',
      grantType: 'client_credentials',
      authMethod: 'public',
      authMethodLabel: 'No explicit credential (public client or mTLS)',
      clientId: null,
      warnings: [],
      ...overrides
    };
  }

  function makeHeaders(name, value) {
    return [{ name, value }];
  }

  it('patches authMethod and clientId from Basic auth header', () => {
    const analysis = makeAnalysis();
    OAuthDecoder.enrichWithHeaders(analysis, makeHeaders('Authorization', 'Basic ' + btoa('clientA:secretB')));
    expect(analysis.authMethod).toBe('client_secret_basic');
    expect(analysis.authMethodLabel).toContain('client_secret_basic');
    expect(analysis.clientId).toBe('clientA');
  });

  it('adds an info warning when Basic auth is detected', () => {
    const analysis = makeAnalysis();
    OAuthDecoder.enrichWithHeaders(analysis, makeHeaders('Authorization', 'Basic ' + btoa('c:s')));
    expect(analysis.warnings.some(w => w.severity === 'info' && w.message.includes('client_secret_basic'))).toBe(true);
  });

  it('patches authMethod and digestParams from Digest header', () => {
    const analysis = makeAnalysis();
    OAuthDecoder.enrichWithHeaders(analysis, makeHeaders('Authorization', 'Digest realm="sap.example.com", username="svcacct", uri="/oauth/token", algorithm=MD5'));
    expect(analysis.authMethod).toBe('digest_auth');
    expect(analysis.digestAuth).toBeDefined();
    expect(analysis.digestAuth.realm).toBe('sap.example.com');
    expect(analysis.clientId).toBe('svcacct');
  });

  it('Digest warning mentions SAP Integration Suite and Dell Boomi', () => {
    const analysis = makeAnalysis();
    OAuthDecoder.enrichWithHeaders(analysis, makeHeaders('Authorization', 'Digest realm="r", username="u"'));
    const warn = analysis.warnings.find(w => w.message.includes('SAP'));
    expect(warn).toBeDefined();
    expect(warn.message).toContain('Dell Boomi');
  });

  it('does NOT overwrite an existing body-derived clientId', () => {
    const analysis = makeAnalysis({ clientId: 'from-body' });
    OAuthDecoder.enrichWithHeaders(analysis, makeHeaders('Authorization', 'Basic ' + btoa('from-header:secret')));
    expect(analysis.clientId).toBe('from-body');
  });

  it('does not patch for Bearer token (scheme=bearer)', () => {
    const analysis = makeAnalysis({ authMethod: 'public' });
    OAuthDecoder.enrichWithHeaders(analysis, makeHeaders('Authorization', 'Bearer eyJhbGci...'));
    expect(analysis.authMethod).toBe('public');
  });

  it('does not patch non-token requestTypes (authorization_request)', () => {
    const analysis = { requestType: 'authorization_request', authMethod: 'public', warnings: [] };
    OAuthDecoder.enrichWithHeaders(analysis, makeHeaders('Authorization', 'Basic ' + btoa('x:y')));
    expect(analysis.authMethod).toBe('public');
  });

  it('also patches device_code_initiation requestType', () => {
    const analysis = makeAnalysis({ requestType: 'device_code_initiation' });
    OAuthDecoder.enrichWithHeaders(analysis, makeHeaders('Authorization', 'Basic ' + btoa('dcClient:dcSecret')));
    expect(analysis.authMethod).toBe('client_secret_basic');
    expect(analysis.clientId).toBe('dcClient');
  });

  it('handles case-insensitive header name lookup', () => {
    const analysis = makeAnalysis();
    OAuthDecoder.enrichWithHeaders(analysis, [{ name: 'AUTHORIZATION', value: 'Basic ' + btoa('id:sec') }]);
    expect(analysis.authMethod).toBe('client_secret_basic');
  });

  it('leaves the analysis untouched when the headers array is empty', () => {
    const analysis = makeAnalysis();
    const before = JSON.parse(JSON.stringify(analysis));
    OAuthDecoder.enrichWithHeaders(analysis, []);
    expect(analysis).toEqual(before);
  });

  it('is a no-op for a null analysis', () => {
    expect(OAuthDecoder.enrichWithHeaders(null, makeHeaders('Authorization', 'Basic ' + btoa('x:y')))).toBeUndefined();
  });

  it('leaves the analysis untouched when headers are null', () => {
    const analysis = makeAnalysis();
    const before = JSON.parse(JSON.stringify(analysis));
    OAuthDecoder.enrichWithHeaders(analysis, null);
    expect(analysis).toEqual(before);
  });

  it('leaves the analysis untouched when there is no Authorization header', () => {
    const analysis = makeAnalysis();
    const before = JSON.parse(JSON.stringify(analysis));
    OAuthDecoder.enrichWithHeaders(analysis, makeHeaders('Content-Type', 'application/x-www-form-urlencoded'));
    expect(analysis).toEqual(before);
  });

  it('replaces only client_auth_* warnings, keeping unrelated findings', () => {
    const analysis = makeAnalysis({
      warnings: [
        { rule: 'pkce_verifier_missing', severity: 'info', message: 'Token exchange without code_verifier — PKCE is required for public clients in OAuth 2.1' },
        { rule: 'client_auth_secret_post', severity: 'info', message: 'Using client_secret in POST body (client_secret_post) — consider client_secret_basic or certificate-based authentication' }
      ]
    });
    OAuthDecoder.enrichWithHeaders(analysis, makeHeaders('Authorization', 'Basic ' + btoa('c:s')));
    const rules = analysis.warnings.map(w => w.rule);
    expect(rules).toContain('pkce_verifier_missing');
    expect(rules).toContain('client_auth_secret_basic');
    expect(rules).not.toContain('client_auth_secret_post');
  });
});

// ─── ROPC (password grant) ────────────────────────────────────────────────────

describe('OAuthDecoder.analyzeTokenRequest — password (ROPC)', () => {
  const tokenUrl = 'https://login.microsoftonline.com/tenant/oauth2/v2.0/token';

  function ropc(extra = {}) {
    return makeRequest(tokenUrl, 'POST', {
      grant_type: 'password',
      client_id: 'legacy-script',
      username: 'alice@contoso.com',
      password: 'Hunter2!',
      scope: 'openid https://graph.microsoft.com/User.Read',
      ...extra
    });
  }

  it('dispatches to the ROPC analyser', () => {
    const result = OAuthDecoder.analyzeTokenRequest(ropc().requestBody, new URLSearchParams());
    expect(result.requestType).toBe('token_request');
    expect(result.grantType).toBe('password');
    expect(result.label).toBe(OAuthDecoder.GRANT_TYPES.password.label);
    expect(result.clientId).toBe('legacy-script');
    expect(result.scopes).toEqual(['openid', 'https://graph.microsoft.com/User.Read']);
  });

  it('raises an error-severity ropc_deprecated warning', () => {
    const result = OAuthDecoder.analyzeTokenRequest(ropc().requestBody, new URLSearchParams());
    const w = result.warnings.find(x => x.rule === 'ropc_deprecated');
    expect(w).toBeDefined();
    expect(w.severity).toBe('error');
    expect(w.message).toMatch(/OAuth 2\.1/);
  });

  it('reports username presence and domain but never the credential values', () => {
    const result = OAuthDecoder.analyzeTokenRequest(ropc().requestBody, new URLSearchParams());
    expect(result.usernamePresent).toBe(true);
    expect(result.usernameDomain).toBe('contoso.com');
    expect(result.passwordPresent).toBe(true);
    const serialised = JSON.stringify(result);
    expect(serialised).not.toContain('alice@contoso.com');
    expect(serialised).not.toContain('Hunter2!');
  });

  it('classifies a public client when no client credential is sent', () => {
    const result = OAuthDecoder.analyzeTokenRequest(ropc().requestBody, new URLSearchParams());
    expect(result.authMethod).toBe('public');
  });

  it('classifies client_secret_post and adds the client_auth_secret_post note', () => {
    const result = OAuthDecoder.analyzeTokenRequest(ropc({ client_secret: 's3cret' }).requestBody, new URLSearchParams());
    expect(result.authMethod).toBe('client_secret_post');
    expect(result.warnings.map(w => w.rule)).toEqual(['ropc_deprecated', 'client_auth_secret_post']);
  });

  it('is reachable through analyzeRequest and detectFlowTypeFromBody', () => {
    const req = ropc();
    expect(OAuthDecoder.analyzeRequest(req).grantType).toBe('password');
    expect(OAuthDecoder.detectFlowTypeFromBody(req.requestBody)).toBe('ropc');
  });
});

// ─── redirect_uri assessment ──────────────────────────────────────────────────

describe('OAuthDecoder.assessRedirectUri', () => {
  it.each([
    ['https://app.contoso.com/callback', null, null],
    ['http://localhost:8400/callback', 'redirect_uri_loopback_http', 'info'],
    ['http://127.0.0.1/cb', 'redirect_uri_loopback_http', 'info'],
    ['http://[::1]:5000/cb', 'redirect_uri_loopback_http', 'info'],
    ['http://app.contoso.com/callback', 'redirect_uri_http', 'warning'],
    ['urn:ietf:wg:oauth:2.0:oob', 'redirect_uri_oob', 'warning'],
    ['msauth://com.contoso.app/abc', 'redirect_uri_custom_scheme', 'info'],
    ['not a uri', 'redirect_uri_invalid', 'warning']
  ])('%s → %s', (uri, rule, severity) => {
    const result = OAuthDecoder.assessRedirectUri(uri);
    if (rule === null) {
      expect(result).toEqual([]);
    } else {
      expect(result).toHaveLength(1);
      expect(result[0].rule).toBe(rule);
      expect(result[0].severity).toBe(severity);
    }
  });

  it('returns no warning when redirect_uri is absent', () => {
    expect(OAuthDecoder.assessRedirectUri(null)).toEqual([]);
    expect(OAuthDecoder.assessRedirectUri('')).toEqual([]);
  });

  it('surfaces redirectUri and an http warning on authorization requests', () => {
    const params = new URLSearchParams({
      response_type: 'code', client_id: 'app', state: 's', code_challenge: 'c', code_challenge_method: 'S256',
      redirect_uri: 'http://app.contoso.com/callback'
    });
    const result = OAuthDecoder.analyzeAuthorizationRequest(params, null);
    expect(result.redirectUri).toBe('http://app.contoso.com/callback');
    expect(result.warnings.map(w => w.rule)).toContain('redirect_uri_http');
  });

  it('assesses redirect_uri on the token exchange as well', () => {
    const req = makeRequest('https://login.microsoftonline.com/t/oauth2/v2.0/token', 'POST', {
      grant_type: 'authorization_code', client_id: 'app', code: 'c', code_verifier: 'v'.repeat(43),
      redirect_uri: 'http://localhost/cb'
    });
    const result = OAuthDecoder.analyzeTokenRequest(req.requestBody, new URLSearchParams());
    expect(result.warnings.map(w => w.rule)).toContain('redirect_uri_loopback_http');
  });
});

// ─── Warning rule ids ─────────────────────────────────────────────────────────

describe('OAuthDecoder warning rule ids', () => {
  const KNOWN_RULES = new Set([
    'pkce_missing', 'pkce_method_not_s256', 'pkce_verifier_missing', 'state_missing', 'implicit_flow',
    'ropc_deprecated', 'redirect_uri_http', 'redirect_uri_loopback_http', 'redirect_uri_oob',
    'redirect_uri_invalid', 'redirect_uri_custom_scheme', 'client_auth_secret_post',
    'client_auth_secret_basic', 'client_auth_digest', 'client_auth_secret', 'token_request_no_body',
    'grant_type_missing'
  ]);

  const analyses = [
    () => OAuthDecoder.analyzeAuthorizationRequest(new URLSearchParams({ response_type: 'token', client_id: 'x', code_challenge_method: 'plain', redirect_uri: 'http://x.y/cb' }), null),
    () => OAuthDecoder.analyzeTokenRequest(null, new URLSearchParams()),
    () => OAuthDecoder.analyzeTokenRequest({ type: 'formData', data: { client_id: ['x'] } }, new URLSearchParams()),
    () => OAuthDecoder.analyzeTokenRequest({ type: 'formData', data: { grant_type: ['authorization_code'], code: ['c'], redirect_uri: ['urn:ietf:wg:oauth:2.0:oob'] } }, new URLSearchParams()),
    () => OAuthDecoder.analyzeTokenRequest({ type: 'formData', data: { grant_type: ['client_credentials'], client_secret: ['s'] } }, new URLSearchParams()),
    () => OAuthDecoder.analyzeTokenRequest({ type: 'formData', data: { grant_type: ['password'], username: ['u'], password: ['p'], client_secret: ['s'] } }, new URLSearchParams())
  ];

  it.each(analyses.map((fn, i) => [i, fn]))('analysis #%i emits only known, non-empty rule ids', (_i, fn) => {
    const result = fn();
    expect(result.warnings.length).toBeGreaterThan(0);
    for (const w of result.warnings) {
      expect(typeof w.rule).toBe('string');
      expect(KNOWN_RULES.has(w.rule)).toBe(true);
      expect(['error', 'warning', 'info']).toContain(w.severity);
      expect(typeof w.message).toBe('string');
    }
  });
});

// ─── client_assertion decoding ────────────────────────────────────────────────

describe('OAuthDecoder.analyzeClientAssertion', () => {
  const now = Math.floor(Date.now() / 1000);

  it('decodes header and payload fields of a private_key_jwt assertion', () => {
    const jwt = buildJwt(
      { iss: 'app-id', sub: 'app-id', aud: 'https://login.microsoftonline.com/t/oauth2/v2.0/token', exp: now + 300, jti: 'nonce-1' },
      { alg: 'RS256', typ: 'JWT', kid: 'key-1', 'x5t#S256': 'thumb-sha256' }
    );
    const result = OAuthDecoder.analyzeClientAssertion(jwt, 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
    expect(result.isJWT).toBe(true);
    expect(result.algorithm).toBe('RS256');
    expect(result.keyId).toBe('key-1');
    expect(result.thumbprint).toBe('thumb-sha256');
    expect(result.issuer).toBe('app-id');
    expect(result.subject).toBe('app-id');
    expect(result.audience).toBe('https://login.microsoftonline.com/t/oauth2/v2.0/token');
    expect(result.jwtId).toBe('nonce-1');
    expect(result.expiry).toBe(new Date((now + 300) * 1000).toISOString());
    expect(result.isExpired).toBe(false);
  });

  it('falls back to the x5t thumbprint when x5t#S256 is absent', () => {
    const jwt = buildJwt({ iss: 'a', exp: now + 60 }, { alg: 'RS256', x5t: 'thumb-sha1' });
    expect(OAuthDecoder.analyzeClientAssertion(jwt).thumbprint).toBe('thumb-sha1');
  });

  it('flags an expired assertion', () => {
    const jwt = buildJwt({ iss: 'a', exp: now - 60 });
    expect(OAuthDecoder.analyzeClientAssertion(jwt).isExpired).toBe(true);
  });

  it('defaults the assertion type to jwt-bearer', () => {
    const jwt = buildJwt({ iss: 'a' });
    expect(OAuthDecoder.analyzeClientAssertion(jwt).assertionType).toBe('urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
  });

  it('returns an error object for a value that is not a three-part JWT', () => {
    expect(OAuthDecoder.analyzeClientAssertion('only.two')).toEqual({ error: 'Not a valid JWT format' });
    expect(OAuthDecoder.analyzeClientAssertion(null)).toEqual({ error: 'Not a valid JWT format' });
  });
});
