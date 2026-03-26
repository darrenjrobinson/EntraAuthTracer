/**
 * Tests for OAuthDecoder — Phase 3: OAuth 2.1 Extensions
 */

import OAuthDecoder from '../src/OAuthDecoder.js';

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

  it('returns without error on empty headers array', () => {
    const analysis = makeAnalysis();
    expect(() => OAuthDecoder.enrichWithHeaders(analysis, [])).not.toThrow();
  });

  it('returns without error on null analysis', () => {
    expect(() => OAuthDecoder.enrichWithHeaders(null, makeHeaders('Authorization', 'Basic ' + btoa('x:y')))).not.toThrow();
  });

  it('returns without error on null headers', () => {
    const analysis = makeAnalysis();
    expect(() => OAuthDecoder.enrichWithHeaders(analysis, null)).not.toThrow();
  });
});
