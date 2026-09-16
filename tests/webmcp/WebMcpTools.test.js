/**
 * Tests for WebMcpTools — the six read-only WebMCP tools over captured requests.
 */

import WebMcpTools, { WebMcpToolError } from '../../src/webmcp/WebMcpTools.js';
import FlowCorrelator from '../../src/FlowCorrelator.js';
import { makeRequest, buildJwt, buildAuthenticatorData, coseEc2P256Key, b64url, utf8ToB64 } from '../helpers.js';

const T0 = 1_757_300_000_000; // 2026-09-08T02:13:20Z
const NOW_S = Math.floor(Date.now() / 1000);

function idTokenHint(extra = {}) {
  return buildJwt({
    iss: 'https://login.microsoftonline.com/tenant/v2.0', aud: 'app', sub: 'sub-1', preferred_username: 'alice@contoso.com',
    upn: 'alice@contoso.com', tid: 'tenant', amr: ['pwd', 'mfa'], platf: '2', xms_cc: ['cp1'], acct: 0, azpacr: 1,
    iat: NOW_S - 60, exp: NOW_S + 3540, ...extra
  }, { alg: 'RS256', typ: 'JWT', kid: 'kid-1' });
}

const SAML_RESPONSE_XML = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r" Version="2.0" IssueInstant="2024-01-01T00:00:01Z" InResponseTo="_q" Destination="https://sp.example.com/acs">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="_a" IssueInstant="2024-01-01T00:00:01Z">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">bob@example.com</saml:NameID></saml:Subject>
    <saml:Conditions NotBefore="2024-01-01T00:00:00Z" NotOnOrAfter="2024-01-01T01:00:00Z"><saml:AudienceRestriction><saml:Audience>https://sp.example.com</saml:Audience></saml:AudienceRestriction></saml:Conditions>
    <saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>bob@example.com</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`;

/** A representative capture: authz-code+PKCE flow, device code flow, FIDO2 assertion, Verified ID, SAML, ROPC. */
function corpus() {
  return [
    // OAuth authorization code + PKCE flow (client "spa-app")
    makeRequest('https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize?client_id=spa-app&response_type=code&state=s1&code_challenge=c&code_challenge_method=S256&login_hint=alice%40contoso.com&redirect_uri=http%3A%2F%2Fapp.contoso.com%2Fcb&id_token_hint=' + idTokenHint(), {
      id: 's-authz', flowType: 'pkce_flow', timestamp: T0, status: 'completed', statusCode: 302, method: 'GET',
      provider: { id: 'entra', label: 'Microsoft Entra ID', hostname: 'login.microsoftonline.com' },
      oauthAnalysis: {
        requestType: 'authorization_request', grantType: 'authorization_code_pkce', label: 'Authorization Code + PKCE', clientId: 'spa-app',
        loginHint: 'alice@contoso.com', redirectUri: 'http://app.contoso.com/cb', scopes: ['openid', 'profile'], scopeLabels: [{ scope: 'openid', label: 'OpenID Connect — identity token' }, { scope: 'profile', label: 'User profile information' }],
        pkce: { codeChallenge: 'c', codeChallengeMethod: 'S256', isS256: true },
        warnings: [{ rule: 'redirect_uri_http', severity: 'warning', message: 'redirect_uri uses plain http (app.contoso.com)' }]
      }
    }),
    makeRequest('https://login.microsoftonline.com/tenant/oauth2/v2.0/token', {
      id: 's-token', flowType: 'pkce_token_exchange', timestamp: T0 + 2500, status: 'completed', statusCode: 200,
      provider: { id: 'entra', label: 'Microsoft Entra ID', hostname: 'login.microsoftonline.com' },
      formData: { grant_type: 'authorization_code', client_id: 'spa-app', code: 'AUTHCODE-SECRET', code_verifier: 'v'.repeat(43), redirect_uri: 'http://app.contoso.com/cb' },
      requestHeaders: [{ name: 'Authorization', value: 'Basic ' + btoa('spa-app:basic-secret') }, { name: 'Content-Type', value: 'application/x-www-form-urlencoded' }],
      oauthAnalysis: {
        requestType: 'token_request', grantType: 'authorization_code_pkce', label: 'Authorization Code + PKCE (Token Exchange)', clientId: 'spa-app',
        authMethod: 'client_secret_basic', authMethodLabel: 'HTTP Basic (client_secret_basic — RFC 6749 §2.3.1)',
        pkceVerifier: { length: 43, isCompliant: true }, scopes: [], scopeLabels: [],
        warnings: [{ rule: 'client_auth_secret_basic', severity: 'info', message: 'Using HTTP Basic authentication (client_secret_basic)' }, { rule: 'redirect_uri_http', severity: 'warning', message: 'redirect_uri uses plain http (app.contoso.com)' }]
      }
    }),
    // Device code flow (client "cli-app")
    makeRequest('https://login.microsoftonline.com/tenant/oauth2/v2.0/devicecode', {
      id: 'd-init', flowType: 'device_code_initiation', timestamp: T0 + 10_000, status: 'completed', statusCode: 200,
      formData: { client_id: 'cli-app', scope: 'openid offline_access' }, deviceCodeCorrelationKey: 'init:cli-app:1',
      oauthAnalysis: { requestType: 'device_code_initiation', grantType: 'device_code', label: 'Device Code Flow (Initiation)', clientId: 'cli-app', scopes: ['openid', 'offline_access'], scopeLabels: [], warnings: [] }
    }),
    makeRequest('https://login.microsoftonline.com/tenant/oauth2/v2.0/token', {
      id: 'd-poll-1', flowType: 'device_code_poll', timestamp: T0 + 15_000, status: 'completed', statusCode: 400,
      formData: { grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: 'DEVICE-CODE-1234567890', client_id: 'cli-app' }, deviceCodeCorrelationKey: 'init:cli-app:1',
      oauthAnalysis: { requestType: 'device_code_poll', grantType: 'device_code', label: 'Device Code Flow (Polling)', clientId: 'cli-app', deviceCode: 'DEVICE-CODE-1234567890', deviceCodePrefix: 'DEVICE-CODE-1234…', warnings: [] }
    }),
    makeRequest('https://login.microsoftonline.com/tenant/oauth2/v2.0/token', {
      id: 'd-poll-2', flowType: 'device_code_poll', timestamp: T0 + 20_000, status: 'completed', statusCode: 200,
      formData: { grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: 'DEVICE-CODE-1234567890', client_id: 'cli-app' }, deviceCodeCorrelationKey: 'init:cli-app:1',
      oauthAnalysis: { requestType: 'device_code_poll', grantType: 'device_code', label: 'Device Code Flow (Polling)', clientId: 'cli-app', deviceCode: 'DEVICE-CODE-1234567890', deviceCodePrefix: 'DEVICE-CODE-1234…', warnings: [] }
    }),
    // FIDO2 assertion with a real authenticatorData
    makeRequest('https://login.microsoftonline.com/common/fido/assertion', {
      id: 'f-assert', flowType: 'fido2_assertion', timestamp: T0 + 30_000, status: 'completed', statusCode: 200,
      json: { clientDataJSON: b64url(JSON.stringify({ type: 'webauthn.get', challenge: 'ch', origin: 'https://login.microsoftonline.com' })), authenticatorData: 'x' },
      fido2Analysis: {
        type: 'fido2',
        clientDataJSON: { type: 'webauthn.get', challenge: 'ch', origin: 'https://login.microsoftonline.com', crossOrigin: false, raw: { type: 'webauthn.get' } },
        authenticatorData: {
          rpIdHash: 'ab'.repeat(32), flags: { UP: true, UV: true, BE: true, BS: true, AT: true, ED: false, raw: 0x5d }, signCount: 9,
          attestedCredentialData: { aaguid: 'ee882879-721c-4913-9775-3dfcce97072a', authenticator: { name: 'YubiKey 5 Series', vendor: 'Yubico', kind: 'roaming' }, credentialIdLength: 16, credentialId: '01'.repeat(16), credentialPublicKey: { type: 'cbor', size: 77, hex: 'a5', decoded: {}, keyInfo: { keyType: 2, algorithm: -7, algorithmDescription: 'ES256 (ECDSA w/ SHA-256)' }, error: null } },
          extensions: null
        },
        attestationObject: null,
        error: null
      }
    }),
    // Verified ID presentation request
    makeRequest('https://verifiedid.did.msidentity.com/v1.0/verifiableCredentials/createPresentationRequest', {
      id: 'v-pres', flowType: 'did_presentation_request', timestamp: T0 + 40_000, status: 'completed', statusCode: 201,
      json: { authority: 'did:web:contoso.com', callback: { url: 'http://localhost:5000/cb', state: 'st' }, requestedCredentials: [{ type: 'VerifiedEmployee' }] },
      didAnalysis: { operation: 'Create Presentation Request', flowType: 'did_presentation_request', host: 'verifiedid.did.msidentity.com', path: '/v1.0/verifiableCredentials/createPresentationRequest', authority: 'did:web:contoso.com', requestedCredentials: ['VerifiedEmployee'], callbackUrl: 'http://localhost:5000/cb', callbackState: 'st', warnings: [{ rule: 'vid_callback_localhost', severity: 'warning', message: 'Callback URL points to localhost (http://localhost:5000/cb)' }] }
    }),
    // SAML POST-binding response to an SP (unknown provider)
    makeRequest('https://sp.example.com/acs', {
      id: 'saml-1', flowType: 'saml', timestamp: T0 + 50_000, status: 'completed', statusCode: 200,
      formData: { SAMLResponse: utf8ToB64(SAML_RESPONSE_XML), RelayState: 'rs' }
    }),
    // ROPC with password and a JSON-shaped errored request
    makeRequest('https://login.microsoftonline.com/tenant/oauth2/v2.0/token', {
      id: 'ropc-1', flowType: 'ropc', timestamp: T0 + 60_000, status: 'error', error: 'net::ERR_FAILED',
      formData: { grant_type: 'password', username: 'svc@contoso.com', password: 'Hunter2!', client_id: 'legacy', client_secret: 'legacy-secret' },
      oauthAnalysis: { requestType: 'token_request', grantType: 'password', label: 'Resource Owner Password ⚠ Deprecated', clientId: 'legacy', authMethod: 'client_secret_post', usernamePresent: true, usernameDomain: 'contoso.com', scopes: [], scopeLabels: [], warnings: [{ rule: 'ropc_deprecated', severity: 'error', message: 'ROPC is removed in OAuth 2.1' }, { rule: 'client_auth_secret_post', severity: 'info', message: 'Using client_secret in POST body' }] }
    })
  ];
}

describe('WebMcpTools', () => {
  describe('run (dispatch)', () => {
    it('rejects unknown tools and invalid arguments with typed errors', async () => {
      await expect(WebMcpTools.run('nope', {}, corpus())).rejects.toMatchObject({ code: 'unknown_tool' });
      await expect(WebMcpTools.run('get_session_detail', {}, corpus())).rejects.toMatchObject({ code: 'invalid_args' });
      await expect(WebMcpTools.run('get_security_warnings', { severity: 'bad' }, corpus())).rejects.toBeInstanceOf(WebMcpToolError);
    });

    it('adds the empty-state note when nothing has been captured', async () => {
      const result = await WebMcpTools.run('list_auth_sessions', {}, []);
      expect(result.sessions).toEqual([]);
      expect(result.total).toBe(0);
      expect(result.note).toMatch(/No captured sessions/);
      const search = await WebMcpTools.run('search_sessions', { query: 'x' }, null);
      expect(search.note).toMatch(/No captured sessions/);
    });

    it('does not add the empty-state note when captures exist', async () => {
      const result = await WebMcpTools.run('list_auth_sessions', { limit: 2 }, corpus());
      expect(result.note).toBeUndefined();
    });
  });

  describe('list_auth_sessions', () => {
    it('returns rows newest first with flow ids, provider, category and label', async () => {
      const result = await WebMcpTools.run('list_auth_sessions', {}, corpus());
      expect(result.total).toBe(9);
      expect(result.returned).toBe(9);
      expect(result.sessions[0].sessionId).toBe('ropc-1');
      expect(result.sessions.at(-1).sessionId).toBe('s-authz');
      const authz = result.sessions.find(s => s.sessionId === 's-authz');
      expect(authz).toMatchObject({
        flowType: 'pkce_flow', flowCategory: 'oauth', flowLabel: 'Authorization Code + PKCE',
        provider: { id: 'entra', label: 'Microsoft Entra ID' }, method: 'GET', status: 'completed', statusCode: 302,
        clientId: 'spa-app', host: 'login.microsoftonline.com', path: '/tenant/oauth2/v2.0/authorize',
        timestamp: new Date(T0).toISOString(), timestampMs: T0
      });
      expect(authz.flowId).toBe(`oauth_spa-app_${T0}`);
      expect(result.flows.count).toBe(FlowCorrelator.computeFlowGroups(corpus()).length);
    });

    it('applies limit and pagination metadata', async () => {
      const result = await WebMcpTools.run('list_auth_sessions', { limit: 3 }, corpus());
      expect(result.total).toBe(9);
      expect(result.returned).toBe(3);
      expect(result.limit).toBe(3);
      expect(result.sessions).toHaveLength(3);
    });

    it('filters by category or by exact flow type', async () => {
      const oauth = await WebMcpTools.run('list_auth_sessions', { flowType: 'oauth' }, corpus());
      expect(oauth.sessions.map(s => s.sessionId).sort()).toEqual(['ropc-1', 's-authz', 's-token']);
      const dc = await WebMcpTools.run('list_auth_sessions', { flowType: 'device_code' }, corpus());
      expect(dc.total).toBe(3);
      const exact = await WebMcpTools.run('list_auth_sessions', { flowType: 'fido2_assertion' }, corpus());
      expect(exact.sessions.map(s => s.sessionId)).toEqual(['f-assert']);
      const none = await WebMcpTools.run('list_auth_sessions', { flowType: 'wsfed' }, corpus());
      expect(none.total).toBe(0);
    });

    it('derives the user from login_hint, ROPC username or a JWT claim, and falls back to null', async () => {
      const rows = (await WebMcpTools.run('list_auth_sessions', {}, corpus())).sessions;
      const by = id => rows.find(s => s.sessionId === id);
      expect(by('s-authz')).toMatchObject({ user: 'alice@contoso.com', userSource: 'login_hint' });
      expect(by('ropc-1')).toMatchObject({ user: 'svc@contoso.com', userSource: 'username' });
      expect(by('f-assert')).toMatchObject({ user: null, userSource: null });
      const jwtOnly = makeRequest('https://idp/x?id_token_hint=' + idTokenHint(), { id: 'j', flowType: 'oauth_authorize' });
      const r = await WebMcpTools.run('list_auth_sessions', {}, [jwtOnly]);
      expect(r.sessions[0]).toMatchObject({ user: 'alice@contoso.com', userSource: 'id_token_hint:preferred_username' });
    });

    it('falls back to live provider detection when the capture predates provider stamping', async () => {
      const rows = (await WebMcpTools.run('list_auth_sessions', {}, corpus())).sessions;
      expect(rows.find(s => s.sessionId === 'v-pres').provider.id).toBe('entra-verified-id');
      expect(rows.find(s => s.sessionId === 'saml-1').provider).toEqual({ id: 'unknown', label: 'sp.example.com', hostname: 'sp.example.com' });
    });

    it('counts warnings and reports the highest severity per row', async () => {
      const rows = (await WebMcpTools.run('list_auth_sessions', {}, corpus())).sessions;
      expect(rows.find(s => s.sessionId === 'ropc-1')).toMatchObject({ warningCount: 2, maxSeverity: 'error' });
      expect(rows.find(s => s.sessionId === 'd-init')).toMatchObject({ warningCount: 0, maxSeverity: null });
      // s-authz: oauth redirect warning + jwt cae? (xms_cc present → no cae warning) → at least 1
      expect(rows.find(s => s.sessionId === 's-authz').warningCount).toBeGreaterThanOrEqual(1);
    });

    it('never leaks secrets through the URL column', async () => {
      const rows = (await WebMcpTools.run('list_auth_sessions', {}, [
        makeRequest('https://idp/token?client_secret=leak&client_id=a', { id: 'u', flowType: 'oauth_token' })
      ])).sessions;
      expect(rows[0].url).not.toContain('leak');
      expect(rows[0].url).toContain('client_id=a');
    });
  });

  describe('search_sessions', () => {
    it('matches the free-text query against url, label, provider, client id and user', async () => {
      const byUser = await WebMcpTools.run('search_sessions', { query: 'alice@contoso.com' }, corpus());
      expect(byUser.sessions.map(s => s.sessionId)).toEqual(['s-authz']);
      const byClient = await WebMcpTools.run('search_sessions', { query: 'cli-app' }, corpus());
      expect(byClient.total).toBe(3);
      const byLabel = await WebMcpTools.run('search_sessions', { query: 'presentation' }, corpus());
      expect(byLabel.sessions.map(s => s.sessionId)).toEqual(['v-pres']);
      const byProviderName = await WebMcpTools.run('search_sessions', { query: 'yubi' }, corpus());
      expect(byProviderName.total).toBe(0);
    });

    it('filters by provider id or label, status and status code', async () => {
      expect((await WebMcpTools.run('search_sessions', { provider: 'entra-verified-id' }, corpus())).sessions.map(s => s.sessionId)).toEqual(['v-pres']);
      // 7 sessions target login.microsoftonline.com (two stamped at capture, five detected live)
      expect((await WebMcpTools.run('search_sessions', { provider: 'Entra ID' }, corpus())).total).toBe(7);
      // 'entra' matches the entra id exactly and 'Microsoft Entra Verified ID' by label substring
      expect((await WebMcpTools.run('search_sessions', { provider: 'entra' }, corpus())).total).toBe(8);
      expect((await WebMcpTools.run('search_sessions', { status: 'error' }, corpus())).sessions.map(s => s.sessionId)).toEqual(['ropc-1']);
      expect((await WebMcpTools.run('search_sessions', { statusCode: 400 }, corpus())).sessions.map(s => s.sessionId)).toEqual(['d-poll-1']);
    });

    it('filters by time range with ISO strings or epoch milliseconds', async () => {
      const since = await WebMcpTools.run('search_sessions', { since: new Date(T0 + 40_000).toISOString() }, corpus());
      expect(since.sessions.map(s => s.sessionId).sort()).toEqual(['ropc-1', 'saml-1', 'v-pres']);
      const between = await WebMcpTools.run('search_sessions', { since: String(T0 + 10_000), until: String(T0 + 20_000) }, corpus());
      expect(between.sessions.map(s => s.sessionId).sort()).toEqual(['d-init', 'd-poll-1', 'd-poll-2']);
    });

    it('combines criteria, echoes them and honours the limit', async () => {
      const result = await WebMcpTools.run('search_sessions', { flowType: 'device_code', statusCode: 200, limit: 1 }, corpus());
      expect(result.total).toBe(2);
      expect(result.returned).toBe(1);
      expect(result.sessions).toHaveLength(1);
      expect(result.criteria).toEqual({ query: null, flowType: 'device_code', provider: null, status: null, statusCode: 200, since: null, until: null });
    });
  });

  describe('get_session_detail', () => {
    it('throws not_found for an unknown session id', async () => {
      await expect(WebMcpTools.run('get_session_detail', { sessionId: 'nope' }, corpus())).rejects.toMatchObject({ code: 'not_found' });
    });

    it('returns redacted request/response data and the OAuth analysis for a token exchange', async () => {
      const d = await WebMcpTools.run('get_session_detail', { sessionId: 's-token' }, corpus());
      expect(d.session.sessionId).toBe('s-token');
      expect(d.request.method).toBe('POST');
      expect(d.request.body.type).toBe('formData');
      expect(d.request.body.params.code).toBe('[REDACTED]');
      expect(d.request.body.params.code_verifier).toBe('v'.repeat(43));
      expect(d.request.body.params.client_id).toBe('spa-app');
      expect(d.request.headers.find(h => h.name === 'Authorization').value).toBe('Basic [REDACTED]');
      expect(d.response).toMatchObject({ status: 'completed', statusCode: 200, error: null });
      expect(d.oauth.authMethod).toBe('client_secret_basic');
      expect(d.related).toEqual({ flowId: `oauth_spa-app_${T0}`, flowType: 'oauth', stepIndex: 2, stepCount: 2 });
      expect(JSON.stringify(d)).not.toContain('AUTHCODE-SECRET');
      expect(JSON.stringify(d)).not.toContain('basic-secret');
    });

    it('redacts URL parameters and truncates id_token_hint on an authorization request', async () => {
      const d = await WebMcpTools.run('get_session_detail', { sessionId: 's-authz' }, corpus());
      expect(d.request.urlParams.client_id).toBe('spa-app');
      expect(d.request.urlParams.id_token_hint).toMatch(/truncated JWT/);
      expect(d.jwt).toHaveLength(1);
      expect(d.jwt[0]).toMatchObject({ source: 'id_token_hint', isEntraToken: true, caeEnabled: true });
      expect(d.jwt[0].summary.tenant).toBe('tenant');
      expect(d.warnings.map(w => w.rule)).toContain('redirect_uri_http');
    });

    it('surfaces FIDO2 authenticator data including BE/BS flags and the AAGUID lookup', async () => {
      const d = await WebMcpTools.run('get_session_detail', { sessionId: 'f-assert' }, corpus());
      expect(d.fido2.authenticatorData.flags).toMatchObject({ UP: true, UV: true, BE: true, BS: true, AT: true });
      expect(d.fido2.authenticatorData.signCount).toBe(9);
      expect(d.fido2.authenticatorData.attestedCredentialData.aaguid).toBe('ee882879-721c-4913-9775-3dfcce97072a');
      expect(d.fido2.authenticatorData.attestedCredentialData.authenticator.vendor).toBe('Yubico');
      expect(d.fido2.clientDataJSON).not.toHaveProperty('raw');
      expect(d.session.flowLabel).toBe('FIDO2 Authentication (Assertion)');
      expect(d.related.flowType).toBe('standalone');
    });

    it('surfaces Verified ID analysis and its warnings', async () => {
      const d = await WebMcpTools.run('get_session_detail', { sessionId: 'v-pres' }, corpus());
      expect(d.verifiedId).toMatchObject({ operation: 'Create Presentation Request', authority: 'did:web:contoso.com', callbackUrl: 'http://localhost:5000/cb' });
      expect(d.warnings.map(w => w.rule)).toEqual(['vid_callback_localhost']);
      expect(d.warnings[0]).toMatchObject({ source: 'verified-id', sessionId: 'v-pres', severity: 'warning', provider: 'entra-verified-id' });
    });

    it('decodes SAML messages including attributes and the security assessment', async () => {
      const d = await WebMcpTools.run('get_session_detail', { sessionId: 'saml-1' }, corpus());
      expect(d.saml.binding).toBe('post');
      expect(d.saml.messageType).toBe('SAMLResponse');
      expect(d.saml.parsed.assertion.nameID.value).toBe('bob@example.com');
      expect(d.saml.parsed.assertion.attributes).toEqual({ email: ['bob@example.com'] });
      expect(d.saml.warnings.map(w => w.rule)).toEqual(expect.arrayContaining(['saml_unsigned', 'saml_assertion_expired']));
      expect(d.warnings.every(w => w.source === 'saml')).toBe(true);
      expect(d.request.body.params.RelayState).toBe('rs');
    });

    it('never returns the full device code or the ROPC password', async () => {
      const poll = await WebMcpTools.run('get_session_detail', { sessionId: 'd-poll-1' }, corpus());
      expect(poll.oauth).not.toHaveProperty('deviceCode');
      expect(poll.oauth.deviceCodePrefix).toBe('DEVICE-CODE-1234…');
      const ropc = await WebMcpTools.run('get_session_detail', { sessionId: 'ropc-1' }, corpus());
      expect(ropc.request.body.params.password).toBe('[REDACTED]');
      expect(ropc.request.body.params.client_secret).toBe('[REDACTED]');
      expect(ropc.request.body.params.username).toBe('svc@contoso.com');
      expect(ropc.response.error).toBe('net::ERR_FAILED');
      expect(JSON.stringify(ropc)).not.toContain('Hunter2!');
    });

    it('parses raw form or JSON bodies and redacts them field by field', async () => {
      const form = makeRequest('https://idp/x', { id: 'raw-form', flowType: 'unknown', raw: 'grant_type=client_credentials&client_id=abc&client_secret=s3cret&scope=a%20b' });
      const f = await WebMcpTools.run('get_session_detail', { sessionId: 'raw-form' }, [form]);
      expect(f.request.body).toMatchObject({ type: 'raw', parsedAs: 'form' });
      expect(f.request.body.params).toEqual({ grant_type: 'client_credentials', client_id: 'abc', client_secret: '[REDACTED]', scope: 'a b' });
      expect(JSON.stringify(f)).not.toContain('s3cret');

      const json = makeRequest('https://idp/x', { id: 'raw-json', flowType: 'unknown', raw: JSON.stringify({ username: 'svc@contoso.com', password: 'Hunter2!', nested: { refresh_token: 'rt-1' } }) });
      const j = await WebMcpTools.run('get_session_detail', { sessionId: 'raw-json' }, [json]);
      expect(j.request.body).toMatchObject({ type: 'raw', parsedAs: 'json' });
      expect(j.request.body.params.username).toBe('svc@contoso.com');
      expect(j.request.body.params.password).toBe('[REDACTED]');
      expect(j.request.body.params.nested.refresh_token).toBe('[REDACTED]');
      expect(JSON.stringify(j)).not.toContain('Hunter2!');
      expect(JSON.stringify(j)).not.toContain('rt-1');
    });

    it('never returns raw body text that could not be parsed', async () => {
      const big = makeRequest('https://idp/x', { id: 'raw', flowType: 'unknown', raw: 'z'.repeat(10_000) });
      const d = await WebMcpTools.run('get_session_detail', { sessionId: 'raw' }, [big]);
      expect(d.request.body).toMatchObject({ type: 'raw', parsedAs: null });
      expect(d.request.body.raw).toMatch(/\[REDACTED raw body — 10000 chars/);
      expect(d.request.body.raw).not.toContain('zzz');
      expect(d.request.body.raw.length).toBeLessThan(200);
    });
  });

  describe('get_security_warnings', () => {
    it('aggregates oauth, verified-id, jwt and saml findings across sessions with rule ids', async () => {
      const result = await WebMcpTools.run('get_security_warnings', {}, corpus());
      const sources = new Set(result.warnings.map(w => w.source));
      for (const s of ['oauth', 'verified-id', 'saml']) expect(sources.has(s)).toBe(true);
      const rules = result.warnings.map(w => w.rule);
      expect(rules).toEqual(expect.arrayContaining(['ropc_deprecated', 'redirect_uri_http', 'client_auth_secret_basic', 'vid_callback_localhost', 'saml_unsigned', 'saml_assertion_expired']));
      for (const w of result.warnings) {
        expect(w).toEqual(expect.objectContaining({ sessionId: expect.any(String), flowId: expect.any(String), rule: expect.any(String), message: expect.any(String), url: expect.any(String), timestamp: expect.any(String) }));
        expect(['error', 'warning', 'info']).toContain(w.severity);
      }
      expect(result.total).toBe(result.warnings.length);
      expect(result.summary.error + result.summary.warning + result.summary.info).toBe(result.total);
    });

    it('orders error before warning before info, newest first within a severity', async () => {
      const result = await WebMcpTools.run('get_security_warnings', {}, corpus());
      const ranks = result.warnings.map(w => ({ error: 0, warning: 1, info: 2 })[w.severity]);
      expect([...ranks].sort((a, b) => a - b)).toEqual(ranks);
      expect(result.warnings[0]).toMatchObject({ rule: 'ropc_deprecated', severity: 'error', sessionId: 'ropc-1' });
      const warningsOnly = result.warnings.filter(w => w.severity === 'warning');
      for (let i = 1; i < warningsOnly.length; i++) expect(warningsOnly[i - 1].timestampMs).toBeGreaterThanOrEqual(warningsOnly[i].timestampMs);
    });

    it('filters by severity', async () => {
      const result = await WebMcpTools.run('get_security_warnings', { severity: 'error' }, corpus());
      expect(result.warnings.every(w => w.severity === 'error')).toBe(true);
      expect(result.total).toBe(1);
      expect(result.summary).toEqual({ error: 1, warning: 0, info: 0 });
    });

    it('includes JWT warnings decoded on demand and slugifies legacy warnings without a rule', async () => {
      const expired = idTokenHint({ exp: NOW_S - 100, xms_cc: undefined });
      const reqs = [
        makeRequest('https://login.microsoftonline.com/t/oauth2/v2.0/authorize?id_token_hint=' + expired, { id: 'j', flowType: 'oauth_authorize', timestamp: T0 }),
        makeRequest('https://idp/token', { id: 'legacy', flowType: 'oauth_token', timestamp: T0 + 1, oauthAnalysis: { label: 'x', warnings: [{ severity: 'warning', message: 'No state parameter — CSRF protection may be absent' }] } })
      ];
      const result = await WebMcpTools.run('get_security_warnings', {}, reqs);
      const rules = result.warnings.map(w => w.rule);
      expect(rules).toContain('jwt_expiry');
      expect(rules).toContain('jwt_cae_not_enabled');
      expect(rules).toContain('no_state_parameter_csrf_protection_may');
      expect(result.warnings.find(w => w.rule === 'jwt_expiry').source).toBe('jwt');
    });
  });

  describe('analyze_flow', () => {
    it('throws not_found for an unknown flow id', async () => {
      await expect(WebMcpTools.run('analyze_flow', { flowId: 'nope' }, corpus())).rejects.toMatchObject({ code: 'not_found' });
    });

    it('describes a device code flow with initiation, polls and token issuance', async () => {
      const flow = await WebMcpTools.run('analyze_flow', { flowId: 'init:cli-app:1' }, corpus());
      expect(flow.type).toBe('device_code');
      expect(flow.label).toBe('Device Code — cli-app…');
      expect(flow.stepCount).toBe(3);
      expect(flow.steps.map(s => s.description)).toEqual(['Initiation', 'Token issued', 'Token issued']);
      expect(flow.steps.map(s => s.step)).toEqual([1, 2, 3]);
      expect(flow.durationMs).toBe(10_000);
      expect(flow.startedAt).toBe(new Date(T0 + 10_000).toISOString());
      expect(flow.summary.deviceCode).toEqual({ initiations: 1, polls: 2, completedPolls: 1 });
      expect(flow.summary.grantType).toBe('device_code');
      expect(flow.summary.scopes).toEqual(['openid', 'offline_access']);
      expect(flow.summary.outcome).toBe('completed');
      expect(flow.provider.id).toBe('entra');
    });

    it('describes an authorization code + PKCE flow with client auth and aggregated warnings', async () => {
      const flow = await WebMcpTools.run('analyze_flow', { flowId: `oauth_spa-app_${T0}` }, corpus());
      expect(flow.type).toBe('oauth');
      expect(flow.label).toBe('OAuth Flow — Authorization Code + PKCE');
      expect(flow.steps.map(s => s.sessionId)).toEqual(['s-authz', 's-token']);
      expect(flow.summary).toMatchObject({
        grantType: 'authorization_code_pkce',
        pkce: { present: true, method: 'S256', compliant: true },
        clientAuthMethod: 'client_secret_basic',
        outcome: 'completed'
      });
      expect(flow.summary.scopes).toEqual(['openid', 'profile']);
      expect(flow.summary.scopeLabels.map(s => s.scope)).toEqual(['openid', 'profile']);
      expect(flow.user).toBe('alice@contoso.com');
      expect(flow.warnings.map(w => w.rule)).toEqual(expect.arrayContaining(['redirect_uri_http', 'client_auth_secret_basic']));
      expect(flow.steps[1].warningCount).toBe(2);
    });

    it('accepts a session id and returns a standalone flow for uncorrelated requests', async () => {
      const flow = await WebMcpTools.run('analyze_flow', { flowId: 'f-assert' }, corpus());
      expect(flow.type).toBe('standalone');
      expect(flow.flowId).toBe('f-assert');
      expect(flow.stepCount).toBe(1);
      expect(flow.label).toBe('FIDO2 Authentication (Assertion)');
      expect(flow.summary.pkce).toBeNull();
      expect(flow.summary.grantType).toBeNull();
    });

    it('summarises Verified ID flows and reports error outcomes', async () => {
      const t = T0;
      const reqs = [
        makeRequest('https://verifiedid.did.msidentity.com/v1.0/verifiableCredentials/createIssuanceRequest', { id: 'i1', flowType: 'did_issuance_request', timestamp: t, status: 'completed', didAnalysis: { operation: 'Create Issuance Request', credentialType: 'VerifiedEmployee', authority: 'did:web:contoso.com', warnings: [] } }),
        makeRequest('https://verifiedid.did.msidentity.com/v1.0/verifiableCredentials/requests/abcd', { id: 'i2', flowType: 'did_request_fetch', timestamp: t + 5000, status: 'error', error: 'net::ERR_ABORTED', didAnalysis: { operation: 'Fetch Request Object', requestId: 'abcd', warnings: [] } })
      ];
      const flow = await WebMcpTools.run('analyze_flow', { flowId: `did_verifiedid.did.msidentity.com_${t}` }, reqs);
      expect(flow.type).toBe('did');
      expect(flow.summary.verifiedId).toEqual({ operations: ['Create Issuance Request', 'Fetch Request Object'], credentialType: 'VerifiedEmployee', authority: 'did:web:contoso.com', requestId: 'abcd', requestStatus: null });
      expect(flow.summary.outcome).toBe('error');
      expect(flow.steps[0].description).toBe('Create Issuance Request');
    });
  });

  describe('get_token_claims', () => {
    it('decodes an id_token_hint from the URL with header, claims, AMR, platform and CAE', async () => {
      const result = await WebMcpTools.run('get_token_claims', { sessionId: 's-authz' }, corpus());
      expect(result.sessionId).toBe('s-authz');
      expect(result.note).toMatch(/Tokens issued by the identity provider/);
      expect(result.tokens).toHaveLength(1);
      const t = result.tokens[0];
      expect(t.source).toBe('id_token_hint');
      expect(t.header).toEqual({ alg: 'RS256', typ: 'JWT', kid: 'kid-1', x5t: null, x5tS256: null });
      expect(t.isEntraToken).toBe(true);
      expect(t.caeEnabled).toBe(true);
      expect(t.summary.tenant).toBe('tenant');
      expect(t.claims.find(c => c.name === 'tid')).toMatchObject({ label: 'Tenant ID', value: 'tenant' });
      expect(t.amr).toEqual([{ method: 'pwd', description: 'Password' }, { method: 'mfa', description: 'Multi-Factor Authentication (generic)' }]);
      expect(t.devicePlatform).toEqual({ code: '2', name: 'Windows' });
      expect(t.warnings).toEqual([]);
    });

    it('collects client_assertion, assertion and Bearer tokens from one request and ignores non-JWT values', async () => {
      const ca = buildJwt({ iss: 'app', sub: 'app', aud: 'https://login.microsoftonline.com/t/oauth2/v2.0/token', exp: NOW_S + 300 }, { alg: 'RS256', kid: 'k', 'x5t#S256': 'thumb' });
      const bearer = buildJwt({ iss: 'https://sts.windows.net/t/', aud: 'https://graph.microsoft.com', upn: 'carol@contoso.com', exp: NOW_S + 60, acct: 1 });
      const req = makeRequest('https://login.microsoftonline.com/t/oauth2/v2.0/token', {
        id: 'multi', flowType: 'client_credentials',
        formData: { grant_type: 'client_credentials', client_assertion: ca, client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', assertion: 'not-a-jwt' },
        requestHeaders: [{ name: 'Authorization', value: 'Bearer ' + bearer }]
      });
      const result = await WebMcpTools.run('get_token_claims', { sessionId: 'multi' }, [req]);
      expect(result.tokens.map(t => t.source)).toEqual(['client_assertion', 'authorization_bearer']);
      expect(result.tokens[0].header.x5tS256).toBe('thumb');
      expect(result.tokens[0].isEntraToken).toBe(false);
      expect(result.tokens[1].isEntraToken).toBe(true);
      expect(result.tokens[1].warnings.map(w => w.rule)).toEqual(expect.arrayContaining(['jwt_guest_account', 'jwt_cae_not_enabled']));
      expect(result.tokens[1].amr).toEqual([]);
      expect(result.tokens[1].devicePlatform).toBeNull();
    });

    it('returns an empty token list (with the note) when the request carries no JWT', async () => {
      const result = await WebMcpTools.run('get_token_claims', { sessionId: 'd-init' }, corpus());
      expect(result.tokens).toEqual([]);
      expect(result.note).toBeDefined();
    });

    it('throws not_found for an unknown session', async () => {
      await expect(WebMcpTools.run('get_token_claims', { sessionId: 'x' }, corpus())).rejects.toMatchObject({ code: 'not_found' });
    });
  });

  describe('helpers', () => {
    it('sanitizeParams redacts secrets and authorization codes, truncates decodable JWTs, keeps the rest', () => {
      const out = WebMcpTools.sanitizeParams({ code: 'c', client_secret: 's', client_assertion: buildJwt({ a: 1 }), state: 'st', nested: { password: 'p', list: ['x', { refresh_token: 'r' }] } });
      expect(out.code).toBe('[REDACTED]');
      expect(out.client_secret).toBe('[REDACTED]');
      expect(out.client_assertion).toMatch(/truncated JWT/);
      expect(out.state).toBe('st');
      expect(out.nested.password).toBe('[REDACTED]');
      expect(out.nested.list[1].refresh_token).toBe('[REDACTED]');
    });

    it('parseTime accepts ISO strings, epoch numbers and numeric strings', () => {
      expect(WebMcpTools.parseTime('2026-09-08T00:00:00Z')).toBe(Date.parse('2026-09-08T00:00:00Z'));
      expect(WebMcpTools.parseTime(1757300000000)).toBe(1757300000000);
      expect(WebMcpTools.parseTime('1757300000000')).toBe(1757300000000);
      expect(WebMcpTools.parseTime('yesterday')).toBeNull();
      expect(WebMcpTools.parseTime(null)).toBeNull();
    });

    it('findJwtCandidates reads form, URL and Bearer sources and de-duplicates', () => {
      const jwt = buildJwt({ a: 1 });
      const r = makeRequest('https://idp/x?request=' + jwt, { formData: { client_assertion: jwt, id_token_hint: 'plain' }, requestHeaders: [{ name: 'authorization', value: 'Bearer ' + jwt }] });
      expect(WebMcpTools.findJwtCandidates(r)).toEqual([{ source: 'client_assertion', jwt }]);
    });

    it('enforceSizeBudget trims oversized results and flags truncation', async () => {
      const reqs = Array.from({ length: 100 }, (_, i) => makeRequest(`https://idp/x${i}?state=${'s'.repeat(900)}`, { id: `r${i}`, flowType: 'oauth_authorize', timestamp: T0 + i, raw: 'q'.repeat(3000) }));
      const result = await WebMcpTools.run('list_auth_sessions', { limit: 100 }, reqs);
      expect(JSON.stringify(result).length).toBeLessThanOrEqual(WebMcpTools.MAX_RESULT_BYTES);
      expect(result.truncated).toBe(true);
      expect(result.returned).toBe(result.sessions.length);
      expect(result.sessions.length).toBeLessThan(100);
    });

    it('leaves small results untouched', async () => {
      const result = await WebMcpTools.run('list_auth_sessions', {}, corpus());
      expect(result.truncated).toBeUndefined();
    });

    it('fido2 details built from real authenticatorData round-trip through the tool', async () => {
      const { b64url: ad } = buildAuthenticatorData({ flags: { UP: true, UV: true, BE: true, BS: false, AT: true }, coseKey: coseEc2P256Key(), aaguid: 'd8522d9f-575b-4866-88a9-ba99fa02f35b', signCount: 3 });
      const Fido2Decoder = (await import('../../src/Fido2Decoder.js')).default;
      const analysis = Fido2Decoder.decodeFido2Request({ type: 'json', data: { authenticatorData: ad } });
      const req = makeRequest('https://idp/webauthn/assertion', { id: 'real', flowType: 'fido2_assertion', json: { authenticatorData: ad }, fido2Analysis: analysis });
      const d = await WebMcpTools.run('get_session_detail', { sessionId: 'real' }, [req]);
      expect(d.fido2.authenticatorData.flags.BE).toBe(true);
      expect(d.fido2.authenticatorData.flags.BS).toBe(false);
      expect(d.fido2.authenticatorData.attestedCredentialData.authenticator.name).toBe('YubiKey Bio Series');
      expect(d.fido2.authenticatorData.attestedCredentialData.credentialPublicKey.keyInfo.algorithmDescription).toMatch(/ES256/);
    });
  });
});
