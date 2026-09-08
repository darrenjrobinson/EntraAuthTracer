/**
 * Tests for FlowCorrelator — categories, filters, timeline grouping,
 * related-request lookup and status-bar counts.
 */

import FlowCorrelator from '../src/FlowCorrelator.js';
import { makeRequest } from './helpers.js';

// Every flowType SAMLTrace.detectFlowType / OAuthDecoder.detectFlowTypeFromBody can emit
const FLOW_TYPE_TABLE = [
  // SAML
  ['saml', 'saml'], ['wsfed', 'saml'], ['saml_ecp', 'saml'], ['adfs_saml', 'saml'],
  // FIDO2
  ['fido2_assertion', 'fido2'], ['fido2_attestation', 'fido2'], ['fido2_preflight', 'fido2'], ['fido2_webauthn', 'fido2'],
  // Device code
  ['device_code_initiation', 'device_code'], ['device_code_poll', 'device_code'],
  // OAuth / OIDC
  ['oauth_authorize', 'oauth'], ['oauth_token', 'oauth'], ['pkce_flow', 'oauth'], ['pkce_token_exchange', 'oauth'],
  ['authcode_token_exchange', 'oauth'], ['client_credentials', 'oauth'], ['refresh_token', 'oauth'], ['ropc', 'oauth'],
  ['oidc_discovery', 'oauth'], ['oidc_userinfo', 'oauth'], ['oidc_introspect', 'oauth'], ['oidc_revocation', 'oauth'],
  ['oidc_logout', 'oauth'], ['okta_authn', 'oauth'], ['okta_idx', 'oauth'],
  // Verified ID / DID
  ['did_issuance_request', 'did'], ['did_presentation_request', 'did'], ['did_request_fetch', 'did'], ['did_callback', 'did'],
  ['did_vc_service', 'did'], ['did_resolution', 'did'], ['did_status', 'did'],
  ['vc_presentation_openid4vp', 'did'], ['vc_issuance_openid4vci', 'did'],
  // Fallback
  ['unknown', 'other']
];

describe('FlowCorrelator', () => {
  describe('getFlowTypeCategory', () => {
    it('covers every known flow type in the explicit map', () => {
      expect(FLOW_TYPE_TABLE).toHaveLength(35);
      expect(Object.keys(FlowCorrelator.FLOW_TYPE_CATEGORY).sort()).toEqual(FLOW_TYPE_TABLE.map(([ft]) => ft).sort());
    });

    it.each(FLOW_TYPE_TABLE)('%s → %s', (flowType, category) => {
      expect(FlowCorrelator.getFlowTypeCategory(flowType)).toBe(category);
    });

    it('returns other for null, undefined and empty input', () => {
      expect(FlowCorrelator.getFlowTypeCategory(null)).toBe('other');
      expect(FlowCorrelator.getFlowTypeCategory(undefined)).toBe('other');
      expect(FlowCorrelator.getFlowTypeCategory('')).toBe('other');
    });

    it('falls back to prefix matching for flow types added later', () => {
      expect(FlowCorrelator.getFlowTypeCategory('fido2_future')).toBe('fido2');
      expect(FlowCorrelator.getFlowTypeCategory('device_code_refresh')).toBe('device_code');
      expect(FlowCorrelator.getFlowTypeCategory('did_future')).toBe('did');
      expect(FlowCorrelator.getFlowTypeCategory('vc_future')).toBe('did');
      expect(FlowCorrelator.getFlowTypeCategory('oidc_future')).toBe('oauth');
      expect(FlowCorrelator.getFlowTypeCategory('okta_future')).toBe('oauth');
      expect(FlowCorrelator.getFlowTypeCategory('saml_artifact')).toBe('saml');
      expect(FlowCorrelator.getFlowTypeCategory('something_else')).toBe('other');
    });

    it('only produces categories that have labels and a display order', () => {
      for (const [flowType] of FLOW_TYPE_TABLE) {
        const cat = FlowCorrelator.getFlowTypeCategory(flowType);
        expect(FlowCorrelator.CATEGORIES).toContain(cat);
        expect(typeof FlowCorrelator.CATEGORY_LABELS[cat]).toBe('string');
      }
      expect(FlowCorrelator.CATEGORY_LABELS.did).toBe('Verified ID');
    });
  });

  describe('isOAuthFlow', () => {
    it('is true for oauth and device_code categories only', () => {
      expect(FlowCorrelator.isOAuthFlow('pkce_flow')).toBe(true);
      expect(FlowCorrelator.isOAuthFlow('oidc_userinfo')).toBe(true);
      expect(FlowCorrelator.isOAuthFlow('device_code_poll')).toBe(true);
      expect(FlowCorrelator.isOAuthFlow('saml')).toBe(false);
      expect(FlowCorrelator.isOAuthFlow('fido2_assertion')).toBe(false);
      expect(FlowCorrelator.isOAuthFlow(null)).toBe(false);
    });
  });

  describe('applyFilters', () => {
    const requests = [
      makeRequest('https://login.microsoftonline.com/t/oauth2/v2.0/authorize?client_id=a', { id: 'a', flowType: 'oauth_authorize', status: 'completed' }),
      makeRequest('https://auth.example.com/connect/userinfo', { id: 'b', flowType: 'oidc_userinfo', status: 'error' }),
      makeRequest('https://adfs.contoso.com/adfs/ls/', { id: 'c', flowType: 'adfs_saml', status: 'completed' }),
      makeRequest('https://resolver.identity.foundation/1.0/identifiers/did:web:x', { id: 'd', flowType: 'did_resolution', status: 'pending' }),
      makeRequest('https://example.com/webauthn/assertion', { id: 'e', flowType: 'fido2_assertion', method: 'POST', status: 'completed' })
    ];
    const ids = (arr) => arr.map(r => r.id);

    it('returns the same array reference when no filter is active', () => {
      expect(FlowCorrelator.applyFilters(requests, {})).toBe(requests);
      expect(FlowCorrelator.applyFilters(requests, { search: '', method: '', flow: '', status: '' })).toBe(requests);
      expect(FlowCorrelator.applyFilters(requests)).toBe(requests);
    });

    it('matches the search text against the URL case-insensitively', () => {
      expect(ids(FlowCorrelator.applyFilters(requests, { search: 'ADFS' }))).toEqual(['c']);
      expect(ids(FlowCorrelator.applyFilters(requests, { search: 'example.com' }))).toEqual(['b', 'e']);
    });

    it('filters by exact HTTP method', () => {
      expect(ids(FlowCorrelator.applyFilters(requests, { method: 'POST' }))).toEqual(['e']);
      expect(ids(FlowCorrelator.applyFilters(requests, { method: 'GET' }))).toEqual(['a', 'b', 'c', 'd']);
    });

    it('filters by category, so OIDC auxiliary endpoints appear under OAuth and ADFS under SAML', () => {
      expect(ids(FlowCorrelator.applyFilters(requests, { flow: 'oauth' }))).toEqual(['a', 'b']);
      expect(ids(FlowCorrelator.applyFilters(requests, { flow: 'saml' }))).toEqual(['c']);
      expect(ids(FlowCorrelator.applyFilters(requests, { flow: 'did' }))).toEqual(['d']);
      expect(ids(FlowCorrelator.applyFilters(requests, { flow: 'fido2' }))).toEqual(['e']);
    });

    it('filters by status', () => {
      expect(ids(FlowCorrelator.applyFilters(requests, { status: 'error' }))).toEqual(['b']);
      expect(ids(FlowCorrelator.applyFilters(requests, { status: 'pending' }))).toEqual(['d']);
    });

    it('combines filters with AND semantics', () => {
      expect(ids(FlowCorrelator.applyFilters(requests, { flow: 'oauth', status: 'completed' }))).toEqual(['a']);
      expect(ids(FlowCorrelator.applyFilters(requests, { flow: 'oauth', method: 'POST' }))).toEqual([]);
    });

    it('tolerates requests without a url', () => {
      const result = FlowCorrelator.applyFilters([{ id: 'x', flowType: 'saml' }], { search: 'foo' });
      expect(result).toEqual([]);
    });
  });

  describe('computeFlowGroups', () => {
    const t0 = 1_700_000_000_000;

    it('groups device code initiation and polls by correlation key and labels with the client id', () => {
      const requests = [
        makeRequest('https://login.microsoftonline.com/t/oauth2/v2.0/devicecode', { id: 'i', flowType: 'device_code_initiation', timestamp: t0, deviceCodeCorrelationKey: 'init:app-client-id:1', oauthAnalysis: { clientId: 'app-client-id' } }),
        makeRequest('https://login.microsoftonline.com/t/oauth2/v2.0/token', { id: 'p2', flowType: 'device_code_poll', timestamp: t0 + 10000, deviceCodeCorrelationKey: 'init:app-client-id:1' }),
        makeRequest('https://login.microsoftonline.com/t/oauth2/v2.0/token', { id: 'p1', flowType: 'device_code_poll', timestamp: t0 + 5000, deviceCodeCorrelationKey: 'init:app-client-id:1' })
      ];
      const groups = FlowCorrelator.computeFlowGroups(requests);
      expect(groups).toHaveLength(1);
      expect(groups[0].type).toBe('device_code');
      expect(groups[0].key).toBe('init:app-client-id:1');
      expect(groups[0].label).toBe('Device Code — app-clie…');
      expect(groups[0].requests.map(r => r.id)).toEqual(['i', 'p1', 'p2']);
    });

    it('groups Verified ID requests per host within the 30 s window and splits on larger gaps', () => {
      const host = 'https://verifiedid.did.msidentity.com/v1.0/verifiableCredentials/createPresentationRequest';
      const requests = [
        makeRequest(host, { id: 'v1', flowType: 'did_presentation_request', timestamp: t0, didAnalysis: { operation: 'Create Presentation Request' } }),
        makeRequest(host, { id: 'v2', flowType: 'did_request_fetch', timestamp: t0 + 20000 }),
        makeRequest(host, { id: 'v3', flowType: 'did_callback', timestamp: t0 + FlowCorrelator.DID_SESSION_WINDOW_MS + 60000, didAnalysis: { operation: 'Request Callback / Event' } })
      ];
      const groups = FlowCorrelator.computeFlowGroups(requests);
      expect(groups).toHaveLength(2);
      expect(groups[0].type).toBe('did');
      expect(groups[0].label).toBe('Verified ID Flow — Create Presentation Request');
      expect(groups[0].requests.map(r => r.id)).toEqual(['v1', 'v2']);
      expect(groups[0].key).toBe(`did_verifiedid.did.msidentity.com_${t0}`);
      expect(groups[1].label).toBe('Request Callback / Event');
      expect(groups[1].requests.map(r => r.id)).toEqual(['v3']);
    });

    it('groups OAuth requests sharing a client id within 60 s, ignoring failed analyses', () => {
      const requests = [
        makeRequest('https://login.microsoftonline.com/t/oauth2/v2.0/authorize', { id: 'a1', flowType: 'pkce_flow', timestamp: t0, oauthAnalysis: { clientId: 'client-A', label: 'Authorization Code + PKCE' } }),
        makeRequest('https://login.microsoftonline.com/t/oauth2/v2.0/token', { id: 'a2', flowType: 'pkce_token_exchange', timestamp: t0 + 3000, oauthAnalysis: { clientId: 'client-A', label: 'Authorization Code + PKCE (Token Exchange)' } }),
        makeRequest('https://login.microsoftonline.com/t/oauth2/v2.0/token', { id: 'a3', flowType: 'refresh_token', timestamp: t0 + FlowCorrelator.OAUTH_SESSION_WINDOW_MS + 1000, oauthAnalysis: { clientId: 'client-A', label: 'Refresh Token' } }),
        makeRequest('https://login.microsoftonline.com/t/oauth2/v2.0/token', { id: 'bad', flowType: 'oauth_token', timestamp: t0 + 1000, oauthAnalysis: { error: 'OAuth analysis failed: boom' } })
      ];
      const groups = FlowCorrelator.computeFlowGroups(requests);
      const oauthGroups = groups.filter(g => g.type === 'oauth');
      expect(oauthGroups).toHaveLength(2);
      expect(oauthGroups[0].key).toBe(`oauth_client-A_${t0}`);
      expect(oauthGroups[0].label).toBe('OAuth Flow — Authorization Code + PKCE');
      expect(oauthGroups[0].requests.map(r => r.id)).toEqual(['a1', 'a2']);
      expect(oauthGroups[1].label).toBe('Refresh Token');
      expect(oauthGroups[1].requests.map(r => r.id)).toEqual(['a3']);
      const standalone = groups.find(g => g.type === 'standalone');
      expect(standalone.requests[0].id).toBe('bad');
      expect(standalone.key).toBe('bad');
      expect(standalone.label).toBeNull();
    });

    it('sorts groups by their first request timestamp and assigns each request to exactly one group', () => {
      const requests = [
        makeRequest('https://sp.example.com/acs', { id: 's', flowType: 'saml', timestamp: t0 + 500 }),
        makeRequest('https://login.microsoftonline.com/t/oauth2/v2.0/authorize', { id: 'o', flowType: 'oauth_authorize', timestamp: t0 + 100, oauthAnalysis: { clientId: 'c', label: 'Authorization Code' } }),
        makeRequest('https://login.microsoftonline.com/t/oauth2/v2.0/devicecode', { id: 'd', flowType: 'device_code_initiation', timestamp: t0, deviceCodeCorrelationKey: 'init:x:1' })
      ];
      const groups = FlowCorrelator.computeFlowGroups(requests);
      expect(groups.map(g => g.requests[0].id)).toEqual(['d', 'o', 's']);
      const all = groups.flatMap(g => g.requests.map(r => r.id)).sort();
      expect(all).toEqual(['d', 'o', 's']);
    });

    it('returns an empty array for no requests', () => {
      expect(FlowCorrelator.computeFlowGroups([])).toEqual([]);
    });
  });

  describe('findRelatedRequests', () => {
    const t0 = 1_700_000_000_000;
    const all = [
      makeRequest('https://x/devicecode', { id: 'i', timestamp: t0, deviceCodeCorrelationKey: 'k1', oauthAnalysis: { clientId: 'c1' } }),
      makeRequest('https://x/token', { id: 'p', timestamp: t0 + 5000, deviceCodeCorrelationKey: 'k1', oauthAnalysis: { clientId: 'c1' } }),
      makeRequest('https://x/authorize', { id: 'a', timestamp: t0 + 200, oauthAnalysis: { clientId: 'c2' } }),
      makeRequest('https://x/token', { id: 'b', timestamp: t0 + 100, oauthAnalysis: { clientId: 'c2' } }),
      makeRequest('https://x/token', { id: 'late', timestamp: t0 + 200 + FlowCorrelator.OAUTH_SESSION_WINDOW_MS + 1, oauthAnalysis: { clientId: 'c2' } }),
      makeRequest('https://x/saml', { id: 's', timestamp: t0 })
    ];

    it('prefers the device code correlation key over the client id', () => {
      expect(FlowCorrelator.findRelatedRequests(all[0], all).map(r => r.id)).toEqual(['p']);
    });

    it('matches OAuth requests with the same client id within the session window, sorted by time', () => {
      expect(FlowCorrelator.findRelatedRequests(all[2], all).map(r => r.id)).toEqual(['b']);
    });

    it('excludes the request itself', () => {
      expect(FlowCorrelator.findRelatedRequests(all[3], all).map(r => r.id)).not.toContain('b');
    });

    it('returns an empty array when nothing correlates', () => {
      expect(FlowCorrelator.findRelatedRequests(all[5], all)).toEqual([]);
    });
  });

  describe('getFlowStepDesc', () => {
    it('describes device code steps', () => {
      expect(FlowCorrelator.getFlowStepDesc({ flowType: 'device_code_initiation' }, 0)).toBe('Initiation');
      expect(FlowCorrelator.getFlowStepDesc({ flowType: 'device_code_poll', status: 'completed' }, 3)).toBe('Token issued');
      expect(FlowCorrelator.getFlowStepDesc({ flowType: 'device_code_poll', status: 'pending' }, 2)).toBe('Poll #2');
    });

    it('uses the Verified ID operation, then the OAuth label, then an empty string', () => {
      expect(FlowCorrelator.getFlowStepDesc({ flowType: 'did_callback', didAnalysis: { operation: 'Request Callback / Event' } }, 0)).toBe('Request Callback / Event');
      expect(FlowCorrelator.getFlowStepDesc({ flowType: 'pkce_flow', oauthAnalysis: { label: 'Authorization Code + PKCE' } }, 0)).toBe('Authorization Code + PKCE');
      expect(FlowCorrelator.getFlowStepDesc({ flowType: 'saml' }, 0)).toBe('');
    });
  });

  describe('countByCategory', () => {
    it('counts totals, per-category and errors — including Verified ID', () => {
      const requests = [
        makeRequest('https://a', { flowType: 'saml', status: 'completed' }),
        makeRequest('https://b', { flowType: 'oidc_discovery', status: 'error' }),
        makeRequest('https://c', { flowType: 'did_resolution', status: 'completed' }),
        makeRequest('https://d', { flowType: 'device_code_poll', status: 'error' }),
        makeRequest('https://e', { flowType: 'fido2_assertion', status: 'completed' }),
        makeRequest('https://f', { flowType: 'unknown', status: 'completed' })
      ];
      expect(FlowCorrelator.countByCategory(requests)).toEqual({
        total: 6,
        byCategory: { saml: 1, oauth: 1, did: 1, device_code: 1, fido2: 1, other: 1 },
        errors: 2
      });
    });

    it('returns zeros for an empty list', () => {
      expect(FlowCorrelator.countByCategory([])).toEqual({ total: 0, byCategory: {}, errors: 0 });
    });
  });
});
