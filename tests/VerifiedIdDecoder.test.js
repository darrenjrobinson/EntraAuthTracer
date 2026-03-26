/**
 * Tests for VerifiedIdDecoder and DID/VC-related SAMLTrace logic
 */

import VerifiedIdDecoder from '../src/VerifiedIdDecoder.js';
import samltrace from '../src/SAMLTrace.js';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeRequest(url, flowType, requestBody = null) {
  return { url, flowType, requestBody };
}

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
    ...extras,
  };
}

// ─── VerifiedIdDecoder.flattenBody ────────────────────────────────────────────

describe('VerifiedIdDecoder.flattenBody', () => {
  it('returns null for null input', () => {
    expect(VerifiedIdDecoder.flattenBody(null)).toBeNull();
  });

  it('returns JSON data as-is', () => {
    const body = { type: 'json', data: { credentialType: 'VerifiedEmployee' } };
    expect(VerifiedIdDecoder.flattenBody(body)).toEqual({ credentialType: 'VerifiedEmployee' });
  });

  it('flattens Chrome formData array values', () => {
    const body = { type: 'formData', data: { authority: ['https://example.com'], pin: ['1234'] } };
    const flat = VerifiedIdDecoder.flattenBody(body);
    expect(flat.authority).toBe('https://example.com');
    expect(flat.pin).toBe('1234');
  });

  it('passes through non-array formData values unchanged', () => {
    const body = { type: 'formData', data: { format: 'jwt_vc' } };
    expect(VerifiedIdDecoder.flattenBody(body).format).toBe('jwt_vc');
  });

  it('returns null for unknown body type', () => {
    expect(VerifiedIdDecoder.flattenBody({ type: 'raw', data: {} })).toBeNull();
  });
});

// ─── VerifiedIdDecoder.analyzeRequest — guard conditions ─────────────────────

describe('VerifiedIdDecoder.analyzeRequest — returns null for non-DID flows', () => {
  it('returns null when flowType is oauth_authorize', () => {
    const req = makeRequest('https://login.microsoftonline.com/authorize', 'oauth_authorize');
    expect(VerifiedIdDecoder.analyzeRequest(req)).toBeNull();
  });

  it('returns null when flowType is absent', () => {
    const req = makeRequest('https://login.microsoftonline.com/token', '');
    expect(VerifiedIdDecoder.analyzeRequest(req)).toBeNull();
  });

  it('returns null when flowType is fido2_assertion', () => {
    const req = makeRequest('https://example.com/webauthn/assertion', 'fido2_assertion');
    expect(VerifiedIdDecoder.analyzeRequest(req)).toBeNull();
  });
});

// ─── VerifiedIdDecoder.analyzeRequest — DID issuance request ─────────────────

describe('VerifiedIdDecoder.analyzeRequest — did_issuance_request', () => {
  const url = 'https://verifiedid.did.msidentity.com/v1.0/verifiableCredentials/createIssuanceRequest';

  it('returns a result object for did_issuance flow', () => {
    const req = makeRequest(url, 'did_issuance_request');
    const result = VerifiedIdDecoder.analyzeRequest(req);
    expect(result).not.toBeNull();
    expect(result.flowType).toBe('did_issuance_request');
  });

  it('sets operation to human-readable label', () => {
    const req = makeRequest(url, 'did_issuance_request');
    const result = VerifiedIdDecoder.analyzeRequest(req);
    expect(result.operation).toBe('Create Issuance Request');
  });

  it('records host and path', () => {
    const req = makeRequest(url, 'did_issuance_request');
    const result = VerifiedIdDecoder.analyzeRequest(req);
    expect(result.host).toBe('verifiedid.did.msidentity.com');
    expect(result.path).toContain('createIssuanceRequest');
  });

  it('extracts credentialType and authority from JSON body', () => {
    const req = makeRequest(url, 'did_issuance_request', {
      type: 'json',
      data: {
        credentialType: 'VerifiedEmployee',
        authority: 'did:web:example.com',
        manifest: 'https://example.com/manifest.json',
      },
    });
    const result = VerifiedIdDecoder.analyzeRequest(req);
    expect(result.credentialType).toBe('VerifiedEmployee');
    expect(result.authority).toBe('did:web:example.com');
    expect(result.manifestUrl).toBe('https://example.com/manifest.json');
  });

  it('sets pinRequired when pin field present in body', () => {
    const req = makeRequest(url, 'did_issuance_request', {
      type: 'json',
      data: { credentialType: 'MyVC', pin: '1234' },
    });
    const result = VerifiedIdDecoder.analyzeRequest(req);
    expect(result.pinRequired).toBe(true);
  });

  it('adds info warning for PIN requirement', () => {
    const req = makeRequest(url, 'did_issuance_request', {
      type: 'json',
      data: { credentialType: 'MyVC', pin: '1234' },
    });
    const result = VerifiedIdDecoder.analyzeRequest(req);
    const pinWarn = result.warnings.find(w => w.message.includes('PIN'));
    expect(pinWarn).toBeDefined();
    expect(pinWarn.severity).toBe('info');
  });

  it('adds info warning when QR code requested', () => {
    const req = makeRequest(url, 'did_issuance_request', {
      type: 'json',
      data: { includeQRCode: true },
    });
    const result = VerifiedIdDecoder.analyzeRequest(req);
    const qrWarn = result.warnings.find(w => w.message.includes('QR code'));
    expect(qrWarn).toBeDefined();
    expect(qrWarn.severity).toBe('info');
  });

  it('does NOT add QR warning when includeQRCode is false', () => {
    const req = makeRequest(url, 'did_issuance_request', {
      type: 'json',
      data: { includeQRCode: false },
    });
    const result = VerifiedIdDecoder.analyzeRequest(req);
    expect(result.warnings.some(w => w.message.includes('QR'))).toBe(false);
  });
});

// ─── VerifiedIdDecoder.analyzeRequest — DID presentation request ──────────────

describe('VerifiedIdDecoder.analyzeRequest — did_presentation_request', () => {
  const url = 'https://verifiedid.did.msidentity.com/v1.0/verifiableCredentials/createPresentationRequest';

  it('returns result with correct operation label', () => {
    const req = makeRequest(url, 'did_presentation_request');
    const result = VerifiedIdDecoder.analyzeRequest(req);
    expect(result.operation).toBe('Create Presentation Request');
  });

  it('extracts requestedCredentials array', () => {
    const req = makeRequest(url, 'did_presentation_request', {
      type: 'json',
      data: {
        requestedCredentials: [
          { type: 'VerifiedEmployee' },
          { type: 'VerifiableCredential' },
        ],
        includesReceipt: true,
      },
    });
    const result = VerifiedIdDecoder.analyzeRequest(req);
    expect(result.requestedCredentials).toEqual(['VerifiedEmployee', 'VerifiableCredential']);
    expect(result.includesReceipt).toBe(true);
  });

  it('extracts clientName from registration field', () => {
    const req = makeRequest(url, 'did_presentation_request', {
      type: 'json',
      data: { registration: { clientName: 'My App' } },
    });
    const result = VerifiedIdDecoder.analyzeRequest(req);
    expect(result.clientName).toBe('My App');
  });

  it('extracts callbackUrl from callback object', () => {
    const req = makeRequest(url, 'did_presentation_request', {
      type: 'json',
      data: { callback: { url: 'https://myapp.com/callback', state: 'abc123' } },
    });
    const result = VerifiedIdDecoder.analyzeRequest(req);
    expect(result.callbackUrl).toBe('https://myapp.com/callback');
    expect(result.callbackState).toBe('abc123');
  });

  it('adds warning for localhost callback URL', () => {
    const req = makeRequest(url, 'did_presentation_request', {
      type: 'json',
      data: { callback: { url: 'http://localhost:3000/callback' } },
    });
    const result = VerifiedIdDecoder.analyzeRequest(req);
    const localhostWarn = result.warnings.find(w => w.message.includes('localhost'));
    expect(localhostWarn).toBeDefined();
    expect(localhostWarn.severity).toBe('warning');
  });

  it('adds warning for 127.0.0.1 callback URL', () => {
    const req = makeRequest(url, 'did_presentation_request', {
      type: 'json',
      data: { callback: { url: 'http://127.0.0.1:8080/vc' } },
    });
    const result = VerifiedIdDecoder.analyzeRequest(req);
    expect(result.warnings.some(w => w.message.includes('localhost'))).toBe(true);
  });

  it('does NOT add localhost warning for production callback', () => {
    const req = makeRequest(url, 'did_presentation_request', {
      type: 'json',
      data: { callback: { url: 'https://myapp.azurewebsites.net/callback' } },
    });
    const result = VerifiedIdDecoder.analyzeRequest(req);
    expect(result.warnings.some(w => w.severity === 'warning')).toBe(false);
  });
});

// ─── VerifiedIdDecoder.analyzeRequest — DID resolution ───────────────────────

describe('VerifiedIdDecoder.analyzeRequest — did_resolution', () => {
  it('returns result for DID resolver endpoint', () => {
    const req = makeRequest(
      'https://resolver.identity.foundation/1.0/identifiers/did:web:example.com',
      'did_resolution'
    );
    const result = VerifiedIdDecoder.analyzeRequest(req);
    expect(result.operation).toBe('DID Document Resolution');
    expect(result.host).toBe('resolver.identity.foundation');
  });

  it('extracts DID identifier from path', () => {
    const req = makeRequest(
      'https://resolver.msidentity.com/v1.0/identifiers/did:ion:EiBAS_abcdef12345',
      'did_resolution'
    );
    const result = VerifiedIdDecoder.analyzeRequest(req);
    expect(result.did).toBe('did:ion:EiBAS_abcdef12345');
  });
});

// ─── VerifiedIdDecoder.analyzeRequest — credential status check ───────────────

describe('VerifiedIdDecoder.analyzeRequest — did_status', () => {
  it('returns result with status operation label', () => {
    const req = makeRequest(
      'https://verifiedid.did.msidentity.com/v1.0/statuslist/tenant123/list1',
      'did_status'
    );
    const result = VerifiedIdDecoder.analyzeRequest(req);
    expect(result.operation).toBe('Credential Status Check');
  });
});

// ─── VerifiedIdDecoder.analyzeRequest — OpenID4VP ────────────────────────────

describe('VerifiedIdDecoder.analyzeRequest — vc_presentation_openid4vp', () => {
  it('returns result with OpenID4VP label', () => {
    const req = makeRequest(
      'https://verifiedid.did.msidentity.com/v1.0/openid4vp/authorize',
      'vc_presentation_openid4vp'
    );
    const result = VerifiedIdDecoder.analyzeRequest(req);
    expect(result.operation).toBe('OpenID4VP Presentation');
  });

  it('extracts presentation_definition and input_descriptors', () => {
    const req = makeRequest(
      'https://verifiedid.did.msidentity.com/v1.0/openid4vp/authorize',
      'vc_presentation_openid4vp',
      {
        type: 'json',
        data: {
          presentation_definition: {
            id: 'pd1',
            input_descriptors: [
              { id: 'id1', name: 'EmployeeCredential' },
              { id: 'id2' },
            ],
          },
          vp_token: 'eyJ...',
        },
      }
    );
    const result = VerifiedIdDecoder.analyzeRequest(req);
    expect(result.presentationDefinition).toBe(true);
    expect(result.inputDescriptors).toContain('id1');
    expect(result.vpTokenPresent).toBe(true);
  });
});

// ─── VerifiedIdDecoder.analyzeRequest — OpenID4VCI ───────────────────────────

describe('VerifiedIdDecoder.analyzeRequest — vc_issuance_openid4vci', () => {
  it('returns result with OpenID4VCI label', () => {
    const req = makeRequest(
      'https://verifiedid.did.msidentity.com/v1.0/openid4vci/credential',
      'vc_issuance_openid4vci'
    );
    const result = VerifiedIdDecoder.analyzeRequest(req);
    expect(result.operation).toBe('OpenID4VCI Credential Issuance');
  });

  it('extracts credential_issuer, format, and proof presence', () => {
    const req = makeRequest(
      'https://verifiedid.did.msidentity.com/v1.0/openid4vci/credential',
      'vc_issuance_openid4vci',
      {
        type: 'json',
        data: {
          credential_issuer: 'https://issuer.example.com',
          format: 'jwt_vc_json',
          proof: { proof_type: 'jwt', jwt: 'eyJ...' },
        },
      }
    );
    const result = VerifiedIdDecoder.analyzeRequest(req);
    expect(result.credentialIssuer).toBe('https://issuer.example.com');
    expect(result.format).toBe('jwt_vc_json');
    expect(result.proofPresent).toBe(true);
  });
});

// ─── VerifiedIdDecoder.analyzeRequest — requestId extraction ─────────────────

describe('VerifiedIdDecoder.analyzeRequest — requestId extraction', () => {
  it('extracts request ID from path segment', () => {
    const req = makeRequest(
      'https://verifiedid.did.msidentity.com/v1.0/verifiableCredentials/request/abc-12345-xyz',
      'did_request_fetch'
    );
    const result = VerifiedIdDecoder.analyzeRequest(req);
    expect(result.requestId).toBe('abc-12345-xyz');
  });
});

// ─── SAMLTrace.isAuthenticationRequest — DID hosts ───────────────────────────

describe('SAMLTrace.isAuthenticationRequest — DID / Verified ID hosts', () => {
  const didHosts = [
    'https://verifiedid.did.msidentity.com/v1.0/verifiableCredentials/createIssuanceRequest',
    'https://beta.did.msidentity.com/v1.0/verifiableCredentials/createIssuanceRequest',
    'https://did.msidentity.com/v1.0/identifiers/did:web:example.com',
    'https://request.msidentity.com/v1.0/request/abc123',
    'https://resolver.msidentity.com/v1.0/identifiers/did:ion:abc',
    'https://resolver.identity.foundation/1.0/identifiers/did:web:example.com',
  ];

  didHosts.forEach(href => {
    it(`captures ${new URL(href).hostname}`, () => {
      const url = new URL(href);
      expect(samltrace.isAuthenticationRequest(url, makeDetails(href))).toBe(true);
    });
  });
});

// ─── SAMLTrace.isAuthenticationRequest — DID URL patterns ────────────────────

describe('SAMLTrace.isAuthenticationRequest — DID URL path patterns', () => {
  it('matches /verifiableCredentials/ path pattern', () => {
    const url = new URL('https://custom.idp.com/api/verifiableCredentials/createRequest');
    expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href))).toBe(true);
  });

  it('matches /openid4vp/ path pattern', () => {
    const url = new URL('https://custom.idp.com/openid4vp/authorize');
    expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href))).toBe(true);
  });

  it('matches /openid4vci/ path pattern', () => {
    const url = new URL('https://custom.idp.com/openid4vci/credential');
    expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href))).toBe(true);
  });

  it('matches /statuslist/ path pattern', () => {
    const url = new URL('https://custom.idp.com/statuslist/tenant/list1');
    expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href))).toBe(true);
  });

  it('matches /identifiers/did: path pattern', () => {
    const url = new URL('https://custom-resolver.com/v1/identifiers/did:web:example.com');
    expect(samltrace.isAuthenticationRequest(url, makeDetails(url.href))).toBe(true);
  });
});

// ─── SAMLTrace.detectFlowType — DID host routing ─────────────────────────────

describe('SAMLTrace.detectFlowType — DID / Verified ID flow detection', () => {
  it('returns did_issuance_request for /createIssuanceRequest on verifiedid host', () => {
    const url = new URL('https://verifiedid.did.msidentity.com/v1.0/verifiableCredentials/createIssuanceRequest');
    expect(samltrace.detectFlowType(url, makeDetails(url.href, 'POST'))).toBe('did_issuance_request');
  });

  it('returns did_issuance_request for beta host', () => {
    const url = new URL('https://beta.did.msidentity.com/v1.0/verifiableCredentials/createIssuanceRequest');
    expect(samltrace.detectFlowType(url, makeDetails(url.href, 'POST'))).toBe('did_issuance_request');
  });

  it('returns did_presentation_request for /createPresentationRequest', () => {
    const url = new URL('https://verifiedid.did.msidentity.com/v1.0/verifiableCredentials/createPresentationRequest');
    expect(samltrace.detectFlowType(url, makeDetails(url.href, 'POST'))).toBe('did_presentation_request');
  });

  it('returns did_request_fetch for /request/{id} path', () => {
    const url = new URL('https://verifiedid.did.msidentity.com/v1.0/verifiableCredentials/request/abc-123');
    expect(samltrace.detectFlowType(url, makeDetails(url.href))).toBe('did_request_fetch');
  });

  it('returns did_callback for /callback path', () => {
    const url = new URL('https://verifiedid.did.msidentity.com/v1.0/verifiableCredentials/callback');
    expect(samltrace.detectFlowType(url, makeDetails(url.href, 'POST'))).toBe('did_callback');
  });

  it('returns did_vc_service for unrecognised path on verifiedid host', () => {
    const url = new URL('https://verifiedid.did.msidentity.com/v1.0/verifiableCredentials/other');
    expect(samltrace.detectFlowType(url, makeDetails(url.href))).toBe('did_vc_service');
  });

  it('returns did_resolution for did.msidentity.com', () => {
    const url = new URL('https://did.msidentity.com/v1.0/identifiers/did:web:example.com');
    expect(samltrace.detectFlowType(url, makeDetails(url.href))).toBe('did_resolution');
  });

  it('returns did_resolution for resolver.msidentity.com', () => {
    const url = new URL('https://resolver.msidentity.com/v1.0/identifiers/did:ion:abc');
    expect(samltrace.detectFlowType(url, makeDetails(url.href))).toBe('did_resolution');
  });

  it('returns did_resolution for resolver.identity.foundation', () => {
    const url = new URL('https://resolver.identity.foundation/1.0/identifiers/did:web:example.com');
    expect(samltrace.detectFlowType(url, makeDetails(url.href))).toBe('did_resolution');
  });

  it('returns did_resolution for /identifiers/did: path on any host', () => {
    const url = new URL('https://custom-resolver.example.com/v1/identifiers/did:web:example.com');
    expect(samltrace.detectFlowType(url, makeDetails(url.href))).toBe('did_resolution');
  });

  it('returns did_status for /statuslist/ path', () => {
    const url = new URL('https://example.com/statuslist/tenant123/list1');
    expect(samltrace.detectFlowType(url, makeDetails(url.href))).toBe('did_status');
  });

  it('returns vc_presentation_openid4vp for /openid4vp/ path', () => {
    const url = new URL('https://example.com/openid4vp/authorize');
    expect(samltrace.detectFlowType(url, makeDetails(url.href))).toBe('vc_presentation_openid4vp');
  });

  it('returns vc_issuance_openid4vci for /openid4vci/ path', () => {
    const url = new URL('https://example.com/openid4vci/credential');
    expect(samltrace.detectFlowType(url, makeDetails(url.href))).toBe('vc_issuance_openid4vci');
  });

  it('DID detection does not interfere with regular OAuth on login.microsoftonline.com', () => {
    const url = new URL('https://login.microsoftonline.com/common/oauth2/v2.0/token');
    const result = samltrace.detectFlowType(url, makeDetails(url.href, 'POST', {
      requestBody: { formData: { grant_type: ['client_credentials'] } },
    }));
    expect(result).not.toMatch(/^did_/);
    expect(result).not.toMatch(/^vc_/);
  });
});

// ─── SAMLTrace.handleVerifiedIdRequest ───────────────────────────────────────

describe('SAMLTrace.handleVerifiedIdRequest', () => {
  it('attaches didAnalysis to a recognised DID request', () => {
    const requestData = makeRequest(
      'https://verifiedid.did.msidentity.com/v1.0/verifiableCredentials/createIssuanceRequest',
      'did_issuance_request'
    );
    samltrace.handleVerifiedIdRequest(requestData);
    expect(requestData.didAnalysis).toBeDefined();
    expect(requestData.didAnalysis.operation).toBe('Create Issuance Request');
  });

  it('does not attach didAnalysis when analyzeRequest returns null', () => {
    // flowType is not a DID type — analyzeRequest returns null
    const requestData = makeRequest('https://login.microsoftonline.com/token', 'oauth_token');
    samltrace.handleVerifiedIdRequest(requestData);
    expect(requestData.didAnalysis).toBeUndefined();
  });
});
