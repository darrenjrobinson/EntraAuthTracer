/**
 * Tests for Exporters — JSON / Markdown / TXT / print-HTML report builders.
 */

import Exporters from '../src/Exporters.js';
import { makeRequest, buildJwt } from './helpers.js';

const NOW = new Date('2026-09-08T01:02:03.456Z');
const VERSION = '1.1.0-test';

function sampleRequests() {
  return [
    makeRequest('https://login.microsoftonline.com/t/oauth2/v2.0/token?client_secret=urlsecret&client_id=app', {
      id: 'r1',
      timestamp: NOW.getTime() - 5000,
      flowType: 'client_credentials',
      status: 'completed',
      statusCode: 200,
      formData: { grant_type: 'client_credentials', client_id: 'app', client_secret: 's3cret', scope: 'https://graph.microsoft.com/.default' },
      requestHeaders: [
        { name: 'Authorization', value: 'Basic ' + btoa('app:s3cret') },
        { name: 'Content-Type', value: 'application/x-www-form-urlencoded' }
      ],
      responseHeaders: [{ name: 'Set-Cookie', value: 'x=y' }],
      oauthAnalysis: {
        label: 'Client Credentials (M2M)', clientId: 'app', grantType: 'client_credentials',
        authMethod: 'client_secret_basic', authMethodLabel: 'HTTP Basic (client_secret_basic)',
        scopes: ['https://graph.microsoft.com/.default'], scopeLabels: [{ scope: 'https://graph.microsoft.com/.default', label: 'Graph' }],
        warnings: [{ rule: 'client_auth_secret_basic', severity: 'info', message: 'Using HTTP Basic authentication (client_secret_basic)' }]
      }
    }),
    makeRequest('https://example.com/webauthn/assertion', {
      id: 'r2',
      timestamp: NOW.getTime() - 3000,
      flowType: 'fido2_assertion',
      status: 'completed',
      statusCode: 200,
      json: { clientDataJSON: 'abc', authenticatorData: 'def' },
      fido2Analysis: {
        type: 'fido2',
        clientDataJSON: { type: 'webauthn.get', origin: 'https://example.com', crossOrigin: false },
        authenticatorData: {
          flags: { UP: true, UV: true, BE: true, BS: true, AT: true, ED: false },
          signCount: 42,
          attestedCredentialData: {
            aaguid: 'ee882879-721c-4913-9775-3dfcce97072a',
            authenticator: { name: 'YubiKey 5 Series', vendor: 'Yubico', kind: 'roaming' },
            credentialPublicKey: { keyInfo: { algorithmDescription: 'ES256 (ECDSA w/ SHA-256)' } }
          }
        },
        attestationObject: { fmt: 'packed' }
      }
    }),
    makeRequest('https://verifiedid.did.msidentity.com/v1.0/verifiableCredentials/createIssuanceRequest', {
      id: 'r3',
      timestamp: NOW.getTime() - 1000,
      flowType: 'did_issuance_request',
      status: 'error',
      error: 'net::ERR_FAILED',
      didAnalysis: {
        operation: 'Create Issuance Request', credentialType: 'VerifiedEmployee', authority: 'did:web:contoso.com',
        callbackUrl: 'http://localhost:5000/cb',
        warnings: [{ rule: 'vid_callback_localhost', severity: 'warning', message: 'Callback URL points to localhost' }]
      }
    }),
    makeRequest('https://sp.example.com/acs?SAMLResponse=<script>alert(1)</script>', {
      id: 'r4',
      timestamp: NOW.getTime(),
      flowType: 'saml',
      status: 'pending',
      raw: 'plain text'
    })
  ];
}

describe('Exporters', () => {
  describe('filename / MIME / build dispatch', () => {
    it.each([
      ['json', 'entra-auth-trace_2026-09-08_01-02-03.json', 'application/json'],
      ['markdown', 'entra-auth-trace_2026-09-08_01-02-03.md', 'text/markdown'],
      ['txt', 'entra-auth-trace_2026-09-08_01-02-03.txt', 'text/plain'],
      ['pdf', 'entra-auth-trace_2026-09-08_01-02-03.html', 'text/html']
    ])('%s → %s (%s)', (format, filename, mime) => {
      expect(Exporters.filename(format, NOW)).toBe(filename);
      expect(Exporters.MIME[format]).toBe(mime);
      expect(typeof Exporters.build(format, sampleRequests(), NOW, VERSION)).toBe('string');
    });

    it('rejects unknown formats', () => {
      expect(() => Exporters.filename('docx', NOW)).toThrow(/Unknown export format/);
      expect(() => Exporters.build('docx', [], NOW, VERSION)).toThrow(/Unknown export format/);
    });
  });

  describe('buildJsonExport', () => {
    const parsed = () => JSON.parse(Exporters.buildJsonExport(sampleRequests(), NOW, VERSION));

    it('stamps the supplied version and counts', () => {
      const data = parsed();
      expect(data.export_metadata.extension_version).toBe(VERSION);
      expect(data.export_metadata.generated_at).toBe(NOW.toISOString());
      expect(data.export_metadata.total_requests).toBe(4);
      expect(data.requests).toHaveLength(4);
    });

    it('redacts Authorization and Set-Cookie headers', () => {
      const [r1] = parsed().requests;
      expect(r1.request_headers.find(h => h.name === 'Authorization').value).toBe('Basic [REDACTED]');
      expect(r1.request_headers.find(h => h.name === 'Content-Type').value).toBe('application/x-www-form-urlencoded');
      expect(r1.response_headers[0].value).toBe('[REDACTED]');
    });

    it('redacts client_secret in the form body and in the URL', () => {
      const [r1] = parsed().requests;
      expect(r1.request_body.data.client_secret).toEqual(['[REDACTED]']);
      expect(r1.request_body.data.client_id).toEqual(['app']);
      expect(new URL(r1.url).searchParams.get('client_secret')).toBe('[REDACTED]');
      expect(new URL(r1.url).searchParams.get('client_id')).toBe('app');
    });

    it('never leaks the secret anywhere in the document', () => {
      const text = Exporters.buildJsonExport(sampleRequests(), NOW, VERSION);
      expect(text).not.toContain('s3cret');
      expect(text).not.toContain('urlsecret');
      expect(text).not.toContain(btoa('app:s3cret'));
    });

    it('includes analyses and flow category, omits absent optional fields', () => {
      const [r1, r2, r3, r4] = parsed().requests;
      expect(r1.oauth_analysis.grantType).toBe('client_credentials');
      expect(r1.flow_category).toBe('oauth');
      expect(r2.fido2_analysis.authenticatorData.attestedCredentialData.aaguid).toBe('ee882879-721c-4913-9775-3dfcce97072a');
      expect(r3.did_analysis.operation).toBe('Create Issuance Request');
      expect(r3.error).toBe('net::ERR_FAILED');
      expect(r3.flow_category).toBe('did');
      expect(r4).not.toHaveProperty('request_headers');
      expect(r4).not.toHaveProperty('oauth_analysis');
      // unparseable raw text is never exported verbatim
      expect(r4.request_body.type).toBe('raw');
      expect(r4.request_body.redacted).toBe(true);
      expect(r4.request_body.data).toMatch(/REDACTED raw body/);
      expect(JSON.stringify(r4)).not.toContain('plain text');
    });

    it('formats timestamps as ISO strings and status codes as numbers', () => {
      const [r1] = parsed().requests;
      expect(r1.timestamp).toBe(new Date(NOW.getTime() - 5000).toISOString());
      expect(r1.status_code).toBe(200);
    });
  });

  describe('buildMarkdownExport', () => {
    const md = () => Exporters.buildMarkdownExport(sampleRequests(), NOW, VERSION);

    it('contains the version line, summary counts and per-request sections', () => {
      const out = md();
      expect(out).toContain(`**Extension:** Entra Auth Tracer v${VERSION}`);
      expect(out).toContain('| **Total Requests** | 4 |');
      expect(out).toContain('| **Completed** | 2 |');
      expect(out).toContain('| **Errors** | 1 |');
      expect(out).toContain('| **Pending** | 1 |');
      expect(out).toContain('### Request 1: POST /t/oauth2/v2.0/token');
    });

    it('lists warnings with severity tags and the client auth method', () => {
      const out = md();
      expect(out).toContain('- [INFO] Using HTTP Basic authentication (client_secret_basic)');
      expect(out).toContain('- [WARNING] Callback URL points to localhost');
      expect(out).toContain('| **Client Auth** | HTTP Basic (client_secret_basic) |');
    });

    it('describes the FIDO2 authenticator, flags and attestation format', () => {
      const out = md();
      expect(out).toContain('| **Authenticator** | YubiKey 5 Series (Yubico) |');
      expect(out).toContain('| **AAGUID** | `ee882879-721c-4913-9775-3dfcce97072a` |');
      expect(out).toContain('| **Flags** | UP UV BE BS AT |');
      expect(out).toContain('| **Sign Count** | 42 |');
      expect(out).toContain('| **Attestation Format** | packed |');
    });

    it('redacts the URL and links the correct repository', () => {
      const out = md();
      expect(out).not.toContain('urlsecret');
      expect(out).toContain('client_secret=%5BREDACTED%5D');
      expect(out).toContain('https://github.com/darrenjrobinson/EntraAuthTracer');
      expect(out).not.toContain('DarrenRobinson/EntraAuthTracer');
    });
  });

  describe('buildTxtExport', () => {
    const txt = () => Exporters.buildTxtExport(sampleRequests(), NOW, VERSION);

    it('contains the version and redacted headers/body', () => {
      const out = txt();
      expect(out).toContain(`Extension : Entra Auth Tracer v${VERSION}`);
      expect(out).toContain('  Authorization: Basic [REDACTED]');
      expect(out).toContain('  client_secret=[REDACTED]');
      expect(out).toContain('  client_id=app');
      expect(out).toContain('  Set-Cookie: [REDACTED]');
      expect(out).not.toContain('s3cret');
    });

    it('prints JSON bodies and the placeholder for unparseable raw bodies', () => {
      const out = txt();
      expect(out).toContain('[REDACTED raw body');
      expect(out).not.toContain('  plain text');
      expect(out).toContain('  {"clientDataJSON":"abc","authenticatorData":"def"}');
    });

    it('includes FIDO2 and Verified ID sections', () => {
      const out = txt();
      expect(out).toContain('  Authenticator: YubiKey 5 Series (Yubico)');
      expect(out).toContain('  Flags       : UP UV BE BS AT');
      expect(out).toContain('  Operation   : Create Issuance Request');
      expect(out).toContain('    [WARNING] Callback URL points to localhost');
    });
  });

  describe('buildPdfHtml', () => {
    const html = () => Exporters.buildPdfHtml(sampleRequests(), NOW, VERSION);

    it('stamps the version and category-based summary rows including Verified ID', () => {
      const out = html();
      expect(out).toContain(`Entra Auth Tracer v${VERSION}`);
      expect(out).toContain('<tr><td>OAuth</td><td>1</td></tr>');
      expect(out).toContain('<tr><td>FIDO2</td><td>1</td></tr>');
      expect(out).toContain('<tr><td>Verified ID</td><td>1</td></tr>');
      expect(out).toContain('<tr><td>SAML</td><td>1</td></tr>');
    });

    it('escapes request-derived values', () => {
      const out = html();
      expect(out).not.toContain('<script>alert(1)</script>');
      expect(out).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    });

    it('renders OAuth, FIDO2 and Verified ID sections with redacted URL', () => {
      const out = html();
      expect(out).toContain('<h4>OAuth 2.1 Analysis</h4>');
      expect(out).toContain('<h4>FIDO2 Analysis</h4>');
      expect(out).toContain('<h4>Verified ID / DID Analysis</h4>');
      expect(out).toContain('YubiKey 5 Series (Yubico)');
      expect(out).toContain('[WARNING] Callback URL points to localhost');
      expect(out).not.toContain('urlsecret');
    });

    it('produces a self-contained HTML document', () => {
      const out = html();
      expect(out.startsWith('<!DOCTYPE html>')).toBe(true);
      expect(out).toContain('</html>');
      expect(out).toContain('@media print');
    });
  });

  describe('edge cases', () => {
    it('handles an empty request list in every format', () => {
      for (const format of Exporters.FORMATS) {
        const out = Exporters.build(format, [], NOW, VERSION);
        expect(typeof out).toBe('string');
        expect(out.length).toBeGreaterThan(0);
      }
      expect(JSON.parse(Exporters.buildJsonExport([], NOW, VERSION)).requests).toEqual([]);
    });

    it('truncates client_assertion instead of removing it', () => {
      const jwt = buildJwt({ iss: 'app' });
      const req = makeRequest('https://idp/token', { formData: { grant_type: 'client_credentials', client_assertion: jwt, client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer' } });
      const data = JSON.parse(Exporters.buildJsonExport([req], NOW, VERSION));
      expect(data.requests[0].request_body.data.client_assertion[0]).toMatch(/truncated JWT/);
      expect(data.requests[0].request_body.data.client_assertion_type[0]).toBe('urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
    });
  });
});
