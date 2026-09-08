/**
 * Tests for SamlDecoder
 */

import SamlDecoder from '../src/SamlDecoder.js';
import { utf8ToB64 } from './helpers.js';
const zlib = require('zlib');

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Base64-encode a UTF-8 string (POST binding: no deflate) */
function b64Encode(str) {
  return utf8ToB64(str);
}

/**
 * Create a redirect-binding encoded string: deflate-raw compress the XML,
 * then base64url-encode it (SAML redirect binding format).
 */
function deflateBase64url(xml) {
  const compressed = zlib.deflateRawSync(Buffer.from(xml, 'utf-8'));
  // base64url: use + → - and / → _ and strip padding
  return Buffer.from(compressed).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Minimal SAML AuthnRequest XML */
const AUTHN_REQUEST_XML = `<samlp:AuthnRequest
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="_test123" Version="2.0"
  IssueInstant="2024-01-01T00:00:00Z"
  Destination="https://idp.example.com/sso"
  AssertionConsumerServiceURL="https://sp.example.com/acs"
  ProviderName="TestSP">
  <saml:Issuer>https://sp.example.com</saml:Issuer>
  <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" AllowCreate="true"/>
  <samlp:RequestedAuthnContext Comparison="exact">
    <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
  </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>`;

/** Minimal SAML Response XML with Assertion */
const RESPONSE_XML = `<samlp:Response
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="_resp456" Version="2.0"
  IssueInstant="2024-01-01T00:00:01Z"
  InResponseTo="_req123"
  Destination="https://sp.example.com/acs">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion ID="_assertion1" IssueInstant="2024-01-01T00:00:01Z">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
        SPNameQualifier="https://sp.example.com">user@example.com</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotBefore="2024-01-01T00:00:00Z" NotOnOrAfter="2024-01-01T01:00:00Z">
      <saml:AudienceRestriction>
        <saml:Audience>https://sp.example.com</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2024-01-01T00:00:00Z" SessionIndex="_session1">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="email">
        <saml:AttributeValue>user@example.com</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="groups">
        <saml:AttributeValue>admins</saml:AttributeValue>
        <saml:AttributeValue>users</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`;

/** Minimal SAML LogoutRequest XML */
const LOGOUT_REQUEST_XML = `<samlp:LogoutRequest
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="_logout1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <saml:NameID>user@example.com</saml:NameID>
  <samlp:SessionIndex>_session1</samlp:SessionIndex>
</samlp:LogoutRequest>`;

/** Minimal SAML LogoutResponse XML */
const LOGOUT_RESPONSE_XML = `<samlp:LogoutResponse
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  ID="_logoutresp1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"
  InResponseTo="_logout1">
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    <samlp:StatusMessage>Successfully logged out</samlp:StatusMessage>
  </samlp:Status>
</samlp:LogoutResponse>`;

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('SamlDecoder', () => {
  describe('extract', () => {
    it('should return null for a request with no SAML data', () => {
      const request = { url: 'https://example.com/page', requestBody: null };
      expect(SamlDecoder.extract(request)).toBeNull();
    });

    it('should detect SAMLRequest in URL query string (redirect binding)', () => {
      const request = { url: 'https://idp.example.com/sso?SAMLRequest=encoded123', requestBody: null };
      const result = SamlDecoder.extract(request);
      expect(result).not.toBeNull();
      expect(result.messageType).toBe('SAMLRequest');
      expect(result.binding).toBe('redirect');
      expect(result.raw).toBe('encoded123');
    });

    it('should detect SAMLResponse in URL query string (redirect binding)', () => {
      const request = { url: 'https://sp.example.com/acs?SAMLResponse=base64data', requestBody: null };
      const result = SamlDecoder.extract(request);
      expect(result.messageType).toBe('SAMLResponse');
      expect(result.binding).toBe('redirect');
    });

    it('should detect wresult in URL query string (WS-Fed)', () => {
      const request = { url: 'https://sp.example.com/acs?wresult=%3CXml%2F%3E', requestBody: null };
      const result = SamlDecoder.extract(request);
      expect(result.messageType).toBe('WSFedResult');
      expect(result.binding).toBe('redirect');
      expect(result.preDecoded).toBe(true);
    });

    it('should detect SAMLRequest in POST body (POST binding)', () => {
      const request = {
        url: 'https://idp.example.com/sso',
        requestBody: { type: 'formData', data: { SAMLRequest: ['encodedXml'] } }
      };
      const result = SamlDecoder.extract(request);
      expect(result.messageType).toBe('SAMLRequest');
      expect(result.binding).toBe('post');
      expect(result.raw).toBe('encodedXml');
    });

    it('should detect SAMLResponse in POST body', () => {
      const request = {
        url: 'https://sp.example.com/acs',
        requestBody: { type: 'formData', data: { SAMLResponse: ['encodedResp'] } }
      };
      const result = SamlDecoder.extract(request);
      expect(result.messageType).toBe('SAMLResponse');
      expect(result.binding).toBe('post');
    });

    it('should detect wresult in POST body', () => {
      const request = {
        url: 'https://sp.example.com/acs',
        requestBody: { type: 'formData', data: { wresult: ['<xml/>'] } }
      };
      const result = SamlDecoder.extract(request);
      expect(result.messageType).toBe('WSFedResult');
      expect(result.preDecoded).toBe(true);
    });
  });

  describe('decode', () => {
    it('should decode a preDecoded (WS-Fed) value with decodeURIComponent', async () => {
      const extracted = { preDecoded: true, raw: '%3CXml%20%2F%3E', binding: 'redirect' };
      const result = await SamlDecoder.decode(extracted);
      expect(result).toBe('<Xml />');
    });

    it('should return raw value if decodeURIComponent fails', async () => {
      const extracted = { preDecoded: true, raw: '%E0%A4%A', binding: 'redirect' }; // Invalid URI
      const result = await SamlDecoder.decode(extracted);
      expect(result).toBe('%E0%A4%A');
    });

    it('should base64-decode a POST binding payload', async () => {
      const xml = '<test />';
      const b64 = btoa(xml);
      const extracted = { raw: b64, binding: 'post', preDecoded: false };
      const result = await SamlDecoder.decode(extracted);
      expect(result).toBe(xml);
    });

    it('should decompress a redirect binding payload via inflateRaw', async () => {
      const xml = '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" />';
      const b64url = deflateBase64url(xml);
      const extracted = { raw: b64url, binding: 'redirect', preDecoded: false };
      const result = await SamlDecoder.decode(extracted);
      expect(result).toBe(xml);
    });
  });

  describe('parse', () => {
    it('should return an error object for invalid XML', () => {
      const result = SamlDecoder.parse('this is not xml <<<');
      expect(result.error).toBeDefined();
    });

    it('should parse an AuthnRequest and return correct base fields', () => {
      const result = SamlDecoder.parse(AUTHN_REQUEST_XML);
      expect(result.messageType).toBe('AuthnRequest');
      expect(result.id).toBe('_test123');
      expect(result.version).toBe('2.0');
      expect(result.destination).toBe('https://idp.example.com/sso');
      expect(result.issuer).toBe('https://sp.example.com');
    });

    it('should parse AuthnRequest-specific fields', () => {
      const result = SamlDecoder.parse(AUTHN_REQUEST_XML);
      expect(result.assertionConsumerServiceURL).toBe('https://sp.example.com/acs');
      expect(result.providerName).toBe('TestSP');
      expect(result.nameIDPolicy).not.toBeNull();
      expect(result.nameIDPolicy.allowCreate).toBe('true');
      expect(result.requestedAuthnContext).not.toBeNull();
      expect(result.requestedAuthnContext.classRefs).toHaveLength(1);
    });

    it('should parse a SAML Response with status and assertion', () => {
      const result = SamlDecoder.parse(RESPONSE_XML);
      expect(result.messageType).toBe('Response');
      expect(result.inResponseTo).toBe('_req123');
      expect(result.status.isSuccess).toBe(true);
      expect(result.status.code).toBe('Success');
      expect(result.assertion).not.toBeNull();
    });

    it('should parse assertion fields including NameID and conditions', () => {
      const result = SamlDecoder.parse(RESPONSE_XML);
      const a = result.assertion;
      expect(a.nameID.value).toBe('user@example.com');
      expect(a.nameID.format).toContain('persistent');
      expect(a.conditions.notBefore).toBe('2024-01-01T00:00:00Z');
      expect(a.conditions.audiences).toContain('https://sp.example.com');
    });

    it('should parse assertion attributes including multi-value', () => {
      const result = SamlDecoder.parse(RESPONSE_XML);
      const attrs = result.assertion.attributes;
      expect(attrs['email']).toEqual(['user@example.com']);
      expect(attrs['groups']).toEqual(['admins', 'users']);
    });

    it('should parse assertion authnStatement', () => {
      const result = SamlDecoder.parse(RESPONSE_XML);
      const stmt = result.assertion.authnStatement;
      expect(stmt.sessionIndex).toBe('_session1');
      expect(stmt.authnContextClassRef).toContain('Password');
    });

    it('should parse a LogoutRequest', () => {
      const result = SamlDecoder.parse(LOGOUT_REQUEST_XML);
      expect(result.messageType).toBe('LogoutRequest');
      expect(result.nameID).toBe('user@example.com');
      expect(result.sessionIndex).toBe('_session1');
    });

    it('should parse a LogoutResponse with status message', () => {
      const result = SamlDecoder.parse(LOGOUT_RESPONSE_XML);
      expect(result.messageType).toBe('LogoutResponse');
      expect(result.inResponseTo).toBe('_logout1');
      expect(result.status.isSuccess).toBe(true);
      expect(result.status.message).toBe('Successfully logged out');
    });

    it('should return base fields for an unknown root element', () => {
      const xml = `<saml:Unknown xmlns:saml="urn:oasis:names:tc:SAML:2.0:protocol" ID="_u1" Version="2.0"/>`;
      const result = SamlDecoder.parse(xml);
      expect(result.messageType).toBe('Unknown');
      expect(result.id).toBe('_u1');
    });
  });

  describe('getText', () => {
    it('should extract text content of a named element', () => {
      const parser = new DOMParser();
      const doc = parser.parseFromString(
        `<root xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Issuer>https://example.com</saml:Issuer></root>`,
        'application/xml'
      );
      expect(SamlDecoder.getText(doc, 'Issuer')).toBe('https://example.com');
    });

    it('should return null when element is not found', () => {
      const parser = new DOMParser();
      const doc = parser.parseFromString('<root/>', 'application/xml');
      expect(SamlDecoder.getText(doc, 'Missing')).toBeNull();
    });
  });

  describe('prettyPrintXml', () => {
    it('should indent nested XML elements', () => {
      const xml = '<root><child><leaf/></child></root>';
      const result = SamlDecoder.prettyPrintXml(xml);
      expect(result).toContain('\n');
      const lines = result.split('\n');
      expect(lines[0]).toBe('<root>');
      expect(lines[1]).toMatch(/^\s+<child>/);
    });

    it('should handle self-closing elements', () => {
      const xml = '<root><item name="x"/></root>';
      const result = SamlDecoder.prettyPrintXml(xml);
      expect(result).toContain('<item name="x"/>');
    });

    it('should handle closing tags with de-indentation', () => {
      const xml = '<a><b></b></a>';
      const result = SamlDecoder.prettyPrintXml(xml);
      const lines = result.split('\n').filter(l => l.trim());
      expect(lines).toHaveLength(4);
    });
  });

  describe('decodeSamlFromRequest - pipeline', () => {
    it('should return null for a non-SAML request', async () => {
      const request = { url: 'https://example.com/page', requestBody: null };
      const result = await SamlDecoder.decodeSamlFromRequest(request);
      expect(result).toBeNull();
    });

    it('should decode a POST-binding SAMLRequest through the full pipeline', async () => {
      const b64 = b64Encode(AUTHN_REQUEST_XML);
      const request = {
        url: 'https://idp.example.com/sso',
        requestBody: { type: 'formData', data: { SAMLRequest: [b64] } }
      };
      const result = await SamlDecoder.decodeSamlFromRequest(request);
      expect(result).not.toBeNull();
      expect(result.binding).toBe('post');
      expect(result.messageType).toBe('SAMLRequest');
      expect(result.parsed.messageType).toBe('AuthnRequest');
      expect(result.xmlText).toContain('AuthnRequest');
    });

    it('should decode a WS-Fed wresult through the full pipeline', async () => {
      const simpleXml = '<t:RequestSecurityTokenResponse xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust"/>';
      const request = {
        url: `https://sp.example.com/acs?wresult=${encodeURIComponent(simpleXml)}`,
        requestBody: null
      };
      const result = await SamlDecoder.decodeSamlFromRequest(request);
      expect(result).not.toBeNull();
      expect(result.messageType).toBe('WSFedResult');
    });

    it('should handle decode errors and return error object', async () => {
      // A redirect-binding SAMLRequest with invalid deflated data will fail inflate
      const request = { url: 'https://idp.example.com/?SAMLRequest=!!!invalid!!!', requestBody: null };
      const result = await SamlDecoder.decodeSamlFromRequest(request);
      // Returns an error object (not null) with binding and messageType set
      expect(result).not.toBeNull();
      expect(result.error).toBeDefined();
    });

    it('should attach the security assessment to the pipeline result', async () => {
      const request = {
        url: 'https://sp.example.com/acs',
        requestBody: { type: 'formData', data: { SAMLResponse: [b64Encode(RESPONSE_XML)] } }
      };
      const result = await SamlDecoder.decodeSamlFromRequest(request);
      expect(Array.isArray(result.warnings)).toBe(true);
      expect(result.warnings.map(w => w.rule)).toContain('saml_unsigned');
    });
  });

  // ─── Signature / encryption detection ────────────────────────────────────

  const SIGNATURE = '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo/><ds:SignatureValue>abc</ds:SignatureValue></ds:Signature>';

  describe('parse — signature and encryption flags', () => {
    it('reports unsigned messages and assertions', () => {
      const parsed = SamlDecoder.parse(RESPONSE_XML);
      expect(parsed.messageSigned).toBe(false);
      expect(parsed.assertion.signed).toBe(false);
      expect(parsed.hasEncryptedAssertion).toBe(false);
    });

    it('detects a message-level signature directly under the root', () => {
      const xml = RESPONSE_XML.replace('<samlp:Status>', SIGNATURE + '<samlp:Status>');
      const parsed = SamlDecoder.parse(xml);
      expect(parsed.messageSigned).toBe(true);
      expect(parsed.assertion.signed).toBe(false);
    });

    it('detects an assertion-level signature without mistaking it for a message signature', () => {
      const xml = RESPONSE_XML.replace('<saml:Subject>', SIGNATURE + '<saml:Subject>');
      const parsed = SamlDecoder.parse(xml);
      expect(parsed.messageSigned).toBe(false);
      expect(parsed.assertion.signed).toBe(true);
    });

    it('detects an EncryptedAssertion', () => {
      const xml = RESPONSE_XML
        .replace(/<saml:Assertion[\s\S]*<\/saml:Assertion>/, '<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"/></saml:EncryptedAssertion>');
      const parsed = SamlDecoder.parse(xml);
      expect(parsed.hasEncryptedAssertion).toBe(true);
      expect(parsed.assertion).toBeNull();
    });

    it('only recognises Signature elements in the XML Signature namespace', () => {
      const foreign = RESPONSE_XML.replace('<samlp:Status>', '<Signature xmlns="urn:example:not-dsig"><Value/></Signature><samlp:Status>');
      expect(SamlDecoder.parse(foreign).messageSigned).toBe(false);
      const unqualified = RESPONSE_XML.replace('<saml:Subject>', '<Signature><Value/></Signature><saml:Subject>');
      expect(SamlDecoder.parse(unqualified).assertion.signed).toBe(false);
      const genuine = RESPONSE_XML.replace('<samlp:Status>', SIGNATURE + '<samlp:Status>');
      expect(SamlDecoder.parse(genuine).messageSigned).toBe(true);
    });

    it('treats only the exact SAML Success URI as success', () => {
      const status = (value) => SamlDecoder.parse(RESPONSE_XML.replace('urn:oasis:names:tc:SAML:2.0:status:Success', value)).status;
      expect(status('urn:oasis:names:tc:SAML:2.0:status:Success').isSuccess).toBe(true);
      expect(status('urn:example:NotSuccess').isSuccess).toBe(false);
      expect(status('urn:oasis:names:tc:SAML:2.0:status:Success ').isSuccess).toBe(false);
      expect(status('urn:oasis:names:tc:SAML:2.0:status:Requester').isSuccess).toBe(false);
    });
  });

  // ─── Redirect-binding signatures (Signature / SigAlg query parameters) ────

  describe('redirect-binding signature handling', () => {
    const sigAlg = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    const signedUrl = `https://idp.example.com/sso?SAMLRequest=${deflateBase64url(AUTHN_REQUEST_XML)}&RelayState=rs&SigAlg=${encodeURIComponent(sigAlg)}&Signature=${encodeURIComponent('c2lnbmF0dXJl')}`;
    const unsignedUrl = `https://idp.example.com/sso?SAMLRequest=${deflateBase64url(AUTHN_REQUEST_XML)}`;

    it('extract() captures the binding signature and algorithm', () => {
      expect(SamlDecoder.extract({ url: signedUrl, requestBody: null }).bindingSignature).toEqual({ present: true, algorithm: sigAlg });
      expect(SamlDecoder.extract({ url: unsignedUrl, requestBody: null }).bindingSignature).toBeNull();
      expect(SamlDecoder.extract({ url: 'https://sp/acs', requestBody: { type: 'formData', data: { SAMLRequest: ['x'] } } }).bindingSignature).toBeUndefined();
    });

    it('does not report a signed Redirect-binding AuthnRequest as unsigned', async () => {
      const signed = await SamlDecoder.decodeSamlFromRequest({ url: signedUrl, requestBody: null });
      expect(signed.parsed.messageType).toBe('AuthnRequest');
      expect(signed.bindingSignature).toEqual({ present: true, algorithm: sigAlg });
      expect(signed.warnings.map(w => w.rule)).not.toContain('saml_request_unsigned');

      const unsigned = await SamlDecoder.decodeSamlFromRequest({ url: unsignedUrl, requestBody: null });
      expect(unsigned.bindingSignature).toBeNull();
      expect(unsigned.warnings.map(w => w.rule)).toContain('saml_request_unsigned');
    });

    it('generateWarnings honours a binding signature for Responses too', () => {
      const parsed = SamlDecoder.parse(RESPONSE_XML);
      const inWindow = Date.parse('2024-01-01T00:30:00Z');
      expect(SamlDecoder.generateWarnings(parsed, inWindow).map(w => w.rule)).toContain('saml_unsigned');
      expect(SamlDecoder.generateWarnings(parsed, inWindow, { bindingSignature: { present: true, algorithm: sigAlg } }).map(w => w.rule)).not.toContain('saml_unsigned');
    });
  });

  // ─── Security assessment ─────────────────────────────────────────────────

  describe('generateWarnings', () => {
    const IN_WINDOW = Date.parse('2024-01-01T00:30:00Z'); // inside the fixture's validity window
    const rules = (xml, now) => SamlDecoder.generateWarnings(SamlDecoder.parse(xml), now).map(w => w.rule);
    const find = (xml, rule, now) => SamlDecoder.generateWarnings(SamlDecoder.parse(xml), now).find(w => w.rule === rule);

    it('flags an unsigned AuthnRequest with an info note and nothing else for the fixture', () => {
      expect(rules(AUTHN_REQUEST_XML)).toEqual(['saml_request_unsigned']);
      expect(find(AUTHN_REQUEST_XML, 'saml_request_unsigned').severity).toBe('info');
    });

    it('notes an AuthnRequest without Destination', () => {
      const xml = AUTHN_REQUEST_XML.replace('Destination="https://idp.example.com/sso"', '');
      expect(rules(xml)).toContain('saml_request_no_destination');
    });

    it('notes an unspecified NameIDPolicy format', () => {
      const xml = AUTHN_REQUEST_XML.replace('nameid-format:persistent', 'nameid-format:unspecified');
      expect(rules(xml)).toContain('saml_nameid_policy_unspecified');
      expect(rules(AUTHN_REQUEST_XML)).not.toContain('saml_nameid_policy_unspecified');
    });

    it('is silent for a signed AuthnRequest with a Destination and a persistent NameID policy', () => {
      const xml = AUTHN_REQUEST_XML.replace('<saml:Issuer>', SIGNATURE + '<saml:Issuer>');
      expect(rules(xml)).toEqual([]);
    });

    it('flags a Response whose assertion has expired (using the real clock)', () => {
      const w = find(RESPONSE_XML, 'saml_assertion_expired');
      expect(w).toBeDefined();
      expect(w.severity).toBe('warning');
      expect(w.message).toContain('2024-01-01T01:00:00Z');
    });

    it('does not flag expiry when evaluated inside the validity window', () => {
      expect(rules(RESPONSE_XML, IN_WINDOW)).not.toContain('saml_assertion_expired');
      expect(rules(RESPONSE_XML, IN_WINDOW)).not.toContain('saml_assertion_not_yet_valid');
    });

    it('flags an assertion that is not yet valid', () => {
      expect(rules(RESPONSE_XML, Date.parse('2023-12-31T00:00:00Z'))).toContain('saml_assertion_not_yet_valid');
    });

    it('flags a Response with neither message nor assertion signature', () => {
      const w = find(RESPONSE_XML, 'saml_unsigned', IN_WINDOW);
      expect(w).toBeDefined();
      expect(w.severity).toBe('warning');
    });

    it('accepts a signature on either the Response or the Assertion', () => {
      const msgSigned = RESPONSE_XML.replace('<samlp:Status>', SIGNATURE + '<samlp:Status>');
      const assertionSigned = RESPONSE_XML.replace('<saml:Subject>', SIGNATURE + '<saml:Subject>');
      expect(rules(msgSigned, IN_WINDOW)).not.toContain('saml_unsigned');
      expect(rules(assertionSigned, IN_WINDOW)).not.toContain('saml_unsigned');
    });

    it('flags a malformed status value that merely contains the word Success', () => {
      const xml = RESPONSE_XML.replace('urn:oasis:names:tc:SAML:2.0:status:Success', 'urn:example:NotSuccess');
      const w = find(xml, 'saml_status_failure', IN_WINDOW);
      expect(w).toBeDefined();
      expect(w.message).toContain('NotSuccess');
    });

    it('reports a non-success status as an error including the status message', () => {
      const xml = RESPONSE_XML
        .replace('urn:oasis:names:tc:SAML:2.0:status:Success', 'urn:oasis:names:tc:SAML:2.0:status:Requester')
        .replace('</samlp:StatusCode>', '')
        .replace('<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"/>',
          '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"/><samlp:StatusMessage>Invalid request</samlp:StatusMessage>');
      const w = find(xml, 'saml_status_failure', IN_WINDOW);
      expect(w).toBeDefined();
      expect(w.severity).toBe('error');
      expect(w.message).toContain('Requester');
      expect(w.message).toContain('Invalid request');
    });

    it('notes an encrypted assertion instead of complaining about a missing one', () => {
      const xml = RESPONSE_XML
        .replace(/<saml:Assertion[\s\S]*<\/saml:Assertion>/, '<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"/></saml:EncryptedAssertion>');
      const r = rules(xml, IN_WINDOW);
      expect(r).toContain('saml_assertion_encrypted');
      expect(r).not.toContain('saml_no_assertion');
      expect(r).not.toContain('saml_unsigned');
    });

    it('warns when a successful Response carries no assertion at all', () => {
      const xml = RESPONSE_XML.replace(/<saml:Assertion[\s\S]*<\/saml:Assertion>/, '');
      expect(rules(xml, IN_WINDOW)).toContain('saml_no_assertion');
    });

    it('warns when the assertion lacks an AudienceRestriction', () => {
      const xml = RESPONSE_XML.replace(/<saml:AudienceRestriction>[\s\S]*<\/saml:AudienceRestriction>/, '');
      expect(rules(xml, IN_WINDOW)).toContain('saml_no_audience_restriction');
      expect(rules(RESPONSE_XML, IN_WINDOW)).not.toContain('saml_no_audience_restriction');
    });

    it('notes an unusually long assertion validity window', () => {
      const xml = RESPONSE_XML.replace('NotOnOrAfter="2024-01-01T01:00:00Z"', 'NotOnOrAfter="2024-01-01T09:00:00Z"');
      const w = find(xml, 'saml_assertion_long_lifetime', IN_WINDOW);
      expect(w).toBeDefined();
      expect(w.message).toContain('540 minutes');
      expect(rules(RESPONSE_XML, IN_WINDOW)).not.toContain('saml_assertion_long_lifetime');
    });

    it('flags a failed LogoutResponse and is silent for a successful one', () => {
      expect(rules(LOGOUT_RESPONSE_XML)).toEqual([]);
      const failed = LOGOUT_RESPONSE_XML.replace('status:Success', 'status:Responder');
      expect(rules(failed)).toEqual(['saml_status_failure']);
    });

    it('returns no warnings for parse errors, LogoutRequests and null input', () => {
      expect(SamlDecoder.generateWarnings(SamlDecoder.parse('<not-xml'))).toEqual([]);
      expect(rules(LOGOUT_REQUEST_XML)).toEqual([]);
      expect(SamlDecoder.generateWarnings(null)).toEqual([]);
    });

    it('gives every warning a rule, a severity and a message', () => {
      const xml = RESPONSE_XML
        .replace('status:Success', 'status:Requester')
        .replace(/<saml:AudienceRestriction>[\s\S]*<\/saml:AudienceRestriction>/, '');
      const warnings = SamlDecoder.generateWarnings(SamlDecoder.parse(xml));
      expect(warnings.length).toBeGreaterThanOrEqual(3);
      for (const w of warnings) {
        expect(w.rule).toMatch(/^saml_/);
        expect(['error', 'warning', 'info']).toContain(w.severity);
        expect(typeof w.message).toBe('string');
      }
    });
  });
});
