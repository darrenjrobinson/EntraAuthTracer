/**
 * Tests for SamlDecoder
 */

import SamlDecoder from '../src/SamlDecoder.js';
const zlib = require('zlib');

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Base64-encode a string (POST binding: no deflate) */
function b64Encode(str) {
  return btoa(unescape(encodeURIComponent(str)));
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
  });
});
