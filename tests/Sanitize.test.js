/**
 * Tests for Sanitize — HTML escaping, credential redaction, JWT extraction.
 */

import Sanitize from '../src/Sanitize.js';
import { makeRequest, buildJwt } from './helpers.js';

describe('Sanitize', () => {
  describe('escapeHtml', () => {
    it('escapes the five HTML-significant characters', () => {
      expect(Sanitize.escapeHtml(`<img src=x onerror="alert('1')">&`))
        .toBe('&lt;img src=x onerror=&quot;alert(&#039;1&#039;)&quot;&gt;&amp;');
    });

    it('returns an empty string for null and undefined', () => {
      expect(Sanitize.escapeHtml(null)).toBe('');
      expect(Sanitize.escapeHtml(undefined)).toBe('');
    });

    it('stringifies non-string input', () => {
      expect(Sanitize.escapeHtml(42)).toBe('42');
      expect(Sanitize.escapeHtml(true)).toBe('true');
    });
  });

  describe('classifyKey', () => {
    it.each([
      ['client_secret', 'secret'],
      ['CLIENT_SECRET', 'secret'],
      ['x-client-secret', 'secret'],
      ['password', 'secret'],
      ['new_password', 'secret'],
      ['refresh_token', 'secret'],
      ['assertion', 'secret'],
      ['access_token', 'secret'],
      ['id_token', 'secret'],
      ['client_assertion', 'truncate'],
      ['id_token_hint', 'truncate'],
      ['client_assertion_type', 'plain'],
      ['code', 'plain'],
      ['code_verifier', 'plain'],
      ['device_code', 'plain'],
      ['state', 'plain'],
      ['nonce', 'plain'],
      ['scope', 'plain'],
      [null, 'plain']
    ])('%s → %s', (key, kind) => {
      expect(Sanitize.classifyKey(key)).toBe(kind);
    });
  });

  describe('redactSensitiveValues', () => {
    it.each(['client_secret', 'password', 'refresh_token', 'assertion', 'access_token', 'id_token'])('redacts %s', (key) => {
      expect(Sanitize.redactSensitiveValues(key, 'super-secret-value')).toBe('[REDACTED]');
    });

    it('matches secret substrings inside longer keys', () => {
      expect(Sanitize.redactSensitiveValues('my_client_secret', 'x')).toBe('[REDACTED]');
      expect(Sanitize.redactSensitiveValues('userPassword', 'x')).toBe('[REDACTED]');
    });

    it('truncates client_assertion rather than hiding it (the UI decodes it elsewhere)', () => {
      const jwt = buildJwt({ iss: 'app' });
      const out = Sanitize.redactSensitiveValues('client_assertion', jwt);
      expect(out.startsWith(jwt.substring(0, 12))).toBe(true);
      expect(out).toMatch(/…\[truncated JWT, \d+ chars\]$/);
      expect(out).not.toBe('[REDACTED]');
    });

    it('truncates id_token_hint even though id_token alone is a secret', () => {
      const jwt = buildJwt({ sub: 'u' });
      expect(Sanitize.redactSensitiveValues('id_token_hint', jwt)).toMatch(/truncated JWT/);
      expect(Sanitize.redactSensitiveValues('id_token', jwt)).toBe('[REDACTED]');
    });

    it('leaves client_assertion_type visible', () => {
      const v = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
      expect(Sanitize.redactSensitiveValues('client_assertion_type', v)).toBe(v);
    });

    it('is null- and undefined-safe', () => {
      expect(Sanitize.redactSensitiveValues('scope', undefined)).toBe('');
      expect(Sanitize.redactSensitiveValues('scope', null)).toBe('');
      expect(Sanitize.redactSensitiveValues(undefined, 'x')).toBe('x');
    });

    it('caps ordinary values at 200 characters with an ellipsis', () => {
      const long = 'a'.repeat(250);
      const out = Sanitize.redactSensitiveValues('state', long);
      expect(out).toHaveLength(203);
      expect(out.endsWith('...')).toBe(true);
      expect(Sanitize.redactSensitiveValues('state', 'a'.repeat(200))).toBe('a'.repeat(200));
    });
  });

  describe('redactHeaders', () => {
    it('keeps the scheme and hides the credential of Authorization headers', () => {
      const out = Sanitize.redactHeaders([{ name: 'Authorization', value: 'Basic ' + btoa('id:secret') }]);
      expect(out).toEqual([{ name: 'Authorization', value: 'Basic [REDACTED]' }]);
    });

    it('handles Bearer, Digest and Proxy-Authorization', () => {
      const out = Sanitize.redactHeaders([
        { name: 'authorization', value: 'Bearer eyJhbGci.payload.sig' },
        { name: 'Proxy-Authorization', value: 'Digest username="u", realm="r"' }
      ]);
      expect(out[0].value).toBe('Bearer [REDACTED]');
      expect(out[1].value).toBe('Digest [REDACTED]');
    });

    it('hides cookies entirely and leaves other headers untouched', () => {
      const out = Sanitize.redactHeaders([
        { name: 'Cookie', value: 'ESTSAUTH=abc' },
        { name: 'Set-Cookie', value: 'x=y' },
        { name: 'Content-Type', value: 'application/json' }
      ]);
      expect(out[0].value).toBe('[REDACTED]');
      expect(out[1].value).toBe('[REDACTED]');
      expect(out[2]).toEqual({ name: 'Content-Type', value: 'application/json' });
    });

    it('does not mutate the input and tolerates non-array input', () => {
      const input = [{ name: 'Authorization', value: 'Bearer t' }];
      const out = Sanitize.redactHeaders(input);
      expect(input[0].value).toBe('Bearer t');
      expect(out).not.toBe(input);
      expect(Sanitize.redactHeaders(null)).toEqual([]);
    });
  });

  describe('redactBody', () => {
    it('redacts formData values by key while preserving the Chrome array shape', () => {
      const body = { type: 'formData', data: { grant_type: ['client_credentials'], client_secret: ['s3cret'], client_id: ['app'] } };
      const out = Sanitize.redactBody(body);
      expect(out).toEqual({ type: 'formData', data: { grant_type: ['client_credentials'], client_secret: ['[REDACTED]'], client_id: ['app'] } });
      expect(body.data.client_secret[0]).toBe('s3cret');
    });

    it('redacts nested JSON keys and drops the unredactable raw text', () => {
      const body = { type: 'json', data: { user: { password: 'p', name: 'n' }, tokens: [{ refresh_token: 'r' }], clientDataJSON: 'x'.repeat(300) }, raw: '{"user":{"password":"p"}}' };
      const out = Sanitize.redactBody(body);
      expect(out.data.user).toEqual({ password: '[REDACTED]', name: 'n' });
      expect(out.data.tokens[0].refresh_token).toBe('[REDACTED]');
      expect(out.data.clientDataJSON).toHaveLength(300); // plain JSON values are not display-truncated
      expect(out.raw).toBeUndefined();
    });

    it('parses form-urlencoded raw bodies and redacts secret fields', () => {
      const out = Sanitize.redactBody({ type: 'raw', data: 'grant_type=client_credentials&client_id=app&client_secret=s3cret&scope=openid%20profile' });
      expect(out.type).toBe('raw');
      expect(out.parsedAs).toBe('form');
      const params = new URLSearchParams(out.data);
      expect(params.get('client_secret')).toBe('[REDACTED]');
      expect(params.get('client_id')).toBe('app');
      expect(params.get('scope')).toBe('openid profile');
      expect(out.data).not.toContain('s3cret');
    });

    it('parses JSON raw bodies and redacts nested secrets', () => {
      const out = Sanitize.redactBody({ type: 'raw', data: '{"user":{"password":"p"},"state":"s"}' });
      expect(out.parsedAs).toBe('json');
      expect(JSON.parse(out.data)).toEqual({ user: { password: '[REDACTED]' }, state: 's' });
    });

    it('replaces raw text that cannot be parsed with a placeholder', () => {
      const xml = '<soap:Envelope><saml:Assertion>secret-bearing</saml:Assertion></soap:Envelope>';
      const out = Sanitize.redactBody({ type: 'raw', data: xml });
      expect(out.redacted).toBe(true);
      expect(out.parsedAs).toBeNull();
      expect(out.data).toBe(`[REDACTED raw body — ${xml.length} chars could not be parsed as form data or JSON]`);
      expect(out.data).not.toContain('secret-bearing');
      expect(Sanitize.redactBody({ type: 'raw', data: 'plain text' }).redacted).toBe(true);
    });

    it('returns null unchanged', () => {
      expect(Sanitize.redactBody(null)).toBeNull();
    });
  });

  describe('parseFormUrlEncoded', () => {
    it('accepts key=value pairs and rejects prose, JSON and XML', () => {
      expect(Sanitize.parseFormUrlEncoded('a=1&b=two%20words')).toEqual([['a', '1'], ['b', 'two words']]);
      expect(Sanitize.parseFormUrlEncoded('a=')).toEqual([['a', '']]);
      expect(Sanitize.parseFormUrlEncoded('plain text')).toBeNull();
      expect(Sanitize.parseFormUrlEncoded('{"a":1}')).toBeNull();
      expect(Sanitize.parseFormUrlEncoded('<x a="1"/>')).toBeNull();
      expect(Sanitize.parseFormUrlEncoded('')).toBeNull();
      expect(Sanitize.parseFormUrlEncoded('novalue')).toBeNull();
    });
  });

  describe('redactUrl', () => {
    it('replaces secret query parameters and keeps the rest', () => {
      const out = Sanitize.redactUrl('https://idp.example.com/token?client_id=app&client_secret=s3cret&state=abc');
      const url = new URL(out);
      expect(url.searchParams.get('client_secret')).toBe('[REDACTED]');
      expect(url.searchParams.get('client_id')).toBe('app');
      expect(url.searchParams.get('state')).toBe('abc');
    });

    it('truncates id_token_hint in the query string', () => {
      const jwt = buildJwt({ sub: 'u' });
      const out = Sanitize.redactUrl(`https://login.microsoftonline.com/t/oauth2/v2.0/authorize?id_token_hint=${jwt}`);
      expect(new URL(out).searchParams.get('id_token_hint')).toMatch(/truncated JWT/);
    });

    it('returns the input unchanged when nothing needs redacting or it is not a URL', () => {
      const clean = 'https://x.example.com/a?b=c';
      expect(Sanitize.redactUrl(clean)).toBe(clean);
      expect(Sanitize.redactUrl('not a url')).toBe('not a url');
    });
  });

  describe('looksLikeJwt', () => {
    it('recognises compact JWTs and rejects other strings', () => {
      expect(Sanitize.looksLikeJwt(buildJwt({ a: 1 }))).toBe(true);
      expect(Sanitize.looksLikeJwt('abc.def.')).toBe(true);
      expect(Sanitize.looksLikeJwt('abc.def')).toBe(false);
      expect(Sanitize.looksLikeJwt('has spaces.no.way')).toBe(false);
      expect(Sanitize.looksLikeJwt(null)).toBe(false);
    });
  });

  describe('extractJwtFromRequest', () => {
    it('reads the parameter from form data first', () => {
      const req = makeRequest('https://idp/token?client_assertion=from-url', { formData: { client_assertion: 'from-body' } });
      expect(Sanitize.extractJwtFromRequest(req)).toBe('from-body');
    });

    it('falls back to the URL query string', () => {
      const req = makeRequest('https://idp/authorize?id_token_hint=from-url');
      expect(Sanitize.extractJwtFromRequest(req, 'id_token_hint')).toBe('from-url');
    });

    it('returns null when absent or for a null request', () => {
      expect(Sanitize.extractJwtFromRequest(makeRequest('https://idp/authorize'))).toBeNull();
      expect(Sanitize.extractJwtFromRequest(null)).toBeNull();
    });
  });
});
