/**
 * Tests for EntraClaimsDecoder
 */

import EntraClaimsDecoder from '../src/EntraClaimsDecoder.js';

describe('EntraClaimsDecoder', () => {
  describe('parseJWT', () => {
    it('should parse valid JWT token', () => {
      const header = { alg: 'RS256', typ: 'JWT' };
      const payload = { sub: 'test', aud: 'test-audience' };
      
      const encodedHeader = btoa(JSON.stringify(header)).replace(/=/g, '');
      const encodedPayload = btoa(JSON.stringify(payload)).replace(/=/g, '');
      const token = `${encodedHeader}.${encodedPayload}.signature`;
      
      const parsed = EntraClaimsDecoder.parseJWT(token);
      
      expect(parsed.sub).toBe('test');
      expect(parsed.aud).toBe('test-audience');
    });

    it('should throw error for invalid JWT format', () => {
      expect(() => {
        EntraClaimsDecoder.parseJWT('invalid.jwt');
      }).toThrow('Invalid JWT format');
    });
  });

  describe('isEntraToken', () => {
    it('should detect Entra token by issuer', () => {
      const payload = {
        iss: 'https://sts.windows.net/tenant-id/',
        sub: 'user'
      };
      
      expect(EntraClaimsDecoder.isEntraToken(payload)).toBe(true);
    });

    it('should detect Entra token by proprietary claims', () => {
      const payload = {
        iss: 'https://other-issuer.com/',
        xms_cc: ['cp1'],
        sub: 'user'
      };
      
      expect(EntraClaimsDecoder.isEntraToken(payload)).toBe(true);
    });

    it('should return false for non-Entra token', () => {
      const payload = {
        iss: 'https://other-issuer.com/',
        sub: 'user'
      };
      
      expect(EntraClaimsDecoder.isEntraToken(payload)).toBe(false);
    });
  });

  describe('detectCAE', () => {
    it('should detect CAE capability with string value', () => {
      const payload = { xms_cc: 'cp1' };
      expect(EntraClaimsDecoder.detectCAE(payload)).toBe(true);
    });

    it('should detect CAE capability with array value', () => {
      const payload = { xms_cc: ['cp1'] };
      expect(EntraClaimsDecoder.detectCAE(payload)).toBe(true);
    });

    it('should return false when CAE not present', () => {
      const payload = { sub: 'user' };
      expect(EntraClaimsDecoder.detectCAE(payload)).toBe(false);
    });

    it('should return false for invalid CAE value', () => {
      const payload = { xms_cc: 'invalid' };
      expect(EntraClaimsDecoder.detectCAE(payload)).toBe(false);
    });
  });

  describe('detectPoP', () => {
    it('should detect PoP binding', () => {
      const payload = {
        cnf: {
          jkt: 'test-thumbprint'
        }
      };
      
      const pop = EntraClaimsDecoder.detectPoP(payload);
      expect(pop.present).toBe(true);
      expect(pop.jwkThumbprint).toBe('test-thumbprint');
    });

    it('should return null when no PoP binding', () => {
      const payload = { sub: 'user' };
      expect(EntraClaimsDecoder.detectPoP(payload)).toBe(null);
    });
  });

  describe('formatTimestamp', () => {
    it('should format Unix timestamp to ISO string', () => {
      const timestamp = 1640995200; // 2022-01-01 00:00:00 UTC
      const formatted = EntraClaimsDecoder.formatTimestamp(timestamp);
      expect(formatted).toBe('2022-01-01T00:00:00.000Z');
    });
  });

  describe('isTimestampClaim', () => {
    it('should identify timestamp claims', () => {
      expect(EntraClaimsDecoder.isTimestampClaim('iat')).toBe(true);
      expect(EntraClaimsDecoder.isTimestampClaim('exp')).toBe(true);
      expect(EntraClaimsDecoder.isTimestampClaim('nbf')).toBe(true);
      expect(EntraClaimsDecoder.isTimestampClaim('auth_time')).toBe(true);
    });

    it('should not identify non-timestamp claims', () => {
      expect(EntraClaimsDecoder.isTimestampClaim('sub')).toBe(false);
      expect(EntraClaimsDecoder.isTimestampClaim('aud')).toBe(false);
    });
  });

  describe('formatClaimValue', () => {
    it('should format timestamp claims', () => {
      const timestamp = 1640995200;
      const formatted = EntraClaimsDecoder.formatClaimValue('iat', timestamp);
      expect(formatted).toBe('2022-01-01T00:00:00.000Z');
    });

    it('should format array claims', () => {
      const array = ['scope1', 'scope2', 'scope3'];
      const formatted = EntraClaimsDecoder.formatClaimValue('scp', array);
      expect(formatted).toBe('scope1, scope2, scope3');
    });

    it('should format object claims as JSON', () => {
      const object = { key: 'value', nested: { prop: 'test' } };
      const formatted = EntraClaimsDecoder.formatClaimValue('cnf', object);
      expect(formatted).toBe('{"key":"value","nested":{"prop":"test"}}');
    });

    it('should convert other values to string', () => {
      expect(EntraClaimsDecoder.formatClaimValue('ver', 2.0)).toBe('2');
      expect(EntraClaimsDecoder.formatClaimValue('sub', 'user-id')).toBe('user-id');
    });
  });

  describe('processEntraClaims', () => {
    it('should process and label known claims', () => {
      const payload = {
        tid: 'tenant-id',
        sub: 'user-id',
        aud: 'audience',
        xms_cc: ['cp1'],
        unknown_claim: 'value'
      };
      
      const processed = EntraClaimsDecoder.processEntraClaims(payload);
      
      expect(processed).toHaveLength(5);
      
      const tidClaim = processed.find(c => c.name === 'tid');
      expect(tidClaim.label).toBe('Tenant ID');
      expect(tidClaim.isEntraSpecific).toBe(true);
      
      const unknownClaim = processed.find(c => c.name === 'unknown_claim');
      expect(unknownClaim.label).toBe(null);
      expect(unknownClaim.isEntraSpecific).toBe(false);
    });
  });

  describe('createSummary', () => {
    it('should create token summary', () => {
      const now = Math.floor(Date.now() / 1000);
      const payload = {
        tid: 'tenant-id',
        idtyp: 'user',
        ver: '2.0',
        aud: 'audience',
        iss: 'issuer',
        scp: 'User.Read Mail.Read',
        exp: now + 3600 // 1 hour from now
      };
      
      const summary = EntraClaimsDecoder.createSummary(payload);
      
      expect(summary.tenant).toBe('tenant-id');
      expect(summary.identityType).toBe('user');
      expect(summary.tokenVersion).toBe('2.0');
      expect(summary.audience).toBe('audience');
      expect(summary.issuer).toBe('issuer');
      expect(summary.scopes).toBe('User.Read Mail.Read');
      expect(summary.isExpired).toBe(false);
    });

    it('should detect expired token', () => {
      const payload = {
        exp: Math.floor(Date.now() / 1000) - 3600 // 1 hour ago
      };
      
      const summary = EntraClaimsDecoder.createSummary(payload);
      expect(summary.isExpired).toBe(true);
    });
  });

  describe('generateWarnings', () => {
    it('should generate expiry warning for expired token', () => {
      const payload = {
        exp: Math.floor(Date.now() / 1000) - 3600 // 1 hour ago
      };
      
      const warnings = EntraClaimsDecoder.generateWarnings(payload);
      
      expect(warnings).toHaveLength(1);
      expect(warnings[0].type).toBe('expiry');
      expect(warnings[0].severity).toBe('error');
    });

    it('should return no warnings for valid token', () => {
      const payload = {
        exp: Math.floor(Date.now() / 1000) + 3600 // 1 hour from now
      };
      
      const warnings = EntraClaimsDecoder.generateWarnings(payload);
      expect(warnings).toHaveLength(0);
    });
  });

  describe('decodeEntraToken', () => {
    it('should decode valid Entra token', () => {
      const payload = {
        tid: 'tenant-id',
        sub: 'user-id',
        aud: 'audience',
        xms_cc: ['cp1'],
        cnf: { jkt: 'thumbprint' },
        exp: Math.floor(Date.now() / 1000) + 3600
      };
      
      const header = { alg: 'RS256', typ: 'JWT' };
      const encodedHeader = btoa(JSON.stringify(header)).replace(/=/g, '');
      const encodedPayload = btoa(JSON.stringify(payload)).replace(/=/g, '');
      const token = `${encodedHeader}.${encodedPayload}.signature`;
      
      const result = EntraClaimsDecoder.decodeEntraToken(token);
      
      expect(result.isEntraToken).toBe(true);
      expect(result.caeEnabled).toBe(true);
      expect(result.popBinding.present).toBe(true);
      expect(result.claims).toBeDefined();
      expect(result.summary).toBeDefined();
      expect(result.warnings).toHaveLength(0);
    });

    it('should handle invalid token gracefully', () => {
      const result = EntraClaimsDecoder.decodeEntraToken('invalid.token');
      
      expect(result.error).toBeDefined();
      expect(result.isEntraToken).toBe(false);
      expect(result.caeEnabled).toBe(false);
      expect(result.popBinding).toBe(null);
    });
  });
});