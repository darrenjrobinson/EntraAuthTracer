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

  describe('generateWarnings — comprehensive', () => {
    it('should warn when token expires within 5 minutes', () => {
      const payload = {
        iss: 'https://sts.windows.net/tenant/',
        exp: Math.floor(Date.now() / 1000) + 120 // 2 minutes from now
      };

      const warnings = EntraClaimsDecoder.generateWarnings(payload);
      const expiryWarn = warnings.find(w => w.type === 'expiry_soon');
      expect(expiryWarn).toBeDefined();
      expect(expiryWarn.severity).toBe('warning');
    });

    it('should not warn about expiry_soon for tokens with > 5 minutes remaining', () => {
      const payload = {
        iss: 'https://sts.windows.net/tenant/',
        exp: Math.floor(Date.now() / 1000) + 600 // 10 minutes
      };

      const warnings = EntraClaimsDecoder.generateWarnings(payload);
      expect(warnings.find(w => w.type === 'expiry_soon')).toBeUndefined();
    });

    it('should flag long-lived token (> 60 minutes)', () => {
      const now = Math.floor(Date.now() / 1000);
      const payload = {
        iss: 'https://sts.windows.net/tenant/',
        iat: now - 100,
        exp: now + 7200 // 2 hours lifetime
      };

      const warnings = EntraClaimsDecoder.generateWarnings(payload);
      const longWarn = warnings.find(w => w.type === 'long_lifetime');
      expect(longWarn).toBeDefined();
      expect(longWarn.severity).toBe('info');
      expect(longWarn.message).toMatch(/\d+ minutes/);
    });

    it('should not flag short-lived token (≤ 60 minutes)', () => {
      const now = Math.floor(Date.now() / 1000);
      const payload = {
        iss: 'https://sts.windows.net/tenant/',
        iat: now - 100,
        exp: now + 3500 // ~58 minutes
      };

      const warnings = EntraClaimsDecoder.generateWarnings(payload);
      expect(warnings.find(w => w.type === 'long_lifetime')).toBeUndefined();
    });

    it('should flag guest account (acct=1)', () => {
      const payload = {
        iss: 'https://sts.windows.net/tenant/',
        acct: 1
      };

      const warnings = EntraClaimsDecoder.generateWarnings(payload);
      const guestWarn = warnings.find(w => w.type === 'guest_account');
      expect(guestWarn).toBeDefined();
      expect(guestWarn.severity).toBe('info');
    });

    it('should not flag member account (acct=0)', () => {
      const payload = {
        iss: 'https://sts.windows.net/tenant/',
        acct: 0
      };

      const warnings = EntraClaimsDecoder.generateWarnings(payload);
      expect(warnings.find(w => w.type === 'guest_account')).toBeUndefined();
    });

    it('should flag public client (azpacr=0)', () => {
      const payload = {
        iss: 'https://sts.windows.net/tenant/',
        azpacr: 0
      };

      const warnings = EntraClaimsDecoder.generateWarnings(payload);
      const publicClient = warnings.find(w => w.type === 'public_client');
      expect(publicClient).toBeDefined();
      expect(publicClient.severity).toBe('warning');
    });

    it('should not flag confidential client (azpacr=1)', () => {
      const payload = {
        iss: 'https://sts.windows.net/tenant/',
        azpacr: 1
      };

      const warnings = EntraClaimsDecoder.generateWarnings(payload);
      expect(warnings.find(w => w.type === 'public_client')).toBeUndefined();
    });

    it('should warn that CAE is not enabled for Entra tokens without xms_cc', () => {
      const payload = {
        iss: 'https://sts.windows.net/tenant/',
        tid: 'tenant-id'
      };

      const warnings = EntraClaimsDecoder.generateWarnings(payload);
      const caeWarn = warnings.find(w => w.type === 'cae_not_enabled');
      expect(caeWarn).toBeDefined();
      expect(caeWarn.severity).toBe('info');
    });

    it('should not add cae_not_enabled warning when CAE is present', () => {
      const payload = {
        iss: 'https://sts.windows.net/tenant/',
        xms_cc: ['cp1']
      };

      const warnings = EntraClaimsDecoder.generateWarnings(payload);
      expect(warnings.find(w => w.type === 'cae_not_enabled')).toBeUndefined();
    });

    it('should not add cae_not_enabled warning for non-Entra tokens', () => {
      const payload = {
        iss: 'https://some-other-idp.example.com/',
        sub: 'user'
      };

      const warnings = EntraClaimsDecoder.generateWarnings(payload);
      expect(warnings.find(w => w.type === 'cae_not_enabled')).toBeUndefined();
    });
  });

  describe('decodeAmrValues', () => {
    it('should decode known AMR values', () => {
      const result = EntraClaimsDecoder.decodeAmrValues(['pwd', 'mfa']);
      expect(result).toHaveLength(2);
      expect(result[0].method).toBe('pwd');
      expect(result[0].description).toBe('Password');
      expect(result[1].method).toBe('mfa');
      expect(result[1].description).toMatch(/Multi-Factor/);
    });

    it('should handle unknown AMR values gracefully', () => {
      const result = EntraClaimsDecoder.decodeAmrValues(['unknown_method']);
      expect(result).toHaveLength(1);
      expect(result[0].method).toBe('unknown_method');
      expect(result[0].description).toMatch(/Unknown/);
    });

    it('should accept a single string instead of array', () => {
      const result = EntraClaimsDecoder.decodeAmrValues('fido');
      expect(result).toHaveLength(1);
      expect(result[0].description).toMatch(/FIDO2/);
    });

    it('should return empty array for null/undefined input', () => {
      expect(EntraClaimsDecoder.decodeAmrValues(null)).toEqual([]);
      expect(EntraClaimsDecoder.decodeAmrValues(undefined)).toEqual([]);
    });

    it('should decode wia (Windows Integrated Auth)', () => {
      const result = EntraClaimsDecoder.decodeAmrValues(['wia']);
      expect(result[0].description).toMatch(/Windows Integrated/);
    });

    it('should decode ngcmfa (Windows Hello for Business)', () => {
      const result = EntraClaimsDecoder.decodeAmrValues(['ngcmfa']);
      expect(result[0].description).toMatch(/Windows Hello/);
    });
  });

  describe('formatClaimValue — AMR and platform', () => {
    it('should decode AMR array to human-readable labels', () => {
      const formatted = EntraClaimsDecoder.formatClaimValue('amr', ['pwd', 'mfa']);
      expect(formatted).toContain('pwd');
      expect(formatted).toContain('Password');
      expect(formatted).toContain('mfa');
    });

    it('should decode platf claim to OS name', () => {
      expect(EntraClaimsDecoder.formatClaimValue('platf', '2')).toMatch(/Windows/);
      expect(EntraClaimsDecoder.formatClaimValue('platf', 5)).toMatch(/iOS/);
      expect(EntraClaimsDecoder.formatClaimValue('platf', '6')).toMatch(/Android/);
    });

    it('should return raw value for unknown platform code', () => {
      expect(EntraClaimsDecoder.formatClaimValue('platf', '99')).toBe('99');
    });
  });
});