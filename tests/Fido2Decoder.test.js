/**
 * Tests for Fido2Decoder
 */

import Fido2Decoder from '../src/Fido2Decoder.js';

describe('Fido2Decoder', () => {
  describe('base64urlDecode', () => {
    it('should decode base64url strings correctly', () => {
      const encoded = 'SGVsbG8gV29ybGQ'; // "Hello World"
      const decoded = Fido2Decoder.base64urlDecode(encoded);
      expect(decoded).toBe('Hello World');
    });

    it('should handle padding correctly', () => {
      const encoded = 'SGVsbG8'; // "Hello" (needs padding)
      const decoded = Fido2Decoder.base64urlDecode(encoded);
      expect(decoded).toBe('Hello');
    });

    it('should convert base64url to base64', () => {
      const base64url = 'SGVsbG8-V29ybGQ_'; // Uses - and _ instead of + and /
      const decoded = Fido2Decoder.base64urlDecode(base64url);
      expect(decoded).toBe('Hello>World?');
    });
  });

  describe('bufferToHex', () => {
    it('should convert ArrayBuffer to hex string', () => {
      const buffer = new ArrayBuffer(4);
      const view = new Uint8Array(buffer);
      view[0] = 0x01;
      view[1] = 0x23;
      view[2] = 0x45;
      view[3] = 0x67;
      
      const hex = Fido2Decoder.bufferToHex(buffer);
      expect(hex).toBe('01234567');
    });

    it('should handle empty buffer', () => {
      const buffer = new ArrayBuffer(0);
      const hex = Fido2Decoder.bufferToHex(buffer);
      expect(hex).toBe('');
    });
  });

  describe('parseFlags', () => {
    it('should parse authenticator flags correctly', () => {
      const flagsByte = 0x41; // UP and AT flags set (bits 0 and 6)
      const flags = Fido2Decoder.parseFlags(flagsByte);
      
      expect(flags.UP).toBe(true);
      expect(flags.UV).toBe(false);
      expect(flags.AT).toBe(true);
      expect(flags.ED).toBe(false);
      expect(flags.raw).toBe(0x41);
    });

    it('should handle all flags set', () => {
      const flagsByte = 0xFF; // All flags set
      const flags = Fido2Decoder.parseFlags(flagsByte);
      
      expect(flags.UP).toBe(true);
      expect(flags.UV).toBe(true);
      expect(flags.AT).toBe(true);
      expect(flags.ED).toBe(true);
    });

    it('should handle no flags set', () => {
      const flagsByte = 0x00;
      const flags = Fido2Decoder.parseFlags(flagsByte);
      
      expect(flags.UP).toBe(false);
      expect(flags.UV).toBe(false);
      expect(flags.AT).toBe(false);
      expect(flags.ED).toBe(false);
    });
  });

  describe('parseAAGUID', () => {
    it('should format AAGUID as UUID string', () => {
      const buffer = new ArrayBuffer(16);
      const view = new Uint8Array(buffer);
      // Set some test bytes
      for (let i = 0; i < 16; i++) {
        view[i] = i;
      }
      
      const uuid = Fido2Decoder.parseAAGUID(buffer);
      expect(uuid).toBe('00010203-0405-0607-0809-0a0b0c0d0e0f');
    });
  });

  describe('decodeClientDataJSON', () => {
    it('should decode valid clientDataJSON', () => {
      const clientData = {
        type: 'webauthn.create',
        challenge: 'test-challenge',
        origin: 'https://example.com',
        crossOrigin: false
      };
      
      const encoded = btoa(JSON.stringify(clientData))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
      
      const decoded = Fido2Decoder.decodeClientDataJSON(encoded);
      
      expect(decoded.type).toBe('webauthn.create');
      expect(decoded.challenge).toBe('test-challenge');
      expect(decoded.origin).toBe('https://example.com');
      expect(decoded.crossOrigin).toBe(false);
    });

    it('should throw error for invalid JSON', () => {
      const invalid = btoa('invalid json');
      
      expect(() => {
        Fido2Decoder.decodeClientDataJSON(invalid);
      }).toThrow('Failed to decode clientDataJSON');
    });
  });

  describe('decodeFido2Request', () => {
    it('should return null for invalid request body', () => {
      const result = Fido2Decoder.decodeFido2Request(null);
      expect(result).toBe(null);
    });

    it('should return null for non-JSON request body', () => {
      const requestBody = { type: 'formData', data: {} };
      const result = Fido2Decoder.decodeFido2Request(requestBody);
      expect(result).toBe(null);
    });

  describe('decodeCBORPublicKey', () => {
    // Note: This test uses mock CBOR data since we can't easily create real CBOR in tests
    it('should handle CBOR decoding errors gracefully', () => {
      const invalidBuffer = new ArrayBuffer(4);
      const result = Fido2Decoder.decodeCBORPublicKey(invalidBuffer);
      
      expect(result.type).toBe('cbor');
      expect(result.size).toBe(4);
      expect(result.error).toContain('CBOR decoding failed');
      expect(result.decoded).toBe(null);
    });

    it('should return proper structure for valid input', () => {
      const buffer = new ArrayBuffer(0); // Empty buffer will cause CBOR error
      const result = Fido2Decoder.decodeCBORPublicKey(buffer);
      
      expect(result).toHaveProperty('type', 'cbor');
      expect(result).toHaveProperty('size');
      expect(result).toHaveProperty('hex');
      expect(result).toHaveProperty('decoded');
      expect(result).toHaveProperty('keyInfo');
      expect(result).toHaveProperty('error');
    });
  });

  describe('parseKeyInfo', () => {
    it('should parse EC2 key info', () => {
      const mockCborObj = {
        1: 2, // Key type: EC2
        3: -7, // Algorithm: ES256
        '-1': 1, // Curve: P-256
        '-2': new ArrayBuffer(32), // x coordinate
        '-3': new ArrayBuffer(32)  // y coordinate
      };

      const result = Fido2Decoder.parseKeyInfo(mockCborObj);
      
      expect(result.keyType).toBe(2);
      expect(result.algorithm).toBe(-7);
      expect(result.keyTypeDescription).toBe('EC2 (Elliptic Curve Keys w/ x- and y-coordinate pair)');
      expect(result.algorithmDescription).toBe('ES256 (ECDSA w/ SHA-256)');
      expect(result.parameters.curve).toBe(1);
      expect(result.parameters.curveDescription).toBe('P-256 (secp256r1)');
    });

    it('should parse RSA key info', () => {
      const mockCborObj = {
        1: 3, // Key type: RSA
        3: -257, // Algorithm: RS256
        '-1': new ArrayBuffer(256), // n (modulus)
        '-2': new ArrayBuffer(3)    // e (exponent)
      };

      const result = Fido2Decoder.parseKeyInfo(mockCborObj);
      
      expect(result.keyType).toBe(3);
      expect(result.algorithm).toBe(-257);
      expect(result.keyTypeDescription).toBe('RSA (RSA Key)');
      expect(result.algorithmDescription).toBe('RS256 (RSASSA-PKCS1-v1_5 w/ SHA-256)');
      expect(result.parameters.n).toBeDefined();
      expect(result.parameters.e).toBeDefined();
    });

    it('should handle unknown key types', () => {
      const mockCborObj = {
        1: 999, // Unknown key type
        3: -999  // Unknown algorithm
      };

      const result = Fido2Decoder.parseKeyInfo(mockCborObj);
      
      expect(result.keyTypeDescription).toBe('Unknown (999)');
      expect(result.algorithmDescription).toBe('Unknown (-999)');
    });

    it('should handle parsing errors gracefully', () => {
      const invalidObj = null;
      
      const result = Fido2Decoder.parseKeyInfo(invalidObj);
      expect(result.error).toContain('Failed to parse key info');
    });
  });

  describe('getKeyTypeDescription', () => {
    it('should return correct descriptions for known key types', () => {
      expect(Fido2Decoder.getKeyTypeDescription(1)).toBe('OKP (Octet Key Pair)');
      expect(Fido2Decoder.getKeyTypeDescription(2)).toBe('EC2 (Elliptic Curve Keys w/ x- and y-coordinate pair)');
      expect(Fido2Decoder.getKeyTypeDescription(3)).toBe('RSA (RSA Key)');
      expect(Fido2Decoder.getKeyTypeDescription(4)).toBe('Symmetric Keys');
    });

    it('should handle unknown key types', () => {
      expect(Fido2Decoder.getKeyTypeDescription(999)).toBe('Unknown (999)');
    });
  });

  describe('getAlgorithmDescription', () => {
    it('should return correct descriptions for known algorithms', () => {
      expect(Fido2Decoder.getAlgorithmDescription(-7)).toBe('ES256 (ECDSA w/ SHA-256)');
      expect(Fido2Decoder.getAlgorithmDescription(-257)).toBe('RS256 (RSASSA-PKCS1-v1_5 w/ SHA-256)');
      expect(Fido2Decoder.getAlgorithmDescription(-37)).toBe('PS256 (RSASSA-PSS w/ SHA-256)');
    });

    it('should handle unknown algorithms', () => {
      expect(Fido2Decoder.getAlgorithmDescription(-999)).toBe('Unknown (-999)');
    });
  });

  describe('getCurveDescription', () => {
    it('should return correct descriptions for known curves', () => {
      expect(Fido2Decoder.getCurveDescription(1)).toBe('P-256 (secp256r1)');
      expect(Fido2Decoder.getCurveDescription(2)).toBe('P-384 (secp384r1)');
      expect(Fido2Decoder.getCurveDescription(3)).toBe('P-521 (secp521r1)');
      expect(Fido2Decoder.getCurveDescription(6)).toBe('Ed25519 (for EdDSA)');
    });

    it('should handle unknown curves', () => {
      expect(Fido2Decoder.getCurveDescription(999)).toBe('Unknown (999)');
    });
  });
  }); // closes the improperly-nested decodeFido2Request describe

  // ─── Additional coverage tests ───────────────────────────────────────────

  describe('base64urlDecodeToBuffer', () => {
    it('should decode a base64url string to an ArrayBuffer', () => {
      // btoa('Hello') = 'SGVsbG8='  →  base64url = 'SGVsbG8'
      const b64url = btoa('Hello').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const result = Fido2Decoder.base64urlDecodeToBuffer(b64url);
      expect(result).toBeInstanceOf(ArrayBuffer);
      expect(result.byteLength).toBe(5);
      const view = new Uint8Array(result);
      expect(view[0]).toBe(72); // 'H'
      expect(view[4]).toBe(111); // 'o'
    });

    it('should produce a buffer with the correct byte values', () => {
      const b64url = btoa('\x00\xFF').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const result = Fido2Decoder.base64urlDecodeToBuffer(b64url);
      const view = new Uint8Array(result);
      expect(view[0]).toBe(0x00);
      expect(view[1]).toBe(0xFF);
    });
  });

  describe('decodeAuthenticatorData - success paths', () => {
    function makeAuthData(flagsByte, extraBytes = new Uint8Array(0)) {
      const buf = new Uint8Array(37 + extraBytes.length);
      buf[32] = flagsByte;
      // signCount stays 0 (bytes 33-36)
      extraBytes.forEach((b, i) => { buf[37 + i] = b; });
      return btoa(String.fromCharCode(...buf)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }

    it('should decode minimal 37-byte authenticatorData with UP flag only', () => {
      const result = Fido2Decoder.decodeAuthenticatorData(makeAuthData(0x01));
      expect(result.rpIdHash).toHaveLength(64); // 32 bytes → 64 hex chars
      expect(result.flags.UP).toBe(true);
      expect(result.flags.AT).toBe(false);
      expect(result.signCount).toBe(0);
      expect(result.attestedCredentialData).toBeNull();
    });

    it('should decode authenticatorData with UP+UV flags', () => {
      const result = Fido2Decoder.decodeAuthenticatorData(makeAuthData(0x05));
      expect(result.flags.UP).toBe(true);
      expect(result.flags.UV).toBe(true);
    });

    it('should reject authenticatorData shorter than 37 bytes', () => {
      const short = new Uint8Array(10);
      const b64url = btoa(String.fromCharCode(...short)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      expect(() => Fido2Decoder.decodeAuthenticatorData(b64url))
        .toThrow('Failed to decode authenticatorData');
    });

    it('should parse attested credential data when AT flag is set', () => {
      // 16 bytes AAGUID (all zeros) + 2 bytes credIdLen=0 + 1 byte CBOR empty map
      const attested = new Uint8Array([...new Array(16).fill(0), 0x00, 0x00, 0xa0]);
      const result = Fido2Decoder.decodeAuthenticatorData(makeAuthData(0x41, attested));
      expect(result.flags.AT).toBe(true);
      expect(result.attestedCredentialData).not.toBeNull();
      expect(result.attestedCredentialData.credentialIdLength).toBe(0);
      expect(result.attestedCredentialData.aaguid).toBe('00000000-0000-0000-0000-000000000000');
    });
  });

  describe('decodeFido2Request - success paths', () => {
    it('should decode a request containing only clientDataJSON', () => {
      const clientData = { type: 'webauthn.get', challenge: 'abc', origin: 'https://example.com' };
      const encoded = btoa(JSON.stringify(clientData)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const result = Fido2Decoder.decodeFido2Request({ type: 'json', data: { clientDataJSON: encoded } });
      expect(result.type).toBe('fido2');
      expect(result.clientDataJSON.type).toBe('webauthn.get');
      expect(result.clientDataJSON.origin).toBe('https://example.com');
      expect(result.authenticatorData).toBeNull();
      expect(result.error).toBeNull();
    });

    it('should decode a request with both clientDataJSON and authenticatorData', () => {
      const clientData = { type: 'webauthn.create', challenge: 'xyz', origin: 'https://example.com' };
      const cdEncoded = btoa(JSON.stringify(clientData)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const authBytes = new Uint8Array(37);
      authBytes[32] = 0x05; // UP + UV
      const adEncoded = btoa(String.fromCharCode(...authBytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const result = Fido2Decoder.decodeFido2Request({
        type: 'json',
        data: { clientDataJSON: cdEncoded, authenticatorData: adEncoded }
      });
      expect(result.clientDataJSON.type).toBe('webauthn.create');
      expect(result.authenticatorData.flags.UV).toBe(true);
      expect(result.error).toBeNull();
    });

    it('should capture decode errors in result.error without throwing', () => {
      // Invalid base64 → JSON parse error propagated to result.error
      const result = Fido2Decoder.decodeFido2Request({ type: 'json', data: { clientDataJSON: '!!!bad!!!' } });
      expect(result.error).not.toBeNull();
    });
  });

  describe('decodeCBORPublicKey - valid CBOR path', () => {
    it('should decode a valid CBOR buffer and populate decoded/keyInfo', () => {
      // 0xa0 = CBOR empty map {}  — decodes to a plain object, triggers keyInfo path
      const validBuf = new Uint8Array([0xa0]).buffer;
      const result = Fido2Decoder.decodeCBORPublicKey(validBuf);
      expect(result.type).toBe('cbor');
      expect(result.error).toBeNull();
      expect(result.decoded).toBeDefined();
      expect(result.keyInfo).toBeDefined();
    });
  });
});