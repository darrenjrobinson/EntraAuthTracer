/**
 * Tests for Fido2Decoder
 */

import Fido2Decoder from '../src/Fido2Decoder.js';
import {
  b64url, bytes, cborEncode, coseEc2P256Key, coseRsaKey,
  buildAuthenticatorData, buildAttestationObject
} from './helpers.js';

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

  // ─── WebAuthn L3 flags: BE / BS ───────────────────────────────────────────

  describe('parseFlags — backup eligibility and state (WebAuthn L3)', () => {
    it('decodes BE (0x08) and BS (0x10)', () => {
      expect(Fido2Decoder.parseFlags(0x08).BE).toBe(true);
      expect(Fido2Decoder.parseFlags(0x08).BS).toBe(false);
      expect(Fido2Decoder.parseFlags(0x10).BS).toBe(true);
      expect(Fido2Decoder.parseFlags(0x10).BE).toBe(false);
    });

    it('0x1d sets UP, UV, BE and BS — a synced passkey assertion', () => {
      const flags = Fido2Decoder.parseFlags(0x1d);
      expect(flags).toMatchObject({ UP: true, UV: true, BE: true, BS: true, AT: false, ED: false });
    });

    it('exposes only the reserved bits that are still reserved (RFU1, RFU4)', () => {
      const flags = Fido2Decoder.parseFlags(0x22);
      expect(flags.RFU1).toBe(true);
      expect(flags.RFU4).toBe(true);
      expect(flags).not.toHaveProperty('RFU2');
      expect(flags).not.toHaveProperty('RFU3');
    });
  });

  // ─── Real authenticatorData built with cbor-web ────────────────────────────

  describe('decodeAuthenticatorData — real COSE keys and extensions', () => {
    it('reads the big-endian signCount', () => {
      const { b64url: ad } = buildAuthenticatorData({ signCount: 0x00000102 });
      expect(Fido2Decoder.decodeAuthenticatorData(ad).signCount).toBe(258);
    });

    it('reads the maximum uint32 signCount', () => {
      const { b64url: ad } = buildAuthenticatorData({ signCount: 0xffffffff });
      expect(Fido2Decoder.decodeAuthenticatorData(ad).signCount).toBe(4294967295);
    });

    it('decodes a real EC2 P-256 COSE key (integer-keyed Map) into keyInfo', () => {
      const { b64url: ad } = buildAuthenticatorData({ flags: { UP: true, UV: true, AT: true }, coseKey: coseEc2P256Key() });
      const result = Fido2Decoder.decodeAuthenticatorData(ad);
      const keyInfo = result.attestedCredentialData.credentialPublicKey.keyInfo;
      expect(keyInfo.keyType).toBe(2);
      expect(keyInfo.algorithm).toBe(-7);
      expect(keyInfo.keyTypeDescription).toMatch(/^EC2/);
      expect(keyInfo.algorithmDescription).toMatch(/^ES256/);
      expect(keyInfo.parameters.curve).toBe(1);
      expect(keyInfo.parameters.curveDescription).toMatch(/P-256/);
      expect(keyInfo.parameters.x).toBe('11'.repeat(32));
      expect(keyInfo.parameters.y).toBe('22'.repeat(32));
    });

    it('decodes a real RSA COSE key into keyInfo', () => {
      const { b64url: ad } = buildAuthenticatorData({ flags: { UP: true, AT: true }, coseKey: coseRsaKey() });
      const keyInfo = Fido2Decoder.decodeAuthenticatorData(ad).attestedCredentialData.credentialPublicKey.keyInfo;
      expect(keyInfo.keyType).toBe(3);
      expect(keyInfo.algorithm).toBe(-257);
      expect(keyInfo.algorithmDescription).toMatch(/^RS256/);
      expect(keyInfo.parameters.n).toHaveLength(512);
      expect(keyInfo.parameters.e).toBe('010001');
    });

    it('exposes the decoded COSE map with string keys and hex byte strings', () => {
      const { b64url: ad } = buildAuthenticatorData({ coseKey: coseEc2P256Key() });
      const decoded = Fido2Decoder.decodeAuthenticatorData(ad).attestedCredentialData.credentialPublicKey.decoded;
      expect(decoded['1']).toBe(2);
      expect(decoded['3']).toBe(-7);
      expect(decoded['-2']).toBe('11'.repeat(32));
    });

    it('sizes the public key by the bytes the CBOR item consumed, not the remaining buffer', () => {
      const key = coseEc2P256Key();
      const { b64url: ad } = buildAuthenticatorData({ coseKey: key, extensions: { credProtect: 2 } });
      const pk = Fido2Decoder.decodeAuthenticatorData(ad).attestedCredentialData.credentialPublicKey;
      expect(pk.size).toBe(cborEncode(key).length);
      expect(pk.hex).toHaveLength(pk.size * 2);
      expect(pk.error).toBeNull();
    });

    it('decodes extensions that follow the credential public key when ED is set', () => {
      const { b64url: ad } = buildAuthenticatorData({ coseKey: coseEc2P256Key(), extensions: { credProtect: 2, minPinLength: 6 } });
      const result = Fido2Decoder.decodeAuthenticatorData(ad);
      expect(result.flags.AT).toBe(true);
      expect(result.flags.ED).toBe(true);
      expect(result.extensions).toEqual({ credProtect: 2, minPinLength: 6 });
      expect(result.attestedCredentialData.credentialPublicKey.keyInfo.keyType).toBe(2);
    });

    it('decodes extensions directly after the header when ED is set without AT', () => {
      const { b64url: ad } = buildAuthenticatorData({ flags: { UP: true, ED: true }, extensions: { credProtect: 1 } });
      const result = Fido2Decoder.decodeAuthenticatorData(ad);
      expect(result.attestedCredentialData).toBeNull();
      expect(result.extensions).toEqual({ credProtect: 1 });
    });

    it('records the credential id and its declared length', () => {
      const credId = bytes(20, 0xcd);
      const { b64url: ad } = buildAuthenticatorData({ coseKey: coseEc2P256Key(), credId });
      const attested = Fido2Decoder.decodeAuthenticatorData(ad).attestedCredentialData;
      expect(attested.credentialIdLength).toBe(20);
      expect(attested.credentialId).toBe('cd'.repeat(20));
    });

    it('labels a known AAGUID with its authenticator name and vendor', () => {
      const { b64url: ad } = buildAuthenticatorData({ coseKey: coseEc2P256Key(), aaguid: 'ee882879-721c-4913-9775-3dfcce97072a' });
      const attested = Fido2Decoder.decodeAuthenticatorData(ad).attestedCredentialData;
      expect(attested.aaguid).toBe('ee882879-721c-4913-9775-3dfcce97072a');
      expect(attested.authenticator.vendor).toBe('Yubico');
      expect(attested.authenticator.name).toMatch(/YubiKey 5/);
    });

    it('reports a zero AAGUID as not provided', () => {
      const { b64url: ad } = buildAuthenticatorData({ coseKey: coseEc2P256Key() });
      const attested = Fido2Decoder.decodeAuthenticatorData(ad).attestedCredentialData;
      expect(attested.authenticator.name).toMatch(/Not provided/);
      expect(attested.authenticator.kind).toBe('unknown');
    });

    it('rejects a credential id longer than the buffer', () => {
      // AAGUID (16 zero bytes) + declared length 0x0100 but no credential bytes follow
      const attested = new Uint8Array([...bytes(16), 0x01, 0x00]);
      const header = buildAuthenticatorData({ flags: { UP: true, AT: true } }).bytes.subarray(0, 37);
      const ad = b64url(new Uint8Array([...header, ...attested]));
      expect(() => Fido2Decoder.decodeAuthenticatorData(ad)).toThrow(/credential ID exceeds buffer/);
    });
  });

  describe('parseKeyInfo — input shapes', () => {
    it('reads integer keys from a Map (what cbor-web returns)', () => {
      const keyInfo = Fido2Decoder.parseKeyInfo(coseEc2P256Key());
      expect(keyInfo.keyType).toBe(2);
      expect(keyInfo.parameters.curve).toBe(1);
    });

    it('describes an OKP / Ed25519 key', () => {
      const keyInfo = Fido2Decoder.parseKeyInfo(new Map([[1, 1], [3, -8], [-1, 6], [-2, bytes(32, 0x44)]]));
      expect(keyInfo.keyTypeDescription).toMatch(/^OKP/);
      expect(keyInfo.algorithmDescription).toMatch(/^EdDSA/);
      expect(keyInfo.parameters.curveDescription).toMatch(/Ed25519/);
      expect(keyInfo.parameters.x).toBe('44'.repeat(32));
    });
  });

  describe('lookupAAGUID', () => {
    it('returns name, vendor and kind for a known AAGUID', () => {
      const hit = Fido2Decoder.lookupAAGUID('08987058-cadc-4b81-b6e1-30de50dcbe96');
      expect(hit).toEqual(expect.objectContaining({ vendor: 'Microsoft', kind: 'platform' }));
      expect(hit.name).toMatch(/Windows Hello/);
    });

    it('is case-insensitive', () => {
      expect(Fido2Decoder.lookupAAGUID('EA9B8D66-4D01-1D21-3CE4-B6B48CB575D4').name).toMatch(/Google Password Manager/);
    });

    it('returns null for an unknown AAGUID and for empty input', () => {
      expect(Fido2Decoder.lookupAAGUID('12345678-1234-1234-1234-123456789abc')).toBeNull();
      expect(Fido2Decoder.lookupAAGUID(null)).toBeNull();
    });
  });

  // ─── Attestation objects ──────────────────────────────────────────────────

  describe('decodeAttestationObject', () => {
    it('decodes fmt, attStmt and the embedded authData of a packed attestation', () => {
      const authData = buildAuthenticatorData({ flags: { UP: true, UV: true, AT: true }, coseKey: coseEc2P256Key(), aaguid: 'd8522d9f-575b-4866-88a9-ba99fa02f35b' }).bytes;
      const { b64url: att } = buildAttestationObject({ fmt: 'packed', attStmt: { alg: -7, sig: bytes(64, 0x5a), x5c: [bytes(10, 0x30)] }, authDataBytes: authData });
      const result = Fido2Decoder.decodeAttestationObject(att);
      expect(result.fmt).toBe('packed');
      expect(result.attStmt.alg).toBe(-7);
      expect(result.attStmt.algorithmDescription).toMatch(/ES256/);
      expect(result.attStmt.sigHex).toBe('5a'.repeat(64));
      expect(result.attStmt.x5cCount).toBe(1);
      expect(result.authData.flags.AT).toBe(true);
      expect(result.authData.attestedCredentialData.authenticator.name).toMatch(/YubiKey Bio/);
    });

    it('handles a "none" attestation with an empty statement', () => {
      const { b64url: att } = buildAttestationObject({ fmt: 'none', attStmt: {} });
      const result = Fido2Decoder.decodeAttestationObject(att);
      expect(result.fmt).toBe('none');
      expect(result.attStmt).toEqual({ alg: null, algorithmDescription: null, sigHex: null, x5cCount: 0 });
      expect(result.authData.flags.UV).toBe(true);
    });

    it('wraps CBOR failures in a descriptive error', () => {
      expect(() => Fido2Decoder.decodeAttestationObject(b64url(new Uint8Array([0xff, 0xff]))))
        .toThrow(/Failed to decode attestationObject/);
    });
  });

  describe('decodeFido2Request — registration and PublicKeyCredential JSON', () => {
    it('reads nested response.{clientDataJSON, attestationObject} and mirrors authData', () => {
      const clientData = b64url(JSON.stringify({ type: 'webauthn.create', challenge: 'c', origin: 'https://login.microsoftonline.com' }));
      const { b64url: att } = buildAttestationObject({ fmt: 'packed' });
      const result = Fido2Decoder.decodeFido2Request({
        type: 'json',
        data: { id: 'cred', rawId: 'cred', type: 'public-key', response: { clientDataJSON: clientData, attestationObject: att } }
      });
      expect(result.error).toBeNull();
      expect(result.clientDataJSON.type).toBe('webauthn.create');
      expect(result.attestationObject.fmt).toBe('packed');
      expect(result.authenticatorData.flags.AT).toBe(true);
      expect(result.authenticatorData.attestedCredentialData.credentialPublicKey.keyInfo.keyType).toBe(2);
    });

    it('prefers an explicit authenticatorData over the attestation copy', () => {
      const { b64url: att } = buildAttestationObject();
      const { b64url: ad } = buildAuthenticatorData({ flags: { UP: true }, signCount: 7 });
      const result = Fido2Decoder.decodeFido2Request({ type: 'json', data: { authenticatorData: ad, attestationObject: att } });
      expect(result.authenticatorData.signCount).toBe(7);
      expect(result.authenticatorData.flags.AT).toBe(false);
    });
  });

  describe('cborToPlain', () => {
    it('converts Maps with integer keys, byte strings and nested arrays', () => {
      const plain = Fido2Decoder.cborToPlain(new Map([[1, bytes(2, 0xab)], [-1, [new Map([['k', 'v']])]]]));
      expect(plain).toEqual({ '1': 'abab', '-1': [{ k: 'v' }] });
    });
  });
});