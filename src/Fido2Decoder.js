/**
 * Entra Auth Tracer - FIDO2 / WebAuthn Decoder
 *
 * Decodes the binary structures a client sends during passkey registration
 * (attestation) and authentication (assertion):
 *  - clientDataJSON (base64url JSON)
 *  - authenticatorData (rpIdHash, flags, signCount, attested credential data,
 *    extensions) per WebAuthn Level 3 §6.1
 *  - attestationObject (CBOR { fmt, attStmt, authData })
 *  - COSE_Key public keys (RFC 9052) — cbor-web returns integer-keyed Maps
 *
 * Only request-side data is available in MV3 (no response bodies), so this is
 * the client → RP half of the ceremony.
 */

import * as CBOR from 'cbor-web';

class Fido2Decoder {
  /**
   * Well-known authenticator AAGUIDs.
   *
   * Sources (verified September 2026):
   *  - passkeydeveloper/passkey-authenticator-aaguids community list
   *    (https://github.com/passkeydeveloper/passkey-authenticator-aaguids)
   *  - darrenjrobinson/PasskeyProviderAAGUIDs PowerShell module
   *    (https://github.com/darrenjrobinson/PasskeyProviderAAGUIDs)
   *  - Microsoft Learn: Windows Hello / Authenticator AAGUIDs
   * Keys are lower-case UUIDs. `kind` is platform | roaming | password_manager.
   */
  static AAGUID_REGISTRY = {
    // Microsoft
    '08987058-cadc-4b81-b6e1-30de50dcbe96': { name: 'Windows Hello Hardware Authenticator', vendor: 'Microsoft', kind: 'platform' },
    '9ddd1817-af5a-4672-a2b9-3e3dd95000a9': { name: 'Windows Hello VBS Hardware Authenticator', vendor: 'Microsoft', kind: 'platform' },
    '6028b017-b1d4-4c02-b4b3-afcdafc96bb2': { name: 'Windows Hello Software Authenticator', vendor: 'Microsoft', kind: 'platform' },
    'de1e552d-db1d-4423-a619-566b625cdc84': { name: 'Microsoft Authenticator for Android (Preview)', vendor: 'Microsoft', kind: 'platform' },
    '90a3ccdf-635c-4729-a248-9b709135078f': { name: 'Microsoft Authenticator for iOS (Preview)', vendor: 'Microsoft', kind: 'platform' },
    // Apple / Google / Samsung platform authenticators
    'fbfc3007-154e-4ecc-8c0b-6e020557d7bd': { name: 'Apple Passwords (iCloud Keychain)', vendor: 'Apple', kind: 'platform' },
    'dd4ec289-e01d-41c9-bb89-70fa845d4bf2': { name: 'iCloud Keychain (Managed)', vendor: 'Apple', kind: 'platform' },
    'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4': { name: 'Google Password Manager', vendor: 'Google', kind: 'platform' },
    'adce0002-35bc-c60a-648b-0b25f1f05503': { name: 'Chrome on Mac', vendor: 'Google', kind: 'platform' },
    '53414d53-554e-4700-0000-000000000000': { name: 'Samsung Pass', vendor: 'Samsung', kind: 'platform' },
    // Password managers
    'bada5566-a7aa-401f-bd96-45619a55120d': { name: '1Password', vendor: 'AgileBits', kind: 'password_manager' },
    'd548826e-79b4-db40-a3d8-11116f7e8349': { name: 'Bitwarden', vendor: 'Bitwarden', kind: 'password_manager' },
    '531126d6-e717-415c-9320-3d9aa6981239': { name: 'Dashlane', vendor: 'Dashlane', kind: 'password_manager' },
    'f3809540-7f14-49c1-a8b3-8f813b225541': { name: 'Enpass', vendor: 'Enpass', kind: 'password_manager' },
    '0ea242b4-43c4-4a1b-8b17-dd6d0b6baec6': { name: 'Keeper', vendor: 'Keeper Security', kind: 'password_manager' },
    'fdb141b2-5d84-443e-8a35-4698c205a502': { name: 'KeePassXC', vendor: 'KeePassXC', kind: 'password_manager' },
    'b84e4048-15dc-4dd0-8640-f4f60813c8af': { name: 'NordPass', vendor: 'Nord Security', kind: 'password_manager' },
    '50726f74-6f6e-5061-7373-50726f746f6e': { name: 'Proton Pass', vendor: 'Proton', kind: 'password_manager' },
    '39a5647e-1853-446c-a1f6-a79bae9f5bc7': { name: 'IDmelon', vendor: 'IDmelon', kind: 'roaming' },
    // Yubico roaming authenticators
    'cb69481e-8ff7-4039-93ec-0a2729a154a8': { name: 'YubiKey 5 Series', vendor: 'Yubico', kind: 'roaming' },
    'ee882879-721c-4913-9775-3dfcce97072a': { name: 'YubiKey 5 Series', vendor: 'Yubico', kind: 'roaming' },
    'fa2b99dc-9e39-4257-8f92-4a30d23c4118': { name: 'YubiKey 5 Series with NFC', vendor: 'Yubico', kind: 'roaming' },
    '2fc0579f-8113-47ea-b116-bb5a8db9202a': { name: 'YubiKey 5 Series with NFC', vendor: 'Yubico', kind: 'roaming' },
    'c5ef55ff-ad9a-4b9f-b580-adebafe026d0': { name: 'YubiKey 5 Series with Lightning (5Ci)', vendor: 'Yubico', kind: 'roaming' },
    '73bb0cd4-e502-49b8-9c6f-b59445bf720b': { name: 'YubiKey 5 FIPS Series', vendor: 'Yubico', kind: 'roaming' },
    'd8522d9f-575b-4866-88a9-ba99fa02f35b': { name: 'YubiKey Bio Series', vendor: 'Yubico', kind: 'roaming' },
    'f8a011f3-8c0a-4d15-8006-17111f9edc7d': { name: 'Security Key by Yubico', vendor: 'Yubico', kind: 'roaming' },
    'b92c3f9a-c014-4056-887f-140a2501163b': { name: 'Security Key by Yubico', vendor: 'Yubico', kind: 'roaming' },
    '149a2021-8ef6-4133-96b8-81f8d5b7f1f5': { name: 'Security Key by Yubico with NFC', vendor: 'Yubico', kind: 'roaming' },
    '6d44ba9b-f6ec-2e49-b930-0c8fe920cb73': { name: 'Security Key by Yubico with NFC', vendor: 'Yubico', kind: 'roaming' },
    'e77e3c64-05e3-428b-8824-0cbeb04b829d': { name: 'Security Key NFC by Yubico', vendor: 'Yubico', kind: 'roaming' },
    'a4e9fc6d-4cbe-4758-b8ba-37598bb5bbaa': { name: 'Security Key NFC by Yubico', vendor: 'Yubico', kind: 'roaming' },
    '47ab2fb4-66ac-4184-9ae1-86be814012d5': { name: 'Security Key NFC by Yubico - Enterprise Edition', vendor: 'Yubico', kind: 'roaming' },
    '0bb43545-fd2c-4185-87dd-feb0b2916ace': { name: 'Security Key NFC by Yubico - Enterprise Edition', vendor: 'Yubico', kind: 'roaming' },
    '9ff4cc65-6154-4fff-ba09-9e2af7882ad2': { name: 'Security Key NFC by Yubico - Enterprise Edition (Enterprise Profile)', vendor: 'Yubico', kind: 'roaming' },
    '2772ce93-eb4b-4090-8b73-330f48477d73': { name: 'Security Key NFC by Yubico - Enterprise Edition Preview', vendor: 'Yubico', kind: 'roaming' },
    '760eda36-00aa-4d29-855b-4012a182cdeb': { name: 'Security Key NFC by Yubico Preview', vendor: 'Yubico', kind: 'roaming' }
  };

  static ZERO_AAGUID = '00000000-0000-0000-0000-000000000000';

  /**
   * Decode a FIDO2 request body. Accepts the flat shape ({ clientDataJSON,
   * authenticatorData }) as well as PublicKeyCredential JSON where the
   * ceremony data is nested under `response`.
   */
  static decodeFido2Request(requestBody) {
    if (!requestBody || requestBody.type !== 'json') {
      return null;
    }

    const data = requestBody.data;
    const result = {
      type: 'fido2',
      clientDataJSON: null,
      authenticatorData: null,
      attestationObject: null,
      error: null
    };

    try {
      const src = (data && data.response && typeof data.response === 'object') ? data.response : data;

      if (src.clientDataJSON) {
        result.clientDataJSON = this.decodeClientDataJSON(src.clientDataJSON);
      }

      if (src.authenticatorData) {
        result.authenticatorData = this.decodeAuthenticatorData(src.authenticatorData);
      }

      if (src.attestationObject) {
        result.attestationObject = this.decodeAttestationObject(src.attestationObject);
        // Registration responses carry authenticatorData inside the attestation
        // object — surface it in the usual place so renderers need no special case.
        if (!result.authenticatorData && result.attestationObject.authData) {
          result.authenticatorData = result.attestationObject.authData;
        }
      }

      return result;
    } catch (error) {
      result.error = error.message;
      return result;
    }
  }

  /**
   * Decode clientDataJSON from Base64url
   */
  static decodeClientDataJSON(clientDataJSON) {
    try {
      const jsonString = this.base64urlDecode(clientDataJSON);
      const parsed = JSON.parse(jsonString);

      return {
        type: parsed.type, // webauthn.create or webauthn.get
        challenge: parsed.challenge,
        origin: parsed.origin,
        crossOrigin: parsed.crossOrigin || false,
        raw: parsed
      };
    } catch (error) {
      throw new Error(`Failed to decode clientDataJSON: ${error.message}`);
    }
  }

  /**
   * Decode base64url authenticatorData.
   */
  static decodeAuthenticatorData(authenticatorData) {
    try {
      const buffer = this.base64urlDecodeToBuffer(authenticatorData);
      return this.decodeAuthenticatorDataBytes(new Uint8Array(buffer));
    } catch (error) {
      throw new Error(`Failed to decode authenticatorData: ${error.message}`);
    }
  }

  /**
   * Decode raw authenticatorData bytes (WebAuthn L3 §6.1):
   *   rpIdHash(32) | flags(1) | signCount(4) | [attestedCredentialData] | [extensions]
   */
  static decodeAuthenticatorDataBytes(bytes) {
    const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    if (u8.byteLength < 37) {
      throw new Error('authenticatorData too short');
    }
    const view = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);

    const result = {
      rpIdHash: this.bufferToHex(u8.subarray(0, 32)),
      flags: this.parseFlags(view.getUint8(32)),
      signCount: view.getUint32(33, false),
      attestedCredentialData: null,
      extensions: null
    };

    let offset = 37;

    // The flags are authenticated data: when AT/ED are set the corresponding bytes
    // must follow, so parse unconditionally and let missing data surface as an error.
    if (result.flags.AT) {
      const attested = this.parseAttestedCredentialData(u8.subarray(offset));
      result.attestedCredentialData = attested;
      offset += 18 + attested.credentialIdLength + (attested.credentialPublicKey.size || 0);
    }

    if (result.flags.ED) {
      try {
        const ext = CBOR.decodeFirstSync(new Uint8Array(u8.subarray(offset)), { extendedResults: true });
        result.extensions = this.cborToPlain(ext.value);
      } catch (error) {
        result.extensions = { error: `Extension decoding failed: ${error.message}` };
      }
    }

    return result;
  }

  /**
   * Parse the authenticator flags byte (WebAuthn L3 §6.1, Table 1).
   */
  static parseFlags(flagsByte) {
    return {
      UP: !!(flagsByte & 0x01),   // User Present
      RFU1: !!(flagsByte & 0x02), // Reserved for future use
      UV: !!(flagsByte & 0x04),   // User Verified
      BE: !!(flagsByte & 0x08),   // Backup Eligibility (credential may be synced)
      BS: !!(flagsByte & 0x10),   // Backup State (credential is currently backed up)
      RFU4: !!(flagsByte & 0x20), // Reserved for future use
      AT: !!(flagsByte & 0x40),   // Attested credential data included
      ED: !!(flagsByte & 0x80),   // Extension data included
      raw: flagsByte
    };
  }

  /**
   * Parse attested credential data (present when the AT flag is set):
   *   aaguid(16) | credentialIdLength(2) | credentialId | credentialPublicKey(CBOR)
   */
  static parseAttestedCredentialData(buffer) {
    const u8 = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    try {
      if (u8.byteLength < 18) throw new Error('attested credential data too short');
      const view = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);

      const aaguid = this.parseAAGUID(u8.subarray(0, 16));
      const credentialIdLength = view.getUint16(16, false);
      if (u8.byteLength < 18 + credentialIdLength) throw new Error('credential ID exceeds buffer length');

      const credentialId = this.bufferToHex(u8.subarray(18, 18 + credentialIdLength));
      const credentialPublicKey = this.decodeCBORPublicKey(u8.subarray(18 + credentialIdLength));

      return {
        aaguid,
        authenticator: this.lookupAAGUID(aaguid),
        credentialIdLength,
        credentialId,
        credentialPublicKey
      };
    } catch (error) {
      throw new Error(`Failed to parse attested credential data: ${error.message}`);
    }
  }

  /**
   * Parse AAGUID bytes to a UUID string.
   */
  static parseAAGUID(buffer) {
    const hex = this.bufferToHex(buffer);
    return [
      hex.substring(0, 8),
      hex.substring(8, 12),
      hex.substring(12, 16),
      hex.substring(16, 20),
      hex.substring(20, 32)
    ].join('-');
  }

  /**
   * Look up a well-known authenticator by AAGUID.
   * @returns {{ name, vendor, kind } | null}
   */
  static lookupAAGUID(uuid) {
    if (!uuid) return null;
    const key = String(uuid).toLowerCase();
    if (key === this.ZERO_AAGUID) {
      return { name: 'Not provided (zero AAGUID)', vendor: null, kind: 'unknown' };
    }
    return this.AAGUID_REGISTRY[key] || null;
  }

  /**
   * Decode a COSE_Key public key. Only the bytes belonging to the CBOR item are
   * consumed, so data that follows the key (e.g. extensions) is left untouched.
   */
  static decodeCBORPublicKey(buffer) {
    const u8 = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    try {
      const { value, length } = CBOR.decodeFirstSync(new Uint8Array(u8), { extendedResults: true });
      if (!value || typeof value !== 'object') {
        throw new Error('expected a COSE_Key map');
      }
      const consumed = u8.subarray(0, length);
      return {
        type: 'cbor',
        size: length,
        hex: this.bufferToHex(consumed),
        decoded: this.cborToPlain(value),
        keyInfo: this.parseKeyInfo(value),
        error: null
      };
    } catch (error) {
      return {
        type: 'cbor',
        size: u8.byteLength,
        hex: this.bufferToHex(u8),
        decoded: null,
        keyInfo: null,
        error: `CBOR decoding failed: ${error.message}`
      };
    }
  }

  /**
   * Extract key type, algorithm and parameters from a decoded COSE_Key.
   * Accepts the integer-keyed Map cbor-web produces as well as a plain object.
   */
  static parseKeyInfo(cborObj) {
    try {
      const get = (k) => (cborObj instanceof Map ? cborObj.get(k) : cborObj[k]);
      const keyType = get(1);   // kty
      const algorithm = get(3); // alg

      const keyInfo = {
        keyType,
        algorithm,
        keyTypeDescription: this.getKeyTypeDescription(keyType),
        algorithmDescription: this.getAlgorithmDescription(algorithm),
        parameters: {}
      };

      if (keyType === 2) {
        // EC2 — curve + x/y coordinates
        keyInfo.parameters = {
          curve: get(-1),
          x: this.toHexIfBytes(get(-2)),
          y: this.toHexIfBytes(get(-3)),
          curveDescription: this.getCurveDescription(get(-1))
        };
      } else if (keyType === 3) {
        // RSA — modulus + exponent
        keyInfo.parameters = {
          n: this.toHexIfBytes(get(-1)),
          e: this.toHexIfBytes(get(-2))
        };
      } else if (keyType === 1) {
        // OKP — curve + public key
        keyInfo.parameters = {
          curve: get(-1),
          x: this.toHexIfBytes(get(-2)),
          curveDescription: this.getCurveDescription(get(-1))
        };
      } else {
        keyInfo.parameters = this.cborToPlain(cborObj);
      }

      return keyInfo;
    } catch (error) {
      return {
        error: `Failed to parse key info: ${error.message}`,
        raw: cborObj
      };
    }
  }

  /**
   * Decode a base64url attestationObject: CBOR { fmt, attStmt, authData }.
   */
  static decodeAttestationObject(attestationObject) {
    try {
      const u8 = new Uint8Array(this.base64urlDecodeToBuffer(attestationObject));
      const decoded = CBOR.decodeFirstSync(u8);
      const get = (obj, k) => (obj instanceof Map ? obj.get(k) : (obj ? obj[k] : undefined));

      const fmt = get(decoded, 'fmt');
      const attStmt = get(decoded, 'attStmt') || {};
      const authData = get(decoded, 'authData');
      const alg = get(attStmt, 'alg');
      const x5c = get(attStmt, 'x5c');

      return {
        fmt: fmt || null,
        attStmt: {
          alg: alg ?? null,
          algorithmDescription: alg != null ? this.getAlgorithmDescription(alg) : null,
          sigHex: this.toHexIfBytes(get(attStmt, 'sig')) || null,
          x5cCount: Array.isArray(x5c) ? x5c.length : 0
        },
        authData: authData ? this.decodeAuthenticatorDataBytes(new Uint8Array(authData)) : null
      };
    } catch (error) {
      throw new Error(`Failed to decode attestationObject: ${error.message}`);
    }
  }

  /**
   * Convert a cbor-web decoded value into JSON-friendly plain data:
   * Maps → objects (string keys), byte strings → hex, arrays/objects recursed.
   */
  static cborToPlain(value) {
    if (value instanceof Map) {
      const out = {};
      for (const [k, v] of value) out[String(k)] = this.cborToPlain(v);
      return out;
    }
    if (value instanceof Uint8Array || value instanceof ArrayBuffer) {
      return this.bufferToHex(value);
    }
    if (Array.isArray(value)) {
      return value.map((v) => this.cborToPlain(v));
    }
    if (value && typeof value === 'object' && !(value instanceof Date)) {
      const out = {};
      for (const [k, v] of Object.entries(value)) out[k] = this.cborToPlain(v);
      return out;
    }
    return value;
  }

  /** Hex-encode byte-like values; pass everything else through. */
  static toHexIfBytes(value) {
    if (value instanceof Uint8Array || value instanceof ArrayBuffer) return this.bufferToHex(value);
    return value;
  }

  /**
   * Get human-readable key type description (COSE kty)
   */
  static getKeyTypeDescription(keyType) {
    const keyTypes = {
      1: 'OKP (Octet Key Pair)',
      2: 'EC2 (Elliptic Curve Keys w/ x- and y-coordinate pair)',
      3: 'RSA (RSA Key)',
      4: 'Symmetric Keys'
    };
    return keyTypes[keyType] || `Unknown (${keyType})`;
  }

  /**
   * Get human-readable algorithm description (COSE alg)
   */
  static getAlgorithmDescription(algorithm) {
    const algorithms = {
      '-7': 'ES256 (ECDSA w/ SHA-256)',
      '-35': 'ES384 (ECDSA w/ SHA-384)',
      '-36': 'ES512 (ECDSA w/ SHA-512)',
      '-257': 'RS256 (RSASSA-PKCS1-v1_5 w/ SHA-256)',
      '-258': 'RS384 (RSASSA-PKCS1-v1_5 w/ SHA-384)',
      '-259': 'RS512 (RSASSA-PKCS1-v1_5 w/ SHA-512)',
      '-37': 'PS256 (RSASSA-PSS w/ SHA-256)',
      '-38': 'PS384 (RSASSA-PSS w/ SHA-384)',
      '-39': 'PS512 (RSASSA-PSS w/ SHA-512)',
      '-8': 'EdDSA (EdDSA signature algorithms)'
    };
    return algorithms[String(algorithm)] || `Unknown (${algorithm})`;
  }

  /**
   * Get human-readable curve description (COSE crv)
   */
  static getCurveDescription(curve) {
    const curves = {
      1: 'P-256 (secp256r1)',
      2: 'P-384 (secp384r1)',
      3: 'P-521 (secp521r1)',
      4: 'X25519 (for ECDH)',
      5: 'X448 (for ECDH)',
      6: 'Ed25519 (for EdDSA)',
      7: 'Ed448 (for EdDSA)'
    };
    return curves[curve] || `Unknown (${curve})`;
  }

  /**
   * Base64url decode to string
   */
  static base64urlDecode(str) {
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) {
      base64 += '=';
    }
    return atob(base64);
  }

  /**
   * Base64url decode to ArrayBuffer
   */
  static base64urlDecodeToBuffer(str) {
    const binaryString = this.base64urlDecode(str);
    const buffer = new ArrayBuffer(binaryString.length);
    const view = new Uint8Array(buffer);
    for (let i = 0; i < binaryString.length; i++) {
      view[i] = binaryString.charCodeAt(i);
    }
    return buffer;
  }

  /**
   * Convert an ArrayBuffer or Uint8Array to a hex string
   */
  static bufferToHex(buffer) {
    const view = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    return Array.from(view)
      .map((byte) => byte.toString(16).padStart(2, '0'))
      .join('');
  }
}

export default Fido2Decoder;
