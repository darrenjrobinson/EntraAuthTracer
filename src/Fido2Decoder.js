/**
 * Entra Auth Tracer - FIDO2 Decoder
 * CBOR decoding for FIDO2/Passkey authentication flows
 * 
 * Handles:
 * - clientDataJSON Base64url decoding and parsing
 * - authenticatorData binary structure parsing
 * - CBOR decoding of credential public keys
 * - Support for EC2 and RSA key types
 */

// Import CBOR decoder for credential public key parsing
import CBOR from 'cbor-web';

class Fido2Decoder {
  /**
   * Decode FIDO2 request body
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
      error: null
    };

    try {
      // Decode clientDataJSON if present
      if (data.clientDataJSON) {
        result.clientDataJSON = this.decodeClientDataJSON(data.clientDataJSON);
      }

      // Decode authenticatorData if present
      if (data.authenticatorData) {
        result.authenticatorData = this.decodeAuthenticatorData(data.authenticatorData);
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
      // Base64url decode
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
   * Decode authenticatorData binary structure
   */
  static decodeAuthenticatorData(authenticatorData) {
    try {
      // Base64url decode to ArrayBuffer
      const buffer = this.base64urlDecodeToBuffer(authenticatorData);
      const view = new DataView(buffer);

      const result = {
        rpIdHash: null,
        flags: null,
        signCount: null,
        attestedCredentialData: null,
        extensions: null
      };

      // Parse fixed header (37 bytes minimum)
      if (buffer.byteLength < 37) {
        throw new Error('authenticatorData too short');
      }

      // rpIdHash (32 bytes)
      result.rpIdHash = this.bufferToHex(buffer.slice(0, 32));

      // flags (1 byte)
      const flagsByte = view.getUint8(32);
      result.flags = this.parseFlags(flagsByte);

      // signCount (4 bytes, big-endian)
      result.signCount = view.getUint32(33, false);

      // Parse attested credential data if AT flag is set
      if (result.flags.AT && buffer.byteLength > 37) {
        result.attestedCredentialData = this.parseAttestedCredentialData(buffer.slice(37));
      }

      return result;
    } catch (error) {
      throw new Error(`Failed to decode authenticatorData: ${error.message}`);
    }
  }

  /**
   * Parse authenticator flags byte
   */
  static parseFlags(flagsByte) {
    return {
      UP: !!(flagsByte & 0x01), // User Present
      RFU1: !!(flagsByte & 0x02), // Reserved for future use
      UV: !!(flagsByte & 0x04), // User Verified
      RFU2: !!(flagsByte & 0x08), // Reserved for future use
      RFU3: !!(flagsByte & 0x10), // Reserved for future use
      RFU4: !!(flagsByte & 0x20), // Reserved for future use
      AT: !!(flagsByte & 0x40), // Attested credential data included
      ED: !!(flagsByte & 0x80), // Extension data included
      raw: flagsByte
    };
  }

  /**
   * Parse attested credential data (when AT flag is set)
   */
  static parseAttestedCredentialData(buffer) {
    const view = new DataView(buffer);
    let offset = 0;

    try {
      // AAGUID (16 bytes)
      const aaguid = this.parseAAGUID(buffer.slice(offset, offset + 16));
      offset += 16;

      // Credential ID Length (2 bytes, big-endian)
      const credentialIdLength = view.getUint16(offset, false);
      offset += 2;

      // Credential ID (credentialIdLength bytes)
      const credentialId = this.bufferToHex(buffer.slice(offset, offset + credentialIdLength));
      offset += credentialIdLength;

      // Credential Public Key (CBOR-encoded, remainder of buffer)
      const publicKeyBuffer = buffer.slice(offset);
      const credentialPublicKey = this.decodeCBORPublicKey(publicKeyBuffer);

      return {
        aaguid,
        credentialIdLength,
        credentialId,
        credentialPublicKey
      };
    } catch (error) {
      throw new Error(`Failed to parse attested credential data: ${error.message}`);
    }
  }

  /**
   * Parse AAGUID to UUID string
   */
  static parseAAGUID(buffer) {
    const hex = this.bufferToHex(buffer);
    // Format as UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    return [
      hex.substring(0, 8),
      hex.substring(8, 12),
      hex.substring(12, 16),
      hex.substring(16, 20),
      hex.substring(20, 32)
    ].join('-');
  }

  /**
   * Decode CBOR public key with full EC2/RSA support
   */
  static decodeCBORPublicKey(buffer) {
    try {
      // Decode CBOR structure
      const decoded = CBOR.decode(buffer);
      
      const result = {
        type: 'cbor',
        size: buffer.byteLength,
        hex: this.bufferToHex(buffer),
        decoded: decoded,
        keyInfo: null,
        error: null
      };

      // Parse key type and extract key information
      if (decoded && typeof decoded === 'object') {
        result.keyInfo = this.parseKeyInfo(decoded);
      }

      return result;
    } catch (error) {
      return {
        type: 'cbor',
        size: buffer.byteLength,
        hex: this.bufferToHex(buffer),
        decoded: null,
        keyInfo: null,
        error: `CBOR decoding failed: ${error.message}`
      };
    }
  }

  /**
   * Parse key information from CBOR decoded structure
   */
  static parseKeyInfo(cborObj) {
    try {
      const keyType = cborObj[1]; // COSE key type
      const algorithm = cborObj[3]; // COSE algorithm
      
      const keyInfo = {
        keyType: keyType,
        algorithm: algorithm,
        keyTypeDescription: this.getKeyTypeDescription(keyType),
        algorithmDescription: this.getAlgorithmDescription(algorithm),
        parameters: {}
      };

      // Parse based on key type
      if (keyType === 2) {
        // EC2 Key (Elliptic Curve)
        keyInfo.parameters = {
          curve: cborObj[-1], // EC curve identifier
          x: cborObj[-2], // x coordinate
          y: cborObj[-3], // y coordinate
          curveDescription: this.getCurveDescription(cborObj[-1])
        };
      } else if (keyType === 3) {
        // RSA Key
        keyInfo.parameters = {
          n: cborObj[-1], // RSA modulus
          e: cborObj[-2]  // RSA exponent
        };
      } else {
        // Unknown key type - include all parameters
        keyInfo.parameters = { ...cborObj };
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
   * Get human-readable key type description
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
   * Get human-readable algorithm description
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
   * Get human-readable curve description
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
    // Convert base64url to base64
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    
    // Add padding if needed
    while (base64.length % 4) {
      base64 += '=';
    }

    // Decode base64 to string
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
   * Convert ArrayBuffer to hex string
   */
  static bufferToHex(buffer) {
    const view = new Uint8Array(buffer);
    return Array.from(view)
      .map(byte => byte.toString(16).padStart(2, '0'))
      .join('');
  }
}

export default Fido2Decoder;