/**
 * Entra Auth Tracer - Entra Claims Decoder
 * Human-readable decoding of Entra-specific JWT claims
 * 
 * Handles:
 * - Entra-proprietary claims registry
 * - CAE (Continuous Access Evaluation) detection
 * - PoP (Proof-of-Possession) token binding
 * - Timestamp decoding and expiry warnings
 * - Claims labeling and semantic interpretation
 */

class EntraClaimsDecoder {
  // Entra-specific claims registry
  static ENTRA_CLAIMS = {
    // Identity
    tid: { label: 'Tenant ID', detail: 'Entra tenant GUID' },
    oid: { label: 'Object ID', detail: 'User/service principal object GUID' },
    sub: { label: 'Subject', detail: 'Immutable per-app user identifier' },
    idtyp: { label: 'Identity type', detail: 'user / app / managed_identity' },
    acct: { label: 'Account type', detail: '0 = member, 1 = guest' },

    // Token metadata
    ver: { label: 'Token version', detail: '1.0 = v1 endpoint, 2.0 = v2 endpoint' },
    aud: { label: 'Audience', detail: 'Intended recipient (app URI or client_id)' },
    iss: { label: 'Issuer', detail: 'STS issuer URI' },
    iat: { label: 'Issued at', detail: 'Unix timestamp — decode to human-readable' },
    nbf: { label: 'Not before', detail: 'Unix timestamp — decode to human-readable' },
    exp: { label: 'Expiry', detail: 'Unix timestamp — decode to human-readable; flag if expired' },

    // Authorization
    scp: { label: 'Delegated scopes', detail: 'Space-separated OAuth scopes (delegated flows)' },
    roles: { label: 'App roles', detail: 'Application role assignments' },
    wids: { label: 'Directory role IDs', detail: 'Entra directory role GUIDs' },

    // Authentication
    amr: { label: 'Auth methods', detail: 'pwd / mfa / wia / fido / rsa / ngcmfa etc.' },
    auth_time: { label: 'Auth time', detail: 'Unix timestamp of initial authentication' },
    nonce: { label: 'Nonce', detail: 'Replay protection value from authorize request' },

    // CAE & Security
    xms_cc: { label: 'CAE capability', detail: 'cp1 = client supports Continuous Access Evaluation' },
    xms_ae: { label: 'Authentication event', detail: 'Entra auth event identifier' },
    acrs: { label: 'Auth context class ref', detail: 'Step-up auth requirement (Conditional Access)' },
    cnf: { label: 'Confirmation (PoP)', detail: 'Proof-of-possession key binding (jwk thumbprint)' },

    // App & Client
    azp: { label: 'Authorized party', detail: 'Client ID of the authorized application' },
    azpacr: { label: 'Auth party ACR', detail: 'Client auth method: 0=public, 1=secret, 2=cert' },
    appid: { label: 'Application ID', detail: 'Client application ID (v1 tokens)' },

    // User info
    name: { label: 'Display name', detail: 'User display name' },
    upn: { label: 'UPN', detail: 'User Principal Name' },
    email: { label: 'Email', detail: 'Email address claim' },
    family_name: { label: 'Surname', detail: 'User surname' },
    given_name: { label: 'Given name', detail: 'User given name' }
  };

  /**
   * Decode JWT token and extract Entra-specific information
   */
  static decodeEntraToken(tokenString) {
    try {
      const payload = this.parseJWT(tokenString);
      
      return {
        isEntraToken: this.isEntraToken(payload),
        caeEnabled: this.detectCAE(payload),
        popBinding: this.detectPoP(payload),
        claims: this.processEntraClaims(payload),
        summary: this.createSummary(payload),
        warnings: this.generateWarnings(payload)
      };
    } catch (error) {
      return {
        error: `Failed to decode token: ${error.message}`,
        isEntraToken: false,
        caeEnabled: false,
        popBinding: null,
        claims: [],
        summary: null,
        warnings: []
      };
    }
  }

  /**
   * Parse JWT token (basic implementation)
   */
  static parseJWT(token) {
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid JWT format');
    }

    // Decode payload (second part)
    const payload = parts[1];
    const decoded = this.base64urlDecode(payload);
    return JSON.parse(decoded);
  }

  /**
   * Check if this is an Entra-issued token
   */
  static isEntraToken(payload) {
    // Check for Entra-specific claims
    const entraIndicators = ['xms_cc', 'xms_ae', 'acrs', 'cnf', 'wids', 'idtyp', 'acct', 'azpacr'];
    const hasEntraClaims = entraIndicators.some(claim => payload.hasOwnProperty(claim));

    // Check issuer
    const issuer = payload.iss || '';
    const isEntraIssuer = issuer.includes('sts.windows.net') || 
                         issuer.includes('login.microsoftonline.com');

    return hasEntraClaims || isEntraIssuer;
  }

  /**
   * Detect CAE (Continuous Access Evaluation) capability
   */
  static detectCAE(payload) {
    const caeCapability = payload.xms_cc;
    
    if (!caeCapability) return false;
    
    // CAE capability can be a string or array
    if (typeof caeCapability === 'string') {
      return caeCapability === 'cp1';
    }
    
    if (Array.isArray(caeCapability)) {
      return caeCapability.includes('cp1');
    }
    
    return false;
  }

  /**
   * Detect PoP (Proof-of-Possession) binding
   */
  static detectPoP(payload) {
    const cnf = payload.cnf;
    
    if (!cnf) return null;
    
    return {
      present: true,
      jwkThumbprint: cnf.jkt || null,
      raw: cnf
    };
  }

  /**
   * Process and label Entra claims
   */
  static processEntraClaims(payload) {
    const processedClaims = [];

    for (const [claimName, claimValue] of Object.entries(payload)) {
      const claimInfo = this.ENTRA_CLAIMS[claimName];
      
      const processedClaim = {
        name: claimName,
        value: this.formatClaimValue(claimName, claimValue),
        rawValue: claimValue,
        label: claimInfo ? claimInfo.label : null,
        detail: claimInfo ? claimInfo.detail : null,
        isEntraSpecific: !!claimInfo,
        isTimestamp: this.isTimestampClaim(claimName)
      };

      processedClaims.push(processedClaim);
    }

    return processedClaims;
  }

  /**
   * Format claim value for display
   */
  static formatClaimValue(claimName, value) {
    // Handle timestamps
    if (this.isTimestampClaim(claimName) && typeof value === 'number') {
      return this.formatTimestamp(value);
    }

    // Handle arrays
    if (Array.isArray(value)) {
      return value.join(', ');
    }

    // Handle objects
    if (typeof value === 'object' && value !== null) {
      return JSON.stringify(value);
    }

    return String(value);
  }

  /**
   * Check if claim is a timestamp
   */
  static isTimestampClaim(claimName) {
    return ['iat', 'nbf', 'exp', 'auth_time'].includes(claimName);
  }

  /**
   * Format Unix timestamp to human-readable string
   */
  static formatTimestamp(timestamp) {
    const date = new Date(timestamp * 1000);
    return date.toISOString();
  }

  /**
   * Create summary information
   */
  static createSummary(payload) {
    return {
      tenant: payload.tid || null,
      identityType: payload.idtyp || 'unknown',
      tokenVersion: payload.ver || 'unknown',
      audience: payload.aud || null,
      issuer: payload.iss || null,
      scopes: payload.scp || payload.roles || null,
      expiry: payload.exp ? this.formatTimestamp(payload.exp) : null,
      isExpired: payload.exp ? (payload.exp * 1000 < Date.now()) : false
    };
  }

  /**
   * Generate warnings for token issues
   */
  static generateWarnings(payload) {
    const warnings = [];

    // Check for expiry
    if (payload.exp && payload.exp * 1000 < Date.now()) {
      warnings.push({
        type: 'expiry',
        message: 'Token has expired',
        severity: 'error'
      });
    }

    // Check for missing PKCE (if this is an authorization code flow)
    // This will be expanded in Phase 3

    return warnings;
  }

  /**
   * Base64url decode
   */
  static base64urlDecode(str) {
    // Convert base64url to base64
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    
    // Add padding if needed
    while (base64.length % 4) {
      base64 += '=';
    }

    // Decode base64
    return atob(base64);
  }
}

export default EntraClaimsDecoder;