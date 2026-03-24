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
    given_name: { label: 'Given name', detail: 'User given name' },
    unique_name: { label: 'Unique name', detail: 'Human-readable subject (v1 tokens — prefer upn/email)' },
    login_hint: { label: 'Login hint', detail: 'UPN or email prefill hint carried by the token' },
    puid: { label: 'PUID', detail: 'Primary User Identifier from MSA or Entra' },

    // Device & Network
    deviceid: { label: 'Device ID', detail: 'Entra-registered device GUID' },
    platf: { label: 'Device platform', detail: '2=Windows, 3=Win Phone, 4=Win VM, 5=iOS, 6=Android, 7=macOS' },
    ipaddr: { label: 'IP Address', detail: 'Client IP address at time of authentication' },
    ctry: { label: 'Country', detail: 'ISO 3166-1 alpha-2 country code from IP geolocation' },
    onprem_sid: { label: 'On-premises SID', detail: 'On-premises Active Directory Security Identifier' },

    // Token internals
    uti: { label: 'Token ID', detail: 'Unique token instance identifier — use for log correlation' },
    rh: { label: 'Refresh epoch', detail: 'Internal refresh-token family hash (opaque)' },
    sid: { label: 'Session ID', detail: 'Per-session OIDC identifier — used for front-channel logout' },
    at_hash: { label: 'Access token hash', detail: 'SHA-256 hash of access_token (first half) — binds id_token to access_token' },
    c_hash: { label: 'Code hash', detail: 'SHA-256 hash of authorization code (first half)' },
    xms_tpl: { label: 'Tenant language', detail: 'Tenant preferred locale (e.g., en-US)' },
    xms_pdl: { label: 'Preferred data location', detail: 'Multi-geo preferred data location code' },
    xms_ssm: { label: 'SSO session method', detail: 'SSO session state / sign-in method context' }
  };

  // Human-readable labels for AMR (Authentication Method Reference) values
  static AMR_VALUES = {
    pwd: 'Password',
    mfa: 'Multi-Factor Authentication (generic)',
    wia: 'Windows Integrated Authentication (Kerberos/NTLM)',
    fido: 'FIDO2 / Passkey',
    rsa: 'RSA hardware token',
    ngcmfa: 'Windows Hello for Business (NGC MFA)',
    otp: 'One-Time Password',
    sms: 'SMS one-time code',
    voice: 'Voice call verification',
    fed: 'Federated identity provider',
    email: 'Email OTP',
    pop: 'Proof-of-Possession',
    kba: 'Knowledge-Based Authentication',
    swk: 'Software-bound key',
    hwk: 'Hardware-bound key (TPM)',
    pin: 'PIN',
    mca: 'Microsoft Authenticator app',
    tel: 'Telephony OTP'
  };

  // Human-readable platform names for the `platf` claim
  static PLATFORM_VALUES = {
    '1': 'Unknown',
    '2': 'Windows',
    '3': 'Windows Phone',
    '4': 'Windows (Virtual/Server)',
    '5': 'iOS',
    '6': 'Android',
    '7': 'macOS'
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
    const hasEntraClaims = entraIndicators.some(claim => Object.prototype.hasOwnProperty.call(payload, claim));

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

    // Decode AMR values to human-readable authentication method names
    if (claimName === 'amr' && Array.isArray(value)) {
      return value.map(m => this.AMR_VALUES[m] ? `${m} (${this.AMR_VALUES[m]})` : m).join(', ');
    }

    // Decode platform number to OS name
    if (claimName === 'platf') {
      const name = this.PLATFORM_VALUES[String(value)];
      return name ? `${value} — ${name}` : String(value);
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
    const now = Date.now();

    // Token already expired
    if (payload.exp && payload.exp * 1000 < now) {
      warnings.push({
        type: 'expiry',
        message: 'Token has expired',
        severity: 'error'
      });
    }

    // Token expiring soon (< 5 minutes)
    if (payload.exp) {
      const msRemaining = payload.exp * 1000 - now;
      if (msRemaining > 0 && msRemaining < 5 * 60 * 1000) {
        const secsRemaining = Math.floor(msRemaining / 1000);
        warnings.push({
          type: 'expiry_soon',
          message: `Token expires in ${secsRemaining} seconds`,
          severity: 'warning'
        });
      }
    }

    // Long-lived token (> 1 hour lifetime)
    if (payload.iat && payload.exp) {
      const lifetimeSecs = payload.exp - payload.iat;
      if (lifetimeSecs > 3600) {
        warnings.push({
          type: 'long_lifetime',
          message: `Token lifetime is ${Math.round(lifetimeSecs / 60)} minutes — access tokens should ideally be ≤60 minutes`,
          severity: 'info'
        });
      }
    }

    // Guest account
    if (payload.acct === 1 || payload.acct === '1') {
      warnings.push({
        type: 'guest_account',
        message: 'Guest account — this user is a B2B guest in this tenant',
        severity: 'info'
      });
    }

    // Public client (no client authentication)
    if (payload.azpacr === 0 || payload.azpacr === '0') {
      warnings.push({
        type: 'public_client',
        message: 'Public client authentication (azpacr=0) — no client secret or certificate was used',
        severity: 'warning'
      });
    }

    // CAE not enabled — informational hint for Entra tokens
    const isEntra = this.isEntraToken(payload);
    if (isEntra && !this.detectCAE(payload)) {
      warnings.push({
        type: 'cae_not_enabled',
        message: 'CAE (Continuous Access Evaluation) not detected — add client capabilities claim (cp1) to enable revocation events',
        severity: 'info'
      });
    }

    return warnings;
  }

  /**
   * Decode AMR (Authentication Method Reference) values to human-readable descriptions.
   * @param {string|string[]} amrArray - AMR claim value from JWT
   * @returns {{ method: string, description: string }[]}
   */
  static decodeAmrValues(amrArray) {
    if (!amrArray) return [];
    const arr = Array.isArray(amrArray) ? amrArray : [amrArray];
    return arr.map(method => ({
      method,
      description: this.AMR_VALUES[method] || `Unknown method (${method})`
    }));
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