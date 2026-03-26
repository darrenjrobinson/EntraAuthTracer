/**
 * Entra Auth Tracer - OAuth 2.1 Decoder
 *
 * Provides grant-type intelligence, PKCE analysis, Device Code correlation,
 * Client Credentials inspection, and security warnings for OAuth 2.x flows
 * captured from Microsoft Entra (Azure AD) endpoints.
 */

class OAuthDecoder {
  // Grant type registry
  static GRANT_TYPES = {
    'authorization_code': {
      label: 'Authorization Code',
      description: 'Standard code flow — exchange code for tokens at the token endpoint',
      oauth21: true,
      requiresPKCE: true
    },
    'authorization_code_pkce': {
      label: 'Authorization Code + PKCE',
      description: 'Authorization Code flow with Proof Key for Code Exchange (RFC 7636)',
      oauth21: true,
      requiresPKCE: false // PKCE is the mechanism, not a further requirement
    },
    'client_credentials': {
      label: 'Client Credentials (M2M)',
      description: 'Machine-to-machine grant — no user context, app authenticates as itself',
      oauth21: true,
      requiresPKCE: false
    },
    'urn:ietf:params:oauth:grant-type:device_code': {
      label: 'Device Code',
      description: 'Limited-input device flow for browserless or input-constrained devices (RFC 8628)',
      oauth21: true,
      requiresPKCE: false
    },
    'refresh_token': {
      label: 'Refresh Token',
      description: 'Silently renew an access token using a previously issued refresh token',
      oauth21: true,
      requiresPKCE: false
    },
    'implicit': {
      label: 'Implicit Flow ⚠ Deprecated',
      description: 'Deprecated in OAuth 2.1 — tokens returned directly from the authorize endpoint',
      oauth21: false,
      requiresPKCE: false
    },
    'password': {
      label: 'Resource Owner Password ⚠ Deprecated',
      description: 'Deprecated in OAuth 2.1 — client collects username/password directly',
      oauth21: false,
      requiresPKCE: false
    }
  };

  // Human-readable labels for well-known Microsoft scopes
  static SCOPE_LABELS = {
    'openid': 'OpenID Connect — identity token',
    'profile': 'User profile information',
    'email': 'Email address',
    'offline_access': 'Offline access (refresh token)',
    'https://graph.microsoft.com/.default': 'Microsoft Graph — all app permissions',
    'https://graph.microsoft.com/User.Read': 'Microsoft Graph: Read user profile',
    'https://graph.microsoft.com/User.ReadWrite': 'Microsoft Graph: Read & write user profile',
    'https://graph.microsoft.com/Mail.Read': 'Microsoft Graph: Read mail',
    'https://graph.microsoft.com/Mail.Send': 'Microsoft Graph: Send mail',
    'https://graph.microsoft.com/Calendars.ReadWrite': 'Microsoft Graph: Read/write calendars',
    'https://graph.microsoft.com/Files.ReadWrite.All': 'Microsoft Graph: Read/write all files',
    'https://graph.microsoft.com/Directory.Read.All': 'Microsoft Graph: Read directory data',
    'https://graph.microsoft.com/GroupMember.Read.All': 'Microsoft Graph: Read group memberships',
    'https://management.azure.com/.default': 'Azure Management API — all permissions',
    'https://management.azure.com/user_impersonation': 'Azure Management: User impersonation',
    'https://vault.azure.net/.default': 'Azure Key Vault — all permissions',
    'https://storage.azure.com/.default': 'Azure Blob Storage — all permissions'
  };

  // ─── Main entry point ──────────────────────────────────────────────────────

  /**
   * Analyse a captured request and return OAuth intelligence.
   * Returns null if this is not an OAuth request.
   */
  static analyzeRequest(requestData) {
    try {
      const url = new URL(requestData.url);
      const path = url.pathname.toLowerCase();

      if (this.isAuthorizationEndpoint(path)) {
        return this.analyzeAuthorizationRequest(url.searchParams, requestData.requestBody);
      }
      if (this.isTokenEndpoint(path)) {
        return this.analyzeTokenRequest(requestData.requestBody, url.searchParams);
      }
      if (this.isDeviceCodeEndpoint(path)) {
        return this.analyzeDeviceCodeInitiation(requestData.requestBody);
      }

      return null;
    } catch (error) {
      return { error: `OAuth analysis failed: ${error.message}` };
    }
  }

  // ─── Endpoint detection ────────────────────────────────────────────────────

  static isAuthorizationEndpoint(path) {
    return /\/oauth2?(\/v2\.0)?\/authorize/.test(path) || path.endsWith('/authorize');
  }

  static isTokenEndpoint(path) {
    return (/\/oauth2?(\/v2\.0)?\/token/.test(path) || path.endsWith('/token')) &&
      !path.includes('/tokeninfo');
  }

  static isDeviceCodeEndpoint(path) {
    return /\/oauth2?(\/v[0-9]+(?:\.[0-9]+)?)?\/devicecode/.test(path) ||
      path.endsWith('/devicecode') ||
      /\/connect\/deviceauthorization/i.test(path); // IdentityServer/Duende RFC 8628
  }

  // ─── Authorization endpoint analysis ──────────────────────────────────────

  /**
   * Analyse GET /authorize request parameters.
   */
  static analyzeAuthorizationRequest(searchParams, _requestBody) {
    const responseType   = searchParams.get('response_type') || '';
    const codeChallenge  = searchParams.get('code_challenge');
    const challMethod    = searchParams.get('code_challenge_method');
    const scope          = searchParams.get('scope') || '';
    const clientId       = searchParams.get('client_id');
    const state          = searchParams.get('state');
    const nonce          = searchParams.get('nonce');
    const prompt         = searchParams.get('prompt');
    const loginHint      = searchParams.get('login_hint');
    const domainHint     = searchParams.get('domain_hint');
    const responseMode   = searchParams.get('response_mode');
    const idTokenHint    = searchParams.get('id_token_hint');

    const isPKCE     = !!codeChallenge;
    const isImplicit = responseType.includes('token') && !responseType.includes('code');

    let grantType, label;
    if (isImplicit) {
      grantType = 'implicit';
      label = 'Implicit Flow (Deprecated)';
    } else if (isPKCE) {
      grantType = 'authorization_code_pkce';
      label = 'Authorization Code + PKCE';
    } else {
      grantType = 'authorization_code';
      label = 'Authorization Code';
    }

    const scopes = scope ? scope.split(' ').filter(Boolean) : [];

    return {
      requestType: 'authorization_request',
      grantType,
      label,
      responseType,
      clientId,
      state,
      nonce,
      prompt,
      loginHint,
      domainHint,
      responseMode,
      idTokenHint: idTokenHint ? this.analyzeClientAssertion(idTokenHint, 'id_token_hint') : null,
      scopes,
      scopeLabels: this.labelScopes(scopes),
      pkce: isPKCE ? this.analyzePKCEChallenge(codeChallenge, challMethod) : null,
      warnings: this.generateAuthorizationWarnings(searchParams, responseType, isPKCE)
    };
  }

  // ─── Token endpoint analysis ───────────────────────────────────────────────

  /**
   * Analyse POST /token request body.
   */
  static analyzeTokenRequest(requestBody, searchParams) {
    if (!requestBody) {
      const grantType = searchParams ? searchParams.get('grant_type') : null;
      return {
        requestType: 'token_request',
        grantType: grantType || 'unknown',
        label: 'Token Request (no body)',
        warnings: [{ severity: 'warning', message: 'Token request has no body — grant_type cannot be determined' }]
      };
    }

    const data = this.flattenBody(requestBody);
    if (!data) {
      return {
        requestType: 'token_request',
        grantType: 'unknown',
        label: 'Token Request (unreadable body)',
        warnings: []
      };
    }

    switch (data.grant_type) {
      case 'authorization_code':
        return this.analyzeAuthCodeExchange(data);
      case 'client_credentials':
        return this.analyzeClientCredentials(data);
      case 'urn:ietf:params:oauth:grant-type:device_code':
        return this.analyzeDeviceCodePoll(data);
      case 'refresh_token':
        return this.analyzeRefreshToken(data);
      default:
        return {
          requestType: 'token_request',
          grantType: data.grant_type || 'unknown',
          label: data.grant_type ? `Token Request (${data.grant_type})` : 'Token Request (unknown grant)',
          warnings: data.grant_type
            ? []
            : [{ severity: 'warning', message: 'Missing grant_type in token request body' }]
        };
    }
  }

  // ─── Grant-specific analysers ──────────────────────────────────────────────

  static analyzeAuthCodeExchange(data) {
    const hasPKCE = !!data.code_verifier;
    const scopes = data.scope ? data.scope.split(' ').filter(Boolean) : [];
    return {
      requestType: 'token_request',
      grantType: hasPKCE ? 'authorization_code_pkce' : 'authorization_code',
      label: hasPKCE
        ? 'Authorization Code + PKCE (Token Exchange)'
        : 'Authorization Code (Token Exchange)',
      clientId: data.client_id,
      redirectUri: data.redirect_uri,
      codePresent: !!data.code,
      pkceVerifier: hasPKCE ? this.analyzePKCEVerifier(data.code_verifier) : null,
      clientAssertion: data.client_assertion
        ? this.analyzeClientAssertion(data.client_assertion, data.client_assertion_type)
        : null,
      scopes,
      scopeLabels: this.labelScopes(scopes),
      warnings: this.generateTokenExchangeWarnings(data, hasPKCE)
    };
  }

  static analyzeClientCredentials(data, headerAuth = null) {
    let authMethod, authMethodLabel;
    // Header-based auth takes precedence (client_secret_basic / digest)
    if (headerAuth) {
      authMethod = headerAuth.scheme;
      authMethodLabel = headerAuth.schemeLabel;
    } else if (data.client_assertion) {
      const assertType = data.client_assertion_type || '';
      authMethod = 'client_assertion';
      authMethodLabel = assertType.includes('jwt-bearer')
        ? 'Certificate / Federated Credential (JWT Bearer)'
        : 'Client Assertion (JWT)';
    } else if (data.client_secret) {
      authMethod = 'client_secret_post';
      authMethodLabel = 'Client Secret POST (password credential in body)';
    } else {
      authMethod = 'public';
      authMethodLabel = 'No explicit credential (public client or mTLS)';
    }

    // Prefer client_id from body; fall back to header-derived value (client_secret_basic)
    const clientId = data.client_id || (headerAuth ? headerAuth.clientId : null);

    const scopes = data.scope ? data.scope.split(' ').filter(Boolean) : [];
    return {
      requestType: 'token_request',
      grantType: 'client_credentials',
      label: 'Client Credentials (M2M)',
      clientId,
      authMethod,
      authMethodLabel,
      scopes,
      scopeLabels: this.labelScopes(scopes),
      clientAssertion: data.client_assertion
        ? this.analyzeClientAssertion(data.client_assertion, data.client_assertion_type)
        : null,
      warnings: this.generateClientCredentialsWarnings(data, authMethod)
    };
  }

  static analyzeDeviceCodePoll(data) {
    return {
      requestType: 'device_code_poll',
      grantType: 'device_code',
      label: 'Device Code Flow (Polling)',
      clientId: data.client_id,
      deviceCode: data.device_code || null,
      deviceCodePrefix: data.device_code
        ? data.device_code.substring(0, 16) + '…'
        : null,
      warnings: []
    };
  }

  static analyzeDeviceCodeInitiation(requestBody) {
    const data = requestBody ? this.flattenBody(requestBody) : {};
    const scopes = (data && data.scope) ? data.scope.split(' ').filter(Boolean) : [];
    return {
      requestType: 'device_code_initiation',
      grantType: 'device_code',
      label: 'Device Code Flow (Initiation)',
      clientId: data ? data.client_id : null,
      scopes,
      scopeLabels: this.labelScopes(scopes),
      warnings: []
    };
  }

  static analyzeRefreshToken(data) {
    const scopes = data.scope ? data.scope.split(' ').filter(Boolean) : [];
    return {
      requestType: 'token_request',
      grantType: 'refresh_token',
      label: 'Refresh Token',
      clientId: data.client_id,
      scopes,
      scopeLabels: this.labelScopes(scopes),
      warnings: []
    };
  }

  // ─── PKCE analysis ─────────────────────────────────────────────────────────

  /**
   * Analyse a code_challenge and its method.
   */
  static analyzePKCEChallenge(challenge, method) {
    const effectiveMethod = method || 'plain';
    const isS256 = effectiveMethod === 'S256';
    return {
      codeChallenge: challenge,
      codeChallengeMethod: effectiveMethod,
      isS256,
      challengeLength: challenge ? challenge.length : 0,
      status: isS256 ? 'compliant' : 'warning',
      recommendation: isS256
        ? 'S256 — compliant with OAuth 2.1'
        : `code_challenge_method=${effectiveMethod} — use S256 (SHA-256) as required by OAuth 2.1`
    };
  }

  /**
   * Analyse a code_verifier value for RFC 7636 compliance.
   */
  static analyzePKCEVerifier(verifier) {
    if (!verifier) return { error: 'No code_verifier present' };
    const len = verifier.length;
    const isCompliant = len >= 43 && len <= 128;
    const isHighEntropy = len >= 64;
    return {
      length: len,
      isCompliant,
      isHighEntropy,
      status: isCompliant ? 'compliant' : 'error',
      recommendation: !isCompliant
        ? `Verifier length ${len} is outside RFC 7636 range (43–128 chars)`
        : isHighEntropy
          ? 'High-entropy verifier — excellent security'
          : 'Compliant verifier — consider 64+ characters for higher entropy'
    };
  }

  // ─── Client assertion (JWT) analysis ──────────────────────────────────────

  /**
   * Attempt to decode a client_assertion JWT and extract key fields.
   * Only reads header + payload; never verifies the signature.
   */
  static analyzeClientAssertion(token, assertionType) {
    try {
      const parts = (token || '').split('.');
      if (parts.length !== 3) return { error: 'Not a valid JWT format' };

      const decodeB64Url = (str) => {
        let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
        b64 += '='.repeat((4 - (b64.length % 4)) % 4);
        return atob(b64);
      };

      let header = null;
      try { header = JSON.parse(decodeB64Url(parts[0])); } catch { /* ignore */ }

      let payload = null;
      try { payload = JSON.parse(decodeB64Url(parts[1])); } catch { /* ignore */ }

      return {
        isJWT: true,
        assertionType: assertionType || 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        algorithm: header ? header.alg : null,
        keyId: header ? header.kid : null,
        thumbprint: header ? (header['x5t#S256'] || header.x5t || null) : null,
        issuer: payload ? payload.iss : null,
        subject: payload ? payload.sub : null,
        audience: payload ? payload.aud : null,
        expiry: payload && payload.exp ? new Date(payload.exp * 1000).toISOString() : null,
        isExpired: payload && payload.exp ? payload.exp * 1000 < Date.now() : null,
        jwtId: payload ? payload.jti : null
      };
    } catch (error) {
      return { error: `Could not decode assertion JWT: ${error.message}` };
    }
  }

  // ─── Warning generators ────────────────────────────────────────────────────

  static generateAuthorizationWarnings(params, responseType, isPKCE) {
    const warnings = [];

    if (!isPKCE && responseType.includes('code')) {
      warnings.push({
        severity: 'warning',
        message: 'Authorization Code request without PKCE — code_challenge is required for public clients in OAuth 2.1'
      });
    }
    if (!params.get('state')) {
      warnings.push({
        severity: 'warning',
        message: 'No state parameter — CSRF protection may be absent'
      });
    }
    if (responseType.includes('token') && !responseType.includes('code')) {
      warnings.push({
        severity: 'error',
        message: 'Implicit flow (response_type includes token) is removed in OAuth 2.1 — migrate to Authorization Code + PKCE'
      });
    }
    if (params.get('code_challenge_method') && params.get('code_challenge_method') !== 'S256') {
      warnings.push({
        severity: 'warning',
        message: `code_challenge_method=${params.get('code_challenge_method')} — S256 is the required method in OAuth 2.1`
      });
    }
    return warnings;
  }

  static generateTokenExchangeWarnings(data, hasPKCE) {
    const warnings = [];
    if (!hasPKCE) {
      warnings.push({
        severity: 'info',
        message: 'Token exchange without code_verifier — PKCE is required for public clients in OAuth 2.1'
      });
    }
    return warnings;
  }

  static generateClientCredentialsWarnings(data, authMethod) {
    const warnings = [];
    if (authMethod === 'client_secret_post') {
      warnings.push({
        severity: 'info',
        message: 'Using client_secret in POST body (client_secret_post) — consider client_secret_basic or certificate-based authentication'
      });
    } else if (authMethod === 'client_secret_basic') {
      warnings.push({
        severity: 'info',
        message: 'Using HTTP Basic authentication (client_secret_basic) — consider certificate-based or federated credential authentication for improved security'
      });
    } else if (authMethod === 'digest_auth') {
      warnings.push({
        severity: 'info',
        message: 'Using HTTP Digest authentication with OAuth — non-standard; most modern IdPs use client_secret_basic or client_assertion'
      });
    } else if (data.client_secret) {
      warnings.push({
        severity: 'info',
        message: 'Using client_secret — consider certificate-based or federated credential authentication for improved security'
      });
    }
    return warnings;
  }

  // ─── Scope labelling ───────────────────────────────────────────────────────

  static labelScopes(scopes) {
    return scopes.map(scope => {
      if (this.SCOPE_LABELS[scope]) return { scope, label: this.SCOPE_LABELS[scope] };
      // Prefix match (e.g. custom API URIs)
      for (const [prefix, label] of Object.entries(this.SCOPE_LABELS)) {
        if (scope.startsWith(prefix)) return { scope, label };
      }
      return { scope, label: null };
    });
  }

  // ─── Helpers ───────────────────────────────────────────────────────────────

  /**
   * Flatten a requestBody object (Chrome webRequest formData values are arrays).
   * Also handles JSON bodies from FIDO2/fetch-style requests.
   */
  static flattenBody(requestBody) {
    if (!requestBody) return null;
    if (requestBody.type === 'formData' && requestBody.data) {
      const flat = {};
      for (const [key, values] of Object.entries(requestBody.data)) {
        flat[key] = Array.isArray(values) ? values[0] : values;
      }
      return flat;
    }
    if (requestBody.type === 'json' && requestBody.data) {
      return requestBody.data;
    }
    return null;
  }

  /**
   * Derive a specific flow type string from body grant_type.
   * Used by SAMLTrace.detectFlowType to refine the initial URL-based guess.
   */
  static detectFlowTypeFromBody(requestBody) {
    const data = this.flattenBody(requestBody);
    if (!data || !data.grant_type) return null;

    switch (data.grant_type) {
      case 'authorization_code':
        return data.code_verifier ? 'pkce_token_exchange' : 'authcode_token_exchange';
      case 'client_credentials':
        return 'client_credentials';
      case 'urn:ietf:params:oauth:grant-type:device_code':
        return 'device_code_poll';
      case 'refresh_token':
        return 'refresh_token';
      default:
        return null;
    }
  }

  // ─── Authorization header parsing ─────────────────────────────────────────

  /**
   * Parse an HTTP Authorization header value and return a structured descriptor.
   * Handles Basic (RFC 7617), Digest (RFC 7616), and Bearer schemes.
   * Returns null if the header is absent or unrecognised.
   *
   * @param {string|undefined} headerValue  Raw Authorization header value
   * @returns {{ scheme, schemeLabel, clientId, clientSecret, digestParams } | null}
   */
  static parseAuthorizationHeader(headerValue) {
    if (!headerValue) return null;

    // Basic: base64(client_id:client_secret)
    const basicMatch = headerValue.match(/^Basic\s+([A-Za-z0-9+/=]+)$/i);
    if (basicMatch) {
      try {
        const decoded = atob(basicMatch[1]);
        const colon = decoded.indexOf(':');
        if (colon !== -1) {
          return {
            scheme: 'client_secret_basic',
            schemeLabel: 'HTTP Basic (client_secret_basic — RFC 6749 §2.3.1)',
            clientId: decoded.substring(0, colon),
            clientSecret: decoded.substring(colon + 1)
          };
        }
      } catch { /* malformed base64 */ }
    }

    // Digest: Authorization: Digest realm="...", username="...", ...
    const digestMatch = headerValue.match(/^Digest\s+(.+)$/i);
    if (digestMatch) {
      const params = {};
      const paramRe = /(\w+)=(?:"([^"]*)"|([^,\s]*))/g;
      let m;
      while ((m = paramRe.exec(digestMatch[1])) !== null) {
        params[m[1]] = m[2] !== undefined ? m[2] : m[3];
      }
      return {
        scheme: 'digest_auth',
        schemeLabel: 'HTTP Digest Authentication (RFC 7616)',
        clientId: params.username || null,
        digestParams: {
          realm: params.realm || null,
          uri: params.uri || null,
          algorithm: params.algorithm || 'MD5',
          qop: params.qop || null
        }
      };
    }

    // Bearer — token already in hand (not a credential exchange)
    if (/^Bearer\s+/i.test(headerValue)) {
      return {
        scheme: 'bearer',
        schemeLabel: 'Bearer Token (already authenticated)',
        clientId: null
      };
    }

    return null;
  }

  /**
   * Enrich an existing oauthAnalysis with information extracted from request
   * headers — called from SAMLTrace.handleBeforeSendHeaders once headers land.
   *
   * Patches authMethod/authMethodLabel/clientId in-place when the Authorization
   * header reveals credentials that weren't visible in the POST body
   * (e.g. client_secret_basic, HTTP Digest).
   *
   * @param {object|null} analysis   Existing oauthAnalysis (mutated in-place)
   * @param {Array}       headers    Chrome webRequest requestHeaders array
   */
  static enrichWithHeaders(analysis, headers) {
    if (!analysis || !headers || !headers.length) return;

    // Find Authorization header (case-insensitive name)
    const authHeader = headers.find(h => h.name.toLowerCase() === 'authorization');
    if (!authHeader) return;

    const parsed = this.parseAuthorizationHeader(authHeader.value);
    if (!parsed) return;

    // Don't overwrite a known client_assertion or client_secret_post with a bearer token
    if (parsed.scheme === 'bearer') return;

    // Only enrich token requests — not authorization endpoint GETs
    if (analysis.requestType !== 'token_request' && analysis.requestType !== 'device_code_initiation') return;

    analysis.authMethod = parsed.scheme;
    analysis.authMethodLabel = parsed.schemeLabel;

    // Prefer body-derived client_id; fill in from header if absent
    if (!analysis.clientId && parsed.clientId) {
      analysis.clientId = parsed.clientId;
    }

    if (parsed.scheme === 'digest_auth') {
      analysis.digestAuth = parsed.digestParams;
    }

    // Replace or add the auth-method warning
    if (analysis.warnings) {
      // Remove any existing client_secret / auth-method warning
      analysis.warnings = analysis.warnings.filter(
        w => !w.message.includes('client_secret') && !w.message.includes('authentication')
      );
      if (parsed.scheme === 'client_secret_basic') {
        analysis.warnings.push({
          severity: 'info',
          message: 'Using HTTP Basic authentication (client_secret_basic) — consider certificate-based or federated credential authentication'
        });
      } else if (parsed.scheme === 'digest_auth') {
        analysis.warnings.push({
          severity: 'info',
          message: `HTTP Digest authentication detected (realm: ${parsed.digestParams.realm || 'unknown'}, algorithm: ${parsed.digestParams.algorithm}) — non-standard with OAuth; used by SAP Integration Suite, Dell Boomi, and some enterprise gateway products`
        });
      }
    }
  }
}

export default OAuthDecoder;
