/**
 * Entra Auth Tracer - Core Request Interception
 * Extended from SimpleSAMLphp SAML-tracer
 * 
 * This module handles:
 * - HTTP request/response interception
 * - SAML/WS-Fed detection and decoding (preserved from upstream)
 * - FIDO2/Passkey flow analysis (NEW)
 * - OAuth 2.1 grant type intelligence (NEW)
 * - Device Code sequence correlation (NEW)
 */

import Fido2Decoder from './Fido2Decoder.js';
import OAuthDecoder from './OAuthDecoder.js';
import VerifiedIdDecoder from './VerifiedIdDecoder.js';

class SAMLTrace {
  constructor() {
    this.state = null;
    this.isListening = false;
  }

  /**
   * Initialize the SAML tracer with extension state
   */
  initialize(extensionState) {
    this.state = extensionState;
    this.startListening();
  }

  /**
   * Start listening for web requests
   */
  startListening() {
    if (this.isListening) return;

    // Register request interceptors
    chrome.webRequest.onBeforeRequest.addListener(
      this.handleBeforeRequest.bind(this),
      { urls: ['<all_urls>'] },
      ['requestBody'] // requestBody is read-only in MV3 (blocking removed)
    );

    chrome.webRequest.onBeforeSendHeaders.addListener(
      this.handleBeforeSendHeaders.bind(this),
      { urls: ['<all_urls>'] },
      ['requestHeaders']
    );

    chrome.webRequest.onHeadersReceived.addListener(
      this.handleHeadersReceived.bind(this),
      { urls: ['<all_urls>'] },
      ['responseHeaders']
    );

    chrome.webRequest.onCompleted.addListener(
      this.handleCompleted.bind(this),
      { urls: ['<all_urls>'] },
      ['responseHeaders']
    );

    chrome.webRequest.onErrorOccurred.addListener(
      this.handleError.bind(this),
      { urls: ['<all_urls>'] }
    );

    this.isListening = true;
    console.log('SAMLTrace: Started listening for requests');
  }

  /**
   * Stop listening for web requests
   */
  stopListening() {
    if (!this.isListening) return;

    chrome.webRequest.onBeforeRequest.removeListener(this.handleBeforeRequest);
    chrome.webRequest.onBeforeSendHeaders.removeListener(this.handleBeforeSendHeaders);
    chrome.webRequest.onHeadersReceived.removeListener(this.handleHeadersReceived);
    chrome.webRequest.onCompleted.removeListener(this.handleCompleted);
    chrome.webRequest.onErrorOccurred.removeListener(this.handleError);

    this.isListening = false;
    console.log('SAMLTrace: Stopped listening for requests');
  }

  /**
   * Handle request before it's sent
   */
  handleBeforeRequest(details) {
    try {
      // Check if this is a relevant request
      const requestData = this.analyzeRequest(details);
      if (!requestData) return {};

      // Store request data
      this.state.requests.push(requestData);

      // Notify badge counter
      if (typeof this.state.onNewAuthRequest === 'function') {
        this.state.onNewAuthRequest();
      }

      // Handle specific flow types
      this.handleFlowSpecifics(requestData, details);

      return {};
    } catch (error) {
      console.error('SAMLTrace: Error in handleBeforeRequest:', error);
      return {};
    }
  }

  /**
   * Analyze request to determine if it's relevant for tracing
   */
  analyzeRequest(details) {
    const url = new URL(details.url);
    
    // Check for authentication-related endpoints
    const isAuthRequest = this.isAuthenticationRequest(url, details);
    if (!isAuthRequest) return null;

    const requestData = {
      id: this.generateRequestId(),
      timestamp: Date.now(),
      url: details.url,
      method: details.method,
      tabId: details.tabId,
      type: details.type,
      requestHeaders: [],
      responseHeaders: [],
      requestBody: null,
      responseBody: null,
      flowType: this.detectFlowType(url, details),
      status: 'pending',
      error: null
    };

    // Extract request body for POST requests (needed for FIDO2 and OAuth)
    if (details.requestBody && details.method === 'POST') {
      requestData.requestBody = this.extractRequestBody(details.requestBody);
    }

    return requestData;
  }

  /**
   * Check if this is an authentication-related request
   */
  isAuthenticationRequest(url, details) {
    // SAML/WS-Fed patterns
    const samlPatterns = [
      /\/saml2?/i,              // /saml/, /saml2/ (any IdP)
      /\/sso/i,                 // /sso — generic SSO endpoint
      /\/ws-federation/i,       // WS-Federation full path
      /\/wsfed(?:[/?#]|$)/i,   // WS-Federation short path used by some implementations
      /samlrequest/i,           // SAML redirect binding query param
      /samlresponse/i,          // SAML POST binding query param
      /samlart/i,               // SAML Artifact binding query param
      /wresult/i,               // WS-Fed result token
      /Shibboleth\.sso/i,       // Shibboleth SP: /Shibboleth.sso/SAML2/POST, /Shibboleth.sso/Logout
      /\/adfs\/ls/i,            // ADFS on-prem login service (form-based auth, SAML redirect target)
      /\/ECP\//i,               // SAML Enhanced Client Profile (Shibboleth IdP — thick clients)
    ];

    // OAuth/OIDC patterns — generic path-based detection
    const oauthPatterns = [
      /\/oauth2?/i,              // /oauth/, /oauth2/ (covers most IdPs)
      /\/token/i,               // token endpoint including /connect/token
      /\/authorize/i,           // authorization endpoint
      /\/devicecode/i,          // device code endpoint
      /\/connect\//i,           // IdentityServer/Duende: /connect/token, /connect/authorize, /connect/userinfo, /connect/endsession, /connect/introspect, /connect/revocation
      /\.well-known\/(openid-configuration|jwks|oauth-authorization-server)/i, // OIDC discovery & JWKS
      /\/userinfo/i,            // OIDC userinfo endpoint
      /\/introspect/i,          // RFC 7662 token introspection
      /\/revoc/i,               // token revocation (/revoke or /revocation)
      /\/endsession/i,          // RP-initiated logout (OpenID Connect)
      /\/api\/v1\/authn/i,      // Okta Classic primary authentication
      /\/idp\/idx\//i,          // Okta Identity Engine (OIE)
    ];

    // FIDO2/Passkey patterns
    // Note: /passkeys?/ requires the word to be a complete path segment to avoid false
    // positives from repo/resource names that happen to start with "Passkey" (e.g. GitHub
    // repository names like /PasskeyProviderAAGUIDs/ would otherwise match).
    const fido2Patterns = [
      /\/assertion/i,
      /\/attestation/i,
      /\/passkeys?(?:[/?#]|$)/i,
      /\/webauthn/i,
      /\/fido2?(?:[/?#]|$)/i,  // explicit /fido2/ or /fido/ path (Azure AD B2C, enterprise FIDO2 servers)
    ];

    // DID / Verified ID patterns — decentralised identity flows
    const didPatterns = [
      /\/verifiableCredentials\//i,     // Entra Verified ID service API
      /\/openid4vp\//i,                 // OpenID for Verifiable Presentations
      /\/openid4vci\//i,                // OpenID for Verifiable Credential Issuance
      /\/statuslist\//i,                // Credential status / revocation list
      /\/identifiers\/did:/i,           // DID resolution requests
    ];

    // Known IdP hostnames — all requests to these are captured unconditionally
    const knownIdpHosts = [
      // Microsoft / Entra
      'login.microsoftonline.com',
      'sts.windows.net',
      'login.live.com',
      // Google / GCP
      'accounts.google.com',
      'oauth2.googleapis.com',
      'securetoken.googleapis.com',  // Firebase Auth
      'openidconnect.googleapis.com',
      // Entra Verified ID / Decentralised Identity
      'verifiedid.did.msidentity.com', // Entra Verified ID v1 service
      'beta.did.msidentity.com',       // Entra Verified ID beta endpoint
      'did.msidentity.com',            // Microsoft DID document host
      'request.msidentity.com',        // Verified ID request service
      'resolver.msidentity.com',       // Microsoft DID resolver
      'resolver.identity.foundation',  // DIF universal resolver
    ];

    // Known IdP domain suffixes — wildcard tenant subdomains
    const knownIdpSuffixes = [
      '.okta.com',          // Okta production tenants
      '.oktapreview.com',   // Okta preview/sandbox tenants
      '.amazoncognito.com', // AWS Cognito user pool domains
    ];

    if (knownIdpHosts.includes(url.hostname)) return true;
    if (knownIdpSuffixes.some(suffix => url.hostname.endsWith(suffix))) return true;

    // Check URL patterns
    const allPatterns = [...samlPatterns, ...oauthPatterns, ...fido2Patterns, ...didPatterns];
    if (allPatterns.some(pattern => pattern.test(url.pathname) || pattern.test(url.search))) {
      return true;
    }

    // Check POST body for SAML tokens — IdP POSTs SAMLResponse to any SP ACS URL
    if (details.requestBody && details.requestBody.formData) {
      const fd = details.requestBody.formData;
      if (fd.SAMLRequest || fd.SAMLResponse || fd.wresult) return true;
    }

    return false;
  }

  /**
   * Detect the type of authentication flow
   */
  detectFlowType(url, details) {
    const path = url.pathname.toLowerCase();
    const search = url.search.toLowerCase();
    const hostname = url.hostname.toLowerCase();

    // ─── DID / Verified ID detection (checked before OAuth — these hosts are unambiguous) ───
    if (hostname === 'verifiedid.did.msidentity.com' || hostname === 'beta.did.msidentity.com') {
      if (path.includes('/createissuancerequest'))     return 'did_issuance_request';
      if (path.includes('/createpresentationrequest')) return 'did_presentation_request';
      if (/\/requests?\//.test(path))                 return 'did_request_fetch';
      if (path.includes('/callback'))                  return 'did_callback';
      return 'did_vc_service';
    }
    if (hostname === 'did.msidentity.com' ||
        hostname === 'resolver.msidentity.com' ||
        hostname === 'resolver.identity.foundation') {
      return 'did_resolution';
    }
    if (path.includes('/identifiers/did:'))  return 'did_resolution';
    if (path.includes('/statuslist/'))       return 'did_status';
    if (path.includes('/openid4vp/'))        return 'vc_presentation_openid4vp';
    if (path.includes('/openid4vci/'))       return 'vc_issuance_openid4vci';

    // SAML detection — check query params and POST body FIRST (before generic OAuth path checks)
    // because Entra SAML flows go through login.microsoftonline.com/.../{tenant}/saml2
    // but also through /common/oauth2/... with a SAMLRequest param
    if (search.includes('samlrequest') || search.includes('samlresponse') || search.includes('samlart')) return 'saml';
    if (search.includes('wresult') || search.includes('wctx')) return 'wsfed';
    // ECP must be checked before generic saml (path contains /SAML2/ AND /ECP/)
    if (path.includes('/ecp/')) return 'saml_ecp';
    if (path.includes('saml') || path.includes('shibboleth.sso')) return 'saml';
    if (path.includes('/adfs/ls')) return 'adfs_saml';
    if (path.includes('wsfed') && !path.includes('ws-federation')) return 'wsfed';
    if (details.requestBody && details.requestBody.formData) {
      const fd = details.requestBody.formData;
      if (fd.SAMLRequest || fd.SAMLResponse) return 'saml';
      if (fd.wresult) return 'wsfed';
    }

    // FIDO2 detection
    if (path.includes('assertion')) return 'fido2_assertion';
    if (path.includes('attestation')) return 'fido2_attestation';
    if (path.includes('webauthn') && path.includes('well-known')) return 'fido2_preflight';
    // Generic WebAuthn/FIDO2 endpoints
    if (path.includes('webauthn')) return 'fido2_webauthn';
    if (/\/fido2?(?:[/?#]|$)/.test(path)) return 'fido2_webauthn';

    // OIDC discovery endpoints
    if (path.includes('.well-known')) return 'oidc_discovery';

    // Okta-specific flows
    if (path.includes('/api/v1/authn')) return 'okta_authn';
    if (path.includes('/idp/idx/')) return 'okta_idx';

    // OIDC auxiliary endpoints (userinfo, introspection, revocation, logout)
    if (path.includes('/userinfo')) return 'oidc_userinfo';
    if (path.includes('/introspect')) return 'oidc_introspect';
    if (path.includes('/revok') || path.includes('/revoc')) return 'oidc_revocation';
    if (path.includes('/endsession') || path.includes('/logout')) return 'oidc_logout';

    // Device code endpoint — always initiation (response is what contains device_code)
    if (OAuthDecoder.isDeviceCodeEndpoint(path)) return 'device_code_initiation';

    // For token endpoint, read the POST body grant_type for precise classification
    if (OAuthDecoder.isTokenEndpoint(path) && details.requestBody) {
      const bodyFlowType = OAuthDecoder.detectFlowTypeFromBody(
        this.peekRequestBody(details.requestBody)
      );
      if (bodyFlowType) return bodyFlowType;
    }

    // Authorization endpoint — check for PKCE challenge in URL
    if (OAuthDecoder.isAuthorizationEndpoint(path)) {
      return search.includes('code_challenge') ? 'pkce_flow' : 'oauth_authorize';
    }

    // Generic token endpoint fallback
    if (OAuthDecoder.isTokenEndpoint(path)) return 'oauth_token';

    return 'unknown';
  }

  /**
   * Peek into a raw requestBody to extract formData as a lightweight object.
   * Does NOT store the result — used only for flow type detection.
   */
  peekRequestBody(requestBody) {
    if (!requestBody) return null;
    if (requestBody.formData) {
      return { type: 'formData', data: requestBody.formData };
    }
    if (requestBody.raw) {
      try {
        const decoder = new TextDecoder('utf-8');
        const text = decoder.decode(requestBody.raw[0].bytes);
        return { type: 'json', data: JSON.parse(text) };
      } catch { /* ignore */ }
    }
    return null;
  }

  /**
   * Handle flow-specific processing
   */
  handleFlowSpecifics(requestData) {
    switch (requestData.flowType) {
      case 'fido2_assertion':
      case 'fido2_attestation':
        this.handleFido2Request(requestData);
        break;
      case 'device_code_initiation':
      case 'device_code_poll':
        this.handleDeviceCodeRequest(requestData);
        this.handleOAuthRequest(requestData);
        break;
      case 'pkce_flow':
      case 'pkce_token_exchange':
      case 'authcode_token_exchange':
      case 'client_credentials':
      case 'refresh_token':
      case 'oauth_authorize':
      case 'oauth_token':
        this.handleOAuthRequest(requestData);
        break;
      case 'did_issuance_request':
      case 'did_presentation_request':
      case 'did_request_fetch':
      case 'did_callback':
      case 'did_vc_service':
      case 'did_resolution':
      case 'did_status':
      case 'vc_presentation_openid4vp':
      case 'vc_issuance_openid4vci':
        this.handleVerifiedIdRequest(requestData);
        break;
    }
  }

  /**
   * Run VerifiedIdDecoder analysis and attach result to the request.
   */
  handleVerifiedIdRequest(requestData) {
    try {
      const analysis = VerifiedIdDecoder.analyzeRequest(requestData);
      if (analysis) {
        requestData.didAnalysis = analysis;
      }
    } catch (error) {
      console.error('Verified ID analysis error:', error);
      requestData.didAnalysis = { error: `Verified ID analysis failed: ${error.message}` };
    }
  }

  /**
   * Run OAuthDecoder analysis and attach result to the request.
   */
  handleOAuthRequest(requestData) {
    try {
      const analysis = OAuthDecoder.analyzeRequest(requestData);
      if (analysis) {
        requestData.oauthAnalysis = analysis;
      }
    } catch (error) {
      console.error('OAuth analysis error:', error);
      requestData.oauthAnalysis = { error: `OAuth analysis failed: ${error.message}` };
    }
  }

  /**
   * Handle FIDO2-specific requests with full decoding
   */
  handleFido2Request(requestData) {
    if (!requestData.requestBody || requestData.requestBody.type !== 'json') {
      return;
    }

    try {
      // Use FIDO2 decoder to process the request
      const fido2Data = Fido2Decoder.decodeFido2Request(requestData.requestBody);
      
      if (fido2Data && !fido2Data.error) {
        requestData.fido2Analysis = fido2Data;
        
        // Store in FIDO2 sessions with additional metadata
        const sessionData = {
          ...requestData,
          fido2Type: this.getFido2Type(requestData.flowType),
          timestamp: requestData.timestamp,
          decoded: fido2Data
        };
        
        this.state.fido2Sessions.push(sessionData);
        
        console.log('FIDO2 request processed:', {
          type: requestData.flowType,
          hasClientData: !!fido2Data.clientDataJSON,
          hasAuthenticatorData: !!fido2Data.authenticatorData
        });
      }
    } catch (error) {
      console.error('FIDO2 processing error:', error);
      requestData.fido2Analysis = {
        error: `FIDO2 processing failed: ${error.message}`
      };
    }
  }

  /**
   * Get FIDO2 type description
   */
  getFido2Type(flowType) {
    switch (flowType) {
      case 'fido2_assertion': return 'Authentication (Assertion)';
      case 'fido2_attestation': return 'Registration (Attestation)';
      case 'fido2_preflight': return 'Pre-flight Check';
      case 'fido2_webauthn': return 'WebAuthn Endpoint';
      default: return 'Unknown FIDO2 Flow';
    }
  }

  /**
   * Handle Device Code flow requests — correlate initiation and poll steps
   * by tracking the device_code token across poll requests.
   */
  handleDeviceCodeRequest(requestData) {
    if (requestData.flowType === 'device_code_initiation') {
      // Record initiation time for later correlation; device_code value is only in the
      // response body (which we cannot read in MV3), so we track by client_id + timestamp.
      const data = requestData.requestBody
        ? OAuthDecoder.flattenBody(requestData.requestBody)
        : null;
      const clientId = data ? data.client_id : 'unknown';
      const correlationKey = `init:${clientId}:${requestData.timestamp}`;
      requestData.deviceCodeCorrelationKey = correlationKey;
      this.state.deviceCodeCorrelation.set(correlationKey, [requestData.id]);
      return;
    }

    if (requestData.flowType === 'device_code_poll') {
      // Extract the device_code value from the POST body to use as a stable correlation key
      const data = requestData.requestBody
        ? OAuthDecoder.flattenBody(requestData.requestBody)
        : null;
      const deviceCode = data && data.device_code ? data.device_code : null;
      if (!deviceCode) return;

      const key = `poll:${deviceCode}`;
      requestData.deviceCodeCorrelationKey = key;

      if (this.state.deviceCodeCorrelation.has(key)) {
        this.state.deviceCodeCorrelation.get(key).push(requestData.id);
      } else {
        this.state.deviceCodeCorrelation.set(key, [requestData.id]);
      }
    }
  }

  /**
   * Extract request body from webRequest details
   */
  extractRequestBody(requestBody) {
    if (!requestBody) return null;

    try {
      // Handle form data
      if (requestBody.formData) {
        return {
          type: 'formData',
          data: requestBody.formData
        };
      }

      // Handle raw data (needed for FIDO2 JSON)
      if (requestBody.raw) {
        const decoder = new TextDecoder('utf-8');
        const bodyText = decoder.decode(requestBody.raw[0].bytes);
        
        // Try to parse as JSON
        try {
          const jsonData = JSON.parse(bodyText);
          return {
            type: 'json',
            data: jsonData,
            raw: bodyText
          };
        } catch {
          return {
            type: 'raw',
            data: bodyText
          };
        }
      }
    } catch (error) {
      console.error('SAMLTrace: Error extracting request body:', error);
    }

    return null;
  }

  /**
   * Handle request headers
   */
  handleBeforeSendHeaders(details) {
    // Find corresponding request and update headers
    const request = this.findRequest(details);
    if (request) {
      request.requestHeaders = details.requestHeaders || [];

      // Enrich OAuth analysis with Authorization header now that headers have arrived.
      // analyzeRequest runs in handleBeforeRequest before headers are available, so
      // client_secret_basic and HTTP Digest credentials are only visible here.
      if (request.oauthAnalysis) {
        OAuthDecoder.enrichWithHeaders(request.oauthAnalysis, request.requestHeaders);
      }
    }
    return {};
  }

  /**
   * Handle response headers
   */
  handleHeadersReceived(details) {
    const request = this.findRequest(details);
    if (request) {
      request.responseHeaders = details.responseHeaders || [];
      request.statusCode = details.statusCode;
    }
    return {};
  }

  /**
   * Handle completed requests
   */
  handleCompleted(details) {
    const request = this.findRequest(details);
    if (request) {
      request.status = 'completed';
      request.statusCode = details.statusCode;
    }
  }

  /**
   * Handle request errors
   */
  handleError(details) {
    const request = this.findRequest(details);
    if (request) {
      request.status = 'error';
      request.error = details.error;
    }
  }

  /**
   * Find a request by details
   */
  findRequest(details) {
    return this.state.requests.find(req => 
      req.url === details.url && 
      req.method === details.method &&
      Math.abs(req.timestamp - details.timeStamp) < 1000 // Within 1 second
    );
  }

  /**
   * Generate unique request ID
   */
  generateRequestId() {
    return 'req_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
  }

  /**
   * Get current state
   */
  getState() {
    return this.state;
  }
}

// Create singleton instance
const samltrace = new SAMLTrace();

export default samltrace;