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
import EntraClaimsDecoder from './EntraClaimsDecoder.js';

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

    // Extract request body for POST requests (needed for FIDO2)
    if (details.requestBody && details.method === 'POST') {
      requestData.requestBody = this.extractRequestBody(details.requestBody);
    }

    return requestData;
  }

  /**
   * Check if this is an authentication-related request
   */
  isAuthenticationRequest(url, details) {
    // SAML/WS-Fed patterns (from upstream)
    const samlPatterns = [
      /\/saml2?/i,
      /\/sso/i,
      /\/ws-federation/i,
      /samlrequest/i,
      /samlresponse/i,
      /wresult/i
    ];

    // OAuth/OIDC patterns
    const oauthPatterns = [
      /\/oauth2?/i,
      /\/token/i,
      /\/authorize/i,
      /\/devicecode/i
    ];

    // FIDO2/Passkey patterns (NEW)
    const fido2Patterns = [
      /\/assertion/i,
      /\/attestation/i,
      /\/passkey/i,
      /\/webauthn/i
    ];

    // Entra-specific endpoints
    const entraHosts = [
      'login.microsoftonline.com',
      'sts.windows.net',
      'login.live.com'
    ];

    // Check host patterns
    if (entraHosts.includes(url.hostname)) return true;

    // Check URL patterns
    const allPatterns = [...samlPatterns, ...oauthPatterns, ...fido2Patterns];
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

    // SAML detection — check query params and POST body FIRST (before generic OAuth path checks)
    // because Entra SAML flows go through login.microsoftonline.com/.../{tenant}/saml2
    // but also through /common/oauth2/... with a SAMLRequest param
    if (search.includes('samlrequest') || search.includes('samlresponse')) return 'saml';
    if (search.includes('wresult') || search.includes('wctx')) return 'wsfed';
    if (path.includes('saml')) return 'saml';
    if (details.requestBody && details.requestBody.formData) {
      const fd = details.requestBody.formData;
      if (fd.SAMLRequest || fd.SAMLResponse) return 'saml';
      if (fd.wresult) return 'wsfed';
    }

    // FIDO2 detection
    if (path.includes('assertion')) return 'fido2_assertion';
    if (path.includes('attestation')) return 'fido2_attestation';
    if (path.includes('webauthn') && path.includes('well-known')) return 'fido2_preflight';

    // OAuth detection
    if (path.includes('devicecode')) return 'device_code_initiation';
    if (path.includes('token') && search.includes('device_code')) return 'device_code_poll';
    if (search.includes('code_challenge')) return 'pkce_flow';
    if (search.includes('client_credentials')) return 'client_credentials';
    if (path.includes('authorize')) return 'oauth_authorize';
    if (path.includes('token')) return 'oauth_token';

    return 'unknown';
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
        break;
      // Additional flow handling will be added in subsequent phases
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
      default: return 'Unknown FIDO2 Flow';
    }
  }

  /**
   * Handle Device Code flow requests (stub - to be implemented in Phase 3)
   */
  handleDeviceCodeRequest(requestData) {
    // Device code correlation will be implemented in Phase 3
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