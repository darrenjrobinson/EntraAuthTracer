/**
 * Entra Auth Tracer - Verified ID / DID Decoder
 *
 * Provides analysis and human-readable decoding of:
 * - Microsoft Entra Verified ID service calls (issuance, presentation)
 * - DID document resolution requests
 * - OpenID4VP / OpenID4VCI flows
 * - Credential status list checks
 */

class VerifiedIdDecoder {
  // Human-readable labels for each Verified ID / DID flow type
  static OPERATION_LABELS = {
    'did_issuance_request':        'Create Issuance Request',
    'did_presentation_request':    'Create Presentation Request',
    'did_request_fetch':           'Fetch Request Object',
    'did_callback':                'Request Callback / Event',
    'did_vc_service':              'Verified ID Service',
    'did_resolution':              'DID Document Resolution',
    'did_status':                  'Credential Status Check',
    'vc_presentation_openid4vp':   'OpenID4VP Presentation',
    'vc_issuance_openid4vci':      'OpenID4VCI Credential Issuance',
  };

  // ─── Main entry point ──────────────────────────────────────────────────────

  /**
   * Analyse a captured request and return Verified ID / DID intelligence.
   * Returns null if this is not a DID / Verified ID request.
   */
  static analyzeRequest(requestData) {
    try {
      const url   = new URL(requestData.url);
      const path  = url.pathname;
      const flowType = requestData.flowType || '';

      if (!flowType.startsWith('did_') && !flowType.startsWith('vc_')) return null;

      const result = {
        operation: this.OPERATION_LABELS[flowType] || 'Decentralised Identity Request',
        flowType,
        host: url.hostname,
        path,
        warnings: [],
      };

      // Extract DID identifier embedded in the path or query string
      const didMatch = (path + url.search).match(/did:[a-zA-Z0-9]+:[^\s/?#"']+/);
      if (didMatch) result.did = didMatch[0];

      // Extract request / transaction ID from path segments like /requests/{id}
      const requestIdMatch = path.match(/\/requests?\/([a-zA-Z0-9_-]{4,})/i);
      if (requestIdMatch) result.requestId = requestIdMatch[1];

      // Enrich from request body when available
      if (requestData.requestBody) {
        const body = this.flattenBody(requestData.requestBody);
        if (body) this.enrichFromBody(result, body);
      }

      // Surface any noteworthy conditions
      this.addWarnings(result);

      return result;
    } catch (error) {
      return { error: `Verified ID analysis failed: ${error.message}` };
    }
  }

  // ─── Body parsing ──────────────────────────────────────────────────────────

  static flattenBody(requestBody) {
    if (!requestBody) return null;
    if (requestBody.type === 'json' && requestBody.data) return requestBody.data;
    if (requestBody.type === 'formData' && requestBody.data) {
      const out = {};
      for (const [k, v] of Object.entries(requestBody.data)) {
        out[k] = Array.isArray(v) ? v[0] : v;
      }
      return out;
    }
    return null;
  }

  static enrichFromBody(result, body) {
    // ─── Entra Verified ID issuance request ───────────────────────────────
    if (body.type === 'issuance' || body.manifest || body.credentialType) {
      if (body.credentialType) result.credentialType = body.credentialType;
      if (body.manifest)       result.manifestUrl    = body.manifest;
      if (body.authority)      result.authority      = body.authority;
      if (body.pin)            result.pinRequired    = true;
    }

    // ─── Entra Verified ID presentation request ───────────────────────────
    if (body.requestedCredentials || body.includesReceipt !== undefined) {
      result.requestedCredentials = Array.isArray(body.requestedCredentials)
        ? body.requestedCredentials.map(c => c.type || c).filter(Boolean)
        : null;
      if (body.includesReceipt !== undefined) result.includesReceipt = !!body.includesReceipt;
    }
    if (body.includeQRCode !== undefined) result.includeQRCode = !!body.includeQRCode;
    if (body.authority && !result.authority)  result.authority  = body.authority;
    if (body.registration)    result.clientName = body.registration.clientName || null;

    // Callback info
    if (body.callback) {
      result.callbackUrl  = typeof body.callback === 'string' ? body.callback : body.callback?.url;
      result.callbackState = body.callback?.state || null;
    }

    // ─── OpenID4VP (vp_token / presentation_definition) ───────────────────
    if (body.presentation_definition) {
      result.presentationDefinition = true;
      result.inputDescriptors = (body.presentation_definition.input_descriptors || [])
        .map(d => d.id || d.name).filter(Boolean);
    }
    if (body.vp_token)  result.vpTokenPresent = true;
    if (body.id_token)  result.idTokenPresent  = true;

    // ─── OpenID4VCI (credential issuance) ─────────────────────────────────
    if (body.credential_issuer)  result.credentialIssuer  = body.credential_issuer;
    if (body.credential_type)    result.credentialType     = body.credential_type;
    if (body.credential_types)   result.credentialType     = body.credential_types.join(', ');
    if (body.proof)              result.proofPresent       = true;
    if (body.format)             result.format             = body.format;

    // ─── StatusList / revocation ──────────────────────────────────────────
    if (body.statusListIndex !== undefined) result.statusListIndex = body.statusListIndex;
    if (body.statusListCredential)          result.statusListCredential = body.statusListCredential;
  }

  // ─── Warnings ─────────────────────────────────────────────────────────────

  static addWarnings(result) {
    if (result.pinRequired) {
      result.warnings.push({
        severity: 'info',
        message: 'PIN required for credential issuance — user will be prompted for a PIN',
      });
    }
    if (result.includeQRCode === true) {
      result.warnings.push({
        severity: 'info',
        message: 'QR code requested — issuance will display a QR code for wallet scanning',
      });
    }
    if (result.callbackUrl && /localhost|127\.0\.0\.1/i.test(result.callbackUrl)) {
      result.warnings.push({
        severity: 'warning',
        message: `Callback URL points to localhost (${result.callbackUrl}) — not suitable for production`,
      });
    }
  }
}

export default VerifiedIdDecoder;
