/**
 * Entra Auth Tracer - SAML 2.0 / WS-Federation Decoder
 *
 * Handles:
 *  - Redirect binding: base64 + raw-DEFLATE → XML
 *  - POST binding: base64 only → XML
 *  - WS-Federation wresult (URL-encoded XML, no compression)
 *
 * Runs in the extension popup context (DOMParser, atob,
 * DecompressionStream all available).
 */

class SamlDecoder {
  // ─── Extraction ────────────────────────────────────────────────────────────

  /**
   * Find raw SAML data inside a captured request object.
   * Returns { raw, messageType, binding [, preDecoded] } or null.
   */
  static extract(request) {
    const url = new URL(request.url);

    // Redirect binding — SAMLRequest (GET → IdP)
    const samlReq = url.searchParams.get('SAMLRequest');
    if (samlReq) return { raw: samlReq, messageType: 'SAMLRequest', binding: 'redirect' };

    // Redirect binding — SAMLResponse (less common)
    const samlRes = url.searchParams.get('SAMLResponse');
    if (samlRes) return { raw: samlRes, messageType: 'SAMLResponse', binding: 'redirect' };

    // WS-Federation wresult (URL-encoded XML, no deflate)
    const wresult = url.searchParams.get('wresult');
    if (wresult) return { raw: wresult, messageType: 'WSFedResult', binding: 'redirect', preDecoded: true };

    // POST binding — form body
    if (request.requestBody && request.requestBody.type === 'formData') {
      const fd = request.requestBody.data;
      if (fd.SAMLRequest && fd.SAMLRequest[0]) {
        return { raw: fd.SAMLRequest[0], messageType: 'SAMLRequest', binding: 'post' };
      }
      if (fd.SAMLResponse && fd.SAMLResponse[0]) {
        return { raw: fd.SAMLResponse[0], messageType: 'SAMLResponse', binding: 'post' };
      }
      if (fd.wresult && fd.wresult[0]) {
        return { raw: fd.wresult[0], messageType: 'WSFedResult', binding: 'post', preDecoded: true };
      }
    }

    return null;
  }

  // ─── Decoding ──────────────────────────────────────────────────────────────

  /**
   * Decode a raw SAML value to an XML string.
   *   Redirect binding: base64 → raw-DEFLATE inflate → XML
   *   POST binding:     base64 → XML
   *   WS-Fed:           URL-decode → XML
   */
  static async decode(extracted) {
    if (extracted.preDecoded) {
      try { return decodeURIComponent(extracted.raw); } catch { return extracted.raw; }
    }

    // Normalise base64url → base64 and fix padding
    const b64 = extracted.raw.replace(/-/g, '+').replace(/_/g, '/');
    const padded = b64 + '=='.slice(0, (4 - (b64.length % 4)) % 4);

    const binaryStr = atob(padded);
    const bytes = Uint8Array.from(binaryStr, c => c.charCodeAt(0));

    if (extracted.binding === 'redirect') {
      return SamlDecoder.inflateRaw(bytes);
    }
    return new TextDecoder('utf-8').decode(bytes);
  }

  /**
   * Inflate a raw-DEFLATE (no zlib header) Uint8Array.
   * Uses the Streams API (available in Chrome 80+).
   */
  static async inflateRaw(bytes) {
    const ds = new DecompressionStream('deflate-raw');
    const writer = ds.writable.getWriter();
    const reader = ds.readable.getReader();

    writer.write(bytes);
    writer.close();

    const chunks = [];
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
    }

    const total = chunks.reduce((n, c) => n + c.length, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) { out.set(c, off); off += c.length; }
    return new TextDecoder('utf-8').decode(out);
  }

  // ─── Parsing ───────────────────────────────────────────────────────────────

  /**
   * Parse SAML XML into a structured result object.
   */
  static parse(xmlText) {
    const parser = new DOMParser();
    const doc = parser.parseFromString(xmlText, 'application/xml');

    const parseError = doc.querySelector('parsererror');
    if (parseError) {
      return { error: 'XML parse failed: ' + parseError.textContent.substring(0, 300) };
    }

    const root = doc.documentElement;
    const base = {
      messageType: root.localName,
      id: root.getAttribute('ID'),
      version: root.getAttribute('Version'),
      issueInstant: root.getAttribute('IssueInstant'),
      destination: root.getAttribute('Destination'),
      issuer: SamlDecoder.getText(doc, 'Issuer'),
    };

    switch (root.localName) {
      case 'AuthnRequest':   return { ...base, ...SamlDecoder.parseAuthnRequest(doc, root) };
      case 'Response':       return { ...base, ...SamlDecoder.parseResponse(doc, root) };
      case 'LogoutRequest':  return { ...base, ...SamlDecoder.parseLogoutRequest(doc, root) };
      case 'LogoutResponse': return { ...base, ...SamlDecoder.parseLogoutResponse(doc, root) };
      default: return base;
    }
  }

  static getText(doc, localName) {
    const el = doc.getElementsByTagNameNS('*', localName)[0];
    return el ? el.textContent.trim() : null;
  }

  static parseAuthnRequest(doc, root) {
    const nipEl = doc.getElementsByTagNameNS('*', 'NameIDPolicy')[0];
    const racEl = doc.getElementsByTagNameNS('*', 'RequestedAuthnContext')[0];
    return {
      assertionConsumerServiceURL: root.getAttribute('AssertionConsumerServiceURL'),
      protocolBinding: root.getAttribute('ProtocolBinding'),
      forceAuthn: root.getAttribute('ForceAuthn'),
      isPassive: root.getAttribute('IsPassive'),
      providerName: root.getAttribute('ProviderName'),
      nameIDPolicy: nipEl ? {
        format: nipEl.getAttribute('Format'),
        allowCreate: nipEl.getAttribute('AllowCreate'),
      } : null,
      requestedAuthnContext: racEl ? {
        comparison: racEl.getAttribute('Comparison'),
        classRefs: Array.from(racEl.getElementsByTagNameNS('*', 'AuthnContextClassRef'))
          .map(e => e.textContent.trim()),
      } : null,
    };
  }

  static parseResponse(doc, root) {
    return {
      inResponseTo: root.getAttribute('InResponseTo'),
      status: SamlDecoder.parseStatus(doc),
      assertion: SamlDecoder.parseAssertion(doc),
    };
  }

  static parseStatus(doc) {
    const codeEl = doc.getElementsByTagNameNS('*', 'StatusCode')[0];
    if (!codeEl) return null;
    const fullCode = codeEl.getAttribute('Value') || '';
    const msgEl = doc.getElementsByTagNameNS('*', 'StatusMessage')[0];
    return {
      code: fullCode.split(':').pop(),
      fullCode,
      isSuccess: fullCode.includes('Success'),
      message: msgEl ? msgEl.textContent.trim() : null,
    };
  }

  static parseAssertion(doc) {
    const aEl = doc.getElementsByTagNameNS('*', 'Assertion')[0];
    if (!aEl) return null;

    const nameIDEl = aEl.getElementsByTagNameNS('*', 'NameID')[0];
    const condEl = aEl.getElementsByTagNameNS('*', 'Conditions')[0];
    const stmtEl = aEl.getElementsByTagNameNS('*', 'AuthnStatement')[0];
    const ctxEl = stmtEl && stmtEl.getElementsByTagNameNS('*', 'AuthnContextClassRef')[0];

    const attributes = {};
    for (const attrEl of aEl.getElementsByTagNameNS('*', 'Attribute')) {
      const name = attrEl.getAttribute('Name') || attrEl.getAttribute('FriendlyName') || '(unknown)';
      attributes[name] = Array.from(attrEl.getElementsByTagNameNS('*', 'AttributeValue'))
        .map(e => e.textContent.trim());
    }

    return {
      id: aEl.getAttribute('ID'),
      issueInstant: aEl.getAttribute('IssueInstant'),
      issuer: (aEl.getElementsByTagNameNS('*', 'Issuer')[0] || {}).textContent
        ? aEl.getElementsByTagNameNS('*', 'Issuer')[0].textContent.trim() : null,
      nameID: nameIDEl ? {
        value: nameIDEl.textContent.trim(),
        format: nameIDEl.getAttribute('Format'),
        spNameQualifier: nameIDEl.getAttribute('SPNameQualifier'),
      } : null,
      conditions: condEl ? {
        notBefore: condEl.getAttribute('NotBefore'),
        notOnOrAfter: condEl.getAttribute('NotOnOrAfter'),
        audiences: Array.from(condEl.getElementsByTagNameNS('*', 'Audience')).map(e => e.textContent.trim()),
      } : null,
      authnStatement: stmtEl ? {
        authnInstant: stmtEl.getAttribute('AuthnInstant'),
        sessionIndex: stmtEl.getAttribute('SessionIndex'),
        authnContextClassRef: ctxEl ? ctxEl.textContent.trim() : null,
      } : null,
      attributes,
    };
  }

  static parseLogoutRequest(doc, _root) {
    return {
      nameID: SamlDecoder.getText(doc, 'NameID'),
      sessionIndex: SamlDecoder.getText(doc, 'SessionIndex'),
    };
  }

  static parseLogoutResponse(doc, root) {
    return {
      inResponseTo: root.getAttribute('InResponseTo'),
      status: SamlDecoder.parseStatus(doc),
    };
  }

  // ─── Formatting ────────────────────────────────────────────────────────────

  /**
   * Indent XML for display (simple pretty-printer, safe for valid XML).
   */
  static prettyPrintXml(xmlText) {
    const stripped = xmlText.replace(/>\s+</g, '><');
    let indent = 0;
    const lines = [];

    for (const part of stripped.split(/(<[^>]+>)/)) {
      if (!part.trim()) continue;
      if (part.startsWith('</')) {
        indent = Math.max(0, indent - 2);
        lines.push(' '.repeat(indent) + part);
      } else if (
        part.startsWith('<') &&
        !part.endsWith('/>') &&
        !part.startsWith('<?') &&
        !part.startsWith('<!')
      ) {
        lines.push(' '.repeat(indent) + part);
        indent += 2;
      } else {
        lines.push(' '.repeat(indent) + part.trim());
      }
    }
    return lines.join('\n');
  }

  // ─── Pipeline ──────────────────────────────────────────────────────────────

  /**
   * Full pipeline: extract → decode → parse.
   * Returns null if no SAML data is present in the request.
   */
  static async decodeSamlFromRequest(request) {
    const extracted = SamlDecoder.extract(request);
    if (!extracted) return null;

    try {
      const xmlText = await SamlDecoder.decode(extracted);
      const parsed = SamlDecoder.parse(xmlText);
      return { binding: extracted.binding, messageType: extracted.messageType, xmlText, parsed };
    } catch (err) {
      return { binding: extracted.binding, messageType: extracted.messageType, error: err.message };
    }
  }
}

export default SamlDecoder;
