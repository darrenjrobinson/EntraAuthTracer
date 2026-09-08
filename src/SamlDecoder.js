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
      // An enveloped XML signature directly under the root element signs the whole message
      messageSigned: SamlDecoder.hasDirectChild(root, 'Signature'),
      hasEncryptedAssertion: doc.getElementsByTagNameNS('*', 'EncryptedAssertion').length > 0,
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

  /** True when `el` has a direct child element with the given local name. */
  static hasDirectChild(el, localName) {
    if (!el) return false;
    return Array.from(el.childNodes).some(n => n.nodeType === 1 && n.localName === localName);
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
      signed: SamlDecoder.hasDirectChild(aEl, 'Signature'),
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

  // ─── Security assessment ───────────────────────────────────────────────────

  /** Clock tolerance applied to NotBefore / NotOnOrAfter checks. */
  static CLOCK_SKEW_MS = 5 * 60 * 1000;
  /** Assertion validity windows longer than this are flagged. */
  static LONG_ASSERTION_LIFETIME_MS = 60 * 60 * 1000;

  /**
   * Assess a parsed SAML message. Returns [{ rule, severity, message }] in the
   * same shape as the OAuth and Verified ID decoders. Never throws.
   *
   * @param {object} parsed  Output of SamlDecoder.parse
   * @param {number} [now]   Epoch milliseconds (injectable for tests)
   */
  static generateWarnings(parsed, now = Date.now()) {
    const warnings = [];
    if (!parsed || parsed.error) return warnings;
    const push = (rule, severity, message) => warnings.push({ rule, severity, message });
    const parseTime = (v) => { const t = v ? Date.parse(v) : NaN; return isNaN(t) ? null : t; };

    if (parsed.messageType === 'AuthnRequest') {
      if (!parsed.destination) {
        push('saml_request_no_destination', 'info',
          'AuthnRequest has no Destination attribute — the IdP cannot verify the request was meant for it');
      }
      if (!parsed.messageSigned) {
        push('saml_request_unsigned', 'info',
          'AuthnRequest is not signed — acceptable for many IdPs, but signing prevents request tampering');
      }
      const fmt = parsed.nameIDPolicy && parsed.nameIDPolicy.format;
      if (fmt && /nameid-format:unspecified$/.test(fmt)) {
        push('saml_nameid_policy_unspecified', 'info',
          'NameIDPolicy format is unspecified — the IdP chooses the identifier; prefer persistent or transient for stable, privacy-preserving subjects');
      }
    }

    if (parsed.messageType === 'Response' || parsed.messageType === 'LogoutResponse') {
      if (parsed.status && !parsed.status.isSuccess) {
        push('saml_status_failure', 'error',
          `SAML status is ${parsed.status.code || parsed.status.fullCode || 'unknown'}${parsed.status.message ? ` — ${parsed.status.message}` : ''}`);
      }
    }

    if (parsed.messageType === 'Response') {
      const a = parsed.assertion;
      if (parsed.hasEncryptedAssertion) {
        push('saml_assertion_encrypted', 'info',
          'Assertion is encrypted (EncryptedAssertion) — contents cannot be decoded without the SP private key');
      } else if (!a && parsed.status && parsed.status.isSuccess) {
        push('saml_no_assertion', 'warning',
          'Successful Response carries no Assertion');
      }

      if (a) {
        if (!parsed.messageSigned && !a.signed) {
          push('saml_unsigned', 'warning',
            'Neither the Response nor the Assertion carries an XML signature — the SP must reject this message');
        }
        const cond = a.conditions || {};
        const notBefore = parseTime(cond.notBefore);
        const notOnOrAfter = parseTime(cond.notOnOrAfter);
        if (notOnOrAfter !== null && notOnOrAfter + SamlDecoder.CLOCK_SKEW_MS < now) {
          push('saml_assertion_expired', 'warning',
            `Assertion expired at ${cond.notOnOrAfter} (NotOnOrAfter is in the past)`);
        }
        if (notBefore !== null && notBefore - SamlDecoder.CLOCK_SKEW_MS > now) {
          push('saml_assertion_not_yet_valid', 'warning',
            `Assertion is not yet valid (NotBefore ${cond.notBefore} is in the future)`);
        }
        if (notBefore !== null && notOnOrAfter !== null && notOnOrAfter - notBefore > SamlDecoder.LONG_ASSERTION_LIFETIME_MS) {
          push('saml_assertion_long_lifetime', 'info',
            `Assertion validity window is ${Math.round((notOnOrAfter - notBefore) / 60000)} minutes — assertions are normally valid for a few minutes`);
        }
        if (!cond.audiences || cond.audiences.length === 0) {
          push('saml_no_audience_restriction', 'warning',
            'Assertion has no AudienceRestriction — it could be replayed to a different service provider');
        }
      }
    }

    return warnings;
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
      const warnings = SamlDecoder.generateWarnings(parsed);
      return { binding: extracted.binding, messageType: extracted.messageType, xmlText, parsed, warnings };
    } catch (err) {
      return { binding: extracted.binding, messageType: extracted.messageType, error: err.message };
    }
  }
}

export default SamlDecoder;
