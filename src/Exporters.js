/**
 * Entra Auth Tracer - Export builders
 *
 * Builds the JSON, Markdown, plain-text and print-ready HTML reports from the
 * captured request list. Pure functions: the caller supplies the requests, the
 * timestamp and the extension version, and receives a string. Credentials are
 * redacted with the same policy the popup uses (see Sanitize).
 */

import FlowCorrelator from './FlowCorrelator.js';
import Sanitize from './Sanitize.js';

class Exporters {
  static REPO_URL = 'https://github.com/darrenjrobinson/EntraAuthTracer';

  static FORMATS = ['json', 'markdown', 'txt', 'pdf'];

  static MIME = {
    json: 'application/json',
    markdown: 'text/markdown',
    txt: 'text/plain',
    pdf: 'text/html'
  };

  static EXT = {
    json: 'json',
    markdown: 'md',
    txt: 'txt',
    pdf: 'html'
  };

  /**
   * Download filename for a format, e.g. entra-auth-trace_2026-09-08_01-02-03.json
   */
  static filename(format, now = new Date()) {
    const ext = Exporters.EXT[format];
    if (!ext) throw new Error(`Unknown export format: ${format}`);
    const ts = now.toISOString().replace(/[:.]/g, '-').replace('T', '_').slice(0, 19);
    return `entra-auth-trace_${ts}.${ext}`;
  }

  /**
   * Build the export content for a format.
   */
  static build(format, requests, now = new Date(), version = 'unknown') {
    switch (format) {
      case 'json': return Exporters.buildJsonExport(requests, now, version);
      case 'markdown': return Exporters.buildMarkdownExport(requests, now, version);
      case 'txt': return Exporters.buildTxtExport(requests, now, version);
      case 'pdf': return Exporters.buildPdfHtml(requests, now, version);
      default: throw new Error(`Unknown export format: ${format}`);
    }
  }

  // ─── Shared helpers ────────────────────────────────────────────────────────

  static isoTime(ts) {
    const d = new Date(ts || 0);
    return isNaN(d.getTime()) ? String(ts) : d.toISOString();
  }

  static statusWithCode(r) {
    return `${r.status}${r.statusCode ? ' (' + r.statusCode + ')' : ''}`;
  }

  static severityTag(w) {
    return `[${String(w.severity || 'info').toUpperCase()}]`;
  }

  /** Attested credential summary for FIDO2 sections (null when absent). */
  static fido2Credential(f) {
    const cred = f && f.authenticatorData && f.authenticatorData.attestedCredentialData;
    if (!cred) return null;
    return {
      aaguid: cred.aaguid,
      authenticator: cred.authenticator ? `${cred.authenticator.name}${cred.authenticator.vendor ? ` (${cred.authenticator.vendor})` : ''}` : null,
      algorithm: cred.credentialPublicKey && cred.credentialPublicKey.keyInfo ? cred.credentialPublicKey.keyInfo.algorithmDescription : null
    };
  }

  static fido2Flags(f) {
    const flags = f && f.authenticatorData && f.authenticatorData.flags;
    if (!flags) return null;
    return ['UP', 'UV', 'BE', 'BS', 'AT', 'ED'].filter(k => flags[k]).join(' ') || 'none';
  }

  // ─── JSON export ─────────────────────────────────────────────────────────────

  static buildJsonExport(requests, now, version) {
    const meta = {
      generated_at: now.toISOString(),
      extension_version: version,
      total_requests: requests.length,
      export_scope: 'complete_session',
      redaction: 'client secrets, passwords, refresh/access/ID tokens, assertions and Authorization/Cookie headers are redacted; client_assertion and id_token_hint are truncated'
    };

    const exportData = {
      export_metadata: meta,
      requests: requests.map(r => Exporters.requestToJsonObj(r))
    };

    return JSON.stringify(exportData, null, 2);
  }

  static requestToJsonObj(r) {
    const obj = {
      id: r.id,
      timestamp: Exporters.isoTime(r.timestamp),
      method: r.method,
      url: Sanitize.redactUrl(r.url),
      flow_type: r.flowType,
      flow_category: FlowCorrelator.getFlowTypeCategory(r.flowType),
      status: r.status
    };
    if (r.statusCode) obj.status_code = r.statusCode;
    if (r.error)      obj.error       = r.error;
    if (r.requestHeaders && r.requestHeaders.length)  obj.request_headers  = Sanitize.redactHeaders(r.requestHeaders);
    if (r.responseHeaders && r.responseHeaders.length) obj.response_headers = Sanitize.redactHeaders(r.responseHeaders);
    if (r.requestBody)  obj.request_body  = Sanitize.redactBody(r.requestBody);
    if (r.responseBody) obj.response_body = r.responseBody;
    if (r.oauthAnalysis)  obj.oauth_analysis  = r.oauthAnalysis;
    if (r.fido2Analysis)  obj.fido2_analysis  = r.fido2Analysis;
    if (r.samlAnalysis)   obj.saml_analysis   = r.samlAnalysis;
    if (r.didAnalysis)    obj.did_analysis     = r.didAnalysis;
    return obj;
  }

  // ─── Markdown export ─────────────────────────────────────────────────────────

  static buildMarkdownExport(requests, now, version) {
    const lines = [];
    lines.push('# Entra Auth Trace Report');
    lines.push('');
    lines.push(`**Generated:** ${now.toUTCString()}`);
    lines.push(`**Extension:** Entra Auth Tracer v${version}`);
    lines.push(`**Total Requests:** ${requests.length}`);
    lines.push('');

    // Summary table
    const flowCounts = {};
    const statusCounts = { completed: 0, error: 0, pending: 0 };
    for (const r of requests) {
      flowCounts[r.flowType] = (flowCounts[r.flowType] || 0) + 1;
      if (r.status in statusCounts) statusCounts[r.status]++;
    }
    lines.push('## Session Summary');
    lines.push('');
    lines.push('| Metric | Value |');
    lines.push('|---|---|');
    lines.push(`| **Total Requests** | ${requests.length} |`);
    lines.push(`| **Completed** | ${statusCounts.completed} |`);
    lines.push(`| **Errors** | ${statusCounts.error} |`);
    lines.push(`| **Pending** | ${statusCounts.pending} |`);
    for (const [flow, count] of Object.entries(flowCounts)) {
      lines.push(`| **${flow}** | ${count} |`);
    }
    lines.push('');

    // Per-request details
    lines.push('## Request Details');
    lines.push('');

    requests.forEach((r, i) => {
      const url = (() => { try { return new URL(r.url); } catch { return { pathname: r.url, hostname: '' }; } })();
      lines.push(`### Request ${i + 1}: ${r.method} ${url.pathname}`);
      lines.push('');
      lines.push('| Field | Value |');
      lines.push('|---|---|');
      lines.push(`| **Timestamp** | ${Exporters.isoTime(r.timestamp)} |`);
      lines.push(`| **Method** | ${r.method} |`);
      lines.push(`| **URL** | \`${Sanitize.redactUrl(r.url)}\` |`);
      lines.push(`| **Flow Type** | ${r.flowType} |`);
      lines.push(`| **Status** | ${Exporters.statusWithCode(r)} |`);
      if (r.error) lines.push(`| **Error** | ${r.error} |`);
      lines.push('');

      // OAuth analysis
      if (r.oauthAnalysis && !r.oauthAnalysis.error) {
        const a = r.oauthAnalysis;
        lines.push('#### OAuth 2.1 Analysis');
        lines.push('');
        lines.push('| Field | Value |');
        lines.push('|---|---|');
        if (a.label)      lines.push(`| **Grant Type** | ${a.label} |`);
        if (a.clientId)   lines.push(`| **Client ID** | \`${a.clientId}\` |`);
        if (a.redirectUri) lines.push(`| **Redirect URI** | ${a.redirectUri} |`);
        if (a.responseType) lines.push(`| **Response Type** | ${a.responseType} |`);
        if (a.authMethodLabel || a.authMethod) lines.push(`| **Client Auth** | ${a.authMethodLabel || a.authMethod} |`);
        if (a.pkce)       lines.push(`| **PKCE** | ${a.pkce.codeChallengeMethod} |`);
        if (a.scopeLabels && a.scopeLabels.length) {
          lines.push(`| **Scopes** | ${a.scopeLabels.map(s => s.scope).join(', ')} |`);
        }
        if (a.warnings && a.warnings.length) {
          lines.push('');
          lines.push('**Security Warnings:**');
          lines.push('');
          for (const w of a.warnings) {
            lines.push(`- ${Exporters.severityTag(w)} ${w.message}`);
          }
        }
        lines.push('');
      }

      // FIDO2 analysis
      if (r.fido2Analysis && !r.fido2Analysis.error) {
        const f = r.fido2Analysis;
        lines.push('#### FIDO2 Analysis');
        lines.push('');
        lines.push('| Field | Value |');
        lines.push('|---|---|');
        if (f.clientDataJSON) {
          const cd = f.clientDataJSON;
          lines.push(`| **Type** | ${cd.type} |`);
          lines.push(`| **Origin** | ${cd.origin} |`);
          lines.push(`| **Cross Origin** | ${cd.crossOrigin ? 'Yes' : 'No'} |`);
        }
        const flags = Exporters.fido2Flags(f);
        if (flags) lines.push(`| **Flags** | ${flags} |`);
        if (f.authenticatorData && f.authenticatorData.signCount != null) lines.push(`| **Sign Count** | ${f.authenticatorData.signCount} |`);
        const cred = Exporters.fido2Credential(f);
        if (cred) {
          lines.push(`| **AAGUID** | \`${cred.aaguid}\` |`);
          if (cred.authenticator) lines.push(`| **Authenticator** | ${cred.authenticator} |`);
          if (cred.algorithm) lines.push(`| **Key Algorithm** | ${cred.algorithm} |`);
        }
        if (f.attestationObject && f.attestationObject.fmt) lines.push(`| **Attestation Format** | ${f.attestationObject.fmt} |`);
        lines.push('');
      }

      // Verified ID / DID analysis
      if (r.didAnalysis && !r.didAnalysis.error) {
        const d = r.didAnalysis;
        lines.push('#### Verified ID / DID Analysis');
        lines.push('');
        lines.push('| Field | Value |');
        lines.push('|---|---|');
        lines.push(`| **Operation** | ${d.operation} |`);
        if (d.did)                  lines.push(`| **DID** | \`${d.did}\` |`);
        if (d.requestId)            lines.push(`| **Request ID** | \`${d.requestId}\` |`);
        if (d.requestStatus)        lines.push(`| **Request Status** | ${d.requestStatus} |`);
        if (d.credentialType)       lines.push(`| **Credential Type** | ${d.credentialType} |`);
        if (d.authority)            lines.push(`| **Authority** | ${d.authority} |`);
        if (d.clientName)           lines.push(`| **Client Name** | ${d.clientName} |`);
        if (d.requestedCredentials) lines.push(`| **Requested Credentials** | ${d.requestedCredentials.join(', ')} |`);
        if (d.callbackUrl)          lines.push(`| **Callback URL** | ${d.callbackUrl} |`);
        if (d.warnings && d.warnings.length) {
          lines.push('');
          lines.push('**Warnings:**');
          for (const w of d.warnings) lines.push(`- ${Exporters.severityTag(w)} ${w.message}`);
        }
        lines.push('');
      }

      lines.push('---');
      lines.push('');
    });

    lines.push('');
    lines.push(`*Generated by [Entra Auth Tracer](${Exporters.REPO_URL})*`);
    return lines.join('\n');
  }

  // ─── Plain text export ───────────────────────────────────────────────────────

  static buildTxtExport(requests, now, version) {
    const lines = [];
    const hr = '='.repeat(72);
    const hr2 = '-'.repeat(72);

    lines.push('ENTRA AUTH TRACE REPORT');
    lines.push(hr);
    lines.push(`Generated : ${now.toUTCString()}`);
    lines.push(`Extension : Entra Auth Tracer v${version}`);
    lines.push(`Requests  : ${requests.length}`);
    lines.push(hr);
    lines.push('');

    requests.forEach((r, i) => {
      lines.push(`REQUEST ${i + 1} of ${requests.length}`);
      lines.push(hr2);
      lines.push(`Time      : ${Exporters.isoTime(r.timestamp)}`);
      lines.push(`Method    : ${r.method}`);
      lines.push(`URL       : ${Sanitize.redactUrl(r.url)}`);
      lines.push(`Flow      : ${r.flowType}`);
      lines.push(`Status    : ${Exporters.statusWithCode(r)}`);
      if (r.error) lines.push(`Error     : ${r.error}`);

      if (r.requestHeaders && r.requestHeaders.length) {
        lines.push('');
        lines.push('Request Headers:');
        for (const h of Sanitize.redactHeaders(r.requestHeaders)) {
          lines.push(`  ${h.name}: ${h.value}`);
        }
      }

      if (r.requestBody) {
        lines.push('');
        lines.push('Request Body:');
        const body = Sanitize.redactBody(r.requestBody);
        if (typeof body === 'string') {
          lines.push('  ' + body.substring(0, 2000));
        } else if (body.type === 'formData' && body.data) {
          for (const [k, v] of Object.entries(body.data)) {
            lines.push(`  ${k}=${Array.isArray(v) ? v[0] : v}`);
          }
        } else if (body.type === 'json') {
          lines.push('  ' + JSON.stringify(body.data).substring(0, 2000));
        } else {
          lines.push('  ' + String(body.data == null ? '' : body.data).substring(0, 2000));
        }
      }

      if (r.responseHeaders && r.responseHeaders.length) {
        lines.push('');
        lines.push('Response Headers:');
        for (const h of Sanitize.redactHeaders(r.responseHeaders)) {
          lines.push(`  ${h.name}: ${h.value}`);
        }
      }

      if (r.oauthAnalysis && !r.oauthAnalysis.error) {
        const a = r.oauthAnalysis;
        lines.push('');
        lines.push('OAuth 2.1 Analysis:');
        if (a.label)       lines.push(`  Grant Type  : ${a.label}`);
        if (a.clientId)    lines.push(`  Client ID   : ${a.clientId}`);
        if (a.redirectUri) lines.push(`  Redirect URI: ${a.redirectUri}`);
        if (a.authMethodLabel || a.authMethod) lines.push(`  Client Auth : ${a.authMethodLabel || a.authMethod}`);
        if (a.pkce)        lines.push(`  PKCE        : ${a.pkce.codeChallengeMethod}`);
        if (a.scopeLabels && a.scopeLabels.length) {
          lines.push(`  Scopes      : ${a.scopeLabels.map(s => s.scope).join(' ')}`);
        }
        if (a.warnings && a.warnings.length) {
          lines.push('  Warnings:');
          for (const w of a.warnings) lines.push(`    ${Exporters.severityTag(w)} ${w.message}`);
        }
      }

      if (r.fido2Analysis && !r.fido2Analysis.error) {
        const f = r.fido2Analysis;
        lines.push('');
        lines.push('FIDO2 Analysis:');
        if (f.clientDataJSON) {
          lines.push(`  Type        : ${f.clientDataJSON.type}`);
          lines.push(`  Origin      : ${f.clientDataJSON.origin}`);
        }
        const flags = Exporters.fido2Flags(f);
        if (flags) lines.push(`  Flags       : ${flags}`);
        if (f.authenticatorData && f.authenticatorData.signCount != null) lines.push(`  Sign Count  : ${f.authenticatorData.signCount}`);
        const cred = Exporters.fido2Credential(f);
        if (cred) {
          lines.push(`  AAGUID      : ${cred.aaguid}`);
          if (cred.authenticator) lines.push(`  Authenticator: ${cred.authenticator}`);
          if (cred.algorithm) lines.push(`  Key Alg     : ${cred.algorithm}`);
        }
        if (f.attestationObject && f.attestationObject.fmt) lines.push(`  Attestation : ${f.attestationObject.fmt}`);
      }

      if (r.didAnalysis && !r.didAnalysis.error) {
        const d = r.didAnalysis;
        lines.push('');
        lines.push('Verified ID / DID Analysis:');
        lines.push(`  Operation   : ${d.operation}`);
        if (d.did)                  lines.push(`  DID         : ${d.did}`);
        if (d.requestId)            lines.push(`  Request ID  : ${d.requestId}`);
        if (d.requestStatus)        lines.push(`  Status      : ${d.requestStatus}`);
        if (d.credentialType)       lines.push(`  Cred Type   : ${d.credentialType}`);
        if (d.authority)            lines.push(`  Authority   : ${d.authority}`);
        if (d.requestedCredentials) lines.push(`  Requested   : ${d.requestedCredentials.join(', ')}`);
        if (d.callbackUrl)          lines.push(`  Callback    : ${d.callbackUrl}`);
        if (d.warnings && d.warnings.length) {
          lines.push('  Warnings:');
          for (const w of d.warnings) lines.push(`    ${Exporters.severityTag(w)} ${w.message}`);
        }
      }

      lines.push('');
    });

    lines.push(hr);
    lines.push(`Generated by Entra Auth Tracer v${version}`);
    return lines.join('\n');
  }

  // ─── PDF / Print HTML export ─────────────────────────────────────────────────

  /**
   * Build a print-optimised HTML report.
   * Saved as .html — the user opens the file and prints to PDF.
   */
  static buildPdfHtml(requests, now, version) {
    const e = (v) => Sanitize.escapeHtml(v == null ? '' : v);
    const ts = now.toUTCString();

    // Flow statistics by category
    const { byCategory, errors } = FlowCorrelator.countByCategory(requests);
    const statusCounts = { completed: 0, error: errors, pending: 0 };
    for (const r of requests) {
      if (r.status === 'completed' || r.status === 'pending') statusCounts[r.status]++;
    }

    const summaryRows = FlowCorrelator.CATEGORIES
      .filter(cat => byCategory[cat])
      .map(cat => `<tr><td>${e(FlowCorrelator.CATEGORY_LABELS[cat])}</td><td>${byCategory[cat]}</td></tr>`)
      .join('');

    const warningsCell = (warnings) => warnings
      .map(w => e(`${Exporters.severityTag(w)} ${w.message}`))
      .join('<br>');

    const requestSections = requests.map((r, i) => {
      let pathname = r.url || '';
      let hostname = '';
      try { const u = new URL(r.url); pathname = u.pathname; hostname = u.hostname; } catch { /* keep */ }

      let sec = `
        <div class="req-section">
          <h3>Request ${i + 1}: <span class="method">${e(r.method || 'GET')}</span> ${e(pathname)}</h3>
          <p class="req-host">${e(hostname)}</p>
          <table>
            <tr><td class="lbl">Timestamp</td><td>${e(Exporters.isoTime(r.timestamp))}</td></tr>
            <tr><td class="lbl">URL</td><td class="url-cell">${e(Sanitize.redactUrl(r.url))}</td></tr>
            <tr><td class="lbl">Flow Type</td><td>${e(r.flowType)}</td></tr>
            <tr><td class="lbl">Status</td><td class="${r.status === 'completed' ? 'ok' : r.status === 'error' ? 'err' : ''}">${e(Exporters.statusWithCode(r))}</td></tr>
            ${r.error ? `<tr><td class="lbl">Error</td><td class="err">${e(r.error)}</td></tr>` : ''}
          </table>`;

      if (r.oauthAnalysis && !r.oauthAnalysis.error) {
        const a = r.oauthAnalysis;
        sec += `
          <h4>OAuth 2.1 Analysis</h4>
          <table>
            ${a.label      ? `<tr><td class="lbl">Grant Type</td><td>${e(a.label)}</td></tr>` : ''}
            ${a.clientId   ? `<tr><td class="lbl">Client ID</td><td class="mono">${e(a.clientId)}</td></tr>` : ''}
            ${a.redirectUri ? `<tr><td class="lbl">Redirect URI</td><td>${e(a.redirectUri)}</td></tr>` : ''}
            ${(a.authMethodLabel || a.authMethod) ? `<tr><td class="lbl">Client Auth</td><td>${e(a.authMethodLabel || a.authMethod)}</td></tr>` : ''}
            ${a.pkce       ? `<tr><td class="lbl">PKCE</td><td>${e(a.pkce.codeChallengeMethod)}${a.pkce.isS256 ? ' ✓ S256' : ' ⚠ non-S256'}</td></tr>` : ''}
            ${a.scopes && a.scopes.length ? `<tr><td class="lbl">Scopes</td><td>${e(a.scopes.join(' '))}</td></tr>` : ''}
            ${a.warnings && a.warnings.length ? `<tr><td class="lbl">Warnings</td><td class="warn">${warningsCell(a.warnings)}</td></tr>` : ''}
          </table>`;
      }

      if (r.fido2Analysis && !r.fido2Analysis.error) {
        const f = r.fido2Analysis;
        const cd = f.clientDataJSON;
        const cred = Exporters.fido2Credential(f);
        const flags = Exporters.fido2Flags(f);
        sec += `
          <h4>FIDO2 Analysis</h4>
          <table>
            ${cd ? `<tr><td class="lbl">Type</td><td>${e(cd.type)}</td></tr>
            <tr><td class="lbl">Origin</td><td>${e(cd.origin)}</td></tr>
            <tr><td class="lbl">Cross Origin</td><td>${cd.crossOrigin ? 'Yes' : 'No'}</td></tr>` : ''}
            ${flags ? `<tr><td class="lbl">Flags</td><td>${e(flags)}</td></tr>` : ''}
            ${cred ? `<tr><td class="lbl">AAGUID</td><td class="mono">${e(cred.aaguid)}</td></tr>` : ''}
            ${cred && cred.authenticator ? `<tr><td class="lbl">Authenticator</td><td>${e(cred.authenticator)}</td></tr>` : ''}
            ${cred && cred.algorithm ? `<tr><td class="lbl">Key Algorithm</td><td>${e(cred.algorithm)}</td></tr>` : ''}
            ${f.attestationObject && f.attestationObject.fmt ? `<tr><td class="lbl">Attestation</td><td>${e(f.attestationObject.fmt)}</td></tr>` : ''}
          </table>`;
      }

      if (r.didAnalysis && !r.didAnalysis.error) {
        const d = r.didAnalysis;
        sec += `
          <h4>Verified ID / DID Analysis</h4>
          <table>
            <tr><td class="lbl">Operation</td><td>${e(d.operation)}</td></tr>
            ${d.did ? `<tr><td class="lbl">DID</td><td class="mono">${e(d.did)}</td></tr>` : ''}
            ${d.requestId ? `<tr><td class="lbl">Request ID</td><td class="mono">${e(d.requestId)}</td></tr>` : ''}
            ${d.requestStatus ? `<tr><td class="lbl">Request Status</td><td>${e(d.requestStatus)}</td></tr>` : ''}
            ${d.credentialType ? `<tr><td class="lbl">Credential Type</td><td>${e(d.credentialType)}</td></tr>` : ''}
            ${d.authority ? `<tr><td class="lbl">Authority</td><td>${e(d.authority)}</td></tr>` : ''}
            ${d.callbackUrl ? `<tr><td class="lbl">Callback URL</td><td>${e(d.callbackUrl)}</td></tr>` : ''}
            ${d.warnings && d.warnings.length ? `<tr><td class="lbl">Warnings</td><td class="warn">${warningsCell(d.warnings)}</td></tr>` : ''}
          </table>`;
      }

      sec += '</div>';
      return sec;
    }).join('<hr class="req-hr">');

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Entra Auth Trace Report</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', Arial, sans-serif; font-size: 12px; color: #323130; background: #fff; padding: 24px; max-width: 900px; margin: 0 auto; }
    .print-hint { background: #0078d4; color: #fff; padding: 10px 16px; border-radius: 4px; margin-bottom: 20px; font-size: 13px; display: flex; align-items: center; gap: 10px; }
    .print-hint kbd { background: rgba(255,255,255,0.2); padding: 2px 7px; border-radius: 3px; font-family: inherit; }
    h1 { font-size: 20px; color: #0078d4; border-bottom: 2px solid #0078d4; padding-bottom: 8px; margin-bottom: 16px; }
    h2 { font-size: 15px; color: #323130; margin: 20px 0 8px; padding-bottom: 4px; border-bottom: 1px solid #edebe9; }
    h3 { font-size: 13px; color: #0078d4; margin: 0 0 4px; }
    h4 { font-size: 11px; color: #605e5c; margin: 10px 0 4px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.4px; }
    .meta { color: #605e5c; font-size: 12px; margin-bottom: 16px; }
    .stats { display: flex; gap: 24px; margin-bottom: 16px; flex-wrap: wrap; }
    .stat { text-align: center; min-width: 80px; }
    .stat-val { font-size: 28px; font-weight: 700; color: #0078d4; line-height: 1; }
    .stat-val.ok { color: #107c10; }
    .stat-val.err { color: #d13438; }
    .stat-lbl { font-size: 11px; color: #605e5c; margin-top: 2px; }
    table { width: 100%; border-collapse: collapse; margin-bottom: 8px; }
    th { background: #f3f2f1; text-align: left; padding: 5px 8px; font-size: 11px; color: #605e5c; font-weight: 700; border-bottom: 1px solid #d2d0ce; }
    td { padding: 4px 8px; border-bottom: 1px solid #edebe9; vertical-align: top; font-size: 12px; }
    td.lbl { font-weight: 600; color: #605e5c; width: 130px; white-space: nowrap; }
    .url-cell { word-break: break-all; font-family: 'Consolas', monospace; font-size: 10px; }
    .mono { font-family: 'Consolas', monospace; font-size: 11px; }
    .method { font-family: 'Consolas', monospace; font-weight: 700; }
    .ok { color: #107c10; font-weight: 600; }
    .err { color: #d13438; }
    .warn { color: #ff8c00; }
    .req-section { margin: 16px 0; padding: 12px 14px; border: 1px solid #edebe9; border-radius: 4px; }
    .req-host { font-size: 11px; color: #605e5c; margin-bottom: 6px; }
    hr.req-hr { border: none; border-top: 2px solid #edebe9; margin: 4px 0; }
    .footer { margin-top: 28px; font-size: 11px; color: #605e5c; text-align: center; padding-top: 10px; border-top: 1px solid #edebe9; }
    @media print {
      .print-hint { display: none !important; }
      .req-section { page-break-inside: avoid; }
      body { padding: 0; }
    }
  </style>
</head>
<body>
  <div class="print-hint">
    &#128196; To save as PDF: press <kbd>Ctrl+P</kbd> (or &#8984;P), then choose <em>Save as PDF</em> as the destination.
  </div>
  <h1>&#128274; Entra Auth Trace Report</h1>
  <p class="meta">Generated: <strong>${e(ts)}</strong> &nbsp;&middot;&nbsp; Entra Auth Tracer v${e(version)} &nbsp;&middot;&nbsp; <strong>${requests.length}</strong> request${requests.length !== 1 ? 's' : ''}</p>

  <h2>Session Summary</h2>
  <div class="stats">
    <div class="stat"><div class="stat-val">${requests.length}</div><div class="stat-lbl">Total</div></div>
    <div class="stat"><div class="stat-val ok">${statusCounts.completed}</div><div class="stat-lbl">Completed</div></div>
    <div class="stat"><div class="stat-val err">${statusCounts.error}</div><div class="stat-lbl">Errors</div></div>
    <div class="stat"><div class="stat-val" style="color:#ff8c00">${statusCounts.pending}</div><div class="stat-lbl">Pending</div></div>
  </div>
  <table>
    <tr><th>Flow Type</th><th>Count</th></tr>
    ${summaryRows}
  </table>

  <h2>Request Details</h2>
  ${requestSections}

  <div class="footer">Generated by <strong>Entra Auth Tracer</strong> v${e(version)} &mdash; ${e(Exporters.REPO_URL)}</div>
</body>
</html>`;
  }
}

export default Exporters;
