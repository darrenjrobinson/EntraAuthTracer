/**
 * Entra Auth Tracer - UI Logic
 * Handles the extension popup interface
 */

import EntraClaimsDecoder from './EntraClaimsDecoder.js';
import OAuthDecoder from './OAuthDecoder.js';
import SamlDecoder from './SamlDecoder.js';

class EntraAuthTracerUI {
  constructor() {
    this.currentRequests = [];
    this.selectedRequest = null;
    this.viewMode = 'list'; // 'list' | 'timeline'
    this.filters = {
      search: '',
      method: '',
      flow: '',
      status: ''
    };
    
    this.init();
  }

  /**
   * Initialize the UI
   */
  init() {
    this.bindEvents();
    this.loadData();
    this.startPeriodicUpdate();
    this.initSplitter();
    this.initPopupResize();

    // Reset the toolbar icon badge whenever the popup is opened
    chrome.runtime.sendMessage({ action: 'resetBadge' });
  }

  // ─── Copy helpers ────────────────────────────────────────────────────────────

  /**
   * Return HTML for a small clipboard copy button storing text in a data attribute.
   */
  makeCopyBtn(text, tooltip = 'Copy') {
    const safe = String(text)
      .replace(/&/g, '&amp;')
      .replace(/"/g, '&quot;');
    return `<button class="copy-btn" title="${tooltip}" data-copy="${safe}" aria-label="${tooltip}">` +
      `<svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">` +
      `<path d="M4 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2zm2-1a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V2a1 1 0 0 0-1-1zm-4 4a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1v-1h-1v1H2V6h1V5H2a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2v-1h-1v1a1 1 0 0 1-1 1H2a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h1z"/>` +
      `</svg></button>`;
  }

  /**
   * Copy text to the clipboard, briefly flash the button green on success.
   */
  async copyToClipboard(text, btn) {
    try {
      await navigator.clipboard.writeText(text);
      if (btn) {
        const orig = btn.title;
        btn.classList.add('copied');
        btn.title = 'Copied!';
        setTimeout(() => { btn.classList.remove('copied'); btn.title = orig; }, 1500);
      }
    } catch (err) {
      console.error('Copy failed:', err);
    }
  }

  /**
   * Update a section-header element to show the title h4 and a copy button.
   * @param {string} id   – element ID of the .section-header div
   * @param {string} title – heading text
   * @param {string} copyText – text placed in the copy button
   */
  setSectionHeader(id, title, copyText) {
    const el = document.getElementById(id);
    if (!el) return;
    el.innerHTML = `<h4>${this.escapeHtml(title)}</h4>${this.makeCopyBtn(copyText, 'Copy ' + title)}`;
  }

  // ─────────────────────────────────────────────────────────────────────────────

  /**
   * Bind event listeners
   */
  bindEvents() {
    // Global copy-button delegation (works for dynamically rendered copy buttons)
    document.getElementById('app').addEventListener('click', (e) => {
      const btn = e.target.closest('.copy-btn');
      if (!btn) return;
      e.stopPropagation();
      this.copyToClipboard(btn.dataset.copy || '', btn);
    });

    // View mode toggle (List ↔ Timeline)
    document.getElementById('viewListBtn').addEventListener('click', () => this.setViewMode('list'));
    document.getElementById('viewTimelineBtn').addEventListener('click', () => this.setViewMode('timeline'));

    // Search and filters
    document.getElementById('searchInput').addEventListener('input', (e) => {
      this.filters.search = e.target.value;
      this.filterAndRender();
    });

    document.getElementById('methodFilter').addEventListener('change', (e) => {
      this.filters.method = e.target.value;
      this.filterAndRender();
    });

    document.getElementById('flowFilter').addEventListener('change', (e) => {
      this.filters.flow = e.target.value;
      this.filterAndRender();
    });

    document.getElementById('statusFilter').addEventListener('change', (e) => {
      this.filters.status = e.target.value;
      this.filterAndRender();
    });

    // Control buttons
    document.getElementById('clearBtn').addEventListener('click', () => {
      this.clearData();
    });

    document.getElementById('exportBtn').addEventListener('click', (e) => {
      e.stopPropagation();
      this.toggleExportMenu();
    });

    document.getElementById('exportMenu').addEventListener('click', (e) => {
      const item = e.target.closest('.export-menu-item');
      if (!item) return;
      this.closeExportMenu();
      this.doExport(item.dataset.format);
    });

    // Close export menu when clicking anywhere else
    document.addEventListener('click', () => this.closeExportMenu());

    // Detail panel
    document.getElementById('closeDetailBtn').addEventListener('click', () => {
      this.closeDetailPanel();
    });

    // Tab navigation
    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        this.switchTab(e.target.dataset.tab);
      });
    });
  }

  /**
   * Load data from background script
   */
  async loadData() {
    try {
      const response = await new Promise((resolve) => {
        chrome.runtime.sendMessage({ action: 'getState' }, resolve);
      });

      if (response) {
        this.currentRequests = response.requests || [];
        // Re-apply any active filters rather than calling renderRequestList() directly,
        // so the user's current filter/search state is respected on every poll.
        this.filterAndRender();
        this.updateStatusBar();
      }
    } catch (error) {
      console.error('Failed to load data:', error);
    }
  }

  /**
   * Start periodic data updates
   */
  startPeriodicUpdate() {
    setInterval(() => {
      this.loadData();
    }, 1000); // Update every second
  }

  /**
   * Clear all data
   */
  async clearData() {
    try {
      await new Promise((resolve) => {
        chrome.runtime.sendMessage({ action: 'clearData' }, resolve);
      });
      
      this.currentRequests = [];
      this.selectedRequest = null;
      this.renderRequestList();
      this.closeDetailPanel();
      this.updateStatusBar();
    } catch (error) {
      console.error('Failed to clear data:', error);
    }
  }

  // ─── Export ──────────────────────────────────────────────────────────────────

  toggleExportMenu() {
    const menu = document.getElementById('exportMenu');
    const btn  = document.getElementById('exportBtn');
    const isOpen = menu.style.display !== 'none';
    menu.style.display = isOpen ? 'none' : 'block';
    btn.setAttribute('aria-expanded', String(!isOpen));
  }

  closeExportMenu() {
    const menu = document.getElementById('exportMenu');
    const btn  = document.getElementById('exportBtn');
    menu.style.display = 'none';
    btn.setAttribute('aria-expanded', 'false');
  }

  /**
   * Export captured requests in the requested format.
   * @param {'json'|'markdown'|'txt'} format
   */
  doExport(format) {
    const requests = this.currentRequests;
    if (!requests || requests.length === 0) {
      alert('No requests to export. Capture some authentication traffic first.');
      return;
    }

    const now = new Date();
    const ts  = now.toISOString().replace(/[:.]/g, '-').replace('T', '_').slice(0, 19);

    switch (format) {
      case 'json': {
        const content = this.buildJsonExport(requests, now);
        this.downloadFile(content, `entra-auth-trace_${ts}.json`, 'application/json');
        break;
      }
      case 'markdown': {
        const content = this.buildMarkdownExport(requests, now);
        this.downloadFile(content, `entra-auth-trace_${ts}.md`, 'text/markdown');
        break;
      }
      case 'txt': {
        const content = this.buildTxtExport(requests, now);
        this.downloadFile(content, `entra-auth-trace_${ts}.txt`, 'text/plain');
        break;
      }
      case 'pdf': {
        const content = this.buildPdfHtml(requests, now);
        this.downloadFile(content, `entra-auth-trace_${ts}.html`, 'text/html');
        break;
      }
    }
  }

  /**
   * Trigger a browser file download with the given content.
   */
  downloadFile(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType + ';charset=utf-8' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = filename;
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      URL.revokeObjectURL(url);
      document.body.removeChild(a);
    }, 1000);
  }

  // ─── JSON export ─────────────────────────────────────────────────────────────

  buildJsonExport(requests, now) {
    const meta = {
      generated_at: now.toISOString(),
      extension_version: '1.0.0',
      total_requests: requests.length,
      export_scope: 'complete_session'
    };

    const exportData = {
      export_metadata: meta,
      requests: requests.map(r => this.requestToJsonObj(r))
    };

    return JSON.stringify(exportData, null, 2);
  }

  requestToJsonObj(r) {
    const obj = {
      id: r.id,
      timestamp: new Date(r.timestamp).toISOString(),
      method: r.method,
      url: r.url,
      flow_type: r.flowType,
      status: r.status
    };
    if (r.statusCode) obj.status_code = r.statusCode;
    if (r.error)      obj.error       = r.error;
    if (r.requestHeaders && r.requestHeaders.length)  obj.request_headers  = r.requestHeaders;
    if (r.responseHeaders && r.responseHeaders.length) obj.response_headers = r.responseHeaders;
    if (r.requestBody)  obj.request_body  = r.requestBody;
    if (r.responseBody) obj.response_body = r.responseBody;
    if (r.oauthAnalysis)  obj.oauth_analysis  = r.oauthAnalysis;
    if (r.fido2Analysis)  obj.fido2_analysis  = r.fido2Analysis;
    if (r.samlAnalysis)   obj.saml_analysis   = r.samlAnalysis;
    return obj;
  }

  // ─── Markdown export ─────────────────────────────────────────────────────────

  buildMarkdownExport(requests, now) {
    const lines = [];
    lines.push('# Entra Auth Trace Report');
    lines.push('');
    lines.push(`**Generated:** ${now.toUTCString()}`);
    lines.push(`**Extension:** Entra Auth Tracer v1.0.0`);
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
      lines.push(`| **Timestamp** | ${new Date(r.timestamp).toISOString()} |`);
      lines.push(`| **Method** | ${r.method} |`);
      lines.push(`| **URL** | \`${r.url}\` |`);
      lines.push(`| **Flow Type** | ${r.flowType} |`);
      lines.push(`| **Status** | ${r.status}${r.statusCode ? ' (' + r.statusCode + ')' : ''} |`);
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
        if (a.pkce)       lines.push(`| **PKCE** | ${a.pkce.codeChallengeMethod} |`);
        if (a.scopeLabels && a.scopeLabels.length) {
          lines.push(`| **Scopes** | ${a.scopeLabels.map(s => s.scope).join(', ')} |`);
        }
        if (a.warnings && a.warnings.length) {
          lines.push('');
          lines.push('**Security Warnings:**');
          lines.push('');
          for (const w of a.warnings) {
            lines.push(`- [${w.severity.toUpperCase()}] ${w.message}`);
          }
        }
        lines.push('');
      }

      // FIDO2 analysis
      if (r.fido2Analysis && !r.fido2Analysis.error) {
        const f = r.fido2Analysis;
        lines.push('#### FIDO2 Analysis');
        lines.push('');
        if (f.clientDataJSON) {
          const cd = f.clientDataJSON;
          lines.push('| Field | Value |');
          lines.push('|---|---|');
          lines.push(`| **Type** | ${cd.type} |`);
          lines.push(`| **Origin** | ${cd.origin} |`);
          lines.push(`| **Cross Origin** | ${cd.crossOrigin ? 'Yes' : 'No'} |`);
          lines.push('');
        }
      }

      lines.push('---');
      lines.push('');
    });

    lines.push('');
    lines.push('*Generated by [Entra Auth Tracer](https://github.com/DarrenRobinson/EntraAuthTracer)*');
    return lines.join('\n');
  }

  // ─── Plain text export ───────────────────────────────────────────────────────

  buildTxtExport(requests, now) {
    const lines = [];
    const hr = '='.repeat(72);
    const hr2 = '-'.repeat(72);

    lines.push('ENTRA AUTH TRACE REPORT');
    lines.push(hr);
    lines.push(`Generated : ${now.toUTCString()}`);
    lines.push(`Extension : Entra Auth Tracer v1.0.0`);
    lines.push(`Requests  : ${requests.length}`);
    lines.push(hr);
    lines.push('');

    requests.forEach((r, i) => {
      lines.push(`REQUEST ${i + 1} of ${requests.length}`);
      lines.push(hr2);
      lines.push(`Time      : ${new Date(r.timestamp).toISOString()}`);
      lines.push(`Method    : ${r.method}`);
      lines.push(`URL       : ${r.url}`);
      lines.push(`Flow      : ${r.flowType}`);
      lines.push(`Status    : ${r.status}${r.statusCode ? ' (' + r.statusCode + ')' : ''}`);
      if (r.error) lines.push(`Error     : ${r.error}`);

      if (r.requestHeaders && r.requestHeaders.length) {
        lines.push('');
        lines.push('Request Headers:');
        for (const h of r.requestHeaders) {
          lines.push(`  ${h.name}: ${h.value}`);
        }
      }

      if (r.requestBody) {
        lines.push('');
        lines.push('Request Body:');
        if (typeof r.requestBody === 'string') {
          lines.push('  ' + r.requestBody.substring(0, 2000));
        } else if (r.requestBody.formData) {
          for (const [k, v] of Object.entries(r.requestBody.formData)) {
            lines.push(`  ${k}=${Array.isArray(v) ? v[0] : v}`);
          }
        } else {
          lines.push('  ' + JSON.stringify(r.requestBody).substring(0, 2000));
        }
      }

      if (r.responseHeaders && r.responseHeaders.length) {
        lines.push('');
        lines.push('Response Headers:');
        for (const h of r.responseHeaders) {
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
        if (a.pkce)        lines.push(`  PKCE        : ${a.pkce.codeChallengeMethod}`);
        if (a.scopeLabels && a.scopeLabels.length) {
          lines.push(`  Scopes      : ${a.scopeLabels.map(s => s.scope).join(' ')}`);
        }
        if (a.warnings && a.warnings.length) {
          lines.push('  Warnings:');
          for (const w of a.warnings) lines.push(`    [${w.severity.toUpperCase()}] ${w.message}`);
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
      }

      lines.push('');
    });

    lines.push(hr);
    lines.push('Generated by Entra Auth Tracer');
    return lines.join('\n');
  }

  // ─── PDF / Print HTML export ─────────────────────────────────────────────────

  /**
   * Build a print-optimised HTML report.
   * Saved as .html — user opens the file and presses Ctrl+P to save as PDF.
   */
  buildPdfHtml(requests, now) {
    const e = (v) => String(v == null ? '' : v)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const ts = now.toUTCString();

    // Flow statistics
    const flowCounts = {};
    const statusCounts = { completed: 0, error: 0, pending: 0 };
    for (const r of requests) {
      const cat = this.getFlowTypeCategory(r.flowType);
      flowCounts[cat] = (flowCounts[cat] || 0) + 1;
      if (r.status in statusCounts) statusCounts[r.status]++;
    }

    const summaryRows = Object.entries(flowCounts)
      .map(([flow, count]) => `<tr><td>${e(flow.toUpperCase())}</td><td>${count}</td></tr>`)
      .join('');

    const requestSections = requests.map((r, i) => {
      let pathname = r.url || '';
      let hostname = '';
      try { const u = new URL(r.url); pathname = u.pathname; hostname = u.hostname; } catch { /* keep */ }

      let sec = `
        <div class="req-section">
          <h3>Request ${i + 1}: <span class="method">${e(r.method || 'GET')}</span> ${e(pathname)}</h3>
          <p class="req-host">${e(hostname)}</p>
          <table>
            <tr><td class="lbl">Timestamp</td><td>${e(new Date(r.timestamp).toISOString())}</td></tr>
            <tr><td class="lbl">URL</td><td class="url-cell">${e(r.url)}</td></tr>
            <tr><td class="lbl">Flow Type</td><td>${e(r.flowType)}</td></tr>
            <tr><td class="lbl">Status</td><td class="${r.status === 'completed' ? 'ok' : r.status === 'error' ? 'err' : ''}">${e(r.status)}${r.statusCode ? ' (' + r.statusCode + ')' : ''}</td></tr>
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
            ${a.pkce       ? `<tr><td class="lbl">PKCE</td><td>${e(a.pkce.codeChallengeMethod)}${a.pkce.isS256 ? ' ✓ S256' : ' ⚠ non-S256'}</td></tr>` : ''}
            ${a.scopes && a.scopes.length ? `<tr><td class="lbl">Scopes</td><td>${e(a.scopes.join(' '))}</td></tr>` : ''}
            ${a.warnings && a.warnings.length ? `<tr><td class="lbl">Warnings</td><td class="warn">${a.warnings.map(w => e('[' + w.severity.toUpperCase() + '] ' + w.message)).join('<br>')}</td></tr>` : ''}
          </table>`;
      }

      if (r.fido2Analysis && !r.fido2Analysis.error && r.fido2Analysis.clientDataJSON) {
        const cd = r.fido2Analysis.clientDataJSON;
        sec += `
          <h4>FIDO2 Analysis</h4>
          <table>
            <tr><td class="lbl">Type</td><td>${e(cd.type)}</td></tr>
            <tr><td class="lbl">Origin</td><td>${e(cd.origin)}</td></tr>
            <tr><td class="lbl">Cross Origin</td><td>${cd.crossOrigin ? 'Yes' : 'No'}</td></tr>
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
  <p class="meta">Generated: <strong>${e(ts)}</strong> &nbsp;&middot;&nbsp; Entra Auth Tracer v1.0.0 &nbsp;&middot;&nbsp; <strong>${requests.length}</strong> request${requests.length !== 1 ? 's' : ''}</p>

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

  <div class="footer">Generated by <strong>Entra Auth Tracer</strong> &mdash; Microsoft Entra authentication inspector</div>
</body>
</html>`;
  }

  // ─────────────────────────────────────────────────────────────────────────────

  /**
   * Apply current filters and render.  Used by both loadData and filter change handlers.
   */
  filterAndRender() {
    const hasFilters = this.filters.search || this.filters.method || this.filters.flow || this.filters.status;
    const requests = hasFilters ? this._applyFilters(this.currentRequests) : this.currentRequests;
    if (this.viewMode === 'timeline') {
      this.renderTimeline(requests);
    } else {
      this.renderRequestList(requests);
    }
  }

  /**
   * Return a filtered subset of requests matching all active filters.
   */
  _applyFilters(requests) {
    return requests.filter(req => {
      if (this.filters.search && !req.url.toLowerCase().includes(this.filters.search.toLowerCase())) return false;
      if (this.filters.method && req.method !== this.filters.method) return false;
      if (this.filters.flow) {
        if (this.getFlowTypeCategory(req.flowType) !== this.filters.flow) return false;
      }
      if (this.filters.status && req.status !== this.filters.status) return false;
      return true;
    });
  }

  /**
   * Filter requests based on current filters (kept for back-compat callers)
   */
  filterRequests() {
    this.filterAndRender();
  }

  /**
   * Get flow type category for filtering
   */
  getFlowTypeCategory(flowType) {
    if (!flowType) return 'other';
    if (flowType.startsWith('fido2_')) return 'fido2';
    if (flowType.startsWith('device_code')) return 'device_code';
    if (flowType === 'client_credentials' || flowType === 'refresh_token' ||
        flowType.includes('oauth') || flowType.includes('pkce') || flowType.includes('authcode')) return 'oauth';
    if (flowType === 'saml' || flowType === 'wsfed') return 'saml';
    return 'other';
  }

  // ─── View mode ────────────────────────────────────────────────────────────────

  /**
   * Switch between 'list' and 'timeline' view modes.
   */
  setViewMode(mode) {
    this.viewMode = mode;

    const listBtn = document.getElementById('viewListBtn');
    const timelineBtn = document.getElementById('viewTimelineBtn');
    const listHeader = document.querySelector('.request-list-header');

    listBtn.classList.toggle('active', mode === 'list');
    listBtn.setAttribute('aria-pressed', String(mode === 'list'));
    timelineBtn.classList.toggle('active', mode === 'timeline');
    timelineBtn.setAttribute('aria-pressed', String(mode === 'timeline'));

    if (listHeader) listHeader.style.display = mode === 'timeline' ? 'none' : '';

    this.filterAndRender();
  }

  // ─── Timeline view ────────────────────────────────────────────────────────────

  /**
   * Group requests into correlated flow groups for the timeline view.
   * Returns an array of { type, key, label, requests[] } objects.
   */
  computeFlowGroups(requests) {
    const groups = [];
    const assignedIds = new Set();

    // 1. Device Code correlation groups (keyed by deviceCodeCorrelationKey)
    const dcMap = new Map();
    for (const r of requests) {
      if (r.deviceCodeCorrelationKey) {
        if (!dcMap.has(r.deviceCodeCorrelationKey)) dcMap.set(r.deviceCodeCorrelationKey, []);
        dcMap.get(r.deviceCodeCorrelationKey).push(r);
        assignedIds.add(r.id);
      }
    }
    for (const [key, reqs] of dcMap) {
      const sorted = reqs.sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));
      const clientId = (sorted[0].oauthAnalysis && sorted[0].oauthAnalysis.clientId)
        ? sorted[0].oauthAnalysis.clientId.substring(0, 8) + '…'
        : key.substring(0, 8) + '…';
      groups.push({ type: 'device_code', key, label: `Device Code — ${clientId}`, requests: sorted });
    }

    // 2. OAuth flows sharing the same clientId within a 60-second session window
    const oauthReqs = requests.filter(r =>
      !assignedIds.has(r.id) && r.oauthAnalysis && !r.oauthAnalysis.error && r.oauthAnalysis.clientId
    );
    const byClient = new Map();
    for (const r of oauthReqs) {
      const cid = r.oauthAnalysis.clientId;
      if (!byClient.has(cid)) byClient.set(cid, []);
      byClient.get(cid).push(r);
    }
    for (const [clientId, reqs] of byClient) {
      const sorted = reqs.sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));
      // Split into sessions: any gap > 60s starts a new session
      let sessionStart = null;
      let session = [];
      const flushSession = () => {
        if (session.length === 0) return;
        const lbl = session.length === 1
          ? (session[0].oauthAnalysis.label || 'OAuth Request')
          : `OAuth Flow — ${session[0].oauthAnalysis.label || clientId.substring(0, 8) + '…'}`;
        groups.push({ type: 'oauth', key: `oauth_${clientId}_${sessionStart}`, label: lbl, requests: session });
        session = [];
        sessionStart = null;
      };
      for (const r of sorted) {
        if (sessionStart === null || (r.timestamp - sessionStart) <= 60000) {
          session.push(r);
          assignedIds.add(r.id);
          if (sessionStart === null) sessionStart = r.timestamp;
        } else {
          flushSession();
          session = [r];
          sessionStart = r.timestamp;
          assignedIds.add(r.id);
        }
      }
      flushSession();
    }

    // 3. Remaining requests as standalone (single-item) entries, preserving time order
    const remaining = requests.filter(r => !assignedIds.has(r.id));
    for (const r of remaining) {
      groups.push({ type: 'standalone', key: r.id, label: null, requests: [r] });
    }

    // Sort groups by the timestamp of their first request
    groups.sort((a, b) => ((a.requests[0] && a.requests[0].timestamp) || 0) - ((b.requests[0] && b.requests[0].timestamp) || 0));

    return groups;
  }

  /**
   * Render a single flow group (multi-request or standalone) in timeline view.
   */
  renderFlowGroup(group) {
    const e = (v) => this.escapeHtml(v);

    if (group.requests.length === 1 && group.type === 'standalone') {
      // Standalone single-item: render like a plain list item but within timeline container
      return `<div class="timeline-standalone">${this.renderRequestItem(group.requests[0])}</div>`;
    }

    const flowBadgeClass = `flow-${group.type === 'device_code' ? 'device_code' : group.type === 'oauth' ? 'oauth' : group.type}`;
    const flowLabel = group.type === 'device_code' ? 'DEVICE CODE' : group.type.toUpperCase();
    const startTime = group.requests[0] ? new Date(group.requests[0].timestamp || Date.now()).toLocaleTimeString() : '';
    const durationMs = group.requests.length > 1
      ? (group.requests[group.requests.length - 1].timestamp || 0) - (group.requests[0].timestamp || 0)
      : null;
    const durationStr = durationMs !== null ? ` · ${(durationMs / 1000).toFixed(1)}s` : '';

    let html = `
      <div class="flow-group">
        <div class="flow-group-header">
          <span class="flow-badge ${flowBadgeClass}">${flowLabel}</span>
          <span class="flow-group-title">${e(group.label || '')}</span>
          <span class="flow-group-meta">${startTime}${durationStr} · ${group.requests.length} req</span>
        </div>`;

    group.requests.forEach((r, idx) => {
      const time = new Date(r.timestamp || Date.now()).toLocaleTimeString();
      const status = r.status || 'pending';
      const statusIcon = status === 'completed' ? '✓' : status === 'error' ? '✗' : '⧖';
      let shortUrl = r.url || '';
      try { shortUrl = new URL(r.url).pathname; } catch { /* keep */ }
      const stepDesc = this._getFlowStepDesc(r, idx);
      const selectedClass = this.selectedRequest && this.selectedRequest.id === r.id ? ' selected' : '';

      html += `
        <div class="flow-group-item${selectedClass}" data-request-id="${e(r.id)}">
          <span class="fgi-step">${idx + 1}</span>
          <span class="fgi-time">${time}</span>
          <span class="fgi-method">${e(r.method || 'GET')}</span>
          <span class="fgi-url" title="${e(r.url)}">${e(shortUrl)}</span>
          <span class="fgi-status status-${status}">${statusIcon}</span>
          ${stepDesc ? `<span class="fgi-desc">${e(stepDesc)}</span>` : ''}
        </div>`;
    });

    html += '</div>';
    return html;
  }

  /**
   * Return a short step description for a request within a flow group.
   */
  _getFlowStepDesc(r, idx) {
    if (r.flowType === 'device_code_initiation') return 'Initiation';
    if (r.flowType && r.flowType.startsWith('device_code') && r.status === 'completed') return 'Token issued';
    if (r.flowType && r.flowType.startsWith('device_code')) return `Poll #${idx}`;
    if (r.oauthAnalysis && r.oauthAnalysis.label) return r.oauthAnalysis.label;
    return '';
  }

  /**
   * Render all requests in Timeline view: grouped flow sections then standalone items.
   */
  renderTimeline(requests = this.currentRequests) {
    const container = document.getElementById('requestList');
    if (!container) return;

    if (!requests || requests.length === 0) {
      container.innerHTML = `
        <div class="no-requests">
          <p>No authentication requests captured yet.</p>
          <p class="hint">Navigate to a Microsoft Entra login or perform SAML authentication to start tracing.</p>
        </div>`;
      return;
    }

    const groups = this.computeFlowGroups(requests);
    let html = '<div class="timeline-view">';
    for (const group of groups) html += this.renderFlowGroup(group);
    html += '</div>';
    container.innerHTML = html;

    // Bind click events — both flow-group items and fallback standalone list items
    container.querySelectorAll('[data-request-id]').forEach(el => {
      el.addEventListener('click', (evt) => {
        // Prevent the copy-btn inside from triggering a request selection
        if (evt.target.closest('.copy-btn')) return;
        const found = requests.find(r => r.id === el.dataset.requestId);
        if (found) this.selectRequest(found);
      });
    });
  }

  // ─── Flow correlation ────────────────────────────────────────────────────────

  /**
   * Return requests correlated with the given request (same device code session or
   * same OAuth clientId within a 60-second window), sorted chronologically.
   * The request itself is NOT included in the returned array.
   */
  findRelatedRequests(request) {
    const results = [];
    // Device code
    if (request.deviceCodeCorrelationKey) {
      this.currentRequests
        .filter(r => r.id !== request.id && r.deviceCodeCorrelationKey === request.deviceCodeCorrelationKey)
        .forEach(r => results.push(r));
    } else if (request.oauthAnalysis && request.oauthAnalysis.clientId) {
      // OAuth clientId + 60-second window
      const cid = request.oauthAnalysis.clientId;
      const ts = request.timestamp || 0;
      this.currentRequests
        .filter(r =>
          r.id !== request.id &&
          r.oauthAnalysis && r.oauthAnalysis.clientId === cid &&
          Math.abs((r.timestamp || 0) - ts) <= 60000
        )
        .forEach(r => results.push(r));
    }
    return results.sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));
  }

  /**
   * After selecting a request, apply .correlated-highlight to other list items
   * that are part of the same flow.
   */
  highlightCorrelatedRequests(request) {
    // Reset any previous highlights
    document.querySelectorAll('.correlated-highlight').forEach(el => el.classList.remove('correlated-highlight'));

    const related = this.findRelatedRequests(request);
    if (related.length === 0) return;

    related.forEach(r => {
      const el = document.querySelector(`[data-request-id="${CSS.escape(r.id)}"]`);
      if (el && !el.classList.contains('selected')) el.classList.add('correlated-highlight');
    });
  }

  /**
   * Update the Related Requests panel in the detail header.
   */
  updateRelatedRequestsPanel(request) {
    const panel = document.getElementById('relatedRequestsPanel');
    const list  = document.getElementById('relatedRequestsList');
    if (!panel || !list) return;

    const related = this.findRelatedRequests(request);
    const allInFlow = [request, ...related].sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));

    if (allInFlow.length <= 1) {
      panel.style.display = 'none';
      return;
    }

    panel.style.display = 'flex';
    list.innerHTML = allInFlow.map((r, idx) => {
      const isCurrent = r.id === request.id;
      const stepDesc = this._getFlowStepDesc(r, idx) || r.flowType || '';
      const statusIcon = r.status === 'completed' ? '✓' : r.status === 'error' ? '✗' : '⧖';
      return `<span class="related-item${isCurrent ? ' related-current' : ''}" data-request-id="${this.escapeHtml(r.id)}" title="${this.escapeHtml(r.url)}">
        ${statusIcon} ${idx + 1}${stepDesc ? ': ' + this.escapeHtml(stepDesc) : ''}
      </span>`;
    }).join('');

    // Clicking a related item navigates to that request
    list.querySelectorAll('.related-item:not(.related-current)').forEach(el => {
      el.addEventListener('click', () => {
        const found = this.currentRequests.find(r => r.id === el.dataset.requestId);
        if (found) this.selectRequest(found);
      });
    });
  }
  renderRequestList(requests = this.currentRequests) {
    const container = document.getElementById('requestList');
    if (!container) return;

    if (!requests || requests.length === 0) {
      container.innerHTML = `
        <div class="no-requests">
          <p>No authentication requests captured yet.</p>
          <p class="hint">Navigate to a Microsoft Entra login or perform SAML authentication to start tracing.</p>
        </div>
      `;
      return;
    }

    const items = [];
    for (const req of requests) {
      try {
        items.push(this.renderRequestItem(req));
      } catch (err) {
        console.error('renderRequestItem failed:', err, req);
        items.push(`<div class="request-item error-item" title="${err.message}">&#9888; Error rendering request: ${(req && req.url) ? req.url.substring(0, 80) : '(unknown)'}</div>`);
      }
    }
    container.innerHTML = items.join('');

    // Bind click events
    container.querySelectorAll('.request-item').forEach(item => {
      item.addEventListener('click', () => {
        const requestId = item.dataset.requestId;
        if (!requestId) return;
        const request = requests.find(r => r.id === requestId);
        if (request) {
          this.selectRequest(request);
        }
      });
    });
  }

  /**
   * Render a single request item
   */
  renderRequestItem(request) {
    const time = new Date(request.timestamp || Date.now()).toLocaleTimeString();
    let hostname = '(unknown)';
    let shortUrl = request.url || '';
    try {
      const parsed = new URL(request.url);
      hostname = parsed.hostname;
      shortUrl = parsed.pathname + (parsed.search ? parsed.search.substring(0, 50) : '');
    } catch { /* keep defaults */ }
    const method = request.method || 'GET';
    const flowCategory = this.getFlowTypeCategory(request.flowType);
    const status = request.status || 'pending';

    return `
      <div class="request-item" data-request-id="${request.id}">
        <span class="col-timestamp">${time}</span>
        <span class="col-method">${method}</span>
        <span class="col-url" title="${this.escapeHtml(request.url || '')}">
          <span class="url-text">${this.escapeHtml(shortUrl || hostname)}</span>
          ${this.makeCopyBtn(request.url || '', 'Copy URL')}
        </span>
        <span class="col-status status-${status}">${this.formatStatus(status)}</span>
        <span class="col-flow">
          <span class="flow-badge flow-${flowCategory}">${flowCategory.toUpperCase()}</span>
        </span>
      </div>
    `;
  }

  /**
   * Format status for display
   */
  formatStatus(status) {
    switch (status) {
      case 'completed': return '✓ Success';
      case 'error': return '✗ Error';
      case 'pending': return '⧖ Pending';
      default: return status;
    }
  }

  /**
   * Select a request and show details
   */
  selectRequest(request) {
    this.selectedRequest = request;
    
    // Update selection in list
    document.querySelectorAll('.request-item, .flow-group-item').forEach(item => {
      item.classList.remove('selected');
      if (item.dataset.requestId === request.id) {
        item.classList.add('selected');
      }
    });

    // Highlight correlated requests
    this.highlightCorrelatedRequests(request);

    // Show detail panel
    this.showDetailPanel(request);
  }

  /**
   * Show the detail panel with request information
   */
  showDetailPanel(request) {
    const panel = document.getElementById('detailPanel');
    panel.style.display = 'flex';

    // Show the pane splitter
    const splitter = document.getElementById('paneSplitter');
    if (splitter) splitter.style.display = 'flex';

    // Update title
    const url = new URL(request.url);
    document.getElementById('detailTitle').textContent = `${request.method} ${url.pathname}`;

    // Wire the header copy button to copy the full URL
    const copyUrlBtn = document.getElementById('copyDetailUrlBtn');
    if (copyUrlBtn) {
      copyUrlBtn.dataset.copy = request.url;
      copyUrlBtn.style.display = 'inline-flex';
    }

    // Determine which tabs to show
    this.updateTabVisibility(request);

    // Update related requests panel
    this.updateRelatedRequestsPanel(request);

    // Populate tab content
    this.populateHttpTab(request);
    this.populateParametersTab(request);
    this.populateSamlTab(request);
    this.populateEntraTab(request);
  }

  /**
   * Update tab visibility based on request type
   */
  updateTabVisibility(request) {
    const entraTab = document.querySelector('[data-tab="entra"]');
    const samlTab = document.querySelector('[data-tab="saml"]');

    // Show Entra tab for Entra-related requests
    const isEntraRequest = this.isEntraRequest(request);
    entraTab.style.display = isEntraRequest ? 'block' : 'none';

    // Show SAML tab for SAML requests (also catches POST-binding SAMLResponse to any SP ACS URL)
    const isSamlRequest = request.flowType === 'saml' || request.flowType === 'wsfed'
      || SamlDecoder.extract(request) !== null;
    samlTab.style.display = isSamlRequest ? 'block' : 'none';

    // Check for CAE badge
    const caeBadge = entraTab.querySelector('.cae-badge');
    if (caeBadge && isEntraRequest) {
      const hasCAE = this.checkForCAE(request);
      caeBadge.style.display = hasCAE ? 'inline' : 'none';
    }
  }

  /**
   * Check if request is Entra-related
   */
  isEntraRequest(request) {
    const url = new URL(request.url);
    const entraHosts = ['login.microsoftonline.com', 'sts.windows.net', 'login.live.com'];
    if (entraHosts.includes(url.hostname)) return true;
    // Also show Entra tab if this request has oauth analysis (client_assertion JWT available)
    if (request.oauthAnalysis && request.oauthAnalysis.clientAssertion) return true;
    return false;
  }

  /**
   * Check for CAE capability in request by attempting to decode an available JWT.
   */
  checkForCAE(request) {
    const jwt = this.extractJwtFromRequest(request) ||
                this.extractJwtFromRequest(request, 'id_token_hint');
    if (!jwt) return false;
    try {
      const decoded = EntraClaimsDecoder.decodeEntraToken(jwt);
      return decoded && decoded.caeEnabled === true;
    } catch {
      return false;
    }
  }

  /**
   * Populate HTTP tab
   */
  populateHttpTab(request) {
    const requestDetails = document.getElementById('requestDetails');
    const responseDetails = document.getElementById('responseDetails');

    // Request details
    const requestCopyText = [
      `URL: ${request.url}`,
      `Method: ${request.method}`,
      `Timestamp: ${new Date(request.timestamp).toISOString()}`,
      `Flow Type: ${request.flowType}`,
    ].join('\n');

    this.setSectionHeader('requestSectionHeader', 'Request', requestCopyText);

    requestDetails.innerHTML = `
      <div class="label">URL:</div>
      <div class="value">${this.escapeHtml(request.url)}</div>
      <div class="label">Method:</div>
      <div class="value">${this.escapeHtml(request.method)}</div>
      <div class="label">Timestamp:</div>
      <div class="value">${new Date(request.timestamp).toISOString()}</div>
      <div class="label">Flow Type:</div>
      <div class="value">${this.escapeHtml(request.flowType)}</div>
    `;

    // Response details
    let responseCopyText;
    if (request.statusCode) {
      responseCopyText = `Status: ${request.statusCode} ${request.status}` +
        (request.error ? `\nError: ${request.error}` : '');
      responseDetails.innerHTML = `
        <div class="label">Status:</div>
        <div class="value">${request.statusCode} ${this.escapeHtml(request.status)}</div>
        ${request.error ? `
          <div class="label">Error:</div>
          <div class="value">${this.escapeHtml(request.error)}</div>
        ` : ''}
      `;
    } else {
      responseCopyText = 'Response pending...';
      responseDetails.innerHTML = '<div class="value">Response pending...</div>';
    }

    this.setSectionHeader('responseSectionHeader', 'Response', responseCopyText);

    // Show FIDO2 section if applicable
    this.populateFido2Section(request);

    // Show OAuth section if applicable
    this.populateOAuthSection(request);
  }

  /**
   * Determine whether this request is an OAuth flow we can analyse.
   */
  isOAuthRequest(request) {
    if (request.oauthAnalysis) return true;
    const flowType = request.flowType || '';
    return flowType.includes('pkce') || flowType.includes('oauth') ||
      flowType.includes('authcode') || flowType === 'client_credentials' ||
      flowType === 'refresh_token' || flowType.startsWith('device_code');
  }

  /**
   * Populate the OAuth 2.1 section in the HTTP tab.
   */
  populateOAuthSection(request) {
    const section  = document.getElementById('oauthSection');
    const details  = document.getElementById('oauthDetails');
    if (!section || !details) return;

    if (!this.isOAuthRequest(request)) {
      section.style.display = 'none';
      return;
    }

    section.style.display = 'block';
    const analysis = request.oauthAnalysis;

    if (!analysis) {
      this.setSectionHeader('oauthSectionHeader', 'OAuth 2.1 Flow Analysis', '');
      details.innerHTML = '<div class="empty-state">No OAuth analysis available for this request.</div>';
      return;
    }
    if (analysis.error) {
      this.setSectionHeader('oauthSectionHeader', 'OAuth 2.1 Flow Analysis', '');
      details.innerHTML = `<div class="error">⚠ ${this.escapeHtml(analysis.error)}</div>`;
      return;
    }

    this.setSectionHeader('oauthSectionHeader', 'OAuth 2.1 Flow Analysis', this.buildOAuthCopyText(analysis));
    details.innerHTML = this.renderOAuthDetails(analysis, request);
  }

  /**
   * Build a plain-text summary of an OAuth analysis for clipboard copy.
   */
  buildOAuthCopyText(analysis) {
    const lines = [];
    if (analysis.label)            lines.push(`Grant Type: ${analysis.label}`);
    if (analysis.clientId)         lines.push(`Client ID: ${analysis.clientId}`);
    if (analysis.responseType)     lines.push(`Response Type: ${analysis.responseType}`);
    if (analysis.responseMode)     lines.push(`Response Mode: ${analysis.responseMode}`);
    if (analysis.redirectUri)      lines.push(`Redirect URI: ${analysis.redirectUri}`);
    if (analysis.state)            lines.push(`State: ${analysis.state}`);
    if (analysis.nonce)            lines.push(`Nonce: ${analysis.nonce}`);
    if (analysis.prompt)           lines.push(`Prompt: ${analysis.prompt}`);
    if (analysis.loginHint)        lines.push(`Login Hint: ${analysis.loginHint}`);
    if (analysis.domainHint)       lines.push(`Domain Hint: ${analysis.domainHint}`);
    if (analysis.authMethod)       lines.push(`Auth Method: ${analysis.authMethodLabel || analysis.authMethod}`);
    if (analysis.deviceCodePrefix) lines.push(`Device Code: ${analysis.deviceCodePrefix}`);
    if (analysis.pkce) {
      lines.push(`PKCE Method: ${analysis.pkce.codeChallengeMethod}`);
      if (analysis.pkce.codeChallenge) lines.push(`PKCE Challenge: ${analysis.pkce.codeChallenge}`);
    }
    if (analysis.pkceVerifier?.verifier) {
      lines.push(`PKCE Verifier: ${analysis.pkceVerifier.verifier}`);
    }
    if (analysis.scopeLabels && analysis.scopeLabels.length) {
      lines.push(`Scopes: ${analysis.scopeLabels.map(s => s.scope).join(' ')}`);
    }
    if (analysis.warnings && analysis.warnings.length) {
      lines.push('');
      lines.push('Warnings:');
      analysis.warnings.forEach(w => lines.push(`  [${w.severity.toUpperCase()}] ${w.message}`));
    }
    return lines.join('\n');
  }

  /**
   * Render all OAuth analysis into HTML.
   */
  renderOAuthDetails(analysis, _request) {
    const e = (v) => this.escapeHtml(v == null ? '' : String(v));
    let html = '';

    // ── Grant type header ──────────────────────────────────────────────────
    const grantInfo = OAuthDecoder.GRANT_TYPES[analysis.grantType] || {};
    const isDeprecated = grantInfo.oauth21 === false;
    html += `
      <div class="oauth-grant-header">
        <div class="oauth-grant-badge ${isDeprecated ? 'oauth-grant-deprecated' : 'oauth-grant-standard'}">
          ${e(analysis.label)}
        </div>
        ${isDeprecated ? '<span class="oauth-deprecated-notice">⚠ Deprecated in OAuth 2.1</span>' : ''}
      </div>
    `;

    if (grantInfo.description) {
      html += `<div class="oauth-description">${e(grantInfo.description)}</div>`;
    }

    // ── Metadata grid ──────────────────────────────────────────────────────
    html += '<div class="details-grid">';
    if (analysis.clientId)  html += `<div class="label">Client ID:</div><div class="value mono">${e(analysis.clientId)}</div>`;
    if (analysis.responseType) html += `<div class="label">Response Type:</div><div class="value">${e(analysis.responseType)}</div>`;
    if (analysis.redirectUri)  html += `<div class="label">Redirect URI:</div><div class="value">${e(analysis.redirectUri)}</div>`;
    if (analysis.responseMode) html += `<div class="label">Response Mode:</div><div class="value">${e(analysis.responseMode)}</div>`;
    if (analysis.state)        html += `<div class="label">State:</div><div class="value mono">${e(analysis.state.substring(0, 40))}${analysis.state.length > 40 ? '…' : ''}</div>`;
    if (analysis.nonce)        html += `<div class="label">Nonce:</div><div class="value mono">${e(analysis.nonce.substring(0, 40))}${analysis.nonce.length > 40 ? '…' : ''}</div>`;
    if (analysis.prompt)       html += `<div class="label">Prompt:</div><div class="value">${e(analysis.prompt)}</div>`;
    if (analysis.loginHint)    html += `<div class="label">Login Hint:</div><div class="value">${e(analysis.loginHint)}</div>`;
    if (analysis.domainHint)   html += `<div class="label">Domain Hint:</div><div class="value">${e(analysis.domainHint)}</div>`;
    if (analysis.authMethod)   html += `<div class="label">Auth Method:</div><div class="value">${e(analysis.authMethodLabel || analysis.authMethod)}</div>`;
    if (analysis.deviceCodePrefix) html += `<div class="label">Device Code:</div><div class="value mono">${e(analysis.deviceCodePrefix)}</div>`;
    html += '</div>';

    // ── PKCE details ──────────────────────────────────────────────────────
    if (analysis.pkce) {
      html += this.renderPKCEDetails(analysis.pkce);
    }
    if (analysis.pkceVerifier) {
      html += this.renderPKCEVerifierDetails(analysis.pkceVerifier);
    }

    // ── Client assertion JWT ───────────────────────────────────────────────
    if (analysis.clientAssertion && !analysis.clientAssertion.error) {
      html += this.renderClientAssertionDetails(analysis.clientAssertion);
    }

    // ── Scopes ────────────────────────────────────────────────────────────
    if (analysis.scopeLabels && analysis.scopeLabels.length > 0) {
      html += this.renderScopeList(analysis.scopeLabels);
    }

    // ── Security warnings ────────────────────────────────────────────────
    if (analysis.warnings && analysis.warnings.length > 0) {
      html += this.renderOAuthWarnings(analysis.warnings);
    }

    return html;
  }

  /**
   * Render PKCE code_challenge section.
   */
  renderPKCEDetails(pkce) {
    const e = (v) => this.escapeHtml(v == null ? '' : String(v));
    const statusClass = pkce.isS256 ? 'pkce-compliant' : 'pkce-warning';
    const statusIcon  = pkce.isS256 ? '✓' : '⚠';
    return `
      <div class="oauth-section">
        <h5>🔐 PKCE — Code Challenge</h5>
        <div class="pkce-status ${statusClass}">${statusIcon} ${e(pkce.recommendation)}</div>
        <div class="details-grid">
          <div class="label">Method:</div>
          <div class="value">${e(pkce.codeChallengeMethod)}</div>
          <div class="label">Challenge (${pkce.challengeLength} chars):</div>
          <div class="value mono">${e(pkce.codeChallenge ? pkce.codeChallenge.substring(0, 50) + (pkce.codeChallenge.length > 50 ? '…' : '') : '')}</div>
        </div>
      </div>
    `;
  }

  /**
   * Render PKCE code_verifier section.
   */
  renderPKCEVerifierDetails(verifier) {
    const e = (v) => this.escapeHtml(v == null ? '' : String(v));
    if (verifier.error) {
      return `<div class="oauth-section"><h5>🔐 PKCE — Code Verifier</h5><div class="error">${e(verifier.error)}</div></div>`;
    }
    const statusClass = verifier.isCompliant ? 'pkce-compliant' : 'pkce-error';
    const statusIcon  = verifier.isCompliant ? '✓' : '✗';
    return `
      <div class="oauth-section">
        <h5>🔐 PKCE — Code Verifier</h5>
        <div class="pkce-status ${statusClass}">${statusIcon} ${e(verifier.recommendation)}</div>
        <div class="details-grid">
          <div class="label">Length:</div>
          <div class="value">${verifier.length} chars ${verifier.isCompliant ? '✓ RFC 7636' : '✗ out-of-range'}</div>
          <div class="label">Entropy:</div>
          <div class="value">${verifier.isHighEntropy ? 'High (≥64 chars)' : 'Standard'}</div>
        </div>
      </div>
    `;
  }

  /**
   * Render client_assertion JWT section.
   */
  renderClientAssertionDetails(assertion) {
    const e = (v) => this.escapeHtml(v == null ? '' : String(v));
    const expiredNote = assertion.isExpired === true
      ? ' <span class="oauth-expired">⚠ EXPIRED</span>'
      : (assertion.isExpired === false ? ' ✓' : '');
    return `
      <div class="oauth-section">
        <h5>🎫 Client Assertion (JWT)</h5>
        <div class="details-grid">
          ${assertion.algorithm ? `<div class="label">Algorithm:</div><div class="value">${e(assertion.algorithm)}</div>` : ''}
          ${assertion.keyId ? `<div class="label">Key ID (kid):</div><div class="value mono">${e(assertion.keyId.substring(0, 50))}</div>` : ''}
          ${assertion.thumbprint ? `<div class="label">Thumbprint:</div><div class="value mono">${e(assertion.thumbprint.substring(0, 50))}</div>` : ''}
          ${assertion.issuer ? `<div class="label">Issuer:</div><div class="value">${e(assertion.issuer)}</div>` : ''}
          ${assertion.audience ? `<div class="label">Audience:</div><div class="value">${e(Array.isArray(assertion.audience) ? assertion.audience.join(', ') : assertion.audience)}</div>` : ''}
          ${assertion.expiry ? `<div class="label">Expiry:</div><div class="value">${e(assertion.expiry)}${expiredNote}</div>` : ''}
        </div>
      </div>
    `;
  }

  /**
   * Render the list of OAuth scopes with human-readable labels.
   */
  renderScopeList(scopeLabels) {
    const e = (v) => this.escapeHtml(v == null ? '' : String(v));
    const items = scopeLabels.map(({ scope, label }) => `
      <div class="scope-item">
        <span class="scope-name">${e(scope)}</span>
        ${label ? `<span class="scope-label">${e(label)}</span>` : ''}
      </div>
    `).join('');
    return `
      <div class="oauth-section">
        <h5>📍 Requested Scopes (${scopeLabels.length})</h5>
        <div class="scope-list">${items}</div>
      </div>
    `;
  }

  /**
   * Render OAuth security warnings.
   */
  renderOAuthWarnings(warnings) {
    const e = (v) => this.escapeHtml(v == null ? '' : String(v));
    const items = warnings.map(w => `
      <div class="oauth-warning oauth-warning-${w.severity}">
        <span class="oauth-warning-icon">${w.severity === 'error' ? '🔴' : w.severity === 'warning' ? '🟡' : '🔵'}</span>
        <span class="oauth-warning-text">${e(w.message)}</span>
      </div>
    `).join('');
    return `
      <div class="oauth-section">
        <h5>🛡 Security Assessment</h5>
        ${items}
      </div>
    `;
  }

  /**
   * Populate FIDO2 section with full decoding support
   */
  populateFido2Section(request) {
    const fido2Section = document.getElementById('fido2Section');
    const fido2Details = document.getElementById('fido2Details');

    if (request.fido2Analysis && !request.fido2Analysis.error) {
      fido2Section.style.display = 'block';
      fido2Details.innerHTML = this.renderFido2Details(request.fido2Analysis, request.flowType);
    } else if (request.flowType.startsWith('fido2_')) {
      fido2Section.style.display = 'block';
      fido2Details.innerHTML = request.fido2Analysis?.error ? 
        `<div class="error">FIDO2 Error: ${request.fido2Analysis.error}</div>` :
        '<div>No FIDO2 data available for this request</div>';
    } else {
      fido2Section.style.display = 'none';
    }
  }

  /**
   * Render comprehensive FIDO2 details
   */
  renderFido2Details(fido2Data, flowType) {
    let html = '';
    
    // Flow type header
    html += `
      <div class="fido2-section">
        <h5>Flow Type: ${this.getFido2TypeDescription(flowType)}</h5>
      </div>
    `;

    // Client Data JSON section
    if (fido2Data.clientDataJSON) {
      const clientData = fido2Data.clientDataJSON;
      html += `
        <div class="fido2-section">
          <h5>📋 Client Data JSON</h5>
          <div class="details-grid">
            <div class="label">Operation Type:</div>
            <div class="value">${clientData.type}</div>
            <div class="label">Origin:</div>
            <div class="value">${clientData.origin}</div>
            <div class="label">Challenge:</div>
            <div class="value" title="${clientData.challenge}">${clientData.challenge.substring(0, 40)}...</div>
            <div class="label">Cross Origin:</div>
            <div class="value">${clientData.crossOrigin ? 'Yes' : 'No'}</div>
          </div>
        </div>
      `;
    }

    // Authenticator Data section
    if (fido2Data.authenticatorData) {
      const authData = fido2Data.authenticatorData;
      const flags = authData.flags;
      
      html += `
        <div class="fido2-section">
          <h5>🔐 Authenticator Data</h5>
          <div class="details-grid">
            <div class="label">RP ID Hash:</div>
            <div class="value" title="${authData.rpIdHash}">${authData.rpIdHash.substring(0, 40)}...</div>
            <div class="label">Signature Counter:</div>
            <div class="value">${authData.signCount}</div>
          </div>
          
          <h6>Authenticator Flags:</h6>
          <div class="flags-grid">
            <div class="flag-item ${flags.UP ? 'flag-set' : 'flag-unset'}" title="User Present">
              UP ${flags.UP ? '✓' : '✗'}
            </div>
            <div class="flag-item ${flags.UV ? 'flag-set' : 'flag-unset'}" title="User Verified">
              UV ${flags.UV ? '✓' : '✗'}
            </div>
            <div class="flag-item ${flags.AT ? 'flag-set' : 'flag-unset'}" title="Attested Credential Data">
              AT ${flags.AT ? '✓' : '✗'}
            </div>
            <div class="flag-item ${flags.ED ? 'flag-set' : 'flag-unset'}" title="Extension Data">
              ED ${flags.ED ? '✓' : '✗'}
            </div>
          </div>
        </div>
      `;

      // Attested Credential Data (if AT flag is set)
      if (authData.attestedCredentialData) {
        const credData = authData.attestedCredentialData;
        html += `
          <div class="fido2-section">
            <h5>🏷️ Attested Credential Data</h5>
            <div class="details-grid">
              <div class="label">AAGUID:</div>
              <div class="value">${credData.aaguid}</div>
              <div class="label">Credential ID Length:</div>
              <div class="value">${credData.credentialIdLength} bytes</div>
              <div class="label">Credential ID:</div>
              <div class="value" title="${credData.credentialId}">${credData.credentialId.substring(0, 40)}...</div>
            </div>
            
            ${this.renderPublicKeyInfo(credData.credentialPublicKey)}
          </div>
        `;
      }
    }

    return html;
  }

  /**
   * Render public key information
   */
  renderPublicKeyInfo(publicKeyData) {
    if (!publicKeyData || publicKeyData.error) {
      return `
        <h6>Public Key:</h6>
        <div class="error">${publicKeyData?.error || 'No public key data'}</div>
      `;
    }

    let html = '<h6>🔑 Credential Public Key:</h6>';
    
    if (publicKeyData.keyInfo && !publicKeyData.keyInfo.error) {
      const keyInfo = publicKeyData.keyInfo;
      
      html += `
        <div class="details-grid">
          <div class="label">Key Type:</div>
          <div class="value">${keyInfo.keyTypeDescription}</div>
          <div class="label">Algorithm:</div>
          <div class="value">${keyInfo.algorithmDescription}</div>
        </div>
      `;

      // EC2 Key parameters
      if (keyInfo.keyType === 2 && keyInfo.parameters.curve) {
        html += `
          <div class="details-grid">
            <div class="label">Curve:</div>
            <div class="value">${keyInfo.parameters.curveDescription}</div>
            <div class="label">Coordinates:</div>
            <div class="value">x: ${keyInfo.parameters.x ? 'Present' : 'Missing'}, y: ${keyInfo.parameters.y ? 'Present' : 'Missing'}</div>
          </div>
        `;
      }

      // RSA Key parameters
      if (keyInfo.keyType === 3) {
        html += `
          <div class="details-grid">
            <div class="label">Modulus (n):</div>
            <div class="value">${keyInfo.parameters.n ? 'Present' : 'Missing'}</div>
            <div class="label">Exponent (e):</div>
            <div class="value">${keyInfo.parameters.e ? 'Present' : 'Missing'}</div>
          </div>
        `;
      }
    } else {
      html += `<div class="error">${publicKeyData.keyInfo?.error || 'Unable to parse key information'}</div>`;
    }

    // CBOR raw data (collapsible)
    html += `
      <details class="cbor-details">
        <summary>Raw CBOR Data (${publicKeyData.size} bytes)</summary>
        <pre class="cbor-hex">${publicKeyData.hex}</pre>
      </details>
    `;

    return html;
  }

  /**
   * Get FIDO2 flow type description
   */
  getFido2TypeDescription(flowType) {
    switch (flowType) {
      case 'fido2_assertion': return 'Authentication (Assertion) - User signing in with existing credential';
      case 'fido2_attestation': return 'Registration (Attestation) - User registering new credential';
      case 'fido2_preflight': return 'Pre-flight Check - Discovering available authenticator options';
      default: return 'Unknown FIDO2 Flow';
    }
  }

  /**
   * Populate Parameters tab
   */
  populateParametersTab(request) {
    const urlParameters = document.getElementById('urlParameters');
    const requestBody = document.getElementById('requestBody');

    // URL parameters
    const url = new URL(request.url);
    const params = Array.from(url.searchParams.entries());

    const urlParamsCopyText = params.length > 0
      ? params.map(([k, v]) => `${k}: ${this.redactSensitiveValues(k, v)}`).join('\n')
      : 'No URL parameters';
    this.setSectionHeader('urlParamsSectionHeader', 'URL Parameters', urlParamsCopyText);

    if (params.length > 0) {
      urlParameters.innerHTML = params.map(([key, value]) => `
        <div class="param-name">${this.escapeHtml(key)}:</div>
        <div class="param-value">${this.escapeHtml(this.redactSensitiveValues(key, value))}</div>
      `).join('');
    } else {
      urlParameters.innerHTML = '<div class="param-value">No URL parameters</div>';
    }

    // Request body
    let bodyCopyText = 'No request body';
    if (request.requestBody) {
      bodyCopyText = this.requestBodyAsText(request.requestBody);
      requestBody.innerHTML = this.renderRequestBody(request.requestBody);
    } else {
      requestBody.innerHTML = '<div class="param-value">No request body</div>';
    }
    this.setSectionHeader('formDataSectionHeader', 'Form Data / Request Body', bodyCopyText);

    // Show device code timeline for device_code flows
    this.populateDeviceCodeTimeline(request);
  }

  /**
   * Populate the Device Code Flow Timeline in the Parameters tab.
   * Correlates all device_code poll requests for the same device_code.
   */
  populateDeviceCodeTimeline(request) {
    const timelineSection = document.getElementById('deviceCodeTimeline');
    const timelineDetails = document.getElementById('deviceCodeDetails');
    if (!timelineSection || !timelineDetails) return;

    const flowType = request.flowType || '';
    if (!flowType.startsWith('device_code')) {
      timelineSection.style.display = 'none';
      return;
    }

    timelineSection.style.display = 'block';

    // Gather related requests: all device_code requests from the full set
    const correlationKey = request.deviceCodeCorrelationKey;
    let relatedIds = [];
    if (correlationKey) {
      // Retrieve IDs from the background's correlation map (passed through via state)
      // In practice they're available via currentRequests filtered by same correlation key
      relatedIds = this.currentRequests
        .filter(r => r.deviceCodeCorrelationKey === correlationKey)
        .map(r => r.id);
    }

    const timelineRequests = relatedIds.length > 1
      ? this.currentRequests.filter(r => relatedIds.includes(r.id))
      : [request];

    timelineDetails.innerHTML = timelineRequests
      .sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0))
      .map((r, idx) => {
        const isInitiation = (r.flowType === 'device_code_initiation');
        const time = new Date(r.timestamp || Date.now()).toLocaleTimeString();
        const markerClass = isInitiation ? 'timeline-initiation'
          : r.status === 'completed' ? 'timeline-success'
          : r.status === 'error'     ? 'timeline-error'
          : 'timeline-poll';
        const label = isInitiation ? 'Device Code Initiation' : `Poll #${idx} — ${r.status || 'pending'}`;
        const isCurrent = r.id === request.id ? ' timeline-current' : '';
        return `
          <div class="timeline-item${isCurrent}">
            <div class="timeline-marker ${markerClass}"></div>
            <div class="timeline-content">
              <div class="timeline-time">${time}</div>
              <div class="timeline-details">${label}${
                r.oauthAnalysis && r.oauthAnalysis.clientId
                  ? ` &mdash; Client: ${this.escapeHtml(r.oauthAnalysis.clientId)}`
                  : ''
              }</div>
            </div>
          </div>
        `;
      }).join('');
  }

  /**
   * Format request body as plain text for clipboard copying.
   */
  requestBodyAsText(body) {
    if (body.type === 'formData') {
      return Object.entries(body.data)
        .map(([k, values]) => `${k}: ${this.redactSensitiveValues(k, values[0])}`)
        .join('\n');
    } else if (body.type === 'json') {
      return JSON.stringify(body.data, null, 2);
    }
    return String(body.data);
  }

  /**
   * Render request body
   */
  renderRequestBody(body) {
    if (body.type === 'formData') {
      return Object.entries(body.data).map(([key, values]) => `
        <div class="param-name">${key}:</div>
        <div class="param-value">${this.redactSensitiveValues(key, values[0])}</div>
      `).join('');
    } else if (body.type === 'json') {
      return `<div class="param-value"><pre>${JSON.stringify(body.data, null, 2)}</pre></div>`;
    } else {
      return `<div class="param-value">${body.data}</div>`;
    }
  }

  /**
   * Escape a value for safe insertion into HTML.
   */
  escapeHtml(text) {
    if (text == null) return '';
    return String(text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  /**
   * Render decoded SAML data as HTML for the SAML tab.
   */
  renderSamlDecoded(decoded) {
    const p = decoded.parsed;
    const e = (v) => this.escapeHtml(v);
    const shortUrn = (v) => (v && v.includes(':')) ? v.split(':').pop() : (v || '');
    let html = '';

    // Summary card
    html += `<div class="saml-summary">
      <div class="saml-meta">
        <span class="saml-type-badge">${e(p.messageType || decoded.messageType)}</span>
        <span class="saml-binding-badge">${e(decoded.binding.toUpperCase())} Binding</span>
      </div>
      <div class="details-grid">
        ${p.id ? `<div class="label">Message ID:</div><div class="value mono">${e(p.id)}</div>` : ''}
        ${p.issueInstant ? `<div class="label">Issue Instant:</div><div class="value">${e(p.issueInstant)}</div>` : ''}
        ${p.issuer ? `<div class="label">Issuer:</div><div class="value">${e(p.issuer)}</div>` : ''}
        ${p.destination ? `<div class="label">Destination:</div><div class="value">${e(p.destination)}</div>` : ''}
        ${p.version ? `<div class="label">Version:</div><div class="value">${e(p.version)}</div>` : ''}
        ${p.inResponseTo ? `<div class="label">In Response To:</div><div class="value mono">${e(p.inResponseTo)}</div>` : ''}
      </div>
    </div>`;

    // AuthnRequest fields
    if (p.messageType === 'AuthnRequest') {
      if (p.assertionConsumerServiceURL || p.protocolBinding || p.forceAuthn || p.providerName) {
        html += `<div class="section"><h5>Request Details</h5><div class="details-grid">
          ${p.assertionConsumerServiceURL ? `<div class="label">ACS URL:</div><div class="value">${e(p.assertionConsumerServiceURL)}</div>` : ''}
          ${p.protocolBinding ? `<div class="label">Protocol Binding:</div><div class="value">${e(shortUrn(p.protocolBinding))}</div>` : ''}
          ${p.forceAuthn ? `<div class="label">Force Authn:</div><div class="value">${e(p.forceAuthn)}</div>` : ''}
          ${p.isPassive ? `<div class="label">Is Passive:</div><div class="value">${e(p.isPassive)}</div>` : ''}
          ${p.providerName ? `<div class="label">Provider Name:</div><div class="value">${e(p.providerName)}</div>` : ''}
        </div></div>`;
      }
      if (p.nameIDPolicy) {
        html += `<div class="section"><h5>NameID Policy</h5><div class="details-grid">
          ${p.nameIDPolicy.format ? `<div class="label">Format:</div><div class="value">${e(shortUrn(p.nameIDPolicy.format))}</div>` : ''}
          ${p.nameIDPolicy.allowCreate ? `<div class="label">Allow Create:</div><div class="value">${e(p.nameIDPolicy.allowCreate)}</div>` : ''}
        </div></div>`;
      }
      if (p.requestedAuthnContext && p.requestedAuthnContext.classRefs && p.requestedAuthnContext.classRefs.length) {
        html += `<div class="section"><h5>Requested AuthnContext</h5><div class="details-grid">
          <div class="label">Comparison:</div><div class="value">${e(p.requestedAuthnContext.comparison || 'exact')}</div>
          <div class="label">Class Refs:</div><div class="value">${p.requestedAuthnContext.classRefs.map(r => e(shortUrn(r))).join('<br>')}</div>
        </div></div>`;
      }
    }

    // Response fields
    if (p.messageType === 'Response') {
      if (p.status) {
        const cls = p.status.isSuccess ? 'success' : 'failure';
        const icon = p.status.isSuccess ? '\u2713' : '\u2717';
        html += `<div class="section"><h5>Status</h5>
          <div class="saml-status ${cls}">${icon} ${e(p.status.code || p.status.fullCode)}
            ${p.status.message ? `<div class="status-message">${e(p.status.message)}</div>` : ''}
          </div></div>`;
      }
      if (p.assertion) {
        const a = p.assertion;
        if (a.nameID) {
          html += `<div class="section"><h5>Subject</h5><div class="details-grid">
            <div class="label">NameID:</div><div class="value">${e(a.nameID.value)}</div>
            ${a.nameID.format ? `<div class="label">Format:</div><div class="value">${e(shortUrn(a.nameID.format))}</div>` : ''}
            ${a.nameID.spNameQualifier ? `<div class="label">SP Qualifier:</div><div class="value">${e(a.nameID.spNameQualifier)}</div>` : ''}
          </div></div>`;
        }
        if (a.conditions) {
          html += `<div class="section"><h5>Conditions</h5><div class="details-grid">
            ${a.conditions.notBefore ? `<div class="label">Not Before:</div><div class="value">${e(a.conditions.notBefore)}</div>` : ''}
            ${a.conditions.notOnOrAfter ? `<div class="label">Not On/After:</div><div class="value">${e(a.conditions.notOnOrAfter)}</div>` : ''}
            ${a.conditions.audiences && a.conditions.audiences.length ? `<div class="label">Audience(s):</div><div class="value">${a.conditions.audiences.map(au => e(au)).join('<br>')}</div>` : ''}
          </div></div>`;
        }
        if (a.authnStatement) {
          html += `<div class="section"><h5>Authentication</h5><div class="details-grid">
            ${a.authnStatement.authnInstant ? `<div class="label">Authn Instant:</div><div class="value">${e(a.authnStatement.authnInstant)}</div>` : ''}
            ${a.authnStatement.sessionIndex ? `<div class="label">Session Index:</div><div class="value">${e(a.authnStatement.sessionIndex)}</div>` : ''}
            ${a.authnStatement.authnContextClassRef ? `<div class="label">AuthnContext:</div><div class="value">${e(shortUrn(a.authnStatement.authnContextClassRef))}</div>` : ''}
          </div></div>`;
        }
        const attrKeys = Object.keys(a.attributes || {});
        if (attrKeys.length > 0) {
          html += `<div class="section"><h5>Attributes (${attrKeys.length})</h5><div class="saml-attributes">`;
          for (const [name, values] of Object.entries(a.attributes)) {
            const shortName = name.includes('/') ? name.split('/').pop() : name;
            html += `<div class="attribute-row">
              <div class="attribute-name" title="${e(name)}">${e(shortName)}</div>
              <div class="attribute-values">${values.map(v => `<span class="attribute-value">${e(v)}</span>`).join('')}</div>
            </div>`;
          }
          html += `</div></div>`;
        }
      }
    }

    // Logout fields
    if (p.messageType === 'LogoutRequest') {
      html += `<div class="section"><h5>Logout Details</h5><div class="details-grid">
        ${p.nameID ? `<div class="label">NameID:</div><div class="value">${e(p.nameID)}</div>` : ''}
        ${p.sessionIndex ? `<div class="label">Session Index:</div><div class="value">${e(p.sessionIndex)}</div>` : ''}
      </div></div>`;
    }
    if (p.messageType === 'LogoutResponse' && p.status) {
      const cls = p.status.isSuccess ? 'success' : 'failure';
      html += `<div class="section"><h5>Status</h5>
        <div class="saml-status ${cls}">${p.status.isSuccess ? '\u2713' : '\u2717'} ${e(p.status.code || p.status.fullCode)}</div>
      </div>`;
    }

    // Raw XML (collapsible)
    html += `<details class="saml-xml-details">
      <summary>Raw XML (${e(decoded.binding)} binding)</summary>
      <pre class="saml-xml">${e(SamlDecoder.prettyPrintXml(decoded.xmlText))}</pre>
    </details>`;

    return html;
  }

  /**
   * Redact sensitive values
   */
  redactSensitiveValues(key, value) {
    const sensitiveKeys = ['client_secret', 'password', 'refresh_token'];
    
    if (sensitiveKeys.some(k => key.toLowerCase().includes(k))) {
      return '[REDACTED]';
    }
    
    return String(value).substring(0, 200) + (value.length > 200 ? '...' : '');
  }

  /**
   * Populate SAML tab — decodes SAMLRequest / SAMLResponse from the captured request.
   */
  async populateSamlTab(request) {
    const samlRequestEl = document.getElementById('samlRequest');
    const samlResponseEl = document.getElementById('samlResponse');

    samlRequestEl.innerHTML = '<div class="loading">Decoding SAML…</div>';
    samlResponseEl.innerHTML = '';

    // Set default section headers while loading
    this.setSectionHeader('samlRequestSectionHeader', 'SAML Request', '');
    this.setSectionHeader('samlResponseSectionHeader', 'SAML Response', '');

    const decoded = await SamlDecoder.decodeSamlFromRequest(request);

    if (!decoded) {
      samlRequestEl.innerHTML = '<div class="empty-state">No SAML data in this request.</div>';
      samlResponseEl.innerHTML = '<div class="empty-state">No SAML data in this request.</div>';
      return;
    }

    if (decoded.error) {
      samlRequestEl.innerHTML = `<div class="error">⚠ Decode error: ${this.escapeHtml(decoded.error)}</div>`;
      samlResponseEl.innerHTML = '';
      return;
    }

    if (decoded.parsed && decoded.parsed.error) {
      const rawHtml = `<details class="saml-xml-details" open>
        <summary>Raw XML (${this.escapeHtml(decoded.binding)} binding)</summary>
        <pre class="saml-xml">${this.escapeHtml(decoded.xmlText)}</pre>
      </details>`;
      samlRequestEl.innerHTML = `<div class="error">${this.escapeHtml(decoded.parsed.error)}</div>${rawHtml}`;
      samlResponseEl.innerHTML = '';
      this.setSectionHeader('samlRequestSectionHeader', 'SAML Request', decoded.xmlText || '');
      return;
    }

    const isResponse = decoded.messageType === 'SAMLResponse' || (decoded.parsed && decoded.parsed.messageType === 'Response');
    const primaryEl = isResponse ? samlResponseEl : samlRequestEl;
    const emptyEl = isResponse ? samlRequestEl : samlResponseEl;
    const primaryHeaderId = isResponse ? 'samlResponseSectionHeader' : 'samlRequestSectionHeader';
    const primaryTitle = isResponse ? 'SAML Response' : 'SAML Request';

    primaryEl.innerHTML = this.renderSamlDecoded(decoded);
    emptyEl.innerHTML = `<div class="empty-state">No ${isResponse ? 'SAMLRequest' : 'SAMLResponse'} captured for this request.</div>`;

    // Copy text = pretty-printed XML
    const copyXml = decoded.xmlText ? SamlDecoder.prettyPrintXml(decoded.xmlText) : '';
    this.setSectionHeader(primaryHeaderId, primaryTitle, copyXml);
  }

  /**
   * Populate Entra tab — shows OAuth grant analysis and any available JWT claims.
   * JWT from response bodies is not available in MV3; we decode client_assertion
   * and id_token_hint JWTs present in the request itself.
   */
  populateEntraTab(request) {
    const entraSummary = document.getElementById('entraSummary');
    const entraClaims  = document.getElementById('entraClaims');
    const e = (v) => this.escapeHtml(v == null ? '' : String(v));

    const analysis = request.oauthAnalysis;

    // ── Summary section ────────────────────────────────────────────────────
    if (analysis && !analysis.error) {
      let summaryHtml = `
        <div class="details-grid">
          <div class="label">Grant Type:</div>
          <div class="value">${e(analysis.label)}</div>
          ${analysis.clientId ? `<div class="label">Client ID:</div><div class="value mono">${e(analysis.clientId)}</div>` : ''}
          ${analysis.scopes && analysis.scopes.length ? `<div class="label">Scopes:</div><div class="value">${analysis.scopes.map(s => e(s)).join(', ')}</div>` : ''}
        </div>
      `;
      if (analysis.pkce) {
        summaryHtml += `
          <div class="entra-badge-row">
            <span class="entra-feature-badge pkce-badge">PKCE — ${e(analysis.pkce.codeChallengeMethod)}</span>
            ${analysis.pkce.isS256 ? '<span class="entra-feature-badge compliant-badge">✓ RFC 7636 Compliant</span>' : '<span class="entra-feature-badge warning-badge">⚠ Use S256</span>'}
          </div>
        `;
      }
      if (analysis.authMethod) {
        summaryHtml += `
          <div class="entra-badge-row">
            <span class="entra-feature-badge auth-method-badge">${e(analysis.authMethodLabel || analysis.authMethod)}</span>
          </div>
        `;
      }
      entraSummary.innerHTML = summaryHtml;
      const summaryText = [
        `Grant: ${analysis.label}`,
        analysis.clientId ? `Client ID: ${analysis.clientId}` : '',
        analysis.scopes && analysis.scopes.length ? `Scopes: ${analysis.scopes.join(' ')}` : ''
      ].filter(Boolean).join('\n');
      this.setSectionHeader('entraSummarySectionHeader', 'Summary', summaryText);
    } else {
      entraSummary.innerHTML = '<div class="empty-state">No Entra-specific analysis available for this request.</div>';
      this.setSectionHeader('entraSummarySectionHeader', 'Summary', '');
    }

    // ── JWT Claims section ──────────────────────────────────────────────────
    // Attempt to decode any JWT travelling in request parameters:
    // client_assertion (client credentials / auth code), id_token_hint (authorize)
    const jwtSource = (analysis && analysis.clientAssertion && !analysis.clientAssertion.error)
      ? { jwt: this.extractJwtFromRequest(request), label: 'client_assertion' }
      : (analysis && analysis.idTokenHint && !analysis.idTokenHint.error)
        ? { jwt: this.extractJwtFromRequest(request, 'id_token_hint'), label: 'id_token_hint' }
        : null;

    if (jwtSource && jwtSource.jwt) {
      const decoded = EntraClaimsDecoder.decodeEntraToken(jwtSource.jwt);
      if (!decoded.error) {
        entraClaims.innerHTML = this.renderEntraClaims(decoded, jwtSource.label);
        this.setSectionHeader('entraClaimsSectionHeader', 'JWT Claims', `JWT source: ${jwtSource.label}`);

        // Update CAE badge
        const entraTabBtn = document.querySelector('[data-tab="entra"]');
        const caeBadge = entraTabBtn ? entraTabBtn.querySelector('.cae-badge') : null;
        if (caeBadge) caeBadge.style.display = decoded.caeEnabled ? 'inline' : 'none';
        return;
      }
    }

    entraClaims.innerHTML = '<div class="empty-state">JWT claims are decoded from <strong>client_assertion</strong> or <strong>id_token_hint</strong> parameters when present in the captured request.</div>';
    this.setSectionHeader('entraClaimsSectionHeader', 'JWT Claims', '');
  }

  /**
   * Extract a JWT string from known request parameters.
   */
  extractJwtFromRequest(request, paramName = 'client_assertion') {
    // Check request body (form data)
    if (request.requestBody && request.requestBody.type === 'formData') {
      const vals = request.requestBody.data[paramName];
      if (vals) return Array.isArray(vals) ? vals[0] : vals;
    }
    // Check URL params
    try {
      const url = new URL(request.url);
      const val = url.searchParams.get(paramName);
      if (val) return val;
    } catch { /* ignore */ }
    return null;
  }

  /**
   * Render decoded Entra JWT claims into HTML.
   */
  renderEntraClaims(decoded, source) {
    const e = (v) => this.escapeHtml(v == null ? '' : String(v));
    let html = '';

    // Token summary bar
    if (decoded.summary) {
      const s = decoded.summary;
      html += `
        <div class="entra-token-summary">
          ${s.identityType ? `<span class="entra-feature-badge">${e(s.identityType)}</span>` : ''}
          ${s.tokenVersion ? `<span class="entra-feature-badge">v${e(s.tokenVersion)}</span>` : ''}
          ${decoded.caeEnabled ? '<span class="entra-feature-badge cae-feature">CAE ✓</span>' : ''}
          ${decoded.popBinding ? '<span class="entra-feature-badge pop-feature">PoP Bound</span>' : ''}
          ${s.isExpired ? '<span class="entra-feature-badge expired-feature">⚠ Expired</span>' : ''}
          <span class="entra-source-note">Source: ${e(source)}</span>
        </div>
        <div class="details-grid">
          ${s.tenant ? `<div class="label">Tenant:</div><div class="value mono">${e(s.tenant)}</div>` : ''}
          ${s.audience ? `<div class="label">Audience:</div><div class="value">${e(Array.isArray(s.audience) ? s.audience.join(', ') : s.audience)}</div>` : ''}
          ${s.expiry ? `<div class="label">Expiry:</div><div class="value">${e(s.expiry)}</div>` : ''}
          ${s.scopes ? `<div class="label">Scopes:</div><div class="value">${e(s.scopes)}</div>` : ''}
        </div>
      `;
    }

    // Warnings
    if (decoded.warnings && decoded.warnings.length > 0) {
      html += this.renderOAuthWarnings(decoded.warnings);
    }

    // Claims table
    if (decoded.claims && decoded.claims.length > 0) {
      html += '<div class="claims-table">';
      for (const claim of decoded.claims) {
        const rowClass = claim.isEntraSpecific ? 'claim-entra' : 'claim-standard';
        html += `
          <div class="claim-row ${rowClass}">
            <div class="claim-name" title="${e(claim.detail || '')}">
              ${e(claim.name)}
              ${claim.label ? `<span class="claim-label">${e(claim.label)}</span>` : ''}
            </div>
            <div class="claim-value ${claim.isTimestamp ? 'claim-timestamp' : ''}">` +
              this.makeCopyBtn(String(claim.rawValue), `Copy ${claim.name}`) +
              `${e(claim.value)}</div>
          </div>
        `;
      }
      html += '</div>';
    }

    return html;
  }

  /**
   * Close detail panel
   */
  closeDetailPanel() {
    document.getElementById('detailPanel').style.display = 'none';

    // Hide the pane splitter
    const splitter = document.getElementById('paneSplitter');
    if (splitter) splitter.style.display = 'none';

    // Hide related requests panel
    const relPanel = document.getElementById('relatedRequestsPanel');
    if (relPanel) relPanel.style.display = 'none';

    // Clear correlation highlights
    document.querySelectorAll('.correlated-highlight').forEach(el => el.classList.remove('correlated-highlight'));
    
    // Clear selection
    document.querySelectorAll('.request-item, .flow-group-item').forEach(item => {
      item.classList.remove('selected');
    });
    
    this.selectedRequest = null;
  }

  /**
   * Switch tabs
   */
  switchTab(tabName) {
    // Update tab buttons — maintain aria-selected for screen reader accessibility
    document.querySelectorAll('.tab-btn').forEach(btn => {
      const isActive = btn.dataset.tab === tabName;
      btn.classList.toggle('active', isActive);
      btn.setAttribute('aria-selected', isActive ? 'true' : 'false');
    });

    // Update tab content
    document.querySelectorAll('.tab-pane').forEach(pane => {
      pane.classList.remove('active');
      if (pane.id === tabName + 'Tab') {
        pane.classList.add('active');
      }
    });
  }

  /**
   * Update status bar with total count and per-flow-category breakdown.
   */
  updateStatusBar() {
    const statusText = document.getElementById('statusText');
    const requestCount = document.getElementById('requestCount');

    statusText.textContent = this.currentRequests.length > 0 ? 'Capturing' : 'Ready';

    if (this.currentRequests.length === 0) {
      requestCount.textContent = '0 requests';
      return;
    }

    const catLabels = { saml: 'SAML', oauth: 'OAuth', fido2: 'FIDO2', device_code: 'Device Code' };
    const flowCounts = {};
    let errorCount = 0;
    for (const r of this.currentRequests) {
      const cat = this.getFlowTypeCategory(r.flowType);
      if (catLabels[cat]) flowCounts[cat] = (flowCounts[cat] || 0) + 1;
      if (r.status === 'error') errorCount++;
    }

    const parts = [`${this.currentRequests.length} req`];
    const breakdown = Object.entries(flowCounts).map(([k, v]) => `${catLabels[k]}: ${v}`).join(', ');
    if (breakdown) parts.push(breakdown);
    if (errorCount) parts.push(`${errorCount} error${errorCount !== 1 ? 's' : ''}`);

    requestCount.textContent = parts.join(' · ');
  }
  /**
   * Draggable splitter — lets the user resize the request-list vs detail-panel split.
   */
  initSplitter() {
    const splitter = document.getElementById('paneSplitter');
    const listContainer = document.querySelector('.request-list-container');
    const mainContent = document.querySelector('.main-content');
    if (!splitter || !listContainer || !mainContent) return;

    // Restore saved split height (stored in pixels)
    const saved = localStorage.getItem('entraTracerSplitH');
    if (saved) {
      listContainer.style.flex = '0 0 auto';
      listContainer.style.height = parseFloat(saved) + 'px';
    }

    let dragging = false;
    let startY = 0;
    let startH = 0;

    splitter.addEventListener('mousedown', (e) => {
      dragging = true;
      startY = e.clientY;
      startH = listContainer.getBoundingClientRect().height;
      splitter.classList.add('dragging');
      document.body.classList.add('no-select');
      e.preventDefault();
    });

    document.addEventListener('mousemove', (e) => {
      if (!dragging) return;
      const mainH = mainContent.getBoundingClientRect().height;
      const newH = Math.max(60, Math.min(mainH - 80, startH + (e.clientY - startY)));
      listContainer.style.flex = '0 0 auto';
      listContainer.style.height = newH + 'px';
      localStorage.setItem('entraTracerSplitH', newH);
    });

    document.addEventListener('mouseup', () => {
      if (!dragging) return;
      dragging = false;
      splitter.classList.remove('dragging');
      document.body.classList.remove('no-select');
    });
  }

  /**
   * Popup resize handle — drag the bottom-right corner to resize both width and height.
   * Maximum dimensions are capped at the available screen area.
   */
  initPopupResize() {
    const handle = document.getElementById('resizeHandle');
    if (!handle) return;

    const html = document.documentElement;

    // Restore saved popup dimensions onto the html element (which drives the popup window size)
    const savedH = localStorage.getItem('entraTracerPopupH');
    if (savedH) html.style.height = parseFloat(savedH) + 'px';
    const savedW = localStorage.getItem('entraTracerPopupW');
    if (savedW) html.style.width = parseFloat(savedW) + 'px';

    let dragging = false;
    let startX = 0, startY = 0, startW = 0, startH = 0;

    handle.addEventListener('mousedown', (e) => {
      dragging = true;
      startX = e.clientX;
      startY = e.clientY;
      startW = html.getBoundingClientRect().width;
      startH = html.getBoundingClientRect().height;
      document.body.classList.add('no-select');
      e.preventDefault();
    });

    document.addEventListener('mousemove', (e) => {
      if (!dragging) return;
      const maxH = window.screen.availHeight;
      const maxW = window.screen.availWidth;
      const newH = Math.max(400, Math.min(maxH, startH + (e.clientY - startY)));
      const newW = Math.max(960, Math.min(maxW, startW + (e.clientX - startX)));
      // Setting dimensions on the html element causes Chrome to resize the popup window
      html.style.width = newW + 'px';
      html.style.height = newH + 'px';
      localStorage.setItem('entraTracerPopupH', newH);
      localStorage.setItem('entraTracerPopupW', newW);
    });

    document.addEventListener('mouseup', () => {
      if (!dragging) return;
      dragging = false;
      document.body.classList.remove('no-select');
    });
  }

}

// Initialize UI when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  new EntraAuthTracerUI();
});