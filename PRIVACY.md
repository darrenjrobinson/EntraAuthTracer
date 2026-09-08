# Privacy Policy — Entra Auth Tracer

**Effective date:** 8 September 2026  
**Extension:** Entra Auth Tracer  
**Author:** Darren J Robinson  

---

## Summary

Entra Auth Tracer processes authentication and identity traffic **entirely on your local device**. No data is transmitted to any external server, collected by the author, or shared with any third party.

The one exception is under your explicit control: if you enable **WebMCP mode** on a tab, the extension makes its captured data readable by AI agents (and scripts) in that tab. See [WebMCP mode](#webmcp-mode-optional-off-by-default) below.

---

## What data does the extension access?

When you use Entra Auth Tracer, the extension observes HTTP/HTTPS requests made by your browser that match authentication and identity protocols (OAuth 2.x, OIDC, SAML 2.0, WS-Federation, FIDO2/WebAuthn, and Entra Verified ID). This includes:

- Request URLs, HTTP methods, response status codes and response headers
- Request headers (e.g. `Authorization`, `Content-Type`) and POST body parameters
- Token endpoint parameters — grant types, client IDs, scopes, PKCE challenge values
- SAML assertions and WS-Federation payloads
- FIDO2 `clientDataJSON`, `authenticatorData` and `attestationObject` binary structures
- JWT claims from `client_assertion`, `id_token_hint`, `assertion` and `Authorization: Bearer` values found in captured requests

Response **bodies** are not available to Manifest V3 extensions, so tokens issued by an identity provider in a response are never captured.

This data is held in memory for the duration of the background worker's life and displayed in the extension popup.

---

## How is the data used?

All captured data is used **solely to display information to you** — the person running the extension — and, only when you enable WebMCP mode on a tab, to answer tool calls from AI agents in that tab. It is decoded, analysed, and rendered locally. It is never:

- Sent by the extension to any remote server controlled by the author or any third party
- Written to a cloud service or database
- Used for analytics, advertising, or any purpose other than local display and the opt-in WebMCP tools

---

## How is the data stored?

| Storage location | What is stored | When it is cleared |
|---|---|---|
| **Extension in-memory state** (background service worker) | The most recent 500 captured requests for the current browser session | When you click **Clear**, when the browser stops the extension's background worker or restarts, or when older entries are evicted to make room |
| **`chrome.storage.session`** | Only while WebMCP mode is enabled: the armed tab id, its origin and URL, the time it was enabled and the registered tool count — never any captured data | When you disable WebMCP mode, the tab navigates away or closes, or the browser exits |
| **`localStorage` of the extension's own pages** | Layout preferences only (view mode, split-pane position, popup size) | When the extension is uninstalled, or manually via browser settings |

No authentication tokens, credentials, assertion payloads, or personal data are persisted to `chrome.storage`, `localStorage` or any other durable store.

---

## Sensitive data handling

The following values are **redacted** (replaced with `[REDACTED]`) in the popup, in every export format and in WebMCP tool output:

- `client_secret` and any parameter or header containing `client_secret`, `password` or `refresh_token`
- the `assertion`, `access_token` and `id_token` parameters
- `Authorization` and `Proxy-Authorization` header credentials (the scheme is kept, e.g. `Basic [REDACTED]`), and `Cookie` / `Set-Cookie` headers
- in WebMCP tool output additionally: authorization `code` values and full device codes

`client_assertion` and `id_token_hint` JWTs are **truncated** to a short preview; their decoded header and claims are shown in the OAuth and Entra panels (and returned by the `get_token_claims` tool) instead. Raw JWT strings are never returned by the WebMCP tools. Single-use debugging values such as `code_verifier`, `state` and `nonce` remain visible because they are what people debug, and they are not reusable credentials.

Request URLs are redacted with the same rules wherever they are displayed or copied (request list, flow chips, detail header, HTTP tab, exports). Raw (unparsed) request bodies are displayed or exported only after being parsed as form data or JSON and redacted field by field; text that cannot be parsed is replaced by a placeholder rather than shown.

The raw request bodies and headers are held unredacted in memory so the decoders can analyse them; redaction is applied at display, export and tool-call time.

---

## WebMCP mode (optional, off by default)

WebMCP is a W3C Community Group draft that lets a web page register tools for AI agents running in the browser. Entra Auth Tracer can register six **read-only** tools on a page you choose. Nothing is registered until you click **Enable WebMCP** in the popup.

- **What is exposed:** the captured requests of the current session as decoded by the extension — OAuth analysis, SAML messages and assertions, FIDO2 data, Verified ID requests, security findings and the decoded **claims** of any JWT the client sent — subject to the redaction rules above.
- **To whom:** any WebMCP-capable AI agent operating in that tab, and, because tools are registered on the page's own model context, the scripts of the page you enabled it on. AI agents are frequently backed by a remote model provider; enabling WebMCP mode therefore means the data can leave your device through the agent. The extension itself still sends nothing anywhere.
- **Scope:** one tab at a time, `https://` pages only, the current document only.
- **How it ends:** click **Disable WebMCP**, load a new document or a different origin in that tab, close the tab, or exit the browser. The tools are unregistered and the `chrome.storage.session` record is removed.
- **What is stored:** only the armed tab's id, origin, URL, enable time and tool count, in `chrome.storage.session` (cleared on browser exit). No captured data is written anywhere.

---

## Data sharing

The extension does not share any data with any person or organisation, including the author. There are no analytics SDKs, crash-reporting libraries, or telemetry integrations in this extension. The optional WebMCP mode lets **you** share captured data with an AI agent of your choosing, as described above.

---

## Exports

If you use the **Export** feature (JSON, Markdown, TXT, or print-ready HTML), the exported file is saved to your local device via the standard browser download mechanism. Exports apply the redaction policy above. You are responsible for the security of exported files — they still contain URLs, non-secret parameters, decoded claims and SAML assertion contents.

---

## Permissions used

| Permission | Why it is needed |
|---|---|
| `webRequest` | Observe HTTP request URLs, headers and request bodies to identify and decode authentication traffic (read-only) |
| `<all_urls>` | Authentication flows occur across many different domains (identity providers, relying parties, DID resolvers) |
| `tabs` | Associate captured requests with the correct browser tab; find the active tab and detect navigation or close while WebMCP mode is enabled |
| `storage` | `chrome.storage.session` keeps the WebMCP armed-tab record across service-worker restarts; nothing else is stored |
| `scripting` | Inject the WebMCP bridge and page runtime into the active tab, only when you click **Enable WebMCP** |

---

## Children's privacy

This extension is a developer and security-professional tool. It is not directed at children and is not intended for use by anyone under the age of 13.

---

## Changes to this policy

If the data practices described here change materially, this document will be updated and the effective date revised. The current version is always available at:  
`https://github.com/darrenjrobinson/EntraAuthTracer/blob/main/PRIVACY.md`

| Date | Change |
|---|---|
| 8 September 2026 (1.2.0) | Add the opt-in WebMCP mode: what is exposed, to whom, scope, how it ends, what `chrome.storage.session` holds; `scripting` permission |
| 8 September 2026 (1.1.0) | Describe the redaction policy (UI and exports), the bounded in-memory buffer, `localStorage` preferences (not `chrome.storage`), and the current permission set |
| 27 March 2026 | Initial policy |

---

## Contact

For privacy questions or concerns, please open a [GitHub Issue](https://github.com/darrenjrobinson/EntraAuthTracer/issues) or contact the author via [blog.darrenjrobinson.com](https://blog.darrenjrobinson.com).
