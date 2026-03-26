# Privacy Policy — Entra Auth Tracer

**Effective date:** 27 March 2026  
**Extension:** Entra Auth Tracer  
**Author:** Darren J Robinson  

---

## Summary

Entra Auth Tracer processes authentication and identity traffic **entirely on your local device**. No data is transmitted to any external server, collected by the author, or shared with any third party.

---

## What data does the extension access?

When you use Entra Auth Tracer, the extension observes HTTP/HTTPS requests made by your browser that match authentication and identity protocols (OAuth 2.x, OIDC, SAML 2.0, FIDO2/WebAuthn, and Entra Verified ID). This includes:

- Request and response URLs, HTTP methods, and status codes
- Request headers (e.g. `Authorization`, `Content-Type`) and POST body parameters
- Token endpoint parameters — grant types, client IDs, scopes, PKCE challenge values
- SAML assertions and WS-Federation payloads
- FIDO2 `clientDataJSON` and `authenticatorData` binary structures
- JWT claims from `id_token`, `access_token`, and `client_assertion` values found in captured requests

This data is captured in memory for the duration of your browser session and displayed in the extension popup.

---

## How is the data used?

All captured data is used **solely to display information to you** — the person running the extension. It is decoded, analysed, and rendered locally in the extension UI. It is never:

- Sent to any remote server controlled by the author or any third party
- Written to a cloud service or database
- Used for analytics, advertising, or any purpose other than local display

---

## How is the data stored?

| Storage location | What is stored | When it is cleared |
|---|---|---|
| **Extension in-memory state** | Captured request list for the current session | When the browser tab or extension popup is closed, or when you click **Clear** |
| **`chrome.storage.local`** (browser local storage) | User preferences only (e.g. selected view mode, split-pane position) | When the extension is uninstalled, or manually via browser settings |

No authentication tokens, credentials, assertion payloads, or personal data are persisted to `chrome.storage` or any other durable store.

---

## Sensitive data handling

The extension automatically **redacts client secrets** in the UI (replacing the value with `[REDACTED]`). Refresh tokens and other bearer credentials visible in captured requests are displayed to you for debugging purposes but are never transmitted or stored.

---

## Data sharing

The extension does not share any data with any person or organisation, including the author. There are no analytics SDKs, crash-reporting libraries, or telemetry integrations in this extension.

---

## Exports

If you use the **Export** feature (JSON, Markdown, TXT, or PDF), the exported file is saved to your local device via the standard browser download mechanism. You are responsible for the security of exported files.

---

## Permissions used

| Permission | Why it is needed |
|---|---|
| `webRequest` | Observe HTTP request URLs and headers to identify authentication traffic |
| `<all_urls>` | Authentication flows occur across many different domains (identity providers, relying parties, DID resolvers) |
| `tabs` | Associate captured requests with the correct browser tab |
| `storage` | Persist user preferences (view mode, pane layout) across sessions |
| `windows` | Open the extension in a standalone resizable window (popout mode) |

---

## Children's privacy

This extension is a developer and security-professional tool. It is not directed at children and is not intended for use by anyone under the age of 13.

---

## Changes to this policy

If the data practices described here change materially, this document will be updated and the effective date revised. The current version is always available at:  
`https://github.com/darrenjrobinson/EntraAuthTracer/blob/main/PRIVACY.md`

---

## Contact

For privacy questions or concerns, please open a [GitHub Issue](https://github.com/darrenjrobinson/EntraAuthTracer/issues) or contact the author via [blog.darrenjrobinson.com](https://blog.darrenjrobinson.com).
