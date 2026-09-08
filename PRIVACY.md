# Privacy Policy — Entra Auth Tracer

**Effective date:** 8 September 2026  
**Extension:** Entra Auth Tracer  
**Author:** Darren J Robinson  

---

## Summary

Entra Auth Tracer processes authentication and identity traffic **entirely on your local device**. No data is transmitted to any external server, collected by the author, or shared with any third party.

---

## What data does the extension access?

When you use Entra Auth Tracer, the extension observes HTTP/HTTPS requests made by your browser that match authentication and identity protocols (OAuth 2.x, OIDC, SAML 2.0, WS-Federation, FIDO2/WebAuthn, and Entra Verified ID). This includes:

- Request URLs, HTTP methods, response status codes and response headers
- Request headers (e.g. `Authorization`, `Content-Type`) and POST body parameters
- Token endpoint parameters — grant types, client IDs, scopes, PKCE challenge values
- SAML assertions and WS-Federation payloads
- FIDO2 `clientDataJSON`, `authenticatorData` and `attestationObject` binary structures
- JWT claims from `client_assertion` and `id_token_hint` values found in captured requests

Response **bodies** are not available to Manifest V3 extensions, so tokens issued by an identity provider in a response are never captured.

This data is held in memory for the duration of the background worker's life and displayed in the extension popup.

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
| **Extension in-memory state** (background service worker) | The most recent 500 captured requests for the current browser session | When you click **Clear**, when the browser stops the extension's background worker or restarts, or when older entries are evicted to make room |
| **`localStorage` of the extension's own pages** | Layout preferences only (view mode, split-pane position, popup size) | When the extension is uninstalled, or manually via browser settings |

No authentication tokens, credentials, assertion payloads, or personal data are persisted to `chrome.storage`, `localStorage` or any other durable store. The `storage` permission is declared for upcoming session-state features; nothing is written to `chrome.storage` in this version.

---

## Sensitive data handling

The following values are **redacted** (replaced with `[REDACTED]`) in the popup and in every export format:

- `client_secret` and any parameter or header containing `client_secret`, `password` or `refresh_token`
- the `assertion`, `access_token` and `id_token` parameters
- `Authorization` and `Proxy-Authorization` header credentials (the scheme is kept, e.g. `Basic [REDACTED]`), and `Cookie` / `Set-Cookie` headers

`client_assertion` and `id_token_hint` JWTs are **truncated** to a short preview; their decoded header and claims are shown in the OAuth and Entra panels instead. Single-use debugging values such as `code`, `code_verifier`, `device_code`, `state` and `nonce` remain visible because they are what people debug, and they are not reusable credentials.

Request URLs are redacted with the same rules wherever they are displayed or copied (request list, flow chips, detail header, HTTP tab, exports). Raw (unparsed) request bodies are displayed or exported only after being parsed as form data or JSON and redacted field by field; text that cannot be parsed is replaced by a placeholder rather than shown.

The raw request bodies and headers are held unredacted in memory so the decoders can analyse them; redaction is applied at display and export time.

---

## Data sharing

The extension does not share any data with any person or organisation, including the author. There are no analytics SDKs, crash-reporting libraries, or telemetry integrations in this extension.

---

## Exports

If you use the **Export** feature (JSON, Markdown, TXT, or print-ready HTML), the exported file is saved to your local device via the standard browser download mechanism. Exports apply the redaction policy above. You are responsible for the security of exported files — they still contain URLs, non-secret parameters, decoded claims and SAML assertion contents.

---

## Permissions used

| Permission | Why it is needed |
|---|---|
| `webRequest` | Observe HTTP request URLs, headers and request bodies to identify and decode authentication traffic (read-only) |
| `<all_urls>` | Authentication flows occur across many different domains (identity providers, relying parties, DID resolvers) |
| `tabs` | Associate captured requests with the correct browser tab |
| `storage` | Declared for upcoming session-state features; not used to store data in this version |

---

## Children's privacy

This extension is a developer and security-professional tool. It is not directed at children and is not intended for use by anyone under the age of 13.

---

## Changes to this policy

If the data practices described here change materially, this document will be updated and the effective date revised. The current version is always available at:  
`https://github.com/darrenjrobinson/EntraAuthTracer/blob/main/PRIVACY.md`

| Date | Change |
|---|---|
| 8 September 2026 | Describe the redaction policy (UI and exports), the bounded in-memory buffer, `localStorage` preferences (not `chrome.storage`), and the current permission set |
| 27 March 2026 | Initial policy |

---

## Contact

For privacy questions or concerns, please open a [GitHub Issue](https://github.com/darrenjrobinson/EntraAuthTracer/issues) or contact the author via [blog.darrenjrobinson.com](https://blog.darrenjrobinson.com).
