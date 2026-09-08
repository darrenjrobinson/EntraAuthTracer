# Changelog

All notable changes to the Entra Auth Tracer extension are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
From 1.1.0 onward, git tags match the manifest version exactly (`v1.1.0`).

## [Unreleased]

## [1.1.0] - 2026-09-08

Hardening release: the test suite now exercises the features the extension advertises
(352 → 691 tests, popup UI included), and the review it enabled fixed a number of
decoding, filtering and redaction defects.

### Added
- **ROPC analysis** — `grant_type=password` token requests are decoded (grant label, client
  authentication method, scopes, username domain — never the credential values) and flagged
  with an error-severity `ropc_deprecated` warning; new `ropc` flow type
- **`redirect_uri` assessment** — plain-http, deprecated `oob`, private-use-scheme and invalid
  redirect URIs are flagged on authorization requests and token exchanges; loopback http is
  noted per RFC 8252; `redirectUri` is now part of the authorization-request analysis
- **Stable warning rule ids** — every OAuth, SAML, Verified ID and JWT warning carries a `rule`
  (`pkce_missing`, `state_missing`, `client_auth_secret_basic`, `redirect_uri_http`,
  `vid_callback_localhost`, `jwt_expiry`, `saml_unsigned`, …) alongside severity and message
- **SAML security assessment** — non-success status, unsigned Response/Assertion, expired or
  not-yet-valid assertions, missing `AudienceRestriction`, encrypted assertions, unsigned
  AuthnRequests, `unspecified` NameID policy and long validity windows; signature and
  encryption flags are exposed by the parser and the findings render in the SAML tab
- **FIDO2** — `attestationObject` decoding (format, algorithm, certificate count, embedded
  `authData`), authenticator extensions (`credProtect`, `minPinLength`, …), PublicKeyCredential
  JSON with fields nested under `response`, OKP key descriptions, and an **AAGUID registry**
  (Windows Hello, Microsoft Authenticator, Apple Passwords, Google Password Manager, Samsung Pass,
  1Password, Bitwarden, Dashlane, Enpass, Keeper, KeePassXC, NordPass, Proton Pass, IDmelon,
  YubiKey 5 / Bio / FIPS, Security Key by Yubico) shown next to the AAGUID
- **Verified ID** — callback payload fields (`requestStatus`, `state`, `requestId`, `subject`,
  verified credential types)
- **Popup** — "Other" option in the flow filter; BE/BS flag tiles, attestation statement and
  extension sections in the FIDO2 panel; Verified ID count in the status bar
- **Exports** — FIDO2 flags, sign count, AAGUID/authenticator and attestation format; a
  Verified ID section and category-based summary in the print report
- **Engineering** — GitHub Actions CI (lint, tests with coverage thresholds, build on Node 20/22);
  `tests/helpers.js` with builders for requests, JWTs, COSE keys, WebAuthn `authenticatorData`
  and attestation objects; jsdom smoke tests for the popup; `LICENSE` file (BSD-2-Clause with
  the upstream SimpleSAMLphp SAML-tracer notice)

### Changed
- `ui.js` split into pure, tested modules: `FlowCorrelator` (categories, filters, timeline
  grouping, related requests, counts), `Sanitize` (escaping, redaction, JWT extraction) and
  `Exporters` (JSON / Markdown / TXT / print HTML); the popup is bootstrapped by `ui.main.js`
- Captured requests record Chrome's `requestId`; later webRequest events are matched on it
- In-memory capture buffer bounded to 500 requests (100 FIDO2 sessions), oldest evicted first
- Manifest: invalid `windows` permission removed; over-broad `web_accessible_resources` removed
  (nothing needed it); `minimum_chrome_version` 103 (`DecompressionStream('deflate-raw')`)
- Build: only the four production icons are packaged (a 1 MB source artwork, a test icon and a
  placeholder README were previously shipped); the dead standalone `SAMLTrace` bundle is gone;
  `npm run package` builds from `dist/`
- Redaction policy broadened and applied consistently: client secrets, passwords, refresh /
  access / ID tokens, assertions and `Authorization` / `Cookie` headers are redacted in the UI
  and in every export; `client_assertion` / `id_token_hint` are truncated
- Repository links point at `github.com/darrenjrobinson/EntraAuthTracer`

### Fixed
- **FIDO2 COSE keys decoded as `Unknown (undefined)` on every real authenticator** — cbor-web
  returns integer-keyed `Map`s, which the key parser indexed as an object; trailing extension
  bytes after the key also aborted decoding
- **BE / BS flags** were labelled as reserved bits
- **Flow filter hid captured requests** — ADFS and SAML ECP were not treated as SAML; OIDC
  discovery / userinfo / introspection / revocation / logout and Okta endpoints were not treated
  as OAuth; the status bar omitted Verified ID; Verified ID badges had no styling
- **`stopListening` removed nothing** (unbound methods were passed to `removeListener`)
- **Identical requests within one second were confused** (device-code polls) — events are now
  matched by Chrome's `requestId`
- **Exports wrote credentials verbatim** — `Authorization: Basic …` headers, `client_secret`
  form fields and URL secrets are now redacted; the TXT body branch matched a shape that never
  existed and dumped the raw body
- Exports stamped a hardcoded `1.0.0`; the version now comes from the manifest
- Raw request bodies, FIDO2 client data, COSE key descriptions, CBOR hex and error strings were
  interpolated into the popup unescaped
- Inline `onerror` handler on the popup logo violated the extension's own CSP
- ESLint failure (unused import) and the deprecated `String.prototype.substr`

### Security
- Redaction applied to exports (see Fixed); PRIVACY.md updated to describe the actual storage
  model (`localStorage` preferences, no `chrome.storage` writes) and the redaction policy

### Documentation
- README: store listing links, corrected permission table (no `webRequestBlocking`), Chrome /
  Edge 103+, accurate scope-registry and PKCE wording, SAML assessment, AAGUID registry,
  redaction and buffer behaviour; original PRD moved to `docs/PRD-v1.0.md`
- CHANGELOG restructured into released versions

## [1.0.0] - 2026-03-27

Initial public release (Chrome Web Store and Microsoft Edge Add-ons). Built in six phases.

### Added
- **Extension infrastructure** — Manifest V3 service worker, `webRequest` capture of
  authentication traffic across `<all_urls>`, webpack build with `cbor-web`, Jest test
  framework with Chrome API mocks
- **Request pipeline** — authentication endpoint detection for Microsoft Entra / Azure AD,
  Microsoft account, Google / Firebase, Okta (Classic `authn` and Identity Engine `idx`),
  AWS Cognito, ADFS, Shibboleth, IdentityServer / Duende, OIDC discovery / JWKS / userinfo /
  introspection / revocation / logout, generic OAuth and SAML paths; flow-type classification;
  device-code correlation keyed by `device_code`
- **OAuth 2.1 / OIDC decoder** — grant-type registry with OAuth 2.1 compliance flags,
  authorization-request and token-request analysis, PKCE challenge / verifier checks (S256,
  RFC 7636 length), client credentials with `client_secret_post` / `client_secret_basic` /
  HTTP Digest / `client_assertion` detection (headers merged in via `onBeforeSendHeaders`),
  device-code initiation and polling, refresh tokens, scope labelling, security warnings
- **Entra claims decoder** — registry of 45 Entra-specific JWT claims with labels and
  tooltips, 18 AMR values, `platf` device platform, CAE (`xms_cc`) detection, PoP (`cnf`)
  binding, token summary, expiry / lifetime / guest / public-client / CAE warnings; decodes
  `client_assertion` and `id_token_hint` JWTs found in requests
- **SAML 2.0 / WS-Federation decoder** — Redirect (raw DEFLATE) and POST bindings, WS-Fed
  `wresult`, parsing of AuthnRequest, Response / Assertion (NameID, conditions, authn
  statement, attributes), LogoutRequest and LogoutResponse, pretty-printed raw XML
- **FIDO2 / WebAuthn decoder** — `clientDataJSON`, `authenticatorData` (RP ID hash, flags,
  sign count, attested credential data with AAGUID and credential id), CBOR public keys
- **Entra Verified ID / DID decoder** — issuance and presentation requests, request fetch,
  callbacks, DID resolution, status lists, OpenID4VP / OpenID4VCI; warnings for localhost
  callbacks, PIN requirement and QR mode
- **Popup UI** — Fluent-inspired design with dark mode; list and timeline views with flow
  cards (device code, OAuth client sessions, Verified ID sessions); related-request
  highlighting and "Flow" chips; HTTP / Parameters / SAML / Entra tabs; search, method, flow
  and status filters; resizable split pane and popup; popout window; copy buttons; WCAG 2.1 AA
  ARIA roles and labels
- **Export** — JSON, Markdown, plain text and print-ready HTML (save as PDF)
- **Toolbar badge** — live counter of captured events, reset when the popup opens
- **Tests** — 352 Jest tests over the decoders, request pipeline and background worker

### Fixed
- `cbor-web` import (`import * as CBOR`) so CBOR decoding worked under Jest / Babel
- Passkey URL pattern tightened to avoid false positives on repository names
- Popout / splitter layout bugs in the dual-mode layout
- Manifest description length for store submission

[Unreleased]: https://github.com/darrenjrobinson/EntraAuthTracer/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/darrenjrobinson/EntraAuthTracer/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/darrenjrobinson/EntraAuthTracer/releases/tag/v1.0.0
