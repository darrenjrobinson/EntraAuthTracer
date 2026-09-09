# Entra Auth Tracer

A Chromium-based browser extension for deep inspection of authentication and identity traffic — across Microsoft Entra (Azure AD), Okta, AWS Cognito, Google, ADFS, Shibboleth, IdentityServer/Duende, SAP, and any standards-compliant SAML 2.0, OIDC, or OAuth 2.x provider. 

Entra Auth Tracer extends the capabilities of SimpleSAMLphp SAML-tracer to support modern authentication flows including FIDO2/Passkey analysis, OAuth 2.1 grant types, HTTP-level client authentication decoding, Entra-specific JWT claims enrichment, and Entra Verified ID / Decentralised Identity (DID) flows.

![Entra Auth Tracer](icons/icon128.png)

![Entra Auth Tracer — timeline view in popout mode with OAuth flow correlation](<images/Entra Auth Tracer.png>)

## Features

### OAuth 2.1 / OIDC Flow Detection

#### Endpoint Coverage
Detects OAuth 2.x and OIDC traffic automatically across a broad set of endpoints and providers:

| Provider / Standard | Detected Paths & Patterns |
|---|---|
| **Microsoft Entra / Azure AD** | `/oauth2/v2.0/authorize`, `/oauth2/v2.0/token`, `/oauth2/v2.0/devicecode`, `/openid/userinfo`, `/connect/endsession` |
| **Entra Verified ID** | `verifiedid.did.msidentity.com`, `beta.did.msidentity.com`, `did.msidentity.com`, `request.msidentity.com` — full issuance & presentation lifecycle |
| **DID Resolvers** | `resolver.msidentity.com`, `resolver.identity.foundation` — DID document resolution |
| **IdentityServer / Duende** | `/connect/token`, `/connect/authorize`, `/connect/deviceauthorization`, `/connect/userinfo`, `/connect/introspect`, `/connect/revocation`, `/connect/endsession` |
| **Okta** | `*.okta.com` and `*.oktapreview.com` — `/oauth2/`, `/api/v1/authn`, `/idp/idx/` |
| **AWS Cognito** | `*.amazoncognito.com` — `/oauth2/`, `/login`, `/token` |
| **Google / Firebase** | `accounts.google.com`, `securetoken.googleapis.com` — `/o/oauth2/`, `/token` |
| **Generic OAuth 2.x** | `/oauth/token`, `/oauth/authorize`, `/oauth2/token` |
| **OIDC Standards** | `/.well-known/openid-configuration` (discovery), `/userinfo`, `/introspect`, `/revoc`, `/endsession` |

#### Flow & Grant Type Intelligence
- **PKCE**: Code challenge/verifier analysis with S256 compliance and RFC 7636 length/charset checks; warnings for `plain` or missing PKCE
- **Redirect URI assessment**: `redirect_uri` values using plain `http://` (non-loopback), the deprecated `oob` URN or a private-use scheme are flagged on both the authorization request and the token exchange (RFC 8252 loopback redirects are noted, not warned)
- **Device Code**: Request correlation via `device_code` token with a visual timeline grouping initiation and poll requests
- **Client Credentials**: Machine-to-machine flow analysis (see Client Authentication below)
- **OIDC Discovery**: Detects `/.well-known/openid-configuration` fetches and labels them with the provider context
- **Okta Classic & OIE**: Detects Okta's `authn` API (Classic Engine) and `idx` pipeline (Identity Engine / OIE)
- **Grant Type Intelligence**: Smart labeling of all OAuth 2.1 grant types with compliance flags and deprecation warnings (implicit, ROPC). ROPC (`grant_type=password`) requests are decoded — client, scopes, client authentication method and the username's domain, never the credential values — and flagged as removed in OAuth 2.1
- **Scope Registry**: Well-known Microsoft Graph and Azure scope URIs mapped to human-readable descriptions (exact and prefix matched)
- **Security Warnings**: Per-flow security assessment with error/warning/info severity surfaced in the UI; every finding carries a stable rule id (e.g. `pkce_missing`, `redirect_uri_http`, `client_auth_secret_basic`, `ropc_deprecated`)

#### Client Authentication Decoding
The extension decodes the authentication method used by the OAuth client at the token endpoint, including credentials that only appear in HTTP headers (captured via `onBeforeSendHeaders` and merged with the body analysis):

| Method | How it appears | What the tracer shows |
|---|---|---|
| `client_secret_post` | `client_secret` in POST body | Client ID, redacted secret, security warning |
| `client_secret_basic` | `Authorization: Basic <base64>` header | Decoded client ID, scheme label, info warning |
| `digest_auth` | `Authorization: Digest ...` header | Decoded realm, URI, algorithm, qop; warning noting SAP Integration Suite / Dell Boomi context |
| `client_assertion` / `private_key_jwt` | `client_assertion` JWT in POST body | Decoded JWT header (`alg`, `x5t`, `x5t#S256`, `kid`) and payload — no signature verification |
| Public / mTLS | No credential in body or headers | Labelled as public client; mTLS noted as browser-level (not visible via web request API) |

### Entra JWT Claims Decoder
- 40+ Entra-specific JWT claims with human-readable labels and tooltips, including device claims (`deviceid`, `platf`, `ipaddr`, `ctry`), token internals (`uti`, `rh`, `sid`, `at_hash`, `c_hash`), and user claims (`unique_name`, `login_hint`, `puid`, `onprem_sid`)
- **AMR Decoding**: 18 Authentication Method Reference values decoded to plain English — Password, FIDO2/Passkey, Windows Hello for Business, SMS OTP, Windows Integrated Auth, Federated IdP, and more
- **Device Platform Decoding**: `platf` claim decoded to OS name (Windows, iOS, Android, macOS, Windows Phone)
- **CAE Detection**: Continuous Access Evaluation capability badge reflecting actual token state
- **PoP Binding**: Proof-of-Possession `cnf` / `jkt` thumbprint surfaced in the Entra tab summary
- **Security Assessments**: Expired token, expiring soon (< 5 min), long-lived lifetime (> 60 min), guest account (`acct=1`), public client (`azpacr=0`), and CAE-not-enabled hint

### SAML 2.0 / WS-Federation
Detects and decodes SAML traffic across a wide range of service providers and identity providers:

| Pattern | Detected Flows |
|---|---|
| **Standard SAML 2.0** | POST and Redirect bindings — `SAMLRequest`, `SAMLResponse`, `SAMLart` (Artifact binding) |
| **Microsoft Entra / ADFS** | `/saml2`, `/adfs/ls/` — POST/Redirect bindings and WS-Fed `wresult` |
| **Shibboleth SP** | `/Shibboleth.sso/SAML2/POST`, `/Shibboleth.sso/SAML2/Redirect`, `/Shibboleth.sso/Logout` |
| **SAML ECP** | Enhanced Client or Proxy profile — detected on `/ECP/` paths |
| **WS-Federation** | Full `/wsfederation` path and short `/wsfed` path — `wa=wsignin1.0`/`wsignout1.0` |

The SAML tab decodes both bindings (raw DEFLATE for Redirect, base64 for POST) and WS-Fed `wresult` payloads, parses AuthnRequest / Response / Assertion / LogoutRequest / LogoutResponse, and runs a **security assessment**: unsigned Response and Assertion, non-success status, expired or not-yet-valid assertions, missing `AudienceRestriction`, encrypted assertions, unsigned AuthnRequests, `unspecified` NameID policies and unusually long validity windows are flagged with the same rule-id / severity model as the OAuth findings.

### FIDO2 / Passkey Analysis
- Full decoding of `clientDataJSON`, `authenticatorData` and registration `attestationObject` (format, algorithm, certificate count) — including PublicKeyCredential JSON with the ceremony data nested under `response`
- Authenticator identification via a built-in AAGUID registry: Windows Hello, Microsoft Authenticator, Apple Passwords / iCloud Keychain, Google Password Manager, Samsung Pass, 1Password, Bitwarden, Dashlane, Enpass, Keeper, KeePassXC, NordPass, Proton Pass, YubiKey 5 / Bio / FIPS series and Security Key by Yubico
- Flag decomposition — UP, UV, **BE** (backup eligible) and **BS** (backup state) for synced passkeys, AT, ED — plus the signature counter and authenticator extensions (`credProtect`, `minPinLength`, …)
- COSE public key parsing for EC2, RSA and OKP keys with curve and algorithm identification
- Rich detail display with formatted output and collapsible raw CBOR data

#### What you will see during a Passkey sign-in

A WebAuthn/Passkey flow involves three distinct HTTP phases, all of which are captured by the tracer:

| Step | Request | Flow Label | What it contains |
|------|---------|------------|-----------------|
| **1. Options / Pre-flight** | `GET /.well-known/webauthn` or `GET /webauthn/challenge` | FIDO2 Pre-flight / WebAuthn Endpoint | Relying Party policy — allowed credentials, user verification requirement, timeout |
| **2. Assertion POST** | `POST /webauthn/assertion` or `POST /assertion` | FIDO2 — Authentication (Assertion) | `clientDataJSON` (decoded: origin, challenge, type), `authenticatorData` (decoded: RP ID hash, flags UP/UV/AT/BE/BS, sign count), and signature bytes |
| **3. Token exchange** | `POST /oauth2/v2.0/token` | OAuth — Authorization Code | Access token, ID token, and Entra JWT claims confirming `amr=fido` |

> **Why you won't see the credential itself**: The actual signing step — where the browser hands the challenge to your authenticator (Windows Hello, YubiKey, etc.) and receives back a signed assertion — happens entirely inside the browser platform via the `navigator.credentials.get()` Web API. This exchange never travels over HTTP and therefore cannot be intercepted by any browser extension. What _is_ visible are the challenge fetch and the signed assertion POST that wrap that ceremony.

### Entra Verified ID / Decentralised Identity (DID)

Captures and decodes the full Verified ID lifecycle — issuance, presentation/verification, DID document resolution, and credential status checks.

#### Captured Endpoints

| Host / Pattern | Flow Detected |
|---|---|
| `verifiedid.did.msidentity.com/v1.0/verifiableCredentials/createIssuanceRequest` | Issuance request |
| `verifiedid.did.msidentity.com/v1.0/verifiableCredentials/createPresentationRequest` | Presentation / verification request |
| `verifiedid.did.msidentity.com/v1.0/verifiableCredentials/request/{id}` | Fetch presentation / issuance request object |
| `beta.did.msidentity.com/…` | Same operations on the beta endpoint |
| `did.msidentity.com` | Microsoft DID document host |
| `resolver.msidentity.com` | Microsoft DID resolver |
| `resolver.identity.foundation` | DIF universal DID resolver |
| `request.msidentity.com` | Verified ID request service |
| `…/statuslist/…` | Credential status list / revocation checks |
| `…/openid4vp/…` | OpenID for Verifiable Presentations (OID4VP) |
| `…/openid4vci/…` | OpenID for Verifiable Credential Issuance (OID4VCI) |

#### What the decoder surfaces

- **Operation label** — human-readable name for each API call (e.g. _Create Issuance Request_, _DID Document Resolution_)
- **Credential type** — the VC type being issued or requested (e.g. `VerifiedEmployee`, `VerifiedID`)
- **Authority** — the issuer / verifier DID or tenant URL
- **Requested credentials** — all credential types listed in a presentation request
- **Request ID** — the transaction identifier used to correlate issuance / presentation steps
- **DID identifier** — the `did:ion:…` or `did:web:…` value embedded in the URL
- **Callback URL** — the app endpoint that receives the Verified ID event callback
- **OpenID4VP/OID4VCI details** — `presentation_definition`, input descriptors, `vp_token` / `id_token` presence, credential format
- **Warnings** — localhost callback URLs flagged for production readiness; PIN requirement surfaced; QR code mode noted

> **Sign-in with the wallet still uses standard OAuth**: When a user presents a Verified ID credential to sign in, Microsoft Authenticator completes the wallet interaction locally. The issuer's Entra tenant then continues with a normal OIDC/OAuth flow through `login.microsoftonline.com`, which the tracer already captures. Both the Verified ID service calls **and** the resulting OAuth token exchange will appear in the timeline.


### Enhanced UI
- Microsoft Fluent-inspired design with full dark-mode support and WCAG 2.1 AA accessibility
- **Multi-format Export**: JSON, Markdown, TXT, and PDF (print-optimised HTML)

  ![Export options — JSON, Markdown, Plain Text and PDF](<images/Entra Auth Tracer - Export.png>)

- **Timeline View**: Toggle between list and timeline modes; correlated requests grouped into flow cards showing step sequence and duration — including Verified ID issuance / presentation sequences

  ![Timeline view with filtered OAuth flows and Entra claims analysis](<images/Entra Auth Tracer - Popout Filters & Entra.png>)

- **Flow Correlation**: Automatic detection of related requests (Device Code sessions, OAuth clientId windows) with soft-highlight in list and a "Flow" chip strip in the detail header

  ![HTTP request detail with multi-step flow correlation chips](<images/Entra Auth Tracer - Detailed Flow.png>)

- **Status Bar Breakdown**: Live per-category request counts (SAML, OAuth, FIDO2, Device Code, Verified ID) plus error count
- **Advanced Filtering**: Real-time search, method, flow-type, and status filters. The flow filter groups every captured endpoint into SAML (incl. ADFS and ECP), OAuth (incl. OIDC discovery, userinfo, introspection, revocation, logout and Okta), FIDO2, Device Code, Verified ID / DID and Other
- **Sensitive Value Handling**: client secrets, passwords, refresh / access / ID tokens, assertions and `Authorization` / `Cookie` headers are redacted in the UI **and in every export**; `client_assertion` and `id_token_hint` are truncated because their decoded claims are shown instead
- **Extension Icon Badge**: Live event-counter badge on the toolbar icon — increments on each captured auth event and resets when the popup is opened
- **Bounded capture buffer**: the most recent 500 requests are kept in memory; older captures are evicted first

## Supported Authentication Flows

### OAuth 2.x / OIDC

| Flow Type | Description |
|-----------|-------------|
| **Authorization Code + PKCE** | Code flow with RFC 7636 PKCE inspection |
| **Client Credentials** | Machine-to-machine with `client_secret_post`, `client_secret_basic`, Digest auth, or `client_assertion` |
| **Device Code** | Initiation, polling, and token exchange with correlated timeline |
| **Refresh Token** | Token refresh requests with client and scope analysis |
| **ROPC / Implicit** | Removed in OAuth 2.1 — decoded and flagged (ROPC: client, scopes, auth method, username domain; Implicit: `response_type`) |
| **OIDC Discovery** | `/.well-known/openid-configuration` endpoint detection |
| **OIDC UserInfo** | `/userinfo` endpoint calls |
| **OIDC Introspection** | `/introspect` token introspection |
| **OIDC Revocation** | `/revoc` token revocation endpoint |
| **OIDC Logout** | `/endsession` and `/connect/endsession` |
| **Okta Classic AuthN** | Okta `api/v1/authn` primary auth flow |
| **Okta Identity Engine (OIE)** | Okta `idp/idx` pipeline |

### SAML & Federation

| Flow Type | Description |
|-----------|-------------|
| **SAML 2.0 — POST Binding** | Full SAML assertion and request analysis via HTML form POST |
| **SAML 2.0 — Redirect Binding** | Query-string encoded `SAMLRequest` / `SAMLResponse` |
| **SAML 2.0 — Artifact Binding** | `SAMLart` artifact resolution |
| **SAML ECP** | Enhanced Client or Proxy profile for non-browser SAML |
| **ADFS SAML** | Microsoft ADFS `/adfs/ls/` endpoint |
| **Shibboleth SP** | Shibboleth `/Shibboleth.sso/` ACS and logout endpoints |
| **WS-Federation** | WS-Fed `wresult` payload decoding — full `/wsfederation` and short `/wsfed` paths |

### FIDO2 / WebAuthn

| Flow Type | Description |
|-----------|-------------|
| **FIDO2 — Pre-flight** | Authenticator options / challenge fetch (`/.well-known/webauthn`, `/webauthn/challenge`) |
| **FIDO2 — Assertion** | Signed assertion POST — decoded `clientDataJSON`, `authenticatorData`, flags |
| **FIDO2 — Attestation** | New credential registration POST with attested credential data |
| **FIDO2 — WebAuthn** | `/fido2/`, `/fido/`, and generic WebAuthn endpoint calls |

### Entra Verified ID / Decentralised Identity (DID)

| Flow Type | Description |
|-----------|-------------|
| **Issuance Request** | `createIssuanceRequest` — credential type, manifest URL, authority, PIN requirement |
| **Presentation Request** | `createPresentationRequest` — requested credential types, verifier name, QR code, callback URL |
| **Fetch Request Object** | Wallet fetches the request payload by request ID |
| **Request Callback** | App endpoint receives issuance or presentation event from the Verified ID service |
| **DID Document Resolution** | DID identifier resolved via Microsoft or DIF universal resolver |
| **Credential Status Check** | StatusList2021 / revocation list HTTP fetch |
| **OpenID4VP Presentation** | OpenID for Verifiable Presentations — `presentation_definition`, input descriptors |
| **OpenID4VCI Issuance** | OpenID for Verifiable Credential Issuance — credential issuer, format, proof |

## Installation

### From the Browser Store

- **Chrome Web Store**: [Entra Auth Tracer](https://chromewebstore.google.com/detail/entra-auth-tracer/phnebijghhehloikpgohcblcljkaokbh)
- **Microsoft Edge Add-ons**: [Entra Auth Tracer](https://microsoftedge.microsoft.com/addons/detail/miggooielleiofpinmmdoaljdcppnimd)

### From a GitHub Release (Recommended for testers)

1. Go to the [Releases page](https://github.com/darrenjrobinson/EntraAuthTracer/releases) and download the latest `EntraAuthTracer-vX.X.X.zip`
2. Unzip the file to a folder on your machine
3. Open Chrome or Edge and navigate to `chrome://extensions/` or `edge://extensions/`
4. Enable **Developer mode** (toggle in the top-right corner)
5. Click **Load unpacked**
6. Select the unzipped folder
7. The Entra Auth Tracer icon will appear in your browser toolbar

> **Note**: Because the extension is sideloaded rather than installed from a store, Chrome/Edge may occasionally remind you it is running in developer mode — this is expected and safe to dismiss.

### Development Installation (Sideloading from source)

1. **Clone the repository:**
   ```bash
   git clone https://github.com/darrenjrobinson/EntraAuthTracer.git
   cd EntraAuthTracer
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Lint, test and build the extension:**
   ```bash
   npm run lint
   npm test
   npm run build
   ```

4. **Load in Chrome/Edge:**
   - Open Chrome/Edge and navigate to `chrome://extensions/` or `edge://extensions/`
   - Enable **Developer mode**
   - Click **Load unpacked**
   - Select the `dist` folder

## Usage

1. **Open the extension** by clicking the Entra Auth Tracer icon in your browser toolbar
2. **Navigate to a Microsoft Entra login** or perform any authentication flow
3. **View captured requests** in the extension popup with detailed analysis
4. **Inspect flows** using the detail panel with protocol-specific tabs (SAML, OAuth, FIDO2, Entra Claims)
5. **Export** captured data in JSON, Markdown, TXT, or PDF format

![HTML export report with session summary and per-request Entra analysis](<images/Entra Auth Tracer - Export Report.png>)

## Permissions

| Permission | Purpose |
|------------|---------|
| `webRequest` | Observe HTTP request URLs, headers and request bodies (read-only — Manifest V3 has no blocking access and cannot read response bodies) |
| `<all_urls>` | Authentication flows span identity providers, relying parties and DID resolvers on many domains |
| `tabs` | Associate captured requests with the originating browser tab |
| `storage` | Declared for upcoming session-state features; nothing is written to `chrome.storage` in this version |

Layout preferences (view mode, split-pane and popup size) are kept in the extension page's own `localStorage`. The extension requires Chrome or Edge 103 or later (`minimum_chrome_version`).

## Privacy & Security

- **Local Processing**: All analysis happens locally in your browser — no data leaves your machine
- **No Data Collection**: The extension does not send data to any external servers
- **Sensitive Data Handling**: client secrets, passwords, refresh / access / ID tokens, assertions and `Authorization` / `Cookie` headers are redacted in the UI and in exports; `client_assertion` and `id_token_hint` are truncated (their decoded claims are displayed). Single-use debugging values such as `code`, `code_verifier`, `state` and `nonce` remain visible
- **Temporary Storage**: Captured requests live only in the memory of the extension's background service worker (at most 500). They are cleared when you click **Clear**, when the browser stops the service worker or restarts, or when older entries are evicted

Full details: [Privacy Policy](PRIVACY.md)

## Contributing

This is a fork of [SimpleSAMLphp SAML-tracer](https://github.com/SimpleSAMLphp/SAML-tracer) licensed under BSD-2-Clause. Contributions are welcome!

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-capability`
3. Make your changes and add tests (`tests/helpers.js` has builders for requests, JWTs and WebAuthn structures)
4. Ensure lint and tests pass: `npm run lint && npm test` — CI runs the same checks plus a build on every pull request, with coverage thresholds enforced
5. Submit a pull request

Maintainers: see [docs/RELEASE.md](docs/RELEASE.md) for how a `vX.Y.Z` tag turns into a GitHub Release and a Chrome Web Store / Edge Add-ons publish.

## License

Licensed under the [BSD-2-Clause License](LICENSE), maintaining compatibility with the upstream SimpleSAMLphp SAML-tracer project.

## Credits

- **Upstream**: [SimpleSAMLphp SAML-tracer](https://github.com/SimpleSAMLphp/SAML-tracer) — foundation SAML/WS-Fed functionality
- **Author**: Darren J Robinson
- **Inspiration**: Microsoft's authentication ecosystem and the need for better debugging tools

## Support

- **GitHub Issues**: [Report a bug or request a feature](https://github.com/darrenjrobinson/EntraAuthTracer/issues)
- **Documentation**: this README, the [CHANGELOG](CHANGELOG.md) and the original [product requirements](docs/PRD-v1.0.md)
- **Blog & Tutorials**: Feature walkthroughs at [blog.darrenjrobinson.com](https://blog.darrenjrobinson.com)

---

**Version**: 1.1.0 | **Browser Support**: Chrome 103+, Edge 103+ | [Privacy Policy](PRIVACY.md)

