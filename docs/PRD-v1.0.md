# Entra Auth Tracer — Chrome/Edge Browser Extension
## Product Requirements Document

**Author:** Darren J Robinson  
**Date:** 2026-03-24  
**Version:** 1.0 (Draft)  
**Status:** Working Spec  
**License Basis:** BSD-2-Clause (fork of SimpleSAMLphp SAML-tracer v1.9.2)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement](#2-problem-statement)
3. [Target Users & Use Cases](#3-target-users--use-cases)
4. [Functional Requirements](#4-functional-requirements)
5. [Technical Architecture](#5-technical-architecture)
6. [UI/UX Requirements](#6-uiux-requirements)
7. [Implementation Roadmap](#7-implementation-roadmap)
8. [Technical Constraints & Known Issues](#8-technical-constraints--known-issues)
9. [Success Metrics](#9-success-metrics)
10. [Out of Scope](#10-out-of-scope)
11. [Open Questions](#11-open-questions)

---

## 1. Executive Summary

**Entra Auth Tracer** is a Chromium-based browser extension (Chrome + Edge) purpose-built for deep inspection of Microsoft Entra (Azure AD) authentication and identity traffic. It is a fork of [SimpleSAMLphp SAML-tracer](https://github.com/SimpleSAMLphp/SAML-tracer) (v1.9.2, BSD-2-Clause), extended with three capabilities that upstream explicitly declined to implement (issue #84, closed "not planned"):

1. **FIDO2/Passkey flow analysis** — CBOR decoding of `clientDataJSON` and `authenticatorData` from `/assertion` and `/attestation` POST bodies
2. **OAuth 2.1 grant type intelligence** — deep awareness of PKCE, Device Code, and Client Credentials flows against Entra endpoints, including device code sequence correlation
3. **Entra-specific JWT claims decoder** — human-readable rendering of Entra-proprietary claims (`xms_cc`, `acrs`, `cnf`, `wids`, `idtyp`, etc.) with a dedicated "Entra" UI tab and CAE status badge

The extension retains full upstream SAML and WS-Fed decoding. This is an additive fork, not a replacement.

**Target browsers:** Google Chrome, Microsoft Edge (Chromium)  
**Manifest version:** MV2 (MV3 migration deferred; see §8)

---

## 2. Problem Statement

### 2.1 The Gap in Existing Tooling

SAML-tracer is the de facto standard for debugging browser-mediated identity flows. It reliably captures and decodes SAMLResponse, AuthnRequest, and WS-Fed `wresult` payloads. For SAML-centric deployments, it's sufficient.

Modern Entra deployments, however, are predominantly OAuth 2.1 / OIDC with increasingly prevalent:
- **FIDO2/Passkey authentication** via Windows Hello and hardware security keys
- **Continuous Access Evaluation (CAE)** enforcing token-bound sessions with `xms_cc: cp1`
- **Proof-of-Possession (PoP)** token binding via `cnf` claim
- **Device Code flows** for headless and cross-device authentication scenarios
- **Client Credentials** for machine-to-machine workloads

None of these are visible in SAML-tracer today. FIDO2 payloads are CBOR-encoded JSON POST bodies — not form parameters, not XML. The extension's `webRequest` hook doesn't capture request bodies at all. OAuth flows are partially detected but treated as opaque parameter bags. JWT claims are decoded but rendered as raw JSON with no Entra-specific semantic labelling.

### 2.2 Upstream Trajectory

Upstream SAML-tracer will not add OAuth/OIDC support (issue #84, explicitly closed). The project's scope is intentionally SAML-only. A fork is the correct path.

### 2.3 Consequence

IAM engineers debugging Entra deployments currently resort to:
- Fiddler/Charles with SSL inspection (heavyweight, disruptive to HSTS/pinned certs)
- Edge DevTools Network tab (raw, no protocol-aware decoding)
- Microsoft's own Entra diagnostic tools (limited to sign-in log data, not live wire capture)
- Manual JWT decoding via jwt.ms (no request context, no flow correlation)

There is no lightweight, browser-native tool that provides protocol-aware, in-context decoding of the full Entra authentication surface. Entra Auth Tracer fills that gap.

---

## 3. Target Users & Use Cases

### 3.1 Primary Users

| Persona | Context |
|---|---|
| **IAM Engineer / Architect** | Debugging Entra conditional access, CAE enforcement, token claims in enterprise deployments |
| **Security Engineer** | Validating FIDO2 attestation, reviewing PoP binding, auditing CAE capability signals |
| **Developer** | Testing OAuth 2.1 integration against Entra — PKCE correctness, scope negotiation, token content |
| **Microsoft MVP / Consultant** | Client-facing diagnostics without heavyweight proxy tooling |

### 3.2 Use Case Matrix

| Use Case | Current State | Target State |
|---|---|---|
| **FIDO2/Passkey flow** | Invisible (POST body not captured) | Full CBOR decode: clientDataJSON, authenticatorData flags, rpIdHash, signCount, attested credential |
| **PKCE flow** | Raw parameter dump | Labelled "PKCE flow", code_challenge surfaced, verifier expectations shown |
| **Device Code flow** | Raw parameter dump | Labelled "Device Code", request/poll/token sequence correlated by device_code value |
| **Client Credentials** | Raw parameter dump | Labelled "Machine-to-Machine", absence of user claims flagged |
| **JWT claims** | Raw JSON decode | Entra claims rendered with labels, CAE badge for xms_cc=cp1, summary section |
| **SAML/WS-Fed** | Full decode (retained) | No change — fully preserved |

---

## 4. Functional Requirements

### 4.1 Use Case 1: FIDO2/Passkey Flow Analysis

#### 4.1.1 Request Interception

The extension MUST hook `chrome.webRequest.onBeforeRequest` with `requestBody: true` in the `extraInfoSpec`. This is in addition to the existing `onBeforeRequest` hooks used for URL-based detection.

**Endpoint detection patterns** (applied to request URL path):

| Pattern | Label |
|---|---|
| `/assertion` | FIDO2 Assertion |
| `/attestation` | FIDO2 Attestation |
| `/passkey` | Passkey |
| `/.well-known/webauthn` | Entra FIDO2 Pre-flight |

The `/.well-known/webauthn` pre-flight MUST be flagged separately as **"Entra FIDO2 pre-flight"** — it is a GET request that Entra uses to enumerate supported authenticator types and MUST NOT be conflated with assertion/attestation POST flows.

#### 4.1.2 CBOR Parsing Dependency

Add `cbor-web` (preferred) or `cbor-x` as an npm dependency. Bundle via webpack/rollup as the existing build pipeline does for other dependencies. Do not load from CDN at runtime.

#### 4.1.3 clientDataJSON Decoding

`clientDataJSON` is Base64url-encoded in the FIDO2 request body. Decoding procedure:

1. Extract `clientDataJSON` field from request body JSON
2. Base64url-decode to UTF-8 string
3. JSON.parse
4. Expose the following fields with labels:

| Field | Label | Notes |
|---|---|---|
| `type` | Operation type | `webauthn.create` (attestation) or `webauthn.get` (assertion) |
| `challenge` | Challenge | Base64url-encoded challenge from RP |
| `origin` | Origin | Must match RP origin |
| `crossOrigin` | Cross-origin | Boolean; flag if true |

#### 4.1.4 authenticatorData Decoding

`authenticatorData` is Base64url-encoded binary (not CBOR-wrapped at the top level). Decoding procedure:

1. Extract from request body
2. Base64url-decode to ArrayBuffer
3. Parse fixed-length binary header:

| Offset | Length | Field | Label |
|---|---|---|---|
| 0 | 32 bytes | `rpIdHash` | RP ID Hash (SHA-256 of rpId) |
| 32 | 1 byte | `flags` | Authenticator Flags |
| 33 | 4 bytes | `signCount` | Signature Counter (big-endian uint32) |

**Flags byte bit decomposition** (bit 0 = LSB):

| Bit | Name | Label |
|---|---|---|
| 0 | UP | User Present |
| 2 | UV | User Verified |
| 6 | AT | Attested Credential Data present |
| 7 | ED | Extension Data present |

Bits 1, 3, 4, 5 are reserved — display their values but do not label.

**Attested Credential Data** (present when AT flag is set, offset 37+):

| Field | Size | Notes |
|---|---|---|
| `aaguid` | 16 bytes | Authenticator AAGUID — decode as UUID string |
| `credentialIdLength` | 2 bytes | Big-endian uint16 |
| `credentialId` | `credentialIdLength` bytes | Hex-encode for display |
| `credentialPublicKey` | remainder | CBOR-decode via cbor-web; display as parsed object |

#### 4.1.5 Authenticator Variance

Windows Hello and FIDO2 hardware keys (YubiKey, etc.) produce structurally different CBOR in `credentialPublicKey`. The decoder MUST handle both EC2 (COSE key type 2) and RSA (COSE key type 3) key types gracefully. Unknown key types MUST display raw CBOR structure rather than erroring.

#### 4.1.6 Test Matrix (FIDO2)

| Scenario | Authenticator | Expected |
|---|---|---|
| New passkey registration | Windows Hello (Entra-joined) | AT=1, EC2 credentialPublicKey, aaguid non-zero |
| Passkey assertion | Windows Hello | UP=1, UV=1, signCount incremented |
| Hardware key registration | YubiKey 5 series | AT=1, EC2 or RSA key, aaguid matches YubiKey AAGUID registry |
| Hardware key assertion | YubiKey 5 series | UP=1, UV=0 or 1 depending on PIN policy |
| Pre-flight | Entra /.well-known/webauthn | Labelled separately, no body decode attempted |

---

### 4.2 Use Case 2: OAuth 2.1 / PKCE / Device Code / Client Credentials

#### 4.2.1 Endpoint Coverage

Extend URL matching in `SAMLTrace.js` to explicitly detect the following Entra v2 endpoints:

| Endpoint | Purpose |
|---|---|
| `login.microsoftonline.com/*/oauth2/v2.0/authorize` | Authorization request |
| `login.microsoftonline.com/*/oauth2/v2.0/token` | Token request |
| `login.microsoftonline.com/*/oauth2/v2.0/devicecode` | Device code initiation |

Existing v1 endpoint detection (`/oauth2/token`, `/oauth2/authorize`) MUST be retained.

#### 4.2.2 Grant Type Detection and Labelling

Grant type is detected from URL parameters (GET) or request body (POST form-encoded). Detection MUST handle both.

**PKCE Flow** (`/oauth2/v2.0/authorize` request):
- Detection: presence of `code_challenge` AND `code_challenge_method=S256`
- Label: **"PKCE Flow"**
- Display: `code_challenge` value, `code_challenge_method`, `state`, `nonce`, `scope`
- Informational: note that verifier is 43-128 chars random, SHA-256 hashed, Base64url-encoded to produce challenge — do not attempt to reverse

**Device Code Flow**:
- Initiation detection: request to `/oauth2/v2.0/devicecode` (any method)
- Poll detection: `/oauth2/v2.0/token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code`
- Token detection: successful token response following poll
- Label: **"Device Code"**
- Sequence correlation: see §4.2.3

**Client Credentials**:
- Detection: `grant_type=client_credentials`
- Label: **"Machine-to-Machine (Client Credentials)"**
- Display: `client_id`, `scope`, absence of `username` / `sub` in decoded token MUST be explicitly flagged as expected
- Note: `client_secret` MUST NOT be rendered in plaintext — display as `[REDACTED — client secret]`

**Authorization Code (no PKCE)**:
- Detection: `grant_type=authorization_code` without `code_challenge`
- Label: **"Authorization Code (no PKCE)"** — display a warning that PKCE is absent

**Implicit / Hybrid** (legacy):
- Detection: `response_type=token` or `response_type=id_token`
- Label: **"Implicit Flow (legacy)"** — display deprecation notice

#### 4.2.3 Device Code Sequence Correlation

The extension MUST maintain an in-memory correlation map keyed on `device_code` value:

```
CorrelationMap[device_code] = {
  initiation: { timestamp, request_url, user_code, verification_uri, expires_in },
  polls: [{ timestamp, status, error? }],
  token: { timestamp, access_token_decoded?, id_token_decoded? }
}
```

- When a devicecode initiation response is received, extract `device_code`, `user_code`, `verification_uri`, `expires_in` from response body and store
- When a poll request is intercepted with `device_code` matching a known entry, append to `polls[]` with timestamp and response status (`authorization_pending`, `slow_down`, `expired_token`, or success)
- When a token response succeeds following a device code poll, mark the entry as complete
- In the UI, render correlated requests as a linked sequence: **Initiation → Poll (×N) → Token**, with polling timeline showing timestamps and inter-poll intervals
- This timeline is diagnostic for slow MFA or conditional access delays affecting device code polling

#### 4.2.4 Inline JWT Decoding

Any `access_token` or `id_token` field in a token endpoint response MUST be decoded inline using the existing JWT decoder. The decoded payload MUST be rendered in the Parameters tab (or new Entra tab if applicable) without requiring a separate action.

`refresh_token` values MUST NOT be decoded (opaque by design) and MUST NOT be displayed in plaintext — show `[refresh_token — opaque, not displayed]`.

---

### 4.3 Use Case 3: CAE / Entra-Specific JWT Claims

#### 4.3.1 Claims Registry

`src/EntraClaimsDecoder.js` MUST implement the following claims registry:

```javascript
const ENTRA_CLAIMS = {
  // Identity
  tid:    { label: 'Tenant ID',             detail: 'Entra tenant GUID' },
  oid:    { label: 'Object ID',             detail: 'User/service principal object GUID' },
  sub:    { label: 'Subject',               detail: 'Immutable per-app user identifier' },
  idtyp:  { label: 'Identity type',         detail: 'user / app / managed_identity' },
  acct:   { label: 'Account type',          detail: '0 = member, 1 = guest' },

  // Token metadata
  ver:    { label: 'Token version',         detail: '1.0 = v1 endpoint, 2.0 = v2 endpoint' },
  aud:    { label: 'Audience',              detail: 'Intended recipient (app URI or client_id)' },
  iss:    { label: 'Issuer',               detail: 'STS issuer URI' },
  iat:    { label: 'Issued at',             detail: 'Unix timestamp — decode to human-readable' },
  nbf:    { label: 'Not before',            detail: 'Unix timestamp — decode to human-readable' },
  exp:    { label: 'Expiry',               detail: 'Unix timestamp — decode to human-readable; flag if expired' },

  // Authorization
  scp:    { label: 'Delegated scopes',      detail: 'Space-separated OAuth scopes (delegated flows)' },
  roles:  { label: 'App roles',             detail: 'Application role assignments' },
  wids:   { label: 'Directory role IDs',    detail: 'Entra directory role GUIDs' },

  // Authentication
  amr:    { label: 'Auth methods',          detail: 'pwd / mfa / wia / fido / rsa / ngcmfa etc.' },
  auth_time: { label: 'Auth time',          detail: 'Unix timestamp of initial authentication' },
  nonce:  { label: 'Nonce',               detail: 'Replay protection value from authorize request' },

  // CAE & Security
  xms_cc: { label: 'CAE capability',        detail: 'cp1 = client supports Continuous Access Evaluation' },
  xms_ae: { label: 'Authentication event',  detail: 'Entra auth event identifier' },
  acrs:   { label: 'Auth context class ref',detail: 'Step-up auth requirement (Conditional Access)' },
  cnf:    { label: 'Confirmation (PoP)',     detail: 'Proof-of-possession key binding (jwk thumbprint)' },

  // App & Client
  azp:    { label: 'Authorized party',      detail: 'Client ID of the authorized application' },
  azpacr: { label: 'Auth party ACR',        detail: 'Client auth method: 0=public, 1=secret, 2=cert' },
  appid:  { label: 'Application ID',        detail: 'Client application ID (v1 tokens)' },

  // User info
  name:   { label: 'Display name',          detail: 'User display name' },
  upn:    { label: 'UPN',                  detail: 'User Principal Name' },
  email:  { label: 'Email',               detail: 'Email address claim' },
  family_name: { label: 'Surname',          detail: 'User surname' },
  given_name:  { label: 'Given name',       detail: 'User given name' },
};
```

This registry MUST be extensible — new claims can be added without structural changes.

#### 4.3.2 CAE Badge

When `xms_cc` claim is present with value `cp1` (or array containing `cp1`), the UI MUST render a **visible "CAE" badge** in the Entra tab header and the request list entry. This is the primary signal that CAE is active for the session. The badge MUST be visually distinct (suggested: green badge, "CAE" label, tooltip "Continuous Access Evaluation enabled").

#### 4.3.3 PoP / cnf Handling

When `cnf` claim is present:
- Decode the `jwk` thumbprint if present
- Display as labelled entry: "Confirmation (PoP)" with `jkt` (JWK thumbprint) value
- Note in UI: "Proof-of-Possession binding active"
- Do not error on absent or malformed `cnf` — graceful degradation

#### 4.3.4 Timestamp Decoding

Claims `iat`, `nbf`, `exp`, `auth_time` MUST be decoded from Unix epoch to ISO 8601 with timezone offset. `exp` MUST be compared to current time — if expired, render with a visual warning indicator.

#### 4.3.5 Entra Tab Activation Logic

The "Entra" tab MUST activate (become visible/selectable) when:

**Condition A:** The request URL hostname is `login.microsoftonline.com` OR `sts.windows.net`

**Condition B:** A decoded JWT in the request or response contains one or more claims from `ENTRA_CLAIMS` that are Entra-proprietary (i.e., `xms_cc`, `xms_ae`, `acrs`, `cnf`, `wids`, `idtyp`, `acct`, `azpacr`)

If neither condition is met, the Entra tab MAY be hidden or greyed out — do not activate for generic OAuth flows against non-Entra endpoints.

---

## 5. Technical Architecture

### 5.1 Fork Baseline

| Component | Upstream File | Action |
|---|---|---|
| Request interception | `src/SAMLTrace.js` | Extend with FIDO2 body hook, OAuth grant detection, device code correlation |
| UI panel | `src/ui.js` | Add Entra tab, FIDO2 section, device code sequence view |
| Manifest | `manifest.json` | Add permissions (see §5.3) |
| FIDO2 decoder | — | **NEW:** `src/Fido2Decoder.js` |
| Entra claims decoder | — | **NEW:** `src/EntraClaimsDecoder.js` |
| CBOR dependency | — | Add `cbor-web` to `package.json` |

Upstream files `src/SAMLDecoder.js`, `src/WsFedDecoder.js`, and all existing test infrastructure MUST remain intact and passing.

### 5.2 Request Body Interception

The existing `onBeforeRequest` listener MUST be augmented with `requestBody` in `extraInfoSpec`. The updated listener registration:

```javascript
chrome.webRequest.onBeforeRequest.addListener(
  handleRequest,
  { urls: ['<all_urls>'] },
  ['blocking', 'requestBody']  // Add 'requestBody' to existing
);
```

`requestBody` is only populated for POST/PUT requests with a body. The handler MUST check `details.requestBody` for null before processing.

For `multipart/form-data`, use `details.requestBody.formData`. For `application/json` and other raw bodies, use `details.requestBody.raw` (array of `ArrayBuffer`).

### 5.3 Manifest Permissions

Add to `manifest.json`:

```json
{
  "permissions": [
    "webRequest",
    "webRequestBlocking",
    "tabs",
    "storage",
    "<all_urls>"
  ],
  "optional_permissions": []
}
```

`requestBody` access is granted implicitly via `webRequestBlocking` in MV2. No separate permission entry is required, but the install-time warning will include "Read and change all your data on all websites" — see §8.1.

### 5.4 File Structure

```
entra-auth-tracer/
├── manifest.json
├── package.json
├── webpack.config.js (or existing build config)
├── src/
│   ├── SAMLTrace.js          (modified — core interception)
│   ├── ui.js                 (modified — Entra tab added)
│   ├── SAMLDecoder.js        (unchanged)
│   ├── WsFedDecoder.js       (unchanged)
│   ├── Fido2Decoder.js       (NEW)
│   └── EntraClaimsDecoder.js (NEW)
├── node_modules/
│   └── cbor-web/             (NEW dependency)
├── icons/
└── tests/
    ├── (existing SAML tests — unchanged)
    ├── Fido2Decoder.test.js  (NEW)
    └── EntraClaimsDecoder.test.js (NEW)
```

### 5.5 In-Memory State

The extension maintains in-memory state in the background page (MV2 persistent background page):

```javascript
const state = {
  requests: [],                    // existing — all captured requests
  deviceCodeCorrelation: new Map(),// NEW — keyed on device_code value
  fido2Sessions: [],               // NEW — captured FIDO2 flows
};
```

State is NOT persisted to `chrome.storage` — it resets when the extension popup is closed (consistent with upstream behaviour). The device code correlation map is bounded by session lifetime.

### 5.6 Build Pipeline

Inherit upstream build pipeline. Add `cbor-web` to webpack bundle. Ensure `Fido2Decoder.js` and `EntraClaimsDecoder.js` are included in the bundle output. No CDN dependencies at runtime.

---

## 6. UI/UX Requirements

### 6.1 Modern Visual Design

**Design Philosophy:** Prioritize functionality and diagnostic capability over UI/UX polish. Professional appearance that enhances usability without compromising performance or features.

| Element | Design Requirement |
|---|---|
| **Color Palette** | Microsoft Fluent-inspired: primary blues (#0078d4), semantic colors (green=#107c10, red=#d13438, orange=#ff8c00) |
| **Typography** | Segoe UI/system fonts, clear hierarchy (16px body, 14px metadata, 20px headings) |
| **Iconography** | Minimal Fluent UI icons for essential actions (filter, search, clear, copy) |
| **Dark Mode** | Full dark theme support respecting `prefers-color-scheme` |
| **Spacing** | 8px grid system for consistent spacing |

### 6.2 Main Request List Interface

Replace the basic popup list with a functional data table interface:

| Feature | Requirement |
|---|---|
| **Responsive Data Table** | Sortable columns (timestamp, method, URL, status, flow type) with resizable widths |
| **Search & Filter** | Global search bar + column filters (dropdown for method/status, text for URL, date range) |
| **Row Selection** | Click to select/highlight rows, keyboard navigation (↑/↓), Ctrl+click multi-select |
| **Visual Flow Indicators** | Color-coded badges: SAML=blue, OAuth=green, FIDO2=purple, Device Code=orange |
| **Status Indicators** | Success/error icons, CAE badge integration in list view |
| **Density Options** | Compact/comfortable/spacious view modes (default: comfortable) |
| **Virtual Scrolling** | Handle 1000+ requests without performance degradation |

### 6.3 Enhanced Filtering & Search

| Feature | Specification |
|---|---|
| **Saved Filters** | Save/load filter presets ("Errors only", "FIDO2 flows", "CAE enabled") |
| **Timeline Filter** | Time range selection: "Last 5min", "Last hour", "Today", custom range |
| **Flow Correlation** | "Show related" button to filter related requests in same authentication flow |
| **Quick Filters** | Toolbar buttons for common filters (Errors, Success, Today) |
| **Search Debouncing** | 300ms delay on search input to prevent excessive filtering |

### 6.4 Detail Panel Enhancement

Modern tabbed interface replacing basic tabs:

### 6.4.1 Existing Tab Structure (Enhanced)

| Tab | Enhanced Content |
|---|---|
| **HTTP** | Request/response headers with copy buttons, collapsible sections |
| **Parameters** | URL/form params with syntax highlighting, copy individual values |
| **SAML** | SAML-specific view (unchanged from upstream) |
| **Entra** | NEW - Entra-specific claims and flow analysis |

### 6.4.2 New "Entra" Tab

Add a fourth tab labelled **"Entra"** with CAE badge inline when `xms_cc=cp1` is detected.

#### 6.4.2.1 Summary Section

Rendered at top of Entra tab with copy-to-clipboard buttons:

| Field | Source | Notes |
|---|---|---|
| Tenant | `tid` claim | Display as GUID with copy button |
| Identity type | `idtyp` | `user` / `app` / `managed_identity` |
| Token version | `ver` | `1.0` / `2.0` |
| CAE Status | `xms_cc` | **CAE** badge (green) if `cp1`, else "Not enabled" |
| PoP Binding | `cnf` | "Active (jkt: ...)" if present, else "None" |
| Scopes | `scp` or `roles` | Space-separated list with word wrap |
| Expiry | `exp` decoded | ISO 8601 + "EXPIRED" warning if past |

#### 6.4.2.2 Claims Table

Two-column table with enhanced functionality:

| Column | Content |
|---|---|
| Claim | Human-readable label from `ENTRA_CLAIMS` registry + copy button |
| Value | Decoded value with copy button; timestamps as ISO 8601; arrays comma-separated |

**Enhanced Features:**
- Claims with `ENTRA_CLAIMS` entries render with labels
- Unknown claims render in muted italic style
- JSON values get syntax highlighting and expand/collapse
- Individual claim copy buttons

#### 6.4.2.3 FIDO2 Section

Collapsible "FIDO2 / Passkey" section in HTTP tab:

- **Flow type:** Attestation / Assertion / Pre-flight with color coding
- **clientDataJSON:** Expandable table (type, challenge, origin, crossOrigin)
- **authenticatorData:** Flags table (UP, UV, AT, ED), rpIdHash (hex), signCount
- **Attested credential** (if AT=1): aaguid (UUID), credentialId (hex), publicKey (formatted CBOR)

#### 6.4.2.4 Device Code Sequence View

Timeline visualization in Parameters tab:

```
[Initiation]  HH:MM:SS.mmm  →  user_code: XXXX-XXXX  verification_uri: ...
[Poll #1]     HH:MM:SS.mmm  →  authorization_pending
[Poll #2]     HH:MM:SS.mmm  +0.35s →  authorization_pending
[Poll #N]     HH:MM:SS.mmm  +N.Ns  →  authorization_pending
[Token]       HH:MM:SS.mmm  →  SUCCESS (access_token decoded inline)
```

With visual timeline bar showing polling intervals and success/error states.

#### 6.4.2.5 Security: Sensitive Value Handling

| Value | Display |
|---|---|
| `client_secret` | `[REDACTED — client_secret]` |
| `refresh_token` | `[refresh_token — opaque, not displayed]` |

### 6.5 Data Export & Documentation

| Feature | Implementation |
|---|---|
| **Copy to Clipboard** | One-click copy for tokens, URLs, claims, entire requests |
| **Export Options** | Multiple formats: JSON, Markdown, TXT, PDF |
| **Bulk Export** | Selected requests or entire filtered list |
| **Export Templates** | Predefined formats for different use cases |
| **Clear Functions** | Clear all, clear selected, clear by time range |
| **Request Correlation** | Visual linking of related requests in same flow |

#### 6.5.1 Export Format Specifications

| Format | Use Case | Content |
|---|---|---|
| **JSON** | Technical integration, backup, complete trace analysis | Full HTTP conversation with raw and decoded data |
| **Markdown** | Documentation, GitHub issues, wikis | Formatted tables with syntax highlighting and flow diagrams |
| **TXT** | Simple sharing, email, logs | Plain text with clear headers and complete technical details |
| **PDF** | Reports, presentations, archival | Professional layout with headers, pagination, and executive summary |

#### 6.5.2 Complete Trace Information Included

**For comprehensive flow analysis, all exports include:**

| Data Category | Details Captured |
|---|---|
| **HTTP Conversation** | Method, URL, status code, response time, redirect chain |
| **Complete Headers** | All request/response headers including custom Entra headers |
| **Request Bodies** | Full POST bodies (form data, JSON, CBOR) with size indicators |
| **Response Bodies** | Complete responses including HTML, JSON, redirects |
| **Timing Data** | Request timestamp, response time, total flow duration |
| **Flow Correlation** | Parent-child relationships, sequence ordering, shared identifiers |
| **Decoded Artifacts** | JWT claims, SAML assertions, FIDO2 structures, OAuth parameters |
| **Security Context** | Certificate details, signature validation, encryption indicators |
| **Network Details** | Cookies set/sent, referrer, user-agent, origin headers |
| **Error Information** | HTTP errors, protocol errors, validation failures with context |

#### 6.5.3 JSON Export Structure

**Complete technical format for debugging and integration:**

```json
{
  "export_metadata": {
    "generated_at": "2026-03-24T10:30:00.000Z",
    "extension_version": "1.0.0",
    "total_requests": 15,
    "flow_duration_ms": 8450,
    "export_scope": "complete_session"
  },
  "flows": [
    {
      "flow_id": "device_code_flow_001",
      "flow_type": "device_code",
      "start_time": "2026-03-24T10:29:12.123Z",
      "duration_ms": 8450,
      "status": "completed",
      "requests": [
        {
          "sequence": 1,
          "request_id": "req_001",
          "timestamp": "2026-03-24T10:29:12.123Z",
          "http": {
            "method": "POST",
            "url": "https://login.microsoftonline.com/tenant/oauth2/v2.0/devicecode",
            "status_code": 200,
            "response_time_ms": 245,
            "request_headers": {
              "Content-Type": "application/x-www-form-urlencoded",
              "User-Agent": "Mozilla/5.0..."
            },
            "response_headers": {
              "Content-Type": "application/json",
              "Cache-Control": "no-cache"
            }
          },
          "request_body": {
            "raw": "client_id=xxxx&scope=https%3A//graph.microsoft.com/.default",
            "parsed": {
              "client_id": "12345678-1234-1234-1234-123456789012",
              "scope": "https://graph.microsoft.com/.default"
            }
          },
          "response_body": {
            "raw": "{\"device_code\":\"...\",\"user_code\":\"E3F4G5H6\"}",
            "parsed": {
              "device_code": "[captured for correlation]",
              "user_code": "E3F4G5H6",
              "verification_uri": "https://microsoft.com/devicelogin",
              "expires_in": 900
            }
          },
          "flow_context": {
            "flow_type": "device_code_initiation",
            "correlation_id": "device_code_flow_001"
          }
        }
      ]
    }
  ],
  "orphaned_requests": [],
  "diagnostics": {
    "parsing_errors": [],
    "correlation_warnings": [],
    "security_notices": []
  }
}
```

#### 6.5.2 Export Scope Options

| Scope | Description |
|---|---|
| **Single Request** | Individual request with full details (all tabs) |
| **Selected Requests** | Multi-selected requests from list |
| **Current Filter** | All requests matching active filter |
| **Complete Session** | All captured requests in current session |
| **Flow Sequence** | Correlated requests (e.g., complete Device Code flow) |

#### 6.5.4 Markdown Export Template

**Complete flow documentation with technical details:**

```markdown
# Entra Auth Trace Report
**Generated:** 2026-03-24 10:30:00 UTC  
**Extension:** Entra Auth Tracer v1.0.0  
**Session Duration:** 8.45 seconds (15 requests)  

## Flow Analysis Summary
| Metric | Value |
|---|---|
| **Complete Flows** | 2 (Device Code, PKCE) |
| **Success Rate** | 93.3% (14/15 requests) |
| **Average Response Time** | 245ms |
| **CAE Sessions** | 1 detected |
| **FIDO2 Flows** | 1 (Windows Hello attestation) |

## Complete Flow Traces

### Flow 1: Device Code Authentication [COMPLETED]
**Duration:** 8.23s | **Status:** ✅ Success | **Correlation ID:** device_code_flow_001

#### Request 1: Device Code Initiation
```
POST /oauth2/v2.0/devicecode HTTP/1.1
Host: login.microsoftonline.com
Content-Type: application/x-www-form-urlencoded
Timestamp: 10:29:12.123 (+0.000s)

client_id=12345678-1234-1234-1234-123456789012
scope=https%3A//graph.microsoft.com/.default

HTTP/1.1 200 OK (245ms)
Content-Type: application/json
Cache-Control: no-cache

{
  "device_code": "[44 chars - captured for correlation]",
  "user_code": "E3F4G5H6",
  "verification_uri": "https://microsoft.com/devicelogin",
  "expires_in": 900,
  "interval": 5
}
```

#### Request 2: Token Polling (Attempt 1)
```
POST /oauth2/v2.0/token HTTP/1.1
Host: login.microsoftonline.com
Timestamp: 10:29:17.456 (+5.333s)

grant_type=urn:ietf:params:oauth:grant-type:device_code
device_code=[correlation_id_matches]
client_id=12345678-1234-1234-1234-123456789012

HTTP/1.1 400 Bad Request (189ms)
Content-Type: application/json

{
  "error": "authorization_pending",
  "error_description": "The authorization request is still pending..."
}
```

#### Request N: Successful Token Exchange
```
POST /oauth2/v2.0/token HTTP/1.1
Timestamp: 10:29:20.789 (+8.666s)

[Same parameters as polling attempt]

HTTP/1.1 200 OK (312ms)
Content-Type: application/json

{
  "access_token": "[JWT - decoded below]",
  "id_token": "[JWT - decoded below]",
  "token_type": "Bearer",
  "expires_in": 3599
}

🔍 **Decoded Access Token Claims:**
| Claim | Value | Description |
|---|---|---|
| aud | https://graph.microsoft.com | Audience |
| iss | https://sts.windows.net/{tenant}/ | Issuer |
| iat | 1711276160 (2026-03-24 10:29:20 UTC) | Issued At |
| exp | 1711279760 (2026-03-24 11:29:20 UTC) | Expires |
| xms_cc | ["cp1"] | ✅ CAE Enabled |
| scp | User.Read Mail.Read | Scopes |
| tid | xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx | Tenant ID |
| upn | user@contoso.com | User Principal Name |
```

### Flow 2: FIDO2 Attestation [COMPLETED]
**Duration:** 1.89s | **Status:** ✅ Success | **Authenticator:** Windows Hello

#### FIDO2 Attestation Request
```
POST /fido/attestation HTTP/1.1
Host: login.microsoftonline.com
Content-Type: application/json
Timestamp: 10:29:05.234

{
  "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRl...",
  "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4/krrmihjLH..."
}

🔍 **Decoded clientDataJSON:**
| Field | Value |
|---|---|
| type | webauthn.create |
| challenge | [32 bytes - base64url] |
| origin | https://login.microsoftonline.com |
| crossOrigin | false |

🔍 **Decoded authenticatorData:**
| Component | Value | Meaning |
|---|---|---|
| rpIdHash | 49720de5880e8c687434170f64766058... | SHA-256 of rpId |
| UP Flag | ✅ Set | User Present |
| UV Flag | ✅ Set | User Verified |
| AT Flag | ✅ Set | Attested Credential Data |
| signCount | 0x00000001 | Signature Counter |
| aaguid | 08987058-cadc-4b81-b6e1-30de50dcbe96 | Windows Hello TPM |
| credentialId | [64 bytes hex] | Unique credential identifier |
```

---

## Diagnostic Information
- **Timing Analysis:** All requests within expected latency bounds
- **Security Validation:** All certificates valid, no HSTS violations  
- **Protocol Compliance:** OAuth 2.1 + OIDC compliant flows detected
- **Correlation Success:** 100% of related requests successfully linked
```

#### 6.5.4 PDF Export Layout

- **Header:** Extension name, timestamp, page numbers
- **Executive Summary:** Session statistics, flow type breakdown
- **Request Details:** Tabular layout with clear sections
- **Appendix:** Raw JSON data (optional, for technical recipients)
- **Footer:** "Generated by Entra Auth Tracer" watermark

#### 6.5.5 Export Security Considerations

| Data Type | Handling |
|---|---|
| **Access Tokens** | Include in exports (diagnostic value) |
| **Client Secrets** | Always redacted as `[REDACTED]` |
| **Refresh Tokens** | Always excluded from exports |
| **Personal Data** | UPN/email included (user choice via checkbox) |

**Export Warning Dialog:**
"This export contains authentication tokens and may include personal information. Only share with authorized personnel for debugging purposes."

#### 6.5.6 Complete Flow Reconstruction Capability

**The exports provide sufficient detail for:**

| Analysis Task | Information Available |
|---|---|
| **Full Protocol Replay** | Complete HTTP conversation with headers, bodies, timing |
| **Security Audit** | All certificates, signatures, token validation, CAE status |
| **Performance Analysis** | Request/response timing, latency breakdown, polling intervals |
| **Flow Debugging** | Request correlation, parameter flow, error context |
| **Compliance Verification** | OAuth 2.1/OIDC compliance, FIDO2 attestation validation |
| **Integration Testing** | Exact parameter values, expected responses, error scenarios |

**Trace Completeness Guarantee:**
- ✅ Wire-level HTTP details (method, headers, status, timing)
- ✅ Complete request/response bodies (with appropriate redaction)
- ✅ Protocol-aware decoding (JWT, SAML, FIDO2 CBOR, OAuth parameters)
- ✅ Flow sequence correlation with timing relationships
- ✅ Error context and diagnostic information
- ✅ Security artifacts (certificates, signatures, validation status)
- ✅ Network-level details (cookies, redirects, referrer chains)

**Suitable for:**
- Reproducing authentication flows in test environments
- Creating detailed bug reports for Microsoft Support
- Security auditing and compliance documentation
- Training materials and documentation
- Integration guide creation with real-world examples

### 6.6 Performance & Memory Management

| Requirement | Implementation |
|---|---|
| **Request Limit** | Default 500 requests, configurable 100-2000 |
| **Auto-pruning** | Remove oldest requests when limit exceeded |
| **Lazy Loading** | Load request details only when tab is opened |
| **Memory Cleanup** | Clear correlation maps and decoded data on extension restart |

### 6.7 User Preferences

| Setting | Default | Description |
|---|---|---|
| **Theme** | System | Light/Dark/System preference |
| **View Density** | Comfortable | Compact/Comfortable/Spacious |
| **Max Requests** | 500 | Auto-prune limit (100-2000) |
| **Default View** | List | List/Timeline view mode |
| **Auto-expand** | Off | Auto-expand new requests |

### 6.8 Accessibility (Functional Priority)

**Note:** Accessibility features are implemented where they don't compromise core functionality or performance.

| Feature | Implementation |
|---|---|
| **Keyboard Navigation** | Tab order for essential functions, Enter/Space activation |
| **Screen Reader Support** | ARIA labels for key interactive elements only |
| **High Contrast** | Respect Windows High Contrast mode for text/background |
| **Focus Indicators** | Visible focus rings on interactive elements |

**Accessibility Compromises:**
- Complex data tables prioritize information density over full screen reader navigation
- FIDO2 binary data display optimized for technical users, not screen reader verbosity
- Color-coding used as primary indicator (not just supplementary) for flow types
- Performance takes priority over exhaustive ARIA descriptions on large request lists

### 6.9 Visual Specifications

| Component | Size/Layout |
|---|---|
| **Main Popup** | 800x600px minimum, resizable |
| **Request List** | 40px row height (comfortable), 32px (compact), 48px (spacious) |
| **Column Widths** | Timestamp: 140px, Method: 60px, URL: flexible, Status: 80px, Type: 100px |
| **Detail Panel** | 60% of popup height, tabbed interface |
| **Search Bar** | Full width, 36px height, prominent placement |

### 6.10 Wireframe Requirements

Critical interface layouts (for implementation reference):

1. **Enhanced Request List**: Sortable table with filter bar, multi-select, badges
2. **Entra Tab Layout**: Summary cards + collapsible claims table  
3. **FIDO2 Detail View**: Technical data presentation with expand/collapse
4. **Device Code Timeline**: Horizontal sequence with polling intervals
5. **Filter Interface**: Dropdown filters + saved presets sidebar

### 6.11 Progressive Enhancement

- **Core Functionality**: Works with basic HTML if JavaScript fails
- **Enhanced Features**: Sorting, filtering, syntax highlighting layer on progressively
- **Performance**: Virtual scrolling activates only for 100+ requests
- **Graceful Degradation**: Unknown CBOR structures display as hex dumps rather than erroring

---

## 7. Implementation Roadmap

### Phase 1 — Foundation (Est. 1–2 days)

| Step | Task |
|---|---|
| 1.1 | Fork `SimpleSAMLphp/SAML-tracer` from GitHub under new repo `entra-auth-tracer` |
| 1.2 | `git clone`, `npm install`, verify existing tests pass |
| 1.3 | Load unpacked extension in Edge via `edge://extensions` — confirm SAML trace still works |
| 1.4 | Add `webRequestBlocking` and `requestBody` to `manifest.json` |
| 1.5 | Create file stubs: `src/Fido2Decoder.js`, `src/EntraClaimsDecoder.js` (export empty objects) |
| 1.6 | Add `cbor-web` to `package.json`, rebuild, confirm bundle |

**Exit criteria:** Existing SAML trace functional, FIDO2/Entra stubs present, cbor-web bundled.

### Phase 2 — FIDO2 Decoder (Est. 2–3 days)

| Step | Task |
|---|---|
| 2.1 | Extend `SAMLTrace.js`: augment `onBeforeRequest` with `requestBody`, add FIDO2 endpoint detection |
| 2.2 | Implement `src/Fido2Decoder.js`: `decodeClientDataJSON()`, `decodeAuthenticatorData()` |
| 2.3 | Handle EC2 and RSA COSE key types in `credentialPublicKey` |
| 2.4 | Add FIDO2 section to `ui.js` (collapsible panel in HTTP tab) |
| 2.5 | Write `tests/Fido2Decoder.test.js` with fixture data from Windows Hello and YubiKey captures |
| 2.6 | Live test: attestation via Windows Hello (Entra-joined device) |
| 2.7 | Live test: assertion via YubiKey hardware key |

**Exit criteria:** clientDataJSON and authenticatorData decoded correctly for both platform and hardware authenticators.

### Phase 3 — OAuth 2.1 Extensions (Est. 2–3 days)

| Step | Task |
|---|---|
| 3.1 | Extend `SAMLTrace.js`: v2.0 endpoint URL matching, grant type detection from body |
| 3.2 | Implement PKCE detection and labelling |
| 3.3 | Implement Client Credentials detection, client_secret redaction |
| 3.4 | Implement Authorization Code (no PKCE) warning |
| 3.5 | Implement device code initiation, poll, and token detection |
| 3.6 | Implement `deviceCodeCorrelation` map and sequence linking |
| 3.7 | Extend `ui.js`: device code sequence view in Parameters tab |
| 3.8 | Inline JWT decode for `access_token` and `id_token` in token responses |
| 3.9 | Live test: PKCE flow via MSAL.js app against Entra |
| 3.10 | Live test: Device Code flow via Azure CLI |
| 3.11 | Live test: Client Credentials via Postman / custom app |

**Exit criteria:** All four grant types detected and labelled; device code sequence correlation working across a complete flow.

### Phase 4 — Entra Claims Decoder + UI (Est. 2–3 days)

| Step | Task |
|---|---|
| 4.1 | Implement `src/EntraClaimsDecoder.js` with full claims registry (§4.3.1) |
| 4.2 | Implement `decodeEntraClaims(jwtPayload)` returning labelled claims array |
| 4.3 | Add "Entra" tab to `ui.js` tab bar |
| 4.4 | Implement Entra tab activation logic (hostname + claim-presence conditions) |
| 4.5 | Implement summary section (tenant, idtyp, ver, CAE status, PoP, scopes, expiry) |
| 4.6 | Implement claims table with label/value columns |
| 4.7 | Implement CAE `cp1` badge in tab header and request list |
| 4.8 | Implement timestamp decoding (iat, nbf, exp, auth_time) to ISO 8601 |
| 4.9 | Implement `exp` expiry warning |
| 4.10 | Write `tests/EntraClaimsDecoder.test.js` |
| 4.11 | Live test: Entra-joined device user token (member, xms_cc=cp1) |
| 4.12 | Live test: Guest user token (acct=1) |
| 4.13 | Live test: Service principal token via client credentials (idtyp=app) |
| 4.14 | Live test: Managed identity token (idtyp=managed_identity) |
| 4.15 | Implement multi-format export system (JSON, Markdown, TXT, PDF) |
| 4.16 | Implement flow correlation and complete trace export functionality |
| 4.17 | Write export functionality tests with sample complete flows |

**Exit criteria:** Entra tab activates correctly, CAE badge renders, all known claims labelled, expiry warning functional, complete trace export working for all formats.

### Phase 5 — Polish & Release (Est. 2–3 days)

| Step | Task |
|---|---|
| 5.1 | Full regression: existing SAML and WS-Fed decoding |
| 5.2 | Cross-browser: Chrome stable, Edge stable |
| 5.3 | README: installation (sideload), permissions justification, usage guide |
| 5.4 | Chrome Web Store packaging and submission (Developer account required) |
| 5.5 | Microsoft Edge Add-ons submission |
| 5.6 | Evaluate open-sourcing under BSD-2-Clause (maintain fork lineage) or MIT |
| 5.7 | GitHub release: v1.0.0 tag, release notes |

**Exit criteria:** Extension passes store review, installs cleanly, all five phases functional.

---

## 8. Technical Constraints & Known Issues

### 8.1 Manifest V2 Dependency

**Status:** By design (current version). **Risk:** Medium-term deprecation.

`webRequest.onBeforeRequest` with `requestBody` is only fully functional under MV2. MV3 replaced `webRequestBlocking` with `declarativeNetRequest`, which:
- Does not support request body inspection
- Cannot be used for dynamic, content-aware request capture

**Current approach:** Stay on MV2. Both Chrome and Edge continue to support MV2 for extensions not submitted to the Web Store (sideloaded). The Web Store timeline for MV2 deprecation has been extended multiple times — as of writing, MV2 extensions remain submittable.

**Future migration path:** MV3 + offscreen documents or a native messaging host for body inspection. This is architecturally non-trivial and out of scope for v1.

**Action:** Document MV2 dependency clearly in README. Monitor Chromium MV3 timeline quarterly.

### 8.2 Elevated Install-Time Permission Warning

Adding `webRequestBlocking` triggers an additional Chrome/Edge install warning: **"Read and change all your data on all websites."**

This is unavoidable given the extension's legitimate need to inspect request bodies. Mitigations:
- README MUST explain why this permission is required (request body inspection for FIDO2/OAuth analysis)
- README MUST note that no data leaves the browser — all processing is local
- Consider a permissions justification page linked from the store listing

### 8.3 CBOR Structure Variance

`authenticatorData.credentialPublicKey` CBOR structure varies by authenticator:

| Authenticator | Key type | COSE alg | Notes |
|---|---|---|---|
| Windows Hello (TPM) | EC2 (kty=2) | ES256 (-7) | Standard COSE_Key |
| Windows Hello (software) | EC2 (kty=2) | ES256 (-7) | May have additional extensions |
| YubiKey 5 (FIDO2) | EC2 (kty=2) | ES256 (-7) | Typical default |
| YubiKey 5 (RSA) | RSA (kty=3) | RS256 (-257) | If configured for RSA |
| macOS Touch ID | EC2 (kty=2) | ES256 (-7) | Platform authenticator |

The decoder MUST NOT hard-code expected structures. Use cbor-web's generic decode and key into COSE map by integer key. Fallback: render raw CBOR object for unknown types.

### 8.4 PoP / cnf Token Rarity

`cnf` claim with PoP binding is uncommon in current production environments. The implementation MUST handle it (per §4.3.3) but test coverage against live PoP-bound tokens will be limited initially. Synthetic test fixtures using known-good `cnf` structures MUST be included in `EntraClaimsDecoder.test.js`.

### 8.5 device_code Correlation Boundary

The correlation map is in-memory in the background page. Edge cases:
- If the extension popup is closed and reopened mid-flow, correlation state is lost (acceptable for v1)
- `device_code` values are opaque strings — the map key is the raw value, no parsing required
- `expires_in` from the devicecode response SHOULD be used to bound the correlation entry lifetime — stale entries (expired device codes) SHOULD be pruned

### 8.6 WS-Fed and SAML Preservation

All upstream SAML and WS-Fed decoding MUST remain functional. This is non-negotiable. Changes to `SAMLTrace.js` MUST be additive — do not refactor existing detection logic. Run the full upstream test suite after each phase and before any release.

### 8.7 Extension Size and Bundle Impact

Adding `cbor-web` will increase the bundle size. `cbor-web` is approximately 40–80 KB minified. This is acceptable but should be verified against browser extension size limits (Chrome: 10 MB total package). Use tree-shaking if the build pipeline supports it to avoid bundling unused CBOR codecs.

---

## 9. Success Metrics

### 9.1 Functional Completeness

| Metric | Target |
|---|---|
| FIDO2 attestation decoded (Windows Hello) | 100% of captured flows |
| FIDO2 attestation decoded (YubiKey) | 100% of captured flows |
| FIDO2 assertion decoded (both) | 100% of captured flows |
| PKCE flow detected and labelled | 100% of PKCE requests to v2.0 endpoint |
| Device code sequence correlated | 100% of complete device code flows |
| Client credentials labelled | 100% |
| Entra claims rendered with labels | 100% of claims in registry |
| CAE badge displayed when xms_cc=cp1 | 100% |
| Upstream SAML/WS-Fed regression | 0 regressions |

### 9.2 Diagnostic Value

- Time-to-insight for a FIDO2 attestation failure: < 30 seconds from flow capture to decoded flags
- Device code polling timeline visible without external tooling
- CAE status determinable from a single token inspection (badge + summary section)

### 9.3 Quality

- All new code covered by unit tests with fixture data
- Extension loads cleanly in Chrome stable and Edge stable
- No console errors on normal operation
- No data transmitted outside the browser

---

## 10. Out of Scope

The following are explicitly out of scope for v1:

| Item | Rationale |
|---|---|
| **MV3 migration** | Requires architectural rework; deferred post-v1 |
| **Firefox support** | Different WebExtensions API surface for requestBody; separate effort |
| **Safari support** | Entirely different extension model |
| **ADFS / on-premises STS** | Focus is cloud Entra; on-prem is a separate use case |
| **Token export / save to file** | Scope creep; risk of sensitive data persistence |
| **Replay / resend requests** | Security concern; out of scope |
| **PKCE verifier recovery** | Cryptographically impossible by design |
| **client_secret capture** | Deliberately redacted — not a diagnostic artifact |
| **Decrypted JWE handling** | Encrypted JWTs are opaque without keys; out of scope |
| **Microsoft Authenticator app flows** | App-side flows not visible in browser traffic |
| **Entra External ID / B2C** | Custom policy flows differ; separate consideration |
| **Automated testing against live tenant** | Manual live test only; no credential storage in test infra |

---

## 11. Open Questions

| # | Question | Owner | Priority |
|---|---|---|---|
| OQ-1 | Should FIDO2 display be a new fifth tab or a section within the HTTP tab? The HTTP tab is already information-dense. A dedicated "FIDO2" tab would keep the UI clean but adds tab bar width. | Darren | Medium |
| OQ-2 | `cbor-web` vs `cbor-x`: `cbor-web` is the browser-targeted build of the `cbor` npm package. `cbor-x` has better performance but less browser testing. Which to use? Recommend `cbor-web` for v1, switch later if performance is a concern. | Darren | Low |
| OQ-3 | Chrome Web Store submission: MV2 extensions are still submittable but may face additional review. Has this been confirmed as of the target submission date? | Darren | High |
| OQ-4 | Open source strategy: Fork under BSD-2-Clause (preserving lineage) or relicense to MIT? BSD-2-Clause is compatible with the upstream licence and simpler — recommend BSD-2-Clause unless there's a specific MIT requirement. | Darren | Low |
| OQ-5 | Should the extension name "Entra Auth Tracer" be validated for any Microsoft trademark concerns? Entra is a Microsoft product name — may require "unofficial" or "community" qualifier in store listing. | Darren | Medium |
| OQ-6 | Device code correlation: should stale entries (expired by `expires_in`) be pruned automatically, or kept for the session and marked "expired"? The latter is more useful for post-hoc diagnosis. | Darren | Low |
| OQ-7 | `wids` claim contains directory role GUIDs — should these be resolved to human-readable role names? A static lookup table is feasible; the set of built-in directory roles is relatively stable. Out of scope for v1 but worth noting. | Darren | Low |
| OQ-8 | Managed identity tokens often lack `upn` and have `idtyp=managed_identity`. The summary section should handle this gracefully — display `appid` + `oid` as the identity anchor. Confirm this is the correct fallback. | Darren | Medium |

---

## Appendix A: Reference Endpoints

| Endpoint | Protocol | Notes |
|---|---|---|
| `login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize` | OAuth 2.1 | Authorization endpoint |
| `login.microsoftonline.com/{tenant}/oauth2/v2.0/token` | OAuth 2.1 | Token endpoint |
| `login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode` | Device Code | Initiation only |
| `login.microsoftonline.com/{tenant}/oauth2/token` | OAuth 2.0 v1 | Legacy; retain detection |
| `login.microsoftonline.com/{tenant}/oauth2/authorize` | OAuth 2.0 v1 | Legacy; retain detection |
| `sts.windows.net/{tenant}/` | WS-Fed / SAML | Retain existing decode |
| `login.microsoftonline.com/{tenant}/saml2` | SAML 2.0 | Retain existing decode |
| `*.well-known/webauthn` | FIDO2 | Entra pre-flight |
| `*/assertion` | FIDO2 | Assertion endpoint |
| `*/attestation` | FIDO2 | Attestation endpoint |

## Appendix B: COSE Key Type Reference

| kty | Type | Common alg | COSE alg value |
|---|---|---|---|
| 2 | EC2 (Elliptic Curve) | ES256 | -7 |
| 3 | RSA | RS256 | -257 |
| 1 | OKP (e.g. Ed25519) | EdDSA | -8 |

## Appendix C: Upstream Fork Rationale

Issue #84 ("Support for OpenID Connect / OAuth 2.0") was filed against SimpleSAMLphp/SAML-tracer and closed as "not planned" by maintainers. Their stated position: the extension's scope is SAML-only, OIDC/OAuth is explicitly excluded.

This PRD documents the downstream fork that implements what upstream declined. BSD-2-Clause permits this use — attribution and licence text must be preserved in `LICENSE` and extension credits.

---

*Document ends.*  
*Version 1.0 — 2026-03-24*  
*Darren J Robinson — Microsoft MVP, Identity & Access Management*
entra-auth-tracer-prd.md
Displaying entra-auth-tracer-prd.md.