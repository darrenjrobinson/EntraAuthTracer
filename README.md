# Entra Auth Tracer

A Chromium-based browser extension for deep inspection of Microsoft Entra (Azure AD) authentication and identity traffic. Entra Auth Tracer extends the capabilities of SimpleSAMLphp SAML-tracer to support modern Entra authentication flows including FIDO2/Passkey analysis, OAuth 2.1 grant types, and Entra-specific JWT claims decoding.

![Entra Auth Tracer](icons/icon128.png)

## Features

### FIDO2 / Passkey Analysis
- Full CBOR decoding of `clientDataJSON` and `authenticatorData`
- Authenticator identification — Windows Hello, YubiKey, and other FIDO2 hardware keys via AAGUID recognition
- Complete FIDO2 binary structure analysis with flag decomposition and credential data extraction
- EC2 (Elliptic Curve) and RSA key type support with algorithm identification
- Rich detail display with formatted output and collapsible raw data

#### What you will see during a Passkey sign-in

A WebAuthn/Passkey flow involves three distinct HTTP phases, all of which are captured by the tracer:

| Step | Request | Flow Label | What it contains |
|------|---------|------------|-----------------|
| **1. Options / Pre-flight** | `GET /.well-known/webauthn` or `GET /webauthn/challenge` | FIDO2 Pre-flight / WebAuthn Endpoint | Relying Party policy — allowed credentials, user verification requirement, timeout |
| **2. Assertion POST** | `POST /webauthn/assertion` or `POST /assertion` | FIDO2 — Authentication (Assertion) | `clientDataJSON` (decoded: origin, challenge, type), `authenticatorData` (decoded: RP ID hash, flags UP/UV/AT/BE/BS, sign count), and signature bytes |
| **3. Token exchange** | `POST /oauth2/v2.0/token` | OAuth — Authorization Code | Access token, ID token, and Entra JWT claims confirming `amr=fido` |

> **Why you won't see the credential itself**: The actual signing step — where the browser hands the challenge to your authenticator (Windows Hello, YubiKey, etc.) and receives back a signed assertion — happens entirely inside the browser platform via the `navigator.credentials.get()` Web API. This exchange never travels over HTTP and therefore cannot be intercepted by any browser extension. What _is_ visible are the challenge fetch and the signed assertion POST that wrap that ceremony.

### OAuth 2.1 Flow Detection
- **PKCE**: Code challenge/verifier analysis with S256 compliance and RFC 7636 entropy checks; warnings for `plain` or missing PKCE
- **Device Code**: Request correlation via `device_code` token with a visual timeline grouping initiation and poll requests
- **Client Credentials**: Machine-to-machine flow analysis detecting `client_secret` vs `client_assertion` (JWT) authentication
- **Grant Type Intelligence**: Smart labeling of all OAuth 2.1 grant types with compliance flags and deprecation warnings (implicit, ROPC)
- **Client Assertion Decoding**: JWT header and payload decoded in-browser for `client_assertion` and `private_key_jwt` without signature verification
- **Scope Registry**: 40+ Microsoft scope URIs mapped to human-readable descriptions
- **Security Warnings**: Per-flow security assessment with error/warning/info severity surfaced in the UI

### Entra JWT Claims Decoder
- 40+ Entra-specific JWT claims with human-readable labels and tooltips, including device claims (`deviceid`, `platf`, `ipaddr`, `ctry`), token internals (`uti`, `rh`, `sid`, `at_hash`, `c_hash`), and user claims (`unique_name`, `login_hint`, `puid`, `onprem_sid`)
- **AMR Decoding**: 18 Authentication Method Reference values decoded to plain English — Password, FIDO2/Passkey, Windows Hello for Business, SMS OTP, Windows Integrated Auth, Federated IdP, and more
- **Device Platform Decoding**: `platf` claim decoded to OS name (Windows, iOS, Android, macOS, Windows Phone)
- **CAE Detection**: Continuous Access Evaluation capability badge reflecting actual token state
- **PoP Binding**: Proof-of-Possession `cnf` / `jkt` thumbprint surfaced in the Entra tab summary
- **Security Assessments**: Expired token, expiring soon (< 5 min), long-lived lifetime (> 60 min), guest account (`acct=1`), public client (`azpacr=0`), and CAE-not-enabled hint

### Enhanced UI
- Microsoft Fluent-inspired design with full dark-mode support and WCAG 2.1 AA accessibility
- **Multi-format Export**: JSON, Markdown, TXT, and PDF (print-optimised HTML)
- **Timeline View**: Toggle between list and timeline modes; correlated requests grouped into flow cards showing step sequence and duration
- **Flow Correlation**: Automatic detection of related requests (Device Code sessions, OAuth clientId windows) with soft-highlight in list and a "Flow" chip strip in the detail header
- **Status Bar Breakdown**: Live per-category request counts (SAML, OAuth, FIDO2, Device Code) plus error count
- **Advanced Filtering**: Real-time search, method, flow-type, and status filters
- **Extension Icon Badge**: Live event-counter badge on the toolbar icon — increments on each captured auth event and resets when the popup is opened

## Supported Authentication Flows

| Flow Type | Description |
|-----------|-------------|
| **SAML 2.0** | Full SAML assertion and request analysis |
| **WS-Federation** | WS-Fed `wresult` payload decoding |
| **FIDO2 — Pre-flight** | Authenticator options / challenge fetch (`/.well-known/webauthn`, `/webauthn/challenge`) |
| **FIDO2 — Assertion** | Signed assertion POST containing decoded `clientDataJSON`, `authenticatorData`, and flags |
| **FIDO2 — Attestation** | New credential registration POST with attested credential data |
| **FIDO2 — WebAuthn** | Generic WebAuthn endpoint calls not matching the above patterns |
| **OAuth 2.1 PKCE** | Authorization Code + PKCE flow inspection with RFC 7636 checks |
| **Device Code** | Device code initiation, polling, and token exchange with timeline |
| **Client Credentials** | Machine-to-machine authentication analysis |

## Installation

### From the Browser Store

- **Chrome Web Store**: Search for "Entra Auth Tracer" or install directly from the store listing
- **Microsoft Edge Add-ons Store**: Search for "Entra Auth Tracer" or install directly from the store listing

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
   git clone https://github.com/DarrenJRobinson/EntraAuthTracer.git
   cd EntraAuthTracer
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Build the extension:**
   ```bash
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

## Permissions

| Permission | Purpose |
|------------|---------|
| `webRequest` | Intercept HTTP requests for analysis |
| `webRequestBlocking` | Access request bodies for FIDO2 decoding |
| `<all_urls>` | Monitor authentication flows across all sites |
| `tabs` | Associate requests with browser tabs |
| `storage` | Store user preferences and settings |

## Privacy & Security

- **Local Processing**: All analysis happens locally in your browser — no data leaves your machine
- **No Data Collection**: The extension does not send data to any external servers
- **Sensitive Data Handling**: Client secrets and refresh tokens are automatically redacted
- **Temporary Storage**: Captured request data is cleared when the extension is closed

## Contributing

This is a fork of [SimpleSAMLphp SAML-tracer](https://github.com/SimpleSAMLphp/SAML-tracer) licensed under BSD-2-Clause. Contributions are welcome!

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-capability`
3. Make your changes and add tests
4. Ensure tests pass: `npm test`
5. Submit a pull request

## License

Licensed under the BSD-2-Clause License, maintaining compatibility with the upstream SimpleSAMLphp SAML-tracer project.

## Credits

- **Upstream**: [SimpleSAMLphp SAML-tracer](https://github.com/SimpleSAMLphp/SAML-tracer) — foundation SAML/WS-Fed functionality
- **Author**: Darren J Robinson
- **Inspiration**: Microsoft's authentication ecosystem and the need for better debugging tools

## Support

- **GitHub Issues**: [Report a bug or request a feature](https://github.com/DarrenJRobinson/EntraAuthTracer/issues)
- **Documentation**: [Project Wiki](https://github.com/DarrenJRobinson/EntraAuthTracer/wiki)
- **Blog & Tutorials**: Feature walkthroughs at [blog.darrenjrobinson.com](https://blog.darrenjrobinson.com)

---

**Version**: 1.0.0 | **Browser Support**: Chrome 88+, Edge 88+

