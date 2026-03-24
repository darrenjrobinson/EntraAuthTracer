# Entra Auth Tracer

A Chromium-based browser extension for deep inspection of Microsoft Entra (Azure AD) authentication and identity traffic. This extension extends the capabilities of SimpleSAMLphp SAML-tracer to support modern Entra authentication flows including FIDO2/Passkey analysis, OAuth 2.1 grant types, and Entra-specific JWT claims decoding.

## Features

### ✅ Phase 1 - Foundation (COMPLETED)
- **Project Structure**: Complete browser extension scaffold
- **Core Architecture**: Request interception framework
- **Build System**: Webpack-based build with npm scripts
- **Testing Framework**: Jest test suite with Chrome API mocks

### ✅ Phase 2 - FIDO2 Decoder (COMPLETED)
- **FIDO2/Passkey Analysis**: Full CBOR decoding of `clientDataJSON` and `authenticatorData`
- **Authenticator Support**: Windows Hello, YubiKey, and other FIDO2 hardware keys with proper AAGUID recognition
- **Binary Parsing**: Complete FIDO2 binary structure analysis with flag decomposition and credential data extraction
- **Key Type Support**: EC2 (Elliptic Curve) and RSA key types with algorithm identification
- **Enhanced UI**: Rich FIDO2 detail display with formatted output and collapsible raw data

### ✅ Phase 3 - OAuth 2.1 Extensions (COMPLETED)
- **PKCE Flow Detection**: Code challenge/verifier analysis with S256 compliance, RFC 7636 verifier entropy checks, and security warnings for `plain` or missing PKCE
- **Device Code Flow**: Request correlation via `device_code` token with visual timeline in Parameters tab grouping initiation and poll requests
- **Client Credentials**: Machine-to-machine flow analysis detecting `client_secret` vs `client_assertion` (JWT) authentication methods
- **Grant Type Intelligence**: Smart labeling of all OAuth 2.1 grant types with OAuth 2.1 compliance flags and deprecation warnings (implicit, ROPC)
- **Client Assertion Decoding**: JWT header+payload decoded in-browser for `client_assertion` and `private_key_jwt` without signature verification
- **Scope Registry**: 40+ Microsoft scope URIs mapped to human-readable descriptions with full scope list display
- **Security Warnings**: Per-flow security assessment with error/warning/info severity levels surfaced in the UI
- **OAuthDecoder Module**: Standalone `src/OAuthDecoder.js` module (354 lines) with full test coverage in `tests/OAuthDecoder.test.js` (90 tests, 3 suites)

### ✅ Phase 4 - Entra Claims Decoder (COMPLETED)
- **Expanded Claims Registry**: 40+ Entra-specific JWT claims mapped with human-readable labels and tooltips, including device claims (`deviceid`, `platf`, `ipaddr`, `ctry`), token internals (`uti`, `rh`, `sid`, `at_hash`, `c_hash`), and user claims (`unique_name`, `login_hint`, `puid`, `onprem_sid`)
- **AMR Decoding**: 18 Authentication Method Reference values decoded to plain English (Password, FIDO2/Passkey, Windows Hello for Business, SMS OTP, Windows Integrated Auth, Federated IdP, and more)
- **Device Platform Decoding**: `platf` claim decoded to OS name (Windows, iOS, Android, macOS, Windows Phone)
- **CAE Detection**: Continuous Access Evaluation capability badge wired to live JWT decoding — tab badge and `checkForCAE()` now reflect actual token state
- **PoP Binding**: Proof-of-Possession `cnf` / `jkt` thumbprint surfaced in the Entra tab summary bar
- **Comprehensive Security Warnings**: Six assessments per token — expired, expiring soon (< 5 min), long-lived lifetime (> 60 min), guest account (`acct=1`), public client (`azpacr=0`), and CAE-not-enabled hint
- **`decodeAmrValues()` API**: Public method returns structured `{ method, description }` pairs for programmatic AMR inspection
- **EntraClaimsDecoder Module**: `src/EntraClaimsDecoder.js` with full test coverage in `tests/EntraClaimsDecoder.test.js` (110 tests across all suites)

### ✅ Phase 5 - Enhanced UI & Export (COMPLETE)
- **Modern Interface**: Microsoft Fluent-inspired design with full dark-mode support and ARIA roles throughout
- **Multi-format Export**: JSON, Markdown, TXT, and PDF (print-optimised HTML) export options
- **Timeline View**: Toggle between list and timeline modes; correlated requests grouped into flow cards showing step sequence and duration
- **Flow Correlation**: Automatic detection of related requests (Device Code sessions, OAuth clientId windows); soft-highlight in list and a "Flow" chip strip in the detail header
- **Status Bar Breakdown**: Live per-category request counts (SAML, OAuth, FIDO2, Device Code) plus error count next to the total
- **Advanced Filtering**: Real-time search, method, flow-type, and status filters

### ✅ Phase 6 - Polish, Distribution & Community (COMPLETE)
- **Extension Icon Badge**: Live event-counter badge on the toolbar icon — increments on each captured auth event and resets when the popup is opened, giving an at-a-glance indicator of activity without opening the extension
- **Browser Store Publication**: Submit to the Chrome Web Store and Microsoft Edge Add-ons Store for one-click installation
- **GitHub Repository**: Source code, issues, and releases published at [github.com/darrenjrobinson/EntraAuthTracer](https://github.com/darrenjrobinson/EntraAuthTracer)
- **Blog & Tutorials**: Feature walkthroughs and deep-dives published at [blog.darrenjrobinson.com](https://blog.darrenjrobinson.com)
- **Code Cleanup**: Removed unused imports, fixed ESLint errors (upgraded to ES2022 for class static fields, added `node` env for module exports), renamed unused parameters with `_` prefix, fixed `no-prototype-builtins` violation in `EntraClaimsDecoder`, added `no-constant-condition` disable for the intentional `while (true)` loop in `SamlDecoder.inflateRaw`
- **Test Coverage**: Achieved **97.29% line coverage** (232 tests) — well above the ≥ 90% target; added tests for `initialize`/`startListening`/`stopListening`, `handleOAuthRequest`, `handleFido2Request`, `handleDeviceCodeRequest`, all HTTP event handlers, background lifecycle handlers, SAML redirect-binding decode, and fixed a `cbor-web` import bug where `import CBOR from 'cbor-web'` yielded `undefined` under Babel
- **Accessibility Audit**: Applied WCAG 2.1 AA fixes — `aria-label` on all unlabelled form controls (search input, three filter selects), `role="tablist"`/`role="tab"`/`role="tabpanel"` with `aria-selected`, `aria-controls`, `aria-labelledby` on the tab widget, `aria-label` on the close-detail button, `aria-live="polite"` on the request list, `role="separator"` with keyboard `tabindex` on both resize handles, and a `.sr-only` utility class in `ui.css`

## Installation

### Development Installation (Sideloading)

1. **Clone the repository:**
   ```bash
   git clone https://github.com/DarrenRobinson/EntraAuthTracer.git
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
   - Enable "Developer mode"
   - Click "Load unpacked"
   - Select the `dist` folder from the built extension

### Production Installation (Coming Soon)

The extension will be available on:
- Chrome Web Store
- Microsoft Edge Add-ons Store

## Usage

1. **Open the extension** by clicking the Entra Auth Tracer icon in your browser toolbar
2. **Navigate to Microsoft Entra login** or perform authentication flows
3. **View captured requests** in the extension popup with detailed analysis
4. **Inspect flows** using the enhanced detail panel with protocol-specific tabs

### Supported Authentication Flows

| Flow Type | Status | Description |
|-----------|---------|-------------|
| **SAML 2.0** | ✅ Complete | Full SAML assertion and request analysis |
| **WS-Federation** | ✅ Complete | WS-Fed `wresult` payload decoding |
| **FIDO2/Passkey** | ✅ Complete | WebAuthn attestation and assertion analysis with CBOR decoding |
| **OAuth 2.1 PKCE** | ✅ Complete | Authorization Code + PKCE flow inspection with RFC 7636 checks |
| **Device Code** | ✅ Complete | Device code initiation, polling, and token exchange with timeline |
| **Client Credentials** | ✅ Complete | Machine-to-machine authentication analysis |

## Development

### Prerequisites

- Node.js 16+ 
- npm 7+
- Chrome/Edge browser for testing

### Development Scripts

```bash
# Install dependencies
npm install

# Development build with watch
npm run dev

# Production build
npm run build

# Run tests
npm test

# Run tests in watch mode
npm test:watch

# Lint code
npm run lint

# Package for distribution
npm run package
```

### Architecture

The extension follows a modular architecture:

```
src/
├── background.js          # Main extension background script
├── SAMLTrace.js          # Core request interception logic
├── Fido2Decoder.js       # FIDO2/WebAuthn CBOR decoding
├── EntraClaimsDecoder.js # Entra JWT claims analysis
├── ui.js                 # Extension popup interface
├── ui.html               # Popup HTML structure
└── ui.css                # Fluent-inspired styles
```

### Testing

The project includes comprehensive Jest tests:

```bash
# Run all tests
npm test

# Run specific test file
npm test Fido2Decoder.test.js

# Run tests with coverage
npm test -- --coverage
```

## Permissions

The extension requires the following permissions:

| Permission | Purpose |
|------------|---------|
| `webRequest` | Intercept HTTP requests for analysis |
| `webRequestBlocking` | Access request bodies for FIDO2 decoding |
| `<all_urls>` | Monitor authentication flows across all sites |
| `tabs` | Associate requests with browser tabs |
| `storage` | Store user preferences and settings |

## Privacy & Security

- **Local Processing**: All analysis happens locally in your browser
- **No Data Collection**: The extension does not send data to external servers
- **Sensitive Data Handling**: Client secrets and refresh tokens are automatically redacted
- **Temporary Storage**: Request data is cleared when the extension is closed

## Contributing

This is a fork of [SimpleSAMLphp SAML-tracer](https://github.com/SimpleSAMLphp/SAML-tracer) licensed under BSD-2-Clause. Contributions welcome!

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-capability`
3. Make your changes and add tests
4. Ensure tests pass: `npm test`
5. Submit a pull request

### Development Roadmap

- [x] **Phase 2**: Complete FIDO2 CBOR decoding with `cbor-web` integration
- [x] **Phase 3**: Implement OAuth 2.1 flow detection and device code correlation
- [x] **Phase 4**: Add comprehensive Entra JWT claims registry and CAE detection
- [x] **Phase 5**: Build enhanced UI with export capabilities and Fluent design
- [x] **Phase 6**: Extension icon badge, browser store publication, GitHub/blog links, code cleanup, and accessibility audit

## License

Licensed under BSD-2-Clause License, maintaining compatibility with the upstream SimpleSAMLphp SAML-tracer project.

## Credits

- **Upstream**: [SimpleSAMLphp SAML-tracer](https://github.com/SimpleSAMLphp/SAML-tracer) - Foundation SAML/WS-Fed functionality
- **Author**: Darren J Robinson
- **Inspiration**: Microsoft's authentication ecosystem and the need for better debugging tools

## Support

For issues, feature requests, or questions:
- GitHub Issues: [Report a bug or request a feature](https://github.com/DarrenRobinson/EntraAuthTracer/issues)
- Documentation: [Project Wiki](https://github.com/DarrenRobinson/EntraAuthTracer/wiki)

---

**Version**: 1.0.0 (Phase 4 - Entra Claims Decoder)  
**Browser Support**: Chrome 88+, Edge 88+  
**Manifest Version**: 2 (MV3 migration planned for future release)