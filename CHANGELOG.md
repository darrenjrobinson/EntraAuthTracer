# Changelog

All notable changes to the Entra Auth Tracer extension are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] — Phase 5

### Phase 5 - Polish & Enhanced UI

#### Added
- **Timeline View**
  - New view-mode toggle (List / Timeline) in the toolbar
  - Timeline mode groups requests into flow cards: Device Code sessions, OAuth clientId sessions, and standalone requests
  - Each flow card shows a header with flow-type badge, session label, start time, duration, and request count
  - Step-numbered rows inside each card with method, URL path, status icon, and a short step description
  - Clicking any row in a flow card selects that request and opens the detail panel
  - Column-header row is automatically hidden in Timeline mode and restored in List mode

- **Flow Correlation**
  - `findRelatedRequests()` identifies requests correlated by Device Code session key or by matching OAuth `client_id` within a 60-second window
  - Selecting a request applies a soft blue highlight (`.correlated-highlight`) to all correlated entries in the list
  - A "Flow" chip strip appears between the detail-panel header and the tab bar listing all requests in the same flow; clicking any chip navigates to that request
  - Highlights and the flow strip are cleared when the detail panel closes

- **PDF / Print Export**
  - New "PDF (Print)" option in the Export dropdown
  - Generates a self-contained print-optimised HTML report with an inline print-to-PDF guide banner
  - Report includes session summary stats, per-flow breakdown table, and expandable per-request sections (HTTP details, OAuth 2.1 analysis, FIDO2 analysis)
  - Downloaded as `.html`; opening the file and pressing Ctrl+P saves as PDF via the browser's native print dialog

- **Status Bar Breakdown**
  - `updateStatusBar()` now shows per-category counts (SAML, OAuth, FIDO2, Device Code) alongside the total and error count
  - Format: `N req · SAML: x, OAuth: y · N errors`

#### Changed
- Export menu now contains four options: JSON, Markdown (.md), Plain Text (.txt), PDF (Print)
- Toolbar layout updated to include the view-mode toggle group before the search bar



### Phase 2 - FIDO2 Decoder Implementation

#### Added
- **Complete FIDO2 CBOR Decoding**
  - Full `clientDataJSON` Base64url decoding and JSON parsing
  - Binary `authenticatorData` structure parsing with 32-byte RP ID hash extraction
  - Flag byte decomposition (UP, UV, AT, ED) with human-readable labels
  - Signature counter extraction and display
  
- **Attested Credential Data Support**
  - AAGUID parsing to UUID format with authenticator identification
  - Credential ID extraction with hex encoding
  - CBOR credential public key decoding with `cbor-web` integration
  
- **Multi-Key Type Support**
  - EC2 (Elliptic Curve) key support with curve identification (P-256, P-384, P-521, Ed25519)
  - RSA key support with modulus and exponent extraction
  - Algorithm recognition (ES256, RS256, PS256, EdDSA, etc.)
  - Graceful handling of unknown key types with raw CBOR fallback
  
- **Enhanced FIDO2 UI**
  - Rich visual display with emoji icons and structured layout
  - Flow type identification (Registration vs Authentication)
  - Interactive flag display with tooltips
  - Collapsible raw CBOR hex data viewer
  - Error handling with descriptive messages

#### Improved
- **Request Processing Pipeline**
  - Enhanced FIDO2 request detection for `/assertion`, `/attestation`, `/passkey` endpoints
  - Improved `/.well-known/webauthn` pre-flight detection
  - Better error handling and graceful degradation
  
- **Test Coverage**
  - Comprehensive Jest tests for CBOR decoding functions
  - Mock CBOR object testing for key type parsing
  - Edge case handling verification
  - Algorithm and curve description testing

### Phase 1 - Foundation Implementation

#### Added
- **Extension Infrastructure**
  - Chrome/Edge Manifest V2 with proper permissions (`webRequest`, `webRequestBlocking`, `<all_urls>`)
  - Webpack build pipeline with `cbor-web` bundling
  - Jest test framework with Chrome API mocks
  
- **Core Architecture** 
  - Background script with extension lifecycle management
  - SAMLTrace core with request interception framework
  - Modular decoder architecture (FIDO2, Entra Claims)
  
- **Modern UI System**
  - Microsoft Fluent-inspired design with CSS variables
  - Responsive layout with resizable panels
  - Dark theme support via `prefers-color-scheme`
  - Tabbed interface (HTTP, Parameters, SAML, Entra)
  
- **Request Management**
  - Smart authentication endpoint detection
  - Flow type classification and labeling
  - Request correlation and timeline tracking
  - Memory management with configurable limits

#### Dependencies
- `cbor-web ^9.0.0` - CBOR encoding/decoding for FIDO2 analysis
- `webpack ^5.88.0` - Module bundling and build pipeline
- `jest ^29.7.0` - Testing framework with jsdom environment

### Technical Specifications

#### FIDO2 Compliance
- **WebAuthn Specification**: Full compliance with W3C WebAuthn Level 2
- **CTAP Protocol**: Support for CTAP 1.0 and 2.0 authenticator data
- **COSE Standards**: RFC 8152 CBOR Object Signing and Encryption support
- **FIDO Alliance**: FIDO2 and FIDO U2F compatibility

#### Browser Support
- **Google Chrome**: Version 88+ (Manifest V2 support)
- **Microsoft Edge**: Version 88+ (Chromium-based)
- **WebExtensions API**: Chrome Extension APIs with `webRequest` v2

#### Security Features
- **Local-Only Processing**: No external data transmission
- **Sensitive Data Redaction**: Automatic `client_secret` and `refresh_token` masking
- **Memory Protection**: Request data cleared on extension restart
- **Minimal Permissions**: Only necessary browser APIs requested

---

## Coming in Future Releases

### Phase 3 - OAuth 2.1 Extensions (Planned)
- PKCE flow analysis with code challenge/verifier correlation
- Device Code flow sequence tracking with polling timeline
- Client Credentials machine-to-machine flow detection
- Grant type intelligence and security warnings

### Phase 4 - Entra Claims Decoder (Planned)  
- Comprehensive JWT claims registry for Entra-specific fields
- CAE (Continuous Access Evaluation) detection and badge display
- PoP (Proof-of-Possession) token binding analysis
- Token expiry warnings and security assessments

### Phase 5 - Enhanced Export & UI (Planned)
- Multi-format export (JSON, Markdown, TXT, PDF)
- Flow correlation with visual timeline
- Advanced search and filtering capabilities
- Chrome Web Store and Edge Add-ons publication