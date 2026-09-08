# PRD — Entra Auth Tracer WebMCP

- **Status:** Complete — v1.0 (implemented in extension release 1.2.0; see [Implementation notes](#implementation-notes-v120))
- **Author:** Darren Robinson
- **Date:** 2026-09-08
- **Repo:** `darrenjrobinson/EntraAuthTracer` (public, Chromium extension)
- **Delivery:** additive feature within the existing extension — no fork, no new repo

---

## 1. Problem / Opportunity

Entra Auth Tracer already captures, decodes, and enriches every auth event the
browser touches: OAuth 2.1/OIDC flows, SAML 2.0/WS-Fed, FIDO2/Passkey
assertions, Verified ID lifecycles, and full Entra JWT claim sets — including
correlated multi-step flows (device code, authz code), client authentication
methods, PKCE compliance checks, and 40+ decoded AMR values.

All of that decoded intelligence lives in `extensionState.requests` in the
background service worker, surfaced today only through the extension popup UI.
A security analyst or identity engineer has to click through the popup manually
to answer questions like *"any security issues with the auth I just did?"* or
*"walk me through that FIDO2 assertion"*.

**WebMCP turns that into a conversation.** Instead of clicking through the popup,
the user asks an AI agent in plain language and the agent calls typed WebMCP
tools — backed by the extension's already-decoded, already-local data — to
return structured answers instantly. No external API calls, no extra OAuth dance:
the data is already there.

**Consumer adoption status (mid-2026):** No mainstream AI agent client consumes
`navigator.modelContext` tools yet. Microsoft Edge 147 ships native WebMCP
support, making it the reference implementation browser; its co-authorship of the
spec with Google makes it the most natural first consumer. Chrome 149 is in an
open Origin Trial. Gemini-in-Chrome is the announced first mainstream agent
consumer. This is a forward-positioned surface: the extension popup remains the
primary UI, and the WebMCP layer is additive once a consuming agent is present.

**Almost nobody has shipped a WebMCP surface for a security/identity tool.**
This is a first in that space.

## 2. Goals

- Expose the extension's captured and decoded auth intelligence as **WebMCP tools
  available to AI agents** running in the user's browser (Edge 147+, Chrome
  origin-trial).
- Deliver as a **user-activated, per-tab** feature — not always-on — so the
  trust surface is narrow and the user controls when captured tokens are
  accessible to an AI agent.
- Require **zero external API calls**: all tool `execute()` paths read from
  `extensionState.requests` already held in the background service worker.
- Maintain **read-only** access — tools surface captured data; they do not
  modify browser state, trigger auth flows, or write to external systems.
- Stay within the existing `EntraAuthTracer` repo — this is an additive feature,
  not a new repo or fork.

## 3. Non-Goals

- **Not** an always-on background WebMCP service. Tools register only when the
  user explicitly activates WebMCP mode on the current tab.
- **Not** a remote or server-side tool surface — data never leaves the browser.
- **Not** a write path — no ability to modify, replay, or forge auth requests.
- **Not** a replacement for the popup UI. The popup remains the primary
  human-readable interface; WebMCP is the machine-readable complement.
- **Not** a separate hosted standalone page (unlike Polyarchy WebMCP). The
  content script injects directly into the active tab.

## 4. Architecture

```
User clicks "Enable WebMCP analysis" in the extension popup
  └─ chrome.tabs.executeScript → injects src/webmcp-content.js into active tab

src/webmcp-content.js (runs in the tab's https:// context)
  ├─ Feature-detects navigator.modelContext?.registerTool
  ├─ Registers 6 read-only tools
  └─ execute(args) → chrome.runtime.sendMessage({ action: 'webmcp', tool, args })
                          └─ background.js reads extensionState.requests
                          └─ returns decoded, structured JSON to the content script
                          └─ content script returns result to the AI agent

Extension popup (src/ui.html / ui.js)
  └─ "Enable WebMCP" toggle button
        ├─ active tab indicator — shows which tab has WebMCP armed
        └─ "Disable" button to unregisterTool() + remove content script

Background (src/background.js)
  └─ chrome.runtime.onMessage listener — handles 'webmcp' action type
  └─ reads extensionState.requests, applies filters/lookups, returns JSON
```

**Why content script injection (not an options/popup page):**

- WebMCP's `navigator.modelContext` is a `https://` page API. Extension pages
  (`chrome-extension://`) almost certainly do not have it available.
- Content scripts run in the tab's `https://` origin context — `navigator.modelContext`
  is available there in Edge 147+ and Chrome origin-trial.
- The content script communicates with the background (which holds all captured
  data) via `chrome.runtime.sendMessage` — the standard extension messaging path.

**Trust model:**

- User activation required — the "Enable WebMCP" button in the popup explicitly
  arms the current tab.
- Scoped to one tab at a time — the AI agent on that tab can query captured
  data; agents on other tabs cannot.
- Token data (JWTs, access tokens captured in traffic) is exposed to the AI
  agent when `get_session_detail` or `get_token_claims` is called. This is
  intentional — the user activated it — but must be clearly documented in the
  extension's WebMCP mode UI.
- On disable (or tab close), `unregisterTool()` is called for all tools and the
  content script removes itself.

**Manifest additions required:**

```json
{
  "permissions": ["scripting", "activeTab"],
  "host_permissions": ["<all_urls>"],
  "content_scripts": [],
  "web_accessible_resources": [{ "resources": ["webmcp-content.js"], "matches": ["<all_urls>"] }]
}
```

`scripting` + `activeTab` covers the injection; no new broad host permissions
are needed beyond what the extension already uses for `webRequest`.

## 5. Tool surface (v1 — read-only)

All tools are **read-only** and return structured JSON from already-decoded
`extensionState.requests`. No external API calls on any path.

| WebMCP tool | Source data | Purpose |
|---|---|---|
| `list_auth_sessions` | `extensionState.requests` | All captured auth events — flow type, provider, user/UPN, HTTP status, timestamp |
| `get_session_detail` | `extensionState.requests[id]` | Full decode for one event — JWT claims, SAML attributes, FIDO2 CBOR, flow label |
| `get_security_warnings` | All requests, security assessment fields | All security issues across captured traffic — severity, rule, affected session |
| `analyze_flow` | `deviceCodeCorrelation` + correlated requests | Correlated OAuth flow timeline — full device code, authz code, or OIDC lifecycle |
| `get_token_claims` | Decoded JWT from a captured token | Entra JWT claim set — 40+ labelled claims, AMR, device platform, CAE status |
| `search_sessions` | `extensionState.requests` with filter | Filter by flow type, provider, UPN/user, HTTP status, time range |

`inputSchema` (JSON Schema) for each tool:

```json
list_auth_sessions: { limit: number (opt, default 20), flowType: string (opt) }
get_session_detail: { sessionId: string (required) }
get_security_warnings: { severity: "error"|"warning"|"info" (opt) }
analyze_flow: { flowId: string (required) }
get_token_claims: { sessionId: string (required) }
search_sessions: { query: string (opt), flowType: string (opt), provider: string (opt), limit: number (opt) }
```

Per the post-March-2026 WebMCP spec, live context (current tab URL, number of
captured sessions, WebMCP mode active status) is **baked into each tool's
description** at registration time rather than passed via `provideContext()`.

## 6. WebMCP lifecycle rules

- Register all tools when the user clicks "Enable WebMCP" — after confirming the
  tab is `https://` and `navigator.modelContext?.registerTool` is available.
- Update each tool's `description` with current context at registration time:
  `"X sessions captured — WebMCP mode active on <url>"`.
- `unregisterTool()` on:
  - User clicks "Disable" in the popup
  - Tab navigates away (listen on `chrome.tabs.onUpdated` for the armed tab)
  - Tab closes (`chrome.tabs.onRemoved`)
  - Extension suspends (`chrome.runtime.onSuspend`)
- Never register tools on `http://` tabs — require `https://`.
- `agentInvoked` (Declarative API) is a **signal, not an auth gate** — analytics
  use only; actual authorization is the user's explicit activation decision.

## 7. Discovery surface

Because this is a content-script injection (not a hosted page), there is no
`.well-known/webmcp` manifest to serve. Discovery is implicit — the tools are
registered on the active tab when WebMCP mode is on, and any WebMCP-aware agent
in that browser session will see them.

A future v2 option: add a `toolname` Declarative API attribute to the extension's
options page so crawlers can discover the capability without JavaScript.

## 8. User stories

**US-1 — Post-auth security audit**
As a security engineer, I want my browser AI assistant to check the auth flow I
just completed for security issues, so I don't have to click through the tracer
popup manually.
- Given Auth Tracer has captured an OAuth flow and WebMCP mode is enabled,
- when I ask "any security issues with the auth I just did?",
- then the agent calls `get_security_warnings` and returns the severity-ranked
  list — PKCE method, token lifetime, missing CAE, public client, etc.

**US-2 — Token claim interrogation**
As an IAM engineer, I want to ask my assistant what specific claims are in the
token I just received, so I can verify the token matches what the app expects.
- Given an access token was captured in the last auth flow,
- when I ask "what claims are in that access token?",
- then the agent calls `get_token_claims` with the session ID and returns the
  full 40+ claim set with human-readable labels, AMR decoded, device platform,
  CAE status, and expiry.

**US-3 — Flow timeline walkthrough**
As a developer debugging an integration, I want the assistant to walk me through
the full OAuth flow timeline, so I can understand the exact sequence of requests
and where it broke.
- Given a correlated OAuth flow (e.g. device code or authz code with PKCE),
- when I ask "explain the auth flow that just happened",
- then the agent calls `analyze_flow` and returns the correlated timeline —
  each request in sequence, flow labels, timing, and any anomalies.

**US-4 — FIDO2 / Passkey assertion decode**
As a security architect, I want to inspect the FIDO2 assertion my client just
sent, so I can verify the authenticator data and flag any credential hygiene
issues.
- Given a FIDO2 assertion was captured (assertion POST + token exchange),
- when I ask "what authenticator was used and what does the assertion say?",
- then the agent calls `get_session_detail` on the assertion session and returns
  the full CBOR decode — AAGUID, RP ID hash, flags (UP/UV/AT/BE/BS), sign count,
  and the correlated token flow.

**US-5 — Multi-session search**
As a consultant reviewing a complex auth environment, I want to search captured
sessions by provider or user, so I can focus on a specific app or identity.
- Given multiple auth sessions have been captured across different providers,
- when I ask "show me all Okta sessions for user john@contoso.com",
- then the agent calls `search_sessions` with `{ provider: "okta", query: "john@contoso.com" }`
  and returns matching sessions with flow labels and status.

**US-6 — Verified ID flow decode**
As a Verified ID implementer, I want the assistant to explain the issuance or
presentation flow I just triggered, so I can verify the request structure and
callback setup.
- Given a Verified ID lifecycle was captured (issuance or presentation),
- when I ask "what happened in that Verified ID exchange?",
- then the agent calls `get_session_detail` on the Verified ID sessions and
  returns: operation type, credential type, authority DID, request ID, callback
  URL, and any warnings (localhost callback, PIN requirement).

**US-7 — Graceful degradation**
As a user on a browser without WebMCP support, I want the "Enable WebMCP"
button to inform me the browser isn't supported, so I'm not left confused.
- Given the user's browser lacks `navigator.modelContext`,
- when they click "Enable WebMCP",
- then the popup shows a clear message: "WebMCP requires Edge 147+ or Chrome
  149+ (Origin Trial). The popup UI works normally."

**US-8 — Per-tab trust, explicit deactivation**
As a security-conscious user, I want to be able to disable WebMCP mode at any
time, so captured token data is no longer accessible to AI agents on that tab.
- Given WebMCP mode is active on a tab,
- when I click "Disable" in the popup or navigate away,
- then all registered tools are unregistered immediately and the content script
  removes itself from the tab.

## 9. Milestones

- **M1 — Background message handler:** Add `'webmcp'` action type to
  `chrome.runtime.onMessage` in `background.js`; implement the 6 query
  functions over `extensionState.requests`; unit-test against existing test
  fixtures.
- **M2 — Content script:** Write `src/webmcp-content.js` — feature-detect,
  `registerTool()` with static schemas, `execute()` → `sendMessage` → returns
  JSON. Test in Edge 147+ DevTools with a mock background response.
- **M3 — Popup activation UI:** Add "Enable WebMCP" toggle to `ui.html`/`ui.js`;
  implement `chrome.tabs.executeScript` injection; track armed tab ID; listen
  for tab navigate/close events; call `unregisterTool()` on disable.
- **M4 — Manifest + permissions:** Add `scripting`, `activeTab`,
  `web_accessible_resources` for `webmcp-content.js`; verify no unintended
  permission scope creep; review CSP.
- **M5 — End-to-end test + publish:** Trigger a real auth flow in Edge 147+,
  enable WebMCP, ask Edge Copilot (or a test WebMCP client) to call each tool
  and verify structured responses. Update CHANGELOG. Blog post: *"I added a
  WebMCP surface to a security tool — your AI can now interrogate auth traffic."*

## 10. Risks / mitigations

- **Token data exposure to AI agents.** The most significant risk: captured JWTs
  and access tokens become accessible to any WebMCP-consuming agent in the armed
  tab. Mitigate: user activation required (no always-on), explicit disable path,
  clear UI labelling ("WebMCP mode active — AI can read captured tokens"), and
  prominent documentation in the extension's WebMCP section.
- **Content script injection permission creep.** `scripting` + `activeTab` are
  established permissions; `<all_urls>` host permission may trigger Chrome Web
  Store review notes. Mitigate: request only `activeTab` for injection (no
  broad host permission needed if using `chrome.scripting.executeScript` with
  the active tab).
- **`navigator.modelContext` unavailable in the injected context.** The content
  script runs in the tab's `https://` isolated world; `navigator.modelContext`
  should be available in Edge 147+ and Chrome origin-trial, but the isolated
  world may differ from the page's main world. Mitigate: inject into `MAIN`
  world (not `ISOLATED`) using `chrome.scripting.executeScript({ world: 'MAIN' })`.
- **Consumer adoption lag.** Same as Polyarchy WebMCP — no mainstream AI client
  calls `modelContext` tools yet. Mitigate: the extension popup remains fully
  functional regardless; WebMCP is additive. Re-evaluate at M5.
- **Spec still settling.** Origin-trial APIs can change. Mitigate: pin to
  current `registerTool`/`unregisterTool` surface; feature-detect defensively.
- **`extensionState` cleared on suspend.** Background service workers can be
  suspended by the browser, clearing `extensionState.requests`. If the background
  suspends while WebMCP mode is active, tool calls will return empty results.
  Mitigate: document in UI; consider persisting requests to `chrome.storage.session`
  in a future iteration.

## 11. Success criteria

- In Edge 147+, a user can: activate WebMCP mode → trigger an OAuth flow → ask
  an AI agent "any security issues?" → receive a structured list from
  `get_security_warnings`.
- All 6 tools return valid structured JSON for real captured sessions.
- Tool registration and deregistration happen correctly on enable/disable and
  on tab navigate/close.
- No performance impact on the extension's normal capture path (`webRequest`
  interception is unaffected).
- The "Enable WebMCP" button shows a clear unsupported message on browsers
  without `navigator.modelContext`.
- CHANGELOG updated; blog post published: *"First WebMCP surface for a
  browser-based auth tracing tool."*

## 12. References

- WebMCP spec and browser support:
  - W3C Web Machine Learning CG — WebMCP Draft Community Group Report (Apr 23,
    2026). Microsoft and Google co-editors.
  - State of WebMCP (Spronta, Jul 23, 2026) — spec status, Edge 147 native
    support, Chrome 149 origin trial.
  - WebMCP Checker — "Complete WebMCP Implementation Guide for 2026" (updated
    May 23, 2026) — current `registerTool`/`unregisterTool` surface, lifecycle
    rules, `agentInvoked`, post-March-2026 `provideContext()` removal.
- Chrome extension APIs:
  - `chrome.scripting.executeScript({ world: 'MAIN' })` — injects into the
    page's main JavaScript world (required for `navigator.modelContext` access).
  - `chrome.runtime.onMessage` — background message handler pattern.
  - `chrome.tabs.onUpdated` / `chrome.tabs.onRemoved` — tab lifecycle events
    for WebMCP mode cleanup.
- Upstream extension source:
  - `darrenjrobinson/EntraAuthTracer` — `src/background.js` (`extensionState`,
    `SAMLTrace.initialize`), `src/ui.js` (popup), `src/OAuthDecoder.js`,
    `src/EntraClaimsDecoder.js`, `src/Fido2Decoder.js`, `src/VerifiedIdDecoder.js`.
- Related PRD:
  - `prds/entrapulse-polyarchy-webmcp-prd.md` (v1.1) — sibling WebMCP surface;
    standalone hosted page model (vs. content script model here).

---

## Implementation notes (v1.2.0)

The PRD was implemented in release 1.2.0 with the following corrections, each
verified against the W3C draft and Chrome's extension documentation at build time:

| PRD | Shipped | Why |
|---|---|---|
| `navigator.modelContext.registerTool` | `document.modelContext` with a `navigator.modelContext` fallback (`src/webmcp/pageRuntime.js`) | The spec moved the API to `document`; Chrome deprecated `navigator.modelContext` in 150 while the 149–156 origin trial still ships it |
| `unregisterTool()` on disable | One `AbortController` per registration generation; `unregisterTool()` used only when a build exposes it; `InvalidStateError` on duplicate names handled by replacing the stale tool | The spec has no `unregisterTool`; tools unregister via `options.signal` or document unload, and `registerTool` rejects duplicate names |
| One content script calling `chrome.runtime.sendMessage` from the MAIN world | Two injected files: `src/webmcp-bridge.js` (isolated world, owns `chrome.runtime`) and `src/webmcp-page.js` (MAIN world, owns registration), linked by `window.postMessage` with origin/source/envelope checks | MAIN-world scripts have no `chrome.*` APIs |
| `chrome.tabs.executeScript`, `web_accessible_resources`, `activeTab` | `chrome.scripting.executeScript({ target, files, world })`; no `web_accessible_resources`; no `activeTab` | MV3 API; files passed to `executeScript` need no web exposure; `<all_urls>` already grants injection so `activeTab` would be redundant |
| Plain JSON from `execute()` | MCP-style `{ content: [{ type: 'text', text }] }`, `isError: true` on failure | Matches the explainer samples and survives the spec's JSON serialisation |
| Armed-tab state in the service worker | `chrome.storage.session` record, re-validated lazily after a worker restart | MV3 workers terminate after ~30 s idle |
| "Tab navigates away" disarms | A new document load or a cross-origin URL change disarms; a same-origin SPA route change keeps the registration | Registrations belong to the document, which survives `history.pushState` |
| `provider` and `user/UPN` fields | New `src/ProviderDetector.js` stamps a provider on every capture; user derived from `login_hint`, ROPC `username`, JWT claims | Neither existed in the codebase |
| SAML attributes in `get_session_detail` | `SamlDecoder.parseLite` (regex) is used automatically in the worker | Service workers have no `DOMParser` |
| Raw tokens in tool output | Claims only; `code`, device codes and all redaction-policy secrets are removed | No analytic value for an agent, replay risk if leaked |

The trust banner reads *WebMCP mode active on `<host>` — AI agents in this tab can
read captured tokens*, and README/PRIVACY note that the page's own scripts can also
invoke the registered tools, because WebMCP tools live on the page's model context.
