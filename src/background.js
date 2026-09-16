/**
 * Entra Auth Tracer - Background Script
 * Main entry point for the browser extension
 * 
 * Fork of SimpleSAMLphp SAML-tracer (BSD-2-Clause)
 * Extended with Entra-specific capabilities
 */

import SAMLTrace from './SAMLTrace.js';
import WebMcpController from './webmcp/WebMcpController.js';

// Extension state
const extensionState = {
  requests: [],
  deviceCodeCorrelation: new Map(),
  fido2Sessions: [],
  isActive: false,
  badgeCount: 0
};

// WebMCP mode — exposes captured data to AI agents in one user-selected tab
const webmcp = new WebMcpController({
  chrome,
  getRequests: () => extensionState.requests
});
// Tab listeners must be registered synchronously at service-worker top level
webmcp.attachListeners();

// ─── Badge management ────────────────────────────────────────────────────────

/**
 * Called by SAMLTrace whenever a new authoritative auth request is stored.
 * Increments the toolbar badge counter.
 */
function onNewAuthRequest() {
  extensionState.badgeCount++;
  chrome.action.setBadgeText({ text: String(extensionState.badgeCount) });
  webmcp.notifySessionsChanged();
}

/**
 * Reset the badge to zero (called when the popup is opened).
 */
function resetBadge() {
  extensionState.badgeCount = 0;
  chrome.action.setBadgeText({ text: '' });
}

/**
 * Initialize the extension
 */
function initializeExtension() {
  console.log('Entra Auth Tracer: Initializing...');

  // Wire up the badge callback so SAMLTrace can notify on new requests
  extensionState.onNewAuthRequest = onNewAuthRequest;

  // Set a persistent badge background colour (Entra blue)
  chrome.action.setBadgeBackgroundColor({ color: '#0078D4' });

  // Initialize SAML tracer with Entra extensions
  SAMLTrace.initialize(extensionState);
  
  // Set up extension lifecycle handlers
  chrome.runtime.onStartup.addListener(onExtensionStartup);
  chrome.runtime.onSuspend.addListener(onExtensionSuspend);

  // Re-validate any WebMCP armed tab persisted before a service-worker restart
  webmcp.ensureRestored();

  console.log('Entra Auth Tracer: Ready');
}

/**
 * Handle extension startup
 */
function onExtensionStartup() {
  console.log('Entra Auth Tracer: Extension starting up');
  extensionState.isActive = true;
}

/**
 * Handle extension suspend
 */
function onExtensionSuspend() {
  console.log('Entra Auth Tracer: Extension suspending');
  extensionState.isActive = false;
  
  // Clear sensitive data
  extensionState.deviceCodeCorrelation.clear();
  extensionState.fido2Sessions = [];
}

/**
 * Get extension state for UI — returns a plain-object-safe copy.
 * Maps and other non-cloneable types must be converted before passing
 * through chrome.runtime.sendMessage (structured clone).
 */
function getExtensionState() {
  return {
    requests: extensionState.requests,
    deviceCodeCorrelation: Object.fromEntries(extensionState.deviceCodeCorrelation),
    fido2Sessions: extensionState.fido2Sessions,
    isActive: extensionState.isActive,
    webmcp: webmcp.status()
  };
}

// Message handling for popup and WebMCP bridge communication
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  // WebMCP actions are asynchronous — keep the channel open and respond later
  if (request && typeof request.action === 'string' && request.action.startsWith('webmcp:')) {
    webmcp.handleMessage(request, sender).then(
      (response) => sendResponse(response),
      (err) => sendResponse({ ok: false, code: 'internal', error: err && err.message ? err.message : String(err) })
    );
    return true;
  }

  switch (request.action) {
    case 'getState':
      sendResponse(getExtensionState());
      break;
    case 'clearData':
      extensionState.requests = [];
      extensionState.deviceCodeCorrelation.clear();
      extensionState.fido2Sessions = [];
      resetBadge();
      webmcp.notifySessionsChanged();
      sendResponse({ success: true });
      break;
    case 'resetBadge':
      resetBadge();
      sendResponse({ success: true });
      break;
    case 'exportData':
      // Export is handled entirely in the UI layer (ui.js doExport/buildJsonExport etc.)
      sendResponse({ success: true });
      break;
    default:
      sendResponse({ success: false, error: 'Unknown action' });
  }
});

// Initialize when background script loads
initializeExtension();

// Export for testing
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    initializeExtension,
    getExtensionState,
    resetBadge,
    onNewAuthRequest,
    onExtensionStartup,
    onExtensionSuspend,
    extensionState,
    webmcp
  };
}