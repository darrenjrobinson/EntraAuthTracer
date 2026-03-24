/**
 * Entra Auth Tracer - Background Script
 * Main entry point for the browser extension
 * 
 * Fork of SimpleSAMLphp SAML-tracer (BSD-2-Clause)
 * Extended with Entra-specific capabilities
 */

import SAMLTrace from './SAMLTrace.js';

// Extension state
const extensionState = {
  requests: [],
  deviceCodeCorrelation: new Map(),
  fido2Sessions: [],
  isActive: false
};

/**
 * Initialize the extension
 */
function initializeExtension() {
  console.log('Entra Auth Tracer: Initializing...');
  
  // Initialize SAML tracer with Entra extensions
  SAMLTrace.initialize(extensionState);
  
  // Set up extension lifecycle handlers
  chrome.runtime.onStartup.addListener(onExtensionStartup);
  chrome.runtime.onSuspend.addListener(onExtensionSuspend);
  
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
    isActive: extensionState.isActive
  };
}

// Message handling for popup communication
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  switch (request.action) {
    case 'getState':
      sendResponse(getExtensionState());
      break;
    case 'clearData':
      extensionState.requests = [];
      extensionState.deviceCodeCorrelation.clear();
      extensionState.fido2Sessions = [];
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
    extensionState
  };
}