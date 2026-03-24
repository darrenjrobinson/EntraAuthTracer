/**
 * Tests for background.js
 *
 * background.js calls initializeExtension() at module load time, which
 * calls SAMLTrace.initialize(). Jest module mocking ensures that real
 * Chrome webRequest listeners are never registered during tests.
 */

// SAMLTrace must be mocked BEFORE background.js is required so that the
// module-level initializeExtension() call does not throw.
jest.mock('../src/SAMLTrace.js', () => ({
  __esModule: true,
  default: {
    initialize: jest.fn()
  }
}));

// Capture the onMessage listener at require-time by storing it from the mock.
// background.js calls chrome.runtime.onMessage.addListener(fn) once at load.
// We intercept it before requiring the module.
let capturedMessageHandler = null;
chrome.runtime.onMessage.addListener.mockImplementation((fn) => {
  capturedMessageHandler = fn;
});

// Also capture the onStartup and onSuspend listeners before load.
let capturedStartupHandler = null;
let capturedSuspendHandler = null;
chrome.runtime.onStartup.addListener.mockImplementation((fn) => {
  capturedStartupHandler = fn;
});
chrome.runtime.onSuspend.addListener.mockImplementation((fn) => {
  capturedSuspendHandler = fn;
});

// Import the background module — it runs initializeExtension() as a
// side-effect, which exercises badge setup and SAMLTrace wiring.
const bg = require('../src/background.js');

describe('background.js', () => {
  beforeEach(() => {
    // Reset badge-related mocks between tests
    jest.clearAllMocks();
    // Reset badgeCount on the shared extensionState
    bg.extensionState.badgeCount = 0;
    bg.extensionState.requests = [];
    bg.extensionState.deviceCodeCorrelation = new Map();
    bg.extensionState.fido2Sessions = [];
    bg.extensionState.isActive = false;
  });

  // ─── onNewAuthRequest ────────────────────────────────────────────────────

  describe('onNewAuthRequest', () => {
    it('should increment badgeCount and call setBadgeText', () => {
      bg.onNewAuthRequest();
      expect(bg.extensionState.badgeCount).toBe(1);
      expect(chrome.action.setBadgeText).toHaveBeenCalledWith({ text: '1' });
    });

    it('should accumulate badge count across multiple calls', () => {
      bg.onNewAuthRequest();
      bg.onNewAuthRequest();
      bg.onNewAuthRequest();
      expect(bg.extensionState.badgeCount).toBe(3);
      expect(chrome.action.setBadgeText).toHaveBeenLastCalledWith({ text: '3' });
    });
  });

  // ─── resetBadge ──────────────────────────────────────────────────────────

  describe('resetBadge', () => {
    it('should reset badgeCount to 0 and clear badge text', () => {
      bg.extensionState.badgeCount = 5;
      bg.resetBadge();
      expect(bg.extensionState.badgeCount).toBe(0);
      expect(chrome.action.setBadgeText).toHaveBeenCalledWith({ text: '' });
    });
  });

  // ─── getExtensionState ───────────────────────────────────────────────────

  describe('getExtensionState', () => {
    it('should return a structured snapshot of extension state', () => {
      bg.extensionState.requests = [{ id: 'req_1' }];
      bg.extensionState.isActive = true;
      bg.extensionState.deviceCodeCorrelation.set('key1', ['req_1']);
      bg.extensionState.fido2Sessions = [{ id: 'f1' }];

      const state = bg.getExtensionState();
      expect(state.requests).toHaveLength(1);
      expect(state.isActive).toBe(true);
      expect(state.deviceCodeCorrelation).toEqual({ key1: ['req_1'] });
      expect(state.fido2Sessions).toHaveLength(1);
    });

    it('should convert Map to plain object for structured-clone safety', () => {
      bg.extensionState.deviceCodeCorrelation.set('dc:abc', ['r1', 'r2']);
      const state = bg.getExtensionState();
      expect(typeof state.deviceCodeCorrelation).toBe('object');
      expect(state.deviceCodeCorrelation['dc:abc']).toEqual(['r1', 'r2']);
    });
  });

  // ─── Message handler ─────────────────────────────────────────────────────

  describe('message handler', () => {
    function sendMessage(action, extraProps = {}) {
      if (!capturedMessageHandler) throw new Error('No onMessage listener captured');
      const sendResponse = jest.fn();
      capturedMessageHandler({ action, ...extraProps }, {}, sendResponse);
      return sendResponse;
    }

    it('should respond to getState with current state', () => {
      bg.extensionState.requests = [{ id: 'r1' }];
      const sendResponse = sendMessage('getState');
      expect(sendResponse).toHaveBeenCalledWith(
        expect.objectContaining({ requests: expect.any(Array) })
      );
    });

    it('should clear data on clearData message', () => {
      bg.extensionState.requests = [{ id: 'r1' }];
      bg.extensionState.badgeCount = 3;
      const sendResponse = sendMessage('clearData');
      expect(bg.extensionState.requests).toHaveLength(0);
      expect(bg.extensionState.badgeCount).toBe(0);
      expect(sendResponse).toHaveBeenCalledWith({ success: true });
    });

    it('should reset badge on resetBadge message', () => {
      bg.extensionState.badgeCount = 7;
      const sendResponse = sendMessage('resetBadge');
      expect(bg.extensionState.badgeCount).toBe(0);
      expect(sendResponse).toHaveBeenCalledWith({ success: true });
    });

    it('should acknowledge exportData message silently', () => {
      const sendResponse = sendMessage('exportData');
      expect(sendResponse).toHaveBeenCalledWith({ success: true });
    });

    it('should return error for unknown action', () => {
      const sendResponse = sendMessage('unknownAction');
      expect(sendResponse).toHaveBeenCalledWith(
        expect.objectContaining({ success: false, error: 'Unknown action' })
      );
    });
  });

  // ─── Lifecycle handlers ──────────────────────────────────────────────────

  describe('onExtensionStartup', () => {
    it('should set isActive to true', () => {
      bg.extensionState.isActive = false;
      bg.onExtensionStartup();
      expect(bg.extensionState.isActive).toBe(true);
    });

    it('should also be invokable via the captured startup listener', () => {
      bg.extensionState.isActive = false;
      if (capturedStartupHandler) capturedStartupHandler();
      expect(bg.extensionState.isActive).toBe(true);
    });
  });

  describe('onExtensionSuspend', () => {
    it('should set isActive to false and clear sensitive data', () => {
      bg.extensionState.isActive = true;
      bg.extensionState.deviceCodeCorrelation.set('key', ['r1']);
      bg.extensionState.fido2Sessions = [{ id: 'f1' }];

      bg.onExtensionSuspend();

      expect(bg.extensionState.isActive).toBe(false);
      expect(bg.extensionState.deviceCodeCorrelation.size).toBe(0);
      expect(bg.extensionState.fido2Sessions).toHaveLength(0);
    });

    it('should also be invokable via the captured suspend listener', () => {
      bg.extensionState.isActive = true;
      if (capturedSuspendHandler) capturedSuspendHandler();
      expect(bg.extensionState.isActive).toBe(false);
    });
  });
});
