/**
 * Jest test setup for Entra Auth Tracer
 */

// Mock Chrome APIs for testing
global.chrome = {
  runtime: {
    onMessage: {
      addListener: jest.fn()
    },
    onStartup: {
      addListener: jest.fn()
    },
    onSuspend: {
      addListener: jest.fn()
    },
    sendMessage: jest.fn((message, callback) => {
      // Simulate async response
      setTimeout(() => {
        if (typeof callback === 'function') callback({ success: true, requests: [] });
      }, 10);
    }),
    getManifest: jest.fn(() => ({ version: '1.1.0-test', name: 'Entra Auth Tracer' })),
    getURL: jest.fn((p) => 'chrome-extension://test-extension-id/' + p)
  },
  action: {
    setBadgeText: jest.fn(),
    setBadgeBackgroundColor: jest.fn()
  },
  windows: {
    create: jest.fn()
  },
  webRequest: {
    onBeforeRequest: {
      addListener: jest.fn(),
      removeListener: jest.fn()
    },
    onBeforeSendHeaders: {
      addListener: jest.fn(),
      removeListener: jest.fn()
    },
    onHeadersReceived: {
      addListener: jest.fn(),
      removeListener: jest.fn()
    },
    onCompleted: {
      addListener: jest.fn(),
      removeListener: jest.fn()
    },
    onErrorOccurred: {
      addListener: jest.fn(),
      removeListener: jest.fn()
    }
  }
};

// jsdom does not expose TextEncoder/TextDecoder — use Node's implementations
if (typeof TextDecoder === 'undefined' || typeof TextEncoder === 'undefined') {
  const util = require('util');
  if (typeof TextEncoder === 'undefined') global.TextEncoder = util.TextEncoder;
  if (typeof TextDecoder === 'undefined') global.TextDecoder = util.TextDecoder;
}

// jsdom lacks CSS.escape (used by the UI to build attribute selectors)
if (typeof CSS === 'undefined' || typeof CSS.escape !== 'function') {
  global.CSS = Object.assign(global.CSS || {}, {
    escape: (s) => String(s).replace(/[^a-zA-Z0-9_-]/g, (c) => '\\' + c)
  });
}

// jsdom lacks Blob URL helpers (used by the UI download path)
if (typeof URL.createObjectURL !== 'function') {
  URL.createObjectURL = jest.fn(() => 'blob:mock-url');
  URL.revokeObjectURL = jest.fn();
}

// Mock atob/btoa for base64 operations
if (typeof atob === 'undefined') {
  global.atob = (str) => Buffer.from(str, 'base64').toString('binary');
  global.btoa = (str) => Buffer.from(str, 'binary').toString('base64');
}

// Polyfill DecompressionStream using Node.js zlib (jsdom does not provide it)
if (typeof DecompressionStream === 'undefined') {
  const zlib = require('zlib');
  global.DecompressionStream = class DecompressionStream {
    constructor(_format) {
      let _inputBytes = null;
      this.writable = {
        getWriter: () => ({
          write: (chunk) => { _inputBytes = chunk; },
          close: () => {}
        })
      };
      this.readable = {
        getReader: () => {
          let _sent = false;
          return {
            read: async () => {
              if (!_sent) {
                _sent = true;
                const decompressed = zlib.inflateRawSync(Buffer.from(_inputBytes));
                return { done: false, value: new Uint8Array(decompressed) };
              }
              return { done: true, value: undefined };
            }
          };
        }
      };
    }
  };
}