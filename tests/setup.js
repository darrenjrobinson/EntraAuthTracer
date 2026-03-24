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
        callback({ success: true, requests: [] });
      }, 10);
    })
  },
  action: {
    setBadgeText: jest.fn(),
    setBadgeBackgroundColor: jest.fn()
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

// Mock TextDecoder for Node.js environment
if (typeof TextDecoder === 'undefined') {
  global.TextDecoder = class TextDecoder {
    decode(buffer) {
      return Buffer.from(buffer).toString('utf-8');
    }
  };
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