/**
 * Jest test setup for Entra Auth Tracer
 */

// Mock Chrome APIs for testing
global.chrome = {
  runtime: {
    onMessage: {
      addListener: jest.fn()
    },
    sendMessage: jest.fn((message, callback) => {
      // Simulate async response
      setTimeout(() => {
        callback({ success: true, requests: [] });
      }, 10);
    })
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