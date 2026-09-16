/**
 * Entra Auth Tracer - WebMCP bridge entry (injected into the ISOLATED world)
 * Bundled by webpack as dist/src/webmcp-bridge.js.
 */

import { installBridge } from './webmcp/bridgeRuntime.js';

installBridge(window, chrome);
