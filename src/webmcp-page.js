/**
 * Entra Auth Tracer - WebMCP page entry (injected into the MAIN world)
 * Bundled by webpack as dist/src/webmcp-page.js.
 */

import { installPageRuntime } from './webmcp/pageRuntime.js';

installPageRuntime(window, document);
