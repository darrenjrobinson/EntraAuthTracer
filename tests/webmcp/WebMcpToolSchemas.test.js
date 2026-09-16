/**
 * Tests for WebMcpToolSchemas — tool definitions, description baking, validation.
 */

import WebMcpToolSchemas from '../../src/webmcp/WebMcpToolSchemas.js';

describe('WebMcpToolSchemas', () => {
  it('defines exactly the six PRD tools with valid WebMCP names', () => {
    expect(WebMcpToolSchemas.TOOL_NAMES).toEqual([
      'list_auth_sessions', 'get_session_detail', 'get_security_warnings',
      'analyze_flow', 'get_token_claims', 'search_sessions'
    ]);
    for (const name of WebMcpToolSchemas.TOOL_NAMES) {
      expect(WebMcpToolSchemas.isValidToolName(name)).toBe(true);
      expect(WebMcpToolSchemas.TOOLS[name].name).toBe(name);
      expect(typeof WebMcpToolSchemas.TOOLS[name].title).toBe('string');
      expect(WebMcpToolSchemas.TOOLS[name].inputSchema.type).toBe('object');
      expect(WebMcpToolSchemas.TOOLS[name].inputSchema.additionalProperties).toBe(false);
    }
    expect(WebMcpToolSchemas.isValidToolName('has space')).toBe(false);
    expect(WebMcpToolSchemas.isValidToolName('x'.repeat(129))).toBe(false);
  });

  it('bakes the session count and origin into every description', () => {
    const d = WebMcpToolSchemas.describe('list_auth_sessions', { sessionCount: 7, origin: 'https://portal.azure.com' });
    expect(d).toContain('7 auth sessions captured — WebMCP mode active on https://portal.azure.com');
    expect(d).toContain('responses (issued tokens) are not visible');
    expect(WebMcpToolSchemas.describe('analyze_flow', { sessionCount: 1, origin: 'https://x' })).toContain('1 auth session captured');
    expect(WebMcpToolSchemas.describe('search_sessions')).toContain('0 auth sessions captured — WebMCP mode active on this tab');
    expect(() => WebMcpToolSchemas.describe('nope')).toThrow(/Unknown tool/);
  });

  it('builds a structured-clone-safe manifest with read-only annotations', () => {
    const manifest = WebMcpToolSchemas.buildManifest({ sessionCount: 2, origin: 'https://example.com' });
    expect(manifest).toHaveLength(6);
    for (const tool of manifest) {
      expect(tool.annotations).toEqual({ readOnlyHint: true, untrustedContentHint: true, consequentialHint: false });
      expect(tool.description).toContain('2 auth sessions captured');
      // plain data only: survives JSON round-trip unchanged (no functions, no class instances)
      expect(JSON.parse(JSON.stringify(tool))).toEqual(tool);
    }
    // manifest schemas are copies, not shared references
    manifest[0].inputSchema.properties.limit.default = 99;
    expect(WebMcpToolSchemas.TOOLS.list_auth_sessions.inputSchema.properties.limit.default).toBe(20);
  });

  describe('validateArgs', () => {
    it('applies defaults, coerces numeric strings and clamps integers', () => {
      expect(WebMcpToolSchemas.validateArgs('list_auth_sessions', {})).toEqual({ ok: true, value: { limit: 20 } });
      expect(WebMcpToolSchemas.validateArgs('list_auth_sessions', { limit: '5' }).value.limit).toBe(5);
      expect(WebMcpToolSchemas.validateArgs('list_auth_sessions', { limit: 500 }).value.limit).toBe(100);
      expect(WebMcpToolSchemas.validateArgs('list_auth_sessions', { limit: 0 }).value.limit).toBe(1);
      expect(WebMcpToolSchemas.validateArgs('list_auth_sessions', null).value.limit).toBe(20);
    });

    it('rejects non-integers, wrong types, unknown enum values and non-object args', () => {
      expect(WebMcpToolSchemas.validateArgs('list_auth_sessions', { limit: 2.5 }).ok).toBe(false);
      expect(WebMcpToolSchemas.validateArgs('list_auth_sessions', { limit: 'ten' }).ok).toBe(false);
      expect(WebMcpToolSchemas.validateArgs('list_auth_sessions', { flowType: 5 }).ok).toBe(false);
      expect(WebMcpToolSchemas.validateArgs('get_security_warnings', { severity: 'critical' })).toEqual({ ok: false, error: 'severity must be one of: error, warning, info' });
      expect(WebMcpToolSchemas.validateArgs('list_auth_sessions', 'x').ok).toBe(false);
      expect(WebMcpToolSchemas.validateArgs('list_auth_sessions', [1]).ok).toBe(false);
    });

    it('enforces required properties and trims strings', () => {
      expect(WebMcpToolSchemas.validateArgs('get_session_detail', {})).toEqual({ ok: false, error: 'sessionId is required' });
      expect(WebMcpToolSchemas.validateArgs('get_session_detail', { sessionId: '  req_1 ' }).value).toEqual({ sessionId: 'req_1' });
      expect(WebMcpToolSchemas.validateArgs('analyze_flow', { flowId: '' }).ok).toBe(false);
    });

    it('drops unknown properties and reports unknown tools', () => {
      const v = WebMcpToolSchemas.validateArgs('search_sessions', { query: 'x', bogus: 1, statusCode: '401' });
      expect(v.ok).toBe(true);
      expect(v.value).toEqual({ query: 'x', statusCode: 401, limit: 20 });
      expect(WebMcpToolSchemas.validateArgs('unknown_tool', {}).ok).toBe(false);
    });
  });
});
