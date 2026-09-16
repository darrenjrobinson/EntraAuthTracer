/**
 * Tests for WebMcpStatusText — popup wording for each WebMCP phase.
 */

import WebMcpStatusText from '../../src/webmcp/WebMcpStatusText.js';
import { UNSUPPORTED_MESSAGE } from '../../src/webmcp/protocol.js';

describe('WebMcpStatusText.describeStatus', () => {
  it('idle: Enable button, no banner', () => {
    expect(WebMcpStatusText.describeStatus({ phase: 'idle', armed: false, lastError: null })).toEqual({
      buttonLabel: 'Enable WebMCP',
      title: WebMcpStatusText.ENABLE_TITLE,
      pressed: false, disabled: false, active: false, banner: null
    });
    expect(WebMcpStatusText.describeStatus(null).buttonLabel).toBe('Enable WebMCP');
  });

  it('arming / disarming: disabled button with progress label', () => {
    expect(WebMcpStatusText.describeStatus({ phase: 'arming' })).toMatchObject({ buttonLabel: 'Enabling…', disabled: true, pressed: false, banner: null });
    expect(WebMcpStatusText.describeStatus({ phase: 'disarming' })).toMatchObject({ buttonLabel: 'Disabling…', disabled: true, pressed: true, banner: null });
  });

  it('armed: Disable button and the trust banner naming the host and tool count', () => {
    const view = WebMcpStatusText.describeStatus({ phase: 'armed', armed: true, host: 'portal.azure.com', origin: 'https://portal.azure.com', toolCount: 6, lastError: null });
    expect(view).toMatchObject({ buttonLabel: 'Disable WebMCP', pressed: true, disabled: false, active: true });
    expect(view.banner).toEqual({
      kind: 'active',
      text: 'WebMCP mode active on portal.azure.com — AI agents in this tab can read captured tokens. 6 tools registered.',
      action: 'disable',
      actionLabel: 'Disable'
    });
  });

  it('armed with a refresh problem appends the error to the banner', () => {
    const view = WebMcpStatusText.describeStatus({ phase: 'armed', host: 'x.example', toolCount: 1, lastError: 'Could not refresh tool descriptions (timed out).' });
    expect(view.banner.text).toBe('WebMCP mode active on x.example — AI agents in this tab can read captured tokens. 1 tool registered. Could not refresh tool descriptions (timed out).');
  });

  it('idle with an error shows the US-7 text verbatim with a Dismiss action', () => {
    const view = WebMcpStatusText.describeStatus({ phase: 'idle', lastError: UNSUPPORTED_MESSAGE, supported: false });
    expect(view.buttonLabel).toBe('Enable WebMCP');
    expect(view.banner).toEqual({ kind: 'warn', text: 'WebMCP requires Edge 147+ or Chrome 149+ (Origin Trial). The popup UI works normally.', action: 'dismiss', actionLabel: 'Dismiss' });
  });

  it('hides a dismissed error until the message changes', () => {
    const status = { phase: 'idle', lastError: 'Boom' };
    expect(WebMcpStatusText.describeStatus(status, { dismissedError: 'Boom' }).banner).toBeNull();
    expect(WebMcpStatusText.describeStatus({ phase: 'idle', lastError: 'Other' }, { dismissedError: 'Boom' }).banner.text).toBe('Other');
  });
});
