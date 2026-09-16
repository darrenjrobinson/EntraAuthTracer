/**
 * Entra Auth Tracer - WebMCP popup presentation
 *
 * Maps the controller's status snapshot to what the popup shows: the toggle
 * button's label/state and the trust banner. Pure so the wording — including the
 * PRD's "AI can read captured tokens" disclosure — is unit-tested.
 */

class WebMcpStatusText {
  static ENABLE_LABEL = 'Enable WebMCP';
  static DISABLE_LABEL = 'Disable WebMCP';
  static ENABLE_TITLE = 'Expose captured auth data (read-only) to AI agents in the active https tab';
  static DISABLE_TITLE = 'Stop exposing captured data to AI agents';

  /**
   * @param {object|null} status   controller.status() snapshot
   * @param {{ dismissedError?: string|null }} [opts]
   * @returns {{ buttonLabel, title, pressed, disabled, active, banner: null | { kind, text, action, actionLabel } }}
   */
  static describeStatus(status, opts = {}) {
    const s = status || { phase: 'idle' };
    const dismissedError = opts.dismissedError || null;

    switch (s.phase) {
      case 'arming':
        return { buttonLabel: 'Enabling…', title: WebMcpStatusText.ENABLE_TITLE, pressed: false, disabled: true, active: false, banner: null };
      case 'disarming':
        return { buttonLabel: 'Disabling…', title: WebMcpStatusText.DISABLE_TITLE, pressed: true, disabled: true, active: true, banner: null };
      case 'armed': {
        const where = s.host || s.origin || 'this tab';
        const count = typeof s.toolCount === 'number' ? s.toolCount : 0;
        let text = `WebMCP mode active on ${where} — AI agents in this tab can read captured tokens. ${count} tool${count === 1 ? '' : 's'} registered.`;
        if (s.lastError) text += ` ${s.lastError}`;
        return {
          buttonLabel: WebMcpStatusText.DISABLE_LABEL,
          title: WebMcpStatusText.DISABLE_TITLE,
          pressed: true,
          disabled: false,
          active: true,
          banner: { kind: 'active', text, action: 'disable', actionLabel: 'Disable' }
        };
      }
      default: {
        const showError = s.lastError && s.lastError !== dismissedError;
        return {
          buttonLabel: WebMcpStatusText.ENABLE_LABEL,
          title: WebMcpStatusText.ENABLE_TITLE,
          pressed: false,
          disabled: false,
          active: false,
          banner: showError ? { kind: 'warn', text: s.lastError, action: 'dismiss', actionLabel: 'Dismiss' } : null
        };
      }
    }
  }
}

export default WebMcpStatusText;
