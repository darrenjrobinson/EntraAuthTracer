/**
 * Entra Auth Tracer - popup bootstrap
 *
 * Kept separate from ui.js so the UI class can be imported (and tested)
 * without instantiating itself on load.
 */

import EntraAuthTracerUI from './ui.js';

document.addEventListener('DOMContentLoaded', () => {
  new EntraAuthTracerUI();
});
