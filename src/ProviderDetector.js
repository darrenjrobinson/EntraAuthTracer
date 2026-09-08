/**
 * Entra Auth Tracer - Identity provider detection
 *
 * Maps a request URL to the identity provider / product behind it, using the
 * same host, suffix and path knowledge SAMLTrace uses to decide what to capture.
 * Pure and side-effect free; usable from the popup, the service worker and tests.
 */

class ProviderDetector {
  static PROVIDERS = {
    'entra':             { label: 'Microsoft Entra ID' },
    'microsoft-account': { label: 'Microsoft account (MSA)' },
    'entra-verified-id': { label: 'Microsoft Entra Verified ID' },
    'did-resolver':      { label: 'DID resolver' },
    'google':            { label: 'Google' },
    'firebase':          { label: 'Firebase Authentication' },
    'okta':              { label: 'Okta' },
    'cognito':           { label: 'AWS Cognito' },
    'adfs':              { label: 'Microsoft ADFS' },
    'shibboleth':        { label: 'Shibboleth' },
    'identityserver':    { label: 'IdentityServer / Duende' },
    'unknown':           { label: 'Unknown' }
  };

  /** Exact hostnames (lower-case). */
  static HOSTS = {
    'login.microsoftonline.com': 'entra',
    'login.microsoftonline.us': 'entra',
    'login.microsoftonline.de': 'entra',
    'login.partner.microsoftonline.cn': 'entra',
    'login.microsoft.com': 'entra',
    'login.windows.net': 'entra',
    'sts.windows.net': 'entra',
    'login.live.com': 'microsoft-account',
    'accounts.google.com': 'google',
    'oauth2.googleapis.com': 'google',
    'openidconnect.googleapis.com': 'google',
    'securetoken.googleapis.com': 'firebase',
    'identitytoolkit.googleapis.com': 'firebase',
    'verifiedid.did.msidentity.com': 'entra-verified-id',
    'beta.did.msidentity.com': 'entra-verified-id',
    'did.msidentity.com': 'entra-verified-id',
    'request.msidentity.com': 'entra-verified-id',
    'resolver.msidentity.com': 'did-resolver',
    'resolver.identity.foundation': 'did-resolver'
  };

  /** Hostname suffixes for tenant-specific domains. */
  static SUFFIXES = [
    ['.okta.com', 'okta'],
    ['.oktapreview.com', 'okta'],
    ['.okta-emea.com', 'okta'],
    ['.amazoncognito.com', 'cognito'],
    ['.b2clogin.com', 'entra'],   // Azure AD B2C
    ['.ciamlogin.com', 'entra']   // Microsoft Entra External ID
  ];

  /** Path patterns that identify a product regardless of host. */
  static PATHS = [
    [/\/adfs\//i, 'adfs'],
    [/Shibboleth\.sso/i, 'shibboleth'],
    [/\/idp\/profile\/SAML2\//i, 'shibboleth'],
    [/\/api\/v1\/authn/i, 'okta'],
    [/\/idp\/idx\//i, 'okta'],
    [/\/connect\/(token|authorize|userinfo|endsession|introspect|revocation|deviceauthorization|checksession)/i, 'identityserver']
  ];

  /**
   * Detect the provider for a URL.
   * @param {string|URL} urlOrString
   * @returns {{ id: string, label: string, hostname: string|null }}
   */
  static detect(urlOrString) {
    let url;
    try {
      url = urlOrString instanceof URL ? urlOrString : new URL(String(urlOrString));
    } catch {
      return { id: 'unknown', label: 'Unknown', hostname: null };
    }
    const hostname = url.hostname.toLowerCase();

    let id = ProviderDetector.HOSTS[hostname] || null;
    if (!id) {
      const suffix = ProviderDetector.SUFFIXES.find(([s]) => hostname.endsWith(s));
      if (suffix) id = suffix[1];
    }
    if (!id) {
      const path = ProviderDetector.PATHS.find(([re]) => re.test(url.pathname));
      if (path) id = path[1];
    }
    if (!id) return { id: 'unknown', label: hostname, hostname };
    return { id, label: ProviderDetector.PROVIDERS[id].label, hostname };
  }

  /** Human label for a provider id. */
  static label(id) {
    const p = ProviderDetector.PROVIDERS[id];
    return p ? p.label : 'Unknown';
  }
}

export default ProviderDetector;
