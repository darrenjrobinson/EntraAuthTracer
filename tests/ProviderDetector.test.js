/**
 * Tests for ProviderDetector — URL → identity provider mapping.
 */

import ProviderDetector from '../src/ProviderDetector.js';

describe('ProviderDetector', () => {
  describe('detect — known hosts', () => {
    it.each([
      ['https://login.microsoftonline.com/common/oauth2/v2.0/token', 'entra', 'Microsoft Entra ID'],
      ['https://login.microsoftonline.us/t/oauth2/v2.0/authorize', 'entra', 'Microsoft Entra ID'],
      ['https://sts.windows.net/t/', 'entra', 'Microsoft Entra ID'],
      ['https://login.live.com/oauth20_token.srf', 'microsoft-account', 'Microsoft account (MSA)'],
      ['https://accounts.google.com/o/oauth2/v2/auth', 'google', 'Google'],
      ['https://oauth2.googleapis.com/token', 'google', 'Google'],
      ['https://openidconnect.googleapis.com/v1/userinfo', 'google', 'Google'],
      ['https://securetoken.googleapis.com/v1/token?key=x', 'firebase', 'Firebase Authentication'],
      ['https://verifiedid.did.msidentity.com/v1.0/verifiableCredentials/createIssuanceRequest', 'entra-verified-id', 'Microsoft Entra Verified ID'],
      ['https://beta.did.msidentity.com/v1.0/x', 'entra-verified-id', 'Microsoft Entra Verified ID'],
      ['https://did.msidentity.com/v1.0/x', 'entra-verified-id', 'Microsoft Entra Verified ID'],
      ['https://request.msidentity.com/x', 'entra-verified-id', 'Microsoft Entra Verified ID'],
      ['https://resolver.msidentity.com/1.0/identifiers/did:web:x', 'did-resolver', 'DID resolver'],
      ['https://resolver.identity.foundation/1.0/identifiers/did:ion:x', 'did-resolver', 'DID resolver']
    ])('%s → %s', (url, id, label) => {
      const result = ProviderDetector.detect(url);
      expect(result.id).toBe(id);
      expect(result.label).toBe(label);
      expect(result.hostname).toBe(new URL(url).hostname);
    });
  });

  describe('detect — tenant suffixes', () => {
    it.each([
      ['https://contoso.okta.com/oauth2/default/v1/token', 'okta'],
      ['https://contoso.oktapreview.com/api/v1/authn', 'okta'],
      ['https://contoso.okta-emea.com/oauth2/v1/authorize', 'okta'],
      ['https://mypool.auth.us-east-1.amazoncognito.com/oauth2/token', 'cognito'],
      ['https://contoso.b2clogin.com/contoso.onmicrosoft.com/b2c_1_signin/oauth2/v2.0/authorize', 'entra'],
      ['https://contoso.ciamlogin.com/contoso.onmicrosoft.com/oauth2/v2.0/token', 'entra']
    ])('%s → %s', (url, id) => {
      expect(ProviderDetector.detect(url).id).toBe(id);
    });
  });

  describe('detect — path patterns', () => {
    it.each([
      ['https://adfs.contoso.com/adfs/ls/?client-request-id=1', 'adfs'],
      ['https://adfs.contoso.com/adfs/oauth2/token', 'adfs'],
      ['https://sp.university.edu/Shibboleth.sso/SAML2/POST', 'shibboleth'],
      ['https://idp.university.edu/idp/profile/SAML2/Redirect/SSO', 'shibboleth'],
      ['https://auth.example.com/connect/token', 'identityserver'],
      ['https://auth.example.com/connect/deviceauthorization', 'identityserver'],
      ['https://sso.example.com/api/v1/authn', 'okta'],
      ['https://sso.example.com/idp/idx/introspect', 'okta']
    ])('%s → %s', (url, id) => {
      expect(ProviderDetector.detect(url).id).toBe(id);
    });
  });

  describe('detect — fallbacks', () => {
    it('reports unknown providers with the hostname as label', () => {
      const result = ProviderDetector.detect('https://idp.example.com/saml2/sso');
      expect(result).toEqual({ id: 'unknown', label: 'idp.example.com', hostname: 'idp.example.com' });
    });

    it('accepts URL objects and lower-cases hostnames', () => {
      expect(ProviderDetector.detect(new URL('https://LOGIN.MICROSOFTONLINE.COM/x')).id).toBe('entra');
    });

    it('does not throw on invalid input', () => {
      expect(ProviderDetector.detect('not a url')).toEqual({ id: 'unknown', label: 'Unknown', hostname: null });
      expect(ProviderDetector.detect(null)).toEqual({ id: 'unknown', label: 'Unknown', hostname: null });
    });

    it('every provider id has a label', () => {
      for (const id of Object.keys(ProviderDetector.PROVIDERS)) {
        expect(typeof ProviderDetector.label(id)).toBe('string');
      }
      expect(ProviderDetector.label('nope')).toBe('Unknown');
    });
  });
});
