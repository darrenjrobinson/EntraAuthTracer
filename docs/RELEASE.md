# Release process

This is the maintainer-facing doc for cutting a release. End users installing the
extension don't need anything here — see [README.md](../README.md#installation).

## Cutting a release

1. Move the `[Unreleased]` section in [CHANGELOG.md](../CHANGELOG.md) to a new
   `## [x.y.z] - YYYY-MM-DD` heading (matching the version you're about to cut), and
   add a fresh empty `## [Unreleased]` above it. `npm version` (next step) refuses to
   run if the target version has no changelog heading.
2. Run `npm version patch` (or `minor` / `major`). This bumps `package.json`, copies
   the same version into `manifest.json` via `scripts/sync-manifest-version.js` (an
   npm `version` lifecycle hook — see [package.json](../package.json)), and creates a
   commit + a `vX.Y.Z` git tag.
3. `git push --follow-tags`

Pushing the tag triggers [`.github/workflows/release.yml`](../.github/workflows/release.yml),
which:

1. Runs the same lint/test/build checks as CI, on the tag
2. Double-checks the tag matches `package.json`/`manifest.json` (fails loudly if not)
3. Runs `web-ext lint` against the built `dist/` folder — advisory only, since its
   Firefox-schema checks always flag MV3's `background.service_worker` and the
   missing Firefox-only `gecko.id` as errors for this Chrome/Edge-only extension;
   real findings (e.g. `innerHTML` usage) still show up in the step's log
4. Packages `dist/` into `EntraAuthTracer-vX.Y.Z.zip` (the same filename
   [README.md](../README.md) documents under "From a GitHub Release")
5. Creates a GitHub Release with that zip attached and the CHANGELOG section for that
   version as the release notes
6. Publishes to the Chrome Web Store and Microsoft Edge Add-ons — but **only if** the
   relevant secrets below are configured. Each store is independent: set only Chrome's
   secrets and only Chrome auto-publishes; Edge stays manual (upload the release zip
   through Partner Center yourself) until its secrets are added too. The workflow run's
   summary tab says which store(s) it actually published to.

## Required GitHub repo secrets

Add these under the repo's **Settings → Secrets and variables → Actions**.

| Secret | Store | What it is |
|---|---|---|
| `CHROME_EXTENSION_ID` | Chrome | The item id from the Chrome Web Store listing URL — already public: `phnebijghhehloikpgohcblcljkaokbh` |
| `CHROME_PUBLISHER_ID` | Chrome | Your publisher id from the Developer Dashboard — see below, distinct from the extension id |
| `CHROME_CLIENT_ID` | Chrome | OAuth client id from Google Cloud Console |
| `CHROME_CLIENT_SECRET` | Chrome | OAuth client secret from Google Cloud Console |
| `CHROME_REFRESH_TOKEN` | Chrome | Refresh token minted once via a one-time manual OAuth consent |
| `EDGE_PRODUCT_ID` | Edge | The extension's Product ID **GUID** from Partner Center — see below, this is *not* the id in the public store URL |
| `EDGE_CLIENT_ID` | Edge | Client ID from Partner Center's Publish API page |
| `EDGE_API_KEY` | Edge | API key from Partner Center's Publish API page |

### Chrome Web Store credentials

`scripts/publish-chrome.sh` talks to the Chrome Web Store API **v2**
(`chromewebstore.googleapis.com`) — the older v1 API
(`www.googleapis.com/chromewebstore/v1.1`) stops working **2026-10-15**, so v2 is the
only option for a workflow set up after that date and the only one documented here.

1. In [Google Cloud Console](https://console.cloud.google.com/), create (or reuse) a
   project and enable the **Chrome Web Store API**.
2. Create an OAuth 2.0 Client ID (application type: **Desktop app**) under
   **APIs & Services → Credentials**. This gives you `CHROME_CLIENT_ID` and
   `CHROME_CLIENT_SECRET`.
3. Mint a refresh token once, by hand: follow Google's current instructions for the
   Chrome Web Store publish API's OAuth flow (search "Chrome Web Store API using OAuth"
   on Google's developer docs — the exact consent-screen click-path changes
   occasionally, so follow their live doc rather than a copy of it here), requesting
   the `https://www.googleapis.com/auth/chromewebstore` scope. The end result is a
   `refresh_token` value — that's `CHROME_REFRESH_TOKEN`.
   - Google's refresh tokens can stop working after 6 months of disuse. Since this repo
     releases somewhat regularly that shouldn't bite, but if `publish-chrome.sh` ever
     starts failing token exchange, just repeat this step to mint a new one.
4. `CHROME_EXTENSION_ID` is the id already in the
   [Chrome Web Store listing URL](https://chromewebstore.google.com/detail/entra-auth-tracer/phnebijghhehloikpgohcblcljkaokbh):
   `phnebijghhehloikpgohcblcljkaokbh`.
5. `CHROME_PUBLISHER_ID` is shown under **Publisher → Settings** in the
   [Developer Dashboard](https://chrome.google.com/webstore/devconsole/) — v2 addresses
   every item as `publishers/{publisherId}/items/{itemId}`, so this is required even
   though v1 never needed it.

### Edge Add-ons credentials

Per Microsoft's [Use the REST API to update an extension](https://learn.microsoft.com/microsoft-edge/extensions/update/api/using-addons-api)
doc (v1.1 — the only version still supported; v1 was retired end of 2024):

1. Sign in to the [Partner Center developer dashboard](https://partner.microsoft.com/dashboard/microsoftedge/public/login?ref=dd)
   with the account used to publish the extension.
2. Under **Microsoft Edge**, select **Publish API**, then **Create API credentials**
   (or **Enable** the v1.1 experience if prompted). This displays a **Client ID** and
   one or more **API Keys** — write the API key down now, it's shown only once. These
   are `EDGE_CLIENT_ID` and `EDGE_API_KEY`.
3. For `EDGE_PRODUCT_ID`: go to **Microsoft Edge → Overview**, select this extension,
   and copy the **Product ID** shown on its overview page (also visible as the GUID in
   the address bar between `microsoftedge/` and `/packages`). This is **not** the same
   as the id in the public Edge Add-ons listing URL
   (`miggooielleiofpinmmdoaljdcppnimd`) — confirm the real Product ID in Partner Center
   rather than assuming they match.

## Local scripts

- `node scripts/verify-tag-version.js vX.Y.Z` — same check the workflow runs
- `node scripts/extract-changelog.js X.Y.Z` — prints what the Release notes will be
- `bash scripts/publish-chrome.sh <zip>` / `bash scripts/publish-edge.sh <zip>` — the
  actual store publish calls; can be run locally with the same env vars set, e.g. to
  republish without re-cutting a release
