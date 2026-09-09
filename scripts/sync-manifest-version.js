// Runs as npm's `version` lifecycle hook (see package.json). Keeps manifest.json's
// version in lockstep with package.json, and refuses to cut a release that has no
// changelog notes yet.
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const MANIFEST_PATH = path.join(ROOT, 'manifest.json');
const CHANGELOG_PATH = path.join(ROOT, 'CHANGELOG.md');

function main() {
  const version = process.env.npm_package_version;
  if (!version) {
    console.error('sync-manifest-version: npm_package_version is not set — run this via `npm version`, not directly');
    process.exit(1);
  }

  const changelog = fs.readFileSync(CHANGELOG_PATH, 'utf8');
  const heading = `## [${version}]`;
  if (!changelog.includes(heading)) {
    console.error(`sync-manifest-version: CHANGELOG.md has no "${heading}" heading`);
    console.error('Move the [Unreleased] notes under that heading before running `npm version`.');
    process.exit(1);
  }

  const manifest = fs.readFileSync(MANIFEST_PATH, 'utf8');
  const versionFieldRe = /("version":\s*")[^"]*(")/;
  if (!versionFieldRe.test(manifest)) {
    console.error('sync-manifest-version: no "version" field found in manifest.json');
    process.exit(1);
  }
  fs.writeFileSync(MANIFEST_PATH, manifest.replace(versionFieldRe, `$1${version}$2`));

  // Stage it so it rides along in the commit `npm version` is about to create.
  execFileSync('git', ['add', 'manifest.json'], { cwd: ROOT, stdio: 'inherit' });
  console.log(`sync-manifest-version: manifest.json -> ${version}`);
}

main();
