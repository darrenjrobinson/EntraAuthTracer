// Runs as npm's `version` lifecycle hook (see package.json). Keeps manifest.json's
// version in lockstep with package.json, and refuses to cut a release that has no
// changelog notes yet.
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const MANIFEST_PATH = path.join(ROOT, 'manifest.json');
const CHANGELOG_PATH = path.join(ROOT, 'CHANGELOG.md');
const PACKAGE_LOCK_PATH = path.join(ROOT, 'package-lock.json');

// By the time this "version" hook runs, npm has already rewritten package.json (and
// package-lock.json) in the working tree with the bumped version, but hasn't committed
// yet. If we reject the bump, undo that rewrite too — otherwise a failed attempt
// leaves the repo sitting on an uncommitted version bump, and a retry after fixing
// CHANGELOG.md would bump again from that already-advanced (but uncommitted) version,
// skipping the version the user actually intended to cut.
function abort(message) {
  console.error(`sync-manifest-version: ${message}`);
  const filesToRestore = ['package.json'];
  if (fs.existsSync(PACKAGE_LOCK_PATH)) filesToRestore.push('package-lock.json');
  try {
    execFileSync('git', ['checkout', '--', ...filesToRestore], { cwd: ROOT, stdio: 'inherit' });
  } catch {
    console.error(`sync-manifest-version: also failed to restore ${filesToRestore.join(', ')} — check \`git status\``);
  }
  process.exit(1);
}

function main() {
  const version = process.env.npm_package_version;
  if (!version) {
    console.error('sync-manifest-version: npm_package_version is not set — run this via `npm version`, not directly');
    process.exit(1);
  }

  const changelog = fs.readFileSync(CHANGELOG_PATH, 'utf8');
  const heading = `## [${version}]`;
  if (!changelog.includes(heading)) {
    abort(`CHANGELOG.md has no "${heading}" heading — move the [Unreleased] notes under that heading before running \`npm version\``);
  }

  const manifest = fs.readFileSync(MANIFEST_PATH, 'utf8');
  const versionFieldRe = /("version":\s*")[^"]*(")/;
  if (!versionFieldRe.test(manifest)) {
    abort('no "version" field found in manifest.json');
  }
  fs.writeFileSync(MANIFEST_PATH, manifest.replace(versionFieldRe, `$1${version}$2`));

  // Stage it so it rides along in the commit `npm version` is about to create.
  execFileSync('git', ['add', 'manifest.json'], { cwd: ROOT, stdio: 'inherit' });
  console.log(`sync-manifest-version: manifest.json -> ${version}`);
}

main();
