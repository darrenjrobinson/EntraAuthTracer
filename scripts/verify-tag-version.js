// Used by the release workflow: fails the run if the pushed tag doesn't match the
// version already recorded in package.json and manifest.json.
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');

function readVersion(file) {
  return JSON.parse(fs.readFileSync(path.join(ROOT, file), 'utf8')).version;
}

function main() {
  const tag = process.argv[2] || process.env.GITHUB_REF_NAME;
  if (!tag) {
    console.error('verify-tag-version: no tag given — pass it as an argument or set GITHUB_REF_NAME');
    process.exit(1);
  }
  if (!/^v\d+\.\d+\.\d+$/.test(tag)) {
    console.error(`verify-tag-version: tag "${tag}" does not look like "vX.Y.Z"`);
    process.exit(1);
  }
  const version = tag.slice(1);

  const pkgVersion = readVersion('package.json');
  const manifestVersion = readVersion('manifest.json');

  const mismatches = [];
  if (pkgVersion !== version) mismatches.push(`package.json is ${pkgVersion}`);
  if (manifestVersion !== version) mismatches.push(`manifest.json is ${manifestVersion}`);

  if (mismatches.length) {
    console.error(`verify-tag-version: tag ${tag} does not match ${mismatches.join(', ')}`);
    process.exit(1);
  }

  console.log(`verify-tag-version: ${tag} matches package.json and manifest.json`);
}

main();
