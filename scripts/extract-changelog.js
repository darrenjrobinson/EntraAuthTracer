// Prints the body of one version's section from CHANGELOG.md, for use as the
// GitHub Release notes. Usage: node scripts/extract-changelog.js <version>
const fs = require('fs');
const path = require('path');

const CHANGELOG_PATH = path.join(__dirname, '..', 'CHANGELOG.md');

function main() {
  const version = (process.argv[2] || '').replace(/^v/, '');
  if (!version) {
    console.error('extract-changelog: usage: node scripts/extract-changelog.js <version>');
    process.exit(1);
  }

  const lines = fs.readFileSync(CHANGELOG_PATH, 'utf8').split('\n');
  const headingRe = new RegExp(`^## \\[${version.replace(/\./g, '\\.')}\\]`);
  const startIdx = lines.findIndex(line => headingRe.test(line));
  if (startIdx === -1) {
    console.error(`extract-changelog: no "## [${version}]" heading found in CHANGELOG.md`);
    process.exit(1);
  }

  // Stop at the next version heading, or at the link-reference block near the
  // bottom of the file (e.g. "[1.1.0]: https://...") if this is the last section.
  let endIdx = lines.length;
  for (let i = startIdx + 1; i < lines.length; i++) {
    if (/^## \[/.test(lines[i]) || /^\[.+\]:\s*https?:\/\//.test(lines[i])) {
      endIdx = i;
      break;
    }
  }

  const section = lines.slice(startIdx + 1, endIdx).join('\n').trim();
  if (!section) {
    console.error(`extract-changelog: "## [${version}]" section is empty`);
    process.exit(1);
  }

  process.stdout.write(section + '\n');
}

main();
