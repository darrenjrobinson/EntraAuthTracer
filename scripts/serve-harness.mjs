/**
 * Entra Auth Tracer - HTTPS static server for the WebMCP test harness.
 *
 * The extension refuses to arm any tab that is not https:// (WebMcpController
 * ._enable), so the harness cannot be opened from disk. This serves the scripts
 * directory over TLS with no npm dependencies.
 *
 * One-time setup (trusted cert, no browser warning):
 *   winget install FiloSottile.mkcert
 *   mkcert -install                     # installs a local CA
 *   cd scripts && mkcert localhost      # writes localhost.pem + localhost-key.pem
 *
 * Then:
 *   node scripts/serve-harness.mjs
 *   https://localhost:8443/webmcp-harness.html
 *
 * Binds to 127.0.0.1 only - never exposed to the network.
 */

import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT) || 8443;
const HOST = '127.0.0.1';

const CERT = process.env.CERT || path.join(HERE, 'localhost.pem');
const KEY = process.env.KEY || path.join(HERE, 'localhost-key.pem');

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon'
};

for (const [label, file] of [['certificate', CERT], ['private key', KEY]]) {
  if (!fs.existsSync(file)) {
    console.error(`\nMissing ${label}: ${file}\n`);
    console.error('Generate a trusted pair with mkcert:\n');
    console.error('  winget install FiloSottile.mkcert');
    console.error('  # open a NEW terminal so PATH picks up mkcert, then:');
    console.error('  mkcert -install');
    console.error(`  cd "${HERE}"`);
    console.error('  mkcert localhost\n');
    console.error('Or point at an existing pair:  CERT=... KEY=... node serve-harness.mjs\n');
    process.exit(1);
  }
}

const server = https.createServer(
  { cert: fs.readFileSync(CERT), key: fs.readFileSync(KEY) },
  (req, res) => {
    const requested = decodeURIComponent(new URL(req.url, 'https://localhost').pathname);
    const rel = requested === '/' ? '/webmcp-harness.html' : requested;

    // Resolve inside HERE only - reject traversal.
    const full = path.resolve(HERE, '.' + rel);
    if (full !== HERE && !full.startsWith(HERE + path.sep)) {
      res.writeHead(403, { 'content-type': 'text/plain' });
      res.end('Forbidden');
      return;
    }

    fs.readFile(full, (err, body) => {
      if (err) {
        res.writeHead(404, { 'content-type': 'text/plain' });
        res.end('Not found: ' + rel);
        console.log(`404 ${rel}`);
        return;
      }
      res.writeHead(200, {
        'content-type': TYPES[path.extname(full).toLowerCase()] || 'application/octet-stream',
        'cache-control': 'no-store'
      });
      res.end(body);
      console.log(`200 ${rel}`);
    });
  }
);

server.listen(PORT, HOST, () => {
  console.log(`\nServing ${HERE}`);
  console.log(`\n  https://localhost:${PORT}/webmcp-harness.html\n`);
  console.log('Open that URL, then click Enable WebMCP in the extension popup');
  console.log('with THAT tab focused. Ctrl+C to stop.\n');
});

server.on('error', (e) => {
  if (e.code === 'EADDRINUSE') console.error(`\nPort ${PORT} is in use. Try:  PORT=8444 node serve-harness.mjs\n`);
  else console.error(e);
  process.exit(1);
});
