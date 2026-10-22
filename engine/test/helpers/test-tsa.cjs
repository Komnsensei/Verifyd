'use strict';

// A local RFC 3161 time-stamp authority for tests, backed by `openssl ts`.
// Generates a throwaway CA and TSA certificate, then answers timestamp queries
// by running `openssl ts -reply` against them. Nothing here ships; the private
// keys live in a temporary directory that is deleted on close().

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

function hasOpenssl() {
  try {
    execFileSync('openssl', ['version'], { stdio: 'pipe' });
    return true;
  } catch (_) {
    return false;
  }
}

function fwd(p) {
  return String(p).replace(/\\/g, '/');
}

function openssl(args, cwd) {
  return execFileSync('openssl', args, { stdio: 'pipe', cwd });
}

function makeCa(dir, name) {
  const key = path.join(dir, name + '.key');
  const crt = path.join(dir, name + '.crt');
  openssl([
    'req', '-x509', '-newkey', 'rsa:2048', '-keyout', key, '-out', crt,
    '-days', '2', '-nodes', '-subj', '/CN=Verifyd Test CA ' + name,
    '-addext', 'basicConstraints=critical,CA:TRUE',
    '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
  ]);
  return { key, crt };
}

function makeTsaCert(dir, name, ca) {
  const key = path.join(dir, name + '.key');
  const csr = path.join(dir, name + '.csr');
  const crt = path.join(dir, name + '.crt');
  const ext = path.join(dir, name + '.ext');
  fs.writeFileSync(ext, [
    'extendedKeyUsage=critical,timeStamping',
    'keyUsage=critical,digitalSignature,nonRepudiation',
    'basicConstraints=critical,CA:FALSE',
    '',
  ].join('\n'));
  openssl(['req', '-new', '-newkey', 'rsa:2048', '-keyout', key, '-out', csr, '-nodes', '-subj', '/CN=Verifyd Test TSA ' + name]);
  openssl(['x509', '-req', '-in', csr, '-CA', ca.crt, '-CAkey', ca.key, '-CAcreateserial', '-out', crt, '-days', '2', '-extfile', ext]);
  return { key, crt };
}

function tsaConfig(dir, ca) {
  const cfg = path.join(dir, 'tsa.cnf');
  fs.writeFileSync(cfg, [
    '[ tsa ]',
    'default_tsa = tsa_config1',
    '[ tsa_config1 ]',
    'dir = ' + fwd(dir),
    'serial = ' + fwd(path.join(dir, 'tsaserial')),
    'crypto_device = builtin',
    'signer_digest = sha256',
    'default_policy = 1.3.6.1.4.1.99999.1',
    'digests = sha256',
    'accuracy = secs:1',
    'ordering = yes',
    'tsa_name = yes',
    'ess_cert_id_chain = no',
    'ess_cert_id_alg = sha256',
    '',
  ].join('\n'));
  fs.writeFileSync(path.join(dir, 'tsaserial'), '01\n');
  return cfg;
}

function startTsa(opts) {
  opts = opts || {};
  if (!hasOpenssl()) return Promise.reject(new Error('openssl not available'));

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'verifyd-tsa-'));
  const ca = makeCa(dir, opts.caName || 'ca');
  const tsa = makeTsaCert(dir, 'tsa', ca);
  const cfg = tsaConfig(dir, ca);
  let counter = 0;

  const server = http.createServer((req, res) => {
    if (req.method !== 'POST' || req.url !== '/tsa') {
      res.writeHead(404);
      res.end('not found');
      return;
    }
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      try {
        const id = ++counter;
        const queryFile = path.join(dir, 'q' + id + '.tsq');
        const replyFile = path.join(dir, 'r' + id + '.tsr');
        fs.writeFileSync(queryFile, Buffer.concat(chunks));
        openssl([
          'ts', '-reply', '-config', fwd(cfg), '-queryfile', fwd(queryFile),
          '-inkey', fwd(tsa.key), '-signer', fwd(tsa.crt), '-chain', fwd(ca.crt),
          '-out', fwd(replyFile),
        ], dir);
        const reply = fs.readFileSync(replyFile);
        res.writeHead(200, {
          'Content-Type': 'application/timestamp-reply',
          'Content-Length': reply.length,
        });
        res.end(reply);
      } catch (e) {
        res.writeHead(500);
        res.end(String((e.stderr && e.stderr.toString()) || e.message));
      }
    });
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      resolve({
        dir,
        url: 'http://127.0.0.1:' + port + '/tsa',
        caPath: ca.crt,
        caDir: dir,
        server,
        close() {
          return new Promise((done) => {
            server.close(() => {
              try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_) {}
              done();
            });
            if (server.closeAllConnections) server.closeAllConnections();
          });
        },
      });
    });
  });
}

// A CA that did not issue the test TSA certificate.
function makeUnrelatedCa(dir) {
  const ca = makeCa(dir, 'other-ca');
  return ca.crt;
}

module.exports = { hasOpenssl, startTsa, makeUnrelatedCa };
