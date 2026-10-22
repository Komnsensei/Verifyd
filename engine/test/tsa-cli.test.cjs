'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const net = require('net');
const { execFile } = require('child_process');
const { promisify } = require('util');

const v = require('../verifyd.cjs');
const { hasOpenssl, startTsa } = require('./helpers/test-tsa.cjs');

const execFileAsync = promisify(execFile);
const CLI = path.join(__dirname, '..', '..', 'bin', 'verifyd.cjs');
const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'verifyd-tsa-cli-'));
const keyring = path.join(workspace, 'keys');

const available = hasOpenssl();
const skip = available ? false : 'openssl is not available';

let tsa = null;

function doc(name, text) {
  const file = path.join(workspace, name);
  fs.writeFileSync(file, text);
  return file;
}

const firstDoc = doc('first.txt', 'Evidence note one. Records provenance, source anchors, and hashes for audit review.\n');
const secondDoc = doc('second.txt', 'Evidence note two. A different document with different bytes and hashes.\n');

// Async on purpose: the test TSA runs in this process, so a synchronous
// spawn would block the event loop and the TSA could never answer.
async function run(args, opts) {
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, [CLI].concat(args), {
      cwd: workspace,
      encoding: 'utf8',
      env: Object.assign({}, process.env, (opts && opts.env) || {}),
    });
    return { status: 0, out: stdout + stderr };
  } catch (e) {
    return {
      status: typeof e.code === 'number' ? e.code : 1,
      out: (e.stdout || '') + (e.stderr || '') + (e.code === undefined ? String(e.message) : ''),
    };
  }
}

function receiptFor(file) {
  return path.join(workspace, path.basename(file).replace(/\.[^.]+$/, '') + '.verifyd-receipt.json');
}

async function audit(file, extra) {
  const res = await run(['audit', path.basename(file), '--keyring', keyring].concat(extra || []));
  assert.strictEqual(res.status, 0, res.out);
  return JSON.parse(fs.readFileSync(receiptFor(file), 'utf8'));
}

function writeReceipt(file, data) {
  fs.writeFileSync(receiptFor(file), JSON.stringify(data, null, 2));
}

test.before(async () => {
  if (available) tsa = await startTsa();
});

test.after(async () => {
  if (tsa) await tsa.close();
  fs.rmSync(workspace, { recursive: true, force: true });
});

test('audit records a token bound to the signed bytes', { skip }, async () => {
  const receipt = await audit(firstDoc, ['--tsa', tsa.url]);

  assert.ok(receipt.timestamp, 'timestamp block present');
  assert.strictEqual(receipt.timestamp.type, 'rfc3161');
  assert.strictEqual(receipt.timestamp.tsa_url, tsa.url);
  assert.ok(receipt.timestamp.token && receipt.timestamp.token.length > 200);

  const payload = v.Signing.signingPayload(receipt);
  assert.strictEqual(receipt.timestamp.imprint_sha256, v.TSA.sha256(payload).toString('hex'),
    'stored imprint equals SHA-256 of the signed payload');
});

test('verify reports attested time separately from signed_at', { skip }, async () => {
  await audit(firstDoc, ['--tsa', tsa.url]);
  const res = await run(['verify', path.basename(receiptFor(firstDoc)), '--keyring', keyring, '--tsa-ca', tsa.caPath]);

  assert.strictEqual(res.status, 0, res.out);
  assert.match(res.out, /Signed at:\s+\d{4}-\d{2}-\d{2}T.*\(self-asserted clock\)/);
  assert.match(res.out, /Attested:\s+\d{4}-\d{2}-\d{2}T/);
  assert.match(res.out, /Time status:\s+ATTESTED/);

  const signed = (res.out.match(/Signed at:\s+(\S+)/) || [])[1];
  const attested = (res.out.match(/Attested:\s+(\S+)/) || [])[1];
  assert.ok(signed && attested && signed !== attested, 'two distinct time values are printed');
});

test('without a trust root the token is UNVERIFIED but the receipt is not rejected', { skip }, async () => {
  await audit(firstDoc, ['--tsa', tsa.url]);
  const res = await run(['verify', path.basename(receiptFor(firstDoc)), '--keyring', keyring]);

  assert.strictEqual(res.status, 0, res.out);
  assert.match(res.out, /Time status:\s+UNVERIFIED/);
  assert.match(res.out, /Attested:\s+\(not established\)/);
});

test('a token lifted from another receipt is rejected', { skip }, async () => {
  const other = await audit(secondDoc, ['--tsa', tsa.url]);
  const receipt = await audit(firstDoc, ['--tsa', tsa.url]);

  receipt.timestamp.token = other.timestamp.token;
  receipt.timestamp.imprint_sha256 = other.timestamp.imprint_sha256;
  writeReceipt(firstDoc, receipt);

  const res = await run(['verify', path.basename(receiptFor(firstDoc)), '--keyring', keyring, '--tsa-ca', tsa.caPath]);
  assert.strictEqual(res.status, 1, res.out);
  assert.match(res.out, /Time status:\s+INVALID/);
  assert.match(res.out, /imprint_mismatch/);
});

test('a corrupted token is rejected', { skip }, async () => {
  const receipt = await audit(firstDoc, ['--tsa', tsa.url]);
  const der = Buffer.from(receipt.timestamp.token, 'base64');
  der[Math.floor(der.length / 2)] ^= 0xff;
  receipt.timestamp.token = der.toString('base64');
  writeReceipt(firstDoc, receipt);

  const res = await run(['verify', path.basename(receiptFor(firstDoc)), '--keyring', keyring, '--tsa-ca', tsa.caPath]);
  assert.strictEqual(res.status, 1, res.out);
  assert.match(res.out, /Time status:\s+INVALID/);
});

test('a stripped token leaves the signature valid and time UNATTESTED', { skip }, async () => {
  const receipt = await audit(firstDoc, ['--tsa', tsa.url]);
  delete receipt.timestamp;
  writeReceipt(firstDoc, receipt);

  const res = await run(['verify', path.basename(receiptFor(firstDoc)), '--keyring', keyring, '--tsa-ca', tsa.caPath]);
  assert.strictEqual(res.status, 0, res.out);
  assert.match(res.out, /Signature:\s+VALID/);
  assert.match(res.out, /Time status:\s+UNATTESTED/);
});

test('a TSA outage still produces a signed, verifiable receipt', async () => {
  const port = await new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => {
      const p = s.address().port;
      s.close(() => resolve(p));
    });
  });

  const receipt = await audit(firstDoc, ['--tsa', 'http://127.0.0.1:' + port + '/tsa']);
  assert.ok(receipt.signature && receipt.signature.value, 'receipt is signed');
  assert.strictEqual(receipt.timestamp.status, 'failed');
  assert.match(receipt.timestamp.error, /tsa_unreachable/);

  const res = await run(['verify', path.basename(receiptFor(firstDoc)), '--keyring', keyring]);
  assert.strictEqual(res.status, 0, res.out);
  assert.match(res.out, /Signature:\s+VALID/);
  assert.match(res.out, /Time status:\s+UNATTESTED/);
  assert.match(res.out, /Recorded:.*tsa_unreachable/);
});

test('a token from a different authority is rejected against this root', { skip }, async () => {
  const other = await startTsa();
  try {
    await audit(firstDoc, ['--tsa', other.url]);
    const res = await run(['verify', path.basename(receiptFor(firstDoc)), '--keyring', keyring, '--tsa-ca', tsa.caPath]);
    assert.strictEqual(res.status, 1, res.out);
    assert.match(res.out, /Time status:\s+INVALID/);
    assert.match(res.out, /chain_/);
  } finally {
    await other.close();
  }
});

test('an unreadable CA path fails with a clear message', { skip }, async () => {
  await audit(firstDoc, ['--tsa', tsa.url]);
  const res = await run(['verify', path.basename(receiptFor(firstDoc)), '--keyring', keyring, '--tsa-ca', 'missing.pem']);
  assert.strictEqual(res.status, 1, res.out);
  assert.match(res.out, /TSA_CA_UNREADABLE|Time status:\s+INVALID/);
});
