'use strict';

// Every receipt shipped in examples/ must verify under the bundled keyring.
// A receipt signed by a key that was never published there cannot be checked
// by a reader, so shipping one has to fail CI instead of only failing the
// documented verify command. The shipped certificates and batch summary are
// checked the same way: a reader compares them against the receipt they name,
// so a stale one must not outlive the receipt it describes.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const Signing = require('../signing.cjs');

const ROOT = path.join(__dirname, '..', '..');
const EXAMPLES = path.join(ROOT, 'examples');
const KEYRING = path.join(EXAMPLES, 'keyring');

function shippedReceipts() {
  return fs.readdirSync(EXAMPLES)
    .filter(name => name.endsWith('.verifyd-receipt.json'))
    .sort()
    .map(name => path.join(EXAMPLES, name));
}

function readShipped() {
  return shippedReceipts().map(file => ({
    file,
    name: path.basename(file),
    envelope: JSON.parse(fs.readFileSync(file, 'utf8')),
  }));
}

function certificateFor(receiptFile) {
  return receiptFile.replace(/\.json$/i, '') + '.verifyd-certificate.txt';
}

function certField(text, label) {
  const match = text.match(new RegExp('^  ' + label + ':\\s+(.+)$', 'm'));
  return match ? match[1].trim() : null;
}

// Certificates print the head and tail of a hash around an ellipsis. Accept
// either the abbreviated display or a full value, and never a value that does
// not belong to the receipt.
function hashDisplayMatches(shown, full) {
  if (typeof shown !== 'string' || typeof full !== 'string' || !shown || !full) return false;
  if (!shown.includes('...')) return shown === full;
  const parts = shown.split('...');
  if (parts.length !== 2 || !parts[0] || !parts[1]) return false;
  return full.startsWith(parts[0]) && full.endsWith(parts[1]) &&
    parts[0].length + parts[1].length <= full.length;
}

test('every shipped example receipt verifies under the bundled keyring', () => {
  const receipts = readShipped();
  assert.ok(receipts.length > 0, 'no example receipts found in examples/');
  assert.ok(fs.existsSync(KEYRING), 'the bundled example keyring is missing');

  for (const item of receipts) {
    const res = Signing.open(item.envelope, { dir: KEYRING });

    assert.strictEqual(res.ok, true,
      item.name + ' does not verify under examples/keyring: ' + res.code + ' ' + res.message);
    assert.strictEqual(res.code, 'OK', item.name + ' verification code');
    assert.strictEqual(res.signer_trusted, true, item.name + ' signer is not trusted by the bundled keyring');
    assert.strictEqual(res.key_id, item.envelope.signature.key_id, item.name + ' reported signer key id');
    assert.deepStrictEqual(res.checks, {
      signature_present: true,
      key_known: true,
      public_key_matches_keyring: true,
      signature_valid: true,
      receipt_hash_valid: true,
    }, item.name + ' signature checks');
  }
});

test('every shipped certificate describes its receipt', () => {
  const receipts = readShipped();
  assert.ok(receipts.length > 0, 'no example receipts found in examples/');

  for (const item of receipts) {
    const certFile = certificateFor(item.file);
    assert.ok(fs.existsSync(certFile), item.name + ' has no shipped certificate');

    const cert = fs.readFileSync(certFile, 'utf8');
    const receipt = item.envelope.receipt || {};
    const document = item.envelope.document || {};
    const signature = item.envelope.signature || {};

    assert.strictEqual(certField(cert, 'Name'), document.file,
      item.name + ' certificate names a different document');
    assert.strictEqual(certField(cert, 'Receipt ID'), receipt.receipt_id,
      item.name + ' certificate names a different receipt id');
    assert.ok(hashDisplayMatches(certField(cert, 'Receipt Hash'), receipt.this_hash),
      item.name + ' certificate receipt hash does not match: ' + certField(cert, 'Receipt Hash'));
    assert.ok(hashDisplayMatches(String(certField(cert, 'Primary Hash')).replace(/^sha256:/, ''), document.sha256),
      item.name + ' certificate document hash does not match: ' + certField(cert, 'Primary Hash'));
    assert.ok(hashDisplayMatches(certField(cert, 'Signer Key ID'), signature.key_id),
      item.name + ' certificate signer key id does not match: ' + certField(cert, 'Signer Key ID'));
  }
});

test('every shipped batch summary row names a shipped receipt', () => {
  const receipts = readShipped();
  const summaryFile = path.join(EXAMPLES, 'BATCH_SUMMARY.json');
  assert.ok(fs.existsSync(summaryFile), 'BATCH_SUMMARY.json is missing');
  const summary = JSON.parse(fs.readFileSync(summaryFile, 'utf8'));
  assert.ok(Array.isArray(summary.results) && summary.results.length > 0,
    'BATCH_SUMMARY.json has no results');

  for (const row of summary.results) {
    assert.ok(typeof row.file === 'string' && row.file, 'a batch summary row has no file name');
    assert.ok(fs.existsSync(path.join(EXAMPLES, row.file)),
      row.file + ' is named in BATCH_SUMMARY.json but not shipped');
    assert.ok(typeof row.receipt === 'string' && row.receipt.length > 0,
      row.file + ' batch summary row has no receipt hash');
    assert.ok(typeof row.sha === 'string' && row.sha.length > 0,
      row.file + ' batch summary row has no document hash');

    const match = receipts.find(item =>
      String((item.envelope.receipt || {}).this_hash || '').startsWith(row.receipt));
    assert.ok(match, row.file + ' batch summary receipt hash ' + row.receipt + ' has no shipped receipt');

    assert.strictEqual((match.envelope.document || {}).file, row.file,
      row.file + ' batch summary row names a different document');
    assert.ok(String((match.envelope.document || {}).sha256 || '').startsWith(row.sha),
      row.file + ' batch summary document hash does not match the shipped receipt');
    assert.strictEqual(row.signed, Boolean(match.envelope.signature && match.envelope.signature.value),
      row.file + ' batch summary signed flag does not match the shipped receipt');
  }
});
