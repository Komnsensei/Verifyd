'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const v = require('../verifyd.cjs');
const Signing = require('../signing.cjs');

const isWindows = process.platform === 'win32';
const dirs = [];

function keyring() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'verifyd-keys-'));
  dirs.push(dir);
  return dir;
}

function makeEnvelope(fields) {
  const receipt = Object.assign({
    valf_version: '1.0',
    receipt_id: '00000000-0000-4000-8000-000000000000',
    document_quality: { value: 46, components: { source_quality: 12 }, calibrated: false },
    prev_hash: 'GENESIS',
  }, (fields && fields.receipt) || {});
  receipt.this_hash = v.sha256(v.canonicalJSON(receipt, ['this_hash']));
  return v.buildEnvelope({
    document: Object.assign({ file: 'paper.txt', sha256: 'a'.repeat(64), words: 10 }, (fields && fields.document) || {}),
    receipt,
  });
}

test.after(() => {
  for (const dir of dirs) fs.rmSync(dir, { recursive: true, force: true });
});

test('init creates a keyring with a private key and a public record', () => {
  const dir = keyring();
  const created = Signing.ensureKeyring({ dir });

  assert.match(created.key_id, /^ed25519:[0-9a-f]{64}$/);
  assert.strictEqual(created.created, true);

  const keys = Signing.listKeys({ dir });
  assert.strictEqual(keys.length, 1);
  assert.strictEqual(keys[0].key_id, created.key_id);
  assert.strictEqual(keys[0].status, 'active');
  assert.strictEqual(keys[0].active, true);

  const slug = created.key_id.replace(':', '-');
  const privateFile = path.join(dir, slug + '.key');
  const publicFile = path.join(dir, slug + '.pub.json');
  assert.ok(fs.existsSync(privateFile), 'private key file exists');
  assert.ok(fs.existsSync(publicFile), 'public record exists');

  const record = JSON.parse(fs.readFileSync(publicFile, 'utf8'));
  assert.strictEqual(record.key_id, created.key_id);
  assert.ok(record.public_key_pem.includes('BEGIN PUBLIC KEY'));

  if (!isWindows) {
    assert.strictEqual(fs.statSync(privateFile).mode & 0o777, 0o600, 'private key is 0600');
    assert.strictEqual(fs.statSync(dir).mode & 0o777, 0o700, 'keyring dir is 0700');
  }
});

test('the private key is never embedded in a receipt', () => {
  const dir = keyring();
  const sealed = Signing.seal(makeEnvelope(), { dir });
  const text = JSON.stringify(sealed);
  assert.ok(text.includes('BEGIN PUBLIC KEY'));
  assert.ok(!text.includes('PRIVATE KEY'), 'no private key material in the receipt');
});

test('a sealed receipt verifies', () => {
  const dir = keyring();
  const sealed = Signing.seal(makeEnvelope(), { dir });
  const res = Signing.open(sealed, { dir });

  assert.strictEqual(res.ok, true, res.message);
  assert.strictEqual(res.code, 'OK');
  assert.strictEqual(res.key_id, sealed.signature.key_id);
  assert.strictEqual(res.signer_trusted, true);
  assert.deepStrictEqual(res.checks, {
    signature_present: true,
    key_known: true,
    public_key_matches_keyring: true,
    signature_valid: true,
    receipt_hash_valid: true,
  });
});

test('a receipt with the signature stripped is rejected', () => {
  const dir = keyring();
  const sealed = Signing.seal(makeEnvelope(), { dir });
  delete sealed.signature;

  const res = Signing.open(sealed, { dir });
  assert.strictEqual(res.ok, false);
  assert.strictEqual(res.code, 'UNSIGNED');
  assert.strictEqual(res.checks.signature_present, false);
});

test('altering the document quality field invalidates the signature', () => {
  const dir = keyring();
  const sealed = Signing.seal(makeEnvelope(), { dir });
  sealed.receipt.document_quality.value = 100;

  const res = Signing.open(sealed, { dir });
  assert.strictEqual(res.ok, false);
  assert.strictEqual(res.code, 'SIGNATURE_INVALID');
  assert.strictEqual(res.checks.signature_valid, false);
});

test('altering document metadata invalidates the signature', () => {
  const dir = keyring();
  const sealed = Signing.seal(makeEnvelope(), { dir });
  sealed.document.words = 99999;

  const res = Signing.open(sealed, { dir });
  assert.strictEqual(res.ok, false);
  assert.strictEqual(res.code, 'SIGNATURE_INVALID');
});

test('altering the receipt body invalidates the signature', () => {
  const dir = keyring();
  const sealed = Signing.seal(makeEnvelope(), { dir });
  sealed.receipt.receipt_id = '11111111-1111-4111-8111-111111111111';

  const res = Signing.open(sealed, { dir });
  assert.strictEqual(res.ok, false);
  assert.strictEqual(res.code, 'SIGNATURE_INVALID');
});

test('a receipt signed by a key outside the keyring is an unexpected signer', () => {
  const trusted = keyring();
  const other = keyring();
  Signing.ensureKeyring({ dir: trusted });
  const foreign = Signing.seal(makeEnvelope(), { dir: other });

  const res = Signing.open(foreign, { dir: trusted });
  assert.strictEqual(res.ok, false);
  assert.strictEqual(res.code, 'UNTRUSTED_KEY');
  assert.strictEqual(res.signer_trusted, false);
});

test('a trusted key id paired with a foreign signature is rejected', () => {
  const trusted = keyring();
  const other = keyring();
  Signing.ensureKeyring({ dir: trusted });
  const foreign = Signing.seal(makeEnvelope(), { dir: other });
  const trustedKey = Signing.listKeys({ dir: trusted })[0];

  foreign.signature.key_id = trustedKey.key_id;
  foreign.signature.public_key = trustedKey.public_key_pem;

  const res = Signing.open(foreign, { dir: trusted });
  assert.strictEqual(res.ok, false);
  assert.strictEqual(res.code, 'SIGNATURE_INVALID');
  assert.strictEqual(res.checks.key_known, true);
  assert.strictEqual(res.checks.signature_valid, false);
});

test('a public key that disagrees with the keyring record is rejected', () => {
  const trusted = keyring();
  const other = keyring();
  Signing.ensureKeyring({ dir: trusted });
  const sealed = Signing.seal(makeEnvelope(), { dir: trusted });
  const otherKey = Signing.listKeys({ dir: other })[0] || (Signing.ensureKeyring({ dir: other }), Signing.listKeys({ dir: other })[0]);

  sealed.signature.public_key = otherKey.public_key_pem;

  const res = Signing.open(sealed, { dir: trusted });
  assert.strictEqual(res.ok, false);
  assert.strictEqual(res.code, 'PUBLIC_KEY_MISMATCH');
});

test('a signature over an internally inconsistent receipt is rejected', () => {
  const dir = keyring();
  const env = makeEnvelope();
  env.receipt.this_hash = 'deadbeef'.repeat(8);
  const sealed = Signing.seal(env, { dir });

  const res = Signing.open(sealed, { dir });
  assert.strictEqual(res.ok, false);
  assert.strictEqual(res.code, 'RECEIPT_HASH_MISMATCH');
  assert.strictEqual(res.checks.signature_valid, true, 'signature itself was valid');
  assert.strictEqual(res.checks.receipt_hash_valid, false);
});

test('rotation keeps old receipts verifiable and signs new ones with the new key', () => {
  const dir = keyring();
  const oldReceipt = Signing.seal(makeEnvelope(), { dir });
  const oldKeyId = oldReceipt.signature.key_id;

  const rotated = Signing.rotateKey({ dir });
  assert.notStrictEqual(rotated.key_id, oldKeyId);
  assert.strictEqual(rotated.previous_key_id, oldKeyId);

  const newReceipt = Signing.seal(makeEnvelope(), { dir });
  assert.strictEqual(newReceipt.signature.key_id, rotated.key_id);

  const oldResult = Signing.open(oldReceipt, { dir });
  assert.strictEqual(oldResult.ok, true, 'retired key still verifies its receipts');

  const newResult = Signing.open(newReceipt, { dir });
  assert.strictEqual(newResult.ok, true);

  const statuses = Signing.listKeys({ dir }).map(k => k.status).sort();
  assert.deepStrictEqual(statuses, ['active', 'retired']);
});

test('deleting a public record distrusts receipts signed by that key', () => {
  const dir = keyring();
  const sealed = Signing.seal(makeEnvelope(), { dir });
  const keyId = sealed.signature.key_id;
  fs.rmSync(path.join(dir, keyId.replace(':', '-') + '.pub.json'));

  const res = Signing.open(sealed, { dir });
  assert.strictEqual(res.ok, false);
  assert.strictEqual(res.code, 'UNTRUSTED_KEY');
});

test('a receipt signed with an explicitly selected retired key is refused', () => {
  const dir = keyring();
  Signing.ensureKeyring({ dir });
  const rotated = Signing.rotateKey({ dir });

  assert.throws(
    () => Signing.seal(makeEnvelope(), { dir, keyId: rotated.previous_key_id }),
    /retired|KEY_NOT_ACTIVE/
  );
});

test('concurrent first use creates exactly one key, atomically', { timeout: 30000 }, async () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'verifyd-key-race-'));
  dirs.push(parent);
  const target = path.join(parent, 'keys');
  const goFile = path.join(parent, 'go');
  const signingPath = path.join(__dirname, '..', 'signing.cjs');
  const script = [
    "const fs = require('fs');",
    'const Signing = require(process.argv[1]);',
    'const go = process.argv[2];',
    'const target = process.argv[3];',
    'const start = Date.now();',
    'while (!fs.existsSync(go)) { if (Date.now() - start > 10000) process.exit(3); }',
    'const out = Signing.ensureKeyring({ dir: target });',
    'process.stdout.write(JSON.stringify(out));',
  ].join('\n');

  const children = Array.from({ length: 8 }, () => spawn(
    process.execPath,
    ['-e', script, signingPath, goFile, target],
    { stdio: ['ignore', 'pipe', 'pipe'] }
  ));

  const results = children.map(child => new Promise(resolve => {
    let out = '';
    let err = '';
    const timer = setTimeout(() => child.kill(), 15000);
    child.stdout.on('data', chunk => { out += chunk; });
    child.stderr.on('data', chunk => { err += chunk; });
    child.on('close', code => {
      clearTimeout(timer);
      resolve({ code, out, err });
    });
  }));

  // Release every process at once, after all eight are waiting on the same file.
  fs.writeFileSync(goFile, 'go\n');
  const settled = await Promise.all(results);

  for (const result of settled) {
    assert.strictEqual(result.code, 0, result.out + result.err);
  }
  const outcomes = settled.map(result => JSON.parse(result.out));
  const keyIds = new Set(outcomes.map(outcome => outcome.key_id));
  assert.strictEqual(keyIds.size, 1, 'all processes reuse the one winning key: ' + [...keyIds].join(', '));
  assert.strictEqual(outcomes.filter(outcome => outcome.created).length, 1,
    'exactly one process reports creating the keyring');

  const keys = Signing.listKeys({ dir: target });
  assert.strictEqual(keys.length, 1, 'one key wins');
  assert.strictEqual(keys[0].status, 'active');
  assert.strictEqual(fs.readFileSync(path.join(target, 'active'), 'utf8').trim(), keys[0].key_id);
  assert.strictEqual(fs.readdirSync(target).filter(name => name.endsWith('.key')).length, 1);
  assert.deepStrictEqual(fs.readdirSync(parent).filter(name => name.startsWith('.verifyd-keys-')), [],
    'losers clean up their temporary keyrings');
});

test('key ids are fingerprints of the SPKI public key', () => {
  const dir = keyring();
  const created = Signing.ensureKeyring({ dir });
  const key = Signing.listKeys({ dir })[0];
  assert.strictEqual(Signing.keyIdFromPem(key.public_key_pem), created.key_id);
  assert.strictEqual(created.key_id, 'ed25519:' + Signing.fingerprintOfPem(key.public_key_pem));
});

test('the signing payload is domain separated and excludes the signature', () => {
  const dir = keyring();
  const sealed = Signing.seal(makeEnvelope(), { dir });
  const payload = Signing.signingPayload(sealed).toString('utf8');
  assert.ok(payload.startsWith('verifyd-receipt-v1\n'));
  assert.ok(!payload.includes('"signature"'), 'signature block is not part of the signed bytes');
});
