'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const CLI = path.join(__dirname, '..', '..', 'bin', 'verifyd.cjs');
const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'verifyd-cli-'));
const keyringA = path.join(workspace, 'keys-a');
const keyringB = path.join(workspace, 'keys-b');
const keyringR = path.join(workspace, 'keys-rotate');
const docFile = path.join(workspace, 'note.txt');

fs.writeFileSync(docFile, [
  'A short document about evidence handling.',
  'It records provenance, source anchors, and hashes for audit review.',
  'No external identifiers are present here.',
].join('\n'));

function run(args, opts) {
  const res = spawnSync(process.execPath, [CLI].concat(args), {
    cwd: workspace,
    encoding: 'utf8',
    env: Object.assign({}, process.env, (opts && opts.env) || {}),
  });
  return { status: res.status, out: (res.stdout || '') + (res.stderr || '') };
}

function receiptPath() {
  return path.join(workspace, 'note.verifyd-receipt.json');
}

function readReceipt() {
  return JSON.parse(fs.readFileSync(receiptPath(), 'utf8'));
}

function writeReceipt(data) {
  fs.writeFileSync(receiptPath(), JSON.stringify(data, null, 2));
}

function audit(keyring) {
  const res = run(['audit', 'note.txt', '--keyring', keyring]);
  assert.strictEqual(res.status, 0, res.out);
  const match = res.out.match(/Signer:\s+(ed25519:[0-9a-f]{64})/);
  assert.ok(match, 'audit reports the signer key id:\n' + res.out);
  return match[1];
}

test.after(() => {
  fs.rmSync(workspace, { recursive: true, force: true });
});

test('audit writes one signed envelope with no duplicated audit block', () => {
  const keyId = audit(keyringA);
  const data = readReceipt();

  assert.strictEqual(data.signature.algorithm, 'ed25519');
  assert.strictEqual(data.signature.key_id, keyId);
  assert.ok(data.signature.value.length > 40);
  assert.ok(data.document.sha256);
  assert.ok(data.receipt.this_hash);

  assert.strictEqual(data.audit, undefined, 'no unhashed duplicate of the receipt');
  assert.strictEqual(data.chain_valid, undefined, 'no unverified derived field in the file');
  assert.strictEqual(typeof data.receipt.lattice.status, 'string', 'lattice status recorded on the receipt');
});

test('verify accepts the receipt it just signed', () => {
  audit(keyringA);
  const res = run(['verify', 'note.verifyd-receipt.json', '--keyring', keyringA]);
  assert.strictEqual(res.status, 0, res.out);
  assert.match(res.out, /Signature:\s+VALID/);
  assert.match(res.out, /Receipt hash:\s+VALID/);
  assert.match(res.out, /Status:\s+VALID/);
});

test('verify rejects a receipt whose signature was stripped', () => {
  audit(keyringA);
  const data = readReceipt();
  delete data.signature;
  writeReceipt(data);

  const res = run(['verify', 'note.verifyd-receipt.json', '--keyring', keyringA]);
  assert.strictEqual(res.status, 1, res.out);
  assert.match(res.out, /Signature:\s+UNSIGNED/);
  assert.match(res.out, /Status:\s+REJECTED/);
});

test('verify rejects a directory instead of leaking EISDIR', () => {
  fs.mkdirSync(path.join(workspace, 'a-receipt-folder'), { recursive: true });
  const res = run(['verify', 'a-receipt-folder']);
  assert.strictEqual(res.status, 1, res.out);
  assert.match(res.out, /not a receipt file/);
  assert.doesNotMatch(res.out, /EISDIR/);
});

test('audit rejects a directory with a pointer to audit-folder', () => {
  fs.mkdirSync(path.join(workspace, 'a-directory'), { recursive: true });
  const res = run(['audit', 'a-directory', '--keyring', keyringA]);
  assert.strictEqual(res.status, 1, res.out);
  assert.match(res.out, /not a file/);
  assert.match(res.out, /audit-folder/);
});

test('audit rejects binary data and counts an empty file as zero words', () => {
  fs.writeFileSync(path.join(workspace, 'blob.bin'), Buffer.from([0, 1, 2, 3]));
  const binary = run(['audit', 'blob.bin', '--keyring', keyringA]);
  assert.strictEqual(binary.status, 1, binary.out);
  assert.match(binary.out, /not a text document/);
  assert.ok(!fs.existsSync(path.join(workspace, 'blob.verifyd-receipt.json')));

  fs.writeFileSync(path.join(workspace, 'empty.txt'), '');
  const empty = run(['audit', 'empty.txt', '--keyring', keyringA]);
  assert.strictEqual(empty.status, 0, empty.out);
  assert.match(empty.out, /Words:\s+0/);
  const receipt = JSON.parse(fs.readFileSync(path.join(workspace, 'empty.verifyd-receipt.json'), 'utf8'));
  assert.strictEqual(receipt.document.words, 0);
});

test('verify sends light metadata receipts to the light command', () => {
  const made = run(['light', 'note.txt']);
  assert.strictEqual(made.status, 0, made.out);

  const res = run(['verify', 'note.verifyd-light-receipt.json', '--keyring', keyringA]);
  assert.strictEqual(res.status, 1, res.out);
  assert.match(res.out, /Light metadata receipts carry no signature/);
  assert.doesNotMatch(res.out, /verify-folder/);
});

test('verify reports a determination directory as unreadable, not as JSON', () => {
  audit(keyringA);
  const dir = path.join(workspace, 'a-determination-dir');
  fs.mkdirSync(dir, { recursive: true });

  const res = run(['verify', 'note.verifyd-receipt.json', '--keyring', keyringA, '--determination', dir]);
  assert.strictEqual(res.status, 1, res.out);
  assert.match(res.out, /Determination:\s+UNREADABLE/);
  assert.match(res.out, /Reason:\s+determination path is a directory/);
  assert.doesNotMatch(res.out, /EISDIR/);
});

test('verify refuses a determination that is not an object without crashing', () => {
  audit(keyringA);
  const nullFile = path.join(workspace, 'null-determination.json');
  fs.writeFileSync(nullFile, 'null\n');

  const res = run(['verify', 'note.verifyd-receipt.json', '--keyring', keyringA, '--determination', nullFile]);
  assert.strictEqual(res.status, 1, res.out);
  assert.match(res.out, /Determination:\s+UNREADABLE/);
  assert.match(res.out, /Reason:\s+determination is not a JSON object/);
  assert.doesNotMatch(res.out, /Cannot read|TypeError/);
});

test('verify rejects a receipt whose document quality was altered', () => {
  audit(keyringA);
  const data = readReceipt();
  const before = data.receipt.document_quality.value;
  data.receipt.document_quality.value = 100;
  writeReceipt(data);

  const res = run(['verify', 'note.verifyd-receipt.json', '--keyring', keyringA]);
  assert.strictEqual(res.status, 1, res.out);
  assert.match(res.out, /Signature:\s+SIGNATURE_INVALID/);
  assert.ok(before !== 100, 'fixture starts below 100 so the change is real');
  assert.strictEqual(data.receipt.document_quality.calibrated, false, 'the heuristic is not a calibrated score');
});

test('verify rejects a receipt tampered through the removed audit copy', () => {
  audit(keyringA);
  const data = readReceipt();
  // The old exploit: an unhashed duplicate that the certifier rendered.
  data.audit = { trust_score: { value: 100 }, lattice_status: 'RATIFIED' };
  writeReceipt(data);

  const res = run(['verify', 'note.verifyd-receipt.json', '--keyring', keyringA]);
  assert.strictEqual(res.status, 1, res.out);
  assert.match(res.out, /SIGNATURE_INVALID/);
});

test('verify rejects a signer the keyring does not trust', () => {
  audit(keyringB);
  const res = run(['verify', 'note.verifyd-receipt.json', '--keyring', keyringA]);
  assert.strictEqual(res.status, 1, res.out);
  assert.match(res.out, /UNTRUSTED_KEY/);
  assert.match(res.out, /Status:\s+REJECTED/);
});

test('verify honours the keyring chosen through the environment', () => {
  audit(keyringA);
  const res = run(['verify', 'note.verifyd-receipt.json'], { env: { VERIFYD_KEYRING: keyringA } });
  assert.strictEqual(res.status, 0, res.out);
  assert.match(res.out, /Status:\s+VALID/);
});

test('rotation keeps the old receipt valid and signs new receipts with the new key', () => {
  const firstKey = audit(keyringR);

  const rotated = run(['keys', 'rotate', '--keyring', keyringR]);
  assert.strictEqual(rotated.status, 0, rotated.out);
  const newKey = (rotated.out.match(/Active:\s+(ed25519:[0-9a-f]{64})/) || [])[1];
  assert.ok(newKey && newKey !== firstKey, rotated.out);

  const oldVerify = run(['verify', 'note.verifyd-receipt.json', '--keyring', keyringR]);
  assert.strictEqual(oldVerify.status, 0, oldVerify.out);

  const secondKey = audit(keyringR);
  assert.strictEqual(secondKey, newKey);

  const newVerify = run(['verify', 'note.verifyd-receipt.json', '--keyring', keyringR]);
  assert.strictEqual(newVerify.status, 0, newVerify.out);

  const listed = run(['keys', 'list', '--keyring', keyringR]);
  assert.strictEqual(listed.status, 0, listed.out);
  assert.match(listed.out, /status=retired/);
  assert.match(listed.out, /status=active/);
});

test('certify renders the signature, the heuristic and the recomputed probability', () => {
  audit(keyringA);
  const res = run(['certify', 'note.verifyd-receipt.json', '--keyring', keyringA]);
  assert.strictEqual(res.status, 0, res.out);
  assert.match(res.out, /Receipt Signature:?\s+VALID/);
  assert.match(res.out, /Signer Key ID:?\s+ed25519:/);
  assert.match(res.out, /Doc Quality:?\s+\d+ \/ 100 \(heuristic, UNCALIBRATED/);
  assert.match(res.out, /Assurance:?\s+\d+ \/ 100\s+p=/);
  assert.match(res.out, /synthetic labels/);
});

test('certify does not call a tampered receipt valid', () => {
  audit(keyringA);
  const data = readReceipt();
  data.receipt.outputs[0].content_hash = 'f'.repeat(64);
  writeReceipt(data);

  const res = run(['certify', 'note.verifyd-receipt.json', '--keyring', keyringA,
    '--out', path.join(workspace, 'tampered-cert.txt')]);
  assert.strictEqual(res.status, 1, res.out);
  assert.match(res.out, /Hash Status:\s+MISMATCH/);
  assert.match(res.out, /Receipt Signature:\s+SIGNATURE_INVALID/);
  assert.match(res.out, /Seal Status:\s+TAMPERED/);
});

test('certify does not stamp an unsigned folder record VALID', () => {
  fs.mkdirSync(path.join(workspace, 'deck'), { recursive: true });
  fs.writeFileSync(path.join(workspace, 'deck', 'one.txt'), 'one\n');

  const folder = run(['audit-folder', 'deck']);
  assert.strictEqual(folder.status, 0, folder.out);

  const res = run(['certify', 'deck.verifyd-folder-receipt.json',
    '--out', path.join(workspace, 'deck-certificate.txt')]);
  assert.match(res.out, /RECEIPT INTEGRITY\s+VALID/);
  assert.match(res.out, /Seal Status:\s+UNVERIFIED/);
  assert.match(res.out, /Receipt Signature:\s+UNSIGNED/);
  assert.doesNotMatch(res.out, /Seal Status:\s+VALID/);
});

test('certify rejects a directory instead of leaking EISDIR', () => {
  fs.mkdirSync(path.join(workspace, 'a-certify-folder'), { recursive: true });
  const res = run(['certify', 'a-certify-folder']);
  assert.strictEqual(res.status, 1, res.out);
  assert.match(res.out, /not a receipt file/);
  assert.doesNotMatch(res.out, /EISDIR/);
});

test('certify refuses JSON that is not a receipt instead of certifying it', () => {
  for (const value of [[], null, {}]) {
    writeReceipt(value);
    const res = run(['certify', 'note.verifyd-receipt.json', '--out', path.join(workspace, 'bad-cert.txt')]);
    assert.strictEqual(res.status, 1, res.out);
    assert.match(res.out, /not a receipt/);
  }
  assert.ok(!fs.existsSync(path.join(workspace, 'bad-cert.txt')));
});

test('a legacy unsigned receipt is rejected with a reason, not a crash', () => {
  writeReceipt({
    document: { file: 'note.txt', sha256: 'b'.repeat(64), words: 3 },
    receipt: { valf_version: '1.0', receipt_id: 'legacy-1', this_hash: 'c'.repeat(64) },
  });

  const res = run(['verify', 'note.verifyd-receipt.json', '--keyring', keyringA]);
  assert.strictEqual(res.status, 1, res.out);
  assert.match(res.out, /UNSIGNED/);
  assert.ok(!res.out.includes('at Object.<anonymous>'), 'no stack trace');
});

test('a folder receipt is redirected to verify-folder instead of crashing', () => {
  writeReceipt({ valf_version: '1.0', receipt_type: 'folder', receipt_id: 'folder-1', folder: {}, this_hash: 'd'.repeat(64) });

  const res = run(['verify', 'note.verifyd-receipt.json', '--keyring', keyringA]);
  assert.strictEqual(res.status, 1, res.out);
  assert.match(res.out, /not a signed document receipt/);
  assert.match(res.out, /verify-folder/);
  assert.ok(!res.out.includes('canonicalize.cjs'), 'no uncaught canonicalization error');
});

test('keys path reports the configured keyring without creating it', () => {
  const target = path.join(workspace, 'keys-never-created');
  const res = run(['keys', 'path', '--keyring', target]);
  assert.strictEqual(res.status, 0, res.out);
  assert.strictEqual(res.out.trim(), target);
  assert.strictEqual(fs.existsSync(target), false);
});
