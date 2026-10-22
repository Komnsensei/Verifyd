'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');
const { promisify } = require('util');

const { hasOpenssl, startTsa } = require('./helpers/test-tsa.cjs');

const execFileAsync = promisify(execFile);
const CLI = path.join(__dirname, '..', '..', 'bin', 'verifyd.cjs');
const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'verifyd-merkle-cli-'));
const keyring = path.join(workspace, 'keys');
const workA = path.join(workspace, 'workA');
const workB = path.join(workspace, 'workB');

const available = hasOpenssl();
const skip = available ? false : 'openssl is not available';

let tsa = null;

for (const dir of [workA, workB]) fs.mkdirSync(dir, { recursive: true });

function writeDoc(dir, name, text) {
  fs.writeFileSync(path.join(dir, name), text);
  return path.join(dir, name);
}

const docsA = [
  writeDoc(workA, 'alpha.txt', 'Alpha record. Provenance, source anchors, and hashes for audit review.\n'),
  writeDoc(workA, 'beta.txt', 'Beta record. Different bytes, different hashes, same batch.\n'),
  writeDoc(workA, 'gamma.txt', 'Gamma record. Third document in the batch for inclusion testing.\n'),
];
const docsB = [
  writeDoc(workB, 'delta.txt', 'Delta record. Belongs to a different batch entirely.\n'),
  writeDoc(workB, 'epsilon.txt', 'Epsilon record. Also in the other batch, with its own path.\n'),
];

async function run(args) {
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, [CLI].concat(args), {
      cwd: workspace,
      encoding: 'utf8',
    });
    return { status: 0, out: stdout + stderr };
  } catch (e) {
    return { status: typeof e.code === 'number' ? e.code : 1, out: (e.stdout || '') + (e.stderr || '') };
  }
}

function receiptPath(file) {
  return file.replace(/\.[^.]+$/, '') + '.verifyd-receipt.json';
}

async function audit(file) {
  const res = await run(['audit', file, '--keyring', keyring]);
  assert.strictEqual(res.status, 0, res.out);
  return receiptPath(file);
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function writeJson(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2) + '\n');
}

test.before(async () => {
  for (const doc of docsA.concat(docsB)) await audit(doc);
});

test.after(async () => {
  if (tsa) await tsa.close();
  fs.rmSync(workspace, { recursive: true, force: true });
});

test('batch commits receipts to a root and attaches a proof to each', async () => {
  const res = await run(['batch', workA, '--keyring', keyring]);
  assert.strictEqual(res.status, 0, res.out);
  assert.match(res.out, /Receipts:\s+3/);

  const root = readJson(path.join(workA, 'verifyd-batch.json'));
  assert.strictEqual(root.tree_size, 3);
  assert.match(root.root_hash, /^[0-9a-f]{64}$/);
  assert.ok(root.signature && root.signature.value, 'root is signed');

  for (const doc of docsA) {
    const receipt = readJson(receiptPath(doc));
    assert.strictEqual(receipt.inclusion.root_hash, root.root_hash);
    assert.strictEqual(receipt.inclusion.tree_size, 3);
    assert.ok(Array.isArray(receipt.inclusion.path));
  }

  const indices = docsA.map(doc => readJson(receiptPath(doc)).inclusion.leaf_index).sort();
  assert.deepStrictEqual(indices, [0, 1, 2], 'each receipt holds its own index');
});

test('verify confirms inclusion using only the receipt, and flags the unanchored root', async () => {
  for (const doc of docsA) {
    const res = await run(['verify', receiptPath(doc), '--keyring', keyring]);
    assert.strictEqual(res.status, 0, res.out);
    assert.match(res.out, /Inclusion:\s+PROOF VALID, ROOT UNVERIFIED \(leaf \d of 3, root [0-9a-f]{12}; pass --batch to authenticate\)/);
  }
});

test('verify checks the signed root when given the batch file', async () => {
  const res = await run(['verify', receiptPath(docsA[1]), '--keyring', keyring, '--batch', path.join(workA, 'verifyd-batch.json')]);
  assert.strictEqual(res.status, 0, res.out);
  assert.match(res.out, /Root:\s+VALID \(ed25519:/);
  assert.match(res.out, /Batch check:\s+VALID/);
  assert.match(res.out, /Root time:\s+UNATTESTED/);
  assert.doesNotMatch(res.out, /unauthenticated/, 'an authenticated root carries no caveat');
});

test('the root is deterministic across runs, the batch id is not', async () => {
  const first = readJson(path.join(workA, 'verifyd-batch.json'));
  const res = await run(['batch', workA, '--keyring', keyring]);
  assert.strictEqual(res.status, 0, res.out);
  const second = readJson(path.join(workA, 'verifyd-batch.json'));

  assert.strictEqual(second.root_hash, first.root_hash);
  assert.notStrictEqual(second.batch_id, first.batch_id);
});

test('a root whose signature does not cover it is rejected', async () => {
  const batchFile = path.join(workA, 'verifyd-batch.json');
  const root = readJson(batchFile);
  root.root_hash = 'f'.repeat(64);
  writeJson(batchFile, root);

  const res = await run(['verify', receiptPath(docsA[0]), '--keyring', keyring, '--batch', batchFile]);
  assert.strictEqual(res.status, 1, res.out);
  assert.match(res.out, /Root:\s+REJECTED \(SIGNATURE_INVALID\)/);

  await run(['batch', workA, '--keyring', keyring]);
});

test('a batch root that is not an object is rejected without crashing', async () => {
  const nullRoot = path.join(workspace, 'null-root.json');
  fs.writeFileSync(nullRoot, 'null\n');
  const nullRes = await run(['verify', receiptPath(docsA[0]), '--keyring', keyring, '--batch', nullRoot]);
  assert.strictEqual(nullRes.status, 1, nullRes.out);
  assert.match(nullRes.out, /Root:\s+UNREADABLE/);
  assert.match(nullRes.out, /Batch check:\s+INVALID \(batch root is not an object\)/);
  assert.doesNotMatch(nullRes.out, /Cannot read|TypeError/);

  const emptyRoot = path.join(workspace, 'empty-root.json');
  fs.writeFileSync(emptyRoot, '{}\n');
  const emptyRes = await run(['verify', receiptPath(docsA[0]), '--keyring', keyring, '--batch', emptyRoot]);
  assert.strictEqual(emptyRes.status, 1, emptyRes.out);
  assert.match(emptyRes.out, /Batch check:\s+INVALID \(batch root is missing required fields\)/);
  assert.doesNotMatch(emptyRes.out, /Cannot read|TypeError/);
});

test('certify enforces the batch root it is given', async () => {
  const receipt = receiptPath(docsA[0]);
  const batchFile = path.join(workA, 'verifyd-batch.json');
  const good = await run(['certify', receipt, '--keyring', keyring, '--batch', batchFile,
    '--out', path.join(workspace, 'batched-certificate.txt')]);
  assert.strictEqual(good.status, 0, good.out);
  assert.match(good.out, /Verification:\s+PASSED/);

  const badRoot = path.join(workspace, 'certify-null-root.json');
  fs.writeFileSync(badRoot, 'null\n');
  const bad = await run(['certify', receipt, '--keyring', keyring, '--batch', badRoot,
    '--out', path.join(workspace, 'bad-batch-certificate.txt')]);
  assert.strictEqual(bad.status, 1, bad.out);
  assert.match(bad.out, /Verification:\s+REJECTED/);
  assert.match(bad.out, /Seal Status:\s+REJECTED/);
  assert.match(bad.out, /batch root is not an object/);
});

test('a proof lifted from another batch is rejected', async () => {
  const batchB = await run(['batch', workB, '--keyring', keyring]);
  assert.strictEqual(batchB.status, 0, batchB.out);

  const receiptA = receiptPath(docsA[0]);
  const receiptB = receiptPath(docsB[0]);
  const dataA = readJson(receiptA);
  dataA.inclusion = readJson(receiptB).inclusion;
  writeJson(receiptA, dataA);

  const res = await run(['verify', receiptA, '--keyring', keyring, '--batch', path.join(workA, 'verifyd-batch.json')]);
  assert.strictEqual(res.status, 1, res.out);
  assert.match(res.out, /Batch check:\s+INVALID \(batch_id mismatch/);

  await run(['batch', workA, '--keyring', keyring]);
});

test('a tampered tree size in the proof is rejected', async () => {
  const receiptFile = receiptPath(docsA[2]);
  const data = readJson(receiptFile);
  data.inclusion.tree_size = 2;
  writeJson(receiptFile, data);

  const res = await run(['verify', receiptFile, '--keyring', keyring]);
  assert.strictEqual(res.status, 1, res.out);
  assert.match(res.out, /Inclusion:\s+INVALID/);

  await run(['batch', workA, '--keyring', keyring]);
});

test('a tampered path is rejected', async () => {
  const receiptFile = receiptPath(docsA[1]);
  const data = readJson(receiptFile);
  data.inclusion.path[0] = 'a'.repeat(64);
  writeJson(receiptFile, data);

  const res = await run(['verify', receiptFile, '--keyring', keyring]);
  assert.strictEqual(res.status, 1, res.out);
  assert.match(res.out, /Inclusion:\s+INVALID \(root_mismatch\)/);

  await run(['batch', workA, '--keyring', keyring]);
});

test('an unbatched receipt still verifies and reports no inclusion', async () => {
  const extra = writeDoc(workA, 'zeta.txt', 'Zeta record. Audited after the batch was made.\n');
  const receipt = await audit(extra);

  const res = await run(['verify', receipt, '--keyring', keyring]);
  assert.strictEqual(res.status, 0, res.out);
  assert.match(res.out, /Inclusion:\s+NOT PRESENT/);
  assert.match(res.out, /Status:\s+VALID/);
});

test('batch refuses to build a root over an unverified receipt', async () => {
  const bad = path.join(workB, 'unsigned.verifyd-receipt.json');
  fs.writeFileSync(bad, JSON.stringify({
    document: { file: 'x.txt' },
    receipt: { receipt_id: 'r1', this_hash: 'b'.repeat(64) },
  }));

  const res = await run(['batch', workB, '--keyring', keyring]);
  assert.strictEqual(res.status, 1, res.out);
  assert.match(res.out, /no root over unverified receipts/);

  fs.rmSync(bad);
});

test('the root can be timestamped and verified against a TSA root', { skip }, async () => {
  tsa = await startTsa();
  const res = await run(['batch', workA, '--keyring', keyring, '--tsa', tsa.url]);
  assert.strictEqual(res.status, 0, res.out);

  const batchFile = path.join(workA, 'verifyd-batch.json');
  const root = readJson(batchFile);
  assert.ok(root.timestamp && root.timestamp.token, 'root carries a token');

  const verified = await run(['verify', receiptPath(docsA[0]), '--keyring', keyring, '--batch', batchFile, '--tsa-ca', tsa.caPath]);
  assert.strictEqual(verified.status, 0, verified.out);
  assert.match(verified.out, /Root time:\s+ATTESTED \d{4}-\d{2}-\d{2}T/);
  assert.match(verified.out, /Batch check:\s+VALID/);

  const wrongCa = await run(['verify', receiptPath(docsA[0]), '--keyring', keyring, '--batch', batchFile, '--tsa-ca', 'missing.pem']);
  assert.strictEqual(wrongCa.status, 1, wrongCa.out);

  await run(['batch', workA, '--keyring', keyring]);
});
