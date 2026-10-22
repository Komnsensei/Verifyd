'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');
const { promisify } = require('util');
const { pathToFileURL } = require('url');

const execFileAsync = promisify(execFile);
const CLI = path.join(__dirname, '..', '..', 'bin', 'verifyd.cjs');
const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'verifyd-witness-cli-'));
const auditor = path.join(workspace, 'auditor');
const trusted = path.join(workspace, 'trusted');
const doc = path.join(workspace, 'subject.txt');
const receiptFile = path.join(workspace, 'subject.verifyd-receipt.json');

const Signing = require('../signing.cjs');
const Canonical = require('../canonicalize.cjs');
const Witness = require('../witness.cjs');

const identities = ['alice@example.org', 'bob@example.org', 'carol@example.org', 'dave@example.org'];
const witnesses = identities.map((identity, i) => ({
  identity,
  dir: path.join(workspace, 'w' + i),
  proof: path.join(workspace, 'proof-' + i + '.txt'),
}));

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

async function run(args) {
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, [CLI].concat(args), { cwd: workspace, encoding: 'utf8' });
    return { status: 0, out: stdout + stderr };
  } catch (e) {
    return { status: typeof e.code === 'number' ? e.code : 1, out: (e.stdout || '') + (e.stderr || '') };
  }
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function keyOf(dir) {
  return fs.readFileSync(path.join(dir, 'active'), 'utf8').trim();
}

function ratifiedEnvelope(attestationCount, signedAt) {
  const receipt = {
    valf_version: '1.0',
    receipt_id: crypto.randomUUID(),
    lattice: { status: 'RATIFIED' },
  };
  receipt.this_hash = sha256(Canonical.canonicalJSON(receipt, { omitKeys: ['this_hash'] }));
  const envelope = {
    valf_version: '1.0',
    receipt_type: 'document',
    signed_at: signedAt || new Date().toISOString(),
    document: { file: 'ratified.txt', sha256: sha256('ratified body') },
    receipt,
  };
  const sealed = Signing.seal(envelope, { dir: auditor });
  for (let i = 0; i < attestationCount; i++) {
    const w = witnesses[i];
    const att = Witness.attest(sealed, {
      dir: w.dir,
      identity: w.identity,
      proofContent: fs.readFileSync(w.proof),
      proofUri: pathToFileURL(w.proof).href,
    });
    Witness.attach(sealed, att);
  }
  return sealed;
}

function writeReceipt(name, envelope) {
  const file = path.join(workspace, name);
  fs.writeFileSync(file, JSON.stringify(envelope, null, 2) + '\n');
  return file;
}

test.before(async () => {
  fs.writeFileSync(doc, 'Witness identity proofing subject document.\n');
  const audit = await run(['audit', doc, '--keyring', auditor]);
  assert.strictEqual(audit.status, 0, audit.out);

  for (const w of witnesses) {
    const init = await run(['witness', 'init', '--keyring', w.dir]);
    assert.strictEqual(init.status, 0, init.out);
    const prove = await run(['witness', 'prove', w.identity, '--proof-out', w.proof, '--keyring', w.dir]);
    assert.strictEqual(prove.status, 0, prove.out);
    const register = await run(['witness', 'register', w.dir, '--into', trusted]);
    assert.strictEqual(register.status, 0, register.out);
  }
  for (const w of witnesses) {
    const att = await run(['witness', 'attest', receiptFile, '--identity', w.identity, '--proof', w.proof, '--keyring', w.dir, '--proof-uri', pathToFileURL(w.proof).href]);
    assert.strictEqual(att.status, 0, att.out);
  }
});

test.after(() => {
  fs.rmSync(workspace, { recursive: true, force: true });
});

test('four witnesses with proofs produce a traceable quorum, signature intact', async () => {
  const res = await run(['verify', receiptFile, '--keyring', auditor, '--witness-keys', trusted]);
  assert.strictEqual(res.status, 0, res.out);
  assert.match(res.out, /Signature:\s+VALID/);
  assert.match(res.out, /Witnesses:\s+4 counted of 4 required \(QUORUM MET\)/);
  for (const identity of identities) assert.match(res.out, new RegExp('counted\\s+' + identity.replace('.', '\\.')));
  assert.match(res.out, /tier=key/);
  assert.doesNotMatch(res.out, /rejected/);
});

test('the same witness key under a second label does not add a witness', async () => {
  const alias = path.join(workspace, 'proof-alias.txt');
  const second = 'alice-alt@example.org';
  fs.writeFileSync(alias, Witness.bindingLine(keyOf(witnesses[0].dir), second) + '\n');
  const att = await run(['witness', 'attest', receiptFile, '--identity', second, '--proof', alias, '--keyring', witnesses[0].dir]);
  assert.strictEqual(att.status, 0, att.out);

  const res = await run(['verify', receiptFile, '--keyring', auditor, '--witness-keys', trusted]);
  assert.strictEqual(res.status, 0, res.out);
  assert.match(res.out, /4 counted of 4 required/);
  assert.match(res.out, /same_key_multiple_labels/);
});

test('a revoked witness key is reported and stops contributing', async () => {
  const revokedRing = path.join(workspace, 'trusted-revoked');
  fs.cpSync(trusted, revokedRing, { recursive: true });
  const revoke = await run(['witness', 'revoke', keyOf(witnesses[3].dir), '--into', revokedRing]);
  assert.strictEqual(revoke.status, 0, revoke.out);

  const res = await run(['verify', receiptFile, '--keyring', auditor, '--witness-keys', revokedRing]);
  assert.strictEqual(res.status, 0, res.out);
  assert.match(res.out, /3 counted of 4 required \(QUORUM NOT MET\)/);
  assert.match(res.out, /key_revoked/);
});

test('an expired witness key is reported and stops contributing', async () => {
  const expiredRing = path.join(workspace, 'trusted-expired');
  fs.cpSync(trusted, expiredRing, { recursive: true });
  const register = await run(['witness', 'register', witnesses[2].dir, '--into', expiredRing, '--expires', '2020-01-01T00:00:00.000Z']);
  assert.strictEqual(register.status, 0, register.out);

  const res = await run(['verify', receiptFile, '--keyring', auditor, '--witness-keys', expiredRing]);
  assert.strictEqual(res.status, 0, res.out);
  assert.match(res.out, /3 counted of 4 required/);
  assert.match(res.out, /key_expired/);
});

test('without witness keys the receipt says attestations were not assessed', async () => {
  const res = await run(['verify', receiptFile, '--keyring', auditor]);
  assert.strictEqual(res.status, 0, res.out);
  assert.match(res.out, /Witnesses:\s+NOT ASSESSED \(witness_keyring_missing/);
  assert.match(res.out, /Status:\s+VALID/);
});

test('the audited party signing as witness is rejected', async () => {
  const proof = path.join(workspace, 'auditor-self.txt');
  fs.writeFileSync(proof, Witness.bindingLine(keyOf(auditor), 'auditor@example.org') + '\n');
  const att = await run(['witness', 'attest', receiptFile, '--identity', 'auditor@example.org', '--proof', proof, '--keyring', auditor]);
  assert.strictEqual(att.status, 0, att.out);

  const res = await run(['verify', receiptFile, '--keyring', auditor, '--witness-keys', trusted]);
  assert.strictEqual(res.status, 0, res.out);
  assert.match(res.out, /self_witness/);
  assert.match(res.out, /4 counted of 4 required/);
});

test('a RATIFIED claim with one witness is rejected', async () => {
  const file = writeReceipt('ratified-one.verifyd-receipt.json', ratifiedEnvelope(1));
  const res = await run(['verify', file, '--keyring', auditor, '--witness-keys', trusted]);
  assert.strictEqual(res.status, 1, res.out);
  assert.match(res.out, /Signature:\s+VALID/);
  assert.match(res.out, /Witnesses:\s+1 counted of 4 required \(QUORUM NOT MET\)/);
  assert.match(res.out, /Status:\s+REJECTED/);
  assert.match(res.out, /Reason:\s+RATIFIED claim is not backed by quorum \(1\/4\)/);
});

test('a RATIFIED claim with no attestations is rejected', async () => {
  const file = writeReceipt('ratified-none.verifyd-receipt.json', ratifiedEnvelope(0));
  const res = await run(['verify', file, '--keyring', auditor]);
  assert.strictEqual(res.status, 1, res.out);
  assert.match(res.out, /Witnesses:\s+none/);
  assert.match(res.out, /Reason:\s+RATIFIED claimed with no witness attestations/);
});

test('a RATIFIED claim with a met quorum passes and says so', async () => {
  const file = writeReceipt('ratified-four.verifyd-receipt.json', ratifiedEnvelope(4));
  const res = await run(['verify', file, '--keyring', auditor, '--witness-keys', trusted]);
  assert.strictEqual(res.status, 0, res.out);
  assert.match(res.out, /Witnesses:\s+4 counted of 4 required \(QUORUM MET\)/);
  assert.match(res.out, /Lattice:\s+RATIFIED \(quorum verified against witness keys\)/);
  assert.match(res.out, /Status:\s+VALID/);
});

test('certify refuses a RATIFIED claim without quorum, matching verify', async () => {
  const file = writeReceipt('certify-ratified-one.verifyd-receipt.json', ratifiedEnvelope(1));
  const cert = await run(['certify', file, '--keyring', auditor, '--witness-keys', trusted,
    '--out', path.join(workspace, 'ratified-one-certificate.txt')]);
  assert.strictEqual(cert.status, 1, cert.out);
  assert.match(cert.out, /Verification:\s+REJECTED/);
  assert.match(cert.out, /Seal Status:\s+REJECTED/);
  assert.match(cert.out, /Lattice Status:\s+RATIFIED \(UNVERIFIED\)/);
  assert.match(cert.out, /Reason:\s+RATIFIED claim is not backed by quorum \(1\/4\)/);
});

test('certify accepts a RATIFIED claim with a met quorum', async () => {
  const file = writeReceipt('certify-ratified-four.verifyd-receipt.json', ratifiedEnvelope(4));
  const cert = await run(['certify', file, '--keyring', auditor, '--witness-keys', trusted,
    '--out', path.join(workspace, 'ratified-four-certificate.txt')]);
  assert.strictEqual(cert.status, 0, cert.out);
  assert.match(cert.out, /Verification:\s+PASSED/);
  assert.match(cert.out, /Seal Status:\s+RATIFIED/);
  assert.doesNotMatch(cert.out, /Verification:\s+REJECTED/);
});

test('a RATIFIED claim that cannot be assessed without a witness keyring is rejected', async () => {
  const file = writeReceipt('ratified-unassessed.verifyd-receipt.json', ratifiedEnvelope(4));
  const res = await run(['verify', file, '--keyring', auditor]);
  assert.strictEqual(res.status, 1, res.out);
  assert.match(res.out, /Witnesses:\s+NOT ASSESSED/);
  assert.match(res.out, /Reason:\s+RATIFIED claim cannot be checked without a witness keyring/);
});

test('vouching through the CLI records the tier', async () => {
  const v = {
    dir: path.join(workspace, 'voucher'),
    proof: path.join(workspace, 'voucher-proof.txt'),
    identity: 'voucher@example.org',
  };
  await run(['witness', 'init', '--keyring', v.dir]);
  await run(['witness', 'prove', v.identity, '--proof-out', v.proof, '--keyring', v.dir]);
  await run(['witness', 'register', v.dir, '--into', trusted]);

  const vouch = await run(['witness', 'vouch', receiptFile, '--witness-key', keyOf(witnesses[0].dir), '--identity', identities[0], '--keyring', v.dir, '--method', 'organizational']);
  assert.strictEqual(vouch.status, 0, vouch.out);
  assert.match(vouch.out, /Tier:\s+vouched/);

  const res = await run(['verify', receiptFile, '--keyring', auditor, '--witness-keys', trusted]);
  assert.strictEqual(res.status, 0, res.out);
  assert.match(res.out, /tier=vouched, voucher ed25519:/);
});
