// Phase D2 acceptance: an admin-signed revocation ends a writer's authority at
// `revoked_at`, and never before a record the ledger already holds.
//
// Two rules carry the weight here, and both are about position rather than the
// writer's word:
//
//   1. Any record that appears past the head a revocation binds was written
//      after that revocation was issued. Its `recorded_at` cannot place it
//      before the boundary, because the writer chose that timestamp. It is
//      refused as a backdated revocation, not interpreted.
//   2. A revocation is evidence only once the ledger contains its commitment
//      entry. Deleting or truncating `<ledger>.revocations.jsonl` therefore
//      fails closed: the commitment remains and the record does not.

'use strict';

const test = require('node:test');
const assert = require('node:assert');

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const Format = require('../ledger-format.cjs');
const Ledger = require('../ledger.cjs');
const Policy = require('../ledger-policy.cjs');
const Store = require('../ledger-store.cjs');
const Merkle = require('../merkle.cjs');
const Signing = require('../signing.cjs');
const Verify = require('../ledger-verify.cjs');

const ROOT = path.resolve(__dirname, '..', '..');
const CLI = path.join(ROOT, 'bin', 'verifyd.cjs');

function digestOf(label) {
  return crypto.createHash('sha256').update(label).digest('hex');
}

function makeEnv(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ledger-revocation-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const keyring = path.join(root, 'keys');
  const otherKeyring = path.join(root, 'other-keys');
  const admin = Signing.ensureKeyring({ dir: keyring });
  const other = Signing.ensureKeyring({ dir: otherKeyring });
  const ledger = path.join(root, 'audit.ledger');
  const T0 = Date.parse('2026-01-01T00:00:00.000Z');
  const at = seconds => () => new Date(T0 + seconds * 1000);
  const plus = seconds => new Date(T0 + seconds * 1000).toISOString();
  const signer = Ledger.keyringSigner({ dir: keyring });
  const signerOther = Ledger.keyringSigner({ dir: otherKeyring });
  const init = Ledger.initLedger(ledger, {
    signer,
    policy: { writer_keys: [admin.key_id, other.key_id], admin_keys: [admin.key_id] },
    now: at(0),
  });

  return {
    root,
    keyring,
    otherKeyring,
    ledger,
    adminKeyId: admin.key_id,
    otherKeyId: other.key_id,
    signer,
    signerOther,
    T0,
    at,
    plus,
    ledgerId: init.ledger_id,
    genesis: init.genesis,
    paths: Ledger.ledgerPaths(ledger),
  };
}

function appendAt(env, label, seconds, signer, keyring) {
  return Ledger.append(env.ledger, {
    signer: signer || env.signer,
    keyring: keyring || env.keyring,
    payload_digest: digestOf(label),
    now: env.at(seconds),
  });
}

// One append attempt from a second process, with no retry: the question is
// whether the write is refused while a restore holds the lock, not whether it
// would eventually win. Exit 7 means LEDGER_LOCKED; 8 is any other failure.
function tryAppend(env, label) {
  const script = [
    "const L = require(process.env.LEDGER_MODULE);",
    "try {",
    "  L.append(process.env.LEDGER_PATH, {",
    "    signer: L.keyringSigner({ dir: process.env.LEDGER_KEYRING }),",
    "    keyring: process.env.LEDGER_KEYRING,",
    "    payload_digest: process.env.LEDGER_DIGEST,",
    "    receipt_id: 'contender',",
    "  });",
    "  process.exit(0);",
    "} catch (e) {",
    "  console.error(e.code || e.message);",
    "  process.exit(e.code === 'LEDGER_LOCKED' ? 7 : 8);",
    "}",
  ].join('\n');
  return spawnSync(process.execPath, ['-e', script], {
    encoding: 'utf8',
    timeout: 20000,
    env: Object.assign({}, process.env, {
      LEDGER_MODULE: path.join(ROOT, 'engine', 'ledger.cjs'),
      LEDGER_PATH: env.ledger,
      LEDGER_KEYRING: env.keyring,
      LEDGER_DIGEST: digestOf(label),
    }),
  });
}

function checkpoints(env) {
  return fs.readFileSync(env.paths.checkpoints, 'utf8').split('\n').filter(Boolean).map(JSON.parse);
}

function entries(env) {
  return fs.readFileSync(env.paths.entries, 'utf8').split('\n').filter(Boolean).map(JSON.parse);
}

function manualRevocation(env, fields) {
  return Ledger.signRevocation(Ledger.buildRevocation({
    ledger_id: env.ledgerId,
    key_id: fields.key_id,
    revoked_at: fields.revoked_at,
    recorded_at: fields.recorded_at,
    head_tree_size: fields.head.tree_size,
    head_checkpoint_hash: fields.head.checkpoint_hash,
    reason: fields.reason === undefined ? null : fields.reason,
  }), fields.signer);
}

// A hand-written record is only evidence once the ledger commits to it, exactly
// as revokeWriter does. `append` refuses the reserved id, so these fixtures
// write the entry directly, the way a ledger written before the guard would
// have; the read path must still recognise the commitment.
function commitManually(env, record, signer) {
  signer = signer || env.signer;
  const prior = entries(env);
  const seq = prior.length + 1;
  const body = Ledger.entryBody({
    ledger_id: env.ledgerId,
    seq,
    payload_digest: Ledger.revocationCommitmentDigest(record),
    receipt_id: Ledger.REVOCATION_COMMITMENT_PREFIX + record.key_id,
    recorded_at: record.recorded_at,
    writer_key_id: signer.key_id,
    prev_entry_hash: prior.length ? prior[prior.length - 1].entry_hash : Ledger.GENESIS,
  });
  const entry = Ledger.signEntry(Object.assign({}, body, { entry_hash: Ledger.entryHash(body) }), signer);
  fs.appendFileSync(env.paths.entries, JSON.stringify(entry) + '\n');

  const frontier = Merkle.createFrontier();
  for (const recorded of prior) frontier.push(Buffer.from(recorded.payload_digest, 'hex'));
  const leaf = frontier.append(Buffer.from(entry.payload_digest, 'hex'));
  const head = checkpoints(env).slice(-1)[0];
  const checkpoint = Ledger.signCheckpoint(Ledger.buildCheckpoint({
    ledger_id: env.ledgerId,
    tree_size: seq,
    root_hash: leaf.root.toString('hex'),
    created_at: record.recorded_at,
    prev_checkpoint_hash: head.checkpoint_hash,
    policy_hash: env.genesis.policy_hash,
  }), signer);
  fs.appendFileSync(env.paths.checkpoints, JSON.stringify(checkpoint) + '\n');
  return entry;
}

function writeRevocationLine(env, record) {
  fs.writeFileSync(env.paths.revocations, JSON.stringify(record) + '\n');
}

test('a revocation is sealed as a ledger entry and ends authority at revoked_at', (t) => {
  const env = makeEnv(t);
  appendAt(env, 'first', 1);

  const revoked = Ledger.revokeWriter(env.ledger, {
    signer: env.signer,
    keyring: env.keyring,
    key_id: env.adminKeyId,
    revoked_at: env.plus(20),
    reason: 'left the team',
    now: env.at(10),
  });

  assert.equal(revoked.revoked_at, env.plus(20));
  assert.equal(revoked.record.head_tree_size, 1, 'the record binds the head it was issued against');
  assert.equal(revoked.record.head_checkpoint_hash, checkpoints(env)[1].checkpoint_hash,
    'the record names the checkpoint it saw, not the one its own seal adds');
  assert.equal(revoked.record.signature.key_id, env.adminKeyId);

  // The commitment rides in the entry log, inside the tree and the chain.
  assert.equal(revoked.commitment.seq, 2);
  assert.equal(revoked.commitment.receipt_id, Ledger.REVOCATION_COMMITMENT_PREFIX + env.adminKeyId);
  assert.equal(revoked.commitment.payload_digest, Ledger.revocationCommitmentDigest(revoked.record));
  assert.equal(entries(env).length, 2);
  assert.equal(checkpoints(env).slice(-1)[0].tree_size, 2);

  // A new append by the revoked key is refused on position, not on its clock:
  // the record exists, so any entry past the bound head came later.
  const before = fs.readFileSync(env.paths.entries);
  assert.throws(() => appendAt(env, 'backdated', 5), (e) => {
    assert.equal(e.code, 'LEDGER_WRITER_REVOKED');
    assert.match(e.message, /after the head the revocation was issued against/);
    assert.match(e.message, /tree 1/);
    return true;
  });
  assert.deepEqual(fs.readFileSync(env.paths.entries), before, 'a refused append writes nothing');

  const verified = Ledger.verifyLocal(env.ledger, { keyring: env.keyring });
  assert.equal(verified.ok, true, verified.code + ': ' + verified.message);
  assert.equal(verified.authorization.ok, true);
});

test('entries recorded before the revocation stay valid', (t) => {
  const env = makeEnv(t);
  appendAt(env, 'first', 1);
  appendAt(env, 'second', 2);

  Ledger.revokeWriter(env.ledger, {
    signer: env.signer,
    keyring: env.keyring,
    key_id: env.adminKeyId,
    revoked_at: env.plus(20),
    now: env.at(10),
  });

  const verified = Ledger.verifyLocal(env.ledger, { keyring: env.keyring });
  assert.equal(verified.ok, true, verified.code + ': ' + verified.message);
});

test('verification refuses a hand-written entry that appears past the bound head', (t) => {
  const env = makeEnv(t);
  const base = appendAt(env, 'base', 1);

  Ledger.revokeWriter(env.ledger, {
    signer: env.signer,
    keyring: env.keyring,
    key_id: env.adminKeyId,
    revoked_at: env.plus(20),
    now: env.at(10),
  });

  // Hand-extend the log exactly as a writer with a backdated clock would: a
  // valid entry and checkpoint, both signed by the revoked key, claiming a time
  // well before the boundary. Position still refuses it.
  const digest = digestOf('late-entry');
  const body = Ledger.entryBody({
    ledger_id: env.ledgerId,
    seq: 3,
    payload_digest: digest,
    receipt_id: 'backdated',
    recorded_at: env.plus(5),
    writer_key_id: env.adminKeyId,
    prev_entry_hash: entries(env)[1].entry_hash,
  });
  const entry = Ledger.signEntry(Object.assign({}, body, { entry_hash: Ledger.entryHash(body) }), env.signer);
  fs.appendFileSync(env.paths.entries, JSON.stringify(entry) + '\n');

  const frontier = Merkle.createFrontier();
  for (const recorded of entries(env).slice(0, 2)) {
    frontier.push(Buffer.from(recorded.payload_digest, 'hex'));
  }
  const leaf = frontier.append(Buffer.from(digest, 'hex'));
  const head = checkpoints(env).slice(-1)[0];
  const checkpoint = Ledger.signCheckpoint(Ledger.buildCheckpoint({
    ledger_id: env.ledgerId,
    tree_size: 3,
    root_hash: leaf.root.toString('hex'),
    created_at: env.plus(5),
    prev_checkpoint_hash: head.checkpoint_hash,
    policy_hash: env.genesis.policy_hash,
  }), env.signer);
  fs.appendFileSync(env.paths.checkpoints, JSON.stringify(checkpoint) + '\n');

  assert.equal(Ledger.verifySignatureOf('entry', entry, env.signer.public_key), true,
    'the refusal is authority, not crypto');

  const verified = Ledger.verifyLocal(env.ledger, { keyring: env.keyring });
  assert.equal(verified.ok, false);
  assert.equal(verified.code, 'LEDGER_WRITER_REVOKED');
  assert.match(verified.message, /entry 3/);
  assert.match(verified.message, /timestamp cannot place it before the boundary/);
  assert.deepEqual(verified.checks.filter(c => !c.ok), [], 'every signature still verifies');
});

test('a hand-bound head can refuse an entry that already existed when the record was written', (t) => {
  const env = makeEnv(t);
  appendAt(env, 'before', 1);

  // The admin hand-writes the record against the head it saw, but the ledger
  // gains another writer's entry before the record is committed. `revoke-writer`
  // binds the current head and cannot produce this shape; a hand-written record
  // can, because the only head it must postdate is the one it names.
  const older = checkpoints(env).slice(-1)[0];
  appendAt(env, 'already-written', 2, env.signerOther, env.otherKeyring);

  const record = manualRevocation(env, {
    signer: env.signer,
    key_id: env.otherKeyId,
    revoked_at: env.plus(3),
    recorded_at: env.plus(4),
    head: older,
  });
  commitManually(env, record, env.signer);
  writeRevocationLine(env, record);

  // The record authenticates (its boundary postdates the head it names), but
  // the entry at seq 2 sits past that head, so position refuses it even though
  // it was written before the record existed. The guarantee is therefore about
  // the head a revocation binds, not about wall-clock history.
  const trusted = new Map();
  for (const dir of [env.keyring, env.otherKeyring]) {
    for (const key of Signing.listKeys({ dir })) trusted.set(key.key_id, key.public_key_pem);
  }
  const verified = Ledger.verifyLocal(env.ledger, { trustedKeys: trusted });
  assert.equal(verified.ok, false);
  assert.equal(verified.code, 'LEDGER_WRITER_REVOKED');
  assert.match(verified.message, /entry 2/);
  assert.deepEqual(verified.checks.filter(c => !c.ok), [], 'every signature still verifies');
});

test('a revoked writer cannot seal another writer\'s revocation', (t) => {
  const env = makeEnv(t);
  appendAt(env, 'before', 1);
  Ledger.revokeWriter(env.ledger, {
    signer: env.signer,
    keyring: env.keyring,
    key_id: env.otherKeyId,
    revoked_at: env.plus(20),
    now: env.at(10),
  });

  // The admin signs a revocation of itself against the current head; the
  // already-revoked `other` writer hand-writes the commitment at a position
  // past its own head, with a recorded_at before its own boundary. The digest
  // and the admin signature are valid, so only the signer's authority can
  // refuse it.
  const head = checkpoints(env).slice(-1)[0];
  const record = manualRevocation(env, {
    signer: env.signer,
    key_id: env.adminKeyId,
    revoked_at: env.plus(40),
    recorded_at: env.plus(15),
    head,
  });
  commitManually(env, record, env.signerOther);
  fs.appendFileSync(env.paths.revocations, JSON.stringify(record) + '\n');

  const trusted = new Map();
  for (const dir of [env.keyring, env.otherKeyring]) {
    for (const key of Signing.listKeys({ dir })) trusted.set(key.key_id, key.public_key_pem);
  }
  const verified = Ledger.verifyLocal(env.ledger, { trustedKeys: trusted });
  assert.equal(verified.ok, false);
  assert.equal(verified.code, 'LEDGER_WRITER_REVOKED');
  assert.match(verified.message, /entry 3/);
  assert.equal(verified.authorization.ok, false);
});

test('a non-listed key cannot seal a revocation commitment', (t) => {
  const env = makeEnv(t);
  appendAt(env, 'before', 1);
  Ledger.revokeWriter(env.ledger, {
    signer: env.signer,
    keyring: env.keyring,
    key_id: env.otherKeyId,
    revoked_at: env.plus(20),
    now: env.at(10),
  });

  const outsiderKeyring = path.join(env.root, 'outsider');
  Signing.ensureKeyring({ dir: outsiderKeyring });
  const outsider = Ledger.keyringSigner({ dir: outsiderKeyring });
  const head = checkpoints(env).slice(-1)[0];
  const record = manualRevocation(env, {
    signer: env.signer,
    key_id: env.adminKeyId,
    revoked_at: env.plus(40),
    recorded_at: env.plus(15),
    head,
  });
  commitManually(env, record, outsider);
  fs.appendFileSync(env.paths.revocations, JSON.stringify(record) + '\n');

  const trusted = new Map();
  for (const dir of [env.keyring, env.otherKeyring, outsiderKeyring]) {
    for (const key of Signing.listKeys({ dir })) trusted.set(key.key_id, key.public_key_pem);
  }
  const verified = Ledger.verifyLocal(env.ledger, { trustedKeys: trusted });
  assert.equal(verified.ok, false);
  assert.equal(verified.code, 'LEDGER_POLICY_MISMATCH');
  assert.match(verified.message, /checkpoint 3/);
});

test('a writer may seal its own revocation through a separate writer keyring', (t) => {
  const env = makeEnv(t);
  appendAt(env, 'before', 1);

  // The admin signs the record; the revoked writer seals only the revocation
  // that ends its own authority. That is the self case the exemption preserves.
  const out = Ledger.revokeWriter(env.ledger, {
    signer: env.signer,
    keyring: env.keyring,
    writerSigner: env.signerOther,
    writerKeyring: env.otherKeyring,
    key_id: env.otherKeyId,
    revoked_at: env.plus(20),
    now: env.at(10),
  });
  assert.equal(out.commitment.signature.key_id, env.otherKeyId);

  const trusted = new Map();
  for (const dir of [env.keyring, env.otherKeyring]) {
    for (const key of Signing.listKeys({ dir })) trusted.set(key.key_id, key.public_key_pem);
  }
  const verified = Ledger.verifyLocal(env.ledger, { trustedKeys: trusted });
  assert.equal(verified.ok, true, verified.code + ': ' + verified.message);
});

test('an admin who is also a writer seals as the admin that signed the record', (t) => {
  const env = makeEnv(t);
  appendAt(env, 'before', 1);

  // The admin is also a writer, so it self-seals its own revocation first.
  Ledger.revokeWriter(env.ledger, {
    signer: env.signer,
    keyring: env.keyring,
    key_id: env.adminKeyId,
    revoked_at: env.plus(20),
    now: env.at(10),
  });

  // Being revoked as a writer does not remove the admin role. The same key
  // signs and seals the next revocation as the admin that signed the record.
  const out = Ledger.revokeWriter(env.ledger, {
    signer: env.signer,
    keyring: env.keyring,
    key_id: env.otherKeyId,
    revoked_at: env.plus(40),
    now: env.at(30),
  });
  assert.equal(out.commitment.signature.key_id, env.adminKeyId);

  const verified = Ledger.verifyLocal(env.ledger, { keyring: env.keyring });
  assert.equal(verified.ok, true, verified.code + ': ' + verified.message);
});

test('a disjoint admin and writer keep the seal outside the exemption', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ledger-revocation-disjoint-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const adminKeyring = path.join(dir, 'admin');
  const targetKeyring = path.join(dir, 'target');
  const sealerKeyring = path.join(dir, 'sealer');
  const admin = Signing.ensureKeyring({ dir: adminKeyring });
  const target = Signing.ensureKeyring({ dir: targetKeyring });
  const sealer = Signing.ensureKeyring({ dir: sealerKeyring });
  const ledger = path.join(dir, 'audit.ledger');
  const T0 = Date.parse('2026-01-01T00:00:00.000Z');
  const at = seconds => () => new Date(T0 + seconds * 1000);
  const plus = seconds => new Date(T0 + seconds * 1000).toISOString();
  const adminSigner = Ledger.keyringSigner({ dir: adminKeyring });
  const targetSigner = Ledger.keyringSigner({ dir: targetKeyring });
  const sealerSigner = Ledger.keyringSigner({ dir: sealerKeyring });

  Ledger.initLedger(ledger, {
    signer: sealerSigner,
    policy: { writer_keys: [target.key_id, sealer.key_id], admin_keys: [admin.key_id] },
    now: at(0),
  });
  Ledger.append(ledger, {
    signer: sealerSigner, keyring: sealerKeyring, payload_digest: digestOf('first'), now: at(1),
  });

  // The admin signs the record and a writer that is neither the admin nor the
  // target seals it. That seal needs no exemption: the sealer is not the key
  // being revoked, so the position rule never applies to it.
  const out = Ledger.revokeWriter(ledger, {
    signer: adminSigner,
    keyring: adminKeyring,
    writerSigner: sealerSigner,
    writerKeyring: sealerKeyring,
    key_id: target.key_id,
    revoked_at: plus(20),
    now: at(10),
  });
  assert.equal(out.record.signature.key_id, admin.key_id);
  assert.equal(out.commitment.signature.key_id, sealer.key_id);

  const trusted = new Map();
  for (const keyring of [adminKeyring, targetKeyring, sealerKeyring]) {
    for (const key of Signing.listKeys({ dir: keyring })) trusted.set(key.key_id, key.public_key_pem);
  }
  const verified = Ledger.verifyLocal(ledger, { trustedKeys: trusted });
  assert.equal(verified.ok, true, verified.code + ': ' + verified.message);

  assert.throws(() => Ledger.append(ledger, {
    signer: targetSigner,
    keyring: targetKeyring,
    trustedKeys: trusted,
    payload_digest: digestOf('late target'),
    now: at(15),
  }), (e) => e.code === 'LEDGER_WRITER_REVOKED');
  assert.throws(() => Ledger.append(ledger, {
    signer: adminSigner,
    keyring: adminKeyring,
    trustedKeys: trusted,
    payload_digest: digestOf('admin receipt'),
    now: at(16),
  }), (e) => e.code === 'LEDGER_POLICY_MISMATCH');
});

test('an admin cannot seal a record another admin signed', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ledger-revocation-admin-signer-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const targetKeyring = path.join(dir, 'target');
  const adminAKeyring = path.join(dir, 'admin-a');
  const adminBKeyring = path.join(dir, 'admin-b');
  const target = Signing.ensureKeyring({ dir: targetKeyring });
  const adminA = Signing.ensureKeyring({ dir: adminAKeyring });
  const adminB = Signing.ensureKeyring({ dir: adminBKeyring });
  const ledger = path.join(dir, 'audit.ledger');
  const T0 = Date.parse('2026-01-01T00:00:00.000Z');
  const at = seconds => () => new Date(T0 + seconds * 1000);
  const plus = seconds => new Date(T0 + seconds * 1000).toISOString();
  const targetSigner = Ledger.keyringSigner({ dir: targetKeyring });
  const adminASigner = Ledger.keyringSigner({ dir: adminAKeyring });
  const adminBSigner = Ledger.keyringSigner({ dir: adminBKeyring });

  const init = Ledger.initLedger(ledger, {
    signer: targetSigner,
    policy: { writer_keys: [target.key_id], admin_keys: [adminA.key_id, adminB.key_id] },
    now: at(0),
  });
  Ledger.append(ledger, {
    signer: targetSigner, keyring: targetKeyring, payload_digest: digestOf('first'), now: at(1),
  });

  // Admin A signs the record; admin B, a listed admin but never its signer,
  // seals it. The admin exemption belongs to the record's signer, so B has no
  // writer authority to fall back on here.
  const env = {
    ledger,
    paths: Ledger.ledgerPaths(ledger),
    ledgerId: init.ledger_id,
    genesis: init.genesis,
    signer: targetSigner,
    at,
    plus,
  };
  const head = checkpoints(env).slice(-1)[0];
  const record = manualRevocation(env, {
    signer: adminASigner,
    key_id: target.key_id,
    revoked_at: plus(20),
    recorded_at: plus(10),
    head,
  });
  commitManually(env, record, adminBSigner);
  writeRevocationLine(env, record);

  const trusted = new Map();
  for (const keyring of [targetKeyring, adminAKeyring, adminBKeyring]) {
    for (const key of Signing.listKeys({ dir: keyring })) trusted.set(key.key_id, key.public_key_pem);
  }
  const verified = Ledger.verifyLocal(ledger, { trustedKeys: trusted });
  assert.equal(verified.ok, false);
  assert.equal(verified.code, 'LEDGER_POLICY_MISMATCH');
  assert.match(verified.message, /checkpoint 2/);
});

test('a forged revocation signature is refused, not ignored', (t) => {
  const env = makeEnv(t);
  appendAt(env, 'first', 1);
  Ledger.revokeWriter(env.ledger, {
    signer: env.signer,
    keyring: env.keyring,
    key_id: env.otherKeyId,
    revoked_at: env.plus(20),
    now: env.at(10),
  });

  const record = JSON.parse(fs.readFileSync(env.paths.revocations, 'utf8').trim());
  record.reason = 'edited after signing';
  writeRevocationLine(env, record);

  const verified = Ledger.verifyLocal(env.ledger, { keyring: env.keyring });
  assert.equal(verified.ok, false);
  assert.equal(verified.code, 'LEDGER_REVOCATION_UNAUTHORIZED');
  assert.match(verified.message, /signature does not match/);
});

test('a revocation signed by a non-admin key is refused', (t) => {
  const env = makeEnv(t);
  appendAt(env, 'first', 1);
  const head = checkpoints(env).slice(-1)[0];

  const record = manualRevocation(env, {
    signer: env.signerOther,
    key_id: env.adminKeyId,
    revoked_at: env.plus(20),
    recorded_at: env.plus(10),
    head,
  });
  commitManually(env, record);
  writeRevocationLine(env, record);

  const verified = Ledger.verifyLocal(env.ledger, { keyring: env.keyring });
  assert.equal(verified.ok, false);
  assert.equal(verified.code, 'LEDGER_REVOCATION_UNAUTHORIZED');
  assert.match(verified.message, /not an admin/);

  assert.throws(() => Ledger.revokeWriter(env.ledger, {
    signer: env.signerOther,
    keyring: env.otherKeyring,
    key_id: env.adminKeyId,
    revoked_at: env.plus(30),
    now: env.at(20),
  }), (e) => e.code === 'LEDGER_POLICY_MISMATCH');
});

test('a backdated revocation cannot invalidate written entries', (t) => {
  const env = makeEnv(t);
  const entry = appendAt(env, 'first', 5);
  const head = checkpoints(env).slice(-1)[0];
  const before = fs.readFileSync(env.paths.entries);

  assert.throws(() => Ledger.revokeWriter(env.ledger, {
    signer: env.signer,
    keyring: env.keyring,
    key_id: env.otherKeyId,
    revoked_at: env.plus(5),
    now: env.at(10),
  }), (e) => {
    assert.equal(e.code, 'LEDGER_REVOCATION_BACKDATED');
    return true;
  });
  assert.equal(fs.existsSync(env.paths.revocations), false, 'a refused revocation writes no file');
  assert.deepEqual(fs.readFileSync(env.paths.entries), before, 'and no commitment entry');

  // Even a correctly signed, correctly committed backdated record is refused
  // by the verifier: the boundary may not reach behind the head it names.
  const record = manualRevocation(env, {
    signer: env.signer,
    key_id: env.otherKeyId,
    revoked_at: entry.entry.recorded_at,
    recorded_at: env.plus(10),
    head,
  });
  commitManually(env, record);
  writeRevocationLine(env, record);

  const verified = Ledger.verifyLocal(env.ledger, { keyring: env.keyring });
  assert.equal(verified.ok, false);
  assert.equal(verified.code, 'LEDGER_REVOCATION_BACKDATED');
  assert.match(verified.message, /at or before records/);
});

test('a revocation whose boundary does not postdate its own sealing entry is refused', (t) => {
  const env = makeEnv(t);
  appendAt(env, 'first', 1);

  assert.throws(() => Ledger.revokeWriter(env.ledger, {
    signer: env.signer,
    keyring: env.keyring,
    key_id: env.otherKeyId,
    revoked_at: env.plus(10),
    now: env.at(10),
  }), (e) => {
    assert.equal(e.code, 'LEDGER_REVOCATION_BACKDATED');
    assert.match(e.message, /does not postdate recorded_at/);
    return true;
  });
  assert.equal(fs.existsSync(env.paths.revocations), false);
  assert.equal(entries(env).length, 1, 'the refused revocation leaves no commitment');
});

test('a deleted revocation file fails closed', (t) => {
  const env = makeEnv(t);
  appendAt(env, 'first', 1);
  Ledger.revokeWriter(env.ledger, {
    signer: env.signer,
    keyring: env.keyring,
    key_id: env.adminKeyId,
    revoked_at: env.plus(20),
    now: env.at(10),
  });

  fs.unlinkSync(env.paths.revocations);

  const verified = Ledger.verifyLocal(env.ledger, { keyring: env.keyring });
  assert.equal(verified.ok, false);
  assert.equal(verified.code, 'LEDGER_REVOCATION_MISSING');
  assert.match(verified.message, /commits to a revocation record/);

  // The write path reads the same evidence and refuses too, so the revoked key
  // cannot be restored by deleting the file first.
  assert.throws(() => appendAt(env, 'after-delete', 30, env.signerOther, env.otherKeyring), (e) => {
    assert.equal(e.code, 'LEDGER_REVOCATION_MISSING');
    return true;
  });
});

test('a truncated revocation file fails closed', (t) => {
  const env = makeEnv(t);
  appendAt(env, 'first', 1);
  Ledger.revokeWriter(env.ledger, {
    signer: env.signer,
    keyring: env.keyring,
    key_id: env.otherKeyId,
    revoked_at: env.plus(20),
    now: env.at(10),
  });
  Ledger.revokeWriter(env.ledger, {
    signer: env.signer,
    keyring: env.keyring,
    key_id: env.adminKeyId,
    revoked_at: env.plus(40),
    now: env.at(20),
  });

  const lines = fs.readFileSync(env.paths.revocations, 'utf8').split('\n').filter(Boolean);
  assert.equal(lines.length, 2);
  assert.equal(Ledger.verifyLocal(env.ledger, { keyring: env.keyring }).ok, true);

  // Roll the file back to an earlier, internally valid state.
  fs.writeFileSync(env.paths.revocations, lines[0] + '\n');
  const verified = Ledger.verifyLocal(env.ledger, { keyring: env.keyring });
  assert.equal(verified.ok, false);
  assert.equal(verified.code, 'LEDGER_REVOCATION_MISSING');
  assert.match(verified.message, /entry 3/);
});

test('a revocation file that is present but unauthenticated is not ignored', (t) => {
  const env = makeEnv(t);
  appendAt(env, 'first', 1);
  fs.writeFileSync(env.paths.revocations, 'this is not a revocation\n');

  const verified = Ledger.verifyLocal(env.ledger, { keyring: env.keyring });
  assert.equal(verified.ok, false);
  assert.equal(verified.code, 'LEDGER_REVOCATION_MALFORMED');

  // The write path reads the same records before extending them.
  assert.throws(() => appendAt(env, 'after', 2), (e) => e.code === 'LEDGER_REVOCATION_MALFORMED');
});

test('a duplicate revocation for one key is refused', (t) => {
  const env = makeEnv(t);
  appendAt(env, 'first', 1);
  Ledger.revokeWriter(env.ledger, {
    signer: env.signer,
    keyring: env.keyring,
    key_id: env.otherKeyId,
    revoked_at: env.plus(20),
    now: env.at(10),
  });

  assert.throws(() => Ledger.revokeWriter(env.ledger, {
    signer: env.signer,
    keyring: env.keyring,
    key_id: env.otherKeyId,
    revoked_at: env.plus(30),
    now: env.at(20),
  }), (e) => e.code === 'LEDGER_REVOCATION_DUPLICATE');

  const lines = fs.readFileSync(env.paths.revocations, 'utf8').split('\n').filter(Boolean);
  assert.equal(lines.length, 1);
});

test('revoking a key that is not a writer is refused', (t) => {
  const env = makeEnv(t);
  appendAt(env, 'first', 1);

  assert.throws(() => Ledger.revokeWriter(env.ledger, {
    signer: env.signer,
    keyring: env.keyring,
    key_id: 'ed25519:' + 'e'.repeat(64),
    now: env.at(10),
  }), (e) => e.code === 'LEDGER_REVOCATION_UNKNOWN_WRITER');
  assert.equal(fs.existsSync(env.paths.revocations), false);
});

test('an admin seals the revocation of the only writer without that key', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ledger-revocation-admin-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const adminKeyring = path.join(dir, 'admin');
  const writerKeyring = path.join(dir, 'writer');
  const admin = Signing.ensureKeyring({ dir: adminKeyring });
  const writer = Signing.ensureKeyring({ dir: writerKeyring });
  const ledger = path.join(dir, 'audit.ledger');
  const T0 = Date.parse('2026-01-01T00:00:00.000Z');
  const at = seconds => () => new Date(T0 + seconds * 1000);
  const plus = seconds => new Date(T0 + seconds * 1000).toISOString();
  const adminSigner = Ledger.keyringSigner({ dir: adminKeyring });
  const writerSigner = Ledger.keyringSigner({ dir: writerKeyring });

  Ledger.initLedger(ledger, {
    signer: writerSigner,
    policy: { writer_keys: [writer.key_id], admin_keys: [admin.key_id] },
    now: at(0),
  });
  Ledger.append(ledger, {
    signer: writerSigner, keyring: writerKeyring, payload_digest: digestOf('first'), now: at(1),
  });

  // No writer signer, and the admin is not a writer: the admin seals the
  // commitment itself. The revoked key never touches the ledger again.
  const out = Ledger.revokeWriter(ledger, {
    signer: adminSigner,
    keyring: adminKeyring,
    key_id: writer.key_id,
    revoked_at: plus(20),
    now: at(10),
  });
  assert.equal(out.record.signature.key_id, admin.key_id);
  assert.equal(out.commitment.signature.key_id, admin.key_id,
    'the admin seals without the revoked key');
  assert.equal(out.commitment.receipt_id, Ledger.REVOCATION_COMMITMENT_PREFIX + writer.key_id);

  const trusted = new Map();
  for (const key of Signing.listKeys({ dir: adminKeyring })) trusted.set(key.key_id, key.public_key_pem);
  for (const key of Signing.listKeys({ dir: writerKeyring })) trusted.set(key.key_id, key.public_key_pem);

  assert.throws(() => Ledger.append(ledger, {
    signer: writerSigner,
    keyring: writerKeyring,
    trustedKeys: trusted,
    payload_digest: digestOf('late'),
    now: at(15),
  }), (e) => e.code === 'LEDGER_WRITER_REVOKED');

  // The seal granted no ordinary append authority: the admin still cannot
  // append a receipt.
  assert.throws(() => Ledger.append(ledger, {
    signer: adminSigner,
    keyring: adminKeyring,
    trustedKeys: trusted,
    payload_digest: digestOf('admin receipt'),
    now: at(16),
  }), (e) => e.code === 'LEDGER_POLICY_MISMATCH');
  const verified = Ledger.verifyLocal(ledger, { trustedKeys: trusted });
  assert.equal(verified.ok, true, verified.code + ': ' + verified.message);

  // The exemption cannot be requested as a bare flag: the single-record scope
  // ignores caller-supplied commitment metadata, so this fabricated subject is
  // just an admin key asking to write without writer authority.
  const read = Store.readLedger(Ledger.ledgerPaths(ledger), fs);
  const fabricated = Policy.authorizeRecord(Ledger.ledgerPaths(ledger), read, fs,
    { key: admin.key_id, at: plus(11), commitment: true,
      commitment_key_id: writer.key_id, commitment_signer: admin.key_id,
      commitment_sealer: admin.key_id },
    { keyring: adminKeyring, requireStatus: true });
  assert.equal(fabricated.ok, false);
  assert.equal(fabricated.code, 'LEDGER_POLICY_MISMATCH');
});

test('fsck re-seals an admin-sealed commitment checkpoint without append authority', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ledger-reseal-admin-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const adminKeyring = path.join(dir, 'admin');
  const writerKeyring = path.join(dir, 'writer');
  const admin = Signing.ensureKeyring({ dir: adminKeyring });
  const writer = Signing.ensureKeyring({ dir: writerKeyring });
  const ledger = path.join(dir, 'audit.ledger');
  const T0 = Date.parse('2026-01-01T00:00:00.000Z');
  const at = seconds => () => new Date(T0 + seconds * 1000);
  const plus = seconds => new Date(T0 + seconds * 1000).toISOString();
  const adminSigner = Ledger.keyringSigner({ dir: adminKeyring });
  const writerSigner = Ledger.keyringSigner({ dir: writerKeyring });
  const paths = Ledger.ledgerPaths(ledger);

  Ledger.initLedger(ledger, {
    signer: writerSigner,
    policy: { writer_keys: [writer.key_id], admin_keys: [admin.key_id] },
    now: at(0),
  });
  Ledger.append(ledger, {
    signer: writerSigner, keyring: writerKeyring, payload_digest: digestOf('first'), now: at(1),
  });
  const revoked = Ledger.revokeWriter(ledger, {
    signer: adminSigner,
    keyring: adminKeyring,
    key_id: writer.key_id,
    revoked_at: plus(20),
    now: at(10),
  });
  assert.equal(revoked.commitment.signature.key_id, admin.key_id);

  // A lost checkpoint tail: the commitment entry and the revocation record are
  // durable, but the checkpoint that sealed the entry is not.
  const lines = fs.readFileSync(paths.checkpoints, 'utf8').split('\n').filter(Boolean);
  assert.deepEqual(lines.map(line => JSON.parse(line).tree_size), [0, 1, 2]);
  fs.writeFileSync(paths.checkpoints, lines.slice(0, -1).join('\n') + '\n');

  const refused = Ledger.fsck(ledger, {});
  assert.equal(refused.code, 'LEDGER_CHECKPOINT_MISSING');
  assert.deepEqual(refused.requirements, ['signer']);

  // The admin is not a writer. Before the repair path knew the narrow admin
  // seal, this was LEDGER_POLICY_MISMATCH and the ledger could not be repaired.
  const repaired = Ledger.fsck(ledger, { signer: adminSigner, keyring: adminKeyring });
  assert.equal(repaired.ok, true, repaired.code + ': ' + repaired.message);
  const reseal = repaired.actions.find(a => a.event === 'CHECKPOINT_RESEALED');
  assert.deepEqual(reseal.sizes, [2]);

  const trusted = new Map();
  for (const keyring of [adminKeyring, writerKeyring]) {
    for (const key of Signing.listKeys({ dir: keyring })) trusted.set(key.key_id, key.public_key_pem);
  }
  const verified = Ledger.verifyLocal(ledger, { trustedKeys: trusted });
  assert.equal(verified.ok, true, verified.code + ': ' + verified.message);

  // The repair act was signing a checkpoint, not an entry: the admin still has
  // no append authority.
  assert.throws(() => Ledger.append(ledger, {
    signer: adminSigner,
    keyring: adminKeyring,
    payload_digest: digestOf('admin receipt'),
    now: at(11),
  }), (e) => e.code === 'LEDGER_POLICY_MISMATCH');
});

test('a supplied revocation file restores a lost sidecar', (t) => {
  const env = makeEnv(t);
  appendAt(env, 'first', 1);
  Ledger.revokeWriter(env.ledger, {
    signer: env.signer,
    keyring: env.keyring,
    key_id: env.otherKeyId,
    revoked_at: env.plus(20),
    now: env.at(10),
  });

  const backup = path.join(env.root, 'backup.revocations.jsonl');
  fs.copyFileSync(env.paths.revocations, backup);
  const original = fs.readFileSync(backup, 'utf8');
  fs.unlinkSync(env.paths.revocations);

  const missing = Ledger.verifyLocal(env.ledger, { keyring: env.keyring });
  assert.equal(missing.ok, false);
  assert.equal(missing.code, 'LEDGER_REVOCATION_MISSING');

  // The supplied file is an alternate source, not a bypass: read-only, and
  // still held to the commitment digest. Verification does not write.
  const supplied = Ledger.verifyLocal(env.ledger, { keyring: env.keyring, revocations: backup });
  assert.equal(supplied.ok, true, supplied.code + ': ' + supplied.message);
  assert.equal(fs.existsSync(env.paths.revocations), false, 'verification writes nothing');

  const restored = Ledger.restoreRevocations(env.ledger, { file: backup, keyring: env.keyring });
  assert.equal(restored.restored, 1);
  assert.equal(fs.readFileSync(env.paths.revocations, 'utf8'), original);

  const verified = Ledger.verifyLocal(env.ledger, { keyring: env.keyring });
  assert.equal(verified.ok, true, verified.code + ': ' + verified.message);
});

test('a supplied file that is not the committed record cannot restore authority', (t) => {
  const env = makeEnv(t);
  appendAt(env, 'first', 1);
  Ledger.revokeWriter(env.ledger, {
    signer: env.signer,
    keyring: env.keyring,
    key_id: env.otherKeyId,
    revoked_at: env.plus(20),
    now: env.at(10),
  });

  const backup = path.join(env.root, 'tampered.revocations.jsonl');
  const originalText = fs.readFileSync(env.paths.revocations, 'utf8');
  const record = JSON.parse(originalText.trim());
  record.reason = 'edited before restore';
  fs.writeFileSync(backup, JSON.stringify(record) + '\n');
  fs.unlinkSync(env.paths.revocations);

  assert.throws(() => Ledger.restoreRevocations(env.ledger, { file: backup, keyring: env.keyring }), (e) => {
    assert.equal(e.code, 'LEDGER_REVOCATION_UNAUTHORIZED');
    return true;
  });
  assert.equal(fs.existsSync(env.paths.revocations), false, 'a refused restore writes nothing');

  // An extra, validly signed record that the ledger never committed to is not
  // accepted either: restoration reproduces the commitments, nothing more.
  const head = checkpoints(env).slice(-1)[0];
  const extra = manualRevocation(env, {
    signer: env.signer,
    key_id: env.adminKeyId,
    revoked_at: env.plus(40),
    recorded_at: env.plus(20),
    head,
  });
  fs.writeFileSync(backup, originalText + JSON.stringify(extra) + '\n');
  assert.throws(() => Ledger.restoreRevocations(env.ledger, { file: backup, keyring: env.keyring }), (e) => {
    assert.equal(e.code, 'LEDGER_REVOCATION_UNCOMMITTED');
    return true;
  });
  assert.equal(fs.existsSync(env.paths.revocations), false);
});

test('restore names an unusable backup instead of claiming the ledger lost its sidecar', (t) => {
  const env = makeEnv(t);
  appendAt(env, 'first', 1);
  Ledger.revokeWriter(env.ledger, {
    signer: env.signer,
    keyring: env.keyring,
    key_id: env.otherKeyId,
    revoked_at: env.plus(20),
    now: env.at(10),
  });
  const backup = path.join(env.root, 'backup.revocations.jsonl');
  fs.copyFileSync(env.paths.revocations, backup);
  fs.unlinkSync(env.paths.revocations);

  // The ledger really does commit a record with no sidecar: the one condition
  // allowed to use LEDGER_REVOCATION_MISSING.
  const genuine = Ledger.verifyLocal(env.ledger, { keyring: env.keyring });
  assert.equal(genuine.ok, false);
  assert.equal(genuine.code, 'LEDGER_REVOCATION_MISSING');

  // A path that does not exist is a caller input error.
  assert.throws(() => Ledger.restoreRevocations(env.ledger, {
    file: path.join(env.root, 'absent.jsonl'),
    keyring: env.keyring,
  }), (e) => e.code === 'LEDGER_IO');

  // An empty backup holds no record: malformed input, not a lost sidecar.
  const empty = path.join(env.root, 'empty.jsonl');
  fs.writeFileSync(empty, '');
  assert.throws(() => Ledger.restoreRevocations(env.ledger, {
    file: empty,
    keyring: env.keyring,
  }), (e) => e.code === 'LEDGER_REVOCATION_MALFORMED');

  // A backup that exists but cannot be read is I/O, with the errno intact.
  const denied = Object.assign({}, fs, {
    readFileSync: function (file, ...rest) {
      if (path.resolve(file) === backup) {
        const error = new Error('access denied');
        error.code = 'EACCES';
        throw error;
      }
      return fs.readFileSync(file, ...rest);
    },
  });
  assert.throws(() => Ledger.restoreRevocations(env.ledger, {
    file: backup,
    keyring: env.keyring,
    fs: denied,
  }), (e) => e.code === 'LEDGER_IO' && /EACCES/.test(e.message));

  assert.equal(fs.existsSync(env.paths.revocations), false, 'refused restores write nothing');
});

test('restore refuses to report a ledger it cannot verify as repaired', (t) => {
  const env = makeEnv(t);
  appendAt(env, 'first', 1);

  // A genuine revocation record, sealed by a key that is neither a writer nor
  // the admin that signed the record. Every byte is structurally valid and the
  // commitment digest matches; whole-ledger authority is what refuses it.
  const outsiderKeyring = path.join(env.root, 'outsider');
  Signing.ensureKeyring({ dir: outsiderKeyring });
  const outsider = Ledger.keyringSigner({ dir: outsiderKeyring });
  const head = checkpoints(env).slice(-1)[0];
  const record = manualRevocation(env, {
    signer: env.signer,
    key_id: env.otherKeyId,
    revoked_at: env.plus(20),
    recorded_at: env.plus(10),
    head,
  });
  commitManually(env, record, outsider);
  writeRevocationLine(env, record);

  const trusted = new Map();
  for (const keyring of [env.keyring, env.otherKeyring, outsiderKeyring]) {
    for (const key of Signing.listKeys({ dir: keyring })) trusted.set(key.key_id, key.public_key_pem);
  }
  const verified = Ledger.verifyLocal(env.ledger, { trustedKeys: trusted });
  assert.equal(verified.ok, false);
  assert.equal(verified.code, 'LEDGER_POLICY_MISMATCH');

  const backup = path.join(env.root, 'backup.revocations.jsonl');
  fs.copyFileSync(env.paths.revocations, backup);
  fs.unlinkSync(env.paths.revocations);

  // The store's own authentication accepts this file. Without the whole-ledger
  // pre-check, restore would write the sidecar and report success.
  assert.throws(() => Ledger.restoreRevocations(env.ledger, {
    file: backup,
    trustedKeys: trusted,
  }), (e) => e.code === 'LEDGER_POLICY_MISMATCH');
  assert.equal(fs.existsSync(env.paths.revocations), false, 'the refused restore writes nothing');
});

test('restore verifies under the ledger lock, so no writer can append inside the window', (t) => {
  const env = makeEnv(t);
  appendAt(env, 'first', 1);
  Ledger.revokeWriter(env.ledger, {
    signer: env.signer,
    keyring: env.keyring,
    key_id: env.otherKeyId,
    revoked_at: env.plus(20),
    now: env.at(10),
  });

  const backup = path.join(env.root, 'backup.revocations.jsonl');
  fs.copyFileSync(env.paths.revocations, backup);
  const original = fs.readFileSync(backup, 'utf8');
  fs.unlinkSync(env.paths.revocations);

  const verifyLocal = Verify.verifyLocal;
  const phases = [];
  let contender = null;
  Verify.verifyLocal = function (ledger, opts) {
    phases.push(phases.length ? 'post' : 'pre');
    assert.equal(fs.existsSync(env.paths.lock), true, 'the check runs while the ledger is locked');
    // A second process gets exactly one attempt while the pre-check is running.
    // With verification outside the lock this append succeeds, and the restore
    // then writes a sidecar for a head the contender already moved.
    if (!contender) contender = tryAppend(env, 'contender');
    return verifyLocal.call(this, ledger, opts);
  };

  let restored;
  try {
    restored = Ledger.restoreRevocations(env.ledger, { file: backup, keyring: env.keyring });
  } finally {
    Verify.verifyLocal = verifyLocal;
  }

  assert.equal(restored.restored, 1);
  assert.deepEqual(phases, ['pre', 'post']);
  assert.equal(contender.status, 7, contender.stderr);
  assert.match(contender.stderr, /LEDGER_LOCKED/);
  assert.equal(entries(env).length, 2, 'the contender wrote no entry');
  assert.equal(fs.readFileSync(env.paths.revocations, 'utf8'), original);
  assert.equal(fs.existsSync(env.paths.lock), false);

  // The same append is admitted once the restore has released the lock, so the
  // refusal above was exclusion, not a broken writer.
  const after = tryAppend(env, 'after');
  assert.equal(after.status, 0, after.stderr);
  assert.equal(entries(env).length, 3);
  const verified = Ledger.verifyLocal(env.ledger, { keyring: env.keyring });
  assert.equal(verified.ok, true, verified.code + ': ' + verified.message);
});

test('a failed post-write check restores the previous sidecar under the lock', (t) => {
  const env = makeEnv(t);
  appendAt(env, 'first', 1);
  Ledger.revokeWriter(env.ledger, {
    signer: env.signer,
    keyring: env.keyring,
    key_id: env.otherKeyId,
    revoked_at: env.plus(20),
    now: env.at(10),
  });

  const backup = path.join(env.root, 'backup.revocations.jsonl');
  fs.copyFileSync(env.paths.revocations, backup);

  // A sentinel makes the rollback observable: the post-check fails, so the
  // bytes that were there before the write must be the bytes after it.
  const sentinel = '{"sentinel":"previous sidecar"}\n';
  fs.writeFileSync(env.paths.revocations, sentinel);

  const phases = [];
  assert.throws(() => Store.restoreRevocations(env.ledger, {
    file: backup,
    keyring: env.keyring,
    verify(phase) {
      phases.push(phase);
      if (phase === 'post') throw Format.fail('LEDGER_POLICY_MISMATCH', 'injected post-check');
    },
  }), (e) => e.code === 'LEDGER_POLICY_MISMATCH');
  assert.deepEqual(phases, ['pre', 'post']);
  assert.equal(fs.readFileSync(env.paths.revocations, 'utf8'), sentinel);
  assert.equal(fs.existsSync(env.paths.lock), false, 'the lock is released after a rollback');

  // With no previous sidecar, the rollback removes the one it wrote.
  fs.unlinkSync(env.paths.revocations);
  assert.throws(() => Store.restoreRevocations(env.ledger, {
    file: backup,
    keyring: env.keyring,
    verify(phase) {
      if (phase === 'post') throw Format.fail('LEDGER_POLICY_MISMATCH', 'injected post-check');
    },
  }), (e) => e.code === 'LEDGER_POLICY_MISMATCH');
  assert.equal(fs.existsSync(env.paths.revocations), false);
  assert.equal(fs.existsSync(env.paths.lock), false);
});

test('a failed sidecar write leaves the commitment unpaired and reports the I/O error', (t) => {
  const env = makeEnv(t);
  appendAt(env, 'first', 1);
  Ledger.revokeWriter(env.ledger, {
    signer: env.signer,
    keyring: env.keyring,
    key_id: env.otherKeyId,
    revoked_at: env.plus(20),
    now: env.at(10),
  });
  const backup = path.join(env.root, 'backup.revocations.jsonl');
  fs.copyFileSync(env.paths.revocations, backup);
  fs.unlinkSync(env.paths.revocations);

  // The commitment entry is already sealed; only the sidecar write fails. The
  // repair must throw, not print a restored file.
  const full = Object.assign({}, fs, {
    renameSync: function (from, to) {
      if (path.resolve(to) === env.paths.revocations) {
        const error = new Error('no space left on device');
        error.code = 'ENOSPC';
        throw error;
      }
      return fs.renameSync(from, to);
    },
  });
  assert.throws(() => Ledger.restoreRevocations(env.ledger, {
    file: backup,
    keyring: env.keyring,
    fs: full,
  }), (e) => e.code === 'ENOSPC');

  assert.equal(fs.existsSync(env.paths.revocations), false, 'no half-written sidecar');
  assert.equal(Ledger.verifyLocal(env.ledger, { keyring: env.keyring }).code,
    'LEDGER_REVOCATION_MISSING');
  // The record is not lost: the supplied file still reads the ledger, and the
  // repair can be retried when the disk allows it.
  assert.equal(Ledger.verifyLocal(env.ledger, {
    keyring: env.keyring, revocations: backup,
  }).ok, true);
});

test('an ordinary append cannot name itself a revocation commitment', (t) => {
  const env = makeEnv(t);
  appendAt(env, 'first', 1);
  const before = fs.readFileSync(env.paths.entries);
  const reserved = Ledger.REVOCATION_COMMITMENT_PREFIX + env.adminKeyId;

  // A receipt claiming the reserved id is refused before any byte is written,
  // so it can never be read back as a commitment to a record that does not
  // exist. The ledger stays valid.
  assert.throws(() => Ledger.append(env.ledger, {
    signer: env.signer,
    keyring: env.keyring,
    payload_digest: digestOf('innocent receipt'),
    receipt_id: reserved,
    now: env.at(2),
  }), (e) => {
    assert.equal(e.code, 'LEDGER_RECEIPT_ID_RESERVED');
    return true;
  });
  assert.deepEqual(fs.readFileSync(env.paths.entries), before, 'a refused append writes nothing');

  const verified = Ledger.verifyLocal(env.ledger, { keyring: env.keyring });
  assert.equal(verified.ok, true, verified.code + ': ' + verified.message);

  // The guard is the prefix, not the field: an ordinary id still appends.
  const normal = Ledger.append(env.ledger, {
    signer: env.signer,
    keyring: env.keyring,
    payload_digest: digestOf('ordinary receipt'),
    receipt_id: 'ordinary-receipt',
    now: env.at(3),
  });
  assert.equal(normal.entry.receipt_id, 'ordinary-receipt');
  assert.equal(Ledger.verifyLocal(env.ledger, { keyring: env.keyring }).ok, true);
});

test('the CLI refuses a receipt that claims the reserved id', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ledger-reserved-id-cli-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const keyring = path.join(dir, 'keys');
  const ledger = path.join(dir, 'audit.ledger');
  const env = { VERIFYD_KEYRING: keyring };
  const run = args => spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    env: Object.assign({}, process.env, env),
  });

  assert.equal(run(['keys', 'init']).status, 0);
  assert.equal(run(['chain', 'init', '--ledger', ledger]).status, 0);

  const receiptFile = path.join(dir, 'receipt.json');
  fs.writeFileSync(receiptFile, JSON.stringify({
    receipt: { receipt_id: Ledger.REVOCATION_COMMITMENT_PREFIX + 'ed25519:' + 'a'.repeat(64) },
  }) + '\n');

  const refused = run(['chain', 'append', receiptFile, '--ledger', ledger]);
  assert.equal(refused.status, 1);
  assert.match(refused.stderr, /LEDGER_RECEIPT_ID_RESERVED/);
  assert.equal(fs.readFileSync(Ledger.ledgerPaths(ledger).entries, 'utf8').trim(), '');

  const verified = run(['chain', 'verify', '--ledger', ledger]);
  assert.equal(verified.status, 0, verified.stderr);
  assert.match(verified.stdout, /Ledger: {7}VALID/);
});

test('the CLI restores a lost revocation file and refuses a tampered one', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ledger-restore-cli-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const keyring = path.join(dir, 'keys');
  const ledger = path.join(dir, 'audit.ledger');
  const env = { VERIFYD_KEYRING: keyring };
  const run = args => spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    env: Object.assign({}, process.env, env),
  });

  assert.equal(run(['keys', 'init']).status, 0);
  assert.equal(run(['chain', 'init', '--ledger', ledger]).status, 0);
  const keyId = Signing.listKeys({ dir: keyring })[0].key_id;

  const first = path.join(dir, 'first.txt');
  fs.writeFileSync(first, 'A document recorded before the revocation.\n');
  assert.equal(run(['audit', first, '--ledger', ledger]).status, 0);
  assert.equal(run(['chain', 'revoke-writer', keyId, '--ledger', ledger]).status, 0);

  const backup = path.join(dir, 'revocations.backup.jsonl');
  fs.copyFileSync(Ledger.ledgerPaths(ledger).revocations, backup);
  fs.unlinkSync(Ledger.ledgerPaths(ledger).revocations);

  const missing = run(['chain', 'verify', '--ledger', ledger]);
  assert.equal(missing.status, 1);
  assert.match(missing.stdout, /REVOCATION_MISSING/);

  // The supplied file lets the ledger be read without writing anything.
  const supplied = run(['chain', 'verify', '--ledger', ledger, '--revocations', backup]);
  assert.equal(supplied.status, 0, supplied.stderr);
  assert.match(supplied.stdout, /Ledger: {7}VALID/);
  assert.equal(fs.existsSync(Ledger.ledgerPaths(ledger).revocations), false);

  const restored = run(['chain', 'restore-revocations', backup, '--ledger', ledger]);
  assert.equal(restored.status, 0, restored.stderr);
  assert.match(restored.stdout, /Restored: {5}1 record\(s\)/);
  assert.match(restored.stdout, /Ledger: {7}VALID/);
  assert.equal(fs.existsSync(Ledger.ledgerPaths(ledger).revocations), true);
  assert.equal(run(['chain', 'verify', '--ledger', ledger]).status, 0);

  // A tampered backup is refused and leaves the sidecar absent.
  const tampered = JSON.parse(fs.readFileSync(backup, 'utf8').trim());
  tampered.reason = 'edited before restore';
  fs.writeFileSync(backup, JSON.stringify(tampered) + '\n');
  fs.unlinkSync(Ledger.ledgerPaths(ledger).revocations);

  const refused = run(['chain', 'restore-revocations', backup, '--ledger', ledger]);
  assert.equal(refused.status, 1);
  assert.match(refused.stderr, /LEDGER_REVOCATION_UNAUTHORIZED/);
  assert.equal(fs.existsSync(Ledger.ledgerPaths(ledger).revocations), false);
});

test('the CLI revokes a writer, seals it, and refuses the next append', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ledger-revocation-cli-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const keyring = path.join(dir, 'keys');
  const ledger = path.join(dir, 'audit.ledger');
  const env = { VERIFYD_KEYRING: keyring };
  const run = args => spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    env: Object.assign({}, process.env, env),
  });

  assert.equal(run(['keys', 'init']).status, 0);
  assert.equal(run(['chain', 'init', '--ledger', ledger]).status, 0);
  const keyId = Signing.listKeys({ dir: keyring })[0].key_id;

  const first = path.join(dir, 'first.txt');
  fs.writeFileSync(first, 'A document recorded before the revocation.\n');
  assert.equal(run(['audit', first, '--ledger', ledger]).status, 0);

  const revoked = run(['chain', 'revoke-writer', keyId, '--ledger', ledger, '--reason', 'left the team']);
  assert.equal(revoked.status, 0, revoked.stderr);
  assert.match(revoked.stdout, /Revoked: {6}ed25519:/);
  assert.match(revoked.stdout, /Signature: {4}VALID/);
  assert.match(revoked.stdout, /Committed: {4}entry 2, tree 2/);

  const second = path.join(dir, 'second.txt');
  fs.writeFileSync(second, 'A document that must not be recorded.\n');
  const refused = run(['audit', second, '--ledger', ledger]);
  assert.equal(refused.status, 1);
  assert.match(refused.stdout, /Ledger: {7}NOT RECORDED \(LEDGER_WRITER_REVOKED\)/);

  const verified = run(['chain', 'verify', '--ledger', ledger]);
  assert.equal(verified.status, 0, verified.stderr);
  assert.match(verified.stdout, /Ledger: {7}VALID/);
});
