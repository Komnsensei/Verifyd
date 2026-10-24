// Phase D1 acceptance: an append proves its signer was an authorized writer
// under the policy genesis committed to, and verification reaches the same
// verdict from the signed records plus the committed policy body.
//
// Every negative case here builds a ledger whose signatures are individually
// valid, so a failure is authority, not crypto. The policy sidecar is
// transport: its hash must equal genesis's `policy_hash` or it is refused.

'use strict';

const test = require('node:test');
const assert = require('node:assert');

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const Ledger = require('../ledger.cjs');
const Format = require('../ledger-format.cjs');
const Merkle = require('../merkle.cjs');
const Signing = require('../signing.cjs');

function digestOf(label) {
  return crypto.createHash('sha256').update(label).digest('hex');
}

function makeEnv(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ledger-policy-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const keyring = path.join(root, 'keys');
  const created = Signing.ensureKeyring({ dir: keyring });
  const signer = Ledger.keyringSigner({ dir: keyring });
  const ledger = path.join(root, 'audit.ledger');
  const policy = { writer_keys: [created.key_id], admin_keys: [created.key_id], witness_policy: null };
  const init = Ledger.initLedger(ledger, { signer, policy });
  return {
    root,
    keyring,
    keyId: created.key_id,
    signer,
    ledger,
    policy,
    ledgerId: init.ledger_id,
    genesis: init.genesis,
    paths: Ledger.ledgerPaths(ledger),
  };
}

function readFile(file) {
  return fs.readFileSync(file);
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function checkpointLines(env) {
  return fs.readFileSync(env.paths.checkpoints, 'utf8').split('\n').filter(Boolean).map(JSON.parse);
}

// A signer with no keyring reference. The append path cannot read a status
// for it, and membership alone is not a status.
function detachedSigner(keyring, keyId) {
  const key = Signing.signingKey({ dir: keyring, keyId, allowRetired: true });
  return {
    key_id: key.key_id,
    public_key: key.public_key_pem,
    sign: payload => crypto.sign(null, payload, key.privateKey).toString('base64'),
  };
}

function patchKeyRecord(keyring, keyId, patch) {
  const record = Signing.listKeys({ dir: keyring }).find(k => k.key_id === keyId);
  assert.ok(record, 'key record must exist: ' + keyId);
  const doc = readJson(record.record_path);
  Object.assign(doc, patch);
  fs.writeFileSync(record.record_path, JSON.stringify(doc, null, 2) + '\n');
}

// A second identity that is trusted (its key is in the ring) but is not a
// writer under the committed policy. Rotation retires the first key, which D1
// still accepts for records it signed earlier, and installs the second.
function addUnlistedKey(env) {
  const rotated = Signing.rotateKey({ dir: env.keyring });
  return { dir: env.keyring, signer: Ledger.keyringSigner({ dir: env.keyring }), keyId: rotated.key_id };
}

test('genesis is committed with a policy body whose hash matches it', (t) => {
  const env = makeEnv(t);
  assert.equal(fs.existsSync(env.paths.policy), true, 'init writes the policy beside the ledger');
  const body = readJson(env.paths.policy);
  assert.equal(Format.policyHash(body), env.genesis.policy_hash);
  assert.deepEqual(body.writer_keys, [env.keyId]);
});

test('an unlisted signer is refused before any byte is written', (t) => {
  const env = makeEnv(t);
  const otherRing = path.join(env.root, 'other-keys');
  const created = Signing.ensureKeyring({ dir: otherRing });
  const other = { dir: otherRing, signer: Ledger.keyringSigner({ dir: otherRing }), keyId: created.key_id };
  Ledger.append(env.ledger, { signer: env.signer, payload_digest: digestOf('first') });

  const before = {
    entries: readFile(env.paths.entries),
    checkpoints: readFile(env.paths.checkpoints),
    state: readFile(env.paths.state),
    policy: readFile(env.paths.policy),
  };

  assert.throws(() => Ledger.append(env.ledger, {
    signer: other.signer,
    keyring: other.dir,
    payload_digest: digestOf('unlisted'),
  }), (e) => {
    assert.equal(e.code, 'LEDGER_POLICY_MISMATCH');
    assert.match(e.message, /not a writer/);
    return true;
  });

  assert.deepEqual(readFile(env.paths.entries), before.entries);
  assert.deepEqual(readFile(env.paths.checkpoints), before.checkpoints);
  assert.deepEqual(readFile(env.paths.state), before.state);
  assert.deepEqual(readFile(env.paths.policy), before.policy);
  assert.equal(fs.existsSync(env.paths.lock), false, 'a refusal must not leave the lock behind');
});

test('verification rejects an unauthorized writer from the signed record alone', (t) => {
  const env = makeEnv(t);
  const other = addUnlistedKey(env);
  Ledger.append(env.ledger, { signer: env.signer, payload_digest: digestOf('authorized') });

  // Hand-extend the log exactly as a writer with an unlisted key could: a
  // cryptographically valid entry and a checkpoint signed by an authorized key.
  const first = readJson(env.paths.entries);
  const digest = digestOf('unauthorized');
  const body = Format.entryBody({
    ledger_id: env.ledgerId,
    seq: 2,
    payload_digest: digest,
    receipt_id: 'forged',
    recorded_at: new Date().toISOString(),
    writer_key_id: other.keyId,
    prev_entry_hash: first.entry_hash,
  });
  const entry = Format.signEntry(Object.assign({}, body, { entry_hash: Format.entryHash(body) }), other.signer);
  fs.appendFileSync(env.paths.entries, JSON.stringify(entry) + '\n');

  const frontier = Merkle.createFrontier();
  frontier.push(Buffer.from(first.payload_digest, 'hex'));
  const leaf = frontier.append(Buffer.from(digest, 'hex'));
  const head = checkpointLines(env).slice(-1)[0];
  const checkpoint = Format.signCheckpoint(Format.buildCheckpoint({
    ledger_id: env.ledgerId,
    tree_size: 2,
    root_hash: leaf.root.toString('hex'),
    created_at: new Date().toISOString(),
    prev_checkpoint_hash: head.checkpoint_hash,
    policy_hash: env.genesis.policy_hash,
  }), env.signer);
  fs.appendFileSync(env.paths.checkpoints, JSON.stringify(checkpoint) + '\n');

  // The signature itself is valid: the refusal below is about authority.
  assert.equal(Format.verifySignatureOf('entry', entry, other.signer.public_key), true);

  const verified = Ledger.verifyLocal(env.ledger, { keyring: env.keyring });
  assert.equal(verified.ok, false);
  assert.equal(verified.code, 'LEDGER_POLICY_MISMATCH');
  assert.match(verified.message, /entry 2/);
  assert.match(verified.message, new RegExp(other.keyId));
  assert.equal(verified.authorization.ok, false);
  assert.equal(verified.authorization.source, 'file');
  assert.deepEqual(verified.checks.filter(c => !c.ok), [], 'signatures all verified');
});

test('a policy body that does not hash to the commitment is refused on both sides', (t) => {
  const env = makeEnv(t);
  const other = addUnlistedKey(env);
  Ledger.append(env.ledger, { signer: env.signer, payload_digest: digestOf('before-swap') });

  fs.writeFileSync(env.paths.policy, JSON.stringify({
    writer_keys: [other.keyId],
    admin_keys: [other.keyId],
    witness_policy: null,
  }) + '\n');

  assert.throws(() => Ledger.append(env.ledger, {
    signer: env.signer,
    keyring: env.keyring,
    payload_digest: digestOf('after-swap'),
  }), (e) => e.code === 'LEDGER_POLICY_MISMATCH' && /hashes to/.test(e.message));

  const verified = Ledger.verifyLocal(env.ledger, { keyring: env.keyring });
  assert.equal(verified.ok, false);
  assert.equal(verified.code, 'LEDGER_POLICY_MISMATCH');
  assert.match(verified.message, /genesis committed/);
  assert.match(verified.message, new RegExp(env.genesis.policy_hash));

  // The signed policy hash is unchanged: only the transport file moved.
  assert.equal(checkpointLines(env)[0].policy_hash, env.genesis.policy_hash);
});

test('a missing policy body is reported, never assumed', (t) => {
  const env = makeEnv(t);
  const receipt = Signing.seal({
    scheme: 'verifyd-receipt-v1',
    receipt: { receipt_id: 'recorded', decision: 'allow', this_hash: null },
    document: { file: 'doc.txt', sha256: 'a'.repeat(64) },
  }, { dir: env.keyring });
  const digest = crypto.createHash('sha256').update(Signing.signingPayload(receipt)).digest('hex');
  const appended = Ledger.append(env.ledger, { signer: env.signer, payload_digest: digest, receipt_id: 'recorded' });
  receipt.ledger = {
    scheme: 'verifyd-ledger-v1',
    ledger_id: appended.block.ledger_id,
    seq: appended.block.seq,
    checkpoint: appended.block.checkpoint,
    path: appended.block.path,
  };

  fs.rmSync(env.paths.policy);

  assert.throws(() => Ledger.append(env.ledger, {
    signer: env.signer,
    keyring: env.keyring,
    payload_digest: digestOf('no-policy'),
  }), (e) => e.code === 'LEDGER_POLICY_MISSING');

  const verified = Ledger.verifyLocal(env.ledger, { keyring: env.keyring });
  assert.equal(verified.ok, false);
  assert.equal(verified.code, 'LEDGER_POLICY_MISSING');
  assert.equal(verified.authorization.ok, false);

  const chain = Ledger.verifyChain(env.ledger, { keyring: env.keyring });
  assert.equal(chain.ok, false);
  assert.equal(chain.code, 'LEDGER_POLICY_MISSING');

  const membership = Ledger.verifyReceipt(receipt, { ledger: env.ledger, keyring: env.keyring });
  assert.equal(membership.status, 'NOT IN CHAIN');
  assert.match(membership.reason, /no policy file/);
});

test('a trusted but unauthorized checkpoint signer cannot prove membership', (t) => {
  const env = makeEnv(t);
  // Rotating retires the first key and installs a second, so both are trusted
  // by the same keyring while only the first is a writer under genesis.
  const other = addUnlistedKey(env);

  const sealed = Signing.seal({
    scheme: 'verifyd-receipt-v1',
    receipt: { receipt_id: 'membership', decision: 'allow', this_hash: null },
    document: { file: 'doc.txt', sha256: 'a'.repeat(64) },
  }, { dir: env.keyring });
  const digest = crypto.createHash('sha256').update(Signing.signingPayload(sealed)).digest('hex');
  const appended = Ledger.append(env.ledger, { signer: env.signer, payload_digest: digest });

  // Replace the size-1 checkpoint with the same body signed by the unlisted key.
  const genesis = checkpointLines(env)[0];
  const leaf = Merkle.createFrontier().append(Buffer.from(digest, 'hex'));
  assert.equal(leaf.root.toString('hex'), appended.block.checkpoint.root_hash);
  const checkpoint = Format.signCheckpoint(Format.buildCheckpoint({
    ledger_id: env.ledgerId,
    tree_size: 1,
    root_hash: leaf.root.toString('hex'),
    created_at: new Date().toISOString(),
    prev_checkpoint_hash: genesis.checkpoint_hash,
    policy_hash: env.genesis.policy_hash,
  }), other.signer);
  fs.writeFileSync(env.paths.checkpoints, JSON.stringify(genesis) + '\n' + JSON.stringify(checkpoint) + '\n');

  sealed.ledger = {
    scheme: 'verifyd-ledger-v1',
    ledger_id: appended.block.ledger_id,
    seq: appended.block.seq,
    checkpoint: appended.block.checkpoint,
    path: appended.block.path,
  };

  const membership = Ledger.verifyReceipt(sealed, { ledger: env.ledger, keyring: env.keyring });
  assert.equal(membership.status, 'NOT IN CHAIN');
  assert.match(membership.reason, /not a writer/);
  assert.equal(membership.anchored, false);
});

test('append refuses a signer whose key status cannot be established', (t) => {
  const env = makeEnv(t);
  const before = readFile(env.paths.entries);

  assert.throws(() => Ledger.append(env.ledger, {
    signer: detachedSigner(env.keyring, env.keyId),
    payload_digest: digestOf('detached'),
  }), (e) => {
    assert.equal(e.code, 'LEDGER_KEY_NOT_ACTIVE');
    assert.match(e.message, /status/);
    return true;
  });
  assert.deepEqual(readFile(env.paths.entries), before, 'a refusal writes nothing');

  // A keyring-backed signer describes its own key, so the { signer } shape
  // used throughout Phase B still appends without an explicit keyring option.
  const appended = Ledger.append(env.ledger, { signer: env.signer, payload_digest: digestOf('factory') });
  assert.equal(appended.entry.seq, 1);
});

test('a revoked writer cannot append when its status is not supplied', (t) => {
  const env = makeEnv(t);
  patchKeyRecord(env.keyring, env.keyId, { status: 'revoked' });

  // With no keyring reference the status is unknown, not "fine".
  assert.throws(() => Ledger.append(env.ledger, {
    signer: detachedSigner(env.keyring, env.keyId),
    payload_digest: digestOf('revoked-detached'),
  }), (e) => e.code === 'LEDGER_KEY_NOT_ACTIVE');

  // With the keyring, it is refused for the status that is actually known.
  assert.throws(() => Ledger.append(env.ledger, {
    signer: env.signer,
    keyring: env.keyring,
    payload_digest: digestOf('revoked-known'),
  }), (e) => e.code === 'LEDGER_KEY_NOT_ACTIVE');
});

test('fsck refuses to reseal with a signer whose status cannot be established', (t) => {
  const env = makeEnv(t);
  Ledger.append(env.ledger, { signer: env.signer, payload_digest: digestOf('ahead') });

  // The entry is durable, the checkpoint is missing: the one condition fsck
  // repairs by re-signing.
  const lines = fs.readFileSync(env.paths.checkpoints, 'utf8').split('\n').filter(Boolean);
  fs.writeFileSync(env.paths.checkpoints, lines[0] + '\n');
  const before = {
    entries: readFile(env.paths.entries),
    checkpoints: readFile(env.paths.checkpoints),
    state: readFile(env.paths.state),
  };

  const refused = Ledger.fsck(env.ledger, { signer: detachedSigner(env.keyring, env.keyId) });
  assert.equal(refused.ok, false);
  assert.equal(refused.code, 'LEDGER_KEY_NOT_ACTIVE');
  assert.match(refused.message, /status/);
  assert.deepEqual(readFile(env.paths.entries), before.entries, 'a refused reseal must not touch entries');
  assert.deepEqual(readFile(env.paths.checkpoints), before.checkpoints, 'a refused reseal must not add a checkpoint');
  assert.deepEqual(readFile(env.paths.state), before.state, 'a refused reseal must not rewrite the state cache');

  // The keyring-backed signer still repairs the missing checkpoint.
  const repaired = Ledger.fsck(env.ledger, { signer: env.signer });
  assert.equal(repaired.ok, true, repaired.code + ': ' + repaired.message);
  const reseal = repaired.actions.find(a => a.event === 'CHECKPOINT_RESEALED');
  assert.deepEqual(reseal.sizes, [1]);
});

test('key status is judged at the record\'s own timestamp', (t) => {
  const env = makeEnv(t);
  Ledger.append(env.ledger, { signer: env.signer, payload_digest: digestOf('dated') });

  // A retired key is not a compromised key: past records stay valid.
  Signing.rotateKey({ dir: env.keyring });
  const retired = Ledger.verifyLocal(env.ledger, { keyring: env.keyring });
  assert.equal(retired.ok, true, retired.code + ': ' + retired.message);
  assert.equal(retired.authorization.ok, true);

  // A dated revocation that postdates the records changes nothing.
  patchKeyRecord(env.keyring, env.keyId, {
    status: 'revoked',
    revoked_at: new Date(Date.now() + 3600 * 1000).toISOString(),
  });
  const datedAfter = Ledger.verifyLocal(env.ledger, { keyring: env.keyring });
  assert.equal(datedAfter.ok, true, datedAfter.code + ': ' + datedAfter.message);

  // A revocation before the records, or an expiry before them, refuses them.
  patchKeyRecord(env.keyring, env.keyId, { revoked_at: '2000-01-01T00:00:00.000Z' });
  const revoked = Ledger.verifyLocal(env.ledger, { keyring: env.keyring });
  assert.equal(revoked.ok, false);
  assert.equal(revoked.code, 'LEDGER_KEY_NOT_ACTIVE');

  patchKeyRecord(env.keyring, env.keyId, {
    status: 'active',
    revoked_at: null,
    expires_at: '2000-01-01T00:00:00.000Z',
  });
  const expired = Ledger.verifyLocal(env.ledger, { keyring: env.keyring });
  assert.equal(expired.ok, false);
  assert.equal(expired.code, 'LEDGER_KEY_NOT_ACTIVE');
  assert.match(expired.message, /expired/);
});

test('a supplied policy is hash-checked and the sidecar is left untouched', (t) => {
  const env = makeEnv(t);
  Ledger.append(env.ledger, { signer: env.signer, payload_digest: digestOf('supplied') });
  const sidecar = readFile(env.paths.policy);

  const ok = Ledger.verifyLocal(env.ledger, { keyring: env.keyring, policy: env.policy });
  assert.equal(ok.ok, true, ok.code + ': ' + ok.message);
  assert.equal(ok.authorization.source, 'supplied');

  const wrong = { writer_keys: [env.keyId], admin_keys: [], witness_policy: null };
  const refused = Ledger.verifyLocal(env.ledger, { keyring: env.keyring, policy: wrong });
  assert.equal(refused.ok, false);
  assert.equal(refused.code, 'LEDGER_POLICY_MISMATCH');

  assert.deepEqual(readFile(env.paths.policy), sidecar, 'verification must not rewrite the policy');
});
