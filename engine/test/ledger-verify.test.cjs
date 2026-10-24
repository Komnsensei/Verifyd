// Receipt membership (6.2) and anchored chain verification (6.3-6.4, 13.5).
//
// Every assertion is made through the public facade. The ledger is built with
// the real store, so the membership block under test is the one append returns,
// not a hand-written proof.

'use strict';

const test = require('node:test');
const assert = require('node:assert');

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const Ledger = require('../ledger.cjs');
const Signing = require('../signing.cjs');

function env(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ledger-verify-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const keyring = path.join(dir, 'keys');
  Signing.ensureKeyring({ dir: keyring });
  const signer = Ledger.keyringSigner({ dir: keyring });
  const ledger = path.join(dir, 'audit.ledger');
  Ledger.initLedger(ledger, {
    signer,
    policy: { writer_keys: [signer.key_id], admin_keys: [signer.key_id] },
  });
  return { dir, keyring, signer, ledger };
}

function sealReceipt(keyring, label) {
  return Signing.seal({
    scheme: 'verifyd-receipt-v1',
    receipt: { receipt_id: label, decision: 'allow', this_hash: null },
    document: { file: 'doc.txt', sha256: 'a'.repeat(64) },
  }, { dir: keyring });
}

function appendReceipt(e, label) {
  const receipt = sealReceipt(e.keyring, label);
  const digest = crypto.createHash('sha256').update(Signing.signingPayload(receipt)).digest('hex');
  const appended = Ledger.append(e.ledger, {
    signer: e.signer,
    payload_digest: digest,
    receipt_id: label,
  });
  receipt.ledger = {
    scheme: 'verifyd-ledger-v1',
    ledger_id: appended.block.ledger_id,
    seq: appended.block.seq,
    checkpoint: appended.block.checkpoint,
    path: appended.block.path,
  };
  return receipt;
}

function checkpointAt(e, size) {
  const text = fs.readFileSync(Ledger.ledgerPaths(e.ledger).checkpoints, 'utf8');
  return text.split('\n').filter(Boolean).map(JSON.parse).find(c => c.tree_size === size) || null;
}

function writeAnchor(e, record, name) {
  const file = path.join(e.dir, name || 'anchor.json');
  fs.writeFileSync(file, JSON.stringify(record, null, 2) + '\n');
  return file;
}

test('a receipt with no ledger block is NOT RECORDED, not a failure', (t) => {
  const e = env(t);
  const receipt = sealReceipt(e.keyring, 'plain');
  const result = Ledger.verifyReceipt(receipt, { ledger: e.ledger, keyring: e.keyring });
  assert.equal(result.status, 'NOT RECORDED');
  assert.equal(result.reason, 'receipt has no ledger block');
});

test('an appended receipt proves membership without an anchor', (t) => {
  const e = env(t);
  for (let i = 0; i < 5; i++) appendReceipt(e, 'r' + i);
  const receipt = sealReceipt(e.keyring, 'target');
  const digest = crypto.createHash('sha256').update(Signing.signingPayload(receipt)).digest('hex');
  const appended = Ledger.append(e.ledger, { signer: e.signer, payload_digest: digest, receipt_id: 'target' });
  receipt.ledger = {
    scheme: 'verifyd-ledger-v1',
    ledger_id: appended.block.ledger_id,
    seq: appended.block.seq,
    checkpoint: appended.block.checkpoint,
    path: appended.block.path,
  };

  // Attaching the block must not disturb the receipt signature.
  assert.equal(Signing.open(receipt, { dir: e.keyring }).ok, true);

  const result = Ledger.verifyReceipt(receipt, { ledger: e.ledger, keyring: e.keyring });
  assert.equal(result.status, 'IN CHAIN', result.reason);
  assert.equal(result.anchored, false);
  assert.equal(result.checkpoint.tree_size, 6);
  assert.equal(result.checkpoint.root_hash, appended.block.checkpoint.root_hash);
});

test('a false membership claim is NOT IN CHAIN for every way it can be false', (t) => {
  const e = env(t);
  for (let i = 0; i < 3; i++) appendReceipt(e, 'r' + i);
  const good = appendReceipt(e, 'good');

  const tamper = (mutate) => {
    const copy = JSON.parse(JSON.stringify(good));
    mutate(copy.ledger);
    return Ledger.verifyReceipt(copy, { ledger: e.ledger, keyring: e.keyring });
  };

  assert.equal(tamper(b => { b.path[0] = 'b'.repeat(64); }).status, 'NOT IN CHAIN');
  assert.equal(tamper(b => { b.checkpoint.root_hash = 'c'.repeat(64); }).status, 'NOT IN CHAIN');
  assert.equal(tamper(b => { b.seq = 1; }).status, 'NOT IN CHAIN');
  assert.equal(tamper(b => { b.ledger_id = 'd'.repeat(64); }).status, 'UNKNOWN LEDGER');
  assert.equal(tamper(b => { b.scheme = 'verifyd-ledger-v2'; }).status, 'NOT IN CHAIN');

  const otherDigest = sealReceipt(e.keyring, 'never-appended');
  const notRecorded = Ledger.verifyReceipt(Object.assign({}, otherDigest, { ledger: good.ledger }), {
    ledger: e.ledger,
    keyring: e.keyring,
  });
  assert.equal(notRecorded.status, 'NOT IN CHAIN');
  assert.match(notRecorded.reason, /does not hold this receipt digest/);

  // A trusted ledger with an untrusted checkpoint key proves nothing.
  const wrong = fs.mkdtempSync(path.join(os.tmpdir(), 'ledger-verify-wrong-'));
  try {
    Signing.ensureKeyring({ dir: wrong });
    const untrusted = Ledger.verifyReceipt(good, { ledger: e.ledger, keyring: wrong });
    assert.equal(untrusted.status, 'NOT IN CHAIN');
    assert.match(untrusted.reason, /key outside the trusted set/);
  } finally {
    fs.rmSync(wrong, { recursive: true, force: true });
  }

  const missing = Ledger.verifyReceipt(good, { ledger: path.join(e.dir, 'nope.ledger'), keyring: e.keyring });
  assert.equal(missing.status, 'UNKNOWN LEDGER');
});

test('an anchor authenticates the checkpoint the proof lands in', (t) => {
  const e = env(t);
  const first = appendReceipt(e, 'first');
  const anchorFile = writeAnchor(e, checkpointAt(e, 1));
  const anchoredFirst = Ledger.verifyReceipt(first, { ledger: e.ledger, keyring: e.keyring, anchor: anchorFile });
  assert.equal(anchoredFirst.status, 'IN CHAIN', anchoredFirst.reason);
  assert.equal(anchoredFirst.anchored, true);

  const later = appendReceipt(e, 'later');
  const anchoredLater = Ledger.verifyReceipt(later, { ledger: e.ledger, keyring: e.keyring, anchor: anchorFile });
  assert.equal(anchoredLater.status, 'IN CHAIN', anchoredLater.reason);
  assert.equal(anchoredLater.anchored, true);

  // An anchor from another ledger is not this ledger's head.
  const other = env(t);
  appendReceipt(other, 'other');
  const foreign = writeAnchor(e, checkpointAt(other, 1), 'foreign.json');
  const result = Ledger.verifyReceipt(later, { ledger: e.ledger, keyring: e.keyring, anchor: foreign });
  assert.equal(result.status, 'INCONSISTENT');

  // An anchor newer than the receipt's checkpoint cannot be reached from it.
  const newer = writeAnchor(e, checkpointAt(e, 2), 'newer.json');
  const older = Ledger.verifyReceipt(first, { ledger: e.ledger, keyring: e.keyring, anchor: newer });
  assert.equal(older.status, 'INCONSISTENT');
});

test('chain verification is OK against an anchor and names fork and rollback', (t) => {
  const e = env(t);
  for (let i = 0; i < 4; i++) appendReceipt(e, 'r' + i);
  const anchorFile = writeAnchor(e, checkpointAt(e, 2));

  const ok = Ledger.verifyChain(e.ledger, { keyring: e.keyring, anchor: anchorFile });
  assert.equal(ok.ok, true, ok.code + ': ' + ok.message);
  assert.equal(ok.mode, 'anchored incremental');
  assert.equal(ok.anchor.tree_size, 2);
  assert.equal(ok.head.tree_size, 4);

  // A larger tree signed by the same key is a rollback when used as this
  // anchor: the observed head cannot reach it.
  const longer = path.join(e.dir, 'long.ledger');
  Ledger.initLedger(longer, {
    signer: e.signer,
    policy: { writer_keys: [e.signer.key_id], admin_keys: [e.signer.key_id] },
  });
  for (let i = 0; i < 6; i++) {
    Ledger.append(longer, {
      signer: e.signer,
      payload_digest: crypto.createHash('sha256').update('long-' + i).digest('hex'),
    });
  }
  const longerCheckpoint = fs.readFileSync(Ledger.ledgerPaths(longer).checkpoints, 'utf8')
    .split('\n').filter(Boolean).map(JSON.parse).find(c => c.tree_size === 6);
  const larger = writeAnchor(e, longerCheckpoint, 'larger.json');
  const rollback = Ledger.verifyChain(e.ledger, { keyring: e.keyring, anchor: larger });
  assert.equal(rollback.ok, false);
  assert.equal(rollback.code, 'LEDGER_ROLLBACK');

  // A retained head at this size with another root is a fork.
  const heads = path.join(e.dir, 'heads.jsonl');
  fs.writeFileSync(heads, JSON.stringify({
    ledger_id: Ledger.verifyChain(e.ledger, { keyring: e.keyring }).head ? JSON.parse(fs.readFileSync(Ledger.ledgerPaths(e.ledger).checkpoints, 'utf8').split('\n').filter(Boolean)[0]).checkpoint_hash : '',
    tree_size: 4,
    root_hash: 'e'.repeat(64),
    checkpoint_hash: 'f'.repeat(64),
  }) + '\n');
  const fork = Ledger.verifyChain(e.ledger, { keyring: e.keyring, heads });
  assert.equal(fork.ok, false);
  assert.equal(fork.code, 'LEDGER_FORK');

  // Two checkpoint hashes at one size are equivocation, not a plain fork.
  const size2 = checkpointAt(e, 2);
  const resignable = Object.assign({}, size2, { created_at: new Date(Date.now() + 1000).toISOString() });
  delete resignable.checkpoint_hash;
  delete resignable.signature;
  const resealed = Ledger.signCheckpoint(Ledger.buildCheckpoint({
    ledger_id: resignable.ledger_id,
    tree_size: resignable.tree_size,
    root_hash: resignable.root_hash,
    created_at: resignable.created_at,
    prev_checkpoint_hash: resignable.prev_checkpoint_hash,
    policy_hash: resignable.policy_hash,
  }), e.signer);
  const equivocation = writeAnchor(e, resealed, 'equivocation.json');
  const equivocal = Ledger.verifyChain(e.ledger, { keyring: e.keyring, anchor: equivocation });
  assert.equal(equivocal.ok, false);
  assert.equal(equivocal.code, 'LEDGER_FORK_EQUIVOCATION');
});

test('verification and membership writing nothing is observable', (t) => {
  const e = env(t);
  for (let i = 0; i < 3; i++) appendReceipt(e, 'r' + i);
  const receipt = appendReceipt(e, 'quiet');
  const anchorFile = writeAnchor(e, checkpointAt(e, 2));

  const snapshot = () => {
    const out = [];
    for (const name of fs.readdirSync(e.dir).sort()) {
      const file = path.join(e.dir, name);
      const stat = fs.statSync(file);
      if (stat.isFile()) out.push(name + ':' + stat.mtimeMs + ':' + stat.size + ':' + fs.readFileSync(file, 'utf8'));
    }
    return out;
  };

  const before = snapshot();
  Ledger.verifyReceipt(receipt, { ledger: e.ledger, keyring: e.keyring, anchor: anchorFile });
  Ledger.verifyChain(e.ledger, { keyring: e.keyring, anchor: anchorFile });
  assert.deepEqual(snapshot(), before);
});

test('a genesis checkpoint is not an anchor', (t) => {
  const e = env(t);
  const receipt = appendReceipt(e, 'genesis-anchor');
  const genesis = writeAnchor(e, checkpointAt(e, 0), 'genesis.json');

  const membership = Ledger.verifyReceipt(receipt, { ledger: e.ledger, keyring: e.keyring, anchor: genesis });
  assert.equal(membership.status, 'INCONSISTENT',
    'a size-0 checkpoint says nothing about any history, so it cannot anchor one');
  assert.equal(membership.anchored, false);

  const chain = Ledger.verifyChain(e.ledger, { keyring: e.keyring, anchor: genesis });
  assert.equal(chain.ok, false);
});

test('an anchor signed by an untrusted key proves nothing', (t) => {
  const e = env(t);
  const receipt = appendReceipt(e, 'foreign-anchor');
  const otherRing = path.join(e.dir, 'other-keys');
  const other = Signing.ensureKeyring({ dir: otherRing });
  const otherSigner = Ledger.keyringSigner({ dir: otherRing });

  const real = checkpointAt(e, 1);
  const forged = Ledger.signCheckpoint(Ledger.buildCheckpoint({
    ledger_id: real.ledger_id,
    tree_size: real.tree_size,
    root_hash: real.root_hash,
    created_at: real.created_at,
    prev_checkpoint_hash: real.prev_checkpoint_hash,
    policy_hash: real.policy_hash,
  }), otherSigner);
  const anchor = writeAnchor(e, forged, 'foreign.json');

  const membership = Ledger.verifyReceipt(receipt, { ledger: e.ledger, keyring: e.keyring, anchor });
  assert.equal(membership.status, 'INCONSISTENT');
  assert.match(membership.reason, /key outside the trusted set/);

  const chain = Ledger.verifyChain(e.ledger, { keyring: e.keyring, anchor });
  assert.equal(chain.ok, false);
  assert.equal(chain.code, 'LEDGER_UNTRUSTED_KEY');
  assert.notEqual(other.key_id, e.signer.key_id);
});

test('a replaced ledger is caught by heads retained for the original one', (t) => {
  const e = env(t);
  const first = appendReceipt(e, 'original-1');
  appendReceipt(e, 'original-2');

  const originalHead = checkpointAt(e, 2);
  const heads = path.join(e.dir, 'kept-heads.jsonl');
  fs.writeFileSync(heads, JSON.stringify({
    ledger_id: checkpointAt(e, 0).checkpoint_hash,
    tree_size: 2,
    root_hash: originalHead.root_hash,
    checkpoint_hash: originalHead.checkpoint_hash,
  }) + '\n');

  // A different, internally valid ledger with a new genesis replaces the file.
  const replaced = path.join(e.dir, 'replaced.ledger');
  Ledger.initLedger(replaced, {
    signer: e.signer,
    policy: { writer_keys: [e.signer.key_id], admin_keys: [e.signer.key_id] },
  });
  Ledger.append(replaced, {
    signer: e.signer,
    payload_digest: crypto.createHash('sha256').update('replacement').digest('hex'),
  });

  const result = Ledger.verifyChain(replaced, { keyring: e.keyring, heads });
  assert.equal(result.ok, false,
    'retained heads name a ledger the observed one is not; that is not a pass');
  assert.equal(result.code, 'LEDGER_UNKNOWN_LEDGER');
  assert.equal(Ledger.verifyChain(replaced, { keyring: e.keyring }).ok, true,
    'without the retained head, a replaced ledger is internally consistent');
  assert.ok(first.ledger);
});

test('a failed membership check writes nothing either', (t) => {
  const e = env(t);
  const receipt = appendReceipt(e, 'quiet-failure');
  const anchor = writeAnchor(e, checkpointAt(e, 0), 'genesis.json');

  const snapshot = () => fs.readdirSync(e.dir).sort().map(name => {
    const file = path.join(e.dir, name);
    if (!fs.statSync(file).isFile()) return name;
    return name + ':' + fs.statSync(file).mtimeMs + ':' + fs.readFileSync(file, 'utf8');
  });

  const before = snapshot();
  const forged = JSON.parse(JSON.stringify(receipt));
  forged.ledger.path[0] = 'f'.repeat(64);
  assert.equal(Ledger.verifyReceipt(forged, { ledger: e.ledger, keyring: e.keyring }).status, 'NOT IN CHAIN');
  assert.equal(Ledger.verifyChain(e.ledger, { keyring: e.keyring, anchor }).ok, false);
  assert.deepEqual(snapshot(), before);
});
