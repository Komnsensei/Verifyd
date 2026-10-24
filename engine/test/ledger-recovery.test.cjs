// Phase B acceptance: the section 5 recovery matrix.
//
// Each test builds a real ledger, then creates one post-crash or tampered disk
// state by hand, and asserts both the reported code and the bytes left behind.
// Only one case may repair itself: an unterminated final entry fragment whose
// complete prefix matches the state cache. Everything else must be reported and
// left alone.

'use strict';

const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const Ledger = require('../ledger.cjs');
const Signing = require('../signing.cjs');

function digestOf(label) {
  return crypto.createHash('sha256').update(label).digest('hex');
}

function readLines(file) {
  const text = fs.readFileSync(file, 'utf8');
  return text.length === 0 ? [] : text.replace(/\n$/, '').split('\n');
}

function makeLedger(t, count) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'verifyd-ledger-recovery-'));
  const keyring = path.join(root, 'keys');
  const created = Signing.ensureKeyring({ dir: keyring });
  const signer = Ledger.keyringSigner({ dir: keyring });
  const ledger = path.join(root, 'ledger.jsonl');
  const paths = Ledger.ledgerPaths(ledger);
  Ledger.initLedger(ledger, {
    signer,
    policy: { writer_keys: [created.key_id], admin_keys: [created.key_id], witness_policy: null },
  });
  for (let i = 1; i <= (count || 0); i++) {
    Ledger.append(ledger, { signer, payload_digest: digestOf('entry-' + i) });
  }
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, keyring, signer, ledger, paths };
}

function snapshot(env) {
  const read = file => (fs.existsSync(file) ? fs.readFileSync(file) : null);
  return {
    entries: read(env.paths.entries),
    checkpoints: read(env.paths.checkpoints),
    state: read(env.paths.state),
    repairs: read(env.paths.repairs),
    torn: read(env.paths.torn),
  };
}

function assertUnchanged(env, before) {
  assert.deepEqual(fs.readFileSync(env.paths.entries), before.entries, 'entry log must be byte-identical');
  assert.deepEqual(fs.readFileSync(env.paths.checkpoints), before.checkpoints, 'checkpoint log must be byte-identical');
  if (before.state === null) assert.equal(fs.existsSync(env.paths.state), false);
  else assert.deepEqual(fs.readFileSync(env.paths.state), before.state, 'state cache must be byte-identical');
  if (before.repairs === null) {
    assert.equal(fs.existsSync(env.paths.repairs), false, 'a refusal must not write a repair record');
  } else {
    assert.deepEqual(fs.readFileSync(env.paths.repairs), before.repairs, 'repair log must be byte-identical');
  }
  if (before.torn === null) {
    assert.equal(fs.existsSync(env.paths.torn), false, 'a refusal must not arm the truncation guard');
  } else {
    assert.deepEqual(fs.readFileSync(env.paths.torn), before.torn, 'the truncation guard must be byte-identical');
  }
}

function appendFragment(env, text) {
  fs.appendFileSync(env.paths.entries, text);
}

function rewriteEntryLine(env, index, mutate) {
  const lines = readLines(env.paths.entries);
  const record = JSON.parse(lines[index]);
  mutate(record);
  lines[index] = JSON.stringify(record);
  fs.writeFileSync(env.paths.entries, lines.join('\n') + '\n');
}

function writeState(env, mutate) {
  const state = JSON.parse(fs.readFileSync(env.paths.state, 'utf8'));
  mutate(state);
  fs.writeFileSync(env.paths.state, JSON.stringify(state) + '\n');
}

test('a torn final entry fragment whose prefix matches the state is truncated once, automatically', (t) => {
  const env = makeLedger(t, 2);
  const clean = fs.readFileSync(env.paths.entries);
  appendFragment(env, '{"scheme":"verifyd-ledger-v1","seq":3,"payload_digest":"ab');

  const result = Ledger.fsck(env.ledger, {});
  assert.equal(result.ok, true, result.code + ': ' + result.message);
  assert.equal(result.code, 'OK');
  assert.deepEqual(result.actions.map(a => a.event), ['TORN_TAIL_TRUNCATED']);
  assert.deepEqual(fs.readFileSync(env.paths.entries), clean, 'the complete prefix must survive byte-for-byte');

  const repairs = Ledger.readRepairEvents(fs, env.paths.repairs);
  assert.equal(repairs.length, 1);
  assert.equal(repairs[0].event, 'TORN_TAIL_TRUNCATED');
  assert.equal(repairs[0].entries_kept, 2);
  assert.equal(repairs[0].state_seq, 2);
  assert.ok(repairs[0].discarded_bytes > 0);
  assert.ok(/^[0-9a-f]+$/.test(repairs[0].discarded_hex));

  const verified = Ledger.verifyLocal(env.ledger, { keyring: env.keyring });
  assert.equal(verified.ok, true, verified.code);
  assert.equal(Ledger.append(env.ledger, { signer: env.signer, payload_digest: digestOf('after-repair') }).entry.seq, 3);
  assert.equal(fs.existsSync(env.paths.lock), false);
});

test('a second torn tail needs the explicit flag and is never truncated silently', (t) => {
  const env = makeLedger(t, 2);
  appendFragment(env, '{"partial":1');
  assert.equal(Ledger.fsck(env.ledger, {}).ok, true);
  Ledger.append(env.ledger, { signer: env.signer, payload_digest: digestOf('third') });

  appendFragment(env, '{"partial":2');
  const before = snapshot(env);
  const refused = Ledger.fsck(env.ledger, {});
  assert.equal(refused.ok, false);
  assert.equal(refused.code, 'LEDGER_TORN_TAIL_REQUIRES_FLAG');
  assert.deepEqual(refused.requirements, ['repair-tail']);
  assertUnchanged(env, before);

  const repaired = Ledger.fsck(env.ledger, { repairTail: true });
  assert.equal(repaired.ok, true, repaired.code + ': ' + repaired.message);
  assert.equal(repaired.actions.filter(a => a.event === 'TORN_TAIL_TRUNCATED').length, 1);

  const repairs = Ledger.readRepairEvents(fs, env.paths.repairs);
  assert.equal(repairs.filter(r => r.event === 'TORN_TAIL_TRUNCATED').length, 2, 'both truncations must be recorded');
  assert.equal(repairs[repairs.length - 1].discarded_bytes, Buffer.byteLength('{"partial":2'));
  assert.equal(Ledger.verifyLocal(env.ledger, { keyring: env.keyring }).ok, true);
});

test('a torn tail whose prefix disagrees with the state cache is not repaired', (t) => {
  const env = makeLedger(t, 2);
  writeState(env, state => { state.seq = 1; state.tree_size = 1; });
  appendFragment(env, '{"partial":3');

  const before = snapshot(env);
  const result = Ledger.fsck(env.ledger, {});
  assert.equal(result.ok, false);
  assert.equal(result.code, 'LEDGER_TORN_TAIL_REQUIRES_FLAG');
  assertUnchanged(env, before);
});

test('a torn checkpoint tail is reported, and resealed only with the flag and a signer', (t) => {
  const env = makeLedger(t, 2);
  const checkpointLines = readLines(env.paths.checkpoints);
  fs.writeFileSync(env.paths.checkpoints,
    checkpointLines.slice(0, -1).join('\n') + '\n' + '{"scheme":"verifyd-ledger-v1","checkpoint_');

  const refused = Ledger.fsck(env.ledger, {});
  assert.equal(refused.ok, false);
  assert.equal(refused.code, 'LEDGER_TORN_CHECKPOINT_TAIL');
  assert.deepEqual(refused.requirements, ['repair-tail']);

  const repaired = Ledger.fsck(env.ledger, { repairTail: true, signer: env.signer });
  assert.equal(repaired.ok, true, repaired.code + ': ' + repaired.message);
  // Re-sealing produces a new head, so the state cache is rebuilt after it; the
  // order matters because the cache must never lead the log.
  assert.deepEqual(repaired.actions.map(a => a.event),
    ['CHECKPOINT_TAIL_TRUNCATED', 'CHECKPOINT_RESEALED', 'STATE_REBUILT']);

  const checkpoints = readLines(env.paths.checkpoints).map(line => JSON.parse(line));
  assert.deepEqual(checkpoints.map(c => c.tree_size), [0, 1, 2]);
  assert.equal(checkpoints[2].prev_checkpoint_hash, checkpoints[1].checkpoint_hash);
  assert.equal(Ledger.verifyLocal(env.ledger, { keyring: env.keyring }).ok, true);
});

test('an entry log ahead of the checkpoint log is resealed only with a signing key', (t) => {
  const env = makeLedger(t, 2);
  const checkpointLines = readLines(env.paths.checkpoints);
  fs.writeFileSync(env.paths.checkpoints, checkpointLines.slice(0, -1).join('\n') + '\n');

  const before = snapshot(env);
  const refused = Ledger.fsck(env.ledger, {});
  assert.equal(refused.ok, false);
  assert.equal(refused.code, 'LEDGER_CHECKPOINT_MISSING');
  assert.deepEqual(refused.requirements, ['signer']);
  assertUnchanged(env, before);

  const repaired = Ledger.fsck(env.ledger, { signer: env.signer });
  assert.equal(repaired.ok, true, repaired.code + ': ' + repaired.message);
  const reseal = repaired.actions.find(a => a.event === 'CHECKPOINT_RESEALED');
  assert.deepEqual(reseal.sizes, [2]);
  const checkpoints = readLines(env.paths.checkpoints).map(line => JSON.parse(line));
  assert.deepEqual(checkpoints.map(c => c.tree_size), [0, 1, 2]);
  assert.equal(Ledger.verifyLocal(env.ledger, { keyring: env.keyring }).ok, true);
});

test('a lagging state cache is rebuilt without touching the logs', (t) => {
  const env = makeLedger(t, 3);
  writeState(env, state => {
    state.seq = 2;
    state.tree_size = 2;
    state.checkpoint_hash = readLines(env.paths.checkpoints)[2] && JSON.parse(readLines(env.paths.checkpoints)[2]).checkpoint_hash;
  });

  const entriesBefore = fs.readFileSync(env.paths.entries);
  const checkpointsBefore = fs.readFileSync(env.paths.checkpoints);

  const result = Ledger.fsck(env.ledger, {});
  assert.equal(result.ok, true, result.code + ': ' + result.message);
  assert.deepEqual(result.actions.map(a => a.event), ['STATE_REBUILT']);
  assert.deepEqual(fs.readFileSync(env.paths.entries), entriesBefore);
  assert.deepEqual(fs.readFileSync(env.paths.checkpoints), checkpointsBefore);

  const state = JSON.parse(fs.readFileSync(env.paths.state, 'utf8'));
  assert.equal(state.seq, 3);
  assert.equal(state.checkpoint_hash, JSON.parse(readLines(env.paths.checkpoints).pop()).checkpoint_hash);
  assert.equal(state.head_hash, JSON.parse(readLines(env.paths.entries).pop()).entry_hash);
});

test('a state cache ahead of the entry log is truncation and is never repaired', (t) => {
  const env = makeLedger(t, 3);
  writeState(env, state => { state.seq = 4; });
  const before = snapshot(env);

  const result = Ledger.fsck(env.ledger, {});
  assert.equal(result.ok, false);
  assert.equal(result.code, 'LEDGER_TRUNCATED');
  assertUnchanged(env, before);
});

test('an entry log shorter than the head checkpoint is truncation', (t) => {
  const env = makeLedger(t, 3);
  const lines = readLines(env.paths.entries);
  fs.writeFileSync(env.paths.entries, lines[0] + '\n');
  const before = snapshot(env);

  const result = Ledger.fsck(env.ledger, {});
  assert.equal(result.ok, false);
  assert.equal(result.code, 'LEDGER_TRUNCATED');
  assertUnchanged(env, before);

  const verified = Ledger.verifyLocal(env.ledger, { keyring: env.keyring });
  assert.equal(verified.ok, false);
  assert.equal(verified.code, 'LEDGER_TRUNCATED');
});

test('a complete line with a stale hash is corruption, not a repairable tail', (t) => {
  const env = makeLedger(t, 3);
  rewriteEntryLine(env, 1, entry => { entry.recorded_at = '2020-01-01T00:00:00.000Z'; });
  const before = snapshot(env);

  const result = Ledger.fsck(env.ledger, {});
  assert.equal(result.ok, false);
  assert.equal(result.code, 'LEDGER_CORRUPT');
  assertUnchanged(env, before);
});

test('a NUL inside a complete line is corruption', (t) => {
  const env = makeLedger(t, 2);
  const lines = readLines(env.paths.entries);
  lines[0] = lines[0].slice(0, 10) + '\u0000' + lines[0].slice(10);
  fs.writeFileSync(env.paths.entries, lines.join('\n') + '\n');
  const before = snapshot(env);

  const result = Ledger.fsck(env.ledger, {});
  assert.equal(result.ok, false);
  assert.equal(result.code, 'LEDGER_CORRUPT');
  assertUnchanged(env, before);
});

test('a re-signed reorder that no longer matches the signed roots is an entry mismatch', (t) => {
  const env = makeLedger(t, 2);
  const original = readLines(env.paths.entries).map(line => JSON.parse(line));
  const payloads = original.map(entry => entry.payload_digest).reverse();

  let previousHash = 'GENESIS';
  const rebuilt = payloads.map((payload, index) => {
    const body = Ledger.entryBody({
      ledger_id: original[index].ledger_id,
      seq: index + 1,
      payload_digest: payload,
      receipt_id: original[index].receipt_id,
      recorded_at: original[index].recorded_at,
      writer_key_id: original[index].writer_key_id,
      prev_entry_hash: previousHash,
    });
    const entry = Ledger.signEntry(Object.assign({}, body, { entry_hash: Ledger.entryHash(body) }), env.signer);
    previousHash = entry.entry_hash;
    return entry;
  });
  fs.writeFileSync(env.paths.entries, rebuilt.map(entry => JSON.stringify(entry)).join('\n') + '\n');

  // The entry chain itself is valid and the checkpoints are untouched, so the
  // only thing wrong is that the signed roots no longer describe this log.
  const before = snapshot(env);
  const result = Ledger.fsck(env.ledger, {});
  assert.equal(result.ok, false);
  assert.equal(result.code, 'LEDGER_ENTRY_MISMATCH');
  assertUnchanged(env, before);
});

test('a checkpoint that does not extend the retained head is a fork', (t) => {
  const env = makeLedger(t, 2);
  const checkpoints = readLines(env.paths.checkpoints).map(line => JSON.parse(line));
  const genesis = checkpoints[0];

  const forged = Ledger.signCheckpoint(Ledger.buildCheckpoint({
    ledger_id: genesis.checkpoint_hash,
    tree_size: 1,
    root_hash: '0'.repeat(64),
    created_at: new Date().toISOString(),
    prev_checkpoint_hash: genesis.checkpoint_hash,
    policy_hash: genesis.policy_hash,
  }), env.signer);
  fs.appendFileSync(env.paths.checkpoints, JSON.stringify(forged) + '\n');

  const before = snapshot(env);
  const result = Ledger.fsck(env.ledger, {});
  assert.equal(result.ok, false);
  assert.equal(result.code, 'LEDGER_FORK');
  assertUnchanged(env, before);
});

test('a dry-run fsck reports the repair it would make and writes nothing', (t) => {
  const env = makeLedger(t, 2);
  appendFragment(env, '{"partial":4');
  const before = snapshot(env);

  const result = Ledger.fsck(env.ledger, { dryRun: true });
  assert.equal(result.ok, false);
  assert.equal(result.code, 'LEDGER_REPAIR_PENDING');
  assert.equal(result.actions[0].dry_run, true);
  assertUnchanged(env, before);
  assert.equal(fs.existsSync(env.paths.lock), false, 'a dry run must not take the lock');
});

test('an entry that names a different writer than the one that signed it is corruption', (t) => {
  const env = makeLedger(t, 2);
  const lines = readLines(env.paths.entries).map(line => JSON.parse(line));
  // The last entry is used so no successor's prev_entry_hash can mask the defect:
  // the only broken thing must be the attribution itself.
  lines[1].writer_key_id = 'ed25519:' + '11'.repeat(32);
  lines[1].entry_hash = Ledger.entryHash(lines[1]);
  fs.writeFileSync(env.paths.entries, lines.map(line => JSON.stringify(line)).join('\n') + '\n');

  // Attribution is part of the signed body, so a writer cannot borrow another
  // writer's key id. This is the binding Phase D authorization depends on.
  const before = snapshot(env);
  const result = Ledger.fsck(env.ledger, {});
  assert.equal(result.ok, false);
  assert.equal(result.code, 'LEDGER_CORRUPT');
  assert.match(result.message, /claims writer/);
  assertUnchanged(env, before);

  const verified = Ledger.verifyLocal(env.ledger, { keyring: env.keyring });
  assert.equal(verified.ok, false);
  assert.equal(verified.code, 'LEDGER_CORRUPT');
  assert.match(verified.message, /claims writer/);
});

test('signing an entry body that names another writer is refused before signing', (t) => {
  const env = makeLedger(t, 0);
  const body = Ledger.entryBody({
    ledger_id: 'a'.repeat(64),
    seq: 1,
    payload_digest: digestOf('borrowed'),
    recorded_at: new Date().toISOString(),
    writer_key_id: 'ed25519:' + '11'.repeat(32),
    prev_entry_hash: 'GENESIS',
  });
  assert.throws(() => Ledger.signEntry(Object.assign({}, body, { entry_hash: Ledger.entryHash(body) }), env.signer),
    (e) => e.code === 'LEDGER_MALFORMED');
});

test('a damaged repair log cannot authorize a second automatic truncation', (t) => {
  const env = makeLedger(t, 2);
  const markerPath = env.ledger + '.torn-tail.json';

  appendFragment(env, '{"partial":1');
  assert.equal(Ledger.fsck(env.ledger, {}).ok, true);
  assert.equal(fs.existsSync(markerPath), true, 'the first repair must arm a durable guard marker');

  // The repair log is the audit trail, not the guard. Damage to it must not
  // reset the "already truncated once" fact.
  fs.writeFileSync(env.paths.repairs, '{"at":"2026-01-01T00:00:00.000Z","event":"TORN_TAIL');

  Ledger.append(env.ledger, { signer: env.signer, payload_digest: digestOf('after-damage') });
  appendFragment(env, '{"partial":2');

  const before = snapshot(env);
  const refused = Ledger.fsck(env.ledger, {});
  assert.equal(refused.ok, false);
  assert.equal(refused.code, 'LEDGER_TORN_TAIL_REQUIRES_FLAG');
  assertUnchanged(env, before);

  // The guard must hold even when the marker itself cannot be read.
  fs.writeFileSync(markerPath, 'not json');
  const stillRefused = Ledger.fsck(env.ledger, {});
  assert.equal(stillRefused.ok, false);
  assert.equal(stillRefused.code, 'LEDGER_TORN_TAIL_REQUIRES_FLAG');
});
