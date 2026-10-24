// Phase B acceptance: one writer wins, the log is durable in a defined order,
// and a failed append leaves nothing behind.
//
// These tests use the real filesystem and real Ed25519 keys. The only seams are
// an explicit filesystem facade (so a test can assert the fsync order and inject
// faults) and child processes (so concurrency is real, not simulated in one
// event loop).

'use strict';

const assert = require('node:assert');
const { spawn, spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const Ledger = require('../ledger.cjs');
const Merkle = require('../merkle.cjs');
const Signing = require('../signing.cjs');

const LEDGER_MODULE = path.resolve(__dirname, '..', 'ledger.cjs');

function digestOf(label) {
  return crypto.createHash('sha256').update(label).digest('hex');
}

function makeEnv(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'verifyd-ledger-writer-'));
  const keyring = path.join(root, 'keys');
  const created = Signing.ensureKeyring({ dir: keyring });
  const signer = Ledger.keyringSigner({ dir: keyring });
  const ledger = path.join(root, 'ledger.jsonl');
  const policy = {
    writer_keys: [created.key_id],
    admin_keys: [created.key_id],
    witness_policy: null,
  };
  Ledger.initLedger(ledger, { signer, policy });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, keyring, keyId: created.key_id, signer, ledger, policy, paths: Ledger.ledgerPaths(ledger) };
}

function readLines(file) {
  const text = fs.readFileSync(file, 'utf8');
  return text.length === 0 ? [] : text.replace(/\n$/, '').split('\n');
}

// Records every filesystem operation in order. Directory opens are faked so the
// intended directory-fsync step is observable on Windows too; production code
// still treats an unsupported directory fsync as a no-op.
function recordFs() {
  const ops = [];
  const names = new Map();
  const DIR = -1;
  const io = {
    readFileSync(file, encoding) { return fs.readFileSync(file, encoding); },
    statSync(file) { return fs.statSync(file); },
    openSync(file, flags) {
      if (flags === 'r' && fs.statSync(file).isDirectory()) {
        ops.push({ op: 'open', file, flags, fd: DIR });
        return DIR;
      }
      const fd = fs.openSync(file, flags);
      names.set(fd, file);
      ops.push({ op: 'open', file, flags, fd });
      return fd;
    },
    writeSync(fd, buf, offset, length) {
      const n = fs.writeSync(fd, buf, offset, length);
      ops.push({ op: 'write', file: names.get(fd), bytes: n });
      return n;
    },
    fsyncSync(fd) {
      ops.push({ op: 'fsync', file: fd === DIR ? '(dir)' : names.get(fd) });
      if (fd !== DIR) fs.fsyncSync(fd);
    },
    closeSync(fd) {
      ops.push({ op: 'close', file: fd === DIR ? '(dir)' : names.get(fd) });
      if (fd !== DIR) fs.closeSync(fd);
    },
    writeFileSync(file, data) {
      ops.push({ op: 'writeFile', file });
      return fs.writeFileSync(file, data);
    },
    renameSync(from, to) {
      ops.push({ op: 'rename', from, to });
      return fs.renameSync(from, to);
    },
    truncateSync(file, size) {
      ops.push({ op: 'truncate', file, size });
      return fs.truncateSync(file, size);
    },
    unlinkSync(file) {
      ops.push({ op: 'unlink', file });
      return fs.unlinkSync(file);
    },
    linkSync(from, to) {
      ops.push({ op: 'link', from, to });
      return fs.linkSync(from, to);
    },
  };
  return { io, ops };
}

function faultFs(target, mode) {
  const names = new Map();
  return {
    readFileSync: fs.readFileSync,
    statSync: fs.statSync,
    openSync(file, flags) {
      const fd = fs.openSync(file, flags);
      names.set(fd, file);
      return fd;
    },
    writeSync(fd, buf, offset, length) {
      if (names.get(fd) === target) {
        if (mode === 'zero') return 0;
        if (mode === 'enospc') {
          const error = new Error('no space left on device');
          error.code = 'ENOSPC';
          throw error;
        }
      }
      return fs.writeSync(fd, buf, offset, length);
    },
    fsyncSync(fd) {
      if (mode === 'fsync' && names.get(fd) === target) {
        const error = new Error('input/output error');
        error.code = 'EIO';
        throw error;
      }
      return fs.fsyncSync(fd);
    },
    closeSync: fs.closeSync,
    writeFileSync: fs.writeFileSync,
    renameSync: fs.renameSync,
    truncateSync: fs.truncateSync,
    unlinkSync: fs.unlinkSync,
    linkSync: fs.linkSync,
  };
}

function runAppender(env) {
  const script = [
    "const L = require(process.env.LEDGER_MODULE);",
    "const signer = L.keyringSigner({ dir: process.env.LEDGER_KEYRING });",
    "function sleep(ms) { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); }",
    "const deadline = Date.now() + 20000;",
    "for (;;) {",
    "  try {",
    "    L.append(process.env.LEDGER_PATH, { signer, payload_digest: process.env.LEDGER_DIGEST });",
    "    process.exit(0);",
    "  } catch (e) {",
    "    if (e.code === 'LEDGER_LOCKED' && Date.now() < deadline) { sleep(5 + Math.floor(Math.random() * 25)); continue; }",
    "    console.error(e.code + ': ' + e.message);",
    "    process.exit(1);",
    "  }",
    "}",
  ].join('\n');

  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['-e', script], {
      env: Object.assign({}, process.env, env),
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stderr = '';
    child.stderr.on('data', chunk => { stderr += chunk.toString(); });
    child.on('close', code => resolve({ code, stderr }));
  });
}

test('init writes a genesis checkpoint with the empty root and an empty log', (t) => {
  const env = makeEnv(t);
  const genesis = JSON.parse(readLines(env.paths.checkpoints)[0]);

  assert.equal(genesis.tree_size, 0);
  assert.equal(genesis.ledger_id, 'GENESIS');
  assert.equal(genesis.root_hash, Ledger.emptyRoot().toString('hex'));
  assert.equal(genesis.checkpoint_hash, Ledger.checkpointHash(genesis));
  assert.equal(genesis.signature.algorithm, 'ed25519');
  assert.equal(genesis.signature.key_id, env.keyId);
  assert.equal(Ledger.verifySignatureOf('checkpoint', genesis, genesis.signature.public_key), true);

  assert.equal(fs.statSync(env.paths.entries).size, 0);
  const state = JSON.parse(fs.readFileSync(env.paths.state, 'utf8'));
  assert.equal(state.seq, 0);
  assert.equal(state.head_hash, 'GENESIS');
  assert.equal(state.checkpoint_hash, genesis.checkpoint_hash);
  assert.equal(state.ledger_id, genesis.checkpoint_hash);
  assert.equal(fs.existsSync(env.paths.lock), false);

  assert.throws(() => Ledger.initLedger(env.ledger, {
    signer: env.signer,
    policy: env.policy,
  }), (e) => e.code === 'LEDGER_EXISTS');
});

test('append chains entries and checkpoints and produces a provable leaf', (t) => {
  const env = makeEnv(t);
  const digests = [];
  let previousEntryHash = 'GENESIS';

  for (let i = 1; i <= 3; i++) {
    const digest = digestOf('entry-' + i);
    digests.push(digest);
    const out = Ledger.append(env.ledger, { signer: env.signer, payload_digest: digest, receipt_id: 'r-' + i });
    assert.equal(out.entry.seq, i);
    assert.equal(out.entry.prev_entry_hash, previousEntryHash);
    previousEntryHash = out.entry.entry_hash;
    assert.equal(out.checkpoint.tree_size, i);
    assert.equal(Ledger.verifySignatureOf('entry', out.entry, out.entry.signature.public_key), true);
    assert.equal(Ledger.verifySignatureOf('checkpoint', out.checkpoint, out.checkpoint.signature.public_key), true);
    assert.equal(out.block.seq, i);
    assert.equal(out.block.checkpoint.root_hash,
      Merkle.buildTree(digests.map(d => Buffer.from(d, 'hex'))).root.toString('hex'));
    assert.equal(out.state_written, true);

    // The attached proof recomputes the checkpoint root from the leaf alone.
    const proof = Merkle.verifyInclusion({
      index: i - 1,
      size: i,
      leafDigest: Buffer.from(digest, 'hex'),
      root: out.block.checkpoint.root_hash,
      path: out.block.path,
    });
    assert.equal(proof.ok, true, 'inclusion proof must recompute the root: ' + proof.reason);
  }

  const entries = readLines(env.paths.entries).map(line => JSON.parse(line));
  assert.deepEqual(entries.map(e => e.seq), [1, 2, 3]);
  assert.equal(entries[1].prev_entry_hash, entries[0].entry_hash);
  assert.equal(entries[2].prev_entry_hash, entries[1].entry_hash);

  const checkpoints = readLines(env.paths.checkpoints).map(line => JSON.parse(line));
  assert.deepEqual(checkpoints.map(c => c.tree_size), [0, 1, 2, 3]);
  for (let i = 2; i < checkpoints.length; i++) {
    assert.equal(checkpoints[i].prev_checkpoint_hash, checkpoints[i - 1].checkpoint_hash);
  }

  const verified = Ledger.verifyLocal(env.ledger, { keyring: env.keyring });
  assert.equal(verified.ok, true, verified.code + ': ' + verified.message);
  assert.deepEqual(verified.checks.map(c => c.name),
    ['structure', 'checkpoint_chain', 'checkpoint_signatures', 'entry_signatures']);

  const state = JSON.parse(fs.readFileSync(env.paths.state, 'utf8'));
  assert.equal(state.seq, 3);
  assert.equal(state.head_hash, entries[2].entry_hash);
  assert.equal(state.checkpoint_hash, checkpoints[3].checkpoint_hash);
});

test('a duplicate payload digest is refused and the log is untouched', (t) => {
  const env = makeEnv(t);
  const digest = digestOf('only-once');
  Ledger.append(env.ledger, { signer: env.signer, payload_digest: digest });

  const before = {
    entries: fs.readFileSync(env.paths.entries),
    checkpoints: fs.readFileSync(env.paths.checkpoints),
    state: fs.readFileSync(env.paths.state),
  };

  assert.throws(() => Ledger.append(env.ledger, { signer: env.signer, payload_digest: digest }),
    (e) => e.code === 'LEDGER_DUPLICATE');

  assert.deepEqual(fs.readFileSync(env.paths.entries), before.entries);
  assert.deepEqual(fs.readFileSync(env.paths.checkpoints), before.checkpoints);
  assert.deepEqual(fs.readFileSync(env.paths.state), before.state);
  assert.equal(fs.existsSync(env.paths.lock), false);
});

test('eight concurrent appenders produce one contiguous chain, one winner per seq', async (t) => {
  const env = makeEnv(t);
  const digests = [];
  for (let i = 1; i <= 8; i++) digests.push(digestOf('concurrent-' + i));

  const results = await Promise.all(digests.map(digest => runAppender({
    LEDGER_MODULE,
    LEDGER_PATH: env.ledger,
    LEDGER_KEYRING: env.keyring,
    LEDGER_DIGEST: digest,
  })));

  for (const result of results) {
    assert.equal(result.code, 0, 'appender failed: ' + result.stderr);
  }

  const entries = readLines(env.paths.entries).map(line => JSON.parse(line));
  assert.equal(entries.length, 8, 'every appender must be recorded exactly once');
  assert.deepEqual(entries.map(e => e.seq), [1, 2, 3, 4, 5, 6, 7, 8]);
  assert.deepEqual(entries.map(e => e.payload_digest).sort(), digests.slice().sort());

  for (let i = 1; i < entries.length; i++) {
    assert.equal(entries[i].prev_entry_hash, entries[i - 1].entry_hash);
  }

  const checkpoints = readLines(env.paths.checkpoints).map(line => JSON.parse(line));
  assert.deepEqual(checkpoints.map(c => c.tree_size), [0, 1, 2, 3, 4, 5, 6, 7, 8]);

  const verified = Ledger.verifyLocal(env.ledger, { keyring: env.keyring });
  assert.equal(verified.ok, true, verified.code + ': ' + verified.message);
  assert.equal(verified.head.seq, 8);
  assert.equal(fs.existsSync(env.paths.lock), false);
});

test('a stale lock with a live PID blocks and needs an explicit unlock', (t) => {
  const env = makeEnv(t);
  Ledger.append(env.ledger, { signer: env.signer, payload_digest: digestOf('before-lock') });

  const held = {
    pid: process.pid,
    host: os.hostname(),
    nonce: 'f'.repeat(32),
    created_at: new Date(Date.now() - 11 * 60 * 1000).toISOString(),
    ledger_path: env.ledger,
    tool_version: 'test',
  };
  fs.writeFileSync(env.paths.lock, JSON.stringify(held) + '\n');

  const before = fs.readFileSync(env.paths.entries);
  assert.throws(() => Ledger.append(env.ledger, { signer: env.signer, payload_digest: digestOf('blocked') }),
    (e) => e.code === 'LEDGER_LOCKED' && e.lock && e.lock.pid === process.pid);
  assert.deepEqual(fs.readFileSync(env.paths.entries), before, 'a blocked append must not write');
  assert.equal(fs.existsSync(env.paths.lock), true);

  const forced = Ledger.append(env.ledger, {
    signer: env.signer,
    payload_digest: digestOf('forced'),
    forceUnlock: true,
  });
  assert.equal(forced.entry.seq, 2);

  const repairs = Ledger.readRepairEvents(fs, env.paths.repairs);
  assert.equal(repairs.filter(r => r.event === 'LOCK_FORCED').length, 1);
  assert.equal(repairs[0].previous.pid, process.pid);
  const leftovers = fs.readdirSync(env.root).filter(name => name.indexOf('.lock.stale-') !== -1);
  assert.equal(leftovers.length >= 1, true, 'the discarded lock record must be retained');
  assert.equal(fs.existsSync(env.paths.lock), false);
});

test('a lock from a dead PID on this host is reclaimed and logged', (t) => {
  const env = makeEnv(t);
  const dead = spawnSync(process.execPath, ['-e', ''], { stdio: 'ignore' });
  assert.equal(dead.status, 0);

  fs.writeFileSync(env.paths.lock, JSON.stringify({
    pid: dead.pid,
    host: os.hostname(),
    nonce: 'a'.repeat(32),
    created_at: new Date(Date.now() - 11 * 60 * 1000).toISOString(),
    ledger_path: env.ledger,
    tool_version: 'test',
  }) + '\n');

  const out = Ledger.append(env.ledger, { signer: env.signer, payload_digest: digestOf('reclaimed') });
  assert.equal(out.entry.seq, 1);
  const repairs = Ledger.readRepairEvents(fs, env.paths.repairs);
  assert.equal(repairs.filter(r => r.event === 'LOCK_RECLAIMED').length, 1);
  assert.equal(repairs[0].previous.pid, dead.pid);
  assert.equal(fs.existsSync(env.paths.lock), false);
});

test('a lock from a foreign host is never reclaimed automatically', (t) => {
  const env = makeEnv(t);
  const dead = spawnSync(process.execPath, ['-e', ''], { stdio: 'ignore' });

  fs.writeFileSync(env.paths.lock, JSON.stringify({
    pid: dead.pid,
    host: 'some-other-host',
    nonce: 'b'.repeat(32),
    created_at: new Date(Date.now() - 60 * 60 * 1000).toISOString(),
    ledger_path: env.ledger,
    tool_version: 'test',
  }) + '\n');

  assert.throws(() => Ledger.append(env.ledger, { signer: env.signer, payload_digest: digestOf('foreign') }),
    (e) => e.code === 'LEDGER_LOCKED');
  assert.equal(fs.existsSync(env.paths.lock), true);
  assert.equal(fs.existsSync(env.paths.repairs), false, 'a refusal is not a reclaim');
});

test('a reclaimed former owner cannot unlink its successor lock', (t) => {
  const env = makeEnv(t);
  const lockA = Ledger.acquireLock(env.ledger, {});
  assert.equal(fs.existsSync(env.paths.lock), true);

  // Simulate a reclaim by another process: the old record is moved aside and a
  // new owner installs its own lock.
  fs.renameSync(env.paths.lock, env.paths.lock + '.moved-by-test');
  const lockB = Ledger.acquireLock(env.ledger, {});
  assert.notEqual(lockB.nonce, lockA.nonce);

  const released = Ledger.releaseLock(lockA, { fs });
  assert.equal(released.released, false);
  assert.equal(released.reason, 'owner_changed');
  assert.equal(fs.existsSync(env.paths.lock), true, 'the successor lock must survive');

  const successor = JSON.parse(fs.readFileSync(env.paths.lock, 'utf8'));
  assert.equal(successor.nonce, lockB.nonce);

  assert.equal(Ledger.releaseLock(lockB, { fs }).released, true);
  assert.equal(fs.existsSync(env.paths.lock), false);
});

test('the append order is entry fsync, checkpoint fsync, state rename, directory fsync', (t) => {
  const env = makeEnv(t);
  const { io, ops } = recordFs();

  Ledger.append(env.ledger, { signer: env.signer, payload_digest: digestOf('ordered'), fs: io });

  const entryOpen = ops.findIndex(o => o.op === 'open' && o.file === env.paths.entries && o.flags === 'a');
  const entryFsync = ops.findIndex(o => o.op === 'fsync' && o.file === env.paths.entries);
  const checkpointOpen = ops.findIndex(o => o.op === 'open' && o.file === env.paths.checkpoints && o.flags === 'a');
  const checkpointFsync = ops.findIndex(o => o.op === 'fsync' && o.file === env.paths.checkpoints);
  const stateTemp = env.paths.state + '.tmp-' + process.pid;
  const stateWrite = ops.findIndex(o => o.op === 'writeFile' && o.file === stateTemp);
  const stateFsync = ops.findIndex(o => o.op === 'fsync' && o.file === stateTemp);
  const stateRename = ops.findIndex(o => o.op === 'rename' && o.to === env.paths.state);

  assert.notEqual(entryOpen, -1, 'entry file opened for append');
  assert.notEqual(entryFsync, -1, 'entry file fsynced');
  assert.notEqual(checkpointOpen, -1, 'checkpoint file opened for append');
  assert.notEqual(checkpointFsync, -1, 'checkpoint file fsynced');
  assert.notEqual(stateWrite, -1, 'state temp file written');
  assert.notEqual(stateFsync, -1, 'state temp file fsynced');
  assert.notEqual(stateRename, -1, 'state file renamed into place');

  assert.ok(entryOpen < entryFsync, 'the entry must be fsynced after it is written');
  assert.ok(entryFsync < checkpointOpen, 'the checkpoint must follow the durable entry');
  assert.ok(checkpointOpen < checkpointFsync, 'the checkpoint must be fsynced after it is written');
  assert.ok(checkpointFsync < stateWrite, 'the state cache must follow the durable checkpoint');
  assert.ok(stateWrite < stateFsync, 'the state temp file must be fsynced before the rename');
  assert.ok(stateFsync < stateRename, 'state must be fsynced before it is renamed');
  assert.equal(ops.slice(stateRename).some(o => o.op === 'fsync' && o.file === '(dir)'), true,
    'the directory must be fsynced after the rename');
});

test('a failing fsync fails the append instead of reporting success', (t) => {
  const env = makeEnv(t);
  const before = fs.readFileSync(env.paths.entries);
  const stateBefore = fs.readFileSync(env.paths.state);

  assert.throws(() => Ledger.append(env.ledger, {
    signer: env.signer,
    payload_digest: digestOf('fsync-failure'),
    fs: faultFs(env.paths.entries, 'fsync'),
  }), (e) => e.code === 'LEDGER_WRITE_FAILED' || e.code === 'LEDGER_CORRUPT');

  assert.deepEqual(fs.readFileSync(env.paths.entries), before, 'a failed fsync must roll back');
  assert.deepEqual(fs.readFileSync(env.paths.state), stateBefore);
  assert.equal(fs.existsSync(env.paths.lock), false);
});

test('ENOSPC and a zero-length write roll back to the pre-append size', (t) => {
  const env = makeEnv(t);
  Ledger.append(env.ledger, { signer: env.signer, payload_digest: digestOf('kept') });

  const entriesBefore = fs.readFileSync(env.paths.entries);
  const checkpointsBefore = fs.readFileSync(env.paths.checkpoints);
  const sizeBefore = fs.statSync(env.paths.entries).size;

  assert.throws(() => Ledger.append(env.ledger, {
    signer: env.signer,
    payload_digest: digestOf('enospc'),
    fs: faultFs(env.paths.entries, 'enospc'),
  }), (e) => e.code === 'LEDGER_WRITE_FAILED');

  assert.equal(fs.statSync(env.paths.entries).size, sizeBefore);
  assert.deepEqual(fs.readFileSync(env.paths.entries), entriesBefore);

  assert.throws(() => Ledger.append(env.ledger, {
    signer: env.signer,
    payload_digest: digestOf('zero-write'),
    fs: faultFs(env.paths.entries, 'zero'),
  }), (e) => e.code === 'LEDGER_WRITE_FAILED');

  assert.equal(fs.statSync(env.paths.entries).size, sizeBefore);
  assert.deepEqual(fs.readFileSync(env.paths.entries), entriesBefore);
  assert.deepEqual(fs.readFileSync(env.paths.checkpoints), checkpointsBefore);
  assert.equal(fs.existsSync(env.paths.lock), false);
});

test('a failed receipt write leaves the receipt untouched and the entry durable', (t) => {
  const env = makeEnv(t);
  const receiptFile = path.join(env.root, 'receipt.json');
  fs.writeFileSync(receiptFile, '{"receipt":"unchanged"}\n');
  const before = fs.readFileSync(receiptFile);

  assert.throws(() => Ledger.append(env.ledger, {
    signer: env.signer,
    payload_digest: digestOf('receipt-failure'),
    receipt_id: 'r-receipt',
    writeReceipt() { throw new Error('write refused'); },
  }), (e) => e.code === 'LEDGER_RECEIPT_WRITE_FAILED');

  assert.deepEqual(fs.readFileSync(receiptFile), before, 'the receipt must be byte-identical');
  const entries = readLines(env.paths.entries).map(line => JSON.parse(line));
  assert.equal(entries.length, 1);
  assert.equal(entries[0].payload_digest, digestOf('receipt-failure'));
  const state = JSON.parse(fs.readFileSync(env.paths.state, 'utf8'));
  assert.equal(state.seq, 1);
});

test('read-only verification and a dry-run fsck write nothing', (t) => {
  const env = makeEnv(t);
  Ledger.append(env.ledger, { signer: env.signer, payload_digest: digestOf('one') });
  Ledger.append(env.ledger, { signer: env.signer, payload_digest: digestOf('two') });

  const snapshot = () => {
    const files = {};
    for (const entry of fs.readdirSync(env.root, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      if (!entry.isFile()) continue;
      const file = path.join(env.root, entry.name);
      files[entry.name] = crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
    }
    return files;
  };

  const before = snapshot();
  const verified = Ledger.verifyLocal(env.ledger, { keyring: env.keyring });
  assert.equal(verified.ok, true, verified.code);
  const checked = Ledger.fsck(env.ledger, { dryRun: true });
  assert.equal(checked.ok, true, checked.code);
  assert.equal(checked.actions.length, 0);

  assert.deepEqual(snapshot(), before, 'read-only paths must not create or touch a file');
  assert.equal(fs.existsSync(env.paths.lock), false, 'a dry run must not take the lock');

  // Byte comparison alone cannot see a file created and removed, so the same
  // paths are run through a recording filesystem and must make no write op at
  // all: no write, no rename, no truncate, no unlink, and no writable open.
  const { io, ops } = recordFs();
  const watched = Ledger.verifyLocal(env.ledger, { keyring: env.keyring, fs: io });
  assert.equal(watched.ok, true, watched.code);
  const watchedCheck = Ledger.fsck(env.ledger, { dryRun: true, fs: io });
  assert.equal(watchedCheck.ok, true, watchedCheck.code);

  const writes = ops.filter(o => o.op === 'write'
    || o.op === 'writeFile'
    || o.op === 'rename'
    || o.op === 'truncate'
    || o.op === 'unlink'
    || o.op === 'link'
    || (o.op === 'open' && o.flags !== 'r'));
  assert.deepEqual(writes, [], 'read-only paths must not write');
});

test('a missing key source is reported, never treated as a verified signature', (t) => {
  const env = makeEnv(t);
  Ledger.append(env.ledger, { signer: env.signer, payload_digest: digestOf('unchecked') });

  const verified = Ledger.verifyLocal(env.ledger, {});
  assert.equal(verified.ok, false);
  assert.equal(verified.code, 'LEDGER_UNTRUSTED_KEY');
  assert.equal(verified.checks.find(c => c.name === 'checkpoint_signatures').ok, false);
  assert.equal(verified.checks.find(c => c.name === 'entry_signatures').ok, false);

  const wrongKeyring = path.join(env.root, 'other-keys');
  Signing.ensureKeyring({ dir: wrongKeyring });
  const untrusted = Ledger.verifyLocal(env.ledger, { keyring: wrongKeyring });
  assert.equal(untrusted.ok, false);
  assert.equal(untrusted.code, 'LEDGER_UNTRUSTED_KEY');
});

function baseFs() {
  return {
    readFileSync: fs.readFileSync,
    statSync: fs.statSync,
    openSync: fs.openSync,
    writeSync: fs.writeSync,
    fsyncSync: fs.fsyncSync,
    closeSync: fs.closeSync,
    writeFileSync: fs.writeFileSync,
    renameSync: fs.renameSync,
    truncateSync: fs.truncateSync,
    unlinkSync: fs.unlinkSync,
    linkSync: fs.linkSync,
  };
}

function lockRecordFor(ledger, nonce, overrides) {
  return Object.assign({
    pid: process.pid,
    host: os.hostname(),
    nonce,
    created_at: new Date().toISOString(),
    ledger_path: ledger,
    tool_version: 'test',
  }, overrides || {});
}

test('a lock that changes hands between judgement and rename is restored, not discarded', (t) => {
  const env = makeEnv(t);
  const dead = spawnSync(process.execPath, ['-e', ''], { stdio: 'ignore' });
  fs.writeFileSync(env.paths.lock, JSON.stringify(lockRecordFor(env.ledger, 'd'.repeat(32), {
    pid: dead.pid,
    created_at: new Date(Date.now() - 11 * 60 * 1000).toISOString(),
  })) + '\n');

  // The rename is the dangerous step: it runs after the staleness judgement, so
  // another process may have installed its own live lock in between. Here that
  // is simulated by replacing the file immediately before the rename.
  const foreignNonce = 'e'.repeat(32);
  let swapped = false;
  const io = Object.assign(baseFs(), {
    renameSync(from, to) {
      if (from === env.paths.lock && !swapped) {
        swapped = true;
        fs.writeFileSync(env.paths.lock, JSON.stringify(lockRecordFor(env.ledger, foreignNonce)) + '\n');
      }
      return fs.renameSync(from, to);
    },
  });

  const before = fs.readFileSync(env.paths.entries);
  assert.throws(() => Ledger.append(env.ledger, {
    signer: env.signer,
    payload_digest: digestOf('raced-reclaim'),
    fs: io,
  }), (e) => e.code === 'LEDGER_LOCKED');

  assert.equal(swapped, true);
  assert.deepEqual(fs.readFileSync(env.paths.entries), before, 'a lost reclaim must not write');
  const onDisk = JSON.parse(fs.readFileSync(env.paths.lock, 'utf8'));
  assert.equal(onDisk.nonce, foreignNonce, 'the other writer lock must still be in place');
});

test('a lock stolen during an append aborts before any bytes are written', (t) => {
  const env = makeEnv(t);
  const foreignNonce = 'f'.repeat(32);
  let stolen = false;
  const io = Object.assign(baseFs(), {
    readFileSync(file, encoding) {
      const data = fs.readFileSync(file, encoding);
      if (file === env.paths.checkpoints && !stolen) {
        stolen = true;
        fs.writeFileSync(env.paths.lock, JSON.stringify(lockRecordFor(env.ledger, foreignNonce)) + '\n');
      }
      return data;
    },
  });

  const entriesBefore = fs.readFileSync(env.paths.entries);
  const checkpointsBefore = fs.readFileSync(env.paths.checkpoints);

  assert.throws(() => Ledger.append(env.ledger, {
    signer: env.signer,
    payload_digest: digestOf('stolen-lock'),
    fs: io,
  }), (e) => e.code === 'LEDGER_LOCK_LOST');

  assert.equal(stolen, true);
  assert.deepEqual(fs.readFileSync(env.paths.entries), entriesBefore);
  assert.deepEqual(fs.readFileSync(env.paths.checkpoints), checkpointsBefore);
});

test('release never unlinks the shared lock path, so it cannot delete a successor lock', (t) => {
  const env = makeEnv(t);
  const lockA = Ledger.acquireLock(env.ledger, {});
  const { io, ops } = recordFs();

  const released = Ledger.releaseLock(lockA, { fs: io });
  assert.equal(released.released, true);

  // The shared path is claimed by rename and only the private name is deleted.
  // An unlink of the shared path is the operation that could delete a lock the
  // releasing process no longer owns.
  assert.equal(ops.filter(o => o.op === 'unlink' && o.file === env.paths.lock).length, 0);
  assert.equal(ops.filter(o => o.op === 'rename' && o.from === env.paths.lock).length, 1);
  assert.equal(fs.existsSync(env.paths.lock), false);
});

test('four appenders racing to reclaim one stale lock all land exactly once', async (t) => {
  const env = makeEnv(t);
  const dead = spawnSync(process.execPath, ['-e', ''], { stdio: 'ignore' });
  fs.writeFileSync(env.paths.lock, JSON.stringify(lockRecordFor(env.ledger, 'a'.repeat(32), {
    pid: dead.pid,
    created_at: new Date(Date.now() - 30 * 60 * 1000).toISOString(),
  })) + '\n');

  const digests = [1, 2, 3, 4].map(i => digestOf('reclaim-race-' + i));
  const results = await Promise.all(digests.map(digest => runAppender({
    LEDGER_MODULE,
    LEDGER_PATH: env.ledger,
    LEDGER_KEYRING: env.keyring,
    LEDGER_DIGEST: digest,
  })));

  for (const result of results) {
    assert.equal(result.code, 0, 'appender failed: ' + result.stderr);
  }

  const entries = readLines(env.paths.entries).map(line => JSON.parse(line));
  assert.deepEqual(entries.map(e => e.seq), [1, 2, 3, 4]);
  assert.deepEqual(entries.map(e => e.payload_digest).sort(), digests.slice().sort());
  const verified = Ledger.verifyLocal(env.ledger, { keyring: env.keyring });
  assert.equal(verified.ok, true, verified.code + ': ' + verified.message);
});

test('a reclaim that loses the rename race still ends with exactly one lock holder', (t) => {
  const env = makeEnv(t);
  const dead = spawnSync(process.execPath, ['-e', ''], { stdio: 'ignore' });
  fs.writeFileSync(env.paths.lock, JSON.stringify(lockRecordFor(env.ledger, 'b'.repeat(32), {
    pid: dead.pid,
    created_at: new Date(Date.now() - 11 * 60 * 1000).toISOString(),
  })) + '\n');

  // Another reclaimer moves the record first and has not created its own lock
  // yet. The losing rename gets ENOENT, the loop retries the exclusive create,
  // and the caller still ends up as the single holder.
  let raced = false;
  const io = Object.assign(baseFs(), {
    renameSync(from, to) {
      if (from === env.paths.lock && !raced) {
        raced = true;
        fs.unlinkSync(env.paths.lock);
        const error = new Error('no such file');
        error.code = 'ENOENT';
        throw error;
      }
      return fs.renameSync(from, to);
    },
  });

  const lock = Ledger.acquireLock(env.ledger, { fs: io });
  assert.equal(raced, true);
  assert.equal(fs.existsSync(env.paths.lock), true);
  const onDisk = JSON.parse(fs.readFileSync(env.paths.lock, 'utf8'));
  assert.equal(onDisk.nonce, lock.nonce);
  assert.equal(Ledger.releaseLock(lock, { fs }).released, true);
});

test('an unreadable lock is reported as unreadable, not as an unknown pid', (t) => {
  const env = makeEnv(t);
  fs.writeFileSync(env.paths.lock, '');

  assert.throws(() => Ledger.append(env.ledger, {
    signer: env.signer,
    payload_digest: digestOf('unreadable-lock'),
  }), (e) => e.code === 'LEDGER_LOCKED'
    && /unreadable/i.test(e.message)
    && !/pid null/.test(e.message));

  const state = JSON.parse(fs.readFileSync(env.paths.state, 'utf8'));
  assert.equal(state.seq, 0);
});

test('forceUnlock clears a zero-byte lock left by a crash during creation', (t) => {
  const env = makeEnv(t);
  // The lock file exists but its record was never written: the crash window the
  // old create() opened between O_EXCL creation and the write.
  fs.writeFileSync(env.paths.lock, '');

  const out = Ledger.append(env.ledger, {
    signer: env.signer,
    payload_digest: digestOf('after-crash'),
    forceUnlock: true,
  });
  assert.equal(out.entry.seq, 1);

  const repairs = Ledger.readRepairEvents(fs, env.paths.repairs);
  assert.equal(repairs.length, 1);
  assert.equal(repairs[0].event, 'LOCK_FORCED');
  assert.equal(repairs[0].unreadable, true);
  assert.equal(typeof repairs[0].previous_raw, 'string');
  assert.equal(fs.existsSync(env.paths.lock), false);
  assert.equal(fs.readdirSync(env.root).some(name => name.indexOf('.lock.stale-') !== -1), true,
    'the discarded record must be retained for inspection');
});

test('a malformed lock record is clearable and never attributed to a process', (t) => {
  const env = makeEnv(t);
  fs.writeFileSync(env.paths.lock, '{"pid":');

  const out = Ledger.append(env.ledger, {
    signer: env.signer,
    payload_digest: digestOf('malformed-lock'),
    forceUnlock: true,
  });
  assert.equal(out.entry.seq, 1);
  assert.equal(Ledger.verifyLocal(env.ledger, { keyring: env.keyring }).ok, true);
});

// A lock record that parses as JSON but carries no usable identity is the one
// shape the malformed and zero-byte tests do not cover: parseLockRecord returns
// an object, so the old reclaim path read it as "a record appeared" and refused
// to discard it, leaving forceUnlock - the documented escape hatch - unable to
// clear a lock no process can own. The record can come from an older writer, an
// interrupted external write, or manual file surgery; either way the escape
// hatch has to work on it.
test('forceUnlock clears a lock record that parses but cannot be attributed', (t) => {
  const env = makeEnv(t);
  const raw = '{"pid":null,"host":"somewhere"}\n';
  fs.writeFileSync(env.paths.lock, raw);

  assert.throws(() => Ledger.append(env.ledger, {
    signer: env.signer,
    payload_digest: digestOf('incomplete-lock'),
  }), (e) => e.code === 'LEDGER_LOCKED' && /unreadable/i.test(e.message));

  const out = Ledger.append(env.ledger, {
    signer: env.signer,
    payload_digest: digestOf('incomplete-lock'),
    forceUnlock: true,
  });
  assert.equal(out.entry.seq, 1);
  assert.equal(Ledger.verifyLocal(env.ledger, { keyring: env.keyring }).ok, true);

  const repairs = Ledger.readRepairEvents(fs, env.paths.repairs);
  assert.equal(repairs.length, 1);
  assert.equal(repairs[0].event, 'LOCK_FORCED');
  assert.equal(repairs[0].unreadable, true);
  assert.equal(repairs[0].previous_raw, raw.slice(0, 512));
  assert.equal(fs.existsSync(env.paths.lock), false);

  const leftover = fs.readdirSync(env.root).find(name => name.indexOf('.lock.stale-unreadable') !== -1);
  assert.equal(!!leftover, true, 'the discarded record must be retained for inspection');
  assert.equal(fs.readFileSync(path.join(env.root, leftover), 'utf8'), raw);
});

test('fsck forceUnlock clears an unattributable record that has a pid but no nonce', (t) => {
  const env = makeEnv(t);
  fs.writeFileSync(env.paths.lock, JSON.stringify({
    pid: process.pid,
    host: os.hostname(),
    created_at: new Date().toISOString(),
  }) + '\n');

  const result = Ledger.fsck(env.ledger, { forceUnlock: true });
  assert.equal(result.code, 'OK');
  assert.equal(result.ok, true);
  assert.equal(fs.existsSync(env.paths.lock), false);
  assert.equal(Ledger.readRepairEvents(fs, env.paths.repairs).some(r => r.event === 'LOCK_FORCED'), true);
});

// The escape hatch may only discard the bytes it judged. If a different record
// appears between the judgement and the move - a writer that finished writing
// its lock, for example - that record belongs to someone and must survive.
test('forceUnlock never discards a different lock that appears while it is discarding', (t) => {
  const env = makeEnv(t);
  const unusable = '{"pid":null}\n';
  const foreign = lockRecordFor(env.ledger, 'c'.repeat(32), { pid: process.pid });
  fs.writeFileSync(env.paths.lock, unusable);

  let reads = 0;
  const io = Object.assign(baseFs(), {
    readFileSync(file, encoding) {
      if (path.resolve(file) === env.paths.lock) {
        reads += 1;
        if (reads === 1) return Buffer.from(unusable);
        // A different writer installs its own record between the judgement and
        // the move. The swap is on disk, not just in the facade's answer.
        fs.writeFileSync(env.paths.lock, JSON.stringify(foreign) + '\n');
        return fs.readFileSync(env.paths.lock);
      }
      return fs.readFileSync(file, encoding);
    },
  });

  assert.throws(() => Ledger.acquireLock(env.ledger, { fs: io, forceUnlock: true }),
    (e) => e.code === 'LEDGER_LOCKED' && /readable|changed/i.test(e.message));
  assert.equal(reads >= 2, true);
  const onDisk = JSON.parse(fs.readFileSync(env.paths.lock, 'utf8'));
  assert.equal(onDisk.nonce, foreign.nonce, 'the other lock must be left in place');
});

// Prefix roots are computed in one incremental pass now, so this pins the
// property that pass must keep: every checkpoint's root is checked, not just
// the head's. The forged checkpoint is re-signed and the tail re-linked, so the
// hash chain and every signature are valid and only the root at size 3 is wrong.
test('the inspection checks every checkpoint root, not only the head', (t) => {
  const env = makeEnv(t);
  for (let i = 1; i <= 5; i++) {
    Ledger.append(env.ledger, { signer: env.signer, payload_digest: digestOf('root-' + i) });
  }

  const checkpoints = readLines(env.paths.checkpoints).map(line => JSON.parse(line));
  const forgedAt = 3;
  let prevHash = checkpoints[forgedAt - 1].checkpoint_hash;
  const forged = checkpoints.slice(0, forgedAt);
  for (let i = forgedAt; i < checkpoints.length; i++) {
    const original = checkpoints[i];
    const rebuilt = Ledger.signCheckpoint(Ledger.buildCheckpoint({
      ledger_id: original.ledger_id,
      tree_size: original.tree_size,
      root_hash: i === forgedAt ? 'a'.repeat(64) : original.root_hash,
      created_at: original.created_at,
      prev_checkpoint_hash: prevHash,
      policy_hash: original.policy_hash,
    }), env.signer);
    forged.push(rebuilt);
    prevHash = rebuilt.checkpoint_hash;
  }
  fs.writeFileSync(env.paths.checkpoints, forged.map(c => JSON.stringify(c)).join('\n') + '\n');

  const verified = Ledger.verifyLocal(env.ledger, { keyring: env.keyring });
  assert.equal(verified.code, 'LEDGER_ENTRY_MISMATCH');
  assert.equal(verified.message.indexOf('tree size 3') !== -1, true);
  assert.throws(() => Ledger.append(env.ledger, {
    signer: env.signer,
    payload_digest: digestOf('after-forgery'),
  }), (e) => e.code === 'LEDGER_ENTRY_MISMATCH');
});

test('init in a missing directory names the directory, not the lock', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'verifyd-ledger-nodir-'));
  const keyring = path.join(root, 'keys');
  const created = Signing.ensureKeyring({ dir: keyring });
  const signer = Ledger.keyringSigner({ dir: keyring });
  const ledger = path.join(root, 'nested', 'ledger.jsonl');
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  assert.throws(() => Ledger.initLedger(ledger, {
    signer,
    policy: { writer_keys: [created.key_id], admin_keys: [created.key_id] },
  }), (e) => e.code === 'LEDGER_DIRECTORY_MISSING'
    && e.message.indexOf(path.dirname(ledger)) !== -1);

  assert.equal(fs.existsSync(path.dirname(ledger)), false, 'init must not invent the directory');
});

test('a failed lock-record write leaves no lock behind to wedge the next writer', (t) => {
  const env = makeEnv(t);
  const names = new Map();
  const io = Object.assign(baseFs(), {
    openSync(file, flags) {
      const fd = fs.openSync(file, flags);
      names.set(fd, file);
      return fd;
    },
    writeSync(fd, buf, offset, length) {
      // Fail the write into the private lock-record temp file, which is the
      // crash window the old create() turned into an empty lock.
      if ((names.get(fd) || '').indexOf('.lock.tmp-') !== -1) {
        const error = new Error('no space left on device');
        error.code = 'ENOSPC';
        throw error;
      }
      return fs.writeSync(fd, buf, offset, length);
    },
  });

  assert.throws(() => Ledger.append(env.ledger, {
    signer: env.signer,
    payload_digest: digestOf('full-disk'),
    fs: io,
  }), (e) => e.code === 'LEDGER_LOCKED');

  assert.equal(fs.existsSync(env.paths.lock), false, 'no partial lock may exist at the shared path');
  assert.deepEqual(fs.readdirSync(env.root).filter(name => name.indexOf('.lock') !== -1), []);

  const out = Ledger.append(env.ledger, { signer: env.signer, payload_digest: digestOf('after-disk-full') });
  assert.equal(out.entry.seq, 1);
});
