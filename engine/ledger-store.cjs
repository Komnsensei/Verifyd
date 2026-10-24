// Verifyd receipt ledger - the persistent single-writer store (Phase B).
//
// WHAT IS DURABLE HERE
//   Entries and checkpoints are appended one line at a time with O_APPEND, one
//   write per record, fsynced before the next step. The state cache is replaced
//   by temp file, fsync, rename, then directory fsync where the platform allows
//   one. The order is entry-fsync, checkpoint-fsync, state rename, so the entry
//   log is always the most advanced artifact and the state cache can only lag
//   it. Nothing in this file relies on a caller remembering to fsync: the only
//   write paths are appendLineDurable and writeState.
//
// WHAT IS NOT DURABLE HERE
//   Directory fsync does not exist on Windows. Power-loss durability there is
//   weaker than on POSIX: a record can be fsynced while the directory entry
//   that names a new file is not. fsyncDir attempts the call and treats an
//   unsupported result as a no-op; it never reports the stronger outcome.
//
// AUTHORITY IS NOT DECIDED HERE
//   Every entry and checkpoint is signed by the writer key the caller supplies.
//   Whether that key was authorized to append is the writer policy committed by
//   policy_hash in genesis, judged in Phase D. This file proves bytes, order
//   and durability; it does not prove that the writer had the right to write.
//
// ONE WRITER AT A TIME
//   A lock file created with O_CREAT|O_EXCL serializes appends, the same
//   property the keyring gets from renaming a directory into place. The lock is
//   a mutex, never the record of truth. A stale lock is reclaimed only when the
//   TTL has expired, the host matches and the PID is gone; a live PID or a
//   foreign host is reported as LEDGER_LOCKED and needs an explicit unlock.
//
// ONE READ MODEL
//   inspectLedger reads both files once, parses and hashes every record, checks
//   both chains and recomputes each checkpoint's prefix root. It reports what it
//   found instead of throwing, because its consumers disagree about what to do
//   with the same damage: append and verify refuse, fsck repairs. readLedger is
//   the refusing wrapper. No consumer walks the log on its own.
//
// DEPENDENCY DIRECTION
//   ledger-format.cjs <- this file <- ledger-recovery.cjs / ledger-verify.cjs.
//   This file never requires engine/ledger.cjs (the public facade).

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const Merkle = require('./merkle.cjs');
const Signing = require('./signing.cjs');
const Policy = require('./ledger-policy.cjs');
const {
  SCHEME,
  GENESIS,
  fail,
  requireText,
  requireHex,
  assertScheme,
  checkpointHash,
  entryBody,
  entryHash,
  signEntry,
  buildGenesis,
  buildCheckpoint,
  signCheckpoint,
  normalizeSigner,
  policyBody,
  policyHash,
  REVOCATION_COMMITMENT_PREFIX,
  requireKeyId,
  revocationBody,
  revocationCommitmentDigest,
  signRevocation,
} = require('./ledger-format.cjs');

const DEFAULT_LOCK_TTL_MS = 10 * 60 * 1000;
const DIR_FSYNC_ERRNOS = new Set(['EISDIR', 'EPERM', 'EACCES', 'EINVAL', 'EBADF', 'ENOTSUP', 'EOPNOTSUPP']);
const TOOL_VERSION = (() => {
  try { return require('../package.json').version; } catch (_) { return 'unknown'; }
})();

function ledgerPaths(ledgerPath) {
  const file = path.resolve(requireText(ledgerPath, 'ledger path'));
  return {
    ledger: file,
    entries: file,
    checkpoints: file + '.checkpoints.jsonl',
    policy: Policy.policyPathFor(file),
    revocations: Policy.revocationPathFor(file),
    state: file + '.state.json',
    lock: file + '.lock',
    repairs: file + '.repairs.log',
    torn: file + '.torn-tail.json',
    dir: path.dirname(file),
  };
}

function clockOf(opts) {
  const source = (opts && opts.now) || Date.now;
  return function now() {
    const value = source();
    return value instanceof Date ? new Date(value.getTime()) : new Date(value);
  };
}

function fileSize(io, file) {
  try {
    return io.statSync(file).size;
  } catch (e) {
    if (e.code === 'ENOENT') return 0;
    throw fail('LEDGER_IO', 'cannot stat ' + file + ': ' + (e.code || e.message));
  }
}

// Directory fsync is available on POSIX and not on Windows. Rather than branch
// on the platform, attempt it and treat the known unsupported errors as a
// no-op, so the caller is never told the stronger guarantee was applied.
function fsyncDir(dir, io) {
  let fd;
  try {
    fd = io.openSync(dir, 'r');
  } catch (e) {
    if (DIR_FSYNC_ERRNOS.has(e.code)) return false;
    throw e;
  }
  try {
    io.fsyncSync(fd);
    return true;
  } catch (e) {
    if (DIR_FSYNC_ERRNOS.has(e.code)) return false;
    throw e;
  } finally {
    try { io.closeSync(fd); } catch (_) { /* already closed */ }
  }
}

function rollbackAppend(io, file, size) {
  try {
    io.truncateSync(file, size);
    const fd = io.openSync(file, 'r+');
    try { io.fsyncSync(fd); } finally { io.closeSync(fd); }
    return true;
  } catch (_) {
    return false;
  }
}

// The single durable append path. A partial line is rolled back to the size the
// file had before the call, so a failed append leaves no half record behind for
// a later reader to mistake for evidence.
function appendLineDurable(file, line, io) {
  const buf = Buffer.from(line, 'utf8');
  const before = fileSize(io, file);
  let fd = null;
  try {
    fd = io.openSync(file, 'a');
    let written = 0;
    while (written < buf.length) {
      const n = io.writeSync(fd, buf, written, buf.length - written);
      if (!Number.isSafeInteger(n) || n <= 0) {
        throw fail('LEDGER_WRITE_FAILED', 'write made no progress at byte ' + written + ' of ' + buf.length);
      }
      written += n;
    }
    io.fsyncSync(fd);
    io.closeSync(fd);
    return { bytes: buf.length, size_before: before, size_after: before + buf.length };
  } catch (e) {
    if (fd !== null) { try { io.closeSync(fd); } catch (_) { /* already closed */ } }
    const rolledBack = rollbackAppend(io, file, before);
    if (!rolledBack) {
      throw fail('LEDGER_CORRUPT', 'append failed and the file could not be rolled back: ' + (e.message || e.code));
    }
    if (e && typeof e.code === 'string' && e.code.indexOf('LEDGER_') === 0) throw e;
    throw fail('LEDGER_WRITE_FAILED', (e && (e.code || e.message)) || 'write failed');
  }
}

function truncateTo(io, file, size) {
  io.truncateSync(file, size);
  const fd = io.openSync(file, 'r+');
  try { io.fsyncSync(fd); } finally { io.closeSync(fd); }
}

function logRepair(io, file, event) {
  const line = JSON.stringify(Object.assign({ at: new Date().toISOString() }, event)) + '\n';
  const fd = io.openSync(file, 'a');
  try {
    io.writeSync(fd, Buffer.from(line, 'utf8'));
    io.fsyncSync(fd);
  } finally {
    io.closeSync(fd);
  }
}

function readRepairEvents(io, file) {
  let buf;
  try {
    buf = io.readFileSync(file);
  } catch (e) {
    if (e.code === 'ENOENT') return [];
    throw fail('LEDGER_IO', 'cannot read ' + file + ': ' + (e.code || e.message));
  }
  const text = Buffer.isBuffer(buf) ? buf.toString('utf8') : String(buf);
  const events = [];
  for (const line of text.split('\n')) {
    if (!line) continue;
    try {
      const event = JSON.parse(line);
      if (event && typeof event === 'object' && !Array.isArray(event)) events.push(event);
    } catch (_) { /* a torn repairs line is not a repair record */ }
  }
  return events;
}

// --- the lock -------------------------------------------------------------

function readBootId() {
  try {
    return fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim() || null;
  } catch (_) {
    return null;
  }
}

function makeLockRecord(ledgerFile, now) {
  const record = {
    pid: process.pid,
    host: os.hostname(),
    nonce: crypto.randomBytes(16).toString('hex'),
    created_at: now().toISOString(),
    ledger_path: ledgerFile,
    tool_version: TOOL_VERSION,
  };
  const bootId = readBootId();
  if (bootId) record.boot_id = bootId;
  return record;
}

function isNetworkPath(file) {
  return process.platform === 'win32' && /^\\\\/.test(file);
}

function pidAlive(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return false;
  if (pid === process.pid) return true;
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    // EPERM means the process exists but the caller may not signal it.
    return e.code === 'EPERM';
  }
}

function readLockText(io, file) {
  let buf;
  try {
    buf = io.readFileSync(file);
  } catch (e) {
    if (e.code === 'ENOENT') return null;
    throw fail('LEDGER_LOCKED', 'the lock file exists but cannot be read: ' + (e.code || e.message));
  }
  return Buffer.isBuffer(buf) ? buf.toString('utf8') : String(buf);
}

function parseLockRecord(text) {
  if (typeof text !== 'string') return null;
  try {
    const record = JSON.parse(text);
    return record && typeof record === 'object' && !Array.isArray(record) ? record : null;
  } catch (_) {
    return null;
  }
}

function readLockFile(io, file) {
  return parseLockRecord(readLockText(io, file));
}

// A record is usable only if it can be attributed to a process and judged for
// staleness. Valid JSON missing those fields is not a usable lock: treating it
// as one would attribute the lock to nobody and report an unknown pid.
function isUsableLockRecord(record) {
  return !!record
    && typeof record.nonce === 'string' && record.nonce.length > 0
    && Number.isSafeInteger(record.pid)
    && typeof record.host === 'string'
    && typeof record.created_at === 'string';
}

function fileExistsAt(io, file) {
  try {
    io.statSync(file);
    return true;
  } catch (e) {
    if (e.code === 'ENOENT' || e.code === 'ENOTDIR') return false;
    return true;
  }
}

function directoryExists(io, dir) {
  try {
    return io.statSync(dir).isDirectory();
  } catch (e) {
    if (e.code === 'ENOENT' || e.code === 'ENOTDIR') return false;
    return true;
  }
}

// A lock is stale only when the TTL has expired AND the recorded process cannot
// be alive. PIDs are recycled, so a live PID is never reclaimed automatically,
// and neither is a lock from a foreign host: both need an explicit unlock.
function isLockStale(record, now, ttlMs) {
  if (!record || typeof record !== 'object') return false;
  const created = Date.parse(record.created_at);
  if (!Number.isFinite(created)) return false;
  if (now.getTime() - created < ttlMs) return false;
  if (record.host !== os.hostname()) return false;
  const currentBoot = readBootId();
  if (record.boot_id && currentBoot && record.boot_id !== currentBoot) return true;
  return !pidAlive(record.pid);
}

function acquireLock(ledgerPath, opts) {
  opts = opts || {};
  const io = opts.fs || fs;
  const pathsOf = ledgerPaths(ledgerPath);
  const now = clockOf(opts);
  // Name the real cause before trying to create anything in it: a missing
  // directory is not a locked ledger, and reporting it as one sends the operator
  // looking for a writer that does not exist.
  if (!directoryExists(io, pathsOf.dir)) {
    throw fail('LEDGER_DIRECTORY_MISSING', 'the ledger directory does not exist: ' + pathsOf.dir);
  }
  if (isNetworkPath(pathsOf.ledger) && !opts.allowNetworkFs) {
    throw fail('LEDGER_NETWORK_FS_REFUSED', 'refusing a UNC ledger path without allowNetworkFs: O_EXCL and O_APPEND are unreliable on some network filesystems');
  }
  const ttl = Number.isSafeInteger(opts.lockTtlMs) && opts.lockTtlMs > 0 ? opts.lockTtlMs : DEFAULT_LOCK_TTL_MS;
  const record = makeLockRecord(pathsOf.ledger, now);
  const events = [];

  // The record is written to a private temporary file first and only then linked
  // into place, so the lock path never holds a half-written record. A crash
  // leaves at most an orphan temporary file, which holds no lock and blocks
  // nothing.
  const writeRecord = (file, flags) => {
    const payload = Buffer.from(JSON.stringify(record) + '\n', 'utf8');
    const fd = io.openSync(file, flags);
    try {
      let written = 0;
      while (written < payload.length) {
        const n = io.writeSync(fd, payload, written, payload.length - written);
        if (!Number.isSafeInteger(n) || n <= 0) {
          throw fail('LEDGER_LOCKED', 'the lock record could not be written completely');
        }
        written += n;
      }
      io.fsyncSync(fd);
    } finally {
      try { io.closeSync(fd); } catch (_) { /* already closed */ }
    }
  };

  const create = () => {
    if (typeof io.linkSync === 'function') {
      const tmp = pathsOf.lock + '.tmp-' + record.nonce;
      try {
        writeRecord(tmp, 'w');
        io.linkSync(tmp, pathsOf.lock);
        return true;
      } catch (e) {
        if (e.code === 'EEXIST') return false;
        if (e.code === 'LEDGER_LOCKED') throw e;
        throw fail('LEDGER_LOCKED', 'cannot create the lock file: ' + (e.code || e.message));
      } finally {
        try { io.unlinkSync(tmp); } catch (_) { /* the link, not this name, is the lock */ }
      }
    }

    // Fallback for a filesystem without hard links: exclusive create, write, and
    // remove the file if any part of the write failed. A partial lock must never
    // survive this call.
    try {
      writeRecord(pathsOf.lock, 'wx');
      return true;
    } catch (e) {
      if (e.code === 'EEXIST') return false;
      try { io.unlinkSync(pathsOf.lock); } catch (_) { /* best effort */ }
      if (e.code === 'LEDGER_LOCKED') throw e;
      throw fail('LEDGER_LOCKED', 'cannot create the lock file: ' + (e.code || e.message));
    }
  };

  // Reclaim moves the judged record to a name derived from its own nonce. Two
  // reclamants therefore cannot both move it: rename is atomic and the loser
  // gets ENOENT. No separate claim file exists, so a crash cannot leave one
  // behind and wedge the only recovery path. A lock that changed hands between
  // the judgement and the rename is put back and reported.
  // A null `held` means the record could not be attributed: the caller has
  // already decided that only an explicit forced unlock may discard it, and it
  // passes the exact bytes it judged as `judgedText`. Only those bytes may be
  // discarded. A record that merely parses is not evidence of another writer -
  // an old, incomplete or hand-written record parses too - and treating it as
  // one is what made forceUnlock refuse to clear a lock it could never clear.
  const reclaim = (held, judgedText) => {
    const currentText = readLockText(io, pathsOf.lock);
    if (currentText === null) return false;
    const current = parseLockRecord(currentText);

    if (held) {
      if (!current || current.nonce !== held.nonce) {
        const changed = fail('LEDGER_LOCKED', 'the lock changed hands while it was being reclaimed');
        changed.lock = current || held;
        throw changed;
      }
    } else if (currentText !== judgedText) {
      // A different record appeared after the judgement. Readable or not, it
      // was not the record this call decided to discard, so it stays where it
      // is and is reported.
      const changed = fail('LEDGER_LOCKED', current
        ? 'the lock became readable while it was being discarded; it belongs to another writer'
        : 'the lock changed while it was being discarded; the replacement was left in place');
      changed.lock = current || null;
      throw changed;
    }

    const target = pathsOf.lock + '.stale-' + (held ? held.nonce : 'unreadable');
    try {
      io.renameSync(pathsOf.lock, target);
    } catch (e) {
      if (e.code === 'ENOENT') return false;
      throw fail('LEDGER_LOCKED', 'cannot set aside the existing lock: ' + (e.code || e.message));
    }

    const movedText = readLockText(io, target);
    const moved = parseLockRecord(movedText);
    // For an unattributable record, identity is its exact text: anything else
    // at the moved name means the file changed hands between the read and the
    // rename, and it is put back rather than discarded.
    const unexpected = held ? (!moved || moved.nonce !== held.nonce) : movedText !== currentText;
    if (unexpected) {
      const restored = restoreMovedLock(io, target, pathsOf.lock);
      const error = fail('LEDGER_LOCKED', 'the lock changed hands while it was being reclaimed'
        + (restored ? '; the other lock was restored' : '; the other lock is at ' + target));
      error.lock = moved || held;
      throw error;
    }

    logRepair(io, pathsOf.repairs, {
      event: opts.forceUnlock ? 'LOCK_FORCED' : 'LOCK_RECLAIMED',
      previous: held || null,
      unreadable: !held,
      previous_raw: held ? null : (movedText === null ? '' : movedText.slice(0, 512)),
      moved_to: target,
    });
    return true;
  };

  for (let attempt = 0; attempt < 4; attempt++) {
    if (create()) {
      return { ledger: pathsOf.ledger, path: pathsOf.lock, nonce: record.nonce, record, events };
    }
    if (!fileExistsAt(io, pathsOf.lock)) continue;

    const rawText = readLockText(io, pathsOf.lock);
    const rawRecord = parseLockRecord(rawText);
    const held = isUsableLockRecord(rawRecord) ? rawRecord : null;

    if (!held) {
      if (!opts.forceUnlock) {
        throw fail('LEDGER_LOCKED', 'the lock at ' + pathsOf.lock
          + ' is unreadable (empty, malformed or incomplete record); it cannot be attributed'
          + ' to a process, so it is never reclaimed automatically; pass forceUnlock to discard it');
      }
      if (rawText === null) continue; // it vanished; try the exclusive create again
      if (reclaim(null, rawText)) events.push({ event: 'LOCK_FORCED', holder: null, unreadable: true });
      continue;
    }

    if (opts.forceUnlock) {
      if (reclaim(held)) events.push({ event: 'LOCK_FORCED', holder: held });
      continue;
    }
    if (isLockStale(held, now(), ttl)) {
      if (reclaim(held)) events.push({ event: 'LOCK_RECLAIMED', holder: held });
      continue;
    }
    const error = fail('LEDGER_LOCKED', 'the ledger is locked by pid '
      + held.pid + ' on ' + held.host + ' since ' + held.created_at
      + '; wait for it to finish or unlock explicitly');
    error.lock = held;
    throw error;
  }
  throw fail('LEDGER_LOCKED', 'could not acquire the lock after reclaiming it');
}

// Restores a lock file this process moved but did not own. A hard link is the
// only restore path, because it fails on an occupied path instead of replacing
// whatever is there. There is deliberately no rename fallback: rename would
// overwrite a lock installed between the check and the call, which is the
// failure this helper exists to avoid. When the link cannot be made, the caller
// reports where the other lock is rather than losing it.
function restoreMovedLock(io, from, to) {
  if (typeof io.linkSync !== 'function') return false;
  try {
    io.linkSync(from, to);
  } catch (_) {
    return false;
  }
  try {
    io.unlinkSync(from);
  } catch (_) { /* the shared path is restored; a duplicate name is harmless */ }
  return true;
}

// Release moves the lock to a private name, checks the record it actually moved,
// and only then deletes it. A writer whose lock was reclaimed therefore cannot
// delete its successor's lock, because the delete never targets the shared path.
function releaseLock(lock, opts) {
  const io = (opts && opts.fs) || fs;
  if (!lock || !lock.path) return { released: false, reason: 'invalid_lock' };
  const movedPath = lock.path + '.release-' + lock.nonce;
  try {
    io.renameSync(lock.path, movedPath);
  } catch (e) {
    if (e.code === 'ENOENT') return { released: false, reason: 'missing' };
    return { released: false, reason: 'unlink_failed', detail: e.code || e.message };
  }

  const moved = readLockFile(io, movedPath);
  if (moved && moved.nonce === lock.nonce) {
    try {
      io.unlinkSync(movedPath);
    } catch (_) { /* the lease is already gone; the leftover file is harmless */ }
    return { released: true, reason: null };
  }

  const restored = restoreMovedLock(io, movedPath, lock.path);
  return { released: false, reason: 'owner_changed', holder: moved, restored };
}

// Fencing: a writer re-checks that the lock still carries its nonce immediately
// before a durable write. A lock that was force-unlocked or reclaimed under a
// live writer makes the next write fail closed instead of racing.
function assertLockOwned(lock, io) {
  const current = readLockFile(io || fs, lock.path);
  if (!current || current.nonce !== lock.nonce) {
    throw fail('LEDGER_LOCK_LOST', 'the lock is no longer held by this writer; no further bytes were written');
  }
  return true;
}

function withLock(ledgerPath, opts, work) {
  const io = (opts && opts.fs) || fs;
  const lock = acquireLock(ledgerPath, opts);
  try {
    return work(lock);
  } finally {
    const released = releaseLock(lock, { fs: io });
    if (!released.released && released.reason === 'owner_changed') {
      try {
        logRepair(io, ledgerPaths(ledgerPath).repairs, {
          event: 'LOCK_OWNER_CHANGED',
          nonce: lock.nonce,
          holder: released.holder || null,
        });
      } catch (_) { /* the incident matters, but it must not mask the append result */ }
    }
  }
}

// --- state cache ----------------------------------------------------------

function writeState(pathsOf, doc, io) {
  const text = JSON.stringify(doc) + '\n';
  // One atomic-write implementation in the project: the keyring helper, called
  // here with an fsync and the caller's filesystem facade.
  Signing.writeAtomic(pathsOf.state, text, { fs: io, fsync: true });
  fsyncDir(pathsOf.dir, io);
}

function readJsonTolerant(io, file) {
  try {
    const buf = io.readFileSync(file);
    return JSON.parse(Buffer.isBuffer(buf) ? buf.toString('utf8') : String(buf));
  } catch (_) {
    return null;
  }
}

// The "an entry tail has already been truncated" fact lives in its own durable
// marker, written and fsynced before the bytes are discarded. The repair log is
// the audit trail of that action, not the guard: a torn line in it must not be
// able to reset the fact and allow a second un-flagged truncation. Only the
// marker's existence matters, never its contents, so an unreadable marker still
// blocks.
function armTornGuard(pathsOf, io, detail) {
  const existing = readJsonTolerant(io, pathsOf.torn);
  const prior = existing && Number.isSafeInteger(existing.truncations) ? existing.truncations : 0;
  const doc = {
    scheme: SCHEME,
    first_seen_at: existing && typeof existing.first_seen_at === 'string' ? existing.first_seen_at : new Date().toISOString(),
    truncations: prior + 1,
    last: detail || null,
  };
  Signing.writeAtomic(pathsOf.torn, JSON.stringify(doc) + '\n', { fs: io, fsync: true });
  fsyncDir(pathsOf.dir, io);
}

// --- reading the log ------------------------------------------------------

// Reads a JSONL file as bytes, so a fragment without its terminating newline is
// distinguishable from a complete record whose text happens to end badly.
function readRecordFile(io, file, parse) {
  let buf;
  try {
    buf = io.readFileSync(file);
  } catch (e) {
    if (e.code === 'ENOENT') {
      return { records: [], fragment: null, fragment_buf: null, fragment_bytes: 0, complete_bytes: 0, exists: false };
    }
    throw fail('LEDGER_IO', 'cannot read ' + file + ': ' + (e.code || e.message));
  }
  if (!Buffer.isBuffer(buf)) buf = Buffer.from(String(buf), 'utf8');
  if (buf.length === 0) {
    return { records: [], fragment: null, fragment_buf: null, fragment_bytes: 0, complete_bytes: 0, exists: true };
  }
  const lastNewline = buf.lastIndexOf(0x0a);
  const completeEnd = lastNewline === -1 ? 0 : lastNewline + 1;
  const fragmentBuf = buf.slice(completeEnd);
  const text = buf.slice(0, completeEnd).toString('utf8');
  const lines = text.length ? text.slice(0, -1).split('\n') : [];
  return {
    records: lines.map(parse),
    fragment: fragmentBuf.length ? fragmentBuf.toString('utf8') : null,
    fragment_buf: fragmentBuf.length ? fragmentBuf : null,
    fragment_bytes: fragmentBuf.length,
    complete_bytes: completeEnd,
    exists: true,
  };
}

function assertSignatureShape(record, what) {
  const signature = record.signature;
  if (!signature || typeof signature !== 'object' || Array.isArray(signature)) {
    throw fail('LEDGER_CORRUPT', what + ' is not signed');
  }
  if (signature.algorithm !== 'ed25519') {
    throw fail('LEDGER_CORRUPT', what + ' uses an unsupported signature algorithm: ' + String(signature.algorithm));
  }
  if (!Signing.KEY_ID_RE.test(signature.key_id || '')) {
    throw fail('LEDGER_CORRUPT', what + ' has a malformed signature key id');
  }
  if (typeof signature.value !== 'string' || signature.value.length === 0) {
    throw fail('LEDGER_CORRUPT', what + ' has an empty signature value');
  }
}

function parseEntryLine(line, index) {
  const position = index + 1;
  if (line.length === 0) throw fail('LEDGER_CORRUPT', 'blank line at entry ' + position);
  if (line.indexOf('\u0000') !== -1) throw fail('LEDGER_CORRUPT', 'NUL byte inside entry ' + position);
  let record;
  try {
    record = JSON.parse(line);
  } catch (e) {
    throw fail('LEDGER_CORRUPT', 'unparseable entry ' + position + ': ' + e.message);
  }
  assertScheme(record, 'entry ' + position);
  assertSignatureShape(record, 'entry ' + position);
  if (record.entry_hash !== entryHash(record)) {
    throw fail('LEDGER_CORRUPT', 'entry ' + position + ' hash does not match its body');
  }
  // Attribution must be as strong as the signature: a writer may not claim
  // another writer's key id in a body it signs with its own key.
  if (record.writer_key_id !== record.signature.key_id) {
    throw fail('LEDGER_CORRUPT', 'entry ' + position + ' claims writer ' + record.writer_key_id
      + ' but is signed by ' + record.signature.key_id);
  }
  return record;
}

function parseCheckpointLine(line, index) {
  const position = index + 1;
  if (line.length === 0) throw fail('LEDGER_CORRUPT', 'blank line at checkpoint ' + position);
  if (line.indexOf('\u0000') !== -1) throw fail('LEDGER_CORRUPT', 'NUL byte inside checkpoint ' + position);
  let record;
  try {
    record = JSON.parse(line);
  } catch (e) {
    throw fail('LEDGER_CORRUPT', 'unparseable checkpoint ' + position + ': ' + e.message);
  }
  assertScheme(record, 'checkpoint ' + position);
  assertSignatureShape(record, 'checkpoint ' + position);
  const recomputed = checkpointHash(record);
  if (record.checkpoint_hash !== recomputed) {
    throw fail('LEDGER_CORRUPT', 'checkpoint ' + position + ' hash does not match its body');
  }
  return record;
}

function verifyEntryChain(entries, ledgerId) {
  const seen = new Set();
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    if (entry.ledger_id !== ledgerId) {
      throw fail('LEDGER_UNKNOWN', 'entry ' + (i + 1) + ' belongs to ledger ' + entry.ledger_id + ', not ' + ledgerId);
    }
    if (entry.seq !== i + 1) {
      throw fail('LEDGER_CORRUPT', 'entry ' + (i + 1) + ' carries seq ' + entry.seq);
    }
    const expectedPrev = i === 0 ? GENESIS : entries[i - 1].entry_hash;
    if (entry.prev_entry_hash !== expectedPrev) {
      throw fail('LEDGER_CORRUPT', 'entry ' + (i + 1) + ' does not link to its predecessor');
    }
    if (seen.has(entry.payload_digest)) {
      throw fail('LEDGER_CORRUPT', 'duplicate payload digest at entry ' + (i + 1));
    }
    seen.add(entry.payload_digest);
  }
  return true;
}

function verifyCheckpointChain(checkpoints, ledgerId) {
  for (let i = 0; i < checkpoints.length; i++) {
    const checkpoint = checkpoints[i];
    if (i === 0) {
      if (checkpoint.ledger_id !== GENESIS || checkpoint.tree_size !== 0 || checkpoint.prev_checkpoint_hash !== GENESIS) {
        throw fail('LEDGER_CORRUPT', 'the first checkpoint is not a genesis checkpoint');
      }
      continue;
    }
    if (checkpoint.ledger_id !== ledgerId) {
      throw fail('LEDGER_UNKNOWN', 'checkpoint ' + (i + 1) + ' belongs to another ledger');
    }
    if (checkpoint.prev_checkpoint_hash !== checkpoints[i - 1].checkpoint_hash) {
      throw fail('LEDGER_FORK', 'checkpoint ' + (i + 1) + ' does not extend the retained head');
    }
    if (checkpoint.tree_size <= checkpoints[i - 1].tree_size) {
      throw fail('LEDGER_FORK', checkpoint.tree_size === checkpoints[i - 1].tree_size
        ? 'two checkpoints at tree size ' + checkpoint.tree_size
        : 'tree size decreases at checkpoint ' + (i + 1));
    }
    if (checkpoint.policy_hash !== checkpoints[0].policy_hash) {
      throw fail('LEDGER_CORRUPT', 'checkpoint ' + (i + 1) + ' carries a different policy hash than genesis');
    }
  }
  return true;
}

// Ledger-shaped adapter over the Merkle frontier. The tree rules live in
// engine/merkle.cjs; this only validates a digest, converts hex, and yields
// each checkpoint's prefix root in order so an early mismatch is reported
// before a later malformed digest is reached. Kept as a store export because
// engine/test/ledger-roots.test.cjs imports it here; the inspection itself
// uses the frontier directly and keeps it for append and fsck.
function* prefixRoots(digests, sizes) {
  const frontier = Merkle.createFrontier();
  for (const size of sizes) {
    if (size > digests.length) {
      throw fail('LEDGER_TRUNCATED', 'tree size ' + size + ' exceeds the ' + digests.length + ' recorded entries');
    }
    while (frontier.size < size) {
      frontier.push(Buffer.from(requireHex(digests[frontier.size], 'payload_digest'), 'hex'));
    }
    yield [size, frontier.root().toString('hex')];
  }
}

function readState(io, file) {
  let doc;
  try {
    const buf = io.readFileSync(file);
    doc = JSON.parse(Buffer.isBuffer(buf) ? buf.toString('utf8') : String(buf));
  } catch (_) {
    return null;
  }
  if (!doc || doc.scheme !== SCHEME) return null;
  if (!Number.isSafeInteger(doc.seq) || doc.seq < 0) return null;
  return doc;
}

// --- one read model -------------------------------------------------------

// The single walk. Every consumer in the ledger uses this instead of reading
// the log itself: append and verify refuse on the first finding, fsck decides
// which findings it may repair. Findings are reported, never thrown, precisely
// because those decisions differ.
//
// The walk is ordered so that each finding is only computed on bytes that have
// survived the checks before it: both chains first, then the counts, then the
// prefix roots. It does not stop at a finding unless the bytes needed for the
// next check are unusable.
function inspectLedger(pathsOf, io) {
  const report = {
    paths: pathsOf,
    checkpoints: [],
    entries: [],
    genesis: null,
    ledgerId: null,
    head: null,
    digests: [],
    frontier: null,
    checkpointRead: null,
    entryRead: null,
    findings: {
      checkpoints: null,
      not_initialized: null,
      checkpoint_tail: null,
      checkpoint_chain: null,
      entries: null,
      entry_tail: null,
      entry_chain: null,
      short: null,
      ahead: null,
      roots: null,
    },
  };

  try {
    report.checkpointRead = readRecordFile(io, pathsOf.checkpoints, parseCheckpointLine);
  } catch (e) {
    report.findings.checkpoints = findingOf(e);
    return report;
  }
  report.checkpoints = report.checkpointRead.records;

  if (report.checkpoints.length === 0) {
    report.findings.not_initialized = {
      code: 'LEDGER_NOT_INITIALIZED',
      message: 'no checkpoint log at ' + pathsOf.checkpoints,
    };
    return report;
  }

  // An unterminated line is a crash artifact, not a record. It is reported for
  // whoever may repair it; the complete records before it are still inspected.
  if (report.checkpointRead.fragment !== null) {
    report.findings.checkpoint_tail = {
      code: 'LEDGER_TORN_CHECKPOINT_TAIL',
      message: 'the final checkpoint line is unterminated (' + report.checkpointRead.fragment_bytes + ' bytes)',
      bytes: report.checkpointRead.fragment_bytes,
    };
  }

  const genesis = report.checkpoints[0];
  if (genesis.ledger_id !== GENESIS || genesis.tree_size !== 0) {
    report.findings.checkpoint_chain = {
      code: 'LEDGER_CORRUPT',
      message: 'the first checkpoint is not a genesis checkpoint',
    };
    return report;
  }
  report.genesis = genesis;
  report.ledgerId = genesis.checkpoint_hash;

  try {
    verifyCheckpointChain(report.checkpoints, report.ledgerId);
  } catch (e) {
    report.findings.checkpoint_chain = findingOf(e);
    return report;
  }
  report.head = report.checkpoints[report.checkpoints.length - 1];

  try {
    report.entryRead = readRecordFile(io, pathsOf.entries, parseEntryLine);
  } catch (e) {
    report.findings.entries = findingOf(e);
    return report;
  }
  report.entries = report.entryRead.records;
  report.digests = report.entries.map(entry => entry.payload_digest);

  if (report.entryRead.fragment !== null) {
    report.findings.entry_tail = {
      code: 'LEDGER_TORN_ENTRY_TAIL',
      message: 'the entry log ends in an unterminated line (' + report.entryRead.fragment_bytes + ' bytes)',
      bytes: report.entryRead.fragment_bytes,
    };
  }

  try {
    verifyEntryChain(report.entries, report.ledgerId);
  } catch (e) {
    report.findings.entry_chain = findingOf(e);
    return report;
  }

  if (report.entries.length < report.head.tree_size) {
    report.findings.short = {
      code: 'LEDGER_TRUNCATED',
      message: 'the entry log holds ' + report.entries.length + ' entries but the head covers ' + report.head.tree_size,
    };
    return report;
  }
  if (report.entries.length > report.head.tree_size) {
    report.findings.ahead = {
      code: 'LEDGER_CHECKPOINT_MISSING',
      message: 'the entry log is ' + (report.entries.length - report.head.tree_size)
        + ' ahead of the checkpoint log; run fsck',
    };
  }

  // Roots are checked even when the entry log is ahead of the head: fsck has to
  // know the retained checkpoints match before it may seal new ones, and the
  // refusing wrapper checks its count findings first, as it always has.
  //
  // One frontier carries the leaves across the checkpoints. Each root is
  // compared before the next site is hashed, so an early mismatch is reported
  // before a later malformed digest is reached. The frontier is kept at the
  // verified head on the report; append and fsck continue from that state
  // instead of rebuilding the tree.
  try {
    const frontier = Merkle.createFrontier();
    let cursor = 0;
    for (const checkpoint of report.checkpoints) {
      if (checkpoint.tree_size > report.digests.length) {
        throw fail('LEDGER_TRUNCATED', 'tree size ' + checkpoint.tree_size
          + ' exceeds the ' + report.digests.length + ' recorded entries');
      }
      while (cursor < checkpoint.tree_size) {
        frontier.push(Buffer.from(requireHex(report.digests[cursor], 'payload_digest'), 'hex'));
        cursor += 1;
      }
      if (frontier.root().toString('hex') !== checkpoint.root_hash) {
        report.findings.roots = {
          code: 'LEDGER_ENTRY_MISMATCH',
          message: 'checkpoint at tree size ' + checkpoint.tree_size + ' does not match the entry log',
          tree_size: checkpoint.tree_size,
        };
        break;
      }
    }
    if (!report.findings.roots) report.frontier = frontier;
  } catch (e) {
    report.findings.roots = findingOf(e);
  }

  return report;
}

function findingOf(error) {
  return { code: (error && error.code) || 'LEDGER_CORRUPT', message: error && error.message };
}

// The refusal order is a contract of its own: append and verify name the first
// structural problem in this sequence, and tests pin the code they get.
const REFUSAL_ORDER = [
  'checkpoints', 'not_initialized', 'checkpoint_tail', 'checkpoint_chain',
  'entries', 'entry_tail', 'entry_chain', 'short', 'ahead', 'roots',
];

// Damage that fsck repairs is refused here as plain corruption: a writer or a
// verifier may not act on a log with an unterminated tail, whatever the repair
// path calls it.
const REFUSALS = {
  checkpoint_tail: { code: 'LEDGER_CORRUPT', message: 'the checkpoint log ends in an unterminated line; run fsck' },
  entry_tail: { code: 'LEDGER_CORRUPT', message: 'the entry log ends in an unterminated line; run fsck' },
};

function firstFinding(report, order) {
  for (const key of order) {
    if (report.findings[key]) return Object.assign({ key }, report.findings[key]);
  }
  return null;
}

// Strict read used before extending the log: anything a verifier would reject
// is also refused at write time, so a writer cannot build on a broken prefix.
function readLedger(pathsOf, io) {
  const report = inspectLedger(pathsOf, io);
  const first = firstFinding(report, REFUSAL_ORDER);
  if (first) {
    const refusal = REFUSALS[first.key] || first;
    throw fail(refusal.code, refusal.message);
  }
  return report;
}

// --- init -----------------------------------------------------------------

function initLedger(ledgerPath, opts) {
  opts = opts || {};
  const io = opts.fs || fs;
  const pathsOf = ledgerPaths(ledgerPath);
  const now = clockOf(opts);
  const policy = policyBody(opts.policy);
  const signer = normalizeSigner(opts.signer);
  if (policy.writer_keys.indexOf(signer.key_id) === -1) {
    throw fail('LEDGER_POLICY_MISMATCH', 'the genesis policy does not list the initializing writer key: ' + signer.key_id);
  }

  return withLock(pathsOf.ledger, opts, (lock) => {
    if (fileSize(io, pathsOf.checkpoints) > 0 || fileSize(io, pathsOf.entries) > 0) {
      throw fail('LEDGER_EXISTS', 'a ledger already exists at ' + pathsOf.ledger);
    }
    assertLockOwned(lock, io);
    const createdAt = now().toISOString();
    // The policy body travels beside the ledger because genesis can commit only
    // its hash. It is written before the genesis line, so a ledger is never
    // committed without the body its policy_hash names.
    Policy.writePolicy(pathsOf, policy, io);
    fsyncDir(pathsOf.dir, io);
    const genesis = signCheckpoint(buildGenesis({
      created_at: createdAt,
      policy_hash: policyHash(policy),
    }), signer);

    appendLineDurable(pathsOf.checkpoints, JSON.stringify(genesis) + '\n', io);
    fsyncDir(pathsOf.dir, io);

    if (fileSize(io, pathsOf.entries) === 0) {
      const fd = io.openSync(pathsOf.entries, 'a');
      io.closeSync(fd);
      fsyncDir(pathsOf.dir, io);
    }

    const state = {
      scheme: SCHEME,
      ledger_id: genesis.checkpoint_hash,
      seq: 0,
      head_hash: GENESIS,
      tree_size: 0,
      checkpoint_hash: genesis.checkpoint_hash,
      root_hash: genesis.root_hash,
      updated_at: createdAt,
    };
    writeState(pathsOf, state, io);

    return { created: true, ledger_id: genesis.checkpoint_hash, genesis, state, paths: pathsOf };
  });
}

// --- append ---------------------------------------------------------------

// The mechanical half of a write, shared by appends and by the commitment entry
// a revocation seals. Authority is the caller's business: both paths authorize
// the signer at the exact position the entry will occupy before calling this.
// The order is entry, checkpoint, state, so the entry log is never behind the
// artifacts derived from it.
function appendRecordLocked(lock, pathsOf, read, io, signer, fields) {
  const seq = read.entries.length + 1;
  const prevEntryHash = read.entries.length ? read.entries[read.entries.length - 1].entry_hash : GENESIS;
  // The reserved id is minted by the revocation path only. A caller-supplied
  // value can never reach this point: append refuses it before the lock, and
  // the explicit flag is what distinguishes the seal from every other write.
  if (fields.receipt_id && fields.receipt_id.indexOf(REVOCATION_COMMITMENT_PREFIX) === 0
      && fields.commitment !== true) {
    throw fail('LEDGER_RECEIPT_ID_RESERVED',
      'receipt ids beginning ' + REVOCATION_COMMITMENT_PREFIX + ' are reserved for revocation commitments');
  }

  const entryBodyDoc = entryBody({
    ledger_id: read.ledgerId,
    seq,
    payload_digest: fields.payload_digest,
    receipt_id: fields.receipt_id === undefined ? null : fields.receipt_id,
    recorded_at: fields.recorded_at,
    writer_key_id: signer.key_id,
    prev_entry_hash: prevEntryHash,
  });
  const entry = signEntry(Object.assign({}, entryBodyDoc, { entry_hash: entryHash(entryBodyDoc) }), signer);

  assertLockOwned(lock, io);
  appendLineDurable(pathsOf.entries, JSON.stringify(entry) + '\n', io);
  fsyncDir(pathsOf.dir, io);

  // Continue the frontier the inspection just validated: the new leaf's root
  // and inclusion path come from that state, not from two more tree builds.
  const leaf = read.frontier.append(Buffer.from(fields.payload_digest, 'hex'));
  const root = leaf.root.toString('hex');
  const checkpointDoc = buildCheckpoint({
    ledger_id: read.ledgerId,
    tree_size: seq,
    root_hash: root,
    created_at: fields.checkpoint_at,
    prev_checkpoint_hash: read.head.checkpoint_hash,
    policy_hash: read.genesis.policy_hash,
  });
  const checkpoint = signCheckpoint(checkpointDoc, signer);

  assertLockOwned(lock, io);
  try {
    appendLineDurable(pathsOf.checkpoints, JSON.stringify(checkpoint) + '\n', io);
  } catch (e) {
    const error = fail('LEDGER_CHECKPOINT_WRITE_FAILED', 'entry ' + entry.entry_hash
      + ' is durable but its checkpoint was not written (' + (e.code || e.message)
      + '); run fsck to re-seal the tail');
    error.entry = entry;
    throw error;
  }
  fsyncDir(pathsOf.dir, io);

  const state = {
    scheme: SCHEME,
    ledger_id: read.ledgerId,
    seq,
    head_hash: entry.entry_hash,
    tree_size: seq,
    checkpoint_hash: checkpoint.checkpoint_hash,
    root_hash: root,
    updated_at: checkpoint.created_at,
  };
  let stateWritten = true;
  assertLockOwned(lock, io);
  try {
    writeState(pathsOf, state, io);
  } catch (_) {
    // The state cache is a cache. A failed rename leaves the log correct and
    // the next append or fsck recomputes from the log; it is not corruption.
    stateWritten = false;
  }

  const inclusionPath = leaf.path.map(h => h.toString('hex'));
  const block = {
    scheme: SCHEME,
    ledger_id: read.ledgerId,
    seq,
    checkpoint: { tree_size: seq, root_hash: root },
    path: inclusionPath,
  };

  if (typeof fields.writeReceipt === 'function') {
    assertLockOwned(lock, io);
    try {
      fields.writeReceipt(block);
    } catch (e) {
      throw fail('LEDGER_RECEIPT_WRITE_FAILED', 'entry and checkpoint are durable; the receipt was not updated (' + (e.code || e.message) + ')');
    }
  }

  return { entry, checkpoint, block, state, state_written: stateWritten, paths: pathsOf };
}

// Appends one receipt digest, then a checkpoint covering it, then the state
// cache, in that order, under the lock. Ordering is what makes recovery
// decidable: the entry log is never behind the artifacts derived from it.
function append(ledgerPath, opts) {
  opts = opts || {};
  const io = opts.fs || fs;
  const pathsOf = ledgerPaths(ledgerPath);
  const now = clockOf(opts);
  const signer = normalizeSigner(opts.signer);
  // A keyring-backed signer names the keyring its status is read from. Status
  // is re-read here, not carried on the signer, so a revocation made after the
  // signer was built still refuses the append.
  const keyring = opts.keyring || (opts.signer && opts.signer.keyring) || null;
  const payloadDigest = requireHex(opts.payload_digest, 'payload_digest');

  // A receipt cannot name itself a revocation commitment. The prefix is outside
  // the receipt-id vocabulary and the store alone mints it, so no caller value
  // can turn an ordinary append into a ledger revocation claim. Refusing here,
  // before the lock and before any byte, is the whole guarantee: the entry that
  // would later be read as a commitment is never written.
  if (typeof opts.receipt_id === 'string'
      && opts.receipt_id.indexOf(REVOCATION_COMMITMENT_PREFIX) === 0) {
    throw fail('LEDGER_RECEIPT_ID_RESERVED',
      'receipt ids beginning ' + REVOCATION_COMMITMENT_PREFIX
      + ' are reserved for revocation commitments and cannot be appended as receipts');
  }

  return withLock(pathsOf.ledger, opts, (lock) => {
    const read = readLedger(pathsOf, io);
    const duplicate = read.entries.find(e => e.payload_digest === payloadDigest);
    if (duplicate) {
      throw fail('LEDGER_DUPLICATE', 'payload digest is already recorded at seq ' + duplicate.seq);
    }

    // Authority is decided before any byte is written: the signer must be a
    // writer under the policy genesis committed to, and the policy body must
    // still hash to that commitment. A refusal leaves the log untouched.
    const recordedAt = now().toISOString();
    const authorized = Policy.authorizeRecord(pathsOf, read, io,
      { key: signer.key_id, at: recordedAt, seq: read.entries.length + 1 },
      {
        policy: opts.policy,
        keyring,
        trustedKeys: opts.trustedKeys,
        revocations: opts.revocations,
        requireStatus: true,
      });
    if (!authorized.ok) throw fail(authorized.code, authorized.message);

    return appendRecordLocked(lock, pathsOf, read, io, signer, {
      payload_digest: payloadDigest,
      receipt_id: opts.receipt_id === undefined ? null : opts.receipt_id,
      recorded_at: recordedAt,
      checkpoint_at: now().toISOString(),
      writeReceipt: opts.writeReceipt,
    });
  });
}

// --- writer revocation ----------------------------------------------------

// Records one admin-signed revocation under the lock, in two steps that make it
// ledger evidence rather than a sidecar claim:
//
//   1. seal a commitment entry (payload digest = digest of the signed record)
//      through the normal entry/checkpoint path, signed by an active writer;
//   2. append the record itself to `<ledger>.revocations.jsonl`.
//
// The record binds the head it was issued against (`head_tree_size`,
// `head_checkpoint_hash`), so `revoked_at` cannot reach behind records that
// already exist, and the commitment means deleting or truncating the sidecar
// cannot restore authority: verification finds the entry and fails closed.
function revokeWriter(ledgerPath, opts) {
  opts = opts || {};
  const io = opts.fs || fs;
  const pathsOf = ledgerPaths(ledgerPath);
  const now = clockOf(opts);
  const signer = normalizeSigner(opts.signer);
  const keyId = requireKeyId(opts.key_id, 'key_id');
  const keyring = opts.keyring || (opts.signer && opts.signer.keyring) || null;

  return withLock(pathsOf.ledger, opts, (lock) => {
    const read = readLedger(pathsOf, io);
    const resolved = Policy.resolvePolicy(pathsOf, read.genesis, io, opts);
    const recordedAt = now().toISOString();

    // A revocation is a write and an admin act. Both halves are checked before
    // any byte is appended.
    const authorized = Policy.authorizeAdmin(resolved.policy, signer.key_id, {
      at: recordedAt,
      records: Policy.keyRecordsOf(keyring ? { keyring } : null),
      requireStatus: true,
    });
    if (!authorized.ok) throw fail(authorized.code, authorized.message);

    if (resolved.policy.writer_keys.indexOf(keyId) === -1) {
      throw fail('LEDGER_REVOCATION_UNKNOWN_WRITER',
        'key is not a writer under the policy committed by genesis: ' + keyId);
    }

    // An existing log is verified before it is extended, and a second
    // revocation for one key is refused rather than merged: two effective dates
    // for one key would make the boundary depend on line order.
    const existing = Policy.readRevocations(pathsOf, read, io, {
      policy: resolved.policy,
      keyring,
      trustedKeys: opts.trustedKeys,
      revocations: opts.revocations,
    });
    if (existing.has(keyId)) {
      throw fail('LEDGER_REVOCATION_DUPLICATE',
        'writer key is already revoked at ' + existing.get(keyId).revoked_at + ': ' + keyId);
    }

    // The commitment is sealed by the admin who signed the revocation when
    // that same admin seals it, otherwise by the named writer. The admin seal
    // is the one write an admin may make: it carries a revocation record and
    // nothing else, so it grants neither the admin nor the revoked key
    // ordinary append authority. A different named writer must actually be a
    // writer; the admission check refuses it otherwise, and the read path lets
    // it skip the position rule only when the record revokes that writer.
    const sealSigner = opts.writerSigner ? normalizeSigner(opts.writerSigner) : signer;
    const adminSeal = sealSigner.key_id === signer.key_id;
    const sealKeyring = adminSeal ? keyring
      : (opts.writerKeyring || (opts.writerSigner && opts.writerSigner.keyring) || keyring);

    // A revocation may end authority from now on, never at or before a record
    // the ledger already holds. Both clocks are considered: the head
    // checkpoint's created_at and every entry's own recorded_at. The default
    // effective time is strictly after the sealing entry is recorded, so the
    // record that carries the revocation is itself valid at a strict boundary.
    const latest = read.entries.reduce(
      (max, entry) => Math.max(max, Date.parse(entry.recorded_at)), Date.parse(read.head.created_at));
    const revokedAt = opts.revoked_at === undefined
      ? new Date(Math.max(Date.parse(recordedAt) + 1, latest + 1)).toISOString()
      : opts.revoked_at;

    const body = revocationBody({
      ledger_id: read.ledgerId,
      key_id: keyId,
      revoked_at: revokedAt,
      recorded_at: recordedAt,
      head_tree_size: read.head.tree_size,
      head_checkpoint_hash: read.head.checkpoint_hash,
      reason: opts.reason === undefined ? null : opts.reason,
    });

    if (Date.parse(body.revoked_at) <= latest) {
      throw fail('LEDGER_REVOCATION_BACKDATED',
        'revoked_at ' + body.revoked_at + ' is at or before records the ledger already holds ('
        + new Date(latest).toISOString() + '); a revocation cannot invalidate written entries');
    }
    // The sealing entry and its checkpoint are written at `recorded_at`. If the
    // boundary were at or before that instant, the record carrying the
    // revocation would be the first thing it invalidated.
    if (Date.parse(body.revoked_at) <= Date.parse(body.recorded_at)) {
      throw fail('LEDGER_REVOCATION_BACKDATED',
        'revoked_at ' + body.revoked_at + ' does not postdate recorded_at '
        + body.recorded_at + '; the boundary must be after the record that seals it');
    }

    const record = signRevocation(body, signer);
    const digest = revocationCommitmentDigest(record);

    const sealAuth = adminSeal
      ? Policy.authorizeAdmin(resolved.policy, sealSigner.key_id, {
        at: recordedAt,
        records: Policy.keyRecordsOf(sealKeyring ? { keyring: sealKeyring } : null),
        requireStatus: true,
      })
      : Policy.authorizeRecord(pathsOf, read, io,
        { key: sealSigner.key_id, at: recordedAt, seq: read.entries.length + 1 },
        {
          policy: opts.policy,
          keyring: sealKeyring,
          trustedKeys: opts.trustedKeys,
          requireStatus: true,
          revocations: opts.revocations,
        });
    if (!sealAuth.ok) throw fail(sealAuth.code, sealAuth.message);

    const commitment = appendRecordLocked(lock, pathsOf, read, io, sealSigner, {
      payload_digest: digest,
      receipt_id: REVOCATION_COMMITMENT_PREFIX + keyId,
      recorded_at: recordedAt,
      checkpoint_at: recordedAt,
      commitment: true,
    });

    try {
      assertLockOwned(lock, io);
      appendLineDurable(pathsOf.revocations, JSON.stringify(record) + '\n', io);
      fsyncDir(pathsOf.dir, io);
    } catch (e) {
      const error = fail('LEDGER_REVOCATION_RECORD_WRITE_FAILED',
        'entry ' + commitment.entry.seq + ' commits to the revocation, but the record was not written ('
        + (e.code || e.message) + '); restore it from this error before verifying');
      error.record = record;
      error.entry = commitment.entry;
      throw error;
    }

    return {
      record,
      revoked_at: body.revoked_at,
      commitment: commitment.entry,
      paths: pathsOf,
    };
  });
}

// Restores `<ledger>.revocations.jsonl` from an operator-supplied file. The file
// is not trusted: every record is authenticated and matched to the ledger's
// commitment entries before a byte is written, so restoration can only
// reproduce what the ledger already committed to. Adding, removing or altering
// a record relative to those commitments is refused.
//
// The whole repair runs under one lock. `opts.verify(phase)` is the facade's
// whole-ledger check ("pre" before the write, "post" after it), called here
// rather than by the caller so no writer can append between the check and the
// write, or between the write and the rollback. The store does not know what
// the check means; it only knows that a throw means "undo the write", which
// keeps the authority verdict in the layer that can reach it.
function restoreRevocations(ledgerPath, opts) {
  opts = opts || {};
  const io = opts.fs || fs;
  const pathsOf = ledgerPaths(ledgerPath);
  const file = path.resolve(requireText(opts.file, 'revocations file'));
  const check = typeof opts.verify === 'function' ? opts.verify : null;

  return withLock(pathsOf.ledger, opts, (lock) => {
    const read = readLedger(pathsOf, io);
    const resolved = Policy.resolvePolicy(pathsOf, read.genesis, io, opts);

    let buf;
    try {
      buf = io.readFileSync(file);
    } catch (e) {
      // The supplied backup is a caller input. A file that cannot be read is an
      // I/O failure, never the verdict that the ledger lost a committed record.
      throw fail('LEDGER_IO',
        'cannot read the supplied revocation file ' + file + ': ' + (e.code || e.message));
    }
    const text = Buffer.isBuffer(buf) ? buf.toString('utf8') : String(buf);
    if (!text.trim().length) {
      throw fail('LEDGER_REVOCATION_MALFORMED',
        'the supplied revocation file holds no records: ' + file);
    }

    // The same read used by verification: record signature, admin membership,
    // status at recorded_at, bound head, boundary, duplicate, and the exact
    // commitment digest. Nothing here can mint a record the ledger did not
    // already commit to.
    const records = Policy.readRevocations(pathsOf, read, io, {
      policy: resolved.policy,
      keyring: opts.keyring,
      trustedKeys: opts.trustedKeys,
      revocations: file,
    });

    // The authority verdict runs while this writer holds the lock. A failure
    // here writes nothing, so there is no rollback to make.
    if (check) check('pre');

    // Read the rollback copy under the same lock. An existing sidecar that
    // cannot be read is refused rather than overwritten without a way back.
    let previous = null;
    if (check) {
      try {
        previous = io.readFileSync(pathsOf.revocations);
      } catch (e) {
        if (e.code !== 'ENOENT') {
          throw fail('LEDGER_IO',
            'cannot read the existing revocation file ' + pathsOf.revocations
            + '; refusing to overwrite it without a rollback copy: ' + (e.code || e.message));
        }
      }
    }

    assertLockOwned(lock, io);
    Signing.writeAtomic(pathsOf.revocations, text, { fs: io, fsync: true });
    fsyncDir(pathsOf.dir, io);

    if (check) {
      try {
        check('post');
      } catch (e) {
        // Put the previous bytes back while the lock is still held. If the lock
        // changed hands or the rollback itself fails, say so in the same error
        // instead of reporting a clean refusal.
        try {
          assertLockOwned(lock, io);
          if (previous === null) io.unlinkSync(pathsOf.revocations);
          else Signing.writeAtomic(pathsOf.revocations, previous, { fs: io, fsync: true });
          fsyncDir(pathsOf.dir, io);
        } catch (rollback) {
          throw fail(e.code || 'LEDGER_IO', e.message
            + '; the previous revocation file could not be restored ('
            + (rollback.code || rollback.message) + ')');
        }
        throw e;
      }
    }

    return { restored: records.size, path: pathsOf.revocations, source: file };
  });
}

module.exports = {
  // Public operations, re-exported by engine/ledger.cjs.
  ledgerPaths,
  acquireLock,
  releaseLock,
  initLedger,
  append,
  revokeWriter,
  restoreRevocations,
  readRepairEvents,
  // Shared with the other layers. Not part of the public surface: recovery uses
  // the lock, the durable append and the root helper; verification uses the
  // read model. They are exported here because they are this layer's job and
  // duplicating them above would be the drift the split exists to prevent.
  inspectLedger,
  prefixRoots,
  readLedger,
  readState,
  writeState,
  armTornGuard,
  fileExistsAt,
  truncateTo,
  logRepair,
  appendLineDurable,
  fsyncDir,
  withLock,
  assertLockOwned,
};
