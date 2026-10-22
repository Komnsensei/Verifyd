'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { canonicalJSON } = require('../engine/canonicalize.cjs');

const RECORD_VERSION = 1;
const FILE_RE = /^events-(\d{6})\.jsonl$/;
const TAIL_WINDOW = 65536;

function sha256Hex(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

function listFiles(dir) {
  let names;
  try {
    names = fs.readdirSync(dir);
  } catch (e) {
    if (e.code === 'ENOENT') return [];
    throw e;
  }
  return names
    .filter(n => FILE_RE.test(n))
    .map(n => ({ name: n, index: Number(FILE_RE.exec(n)[1]) }))
    .sort((a, b) => a.index - b.index);
}

function readFirstRecord(file) {
  const fd = fs.openSync(file, 'r');
  let buf;
  try {
    buf = Buffer.alloc(Math.min(TAIL_WINDOW, fs.statSync(file).size));
    fs.readSync(fd, buf, 0, buf.length, 0);
  } finally {
    fs.closeSync(fd);
  }
  for (const line of buf.toString('utf8').split('\n')) {
    if (!line) continue;
    try {
      return JSON.parse(line);
    } catch (e) {
      return null;
    }
  }
  return null;
}

function readTailRecord(file) {
  const st = fs.statSync(file);
  if (st.size === 0) return null;
  const start = Math.max(0, st.size - TAIL_WINDOW);
  const fd = fs.openSync(file, 'r');
  let buf;
  try {
    buf = Buffer.alloc(st.size - start);
    fs.readSync(fd, buf, 0, buf.length, start);
  } finally {
    fs.closeSync(fd);
  }
  const text = buf.toString('utf8');
  const lines = text.split('\n').filter(Boolean);
  for (let i = lines.length - 1; i >= 0; i--) {
    try {
      return JSON.parse(lines[i]);
    } catch (e) {
      // A torn final line is possible after a crash; keep looking backwards.
    }
  }
  return null;
}

// Append-only, hash-chained JSONL evidence store.
//
// Every record carries prev/hash, so edits, reordering and truncation of the
// middle are detectable without a database. Chain continuity survives rotation
// because the head is recomputed by reading the last valid record on open.
class EventStore {
  constructor(opts) {
    opts = opts || {};
    this.dir = opts.dir;
    this.maxBytes = opts.maxBytes || 8388608;
    this.maxFiles = opts.maxFiles || 8;
    this.retentionDays = opts.retentionDays || 30;
    this.fsync = Boolean(opts.fsync);
    this.files = [];
    this.currentIndex = 1;
    this.currentFile = null;
    this.currentBytes = 0;
    this.seq = 0;
    this.head = 'GENESIS';
    this.fd = null;
    this.recordsWritten = 0;
    this.bytesWritten = 0;
    this.lastWriteError = null;
    this.opened = false;
  }

  fileFor(index) {
    return path.join(this.dir, 'events-' + String(index).padStart(6, '0') + '.jsonl');
  }

  open() {
    fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    this.files = listFiles(this.dir);
    if (this.files.length === 0) {
      this.currentIndex = 1;
      this.currentFile = this.fileFor(1);
      fs.closeSync(fs.openSync(this.currentFile, 'a', 0o600));
    } else {
      const last = this.files[this.files.length - 1];
      this.currentIndex = last.index;
      this.currentFile = path.join(this.dir, last.name);
      const rec = readTailRecord(this.currentFile);
      if (rec && typeof rec.seq === 'number' && typeof rec.hash === 'string') {
        this.seq = rec.seq;
        this.head = rec.hash;
      }
    }
    try {
      fs.chmodSync(this.currentFile, 0o600);
    } catch (e) { /* best effort on platforms without POSIX modes */ }
    this.currentBytes = fs.statSync(this.currentFile).size;
    this.fd = fs.openSync(this.currentFile, 'a', 0o600);
    this.opened = true;
    return this;
  }

  rotate() {
    if (this.fd !== null) {
      fs.closeSync(this.fd);
      this.fd = null;
    }
    this.currentIndex += 1;
    this.currentFile = this.fileFor(this.currentIndex);
    this.fd = fs.openSync(this.currentFile, 'a', 0o600);
    try {
      fs.chmodSync(this.currentFile, 0o600);
    } catch (e) { /* best effort */ }
    this.currentBytes = 0;
    this.files = listFiles(this.dir);
    this.prune();
    return this.currentFile;
  }

  append(type, payload, at) {
    if (!this.opened) throw new Error('store not open');
    const body = {
      v: RECORD_VERSION,
      seq: this.seq + 1,
      at: at || new Date().toISOString(),
      prev: this.head,
      type,
      payload
    };
    const hash = sha256Hex(canonicalJSON(body));
    const line = JSON.stringify(Object.assign({}, body, { hash })) + '\n';
    const bytes = Buffer.byteLength(line, 'utf8');

    if (this.currentBytes > 0 && this.currentBytes + bytes > this.maxBytes) {
      this.rotate();
    }

    try {
      fs.writeSync(this.fd, line);
      if (this.fsync) fs.fsyncSync(this.fd);
    } catch (e) {
      this.lastWriteError = { at: new Date().toISOString(), code: e.code || 'STORE_WRITE_ERROR', message: e.message };
      const err = new Error('evidence store write failed: ' + e.message);
      err.code = 'STORE_WRITE_FAILED';
      throw err;
    }

    this.seq = body.seq;
    this.head = hash;
    this.currentBytes += bytes;
    this.recordsWritten += 1;
    this.bytesWritten += bytes;
    this.lastWriteError = null;
    return { seq: body.seq, hash, file: this.currentFile };
  }

  // Oldest-first order across rotations. Returns files actually retained.
  retentionPath() {
    return path.join(this.dir, 'retention.json');
  }

  readRetention() {
    try {
      return JSON.parse(fs.readFileSync(this.retentionPath(), 'utf8'));
    } catch (e) {
      return null;
    }
  }

  // Retention deliberately removes the oldest records. Before doing so we write
  // an anchor (last pruned seq/hash) so verification can distinguish authorized
  // retention from someone deleting the head of the chain.
  writeRetention(anchor) {
    const prev = this.readRetention();
    const next = {
      version: 1,
      pruned_through_seq: Math.max(anchor.seq, prev ? prev.pruned_through_seq || 0 : 0),
      anchor_hash: anchor.hash,
      pruned_files: (prev ? prev.pruned_files || 0 : 0) + anchor.files,
      at: new Date().toISOString()
    };
    const tmp = this.retentionPath() + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(next), { mode: 0o600 });
    fs.renameSync(tmp, this.retentionPath());
  }

  prune(now) {
    const cutoff = (now ? new Date(now).getTime() : Date.now()) - this.retentionDays * 86400000;
    const files = listFiles(this.dir);
    const rotated = files.filter(f => f.index !== this.currentIndex);
    const doomed = [];
    for (const f of rotated) {
      const full = path.join(this.dir, f.name);
      let st;
      try {
        st = fs.statSync(full);
      } catch (e) {
        continue;
      }
      if (st.mtimeMs < cutoff) doomed.push(f);
    }
    const afterAge = listFiles(this.dir);
    const keepRotated = Math.max(0, this.maxFiles - 1);
    const rotatedNow = afterAge.filter(f => f.index !== this.currentIndex);
    const excess = rotatedNow.length - keepRotated;
    for (let i = 0; i < excess; i++) {
      if (!doomed.some(d => d.name === rotatedNow[i].name)) doomed.push(rotatedNow[i]);
    }

    let anchor = null;
    for (const f of doomed) {
      const rec = readTailRecord(path.join(this.dir, f.name));
      if (rec && typeof rec.seq === 'number' && rec.hash) {
        if (!anchor || rec.seq > anchor.seq) anchor = { seq: rec.seq, hash: rec.hash, files: 0 };
      }
      try {
        fs.unlinkSync(path.join(this.dir, f.name));
        if (anchor) anchor.files += 1;
      } catch (e) { /* ignore */ }
    }
    if (anchor && anchor.files > 0) this.writeRetention(anchor);
    this.files = listFiles(this.dir);
    return this.files.length;
  }

  verify(opts) {
    opts = opts || {};
    const files = listFiles(this.dir);
    const result = {
      valid: true,
      files: files.map(f => f.name),
      records: 0,
      events: 0,
      alerts: 0,
      errors: [],
      head: 'GENESIS',
      last_seq: 0,
      truncated_tail: false,
      partial_history: false,
      retention_anchor: null,
      empty_store: files.length === 0
    };
    let prev = 'GENESIS';
    if (files.length > 0) {
      const first = readFirstRecord(path.join(this.dir, files[0].name));
      if (first && first.prev !== 'GENESIS') {
        const anchor = this.readRetention();
        if (anchor && anchor.anchor_hash === first.prev && first.seq === anchor.pruned_through_seq + 1) {
          prev = anchor.anchor_hash;
          result.last_seq = anchor.pruned_through_seq;
          result.partial_history = true;
          result.retention_anchor = { seq: anchor.pruned_through_seq, hash: anchor.anchor_hash };
        } else {
          result.valid = false;
          result.errors.push({ file: files[0].name, line: 1, code: 'MISSING_HISTORY', detail: 'earliest retained record does not link to a recorded retention anchor' });
          prev = first.prev;
          result.last_seq = first.seq - 1;
        }
      }
    }
    for (const f of files) {
      const full = path.join(this.dir, f.name);
      let text;
      try {
        text = fs.readFileSync(full, 'utf8');
      } catch (e) {
        result.errors.push({ file: f.name, line: 0, code: 'READ_ERROR', detail: e.message });
        result.valid = false;
        continue;
      }
      const lines = text.split('\n');
      const lastNonEmpty = lines.reduce((acc, l, i) => (l ? i : acc), -1);
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!line) continue;
        let rec;
        try {
          rec = JSON.parse(line);
        } catch (e) {
          if (i === lastNonEmpty && i === lines.length - 1) {
            result.truncated_tail = true;
            continue;
          }
          result.errors.push({ file: f.name, line: i + 1, code: 'MALFORMED_JSON' });
          result.valid = false;
          continue;
        }
        const expected = sha256Hex(canonicalJSON({
          v: rec.v,
          seq: rec.seq,
          at: rec.at,
          prev: rec.prev,
          type: rec.type,
          payload: rec.payload
        }));
        if (rec.hash !== expected) {
          result.errors.push({ file: f.name, line: i + 1, code: 'HASH_MISMATCH', seq: rec.seq });
          result.valid = false;
        }
        if (rec.prev !== prev) {
          result.errors.push({ file: f.name, line: i + 1, code: 'CHAIN_BROKEN', seq: rec.seq, expected_prev: prev });
          result.valid = false;
        }
        if (typeof rec.seq !== 'number' || rec.seq !== result.last_seq + 1) {
          result.errors.push({ file: f.name, line: i + 1, code: 'SEQ_GAP', seq: rec.seq, expected: result.last_seq + 1 });
          result.valid = false;
        }
        result.last_seq = rec.seq;
        result.records += 1;
        if (rec.type === 'event') result.events += 1;
        if (rec.type === 'alert') result.alerts += 1;
        prev = rec.hash;
        result.head = rec.hash;
      }
    }
    return result;
  }

  stats() {
    let totalBytes = 0;
    for (const f of listFiles(this.dir)) {
      try { totalBytes += fs.statSync(path.join(this.dir, f.name)).size; } catch (e) { /* ignore */ }
    }
    return {
      dir: this.dir,
      files: listFiles(this.dir).length,
      current_file: this.currentFile ? path.basename(this.currentFile) : null,
      current_bytes: this.currentBytes,
      total_bytes: totalBytes,
      max_bytes: this.maxBytes,
      utilization: this.maxBytes > 0 ? this.currentBytes / this.maxBytes : 0,
      seq: this.seq,
      head: this.head,
      last_write_error: this.lastWriteError
    };
  }

  close() {
    if (this.fd !== null) {
      try { fs.closeSync(this.fd); } catch (e) { /* ignore */ }
      this.fd = null;
    }
    this.opened = false;
  }
}

module.exports = { EventStore, sha256Hex, listFiles };
