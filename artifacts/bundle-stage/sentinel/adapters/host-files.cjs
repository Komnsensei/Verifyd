'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { BaseAdapter } = require('./base.cjs');

const MAX_FILES = 5000;
const MAX_FILE_BYTES = 32 * 1024 * 1024;

function hashFile(file) {
  const st = fs.statSync(file);
  if (!st.isFile()) return null;
  if (st.size > MAX_FILE_BYTES) return { sha256: 'skipped:size', size: st.size, mtime_ms: st.mtimeMs, skipped: true };
  const h = crypto.createHash('sha256');
  const fd = fs.openSync(file, 'r');
  try {
    const buf = Buffer.alloc(65536);
    let read;
    while ((read = fs.readSync(fd, buf, 0, buf.length, null)) > 0) {
      h.update(buf.subarray(0, read));
    }
  } finally {
    fs.closeSync(fd);
  }
  return { sha256: h.digest('hex'), size: st.size, mtime_ms: st.mtimeMs, skipped: false };
}

function walk(root, out, depth) {
  if (out.length >= MAX_FILES || (depth || 0) > 12) return;
  let entries;
  try {
    entries = fs.readdirSync(root, { withFileTypes: true });
  } catch (e) {
    return;
  }
  entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  for (const ent of entries) {
    if (out.length >= MAX_FILES) return;
    const full = path.join(root, ent.name);
    if (ent.isDirectory()) {
      if (ent.name === 'node_modules' || ent.name === '.git') continue;
      walk(full, out, (depth || 0) + 1);
    } else if (ent.isFile()) {
      out.push(full);
    }
  }
}

class HostFilesAdapter extends BaseAdapter {
  constructor(opts) {
    super(Object.assign({
      id: 'host.files',
      name: 'Monitored application/config directories',
      category: 'B: Windows host',
      capabilities: ['SHA-256 baseline of configured files and directories', 'created/modified/deleted change events'],
      limitations: [
        'polling, so a change that is reverted between polls is not seen',
        'bounded to ' + MAX_FILES + ' files and ' + Math.round(MAX_FILE_BYTES / 1048576) + 'MB per file',
        'does not use the Windows USN journal (no extra privilege requirement)'
      ],
      source: { type: 'in-process', method: 'sha256 baseline diff' }
    }, opts));
    this.baseline = null;
    this.baselinePath = this.deps.stateDir ? path.join(this.deps.stateDir, 'files-baseline.json') : null;
  }

  loadBaseline() {
    if (!this.baselinePath) return null;
    try {
      const raw = JSON.parse(fs.readFileSync(this.baselinePath, 'utf8'));
      if (raw && raw.files && typeof raw.files === 'object') return raw.files;
    } catch (e) { /* first run or corrupt baseline: rebuild */ }
    return null;
  }

  persistBaseline(map) {
    if (!this.baselinePath) return;
    const tmp = this.baselinePath + '.tmp';
    try {
      fs.writeFileSync(tmp, JSON.stringify({ version: 1, saved_at: new Date().toISOString(), files: map }), { mode: 0o600 });
      fs.renameSync(tmp, this.baselinePath);
    } catch (e) { /* non-fatal: next poll rebuilds */ }
  }

  async init() {
    if (this.config.enabled === false) return this.markNotConfigured('disabled in config');
    const paths = (this.config.paths || []).filter(Boolean);
    if (paths.length === 0) return this.markNotConfigured('adapters.host_files.paths is empty');
    const present = paths.filter(p => {
      try { fs.statSync(p); return true; } catch (e) { return false; }
    });
    if (present.length === 0) return this.markUnavailable('none of the configured paths exist: ' + paths.join(', '));
    this.detail.paths = present;
    this.detail.missing = paths.filter(p => !present.includes(p));
    this.baseline = this.loadBaseline();
    if (this.baseline) this.detail.baseline_restored = Object.keys(this.baseline).length;
    return this.markActive('hashing ' + present.length + ' monitored path(s)', this.detail);
  }

  scan() {
    const files = [];
    for (const p of this.config.paths || []) {
      let st;
      try { st = fs.statSync(p); } catch (e) { continue; }
      if (st.isDirectory()) walk(p, files, 0);
      else if (st.isFile()) files.push(p);
    }
    const map = {};
    for (const f of files.slice(0, MAX_FILES)) {
      try {
        const h = hashFile(f);
        if (h) map[f] = h;
      } catch (e) { /* unreadable file: skip but keep scanning */ }
    }
    return map;
  }

  async poll() {
    if (!this.config.enabled) return { events: [] };
    const current = this.scan();
    const nowIso = new Date().toISOString();
    const events = [];
    if (this.baseline == null) {
      this.baseline = current;
      this.persistBaseline(current);
      this.cursor = { baseline_at: nowIso, files: Object.keys(current).length };
      this.succeeded(0);
      return { events };
    }
    for (const [file, info] of Object.entries(current)) {
      const prev = this.baseline[file];
      if (!prev) {
        events.push(this.changeEvent(file, 'created', null, info, nowIso));
      } else if (prev.sha256 !== info.sha256) {
        events.push(this.changeEvent(file, 'modified', prev, info, nowIso));
      }
    }
    for (const file of Object.keys(this.baseline)) {
      if (!current[file]) events.push(this.changeEvent(file, 'deleted', this.baseline[file], null, nowIso));
    }
    this.baseline = current;
    // The on-disk baseline only needs rewriting when something changed; a steady
    // 5000-file tree would otherwise rewrite ~700KB every minute.
    if (events.length > 0) this.persistBaseline(current);
    this.cursor = { baseline_at: (this.cursor && this.cursor.baseline_at) || nowIso, files: Object.keys(current).length, last_poll_at: nowIso };
    this.succeeded(events.length);
    return { events };
  }

  changeEvent(file, change, prev, info, ts) {
    return {
      adapter: this.id,
      kind: 'host.file',
      ts,
      hint: 'file:' + change + ':' + file + ':' + ts,
      outcome: change === 'deleted' ? 'removed' : 'changed',
      host: { path: file, hostname: this.deps.hostname || null },
      facts: {
        change,
        previous_sha256: prev ? prev.sha256 : null,
        current_sha256: info ? info.sha256 : null,
        size_bytes: info ? info.size : (prev ? prev.size : null),
        previous_size_bytes: prev ? prev.size : null
      }
    };
  }

  restoreCursor(cursor) {
    super.restoreCursor(cursor);
    // Baseline hashes are loaded from files-baseline.json during init, so a
    // change made while the service was stopped is still reported on restart.
  }
}

module.exports = { HostFilesAdapter, hashFile, walk, MAX_FILES };
