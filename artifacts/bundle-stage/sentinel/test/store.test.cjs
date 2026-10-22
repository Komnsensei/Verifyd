'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { EventStore } = require('../store.cjs');
const { buildEvent } = require('../event.cjs');
const { tempDir } = require('./helpers.cjs');

function openStore(dir, overrides) {
  return new EventStore(Object.assign({
    dir,
    maxBytes: 1024 * 1024,
    maxFiles: 4,
    retentionDays: 30
  }, overrides || {})).open();
}

test('an empty or missing store is reported explicitly, not as assurance', () => {
  const dir = tempDir('empty');
  const result = new EventStore({ dir: path.join(dir, 'missing'), maxBytes: 1024, maxFiles: 2, retentionDays: 1 }).verify();
  assert.strictEqual(result.valid, true);
  assert.strictEqual(result.empty_store, true);
  assert.strictEqual(result.records, 0);
});

test('appends a verifiable hash chain and continues after restart', () => {
  const dir = tempDir('chain');
  const store = openStore(dir);
  store.append('event', { n: 1 });
  store.append('event', { n: 2 });
  const head = store.head;
  const seq = store.seq;
  store.close();

  const reopened = openStore(dir);
  assert.strictEqual(reopened.seq, seq);
  assert.strictEqual(reopened.head, head);
  reopened.append('alert', { n: 3 });
  const v = reopened.verify();
  assert.strictEqual(v.valid, true);
  assert.strictEqual(v.records, 3);
  assert.strictEqual(v.events, 2);
  assert.strictEqual(v.alerts, 1);
  reopened.close();
});

test('detects a modified payload and reports the location', () => {
  const dir = tempDir('tamper');
  const store = openStore(dir);
  store.append('event', { n: 1 });
  store.append('event', { n: 2 });
  store.close();

  const file = path.join(dir, 'events-000001.jsonl');
  const lines = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean);
  const rec = JSON.parse(lines[0]);
  rec.payload.n = 999;
  lines[0] = JSON.stringify(rec);
  fs.writeFileSync(file, lines.join('\n') + '\n');

  const v = openStore(dir).verify();
  assert.strictEqual(v.valid, false);
  assert.ok(v.errors.some(e => e.code === 'HASH_MISMATCH'));
});

test('detects a reordered record', () => {
  const dir = tempDir('reorder');
  const store = openStore(dir);
  store.append('event', { n: 1 });
  store.append('event', { n: 2 });
  store.close();

  const file = path.join(dir, 'events-000001.jsonl');
  const lines = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean);
  [lines[0], lines[1]] = [lines[1], lines[0]];
  fs.writeFileSync(file, lines.join('\n') + '\n');

  const v = openStore(dir).verify();
  assert.strictEqual(v.valid, false);
  assert.ok(v.errors.some(e => e.code === 'CHAIN_BROKEN' || e.code === 'SEQ_GAP'));
});

test('tolerates a torn trailing line from a crash', () => {
  const dir = tempDir('torn');
  const store = openStore(dir);
  store.append('event', { n: 1 });
  store.close();
  fs.appendFileSync(path.join(dir, 'events-000001.jsonl'), '{"v":1,"seq":2,"at":');

  const v = openStore(dir).verify();
  assert.strictEqual(v.valid, true);
  assert.strictEqual(v.truncated_tail, true);
  assert.strictEqual(v.records, 1);
});

test('rotates by size and verifies across files', () => {
  const dir = tempDir('rotate');
  const store = openStore(dir, { maxBytes: 4000, maxFiles: 20 });
  for (let i = 0; i < 40; i++) store.append('event', { i, padding: 'x'.repeat(60) });
  const stats = store.stats();
  assert.ok(stats.files > 1, 'expected multiple rotated files');
  const v = store.verify();
  assert.strictEqual(v.valid, true);
  assert.strictEqual(v.records, 40);
  assert.ok(v.last_seq === 40);
  store.close();
});

test('retention drops old rotated files and enforces max_files', async () => {
  const dir = tempDir('retain');
  const store = openStore(dir, { maxBytes: 700, maxFiles: 3 });
  for (let i = 0; i < 60; i++) store.append('event', { i, padding: 'y'.repeat(60) });
  store.close();

  const rotated = fs.readdirSync(dir).filter(f => f.startsWith('events-')).sort();
  assert.ok(rotated.length <= 3, 'max_files must bound retained files');
  const old = path.join(dir, rotated[0]);
  const past = new Date(Date.now() - 60 * 86400000);
  fs.utimesSync(old, past, past);

  const reopened = new EventStore({ dir, maxBytes: 700, maxFiles: 3, retentionDays: 30 }).open();
  reopened.prune();
  assert.strictEqual(fs.existsSync(old), false, 'file older than retention_days should be removed');
  reopened.close();
});

test('verification distinguishes retention from missing history', async () => {
  const dir = tempDir('retain-verify');
  const store = openStore(dir, { maxBytes: 700, maxFiles: 3 });
  for (let i = 0; i < 40; i++) store.append('event', { i, padding: 'z'.repeat(60) });
  store.close();

  const reopened = new EventStore({ dir, maxBytes: 700, maxFiles: 3, retentionDays: 30 }).open();
  reopened.prune();
  const v = reopened.verify();
  assert.strictEqual(v.valid, true);
  assert.strictEqual(v.partial_history, true);
  assert.ok(v.retention_anchor);
  reopened.close();

  fs.unlinkSync(path.join(dir, 'retention.json'));
  const withoutAnchor = openStore(dir).verify();
  assert.strictEqual(withoutAnchor.valid, false);
  assert.ok(withoutAnchor.errors.some(e => e.code === 'MISSING_HISTORY'));
});

test('redacts credentials before they reach the evidence file', async () => {
  const dir = tempDir('redact');
  const store = openStore(dir);
  const ev = buildEvent({
    adapter: 'http.access',
    kind: 'http.request',
    ts: '2026-01-15T09:00:00.000Z',
    source: { ip: '198.51.100.5', principal: 'u1' },
    request: {
      method: 'POST',
      path: '/login?token=supersecret&page=2',
      query: { token: 'supersecret', page: '2' },
      headers: { authorization: 'Bearer abcdefghijklmnop', cookie: 'sid=verysecret', 'user-agent': 'curl/8.0' },
      bytes_in: 200
    },
    response: { status: 200, bytes_out: 100 },
    facts: {
      note: 'key AKIAABCDEFGHIJKLMNOP and sk-live-abcdefghijklmnopqrstuvwx',
      nested: { password: 'hunter2' }
    }
  });
  store.append('event', ev);
  store.close();

  const text = fs.readFileSync(path.join(dir, 'events-000001.jsonl'), 'utf8');
  assert.ok(!text.includes('supersecret'), 'query secret leaked via path or query');
  assert.ok(!text.includes('abcdefghijklmnopqrstuvwx'), 'api key leaked');
  assert.ok(!text.includes('hunter2'), 'password leaked');
  assert.ok(!text.includes('verysecret'), 'cookie leaked');
  assert.ok(text.includes('[REDACTED]'));
  assert.ok(text.includes('curl/8.0'), 'non-sensitive user agent should be preserved');
});

test('store files are created with restrictive permissions', () => {
  const dir = tempDir('perms');
  const store = openStore(dir);
  store.append('event', { n: 1 });
  store.close();
  if (process.platform !== 'win32') {
    const mode = fs.statSync(path.join(dir, 'events-000001.jsonl')).mode & 0o777;
    assert.strictEqual(mode, 0o600);
    const dirmode = fs.statSync(dir).mode & 0o777;
    assert.ok(dirmode <= 0o700);
  }
});

test('canonical hashing is stable for equal payloads', () => {
  const dir = tempDir('stable');
  const store = openStore(dir);
  const a = store.append('event', { b: 2, a: 1 });
  const b = store.append('event', { a: 1, b: 2 });
  assert.notStrictEqual(a.hash, b.hash, 'chain hash includes prev, so records differ');
  store.close();
  const v = openStore(dir).verify();
  assert.strictEqual(v.valid, true);
  assert.strictEqual(v.head.length, 64);
  assert.match(v.head, /^[0-9a-f]{64}$/);
});
