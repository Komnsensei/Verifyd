'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { Dispatcher } = require('../dispatcher.cjs');
const { tempDir } = require('./helpers.cjs');

function alert(id) {
  return {
    schema: 'sentinel.alert/1',
    alert_id: id,
    created_at: '2026-01-15T09:00:00.000Z',
    rule_id: 'AUTH_FAIL_BURST',
    severity: 'low',
    score: 15
  };
}

function webhook(overrides) {
  return Object.assign({
    url: 'https://receiver.example.test/sentinel',
    secret_env: 'SENTINEL_TEST_WEBHOOK_SECRET',
    timeout_ms: 1000,
    max_attempts: 6,
    backoff_base_ms: 1,
    backoff_max_ms: 5
  }, overrides || {});
}

test('signs payloads with HMAC over timestamp.body', async () => {
  process.env.SENTINEL_TEST_WEBHOOK_SECRET = 'test-secret-value';
  let captured = null;
  const d = new Dispatcher({
    dir: tempDir('disp'),
    webhook: webhook(),
    transport: async (opts, payload) => {
      captured = { opts, payload: payload.toString('utf8') };
      return { status: 200, body: 'ok' };
    }
  }).open();
  d.enqueue(alert('a1'));
  const res = await d.flush();
  assert.strictEqual(res.sent, 1);
  const ts = captured.opts.headers['x-sentinel-timestamp'];
  const expected = 'sha256=' + crypto.createHmac('sha256', 'test-secret-value').update(ts + '.' + captured.payload).digest('hex');
  assert.strictEqual(captured.opts.headers['x-sentinel-signature'], expected);
  assert.strictEqual(captured.opts.headers['x-sentinel-alert-id'], 'a1');
  assert.strictEqual(JSON.parse(captured.payload).alert.alert_id, 'a1');
  d.close();
});

test('retries after failures and recovers when the receiver returns 200', async () => {
  process.env.SENTINEL_TEST_WEBHOOK_SECRET = 'test-secret-value';
  let now = 1000000;
  let calls = 0;
  const d = new Dispatcher({
    dir: tempDir('disp-retry'),
    webhook: webhook(),
    clock: () => now,
    transport: async () => {
      calls += 1;
      return { status: calls <= 2 ? 500 : 200, body: '' };
    }
  }).open();
  d.enqueue(alert('a2'));

  await d.flush();
  assert.strictEqual(calls, 1);
  assert.strictEqual(d.pending().length, 1);

  now += 1000;
  await d.flush();
  assert.strictEqual(calls, 2);
  assert.strictEqual(d.pending().length, 1);

  now += 1000;
  await d.flush();
  assert.strictEqual(calls, 3);
  assert.strictEqual(d.pending().length, 0);
  assert.strictEqual(d.stats().delivered, 1);
  assert.ok(d.stats().last_success_at);
  d.close();
});

test('dead-letters after max_attempts and keeps the record', async () => {
  process.env.SENTINEL_TEST_WEBHOOK_SECRET = 'test-secret-value';
  let now = 1000000;
  const d = new Dispatcher({
    dir: tempDir('disp-dead'),
    webhook: webhook({ max_attempts: 2 }),
    clock: () => now,
    transport: async () => ({ status: 503, body: 'unavailable' })
  }).open();
  d.enqueue(alert('a3'));

  await d.flush();
  now += 1000;
  await d.flush();

  assert.strictEqual(d.pending().length, 0);
  assert.strictEqual(d.stats().dead_letter, 1);
  assert.ok(d.stats().last_error);
  d.close();
});

test('replays a pending alert after a process restart', async () => {
  process.env.SENTINEL_TEST_WEBHOOK_SECRET = 'test-secret-value';
  const dir = tempDir('disp-replay');
  let now = 1000000;
  const first = new Dispatcher({
    dir,
    webhook: webhook({ max_attempts: 5 }),
    clock: () => now,
    transport: async () => ({ status: 500, body: '' })
  }).open();
  first.enqueue(alert('a4'));
  await first.flush();
  assert.strictEqual(first.pending().length, 1);
  first.close();

  let delivered = null;
  now += 5000;
  const second = new Dispatcher({
    dir,
    webhook: webhook(),
    clock: () => now,
    transport: async (opts, payload) => {
      delivered = JSON.parse(payload.toString('utf8')).alert.alert_id;
      return { status: 200, body: 'ok' };
    }
  }).open();
  assert.strictEqual(second.pending().length, 1, 'queued alert must survive restart');
  const res = await second.flush();
  assert.strictEqual(res.sent, 1);
  assert.strictEqual(delivered, 'a4');
  second.close();
});

test('refuses an insecure non-loopback webhook', () => {
  const d = new Dispatcher({
    dir: tempDir('disp-insecure'),
    webhook: webhook({ url: 'http://receiver.example.test/hook' }),
    transport: async () => ({ status: 200 })
  }).open();
  assert.strictEqual(d.stats().status, 'UNAVAILABLE');
  assert.match(d.stats().status_reason, /https is required/);
  d.close();
});

test('reports UNAVAILABLE when the signing secret is absent', () => {
  delete process.env.SENTINEL_MISSING_SECRET;
  const d = new Dispatcher({
    dir: tempDir('disp-secret'),
    webhook: webhook({ secret_env: 'SENTINEL_MISSING_SECRET' }),
    transport: async () => ({ status: 200 })
  }).open();
  assert.strictEqual(d.stats().status, 'UNAVAILABLE');
  assert.match(d.stats().status_reason, /SENTINEL_MISSING_SECRET/);
  d.close();
});

test('compacts delivered alerts out of the queue and preserves pending retries', async () => {
  process.env.SENTINEL_TEST_WEBHOOK_SECRET = 'test-secret-value';
  const dir = tempDir('disp-compact');
  let now = 1000000;
  let healthy = true;
  const d = new Dispatcher({
    dir,
    webhook: webhook({ max_attempts: 5 }),
    clock: () => now,
    compactThresholdBytes: 1,
    transport: async () => ({ status: healthy ? 200 : 500, body: '' })
  }).open();
  d.enqueue(alert('delivered-1'));
  await d.flush();
  assert.strictEqual(d.pending().length, 0);
  d.maybeCompact();
  d.close();

  const reopened = new Dispatcher({
    dir,
    webhook: webhook(),
    clock: () => now,
    transport: async () => ({ status: 500, body: '' })
  }).open();
  assert.strictEqual(reopened.pending().length, 0, 'delivered alerts must not reappear');
  reopened.enqueue(alert('pending-1'));
  await reopened.flush();
  assert.strictEqual(reopened.pending().length, 1);
  reopened.close();

  now += 5000;
  const third = new Dispatcher({ dir, webhook: webhook(), clock: () => now, transport: async () => ({ status: 200 }) }).open();
  assert.strictEqual(third.pending().length, 1, 'pending alert with attempts must survive compaction');
  assert.ok(third.pending()[0].attempts >= 1);
  await third.flush();
  assert.strictEqual(third.pending().length, 0);
  third.close();
});

test('rejects payloads above the size cap without retrying', async () => {
  process.env.SENTINEL_TEST_WEBHOOK_SECRET = 'test-secret-value';
  const d = new Dispatcher({
    dir: tempDir('disp-size'),
    webhook: webhook(),
    transport: async () => ({ status: 200 })
  }).open();
  d.enqueue({ alert_id: 'huge', rule_id: 'BULK_RESPONSE_VOLUME', padding: 'x'.repeat(300 * 1024) });
  await d.flush();
  assert.strictEqual(d.pending().length, 0);
  assert.strictEqual(d.stats().dead_letter, 1);
  d.close();
});
