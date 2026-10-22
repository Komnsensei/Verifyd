'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const http = require('http');
const { createAccessLogger } = require('../integrations/http-middleware.cjs');
const { HttpAccessAdapter } = require('../adapters/http-access.cjs');
const { makeRunner, makeConfig, disableAllAdapters, tempDir, withServer } = require('./helpers.cjs');

test('local API traffic is collected, detected and redacted end to end', async () => {
  const dir = tempDir('api');
  const logPath = path.join(dir, 'access.jsonl');
  const access = createAccessLogger({
    logPath,
    service: 'test-api',
    // Deliberately allow sensitive headers through, to prove the adapter-side
    // redaction removes them before they are persisted.
    headerAllowlist: ['user-agent', 'authorization', 'cookie'],
    getPrincipal: (req) => req.headers['x-user'] || null
  });

  let pageHits = 0;
  const handler = (req, res) => {
    access.middleware(req, res);
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname === '/api/v1/session' && req.method === 'POST') {
      if (req.headers['x-fail'] === '1') {
        res.writeHead(401, { 'content-type': 'application/json' });
        return res.end('{"error":"invalid credentials"}');
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end('{"token":"[not-logged]"}');
    }
    if (url.pathname === '/api/v1/records') {
      pageHits += 1;
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ page: url.searchParams.get('page'), rows: Array(100).fill({ id: 1 }) }));
    }
    if (url.pathname === '/admin/users') {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end('{"users":[{"id":1}]}');
    }
    res.writeHead(404);
    res.end('not found');
  };

  await withServer(handler, async (port) => {
    const base = 'http://127.0.0.1:' + port;
    for (let i = 0; i < 5; i++) {
      const r = await fetch(base + '/api/v1/session', {
        method: 'POST',
        headers: { 'x-user': 'alice', 'x-fail': '1', authorization: 'Bearer supersecret-token-value', cookie: 'sid=hidden' }
      });
      assert.strictEqual(r.status, 401);
    }
    for (let page = 1; page <= 6; page++) {
      const r = await fetch(base + '/api/v1/records?page=' + page + '&limit=100', { headers: { 'x-user': 'bob' } });
      assert.strictEqual(r.status, 200);
      await r.text();
    }
    const admin = await fetch(base + '/admin/users');
    assert.strictEqual(admin.status, 200);
    await admin.text();
  });

  const raw = fs.readFileSync(logPath, 'utf8');
  assert.ok(!raw.includes('supersecret-token-value'), 'authorization header must never reach the log');
  assert.ok(!raw.includes('hidden'), 'cookie must never reach the log');

  const adapter = new HttpAccessAdapter({
    config: { enabled: true, path: logPath, format: 'sentinel-jsonl', poll_interval_ms: 1000 },
    deps: {}
  });
  await adapter.init();
  assert.strictEqual(adapter.status, 'ACTIVE');

  const config = disableAllAdapters(makeConfig());
  const runner = await makeRunner({ config, adapters: [adapter] });
  const stats = await runner.cycle();
  assert.strictEqual(stats.events, 12);

  const rules = runner.recentAlerts.map(a => a.rule_id);
  assert.ok(rules.includes('AUTH_FAIL_BURST'), 'expected auth failure detection, got ' + rules.join(','));
  assert.ok(rules.includes('SEQUENTIAL_ENUMERATION'));
  const protectedAlert = runner.recentAlerts.find(a => a.rule_id === 'PROTECTED_UNAUTHENTICATED');
  assert.ok(protectedAlert);
  assert.strictEqual(protectedAlert.severity, 'critical');

  const stored = runner.store.verify();
  assert.strictEqual(stored.valid, true);
  assert.strictEqual(stored.events, 12);

  const eventsText = fs.readFileSync(path.join(config.service.state_dir, 'events-000001.jsonl'), 'utf8');
  assert.ok(!eventsText.includes('supersecret-token-value'));
  assert.ok(eventsText.includes('[REDACTED]'));

  const snap = runner.snapshot();
  assert.strictEqual(snap.health.chain_ok, true);
  assert.strictEqual(snap.health.adapters_active, 1);
  await runner.stop('test');
});

test('HTTP adapter reports a missing log and recovers when it appears', async () => {
  const dir = tempDir('httprev');
  const logPath = path.join(dir, 'late.jsonl');
  const adapter = new HttpAccessAdapter({
    config: { enabled: true, path: logPath, format: 'sentinel-jsonl', poll_interval_ms: 1000 },
    deps: {}
  });
  await adapter.init();
  assert.strictEqual(adapter.status, 'UNAVAILABLE');

  fs.writeFileSync(logPath, JSON.stringify({ ts: new Date().toISOString(), method: 'GET', path: '/', status: 200, bytes_out: 10 }) + '\n');
  const res = await adapter.poll();
  assert.strictEqual(adapter.status, 'ACTIVE');
  assert.strictEqual(res.events.length, 1);
});
