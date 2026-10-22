'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const net = require('net');
const { HostListenersAdapter } = require('../adapters/host-listeners.cjs');
const { createService } = require('../index.cjs');
const { buildConfig } = require('../config.cjs');
const { makeRunner, makeConfig, disableAllAdapters, tempDir, silentLogger, feed } = require('./helpers.cjs');
const { buildScenario } = require('../simulate.cjs');

function freePort() {
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const p = srv.address().port;
      srv.close(() => resolve(p));
    });
  });
}

function listenerAdapter(ports) {
  return new HostListenersAdapter({
    config: { enabled: true, poll_interval_ms: 1000, ignore_ports: [], allow_processes: [] },
    deps: { powershell: async () => ports, platform: 'win32', hostname: 'h1' }
  });
}

test('state, baseline and chain recover across a service restart', async () => {
  const stateDir = tempDir('restart');
  const base = disableAllAdapters(makeConfig());
  base.service.state_dir = stateDir;

  const first = await makeRunner({ config: base, stateDir, adapters: [listenerAdapter([{ address: '0.0.0.0', port: 4444, pid: 8123, process: 'x.exe' }])] });
  await first.cycle();
  const seqAfterFirst = first.store.seq;
  assert.strictEqual(first.recentAlerts.filter(a => a.rule_id === 'NEW_LISTENER').length, 0, 'baseline poll must not alert');
  await first.stop('restart-test');

  const second = await makeRunner({ config: base, stateDir, adapters: [listenerAdapter([{ address: '0.0.0.0', port: 4444, pid: 8123, process: 'x.exe' }])] });
  await second.cycle();
  assert.strictEqual(second.recentAlerts.filter(a => a.rule_id === 'NEW_LISTENER').length, 0, 'known listener must not re-alert after restart');
  await second.stop('restart-test');

  const third = await makeRunner({
    config: base,
    stateDir,
    adapters: [listenerAdapter([
      { address: '0.0.0.0', port: 4444, pid: 8123, process: 'x.exe' },
      { address: '0.0.0.0', port: 5555, pid: 9001, process: 'newsvc.exe' }
    ])]
  });
  await third.cycle();
  const alerts = third.recentAlerts.filter(a => a.rule_id === 'NEW_LISTENER');
  assert.strictEqual(alerts.length, 1);
  assert.strictEqual(alerts[0].entity.route, null);
  assert.strictEqual(alerts[0].evidence.port, 5555);

  const verify = third.store.verify();
  assert.strictEqual(verify.valid, true);
  assert.ok(third.store.seq > seqAfterFirst, 'sequence must continue across restarts');
  await third.stop('restart-test');
});

test('diagnostics health is public on loopback but status requires the token', async () => {
  const port = await freePort();
  process.env.SENTINEL_DIAG_TOKEN = 'test-diag-token';
  const config = disableAllAdapters(makeConfig({ diagnostics: { port, bind: '127.0.0.1' } }));
  const svc = await createService({ config, logger: silentLogger });
  try {
    const health = await fetch('http://127.0.0.1:' + port + '/health');
    assert.strictEqual(health.status, 200);
    const body = await health.json();
    assert.strictEqual(body.service, 'sentinel');
    assert.strictEqual(body.store_writable, true);

    const noToken = await fetch('http://127.0.0.1:' + port + '/status');
    assert.strictEqual(noToken.status, 401);

    const badToken = await fetch('http://127.0.0.1:' + port + '/status', { headers: { authorization: 'Bearer wrong' } });
    assert.strictEqual(badToken.status, 401);

    const ok = await fetch('http://127.0.0.1:' + port + '/status', { headers: { authorization: 'Bearer test-diag-token' } });
    assert.strictEqual(ok.status, 200);
    const snap = await ok.json();
    assert.strictEqual(snap.service, 'sentinel');
    assert.ok(snap.detection.mode === 'detect');

    const cov = await fetch('http://127.0.0.1:' + port + '/coverage', { headers: { 'x-sentinel-token': 'test-diag-token' } });
    assert.strictEqual(cov.status, 200);
    const coverage = await cov.json();
    assert.ok(Array.isArray(coverage.adapters));
    assert.ok(coverage.blind_spots.some(b => b.adapter === 'global'));
  } finally {
    delete process.env.SENTINEL_DIAG_TOKEN;
    await svc.stop('test');
  }
});

test('remote diagnostics bind works only with a token', async () => {
  const port = await freePort();
  process.env.SENTINEL_DIAG_TOKEN = 'remote-token';
  const config = disableAllAdapters(makeConfig({ diagnostics: { port, bind: '0.0.0.0', allow_remote: true } }));
  const svc = await createService({ config, logger: silentLogger });
  try {
    const denied = await fetch('http://127.0.0.1:' + port + '/status');
    assert.strictEqual(denied.status, 401);
    const allowed = await fetch('http://127.0.0.1:' + port + '/status', { headers: { 'x-sentinel-token': 'remote-token' } });
    assert.strictEqual(allowed.status, 200);
  } finally {
    delete process.env.SENTINEL_DIAG_TOKEN;
    await svc.stop('test');
  }
});

test('config validation rejects insecure and unsafe combinations', () => {
  const insecure = buildConfig({ alerts: { webhook: { url: 'http://example.com/hook' } } });
  assert.ok(insecure.errors.some(e => /https is required/.test(e)));

  const armedInDetect = buildConfig({ actions: { enabled: true } });
  assert.ok(armedInDetect.errors.some(e => /actions\.enabled requires detection\.mode=respond/.test(e)));

  const remote = buildConfig({ diagnostics: { bind: '0.0.0.0' } });
  assert.ok(remote.errors.some(e => /allow_remote/.test(e)));

  const creds = buildConfig({ alerts: { webhook: { url: 'https://user:pass@example.com/hook' } } });
  assert.ok(creds.errors.some(e => /must not embed credentials/.test(e)));

  const metadata = buildConfig({ alerts: { webhook: { url: 'https://169.254.169.254/latest/meta-data' } } });
  assert.ok(metadata.errors.some(e => /metadata/.test(e)));
});

test('end-to-end alert delivery to a local authenticated receiver', async () => {
  const port = await freePort();
  process.env.SENTINEL_TEST_HOOK_SECRET = 'hook-secret';
  const received = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      received.push({ headers: req.headers, body: Buffer.concat(chunks).toString('utf8') });
      res.writeHead(200);
      res.end('ok');
    });
  });
  await new Promise(resolve => server.listen(port, '127.0.0.1', resolve));

  const config = disableAllAdapters(makeConfig({
    alerts: {
      webhook: {
        url: 'http://127.0.0.1:' + port + '/hook',
        secret_env: 'SENTINEL_TEST_HOOK_SECRET',
        allow_insecure_loopback: true,
        backoff_base_ms: 1
      }
    }
  }));
  const runner = await makeRunner({ config });
  try {
    await feed(runner, buildScenario('auth-fail'));
    const flush = await runner.dispatcher.flush();
    assert.strictEqual(flush.sent >= 1, true);
    assert.ok(received.length >= 1);

    const rec = received[0];
    const ts = rec.headers['x-sentinel-timestamp'];
    const expected = 'sha256=' + crypto.createHmac('sha256', 'hook-secret').update(ts + '.' + rec.body).digest('hex');
    assert.strictEqual(rec.headers['x-sentinel-signature'], expected);
    const parsed = JSON.parse(rec.body);
    assert.strictEqual(parsed.schema, 'sentinel.webhook/1');
    assert.ok(parsed.alert.rule_id);
  } finally {
    delete process.env.SENTINEL_TEST_HOOK_SECRET;
    await runner.stop('test');
    if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
});

test('alert queue drains after a receiver outage without losing alerts', async () => {
  const port = await freePort();
  process.env.SENTINEL_TEST_HOOK_SECRET = 'hook-secret';
  let healthy = false;
  const seen = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      if (!healthy) {
        res.writeHead(503);
        res.end('down');
        return;
      }
      seen.push(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      res.writeHead(200);
      res.end('ok');
    });
  });
  await new Promise(resolve => server.listen(port, '127.0.0.1', resolve));

  const config = disableAllAdapters(makeConfig({
    alerts: {
      webhook: {
        url: 'http://127.0.0.1:' + port + '/hook',
        secret_env: 'SENTINEL_TEST_HOOK_SECRET',
        allow_insecure_loopback: true,
        backoff_base_ms: 1
      }
    }
  }));
  const runner = await makeRunner({ config });
  try {
    await feed(runner, buildScenario('bulk'));
    await runner.dispatcher.flush();
    assert.strictEqual(runner.dispatcher.stats().queued, 1, 'alert must stay queued while receiver is down');

    healthy = true;
    for (let i = 0; i < 6 && runner.dispatcher.stats().queued > 0; i++) {
      await new Promise(r => setTimeout(r, 15));
      await runner.dispatcher.flush();
    }
    assert.strictEqual(runner.dispatcher.stats().queued, 0);
    assert.strictEqual(seen.length, 1);
  } finally {
    delete process.env.SENTINEL_TEST_HOOK_SECRET;
    await runner.stop('test');
    if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
});

test('a stalled adapter raises a missed-poll diagnostic', async () => {
  const config = disableAllAdapters(makeConfig());
  const adapter = listenerAdapter([{ address: '0.0.0.0', port: 443, pid: 4, process: 'System' }]);
  const runner = await makeRunner({ config, adapters: [adapter] });
  try {
    await runner.cycle();
    adapter.last_ok_at = new Date(Date.now() - 60000).toISOString();
    runner.checkMissed(adapter, Date.now());
    const diag = runner.recentAlerts.find(a => a.rule_id === 'MISSED_POLL_INTERVAL');
    assert.ok(diag, 'expected a missed-poll diagnostic');
    assert.strictEqual(diag.severity, 'low');
    assert.ok(diag.evidence.overdue_ms >= 60000);
  } finally {
    await runner.stop('test');
  }
});

test('a service with no configured sources reports degradation, not false coverage', async () => {
  const config = disableAllAdapters(makeConfig());
  const runner = await makeRunner({ config });
  const cov = runner.coverage();
  assert.strictEqual(cov.summary.active, 0);
  assert.strictEqual(cov.summary.unavailable, 0);
  assert.strictEqual(runner.healthSummary().status, 'ok', 'nothing failing, but all sources blind');
  assert.ok(cov.blind_spots.some(b => b.adapter === 'global'));
  await runner.stop('test');
});
