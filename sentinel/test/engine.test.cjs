'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { makeRunner, feed, makeConfig, disableAllAdapters, readRecords } = require('./helpers.cjs');
const { buildScenario, iso, http } = require('../simulate.cjs');

test('normal browsing produces no alerts', async () => {
  const runner = await makeRunner();
  await feed(runner, buildScenario('normal'));
  assert.strictEqual(runner.recentAlerts.length, 0, 'expected zero alerts for normal browsing');
  assert.strictEqual(runner.counters.events, 40);
  assert.strictEqual(runner.store.verify().valid, true);
  await runner.stop('test');
});

test('weird user agent or missing accept-language is not a detection', async () => {
  const runner = await makeRunner();
  const raws = [];
  for (let i = 0; i < 20; i++) {
    raws.push(http({
      ts: iso(i * 2000),
      hint: 'ua:' + i,
      path: '/pricing',
      ip: '198.51.100.20',
      bytes_out: 2000,
      facts: {}
    }));
  }
  raws.forEach(r => { r.source.user_agent = 'curl/8.0'; });
  await feed(runner, raws);
  assert.strictEqual(runner.recentAlerts.length, 0);
  await runner.stop('test');
});

test('repeated authentication failures raise AUTH_FAIL_BURST with evidence', async () => {
  const runner = await makeRunner();
  await feed(runner, buildScenario('auth-fail'));
  const alerts = runner.recentAlerts.filter(a => a.rule_id === 'AUTH_FAIL_BURST');
  assert.strictEqual(alerts.length, 1);
  const a = alerts[0];
  assert.strictEqual(a.score, 15);
  assert.strictEqual(a.severity, 'low');
  assert.ok(a.evidence.failures >= 5);
  assert.strictEqual(a.entity.principal, 'alice');
  assert.strictEqual(a.source_adapter, 'http.access');
  assert.ok(a.event_ids.length === 1);
  assert.ok(a.recommended_response.length > 0);
  assert.strictEqual(a.facts.classification, 'heuristic');
  await runner.stop('test');
});

test('sequential pagination raises SEQUENTIAL_ENUMERATION', async () => {
  const runner = await makeRunner();
  await feed(runner, buildScenario('enumeration'));
  const a = runner.recentAlerts.filter(x => x.rule_id === 'SEQUENTIAL_ENUMERATION');
  assert.strictEqual(a.length, 1);
  assert.strictEqual(a[0].score, 25);
  assert.strictEqual(a[0].severity, 'medium');
  assert.strictEqual(a[0].evidence.mode, 'pagination');
  assert.ok(a[0].evidence.longest_consecutive_run >= 5);
  await runner.stop('test');
});

test('single bulk response raises BULK_RESPONSE_VOLUME', async () => {
  const runner = await makeRunner();
  await feed(runner, buildScenario('bulk'));
  const a = runner.recentAlerts.filter(x => x.rule_id === 'BULK_RESPONSE_VOLUME');
  assert.strictEqual(a.length, 1);
  assert.strictEqual(a[0].score, 30);
  assert.strictEqual(a[0].evidence.mode, 'single_response');
  assert.ok(a[0].evidence.bytes_out >= 3 * 1024 * 1024);
  await runner.stop('test');
});

test('unauthenticated access to a protected route is critical', async () => {
  const runner = await makeRunner();
  await feed(runner, buildScenario('unauthorized'));
  const a = runner.recentAlerts.filter(x => x.rule_id === 'PROTECTED_UNAUTHENTICATED');
  assert.strictEqual(a.length, 1);
  assert.strictEqual(a[0].score, 100);
  assert.strictEqual(a[0].severity, 'critical');
  assert.strictEqual(a[0].critical, true);
  assert.strictEqual(a[0].entity.route, '/admin/users');
  await runner.stop('test');
});

test('denied then successful access correlates the same route', async () => {
  const runner = await makeRunner();
  await feed(runner, buildScenario('denied-then-success'));
  const a = runner.recentAlerts.filter(x => x.rule_id === 'DENIED_THEN_SUCCESS');
  assert.strictEqual(a.length, 1);
  assert.strictEqual(a[0].score, 20);
  assert.strictEqual(a[0].evidence.elapsed_ms, 15000);
  await runner.stop('test');
});

test('allowlisted source is stored but not scored', async () => {
  const config = disableAllAdapters(makeConfig({
    allowlist: [{ ip: '203.0.113.77', reason: 'authorized scanner' }]
  }));
  const runner = await makeRunner({ config, stateDir: require('./helpers.cjs').tempDir('allow') });
  await feed(runner, buildScenario('unauthorized'));
  assert.strictEqual(runner.recentAlerts.length, 0);
  const events = readRecords(config.service.state_dir).filter(r => r.type === 'event');
  assert.strictEqual(events.length, 1);
  assert.strictEqual(events[0].payload.allowlisted, true);
  assert.match(events[0].payload.facts.allowlist_reason, /authorized scanner/);
  await runner.stop('test');
});

test('duplicate detections within the cooldown are suppressed and counted', async () => {
  const runner = await makeRunner();
  await feed(runner, buildScenario('auth-fail'));
  const first = runner.recentAlerts.filter(a => a.rule_id === 'AUTH_FAIL_BURST').length;
  await feed(runner, buildScenario('auth-fail'));
  const second = runner.recentAlerts.filter(a => a.rule_id === 'AUTH_FAIL_BURST').length;
  assert.strictEqual(first, 1);
  assert.strictEqual(second, 1, 'second burst inside cooldown must not create a second alert');
  assert.ok(runner.engine.counters.suppressed >= 1);
  await runner.stop('test');
});

test('distinct rules for one entity correlate into a higher-severity alert', async () => {
  const runner = await makeRunner();
  const raws = [];
  for (let i = 0; i < 5; i++) {
    raws.push(http({
      ts: iso(i * 2000),
      hint: 'corr-fail:' + i,
      method: 'POST',
      path: '/api/v1/session',
      principal: 'analyst-9',
      ip: '203.0.113.90',
      status: 401,
      bytes_out: 80
    }));
  }
  raws.push(http({
    ts: iso(12000),
    hint: 'corr-success',
    method: 'POST',
    path: '/api/v1/session',
    principal: 'analyst-9',
    ip: '203.0.113.90',
    status: 200,
    bytes_out: 1200
  }));
  raws.push(http({
    ts: iso(20000),
    hint: 'corr-bulk',
    path: '/api/v1/export',
    principal: 'analyst-9',
    ip: '203.0.113.90',
    bytes_out: 4 * 1024 * 1024
  }));
  await feed(runner, raws);
  const rules = runner.recentAlerts.map(a => a.rule_id);
  assert.ok(rules.includes('BULK_RESPONSE_VOLUME'));
  const correlated = runner.recentAlerts.filter(a => a.rule_id === 'CORRELATED_ACTIVITY');
  assert.strictEqual(correlated.length, 1);
  assert.ok(correlated[0].evidence.distinct_rules.length >= 2);
  assert.ok(['high', 'critical'].includes(correlated[0].severity));
  await runner.stop('test');
});

test('database audit events raise bulk, privilege and identity rules', async () => {
  const runner = await makeRunner();
  const raw = (extra) => Object.assign({
    adapter: 'db.audit',
    kind: 'db.audit',
    ts: iso(0),
    source: { principal: 'svc_reporting', ip: '10.0.0.9', principal_type: 'database' },
    facts: { database: 'orders', source: 'exported-audit-log' }
  }, extra);
  await feed(runner, [
    raw({ hint: 'db:bulk', outcome: 'success', facts: { database: 'orders', rows_read: 25000, statement_type: 'SELECT', table: 'orders' } }),
    raw({ hint: 'db:auth', outcome: 'auth_failure', facts: { database: 'orders', action: 'AUTH' } }),
    raw({ hint: 'db:new', outcome: 'success', facts: { database: 'orders', action: 'CREATE ROLE', target: 'svc_new' } })
  ]);
  const rules = runner.recentAlerts.map(a => a.rule_id);
  assert.ok(rules.includes('DB_BULK_READ'));
  assert.ok(rules.includes('DB_AUTH_FAILURE'));
  assert.ok(rules.includes('DB_NEW_IDENTITY'));
  await runner.stop('test');
});

test('baseline suppresses volume noise for a steady route', async () => {
  const runner = await makeRunner();
  const raws = [];
  // 10 minutes of steady 4-request minutes, then one 5-request minute.
  for (let minute = 0; minute < 10; minute++) {
    for (let i = 0; i < 4; i++) {
      raws.push(http({
        ts: iso(minute * 60000 + i * 1000),
        hint: 'steady:' + minute + ':' + i,
        path: '/api/v1/users',
        principal: 'batch-job',
        ip: '198.51.100.30',
        bytes_out: 900
      }));
    }
  }
  const alertCountBefore = runner.recentAlerts.length;
  await feed(runner, raws);
  const sensitive = runner.recentAlerts.filter(a => a.rule_id === 'SENSITIVE_ROUTE_REPEAT');
  assert.strictEqual(sensitive.length, 0, 'steady baseline traffic should not alert on repetition');
  assert.ok(runner.baseline.summary('/api/v1/users', iso(9 * 60000)).established);
  assert.ok(runner.recentAlerts.length === alertCountBefore);
  await runner.stop('test');
});
