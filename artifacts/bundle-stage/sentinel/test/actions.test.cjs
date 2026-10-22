'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { ActionGate } = require('../actions.cjs');
const { makeConfig } = require('./helpers.cjs');

function alert(overrides) {
  return Object.assign({
    alert_id: 'a1',
    rule_id: 'BULK_RESPONSE_VOLUME',
    severity: 'high',
    score: 55,
    entity: { ip: '203.0.113.9', principal: 'alice' }
  }, overrides || {});
}

test('actions are ineligible in detection-only mode', () => {
  const cfg = makeConfig();
  const gate = new ActionGate(cfg);
  const plan = gate.plan(alert());
  assert.strictEqual(plan.eligible, false);
  assert.strictEqual(plan.intents.length, 0);
  assert.ok(plan.reasons.some(r => /detection\.mode/.test(r)));
});

test('actions with no authorized target produce no intents', () => {
  const cfg = makeConfig({ detection: { mode: 'respond' } });
  cfg.actions.enabled = true;
  const gate = new ActionGate(cfg);
  const plan = gate.plan(alert());
  assert.strictEqual(plan.intents.length, 0, 'no target URL means no outbound intent');
});

test('dry-run plans a gateway and rotation intent without sending anything', async () => {
  const cfg = makeConfig({
    detection: { mode: 'respond' },
    actions: {
      enabled: true,
      dry_run: true,
      targets: {
        gateway_rate_limit: { url: 'https://gateway.example.test/control', secret_env: 'SENTINEL_ACTION_SECRET' },
        waf_block: { url: 'https://waf.example.test/control', secret_env: 'SENTINEL_ACTION_SECRET' },
        credential_rotation: { url: 'https://idp.example.test/control', secret_env: 'SENTINEL_ACTION_SECRET' }
      }
    }
  });
  let sent = 0;
  const gate = new ActionGate(cfg, { transport: async () => { sent += 1; return { status: 200 }; } });
  const result = await gate.execute(alert());
  assert.strictEqual(sent, 0, 'dry run must not send');
  assert.strictEqual(result.plan.dry_run, true);
  const types = result.results.map(r => r.action);
  assert.ok(types.includes('gateway_rate_limit'));
  assert.ok(types.includes('waf_block'));
  assert.ok(types.includes('credential_rotation'));
  for (const r of result.results) {
    assert.strictEqual(r.performed, false);
    assert.strictEqual(r.dry_run, true);
  }
  const rotation = result.results.find(r => r.action === 'credential_rotation');
  assert.strictEqual(rotation.target, 'alice');
});

test('a low-severity alert cannot trigger a block or rotation', () => {
  const cfg = makeConfig({
    detection: { mode: 'respond' },
    actions: {
      enabled: true,
      dry_run: true,
      targets: {
        gateway_rate_limit: { url: 'https://gateway.example.test/control', secret_env: 'SENTINEL_ACTION_SECRET' },
        waf_block: { url: 'https://waf.example.test/control', secret_env: 'SENTINEL_ACTION_SECRET' },
        credential_rotation: { url: 'https://idp.example.test/control', secret_env: 'SENTINEL_ACTION_SECRET' }
      }
    }
  });
  const gate = new ActionGate(cfg);
  const plan = gate.plan(alert({ severity: 'low', score: 15 }));
  assert.strictEqual(plan.intents.length, 0);
});

test('missing action secret fails closed when not in dry-run', async () => {
  delete process.env.SENTINEL_ACTION_SECRET;
  const cfg = makeConfig({
    detection: { mode: 'respond' },
    actions: {
      enabled: true,
      dry_run: false,
      targets: {
        waf_block: { url: 'https://waf.example.test/control', secret_env: 'SENTINEL_ACTION_SECRET' }
      }
    }
  });
  const gate = new ActionGate(cfg, { transport: async () => ({ status: 200 }) });
  const result = await gate.execute(alert());
  assert.ok(result.results.length >= 1);
  for (const r of result.results) {
    assert.strictEqual(r.performed, false);
    assert.match(r.error, /SENTINEL_ACTION_SECRET/);
  }
});
