'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { HostListenersAdapter } = require('../adapters/host-listeners.cjs');
const { HostProcessAdapter } = require('../adapters/host-process.cjs');
const { HostSecurityAdapter } = require('../adapters/host-security.cjs');
const { HostDefenderAdapter } = require('../adapters/host-defender.cjs');
const { HostFilesAdapter } = require('../adapters/host-files.cjs');
const { HttpAccessAdapter } = require('../adapters/http-access.cjs');
const { DbAuditAdapter } = require('../adapters/db-audit.cjs');
const { WebflowAdapter } = require('../adapters/webflow.cjs');
const { ProxyLogAdapter } = require('../adapters/proxy-log.cjs');
const { BaseAdapter } = require('../adapters/base.cjs');
const { makeRunner, makeConfig, disableAllAdapters, tempDir } = require('./helpers.cjs');

function listenerPowerShell(list) {
  return async () => list();
}

function listenerConfig(extra) {
  return Object.assign({ enabled: true, poll_interval_ms: 1000, ignore_ports: [], allow_processes: [] }, extra || {});
}

test('listener baseline: first poll is silent, new port raises one event', async () => {
  let current = [{ address: '0.0.0.0', port: 443, pid: 4, process: 'System' }];
  const adapter = new HostListenersAdapter({
    config: listenerConfig(),
    deps: { powershell: listenerPowerShell(() => current), platform: 'win32', hostname: 'h1' }
  });
  await adapter.init();
  assert.strictEqual(adapter.status, 'ACTIVE');
  const first = await adapter.poll();
  assert.strictEqual(first.events.length, 0, 'baseline establishment must not alert');

  current = current.concat([{ address: '0.0.0.0', port: 4444, pid: 8123, process: 'unknown.exe' }]);
  const second = await adapter.poll();
  assert.strictEqual(second.events.length, 1);
  assert.strictEqual(second.events[0].facts.is_new, true);
  assert.strictEqual(second.events[0].host.port, 4444);
  assert.strictEqual(second.events[0].adapter, 'host.listeners');
});

test('listener baseline survives restore and does not re-alert', async () => {
  let current = [{ address: '0.0.0.0', port: 4444, pid: 8123, process: 'unknown.exe' }];
  const deps = { powershell: listenerPowerShell(() => current), platform: 'win32', hostname: 'h1' };
  const first = new HostListenersAdapter({ config: listenerConfig(), deps });
  await first.init();
  await first.poll();
  const cursor = JSON.parse(JSON.stringify(first.getCursor()));

  const second = new HostListenersAdapter({ config: listenerConfig(), deps });
  second.restoreCursor(cursor);
  await second.init();
  const res = await second.poll();
  assert.strictEqual(res.events.length, 0, 'restart must not re-report known listeners');
});

test('listener removals are recorded without a detection', async () => {
  let current = [{ address: '0.0.0.0', port: 4444, pid: 8123, process: 'x.exe' }];
  const adapter = new HostListenersAdapter({
    config: listenerConfig(),
    deps: { powershell: listenerPowerShell(() => current), platform: 'win32' }
  });
  await adapter.init();
  await adapter.poll();
  current = [];
  const res = await adapter.poll();
  assert.strictEqual(res.events.length, 1);
  assert.strictEqual(res.events[0].facts.change, 'removed');
});

test('allowlisted listener process is still recorded but not scored', async () => {
  let current = [{ address: '0.0.0.0', port: 443, pid: 4, process: 'System' }];
  const adapter = new HostListenersAdapter({
    config: listenerConfig({ allow_processes: ['knownsvc'] }),
    deps: { powershell: listenerPowerShell(() => current), platform: 'win32' }
  });
  await adapter.init();
  await adapter.poll();
  current = current.concat([{ address: '0.0.0.0', port: 9999, pid: 900, process: 'knownsvc' }]);
  const res = await adapter.poll();
  assert.strictEqual(res.events.length, 1);
  assert.strictEqual(res.events[0].facts.allowlisted_process, true);
  const runner = await makeRunner();
  await runner.processRawEvent(res.events[0], { events: 0, alerts: 0, duplicates: 0, allowlisted: 0 });
  assert.strictEqual(runner.recentAlerts.length, 0);
  await runner.stop('test');
});

test('process adapter reads 4688 events and flags temp images', async () => {
  const adapter = new HostProcessAdapter({
    config: { enabled: true, poll_interval_ms: 1000, mode: 'auto' },
    deps: {
      platform: 'win32',
      hostname: 'h1',
      powershell: async (script) => {
        if (script.includes('auditpol')) return 'Process Creation\n    Success and Failure';
        return [{
          ts: '2026-01-15T09:00:00.000Z',
          pid: 8123,
          image: 'C:\\Users\\svc\\AppData\\Local\\Temp\\unknown.exe',
          parent: 'C:\\Windows\\System32\\cmd.exe',
          user: 'svc',
          command_line: 'unknown.exe --dump'
        }];
      }
    }
  });
  await adapter.init();
  assert.strictEqual(adapter.status, 'ACTIVE');
  assert.strictEqual(adapter.detail.mode, 'security-4688');
  const res = await adapter.poll();
  assert.strictEqual(res.events.length, 1);
  assert.strictEqual(res.events[0].facts.from_temp_dir, true);
  assert.strictEqual(res.events[0].host.process, 'unknown.exe');
  assert.strictEqual(res.events[0].host.parent_process, 'cmd.exe');
});

test('process adapter without 4688 auditing degrades to snapshot mode', async () => {
  const adapter = new HostProcessAdapter({
    config: { enabled: true, poll_interval_ms: 1000, mode: 'security' },
    deps: {
      platform: 'win32',
      powershell: async (script) => (script.includes('auditpol') ? 'No Auditing' : [])
    }
  });
  await adapter.init();
  assert.strictEqual(adapter.status, 'UNAVAILABLE');
  assert.match(adapter.reason, /audit policy/);
});

test('security adapter maps failed logons', async () => {
  const adapter = new HostSecurityAdapter({
    config: { enabled: true, poll_interval_ms: 1000, events: [4625] },
    deps: {
      platform: 'win32',
      powershell: async (script) => {
        if (script.includes('WindowsPrincipal')) return { admin: true, user: 'HOST\\audit' };
        return [{ id: 4625, ts: '2026-01-15T09:00:00.000Z', user: 'alice', ip: '203.0.113.5', logon_type: '3', status: '0xc000006d', substatus: '0xc000006a' }];
      }
    }
  });
  await adapter.init();
  assert.strictEqual(adapter.status, 'ACTIVE');
  const res = await adapter.poll();
  assert.strictEqual(res.events.length, 1);
  assert.strictEqual(res.events[0].kind, 'host.session');
  assert.strictEqual(res.events[0].outcome, 'auth_failure');
  assert.strictEqual(res.events[0].facts.windows_event_id, 4625);
});

test('security adapter reports inability without elevation', async () => {
  const adapter = new HostSecurityAdapter({
    config: { enabled: true, poll_interval_ms: 1000, events: [4625] },
    deps: { platform: 'win32', powershell: async () => ({ admin: false, user: 'HOST\\user' }) }
  });
  await adapter.init();
  assert.strictEqual(adapter.status, 'UNAVAILABLE');
  assert.match(adapter.reason, /not elevated/);
});

test('defender adapter maps detection events', async () => {
  const adapter = new HostDefenderAdapter({
    config: { enabled: true, poll_interval_ms: 1000 },
    deps: {
      platform: 'win32',
      powershell: async (script) => {
        if (script.includes('ListLog')) return { exists: true, record_count: 42 };
        return [{ id: 1116, ts: '2026-01-15T09:00:00.000Z', threat: 'Trojan:Win32/Test', action: 'Quarantine', message: 'x' }];
      }
    }
  });
  await adapter.init();
  assert.strictEqual(adapter.status, 'ACTIVE');
  const res = await adapter.poll();
  assert.strictEqual(res.events.length, 1);
  assert.strictEqual(res.events[0].facts.defender_event_id, 1116);
  assert.strictEqual(res.events[0].facts.threat, 'Trojan:Win32/Test');
});

test('file integrity adapter reports modified and deleted files', async () => {
  const dir = tempDir('files');
  const target = path.join(dir, 'app-config.json');
  fs.writeFileSync(target, '{"a":1}');
  const adapter = new HostFilesAdapter({
    config: { enabled: true, paths: [target], poll_interval_ms: 1000 },
    deps: { hostname: 'h1' }
  });
  await adapter.init();
  assert.strictEqual(adapter.status, 'ACTIVE');
  assert.strictEqual((await adapter.poll()).events.length, 0, 'first scan establishes baseline');

  fs.writeFileSync(target, '{"a":2}');
  const changed = await adapter.poll();
  assert.strictEqual(changed.events.length, 1);
  assert.strictEqual(changed.events[0].facts.change, 'modified');
  assert.notStrictEqual(changed.events[0].facts.previous_sha256, changed.events[0].facts.current_sha256);

  fs.unlinkSync(target);
  const deleted = await adapter.poll();
  assert.strictEqual(deleted.events.length, 1);
  assert.strictEqual(deleted.events[0].facts.change, 'deleted');
});

test('file integrity baseline survives a restart and detects offline changes', async () => {
  const dir = tempDir('files-restart');
  const stateDir = tempDir('files-state');
  const target = path.join(dir, 'app.json');
  fs.writeFileSync(target, '{"v":1}');
  const config = { enabled: true, paths: [target], poll_interval_ms: 1000 };

  const first = new HostFilesAdapter({ config, deps: { hostname: 'h1', stateDir } });
  await first.init();
  await first.poll();

  fs.writeFileSync(target, '{"v":2}');
  const second = new HostFilesAdapter({ config, deps: { hostname: 'h1', stateDir } });
  await second.init();
  const res = await second.poll();
  assert.strictEqual(res.events.length, 1);
  assert.strictEqual(res.events[0].facts.change, 'modified');
});

test('http access adapter maps sentinel JSONL and caddy JSON', async () => {
  const dir = tempDir('httplog');
  const file = path.join(dir, 'access.jsonl');
  fs.writeFileSync(file, [
    JSON.stringify({ ts: '2026-01-15T09:00:00.000Z', method: 'GET', path: '/a?page=1', status: 200, bytes_out: 100, ip: '198.51.100.1', principal: 'u1' }),
    JSON.stringify({ ts: 1768467600, request: { method: 'POST', uri: '/login', remote_ip: '198.51.100.2', headers: { 'User-Agent': ['x'] } }, status: 401, size: 50 })
  ].join('\n') + '\n');
  const adapter = new HttpAccessAdapter({
    config: { enabled: true, path: file, format: 'sentinel-jsonl', poll_interval_ms: 1000 },
    deps: {}
  });
  await adapter.init();
  assert.strictEqual(adapter.status, 'ACTIVE');
  const res = await adapter.poll();
  assert.strictEqual(res.events.length, 2);
  assert.strictEqual(res.events[0].kind, 'http.request');
  assert.strictEqual(res.events[0].request.page, 1);

  const caddy = new HttpAccessAdapter({
    config: { enabled: true, path: file, format: 'caddy-json', poll_interval_ms: 1000 },
    deps: {}
  });
  await caddy.init();
  const caddyRes = await caddy.poll();
  assert.strictEqual(caddyRes.events.length, 2);
  assert.strictEqual(caddyRes.events[1].source.ip, '198.51.100.2');
  assert.strictEqual(caddyRes.events[1].outcome, 'auth_failure');
});

test('unconfigured sources report NOT_CONFIGURED, never ACTIVE', async () => {
  const db = new DbAuditAdapter({ config: { enabled: true, path: '' }, deps: {} });
  await db.init();
  assert.strictEqual(db.status, 'NOT_CONFIGURED');
  assert.match(db.reason, /db_audit\.path/);

  const wf = new WebflowAdapter({ config: { enabled: true, log_path: '' }, deps: {} });
  await wf.init();
  assert.strictEqual(wf.status, 'NOT_CONFIGURED');
  assert.match(wf.reason, /Webflow API audit logs are not configured/);

  const proxy = new ProxyLogAdapter({ config: { enabled: true, path: '/nonexistent/x.jsonl', provider: 'cloudflare-logpush' }, deps: {} });
  await proxy.init();
  assert.strictEqual(proxy.status, 'UNAVAILABLE');
});

test('windows adapters report UNAVAILABLE on a non-Windows host', async () => {
  const a = new HostListenersAdapter({ config: listenerConfig(), deps: { platform: 'linux', powershell: async () => [] } });
  await a.init();
  assert.strictEqual(a.status, 'UNAVAILABLE');
  assert.match(a.reason, /requires Windows/);

  const p = new HostProcessAdapter({ config: { enabled: true, mode: 'auto' }, deps: { platform: 'linux' } });
  await p.init();
  assert.strictEqual(p.status, 'UNAVAILABLE');

  const d = new HostDefenderAdapter({ config: { enabled: true }, deps: { platform: 'linux' } });
  await d.init();
  assert.strictEqual(d.status, 'UNAVAILABLE');
});

test('an adapter that cannot read its source does not stop the service', async () => {
  class DeniedAdapter extends BaseAdapter {
    constructor() {
      super({ id: 'test.denied', name: 'Denied source', category: 'test', config: { enabled: true, poll_interval_ms: 1000 }, capabilities: [], limitations: [] });
    }
    async init() {
      const e = new Error('access denied');
      e.code = 'EACCES';
      throw e;
    }
  }
  const config = disableAllAdapters(makeConfig());
  const runner = await makeRunner({ config, adapters: [new DeniedAdapter()] });
  const stats = await runner.cycle();
  assert.strictEqual(stats.adapter_errors, 0);
  const cov = runner.coverage();
  const denied = cov.adapters.find(a => a.id === 'test.denied');
  assert.strictEqual(denied.status, 'UNAVAILABLE');
  assert.match(denied.reason, /EACCES/);
  assert.ok(cov.blind_spots.some(b => b.adapter === 'test.denied'));
  assert.strictEqual(cov.blind_spots.some(b => b.adapter === 'global'), true);
  await runner.stop('test');
});
