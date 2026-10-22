'use strict';

// Synthetic events. Deterministic timestamps and ids so sample alerts and tests
// are reproducible. Every scenario is local-only: nothing is sent to a
// third-party system.

const BASE_MS = Date.UTC(2026, 0, 15, 9, 0, 0);

function iso(offsetMs) {
  return new Date(BASE_MS + offsetMs).toISOString();
}

function http(opts) {
  return {
    adapter: 'http.access',
    kind: 'http.request',
    ts: opts.ts,
    hint: opts.hint,
    source: {
      ip: opts.ip || '198.51.100.10',
      principal: Object.prototype.hasOwnProperty.call(opts, 'principal') ? opts.principal : 'user-1',
      user_agent: 'sentinel-sim/1.0'
    },
    request: {
      method: opts.method || 'GET',
      path: opts.path,
      route: opts.route,
      query: opts.query || {},
      bytes_in: opts.bytes_in || 120
    },
    response: { status: opts.status == null ? 200 : opts.status, bytes_out: opts.bytes_out == null ? 2400 : opts.bytes_out, duration_ms: 30 },
    host: { hostname: 'sim-web-01', service: 'api' },
    facts: opts.facts || {}
  };
}

function scenarioNormal(count) {
  const out = [];
  const routes = ['/', '/pricing', '/api/v1/catalog', '/api/v1/catalog?page=1', '/docs'];
  for (let i = 0; i < (count || 40); i++) {
    const path = routes[i % routes.length];
    out.push(http({
      ts: iso(i * 3000),
      hint: 'sim:normal:' + i,
      path,
      principal: i % 3 === 0 ? 'alice' : 'bob',
      ip: i % 2 === 0 ? '198.51.100.10' : '198.51.100.11',
      bytes_out: 1800 + (i % 5) * 400
    }));
  }
  return out;
}

function scenarioAuthFail() {
  const out = [];
  for (let i = 0; i < 6; i++) {
    out.push(http({
      ts: iso(i * 8000),
      hint: 'sim:authfail:' + i,
      path: '/api/v1/session',
      principal: 'alice',
      ip: '203.0.113.9',
      method: 'POST',
      status: 401,
      bytes_out: 90
    }));
  }
  out.push(http({
    ts: iso(52000),
    hint: 'sim:authfail:success',
    path: '/api/v1/session',
    principal: 'alice',
    ip: '203.0.113.9',
    method: 'POST',
    status: 200,
    bytes_out: 1200
  }));
  return out;
}

function scenarioEnumeration() {
  const out = [];
  for (let page = 1; page <= 12; page++) {
    out.push(http({
      ts: iso(page * 4000),
      hint: 'sim:enum:' + page,
      path: '/api/v1/records?page=' + page + '&limit=100',
      principal: 'contractor-7',
      ip: '203.0.113.44',
      query: { page: String(page), limit: '100' },
      bytes_out: 42000
    }));
  }
  return out;
}

function scenarioBulk() {
  return [
    http({
      ts: iso(0),
      hint: 'sim:bulk:export',
      path: '/api/v1/export?limit=100000',
      principal: 'contractor-7',
      ip: '203.0.113.44',
      query: { limit: '100000' },
      bytes_out: 3 * 1024 * 1024
    })
  ];
}

function scenarioUnauthorized() {
  return [
    http({
      ts: iso(0),
      hint: 'sim:unauthz:admin',
      path: '/admin/users',
      principal: null,
      ip: '203.0.113.77',
      status: 200,
      bytes_out: 88000
    })
  ];
}

function scenarioDeniedThenSuccess() {
  return [
    http({ ts: iso(0), hint: 'sim:dts:denied', path: '/api/v1/payroll/2026', principal: 'alice', ip: '198.51.100.10', status: 403, bytes_out: 60 }),
    http({ ts: iso(15000), hint: 'sim:dts:success', path: '/api/v1/payroll/2026', principal: 'alice', ip: '198.51.100.10', status: 200, bytes_out: 64000 })
  ];
}

function scenarioHost() {
  return [
    {
      adapter: 'host.listeners',
      kind: 'host.listener',
      ts: iso(0),
      hint: 'listener:add:0.0.0.0:4444',
      outcome: 'observed',
      host: { address: '0.0.0.0', port: 4444, pid: 8123, process: 'unknown.exe', hostname: 'sim-host' },
      facts: { change: 'added', is_new: true, baseline_ports: 12, allowlisted_process: false, first_seen: iso(0) }
    },
    {
      adapter: 'host.process',
      kind: 'host.process',
      ts: iso(2000),
      hint: '4688:8123:' + iso(2000),
      outcome: 'observed',
      host: { pid: 8123, process: 'unknown.exe', path: 'C:\\Users\\svc\\AppData\\Local\\Temp\\unknown.exe', parent_process: 'cmd.exe', user: 'svc', hostname: 'sim-host' },
      facts: { source: 'security-4688', from_temp_dir: true, command_line: 'unknown.exe --dump', command_line_available: true }
    },
    {
      adapter: 'host.defender',
      kind: 'host.defender',
      ts: iso(4000),
      hint: 'defender:1116:' + iso(4000),
      outcome: 'observed',
      host: { hostname: 'sim-host' },
      facts: { defender_event_id: 1116, threat: 'Trojan:Win32/Simulated', action: 'Quarantine', log: 'Microsoft-Windows-Windows Defender/Operational' }
    }
  ];
}

const SCENARIOS = {
  normal: { name: 'normal browsing', build: scenarioNormal },
  'auth-fail': { name: 'repeated failed logins', build: scenarioAuthFail },
  enumeration: { name: 'sequential pagination', build: scenarioEnumeration },
  bulk: { name: 'bulk export', build: scenarioBulk },
  unauthorized: { name: 'unauthorized protected access', build: scenarioUnauthorized },
  'denied-then-success': { name: 'denied then success', build: scenarioDeniedThenSuccess },
  host: { name: 'host listener/process/defender', build: scenarioHost }
};

function buildScenario(name) {
  const s = SCENARIOS[name];
  if (!s) throw new Error('unknown scenario: ' + name);
  return s.build();
}

function allScenarios() {
  return Object.keys(SCENARIOS);
}

module.exports = { SCENARIOS, buildScenario, allScenarios, iso, http, BASE_MS };
