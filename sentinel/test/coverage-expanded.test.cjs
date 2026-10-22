'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { HostPersistenceAdapter } = require('../adapters/host-persistence.cjs');
const { HostFileAuditAdapter } = require('../adapters/host-fileaudit.cjs');
const { HostSysmonAdapter } = require('../adapters/host-sysmon.cjs');
const { HostDnsAdapter } = require('../adapters/host-dns.cjs');
const { HostSecurityAdapter } = require('../adapters/host-security.cjs');
const { CloudAuditAdapter } = require('../adapters/cloud-audit.cjs');
const { SqlServerAdapter } = require('../adapters/sqlserver.cjs');
const { SaasAuditAdapter } = require('../adapters/saas-audit.cjs');
const { NetworkSensorAdapter } = require('../adapters/network-sensor.cjs');
const { createAccessLogger } = require('../integrations/http-middleware.cjs');
const { HttpAccessAdapter } = require('../adapters/http-access.cjs');
const { Anchor } = require('../anchor.cjs');
const { makeRunner, makeConfig, disableAllAdapters, tempDir, withServer, feed } = require('./helpers.cjs');

test('persistence adapter maps registry 4657, scheduled-task 4698 and WMI 5861 events and raises rules', async () => {
  const adapter = new HostPersistenceAdapter({
    config: { enabled: true, poll_interval_ms: 1000 },
    deps: {
      platform: 'win32',
      hostname: 'win-host',
      powershell: async (script) => {
        if (script.includes('ListLog')) {
          return {
            security: { enabled: true, records: 100 },
            wmi: { enabled: true, records: 20 },
            audit: 'Registry Success and Failure\nOther Object Access Events Success and Failure'
          };
        }
        return [
          {
            channel: 'Security',
            id: 4657,
            ts: '2026-01-15T10:00:00.000Z',
            record_id: 1,
            user: 'admin',
            process: 'C:\\Windows\\System32\\reg.exe',
            object_name: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater',
            operation: '%%1904'
          },
          {
            channel: 'Security',
            id: 4698,
            ts: '2026-01-15T10:00:01.000Z',
            record_id: 2,
            user: 'admin',
            process: 'C:\\Windows\\System32\\schtasks.exe',
            task_name: '\\PersistenceTask',
            task_content: '<Task><Exec><Command>cmd.exe</Command></Exec></Task>'
          },
          {
            channel: 'WMI-Activity',
            id: 5861,
            ts: '2026-01-15T10:00:02.000Z',
            record_id: 3,
            operation: 'permanent_subscription',
            task_content: 'Namespace = //./root/subscription; Consumer = CommandLineEventConsumer'
          }
        ];
      }
    }
  });
  await adapter.init();
  assert.strictEqual(adapter.status, 'ACTIVE');
  const res = await adapter.poll();
  assert.strictEqual(res.events.length, 3);
  assert.strictEqual(res.events[0].kind, 'host.registry');
  assert.strictEqual(res.events[1].kind, 'host.scheduled_task');
  assert.strictEqual(res.events[2].kind, 'host.wmi_subscription');

  const runner = await makeRunner();
  await feed(runner, res.events);
  const rules = runner.recentAlerts.map(a => a.rule_id);
  assert.ok(rules.includes('PERSISTENCE_CHANGE'));
  assert.ok(rules.includes('WMI_SUBSCRIPTION'));
  await runner.stop('test');
});

test('file audit adapter maps 4663 read/write/delete access flags', async () => {
  const adapter = new HostFileAuditAdapter({
    config: { enabled: true, poll_interval_ms: 1000 },
    deps: {
      platform: 'win32',
      hostname: 'win-host',
      powershell: async (script) => {
        if (script.includes('ListLog')) {
          return { security: { enabled: true, records: 50 }, audit: 'File System Success and Failure' };
        }
        return [
          {
            ts: '2026-01-15T10:05:00.000Z',
            record_id: 10,
            user: 'svc_app',
            process: 'C:\\Program Files\\App\\reader.exe',
            object_name: 'C:\\Data\\customers.csv',
            object_type: 'File',
            access_mask: '0x1',
            access_list: 'ReadData (or ListDirectory)'
          },
          {
            ts: '2026-01-15T10:05:01.000Z',
            record_id: 11,
            user: 'svc_app',
            process: 'C:\\Program Files\\App\\writer.exe',
            object_name: 'C:\\Data\\customers.csv',
            object_type: 'File',
            access_mask: '0x10000',
            access_list: 'DELETE'
          }
        ];
      }
    }
  });
  await adapter.init();
  assert.strictEqual(adapter.status, 'ACTIVE');
  const res = await adapter.poll();
  assert.strictEqual(res.events.length, 2);
  assert.strictEqual(res.events[0].kind, 'host.file_access');
  assert.strictEqual(res.events[0].outcome, 'read');
  assert.strictEqual(res.events[0].facts.read, true);
  assert.strictEqual(res.events[1].outcome, 'removed');
  assert.strictEqual(res.events[1].facts.delete, true);
});

test('sysmon adapter maps process 1, network 3, dns 22, wmi 20 and process tamper 25', async () => {
  const adapter = new HostSysmonAdapter({
    config: { enabled: true, poll_interval_ms: 1000 },
    deps: {
      platform: 'win32',
      hostname: 'win-host',
      powershell: async (script) => {
        if (script.includes('ListLog')) return { exists: true, enabled: true, records: 300 };
        return [
          { id: 1, ts: '2026-01-15T10:10:00.000Z', record_id: 1, data: { ProcessId: '4100', Image: 'C:\\Users\\bob\\AppData\\Local\\Temp\\drop.exe', ParentImage: 'C:\\Windows\\System32\\cmd.exe', User: 'HOST\\bob', CommandLine: 'drop.exe -q' } },
          { id: 3, ts: '2026-01-15T10:10:01.000Z', record_id: 2, data: { Image: 'C:\\Windows\\System32\\curl.exe', SourceIp: '10.0.0.5', SourcePort: '51000', DestinationIp: '198.51.100.88', DestinationPort: '443', Protocol: 'tcp', Initiated: 'true' } },
          { id: 22, ts: '2026-01-15T10:10:02.000Z', record_id: 3, data: { Image: 'C:\\Windows\\System32\\curl.exe', QueryName: 'exfil.example.test', QueryType: 'A', QueryStatus: '0', QueryResults: '198.51.100.88' } },
          { id: 20, ts: '2026-01-15T10:10:03.000Z', record_id: 4, data: { Image: 'C:\\Windows\\System32\\wbem\\scrcons.exe', Consumer: 'evil', EventType: 'WmiConsumerEvent' } },
          { id: 25, ts: '2026-01-15T10:10:04.000Z', record_id: 5, data: { Image: 'C:\\Users\\bob\\AppData\\Local\\Temp\\hollow.exe', Type: 'Image is replaced' } }
        ];
      }
    }
  });
  await adapter.init();
  assert.strictEqual(adapter.status, 'ACTIVE');
  const res = await adapter.poll();
  assert.strictEqual(res.events.length, 5);

  const runner = await makeRunner();
  await feed(runner, res.events);
  const rules = runner.recentAlerts.map(a => a.rule_id);
  assert.ok(rules.includes('PROCESS_FROM_TEMP'));
  assert.ok(rules.includes('WMI_SUBSCRIPTION'));
  assert.ok(rules.includes('SYSMON_PROCESS_TAMPER'));
  await runner.stop('test');
});

test('dns client and security 4673 adapters map events cleanly', async () => {
  const dns = new HostDnsAdapter({
    config: { enabled: true, poll_interval_ms: 1000 },
    deps: {
      platform: 'win32',
      hostname: 'win-host',
      powershell: async (script) => {
        if (script.includes('ListLog')) return { exists: true, enabled: true, records: 12 };
        return [{ ts: '2026-01-15T10:12:00.000Z', record_id: 7, query_name: 'api.internal', query_type: '1', query_status: 'No Error', query_results: '10.0.0.10' }];
      }
    }
  });
  await dns.init();
  assert.strictEqual(dns.status, 'ACTIVE');
  const dnsRes = await dns.poll();
  assert.strictEqual(dnsRes.events.length, 1);
  assert.strictEqual(dnsRes.events[0].kind, 'host.dns');
  assert.strictEqual(dnsRes.events[0].outcome, 'success');

  const sec = new HostSecurityAdapter({
    config: { enabled: true, poll_interval_ms: 1000 },
    deps: {
      platform: 'win32',
      powershell: async (script) => {
        if (script.includes('WindowsPrincipal')) return { admin: true, user: 'HOST\\admin' };
        return [{ id: 4673, ts: '2026-01-15T10:12:05.000Z', subject: 'svc_backup', privileges: 'SeDebugPrivilege', process: 'C:\\Tools\\proc.exe', service: 'Winmgmt' }];
      }
    }
  });
  await sec.init();
  const secRes = await sec.poll();
  assert.strictEqual(secRes.events.length, 1);
  assert.strictEqual(secRes.events[0].outcome, 'privileged_operation');
  assert.strictEqual(secRes.events[0].facts.privileges, 'SeDebugPrivilege');
});

test('cloud audit adapter maps CloudTrail, Azure Activity and GCP Audit and raises CLOUD_PRIVILEGE_CHANGE', async () => {
  const dir = tempDir('cloud');
  const awsFile = path.join(dir, 'aws.jsonl');
  fs.writeFileSync(awsFile, JSON.stringify({
    Records: [{
      eventTime: '2026-01-15T10:20:00.000Z',
      eventSource: 'iam.amazonaws.com',
      eventName: 'AttachUserPolicy',
      awsRegion: 'us-east-1',
      sourceIPAddress: '203.0.113.55',
      userIdentity: { arn: 'arn:aws:iam::123456789012:user/admin', accountId: '123456789012' },
      requestParameters: { roleName: 'ProdAdmin' }
    }]
  }) + '\n');

  const aws = new CloudAuditAdapter({ config: { enabled: true, path: awsFile, provider: 'aws-cloudtrail' }, deps: {} });
  await aws.init();
  assert.strictEqual(aws.status, 'ACTIVE');
  const awsEvents = (await aws.poll()).events;
  assert.strictEqual(awsEvents.length, 1);
  assert.strictEqual(awsEvents[0].facts.privilege_change, true);

  const runner = await makeRunner();
  await feed(runner, awsEvents);
  assert.ok(runner.recentAlerts.some(a => a.rule_id === 'CLOUD_PRIVILEGE_CHANGE'));
  await runner.stop('test');
});

test('sqlserver live adapter maps active DMV sessions and raises DB_LIVE_BULK_READ', async () => {
  const adapter = new SqlServerAdapter({
    config: { enabled: true, server: 'localhost', database: 'OrdersDb', poll_interval_ms: 1000 },
    deps: {
      platform: 'win32',
      hostname: 'sql-host',
      powershell: async (script) => {
        if (script.includes('@@VERSION')) return { ok: true, database: 'OrdersDb', version: 'Microsoft SQL Server 2022' };
        return [{
          session_id: 58,
          login_name: 'svc_etl',
          host_name: 'app01',
          program_name: 'etl-worker',
          session_status: 'running',
          request_status: 'running',
          command: 'SELECT',
          cpu_time: 1200,
          reads: 5000,
          writes: 0,
          logical_reads: 250000,
          total_elapsed_time: 4000,
          wait_type: 'PAGEIOLATCH_SH',
          blocking_session_id: null,
          database_name: 'OrdersDb',
          statement_text: 'SELECT * FROM dbo.Customers'
        }];
      }
    }
  });
  await adapter.init();
  assert.strictEqual(adapter.status, 'ACTIVE');
  const res = await adapter.poll();
  assert.strictEqual(res.events.length, 1);
  assert.strictEqual(res.events[0].kind, 'db.session');

  const runner = await makeRunner();
  await feed(runner, res.events);
  assert.ok(runner.recentAlerts.some(a => a.rule_id === 'DB_LIVE_BULK_READ'));
  await runner.stop('test');
});

test('saas audit adapter pulls events over authenticated loopback HTTP', async () => {
  process.env.SENTINEL_TEST_SAAS_TOKEN = 'saas-token-123';
  try {
    await withServer((req, res) => {
      assert.strictEqual(req.headers.authorization, 'Bearer saas-token-123');
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        events: [{ id: 'ev1', ts: '2026-01-15T10:30:00.000Z', actor_email: 'ops@example.com', ip: '198.51.100.12', action: 'user.export', resource: 'org/1', status: 'success' }]
      }));
    }, async (port) => {
      const adapter = new SaasAuditAdapter({
        config: {
          enabled: true,
          url: 'http://127.0.0.1:' + port + '/audit',
          token_env: 'SENTINEL_TEST_SAAS_TOKEN',
          records_path: 'events',
          since_param: 'since',
          allow_insecure_loopback: true
        },
        deps: {}
      });
      await adapter.init();
      assert.strictEqual(adapter.status, 'ACTIVE');
      const res = await adapter.poll();
      assert.strictEqual(res.events.length, 1);
      assert.strictEqual(res.events[0].kind, 'saas.audit');
      assert.strictEqual(res.events[0].source.principal, 'ops@example.com');
    });
  } finally {
    delete process.env.SENTINEL_TEST_SAAS_TOKEN;
  }
});

test('network sensor adapter maps Zeek and Suricata records and raises bulk/IDS alerts', async () => {
  const dir = tempDir('net');
  const file = path.join(dir, 'sensor.jsonl');
  fs.writeFileSync(file, [
    JSON.stringify({ _path: 'conn', ts: '2026-01-15T10:40:00.000Z', uid: 'C1', 'id.orig_h': '10.0.0.4', 'id.orig_p': 55111, 'id.resp_h': '198.51.100.200', 'id.resp_p': 443, proto: 'tcp', service: 'ssl', orig_bytes: 60000000, resp_bytes: 12000, conn_state: 'SF' }),
    JSON.stringify({ _path: 'ssl', ts: '2026-01-15T10:40:01.000Z', uid: 'C1', 'id.orig_h': '10.0.0.4', 'id.resp_h': '198.51.100.200', 'id.resp_p': 443, server_name: 'cdn.example.net', version: 'TLSv13', cipher: 'TLS_AES_256_GCM_SHA384', established: true }),
    JSON.stringify({ event_type: 'alert', timestamp: '2026-01-15T10:40:02.000Z', flow_id: 99, src_ip: '10.0.0.4', src_port: 55111, dest_ip: '198.51.100.200', dest_port: 443, proto: 'TCP', alert: { signature: 'ET POLICY Outbound Bulk Transfer', signature_id: 2020001, category: 'Policy', severity: 1, action: 'allowed' } })
  ].join('\n') + '\n');

  const adapter = new NetworkSensorAdapter({ config: { enabled: true, path: file, provider: 'auto' }, deps: {} });
  await adapter.init();
  assert.strictEqual(adapter.status, 'ACTIVE');
  const res = await adapter.poll();
  assert.strictEqual(res.events.length, 3);
  assert.strictEqual(res.events[0].kind, 'network.flow');
  assert.strictEqual(res.events[1].kind, 'network.tls');
  assert.strictEqual(res.events[2].kind, 'network.alert');

  const runner = await makeRunner();
  await feed(runner, res.events);
  const rules = runner.recentAlerts.map(a => a.rule_id);
  assert.ok(rules.includes('NETWORK_BULK_TRANSFER'));
  assert.ok(rules.includes('NETWORK_IDS_ALERT'));
  await runner.stop('test');
});

test('HTTP middleware records body sha256 and JSON skeleton without storing raw body values', async () => {
  const dir = tempDir('bodyshape');
  const logPath = path.join(dir, 'access.jsonl');
  const access = createAccessLogger({ logPath, service: 'shape-api' });

  await withServer((req, res) => {
    access.middleware(req, res);
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ items: [{ id: 1, secret_value: 'never-persist-this-value' }], total: 1 }));
    });
  }, async (port) => {
    const r = await fetch('http://127.0.0.1:' + port + '/api/query', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ filter: 'sensitive-query-string', limit: 50 })
    });
    assert.strictEqual(r.status, 200);
    await r.text();
  });

  const raw = fs.readFileSync(logPath, 'utf8');
  assert.ok(!raw.includes('never-persist-this-value'), 'response body value must not be logged');
  assert.ok(!raw.includes('sensitive-query-string'), 'request body value must not be logged');
  const rec = JSON.parse(raw.trim());
  assert.match(rec.request_body_sha256, /^[0-9a-f]{64}$/);
  assert.match(rec.response_body_sha256, /^[0-9a-f]{64}$/);
  assert.strictEqual(rec.request_body_shape.type, 'object');
  assert.deepStrictEqual(rec.request_body_shape.keys, ['filter', 'limit']);
  assert.strictEqual(rec.response_body_shape.fields.items, 'array:1');

  const adapter = new HttpAccessAdapter({ config: { enabled: true, path: logPath }, deps: {} });
  await adapter.init();
  const polled = await adapter.poll();
  assert.strictEqual(polled.events.length, 1);
  assert.strictEqual(polled.events[0].request.body_sha256, rec.request_body_sha256);
  assert.strictEqual(polled.events[0].response.body_shape.fields.items, 'array:1');
});

test('off-host anchor publishes chain head and detects rollback or head mismatch', async () => {
  const stateDir = tempDir('anchor-state');
  const anchorDir = tempDir('anchor-out');
  const anchorPath = path.join(anchorDir, 'anchor.json');
  const config = disableAllAdapters(makeConfig({
    store: { anchor: { path: anchorPath, interval_ms: 1000 } }
  }));
  const runner = await makeRunner({ config, stateDir });
  await feed(runner, [{
    adapter: 'http.access',
    kind: 'http.request',
    ts: '2026-01-15T11:00:00.000Z',
    request: { method: 'GET', path: '/ok' },
    response: { status: 200, bytes_out: 10 }
  }]);
  await runner.cycle();
  assert.ok(fs.existsSync(anchorPath), 'anchor file should be published after cycle');

  const anchor = new Anchor({ path: anchorPath, hostname: os.hostname() });
  const match = anchor.verify(runner.store, os.hostname());
  assert.strictEqual(match.ok, true);
  assert.strictEqual(match.status, 'MATCH');

  // Simulate an attacker rolling back or editing the local head while the off-host anchor remains intact.
  const rollback = anchor.verify({ head: 'GENESIS', seq: 0, records: 0 }, os.hostname());
  assert.strictEqual(rollback.ok, false);
  assert.strictEqual(rollback.status, 'ROLLBACK');

  const mismatch = anchor.verify({ head: '0'.repeat(64), seq: runner.store.seq, records: runner.store.seq }, os.hostname());
  assert.strictEqual(mismatch.ok, false);
  assert.strictEqual(mismatch.status, 'HEAD_MISMATCH');
  await runner.stop('test');
});
