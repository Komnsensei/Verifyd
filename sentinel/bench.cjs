'use strict';

// Repeatable resource measurement for the event -> rule -> store path.
// Usage: node sentinel/bench.cjs [eventCount]
// Prints one JSON object; no network, no external services.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { buildConfig } = require('./config.cjs');
const { SentinelRunner } = require('./runner.cjs');
const { http, iso } = require('./simulate.cjs');

async function main() {
  const count = Number(process.argv[2]) || 10000;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-bench-'));
  const { config, errors } = buildConfig({});
  if (errors.length) throw new Error(errors.join('; '));
  config.service.state_dir = dir;
  config.diagnostics.port = 0;
  for (const key of Object.keys(config.adapters)) config.adapters[key].enabled = false;

  const silent = { error() {}, warn() {}, info() {}, debug() {}, child() { return silent; } };
  const runner = new SentinelRunner({ config, adapters: [], logger: silent });
  await runner.init();

  const raws = new Array(count);
  const routes = ['/api/v1/catalog', '/pricing', '/docs', '/api/v1/records'];
  const principals = ['alice', 'bob', 'carol', 'batch-job'];
  for (let i = 0; i < count; i++) {
    raws[i] = http({
      ts: iso(i * 50),
      hint: 'bench:' + i,
      path: routes[i % routes.length],
      principal: principals[i % principals.length],
      ip: '198.51.100.' + (10 + (i % 20)),
      bytes_out: 800 + (i % 7) * 120
    });
  }

  const rssBefore = process.memoryUsage().rss;
  const t0 = process.hrtime.bigint();
  const stats = { events: 0, duplicates: 0, alerts: 0, allowlisted: 0 };
  for (const raw of raws) await runner.processRawEvent(raw, stats);
  const t1 = process.hrtime.bigint();
  const mem = process.memoryUsage();
  const durationMs = Number(t1 - t0) / 1e6;
  const store = runner.store.stats();
  const verifyStart = process.hrtime.bigint();
  const verify = runner.store.verify();
  const verifyMs = Number(process.hrtime.bigint() - verifyStart) / 1e6;

  const result = {
    node: process.version,
    platform: process.platform,
    arch: process.arch,
    events_processed: count,
    alerts: stats.alerts,
    duration_ms: Number(durationMs.toFixed(1)),
    events_per_second: Math.round(count / (durationMs / 1000)),
    rss_before_mb: Number((rssBefore / 1048576).toFixed(1)),
    rss_after_mb: Number((mem.rss / 1048576).toFixed(1)),
    heap_used_mb: Number((mem.heapUsed / 1048576).toFixed(1)),
    external_mb: Number((mem.external / 1048576).toFixed(1)),
    store_files: store.files,
    store_bytes: store.total_bytes,
    verify_ms: Number(verifyMs.toFixed(1)),
    verify_valid: verify.valid,
    state_dir: dir
  };
  await runner.stop('bench');
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  fs.rmSync(dir, { recursive: true, force: true });
}

main().catch(e => {
  process.stderr.write('bench failed: ' + (e.stack || e.message) + '\n');
  process.exit(1);
});
