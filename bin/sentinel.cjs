#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { loadConfig, secretEnvNames, secretPresence } = require('../sentinel/config.cjs');
const { createService } = require('../sentinel/index.cjs');
const { SentinelRunner } = require('../sentinel/runner.cjs');
const { EventStore } = require('../sentinel/store.cjs');
const { Anchor } = require('../sentinel/anchor.cjs');
const { RULE_DEFS } = require('../sentinel/rules.cjs');
const { buildScenario, allScenarios } = require('../sentinel/simulate.cjs');
const { buildEvent } = require('../sentinel/event.cjs');
const { VERSION } = require('../sentinel/version.cjs');
const { createLogger, createFileSink } = require('../sentinel/logging.cjs');

const EXIT = { OK: 0, CONFIG: 2, VERIFY: 3, RUNTIME: 4 };

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next && !next.startsWith('--')) {
        args[key] = next;
        i += 1;
      } else {
        args[key] = true;
      }
    } else {
      args._.push(a);
    }
  }
  return args;
}

function usage() {
  return [
    'SENTINEL - defensive data-access monitoring (v' + VERSION + ')',
    '',
    'USAGE',
    '  node bin/sentinel.cjs <command> [options]',
    '',
    'COMMANDS',
    '  run                 Start the monitoring service (detection-only by default)',
    '  once                Run a single collection/detection cycle and exit',
    '  status              Probe adapters and print the current service snapshot',
    '  coverage            Print the monitoring coverage matrix and blind spots',
    '  verify              Verify the evidence hash chain',
    '  rules               Print the deterministic scoring rubric',
    '  simulate [name]     Feed synthetic events through the real pipeline',
    '  config-check        Validate configuration and report secret variable names',
    '  rotate              Force a store rotation',
    '  prune               Apply retention rules to rotated evidence files',
    '  webhook-test        Enqueue and flush one synthetic alert',
    '',
    'OPTIONS',
    '  --config <path>     Configuration file (default: ./sentinel/config.json)',
    '  --state-dir <path>  Override service.state_dir',
    '  --scenario <name>   Scenario for simulate; "all" runs every scenario',
    '  --json              Machine-readable output where supported',
    '  --port <n>          Override diagnostics.port for run',
    '  --log-file <path>   Also append JSON logs to this file (10MB rotation)',
    '  --quiet             Only errors on stderr',
    '',
    'Scenarios: ' + allScenarios().join(', ')
  ].join('\n');
}

function configPathFrom(args) {
  if (args.config) return path.resolve(args.config);
  const local = path.resolve('sentinel/config.json');
  if (fs.existsSync(local)) return local;
  return null;
}

function applyOverrides(config, args) {
  const cfg = JSON.parse(JSON.stringify(config));
  if (args['state-dir']) cfg.service.state_dir = path.resolve(args['state-dir']);
  if (args.port) cfg.diagnostics.port = Number(args.port);
  return cfg;
}

function loadOrExit(args) {
  const cfgPath = configPathFrom(args);
  let loaded;
  try {
    loaded = loadConfig(cfgPath);
  } catch (e) {
    process.stderr.write('Cannot load configuration' + (cfgPath ? ' from ' + cfgPath : '') + ': ' + e.message + '\n');
    process.exit(EXIT.CONFIG);
  }
  if (loaded.errors.length) {
    process.stderr.write('Configuration errors:\n' + loaded.errors.map(e => '  - ' + e).join('\n') + '\n');
    process.exit(EXIT.CONFIG);
  }
  if (loaded.warnings.length) {
    process.stderr.write('Configuration warnings:\n' + loaded.warnings.map(w => '  - ' + w).join('\n') + '\n');
  }
  return { config: applyOverrides(loaded.config, args), path: loaded.path, warnings: loaded.warnings };
}

function table(rows, headers) {
  const cols = headers.map((h, i) => Math.max(h.length, ...rows.map(r => String(r[i] == null ? '' : r[i]).length)));
  const line = (cells) => cells.map((c, i) => String(c == null ? '' : c).padEnd(cols[i])).join('  ');
  return [line(headers), cols.map(c => '-'.repeat(c)).join('  '), ...rows.map(line)].join('\n');
}

function combinedSink(logFile) {
  if (!logFile) return undefined;
  const fileSink = createFileSink(logFile);
  return (line) => {
    process.stderr.write(line + '\n');
    fileSink(line);
  };
}

async function cmdRun(args) {
  const loaded = loadOrExit(args);
  const logger = createLogger({
    level: args.quiet ? 'error' : loaded.config.service.log_level,
    sink: combinedSink(args['log-file'])
  });
  const svc = await createService({ config: loaded.config, configPath: loaded.path, logger });
  if (!svc.ok) {
    process.stderr.write('Configuration errors:\n' + svc.errors.map(e => '  - ' + e).join('\n') + '\n');
    return EXIT.CONFIG;
  }
  const snap = svc.snapshot();
  logger.info('sentinel starting', {
    version: VERSION,
    mode: loaded.config.detection.mode,
    state_dir: loaded.config.service.state_dir,
    diagnostics: svc.health ? svc.health.address() : null,
    adapters: snap.adapters.map(a => ({ id: a.id, status: a.status, reason: a.reason })),
    secret_env_names: svc.secret_env_names,
    secret_env_present: svc.secret_env_present
  });
  if (!args.quiet) {
    process.stdout.write('sentinel ' + VERSION + ' running (mode=' + loaded.config.detection.mode + ')\n');
    process.stdout.write('state: ' + loaded.config.service.state_dir + '\n');
    if (svc.health) {
      const addr = svc.health.address();
      process.stdout.write('diagnostics: http://' + addr.bind + ':' + addr.port + ' (auth=' + (addr.require_token ? 'token' : 'none, loopback') + ')\n');
    }
    process.stdout.write('coverage: ' + snap.adapters.filter(a => a.status === 'ACTIVE').length + ' active, ' +
      snap.adapters.filter(a => a.status === 'UNAVAILABLE').length + ' unavailable, ' +
      snap.adapters.filter(a => a.status === 'NOT_CONFIGURED').length + ' not configured\n');
    for (const b of snap.adapters.filter(a => a.status !== 'ACTIVE')) {
      process.stdout.write('  [' + b.status + '] ' + b.id + ': ' + b.reason + '\n');
    }
  }

  let shuttingDown = false;
  const shutdown = async (signal) => {
    if (shuttingDown) return;
    shuttingDown = true;
    process.stdout.write('\nsentinel: shutting down (' + signal + ')\n');
    try {
      await svc.stop(signal);
    } catch (e) {
      process.stderr.write('shutdown error: ' + e.message + '\n');
    }
    process.exit(EXIT.OK);
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));

  svc.runner.start(svc.health);
  const keepAlive = setInterval(() => {}, 1 << 30);
  process.on('exit', () => clearInterval(keepAlive));
  return new Promise(() => {});
}

async function cmdOnce(args) {
  const loaded = loadOrExit(args);
  const logger = createLogger({ level: args.quiet ? 'error' : loaded.config.service.log_level });
  const svc = await createService({ config: loaded.config, withHealth: false, logger });
  const stats = await svc.runner.cycle();
  const snap = svc.snapshot();
  await svc.stop('once');
  if (args.json) {
    process.stdout.write(JSON.stringify({
      stats,
      health: snap.health,
      adapters: snap.adapters,
      counters: snap.counters,
      recent_alerts: snap.recent_alerts,
      store: snap.store
    }, null, 2) + '\n');
  } else {
    process.stdout.write('cycle: ' + stats.events + ' events, ' + stats.alerts + ' alerts, ' +
      stats.duplicates + ' duplicates, ' + stats.adapter_errors + ' adapter errors, ' + stats.duration_ms + 'ms\n');
    process.stdout.write('health: ' + snap.health.status + ' | store ok: ' + snap.health.store_writable + ' | chain ok: ' + snap.health.chain_ok + '\n');
    for (const a of snap.adapters) process.stdout.write('  [' + a.status + '] ' + a.id + ': ' + a.reason + '\n');
  }
  return EXIT.OK;
}

async function cmdStatus(args) {
  const loaded = loadOrExit(args);
  const svc = await createService({ config: loaded.config, withHealth: false, logger: createLogger({ level: 'error' }) });
  const snap = svc.snapshot();
  await svc.stop('status');
  if (args.json) {
    process.stdout.write(JSON.stringify(snap, null, 2) + '\n');
    return EXIT.OK;
  }
  process.stdout.write('SENTINEL ' + VERSION + '\n');
  process.stdout.write('health: ' + snap.health.status + ' (uptime ' + snap.health.uptime_s + 's, cycles ' + snap.health.cycles + ')\n');
  process.stdout.write('mode: ' + snap.detection.mode + ' | alerts: ' + snap.counters.alerts + ' | events: ' + snap.counters.events + '\n');
  process.stdout.write('store: ' + snap.store.current_file + ' seq=' + snap.store.seq + ' util=' + (snap.store.utilization * 100).toFixed(1) + '%\n');
  process.stdout.write('dispatcher: ' + snap.dispatcher.status + ' queued=' + snap.dispatcher.queued + ' delivered=' + snap.dispatcher.delivered + '\n');
  process.stdout.write('actions: ' + (snap.actions.eligible ? 'armed' : 'not armed') + ' dry_run=' + snap.actions.dry_run + '\n');
  process.stdout.write('\n' + table(snap.adapters.map(a => [a.id, a.status, a.reason]), ['ADAPTER', 'STATUS', 'REASON']) + '\n');
  return EXIT.OK;
}

async function cmdCoverage(args) {
  const loaded = loadOrExit(args);
  const svc = await createService({ config: loaded.config, withHealth: false, logger: createLogger({ level: 'error' }) });
  const cov = svc.runner.coverage();
  await svc.stop('coverage');
  if (args.json) {
    process.stdout.write(JSON.stringify(cov, null, 2) + '\n');
    return EXIT.OK;
  }
  process.stdout.write('MONITORING COVERAGE (' + cov.generated_at + ')\n');
  process.stdout.write('mode: ' + cov.mode + ' | active ' + cov.summary.active + ', unavailable ' + cov.summary.unavailable + ', not configured ' + cov.summary.not_configured + '\n\n');
  process.stdout.write(table(cov.adapters.map(a => [a.id, a.category, a.status, a.reason]), ['ADAPTER', 'CATEGORY', 'STATUS', 'DETAIL']) + '\n\n');
  process.stdout.write('BLIND SPOTS\n');
  for (const b of cov.blind_spots) {
    process.stdout.write('  [' + b.status + '] ' + b.adapter + ': ' + b.reason + '\n');
    for (const l of b.limitations || []) process.stdout.write('      - ' + l + '\n');
  }
  return EXIT.OK;
}

function cmdVerify(args) {
  const loaded = loadOrExit(args);
  const store = new EventStore({
    dir: loaded.config.service.state_dir,
    maxBytes: loaded.config.store.max_bytes,
    maxFiles: loaded.config.store.max_files,
    retentionDays: loaded.config.store.retention_days
  });
  store.open();
  const result = store.verify();
  store.close();
  const anchorCfg = (loaded.config.store && loaded.config.store.anchor) || {};
  const anchorPath = args.anchor ? path.resolve(args.anchor) : anchorCfg.path;
  if (anchorPath) {
    const anchor = new Anchor({ path: anchorPath, hostname: os.hostname() });
    result.anchor = anchor.verify({ head: result.head, seq: result.last_seq, records: result.records }, os.hostname());
    if (result.anchor.ok === false) {
      result.valid = false;
      result.errors.push({ file: path.basename(anchorPath), line: 1, code: 'ANCHOR_' + result.anchor.status, detail: result.anchor.reason });
    }
  }
  if (args.json) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } else {
    process.stdout.write('Chain valid: ' + result.valid + '\n');
    if (result.empty_store) {
      process.stdout.write('note: no evidence files found; nothing was verified\n');
    }
    process.stdout.write('records: ' + result.records + ' (events ' + result.events + ', alerts ' + result.alerts + ')\n');
    process.stdout.write('head: ' + result.head + '\n');
    if (result.anchor) process.stdout.write('anchor: ' + result.anchor.status + ' (' + (result.anchor.reason || 'matched') + ')\n');
    if (result.truncated_tail) process.stdout.write('note: a torn final line was ignored (crash-consistent append)\n');
    for (const e of result.errors.slice(0, 20)) process.stdout.write('  ERROR ' + e.file + ':' + e.line + ' ' + e.code + ' ' + JSON.stringify(e) + '\n');
  }
  return result.valid ? EXIT.OK : EXIT.VERIFY;
}

function cmdRules(args) {
  const loaded = loadOrExit(args);
  const cfg = loaded.config.detection;
  const rows = RULE_DEFS.map(def => {
    const c = cfg.rules[def.score_key] || {};
    const enabled = c.enabled !== false;
    return [def.id, enabled ? 'on' : 'off', c.score != null ? c.score : '-', def.title];
  });
  if (args.json) {
    process.stdout.write(JSON.stringify(RULE_DEFS.map(def => ({
      id: def.id,
      title: def.title,
      enabled: (cfg.rules[def.score_key] || {}).enabled !== false,
      config: cfg.rules[def.score_key] || {}
    })), null, 2) + '\n');
    return EXIT.OK;
  }
  process.stdout.write('DETERMINISTIC RUBRIC (initial tuning values, not calibrated probabilities)\n\n');
  process.stdout.write(table(rows, ['RULE', 'ENABLED', 'SCORE', 'DESCRIPTION']) + '\n');
  process.stdout.write('\nseverity: ' + JSON.stringify(cfg.severity_thresholds) + '\n');
  process.stdout.write('window_ms: ' + cfg.window_ms + ' | dedupe_cooldown_ms: ' + cfg.dedupe_cooldown_ms + ' | min_alert_score: ' + cfg.min_alert_score + '\n');
  return EXIT.OK;
}

async function cmdSimulate(args) {
  const loaded = loadOrExit(args);
  const names = args.scenario && args.scenario !== 'all'
    ? [args.scenario]
    : (args.scenario === 'all' ? allScenarios() : ['normal', 'auth-fail', 'enumeration', 'bulk', 'unauthorized']);
  const results = [];
  for (const name of names) {
    const dir = path.join(os.tmpdir(), 'sentinel-sim-' + process.pid + '-' + name + '-' + Date.now());
    const cfg = JSON.parse(JSON.stringify(loaded.config));
    cfg.service.state_dir = dir;
    cfg.adapters = Object.fromEntries(Object.keys(cfg.adapters).map(k => [k, Object.assign({}, cfg.adapters[k], { enabled: false })]));
    cfg.diagnostics.port = 0;
    const logger = createLogger({ level: 'error' });
    const runner = new SentinelRunner({ config: cfg, adapters: [], logger });
    await runner.init();
    const raws = buildScenario(name);
    for (const raw of raws) {
      await runner.processRawEvent(raw, { events: 0, duplicates: 0, alerts: 0, allowlisted: 0 });
    }
    const alerts = runner.recentAlerts.slice();
    const verify = runner.store.verify();
    await runner.stop('simulate');
    results.push({
      scenario: name,
      events: raws.length,
      alerts: alerts.map(a => ({
        rule_id: a.rule_id,
        severity: a.severity,
        score: a.score,
        title: a.title,
        entity: a.entity,
        evidence: a.evidence,
        recommended_response: a.recommended_response
      })),
      chain_valid: verify.valid,
      state_dir: dir
    });
  }
  if (args.json) {
    process.stdout.write(JSON.stringify(results, null, 2) + '\n');
    return EXIT.OK;
  }
  for (const r of results) {
    process.stdout.write('\nSCENARIO ' + r.scenario + ': ' + r.events + ' events, ' + r.alerts.length + ' alert(s), chain valid=' + r.chain_valid + '\n');
    for (const a of r.alerts) {
      process.stdout.write('  [' + a.severity.toUpperCase() + ' ' + a.score + '] ' + a.rule_id + ' - ' + a.title + '\n');
      process.stdout.write('    entity: ' + JSON.stringify(a.entity) + '\n');
      process.stdout.write('    evidence: ' + JSON.stringify(a.evidence).slice(0, 400) + '\n');
    }
    if (r.alerts.length === 0) process.stdout.write('  no detections (expected for normal browsing)\n');
    process.stdout.write('  state: ' + r.state_dir + '\n');
  }
  return EXIT.OK;
}

function cmdConfigCheck(args) {
  const cfgPath = configPathFrom(args);
  const loaded = loadConfig(cfgPath);
  const names = secretEnvNames(loaded.config);
  const presence = secretPresence(process.env, names);
  if (args.json) {
    process.stdout.write(JSON.stringify({
      path: loaded.path,
      errors: loaded.errors,
      warnings: loaded.warnings,
      secret_env_names: names,
      secret_env_present: presence
    }, null, 2) + '\n');
  } else {
    process.stdout.write('config: ' + (loaded.path || '(defaults)') + '\n');
    process.stdout.write('errors: ' + (loaded.errors.length ? '\n  - ' + loaded.errors.join('\n  - ') : 'none') + '\n');
    process.stdout.write('warnings: ' + (loaded.warnings.length ? '\n  - ' + loaded.warnings.join('\n  - ') : 'none') + '\n');
    process.stdout.write('secret env var names (values never read or printed):\n');
    for (const n of names) process.stdout.write('  ' + n + ': ' + (presence[n] ? 'present' : 'absent') + '\n');
    process.stdout.write('state_dir: ' + loaded.config.service.state_dir + '\n');
    process.stdout.write('mode: ' + loaded.config.detection.mode + '\n');
  }
  return loaded.errors.length ? EXIT.CONFIG : EXIT.OK;
}

function cmdRotate(args) {
  const loaded = loadOrExit(args);
  const store = new EventStore({
    dir: loaded.config.service.state_dir,
    maxBytes: loaded.config.store.max_bytes,
    maxFiles: loaded.config.store.max_files,
    retentionDays: loaded.config.store.retention_days
  });
  store.open();
  const file = store.rotate();
  const stats = store.stats();
  store.close();
  process.stdout.write('rotated to ' + path.basename(file) + ' (' + stats.files + ' files retained)\n');
  return EXIT.OK;
}

function cmdPrune(args) {
  const loaded = loadOrExit(args);
  const store = new EventStore({
    dir: loaded.config.service.state_dir,
    maxBytes: loaded.config.store.max_bytes,
    maxFiles: loaded.config.store.max_files,
    retentionDays: loaded.config.store.retention_days
  });
  store.open();
  const files = store.prune();
  const stats = store.stats();
  store.close();
  process.stdout.write('retention applied: ' + files + ' files retained, ' + stats.total_bytes + ' bytes\n');
  return EXIT.OK;
}

async function cmdWebhookTest(args) {
  const loaded = loadOrExit(args);
  const cfg = JSON.parse(JSON.stringify(loaded.config));
  cfg.adapters = Object.fromEntries(Object.keys(cfg.adapters).map(k => [k, Object.assign({}, cfg.adapters[k], { enabled: false })]));
  cfg.diagnostics.port = 0;
  const runner = new SentinelRunner({ config: cfg, adapters: [], logger: createLogger({ level: 'error' }) });
  await runner.init();
  runner.diagnostic('WEBHOOK_TEST', 'Synthetic webhook delivery test', 'low', { test: true }, 'No action required; this is a connectivity check.');
  const flush = await runner.dispatcher.flush();
  const stats = runner.dispatcher.stats();
  await runner.stop('webhook-test');
  process.stdout.write(JSON.stringify({ flush, dispatcher: stats, secret_env: cfg.alerts.webhook.secret_env }, null, 2) + '\n');
  return stats.status === 'ACTIVE' && (flush.sent > 0 || stats.delivered > 0) ? EXIT.OK : EXIT.RUNTIME;
}

async function main() {
  // A closed stdout (service wrapper, log collector restart) must not crash the
  // monitoring process.
  for (const stream of [process.stdout, process.stderr]) {
    stream.on('error', (err) => {
      if (err && err.code === 'EPIPE') process.exit(0);
    });
  }
  const args = parseArgs(process.argv.slice(2));
  const cmd = args._[0] || 'help';
  switch (cmd) {
    case 'run': return cmdRun(args);
    case 'once': return cmdOnce(args);
    case 'status': return cmdStatus(args);
    case 'coverage': return cmdCoverage(args);
    case 'verify': return cmdVerify(args);
    case 'rules': return cmdRules(args);
    case 'simulate': return cmdSimulate(args);
    case 'config-check': return cmdConfigCheck(args);
    case 'rotate': return cmdRotate(args);
    case 'prune': return cmdPrune(args);
    case 'webhook-test': return cmdWebhookTest(args);
    case 'help':
    case '--help':
    case '-h':
      process.stdout.write(usage() + '\n');
      return EXIT.OK;
    case 'version':
      process.stdout.write(VERSION + '\n');
      return EXIT.OK;
    default:
      process.stderr.write('unknown command: ' + cmd + '\n\n' + usage() + '\n');
      return EXIT.CONFIG;
  }
}

main().then(code => {
  if (typeof code === 'number') process.exitCode = code;
}).catch(e => {
  process.stderr.write('sentinel: ' + (e.stack || e.message) + '\n');
  process.exitCode = EXIT.RUNTIME;
});
