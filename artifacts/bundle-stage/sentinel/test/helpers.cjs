'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { buildConfig } = require('../config.cjs');
const { SentinelRunner } = require('../runner.cjs');
const { listFiles } = require('../store.cjs');

const silentLogger = {
  error() {}, warn() {}, info() {}, debug() {},
  child() { return silentLogger; }
};

function tempDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-test-' + (prefix || 'x') + '-'));
}

function makeConfig(overrides) {
  const { config, errors } = buildConfig(overrides || {});
  if (errors.length) throw new Error('config errors: ' + errors.join('; '));
  return config;
}

function disableAllAdapters(config) {
  for (const key of Object.keys(config.adapters)) {
    config.adapters[key] = Object.assign({}, config.adapters[key], { enabled: false });
  }
  return config;
}

async function makeRunner(opts) {
  opts = opts || {};
  const config = opts.config || disableAllAdapters(makeConfig());
  // Always isolate state unless the caller explicitly shares one; parallel test
  // files must never write to the same chain.
  config.service.state_dir = opts.stateDir || tempDir('state');
  config.diagnostics.port = 0;
  const runner = new SentinelRunner({
    config,
    adapters: opts.adapters || [],
    logger: opts.logger || silentLogger,
    transport: opts.transport || null,
    clock: opts.clock || null
  });
  await runner.init();
  return runner;
}

function feed(runner, raws) {
  const stats = { events: 0, duplicates: 0, alerts: 0, allowlisted: 0 };
  return (async () => {
    for (const raw of raws) await runner.processRawEvent(raw, stats);
    return stats;
  })();
}

function readRecords(dir) {
  const out = [];
  for (const f of listFiles(dir)) {
    const text = fs.readFileSync(path.join(dir, f.name), 'utf8');
    for (const line of text.split('\n')) {
      if (!line) continue;
      try { out.push(JSON.parse(line)); } catch (e) { /* torn line */ }
    }
  }
  return out;
}

function alertsOf(runner, ruleId) {
  return runner.recentAlerts.filter(a => !ruleId || a.rule_id === ruleId);
}

async function withServer(handler, fn) {
  const http = require('http');
  const server = http.createServer(handler);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  try {
    return await fn(port);
  } finally {
    if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
}

module.exports = {
  silentLogger,
  tempDir,
  makeConfig,
  disableAllAdapters,
  makeRunner,
  feed,
  readRecords,
  alertsOf,
  withServer
};
