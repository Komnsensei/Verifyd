'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { EventStore } = require('./store.cjs');
const { Dispatcher } = require('./dispatcher.cjs');
const { ActionGate } = require('./actions.cjs');
const { DetectionEngine } = require('./rules.cjs');
const { Baseline } = require('./baseline.cjs');
const { matchesAllowlist } = require('./allowlist.cjs');
const { buildEvent } = require('./event.cjs');
const { createAdapters } = require('./adapters/index.cjs');
const { VERSION, ALERT_SCHEMA, STATUS } = require('./version.cjs');
const { createLogger } = require('./logging.cjs');

const DIAG_COOLDOWN_MS = 300000;
const REINIT_COOLDOWN_MS = 300000;
const VERIFY_INTERVAL_MS = 300000;
const SEEN_RETENTION_MS = 900000;

class SentinelRunner {
  constructor(opts) {
    opts = opts || {};
    this.config = opts.config;
    this.logger = opts.logger || createLogger({ level: (this.config.service && this.config.service.log_level) || 'info' });
    this.clock = opts.clock || (() => Date.now());
    this.stateDir = this.config.service.state_dir;
    this.runtimePath = path.join(this.stateDir, 'runtime.json');
    this.powershell = opts.powershell || require('./windows/powershell.cjs').makePowerShellRunner({ timeoutMs: this.config.runtime.adapter_timeout_ms });

    this.store = opts.store || new EventStore({
      dir: this.stateDir,
      maxBytes: this.config.store.max_bytes,
      maxFiles: this.config.store.max_files,
      retentionDays: this.config.store.retention_days,
      fsync: this.config.store.fsync
    });
    this.baseline = new Baseline({
      enabled: this.config.baseline.enabled,
      bucketMs: this.config.baseline.bucket_ms,
      buckets: this.config.baseline.buckets,
      minBuckets: this.config.baseline.min_buckets,
      alertRatio: this.config.baseline.alert_ratio
    });
    this.engine = new DetectionEngine(this.config, { baseline: this.baseline, now: this.clock });
    this.dispatcher = opts.dispatcher || new Dispatcher({
      dir: this.stateDir,
      webhook: this.config.alerts.webhook,
      clock: this.clock,
      transport: opts.transport || null,
      logger: this.logger
    });
    this.actions = new ActionGate(this.config, { clock: this.clock, transport: opts.transport || null });
    this.adapters = opts.adapters || createAdapters(this.config, {
      powershell: this.powershell,
      hostname: os.hostname(),
      stateDir: this.stateDir,
      getHealth: () => this.healthSummary()
    });

    this.startedAt = null;
    this.lastCycleAt = null;
    this.lastCycleDurationMs = null;
    this.cycles = 0;
    this.nextDue = new Map();
    this.missedPolls = 0;
    this.diagCooldown = new Map();
    this.seen = new Map();
    this.recentAlerts = [];
    this.counters = { events: 0, alerts: 0, duplicates: 0, allowlisted: 0, adapter_errors: 0, operational_alerts: 0 };
    this.storeError = null;
    this.chain = { ok: true, checked_at: null, errors: [] };
    this.lastVerifyAt = 0;
    this.timer = null;
    this.stopping = false;
    this.cursorsRestored = false;
    this.initialized = false;
    this.dispatchStats = this.dispatcher.stats();
  }

  async init() {
    fs.mkdirSync(this.stateDir, { recursive: true, mode: 0o700 });
    this.store.open();
    this.restoreRuntime();
    this.dispatcher.open();
    this.dispatchStats = this.dispatcher.stats();
    this.startedAt = new Date(this.clock()).toISOString();

    for (const adapter of this.adapters) {
      adapter.restoreCursor(this.savedCursors[adapter.id] || null);
      await this.initAdapter(adapter);
      this.nextDue.set(adapter.id, this.clock());
    }

    const verify = this.store.verify();
    this.chain = { ok: verify.valid, checked_at: new Date(this.clock()).toISOString(), errors: verify.errors.slice(0, 20), head: verify.head, records: verify.records };
    this.lastVerifyAt = this.clock();
    if (!verify.valid) {
      this.logger.error('evidence chain verification failed at startup', { errors: verify.errors.slice(0, 5) });
    }
    this.initialized = true;
    return this;
  }

  async initAdapter(adapter) {
    adapter._last_init_attempt = this.clock();
    try {
      await withTimeout(adapter.init(), this.config.runtime.adapter_timeout_ms, adapter.id + ' init');
    } catch (e) {
      adapter.failed(e);
      adapter.markUnavailable('init failed: ' + (e.code || e.message));
      this.logger.warn('adapter init failed', { adapter: adapter.id, error: e.code || e.message });
    }
    return adapter;
  }

  restoreRuntime() {
    this.savedCursors = {};
    try {
      if (!fs.existsSync(this.runtimePath)) return;
      const raw = JSON.parse(fs.readFileSync(this.runtimePath, 'utf8'));
      this.savedCursors = raw.adapter_cursors || {};
      if (raw.baseline) this.baseline = Baseline.fromJSON(raw.baseline, {
        enabled: this.config.baseline.enabled,
        bucketMs: this.config.baseline.bucket_ms,
        buckets: this.config.baseline.buckets,
        minBuckets: this.config.baseline.min_buckets,
        alertRatio: this.config.baseline.alert_ratio
      });
      this.engine.baseline = this.baseline;
      if (Array.isArray(raw.recent_alerts)) this.recentAlerts = raw.recent_alerts.slice(-50);
      if (raw.counters) Object.assign(this.counters, raw.counters);
      this.cursorsRestored = true;
    } catch (e) {
      this.logger.warn('runtime state could not be restored; starting with fresh adapter cursors', { error: e.code || e.message });
    }
  }

  saveRuntime() {
    const cursors = {};
    for (const adapter of this.adapters) {
      try {
        cursors[adapter.id] = adapter.getCursor();
      } catch (e) { /* ignore */ }
    }
    const payload = {
      version: 1,
      saved_at: new Date(this.clock()).toISOString(),
      started_at: this.startedAt,
      adapter_cursors: cursors,
      baseline: this.baseline.toJSON(),
      counters: this.counters,
      recent_alerts: this.recentAlerts.slice(-50),
      store_head: this.store.head,
      store_seq: this.store.seq
    };
    const tmp = this.runtimePath + '.tmp';
    try {
      let text = JSON.stringify(payload);
      const limit = this.config.runtime.max_runtime_state_bytes || 1048576;
      if (Buffer.byteLength(text) > limit) {
        payload.recent_alerts = payload.recent_alerts.slice(-10);
        text = JSON.stringify(payload);
      }
      if (Buffer.byteLength(text) > limit) {
        payload.recent_alerts = [];
        text = JSON.stringify(payload);
      }
      fs.writeFileSync(tmp, text, { mode: 0o600 });
      fs.renameSync(tmp, this.runtimePath);
    } catch (e) {
      this.logger.warn('runtime state could not be saved', { error: e.code || e.message });
    }
  }

  isDue(adapter, now) {
    const due = this.nextDue.get(adapter.id) || 0;
    return now >= due;
  }

  scheduleNext(adapter, now) {
    const jitter = 0.9 + ((adapter.id.length % 7) / 40); // deterministic spread
    this.nextDue.set(adapter.id, now + Math.round(adapter.intervalMs * jitter));
  }

  pruneSeen() {
    const cutoff = this.clock() - SEEN_RETENTION_MS;
    for (const [id, ts] of this.seen.entries()) {
      if (ts < cutoff) this.seen.delete(id);
    }
    if (this.seen.size > 50000) {
      const keys = Array.from(this.seen.keys()).slice(0, this.seen.size - 50000);
      for (const k of keys) this.seen.delete(k);
    }
  }

  async maybeReinit(adapter) {
    if (adapter.config.enabled === false) return false;
    if (adapter.status !== STATUS.UNAVAILABLE) return false;
    if (this.clock() - (adapter._last_init_attempt || 0) < REINIT_COOLDOWN_MS) return false;
    await this.initAdapter(adapter);
    return adapter.status === STATUS.ACTIVE;
  }

  async cycle() {
    if (this.stopping) return { skipped: 'stopping' };
    const t0 = this.clock();
    const stats = { at: new Date(t0).toISOString(), adapters_polled: 0, events: 0, duplicates: 0, allowlisted: 0, alerts: 0, adapter_errors: 0, duration_ms: 0 };
    this.pruneSeen();

    for (const adapter of this.adapters) {
      if (adapter.config.enabled === false) continue;
      if (adapter.status === STATUS.NOT_CONFIGURED) continue;
      if (!this.isDue(adapter, t0)) {
        this.checkMissed(adapter, t0);
        continue;
      }
      if (adapter.status === STATUS.UNAVAILABLE) {
        const recovered = await this.maybeReinit(adapter);
        if (!recovered) {
          this.scheduleNext(adapter, t0);
          this.checkMissed(adapter, t0);
          continue;
        }
      }
      stats.adapters_polled += 1;
      let result;
      try {
        result = await withTimeout(adapter.poll(), this.config.runtime.adapter_timeout_ms, adapter.id + ' poll');
      } catch (e) {
        stats.adapter_errors += 1;
        this.counters.adapter_errors += 1;
        adapter.failed(e);
        this.logger.warn('adapter poll failed', { adapter: adapter.id, error: e.code || e.message, failures: adapter.consecutive_failures });
        this.diagnostic('ADAPTER_POLL_FAILED', 'Adapter poll failed: ' + adapter.id, 'medium', {
          adapter: adapter.id,
          error: e.code || e.message,
          consecutive_failures: adapter.consecutive_failures
        }, 'Check service permissions, log paths and PowerShell availability for this adapter.');
        this.scheduleNext(adapter, t0);
        continue;
      }
      const events = (result && result.events) || [];
      if (adapter.consecutive_failures > 0) adapter.consecutive_failures = 0;
      adapter.succeeded(events.length);
      this.scheduleNext(adapter, t0);
      for (const raw of events) {
        await this.processRawEvent(raw, stats);
      }
    }

    try {
      const flush = await this.dispatcher.flush();
      this.dispatchStats = this.dispatcher.stats();
      if (flush && flush.sent) this.logger.info('alerts delivered', { sent: flush.sent, pending: flush.pending });
    } catch (e) {
      this.logger.warn('dispatcher flush failed', { error: e.code || e.message });
    }

    if (this.clock() - this.lastVerifyAt >= VERIFY_INTERVAL_MS) {
      const v = this.store.verify();
      this.chain = { ok: v.valid, checked_at: new Date(this.clock()).toISOString(), errors: v.errors.slice(0, 20), head: v.head, records: v.records };
      this.lastVerifyAt = this.clock();
      if (!v.valid) {
        this.diagnostic('EVIDENCE_CHAIN_INVALID', 'Evidence chain verification failed', 'critical', {
          errors: v.errors.slice(0, 10),
          head: v.head
        }, 'Stop writes, preserve the evidence directory, and investigate tampering before continuing.');
      }
    }

    this.cycles += 1;
    this.lastCycleAt = new Date(this.clock()).toISOString();
    this.lastCycleDurationMs = this.clock() - t0;
    stats.duration_ms = this.lastCycleDurationMs;
    this.saveRuntime();
    return stats;
  }

  async processRawEvent(raw, stats) {
    let event;
    try {
      event = buildEvent(raw, { now: this.clock() });
    } catch (e) {
      this.logger.warn('event normalization failed', { adapter: raw && raw.adapter, error: e.code || e.message });
      return;
    }
    if (this.seen.has(event.event_id)) {
      stats.duplicates += 1;
      this.counters.duplicates += 1;
      return;
    }
    this.seen.set(event.event_id, this.clock());
    stats.events += 1;
    this.counters.events += 1;

    const allowed = matchesAllowlist(event, this.config.allowlist, this.clock());
    if (allowed) {
      event.allowlisted = true;
      event.facts.allowlist_reason = allowed.reason || 'matched allowlist entry';
      stats.allowlisted += 1;
      this.counters.allowlisted += 1;
      this.writeRecord('event', event);
      return;
    }

    this.writeRecord('event', event);
    let alerts = [];
    try {
      alerts = this.engine.observe(event);
    } catch (e) {
      this.logger.warn('rule engine error', { error: e.code || e.message, event_id: event.event_id });
      return;
    }
    for (const alert of alerts) {
      await this.recordAlert(alert);
      stats.alerts += 1;
    }
  }

  writeRecord(type, payload) {
    try {
      this.store.append(type, payload, new Date(this.clock()).toISOString());
      this.storeError = null;
      return true;
    } catch (e) {
      this.storeError = { at: new Date(this.clock()).toISOString(), code: e.code || 'STORE_WRITE_FAILED', message: e.message };
      this.logger.error('evidence write failed', { error: e.code || e.message });
      return false;
    }
  }

  async recordAlert(alert) {
    // Alerts are rule output, not adapter input; normalize once so a stray
    // undefined field cannot cost the evidence record.
    alert = JSON.parse(JSON.stringify(alert));
    this.recentAlerts.push(alert);
    if (this.recentAlerts.length > 100) this.recentAlerts = this.recentAlerts.slice(-100);
    this.counters.alerts += 1;
    this.writeRecord('alert', alert);
    try {
      this.dispatcher.enqueue(alert);
    } catch (e) {
      this.logger.warn('alert queue write failed', { error: e.code || e.message, alert_id: alert.alert_id });
    }
    let actionResult = null;
    try {
      actionResult = await this.actions.execute(alert);
    } catch (e) {
      this.logger.warn('response action failed', { error: e.code || e.message, alert_id: alert.alert_id });
    }
    if (actionResult && actionResult.results && actionResult.results.length) {
      this.writeRecord('action', {
        at: new Date(this.clock()).toISOString(),
        alert_id: alert.alert_id,
        dry_run: actionResult.plan.dry_run,
        results: actionResult.results
      });
    }
  }

  diagnostic(ruleId, title, severity, facts, recommendation) {
    const key = ruleId + '|' + JSON.stringify(facts).slice(0, 120);
    const last = this.diagCooldown.get(key) || 0;
    if (this.clock() - last < DIAG_COOLDOWN_MS) return null;
    this.diagCooldown.set(key, this.clock());
    const alert = {
      schema: ALERT_SCHEMA,
      alert_id: 'diag-' + require('crypto').createHash('sha256').update(key + ':' + this.clock()).digest('hex').slice(0, 24),
      created_at: new Date(this.clock()).toISOString(),
      rule_id: ruleId,
      rule_version: VERSION,
      title,
      mode: this.config.detection.mode,
      severity,
      score: 0,
      critical: severity === 'critical',
      entity: { key: 'service', principal: null, ip: null, route: null, process: null, host: os.hostname() },
      source_adapter: 'sentinel',
      event_kind: 'service',
      event_ids: [],
      first_seen: new Date(this.clock()).toISOString(),
      last_seen: new Date(this.clock()).toISOString(),
      occurrences: 1,
      suppressed_since_previous: 0,
      evidence: facts,
      facts: { observed: true, classification: 'operational' },
      recommended_response: [recommendation || 'Inspect service logs and adapter status.'],
      baseline: null
    };
    this.counters.operational_alerts += 1;
    this.recordAlert(alert).catch(() => {});
    return alert;
  }

  checkMissed(adapter, now) {
    if (adapter.status !== STATUS.ACTIVE) return;
    if (!adapter.last_ok_at) return;
    const lastOk = new Date(adapter.last_ok_at).getTime();
    if (!Number.isFinite(lastOk)) return;
    if (now - lastOk > 3 * adapter.intervalMs) {
      this.missedPolls += 1;
      this.diagnostic('MISSED_POLL_INTERVAL', 'Adapter missed its polling interval', 'low', {
        adapter: adapter.id,
        interval_ms: adapter.intervalMs,
        overdue_ms: now - lastOk,
        last_ok_at: adapter.last_ok_at
      }, 'Check for adapter stalls, PowerShell timeouts or an overloaded host.');
    }
  }

  healthSummary() {
    const active = this.adapters.filter(a => a.status === STATUS.ACTIVE).length;
    const unavailable = this.adapters.filter(a => a.status === STATUS.UNAVAILABLE).length;
    const notConfigured = this.adapters.filter(a => a.status === STATUS.NOT_CONFIGURED).length;
    const storeStats = this.store.stats();
    let status = 'ok';
    if (this.storeError || !this.chain.ok) status = 'failing';
    else if (unavailable > 0) status = 'degraded';
    return {
      status,
      started_at: this.startedAt,
      uptime_s: this.startedAt ? Math.round((this.clock() - new Date(this.startedAt).getTime()) / 1000) : 0,
      last_cycle_at: this.lastCycleAt,
      cycles: this.cycles,
      store_writable: !this.storeError,
      chain_ok: this.chain.ok,
      chain_checked_at: this.chain.checked_at,
      adapters_active: active,
      adapters_unavailable: unavailable,
      adapters_not_configured: notConfigured,
      missed_polls: this.missedPolls,
      store: storeStats,
      dispatcher: this.dispatchStats,
      paused: false
    };
  }

  coverage() {
    const adapters = this.adapters.map(a => a.describe());
    const blind = [];
    for (const a of adapters) {
      if (a.status !== STATUS.ACTIVE) {
        blind.push({ adapter: a.id, status: a.status, reason: a.reason, limitations: a.limitations });
      }
    }
    blind.push({
      adapter: 'global',
      status: 'LIMITATION',
      reason: 'Host telemetry cannot establish what happened inside an uninstrumented external API or database. Full coverage requires integrating those systems\u2019 own audit logs.',
      limitations: [
        'No detection of scrapers that stay below every configured threshold',
        'No packet capture, TLS inspection or endpoint instrumentation',
        'Access logs are trusted as written by the producer'
      ]
    });
    return {
      generated_at: new Date(this.clock()).toISOString(),
      mode: this.config.detection.mode,
      adapters,
      summary: {
        active: adapters.filter(a => a.status === STATUS.ACTIVE).length,
        unavailable: adapters.filter(a => a.status === STATUS.UNAVAILABLE).length,
        not_configured: adapters.filter(a => a.status === STATUS.NOT_CONFIGURED).length
      },
      blind_spots: blind
    };
  }

  snapshot() {
    return {
      version: VERSION,
      health: this.healthSummary(),
      detection: Object.assign({ mode: this.config.detection.mode, window_ms: this.config.detection.window_ms, dedupe_cooldown_ms: this.config.detection.dedupe_cooldown_ms }, this.engine.status()),
      dispatcher: Object.assign({}, this.dispatchStats, this.dispatcher.stats()),
      actions: this.actions.stats(),
      adapters: this.adapters.map(a => a.describe()),
      store: this.store.stats(),
      counters: Object.assign({}, this.counters),
      recent_alerts: this.recentAlerts.slice(-25),
      blind_spots: this.coverage().blind_spots
    };
  }

  start(healthServer) {
    this.healthServer = healthServer || null;
    this.stopping = false;
    const tick = async () => {
      if (this.stopping) return;
      try {
        await this.cycle();
      } catch (e) {
        this.logger.error('cycle failed', { error: e.code || e.message });
      }
      if (this.stopping) return;
      this.timer = setTimeout(tick, this.config.runtime.poll_interval_ms);
      if (this.timer.unref) this.timer.unref();
    };
    this.timer = setTimeout(tick, 0);
    if (this.timer.unref) this.timer.unref();
    return this;
  }

  async stop(reason) {
    if (this.stopping) return;
    this.stopping = true;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    this.saveRuntime();
    for (const adapter of this.adapters) {
      try { await adapter.stop(); } catch (e) { /* ignore */ }
    }
    if (this.healthServer) {
      try { await this.healthServer.close(); } catch (e) { /* ignore */ }
    }
    this.dispatcher.close();
    this.store.close();
    this.logger.info('sentinel stopped', { reason: reason || 'signal' });
  }
}

function withTimeout(promise, ms, label) {
  let timer;
  return Promise.race([
    promise,
    new Promise((resolve, reject) => {
      timer = setTimeout(() => {
        const e = new Error((label || 'operation') + ' timed out after ' + ms + 'ms');
        e.code = 'TIMEOUT';
        reject(e);
      }, ms);
      if (timer.unref) timer.unref();
    })
  ]).finally(() => clearTimeout(timer));
}

module.exports = { SentinelRunner, withTimeout };
