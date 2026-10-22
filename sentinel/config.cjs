'use strict';

const fs = require('fs');
const path = require('path');
const { CONFIG_SCHEMA } = require('./version.cjs');

const DEFAULTS = {
  schema: CONFIG_SCHEMA,
  service: {
    name: 'sentinel',
    state_dir: './sentinel-state',
    log_level: 'info'
  },
  runtime: {
    poll_interval_ms: 10000,
    adapter_timeout_ms: 20000,
    max_events_per_cycle: 5000,
    shutdown_timeout_ms: 5000,
    max_runtime_state_bytes: 1048576
  },
  store: {
    max_bytes: 8388608,
    max_files: 8,
    retention_days: 30,
    fsync: false,
    anchor: {
      path: '',
      url: '',
      secret_env: 'SENTINEL_ANCHOR_SECRET',
      interval_ms: 60000,
      allow_insecure_loopback: false
    }
  },
  detection: {
    mode: 'detect',
    window_ms: 300000,
    dedupe_cooldown_ms: 300000,
    min_alert_score: 10,
    severity_thresholds: { low: 1, medium: 25, high: 50, critical: 80 },
    protected_routes: ['/admin/*', '/api/v1/export*'],
    sensitive_routes: ['/admin/*', '/api/v1/users*', '/api/v1/export*'],
    rules: {
      auth_fail_burst: { enabled: true, score: 15, min_events: 5 },
      rate_limit_burst: { enabled: true, score: 10, min_events: 3 },
      denied_then_success: { enabled: true, score: 20 },
      sequential_enumeration: { enabled: true, score: 25, min_pages: 5, min_ids: 10 },
      bulk_response_volume: { enabled: true, score: 30, min_bytes_window: 10485760, min_bytes_single: 2097152 },
      sensitive_route_repeat: { enabled: true, score: 20, min_hits: 10 },
      protected_unauthenticated: { enabled: true, score: 100 },
      new_listener: { enabled: true, score: 15 },
      process_from_temp: { enabled: true, score: 20 },
      defender_detection: { enabled: true, score: 40 },
      file_integrity_change: { enabled: true, score: 15, score_deleted: 20 },
      db_bulk_read: { enabled: true, score: 30, min_rows: 5000 },
      db_auth_failure: { enabled: true, score: 15 },
      db_new_identity: { enabled: true, score: 20 },
      db_privilege_change: { enabled: true, score: 25 },
      host_auth_failure_burst: { enabled: true, score: 15, min_events: 5 },
      persistence_change: { enabled: true, score: 35 },
      wmi_subscription: { enabled: true, score: 60 },
      cloud_privilege_change: { enabled: true, score: 40 },
      db_live_bulk_read: { enabled: true, score: 30, min_logical_reads: 100000 },
      sysmon_tamper: { enabled: true, score: 60 },
      network_bulk_transfer: { enabled: true, score: 30, min_bytes: 52428800 },
      network_ids_alert: { enabled: true, score: 25, min_severity: 2 }
    }
  },
  baseline: {
    enabled: true,
    bucket_ms: 60000,
    buckets: 30,
    min_buckets: 5,
    alert_ratio: 3,
    require_baseline: true
  },
  allowlist: [],
  adapters: {
    http_access: { enabled: true, path: '', format: 'sentinel-jsonl', poll_interval_ms: 2000, max_lines_per_poll: 2000 },
    host_listeners: { enabled: true, poll_interval_ms: 30000, ignore_ports: [], allow_processes: [] },
    host_process: { enabled: true, poll_interval_ms: 20000, mode: 'auto' },
    host_security: { enabled: false, poll_interval_ms: 60000, events: [4624, 4625, 4647, 4672, 4673] },
    host_defender: { enabled: true, poll_interval_ms: 60000 },
    host_files: { enabled: false, paths: [], poll_interval_ms: 60000 },
    host_persistence: { enabled: false, poll_interval_ms: 60000 },
    host_fileaudit: { enabled: false, poll_interval_ms: 30000 },
    host_sysmon: { enabled: false, poll_interval_ms: 15000 },
    host_dns: { enabled: false, poll_interval_ms: 30000 },
    cloud_audit: { enabled: false, path: '', provider: 'generic', poll_interval_ms: 5000 },
    sqlserver: { enabled: false, server: '', database: '', connection_string_env: 'SENTINEL_SQL_CONNECTION', poll_interval_ms: 30000, max_sessions: 50 },
    saas_audit: { enabled: false, url: '', token_env: 'SENTINEL_SAAS_TOKEN', records_path: 'events', since_param: 'since', poll_interval_ms: 60000 },
    db_audit: { enabled: false, path: '', poll_interval_ms: 5000 },
    proxy_log: { enabled: false, path: '', provider: 'generic-jsonl', poll_interval_ms: 5000 },
    network_sensor: { enabled: false, path: '', provider: 'auto', log_type: '', poll_interval_ms: 5000 },
    webflow: { enabled: false, log_path: '', poll_interval_ms: 300000 },
    self_health: { enabled: true, poll_interval_ms: 30000, max_store_utilization: 0.9 }
  },
  alerts: {
    min_severity: 'low',
    webhook: {
      url: '',
      secret_env: 'SENTINEL_WEBHOOK_SECRET',
      timeout_ms: 5000,
      max_attempts: 6,
      backoff_base_ms: 500,
      backoff_max_ms: 60000,
      allow_insecure_loopback: false
    }
  },
  actions: {
    enabled: false,
    dry_run: true,
    targets: {
      gateway_rate_limit: { url: '', secret_env: 'SENTINEL_ACTION_SECRET' },
      waf_block: { url: '', secret_env: 'SENTINEL_ACTION_SECRET' },
      credential_rotation: { url: '', secret_env: 'SENTINEL_ACTION_SECRET' }
    },
    max_ttl_seconds: 3600
  },
  diagnostics: {
    bind: '127.0.0.1',
    port: 8790,
    token_env: 'SENTINEL_DIAG_TOKEN',
    allow_remote: false,
    recent_alerts: 25
  }
};

const SEVERITIES = ['low', 'medium', 'high', 'critical'];

function deepClone(v) {
  return JSON.parse(JSON.stringify(v));
}

function isPlainObject(v) {
  if (!v || typeof v !== 'object') return false;
  const p = Object.getPrototypeOf(v);
  return p === Object.prototype || p === null;
}

function deepMerge(base, override) {
  if (!isPlainObject(override)) return override;
  const out = isPlainObject(base) ? Object.assign({}, base) : {};
  for (const k of Object.keys(override)) {
    if (isPlainObject(override[k]) && isPlainObject(out[k])) {
      out[k] = deepMerge(out[k], override[k]);
    } else {
      out[k] = override[k];
    }
  }
  return out;
}

function isLoopbackHost(host) {
  if (!host) return false;
  const h = String(host).toLowerCase();
  if (h === 'localhost' || h === '::1' || h === '[::1]') return true;
  if (h === '127.0.0.1' || h === '::ffff:127.0.0.1') return true;
  return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h);
}

const METADATA_HOSTS = new Set([
  '169.254.169.254',
  '100.100.100.200',
  'metadata.google.internal',
  'metadata',
  'fd00:ec2::254'
]);

// Remote receivers must be authenticated and must not point at cloud metadata.
// HTTPS is mandatory except for explicitly permitted loopback development.
function validateTargetUrl(url, label, opts) {
  const errors = [];
  opts = opts || {};
  if (!url) return errors;
  let u;
  try {
    u = new URL(url);
  } catch (e) {
    errors.push(label + ': invalid URL');
    return errors;
  }
  if (u.username || u.password) errors.push(label + ': URL must not embed credentials; use an env var secret');
  const host = u.hostname.toLowerCase();
  if (METADATA_HOSTS.has(host)) errors.push(label + ': cloud metadata endpoints are not allowed');
  if (u.protocol === 'http:') {
    if (!isLoopbackHost(host)) errors.push(label + ': https is required for non-loopback destinations');
    else if (!opts.allow_insecure_loopback) errors.push(label + ': http loopback requires allow_insecure_loopback=true');
  } else if (u.protocol !== 'https:') {
    errors.push(label + ': unsupported protocol ' + u.protocol);
  }
  return errors;
}

function validateConfig(cfg) {
  const errors = [];
  const warnings = [];

  if (!cfg || typeof cfg !== 'object') return { errors: ['config must be an object'], warnings };

  const positiveInts = [
    ['runtime.poll_interval_ms', cfg.runtime.poll_interval_ms],
    ['runtime.adapter_timeout_ms', cfg.runtime.adapter_timeout_ms],
    ['store.max_bytes', cfg.store.max_bytes],
    ['store.max_files', cfg.store.max_files],
    ['detection.window_ms', cfg.detection.window_ms],
    ['detection.dedupe_cooldown_ms', cfg.detection.dedupe_cooldown_ms],
    ['diagnostics.port', cfg.diagnostics.port]
  ];
  for (const [name, value] of positiveInts) {
    if (!Number.isInteger(value) || value <= 0) errors.push(name + ' must be a positive integer');
  }

  if (!SEVERITIES.includes(cfg.alerts.min_severity)) {
    errors.push('alerts.min_severity must be one of ' + SEVERITIES.join(', '));
  }
  if (!['detect', 'respond'].includes(cfg.detection.mode)) {
    errors.push('detection.mode must be "detect" or "respond"');
  }

  const th = cfg.detection.severity_thresholds || {};
  const ordered = ['low', 'medium', 'high', 'critical'].map(k => th[k]);
  if (!ordered.every(n => Number.isFinite(n))) {
    errors.push('detection.severity_thresholds must define numeric low/medium/high/critical');
  } else {
    for (let i = 1; i < ordered.length; i++) {
      if (ordered[i] <= ordered[i - 1]) errors.push('detection.severity_thresholds must be strictly increasing');
    }
  }

  errors.push(...validateTargetUrl(cfg.alerts.webhook.url, 'alerts.webhook.url', {
    allow_insecure_loopback: cfg.alerts.webhook.allow_insecure_loopback === true
  }));

  if (cfg.store.anchor && cfg.store.anchor.url) {
    errors.push(...validateTargetUrl(cfg.store.anchor.url, 'store.anchor.url', {
      allow_insecure_loopback: cfg.store.anchor.allow_insecure_loopback === true
    }));
    if (!cfg.store.anchor.secret_env) {
      errors.push('store.anchor.secret_env is required when store.anchor.url is set');
    }
  }
  if (cfg.store.anchor && cfg.store.anchor.interval_ms != null && (!Number.isInteger(cfg.store.anchor.interval_ms) || cfg.store.anchor.interval_ms <= 0)) {
    errors.push('store.anchor.interval_ms must be a positive integer');
  }

  for (const key of Object.keys(cfg.actions.targets || {})) {
    const target = cfg.actions.targets[key];
    if (!target || !target.url) continue;
    errors.push(...validateTargetUrl(target.url, 'actions.targets.' + key + '.url', { allow_insecure_loopback: false }));
  }

  if (cfg.actions.enabled && cfg.detection.mode !== 'respond') {
    errors.push('actions.enabled requires detection.mode=respond (detection-only mode must not act)');
  }
  if (cfg.actions.enabled) {
    const anyTarget = Object.values(cfg.actions.targets || {}).some(t => t && t.url);
    if (!anyTarget) errors.push('actions.enabled requires at least one configured authorized target URL');
  }

  const bind = cfg.diagnostics.bind;
  if (!isLoopbackHost(bind) && !cfg.diagnostics.allow_remote) {
    errors.push('diagnostics.bind must be loopback unless diagnostics.allow_remote=true');
  }
  if (!isLoopbackHost(bind) && cfg.diagnostics.allow_remote) {
    if (!cfg.diagnostics.token_env) errors.push('remote diagnostics requires diagnostics.token_env so requests can be authenticated');
    warnings.push('diagnostics bound to ' + bind + '; every request must present the token from ' + cfg.diagnostics.token_env);
  }

  if (cfg.alerts.webhook.url && !cfg.alerts.webhook.secret_env) {
    errors.push('alerts.webhook.secret_env is required so payloads can be signed');
  }

  for (const name of Object.keys(cfg.adapters || {})) {
    const a = cfg.adapters[name];
    if (a && a.enabled === false) continue;
    if (a && a.poll_interval_ms != null && (!Number.isInteger(a.poll_interval_ms) || a.poll_interval_ms <= 0)) {
      errors.push('adapters.' + name + '.poll_interval_ms must be a positive integer');
    }
  }

  if (cfg.store.max_files < 2) warnings.push('store.max_files < 2 means rotation keeps very little history');
  if (!isPlainObject(cfg.allowlist)) {
    if (!Array.isArray(cfg.allowlist)) errors.push('allowlist must be an array');
  }

  return { errors, warnings };
}

function resolvePaths(cfg, baseDir) {
  const out = deepClone(cfg);
  const sd = out.service.state_dir;
  out.service.state_dir = path.isAbsolute(sd) ? sd : path.resolve(baseDir, sd);
  for (const key of ['http_access', 'db_audit', 'proxy_log', 'cloud_audit', 'network_sensor']) {
    const a = out.adapters[key];
    if (a && a.path && !path.isAbsolute(a.path)) a.path = path.resolve(baseDir, a.path);
  }
  if (out.store.anchor && out.store.anchor.path && !path.isAbsolute(out.store.anchor.path)) {
    out.store.anchor.path = path.resolve(baseDir, out.store.anchor.path);
  }
  if (out.adapters.webflow && out.adapters.webflow.log_path && !path.isAbsolute(out.adapters.webflow.log_path)) {
    out.adapters.webflow.log_path = path.resolve(baseDir, out.adapters.webflow.log_path);
  }
  if (out.adapters.host_files && Array.isArray(out.adapters.host_files.paths)) {
    out.adapters.host_files.paths = out.adapters.host_files.paths.map(p => (path.isAbsolute(p) ? p : path.resolve(baseDir, p)));
  }
  return out;
}

function loadConfigFile(file) {
  const abs = path.resolve(file);
  const raw = fs.readFileSync(abs, 'utf8');
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    const err = new Error('config is not valid JSON: ' + e.message);
    err.code = 'CONFIG_PARSE_ERROR';
    throw err;
  }
  return parsed;
}

function buildConfig(overrides, opts) {
  opts = opts || {};
  const merged = deepMerge(deepClone(DEFAULTS), overrides || {});
  const baseDir = opts.baseDir || process.cwd();
  const resolved = resolvePaths(merged, baseDir);
  const check = validateConfig(resolved);
  return { config: resolved, errors: check.errors, warnings: check.warnings };
}

function loadConfig(file, opts) {
  opts = opts || {};
  if (!file) {
    const built = buildConfig({}, opts);
    return Object.assign({ path: null }, built);
  }
  const overrides = loadConfigFile(file);
  const built = buildConfig(overrides, Object.assign({ baseDir: path.dirname(path.resolve(file)) }, opts));
  return Object.assign({ path: path.resolve(file) }, built);
}

// Report only the *names* of secret-bearing variables, never their values.
function secretEnvNames(cfg) {
  const names = new Set();
  if (cfg.alerts.webhook.secret_env) names.add(cfg.alerts.webhook.secret_env);
  for (const key of Object.keys(cfg.actions.targets || {})) {
    const t = cfg.actions.targets[key];
    if (t && t.secret_env) names.add(t.secret_env);
  }
  if (cfg.diagnostics.token_env) names.add(cfg.diagnostics.token_env);
  if (cfg.adapters && cfg.adapters.saas_audit && cfg.adapters.saas_audit.token_env) names.add(cfg.adapters.saas_audit.token_env);
  if (cfg.adapters && cfg.adapters.sqlserver && cfg.adapters.sqlserver.connection_string_env) names.add(cfg.adapters.sqlserver.connection_string_env);
  if (cfg.store && cfg.store.anchor && cfg.store.anchor.secret_env) names.add(cfg.store.anchor.secret_env);
  return Array.from(names).sort();
}

function secretPresence(env) {
  const out = {};
  for (const name of arguments[1] || []) out[name] = Boolean(env && env[name]);
  return out;
}

module.exports = {
  DEFAULTS,
  SEVERITIES,
  buildConfig,
  loadConfig,
  validateConfig,
  validateTargetUrl,
  secretEnvNames,
  secretPresence,
  isLoopbackHost,
  deepMerge,
  deepClone
};
