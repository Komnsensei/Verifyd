'use strict';

const crypto = require('crypto');
const { canonicalJSON } = require('../engine/canonicalize.cjs');
const { EVENT_SCHEMA } = require('./version.cjs');
const { redact, redactHeaders, redactQuery } = require('./redact.cjs');

// Canonical, JSON-safe event shape. Fields are always present so downstream
// rules never have to guess whether a value was missing or null.
function baseEvent(parts) {
  return {
    schema: EVENT_SCHEMA,
    event_id: parts.event_id,
    ts: parts.ts,
    observed_at: parts.observed_at,
    adapter: parts.adapter,
    adapter_version: parts.adapter_version || '0.1.0',
    kind: parts.kind,
    outcome: parts.outcome || 'unknown',
    source: Object.assign({
      ip: null,
      port: null,
      principal: null,
      principal_type: null,
      user_agent: null
    }, parts.source || {}),
    request: Object.assign({
      method: null,
      route: null,
      path: null,
      query_keys: [],
      query: {},
      page: null,
      offset: null,
      limit: null,
      bytes_in: null
    }, parts.request || {}),
    response: Object.assign({
      status: null,
      bytes_out: null,
      duration_ms: null
    }, parts.response || {}),
    host: Object.assign({
      hostname: null,
      pid: null,
      process: null,
      parent_process: null,
      service: null,
      user: null,
      port: null,
      address: null,
      path: null
    }, parts.host || {}),
    facts: parts.facts || {},
    labels: parts.labels || [],
    allowlisted: false
  };
}

function coalesce() {
  for (let i = 0; i < arguments.length; i++) {
    const v = arguments[i];
    if (v !== undefined && v !== null && v !== '') return v;
  }
  return null;
}

function asInt(v) {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? Math.trunc(n) : null;
}

function isoNow(now) {
  const d = now ? new Date(now) : new Date();
  return d.toISOString();
}

// Route keys collapse identifiers so "GET /users/12" and "GET /users/99" are one
// route for rate/baseline purposes, while the raw path stays in evidence.
function routeKey(pathOrUrl) {
  if (!pathOrUrl) return '/';
  let p = String(pathOrUrl);
  const q = p.indexOf('?');
  if (q >= 0) p = p.slice(0, q);
  const h = p.indexOf('#');
  if (h >= 0) p = p.slice(0, h);
  p = p.replace(/\/{2,}/g, '/').toLowerCase();
  p = p.replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=\/|$)/g, '/:id');
  p = p.replace(/\/\d+(?=\/|$)/g, '/:id');
  p = p.replace(/\/[0-9a-f]{16,}(?=\/|$)/g, '/:id');
  if (p.length > 1 && p.endsWith('/')) p = p.slice(0, -1);
  return p || '/';
}

// Deterministic event id. The adapter supplies a locality hint (file + line,
// listener port, process start time) so re-reading the same evidence after a
// crash maps to the same id instead of inflating counts.
function computeEventId(parts) {
  const idMaterial = {
    adapter: parts.adapter,
    kind: parts.kind,
    ts: parts.ts,
    hint: parts.hint || null,
    ip: (parts.source && parts.source.ip) || null,
    principal: (parts.source && parts.source.principal) || null,
    method: (parts.request && parts.request.method) || null,
    route: (parts.request && parts.request.route) || null,
    status: (parts.response && parts.response.status) || null,
    bytes_out: (parts.response && parts.response.bytes_out) || null,
    pid: (parts.host && parts.host.pid) || null,
    path: (parts.host && parts.host.path) || null
  };
  return crypto.createHash('sha256').update(canonicalJSON(idMaterial)).digest('hex');
}

function sanitize(value) {
  // canonicalJSON rejects undefined/Date/etc, so normalize through JSON first.
  return JSON.parse(JSON.stringify(value));
}

// Build an event from an adapter's partially-filled parts. All persisted
// strings/objects pass through redaction.
function buildEvent(parts, opts) {
  opts = opts || {};
  let ts = isoNow(opts.now);
  let timestampInvalid = false;
  if (parts.ts) {
    const parsed = new Date(parts.ts);
    if (Number.isFinite(parsed.getTime())) ts = parsed.toISOString();
    else timestampInvalid = true;
  }
  const normalized = {
    adapter: parts.adapter,
    kind: parts.kind,
    ts,
    hint: parts.hint || null,
    source: parts.source || {},
    request: parts.request || {},
    response: parts.response || {},
    host: parts.host || {},
    facts: parts.facts || {}
  };
  const event_id = parts.event_id || computeEventId(normalized);

  const request = Object.assign({}, parts.request || {});
  if (request.path && !request.route) request.route = routeKey(request.path);
  if (request.query && typeof request.query === 'object') {
    const rq = redactQuery(request.query);
    request.query_keys = rq.keys;
    request.query = rq.values;
    if (request.page == null && rq.values.page != null) request.page = asInt(rq.values.page);
    if (request.offset == null && rq.values.offset != null) request.offset = asInt(rq.values.offset);
    if (request.limit == null && rq.values.limit != null) request.limit = asInt(rq.values.limit);
  }
  if (request.path) {
    // Query values live in request.query (allowlisted and redacted); the raw
    // query string must not be duplicated into the stored path.
    request.path = String(request.path).split('#')[0].split('?')[0];
  }
  if (request.headers) {
    request.headers = redactHeaders(request.headers);
  } else {
    delete request.headers;
  }
  request.bytes_in = asInt(request.bytes_in);
  if (request.page != null) request.page = asInt(request.page);
  if (request.offset != null) request.offset = asInt(request.offset);
  if (request.limit != null) request.limit = asInt(request.limit);

  const response = Object.assign({}, parts.response || {});
  response.status = asInt(response.status);
  response.bytes_out = asInt(response.bytes_out);
  response.duration_ms = asInt(response.duration_ms);

  const host = Object.assign({}, parts.host || {});
  host.pid = asInt(host.pid);
  host.port = asInt(host.port);

  const ev = baseEvent({
    event_id,
    ts,
    observed_at: isoNow(opts.now),
    adapter: parts.adapter,
    adapter_version: parts.adapter_version,
    kind: parts.kind,
    outcome: parts.outcome,
    source: parts.source || {},
    request,
    response,
    host,
    facts: redact(Object.assign({}, parts.facts || {}, timestampInvalid ? { timestamp_invalid: true } : {})),
    labels: parts.labels || []
  });
  ev.request.query_keys = Array.isArray(ev.request.query_keys) ? ev.request.query_keys : [];
  ev.source.ip = ev.source.ip ? String(ev.source.ip).slice(0, 64) : null;
  ev.source.principal = ev.source.principal ? String(ev.source.principal).slice(0, 256) : null;
  ev.source.user_agent = ev.source.user_agent ? String(ev.source.user_agent).slice(0, 256) : null;
  return sanitize(ev);
}

function outcomeForStatus(status) {
  if (status == null) return 'unknown';
  if (status === 401 || status === 407) return 'auth_failure';
  if (status === 403) return 'denied';
  if (status === 429) return 'rate_limited';
  if (status >= 200 && status < 400) return 'success';
  if (status >= 400 && status < 500) return 'client_error';
  if (status >= 500) return 'server_error';
  return 'unknown';
}

// Adapter-facing helper: build an HTTP/API event from a reverse-proxy or
// instrumented-app access record.
function httpEvent(raw, adapterId, opts) {
  const status = asInt(raw.status != null ? raw.status : raw.status_code);
  const path = raw.path || raw.url || raw.route || '/';
  const request = {
    method: raw.method ? String(raw.method).toUpperCase() : null,
    path: path,
    route: raw.route ? routeKey(raw.route) : routeKey(path),
    query: raw.query || {},
    bytes_in: raw.bytes_in != null ? raw.bytes_in : raw.request_bytes,
    headers: raw.headers || null,
    body_sha256: raw.request_body_sha256 || null,
    body_bytes: raw.request_body_bytes != null ? raw.request_body_bytes : null,
    body_shape: raw.request_body_shape || null
  };
  if (raw.page != null) request.page = raw.page;
  if (raw.offset != null) request.offset = raw.offset;
  if (raw.limit != null) request.limit = raw.limit;
  if (!request.query || Object.keys(request.query).length === 0) {
    const qi = String(path).indexOf('?');
    if (qi >= 0) {
      const params = new URLSearchParams(String(path).slice(qi + 1));
      const q = {};
      for (const [k, v] of params.entries()) q[k] = v;
      request.query = q;
    }
  }
  return buildEvent({
    adapter: adapterId,
    kind: 'http.request',
    ts: raw.ts || raw.timestamp || raw.time,
    hint: raw.hint || null,
    source: {
      ip: coalesce(raw.ip, raw.remote_ip, raw.client_ip, raw['cf-connecting-ip'], raw['x-forwarded-for']),
      port: raw.source_port,
      principal: coalesce(raw.principal, raw.user, raw.user_id, raw.sub),
      principal_type: raw.principal_type || null,
      user_agent: raw.user_agent || (raw.headers && raw.headers['user-agent']) || null
    },
    request,
    response: {
      status,
      bytes_out: raw.bytes_out != null ? raw.bytes_out : raw.response_bytes,
      duration_ms: raw.duration_ms != null ? raw.duration_ms : raw.elapsed_ms,
      body_sha256: raw.response_body_sha256 || null,
      body_bytes: raw.response_body_bytes != null ? raw.response_body_bytes : null,
      body_shape: raw.response_body_shape || null
    },
    host: {
      hostname: raw.host || raw.hostname || null,
      service: raw.service || null
    },
    outcome: raw.outcome || outcomeForStatus(status),
    facts: raw.facts || {},
    labels: raw.labels || []
  }, opts);
}

module.exports = {
  baseEvent,
  buildEvent,
  computeEventId,
  routeKey,
  outcomeForStatus,
  httpEvent,
  asInt,
  coalesce,
  sanitize,
  isoNow
};
