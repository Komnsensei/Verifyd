'use strict';

const fs = require('fs');
const { BaseAdapter } = require('./base.cjs');
const { JsonlTailer } = require('../tailer.cjs');
const { httpEvent } = require('../event.cjs');

function mapCaddy(obj) {
  const req = obj.request || {};
  const headers = req.headers || {};
  let ts = obj.timestamp || null;
  if (obj.ts != null) {
    const numeric = typeof obj.ts === 'number' || /^\d+(\.\d+)?$/.test(String(obj.ts));
    ts = new Date(numeric ? Number(obj.ts) * 1000 : obj.ts).toISOString();
  }
  return {
    ts,
    method: req.method,
    path: req.uri || req.uri_path,
    ip: req.remote_ip || req.client_ip,
    user_agent: Array.isArray(headers['User-Agent']) ? headers['User-Agent'][0] : headers['User-Agent'],
    principal: obj.user_id || (req.headers && req.headers['X-User-Id']),
    status: obj.status,
    bytes_out: obj.size,
    duration_ms: obj.duration ? Math.round(obj.duration * 1000) : null,
    host: req.host || headers.Host,
    facts: { log_source: 'caddy' }
  };
}

function mapGeneric(obj) {
  return Object.assign({ facts: { log_source: 'generic-jsonl' } }, obj);
}

function mapperFor(format) {
  if (format === 'caddy-json') return mapCaddy;
  if (format === 'generic-jsonl') return mapGeneric;
  return mapGeneric;
}

class HttpAccessAdapter extends BaseAdapter {
  constructor(opts) {
    super(Object.assign({
      id: 'http.access',
      name: 'HTTP/API access log',
      category: 'A: HTTP/API access',
      capabilities: [
        'request rate by route, method, principal and source address',
        'status-code outcomes including auth failures and rate limits',
        'pagination/offset parameters and response byte counts',
        'sensitive/protected route matching'
      ],
      limitations: [
        'only sees traffic that reaches an instrumented app or reverse proxy that writes an access log',
        'cannot observe requests blocked upstream by a CDN/WAF unless those logs are also collected',
        'log timestamps are trusted as supplied by the writer'
      ]
    }, opts));
    this.format = this.config.format || 'sentinel-jsonl';
    this.pollMaxLines = this.config.max_lines_per_poll || 2000;
    this.tailer = null;
  }

  map(raw) {
    const obj = mapperFor(this.format)(raw);
    return httpEvent(obj, this.id);
  }

  async init() {
    if (this.config.enabled === false) return this.markNotConfigured('disabled in config');
    if (!this.config.path) return this.markNotConfigured('adapters.http_access.path is empty');
    let st;
    try {
      st = fs.statSync(this.config.path);
    } catch (e) {
      return this.markUnavailable('access log not found at ' + this.config.path + ' (' + (e.code || e.message) + ')');
    }
    if (!st.isFile()) return this.markUnavailable('configured path is not a regular file: ' + this.config.path);
    this.source = { path: this.config.path, format: this.format, bytes: st.size };
    this.tailer = new JsonlTailer({ file: this.config.path, maxLines: this.pollMaxLines, cursor: this.cursor });
    return this.markActive('tailing ' + this.format + ' access log', { path: this.config.path, format: this.format });
  }

  async poll() {
    if (this.status !== 'ACTIVE') {
      // Recover automatically if the file appeared after startup.
      if (this.config.path && fs.existsSync(this.config.path)) await this.init();
      if (this.status !== 'ACTIVE') return { events: [] };
    }
    const res = this.tailer.poll();
    this.cursor = res.cursor;
    if (res.missing) {
      this.markUnavailable('access log disappeared at ' + this.config.path);
      return { events: [] };
    }
    const events = [];
    for (const line of res.lines) {
      if (!line.parsed) continue;
      try {
        events.push(this.map(line.parsed));
      } catch (e) {
        // Drop malformed records from detection but keep the poll healthy.
      }
    }
    this.detail.lag_lines = res.bad_lines;
    this.detail.rotated = res.rotated;
    this.succeeded(events.length);
    return { events };
  }
}

module.exports = { HttpAccessAdapter, mapCaddy };
