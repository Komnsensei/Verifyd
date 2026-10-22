'use strict';

const fs = require('fs');
const { BaseAdapter } = require('./base.cjs');
const { JsonlTailer } = require('../tailer.cjs');
const { httpEvent } = require('../event.cjs');

function toIso(ts) {
  if (ts == null) return new Date().toISOString();
  if (typeof ts === 'number' || /^\d+$/.test(String(ts))) {
    const n = Number(ts);
    // Cloudflare Logpush sends nanoseconds since epoch.
    if (n > 1e15) return new Date(n / 1e6).toISOString();
    if (n > 1e12) return new Date(n).toISOString();
    return new Date(n * 1000).toISOString();
  }
  return new Date(ts).toISOString();
}

function mapCloudflareLogpush(raw) {
  return {
    ts: toIso(raw.EdgeStartTimestamp || raw.EdgeEndTimestamp),
    method: raw.ClientRequestMethod,
    path: raw.ClientRequestURI,
    ip: raw.ClientIP,
    status: raw.EdgeResponseStatus,
    bytes_out: raw.EdgeResponseBytes,
    bytes_in: raw.ClientRequestBytes,
    user_agent: raw.ClientRequestUserAgent,
    host: raw.ClientRequestHost,
    duration_ms: raw.EdgeResponseTime != null ? Math.round(Number(raw.EdgeResponseTime) * 1000) : null,
    facts: {
      log_source: 'cloudflare-logpush',
      ray_id: raw.RayID || null,
      waf_action: raw.WAFAction || null,
      waf_rule_id: raw.WAFRuleID || null,
      security_action: raw.SecurityAction || null,
      bot_score: raw.BotScore != null ? Number(raw.BotScore) : null,
      country: raw.ClientCountryName || null
    }
  };
}

function mapGeneric(raw) {
  return Object.assign({ facts: { log_source: 'generic-jsonl' } }, raw);
}

class ProxyLogAdapter extends BaseAdapter {
  constructor(opts) {
    super(Object.assign({
      id: 'proxy.access',
      name: 'Reverse proxy / CDN / WAF access log',
      category: 'C: Data stores and external services',
      capabilities: [
        'edge request rate, status and byte counts',
        'WAF action and rule identifiers when the provider exports them',
        'source address as seen by the edge'
      ],
      limitations: [
        'requires the provider to export logs to a readable file; no provider API credentials are held by this service',
        'log delivery latency varies by provider (Cloudflare Logpush is near-real-time but not synchronous)',
        'requests dropped before the edge logger are invisible'
      ],
      source: { type: 'file', format: 'jsonl' }
    }, opts));
    this.provider = this.config.provider || 'generic-jsonl';
    this.tailer = null;
  }

  map(raw) {
    if (this.provider === 'cloudflare-logpush') return mapCloudflareLogpush(raw);
    return mapGeneric(raw);
  }

  async init() {
    if (this.config.enabled === false) return this.markNotConfigured('disabled in config');
    if (!this.config.path) {
      return this.markNotConfigured('adapters.proxy_log.path is empty; export CDN/WAF logs to JSONL and set the path');
    }
    try {
      const st = fs.statSync(this.config.path);
      if (!st.isFile()) return this.markUnavailable('configured proxy log path is not a regular file');
      this.source = { path: this.config.path, provider: this.provider, bytes: st.size };
      this.tailer = new JsonlTailer({ file: this.config.path, maxLines: 2000, cursor: this.cursor });
      return this.markActive('tailing ' + this.provider + ' access log', { path: this.config.path, provider: this.provider });
    } catch (e) {
      return this.markUnavailable('proxy log not readable: ' + (e.code || e.message));
    }
  }

  async poll() {
    if (this.status !== 'ACTIVE') {
      if (this.config.path && fs.existsSync(this.config.path)) await this.init();
      if (this.status !== 'ACTIVE') return { events: [] };
    }
    const res = this.tailer.poll();
    this.cursor = res.cursor;
    const events = [];
    for (const line of res.lines) {
      if (!line.parsed) continue;
      try {
        events.push(httpEvent(this.map(line.parsed), this.id));
      } catch (e) { /* skip unparseable */ }
    }
    this.succeeded(events.length);
    return { events };
  }
}

module.exports = { ProxyLogAdapter, mapCloudflareLogpush, toIso };
