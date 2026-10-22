'use strict';

const { BaseAdapter } = require('./base.cjs');
const { validateTargetUrl } = require('../config.cjs');

function getPath(obj, dotted) {
  if (!dotted) return obj;
  let cur = obj;
  for (const part of String(dotted).split('.')) {
    if (cur == null) return null;
    cur = cur[part];
  }
  return cur;
}

function mapRecord(raw, provider) {
  const principal = raw.principal || raw.actor || raw.user || raw.user_email || raw.actor_email || null;
  const ip = raw.ip || raw.source_ip || raw.client_ip || raw.actor_ip || null;
  const action = raw.action || raw.event || raw.event_type || raw.operation || null;
  const status = raw.status || raw.result || raw.outcome || null;
  const failed = raw.error === true || raw.success === false || /fail|error|denied/i.test(String(status || ''));
  return {
    ts: raw.ts || raw.timestamp || raw.time || raw.created_at || new Date().toISOString(),
    principal,
    ip,
    action,
    outcome: failed ? 'failure' : 'success',
    resource: raw.resource || raw.target || raw.object || null,
    facts: {
      provider: provider || 'saas',
      status: status || null,
      event_id: raw.id || raw.event_id || null,
      raw_keys: Object.keys(raw).slice(0, 40)
    }
  };
}

class SaasAuditAdapter extends BaseAdapter {
  constructor(opts) {
    super(Object.assign({
      id: 'saas.audit',
      name: 'Third-party SaaS audit API',
      category: 'C: Data stores and external services',
      capabilities: [
        'authenticated HTTPS pull from a SaaS audit endpoint',
        'principal, source address, action, resource and failure outcome',
        'cursor-based since parameter when the provider supports it'
      ],
      limitations: [
        'requires the operator to supply an API token in an environment variable; this build stores no SaaS credential',
        'provider-specific pagination beyond the configured response path is not implemented',
        'the provider must expose an audit/event endpoint authorized for the token'
      ],
      source: { type: 'https', format: 'json' }
    }, opts));
  }

  token() {
    const name = this.config.token_env;
    return name ? process.env[name] : null;
  }

  async init() {
    if (this.config.enabled === false) return this.markNotConfigured('disabled in config');
    if (!this.config.url) return this.markNotConfigured('adapters.saas_audit.url is empty');
    const errors = validateTargetUrl(this.config.url, 'adapters.saas_audit.url', { allow_insecure_loopback: this.config.allow_insecure_loopback === true });
    if (errors.length) return this.markUnavailable(errors.join('; '));
    if (!this.config.token_env) return this.markNotConfigured('adapters.saas_audit.token_env is empty');
    if (!this.token()) return this.markNotConfigured('token environment variable ' + this.config.token_env + ' is not set');
    return this.markActive('configured for ' + (this.config.provider || 'generic') + ' audit API', { url_host: new URL(this.config.url).host, token_env: this.config.token_env });
  }

  async poll() {
    if (!this.config.enabled || this.status !== 'ACTIVE') return { events: [] };
    const url = new URL(this.config.url);
    if (this.config.since_param && this.cursor && this.cursor.last_ts) {
      url.searchParams.set(this.config.since_param, this.cursor.last_ts);
    }
    if (this.config.limit_param) url.searchParams.set(this.config.limit_param, String(this.config.limit || 500));
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15000);
    let response;
    try {
      response = await fetch(url, {
        method: 'GET',
        headers: { authorization: 'Bearer ' + this.token(), accept: 'application/json' },
        signal: controller.signal
      });
    } finally {
      clearTimeout(timer);
    }
    if (!response.ok) throw new Error('SaaS audit API returned HTTP ' + response.status);
    const body = await response.json();
    const records = getPath(body, this.config.records_path);
    const list = Array.isArray(records) ? records : (records && typeof records === 'object' ? [records] : []);
    const events = [];
    let maxTs = this.cursor && this.cursor.last_ts ? this.cursor.last_ts : null;
    for (const raw of list) {
      if (!raw || typeof raw !== 'object') continue;
      const item = mapRecord(raw, this.config.provider);
      if (!maxTs || new Date(item.ts) > new Date(maxTs)) maxTs = item.ts;
      events.push({
        adapter: this.id,
        kind: 'saas.audit',
        ts: item.ts,
        hint: 'saas:' + (item.facts.provider || '') + ':' + (item.facts.event_id || item.action || '') + ':' + (item.principal || '') + ':' + item.ts,
        outcome: item.outcome,
        source: { principal: item.principal, ip: item.ip, principal_type: 'saas' },
        host: { hostname: this.deps.hostname || null },
        facts: Object.assign({}, item.facts, { action: item.action, resource: item.resource })
      });
    }
    this.cursor = { last_ts: maxTs };
    this.succeeded(events.length);
    return { events };
  }
}

module.exports = { SaasAuditAdapter, mapRecord, getPath };
