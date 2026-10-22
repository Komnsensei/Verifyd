'use strict';

// Safe response actions.
//
// Three independent gates must all be open before anything leaves the process:
//   1. detection.mode === "respond"
//   2. actions.enabled === true
//   3. the specific target URL is configured for that action type
// actions.dry_run defaults to true and only records the intended request.
// This module never modifies the local firewall, never kills processes and never
// deletes evidence. It emits a signed control request to an operator-owned
// endpoint (gateway/WAF control API) that the operator has configured.

const { signPayload, postJson } = require('./dispatcher.cjs');
const { validateTargetUrl } = require('./config.cjs');
const { SEVERITY_RANK } = require('./rules.cjs');

const ACTION_RULES = {
  gateway_rate_limit: { min_severity: 'medium', target: 'gateway_rate_limit', ttl: 300, requires: ['ip'] },
  waf_block: { min_severity: 'high', target: 'waf_block', ttl: 900, requires: ['ip'] },
  // Requests rotation through an operator-owned identity endpoint. Sentinel does
  // not hold provider credentials and never performs the rotation itself.
  credential_rotation: { min_severity: 'high', target: 'credential_rotation', ttl: 0, requires: ['principal'] }
};

class ActionGate {
  constructor(config, opts) {
    this.config = config;
    this.clock = (opts && opts.clock) || (() => Date.now());
    this.transport = (opts && opts.transport) || null;
    this.clockFn = this.clock;
    this.history = [];
  }

  eligibility() {
    const cfg = this.config;
    const reasons = [];
    if (cfg.detection.mode !== 'respond') reasons.push('detection.mode is "' + cfg.detection.mode + '"; actions require "respond"');
    if (!cfg.actions.enabled) reasons.push('actions.enabled is false');
    if (!cfg.actions.dry_run) {
      for (const [name, target] of Object.entries(cfg.actions.targets || {})) {
        if (!target || !target.url) continue;
        const errs = validateTargetUrl(target.url, 'actions.targets.' + name + '.url', { allow_insecure_loopback: false });
        if (errs.length) reasons.push(...errs);
      }
    }
    return { eligible: reasons.length === 0, reasons, dry_run: cfg.actions.dry_run !== false };
  }

  plan(alert) {
    const cfg = this.config;
    const elig = this.eligibility();
    const plan = { eligible: elig.eligible, reasons: elig.reasons, dry_run: elig.dry_run, intents: [] };
    if (!elig.eligible) return plan;
    for (const [action, rule] of Object.entries(ACTION_RULES)) {
      if (SEVERITY_RANK[alert.severity] < SEVERITY_RANK[rule.min_severity]) continue;
      const missing = rule.requires.filter(f => {
        if (f === 'ip') return !alert.entity || !alert.entity.ip;
        if (f === 'principal') return !alert.entity || !alert.entity.principal;
        return true;
      });
      if (missing.length) continue;
      const target = cfg.actions.targets[rule.target];
      if (!target || !target.url) continue;
      plan.intents.push({
        action,
        target_url: target.url,
        target: rule.requires.includes('principal') ? alert.entity.principal : alert.entity.ip,
        ttl_seconds: Math.min(rule.ttl, cfg.actions.max_ttl_seconds || 3600),
        alert_id: alert.alert_id,
        severity: alert.severity,
        score: alert.score,
        reason: 'sentinel ' + alert.rule_id + ' score=' + alert.score
      });
    }
    return plan;
  }

  async execute(alert) {
    const plan = this.plan(alert);
    const results = [];
    for (const intent of plan.intents) {
      const payload = JSON.stringify({
        schema: 'sentinel.action/1',
        action: intent.action,
        target: intent.target,
        ttl_seconds: intent.ttl_seconds,
        alert_id: intent.alert_id,
        reason: intent.reason,
        requested_at: new Date(this.clock()).toISOString()
      });
      const record = {
        at: new Date(this.clock()).toISOString(),
        alert_id: intent.alert_id,
        action: intent.action,
        target: intent.target,
        dry_run: plan.dry_run,
        performed: false,
        error: null
      };
      if (plan.dry_run) {
        record.note = 'dry_run: request not sent';
        this.history.push(record);
        results.push(record);
        continue;
      }
      const envName = (this.config.actions.targets[ACTION_RULES[intent.action].target] || {}).secret_env;
      const secret = envName ? process.env[envName] : null;
      if (!secret) {
        record.error = 'secret env var ' + (envName || '(unset)') + ' is not set';
        this.history.push(record);
        results.push(record);
        continue;
      }
      const ts = String(Math.floor(this.clock() / 1000));
      try {
        const res = await postJson(intent.target_url, payload, {
          'x-sentinel-timestamp': ts,
          'x-sentinel-signature': signPayload(secret, ts, payload),
          'x-sentinel-action': intent.action
        }, 5000, this.transport);
        record.http_status = res.status;
        record.performed = res.status >= 200 && res.status < 300;
        if (!record.performed) record.error = 'target returned ' + res.status;
      } catch (e) {
        record.error = e.code || e.message;
      }
      this.history.push(record);
      results.push(record);
    }
    if (this.history.length > 200) this.history = this.history.slice(-200);
    return { plan, results };
  }

  stats() {
    const elig = this.eligibility();
    return {
      enabled: this.config.actions.enabled,
      dry_run: elig.dry_run,
      eligible: elig.eligible,
      reasons: elig.reasons,
      configured_targets: Object.keys(this.config.actions.targets || {}).filter(k => this.config.actions.targets[k].url),
      recent: this.history.slice(-10)
    };
  }
}

module.exports = { ActionGate, ACTION_RULES };
