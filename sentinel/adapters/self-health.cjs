'use strict';

const fs = require('fs');
const path = require('path');
const { BaseAdapter } = require('./base.cjs');

class SelfHealthAdapter extends BaseAdapter {
  constructor(opts) {
    super(Object.assign({
      id: 'self.health',
      name: 'Monitoring-service health',
      category: 'B: Windows host',
      capabilities: [
        'evidence store writability, chain head and size utilization',
        'alert queue depth and delivery errors',
        'process memory and event-loop lag proxy',
        'disk free space on the state volume'
      ],
      limitations: [
        'reports the service\'s own health only; it cannot detect its own total failure (needs an external heartbeat)',
        'disk free is read from the state directory volume only'
      ],
      source: { type: 'in-process', method: 'fs + process metrics' }
    }, opts));
    this.stateDir = this.deps.stateDir;
    this.lastStatus = null;
    this.lastEmitAt = 0;
    this.lastHeartbeatAt = 0;
  }

  async init() {
    if (this.config.enabled === false) return this.markNotConfigured('disabled in config');
    try {
      const probe = path.join(this.stateDir, '.health-probe');
      fs.writeFileSync(probe, String(Date.now()));
      fs.unlinkSync(probe);
      return this.markActive('state directory is writable', { state_dir: this.stateDir });
    } catch (e) {
      return this.markUnavailable('state directory not writable: ' + (e.code || e.message));
    }
  }

  async poll() {
    if (!this.config.enabled) return { events: [] };
    const nowIso = new Date().toISOString();
    const health = this.deps.getHealth ? this.deps.getHealth() : {};
    const mem = process.memoryUsage();
    const facts = {
      status: health.status || 'unknown',
      store_writable: health.store_writable !== false,
      chain_ok: health.chain_ok !== false,
      store_utilization: health.store ? Number((health.store.utilization || 0).toFixed(3)) : null,
      queue_pending: health.dispatcher ? health.dispatcher.queued : null,
      adapters_active: health.adapters_active != null ? health.adapters_active : null,
      adapters_unavailable: health.adapters_unavailable != null ? health.adapters_unavailable : null,
      missed_polls: health.missed_polls != null ? health.missed_polls : null,
      rss_bytes: mem.rss,
      heap_used_bytes: mem.heapUsed,
      heap_total_bytes: mem.heapTotal,
      external_bytes: mem.external
    };

    try {
      const st = fs.statfsSync(this.stateDir);
      facts.disk_free_bytes = Number(st.bavail) * Number(st.bsize);
      facts.disk_total_bytes = Number(st.blocks) * Number(st.bsize);
    } catch (e) {
      facts.disk_free_bytes = null;
    }

    const events = [];
    const maxUtil = this.config.max_store_utilization || 0.9;
    const degraded = facts.store_utilization != null && facts.store_utilization > maxUtil;
    const reasons = [];
    if (!facts.store_writable) reasons.push('store_not_writable');
    if (!facts.chain_ok) reasons.push('chain_invalid');
    if (degraded) reasons.push('store_utilization_high');
    if (facts.status !== 'ok') reasons.push('service_degraded');

    const shouldEmit = reasons.length > 0 || this.lastStatus !== 'ok' || (Date.now() - this.lastEmitAt) >= 300000;
    if (shouldEmit) {
      events.push({
        adapter: this.id,
        kind: 'service.health',
        ts: nowIso,
        hint: 'health:' + nowIso,
        outcome: 'observed',
        facts: Object.assign(facts, { reasons, heartbeat: reasons.length === 0 })
      });
      this.lastEmitAt = Date.now();
    }
    this.lastStatus = reasons.length ? 'degraded' : 'ok';
    this.cursor = { last_heartbeat_at: nowIso };
    this.succeeded(events.length);
    return { events };
  }
}

module.exports = { SelfHealthAdapter };
