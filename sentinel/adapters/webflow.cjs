'use strict';

const fs = require('fs');
const { BaseAdapter } = require('./base.cjs');
const { JsonlTailer } = require('../tailer.cjs');
const { httpEvent } = require('../event.cjs');

// Webflow integration is intentionally limited to operator-exported logs.
// No API token is requested or stored, because Webflow's public API does not
// expose a documented security audit event stream for this use case.
class WebflowAdapter extends BaseAdapter {
  constructor(opts) {
    super(Object.assign({
      id: 'webflow.logs',
      name: 'Webflow (exported logs)',
      category: 'C: Data stores and external services',
      capabilities: ['parses operator-exported request logs when a log_path is supplied'],
      limitations: [
        'no authorized Webflow audit-log API integration exists in this build',
        'no Webflow API token is collected or stored',
        'without an exported log file this source is reported NOT CONFIGURED, not monitored'
      ],
      source: { type: 'file', format: 'jsonl' }
    }, opts));
    this.tailer = null;
  }

  async init() {
    if (this.config.enabled === false) {
      return this.markNotConfigured('disabled in config; no Webflow audit integration is configured');
    }
    if (!this.config.log_path) {
      return this.markNotConfigured('Webflow API audit logs are not configured; supply an exported JSONL log path or leave this source unmonitored');
    }
    try {
      const st = fs.statSync(this.config.log_path);
      if (!st.isFile()) return this.markUnavailable('configured Webflow log path is not a regular file');
      this.source = { path: this.config.log_path, bytes: st.size };
      this.tailer = new JsonlTailer({ file: this.config.log_path, maxLines: 1000, cursor: this.cursor });
      return this.markActive('tailing operator-exported Webflow log (delayed; not live API auditing)', { path: this.config.log_path, live: false });
    } catch (e) {
      return this.markUnavailable('Webflow log not readable: ' + (e.code || e.message));
    }
  }

  async poll() {
    if (this.status !== 'ACTIVE') return { events: [] };
    const res = this.tailer.poll();
    this.cursor = res.cursor;
    const events = [];
    for (const line of res.lines) {
      if (!line.parsed) continue;
      const raw = Object.assign({ facts: { log_source: 'webflow-export' } }, line.parsed);
      raw.facts = Object.assign({ provider: 'webflow', live: false }, raw.facts);
      try {
        events.push(httpEvent(raw, this.id));
      } catch (e) { /* skip */ }
    }
    this.succeeded(events.length);
    return { events };
  }
}

module.exports = { WebflowAdapter };
