'use strict';

const { STATUS } = require('../version.cjs');

class BaseAdapter {
  constructor(opts) {
    opts = opts || {};
    this.id = opts.id;
    this.name = opts.name;
    this.category = opts.category;
    this.config = opts.config || {};
    this.deps = opts.deps || {};
    this.intervalMs = this.config.poll_interval_ms || 10000;
    this.status = STATUS.NOT_CONFIGURED;
    this.reason = 'adapter not initialised';
    this.detail = {};
    this.capabilities = opts.capabilities || [];
    this.limitations = opts.limitations || [];
    this.source = opts.source || null;
    this.last_ok_at = null;
    this.last_error = null;
    this.consecutive_failures = 0;
    this.events_emitted = 0;
    this.cursor = null;
  }

  markActive(reason, detail) {
    this.status = STATUS.ACTIVE;
    this.reason = reason || 'active';
    this.detail = detail || {};
    return this;
  }

  markUnavailable(reason, detail) {
    this.status = STATUS.UNAVAILABLE;
    this.reason = reason || 'unavailable';
    this.detail = detail || {};
    return this;
  }

  markNotConfigured(reason, detail) {
    this.status = STATUS.NOT_CONFIGURED;
    this.reason = reason || 'not configured';
    this.detail = detail || {};
    return this;
  }

  succeeded(count) {
    this.last_ok_at = new Date().toISOString();
    this.consecutive_failures = 0;
    this.last_error = null;
    if (count) this.events_emitted += count;
  }

  failed(err) {
    this.consecutive_failures += 1;
    this.last_error = { at: new Date().toISOString(), code: (err && err.code) || 'ADAPTER_ERROR', message: (err && err.message) || String(err) };
    if (this.status === STATUS.ACTIVE) {
      this.status = STATUS.UNAVAILABLE;
      this.reason = 'last poll failed: ' + this.last_error.message;
    }
  }

  getCursor() {
    return this.cursor;
  }

  restoreCursor(cursor) {
    this.cursor = cursor || null;
  }

  describe() {
    return {
      id: this.id,
      name: this.name,
      category: this.category,
      status: this.status,
      reason: this.reason,
      detail: this.detail,
      source: this.source,
      capabilities: this.capabilities,
      limitations: this.limitations,
      interval_ms: this.intervalMs,
      last_ok_at: this.last_ok_at,
      last_error: this.last_error,
      consecutive_failures: this.consecutive_failures,
      events_emitted: this.events_emitted
    };
  }

  async init() {
    this.markNotConfigured('adapter does not implement init()');
    return this;
  }

  async poll() {
    throw new Error(this.id + ' does not implement poll()');
  }

  async stop() {}
}

module.exports = { BaseAdapter };
