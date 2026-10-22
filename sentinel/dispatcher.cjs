'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const { validateTargetUrl } = require('./config.cjs');

const MAX_PAYLOAD_BYTES = 262144;

function nowIso(clock) {
  return new Date(clock()).toISOString();
}

function deterministicJitter(id, attempt) {
  const h = crypto.createHash('sha256').update(id + ':' + attempt).digest();
  return (h[0] / 255) * 0.25 + 0.875; // 0.875 - 1.125, stable across restarts
}

function signPayload(secret, timestamp, body) {
  return 'sha256=' + crypto.createHmac('sha256', secret).update(timestamp + '.' + body).digest('hex');
}

function postJson(url, body, headers, timeoutMs, transport) {
  const u = new URL(url);
  const mod = u.protocol === 'https:' ? https : http;
  const payload = Buffer.from(body, 'utf8');
  const opts = {
    method: 'POST',
    protocol: u.protocol,
    hostname: u.hostname,
    port: u.port || (u.protocol === 'https:' ? 443 : 80),
    path: u.pathname + (u.search || ''),
    headers: Object.assign({
      'content-type': 'application/json',
      'content-length': payload.length,
      'user-agent': 'sentinel-webhook/0.1'
    }, headers || {}),
    timeout: timeoutMs
  };
  if (transport) return transport(opts, payload);
  return new Promise((resolve, reject) => {
    const req = mod.request(opts, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8').slice(0, 1024);
        resolve({ status: res.statusCode, body: text });
      });
    });
    req.on('timeout', () => {
      req.destroy(new Error('webhook timeout after ' + timeoutMs + 'ms'));
    });
    req.on('error', reject);
    req.end(payload);
  });
}

// Durable, append-only alert queue.
//
// Every state change is an appended op (enqueue/attempt/ack/dead), so a crash or
// Windows restart mid-delivery replays deterministically instead of losing the
// alert. The queue file is compacted only when it grows well past live items.
class Dispatcher {
  constructor(opts) {
    opts = opts || {};
    this.dir = opts.dir;
    this.compactThresholdBytes = opts.compactThresholdBytes || 8 * 1024 * 1024;
    this.retainItems = opts.retainItems || 2000;
    this.queuePath = path.join(this.dir, 'alerts.queue.jsonl');
    this.webhook = opts.webhook || {};
    this.clock = opts.clock || (() => Date.now());
    this.transport = opts.transport || null;
    this.logger = opts.logger || { warn() {}, info() {} };
    this.items = new Map();
    this.seq = 0;
    this.counters = { enqueued: 0, sent: 0, failed_attempts: 0, deadlettered: 0, acks_replayed: 0 };
    this.last_error = null;
    this.last_success_at = null;
    this.fd = null;
    this.status = 'NOT_CONFIGURED';
    this.status_reason = 'no webhook destination configured; alerts remain in the local evidence store';
  }

  secret() {
    const name = this.webhook.secret_env;
    if (!name) return null;
    const v = process.env[name];
    return v ? v : null;
  }

  open() {
    fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    if (fs.existsSync(this.queuePath)) this.replay();
    this.fd = fs.openSync(this.queuePath, 'a', 0o600);
    try { fs.chmodSync(this.queuePath, 0o600); } catch (e) { /* best effort */ }
    this.maybeCompact();
    this.refreshStatus();
    return this;
  }

  refreshStatus() {
    if (!this.webhook.url) {
      this.status = 'NOT_CONFIGURED';
      this.status_reason = 'alerts.webhook.url is empty; alerts are stored and queued locally only';
      return;
    }
    const urlErrors = validateTargetUrl(this.webhook.url, 'alerts.webhook.url', { allow_insecure_loopback: this.webhook.allow_insecure_loopback });
    if (urlErrors.length > 0) {
      this.status = 'UNAVAILABLE';
      this.status_reason = urlErrors.join('; ');
      return;
    }
    if (!this.secret()) {
      this.status = 'UNAVAILABLE';
      this.status_reason = 'webhook configured but secret env var ' + (this.webhook.secret_env || '(unset)') + ' is not set';
      return;
    }
    this.status = 'ACTIVE';
    this.status_reason = 'signed webhook delivery enabled';
  }

  replay() {
    const text = fs.readFileSync(this.queuePath, 'utf8');
    for (const line of text.split('\n')) {
      if (!line) continue;
      let op;
      try { op = JSON.parse(line); } catch (e) { continue; }
      this.applyOp(op);
    }
  }

  applyOp(op) {
    if (!op || !op.id) return;
    if (op.op === 'enqueue') {
      if (!this.items.has(op.id)) {
        this.items.set(op.id, {
          id: op.id,
          alert: op.alert,
          attempts: 0,
          next_at: 0,
          status: 'pending',
          enqueued_at: op.at,
          last_error: null,
          delivered_at: null
        });
        this.counters.enqueued += 1;
      }
    } else if (op.op === 'attempt') {
      const item = this.items.get(op.id);
      if (item) {
        item.attempts = op.attempt;
        item.next_at = op.next_at;
        item.last_error = op.error || null;
      }
    } else if (op.op === 'ack') {
      const item = this.items.get(op.id);
      if (item) {
        item.status = 'acked';
        item.delivered_at = op.at;
        this.counters.sent += 1;
      }
    } else if (op.op === 'dead') {
      const item = this.items.get(op.id);
      if (item) {
        item.status = 'dead';
        item.last_error = op.error || item.last_error;
        this.counters.deadlettered += 1;
      }
    }
  }

  appendOp(op) {
    const line = JSON.stringify(op) + '\n';
    fs.writeSync(this.fd, line);
  }

  enqueue(alert) {
    const id = alert.alert_id || crypto.createHash('sha256').update(JSON.stringify(alert)).digest('hex').slice(0, 32);
    if (this.items.has(id)) return id;
    const at = nowIso(this.clock);
    const op = { op: 'enqueue', id, at, alert };
    this.appendOp(op);
    this.applyOp(op);
    return id;
  }

  pending() {
    return Array.from(this.items.values()).filter(i => i.status === 'pending');
  }

  backoffMs(attempt, id) {
    const base = this.webhook.backoff_base_ms || 500;
    const max = this.webhook.backoff_max_ms || 60000;
    const raw = base * Math.pow(2, Math.max(0, attempt - 1));
    return Math.min(max, Math.round(raw * deterministicJitter(id, attempt)));
  }

  async flush() {
    this.refreshStatus();
    if (this.status !== 'ACTIVE') {
      return { status: this.status, reason: this.status_reason, sent: 0, pending: this.pending().length };
    }
    const now = this.clock();
    const due = this.pending().filter(i => (i.next_at || 0) <= now);
    let sent = 0;
    for (const item of due) {
      const body = JSON.stringify({ schema: 'sentinel.webhook/1', alert: item.alert });
      if (Buffer.byteLength(body) > MAX_PAYLOAD_BYTES) {
        this.fail(item, 'payload_too_large', true);
        continue;
      }
      const ts = String(Math.floor(now / 1000));
      const secret = this.secret();
      const headers = {
        'x-sentinel-timestamp': ts,
        'x-sentinel-signature': signPayload(secret, ts, body),
        'x-sentinel-rule': item.alert.rule_id || 'unknown',
        'x-sentinel-alert-id': item.id
      };
      try {
        const res = await postJson(this.webhook.url, body, headers, this.webhook.timeout_ms || 5000, this.transport);
        if (res.status >= 200 && res.status < 300) {
          const op = { op: 'ack', id: item.id, at: nowIso(this.clock) };
          this.appendOp(op);
          this.applyOp(op);
          this.last_success_at = op.at;
          this.last_error = null;
          sent += 1;
        } else {
          this.fail(item, 'http_' + res.status, false);
        }
      } catch (e) {
        this.fail(item, e.code || e.message || 'transport_error', false);
      }
    }
    this.pruneItems();
    this.maybeCompact();
    return { status: this.status, sent, pending: this.pending().length, dead: this.counters.deadlettered };
  }

  pruneItems() {
    if (this.items.size <= this.retainItems) return;
    for (const [id, item] of this.items) {
      if (this.items.size <= this.retainItems) break;
      if (item.status === 'acked' || item.status === 'dead') this.items.delete(id);
    }
  }

  // Queue compaction rewrites only live items. Attempt/backoff state is kept so
  // a receiver outage does not reset an already backed-off alert.
  maybeCompact() {
    let size = 0;
    try { size = fs.statSync(this.queuePath).size; } catch (e) { return false; }
    if (size <= this.compactThresholdBytes) return false;
    if (this.fd !== null) {
      fs.closeSync(this.fd);
      this.fd = null;
    }
    const tmp = this.queuePath + '.tmp';
    const lines = [];
    for (const item of this.items.values()) {
      if (item.status !== 'pending') continue;
      lines.push(JSON.stringify({ op: 'enqueue', id: item.id, at: item.enqueued_at, alert: item.alert }));
      if (item.attempts > 0) {
        lines.push(JSON.stringify({ op: 'attempt', id: item.id, at: new Date(this.clock()).toISOString(), attempt: item.attempts, next_at: item.next_at, error: item.last_error }));
      }
    }
    try {
      fs.writeFileSync(tmp, lines.length ? lines.join('\n') + '\n' : '', { mode: 0o600 });
      fs.renameSync(tmp, this.queuePath);
      this.logger.info('alert queue compacted', { live: this.pending().length, removed_bytes: size });
      return true;
    } catch (e) {
      this.logger.warn('alert queue compaction failed', { error: e.code || e.message });
      return false;
    } finally {
      if (this.fd === null) this.fd = fs.openSync(this.queuePath, 'a', 0o600);
    }
  }

  fail(item, error, permanent) {
    const attempt = item.attempts + 1;
    const maxAttempts = this.webhook.max_attempts || 6;
    const dead = permanent || attempt >= maxAttempts;
    const at = nowIso(this.clock);
    const nextAt = dead ? 0 : this.clock() + this.backoffMs(attempt, item.id);
    const op = dead
      ? { op: 'dead', id: item.id, at, attempt, error }
      : { op: 'attempt', id: item.id, at, attempt, next_at: nextAt, error };
    this.appendOp(op);
    this.applyOp(op);
    this.last_error = { at, error };
    this.counters.failed_attempts += 1;
    this.logger.warn('webhook delivery failed', { id: item.id, attempt, error, dead });
  }

  stats() {
    const pending = this.pending();
    const all = Array.from(this.items.values());
    return {
      status: this.status,
      status_reason: this.status_reason,
      queued: pending.length,
      delivered: this.counters.sent,
      dead_letter: this.counters.deadlettered,
      retained_records: all.length,
      last_success_at: this.last_success_at,
      last_error: this.last_error
    };
  }

  close() {
    if (this.fd !== null) {
      try { fs.closeSync(this.fd); } catch (e) { /* ignore */ }
      this.fd = null;
    }
  }
}

module.exports = { Dispatcher, signPayload, postJson, deterministicJitter, MAX_PAYLOAD_BYTES };
