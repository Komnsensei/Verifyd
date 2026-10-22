'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { canonicalJSON } = require('../engine/canonicalize.cjs');

// An anchor is a second copy of the evidence head, written somewhere the
// service account cannot rewrite without leaving a different copy behind: a
// UNC path, a mounted read-once share, or an authenticated HTTPS receiver.
// It is what turns "edit the local JSONL" into "the local head no longer
// matches the last published head".
//
// The anchor is intentionally small. It contains no events, only the chain
// head, sequence, record count and the newest event timestamp.

const SCHEMA = 'sentinel.anchor/1';

function hmac(secret, timestamp, body) {
  return crypto.createHmac('sha256', secret).update(timestamp + '.' + body).digest('hex');
}

class Anchor {
  constructor(opts) {
    opts = opts || {};
    this.path = opts.path || null;
    this.url = opts.url || null;
    this.secretEnv = opts.secret_env || null;
    this.intervalMs = opts.interval_ms || 60000;
    this.clock = opts.clock || (() => Date.now());
    this.transport = opts.transport || null;
    this.hostname = opts.hostname || null;
    this.logger = opts.logger || null;
    this.lastPublishAt = 0;
    this.lastError = null;
    this.lastPublished = null;
  }

  get configured() {
    return Boolean(this.path || this.url);
  }

  secret() {
    if (!this.secretEnv) return null;
    return process.env[this.secretEnv] || null;
  }

  open() {
    if (!this.path) return;
    fs.mkdirSync(path.dirname(this.path), { recursive: true, mode: 0o700 });
  }

  read() {
    if (!this.path) return null;
    try {
      const parsed = JSON.parse(fs.readFileSync(this.path, 'utf8'));
      if (!parsed || parsed.schema !== SCHEMA || typeof parsed.head !== 'string') return null;
      return parsed;
    } catch (e) {
      if (e.code === 'ENOENT') return null;
      return { parse_error: e.code || e.message };
    }
  }

  // Compare an existing off-host anchor with the store. A missing anchor is
  // not an error (first run); a head mismatch is.
  verify(store, hostname) {
    if (!this.configured) return { configured: false, ok: true, reason: 'anchor not configured' };
    const anchor = this.read();
    if (!anchor) {
      return { configured: true, ok: true, status: 'EMPTY', reason: 'no anchor has been published yet', hostname: hostname || this.hostname || null };
    }
    if (anchor.parse_error) return { configured: true, ok: false, status: 'UNREADABLE', reason: anchor.parse_error };
    const seq = Number(anchor.seq);
    const records = Number(anchor.records);
    if (!Number.isInteger(seq) || !Number.isInteger(records)) {
      return { configured: true, ok: false, status: 'MALFORMED', reason: 'anchor seq/records are not integers', anchor };
    }
    if (anchor.host && hostname && anchor.host !== hostname) {
      return { configured: true, ok: false, status: 'FOREIGN_HOST', reason: 'anchor belongs to ' + anchor.host, anchor };
    }
    const localSeq = Number(store.seq || 0);
    if (seq > localSeq) {
      return { configured: true, ok: false, status: 'ROLLBACK', reason: 'anchor seq ' + seq + ' is ahead of local seq ' + localSeq, anchor };
    }
    if (seq === localSeq && anchor.head !== store.head) {
      return { configured: true, ok: false, status: 'HEAD_MISMATCH', reason: 'anchor head differs from local head at the same seq', anchor };
    }
    return {
      configured: true,
      ok: true,
      status: 'MATCH',
      anchor,
      lag_records: localSeq - seq,
      published_at: anchor.published_at || null
    };
  }

  snapshot(store, lastEventTs) {
    return {
      schema: SCHEMA,
      host: this.hostname,
      head: store.head,
      seq: Number(store.seq || 0),
      records: Number(store.records != null ? store.records : store.seq || 0),
      last_event_ts: lastEventTs || null,
      published_at: new Date(this.clock()).toISOString()
    };
  }

  async publish(store, lastEventTs) {
    if (!this.configured) return { published: false, reason: 'not configured' };
    const snap = this.snapshot(store, lastEventTs);
    const body = canonicalJSON(snap);
    const errors = [];
    if (this.path) {
      try {
        const tmp = this.path + '.tmp';
        fs.writeFileSync(tmp, body, { mode: 0o600 });
        fs.renameSync(tmp, this.path);
      } catch (e) {
        errors.push('file: ' + (e.code || e.message));
      }
    }
    if (this.url) {
      const secret = this.secret();
      if (!secret) {
        errors.push('url: ' + (this.secretEnv || 'anchor secret') + ' is not set');
      } else {
        const timestamp = String(this.clock());
        try {
          const res = await this.send(this.url, body, timestamp, hmac(secret, timestamp, body));
          if (!res || res.status < 200 || res.status >= 300) {
            errors.push('url: HTTP ' + (res && res.status));
          }
        } catch (e) {
          errors.push('url: ' + (e.code || e.message));
        }
      }
    }
    this.lastPublishAt = this.clock();
    if (errors.length) {
      this.lastError = { at: new Date(this.clock()).toISOString(), message: errors.join('; ') };
      if (this.logger) this.logger.warn('anchor publish failed', { error: this.lastError.message });
      return { published: false, error: this.lastError.message };
    }
    this.lastError = null;
    this.lastPublished = snap;
    return { published: true, anchor: snap };
  }

  async send(url, body, timestamp, signature) {
    const headers = {
      'content-type': 'application/json',
      'x-sentinel-timestamp': timestamp,
      'x-sentinel-signature': signature
    };
    if (this.transport) return this.transport(url, { method: 'POST', headers, body });
    const res = await fetch(url, { method: 'POST', headers, body });
    return { status: res.status, ok: res.ok };
  }

  status() {
    return {
      configured: this.configured,
      path: this.path ? path.basename(this.path) : null,
      url: this.url ? new URL(this.url).host : null,
      last_publish_at: this.lastPublishAt ? new Date(this.lastPublishAt).toISOString() : null,
      last_published: this.lastPublished ? { head: this.lastPublished.head, seq: this.lastPublished.seq, records: this.lastPublished.records } : null,
      last_error: this.lastError
    };
  }
}

module.exports = { Anchor, SCHEMA, hmac };
