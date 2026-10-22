'use strict';

const fs = require('fs');
const path = require('path');
const { redactHeaders, redactQuery } = require('../redact.cjs');

// Framework-neutral access logger. Works with a plain Node http server and with
// connect/Express-style middleware (req, res, next).
//
// The emitted JSONL is the canonical input for the http.access adapter, so an
// application can instrument itself without exposing request bodies or headers.
function createAccessLogger(opts) {
  opts = opts || {};
  if (!opts.logPath) throw new Error('createAccessLogger requires logPath');
  const logPath = path.resolve(opts.logPath);
  const getPrincipal = typeof opts.getPrincipal === 'function' ? opts.getPrincipal : () => null;
  const service = opts.service || null;
  const headerAllowlist = opts.headerAllowlist || ['user-agent'];

  fs.mkdirSync(path.dirname(logPath), { recursive: true, mode: 0o700 });
  try {
    if (!fs.existsSync(logPath)) fs.writeFileSync(logPath, '', { mode: 0o600 });
    fs.chmodSync(logPath, 0o600);
  } catch (e) { /* best effort */ }

  function write(record) {
    try {
      fs.appendFileSync(logPath, JSON.stringify(record) + '\n', { mode: 0o600 });
    } catch (e) {
      // Never break the application because auditing failed; surface on stderr.
      process.stderr.write(JSON.stringify({ ts: new Date().toISOString(), level: 'error', msg: 'access_log_write_failed', error: e.code || e.message }) + '\n');
    }
  }

  function middleware(req, res, next) {
    const started = process.hrtime.bigint();
    const startedAt = new Date().toISOString();
    let bytesOut = 0;

    const originalWrite = res.write;
    const originalEnd = res.end;
    res.write = function (chunk, encoding, cb) {
      if (chunk) bytesOut += Buffer.isBuffer(chunk) ? chunk.length : Buffer.byteLength(String(chunk), typeof encoding === 'string' ? encoding : 'utf8');
      return originalWrite.call(this, chunk, encoding, cb);
    };
    res.end = function (chunk, encoding, cb) {
      if (chunk && typeof chunk !== 'function') {
        bytesOut += Buffer.isBuffer(chunk) ? chunk.length : Buffer.byteLength(String(chunk), typeof encoding === 'string' ? encoding : 'utf8');
      }
      return originalEnd.call(this, chunk, encoding, cb);
    };

    res.on('finish', () => {
      const durationMs = Number(process.hrtime.bigint() - started) / 1e6;
      const url = req.originalUrl || req.url || '/';
      const qi = url.indexOf('?');
      let query = {};
      if (qi >= 0) {
        const params = new URLSearchParams(url.slice(qi + 1));
        for (const [k, v] of params.entries()) query[k] = v;
      }
      const headers = {};
      for (const h of headerAllowlist) {
        if (req.headers[h] != null) headers[h] = req.headers[h];
      }
      const fwd = req.headers['x-forwarded-for'];
      const ip = fwd ? String(fwd).split(',')[0].trim() : (req.socket && req.socket.remoteAddress);
      let principal = null;
      try {
        principal = getPrincipal(req) || null;
      } catch (e) {
        principal = null;
      }
      const rq = redactQuery(query);
      write({
        ts: startedAt,
        method: req.method,
        path: url,
        status: res.statusCode,
        duration_ms: Math.round(durationMs),
        bytes_in: req.headers['content-length'] ? Number(req.headers['content-length']) : 0,
        bytes_out: bytesOut,
        ip,
        principal,
        user_agent: req.headers['user-agent'] || null,
        headers: redactHeaders(headers),
        query: rq.values,
        query_keys: rq.keys,
        service,
        host: req.headers.host || null
      });
    });

    if (typeof next === 'function') next();
  }

  return {
    logPath,
    middleware,
    handler: middleware
  };
}

module.exports = { createAccessLogger };
