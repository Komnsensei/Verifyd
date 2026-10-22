'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { redactHeaders, redactQuery } = require('../redact.cjs');

function asBuffer(chunk, encoding) {
  if (chunk == null) return null;
  if (Buffer.isBuffer(chunk)) return chunk;
  return Buffer.from(String(chunk), typeof encoding === 'string' ? encoding : 'utf8');
}

function jsonShape(value, depth) {
  if (depth > 3) return { type: 'truncated' };
  if (value === null) return { type: 'null' };
  if (Array.isArray(value)) {
    return { type: 'array', length: value.length, first: value.length ? jsonShape(value[0], depth + 1) : null };
  }
  if (typeof value === 'object') {
    const keys = Object.keys(value).slice(0, 30).sort();
    const fields = {};
    for (const key of keys) {
      const v = value[key];
      fields[key] = v === null ? 'null' : Array.isArray(v) ? 'array:' + v.length : typeof v;
    }
    return { type: 'object', keys, fields };
  }
  if (typeof value === 'string') return { type: 'string', length: value.length };
  return { type: typeof value };
}

function summarizeBody(hash, bytes, chunks, contentType) {
  if (!hash) return null;
  const out = { sha256: hash.digest('hex'), bytes };
  if (bytes > 0 && /json/i.test(String(contentType || ''))) {
    try { out.shape = jsonShape(JSON.parse(Buffer.concat(chunks).toString('utf8')), 0); } catch (e) { out.shape = null; }
  }
  return out;
}

// Framework-neutral access logger. Works with a plain Node http server and with
// connect/Express-style middleware (req, res, next).
//
// The emitted JSONL is the canonical input for the http.access adapter, so an
// application can instrument itself without exposing request bodies or headers.
// bodyMode=shape (default) stores a SHA-256 and a key/type/length skeleton; body
// values are never written. Use bodyMode=none to disable even that metadata.
function createAccessLogger(opts) {
  opts = opts || {};
  if (!opts.logPath) throw new Error('createAccessLogger requires logPath');
  const logPath = path.resolve(opts.logPath);
  const getPrincipal = typeof opts.getPrincipal === 'function' ? opts.getPrincipal : () => null;
  const service = opts.service || null;
  const headerAllowlist = opts.headerAllowlist || ['user-agent'];
  const bodyMode = opts.bodyMode || 'shape';
  const maxBodyBytes = Math.max(1024, Number(opts.maxBodyBytes) || 65536);
  const captureBodies = bodyMode === 'hash' || bodyMode === 'shape';

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
    let bytesIn = 0;
    const reqHash = captureBodies ? crypto.createHash('sha256') : null;
    const resHash = captureBodies ? crypto.createHash('sha256') : null;
    const reqChunks = [];
    const resChunks = [];
    let reqStored = 0;
    let resStored = 0;

    if (captureBodies && req && typeof req.on === 'function' && !req.readableEnded) {
      req.on('data', (chunk) => {
        const buf = asBuffer(chunk);
        if (!buf) return;
        bytesIn += buf.length;
        reqHash.update(buf);
        if (reqStored < maxBodyBytes) {
          const take = Math.min(buf.length, maxBodyBytes - reqStored);
          reqChunks.push(buf.subarray(0, take));
          reqStored += take;
        }
      });
    }

    let resContentType = null;
    const originalWriteHead = res.writeHead;
    res.writeHead = function (statusCode, statusMessage, headers) {
      const h = (typeof statusMessage === 'object' && statusMessage !== null) ? statusMessage : headers;
      if (h && typeof h === 'object') {
        for (const k of Object.keys(h)) {
          if (String(k).toLowerCase() === 'content-type') resContentType = h[k];
        }
      }
      return originalWriteHead.apply(this, arguments);
    };
    const originalWrite = res.write;
    const originalEnd = res.end;
    res.write = function (chunk, encoding, cb) {
      const buf = asBuffer(chunk, encoding);
      if (buf) {
        bytesOut += buf.length;
        if (resHash) {
          resHash.update(buf);
          if (resStored < maxBodyBytes) {
            const take = Math.min(buf.length, maxBodyBytes - resStored);
            resChunks.push(buf.subarray(0, take));
            resStored += take;
          }
        }
      }
      return originalWrite.call(this, chunk, encoding, cb);
    };
    res.end = function (chunk, encoding, cb) {
      const buf = (chunk && typeof chunk !== 'function') ? asBuffer(chunk, encoding) : null;
      if (buf) {
        bytesOut += buf.length;
        if (resHash) {
          resHash.update(buf);
          if (resStored < maxBodyBytes) {
            const take = Math.min(buf.length, maxBodyBytes - resStored);
            resChunks.push(buf.subarray(0, take));
            resStored += take;
          }
        }
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
      const reqBody = summarizeBody(reqHash, bytesIn, reqChunks, req.headers['content-type']);
      const resHeaderCt = res.getHeader ? res.getHeader('content-type') : null;
      const resBody = summarizeBody(resHash, bytesOut, resChunks, resHeaderCt || resContentType);
      write({
        ts: startedAt,
        method: req.method,
        path: url,
        status: res.statusCode,
        duration_ms: Math.round(durationMs),
        bytes_in: req.headers['content-length'] ? Number(req.headers['content-length']) : bytesIn,
        bytes_out: bytesOut,
        request_body_sha256: reqBody ? reqBody.sha256 : null,
        request_body_bytes: reqBody ? reqBody.bytes : null,
        request_body_shape: reqBody && reqBody.shape ? reqBody.shape : null,
        response_body_sha256: resBody ? resBody.sha256 : null,
        response_body_bytes: resBody ? resBody.bytes : null,
        response_body_shape: resBody && resBody.shape ? resBody.shape : null,
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
