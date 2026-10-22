'use strict';

const http = require('http');
const crypto = require('crypto');
const { isLoopbackHost } = require('./config.cjs');

function safeEqual(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function json(res, status, obj) {
  const body = JSON.stringify(obj, null, 2);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff'
  });
  res.end(body);
}

// Diagnostics server. Loopback by default; a non-loopback bind requires the
// configured token on every request except /health, which stays minimal.
function createHealthServer(opts) {
  const snapshot = opts.snapshot;
  const bind = opts.bind || '127.0.0.1';
  const port = opts.port || 8790;
  const tokenEnv = opts.tokenEnv;
  const requireToken = !isLoopbackHost(bind);
  const recentLimit = opts.recentLimit || 25;
  let server = null;
  let actualPort = null;

  function authorized(req) {
    if (!tokenEnv) return !requireToken;
    const expected = process.env[tokenEnv];
    if (!expected) return false;
    const header = req.headers['authorization'];
    const bearer = header && /^Bearer\s+(.+)$/i.exec(header);
    const provided = (bearer && bearer[1]) || req.headers['x-sentinel-token'];
    return Boolean(provided) && safeEqual(provided, expected);
  }

  const handler = (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const pathname = url.pathname;
    const snap = snapshot();

    if (pathname === '/health') {
      const ok = snap.health.status === 'ok';
      return json(res, ok ? 200 : 503, {
        status: snap.health.status,
        service: 'sentinel',
        version: snap.version,
        uptime_s: snap.health.uptime_s,
        last_cycle_at: snap.health.last_cycle_at,
        store_writable: snap.health.store_writable,
        evidence_chain_ok: snap.health.chain_ok
      });
    }

    if (!authorized(req)) {
      return json(res, 401, { error: 'unauthorized', detail: 'supply the token from ' + (tokenEnv || '(unset)') + ' as Authorization: Bearer or X-Sentinel-Token' });
    }

    if (pathname === '/status') {
      return json(res, 200, {
        service: 'sentinel',
        version: snap.version,
        health: snap.health,
        detection: snap.detection,
        dispatcher: snap.dispatcher,
        actions: snap.actions,
        adapters: snap.adapters.map(a => ({ id: a.id, status: a.status, reason: a.reason, last_ok_at: a.last_ok_at, failures: a.consecutive_failures })),
        store: snap.store
      });
    }
    if (pathname === '/coverage') {
      return json(res, 200, { generated_at: new Date().toISOString(), adapters: snap.adapters, blind_spots: snap.blind_spots });
    }
    if (pathname === '/alerts/recent') {
      const limit = Math.min(Number(url.searchParams.get('limit')) || recentLimit, 200);
      return json(res, 200, { alerts: snap.recent_alerts.slice(-limit) });
    }
    if (pathname === '/metrics') {
      const lines = [];
      lines.push('# TYPE sentinel_events_total counter');
      lines.push('sentinel_events_total ' + snap.counters.events);
      lines.push('# TYPE sentinel_alerts_total counter');
      lines.push('sentinel_alerts_total ' + snap.counters.alerts);
      lines.push('# TYPE sentinel_adapter_up gauge');
      for (const a of snap.adapters) {
        lines.push('sentinel_adapter_up{adapter="' + a.id + '"} ' + (a.status === 'ACTIVE' ? 1 : 0));
      }
      lines.push('# TYPE sentinel_queue_pending gauge');
      lines.push('sentinel_queue_pending ' + (snap.dispatcher.queued || 0));
      res.writeHead(200, { 'content-type': 'text/plain; version=0.0.4', 'cache-control': 'no-store' });
      return res.end(lines.join('\n') + '\n');
    }
    return json(res, 404, { error: 'not_found' });
  };

  return {
    start() {
      return new Promise((resolve, reject) => {
        server = http.createServer(handler);
        server.on('error', reject);
        server.listen(port, bind, () => {
          actualPort = server.address().port;
          resolve({ port: actualPort, bind });
        });
      });
    },
    close() {
      return new Promise((resolve) => {
        if (!server) return resolve();
        server.close(() => resolve());
        if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
      });
    },
    address() {
      return { bind, port: actualPort, require_token: requireToken || Boolean(tokenEnv) };
    }
  };
}

module.exports = { createHealthServer, safeEqual };
