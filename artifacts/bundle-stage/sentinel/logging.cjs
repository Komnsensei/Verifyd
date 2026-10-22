'use strict';

const fs = require('fs');
const path = require('path');

const LEVELS = { error: 0, warn: 1, info: 2, debug: 3 };

// Bounded file sink for hosts that run the service without a console (Windows
// scheduled task). One generation of rotation is enough for operational logs;
// evidence has its own hash-chained store with its own retention.
function createFileSink(file, opts) {
  opts = opts || {};
  const maxBytes = opts.maxBytes || 10 * 1024 * 1024;
  const target = path.resolve(file);
  fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
  return function sink(line) {
    try {
      let size = 0;
      try { size = fs.statSync(target).size; } catch (e) { size = 0; }
      if (size + Buffer.byteLength(line) > maxBytes) {
        try { fs.renameSync(target, target + '.1'); } catch (e) { /* ignore */ }
      }
      fs.appendFileSync(target, line + '\n', { mode: 0o600 });
    } catch (e) {
      // Logging must never take the service down.
    }
  };
}

function createLogger(opts) {
  opts = opts || {};
  const level = LEVELS[opts.level] != null ? opts.level : 'info';
  const sink = opts.sink || ((line) => process.stderr.write(line + '\n'));
  const base = opts.fields || {};

  function emit(lvl, msg, fields) {
    if (LEVELS[lvl] > LEVELS[level]) return;
    const rec = Object.assign({ ts: new Date().toISOString(), level: lvl, msg }, base, fields || {});
    try {
      sink(JSON.stringify(rec));
    } catch (e) {
      sink(JSON.stringify({ ts: new Date().toISOString(), level: 'error', msg: 'log_serialization_failed' }));
    }
  }

  return {
    level,
    error: (msg, fields) => emit('error', msg, fields),
    warn: (msg, fields) => emit('warn', msg, fields),
    info: (msg, fields) => emit('info', msg, fields),
    debug: (msg, fields) => emit('debug', msg, fields),
    child: (fields) => createLogger(Object.assign({}, opts, { fields: Object.assign({}, base, fields) }))
  };
}

module.exports = { createLogger, createFileSink, LEVELS };
