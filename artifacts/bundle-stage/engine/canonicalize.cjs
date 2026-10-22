'use strict';

const { DEFAULT_LIMITS } = require('./limits.cjs');

function fail(code, detail) {
  const e = new Error(detail || code);
  e.code = code;
  return e;
}

function isPlainObject(v) {
  if (!v || typeof v !== 'object') return false;
  const p = Object.getPrototypeOf(v);
  return p === Object.prototype || p === null;
}

function normalizeJsonValue(value, opts, state) {
  opts = opts || {};
  const limits = Object.assign({}, DEFAULT_LIMITS, opts.limits || {});
  state = state || {
    depth: 0,
    seen: new WeakSet(),
    path: '$',
    omitKeys: new Set(opts.omitKeys || [])
  };

  const t = typeof value;

  if (value === null) return null;

  if (t === 'string') {
    if (value.length > limits.maxStringLength) throw fail('STRING_LIMIT_EXCEEDED', state.path);
    return value;
  }

  if (t === 'boolean') return value;

  if (t === 'number') {
    if (!Number.isFinite(value)) throw fail('NON_FINITE_NUMBER_REJECTED', state.path);
    if (Object.is(value, -0)) return 0;
    return value;
  }

  if (t === 'undefined' || t === 'function' || t === 'symbol' || t === 'bigint') {
    throw fail('UNSAFE_JSON_VALUE_REJECTED', state.path + ' type=' + t);
  }

  if (state.depth > limits.maxDepth) throw fail('DEPTH_LIMIT_EXCEEDED', state.path);

  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    throw fail('BINARY_VALUE_REJECTED', state.path);
  }

  if (value instanceof Date) {
    throw fail('DATE_OBJECT_REJECTED_USE_ISO_STRING', state.path);
  }

  if (state.seen.has(value)) throw fail('CYCLE_REJECTED', state.path);
  state.seen.add(value);

  if (Array.isArray(value)) {
    if (value.length > limits.maxArrayLength) throw fail('ARRAY_LIMIT_EXCEEDED', state.path);
    const out = value.map((x, i) => normalizeJsonValue(x, opts, {
      depth: state.depth + 1,
      seen: state.seen,
      path: state.path + '[' + i + ']',
      omitKeys: state.omitKeys
    }));
    state.seen.delete(value);
    return out;
  }

  if (!isPlainObject(value)) throw fail('NON_PLAIN_OBJECT_REJECTED', state.path);

  const keys = Object.keys(value).filter(k => !state.omitKeys.has(k)).sort();
  if (keys.length > limits.maxKeysPerObject) throw fail('OBJECT_KEYS_LIMIT_EXCEEDED', state.path);

  const out = {};
  for (const k of keys) {
    out[k] = normalizeJsonValue(value[k], opts, {
      depth: state.depth + 1,
      seen: state.seen,
      path: state.path + '.' + k,
      omitKeys: state.omitKeys
    });
  }

  state.seen.delete(value);
  return out;
}

function canonicalJSON(value, opts) {
  opts = opts || {};
  const normalized = normalizeJsonValue(value, opts);
  const s = JSON.stringify(normalized);
  const limits = Object.assign({}, DEFAULT_LIMITS, opts.limits || {});
  if (Buffer.byteLength(s, 'utf8') > limits.maxCanonicalBytes) {
    throw fail('CANONICAL_BYTES_LIMIT_EXCEEDED', String(Buffer.byteLength(s, 'utf8')));
  }
  return s;
}

module.exports = { canonicalJSON, normalizeJsonValue };
