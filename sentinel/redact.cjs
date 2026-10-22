'use strict';

// Redaction is applied at the boundary (adapter output -> store) so that no
// credential material is ever written to the evidence log, even if an upstream
// access log contains it. Keys are matched case-insensitively.

const REDACTED = '[REDACTED]';

const SENSITIVE_KEY_PATTERNS = [
  /^authorization$/i,
  /^proxy-authorization$/i,
  /^cookie$/i,
  /^set-cookie$/i,
  /^x-api-key$/i,
  /^x-auth-token$/i,
  /^x-csrf-token$/i,
  /^x-xsrf-token$/i,
  /^api[-_]?key$/i,
  /^apikey$/i,
  /^access[-_]?token$/i,
  /^refresh[-_]?token$/i,
  /^id[-_]?token$/i,
  /^session[-_]?id$/i,
  /^session$/i,
  /^password$/i,
  /^passwd$/i,
  /^secret$/i,
  /^client[-_]?secret$/i,
  /^private[-_]?key$/i,
  /^credential(s)?$/i,
  /^auth$/i,
  /^bearer$/i,
  /^token$/i,
  /^signature$/i,
  /^otp$/i,
  /^card[-_]?number$/i,
  /^cvv$/i
];

// Free-text credential shapes. Bounded to keep redaction O(n) and predictable.
const TEXT_PATTERNS = [
  { name: 'jwt', re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  { name: 'bearer', re: /\bBearer\s+[A-Za-z0-9._~+/=-]{12,}/gi },
  { name: 'basic', re: /\bBasic\s+[A-Za-z0-9+/=]{8,}/gi },
  { name: 'aws-access-key', re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { name: 'openai-key', re: /\bsk-[A-Za-z0-9_-]{20,}\b/g },
  { name: 'github-token', re: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g },
  { name: 'slack-token', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g },
  { name: 'private-key-block', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g }
];

const MAX_STRING = 2048;
const MAX_DEPTH = 8;

function isSensitiveKey(key) {
  if (typeof key !== 'string') return false;
  for (const re of SENSITIVE_KEY_PATTERNS) {
    if (re.test(key)) return true;
  }
  return false;
}

function redactText(value) {
  if (typeof value !== 'string') return value;
  let out = value;
  for (const p of TEXT_PATTERNS) {
    out = out.replace(p.re, '[REDACTED:' + p.name + ']');
  }
  if (out.length > MAX_STRING) {
    out = out.slice(0, MAX_STRING) + '...[truncated]';
  }
  return out;
}

function redact(value, depth) {
  depth = depth || 0;
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') return redactText(value);
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (depth >= MAX_DEPTH) return '[TRUNCATED_DEPTH]';
  if (Array.isArray(value)) {
    const cap = Math.min(value.length, 200);
    const out = new Array(cap);
    for (let i = 0; i < cap; i++) out[i] = redact(value[i], depth + 1);
    return out;
  }
  if (typeof value === 'object') {
    const out = {};
    for (const k of Object.keys(value)) {
      out[k] = isSensitiveKey(k) ? REDACTED : redact(value[k], depth + 1);
    }
    return out;
  }
  return '[UNSUPPORTED:' + typeof value + ']';
}

// Header maps get an extra pass: any header name we do not explicitly keep is
// dropped rather than stored, because unknown headers are a common leak path.
const KEPT_HEADERS = new Set(['user-agent', 'content-type', 'accept', 'referer', 'x-forwarded-for', 'cf-connecting-ip', 'host']);

function redactHeaders(headers) {
  if (!headers || typeof headers !== 'object') return {};
  const out = {};
  for (const rawKey of Object.keys(headers)) {
    const key = String(rawKey).toLowerCase();
    if (isSensitiveKey(key)) {
      out[key] = REDACTED;
      continue;
    }
    if (!KEPT_HEADERS.has(key)) continue;
    out[key] = redactText(String(headers[rawKey]));
  }
  return out;
}

// URL query handling: keep parameter names and only allowlisted, non-sensitive
// scalar values. Everything else becomes a hash-free marker.
const SAFE_QUERY_KEYS = new Set(['page', 'offset', 'limit', 'per_page', 'pagesize', 'cursor', 'sort', 'order', 'q', 'search', 'filter', 'since', 'until']);

function redactQuery(query) {
  if (!query || typeof query !== 'object') return { keys: [], values: {} };
  const keys = Object.keys(query).sort();
  const values = {};
  for (const k of keys) {
    if (!SAFE_QUERY_KEYS.has(k) || isSensitiveKey(k)) continue;
    const v = query[k];
    if (typeof v === 'string' || typeof v === 'number') {
      values[k] = redactText(String(v)).slice(0, 128);
    } else if (Array.isArray(v) && v.length > 0) {
      values[k] = String(v[0]).slice(0, 128);
    }
  }
  return { keys, values };
}

module.exports = {
  REDACTED,
  isSensitiveKey,
  redactText,
  redact,
  redactHeaders,
  redactQuery
};
