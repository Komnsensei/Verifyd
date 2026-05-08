'use strict';

const SECRET_RE = /(sk_live_[A-Za-z0-9_]+|sk-proj-[A-Za-z0-9_-]+|gsk_[A-Za-z0-9_-]+|ghp_[A-Za-z0-9_]+|vcp_[A-Za-z0-9_]+|(?:api[_-]?key|secret|token|password)\s*[:=]\s*['"][^'"]{12,}['"])/i;

function scanText(text) {
  text = String(text || '');
  const match = text.match(SECRET_RE);
  return {
    has_secret: !!match,
    pattern: match ? 'SECRET_PATTERN' : null
  };
}

function redact(text) {
  return String(text || '').replace(SECRET_RE, '[REDACTED_SECRET]');
}

module.exports = { SECRET_RE, scanText, redact };
