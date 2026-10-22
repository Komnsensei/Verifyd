'use strict';

const { globToRegExp, ipMatches } = require('./rules.cjs');

function matchField(event, key, expected) {
  const values = Array.isArray(expected) ? expected : [expected];
  let actual;
  if (key === 'adapter') actual = event.adapter;
  else if (key === 'ip') actual = event.source.ip;
  else if (key === 'principal') actual = event.source.principal;
  else if (key === 'route') actual = event.request.route;
  else if (key === 'process') actual = event.host.process;
  else if (key === 'path') actual = event.host.path;
  else return false;
  if (actual == null) return false;
  for (const v of values) {
    if (v == null) continue;
    if (key === 'ip' && ipMatches(actual, String(v))) return true;
    if (key === 'route' || key === 'path') {
      if (globToRegExp(String(v)).test(String(actual))) return true;
    } else if (String(actual).toLowerCase() === String(v).toLowerCase()) {
      return true;
    }
  }
  return false;
}

// An entry matches when every field it declares matches. Entries with an
// `until` timestamp in the past are ignored, so temporary exceptions expire.
function matchesAllowlist(event, entries, nowMs) {
  if (!Array.isArray(entries) || entries.length === 0) return null;
  const now = nowMs || Date.now();
  for (const entry of entries) {
    if (!entry || typeof entry !== 'object') continue;
    if (entry.until && new Date(entry.until).getTime() < now) continue;
    const keys = ['adapter', 'ip', 'principal', 'route', 'process', 'path'].filter(k => entry[k] != null);
    if (keys.length === 0) continue;
    let all = true;
    for (const k of keys) {
      if (!matchField(event, k, entry[k])) { all = false; break; }
    }
    if (all) return entry;
  }
  return null;
}

module.exports = { matchesAllowlist, matchField };
