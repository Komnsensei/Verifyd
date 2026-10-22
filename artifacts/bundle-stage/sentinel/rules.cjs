'use strict';

const crypto = require('crypto');
const { canonicalJSON } = require('../engine/canonicalize.cjs');
const { ALERT_SCHEMA, VERSION } = require('./version.cjs');

// ---------------------------------------------------------------------------
// Deterministic scoring rubric.
//
// Every number below is an initial tuning value, not a calibrated probability.
// Scores from separate rules are additive only through the correlation pass,
// which requires at least two distinct rules for the same entity inside the
// configured window. Single detections never inherit another rule's score.
// ---------------------------------------------------------------------------

const RULE_DEFS = [
  {
    id: 'AUTH_FAIL_BURST',
    title: 'Repeated authentication failures',
    score_key: 'auth_fail_burst',
    kinds: ['http.request', 'host.session'],
    applies(event) {
      return event.outcome === 'auth_failure' || event.response.status === 401 || event.response.status === 407;
    },
    test(ctx) {
      const cfg = ctx.ruleCfg;
      if (ctx.samples.length < cfg.min_events) return null;
      const routes = uniq(ctx.samples.map(s => s.route)).slice(0, 10);
      return {
        score: cfg.score,
        evidence: {
          failures: ctx.samples.length,
          window_ms: ctx.windowMs,
          statuses: uniq(ctx.samples.map(s => s.status)),
          routes,
          first_failure_at: ctx.samples[0].at,
          last_failure_at: ctx.samples[ctx.samples.length - 1].at
        },
        facts: { failure_count: ctx.samples.length }
      };
    }
  },
  {
    id: 'RATE_LIMIT_BURST',
    title: 'Repeated rate-limit responses',
    score_key: 'rate_limit_burst',
    kinds: ['http.request'],
    applies(event) {
      return event.response.status === 429 || event.outcome === 'rate_limited';
    },
    test(ctx) {
      const cfg = ctx.ruleCfg;
      if (ctx.samples.length < cfg.min_events) return null;
      return {
        score: cfg.score,
        evidence: { rate_limited: ctx.samples.length, window_ms: ctx.windowMs, routes: uniq(ctx.samples.map(s => s.route)).slice(0, 10) }
      };
    }
  },
  {
    id: 'DENIED_THEN_SUCCESS',
    title: 'Access denied followed by successful access',
    score_key: 'denied_then_success',
    kinds: ['http.request'],
    applies(event) {
      return event.response.status != null;
    },
    test(ctx) {
      const cfg = ctx.ruleCfg;
      const ev = ctx.event;
      if (!(ev.response.status >= 200 && ev.response.status < 300)) return null;
      const deniedAt = ctx.state.denied.get(ev.request.route);
      if (!deniedAt) return null;
      ctx.state.denied.delete(ev.request.route);
      return {
        score: cfg.score,
        evidence: {
          route: ev.request.route,
          denied_at: deniedAt.at,
          denied_status: deniedAt.status,
          success_at: ev.ts,
          elapsed_ms: new Date(ev.ts).getTime() - new Date(deniedAt.at).getTime()
        }
      };
    }
  },
  {
    id: 'SEQUENTIAL_ENUMERATION',
    title: 'Sequential record enumeration',
    score_key: 'sequential_enumeration',
    kinds: ['http.request'],
    applies(event) {
      return event.request.method === 'GET' && event.response.status >= 200 && event.response.status < 300;
    },
    test(ctx) {
      const cfg = ctx.ruleCfg;
      const ev = ctx.event;
      const pages = ctx.state.pages;
      const ids = ctx.state.ids;

      const pageVal = ev.request.page != null ? ev.request.page : ev.request.offset;
      if (pageVal != null && Number.isFinite(pageVal)) {
        pages.set(pageVal, ev.ts);
        const numeric = Array.from(pages.keys()).sort((a, b) => a - b);
        const run = longestConsecutiveRun(numeric);
        if (numeric.length >= cfg.min_pages || run >= cfg.min_pages) {
          return {
            score: cfg.score,
            evidence: {
              mode: 'pagination',
              distinct_pages: numeric.length,
              longest_consecutive_run: run,
              pages: numeric.slice(0, 25),
              window_ms: ctx.windowMs,
              route: ev.request.route
            },
            facts: { distinct_pages: numeric.length, consecutive_run: run }
          };
        }
      }

      const pathId = numericPathId(ev.request.path);
      if (pathId != null) {
        ids.push(pathId);
        if (ids.length > 500) ids.shift();
        const unique = Array.from(new Set(ids));
        const run = longestConsecutiveRun(unique.slice().sort((a, b) => a - b));
        if (unique.length >= cfg.min_ids && run >= Math.floor(cfg.min_ids * 0.8)) {
          return {
            score: cfg.score,
            evidence: {
              mode: 'path-identifiers',
              distinct_ids: unique.length,
              longest_consecutive_run: run,
              first_id: unique[0],
              last_id: unique[unique.length - 1],
              window_ms: ctx.windowMs,
              route: ev.request.route
            },
            facts: { distinct_ids: unique.length, consecutive_run: run }
          };
        }
      }
      return null;
    }
  },
  {
    id: 'BULK_RESPONSE_VOLUME',
    title: 'Unusual bulk response volume',
    score_key: 'bulk_response_volume',
    kinds: ['http.request'],
    applies(event) {
      return event.response.bytes_out != null && event.response.status >= 200 && event.response.status < 300;
    },
    test(ctx) {
      const cfg = ctx.ruleCfg;
      const ev = ctx.event;
      const base = ctx.baseline.summary(ev.request.route, ev.ts);
      const single = ev.response.bytes_out;
      const total = ctx.samples.reduce((a, s) => a + s.bytes, 0);

      if (single >= cfg.min_bytes_single) {
        return {
          score: cfg.score,
          evidence: {
            mode: 'single_response',
            bytes_out: single,
            threshold_bytes: cfg.min_bytes_single,
            route: ev.request.route,
            baseline_ratio: base.ratio,
            baseline_established: base.established
          },
          facts: { bytes_out: single }
        };
      }

      if (total >= cfg.min_bytes_window) {
        if (!cfg.ignore_baseline && ctx.baseline.isWithinBaseline(ev.request.route, ev.ts)) {
          ctx.suppressedByBaseline = true;
          return null;
        }
        return {
          score: cfg.score,
          evidence: {
            mode: 'window_total',
            bytes_out: total,
            responses: ctx.samples.length,
            threshold_bytes: cfg.min_bytes_window,
            window_ms: ctx.windowMs,
            route: ev.request.route,
            baseline_ratio: base.ratio,
            baseline_established: base.established
          },
          facts: { bytes_out: total, responses: ctx.samples.length }
        };
      }
      return null;
    }
  },
  {
    id: 'SENSITIVE_ROUTE_REPEAT',
    title: 'Repeated access to sensitive endpoints',
    score_key: 'sensitive_route_repeat',
    kinds: ['http.request'],
    applies(event) {
      return matchAnyRoute(event.request.route, this._routes || []);
    },
    test(ctx) {
      const cfg = ctx.ruleCfg;
      const ev = ctx.event;
      // Repetition is per route; aggregating across sensitive routes would
      // overstate a client that touches each endpoint once.
      const hits = ctx.samples.filter(s => s.route === ev.request.route);
      if (hits.length < cfg.min_hits) return null;
      const base = ctx.baseline.summary(ev.request.route, ev.ts);
      const bcfg = ctx.baselineCfg || {};
      if (bcfg.enabled !== false && bcfg.require_baseline !== false && !base.established) {
        // Learning window: repetition is only judged against a baseline once one
        // exists. Individual bulk/unauthorized rules still fire during learning.
        return null;
      }
      if (!ctx.ruleCfg.ignore_baseline && base.established && base.ratio !== null && base.ratio < ctx.baseline.alertRatio) {
        return null;
      }
      return {
        score: cfg.score,
        evidence: {
          hits: hits.length,
          min_hits: cfg.min_hits,
          route: ev.request.route,
          window_ms: ctx.windowMs,
          baseline_ratio: base.ratio,
          baseline_established: base.established
        },
        facts: { hits: hits.length }
      };
    }
  },
  {
    id: 'PROTECTED_UNAUTHENTICATED',
    title: 'Protected endpoint accessed without authorization',
    score_key: 'protected_unauthenticated',
    kinds: ['http.request'],
    applies(event) {
      if (!matchAnyRoute(event.request.route, this._routes || [])) return false;
      const okStatus = event.response.status >= 200 && event.response.status < 300;
      if (!okStatus) return false;
      const authorized = event.facts && event.facts.authorized;
      return !event.source.principal || authorized === false;
    },
    test(ctx) {
      const cfg = ctx.ruleCfg;
      const ev = ctx.event;
      return {
        score: cfg.score,
        critical: true,
        evidence: {
          route: ev.request.route,
          status: ev.response.status,
          principal: ev.source.principal,
          authorized_flag: ev.facts && ev.facts.authorized != null ? ev.facts.authorized : null,
          bytes_out: ev.response.bytes_out,
          reason: ev.source.principal ? 'authenticated principal marked unauthorized' : 'no authenticated principal on protected route'
        },
        facts: { protected_route: ev.request.route, unauthenticated: !ev.source.principal }
      };
    }
  },
  {
    id: 'NEW_LISTENER',
    title: 'New network listener appeared',
    score_key: 'new_listener',
    kinds: ['host.listener'],
    applies(event) {
      return event.facts && event.facts.is_new === true && event.facts.allowlisted_process !== true;
    },
    test(ctx) {
      const cfg = ctx.ruleCfg;
      const ev = ctx.event;
      return {
        score: cfg.score,
        evidence: {
          address: ev.host.address,
          port: ev.host.port,
          process: ev.host.process,
          pid: ev.host.pid,
          baseline_ports: ev.facts.baseline_ports || null,
          first_seen: ev.facts.first_seen || ev.ts
        }
      };
    }
  },
  {
    id: 'PROCESS_FROM_TEMP',
    title: 'Process launched from a temporary directory',
    score_key: 'process_from_temp',
    kinds: ['host.process'],
    applies(event) {
      return event.facts && event.facts.from_temp_dir === true && event.facts.allowlisted_process !== true;
    },
    test(ctx) {
      const cfg = ctx.ruleCfg;
      const ev = ctx.event;
      return {
        score: cfg.score,
        evidence: {
          process: ev.host.process,
          pid: ev.host.pid,
          parent: ev.host.parent_process,
          user: ev.host.user,
          executable: ev.host.path,
          reason: 'image path is under a temp directory'
        }
      };
    }
  },
  {
    id: 'DEFENDER_DETECTION',
    title: 'Windows Defender reported a detection',
    score_key: 'defender_detection',
    kinds: ['host.defender'],
    applies(event) {
      return event.facts && (event.facts.defender_event_id === 1116 || event.facts.defender_event_id === 1117 || event.facts.threat);
    },
    test(ctx) {
      const cfg = ctx.ruleCfg;
      const ev = ctx.event;
      return {
        score: cfg.score,
        evidence: {
          threat: ev.facts.threat || null,
          severity: ev.facts.threat_severity || null,
          action: ev.facts.action || null,
          process: ev.host.process,
          path: ev.host.path,
          defender_event_id: ev.facts.defender_event_id || null
        }
      };
    }
  },
  {
    id: 'FILE_INTEGRITY_CHANGE',
    title: 'Monitored file changed',
    score_key: 'file_integrity_change',
    kinds: ['host.file'],
    applies(event) {
      return event.facts && (event.facts.change === 'modified' || event.facts.change === 'deleted' || event.facts.change === 'created');
    },
    test(ctx) {
      const cfg = ctx.ruleCfg;
      const ev = ctx.event;
      const change = ev.facts.change;
      return {
        score: change === 'deleted' ? cfg.score_deleted : cfg.score,
        evidence: {
          path: ev.host.path,
          change,
          previous_sha256: ev.facts.previous_sha256 || null,
          current_sha256: ev.facts.current_sha256 || null,
          size_bytes: ev.facts.size_bytes != null ? ev.facts.size_bytes : null
        }
      };
    }
  },
  {
    id: 'DB_BULK_READ',
    title: 'Bulk database read',
    score_key: 'db_bulk_read',
    kinds: ['db.audit'],
    applies(event) {
      return event.facts && Number.isFinite(event.facts.rows_read) && event.facts.rows_read >= 0 && event.outcome !== 'failure';
    },
    test(ctx) {
      const cfg = ctx.ruleCfg;
      const ev = ctx.event;
      if (ev.facts.rows_read < cfg.min_rows) return null;
      return {
        score: cfg.score,
        evidence: {
          rows_read: ev.facts.rows_read,
          min_rows: cfg.min_rows,
          statement_type: ev.facts.statement_type || null,
          table: ev.facts.table || null,
          principal: ev.source.principal,
          database: ev.facts.database || null
        }
      };
    }
  },
  {
    id: 'DB_AUTH_FAILURE',
    title: 'Database authentication failure',
    score_key: 'db_auth_failure',
    kinds: ['db.audit'],
    applies(event) {
      return event.outcome === 'auth_failure' || event.outcome === 'failure';
    },
    test(ctx) {
      const cfg = ctx.ruleCfg;
      const ev = ctx.event;
      return {
        score: cfg.score,
        evidence: {
          principal: ev.source.principal,
          database: ev.facts.database,
          source_ip: ev.source.ip,
          action: ev.facts.action || null,
          window_ms: ctx.windowMs
        }
      };
    }
  },
  {
    id: 'DB_NEW_IDENTITY',
    title: 'New database service identity or role',
    score_key: 'db_new_identity',
    kinds: ['db.audit'],
    applies(event) {
      const action = String((event.facts && event.facts.action) || '').toUpperCase();
      return (event.facts && event.facts.new_identity === true) || action === 'CREATE USER' || action === 'CREATE ROLE' || action === 'ALTER ROLE';
    },
    test(ctx) {
      const cfg = ctx.ruleCfg;
      const ev = ctx.event;
      return {
        score: cfg.score,
        evidence: {
          principal: ev.source.principal,
          target: ev.facts.target || null,
          action: ev.facts.action || null,
          database: ev.facts.database || null,
          new_identity: ev.facts.new_identity === true
        }
      };
    }
  },
  {
    id: 'DB_PRIVILEGE_CHANGE',
    title: 'Database privilege change',
    score_key: 'db_privilege_change',
    kinds: ['db.audit'],
    applies(event) {
      return event.facts && event.facts.privilege_change === true;
    },
    test(ctx) {
      const cfg = ctx.ruleCfg;
      const ev = ctx.event;
      return {
        score: cfg.score,
        evidence: {
          principal: ev.source.principal,
          target: ev.facts.target || null,
          privilege: ev.facts.privilege || null,
          statement: ev.facts.statement || null
        }
      };
    }
  },
  {
    id: 'HOST_AUTH_FAILURE_BURST',
    title: 'Repeated Windows logon failures',
    score_key: 'host_auth_failure_burst',
    kinds: ['host.session'],
    applies(event) {
      return event.outcome === 'auth_failure';
    },
    test(ctx) {
      const cfg = ctx.ruleCfg;
      if (ctx.samples.length < cfg.min_events) return null;
      return {
        score: cfg.score,
        evidence: {
          failures: ctx.samples.length,
          window_ms: ctx.windowMs,
          accounts: uniq(ctx.samples.map(s => s.principal)).slice(0, 10),
          source_addresses: uniq(ctx.samples.map(s => s.ip)).slice(0, 10)
        }
      };
    }
  }
];

const RECOMMENDED = {
  AUTH_FAIL_BURST: ['Confirm the principal and source address are expected', 'Check identity-provider logs for the same pattern', 'Rotate credentials only if compromise is confirmed'],
  RATE_LIMIT_BURST: ['Check gateway/WAF rate-limit policy', 'Confirm whether the client is a known integration'],
  DENIED_THEN_SUCCESS: ['Review the authorization decision for the successful request', 'Verify the principal was granted access legitimately'],
  SEQUENTIAL_ENUMERATION: ['Identify the client and confirm the enumeration was authorized', 'Review data classification of the enumerated records', 'Consider scoped rate limits at the gateway'],
  BULK_RESPONSE_VOLUME: ['Confirm the download was expected', 'Review egress volume for the same principal/source', 'Escalate if the data is regulated or customer-owned'],
  SENSITIVE_ROUTE_REPEAT: ['Confirm the client is a known integration', 'Review whether the endpoint needs tighter authorization'],
  PROTECTED_UNAUTHENTICATED: ['Treat as a potential access-control failure', 'Verify gateway auth is enforced for this route', 'Preserve logs and escalate to incident response'],
  NEW_LISTENER: ['Identify the process owning the port', 'Confirm the service was expected and is patched', 'Do not terminate the process until ownership is established'],
  PROCESS_FROM_TEMP: ['Identify the parent process and signer of the image', 'Collect the image hash for triage', 'Do not delete the binary before preserving evidence'],
  DEFENDER_DETECTION: ['Follow Defender remediation status', 'Isolate the host if the threat is active', 'Preserve Defender event details'],
  FILE_INTEGRITY_CHANGE: ['Diff the file against the last known-good copy', 'Confirm a legitimate deployment did not cause the change', 'Restore from a trusted source if unexplained'],
  DB_BULK_READ: ['Confirm the query was authorized', 'Review the principal and source host', 'Check egress of the returned data'],
  DB_AUTH_FAILURE: ['Confirm the principal and source host are expected', 'Check database and identity-provider logs', 'Verify no successful connection followed the failure'],
  DB_NEW_IDENTITY: ['Confirm the change ticket for the new identity', 'Review its grants for least privilege', 'Identify who will use it'],
  DB_PRIVILEGE_CHANGE: ['Confirm the change ticket', 'Review the grant for least privilege', 'Verify the actor identity'],
  HOST_AUTH_FAILURE_BURST: ['Confirm whether a password spray is in progress', 'Check account lockout policy', 'Review successful logons from the same source'],
  CORRELATED_ACTIVITY: ['Open an incident record with the component alert ids', 'Correlate with application and database audit logs', 'Escalate per severity']
};

function uniq(arr) {
  return Array.from(new Set(arr.filter(v => v !== null && v !== undefined)));
}

function longestConsecutiveRun(sortedNums) {
  if (sortedNums.length === 0) return 0;
  let best = 1;
  let run = 1;
  for (let i = 1; i < sortedNums.length; i++) {
    if (sortedNums[i] === sortedNums[i - 1] + 1) run += 1;
    else if (sortedNums[i] !== sortedNums[i - 1]) run = 1;
    if (run > best) best = run;
  }
  return best;
}

function numericPathId(p) {
  if (!p) return null;
  const segs = String(p).split('?')[0].split('/').filter(Boolean);
  if (segs.length === 0) return null;
  const last = segs[segs.length - 1];
  if (!/^\d{1,12}$/.test(last)) return null;
  return Number(last);
}

function globToRegExp(glob) {
  const escaped = String(glob).replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
  return new RegExp('^' + escaped + '$', 'i');
}

function matchAnyRoute(route, patterns) {
  if (!route || !patterns || patterns.length === 0) return false;
  for (const p of patterns) {
    if (globToRegExp(p).test(route)) return true;
  }
  return false;
}

function ipv4ToInt(ip) {
  const parts = String(ip).split('.');
  if (parts.length !== 4) return null;
  let out = 0;
  for (const p of parts) {
    const n = Number(p);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    out = (out * 256) + n;
  }
  return out >>> 0;
}

function ipMatches(ip, pattern) {
  if (!ip || !pattern) return false;
  const cidr = String(pattern).split('/');
  if (cidr.length === 2) {
    const base = ipv4ToInt(cidr[0]);
    const target = ipv4ToInt(ip);
    const bits = Number(cidr[1]);
    if (base == null || target == null || !Number.isInteger(bits) || bits < 0 || bits > 32) return false;
    if (bits === 0) return true;
    const mask = bits === 32 ? 0xffffffff : (0xffffffff << (32 - bits)) >>> 0;
    return (base & mask) === (target & mask);
  }
  return globToRegExp(pattern).test(ip);
}

function entityKey(event) {
  if (event.source.principal) return 'principal:' + event.source.principal;
  if (event.source.ip) return 'ip:' + event.source.ip;
  if (event.host && event.host.pid) return 'pid:' + event.host.pid;
  if (event.host && event.host.path) return 'path:' + event.host.path;
  return 'adapter:' + event.adapter;
}

function severityForScore(score, thresholds, critical) {
  if (critical) return 'critical';
  if (score >= thresholds.critical) return 'critical';
  if (score >= thresholds.high) return 'high';
  if (score >= thresholds.medium) return 'medium';
  return 'low';
}

const SEVERITY_RANK = { low: 1, medium: 2, high: 3, critical: 4 };

class DetectionEngine {
  constructor(config, deps) {
    deps = deps || {};
    this.config = config;
    this.baseline = deps.baseline;
    this.now = deps.now || (() => Date.now());
    this.rules = this.buildRules(config);
    this.state = new Map();
    this.dedupe = new Map();
    this.correlation = new Map();
    this.counters = { evaluated: 0, detections: 0, alerts: 0, suppressed: 0, correlated: 0, baseline_suppressed: 0 };
    this.lastPruneMs = 0;
  }

  buildRules(config) {
    const det = config.detection;
    const sensitive = det.sensitive_routes || [];
    const protectedRoutes = det.protected_routes || [];
    const out = [];
    for (const def of RULE_DEFS) {
      const ruleCfg = Object.assign({}, det.rules[def.score_key] || {});
      if (ruleCfg.enabled === false) continue;
      if (def.applyTo) {
        // reserved for future per-rule scoping
      }
      const bound = {
        id: def.id,
        title: def.title,
        def,
        ruleCfg,
        _routes: def.id === 'SENSITIVE_ROUTE_REPEAT' ? sensitive : (def.id === 'PROTECTED_UNAUTHENTICATED' ? protectedRoutes : [])
      };
      out.push(bound);
    }
    return out;
  }

  stateFor(ruleId, key) {
    const k = ruleId + '|' + key;
    let st = this.state.get(k);
    if (!st) {
      st = {
        key,
        samples: [],
        denied: new Map(),
        pages: new Map(),
        ids: [],
        last_at: null
      };
      this.state.set(k, st);
    }
    return st;
  }

  prune(nowMs) {
    const windowMs = this.config.detection.window_ms;
    for (const st of this.state.values()) {
      if (st.samples.length && nowMs - new Date(st.samples[st.samples.length - 1].at).getTime() <= windowMs) {
        // Newest sample is still inside the window; nothing has expired yet.
      } else {
        st.samples = st.samples.filter(s => nowMs - new Date(s.at).getTime() <= windowMs);
      }
      for (const [route, rec] of st.denied.entries()) {
        if (nowMs - new Date(rec.at).getTime() > windowMs) st.denied.delete(route);
      }
      for (const [page, at] of st.pages.entries()) {
        if (nowMs - new Date(at).getTime() > windowMs) st.pages.delete(page);
      }
    }
    for (const [k, rec] of this.correlation.entries()) {
      rec.alerts = rec.alerts.filter(a => nowMs - new Date(a.at).getTime() <= windowMs);
      if (rec.alerts.length === 0) this.correlation.delete(k);
    }
  }

  // Main entry point. Returns alerts (already deduplicated and correlated).
  observe(event) {
    // Correlation, dedupe and alert timestamps follow event time, not processing
    // time, so a backlog of replayed log lines keeps its real ordering instead of
    // collapsing into one window.
    const wallNow = this.now();
    const evMs = new Date(event.ts).getTime();
    const nowMs = Number.isFinite(evMs) ? evMs : wallNow;
    this.counters.evaluated += 1;
    // Expiry is checked at most once per second of event time; doing it per
    // event turns high-volume collection into an O(entities x samples) scan.
    if (nowMs - this.lastPruneMs >= 1000 || nowMs < this.lastPruneMs) {
      this.prune(nowMs);
      this.lastPruneMs = nowMs;
    }

    if (this.baseline && event.kind === 'http.request') {
      this.baseline.observe(event.request.route, event.ts);
    }

    const key = entityKey(event);
    const produced = [];

    for (const rule of this.rules) {
      const def = rule.def;
      if (!def.kinds.includes(event.kind)) continue;
      const applies = typeof def.applies === 'function'
        ? def.applies.call(rule, event)
        : false;
      if (!applies) continue;

      const st = this.stateFor(def.id, key);
      // Record the observation *before* testing so the current event counts.
      st.samples.push({
        at: event.ts,
        route: event.request.route,
        status: event.response.status,
        bytes: event.response.bytes_out || 0,
        principal: event.source.principal,
        ip: event.source.ip
      });
      if (st.samples.length > 5000) st.samples.shift();
      if (event.response.status === 401 || event.response.status === 403) {
        st.denied.set(event.request.route, { at: event.ts, status: event.response.status });
      }

      const ctx = {
        event,
        state: st,
        samples: st.samples.slice(),
        ruleCfg: rule.ruleCfg,
        baselineCfg: this.config.baseline,
        windowMs: this.config.detection.window_ms,
        baseline: this.baseline || { summary: () => ({ established: false, ratio: null }), isWithinBaseline: () => false, alertRatio: 3 }
      };

      let result;
      try {
        result = def.test(ctx);
      } catch (e) {
        result = null;
      }
      if (ctx.suppressedByBaseline) this.counters.baseline_suppressed += 1;
      if (!result) continue;
      if (result.score < this.config.detection.min_alert_score) continue;

      this.counters.detections += 1;
      const alert = this.buildAlert(rule, result, event, key, ctx, nowMs);
      const deduped = this.applyDedupe(alert, nowMs);
      if (deduped) produced.push(deduped);
    }

    const correlated = this.applyCorrelation(key, event, produced, nowMs);
    if (correlated) produced.push(correlated);

    this.counters.alerts += produced.length;
    return produced;
  }

  buildAlert(rule, result, event, key, ctx, nowMs) {
    const thresholds = this.config.detection.severity_thresholds;
    const severity = severityForScore(result.score, thresholds, result.critical);
    const recommended = RECOMMENDED[rule.id] || ['Review the evidence and confirm whether the activity was expected'];
    const alert = {
      schema: ALERT_SCHEMA,
      alert_id: null,
      created_at: new Date(nowMs != null ? nowMs : this.now()).toISOString(),
      rule_id: rule.id,
      rule_version: VERSION,
      title: rule.title,
      mode: this.config.detection.mode,
      severity,
      score: result.score,
      critical: Boolean(result.critical),
      entity: {
        key,
        principal: event.source.principal,
        ip: event.source.ip,
        route: event.request.route || event.host.path || null,
        process: event.host.process || null,
        host: event.host.hostname || null
      },
      source_adapter: event.adapter,
      event_kind: event.kind,
      event_ids: [event.event_id],
      first_seen: ctx.samples.length ? ctx.samples[0].at : event.ts,
      last_seen: event.ts,
      occurrences: 1,
      suppressed_since_previous: 0,
      evidence: result.evidence,
      facts: Object.assign({
        observed: true,
        classification: 'heuristic',
        note: 'Score is a tuning value, not a calibrated probability.'
      }, result.facts || {}),
      recommended_response: recommended,
      baseline: this.baseline ? this.baseline.summary(event.request.route, event.ts) : null
    };
    alert.alert_id = crypto.createHash('sha256').update(canonicalJSON({
      rule: rule.id,
      key,
      created_at: alert.created_at,
      event_id: event.event_id,
      score: alert.score
    })).digest('hex').slice(0, 32);
    return alert;
  }

  applyDedupe(alert, nowMs) {
    const cooldown = this.config.detection.dedupe_cooldown_ms;
    const key = alert.rule_id + '|' + alert.entity.key + '|' + (alert.entity.route || '-');
    const rec = this.dedupe.get(key);
    if (rec && nowMs - rec.last_at < cooldown) {
      rec.suppressed += 1;
      rec.occurrences += 1;
      rec.last_at = nowMs;
      this.counters.suppressed += 1;
      return null;
    }
    const occurrences = rec ? rec.occurrences + 1 : 1;
    const suppressed = rec ? rec.suppressed : 0;
    this.dedupe.set(key, { last_at: nowMs, suppressed: 0, occurrences, first_at: rec ? rec.first_at : nowMs });
    alert.occurrences = occurrences;
    alert.suppressed_since_previous = suppressed;
    alert.dedupe_window_ms = cooldown;
    return alert;
  }

  applyCorrelation(key, event, freshAlerts, nowMs) {
    if (freshAlerts.length === 0) return null;
    const windowMs = this.config.detection.window_ms;
    let rec = this.correlation.get(key);
    if (!rec) {
      rec = { alerts: [] };
      this.correlation.set(key, rec);
    }
    for (const a of freshAlerts) rec.alerts.push({ rule_id: a.rule_id, score: a.score, at: a.created_at, alert_id: a.alert_id });
    rec.alerts = rec.alerts.filter(a => nowMs - new Date(a.at).getTime() <= windowMs);

    const distinctRules = new Set(rec.alerts.map(a => a.rule_id));
    if (distinctRules.size < 2) return null;

    const totalScore = Math.min(100, rec.alerts.reduce((sum, a) => sum + a.score, 0));
    const thresholds = this.config.detection.severity_thresholds;
    if (totalScore < thresholds.high) return null;

    const dedupeKey = 'CORRELATED|' + key;
    const cooldown = this.config.detection.dedupe_cooldown_ms;
    const d = this.dedupe.get(dedupeKey);
    if (d && nowMs - d.last_at < cooldown) {
      d.suppressed += 1;
      this.counters.suppressed += 1;
      return null;
    }
    this.dedupe.set(dedupeKey, { last_at: nowMs, suppressed: 0, occurrences: d ? d.occurrences + 1 : 1, first_at: d ? d.first_at : nowMs });

    const alert = {
      schema: ALERT_SCHEMA,
      alert_id: crypto.createHash('sha256').update(canonicalJSON({
        rule: 'CORRELATED_ACTIVITY',
        key,
        at: new Date(nowMs).toISOString(),
        components: rec.alerts.map(a => a.alert_id)
      })).digest('hex').slice(0, 32),
      created_at: new Date(nowMs).toISOString(),
      rule_id: 'CORRELATED_ACTIVITY',
      rule_version: VERSION,
      title: 'Correlated suspicious activity',
      mode: this.config.detection.mode,
      severity: severityForScore(totalScore, thresholds, false),
      score: totalScore,
      critical: false,
      entity: {
        key,
        principal: event.source.principal,
        ip: event.source.ip,
        route: event.request.route || event.host.path || null,
        process: event.host.process || null,
        host: event.host.hostname || null
      },
      source_adapter: event.adapter,
      event_kind: 'correlation',
      event_ids: [event.event_id],
      first_seen: rec.alerts[0].at,
      last_seen: event.ts,
      occurrences: 1,
      suppressed_since_previous: 0,
      evidence: {
        window_ms: windowMs,
        distinct_rules: Array.from(distinctRules),
        components: rec.alerts.slice(-20),
        combined_score: totalScore
      },
      facts: { observed: true, classification: 'heuristic', note: 'Additive score across distinct rules in one window.' },
      recommended_response: RECOMMENDED.CORRELATED_ACTIVITY,
      baseline: null
    };
    this.counters.correlated += 1;
    return alert;
  }

  status() {
    return Object.assign({}, this.counters, {
      rules_enabled: this.rules.map(r => r.id),
      tracked_entities: this.state.size,
      dedupe_entries: this.dedupe.size,
      correlation_entities: this.correlation.size
    });
  }

  reset() {
    this.state.clear();
    this.dedupe.clear();
    this.correlation.clear();
  }
}

module.exports = {
  DetectionEngine,
  RULE_DEFS,
  RECOMMENDED,
  severityForScore,
  matchAnyRoute,
  ipMatches,
  entityKey,
  globToRegExp,
  longestConsecutiveRun,
  numericPathId,
  SEVERITY_RANK
};
