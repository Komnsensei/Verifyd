'use strict';

// Per-route request baseline.
//
// Purpose: give the rule engine an observed reference so that "normal browsing"
// does not trip volume rules, and so alerts can state a deviation ratio instead
// of a bare count. This is a deterministic minute-bucket mean, not a model, and
// it is only consulted after min_buckets of observation.
class Baseline {
  constructor(opts) {
    opts = opts || {};
    this.enabled = opts.enabled !== false;
    this.bucketMs = opts.bucketMs || 60000;
    this.bucketCount = opts.buckets || 30;
    this.minBuckets = opts.minBuckets || 5;
    this.alertRatio = opts.alertRatio || 3;
    // route -> { buckets: {bucketIndex: count}, seen }
    this.routes = new Map();
  }

  bucketIndex(at) {
    return Math.floor(new Date(at).getTime() / this.bucketMs);
  }

  entry(route) {
    let e = this.routes.get(route);
    if (!e) {
      e = { buckets: new Map(), seen: 0 };
      this.routes.set(route, e);
    }
    return e;
  }

  observe(route, at) {
    if (!this.enabled || !route) return;
    const e = this.entry(route);
    const idx = this.bucketIndex(at);
    e.buckets.set(idx, (e.buckets.get(idx) || 0) + 1);
    e.seen += 1;
    this.gc(route, idx);
  }

  gc(route, currentIdx) {
    const e = this.routes.get(route);
    if (!e) return;
    const oldest = currentIdx - this.bucketCount;
    for (const k of e.buckets.keys()) {
      if (k <= oldest) e.buckets.delete(k);
    }
  }

  // Mean and p95 of completed buckets, excluding the bucket we are currently in
  // so that the current burst does not dilute its own signal.
  summary(route, at) {
    const e = this.routes.get(route);
    if (!e) return { established: false, buckets: 0, mean: 0, p95: 0, current: 0, ratio: null };
    const idx = this.bucketIndex(at);
    const values = [];
    let current = 0;
    for (const [k, v] of e.buckets.entries()) {
      if (k === idx) current = v;
      else if (k < idx) values.push(v);
    }
    values.sort((a, b) => a - b);
    const n = values.length;
    const established = n >= this.minBuckets;
    const mean = n ? values.reduce((a, b) => a + b, 0) / n : 0;
    const p95 = n ? values[Math.min(n - 1, Math.floor(n * 0.95))] : 0;
    const reference = Math.max(mean, p95, 1);
    return {
      established,
      buckets: n,
      mean: Number(mean.toFixed(3)),
      p95,
      current,
      ratio: Number((current / reference).toFixed(3))
    };
  }

  // True when volume is within the learned band. Unknown routes never suppress.
  isWithinBaseline(route, at) {
    if (!this.enabled) return false;
    const s = this.summary(route, at);
    if (!s.established) return false;
    return s.current <= Math.max(1, s.mean * this.alertRatio);
  }

  toJSON() {
    const routes = {};
    const entries = Array.from(this.routes.entries())
      .map(([route, e]) => {
        const buckets = Array.from(e.buckets.entries());
        const newest = buckets.reduce((max, b) => Math.max(max, b[0]), 0);
        return { route, e, buckets, newest };
      })
      .filter(x => x.buckets.length > 0)
      .sort((a, b) => b.newest - a.newest)
      .slice(0, 200);
    for (const x of entries) {
      routes[x.route] = { seen: x.e.seen, buckets: x.buckets };
    }
    return { version: 1, bucket_ms: this.bucketMs, routes };
  }

  static fromJSON(obj, opts) {
    const b = new Baseline(opts);
    if (!obj || !obj.routes) return b;
    for (const route of Object.keys(obj.routes)) {
      const src = obj.routes[route] || {};
      b.routes.set(route, {
        seen: src.seen || 0,
        buckets: new Map((src.buckets || []).filter(x => Array.isArray(x) && x.length === 2))
      });
    }
    return b;
  }
}

module.exports = { Baseline };
