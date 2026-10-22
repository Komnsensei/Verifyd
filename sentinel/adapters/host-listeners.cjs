'use strict';

const { BaseAdapter } = require('./base.cjs');

const LISTENER_SCRIPT = `
$conns = Get-NetTCPConnection -State Listen -ErrorAction Stop | Select-Object LocalAddress, LocalPort, OwningProcess
$procNames = @{}
Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procNames[[int]$_.Id] = $_.ProcessName }
$out = @()
foreach ($c in $conns) {
  $pidValue = [int]$c.OwningProcess
  $pname = $null
  if ($procNames.ContainsKey($pidValue)) { $pname = $procNames[$pidValue] }
  $out += [pscustomobject]@{
    address = [string]$c.LocalAddress
    port = [int]$c.LocalPort
    pid = $pidValue
    process = $pname
  }
}
$out | ConvertTo-Json -Compress -Depth 4
`;

const MAX_TRACKED = 4000;

class HostListenersAdapter extends BaseAdapter {
  constructor(opts) {
    super(Object.assign({
      id: 'host.listeners',
      name: 'Windows listening ports',
      category: 'B: Windows host',
      capabilities: [
        'enumerates TCP listeners with owning PID and process name',
        'diffs against a persisted baseline to surface new listeners',
        'records both newly added and removed listeners as evidence'
      ],
      limitations: [
        'baseline is established on first successful poll; pre-existing listeners are not retroactively reported',
        'UDP listeners are not covered',
        'short-lived listeners between polls can be missed',
        'process name can be null for protected processes without elevation'
      ],
      source: { type: 'powershell', cmdlet: 'Get-NetTCPConnection' }
    }, opts));
    this.baseline = null;
    this.ignorePorts = new Set((this.config.ignore_ports || []).map(Number));
    this.allowProcesses = new Set((this.config.allow_processes || []).map(s => String(s).toLowerCase()));
  }

  key(entry) {
    return entry.address + ':' + entry.port;
  }

  get platform() {
    return this.deps.platform || process.platform;
  }

  async init() {
    if (this.config.enabled === false) return this.markNotConfigured('disabled in config');
    if (this.platform !== 'win32') {
      return this.markUnavailable('requires Windows (Get-NetTCPConnection); host is ' + this.platform);
    }
    try {
      const sample = await this.deps.powershell(LISTENER_SCRIPT, { timeoutMs: 15000 });
      this.detail.observed_listeners = Array.isArray(sample) ? sample.length : (sample ? 1 : 0);
      return this.markActive('polling TCP listener table', { interval_ms: this.intervalMs });
    } catch (e) {
      return this.markUnavailable('cannot read TCP listener table: ' + (e.code || e.message));
    }
  }

  async poll() {
    if (this.platform !== 'win32') return { events: [] };
    const raw = await this.deps.powershell(LISTENER_SCRIPT, { timeoutMs: 15000 });
    const list = raw == null ? [] : (Array.isArray(raw) ? raw : [raw]);
    const current = new Map();
    for (const item of list) {
      if (!item || item.port == null) continue;
      const entry = {
        address: String(item.address || ''),
        port: Number(item.port),
        pid: item.pid == null ? null : Number(item.pid),
        process: item.process ? String(item.process) : null
      };
      if (this.ignorePorts.has(entry.port)) continue;
      if (entry.port <= 0 || entry.port > 65535) continue;
      current.set(this.key(entry), entry);
    }

    const nowIso = new Date().toISOString();
    if (this.baseline == null) {
      this.baseline = {};
      for (const [k, entry] of current.entries()) {
        this.baseline[k] = { first_seen: nowIso, pid: entry.pid, process: entry.process, port: entry.port, address: entry.address };
      }
      this.cursor = { baseline: this.baseline, baseline_at: nowIso };
      this.succeeded(0);
      return { events: [] };
    }

    const events = [];
    const baseline = this.baseline;
    for (const [k, entry] of current.entries()) {
      if (baseline[k]) continue;
      baseline[k] = { first_seen: nowIso, pid: entry.pid, process: entry.process, port: entry.port, address: entry.address };
      const allowlisted = entry.process && this.allowProcesses.has(entry.process.toLowerCase());
      events.push({
        adapter: this.id,
        kind: 'host.listener',
        ts: nowIso,
        hint: 'listener:add:' + k,
        outcome: 'observed',
        host: {
          address: entry.address,
          port: entry.port,
          pid: entry.pid,
          process: entry.process,
          hostname: this.deps.hostname || null
        },
        facts: {
          change: 'added',
          is_new: true,
          baseline_ports: Object.keys(baseline).length,
          allowlisted_process: Boolean(allowlisted),
          first_seen: nowIso
        }
      });
    }

    const removed = [];
    for (const k of Object.keys(baseline)) {
      if (current.has(k)) continue;
      removed.push(k);
      delete baseline[k];
    }
    for (const k of removed.slice(0, 200)) {
      const sep = k.lastIndexOf(':');
      const address = sep >= 0 ? k.slice(0, sep) : k;
      const port = sep >= 0 ? Number(k.slice(sep + 1)) : null;
      events.push({
        adapter: this.id,
        kind: 'host.listener',
        ts: nowIso,
        hint: 'listener:remove:' + k + ':' + nowIso,
        outcome: 'observed',
        host: { address, port, hostname: this.deps.hostname || null },
        facts: { change: 'removed', is_new: false }
      });
    }

    // Bound persisted baseline growth on a long-running host.
    const keys = Object.keys(baseline);
    if (keys.length > MAX_TRACKED) {
      const trimmed = {};
      for (const k of keys.slice(-MAX_TRACKED)) trimmed[k] = baseline[k];
      this.baseline = trimmed;
    }
    this.cursor = { baseline: this.baseline, baseline_at: this.cursor ? this.cursor.baseline_at : nowIso, last_poll_at: nowIso };
    this.detail.tracked_listeners = Object.keys(this.baseline).length;
    this.succeeded(events.length);
    return { events };
  }

  restoreCursor(cursor) {
    super.restoreCursor(cursor);
    this.baseline = cursor && cursor.baseline ? cursor.baseline : null;
  }
}

module.exports = { HostListenersAdapter, LISTENER_SCRIPT };
