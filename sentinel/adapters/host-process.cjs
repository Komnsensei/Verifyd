'use strict';

const { BaseAdapter } = require('./base.cjs');

const AUDIT_SCRIPT = `
auditpol /get /subcategory:"Process Creation" 2>$null | Out-String
`;

function buildSecurityScript(startIso) {
  const safe = String(startIso).replace(/'/g, "''");
  return `
$start = [datetime]::Parse('${safe}').ToUniversalTime()
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=$start} -MaxEvents 200 -ErrorAction Stop
$out = @()
foreach ($e in $events) {
  $x = [xml]$e.ToXml()
  $d = @{}
  foreach ($n in $x.Event.EventData.Data) { $d[[string]$n.Name] = [string]$n.'#text' }
  $pidValue = $null
  if ($d['NewProcessId']) {
    try { $pidValue = [Convert]::ToInt32($d['NewProcessId'], 16) } catch { $pidValue = $null }
  }
  $out += [pscustomobject]@{
    ts = $e.TimeCreated.ToUniversalTime().ToString('o')
    pid = $pidValue
    image = $d['NewProcessName']
    parent = $d['ParentProcessName']
    user = $d['SubjectUserName']
    command_line = $d['CommandLine']
  }
}
$out | ConvertTo-Json -Compress -Depth 4
`;
}

const CIM_SCRIPT = `
$out = @()
Get-CimInstance Win32_Process -ErrorAction Stop | ForEach-Object {
  $out += [pscustomobject]@{
    ts = (Get-Date).ToUniversalTime().ToString('o')
    pid = [int]$_.ProcessId
    parent_pid = [int]$_.ParentProcessId
    image = $_.Name
    path = $_.ExecutablePath
    user = $null
    command_line = $_.CommandLine
    created = if ($_.CreationDate) { $_.CreationDate.ToUniversalTime().ToString('o') } else { $null }
  }
}
$out | ConvertTo-Json -Compress -Depth 4
`;

const TEMP_RE = /(\\|\/)(temp|tmp)(\\|\/)/i;

function looksTemporary(p) {
  if (!p) return false;
  return TEMP_RE.test(p) || /\\appdata\\local\\temp\\/i.test(p);
}

class HostProcessAdapter extends BaseAdapter {
  constructor(opts) {
    super(Object.assign({
      id: 'host.process',
      name: 'Windows process creation',
      category: 'B: Windows host',
      capabilities: [
        'process creation with image, parent, user and PID',
        'command line when the 4688 policy includes it',
        'flags images launched from temporary directories'
      ],
      limitations: [
        '4688 requires "Audit Process Creation" success auditing and a Security log read permission',
        'CIM fallback is a snapshot diff and misses processes that start and exit between polls',
        'command lines are truncated and credential-shaped text is redacted before storage'
      ],
      source: { type: 'powershell', cmdlet: 'Get-WinEvent Security 4688 / Get-CimInstance Win32_Process' }
    }, opts));
    this.mode = this.config.mode || 'auto';
    this.resolvedMode = null;
    this.knownPids = new Map();
  }

  get platform() {
    return this.deps.platform || process.platform;
  }

  async init() {
    if (this.config.enabled === false) return this.markNotConfigured('disabled in config');
    if (this.platform !== 'win32') {
      return this.markUnavailable('requires Windows process telemetry; host is ' + this.platform);
    }
    if (this.mode === 'cim') {
      this.resolvedMode = 'cim-snapshot';
      return this.markActive('snapshot diffing via Win32_Process (4688 disabled by config)', { mode: this.resolvedMode });
    }
    let auditEnabled = false;
    try {
      const out = await this.deps.powershell(AUDIT_SCRIPT, { timeoutMs: 10000 });
      const text = typeof out === 'string' ? out : JSON.stringify(out || '');
      auditEnabled = /Process Creation/i.test(text) && /Success/i.test(text) && !/No Auditing/i.test(text);
    } catch (e) {
      auditEnabled = false;
    }
    if (this.mode === 'security' && !auditEnabled) {
      this.resolvedMode = null;
      return this.markUnavailable('audit policy does not record process creation; enable "Audit Process Creation" (Success) or set adapters.host_process.mode="cim"');
    }
    this.resolvedMode = auditEnabled ? 'security-4688' : 'cim-snapshot';
    if (auditEnabled) {
      return this.markActive('reading Security event 4688', { mode: this.resolvedMode });
    }
    return this.markActive('4688 auditing not enabled; using CIM snapshot diff', {
      mode: this.resolvedMode,
      degraded: true,
      note: 'short-lived processes will be missed until 4688 success auditing is enabled'
    });
  }

  async poll() {
    if (this.platform !== 'win32') return { events: [] };
    if (!this.resolvedMode) await this.init();
    if (this.resolvedMode === 'security-4688') return this.pollSecurity();
    return this.pollCim();
  }

  async pollSecurity() {
    const since = (this.cursor && this.cursor.last_ts)
      ? new Date(new Date(this.cursor.last_ts).getTime() - 1000).toISOString()
      : new Date(Date.now() - this.intervalMs * 2).toISOString();
    const raw = await this.deps.powershell(buildSecurityScript(since), { timeoutMs: 20000 });
    const list = raw == null ? [] : (Array.isArray(raw) ? raw : [raw]);
    const events = [];
    let maxTs = this.cursor && this.cursor.last_ts ? this.cursor.last_ts : null;
    for (const item of list) {
      if (!item || !item.image) continue;
      const ts = item.ts || new Date().toISOString();
      if (!maxTs || new Date(ts) > new Date(maxTs)) maxTs = ts;
      events.push({
        adapter: this.id,
        kind: 'host.process',
        ts,
        hint: '4688:' + (item.pid || '?') + ':' + ts + ':' + item.image,
        outcome: 'observed',
        host: {
          pid: item.pid,
          process: baseName(item.image),
          path: item.image,
          parent_process: baseName(item.parent),
          user: item.user,
          hostname: this.deps.hostname || null
        },
        facts: {
          source: 'security-4688',
          parent_image: item.parent || null,
          command_line: item.command_line ? String(item.command_line).slice(0, 512) : null,
          command_line_available: Boolean(item.command_line),
          from_temp_dir: looksTemporary(item.image)
        }
      });
    }
    this.cursor = { last_ts: maxTs, mode: this.resolvedMode };
    this.succeeded(events.length);
    return { events };
  }

  async pollCim() {
    const raw = await this.deps.powershell(CIM_SCRIPT, { timeoutMs: 20000 });
    const list = raw == null ? [] : (Array.isArray(raw) ? raw : [raw]);
    const byPid = new Map();
    for (const item of list) {
      if (!item || item.pid == null) continue;
      byPid.set(Number(item.pid), item);
    }
    const nowIso = new Date().toISOString();
    const events = [];
    if (this.knownPids.size === 0 && !this.cursor) {
      for (const pid of byPid.keys()) this.knownPids.set(pid, nowIso);
      this.cursor = { mode: this.resolvedMode, baseline_at: nowIso };
      this.succeeded(0);
      return { events: [] };
    }
    for (const [pid, item] of byPid.entries()) {
      if (this.knownPids.has(pid)) continue;
      this.knownPids.set(pid, nowIso);
      const parent = item.parent_pid != null ? byPid.get(Number(item.parent_pid)) : null;
      const image = item.path || item.image;
      events.push({
        adapter: this.id,
        kind: 'host.process',
        ts: nowIso,
        hint: 'cim:' + pid + ':' + (item.created || '') + ':' + (image || item.image),
        outcome: 'observed',
        host: {
          pid,
          process: item.image || baseName(image),
          path: image || null,
          parent_process: parent ? parent.image : null,
          user: item.user || null,
          hostname: this.deps.hostname || null
        },
        facts: {
          source: 'cim-snapshot',
          command_line: item.command_line ? String(item.command_line).slice(0, 512) : null,
          command_line_available: Boolean(item.command_line),
          from_temp_dir: looksTemporary(image)
        }
      });
    }
    // Retain only PIDs still present, bounded.
    const live = new Set(byPid.keys());
    for (const pid of Array.from(this.knownPids.keys())) {
      if (!live.has(pid)) this.knownPids.delete(pid);
    }
    this.cursor = { mode: this.resolvedMode, last_poll_at: nowIso, tracked: this.knownPids.size };
    this.succeeded(events.length);
    return { events };
  }

  restoreCursor(cursor) {
    super.restoreCursor(cursor);
    if (cursor && cursor.mode) this.resolvedMode = cursor.mode;
  }
}

function baseName(p) {
  if (!p) return null;
  const parts = String(p).split(/[\\/]/);
  return parts[parts.length - 1] || null;
}

module.exports = { HostProcessAdapter, looksTemporary, buildSecurityScript, CIM_SCRIPT, AUDIT_SCRIPT };
