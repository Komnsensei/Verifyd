'use strict';

const { BaseAdapter } = require('./base.cjs');

const PROBE = `
$out = [ordered]@{ security = $null; audit = $null; error = $null }
try {
  $log = Get-WinEvent -ListLog 'Security' -ErrorAction Stop
  $out.security = @{ enabled = $log.IsEnabled; records = $log.RecordCount }
} catch { $out.error = $_.Exception.Message }
try { $out.audit = (auditpol /get /subcategory:"File System" 2>$null | Out-String) } catch { }
$out | ConvertTo-Json -Compress -Depth 4
`;

function buildScript(startIso) {
  const safe = String(startIso).replace(/'/g, "''");
  return `
$start = [datetime]::Parse('${safe}').ToUniversalTime()
$events = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4663; StartTime=$start } -MaxEvents 300 -ErrorAction Stop
$out = @()
foreach ($e in $events) {
  $x = [xml]$e.ToXml()
  $d = @{}
  foreach ($n in $x.Event.EventData.Data) { $d[[string]$n.Name] = [string]$n.'#text' }
  $out += [pscustomobject]@{
    ts = $e.TimeCreated.ToUniversalTime().ToString('o')
    record_id = $e.RecordId
    user = $d['SubjectUserName']
    process = $d['ProcessName']
    object_name = $d['ObjectName']
    object_type = $d['ObjectType']
    access_mask = $d['AccessMask']
    access_list = $d['AccessList']
    handle_id = $d['HandleId']
  }
}
$out | ConvertTo-Json -Compress -Depth 5
`;
}

function parseMask(value) {
  if (value == null || value === '') return null;
  const n = parseInt(String(value), /^0x/i.test(String(value)) ? 16 : 16);
  return Number.isFinite(n) ? n : null;
}

function accessFlags(item) {
  const mask = parseMask(item.access_mask);
  const list = String(item.access_list || '');
  const read = (mask != null && (mask & 0x1) !== 0) || /ReadData|ListDirectory|ReadAttributes|ReadExtendedAttributes/i.test(list);
  const write = (mask != null && (mask & (0x2 | 0x4 | 0x100)) !== 0) || /WriteData|AppendData|WriteAttributes|WriteExtendedAttributes|WriteDAC|WriteOwner/i.test(list);
  const del = (mask != null && (mask & 0x10000) !== 0) || /\\bDelete\\b/i.test(list) || (mask != null && (mask & 0x40) !== 0);
  return { mask, read, write, delete: del };
}

function isFileObject(item) {
  const type = String(item.object_type || '').toLowerCase();
  if (type && type !== 'file') return false;
  const name = String(item.object_name || '');
  return name.length > 0 && (/^[a-zA-Z]:\\/.test(name) || /^\\Device\\/.test(name) || name.indexOf('\\') >= 0);
}

class HostFileAuditAdapter extends BaseAdapter {
  constructor(opts) {
    super(Object.assign({
      id: 'host.fileaudit',
      name: 'Windows file access audit (4663)',
      category: 'B: Windows host',
      capabilities: [
        'file read/write/delete access with process and account',
        'object path and access mask from the Security log',
        'complements hash-based host.files polling with access events'
      ],
      limitations: [
        'requires Audit File System policy and a SACL on each monitored path',
        '4663 is generated only when the object SACL matches the access',
        'security log volume can be high on busy file servers',
        'does not capture file contents'
      ],
      source: { type: 'powershell', log: 'Security 4663' }
    }, opts));
  }

  get platform() {
    return this.deps.platform || process.platform;
  }

  async init() {
    if (this.config.enabled === false) return this.markNotConfigured('disabled in config');
    if (this.platform !== 'win32') {
      return this.markUnavailable('requires Windows Security file auditing; host is ' + this.platform);
    }
    try {
      const probe = await this.deps.powershell(PROBE, { timeoutMs: 10000 });
      if (!probe || probe.error || !probe.security || probe.security.enabled === false) {
        return this.markUnavailable('Security log not readable: ' + ((probe && probe.error) || 'unknown error'));
      }
      const policy = String(probe.audit || '');
      const auditOn = /Success|Failure/i.test(policy) && !/No Auditing/i.test(policy);
      this.detail = { file_system_audit: auditOn, sacl_required: true, security_records: probe.security.records };
      if (!auditOn) return this.markUnavailable('Audit File System is not enabled; run enable-audit.ps1', this.detail);
      return this.markActive('reading file access events; per-path SACLs are required', this.detail);
    } catch (e) {
      return this.markUnavailable('file audit probe failed: ' + (e.code || e.message));
    }
  }

  async poll() {
    if (this.platform !== 'win32' || !this.config.enabled) return { events: [] };
    if (this.status !== 'ACTIVE') return { events: [] };
    const since = (this.cursor && this.cursor.last_ts)
      ? new Date(new Date(this.cursor.last_ts).getTime() - 1000).toISOString()
      : new Date(Date.now() - this.intervalMs * 2).toISOString();
    const raw = await this.deps.powershell(buildScript(since), { timeoutMs: 20000 });
    const list = raw == null ? [] : (Array.isArray(raw) ? raw : [raw]);
    const events = [];
    let maxTs = this.cursor && this.cursor.last_ts ? this.cursor.last_ts : null;
    for (const item of list) {
      if (!item || !item.object_name || !isFileObject(item)) continue;
      const ts = item.ts || new Date().toISOString();
      if (!maxTs || new Date(ts) > new Date(maxTs)) maxTs = ts;
      const flags = accessFlags(item);
      events.push({
        adapter: this.id,
        kind: 'host.file_access',
        ts,
        hint: '4663:' + (item.record_id || ts) + ':' + item.object_name,
        outcome: flags.delete ? 'removed' : (flags.write ? 'changed' : (flags.read ? 'read' : 'observed')),
        source: { principal: item.user || null, principal_type: 'windows-account' },
        host: {
          hostname: this.deps.hostname || null,
          process: baseName(item.process),
          path: item.object_name
        },
        facts: {
          windows_event_id: 4663,
          object_type: item.object_type || null,
          process_path: item.process || null,
          access_mask: flags.mask,
          access_list: item.access_list || null,
          read: flags.read,
          write: flags.write,
          delete: flags.delete,
          handle_id: item.handle_id || null,
          log: 'Security'
        }
      });
    }
    this.cursor = { last_ts: maxTs };
    this.succeeded(events.length);
    return { events };
  }
}

function baseName(p) {
  if (!p) return null;
  const parts = String(p).split(/[\\/]/);
  return parts[parts.length - 1] || null;
}

module.exports = { HostFileAuditAdapter, buildScript, PROBE, parseMask, accessFlags, isFileObject };
