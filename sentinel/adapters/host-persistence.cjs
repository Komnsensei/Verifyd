'use strict';

const { BaseAdapter } = require('./base.cjs');

const WMI_LOG = 'Microsoft-Windows-WMI-Activity/Operational';
const SECURITY_IDS = [4657, 4698, 4699, 4700, 4702];

const PROBE = `
$out = [ordered]@{
  security = $null
  security_error = $null
  wmi = $null
  wmi_error = $null
  audit = $null
}
try {
  $log = Get-WinEvent -ListLog 'Security' -ErrorAction Stop
  $out.security = @{ enabled = $log.IsEnabled; records = $log.RecordCount }
} catch { $out.security_error = $_.Exception.Message }
try {
  $log = Get-WinEvent -ListLog '${WMI_LOG}' -ErrorAction Stop
  $out.wmi = @{ enabled = $log.IsEnabled; records = $log.RecordCount }
} catch { $out.wmi_error = $_.Exception.Message }
try {
  $out.audit = (auditpol /get /subcategory:"Registry" 2>$null | Out-String) + (auditpol /get /subcategory:"Other Object Access Events" 2>$null | Out-String)
} catch { }
$out | ConvertTo-Json -Compress -Depth 4
`;

function buildScript(startIso) {
  const safe = String(startIso).replace(/'/g, "''");
  return `
$start = [datetime]::Parse('${safe}').ToUniversalTime()
$out = @()
try {
  $events = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=@(${SECURITY_IDS.join(',')}); StartTime=$start } -MaxEvents 200 -ErrorAction Stop
  foreach ($e in $events) {
    $x = [xml]$e.ToXml()
    $d = @{}
    foreach ($n in $x.Event.EventData.Data) { $d[[string]$n.Name] = [string]$n.'#text' }
    $out += [pscustomobject]@{
      channel = 'Security'
      id = $e.Id
      ts = $e.TimeCreated.ToUniversalTime().ToString('o')
      record_id = $e.RecordId
      user = $d['SubjectUserName']
      process = $d['ProcessName']
      object_name = $d['ObjectName']
      operation = $d['OperationType']
      task_name = $d['TaskName']
      task_content = $d['TaskContent']
      error = $null
    }
  }
} catch {
  $out += [pscustomobject]@{ channel = 'Security'; error = $_.Exception.Message }
}
try {
  $events = Get-WinEvent -FilterHashtable @{ LogName='${WMI_LOG}'; Id=5861; StartTime=$start } -MaxEvents 100 -ErrorAction Stop
  foreach ($e in $events) {
    $msg = [string]$e.Message
    if ($msg.Length -gt 800) { $msg = $msg.Substring(0, 800) }
    $out += [pscustomobject]@{
      channel = 'WMI-Activity'
      id = $e.Id
      ts = $e.TimeCreated.ToUniversalTime().ToString('o')
      record_id = $e.RecordId
      user = $null
      process = $null
      object_name = $null
      operation = 'permanent_subscription'
      task_name = $null
      task_content = $msg
      error = $null
    }
  }
} catch {
  $out += [pscustomobject]@{ channel = 'WMI-Activity'; error = $_.Exception.Message }
}
$out | ConvertTo-Json -Compress -Depth 5
`;
}

function auditEnabled(text, name) {
  if (!text) return false;
  const s = String(text);
  const marker = s.indexOf(name);
  if (marker < 0) return false;
  const tail = s.slice(marker, marker + 160);
  return /Success|Failure/i.test(tail) && !/No Auditing/i.test(tail);
}

class HostPersistenceAdapter extends BaseAdapter {
  constructor(opts) {
    super(Object.assign({
      id: 'host.persistence',
      name: 'Windows persistence (registry, scheduled tasks, WMI)',
      category: 'B: Windows host',
      capabilities: [
        'registry value changes (4657) for audited persistence keys',
        'scheduled task creation, deletion, disable and update (4698/4699/4700/4702)',
        'WMI permanent event subscriptions (WMI-Activity 5861)'
      ],
      limitations: [
        '4657 requires Audit Registry and a SACL on the monitored key',
        '4698/4702 require Audit Other Object Access Events',
        'WMI-Activity operational log must be enabled and readable',
        'Sysmon registry events are covered separately by host.sysmon'
      ],
      source: { type: 'powershell', logs: 'Security 4657/4698/4699/4700/4702, WMI-Activity 5861' }
    }, opts));
  }

  get platform() {
    return this.deps.platform || process.platform;
  }

  async init() {
    if (this.config.enabled === false) return this.markNotConfigured('disabled in config');
    if (this.platform !== 'win32') {
      return this.markUnavailable('requires Windows Security and WMI-Activity logs; host is ' + this.platform);
    }
    try {
      const probe = await this.deps.powershell(PROBE, { timeoutMs: 10000 });
      const securityOk = probe && probe.security && probe.security.enabled !== false && !probe.security_error;
      const wmiOk = probe && probe.wmi && probe.wmi.enabled !== false && !probe.wmi_error;
      if (!securityOk && !wmiOk) {
        return this.markUnavailable('neither Security nor WMI-Activity is readable: ' + ((probe && (probe.security_error || probe.wmi_error)) || 'probe failed'));
      }
      this.detail = {
        security: securityOk,
        wmi: wmiOk,
        registry_audit: auditEnabled(probe.audit, 'Registry'),
        object_access_audit: auditEnabled(probe.audit, 'Other Object Access Events')
      };
      if (!securityOk) this.detail.security_error = probe.security_error;
      if (!wmiOk) this.detail.wmi_error = probe.wmi_error;
      return this.markActive('reading persistence events from ' + [securityOk ? 'Security' : null, wmiOk ? 'WMI-Activity' : null].filter(Boolean).join(' + '), this.detail);
    } catch (e) {
      return this.markUnavailable('persistence probe failed: ' + (e.code || e.message));
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
    let errors = 0;
    for (const item of list) {
      if (!item) continue;
      if (item.error) { errors += 1; continue; }
      if (!item.id) continue;
      const ts = item.ts || new Date().toISOString();
      if (!maxTs || new Date(ts) > new Date(maxTs)) maxTs = ts;
      const id = Number(item.id);
      const common = {
        adapter: this.id,
        ts,
        hint: 'persistence:' + id + ':' + (item.record_id || ts) + ':' + (item.object_name || item.task_name || ''),
        source: { principal: item.user || null, principal_type: 'windows-account' },
        host: { hostname: this.deps.hostname || null, process: item.process ? baseName(item.process) : null, path: item.object_name || item.task_name || null }
      };
      if (id === 4657) {
        events.push(Object.assign(common, {
          kind: 'host.registry',
          outcome: 'changed',
          facts: {
            windows_event_id: id,
            operation: item.operation || null,
            object_name: item.object_name || null,
            process_path: item.process || null,
            log: 'Security'
          }
        }));
      } else if (id === 4698 || id === 4699 || id === 4700 || id === 4702) {
        const action = id === 4698 ? 'created' : id === 4699 ? 'deleted' : id === 4700 ? 'disabled' : 'updated';
        events.push(Object.assign(common, {
          kind: 'host.scheduled_task',
          outcome: action === 'deleted' ? 'removed' : 'changed',
          facts: {
            windows_event_id: id,
            action,
            task_name: item.task_name || null,
            task_content_excerpt: item.task_content ? String(item.task_content).slice(0, 800) : null,
            log: 'Security'
          }
        }));
      } else if (id === 5861) {
        events.push(Object.assign(common, {
          kind: 'host.wmi_subscription',
          outcome: 'observed',
          facts: {
            windows_event_id: id,
            operation: 'permanent_subscription',
            message_excerpt: item.task_content || null,
            log: 'WMI-Activity'
          }
        }));
      }
    }
    if (errors > 0 && events.length === 0 && errors === list.length) {
      throw new Error('all persistence event queries failed');
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

module.exports = { HostPersistenceAdapter, buildScript, PROBE, SECURITY_IDS, WMI_LOG, auditEnabled };
