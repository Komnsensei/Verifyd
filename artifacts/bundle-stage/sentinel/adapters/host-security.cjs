'use strict';

const { BaseAdapter } = require('./base.cjs');

const ADMIN_PROBE = `
$p = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
[pscustomobject]@{ admin = $isAdmin; user = [string][Security.Principal.WindowsIdentity]::GetCurrent().Name } | ConvertTo-Json -Compress
`;

function buildScript(eventIds, startIso) {
  const ids = eventIds.join(',');
  const safe = String(startIso).replace(/'/g, "''");
  return `
$start = [datetime]::Parse('${safe}').ToUniversalTime()
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=@(${ids}); StartTime=$start} -MaxEvents 200 -ErrorAction Stop
$out = @()
foreach ($e in $events) {
  $x = [xml]$e.ToXml()
  $d = @{}
  foreach ($n in $x.Event.EventData.Data) { $d[[string]$n.Name] = [string]$n.'#text' }
  $out += [pscustomobject]@{
    id = $e.Id
    ts = $e.TimeCreated.ToUniversalTime().ToString('o')
    user = $d['TargetUserName']
    subject = $d['SubjectUserName']
    ip = $d['IpAddress']
    logon_type = $d['LogonType']
    status = $d['Status']
    substatus = $d['SubStatus']
    privileges = $d['PrivilegeList']
  }
}
$out | ConvertTo-Json -Compress -Depth 4
`;
}

class HostSecurityAdapter extends BaseAdapter {
  constructor(opts) {
    super(Object.assign({
      id: 'host.security',
      name: 'Windows Security log (logon events)',
      category: 'B: Windows host',
      capabilities: [
        'failed logons (4625) with source address, account and logon type',
        'successful logons (4624)',
        'special privileges assigned (4672)'
      ],
      limitations: [
        'requires an elevated account with Security log read access',
        'requires the matching audit policy subcategories to be enabled',
        'cannot see domain-controller-side events unless this host is the DC'
      ],
      source: { type: 'powershell', cmdlet: 'Get-WinEvent Security 4624/4625/4672' }
    }, opts));
    this.eventIds = this.config.events && this.config.events.length ? this.config.events : [4625, 4672];
  }

  get platform() {
    return this.deps.platform || process.platform;
  }

  async init() {
    if (this.config.enabled === false) return this.markNotConfigured('disabled in config; enable only where Security log access is authorized');
    if (this.platform !== 'win32') {
      return this.markUnavailable('requires Windows Security event log; host is ' + this.platform);
    }
    try {
      const probe = await this.deps.powershell(ADMIN_PROBE, { timeoutMs: 10000 });
      const isAdmin = probe && probe.admin === true;
      if (!isAdmin) {
        return this.markUnavailable('process is not elevated; Security log read requires an authorized admin account');
      }
      this.detail.account = probe.user || null;
      return this.markActive('reading Security log for events ' + this.eventIds.join(','), { events: this.eventIds, account: probe.user });
    } catch (e) {
      return this.markUnavailable('Security log probe failed: ' + (e.code || e.message));
    }
  }

  async poll() {
    if (this.platform !== 'win32' || !this.config.enabled) return { events: [] };
    const since = (this.cursor && this.cursor.last_ts)
      ? new Date(new Date(this.cursor.last_ts).getTime() - 1000).toISOString()
      : new Date(Date.now() - this.intervalMs * 2).toISOString();
    const raw = await this.deps.powershell(buildScript(this.eventIds, since), { timeoutMs: 20000 });
    const list = raw == null ? [] : (Array.isArray(raw) ? raw : [raw]);
    const events = [];
    let maxTs = this.cursor && this.cursor.last_ts ? this.cursor.last_ts : null;
    for (const item of list) {
      if (!item || !item.id) continue;
      const ts = item.ts || new Date().toISOString();
      if (!maxTs || new Date(ts) > new Date(maxTs)) maxTs = ts;
      const id = Number(item.id);
      let outcome = 'observed';
      if (id === 4625) outcome = 'auth_failure';
      else if (id === 4624) outcome = 'success';
      else if (id === 4672) outcome = 'privileged_logon';
      events.push({
        adapter: this.id,
        kind: 'host.session',
        ts,
        hint: 'security:' + id + ':' + ts + ':' + (item.user || item.subject || ''),
        outcome,
        source: {
          ip: normalizeIp(item.ip),
          principal: item.user || item.subject || null,
          principal_type: 'windows-account'
        },
        host: { hostname: this.deps.hostname || null, user: item.subject || null },
        facts: {
          windows_event_id: id,
          logon_type: item.logon_type ? Number(item.logon_type) : null,
          status: item.status || null,
          substatus: item.substatus || null,
          privileges: item.privileges ? String(item.privileges).slice(0, 512) : null
        }
      });
    }
    this.cursor = { last_ts: maxTs, events: this.eventIds };
    this.succeeded(events.length);
    return { events };
  }
}

function normalizeIp(ip) {
  if (!ip) return null;
  const s = String(ip).trim();
  if (s === '-' || s === '::1' || s === '127.0.0.1') return s === '-' ? null : s;
  return s;
}

module.exports = { HostSecurityAdapter, buildScript, ADMIN_PROBE };
