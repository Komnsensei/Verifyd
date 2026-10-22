'use strict';

const { BaseAdapter } = require('./base.cjs');

const DNS_LOG = 'Microsoft-Windows-DNS-Client/Operational';
const DNS_ID = 3008;

const PROBE = `
try {
  $log = Get-WinEvent -ListLog '${DNS_LOG}' -ErrorAction Stop
  [pscustomobject]@{ exists = $true; enabled = $log.IsEnabled; records = $log.RecordCount; error = $null } | ConvertTo-Json -Compress
} catch {
  [pscustomobject]@{ exists = $false; enabled = $false; records = 0; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`;

function buildScript(startIso) {
  const safe = String(startIso).replace(/'/g, "''");
  return `
$start = [datetime]::Parse('${safe}').ToUniversalTime()
$events = Get-WinEvent -FilterHashtable @{ LogName='${DNS_LOG}'; Id=${DNS_ID}; StartTime=$start } -MaxEvents 300 -ErrorAction Stop
$out = @()
foreach ($e in $events) {
  $x = [xml]$e.ToXml()
  $d = @{}
  foreach ($n in $x.Event.EventData.Data) { $d[[string]$n.Name] = [string]$n.'#text' }
  $out += [pscustomobject]@{
    ts = $e.TimeCreated.ToUniversalTime().ToString('o')
    record_id = $e.RecordId
    query_name = $d['QueryName']
    query_type = $d['QueryType']
    query_status = $d['QueryStatus']
    query_results = $d['QueryResults']
    interface_index = $d['InterfaceIndex']
  }
}
$out | ConvertTo-Json -Compress -Depth 5
`;
}

class HostDnsAdapter extends BaseAdapter {
  constructor(opts) {
    super(Object.assign({
      id: 'host.dns',
      name: 'Windows DNS Client queries',
      category: 'B: Windows host',
      capabilities: ['DNS query names, types, status and results from the DNS Client operational log'],
      limitations: [
        'the DNS Client log records client lookups, not all DNS traffic on the wire',
        'requires the Microsoft-Windows-DNS-Client/Operational log to be enabled and readable',
        'Sysmon event 22 is preferable when Sysmon is already deployed'
      ],
      source: { type: 'powershell', log: DNS_LOG }
    }, opts));
  }

  get platform() {
    return this.deps.platform || process.platform;
  }

  async init() {
    if (this.config.enabled === false) return this.markNotConfigured('disabled in config');
    if (this.platform !== 'win32') {
      return this.markUnavailable('requires Windows DNS Client log; host is ' + this.platform);
    }
    try {
      const probe = await this.deps.powershell(PROBE, { timeoutMs: 10000 });
      if (!probe || probe.exists !== true) return this.markUnavailable('DNS Client operational log is not present');
      if (probe.enabled === false) return this.markUnavailable('DNS Client operational log is disabled');
      return this.markActive('reading DNS Client queries', { log: DNS_LOG, records: probe.records });
    } catch (e) {
      return this.markUnavailable('DNS log probe failed: ' + (e.code || e.message));
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
      if (!item || !item.query_name) continue;
      const ts = item.ts || new Date().toISOString();
      if (!maxTs || new Date(ts) > new Date(maxTs)) maxTs = ts;
      events.push({
        adapter: this.id,
        kind: 'host.dns',
        ts,
        hint: 'dnsclient:' + (item.record_id || ts) + ':' + item.query_name,
        outcome: String(item.query_status || '').toLowerCase().indexOf('no error') >= 0 ? 'success' : 'observed',
        host: { hostname: this.deps.hostname || null },
        facts: {
          source: 'dns-client-3008',
          query_name: item.query_name,
          query_type: item.query_type || null,
          query_status: item.query_status || null,
          query_results: item.query_results || null,
          interface_index: item.interface_index != null ? Number(item.interface_index) : null
        }
      });
    }
    this.cursor = { last_ts: maxTs };
    this.succeeded(events.length);
    return { events };
  }
}

module.exports = { HostDnsAdapter, buildScript, PROBE, DNS_LOG, DNS_ID };
