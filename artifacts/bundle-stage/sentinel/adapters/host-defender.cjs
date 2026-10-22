'use strict';

const { BaseAdapter } = require('./base.cjs');

const LOG = 'Microsoft-Windows-Windows Defender/Operational';
const DEFENDER_IDS = [1116, 1117, 5007];

const PROBE = `
$log = Get-WinEvent -ListLog '${LOG}' -ErrorAction Stop
[pscustomobject]@{ exists = $true; record_count = $log.RecordCount; enabled = $log.IsEnabled } | ConvertTo-Json -Compress
`;

function buildScript(startIso) {
  const safe = String(startIso).replace(/'/g, "''");
  return `
$start = [datetime]::Parse('${safe}').ToUniversalTime()
$events = Get-WinEvent -FilterHashtable @{LogName='${LOG}'; Id=@(1116,1117,5007); StartTime=$start} -MaxEvents 100 -ErrorAction Stop
$out = @()
foreach ($e in $events) {
  $msg = [string]$e.Message
  $threat = $null
  if ($msg -match 'Name:\\s*([^\\r\\n]+)') { $threat = $Matches[1].Trim() }
  $action = $null
  if ($msg -match 'Action:\\s*([^\\r\\n]+)') { $action = $Matches[1].Trim() }
  $out += [pscustomobject]@{
    id = $e.Id
    ts = $e.TimeCreated.ToUniversalTime().ToString('o')
    message = $msg.Substring(0, [Math]::Min(600, $msg.Length))
    threat = $threat
    action = $action
  }
}
$out | ConvertTo-Json -Compress -Depth 4
`;
}

class HostDefenderAdapter extends BaseAdapter {
  constructor(opts) {
    super(Object.assign({
      id: 'host.defender',
      name: 'Windows Defender detections',
      category: 'B: Windows host',
      capabilities: ['Defender detection events (1116/1117) and configuration changes (5007)'],
      limitations: [
        'only reports what the Defender operational log records',
        'message parsing is best-effort because the event schema is not stable across Defender versions',
        'does not replace EDR telemetry'
      ],
      source: { type: 'powershell', log: LOG }
    }, opts));
  }

  get platform() {
    return this.deps.platform || process.platform;
  }

  async init() {
    if (this.config.enabled === false) return this.markNotConfigured('disabled in config');
    if (this.platform !== 'win32') {
      return this.markUnavailable('requires Windows Defender event log; host is ' + this.platform);
    }
    try {
      const probe = await this.deps.powershell(PROBE, { timeoutMs: 10000 });
      if (!probe || probe.exists !== true) return this.markUnavailable('Defender operational log not present on this host');
      return this.markActive('reading Defender operational log', { log: LOG, record_count: probe.record_count });
    } catch (e) {
      return this.markUnavailable('Defender log probe failed: ' + (e.code || e.message));
    }
  }

  async poll() {
    if (this.platform !== 'win32' || !this.config.enabled) return { events: [] };
    const since = (this.cursor && this.cursor.last_ts)
      ? new Date(new Date(this.cursor.last_ts).getTime() - 1000).toISOString()
      : new Date(Date.now() - this.intervalMs * 2).toISOString();
    const raw = await this.deps.powershell(buildScript(since), { timeoutMs: 20000 });
    const list = raw == null ? [] : (Array.isArray(raw) ? raw : [raw]);
    const events = [];
    let maxTs = this.cursor && this.cursor.last_ts ? this.cursor.last_ts : null;
    for (const item of list) {
      if (!item || !item.id) continue;
      const ts = item.ts || new Date().toISOString();
      if (!maxTs || new Date(ts) > new Date(maxTs)) maxTs = ts;
      events.push({
        adapter: this.id,
        kind: 'host.defender',
        ts,
        hint: 'defender:' + item.id + ':' + ts + ':' + (item.threat || ''),
        outcome: 'observed',
        host: { hostname: this.deps.hostname || null },
        facts: {
          defender_event_id: Number(item.id),
          threat: item.threat || null,
          action: item.action || null,
          message_excerpt: item.message || null,
          log: LOG
        }
      });
    }
    this.cursor = { last_ts: maxTs };
    this.succeeded(events.length);
    return { events };
  }
}

module.exports = { HostDefenderAdapter, LOG, DEFENDER_IDS, buildScript };
