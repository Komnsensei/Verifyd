'use strict';

const { BaseAdapter } = require('./base.cjs');

const SYSMON_LOG = 'Microsoft-Windows-Sysmon/Operational';
const SYSMON_IDS = [1, 3, 7, 8, 10, 11, 12, 13, 14, 17, 18, 19, 20, 21, 22, 25];

const PROBE = `
try {
  $log = Get-WinEvent -ListLog '${SYSMON_LOG}' -ErrorAction Stop
  [pscustomobject]@{ exists = $true; enabled = $log.IsEnabled; records = $log.RecordCount; error = $null } | ConvertTo-Json -Compress
} catch {
  [pscustomobject]@{ exists = $false; enabled = $false; records = 0; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`;

function buildScript(startIso) {
  const safe = String(startIso).replace(/'/g, "''");
  return `
$start = [datetime]::Parse('${safe}').ToUniversalTime()
$events = Get-WinEvent -FilterHashtable @{ LogName='${SYSMON_LOG}'; Id=@(${SYSMON_IDS.join(',')}); StartTime=$start } -MaxEvents 300 -ErrorAction Stop
$out = @()
foreach ($e in $events) {
  $x = [xml]$e.ToXml()
  $d = @{}
  foreach ($n in $x.Event.EventData.Data) { $d[[string]$n.Name] = [string]$n.'#text' }
  $msg = [string]$e.Message
  if ($msg.Length -gt 600) { $msg = $msg.Substring(0, 600) }
  $out += [pscustomobject]@{
    id = $e.Id
    ts = $e.TimeCreated.ToUniversalTime().ToString('o')
    record_id = $e.RecordId
    data = $d
    message = $msg
  }
}
$out | ConvertTo-Json -Compress -Depth 6
`;
}

function baseName(p) {
  if (!p) return null;
  const parts = String(p).split(/[\\/]/);
  return parts[parts.length - 1] || null;
}

function isTemp(p) {
  if (!p) return false;
  return /(\\|\/)(temp|tmp)(\\|\/)/i.test(String(p)) || /\\appdata\\local\\temp\\/i.test(String(p));
}

function common(adapter, item, data) {
  return {
    adapter: adapter.id,
    ts: item.ts || new Date().toISOString(),
    hint: 'sysmon:' + item.id + ':' + (item.record_id || item.ts || '') + ':' + (data.Image || data.ImageLoaded || data.TargetFilename || data.TargetObject || ''),
    source: { principal: data.User || null, principal_type: 'windows-account' },
    host: { hostname: adapter.deps.hostname || null }
  };
}

function mapSysmonItem(adapter, item) {
  const data = item.data || {};
  const id = Number(item.id);
  const base = common(adapter, item, data);
  base.facts = { sysmon_event_id: id, rule_name: data.RuleName || null };

  if (id === 1) {
    return Object.assign(base, {
      kind: 'host.process',
      outcome: 'observed',
      host: Object.assign(base.host, {
        pid: data.ProcessId ? Number(data.ProcessId) : null,
        process: baseName(data.Image),
        path: data.Image || null,
        parent_process: baseName(data.ParentImage),
        user: data.User || null
      }),
      facts: Object.assign(base.facts, {
        source: 'sysmon-event-1',
        parent_image: data.ParentImage || null,
        command_line: data.CommandLine ? String(data.CommandLine).slice(0, 512) : null,
        command_line_available: Boolean(data.CommandLine),
        hashes: data.Hashes || null,
        from_temp_dir: isTemp(data.Image)
      })
    });
  }

  if (id === 3) {
    return Object.assign(base, {
      kind: 'host.network',
      outcome: 'observed',
      source: Object.assign(base.source, {
        ip: data.SourceIp || null,
        port: data.SourcePort ? Number(data.SourcePort) : null
      }),
      host: Object.assign(base.host, {
        port: data.DestinationPort ? Number(data.DestinationPort) : null,
        process: baseName(data.Image),
        path: data.Image || null
      }),
      facts: Object.assign(base.facts, {
        source: 'sysmon-event-3',
        destination_ip: data.DestinationIp || null,
        destination_port: data.DestinationPort ? Number(data.DestinationPort) : null,
        protocol: data.Protocol || null,
        initiated: data.Initiated != null ? String(data.Initiated) === 'true' : null,
        source_host: data.SourceHostname || null,
        destination_host: data.DestinationHostname || null
      })
    });
  }

  if (id === 22) {
    return Object.assign(base, {
      kind: 'host.dns',
      outcome: 'observed',
      host: Object.assign(base.host, {
        process: baseName(data.Image),
        path: data.Image || null
      }),
      facts: Object.assign(base.facts, {
        source: 'sysmon-event-22',
        query_name: data.QueryName || null,
        query_type: data.QueryType || null,
        query_status: data.QueryStatus || null,
        query_results: data.QueryResults || null,
        process_guid: data.ProcessGuid || null
      })
    });
  }

  if (id === 11) {
    return Object.assign(base, {
      kind: 'host.file',
      outcome: 'changed',
      host: Object.assign(base.host, {
        path: data.TargetFilename || null,
        process: baseName(data.Image)
      }),
      facts: Object.assign(base.facts, {
        source: 'sysmon-event-11',
        change: 'created',
        process_path: data.Image || null
      })
    });
  }

  if (id === 12 || id === 13 || id === 14) {
    return Object.assign(base, {
      kind: 'host.registry',
      outcome: 'changed',
      host: Object.assign(base.host, {
        path: data.TargetObject || null,
        process: baseName(data.Image)
      }),
      facts: Object.assign(base.facts, {
        source: 'sysmon-event-' + id,
        event_type: data.EventType || null,
        details: data.Details ? String(data.Details).slice(0, 512) : null,
        process_path: data.Image || null
      })
    });
  }

  if (id === 19 || id === 20 || id === 21) {
    return Object.assign(base, {
      kind: 'host.wmi_subscription',
      outcome: 'observed',
      host: Object.assign(base.host, {
        process: baseName(data.Image),
        path: data.Query || data.Consumer || null
      }),
      facts: Object.assign(base.facts, {
        source: 'sysmon-event-' + id,
        operation: id === 19 ? 'wmi_filter_added' : id === 20 ? 'wmi_consumer_added' : 'wmi_binding_added',
        event_type: data.EventType || null,
        query: data.Query || null,
        consumer: data.Consumer || null,
        namespace: data.Operation || null,
        process_path: data.Image || null
      })
    });
  }

  if (id === 25) {
    return Object.assign(base, {
      kind: 'host.tamper',
      outcome: 'observed',
      host: Object.assign(base.host, {
        process: baseName(data.Image),
        path: data.Image || null
      }),
      facts: Object.assign(base.facts, {
        source: 'sysmon-event-25',
        tamper_type: data.Type || null
      })
    });
  }

  if (id === 7) {
    return Object.assign(base, {
      kind: 'host.image',
      outcome: 'observed',
      host: Object.assign(base.host, {
        path: data.ImageLoaded || null,
        process: baseName(data.Image)
      }),
      facts: Object.assign(base.facts, {
        source: 'sysmon-event-7',
        signed: data.Signed || null,
        signature: data.Signature || null,
        signature_status: data.SignatureStatus || null,
        process_path: data.Image || null
      })
    });
  }

  if (id === 8 || id === 10) {
    return Object.assign(base, {
      kind: id === 8 ? 'host.injection' : 'host.process_access',
      outcome: 'observed',
      host: Object.assign(base.host, {
        process: baseName(data.SourceImage || data.Image),
        path: data.SourceImage || data.Image || null
      }),
      facts: Object.assign(base.facts, {
        source: 'sysmon-event-' + id,
        target_image: data.TargetImage || null,
        granted_access: data.GrantedAccess || null,
        call_trace: data.CallTrace ? String(data.CallTrace).slice(0, 512) : null
      })
    });
  }

  if (id === 17 || id === 18) {
    return Object.assign(base, {
      kind: 'host.pipe',
      outcome: 'observed',
      host: Object.assign(base.host, {
        path: data.PipeName || null,
        process: baseName(data.Image)
      }),
      facts: Object.assign(base.facts, {
        source: 'sysmon-event-' + id,
        event_type: data.EventType || null,
        process_path: data.Image || null
      })
    });
  }

  return Object.assign(base, {
    kind: 'host.sysmon',
    outcome: 'observed',
    facts: Object.assign(base.facts, { source: 'sysmon-event-' + id, message_excerpt: item.message || null })
  });
}

class HostSysmonAdapter extends BaseAdapter {
  constructor(opts) {
    super(Object.assign({
      id: 'host.sysmon',
      name: 'Sysmon endpoint telemetry',
      category: 'B: Windows host',
      capabilities: [
        'process creation including short-lived processes (event 1)',
        'network connection metadata (event 3)',
        'DNS queries (event 22)',
        'file creation (event 11), registry changes (12/13/14)',
        'WMI filter/consumer/binding persistence (19/20/21)',
        'image loads, process access, injection and process tampering (7/8/10/25)'
      ],
      limitations: [
        'requires Sysmon installed and its operational log readable',
        'event 3 is connection metadata, not packet contents',
        'event 22 is DNS client telemetry, not a network sensor',
        'Sysmon configuration controls which events exist at all'
      ],
      source: { type: 'powershell', log: SYSMON_LOG }
    }, opts));
  }

  get platform() {
    return this.deps.platform || process.platform;
  }

  async init() {
    if (this.config.enabled === false) return this.markNotConfigured('disabled in config');
    if (this.platform !== 'win32') {
      return this.markUnavailable('requires Windows Sysmon; host is ' + this.platform);
    }
    try {
      const probe = await this.deps.powershell(PROBE, { timeoutMs: 10000 });
      if (!probe || probe.exists !== true) {
        return this.markUnavailable('Sysmon operational log is not installed: ' + ((probe && probe.error) || 'not found'));
      }
      if (probe.enabled === false) return this.markUnavailable('Sysmon operational log is disabled');
      this.detail = { log: SYSMON_LOG, records: probe.records };
      return this.markActive('reading Sysmon events ' + SYSMON_IDS.join(','), this.detail);
    } catch (e) {
      return this.markUnavailable('Sysmon probe failed: ' + (e.code || e.message));
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
      if (!item || !item.id) continue;
      const ts = item.ts || new Date().toISOString();
      if (!maxTs || new Date(ts) > new Date(maxTs)) maxTs = ts;
      events.push(mapSysmonItem(this, item));
    }
    this.cursor = { last_ts: maxTs };
    this.succeeded(events.length);
    return { events };
  }
}

module.exports = { HostSysmonAdapter, mapSysmonItem, buildScript, PROBE, SYSMON_LOG, SYSMON_IDS, isTemp };
