'use strict';

const { BaseAdapter } = require('./base.cjs');

function quote(value) {
  return String(value == null ? '' : value).replace(/'/g, "''");
}

function connectionScript(server, database, envName) {
  const safeEnv = /^[A-Za-z_][A-Za-z0-9_]*$/.test(envName || '') ? envName : null;
  if (safeEnv) {
    return `
$cs = $env:${safeEnv}
if (-not $cs) { throw 'connection string environment variable ${safeEnv} is not set' }
$conn = New-Object System.Data.SqlClient.SqlConnection $cs
`;
  }
  return `
$b = New-Object System.Data.SqlClient.SqlConnectionStringBuilder
$b.DataSource = '${quote(server)}'
$b.InitialCatalog = '${quote(database)}'
$b.IntegratedSecurity = $true
$b.TrustServerCertificate = $true
$b.ConnectTimeout = 5
$conn = New-Object System.Data.SqlClient.SqlConnection $b.ConnectionString
`;
}

function buildProbe(server, database, envName) {
  return `
${connectionScript(server, database, envName)}
try {
  $conn.Open()
  $cmd = $conn.CreateCommand()
  $cmd.CommandText = 'SELECT DB_NAME() AS database_name, @@VERSION AS version'
  $r = $cmd.ExecuteReader()
  $out = $null
  if ($r.Read()) { $out = [pscustomobject]@{ ok = $true; database = [string]$r['database_name']; version = ([string]$r['version']).Split([char]10)[0] } }
  $r.Close()
  $conn.Close()
  if ($out) { $out | ConvertTo-Json -Compress } else { [pscustomobject]@{ ok = $false; error = 'no rows returned' } | ConvertTo-Json -Compress }
} catch {
  [pscustomobject]@{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`;
}

function buildQuery(server, database, envName, maxSessions) {
  const max = Math.max(1, Math.min(500, Number(maxSessions) || 50));
  return `
${connectionScript(server, database, envName)}
$out = @()
try {
  $conn.Open()
  $cmd = $conn.CreateCommand()
  $cmd.CommandText = @"
SELECT TOP (${max})
  s.session_id, s.login_name, s.host_name, s.program_name, s.status AS session_status,
  r.status AS request_status, r.command, r.cpu_time, r.reads, r.writes, r.logical_reads,
  r.total_elapsed_time, r.wait_type, r.blocking_session_id,
  DB_NAME(COALESCE(r.database_id, s.database_id)) AS database_name,
  CONVERT(nvarchar(1000), t.text) AS statement_text
FROM sys.dm_exec_sessions s
LEFT JOIN sys.dm_exec_requests r ON r.session_id = s.session_id
OUTER APPLY sys.dm_exec_sql_text(r.sql_handle) t
WHERE s.is_user_process = 1
ORDER BY s.session_id
"@
  $r = $cmd.ExecuteReader()
  while ($r.Read()) {
    $out += [pscustomobject]@{
      session_id = [int]$r['session_id']
      login_name = [string]$r['login_name']
      host_name = [string]$r['host_name']
      program_name = [string]$r['program_name']
      session_status = [string]$r['session_status']
      request_status = [string]$r['request_status']
      command = [string]$r['command']
      cpu_time = $(if ($r['cpu_time'] -is [DBNull]) { $null } else { [long]$r['cpu_time'] })
      reads = $(if ($r['reads'] -is [DBNull]) { $null } else { [long]$r['reads'] })
      writes = $(if ($r['writes'] -is [DBNull]) { $null } else { [long]$r['writes'] })
      logical_reads = $(if ($r['logical_reads'] -is [DBNull]) { $null } else { [long]$r['logical_reads'] })
      total_elapsed_time = $(if ($r['total_elapsed_time'] -is [DBNull]) { $null } else { [long]$r['total_elapsed_time'] })
      wait_type = [string]$r['wait_type']
      blocking_session_id = $(if ($r['blocking_session_id'] -is [DBNull]) { $null } else { [int]$r['blocking_session_id'] })
      database_name = [string]$r['database_name']
      statement_text = [string]$r['statement_text']
    }
  }
  $r.Close()
  $conn.Close()
} catch {
  $out = @([pscustomobject]@{ error = $_.Exception.Message })
}
$out | ConvertTo-Json -Compress -Depth 4
`;
}

class SqlServerAdapter extends BaseAdapter {
  constructor(opts) {
    super(Object.assign({
      id: 'sqlserver.live',
      name: 'SQL Server live sessions and requests',
      category: 'C: Data stores and external services',
      capabilities: [
        'live user sessions and active requests from sys.dm_exec_sessions/sys.dm_exec_requests',
        'statement text for active requests (truncated and redacted)',
        'read/write/logical-read counters and blocking sessions'
      ],
      limitations: [
        'requires Windows, a SQL Server client assembly and an account with VIEW SERVER STATE',
        'polling sees a request only while it is active; very short statements can be missed',
        'does not capture historical statements unless the statement is still active',
        'integrated security or a connection string in an environment variable; no password is stored in config'
      ],
      source: { type: 'powershell', technology: 'System.Data.SqlClient + DMVs' }
    }, opts));
    this.seen = new Map();
  }

  get platform() {
    return this.deps.platform || process.platform;
  }

  configured() {
    return Boolean(this.config.server || this.config.connection_string_env);
  }

  async init() {
    if (this.config.enabled === false) return this.markNotConfigured('disabled in config');
    if (this.platform !== 'win32') return this.markUnavailable('requires Windows SQL Server DMV access; host is ' + this.platform);
    if (!this.configured()) return this.markNotConfigured('adapters.sqlserver.server or connection_string_env is empty');
    try {
      const probe = await this.deps.powershell(buildProbe(this.config.server, this.config.database, this.config.connection_string_env), { timeoutMs: 15000 });
      if (!probe || probe.ok !== true) {
        return this.markUnavailable('SQL Server connection failed: ' + ((probe && probe.error) || 'unknown error'));
      }
      this.detail = { database: probe.database || this.config.database || null, version: probe.version || null };
      return this.markActive('polling SQL Server DMVs', this.detail);
    } catch (e) {
      return this.markUnavailable('SQL Server probe failed: ' + (e.code || e.message));
    }
  }

  async poll() {
    if (this.platform !== 'win32' || !this.config.enabled) return { events: [] };
    if (this.status !== 'ACTIVE') {
      await this.init();
      if (this.status !== 'ACTIVE') return { events: [] };
    }
    const raw = await this.deps.powershell(buildQuery(this.config.server, this.config.database, this.config.connection_string_env, this.config.max_sessions), { timeoutMs: 20000 });
    const list = raw == null ? [] : (Array.isArray(raw) ? raw : [raw]);
    if (list.length === 1 && list[0] && list[0].error) throw new Error('SQL query failed: ' + list[0].error);
    const events = [];
    const nowIso = new Date().toISOString();
    const current = new Set();
    for (const row of list) {
      if (!row || row.session_id == null) continue;
      const key = String(row.session_id) + '|' + (row.login_name || '') + '|' + (row.session_status || '') + '|' + (row.command || '') + '|' + (row.reads || 0) + '|' + (row.logical_reads || 0) + '|' + (row.blocking_session_id || 0);
      current.add(key);
      if (this.seen.has(key)) continue;
      this.seen.set(key, nowIso);
      events.push({
        adapter: this.id,
        kind: 'db.session',
        ts: nowIso,
        hint: 'sqlserver:' + row.session_id + ':' + (row.login_name || '') + ':' + (row.logical_reads || 0),
        outcome: row.request_status ? 'active' : (String(row.session_status || '').toLowerCase() === 'sleeping' ? 'idle' : 'observed'),
        source: { principal: row.login_name || null, principal_type: 'database' },
        host: { hostname: row.host_name || this.deps.hostname || null },
        facts: {
          source: 'sqlserver-dmv',
          live: true,
          session_id: Number(row.session_id),
          session_status: row.session_status || null,
          request_status: row.request_status || null,
          command: row.command || null,
          database: row.database_name || this.config.database || null,
          program: row.program_name || null,
          cpu_time: row.cpu_time != null ? Number(row.cpu_time) : null,
          reads: row.reads != null ? Number(row.reads) : null,
          writes: row.writes != null ? Number(row.writes) : null,
          logical_reads: row.logical_reads != null ? Number(row.logical_reads) : null,
          elapsed_ms: row.total_elapsed_time != null ? Number(row.total_elapsed_time) : null,
          wait_type: row.wait_type || null,
          blocking_session_id: row.blocking_session_id != null ? Number(row.blocking_session_id) : null,
          statement_excerpt: row.statement_text ? String(row.statement_text).slice(0, 1000) : null
        }
      });
    }
    for (const key of Array.from(this.seen.keys())) {
      if (!current.has(key)) this.seen.delete(key);
    }
    this.cursor = { last_poll_at: nowIso, sessions: current.size };
    this.succeeded(events.length);
    return { events };
  }
}

module.exports = { SqlServerAdapter, buildProbe, buildQuery, connectionScript };
