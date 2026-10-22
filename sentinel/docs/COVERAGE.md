# Monitoring coverage matrix

Generated from a live adapter probe, with the verification host's result kept
alongside the Windows expectation. A source is only `ACTIVE` when it was opened
or queried successfully during this run.

## Status semantics

| Status | Meaning | Consequence |
|---|---|---|
| `ACTIVE` | Source opened/queried successfully | events flow into detection |
| `UNAVAILABLE` | Configured or expected, but platform, permission or path denied it | retried every 5 minutes; listed as a blind spot |
| `NOT_CONFIGURED` | No path/URL/integration exists | not monitored; listed as a blind spot |

`node bin/sentinel.cjs coverage --config <file>` prints the current matrix.
No adapter is ever reported `ACTIVE` because it is "supposed" to work.

## Matrix

Verification host: Ubuntu 24.04.5 LTS, x86_64, Node 24.21.0, no PowerShell.
Raw JSON: [samples/coverage-linux.json](samples/coverage-linux.json).

| # | Adapter | Data source | What it proves | Status on this host | Expected on Windows | Blind spot when inactive |
|---|---|---|---|---|---|---|
| A | `http.access` | JSONL access log from instrumented app, Caddy or generic writer | route/method/principal/IP rates, 401/403/429, pagination, bytes out, body SHA-256 and JSON skeleton | `NOT_CONFIGURED` (path empty) | `ACTIVE` when `adapters.http_access.path` is readable | All application-layer access patterns are invisible |
| C | `proxy.access` | Cloudflare Logpush JSONL or generic proxy JSONL | edge request rate, status, WAF action/rule, source IP | `NOT_CONFIGURED` | `ACTIVE` when a provider log path is readable | WAF/CDN events and pre-origin traffic are invisible |
| B | `host.listeners` | `Get-NetTCPConnection -State Listen` | new/removed TCP listeners with owning PID/process | `UNAVAILABLE` (requires Windows) | `ACTIVE` with persisted baseline | A new backdoor listener would not be reported |
| B | `host.process` | Security 4688, or CIM `Win32_Process` snapshot diff | process image, parent, user, command line, temp-directory launch | `UNAVAILABLE` (requires Windows) | `ACTIVE` (4688 enabled by `enable-audit.ps1`; CIM is fallback) | Process execution is invisible; CIM misses short-lived processes |
| B | `host.security` | Security 4624/4625/4647/4672/4673 | Windows logon/logoff, failed logons, special privileges, sensitive privilege use | `NOT_CONFIGURED` (disabled in raw default) | `ACTIVE` when elevated and enabled by `setup-sentinel.ps1` + `enable-audit.ps1` | Host logon attacks and privileged operations are invisible |
| B | `host.defender` | `Microsoft-Windows-Windows Defender/Operational` | Defender detection and configuration changes | `UNAVAILABLE` (requires Windows) | `ACTIVE` when the channel exists and is readable | Defender findings do not reach Sentinel |
| B | `host.files` | SHA-256 baseline of configured paths | created/modified/deleted application or config files | `NOT_CONFIGURED` (no paths) | `ACTIVE` for existing paths | Tampering with monitored app files is invisible |
| B | `host.persistence` | Security 4657/4698/4699/4700/4702 + WMI-Activity 5861 | registry persistence value edits, scheduled-task changes, permanent WMI subscriptions | `NOT_CONFIGURED` (disabled in raw default) | `ACTIVE` when enabled by `setup-sentinel.ps1` + `enable-audit.ps1` | Registry, scheduled-task and WMI persistence are invisible |
| B | `host.fileaudit` | Security 4663 | file read/write/delete access with process, user and access mask | `NOT_CONFIGURED` (disabled in raw default) | `ACTIVE` when Audit File System and per-path SACLs are enabled by `enable-audit.ps1` | File reads between hash polls are invisible |
| B | `host.sysmon` | `Microsoft-Windows-Sysmon/Operational` (1/3/7/8/10/11/12-14/17-21/22/25) | short-lived processes, network connections, DNS queries, registry/file/WMI events, image loads, process access/injection/tamper | `NOT_CONFIGURED` (disabled in raw default) | `ACTIVE` when Sysmon is installed on the host | Kernel/ETW/Sysmon-level events are invisible |
| B | `host.dns` | `Microsoft-Windows-DNS-Client/Operational` (3008) | DNS client query names, types, status and results | `NOT_CONFIGURED` (disabled in raw default) | `ACTIVE` when the DNS-Client operational channel is enabled | Host DNS client lookups are invisible |
| C | `cloud.audit` | Exported AWS CloudTrail, Azure Activity or GCP Audit JSONL | control-plane actions, principal, source IP, IAM/policy privilege changes | `NOT_CONFIGURED` (no path) | `ACTIVE` when the export file exists | Cloud control-plane activity is invisible |
| C | `sqlserver.live` | `sys.dm_exec_sessions` / `sys.dm_exec_requests` / `sys.dm_exec_sql_text` | live SQL Server sessions, active statement text, reads/writes/logical reads, blocking | `NOT_CONFIGURED` (disabled in raw default) | `ACTIVE` when a server or connection string env var and `VIEW SERVER STATE` are present | Live SQL Server session activity is invisible |
| C | `saas.audit` | Authenticated HTTPS JSON pull (`token_env`) | third-party SaaS audit events with cursor-based `since` parameter | `NOT_CONFIGURED` (no URL/token) | `ACTIVE` when `url` and the token env var are set | Third-party SaaS audit trails are invisible |
| C | `db.audit` | Exported database audit JSONL | bulk reads (`rows_read`), GRANT/REVOKE, auth failures | `NOT_CONFIGURED` (no path) | `ACTIVE` when the export exists | Historical database audit logs are invisible |
| C | `network.sensor` | Zeek or Suricata EVE JSONL | per-flow byte counts, DNS queries, TLS SNI/version/cipher/certificate metadata, HTTP metadata, IDS alerts | `NOT_CONFIGURED` (no path) | `ACTIVE` when a sensor JSONL path is readable | Wire-level flows, TLS metadata and IDS alerts are invisible |
| C | `webflow.logs` | Operator-exported Webflow JSONL only | request-level access from an export | `NOT_CONFIGURED` | `NOT_CONFIGURED` unless a log export is supplied | No Webflow audit trail is monitored |
| - | `self.health` | in-process store/queue/memory/disk checks | service health, store utilization, queue depth | `ACTIVE` | `ACTIVE` | Self-monitoring only; pair with `store.anchor` for off-host tamper detection |

Summary from this run: **1 ACTIVE, 3 UNAVAILABLE, 14 NOT_CONFIGURED**.

## Coverage by requirement

### A. HTTP/API access

Covered when `http.access` or `proxy.access` is ACTIVE:

- request rate by normalized route, method, principal and source address;
- auth failures (401/407), authorization failures (403), rate limiting (429);
- pagination/offset parameters, sequential record ids, repeated sensitive routes;
- response byte counts and single/window bulk thresholds;
- request and response body SHA-256 hashes plus JSON key/type/length skeletons
  via `createAccessLogger` (`bodyMode: "shape"`, default) without storing raw
  body values;
- upstream WAF/CDN blocks and edge metadata via `proxy.access` (Cloudflare
  Logpush or generic JSONL);
- protected-route access without a principal or with `authorized: false`.

Remaining boundary:

- an uninstrumented API that neither uses `createAccessLogger` nor writes an
  access/proxy/sensor log has no telemetry to collect.

### B. Windows host

Covered when the corresponding adapters and `sentinel/windows/enable-audit.ps1`
are active (run automatically by `setup-sentinel.ps1`):

- listening-port changes against a persisted baseline (`host.listeners`);
- process creation with parent/user/image and full 4688 command line
  (`host.process`), plus short-lived process creation via Sysmon event 1
  (`host.sysmon`);
- failed/successful logons (4624/4625), logoffs (4647), special privileges
  (4672) and sensitive privilege use (4673) (`host.security`);
- registry persistence (4657), scheduled-task creation/deletion/disable/update
  (4698/4699/4700/4702) and WMI permanent event subscriptions (5861)
  (`host.persistence`);
- file read, write and delete audit events (4663) on SACL-configured paths
  (`host.fileaudit`) alongside SHA-256 baseline diffs (`host.files`);
- Sysmon endpoint telemetry (`host.sysmon`: events 1, 3, 7, 8, 10, 11, 12-14,
  17-21, 22, 25) and Windows DNS Client queries (`host.dns`: event 3008);
- Defender detection and configuration events (`host.defender`);
- audit policy and SACL enablement via `sentinel/windows/enable-audit.ps1`;
- service health, missed polls, store write failures and queue depth.

### C. Data stores, cloud, SaaS and network sensors

Covered when the corresponding adapters are configured:

- live SQL Server sessions, active statement text, read/write/logical-read
  counters and blocking sessions via `sqlserver.live` (`DB_LIVE_BULK_READ`);
- exported database audit logs via `db.audit` (`DB_BULK_READ`,
  `DB_AUTH_FAILURE`, `DB_NEW_IDENTITY`, `DB_PRIVILEGE_CHANGE`);
- AWS CloudTrail, Azure Activity and GCP Audit Log JSONL exports via
  `cloud.audit` (`CLOUD_PRIVILEGE_CHANGE`);
- third-party SaaS audit APIs over authenticated HTTPS via `saas.audit` (token
  supplied in `SENTINEL_SAAS_TOKEN` or configured `token_env`);
- Zeek and Suricata EVE network sensor logs via `network.sensor` (flow byte
  counts, DNS, TLS SNI/cipher/cert metadata, HTTP metadata and IDS alerts via
  `NETWORK_BULK_TRANSFER` and `NETWORK_IDS_ALERT`).

## Global boundaries and off-host tamper resistance

- **Off-host chain-head anchoring (`store.anchor`)**: configure
  `store.anchor.path` (such as a remote UNC share) and/or `store.anchor.url`
  (HMAC-signed with `SENTINEL_ANCHOR_SECRET`). Every cycle and `sentinel verify`
  compares the local chain head and sequence against the anchor and raises
  `ANCHOR_MISMATCH` (`ROLLBACK`, `HEAD_MISMATCH`, `FOREIGN_HOST`) if a local
  administrator truncates or rewrites the store.
- **Thresholds vs. guarantees**: detection rules are deterministic thresholds
  plus a per-route baseline; activity that stays below every threshold and
  within baseline does not trigger an alert.
- **Timestamps**: each event records both the producer's `ts` and Sentinel's
  `observed_at`.
- **TLS payloads**: `network.sensor` records TLS handshake metadata and flow
  byte volume; TLS plaintext is never decrypted.

## Verification commands

```
node bin/sentinel.cjs coverage --config <config>          # human table + blind spots
node bin/sentinel.cjs coverage --config <config> --json   # machine-readable
curl -H "Authorization: Bearer $SENTINEL_DIAG_TOKEN" http://127.0.0.1:8790/coverage
```

## Windows prerequisite checklist

| Adapter | Prerequisite |
|---|---|
| `host.listeners` | Windows; no elevation required for the TCP table |
| `host.process` | 4688: `Audit Process Creation` = Success + command-line registry value (`enable-audit.ps1`). CIM: no special right |
| `host.security` | Elevated or Event Log Readers; logon/logoff/privilege audit subcategories enabled (`enable-audit.ps1`) |
| `host.persistence` | `Audit Registry` + key SACLs, `Audit Other Object Access Events`, and `WMI-Activity/Operational` enabled (`enable-audit.ps1`) |
| `host.fileaudit` | `Audit File System` + read/write/delete SACL on monitored paths (`enable-audit.ps1 -FilePaths ...`) |
| `host.sysmon` | Sysmon installed and `Microsoft-Windows-Sysmon/Operational` readable |
| `host.dns` | `Microsoft-Windows-DNS-Client/Operational` enabled and readable |
| `host.defender` | Defender operational log present and readable |
| `host.files` | Read access to configured paths |
| `sqlserver.live` | Windows, `System.Data.SqlClient`, `VIEW SERVER STATE`, and `server` or `SENTINEL_SQL_CONNECTION` |
| `saas.audit` | HTTPS audit endpoint and token in `SENTINEL_SAAS_TOKEN` (or configured `token_env`) |
| `http.access` / `proxy.access` / `db.audit` / `cloud.audit` / `network.sensor` | A JSONL file path the service account can read |
| `store.anchor` | Off-host file path (e.g. UNC share) or HTTPS anchor receiver + `SENTINEL_ANCHOR_SECRET` |
