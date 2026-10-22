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
| A | `http.access` | JSONL access log from instrumented app, Caddy or generic writer | route/method/principal/IP rates, 401/403/429, pagination, bytes out | `NOT_CONFIGURED` (path empty) | `ACTIVE` when `adapters.http_access.path` is readable | All application-layer access patterns are invisible |
| C | `proxy.access` | Cloudflare Logpush JSONL or generic proxy JSONL | edge request rate, status, WAF action/rule, source IP | `NOT_CONFIGURED` | `ACTIVE` when a provider log path is readable | WAF/CDN events and pre-origin traffic are invisible |
| B | `host.listeners` | `Get-NetTCPConnection -State Listen` | new/removed TCP listeners with owning PID/process | `UNAVAILABLE` (requires Windows) | `ACTIVE` with persisted baseline | A new backdoor listener would not be reported |
| B | `host.process` | Security 4688, or CIM `Win32_Process` snapshot diff | process image, parent, user, temp-directory launch | `UNAVAILABLE` (requires Windows) | `ACTIVE` (4688 preferred; CIM is degraded) | Process execution is invisible; CIM misses short-lived processes |
| B | `host.security` | Security 4624/4625/4672 | Windows logon success/failure, source IP, special privileges | `NOT_CONFIGURED` (disabled by default) | `UNAVAILABLE` unless elevated or in Event Log Readers, and audit policy is on | Host logon attacks and privileged logons are invisible |
| B | `host.defender` | `Microsoft-Windows-Windows Defender/Operational` | Defender detection and configuration changes | `UNAVAILABLE` (requires Windows) | `ACTIVE` when the channel exists and is readable | Defender findings do not reach Sentinel |
| B | `host.files` | SHA-256 baseline of configured paths | created/modified/deleted application or config files | `NOT_CONFIGURED` (no paths) | `ACTIVE` for existing paths | Tampering with monitored app files is invisible |
| C | `db.audit` | Exported database audit JSONL | bulk reads (`rows_read`), GRANT/REVOKE, auth failures | `NOT_CONFIGURED` (no path) | `ACTIVE` when the export exists | Database-side exfiltration cannot be measured |
| C | `webflow.logs` | Operator-exported Webflow JSONL only | request-level access from an export | `NOT_CONFIGURED` | `NOT_CONFIGURED` unless a log export is supplied | No Webflow audit trail is monitored |
| - | `self.health` | in-process store/queue/memory/disk checks | service health, store utilization, queue depth | `ACTIVE` | `ACTIVE` | Self-monitoring only; cannot detect its own total failure |

Summary from this run: **1 ACTIVE, 3 UNAVAILABLE, 6 NOT_CONFIGURED**.

## Coverage by requirement

### A. HTTP/API access

Covered when `http.access` or `proxy.access` is ACTIVE:

- request rate by normalized route, method, principal and source address;
- auth failures (401/407), authorization failures (403), rate limiting (429);
- pagination/offset parameters, sequential record ids, repeated sensitive routes;
- response byte counts and single/window bulk thresholds;
- protected-route access without a principal or with `authorized: false`.

Not covered:

- requests blocked upstream by a WAF/CDN unless that log is also collected;
- request/response bodies (never collected), so payload-level scraping cannot be
  distinguished from ordinary reads;
- APIs with no access log and no middleware instrumentation.

### B. Windows host

Covered when the corresponding adapters are ACTIVE:

- listening-port changes against a persisted baseline;
- process creation with parent/user/image, 4688 command line when audited;
- failed/successful logons and special-privilege assignment, if authorized;
- Defender detection events;
- SHA-256 changes in explicitly configured directories;
- service health, missed polls, store write failures and queue depth.

Not covered:

- kernel drivers, ETW providers, Sysmon-only events, network packet contents;
- file reads (only content hashes of monitored files at poll time);
- registry persistence, scheduled-task creation, WMI subscriptions;
- processes that start and exit between CIM polls when 4688 is not enabled;
- event log channels without an enabled audit policy.

### C. Data stores and external services

`db.audit`, `proxy.access` and `webflow.logs` consume **exported logs only**.
Sentinel holds no database password, cloud API token or Webflow token in this
build. Without an export, those sources are `NOT_CONFIGURED`, not "monitored".

Not covered:

- live SQL statement capture or DB session introspection;
- cloud control-plane audit logs (CloudTrail/Azure Activity/GCP Audit) unless
  separately exported to a collected file format;
- third-party SaaS audit APIs that require credentials this build does not hold.

## Global blind spots

- Host telemetry cannot establish what happened inside an uninstrumented
  external API or database. Full coverage requires integrating those systems'
  own audit logs and audit events.
- No detection of scrapers or exfiltration that stay below every configured
  threshold. Thresholds are tuning values, not guarantees.
- Log timestamps are trusted as written by the producer.
- Single-node deployment: if the host is compromised, an attacker with admin
  rights can stop the service; the hash chain makes after-the-fact edits
  detectable only if a copy of the head/anchor was preserved elsewhere.
- No packet capture, TLS inspection, DNS monitoring or endpoint agent.

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
| `host.process` | 4688: `Audit Process Creation` = Success, Security log read. CIM: no special right |
| `host.security` | Elevated or Event Log Readers; logon audit subcategories enabled |
| `host.defender` | Defender operational log present and readable |
| `host.files` | Read access to configured paths |
| `http.access` / `proxy.access` / `db.audit` | A log file path the service account can read |
