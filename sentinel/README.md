# SENTINEL

Defensive data-access monitoring for Windows hosts and the APIs they serve.
Detects, records, correlates and alerts on suspicious access patterns; starts in
**detection-only** mode and never hides uncertainty.

Sentinel is part of the Verifyd repository, reuses the engine's canonical JSON
and SHA-256 primitives, and adds no runtime dependency.

## Status of this build

- Engine, storage, detection, dispatch, diagnostics and tests: **executed** on
  Ubuntu 24.04 with Node.js 24.21 (71 tests, 0 failures).
- Windows adapters: **implemented and unit-tested with injected telemetry**;
  they report `UNAVAILABLE` on any non-Windows host.
- PowerShell install/control/uninstall/validate/enable-audit scripts: **not executed** in
  this environment (no Windows host). They are parser-checked; review before use.
  The validation harness is [docs/WINDOWS-VALIDATION.md](docs/WINDOWS-VALIDATION.md).
- External integrations (database, SQL Server DMVs, cloud control plane, SaaS audit API, CDN/WAF, network sensor, Webflow): **not configured** by default and
  reported as such until configured. No token or credential is stored in the repo.

Details and raw results: [docs/VERIFICATION.md](docs/VERIFICATION.md).

## What it does

```
access log / Windows event log / SQL DMVs / cloud & SaaS & network sensor logs
        |
        v
  adapters (18, independently statused)
        |
        v
  normalize + redact + event_id  ->  hash-chained JSONL evidence (+ optional off-host anchor)
        |
        v
  deterministic rubric + correlation window + dedupe + baseline
        |
        +--> alert store (same chain)
        +--> signed webhook (durable queue, retry, backoff)
        +--> optional guarded control request (off by default, dry-run)
```

## Quick start (Linux/macOS, synthetic events)

No install step.

```
node bin/sentinel.cjs config-check
node bin/sentinel.cjs rules
node bin/sentinel.cjs simulate --scenario all
node --test "sentinel/test/*.test.cjs"
```

`simulate` runs real adapters? No: it feeds synthetic events through the real
normalizer, rule engine, store and dispatcher. Nothing leaves the process.

Synthetic scenario results (deterministic):

| Scenario | Events | Alerts |
|---|---|---|
| normal | 40 | 0 |
| auth-fail | 7 | 2 (AUTH_FAIL_BURST, DENIED_THEN_SUCCESS) |
| enumeration | 12 | 1 (SEQUENTIAL_ENUMERATION) |
| bulk | 1 | 1 (BULK_RESPONSE_VOLUME) |
| unauthorized | 1 | 1 (PROTECTED_UNAUTHENTICATED, critical) |
| denied-then-success | 2 | 1 |
| host | 3 | 3 (NEW_LISTENER, PROCESS_FROM_TEMP, DEFENDER_DETECTION) |

## Quick start (Windows host)

Double-click `SETUP-SENTINEL.cmd` in the repository root. It installs Node.js
LTS if needed, installs Sentinel, runs the validation checklist, and adds
**Start Menu > Sentinel Status** - a tray window with live health, the adapter
split and recent alerts.

Manual commands, service-account guidance, reboot test and uninstall:
[windows/README-WINDOWS.md](windows/README-WINDOWS.md).

## Coverage

Every adapter reports one of three states, and the service never upgrades a
state it has not proven:

| State | Meaning |
|---|---|
| `ACTIVE` | Source was opened/queried successfully during this run |
| `UNAVAILABLE` | Configured or expected, but the host/platform/permission denied it |
| `NOT_CONFIGURED` | No path, URL or integration exists for it |

| Adapter | Source | Non-Windows result |
|---|---|---|
| `http.access` | JSONL access log (app middleware / Caddy / generic) | needs a log path |
| `proxy.access` | Cloudflare Logpush or generic JSONL | needs a log path |
| `host.listeners` | `Get-NetTCPConnection -State Listen` | `UNAVAILABLE` |
| `host.process` | Security 4688 or CIM snapshot diff | `UNAVAILABLE` |
| `host.security` | Security 4624/4625/4647/4672/4673 | `UNAVAILABLE` |
| `host.defender` | Defender operational log | `UNAVAILABLE` |
| `host.files` | SHA-256 baseline of configured paths, persisted across restarts | works anywhere |
| `host.persistence` | Security 4657/4698/4699/4700/4702 + WMI-Activity 5861 | `UNAVAILABLE` |
| `host.fileaudit` | Security 4663 file read/write/delete audit | `UNAVAILABLE` |
| `host.sysmon` | Sysmon operational log (events 1/3/7/8/10/11/12-14/17-21/22/25) | `UNAVAILABLE` |
| `host.dns` | Windows DNS Client operational log (3008) | `UNAVAILABLE` |
| `cloud.audit` | AWS CloudTrail, Azure Activity, GCP Audit JSONL | needs a log path |
| `sqlserver.live` | SQL Server DMV live sessions and active statements | `UNAVAILABLE` |
| `saas.audit` | Authenticated HTTPS SaaS audit API pull | needs URL + token env |
| `db.audit` | exported JSONL audit log (bulk reads, privilege and identity changes, auth failures) | needs a log path |
| `network.sensor` | Zeek / Suricata EVE JSONL (flows, DNS, TLS metadata, IDS alerts) | needs a log path |
| `webflow.logs` | operator-exported JSONL only | `NOT_CONFIGURED` |
| `self.health` | store, queue, memory, disk | `ACTIVE` |

Matrix with observed reasons on the verification host:
[docs/COVERAGE.md](docs/COVERAGE.md).

## Detection rubric

Scores are initial tuning values, not calibrated probabilities. Full detail and
tuning guidance: [docs/RULES.md](docs/RULES.md).

| Rule | Score | Trigger |
|---|---|---|
| AUTH_FAIL_BURST | +15 | 5+ auth failures in the window |
| RATE_LIMIT_BURST | +10 | 3+ rate-limit responses |
| DENIED_THEN_SUCCESS | +20 | 401/403 then 2xx on the same route |
| SEQUENTIAL_ENUMERATION | +25 | 5+ consecutive pages or 10+ sequential ids |
| BULK_RESPONSE_VOLUME | +30 | 2MB single response or 10MB in window |
| SENSITIVE_ROUTE_REPEAT | +20 | 10+ hits on a sensitive route above baseline |
| PROTECTED_UNAUTHENTICATED | +100 | 2xx on a protected route without authorization |
| NEW_LISTENER | +15 | listener not in the persisted baseline |
| PROCESS_FROM_TEMP | +20 | image path under a temp directory |
| DEFENDER_DETECTION | +40 | Defender 1116/1117 |
| FILE_INTEGRITY_CHANGE | +15/+20 | modified/deleted monitored file |
| DB_BULK_READ | +30 | 5000+ rows in one audited statement |
| DB_AUTH_FAILURE | +15 | database authentication failure |
| DB_NEW_IDENTITY | +20 | new user/role created |
| DB_PRIVILEGE_CHANGE | +25 | GRANT/REVOKE/role change |
| HOST_AUTH_FAILURE_BURST | +15 | 5+ Windows logon failures |
| PERSISTENCE_CHANGE | +35 | registry persistence (4657 / Sysmon 12-14) or scheduled task (4698/4699/4700/4702) |
| WMI_SUBSCRIPTION | +60 | permanent WMI event subscription (5861 / Sysmon 19-21) |
| CLOUD_PRIVILEGE_CHANGE | +40 | CloudTrail / Azure / GCP IAM or policy privilege change |
| DB_LIVE_BULK_READ | +30 | live SQL Server DMV session with 100k+ logical reads |
| SYSMON_PROCESS_TAMPER | +60 | Sysmon event 25 process tampering |
| NETWORK_BULK_TRANSFER | +30 | Zeek/Suricata flow >= 50 MB |
| NETWORK_IDS_ALERT | +25 | Suricata/sensor IDS alert with severity <= 2 |

Severity: `low` < 25, `medium` >= 25, `high` >= 50, `critical` >= 80.
`min_alert_score` defaults to 10.

False-positive guards:

- Voluntary browser traffic does not alert (test covers 120+ normal requests).
- User-Agent or a missing `Accept-Language` is never scored.
- Steady per-route traffic is compared against a learned minute-bucket baseline;
  repetition rules wait for the baseline to exist.
- Duplicate detections for the same rule/entity/route are suppressed for the
  cooldown and counted instead of re-alerted.
- Allowlists can pin known scanners/integrations by IP/CIDR, principal, route,
  process or adapter, with an optional expiry.

## Evidence

`state/events-NNNNNN.jsonl`, one JSON object per line:

```json
{"v":1,"seq":42,"at":"2026-10-21T03:00:00.000Z","prev":"<sha256>",
 "type":"alert","hash":"<sha256>","payload":{"schema":"sentinel.alert/1",
 "rule_id":"AUTH_FAIL_BURST","severity":"low","score":15, "...":"..."}}
```

- `hash = SHA-256(canonicalJSON({v,seq,at,prev,type,payload}))`, chained.
- Rotation by size, retention by age and count, with a retention anchor so
  verification distinguishes authorized pruning from deleted history.
- Files created with mode `0600`; Windows install applies SYSTEM/Administrators
  ACLs with well-known SIDs.
- Authorization headers, cookies, API keys, JWTs and credential-shaped strings
  are redacted before the record is hashed, never after.
- Request and response body values are never stored; `createAccessLogger`
  records only SHA-256 hashes and a JSON key/type/length skeleton (`bodyMode:
  "shape"`, default) so payload-level scraping is distinguishable without
  persisting sensitive content.
- Optional off-host chain-head anchoring (`store.anchor.path` or
  `store.anchor.url` signed with `SENTINEL_ANCHOR_SECRET`) detects local chain
  rollback or truncation.

Verify at any time:

```
node bin/sentinel.cjs verify --config sentinel/config.example.json
```

`Chain valid: true` means every record links to its predecessor and no hash was
altered. A torn final line from a crash is reported separately, not hidden.

## Diagnostics

Loopback by default (`127.0.0.1:8790`). Endpoints: `/health`, `/status`,
`/coverage`, `/alerts/recent`, `/metrics`.

`/health` is minimal and unauthenticated on loopback. Everything else requires
the token named by `diagnostics.token_env` whenever that variable exists; a
non-loopback bind is refused unless `allow_remote` is set and a token is
configured. The token is compared in constant time.

## Webhook delivery

- HTTPS required except loopback with `allow_insecure_loopback`.
- `X-Sentinel-Signature: sha256=HMAC(secret_env, timestamp + "." + body)`.
- Append-only queue (`alerts.queue.jsonl`) with `enqueue/attempt/ack/dead` ops,
  exponential backoff with stable jitter, dead-letter after `max_attempts`.
- The queue compacts past 8 MB, preserving live items and their backoff state,
  and prunes delivered records from memory.
- Receiver outages do not lose alerts; replay happens after restart.

## Safe response

`detection.mode` defaults to `detect`. Actions require `respond` mode,
`actions.enabled: true`, a configured authorized target URL, and default to
`dry_run: true`. Action types: temporary gateway rate limit, WAF source block,
and a signed credential-rotation request to an approved identity endpoint.
Sentinel holds no provider credentials and performs no rotation itself. Nothing
in this service edits the local firewall, kills processes, deletes evidence or
tarpits requests.

## Configuration

`config.example.json` is a complete, secret-free example. Secret-bearing values
are read from environment variables and reported by name only:

- `SENTINEL_WEBHOOK_SECRET`
- `SENTINEL_DIAG_TOKEN`
- `SENTINEL_ACTION_SECRET`
- `SENTINEL_SAAS_TOKEN`
- `SENTINEL_SQL_CONNECTION`
- `SENTINEL_ANCHOR_SECRET`

`node bin/sentinel.cjs config-check` prints which names are present (never values).

## CLI

```
node bin/sentinel.cjs run|once|status|coverage|verify|rules|simulate|config-check|rotate|prune|webhook-test
```

Exit codes: `0` ok, `2` configuration error, `3` chain verification failed,
`4` runtime failure.

## Tests

```
npm run test:sentinel
```

72 tests covering normal browsing, failed logins, pagination/enumeration, bulk
reads, unauthorized access, listeners/process/persistence/file-audit/Sysmon/DNS
events, cloud/SQL Server/SaaS/network-sensor adapters, body-shape capture,
off-host chain anchoring, dedupe, webhook failure and recovery,
rotation/redaction/retention/restart, missing permissions, unavailable sources,
health-endpoint auth, config validation and end-to-end collection from a local
instrumented API.

Raw TAP output: [docs/samples/test-run.tap](docs/samples/test-run.tap).

## Resource usage (measured)

| Case | Result |
|---|---|
| Idle service, one ACTIVE adapter | 57.7 MB RSS, 7 threads |
| 10,000 events through full pipeline | 1.39 s, 7,219 events/s, 107 MB RSS |
| 50,000 events | 6.68 s, 7,485 events/s, 182 MB RSS |
| Verify 10k / 50k records | 0.34 s / 1.94 s |

Host: Ubuntu 24.04, x86_64, Node 24.21, 3.9 GB RAM. PowerShell and Windows
event collection are not included in these numbers because they cannot run here.

## Known limitations

- Host telemetry cannot establish what happened inside an uninstrumented
  external API or database. Integrate those systems' own audit logs.
- No packet capture, TLS inspection, endpoint driver or Sysmon requirement.
- Polling adapters can miss events between polls; CIM snapshot process mode
  misses short-lived processes unless 4688 auditing is enabled.
- Log timestamps are trusted as written by the producer; correlation uses event
  time, so a producer that rewrites history can shift windows.
- No detection of a scraper that stays below every configured threshold.
- Windows Event Log coverage depends on audit policy and the service account's
  read permissions; Sentinel cannot enable auditing for you.
- Single-node only: no clustering, no central aggregation, no built-in SIEM.
- Installed as a boot-start scheduled task, not an SCM service. There is no
  NSSM/service wrapper, so Windows service control semantics do not apply.
- Windows Event Log writing is not implemented; evidence is file-based JSONL.
