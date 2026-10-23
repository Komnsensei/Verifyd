# Verification record

Date: 2026-10-21 (UTC)
Workspace: Linux cloud worktree, branch `freebuff/3689be55ed17d6731ac0b22c`,
base commit `915b569`.

> Historical run record: the counts below (71 tests) describe the run at that
> base commit on 2026-10-21. They are not a claim about the current suite,
> which emits 72 tests.

## 1. Environment discovered

| Item | Observed |
|---|---|
| OS | Ubuntu 24.04.5 LTS (Noble), kernel 6.1.102, x86_64 |
| CPU / RAM | 2 vCPU, 3,915 MB total, 3,417 MB available |
| Disk | 16 GB volume, 8.8 GB available at start |
| Node.js | v24.21.0 |
| npm | 11.19.0 |
| Bun | 1.3.14 |
| Python | 3.12.3 |
| Git | 2.43.0 |
| PowerShell | Windows PowerShell absent; `pwsh` 7.4.6 installed to /tmp only for PowerShell-parser syntax checks |
| Listening TCP | 22, 3000, 44005 (loopback), 53 (systemd-resolved, loopback) |
| Reverse proxy / CDN / DB config | none in the repository or environment |
| Environment files | none present; no `.env` values read |
| Secret-like env var names in shell | none matching proxy/database/cloud patterns |

Consequence: this host cannot produce Windows event-log telemetry, does not have
the Security/Defender channels, and cannot execute `Get-NetTCPConnection`,
`Get-WinEvent` or the scheduled-task scripts. Windows adapter logic is exercised
with injected telemetry and platform overrides, not against a real Windows host.

### Repository state

- Existing project: Verifyd v1.0, zero-dependency CommonJS, Node >= 18.
- No existing monitoring component was present; Sentinel is additive under
  `sentinel/` with one CLI entry point at `bin/sentinel.cjs`.
- No database, queue or web framework was introduced. Storage is JSONL plus the
  existing canonical JSON helper (`engine/canonicalize.cjs`).
- No secrets, browser credentials or private files were read. Configuration
  reports only environment variable **names**.

## 2. Test results

Command:

```
node --test --test-timeout=25000 --test-reporter=tap "sentinel/test/*.test.cjs"
```

Result (exit status 0):

```
# tests 71
# pass 71
# fail 0
# cancelled 0
# skipped 0
# todo 0
```

Raw TAP: [samples/test-run.tap](samples/test-run.tap).

Coverage of the required scenarios:

| Required scenario | Test(s) | Result |
|---|---|---|
| Normal browsing without false positives | `normal browsing produces no alerts`, `weird user agent...` | pass, 0 alerts for 40 + 20 events |
| Repeated failed logins | `repeated authentication failures raise AUTH_FAIL_BURST...` | pass, score 15, evidence count 5 |
| Sequential pagination and bulk reads | `sequential pagination...`, `single bulk response...` | pass, 25/30 |
| Unauthorized protected resource | `unauthenticated access to a protected route is critical` | pass, critical 100 |
| New listening ports and process events | adapter tests with injected PowerShell + host scenario | pass |
| Duplicate suppression | `duplicate detections within the cooldown...` | pass, 1 alert, counter incremented |
| Webhook failure and recovery | dispatcher retry/recovery + local receiver outage | pass, queue drains |
| Rotation, redaction, retention, restart | store suite + restart test | pass |
| Missing permissions and unavailable sources | `an adapter that cannot read its source...`, platform tests | pass, service continues |
| Windows reboot / service restart | restart test with persisted baseline + chain | pass in simulation; real reboot **pending Windows host** |

Additional tests: config validation (HTTP webhook rejected, metadata endpoint
rejected, remote diagnostics requires token), constant-time token auth on the
diagnostics endpoint, HMAC signature verification, payload size cap, dead-letter,
end-to-end collection from a local instrumented HTTP API with 12 real requests,
and database audit rules for bulk reads, authentication failures and new
identities, plus gated response-action tests (dry-run, missing secret,
severity floors).

## 3. Synthetic scenario results

```
node bin/sentinel.cjs simulate --scenario all
```

| Scenario | Events | Alerts |
|---|---|---|
| normal | 40 | 0 |
| auth-fail | 7 | 2: AUTH_FAIL_BURST (15), DENIED_THEN_SUCCESS (20) |
| enumeration | 12 | 1: SEQUENTIAL_ENUMERATION (25) |
| bulk | 1 | 1: BULK_RESPONSE_VOLUME (30) |
| unauthorized | 1 | 1: PROTECTED_UNAUTHENTICATED (critical, 100) |
| denied-then-success | 2 | 1: DENIED_THEN_SUCCESS (20) |
| host | 3 | 3: NEW_LISTENER (15), PROCESS_FROM_TEMP (20), DEFENDER_DETECTION (40) |

All generated stores verified `Chain valid: true`.
Full JSON: [samples/alerts.json](samples/alerts.json).

## 4. Resource usage

Measured on the host above, single process, Node 24.21.

| Case | Measurement |
|---|---|
| Idle service, self.health only | 57.7 MB RSS, 7 threads, `VmHWM` 58.1 MB |
| 10,000 events through full pipeline | 1.39 s, 7,219 events/s, 107 MB RSS, 23 MB heap |
| 50,000 events | 6.68 s, 7,485 events/s, 182 MB RSS, 88 MB heap |
| Verify 10,000 records | 339 ms |
| Verify 50,000 records (50.9 MB store, 7 files) | 1,941 ms |
| Store growth | ~1 KB per HTTP event (hash chain + normalized fields) |

Command for reproductions:

```
node sentinel/bench.cjs 10000
node sentinel/bench.cjs 50000
```

The benchmark disables adapters and feeds synthetic events through the real
normalizer, rule engine, hash-chained store and verifier. PowerShell polling cost
is not included; each host adapter has a 15-20 s timeout and a configurable
interval.

An initial implementation pruned rule state on every event and measured 262
events/s. Pruning was changed to at most once per second of event time, raising
throughput to ~7,200-8,200 events/s with no rule behavior change (tests re-run).

## 5. What was executed vs not

Executed:

- full test suite (71 tests) on Linux;
- PowerShell parser check of all nine `.ps1` files under `pwsh` 7.4.6 (syntax only);
- `tray.ps1 -Once` against a live local service: with token (health, chain,
  adapter split, alerts), without token (health only), and with the service
  stopped (UNREACHABLE, exit 1);
- the config write path used by `setup-sentinel.ps1`/`install.ps1` emits
  UTF-8 without BOM and is accepted by `config-check`; a BOM-prefixed copy is
  rejected, confirming the encoding check is meaningful;
- CLI: `config-check`, `rules`, `simulate`, `coverage`, `once`, `run`, `verify`;
- real HTTP server + middleware + adapter end-to-end;
- real local webhook receiver with HMAC verification, outage and recovery;
- idle service start, `/health`, token rejection on `/status`, SIGTERM shutdown,
  chain verification after shutdown;
- retention, rotation, tamper/reorder/torn-tail verification;
- store permission modes on POSIX;
- resource measurements above.

Not executed (explicitly not claimed as working):

- `install.ps1`, `control.ps1`, `uninstall.ps1`, `preflight.ps1`, `validate.ps1`,
  `enable-audit.ps1`, `setup-sentinel.ps1` and `tray.ps1`/`tray-ui.ps1` on Windows (they parse
  cleanly, but no Windows cmdlet, ACL, SACL, auditpol, scheduled task, shortcut or WinForms
  window was run);
- `Get-NetTCPConnection`, `Get-WinEvent` (Security/Defender), 4688 parsing,
  `Get-CimInstance Win32_Process` against live Windows;
- Windows scheduled task registration, boot start, reboot recovery;
- Windows ACL application via `icacls`;
- any database, CDN/WAF, Cloudflare Logpush or Webflow live API;
- any third-party system.

These are code-complete but unverified on the target OS. The test suite injects
the exact PowerShell JSON shapes the adapters expect, which validates mapping
and detection logic, not the Windows cmdlets themselves.

## 6. Acceptance criteria mapping

| Criterion | Status |
|---|---|
| Working source code, not pseudocode | met: 34 source modules + CLI + 9 test files |
| Windows installation and startup scripts | delivered, parser-checked, **unexecuted** here |
| Documented configuration with no secrets | met: `sentinel/config.example.json`, env names only |
| Automated tests and actual results | met: 71/71 pass, TAP saved |
| Coverage matrix for active and unavailable sources | met: `docs/COVERAGE.md` + live `coverage` command |
| Sample alerts and IR runbook | met: `docs/RUNBOOK.md`, `docs/samples/alerts.json` |
| Resource usage and limitations | met: section 4 and `README.md` limitations |
| PowerShell install/start/stop/inspect/uninstall | met in `windows/README-WINDOWS.md`, unexecuted |
| Start on Windows | **pending real Windows verification** |
| Recover after restart | met in simulation: sequence continues, baseline persists, queue replays |
| Detect synthetic test events | met: 7 scenarios, expected alerts |
| Auditable alerts | met: hash-chained alert records, verify passes |
| Redact secrets | met: authorization/cookie/API key/JWT/password redaction tested |
| Identify blind spots | met: explicit statuses + global limitations in every coverage output |

## 7. Prerequisite checks before claiming Windows coverage

Run these on the target host and attach the output to the deployment record:

```powershell
cd sentinel\windows
.\preflight.ps1 -OutputPath C:\Temp\sentinel-preflight.json
.\validate.ps1 -TestListener -RestartService
Restart-Computer -Force
# after logon, elevated:
.\validate.ps1 -RecoveryCheck
```

Procedure and expected results: [WINDOWS-VALIDATION.md](WINDOWS-VALIDATION.md).

Acceptance for Windows: task state Running, `/health` reachable, chain valid and
sequence continuing, the same listeners not re-alerted, synthetic 4688/4625/1116
events mapped into the expected kinds, and a documented decision for every
adapter that remains UNAVAILABLE or NOT_CONFIGURED.

## 8. Known limitations carried forward

- Polling latency: `http.access` 2 s default, host adapters 20-60 s.
- CIM process mode misses short-lived processes; 4688 needs audit policy.
- Windows Security log needs elevation or Event Log Readers, plus audit policy.
- Database/CDN/Webflow coverage is exported-log only; no credentials are held.
- Correlation uses event time from the producer; a producer that rewrites
  timestamps can shift windows.
- Single-node, local state. No central aggregation or tamper-proof off-host copy.
- The hash chain detects edits/truncation only if the head or a copy is preserved
  elsewhere; an attacker with full control of the host can rewrite the whole
  chain and its anchors.
- No guarantee of detecting low-and-slow scraping below configured thresholds.
