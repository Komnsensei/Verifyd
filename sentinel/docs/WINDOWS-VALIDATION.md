# Windows validation procedure

This procedure turns "it should work on Windows" into a captured evidence bundle.
It cannot be executed from a Linux host and must run on the Windows machine that
Sentinel is installed on.

## One-click setup

Extract the bundle and double-click `SETUP-SENTINEL.cmd` at the repository
root. It requests elevation, installs Node.js LTS with winget if Node is
missing, installs Sentinel, creates the diagnostics token, runs the checklist
below, and opens the evidence folder. The install also creates
**Start Menu > Sentinel Status**, a tray window with live health, the adapter
split and recent alerts, plus buttons to run a fresh check. No commands need to
be typed.

## Manual run

From an elevated PowerShell session in `sentinel\windows`:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\validate.ps1 -TestListener
```

If the scheduled task is running, local diagnostics require the token named by
`diagnostics.token_env` (`SENTINEL_DIAG_TOKEN` by default). Set it once and open
a new elevated shell, or restart the task, so the service inherits it:

```powershell
[Environment]::SetEnvironmentVariable('SENTINEL_DIAG_TOKEN',
  [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N'), 'Machine')
.\control.ps1 -Action restart
```

Without a token the harness still captures the coverage matrix through the
read-only CLI, but `/alerts/recent` is unreachable, so `-TestListener` and
`-RestartService` report SKIP with that reason instead of a false FAIL.

A full pass including restart continuity:

```powershell
.\validate.ps1 -TestListener -RestartService
```

After a manual reboot:

```powershell
Restart-Computer -Force
# after logon, elevated:
.\validate.ps1 -RecoveryCheck
```

The default output directory is
`C:\ProgramData\Sentinel\validation\<UTC timestamp>\`. Pass `-OutputDir` to
change it.

## What the harness does

1. Runs `preflight.ps1` and captures environment facts (no secret values).
2. Starts the scheduled task if needed and waits for `/health` (60s).
   If no task is running, uses `sentinel.cjs once` instead.
3. Captures the full coverage matrix, including reasons for every UNAVAILABLE
   and NOT_CONFIGURED adapter.
4. Captures real samples: TCP listeners with owning processes, CIM process
   snapshot, Security events (4625/4688/4672, no command lines), Defender events.
5. Verifies the evidence chain and records `records`, `last_seq`, `head`.
   A fresh install with no evidence yet reports `chain_before: SKIP`, not a
   vacuous pass.
6. With `-TestListener`, opens a temporary loopback TCP listener, waits for the
   configured listener poll, and asserts a `NEW_LISTENER` alert for that exact
   port. The listener is always closed in `finally`.
7. With `-RestartService`, stops and starts the task, re-verifies the chain, and
   asserts that listeners known before the restart were not re-alerted.
8. With `-RecoveryCheck`, compares `last_seq` with the previous report.
9. Writes `report.json`, `coverage.json`, `preflight.json`, `verify-before.json`
   and `samples\*.json`.

Exit codes: `0` report written (even if adapters are UNAVAILABLE), `1` evidence
chain invalid, `2` prerequisites missing or not Windows, `3` service failed to
become ready.

## Expected results on a correctly configured host

| Adapter | ACTIVE when | If not ACTIVE |
|---|---|---|
| `http.access` | `adapters.http_access.path` exists and is readable | UNAVAILABLE with the path and OS error, or NOT_CONFIGURED if empty |
| `proxy.access` | exported CDN/WAF JSONL exists | NOT_CONFIGURED |
| `host.listeners` | always on Windows | UNAVAILABLE only if the TCP table cannot be read |
| `host.process` | 4688 auditing (preferred) or CIM access | UNAVAILABLE with the audit-policy reason |
| `host.security` | adapter enabled, process elevated or in Event Log Readers | NOT_CONFIGURED if disabled, UNAVAILABLE without authorization |
| `host.defender` | Defender operational log exists and is readable | UNAVAILABLE |
| `host.files` | at least one configured path exists | NOT_CONFIGURED if disabled or no paths |
| `db.audit` | exported audit JSONL exists | NOT_CONFIGURED |
| `webflow.logs` | operator-exported JSONL exists | NOT_CONFIGURED by design |
| `self.health` | state directory writable | UNAVAILABLE on permission failure |

`-TestListener` should produce one LOW alert, `NEW_LISTENER`, with
`evidence.port` equal to the temporary port. If it fails while `host.listeners`
is ACTIVE, the likely cause is the poll interval: the harness waits
`poll_interval_ms * 1.5 + 10s`, capped at 3 minutes.

## What this proves and does not prove

Proves, when the checks pass:

- the service starts under the configured task account and answers `/health`;
- the evidence chain is internally consistent and continues across restart;
- each ACTIVE source was actually read on this host;
- the listener path works end to end, including scoring and storage;
- UNAVAILABLE/NOT_CONFIGURED sources are explicit rather than silently missing.

Does not prove:

- actual reboot behavior unless you run the separate `Restart-Computer` step and
  then `-RecoveryCheck`;
- that a Security event will be generated by your audit policy (the samples show
  whether any exist; an empty list is a finding, not a pass);
- API, database, CDN/WAF or Webflow coverage where those integrations are not
  configured;
- detection of low-and-slow access below configured thresholds.

## Handling the bundle

`report.json` and the samples can contain host names, account names, process
paths and Defender messages. Review before sharing outside the incident or
deployment record. No token or environment value is written.

Preserve the bundle with the deployment record. It is the evidence that the
coverage matrix was measured rather than assumed.
