# Sentinel on Windows

All commands are PowerShell, run from an elevated session. Paths assume the
default install directory `C:\ProgramData\Sentinel`; change `-InstallDir` and the
paths below together if you install elsewhere.

The service starts in **detection-only** mode. No firewall rule is created, no
process is terminated, and no credential is collected by these scripts.

## One-click install and validation

Double-click `SETUP-SENTINEL.cmd` in the repository root. It requests elevation,
installs Node.js LTS with winget if Node is missing, installs Sentinel, creates
a local diagnostics token, runs the validation checklist and opens the evidence
folder. The install also adds **Start Menu > Sentinel Status**, a small tray
window showing live health, ACTIVE/UNAVAILABLE adapters and recent alerts. The
manual procedure below remains available for controlled deployments.

## 1. Preflight (read-only)

```powershell
cd <repo>\sentinel\windows
powershell -NoProfile -ExecutionPolicy Bypass -File .\preflight.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\preflight.ps1 -OutputPath C:\Temp\sentinel-preflight.json
```

The JSON report contains OS/build, Node version, disk free, listening ports with
owning processes, audit-policy state, available event log channels, Defender
status and whether the documented secret environment variable names exist. It
never reads secret values.

## 2. Install

Simplest path, running as the built-in LocalService account (least privilege):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Start
```

Running as a dedicated service account with Security-log access (recommended when
`host.security` is enabled):

```powershell
$cred = Get-Credential 'CONTOSO\svc-sentinel'
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 `
  -InstallDir 'D:\Sentinel' `
  -Account $cred.UserName `
  -Credential $cred `
  -GrantEventLogRead `
  -Start
```

Deploying an existing configuration:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 `
  -ConfigPath '\\files\configs\sentinel-production.json' `
  -Start
```

Replacing an existing installation (task is re-registered, state is kept):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Force -Start
```

What the installer does:

1. Requires elevation, Node.js 18+ and the repository layout.
2. Copies `engine\`, `sentinel\`, `bin\` and `package.json` to `-InstallDir`.
3. Creates or keeps `config.json`; a new one points `service.state_dir` at
   `<InstallDir>\state`.
4. Restricts `state\`, `logs\` and `config.json` to SYSTEM and Administrators
   using well-known SIDs.
5. Runs `config-check` and refuses to register the task if the config is invalid.
6. Registers scheduled task `SentinelDataAccessMonitor` at startup with
   restart-on-failure and no execution time limit.

Secrets are machine environment variables, never config values:

```powershell
[Environment]::SetEnvironmentVariable('SENTINEL_DIAG_TOKEN', '<random 32+ chars>', 'Machine')
[Environment]::SetEnvironmentVariable('SENTINEL_WEBHOOK_SECRET', '<random 32+ chars>', 'Machine')
[Environment]::SetEnvironmentVariable('SENTINEL_ACTION_SECRET', '<random 32+ chars>', 'Machine')
```

Restart the task after setting them so the service inherits the new environment.

## 3. Start, stop, restart

```powershell
Start-ScheduledTask   -TaskName SentinelDataAccessMonitor
Stop-ScheduledTask    -TaskName SentinelDataAccessMonitor
# restart = stop then start
Stop-ScheduledTask  -TaskName SentinelDataAccessMonitor
Start-ScheduledTask -TaskName SentinelDataAccessMonitor
```

Through the control script:

```powershell
.\control.ps1 -Action start
.\control.ps1 -Action stop
.\control.ps1 -Action restart
```

`Stop-ScheduledTask` terminates the task process tree; Windows does not deliver a
POSIX SIGTERM. Evidence already written is on disk because appends are
synchronous, and the hash chain, queue and runtime state recover on next start.
When run interactively, Ctrl+C uses the graceful shutdown path instead.

## 4. Inspect

```powershell
.\control.ps1 -Action status
.\control.ps1 -Action health
.\control.ps1 -Action coverage
.\control.ps1 -Action verify
.\control.ps1 -Action logs -Lines 100

Get-ScheduledTaskInfo -TaskName SentinelDataAccessMonitor
Get-CimInstance Win32_Process -Filter "Name = 'node.exe'" |
  Where-Object { $_.CommandLine -like '*sentinel.cjs*' } |
  Select-Object ProcessId, CreationDate, CommandLine

Invoke-RestMethod http://127.0.0.1:8790/health
$h = @{ Authorization = "Bearer $env:SENTINEL_DIAG_TOKEN" }
Invoke-RestMethod http://127.0.0.1:8790/status   -Headers $h
Invoke-RestMethod http://127.0.0.1:8790/coverage -Headers $h
Invoke-RestMethod http://127.0.0.1:8790/alerts/recent?limit=10 -Headers $h
```

Direct CLI equivalents (they probe adapters and exit):

```powershell
node C:\ProgramData\Sentinel\bin\sentinel.cjs status   --config C:\ProgramData\Sentinel\config.json
node C:\ProgramData\Sentinel\bin\sentinel.cjs coverage --config C:\ProgramData\Sentinel\config.json
node C:\ProgramData\Sentinel\bin\sentinel.cjs verify   --config C:\ProgramData\Sentinel\config.json
node C:\ProgramData\Sentinel\bin\sentinel.cjs rules    --config C:\ProgramData\Sentinel\config.json
```

## 5. Validation and reboot test

Run the harness first. It captures adapter states, real Windows samples and chain
verification into `C:\ProgramData\Sentinel\validation\<timestamp>\`.

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\validate.ps1 -TestListener -RestartService
```

Then perform the actual reboot test:

```powershell
Restart-Computer -Force
# after logon, in an elevated shell:
.\validate.ps1 -RecoveryCheck
```

The harness does not reboot for you. `-RecoveryCheck` compares the evidence
sequence with the previous report and re-verifies the chain.

Manual equivalents are still available:

```powershell
.\control.ps1 -Action status
.\control.ps1 -Action verify
```

Expected after reboot:

- Task state `Running`, health endpoint reachable.
- `Chain valid: True` and the sequence number continues from before the reboot.
- No duplicate `NEW_LISTENER` alert for ports that existed before the reboot.
- Any queued webhook alerts are delivered once the receiver is reachable.

A full reboot test requires an actual Windows host. It is not executed by the
Linux test suite; see `docs\VERIFICATION.md` and `docs\WINDOWS-VALIDATION.md`.

## 6. Uninstall

Preserve evidence (default):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\uninstall.ps1
```

Remove program files but keep evidence:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\uninstall.ps1 -RemoveInstall
```

Remove everything, including evidence, only with explicit confirmation flags:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\uninstall.ps1 -RemoveInstall -RemoveData -Force
```

Before deleting evidence, copy the `state\` directory and record
`node bin\sentinel.cjs verify` output for the audit record. Uninstalling is not
a secure erase; treat deleted evidence as gone.

## 7. Configuration notes

- `adapters.http_access.path` must point at a JSONL access log written by an
  instrumented app or reverse proxy. See `sentinel/integrations/http-middleware.cjs`.
- `adapters.host_security.enabled` is `false` by default because Security log
  access requires explicit authorization. Enable it only on hosts you administer.
  LocalService usually cannot read the Security log; use a dedicated account in
  Event Log Readers and verify with `control.ps1 -Action coverage`. Sentinel reports
  `UNAVAILABLE` instead of pretending the source is covered.
- `adapters.host_process.mode` is `auto`: uses 4688 when process-creation
  auditing is enabled, otherwise a CIM snapshot diff (misses short-lived processes).
- `adapters.db_audit.path`, `adapters.proxy_log.path` and `adapters.webflow.log_path`
  read exported JSONL. No database driver or cloud API credential is used.
- `alerts.webhook.url` must be HTTPS unless it is a loopback receiver with
  `allow_insecure_loopback: true`. Payloads are HMAC-SHA256 signed.
- `actions.enabled` stays `false`. Enabling it also requires
  `detection.mode: "respond"`, configured target URLs, and leaves `dry_run: true`
  unless deliberately changed.

## 8. Troubleshooting

| Symptom | Check |
|---|---|
| Task registered but not running | `Get-ScheduledTaskInfo`; last result `0x1` = bad arguments, `0x2` = file not found. Run the CLI command from the task action manually. |
| `coverage` shows Windows adapters UNAVAILABLE | Confirm the host is Windows, the task account can read the event log, and `host_process.mode` matches the audit policy. |
| Security adapter UNAVAILABLE | Process is not elevated or the account is not in Event Log Readers; 4625/4672 also require the matching audit subcategory. |
| No HTTP events | `adapters.http_access.path` empty, file missing, or the emitter is not writing JSONL. `coverage` reports which. |
| Webhook never delivers | `dispatcher.status` is `UNAVAILABLE` when the URL is empty, not HTTPS, or the signing secret env var is absent. `alerts.queue.jsonl` retains undelivered alerts. |
| Chain verification fails | Stop the service, preserve `state\`, inspect `MISSING_HISTORY`/`HASH_MISMATCH` output, do not delete files. |
| High memory | Lower `store.max_bytes`, `detection.window_ms`, or adapter polling intervals; see `docs\VERIFICATION.md`. |

## 9. Files created

```
C:\ProgramData\Sentinel\
  bin\sentinel.cjs
  engine\...
  sentinel\...
  config.json
  logs\sentinel.log        (operational JSON logs, 10MB rotation)
  state\
    events-000001.jsonl    (hash-chained evidence)
    retention.json         (retention anchor)
    alerts.queue.jsonl     (durable webhook queue)
    runtime.json           (adapter cursors, baseline, recent alerts)
```
