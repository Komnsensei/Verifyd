<#
.SYNOPSIS
  Installs the Sentinel data-access monitor on Windows.

.DESCRIPTION
  Copies the engine and CLI to an install directory, prepares a config and
  state directory with restrictive ACLs, and registers a scheduled task that
  starts the service at boot and restarts it on failure.

  The service starts in detection-only mode. No firewall rule is created and
  no credential is collected by this script.

.PARAMETER InstallDir
  Target directory. Default: C:\ProgramData\Sentinel

.PARAMETER ConfigPath
  Optional existing config.json to deploy. When omitted, config.example.json is
  copied and its state_dir is pointed at <InstallDir>\state.

.PARAMETER Account
  Account for the scheduled task. Default: NT AUTHORITY\LocalService, which is
  least-privilege for this service. Use -Credential for a password-based service
  account and add it to the local "Event Log Readers" group with
  -GrantEventLogRead if Security log access is needed. Security-log and Defender
  adapters may additionally require a more privileged account; coverage reports
  UNAVAILABLE rather than pretending.

.PARAMETER Start
  Start the task after registration.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Start

.EXAMPLE
  $cred = Get-Credential
  powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 `
    -Account $cred.UserName -Credential $cred -GrantEventLogRead -Start
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
  [string]$InstallDir = (Join-Path $env:ProgramData 'Sentinel'),
  [string]$ConfigPath,
  [string]$TaskName = 'SentinelDataAccessMonitor',
  [string]$Account = 'NT AUTHORITY\LocalService',
  [System.Management.Automation.PSCredential]$Credential,
  [switch]$GrantEventLogRead,
  [switch]$Start,
  [switch]$Force
)

$ErrorActionPreference = 'Stop'

function Fail([string]$Message) {
  Write-Error $Message
  exit 1
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Fail 'Run this script from an elevated PowerShell session.' }

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Test-Path (Join-Path $repoRoot 'bin\sentinel.cjs'))) {
  Fail "Cannot locate the repository root from $PSScriptRoot. Expected bin\sentinel.cjs under $repoRoot."
}

$node = Get-Command node.exe -ErrorAction SilentlyContinue
if (-not $node) { Fail 'Node.js 18 or newer is required and node.exe was not found on PATH.' }
$nodeVersion = (& $node.Source --version).TrimStart('v')
if ([int]($nodeVersion.Split('.')[0]) -lt 18) { Fail "Node.js 18+ required; found $nodeVersion." }

$existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existing -and -not $Force) {
  Fail "Scheduled task '$TaskName' already exists. Re-run with -Force to replace it."
}

$stateDir = Join-Path $InstallDir 'state'
$logsDir = Join-Path $InstallDir 'logs'
$configDest = Join-Path $InstallDir 'config.json'

New-Item -ItemType Directory -Force -Path $InstallDir, $stateDir, $logsDir | Out-Null

foreach ($item in @('engine', 'sentinel', 'bin', 'package.json')) {
  $src = Join-Path $repoRoot $item
  if (-not (Test-Path $src)) { Fail "Missing source item: $src" }
  Copy-Item -Path $src -Destination $InstallDir -Recurse -Force
}

if ($ConfigPath) {
  if (-not (Test-Path $ConfigPath)) { Fail "Config not found: $ConfigPath" }
  Copy-Item -Path $ConfigPath -Destination $configDest -Force
  Write-Output "config: copied $ConfigPath"
} elseif (-not (Test-Path $configDest)) {
  $example = Join-Path $InstallDir 'sentinel\config.example.json'
  $cfg = Get-Content -Path $example -Raw | ConvertFrom-Json
  $cfg.service.state_dir = $stateDir
  $configJson = $cfg | ConvertTo-Json -Depth 20
  [System.IO.File]::WriteAllText($configDest, $configJson, (New-Object System.Text.UTF8Encoding($false)))
  Write-Output "config: created $configDest from config.example.json"
} else {
  Write-Output "config: kept existing $configDest"
}

# The task account must be able to write evidence even when it is not SYSTEM.
$member = if ($Credential) { $Credential.UserName } else { $Account }
try {
  $accountSid = (New-Object System.Security.Principal.NTAccount($member)).Translate([System.Security.Principal.SecurityIdentifier]).Value
} catch {
  Fail "Cannot resolve account '$member' to a SID. Use DOMAIN\user or a well-known account name."
}

# Restrict evidence and configuration using SIDs so the ACLs apply on
# non-English Windows installations too. Config is read-only for the service.
& icacls.exe $InstallDir /grant "*${accountSid}:(OI)(CI)RX" | Out-Null
& icacls.exe $stateDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "*${accountSid}:(OI)(CI)F" | Out-Null
& icacls.exe $logsDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "*${accountSid}:(OI)(CI)F" | Out-Null
& icacls.exe $configDest /inheritance:r /grant:r '*S-1-5-18:R' '*S-1-5-32-544:F' '*S-1-5-32-545:R' "*${accountSid}:R" | Out-Null

$configCheckArgs = @((Join-Path $InstallDir 'bin\sentinel.cjs'), 'config-check', '--config', $configDest)
& $node.Source @configCheckArgs
if ($LASTEXITCODE -ne 0) { Fail "Configuration validation failed. Fix $configDest before starting the service." }

$action = New-ScheduledTaskAction `
  -Execute $node.Source `
  -Argument ('"{0}" run --config "{1}" --log-file "{2}"' -f (Join-Path $InstallDir 'bin\sentinel.cjs'), $configDest, (Join-Path $logsDir 'sentinel.log')) `
  -WorkingDirectory $InstallDir

$trigger = New-ScheduledTaskTrigger -AtStartup

$settings = New-ScheduledTaskSettingsSet `
  -StartWhenAvailable `
  -AllowStartIfOnBatteries `
  -DontStopIfGoingOnBatteries `
  -RestartCount 999 `
  -RestartInterval (New-TimeSpan -Minutes 1) `
  -ExecutionTimeLimit ([TimeSpan]::Zero) `
  -MultipleInstances IgnoreNew

if ($Credential) {
  $principal = New-ScheduledTaskPrincipal -UserId $Credential.UserName -LogonType Password
} else {
  $principal = New-ScheduledTaskPrincipal -UserId $Account -LogonType ServiceAccount
}

Register-ScheduledTask `
  -TaskName $TaskName `
  -Action $action `
  -Trigger $trigger `
  -Settings $settings `
  -Principal $principal `
  -Description 'Sentinel defensive data-access monitoring (detection-only by default)' `
  -Force | Out-Null

if ($GrantEventLogRead) {
  try {
    Add-LocalGroupMember -Group 'Event Log Readers' -Member $member -ErrorAction Stop
    Write-Output "acl: added $member to local group 'Event Log Readers'"
  } catch {
    Write-Warning "Could not add $member to Event Log Readers: $($_.Exception.Message)"
  }
}

if ($Start) {
  Start-ScheduledTask -TaskName $TaskName
  Start-Sleep -Seconds 3
  $info = Get-ScheduledTaskInfo -TaskName $TaskName
  Write-Output "task: $TaskName started (last result $($info.LastTaskResult))"
}

$trayScript = Join-Path $InstallDir 'sentinel\windows\tray.ps1'
$shortcutPath = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Sentinel Status.lnk'
if (Test-Path $trayScript) {
  try {
    $psExe = Join-Path $PSHOME 'powershell.exe'
    if (-not (Test-Path $psExe)) { $psExe = Join-Path $PSHOME 'pwsh.exe' }
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $psExe
    $shortcut.Arguments = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $trayScript + '"'
    $shortcut.WorkingDirectory = $InstallDir
    $shortcut.Description = 'Sentinel data-access monitor status'
    $shortcut.IconLocation = '%SystemRoot%\System32\shell32.dll,77'
    $shortcut.Save()
    Write-Output "shortcut: $shortcutPath"
  } catch {
    Write-Warning "Could not create the Start Menu shortcut: $($_.Exception.Message)"
  }
}

Write-Output ''
Write-Output 'Sentinel installed.'
Write-Output "  install dir : $InstallDir"
Write-Output "  config      : $configDest"
Write-Output "  state       : $stateDir"
Write-Output "  logs        : $(Join-Path $logsDir 'sentinel.log')"
Write-Output "  task        : $TaskName (runs as $member)"
Write-Output ''
Write-Output 'Next steps:'
Write-Output "  1. Edit $configDest and set adapters.http_access.path (and any other sources)."
Write-Output "  2. Set secrets outside this project, for example:"
Write-Output '       [Environment]::SetEnvironmentVariable("SENTINEL_DIAG_TOKEN", "<random>", "Machine")'
Write-Output '       [Environment]::SetEnvironmentVariable("SENTINEL_WEBHOOK_SECRET", "<random>", "Machine")'
Write-Output '  3. Inspect coverage:'
Write-Output "       node `"$InstallDir\bin\sentinel.cjs`" coverage --config `"$configDest`""
Write-Output '  4. Read docs\RUNBOOK.md and docs\COVERAGE.md before enabling response actions.'
