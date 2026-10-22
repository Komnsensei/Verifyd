<#
.SYNOPSIS
  Read-only Windows environment discovery for Sentinel.

.DESCRIPTION
  Collects host, runtime, network, audit-policy and log-channel facts needed to
  decide which monitoring adapters can be ACTIVE. It never reads secret values:
  only whether the documented environment variable names are present.

  Output is JSON on stdout. Nothing is modified.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\preflight.ps1
  powershell -NoProfile -ExecutionPolicy Bypass -File .\preflight.ps1 -OutputPath C:\Temp\sentinel-preflight.json
#>
[CmdletBinding()]
param(
  [string]$OutputPath,
  [string]$InstallDir = (Join-Path $env:ProgramData 'Sentinel'),
  [string]$TaskName = 'SentinelDataAccessMonitor',
  [int]$MaxListeners = 60
)

$ErrorActionPreference = 'Continue'

function Try-Get {
  param([scriptblock]$Block, $Default = $null)
  try { return & $Block } catch { return $Default }
}

$report = [ordered]@{
  generated_at_utc = (Get-Date).ToUniversalTime().ToString('o')
  host = [ordered]@{
    computer_name = $env:COMPUTERNAME
    os = Try-Get { (Get-CimInstance Win32_OperatingSystem).Caption }
    version = Try-Get { (Get-CimInstance Win32_OperatingSystem).Version }
    build = Try-Get { (Get-CimInstance Win32_OperatingSystem).BuildNumber }
    architecture = $env:PROCESSOR_ARCHITECTURE
    powershell = $PSVersionTable.PSVersion.ToString()
    is_elevated = Try-Get {
      ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } $false
    identity = Try-Get { [Security.Principal.WindowsIdentity]::GetCurrent().Name }
  }
  runtime = [ordered]@{
    node = Try-Get { (& node.exe --version 2>$null) } 'absent'
    node_path = Try-Get { (Get-Command node.exe -ErrorAction Stop).Source } $null
    bun = Try-Get { (& bun.exe --version 2>$null) } 'absent'
    git = Try-Get { (& git.exe --version 2>$null) } 'absent'
  }
  disk = [ordered]@{
    install_dir = $InstallDir
    free_bytes = Try-Get {
      $drive = (Split-Path -Qualifier $InstallDir)
      (Get-PSDrive -Name $drive.TrimEnd(':')).Free
    } $null
  }
  scheduled_task = [ordered]@{
    name = $TaskName
    exists = [bool](Try-Get { Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop } $null)
    state = Try-Get { (Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop).State } $null
    last_result = Try-Get { (Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction Stop).LastTaskResult } $null
    last_run = Try-Get { (Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction Stop).LastRunTime } $null
  }
  listening = @()
  audit_policy = [ordered]@{
    process_creation = 'unknown'
    logon = 'unknown'
    object_access = 'unknown'
  }
  logs = [ordered]@{
    security_readable = $false
    security_latest_event = $null
    channels = [ordered]@{}
  }
  defender = [ordered]@{
    available = $false
    real_time_protection = $null
    signatures_age_days = $null
  }
  sentinel = [ordered]@{
    install_dir_exists = (Test-Path $InstallDir)
    config_exists = (Test-Path (Join-Path $InstallDir 'config.json'))
    state_dir_bytes = Try-Get {
      $state = Join-Path $InstallDir 'state'
      if (Test-Path $state) { (Get-ChildItem $state -Recurse -File | Measure-Object Length -Sum).Sum } else { 0 }
    } $null
    running_processes = Try-Get {
      @(Get-CimInstance Win32_Process -Filter "Name = 'node.exe'" |
        Where-Object { $_.CommandLine -like '*sentinel.cjs*' } |
        Select-Object ProcessId, CreationDate)
    } @()
  }
  secret_env_names = [ordered]@{}
}

$listeners = Try-Get {
  Get-NetTCPConnection -State Listen -ErrorAction Stop |
    Select-Object -First $MaxListeners LocalAddress, LocalPort, OwningProcess
} @()
$processNames = @{}
Try-Get { Get-Process | ForEach-Object { $processNames[[int]$_.Id] = $_.ProcessName } } | Out-Null
foreach ($l in @($listeners)) {
  if ($null -eq $l) { continue }
  $pidValue = [int]$l.OwningProcess
  $name = $null
  if ($processNames.ContainsKey($pidValue)) { $name = $processNames[$pidValue] }
  $report.listening += [pscustomobject]@{
    address = [string]$l.LocalAddress
    port = [int]$l.LocalPort
    pid = $pidValue
    process = $name
  }
}

$auditText = Try-Get { (& auditpol.exe /get /category:* 2>$null | Out-String) } ''
if ($auditText -match 'Process Creation[\s\S]{0,400}?Success') { $report.audit_policy.process_creation = 'success' }
elseif ($auditText -match 'Process Creation') { $report.audit_policy.process_creation = 'not-enabled' }
if ($auditText -match 'Logon[\s\S]{0,400}?Success') { $report.audit_policy.logon = 'success' }
elseif ($auditText -match 'Logon') { $report.audit_policy.logon = 'not-enabled' }
if ($auditText -match 'Object Access[\s\S]{0,400}?Success') { $report.audit_policy.object_access = 'success' }
elseif ($auditText -match 'Object Access') { $report.audit_policy.object_access = 'not-enabled' }

$channels = @(
  'Security',
  'System',
  'Application',
  'Microsoft-Windows-Windows Defender/Operational',
  'Microsoft-Windows-Sysmon/Operational',
  'Microsoft-Windows-WMI-Activity/Operational',
  'Microsoft-Windows-DNS-Client/Operational',
  'Microsoft-Windows-PowerShell/Operational'
)
foreach ($channel in $channels) {
  $exists = [bool](Try-Get { Get-WinEvent -ListLog $channel -ErrorAction Stop } $null)
  $report.logs.channels[$channel] = $exists
}

$latest = Try-Get { Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop } $null
if ($latest) {
  $report.logs.security_readable = $true
  $report.logs.security_latest_event = $latest.TimeCreated.ToUniversalTime().ToString('o')
}

$mp = Try-Get { Get-MpComputerStatus -ErrorAction Stop } $null
if ($mp) {
  $report.defender.available = $true
  $report.defender.real_time_protection = [bool]$mp.RealTimeProtectionEnabled
  $report.defender.signatures_age_days = Try-Get {
    [math]::Round(((Get-Date) - $mp.AntivirusSignatureLastUpdated).TotalDays, 1)
  } $null
}

# Presence only. Values are never read or printed.
$secretNames = @(
  'SENTINEL_WEBHOOK_SECRET',
  'SENTINEL_DIAG_TOKEN',
  'SENTINEL_ACTION_SECRET',
  'SENTINEL_SAAS_TOKEN',
  'SENTINEL_SQL_CONNECTION',
  'SENTINEL_ANCHOR_SECRET'
)
foreach ($name in $secretNames) {
  $report.secret_env_names[$name] = [bool](Test-Path "env:$name")
}

$json = $report | ConvertTo-Json -Depth 8
if ($OutputPath) {
  [System.IO.File]::WriteAllText($OutputPath, $json, (New-Object System.Text.UTF8Encoding($false)))
  Write-Output "preflight report written to $OutputPath"
} else {
  Write-Output $json
}
