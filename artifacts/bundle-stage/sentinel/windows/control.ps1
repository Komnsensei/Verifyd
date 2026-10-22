<#
.SYNOPSIS
  Start, stop, inspect or verify a Sentinel installation.

.EXAMPLE
  .\control.ps1 -Action status
  .\control.ps1 -Action verify
  .\control.ps1 -Action logs -Lines 80
#>
[CmdletBinding()]
param(
  [ValidateSet('start', 'stop', 'restart', 'status', 'verify', 'coverage', 'logs', 'health')]
  [string]$Action = 'status',
  [string]$InstallDir = (Join-Path $env:ProgramData 'Sentinel'),
  [string]$TaskName = 'SentinelDataAccessMonitor',
  [int]$Lines = 60
)

$ErrorActionPreference = 'Stop'
$cli = Join-Path $InstallDir 'bin\sentinel.cjs'
$config = Join-Path $InstallDir 'config.json'
$logFile = Join-Path $InstallDir 'logs\sentinel.log'

if (-not (Test-Path $cli)) { Write-Error "Sentinel is not installed at $InstallDir"; exit 2 }
$node = (Get-Command node.exe -ErrorAction SilentlyContinue)
if (-not $node) { Write-Error 'node.exe not found on PATH'; exit 2 }

function Show-Task {
  $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  if (-not $task) {
    Write-Output "task: $TaskName not registered"
    return
  }
  $info = Get-ScheduledTaskInfo -TaskName $TaskName
  Write-Output "task: $TaskName state=$($task.State) last_run=$($info.LastRunTime) last_result=$($info.LastTaskResult)"
}

function Show-Health {
  $port = 8790
  try {
    $cfg = Get-Content $config -Raw | ConvertFrom-Json
    if ($cfg.diagnostics.port) { $port = [int]$cfg.diagnostics.port }
    $bind = '127.0.0.1'
    if ($cfg.diagnostics.bind) { $bind = [string]$cfg.diagnostics.bind }
  } catch {
    Write-Warning "Could not read $config; using defaults."
  }
  $headers = @{}
  if ($env:SENTINEL_DIAG_TOKEN) { $headers['Authorization'] = "Bearer $env:SENTINEL_DIAG_TOKEN" }
  $probeHost = $bind
  if ($bind -eq '0.0.0.0' -or $bind -eq '::') { $probeHost = '127.0.0.1' }
  try {
    $res = Invoke-RestMethod -Method Get -Uri "http://$probeHost`:$port/health" -Headers $headers -TimeoutSec 5
    Write-Output ('health: ' + ($res | ConvertTo-Json -Compress))
  } catch {
    Write-Warning "Health endpoint not reachable at http://$probeHost`:$port/health : $($_.Exception.Message)"
  }
}

switch ($Action) {
  'start' {
    Start-ScheduledTask -TaskName $TaskName
    Start-Sleep -Seconds 2
    Show-Task
    Show-Health
  }
  'stop' {
    Stop-ScheduledTask -TaskName $TaskName
    Write-Output "task: $TaskName stop requested (in-flight evidence writes are flushed by the service)"
    Show-Task
  }
  'restart' {
    Stop-ScheduledTask -TaskName $TaskName
    Start-Sleep -Seconds 2
    Start-ScheduledTask -TaskName $TaskName
    Start-Sleep -Seconds 2
    Show-Task
    Show-Health
  }
  'status' {
    Show-Task
    Show-Health
    & $node.Source $cli status --config $config
  }
  'health' { Show-Health }
  'verify' {
    & $node.Source $cli verify --config $config
    exit $LASTEXITCODE
  }
  'coverage' {
    & $node.Source $cli coverage --config $config
    exit $LASTEXITCODE
  }
  'logs' {
    if (-not (Test-Path $logFile)) { Write-Output "no log file at $logFile"; break }
    Get-Content -Path $logFile -Tail $Lines
  }
}
