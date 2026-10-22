<#
.SYNOPSIS
  Runs the Sentinel validation checklist on a Windows host and writes an evidence bundle.

.DESCRIPTION
  Captures real adapter states, environment facts, Windows event samples and a
  hash-chain verification, then optionally exercises listener detection and a
  service restart. Every check is labelled PASS, FAIL, SKIP or INFO. Adapters
  that are UNAVAILABLE are reported as such, never as covered.

  This script does not reboot the host. After a manual reboot, run it again with
  -RecoveryCheck to compare the evidence sequence with the previous report.

.PARAMETER TestListener
  Opens a temporary loopback TCP listener, waits for the configured listener
  poll, and checks for a NEW_LISTENER alert for that exact port. The listener is
  closed in a finally block. This creates one real low-severity alert.

.PARAMETER RestartService
  Stops and starts the scheduled task, then verifies chain continuity and that
  known listeners were not re-alerted.

.PARAMETER RecoveryCheck
  Compares this run with the previous report in the validation directory. Use
  after a reboot.

.EXAMPLE
  .\validate.ps1 -TestListener

.EXAMPLE
  .\validate.ps1 -RestartService

.EXAMPLE
  .\validate.ps1 -RecoveryCheck
#>
[CmdletBinding()]
param(
  [string]$InstallDir,
  [string]$TaskName = 'SentinelDataAccessMonitor',
  [string]$OutputDir,
  [switch]$SkipServiceStart,
  [switch]$TestListener,
  [switch]$RestartService,
  [switch]$RecoveryCheck
)

$ErrorActionPreference = 'Stop'

function Fail([string]$Message, [int]$Code) {
  [Console]::Error.WriteLine($Message)
  exit $Code
}

function Write-JsonFile {
  param($Object, [string]$Path)
  $Object | ConvertTo-Json -Depth 12 | Set-Content -Path $Path -Encoding UTF8
}

function Wait-Health {
  param([int]$Port, [int]$Seconds)
  $deadline = (Get-Date).AddSeconds($Seconds)
  while ((Get-Date) -lt $deadline) {
    try {
      $res = Invoke-RestMethod -Method Get -Uri ("http://127.0.0.1:{0}/health" -f $Port) -TimeoutSec 3
      if ($res -and $res.status) { return $res }
    } catch {
      Start-Sleep -Seconds 2
    }
  }
  return $null
}

if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
  [Console]::Error.WriteLine("validate.ps1 requires Windows. Current platform: " + [System.Environment]::OSVersion.Platform)
  exit 2
}

if (-not $InstallDir) {
  if ($env:ProgramData) { $InstallDir = Join-Path $env:ProgramData 'Sentinel' }
  else { $InstallDir = Join-Path $env:USERPROFILE 'Sentinel' }
}

$node = Get-Command node.exe -ErrorAction SilentlyContinue
if (-not $node) { Fail 'node.exe not found on PATH. Install Node.js 18+ first.' 2 }

$cli = Join-Path $InstallDir 'bin\sentinel.cjs'
$config = Join-Path $InstallDir 'config.json'
if (-not (Test-Path $cli)) { Fail "Sentinel CLI not found at $cli. Run install.ps1 first." 2 }
if (-not (Test-Path $config)) { Fail "Sentinel config not found at $config." 2 }

$cfg = Get-Content -Path $config -Raw | ConvertFrom-Json
$port = 8790
if ($cfg.diagnostics.port) { $port = [int]$cfg.diagnostics.port }
$listenerInterval = 30000
if ($cfg.adapters.host_listeners.poll_interval_ms) { $listenerInterval = [int]$cfg.adapters.host_listeners.poll_interval_ms }

if (-not $OutputDir) {
  $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
  $OutputDir = Join-Path $InstallDir ('validation\' + $stamp)
}
$samplesDir = Join-Path $OutputDir 'samples'
New-Item -ItemType Directory -Force -Path $OutputDir, $samplesDir | Out-Null

$tokenName = 'SENTINEL_DIAG_TOKEN'
if ($cfg.diagnostics.token_env) { $tokenName = [string]$cfg.diagnostics.token_env }
$diagToken = $null
try {
  $diagToken = [Environment]::GetEnvironmentVariable($tokenName)
  if (-not $diagToken) { $diagToken = [Environment]::GetEnvironmentVariable($tokenName, 'Machine') }
  if (-not $diagToken) { $diagToken = [Environment]::GetEnvironmentVariable($tokenName, 'User') }
} catch { $diagToken = $null }
$headers = @{}
if ($diagToken) { $headers['Authorization'] = 'Bearer ' + $diagToken }

$os = $null
try { $os = Get-CimInstance Win32_OperatingSystem } catch { }
$elevated = $false
try {
  $elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { }

$checks = New-Object System.Collections.ArrayList
function Add-Check {
  param([string]$Name, [string]$Status, [string]$Detail)
  [void]$checks.Add([pscustomobject]@{ name = $Name; status = $Status; detail = $Detail })
}

# 1. Read-only environment capture.
$preflightPath = Join-Path $OutputDir 'preflight.json'
try {
  & (Join-Path $PSScriptRoot 'preflight.ps1') -OutputPath $preflightPath -InstallDir $InstallDir -TaskName $TaskName | Out-Null
  if (Test-Path $preflightPath) { Add-Check 'preflight' 'PASS' 'environment report captured' }
  else { Add-Check 'preflight' 'FAIL' 'preflight.ps1 produced no report' }
} catch {
  Add-Check 'preflight' 'FAIL' $_.Exception.Message
}

# 2. Service state.
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
$taskInfo = $null
if ($task) {
  try { $taskInfo = Get-ScheduledTaskInfo -TaskName $TaskName } catch { $taskInfo = $null }
}
$runningNode = @(Get-CimInstance Win32_Process -Filter "Name = 'node.exe'" -ErrorAction SilentlyContinue |
  Where-Object { $_.CommandLine -like '*sentinel.cjs*' })

$health = $null
$startedByHarness = $false
if ($runningNode.Count -gt 0) {
  $health = Wait-Health -Port $port -Seconds 10
  if (-not $health) {
    Add-Check 'service_start' 'FAIL' 'service process exists but /health is unreachable'
  } else {
    Add-Check 'service_start' 'INFO' 'using an already-running service; task was not started'
  }
} elseif ($task -and -not $SkipServiceStart) {
  Start-ScheduledTask -TaskName $TaskName
  $startedByHarness = $true
  $health = Wait-Health -Port $port -Seconds 60
  if (-not $health) {
    Add-Check 'service_start' 'FAIL' 'task started but /health did not become ready within 60s'
    $partial = [ordered]@{
      schema = 'sentinel.windows-validation/1'
      generated_at = (Get-Date).ToUniversalTime().ToString('o')
      error = 'service_start_failed'
      install_dir = $InstallDir
      config = $config
      checks = @($checks)
      remedy = 'Run control.ps1 -Action logs; check the task action and config-check output.'
    }
    Write-JsonFile -Object $partial -Path (Join-Path $OutputDir 'report.json')
    Write-Output ('VALIDATION FAILED: service did not become ready. Report: ' + (Join-Path $OutputDir 'report.json'))
    exit 3
  }
  Add-Check 'service_start' 'PASS' ('task started, /health ready on 127.0.0.1:' + $port)
} else {
  Add-Check 'service_start' 'INFO' 'no running service; using one-shot CLI collection'
}

$useHttp = $false
if ($health) { $useHttp = $true }

# Local diagnostics are loopback-only but authenticated whenever the configured
# token variable holds a value. Without one, HTTP `/coverage` and `/alerts`
# return 401, so fall back to the read-only CLI for coverage instead of
# reporting a false failure. HTTP-only checks are skipped, not faked.
$httpAuthorized = $useHttp -and [bool]$diagToken
if ($useHttp -and -not $diagToken) {
  Add-Check 'diagnostics_token' 'SKIP' ('no value for ' + $tokenName + '; HTTP checks skipped, coverage read via CLI')
} elseif ($httpAuthorized) {
  Add-Check 'diagnostics_token' 'PASS' ('token found for ' + $tokenName)
}

# 3. Coverage matrix.
$coverage = $null
try {
  if ($httpAuthorized) {
    $coverage = Invoke-RestMethod -Method Get -Uri ("http://127.0.0.1:{0}/coverage" -f $port) -Headers $headers -TimeoutSec 15
  } else {
    $raw = & $node.Source $cli coverage --config $config --json | Out-String
    if ($LASTEXITCODE -ne 0) { throw 'coverage command failed' }
    $coverage = $raw | ConvertFrom-Json
  }
  Write-JsonFile -Object $coverage -Path (Join-Path $OutputDir 'coverage.json')
  $active = @($coverage.adapters | Where-Object { $_.status -eq 'ACTIVE' })
  $unavailable = @($coverage.adapters | Where-Object { $_.status -eq 'UNAVAILABLE' })
  Add-Check 'coverage' 'PASS' ('ACTIVE ' + $active.Count + ', UNAVAILABLE ' + $unavailable.Count + ', NOT_CONFIGURED ' + @($coverage.adapters | Where-Object { $_.status -eq 'NOT_CONFIGURED' }).Count)
} catch {
  Add-Check 'coverage' 'FAIL' $_.Exception.Message
  $coverage = $null
}

# 4. Samples. These may contain host and account identifiers; review before sharing.
$listenerSample = [ordered]@{ captured_at = (Get-Date).ToUniversalTime().ToString('o'); available = $false; error = $null; listeners = @() }
try {
  $conns = Get-NetTCPConnection -State Listen -ErrorAction Stop | Select-Object -First 80
  $procNames = @{}
  Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procNames[[int]$_.Id] = $_.ProcessName }
  $list = @()
  foreach ($c in $conns) {
    $owner = [int]$c.OwningProcess
    $name = $null
    if ($procNames.ContainsKey($owner)) { $name = $procNames[$owner] }
    $list += [pscustomobject]@{ address = [string]$c.LocalAddress; port = [int]$c.LocalPort; pid = $owner; process = $name }
  }
  $listenerSample.listeners = $list
  $listenerSample.available = $true
} catch { $listenerSample.error = $_.Exception.Message }
Write-JsonFile -Object $listenerSample -Path (Join-Path $samplesDir 'listeners.json')

$processSample = [ordered]@{ captured_at = (Get-Date).ToUniversalTime().ToString('o'); available = $false; error = $null; processes = @() }
try {
  $processes = Get-CimInstance Win32_Process -ErrorAction Stop |
    Sort-Object CreationDate -Descending |
    Select-Object -First 40 ProcessId, ParentProcessId, Name, ExecutablePath, CreationDate
  $processSample.processes = @($processes)
  $processSample.available = $true
} catch { $processSample.error = $_.Exception.Message }
Write-JsonFile -Object $processSample -Path (Join-Path $samplesDir 'processes.json')

$securitySample = [ordered]@{ captured_at = (Get-Date).ToUniversalTime().ToString('o'); available = $false; error = $null; events = @() }
try {
  $since = (Get-Date).AddHours(-24)
  $events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = @(4625, 4688, 4672); StartTime = $since } -MaxEvents 15 -ErrorAction Stop
  $out = @()
  foreach ($e in $events) {
    $xml = [xml]$e.ToXml()
    $data = @{}
    foreach ($n in $xml.Event.EventData.Data) { $data[[string]$n.Name] = [string]$n.'#text' }
    $out += [pscustomobject]@{
      event_id = $e.Id
      time_utc = $e.TimeCreated.ToUniversalTime().ToString('o')
      target_user = $data['TargetUserName']
      subject_user = $data['SubjectUserName']
      source_ip = $data['IpAddress']
      process = $data['NewProcessName']
      logon_type = $data['LogonType']
    }
  }
  $securitySample.events = $out
  $securitySample.available = $true
} catch { $securitySample.error = $_.Exception.Message }
Write-JsonFile -Object $securitySample -Path (Join-Path $samplesDir 'security.json')

$defenderSample = [ordered]@{ captured_at = (Get-Date).ToUniversalTime().ToString('o'); available = $false; error = $null; events = @() }
try {
  $events = Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -MaxEvents 10 -ErrorAction Stop |
    Where-Object { $_.Id -eq 1116 -or $_.Id -eq 1117 -or $_.Id -eq 5007 }
  $out = @()
  foreach ($e in $events) {
    $msg = [string]$e.Message
    if ($msg.Length -gt 240) { $msg = $msg.Substring(0, 240) }
    $out += [pscustomobject]@{ event_id = $e.Id; time_utc = $e.TimeCreated.ToUniversalTime().ToString('o'); message = $msg }
  }
  $defenderSample.events = $out
  $defenderSample.available = $true
} catch { $defenderSample.error = $_.Exception.Message }
Write-JsonFile -Object $defenderSample -Path (Join-Path $samplesDir 'defender.json')

# 5. Chain verification before optional mutations.
$verifyRaw = & $node.Source $cli verify --config $config --json | Out-String
$verifyExit = $LASTEXITCODE
$verify = $null
try { $verify = $verifyRaw | ConvertFrom-Json } catch { }
Write-JsonFile -Object ([ordered]@{ exit_code = $verifyExit; result = $verify }) -Path (Join-Path $OutputDir 'verify-before.json')
if ($verify -and $verify.valid -and $verify.empty_store) {
  Add-Check 'chain_before' 'SKIP' 'no evidence records yet; there is no chain to verify'
} elseif ($verify -and $verify.valid -and [int]$verify.records -gt 0) {
  Add-Check 'chain_before' 'PASS' ('records=' + $verify.records + ' last_seq=' + $verify.last_seq)
} else {
  Add-Check 'chain_before' 'FAIL' ('chain verification exit=' + $verifyExit)
}

# 6. Listener detection test.
$listenerTest = [ordered]@{ status = 'SKIP'; port = $null; detail = 'not requested'; alert_id = $null }
$listener = $null
if ($TestListener -and $useHttp -and -not $diagToken) {
  $listenerTest.status = 'SKIP'
  $listenerTest.detail = 'requires the diagnostics token in ' + $tokenName + ' to read /alerts/recent'
  Add-Check 'listener_detection' 'SKIP' $listenerTest.detail
  Write-JsonFile -Object $listenerTest -Path (Join-Path $samplesDir 'listener-test.json')
} elseif ($TestListener) {
  try {
    if (-not $useHttp) {
      $baselineRaw = & $node.Source $cli once --config $config --json --quiet | Out-String
      $baseline = $baselineRaw | ConvertFrom-Json
      if ($baseline.stats.alerts -gt 0) {
        Add-Check 'listener_baseline' 'INFO' ('baseline cycle produced ' + $baseline.stats.alerts + ' unrelated alert(s)')
      }
    }
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $testPort = [int]$listener.LocalEndpoint.Port
    $listenerTest.port = $testPort
    Start-Sleep -Seconds 3

    $match = $null
    if ($useHttp) {
      $waitMs = [Math]::Min(($listenerInterval * 1.5) + 10000, 180000)
      Start-Sleep -Milliseconds $waitMs
      $recent = Invoke-RestMethod -Method Get -Uri ("http://127.0.0.1:{0}/alerts/recent?limit=50" -f $port) -Headers $headers -TimeoutSec 15
      $alerts = @($recent.alerts)
      $match = $alerts | Where-Object { $_.rule_id -eq 'NEW_LISTENER' -and $_.evidence.port -eq $testPort } | Select-Object -First 1
    } else {
      $runRaw = & $node.Source $cli once --config $config --json --quiet | Out-String
      $run = $runRaw | ConvertFrom-Json
      Write-JsonFile -Object $run -Path (Join-Path $OutputDir 'once-listener.json')
      $alerts = @($run.recent_alerts)
      $match = $alerts | Where-Object { $_.rule_id -eq 'NEW_LISTENER' -and $_.evidence.port -eq $testPort } | Select-Object -First 1
    }

    if ($match) {
      $listenerTest.status = 'PASS'
      $listenerTest.alert_id = $match.alert_id
      $listenerTest.detail = 'NEW_LISTENER alert captured for the temporary loopback port'
      Add-Check 'listener_detection' 'PASS' ('port ' + $testPort + ' detected')
    } else {
      $listenerTest.status = 'FAIL'
      $hostListener = $null
      if ($coverage) { $hostListener = $coverage.adapters | Where-Object { $_.id -eq 'host.listeners' } | Select-Object -First 1 }
      if ($hostListener) {
        $listenerTest.detail = 'no alert; adapter status=' + $hostListener.status + ' reason=' + $hostListener.reason
      } else {
        $listenerTest.detail = 'no alert and no coverage record for host.listeners'
      }
      Add-Check 'listener_detection' 'FAIL' $listenerTest.detail
    }
    Write-JsonFile -Object $listenerTest -Path (Join-Path $samplesDir 'listener-test.json')
  } catch {
    $listenerTest.status = 'FAIL'
    $listenerTest.detail = $_.Exception.Message
    Add-Check 'listener_detection' 'FAIL' $_.Exception.Message
  } finally {
    if ($listener) {
      try { $listener.Stop() } catch { }
    }
  }
} else {
  Add-Check 'listener_detection' 'SKIP' 'use -TestListener to exercise it'
}

# 7. Service restart continuity.
$restartTest = [ordered]@{ status = 'SKIP'; detail = 'not requested'; before_seq = $null; after_seq = $null; duplicate_listener_alerts = $null }
if ($RestartService) {
  if (-not $task) {
    $restartTest.detail = 'scheduled task not installed'
    Add-Check 'service_restart' 'SKIP' $restartTest.detail
  } elseif ($useHttp -and -not $diagToken) {
    $restartTest.detail = 'requires the diagnostics token in ' + $tokenName + ' to check duplicate alerts'
    Add-Check 'service_restart' 'SKIP' $restartTest.detail
  } else {
    try {
      $knownPorts = @()
      try {
        $knownPorts = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object { [int]$_.LocalPort })
      } catch { }
      $beforeSeq = $null
      if ($verify) { $beforeSeq = $verify.last_seq }
      $restartAt = (Get-Date).ToUniversalTime()
      Stop-ScheduledTask -TaskName $TaskName
      Start-Sleep -Seconds 3
      Start-ScheduledTask -TaskName $TaskName
      $healthAfter = Wait-Health -Port $port -Seconds 60
      if (-not $healthAfter) { throw 'service did not become ready after restart' }
      $afterRaw = & $node.Source $cli verify --config $config --json | Out-String
      $after = $afterRaw | ConvertFrom-Json
      $duplicates = 0
      $recent = Invoke-RestMethod -Method Get -Uri ("http://127.0.0.1:{0}/alerts/recent?limit=100" -f $port) -Headers $headers -TimeoutSec 15
      foreach ($a in @($recent.alerts)) {
        if ($a.rule_id -ne 'NEW_LISTENER') { continue }
        if ([datetime]$a.created_at -lt $restartAt) { continue }
        if ($knownPorts -contains [int]$a.evidence.port) { $duplicates++ }
      }
      $restartTest.before_seq = $beforeSeq
      $restartTest.after_seq = $after.last_seq
      $restartTest.duplicate_listener_alerts = $duplicates
      if ($after.valid -and ($null -eq $beforeSeq -or $after.last_seq -ge $beforeSeq) -and $duplicates -eq 0) {
        $restartTest.status = 'PASS'
        $restartTest.detail = 'chain valid, sequence continued, no duplicate listener alerts'
        Add-Check 'service_restart' 'PASS' $restartTest.detail
      } else {
        $restartTest.status = 'FAIL'
        $restartTest.detail = 'valid=' + $after.valid + ' before_seq=' + $beforeSeq + ' after_seq=' + $after.last_seq + ' duplicates=' + $duplicates
        Add-Check 'service_restart' 'FAIL' $restartTest.detail
      }
    } catch {
      $restartTest.status = 'FAIL'
      $restartTest.detail = $_.Exception.Message
      Add-Check 'service_restart' 'FAIL' $_.Exception.Message
    }
  }
} else {
  Add-Check 'service_restart' 'SKIP' 'use -RestartService to exercise it'
}
Write-JsonFile -Object $restartTest -Path (Join-Path $samplesDir 'restart-test.json')

# 8. Recovery comparison after a manual reboot.
$recovery = [ordered]@{ status = 'SKIP'; detail = 'use -RecoveryCheck after a reboot'; previous_seq = $null; current_seq = $null }
if ($RecoveryCheck) {
  $previousPath = Join-Path (Split-Path -Parent $OutputDir) 'last-report.json'
  if (Test-Path $previousPath) {
    try {
      $prev = Get-Content -Path $previousPath -Raw | ConvertFrom-Json
      $currentRaw = & $node.Source $cli verify --config $config --json | Out-String
      $current = $currentRaw | ConvertFrom-Json
      $recovery.previous_seq = $prev.verify.last_seq
      $recovery.current_seq = $current.last_seq
      if ($current.valid -and ($null -eq $prev.verify.last_seq -or $current.last_seq -ge $prev.verify.last_seq)) {
        $recovery.status = 'PASS'
        $recovery.detail = 'chain valid and sequence did not move backwards'
        Add-Check 'recovery' 'PASS' $recovery.detail
      } else {
        $recovery.status = 'FAIL'
        $recovery.detail = 'chain or sequence regression detected'
        Add-Check 'recovery' 'FAIL' $recovery.detail
      }
    } catch {
      $recovery.status = 'FAIL'
      $recovery.detail = $_.Exception.Message
      Add-Check 'recovery' 'FAIL' $_.Exception.Message
    }
  } else {
    $recovery.detail = 'no previous report at ' + $previousPath
    Add-Check 'recovery' 'SKIP' $recovery.detail
  }
} else {
  Add-Check 'recovery' 'SKIP' 'use -RecoveryCheck after a reboot'
}

# 9. Final report.
$activeAdapters = @()
$unavailableAdapters = @()
$notConfigured = @()
if ($coverage) {
  $activeAdapters = @($coverage.adapters | Where-Object { $_.status -eq 'ACTIVE' })
  $unavailableAdapters = @($coverage.adapters | Where-Object { $_.status -eq 'UNAVAILABLE' })
  $notConfigured = @($coverage.adapters | Where-Object { $_.status -eq 'NOT_CONFIGURED' })
}

$osCaption = $null
$osVersion = $null
$osBuild = $null
if ($os) {
  $osCaption = $os.Caption
  $osVersion = $os.Version
  $osBuild = $os.BuildNumber
}
$taskStateValue = $null
$taskLastResultValue = $null
$taskLastRunValue = $null
if ($task) {
  $taskStateValue = $task.State
  if ($taskInfo) {
    $taskLastResultValue = $taskInfo.LastTaskResult
    $taskLastRunValue = $taskInfo.LastRunTime
  }
}
$coverageSummary = $null
$blindSpots = @()
if ($coverage) {
  $coverageSummary = $coverage.summary
  $blindSpots = @($coverage.blind_spots)
}
$nodeVersion = (& $node.Source --version)

$report = [ordered]@{
  schema = 'sentinel.windows-validation/1'
  generated_at = (Get-Date).ToUniversalTime().ToString('o')
  host = [ordered]@{
    computer_name = $env:COMPUTERNAME
    os = $osCaption
    version = $osVersion
    build = $osBuild
    architecture = $env:PROCESSOR_ARCHITECTURE
    powershell = $PSVersionTable.PSVersion.ToString()
    elevated = $elevated
    identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
  }
  runtime = [ordered]@{ node = $nodeVersion; cli = $cli; config = $config }
  task = [ordered]@{
    name = $TaskName
    installed = [bool]$task
    state = $taskStateValue
    last_result = $taskLastResultValue
    last_run = $taskLastRunValue
    started_by_harness = $startedByHarness
  }
  service = [ordered]@{ health = $health; used_http = $useHttp; http_authorized = $httpAuthorized }
  coverage = [ordered]@{
    summary = $coverageSummary
    active = @($activeAdapters | ForEach-Object { $_.id })
    unavailable = @($unavailableAdapters | ForEach-Object { [pscustomobject]@{ id = $_.id; reason = $_.reason } })
    not_configured = @($notConfigured | ForEach-Object { [pscustomobject]@{ id = $_.id; reason = $_.reason } })
    blind_spots = $blindSpots
  }
  verify = $verify
  checks = @($checks)
  listener_test = $listenerTest
  restart_test = $restartTest
  recovery = $recovery
  samples = [ordered]@{
    preflight = 'preflight.json'
    coverage = 'coverage.json'
    listeners = 'samples/listeners.json'
    processes = 'samples/processes.json'
    security = 'samples/security.json'
    defender = 'samples/defender.json'
    listener_test = 'samples/listener-test.json'
    restart_test = 'samples/restart-test.json'
  }
  limitations = @(
    'A reboot is not performed by this script. Reboot manually, then run -RecoveryCheck.',
    'UNAVAILABLE means the source could not be read; it is not coverage.',
    'Samples can contain host names, account names and process paths. Review before sharing.',
    'No database, CDN/WAF, Webflow or other third-party API was contacted.',
    'A PASS on listener_detection proves the host listener path; it does not prove API or database coverage.'
  )
}

$reportPath = Join-Path $OutputDir 'report.json'
Write-JsonFile -Object $report -Path $reportPath
Write-JsonFile -Object $report -Path (Join-Path (Split-Path -Parent $OutputDir) 'last-report.json')

Write-Output ''
Write-Output ('VALIDATION ' + $OutputDir)
Write-Output ('host: ' + $env:COMPUTERNAME + ' | elevated=' + $elevated + ' | node=' + $nodeVersion)
Write-Output ('task: installed=' + [bool]$task + ' state=' + $report.task.state + ' last_result=' + $report.task.last_result)
Write-Output ('adapters: ' + $activeAdapters.Count + ' ACTIVE, ' + $unavailableAdapters.Count + ' UNAVAILABLE, ' + $notConfigured.Count + ' NOT_CONFIGURED')
if ($activeAdapters.Count -gt 0) { Write-Output ('  ACTIVE: ' + (($activeAdapters | ForEach-Object { $_.id }) -join ', ')) }
if ($unavailableAdapters.Count -gt 0) {
  foreach ($a in $unavailableAdapters) { Write-Output ('  UNAVAILABLE: ' + $a.id + ' - ' + $a.reason) }
}
foreach ($c in @($checks)) { Write-Output ('check ' + $c.name + ': ' + $c.status + ' - ' + $c.detail) }
if ($verify) { Write-Output ('chain: valid=' + $verify.valid + ' records=' + $verify.records + ' last_seq=' + $verify.last_seq) }
Write-Output ('report: ' + $reportPath)
Write-Output ''

if (-not $verify) {
  Write-Output 'RESULT: FAILED (chain could not be verified). Preserve the state directory and investigate.'
  exit 1
}
if (-not $verify.valid) {
  Write-Output 'RESULT: FAILED (evidence chain invalid). Preserve the state directory and investigate.'
  exit 1
}
Write-Output 'RESULT: report written. Review UNAVAILABLE adapters and blind spots before treating coverage as complete.'
exit 0
