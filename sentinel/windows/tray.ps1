<#
.SYNOPSIS
  Sentinel notification-area status window.

.DESCRIPTION
  Runs from the Start Menu shortcut created by setup. Shows service health,
  the ACTIVE/UNAVAILABLE adapter split and the latest alerts without exposing
  the diagnostics token. Use -Once for a text snapshot (no window).

.PARAMETER Once
  Fetch one snapshot, print it to standard output and exit. No WinForms objects
  are created, so this also works in a non-interactive check.

.PARAMETER InstallDir
  Install directory. Defaults to two levels above this script.
#>
[CmdletBinding()]
param(
  [switch]$Once,
  [string]$InstallDir
)

$ErrorActionPreference = 'Stop'

if (-not $InstallDir) {
  $InstallDir = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
}

$configPath = Join-Path $InstallDir 'config.json'
if (-not (Test-Path $configPath)) {
  $msg = 'Sentinel config not found at ' + $configPath + '. Run SETUP-SENTINEL.cmd first.'
  if ($Once) { Write-Error $msg; exit 2 }
  Add-Type -AssemblyName System.Windows.Forms
  [System.Windows.Forms.MessageBox]::Show($msg, 'Sentinel', 'OK', 'Error') | Out-Null
  exit 2
}

$cfg = Get-Content -Path $configPath -Raw | ConvertFrom-Json
$port = 8790
if ($cfg.diagnostics -and $cfg.diagnostics.port) { $port = [int]$cfg.diagnostics.port }
$bind = '127.0.0.1'
if ($cfg.diagnostics -and $cfg.diagnostics.bind) { $bind = [string]$cfg.diagnostics.bind }
if ($bind -eq '0.0.0.0' -or $bind -eq '*') { $bind = '127.0.0.1' }
elseif ($bind -eq '::' -or $bind -eq '::1') { $bind = '[::1]' }
$script:BaseUrl = 'http://' + $bind + ':' + $port

$tokenName = 'SENTINEL_DIAG_TOKEN'
if ($cfg.diagnostics -and $cfg.diagnostics.token_env) { $tokenName = [string]$cfg.diagnostics.token_env }
$script:Token = $null
foreach ($scope in @('Process', 'Machine', 'User')) {
  try {
    $value = [Environment]::GetEnvironmentVariable($tokenName, $scope)
    if ($value) { $script:Token = $value; break }
  } catch { }
}

try { Add-Type -AssemblyName System.Net.Http | Out-Null } catch { }
$script:HttpClient = New-Object System.Net.Http.HttpClient
$script:HttpClient.Timeout = [TimeSpan]::FromSeconds(4)

function Invoke-SentinelGet {
  param([string]$Path)
  $req = $null
  $resp = $null
  try {
    $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, ($script:BaseUrl + $Path))
    if ($script:Token) {
      $req.Headers.Authorization = [System.Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $script:Token)
    }
    $resp = $script:HttpClient.SendAsync($req).GetAwaiter().GetResult()
    $text = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
    $body = $null
    try { $body = $text | ConvertFrom-Json } catch { }
    return [pscustomobject]@{ StatusCode = [int]$resp.StatusCode; Body = $body; Raw = $text }
  } finally {
    if ($resp) { $resp.Dispose() }
    if ($req) { $req.Dispose() }
  }
}

function Get-SentinelState {
  $state = [pscustomobject]@{
    Reachable = $false
    Health = $null
    Status = $null
    Coverage = $null
    Alerts = @()
    Error = $null
    TokenPresent = [bool]$script:Token
    CheckedAt = (Get-Date).ToUniversalTime().ToString('o')
  }
  try {
    $health = Invoke-SentinelGet '/health'
    if ($health.StatusCode -eq 200 -or $health.StatusCode -eq 503) {
      $state.Health = $health.Body
      $state.Reachable = $true
    } else {
      $state.Error = 'health returned HTTP ' + $health.StatusCode
      return $state
    }
  } catch {
    try { $state.Error = $_.Exception.GetBaseException().Message }
    catch { $state.Error = $_.Exception.Message }
    return $state
  }
  if ($script:Token) {
    try { $state.Status = (Invoke-SentinelGet '/status').Body } catch { }
    try { $state.Coverage = (Invoke-SentinelGet '/coverage').Body } catch { }
    try { $state.Alerts = @((Invoke-SentinelGet '/alerts/recent?limit=5').Body.alerts) } catch { }
  }
  return $state
}

function Limit-Text {
  param($Text, [int]$Max = 110)
  if ($null -eq $Text) { return '' }
  $value = [string]$Text
  if ($value.Length -le $Max) { return $value }
  return $value.Substring(0, $Max - 3) + '...'
}

function Format-SentinelState {
  param($State)
  $lines = New-Object System.Collections.Generic.List[string]
  if (-not $State.Reachable) {
    [void]$lines.Add('STATUS: UNREACHABLE')
    [void]$lines.Add('')
    [void]$lines.Add('The Sentinel service did not answer on ' + $script:BaseUrl + '.')
    if ($State.Error) { [void]$lines.Add('Detail: ' + (Limit-Text $State.Error 200)) }
    [void]$lines.Add('')
    [void]$lines.Add('The scheduled task may be stopped. Open the Start Menu shortcut')
    [void]$lines.Add('again after starting it, or run a full check as administrator.')
    return ($lines -join "`r`n")
  }

  $health = $State.Health
  $status = 'unknown'
  if ($health -and $health.status) { $status = [string]$health.status }
  [void]$lines.Add('STATUS: ' + $status.ToUpperInvariant())

  $uptime = 'unknown'
  if ($health -and $null -ne $health.uptime_s) {
    $seconds = [int]$health.uptime_s
    $uptime = ('{0}h {1}m' -f [int][math]::Floor($seconds / 3600), [int][math]::Floor(($seconds % 3600) / 60))
  }
  $lastCycle = 'not yet'
  if ($health -and $health.last_cycle_at) { $lastCycle = [string]$health.last_cycle_at }
  $chainOk = $null
  if ($State.Status -and $State.Status.health) { $chainOk = $State.Status.health.chain_ok }
  elseif ($health) { $chainOk = $health.evidence_chain_ok }
  $chain = 'unknown'
  if ($null -ne $chainOk) { if ($chainOk) { $chain = 'OK' } else { $chain = 'FAILING' } }
  $version = 'unknown'
  if ($State.Status -and $State.Status.version) { $version = [string]$State.Status.version }
  elseif ($health -and $health.version) { $version = [string]$health.version }

  [void]$lines.Add('Version ' + $version + '  |  Uptime ' + $uptime + '  |  Chain ' + $chain)
  [void]$lines.Add('Last cycle: ' + $lastCycle)

  $adapters = @()
  if ($State.Coverage -and $State.Coverage.adapters) { $adapters = @($State.Coverage.adapters) }
  elseif ($State.Status -and $State.Status.adapters) { $adapters = @($State.Status.adapters) }
  $active = @($adapters | Where-Object { $_.status -eq 'ACTIVE' })
  $unavailable = @($adapters | Where-Object { $_.status -eq 'UNAVAILABLE' })
  $notConfigured = @($adapters | Where-Object { $_.status -eq 'NOT_CONFIGURED' })

  [void]$lines.Add('')
  [void]$lines.Add(('ADAPTERS: {0} ACTIVE, {1} UNAVAILABLE, {2} NOT CONFIGURED' -f $active.Count, $unavailable.Count, $notConfigured.Count))
  if ($active.Count -gt 0) {
    [void]$lines.Add('  ACTIVE')
    foreach ($a in $active) { [void]$lines.Add(('    {0,-18} {1}' -f $a.id, (Limit-Text $a.reason 80))) }
  }
  if ($unavailable.Count -gt 0) {
    [void]$lines.Add('  UNAVAILABLE')
    foreach ($a in $unavailable) { [void]$lines.Add(('    {0,-18} {1}' -f $a.id, (Limit-Text $a.reason 80))) }
  }
  if ($notConfigured.Count -gt 0) {
    [void]$lines.Add('  NOT CONFIGURED')
    foreach ($a in $notConfigured) { [void]$lines.Add(('    {0,-18} {1}' -f $a.id, (Limit-Text $a.reason 80))) }
  }

  $alerts = @($State.Alerts)
  [void]$lines.Add('')
  [void]$lines.Add('RECENT ALERTS (' + $alerts.Count + ')')
  if ($alerts.Count -eq 0) {
    [void]$lines.Add('  none')
  } else {
    foreach ($a in $alerts) {
      $when = ''
      if ($a.created_at) {
        try { $when = ([datetime]$a.created_at).ToLocalTime().ToString('yyyy-MM-dd HH:mm') }
        catch { $when = [string]$a.created_at }
      }
      [void]$lines.Add(('  {0}  {1,-8} {2}' -f $when, $a.severity, $a.rule_id))
      [void]$lines.Add('      ' + (Limit-Text $a.title 95))
    }
  }

  if (-not $State.TokenPresent) {
    [void]$lines.Add('')
    [void]$lines.Add('The diagnostics token is not available to this account.')
    [void]$lines.Add('Only service health can be shown. Run a full check as administrator.')
  } elseif ($null -eq $State.Status) {
    [void]$lines.Add('')
    [void]$lines.Add('Diagnostics returned no status. The token may have changed;')
    [void]$lines.Add('restart the service or run a full check as administrator.')
  }

  return ($lines -join "`r`n")
}

if ($Once) {
  try {
    $snapshot = Get-SentinelState
    Write-Output (Format-SentinelState -State $snapshot)
    if ($snapshot.Reachable) { exit 0 }
    exit 1
  } finally {
    $script:HttpClient.Dispose()
  }
}


$uiPath = Join-Path $PSScriptRoot 'tray-ui.ps1'
if (-not (Test-Path $uiPath)) {
  Write-Error ('The tray UI file is missing: ' + $uiPath)
  exit 2
}
try {
  . $uiPath
} finally {
  try { $script:HttpClient.Dispose() } catch { }
}
