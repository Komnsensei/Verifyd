<#
.SYNOPSIS
  One-click Sentinel setup and Windows validation.

.DESCRIPTION
  Double-click SETUP-SENTINEL.cmd. This script requests administrator approval,
  installs Node.js LTS with winget if Node is missing, installs Sentinel, sets
  a local diagnostics token, runs the validation checklist, and opens the
  evidence folder. Every step is printed; no commands need to be typed.

.PARAMETER InstallDir
  Install location. Defaults to C:\ProgramData\Sentinel.

.PARAMETER TaskName
  Scheduled task name. Defaults to SentinelDataAccessMonitor.
#>
[CmdletBinding()]
param(
  [string]$InstallDir = (Join-Path $env:ProgramData 'Sentinel'),
  [string]$TaskName = 'SentinelDataAccessMonitor'
)

$ErrorActionPreference = 'Stop'
$scriptRoot = $PSScriptRoot
$repoRoot = Split-Path -Parent (Split-Path -Parent $scriptRoot)

function Test-Admin {
  try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList $id
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch {
    return $false
  }
}

function Write-Step([string]$Message) {
  Write-Host ''
  Write-Host ('== ' + $Message) -ForegroundColor Cyan
}

function Write-Ok([string]$Message) {
  Write-Host ('   ' + $Message) -ForegroundColor Green
}

function Write-Warn([string]$Message) {
  Write-Host ('   ' + $Message) -ForegroundColor Yellow
}

function Find-Node {
  $cmd = Get-Command node.exe -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd }
  $candidates = @()
  if ($env:ProgramFiles) { $candidates += (Join-Path $env:ProgramFiles 'nodejs\node.exe') }
  if (${env:ProgramFiles(x86)}) { $candidates += (Join-Path ${env:ProgramFiles(x86)} 'nodejs\node.exe') }
  if ($env:LOCALAPPDATA) { $candidates += (Join-Path $env:LOCALAPPDATA 'Programs\nodejs\node.exe') }
  foreach ($p in $candidates) {
    if ($p -and (Test-Path $p)) { return [pscustomobject]@{ Source = $p } }
  }
  return $null
}

if (-not (Test-Admin)) {
  Write-Host ''
  Write-Host 'Windows will now ask for administrator approval.' -ForegroundColor Yellow
  try {
    $exe = Join-Path $PSHOME 'powershell.exe'
    if (-not (Test-Path $exe)) { $exe = Join-Path $PSHOME 'pwsh.exe' }
    $argLine = '-NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '"' +
      ' -InstallDir "' + $InstallDir + '" -TaskName "' + $TaskName + '"'
    Start-Process -FilePath $exe -Verb RunAs -ArgumentList $argLine | Out-Null
    exit 0
  } catch {
    Write-Host ('Could not start the elevated setup: ' + $_.Exception.Message) -ForegroundColor Red
    Write-Host 'Right-click SETUP-SENTINEL.cmd and choose "Run as administrator".'
    Read-Host 'Press Enter to close this window' | Out-Null
    exit 1
  }
}

$logDir = Join-Path $env:ProgramData 'Sentinel'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$logPath = Join-Path $logDir 'setup.log'
try { Start-Transcript -Path $logPath -Append | Out-Null } catch { }
$tempConfig = $null
$exitCode = 0

try {
  Write-Step '1/6  Checking the bundle and Node.js'
  if (-not (Test-Path (Join-Path $repoRoot 'bin\sentinel.cjs'))) {
    throw ('The bundle is incomplete. Extract the whole zip and run this file from that folder. Missing: ' + (Join-Path $repoRoot 'bin\sentinel.cjs'))
  }

  $node = Find-Node
  if (-not $node) {
    Write-Warn 'Node.js was not found. Sentinel needs Node.js 18 or newer.'
    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
    $answer = 'n'
    if ($winget) {
      $answer = Read-Host 'Install Node.js LTS automatically with winget now? [Y/n]'
    }
    if ($winget -and ($answer -notmatch '^(n|no)$')) {
      Write-Host '   Installing Node.js LTS. This can take a few minutes...' -ForegroundColor Yellow
      & $winget.Source install --id OpenJS.NodeJS.LTS -e --silent --accept-package-agreements --accept-source-agreements
      Start-Sleep -Seconds 2
      $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
      $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
      $env:Path = $machinePath + ';' + $userPath
      $node = Find-Node
    }
    if (-not $node) {
      Write-Warn 'Opening the Node.js download page. Install Node.js 18+, then double-click SETUP-SENTINEL.cmd again.'
      Start-Process 'https://nodejs.org/en/download'
      throw 'Node.js is required and was not installed.'
    }
  }

  $nodeVersion = (& $node.Source --version).Trim().TrimStart('v')
  $nodeMajor = 0
  [void][int]::TryParse(($nodeVersion -split '\.')[0], [ref]$nodeMajor)
  if ($nodeMajor -lt 18) { throw ('Node.js 18+ is required; found ' + $nodeVersion + '.') }
  $nodeDir = Split-Path -Parent $node.Source
  if ($env:Path -notlike ($nodeDir + '*')) { $env:Path = $nodeDir + ';' + $env:Path }
  Write-Ok ('Node.js ' + $nodeVersion + ' at ' + $node.Source)

  Write-Step '2/6  Installing Sentinel'
  $existing = $null
  try { $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue } catch { }
  if ($existing) {
    Write-Warn ('Replacing the existing task ' + $TaskName + '.')
    try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue } catch { }
    Start-Sleep -Seconds 2
  }

  $configDest = Join-Path $InstallDir 'config.json'
  if (-not (Test-Path $configDest)) {
    $exampleConfig = Join-Path $repoRoot 'sentinel\config.example.json'
    if (-not (Test-Path $exampleConfig)) { throw ('Missing ' + $exampleConfig + '.') }
    $newConfig = Get-Content -Path $exampleConfig -Raw | ConvertFrom-Json
    $newConfig.service.state_dir = (Join-Path $InstallDir 'state')
    $newConfig.adapters.host_security.enabled = $true
    $newConfig.adapters.host_persistence.enabled = $true
    $newConfig.adapters.host_fileaudit.enabled = $true
    $newConfig.adapters.host_sysmon.enabled = $true
    $newConfig.adapters.host_dns.enabled = $true
    $tempConfig = Join-Path $env:TEMP ('sentinel-config-' + [guid]::NewGuid().ToString('N') + '.json')
    $configJson = $newConfig | ConvertTo-Json -Depth 20
    [System.IO.File]::WriteAllText($tempConfig, $configJson, (New-Object System.Text.UTF8Encoding($false)))
  }

  $installArgs = @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass',
    '-File', (Join-Path $scriptRoot 'install.ps1'),
    '-InstallDir', $InstallDir,
    '-TaskName', $TaskName,
    '-GrantEventLogRead'
  )
  if ($existing) { $installArgs += '-Force' }
  if ($tempConfig) { $installArgs += @('-ConfigPath', $tempConfig) }
  & powershell.exe @installArgs
  if ($LASTEXITCODE -ne 0) { throw ('The installer failed with exit code ' + $LASTEXITCODE + '. See ' + $logPath + '.') }
  if ($tempConfig) {
    Remove-Item -Path $tempConfig -Force -ErrorAction SilentlyContinue
    $tempConfig = $null
  }
  Write-Ok 'Sentinel is installed.'

  Write-Step '3/6  Applying Windows audit policy and SACLs'
  $auditScript = Join-Path $scriptRoot 'enable-audit.ps1'
  if (-not (Test-Path $auditScript)) {
    Write-Warn ('The audit-policy switch is missing: ' + $auditScript)
  } else {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $auditScript -OutputPath (Join-Path $InstallDir 'audit-policy.json')
    if ($LASTEXITCODE -eq 0) {
      Write-Ok 'Audit policy and SACLs are enabled.'
    } else {
      Write-Warn 'Some audit-policy items failed. Sentinel still runs; coverage shows the gaps in the validation report.'
    }
  }

  Write-Step '4/6  Configuring local diagnostics'
  $configPath = Join-Path $InstallDir 'config.json'
  if (-not (Test-Path $configPath)) { throw ('Installer did not create ' + $configPath + '.') }
  $cfg = Get-Content -Path $configPath -Raw | ConvertFrom-Json
  $tokenName = 'SENTINEL_DIAG_TOKEN'
  if ($cfg.diagnostics -and $cfg.diagnostics.token_env) { $tokenName = [string]$cfg.diagnostics.token_env }
  $token = [Environment]::GetEnvironmentVariable($tokenName, 'Machine')
  if (-not $token) {
    $token = [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')
    [Environment]::SetEnvironmentVariable($tokenName, $token, 'Machine')
    Write-Ok ('Generated ' + $tokenName + ' (value not displayed).')
  } else {
    Write-Ok ('Using the existing ' + $tokenName + '.')
  }
  [Environment]::SetEnvironmentVariable($tokenName, $token, 'Process')

  Write-Step '5/6  Running the validation checklist (1-2 minutes)'
  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $scriptRoot 'validate.ps1') -InstallDir $InstallDir -TaskName $TaskName -TestListener
  $validationExit = $LASTEXITCODE
  if ($validationExit -ne 0) {
    throw ('Validation failed with exit code ' + $validationExit + '. Open ' + (Join-Path $InstallDir 'validation') + ' for the partial report.')
  }

  $validationRoot = Join-Path $InstallDir 'validation'
  $latest = $null
  if (Test-Path $validationRoot) {
    $latest = Get-ChildItem -Path $validationRoot -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  }
  if (-not $latest) { throw 'Validation finished but no report folder was found.' }
  $reportPath = Join-Path $latest.FullName 'report.json'
  if (Test-Path $reportPath) {
    try {
      $report = Get-Content -Path $reportPath -Raw | ConvertFrom-Json
      $active = @($report.coverage.active)
      $unavailable = @($report.coverage.unavailable)
      Write-Host ''
      if ($active.Count -gt 0) { Write-Ok ('ACTIVE: ' + ($active -join ', ')) }
      else { Write-Warn 'ACTIVE: none' }
      foreach ($a in $unavailable) { Write-Warn ('UNAVAILABLE ' + $a.id + ': ' + $a.reason) }
      Write-Host ('   report: ' + $reportPath)
    } catch {
      Write-Warn ('The report was written but could not be summarized: ' + $_.Exception.Message)
    }
  }
  try { Invoke-Item $latest.FullName } catch { Write-Warn ('Open the folder manually: ' + $latest.FullName) }

  Write-Step '6/6  Starting the status icon'
  $trayScript = Join-Path $InstallDir 'sentinel\windows\tray.ps1'
  if (-not (Test-Path $trayScript)) {
    Write-Warn ('The status app is missing: ' + $trayScript)
  } else {
    $startMenu = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Sentinel Status.lnk'
    if (Test-Path $startMenu) { Write-Ok ('Start Menu: ' + $startMenu) }
    else { Write-Warn ('The Start Menu shortcut was not created: ' + $startMenu) }
    $psExe = Join-Path $PSHOME 'powershell.exe'
    if (-not (Test-Path $psExe)) { $psExe = Join-Path $PSHOME 'pwsh.exe' }
    try {
      $trayArgs = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $trayScript + '"'
      $trayProc = Start-Process -FilePath $psExe -ArgumentList $trayArgs -WorkingDirectory $InstallDir -PassThru
      Start-Sleep -Seconds 2
      if ($trayProc.HasExited) {
        if ($trayProc.ExitCode -eq 0) { Write-Ok 'Status icon is already running.' }
        else { Write-Warn ('The status icon exited with code ' + $trayProc.ExitCode + '. Run tray.ps1 -Once for details.') }
      } else {
        Write-Ok 'Status icon is running in the notification area.'
      }
    } catch {
      Write-Warn ('Could not start the status icon: ' + $_.Exception.Message)
    }
  }

  Write-Host ''
  Write-Host 'DONE. The evidence folder is open in Explorer.' -ForegroundColor Green

} catch {
  Write-Host ''
  Write-Host ('SETUP FAILED: ' + $_.Exception.Message) -ForegroundColor Red
  Write-Host ('Full log: ' + $logPath)
  if (Test-Path $logPath) { Write-Host 'Open that file for details; it contains no token values.' }
  $exitCode = 1
} finally {
  if ($tempConfig) { Remove-Item -Path $tempConfig -Force -ErrorAction SilentlyContinue }
  try { Stop-Transcript | Out-Null } catch { }
  Write-Host ''
  Read-Host 'Press Enter to close this window' | Out-Null
}
exit $exitCode
