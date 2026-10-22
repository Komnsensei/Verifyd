<#
.SYNOPSIS
  Stops and unregisters the Sentinel scheduled task.

.DESCRIPTION
  Evidence is preserved by default. Removing the install directory requires
  -RemoveInstall, and deleting recorded evidence additionally requires
  -RemoveData. Both are explicit so an uninstall cannot silently destroy an
  audit trail.

.EXAMPLE
  .\uninstall.ps1
  .\uninstall.ps1 -RemoveInstall
  .\uninstall.ps1 -RemoveInstall -RemoveData -Force
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
  [string]$InstallDir = (Join-Path $env:ProgramData 'Sentinel'),
  [string]$TaskName = 'SentinelDataAccessMonitor',
  [switch]$RemoveInstall,
  [switch]$RemoveData,
  [switch]$Force
)

$ErrorActionPreference = 'Stop'
$stateDir = Join-Path $InstallDir 'state'

$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($task) {
  try { Stop-ScheduledTask -TaskName $TaskName } catch { Write-Warning "Stop failed: $($_.Exception.Message)" }
  Start-Sleep -Seconds 1
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
  Write-Output "task: $TaskName unregistered"
} else {
  Write-Output "task: $TaskName was not registered"
}

$shortcutPath = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Sentinel Status.lnk'
if (Test-Path $shortcutPath) {
  Remove-Item -Path $shortcutPath -Force -ErrorAction SilentlyContinue
  Write-Output "shortcut: removed $shortcutPath"
}

if (-not $RemoveInstall) {
  Write-Output "install dir preserved: $InstallDir"
  Write-Output "evidence preserved: $stateDir"
  if (Test-Path $stateDir) {
    $bytes = (Get-ChildItem $stateDir -Recurse -File | Measure-Object Length -Sum).Sum
    Write-Output ("evidence size: {0:N0} bytes" -f [double]$bytes)
  }
  Write-Output 'Re-run with -RemoveInstall to remove program files.'
  exit 0
}

if ($RemoveData) {
  if (-not $Force) {
    Write-Output "Refusing to delete evidence without -Force. Evidence remains at $stateDir"
    exit 1
  }
  if (Test-Path $stateDir) {
    Remove-Item -Path $stateDir -Recurse -Force
    Write-Output "evidence deleted: $stateDir"
  }
} elseif (Test-Path $stateDir) {
  Write-Output "evidence preserved: $stateDir (pass -RemoveData -Force to delete)"
}

$keep = @()
Get-ChildItem -Path $InstallDir -Force | Where-Object { $_.Name -eq 'state' } | ForEach-Object { $keep += $_.FullName }
Get-ChildItem -Path $InstallDir -Force | Where-Object { $keep -notcontains $_.FullName } | Remove-Item -Recurse -Force
Write-Output "program files removed from $InstallDir"
