<#
.SYNOPSIS
  Enables the Windows audit policy and SACLs that Sentinel adapters consume.

.DESCRIPTION
  This is the switch that turns event-log absence into coverage. It enables
  process creation, logon, file system, registry, scheduled-task object access
  and privilege-use auditing, turns on 4688 command lines, and enables the
  WMI-Activity operational log. It also adds SACLs to common persistence
  registry keys so 4657 events can be generated.

  Sysmon is detected but not installed. host.sysmon reports UNAVAILABLE until
  Sysmon is deployed separately; its event 1 covers short-lived processes even
  when 4688 is disabled.

.PARAMETER FilePaths
  Files or directories to receive a read/write/delete SACL. 4663 is generated
  only for objects with a matching SACL.

.PARAMETER RegistryKeys
  HKLM-relative registry keys to audit. Defaults to common persistence keys.

.PARAMETER SkipSacls
  Apply audit policy only. Useful when SACL delegation is managed elsewhere.

.PARAMETER OutputPath
  JSON result path. Defaults to ProgramData\Sentinel\audit-policy.json.
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
  [string[]]$FilePaths = @(),
  [string[]]$RegistryKeys = @(
    'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
    'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
    'SYSTEM\CurrentControlSet\Services'
  ),
  [switch]$SkipSacls,
  [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
if (-not $OutputPath) {
  $OutputPath = Join-Path $env:ProgramData 'Sentinel\audit-policy.json'
}
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutputPath) | Out-Null

$results = New-Object System.Collections.ArrayList
function Add-Result([string]$Name, [string]$Status, [string]$Detail) {
  [void]$results.Add([pscustomobject]@{ name = $Name; status = $Status; detail = $Detail })
}

$subcategories = @(
  'Process Creation',
  'Logon',
  'Logoff',
  'File System',
  'Registry',
  'Other Object Access Events',
  'Sensitive Privilege Use',
  'Audit Policy Change'
)
foreach ($sub in $subcategories) {
  & auditpol.exe /set /subcategory:"$sub" /success:enable /failure:enable 2>&1 | Out-Null
  if ($LASTEXITCODE -eq 0) { Add-Result ('audit:' + $sub) 'enabled' 'success and failure' }
  else { Add-Result ('audit:' + $sub) 'failed' ('auditpol exit ' + $LASTEXITCODE) }
}

try {
  $auditKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
  New-Item -Path $auditKey -Force | Out-Null
  New-ItemProperty -Path $auditKey -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -PropertyType DWord -Force | Out-Null
  Add-Result 'process:command_line' 'enabled' '4688 includes command lines after the next process start'
} catch {
  Add-Result 'process:command_line' 'failed' $_.Exception.Message
}

try {
  & wevtutil.exe sl 'Microsoft-Windows-WMI-Activity/Operational' /e:true 2>&1 | Out-Null
  if ($LASTEXITCODE -eq 0) { Add-Result 'log:wmi-activity' 'enabled' 'Microsoft-Windows-WMI-Activity/Operational' }
  else { Add-Result 'log:wmi-activity' 'failed' ('wevtutil exit ' + $LASTEXITCODE) }
} catch {
  Add-Result 'log:wmi-activity' 'failed' $_.Exception.Message
}

$sysmonLog = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue
if ($sysmonLog) {
  Add-Result 'sysmon' 'present' ('records ' + $sysmonLog.RecordCount + '; host.sysmon can read it')
} else {
  Add-Result 'sysmon' 'not_installed' 'install Sysmon separately if event 1/3/22 coverage is required'
}

if (-not $SkipSacls) {
  $code = @'
using System;
using System.Runtime.InteropServices;
public static class SentinelPrivilege {
  [StructLayout(LayoutKind.Sequential)] public struct LUID { public uint LowPart; public int HighPart; }
  [StructLayout(LayoutKind.Sequential)] public struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }
  [StructLayout(LayoutKind.Sequential)] public struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public LUID_AND_ATTRIBUTES Privilege; }
  [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
  [DllImport("advapi32.dll", SetLastError = true)] static extern bool LookupPrivilegeValue(string system, string name, out LUID luid);
  [DllImport("advapi32.dll", SetLastError = true)] static extern bool AdjustTokenPrivileges(IntPtr token, bool disable, ref TOKEN_PRIVILEGES state, uint length, IntPtr previous, IntPtr returnLength);
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  public static bool Enable(string name) {
    IntPtr token;
    if (!OpenProcessToken(GetCurrentProcess(), 0x28, out token)) return false;
    LUID luid;
    if (!LookupPrivilegeValue(null, name, out luid)) return false;
    TOKEN_PRIVILEGES state = new TOKEN_PRIVILEGES();
    state.PrivilegeCount = 1;
    state.Privilege.Luid = luid;
    state.Privilege.Attributes = 2;
    bool ok = AdjustTokenPrivileges(token, false, ref state, (uint)Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)), IntPtr.Zero, IntPtr.Zero);
    return ok && Marshal.GetLastWin32Error() == 0;
  }
}
'@
  try {
    Add-Type -TypeDefinition $code -ErrorAction Stop
    [void][SentinelPrivilege]::Enable('SeSecurityPrivilege')
  } catch {
    Add-Result 'privilege:se_security' 'failed' $_.Exception.Message
  }

  $sid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)
  $auditFlags = [System.Security.AccessControl.AuditFlags]::Success -bor [System.Security.AccessControl.AuditFlags]::Failure
  foreach ($p in $FilePaths) {
    try {
      if (-not (Test-Path -LiteralPath $p)) { Add-Result ('sacl:file:' + $p) 'missing' 'path does not exist'; continue }
      $isDir = (Get-Item -LiteralPath $p).PSIsContainer
      $rights = [System.Security.AccessControl.FileSystemRights]::ReadData -bor [System.Security.AccessControl.FileSystemRights]::WriteData -bor [System.Security.AccessControl.FileSystemRights]::AppendData -bor [System.Security.AccessControl.FileSystemRights]::Delete
      $inherit = if ($isDir) { [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit } else { [System.Security.AccessControl.InheritanceFlags]::None }
      $rule = New-Object System.Security.AccessControl.FileSystemAuditRule($sid, $rights, $inherit, [System.Security.AccessControl.PropagationFlags]::None, $auditFlags)
      $acl = Get-Acl -LiteralPath $p -Audit
      $acl.AddAuditRule($rule)
      Set-Acl -LiteralPath $p -AclObject $acl
      Add-Result ('sacl:file:' + $p) 'enabled' 'read/write/delete success and failure'
    } catch {
      Add-Result ('sacl:file:' + $p) 'failed' $_.Exception.Message
    }
  }

  $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Default)
  foreach ($keyName in $RegistryKeys) {
    try {
      $key = $base.OpenSubKey($keyName, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions -bor [System.Security.AccessControl.RegistryRights]::ReadKey)
      if (-not $key) { Add-Result ('sacl:registry:' + $keyName) 'missing' 'key does not exist'; continue }
      $rights = [System.Security.AccessControl.RegistryRights]::SetValue -bor [System.Security.AccessControl.RegistryRights]::CreateSubKey -bor [System.Security.AccessControl.RegistryRights]::Delete
      $rule = New-Object System.Security.AccessControl.RegistryAuditRule($sid, $rights, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit, [System.Security.AccessControl.PropagationFlags]::None, $auditFlags)
      $acl = $key.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Audit)
      $acl.AddAuditRule($rule)
      $key.SetAccessControl($acl)
      $key.Close()
      Add-Result ('sacl:registry:' + $keyName) 'enabled' 'set value/create subkey/delete success and failure'
    } catch {
      Add-Result ('sacl:registry:' + $keyName) 'failed' $_.Exception.Message
    }
  }
}

$report = [ordered]@{
  schema = 'sentinel.audit-policy/1'
  generated_at = (Get-Date).ToUniversalTime().ToString('o')
  host = $env:COMPUTERNAME
  results = @($results)
}
$json = $report | ConvertTo-Json -Depth 8
[System.IO.File]::WriteAllText($OutputPath, $json, (New-Object System.Text.UTF8Encoding($false)))
Write-Output ('audit policy report: ' + $OutputPath)
foreach ($r in $results) { Write-Output ('  ' + $r.status.ToUpperInvariant() + ' ' + $r.name + ' - ' + $r.detail) }
$failed = @($results | Where-Object { $_.status -eq 'failed' })
if ($failed.Count -gt 0) { exit 1 }
exit 0
