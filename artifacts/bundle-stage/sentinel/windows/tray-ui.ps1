<#
  WinForms notification-area UI for Sentinel. Loaded by tray.ps1 when not -Once.
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$created = $false
try {
  $mutex = [System.Threading.Mutex]::new($true, 'Local\SentinelStatusTray', [ref]$created)
  if (-not $created) { exit 0 }
} catch { }

function Get-StatusIcon {
  param($State)
  if (-not $State.Reachable) { return [System.Drawing.SystemIcons]::Error }
  $status = ''
  if ($State.Health -and $State.Health.status) { $status = [string]$State.Health.status }
  if ($status -eq 'ok') { return [System.Drawing.SystemIcons]::Information }
  if ($status -eq 'degraded') { return [System.Drawing.SystemIcons]::Warning }
  return [System.Drawing.SystemIcons]::Error
}

function Get-TrayText {
  param($State)
  if (-not $State.Reachable) { return 'Sentinel: unreachable' }
  $status = 'unknown'
  if ($State.Health -and $State.Health.status) { $status = [string]$State.Health.status }
  $active = 0
  if ($State.Health -and $null -ne $State.Health.adapters_active) { $active = [int]$State.Health.adapters_active }
  $text = 'Sentinel: ' + $status + ' (' + $active + ' active)'
  if ($text.Length -gt 63) { $text = $text.Substring(0, 63) }
  return $text
}

function Get-LatestValidationDir {
  $root = Join-Path $InstallDir 'validation'
  try {
    if (-not (Test-Path $root)) { return $null }
    return (Get-ChildItem -Path $root -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1)
  } catch {
    return $null
  }
}

function Open-EvidenceFolder {
  $latest = Get-LatestValidationDir
  if (-not $latest) {
    [System.Windows.Forms.MessageBox]::Show('No validation folder has been created yet.', 'Sentinel', 'OK', 'Information') | Out-Null
    return
  }
  try { Start-Process -FilePath explorer.exe -ArgumentList ('"' + $latest.FullName + '"') | Out-Null }
  catch { [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Sentinel', 'OK', 'Error') | Out-Null }
}

function Open-LatestReport {
  $latest = Get-LatestValidationDir
  if (-not $latest) {
    [System.Windows.Forms.MessageBox]::Show('No report has been written yet. Run a full check first.', 'Sentinel', 'OK', 'Information') | Out-Null
    return
  }
  $report = Join-Path $latest.FullName 'report.json'
  if (-not (Test-Path $report)) {
    [System.Windows.Forms.MessageBox]::Show('The latest validation folder has no report.json.', 'Sentinel', 'OK', 'Warning') | Out-Null
    return
  }
  try { Invoke-Item $report }
  catch { [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Sentinel', 'OK', 'Error') | Out-Null }
}

function Start-FullCheck {
  $validator = Join-Path $InstallDir 'sentinel\windows\validate.ps1'
  if (-not (Test-Path $validator)) {
    [System.Windows.Forms.MessageBox]::Show('validate.ps1 is missing from the install.', 'Sentinel', 'OK', 'Error') | Out-Null
    return
  }
  $argLine = '-NoProfile -ExecutionPolicy Bypass -NoExit -File "' + $validator + '" -InstallDir "' + $InstallDir + '" -TestListener'
  try { Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argLine | Out-Null }
  catch { [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Sentinel', 'OK', 'Error') | Out-Null }
}

function Update-StatusForm {
  if (-not $script:StatusForm -or $script:StatusForm.IsDisposed) { return }
  if (-not $script:State) { return }
  $script:BodyBox.Text = Format-SentinelState -State $script:State
}

function New-StatusForm {
  $form = New-Object System.Windows.Forms.Form
  $form.Text = 'Sentinel status'
  $form.ClientSize = New-Object System.Drawing.Size(760, 560)
  $form.MinimumSize = New-Object System.Drawing.Size(560, 380)
  $form.StartPosition = 'CenterScreen'
  $form.Icon = [System.Drawing.SystemIcons]::Shield
  $form.ShowInTaskbar = $true

  $body = New-Object System.Windows.Forms.TextBox
  $body.Multiline = $true
  $body.ReadOnly = $true
  $body.ScrollBars = 'Both'
  $body.WordWrap = $false
  $body.Dock = 'Fill'
  $body.Font = New-Object System.Drawing.Font('Consolas', 9)
  $body.BackColor = [System.Drawing.Color]::White
  $form.Controls.Add($body)
  $script:BodyBox = $body

  $panel = New-Object System.Windows.Forms.FlowLayoutPanel
  $panel.Dock = 'Bottom'
  $panel.Height = 46
  $panel.Padding = New-Object System.Windows.Forms.Padding(8, 8, 8, 8)
  $panel.FlowDirection = 'LeftToRight'
  $form.Controls.Add($panel)

  $refresh = New-Object System.Windows.Forms.Button
  $refresh.Text = 'Refresh'
  $refresh.Width = 90
  $refresh.Add_Click({ Update-Tray })
  $panel.Controls.Add($refresh)

  $check = New-Object System.Windows.Forms.Button
  $check.Text = 'Full check (admin)'
  $check.Width = 135
  $check.Add_Click({ Start-FullCheck })
  $panel.Controls.Add($check)

  $folder = New-Object System.Windows.Forms.Button
  $folder.Text = 'Evidence folder'
  $folder.Width = 120
  $folder.Add_Click({ Open-EvidenceFolder })
  $panel.Controls.Add($folder)

  $report = New-Object System.Windows.Forms.Button
  $report.Text = 'Latest report'
  $report.Width = 110
  $report.Add_Click({ Open-LatestReport })
  $panel.Controls.Add($report)

  $close = New-Object System.Windows.Forms.Button
  $close.Text = 'Close'
  $close.Width = 80
  $close.Add_Click({ $script:StatusForm.Close() })
  $panel.Controls.Add($close)

  $form.Add_FormClosed({ $script:StatusForm = $null })
  return $form
}

function Show-StatusWindow {
  if ($script:StatusForm -and -not $script:StatusForm.IsDisposed) {
    $script:StatusForm.WindowState = 'Normal'
    $script:StatusForm.Show()
    $script:StatusForm.Activate()
    return
  }
  $script:StatusForm = New-StatusForm
  Update-StatusForm
  $script:StatusForm.Show()
  $script:StatusForm.Activate()
}

function Update-Tray {
  $script:State = Get-SentinelState
  $notify.Icon = Get-StatusIcon -State $script:State
  $notify.Text = Get-TrayText -State $script:State
  if ($script:StatusForm -and -not $script:StatusForm.IsDisposed) { Update-StatusForm }
}

$script:StatusForm = $null
$script:State = $null

$menu = New-Object System.Windows.Forms.ContextMenuStrip
$openItem = $menu.Items.Add('Open status')
$openItem.Add_Click({ Show-StatusWindow })
$refreshItem = $menu.Items.Add('Refresh now')
$refreshItem.Add_Click({ Update-Tray })
$checkItem = $menu.Items.Add('Run full check (admin)')
$checkItem.Add_Click({ Start-FullCheck })
[void]$menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))
$folderItem = $menu.Items.Add('Open evidence folder')
$folderItem.Add_Click({ Open-EvidenceFolder })
$reportItem = $menu.Items.Add('Open latest report')
$reportItem.Add_Click({ Open-LatestReport })
[void]$menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))
$exitItem = $menu.Items.Add('Exit')
$exitItem.Add_Click({
  $notify.Visible = $false
  $notify.Dispose()
  [System.Windows.Forms.Application]::Exit()
})

$notify = New-Object System.Windows.Forms.NotifyIcon
$notify.Icon = [System.Drawing.SystemIcons]::Information
$notify.Text = 'Sentinel starting...'
$notify.ContextMenuStrip = $menu
$notify.Visible = $true
$notify.Add_DoubleClick({ Show-StatusWindow })

Update-Tray

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 30000
$timer.Add_Tick({ try { Update-Tray } catch { } })
$timer.Start()

try {
  [System.Windows.Forms.Application]::Run()
} finally {
  try { $timer.Stop(); $timer.Dispose() } catch { }
  try { $notify.Visible = $false; $notify.Dispose() } catch { }
  try { $script:HttpClient.Dispose() } catch { }
}

