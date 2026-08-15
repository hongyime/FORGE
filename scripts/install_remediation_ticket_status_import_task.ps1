[CmdletBinding()]
param(
    [string]$TaskName = "FORGE Import Remediation Ticket Statuses",
    [string]$DataDir = "",
    [Parameter(Mandatory = $true)][string]$StatusFile,
    [int]$EveryMinutes = 60,
    [int]$TimeoutMinutes = 20,
    [string]$ClosePolicy = "trust_external_status",
    [bool]$Apply = $false,
    [switch]$DryRun,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"

if ($Uninstall) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "Removed scheduled task: $TaskName"
    exit 0
}

$taskRunner = Join-Path $PSScriptRoot "run_remediation_ticket_status_import_task.ps1"
if (-not (Test-Path $taskRunner)) {
    throw "scheduled task runner not found: $taskRunner"
}
if (-not (Test-Path -LiteralPath $StatusFile)) {
    throw "status file not found: $StatusFile"
}

$launcherDir = Join-Path $PSScriptRoot "scheduled"
$launcher = Join-Path $launcherDir "forge_remediation_ticket_status_import.cmd"
$applyArg = if ($Apply -and -not $DryRun) { " -Apply" } else { "" }
$dataDirArg = if ([string]::IsNullOrWhiteSpace($DataDir)) { "" } else { " -DataDir `"$DataDir`"" }
$launcherBody = @"
@echo off
setlocal
call powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "$taskRunner"$dataDirArg -StatusFile "$StatusFile" -TimeoutMinutes $TimeoutMinutes -ClosePolicy "$ClosePolicy"$applyArg
set "RESULT=%ERRORLEVEL%"
exit /b %RESULT%
"@
New-Item -ItemType Directory -Path $launcherDir -Force | Out-Null
Set-Content -LiteralPath $launcher -Value $launcherBody -Encoding ASCII

$executionLimitMinutes = [Math]::Max($TimeoutMinutes + 5, 10)
$interval = [Math]::Max([Math]::Max(5, $EveryMinutes), $executionLimitMinutes)
$actionArgument = "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$taskRunner`"$dataDirArg -StatusFile `"$StatusFile`" -TimeoutMinutes $TimeoutMinutes -ClosePolicy `"$ClosePolicy`"$applyArg"
$trigger = New-ScheduledTaskTrigger `
    -Once `
    -At (Get-Date).AddMinutes(1) `
    -RepetitionInterval (New-TimeSpan -Minutes $interval) `
    -RepetitionDuration (New-TimeSpan -Days 3650)
$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument $actionArgument `
    -WorkingDirectory $launcherDir
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Minutes $executionLimitMinutes) `
    -MultipleInstances IgnoreNew

Register-ScheduledTask `
    -TaskName $TaskName `
    -Trigger $trigger `
    -Action $action `
    -Settings $settings `
    -Force | Out-Null

Write-Host "Installed scheduled task: $TaskName"
if ($interval -ne $EveryMinutes) {
    Write-Host "Requested interval $EveryMinutes minute(s) was raised to $interval minute(s) to fit the execution budget."
}
Write-Host "Runs every $interval minute(s) while Windows is running."
Write-Host "Mode: $(if ($Apply -and -not $DryRun) { 'apply' } else { 'dry-run' })"
Write-Host "Close policy: $ClosePolicy"
Write-Host "Status file: $StatusFile"
Write-Host "Launcher: $launcher"
