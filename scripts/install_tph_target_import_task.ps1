[CmdletBinding()]
param(
    [string]$TaskName = "FORGE Import theprawnhunter Targets",
    [string]$ApiUrl = "http://127.0.0.1:8011/monitor/targets/export",
    [string]$TphEnvPath = "X:\01 REPOSITORIES\theprawnhunter\.env",
    [int]$EveryMinutes = 60,
    [int]$Limit = 100,
    [int]$MaxIter = 1,
    [int]$StartLimit = 1,
    [int]$WaitSeconds = 60,
    [int]$TimeoutMinutes = 45,
    [int]$StopGraceSeconds = 90,
    [int]$WatchdogHelperTimeoutSeconds = 120,
    [int]$StaleHelperFileMinutes = 360,
    [int]$ModuleTimeoutSeconds = 900,
    [int]$StaleRunMinutes = 120,
    [bool]$Start = $true,
    [switch]$DryRun,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"

if ($Uninstall) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "Removed scheduled task: $TaskName"
    exit 0
}

$runner = Join-Path $PSScriptRoot "import_tph_targets.ps1"
if (-not (Test-Path $runner)) {
    throw "import runner not found: $runner"
}
$taskRunner = Join-Path $PSScriptRoot "run_tph_target_import_task.ps1"
if (-not (Test-Path $taskRunner)) {
    throw "scheduled task runner not found: $taskRunner"
}

$launcherDir = Join-Path $PSScriptRoot "scheduled"
$launcher = Join-Path $launcherDir "forge_tph_import.cmd"
$dryRunArg = if ($DryRun) { " -DryRun" } else { "" }
$startArg = if ($Start) { " -Start" } else { "" }
$launcherBody = @"
@echo off
setlocal
call powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "$taskRunner" -ApiUrl "$ApiUrl" -TphEnvPath "$TphEnvPath" -Limit $Limit -MaxIter $MaxIter -StartLimit $StartLimit -WaitSeconds $WaitSeconds -TimeoutMinutes $TimeoutMinutes -StopGraceSeconds $StopGraceSeconds -WatchdogHelperTimeoutSeconds $WatchdogHelperTimeoutSeconds -StaleHelperFileMinutes $StaleHelperFileMinutes -ModuleTimeoutSeconds $ModuleTimeoutSeconds -StaleRunMinutes $StaleRunMinutes$startArg$dryRunArg
set "RESULT=%ERRORLEVEL%"
exit /b %RESULT%
"@
New-Item -ItemType Directory -Path $launcherDir -Force | Out-Null
Set-Content -LiteralPath $launcher -Value $launcherBody -Encoding ASCII
$executionLimitMinutes = [Math]::Max($TimeoutMinutes, 10)
$interval = [Math]::Max([Math]::Max(5, $EveryMinutes), $executionLimitMinutes)
$trigger = New-ScheduledTaskTrigger `
    -Once `
    -At (Get-Date).AddMinutes(1) `
    -RepetitionInterval (New-TimeSpan -Minutes $interval) `
    -RepetitionDuration (New-TimeSpan -Days 3650)
$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$taskRunner`" -ApiUrl `"$ApiUrl`" -TphEnvPath `"$TphEnvPath`" -Limit $Limit -MaxIter $MaxIter -StartLimit $StartLimit -WaitSeconds $WaitSeconds -TimeoutMinutes $TimeoutMinutes -StopGraceSeconds $StopGraceSeconds -WatchdogHelperTimeoutSeconds $WatchdogHelperTimeoutSeconds -StaleHelperFileMinutes $StaleHelperFileMinutes -ModuleTimeoutSeconds $ModuleTimeoutSeconds -StaleRunMinutes $StaleRunMinutes$startArg$dryRunArg" `
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
    Write-Host "Requested interval $EveryMinutes minute(s) was raised to $interval minute(s) to fit the watchdog execution budget."
}
Write-Host "Runs every $interval minute(s) while Windows is running."
Write-Host "Start enabled: $Start; max new passive runs per import: $StartLimit; max iterations per run: $MaxIter"
Write-Host "Watchdog timeout: $TimeoutMinutes minute(s)"
Write-Host "Graceful stop window: $StopGraceSeconds second(s); watchdog helper timeout: $WatchdogHelperTimeoutSeconds second(s); stale helper cleanup: $StaleHelperFileMinutes minute(s); module timeout: $ModuleTimeoutSeconds second(s)"
Write-Host "Launcher: $launcher"
