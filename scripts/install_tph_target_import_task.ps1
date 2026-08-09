[CmdletBinding()]
param(
    [string]$TaskName = "FORGE Import theprawnhunter Targets",
    [string]$ApiUrl = "http://127.0.0.1:8011/monitor/targets/export",
    [string]$TphEnvPath = "X:\01 REPOSITORIES\theprawnhunter\.env",
    [int]$EveryMinutes = 30,
    [int]$Limit = 100,
    [int]$MaxIter = 3,
    [int]$StartLimit = 3,
    [int]$WaitSeconds = 180,
    [int]$TimeoutMinutes = 45,
    [int]$StopGraceSeconds = 90,
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

$interval = [Math]::Max(5, $EveryMinutes)
$launcherDir = Join-Path $PSScriptRoot "scheduled"
$launcher = Join-Path $launcherDir "forge_tph_import.cmd"
$dryRunArg = if ($DryRun) { " -DryRun" } else { "" }
$startArg = if ($Start) { " -Start" } else { "" }
$launcherBody = @"
@echo off
setlocal
call powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "$taskRunner" -ApiUrl "$ApiUrl" -TphEnvPath "$TphEnvPath" -Limit $Limit -MaxIter $MaxIter -StartLimit $StartLimit -WaitSeconds $WaitSeconds -TimeoutMinutes $TimeoutMinutes -StopGraceSeconds $StopGraceSeconds -ModuleTimeoutSeconds $ModuleTimeoutSeconds -StaleRunMinutes $StaleRunMinutes$startArg$dryRunArg
set "RESULT=%ERRORLEVEL%"
exit /b %RESULT%
"@
New-Item -ItemType Directory -Path $launcherDir -Force | Out-Null
Set-Content -LiteralPath $launcher -Value $launcherBody -Encoding ASCII
$trigger = New-ScheduledTaskTrigger `
    -Once `
    -At (Get-Date).AddMinutes(1) `
    -RepetitionInterval (New-TimeSpan -Minutes $interval) `
    -RepetitionDuration (New-TimeSpan -Days 3650)
$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$taskRunner`" -ApiUrl `"$ApiUrl`" -TphEnvPath `"$TphEnvPath`" -Limit $Limit -MaxIter $MaxIter -StartLimit $StartLimit -WaitSeconds $WaitSeconds -TimeoutMinutes $TimeoutMinutes -StopGraceSeconds $StopGraceSeconds -ModuleTimeoutSeconds $ModuleTimeoutSeconds -StaleRunMinutes $StaleRunMinutes$startArg$dryRunArg" `
    -WorkingDirectory $launcherDir
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Minutes ([Math]::Max($TimeoutMinutes + 5, 10))) `
    -MultipleInstances IgnoreNew

Register-ScheduledTask `
    -TaskName $TaskName `
    -Trigger $trigger `
    -Action $action `
    -Settings $settings `
    -Force | Out-Null

Write-Host "Installed scheduled task: $TaskName"
Write-Host "Runs every $interval minute(s) while Windows is running."
Write-Host "Start enabled: $Start; max new passive runs per import: $StartLimit; max iterations per run: $MaxIter"
Write-Host "Watchdog timeout: $TimeoutMinutes minute(s)"
Write-Host "Graceful stop window: $StopGraceSeconds second(s); module timeout: $ModuleTimeoutSeconds second(s)"
Write-Host "Launcher: $launcher"
