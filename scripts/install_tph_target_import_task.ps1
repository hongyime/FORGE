[CmdletBinding()]
param(
    [string]$TaskName = "FORGE Import theprawnhunter Targets",
    [string]$ApiUrl = "http://127.0.0.1:8011/monitor/targets/export",
    [string]$TphEnvPath = "X:\01 REPOSITORIES\theprawnhunter\.env",
    [int]$EveryMinutes = 30,
    [int]$Limit = 25,
    [int]$WaitSeconds = 60,
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

$interval = [Math]::Max(5, $EveryMinutes)
$launcherDir = Join-Path $PSScriptRoot "scheduled"
$launcher = Join-Path $launcherDir "forge_tph_import.cmd"
$dryRunArg = if ($DryRun) { " -DryRun" } else { "" }
$launcherBody = @"
@echo off
setlocal
call powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$runner" -ApiUrl "$ApiUrl" -TphEnvPath "$TphEnvPath" -Limit $Limit -WaitSeconds $WaitSeconds$dryRunArg
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
    -Execute $env:ComSpec `
    -Argument "/d /c `"$launcher`"" `
    -WorkingDirectory $launcherDir
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 15) `
    -MultipleInstances IgnoreNew

Register-ScheduledTask `
    -TaskName $TaskName `
    -Trigger $trigger `
    -Action $action `
    -Settings $settings `
    -Force | Out-Null

Write-Host "Installed scheduled task: $TaskName"
Write-Host "Runs every $interval minute(s) while Windows is running."
Write-Host "Launcher: $launcher"
