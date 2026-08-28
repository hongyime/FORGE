[CmdletBinding()]
param(
    [string]$TaskName = "FORGE Guarded Autostart",
    [string]$Config = "",
    [int]$EveryMinutes = 30,
    [int]$StartupDelayMinutes = 5,
    [int]$TimeoutMinutes = 150,
    [switch]$DryRun,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"

if ($Uninstall) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-ItemProperty `
        -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
        -Name $TaskName `
        -ErrorAction SilentlyContinue
    Write-Host "Removed scheduled task: $TaskName"
    Write-Host "Removed HKCU Run entry if present: $TaskName"
    exit 0
}

$taskRunner = Join-Path $PSScriptRoot "run_guarded_autostart_task.ps1"
if (-not (Test-Path -LiteralPath $taskRunner)) {
    throw "scheduled task runner not found: $taskRunner"
}

if ([string]::IsNullOrWhiteSpace($Config)) {
    $Config = (Resolve-Path (Join-Path $PSScriptRoot "..\imports\autostart.local.json") -ErrorAction SilentlyContinue).Path
    if ([string]::IsNullOrWhiteSpace($Config)) {
        $Config = Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..")).Path "imports\autostart.local.json"
    }
}

$launcherDir = Join-Path $PSScriptRoot "scheduled"
$launcher = Join-Path $launcherDir "forge_guarded_autostart.cmd"
$launcherBody = @"
@echo off
setlocal
call powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "$taskRunner" -Config "$Config" -TimeoutMinutes $TimeoutMinutes
set "RESULT=%ERRORLEVEL%"
exit /b %RESULT%
"@
New-Item -ItemType Directory -Path $launcherDir -Force | Out-Null
Set-Content -LiteralPath $launcher -Value $launcherBody -Encoding ASCII

$executionLimitMinutes = [Math]::Max($TimeoutMinutes + 5, 10)
$interval = [Math]::Max([Math]::Max(5, $EveryMinutes), $executionLimitMinutes)
$actionArgument = "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$taskRunner`" -Config `"$Config`" -TimeoutMinutes $TimeoutMinutes"
$logonTrigger = New-ScheduledTaskTrigger -AtLogOn
$logonTrigger.Delay = "PT$([Math]::Max(1, $StartupDelayMinutes))M"
$repeatTrigger = New-ScheduledTaskTrigger `
    -Once `
    -At (Get-Date).AddMinutes([Math]::Max(1, $StartupDelayMinutes)) `
    -RepetitionInterval (New-TimeSpan -Minutes $interval) `
    -RepetitionDuration (New-TimeSpan -Days 3650)
$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument $actionArgument `
    -WorkingDirectory $launcherDir
$principal = New-ScheduledTaskPrincipal `
    -UserId "$env:USERDOMAIN\$env:USERNAME" `
    -LogonType Interactive `
    -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Minutes $executionLimitMinutes) `
    -MultipleInstances IgnoreNew `
    -Priority 7

if ($DryRun) {
    Write-Host "Dry-run: would install scheduled task: $TaskName"
    Write-Host "Config: $Config"
    Write-Host "Startup delay: $StartupDelayMinutes minute(s); interval: $interval minute(s); timeout: $TimeoutMinutes minute(s)"
    Write-Host "Action: powershell.exe $actionArgument"
    Write-Host "Fallback HKCU Run action: powershell.exe $actionArgument"
    Write-Host "Launcher: $launcher"
    exit 0
}

try {
    Register-ScheduledTask `
        -TaskName $TaskName `
        -Trigger @($logonTrigger, $repeatTrigger) `
        -Action $action `
        -Principal $principal `
        -Settings $settings `
        -Force | Out-Null
    Write-Host "Installed scheduled task: $TaskName"
    if ($interval -ne $EveryMinutes) {
        Write-Host "Requested interval $EveryMinutes minute(s) was raised to $interval minute(s) to fit the execution budget."
    }
    Write-Host "Runs at logon after $StartupDelayMinutes minute(s), then every $interval minute(s) while Windows is running."
} catch {
    $runKeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    New-Item -Path $runKeyPath -Force | Out-Null
    New-ItemProperty `
        -Path $runKeyPath `
        -Name $TaskName `
        -Value "powershell.exe $actionArgument" `
        -PropertyType String `
        -Force | Out-Null
    Write-Host "Scheduled task install failed: $($_.Exception.Message)"
    Write-Host "Installed HKCU Run startup entry instead: $TaskName"
    Write-Host "Runs at user logon; recurring cadence requires Task Scheduler permission."
}
Write-Host "Mode: cycle apply/live; source queues run before guarded live work, which still requires config gates, FORGE_ROE_ID, resource health, Docker health, cooldown/backoff, and a free lock."
Write-Host "Config: $Config"
Write-Host "Launcher: $launcher"
