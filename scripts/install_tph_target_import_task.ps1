[CmdletBinding()]
param(
    [string]$TaskName = "FORGE Import theprawnhunter Targets",
    [string]$ApiUrl = "http://127.0.0.1:8011/monitor/targets/export",
    [string]$TphEnvPath = "X:\01 REPOSITORIES\theprawnhunter\.env",
    [int]$EveryMinutes = 30,
    [ValidateSet("ImportOnly", "LowAndSlow", "Operator")]
    [string]$Profile = "ImportOnly",
    [int]$Limit = 0,
    [int]$MaxIter = 0,
    [int]$StartLimit = 0,
    [int]$WaitSeconds = 0,
    [int]$TimeoutMinutes = 0,
    [int]$StopGraceSeconds = 0,
    [int]$ModuleTimeoutSeconds = 0,
    [int]$StaleRunMinutes = 0,
    [Nullable[bool]]$Start = $null,
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

function Resolve-ProfileDefault {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$ProfileName
    )
    $profiles = @{
        ImportOnly = @{
            Limit = 1000
            MaxIter = 1
            StartLimit = 0
            WaitSeconds = 60
            TimeoutMinutes = 10
            StopGraceSeconds = 30
            ModuleTimeoutSeconds = 240
            StaleRunMinutes = 90
            Start = $false
        }
        LowAndSlow = @{
            Limit = 1000
            MaxIter = 1
            StartLimit = 1
            WaitSeconds = 60
            TimeoutMinutes = 25
            StopGraceSeconds = 60
            ModuleTimeoutSeconds = 240
            StaleRunMinutes = 45
            Start = $true
        }
        Operator = @{
            Limit = 100
            MaxIter = 3
            StartLimit = 3
            WaitSeconds = 180
            TimeoutMinutes = 45
            StopGraceSeconds = 90
            ModuleTimeoutSeconds = 900
            StaleRunMinutes = 120
            Start = $true
        }
    }
    return $profiles[$ProfileName][$Name]
}

$Limit = if ($Limit -gt 0) { $Limit } else { Resolve-ProfileDefault "Limit" $Profile }
$MaxIter = if ($MaxIter -gt 0) { $MaxIter } else { Resolve-ProfileDefault "MaxIter" $Profile }
$StartLimit = if ($StartLimit -gt 0) { $StartLimit } else { Resolve-ProfileDefault "StartLimit" $Profile }
$WaitSeconds = if ($WaitSeconds -gt 0) { $WaitSeconds } else { Resolve-ProfileDefault "WaitSeconds" $Profile }
$TimeoutMinutes = if ($TimeoutMinutes -gt 0) { $TimeoutMinutes } else { Resolve-ProfileDefault "TimeoutMinutes" $Profile }
$StopGraceSeconds = if ($StopGraceSeconds -gt 0) { $StopGraceSeconds } else { Resolve-ProfileDefault "StopGraceSeconds" $Profile }
$ModuleTimeoutSeconds = if ($ModuleTimeoutSeconds -gt 0) { $ModuleTimeoutSeconds } else { Resolve-ProfileDefault "ModuleTimeoutSeconds" $Profile }
$StaleRunMinutes = if ($StaleRunMinutes -gt 0) { $StaleRunMinutes } else { Resolve-ProfileDefault "StaleRunMinutes" $Profile }
$Start = if ($null -ne $Start) { [bool]$Start } else { [bool](Resolve-ProfileDefault "Start" $Profile) }

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
Write-Host "Profile: $Profile"
Write-Host "Runs every $interval minute(s) while Windows is running."
Write-Host "Start enabled: $Start; max new passive runs per import: $StartLimit; max iterations per run: $MaxIter"
Write-Host "Watchdog timeout: $TimeoutMinutes minute(s)"
Write-Host "Graceful stop window: $StopGraceSeconds second(s); module timeout: $ModuleTimeoutSeconds second(s)"
Write-Host "Launcher: $launcher"
