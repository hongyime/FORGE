[CmdletBinding()]
param(
    [string]$Config = "",
    [int]$TimeoutMinutes = 25,
    [switch]$Loop,
    [int]$EveryMinutes = 155,
    [int]$StartupDelayMinutes = 0,
    [int]$FailureBackoffMinutes = 30,
    [int]$MaxConsecutiveFailures = 3,
    [switch]$SelfTest
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path (Join-Path $scriptDir "..")).Path
$scheduledDir = Join-Path $scriptDir "scheduled"
$logPath = Join-Path $scheduledDir "forge_guarded_autostart.log"
$stdoutPath = Join-Path $scheduledDir "forge_guarded_autostart.stdout.log"
$stderrPath = Join-Path $scheduledDir "forge_guarded_autostart.stderr.log"

function Write-TaskLog {
    param([Parameter(Mandatory = $true)][string]$Message)
    New-Item -ItemType Directory -Path $scheduledDir -Force | Out-Null
    $stamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
    Add-Content -LiteralPath $logPath -Value "[$stamp] $Message" -Encoding UTF8
}

function ConvertTo-ProcessArgument {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)
    if ($Value -notmatch '[\s"]') {
        return $Value
    }
    return '"' + ($Value -replace '"', '\"') + '"'
}

function Join-ProcessArguments {
    param([Parameter(Mandatory = $true)][string[]]$Values)
    return (($Values | ForEach-Object { ConvertTo-ProcessArgument $_ }) -join " ")
}

function Stop-ProcessTree {
    param([Parameter(Mandatory = $true)][int]$RootProcessId)
    $taskkill = Join-Path $env:SystemRoot "System32\taskkill.exe"
    if (Test-Path -LiteralPath $taskkill) {
        & $taskkill /PID $RootProcessId /T /F | Out-Null
        return
    }
    Stop-Process -Id $RootProcessId -Force -ErrorAction Stop
}

if ($SelfTest) {
    Write-TaskLog "self-test ok runner=$PSCommandPath"
    Write-Output "self-test ok"
    exit 0
}

$python = Join-Path $repoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python)) {
    $python = "python"
}

$configPath = $Config
if ([string]::IsNullOrWhiteSpace($configPath)) {
    $configPath = Join-Path $repoRoot "imports\autostart.local.json"
}

$arguments = @(
    "-m",
    "forge.cli",
    "automation",
    "cycle",
    "--autostart-config",
    $configPath,
    "--apply",
    "--live",
    "--json"
)
$argumentText = Join-ProcessArguments $arguments

function Invoke-AutomationCycle {
    Write-TaskLog "starting automation cycle autostart_config=$configPath timeout_minutes=$TimeoutMinutes"
    New-Item -ItemType Directory -Path $scheduledDir -Force | Out-Null
    Set-Content -LiteralPath $stdoutPath -Value "" -Encoding UTF8
    Set-Content -LiteralPath $stderrPath -Value "" -Encoding UTF8

    $process = Start-Process `
        -FilePath $python `
        -ArgumentList $argumentText `
        -WorkingDirectory $repoRoot `
        -WindowStyle Hidden `
        -PassThru `
        -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath

    if (-not $process.WaitForExit([Math]::Max(1, $TimeoutMinutes) * 60 * 1000)) {
        try {
            Stop-ProcessTree -RootProcessId $process.Id
        } catch {
            Write-TaskLog "timed out and process already exited id=$($process.Id)"
        }
        Write-TaskLog "timed out process_tree_root_id=$($process.Id)"
        return 124
    }

    $exitCode = [int]$process.ExitCode
    Write-TaskLog "completed exit_code=$exitCode"
    return $exitCode
}

if (-not $Loop) {
    exit (Invoke-AutomationCycle)
}

$createdNew = $false
$mutex = New-Object System.Threading.Mutex($true, "Local\FORGE_Guarded_Autostart_Loop", [ref]$createdNew)
if (-not $createdNew) {
    Write-TaskLog "loop already running; exiting"
    exit 0
}

try {
    $delaySeconds = [Math]::Max(0, $StartupDelayMinutes) * 60
    $consecutiveFailures = 0
    if ($delaySeconds -gt 0) {
        Write-TaskLog "loop startup delay seconds=$delaySeconds"
        Start-Sleep -Seconds $delaySeconds
    }
    while ($true) {
        $exitCode = Invoke-AutomationCycle
        if ($exitCode -eq 0) {
            $consecutiveFailures = 0
            $sleepSeconds = [Math]::Max(5, $EveryMinutes) * 60
        } else {
            $consecutiveFailures += 1
            Write-TaskLog "loop cycle failed exit_code=$exitCode consecutive_failures=$consecutiveFailures"
            if ($consecutiveFailures -ge [Math]::Max(1, $MaxConsecutiveFailures)) {
                Write-TaskLog "loop exiting after max consecutive failures=$MaxConsecutiveFailures last_exit_code=$exitCode"
                exit $exitCode
            }
            $sleepSeconds = [Math]::Max(5, $FailureBackoffMinutes) * 60
        }
        Write-TaskLog "loop sleeping seconds=$sleepSeconds"
        Start-Sleep -Seconds $sleepSeconds
    }
} finally {
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}
