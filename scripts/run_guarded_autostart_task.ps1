[CmdletBinding()]
param(
    [string]$Config = "",
    [int]$TimeoutMinutes = 25,
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

Write-TaskLog "starting automation cycle autostart_config=$configPath timeout_minutes=$TimeoutMinutes"
New-Item -ItemType Directory -Path $scheduledDir -Force | Out-Null
Set-Content -LiteralPath $stdoutPath -Value "" -Encoding UTF8
Set-Content -LiteralPath $stderrPath -Value "" -Encoding UTF8

$process = Start-Process `
    -FilePath $python `
    -ArgumentList $arguments `
    -WorkingDirectory $repoRoot `
    -WindowStyle Hidden `
    -PassThru `
    -RedirectStandardOutput $stdoutPath `
    -RedirectStandardError $stderrPath

if (-not $process.WaitForExit([Math]::Max(1, $TimeoutMinutes) * 60 * 1000)) {
    try {
        Stop-Process -Id $process.Id -Force -ErrorAction Stop
    } catch {
        Write-TaskLog "timed out and process already exited id=$($process.Id)"
    }
    Write-TaskLog "timed out process_id=$($process.Id)"
    exit 124
}

$exitCode = [int]$process.ExitCode
Write-TaskLog "completed exit_code=$exitCode"
exit $exitCode
