[CmdletBinding()]
param(
    [string]$DataDir = "",
    [Parameter(Mandatory = $true)][string]$StatusFile,
    [string]$Operator = "scheduled-remediation-ticket-status-import",
    [string]$ClosePolicy = "trust_external_status",
    [int]$TimeoutMinutes = 20,
    [switch]$Apply,
    [switch]$SelfTest
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path (Join-Path $scriptDir "..")).Path
$scheduledDir = Join-Path $scriptDir "scheduled"
$logPath = Join-Path $scheduledDir "forge_remediation_ticket_status_import.log"
$stdoutPath = Join-Path $scheduledDir "forge_remediation_ticket_status_import.stdout.log"
$stderrPath = Join-Path $scheduledDir "forge_remediation_ticket_status_import.stderr.log"

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

$resolvedStatusFile = (Resolve-Path -LiteralPath $StatusFile -ErrorAction Stop).Path
if ([string]::IsNullOrWhiteSpace($DataDir)) {
    $DataDir = Join-Path $repoRoot ".forge_data"
}
$resolvedDataDir = $DataDir
if (Test-Path -LiteralPath $DataDir) {
    $resolvedDataDir = (Resolve-Path -LiteralPath $DataDir).Path
}

$arguments = @(
    "-m",
    "forge.cli",
    "remediation",
    "import-ticket-statuses",
    "--data-dir",
    $resolvedDataDir,
    "--file",
    $resolvedStatusFile,
    "--operator",
    $Operator,
    "--close-policy",
    $ClosePolicy,
    "--json"
)
if (-not $Apply) {
    $arguments += "--dry-run"
}

Write-TaskLog "starting remediation ticket status import data_dir=$resolvedDataDir status_file=$resolvedStatusFile apply=$Apply close_policy=$ClosePolicy timeout_minutes=$TimeoutMinutes"
New-Item -ItemType Directory -Path $scheduledDir -Force | Out-Null
Set-Content -LiteralPath $stdoutPath -Value "" -Encoding UTF8
Set-Content -LiteralPath $stderrPath -Value "" -Encoding UTF8

$process = Start-Process `
    -FilePath "python" `
    -ArgumentList $arguments `
    -WorkingDirectory $repoRoot `
    -NoNewWindow `
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
