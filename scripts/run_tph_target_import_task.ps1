[CmdletBinding()]
param(
    [string]$ApiUrl = "http://127.0.0.1:8011/monitor/targets/export",
    [string]$TphEnvPath = "X:\01 REPOSITORIES\theprawnhunter\.env",
    [int]$Limit = 1000,
    [int]$MaxIter = 1,
    [int]$StartLimit = 1,
    [int]$WaitSeconds = 60,
    [int]$TimeoutMinutes = 25,
    [int]$StopGraceSeconds = 60,
    [int]$ModuleTimeoutSeconds = 240,
    [int]$StaleRunMinutes = 90,
    [switch]$NoStaleCleanup,
    [switch]$DryRun,
    [switch]$Start
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$runner = Join-Path $scriptDir "import_tph_targets.ps1"
$scheduledDir = Join-Path $scriptDir "scheduled"
$logPath = Join-Path $scheduledDir "forge_tph_import.log"
$stdoutPath = Join-Path $scheduledDir "forge_tph_import.stdout.log"
$stderrPath = Join-Path $scheduledDir "forge_tph_import.stderr.log"

function Write-TaskLog {
    param([Parameter(Mandatory = $true)][string]$Message)
    New-Item -ItemType Directory -Path $scheduledDir -Force | Out-Null
    $stamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
    Add-Content -LiteralPath $logPath -Value "[$stamp] $Message" -Encoding UTF8
}

function Get-ChildProcessIds {
    param([Parameter(Mandatory = $true)][int]$ParentProcessId)
    $children = @(Get-CimInstance Win32_Process | Where-Object { $_.ParentProcessId -eq $ParentProcessId })
    foreach ($child in $children) {
        [int]$child.ProcessId
        Get-ChildProcessIds -ParentProcessId ([int]$child.ProcessId)
    }
}

function Stop-ProcessTree {
    param([Parameter(Mandatory = $true)][int]$RootProcessId)
    $ids = @(Get-ChildProcessIds -ParentProcessId $RootProcessId) + $RootProcessId
    foreach ($id in ($ids | Select-Object -Unique | Sort-Object -Descending)) {
        try {
            Stop-Process -Id $id -Force -ErrorAction Stop
            Write-TaskLog "stopped process id=$id"
        } catch {
            Write-TaskLog "process id=$id already exited or could not be stopped"
        }
    }
}

function Stop-StaleImportProcesses {
    $repoRoot = (Resolve-Path (Join-Path $scriptDir "..")).Path
    $escapedRepo = [regex]::Escape($repoRoot)
    $patterns = @(
        "import_tph_targets\.ps1",
        "forge\.cli targets import",
        "forge\.cli kill-chain"
    )
    $matches = Get-CimInstance Win32_Process | Where-Object {
        $processCommandLine = [string]$_.CommandLine
        $isMatch = $_.ProcessId -ne $PID -and $processCommandLine -and $processCommandLine -match $escapedRepo
        $patternMatched = $false
        foreach ($pattern in $patterns) {
            if ($processCommandLine -match $pattern) {
                $patternMatched = $true
                break
            }
        }
        $isMatch -and $patternMatched
    }
    foreach ($proc in $matches) {
        Write-TaskLog "stale import process found id=$($proc.ProcessId) name=$($proc.Name); stopping tree"
        Stop-ProcessTree -RootProcessId ([int]$proc.ProcessId)
    }
}

function Quote-ProcessArgument {
    param([Parameter(Mandatory = $true)][string]$Value)
    return '"' + ($Value -replace '"', '\"') + '"'
}

function Mark-TimedOutRunsFailed {
    param([Parameter(Mandatory = $true)][string]$StartedAfterIso)
    $repoRoot = Resolve-Path (Join-Path $scriptDir "..")
    $python = Join-Path $repoRoot ".venv\Scripts\python.exe"
    if (-not (Test-Path $python)) {
        $python = (Get-Command python -ErrorAction Stop).Source
    }
    $code = @"
import sqlite3
import sys
from pathlib import Path

data_dir = Path(sys.argv[1])
cutoff = sys.argv[2]
message = "scheduled import watchdog timeout; process tree stopped"
for db_path in sorted((data_dir / "engagements").glob("*.db")):
    con = sqlite3.connect(db_path)
    try:
        tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "engagement_runs" not in tables:
            continue
        run_rows = con.execute(
            """
            SELECT id
            FROM engagement_runs
            WHERE run_kind='kill_chain'
              AND status='running'
              AND started_at >= ?
            """,
            (cutoff,),
        ).fetchall()
        if not run_rows:
            continue
        run_ids = [row[0] for row in run_rows]
        con.executemany(
            """
            UPDATE engagement_runs
            SET status='failed',
                error=?,
                completed_at=CURRENT_TIMESTAMP,
                updated_at=CURRENT_TIMESTAMP
            WHERE id=?
            """,
            [(message, run_id) for run_id in run_ids],
        )
        if "seed_runs" in tables:
            con.execute(
                """
                UPDATE seed_runs
                SET status='failed',
                    error=?,
                    completed_at=CURRENT_TIMESTAMP
                WHERE status='running'
                """,
                (message,),
            )
        con.commit()
        print(f"{db_path.name}: marked {len(run_ids)} timed-out run(s) failed")
    finally:
        con.close()
"@
    & $python -c $code (Join-Path $repoRoot ".forge_data") $StartedAfterIso | ForEach-Object {
        Write-TaskLog $_
    }
}

function Request-GracefulStopForTimedOutRuns {
    param([Parameter(Mandatory = $true)][string]$StartedAfterIso)
    $repoRoot = Resolve-Path (Join-Path $scriptDir "..")
    $python = Join-Path $repoRoot ".venv\Scripts\python.exe"
    if (-not (Test-Path $python)) {
        $python = (Get-Command python -ErrorAction Stop).Source
    }
    $code = @"
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

data_dir = Path(sys.argv[1])
cutoff = sys.argv[2]
control_dir = data_dir / "run_control"
control_dir.mkdir(parents=True, exist_ok=True)
payload = {
    "requested_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    "requested_by": "scheduled_import_watchdog",
    "reason": "scheduled import watchdog timeout; graceful stop requested",
}
for db_path in sorted((data_dir / "engagements").glob("*.db")):
    con = sqlite3.connect(db_path)
    try:
        tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "engagement_runs" not in tables:
            continue
        rows = con.execute(
            """
            SELECT DISTINCT engagement_id
            FROM engagement_runs
            WHERE run_kind='kill_chain'
              AND status='running'
              AND started_at >= ?
            """,
            (cutoff,),
        ).fetchall()
        for (engagement_id,) in rows:
            marker = control_dir / f"engagement_{int(engagement_id)}_stop.json"
            marker.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
            print(f"requested graceful stop engagement={int(engagement_id)}")
    finally:
        con.close()
"@
    & $python -c $code (Join-Path $repoRoot ".forge_data") $StartedAfterIso | ForEach-Object {
        Write-TaskLog $_
    }
}

function Mark-StaleRunningRunsFailed {
    $repoRoot = Resolve-Path (Join-Path $scriptDir "..")
    $python = Join-Path $repoRoot ".venv\Scripts\python.exe"
    if (-not (Test-Path $python)) {
        $python = (Get-Command python -ErrorAction Stop).Source
    }
    $staleBefore = (Get-Date).ToUniversalTime().AddMinutes(-1 * [Math]::Max(1, $StaleRunMinutes)).ToString("yyyy-MM-ddTHH:mm:ss")
    $code = @"
import sqlite3
import sys
from pathlib import Path

data_dir = Path(sys.argv[1])
cutoff = sys.argv[2]
message = "scheduled import stale-run recovery; no active supervisor retained this run"
for db_path in sorted((data_dir / "engagements").glob("*.db")):
    con = sqlite3.connect(db_path)
    try:
        tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "engagement_runs" not in tables:
            continue
        rows = con.execute(
            """
            SELECT id
            FROM engagement_runs
            WHERE run_kind='kill_chain'
              AND status='running'
              AND updated_at < ?
            """,
            (cutoff,),
        ).fetchall()
        if not rows:
            continue
        run_ids = [row[0] for row in rows]
        con.executemany(
            """
            UPDATE engagement_runs
            SET status='failed',
                error=?,
                completed_at=CURRENT_TIMESTAMP,
                updated_at=CURRENT_TIMESTAMP
            WHERE id=?
            """,
            [(message, run_id) for run_id in run_ids],
        )
        con.commit()
        print(f"{db_path.name}: recovered {len(run_ids)} stale running run(s)")
    finally:
        con.close()
"@
    & $python -c $code (Join-Path $repoRoot ".forge_data") $staleBefore | ForEach-Object {
        Write-TaskLog $_
    }
}

if (-not (Test-Path $runner)) {
    throw "import runner not found: $runner"
}

if (-not $NoStaleCleanup) {
    Stop-StaleImportProcesses
    Mark-StaleRunningRunsFailed
}

$args = @(
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy", "Bypass",
    "-File", (Quote-ProcessArgument $runner),
    "-ApiUrl", (Quote-ProcessArgument $ApiUrl),
    "-TphEnvPath", (Quote-ProcessArgument $TphEnvPath),
    "-Limit", [string]$Limit,
    "-MaxIter", [string]$MaxIter,
    "-StartLimit", [string]$StartLimit,
    "-WaitSeconds", [string]$WaitSeconds
)
if ($Start) {
    $args += "-Start"
}
if ($DryRun) {
    $args += "-DryRun"
}

$timeout = [Math]::Max(1, $TimeoutMinutes) * 60 * 1000
$startedAfter = (Get-Date).ToUniversalTime().AddMinutes(-1).ToString("yyyy-MM-ddTHH:mm:ss")
Write-TaskLog "starting import start=$([bool]$Start) limit=$Limit start_limit=$StartLimit max_iter=$MaxIter timeout_minutes=$TimeoutMinutes"
$startInfo = [System.Diagnostics.ProcessStartInfo]::new()
$startInfo.FileName = "powershell.exe"
$startInfo.Arguments = ($args -join " ")
$startInfo.WorkingDirectory = $scriptDir
$startInfo.UseShellExecute = $false
$startInfo.CreateNoWindow = $true
$startInfo.RedirectStandardOutput = $true
$startInfo.RedirectStandardError = $true
$startInfo.EnvironmentVariables["FORGE_MODULE_SUBPROCESS_TIMEOUT_SECONDS"] = [string][Math]::Max(30, $ModuleTimeoutSeconds)
$process = [System.Diagnostics.Process]::new()
$process.StartInfo = $startInfo
$null = $process.Start()
$stdoutTask = $process.StandardOutput.ReadToEndAsync()
$stderrTask = $process.StandardError.ReadToEndAsync()

if (-not $process.WaitForExit($timeout)) {
    Write-TaskLog "timeout exceeded; requesting graceful stop root=$($process.Id)"
    Request-GracefulStopForTimedOutRuns -StartedAfterIso $startedAfter
    if ($process.WaitForExit([Math]::Max(1, $StopGraceSeconds) * 1000)) {
        $process.WaitForExit()
        Add-Content -LiteralPath $stdoutPath -Value $stdoutTask.Result -Encoding UTF8
        Add-Content -LiteralPath $stderrPath -Value $stderrTask.Result -Encoding UTF8
        Write-TaskLog "finished import after graceful stop exit=$($process.ExitCode)"
        exit $process.ExitCode
    }
    Write-TaskLog "graceful stop window expired; stopping process tree root=$($process.Id)"
    Stop-ProcessTree -RootProcessId $process.Id
    Mark-TimedOutRunsFailed -StartedAfterIso $startedAfter
    Add-Content -LiteralPath $stdoutPath -Value $stdoutTask.Result -Encoding UTF8
    Add-Content -LiteralPath $stderrPath -Value $stderrTask.Result -Encoding UTF8
    Write-TaskLog "finished import exit=timeout"
    exit 124
}

$process.WaitForExit()
Add-Content -LiteralPath $stdoutPath -Value $stdoutTask.Result -Encoding UTF8
Add-Content -LiteralPath $stderrPath -Value $stderrTask.Result -Encoding UTF8
Write-TaskLog "finished import exit=$($process.ExitCode)"
exit $process.ExitCode
