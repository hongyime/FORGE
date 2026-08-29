[CmdletBinding()]
param(
    [string]$ApiUrl = "http://127.0.0.1:8011/monitor/targets/export",
    [string]$TphEnvPath = "X:\01 REPOSITORIES\theprawnhunter\.env",
    [int]$Limit = 100,
    [int]$MaxIter = 1,
    [int]$MaxRuntimeMinutes = 25,
    [int]$StartLimit = 1,
    [int]$WaitSeconds = 60,
    [int]$TimeoutMinutes = 45,
    [int]$StopGraceSeconds = 90,
    [int]$WatchdogHelperTimeoutSeconds = 120,
    [int]$TimeoutRecoveryHelperSeconds = 10,
    [int]$StaleHelperFileMinutes = 360,
    [int]$ModuleTimeoutSeconds = 900,
    [int]$StaleRunMinutes = 120,
    [switch]$NoStaleCleanup,
    [switch]$StaleHelperProcessCleanup,
    [switch]$StaleProcessCleanup,
    [switch]$WatchdogSelfTest,
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
$taskBudgetMinutes = [Math]::Max(1, $TimeoutMinutes)
$taskDeadline = (Get-Date).AddMinutes($taskBudgetMinutes)
$childTimeoutGraceSeconds = 120

function Write-TaskLog {
    param([Parameter(Mandatory = $true)][string]$Message)
    New-Item -ItemType Directory -Path $scheduledDir -Force | Out-Null
    $stamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
    Add-Content -LiteralPath $logPath -Value "[$stamp] $Message" -Encoding UTF8
}

function Get-RemainingTaskBudgetMilliseconds {
    param([int]$ReserveSeconds = 0)
    $remaining = ($taskDeadline - (Get-Date)).TotalMilliseconds - ([Math]::Max(0, $ReserveSeconds) * 1000)
    return [Math]::Max(0, [int][Math]::Floor($remaining))
}

function Get-RemainingTaskBudgetSeconds {
    param([int]$ReserveSeconds = 0)
    return [Math]::Max(0, [int][Math]::Floor((Get-RemainingTaskBudgetMilliseconds -ReserveSeconds $ReserveSeconds) / 1000))
}

function Get-EffectiveChildRuntimeMinutes {
    param(
        [Parameter(Mandatory = $true)][int]$RequestedMinutes,
        [Parameter(Mandatory = $true)][int]$Starts,
        [Parameter(Mandatory = $true)][int]$ReserveSeconds
    )
    if ($Starts -le 0) {
        return [Math]::Max(1, $RequestedMinutes)
    }
    $availableSeconds = ([Math]::Max(1, $TimeoutMinutes) * 60) - [Math]::Max(0, $ReserveSeconds)
    $perStartSeconds = [Math]::Floor($availableSeconds / [Math]::Max(1, $Starts))
    $runtimeSeconds = $perStartSeconds - $childTimeoutGraceSeconds
    $effectiveMinutes = [int][Math]::Floor($runtimeSeconds / 60)
    if ($effectiveMinutes -lt 1) {
        throw "scheduled import budget cannot fit StartLimit=$Starts within TimeoutMinutes=$TimeoutMinutes; lower StartLimit or increase TimeoutMinutes"
    }
    return [Math]::Min([Math]::Max(1, $RequestedMinutes), $effectiveMinutes)
}

function Get-Win32Processes {
    param([Parameter(Mandatory = $true)][string]$Filter)
    try {
        return @(Get-CimInstance Win32_Process -Filter $Filter -OperationTimeoutSec 5 -ErrorAction Stop)
    } catch {
        Write-TaskLog "process query failed filter=$Filter error=$($_.Exception.Message)"
        return @()
    }
}

function Get-ChildProcessIds {
    param([Parameter(Mandatory = $true)][int]$ParentProcessId)
    $children = Get-Win32Processes -Filter "ParentProcessId=$ParentProcessId"
    foreach ($child in $children) {
        [int]$child.ProcessId
        Get-ChildProcessIds -ParentProcessId ([int]$child.ProcessId)
    }
}

function Stop-ProcessIds {
    param([Parameter(Mandatory = $true)][int[]]$ProcessIds)
    foreach ($id in ($ProcessIds | Select-Object -Unique | Sort-Object -Descending)) {
        try {
            Stop-Process -Id $id -Force -ErrorAction Stop
            Write-TaskLog "stopped process id=$id"
        } catch {
            Write-TaskLog "process id=$id already exited or could not be stopped"
        }
    }
}

function Stop-ProcessTree {
    param([Parameter(Mandatory = $true)][int]$RootProcessId)
    $ids = @(Get-ChildProcessIds -ParentProcessId $RootProcessId) + $RootProcessId
    Stop-ProcessIds -ProcessIds $ids
}

function Stop-StaleImportProcesses {
    $repoRoot = (Resolve-Path (Join-Path $scriptDir "..")).Path
    $escapedRepo = [regex]::Escape($repoRoot)
    $patterns = @(
        "import_tph_targets\.ps1",
        "forge\.cli targets import",
        "forge\.cli kill-chain"
    )
    $processFilter = "Name='powershell.exe' OR Name='pwsh.exe' OR Name='python.exe' OR Name='pythonw.exe'"
    $matches = Get-Win32Processes -Filter $processFilter | Where-Object {
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

function Test-LegacyInlineWatchdogHelperCommandLine {
    param([AllowEmptyString()][string]$CommandLine)
    if (-not $CommandLine) {
        return $false
    }

    $usesInlinePython = (
        $CommandLine -match '(?i)(?:^|\s|")(?:[^"]*[\\/])?pythonw?(?:\.exe)?(?:"|\s).*?\s-[c]\s'
    )
    if (-not $usesInlinePython) {
        return $false
    }

    $markers = @(
        "scheduled import watchdog timeout",
        "scheduled import stale-run recovery",
        "scheduled_import_watchdog",
        "engagement_runs",
        "seed_runs"
    )
    foreach ($marker in $markers) {
        if ($CommandLine -like "*$marker*") {
            return $true
        }
    }
    return $false
}

function Stop-StaleWatchdogHelperProcesses {
    param([int]$OlderThanMinutes = $StaleHelperFileMinutes)
    $cutoff = (Get-Date).AddMinutes(-1 * [Math]::Max(10, $OlderThanMinutes))
    $processFilter = "Name='python.exe' OR Name='pythonw.exe'"
    $matches = Get-Win32Processes -Filter $processFilter | Where-Object {
        $processCommandLine = [string]$_.CommandLine
        $isTempScriptWatchdog = $processCommandLine -match "forge_tph_watchdog_[0-9a-f]+\.py"
        $isLegacyInlineWatchdog = Test-LegacyInlineWatchdogHelperCommandLine -CommandLine $processCommandLine
        if (-not $isTempScriptWatchdog -and -not $isLegacyInlineWatchdog) {
            $false
        } else {
            try {
                ([datetime]$_.CreationDate) -lt $cutoff
            } catch {
                Write-TaskLog "watchdog helper process age check skipped id=$($_.ProcessId) error=$($_.Exception.Message)"
                $false
            }
        }
    }
    foreach ($proc in $matches) {
        $kind = "temp-script"
        if (Test-LegacyInlineWatchdogHelperCommandLine -CommandLine ([string]$proc.CommandLine)) {
            $kind = "legacy-inline"
        }
        Write-TaskLog "stale $kind watchdog helper process found id=$($proc.ProcessId) name=$($proc.Name); stopping tree"
        Stop-ProcessTree -RootProcessId ([int]$proc.ProcessId)
    }
}

function Remove-StaleWatchdogHelperFiles {
    param([int]$OlderThanMinutes = $StaleHelperFileMinutes)
    $cutoff = (Get-Date).AddMinutes(-1 * [Math]::Max(10, $OlderThanMinutes))
    $tempDir = [System.IO.Path]::GetTempPath()
    try {
        $files = @(Get-ChildItem -LiteralPath $tempDir -Filter "forge_tph_watchdog_*.py" -File -ErrorAction Stop | Where-Object {
            $_.LastWriteTime -lt $cutoff
        })
    } catch {
        Write-TaskLog "stale watchdog helper file scan skipped: $($_.Exception.Message)"
        return
    }
    foreach ($file in $files) {
        try {
            Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
            Write-TaskLog "removed stale watchdog helper file path=$($file.FullName)"
        } catch {
            Write-TaskLog "stale watchdog helper file cleanup skipped path=$($file.FullName) error=$($_.Exception.Message)"
        }
    }
}

function Quote-WindowsProcessArgument {
    param([AllowEmptyString()][string]$Value)
    if ($null -eq $Value -or $Value.Length -eq 0) {
        return '""'
    }
    if ($Value -notmatch '[\s"]') {
        return $Value
    }

    $quoted = [System.Text.StringBuilder]::new()
    [void]$quoted.Append('"')
    $backslashes = 0
    foreach ($char in $Value.ToCharArray()) {
        if ($char -eq '\') {
            $backslashes += 1
            continue
        }
        if ($char -eq '"') {
            [void]$quoted.Append(('\' * (($backslashes * 2) + 1)))
            [void]$quoted.Append('"')
            $backslashes = 0
            continue
        }
        if ($backslashes -gt 0) {
            [void]$quoted.Append(('\' * $backslashes))
            $backslashes = 0
        }
        [void]$quoted.Append($char)
    }
    if ($backslashes -gt 0) {
        [void]$quoted.Append(('\' * ($backslashes * 2)))
    }
    [void]$quoted.Append('"')
    return $quoted.ToString()
}

function Initialize-WindowsJobObjectSupport {
    if ("ForgeWin32Job" -as [type]) {
        return
    }

    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class ForgeWin32Job
{
    public const int JobObjectExtendedLimitInformation = 9;
    public const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;

    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetInformationJobObject(
        IntPtr hJob,
        int JobObjectInfoClass,
        IntPtr lpJobObjectInfo,
        uint cbJobObjectInfoLength
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@
}

function Get-LastWin32ErrorMessage {
    $errorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    return ([System.ComponentModel.Win32Exception]::new($errorCode)).Message
}

function New-KillOnCloseJobObject {
    Initialize-WindowsJobObjectSupport
    $jobHandle = [ForgeWin32Job]::CreateJobObject([IntPtr]::Zero, $null)
    if ($jobHandle -eq [IntPtr]::Zero) {
        throw "CreateJobObject failed: $(Get-LastWin32ErrorMessage)"
    }

    $info = [ForgeWin32Job+JOBOBJECT_EXTENDED_LIMIT_INFORMATION]::new()
    $info.BasicLimitInformation.LimitFlags = [ForgeWin32Job]::JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    $size = [System.Runtime.InteropServices.Marshal]::SizeOf($info)
    $buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size)
    try {
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($info, $buffer, $false)
        $success = [ForgeWin32Job]::SetInformationJobObject(
            $jobHandle,
            [ForgeWin32Job]::JobObjectExtendedLimitInformation,
            $buffer,
            [uint32]$size
        )
        if (-not $success) {
            $message = Get-LastWin32ErrorMessage
            [void][ForgeWin32Job]::CloseHandle($jobHandle)
            throw "SetInformationJobObject failed: $message"
        }
    } finally {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)
    }

    return $jobHandle
}

function Add-ProcessToJobObject {
    param(
        [Parameter(Mandatory = $true)][IntPtr]$JobHandle,
        [Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process
    )
    if ($JobHandle -eq [IntPtr]::Zero -or $Process.HasExited) {
        return
    }
    $success = [ForgeWin32Job]::AssignProcessToJobObject($JobHandle, $Process.Handle)
    if (-not $success) {
        throw "AssignProcessToJobObject failed for process id=$($Process.Id): $(Get-LastWin32ErrorMessage)"
    }
}

function Close-JobObject {
    param([Parameter(Mandatory = $true)][IntPtr]$JobHandle)
    if ($JobHandle -ne [IntPtr]::Zero) {
        [void][ForgeWin32Job]::CloseHandle($JobHandle)
    }
}

function Invoke-WatchdogPython {
    param(
        [Parameter(Mandatory = $true)][string]$Python,
        [Parameter(Mandatory = $true)][string]$Code,
        [string[]]$ScriptArguments = @(),
        [int]$TimeoutSeconds = $WatchdogHelperTimeoutSeconds
    )
    $tempScript = Join-Path ([System.IO.Path]::GetTempPath()) ("forge_tph_watchdog_{0}.py" -f ([guid]::NewGuid().ToString("N")))
    try {
        [System.IO.File]::WriteAllText($tempScript, $Code, [System.Text.UTF8Encoding]::new($false))
        $helperArgs = @($tempScript) + $ScriptArguments
        $helperStartInfo = [System.Diagnostics.ProcessStartInfo]::new()
        $helperStartInfo.FileName = $Python
        $helperStartInfo.Arguments = (($helperArgs | ForEach-Object { Quote-WindowsProcessArgument $_ }) -join " ")
        $helperStartInfo.WorkingDirectory = $scriptDir
        $helperStartInfo.UseShellExecute = $false
        $helperStartInfo.CreateNoWindow = $true
        $helperStartInfo.RedirectStandardOutput = $true
        $helperStartInfo.RedirectStandardError = $true

        $helper = [System.Diagnostics.Process]::new()
        $helper.StartInfo = $helperStartInfo
        $helperJobHandle = [IntPtr]::Zero
        try {
            $helperJobHandle = New-KillOnCloseJobObject
            $null = $helper.Start()
            Add-ProcessToJobObject -JobHandle $helperJobHandle -Process $helper
            $stdoutTask = $helper.StandardOutput.ReadToEndAsync()
            $stderrTask = $helper.StandardError.ReadToEndAsync()
            if (-not $helper.WaitForExit([Math]::Max(1, $TimeoutSeconds) * 1000)) {
                Write-TaskLog "python watchdog helper timeout; closing helper job root=$($helper.Id)"
                Close-JobObject -JobHandle $helperJobHandle
                $helperJobHandle = [IntPtr]::Zero
                if (-not $helper.WaitForExit(5000)) {
                    try {
                        Stop-Process -Id $helper.Id -Force -ErrorAction Stop
                        Write-TaskLog "stopped python watchdog helper root id=$($helper.Id)"
                        $helper.WaitForExit(5000) | Out-Null
                    } catch {
                        Write-TaskLog "python watchdog helper root id=$($helper.Id) already exited or could not be stopped"
                    }
                }
                throw "python watchdog helper timed out after $TimeoutSeconds second(s)"
            }
            $helper.WaitForExit()

            $stdout = $stdoutTask.Result
            $stderr = $stderrTask.Result
            foreach ($line in ($stdout -split "\r?\n")) {
                if ($line) {
                    $line
                }
            }
            foreach ($line in ($stderr -split "\r?\n")) {
                if ($line) {
                    "stderr: $line"
                }
            }
            if ($helper.ExitCode -ne 0) {
                throw "python watchdog helper failed exit=$($helper.ExitCode)"
            }
        } finally {
            Close-JobObject -JobHandle $helperJobHandle
        }
    } finally {
        for ($attempt = 1; $attempt -le 5; $attempt++) {
            try {
                Remove-Item -LiteralPath $tempScript -ErrorAction Stop
                break
            } catch {
                if ($attempt -eq 5 -or -not (Test-Path -LiteralPath $tempScript)) {
                    break
                }
                Start-Sleep -Milliseconds 200
            }
        }
    }
}

function Invoke-OptionalRecoveryStep {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )
    try {
        & $Action
    } catch {
        Write-TaskLog "$Name skipped: $($_.Exception.Message)"
    }
}

function Test-WatchdogPythonQuoting {
    param([Parameter(Mandatory = $true)][string]$Python)
    $code = @"
import sys

message = "scheduled import watchdog self-test; quotes preserved"
expected_arg = 'C:\\Forge Watchdog Self Test\\argument with spaces and "quotes"'
if sys.argv[1] != expected_arg:
    raise SystemExit(f"argument quoting failed: {sys.argv[1]!r}")
print(message)
"@
    Invoke-WatchdogPython -Python $Python -Code $code -ScriptArguments @('C:\Forge Watchdog Self Test\argument with spaces and "quotes"') | ForEach-Object {
        Write-TaskLog $_
    }
}

function Mark-TimedOutRunsFailed {
    param(
        [Parameter(Mandatory = $true)][string]$StartedAfterIso,
        [int]$TimeoutSeconds = $WatchdogHelperTimeoutSeconds
    )
    $repoRoot = Resolve-Path (Join-Path $scriptDir "..")
    $python = Join-Path $repoRoot ".venv\Scripts\python.exe"
    if (-not (Test-Path $python)) {
        $python = (Get-Command python -ErrorAction Stop).Source
    }
    $code = @"
import concurrent.futures
import os
import sqlite3
import sys
from pathlib import Path

data_dir = Path(sys.argv[1])
cutoff = sys.argv[2]
message = "scheduled import watchdog timeout; process tree stopped"


def scan_db(db_path):
    con = None
    try:
        con = sqlite3.connect(db_path, timeout=1.0)
        con.execute("PRAGMA busy_timeout=1000")
        tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "engagement_runs" not in tables:
            return []
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
            return []
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
        return [f"{db_path.name}: marked {len(run_ids)} timed-out run(s) failed"]
    except sqlite3.Error as exc:
        return [f"{db_path.name}: skipped watchdog timeout recovery ({exc.__class__.__name__}: {exc})"]
    finally:
        if con is not None:
            con.close()


paths = sorted((data_dir / "engagements").glob("*.db"))
workers = min(16, max(1, os.cpu_count() or 4), max(1, len(paths)))
with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
    for lines in pool.map(scan_db, paths):
        for line in lines:
            print(line)
"@
    Invoke-WatchdogPython -Python $python -Code $code -ScriptArguments @((Join-Path $repoRoot ".forge_data"), $StartedAfterIso) -TimeoutSeconds $TimeoutSeconds | ForEach-Object {
        Write-TaskLog $_
    }
}

function Request-GracefulStopForTimedOutRuns {
    param(
        [Parameter(Mandatory = $true)][string]$StartedAfterIso,
        [int]$TimeoutSeconds = $WatchdogHelperTimeoutSeconds
    )
    $repoRoot = Resolve-Path (Join-Path $scriptDir "..")
    $python = Join-Path $repoRoot ".venv\Scripts\python.exe"
    if (-not (Test-Path $python)) {
        $python = (Get-Command python -ErrorAction Stop).Source
    }
    $code = @"
import concurrent.futures
import json
import os
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


def scan_db(db_path):
    con = None
    try:
        con = sqlite3.connect(db_path, timeout=1.0)
        con.execute("PRAGMA busy_timeout=1000")
        tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "engagement_runs" not in tables:
            return []
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
        messages = []
        for (engagement_id,) in rows:
            marker = control_dir / f"engagement_{int(engagement_id)}_stop.json"
            marker.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
            messages.append(f"requested graceful stop engagement={int(engagement_id)}")
        return messages
    except sqlite3.Error as exc:
        return [f"{db_path.name}: skipped graceful-stop recovery ({exc.__class__.__name__}: {exc})"]
    finally:
        if con is not None:
            con.close()


paths = sorted((data_dir / "engagements").glob("*.db"))
workers = min(16, max(1, os.cpu_count() or 4), max(1, len(paths)))
with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
    for lines in pool.map(scan_db, paths):
        for line in lines:
            print(line)
"@
    Invoke-WatchdogPython -Python $python -Code $code -ScriptArguments @((Join-Path $repoRoot ".forge_data"), $StartedAfterIso) -TimeoutSeconds $TimeoutSeconds | ForEach-Object {
        Write-TaskLog $_
    }
}

function Mark-StaleRunningRunsFailed {
    param([int]$TimeoutSeconds = $WatchdogHelperTimeoutSeconds)
    $repoRoot = Resolve-Path (Join-Path $scriptDir "..")
    $python = Join-Path $repoRoot ".venv\Scripts\python.exe"
    if (-not (Test-Path $python)) {
        $python = (Get-Command python -ErrorAction Stop).Source
    }
    $staleBefore = (Get-Date).ToUniversalTime().AddMinutes(-1 * [Math]::Max(1, $StaleRunMinutes)).ToString("yyyy-MM-ddTHH:mm:ss")
    $code = @"
import concurrent.futures
import os
import sqlite3
import sys
from pathlib import Path

data_dir = Path(sys.argv[1])
cutoff = sys.argv[2]
message = "scheduled import stale-run recovery; no active supervisor retained this run"


def scan_db(db_path):
    con = None
    try:
        con = sqlite3.connect(db_path, timeout=1.0)
        con.execute("PRAGMA busy_timeout=1000")
        tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "engagement_runs" not in tables:
            return []
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
            return []
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
        return [f"{db_path.name}: recovered {len(run_ids)} stale running run(s)"]
    except sqlite3.Error as exc:
        return [f"{db_path.name}: skipped stale-run recovery ({exc.__class__.__name__}: {exc})"]
    finally:
        if con is not None:
            con.close()


paths = sorted((data_dir / "engagements").glob("*.db"))
workers = min(16, max(1, os.cpu_count() or 4), max(1, len(paths)))
with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
    for lines in pool.map(scan_db, paths):
        for line in lines:
            print(line)
"@
    Invoke-WatchdogPython -Python $python -Code $code -ScriptArguments @((Join-Path $repoRoot ".forge_data"), $staleBefore) -TimeoutSeconds $TimeoutSeconds | ForEach-Object {
        Write-TaskLog $_
    }
}

if (-not (Test-Path $runner)) {
    throw "import runner not found: $runner"
}

if ($WatchdogSelfTest) {
    $repoRoot = Resolve-Path (Join-Path $scriptDir "..")
    $python = Join-Path $repoRoot ".venv\Scripts\python.exe"
    if (-not (Test-Path $python)) {
        $python = (Get-Command python -ErrorAction Stop).Source
    }
    Test-WatchdogPythonQuoting -Python $python
    exit 0
}

if (-not $NoStaleCleanup) {
    Remove-StaleWatchdogHelperFiles -OlderThanMinutes $StaleHelperFileMinutes
    if ($StaleHelperProcessCleanup) {
        Stop-StaleWatchdogHelperProcesses -OlderThanMinutes $StaleHelperFileMinutes
    } else {
        Write-TaskLog "skipping stale watchdog helper process scan; stale temp-file cleanup remains enabled"
    }
    if ($StaleProcessCleanup) {
        Stop-StaleImportProcesses
    } else {
        Write-TaskLog "skipping stale process scan; watchdog job handles new import child processes"
    }
    $staleRecoveryTimeoutSeconds = Get-RemainingTaskBudgetSeconds -ReserveSeconds ([Math]::Max(30, $StopGraceSeconds + 30))
    if ($staleRecoveryTimeoutSeconds -gt 0) {
        Invoke-OptionalRecoveryStep -Name "stale-run recovery" -Action {
            Mark-StaleRunningRunsFailed -TimeoutSeconds ([Math]::Min($WatchdogHelperTimeoutSeconds, $staleRecoveryTimeoutSeconds))
        }
    } else {
        Write-TaskLog "stale-run recovery skipped: no remaining task budget"
    }
}

$args = @(
    "-NoProfile",
    "-NonInteractive",
    "-WindowStyle", "Hidden",
    "-ExecutionPolicy", "Bypass",
    "-File", (Quote-WindowsProcessArgument $runner),
    "-ApiUrl", (Quote-WindowsProcessArgument $ApiUrl),
    "-TphEnvPath", (Quote-WindowsProcessArgument $TphEnvPath),
    "-Limit", [string]$Limit,
    "-MaxIter", [string]$MaxIter,
    "-MaxRuntimeMinutes", [string]$MaxRuntimeMinutes,
    "-StartLimit", [string]$StartLimit,
    "-WaitSeconds", [string]$WaitSeconds
)
if ($Start) {
    $args += "-Start"
}
if ($DryRun) {
    $args += "-DryRun"
}

$timeoutCleanupReserveSeconds = [Math]::Max(
    45,
    [Math]::Max(1, $StopGraceSeconds) + [Math]::Max(1, $TimeoutRecoveryHelperSeconds) + 30
)
$effectiveStartLimit = if ($Start) { [Math]::Max(1, $StartLimit) } else { 0 }
$effectiveMaxRuntimeMinutes = Get-EffectiveChildRuntimeMinutes `
    -RequestedMinutes $MaxRuntimeMinutes `
    -Starts $effectiveStartLimit `
    -ReserveSeconds $timeoutCleanupReserveSeconds
$maxRuntimeIndex = $args.IndexOf("-MaxRuntimeMinutes")
if ($maxRuntimeIndex -ge 0 -and ($maxRuntimeIndex + 1) -lt $args.Count) {
    $args[$maxRuntimeIndex + 1] = [string]$effectiveMaxRuntimeMinutes
}
$timeout = Get-RemainingTaskBudgetMilliseconds -ReserveSeconds $timeoutCleanupReserveSeconds
if ($timeout -lt 1000) {
    Write-TaskLog "import skipped: no remaining task budget after startup and cleanup reserve"
    exit 124
}
$startedAfter = (Get-Date).ToUniversalTime().AddMinutes(-1).ToString("yyyy-MM-ddTHH:mm:ss")
Write-TaskLog "starting import start=$([bool]$Start) limit=$Limit start_limit=$StartLimit max_iter=$MaxIter requested_max_runtime_minutes=$MaxRuntimeMinutes effective_max_runtime_minutes=$effectiveMaxRuntimeMinutes task_timeout_minutes=$TimeoutMinutes import_timeout_seconds=$([Math]::Floor($timeout / 1000))"
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
$jobHandle = [IntPtr]::Zero
try {
    $jobHandle = New-KillOnCloseJobObject
    $null = $process.Start()
    Add-ProcessToJobObject -JobHandle $jobHandle -Process $process
    Write-TaskLog "attached import process to watchdog job root=$($process.Id)"
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()

    if (-not $process.WaitForExit($timeout)) {
        Write-TaskLog "timeout exceeded; requesting graceful stop root=$($process.Id)"
        $recoveryTimeoutSeconds = Get-RemainingTaskBudgetSeconds -ReserveSeconds (
            [Math]::Max(20, [Math]::Max(1, $StopGraceSeconds) + 20)
        )
        Invoke-OptionalRecoveryStep -Name "graceful-stop request" -Action {
            Request-GracefulStopForTimedOutRuns -StartedAfterIso $startedAfter -TimeoutSeconds (
                [Math]::Min(
                    [Math]::Max(1, $TimeoutRecoveryHelperSeconds),
                    [Math]::Max(1, $recoveryTimeoutSeconds)
                )
            )
        }
        $graceMilliseconds = [Math]::Min(
            [Math]::Max(1, $StopGraceSeconds) * 1000,
            [Math]::Max(0, (Get-RemainingTaskBudgetMilliseconds -ReserveSeconds 20))
        )
        if ($graceMilliseconds -gt 0 -and $process.WaitForExit($graceMilliseconds)) {
            $process.WaitForExit()
            Add-Content -LiteralPath $stdoutPath -Value $stdoutTask.Result -Encoding UTF8
            Add-Content -LiteralPath $stderrPath -Value $stderrTask.Result -Encoding UTF8
            Write-TaskLog "finished import after graceful stop exit=$($process.ExitCode)"
            exit $process.ExitCode
        }
        $descendantIdsBeforeJobClose = @(Get-ChildProcessIds -ParentProcessId ([int]$process.Id))
        if ($descendantIdsBeforeJobClose.Count -gt 0) {
            Write-TaskLog "captured import child process ids before watchdog close root=$($process.Id) children=$($descendantIdsBeforeJobClose -join ',')"
        }
        Write-TaskLog "graceful stop window expired; closing watchdog job root=$($process.Id)"
        Close-JobObject -JobHandle $jobHandle
        $jobHandle = [IntPtr]::Zero
        $remainingProcessIds = @($descendantIdsBeforeJobClose) + @(Get-ChildProcessIds -ParentProcessId ([int]$process.Id))
        if (-not $process.HasExited) {
            $remainingProcessIds += [int]$process.Id
        }
        if ($remainingProcessIds.Count -gt 0) {
            Write-TaskLog "stopping remaining import process ids after watchdog close root=$($process.Id) candidates=$($remainingProcessIds -join ',')"
            Stop-ProcessIds -ProcessIds $remainingProcessIds
        }
        if (-not $process.WaitForExit(3000)) {
            try {
                Stop-Process -Id $process.Id -Force -ErrorAction Stop
                Write-TaskLog "stopped import root process id=$($process.Id)"
                $process.WaitForExit(3000) | Out-Null
            } catch {
                Write-TaskLog "import root process id=$($process.Id) already exited or could not be stopped"
            }
        }
        $markTimeoutSeconds = Get-RemainingTaskBudgetSeconds -ReserveSeconds 5
        if ($markTimeoutSeconds -gt 0) {
            Invoke-OptionalRecoveryStep -Name "timed-out run marking" -Action {
                Mark-TimedOutRunsFailed -StartedAfterIso $startedAfter -TimeoutSeconds ([Math]::Min($WatchdogHelperTimeoutSeconds, $markTimeoutSeconds))
            }
        } else {
            Write-TaskLog "timed-out run marking skipped: no remaining task budget"
        }
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
} finally {
    Close-JobObject -JobHandle $jobHandle
}
