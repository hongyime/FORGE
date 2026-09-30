#!/usr/bin/env pwsh
# scripts/run-canaries.ps1
#
# Run all 16 FORGE Rust xtask verify canaries and report results.
# Exit 0 if all pass, non-zero if any fail.
#
# Usage:
#   .\scripts\run-canaries.ps1              # full run, all 16 canaries
#   .\scripts\run-canaries.ps1 -Quick        # only fast canaries (skip heavy ones)
#   .\scripts\run-canaries.ps1 -SkipBuild    # assume forge-xtask already built

[CmdletBinding()]
param(
    [switch]$Quick,
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
$NativeDir = Join-Path $RepoRoot 'native'
$Bin = Join-Path $NativeDir 'target\debug\forge-xtask.exe'
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$EvidenceRoot = Join-Path $RepoRoot ".omo\evidence\rust-rewrite\canary-run-$Stamp"
$LogFile = Join-Path $RepoRoot ".omo\evidence\rust-rewrite\canary-log-$Stamp.log"

New-Item -ItemType Directory -Force -Path (Split-Path $LogFile) | Out-Null

# MSVC toolchain env (required for cargo on this host)
$env:PATH = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64;$env:PATH"
$env:LIB = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\lib\x64;C:\Program Files (x86)\Windows Kits\10\lib\10.0.26100.0\um\x64;C:\Program Files (x86)\Windows Kits\10\lib\10.0.26100.0\ucrt\x64"
$env:INCLUDE = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\include;C:\Program Files (x86)\Windows Kits\10\include\10.0.26100.0\ucrt;C:\Program Files (x86)\Windows Kits\10\include\10.0.26100.0\um;C:\Program Files (x86)\Windows Kits\10\include\10.0.26100.0\shared"

function Write-Both {
    param($msg)
    Write-Host $msg
    $msg | Out-File $LogFile -Append
}

Write-Both "=== FORGE Canary Runner ==="
Write-Both "Timestamp: $Stamp"
Write-Both "Repo: $RepoRoot"
Write-Both "Git HEAD: $(git -C $RepoRoot rev-parse --short HEAD)"
Write-Both "Mode: $(if ($Quick) { 'quick' } else { 'full' })"
Write-Both ""

# Build once, offline
if (-not $SkipBuild) {
    Write-Both "--- Building forge-xtask ---"
    Push-Location $NativeDir
    try {
        $buildOutput = cargo build -p forge-xtask --offline 2>&1
        $buildTail = $buildOutput | Select-Object -Last 3 | Out-String
        Write-Both $buildTail.TrimEnd()
        if ($LASTEXITCODE -ne 0) {
            Write-Both "ERROR: cargo build failed"
            exit 2
        }
    }
    finally { Pop-Location }
}

if (-not (Test-Path $Bin)) {
    Write-Both "ERROR: forge-xtask binary not found at $Bin"
    exit 3
}

# Full canary set (16). Quick mode skips the slowest heavies.
$AllCases = @(
    'artifacts', 'enrichment', 'validation', 'scoring', 'pipeline',
    'graphs', 'reports', 'monitoring', 'remediation', 'operations',
    'service-parity', 'cli', 'platform-api', 'engagement-api', 'ui', 'release'
)
$QuickSkip = @('service-parity', 'platform-api', 'engagement-api')
$Cases = if ($Quick) { $AllCases | Where-Object { $_ -notin $QuickSkip } } else { $AllCases }

Write-Both "--- Running $($Cases.Count) canaries ---"
$Passed = 0
$Failed = @()
$Timings = @()

foreach ($case in $Cases) {
    $caseDir = Join-Path $EvidenceRoot $case
    New-Item -ItemType Directory -Force -Path $caseDir | Out-Null
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $output = & $Bin verify $case --evidence $caseDir --root $RepoRoot 2>&1
    $exitCode = $LASTEXITCODE
    $sw.Stop()
    $ms = $sw.ElapsedMilliseconds
    $Timings += [PSCustomObject]@{Case = $case; Ms = $ms }
    $lastLine = ($output | Select-Object -Last 1).ToString().Trim()

    if ($exitCode -eq 0) {
        $Passed++
        $status = "PASS"
    }
    else {
        $Failed += $case
        $status = "FAIL"
    }
    Write-Both ("  [{0,4}ms] {1,-16} {2}: {3}" -f $ms, $case, $status, $lastLine)

    # Save full output per case for debugging
    $output | Out-File (Join-Path $caseDir "output.txt")
}

Write-Both ""
Write-Both "--- Summary ---"
Write-Both "PASSED: $Passed / $($Cases.Count)"
if ($Failed.Count -gt 0) {
    Write-Both "FAILED: $($Failed -join ', ')"
}
$totalMs = ($Timings | Measure-Object Ms -Sum).Sum
Write-Both "Total time: ${totalMs}ms"
Write-Both "Evidence: $EvidenceRoot"
Write-Both "Log:      $LogFile"

if ($Failed.Count -gt 0) { exit 1 } else { exit 0 }
