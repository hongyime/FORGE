#!/usr/bin/env pwsh
# scripts/parity_check.ps1
#
# Compare Python (:8000, :8080) responses to Rust shadow (:9000, :9080)
# responses. Used for Cutover Phase 3 traffic parity soak.
#
# Usage:
#   pwsh scripts\parity_check.ps1                          # 10 iters, 1s delay
#   pwsh scripts\parity_check.ps1 -Iterations 60           # 60 iters
#   pwsh scripts\parity_check.ps1 -Iterations 60 -DelaySeconds 30
#   pwsh scripts\parity_check.ps1 -EndpointsFile custom.json
#   pwsh scripts\parity_check.ps1 -Quiet                   # only print summary
#
# Comparison modes per endpoint pair:
#   shape         — parse both as JSON, compare top-level key SET only.
#                   Values may legitimately differ (version strings, timestamps).
#                   Catches missing/extra fields.
#   exact         — byte-for-byte body match.
#   status_only   — only HTTP status code parity.
#
# Exit 0 if all pairs pass across all iterations. Exit 1 if any fail.

[CmdletBinding()]
param(
    [int]$Iterations = 10,
    [int]$DelaySeconds = 1,
    [string]$EndpointsFile = "",
    [switch]$Quiet
)

$ErrorActionPreference = 'Continue'
$RepoRoot = 'C:\forge'
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$LogFile = Join-Path $RepoRoot ".omo\evidence\rust-rewrite\parity-$Stamp.log"
New-Item -ItemType Directory -Force -Path (Split-Path $LogFile) | Out-Null

# Default endpoint pairs
$defaultEndpoints = @(
    @{ Name = 'platform/health'; Python = 'http://127.0.0.1:8000/health'; Rust = 'http://127.0.0.1:9000/health'; Compare = 'shape' }
    @{ Name = 'webui/health';    Python = 'http://127.0.0.1:8080/health'; Rust = 'http://127.0.0.1:9080/health'; Compare = 'shape' }
)

if ($EndpointsFile -and (Test-Path $EndpointsFile)) {
    $endpoints = Get-Content $EndpointsFile -Raw | ConvertFrom-Json
} else {
    $endpoints = $defaultEndpoints
}

function Write-Both {
    param($msg)
    if (-not $Quiet) { Write-Host $msg }
    $msg | Out-File $LogFile -Append -Encoding utf8
}

Write-Both "=== parity_check.ps1 ==="
Write-Both "Timestamp: $Stamp"
Write-Both "Iterations: $Iterations"
Write-Both "DelaySeconds: $DelaySeconds"
Write-Both "Endpoints: $($endpoints.Count) pairs"
Write-Both ""

# Fetch a URL. Uses `docker exec` inside a chosen container for stack-internal
# probes (bypasses WSL2 Windows-loopback flake). Falls back to host `Invoke-WebRequest`
# / `curl.exe` if no container hint is supplied.
#
# Container mapping: URLs on 127.0.0.1:8000 or 127.0.0.1:8080 are probed via
# `forge-dev-forge-api-1` / `forge-dev-forge-webui-1` (Python stack) using
# curl to `localhost` on the same internal port — same technique Docker's
# healthcheck uses, so it is authoritative for service health.
function Get-Response {
    param($url)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    # Map host loopback URLs -> in-container probe pair
    $containerProbe = $null
    switch -Regex ($url) {
        '127\.0\.0\.1:8000' { $containerProbe = @{ Container = 'forge-dev-forge-api-1';        Url = 'http://localhost:8000/health' } }
        '127\.0\.0\.1:8080' { $containerProbe = @{ Container = 'forge-dev-forge-webui-1';      Url = 'http://localhost:8080/health' } }
        '127\.0\.0\.1:9000' { $containerProbe = @{ Container = 'forge-dev-forge-rust-api-1';   Url = 'http://localhost:9000/health' } }
        '127\.0\.0\.1:9080' { $containerProbe = @{ Container = 'forge-dev-forge-rust-webui-1'; Url = 'http://localhost:9080/health' } }
    }

    if ($containerProbe) {
        try {
            $out = & docker exec $containerProbe.Container curl -sS --max-time 5 -o - -w "`n---STATUS---%{http_code}" $containerProbe.Url 2>&1
            $sw.Stop()
            $joined = ($out -join "`n")
            if ($joined -match '---STATUS---(\d+)$') {
                $status = [int]$matches[1]
                $body = $joined -replace "`n?---STATUS---\d+$", ''
                return @{ Status = $status; Body = $body.Trim(); LatencyMs = $sw.ElapsedMilliseconds; Ok = ($status -ge 200 -and $status -lt 500); Err = $null }
            }
            return @{ Status = 0; Body = ''; LatencyMs = $sw.ElapsedMilliseconds; Ok = $false; Err = "docker exec parse failed: $joined" }
        } catch {
            $sw.Stop()
            return @{ Status = 0; Body = ''; LatencyMs = $sw.ElapsedMilliseconds; Ok = $false; Err = "docker exec failed: $($_.Exception.Message)" }
        }
    }

    # Non-mapped URL: try host directly
    try {
        $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        $sw.Stop()
        return @{ Status = [int]$resp.StatusCode; Body = $resp.Content; LatencyMs = $sw.ElapsedMilliseconds; Ok = $true; Err = $null }
    } catch {
        $sw.Stop()
        return @{ Status = 0; Body = ''; LatencyMs = $sw.ElapsedMilliseconds; Ok = $false; Err = $_.Exception.Message }
    }
}

function Compare-Shape {
    param($pyBody, $rsBody)
    try {
        $py = $pyBody | ConvertFrom-Json -ErrorAction Stop
        $rs = $rsBody | ConvertFrom-Json -ErrorAction Stop
    } catch {
        return @{ Match = $false; Reason = "json_parse_failed: $($_.Exception.Message)" }
    }
    $pyKeys = @($py.PSObject.Properties.Name | Sort-Object)
    $rsKeys = @($rs.PSObject.Properties.Name | Sort-Object)
    $onlyPy = $pyKeys | Where-Object { $rsKeys -notcontains $_ }
    $onlyRs = $rsKeys | Where-Object { $pyKeys -notcontains $_ }
    if ($onlyPy -or $onlyRs) {
        return @{ Match = $false; Reason = "keys diverge: py_only=[$($onlyPy -join ',')] rs_only=[$($onlyRs -join ',')]" }
    }
    return @{ Match = $true; Reason = "keys=[$($pyKeys -join ',')]" }
}

# Track counters
$totalPairs = 0
$passedPairs = 0
$divergenceCounts = @{}
foreach ($ep in $endpoints) { $divergenceCounts[$ep.Name] = @{ Pass = 0; Fail = 0; FailReasons = @() } }

for ($i = 1; $i -le $Iterations; $i++) {
    if (-not $Quiet) { Write-Host "--- iter $i / $Iterations ---" }
    foreach ($ep in $endpoints) {
        $totalPairs++
        $py = Get-Response $ep.Python
        $rs = Get-Response $ep.Rust

        # Compare
        $verdict = $null
        switch ($ep.Compare) {
            'exact' {
                $match = ($py.Body -eq $rs.Body) -and ($py.Status -eq $rs.Status)
                $verdict = @{ Match = $match; Reason = "py_status=$($py.Status) rs_status=$($rs.Status); body_eq=$($py.Body -eq $rs.Body)" }
            }
            'status_only' {
                $match = ($py.Status -eq $rs.Status)
                $verdict = @{ Match = $match; Reason = "py_status=$($py.Status) rs_status=$($rs.Status)" }
            }
            default {
                # shape
                if (-not $py.Ok -or -not $rs.Ok) {
                    $verdict = @{ Match = $false; Reason = "fetch_failed: py_ok=$($py.Ok) rs_ok=$($rs.Ok) py_err=$($py.Err) rs_err=$($rs.Err)" }
                } else {
                    $verdict = Compare-Shape $py.Body $rs.Body
                }
            }
        }

        if ($verdict.Match) {
            $passedPairs++
            $divergenceCounts[$ep.Name].Pass++
            Write-Both "  [PASS] $($ep.Name) iter=$i py=$($py.Status)/$($py.LatencyMs)ms rs=$($rs.Status)/$($rs.LatencyMs)ms $($verdict.Reason)"
        } else {
            $divergenceCounts[$ep.Name].Fail++
            $divergenceCounts[$ep.Name].FailReasons += "iter=$i $($verdict.Reason) py_body=$($py.Body) rs_body=$($rs.Body)"
            Write-Both "  [FAIL] $($ep.Name) iter=$i $($verdict.Reason)"
        }
    }
    if ($i -lt $Iterations) { Start-Sleep -Seconds $DelaySeconds }
}

Write-Both ""
Write-Both "=== SUMMARY ==="
Write-Both ("Total pairs:  {0}" -f $totalPairs)
Write-Both ("Passed:       {0}" -f $passedPairs)
Write-Both ("Failed:       {0}" -f ($totalPairs - $passedPairs))
Write-Both ""
Write-Both "Per-endpoint:"
foreach ($name in $divergenceCounts.Keys) {
    $c = $divergenceCounts[$name]
    Write-Both ("  {0,-24} pass={1,3} fail={2,3}" -f $name, $c.Pass, $c.Fail)
    if ($c.Fail -gt 0) {
        $c.FailReasons | Select-Object -First 3 | ForEach-Object { Write-Both "    reason: $_" }
    }
}

# JSON summary appended
$jsonSummary = @{
    timestamp = $Stamp
    iterations = $Iterations
    delay_seconds = $DelaySeconds
    total_pairs = $totalPairs
    passed = $passedPairs
    failed = ($totalPairs - $passedPairs)
    per_endpoint = @{}
}
foreach ($name in $divergenceCounts.Keys) {
    $c = $divergenceCounts[$name]
    $jsonSummary.per_endpoint[$name] = @{ pass = $c.Pass; fail = $c.Fail; fail_reasons = $c.FailReasons }
}
"" | Out-File $LogFile -Append -Encoding utf8
"---JSON SUMMARY---" | Out-File $LogFile -Append -Encoding utf8
($jsonSummary | ConvertTo-Json -Depth 5) | Out-File $LogFile -Append -Encoding utf8

Write-Both ""
Write-Both "Log:    $LogFile"

if ($passedPairs -eq $totalPairs) {
    Write-Both "Result: GREEN (all pairs matched)"
    exit 0
} else {
    Write-Both "Result: RED ($($totalPairs - $passedPairs) failures)"
    exit 1
}
