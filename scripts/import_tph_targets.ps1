[CmdletBinding()]
param(
    [string]$ApiUrl = "http://127.0.0.1:8011/monitor/targets/export",
    [string]$TphEnvPath = "X:\01 REPOSITORIES\theprawnhunter\.env",
    [string]$RoeId = "",
    [int]$Limit = 100,
    [int]$MaxIter = 3,
    [int]$MaxRuntimeMinutes = 25,
    [int]$StartLimit = 3,
    [int]$WaitSeconds = 180,
    [switch]$DryRun,
    [switch]$Start
)

$ErrorActionPreference = "Stop"
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$python = Join-Path $repoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    $python = (Get-Command python -ErrorAction Stop).Source
}

function Get-EnvFileValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )
    if (-not (Test-Path $Path)) {
        return ""
    }
    foreach ($line in Get-Content -LiteralPath $Path) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith("#")) {
            continue
        }
        $match = [regex]::Match($trimmed, "^\s*$([regex]::Escape($Name))\s*=\s*(.*)\s*$")
        if ($match.Success) {
            return $match.Groups[1].Value.Trim().Trim('"').Trim("'")
        }
    }
    return ""
}

function Test-TcpPort {
    param(
        [Parameter(Mandatory = $true)][string]$HostName,
        [Parameter(Mandatory = $true)][int]$Port,
        [int]$TimeoutMilliseconds = 1000
    )
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $asyncResult = $client.BeginConnect($HostName, $Port, $null, $null)
        $connected = $asyncResult.AsyncWaitHandle.WaitOne(
            [Math]::Max(100, $TimeoutMilliseconds),
            $false
        )
        if (-not $connected) {
            return $false
        }
        $client.EndConnect($asyncResult)
        return $client.Connected
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

function Get-TargetFeedDiagnostics {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][string]$TphEnvPath
    )
    $parts = [System.Collections.Generic.List[string]]::new()
    try {
        $uri = [uri]$Url
        if ($uri.Host -and $uri.Port -gt 0) {
            $portReachable = Test-TcpPort -HostName $uri.Host -Port $uri.Port
            $parts.Add("tcp=$($uri.Host):$($uri.Port) reachable=$portReachable")
        }
    } catch {
        $parts.Add("url_parse_error=$($_.Exception.Message)")
    }

    $envExists = Test-Path -LiteralPath $TphEnvPath
    $parts.Add("tph_env_exists=$envExists")
    try {
        $tphRepoPath = Split-Path -Parent $TphEnvPath
        $composePath = Join-Path $tphRepoPath "docker-compose.yml"
        $parts.Add("compose_file=$composePath exists=$(Test-Path -LiteralPath $composePath)")
    } catch {
        $parts.Add("compose_file_check_error=$($_.Exception.Message)")
    }
    return ($parts -join "; ")
}

function Wait-TargetFeed {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][hashtable]$Headers,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][string]$TphEnvPath
    )
    $deadline = (Get-Date).AddSeconds([Math]::Max(1, $TimeoutSeconds))
    $attempt = 0
    $lastError = ""
    Write-Host "waiting for target feed url=$Url timeout_seconds=$TimeoutSeconds"
    do {
        $attempt += 1
        try {
            $remainingSeconds = [Math]::Max(
                1,
                [int][Math]::Ceiling(($deadline - (Get-Date)).TotalSeconds)
            )
            Invoke-RestMethod -Uri $Url -Headers $Headers -Method Get -TimeoutSec ([Math]::Min(5, $remainingSeconds)) | Out-Null
            Write-Host "target feed reachable attempts=$attempt"
            return
        } catch {
            $lastError = $_.Exception.Message
            $sleepSeconds = [Math]::Min(
                3,
                [Math]::Max(0, [int][Math]::Floor(($deadline - (Get-Date)).TotalSeconds))
            )
            if ($sleepSeconds -gt 0) {
                Start-Sleep -Seconds $sleepSeconds
            }
        }
    } while ((Get-Date) -lt $deadline)
    $diagnostics = Get-TargetFeedDiagnostics -Url $Url -TphEnvPath $TphEnvPath
    throw "target feed did not become reachable before timeout: $Url; attempts=$attempt; last_error=$lastError; $diagnostics"
}

function Add-FeedLimit {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][int]$LimitValue
    )
    if ($Url -match '([?&])limit=') {
        return $Url
    }
    $separator = "?"
    if ($Url.Contains("?")) {
        $separator = "&"
    }
    return "$Url$separator`limit=$LimitValue"
}

Set-Location $repoRoot

if (-not $env:TPH_MONITOR_KEY) {
    $monitorKey = Get-EnvFileValue -Path $TphEnvPath -Name "MONITOR_API_KEY"
    if (-not $monitorKey) {
        throw "TPH_MONITOR_KEY is not set and MONITOR_API_KEY was not found in $TphEnvPath"
    }
    $env:TPH_MONITOR_KEY = $monitorKey
}

if (-not $env:FORGE_DATA_DIR) {
    $env:FORGE_DATA_DIR = (Join-Path $repoRoot ".forge_data")
}
if (-not $env:FORGE_OFFLINE_STRICT) {
    $env:FORGE_OFFLINE_STRICT = "0"
}
if (-not $RoeId) {
    $RoeId = $env:FORGE_ROE_ID
}
if (-not $RoeId) {
    $forgeEnv = Join-Path $repoRoot ".env"
    $RoeId = Get-EnvFileValue -Path $forgeEnv -Name "FORGE_ROE_ID"
}

$feedUrl = Add-FeedLimit -Url $ApiUrl -LimitValue $Limit
$headers = @{ "X-Monitor-Key" = $env:TPH_MONITOR_KEY }
Wait-TargetFeed -Url $feedUrl -Headers $headers -TimeoutSeconds $WaitSeconds -TphEnvPath $TphEnvPath

$args = @(
    "-m", "forge.cli",
    "targets", "import",
    "--feed-url", $feedUrl,
    "--auth-header-env", "TPH_MONITOR_KEY",
    "--limit", [string]$Limit,
    "--max-iter", [string]$MaxIter,
    "--max-runtime-minutes", [string]$MaxRuntimeMinutes,
    "--start-limit", [string]$StartLimit
)
if ($RoeId) {
    $args += @("--roe-id", $RoeId)
}
if ($DryRun) {
    $args += "--dry-run"
}
if ($Start) {
    $args += "--start"
}

& $python @args
exit $LASTEXITCODE
