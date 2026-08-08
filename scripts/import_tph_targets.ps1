[CmdletBinding()]
param(
    [string]$ApiUrl = "http://127.0.0.1:8011/monitor/targets/export",
    [string]$TphEnvPath = "X:\01 REPOSITORIES\theprawnhunter\.env",
    [string]$RoeId = "",
    [int]$Limit = 100,
    [int]$MaxIter = 3,
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

function Wait-TargetFeed {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][hashtable]$Headers,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )
    $deadline = (Get-Date).AddSeconds([Math]::Max(1, $TimeoutSeconds))
    do {
        try {
            Invoke-RestMethod -Uri $Url -Headers $Headers -Method Get -TimeoutSec 5 | Out-Null
            return
        } catch {
            Start-Sleep -Seconds 3
        }
    } while ((Get-Date) -lt $deadline)
    throw "target feed did not become reachable before timeout: $Url"
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
Wait-TargetFeed -Url $feedUrl -Headers $headers -TimeoutSeconds $WaitSeconds

$args = @(
    "-m", "forge.cli",
    "targets", "import",
    "--feed-url", $feedUrl,
    "--auth-header-env", "TPH_MONITOR_KEY",
    "--limit", [string]$Limit,
    "--max-iter", [string]$MaxIter
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
