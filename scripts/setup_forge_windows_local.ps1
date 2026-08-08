param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
    [string]$HydrationRoot = (Join-Path $env:USERPROFILE '_forge_hydration_full'),
    [string]$ForgeLocalRoot = (Join-Path $env:USERPROFILE '.forge'),
    [switch]$SkipDefender,
    [switch]$VerifyOnly
)

$ErrorActionPreference = 'Stop'

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Add-Directory {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
    return (Resolve-Path -LiteralPath $Path).Path
}

function Add-DefenderExclusion {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject]@{ Path = $Path; Status = 'missing' }
    }
    try {
        Add-MpPreference -ExclusionPath $Path -ErrorAction Stop
        return [pscustomobject]@{ Path = $Path; Status = 'excluded' }
    } catch {
        return [pscustomobject]@{ Path = $Path; Status = 'failed'; Error = $_.Exception.Message }
    }
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$hydration = Add-Directory $HydrationRoot
$forgeLocal = Add-Directory $ForgeLocalRoot

$requiredLocalDirs = @(
    $hydration,
    (Join-Path $hydration 'cache'),
    (Join-Path $hydration 'artifacts'),
    (Join-Path $hydration 'logs'),
    (Join-Path $hydration 'tools'),
    $forgeLocal,
    (Join-Path $forgeLocal 'data'),
    (Join-Path $forgeLocal 'backups')
)

foreach ($dir in $requiredLocalDirs) {
    Add-Directory $dir | Out-Null
}

$manifest = [ordered]@{
    generated_at = (Get-Date).ToString('o')
    repo_root = $repo
    hydration_root = $hydration
    forge_local_root = $forgeLocal
    purpose = 'FORGE local operational workspace and targeted Windows Defender exclusions'
}
$manifestPath = Join-Path $hydration 'forge_hydration_manifest.json'
$manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

Write-Host "FORGE local workspace ready:"
Write-Host "  repo:      $repo"
Write-Host "  hydration: $hydration"
Write-Host "  local:     $forgeLocal"
Write-Host "  manifest:  $manifestPath"

Push-Location $repo
try {
    $deleted = git ls-files --deleted
    if ($deleted) {
        Write-Warning "Tracked files missing from working tree:"
        $deleted | ForEach-Object { Write-Warning "  $_" }
    } else {
        Write-Host "Git tracked-file check: no deleted files."
    }

    git fsck --no-dangling | Out-Host
} finally {
    Pop-Location
}

if ($VerifyOnly -or $SkipDefender) {
    Write-Host "Defender exclusions not changed."
    exit 0
}

if (-not (Test-Admin)) {
    Write-Warning "Defender exclusions require an elevated PowerShell session."
    Write-Warning "Re-run as Administrator:"
    Write-Warning "  powershell -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit 2
}

$exclusionPaths = @(
    $hydration,
    $forgeLocal,
    (Join-Path $repo '.venv'),
    (Join-Path $repo 'forge\phase3'),
    (Join-Path $repo 'forge\phase5')
) | Sort-Object -Unique

$results = foreach ($path in $exclusionPaths) {
    Add-DefenderExclusion $path
}

$results | Format-Table -AutoSize

Write-Host "Targeted Defender exclusion setup complete."
