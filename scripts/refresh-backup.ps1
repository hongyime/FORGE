#!/usr/bin/env pwsh
# scripts/refresh-backup.ps1
#
# Refresh the FORGE off-repo backup at X:\01 REPOSITORIES\forge-backup-<stamp>\
#
# Creates a NEW timestamped snapshot each run (no in-place overwrite).
# Copies secrets, runtime data, and config that are NOT in git.
#
# Usage:
#   pwsh scripts\refresh-backup.ps1                      # default target
#   pwsh scripts\refresh-backup.ps1 -TargetRoot X:\path  # custom root
#   pwsh scripts\refresh-backup.ps1 -Rotate 3            # keep last N snapshots, prune older

[CmdletBinding()]
param(
    [string]$TargetRoot = 'X:\01 REPOSITORIES',
    [int]$Rotate = 0
)

$ErrorActionPreference = 'Stop'
$RepoRoot = 'C:\forge'
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$BackupRoot = Join-Path $TargetRoot "forge-backup-$Stamp"

if (-not (Test-Path $TargetRoot)) {
    Write-Error "Target root not found: $TargetRoot"
    exit 1
}
if (-not (Test-Path $RepoRoot)) {
    Write-Error "Repo not found: $RepoRoot"
    exit 1
}

Write-Host "=== FORGE backup refresh ==="
Write-Host "Repo:   $RepoRoot"
Write-Host "Target: $BackupRoot"
Write-Host ""

# Create subdir skeleton
foreach ($sub in 'secrets','data','config','evidence') {
    New-Item -ItemType Directory -Force -Path (Join-Path $BackupRoot $sub) | Out-Null
}

# --- 1. Secrets (small, sensitive, always fresh copy) ---
Write-Host "--- secrets ---"
$secretFiles = @('.env', '.env.dev', 'forge_primary_secret.key')
$manifest = @()
foreach ($f in $secretFiles) {
    $src = Join-Path $RepoRoot $f
    if (Test-Path $src) {
        $dst = Join-Path "$BackupRoot\secrets" $f
        Copy-Item $src $dst -Force
        $hash = (Get-FileHash $dst -Algorithm SHA256).Hash
        $sz = (Get-Item $dst).Length
        $manifest += "$hash  $f  $sz bytes"
        Write-Host "  copied  $f  sha256=$($hash.Substring(0,16))..."
    } else {
        Write-Host "  SKIP    $f (not present)"
    }
}
$manifest | Out-File "$BackupRoot\secrets\SHA256SUMS.txt" -Encoding utf8

# --- 2. Runtime data (parallel robocopy for speed) ---
Write-Host ""
Write-Host "--- runtime data ---"
$dataDirs = @('.forge_data','imports','reports','manifests','_audit_logs','latest_logs','downloads','vendor')
$jobs = @()
foreach ($d in $dataDirs) {
    $src = Join-Path $RepoRoot $d
    $dst = Join-Path "$BackupRoot\data" $d
    if (Test-Path $src) {
        $jobs += Start-Job -ArgumentList $src, $dst, $d -ScriptBlock {
            param($src, $dst, $d)
            $r = robocopy $src $dst /E /R:1 /W:1 /NP /NFL /NDL /NJH /NJS 2>&1
            "$d exit=$LASTEXITCODE"
        }
    }
}
Write-Host "  $($jobs.Count) parallel jobs..."
$jobs | Wait-Job | Out-Null
$jobs | ForEach-Object { Receive-Job $_ | ForEach-Object { Write-Host "    $_" } }
$jobs | Remove-Job -Force

# --- 3. Config files ---
Write-Host ""
Write-Host "--- config ---"
$configFiles = @(
    '.env.example', '.gitignore', 'pyproject.toml',
    'docker\docker-compose.dev.yml',
    'docker\docker-compose.prod.yml',
    'docker\docker-compose.legacy.yml',
    'docker\README.md',
    '.githooks\pre-push',
    'scripts\run-canaries.ps1',
    'scripts\refresh-backup.ps1'
)
foreach ($f in $configFiles) {
    $src = Join-Path $RepoRoot $f
    if (Test-Path $src) {
        $dst = Join-Path "$BackupRoot\config" $f
        New-Item -ItemType Directory -Force -Path (Split-Path $dst) | Out-Null
        Copy-Item $src $dst -Force
    }
}

# git config snapshot
$gitCfg = [ordered]@{}
$gitCfg['hooksPath']        = git -C $RepoRoot config core.hooksPath 2>&1
$gitCfg['user.email']       = git -C $RepoRoot config user.email 2>&1
$gitCfg['user.name']        = git -C $RepoRoot config user.name 2>&1
$gitCfg['remote.origin.url']= git -C $RepoRoot config remote.origin.url 2>&1
$gitCfg['HEAD']             = git -C $RepoRoot rev-parse HEAD 2>&1
$gitCfg['branch']           = git -C $RepoRoot branch --show-current 2>&1
$gitCfg['status_short']     = (git -C $RepoRoot status --short 2>&1) -join "`n"
$gitCfg | ConvertTo-Json -Depth 3 | Out-File "$BackupRoot\config\git-config.json" -Encoding utf8

# .agents state
New-Item -ItemType Directory -Force -Path "$BackupRoot\config\.agents" | Out-Null
Copy-Item "$RepoRoot\.agents\STATE.md"   "$BackupRoot\config\.agents\STATE.md"   -Force
Copy-Item "$RepoRoot\.agents\JOURNAL.md" "$BackupRoot\config\.agents\JOURNAL.md" -Force

# --- 4. Summary manifest ---
$totalMB = [math]::Round(((Get-ChildItem $BackupRoot -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum / 1MB), 1)
$fileCount = (Get-ChildItem $BackupRoot -Recurse -File -ErrorAction SilentlyContinue | Measure-Object).Count
$summary = @{
    timestamp = $Stamp
    backup_root = $BackupRoot
    git_head = $gitCfg['HEAD']
    branch = $gitCfg['branch']
    total_mb = $totalMB
    file_count = $fileCount
}
$summary | ConvertTo-Json | Out-File "$BackupRoot\MANIFEST.json" -Encoding utf8

# Record last backup path for the RESTORE.md link
$BackupRoot | Out-File "$RepoRoot\.omo\evidence\rust-rewrite\last-backup-root.txt" -Encoding utf8

Write-Host ""
Write-Host "=== summary ==="
Write-Host "  files:   $fileCount"
Write-Host "  size:    $totalMB MB"
Write-Host "  path:    $BackupRoot"

# --- 5. Rotation (optional) ---
if ($Rotate -gt 0) {
    Write-Host ""
    Write-Host "--- rotation ---"
    $snapshots = Get-ChildItem $TargetRoot -Directory -Filter "forge-backup-*" | Sort-Object Name -Descending
    if ($snapshots.Count -gt $Rotate) {
        $toDelete = $snapshots | Select-Object -Skip $Rotate
        foreach ($old in $toDelete) {
            Write-Host "  pruning $($old.Name)..."
            Remove-Item -Recurse -Force $old.FullName -ErrorAction SilentlyContinue
        }
        Write-Host "  kept most recent $Rotate snapshots"
    } else {
        Write-Host "  $($snapshots.Count) snapshots, nothing to prune (Rotate=$Rotate)"
    }
}

Write-Host ""
Write-Host "Done. Backup: $BackupRoot"
