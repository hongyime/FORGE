param([string]$LinkPath, [string]$TargetPath)
$ErrorActionPreference = 'Stop'
# Test-only setup for an NTFS reparse point; no privilege/configuration changes.
$fixtureRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../../target/t1-fixtures'))
foreach ($fixturePath in @($LinkPath, $TargetPath)) {
    $resolvedFixture = [IO.Path]::GetFullPath($fixturePath)
    if (-not $resolvedFixture.StartsWith($fixtureRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Junction setup accepts only owned native test fixture paths.'
    }
}
New-Item -ItemType Junction -Path $LinkPath -Target $TargetPath | Out-Null
