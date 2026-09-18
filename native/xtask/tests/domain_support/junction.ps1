param([string]$LinkPath, [string]$TargetPath)
$ErrorActionPreference = 'Stop'
# Same owned-fixture junction pattern as tests/support/junction.ps1.
$fixtureRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../../../.omo/evidence/rust-rewrite/task-3/domain-command-fixtures'))
foreach ($fixturePath in @($LinkPath, $TargetPath)) {
    $resolvedFixture = [IO.Path]::GetFullPath($fixturePath)
    if (-not $resolvedFixture.StartsWith($fixtureRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Junction setup accepts only owned domain test fixture paths.'
    }
}
New-Item -ItemType Junction -Path $LinkPath -Target $TargetPath | Out-Null
