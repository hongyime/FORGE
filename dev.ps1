# FORGE dev-stack launcher (Windows)
#
# Idempotent wrapper around `docker compose` for the canonical dev stack.
# Authoritative compose file: docker/docker-compose.dev.yml
# Env file: .env.dev  (must exist — run scripts/setup.ps1 first if missing)
#
# Usage:
#   pwsh -File dev.ps1              # up -d
#   pwsh -File dev.ps1 build        # rebuild image (after Dockerfile/pyproject changes)
#   pwsh -File dev.ps1 up           # bring stack up (--no-build)
#   pwsh -File dev.ps1 down         # stop stack, keep volumes
#   pwsh -File dev.ps1 logs         # tail all logs
#   pwsh -File dev.ps1 ps           # service status
#   pwsh -File dev.ps1 rust-shadow  # opt-in: bring up Rust shadow services on :9000/:9080
#
# Pass additional docker-compose args after the action.

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('up', 'build', 'down', 'logs', 'ps', 'rust-shadow')]
    [string]$Action = 'up',

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ComposeArgs = @()
)

$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    if (-not (Test-Path .env.dev)) {
        Write-Error ".env.dev not found — run: pwsh -File scripts/setup.ps1"
        exit 2
    }
    $compose = @('compose', '--env-file', '.env.dev', '-f', 'docker/docker-compose.dev.yml')

    switch ($Action) {
        'up'          { $cmd = $compose + @('up', '-d', '--no-build') + $ComposeArgs }
        'build'       { $cmd = $compose + @('build') + $ComposeArgs }
        'down'        { $cmd = $compose + @('down') + $ComposeArgs }
        'logs'        { $cmd = $compose + @('logs', '-f') + $ComposeArgs }
        'ps'          { $cmd = $compose + @('ps') + $ComposeArgs }
        'rust-shadow' { $cmd = $compose + @('--profile', 'rust-shadow', 'up', '-d', '--no-build') + $ComposeArgs }
    }

    & docker @cmd
    $exitCode = $LASTEXITCODE
} finally {
    Pop-Location
}
exit $exitCode
