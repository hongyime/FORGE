# tools/forge-stack.ps1 - Helper for the forge-* dev/evidence container stack.
#
# Usage:
#   .\tools\forge-stack.ps1 up           # bring up postgres + soak-redis
#   .\tools\forge-stack.ps1 up -Llm      # also start ollama
#   .\tools\forge-stack.ps1 down         # tear down (preserves volumes)
#   .\tools\forge-stack.ps1 reset        # tear down + WIPE volumes
#   .\tools\forge-stack.ps1 status       # show containers + ports + healthcheck
#   .\tools\forge-stack.ps1 logs <svc>   # tail logs from one service
#   .\tools\forge-stack.ps1 psql         # interactive psql into forge-postgres
#   .\tools\forge-stack.ps1 redis        # interactive redis-cli into forge-soak-redis

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet("up", "down", "reset", "status", "logs", "psql", "redis", "pull-ollama-model")]
    [string]$Command,

    [Parameter(Position = 1)]
    [string]$Service,

    [switch]$Llm,

    [string]$OllamaModel = "qwen2.5:0.5b"
)

$ErrorActionPreference = "Stop"
$composeFile = Join-Path $PSScriptRoot "..\docker-compose.dev.yml"
if (-not (Test-Path $composeFile)) {
    Write-Error "docker-compose.dev.yml not found at $composeFile"
    exit 1
}

function Invoke-Compose {
    param([Parameter(Mandatory)][string[]]$Args)
    & docker compose -f $composeFile @Args
}

switch ($Command) {
    "up" {
        $args = @("up", "-d")
        if ($Llm) {
            Write-Host "Including LLM profile (will pull ollama image, ~1 GB)..."
            $args = @("--profile", "llm") + $args
        }
        Invoke-Compose -Args $args
        Start-Sleep -Seconds 3
        Invoke-Compose -Args @("ps")
    }
    "down" {
        Invoke-Compose -Args @("down")
    }
    "reset" {
        Write-Host "About to delete ALL forge-* dev volumes (postgres data, ollama models)." -ForegroundColor Yellow
        $confirm = Read-Host "Type 'yes' to confirm"
        if ($confirm -ne "yes") {
            Write-Host "Aborted."
            exit 0
        }
        Invoke-Compose -Args @("down", "-v", "--remove-orphans")
    }
    "status" {
        Invoke-Compose -Args @("ps")
        Write-Host ""
        Write-Host "=== healthcheck states ===" -ForegroundColor Cyan
        $names = @("forge-postgres", "forge-soak-redis", "forge-ollama")
        foreach ($n in $names) {
            $exists = & docker ps -a --filter "name=$n" --format "{{.Names}}" 2>$null
            if ($exists) {
                $health = & docker inspect $n --format '{{.State.Health.Status}}' 2>$null
                if (-not $health -or $health -eq "<no value>") { $health = "(no healthcheck yet)" }
                Write-Host ("  {0,-22} {1}" -f $n, $health)
            }
        }
    }
    "logs" {
        if (-not $Service) {
            Write-Error "Usage: .\tools\forge-stack.ps1 logs <service>  (e.g. postgres, soak-redis, ollama)"
            exit 1
        }
        Invoke-Compose -Args @("logs", "-f", "--tail=100", $Service)
    }
    "psql" {
        & docker exec -it forge-postgres psql -U forge -d forge
    }
    "redis" {
        & docker exec -it forge-soak-redis redis-cli
    }
    "pull-ollama-model" {
        $running = & docker ps --filter "name=forge-ollama" --format "{{.Names}}" 2>$null
        if (-not $running) {
            Write-Error "forge-ollama not running. Start with: .\tools\forge-stack.ps1 up -Llm"
            exit 1
        }
        Write-Host "Pulling $OllamaModel into forge-ollama..."
        & docker exec forge-ollama ollama pull $OllamaModel
    }
}
