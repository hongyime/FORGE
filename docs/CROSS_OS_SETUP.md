# Cross-OS Setup (Linux / macOS / Windows)

> Single source of truth. If any other doc contradicts this, this one wins.
> Bootstrap scripts are idempotent — re-running them is safe.

## Prerequisites (all OS)

| Tool | Minimum | Check |
|---|---|---|
| Docker Engine or Docker Desktop | 24.x | `docker info` |
| Docker Compose plugin | 2.24+ | `docker compose version` |
| Git | 2.30+ | `git --version` |
| POSIX shell (Linux/macOS) OR PowerShell 7+ (any OS) | `sh` / `pwsh --version` |

FORGE ships **no host Python or Rust requirement** for running the dev stack —
everything lives inside containers. Local Python is only needed if you want to
run `pytest` outside Docker or use the `forge` CLI directly on the host (via
`bootstrap.py`).

## Windows

### One-shot bootstrap

```powershell
git clone <repo> C:\forge
cd C:\forge
pwsh -File scripts\setup.ps1 -Up
```

That's it. `setup.ps1`:
- Verifies Docker Desktop is reachable (fails cleanly if not)
- Creates `.env.dev` with strong random secrets via
  `System.Security.Cryptography.RandomNumberGenerator`
- Creates host bind-mount dirs (`reports\`, `imports\`, `.forge_data\`)
- Validates `docker\docker-compose.dev.yml`
- Brings the stack up (with `-Up`)

Verify:
```powershell
pwsh -File dev.ps1 ps
Invoke-WebRequest http://127.0.0.1:8000/health -UseBasicParsing | Select-Object -ExpandProperty Content
Invoke-WebRequest http://127.0.0.1:8080/health -UseBasicParsing | Select-Object -ExpandProperty Content
```

Daily use:
```powershell
pwsh -File dev.ps1              # up -d
pwsh -File dev.ps1 logs         # tail all
pwsh -File dev.ps1 down         # stop
pwsh -File dev.ps1 rust-shadow  # opt-in Rust :9000/:9080
```

### Docker Desktop / WSL2 gotcha

If `docker info` hangs or returns
`WslExec: an error occurred create instance 0x88872746`, WSL is stuck. Recovery:

```powershell
wsl --shutdown
Stop-Process -Name 'Docker Desktop','com.docker.backend','vpnkit' -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3
Start-Process 'C:\Program Files\Docker\Docker\Docker Desktop.exe'
# Wait 30–60s, then:
docker info --format '{{.ServerVersion}}'
```

The `vmcompute` service protects itself from user-level `Restart-Service`; only
the elevated Docker Desktop process can cycle it. If the above fails, reboot.

### PowerShell execution policy

If `pwsh -File scripts\setup.ps1` refuses to run, use:

```powershell
pwsh -ExecutionPolicy Bypass -File scripts\setup.ps1 -Up
```

## Linux

### One-shot bootstrap

```sh
git clone <repo> ~/forge
cd ~/forge
sh scripts/setup.sh --up
```

`setup.sh` uses `openssl rand -hex` when available, falling back to
`/dev/urandom`. `.env.dev` is written with mode 600.

Verify:
```sh
sh dev.sh ps
curl -s http://127.0.0.1:8000/health
curl -s http://127.0.0.1:8080/health
```

Daily use:
```sh
sh dev.sh              # up -d
sh dev.sh logs         # tail all
sh dev.sh down         # stop
sh dev.sh rust-shadow  # opt-in Rust :9000/:9080
```

### Docker rootless vs rootful

Both work. If using rootless, ensure your user is in the `docker` group or
`XDG_RUNTIME_DIR` points at the rootless socket. `setup.sh` reads
`docker info` and fails fast if the daemon is unreachable — it does not attempt
`sudo`.

### SELinux (RHEL / Fedora / Rocky)

The compose file uses named volumes, which SELinux tolerates. Host bind-mounts
(`reports/`, `imports/`, `.forge_data/`) may need a `:z` suffix if you extend
the compose file:

```yaml
- ./reports:/app/reports:rw,z
```

## macOS

### One-shot bootstrap

```sh
git clone <repo> ~/forge
cd ~/forge
sh scripts/setup.sh --up
```

Same as Linux. Docker Desktop for Mac ships a bundled `docker compose` plugin.

Apple Silicon: images are `linux/amd64` by default; Docker Desktop rosetta
emulation handles this. Native `linux/arm64` builds are not yet published — if
you want native, build locally with:

```sh
docker compose --env-file .env.dev -f docker/docker-compose.dev.yml build
```

Bind-mount performance on macOS: named volumes are fast (default). Host
bind-mounts to `reports/` etc. use VirtioFS on modern Docker Desktop — expect
~5–10× slower first-file access than Linux; acceptable for the artifact dirs
we mount.

## Verifying setup on any OS

```sh
docker compose --env-file .env.dev -f docker/docker-compose.dev.yml ps
```

Expected:
```
NAME                          SERVICE       STATUS
forge-dev-forge-api-1         forge-api     Up (healthy)
forge-dev-forge-webui-1       forge-webui   Up (healthy)
forge-dev-forge-worker-1      forge-worker  Up
forge-dev-postgres-1          postgres      Up (healthy)
forge-dev-redis-1             redis         Up (healthy)
```

Health endpoints:
```sh
curl -s http://127.0.0.1:8000/health   # {"status":"ok","bus_connected":true,"version":"7.2.0-platform"}
curl -s http://127.0.0.1:8080/health   # {"status":"ok","version":"7.2.0"}
```

## Backups

```powershell
# Windows
pwsh -File scripts\refresh-backup.ps1
```

```sh
# Linux / macOS
sh scripts/refresh-backup.sh
```

Both drop a timestamped snapshot to `$HOME/forge-backups/forge-backup-<stamp>/`
(or `$env:USERPROFILE\forge-backups\`), excluding `.git/objects/pack`,
`node_modules`, `target/`, `.venv/`, caches, `.forge_data/`, dashboard data,
and log files. Each snapshot ships with its own `RESTORE.md`.

## Parity check (Rust shadow)

Requires the Rust shadow profile to be up:

```powershell
pwsh -File scripts\parity_check.ps1                    # Windows
```

```sh
sh scripts/parity_check.sh                             # Linux / macOS
```

Both compare the JSON key set of Python `/health` responses to Rust `/health`
responses across N iterations. Uses `docker exec` to bypass any host-loopback
flake. Exits 0 if all pairs match, 1 otherwise. Log written to
`.omo/evidence/rust-rewrite/parity-<stamp>.log`.

## Uninstall / reset

Full reset (destroys all data):
```sh
docker compose --env-file .env.dev -f docker/docker-compose.dev.yml down -v
rm -f .env.dev
rm -rf reports imports .forge_data
```

Partial reset (keep code, drop containers + volumes):
```sh
sh dev.sh down                                                   # stop
docker compose --env-file .env.dev -f docker/docker-compose.dev.yml down -v  # + volumes
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| `docker info` hangs (Windows) | See "Docker Desktop / WSL2 gotcha" above |
| `set FORGE_POSTGRES_PASSWORD in .env.dev` error | Re-run `setup.{ps1,sh}` — .env.dev is missing or corrupt |
| Health endpoints 000 / empty | Check `docker compose ... logs forge-api` for startup errors |
| `forge-toolkit-rust:local not found` | Build first: `docker build -f docker/Dockerfile --target rust-runtime -t forge-toolkit-rust:local .` |
| SMB / network drive checkout | Compose bind mounts must be readable by the Docker daemon; see `docker/README.md` "Compose Watch for SMB" section |
| Port 8000 / 8080 in use | Set `FORGE_API_PORT` / `FORGE_WEB_PORT` in `.env.dev` |
| Windows Defender flags files | See `AGENTS.md` — do NOT add exclusions or disable real-time protection |
