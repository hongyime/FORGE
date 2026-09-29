# FORGE Docker Stacks

Two Compose stacks: `forge-dev` for local development and testing, `forge-prod` for self-hosted production deployments.

---

## Two stacks: dev and prod

| Stack | File | Env file | Project name | Default services | With profile |
|-------|------|----------|--------------|------------------|--------------|
| Dev | `docker/docker-compose.dev.yml` | `.env.dev` | `forge-dev` | 5 (Python only) | +2 with `--profile rust-shadow` |
| Prod | `docker/docker-compose.prod.yml` | `.env.prod` | `forge-prod` | 5 core | +2 with `--profile rust-shadow`; +1 with `--profile autostart` |

The old `docker/docker-compose.yml` remains as a reference but is superseded by these two files.

---

## Quick start — DEV

```powershell
# 1. Copy the dev env template and fill in values (or use defaults as-is for local work)
#    .env.dev is already .gitignored
Copy-Item .env.dev .env.dev   # already exists if you ran the dev-stack setup

# 2. Build the image (first time, or after pyproject.toml/Dockerfile changes)
docker compose --env-file .env.dev -f docker/docker-compose.dev.yml build

# 3. Start all services detached
docker compose --env-file .env.dev -f docker/docker-compose.dev.yml up -d

# 4. Check service status
docker compose --env-file .env.dev -f docker/docker-compose.dev.yml ps

# 5. Tail API logs
docker compose --env-file .env.dev -f docker/docker-compose.dev.yml logs -f forge-api

# 6. Tail all logs
docker compose --env-file .env.dev -f docker/docker-compose.dev.yml logs -f

# 7. Stop (preserves volumes)
docker compose --env-file .env.dev -f docker/docker-compose.dev.yml down

# 8. Stop and wipe all dev data (destructive)
docker compose --env-file .env.dev -f docker/docker-compose.dev.yml down -v
```

---

## Quick start — PROD

```powershell
# 1. Create .env.prod with real secrets (copy .env.dev as a template, then replace values)
#    .env.prod is .gitignored — never commit it

# 2. Validate config before starting (catches missing required vars)
docker compose --env-file .env.prod -f docker/docker-compose.prod.yml config --quiet

# 3. Build the image
docker compose --env-file .env.prod -f docker/docker-compose.prod.yml build

# 4. Start core services
docker compose --env-file .env.prod -f docker/docker-compose.prod.yml up -d

# 5. Start with guarded autostart loop (production autopilot — requires ROE)
docker compose --env-file .env.prod -f docker/docker-compose.prod.yml --profile autostart up -d

# 6. Check status
docker compose --env-file .env.prod -f docker/docker-compose.prod.yml ps
```

---

## Resource budget

Both stacks use the same minimal-footprint defaults. In prod, all caps are overridable via env vars.

### Dev stack (`forge-dev`) — hard-coded minimums

#### Default startup (5 services — Python stack only)

| Service | Memory | CPU | Notes |
|---------|--------|-----|-------|
| postgres | 256 MB | 0.25 | State + audit DB |
| redis | 128 MB | 0.15 | Workflow bus |
| forge-api | 512 MB | 0.50 | uvicorn REST/WebSocket |
| forge-webui | 384 MB | 0.35 | uvicorn web UI |
| forge-worker | 384 MB | 0.35 | Background task runner |
| **Total** | **~1.66 GB** | **~1.60** | Under 2 GB ceiling |

#### With `--profile rust-shadow` (7 services — adds Rust shadow endpoints)

| Service | Memory | CPU | Notes |
|---------|--------|-----|-------|
| forge-rust-api | 256 MB | 0.30 | Rust axum API on :9000 (opt-in) |
| forge-rust-webui | 256 MB | 0.30 | Rust axum web UI on :9080 (opt-in) |
| **Total (all 7)** | **~2.17 GB** | **~2.20** | Requires `forge-toolkit-rust:local` image |

### Prod stack (`forge-prod`) — minimal defaults, env-var scalable

#### Default startup (5 services)

| Service | Default memory | Override env var | Default CPU | Override env var |
|---------|----------------|------------------|-------------|------------------|
| postgres | 256 MB | `FORGE_POSTGRES_MEM_LIMIT` | 0.25 | `FORGE_POSTGRES_CPUS` |
| redis | 128 MB | `FORGE_REDIS_MEM_LIMIT` | 0.15 | `FORGE_REDIS_CPUS` |
| forge-api | 512 MB | `FORGE_API_MEM` | 0.50 | `FORGE_API_CPUS` |
| forge-webui | 384 MB | `FORGE_WEB_MEM` | 0.35 | `FORGE_WEB_CPUS` |
| forge-worker | 384 MB | `FORGE_WORKER_MEM` | 0.35 | `FORGE_WORKER_CPUS` |
| **Core total** | **~1.66 GB** | | **~1.60** | |

#### With `--profile rust-shadow` (+2 services)

| Service | Default memory | Override env var | Default CPU | Override env var |
|---------|----------------|------------------|-------------|------------------|
| forge-rust-api | 256 MB | `FORGE_RUST_API_MEM` | 0.30 | `FORGE_RUST_API_CPUS` |
| forge-rust-webui | 256 MB | `FORGE_RUST_WEBUI_MEM` | 0.30 | `FORGE_RUST_WEBUI_CPUS` |
| **+rust-shadow total** | **~2.17 GB** | | **~2.20** | |

To scale up for a larger host, set overrides in `.env.prod`:

```bash
FORGE_API_MEM=1g
FORGE_API_CPUS=1.0
FORGE_WORKER_MEM=768m
FORGE_WORKER_CPUS=0.75
FORGE_POSTGRES_MEM_LIMIT=512m
```

---

## What's different from the old `docker-compose.yml`

| Aspect | Old `docker-compose.yml` | New dev stack | New prod stack |
|--------|--------------------------|---------------|----------------|
| Project name | `forge` | `forge-dev` | `forge-prod` |
| `FORGE_ENV` | `production` | `development` | `production` |
| `FORGE_DEPLOYMENT_PROFILE` | `production` | `` (empty) | `production` |
| `FORGE_LOG_LEVEL` | `INFO` | `DEBUG` | `INFO` |
| `FORGE_LLM_PROVIDER` | `llama_cpp` | `template` | `template` (override to `llama_cpp` if needed) |
| HSTS seconds | 31536000 | 0 (no HSTS) | 31536000 |
| TLS terminator | `reverse-proxy` | `none` | `reverse-proxy` |
| Remote audit URI | required | empty (local only) | `file:///remote-audit` (or custom) |
| Audit remote scope | required | empty | required |
| postgres host port | none | none | none |
| redis host port | none | none | none |
| forge-api host bind | `127.0.0.1` | `127.0.0.1` | `${FORGE_BIND_HOST:-127.0.0.1}` |
| forge-webui host bind | `127.0.0.1` | `127.0.0.1` | `${FORGE_BIND_HOST:-127.0.0.1}` |
| `restart` policy | `unless-stopped` | `on-failure:3` | `on-failure:3` |
| Healthcheck interval | 10–15s | 15s | 15s |
| Healthcheck start_period | 60s | 30s (faster dev feedback) | 60s |
| Worker replicas | `${FORGE_WORKER_REPLICAS:-1}` | always 1 | always 1 (no `deploy:` block) |
| forge-guarded-autostart | included (profile-gated) | **dropped** | removed (2026-09-28) |
| forge-rust-api | not present | `--profile rust-shadow` (opt-in) | `--profile rust-shadow` (opt-in) |
| forge-rust-webui | not present | `--profile rust-shadow` (opt-in) | `--profile rust-shadow` (opt-in) |
| Volume namespace | `forge-*` | `forge-dev-*` | `forge-prod-*` |
| Network name | `forge-net` | `forge-dev-net` | `forge-prod-net` |
| Source bind-mount | no | no | no |
| Output bind-mounts | autostart only | reports/, imports/, .forge_data/ | autostart only |
| Resource caps style | top-level `cpus`/`mem_limit` | top-level `cpus`/`mem_limit` | top-level `cpus`/`mem_limit` (env-var overridable) |

---

## Migration from `docker-compose.yml` + `low-memory.env.example`

### Step 1 — Create your dev env file

The `.env.dev` at repo root is your new dev secrets file. It ships with
clearly-labeled dev placeholder values. Review and adjust if needed:

```powershell
# Already created by the dev-stack setup — check it exists:
Test-Path .env.dev
```

### Step 2 — Validate the new dev compose file

```powershell
docker compose --env-file .env.dev -f docker/docker-compose.dev.yml config --quiet
docker compose --env-file .env.dev -f docker/docker-compose.dev.yml config --services
```

Expected output from `--services` (default, no profile): `forge-api`, `forge-webui`, `forge-worker`, `postgres`, `redis`

### Step 3 — Remove old containers (if any)

```powershell
# If the old stack was running, stop it first
docker compose -f docker/docker-compose.yml down

# Or remove all stopped containers
docker container prune -f
```

### Step 4 — Start the new dev stack

```powershell
docker compose --env-file .env.dev -f docker/docker-compose.dev.yml build
docker compose --env-file .env.dev -f docker/docker-compose.dev.yml up -d
```

### Step 5 — For production: create `.env.prod`

Copy `.env.dev` as a starting template and replace **every** placeholder value:

```powershell
Copy-Item .env.dev .env.prod
# Edit .env.prod:
# - Set real FORGE_POSTGRES_PASSWORD (>=20 chars, random)
# - Set real FORGE_ENGAGEMENT_KEY (>=64 hex chars)
# - Set real FORGE_WEB_SECRET_KEY (>=64 hex chars)
# - Set real FORGE_WEB_BOOTSTRAP_TOKEN (>=32 chars)
# - Set FORGE_PUBLIC_BASE_URL to your https:// URL
# - Set FORGE_AUDIT_BUNDLE_REMOTE_SCOPE to your customer/workspace label
# - Remove the FORGE_DEPLOYMENT_PROFILE= line (it's set to 'production' in compose)
```

### Volume namespace change

Old volumes were named `forge-postgres`, `forge-data`, etc.
New dev volumes are `forge-dev-postgres-data`, `forge-dev-data`, etc.

If you have data in the old volumes that you want to preserve, migrate it
before switching:

```powershell
# Example: migrate postgres data
docker run --rm `
  -v forge-postgres:/src `
  -v forge-dev-postgres-data:/dst `
  alpine sh -c "cp -av /src/. /dst/"
```

---

## Command cheatsheet

### 5 most common dev commands

```powershell
# 1. Start dev stack (5 Python services — default, no Rust shadow)
docker compose --env-file .env.dev -f docker/docker-compose.dev.yml up -d

# 2. Check service health
docker compose --env-file .env.dev -f docker/docker-compose.dev.yml ps

# 3. Tail forge-api logs
docker compose --env-file .env.dev -f docker/docker-compose.dev.yml logs -f forge-api

# 4. Rebuild after code/dependency changes
docker compose --env-file .env.dev -f docker/docker-compose.dev.yml build --no-cache

# 5. Stop dev stack (keep data)
docker compose --env-file .env.dev -f docker/docker-compose.dev.yml down
```

### Useful extras

```powershell
# Run a one-off command in the api container
docker compose --env-file .env.dev -f docker/docker-compose.dev.yml run --rm forge-api python -m forge.cli doctor --json

# Exec into a running container
docker compose --env-file .env.dev -f docker/docker-compose.dev.yml exec forge-api bash

# Show all FORGE stacks
docker compose ls

# Verify resource caps are set
docker compose --env-file .env.dev -f docker/docker-compose.dev.yml config | Select-String -Pattern "mem_limit|cpus:" -Context 1,0

# Validate prod config before deploying
docker compose --env-file .env.prod -f docker/docker-compose.prod.yml config --quiet
```

---

## Rust shadow endpoints (opt-in)

The Rust shadow services (`forge-rust-api` on :9000 and `forge-rust-webui` on :9080) are
**behind `--profile rust-shadow`** in both the dev and prod stacks. They do NOT start
automatically on a plain `docker compose up -d`.

### Why opt-in?

User pivot (2026-09-29): _"dont want the full system running yet / scaling back to dev work /
all docker need to be minimal footprint (even when real prod)"_. Rust shadow services require
the `forge-toolkit-rust:local` image which must be built separately. Until Phase 4+ parity
work is actively underway, the default stack is the 5-service Python-only configuration.

### Default startup — Python stack only (5 services)

```powershell
# Dev — starts ONLY postgres, redis, forge-api, forge-webui, forge-worker
docker compose --env-file .env.dev -f docker/docker-compose.dev.yml up -d

# Prod equivalent
docker compose --env-file .env.prod -f docker/docker-compose.prod.yml up -d
```

### Opt-in Rust shadow startup — 7 services (for Phase 3+ parity work)

**Prerequisites:** build the Rust image first:
```powershell
docker build -f docker/Dockerfile.rust -t forge-toolkit-rust:local .
```
Then start with the profile:
```powershell
# Dev — all 7 services including Rust shadow on :9000 and :9080
docker compose --env-file .env.dev -f docker/docker-compose.dev.yml --profile rust-shadow up -d

# Prod equivalent
docker compose --env-file .env.prod -f docker/docker-compose.prod.yml --profile rust-shadow up -d
```

### Verify active service count

```powershell
# Default mode — should list 5 services
docker compose --env-file .env.dev -f docker/docker-compose.dev.yml config --services

# With rust-shadow — should list 7 services
docker compose --env-file .env.dev -f docker/docker-compose.dev.yml --profile rust-shadow config --services
```

---

## Environment files

| File | Purpose | Committed? |
|------|---------|------------|
| `.env.dev` | Dev secrets and config | No (`.gitignored`) |
| `.env.prod` | Production secrets and config | No (`.gitignored`) |
| `.env.local` | Legacy local overrides | No (`.gitignored`) |
| `docker/low-memory.env.example` | Old production low-memory reference | Yes (example only) |

Never commit `.env.dev` or `.env.prod`. They contain secrets even when labeled as dev placeholders.

---

## Ports

| Service | Dev | Prod | Notes |
|---------|-----|------|-------|
| forge-api | `127.0.0.1:8000` | `${FORGE_BIND_HOST}:8000` | Loopback by default |
| forge-webui | `127.0.0.1:8080` | `${FORGE_BIND_HOST}:8080` | Loopback by default |
| postgres | internal only | internal only | Never published to host |
| redis | internal only | internal only | Never published to host |

In production behind a reverse proxy, set `FORGE_BIND_HOST=0.0.0.0` only when the
reverse proxy is on the same host. Never expose postgres or redis to the host network.
