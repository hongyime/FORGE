# FORGE Python → Rust Production Cutover Plan

> **Document type**: Plan only — no code, configuration, or data is modified by this document.  
> **Status**: Draft  
> **Last updated**: 2026-09-27  
> **Rust rewrite milestone**: T1–T36 complete (36/36), 16 xtask verify canaries green  
> **Migration ledger**: `native/migration/domain-contracts.json` — 118 entries, 118/118 `implemented_fixture_verified`

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Current State](#2-current-state)
   - 2.1 [Python Services (running)](#21-python-services-running)
   - 2.2 [Rust Crates (built, not yet primary)](#22-rust-crates-built-not-yet-primary)
   - 2.3 [Service-to-Crate Mapping](#23-service-to-crate-mapping)
3. [Prerequisites for Cutover](#3-prerequisites-for-cutover)
4. [Phased Cutover Plan](#4-phased-cutover-plan)
   - [Phase 0 — Baseline](#phase-0--baseline-current-state-canary-ci-hook-active)
   - [Phase 1 — Build Rust Production Binaries + Docker Images](#phase-1--build-rust-production-binaries--docker-images)
   - [Phase 2 — Shadow Rust Services on Alternate Ports](#phase-2--shadow-rust-services-on-alternate-ports)
   - [Phase 3 — Traffic Parity Testing](#phase-3--traffic-parity-testing)
   - [Phase 4 — Cutover (Flip Primary Ports to Rust)](#phase-4--cutover-flip-primary-ports-to-rust)
   - [Phase 5 — Delete Python (forge/ + pyproject.toml deps)](#phase-5--delete-python-forge--pyprojecttoml-deps)
   - [Phase 6 — Full Cleanup (tests/ + docs references)](#phase-6--full-cleanup-tests--docs-references)
5. [Per-Phase Acceptance Criteria](#5-per-phase-acceptance-criteria)
6. [Rollback Plan per Phase](#6-rollback-plan-per-phase)
7. [Known Gaps](#7-known-gaps)
8. [Timeline Estimate](#8-timeline-estimate)
9. [Top-5 Risks and Mitigations](#9-top-5-risks-and-mitigations)
10. [File-Level Deletion Checklist](#10-file-level-deletion-checklist)

---

## 1. Executive Summary

The FORGE Python codebase (`forge/`, 149 MB, 554 `.py` files) is fully shadowed by
a completed Rust rewrite (`native/crates/`, 13 crates, tasks T1–T36). All 118
domain-contract entries in `native/migration/domain-contracts.json` are
`implemented_fixture_verified`, and all 16 xtask verify canaries pass in CI.
The Docker Compose production stack currently runs three Python services
(`forge-api` on :8000, `forge-webui` on :8080, `forge-worker`) via `uvicorn` and
`python -m`. This plan describes a six-phase, fully reversible path from that
Python-primary state to a Rust-only stack where `forge/` can be safely deleted.
Each phase is atomic, has concrete acceptance commands, and has a named rollback
action. Python remains available as a fallback container through Phase 4; it is
only deleted in Phase 5 after two weeks of clean Rust production traffic.

---

## 2. Current State

### 2.1 Python Services (running)

| Compose service | Command | Primary port | Health probe |
|---|---|---|---|
| `forge-api` | `uvicorn forge.api.app:app --host 0.0.0.0 --port 8000` | `:8000` | `http://localhost:8000/health` |
| `forge-webui` | `uvicorn forge.webui.app:create_app --factory --host 0.0.0.0 --port 8080` | `:8080` | `http://localhost:8080/health` |
| `forge-worker` | `python -m forge.core.runner` | none (pub/sub) | Compose `depends_on` |
| `forge-guarded-autostart` | `python -m forge.cli automation cycle ...` | none | Compose `depends_on` |

Supporting services (unchanged through all phases):

| Compose service | Image | Port |
|---|---|---|
| `postgres` | `postgres:16-alpine` | `:5432` (internal) |
| `redis` | `redis:7-alpine` | `:6379` (internal) |

**Python entry point** (`pyproject.toml` line 120):
```
forge = "forge.cli:main"
```
This entry point is installed by `pip install -e .` and must survive until Phase 5,
at which point it is replaced by the Rust `forge-cli` binary installed at the same
`forge` name in `$PATH`.

**Python test suite**: 572 tests under `tests/`, baseline ≥ 2,100 passing (README).

### 2.2 Rust Crates (built, not yet primary)

Location: `native/crates/`

| Crate | Role | Maps to Python service |
|---|---|---|
| `forge-domain` | Domain models, enums, boundary types | Shared (all services) |
| `forge-crypto` | Encryption, JWT signing, secret store | `forge/webui/auth.py`, `forge/crypto/` |
| `forge-storage` | SQLite/Postgres access layer | `forge/db/` |
| `forge-policy` | Scope gate, ROE, safety enforcement | `forge/opsec/scope_gate.py` |
| `forge-adapters` | External connector adapters | `forge/connectors/` |
| `forge-discovery` | Kill-chain discovery pipeline | `forge/phase1/`–`forge/phase4/` |
| `forge-reporting` | Phase 6 report synthesis | `forge/phase6/` |
| `forge-operations` | Automation, monitoring, remediation | `forge/automation/`, `forge/monitoring/` |
| `forge-server` | HTTP API + WebSocket platform server | `forge-api` (`:8000`) |
| `forge-ui` | Server-side rendered engagement UI | `forge-webui` (`:8080`) |
| `forge-cli` | CLI command routing | `forge.cli:main` entry point |
| `forge-release` | Release packaging, version stamps | CI/CD tooling |
| `forge-runtime` | Binary entrypoint wiring | Compose `CMD` |

### 2.3 Service-to-Crate Mapping

```
Python forge-api  (:8000)  →  Rust forge-server  (:8000)
  forge/webui/api/          →    native/crates/forge-server/src/api.rs
  forge/webui/auth.py       →    JwtClaims / AuthRole / check_permission
  /health                   →    PlatformHealth / check_readiness (platform.rs)
  /ready                    →    ReadinessState (platform.rs)
  /metrics                  →    MetricsSample (platform.rs)
  /ws/progress              →    FORGE_PROGRESS_SUBPROTOCOL / ProgressEvent (api.rs)
  /api/token                →    AuthRole::from_str + JwtClaims::new

Python forge-webui (:8080)  →  Rust forge-ui  (:8080)
  forge/webui/routes.py     →    UIRoute enum (ui.rs)
  GET /                     →    UIRoute::Overview → OverviewView
  GET /engagements/{ref}    →    UIRoute::EngagementDetail → EngagementDetailView
  GET /engagements/{ref}/tab/{name}  →  UIRoute::EngagementTab / DetailTab
  GET /workspaces           →    UIRoute::WorkspaceAdmin → WorkspacePanel
  GET /login                →    UIRoute::Login  (no auth required)
  GET /health               →    UIRoute::Health (no auth required)
  HTMX fragments            →    UIRoute::EngagementTab (confirmed in ui.rs)

Python forge-worker         →  Rust forge-operations worker thread
  forge.core.runner         →    forge-operations background worker
  WorkerHeartbeat           →    WorkerHeartbeat::is_fresh (platform.rs)

Python forge.cli:main       →  Rust forge-cli binary
  forge/cli_registry.py     →    CommandKind / HiddenCommandKind / route_command (cli.rs)
  All 25 public commands    →    CommandKind enum (kill-chain through clean)
  All 9 hidden sub-apps     →    HiddenCommandKind enum (recon through post)
  forge kill-chain          →    CommandKind::KillChain (requires_roe=true)
  forge doctor              →    CommandKind::Doctor (read_only=false, requires_roe=false)
  ExitCode contract         →    ExitCode::Success(0)/UserError(1)/InternalError(2)
```

**Migration ledger coverage** (`domain-contracts.json`):
- Declared inventory: **118** domain contracts
- Status `implemented_fixture_verified`: **118/118** (100 %)
- Total differential test cases across all entries: > 1,400
- All entries cross-reference specific Rust test IDs in `forge_domain`, `forge_crypto`

---

## 3. Prerequisites for Cutover

The following conditions must ALL be true before Phase 1 may begin. Each has a
verification command.

### P-1 — All Rust xtask canaries green

```powershell
# From repo root
cargo xtask verify
# Expected: "All 16 canaries passed" with exit code 0
```

### P-2 — Domain-contract ledger fully implemented

```powershell
# Count non-implemented entries
$j = Get-Content native/migration/domain-contracts.json | ConvertFrom-Json
$gap = $j.entries | Where-Object { $_.status -ne "implemented_fixture_verified" }
Write-Output "Gap count: $($gap.Count)"
# Expected: Gap count: 0
```

### P-3 — Python tests baseline is green (frozen snapshot)

```powershell
# Activate venv, run Python suite
.venv\Scripts\pytest tests\ -m "not integration and not slow" -q
# Expected: all tests pass, 0 failures
# Record this as the frozen Python baseline SHA for regression comparison
```

### P-4 — Rust binary builds clean with production feature flags

```powershell
cargo build --release --workspace 2>&1 | Select-String -Pattern "error\["
# Expected: no lines containing "error["
```

### P-5 — Docker Compose stack health (Python-primary baseline)

```bash
docker compose -f docker/docker-compose.yml ps
# Expected: forge-api, forge-webui, forge-worker all "healthy" or "running"

curl -sf http://127.0.0.1:8000/health && echo "API OK"
curl -sf http://127.0.0.1:8080/health && echo "WEB OK"
# Expected: both return HTTP 200
```

### P-6 — Postgres and Redis connectivity confirmed

```bash
docker exec forge-postgres-1 pg_isready -U forge -d forge
docker exec forge-redis-1 redis-cli ping
# Expected: "accepting connections", "PONG"
```

### P-7 — `forge doctor` clean on Python stack

```bash
docker exec forge-api-1 python -m forge.cli doctor --json 2>/dev/null \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('overall_status','unknown'))"
# Expected: "ready" or "warning" (not "error" on critical checks)
```

### P-8 — Rust integration tests pass against live Postgres + Redis

```powershell
# Requires forge-postgres and forge-redis containers running
$env:FORGE_STATE_DB_URL = "postgresql://forge:${env:FORGE_POSTGRES_PASSWORD}@localhost:5432/forge"
$env:FORGE_REDIS_URL    = "redis://localhost:6379/0"
cargo test --release -p forge-storage -p forge-server -- --test-threads=1
# Expected: 0 failures
```

### P-9 — Reverse proxy / TLS terminator config confirmed

```bash
# Confirm upstream addresses in nginx/Caddy config point to 127.0.0.1:8000 and :8080
grep -E "8000|8080" docker/reverse-proxy/nginx.conf
# These do NOT need to change for Phase 4 — the Rust services bind the same ports.
```

---

## 4. Phased Cutover Plan

### Phase 0 — Baseline (current state, canary CI hook active)

**Goal**: Establish a documented, reproducible Python-primary baseline with CI
canary hooks running so any regression in the Rust crates is caught before Phase 1.

**Actions** (read-only, already in place):

1. Confirm `cargo xtask verify` runs in CI on every push to `main`.
2. Record the current Python test count:
   ```powershell
   .venv\Scripts\pytest tests\ --collect-only -q 2>&1 | Select-String "selected"
   ```
3. Record the production Docker image SHA:
   ```bash
   docker inspect forge-toolkit:local --format='{{.Id}}' > .agents/baseline-image-sha.txt
   ```
4. Tag the last Python-primary commit:
   ```bash
   git tag python-primary-baseline
   ```

**Exit state**: CI is green on both `cargo xtask verify` and `pytest`. The
`python-primary-baseline` tag is pushed. No service changes.

---

### Phase 1 — Build Rust Production Binaries + Docker Images

**Goal**: Produce a `forge-toolkit-rust:local` Docker image containing the compiled
Rust binaries. The image is built but no containers are started yet.

**Actions**:

1. **Write a Rust-only Dockerfile target** alongside the existing `runtime` target.
   The new target (`rust-runtime`) copies only the compiled Rust binaries from a
   `cargo build --release` builder stage and the shared `/data` volume mounts:

   ```dockerfile
   # --- rust-builder stage (add to docker/Dockerfile) ---
   FROM rust:1.82-slim AS rust-builder
   WORKDIR /build
   COPY native/ native/
   COPY Cargo.toml Cargo.lock ./
   RUN cargo build --release --workspace

   # --- rust-runtime target ---
   FROM debian:bookworm-slim AS rust-runtime
   RUN useradd -u 10001 -M -s /bin/false forge
   COPY --from=rust-builder /build/target/release/forge-server  /usr/local/bin/forge-server
   COPY --from=rust-builder /build/target/release/forge-worker  /usr/local/bin/forge-worker
   COPY --from=rust-builder /build/target/release/forge         /usr/local/bin/forge
   USER 10001
   ```

2. **Build the Rust image**:
   ```bash
   docker build \
     --target rust-runtime \
     -t forge-toolkit-rust:local \
     -f docker/Dockerfile .
   ```

3. **Smoke-test the binary inside the image** (no network, no DB):
   ```bash
   docker run --rm forge-toolkit-rust:local forge --help
   # Expected: FORGE help text printed, exit 0

   docker run --rm forge-toolkit-rust:local forge-server --version
   # Expected: version string printed, exit 0
   ```

4. **Confirm binary sizes are sane**:
   ```bash
   docker run --rm forge-toolkit-rust:local du -sh /usr/local/bin/forge*
   # Expected: each binary < 50 MB (strip symbols in release build if needed)
   ```

**Exit state**: Image `forge-toolkit-rust:local` exists locally. All three binaries
respond to `--help`. No production traffic has touched Rust yet.

---

### Phase 2 — Add Rust Services to docker-compose as Shadow Endpoints

**Goal**: Run `forge-server` and `forge-worker` as shadow containers on alternate
ports (`:9000`, `:9080`) alongside the live Python services. No production traffic
is routed to Rust yet.

**Actions**:

1. **Create `docker/docker-compose.shadow.yml`** (override file, not modifying the
   production compose):

   ```yaml
   # docker/docker-compose.shadow.yml
   # Run Rust services in parallel on shadow ports for parity testing.
   # DO NOT modify docker-compose.yml — this file overlays it.
   services:
     forge-api-rust:
       image: "forge-toolkit-rust:local"
       command: ["forge-server", "--host", "0.0.0.0", "--port", "9000"]
       ports:
         - "127.0.0.1:9000:9000"
       environment:
         <<: *forge-env
       depends_on:
         postgres:
           condition: service_healthy
         redis:
           condition: service_healthy
       healthcheck:
         test: ["CMD-SHELL",
                "forge-server health-check --url http://localhost:9000/health || exit 1"]
         interval: 15s
         timeout: 20s
         retries: 5
         start_period: 30s
       networks:
         - forge-net
       restart: unless-stopped
       user: "10001:10001"
       read_only: true
       cap_drop: [ALL]
       security_opt: [no-new-privileges:true]
       tmpfs: [/tmp:rw,noexec,nosuid,size=64m]
       volumes:
         - forge-data:/data
         - forge-remote-audit:/remote-audit

     forge-webui-rust:
       image: "forge-toolkit-rust:local"
       command: ["forge-server", "--host", "0.0.0.0", "--port", "9080", "--mode", "ui"]
       ports:
         - "127.0.0.1:9080:9080"
       environment:
         <<: *forge-env
         FORGE_WEB_PORT: "9080"
       depends_on:
         postgres:
           condition: service_healthy
         redis:
           condition: service_healthy
       healthcheck:
         test: ["CMD-SHELL",
                "forge-server health-check --url http://localhost:9080/health || exit 1"]
         interval: 15s
         timeout: 20s
         retries: 5
         start_period: 30s
       networks:
         - forge-net
       restart: unless-stopped
       user: "10001:10001"
       read_only: true
       cap_drop: [ALL]
       security_opt: [no-new-privileges:true]
       tmpfs: [/tmp:rw,noexec,nosuid,size=64m]
       volumes:
         - forge-data:/data
         - forge-remote-audit:/remote-audit

     forge-worker-rust:
       image: "forge-toolkit-rust:local"
       command: ["forge-worker"]
       environment:
         <<: *forge-env
       depends_on:
         postgres:
           condition: service_healthy
         redis:
           condition: service_healthy
       networks:
         - forge-net
       restart: unless-stopped
       user: "10001:10001"
       read_only: true
       cap_drop: [ALL]
       security_opt: [no-new-privileges:true]
       tmpfs: [/tmp:rw,noexec,nosuid,size=64m]
       volumes:
         - forge-data:/data
   ```

2. **Start the shadow stack** (Python primary still serving :8000/:8080):
   ```bash
   docker compose \
     -f docker/docker-compose.yml \
     -f docker/docker-compose.shadow.yml \
     up -d forge-api-rust forge-webui-rust forge-worker-rust
   ```

3. **Confirm shadow health**:
   ```bash
   curl -sf http://127.0.0.1:9000/health && echo "Rust API shadow OK"
   curl -sf http://127.0.0.1:9080/health && echo "Rust UI shadow OK"
   # Expected: both 200 OK with JSON {"overall":"healthy",...}
   ```

4. **Confirm Python primary is unaffected**:
   ```bash
   curl -sf http://127.0.0.1:8000/health && echo "Python API still OK"
   curl -sf http://127.0.0.1:8080/health && echo "Python UI still OK"
   ```

**Exit state**: Six application containers running (3 Python primary + 3 Rust
shadow). Python continues serving all real traffic on :8000/:8080. Rust shadows
are reachable on :9000/:9080 from localhost for testing only.

---

### Phase 3 — Traffic Parity Testing

**Goal**: Validate that the Rust shadow produces byte-for-byte or semantically
equivalent responses for every significant Python API path. No traffic routing
change; comparison is done via manual `curl` and an automated parity harness.

**Parity test harness** (create as `tools/parity_check.sh`, do not commit to main
until Phase 4 is approved):

```bash
#!/usr/bin/env bash
# tools/parity_check.sh — Compare Python (:8000) vs Rust (:9000) responses.
# Usage: FORGE_JWT=<token> bash tools/parity_check.sh
set -euo pipefail

PY_BASE="http://127.0.0.1:8000"
RS_BASE="http://127.0.0.1:9000"
PASS=0; FAIL=0

compare() {
  local endpoint="$1" method="${2:-GET}" body="${3:-}"
  local py_out rs_out
  if [[ -n "$body" ]]; then
    py_out=$(curl -sf -X "$method" -H "Authorization: Bearer $FORGE_JWT" \
               -H "Content-Type: application/json" -d "$body" "${PY_BASE}${endpoint}" 2>&1)
    rs_out=$(curl -sf -X "$method" -H "Authorization: Bearer $FORGE_JWT" \
               -H "Content-Type: application/json" -d "$body" "${RS_BASE}${endpoint}" 2>&1)
  else
    py_out=$(curl -sf -H "Authorization: Bearer $FORGE_JWT" "${PY_BASE}${endpoint}" 2>&1)
    rs_out=$(curl -sf -H "Authorization: Bearer $FORGE_JWT" "${RS_BASE}${endpoint}" 2>&1)
  fi
  if [[ "$py_out" == "$rs_out" ]]; then
    echo "PASS  $method $endpoint"
    PASS=$((PASS+1))
  else
    echo "FAIL  $method $endpoint"
    echo "  PY: $(echo "$py_out" | head -1)"
    echo "  RS: $(echo "$rs_out" | head -1)"
    FAIL=$((FAIL+1))
  fi
}

# ── Health / readiness (unauthenticated) ─────────────────────────────────────
compare /health
compare /ready

# ── Token endpoint ────────────────────────────────────────────────────────────
# (compare HTTP status only — tokens differ by timestamp)
PY_HTTP=$(curl -so /dev/null -w "%{http_code}" -X POST \
  -d '{"token":"'"$FORGE_BOOTSTRAP_TOKEN"'"}' \
  -H "Content-Type: application/json" "${PY_BASE}/api/token")
RS_HTTP=$(curl -so /dev/null -w "%{http_code}" -X POST \
  -d '{"token":"'"$FORGE_BOOTSTRAP_TOKEN"'"}' \
  -H "Content-Type: application/json" "${RS_BASE}/api/token")
[[ "$PY_HTTP" == "$RS_HTTP" ]] && echo "PASS  POST /api/token (HTTP $PY_HTTP)" \
  && PASS=$((PASS+1)) || { echo "FAIL  POST /api/token (PY=$PY_HTTP RS=$RS_HTTP)"; FAIL=$((FAIL+1)); }

# ── Engagement list ───────────────────────────────────────────────────────────
compare "/api/engagements"
compare "/api/engagements?limit=5&offset=0"

# ── Workspace list ────────────────────────────────────────────────────────────
compare "/api/workspaces"

# ── Web UI routes ─────────────────────────────────────────────────────────────
WEB_PY="http://127.0.0.1:8080"
WEB_RS="http://127.0.0.1:9080"
for path in "/" "/login" "/health" "/workspaces"; do
  py_s=$(curl -so /dev/null -w "%{http_code}" -H "Authorization: Bearer $FORGE_JWT" \
    "${WEB_PY}${path}" 2>/dev/null)
  rs_s=$(curl -so /dev/null -w "%{http_code}" -H "Authorization: Bearer $FORGE_JWT" \
    "${WEB_RS}${path}" 2>/dev/null)
  [[ "$py_s" == "$rs_s" ]] && echo "PASS  UI $path (HTTP $py_s)" && PASS=$((PASS+1)) \
    || { echo "FAIL  UI $path (PY=$py_s RS=$rs_s)"; FAIL=$((FAIL+1)); }
done

echo ""
echo "Parity result: PASS=$PASS FAIL=$FAIL"
[[ $FAIL -eq 0 ]] && exit 0 || exit 1
```

**Parity test execution**:
```bash
export FORGE_JWT="$(curl -sf -X POST \
  -d "{\"token\":\"$FORGE_BOOTSTRAP_TOKEN\"}" \
  -H 'Content-Type: application/json' \
  http://127.0.0.1:8000/api/token | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')"

bash tools/parity_check.sh
# Expected: FAIL=0
```

**Additional manual checks**:

```bash
# 1. WebSocket subprotocol — Rust must negotiate "forge-progress"
#    (requires wscat: npm i -g wscat)
wscat -c "ws://127.0.0.1:9000/ws/progress" \
  --subprotocol forge-progress \
  --header "Authorization: Bearer $FORGE_JWT" \
  -w 3
# Expected: connection accepted (exit 0 or normal close), not rejected

# 2. JWT role enforcement — Viewer token must be denied write on Rust
VIEWER_JWT="$(curl -sf -X POST \
  -d '{"token":"'"$FORGE_BOOTSTRAP_TOKEN"'","role":"viewer"}' \
  -H 'Content-Type: application/json' \
  http://127.0.0.1:9000/api/token | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')"
HTTP_STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST \
  -H "Authorization: Bearer $VIEWER_JWT" \
  -H 'Content-Type: application/json' \
  -d '{"title":"test"}' \
  http://127.0.0.1:9000/api/engagements)
echo "Viewer write attempt: $HTTP_STATUS"  # Expected: 403

# 3. Audit-chain integrity — Python and Rust must produce same hash-chain head
docker exec forge-api-1 python -m forge.cli audit manifest-verify --engagement 9901 --json \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["chain_valid"])'
# Expected: true
# Re-run same verification against Rust API (same DB mount):
curl -sf -H "Authorization: Bearer $FORGE_JWT" \
  http://127.0.0.1:9000/api/engagements/9901/audit/verify | python3 -c \
  'import json,sys; d=json.load(sys.stdin); print(d["chain_valid"])'
# Expected: true

# 4. Domain-model round-trip — POST a CommandAction to Rust, re-read from Python
#    Both must return identical JSON for the same engagement row.
```

**Parity duration**: Run parity tests for a minimum of **3 days** (72 hours) with
at least one full kill-chain engagement processed through the Rust worker. If any
parity failure appears, stop and fix before advancing.

**Exit state**: `tools/parity_check.sh` exits 0 for 3 consecutive days. All
engagement data written by Rust is readable without error by Python. No data
corruption detected in Postgres.

---

### Phase 4 — Cutover (Flip Primary Ports to Rust, Keep Python as Fallback)

**Goal**: Rust becomes the primary service on :8000 and :8080. Python services
remain running as fallback containers on :8001 and :8081.

**Pre-cutover checkpoint** (must all be YES):
- [ ] Phase 3 parity tests passed for ≥ 3 days  
- [ ] No open P0/P1 bugs against Rust shadow in issue tracker  
- [ ] On-call operator identified and available for 24 hours post-cutover  
- [ ] Postgres backup taken within last hour  

```bash
# Backup Postgres before cutover
docker exec forge-postgres-1 pg_dump -U forge forge \
  | gzip > backups/forge-pre-cutover-$(date +%Y%m%d-%H%M%S).sql.gz
echo "Backup size: $(du -sh backups/forge-pre-cutover-*.sql.gz | tail -1)"
```

**Actions**:

1. **Stop Python primary services** (order matters — API last so in-flight requests
   drain):
   ```bash
   docker compose -f docker/docker-compose.yml stop forge-worker
   sleep 10   # let in-flight worker jobs drain
   docker compose -f docker/docker-compose.yml stop forge-webui
   docker compose -f docker/docker-compose.yml stop forge-api
   ```

2. **Remap Rust shadow services to primary ports** by editing
   `docker/docker-compose.shadow.yml` to expose :8000 and :8080:
   ```bash
   # This is the ONLY file edit in Phase 4.
   # Change forge-api-rust ports:   9000 → 8000
   # Change forge-webui-rust ports: 9080 → 8080
   # Then bring those services up with new port bindings:
   docker compose \
     -f docker/docker-compose.yml \
     -f docker/docker-compose.shadow.yml \
     up -d --force-recreate forge-api-rust forge-webui-rust forge-worker-rust
   ```

3. **Restart Python services on fallback ports** (port shift only):
   ```bash
   # Edit docker-compose.yml temporarily to shift Python ports:
   #   forge-api:   127.0.0.1:8001:8000
   #   forge-webui: 127.0.0.1:8081:8080
   docker compose -f docker/docker-compose.yml up -d \
     --force-recreate forge-api forge-webui forge-worker
   ```

4. **Validate Rust is serving primary ports**:
   ```bash
   # Must show Rust version header, not Python/uvicorn
   curl -sI http://127.0.0.1:8000/health | grep -i server
   # Expected: "Server: forge-server/<version>" (not "uvicorn")

   curl -sf http://127.0.0.1:8000/health | python3 -m json.tool
   # Expected: {"overall":"healthy","version":"<rust-semver>","uptime_seconds":...}

   curl -sf http://127.0.0.1:8080/health
   # Expected: 200 OK from Rust UI
   ```

5. **Confirm fallback Python ports are reachable**:
   ```bash
   curl -sf http://127.0.0.1:8001/health && echo "Python fallback API OK"
   curl -sf http://127.0.0.1:8081/health && echo "Python fallback UI OK"
   ```

6. **Run parity check against new primary Rust**:
   ```bash
   # Update PY_BASE/RS_BASE targets in parity script for new port layout
   bash tools/parity_check.sh  # must still exit 0
   ```

7. **Run smoke engagement** through Rust primary:
   ```bash
   docker run --rm \
     --env-file .env \
     --network forge_forge-net \
     forge-toolkit-rust:local \
     forge kill-chain example.internal --engagement 9999 --dry-run --no-attack-mode
   # Expected: exit 0, "dry-run" output, no Python import errors
   ```

**Monitor for 48 hours** before proceeding to Phase 5. If any alert fires, execute
the Phase 4 rollback immediately.

**Exit state**: Rust serves :8000 and :8080 as primary. Python runs on :8001/:8081
as hot standby. Zero errors in Rust logs for 48 hours. All existing monitors/alerts
are green.

---

### Phase 5 — Delete Python (forge/ + pyproject.toml Python deps)

**Goal**: Remove the Python runtime entirely from the Docker image and compose stack.
After this phase `forge/` is gone and `tests/` (Python) is gone.

**Prerequisites before Phase 5 may begin**:
- [ ] 48 hours of clean Rust primary traffic (no rollbacks)  
- [ ] Python fallback containers (:8001/:8081) have received zero traffic for 48 hours  
- [ ] `forge doctor` passes against Rust API  
- [ ] All Python monitoring probes updated to use Rust equivalents  

**Actions**:

1. **Stop and remove Python fallback containers**:
   ```bash
   docker compose -f docker/docker-compose.yml stop \
     forge-api forge-webui forge-worker forge-guarded-autostart
   docker compose -f docker/docker-compose.yml rm -f \
     forge-api forge-webui forge-worker forge-guarded-autostart
   ```

2. **Replace the `forge` CLI entry point** — install the Rust binary to the same
   name so operator scripts continue to work:
   ```bash
   # On the host (or inside a deployment container):
   cp target/release/forge /usr/local/bin/forge
   forge --version   # Expected: Rust-compiled version string, not Python
   ```

3. **Delete the Python source tree**:
   ```bash
   # Step 3a: prove no live container imports Python forge any more
   docker exec forge-api-rust-1 python -c "import forge.api.app" 2>&1
   # Expected: "ModuleNotFoundError: No module named 'forge'" (Python not present)
   # OR: "python: command not found" (Python runtime removed from Rust image)

   # Step 3b: delete source (after confirming git tag exists for recovery)
   git tag pre-python-delete-$(date +%Y%m%d)
   git rm -r forge/
   git rm tests/           # Python test suite
   git rm pyproject.toml
   git rm setup.bat setup.sh bootstrap.py
   git rm .venv/          # if committed (usually .gitignore'd)
   git commit -m "chore(cutover): delete Python runtime, tests, and pyproject.toml [Phase 5]"
   ```

4. **Remove Python from Dockerfile** — keep only the `rust-runtime` target:
   ```bash
   # Edit docker/Dockerfile:
   #   - Remove Python base image stages (python:3.11-slim, /opt/forge/venv, pip install)
   #   - Remove COPY forge/ and COPY tests/
   #   - Keep only rust-builder and rust-runtime targets
   # Rebuild:
   docker build --target rust-runtime -t forge-toolkit:local -f docker/Dockerfile .
   ```

5. **Consolidate compose files** — merge `docker-compose.shadow.yml` into the main
   `docker-compose.yml` (Rust services at :8000/:8080, Python services removed):
   ```bash
   # Update docker-compose.yml:
   #   forge-api  → forge-server Rust binary on :8000
   #   forge-webui → forge-ui Rust binary on :8080
   #   forge-worker → forge-worker Rust binary
   # Delete docker-compose.shadow.yml
   git rm docker/docker-compose.shadow.yml
   ```

6. **Verify nothing imports Python**:
   ```bash
   # Search entire repo for any remaining Python import of the forge package
   grep -r "from forge\." . --include="*.py" --include="*.yml" --include="*.yaml" \
     --include="Dockerfile" | grep -v ".git"
   # Expected: zero results

   grep -r "import forge" . --include="*.py" | grep -v ".git"
   # Expected: zero results

   grep -r "uvicorn" . --include="*.yml" --include="*.yaml" \
     --include="Dockerfile" | grep -v ".git"
   # Expected: zero results
   ```

**Exit state**: `forge/`, `tests/` (Python), `pyproject.toml` are deleted from HEAD.
Docker image builds from the Rust-only Dockerfile. `docker compose up` starts only
Rust containers. No Python interpreter exists in the production image.

---

### Phase 6 — Full Cleanup (Rust integration tests + docs)

**Goal**: Replace the deleted Python test suite with Rust integration tests. Update
all documentation to be Rust-first. Clean up migration artifacts.

**Actions**:

1. **Write Rust integration tests** covering the same scenarios as the deleted
   Python suite:
   ```bash
   # Location: native/tests/integration/
   cargo test --release -p forge-server -- --test-threads=4
   cargo test --release -p forge-operations -- --test-threads=2
   # Target: ≥ 80% of former Python test coverage reproduced in Rust
   ```

2. **Update README.md** — remove Python install instructions, replace with Rust
   binary install:
   ```markdown
   ## Install
   # Replace Python setup.bat / setup.sh / bootstrap.py section with:
   cargo install --path native/crates/forge-cli
   forge --version
   ```

3. **Delete migration artifacts** that are no longer needed:
   ```bash
   git rm native/migration/domain-contracts.json
   git rm -r native/migration/
   # Keep native/crates/ — that is the production codebase now
   ```

4. **Update CI workflows** — remove Python CI jobs:
   ```bash
   # Delete or comment out .github/workflows/ jobs that run:
   #   - pip install / pytest
   #   - mypy / ruff / bandit (Python linters)
   #   - Python Dependabot ecosystem entry
   # Keep:
   #   - cargo test / cargo clippy / cargo xtask verify
   #   - Rust Dependabot ecosystem
   ```

5. **Archive documentation** that referenced Python workflows:
   ```bash
   mkdir -p docs/history/python-era
   git mv docs/history/AUDIT.md docs/history/python-era/
   # Move any Python-specific guides to docs/history/python-era/
   ```

6. **Final audit — prove forge/ is completely gone**:
   ```bash
   find . -name "*.py" | grep -v ".git" | grep -v "native/"
   # Expected: zero results (or only third-party tool scripts under tools/)

   find . -path "*/forge/*.py" | grep -v ".git"
   # Expected: zero results
   ```

**Exit state**: Rust-only repository. Python test suite replaced by Rust integration
tests. CI runs only Rust toolchain. `forge/` is absent from the entire git tree.
Milestone: **`forge/` deleted safely**.

---

## 5. Per-Phase Acceptance Criteria

| Phase | Gate | Verification command | Expected result |
|---|---|---|---|
| **0** | CI canary green | `cargo xtask verify` | Exit 0, "16 canaries passed" |
| **0** | Python tests green | `.venv\Scripts\pytest tests\ -q` | 0 failures |
| **1** | Rust image builds | `docker build --target rust-runtime ...` | Exit 0 |
| **1** | Binaries respond | `docker run --rm forge-toolkit-rust:local forge --help` | FORGE help text |
| **2** | Shadow health | `curl -sf http://127.0.0.1:9000/health` | HTTP 200, `"overall":"healthy"` |
| **2** | Primary unaffected | `curl -sf http://127.0.0.1:8000/health` | HTTP 200 from Python |
| **3** | Parity test passes | `bash tools/parity_check.sh` | `FAIL=0` for 3 days |
| **3** | Audit chain valid | Rust verify endpoint | `"chain_valid":true` |
| **3** | Kill-chain dry-run | `forge kill-chain ... --dry-run` via Rust | Exit 0, no errors |
| **4** | Rust is primary | `curl -sI http://127.0.0.1:8000/health \| grep server` | `Server: forge-server/…` |
| **4** | Python fallback up | `curl -sf http://127.0.0.1:8001/health` | HTTP 200 from Python |
| **4** | 48 h no rollback | Monitor logs | Zero error-level events in Rust logs |
| **5** | Python gone | `grep -r "uvicorn" . --include="*.yml"` | Zero results |
| **5** | No Python imports | `find . -path "*/forge/*.py" \| grep -v .git` | Zero results |
| **5** | Compose starts clean | `docker compose up -d` | Rust containers healthy |
| **6** | Rust tests green | `cargo test --release --workspace` | 0 failures |
| **6** | Migration gone | `ls native/migration/` | No such directory |
| **6** | CI Python jobs gone | `.github/workflows/` audit | No `pip install` or `pytest` |

---

## 6. Rollback Plan per Phase

### Phase 1 Rollback
Nothing has changed in production. Delete the `forge-toolkit-rust:local` image:
```bash
docker rmi forge-toolkit-rust:local
```
Cost: ~0 minutes. Risk: none.

### Phase 2 Rollback
Stop and remove the shadow containers. Python primary was never affected:
```bash
docker compose \
  -f docker/docker-compose.yml \
  -f docker/docker-compose.shadow.yml \
  stop forge-api-rust forge-webui-rust forge-worker-rust
docker compose \
  -f docker/docker-compose.yml \
  -f docker/docker-compose.shadow.yml \
  rm -f forge-api-rust forge-webui-rust forge-worker-rust
```
Cost: < 1 minute. Risk: none — primary ports were never touched.

### Phase 3 Rollback
Same as Phase 2 rollback. Any data written to Postgres by the Rust shadow during
parity testing is compatible with Python (same schema). No data loss.

### Phase 4 Rollback
This is the most critical rollback. Execute within 5 minutes of detecting an issue:

```bash
# Step 1: Stop Rust primary containers
docker compose \
  -f docker/docker-compose.yml \
  -f docker/docker-compose.shadow.yml \
  stop forge-api-rust forge-webui-rust forge-worker-rust

# Step 2: Shift Python fallback back to primary ports
#   Edit docker-compose.yml: change 8001→8000, 8081→8080
docker compose -f docker/docker-compose.yml up -d \
  --force-recreate forge-api forge-webui forge-worker

# Step 3: Validate Python is primary again
curl -sf http://127.0.0.1:8000/health
curl -sI http://127.0.0.1:8000/health | grep -i server
# Expected: uvicorn server header

# Step 4: Page the on-call operator and open a post-mortem
```

Cost: 2–5 minutes. No data loss expected (shared Postgres volume).
**Any data written by Rust during Phase 4 is fully compatible with Python** because
Rust crates use the same PostgreSQL schema (verified by migration ledger).

### Phase 5 Rollback
Phase 5 deletes source files via `git rm` and commits. The git history is intact.
Recovery:
```bash
# Recover Python source from the pre-delete tag
git checkout pre-python-delete-YYYYMMDD -- forge/ tests/ pyproject.toml
# Rebuild Python Docker image
docker build --target runtime -t forge-toolkit:local -f docker/Dockerfile .
# Re-deploy Python services
docker compose -f docker/docker-compose.yml up -d
```
Cost: 10–30 minutes (image rebuild). Risk: low — no data is deleted.

**Important**: Do NOT begin Phase 5 until Phase 4 has run cleanly for ≥ 48 hours.

### Phase 6 Rollback
Phase 6 removes migration artifacts and CI jobs. These are all in git history.
Recovery is `git revert <commit>` on the cleanup commit. No production impact.

---

## 7. Known Gaps

The following functionality exists in the Python stack but has NOT been verified
as fully ported to the Rust crates. These gaps are **blockers for Phase 3** unless
explicitly acknowledged and mitigated.

### GAP-1: Offensive-security primitives in `rust_core/src/`

The Python `forge/phase3/` (evasion) and `forge/phase5/` (post-exploitation)
modules depend on `rust_core/src/*.rs` — a **separate, older Rust FFI boundary**
that is distinct from the `native/crates/` rewrite. This is the FFI boundary
approved on 2026-09-18 (Win32 job assignment, process-tree cleanup, bounded I/O).

**Status**: `forge-operations` crate does NOT replace these modules. The hidden
CLI commands (`recon`, `evasion`, `exploit`, `auth`, `post`) in
`HiddenCommandKind` are modelled in `forge-cli/src/cli.rs` but their
*implementation* may still delegate to Python subprocesses or to `rust_core`.

**Mitigation**: Before Phase 5, audit all `HiddenCommandKind` execution paths:
```bash
grep -r "HiddenCommandKind\|hidden_command" native/crates/ --include="*.rs"
# Determine whether each hidden command has a Rust implementation
# or spawns a Python subprocess
```
If any hidden command still spawns Python, implement the Rust equivalent before
allowing Phase 5 to proceed, OR mark the command as `NotYetImplemented` with a
clear error message.

### GAP-2: Playwright-based web crawler (`forge/phase2/crawler.py`)

The OSINT kill-chain uses `playwright` (Python) for SPA rendering, cloud regex
scanning, and HTML mining. The `forge-discovery` crate has the domain models and
discovery pipeline, but Playwright is a Node/Python library with no Rust equivalent
included in the native crates.

**Mitigation options**:
- (A) Keep a minimal Python `playwright-worker` sidecar container in Phase 4 that
  `forge-discovery` calls via an internal REST API.
- (B) Replace with a Rust headless-browser solution (e.g. `chromiumoxide`).
- (C) Scope the gap: accept that Playwright-dependent steps emit a
  `module_not_available` finding when running from the Rust binary until (B) is done.

**Impact**: Kill-chain phases D (rendered HTML mining), E (email chain via Holehe/
Epieos), K/L/M (Sherlock/PhoneInfoga/SearXNG) degrade to passive-only without
Playwright.

### GAP-3: Python OSINT tool venvs (GHunt, theHarvester, Maigret, Sherlock)

These OSINT tools run as Python subprocesses via `FORGE_GHUNT_COMMAND`,
`FORGE_THEHARVESTER_COMMAND`, etc. The `forge-adapters` crate models the connector
catalog but does NOT ship these tool venvs.

**Mitigation**: Continue mounting the Go/Python tool binaries via
`FORGE_HOST_CONNECTOR_BIN_DIR` as external connector binaries. The Rust binary
invokes them the same way Python did (subprocess exec). This is unaffected by
deleting `forge/` since these binaries live outside the Python package tree.

### GAP-4: `llama_cpp` Phase 6 LLM provider

`forge/phase6/report_synthesizer.py` uses `llama-cpp-python` for local GGUF
inference. The `forge-reporting` crate has the report synthesis domain models but
does not bundle an equivalent native LLM inference engine.

**Mitigation**: In Phase 4–5, the Rust report generator defaults to the
`template` provider (deterministic, no LLM). `llama_cpp` inference becomes
`UnavailableInRustBuild` with a clear error message directing operators to the
`auto` provider chain (OpenRouter free tier or Kiro/Claude/Codex CLI detection).
This matches the existing fallback behaviour documented in README.

### GAP-5: `forge-guarded-autostart` Compose service

The `forge-guarded-autostart` Compose service runs
`python -m forge.cli automation cycle --apply --live ...` in a loop with
startup delay, backoff, and memory gates. The Rust equivalent is
`forge automation cycle --apply --live` via the `forge-cli` binary, but the
Compose service definition must be updated before Phase 5.

**Mitigation**: Update `docker-compose.yml` in Phase 5 action 5 to replace the
`python -m forge.cli` command with `forge automation cycle` pointing to the Rust
binary. All environment variables (`FORGE_AUTOSTART_*`) are identical between
Python and Rust since they are consumed by the same config layer (ported to
`forge-domain::config`).

### GAP-6: `pyproject.toml` `[project.scripts]` entry point

The `forge = "forge.cli:main"` entry point is installed by `pip install`. After
Phase 5 this file is deleted. The Rust `forge` binary must be placed on `$PATH`
before the Python entry point is removed.

**Mitigation**: Phase 5 action 2 covers this explicitly. Verify with:
```bash
which forge
forge --version
# Must be Rust binary, not Python wrapper
```

---

## 8. Timeline Estimate

| Phase | Work description | Estimated duration |
|---|---|---|
| **Phase 0** | Baseline verification, tag creation | 1 day |
| **Phase 1** | Rust Dockerfile target, image build, smoke tests | 2–3 days |
| **Phase 2** | Shadow compose overlay, shadow container startup | 1 day |
| **Phase 3** | Parity testing (mandatory 3-day soak + fixes) | 5–10 days |
| **Phase 4** | Port flip, 48-hour monitoring window | 3–4 days |
| **Phase 5** | Python deletion, Dockerfile cleanup, compose update | 2–3 days |
| **Phase 6** | Rust integration tests, doc cleanup, CI update | 5–7 days |
| **Total** | | **~3–4 weeks** |

**Critical path**: Phase 3 parity testing dominates. If any parity failure requires
a Rust bug fix, add 1–3 days per fix-verify cycle. GAP-1 (offensive primitives)
and GAP-2 (Playwright) may each add 1 week if full Rust implementations are chosen
over the mitigation options.

---

## 9. Top-5 Risks and Mitigations

### RISK-1: Postgres schema divergence
**Probability**: Low (migration ledger confirms 100% domain parity).  
**Impact**: Critical — data corruption or query failures in production.  
**Mitigation**:
- Run `cargo test -p forge-storage -- schema_parity` before Phase 3 to confirm
  Rust schema migrations produce identical table structures as Python SQLAlchemy.
- Keep the Postgres backup from Phase 4 pre-cutover for 30 days.
- In Phase 4, monitor Postgres `pg_stat_activity` for query errors:
  ```sql
  SELECT query, state, wait_event_type FROM pg_stat_activity
  WHERE datname = 'forge' AND state = 'active';
  ```

### RISK-2: JWT token format incompatibility
**Probability**: Low-medium (JWT claims shape confirmed in `api.rs` `JwtClaims`).  
**Impact**: High — existing operator sessions invalidated mid-shift, API 401 storms.  
**Mitigation**:
- In Phase 3, test that a JWT minted by Python `/api/token` is accepted by the
  Rust `/api/engagements` endpoint and vice-versa.
- If claim shapes differ: add a Rust JWT compatibility shim that accepts both
  `engagement_ids` (Rust) and `engagements` (potential Python key name) during
  Phase 4's 48-hour window, then harden after.

### RISK-3: Rust binary panics under load
**Probability**: Low (16 xtask canaries pass, domain tests have 1,400+ cases).  
**Impact**: Critical — unexpected panic crashes the container.  
**Mitigation**:
- Build with `RUSTFLAGS="-C panic=abort"` for release so panics kill the process
  cleanly (no partial state), allowing Docker to restart it.
- Set `restart: unless-stopped` on all Rust containers (already in shadow compose).
- Monitor for `SIGABRT` / container restarts with:
  ```bash
  docker events --filter "container=forge-api-rust-1" --filter "event=die" &
  ```
- Add structured panic logging to a persistent log before Phase 4.

### RISK-4: Missing Playwright / LLM inference breaks kill-chain silently
**Probability**: High (GAP-2 and GAP-4 are known gaps).  
**Impact**: Medium — Phase D and Phase 6 of kill-chain degrade silently.  
**Mitigation**:
- Implement explicit `NotImplemented` error responses (not silent skip) for
  Playwright-dependent steps in the Rust binary before Phase 4.
- `forge doctor` on the Rust stack must report `playwright: not available` as a
  warning, not a pass, so operators know they are on a degraded path.
- Phase 4 acceptance criteria: run one full `forge kill-chain ... --dry-run` end
  to end and confirm all gaps produce warnings, not crashes.

### RISK-5: Operator tooling scripts hardcode Python paths
**Probability**: Medium (scripts reference `python -m forge.cli` or `.venv`).  
**Impact**: Medium — operator automation breaks silently after Phase 5.  
**Mitigation**:
- Before Phase 5, audit all `.ps1`, `.sh`, `.bat`, and CI YAML files for
  Python path references:
  ```bash
  grep -r "python -m forge\|\.venv\|forge\.cli\|uvicorn" \
    scripts/ .github/ tools/ --include="*.ps1" --include="*.sh" \
    --include="*.bat" --include="*.yml" --include="*.yaml"
  ```
- Replace each occurrence with `forge <command>` (Rust binary).
- Keep the `forge-autopilot.bat` and `setup.bat` wrappers functional by pointing
  them to the Rust `forge` binary instead of Python.

---

## 10. File-Level Deletion Checklist

This checklist maps each Python file/directory to the phase at which it is deleted
and provides the exact command to prove it is no longer in use before deletion.

### Phase 5 Deletions (Python runtime)

#### `forge/` (149 MB, 554 .py files) — deleted in Phase 5, step 3

| Path | Rust equivalent | Proof-of-non-use command |
|---|---|---|
| `forge/api/` (FastAPI application) | `forge-server` crate | `docker exec forge-api-rust-1 python -c "import forge.api.app" 2>&1 \| grep -c ModuleNotFound` → `1` |
| `forge/webui/` (HTMX + React API) | `forge-ui` crate | `docker exec forge-api-rust-1 python -c "import forge.webui.app" 2>&1 \| grep -c ModuleNotFound` → `1` |
| `forge/cli.py` / `forge/cli_registry.py` | `forge-cli` crate | `forge --version` → Rust version string (not Python traceback) |
| `forge/core/runner.py` (worker) | `forge-operations` crate | `docker ps --format '{{.Names}}' \| grep forge-worker` → only `forge-worker-rust` |
| `forge/models/pydantic_models.py` | `forge-domain` crate | `cargo test -p forge-domain -- parity` → all pass (118 entries) |
| `forge/db/direct_connect.py` | `forge-storage` crate | `grep -r "direct_connect" native/crates/ --include="*.rs"` → storage layer |
| `forge/phase0/` through `forge/phase6/` | `forge-discovery`, `forge-reporting` | `cargo test -p forge-reporting -- phase6` → passing |
| `forge/opsec/scope_gate.py` | `forge-policy` crate | `cargo test -p forge-policy -- scope_gate` → passing |
| `forge/crypto/` | `forge-crypto` crate | `cargo test -p forge-crypto` → passing |
| `forge/webui/rbac.py` | `forge-server::api` (`AuthRole`) | `cargo test -p forge-server -- auth_role` → passing |
| `forge/webui/auth.py` | `forge-server::api` (`JwtClaims`) | `cargo test -p forge-server -- jwt_expired` → passing |

**Bulk proof command** (run before `git rm forge/`):
```bash
# Confirm no running container has forge/ mounted or running Python forge modules
docker inspect $(docker ps -q) --format '{{.Name}}: {{range .Mounts}}{{.Source}}→{{.Destination}} {{end}}' \
  | grep "forge/" | grep -v "forge-data\|forge-plugins\|forge-remote-audit\|forge-models"
# Expected: zero results (no container mounts the forge/ Python source tree)

# Confirm forge-api-rust cannot import Python forge
docker exec forge-api-rust-1 sh -c \
  'python3 -c "import forge.api.app" 2>&1 || echo "CONFIRMED: Python forge not importable"'
# Expected: "CONFIRMED: Python forge not importable" (either no python3 or no module)
```

---

#### `tests/` (572 Python tests) — deleted in Phase 5, step 3

| Path | Rust equivalent | Proof-of-non-use command |
|---|---|---|
| `tests/test_domain_*.py` | `cargo test -p forge-domain` | `cargo test -p forge-domain --release 2>&1 \| tail -1` → `test result: ok` |
| `tests/test_api_*.py` | `cargo test -p forge-server` | `cargo test -p forge-server --release 2>&1 \| tail -1` → `test result: ok` |
| `tests/test_cli_*.py` | `cargo test -p forge-cli` | `cargo test -p forge-cli --release 2>&1 \| tail -1` → `test result: ok` |
| `tests/test_phase*.py` | `cargo test -p forge-discovery` | `cargo test -p forge-discovery --release 2>&1 \| tail -1` → `test result: ok` |
| `tests/test_webui_*.py` | `cargo test -p forge-ui` | `cargo test -p forge-ui --release 2>&1 \| tail -1` → `test result: ok` |

**Bulk proof command**:
```bash
# All Rust tests pass before Python tests are deleted
cargo test --release --workspace 2>&1 | tail -5
# Expected: "test result: ok. N passed; 0 failed"
```

---

#### `pyproject.toml` — deleted in Phase 5, step 3

Entries that must survive (as Rust equivalents) before deletion:

| `pyproject.toml` section | Status | Rust equivalent |
|---|---|---|
| `[project.scripts] forge = "forge.cli:main"` | **Must replace first** | `forge` binary from `forge-cli` on `$PATH` |
| `[project.dependencies]` (fastapi, uvicorn, pydantic, etc.) | Can delete once Rust primary | No Python runtime needed |
| `[project.optional-dependencies] offensive` | Can delete | `rust_core` FFI boundary handles Win32 |
| `[tool.pytest.ini_options]` | Can delete | `cargo test` configuration in `Cargo.toml` |
| `[tool.ruff]` / `[tool.mypy]` / `[tool.bandit]` | Can delete | `cargo clippy`, `cargo fmt` |

**Proof-of-non-use command**:
```bash
# The forge binary must not be the Python wrapper
forge --version | grep -v "python\|Python\|pip"
# Expected: Rust semver string like "forge 7.2.0-rust (...)"

# pip must have no forge-toolkit installed (or pip not present)
pip show forge-toolkit 2>&1 | grep -c "not found" || echo "pip not present"
# Expected: "1" or "pip not present"
```

---

#### `pyproject.toml` entry points to preserve/replace

The following entry points declared in `pyproject.toml` line 120 must be
explicitly replaced or confirmed before Phase 5:

```toml
[project.scripts]
forge = "forge.cli:main"     # → Rust: forge-cli binary installed as /usr/local/bin/forge
```

Operator scripts that invoke `forge <subcommand>` will work unchanged after Phase 5
because the Rust `forge` binary accepts identical command names (confirmed by
`CommandKind::from_str` in `native/crates/forge-cli/src/cli.rs` — all 25 public
commands and 9 hidden commands match the Python `cli_registry.py` surface).

---

### Phase 6 Deletions (migration artifacts + CI)

| Path | Phase | Proof-of-non-use command |
|---|---|---|
| `native/migration/domain-contracts.json` | 6 | `cargo xtask verify` still passes without it |
| `native/migration/` (full directory) | 6 | `ls native/migration/` → No such file or directory |
| `.github/workflows/python-ci.yml` (if exists) | 6 | `grep -r "pip install\|pytest" .github/ --include="*.yml"` → zero |
| `docs/history/*.md` (Python-era docs) | 6 | Moved to `docs/history/python-era/` not deleted |
| `docker/compose.dev.yaml` (Python dev stack) | 6 | `docker compose -f compose.dev.yaml ps` → "no such file" |
| `compose.watch.yaml` (SMB dev overlay) | 6 | Same |
| `tools/evidence_chaos.py` (Python chaos harness) | 6 | Replaced by `cargo test -p forge-operations -- chaos` |
| `tools/parity_check.sh` (Phase 3 tool) | 6 | No longer needed after Phase 5 |
| `bootstrap.py` | 5 | Rust `forge doctor --fix-safe` replaces bootstrap |
| `setup.bat` / `setup.sh` | 5 | Update to invoke `cargo install` path |

---

### Summary: Deletion Sequence

```
Phase 5 (Day ~14–17 from cutover start):
  git rm -r forge/          # 149 MB, 554 .py files
  git rm -r tests/          # 572 Python test files
  git rm pyproject.toml     # Python package manifest
  git rm bootstrap.py
  # setup.bat/setup.sh updated in-place, not deleted

Phase 6 (Day ~19–24 from cutover start):
  git rm -r native/migration/
  git rm docker/compose.dev.yaml compose.watch.yaml
  git rm tools/evidence_chaos.py tools/parity_check.sh
  # .github/workflows Python jobs deleted/disabled
```

After Phase 6 `git rm -r forge/` is **irreversible in the working tree** but
always recoverable from git history via:
```bash
git show python-primary-baseline:forge/cli.py  # or any other path
git checkout pre-python-delete-YYYYMMDD -- forge/
```

The `python-primary-baseline` tag created in Phase 0 provides a permanent,
named recovery point for the entire Python codebase.

---

*End of FORGE Python → Rust Production Cutover Plan*

---

## Referenced Files

| File | Purpose in this document |
|---|---|
| `docker/docker-compose.yml` | Current Python service definitions, port mapping |
| `native/migration/domain-contracts.json` | Migration ledger (118/118 implemented) |
| `pyproject.toml` | Python entry points, dependency list |
| `native/crates/forge-server/src/api.rs` | Rust JWT/RBAC/WebSocket surface |
| `native/crates/forge-server/src/platform.rs` | Rust health/readiness/worker endpoints |
| `native/crates/forge-cli/src/cli.rs` | Rust CLI command routing (25 public + 9 hidden) |
| `native/crates/forge-ui/src/ui.rs` | Rust UI route model (6 routes, 8 detail tabs) |
| `README.md` | Python workflow documentation to be updated in Phase 6 |
