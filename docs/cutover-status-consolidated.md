# FORGE Cutover Status — Consolidated (2026-09-29)

## Executive Summary

As of 2026-09-29, all infrastructure groundwork for the Rust cutover is complete and committed to
`main`. Phases 0–3 are fully delivered: the Rust image builds cleanly, both shadow HTTP servers
run as real axum services on :9000/:9080, and the Phase 3 parity test harness is in place. Phase 4
code preparation (provider key validators, artifact parsers, identity normalisation) is also
committed to the codebase. Per the user's explicit pivot — "don't want the full system running yet,
scaling back to dev work, all docker need to be minimal footprint (even when real prod)" — the Rust
shadow services (`forge-rust-api`, `forge-rust-webui`) are now **behind `--profile rust-shadow`**
in both the dev and prod Compose stacks. A plain `docker compose up -d` starts only the 5-service
Python stack (postgres + redis + forge-api + forge-webui + forge-worker, ~1.66 GB). Phases 4-flip,
5, and 6 are blocked on operator wall-clock work (image rebuild, traffic migration, Python
decommission) and will resume when the user is ready.

---

## Current Stack Configuration

| Startup mode | Services | Memory footprint | How to invoke |
|---|---|---|---|
| **Default** | postgres, redis, forge-api, forge-webui, forge-worker | ~1.66 GB | `docker compose up -d` |
| **+rust-shadow** | + forge-rust-api (:9000), forge-rust-webui (:9080) | ~2.17 GB | `docker compose --profile rust-shadow up -d` |
| **+autostart** (prod only) | + forge-guarded-autostart (removed 2026-09-28) | n/a | removed |

### Dev stack (`forge-dev`)

```powershell
# Default — 5 Python services
docker compose --env-file .env.dev -f docker/docker-compose.dev.yml up -d

# All 7 services — Rust shadow opt-in (requires forge-toolkit-rust:local image)
docker compose --env-file .env.dev -f docker/docker-compose.dev.yml --profile rust-shadow up -d
```

### Prod stack (`forge-prod`)

```powershell
# Default — 5 Python services
docker compose --env-file .env.prod -f docker/docker-compose.prod.yml up -d

# All 7 services — Rust shadow opt-in (requires forge-toolkit-rust:local image)
docker compose --env-file .env.prod -f docker/docker-compose.prod.yml --profile rust-shadow up -d
```

---

## What's on Disk but Not Running

The following are committed to the codebase and ready for use, but are **not active** in the
default Docker stack:

| Artifact | Location | Status |
|---|---|---|
| Phase 4 artifact parsers | `forge/phase4/artifact_parsers.py` | Committed, not in running containers |
| Phase 4 provider key validators | `forge/phase4/provider_key_validators.py` | Committed, not in running containers |
| Phase 4 identity normalisation | `forge/utils/intel/identity_normalization.py` | Committed, not in running containers |
| Rust shadow API service | `forge-rust-api` in Compose | Image `forge-toolkit-rust:local` needs rebuild |
| Rust shadow web UI service | `forge-rust-webui` in Compose | Image `forge-toolkit-rust:local` needs rebuild |
| Phase 3 parity harness | `tests/rust_parity/` | Ready, runs against both stacks when Rust is up |

The `forge-toolkit-rust:local` Docker image must be explicitly rebuilt before the shadow services
can start. This is a separate operator step and is **not** part of the default dev startup.

---

## Full Cutover Phase State

| Phase | Name | Status | Notes |
|---|---|---|---|
| **Phase 0** | Knowledge-base and baseline freeze | **DONE** | Committed `main` |
| **Phase 1** | Rust image builds clean | **DONE** | `forge-toolkit-rust:local` builds from `docker/Dockerfile.rust` |
| **Phase 2** | Shadow endpoints wired | **DONE (opt-in)** | `--profile rust-shadow` required; OFF by default per user pivot |
| **Phase 3** | Parity test harness | **DONE** | `tests/rust_parity/` ready; runs when shadow services are up |
| **Phase 4** | Code prep committed | **DONE (code only)** | Parsers, validators, normalisation in codebase; not in running containers |
| **Phase 4-flip** | Route traffic to Rust | **BLOCKED** | Operator wall-clock: rebuild image, bring up shadow, verify parity, flip load balancer |
| **Phase 5** | Python shadow/canary period | **BLOCKED** | Requires Phase 4-flip complete |
| **Phase 6** | Python decommission | **BLOCKED** | Requires Phase 5 stability window |

### Why Phase 2 is "opt-in" now

The original plan had shadow services start automatically. The user pivot explicitly requested that
no full-system running occur during active development. The shadow services have been placed behind
`--profile rust-shadow` so that a fresh `docker compose up -d` starts only the 5-service Python
stack. The shadow code, configs, and test harness remain intact and will not be lost.

---

## How to Bring Shadow Services Back

When you're ready to resume Phase 3/4 parity work:

### Step 1 — Rebuild the Rust image

```powershell
# From repo root
docker build -f docker/Dockerfile.rust -t forge-toolkit-rust:local .
```

Or if a multi-stage build is wired:

```powershell
docker compose --env-file .env.dev -f docker/docker-compose.dev.yml --profile rust-shadow build forge-rust-api
```

### Step 2 — Start the full 7-service stack

```powershell
docker compose --env-file .env.dev -f docker/docker-compose.dev.yml --profile rust-shadow up -d
```

### Step 3 — Verify all 7 services are healthy

```powershell
docker compose --env-file .env.dev -f docker/docker-compose.dev.yml --profile rust-shadow ps
```

### Step 4 — Run parity tests

```powershell
python -m pytest tests/rust_parity/ -v
```

---

## How to Fully Retire the Cutover Work (If Needed)

The cutover can be fully dormant with no operator action beyond the default startup:

1. **Do nothing** — the default `docker compose up -d` already starts only the Python stack.
2. The Rust code in `native/` and `forge/phase4/` is committed but does not run unless you rebuild
   the image and pass `--profile rust-shadow`.
3. Parity test files in `tests/rust_parity/` are committed but do not run in the default test
   suite unless explicitly targeted.

To remove shadow service configuration entirely (not recommended — it's low-cost dormant):

```powershell
# Preview what would be different with Rust shadow removed:
docker compose --env-file .env.dev -f docker/docker-compose.dev.yml config --services
# Output: 5 services (already the case without --profile rust-shadow)
```

---

## Resource Budget Reference

| Mode | Services | RAM | CPU cores |
|---|---|---|---|
| Default (Python only) | 5 | ~1.66 GB | ~1.60 |
| +`--profile rust-shadow` | 7 | ~2.17 GB | ~2.20 |

All prod caps are env-var overridable. See `docker/README.md` for per-service override variables.

---

## Files Modified by This Reorganisation (2026-09-29)

| File | Change |
|---|---|
| `docker/docker-compose.dev.yml` | Added `profiles: [rust-shadow]` to `forge-rust-api` and `forge-rust-webui`; updated header comment |
| `docker/docker-compose.prod.yml` | Added `profiles: [rust-shadow]` to both Rust services; fixed `restart: unless-stopped` → `on-failure:3` on both Rust services; updated header comment |
| `docker/README.md` | Updated "Two stacks" table; split resource budget into default vs opt-in; added "Rust shadow endpoints (opt-in)" section; updated cheatsheet; updated "What's different" table |
| `docs/cutover-status-consolidated.md` | This file — new consolidated cutover status document |

---

*Generated by OpenCode on 2026-09-29. Parent commit: `815916b` on `main`.*
