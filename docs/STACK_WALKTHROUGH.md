# FORGE Stack Walkthrough (start-to-finish)

> Snapshot: `4a99a43`. Reflects the current dev-first, minimal-footprint stack.
> For the Rust cutover status, see [`RUST_CUTOVER_REMAINING.md`](RUST_CUTOVER_REMAINING.md).
> For OS-specific bootstrap, see [`CROSS_OS_SETUP.md`](CROSS_OS_SETUP.md).

## 1. Repository shape

```
forge/                          root
├── forge/                      Python runtime (554 .py, 45 subsystems)
│   ├── api/                    REST + WebSocket API (FastAPI/uvicorn)
│   ├── webui/                  HTMX + React SPA + JWT + /ws/progress
│   ├── auth/                   JWT, RBAC (forge.webui.rbac)
│   ├── phase0..phase6/         ASM pipeline stages
│   ├── connectors/             OSINT + validation + CTI adapters
│   ├── graph/                  Attack-path graph + exports
│   ├── monitoring/             Scheduled snapshots + alerts
│   ├── remediation/            Ticket sync + workflow
│   ├── active_validation/      Non-destructive validation
│   ├── audit/                  Hash-chained audit log + bundles
│   ├── standards/              STIX/TAXII, CVSS/CWE/CPE/EPSS/KEV/ATT&CK
│   └── ...
├── native/                     Rust workspace (13 crates, 779 tests)
│   ├── crates/
│   │   ├── forge-domain/       Core types, enums, ID canonicalization
│   │   ├── forge-server/       axum HTTP shadow (:9000/:9080)
│   │   ├── forge-cli/          CLI skeleton
│   │   └── ...
│   ├── xtask/                  Canary runner
│   └── migration/              Domain contract ledger
├── docker/
│   ├── docker-compose.dev.yml  Dev stack (5 services + 2 opt-in Rust)
│   ├── docker-compose.prod.yml Prod stack
│   ├── Dockerfile              Multi-stage: runtime, ci, rust-runtime
│   └── README.md               Compose usage guide
├── scripts/
│   ├── setup.ps1 / setup.sh    Idempotent cross-OS bootstrap
│   ├── parity_check.ps1 / .sh  Python vs Rust shadow JSON parity
│   ├── refresh-backup.ps1 / .sh  Timestamped off-repo snapshots
│   └── ...
├── dev.ps1 / dev.sh            Compose launcher wrappers
├── .env.dev                    Dev secrets (gitignored)
├── .agents/
│   ├── STATE.md                Cross-harness current task
│   ├── JOURNAL.md              Append-only decision log
│   └── handoffs/               Detailed handoff docs
├── SPEC.md, END_GOAL.md        Root implementer contract
└── AGENTS.md                   Multi-agent operating rules
```

## 2. The dev stack (default)

`docker compose --env-file .env.dev -f docker/docker-compose.dev.yml up -d`

Starts 5 services in one `forge-dev` project:

| Service | Port | Purpose | Resource cap |
|---|---|---|---|
| postgres | internal | State + audit DB (postgres:16-alpine) | 256 MB / 0.25 CPU |
| redis | internal | Workflow bus (redis:7-alpine) | 128 MB / 0.15 CPU |
| forge-api | 127.0.0.1:8000 | REST + WebSocket API (uvicorn) | 512 MB / 0.50 CPU |
| forge-webui | 127.0.0.1:8080 | HTMX + React web UI (uvicorn) | 384 MB / 0.35 CPU |
| forge-worker | (none) | Background task runner | 384 MB / 0.35 CPU |

Total footprint: **~1.66 GB memory, ~1.60 CPU**. All containers run as non-root
(`10001:10001`), read-only rootfs, no privileges, `cap_drop: ALL`, tmpfs `/tmp`,
loopback-only host binds.

Health probes:
- `curl http://127.0.0.1:8000/health` → `{"status":"ok","bus_connected":true,"version":"7.2.0-platform"}`
- `curl http://127.0.0.1:8080/health` → `{"status":"ok","version":"7.2.0"}`

## 3. The Rust shadow (opt-in)

`docker compose --env-file .env.dev -f docker/docker-compose.dev.yml --profile rust-shadow up -d`

Adds 2 axum HTTP shadow containers (requires `forge-toolkit-rust:local` image
built first via `docker build -f docker/Dockerfile --target rust-runtime -t forge-toolkit-rust:local .`):

| Service | Port | Binary | Resource cap |
|---|---|---|---|
| forge-rust-api | 127.0.0.1:9000 | `/usr/local/bin/forge-server` (FORGE_API_PORT=9000) | 256 MB / 0.30 CPU |
| forge-rust-webui | 127.0.0.1:9080 | Same binary, FORGE_WEB_PORT=9080 | 256 MB / 0.30 CPU |

Only `/health` is currently proven; parity soak lives in
`scripts/parity_check.ps1|.sh`. See `RUST_CUTOVER_REMAINING.md` for what is NOT
yet implemented.

## 4. First-run flow (any OS)

```
git clone <repo> forge
cd forge
sh scripts/setup.sh --up          # Linux / macOS
pwsh -File scripts/setup.ps1 -Up  # Windows
```

`setup.{ps1,sh}` is idempotent — it:

1. Verifies Docker daemon reachable
2. Creates `.env.dev` with cryptographically strong secrets if missing (or
   regenerates on `--force`/`-Force`)
3. Ensures `reports/`, `imports/`, `.forge_data/` bind-mount directories exist
4. Validates `docker compose` config
5. With `--up`/`-Up`, brings the stack up

Then daily:

```
sh dev.sh          # or: pwsh -File dev.ps1     — up -d
sh dev.sh ps       # service status
sh dev.sh logs     # tail all logs
sh dev.sh down     # stop, keep volumes
```

For the Rust shadow: `sh dev.sh rust-shadow` (requires image built first).

## 5. Runtime lifecycle inside the containers

1. `forge-api` boots: reads env, connects to postgres + redis, mounts audit
   log at `/data/audit/audit.jsonl`, starts uvicorn on 0.0.0.0:8000
2. `forge-webui` boots: same env, serves HTMX templates from
   `forge/webui/templates/`, proxies React SPA under `/`, exposes
   `/ws/progress` WebSocket subprotocol `forge-progress`
3. `forge-worker` boots: `python -m forge.core.runner`, subscribes to Redis
   bus channels, executes background workflows

Volumes mounted:
- `forge-dev-postgres-data` → `/var/lib/postgresql/data`
- `forge-dev-data` → `/data` (audit log, engagement DBs, control.db)
- `forge-dev-plugins` → `/plugins` (read-only)
- `forge-dev-models` → `/home/forge/.cache/forge/models` (read-only)
- Host `reports/` → `/app/reports` (read-write, for artifact inspection)
- Host `imports/` → `/app/imports` (read-write, for feed drops)
- Host `.forge_data/` → `/app/.forge_data` (read-write)

## 6. The `forge` CLI (still Python)

Entry point: `python -m forge.cli` or the installed `forge` console script.

Top-level verbs (public):
- `forge kill-chain <seed> --engagement N` — the deterministic ASM pipeline
- `forge menu` — TUI engagement browser
- `forge kb {sync,status,fetch-breach}` — knowledge-base ETL
- `forge report {generate,quality-audit,stale-plan,stale-run,long-run-plan,policy-plan}`
- `forge graph {build,sync-assets,ownership,attribution,cypher-export,tier-zero}`
- `forge automation {cycle,status,policy,feed-build,defaults,limits,self-heal-plan,guarded-autostart}`
- `forge monitoring {status,due-plan,exposure-metrics,run-due,deliver-alerts,worker}`
- `forge remediation {review-queue,propagate-owners,draft-from-asset-graph,request-retest,sync-tickets}`
- `forge active-validation {preview,create,approve,run,list,methods,coverage}`
- `forge connectors {list,install-plan,run-plan,run,import-*,run-identity,run-secrets,import-secrets,secret-*,policy-summary,plugin-validate}`
- `forge workspaces {list,upsert,members,member-set,member-delete,audit,backfill-memberships}`
- `forge standards {import-stix,export-stix}`
- `forge audit {manifest-verify,manifest-export,manifest-bundle-verify}`
- `forge retention {preview,apply}`
- `forge doctor` — operator readiness probe
- `forge demo proof-pack` — reproducible demo engagement
- `forge dashboard` — static local operator dashboard

Advanced sub-apps hidden from top-level help but reachable via kill-chain:
`recon`, `osint`, `evasion`, `exploit`, `vuln`, `cloud`, `web`, `auth`, `post`.

## 7. The one command you need

```
forge kill-chain <seed> --engagement <N>
```

`<seed>` is auto-classified into one of 10 types: domain, IPv4, URL, email,
phone (E.164), username (`@handle`), company, full name, cloud ref
(`cloud_ref:aws_s3:...`), artifact URL. The pipeline then loops phases A–M with
early-stable-snapshot termination, HIBP domain check, optional read-only
proof-bound validation (attack-mode + ROE + scope manifest), vuln passive,
exploit-reference correlation, graph build, report generate.

Every operation is scope-gated (`assert_in_scope`) and hash-chain audit-logged
(`audit_log` rows).

## 8. Testing

- Python: `pytest tests/` (2,100+ passing at baseline)
- Rust: `cd native && cargo test --workspace --locked --offline` (779 tests)
- Chaos: `python tools/evidence_chaos.py` (needs redis-server)
- Frontend: `cd forge/reporting/webui && npm test` (44 Vitest tests)
- Canaries: `pwsh -File scripts/run-canaries.ps1`

## 9. Documentation index

Read in this order when picking up work:

1. [`.agents/STATE.md`](../.agents/STATE.md) — current task, blockers
2. [`.agents/JOURNAL.md`](../.agents/JOURNAL.md) — decisions and rationale
3. [`END_GOAL.md`](../END_GOAL.md) — locked project goal
4. [`SPEC.md`](../SPEC.md) — implementer contract
5. [`README.md`](../README.md) — main user reference
6. [`docker/README.md`](../docker/README.md) — compose stack guide
7. [`docs/CROSS_OS_SETUP.md`](CROSS_OS_SETUP.md) — OS-specific bootstrap
8. [`docs/RUST_CUTOVER_REMAINING.md`](RUST_CUTOVER_REMAINING.md) — Rust gap analysis
9. [`docs/competitive_upgrade_consolidated_backlog.md`](competitive_upgrade_consolidated_backlog.md)
10. [`docs/cutover-status-consolidated.md`](cutover-status-consolidated.md)
11. [`DAILY_USE.md`](../DAILY_USE.md) — operator cheatsheet

## 10. What NOT to do

- Never publish `.env.dev` or `.env.prod`
- Never expose `postgres` or `redis` to the host network
- Never disable Windows Defender to work around a legacy Impacket-adjacent
  detection (see `AGENTS.md`)
- Never write new Python migration helpers — new migration work must be Rust,
  administration is PowerShell
- Never delete failing tests to make the build pass
- Never subprocess into another agent using a different model/provider than the
  parent session

## 11. Design principles (locked)

1. **Nothing operates outside scope.** `assert_in_scope` gates every network
   module
2. **Every action leaves a receipt.** `audit_log` rows are hash-chained
3. **Auto-discover, don't hardcode.** OSINT modules auto-find their target
   credentials
4. **Standalone by default.** No cloud dependency; template fallback works with
   zero LLMs
5. **Chaos-tested durability.** Workflow engine survives Redis crash, SQLite
   lock contention, plugin SIGKILL, disk-full — proven weekly in CI
