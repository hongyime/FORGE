# Rust Cutover — Remaining Work (honest gap analysis)

> Baseline commit: `4a99a43` (main). Rust shadows opt-in behind `--profile rust-shadow`.
> Python remains the operational default. Do not treat this document as a promise
> of scope — it's a truthful map of what exists, what doesn't, and what would be
> required to retire Python.

## TL;DR

**Full cutover to Rust is not possible today.** The Rust workspace covers domain
contracts (~13 crates, 779 tests green) and a skeleton HTTP shadow. The user-facing
runtime — kill-chain, connectors, monitoring, remediation, active-validation, WebUI,
WebSocket progress, dashboard renderer, workflow engine — remains Python.

Rough completion by surface area: **~10–15%**. Domain crates are real. Everything
above them (behavior, wire protocols, CLI verbs, HTMX/React UI) is not.

## What IS in Rust (`native/`)

| Crate | Purpose | Status |
|---|---|---|
| `forge-domain` | Core types, enums, ID canonicalization | Contracts + property tests |
| `forge-policy` | Policy invariants | Types + tests |
| `forge-crypto` | Hash chain / signing primitives | Types + tests |
| `forge-adapters` | Adapter contracts | Types |
| `forge-storage` | Storage traits | Types + tests |
| `forge-runtime` | Runtime traits | Types + tests |
| `forge-discovery` | Discovery contracts | Types + tests |
| `forge-reporting` | Report contracts | Types + tests |
| `forge-operations` | Ops contracts | Types + tests |
| `forge-cli` | CLI skeleton | ~10k of scaffolding — no real verbs wired |
| `forge-server` | axum HTTP shadow (:9000/:9080) | health/echo only, JWT middleware stub, Redis dial |
| `forge-ui` | UI route enums | Types |
| `forge-release` | Packaging/deploy state machines | Types |
| `xtask` | Local canary runner | 63 canaries green |

Total: 779 workspace tests pass. `unsafe_code = "forbid"` workspace-wide except one
reviewed native Win32 FFI boundary (job-object process containment, Windows-only).

## What is NOT in Rust (still Python)

`forge/` contains **554 .py files across 45 subsystems**. The subsystems that would
need Rust replacements for a real cutover:

### Runtime / API (highest priority for cutover parity)
- `forge/api/` — REST API (dozens of routes: engagements, findings, workspaces,
  audit reviews, retention, remediation, active-validation, connectors, monitoring)
- `forge/webui/` — HTMX server-rendered tabs + React SPA proxy + JWT auth +
  `/ws/progress` WebSocket
- `forge/auth/` — JWT issuance, RBAC (`forge.webui.rbac`), workspace isolation
- `forge/db/` — `direct_connect.py` SQLite helper, migrations, control DB
- `forge/distributed/` — Redis workflow bus
- `forge/bus/`, `forge/orchestration/` — task fan-out

### The one command you need
- `forge kill-chain <seed>` — the entire deterministic ASM pipeline. Auto-type
  detection, 13-step iteration loop, phase A–M enrichment, HIBP, cloud auto-scan,
  graph build, report generate, prereq detection

### Phases 0–6 (the ASM pipeline itself)
- `forge/phase0/` — Knowledge-base ETL
- `forge/phase1/` — Orchestrator partitions
- `forge/phase2/` — Discovery
- `forge/phase3/` — Enrichment
- `forge/phase4/` — Artifact parsing + provider key validators
- `forge/phase5/` — Clipboard/identity
- `forge/phase6/` — Report generation (auto/template/llama_cpp cascade)

### OSINT / connectors
- `forge/connectors/` — ProjectDiscovery (subfinder/httpx/katana/nuclei),
  Gitleaks, TruffleHog, HIBP, Shodan, Censys, urlscan, ThreatFox, URLhaus,
  Supabase, STIX/TAXII imports
- `forge/collection/` — Collection profiles
- `forge/tools/` — OSINT tool subprocess wrappers (theHarvester, Sherlock, etc.)

### Data plane
- `forge/graph/` — Attack path graph, Maltego export, ownership, tier-zero
- `forge/monitoring/` — Scheduled snapshots, alerts, exposure metrics
- `forge/remediation/` — Ticket sync (Jira/ServiceNow/GitHub/Tines/Splunk/Torq)
- `forge/active_validation/` — Non-destructive validation runs, retest, coverage
- `forge/retention/` — Retention policies, legal holds
- `forge/audit/` — Hash-chained audit log + append-only bundle store
- `forge/standards/` — STIX 2.1 import/export, CVSS/CWE/CPE/EPSS/KEV/ATT&CK
- `forge/hardening/` — Doctor, deployment checks
- `forge/reporting/` — Report metadata, static dashboard renderer

### Interfaces
- `forge/cli_commands/` — every non-kill-chain CLI verb (`forge doctor`,
  `forge automation`, `forge monitoring`, `forge remediation`, `forge graph`,
  `forge connectors`, `forge workspaces`, `forge retention`, `forge demo`, etc.)
- `forge/tui/` — Interactive TUI engagement browser
- `forge/reporting/webui/` — React frontend (TypeScript + Vite)

## Minimum realistic path to Rust cutover

Each is a T3–T36-scale wave (weeks to months of directed work). None are optional
for actually retiring Python.

1. **W7 — API parity**: port `/api/*` route surface from FastAPI to axum, JWT
   middleware, RBAC evaluator, workspace isolation, WebSocket `/ws/progress`
2. **W8 — Storage parity**: port SQLite migrations + Postgres async pool to sqlx,
   audit hash-chain triggers, control DB
3. **W9 — Kill-chain core**: seed classifier, 13-step iteration loop, phase A–M
   dispatch, scope gate enforcement, resume, watchdog
4. **W10 — Phase enrichers**: phase0–phase6 as Rust modules or subprocess
   adapters with parity fixtures for each
5. **W11 — Connector runners**: 20+ connectors, secret-store integration,
   catalog manifests, plugin validator
6. **W12 — Graph + monitoring + remediation + active-validation**: 4 subsystems,
   each with CLI verbs, API routes, dashboard surface, ticket-event ledger
7. **W13 — WebUI**: HTMX server-side templates in axum (`askama` or `maud`) +
   embed React static bundle
8. **W14 — TUI**: reimplement the interactive browser (`ratatui`)
9. **W15 — Report generation**: Phase 6 auto/template/llama_cpp cascade in Rust
   (deterministic template path first; keyed backends optional)
10. **W16 — Doctor + deployment hardening**: readiness probes, RBAC audit,
    dev/prod profile checks, connector secret decryptability
11. **W17 — Migration + rollback**: dual-write bridge (Python + Rust both
    consuming/writing the same Postgres schema), parity soak, cutover switch,
    rollback tag
12. **W18 — Docs, packaging, release QA**: Helm chart parity, systemd unit,
    binary release, offensive tool prereqs, cross-platform bootstrap

## Blockers not addressable by code

- **LSP**: `rust-analyzer` not installed on the current toolchain; adds friction
  but not a hard blocker
- **Windows build hygiene**: Defender flags Impacket-adjacent helpers; per
  AGENTS.md, new migration helpers must be Rust
- **Same-model subagent policy**: cross-model delegation forbidden; slows
  parallel Rust waves that would otherwise use category subagents
- **Docker Desktop / WSL flakiness**: the entire cutover verification chain
  depends on `docker compose` being reachable

## What the Rust shadow does today (`--profile rust-shadow`)

Running `docker compose --env-file .env.dev -f docker/docker-compose.dev.yml --profile rust-shadow up -d`
adds two containers:

- `forge-dev-forge-rust-api-1`   — axum HTTP on :9000, `/health` responds
- `forge-dev-forge-rust-webui-1` — same binary on :9080, `/health` responds

`scripts/parity_check.ps1` (or `parity_check.sh`) compares JSON key sets of
Python `/health` vs Rust `/health`. That's the extent of the traffic parity
surface currently proven. It is a scaffold, not a shadow of real behavior.

## Rollback anchors (still active)

- `git tag python-primary-baseline` on origin — checkout to fully revert
- `.agents/baseline-postgres-schema.sql` — Postgres schema baseline
- Off-repo backup at `X:\01 REPOSITORIES\forge-backup-20260928-201422\`
- Refresh script `pwsh scripts/refresh-backup.ps1` (Windows) or
  `sh scripts/refresh-backup.sh` (Linux/macOS)

## Decision framework

Before starting any Rust cutover wave, answer:

1. **Will this replace Python behavior, or shadow it?** Shadowing without
   retirement is technical debt.
2. **Is there a parity soak that proves equivalence?** If not, you can't cut
   over — you can only add.
3. **What's the rollback story if the Rust wave regresses?** The
   `python-primary-baseline` tag covers a whole-tree revert, but the operator
   experience during rollback is what matters.
4. **Does this preserve `unsafe_code = "forbid"`?** Only the reviewed Win32 FFI
   is exempt.
