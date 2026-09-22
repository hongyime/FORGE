# FORGE Rust Rewrite — T9–T36 + F1–F4 Execution Checklist

**Status as of 2026-09-22:** T1–T8 accepted. T9 is next.
**Working rule:** One task = one or more commits, each commit verified (fmt+clippy+tests+xtask canary). MOLT updated after every accepted commit. Never claim done without evidence.

---

## How to use this file

1. Pick the lowest-numbered open `[ ]` task whose dependencies are all `[x]`.
2. Read the **Scope**, **References**, **Acceptance**, and **QA** fields from `.omo/plans/forge-full-rust-rewrite.md`.
3. Read the Python source listed under References before writing any Rust.
4. Implement in atomic subtasks; run gates after each.
5. On acceptance: check the `[ ]` → `[x]`, fill the commit SHA, update `.agents/STATE.md` + `.agents/JOURNAL.md`, push.

---

## Per-task gate sequence (repeat for every task)

```
[ ] MSVC env set (LIB/INCLUDE/PATH from VS2022) — required for rusqlite/sha2 C compilation
[ ] cargo fmt --manifest-path native/Cargo.toml --all            (exit 0)
[ ] cargo clippy --workspace --all-targets --offline -- -D warnings  (exit 0)
[ ] cargo test -p <crate> --offline --jobs 1 -- --test-threads=1    (all pass)
[ ] cargo build -p forge-xtask --offline --jobs 1                (exit 0)
[ ] forge-xtask verify <CASE> --evidence .omo/evidence/rust-rewrite/task-N/
[ ] git add <explicit paths>  (no broad add ., no .env, no target/)
[ ] git commit -m "feat(...): <description> — TN"
[ ] git push origin main
[ ] .agents/STATE.md updated (progress dashboard + current increment)
[ ] .agents/JOURNAL.md entry appended
[ ] git add .agents/ && git commit -m "docs(migration): record TN acceptance" && git push
```

**Never skip the MOLT commit.** It is the handoff for other agents working in parallel.

---

## Wave 2 — Storage · Audit · Buses · Plugins · Runtime (T9–T12)

### T9 — Port platform Postgres state and workflow history
**Crate:** `native/crates/forge-storage` (new module `src/platform/`)
**Python refs:** `forge/workflow/`, `alembic/versions/`, `forge/api/deps.py`, `tests/workflow/`
**xtask case:** `verify postgres`
**Dependencies:** T7 ✅, T8 ✅

- [ ] T9.1 — Read `forge/workflow/models.py`, `forge/api/deps.py`, alembic migration heads; document all Postgres tables and column types
- [ ] T9.2 — Add `sqlx = { version = "0.8", features = ["postgres","runtime-tokio-rustls","migrate","uuid","chrono"] }` + `tokio = { version = "1", features = ["full"] }` to `native/crates/forge-storage/Cargo.toml`; run `cargo check -p forge-storage --offline`
- [ ] T9.3 — Create `native/crates/forge-storage/src/platform/` with `mod.rs`, `migrations.rs` (embed migrations via `sqlx::migrate!`), `models.rs` (workflow state structs), `pool.rs` (PgPool factory with health check)
- [ ] T9.4 — Port `forge/workflow/` state machine: workflow runs, transitions, history replay, idempotent upserts, versioned rows
- [ ] T9.5 — Add unit tests (in-memory / mock) + integration tests requiring Postgres (gated by `FORGE_TEST_POSTGRES_URL` env; missing = `BLOCKED` receipt, not skip)
- [ ] T9.6 — Add `xtask/src/postgres_verify.rs` with canaries: fresh schema applies, state round-trip, restart-replay, disconnected DB = unhealthy
- [ ] T9.7 — Wire `"postgres"` case in `xtask/src/main.rs`
- [ ] T9.8 — Run full gate sequence; commit `feat(storage): port workflow persistence — T9`
- [ ] T9.9 — MOLT: update STATE.md + JOURNAL.md; commit + push
**Commit SHA:** ___________

---

### T10 — Port message bus, bounded eventing and task coordination
**Crate:** `native/crates/forge-runtime` (new)
**Python refs:** `forge/bus/`, `forge/distributed/`, `forge/agents/event_bus.py`, `forge/agents/coordinator.py`
**xtask case:** `verify bus`
**Dependencies:** T7 ✅, T8 ✅

- [ ] T10.1 — Read `forge/bus/redis_bus.py`, `forge/distributed/`, `forge/agents/event_bus.py`; document envelope schema, ack semantics, dedup keys
- [ ] T10.2 — Create `native/crates/forge-runtime/Cargo.toml` with `redis = "0.25"`, `tokio`, `serde_json`; add to workspace
- [ ] T10.3 — Port in-process bus: `EventBus` trait, `LocalBus` impl (tokio broadcast), bounded capacity, backpressure error type
- [ ] T10.4 — Port Redis bus: envelope serialize/deserialize, ack, retry with backoff, dedup via Redis SET NX, `stream` or `pubsub` backend
- [ ] T10.5 — Port coordinator: task assignment, capacity guards, heartbeat, cancellation token
- [ ] T10.6 — Unit tests for ordering, overflow, dedup, reconnect; integration tests gated by `FORGE_TEST_REDIS_URL`
- [ ] T10.7 — Add `xtask/src/bus_verify.rs`; canaries: ordered lifecycle, ack sequence, overflow bounded, disconnect explicit
- [ ] T10.8 — Wire `"bus"` case; run full gate sequence; commit `feat(runtime): port buses and task coordination — T10`
- [ ] T10.9 — MOLT update; commit + push
**Commit SHA:** ___________

---

### T11 — Port connectors and first-party plugin execution boundary
**Crate:** `native/crates/forge-adapters` (extend existing) + new `src/plugins/`
**Python refs:** `forge/plugins/`, `forge/connectors/`, `forge/agents/base_plugin.py`
**xtask case:** `verify plugins`
**Dependencies:** T5 ✅, T6 ✅, T7 ✅, T8 ✅

- [ ] T11.1 — Inventory all shipped first-party plugin IDs from `forge/plugins/` and `forge/connectors/`
- [ ] T11.2 — Define `NativePlugin` trait: `id()`, `execute(PluginInput) -> PluginResult`, `capability_manifest() -> Manifest`
- [ ] T11.3 — Port first-party builtin connectors to Rust (subfinder, httpx, katana, nuclei adapters as process-boundary wrappers)
- [ ] T11.4 — Implement external plugin boundary: JSON-over-stdio contract, versioned schema, child-process spawner with timeout+kill, output size cap
- [ ] T11.5 — Port Win32 FFI process containment (approved narrow boundary): Job Object, bounded pipes, descendant cleanup on supervisor exit
- [ ] T11.6 — Tests: valid plugin round-trip, malformed JSON rejected, oversized output truncated+audited, hung child terminated within deadline
- [ ] T11.7 — Add `xtask/src/plugins_verify.rs`; wire `"plugins"` case; run gate sequence; commit `feat(plugins): replace Python runtime loading — T11`
- [ ] T11.8 — MOLT update; commit + push
**Commit SHA:** ___________

---

### T12 — Port workflow engine, agent loop and scheduler
**Crate:** `native/crates/forge-runtime` (extend)
**Python refs:** `forge/core/runner.py`, `forge/workflow/`, `forge/agents/`, `forge/orchestrator/`
**xtask case:** `verify runtime`
**Dependencies:** T6 ✅, T9, T10, T11

- [ ] T12.1 — Read `forge/core/runner.py`, `forge/agents/base_plugin.py`; document workflow state machine transitions
- [ ] T12.2 — Port workflow state machine: phases, transitions, retry/cooldown, distributed lock, cancellation token
- [ ] T12.3 — Port agent loop: phase runners (discovery/analysis/reporting/governance), worker startup/shutdown, heartbeat
- [ ] T12.4 — Port scheduler: due-check, cooldown, single-instance lock via Redis/SQLite, backoff
- [ ] T12.5 — Tests: multi-step fixture completes, mid-task kill then resume (no duplicate evidence, no abandoned lock)
- [ ] T12.6 — Add `xtask/src/runtime_verify.rs`; wire `"runtime"` case; run gate sequence; commit `feat(runtime): port workflow and worker engine — T12`
- [ ] T12.7 — MOLT update; commit + push
**Commit SHA:** ___________

---

## Wave 3 — Discovery · Enrichment · Parsing · Validation · Scoring (T13–T18)

### T13 — Port scoped seed intake and bounded recursive discovery
**Crate:** `native/crates/forge-runtime` / new `forge-discovery`
**Python refs:** `forge/phase1/`, `forge/targets_import.py`, `forge/engagement_orchestrator.py`
**xtask case:** `verify discovery`
**Dependencies:** T2 partial, T5 ✅, T6 ✅, T12

- [ ] T13.1 — Port seed classifier: typed seeds, auto-detect, normalize, scope-check
- [ ] T13.2 — Port related-seed promotion: provenance chains, conflict/dedup, confidence
- [ ] T13.3 — Port target feed import: JSON feed v1 schema, engagement-per-seed, narrow scope manifest auto-generation
- [ ] T13.4 — Port resume candidates: classify pending/failed/abandoned runs
- [ ] T13.5 — Port stable-snapshot termination: iteration loop guard, budget exhaustion, stable-diff detection
- [ ] T13.6 — Tests: multi-seed fixture → stable snapshot; budget exhaustion preserves pending queue; out-of-scope pivot = zero traffic
- [ ] T13.7 — `verify discovery` canary; gate sequence; commit + MOLT
**Commit SHA:** ___________

---

### T14 — Port passive identity, DNS, history and provider enrichment
**Crate:** extend `forge-discovery` / new `forge-enrichment`
**Python refs:** `forge/phase0/`, `forge/phase2/`, `forge/utils/intel/`
**xtask case:** `verify enrichment`
**Dependencies:** T2 partial, T5 ✅, T6 ✅, T12

- [ ] T14.1 — Port DNS enrichment: MX/TXT/NS/CNAME, 21 SaaS-signal families, pacing/retry-after ceiling
- [ ] T14.2 — Port RDAP/CT: crt.sh, rdap.org, rate-limit backoff
- [ ] T14.3 — Port Wayback/Common Crawl CDX: domain-wide, bounded index count, results cap
- [ ] T14.4 — Port identity normalizer: email/username/company/phone/social dedup
- [ ] T14.5 — Port optional tool adapters (theHarvester, Holehe, Sherlock) as bounded external process callers with keyed/free distinction
- [ ] T14.6 — Tests: cached provider responses match expected pivots; 429 → bounded retry or explicit unavailable; missing key → `BLOCKED` receipt
- [ ] T14.7 — `verify enrichment` canary; gate sequence; commit + MOLT
**Commit SHA:** ___________

---

### T15 — Port static artifact decoding, parsing and queue processing
**Crate:** new `forge-analysis`
**Python refs:** `forge/phase4/artifact_parsers.py`, `forge/orchestration/artifact*/`
**xtask case:** `verify artifacts`
**Dependencies:** T2 partial, T5 ✅, T6 ✅, T12

- [ ] T15.1 — Port 9 artifact parsers: APK/IPA/document/archive/config/binary/other; static, non-executing
- [ ] T15.2 — Port nested-archive handler with decompression-bomb guard (max bytes before expand)
- [ ] T15.3 — Port URL/artifact-type classifier
- [ ] T15.4 — Port bounded worker pool for artifact queue (max workers, scope-gate before fetch)
- [ ] T15.5 — Tests: nested safe fixtures preserve canonical candidates+lineage; ZIP traversal/bomb/corrupt all fail without executing; every parser has positive + malformed fixture
- [ ] T15.6 — `verify artifacts` canary; gate sequence; commit + MOLT
**Commit SHA:** ___________

---

### T16 — Port non-destructive validation and latest-proof reportability
**Crate:** extend `forge-analysis`
**Python refs:** `forge/active_validation/`, `forge/phase4/provider_key_validators.py`, `forge/db/validation.py`
**xtask case:** `verify validation`
**Dependencies:** T2 partial, T5 ✅, T6 ✅, T12

- [ ] T16.1 — Port 9 provider key validators (stable, non-placeholder proof before `ACTIVE`)
- [ ] T16.2 — Port active-validation job/run model: dry_run / lab / read_only_live modes, approval gate, ROE/scope prerequisite
- [ ] T16.3 — Port HTTP reachability + security-headers methods (no response body stored, scrubbed URLs)
- [ ] T16.4 — Port fix-verification method: expected-result comparison, proof freshness
- [ ] T16.5 — Port latest-row reportability rule: DEAD/unknown proof revokes stale reportability
- [ ] T16.6 — Tests: placeholder proof → no finding; latest DEAD → reportability revoked; missing approval → blocked before network
- [ ] T16.7 — `verify validation` canary; gate sequence; commit + MOLT
**Commit SHA:** ___________

---

### T17 — Port deterministic scoring and standards enrichment
**Crate:** extend `forge-analysis`
**Python refs:** `forge/deterministic_findings.py`, `forge/standards/`
**xtask case:** `verify scoring`
**Dependencies:** T2 partial, T5 ✅, T6 ✅, T12

- [ ] T17.1 — Port rule engine: severity/rule-identifier derivation from evidence; no LLM output touches findings
- [ ] T17.2 — Port CVE/CVSS v4.0 normalization (prefer v4.0, retain v3/v2 as alternatives)
- [ ] T17.3 — Port EPSS, CISA KEV, CWE, CPE, ATT&CK local-cache enrichment (no live provider calls)
- [ ] T17.4 — Port STIX 2.1 import/export: parse vulnerability objects, emit bundle + TAXII manifest
- [ ] T17.5 — Tests: fixed fixtures → same findings+scores every run; injected narrative severity cannot promote finding
- [ ] T17.6 — `verify scoring` canary; gate sequence; commit + MOLT
**Commit SHA:** ___________

---

### T18 — Prove full pipeline parity through Rust runtime
**Crate:** integration tests in `native/` workspace
**Python refs:** `tests/integration/test_canonical_release_e2e.py`, `forge/demo.py`
**xtask case:** `verify pipeline`
**Dependencies:** T13, T14, T15, T16, T17

- [ ] T18.1 — Build canonical multi-seed fixture (synthetic engagement, no live deps)
- [ ] T18.2 — Run full pipeline: intake → discovery → parsing → validation → scoring → persisted provenance
- [ ] T18.3 — Assert same findings/severity/reportability as Python reference
- [ ] T18.4 — Test cancellation/resume: interrupted iteration preserves pending queue; restart deduplicates
- [ ] T18.5 — `verify pipeline` canary; gate sequence; commit + MOLT
**Commit SHA:** ___________

---

## Wave 4 — Graphs · Reports · Monitoring · Remediation · Automation (T19–T24)

### T19 — Port asset/attack graphs and all graph/export formats
**Crate:** new `forge-reporting`
**xtask case:** `verify graphs`
**Dependencies:** T2 partial, T8 ✅, T12, T18

- [ ] T19.1 — Port `forge/graph/`: asset entities, relationships, ownership claims, tier-zero scoring
- [ ] T19.2 — Port export formats: JSON, GraphML, Mermaid, DOT, MTGX, CSV, Cypher, Nemesis
- [ ] T19.3 — Port attribution import, ownership conflict resolution
- [ ] T19.4 — Tests: canonical entity/node/edge fields survive all formats; secret canaries excluded
- [ ] T19.5 — `verify graphs` canary; gate sequence; commit + MOLT
**Commit SHA:** ___________

---

### T20 — Port reports, templates, raw fallback and narrative providers
**Crate:** extend `forge-reporting`
**xtask case:** `verify reports`
**Dependencies:** T2 partial, T8 ✅, T12, T18

- [ ] T20.1 — Port all report families + template renderer (deterministic, no LLM required)
- [ ] T20.2 — Port provider cascade: local llama_cpp → OpenRouter free → template fallback
- [ ] T20.3 — Port raw JSON/CSV exports with checksums
- [ ] T20.4 — Tests: every fixture → auditable template/raw report when ALL providers fail
- [ ] T20.5 — `verify reports` canary; gate sequence; commit + MOLT
**Commit SHA:** ___________

---

### T21 — Port monitoring, alerts and exposure history
**Crate:** new `forge-operations`
**xtask case:** `verify monitoring`
**Dependencies:** T2 partial, T8 ✅, T12, T18

- [ ] T21.1 — Port monitoring policies: due-check, snapshot/diff, change classification
- [ ] T21.2 — Port alert model: open/acknowledged/resolved, suppression, delivery channels
- [ ] T21.3 — Port bounded worker refresh paths (seed_exposure, connector, active_validation)
- [ ] T21.4 — Tests: fixture clocks → expected due set+history; repeated equivalent evidence = no duplicate alert
- [ ] T21.5 — `verify monitoring` canary; gate sequence; commit + MOLT
**Commit SHA:** ___________

---

### T22 — Port remediation, ticket handoffs and retest lifecycle
**Crate:** extend `forge-operations`
**xtask case:** `verify remediation`
**Dependencies:** T2 partial, T8 ✅, T12, T18

- [ ] T22.1 — Port remediation items: owner, SLA, status, risk-acceptance expiry, retest linkage
- [ ] T22.2 — Port ticket event ledger: JSONL/GitHub/Jira/ServiceNow/Tines/Splunk/Torq connectors (data-boundary, no real ticket creation in QA)
- [ ] T22.3 — Port graph-owner propagation, `draft-from-asset-graph`
- [ ] T22.4 — Tests: expired risk/missing credentials/blocked retest = explicit unresolved work
- [ ] T22.5 — `verify remediation` canary; gate sequence; commit + MOLT
**Commit SHA:** ___________

---

### T23 — Port retention, workspaces and operator automation
**Crate:** extend `forge-operations`
**xtask case:** `verify operations`
**Dependencies:** T2 partial, T8 ✅, T12, T18

- [ ] T23.1 — Port retention preview/apply/legal-hold with policy enforcement
- [ ] T23.2 — Port workspace/member admin and control audit via `forge-storage`
- [ ] T23.3 — Port feed/queue/autostart: cooldown, backoff, single-instance lock, ROE gate
- [ ] T23.4 — Port doctor checks: per-check status, action_plan JSON
- [ ] T23.5 — Tests: string confirmation / active lock / missing ROE / legal hold reject before mutation
- [ ] T23.6 — `verify operations` canary; gate sequence; commit + MOLT
**Commit SHA:** ___________

---

### T24 — Close domain/service parity and API contract schemas
**Crate:** integration + ledger
**xtask case:** `verify service-parity`
**Dependencies:** T19, T20, T21, T22, T23

- [ ] T24.1 — Reconcile native ledger: every mapped capability has a verified receipt
- [ ] T24.2 — Build portable fixtures for CLI/server/UI tasks from T19-T23 outputs
- [ ] T24.3 — `verify service-parity` canary; gate sequence; commit + MOLT
**Commit SHA:** ___________

---

## Wave 5 — CLI · APIs · Rust UI · E2E (T25–T30)

### T25 — Port complete public/hidden CLI and native TUI
**Crate:** new `native/crates/forge-cli`
**xtask case:** `verify cli`
**Dependencies:** T24

- [ ] T25.1 — Port all public commands from `forge/cli_registry.py` (exact names/options/exit codes)
- [ ] T25.2 — Port hidden commands (recon, osint, etc.) with explicit platform errors for unsupported ops
- [ ] T25.3 — Port interactive menu (`forge menu`) and TUI workflows
- [ ] T25.4 — Tests: `forge demo proof-pack` on synthetic data; unknown command exits nonzero; denied op = no DB write
- [ ] T25.5 — `verify cli` canary; gate sequence; commit + MOLT
**Commit SHA:** ___________

---

### T26 — Port platform API, health and worker entrypoints
**Crate:** new `native/crates/forge-server`
**xtask case:** `verify platform-api`
**Dependencies:** T24, T25

- [ ] T26.1 — Port `/ready`, `/health`, `/metrics` endpoints (loopback 8000)
- [ ] T26.2 — Port workflow/report/quality API routes with JWT auth
- [ ] T26.3 — Port worker entrypoint: bus join, fixture processing, heartbeat
- [ ] T26.4 — Tests: actual localhost HTTP; worker event completes; DB/bus outage → unavailable health
- [ ] T26.5 — `verify platform-api` canary; gate sequence; commit + MOLT
**Commit SHA:** ___________

---

### T27 — Port engagement web API, auth and progress sockets
**Crate:** extend `forge-server`
**xtask case:** `verify engagement-api`
**Dependencies:** T24, T25, T26

- [ ] T27.1 — Port all engagement/control routes (loopback 8080)
- [ ] T27.2 — Port JWT issuance/claims, RBAC, workspace isolation
- [ ] T27.3 — Port WebSocket progress (tenant-scoped, `forge-progress` subprotocol)
- [ ] T27.4 — Tests: wrong tenant/stale token/path traversal → denied; websocket engagement mismatch → denied
- [ ] T27.5 — `verify engagement-api` canary; gate sequence; commit + MOLT
**Commit SHA:** ___________

---

### T28 — Port Rust UI overview, navigation and workspace administration
**Crate:** new `native/crates/forge-ui` (Leptos SSR + hydrate)
**xtask case:** `verify ui-overview`
**Dependencies:** T26, T27

- [ ] T28.1 — Scaffold Leptos SSR/hydrate targets (dual-compilation per Leptos docs)
- [ ] T28.2 — Port overview/search/filter/navigation, workspace/member controls, create engagement
- [ ] T28.3 — Port login/setup flows
- [ ] T28.4 — Tests: browser login/create/navigate/filter at desktop+mobile; expired token → actionable state
- [ ] T28.5 — `verify ui-overview` canary; gate sequence; commit + MOLT
**Commit SHA:** ___________

---

### T29 — Port Rust UI engagement review, graphs and actions
**Crate:** extend `forge-ui`
**xtask case:** `verify ui-detail`
**Dependencies:** T27, T28

- [ ] T29.1 — Port evidence/provenance/timeline panels
- [ ] T29.2 — Port graph interaction, report/raw-export review, connectors/secrets UI
- [ ] T29.3 — Port validation/remediation/retention/audit-review panels + live progress
- [ ] T29.4 — Tests: graph/report/validation/remediation/retention workflow in browser; denied action / disconnected socket → correct state
- [ ] T29.5 — `verify ui-detail` canary; gate sequence; commit + MOLT
**Commit SHA:** ___________

---

### T30 — Prove native operator journey across every surface
**Crate:** E2E harness
**xtask case:** `verify operator-e2e`
**Dependencies:** T25, T26, T27, T28, T29

- [ ] T30.1 — Build CLI + API + worker + browser E2E journey from synthetic intake through exports
- [ ] T30.2 — Assert same findings/provenance/reportability across all surfaces
- [ ] T30.3 — Test provider failure: partial/fallback output + no leaked test resources
- [ ] T30.4 — `verify operator-e2e` canary; gate sequence; commit + MOLT
**Commit SHA:** ___________

---

## Wave 6 — Packaging · Deployment · Release QA · Cutover (T31–T36)

### T31 — Package Python-free native distributions
**xtask case:** `verify packaging`
**Dependencies:** T30

- [ ] T31.1 — Release profile: stripped, LTO, single-file binary
- [ ] T31.2 — UPX compression step for Windows EXE + Linux binary
- [ ] T31.3 — Native Docker target (no Python/Node in runtime layer)
- [ ] T31.4 — Windows SBOM + THIRD_PARTY_LICENSES.md
- [ ] T31.5 — Tests: clean-runtime install/version/demo succeeds; missing optional tool → catalog unavailable, core demo passes
- [ ] T31.6 — `verify packaging` canary; gate sequence; commit + MOLT
**Commit SHA:** ___________

---

### T32 — Replace service deployment and startup supervision
**xtask case:** `verify deployment`
**Dependencies:** T31

- [ ] T32.1 — Native Compose file: replace Python/Node images with native binary image
- [ ] T32.2 — Native Windows scheduled-task + POSIX systemd unit
- [ ] T32.3 — Native Helm chart update
- [ ] T32.4 — Tests: `docker compose up -d --wait --wait-timeout 180` in isolated project; Redis stop → health unavailable → recovery; no duplicate work
- [ ] T32.5 — `verify deployment` canary; gate sequence; commit + MOLT
**Commit SHA:** ___________

---

### T33 — Cross-platform tests, mutation, chaos and soak
**xtask case:** `verify release-suites`
**Dependencies:** T31, T32

- [ ] T33.1 — Run Windows/Linux/macOS CI matrix against release artifact digests
- [ ] T33.2 — Targeted mutation against domain/policy (survivors explained/fixed)
- [ ] T33.3 — Deterministic fault injection: Redis kill, Postgres drop, disk full
- [ ] T33.4 — **24-hour synthetic soak** — do NOT claim from shorter run; measure memory/queue growth vs declared budgets
- [ ] T33.5 — `verify release-suites` canary; all lane receipts reconcile; commit + MOLT
**Commit SHA:** ___________

---

### T34 — Rehearse copy-based data cutover and rollback
**xtask case:** `verify cutover`
**Dependencies:** T31, T32, T33

- [ ] T34.1 — Fence new writes; drain workers/queues; take coordinated SQLite+Postgres+audit checkpoints
- [ ] T34.2 — Run cutover with maintenance mode until pre-write verification succeeds
- [ ] T34.3 — Record durable replayable mutation/outbox receipts for rollback
- [ ] T34.4 — Test rollback: fixture counts, ownership, encrypted readability, audit hashes survive
- [ ] T34.5 — `verify cutover` canary; gate sequence; commit + MOLT
**Commit SHA:** ___________

---

### T35 — Retire legacy first-party runtime and reconcile all migration
**xtask case:** `verify retirement`
**Dependencies:** T34

- [ ] T35.1 — Remove Python/React application runtime from distribution
- [ ] T35.2 — Reconcile every legacy subsystem capability (c2, kerberos, phase3, phase5, post_exploitation, hardening, hybrid, auth, post) against T11/T16/T25 evidence
- [ ] T35.3 — Update README, DAILY_USE, END_GOAL, SPEC via designated spec workflow
- [ ] T35.4 — All launchers reach native binaries; no Python subprocess fallback
- [ ] T35.5 — Rebuild final release artifacts; compare hashes with T33; rerun T33 if runtime/assets changed
- [ ] T35.6 — `verify retirement` canary; gate sequence; commit + MOLT
**Commit SHA:** ___________

---

### T36 — Validate installed system and restore paused workloads
**xtask case:** `verify installed`
**Dependencies:** T35

- [ ] T36.1 — `curl.exe --fail http://127.0.0.1:8000/health` passes on native install
- [ ] T36.2 — `curl.exe --fail http://127.0.0.1:8080/health` passes
- [ ] T36.3 — Authenticated synthetic job completes; worker heartbeat truthful
- [ ] T36.4 — Restore paused TPH set: `docker start theprawnhunter_redis theprawnhunter_api theprawnhunter_worker-core theprawnhunter_worker-scanners theprawnhunter_worker-scrape theprawnhunter_worker-validators theprawnhunter_beat theprawnhunter_bot theprawnhunter_flower theprawnhunter_frontend`
- [ ] T36.5 — Inspect restored container health; report BLOCKED if resource budget prevents coexistence
- [ ] T36.6 — `verify installed` canary; gate sequence; commit + MOLT
**Commit SHA:** ___________

---

## Final Verification Gates (all parallel, all must APPROVE)

### F1 — Plan compliance audit
- [ ] `cargo run -p forge-xtask -- verify plan-compliance --evidence .omo/evidence/rust-rewrite/final-F1`
- [ ] All 36 tasks have receipt revision hashes; no missing required entry

### F2 — Code quality review
- [ ] `cargo fmt --all -- --check` (final revision)
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` (final revision)
- [ ] `cargo test --workspace --locked --jobs 1` (final revision)
- [ ] Dependency/runtime composition audit; no supply-chain surprise

### F3 — Real manual QA
- [ ] Browser: login/create/navigate/filter/export at desktop + mobile
- [ ] Failover + rollback exercised on synthetic fixtures
- [ ] Screenshots + HTTP/action logs + teardown receipts at `.omo/evidence/rust-rewrite/final-F3`
- [ ] No mock-only or screenshot-only claim

### F4 — Scope fidelity
- [ ] Whole first-party Rust scope verified
- [ ] No Python/React application runtime in release
- [ ] No unsupported feature silently removed
- [ ] Preserved data/history confirmed
- [ ] Artifact/revision hashes at `.omo/evidence/rust-rewrite/final-F4`

---

## Anti-stuck rules

1. **MSVC env** — Set `LIB`, `INCLUDE`, `PATH` from VS2022 in every shell before any `cargo build/test` that touches rusqlite/sha2 C code.
2. **Targeted tests** — Use `-p forge-storage` not `--workspace` to avoid 30-min full compile cycles during development. Run `--workspace` only for the gate sequence before each commit.
3. **Offline first** — Use `--offline` after first successful `cargo check --offline` (lock file updated). Fall back to online only when a new dep isn't yet in the lock file.
4. **No `git add .`** — Always stage explicit file paths. Never include `target/`, `.env`, `*.db`, `*.json` evidence blobs.
5. **MOLT after every push** — Update STATE.md progress dashboard + JOURNAL.md entry. This is the handoff for parallel agents.
6. **Parallel agents pull before push** — `git fetch origin && git log --oneline origin/main -5` before every push. If main moved, `git merge origin/main --no-edit` and rerun tests.
7. **Subagent model constraint** — Per AGENTS.md, subagents must use `amazon-bedrock/global.anthropic.claude-sonnet-4-6`. If team mode can't enforce routing, work directly.
8. **Incremental commits** — Never accumulate more than one task worth of changes before committing. A 10-hour uncommitted session is a hung-session risk.
9. **Ralph loop** — For tasks with many subtasks, use Ralph loop pattern: implement → test → commit → repeat, with `COMPLETE` sentinel when all subtasks done.

---

## Current CI gates (`.github/workflows/`)

These must stay green on main throughout the rewrite:
- Python pytest (unit + connectors + phase5/phase6) — no regressions allowed
- Vitest frontend (44/44)
- Rust fmt + clippy + workspace tests
- TruffleHog secret scan
- Bandit + Semgrep SAST

---

_Last updated: 2026-09-22 | Next task: T9_
