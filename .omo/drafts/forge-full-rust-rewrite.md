---
slug: forge-full-rust-rewrite
status: approved
intent: clear
review_required: false
pending-action: review, publish, and hand off .omo/plans/forge-full-rust-rewrite.md to execution
approach: Complete first-party Rust replacement using parity-gated migration, preserved data/contracts, native CLI/API/workers, and a proposed Rust-authored web UI; final distribution must not depend on Python.
---

# Draft: forge-full-rust-rewrite

## Components (topology ledger)
<!-- Lock the SHAPE before depth. One row per top-level component that can succeed or fail independently. -->
<!-- id | outcome (one line) | status: active|deferred | evidence path -->

| ID | Outcome | Status | Evidence |
|---|---|---|---|
| C1 | Every current capability, test lane, and active session task has a verified migration disposition | active | `forge/cli_registry.py`, `pyproject.toml`, `tests/`, `.agents/`, `.claude/handoffs/`, `.kiro/`, `.omo/` |
| C2 | Rust domain/persistence/auth/audit preserves existing stored evidence and authorization contracts | active | `SPEC.md:57-91`, `forge/db/schema.py`, `forge/db/control.py`, `forge/workflow/`, `forge/audit/` |
| C3 | Native Rust orchestration/discovery/parsing/validation/scoring/reporting reproduces the complete supported engagement workflow | active | `END_GOAL.md`, `forge/orchestration/`, `forge/phase0/` through `forge/phase6/`, `forge/monitoring/`, `forge/remediation/` |
| C4 | CLI, API, worker, and plugin/connector/provider interfaces run without first-party Python | active | `forge/cli_registry.py:15-45`, `forge/api/app.py`, `forge/core/runner.py`, `forge/plugins/loader.py:97-117`, `forge/connectors/`, `forge/providers/` |
| C5 | Web dashboard and operator UI retain feature parity in a Rust-first distribution | active | `forge/webui/app.py`, `forge/reporting/webui/package.json`, `forge/menu_shell.py`, `forge/tui/` |
| C6 | Reproducible Windows/Linux/macOS-appropriate packaging, full test evidence, healthy services, rollback and operator handoff | active | `docker/Dockerfile`, `docker/docker-compose.yml`, `build_rust_core.bat`, `.github/workflows/` |

## Open assumptions (announced defaults)
<!-- Record any default you adopt instead of asking, so the user can veto it at the gate. -->
<!-- assumption | adopted default | rationale | reversible? -->

- Plan the whole rewrite, not an MVP or a subset. Stages are implementation order, not scope reduction.
- Preserve existing CLI names/flags, API/JSON/error contracts, workspace authorization, export formats, config names and data readability unless an explicit compatibility decision is approved.
- Retain engagement/control SQLite and platform Postgres/Redis responsibilities during migration; avoid combining a language rewrite with a new database architecture.
- Native Rust CLI/API/worker share a Cargo workspace and typed domain layer. Proposed internals: clap, Tokio, Axum, serde, SQLx, tracing; select compatible pinned versions after build feasibility checks, not guessed version literals.
- New workspace should be separate from the existing PyO3 crate while porting. Existing Rust helper code is reusable only after tests and runtime-independent boundary review. Final first-party runtime contains no CPython, PyO3, PyArmor, Python subprocess fallback, or Python entrypoint.
- Keep the legacy implementation available as an isolated comparison oracle until cutover. Final acceptance must also work with Python absent from PATH; do not confuse migration-only oracle tooling with deployment requirements.
- Preserve existing fail-closed/unsupported behavior where functionality is not implemented; do not manufacture new behavior to erase TODO text. Every capability still receives an explicit disposition.
- Proposed test strategy: characterization plus differential fixtures, then Rust TDD; unit/property/integration/E2E/browser/network-lab/chaos/soak lanes accounted for. No skipped test or excluded file is counted as passed.
- Preserve source/history and user data. Test migration works on copies, uses single-writer cutover, and has a rehearsed rollback; no dual writers to production engagement databases.

## Findings (cited - path:lines)

- `rust_core/Cargo.toml:8-23`: current native crate is `cdylib`/`rlib` with PyO3; it is not a standalone application.
- `pyproject.toml:119-120`: public executable currently enters `forge.cli:main`.
- `forge/cli_registry.py:15-45,127-197`: root CLI covers many command groups, including separate public and hidden groups. Inventory must derive from code, not a hand-picked list.
- `forge/plugins/loader.py:97-117`: existing executable plugin discovery imports Python files, so plugin migration is a genuine compatibility boundary separate from JSON connector manifests and the new agent capability schema.
- `forge/db/schema.py:8-17,28-120`: engagement schema includes FTS5, encrypted columns, SQLite-specific boolean and foreign-key semantics, and typed seed/lineage tables. Porting ORM calls alone is insufficient.
- `SPEC.md:57-91`: V1-V14 require deterministic findings, monotonic IDs, provenance, bounded recursion, non-executing parsers, validated reportability, parity, fallback, test ownership, and literal-boolean retention confirmation.
- `forge/api/routes/health.py:27-64`: `/health` checks bus availability, while `/ready` is currently a lightweight liveness endpoint. Preserve or explicitly version semantics; add dependency/worker readiness evidence rather than treating process existence as health.
- `docker/docker-compose.yml:108-175`: separate API 8000, web 8080 and worker; Postgres/Redis dependencies.
- `docker/Dockerfile:13-21,24-45,74-90`: production image currently installs Python, venv and the Python package. Final packaging must replace this path, not merely add Rust beside it.
- `forge/reporting/webui/package.json:6-16`: UI is currently React/Vite with Vitest and TypeScript build; a literal first-party Rust rewrite needs a UI technology decision.
- `pyproject.toml:235-274`: pytest testpaths includes `tests`; default excludes chaos/slow/cart_readiness/network. Also inventory root `test_continuous_loop.py`, tools evidence harnesses, CI-specific command slices, frontend tests and inline Cargo tests.
- `tests/conftest.py:118-179`: Postgres-dependent tests skip when service/driver is absent; ported CI must fail missing required prerequisites instead of reporting a misleading pass.
- `tests/integration/conftest.py:16-17,36-50`: SSH integration requires mock-service inputs; integration local batches force sequential execution on Windows. The reason and production concurrency cases need parity tests.
- Existing readiness evidence: 29 agent tests and native AES smoke passed; full Python collection crashed; Cargo build and frontend workers timed out. These failures belong in the baseline phase, not proof that Rust solves them automatically.
- `.omo/plans/consolidated-competitive-upgrade-plan.md:3,15-35` is complete. `.kiro/sprints/sprint5_plan.md:5-9` explicitly identifies itself as historical. Historical TODOs must be reconciled, not activated indiscriminately.
- `.claude/handoffs/` contains 537 entries; partial searches found repeated July backlog reminders. No full reconciliation claim has been made.
- Git baseline at planning entry: `e4caf4c`; dirty `.agents/STATE.md`, `.agents/JOURNAL.md`, and an unrelated `rust_core/src/kerberos.rs` edit. Refresh before execution; do not overwrite user/other-agent work.
- Official Leptos documentation confirms Rust server rendering with Axum and browser WebAssembly hydration: https://book.leptos.dev/getting_started/index.html and https://book.leptos.dev/ssr/22_life_cycle.html . Rust-authored UI still produces HTML/CSS/WASM and generated browser glue; it is not an all-native browser executable.
- Prior three exploration subagents failed provider lookup/fallback and produced no findings. Planning uses direct repository and official-document retrieval; do not count agent self-reports as evidence or automatically replace cancelled inventory agents.

## Decisions (with rationale)

- User explicitly clarified **complete Rust rewrite** and asked to plan it before implementation.
- User approved pausing theprawnhunter to release memory. Used graceful stop (pause would retain memory); command returned all ten requested container names successfully. Left FORGE development Postgres/Redis and Pi-hole untouched.
- Stopped set: `theprawnhunter_api`, `theprawnhunter_worker-scanners`, `theprawnhunter_worker-scrape`, `theprawnhunter_beat`, `theprawnhunter_worker-validators`, `theprawnhunter_flower`, `theprawnhunter_bot`, `theprawnhunter_worker-core`, `theprawnhunter_frontend`, `theprawnhunter_redis`.
- Restore receipt for the execution phase: `docker start theprawnhunter_redis theprawnhunter_api theprawnhunter_worker-core theprawnhunter_worker-scanners theprawnhunter_worker-scrape theprawnhunter_worker-validators theprawnhunter_beat theprawnhunter_bot theprawnhunter_flower theprawnhunter_frontend`; verify health after startup. Keep the stopped-set record so unrelated containers are not affected.
- User subsequently approved every proposed boundary and requested all steps, subagents, commit and push to main. Current planner produces/reviews the execution contract; implementation proceeds in the worker phase with task evidence, not by interpreting this approval as a completion claim.
- Updated baseline: `0717e42`; another session committed the prior dirty Rust fix in `540cb44` and reported 53 native library tests and focused Python slices passing. Full-scope and frontend/runtime claims remain unverified. Preserve these new commits rather than resetting to the initial draft revision.

## Scope IN

- Native domain/runtime, CLI and operator TUI, APIs/websockets/auth, workers/bus/workflows, all currently supported scoped pipeline capabilities, static artifact and provider handling, validation/scoring, graph/report/export/standards, monitoring/remediation/retention, agent/plugin/connector boundaries.
- Existing data compatibility, audit-chain and encryption compatibility, migration-only reference harness, full test disposition ledger and replacement Rust coverage, dependency readiness, native distribution/container/startup paths and clean cutover.
- Reconcile every task-bearing project dot folder: completed with evidence, superseded with citation, or active with an executable plan item. Do not erase unverified work.
- UI and third-party tool boundaries approved as recommended below.

## Proposed migration sequence (approval brief, not executable task list)

1. Freeze and reproduce baseline; produce exhaustive command/API/config/data/capability/test/session ledgers and safe replay fixtures. Diagnose missing/crashed test evidence before trusting parity.
2. Establish Rust workspace, domain types, config/errors, provenance/security contracts, storage/audit/crypto compatibility, and owned test-data cleanup.
3. Port orchestration, agent/plugin boundaries, scoped adapters, parsers, validation/scoring, and providers with behavior-level differential tests and bounded cancellation/backpressure.
4. Port reporting/graphs/exports, monitoring/remediation/retention, CLI/TUI, API/websocket and worker surfaces; every inventory entry gets an explicit parity check.
5. Replace UI under the selected Rust/React boundary; preserve routes, operator interactions, accessibility, exports and authorized live progress.
6. Package without Python, run full cross-platform and failure/soak gates, rehearse data rollback and single-writer cutover, retire legacy runtime only after parity, restore paused services and close all active-ledger entries with evidence.

## Scope OUT (Must NOT have)

- No reduced-capability MVP presented as full completion; no permanent Python fallback disguised as a rewrite.
- No unrequested new product features, weakened scope/ROE/reportability rules, live scans as readiness checks, or implementation of historical sensor-avoidance requests.
- No deleting session history to make TODO counts zero, hiding failing tests, declaring an installed binary equal to current-source build proof, or promising mathematical flawlessness.
- No production data/schema/destructive cutover changes during planning. No edits to the other agent's Rust work.

## Open questions

None outstanding for plan generation. Approved: Leptos SSR/WASM with Axum; all first-party application/plugin code Rust; optional independent external-tool runtimes allowed; characterization + Rust TDD + differential/E2E/chaos/soak with explicit prerequisites and no excluded-as-passed accounting.

## Approval gate
status: approved
<!-- When exploration is exhausted and unknowns are answered, set status: awaiting-approval. -->
<!-- That durable record is the loop guard: on a later turn read it and resume at the gate instead of re-running exploration. -->

Approval received: “i approve all do all the steps now, spin subagents commit and push main”. Plan created with 36 implementation tasks and four final verifiers. Next: finish review/structural validation, publish approved plan checkpoint, then explicit worker handoff. Native Metis/Momus/Oracle task types are not exposed by the current task tool; a read-only explore gap-review was launched and must be reported by its actual tool/result, not relabeled as native high-accuracy approval.
