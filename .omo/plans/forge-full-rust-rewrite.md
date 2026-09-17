# forge-full-rust-rewrite - Work Plan

## TL;DR (For humans)
<!-- Fill this LAST, after the detailed plan below is written, so it summarizes the REAL plan. -->
<!-- Plain English for a non-engineer: NO file paths, NO todo numbers, NO wave/agent/tool names. -->

**What you'll get:** A complete Rust replacement for FORGE's application, including its command line, browser dashboard, background services and supported engagement workflows. Existing evidence remains readable, and every capability, test and active reminder has an evidence-backed migration record.

**Why this approach:** Port behavior against known fixtures before switching installations. Keep data formats and authorization rules stable so the language change does not become an uncontrolled data or product redesign.

**What it will NOT do:** Ship an incomplete replacement as finished, keep a hidden Python fallback, erase historical reminders to conceal unfinished work, or weaken existing safety and reporting gates.

**Effort:** XL
**Risk:** High — broad behavior, stored evidence, plugin compatibility and native/browser packaging must move together.
**Decisions to sanity-check:** Approved: Rust-authored application and dashboard; optional independent tools may retain their own runtimes; test-first migration, explicit rollback and verified incremental publishing.

Your next move: execution has been requested; use a dedicated worker session to execute the ordered tasks and publish verified checkpoints. Full execution detail follows below.

---

> TL;DR (machine): XL, high-risk full first-party Rust migration; 36 implementation tasks in six waves plus four final verifiers; preserve contracts/data and prove Python-free operation.

## Scope
### Must have

- Approval: user approved the complete Rust rewrite, Rust-authored browser UI, optional external-tool runtime boundary, parity-first/TDD strategy, subagents, and commits/pushes to `main` on 2026-09-15. This plan is the execution contract, not completion evidence.
- Rewrite all shipped first-party runtime functionality in Rust: CLI/TUI, public and hidden command dispatch, HTTP/websocket surfaces, workflows/agents/plugins, scoped discovery, static parsing, validation/scoring, reporting/graphs/standards, monitoring/remediation/retention, storage and startup tooling. Browser UI: Leptos SSR/hydration with Axum; generated HTML/CSS/WASM/JS glue is allowed. Do not retain React application logic at cutover.
- Optional third-party tools may run in their own isolated runtimes through bounded adapters. Their absence must not break the deterministic core. Shipped first-party Python plugins must be ported, not relabeled as third-party exceptions.
- Preserve `END_GOAL.md` and SPEC V1-V14, existing CLI names/options/exit semantics, API routes and machine-readable payloads, config precedence, SQLite evidence/control files, platform Postgres/Redis roles, encryption formats, audit-chain verification, monotonic IDs and report/export compatibility.
- Retain migration-only Python reference tools until parity is proven. Final executable/container path contains no first-party Python interpreter, PyO3/PyArmor dependency or Python fallback.
- Every source capability, test case/lane and active session reminder receives a stable inventory ID, owner task and disposition. Historical/superseded tasks get evidence-linked dispositions; active tasks must be implemented or explicitly blocked, never silently erased.
- Legacy subsystem ownership is explicit: `forge/c2/`, `forge/kerberos/`, `forge/phase3/`, `forge/phase5/`, `forge/post_exploitation/`, `forge/hardening/`, `forge/hybrid/`, `forge/auth/` and `forge/post/` are inventoried by task 1, receive native adapter/plugin and platform-capability ownership in task 11, supported policy-admitted service behavior in task 16, and hidden-command/error compatibility in task 25. Task 35 verifies each individual capability disposition. These namespaces are not omitted merely because hidden from help. Existing non-destructive/authorized supported behavior must have native parity; already-disabled/unsupported behavior retains explicit fail-closed results. Any conflict with the normative ASM contract becomes a blocking, cited policy decision, not silent feature removal or a successful empty stub.
- Baseline at plan generation: `0717e42`. Another session committed Rust fix `540cb44` and reported 53 Rust tests, 29 agent tests and 102 connector tests passing; treat these as reported slices until evidence is rerun. Earlier full collection access violation, frontend worker failures and service startup failures remain unresolved.

### Must NOT have (guardrails, anti-slop, scope boundaries)

- No reduced-feature executable described as the completed rewrite, empty successful handlers, skip-based green suites, unchecked parser/network bounds, new attack capabilities, or implementation of historical sensor-avoidance requests.
- No concurrent Python/Rust writers to the same live databases. No changing audit history, deleting source/session history, rotating existing keys, dropping data or forcing `main` to match an old baseline.
- No product-code edits by read-only review agents. No broad `git add .`, automatic `.env` inclusion, or commits of raw logs/DBs/customer evidence. Preserve unknown dirty changes.
- No metric guarantees invented from the language choice. Measure correctness, time and memory; Rust does not itself prove security or fix every environment issue.

## Verification strategy
> Zero human intervention - all verification is agent-executed.
- Test decision: characterization of existing valid behavior, then Rust TDD with `cargo test`, properties, fixture differentials and real CLI/HTTP/browser checks. Changes to existing Python during baseline repair also require failing-first regressions. Prose/format-only edits need structural checks, not artificial tests.
- Workspace: `native/Cargo.toml`, `native/crates/forge-{domain,storage,policy,runtime,adapters,analysis,reporting,operations,server,ui,cli}`, `native/xtask`; existing `rust_core/` remains independently buildable until retirement. Create only crates needed by the current task, not empty future stubs.
- Bootstrap native toolchain at the installed Rust `1.94.1` with edition 2024, `rustfmt` and `clippy`; commit a separate native lockfile. Use compatible families clap 4, Tokio 1, Axum 0.8, Leptos 0.8, serde 1 and SQLx 0.8, locked to resolver-selected versions. A compatibility failure blocks that task; update the recorded toolchain/dependency decision with evidence rather than silently floating toolchains. Leptos dual-target build is documented at https://book.leptos.dev/ssr/22_life_cycle.html .
- Every executable task has a `verify CASE` receipt via `cargo run --locked --manifest-path native/Cargo.toml -p forge-xtask -- verify CASE --evidence .omo/evidence/rust-rewrite/task-N`. Task 1 implements dispatch only for real implemented cases; unknown/unimplemented cases fail nonzero. The helper invokes actual checks and records command, revision, fixture hashes, duration, exit code, collected/executed/passed/failed/skipped counts, stdout/stderr artifact refs, and owned-resource teardown. It cannot substitute string/grep checks for runtime behavior.
- Task-specific `QA` entries below name the CASE and both required scenarios. The invocation above is literal after replacing CASE and N with that task's listed values. Add Rust tests under each affected crate's `tests/` with scenario IDs from its ledger; record RED and GREEN output before completion. Acceptance requires each named assertion, not merely successful helper exit.
- Common gates after each native change: `cargo fmt --manifest-path native/Cargo.toml --all -- --check`; `cargo clippy --manifest-path native/Cargo.toml --workspace --all-targets --locked -- -D warnings`; `cargo test --manifest-path native/Cargo.toml --workspace --locked`. Use `--jobs 1` on this host. Target-specific/WASM features run in their dedicated matrices; do not assume mutually exclusive SSR/hydration feature sets can be compiled together.
- Fixture differencing may normalize only documented nondeterministic fields (injected clock/IDs/random nonce); assertions still compare the resulting semantic values, sequence/order where contractual, provenance and checksums. Do not compare expectations calculated from output under test.
- Use synthetic engagements and per-attempt directories/DB schemas/ephemeral ports. HTTP observations use local fixture servers; any live provider lane requires existing scoped prerequisites and reports BLOCKED when missing. No live target acquisition during migration QA. Mutation/chaos/soak are explicit lanes, not forgotten marker exclusions.
- Build and run the release artifact with no Python/Node application runtime installed; test native WASM UI via a separately provisioned browser harness. Verify browser workflows, not just static screenshots. Existing Python testing tools are migration-only and must be identified in the final test ledger.

## Execution strategy
### Parallel execution waves
> Target 5-8 todos per wave. Fewer than 3 (except the final) means you under-split.

Six waves, six tasks each. A wave finishes only when its tasks have reviewed evidence; task dependencies below remain binding within a wave. Maximum two coding agents and one heavy build/test at a time on the current host. Assign disjoint crates/worktrees; one integrator owns manifests, lockfiles, state and `main` commits. Reviewers are read-only. If subagent infrastructure fails, record it and perform direct work; never fabricate review receipts.

Scheduling clarification after the first checkpoint: T1's native code contract was independently confirmed and published in `5b7b82e` (28 passing native tests). Its checkbox remains open for denied fixture cleanup and unavailable LSP. Tasks 2 and 3 may consume that accepted code/interface while those non-code closure items remain explicitly blocked; this does not authorize denied deletions, mark T1 complete, waive final diagnostics/cleanup, or bypass any other dependency. Final release still requires closure of every item. This separates usable prerequisite code from final administrative closure so independent work can continue.

The ten theprawnhunter containers were stopped with permission to release RAM. Do not stop additional workloads. Their restore set is in task 36. Keep FORGE development Postgres/Redis available. Recheck actual state because other sessions may operate concurrently.

Single-source migration ledgers live in `native/migration/`: `capabilities.json`, `contracts.json`, `tests.json`, `session-work.json`, `baseline.json`, `parity.json`, `resources.json`. Stable IDs survive rescan. Statuses are `pending`, `implemented`, `verified`, `superseded`, `blocked`; verified requires receipt references, superseded requires a replacement/citation, blocked is never release-pass. These are product-specific migration evidence, not generic task management.

### Dependency matrix
| Todo | Depends on | Blocks | Can parallelize with |
| --- | --- | --- | --- |
| 1 | none | 2-6, all verification | none |
| 2 | 1 | 7-30 parity gates | 3 |
| 3 | 1 | 4-6,7 | 2 |
| 4 | 3 | 5-7 | 2 |
| 5 | 3,4 | 6,11,13-17 | 2 |
| 6 | 3,4,5 | 7,11,12 | 2 |
| 7 | 2,3,4,6 | 8-12 | none |
| 8 | 7 | 9-12 | none |
| 9-10 | 7,8 | 12,19-24 | each other |
| 11 | 5,6,7,8 | 12,19,24 | 9,10 |
| 12 | 6,9,10,11 | 13-30 | none |
| 13-17 | 2,5,6,12 | 18 | each other, max two |
| 18 | 13-17 | 19-30 | none |
| 19-23 | 2,8,12,18 | 24 | each other, max two |
| 24 | 19-23 | 25-30 | none |
| 25 | 24 | 26,27,30 | none |
| 26 | 24,25 | 27,28,29,30 | none |
| 27 | 24,25,26 | 28,29,30 | none |
| 28 | 26,27 | 29,30 | none |
| 29 | 27,28 | 30 | none |
| 30 | 25-29 | 31-36 | none |
| 31 | 30 | 32,33,34 | none |
| 32 | 31 | 33,34 | none |
| 33 | 31,32 | 34-36 | none; one heavy test |
| 34 | 31-33 | 35,36 | none |
| 35 | 34 | 36 | none |
| 36 | 35 | F1-F4 | none |
| F1-F4 | 1-36 | release claim | independent read-only verification |

## Todos
> Implementation + Test = ONE todo. Never separate.
<!-- APPEND TASK BATCHES BELOW THIS LINE WITH edit/apply_patch - never rewrite the headers above. -->
- [~] 1. Bootstrap native migration inventory and fail-closed evidence runner
  Blocked closure: native code and independent verification are published (`5b7b82e`); previously denied cleanup of `native/target/reviewer-t1` and `native/target/t1-id-cli-20260916-01`, plus unavailable LSP diagnostics, remain unresolved. No denied action is authorized by this status. Accepted code may be consumed per the scheduling clarification above; this is not full task completion.
  Scope: `native/{Cargo.toml,Cargo.lock,rust-toolchain.toml,xtask/}`, `native/migration/`. Inventory every first-party source under `forge/`, `rust_core/src/`, launchers/scripts/tools, Python tests including root tests, frontend tests, workflow jobs and project-local dot-folder task records. Exclude secret/env/database/cache/vendor contents; retain path-level exclusions in the ledger. Syntax-aware discovery must handle Python decorators/async/classes/parameterization and Rust inline tests; static declarations are not collected test cases. No fake counts or arbitrary CLI commands.
  References: `forge/cli_registry.py:15-45,127-197`, `pyproject.toml:235-274`, `tests/conftest.py:42-73`, `.agents/STATE.md`, `.claude/handoffs/`, `.kiro/`, `.omo/plans/`, `test_continuous_loop.py`, `.github/workflows/`.
  Dependencies: wave 1; none. Acceptance: stable unique ledger IDs, no ignored capability, every unresolved entry `pending`/`blocked`, scanner reports unreadable inputs rather than silently skipping. Record baseline revision and dirty paths.
  QA: `verify inventory`; happy rescan is semantically identical and includes public/hidden command groups, all runners and task-bearing folders; failure corrupt fixture declaration or unreadable source yields nonzero and a cited problem. Unit tests prove unknown verify cases fail.
  Commit: Y | `feat(migration): inventory Rust rewrite scope`.

- [~] 2. Recover trustworthy baseline and complete test-case accounting
  Blocked full baseline: required live/provider/operator-state lanes lack explicit scoped prerequisites and prior fixture cleanup was denied. Implementable work remains: non-Python adapters and complete collection/execution accounting. Corrective runner code is independently confirmed (48 native tests; `task-2/adversarial-verify-final.json`) and published in `486c344`; the historical 3,318 observed cases are partial, not a full-suite total. Bounded Vitest execution-accounting adapter accepted and published in `aca24ce` (13 files: 8 source modules + 3 test files + main.rs/baseline.rs dispatch); runtime collection and full input provenance DEFERRED; lane.complete hard-false preserved. No full T2 completion.
  Scope: `native/migration/baseline.json`, test adapter in `native/xtask/`, affected legacy tests/runtime only for confirmed blockers. Collect each test file in a contained subprocess if a monolithic native import crashes, track parameterized IDs and exit/signal outcomes, reconcile markers including network/slow/chaos/cart_readiness and root/evidence harnesses. Reproduce/fix native crash and Vitest worker startup with evidence; do not blanket-exclude registry tests or call a timeout a pass.
  References: `tests/test_obfuscated.py`, `tests/connectors/test_registry.py:38`, `tests/integration/conftest.py:36-50`, `forge/reporting/webui/package.json`, `rust_core/Cargo.toml`, `build_rust_core.bat`, `.agents/STATE.md`.
  Dependencies: wave 1; 1. Acceptance: every discovered lane has exact invocation, prerequisites, case IDs and actual result; required baseline tests run or remain blocking. Isolated comparison fixtures cover valid behavior and SPEC overrides for known bugs.
  QA: `verify baseline`; happy 29-agent suite, current native suite and complete parameterized inventory reconcile counts; failure forced child crash/timeout produces failed receipt, cleans child tree and cannot drop file from totals.
  Commit: Y | `test(migration): capture executable parity baseline`.

- [~] 3. Establish native typed domain and serialization contracts
  Blocked contracts: characterization proved source-default disclosure in `DehashedResult.password`, `HashCredential.hash_plaintext`, and short `KeyScannerFinding.key_prefix`. Exact compatibility conflicts with the approved secret-redaction requirement; resolve the affected serialization boundary before those three ports. Evidence: `task-3/remaining-contracts/source-security-conflicts.json`. Unaffected DTO implementation remains actionable and must not be stalled or falsely marked complete.
  Verified progress: initial domain increment in `486c344`; workspace integration in `91e79bb`; portable fixtures in `a446679`, typed records in `f8a9361`, canonical LF fixture metadata + integrity guard in `5e12b89`, functional baseline budget fix in `37cf5c4`, enum boundary parity consumer and fixtures in `d92464d`, graph coercion fix in `7491cb6`, graph parity consumers in `489c92b`, BreachRecord/TaskState coverage in `59fc1b1`, domain ledger correction in `95e8cbe` — all pushed to origin/main. Parent verification: `cargo test --workspace --locked --offline --jobs 1 --test-threads=1` passed **190 tests** (119 domain + 71 xtask), 0 failures/ignores; fmt and clippy -D warnings clean. Evidence: `.omo/evidence/rust-rewrite/task-3/remaining-contracts/fixture-canonicalization/parent-vitest-{fmt,clippy,workspace-final}.json`; mutex released. Scoped reviewer ses_f55a27f13ffe2J6r6558QASYQM approved enum increment after corrections, no blockers. Independent reviewer ses_f5216b9a6ffecql5TpWZbOQk8n approved bounded Vitest scope; only non-blocking reason-text notes. Tracked ledger (corrected 2026-09-17 audit, committed `95e8cbe`): 43 `implemented_fixture_verified` (24 DTOs + 2 agent contracts + 16 enum sections/15 Rust types + 1 BreachRecord), 5 `existing_partial` (AttackNode/Edge/Graph/AttackGraphReportContext — structural fixture not source-captured; TaskState — no Python plain-class boundary characterization), 3 `blocked_policy_conflict`, 1 `blocked_dependency`. Full 118-entry type/table parity remains open; 66 `reference_only` entries route by owner (storage→T7, plugin/bus runtime→T10–T12); broad graph differential proof still partial despite 190 tests pass. No full T3 completion.
  Scope: `native/crates/forge-domain/`; engagement/workspace/entity IDs, typed seeds, URLs, findings, reportability, task states, provenance, timestamps and enums. No CLI/server dependency and no Python runtime.
  References: `forge/models/`, `forge/engagement_ids.py`, `forge/db/schema.py:28-120`, `forge/agents/base_plugin.py`, `forge/standards/`, SPEC V1-V8.
  Dependencies: wave 1; 1. Acceptance: all domain/JSON schema IDs in ledger map to Rust types; enum unknown values, null/missing distinctions, Unicode/URL normalization and ordering preserve contract or reject per SPEC.
  QA: `verify domain`; happy representative multi-seed/graph/task fixtures roundtrip unchanged; failure malformed enum/ID/URL produces typed error before persistence. Add property tests for canonicalization idempotence.
  Commit: Y | `feat(domain): port typed engagement contracts`.

- [~] 4. Port configuration, errors, logging and resource lifecycle
  Blocked start: prerequisite T3 is not accepted; unresolved serialization-policy decisions and incomplete domain-proof acceptance remain. The T1 scheduling exception authorizes T2/T3 only, not T4. Read-only preparation is permitted; production implementation waits for its prerequisite without weakening any acceptance gate.
  Scope: `native/crates/forge-domain/src/config/`, shared runtime support. Preserve explicit CLI > environment > local-config > default precedence, bounded budgets, redaction and structured errors. Settings parsing must not spawn services or read unrelated secrets.
  References: `forge/config.py`, `forge/cli_runtime.py`, `forge/utils/log_redaction.py`, `forge/subprocess_tree.py`, `forge/automation_self_heal.py`.
  Dependencies: wave 1; 3. Acceptance: config inventory maps every supported key; invalid settings fail before side effects, cancellation releases owned handles, logs contain no fixture secret canaries.
  QA: `verify config`; happy conflicting distinct values select correct precedence; failure malformed budgets/secret-bearing errors stay fail-closed and redacted. Child tree termination is tested on Windows and POSIX.
  Commit: Y | `feat(runtime): port config and lifecycle contracts`.

- [ ] 5. Port scope, authorization and admission gates
  Scope: `native/crates/forge-policy/`; typed authorized contexts, ROE/scope, URL-prefix and redirect/subresource restrictions, capabilities/RBAC, validation approval and retention confirmation. A caller cannot bypass gates by invoking a lower layer directly.
  References: `forge/opsec/scope_gate.py`, `forge/webui/rbac.py`, `forge/active_validation/`, `forge/agents/base_plugin.py`, `forge/governance/`, SPEC V5-V14.
  Dependencies: wave 1; 3,4. Acceptance: contract fixtures cover wildcard rejection, IPv4/IPv6, URL paths, tenant denial, manual approval, literal boolean confirmation; denied operations cause zero I/O/persistence calls.
  QA: `verify policy`; happy explicitly authorized local fixture accepted; failure cross-tenant, redirect escape and string `true` retention requests rejected before dispatch.
  Commit: Y | `feat(policy): preserve authorization invariants`.

- [ ] 6. Port compatible cryptography and safe adapter interfaces
  Scope: `native/crates/forge-storage/src/crypto/`, `native/crates/forge-adapters/`; AES/encoding/key-reference formats, typed HTTP/process/browser adapter traits and deterministic fakes. Native library internals have no PyO3 dependency.
  References: `rust_core/src/crypto.rs`, `forge/connectors/secrets.py`, `forge/db/`, `forge/connectors/runner.py`, `forge/utils/intel/provider_urls.py`.
  Dependencies: wave 1; 3,4,5. Acceptance: old encrypted fixtures decrypt in Rust and Rust fixtures decrypt in legacy reference; malformed keys/ciphertexts fail without panic. Tool adapters declare version, availability, budgets, output schema and provenance.
  QA: `verify crypto-adapters`; happy cross-language encrypted fixture roundtrip; failure wrong key/truncated ciphertext/missing optional tool produces explicit error without fake success or core-startup failure.
  Commit: Y | `feat(adapters): add native compatibility boundaries`.

- [ ] 7. Port SQLite engagement/control repositories and migrations
  Scope: `native/crates/forge-storage/`; every table/index/trigger/FTS item and migration discovered in SQLite ledgers, transaction boundaries, WAL/FK/timeouts and control-index/tombstone behavior. Work on copied fixtures only.
  References: `forge/db/{schema.py,migrations.py,direct_connect.py,session.py,control.py}`, `forge/engagement_ids.py`, `forge/workspace_backfill.py`, `tests/db/`.
  Dependencies: wave 2; 2,3,4,6. Acceptance: schema/data parity, read/write compatibility, monotonic non-reused IDs and corruption/migration interruption recovery. No parallel writers during differential checks.
  QA: `verify sqlite`; happy migrate old fixture then compare tables/exports; failure aborted migration rolls back and original copy hash stays unchanged.
  Commit: Y | `feat(storage): port SQLite evidence stores`.

- [ ] 8. Port audit chains, manifests, reviews and retained evidence
  Scope: native storage/audit services; canonical serialization/hash algorithms, manifest signatures, bundle checksums, append-only enforcement, remote mounted storage, legal holds and review provenance.
  References: `forge/audit/`, `forge/reporting/audit_manifest_artifacts.py`, `forge/retention/`, `tests/audit/`, SPEC V3,V8,V11,V14.
  Dependencies: wave 2; 7. Acceptance: Rust verifies historical synthetic chains byte-for-byte; new append verifies through legacy reader; tampering and legal-hold violations rejected.
  QA: `verify audit`; happy verify/append/export/import fixture receipts match; failure modify one historical byte or request held-data removal yields nonzero without replacing evidence.
  Commit: Y | `feat(audit): preserve chain and manifest compatibility`.

- [ ] 9. Port platform Postgres state and workflow history
  Scope: `native/crates/forge-storage/src/platform/`; existing Postgres models/migrations, workflow persistence/history/replay, workspace enforcement and idempotent transitions.
  References: `forge/workflow/`, `alembic/`, `forge/api/deps.py`, `tests/workflow/`, `tests/conftest.py:118-179`.
  Dependencies: wave 2; 7,8. Acceptance: per-attempt Postgres schema fixtures preserve state/version/history; restart resumes without duplicate committed transitions. Required unavailable Postgres is a failed prerequisite, not a skip.
  QA: `verify postgres`; happy restart/replay matches committed history; failure duplicate/stale update rejected and disconnected DB gives unhealthy readiness.
  Commit: Y | `feat(storage): port workflow persistence`.

- [ ] 10. Port message bus, bounded eventing and task coordination
  Scope: `native/crates/forge-runtime/`; Redis and in-process buses, envelopes/ack/retry/dedup, cancellation/backpressure, bounded pub/sub and coordinator lifecycle. Distinguish the new agent event bus from durable platform bus.
  References: `forge/bus/`, `forge/distributed/`, `forge/agents/{event_bus.py,coordinator.py,capability_manifest.py}`, `tests/test_*bus*`, `tests/unit/`.
  Dependencies: wave 2; 7,8. Acceptance: event ordering, capacity, failure semantics, duplicate delivery and task status contracts preserved; no task status fabricated after process restart.
  QA: `verify bus`; happy ordered lifecycle and ack sequence; failure queue overflow/Redis disconnect/replayed message stays bounded, explicit and deduplicated.
  Commit: Y | `feat(runtime): port buses and task coordination`.

- [ ] 11. Port connectors and first-party plugin execution boundary
  Scope: native adapter/policy registry, all shipped builtins and data-only connector manifests, including legacy subsystem wrappers/platform admission for `forge/{c2,kerberos,phase3,phase5,post_exploitation,hardening,hybrid,auth,post}/`. Port owned plugins to Rust; optional external plugins use versioned bounded JSON-over-stdio contracts, never arbitrary in-process Python imports. Supply manifest validation and a per-capability compatibility inventory for old plugin owners, with task 16/25 ownership of supported service behavior/dispatch. Do not activate a previously disabled capability.
  References: `forge/plugins/{base.py,loader.py,executor.py}`, `forge/connectors/`, `forge/agents/base_plugin.py`, `tests/plugins/`, `tests/connectors/`.
  Dependencies: wave 2; 5,6,7,8. Acceptance: each first-party plugin ID routes to native implementation; external executable allowlist, explicit capability context, child limits and sanitized results cannot be bypassed through manifests.
  QA: `verify plugins`; happy registered native plugin and external fixture return schema-valid evidence; failure unknown capability, malformed JSON, oversized output or hung child rejected/terminated and audited.
  Commit: Y | `feat(plugins): replace Python runtime loading`.

- [ ] 12. Port workflow engine, agent loop and scheduler
  Scope: native runtime; planner/discovery/analysis/reporting/governance agent roles, workflow state machine, scheduling, retry/cooldown/locks, cancellation and worker startup/shutdown. No fake planner completion.
  References: `forge/core/`, `forge/workflow/`, `forge/agents/`, `forge/orchestrator/`, `forge/orchestration/`, `forge/core/runner.py`.
  Dependencies: wave 2; 6,9,10,11. Acceptance: fixture workflows execute through actual bus/repositories/plugin boundaries; restart and interruption preserve deterministic completed/pending work and clean owned locks.
  QA: `verify runtime`; happy multi-step workflow completes with receipts; failure terminate worker mid-task then resume without duplicate evidence or abandoned active lock.
  Commit: Y | `feat(runtime): port workflow and worker engine`.

- [ ] 13. Port scoped seed intake and bounded recursive discovery
  Scope: native runtime/adapters, seed classifier, related seeds, promotion/conflict/provenance, scope import, target feed and resume candidates. Preserve every typed seed and pending-work/stable termination rule.
  References: `forge/{targets_import.py,targets_resume_candidates.py,engagement_orchestrator.py,cli_kill_chain.py}`, `forge/orchestration/`, `forge/phase1/`, `tests/phase1/`.
  Dependencies: wave 3; 2,5,6,12. Acceptance: multi-iteration fixture reaches same canonical seeds, lineage and termination reason; failed queued work is not mistaken for convergence.
  QA: `verify discovery`; happy multi-seed fixture reaches stable snapshot; failure budget exhaustion/resume preserves pending queue and no out-of-scope pivot executes.
  Commit: Y | `feat(discovery): port bounded recursive intake`.

- [ ] 14. Port passive identity, DNS, history and provider enrichment
  Scope: every in-scope provider/enricher in capability ledger; DNS/RDAP/CT/history, identity normalization, public artifact metadata and optional tool adapters. Maintain pacing, retry-after ceilings, source constraints and free/keyed distinctions.
  References: `forge/phase0/`, `forge/phase2/`, `forge/utils/intel/`, `forge/ingestion/`, `tests/phase0/`, `tests/phase2/`.
  Dependencies: wave 3; 2,5,6,12. Acceptance: provider fixture families produce equivalent normalized evidence; no missing provider silently falls back to a misleading empty success.
  QA: `verify enrichment`; happy cached provider/identity responses match expected pivots; failure 429/malformed payload/missing key yields bounded retry or explicit unavailable status without unvalidated findings.
  Commit: Y | `feat(enrichment): port passive provider adapters`.

- [ ] 15. Port static artifact decoding, parsing and queue processing
  Scope: native analysis modules for every artifact parser/decoder/format in ledger, nested archives, encoding, URL classification, bounded worker execution, lineage and error taxonomy. Optional OCR/media engines remain declared external/native dependencies.
  References: `forge/phase4/artifact_parsers.py`, `forge/orchestration/artifact*`, `forge/utils/`, `tests/phase4/`, `tests/orchestration/`.
  Dependencies: wave 3; 2,5,6,12. Acceptance: every parser has positive and malformed fixture; output order/limits match contracts; bytes/path/depth budgets enforced before expensive allocations.
  QA: `verify artifacts`; happy nested safe fixtures preserve canonical candidates/lineage; failure ZIP traversal, decompression bomb, corrupt/unsupported format never executes input and records bounded failure.
  Commit: Y | `feat(analysis): port bounded static parsers`.

- [ ] 16. Port non-destructive validation and latest-proof reportability
  Scope: native analysis/policy, cloud/resource/key proof parsers, active-validation jobs/methods, latest-row rules, remediation retest and allowed local/lab/live admission. Own the supported policy-admitted non-destructive behavior and platform contracts inventoried from legacy `c2`, `kerberos`, `phase3`, `phase5`, `post_exploitation`, `hardening`, `hybrid`, `auth` and `post` namespaces; preserve existing disabled/unsupported/manual-only outcomes and their tests. Pure static formatting/crypto helpers route to tasks 6/15; adapter lifecycle routes to task 11. Behavior conflicting with the normative ASM goal remains an explicit release blocker pending resolution, never an omitted row or silently substituted stub. Add no new offensive capability or sensor-avoidance behavior.
  References: `forge/active_validation/`, `forge/phase4/provider_key_validators.py`, `forge/utils/cloud_exposure_gate.py`, `forge/db/validation.py`, `tests/active_validation/`.
  Dependencies: wave 3; 2,5,6,12. Acceptance: only supported stable proof authorizes a finding; newer failed/unknown proof revokes stale reportability; redirect/URL/key values remain scrubbed.
  QA: `verify validation`; happy known proof fixture validates; failure placeholder proof, latest DEAD result or missing approval prevents findings and network dispatch.
  Commit: Y | `feat(validation): port proof-bound validation`.

- [ ] 17. Port deterministic scoring and standards enrichment
  Scope: native analysis; rule engine, findings synthesis, CVE/CVSS/EPSS/KEV/CWE/ATT&CK associations and standards normalization. LLM output never sets findings/severity.
  References: `forge/deterministic_findings.py`, `forge/standards/`, `forge/phase4/`, `tests/standards/`, `tests/test_cloud_exposure_gate.py`, SPEC V6-V9.
  Dependencies: wave 3; 2,5,6,12. Acceptance: deterministic severity/rule identifiers/evidence match fixed fixtures including unsupported/suspect inventory; numeric comparisons have an explicit contract, not arbitrary tolerance.
  QA: `verify scoring`; happy repeated fixtures yield same findings and scores; failure injected narrative severity or unsupported proof cannot promote a finding.
  Commit: Y | `feat(scoring): port deterministic findings`.

- [ ] 18. Prove full pipeline parity through Rust runtime
  Scope: native integration/differential scenarios combining tasks 13-17; no placeholder phase runners. Reconcile every pipeline capability row against implemented behavior and remaining non-pipeline tasks.
  References: `tests/integration/test_canonical_release_e2e.py`, other `tests/integration/` recursion fixtures, `forge/demo.py`, `END_GOAL.md:150-223`.
  Dependencies: wave 3; 13-17. Acceptance: real native runtime traverses intake/discovery/parsing/validation/scoring with persisted provenance, cancellation/resume and no live external dependency.
  QA: `verify pipeline`; happy multi-seed canonical fixture matches reference contracts; failure interrupted recursive iteration preserves pending work and denied scope produces zero target traffic.
  Commit: Y | `test(pipeline): prove native engagement parity`.

- [ ] 19. Port asset/attack graphs and all graph/export formats
  Scope: native reporting; asset ownership/conflicts, attribution, identity/cloud relationships, tier-zero/path/choke-point/fix-set scoring and JSON/GraphML/Mermaid/DOT/MTGX/CSV/Cypher/Nemesis export inventory.
  References: `forge/graph/`, `forge/cli_graph.py`, `forge/cli_artifacts.py`, `tests/graph/`, commits `16ce013` and associated tests.
  Dependencies: wave 4; 2,8,12,18. Acceptance: canonical entity/node/edge fields and provenance survive every format; secret/path canaries excluded; exports reflect same validated evidence.
  QA: `verify graphs`; happy shared fixture has expected nodes/edges/ownership/fix-set across formats; failure malformed missing graph/type data errors explicitly rather than emitting empty successful graph.
  Commit: Y | `feat(graph): port canonical graph exports`.

- [ ] 20. Port reports, native templates, raw fallback and narrative providers
  Scope: native reporting/adapters; all report families, history/checksums, raw JSON/CSV, template rendering, CLI/provider cascade, local inference interface and quality/staleness/policy plans. Optional local inference may use its own native service; no llama-cpp-python in core.
  References: `forge/phase6/`, `forge/reporting/`, `forge/report/`, `forge/providers/`, `tests/phase6/`, `tests/reporting/`, SPEC V7,V9,V12,V13.
  Dependencies: wave 4; 2,8,12,18. Acceptance: every valid fixture produces an auditable template/raw report when all narrative providers fail; no prose assertion masquerades as behavior coverage.
  QA: `verify reports`; happy native template/checksum and provider fixture succeed; failure provider quota/token/timeout/missing executable still yields valid raw/template artifacts with failure metadata.
  Commit: Y | `feat(reporting): port deterministic report fallback`.

- [ ] 21. Port monitoring, alerts and exposure history
  Scope: `native/crates/forge-operations/`; policies, due planning, snapshots/diffs, alerts/suppression/delivery, bounded worker refresh, exposure metrics and enabled/idle semantics.
  References: `forge/monitoring/`, `tests/monitoring/`, `forge/connectors/`, `forge/active_validation/`.
  Dependencies: wave 4; 2,8,12,18. Acceptance: fixture clocks produce same due set/history; refresh respects gate and queue bounds; repeated equivalent evidence does not create duplicate alerts.
  QA: `verify monitoring`; happy due fixture records expected diff and alert; failure disconnected destination stores redacted failure/backoff and suppression prevents delivery.
  Commit: Y | `feat(monitoring): port policies and alerts`.

- [ ] 22. Port remediation, ticket handoffs and retest lifecycle
  Scope: native operations/adapters; ownership propagation, risk acceptance expiry/review, SLA queues, native local ticket event ledger, external ticket integrations and validation-linked retest.
  References: `forge/remediation/`, `tests/remediation/`, `forge/active_validation/`, `forge/graph/`.
  Dependencies: wave 4; 2,8,12,18. Acceptance: state transitions, expiry/timezone semantics, failed-handoff queue reasons and graph recommendations match fixture contracts; no real ticket creation during QA.
  QA: `verify remediation`; happy accepted risk and successful fixture retest update lifecycle correctly; failure expired risk/missing credentials/blocked retest remains explicit unresolved work.
  Commit: Y | `feat(remediation): port owner and retest workflow`.

- [ ] 23. Port retention, workspaces and operator automation
  Scope: native operations/storage; workspace/member administration, control audit, retention preview/apply/legal holds, feed/queue/autostart configuration, cooldown/backoff/single-instance locks and doctor/operator guidance.
  References: `forge/retention/`, `forge/workspaces_cli.py`, `forge/automation*`, `forge/targets_import*`, `forge/doctor.py`, `tests/retention/`, `tests/automation/`.
  Dependencies: wave 4; 2,8,12,18. Acceptance: all inventoried commands have truthful read-only/dry-run semantics and bounded apply behavior; confirm exactly true gates retained; cleanup removes only fixture-owned artifacts.
  QA: `verify operations`; happy fixture preview/apply respects policy; failure string confirmation, active lock, missing ROE and legal hold reject before mutation or live dispatch.
  Commit: Y | `feat(operations): port lifecycle and automation`.

- [ ] 24. Close domain/service parity and API contract schemas
  Scope: native migration ledger and integration cases combining 19-23. Build portable fixtures consumed by CLI/server/UI tasks, covering every supported result/error schema.
  References: `forge/webui/app.py`, `forge/api/routes/`, `forge/cli_registry.py`, native ledger, `tests/webui/`, `tests/cli/`.
  Dependencies: wave 4; 19-23. Acceptance: no service capability remains unmapped; provisional `implemented` entries lack verified status until executable case receipts exist. Inventory deltas from concurrent upstream work are reconciled.
  QA: `verify service-parity`; happy schema/behavior matrix is complete; failure delete a mapped implementation/test receipt and the ledger gate fails.
  Commit: Y | `test(parity): close native service contracts`.

- [ ] 25. Port complete public/hidden CLI and native TUI
  Scope: `native/crates/forge-cli/`; binary `forge`, existing commands/options/defaults/help visibility/JSON/exit codes, interactive menu and TUI workflows. Unsupported platform functions retain explicit platform errors; no success stubs.
  References: `forge/cli*.py`, `forge/cli_commands/`, `forge/menu_shell.py`, `forge/tui/`, `tests/cli/`, capability inventory.
  Dependencies: wave 5; 24. Acceptance: every command ID has dispatch and behavior tests; noninteractive JSON remains parseable and secret-free; terminal navigation and CJK/Unicode widths verified with an actual terminal rendering harness.
  QA: `verify cli`; happy `forge demo proof-pack` plus report/graph/status on synthetic data; failure unknown command/missing argument/denied operation exits nonzero without DB writes.
  Commit: Y | `feat(cli): port complete native operator commands`.

- [ ] 26. Port platform API, health and worker entrypoints
  Scope: `native/crates/forge-server/`, CLI `serve-api` and `worker`; existing platform workflow/report/quality endpoints and health payloads on loopback 8000. Preserve `/ready` legacy semantics while operational checks explicitly verify dependencies and worker heartbeat.
  References: `forge/api/`, `forge/core/runner.py`, `docker/docker-compose.yml:108-175`, `tests/core/`, `tests/integration/`.
  Dependencies: wave 5; 24,25. Acceptance: HTTP fixtures preserve route/schema/status contracts and tenant access; worker joins bus, processes fixture request and reports heartbeat; no swallowed schema-init failure presented as healthy.
  QA: `verify platform-api`; happy actual localhost requests and worker event complete; failure DB/bus outage gives unavailable health and queued fixture resumes after recovery.
  Commit: Y | `feat(server): port API and worker processes`.

- [ ] 27. Port engagement web API, auth and progress sockets
  Scope: native server `serve-web` on loopback 8080, all engagement/control routes, JWT issuance/claims, RBAC, websocket subprotocol and ownership guards, generated artifact/static access and headers.
  References: `forge/webui/`, `forge/security_headers.py`, `tests/webui/`, `forge/webui/app.py:458-1047` and all remaining registered routes in inventory.
  Dependencies: wave 5; 24,25,26. Acceptance: every route/permission pairing passes parity tests; websocket only emits allowed engagement progress; path traversal and cross-workspace artifact reads rejected.
  QA: `verify engagement-api`; happy token-scoped synthetic engagement CRUD/review/export; failure wrong tenant, stale token, invalid retention confirm and websocket engagement mismatch denied.
  Commit: Y | `feat(server): port engagement web contracts`.

- [ ] 28. Port Rust UI overview, navigation and workspace administration
  Scope: `native/crates/forge-ui/`, Leptos SSR and hydrate targets; overview/search/filter/navigation, workspace/member controls, setup/login and create engagement; accessible responsive UI, equivalent routes and state handling.
  References: `forge/reporting/webui/src/`, `forge/webui/templates/`, UI route/interaction ledger, existing frontend tests; Leptos SSR documentation in draft.
  Dependencies: wave 5; 26,27. Acceptance: no hydration mismatch, route parity, correct loading/error/empty states, keyboard and mobile operation; server endpoints enforce authorization independently of rendered controls.
  QA: `verify ui-overview`; happy browser login/create/navigate/filter with fixture data at desktop/mobile; failure expired token/empty workspace/API rejection shows actionable state without unsafe mutation.
  Commit: Y | `feat(ui): port Rust workspace overview`.

- [ ] 29. Port Rust UI engagement review, graphs and actions
  Scope: native UI detail panels, evidence/provenance/timeline, graph interaction, reports/raw exports, connectors/secrets, validation, remediation, retention, audit review and live progress. Preserve all inventoried React/static/HTMX operator capabilities; equivalent legacy URLs may redirect only when contract allows.
  References: `forge/reporting/webui/src/`, `forge/webui/templates/htmx/`, `tests/webui/`, frontend `*.test.tsx`, native API schemas.
  Dependencies: wave 5; 27,28. Acceptance: all controls have real authorized backing calls; reportability/counts match native service payloads; large graph interactions remain responsive without losing nodes silently.
  QA: `verify ui-detail`; happy browser traverses graph/report/validation/remediation/retention workflow; failure denied action, disconnected socket, malformed graph and withheld proof show correct state without leaking values.
  Commit: Y | `feat(ui): port engagement review workflows`.

- [ ] 30. Prove native operator journey across every surface
  Scope: native E2E harness/ledger; actual CLI + API + worker + browser journey from synthetic intake through exports and owned cleanup. Cross-surface consistency is asserted from independent fixture expectations.
  References: `tests/integration/test_canonical_release_e2e.py`, `forge/demo.py`, `END_GOAL.md`, all native receipt/contract ledgers.
  Dependencies: wave 5; 25-29. Acceptance: same findings/provenance/reportability across API/UI/graph/report/raw/audit, reports survive provider failure, deny paths have no side effects, test artifact teardown recorded.
  QA: `verify operator-e2e`; happy full journey including restart/resume; failure provider loss plus interrupted worker still yields truthful partial/fallback output and no leaked test resources.
  Commit: Y | `test(e2e): prove full native operator journey`.

- [ ] 31. Package reproducible Python-free native distributions
  Scope: `native/` release profiles/artifacts, packaging scripts and native Docker targets; Windows exe, Linux native container/binary and macOS-supported paths, bundled UI assets/licenses/SBOM. No dev-only interpreter or node_modules in runtime.
  References: `docker/Dockerfile`, `setup.bat`, `setup.sh`, `bootstrap.py`, existing launchers, `THIRD_PARTY_LICENSES.md`, native toolchain/lock.
  Dependencies: wave 6; 30. Acceptance: clean build installs and runs from minimal environment without Python/Node; declared optional tools remain external; Windows-specific actions are accurately gated elsewhere.
  QA: `verify packaging`; happy release install/version/demo in clean runtime; failure missing optional tool yields catalog unavailable while core demo/report still succeeds, missing mandatory asset fails startup.
  Commit: Y | `build(native): package Python-free distributions`.

- [ ] 32. Replace service deployment and startup supervision
  Scope: native production/dev Compose, Windows scheduled/startup scripts, POSIX/systemd/Helm/reverse-proxy templates in inventory. Keep established ports, secrets by reference, persistent volumes, least privilege and bounded memory.
  References: `docker/`, `scripts/install_guarded_autostart_task.ps1`, `scripts/run_guarded_autostart_task.ps1`, `tools/forge-stack.ps1`, runtime ledger.
  Dependencies: wave 6; 31. Acceptance: preflight succeeds, services start in correct dependency order, API/web health + worker heartbeat truthful, restart recovers; migration smoke runs only synthetic queued work.
  QA: `verify deployment`; happy `docker compose -f docker/docker-compose.yml up -d --wait --wait-timeout 180` in isolated project with generated test env; failure Redis stopped makes health unavailable then recovers without duplicate work.
  Commit: Y | `build(deploy): switch services to native runtime`.

- [ ] 33. Complete cross-platform tests, mutation, chaos and soak lanes
  Scope: native test/CI matrix, all replacement test IDs and legacy disposition receipts. Run supported Windows/Linux/macOS and browser target builds; required fixture services provisioned explicitly. No `allow-failure` hides required gates.
  References: `.github/workflows/`, `tests/chaos/`, `tests/properties/`, `tests/performance/`, `tools/evidence*`, `.kiro/specs/autonomous-security-platform/tasks.md:494-496`, native test ledger.
  Dependencies: wave 6; 31,32. Acceptance: every required replacement case passes against release artifact/image digests produced by 31 and deployed by 32; missing feature/tool/platform has an explicit supported-contract disposition. Run targeted mutation against domain/policy (survivors explained/fixed), deterministic fault injection and 24h synthetic soak; measure memory/queue growth against declared budgets. Runtime/bundled-asset/dependency changes later invalidate affected receipts; rerun the full release matrix and soak if the tested runtime artifact changes.
  QA: `verify release-suites`; happy all lane receipts reconcile totals including 24h soak; failure deliberately mutate authorization or kill Redis and relevant test fails/recovery proves bounded operation. Never claim 24h from a shorter run.
  Commit: Y | `test(release): enforce full native verification matrix`.

- [ ] 34. Rehearse copy-based data cutover and rollback
  Scope: native migration/export/import/checkpoint tooling and fixtures. Fence new writes and drain workers/queues before taking coordinated SQLite/Postgres/audit checkpoints and queue watermarks; retain old binary/data copy. During cutover use maintenance mode until pre-write verification succeeds. After enabling native writes, record durable replayable mutation/outbox receipts so rollback can preserve every acknowledged post-cutover write and audit event. Never restore a pre-cutover snapshot over newly acknowledged evidence.
  References: `forge/db/`, `forge/workflow/`, `forge/audit/`, native storage/cutover contracts, deployment receipts.
  Dependencies: wave 6; 31-33. Acceptance: fixture counts, ownership, encrypted readability and historical audit verification survive. Rollback either reopens a proven backward-compatible latest snapshot or replays all acknowledged native changes into a compatible checkpoint with original IDs/order/audit hashes; duplicate queue deliveries remain deduplicated. If lossless replay is unsupported, rollback is blocked and the latest data is retained under write fencing, never discarded.
  QA: `verify cutover`; happy staged fixture cutover/reopen yields identical public evidence; failure injected migration/checksum error prevents activation. A second failure scenario writes new evidence after activation, interrupts service, then rolls back and proves every acknowledged row/audit event and queued work survives exactly once.
  Commit: Y | `feat(migration): add rehearsed native cutover`.

- [ ] 35. Retire legacy first-party runtime and reconcile all migration work
  Scope: packaging/entrypoints, capability/test/session ledgers and tracked continuation docs. Remove Python/React runtime from distribution; retain historical source in Git and migration-only fixtures until explicit cleanup approval. Update root SPEC through its designated spec workflow if contracts need clarification, not silent edits.
  References: native ledgers, `README.md`, `DAILY_USE.md`, `END_GOAL.md`, `SPEC.md`, `.agents/`, `.claude/`, `.kiro/`, `.omo/`.
  Dependencies: wave 6; 34. Acceptance: every supported capability and test case verified or evidenced superseded, zero active unowned/pending/blocked migration items; source/session history is preserved. Explicitly reconcile every legacy subsystem capability listed in Scope against native task 11/16/25 evidence: directory-level retirement, empty success stubs and unapproved feature removal fail the gate. All launchers reach native binaries, no Python subprocess fallback or first-party plugin loophole. Rebuild final release artifacts and compare hashes with task 33; changed runtime/assets/dependencies require rerunning task 33 against final artifacts before task 36, while docs-only changes retain receipts by identical artifact hash.
  QA: `verify retirement`; happy clean artifact works without interpreters and ledgers close; failure introduce a Python fallback/unmapped active TODO and gate rejects release.
  Commit: Y | `refactor(runtime): retire legacy deployment paths`.

- [ ] 36. Validate installed system and restore paused workloads
  Scope: operator startup validation, final resource receipt and exact paused-set restoration. Verify API 8000/web 8080, backing dependencies, worker heartbeat and synthetic job/report path on the actual target install. Restore only the recorded TPH set; no scans are initiated by QA.
  References: approved draft stopped-set record, `docker/docker-compose.yml`, native deployment/evidence receipts, `.agents/STATE.md`.
  Dependencies: wave 6; 35. Acceptance: installed native Forge reports correct revision, all service health checks pass after normal restart, owned QA artifacts/processes are gone and paused-set restoration has a receipt.
  QA: `verify installed`; happy `curl.exe --fail http://127.0.0.1:8000/health` and `curl.exe --fail http://127.0.0.1:8080/health` plus authenticated synthetic job and worker heartbeat; failure dependency disconnect produces unavailable status then recovers. Restore with `docker start theprawnhunter_redis theprawnhunter_api theprawnhunter_worker-core theprawnhunter_worker-scanners theprawnhunter_worker-scrape theprawnhunter_worker-validators theprawnhunter_beat theprawnhunter_bot theprawnhunter_flower theprawnhunter_frontend`, then inspect their health. If resource budget prevents coexistence, report blocked rather than silently leaving them stopped.
  Commit: Y | `docs(release): record native runtime acceptance`.

## Final verification wave
> Runs in parallel after ALL todos. ALL must APPROVE. Surface results and wait for the user's explicit okay before declaring complete.
- [ ] F1. Plan compliance audit
  Read-only reviewer: compare tasks 1-36, stable capability/session IDs and receipt revision hashes to live tree. Command: `cargo run --locked --manifest-path native/Cargo.toml -p forge-xtask -- verify plan-compliance --evidence .omo/evidence/rust-rewrite/final-F1`. Pass only with no unverified required entry; missing receipt is failure. Return exact revision/verdict/citations.
- [ ] F2. Code quality review
  Independent read-only reviewer: native workspace architecture, parser limits, cancellation, audit/auth/storage compatibility and all warning/type/test gates. Re-run fmt/clippy/workspace tests on final revision. Audit dependency/runtime composition. Pass only with no requirement-blocking issue; attach `.omo/evidence/rust-rewrite/final-F2` receipts.
- [ ] F3. Real manual QA
  Separate QA agent: run installed CLI/API/worker/browser journey at desktop/mobile, failover and rollback checks using synthetic fixtures; reproduce real health and native process evidence. Screenshots, HTTP/action logs and teardown receipts at `.omo/evidence/rust-rewrite/final-F3`. No mock-only or screenshot-only pass.
- [ ] F4. Scope fidelity
  Independent read-only reviewer: verify whole requested first-party Rust scope, external-tool boundary, no lost supported features/tests, no unrequested offensive expansion, no erased user/session work. Check absence of Python/React application runtime from release and preserved data/history. Attach exact artifact/revision hashes and verdict at `.omo/evidence/rust-rewrite/final-F4`.

## Commit strategy

- User explicitly requested commits and push to `main`. First publish this reviewed planning checkpoint. During execution commit each verified atomic task/subtask with implementation and direct tests together. Larger tasks may have several independently verified commits; no monolithic rewrite commit.
- Match recent English Conventional Commits (`feat(...)`, `test(...)`, `fix(...)`, `docs(...)`). Before each commit inspect status, intended diff and recent touched-path history. Stage explicit paths; no secrets, ignored databases, raw customer logs or unrelated changes. Plans under ignored `.omo/` need explicit file-only staging; never force-add the entire directory.
- One integrator owns `main`; coding subagents work on disjoint files/task branches and do not push. Fetch/inspect upstream before push; if main moved, stop integration, reconcile normally and retest affected scope. Never force push, reset unrelated work, skip hooks, or claim local work is published until remote SHA is checked.
- Persist short truthful `.agents/STATE.md` and append `.agents/JOURNAL.md` decisions. Keep task statuses/evidence in this plan and native ledgers. A task is not checked merely because its commit exists.

## Success criteria

1. All 36 tasks and F1-F4 have evidence-backed completion on the final native revision; the six component outcomes from the approved draft hold.
2. Every discovered capability/test/session entry is reconciled with executable proof or evidenced supersession. Required tests and functionality cannot be waived by a default exclusion, absent service or crashed collector.
3. The complete supported engagement journey and operator review surfaces work using native Rust runtime without Python/React application logic; optional external tools are explicit dependencies, never core fallbacks.
4. Existing data, cryptographic envelopes, IDs, audit evidence and authorization/reportability boundaries remain compatible. Cutover and rollback are exercised on representative synthetic copies.
5. Windows/Linux/macOS-supported paths and browser targets build; full test/chaos/mutation/24h-soak receipts exist and resource behavior stays within recorded budgets.
6. Installed API/web/worker and backing services are healthy, actual synthetic work completes, TPH paused set restored, and all temporary QA resources accounted for.
7. Intended verified commits are pushed to origin/main with matching SHA. No statement of flawless operation replaces measurable evidence; open failures block the full-rewrite completion claim.
