# Current Task: Rust rewrite — decisions resolved; finish domain and native test infrastructure

**Status:** IN PROGRESS — finish T3 verification entrypoint | Latest native code checkpoint: `5828331` (272 tests/doctests passed) | Date: 2026-09-18

## Progress dashboard

These are different measurements, not an estimated overall completion percentage.

```text
Major milestones fully closed  [....................]   0 / 36
Milestones with delivered work [~~..................]   3 / 36 (T1-T3, partial)
Contract inventory verified    [#########...........]  52 / 118 (44%, all owners)
Latest native test run         [####################] 272 / 272 passed
Final release reviews         [....]                    0 / 4
```

| Phase | Tasks | Current state |
| --- | --- | --- |
| Foundations, tests, domain, config, gates | T1-T6 | T1-T3 partial; T4-T6 queued |
| Storage, audit, buses, plugins, runtime | T7-T12 | Not started |
| Discovery, enrichment, parsing, validation, scoring | T13-T18 | Not started |
| Graphs, reports, monitoring, remediation, automation | T19-T24 | Not started |
| Native CLI, APIs and Rust UI | T25-T30 | Not started |
| Packaging, deployment, release QA and cutover | T31-T36 | Not started |

### Current verified increment
- Code checkpoint `5828331` implements `DehashedResult`, `KeyScannerFinding`, `HashCredential` and `HashCredentialSet`. Replayed 94 preserved Pydantic source cases and 12 new dataclass source cases; seven new native tests pass. One full workspace run passed 272 tests/doctests, zero failed/ignored; fmt and Clippy passed. Evidence: `.omo/evidence/rust-rewrite/task-3/remaining-contracts/approved-contracts-checkpoint.json`. Inline review fallback only; no independent review claimed. All 52 T3-owned entries now have scoped fixture verification; 66 entries belong to later runtime/storage tasks. T3 is not yet closed: the required `verify domain` command is still missing.
- Dataclass scalar JSON values deliberately remain uncoerced. Set collections materialize the declared lists of credential objects; arbitrary non-list Python objects are outside this tested collection boundary. No lookup, cracking, network or persistence was added.

### Decisions received — do not ask again
- Original plaintext serialization is preserved for `DehashedResult.password`, `HashCredential.hash_plaintext` and short `KeyScannerFinding.key_prefix`. The source's existing `key_value: SecretStr` behavior is retained; no blanket redaction change was made.
- Narrow reviewed Win32 FFI is approved for native process containment, behind a safe API. Keep the unsafe-code prohibition in other first-party crates. Purpose: stop/reap Cargo/test subprocess trees on exit, timeout or crash, without another Python helper.
- Same exact provider/model for subagents remains mandatory; work directly if the interface cannot enforce it.

### Immediate todo
- [x] Receive and record plaintext-compatibility and narrow Win32 FFI decisions.
- [x] Restore queued plan statuses and this visible progress dashboard.
- [x] Finish the three T3 contract ports and `HashCredentialSet`, with source-parity tests.
- [x] Commit the verified four-contract increment (`5828331`).
- [ ] Add and test the required `verify domain` command, then close T3.
- [ ] Implement production native process containment: bounded stdout/stderr, deadlines, failure paths and descendant cleanup.
- [ ] Add actual Cargo test collection/execution accounting to T2.
- [ ] Run scoped review and appropriate full native verification, then publish each tested increment.
- [ ] Proceed to T4 configuration and subsequent tasks in dependency order.

Full ordered task list: `.omo/plans/forge-full-rust-rewrite.md`. Contract ledger: `native/migration/domain-contracts.json`. The earlier all-blocked sweep is superseded; 33 not-started implementation milestones and four final gates are queued, not awaiting another policy approval. T1/T2 retain their genuine external/full-acceptance blockers. Older 48-verified/policy-blocked ledger claims below are historical; current ledger is 52 verified and 66 later-owner references, with complete_t3=false pending its verifier/closure.

## Historical checkpoints (prior unanswered-policy notes are superseded above)

- **Awaiting explicit decisions:** T3 default-secret serialization and the proposed narrow Win32 FFI exception remain unanswered. Generic continuation is not approval to change either contract or weaken `unsafe_code = "forbid"`. No additional runtime implementation was started; last accepted native code remains `49cd38a` with 265 passing tests/doctests.
- **Dependency sweep:** all 36 implementation tasks and four final gates remain incomplete (`[~]`, zero `[x]`). T12-T36 and F1-F4 now name their unaccepted direct prerequisites instead of appearing immediately runnable. This does not mark the rewrite complete or waive any work. Scoped T2/T3 work is permitted only within the existing scheduling exception; policy-gated adoption remains paused. Missing live/operator prerequisites, LSP, denied cleanup and final release/restoration evidence remain open independently of the two policy choices.
- **Containment integration policy gate (2026-09-18):** `native/Cargo.toml:9-10` sets `unsafe_code = "forbid"`; xtask inherits it. The tested native Windows Job Object path needs a narrowly reviewed first-party Win32 FFI boundary. No policy exception or production adoption is approved. Keep the forbid setting intact until a verified safe dependency is selected or an explicit scoped exception is agreed. Inspected WinSafe 0.0.29 `CreateProcess` takes `STARTUPINFO`, not the extended attribute list used by the proof; this does not establish that all safe alternatives are unavailable. T10 is marked `[~]` on unaccepted T7/T8. No source, dependency or database change was made for this gate.
- **Delegation correction (2026-09-18):** user requires every subagent to use the parent session's exact provider/model. Current route: `amazon-bedrock/global.openai.gpt-6-astra`. Avoid category defaults and cross-model fallbacks; if exact routing cannot be enforced, work directly. Image tasks also require attachment delivery verification. Durable rule is in `AGENTS.md`; this records a delegation policy, not a change to global harness configuration. The process-wrap lookup failed with a provider token error; its source audit was subsequently completed directly.
- **Next T2 containment step:** process-wrap 10.0.0 std JobObject is unsuitable as a drop-in (kill-on-close disabled, no active-process-zero event check, unbounded/sequential output helpers). A direct isolated Rust 1.94.1/windows-sys 0.61.2 probe passed normal exit, explicit job termination, job-handle closure and abrupt supervisor-exit descendant cleanup. Evidence: `.omo/evidence/rust-rewrite/task-2/native-job-probe/verdict.json`; no active probe processes or runtime fixture directories remained. This is Windows-only feasibility, not production adoption, bounded-pipe/failure-injection or Miri/sanitizer proof. Next: design and test a production containment increment before Cargo collection integration. Main application suite remains 265 tests. T8/T9 are `[~]` for unaccepted prerequisite chains.
- **2026-09-18 bootstrap checkpoint (`7ca7fa0`):** unset/unknown safe-mode values default to core-only dependencies and normalize the child environment; safe setup cannot fall back to generic/full legacy requirements, including development setup. Existing bootstrap/test files only; no new Python helper or dependency installation. Parent verification: 19 pytest tests passed, Ruff passed, CLI `--help` exited 0. Does not guarantee detection-free artifacts.
- **Rust-only blocked-receipt checkpoint published (`49cd38a`):** Rust-only roots (`native/`, `rust_core/`) now emit blocked receipts with zero observed cases/attempts and no Python launcher/adapter prerequisite required; empty roots fail without invalid JSON; Python/Vitest-backed provenance retained unchanged. 4 files: `baseline.rs`, `baseline_discovery.rs`, `baseline_inputs.rs`, `tests/baseline_rust_only.rs`. Actual Rust Cargo collection/execution still pending; lanes incomplete. Not a Python-free entire runner; not full T2 or rewrite completion. Full workspace run: **265 tests/doctests** (127 domain integrations + 79 xtask units + 57 xtask integrations + 2 domain doctests), 0 failed/ignored/filtered; command: `cargo test --workspace --locked --offline --jobs 1 --no-fail-fast -- --test-threads=1 --nocapture`. fmt and Clippy -D warnings clean. Evidence: `.omo/evidence/rust-rewrite/task-3/remaining-contracts/fixture-canonicalization/parent-rust-only-workspace.{json,log}`, exit 0, mutex_released=true. Reviewer ses_f5216b9a6ffecql5TpWZbOQk8n approved.
- **T2 bounded Vitest checkpoint published (`79763cc`, `76424e4`):** Worker implemented typed file/name/location collect-before-run matching, shared deadline, ambiguity/project blockers, preserved observed counts, and bounded drift guards in 13 inseparable files (`79763cc`). Parent added diagnostic-only Attempt detail to an existing corrective assertion; no budget or assertion semantics changed (`76424e4`). One complete native workspace invocation passed **262 tests/doctests** (127 domain integrations + 79 xtask units + 54 xtask integrations + 2 domain doctests), 0 failed/ignored/filtered; command: `cargo test --workspace --locked --offline --jobs 1 --no-fail-fast -- --test-threads=1 --nocapture`. fmt and workspace Clippy clean. Evidence: `.omo/evidence/rust-rewrite/task-3/remaining-contracts/fixture-canonicalization/parent-cross-mode-workspace-observed.{json,log}`, exit 0, mutex_released=true, current-run cleanup successful. Historical full-run failures (10-minute outer timeout; `execution_attempt_preserves_prior_failure` valid-attempt assertion; collect-only FAILED before outer batch watchdog truncation, termination cause unknown) preserved as historical; `instability-diagnosis.json` has `confirmed_root_cause=false` — current complete pass bounds checkpoint risk but does not prove why prior runs failed.
- **Review:** Independent review task `bg_d7ac2fbe` was cancelled after model-routing failure/stale timeout (historical; preserved). Independent reviewer session `ses_f5216b9a6ffecql5TpWZbOQk8n` subsequently returned CODE APPROVE then PUBLICATION APPROVE for the bounded T2 increment after reading the full workspace run. LSP remains unavailable. Evidence: `.omo/evidence/rust-rewrite/task-3/remaining-contracts/fixture-canonicalization/parent-cross-mode-workspace-observed.{json,log}`. Bounded scope: single-project/unambiguous-supported-profile; source coverage bounded to known frontend extensions/manifests + 3 tool identities (NOT universal transitive closure); no full T2/T3/rewrite/LSP approval. T6 and T7 now `[~]` per actual prerequisite chain; T3 serialization policy decision unresolved; T2 other adapters/scoped lanes remain open.
- Windows build constraint (2026-09-17): user reported resolved Defender detections in the `uv` cache. Read-only Defender history identified Impacket-related credential/relay/remote-execution scripts; this is not evidence that `uv` itself was detected. Antivirus and real-time protection were enabled when checked. New migration helpers must be Rust, with PowerShell for host administration; no new Python helpers, cache refreshes or bulk offensive-extra installs. Preserve existing adapters as legacy until safely replaced; do not bypass Defender or promise detection-free files. See `AGENTS.md` for the durable build rules.
- Parallel coordination (2026-09-17): three bounded read-only category workers were launched for T2 adapters, dependencies, and domain-proof claims. The explore-model routing attempt failed (nonexistent model name); the three workers subsequently completed successfully and produced output. Their completion claims remain subject to independent evidence review before being treated as accepted proof — distinguish worker-published counts from parent-verified baselines.
- **2026-09-17 graph coercion fix** (`7491cb6`): Replaced plain `bool`/`i64`/`f64` in all four graph `*Input` structs (`AttackNodeInput`, `AttackEdgeInput`, `AttackGraphInput`, `AttackGraphReportContextInput`) with `JsonBool`/`JsonInt`/`JsonFloat` wrappers from `json_boundary.rs`. Added `zero_int()` and `zero_float()` default helpers. RED test (`graph_coercion_mismatch`) was EXIT 101 with 20 mismatches; now EXIT 0. Fixture: `graph-coercion-cases.json` 31 cases (20 mismatch + 11 control). Evidence: `.omo/evidence/rust-rewrite/task-3/remaining-contracts/graph-parity/evidence.json` → `SCOPED_COERCION_FIXED`.
- ~~**2026-09-17 graph parity consumers** (`489c92b`): Added 41 parity tests across `graph_node_edge_parity.rs` (11), `graph_full_parity.rs` (13), `graph_report_parity.rs` (17). All GREEN. Ledger advanced 42→46 `implemented_fixture_verified` for AttackNode/Edge/Graph/AttackGraphReportContext.~~ **[SUPERSEDED BY 2026-09-17 AUDIT]** Tests and code are preserved; ledger advance was unsupported — structural fixture is hand-authored, not source-captured. Four graph contracts remain `existing_partial`.
- ~~**2026-09-17 BreachRecord+TaskState coverage** (`59fc1b1`): Ledger advanced 46→48; all 6 previously `existing_partial` contracts are now `implemented_fixture_verified`. 0 `existing_partial` remaining.~~ **[SUPERSEDED BY 2026-09-17 AUDIT]** BreachRecord advance is valid and retained. TaskState advance was unsupported — plain Python class, no boundary characterization. Corrected ledger: 43 `implemented_fixture_verified`, 5 `existing_partial`. See line 11 for accepted counts.
- **T3 domain ledger** (`native/migration/domain-contracts.json` — corrected `95e8cbe`, graph proof `81a1b56`, TaskState proof `cc3b273`): 118 entries. 48 `implemented_fixture_verified` (24 DTOs + 2 agent contracts + 16 enum sections + 1 BreachRecord + 4 graph types + 1 TaskState); 0 `existing_partial`; 66 `reference_only`; 3 `blocked_policy_conflict` (`DehashedResult.password`, `HashCredential.hash_plaintext`, `KeyScannerFinding.key_prefix`); 1 `blocked_dependency` (`HashCredentialSet`). 48+0+66+3+1=118. Note: prior 48-verified claim in `59fc1b1` was premature (reverted `95e8cbe`); this count is genuinely supported. 3 serialization policy conflicts + HashCredentialSet remain blocked; 66 reference entries route by owner. complete_t3=false.
- **Published commits this session** (all pushed to origin/main): `7491cb6` (graph coercion fix), `489c92b` (graph parity consumers + ledger), `59fc1b1` (BreachRecord/TaskState coverage + ledger), `aca24ce` (bounded Vitest adapter), `95e8cbe` (ledger correction — 5 reverted), `408b4c8` (Vitest collect-mode), `81a1b56` (graph source-parity proof + 4 ledger advances), `dc0c065` (Vitest tool-identity hashing), `cc3b273` (TaskState source proof + ledger advance to 48), `11c6014` (bounded Vitest input-drift guard), `79763cc` (T2 collect-before-run reconciliation — 13 files: typed matching, shared deadline, ambiguity/project blockers, preserved observed counts, bounded drift guards), `76424e4` (diagnostic-only Attempt detail in corrective assertion; no budget/assertion change).
- LSP timed out; not clean-claimed. Full workspace run after T2 bounded checkpoint — `cargo test --workspace --locked --offline --jobs 1 --no-fail-fast -- --test-threads=1 --nocapture`: **262 tests/doctests pass** (127 domain integrations + 79 xtask units + 54 xtask integrations + 2 domain doctests), 0 failed/ignored/filtered. fmt and Clippy -D warnings clean. Evidence: `.omo/evidence/rust-rewrite/task-3/remaining-contracts/fixture-canonicalization/parent-cross-mode-workspace-observed.{json,log}`; exit 0, mutex released. Prior `parent-input-drift-{fmt,clippy,workspace}.json` (253 tests, pre-T2-checkpoint) preserved as historical.
- **Published native baseline:** 8 LF-normalization fixture drift files remain unstaged (`native/crates/forge-domain/tests/fixtures/{python-cases,reference-agent,reference-cases,reference-seeds,review-fixes,timezone-offsets,unaffected-agents,unaffected-extra}.json`) — CRLF/LF line-ending drift only, no content change; do not stage. Accepted T2 input-drift coverage is bounded known frontend extensions/manifests + 3 tool identities, NOT universal dependency closure. Supported proven frontend lane can now complete; full baseline (live/provider/operator-state lanes) and remaining T2 adapter/scoped lanes remain open. T3: 0 existing_partial; 3 serialization policy conflicts + HashCredentialSet remain blocked; 66 reference entries route by owner.

- T2 corrective increment independently confirmed: 48 native tests, fmt/Clippy, repeated-failure retention and deadline checks pass (`task-2/adversarial-verify-final.json`). Full baseline (live/provider/operator-state lanes) remains incomplete.
- Root workspace integration verified and pushed in `91e79bb`: 48 xtask + 20 domain consumers + 2 doctests. Evidence: `.omo/evidence/rust-rewrite/workspace-integration/done-claim.json`. Do not redo integration.
- Denied cleanup: `native/target/reviewer-t1` and `native/target/t1-id-cli-20260916-01` — no retry without explicit authorization. Missing baseline adapters and scoped live prerequisites remain open.
- Existing Python deployment health checks (API 8000, web 8080) were historical; no new deployment or live assessment this session.
- **Next action:** T3 serialization policy conflicts (`DehashedResult.password`, `HashCredential.hash_plaintext`, `KeyScannerFinding.key_prefix`) and `HashCredentialSet` dependency remain blocked. The 66 `reference_only` entries are not all T3 work — storage→T7, plugin/bus runtime→T10–T12; no blanket T3 blocker. T4 remains [~] (prereq: T3 acceptance). Missing baseline adapters (T2) and plan tasks T5–T36 + F1–F4 also remain open. No T3 completion claim.
## Active approved migration (do not discard)

- User approved all steps of the complete first-party Rust rewrite, subagents, and atomic commits/pushes to main. Authoritative execution plan: `.omo/plans/forge-full-rust-rewrite.md` (36 tasks + F1-F4); approved plan/draft/visual commits `cede061`, `5fa2142`, `35cad10` are published. Visual overview: https://1cxewab3ciln.postplan.dev .
- `native/` is deliberate rewrite source, not disposable build output. Initial code shipped in `5b7b82e`; domain/baseline code and five migration ledgers were committed by the parallel session in `486c344`. Regenerate/reconcile ledger snapshots before relying on counts; code and ledger completion remain different claims.
- Stable-ID/owner regression was reproduced independently, fixed with six new failing-first regressions, and reverified independently. **28/28 native tests**, fmt, Clippy, fixture CLI verification and ID/owner/rescan checks pass. Final code verdict: **confirmed** in `.omo/evidence/rust-rewrite/task-1/adversarial-verify-final.json`; full T1 verdict still incomplete. Three config files received trailing-blank-line-only cleanup after review; no behavior changed.
- Automatic approval denied fixture cleanup for `native/target/reviewer-t1` and `native/target/t1-id-cli-20260916-01`; both remain as tracked owned QA data. No denied deletion was retried or bypassed. Ask for explicit permission for those exact paths before retrying.
- LSP diagnostics were unavailable: the parent daemon timed out twice; compiler/Clippy success is recorded separately. All owned Codex worker/verification wrapper PIDs were absent in the final process check; review team was shut down and deleted.
- T1 remains unchecked; T2-T36 and F1-F4 are not complete. Do not label this checkpoint a full Rust rewrite or all-test-suite completion. Existing T1 stable-ID requirement already covered the confirmed bug; regression tests now enforce it without a new normative ASM invariant.
- Continued read-only diagnosis: LSP daemon log shows Rustup component downloads; stable toolchain has no `rust-analyzer` binary/component. No installation/config changes or denied cleanup retries performed. Plan scheduling now allows T2/T3 to consume independently accepted T1 code while its cleanup/diagnostic closure stays open; final acceptance criteria are unchanged.
- Existing task-2 baseline repair commits from the other session (`ce98f44`, `bb6d85d`, `90b0231`) are preserved; reported results below do not close full native migration or all-test accounting.
- TPH stopped-set/restoration obligation remains in plan task 36. Current runtime checked directly: API 8000 and web 8080 health endpoints returned `status: ok`; production API/web/Postgres/Redis containers healthy and worker container running. These are the existing Python-based services, not Rust cutover proof.

## Parallel baseline-repair session — reported completed and pushed (ce98f44)

| Check | Result |
|-------|--------|
| pytest collection hang (Windows) | ✅ FIXED — `forge/webui/__init__.py` lazy-loads `create_app`/`create_server`; eager import of 2600-line `app.py` was hanging collection 30-60 s |
| Frontend Vitest worker startup timeout | ✅ FIXED — `vitest.config.ts` uses `pool:forks+singleFork+environment:node`; `test-setup.ts` manually bootstraps jsdom in setup phase (no fork-startup timeout on Node 26/Windows) |
| API/web/worker services port 8080 | ✅ FIXED — `docker compose up -d` started all 5 containers; forge-webui (healthy:8080), forge-api (healthy:8000), forge-worker (running), postgres (healthy), redis (healthy) |
| `tests/webui/` | ✅ 216 passed (lazy-import fix + scope_manifest payload update) |
| `tests/phase6/` | ✅ 155 passed, 1 deselected (cloud-gate assertions + @pytest.mark.slow for LLM test) |
| `tests/phase5/` | ✅ 184 passed (pyperclip installed) |
| `tests/unit/` | ✅ 29 passed |
| `tests/connectors/` (per-file) | ✅ 102 passed |
| `tests/workflow/ + standards/` | ✅ 13 passed, 14 skipped (alembic + psycopg installed) |
| Vitest frontend suite | ✅ 44/44 passed in 14.95 s |

## Deps installed this session (not in pyproject.toml dev group yet)

| Package | Why |
|---------|-----|
| `alembic==1.20.0` | was missing — broke `tests/workflow/` collection |
| `psycopg[binary]==3.3.5` | postgres connectivity for workflow tests |
| `pyperclip==1.11.0` | phase5 clipboard collector test |
| `jsonschema==4.26.0` | `forge.plugins.schemas.validators` import |
| `botocore==1.43.94` | reinstalled (was corrupted; broke phase4 collection) |

## Fixes committed in ce98f44

- `forge/webui/__init__.py` — lazy `__getattr__` for `create_app`/`create_server`
- `forge/reporting/webui/vitest.config.ts` — `pool:forks`, `singleFork:true`, `environment:'node'`
- `forge/reporting/webui/src/test-setup.ts` — manual jsdom bootstrap + RAF/fetch/matchMedia stubs
- `tests/webui/test_run_status.py` — add `scope_manifest_required`/`scope_manifest_present` to payload contract
- `tests/phase6/test_report_cloud_exposure_gating.py` — update `validation_reportable` assertions for `742931608514` (commit `02b646d` made `aws_sts_get_caller_identity` reportable)
- `tests/phase6/test_llm_validation.py` — `@pytest.mark.slow` on integration LLM test

## Still open (operator decision needed)

- **tests/phase4/ + tests/plugins/** — ran for > 5 min without completing; likely contains slow AWS/cloud integration tests. `tests/plugins/` now collects clean after `jsonschema` install. `tests/phase4/` now collects clean after `botocore` reinstall. No failures seen — just slow.
- **tests/integration/** — SSH/SMB mock containers not running. Start with `docker compose -f docker/docker-compose.test.yml up -d --wait` to enable.
- **Deps not in pyproject.toml** — the 5 packages above were installed via `uv pip install` but are not recorded in `pyproject.toml [dev]` or `[optional-dependencies]`. Add them if they should be permanent.
- **`native/` directory** — intentional rewrite source published in `5b7b82e`; T1 closure remains blocked as described above. Do not add the source tree to `.gitignore`; preserve only the existing build-target exclusion.

<!-- MOLT_AUTO_START -->
## Auto State

- Updated: 2026-09-18 21:25:41 +08:00
- Machine: PRAWN-E14
- Harness: claude
- Event: stop
- Branch: main
- HEAD: e97a997
- Dirty files: 8
- Resume hint: Read .agents/STATE.md, then the latest file in .agents/handoffs/ if present.
<!-- MOLT_AUTO_END -->
