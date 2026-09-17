# Current Task: Complete Rust rewrite — bounded Vitest input-drift guard published (48 verified, 0 partial)

**Status:** IN PROGRESS; native workspace integrated | Latest code checkpoint pushed: `11c6014` (drift guard) | Date: 2026-09-17

## Current worker progress

- Windows build constraint (2026-09-17): user reported resolved Defender detections in the `uv` cache. Read-only Defender history identified Impacket-related credential/relay/remote-execution scripts; this is not evidence that `uv` itself was detected. Antivirus and real-time protection were enabled when checked. New migration helpers must be Rust, with PowerShell for host administration; no new Python helpers, cache refreshes or bulk offensive-extra installs. Preserve existing adapters as legacy until safely replaced; do not bypass Defender or promise detection-free files. See `AGENTS.md` for the durable build rules.
- Parallel coordination (2026-09-17): three bounded read-only category workers were launched for T2 adapters, dependencies, and domain-proof claims. The explore-model routing attempt failed (nonexistent model name); the three workers subsequently completed successfully and produced output. Their completion claims remain subject to independent evidence review before being treated as accepted proof — distinguish worker-published counts from parent-verified baselines.
- **2026-09-17 graph coercion fix** (`7491cb6`): Replaced plain `bool`/`i64`/`f64` in all four graph `*Input` structs (`AttackNodeInput`, `AttackEdgeInput`, `AttackGraphInput`, `AttackGraphReportContextInput`) with `JsonBool`/`JsonInt`/`JsonFloat` wrappers from `json_boundary.rs`. Added `zero_int()` and `zero_float()` default helpers. RED test (`graph_coercion_mismatch`) was EXIT 101 with 20 mismatches; now EXIT 0. Fixture: `graph-coercion-cases.json` 31 cases (20 mismatch + 11 control). Evidence: `.omo/evidence/rust-rewrite/task-3/remaining-contracts/graph-parity/evidence.json` → `SCOPED_COERCION_FIXED`.
- ~~**2026-09-17 graph parity consumers** (`489c92b`): Added 41 parity tests across `graph_node_edge_parity.rs` (11), `graph_full_parity.rs` (13), `graph_report_parity.rs` (17). All GREEN. Ledger advanced 42→46 `implemented_fixture_verified` for AttackNode/Edge/Graph/AttackGraphReportContext.~~ **[SUPERSEDED BY 2026-09-17 AUDIT]** Tests and code are preserved; ledger advance was unsupported — structural fixture is hand-authored, not source-captured. Four graph contracts remain `existing_partial`.
- ~~**2026-09-17 BreachRecord+TaskState coverage** (`59fc1b1`): Ledger advanced 46→48; all 6 previously `existing_partial` contracts are now `implemented_fixture_verified`. 0 `existing_partial` remaining.~~ **[SUPERSEDED BY 2026-09-17 AUDIT]** BreachRecord advance is valid and retained. TaskState advance was unsupported — plain Python class, no boundary characterization. Corrected ledger: 43 `implemented_fixture_verified`, 5 `existing_partial`. See line 11 for accepted counts.
- **T3 domain ledger** (`native/migration/domain-contracts.json` — corrected `95e8cbe`, graph proof `81a1b56`, TaskState proof `cc3b273`): 118 entries. 48 `implemented_fixture_verified` (24 DTOs + 2 agent contracts + 16 enum sections + 1 BreachRecord + 4 graph types + 1 TaskState); 0 `existing_partial`; 66 `reference_only`; 3 `blocked_policy_conflict` (`DehashedResult.password`, `HashCredential.hash_plaintext`, `KeyScannerFinding.key_prefix`); 1 `blocked_dependency` (`HashCredentialSet`). 48+0+66+3+1=118. Note: prior 48-verified claim in `59fc1b1` was premature (reverted `95e8cbe`); this count is genuinely supported. 3 serialization policy conflicts + HashCredentialSet remain blocked; 66 reference entries route by owner. complete_t3=false.
- **Published commits this session** (all pushed to origin/main): `7491cb6` (graph coercion fix), `489c92b` (graph parity consumers + ledger), `59fc1b1` (BreachRecord/TaskState coverage + ledger), `aca24ce` (bounded Vitest adapter), `95e8cbe` (ledger correction — 5 reverted), `408b4c8` (Vitest collect-mode), `81a1b56` (graph source-parity proof + 4 ledger advances), `dc0c065` (Vitest tool-identity hashing), `cc3b273` (TaskState source proof + ledger advance to 48), `11c6014` (bounded Vitest input-drift guard).
- LSP timed out; not clean-claimed. Parent ran `cargo test --workspace --locked --offline --jobs 1 -- --test-threads=1`: **253 tests pass** (129 domain + 124 xtask), 0 failures/ignores. fmt and clippy -D warnings clean. Evidence: `.omo/evidence/rust-rewrite/task-3/remaining-contracts/fixture-canonicalization/parent-input-drift-{fmt,clippy,workspace}.json`; mutex released.
- **Working tree after publication:** 8 LF-normalization fixture drift files remain unstaged (`native/crates/forge-domain/tests/fixtures/{python-cases,reference-agent,reference-cases,reference-seeds,review-fixes,timezone-offsets,unaffected-agents,unaffected-extra}.json`) — CRLF/LF line-ending drift only, no content change; do not stage. T2: input-drift guard now snapshots frontend source/config/setup/tests + package/lock before and after each Vitest attempt; drift detected → lane.complete=false with prior reason preserved; source coverage is bounded known frontend extensions/manifests + 3 tool identities, NOT universal dependency closure; cross-mode reconciliation DEFERRED; lane.complete remains false. T3: 0 existing_partial; 3 serialization policy conflicts + HashCredentialSet remain blocked; 66 reference entries route by owner.

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

- Updated: 2026-09-17 20:20:34 +08:00
- Machine: PRAWN-E14
- Harness: claude
- Event: stop
- Branch: main
- HEAD: 49edc12
- Dirty files: 8
- Resume hint: Read .agents/STATE.md, then the latest file in .agents/handoffs/ if present.
<!-- MOLT_AUTO_END -->
