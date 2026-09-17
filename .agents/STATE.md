# Current Task: Complete Rust rewrite — T3 graph-coercion fix + all domain contracts verified

**Status:** IN PROGRESS; native workspace integrated | Latest pushed: `59fc1b1` | Date: 2026-09-17

## Current worker progress

- **2026-09-17 graph coercion fix** (`7491cb6`): Replaced plain `bool`/`i64`/`f64` in all four graph `*Input` structs (`AttackNodeInput`, `AttackEdgeInput`, `AttackGraphInput`, `AttackGraphReportContextInput`) with `JsonBool`/`JsonInt`/`JsonFloat` wrappers from `json_boundary.rs`. Added `zero_int()` and `zero_float()` default helpers. RED test (`graph_coercion_mismatch`) was EXIT 101 with 20 mismatches; now EXIT 0. Fixture: `graph-coercion-cases.json` 31 cases (20 mismatch + 11 control). Evidence: `.omo/evidence/rust-rewrite/task-3/remaining-contracts/graph-parity/evidence.json` → `SCOPED_COERCION_FIXED`.
- **2026-09-17 graph parity consumers** (`489c92b`): Added 41 parity tests across `graph_node_edge_parity.rs` (11), `graph_full_parity.rs` (13), `graph_report_parity.rs` (17). All GREEN. Ledger advanced 42→46 `implemented_fixture_verified` for AttackNode/Edge/Graph/AttackGraphReportContext.
- **2026-09-17 BreachRecord+TaskState coverage** (`59fc1b1`): Added `breach_record_rejects_extra_fields_and_unknown_confidence` to `corrective_consumer.rs` (8 tests total). Ledger advanced 46→48; all 6 previously `existing_partial` contracts are now `implemented_fixture_verified`. 0 `existing_partial` remaining.
- **T3 domain ledger** (`native/migration/domain-contracts.json` — committed `489c92b`/`59fc1b1`): 118 entries. 48 `implemented_fixture_verified` (24 DTOs + 2 agent contracts + 16 enum sections/15 Rust types + 6 domain records now cleared); 0 `existing_partial`; 66 `reference_only`; 3 `blocked_policy_conflict` (`DehashedResult.password`, `HashCredential.hash_plaintext`, `KeyScannerFinding.key_prefix`); 1 `blocked_dependency` (`HashCredentialSet`). Full type/table parity remains open.
- **Published commits this session** (all pushed to origin/main): `7491cb6` (graph coercion fix), `489c92b` (graph parity consumers + ledger), `59fc1b1` (BreachRecord/TaskState coverage + ledger).
- LSP timed out again; not clean-claimed. Compiler, Clippy (warnings denied), and fmt pass verified for all three commits under `Local\FORGE_RUST_REWRITE_QA` mutex.
- **Dirty working tree (unchanged from prior session):** 8 LF-normalization fixture drift files (unstaged M entries); these are not blocking and not related to the session's work.

- T2 corrective increment independently confirmed: 48 native tests, fmt/Clippy, repeated-failure retention and deadline checks pass (`task-2/adversarial-verify-final.json`). Full baseline (live/provider/operator-state lanes) remains incomplete.
- Root workspace integration verified and pushed in `91e79bb`: 48 xtask + 20 domain consumers + 2 doctests. Evidence: `.omo/evidence/rust-rewrite/workspace-integration/done-claim.json`. Do not redo integration.
- Denied cleanup: `native/target/reviewer-t1` and `native/target/t1-id-cli-20260916-01` — no retry without explicit authorization. Missing baseline adapters and scoped live prerequisites remain open.
- Existing Python deployment health checks (API 8000, web 8080) were historical; no new deployment or live assessment this session.
- **Next action:** Full T3 completion still requires full type/table parity (66 `reference_only` contracts), missing baseline adapters (T2), and plan tasks T4–T36 + F1–F4. No T3 completion claim; domain-contract partial-record axis is now cleared.
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

- Updated: 2026-09-17 (post-graph-coercion-and-domain-record-clearance)
- Machine: PRAWN-E14
- Harness: opencode
- Event: stop
- Branch: main
- HEAD: 59fc1b1
- Dirty files: 8 LF-payload M entries (same as prior session; unchanged)
- Resume hint: Read .agents/STATE.md. All 6 previously existing_partial T3 domain contracts are now implemented_fixture_verified. Next: T2 missing baseline adapters or T4+ plan tasks.
<!-- MOLT_AUTO_END -->
