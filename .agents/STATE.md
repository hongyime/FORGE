# Current Task: Complete Rust rewrite — native inventory code published; T1 cleanup blocked

**Status:** BLOCKED at T1 closure | Native checkpoint: `5b7b82e` | Date: 2026-09-16

## Active approved migration (do not discard)

- User approved all steps of the complete first-party Rust rewrite, subagents, and atomic commits/pushes to main. Authoritative execution plan: `.omo/plans/forge-full-rust-rewrite.md` (36 tasks + F1-F4); approved plan/draft/visual commits `cede061`, `5fa2142`, `35cad10` are published. Visual overview: https://1cxewab3ciln.postplan.dev .
- `native/` is deliberate NEW SOURCE for the rewrite, not disposable build output. Source/manifests/tests were committed and pushed in `5b7b82e`; remote SHA matched. Only `native/target/` is build/cache output. Five generated `native/migration/*.json` ledgers remain local/untracked; regenerate/reconcile against the current revision before relying on their snapshot counts.
- Stable-ID/owner regression was reproduced independently, fixed with six new failing-first regressions, and reverified independently. **28/28 native tests**, fmt, Clippy, fixture CLI verification and ID/owner/rescan checks pass. Final code verdict: **confirmed** in `.omo/evidence/rust-rewrite/task-1/adversarial-verify-final.json`; full T1 verdict still incomplete. Three config files received trailing-blank-line-only cleanup after review; no behavior changed.
- Automatic approval denied fixture cleanup for `native/target/reviewer-t1` and `native/target/t1-id-cli-20260916-01`; both remain as tracked owned QA data. No denied deletion was retried or bypassed. Ask for explicit permission for those exact paths before retrying.
- LSP diagnostics were unavailable: the parent daemon timed out twice; compiler/Clippy success is recorded separately. All owned Codex worker/verification wrapper PIDs were absent in the final process check; review team was shut down and deleted.
- T1 remains unchecked; T2-T36 and F1-F4 are not complete. Do not label this checkpoint a full Rust rewrite or all-test-suite completion. Existing T1 stable-ID requirement already covered the confirmed bug; regression tests now enforce it without a new normative ASM invariant.
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

- Updated: 2026-09-16 03:05:27 +08:00
- Machine: PRAWN-E14
- Harness: codex
- Event: session-start
- Branch: main
- HEAD: 35cad10
- Dirty files: 1
- Resume hint: Read .agents/STATE.md, then the latest file in .agents/handoffs/ if present.
<!-- MOLT_AUTO_END -->
