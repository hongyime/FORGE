# End Goal Completion Audit

Last updated: 2026-07-25

Status: not release-complete. The locked end goal is still
`FORGE-DETERMINISTIC-ASM-PIPELINE-v1`: scoped multi-seed intake, bounded
recursive discovery, static artifact enrichment, non-destructive
validation-before-reporting, deterministic scoring, graph/dashboard/report/audit
review, LLM/template/raw fallback, and cleanup.

This audit records current evidence. It does not replace `docs/end_goal.md`.

## Summary

| Gate | Status | Evidence | Gap |
|---|---|---|---|
| Intake and monotonic IDs | Proven by focused tests | `forge/db/schema.py`, `forge/webui/app.py`, `tests/integration/test_webui_engagement_api.py` | Dedicated `cloud_ref` seed classification is still absent; non-HTTP cloud refs fall to `other`. |
| ROE and scope gates | Strong | `forge/cli.py` live kill-chain gate, direct CLI gates, web launch tests, upgraded `tests/phase1/test_kill_chain_dashboard_smoke.py` | Need one API-launched all-gates E2E with ROE/scope manifest, not only split tests. |
| Recursive discovery | Strong | `forge/cli.py` convergence metadata, `EngagementSynthesisEngine`, convergence tests, multi-seed E2E fixture | Broad multi-seed E2E is long-running; use a smaller canonical release fixture. |
| Cross-reference/conflicts | Partial but implemented | `EngagementSynthesisEngine`, conflict relation tests, dashboard seed relation visibility | No one all-gates release test proves promotion, conflict visibility, and termination together. |
| Static artifact enrichment | Strong | Helm, OCI/Docker, service-worker, Terraform, SAML, public metadata, APK/config/document suites | Continue focused parser gaps only when tied to recursion or review parity. |
| Validation before reporting | Strong | `cloud_exposure_gate.py`, `validation_proof.py`, deterministic/report/dashboard/graph gates | Keep adding provider-proof regressions when new validators are added. |
| Deterministic scoring | Strong for current cloud/key paths | `deterministic_findings.py`, Phase 6/dashboard/graph reportability tests | Do not mark complete until canonical release fixture proves final reportability end to end. |
| LLM/template/raw fallback | Stronger after this checkpoint | `report_synthesizer.py`, Phase 6 fallback tests, raw-export fallback audit receipt | Need one raw-export all-surface E2E with dashboard/API/download/audit manifest parity. |
| Dashboard/graph/report/audit review | Strong by slice | `forge/reporting/dashboard.py`, React detail, graph/export tests, audit manifest tests | Need one canonical raw-export fallback run proving all review surfaces together. |
| Cleanup | Partial | cleanup isolation helpers/tests and current workspace `.forge_data/engagements` count | Cleanup/no-ID-reuse must be tied into the canonical release E2E. |

## This Checkpoint

- Upgraded the representative dashboard smoke so non-dry-run `kill_chain()`
  runs with explicit `roe_id` and inline scope manifest, validates the
  discovered Firebase/Supabase resources only when they are in scope, and
  asserts the dashboard preserves ROE/scope state without leaking raw manifest
  contents.
- Updated the multi-seed recursive fixture to include `HTML` in the current
  report-family export contract; the broad multi-seed recursive E2E passed
  after the update (`1 passed in 262.31s`).
- Added raw-export fallback audit parity: if normal report-family persistence
  fails and FORGE emits raw JSON/CSV, Phase 6 now writes a
  `report_findings_included` receipt for the raw JSON target with raw-export
  lineage, render path, format, finding count, checksum, and targets.

## Next Checkpoint

Add a compact canonical release E2E:

1. Create an engagement through the web/API path with multiple typed seeds.
2. Launch mocked `kill_chain()` with explicit ROE and scope manifest.
3. Prove recursion through at least one web pivot, identity pivot, artifact
   pivot, cloud/key validation, deterministic finding, graph export, template
   fallback, and raw-export fallback.
4. Generate dashboard and query live API detail/download surfaces.
5. Assert report history, validation inventory, graph exports, checksums,
   report inclusion audit receipt, run audit manifest status, and raw JSON/CSV
   parity.
6. Run/assert test-owned cleanup, `.forge_data/engagements` has no test DBs,
   and monotonic engagement IDs are not reused after deletion.

Only after that E2E and adjacent focused suites pass should `SPEC.md` T1 move
from open to complete.
