# Report Route Unknown Workflow 404

Date: 2026-07-24
Project: `C:\Users\bryan\OneDrive\01 TOOLKITS\forgetoolkit`
Branch: `main`

## Current State

FORGE remains locked to `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`: one authorized,
deterministic ASM pipeline from scoped multi-seed intake through bounded
recursive discovery, static artifact analysis, non-destructive validation,
rule-engine scoring, dashboard/report/graph/audit review, and guaranteed
template/raw fallback.

This checkpoint closes a legacy report API determinism gap:
`GET /reports/{workflow_id}` had a dead `status_data is None` 404 branch, but
the real workflow engine raises `KeyError` for unknown workflow IDs.

## Changes Made

- Updated `forge/api/routes/reports.py` so `get_report()` catches `KeyError`
  from `engine.get_status()` and returns `404` with
  `workflow_not_found:{workflow_id}` before loading report state.
- Added
  `tests/integration/test_mvp_workflow.py::TestApiReportRoute::test_report_route_missing_workflow_returns_404`.

## Verification

- `python -m py_compile forge\api\routes\reports.py tests\integration\test_mvp_workflow.py`
- `python -m ruff check forge\api\routes\reports.py tests\integration\test_mvp_workflow.py`
- `python -m pytest tests\integration\test_mvp_workflow.py::TestApiReportRoute::test_report_route_missing_workflow_returns_404 -q --color=no`
- `python -m pytest tests\integration\test_mvp_workflow.py::TestApiReportRoute -q --color=no`

Results: compile passed; Ruff passed; focused missing-report workflow test
passed (`1 passed`); full report-route class passed (`3 passed`). Workspace
`.forge_data/engagements` contained `0` entries after the run.

## Important Context

No report lineage, rendering, fallback ordering, workflow state-store,
kill-chain, live execution, validation gate, severity rule, scope gate,
dashboard, or graph behavior changed. This is route-layer deterministic error
handling only.

## Immediate Next Step

Audit one current-code deterministic kill-chain, passive-recursion, validation,
report/export, or dashboard/API review gap not already covered by the report
route 404, workflow status 404, Playwright screenshot scope, workflow history
bounds, crawler redirect scope, artifact inventory, or workflow lineage
checkpoints. Prefer compact helpers and focused tests over growing large files.
Keep live calls mocked unless an explicit ROE/scope manifest and target are
supplied.
