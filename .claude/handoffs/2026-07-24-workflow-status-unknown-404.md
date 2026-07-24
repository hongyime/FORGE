# Workflow Status Unknown-ID 404

Date: 2026-07-24
Project: `C:\Users\bryan\OneDrive\01 TOOLKITS\forgetoolkit`
Branch: `main`

## Current State

FORGE remains locked to `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`: one authorized,
deterministic ASM pipeline from scoped multi-seed intake through bounded
recursive discovery, static artifact analysis, non-destructive validation,
rule-engine scoring, dashboard/report/graph/audit review, and guaranteed
template/raw fallback.

This checkpoint closes an API determinism gap: `GET /workflows/{workflow_id}/status`
had a `result is None` 404 branch, but the real workflow engine raises
`KeyError` for unknown workflow IDs.

## Changes Made

- Updated `forge/api/routes/workflows.py` so `get_workflow_status()` catches
  `KeyError` from `engine.get_status()` and returns `404` with
  `workflow_not_found:{workflow_id}`.
- Added
  `tests/integration/test_history_routes.py::test_status_unknown_workflow_returns_404`.

## Verification

- `python -m py_compile forge\api\routes\workflows.py tests\integration\test_history_routes.py`
- `python -m ruff check forge\api\routes\workflows.py tests\integration\test_history_routes.py`
- `python -m pytest tests\integration\test_history_routes.py::test_status_unknown_workflow_returns_404 -q --color=no`
- `python -m pytest tests\integration\test_history_routes.py -q --color=no`

Results: compile passed; Ruff passed; focused unknown-status test passed (`1
passed`); full history/status route suite passed (`10 passed`). Workspace
`.forge_data/engagements` contained `0` entries after the run.

## Important Context

No workflow state-store, history, replay, kill-chain, live execution, report,
validation gate, severity rule, scope gate, dashboard, or graph behavior
changed. This is route-layer deterministic error handling only.

## Immediate Next Step

Audit one current-code deterministic kill-chain, passive-recursion, validation,
report/export, or dashboard/API review gap not already covered by the workflow
status 404, Playwright screenshot scope, workflow history bounds, crawler
redirect scope, artifact inventory, or workflow lineage checkpoints. Prefer
compact helpers and focused tests over growing large files. Keep live calls
mocked unless an explicit ROE/scope manifest and target are supplied.
