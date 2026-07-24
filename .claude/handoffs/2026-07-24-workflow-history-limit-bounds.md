# Workflow History Limit Bounds

Date: 2026-07-24
Project: `C:\Users\bryan\OneDrive\01 TOOLKITS\forgetoolkit`
Branch: `main`

## Current State

FORGE remains locked to `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`: one authorized,
deterministic ASM pipeline from scoped multi-seed intake through bounded
recursive discovery, static artifact analysis, non-destructive validation,
rule-engine scoring, dashboard/report/graph/audit review, and guaranteed
template/raw fallback.

This checkpoint closes an API bounds gap: `GET /workflows/{workflow_id}/history`
accepted `limit=0` and negative limits, then the state store treated those as
unbounded history queries.

## Changes Made

- Updated `forge/api/routes/workflows.py` so `limit` uses FastAPI
  `Query(default=None, ge=1)`.
- Added
  `tests/integration/test_history_routes.py::test_history_rejects_non_positive_limit`
  for `limit=0` and `limit=-1`.

## Verification

- `python -m py_compile forge\api\routes\workflows.py tests\integration\test_history_routes.py`
- `python -m ruff check forge\api\routes\workflows.py tests\integration\test_history_routes.py`
- `python -m pytest tests\integration\test_history_routes.py::test_history_rejects_non_positive_limit -q --color=no`
- `python -m pytest tests\integration\test_history_routes.py -q --color=no`

Results: compile passed; Ruff passed; focused non-positive limit test passed
(`2 passed`); full history route suite passed (`9 passed`). Workspace
`.forge_data/engagements` contained `0` entries after the run.

## Important Context

No kill-chain, live execution, report generation, validation gate, severity
rule, scope gate, dashboard, or workflow state-store behavior changed. This is
route-layer input validation only.

## Immediate Next Step

Audit one current-code deterministic kill-chain, passive-recursion, validation,
report/export, or dashboard/API review gap not already covered by the workflow
history bounds, crawler redirect scope, artifact inventory, or workflow lineage
checkpoints. Prefer compact helpers and focused tests over growing large files.
Keep live calls mocked unless an explicit ROE/scope manifest and target are
supplied.
