# Workflow Report Nested Phase 6 Lineage

Date: 2026-07-24
Project: `C:\Users\bryan\OneDrive\01 TOOLKITS\forgetoolkit`
Branch: `main`

## Current State

FORGE remains locked to `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`: one authorized,
deterministic ASM pipeline from scoped multi-seed intake through bounded
recursive discovery, static artifact analysis, non-destructive validation,
rule-engine scoring, dashboard/report/graph/audit review, and guaranteed
template/raw fallback.

This checkpoint closes a workflow report API reviewability gap: Phase 6 report
JSON stores lineage under `report.report_lineage`, but legacy
`GET /reports/{workflow_id}` only read top-level workflow lineage.

## Changes Made

- Updated `forge/api/routes/reports.py` so `_report_text_and_metadata()` merges
  nested `report["report_lineage"]` keys into metadata when those keys are not
  already present.
- Preserved existing override behavior: top-level `report_metadata` and
  `report_lineage` still win over nested report payload fields.
- Added
  `tests/integration/test_mvp_workflow.py::TestApiReportRoute::test_report_route_surfaces_nested_phase6_report_lineage`.

## Verification

- `python -m py_compile forge\api\routes\reports.py tests\integration\test_mvp_workflow.py`
- `python -m ruff check forge\api\routes\reports.py tests\integration\test_mvp_workflow.py`
- `python -m pytest tests\integration\test_mvp_workflow.py::TestApiReportRoute::test_report_route_surfaces_nested_phase6_report_lineage tests\integration\test_mvp_workflow.py::TestApiReportRoute::test_report_route_surfaces_raw_export_lineage -q --color=no`
- `python -m pytest tests\integration\test_mvp_workflow.py::TestApiReportRoute -q --color=no`

Results: compile passed; Ruff passed; focused nested plus raw-export route tests
passed (`2 passed`); full route class passed (`2 passed`). Workspace
`.forge_data/engagements` contained `0` entries after the run.

## Important Context

No live provider call, report rendering, fallback ordering, validation gate,
severity rule, scope gate, or kill-chain behavior changed. This is a legacy API
surface parity fix only.

## Immediate Next Step

Audit one current-code deterministic kill-chain, passive-recursion, validation,
report/export, or dashboard/API review gap not already covered by the artifact
inventory and workflow lineage checkpoints. Prefer a compact helper/test over
growing large files, and keep live calls mocked unless an explicit ROE/scope
manifest and target are supplied.
