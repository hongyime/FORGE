# Phase 6 Artifact Inventory Export Parity

Date: 2026-07-24
Project: `C:\Users\bryan\OneDrive\01 TOOLKITS\forgetoolkit`
Branch: `main`

## Current State

FORGE remains locked to `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`: one authorized,
deterministic ASM pipeline from scoped multi-seed intake through bounded
recursive discovery, static artifact analysis, non-destructive validation,
rule-engine scoring, dashboard/report/graph/audit review, and guaranteed
template/raw fallback.

This checkpoint closes a Phase 6 review/export gap: parsed `artifact_queue`
inventory was visible in dashboard JSON but not in deterministic Phase 6 report
context or raw CSV exports.

## Changes Made

- Added `forge/phase6/artifact_inventory.py`, a compact helper that loads
  `artifact_queue` rows and scrubs metadata before report/export use.
- Added `artifact_inventory` to `ReportContext`; companion JSON exports include
  it automatically through `asdict(ctx)`.
- Added raw CSV `record_type=artifact` rows with source URL, type, status,
  hash, notes, parser/format/count metadata, and timestamps.
- Added `tests/phase6/test_report_artifact_inventory_export.py` to prove local
  paths and secret-bearing metadata are omitted from JSON/CSV exports.

## Verification

- `python -m py_compile forge\phase6\artifact_inventory.py forge\phase6\report_synthesizer.py tests\phase6\test_report_artifact_inventory_export.py`
- `python -m ruff check forge\phase6\artifact_inventory.py forge\phase6\report_synthesizer.py tests\phase6\test_report_artifact_inventory_export.py`
- `python -m pytest tests\phase6\test_report_artifact_inventory_export.py -q --color=no`
- `python -m pytest tests\phase6\test_report_artifact_inventory_export.py tests\phase6\test_report_synthesizer.py -k "artifact_inventory or artifact_seed_relations or archive_url_provenance" -q --color=no`

Results: compile passed; Ruff passed; focused artifact test passed (`1
passed`); adjacent artifact provenance selector passed (`3 passed, 102
deselected`).

## Important Context

No live execution, cloud validation behavior, rule-engine severity behavior,
LLM provider behavior, retry/proxy behavior, or scope-gate behavior changed.
This is review/export parity only.

The helper intentionally omits `local_path` and drops secret-bearing metadata
keys such as `token`, `client_secret`, `key`, `password`, and local path fields.
String values are passed through the existing validation-summary redactor.

## Immediate Next Step

Fix the workflow report API lineage gap found by the report/API sidecar:
`/reports/{workflow_id}` reads top-level `report_lineage` but can miss Phase 6
lineage nested under `intermediate_results["report"]["report_lineage"]`.
Suggested focused test:
`tests/integration/test_mvp_workflow.py::TestApiReportRoute::test_report_route_surfaces_nested_phase6_report_lineage`.
