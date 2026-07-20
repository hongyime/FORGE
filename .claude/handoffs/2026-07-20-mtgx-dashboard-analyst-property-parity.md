# MTGX Dashboard Analyst Property Parity

Date: 2026-07-20

## Goal Gate

Review/dashboard fidelity for the deterministic authorized engagement pipeline.

## What Changed

- `forge/reporting/dashboard.py` now preserves safe non-control `forge.*`
  properties from `.mtgx` node payloads, including analyst fields such as
  `validation_detail`.
- `.mtgx` edge `forge.metadata_json` now flows into dashboard graph edge
  metadata instead of being discarded.
- Sensitive metadata keys such as `key_enc` remain scrubbed from node and edge
  dashboard payloads.
- `tests/reporting/test_dashboard.py` adds a focused `.mtgx`-only fallback
  regression proving safe analyst metadata survives and sensitive keys do not.

## Verification

- `python -m py_compile forge\reporting\dashboard.py tests\reporting\test_dashboard.py`
- `python -m ruff check forge\reporting\dashboard.py tests\reporting\test_dashboard.py`
- `python -m pytest tests\reporting\test_dashboard.py::test_generate_dashboard_parses_mtgx_into_detail_graph_payload_when_graphml_missing tests\reporting\test_dashboard.py::test_generate_dashboard_parses_graphml_into_detail_graph_payload tests\reporting\test_dashboard.py::test_generate_dashboard_prefers_graph_json_artifact_over_graphml_when_snapshot_missing -q --color=no` -> `3 passed`
- `python -m pytest tests\reporting\test_dashboard.py -k "mtgx or graphml or graph_json_artifact" -q --color=no` -> `3 passed, 14 deselected`
- Cleanup inventory unchanged: `.forge_data\engagements` contains `1`, `5010`, `master.db`

## Safety Boundary

Dashboard parser/reviewability only. No runtime scan/provider/live/proof gate,
credential use, scope relaxation, proxy/IP rotation, rate-limit bypass,
deterministic severity, report gate, or finding creation changes.

## Next Suggested Step

Continue from `docs/engagement_overhaul_tasklist.md` ->
`## Compact active backlog`: audit the next concrete release-gate gap before
editing, preferably graph/dashboard/report parity, raw export fallback, cleanup
proof, or a concrete identity-provider/passive-artifact parser gap.
