# Artifact Review Surface Parity Handoff

Date: 2026-07-24

## Completed

- Added dashboard review parity for inventory-only cloud assets:
  `forge/reporting/dashboard.py` now emits `sections.cloud_assets`, counts
  `cloud_assets`, and includes `cloud_assets` as fallback graph `CLOUD` nodes
  when no attack-graph snapshot/export exists.
- Added deterministic report inventory parity:
  `forge/phase6/report_synthesizer.py` now loads `cloud_asset_inventory`,
  renders a template "Cloud Asset Inventory (Not Findings)" table, and exports
  raw CSV rows with `record_type=cloud_asset`.
- Added focused parity coverage in
  `tests/phase1/test_artifact_review_surface_parity.py`.

## Behavioral Contract

- Cloud ARN/resources stored in `cloud_assets` are analyst inventory unless
  a deterministic validation row with stable proof makes them reportable.
- Unvalidated inventory is visible in dashboard/report/raw export, but it is
  not inserted into `ctx.exploits.exploited`, not scored as a finding, and not
  promoted into validated risk narrative.
- React Native bundle pivots, source-map artifact queue entries, contact
  identity seeds, and AWS ARN inventory now stay visible across graph,
  dashboard, deterministic report context, template Markdown, and raw CSV.

## Verification Run

- `python -m ruff check forge/reporting/dashboard.py forge/phase6/report_synthesizer.py tests/phase1/test_artifact_review_surface_parity.py`
- `python -m py_compile forge/reporting/dashboard.py forge/phase6/report_synthesizer.py tests/phase1/test_artifact_review_surface_parity.py`
- `python -m pytest tests/phase1/test_artifact_review_surface_parity.py -q`
  - `1 passed`
- `python -m pytest tests/phase1/test_artifact_cloud_reference_detection.py tests/phase1/test_artifact_review_surface_parity.py -q`
  - `2 passed`
- `python -m pytest tests/phase6/test_report_synthesizer.py -k "artifact_seed_relations or archive_url_provenance or cloud_validation_metadata" -q`
  - `3 passed, 83 deselected`
- `python -m pytest tests/phase1/test_artifact_provenance.py tests/phase1/test_artifact_recursive_queue.py tests/phase1/test_artifact_react_native_bundle.py tests/phase1/test_artifact_calendar_contact_identity.py tests/phase1/test_artifact_cloud_reference_detection.py tests/phase1/test_artifact_review_surface_parity.py -q`
  - `11 passed`

## Known Residual

- `python -m pytest tests/reporting/test_dashboard.py -k "cloud or graph or detail" -q`
  currently has one stale stable-proof fixture failure:
  `test_generate_dashboard_surfaces_storage_validation_evidence_in_detail_graph`
  expects `VALIDATED`, but strict stable-proof gating renders `UNVERIFIED`.
  This is not caused by the new cloud inventory section; the fixture stores a
  legacy proof string that does not satisfy current stable-proof rules.

## Next Tasks

1. Fix/test remote artifact download result attribution when earlier queued
   remote artifacts are scope-skipped before the bounded downloader runs.
2. Add recursive second-pass artifact queue convergence coverage proving a URL
   discovered during artifact text parsing is parsed on the next `process()`.
3. Add audit-lineage assertions for artifact-derived queued URLs and
   cloud-assets inventory.
