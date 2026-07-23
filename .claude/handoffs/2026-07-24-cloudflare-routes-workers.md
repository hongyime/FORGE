# Cloudflare Routes Workers Handoff

Date: 2026-07-24

Checkpoint: passive Cloudflare Pages `_routes.json` worker migration.

Changed:
- `forge/engagement_orchestrator.py`:
  `_static_hosting_control_candidate_values()` now routes independent
  `_routes.json` `include`, `exclude`, and `routes` entries through
  `_run_ordered_local_batch()` before URL normalization.
- `forge/engagement_orchestrator.py`: added
  `_static_hosting_control_cloudflare_route_candidate_values()` for one
  Cloudflare Pages route entry at a time.
- `tests/phase1/test_artifact_static_hosting_control_workers.py`: added
  `_routes.json` worker coverage proving bounded parallel entry extraction,
  deterministic entry order, local base-URL resolution, and sensitive query
  stripping.

Verification:
- `.venv\Scripts\python.exe -m compileall forge\engagement_orchestrator.py tests\phase1\test_artifact_static_hosting_control_workers.py`
- `.venv\Scripts\python.exe -m ruff check forge\engagement_orchestrator.py tests\phase1\test_artifact_static_hosting_control_workers.py`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_static_hosting_control_workers.py tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_static_hosting_control_files -q --color=no`

Result:
- Compile passed.
- Ruff passed.
- Focused worker tests plus engagement-backed static-hosting control slice:
  `3 passed`.

Safety boundary:
- Passive static hosting-control parsing only.
- No Cloudflare API calls.
- No live probing, provider calls, credential validation/use, proxy/IP rotation,
  rate-limit bypass, validation/report gate change, or severity change.

Next gate:
- Continue with Ohm's remaining ExternalSecret `data` / `dataFrom` remote-ref
  candidate if still applicable.
- GoReleaser nested list/scalar walkers are lower priority and should only be
  changed if a concrete worker or coverage gap remains after ExternalSecret.
