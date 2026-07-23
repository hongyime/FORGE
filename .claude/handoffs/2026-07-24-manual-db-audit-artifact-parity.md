# Manual Plus DB Audit Artifact Parity

Date: 2026-07-24
Commit: `32ee3bb`

## Gate

Review / audit fidelity. Manual audit sidecars must not hide canonical
DB-backed run audit manifest summaries.

## Changed

- `_materialize_audit_manifest_artifacts()` now returns existing manual
  `audit_*.json` sidecars while still materializing DB-backed
  `audit_{engagement_id}_run_{run_id}_{short_hash}.json` summaries when
  `run_audit_manifests` exists.
- Static dashboard and live web API fixtures now keep the manual audit sidecar
  and assert `audit_count == 2`.
- Both tests still verify the DB-backed artifact is downloadable/visible,
  verified on detail/download paths, and does not expose raw `manifest_json`.

## Verification

- `python -m compileall -q forge\reporting\dashboard.py tests\reporting\test_dashboard.py tests\integration\test_webui_engagement_api.py`
- `ruff check forge\reporting\dashboard.py tests\reporting\test_dashboard.py tests\integration\test_webui_engagement_api.py`
- `python -m pytest tests\reporting\test_dashboard.py -k "generate_dashboard_emits_slug_routes_and_json_contract" -q --color=no`
- `python -m pytest tests\integration\test_webui_engagement_api.py -k "engagement_list_and_detail_routes" -q --color=no`
- `python -m pytest tests\reporting\test_dashboard.py -q --color=no`
- `python -m pytest tests\integration\test_webui_engagement_api.py -q --color=no`
- Pytest engagement cleanup: `removed=4 remaining=0 post_scan=0`

## Next

Fix the kill-chain remote artifact scope-gate ordering found by sidecar audit:
pre-existing queued remote artifacts must receive the scope-manifest gate before
the first artifact processing pass.
