# Dashboard Cloud Alias Graph Parity

Date: 2026-07-24

## Result

Fixed dashboard/detail JSON graph parity for imported or stale graph payloads
that contain duplicate legacy/canonical cloud nodes for the same resource.

## Runtime Changes

- `forge/reporting/dashboard.py`
  - Adds a graph payload alias merge before validation filtering.
  - Canonicalizes CLOUD review nodes by `(asset_type, identifier)` using the
    shared cloud exposure normalizer.
  - Merges duplicate alias metadata into the kept canonical node.
  - Rewrites edges and critical-path node IDs to the kept node.
  - Drops duplicate/self-loop edges created by the merge.

## Tests

- Added `tests/reporting/test_dashboard_cloud_alias_graph.py`.

Verification run:

- `python -m compileall forge\reporting\dashboard.py tests\reporting\test_dashboard_cloud_alias_graph.py`
- `ruff check forge\reporting\dashboard.py tests\reporting\test_dashboard_cloud_alias_graph.py`
- `python -m pytest tests\reporting\test_dashboard_cloud_alias_graph.py -q`
  - Result: `1 passed`
- `python -m pytest tests\reporting\test_dashboard.py -k "cloud_validation or graph_payload or key_validation_proof_rows or stale_api_key_graph" -q`
  - Result: `8 passed, 13 deselected`
- `python -m pytest tests\integration\test_webui_engagement_api.py -k "graph_payload or cloud_validation or key_validation or latest" -q`
  - Result: `5 passed, 32 deselected, 6 warnings`

## Next Gate

Audit another concrete passive-to-live validation parity gap, preferably
provider-specific proof/detail reviewability for long-tail validators or
report/raw-export parity for canonicalized aliases.

Keep live provider calls mocked unless an explicit ROE/scope manifest and
target are supplied.
