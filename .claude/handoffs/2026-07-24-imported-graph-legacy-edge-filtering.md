# Imported Graph Legacy Edge Filtering

Date: 2026-07-24

## Completed

- Fixed imported dashboard/API graph payload filtering so stale deterministic
  cloud/key nodes cannot leave dangling edges when snapshot edges use legacy
  `source` / `target` keys instead of canonical `source_node_id` /
  `target_node_id`.
- Added a shared graph edge endpoint helper in `forge.reporting.dashboard` and
  reused it in validation filtering plus cloud-alias graph-node dedupe.
- Updated dashboard and live engagement API regression fixtures to exercise
  legacy edge-key payloads.

## Verification

- `python -m compileall forge\reporting\dashboard.py tests\reporting\test_dashboard.py tests\integration\test_webui_engagement_api.py tests\reporting\test_dashboard_cloud_alias_graph.py`
- `python -m ruff check forge\reporting\dashboard.py tests\reporting\test_dashboard.py tests\integration\test_webui_engagement_api.py tests\reporting\test_dashboard_cloud_alias_graph.py`
- `python -m pytest tests\reporting\test_dashboard.py -k "unknown_method_graph_snapshot_vuln_nodes or malformed_deterministic_cloud_findings or stale_api_key_graph_snapshot_nodes" -q`
- `python -m pytest tests\reporting\test_dashboard_cloud_alias_graph.py -q`
- `python -m pytest tests\integration\test_webui_engagement_api.py -k "filters_malformed_deterministic_cloud_findings or parses_json_graph_payload_from_latest_attack_snapshot" -q`
- `cleanup_pytest_engagement_dbs([Path(gettempdir())])`

Result: all focused checks passed; cleanup reported `removed=4 remaining=0`.

## Next

Audit another concrete passive-to-live validation/report/API parity gap. Good
candidates: long-tail provider proof/detail reviewability, imported graph/raw
export payload shape mismatches, or any route where deterministic validation
status is less strict than findings/report/dashboard gates. Keep live provider
calls mocked unless an explicit ROE/scope manifest and target are supplied.
