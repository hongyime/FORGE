# Validation Inventory And Raw Export Parity

Date: 2026-07-24

## Completed

- Phase 6 raw CSV finding rows now preserve structured validation notes,
  evidence summary, and validation checked timestamp from the same finding
  context used by JSON/template report outputs.
- Added display-safe `effective_validation_status()` so key-provider validation
  inventory with stable proof can show `VALIDATED` without becoming a reportable
  deterministic cloud exposure.
- Wired Phase 6, static dashboard, and live engagement API validation inventory
  rows to the display-safe status while retaining strict
  `validation_reportable` cloud-exposure gates.
- Hardened imported graph filtering for mixed endpoint key shapes. If any of
  `source`, `source_node_id`, `target`, or `target_node_id` points to a removed
  deterministic cloud/key node, the edge is rejected. Cloud-alias graph dedupe
  now rewrites all existing endpoint aliases when remapping nodes.

## Verification

- `python -m compileall forge\utils\cloud_exposure_gate.py forge\phase6\report_synthesizer.py forge\reporting\dashboard.py tests\test_cloud_exposure_gate.py tests\phase6\test_report_cloud_exposure_gating.py tests\phase6\test_report_synthesizer.py tests\reporting\test_dashboard.py tests\integration\test_webui_engagement_api.py`
- `python -m ruff check forge\utils\cloud_exposure_gate.py forge\phase6\report_synthesizer.py forge\reporting\dashboard.py tests\test_cloud_exposure_gate.py tests\phase6\test_report_cloud_exposure_gating.py tests\phase6\test_report_synthesizer.py tests\reporting\test_dashboard.py tests\integration\test_webui_engagement_api.py`
- `python -m pytest tests\test_cloud_exposure_gate.py tests\phase6\test_report_cloud_exposure_gating.py tests\phase6\test_report_synthesizer.py -k "key_provider_validation_status or cloud_exposures_on_latest_validated_status or key_validation_proof or unverified_key_validation_method or raw_export" -q`
- `python -m pytest tests\reporting\test_dashboard.py -k "unknown_method_graph_snapshot_vuln_nodes or malformed_deterministic_cloud_findings or stale_api_key_graph_snapshot_nodes or validated_key_provider_inventory" -q`
- `python -m pytest tests\integration\test_webui_engagement_api.py -k "filters_malformed_deterministic_cloud_findings or surfaces_validated_key_provider_inventory" -q`
- `python -m pytest tests\reporting\test_dashboard_cloud_alias_graph.py -q`
- `cleanup_pytest_engagement_dbs([Path(gettempdir())])`

Focused checks passed; cleanup reported `removed=4 remaining=0`.

## Subagent Notes

- Kierkegaard found the key-provider inventory display gap: stored
  `VALIDATED` `aws_sts_get_caller_identity` rows displayed as `UNVERIFIED`
  because inventory projection reused a cloud-exposure-only effective status.
- Euclid found the mixed graph-edge alias gap: an edge with canonical and legacy
  endpoint keys could retain a stale `source`/`target` alias after node removal.

## Next

Audit another concrete passive-to-live validation/report/API parity gap.
Candidates: long-tail provider proof/detail reviewability, imported
graph/raw-export shape mismatches, or routes where deterministic validation
status is less strict than findings/report/dashboard gates. Keep live provider
calls mocked unless an explicit ROE/scope manifest and target are supplied.
