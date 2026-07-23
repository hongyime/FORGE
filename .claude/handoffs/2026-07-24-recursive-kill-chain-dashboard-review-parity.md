# Recursive Kill-Chain Dashboard Review Parity

## Result
- The mocked multi-seed recursive kill-chain E2E now proves the real generated dashboard/detail route can review the same engagement output.
- The E2E still covers recursive seed promotion, non-destructive validation/report gates, deterministic template fallback after LLM/provider failure, checksum/report-lineage exports, graph generation, and exclusion of unverified cloud assets from findings.
- New dashboard assertions verify slug detail routing, completed run metadata, report fallback lineage, available report exports, full seed visibility, validated finding rows, validation inventory, VULN graph-node validation status, Maltego workspace visibility, and fallback reason rendering.
- Repeated validated public-metadata identifiers were extracted into the shared fixture to keep `tests/phase1/test_kill_chain_multiseed_recursive_e2e.py` under 1000 lines.

## Changed Files
- `tests/phase1/kill_chain_multiseed_fixture.py`
- `tests/phase1/test_kill_chain_multiseed_recursive_e2e.py`

## Verification
- `python -m compileall -q tests\phase1\kill_chain_multiseed_fixture.py tests\phase1\test_kill_chain_multiseed_recursive_e2e.py`
- `ruff check tests\phase1\kill_chain_multiseed_fixture.py tests\phase1\test_kill_chain_multiseed_recursive_e2e.py`
- `python -m pytest tests\phase1\test_kill_chain_multiseed_recursive_e2e.py -q --color=no -m "slow or not slow"`: `1 passed in 279.22s`
- `python -m pytest tests\reporting\test_dashboard.py::test_generate_dashboard_emits_slug_routes_and_json_contract tests\reporting\test_dashboard.py::test_generate_dashboard_surfaces_raw_export_report_family tests\reporting\test_dashboard.py::test_generate_dashboard_filters_unknown_method_deterministic_cloud_rows tests\reporting\test_dashboard.py::test_generate_dashboard_surfaces_storage_validation_evidence_in_detail_graph -q --color=no`: `4 passed`
- `cleanup_pytest_engagement_dbs()`: `removed=4 remaining=0`, post-scan `0`

## Safety
- No live external calls were made; the E2E keeps socket/network providers mocked.
- Dashboard generation is local static rendering over the test engagement DB and report artifacts.
- Unverified cloud resources remain reviewable as validation inventory but are still excluded from findings and vulnerability graph nodes.

## Next
- Continue with a concrete provider/export parity gap or another mocked E2E acceptance gap found by current-code audit.
- Avoid reopening worker-pool micro-optimizations unless a measured bottleneck appears.
