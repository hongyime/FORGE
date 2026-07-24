# Dashboard Cloud Asset Alias Validation Checkpoint

Date: 2026-07-24

Goal stage: review/validation.

## Summary

Static engagement detail cloud-asset rows now normalize both sides of the
latest-validation join. Assets stored with alias asset types such as `s3` can
now pick up canonical validation rows stored as `aws_s3` for the same
identifier. The rendered review row still preserves the stored asset type while
displaying the canonical type and effective validation/reportability status.

No live probing, provider calls, validation gate, severity rule, report
generation, crawler, API, or frontend behavior changed.

## Files

- `forge/reporting/dashboard.py`
- `tests/reporting/test_dashboard.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- `python -m py_compile forge\reporting\dashboard.py tests\reporting\test_dashboard.py`
- `python -m ruff check forge\reporting\dashboard.py tests\reporting\test_dashboard.py`
- `python -m pytest tests\reporting\test_dashboard.py::test_generate_dashboard_cloud_assets_join_validation_across_asset_type_alias -q --color=no` -> `1 passed`
- `python -m pytest tests\reporting\test_dashboard.py -k "cloud_assets_use_latest_validation_result or cloud_assets_join_validation_across_asset_type_alias or orders_cloud_validation_results_by_latest_checked_at or surfaces_storage_validation_evidence_in_detail_graph" -q --color=no` -> `4 passed, 24 deselected`
- `python -m pytest tests\reporting\test_dashboard.py -q --color=no` -> `28 passed`
- `.forge_data/engagements` count after tests: `0`

## Next

Canonicalize crawler URLs before recursive enqueue/fetch so href parser
expansion does not create duplicate deterministic crawl rows for fragment-only
variants like `/app`, `/app#top`, and `/app#pricing`.
