# Cloud Asset Latest-Validation Parity Handoff

Date: 2026-07-24

## Goal Stage

Validation + review parity. This checkpoint keeps dashboard/API cloud asset
review rows aligned with the latest validation state without changing provider
validation behavior.

## Completed

- `forge/reporting/dashboard.py` now joins `cloud_assets` to only the latest
  matching `cloud_validation_results` row by `(engagement_id, asset_type,
  identifier)`, ordered by `checked_at` descending and then validation row id
  descending.
- This prevents legacy/non-unique validation-history tables from duplicating
  one cloud asset row or showing stale proof beside a newer validation result.
- Static dashboard regression covers a legacy duplicate validation-history
  table and proves the asset row uses the latest proof.
- Live engagement-detail API regression covers the same `_detail_sections()`
  projection through `/api/engagements/{ref}`.

## Verification

- `python -m ruff check forge\reporting\dashboard.py tests\reporting\test_dashboard.py tests\integration\test_webui_engagement_api.py` -> passed
- `python -m py_compile forge\reporting\dashboard.py tests\reporting\test_dashboard.py tests\integration\test_webui_engagement_api.py` -> passed
- `python -m pytest tests\reporting\test_dashboard.py -k "cloud_assets_use_latest_validation_result or orders_cloud_validation_results_by_latest_checked_at" -q` -> `2 passed, 24 deselected`
- `python -m pytest tests\integration\test_webui_engagement_api.py -k "cloud_assets_use_latest_validation_result or orders_cloud_validation_results_by_latest_checked_at" -q` -> `2 passed, 40 deselected`

## Next

Surface method-tagged Slack validation proof on dashboard/API vulnerability
finding rows. Phase 6 already preserves `VALIDATED:slack_auth_test:...` proof
in report context/raw CSV, but `_detail_sections()` currently renders
vulnerability rows without validation status/method/proof fields. Use mocked or
local fixtures only; do not call Slack.
