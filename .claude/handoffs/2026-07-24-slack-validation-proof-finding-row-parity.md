# Slack Validation Proof Finding-Row Parity Handoff

Date: 2026-07-24

## Goal Stage

Validation + review parity. This checkpoint exposes deterministic key
validation proof already present in findings to dashboard/API review surfaces.

## Completed

- `forge/reporting/dashboard.py` now renders vulnerability finding rows through
  a helper that parses method-tagged evidence with `parse_validated_detail()`.
- `sections["vulnerability_findings"]` rows now include:
  - `Validation Status`
  - `Validation Method`
  - `Validation Proof`
- Static dashboard and live API regressions prove a local
  `DETERMINISTIC_KEY_EXPOSURE` Slack finding with
  `validation=VALIDATED:slack_auth_test:Slack auth ok: actor_id=... team_id=...`
  exposes the method and proof in review payloads.
- No Slack provider calls or live validation behavior were added.

## Verification

- `python -m ruff check forge\reporting\dashboard.py tests\reporting\test_dashboard.py tests\integration\test_webui_engagement_api.py` -> passed
- `python -m py_compile forge\reporting\dashboard.py tests\reporting\test_dashboard.py tests\integration\test_webui_engagement_api.py` -> passed
- `python -m pytest tests\reporting\test_dashboard.py::test_generate_dashboard_surfaces_slack_validation_proof_on_finding_rows -q` -> `1 passed`
- `python -m pytest tests\integration\test_webui_engagement_api.py::test_engagement_detail_api_surfaces_slack_validation_proof_on_finding_rows -q` -> `1 passed`
- `python -m pytest tests\reporting\test_dashboard.py -k "cloud_assets_use_latest_validation_result or orders_cloud_validation_results_by_latest_checked_at or surfaces_slack_validation_proof_on_finding_rows or surfaces_key_validation_proof_rows" -q` -> `4 passed, 23 deselected`
- `python -m pytest tests\integration\test_webui_engagement_api.py -k "cloud_assets_use_latest_validation_result or orders_cloud_validation_results_by_latest_checked_at or surfaces_slack_validation_proof_on_finding_rows or surfaces_validated_key_provider_inventory" -q` -> `4 passed, 39 deselected`

## Next

Audit another concrete passive-to-live validation/report/API parity gap,
preferably imported graph/raw-export shape mismatches for validation proof
fields or provider-specific proof/detail reviewability for remaining long-tail
validators. Keep provider calls mocked unless an explicit ROE/scope manifest and
target are supplied.
