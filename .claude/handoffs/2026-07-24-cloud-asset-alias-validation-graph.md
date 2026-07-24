# Cloud Asset Alias Validation And Graph Handoff

Date: 2026-07-24

## Result

Fixed a passive-to-live validator handoff parity gap where legacy cloud asset
aliases could cause repeated validation claims or duplicate graph review nodes.

## Runtime Changes

- `forge/phase4/validation_claims.py`
  - Normalizes cloud asset aliases during pending claim selection.
  - Treats existing canonical validation rows as covering legacy alias rows.
  - De-dupes equivalent alias/canonical rows inside a single sweep before
    provider validation.

- `forge/phase4/attack_path.py`
  - Canonicalizes cloud asset service keys in `_node_for_cloud()`,
    `_load_cloud_validation_results()`, and `_load_cloud_assets()`.
  - Keeps original alias metadata (`asset_type_original` /
    `asset_type_aliases`) for operator review.
  - Prevents duplicate graph nodes such as `CLOUD::s3::bucket` plus
    `CLOUD::aws_s3::bucket` for one resource.

## Tests

- Added `tests/phase4/test_cloud_validation_asset_claim_aliases.py`.
- Added `tests/phase4/test_attack_path.py::test_cloud_asset_alias_rows_merge_with_canonical_validation_nodes`.

Verification run:

- `python -m compileall forge\phase4\validation_claims.py forge\phase4\attack_path.py tests\phase4\test_cloud_validation_asset_claim_aliases.py tests\phase4\test_attack_path.py`
- `ruff check forge\phase4\validation_claims.py forge\phase4\attack_path.py tests\phase4\test_cloud_validation_asset_claim_aliases.py tests\phase4\test_attack_path.py`
- `python -m pytest tests\phase4\test_cloud_validation_asset_claim_aliases.py -q`
  - Result: `2 passed`
- `python -m pytest tests\phase4\test_cloud_validate.py -k "cloud_asset_validate_batch or sweep_pending_cloud_asset_validations" -q`
  - Result: `16 passed, 117 deselected`
- `python -m pytest tests\phase4\test_attack_path.py -k "cloud_assets_with_same_identifier or alias_rows_merge or deterministic_cloud_exposure_uses_latest_validation_status or legacy_deterministic_cloud_exposure" -q`
  - Result: `4 passed, 105 deselected`
- `python -m pytest tests\phase4\test_cloud_validation_registry_contract.py -q`
  - Result: `1 passed`

## Next Gate

Audit another concrete passive-to-live validation parity gap, preferably
provider-specific proof/detail reviewability for long-tail validators or
dashboard/report parity for newly canonicalized aliases.

Keep live provider calls mocked unless an explicit ROE/scope manifest and
target are supplied.
