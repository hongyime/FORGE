# Downgraded Provider Validation Reviewability

Date: 2026-07-24

## Gate Advanced

Validation, report/dashboard reviewability, and deterministic proof gating.

## What Changed

- `parse_validated_detail()` now parses method-tagged non-reportable statuses
  such as `UNVERIFIED:<method>:<detail>` and
  `validation=UNVERIFIED:<method>:<detail>`.
- Non-`VALIDATED` statuses expose structured `validation_status` and
  `validation_method`, but always return an empty `validation_proof`.
- Downgraded Datadog validator inventory now remains non-reportable while
  dashboard rows and Phase 6 raw exports still show
  `datadog_api_key_validate` for analyst review.
- Reportability remains unchanged: only `VALIDATED` rows with stable
  provider-specific proof can contribute to deterministic key-finding counts.

## Verification

- `python -m compileall forge\utils\validation_proof.py tests\core\test_validation_proof.py tests\reporting\test_dashboard.py tests\phase6\test_report_synthesizer.py`
- `ruff check forge\utils\validation_proof.py tests\core\test_validation_proof.py tests\reporting\test_dashboard.py tests\phase6\test_report_synthesizer.py`
- `python -m pytest tests\core\test_validation_proof.py -q`
- `python -m pytest tests\reporting\test_dashboard.py -k "key_validation_proof_rows or unverified_key_validation_method or stale_key_validation_proof" -q`
- `python -m pytest tests\phase6\test_report_synthesizer.py -k "key_validation_proof or unverified_key_validation_method or unlabelled_embedded or raw_export" -q`
- `python -m pytest tests\phase4\test_cloud_validate.py -k "datadog or newer_provider_active_results_without_stable_proof or keeps_active_key_without_provider_proof_unverified" -q`
- `python -m pytest tests\phase4\test_attack_path.py -k "active_apikey_node_carries_validation_proof_metadata or excludes_stale or bare_legacy" -q`

## Next

Audit another concrete passive-to-live validation parity gap, preferably another
long-tail provider proof/detail reviewability mismatch. Keep live provider calls
mocked unless an explicit ROE/scope manifest and target are supplied.
