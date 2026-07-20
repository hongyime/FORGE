# Assetlinks Android Package Inventory

Date: 2026-07-20

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`

Acceptance stage: artifact analysis, recursion, validation-state auditability.

## Summary

Source-aware `assetlinks.json` parsing now extracts valid Android Digital Asset
Links `target.namespace=android_app` / `target.package_name` values and stores
them as passive `mobile_android_package` resource inventory with source
`artifact_assetlinks_android_package`.

This preserves existing generic email, URL, and Supabase recursion from the
same artifact payload. Malformed package strings are filtered.

## Files Changed

- `forge/utils/artifact_assetlinks.py`
- `forge/engagement_orchestrator.py`
- `tests/phase1/test_artifact_assetlinks_metadata.py`
- `tests/phase4/test_cloud_validation_registry_contract.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- TDD failure before implementation:
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_assetlinks_metadata.py -q --color=no`
  failed on missing `mobile_android_package` inventory.
- Focused regression after implementation:
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_assetlinks_metadata.py -q --color=no`
  -> `1 passed`
- Compile:
  `.venv\Scripts\python.exe -m py_compile forge\engagement_orchestrator.py forge\utils\artifact_assetlinks.py tests\phase1\test_artifact_assetlinks_metadata.py tests\phase4\test_cloud_validation_registry_contract.py`
- Ruff:
  `.venv\Scripts\python.exe -m ruff check forge\engagement_orchestrator.py forge\utils\artifact_assetlinks.py tests\phase1\test_artifact_assetlinks_metadata.py tests\phase4\test_cloud_validation_registry_contract.py`
  -> `All checks passed!`
- Focused/adjacent artifact slice:
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_assetlinks_metadata.py tests\phase1\test_artifact_public_metadata_labels.py tests\phase1\test_artifact_helpers.py -q --color=no`
  -> `10 passed`
- Adjacent orchestrator assetlinks/well-known slice:
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py -k "assetlinks or apple_app_site_association or well_known_public_metadata" -q --color=no`
  -> `2 passed, 757 deselected`
- Adjacent well-known metadata slice:
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_well_known_microsoft_identity_metadata.py tests\phase1\test_artifact_well_known_api_metadata.py tests\phase1\test_artifact_well_known_service_metadata.py -q --color=no`
  -> `6 passed`
- Validation registry terminal-state contract:
  `.venv\Scripts\python.exe -m pytest tests\phase4\test_cloud_validation_registry_contract.py -q --color=no`
  -> `1 passed`
- Cleanup check:
  `.forge_data\engagements` remained `1`, `5010`, `master.db`.

## Safety

Passive static metadata inventory only. No Android store lookup, app download,
provider call, live probing, credential use, scope relaxation, proxy/IP
rotation, rate-limit bypass, report-gate change, severity change, or
deterministic finding creation was added.

Subagent review was attempted first but failed with `agent thread limit reached`;
work proceeded locally under the locked end-goal contract.
