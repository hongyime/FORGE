# Apple App-Site-Association iOS App Inventory

Date: 2026-07-20

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`

Acceptance stage: artifact analysis, recursion, validation-state auditability.

## Summary

Source-aware `apple-app-site-association` parsing now extracts concrete AASA
`appID`, `appIDs`, and `apps` values such as `TEAMID.com.example.app` and stores
them as passive `mobile_ios_app` resource inventory with source
`artifact_apple_app_site_association`.

Wildcard and malformed app identifiers are filtered. Existing email, URL, and
Supabase recursion from the same payload is preserved. Canonical resource
identifiers remain lowercase through existing storage normalization, while
`provider_identifier` preserves the original Team ID casing.

## Files Changed

- `forge/utils/artifact_aasa.py`
- `forge/engagement_orchestrator.py`
- `tests/phase1/test_artifact_aasa_metadata.py`
- `tests/phase4/test_cloud_validation_registry_contract.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- TDD failure before implementation:
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_aasa_metadata.py -q --color=no`
  failed on missing `mobile_ios_app` inventory.
- Focused regression after implementation:
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_aasa_metadata.py -q --color=no`
  -> `1 passed`
- Compile:
  `.venv\Scripts\python.exe -m py_compile forge\engagement_orchestrator.py forge\utils\artifact_aasa.py tests\phase1\test_artifact_aasa_metadata.py tests\phase4\test_cloud_validation_registry_contract.py`
- Ruff:
  `.venv\Scripts\python.exe -m ruff check forge\engagement_orchestrator.py forge\utils\artifact_aasa.py tests\phase1\test_artifact_aasa_metadata.py tests\phase4\test_cloud_validation_registry_contract.py`
  -> `All checks passed!`
- Adjacent AASA/assetlinks/public metadata slice:
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_aasa_metadata.py tests\phase1\test_artifact_assetlinks_metadata.py tests\phase1\test_artifact_public_metadata_labels.py -q --color=no`
  -> `3 passed`
- Adjacent orchestrator slice:
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py -k "apple_app_site_association or assetlinks" -q --color=no`
  -> `2 passed, 757 deselected`
- Validation registry terminal-state contract:
  `.venv\Scripts\python.exe -m pytest tests\phase4\test_cloud_validation_registry_contract.py -q --color=no`
  -> `1 passed`
- Cleanup check:
  `.forge_data\engagements` remained `1`, `5010`, `master.db`.

## Safety

Passive static metadata inventory only. No App Store lookup, app download,
provider call, live probing, credential use, scope relaxation, proxy/IP
rotation, rate-limit bypass, report-gate change, severity change, or
deterministic finding creation was added.

Subagent review was attempted first but failed with `agent thread limit reached`;
work proceeded locally under the locked end-goal contract.
