# Web Manifest Related-App Inventory

Date: 2026-07-20

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`

Acceptance stage: artifact analysis, recursion, validation-state auditability.

## Summary

Source-aware Web App Manifest parsing now extracts passive mobile app inventory
from `related_applications` entries:

- Android `platform=play` package IDs become `mobile_android_package`.
- iTunes/App Store IDs from `platform=itunes` `id` or App Store URLs become
  `mobile_ios_app_store_id`.

Malformed package/store IDs are filtered. Existing manifest email, URL, and
Supabase recursion is preserved.

## Files Changed

- `forge/utils/artifact_web_manifest.py`
- `forge/engagement_orchestrator.py`
- `tests/phase1/test_artifact_web_manifest_metadata.py`
- `tests/phase4/test_cloud_validation_registry_contract.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- TDD failure before implementation:
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_web_manifest_metadata.py -q --color=no`
  failed on missing mobile related-app inventory.
- Focused regression after implementation:
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_web_manifest_metadata.py -q --color=no`
  -> `1 passed`
- Compile:
  `.venv\Scripts\python.exe -m py_compile forge\engagement_orchestrator.py forge\utils\artifact_web_manifest.py tests\phase1\test_artifact_web_manifest_metadata.py tests\phase4\test_cloud_validation_registry_contract.py`
- Ruff:
  `.venv\Scripts\python.exe -m ruff check forge\engagement_orchestrator.py forge\utils\artifact_web_manifest.py tests\phase1\test_artifact_web_manifest_metadata.py tests\phase4\test_cloud_validation_registry_contract.py`
  -> `All checks passed!`
- Adjacent manifest/mobile/public metadata slice:
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_web_manifest_metadata.py tests\phase1\test_artifact_assetlinks_metadata.py tests\phase1\test_artifact_aasa_metadata.py tests\phase1\test_artifact_public_metadata_labels.py -q --color=no`
  -> `4 passed`
- Adjacent orchestrator slice:
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py -k "web_app_manifest or manifest_json_public_metadata or assetlinks or apple_app_site_association" -q --color=no`
  -> `3 passed, 756 deselected`
- Validation registry terminal-state contract:
  `.venv\Scripts\python.exe -m pytest tests\phase4\test_cloud_validation_registry_contract.py -q --color=no`
  -> `1 passed`
- Cleanup check:
  `.forge_data\engagements` remained `1`, `5010`, `master.db`.

## Safety

Passive static metadata inventory only. No Play Store/App Store lookup, app
download, provider call, live probing, credential use, scope relaxation,
proxy/IP rotation, rate-limit bypass, report-gate change, severity change, or
deterministic finding creation was added.

Subagent review was attempted first but failed with `agent thread limit reached`;
work proceeded locally under the locked end-goal contract.
