# Android AAR Route Discovery

Date: 2026-07-24

## Result

Passive web/JS route mining now recognizes linked Android `.aar` library
archives, and safe AAR MIME types infer `.aar` remote artifact filenames.

This lets the existing local/archive AAR parser run when pages or bundles link
paths such as `/libs/mobile-sdk.aar`, preserving recursive pivots from Android
library resources.

## Files

- `forge/engagement_orchestrator.py`
- `tests/phase1/test_artifact_remote_static_classification.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- TDD first: focused AAR route/MIME test failed on missing
  `application/x-aar` mapping.
- `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_artifact_remote_static_classification.py`
- `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_artifact_remote_static_classification.py`
- `python -m pytest tests\phase1\test_artifact_remote_static_classification.py::test_android_aar_content_types_and_routes_map_to_static_artifacts tests\phase1\test_artifact_remote_static_classification.py::test_classify_remote_artifact_url_recognizes_debian_package_archives -q`
- `python -m pytest tests\phase1\test_artifact_remote_static_classification.py tests\phase1\test_artifact_model_binaries.py tests\phase1\test_artifact_realm.py -q`
- `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "zip_backed_bundle_archives or remote_mobile_bundle or queues_seed_mobile_bundle_urls or route" -q`
- `python -m pytest tests\phase1\test_artifact_har.py tests\phase1\test_artifact_columnar_data.py tests\phase1\test_artifact_oci_layers.py -q`
- Cleanup inventory found only persistent `.forge_data/engagements` entries
  `1`, `5010`, and `master.db`; no pytest/test-like engagement DBs were
  created.

## Safety Boundary

No live probing, code execution, credential use, provider validation, or scope
relaxation was added. This only improves static route and MIME classification
so existing bounded artifact parsing can run.

## Next

Continue with a fresh bounded backend gap audit. One local candidate observed
but not implemented in this checkpoint: React Native bundle members such as
`assets/index.android.bundle`, `.jsbundle`, and Hermes `.hbc` inside archives
may need explicit member dispatch coverage.
