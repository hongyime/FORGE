# React Native Bundle Member Recursion Handoff

Date: 2026-07-24

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`.

End goal: FORGE must be one comprehensive deterministic authorized ASM and
threat-intelligence pipeline from scoped multi-seed intake through bounded
recursive discovery, static artifact enrichment, non-destructive
validation-before-reporting, rule-engine findings/severity,
graph/dashboard/report/audit review, guaranteed template/raw fallback when
LLM/API narrative providers fail, and automated test-data cleanup.

## Completed Checkpoint

React Native archive members and remote routes now recurse through static
artifact discovery without executing mobile code.

- React Native JavaScript bundle names are recognized for `.jsbundle`,
  `index.android.bundle`, and `index.ios.bundle`.
- Hermes bytecode bundles are recognized for `.hbc`.
- JS bundle archive members route through existing text extraction.
- Hermes archive members route through the bounded binary-string extraction
  path.
- Remote route discovery and safe MIME suffix mapping now recognize React
  Native bundles and Hermes bytecode.

## Files Changed

- `forge/engagement_orchestrator.py`
- `tests/phase1/test_artifact_react_native_bundle.py`
- `tests/phase1/test_artifact_remote_static_classification.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- TDD failed first on missing `.jsbundle` remote classification and missing
  Hermes member string extraction.
- `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_artifact_react_native_bundle.py tests\phase1\test_artifact_remote_static_classification.py`
- `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_artifact_react_native_bundle.py tests\phase1\test_artifact_remote_static_classification.py`
- `python -m pytest tests\phase1\test_artifact_react_native_bundle.py tests\phase1\test_artifact_remote_static_classification.py::test_react_native_bundle_routes_map_to_static_artifacts -q`
  passed: `2 passed`.
- `python -m pytest tests\phase1\test_artifact_remote_static_classification.py tests\phase1\test_artifact_model_binaries.py tests\phase1\test_artifact_realm.py tests\phase1\test_artifact_react_native_bundle.py -q`
  passed: `22 passed`.
- `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "zip_backed_bundle_archives or remote_mobile_bundle or queues_seed_mobile_bundle_urls or route or binary_string" -q`
  passed: `33 passed, 729 deselected`.
- `python -m pytest tests\phase1\test_artifact_har.py tests\phase1\test_artifact_columnar_data.py tests\phase1\test_artifact_oci_layers.py -q`
  passed: `10 passed`.
- Cleanup inventory found only `.forge_data/engagements` `1`, `5010`, and
  `master.db`.

## Next Sequence

1. Immediately enqueue artifact-like URLs discovered inside artifacts using
   existing passive classification only. Target
   `_persist_generic_text_discovery_batch` and `_store_artifact_url_seed` in
   `forge/engagement_orchestrator.py`; add a mocked/local regression proving a
   discovered source map, manifest, or nested static artifact URL moves into
   `artifact_queue` without waiting for a later outer CLI pass.
2. Broaden inventory-only AWS ARN cloud-reference parsing in generic artifact
   text for allowlisted service families beyond S3/KMS. Do not resolve or read
   resources.
3. Add conservative calendar/vCard identity enrichment from explicit contact
   fields (`FN`, `N`, `ORG`, `TITLE`) with provenance.
4. Add graph/report/dashboard parity checks for recursive artifact-derived
   pivots.

## Safety Boundary

These tasks are static/passive/local or mocked. Do not add live probing,
credential attacks, rate-limit bypass, proxy/IP rotation, exploitation,
persistence, lateral movement, or post-exploitation. Live checks require an
explicit ROE/scope manifest and mocked tests.
