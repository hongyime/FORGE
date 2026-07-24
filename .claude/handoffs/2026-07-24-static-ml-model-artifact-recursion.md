# Static ML Model Artifact Recursion

Date: 2026-07-24

## Result

Passive TensorFlow Lite/CoreML/protobuf model artifacts now enter static
recursive discovery.

- `.tflite`, `.mlmodel`, `.mlmodelc`, `.pb`, and `.pbtxt` classify as document
  artifacts and route through bounded binary-string extraction.
- Route-discovered model URLs with those suffixes can enter artifact queueing.
- Safe model MIME mappings infer artifact suffixes for TensorFlow Lite,
  CoreML, and binary protobuf downloads.
- Existing recursion handles emails, URLs, Firebase refs, Supabase refs, S3
  URIs, and GCS URIs from extracted strings.

## Files

- `forge/engagement_orchestrator.py`
- `tests/phase1/test_artifact_model_binaries.py`
- `tests/phase1/test_artifact_remote_static_classification.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- TDD first: local model ingestion returned `0`, remote model classification
  returned `None`, and model MIME mappings returned `""`.
- `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_artifact_model_binaries.py tests\phase1\test_artifact_remote_static_classification.py`
- `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_artifact_model_binaries.py tests\phase1\test_artifact_remote_static_classification.py`
- `python -m pytest tests\phase1\test_artifact_model_binaries.py tests\phase1\test_artifact_remote_static_classification.py::test_classify_remote_artifact_url_recognizes_model_binary_artifacts tests\phase1\test_artifact_remote_static_classification.py::test_model_content_types_and_routes_map_to_static_artifacts -q`
- `python -m pytest tests\phase1\test_artifact_model_binaries.py tests\phase1\test_artifact_remote_static_classification.py -q`
- `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "model_binary or columnar_data_export_static_artifacts or legacy_binary or binary_string or route" -q`
- `python -m pytest tests\phase1\test_artifact_realm.py tests\phase1\test_artifact_columnar_data.py tests\phase1\test_artifact_har.py tests\phase1\test_artifact_oci_layers.py -q`
- Cleanup inventory found only persistent `.forge_data/engagements` entries
  `1`, `5010`, and `master.db`; no pytest/test-like engagement DBs were
  created.

## Safety Boundary

No model deserialization, execution, inference, live probing, credential use,
provider validation, or scope relaxation was added. This is static bounded
byte-string extraction only.

## Next

Run or collect a fresh bounded backend gap audit, then implement one compact
safe static/passive recursion, provider normalization, validation-proof, or
bounded-worker dispatch gap with mocked/local tests.
