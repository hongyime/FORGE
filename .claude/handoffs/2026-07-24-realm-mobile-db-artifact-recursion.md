# Realm Mobile DB Artifact Recursion

Date: 2026-07-24

## Result

Passive Realm mobile database artifacts now enter static recursive discovery.

- `.realm` is classified as a document/static dump artifact.
- `application/realm`, `application/vnd.realm`, and `application/x-realm`
  remote content types map to `.realm`.
- Existing bounded `#binary-strings` extraction handles Realm files, so emails,
  URLs, Firebase refs, Supabase refs, S3 URIs, and GCS URIs feed the existing
  recursive seed/cloud-asset pipeline.

## Files

- `forge/engagement_orchestrator.py`
- `tests/phase1/test_artifact_realm.py`
- `tests/phase1/test_artifact_remote_static_classification.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- TDD first: local Realm ingestion returned `0`, remote `.realm`
  classification returned `None`, and Realm MIME mappings returned `""`.
- `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_artifact_realm.py tests\phase1\test_artifact_remote_static_classification.py`
- `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_artifact_realm.py tests\phase1\test_artifact_remote_static_classification.py`
- `python -m pytest tests\phase1\test_artifact_realm.py tests\phase1\test_artifact_remote_static_classification.py::test_classify_remote_artifact_url_recognizes_dump_binary_artifacts tests\phase1\test_artifact_remote_static_classification.py::test_dump_content_types_map_to_static_artifact_suffixes -q`
- `python -m pytest tests\phase1\test_artifact_realm.py tests\phase1\test_artifact_remote_static_classification.py tests\phase1\test_artifact_columnar_data.py -q`
- `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "dump_binary or columnar_data_export_static_artifacts or legacy_binary or binary_string" -q`
- `python -m pytest tests\phase1\test_artifact_har.py tests\phase1\test_artifact_oci_layers.py tests\phase1\test_artifact_remote_static_classification.py -q`
- Cleanup inventory found only persistent `.forge_data/engagements` entries
  `1`, `5010`, and `master.db`; no pytest/test-like engagement DBs were
  created.

## Safety Boundary

No Realm execution, database opening, live probing, credential use, provider
validation, or scope relaxation was added. This is static bounded byte-string
extraction only.

## Next

Collect read-only subagent `Pauli`'s next backend gap audit, then implement one
compact safe static/passive recursion, provider normalization, validation-proof,
or bounded-worker dispatch gap with mocked/local tests.
