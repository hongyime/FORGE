# Parquet Columnar Artifact Parser

Date: 2026-07-24

## Result

Passive `.parquet` artifacts now use a bounded pyarrow-backed parser before
the generic binary-string carving path.

The parser emits a `#parquet-table` payload containing:

- Parquet format marker and column names.
- Bounded key/value metadata.
- Bounded interesting string cell values from up to the first 4 row groups, 64
  columns, and 64 rows per row group.

Existing payload recursion then handles emails, URLs, Firebase refs, Supabase
refs, S3 URIs, and GCS URIs without adding new live provider calls.

If `pyarrow` is unavailable, the artifact is too large for bounded parsing, or
parsing fails, the artifact falls back to the existing bounded
`#binary-strings` extraction path.

## Files

- `forge/engagement_orchestrator.py`
- `tests/phase1/test_artifact_columnar_data.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- TDD first: parser-marker assertion failed because existing extraction only
  emitted `#binary-strings`.
- `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_artifact_columnar_data.py`
- `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_artifact_columnar_data.py`
- `python -m pytest tests\phase1\test_artifact_columnar_data.py -q`
- `python -m pytest tests\phase1\test_artifact_columnar_data.py tests\phase1\test_artifact_remote_static_classification.py -q`
- `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "columnar_data_export_static_artifacts or legacy_binary or binary_string or embedded_archive" -q`
- `python -m pytest tests\phase1\test_artifact_har.py tests\phase1\test_artifact_oci_layers.py tests\phase1\test_artifact_remote_static_classification.py -q`
- Cleanup inventory found only persistent `.forge_data/engagements` entries
  `1`, `5010`, and `master.db`; no pytest/test-like engagement DBs were
  created.

## Safety Boundary

No execution of artifact contents, live probing, credential use, provider
validation, or scope relaxation was added. Parsing is local/static and bounded;
cloud/resource recursion remains handled by existing passive payload pipelines.

## Next

Implement the read-only subagent finding for Realm mobile DB artifacts:
`.realm` is currently not classified. The likely minimal patch is adding
`.realm` to the existing dump/binary-string suffix family plus safe content-type
mapping, then adding classification and queue-backed recursive extraction tests.
