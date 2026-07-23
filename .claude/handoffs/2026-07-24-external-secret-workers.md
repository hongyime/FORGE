# ExternalSecret Workers Handoff

Date: 2026-07-24

Checkpoint: passive ExternalSecret remote-ref worker migration.

Changed:
- `forge/engagement_orchestrator.py`:
  `_yaml_external_secret_remote_ref_keys()` now routes independent
  ExternalSecret `data` and `dataFrom` entries through `_run_ordered_local_batch()`.
- `forge/engagement_orchestrator.py`: added
  `_yaml_external_secret_remote_ref_entry_keys()` for one `data` or `dataFrom`
  entry at a time.
- `tests/phase1/test_artifact_external_secret_workers.py`: added focused
  coverage proving bounded parallel extraction, `data` before `dataFrom` order,
  and duplicate filtering.

Verification:
- `.venv\Scripts\python.exe -m compileall forge\engagement_orchestrator.py tests\phase1\test_artifact_external_secret_workers.py`
- `.venv\Scripts\python.exe -m ruff check forge\engagement_orchestrator.py tests\phase1\test_artifact_external_secret_workers.py`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_external_secret_workers.py tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_structured_yaml_cloud_assets -q --color=no`

Result:
- Compile passed.
- Ruff passed.
- Focused worker regression plus structured YAML cloud-asset integration slice:
  `2 passed`.

Safety boundary:
- Passive static ExternalSecret metadata parsing only.
- Provider expansion remains serial where it depends on cumulative remote keys.
- No Kubernetes API calls.
- No secret-store/cloud-provider calls.
- No live probing, credential validation/use, proxy/IP rotation, rate-limit
  bypass, validation/report gate change, or severity change.

Next gate:
- GoReleaser nested list/scalar walkers are lower priority. Audit first and skip
  code changes if root child dispatch already covers the useful top-level work.
