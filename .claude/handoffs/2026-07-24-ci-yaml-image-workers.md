# CI YAML Image Workers Handoff

Date: 2026-07-24

Checkpoint: passive CI YAML image extraction worker migration.

Changed:
- `forge/engagement_orchestrator.py`: Cloud Build, Drone, and Woodpecker image
  extraction now build ordered image jobs and normalize them through
  `_yaml_ci_image_candidates_from_jobs()` / `_yaml_ci_image_job_candidate()`.
- `forge/engagement_orchestrator.py`: Buildkite plugin extraction now sends each
  top-level plugin root through `_yaml_buildkite_plugin_image_candidate_values()`
  while nested plugin recursion stays serial inside that root.
- `tests/phase1/test_artifact_ci_workflow_workers.py`: added regression coverage
  proving ordered worker-path usage, output order, and dedupe for Cloud Build,
  Buildkite, Drone, and Woodpecker image extraction.

Verification:
- `.venv\Scripts\python.exe -m compileall forge\engagement_orchestrator.py tests\phase1\test_artifact_ci_workflow_workers.py`
- `.venv\Scripts\python.exe -m ruff check forge\engagement_orchestrator.py tests\phase1\test_artifact_ci_workflow_workers.py`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_ci_workflow_workers.py -q --color=no`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_ci_cd_workflow_metadata_artifacts tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_gitlab_ci_include_refs -q --color=no`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_observability_workers.py::test_observability_children_use_bounded_workers_and_preserve_order tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_observability_config_targets -q --color=no`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_orchestration_workers.py::test_orchestration_document_children_use_bounded_workers_and_preserve_order tests\phase1\test_artifact_orchestration_workers.py::test_orchestration_routing_rules_use_bounded_workers_and_preserve_order -q --color=no`

Result:
- Compile passed.
- Ruff passed.
- Focused worker tests: `4 passed`.
- Engagement-backed CI workflow slices: `2 passed`.
- Adjacent no-code boundary worker slices: `4 passed`.

Safety boundary:
- Passive static artifact parsing only.
- No CI workflow execution.
- No container pulls, registry probing, provider calls, live probing, credential
  use, proxy/IP rotation, rate-limit bypass, validation/report gate change, or
  severity change.

Next gate:
- Continue auditing remaining static parser/enricher candidates for a proven
  worker-pool or test coverage gap before editing.
- Re-check candidates around orchestration endpoint/text flattening and other
  small nested walkers; only patch if the top-level independent work can move
  under the existing ordered bounded worker-pool path without changing behavior.
