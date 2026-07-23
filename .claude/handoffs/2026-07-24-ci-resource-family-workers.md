# CI Resource Family Worker Handoff

Date: 2026-07-24

## Result

Azure Pipelines, Bitbucket Pipelines, and GitLab CI structured metadata
extraction now routes independent static resource families through the existing
ordered bounded worker pool.

Changed production code:

- `forge/engagement_orchestrator.py`
- New `_yaml_ci_resource_family_candidates()` dispatcher.
- `_yaml_azure_pipelines_structured_candidates()` batches repositories and
  containers as ordered family jobs.
- `_yaml_bitbucket_pipelines_structured_candidates()` batches repositories and
  containers as ordered family jobs.
- `_yaml_gitlab_ci_structured_candidates()` batches include repositories and
  service containers as ordered family jobs.

Existing direct pipeline/workflow identifiers still emit before resource
families. Repository/include resource output still precedes container/service
resource output.

## Verification

Commands run from repository root:

```powershell
python -m compileall -q forge\engagement_orchestrator.py tests\phase1\test_artifact_ci_workflow_workers.py
ruff check forge\engagement_orchestrator.py tests\phase1\test_artifact_ci_workflow_workers.py
python -m pytest tests\phase1\test_artifact_ci_workflow_workers.py::test_ci_repository_walkers_use_ordered_worker_path_and_preserve_order tests\phase1\test_artifact_ci_workflow_workers.py::test_ci_container_walkers_use_ordered_worker_path_and_preserve_order tests\phase1\test_artifact_ci_workflow_workers.py::test_ci_structured_resource_families_use_ordered_worker_path_and_preserve_order tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_azure_pipelines_resource_refs tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_bitbucket_pipelines_resource_refs tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_gitlab_ci_include_refs -q --color=no
python -m pytest tests\phase1\test_artifact_ci_workflow_workers.py tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_ci_cd_workflow_metadata_artifacts -q --color=no
```

Results:

- Compile passed.
- Ruff passed.
- Focused resource slice: `6 passed`.
- Compact CI worker/general metadata slice: `7 passed`.

## Safety

Passive/static parsing only. No CI job execution, include fetching, provider
calls, repository checkout, image pull, validation/reporting gate change,
scope relaxation, proxy/IP rotation, credential use, or Terraform execution was
added.

## Next

Audit CircleCI workflow/container fan-out. Patch only if the workflow-name and
container-image split is worth moving under the same bounded family dispatcher
without adding provider or CI execution behavior.
