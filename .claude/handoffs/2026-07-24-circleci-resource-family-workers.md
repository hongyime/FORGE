# CircleCI Resource Family Worker Handoff

Date: 2026-07-24

## Result

CircleCI structured metadata extraction now routes independent static resource
families through the existing ordered bounded worker pool.

Changed production code:

- `forge/engagement_orchestrator.py`
- `_yaml_circleci_config_structured_candidates()` batches workflow names and
  container images as ordered family jobs.
- `_yaml_ci_resource_family_candidates()` now handles CircleCI workflow and
  container families alongside Azure Pipelines, Bitbucket Pipelines, and GitLab
  CI resource families.

Workflow identifiers still emit before container-image pivots.

## Verification

Commands run from repository root:

```powershell
python -m compileall -q forge\engagement_orchestrator.py tests\phase1\test_artifact_ci_workflow_workers.py
ruff check forge\engagement_orchestrator.py tests\phase1\test_artifact_ci_workflow_workers.py
python -m pytest tests\phase1\test_artifact_ci_workflow_workers.py tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_ci_cd_workflow_metadata_artifacts -q --color=no
```

Results:

- Compile passed.
- Ruff passed.
- Compact CI worker/general metadata slice: `7 passed`.

## Safety

Passive/static parsing only. No CircleCI execution, orb fetching, provider
calls, repository checkout, image pull, validation/reporting gate change,
scope relaxation, proxy/IP rotation, credential use, or Terraform execution was
added.

## Next

Run a fresh audit for remaining passive/static parser or enricher hotspots.
Skip code changes when the remaining loops are cheap, already covered by an
outer worker batch, or require shared mutable callbacks.
