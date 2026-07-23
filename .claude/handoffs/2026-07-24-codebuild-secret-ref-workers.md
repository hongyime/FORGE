# CodeBuild Secret-Ref Workers Handoff

Date: 2026-07-24

Checkpoint: passive CodeBuild buildspec secret-reference worker migration.

Changed:
- `forge/engagement_orchestrator.py`:
  `_yaml_codebuild_buildspec_structured_candidates()` now builds ordered jobs for
  `env.parameter-store` and `env.secrets-manager` refs, then routes them through
  `_run_ordered_local_batch()`.
- `forge/engagement_orchestrator.py`: added
  `_yaml_codebuild_secret_job_candidate()` for one static reference conversion at
  a time.
- `tests/phase1/test_artifact_codebuild_workers.py`: added a focused regression
  proving bounded parallel conversion, parameter-store-before-secrets ordering,
  ARN trimming, JSON-key suffix trimming, and duplicate filtering.

Verification:
- `.venv\Scripts\python.exe -m compileall forge\engagement_orchestrator.py tests\phase1\test_artifact_codebuild_workers.py`
- `.venv\Scripts\python.exe -m ruff check forge\engagement_orchestrator.py tests\phase1\test_artifact_codebuild_workers.py`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_codebuild_workers.py tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_codebuild_buildspec_secret_refs -q --color=no`

Result:
- Compile passed.
- Ruff passed.
- Focused worker plus engagement-backed CodeBuild slice: `2 passed`.

Safety boundary:
- Passive static buildspec parsing only.
- No CodeBuild execution.
- No AWS API calls.
- No provider calls, live probing, credential validation/use, proxy/IP rotation,
  rate-limit bypass, validation/report gate change, or severity change.

Next gate:
- Ohm's read-only audit after `97cbb81` ranked remaining candidates:
  Recon JSONL line walker, Cloudflare Pages `_routes.json` value walker,
  ExternalSecret `data`/`dataFrom` refs, and GoReleaser nested list/scalar
  walkers. SOPS was already completed after that audit.
- Continue with one candidate at a time, keeping changes passive/static and
  adding focused worker regression plus an existing engagement-backed slice.
