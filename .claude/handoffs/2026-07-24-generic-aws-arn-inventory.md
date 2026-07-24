# Generic AWS ARN Inventory Handoff

Date: 2026-07-24

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`.

End goal: FORGE must be one comprehensive deterministic authorized ASM and
threat-intelligence pipeline from scoped multi-seed intake through bounded
recursive discovery, static artifact enrichment, non-destructive
validation-before-reporting, rule-engine findings/severity,
graph/dashboard/report/audit review, guaranteed template/raw fallback when
LLM/API narrative providers fail, and automated test-data cleanup.

## Completed Checkpoint

Generic artifact text cloud-reference parsing now inventories allowlisted AWS
ARNs beyond S3/KMS without resolving, reading, or validating resources.

- Supported inventory-only ARN families: IAM role/user/policy, Lambda function/
  layer, SQS queue, SNS topic, ECR repository, CloudFront distribution, and
  Execute API/API Gateway route ARNs.
- Unsupported services, malformed account IDs, and unknown resource subtypes
  are skipped.
- The parser does not store generic catch-all `aws_iam`, `aws_lambda`,
  `aws_ecr`, or `aws_cloudfront` rows.
- `cloud_assets.identifier` remains deterministic/lowercased while first-seen
  exact ARN casing is preserved in `provider_identifier`.
- No `cloud_validation_results` rows are created by this inventory-only parser.

## Files Changed

- `forge/engagement_orchestrator.py`
- `tests/phase1/test_artifact_cloud_reference_detection.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- TDD failed first with only the existing KMS ARN row.
- `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_artifact_cloud_reference_detection.py`
- `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_artifact_cloud_reference_detection.py`
- `python -m pytest tests\phase1\test_artifact_cloud_reference_detection.py -q`
  passed: `1 passed`.
- `python -m pytest tests\phase1\test_artifact_cloud_reference_detection.py tests\phase1\test_artifact_har.py tests\phase1\test_artifact_columnar_data.py tests\phase1\test_artifact_react_native_bundle.py tests\phase1\test_artifact_recursive_queue.py -q`
  passed: `12 passed`.
- `python -m pytest tests\phase1\test_artifact_aws_app_runner.py tests\phase1\test_artifact_aws_cdk.py tests\phase1\test_artifact_cloudformation.py tests\phase1\test_artifact_ecs_task_definition.py tests\phase1\test_artifact_codebuild_workers.py -q`
  passed: `16 passed`.
- `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "artifact_queue_processor_parallelizes_firebase_project_persistence_prep or artifact_queue_processor_parallelizes_supabase_config_persistence_prep or kill_chain_html_artifact_urls_feed_remote_artifact_queue_and_static_analysis or queues_seed_mobile_bundle_urls or remote_mobile_bundle or route" -q`
  passed: `20 passed, 742 deselected`.
- Cleanup inventory found only `.forge_data/engagements` `1`, `5010`, and
  `master.db`.

## Residual

A broad selector,
`python -m pytest tests\phase1\test_engagement_orchestrator.py -k "cloud_assets or cloud_reference or aws_s3 or firebase or supabase or artifact_queue" -q`,
ran `421 passed, 340 deselected` but failed one managed-hosting
reachability-sensitive test unrelated to ARN parsing:
`test_kill_chain_html_mines_managed_hosting_aliases_without_firebase_false_validation`.
Observed failure: `vercel` classified `DEAD` instead of expected
`ACCESSIBLE_BUT_NO_DATA`.

## Next Sequence

1. Add conservative calendar/vCard identity enrichment from explicit contact
   fields (`FN`, `N`, `ORG`, `TITLE`) with provenance.
2. Add graph/report/dashboard parity checks for recursive artifact-derived
   pivots.

## Safety Boundary

These tasks are static/passive/local or mocked. Do not add live probing,
credential attacks, rate-limit bypass, proxy/IP rotation, exploitation,
persistence, lateral movement, or post-exploitation. Live checks require an
explicit ROE/scope manifest and mocked tests.
