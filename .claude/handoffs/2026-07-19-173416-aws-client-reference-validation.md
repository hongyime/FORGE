# AWS Client-Reference Validation Handoff

Date: 2026-07-19

## Summary

Implemented deterministic passive validation for AWS client references discovered from Amplify/Cognito/AppSync artifacts.

Changed files:
- `forge/phase4/cloud_validate.py`
- `tests/phase4/test_cloud_validate.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## What Changed

- Added `AwsCognitoUserPoolMetadataValidator`.
- Added `AwsCognitoAppClientMetadataValidator`.
- Added `AwsAppSyncApiReachabilityValidator`.
- Registered validators for:
  - `aws_cognito_user_pool`
  - `aws_cognito_app_client`
  - `aws_appsync_api`
- Added pending-sweep inclusion for:
  - `aws_cognito_user_pool`
  - `aws_cognito_identity_pool`
  - `aws_cognito_app_client`
  - `aws_appsync_api`
  - `aws_pinpoint_app`
- Kept `aws_cognito_identity_pool` and `aws_pinpoint_app` as explicit `UNSUPPORTED` results because no safe public validation method was added.

## Safety Boundary

- Cognito user-pool validation only reads public OIDC discovery metadata.
- Cognito app-client validation only validates the associated user-pool metadata and does not use the app client ID for authentication.
- AppSync validation only performs read-only endpoint reachability and does not send GraphQL queries, mutations, POST bodies, or introspection.
- AWS probes do not follow redirects.
- These checks return `ACCESSIBLE_BUT_NO_DATA` or `UNSUPPORTED`.
- These checks do not create deterministic vulnerability findings.
- No AWS auth flow, token exchange, Cognito identity-pool `GetId`, AppSync query/introspection, Pinpoint API call, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate weakening was added.

## Verification

```powershell
.venv\Scripts\python.exe -m py_compile forge\phase4\cloud_validate.py tests\phase4\test_cloud_validate.py
.venv\Scripts\python.exe -m ruff check forge\phase4\cloud_validate.py tests\phase4\test_cloud_validate.py
```

Result: compile passed, Ruff passed.

```powershell
.venv\Scripts\python.exe -m pytest tests\phase4\test_cloud_validate.py::test_run_cloud_asset_validate_preserves_case_sensitive_provider_identifier tests\phase4\test_cloud_validate.py::test_run_cloud_asset_validate_batch_processes_aws_client_references_without_findings tests\phase4\test_cloud_validate.py::test_sweep_pending_cloud_asset_validations_processes_aws_client_references -q --color=no
```

Result: `3 passed`.

```powershell
.venv\Scripts\python.exe -m pytest tests\phase4\test_cloud_validate.py -q --color=no -k "aws_cognito or aws_appsync or aws_pinpoint or provider_identifier or cloud_asset_validate or sweep_pending_cloud_asset_validations" -m "slow or not slow"
```

Result: `86 passed, 53 deselected`.

```powershell
.venv\Scripts\python.exe -m pytest tests\phase4\test_cloud_validate.py -q --color=no -m "slow or not slow"
```

Result: `139 passed`.

```powershell
.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_amplify_client_config.py tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_amplify_client_config_artifacts -q --color=no
```

Result: `5 passed`.

Cleanup:

```powershell
remaining_test_like_engagement_dbs=0
```

## Review

- Multi-agent reviewer `019f79c8-e517-7c22-8d38-2d51810169af` found no Critical/Important issues.
- Minor reviewer suggestions were fixed:
  - AWS validator redirects disabled.
  - Fake AWS client now rejects query/body/auth kwargs and auth headers.
  - Batch and pending-sweep tests now include `aws_cognito_identity_pool` unsupported coverage.
- Claude CLI review was attempted with the supported non-interactive CLI flags, but local Claude returned: `You've hit your session limit - resets 6:50pm (Asia/Singapore)`.

## External References Checked

- AWS Cognito OIDC discovery endpoints: `https://docs.aws.amazon.com/cognito/latest/developerguide/federation-endpoints.html`
- AWS Cognito endpoints/reference: `https://docs.aws.amazon.com/general/latest/gr/cognito.html`
- AWS AppSync endpoint format: `https://docs.aws.amazon.com/appsync/latest/devguide/custom-domain-name.html`
- AWS AppSync auth modes: `https://docs.aws.amazon.com/appsync/latest/devguide/security-authz.html`

## Claude Review Prompt

Review only this checkpoint:

- `forge/phase4/cloud_validate.py`
- `tests/phase4/test_cloud_validate.py`

Check:
- Are the new AWS validators passive and non-destructive?
- Do they avoid auth/token exchange/AppSync query execution?
- Do `ACCESSIBLE_BUT_NO_DATA` and `UNSUPPORTED` avoid deterministic vulnerability findings?
- Are mixed-case provider identifiers preserved through direct, batch, and pending-sweep paths?
- Are tests meaningful and fully mocked?

Known workspace issue: this directory is not a Git repository, so no commit or git diff is available here.

## Next Recommended Work

- Continue moving remaining safe sequential enrichers under bounded worker-pool execution.
- Add the next passive artifact parser gap only if it feeds recursive discovery without expanding live auth/exploitation behavior.
- Do not add IP rotation/rate-limit bypass. Keep slow, bounded, audited provider interaction.
