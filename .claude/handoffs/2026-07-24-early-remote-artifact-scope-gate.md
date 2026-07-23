# Early Remote Artifact Scope Gate

Date: 2026-07-24
Commit: `ce33ff7`

## Gate

Discovery / artifact analysis / validation boundary. Remote artifact downloads
must be scope-manifest gated before the first artifact processing pass.

## Changed

- Moved the existing remote artifact scope decision, boolean checker, audit
  callback, and `ArtifactQueueProcessor.set_remote_scope_gate()` registration
  above startup `ingest_local_artifacts()` and `process()`.
- Kept the decision behavior unchanged:
  - no manifest -> allowed;
  - invalid URL -> denied;
  - manifest denial -> skipped with `scope_manifest_denied_remote_artifact`;
  - denial audit action -> `remote_artifact_scope_denied`.
- Extended `test_kill_chain_scope_manifest_denies_out_of_scope_remote_artifact_download`
  with a pre-existing queued remote APK at `https://evil.example/bootstrap.apk`.
  The fake downloader raises if that URL is reached, proving denial happens
  before outbound download.

## Verification

- `python -m compileall -q forge\cli.py tests\phase1\test_engagement_orchestrator.py`
- `ruff check forge\cli.py tests\phase1\test_engagement_orchestrator.py`
- `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "scope_manifest_denies_out_of_scope_remote_artifact_download" -q --color=no`
- `python -m pytest tests\phase1\test_kill_chain_convergence.py -q --color=no`
- `python -m pytest tests\phase1\test_kill_chain_multiseed_recursive_e2e.py::test_kill_chain_multiseed_recursive_discovery_stabilizes_with_validated_output -q --color=no`
- Pytest engagement cleanup: `removed=4 remaining=0 post_scan=0`

## Next

Audit and fix run finalization ordering for `--auto-run-detected`: follow-on
auto-run action evidence should land in final run metadata/manifests before the
engagement run is marked completed.
