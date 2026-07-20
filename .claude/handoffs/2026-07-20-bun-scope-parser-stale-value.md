# Bun Scope Parser Stale-Value Checkpoint

## Summary

The passive JS-runtime/Bun config parser no longer reuses the previous registry candidate when a non-assignment line appears inside `[install.scopes]`.

## Safety Boundary

- Passive static parser correctness only.
- No Bun/Deno execution, package install, registry access, provider call, live probing, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, report-gate change, exploitation, or destructive behavior.

## Verification

- `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_artifact_js_runtime_config.py`
- `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_artifact_js_runtime_config.py`
- `python -m pytest tests\phase1\test_artifact_js_runtime_config.py tests\phase1\test_engagement_orchestrator.py -k "js_runtime_text_structured_payload or bun_scope" -q --color=no` -> `2 passed, 759 deselected`
