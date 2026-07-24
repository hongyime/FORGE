# HAR WebSocket Message Recursion

Date: 2026-07-24
Branch: `main`
Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`

## Current State Summary

Passive HAR parsing now reads `_webSocketMessages[]` entries and feeds bounded
message data into the existing artifact text discovery pipeline.

Before this checkpoint, HAR summary/request/response/response-content parsing
worked, but WebSocket frame payloads were ignored. That meant URLs, emails, and
cloud references visible in captured WebSocket message data did not become
recursive engagement seeds or cloud asset references.

## Files Changed

- `forge/engagement_orchestrator.py`
- `tests/phase1/test_artifact_har.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- TDD fixture first failed with `discovered_seeds=0`.
- `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_artifact_har.py`
- `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_artifact_har.py`
- `python -m pytest tests\phase1\test_artifact_har.py -q` -> `6 passed`
- `python -m pytest tests\phase1\test_artifact_api_format_labels.py tests\phase1\test_artifact_orchestration_workers.py tests\phase1\test_artifact_helm_index.py -q` -> `8 passed`
- `python -m pytest tests\phase1\test_artifact_har.py tests\phase1\test_artifact_web_manifest_metadata.py tests\phase1\test_artifact_open_resource_discovery_metadata.py tests\phase1\test_artifact_charles_session_workers.py -q` -> `10 passed`
- `python -m pytest tests\phase1\test_artifact_helpers.py tests\phase1\test_artifact_remote_static_classification.py tests\phase1\test_artifact_container_images.py -q` -> `31 passed`
- `python -m pytest tests\phase1\test_kill_chain_service_worker_precache_e2e.py -q` -> `1 passed`
- Pytest engagement DB cleanup -> `removed=3 remaining=0`

## Important Context

Subagent `Hegel` found the gap. The implemented path is passive/static only:

- `_har_entry_lines()` now includes a `websocket_messages` family.
- `_har_entry_family_lines()` dispatches to `_har_websocket_message_lines()`.
- `_har_websocket_message_lines()` reads at most 64 messages.
- `_har_websocket_message_line_batch()` emits bounded `type`, `time`,
  `opcode`, and `data` lines.

The fixture proves WebSocket message data can recursively surface:

- `ws-owner@acme.example`
- `https://ws-api.acme.example/v1`
- `https://ws-live.firebaseio.com`
- `https://ws-project.supabase.co`
- `s3://ws-public-bucket`
- `gs://ws-public-assets`

## Immediate Next Step

Run a fresh bounded audit for one concrete backend kill-chain gap. Good targets
are passive parser/container/OCR source shapes, provider-proof hardening,
identity/provider normalization, or bounded-worker migration for a proven
pure-local sequential enricher.

Safety boundary: no browser replay, live target probing, credential use, scope
relaxation, proxy/IP rotation, or rate-limit bypass unless explicit ROE/scope
manifest and mocked tests are present.
