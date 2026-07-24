# HAR WebSocket Message Alias Support

Date: 2026-07-24
Branch: `main`
Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`

## Current State Summary

Passive HAR parsing now accepts both Chrome-style `_webSocketMessages[]` and
unprefixed `webSocketMessages[]` arrays.

This closes a source-shape variant where non-Chrome HAR exporters can store
WebSocket message payloads under the unprefixed field, causing emails, URLs,
and cloud references in those messages to be dropped before recursive artifact
discovery.

## Files Changed

- `forge/engagement_orchestrator.py`
- `tests/phase1/test_artifact_har.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- Focused alias TDD first failed on missing `ws-alias@acme.example`.
- `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_artifact_har.py`
- `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_artifact_har.py`
- `python -m pytest tests\phase1\test_artifact_har.py -q` -> `6 passed`
- `python -m pytest tests\phase1\test_artifact_har.py tests\phase1\test_artifact_web_manifest_metadata.py tests\phase1\test_artifact_open_resource_discovery_metadata.py tests\phase1\test_artifact_charles_session_workers.py -q` -> `10 passed`
- `python -m pytest tests\phase1\test_kill_chain_service_worker_precache_e2e.py -q` -> `1 passed`
- Pytest engagement DB cleanup -> `removed=4 remaining=0`

## Immediate Next Step

Implement the verified Instagram business contact persistence gap:

- Persist public `business_email` and `business_phone_number` from Instagram
  `web_profile_info`.
- Add Phase 2 provider persistence coverage.
- Add Phase 1 synthesis coverage proving those persisted fields become
  recursive email/phone seeds.

Safety boundary: mocked provider payloads only. No live Instagram calls,
authentication, scraping expansion, proxy/IP rotation, or rate-limit bypass.
