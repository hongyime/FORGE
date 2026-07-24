# Artifact Text Recursive Queue Handoff

Date: 2026-07-24

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`.

End goal: FORGE must be one comprehensive deterministic authorized ASM and
threat-intelligence pipeline from scoped multi-seed intake through bounded
recursive discovery, static artifact enrichment, non-destructive
validation-before-reporting, rule-engine findings/severity,
graph/dashboard/report/audit review, guaranteed template/raw fallback when
LLM/API narrative providers fail, and automated test-data cleanup.

## Completed Checkpoint

Artifact text URL persistence now immediately queues artifact-like HTTP(S) URLs
using the existing passive remote artifact classifier.

- Source maps, static manifests, and nested archives discovered inside
  already-parsed artifacts move into `artifact_queue`.
- Queued rows use `discovered_from='artifact_text'` and `status='queued'`.
- Non-artifact API URLs remain engagement seeds only.
- Existing queue rows are preserved with
  `ON CONFLICT(engagement_id, source_url) DO NOTHING`, so parsed/downloaded/
  failed rows are not reset.
- The helper does not fetch remote URLs during the same processing pass.

## Files Changed

- `forge/engagement_orchestrator.py`
- `tests/phase1/test_artifact_recursive_queue.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- TDD failed first with no queued artifact rows.
- `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_artifact_recursive_queue.py`
- `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_artifact_recursive_queue.py`
- `python -m pytest tests\phase1\test_artifact_recursive_queue.py -q`
  passed: `2 passed`.
- `python -m pytest tests\phase1\test_artifact_recursive_queue.py tests\phase1\test_artifact_react_native_bundle.py tests\phase1\test_artifact_remote_static_classification.py -q`
  passed: `22 passed`.
- `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "artifact_queue_processor_parallelizes_firebase_project_persistence_prep or artifact_queue_processor_parallelizes_supabase_config_persistence_prep or kill_chain_html_artifact_urls_feed_remote_artifact_queue_and_static_analysis or queues_seed_mobile_bundle_urls or remote_mobile_bundle or route" -q`
  passed: `20 passed, 742 deselected`.
- `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "extensionless_remote_dex or extensionless_remote_image or extensionless_remote_avif" -q`
  passed: `3 passed, 759 deselected`.
- Cleanup inventory found only `.forge_data/engagements` `1`, `5010`, and
  `master.db`.

## Next Sequence

1. Broaden inventory-only AWS ARN cloud-reference parsing in generic artifact
   text for allowlisted service families beyond S3/KMS. Target
   `_artifact_text_cloud_asset_family_candidates` and the generic cloud-asset
   family dispatch in `forge/engagement_orchestrator.py`. Do not resolve or
   read resources.
2. Add conservative calendar/vCard identity enrichment from explicit contact
   fields (`FN`, `N`, `ORG`, `TITLE`) with provenance.
3. Add graph/report/dashboard parity checks for recursive artifact-derived
   pivots.

## Safety Boundary

These tasks are static/passive/local or mocked. Do not add live probing,
credential attacks, rate-limit bypass, proxy/IP rotation, exploitation,
persistence, lateral movement, or post-exploitation. Live checks require an
explicit ROE/scope manifest and mocked tests.
