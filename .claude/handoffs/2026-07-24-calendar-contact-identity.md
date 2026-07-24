# Calendar Contact Identity Handoff

Date: 2026-07-24

Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`.

End goal: FORGE must be one comprehensive deterministic authorized ASM and
threat-intelligence pipeline from scoped multi-seed intake through bounded
recursive discovery, static artifact enrichment, non-destructive
validation-before-reporting, rule-engine findings/severity,
graph/dashboard/report/audit review, guaranteed template/raw fallback when
LLM/API narrative providers fail, and automated test-data cleanup.

## Completed Checkpoint

Calendar and vCard artifacts now promote conservative explicit contact identity
fields into the existing seed graph.

- `FN` and `N` become `name` seeds.
- `ORG` becomes `company` seeds.
- `TITLE` is preserved as `contact_title` provenance metadata on promoted
  seeds, not as a recursive `other` or title seed.
- Names and companies in `SUMMARY`, `DESCRIPTION`, and `ORGANIZER;CN` are not
  promoted.
- Existing email, phone, and URL pivots are unchanged.

## Files Changed

- `forge/engagement_orchestrator.py`
- `tests/phase1/test_artifact_calendar_contact_identity.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- TDD failed first with only email seed promotion.
- `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_artifact_calendar_contact_identity.py`
- `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_artifact_calendar_contact_identity.py`
- `python -m pytest tests\phase1\test_artifact_calendar_contact_identity.py -q`
  passed: `2 passed`.
- `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "calendar or vcard or contact" -q`
  passed: `11 passed, 751 deselected`.
- `python -m pytest tests\phase1\test_artifact_calendar_contact_identity.py tests\phase1\test_artifact_cloud_reference_detection.py tests\phase1\test_artifact_recursive_queue.py tests\phase1\test_artifact_react_native_bundle.py tests\phase1\test_artifact_har.py tests\phase1\test_artifact_columnar_data.py -q`
  passed: `14 passed`.
- `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "fanout_m_seed_name or fanout_n_seed_company or public_profile_urls_feed_recursive_identity or company_seed" -q`
  passed: `2 passed, 760 deselected`.
- `python -m pytest tests\phase1\test_social_profile_url_parser_links.py -q`
  passed: `1 passed`.
- Cleanup inventory found only `.forge_data/engagements` `1`, `5010`, and
  `master.db`.

## Next Sequence

1. Add graph/report/dashboard parity checks for newly recursive
   artifact-derived pivots, including React Native/source-map/cloud ARN/contact
   identity pivots.

## Safety Boundary

These tasks are static/passive/local or mocked. Do not add live probing,
credential attacks, rate-limit bypass, proxy/IP rotation, exploitation,
persistence, lateral movement, or post-exploitation. Live checks require an
explicit ROE/scope manifest and mocked tests.
