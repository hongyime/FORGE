# Instagram Business Contact Recursion

Date: 2026-07-24

## Result

Public Instagram business-contact fields from `web_profile_info` now survive
lookup and persistence so they can feed recursive identity pivots:

- `business_email`, `businessEmail`, `public_email`, `publicEmail`,
  `contact_email`, `contactEmail` normalize into `profile.business_email`.
- `business_phone_number`, `businessPhoneNumber`, `business_phone`,
  `businessPhone`, `public_phone_number`, `publicPhoneNumber`,
  `contact_phone`, `contactPhone` normalize into `profile.business_phone`.
- `persist_instagram_findings()` stores those fields in `social_profiles`
  `profile_data`.
- Existing `EngagementSynthesisEngine` support then promotes them into
  recursive `email` and `phone` seeds.

## Files

- `forge/utils/intel/instagram_lookup.py`
- `tests/phase2/test_identity_provider_pacing.py`
- `tests/phase1/test_social_profile_anchor_normalization.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- TDD first: focused provider test failed on missing `business_email`.
- `python -m py_compile forge\utils\intel\instagram_lookup.py tests\phase2\test_identity_provider_pacing.py tests\phase1\test_social_profile_anchor_normalization.py`
- `python -m ruff check forge\utils\intel\instagram_lookup.py tests\phase2\test_identity_provider_pacing.py tests\phase1\test_social_profile_anchor_normalization.py`
- `python -m pytest tests\phase2\test_identity_provider_pacing.py::test_instagram_lookup_preserves_business_contacts_for_recursion tests\phase1\test_social_profile_anchor_normalization.py::test_instagram_business_contacts_feed_recursive_identity_pivots -q`
- `python -m pytest tests\phase2\test_identity_provider_pacing.py -q`
- `python -m pytest tests\phase1\test_social_profile_anchor_normalization.py tests\phase1\test_social_profile_app_link_aliases.py tests\phase1\test_epieos_envelope_synthesis.py -q`
- Cleanup inventory found only persistent `.forge_data/engagements` entries
  `1`, `5010`, and `master.db`; no pytest/test-like engagement DBs were
  created.

## Safety Boundary

No live provider call, credential use, account access, bypass, or scope
relaxation was added. Tests use mocked `httpx` responses and local SQLite
fixtures only.

## Next

Continue with the already identified Parquet columnar static-artifact parser
gap. After that, consider the subagent finding that `.realm` mobile DB files
are not classified and can be safely handled via existing bounded binary-string
extraction.
