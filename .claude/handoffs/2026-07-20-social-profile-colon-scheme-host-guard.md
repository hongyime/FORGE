# Social Profile Colon-Scheme Host Guard

Date: 2026-07-20

## Summary

The social profile host fallback now accepts scheme-less web profile values only when `urlparse()` did not detect an explicit scheme. This preserves valid profile pivots such as `github.com/acme` and `//github.com/acme`, while rejecting colon-scheme identifiers such as `mailto:alice@github.com`, `urn:github:alice`, and `github:alice` as fake host matches.

## Files Changed

- `forge/utils/intel/social_profile_hosts.py`
- `tests/phase2/test_social_profile_hosts.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`
- `END_GOAL.md`

## Verification

- `.venv\Scripts\python.exe -m py_compile forge\utils\intel\social_profile_hosts.py tests\phase2\test_social_profile_hosts.py`
- `.venv\Scripts\ruff.exe check forge\utils\intel\social_profile_hosts.py tests\phase2\test_social_profile_hosts.py`
- `.venv\Scripts\python.exe -m pytest tests\phase2\test_social_profile_hosts.py tests\phase2\test_social_scraper_aliases.py tests\phase2\test_social_scraper_app_links.py -q --color=no` -> `11 passed`
- `.venv\Scripts\python.exe -m pytest tests\phase2\test_social_scraper.py tests\phase2\test_social_scraper_aliases.py tests\phase2\test_social_scraper_app_links.py tests\phase2\test_social_profile_hosts.py -q --color=no` -> `87 passed`
- Direct host-match probe confirmed `github.com/acme` and `//github.com/acme` still match, while `mailto:alice@github.com`, `urn:github:acme`, and `github:acme` do not.
- Workspace engagement cleanup check found only `.forge_data\engagements\1`, `.forge_data\engagements\5010`, and `.forge_data\engagements\master.db`; no new pytest engagement DBs were left behind.

## Safety

Passive identity host-guard hardening only. No provider calls, live probing, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change.

## Next Suggested Work

Subagent `Anscombe` found a passive parser coverage gap: Pact contract parsing supports protocol-relative endpoints such as `//pact-cdn.acme.example/v1/status`, but there is no focused regression. Add a compact Pact test module or focused test in the artifact API-client worker coverage.
