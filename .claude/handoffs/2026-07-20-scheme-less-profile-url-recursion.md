# Scheme-less Social Profile URL Recursion

Date: 2026-07-20

## Summary

Epieos/social profile host guards now accept known profile URLs without an
explicit scheme, such as `github.com/acmeops` and `www.github.com/acmeops`.
This preserves platform aliases and recursive handle pivots when provider
payloads return scheme-less `profileUrl` values.

Explorer `Linnaeus` found the gap: `profile_url_hostname()` parsed raw text
with `urlparse()`, so `github.com/acme` had no hostname and alias host matching
rejected it.

## Files Changed

- `forge/utils/intel/social_profile_hosts.py`
- `tests/phase2/test_social_profile_hosts.py`
- `tests/phase2/test_social_scraper_aliases.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- `.venv\Scripts\python.exe -m py_compile forge\utils\intel\social_profile_hosts.py tests\phase2\test_social_profile_hosts.py tests\phase2\test_social_scraper_aliases.py`
- `.venv\Scripts\ruff.exe check forge\utils\intel\social_profile_hosts.py tests\phase2\test_social_profile_hosts.py tests\phase2\test_social_scraper_aliases.py`
- `.venv\Scripts\python.exe -m pytest tests\phase2\test_social_profile_hosts.py tests\phase2\test_social_scraper_aliases.py tests\phase2\test_social_scraper.py -q --color=no` -> `83 passed`

Workspace engagement cleanup check found only pre-existing entries:
`1`, `5010`, `master.db`.

## Safety

Passive identity parsing only. No provider calls, live probing, credential use,
scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or
report-gate change was added.

## Next Suggested Work

Continue with concrete recursive-discovery gaps or focused test splits that map
to `docs/end_goal.md`. The RDP/Citrix remote-access artifact behavior is present
but still has DB-backed coverage in the Phase 1 mega test; a focused test split
would reduce continuation friction if no higher-value runtime gap is found.
