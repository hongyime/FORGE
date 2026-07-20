# LinkedIn Non-web Alias Fallback

Date: 2026-07-20

## Summary

Epieos LinkedIn parser now ignores non-web explicit profile aliases such as
`urn:li:fsd_profile:alice-example` and falls back to valid `publicIdentifier` /
handle reconstruction. HTTP(S) and scheme-less web host mismatches still block
fallback, so lookalikes such as `https://notlinkedin.com/in/alice` and
`notlinkedin.com/in/alice` do not create rows.

Explorer `Mencius` found the gap: an invalid non-web `profileUrl` caused
`_epieos_profile_url()` to return `""` before reaching LinkedIn handle fallback.

## Files Changed

- `forge/utils/intel/social_scraper.py`
- `tests/phase2/test_social_scraper_aliases.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- `.venv\Scripts\python.exe -m py_compile forge\utils\intel\social_scraper.py tests\phase2\test_social_scraper_aliases.py`
- `.venv\Scripts\ruff.exe check forge\utils\intel\social_scraper.py tests\phase2\test_social_scraper_aliases.py`
- `.venv\Scripts\python.exe -m pytest tests\phase2\test_social_scraper_aliases.py tests\phase2\test_social_scraper_app_links.py -q --color=no` -> `6 passed`
- `.venv\Scripts\python.exe -m pytest tests\phase2\test_social_scraper.py tests\phase2\test_social_scraper_aliases.py tests\phase2\test_social_scraper_app_links.py -q --color=no` -> `82 passed`

Direct parser probe confirmed:

- `urn:li:fsd_profile:alice-example` plus `publicIdentifier` creates `https://www.linkedin.com/in/alice-example`.
- `linkedin://in/app-link-alice` plus `publicIdentifier` creates `https://www.linkedin.com/in/app-link-alice`.
- `https://notlinkedin.com/in/alice` and `notlinkedin.com/in/alice` stay blocked.

Workspace engagement cleanup check found only pre-existing entries:
`1`, `5010`, `master.db`.

## Safety

Passive parser-only identity normalization. No network, provider call, auth
probing, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive
behavior, or report-gate change was added.

## Next Suggested Work

Continue looking for concrete recursive-discovery gaps with focused tests. Prefer
runtime parser/proof/recursion gaps over broad UI or provider-count work.
