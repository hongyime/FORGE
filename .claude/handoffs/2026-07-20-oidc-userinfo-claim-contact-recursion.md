# OIDC Userinfo And Claim Contact Recursion Handoff

Acceptance stages advanced: identity enrichment and recursion.

OIDC/userinfo-style identity claim containers now preserve safe contact and URL
pivots on the enclosing provider row:

- `claims.email`
- `claims.phone_number`
- `userinfo.email`
- `userinfo.phone_number`
- `userinfo.profile`
- `userinfo.website`

The parser no longer lets `userinfo` become its own fake platform row when it is
nested under a provider. Token/scalar claims such as `access_token`, `sub`,
`iss`, and `aud` are not persisted as URL/contact evidence.

Files changed:

- `forge/utils/intel/social_scraper.py`
- `tests/phase2/test_social_scraper.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

Verification:

- `.venv\Scripts\python.exe -m py_compile forge\utils\intel\social_scraper.py tests\phase2\test_social_scraper.py`
- `.venv\Scripts\ruff.exe check forge\utils\intel\social_scraper.py tests\phase2\test_social_scraper.py`
- `.venv\Scripts\python.exe -m pytest tests\phase2\test_social_scraper.py -q --color=no` -> `79 passed`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py -k "social_profile" -q --color=no` -> `80 passed, 679 deselected`
- Cleanup check: `.forge_data\engagements` remained `1`, `5010`, and `master.db`.

Review:

- Explorer `Kierkegaard` identified the nested `userinfo` gap after the earlier
  claim URL checkpoint.
- Explorer `James` audited the end-goal/continuation docs and recommended
  clarifying that `docs/engagement_overhaul_tasklist.md` -> `## Compact active
  backlog` wins over candidate notes in `docs/claude_quick_handoff.md`.

Safety:

- Passive parser-only identity enrichment.
- No provider calls, userinfo/JWKS fetches, token validation, live probing, scope
  relaxation, generic claim flattening, proxy/IP rotation, rate-limit bypass,
  validation/report-gate change, or persistent non-test engagement DB mutation
  changed.

Next:

- Audit another concrete identity-provider payload shape or passive
  artifact/parser source shape before writing code.
- If no missing recursive pivot is found, switch to release-level mocked
  end-to-end/report-fallback tests or safe mega-test/module splits.
