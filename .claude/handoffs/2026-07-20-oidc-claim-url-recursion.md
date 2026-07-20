# OIDC Claim URL Recursion Handoff

Acceptance stages advanced: identity enrichment and recursion.

Epieos/userinfo-style nested OIDC claim URL fields now stay on the existing
provider row as recursive URL evidence:

- `claims.profile`
- `claims.website`
- related website/homepage/blog aliases handled by the small claim URL helper

The parser does not create a separate `claims` platform row. Scalar and token
claims such as `sub` and `access_token` are not persisted as URL evidence.

Files changed:

- `forge/utils/intel/social_scraper.py`
- `tests/phase2/test_social_scraper.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

Verification:

- `.venv\Scripts\python.exe -m py_compile forge\utils\intel\social_scraper.py tests\phase2\test_social_scraper.py`
- `.venv\Scripts\ruff.exe check forge\utils\intel\social_scraper.py tests\phase2\test_social_scraper.py`
- `.venv\Scripts\python.exe -m pytest tests\phase2\test_social_scraper.py -q --color=no` -> `78 passed`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py -k "social_profile" -q --color=no` -> `80 passed, 679 deselected`
- Cleanup check: `.forge_data\engagements` remained `1`, `5010`, and `master.db`.

Review:

- Explorer `Euclid` identified the dropped `claims.profile` / `claims.website`
  recursive URL gap.

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
