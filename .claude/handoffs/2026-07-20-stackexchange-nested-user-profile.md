# Nested StackExchange User-Profile Recursion Handoff

Acceptance stages advanced: identity enrichment and recursion.

Provider-scoped Epieos StackExchange/StackOverflow `user` payloads now become
safe public profile pivots when they include:

- A numeric `user_id` / `userId` / `id`.
- A normalized handle from the existing Epieos handle parser.
- Either no site override or an accepted StackExchange network host such as
  `serverfault.com`, `superuser.com`, or `*.stackexchange.com`.

Invalid site hints such as `not-stackexchange.example` are rejected instead of
defaulting to fake StackOverflow URLs.

Files changed:

- `forge/utils/intel/social_profile_hosts.py`
- `forge/utils/intel/social_scraper.py`
- `tests/phase2/test_social_profile_hosts.py`
- `tests/phase2/test_social_scraper.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

Implementation notes:

- Pure StackExchange payload shaping lives in
  `forge/utils/intel/social_profile_hosts.py`.
- `forge/utils/intel/social_scraper.py` only adapts that payload through the
  existing Epieos handle/profile parser.
- No generic nested-user flattening was added.

Verification:

- `.venv\Scripts\python.exe -m py_compile forge\utils\intel\social_profile_hosts.py forge\utils\intel\social_scraper.py tests\phase2\test_social_profile_hosts.py tests\phase2\test_social_scraper.py`
- `.venv\Scripts\ruff.exe check forge\utils\intel\social_profile_hosts.py forge\utils\intel\social_scraper.py tests\phase2\test_social_profile_hosts.py tests\phase2\test_social_scraper.py`
- `.venv\Scripts\python.exe -m pytest tests\phase2\test_social_profile_hosts.py tests\phase2\test_social_scraper.py -q --color=no` -> `84 passed`
- `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py -k "social_profile" -q --color=no` -> `80 passed, 679 deselected`
- Cleanup check: `.forge_data\engagements` remained `1`, `5010`, and `master.db`.

Safety:

- Passive provider-payload normalization only.
- No provider calls, live probing, authentication, scope relaxation, generic
  nested-user flattening, validation/report-gate change, rate-limit bypass,
  proxy/IP rotation, or persistent non-test engagement DB mutation changed.

Next:

- Audit another concrete identity-provider payload shape or passive
  artifact/parser source shape before writing code.
- If no missing recursive pivot is found, switch to release-level mocked
  end-to-end/report-fallback tests or safe mega-test/module splits.
