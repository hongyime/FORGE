# Run Launch Response Reviewability

Date: 2026-07-24

Checkpoint: live launch/resume/restart route responses now echo normalized
execution switches as structured fields: `max_iter`, `skip_cloud`, and
`skip_keyscan`.

Why: the progress event already stored these values, but the synchronous API
response only exposed them indirectly through `command_preview`. Operators and
dashboard clients should be able to review the requested kill-chain shape
without parsing a shell command string.

Touched files:

- `forge/webui/app.py`
- `tests/integration/test_webui_engagement_api.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

Verification:

- `python -m compileall forge\webui\app.py tests\integration\test_webui_engagement_api.py`
- `python -m ruff check forge\webui\app.py tests\integration\test_webui_engagement_api.py`
- `python -m pytest tests\integration\test_webui_engagement_api.py -k "launch_engagement_kill_chain_route or restart_engagement_kill_chain_route_publishes_progress_event or engagement_pause_and_resume_routes" -q`

Result: `9 passed, 31 deselected`; warnings were existing jose JWT UTC
deprecations.

Agent notes:

- Claude review could not run because OAuth was expired.
- Codex CLI fallback rejected `gpt-5.2` for this account.
- The earlier graph artifact and audit-manifest parity findings were already
  closed in the current checkout and covered by focused tests.

Suggested next bounded audit:

Find exactly one concrete dashboard/API parity or reviewability gap in audit
log, run metadata, graph/report artifact, or validation inventory surfaces. Do
not broaden into provider additions unless a deterministic end-goal acceptance
gate is failing.
