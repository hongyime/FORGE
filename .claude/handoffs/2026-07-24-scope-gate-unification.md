# Scope Gate Unification

Date: 2026-07-24

## Checkpoint

`forge.opsec.scope_gate.assert_in_scope()` now matches
`forge.governance.scope_gate` semantics for live-operation gating:

- Missing or empty scope fails closed.
- Bare domains authorize exact apex matches only.
- `*.example.com` authorizes subdomains only, not the apex.
- Apex plus subdomains require both `example.com` and `*.example.com`.
- CIDR matching uses Python's `ipaddress` module.

This closes the lower-level module bypass where direct callers of the opsec
helper could previously treat missing scope as a no-op or over-authorize
subdomains from a bare apex entry.

## Files Changed

- `forge/opsec/scope_gate.py`
- `tests/opsec/test_scope_gate.py`
- `tests/phase2/test_login_probe.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- `python -m pytest tests\opsec\test_scope_gate.py tests\governance\test_scope_gate.py -q`
  -> `37 passed`
- `python -m pytest tests\phase2\test_theharvester.py tests\phase2\test_key_scanner.py tests\phase2\test_login_probe.py -k "scope or out_of_scope or in_scope" -q`
  -> `7 passed, 137 deselected`
- `python -m pytest tests\cli\test_direct_live_scope.py tests\distributed\test_runnable_scope.py -q`
  -> `38 passed`
- `python -m pytest tests\phase1\test_engagement_ids.py tests\governance\test_scope_gate.py tests\opsec\test_scope_gate.py -q`
  -> `40 passed`
- `python -m pytest tests\integration\test_webui_engagement_api.py -k "rejects_live_sensitive_modes_without_scope_manifest or rejects_live_without_scope_manifest_when_required_by_env or passes_scope_manifest" -q`
  -> `3 passed, 38 deselected`
- `python -m ruff check forge\opsec\scope_gate.py tests\opsec\test_scope_gate.py tests\phase2\test_login_probe.py`
  -> passed
- `python -m py_compile forge\opsec\scope_gate.py tests\opsec\test_scope_gate.py tests\phase2\test_login_probe.py`
  -> passed

## Safety Notes

No scope relaxation, proxy rotation, rate-limit bypass, exploit automation,
post-exploitation behavior, or live target probing was added. Stale tests were
updated to express subdomain authorization explicitly with `*.acme.local`.

## Next

Harden explicit LLM/provider fallback regressions for quota, rate-limit, auth,
and timeout failures so every adapter degrades through cascade, deterministic
template fallback, and raw JSON/CSV export.
