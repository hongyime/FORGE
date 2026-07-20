# FORGE Web UI

This React/Vite app is the dashboard surface for the deterministic FORGE
engagement pipeline. It must expose the same engagement facts as the backend:
metadata, seeds, recursive discoveries, validation inventory, deterministic
findings/severity, graph exports, reports, raw exports, and audit history.

The web UI is not a separate source of truth. Current product goal and release
gates live in:

- `END_GOAL.md`
- `docs/end_goal.md`
- `docs/deterministic_engagement_contract.md`
- `docs/engagement_overhaul_tasklist.md`

Do not add UI-only polish that weakens or bypasses scope gates,
validation-before-reporting, rule-engine severity, deterministic fallback, or
auditability.
