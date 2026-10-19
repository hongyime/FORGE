# FORGE Web UI

This React/Vite app is the dashboard surface for the deterministic FORGE
engagement pipeline. It must expose the same engagement facts as the backend:
metadata, seeds, recursive discoveries, validation inventory, deterministic
findings/severity, graph exports, reports, raw exports, and audit history.

The web UI is not a separate source of truth. Current FORGE purpose and policy
live in [`docs/RULES.md`](../../../docs/RULES.md) and its linked specifications.
This UI overview describes implementation surfaces only. Historical planning
documents do not override those rules.

Do not add UI-only polish that weakens or bypasses scope gates, evidence gates,
rule-engine severity, deterministic fallback, or auditability.
