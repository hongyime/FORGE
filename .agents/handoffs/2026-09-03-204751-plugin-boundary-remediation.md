# Plugin Boundary Remediation

## Objective

Bring the v1 plugin event bus into conformance with
`docs/specs/plugin_boundary_v1.md` without disturbing unrelated concurrent
changes.

## Confirmed Gaps

- Publisher registration is optional, and subscribers are not engagement-bound.
- `collection:progress` is documented but absent from the schema registry.
- The 20 events / 10 seconds burst cap and repeated-offender disable are absent.
- Event audit write failures are logged and swallowed.
- Plugin ID, 50-key, and depth-5 limits are not fully enforced.
- Existing tests publish through unregistered identities and therefore encode
  the insecure compatibility behavior.

## Intended Contract

- `register_publisher()` is the trusted in-process identity-registration step;
  unregistered publishing and subscribing fail closed.
- The minute cap is global per plugin; the burst cap is also global per plugin.
- Three rate-limit violations disable the plugin only for the affected
  engagement until explicitly re-registered.
- Audit persistence must succeed before an accepted event reaches history or
  subscribers.
- Tests use isolated audit paths and exercise behavior, not imports.

## Resume

Implement in `forge/plugins/event_bus.py`, `forge/plugins/event_audit.py`, and
`forge/plugins/schemas/event_schema.py`; update the existing plugin tests; run
focused Ruff/pytest before the repository-wide test matrix.
