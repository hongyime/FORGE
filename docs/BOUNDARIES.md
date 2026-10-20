# Hard Boundaries

These boundaries are non-negotiable:

- **No exploitation.** Do not execute exploits or perform post-exploitation.
- **No defense evasion.** No EDR bypass, telemetry blocking, sandbox evasion,
  or equivalent activity.
- **Human-authorized scope.** A human must set the authorized scope. Bryan
  explicitly approved wildcard (`*`) authorization for Phase 5 target
  engagement on 2026-10-20; in that phase it authorizes supported feed targets.
  It does not relax any other boundary, phase gate, concurrency cap, or the
  pre-exploitation-only assessment limit.
- **Phase gates and concurrency caps stay in force.** All work must pass the
  configured gates and remain within concurrency limits.
- **Deterministic behavior.** Given the same inputs and state, assessment
  decisions and results must be reproducible; avoid unbounded or uncontrolled
  execution.
- **Traceable operation.** Preserve provenance, evidence, and an audit log for
  checks, decisions, and findings.

## Sources and precedence

This rule draws on `SECURITY.md`, `STANDARDS.md`, `AGENTS.md`,
`docs/forge_continuous_loop_architecture.md`, and historical records. The
October 19, 2026 v2 rule supersedes older unconstrained-execution goals and
proposals for evasion or exploitation. The Phase 5 wildcard exception above is
an explicitly approved, traceable authorization decision.
Historical `.agents/` records remain untouched and do not override this rule.
