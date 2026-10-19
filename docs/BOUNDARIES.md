# Hard Boundaries

These boundaries are non-negotiable:

- **No exploitation.** Do not execute exploits or perform post-exploitation.
- **No defense evasion.** No EDR bypass, telemetry blocking, sandbox evasion,
  or equivalent activity.
- **Human-authorized, specific scope.** A human must set the authorized scope.
  A wildcard in configuration is not legal authorization and does not make
  every target authorized.
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
October 19, 2026 v2 rule supersedes older wildcard-equals-everything language,
unconstrained-execution goals, and proposals for evasion or exploitation.
Historical `.agents/` records remain untouched and do not override this rule.
