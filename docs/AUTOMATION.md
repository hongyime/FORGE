# Automation and Human Review

FORGE automatically triages, prioritizes, and reports routine findings.

Human review is required only for:

- changes to authorized scope;
- introduction of a new target type; and
- confirmation of a high-severity finding.

These review gates do not authorize activity outside the rules in
[`BOUNDARIES.md`](BOUNDARIES.md) and [`ENGAGEMENT.md`](ENGAGEMENT.md).
Phase gates and concurrency caps remain in force.

## Sources and precedence

This rule draws on the automation flow in
`docs/forge_continuous_loop_architecture.md`,
`docs/autopilot-phase-testing.md`, and `DAILY_USE.md`. The October 19, 2026 v2
rule supersedes broader older language that could be read to authorize
unreviewed scope changes or new target types.
