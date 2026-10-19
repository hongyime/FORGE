# Engagement Limits

The engagement path covers reconnaissance, discovery, vulnerability
identification, and exposed-credential findings. It stops before exploitation.

FORGE must not perform:

- exploitation;
- persistence or lateral movement;
- collection or exfiltration; or
- defense evasion, including EDR bypass, telemetry blocking, or sandbox
  evasion.

Phase gates, concurrency caps, deterministic decisions, evidence provenance,
and audit logging remain required throughout an engagement. ATT&CK mappings and
planned attack paths do not grant permission to cross these limits.

## Sources and precedence

This rule draws on `docs/autopilot-phase-testing.md`,
`docs/forge_continuous_loop_architecture.md`, and the former `END_GOAL.md` and
`SPEC.md`. The October 19, 2026 v2 rule supersedes older exploitation-pipeline,
persistence, lateral-movement, collection, or exfiltration language.
