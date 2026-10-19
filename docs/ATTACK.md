# MITRE ATT&CK and Assessment Path

Every check and finding must map to a MITRE ATT&CK tactic and technique.
FORGE plans the assessment path through pre-exploitation:

1. Reconnaissance
2. Discovery
3. Vulnerability identification
4. Exposed-credential finding

An ATT&CK mapping describes the security behavior represented by a check or
finding. It does not authorize execution of an exploit. Engagement stops before
exploitation; see [`ENGAGEMENT.md`](ENGAGEMENT.md).

## Sources and precedence

This rule draws on the ATT&CK references in `README.md`, `STANDARDS.md`,
`docs/STACK_WALKTHROUGH.md`, and historical competitive upgrade material. The
October 19, 2026 v2 rule supersedes proposals for exploit execution, evasion,
or post-exploitation in those older materials.
