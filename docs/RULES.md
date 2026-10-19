# FORGE Rules

FORGE is an automated, deterministic, traceable security assessment platform
for human-authorized, specifically scoped work. This index links to its
canonical rules, approved by Bryan on 2026-10-19:

- [Purpose](PURPOSE.md)
- [Automation and review](AUTOMATION.md)
- [MITRE ATT&CK and assessment path](ATTACK.md)
- [Hard boundaries](BOUNDARIES.md)
- [Supported targets and scope](TARGETS.md)
- [Engagement limits](ENGAGEMENT.md)

These rules apply to every person and AI agent working on FORGE. **They must
not be changed without human approval. Agents must not append, modify, or add
rules to these documents autonomously.** A requested rule change requires a
human to approve it before the documents are changed.

Read this index first, then the rule pages relevant to the task. If an older
source conflicts with these approved rules, follow the rule pages. This v2 set
supersedes conflicting statements in `README.md`, `DAILY_USE.md`, `END_GOAL.md`
and `SPEC.md` (removed in this consolidation), `docs/forge_continuous_loop_architecture.md`,
`docs/competitive_upgrade_do_now.spec.md`,
`docs/competitive_upgrade_explore.spec.md`,
`docs/competitive_upgrade_consolidated_backlog.md`,
`docs/STACK_WALKTHROUGH.md`, `docs/autopilot-phase-testing.md`,
`competitive-upgrade-report.md`, and historical `.agents/` records. The remaining
documents are retained where they contain implementation guidance, research,
or historical context; they do not grant exceptions to these rules. The
repository-wide `STANDARDS.md` governs general repository practices, not FORGE
product policy. `manifests/default.json` is an implementation artifact and
does not establish legal authorization.
