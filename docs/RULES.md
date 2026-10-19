# FORGE Rules

**Canonical policy, Bryan-approved 2026-10-19 (v2).** This file defines the
product purpose, permitted target types, automation, and operational boundaries
for FORGE. When an older document, example, manifest, backlog item, or historical
decision conflicts with these rules, this file takes precedence. The source
documents remain available for historical and implementation context; this
policy does not silently amend them.

## Purpose

FORGE is an automated, deterministic, traceable security assessment platform.
It performs authorized assessments against scope specifically set by a human.

## Automation and review

FORGE automatically triages, prioritizes, and reports routine findings. Human
review is required for changes to authorized scope, introduction of a new target
type, and confirmation of a high-severity finding. These review points do not
authorize activity beyond the boundaries below.

## Targets

The supported target types are:

- URLs
- Domains
- IPv4 addresses
- Cloud references (`cloud_ref`)

Other identity or contact data—including usernames, email addresses, phone
numbers, names, and companies—is not an in-scope target type.

## Assessment path

Every check and finding must map to a MITRE ATT&CK tactic and technique. FORGE
plans and performs the assessment path through pre-exploitation:

1. Reconnaissance
2. Discovery
3. Vulnerability identification
4. Exposed-credential finding

Engagement stops before exploitation. The presence of an ATT&CK mapping or a
planned attack path does not grant permission to execute an exploit.

## Non-negotiable boundaries

- **No exploitation.** Do not execute exploits or perform post-exploitation.
- **No defense evasion.** No EDR bypass, telemetry blocking, sandbox evasion, or
  equivalent evasion activity.
- **Human-authorized, specific scope.** A human must set the authorized targets
  and scope. A wildcard in configuration is not legal authorization and does
  not make every target authorized.
- **Phase gates and concurrency caps remain in force.** Work must pass the
  configured phase gates and stay within its concurrency limits.
- **Deterministic behavior.** Given the same inputs and state, assessment
  decisions and results must be reproducible; do not introduce unbounded or
  uncontrolled execution.
- **Traceable operation.** Preserve provenance, supporting evidence, and an
  audit log for checks, decisions, and findings.
- **No post-exploitation activity.** No persistence, lateral movement,
  collection, or exfiltration.

## Source documents and precedence

This policy consolidates the following sources. Their other material remains
historical, explanatory, or implementation-specific; the rules above govern
where wording conflicts.

| Rule area | Sources informing this policy | Precedence and conflict resolved |
| --- | --- | --- |
| Purpose and authorized assessment | `README.md`, `END_GOAL.md`, `SPEC.md`, `DAILY_USE.md`, `SECURITY.md`, `STANDARDS.md` | The deterministic, traceable assessment purpose is retained. Any October 11, 2026 exploitation-pipeline objective in `END_GOAL.md` or `SPEC.md` is superseded where it permits exploitation or post-exploitation. |
| Automation and review | `docs/forge_continuous_loop_architecture.md`, `docs/autopilot-phase-testing.md`, `DAILY_USE.md`, `competitive-upgrade-report.md` (local report, if present) | Automated routine triage, prioritization, and reporting are permitted. Human review boundaries in this file govern; broader autonomous execution language in older material does not override them. |
| Target types and scope | `docs/forge_continuous_loop_architecture.md`, `docs/STACK_WALKTHROUGH.md`, `docs/competitive_upgrade_do_now.spec.md`, `docs/competitive_upgrade_explore.spec.md`, `competitive-upgrade-report.md` (local report, if present), `manifests/default.json` | The supported set is limited to URL, domain, IPv4, and `cloud_ref`. The manifest is an implementation artifact, not proof of authorization. Its wildcard note and wildcard scope values do not authorize all targets. |
| Phase gates and concurrency | `docs/autopilot-phase-testing.md`, `docs/forge_continuous_loop_architecture.md`, `docs/STACK_WALKTHROUGH.md`, `competitive-upgrade-report.md` (local report, if present) | Existing phase gates and concurrency caps remain. Older descriptions of phases do not expand the allowed activity past the pre-exploitation boundary. |
| ATT&CK and pre-exploitation path | `README.md`, `STANDARDS.md`, `docs/STACK_WALKTHROUGH.md`, `docs/competitive_upgrade_do_now.spec.md`, `docs/competitive_upgrade_explore.spec.md`, `docs/competitive_upgrade_consolidated_backlog.md`, `docs/competitive_upgrade_offensive_capabilities.md` | ATT&CK mapping is required for every check and finding. Exploitation, evasion, and post-exploitation proposals in upgrade documents are not authorization and are superseded by this file. |
| Hard boundaries and traceability | `SECURITY.md`, `STANDARDS.md`, `AGENTS.md`, `.agents/STATE.md`, `.agents/JOURNAL.md`, `.agents/handoffs/`, `.agents/CHECKLIST-T9-T36.md`, `docs/explore/av_bypass_not_needed.md`, `docs/competitive_research_strix_cairn_muraena.md` | Historical approvals, research, and agent handoffs do not override this policy. In particular, older wildcard-equals-everything language and evasion or unconstrained-execution proposals are superseded. |

### Conflict notes

- `SPEC.md` and `END_GOAL.md` contain an October 11, 2026 contract for an
  exploitation pipeline, including autonomous exploit and post-exploitation
  capabilities. Those permissions are withdrawn by this October 19 policy.
- `manifests/default.json` contains wildcard scope and a note treating `*` as
  unrestricted scope, alongside permissions and goals for exploitation,
  persistence, and data collection. Those fields do not establish legal
  authorization and do not override the boundaries here. The manifest is
  intentionally left unchanged by this documentation change.
- Competitive upgrade specifications, backlogs, research, and offensive
  capability documents contain proposed exploitation, evasion, persistence,
  lateral-movement, or exfiltration work. Such proposals are not approved
  behavior under this policy.
- `.agents/STATE.md`, `.agents/JOURNAL.md`, and handoffs record historical
  decisions and operating context. Past approvals—including prior broad
  wildcard interpretations—are superseded where they conflict with this policy.

## Inventory note

The repository-wide Markdown review also found historical audit and changelog
files, Rust migration and cutover documents, vendor/template documentation, and
component walkthroughs. They may describe implementation details or past
capabilities, but they do not create exceptions to this canonical policy.
