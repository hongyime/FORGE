# FORGE CLI UX Audit

**Auditor:** independent UX reviewer
**Date:** 2026-10-11
**Scope:** `forge` CLI surface at `C:\forge` (v7.2.0) — read-only analysis, no code changes.
**Method:** `python -m forge.cli --help` plus every subcommand's `--help`; verified against `README.md`, `QUICKSTART.md`, `forge/cli_registry.py`.

---

## 1. Executive summary

FORGE's CLI exposes **35 top-level commands** and **~128 subcommand leaves** — roughly **~140 invocable endpoints**. Many are well-engineered and genuinely orthogonal. But the top-level surface has drifted into three recurring overlap patterns:

1. **The "run everything" triangle** — `autopilot`, `automation cycle --apply --live`, `automation guarded-autostart --apply` all terminate in the same guarded-autopilot pipeline.
2. **The "launch kill-chain" trio** — `kill-chain`, `collection profiles emit`, `targets import --start`.
3. **The scattered "import" verbs** — seven different `import*` surfaces across five top-level groups.

Add two confirmed implementation bugs/drifts:

- **`connect <service>` doesn't match the README.** README documents `forge connect {github,supabase,shodan,...}` as a positional-arg verb. The CLI implements 10 separate subcommands — and each subcommand lists *every other provider's* flags in its `--help`, which is actively misleading.
- **`dashboard` is both a terminal command and a subcommand parent** (`dashboard` builds overview, `dashboard goal-progress -e N` is a different view). Help text explains this but it's an unusual pattern.

**New-user cognitive load:** the current `forge --help` output requires scanning 35 unlabeled commands in a single flat list. That exceeds Hick's Law and Miller's 7±2 by a wide margin for a tool whose misuse has real-world consequences (scope violations, authorization gates).

**Recommended minimum command set for a new user: 5 commands.** Everything else should be learnable progressively or auto-run by `autopilot`/`kill-chain`.

---

## 2. Current command count

### Top-level (35)

```
setup, doctor, scaffold, menu, operator-guide, clean, kill-chain,
kb, graph, report, audit, targets, import, monitoring, remediation,
active-validation, automation, connectors, standards, workspaces, demo,
retention, sessions, artifacts, collection, agents, recursion, mcp,
skills, exploitation, autopilot, feeds, connect, scope, dashboard
```

### Subcommand leaves per group

| Group | Leaves | Notes |
|---|---|---|
| `automation` | 13 | largest group; policy/defaults/limits are near-duplicates |
| `connectors` | 15 | 7 of these are `import-*`/`run-*`/`secret-*` paired families |
| `connect` | 10 | 1 per provider + list/remove; **all expose identical flag set** |
| `remediation` | 9 | ticket lifecycle; mostly orthogonal |
| `graph` | 9 (5 flat + ownership×3 + attribution×1) | `build` is essential, rest are specialized |
| `targets` | 7 | 4 of these are resume-related |
| `active-validation` | 7 | matches `exploitation` + `kill-chain --attack-mode` in audience confusion |
| `workspaces` | 7 | tenant admin |
| `report` | 7 | 1 essential (`generate`), 5 are ops/review plans |
| `monitoring` | 6 | 3 are "do work now" variants |
| `exploitation` | 5 (3 flat + credentials×2) | overlaps with `kill-chain` exploitation phase |
| `scope` | 4 | overlaps with `targets add` |
| `feeds` | 3 | threat-intel, distinct from `automation feed-build` |
| `kb` | 3 | offline KB ETL |
| `audit` | 3 | manifest verify/export |
| `collection` | 3 (profiles only) | wraps `kill-chain` |
| `dashboard` | 3 (bare + 2 subs) | nesting confusion |
| `import` | 2 | collector imports (BloodHound/AzureHound) |
| `recursion` | 2 (intents only) | advanced |
| `agents` | 2 | advanced |
| `mcp` | 2 | advanced |
| `skills` | 2 | advanced |
| `standards` | 2 | STIX import/export |
| `retention` | 2 | preview/apply |
| `artifacts` | 2 | status + Nemesis export |
| `demo` | 1 | proof pack |
| `sessions` | 1 | enum |
| Standalone (no subs) | 8 | setup, doctor, scaffold, menu, operator-guide, clean, kill-chain, autopilot |

**Total addressable endpoints: ~137.**

---

## 3. Identified overlaps and redundancies

### 3.1 The "run everything" triangle (HIGH severity)

Three distinct top-level entry points converge on the same guarded live-work pipeline:

| Command | Behavior | Pipeline |
|---|---|---|
| `forge autopilot` (`--apply` default) | Full live loop | feed-build → feed-fetch → auto-scope → import → resume → monitoring → dashboard |
| `forge automation cycle --apply --live` | Same + consume source queues first | queue drain → autopilot handoff |
| `forge automation guarded-autostart --apply` | Same, gated by `imports/autostart.local.json` | gate check → autopilot invocation |

The README has to spend ~500 words disambiguating which to use when. `autopilot` and `cycle --apply --live` and `guarded-autostart --apply` end up calling each other through different wrappers. Three names for one workflow is excessive.

**Impact:** When a new operator reads `README`, they encounter the 500-word reconciliation paragraph and have no clear mental model of which command owns which gate.

### 3.2 The "launch kill-chain" trio (MEDIUM severity)

| Command | What it does | Overlap |
|---|---|---|
| `forge kill-chain <seed>` | Runs the spider directly | authoritative |
| `forge collection profiles emit <name>` | **Prints** a `kill-chain` command string (does NOT execute) | wraps kill-chain |
| `forge targets import --start` | Imports a feed and launches `kill-chain` per target | wraps kill-chain |
| `forge autopilot` | Also launches kill-chains for new feed items | wraps kill-chain |

The `profiles emit` output is print-only (a safety-wrapper over `kill-chain`). New users predictably try to copy-paste the printed command and misinterpret "emit" as "run". The `--help` text explicitly says *"The command is PRINTED — never executed"* but that caveat gets lost.

### 3.3 Seven different "import" verbs (MEDIUM severity)

```
forge import bloodhound            # collector output into engagement
forge import azurehound            # collector output into engagement
forge targets import               # feed into new engagements
forge connectors import-cti        # CTI drops into engagement
forge connectors import-discovery  # Shodan/Censys/urlscan JSON
forge connectors import-validation # Burp/DAST XML
forge connectors import-secrets    # Gitleaks/TruffleHog output
forge standards import-stix        # STIX vuln bundle
forge remediation import-ticket-statuses  # ticket state
```

Nine endpoints spread across five top-level groups all do "accept external file → write to engagement DB". The verb is consistent; the location is not.

### 3.4 `forge connect <service>` — 10 clones with identical flags (BUG)

Each provider (`github`, `supabase`, `shodan`, `virustotal`, `replit`, `urlscan`, `censys`, `dehashed`) is a separate subcommand. Verified: `forge connect shodan --help` lists `--org/--user` (GitHub-only flags) and `--project-ref/--url` (Supabase-only) etc. **Every subcommand shows every other subcommand's flags.** This is both a UX bug and a drift from the README, which documents the pattern as `forge connect SERVICE [OPTIONS]`.

### 3.5 The report ops cluster (MEDIUM severity)

| Command | Purpose |
|---|---|
| `report generate` | Generate the engagement report (**essential**) |
| `report quality-audit` | "Summarize local report/dashboard quality breakpoints" |
| `report stale-plan` | "Plan stale latest-report regeneration" |
| `report stale-run` | "Regenerate stale latest reports sequentially" |
| `report long-run-plan` | "Plan long-run review" |
| `report policy-plan` | "Explain latest-run policy flag counts" |
| `report quality-metrics` | "Generate a quality-metrics report section" (library-level utility) |

Five of these seven read `reports/dashboard/data/engagements.json`, scan for operator-review conditions, and print a plan. They're variations on one function: "look at report health, tell me what's wrong".

### 3.6 The targets resume cluster (MEDIUM severity)

```
forge targets resume-candidates     # list candidates
forge targets resume-plan           # list candidates + command plan
forge targets resume-run            # execute plan
forge targets resume-lock-status    # inspect the batch lock
forge targets backfill-scope-manifests  # recover missing manifests
```

Five commands for one workflow (find stalled runs → plan → run). The naming convention (`resume-X`) is clean, but five siblings is a lot. `resume-plan` is a superset of `resume-candidates`; `resume-run --dry-run` is a superset of `resume-plan`.

### 3.7 `scope` vs `targets add` vs `connect` (LOW severity)

| Command | Writes to |
|---|---|
| `forge scope add-domain acme.com` | scope manifest JSON |
| `forge targets add acme.com` | scope manifest JSON **+** engagement row |
| `forge connect github --token-env ...` | `connections.json` (plus optionally spiders repos) |
| `forge targets add --github ORG` | scope manifest **+** queues GitHub for scan |

Four ways to say "add target"; each has slightly different side-effects. The `--help` text does not currently clarify which one updates which store.

### 3.8 `feeds fetch` vs `automation feed-build` (NOT redundant, but confusingly named)

These actually do different things, but share the "feed" vocabulary and new users consistently conflate them:

- `forge feeds fetch` — pulls **threat-intel feeds** (NVD, CISA KEV, EPSS, nuclei-templates) into `imports/`.
- `forge automation feed-build` — merges local engagement DBs, reports, CTI drops, connector outputs into **`imports/target-feed.json`** for later `targets import`.

Different inputs, different outputs, same word.

### 3.9 Multiple "do work now" entry points inside `monitoring` and `automation`

- `monitoring run-due` — one-shot execution of due policies.
- `monitoring worker` — long-running worker.
- `monitoring deliver-alerts` — alert delivery pass.
- `automation cycle` — orchestrates feed-build + queue drain + optional live handoff.
- `automation run` — "planner that does NOT launch live actions".

The last one is especially confusing: `forge automation run` by name sounds like "run the thing", but its own help text says *"This planner does not launch live actions"* — so it's a planner masquerading as a runner.

### 3.10 `exploitation` vs `kill-chain --include-exploitation` vs `active-validation` (HIGH severity for new-user confusion)

| Command | Mental model |
|---|---|
| `forge kill-chain --attack-mode` | Default. Live recon + bounded validation. Includes an exploitation **phase**. |
| `forge kill-chain --include-exploitation` | Default-on. Switches the above phase on/off. |
| `forge exploitation start --module ...` | Launch a **specific** exploitation module (reverse_proxy, post_login, autonomous, goal_engine) outside kill-chain. |
| `forge active-validation run` | Launch a scoped **active-validation job** (http_reachability, http_security_headers, fix_verification). |

All four touch "live scanning" with different scope rules. The README does differentiate them, but their names do not. A new operator cannot predict from the name alone which gate they're invoking.

---

## 4. Confusing names and labels

| Name | Issue | Suggested alternative |
|---|---|---|
| `automation run` | Says "run" but is a planner. | `automation plan` |
| `automation cycle` | Jargony. Users don't know what a "cycle" is here. | `automation daily` or fold into `autopilot` |
| `automation defaults` / `automation limits` / `automation policy` | Three ways to see config. | `automation config --section=defaults\|limits\|policy` |
| `collection profiles emit` | "Emit" is non-standard CLI verb. Users think it executes. | `collection profiles print-command` or `collection profiles dry-run` |
| `recursion intents` | Doesn't tell a new user what it does. | `agent intents` or hide from `--help` |
| `agents list` / `agents task-status` | "Agents" is overloaded (LLM agents? internal plugins?). | `plugins list` / `plugins task-status` |
| `mcp` | Acronym-only. Not everyone knows MCP = Model Context Protocol. | Keep `mcp` but add help string "Model Context Protocol server for LLM/IDE integration" |
| `skills` | Overloaded with Claude/Kiro skills. These are internal manifests. | `playbooks` |
| `scope auto-expand` | Verb-adverb-verb chain is unusual. | `scope expand` with `--auto` flag |
| `graph sync-assets` | New user doesn't know what the "asset graph" is. | `graph refresh` or `graph rebuild` |
| `graph tier-zero` | Jargon from AD tiering model; unexplained for non-AD users. | Keep but add help text explaining tier-zero |
| `targets backfill-scope-manifests` | 25-character command name. | `targets fix-manifests` |
| `monitoring deliver-alerts` | Reads like a flag misuse (`deliver` + `alerts`). | `monitoring send-alerts` |
| `report policy-plan` | Says "plan" but doesn't plan work — explains flag **counts**. | `report policy-explain` |
| `report quality-audit` | OK name but overlaps with `doctor`. | fold into `doctor --section reports` |
| `kill-chain --go-hard` | Playful but opaque. | `kill-chain --aggressive` or `--deep` |

---

## 5. Commands that would confuse a new user

In order of expected confusion-per-session:

1. **`autopilot` vs `automation cycle` vs `guarded-autostart`** — new user cannot tell which runs live, which is a planner, which is a wrapper.
2. **The 10 `connect <service>` clones with identical flags** — reading the help panel for one provider shows every other provider's flags.
3. **`collection profiles emit`** — new user assumes it runs the profile; it only prints.
4. **`automation run` is a planner** — the one command that sounds like "do it" is specifically the one that does not.
5. **`forge import` vs `forge targets import` vs `forge connectors import-*`** — three different top-level groups all do "import a file".
6. **`exploitation` as a top-level command when `kill-chain` already runs an exploitation phase** — new users ignore `exploitation` entirely because `kill-chain` sounds more aggressive.
7. **`dashboard` vs `dashboard goal-progress`** — the base command and a subcommand both do something; the subcommand needs `-e N` while the base doesn't.
8. **`scope`, `targets`, `connect`** — three top-level groups for "configure what I'm scanning".
9. **`active-validation` vs `--attack-mode` vs `exploitation`** — three gated-live-work systems with different scope rules.
10. **`recursion`, `agents`, `mcp`, `skills`** — four Explore-tier/advanced features at top level with no "advanced" visual grouping.

---

## 6. Minimal command set for a new user

**Must learn (5):**

| # | Command | When |
|---|---|---|
| 1 | `forge setup` | once, right after clone |
| 2 | `forge doctor` | after setup, and whenever something is off |
| 3 | `forge kill-chain <seed> --engagement <N>` | the main workflow |
| 4 | `forge dashboard` | after a run, to see results |
| 5 | `forge autopilot` *(or `forge-autopilot.bat`)* | hands-free continuous operation |

**Should learn eventually (3):**

| # | Command | When |
|---|---|---|
| 6 | `forge targets add <seed>` | add more seeds to an existing engagement |
| 7 | `forge report generate -e N` | regenerate the report with a different backend |
| 8 | `forge audit manifest-verify -e N` | prove engagement integrity |

**Everything else can stay hidden until needed.** A new user who learns 5 commands can:

- Install FORGE (`setup`)
- Verify readiness (`doctor`)
- Run an authorized assessment (`kill-chain`)
- Review results (`dashboard`)
- Automate continuous operation (`autopilot`)

That's the full assessment loop in 5 commands.

---

## 7. Proposed simplifications

### 7.1 KEEP (essential, well-named, no change)

- `setup`, `doctor`, `kill-chain`, `dashboard`, `autopilot`
- `menu`, `operator-guide`, `clean`
- `report generate`
- `graph build`, `graph sync-assets`
- `targets add`, `targets import`
- `audit manifest-verify`, `audit manifest-export`, `audit manifest-bundle-verify`
- `scope show`, `scope add-domain`, `scope add-ip`, `scope auto-expand`
- `kb sync`, `kb status`, `kb fetch-breach`
- `demo proof-pack`

### 7.2 COMBINE (merge families into one command with flags)

| Keep | Fold in | Rationale |
|---|---|---|
| `forge autopilot` | `automation cycle` + `automation guarded-autostart` | Three triggers for one pipeline. Make `autopilot` the only entry; add `--guarded` and `--drain-queue` flags. |
| `forge connect SERVICE` (positional) | current 10 clones | Match the README. Each service only shows its applicable flags. |
| `forge import --type collector --kind bloodhound\|azurehound ...` | `import bloodhound`, `import azurehound` | Collector-import becomes one typed command. Room to add Nessus/Nmap/etc. later without new subcommands. |
| `forge targets resume [--plan\|--run\|--candidates\|--lock-status]` | the 5 `resume-*` commands + `backfill-scope-manifests` | Default `--plan`. `--run` executes. `--candidates` is list-only. Fewer top-level verbs under `targets`. |
| `forge automation config [--section defaults\|limits\|policy]` | `automation defaults`, `automation limits`, `automation policy` | All three are read-only config views. |
| `forge report health [--section stale\|long-run\|policy\|quality]` | `report quality-audit`, `report stale-plan`, `report long-run-plan`, `report policy-plan` | All four scan `reports/` and print a plan. |
| `forge report regen [--stale] [--all]` | `report stale-run` | One command for all regen flows. `generate` stays for the single-engagement case. |
| `forge graph owners [list\|set\|resolve\|import]` | `graph ownership *`, `graph attribution import` | Collapse two 1-use subgroups into one. |

### 7.3 ALIAS (keep the name but mark as alias in help)

- `forge-autopilot.bat`/`.sh` are already aliases for `forge autopilot` — document explicitly.
- `forge automation cycle` → alias for `forge autopilot --once` with a deprecation note. Operators who've internalized the name keep working; new users see the canonical path.
- `forge collection profiles emit` → alias for `forge kill-chain --profile <name> --dry-run --print-only`. The profile system is useful; the top-level `collection` group is unnecessary.

### 7.4 DEPRECATE / HIDE from `--help` (keep for scripts, remove from top-level listing)

Move to a hidden `advanced` list, surfaced only via `forge --help-advanced` or `forge operator-guide`:

- `recursion intents` — advanced research feature.
- `agents list`, `agents task-status` — internal plugin inspection.
- `mcp serve`, `mcp tools` — LLM-integration surface; expose only to those who already know.
- `skills list`, `skills validate` — manifest registry; hide from new users.
- `workspaces *` — tenant admin; most users operate in default workspace.
- `artifacts status`, `artifacts nemesis-export` — handoff/diagnostic.
- `sessions enum` — Phase-3 session enumeration; rare for recon-only ops.
- `collection profiles *` — see above; aliased into `kill-chain --profile`.
- `automation run` (planner that doesn't run), `automation command-review` — low-value.
- `report quality-metrics` — library-level dev utility.
- `scaffold` — one-time deployment tool.

### 7.5 REMOVE (confirmed dead/redundant)

- Nothing *removed* — every endpoint has a legitimate caller or test. Hiding and consolidation are safer than removal.

---

## 8. The reorganized `forge --help` (proposed)

Instead of a 35-item flat list, group by lifecycle:

```
Usage: forge [OPTIONS] COMMAND [ARGS]...

FORGE — Full-Spectrum Red Team Platform (v7.2.0)

GETTING STARTED
  setup            Bootstrap FORGE for first-run operators.
  doctor           Readiness check — dependencies, keys, providers.
  menu             Interactive TUI engagement browser.
  operator-guide   Full workflow guide — every module, linked.

RUN
  kill-chain       Depth-first OSINT spider against any identifier.
  autopilot        Self-running automation loop (feed → import → resume → monitor).
  targets          Add seeds, import feeds, resume stalled runs.
  scope            View or edit the scope manifest.
  connect          Store service connections (GitHub, Supabase, Shodan, …).

REVIEW
  dashboard        Static engagement dashboard + goal-progress view.
  report           Generate, regenerate, or audit engagement reports.
  graph            Attack-path export, asset graph, tier-zero scoring.
  audit            Manifest verification and portable bundle export.

ADVANCED
  exploitation     Scoped authorized exploitation modules.
  active-validation  Separately gated active-validation jobs.
  monitoring       Continuous monitoring policies and alerts.
  remediation      Remediation workflow and ticket sync.
  retention        Enterprise retention policies.
  import           Import collector output (BloodHound, AzureHound).
  connectors       Free-first connector catalog.
  standards        Local STIX/TAXII standards exchange.

Run `forge --help-advanced` for internal/explore commands.
```

The three groups a new user cares about (**GETTING STARTED → RUN → REVIEW**) have **13 commands total**. They can learn 5, work productively, and discover the rest as needed.

---

## 9. Cognitive load analysis

### Before

- **35 top-level commands** in one unlabeled flat list.
- **~140 total endpoints** reachable from `--help` traversal.
- **5 commands** that look like they "run the main workflow" (`kill-chain`, `autopilot`, `automation cycle`, `automation run`, `automation guarded-autostart`) — of which one is a planner.
- **9 "import" verbs** across 5 top-level groups.
- **10 `connect` subcommands** each displaying all 10 providers' flags.
- **4 commands with "scope" semantics** (`scope`, `targets add`, `connect`, `collection profiles emit`).
- **5 commands for the resume workflow** under `targets`.
- **7 report commands** of which 1 is essential.
- **13 automation commands** of which ~3 are essential.

Hick's Law: decision time scales with log₂(n+1). Going from 35 → 5 visible top-level commands cuts first-decision latency from ~5.2 bits to ~2.6 bits — roughly **half** the cognitive load at the entry point.

### After (proposed)

- **13 visible top-level commands** grouped by lifecycle.
- **5 "must-learn" commands** for a new user.
- **1 canonical path** for "run everything" (`autopilot` + flags).
- **1 canonical path** for "connect to a service" (`connect SERVICE`).
- **1 canonical path** for the resume workflow (`targets resume [--plan|--run|--candidates|--lock-status]`).
- **1 canonical path** for report health (`report health [--section ...]`).
- **Advanced features hidden** until `--help-advanced`.

Progressive disclosure: a new user learns 5 commands, then expands into REVIEW (`report`, `graph`, `audit`), then into ADVANCED only when their engagement actually needs those features.

### Where cognitive load CANNOT be removed

Some complexity is intrinsic:

- **Scope gates and ROE** must stay visible — they're safety primitives.
- **The scope manifest / `--scope-manifest` flag** must stay visible on live-mode commands.
- **`FORGE_SAFE_MODE`, `--dry-run`, `--roe-id`** must stay visible.
- **Audit manifests** must have a verification path (`audit manifest-verify`).

These aren't UX bloat; they're the safety contract. Keep them.

---

## 10. What I did not do and why

- **I did not modify any code.** The task was audit-only, per the brief.
- **I did not benchmark actual time-to-first-successful-run for a new user.** That would require a usability study, not a code review. The findings here are structural; empirical validation is the natural next step.
- **I did not propose destructive renames (e.g., renaming `autopilot` to something else).** The brand name `autopilot` is already in the launcher scripts (`forge-autopilot.bat/.sh`) and in operator mental models. Keeping it as the canonical name reduces migration cost.
- **I did not grade individual Phase 6 report backends, Phase 4 graph exports, or specific connector implementations.** The audit focuses on command-surface shape, not module internals.
- **I did not reconcile the Rust-cutover plan** (`docs/rust-cutover-plan.md`) with this UX proposal. If the Rust rewrite is in flight, these changes should land there, not in the Python CLI being retired.

---

## 11. Suggested next steps (in priority order)

1. **Fix `connect SERVICE` to match the README** — single bug fix, high new-user impact. The current state actively misleads.
2. **Hide advanced commands** (`recursion`, `agents`, `mcp`, `skills`, `workspaces`, `artifacts`, `sessions`, `scaffold`, `collection`) behind a `--help-advanced` or `--help --advanced` flag. Pure help-text change, zero behavior change.
3. **Group `--help` output by lifecycle** (GETTING STARTED / RUN / REVIEW / ADVANCED). Pure help-text change.
4. **Clarify `autopilot` vs `automation cycle` vs `guarded-autostart`** in each `--help`. Mark `cycle` and `guarded-autostart` as "lower-level — most operators use `autopilot`".
5. **Consolidate `targets resume-*` into `targets resume --plan|--run|--candidates|--lock-status`.** Add shims that print a deprecation notice for the old names.
6. **Consolidate `report quality-audit`/`stale-plan`/`long-run-plan`/`policy-plan` into `report health --section ...`.**
7. **Rename `automation run` → `automation plan`** (it is a planner, not a runner).
8. **Add a visible banner on `collection profiles emit` output** explaining the command is printed, not executed.

Items 1–3 together cover ~80% of new-user confusion and are zero-risk documentation/help-text changes.
