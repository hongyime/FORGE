# Claude Quick Handoff

Last updated: 2026-08-16

End goal quick answer: FORGE must be one deterministic authorized engagement
pipeline from scoped multi-seed intake through bounded recursive discovery,
static artifact enrichment, non-destructive validation-before-reporting,
rule-engine findings/severity, graph/dashboard/report/audit review, guaranteed
template/raw fallback when LLM/API narrative providers fail, and automated
test-data cleanup. Subagents are accelerators only; they do not redefine this
goal.

If asked for the end goal, answer this first, then point to `END_GOAL.md` and
`docs/engagement_overhaul_tasklist.md` as source-of-truth docs.

Use this file first for short resume context, then verify current continuation
order in `docs/engagement_overhaul_tasklist.md` -> `## Compact active backlog`;
that section wins if task/status details differ. Goal lock:
`FORGE-DETERMINISTIC-ASM-PIPELINE-v1`. Normative goal and fast entry point:
`END_GOAL.md`; root implementer spec: `SPEC.md`; acceptance criteria:
`docs/engagement_overhaul_tasklist.md` -> `## Canonical End Goal`.
Runtime `/goal` state, chat summaries, and old handoff notes are advisory only;
if they conflict with those docs, keep the goal lock and correct the stale
continuation note instead of redefining the project.

Current industry benchmark note: `docs/engagement_overhaul_tasklist.md` now
contains a sourced 2026-08-11 snapshot for BAS/active validation, cloud exposure
graphs, secrets lifecycle, standards/intel, and free-first integrations. Use it
as the roadmap baseline: NodeZero/Pentera/AttackIQ/SafeBreach define the
active-validation gap; Wiz/Orca/Microsoft Exposure Management define the graph
gap; TruffleHog/GitGuardian/GitHub define the secrets lifecycle gap; STIX/TAXII,
CVSS v4.0, EPSS, CISA KEV, and MITRE ATT&CK stay local/cache-first; and
ProjectDiscovery/local secrets tooling/free lookup paths remain the default
before paid adapters.
Latest checkpoint (2026-08-16): Web UI engagement discovery route callables
now bind through `forge.webui.engagement_discovery.build_engagement_discovery_providers`
instead of five inline wrappers in `forge.webui.app.create_app()`. The provider
preserves list, tombstone-list, detail, artifact, and DB resolution callable
contracts while keeping context refresh inside the discovery module.
Verification passed for Web UI engagement-discovery plus HTMX wiring tests (`27
passed`), Ruff, and `py_compile`. Backprop: `SPEC.md` B373.
Latest checkpoint (2026-08-16): Web UI route workspace-access checker binding
moved out of `forge.webui.app.create_app()`.
`forge.webui.workspace_access.build_workspace_access_checker` now owns the
connection-bound wrapper around the existing workspace access predicate,
preserving membership, legacy, and `workspaces:any` decisions for route
payloads. Verification passed for Web UI workspace-access plus HTMX wiring tests
(`24 passed`), Ruff, and `py_compile`. Backprop: `SPEC.md` B372.
Latest checkpoint (2026-08-16): Web UI engagement artifact route-file provider
binding moved out of `forge.webui.app.create_app()`.
`forge.webui.artifacts.build_engagement_artifact_files_provider` now owns the
reports-root binding for report/audit/graph route-file discovery while
preserving audit-manifest materialization and discovery-context behavior.
Verification passed for Web UI artifact plus HTMX wiring tests (`27 passed`),
Ruff, and `py_compile`. Backprop: `SPEC.md` B371.
Latest checkpoint (2026-08-16): Scheduled target-import monitoring snapshots no
longer warn on existing ISO `T` timestamps in engagement DBs opened with sqlite
declared-type parsing. `forge.monitoring.continuous._select_existing` casts
timestamp-like `*_at` fields to text before exposure-state JSON construction.
Verification passed for focused monitoring/import regressions (`2 passed`),
Ruff, `py_compile`, and a local no-start target-import smoke test. Backprop:
`SPEC.md` B370.
Latest checkpoint (2026-08-16): A stale Web UI audit-review annotation wrapper
was removed from `forge.webui.app.create_app()`.
`forge.webui.run_status.annotate_run_audit_review` remains the owned
implementation used through engagement payload construction; app setup no
longer imports or defines an unused local wrapper. Verification passed for Web
UI run-status plus engagement-payload tests (`13 passed`), HTMX app wiring tests
(`19 passed`), Ruff, and `py_compile`. Backprop: `SPEC.md` B369.
Latest checkpoint (2026-08-16): Web UI engagement summary/detail payload
binding was split out of `forge.webui.app.create_app()`.
`forge.webui.engagement_payloads.build_engagement_payload_providers` now binds
reports root and dashboard formatters for the discovery summary/detail builders.
Verification passed for Web UI engagement-payload tests (`3 passed`), HTMX app
wiring tests (`19 passed`), Ruff, and `py_compile`. Backprop: `SPEC.md` B368.
Latest checkpoint (2026-08-16): Web UI workflow DB opener binding was split out
of `forge.webui.app.create_app()`.
`forge.webui.db.build_workflow_db_opener` now binds the route-level DB opener
used by engagement detail, asset, remediation, retention, monitoring, and other
workflow routes. Verification passed for Web UI DB tests (`2 passed`), HTMX app
wiring tests (`19 passed`), Ruff, and `py_compile`. Backprop: `SPEC.md` B367.
Latest checkpoint (2026-08-16): Web UI engagement-discovery context binding was
split out of `forge.webui.app.create_app()`.
`forge.webui.engagement_discovery.build_engagement_discovery_context_provider`
now owns construction of the `EngagementDiscoveryContext` provider used by
index, detail, artifact, and DB resolution routes. Verification passed for Web
UI engagement-discovery tests (`7 passed`), HTMX app wiring tests (`19 passed`),
Ruff, and `py_compile`. Backprop: `SPEC.md` B366.
Latest checkpoint (2026-08-16): Web UI frontend entry response binding was
split out of `forge.webui.app.create_app()`.
`forge.webui.shell_routes.build_frontend_entry_response_provider` now binds the
React index path, legacy template path, and `FileResponse` used by dashboard and
SPA fallback routes. Verification passed for Web UI shell route tests (`7
passed`), HTMX app wiring tests (`19 passed`), Ruff, and `py_compile`.
Backprop: `SPEC.md` B365.
Latest checkpoint (2026-08-16): A stale Web UI latest-running run wrapper was
removed from `forge.webui.app.create_app()`.
`forge.webui.run_status.latest_running_engagement_run` remains the owned query
used by run-control and kill-chain launch helpers; app setup no longer imports
or defines an unused local wrapper. Verification passed for Web UI run-status
tests (`10 passed`), HTMX app wiring tests (`19 passed`), Ruff, and
`py_compile`. Backprop: `SPEC.md` B364.
Latest checkpoint (2026-08-16): Web UI report/audit file-provider binding was
split out of `forge.webui.app.create_app()`.
`forge.webui.artifacts.build_report_files_provider` and
`forge.webui.artifacts.build_audit_files_provider` now bind the reports root to
the existing report/audit filename discovery helpers, keeping artifact path
binding in the artifact module. Verification passed for Web UI artifact tests
(`7 passed`), HTMX app wiring tests (`19 passed`), Ruff, and `py_compile`.
Backprop: `SPEC.md` B363.
Latest checkpoint (2026-08-16): Web UI reports-directory provider binding was
split out of `forge.webui.app.create_app()`.
`forge.webui.artifacts.build_reports_dir_provider` now binds the `Path.cwd() /
"reports"` root used by report, audit, and graph artifact routes, keeping
report path policy in the artifact module. Verification passed for Web UI
artifact tests (`7 passed`), HTMX app wiring tests (`19 passed`), Ruff, and
`py_compile`. Backprop: `SPEC.md` B362.
Latest checkpoint (2026-08-16): Web UI logs-directory provider binding was
split out of `forge.webui.app.create_app()`.
`forge.webui.logs.build_logs_dir_provider` now binds `FORGE_DATA_DIR` to the
logs root provider used by log routes, keeping logs path creation policy in the
logs module. Verification passed for Web UI logs tests (`5 passed`), HTMX app
wiring tests (`19 passed`), Ruff, and `py_compile`. Backprop: `SPEC.md` B361.
Latest checkpoint (2026-08-16): Web UI launch-time run-control marker cleanup
was split out of `forge.webui.app.create_app()`.
`forge.webui.run_control.build_run_control_marker_clearer` now binds
`FORGE_DATA_DIR` to stale stop/pause marker cleanup before launching a new
kill-chain run, keeping marker path policy in the run-control module.
Verification passed for Web UI run-control tests (`9 passed`), HTMX app wiring
tests (`19 passed`), Ruff, and `py_compile`. Backprop: `SPEC.md` B360.
Latest checkpoint (2026-08-16): Web UI synchronous progress publishing was
split out of `forge.webui.app.create_app()`.
`forge.webui.state.build_progress_publisher` now binds a broker publish method
to the shared `ProgressEvent` constructor, preserving the event shape used by
task, lifecycle, seed, run-control, and command-center route payloads.
Verification passed for Web UI state tests (`5 passed`), HTMX app wiring tests
(`19 passed`), Ruff, and `py_compile`. Backprop: `SPEC.md` B359.
Latest checkpoint (2026-08-16): Web UI engagement summary/detail payload
construction was split out of `forge.webui.app.create_app()`.
`forge.webui.engagement_payloads` now owns dashboard/detail payload shaping,
including report history/previews, graph payload state, audit-review annotations,
and verified audit-manifest materialization for detail payloads. Verification
passed for Web UI engagement-payload tests (`2 passed`), HTMX app wiring tests
(`19 passed`), Ruff, and `py_compile`. Backprop: `SPEC.md` B358.
Latest checkpoint (2026-08-16): Web UI engagement artifact route-file
aggregation was split out of `forge.webui.app.create_app()`.
`forge.webui.artifacts.engagement_artifact_files` now owns ordered
report/audit/graph file discovery for artifact routes, with injectable audit
manifest materialization and graph discovery hooks. Verification passed for Web
UI artifact tests (`7 passed`), HTMX app wiring tests (`19 passed`), Ruff, and
`py_compile`. Backprop: `SPEC.md` B357.
Latest checkpoint (2026-08-16): The 01:05 scheduled target-import run returned
Task Scheduler result `2` without generating a new report. A traceback-friendly
mocked reproduction showed the real failure was target-import monitoring seeding:
`create_monitoring_snapshot()` read existing SQLite timestamp rows through
Python's deprecated converter and raised `not enough values to unpack`. Target
import now logs bounded warnings when monitoring seeding fails and continues to
scope manifest generation plus passive start decisions. Verification passed for
target-import tests (`16 passed`), Ruff, `py_compile`, and a mocked
production-data reproduction that reached fake start with `OK 100 started 1`.
Backprop: `SPEC.md` B356.
Latest checkpoint (2026-08-16): Web UI artifact file helper policy was split
out of `forge.webui.app.create_app()`. `forge.webui.artifacts` now owns
`reports_dir`, `report_files`, and `audit_files`, preserving `Path.cwd()/reports`,
existing report/audit filename discovery patterns, and report/graph/audit payload
ordering through the established artifact payload path. Verification passed for
Web UI artifact tests (`6 passed`), HTMX app wiring tests (`19 passed`), Ruff,
and `py_compile`. Backprop: `SPEC.md` B355.
Latest checkpoint (2026-08-16): Scheduled target import generated
`reports/engagement_10078_kill_chain_20260815T161113.md` but still ended with
Task Scheduler result `2` and stderr `Invalid value: not enough values to
unpack`. Target import now accepts child exit code `2` when the engagement DB
contains a completed `kill_chain` run for the same engagement and seed, in
addition to the previous captured-output `Kill-chain complete` plus `Report:`
success gate. Real exit-2 CLI/parser failures without DB completion still fail.
Verification passed for target-import regression tests (`15 passed`), Ruff, and
`py_compile`. Backprop: `SPEC.md` B354.
Latest checkpoint (2026-08-16): Web UI workflow engagement DB opening was split
out of `forge.webui.app.create_app()`. `forge.webui.db.open_workflow_db` now
owns direct-connect use, `sqlite3.Row` row factory setup before migrations,
migration-before-validation ordering, canonical-schema validation, and returned
open connection semantics for route handlers. Verification passed for Web UI
DB-helper tests (`2 passed`), HTMX app wiring tests (`19 passed`), Ruff, and
`py_compile`. Backprop: `SPEC.md` B353.
Latest checkpoint (2026-08-16): Web UI route permission guarding was split out
of `forge.webui.app.create_app()`. `forge.webui.auth_dependencies` now exposes
`build_principal_permission_guard`, and `create_app()` uses it for the local
route guard. The helper preserves `Principal.has_permission` wildcard and prefix
matching, HTTP 403 status mapping, and exact missing-permission detail text.
Verification passed for Web UI auth-dependency tests (`4 passed`), HTMX app
wiring tests (`19 passed`), Ruff, and `py_compile`. Backprop: `SPEC.md` B352.
Latest checkpoint (2026-08-16): Web UI latest audit-log timestamp lookup was
split out of `forge.webui.app.create_app()`. `forge.webui.run_status` now owns
`latest_audit_timestamp`, preserving newest-audit-row selection by descending id,
missing-table tolerance, empty fallback, and injected date formatting for
dashboard summary payloads. Verification passed for Web UI run-status tests (`10
passed`), HTMX app wiring tests (`19 passed`), Ruff, and `py_compile`.
Backprop: `SPEC.md` B351.
Latest checkpoint (2026-08-16): Web UI engagement row listing was moved out of
`forge.webui.app.create_app()`. `forge.webui.engagement_lifecycle` now exposes
`engagement_rows` beside the existing `engagement_row`, and `create_app()` wires
discovery context to those shared lifecycle helpers. The row-list helper
preserves dashboard/discovery column shape and ID ordering. Verification passed
for engagement lifecycle tests (`11 passed`), engagement discovery tests (`6
passed`), and HTMX app wiring tests (`19 passed`) after the combined command
exceeded 120s; Ruff and `py_compile` passed. Backprop: `SPEC.md` B350.
Latest checkpoint (2026-08-16): Web UI run audit-review annotation was split
out of `forge.webui.app.create_app()`. `forge.webui.run_status` now owns
`annotate_run_audit_review`, preserving non-dict passthrough, run-id and
manifest-hash extraction, top-level `audit_review`, nested audit-manifest
`review`, and non-mutating payload copies. Verification passed for Web UI
run-status plus HTMX app wiring tests (`27 passed`), Ruff, and `py_compile`.
Backprop: `SPEC.md` B349.
Latest checkpoint (2026-08-16): Web UI workspace RBAC/access setup was split
out of `forge.webui.app.create_app()`. `forge.webui.workspace_access` now owns
workspace foundation bootstrapping, membership checks, workspace access, and
engagement-row access decisions. `create_app()` delegates those helpers while
preserving default workspace creation, legacy `workspace_id` migration,
membership-based access, bootstrap allowance, `workspaces:any`,
`workspaces:legacy`, and denial of legacy owner fallback after explicit
memberships exist. Verification passed for Web UI workspace access/routes,
engagement discovery, and HTMX app wiring tests (`31 passed`), Ruff, and
`py_compile`. Backprop: `SPEC.md` B348.
Latest checkpoint (2026-08-16): Web UI live run-progress snapshot scanning was
split out of `forge.webui.app.create_app()`. `forge.webui.run_status` now owns
`iter_live_run_progress_snapshots` with injectable numeric-DB discovery,
table-exists, and connection helpers. `create_app()` delegates the scan while
preserving missing-table and SQLite operational-error skips, newest row per
engagement selection, terminal/step-less row suppression, and existing progress
payload/fingerprint shaping. Verification passed for Web UI run-status plus
HTMX app wiring tests (`25 passed`), Ruff, and `py_compile`. Backprop:
`SPEC.md` B347.
Latest checkpoint (2026-08-16): Web UI auth/bootstrap helper setup was split
out of `forge.webui.app.create_app()`. `forge.webui.auth_dependencies` now owns
injectable bearer-principal, bootstrap-secret, and progress-WebSocket token
parsing helpers without importing FastAPI at module import time. `create_app()`
delegates those helpers while preserving missing/invalid bearer 401s, disabled
bootstrap-token 503s, bootstrap token trimming, and WebSocket token lookup from
query params, Authorization header, and subprotocols. Verification passed for
Web UI auth-dependency plus HTMX app wiring tests (`22 passed`), Ruff, and
`py_compile`. Backprop: `SPEC.md` B346.
Latest checkpoint (2026-08-15): Web UI middleware setup was split out of
`forge.webui.app.create_app()`. `forge.webui.middleware` now owns the pure
`InMemoryRateLimiter` plus installers for the rate-limit middleware and
production internal-error handler; `create_app()` delegates those concerns while
preserving `/health` bypass, per-client request windows, 60 request/minute
limits, and production traceback suppression. Verification passed for Web UI
middleware plus HTMX app wiring tests (`21 passed`), Ruff, and `py_compile`.
Backprop: `SPEC.md` B345.
Latest checkpoint (2026-08-15): attack-graph exports now apply an export-layer
metadata guard before any artifact writer consumes the graph. `forge.graph.export`
sanitizes node and edge metadata once after build/filtering, stripping
secret-bearing keys and nested values, removing sensitive HTTP(S) query
parameters, and dropping URL userinfo while preserving reviewable non-sensitive
proof/source metadata. The guard covers JSON, Mermaid/DOT renderer inputs,
GraphML, MTGX workspace/manifest, node CSV, and edge CSV exports. Verification
passed for focused graph export tests (`4 passed`), graph artifact parser tests
(`3 passed`), Ruff, and `py_compile`. Backprop: `SPEC.md` B344.
Latest checkpoint (2026-08-15): scheduled theprawnhunter target import was
hardened after live logs showed runs could exceed the intended wall-clock cap
and live fan-out could crash on `engagement_seeds.source` CHECK constraints.
`run_tph_target_import_task.ps1` now treats `-TimeoutMinutes` as the whole task
budget, deducts stale-recovery/startup time before import launch, and keeps
cleanup inside that same budget; `install_tph_target_import_task.ps1` now
registers Task Scheduler `ExecutionTimeLimit` directly from that timeout. The
local task was reinstalled with `ExecutionTimeLimit=PT45M`,
`MultipleInstances IgnoreNew`, `-Start`, limit 100, max-iter 1, and start-limit
1. `SeedRunTracker` now normalizes runtime-only source labels such as
`social_profile` to schema-safe neutral values while preserving the raw label in
`metadata_json.raw_source`. Follow-up scheduled testing found and fixed two
remaining import-run failures: allocator drift could hand target import a DB
that already contained an engagement row, and a passive kill-chain that
completed and generated a report could still exit `2` after
`--no-auto-run-detected` skipped optional follow-on modules. Target import now
skips populated allocated DB IDs, and it accepts only the specific
`Kill-chain complete` plus `Report:` exit-2 shape while preserving failure for
real CLI/parser errors. Verification passed for scheduler/import/run tracking,
Python Ruff/compileall, engagement API/history/MVP/API auth batches,
theprawnhunter target-feed/auth checks, target-import regressions (`14
passed`), real feed import of 100 targets, and a scheduled live run that
generated `reports/engagement_10696_kill_chain_20260815T150918.md`.
Latest checkpoint (2026-08-14): the canonical release E2E now proves the
enterprise CTEM roadmap primitives inside the same representative engagement
instead of relying only on isolated module tests. `tests/integration/test_canonical_release_e2e.py`
now uses PyJWT (`jwt`) instead of the stale `python-jose` skip guard, then runs
multi-seed intake including a literal `cloud_ref:aws_s3:...` operator seed,
ROE/scope-manifest launch, artifact/cloud/identity discovery, deterministic
validation/finding gates, connector catalog
free-first/read-only-gated readiness, active-validation lab proof, monitoring
snapshot/diff/alerting, owner-routed monitoring-alert remediation, scoped lab
fix-verification retest with active-validation feedback into resolved/passed
remediation state, secret lifecycle owner routing/remediation guidance, local
standards/STIX enrichment, graph/MTGX export, dashboard review sections,
template-to-raw JSON/CSV fallback with checksums, audit manifest verification,
API download parity, first-class cloud-ref inventory as unvalidated/non-reportable
until validated, and cleanup/no ID reuse in one local mocked path.
Verification: expanded canonical E2E passed (`1 passed`), focused CTEM module
bundle passed (`104 passed` across monitoring, active validation, secrets
lifecycle, standards, and connector registry), py_compile passed for the E2E and
cloud-asset metadata helper, Ruff passed for both touched code files, the
cloud-ref classifier plus canonical E2E bundle passed (`55 passed`), and
`git diff --check` passed for the touched E2E/helper/docs.
Backprop: `SPEC.md` B80 records the stale `python-jose` guard and missing
canonical CTEM proof gap. Follow-up verification also passed the canonical E2E
plus cleanup-script contract (`7 passed`) and the focused CTEM bundle again
(`104 passed`). A non-destructive `%TEMP%` cleanup inventory still found 25
pre-existing pytest engagement temp dirs; no deletion was performed because
file deletion needs explicit user confirmation.
Latest loop-proof verification: `python -m py_compile
tests\integration\test_canonical_release_e2e.py` passed; `python -m ruff check
tests\integration\test_canonical_release_e2e.py` -> `All checks passed!`;
`pytest
tests\integration\test_canonical_release_e2e.py::test_canonical_release_e2e_proves_all_surfaces_and_cleanup
-q` -> `1 passed`. `SPEC.md` B249 records the monitoring-alert ->
remediation -> active-validation retest feedback-loop proof.
Latest tenancy proof verification: `python -m py_compile
tests\integration\test_webui_rbac.py` passed; `python -m ruff check
tests\integration\test_webui_rbac.py` -> `All checks passed!`; `pytest
tests\integration\test_webui_rbac.py::test_ctem_engagement_routes_are_workspace_isolated
-q` -> `1 passed`. `SPEC.md` B250 records the original CTEM cross-workspace
route matrix, and `SPEC.md` B269 records the expanded enterprise read-surface
proof: a beta principal with broad CTEM/read permissions still cannot list,
download, tail, query, or subscribe to alpha engagement report artifacts, logs,
run lists, scan progress, tasks/workers/queue metrics, legacy numeric
asset/vulnerability endpoints, or `/ws/progress`; denied REST responses stay 404
without alpha slug/name/body text, and the websocket closes with policy code
`1008`.
Latest release-readiness verification: dashboard generation is now explicit
`data_dir` scoped by default; operator CLI dashboard refresh paths opt into
legacy cwd discovery explicitly. This fixed reporting verification timeouts in
workspaces with many local `.forge_data/engagements` DBs. Verification passed:
dashboard file (`37 passed`), reporting dashboard/webui/evidence/timeline bundle
(`54 passed`), engagement-enrichment helper tests (`5 passed`), canonical CTEM
E2E (`1 passed`), RBAC/platform auth (`11 passed`),
monitoring/remediation/active-validation (`79 passed`),
graph/secrets/standards/connectors (`78 passed`), and doctor/demo/packaging
(`52 passed`, `1 skipped` because Helm is not installed). `SPEC.md` B251
records the dashboard hermeticity bug and fix.
Latest Windows scheduled-task checkpoint: the TPH import task quote-stripping
failure is covered by temp-script watchdog helpers plus `-WatchdogSelfTest`, and
live inspection showed the remaining stuck `Running` state came from optional
WMI stale-watchdog process scans timing out before import startup. The script now
keeps stale temp-file cleanup on by default but makes stale watchdog helper
process scanning opt-in with `-StaleHelperProcessCleanup`; explicit stale
import-process cleanup remains behind `-StaleProcessCleanup`. The stale live
scheduled-task instance was stopped and Task Scheduler returned to `Ready` for
the next run. Verification passed watchdog self-test, `tests/core/test_windows_launchers.py`
(`12 passed`), and `tests/cli/test_targets_import.py` (`11 passed`). `SPEC.md`
B252 records the root cause and fix.
Latest cloud-graph-depth checkpoint: attack-path exposure summaries now include
explicit toxic-combination labels plus scrubbed cloud context. A public internet
path through sensitive S3 data to wildcard/admin IAM now surfaces
`public_sensitive_data_exposure`, `privileged_identity_to_sensitive_data`, and
`public_to_privileged_sensitive_data_path`, along with account refs, regions,
sensitivity tiers, workloads, and identity refs. Verification passed
py_compile/Ruff for `forge/graph/assets.py` and `tests/graph/test_asset_graph.py`,
the full graph suite (`15 passed`), and dashboard/API graph touchpoints
(`2 passed`). `SPEC.md` B253 records the Wiz/Orca-style toxic-combination
summary gap and fix.
Latest cloud choke-point checkpoint: choke points now carry
`blast_radius_summary` with reachable counts, critical asset refs,
entity/risk-tier counts, risk tags/factors, toxic combinations, and scrubbed
cloud context. The focused graph regression proves finding choke points
summarize proof/ownership reachability while the sensitive S3 cloud-asset choke
point exposes account, region, sensitivity, workload, identity, and
public-sensitive-data-plus-privileged-IAM toxic-combination blast radius.
Verification passed `python -m py_compile forge\graph\assets.py
tests\graph\test_asset_graph.py` and
`pytest tests\graph\test_asset_graph.py::test_sync_engagement_asset_graph_projects_existing_evidence_idempotently
-q` (`1 passed`). `SPEC.md` B262 records the checkpoint.
Latest dashboard graph checkpoint: static dashboard/report choke-point rows now
render the new blast-radius context as critical asset refs, risk mix, toxic
combinations, and scrubbed cloud context. The dashboard fixture now includes a
public sensitive S3 asset with privileged IAM/workload context and proves
`accounts=123456789012`, sensitivity, critical refs, and
`public_sensitive_data_exposure` appear in JSON/HTML while IAM tokens stay
scrubbed. Verification passed py_compile/Ruff for `forge/reporting/dashboard.py`
and `tests/reporting/test_dashboard.py`, plus the paired graph/dashboard
regression (`2 passed`). `SPEC.md` B263 records the checkpoint.
Latest doctor/operator setup checkpoint: `forge doctor --json` now emits a
top-level `action_plan` and a `Connector Action Plan` check. The plan groups
free connector setup into `install_free_binaries`, `run_free_connectors`,
`configure_optional_keys`, `review_catalog_only`,
`keep_active_validation_fail_closed`, and `review_paid_adapters`, using only
connector IDs, binary names, env var names, and commands. Verification passed
py_compile/Ruff for `forge/doctor.py` and `tests/cli/test_doctor.py`, and the
full doctor suite (`39 passed`). `SPEC.md` B264 records the checkpoint.
Latest doctor/provider setup checkpoint: the doctor `action_plan` now also
includes `review_paid_llm_backends`, `enable_live_validation_only_after_roe`,
and `run_live_provider_probes_if_intended`, sourced from the existing paid LLM,
active-validation, and LLM provider checks. Static provider readiness, live
provider discovery, missing-provider states, paid-backend enablement, and live
active-validation enablement are now machine-readable setup actions without
secret values. Verification passed py_compile/Ruff for `forge/doctor.py` and
`tests/cli/test_doctor.py`, and the full doctor suite (`39 passed`). `SPEC.md`
B265 records the checkpoint.
Latest README/CLI drift checkpoint: the public command docs now have a
command-level registry guard, not only a group-level guard. The test compares
README public command lines against every registered public modular subcommand
for targets, monitoring, remediation, active-validation, connectors, standards,
workspaces, and retention. README now includes remediation `handoff-plan`,
`integration-runbook`, `import-ticket-statuses`, and `workspaces audit`.
Verification passed py_compile/Ruff for `tests/cli/test_cli_registry.py` and
the full CLI registry suite (`18 passed`). `SPEC.md` B266 records the
checkpoint.
Latest README/default drift checkpoint: README now distinguishes standalone
`forge report generate --provider` from kill-chain `--report-provider`,
documents `forge demo proof-pack` default engagement id `9901`, narrows
`--engagement` auto-derivation to kill-chain versus existing-engagement
commands, and lists exact snake_case doctor `action_plan` IDs. The CLI registry
tests now verify these docs against Typer help/defaults and README text.
Verification passed py_compile/Ruff for `tests/cli/test_cli_registry.py` and
the full CLI registry suite (`20 passed`). `SPEC.md` B267 records the
checkpoint.
Latest secrets-lifecycle checkpoint: secret prevention plans now include
value-free artifact templates for `.pre-commit-config.yaml`,
`.github/workflows/forge-secret-scan.yml`, and `.git/hooks/pre-push`, generated
from existing Gitleaks, detect-secrets, TruffleHog, and provider
push-protection guidance. No files are written and no raw/encrypted secret
material is included. Verification passed py_compile/Ruff for
`forge/secrets/lifecycle.py` and `tests/secrets/test_secret_lifecycle.py`, the
full secrets suite (`7 passed`), connector free-first/prevention export tests
(`2 passed`), and the doctor operator-readiness row test (`1 passed`).
`SPEC.md` B254 records the workflow-template gap and fix.
Latest remediation-integration checkpoint: live optional ticket/SOAR/SIEM
adapters already existed, but operators lacked a free-first review artifact
before enabling paid/write-capable systems. `remediation_ticket_handoff_plan`
and `forge remediation handoff-plan` now generate sanitized per-connector
request/body templates for local JSONL/stdout, generic webhook, GitHub Issues,
Jira, ServiceNow, Tines, Splunk HEC, and Torq without network calls, file
writes, or ticket-event inserts. Verification passed py_compile for
`forge/remediation/connectors.py`, `forge/remediation/cli.py`, and
`tests/remediation/test_connectors.py`, focused handoff function/CLI tests
(`2 passed`), the full remediation suite (`24 passed`), and Ruff for the
touched remediation files. `SPEC.md` B255 records the handoff-preview gap and
fix.
Latest ticket-status reconciliation checkpoint: external remediation
integrations now have a free-first inbound path. `import_remediation_ticket_statuses`
and `forge remediation import-ticket-statuses --file statuses.jsonl` consume
operator-supplied JSON/JSONL exports, map known external states back to Forge
remediation status, keep unmatched/unknown rows in review output, strip
secret-bearing ticket URLs, and write audit receipts only when not in dry-run.
Verification passed focused importer function/CLI tests (`2 passed`),
py_compile for the touched remediation files, the full remediation suite
(`26 passed`), and Ruff for the touched remediation files. `SPEC.md` B256
records the inbound reconciliation gap and fix.
Latest ticket-status batch checkpoint: inbound reconciliation now supports
operator/scheduled shared exports across `FORGE_DATA_DIR`. `import_remediation_ticket_statuses_for_data_dir`
and `forge remediation import-ticket-statuses --data-dir ... --file statuses.jsonl`
group JSONL rows by `engagement_id`, aggregate dry-run/apply summaries per DB,
preserve foreign engagement rows for review, and update only matched engagement
items. Verification passed focused batch importer/CLI tests (`2 passed`),
py_compile for touched remediation files, the full remediation suite
(`28 passed`), and Ruff for `forge/remediation/connectors.py`,
`forge/remediation/runner.py`, `forge/remediation/cli.py`, and
`tests/remediation/test_connectors.py`. `SPEC.md` B257 records the batch import
gap and fix.
Latest scheduled reconciliation checkpoint: Windows operator wrappers now make
the batch inbound status import repeatable. `scripts/run_remediation_ticket_status_import_task.ps1`
logs to `scripts/scheduled/forge_remediation_ticket_status_import*.log`,
invokes `forge remediation import-ticket-statuses --data-dir ... --file ... --json`,
defaults to `--dry-run`, and requires explicit `-Apply` for DB mutation.
`scripts/install_remediation_ticket_status_import_task.ps1` installs
`FORGE Import Remediation Ticket Statuses` with an execution budget and
`MultipleInstances IgnoreNew`. Verification passed the runner self-test,
focused launcher wrapper tests (`2 passed`), full Windows launcher tests
(`14 passed`), full remediation suite (`28 passed`), py_compile for touched
Python files, and Ruff for touched Python files. `SPEC.md` B258 records the
scheduled-wrapper gap and fix.
Latest doctor/operator-readiness checkpoint: `forge doctor` now includes a
value-free `Remediation Ticket Status Import` row. It remains `OFF` until
configured, verifies the status-import runner/installer scripts, checks that the
configured JSON/JSONL status export exists without reading or printing file
contents, queries the Windows scheduled task only when relevant, and guides
operators toward dry-run-first installation before `-Apply`. Verification
passed focused remediation-status-import doctor checks plus existing TPH bridge
checks (`4 passed`), full doctor suite (`39 passed`), full Windows launcher
tests (`14 passed`), py_compile for `forge/doctor.py` and
`tests/cli/test_doctor.py`, and Ruff for touched Python files. Ruff reported an
access-denied warning while writing its cache file, but lint itself passed.
`SPEC.md` B259 records the doctor-discoverability gap and fix.
Latest remediation approval-policy checkpoint: inbound ticket-status imports
now support explicit external-closure policy. `--close-policy require_retest_for_resolved`
on `forge remediation import-ticket-statuses`, the data-dir runner path, and
the scheduled PowerShell wrapper maps external closed/fixed states to
`retest_pending` with `retest_status=pending` plus reconciliation policy
metadata, instead of treating ticket-system closure as Forge resolution. The
default remains `trust_external_status` for compatibility. Verification passed
focused policy/CLI/launcher tests (`4 passed`), runner self-test with
`-ClosePolicy require_retest_for_resolved`, full remediation suite (`30 passed`),
full Windows launcher tests (`14 passed`), py_compile for touched remediation
and launcher test files, and Ruff for touched Python files. `SPEC.md` B260
records the fix-verification policy gap and fix.
Latest remediation runbook checkpoint: `remediation_integration_runbook()` and
`forge remediation integration-runbook --json` now emit a value-free operating
runbook for local JSONL/stdout, GitHub Issues, Jira, ServiceNow, Tines, Splunk
HEC, and Torq. It ties together setup gates, dry-run handoff review, optional
live `sync-tickets`, inbound `import-ticket-statuses`, scheduled importer
installation, and close-policy guidance without network calls, file writes, or
secret-bearing URLs. Verification passed focused runbook function/CLI tests
(`2 passed`), py_compile for touched remediation files, full remediation suite
(`32 passed`), and Ruff for touched remediation files. `SPEC.md` B261 records
the operator-runbook gap and fix.
Graph/workflow checkpoint: `forge/graph/assets.py` now adds per-path exposure
summaries and recommended actions to attack paths, and
`forge/remediation/workflow.py` adds
`draft_remediation_from_asset_graph_candidates()` to create idempotent local
`asset_graph` remediation drafts from minimal-fix candidates. The schema and
migration runner now allow `asset_graph` as a remediation source. This is
passive local workflow creation only: no ticket sync, active validation, network
calls, or intrusive behavior. Verification passed py_compile, Ruff, focused
graph/remediation regressions (`2 passed`), full graph/remediation suites
(`31 passed`), schema/control checks (`3 passed`), and `git diff --check`.
Backprop: `SPEC.md` B81 records the previously disconnected graph-prioritization
to remediation-workflow gap.
Graph/remediation API checkpoint: the same graph-derived remediation draft path
is now operator-reachable through
`POST /api/engagements/{engagement_ref}/remediation/draft-from-asset-graph`.
The route requires `remediation:write` plus `assets:read`, validates `limit`,
and returns refreshed remediation items, summary, and review queue while
remaining passive/local. Route/helper regressions cover success with real graph
minimal-fix candidates, idempotent redraft, both permission denials, invalid
limit handling, secret-scrubbed graph metadata, and the central web permission
matrix entry for the new endpoint. Verification passed focused route/helper
pytest (`2 passed`), follow-up permission-matrix plus route pytest (`2 passed`),
py_compile, and Ruff for the touched route/app/test files. Backprop: `SPEC.md`
B82 records the workflow-service to web-API gap.
Doctor graph-remediation checkpoint: `forge doctor` now surfaces the new
graph-to-remediation path during operator readiness review. The Remediation
Review Queue row counts undrafted asset graph minimal-fix candidates when graph
tables are present, warns with both the CLI draft command and web API route, and
keeps evidence/metadata redacted. Verification passed the explicit remediation
queue doctor regressions (`3 passed`), the standalone graph-candidate doctor
regression (`1 passed`), py_compile, and Ruff for `forge\doctor.py` plus
`tests\cli\test_doctor.py`. Backprop: `SPEC.md` B83 records the doctor
discoverability gap.
Graph/remediation CLI checkpoint: the doctor/README path now exists as
`forge remediation draft-from-asset-graph --engagement N --json`. It uses the
normal remediation CLI DB opener, calls the idempotent graph draft service, and
emits JSON or a bounded human summary without ticket sync, active validation,
network calls, or intrusive behavior. Verification passed the focused CLI draft
regression (`1 passed`), remediation CLI subset (`6 passed`), CLI registry
modular command group regression (`1 passed`), py_compile, and Ruff for the
touched remediation CLI/test files. Backprop: `SPEC.md` B84 records the missing
documented CLI command gap.
Graph/remediation dashboard checkpoint: the live React Remediation panel now
has a `Draft graph fixes` action beside graph owner propagation. It requires
live API access, calls `/remediation/draft-from-asset-graph`, refreshes
remediation state, and reports drafted/candidate counts while preserving the
same passive/local behavior: no ticket sync, active validation, network calls,
or intrusive behavior. Verification passed the React remediation contract
regression (`1 passed`), React production build, and Ruff for the contract test.
Backprop: `SPEC.md` B85 records the missing dashboard workflow action.
Graph/remediation loop checkpoint: graph-derived remediation drafts now resync
the asset graph after successful upserts, and `asset_graph` remediation
`finding_ref` values resolve back to existing graph entity keys before falling
back to synthetic findings. Drafted graph fixes now show up immediately as
remediation nodes with `remediates` edges to the original candidate entity
instead of detached `finding:asset_graph:*` nodes. Verification passed focused
graph/remediation draft plus CLI regressions (`2 passed`), adjacent graph
projection/account-context regressions (`2 passed`), py_compile, and Ruff for
the graph/remediation workflow/test files. Backprop: `SPEC.md` B86 records the
missing graph-loop closure.
Standards checkpoint: the default Phase 0 NVD cache now captures
`cvssMetricV40` base scores and vector strings plus v3/v2 vectors, migrates
existing local `cvss_scores` tables on write, and exposes v4 through
`kb_query` and `lookup_local_cve_metadata()` so normal `forge kb sync` data can
drive the existing CVSS v4 preference. STIX external-reference URLs and Forge
target URLs are sanitized for userinfo, sensitive query parameters, and
sensitive fragments before local STIX/TAXII import/export handoff. Local STIX
2.1 vulnerability bundles can now enrich existing CVE findings with CVSS, EPSS,
KEV, CWE/CPE, ATT&CK, object ID/name, and sanitized refs without creating new
findings. `forge standards import-stix --engagement N --bundle-file bundle.json`
is the operator path, with `--dry-run --json` preview and match-only processing.
`forge standards export-stix --engagement N --bundle-file forge-stix.json
--taxii-manifest-file forge-taxii-manifest.json --json` writes sanitized STIX
bundle and TAXII-style manifest files from stored findings.
`forge doctor` now includes a `Standards Exchange` row that scans engagement DBs
for v41 standards columns, reports vulnerability/metadata/exchange-identifier
counts, and flags stale schemas before local STIX/TAXII import/export.
Latest local STIX import verification passed for py_compile/Ruff. Focused
standards, doctor, and connector-registry suites passed (`8 passed`, `34
passed`, `38 passed`). Side audit `Mill` identified the default-NVD CVSS v4
ingestion gap. README public commands now list the `forge standards
import-stix|export-stix` operator path, and `tests/cli/test_cli_registry.py`
guards documented public groups against the Typer registry builder and shipped
root `forge.cli.app` (`4 passed`).
`forge.connectors.registry` now exposes that posture as a shared connector
catalog: `forge connectors list --json` reports passive parsers,
ProjectDiscovery/local secrets tooling, optional Shodan/Censys/HIBP/GitGuardian
paths, remediation ticket adapters, local standards enrichment, and future
active-validation plugins with cost profile, safety class, readiness, outputs,
gates, execution paths, runner support, and execution status. `forge connectors
run` now has four runnable ProjectDiscovery paths:
Subfinder persists scoped subdomain seeds, HTTPX imports scoped JSONL probe
output into sanitized crawl/URL seed/host/service evidence, and Katana runs
bounded JSONL crawling with safe depth/rate defaults while persisting scoped
discovered URLs as crawl rows and URL seeds. Nuclei now requires explicit
templates, caps severity/rate gates, imports scoped JSONL matches into
standards-aware `vulnerability_findings`, and omits raw request/response
evidence from results. All four skip out-of-scope tool output. Catalog rows distinguish wired operator paths from catalog-only or
planned-fail-closed entries, and `forge doctor` summarizes those counts while
reporting Connector Catalog `WARN` when free-first local connector binaries are
missing instead of treating a static catalog as fully ready.
The connector catalog now has a manifest-only extension lane: local
`forge.connector.plugin.v1` JSON files under
`FORGE_DATA_DIR/connector_plugins`, `FORGE_CONNECTOR_PLUGIN_DIR(S)`, or
`forge connectors list --plugin-dir PATH` register `plugin_` catalog rows only.
Validation rejects unsafe safety classes, Forge runner claims, invalid
env/binary names, and manifests missing gates such as `scope_manifest`,
`rate_limit`, `write_permission`, or `paid_opt_in`; `active_validation`
manifests are accepted only as catalog-only `active_validation_gated` entries
with `approval`, `roe_id`, `scope_manifest`, and `live_gate`;
`forge connectors plugin-validate --json` reports valid/invalid manifests for
CI or pre-demo checks. No plugin code is imported or executed by this catalog
path. `forge doctor` now reports active-validation plugin manifest counts
separately in the Connector Catalog row and repeats the catalog-only
approval/ROE/scope/live-gate posture. The React Connector Catalog panel now
also shows plugin manifest counts, active-validation plugin counts,
plugin-catalog execution counts, runner-path counts, and per-row
source/execution/runner state. Invalid plugin manifests now fail closed during
operator review: doctor reports a Connector Catalog warning with
`forge connectors plugin-validate --json` remediation, and the live connector
catalog API maps registry validation errors to HTTP 400 for dashboard load
errors. The first catalog-backed
execution paths include `forge connectors run --engagement N --connector
projectdiscovery_subfinder --target DOMAIN` and
`forge connectors run --engagement N --connector projectdiscovery_nuclei --target URL --template TEMPLATE --severity high --rate-limit 5`:
they resolve the matching local ProjectDiscovery binary, refuse targets outside
engagement scope, support dry-run without requiring the binary, skip
out-of-scope output, and append connector audit rows. ProjectDiscovery run
results now expose `gates`, `budgets`, and `plan` fields for operator preview:
scope/output-filter gates, concurrency `1`, queue item `1`, bounded timeout,
connector rate/depth settings, and a capped `--max-results` import budget that
is applied before persistence and recorded in audit text. `forge connectors import-discovery --connector
shodan_host_lookup|censys_lookup|urlscan_search` now provides the first Shodan/
Censys/urlscan provider report import path: it accepts operator-supplied JSON,
scope-gates observed hostnames/IPs and urlscan page/task URLs, persists
in-scope hosts/services/seeds/crawl rows with provider provenance, queues
sanitized urlscan URLs for recursive URL mining, and keeps provider report
bodies/API keys out of results and audit rows. The
secrets connector path now also supports
`forge connectors run-secrets` for bounded local Gitleaks/TruffleHog execution
against an operator-supplied path plus `forge connectors import-secrets` for
existing Gitleaks JSON reports and TruffleHog newline JSON reports; imported
rows are scope-bound to the engagement domain, raw scanner secrets are reduced
to redacted display values only, and the same call syncs
`secret_lifecycle_items` for owner routing, suppression, and revocation
guidance. The static dashboard JSON/HTML and React detail route now also show a
redacted Secret Lifecycle inventory beside validation inventory, including
owner routing, suppression state, remediation status, and revocation/prevention
guidance without raw or encrypted secret material. `forge connectors
secret-prevention-plan --engagement N --json` now exports the full value-free
pre-commit/PR/push prevention plan from those lifecycle rows, including target
artifact names and commands without raw or encrypted secret material.
Verification for that
dashboard/UI slice: py_compile, Ruff, React web UI contract (`9 passed`),
React production build, new static dashboard lifecycle regression (`1 passed`),
and adjacent key-validation proof dashboard regression (`1 passed`). The
combined two-test dashboard selector timed out at 244s on this workspace; both
selected tests passed individually. `forge connectors run-identity --connector
hibp_pwned_passwords` now
provides the first free/no-key identity exposure runner: it checks already
stored SHA-1/NTLM password hashes through the HIBP Pwned Passwords range API or
an operator-supplied offline corpus, stores only pwned-count metadata plus
remediation items, and never returns/audits plaintext passwords or full hashes.
Monitoring policies can also opt into these connectors via
refresh metadata; the scheduler prevalidates every target, skips out-of-scope
targets without process execution, records unsupported or missing-binary evidence
in sanitized snapshot summaries, and omits connector command/stdout/stderr from
monitoring refresh payloads; pwned credential matches become normal
`identity_exposure` monitoring findings for scheduled diffs and alerts, while
Shodan/Censys/urlscan report imports become normal host/seed/URL additions for
exposure diffs and alerts.

Current intake checkpoint: literal cloud refs now enter through the same
multi-seed path as domains/IPs/URLs/emails/phones/usernames/names/companies.
`cloud_ref:aws_s3:bucket`, `aws_s3:bucket`, `s3://bucket`, `gs://bucket`,
`azure://account/container`, and provider URL-form refs classify as
`cloud_ref`, canonicalize deterministically, dedupe alternate forms, and the
CLI seed persistence path immediately promotes them into `cloud_assets` without
adding live scanner behavior or weakening scope gates.

Latest checkpoint (2026-08-11): the enterprise CTEM roadmap checkpoint is active
at `docs/engagement_overhaul_tasklist.md` -> `## Compact active backlog`.
First Priority 0 foundation slice is in the working tree: JWTs now expose a
`Principal` while preserving `verify_token()` compatibility; migration v27 adds
`workspaces`, `workspace_memberships`, and `engagements.workspace_id`; web UI
engagement creation seeds workspace membership; `/ws/progress` now requires a
valid bearer token; web UI engagement list/detail/update/seed/run/log/artifact
and integer-ID task/asset/action APIs now enforce the caller's workspace claim;
platform API workflow/report routes now require JWT permissions while `/health`
and `/ready` stay public; explicit non-legacy tokens now need DB workspace
membership, explicit wildcard tokens no longer bypass membership, engagement
create/write plus command-center execute/approve/sentry controls require
permissions, broader web UI API read/write/control routes now gate automation,
runs, logs, artifacts, scans, tasks, workers, queue metrics, assets, findings,
actions, timeline, and raw dashboard data by capability, `/ws/progress` is
scoped to an authorized engagement, HTMX
engagement detail routes require authenticated workspace access, and generated
dashboard JSON under `/data` is served through scoped dynamic responses. Focused
migration/auth/websocket, cross-workspace deny, platform permission,
membership-bypass, action/sentry gate, HTMX auth, generated-dashboard-data, and
web UI permission-matrix tests cover the slice. The checkpoint is not complete:
latest websocket polish now has every live client entry point passing
`engagement_id` plus a JWT over the `forge-progress` WebSocket subprotocol, and
the server accepts subprotocol JWTs while still fail-closing missing token,
missing engagement, or unauthorized engagement connections.
`forge.webui.rbac` now centralizes role-derived permission grants for
`viewer`, `operator`, and owner/admin tokens; explicit role-only JWTs no longer
fall back to legacy wildcard permissions, namespace wildcards like
`engagements:*` are supported, `/api/token` now defaults to a role-scoped
`operator` token instead of a legacy wildcard token and only grants broad
owner/admin workspace access when explicitly requested, read-only seed listing
is allowed, and mutating engagement update plus asset-graph rebuild routes
require write permissions. Focused PyJWT, platform auth, and web UI engagement
API regressions cover this RBAC tightening.
Platform workflow/report tenancy is also started: `/workflows` stores workspace
metadata in the existing `_params` checkpoint payload, rejects creation into an
unauthorized workspace, and enforces workspace access on status, advance, fail,
history, replay, and `/reports` through control-DB membership checks for
explicit scoped tokens. A same-workspace JWT claim without a
`workspace_memberships` row is denied unless the principal has the explicit
`workspaces:any` override. Cross-workspace status/mutation/report/history/replay
access uses the same not-found response as missing workflows. Focused platform
auth/history/report route tests cover claim-only denial and cross-workspace 404
behavior without a state-store migration.
central tenancy index foundation is now in the working tree:
`forge/db/control.py` creates `.forge_data/control.db` with `workspaces`,
`workspace_memberships`, and `engagement_index`; web UI engagement
create/update/list/detail/artifact/path resolution uses it as a verified
candidate source while still re-checking the per-engagement DB row before detail
or mutation paths are returned. The index now stores sanitized `summary_json`,
summary version, DB/WAL/SHM fingerprint, `last_seen_at`, and `missing_since`;
fresh list summaries can be served from `control.db` without opening every
engagement DB, while stale summaries fall back to verified per-engagement reads.
Engagement `operator` values are metadata only: control indexing and workspace
backfill no longer create owner memberships from mutable operator fields.
`forge doctor` now reports workspace membership/control-index readiness across
local engagement DBs so invisible legacy/manual DB state is caught before web
demo or self-host rollout.
Workspace administration is now surfaced through `/api/workspaces` plus
`/api/workspaces/{workspace}/members` list/upsert/delete routes behind
`workspaces:read`, `workspaces:write`, and `workspaces:members:write`; scoped
callers stay bound to their membership workspace, while owner/admin wildcard
tokens can manage all workspaces. The matching operator CLI now registers
`forge workspaces list|upsert|members|member-set|member-delete` with JSON output
for automation, role-derived permissions, explicit custom grants, confirmation
for deletion, and redaction of secret-bearing workspace metadata. The live
React overview also has a workspace-administration panel for scoped workspace
listing, metadata upsert, member grant/revoke, and selected-workspace engagement
creation.
Control-plane administration now has its own append-only audit trail:
`control_audit_events` in `control.db` records workspace upserts, membership
grants/updates, and membership deletes with redacted payloads, actor/subject,
source surface, and previous/current event hashes. SQLite triggers reject
updates/deletes to the control-audit table, and `forge doctor` reports
hash-chain validity plus append-only trigger readiness. Operators can review it
with `forge workspaces audit --workspace ID --json`; the web API exposes
`/api/workspaces/{workspace}/audit` behind workspace read access. The live
React engagement workspace now renders that scoped feed as a workspace-audit
panel with actor/source/hash fields and redacted payload previews.
The stale `python-jose` import skip was removed so PyJWT/RBAC web UI regressions
run instead of being skipped.
Non-web indexing is also started: `index_engagement_db_file()` builds sanitized
minimal summaries from local engagement DBs, target-feed imports index new
engagements, and CLI kill-chain bootstrap best-effort indexes freshly ensured
engagement rows. Control-index tombstone lifecycle is now started: missing
indexed DB rows are hidden from normal lists, exposed through a
workspace-filtered tombstone API, and purged after
`FORGE_CONTROL_TOMBSTONE_RETENTION_DAYS` without deleting engagement DBs or
artifacts. Remediation foundation is also started: schema/migration v28 adds
`remediation_items`; web API routes list/upsert/update remediation owner/SLA/
status/ticket/risk-acceptance reason plus expiry/review date/retest state; `remediation:read`,
`remediation:write`, `remediation:accept`, and `remediation:retest` gate normal
workflow, risk acceptance, and retest transitions, with new accepted-risk writes
requiring both a reason and `risk_acceptance_expires_at`; response payloads
classify accepted risk as current, expiring soon, expired, missing-expiry, or
invalid-expiry and summarize the review-due queue; `forge remediation
review-queue` plus `GET
/api/engagements/{engagement}/remediation/review-queue` expose the operator
queue for unowned active work, missing tickets, overdue SLAs, accepted-risk
reviews, and pending/blocked retests; `remediation:export` gates CSV/JSON
export and includes that queue; audit rows record remediation
upserts/updates/exports; the React engagement detail view now has a first-class
remediation workflow panel with live item cards, review-queue rows,
owner/status/SLA/risk expiry/review/retest/ticket editing, JSONL ticket sync,
and JSON/CSV export links. Next
operational schema-drift hardening now covers that risk-expiry field:
`apply_schema()` defers the migration-owned remediation risk-expiry index when
legacy DBs lack the column, and `run_migrations()` repairs current-version DBs
that are missing `risk_acceptance_expires_at` before seed-run recovery or
scheduled target imports query remediation state. Static dashboard refresh now
also tolerates legacy remediation tables that lack that additive column by
rendering an empty risk-expiry value and skipping only the derived review-queue
section that requires the column. `forge exploit correlate` now treats invalid
placeholder SQLite cache files the same as missing caches, recording a controlled
skip instead of surfacing `DatabaseError: file is not a database` during
scheduled-run finalization. Next continuous-monitoring foundation is also
started: schema/migration v29 adds
monitoring policies, snapshots, changes, and alerts; `forge.monitoring.continuous`
collects deterministic exposure state from hosts/emails/cloud assets/
vulnerabilities/key findings/cloud validations; API routes create baseline and
diff snapshots, list monitoring state, upsert policies, and acknowledge/resolve
alerts behind `monitoring:read`/`monitoring:write`; due-policy execution now
finds enabled policies whose `next_run_at` is due, creates scheduled snapshots,
advances run times, records diff alerts, and writes `monitoring_policy_due_run`
audit rows; `forge monitoring status --json` provides a read-only
operator/cron health summary without running jobs or delivering alerts,
including unrouted open alert, suppressed delivery row, and active suppression
counts beside open and failed alerts; `forge
monitoring run-due` provides a local operator/cron runner across numeric
engagement DBs; `forge monitoring worker` provides a long-lived local polling
worker with bounded `--iterations` support for smoke tests and service
supervisors; due-policy execution now accepts a refresh-before-diff
callback so runner/service integrations can run safe passive refresh work
before the scheduled snapshot, while recording refresh completed/skipped/failed
status into snapshot summaries and audit result payloads; the local runner also
has a metadata-gated `seed_exposure` refresh that performs no network calls and
promotes non-failed domain/subdomain/IP/URL/email/cloud-ref seeds before
diffing, plus a metadata-gated `projectdiscovery_subfinder` connector refresh
for scoped free/local passive subdomain discovery; the same connector refresh
path can now schedule scoped local `gitleaks_local`/`trufflehog_local` secret
scanner runs when policy metadata supplies a `domain` and `source_path`, and
monitoring snapshots keep only sanitized run counts/source paths instead of
scanner commands/stdout/report bodies; schema/migration v31 adds
`monitoring_alert_deliveries`,
and `forge monitoring deliver-alerts` delivers open alerts to local JSONL by
default, stdout for shell pipelines, or an explicitly configured generic
webhook, while the worker can deliver after each scan when delivery flags are
supplied; schema/migration v32 adds `monitoring_alert_routes` and
`monitoring_alert_suppressions`, delivery matches enabled routes by severity,
alert type, and entity prefix, includes owner/escalation metadata in alert
payloads, and records suppressed alerts as skipped deliveries; web monitoring
overview responses now include configured alert routes and suppressions, and
monitoring write APIs can upsert routes or add suppressions with audit rows;
`forge doctor` now reports monitoring schedule readiness, including stale
tables, idle policy state, due/overdue enabled policies, open alerts, and
failed delivery rows without running scheduled jobs; static dashboard JSON/HTML
and live engagement detail payloads now expose monitoring policies, snapshot
trend rows, exposure changes, alert status, alert routes, and suppressions;
schema/migration v33 allows `monitoring_alerts` as remediation
sources, and the monitoring alert remediation API now upserts one owner-aware
remediation item per alert using matching route owner/escalation metadata,
optional SLA days, optional ticket refs, API audit rows, and dashboard/detail
visibility; schema/migration v34 adds idempotent `remediation_ticket_events`,
the remediation connector layer emits ticket create/update payloads to local
JSONL by default, stdout for shell pipelines, or an explicitly configured
generic webhook, `forge remediation sync-tickets` gives operators a cron/script
entry point, and the web API/dashboard can sync one remediation item to local or
explicitly configured remote ticket/SOAR/SIEM destinations; schema/migration v35 adds `github_issues` as an optional ticket-event
connector, and `forge remediation sync-tickets --github-repo owner/repo` creates
or updates GitHub Issues when a token env var is supplied while recording issue
number/URL metadata without printing the token; schema/migration v36 adds Jira
Cloud create/update support behind `--jira-base-url`, `--jira-project-key`, and
Jira email/token env vars while recording issue key/URL/method metadata without
printing the token; schema/migration v37 adds optional ServiceNow Table API
create/update support behind `--servicenow-instance-url`, table selection, and
basic/bearer auth env vars while recording number/sys_id/URL/method metadata
without printing credentials; schema/migration v45 adds optional Tines,
Splunk HEC, and Torq delivery behind explicit operator-supplied URLs/token env
vars. The React remediation panel now exposes those destinations through the
same sync-ticket route while accepting env var names instead of token values.
Tines/Torq post remediation automation events to webhooks, Splunk HEC indexes a
remediation event envelope with `Authorization: Splunk <token>`, and metadata
stores platform labels plus redacted webhook destination keys without printing
token values. Missing connector credentials and per-item connector
configuration errors are now recorded as failed `remediation_ticket_events` with
sanitized error metadata instead of aborting the whole batch; `forge doctor`
now checks existing engagement DBs for the remediation ticket-event ledger and
current ticket/SOAR connector enum coverage before operators rely on connector
sync; latest ticket-event status is now operator-visible in the remediation
review queue, static dashboard, and React review-queue rows, including failed
sync reason labels, connector, attempt count, and redacted destination/error
text that clears once a later delivered event exists; schema/migration v38 adds canonical
`asset_entities`, `asset_relationships`, and `asset_ownership_claims`;
`forge.graph.assets` projects existing seeds, relations, hosts/services,
identities, cloud assets, validations, key findings, vulnerability findings,
remediation items, tickets, and validation claims into scrubbed graph rows; and
`forge graph sync-assets` plus `forge graph ownership list|set` provide the
first local operator path for asset attribution and ownership claims; `forge
graph attribution import --file attributions.json|csv` now imports local
subsidiary, acquisition, third-party, cloud-account, and cloud-org attribution
records into confidence-scored organization/owner/cloud graph nodes,
relationships, and ownership claims without live provider calls; live engagement
APIs now expose asset-graph read, rebuild, ownership-claim upsert, and batch
attribution import routes behind `assets:read`/`assets:write`; and static
dashboard detail JSON/HTML now surfaces asset graph entity, relationship,
ownership, and summary sections without rendering scrubbed secret metadata.
Ownership conflict resolution is now operator-actionable too: `forge graph
ownership resolve --entity-key KEY --owner OWNER` and
`POST /api/engagements/{engagement}/asset-graph/ownership-conflicts/resolve`
select the active owner claim, mark competing active owners as superseded or
rejected, remove stale ownership edges from the current graph, and preserve
sanitized resolution evidence.
Schema/migration v40 adds
typed `evidence` nodes and `supported_by` provenance
edges, and the graph projection now links scrubbed cloud validation, secret
observation, vulnerability, and remediation evidence without exposing raw
secrets. Schema/migration v41 adds vulnerability standards metadata columns for
CVE, CVSS version/vector, CWE, CPE, EPSS, CISA KEV, MITRE ATT&CK, and
STIX-style external refs; `forge.standards.vulnerabilities` enriches findings
from persisted rows plus local KB tables without network calls, prefers valid
CVSS v4.0 `CVSS:4.0/` vectors over older CVSS versions when available, retains
older scores as alternatives, and asset graph finding metadata includes the
normalized standards block. The graph projection
now also infers passive cloud context from existing `cloud_assets` and
`cloud_validation_results`: account/org nodes, cloud-account ownership claims,
storage/data-sensitivity hints, and internet-exposure risk tags are derived from
stored metadata, ARNs, Azure resource IDs, and validation evidence without live
provider calls. Validated/active cloud secrets now also create explicit
secret-to-cloud-account/resource edges when the provider and stored cloud context
match, giving the graph a passive identity-to-cloud chain without parsing raw
credential values. The same projection now adds a `Public Internet` entrypoint
node and links it to passively observed public hosts and internet-exposed cloud
assets using stored host context, public-observation sources, and validation
metadata only. Stored host/cloud metadata now also projects passive workload
nodes for runtime context, with host-to-workload and cloud-to-workload
provenance edges plus workload risk tags. Focused graph tests cover the context
nodes, relationships, claims, risk tags, identity-to-cloud edges,
internet-entrypoint edges, workload edges, and cloud/host metadata scrubbing.
Asset graph ownership
resolution now reports competing active owner claims, `forge graph ownership
list --json` and live asset-graph responses include `ownership_conflicts`, the
static dashboard shows conflict rows/counts, and monitoring alert remediation
now falls back to the highest-confidence graph owner when no explicit or route
owner is provided while recording conflict metadata. `forge remediation
propagate-owners` and the live `remediation/propagate-owners` route now apply
resolved graph owners to existing unowned remediation items, preserving explicit
owners by default and storing confidence/conflict provenance. The React
remediation panel now includes the same graph-owner propagation action with
owned/unowned counts and an explicit overwrite toggle. Schema/migration v42 adds
local secrets lifecycle tables (`secret_lifecycle_items` and
`secret_suppressions`), deterministic revocation/prevention guidance for common
providers, owner routing from key validation claims, active suppression state,
and scrubbed lifecycle metadata on secret graph nodes. Lifecycle sync now
opens/updates remediation items for unsuppressed active or unconfirmed secret
findings and resolves linked items when the key finding becomes revoked, without
raw secret material and without making live TruffleHog/GitGuardian/GitHub
provider calls. Schema/migration v43 adds append-only `audit_reviews` for audit-manifest human review,
attestation, and legal-hold state. `audit:read`/`audit:review` gate the live
web API list/append endpoints, review attestations are scrubbed before storage,
review events write audit rows, and run/detail payloads annotate audit
manifests with latest review summaries without changing manifest verification
hashes. The React engagement detail workspace now includes an Audit Review
panel with latest review status, status-count tokens, legal-hold counts, static
review-history fallback, and token-gated review submission for the current run
manifest. Schema/migration v44 adds `retention_policies`, `retention_runs`,
and `retention_run_items` for per-engagement retention settings, recorded
preview/apply summaries, and itemized counts. `forge retention
preview|apply --engagement N` is the local operator path; apply requires
`--confirm`, preserves audit logs, run manifests, audit-review events, report
artifacts, and open-alert delivery state, and blocks destructive retention when
the latest audit-review state has an active legal hold unless the policy
explicitly overrides it. Confirmed cleanup currently prunes old monitoring
trend points, closed-alert delivery history, expired alert suppressions,
completed remediation ticket events, and old retention run records. Retention
web APIs now expose overview/update/preview/apply under the engagement resource
behind `retention:read` and `retention:write`, with the same workspace
resolution used by other engagement APIs. The generated dashboard and React
engagement detail view now surface retention policy, run, itemized cleanup,
legal-hold, preview, and confirmed-apply state, with React apply gated by an
explicit confirmation checkbox. `forge doctor` now includes a read-only
Retention Policies row that reports whether existing numeric
engagement DBs have the v44 retention ledger tables.
Schema/migration v30 adds
`monitoring_trend_points`, every snapshot now persists aggregate
asset/finding/severity/change/alert counts, monitoring overview responses
return chronological `trend_series`, and alert status updates refresh
open-alert counts. Remote audit bundle storage now has an opt-in
`forge audit manifest-export --remote-store` path for explicitly configured
scoped mounted/file storage, with append-only exclusive-create semantics and a
doctor readiness row that does not print URI/scope values. `forge doctor` also
has a Deployment Hardening row keyed by `FORGE_DEPLOYMENT_PROFILE=production`;
it checks JWT web auth, scope-manifest enforcement, safe mode, append-only
remote audit bundle storage, Redis for distributed mode, dev `FORGE_ENV`, web
bootstrap token posture, and dev-only platform DB defaults while printing env
var names only. The production Docker path now has a repo-root runtime
Dockerfile, Postgres/Redis self-host Compose stack, non-root/read-only app
containers, loopback-bound API/web ports, required secret interpolation, and
root `.dockerignore` exclusions for local state and secret material. API and
web UI surfaces now share OWASP-style app-layer security headers with
production HSTS when an HTTPS public URL or TLS terminator is configured, and
doctor flags production deployments that disable that middleware. The operator
artifact baseline now includes `docker/reverse-proxy/Caddyfile`,
`docker/reverse-proxy/nginx.conf`, and `docker/systemd/forge-compose.service`;
the packaging contract asserts loopback upstreams, forwarded HTTPS context,
security headers, compose config preflight, and `/etc/forge/forge.env`
integration. A first Helm baseline now lives under `docker/helm/forge/`; it
defines API, web UI, and worker deployments on the same runtime image with
required production URL/secrets, non-root/read-only pod contexts, ClusterIP
services, persistent `/data` and `/remote-audit` claims, JWT/scope-manifest/
security-header env, Postgres/Redis URLs, and append-only audit storage.
It now includes an optional Ingress template for API/web split routing and
`values.production-example.yaml` for managed Postgres, managed Redis, TLS
secret, storage class, and secret-value wiring. Secret delivery supports
inline chart-managed Secrets, `secrets.existingSecretName` for operator-created
Secrets, and an optional External Secrets Operator template for web,
bootstrap, engagement encryption, Postgres, and remote-audit scope values.
Linux install/upgrade automation now starts with
`scripts/self_host_operator.sh`: preflight, install-systemd, upgrade-compose,
helm-lint, helm-template, and status commands share a `--dry-run` guard for
mutating host actions. Preflight checks `/etc/forge/forge.env` for required
production key names plus redacted value policy without sourcing or printing
values: web secret, bootstrap token, and engagement key must be at least 32
characters, `FORGE_PUBLIC_BASE_URL` must be HTTPS, and
`FORGE_AUDIT_BUNDLE_REMOTE_SCOPE` must match the safe token pattern. The Helm
baseline is now
operator-render verified with Helm v3.15.4: lint and template passed for the
production example values, and focused render checks cover chart-managed
Secrets, existing Secrets, ExternalSecret mode, and fail-closed missing secret
values. Remediation UI polish has a first
checkpoint too: the live remediation panel now shows selected item context,
queue health, and live-action readiness in a compact command strip before the
longer owner/update/ticket/retest forms. Next work is broader distro/cluster
install hardening and actual cluster deploy validation around the current
Docker/systemd/Helm baseline.
Latest self-host env-contract checkpoint: Compose and Helm now require/project
`FORGE_ENGAGEMENT_KEY` through inline, existing-secret, and ExternalSecret
modes, and `SPEC.md` B271 records the redacted preflight validation proof.
Verification: `python -m py_compile tests\core\test_docker_packaging.py`;
`python -m ruff check tests\core\test_docker_packaging.py` -> `All checks
passed!`; `pytest tests\core\test_docker_packaging.py -q` -> `13 passed, 1
skipped` because Helm is not installed locally.
The live React graph panel now covers the previously missing deeper asset graph
conflict-resolution UI: it reads `ownership_conflicts`, shows competing owner
claim queues, calls
`/api/engagements/{engagement}/asset-graph/ownership-conflicts/resolve` for the
selected owner, refreshes the live snapshot, and reports success/errors inline.
Backprop: `SPEC.md` B87 records the missing live graph conflict action.
Owner propagation now has an explicit shared policy too: CLI/API/React can keep
the default highest-confidence assignment, skip unresolved ownership conflicts,
and require a minimum owner confidence before updating remediation rows; results
record skipped-conflict and skipped-low-confidence counts plus sanitized policy
metadata/audit receipts. Backprop: `SPEC.md` B88 records the previous hardcoded
owner propagation policy gap.
Scheduled passive provider refresh now supports real multi-provider report
imports: monitoring connector policies can provide per-connector `report_files`
or `provider_reports` mappings for Shodan, Censys, and urlscan while the older
single `report_file` remains a fallback. Refresh summaries preserve sanitized
report-file labels and URL/crawl counters, not provider report bodies.
Backprop: `SPEC.md` B89 records the previous single-report-file scheduling gap.
The asset graph read path now includes deterministic `forge.asset_graph.v1`
critical asset tags, scored attack-path summaries, choke points, blast-radius
hints, and minimal fix-set candidates from stored graph, ownership, standards,
and secret lifecycle metadata. Minimal fix candidates, attack-path nodes, and
choke points now include bounded scrubbed remediation item/ticket/SLA/retest
summaries when workflow state is linked; generated static dashboard detail
pages now expose attack-path, choke-point, and minimal fix-set tables with
scrubbed remediation action context instead of count-only graph review.
Public sensitive cloud data assets now produce a dedicated
`restrict_public_sensitive_data_asset` minimal-fix candidate with scrubbed
actions for public-access removal, policy or ACL restriction, data
classification review, data-loss guardrails, and cloud-account owner routing.
Validated AWS STS caller-identity proof now promotes stable 12-digit AWS
account IDs into cloud-account context, so active AWS secret evidence links
through `organization:cloud_account:aws:<account_id>` and the existing
secret-to-cloud-resource chain.
Stored IAM/principal metadata on cloud assets also becomes passive identity
nodes linked to cloud resources/accounts; high-privilege or wildcard cloud
identities are ranked as minimal-fix candidates with scrubbed metadata only.
IAM-style action/resource/policy/effect fields are reduced to bounded
permission summaries, and wildcard actions/resources, write-capable grants, and
sensitive data access now appear as risk factors in graph JSON and dashboard
fix-candidate rows without retaining raw policy secret material.
Cross-cloud IAM exports now get the same passive treatment: GCP-style
`bindings[].members[]` and Azure-style `role_assignments[]` are normalized into
service-account or managed-identity nodes, linked to their cloud resources and
accounts, privilege-inferred from role names, and ranked for least-privilege
remediation. Focused graph tests prove identity-to-cloud/account edges,
permission summaries, critical identity tags, minimal-fix candidates, and
secret-bearing metadata scrubbing.
Active-validation proof is now part of the same graph primitive: graph sync
projects stored active-validation runs into `validation` nodes, links them to
active-validation proof evidence with `supported_by`, and attaches
`validated_by` edges from resolved host, finding, remediation, or URL target
nodes when those already exist. The reverse bridge now exists as safe
recommendations too: graph-ranked attack paths, critical assets, and
minimal-fix candidates are converted into bounded `graph_scenarios` in the
active-validation list payload. These drafts are non-destructive only
(`dry_run`/`lab`), create no jobs, approve nothing, execute no live network
requests, and carry scrubbed graph context for operator review. The React
Active Validation panel now shows the same drafts as “Graph recommendations”
with target/method/mode/risk context and a `Use draft` button that pre-fills
the create-job form while keeping job creation explicit. When a job is created
from a selected draft, the graph scenario metadata is sent with the create
request so the queued job keeps the asset-graph reason, expected result, and
scrubbed path context; manual target/kind/method/mode edits clear stale draft
lineage. Focused backend tests now pin the same route/storage contract and
prove token, secret, and sensitive URL query material is scrubbed from stored
graph-draft metadata.
Schema/migration v39 starts the separate active-validation lane:
`active_validation_jobs` and `active_validation_runs` store target/method/mode,
approval, ROE/scope manifest references, run evidence, and audit lineage;
`forge active-validation preview|create|approve|run|list|methods|coverage` gives
operators a local CLI and method registry with supported modes, implementation
status, proof kind, ATT&CK/control mappings, and required gates; preview returns
a state-free, zero-network plan with gate status, deterministic budgets, redacted
target/scope refs, and no job/run inserts; live engagement APIs now expose
list/preview/create/approve/run paths behind
`active_validation:read|write|approve|run|live` and include the method catalog
in read snapshots; static dashboard JSON/HTML surfaces Active Validation
Jobs/Runs review sections with method status/proof/coverage columns; and the
React engagement detail route now has a token-gated Active Validation panel
for job creation, method provenance, approval context, per-job run controls,
live-gate toggling, and run evidence review;
coverage collection is read-only and now returns a BAS-style
ATT&CK/control-family matrix from stored jobs and latest run evidence, grouping
planned, approved, passed, failed, blocked, and unrun states through both the
CLI and active-validation API snapshot; generated static dashboard detail pages
and the React engagement detail route now render the same Active Validation
Coverage section beside job/run evidence;
dry-run jobs complete as preview-only, approved lab/fixture jobs complete with
simulated proof evidence, approved `control_simulation` lab jobs compare
expected versus observed fixture control outcomes and classify the run as
passed or failed in coverage, and `read_only_live` jobs fail closed unless
approved, ROE/scope-bound, explicitly live-enabled, and backed by an
implemented method.
The first implemented live methods are `http_reachability`,
`http_security_headers`, and remediation-oriented `fix_verification`: one
non-destructive no-redirect HTTP observation to an approved absolute HTTP(S)
URL, with `HEAD` first and ranged `GET` fallback only when `HEAD` is
unsupported, no response-body storage, public target/audit URL query redaction,
mocked regression coverage, and no lateral movement, persistence, credential
use, exploit chaining, proxy rotation, or scope relaxation. The security-header
method stores CSP/HSTS/nosniff/frame/referrer/permissions/cross-origin posture,
missing/weak header labels, and no `Set-Cookie` or body content.
Remediation retest is now linked to that lane: `forge remediation
request-retest --item-id N` creates an active-validation job with sanitized
remediation metadata, marks the item `retest_pending`, and stores bounded job
history; `forge active-validation run` applies linked run results back to
`remediation_items`, with dry-run remaining pending, blocked validation marking
retest blocked, fixture/lab proof resolving the item, and read-only live fix
verification passing only when the observed result matches the expected
remediation outcome. `forge
remediation apply-retest-run` reconciles already-created active-validation runs.
The web API now exposes the same request bridge at
`POST /api/engagements/{engagement}/remediation/{item}/request-retest`, gated by
`remediation:write`, `remediation:retest`, `active_validation:write`, and
`active_validation:approve` when the request pre-approves a job. The React
engagement detail Remediation panel now has selected-item retest request
controls for target override, method/mode, ROE/scope, expected result, and
pre-approval, refreshing remediation and active-validation snapshots after the
request.
Active-validation proof review is now more operator-visible: new runs store a
redacted `proof_summary`, and static dashboard plus React detail run rows show
`Evidence`, `Live Proof`, and `Fix Match` fields with HTTP method/status or
network error, redirect, body-captured state, and fix-verification
expected/observed/matched facts. Static job/run targets now use the dashboard
URL sanitizer before display. Verification passed for py_compile/Ruff, focused
active-validation dashboard/API/Web UI contract tests (`3 passed`), React lint
with existing hook-dependency warnings, and React production build.
Latest active-validation gate-evidence checkpoint: persisted run evidence now
also carries compact `gates` and `budgets` receipts for dry-run, lab,
read-only-live blocked, live-disabled, scope-denied, and live-executed paths.
The focused regression proves an approved `read_only_live` HTTP job targeting a
URL outside the ROE/scope manifest returns `scope_manifest_denied` before any
HTTP client request, with `network_execution=false`, live request budget `0`,
blocked `scope_manifest`, non-evaluated `live_gate`, and redacted target query
material. Verification: `python -m py_compile
forge\active_validation\runner.py
tests\active_validation\test_active_validation.py`; `python -m ruff check
forge\active_validation\runner.py
tests\active_validation\test_active_validation.py` -> `All checks passed!`;
`pytest tests\active_validation\test_active_validation.py -q` -> `21 passed`.
`SPEC.md` B270 records the checkpoint.
Latest active-validation control-simulation checkpoint: local lab fixture
control simulations now persist redacted expected/observed/matched control
proof, sanitize URL-like metadata values before storage, and feed
`control_passed`/`control_failed` states into the BAS-style coverage matrix.
Verification: py_compile/Ruff and focused control-simulation regression passed.
Latest active-validation monitoring checkpoint: continuous-monitoring snapshots
now include the latest run per active-validation job as
`finding:active_validation:*` state, and active-validation monitoring policies
can run approved non-destructive dry-run/lab validation jobs before snapshotting.
Snapshot diffs and alert/trend history surface failed controls and changed
validation proof using sanitized target refs and compact proof summaries, while
stable semantic fingerprints suppress duplicate alerts for equivalent reruns
with new run IDs. Read-only live scheduled validation remains off unless policy
metadata explicitly opts in and the existing ROE/scope/live gates pass.
Verification: focused py_compile/Ruff passed, the active-validation monitoring
regressions passed, and the full monitoring continuous suite passed
(`32 passed`).
Current architecture checkpoint: attack-graph artifact writing now lives in
`forge.graph.export.export_attack_graph`; `forge graph build` is a thin
config/console wrapper, and `forge.demo` calls the service directly for proof
packs. Focused export service tests passed (`3 passed`) and existing phase4
GraphML/MTGX CLI regressions passed (`2 passed, 110 deselected`). Run tracking
now lives in `forge.orchestration.run_tracking`; `SeedRunHandle`,
`EngagementRunHandle`, `SeedRunTracker`, and `EngagementRunTracker` remain
legacy-compatible through `forge.engagement_orchestrator` imports while the new
module owns `seed_runs`/`engagement_runs`, abandoned-run finalizers,
short-lock progress updates, and audit-manifest writes. Verification passed for
new direct-module/import-compatibility plus audit-manifest tests (`21 passed`)
and focused phase1 tracker regressions (`4 passed, 779 deselected`).
Target feed command registration now lives in `forge.targets_import_cli`,
leaving `forge.cli` as the thin Typer registrar for `forge targets import`.
Root operator command implementations for `dashboard`, `doctor`, `scaffold`,
and `menu` now live in `forge.cli_operator`, and their root command decorators
now live in `forge.cli_root_commands`. Hidden web/distributed-worker commands
now register through `forge.cli_web`, covering `web start|stop|status|enqueue`,
`web worker-once`, `web worker-loop`, and `web automation-loop`. Phase 0
knowledge-base commands now register through `forge.cli_kb`, covering
`kb sync|status|fetch-breach`. Phase 1 reconnaissance commands now register
through `forge.cli_recon`, covering `recon wizard|subdomains|crawl|ports` and
preserving the legacy `forge.cli` subdomain-summary helper import path. Phase 3
evasion command registration now lives in `forge.cli_evasion`, covering
`evasion generate`. Phase 4 exploit-correlation registration now lives in
`forge.cli_exploit`, preserving `forge.cli.exploit_correlate`, and root cleanup
registration now lives in `forge.cli_clean`, preserving `forge.cli.clean`.
Phase 4 web-vulnerability commands now register through `forge.cli_vuln`,
preserving direct `forge.cli.vuln_*` adapters, and authentication-testing
commands now register through `forge.cli_auth`, preserving direct
`forge.cli.auth_*` adapters. Root `kill-chain` registration now lives in
`forge.cli_kill_chain`, preserving the large direct `forge.cli.kill_chain`
implementation/import path. Verification passed for py_compile and Ruff over
`forge/cli.py`, `forge/cli_kill_chain.py`, and focused CLI tests; CLI registry
regressions passed (`14 passed`).
Root Typer app/sub-app construction and modular command registration now live
in `forge.cli_registry.build_forge_cli_apps`; `forge.cli` imports the built
registry plus dedicated command registrars and now keeps only direct
compatibility adapters plus the large `kill_chain` implementation body. This
isolates public/hidden group wiring plus all command registration behind direct
contract tests without changing `forge.cli:main` or
`from forge.cli import kill_chain`.
Legacy decorator-module side-effect imports and direct command-function
re-exports now live in `forge.cli_legacy_decorators`; `forge.cli` re-exports the
same names through a single compatibility import block. Verification passed for
py_compile/Ruff over CLI/compat/test files; focused CLI registry tests passed
(`15 passed`).
Kill-chain runtime option normalization now lives in
`forge.utils.kill_chain_runtime`. The helper owns Typer-default coercion, ROE ID
cleanup, go-hard profile defaults, legacy loop aliases, worker fan-out, and
synthesis/validation batch budgets. Live scope-manifest preflight now also
lives there through injected loader/broad-scope rejector callbacks, so
`forge.cli.kill_chain` consumes the normalized runtime object while preserving
the existing direct import path and the safety ordering that rejects invalid
scope manifests before priming attack-mode automation env vars. Verification
passed for py_compile/Ruff over `forge/cli.py`,
`forge/utils/kill_chain_runtime.py`, and the focused option tests; runtime
option/preflight tests passed (`10 passed`) and focused CLI safety/budget
regressions passed (`3 passed`).
Kill-chain terminal run completion now lives in
`forge.orchestration.run_tracking.complete_engagement_run_once` with an
explicit `EngagementRunCompletionGuard`. The helper owns pending-work refresh,
progress-count refresh, terminal action/metadata construction, terminal audit
emission, tracked-run finish, run-control cleanup, duplicate-completion
suppression, and dashboard review refresh through injected callbacks;
`forge.cli.kill_chain` keeps only the local callback wiring used by
prerequisite handling. Verification passed for py_compile/Ruff over
`forge/cli.py`, `forge/orchestration/run_tracking.py`,
`forge/orchestration/__init__.py`, and the run-tracking tests; direct
run-tracking tests passed (`20 passed`), runtime option/preflight tests passed
(`10 passed`), and focused kill-chain completion/fallback regressions passed
with ambient AWS env cleared (`3 passed`). A telemetry regression run without
clearing AWS env failed because local AWS credentials correctly changed the
final `last_step` to the auto-detected prereq label; rerunning with AWS env
cleared passed.
Kill-chain finalization stage execution now lives in
`forge.orchestration.report_finalization`: parallel credential-validation/
pregraph dispatch, sequential graph/report dispatch, finalization progress
accounting, failure-count updates, and report-returncode lookup are behind
orchestration helpers. `forge.cli.kill_chain` still builds the plan and supplies
the local module-dispatch callbacks. Verification passed for py_compile/Ruff
over `forge/cli.py`, `forge/orchestration/report_finalization.py`,
`forge/orchestration/__init__.py`, and the report-finalization tests; direct
report-finalization tests passed (`15 passed`), and focused kill-chain
telemetry/report-fallback regressions passed with ambient AWS env cleared
(`2 passed`).
Kill-chain final summary rendering now lives in
`forge.orchestration.report_finalization.emit_kill_chain_final_summary`.
Terminal success/pending/failure messaging, report/evidence path output, and
Maltego GraphML/MTGX/CSV path display are delegated through a print callback
while preserving the existing Rich markup and artifact path conventions.
Verification passed for py_compile/Ruff over `forge/cli.py`,
`forge/orchestration/report_finalization.py`,
`forge/orchestration/__init__.py`, and the report-finalization tests; direct
report-finalization tests passed (`17 passed`), and the focused kill-chain
telemetry closeout regression passed with ambient AWS env cleared (`1 passed`).
DB-backed data-driven offensive finalizer spec discovery now lives in
`forge.orchestration.report_finalization.build_data_driven_offensive_finalization_specs`.
It owns attack-mode/dry-run gating, read-only DB lookup, optional table
tolerance, inferred web target command assembly for `vuln idor`, `auth brute`,
and `auth bypass`, validated lateral target command assembly for `post lateral`,
ROE propagation, and scope-manifest argument appending. Verification passed for
py_compile/Ruff over `forge/cli.py`,
`forge/orchestration/report_finalization.py`,
`forge/orchestration/__init__.py`, and the report-finalization tests; direct
report-finalization tests passed (`20 passed`), and the adjacent kill-chain
credential finalization batch regression passed with ambient AWS env cleared
(`1 passed`).
Pure kill-chain seed/routing helpers now live in
`forge.utils.kill_chain_seed_helpers` instead of inside the
`forge.cli.kill_chain` command body. The extracted module owns
company/person-name heuristics, managed/social/cloud host exclusion,
placeholder-IP detection, root-domain normalization, host context JSON shaping,
and initial-seed dedupe policy. `forge.cli.kill_chain` keeps command-specific
classification, canonicalization, and DB side-effect wiring. Verification
passed for py_compile/Ruff over `forge/cli.py`,
`forge/utils/kill_chain_seed_helpers.py`, and
`tests/utils/test_kill_chain_seed_helpers.py`; focused helper, kill-chain
option, and CLI registry tests passed (`34 passed`). `SPEC.md` B272 records
the checkpoint.
Initial seed canonicalization and route payload shaping also now live in
`forge.utils.kill_chain_seed_helpers`. The module owns email/domain/IP/
cloud-ref initial value canonicalization, classified seed entry preparation
through injected classifier/canonicalizers, hostname/domain derivation with
injectable reverse DNS, managed-host exclusion, and initial route payload
construction. `forge.cli.kill_chain` now keeps only command-specific classifier
and cloud/http canonicalizer wiring for that path. Verification passed for
py_compile/Ruff over `forge/cli.py`,
`forge/utils/kill_chain_seed_helpers.py`, and
`tests/utils/test_kill_chain_seed_helpers.py`; focused helper, kill-chain
option, and CLI registry tests passed (`37 passed`). `SPEC.md` B273 records
the checkpoint.
Managed-hosting URL-to-cloud-asset seed parsing now lives in
`forge.utils.kill_chain_seed_helpers.extract_cloud_asset_seed_refs`.
`forge.cli.kill_chain` keeps only the DB promotion wrapper that merges literal
`cloud_ref` seeds and inserts `cloud_assets` rows. Helper coverage proves
Supabase, Firebase, S3, DigitalOcean Spaces, GCS, Azure Blob/static website,
Cloudflare Pages/Workers, GitHub Pages, Vercel, invalid URL, and overlap
dedupe behavior; focused helper, kill-chain option, and CLI registry tests
passed (`39 passed`). `SPEC.md` B274 records the checkpoint.
Kill-chain cloud-asset seed persistence now lives in
`forge.orchestration.seed_promotion`. The helpers preserve literal `cloud_ref`
plus managed URL ref merge, `INSERT OR IGNORE`, source labels, insert-failure
swallowing, service/ref normalization, malformed target skipping,
provider-identifier upgrade policy for placeholder identifiers, richer
provider-identifier preservation, and rowcount accounting. `forge.cli.kill_chain`
keeps only engagement-context wrappers. Verification passed for py_compile/Ruff
over `forge/cli.py`, `forge/orchestration/seed_promotion.py`,
`tests/orchestration/test_seed_promotion.py`,
`forge/utils/kill_chain_seed_helpers.py`, and
`tests/utils/test_kill_chain_seed_helpers.py`; focused seed-promotion, helper,
kill-chain option, and CLI registry tests passed (`42 passed`). `SPEC.md` B275
records the checkpoint.
Generic kill-chain seed lookup and `seed_relations` insertion now live in
`forge.orchestration.seed_promotion` too. `lookup_engagement_seed_id` preserves
engagement-scoped seed/type lookup plus missing/malformed/error-to-`None`
behavior; `insert_seed_relation` preserves missing/self skips, `INSERT OR
IGNORE`, confidence coercion, sorted evidence JSON, and swallowed insert
failures. `forge.cli.kill_chain` keeps only engagement-context wrappers.
Verification passed for py_compile/Ruff over `forge/cli.py`,
`forge/orchestration/seed_promotion.py`,
`tests/orchestration/test_seed_promotion.py`,
`forge/utils/kill_chain_seed_helpers.py`, and
`tests/utils/test_kill_chain_seed_helpers.py`; focused seed-promotion, helper,
kill-chain option, and CLI registry tests passed (`45 passed`). `SPEC.md` B276
records the checkpoint.
Social URL and email-localpart seed cross-reference promotion now live in
`forge.orchestration.seed_promotion` behind injected upsert, classifier, and
synthesis helper callables. The split preserves unknown-platform skips,
URL-seed lookup gating, username/company/name profile expansion, Bluesky
domain-handle promotion, email normalization, empty-handle skips,
discovered-email creation, username creation, relation evidence/confidence,
and CLI compatibility wrappers. Verification passed for py_compile/Ruff over
`forge/cli.py`, `forge/orchestration/seed_promotion.py`,
`tests/orchestration/test_seed_promotion.py`,
`forge/utils/kill_chain_seed_helpers.py`, and
`tests/utils/test_kill_chain_seed_helpers.py`; focused seed-promotion, helper,
kill-chain option, and CLI registry tests passed (`47 passed`). `SPEC.md` B277
records the checkpoint.
Kill-chain engagement-run metadata shaping and websocket progress payload
shaping now live in `forge.orchestration.run_tracking`.
`kill_chain_engagement_run_metadata` preserves command-supplied seed/runtime
counters, live-execution policy metadata, recent-step trimming, ETA coercion,
queue metric normalization, pending-work fields, iteration delta/stability, and
report/runtime fields. `current_run_progress_payload` preserves the dashboard
event shape for progress publications. `forge.cli.kill_chain` now keeps only
command-local counters and policy inputs before delegating. Verification passed
for py_compile/Ruff over `forge/cli.py`,
`forge/orchestration/run_tracking.py`, `forge/orchestration/__init__.py`, and
`tests/orchestration/test_run_tracking.py`; focused run-tracking,
seed-promotion, helper, kill-chain option, and CLI registry tests passed
(`70 passed`). `SPEC.md` B278 records the checkpoint.
Kill-chain console markup stripping and progress phase inference now live in
`forge.orchestration.run_tracking` as `strip_console_markup` and
`infer_kill_chain_run_phase`, exported through `forge.orchestration`.
`forge.cli.kill_chain` progress publishing now delegates Rich-tag stripping,
whitespace collapse, `Iteration N` parsing, numeric fan-out prefix parsing,
normalized phase slugging, and fallback phase behavior while preserving the
existing progress event payload contract. Verification passed for py_compile/
Ruff over `forge/cli.py`, `forge/orchestration/run_tracking.py`,
`forge/orchestration/__init__.py`, and
`tests/orchestration/test_run_tracking.py`; focused run-tracking,
seed-promotion, helper, kill-chain option, and CLI registry tests passed
(`72 passed`). `SPEC.md` B279 records the checkpoint.
`_publish_run_progress` now delegates progress-state mutation to
`forge.orchestration.run_tracking.update_kill_chain_run_progress_state`, also
exported through `forge.orchestration`. The CLI now only computes elapsed
time/timestamp and flushes when the helper reports a real update. The helper
preserves empty-step skips, duplicate suppression, forced duplicate
publication, Rich-cleaned/truncated step and message fields, phase inference,
elapsed rounding, timestamp propagation, and eight-entry recent-step retention.
Verification passed for py_compile/Ruff over `forge/cli.py`,
`forge/orchestration/run_tracking.py`, `forge/orchestration/__init__.py`, and
`tests/orchestration/test_run_tracking.py`; focused run-tracking,
seed-promotion, helper, kill-chain option, and CLI registry tests passed
(`75 passed`). `SPEC.md` B280 records the checkpoint.
Artifact processor cumulative progress counter mutation now lives in
`forge.orchestration.run_tracking.update_artifact_processor_cumulative_metrics`,
exported through `forge.orchestration`. `forge.cli.kill_chain` now delegates
cumulative artifact progress state mutation and only flushes afterward. The
helper preserves non-dict queue recovery, existing counter carry-forward, local
intake accumulation, invocation counting,
processed/failed/skipped/firebase/supabase/discovered seed accumulation,
negative delta clamping, and unrelated queue metric preservation. Verification
passed for py_compile/Ruff over `forge/cli.py`,
`forge/orchestration/run_tracking.py`, `forge/orchestration/__init__.py`, and
`tests/orchestration/test_run_tracking.py`; focused run-tracking,
seed-promotion, helper, kill-chain option, and CLI registry tests passed
(`77 passed`). `SPEC.md` B281 records the checkpoint.
Resume-time artifact queue metric replay now lives in
`forge.orchestration.run_tracking.restore_prior_artifact_queue_metrics`,
exported through `forge.orchestration`. `forge.cli.kill_chain` keeps the
DB/JSON lookup local and delegates restoration of `artifact_processor` and
`artifact_processor_cumulative` queue groups. The helper preserves malformed
payload no-op behavior, partial artifact group restore from bad state,
string/int/None count coercion, unrelated queue metric preservation, ignored
non-artifact groups, and artifact processor/cumulative replacement semantics.
Verification passed for py_compile/Ruff over `forge/cli.py`,
`forge/orchestration/run_tracking.py`, `forge/orchestration/__init__.py`, and
`tests/orchestration/test_run_tracking.py`; focused run-tracking,
seed-promotion, helper, kill-chain option, and CLI registry tests passed
(`80 passed`). `SPEC.md` B282 records the checkpoint.
Kill-chain stop/pause marker cleanup, marker payload parsing,
malformed-marker fallback, and engagement-run metadata flag lookup now live in
`forge.orchestration.run_tracking` as `clear_run_control_marker_paths`,
`read_run_control_marker_request`, and
`run_control_request_from_run_metadata`, exported through `forge.orchestration`.
`forge.cli.kill_chain` keeps marker paths and command wiring local while
orchestration owns tolerant marker deletion, missing and malformed marker
behavior, non-dict marker fallback, read-only metadata lookup, bad JSON no-op
behavior, and flag-gated payload return. Verification passed for py_compile/Ruff
over `forge/cli.py`, `forge/orchestration/run_tracking.py`,
`forge/orchestration/__init__.py`, and `tests/orchestration/test_run_tracking.py`;
focused run-tracking, seed-promotion, helper, kill-chain option, and CLI
registry tests passed (`84 passed`). `SPEC.md` B283 records the checkpoint.
Remote artifact URL scope decisions now live in
`forge.orchestration.artifact_queue.remote_artifact_url_scope_decision`,
re-exported through `forge.orchestration.artifacts` and `forge.orchestration`.
`forge.cli.kill_chain` delegates pure URL normalization, dry-run/no-manifest
behavior, scope-manifest URL validation, invalid URL rejection, allow/deny
handling, and denial source shaping while retaining audit and artifact
processor callback wiring. Verification passed for py_compile/Ruff over
`forge/cli.py`, `forge/orchestration/artifact_queue.py`,
`forge/orchestration/artifacts.py`, `forge/orchestration/__init__.py`, and
`tests/orchestration/test_artifacts.py`; focused artifact, kill-chain option,
and CLI registry tests passed (`323 passed`). `SPEC.md` B284 records the
checkpoint.
Kill-chain stop/pause interrupt transition shaping now lives in
`forge.orchestration.run_tracking.RunControlInterruptTransition` and
`run_control_interrupt_transition`, exported through `forge.orchestration`.
`forge.cli.kill_chain` keeps side effects local while orchestration owns
stop-over-pause precedence, default request context, cancelled/paused lifecycle
metadata, pause resume recommendation, audit action/status selection,
dashboard reason, console label, and no-op behavior when no request exists.
Verification passed for py_compile/Ruff over `forge/cli.py`,
`forge/orchestration/run_tracking.py`, `forge/orchestration/__init__.py`, and
`tests/orchestration/test_run_tracking.py`; focused run-tracking,
seed-promotion, helper, kill-chain option, and CLI registry tests passed
(`88 passed`). `SPEC.md` B285 records the checkpoint.
Module seed-run finalization batch orchestration now lives in
`forge.orchestration.run_tracking.finalize_seed_run_batch`, exported through
`forge.orchestration`. `forge.cli.kill_chain` delegates prep/apply
coordination while keeping local compatibility wrappers for scattered one-off
call sites. The helper preserves tracker/empty-handle no-op behavior, parallel
prep log shape, prep/apply progress labels, order-preserved apply note,
metadata precedence, error/status/output propagation, and finish callback
invocation. Verification passed for py_compile/Ruff over `forge/cli.py`,
`forge/orchestration/run_tracking.py`, `forge/orchestration/__init__.py`, and
`tests/orchestration/test_run_tracking.py`; focused run-tracking,
seed-promotion, helper, kill-chain option, and CLI registry tests passed
(`90 passed`). `SPEC.md` B286 records the checkpoint.
Artifact discovery helper glue now lives in
`forge.orchestration.artifact_queue`: `artifact_source_metadata`,
`prepare_artifact_source_candidate_item`,
`prepare_artifact_source_reduction_item`,
`prepare_artifact_classification_reduction_item`,
`apply_artifact_source_candidate_item`, and
`apply_artifact_queue_total_item`, re-exported through
`forge.orchestration.artifacts` and `forge.orchestration`. `forge.cli.kill_chain`
keeps local wrapper names but delegates metadata allow-listing, alias handling,
list bounds/filtering, crawl/seed row shaping, source/seed/artifact
normalization, candidate append order, and negative queue total halt behavior to
artifact queue helpers. Verification passed for py_compile/Ruff over
`forge/cli.py`, `forge/orchestration/artifact_queue.py`,
`forge/orchestration/artifacts.py`, `forge/orchestration/__init__.py`, and
`tests/orchestration/test_artifacts.py`; focused artifact, kill-chain option,
and CLI registry tests passed (`327 passed`). `SPEC.md` B287 records the
checkpoint.
Artifact URL discovery coordination now lives in
`forge.orchestration.artifact_queue.queue_discovered_artifact_candidates`,
re-exported through `forge.orchestration.artifacts` and `forge.orchestration`.
`forge.cli.kill_chain` now supplies DB source rows and the queue-write callback
while artifact queue orchestration owns source prep/reduction/apply, artifact
classification, queue-candidate dedupe, queue writes, total aggregation, batch
labels, parallel parse logging, apply order notes, classification callback
dispatch, URL dedupe, queue write ordering, and negative-total halt behavior.
Verification passed for py_compile/Ruff over `forge/cli.py`,
`forge/orchestration/artifact_queue.py`, `forge/orchestration/artifacts.py`,
`forge/orchestration/__init__.py`, and `tests/orchestration/test_artifacts.py`;
focused artifact, kill-chain option, and CLI registry tests passed
(`328 passed`). `SPEC.md` B288 records the checkpoint.
Static artifact parser sweep coordination now lives in
`forge.orchestration.artifact_queue.sweep_completed_artifact_metadata`,
re-exported through `forge.orchestration.artifacts` and `forge.orchestration`.
`forge.cli.kill_chain` keeps parser/connect imports and log callbacks local
while artifact queue persistence owns completed-row selection, local-path
existence checks, parser result normalization, bounded metadata JSON updates,
commit/log behavior, and best-effort failure suppression. Verification passed
for py_compile/Ruff over `forge/cli.py`,
`forge/orchestration/artifact_queue.py`, `forge/orchestration/artifacts.py`,
`forge/orchestration/__init__.py`, and `tests/orchestration/test_artifacts.py`;
focused artifact tests passed (`300 passed`). `SPEC.md` B289 records the
checkpoint.
Artifact processing summary log policy now lives in
`forge.orchestration.artifacts.artifact_processing_summary_log_message`,
exported through `forge.orchestration`. `forge.cli.kill_chain` uses that helper
for both initial artifact processing and per-iteration K3 processing, preserving
the processed-or-skipped gate and exact processed/firebase/supabase/skipped
fields while removing duplicate formatting from the CLI. Verification passed for
py_compile/Ruff over `forge/cli.py`, `forge/orchestration/artifact_queue.py`,
`forge/orchestration/artifacts.py`, `forge/orchestration/__init__.py`, and
`tests/orchestration/test_artifacts.py`; focused artifact tests passed (`301
passed`). `SPEC.md` B290 records the checkpoint.
Artifact queue count log policy now lives in
`forge.orchestration.artifact_queue.local_artifact_intake_log_message` and
`forge.orchestration.artifact_queue.discovered_artifact_queue_log_message`,
re-exported through `forge.orchestration.artifacts` and `forge.orchestration`.
`forge.cli.kill_chain` keeps log labels and cumulative metric updates local
while artifact queue helpers own zero/negative suppression and the exact
Rich-marked local/discovered queue messages. Verification passed for
py_compile/Ruff over `forge/cli.py`, `forge/orchestration/artifact_queue.py`,
`forge/orchestration/artifacts.py`, `forge/orchestration/__init__.py`, and
`tests/orchestration/test_artifacts.py`; focused artifact tests passed (`302
passed`). `SPEC.md` B291 records the checkpoint.
Seed synthesis summary log policy now lives in
`forge.orchestration.synthesis.synthesis_summary_log_message`, exported through
`forge.orchestration`. `forge.cli.kill_chain` keeps labels and root-domain
refresh side effects local while synthesis owns the seeds/relations positive
gate plus the initial `corroborated=` and per-iteration K4 `roots=` message
shapes. Verification passed for py_compile/Ruff over `forge/cli.py`,
`forge/orchestration/artifact_queue.py`, `forge/orchestration/artifacts.py`,
`forge/orchestration/synthesis.py`, `forge/orchestration/__init__.py`,
`tests/orchestration/test_artifacts.py`, and
`tests/orchestration/test_synthesis.py`; focused artifact/synthesis,
kill-chain option, and CLI registry tests passed (`348 passed`). `SPEC.md`
B292 records the checkpoint.
Deterministic finding synthesis audit/log policy now lives in
`forge.deterministic_findings.finding_synthesis_audit_result` and
`forge.deterministic_findings.finding_synthesis_log_message`. `forge.cli.kill_chain`
keeps audit/log side effects local while deterministic findings owns pass-label
audit result shaping, sorted severity JSON serialization, and the
inserted/updated/removed positive gate for operator log output. Verification
passed for py_compile/Ruff over `forge/cli.py`,
`forge/deterministic_findings.py`, `forge/orchestration/artifact_queue.py`,
`forge/orchestration/artifacts.py`, `forge/orchestration/synthesis.py`,
`forge/orchestration/__init__.py`, `tests/orchestration/test_artifacts.py`,
`tests/orchestration/test_synthesis.py`, and
`tests/phase1/test_deterministic_findings.py`; focused deterministic,
artifact/synthesis, kill-chain option, and CLI registry tests passed (`368
passed`). `SPEC.md` B293 records the checkpoint.
Abandoned seed-run recovery log policy now lives in
`forge.orchestration.run_tracking.abandoned_seed_run_recovery_log_message`,
exported through `forge.orchestration`. `forge.cli.kill_chain` keeps recovery
execution and `_log` side effects local while run tracking owns zero/negative
suppression and the exact abandoned seed-run recovery message. Verification
passed for py_compile/Ruff over `forge/cli.py`,
`forge/deterministic_findings.py`, `forge/orchestration/artifact_queue.py`,
`forge/orchestration/artifacts.py`, `forge/orchestration/synthesis.py`,
`forge/orchestration/run_tracking.py`, `forge/orchestration/__init__.py`,
`tests/orchestration/test_artifacts.py`, `tests/orchestration/test_synthesis.py`,
`tests/orchestration/test_run_tracking.py`, and
`tests/phase1/test_deterministic_findings.py`; focused run-tracking,
deterministic, artifact/synthesis, kill-chain option, and CLI registry tests
passed (`412 passed`). `SPEC.md` B294 records the checkpoint.
Persisted fan-out resume reuse log policy now lives in
`forge.orchestration.run_tracking.persisted_fanout_resume_reuse_log_message`,
exported through `forge.orchestration`. `forge.cli.kill_chain` keeps reuse
counting and `_log` side effects local while run tracking owns zero/negative
suppression and the exact persisted fan-out reuse message. Verification passed
for py_compile/Ruff over `forge/cli.py`, `forge/deterministic_findings.py`,
`forge/orchestration/artifact_queue.py`, `forge/orchestration/artifacts.py`,
`forge/orchestration/synthesis.py`, `forge/orchestration/run_tracking.py`,
`forge/orchestration/__init__.py`, `tests/orchestration/test_artifacts.py`,
`tests/orchestration/test_synthesis.py`, `tests/orchestration/test_run_tracking.py`,
and `tests/phase1/test_deterministic_findings.py`; focused run-tracking,
deterministic, artifact/synthesis, kill-chain option, and CLI registry tests
passed (`413 passed`). `SPEC.md` B295 records the checkpoint.
Resume-skip completed-target log policy now lives in
`forge.orchestration.run_tracking.resume_completed_skip_log_entry`, exported
through `forge.orchestration`. `forge.cli.kill_chain` keeps prepared-log
emission and batch ordering local while run tracking owns normalized
stage/target label shaping and the exact completed-target resume-skip message
for the central resume-skip helper and passive-domain schedule reduction.
Verification passed for py_compile/Ruff over `forge/cli.py`,
`forge/deterministic_findings.py`, `forge/orchestration/artifact_queue.py`,
`forge/orchestration/artifacts.py`, `forge/orchestration/synthesis.py`,
`forge/orchestration/run_tracking.py`, `forge/orchestration/__init__.py`,
`tests/orchestration/test_artifacts.py`, `tests/orchestration/test_synthesis.py`,
`tests/orchestration/test_run_tracking.py`, and
`tests/phase1/test_deterministic_findings.py`; focused run-tracking,
deterministic, artifact/synthesis, kill-chain option, and CLI registry tests
passed (`414 passed`). `SPEC.md` B296 records the checkpoint.
Seed-promotion contracts and persistence policy now live in
`forge.orchestration.synthesis`; `SeedCandidate`, `SynthesisSummary`,
source-priority policy, metadata merge policy, email seed mirroring, seed
upsert behavior, `seed_relations` insertion, seed-lookup/depth helpers,
social-profile anchor normalization/confidence, social-profile anchor seed
construction, social-profile candidate flatten/dedupe helpers, social-profile
pivot-to-seed construction, and the scope/email/host/artifact seed-candidate
builders are outside the monolith. Social-profile payload traversal, inherited
context propagation, payload-entry source injection, payload de-dupe policy,
social-profile pivot filtering/flattening, and standard URL/host/seed/handle
pivot-entry construction also now live in `forge.orchestration.synthesis`.
Ordered pivot family dispatch, matrix/federated/domain source-specific pivot
assembly, and the Bluesky domain-handle promotion rule now live there too.
Social-profile platform/direct-platform selection, URL/identity/scalar URL-hint
key scans, platform-label normalization, and URL-ish candidate coercion also
now live in synthesis. Handle aggregation, account/link/text handle source
merging, ordered value filtering, and related-host aggregation/filtering are
extracted there too. Domain alias stripping, nested/list domain-host recursion,
domain-host string filtering, and top-level domain-host aggregation are also
extracted there now. The large social-profile platform host mapping is also
extracted into synthesis while `EngagementSynthesisEngine` preserves legacy
methods as delegates. Artifact URL seed-prep coordination, family merge
normalization, social-pivot construction, social/cloud URL-entry normalization,
non-provider related-host promotion, cloud-asset family dispatch, and
URL-to-cloud-asset provider matching now live in
`forge.orchestration.artifacts`; generic artifact-text discovery batch
job planning, ordered batch collection/result fallback, family coordination,
batch normalization, merge de-dupe policy, and text discovery persistence-entry
builders are there now too. Structured-discovery job expansion, payload job
planning, result normalization, source-hint-preserving payload-entry
construction, and per-payload family fan-out are extracted there too. Artifact
relation context sanitization/merge, cloud-asset provenance metadata shaping,
source-URL payload rebasing, data-URI byte decoding, text-payload signal
filtering, image data-URI OCR/barcode/metadata payload shaping, and ordered
line de-dupe are extracted there as well. Firebase/Supabase mobile-config
de-dupe and persistence-entry shaping are extracted there too. Artifact
source-seed metadata construction, provenance allowlisting, evidence metadata
shaping, and seed metadata merge policy are extracted there too. Artifact
text-discovered URL queue admission, scope-denial reason shaping, and queue
metadata JSON construction are extracted there too. Artifact queue row dispatch
into local work, remote download, or pending skip decisions is extracted there
too. Dispatch action normalization is extracted there too:
`artifact_queue_dispatch_actions()` owns ordered queue-row dispatch fan-out,
legacy tuple normalization, malformed entry filtering, and typed local-ready/
remote-request/skipped-row action shaping while `ArtifactQueueProcessor.process()`
keeps slot placement and DB side effects. Remote download reconciliation into
failed, skipped, local-path update, or ready-work decisions is extracted there
too. Local artifact record shaping,
stat metadata, and unchanged-file metadata matching are extracted there too.
Artifact local-path and status metadata update shaping are extracted there too.
Remote artifact download scope-gate decisions are extracted there too. Local
remote-download batch coordination now lives there too:
`download_remote_artifact_batch()` owns ordered result placement, scope-denial
result shaping/callback isolation, worker bounding, exception-to-result
wrapping, and `... / remote download` progress metrics while
`download_remote_artifact_request()` now owns the HTTP/cache/rate-limit/
classifier side effects behind the processor compatibility adapter. Local parse batch
coordination now lives there too: `parse_local_artifact_batch()` owns ordered
parse result placement, parallel exception-to-`ParsedArtifact` wrapping, worker
bounding, and `... / parse` progress metrics while preserving the legacy
single-worker exception propagation contract and leaving parser side effects in
`ArtifactQueueProcessor._parse_local_artifact()`. Remote download
reconciliation action normalization now lives there too:
`artifact_remote_download_reconciliation_actions()` owns zipping remote queue
slots to download results, ordered reconciliation fan-out, malformed entry
filtering, and typed failed/skipped/local-path/ready-item action shaping while
`ArtifactQueueProcessor.process()` keeps the SQLite status/local-path writes and
summary counters. Parsed-result action shaping now lives there too:
`artifact_parsed_result_actions()` owns parse failure vs persisted-success status
notes and summary-delta shaping while the processor still supplies the parsed
artifact persistence callback and performs the final status writes/counter
application. Dispatch-derived process-state planning now lives there too:
`ArtifactQueueProcessPlan` and `artifact_queue_process_plan()` own ready-slot
placement, remote-request pairing, skipped-row accumulation, and ready-item
projection for dispatch actions. Remote reconciliation process-state planning
now lives there too: `ArtifactQueueReconciliationWriteAction` and
`artifact_queue_reconciled_process_plan()` own failed-row/local-path write
planning, reconciliation skipped-row accumulation, and remote ready-slot
placement while DB writes and summary counters remain in
`ArtifactQueueProcessor.process()`. Reconciliation write application now lives
there too: `ArtifactQueueReconciliationApplyResult` and
`apply_artifact_queue_reconciliation_writes()` own ordered failed/local-path
callback application and failed-summary deltas while the processor injects the
SQLite callbacks. Remote-stage orchestration now lives there too:
`ArtifactQueueRemoteStageResult` and `process_artifact_queue_remote_stage()`
own remote download invocation, ordered reconciliation, reconciled plan
construction, reconciliation write application, and failed-summary deltas while
the processor injects download, worker, reconciliation, and SQLite callbacks.
Dispatch-stage orchestration now lives there too:
`ArtifactQueueDispatchStageResult` and `process_artifact_queue_dispatch_stage()`
own ordered queue-row dispatch invocation and initial process-plan construction
while the processor injects its existing ordered worker and dispatch callback.
Acquisition-stage orchestration now lives there too:
`ArtifactQueueAcquisitionStageResult` and
`process_artifact_queue_acquisition_stage()` compose remote download
reconciliation with skipped-row status application while the processor injects
download, worker, reconciliation, local-path, and SQLite status callbacks and
keeps the commit boundary before parse.
Processing-cycle orchestration now lives there too:
`ArtifactQueueProcessingCycleResult` and
`process_artifact_queue_processing_cycle()` compose acquisition, the injected
post-acquisition commit, and parse-stage execution while the processor keeps DB
setup, queue row loading, callback wiring, and final commit.
Queue-row processing orchestration now lives there too:
`ArtifactQueueRowsProcessResult` and `process_artifact_queue_rows()` compose
ordered dispatch, processing-cycle execution, the injected post-acquisition
commit, and the injected final commit while the processor keeps DB setup, queue
row loading, attempt marking, and callback wiring. The row-processing callback
surface is now explicit via `ArtifactQueueRowsProcessCallbacks`, replacing the
long keyword-only callback list at that boundary.
Queue-row preparation now lives there too:
`ArtifactQueueRowsPreparationResult` and
`prepare_artifact_queue_processing_rows()` own queue row selection, selected
artifact ID extraction, attempt marking, and the injected post-attempt commit
while the processor keeps schema/migration setup and row factory configuration.
Engagement-level artifact queue processing now lives there too:
`ArtifactQueueEngagementProcessResult` and
`process_artifact_queue_for_engagement()` compose queue-row preparation with
row processing, so `ArtifactQueueProcessor.process()` keeps schema/migration
setup and row factory configuration. Processor-side callback construction is
now built by `artifact_queue_rows_process_callbacks_from_services()`, which
binds the DB context, progress-aware download/parse wrappers, SQLite
status/local-path adapters, parsed persistence callback, and acquisition/final
commit callbacks. `_artifact_queue_rows_process_callbacks()` remains the thin
processor delegate that passes existing services into that explicit
`ArtifactQueueRowsProcessCallbacks` contract.
Artifact queue processor runtime setup now has its own adapter module too:
`forge.orchestration.artifact_processor_runtime` owns schema/migration/open/
close flow for local artifact ingest and queue processing. `ArtifactQueueProcessor`
now builds `ArtifactProcessorRuntimeServices` from its existing bound parser,
downloader, persistence, reconciliation, and ordered-worker methods, then
delegates `ingest_local_artifacts()` and `process()` through runtime helpers.
Verification: compile/Ruff for the runtime slice passed; runtime adapter tests
and package export coverage passed (`3 passed`); full artifact orchestration helper suite passed
(`150 passed`); targeted Phase 1 retry/process regression passed (`1 passed`).
Broad `tests/phase1/test_engagement_orchestrator.py -k artifact` timed out
after 304 seconds, so broad Phase 1 artifact compatibility remains an open
verification gap for this checkpoint.
Static artifact helper extraction now lives there too:
`static_batch_worker_count()`, `run_ordered_static_batch()`,
`decode_text_artifact_entry()`, and `decode_text_artifact_bytes()` moved into
`forge.orchestration.artifacts` and are exported through `forge.orchestration`.
`ArtifactQueueProcessor` keeps compatibility
wrappers for `_static_batch_worker_count()`, `_run_ordered_static_batch()`,
`_decode_text_artifact_entry()`, and `_decode_text_artifact_bytes()`.
Verification: compile/Ruff for the static-helper slice passed; direct helper
selector passed (`3 passed, 150 deselected`); full artifact orchestration helper
suite passed (`153 passed`); targeted Phase 1 retry/process regression passed
(`1 passed`); runtime adapter suite passed (`3 passed`).
Compressed archive stream helpers now live there too:
`archive_stream_kind()`, `decompress_archive_stream_bytes()`, and
`extract_archive_decompressed_payloads()` moved into
`forge.orchestration.artifacts` and are exported through `forge.orchestration`.
`ArtifactQueueProcessor` keeps compatibility wrappers for `_archive_stream_kind()`
`_decompress_archive_stream_bytes()`, and
`_extract_archive_decompressed_payloads()`. Verification: compile/Ruff for the
compressed-stream slice passed; decompressed/archive helper selector passed (`2
passed, 153 deselected`); full artifact orchestration helper suite passed (`155
passed`); bzip2/txz/buried-xz and brotli/tar-brotli processor regressions passed
(`2 passed`).
ZIP archive payload coordination now lives there too:
`extract_archive_zip_payloads()` moved into `forge.orchestration.artifacts` and
is exported through `forge.orchestration`. It preserves text ZIP extraction plus
SAZ session-pairing aggregation while `ArtifactQueueProcessor` keeps
`_extract_archive_zip_payloads()` as the compatibility wrapper. Verification:
compile/Ruff for the ZIP slice passed; ZIP/family/export helper selector passed
(`3 passed, 153 deselected`); full artifact orchestration helper suite passed
(`156 passed`); recursive artifact queue regression passed (`3 passed`).
TAR archive payload coordination now lives there too:
`extract_archive_tar_payloads()` moved into `forge.orchestration.artifacts` and
is exported through `forge.orchestration`. It preserves OCI image-layout
precedence, Docker-save fallback, and generic TAR text extraction while
`ArtifactQueueProcessor` keeps `_extract_archive_tar_payloads()` as a
depth-preserving compatibility wrapper. Verification: compile/Ruff for the TAR
slice passed; TAR/export helper selector passed (`3 passed, 155 deselected`);
full artifact orchestration helper suite passed (`158 passed`); OCI layer
regression passed (`2 passed`); `git diff --check` only reported the existing
CRLF normalization warning for `forge/engagement_orchestrator.py`.
AR archive member planning and payload coordination now live there too:
`AR_ARCHIVE_MAGIC`, `ar_archive_member_jobs()`, and
`extract_archive_ar_payloads()` moved into `forge.orchestration.artifacts` and
are exported through `forge.orchestration`. They preserve standard, BSD `#1/`,
and GNU string-table member names, unsafe/empty/oversized member filtering,
ordered member extraction, and the legacy `_ar_archive_member_jobs()` /
`_extract_archive_ar_payloads()` wrappers. Verification: compile/Ruff for the
AR slice passed; AR/export helper selector passed (`3 passed, 157 deselected`);
full artifact orchestration helper suite passed (`160 passed`); recursive
artifact queue regression passed (`3 passed`); `git diff --check` only reported
the existing CRLF normalization warning for `forge/engagement_orchestrator.py`.
CPIO `newc` member planning and payload coordination now live there too:
`CPIO_NEWC_MAGICS`, `cpio_newc_member_jobs()`, and
`extract_archive_cpio_payloads()` moved into `forge.orchestration.artifacts` and
are exported through `forge.orchestration`. They preserve trailer handling,
regular-file filtering, unsafe/empty/oversized member filtering, and the legacy
`_cpio_newc_member_jobs()` / `_extract_archive_cpio_payloads()` wrappers.
Verification: compile/Ruff for the CPIO slice passed; CPIO/export helper
selector passed (`3 passed, 159 deselected`); full artifact orchestration helper
suite passed (`162 passed`); recursive artifact queue regression passed (`3
passed`); `git diff --check` only reported the existing CRLF normalization
warning for `forge/engagement_orchestrator.py`.
ASAR header parsing, integer coercion, member planning, and payload coordination
now live there too: `DEFAULT_MAX_ASAR_VISIT_DEPTH`,
`asar_header_and_content_base()`, `asar_non_negative_int()`,
`asar_archive_member_jobs()`, and `extract_archive_asar_payloads()` moved into
`forge.orchestration.artifacts` and are exported through `forge.orchestration`.
They preserve header bounds, nested traversal bounds, unpacked-member skips,
image-size exceptions, unsafe/empty/oversized member filtering, and the legacy
`_asar_header_and_content_base()` / `_asar_non_negative_int()` /
`_asar_archive_member_jobs()` / `_extract_archive_asar_payloads()` wrappers.
Verification: compile/Ruff for the ASAR slice passed; ASAR/export helper
selector passed (`4 passed, 161 deselected`); full artifact orchestration helper
suite passed (`165 passed`); recursive artifact queue regression passed (`3
passed`); `git diff --check` only reported the existing CRLF normalization
warning for `forge/engagement_orchestrator.py`.
7z archive-family gating now lives there too: `SEVEN_Z_ARCHIVE_MAGIC` and
`extract_archive_7z_payloads()` moved into `forge.orchestration.artifacts` and
are exported through `forge.orchestration`. They preserve the optional `py7zr`
availability guard, 7z magic check, and legacy `_extract_archive_7z_payloads()`
wrapper that calls the existing text-member 7z extractor with the original
recursion depth. Verification: compile/Ruff for the 7z slice passed; 7z/export
helper selector passed (`2 passed, 164 deselected`); adjacent 7z helper selector
passed (`3 passed, 163 deselected`); full artifact orchestration helper suite
passed (`166 passed`); exact Phase 1 7z regressions passed (`3 passed, 780
deselected`); `git diff --check` only reported the existing CRLF normalization
warning for `forge/engagement_orchestrator.py`. A broader Phase 1 `7z or
archive` selector was noisy and surfaced an unrelated Wayback/CommonCrawl
provenance failure where zero historical URLs were fetched for
`test_kill_chain_wayback_commoncrawl_preserves_url_level_archive_source`; keep
that separate unless the archive provenance backlog is being audited.
Embedded archive signature detection and offset planning now live there too:
`EMBEDDED_ARCHIVE_SIGNATURES`, `looks_like_archive_bytes()`,
`embedded_archive_signature_matches()`, `embedded_archive_match_entry()`, and
`embedded_archive_offsets()` moved into `forge.orchestration.artifacts` and are
exported through `forge.orchestration`. They preserve root-offset skips, bounded
scanning, duplicate suppression, offset sorting, archive signature coverage,
ASAR/TAR recognition, ordered local batching, and the legacy
`_looks_like_archive_bytes()`, `_embedded_archive_signature_matches()`,
`_embedded_archive_match_entry()`, and `_embedded_archive_offsets()`
monkeypatch-compatible wrappers. Verification: compile/Ruff for the
embedded-archive slice passed; embedded-archive/export helper selector passed
(`4 passed, 165 deselected`); full artifact orchestration helper suite passed
(`169 passed`); exact Phase 1 embedded archive wrapper regressions passed (`2
passed, 781 deselected`); `git diff --check` only reported the existing CRLF
normalization warning for `forge/engagement_orchestrator.py`.
Embedded archive job DTO/planning and payload coordination now live there too:
`EmbeddedArchiveExtractionJob`, `embedded_archive_job_entry()`, and
`extract_embedded_archive_payloads()` moved into
`forge.orchestration.artifacts` and are exported through `forge.orchestration`.
They preserve the depth guard, first-three carved-offset cap, ordered job
construction, ordered extraction, payload-batch flattening, carved member naming
inputs, and legacy `_embedded_archive_job_entry()` /
`_extract_embedded_archive_payloads()` monkeypatch-compatible wrappers.
Verification: compile/Ruff for the embedded-archive job slice passed; embedded
archive job/export selector passed (`4 passed, 167 deselected`); full artifact
orchestration helper suite passed (`171 passed`); exact Phase 1 embedded archive
wrapper regressions passed (`2 passed, 781 deselected`); `git diff --check`
only reported the existing CRLF normalization warning for
`forge/engagement_orchestrator.py`.
Embedded image carving helpers now live there too: `EMBEDDED_IMAGE_SIGNATURES`,
`embedded_image_signature_matches()`, `embedded_image_bytes()`, and
`embedded_image_entries()` moved into `forge.orchestration.artifacts` and are
exported through `forge.orchestration`. They preserve the WebP `WEBP` guard,
PNG/JPEG/GIF/WebP/TIFF byte bounds, offset ordering and duplicate suppression,
overlap skipping, candidate caps, ordered local batching, and the legacy
`_embedded_image_*` monkeypatch-compatible wrappers. Verification: compile/Ruff
for the embedded-image slice passed; embedded image/export helper selector
passed (`3 passed, 170 deselected`); full artifact orchestration helper suite
passed (`173 passed`); exact Phase 1 embedded image carving regressions passed
(`3 passed`); `git diff --check` only reported the existing CRLF normalization
warning for `forge/engagement_orchestrator.py`.
Image payload coordination now lives there too: `IMAGE_PAYLOAD_FAMILIES`,
`extract_image_payloads()`, `extract_image_member_payloads()`,
`embedded_image_payload_batch()`, and `extract_embedded_image_payloads()` moved
into `forge.orchestration.artifacts` and are exported through
`forge.orchestration`. They preserve OCR/barcode/metadata family order, ordered
payload-batch flattening, embedded image `#embedded-image-{index}{suffix}` member
naming, empty-entry short-circuits, and legacy `_extract_image_*` /
`_embedded_image_payload_batch()` monkeypatch-compatible wrappers. Verification:
compile/Ruff for the image-payload slice passed; image payload/export helper
selector passed (`5 passed, 171 deselected`); full artifact orchestration helper
suite passed (`176 passed`); exact Phase 1 embedded image carving regressions
passed (`3 passed`); `git diff --check` only reported the existing CRLF
normalization warning for `forge/engagement_orchestrator.py`.
Binary string payload coordination now lives there too:
`BINARY_STRING_CANDIDATE_FAMILIES` and `binary_string_payload()` moved into
`forge.orchestration.artifacts` and are exported through `forge.orchestration`.
They preserve ASCII/UTF-16 family order, ordered family-entry flattening,
ordered value-entry normalization, duplicate suppression, empty-value filtering,
the 128-value cap, and the legacy `_binary_string_payload()` wrapper that feeds
image metadata and binary artifact extraction. Verification: compile/Ruff for
the binary-string slice passed; binary/image/export helper selector passed (`6
passed, 171 deselected`); full artifact orchestration helper suite passed (`177
passed`); exact Phase 1 binary-string/image-metadata wrapper regressions passed
(`6 passed`); `git diff --check` only reported the existing CRLF normalization
warning for `forge/engagement_orchestrator.py`.
Binary string pure helper dispatch now lives there too:
`interesting_binary_string()`, `binary_string_candidate_family()`,
`binary_string_family_entries()`, and `binary_string_value_entry()` moved into
`forge.orchestration.artifacts` and are exported through `forge.orchestration`.
They preserve the interesting-string predicate, ASCII/UTF-16 family dispatch,
candidate trimming, empty filtering, and legacy private wrapper names used by
existing monkeypatch tests. Verification: compile/Ruff for the pure-helper
binary-string slice passed; binary/export selector passed (`3 passed, 175
deselected`); full artifact orchestration helper suite passed (`178 passed`);
exact Phase 1 binary-string/image-metadata wrapper regressions passed (`6
passed`); `git diff --check` only reported the existing CRLF normalization
warning for `forge/engagement_orchestrator.py`.
Binary string ASCII/UTF-16 scanner helpers now live there too:
`BINARY_STRING_ASCII_RE`, `BINARY_STRING_UTF16LE_RE`,
`binary_string_ascii_candidate()`, `binary_string_ascii_candidates()`,
`binary_string_utf16_candidate()`, and `binary_string_utf16_candidates()` moved
into `forge.orchestration.artifacts` and are exported through
`forge.orchestration`. They preserve passive regex extraction, Latin-1 and
UTF-16LE decoding, interesting-string filtering, ordered local batching,
empty-result filtering, and legacy private wrapper names. Verification:
compile/Ruff for the scanner slice passed; binary/export selector passed (`4
passed, 175 deselected`); full artifact orchestration helper suite passed (`179
passed`); exact Phase 1 binary-string/image-metadata wrapper regressions passed
(`6 passed`); `git diff --check` only reported the existing CRLF normalization
warning for `forge/engagement_orchestrator.py`.
OLE metadata line extraction now lives there too: `OLE_METADATA_KEYS`,
`ole_metadata_line()`, and `ole_metadata_lines()` moved into
`forge.orchestration.artifacts` and are exported through `forge.orchestration`.
They preserve metadata-fetch failure handling, fixed metadata key order, ordered
local batching, empty-line filtering, duplicate suppression, the 64-line cap,
and legacy private wrapper names. Verification: compile/Ruff for the OLE
metadata slice passed; OLE/export selector passed (`2 passed, 178 deselected`);
full artifact orchestration helper suite passed (`180 passed`); exact Phase 1
OLE metadata wrapper regression passed (`1 passed`); `git diff --check` only
reported the existing CRLF normalization warning for
`forge/engagement_orchestrator.py`.
XML/member payload routing now lives there too: `XML_MEMBER_SUFFIXES`,
`XML_MEMBER_PAYLOAD_FAMILIES`, `member_payloads()`, and
`extract_member_payload_family()` moved into `forge.orchestration.artifacts` and
are exported through `forge.orchestration`. They preserve Android manifest and
database client config shortcuts, `.rels` relationship payload routing, XML
text/meta family order, ordered payload-batch flattening, generic text fallback,
and legacy `_member_payloads()` / `_extract_member_payload_family()` wrappers.
Verification: compile/Ruff for the member-payload slice passed; member/export
selector passed (`6 passed, 176 deselected`); full artifact orchestration helper
suite passed (`182 passed`); exact Phase 1 XML member/document archive
regressions passed (`2 passed`); `git diff --check` only reported the existing
CRLF normalization warning for `forge/engagement_orchestrator.py`.
XML/relationship leaf line helpers now live there too: `normalize_xml_tag()`,
`xml_text_value()`, `xml_property_line()`, `relationship_line()`,
`ordered_line_batch_entries()`, and `ordered_line_entry()` moved into
`forge.orchestration.artifacts` and are exported through `forge.orchestration`.
They preserve namespace tag normalization, XML text trimming, leaf-only property
formatting, relationship target/type formatting, ordered empty-line filtering,
and legacy private wrapper names. Verification: compile/Ruff for the XML/line
helper slice passed; XML/ordered-line export selector passed (`2 passed, 181
deselected`); full artifact orchestration helper suite passed (`183 passed`);
exact Phase 1 XML/relationship wrapper regressions passed (`5 passed`); `git
diff --check` only reported the existing CRLF normalization warning for
`forge/engagement_orchestrator.py`.
PDF metadata line helpers now live there too: `pdf_metadata_lines()` and
`pdf_metadata_lines_for_key()` moved into `forge.orchestration.artifacts` and
are exported through `forge.orchestration`. They preserve Latin-1 fallback
decoding, fixed metadata key order, URI extraction, PDF metadata text
trimming/unescaping, ordered batch flattening, duplicate suppression, the
64-line cap, and legacy private wrapper names. Verification: compile/Ruff for
the PDF metadata slice passed; PDF/export selector passed (`2 passed, 182
deselected`); full artifact orchestration helper suite passed (`184 passed`);
exact Phase 1 PDF metadata wrapper regressions passed (`2 passed`); `git diff
--check` only reported the existing CRLF normalization warning for
`forge/engagement_orchestrator.py`.
Email metadata line helpers now live there too:
`email_message_metadata_lines()` and `email_message_metadata_line()` moved into
`forge.orchestration.artifacts` and are exported through `forge.orchestration`.
They preserve fixed header order, whitespace trimming, empty-header filtering,
case-insensitive duplicate suppression, the 64-line cap, ordered local batching,
and legacy private wrapper names. Verification: compile/Ruff for the email
metadata slice passed; email/export selector passed (`2 passed, 183
deselected`); full artifact orchestration helper suite passed (`185 passed`);
exact Phase 1 email metadata wrapper regression passed (`1 passed`); `git diff
--check` only reported the existing CRLF normalization warning for
`forge/engagement_orchestrator.py`.
PDF XMP payload extraction now lives there too: `pdf_xmp_payload()` moved into
`forge.orchestration.artifacts` and is exported through `forge.orchestration`.
It preserves Latin-1 fallback decoding, case-insensitive first XMP block
matching across lines, XML text payload delegation, no-match empty output, and
the legacy private wrapper name. Verification: compile/Ruff for the PDF XMP
slice passed; PDF-XMP/export selector passed (`2 passed, 184 deselected`); full
artifact orchestration helper suite passed (`186 passed`); exact Phase 1 PDF
subextractor wrapper regressions passed (`2 passed`); `git diff --check` only
reported the existing CRLF normalization warning for
`forge/engagement_orchestrator.py`.
PDF payload family coordination now lives there too:
`extract_pdf_payloads()` and `extract_pdf_payload_fragment()` moved into
`forge.orchestration.artifacts` and are exported through `forge.orchestration`.
They preserve the fixed text/metadata/XMP/OCR family order, bounded data
fan-out supplied by the processor, metadata and XMP payload naming, OCR/text
callback injection for path and byte sources, ordered tuple-batch filtering, and
legacy private wrapper names. Verification: compile/Ruff for the PDF payload
slice passed; PDF-payload/export selector passed (`3 passed, 185 deselected`);
full artifact orchestration helper suite passed (`188 passed`); exact Phase 1
PDF payload wrapper regressions passed (`3 passed`); `git diff --check` only
reported the existing CRLF normalization warning for
`forge/engagement_orchestrator.py`.
PDF text payload shaping now lives there too:
`extract_pdf_text_payloads_from_path()` and
`extract_pdf_text_payloads_from_bytes()` moved into
`forge.orchestration.artifacts` and are exported through `forge.orchestration`.
They preserve missing-path empty output, injected text reading for path-backed
PDFs, source/member tuple naming, Latin-1 fallback decoding, bounded byte
slicing, and legacy private wrapper names. Verification: compile/Ruff for the
PDF text slice passed; PDF-text/export selector passed (`2 passed, 187
deselected`); full artifact orchestration helper suite passed (`189 passed`);
exact Phase 1 PDF wrapper regressions passed (`3 passed`); `git diff --check`
only reported the existing CRLF normalization warning for
`forge/engagement_orchestrator.py`.
SQLite connection payload family coordination now lives there too:
`extract_sqlite_connection_payloads_from_jobs()` and
`extract_sqlite_connection_payload_family()` moved into
`forge.orchestration.artifacts` and are exported through `forge.orchestration`.
They preserve the fixed summary/objects family order, ordered local batching,
tuple-batch filtering, summary and object callback injection, and legacy private
wrapper names while keeping SQLite master queries and object-job construction in
the processor. Verification: compile/Ruff for the SQLite family slice passed;
SQLite-family/export selector passed (`3 passed, 188 deselected`); full
artifact orchestration helper suite passed (`191 passed`); exact Phase 1 SQLite
wrapper regressions passed (`5 passed`); `git diff --check` only reported the
existing CRLF normalization warning for `forge/engagement_orchestrator.py`.
SQLite connection object payload flattening now lives there too:
`extract_sqlite_connection_object_payloads_from_jobs()` moved into
`forge.orchestration.artifacts` and is exported through `forge.orchestration`.
It preserves empty-job short-circuiting, ordered per-object extraction, ordered
tuple-batch filtering, final serial flattening, and legacy private wrapper names
while keeping SQLite object extraction in the processor. Verification:
compile/Ruff for the SQLite object slice passed; SQLite-object/export selector
passed (`2 passed, 190 deselected`); full artifact orchestration helper suite
passed (`192 passed`); exact Phase 1 SQLite object wrapper regression passed
(`1 passed`); adjacent Phase 1 SQLite wrapper regressions passed (`7 passed`);
`git diff --check` only reported the existing CRLF normalization warning for
`forge/engagement_orchestrator.py`.
SQLite object payload extraction from an open connection now lives there too:
`extract_sqlite_object_payloads_from_connection()` moved into
`forge.orchestration.artifacts` and is exported through `forge.orchestration`.
It preserves blank-object short-circuiting, object-name/SQL trimming, safe
column/sample-row fallback on SQLite errors, bounded row sampling, fixed
schema/columns/rows family order, tuple-batch filtering, and legacy private
wrapper names while keeping identifier quoting and payload-family construction
injected by the processor. Verification: compile/Ruff for the SQLite object
connection slice passed; SQLite object connection/export selector passed (`2
passed, 191 deselected`); full artifact orchestration helper suite passed (`193
passed`); exact Phase 1 object subsection wrapper regression passed (`1
passed`); adjacent Phase 1 SQLite wrapper regressions passed (`9 passed`); `git
diff --check` only reported the existing CRLF normalization warning for
`forge/engagement_orchestrator.py`.
SQLite object payload family dispatch now lives there too:
`extract_sqlite_object_payload_family()` moved into
`forge.orchestration.artifacts` and is exported through `forge.orchestration`.
It preserves the schema/columns/rows branch contract, unknown-family empty
output, callback argument forwarding, and legacy private wrapper names while
keeping concrete schema, column, and row payload rendering injected by the
processor. Verification: compile/Ruff for the SQLite object-family slice passed;
SQLite object-family/export selector passed (`2 passed, 192 deselected`); full
artifact orchestration helper suite passed (`194 passed`); exact Phase 1
object-family wrapper regression passed (`1 passed`); adjacent Phase 1 SQLite
wrapper regressions passed (`9 passed`); `git diff --check` only reported the
existing CRLF normalization warning for `forge/engagement_orchestrator.py`.
SQLite object row-payload coordination now lives there too:
`extract_sqlite_object_row_payloads()` moved into
`forge.orchestration.artifacts` and is exported through `forge.orchestration`.
It preserves one-based row enumeration, ordered local batching, `None` row
filtering, row renderer callback injection, and legacy private wrapper names
while keeping individual row rendering in the processor. Verification:
compile/Ruff for the SQLite row-payload slice passed; SQLite row-payload/export
selector passed (`2 passed, 193 deselected`); full artifact orchestration helper
suite passed (`195 passed`); exact Phase 1 row-payload wrapper regression passed
(`1 passed`); adjacent Phase 1 SQLite wrapper regressions passed (`9 passed`);
`git diff --check` only reported the existing CRLF normalization warning for
`forge/engagement_orchestrator.py`.
SQLite single-row payload rendering coordination now lives there too:
`extract_sqlite_row_payload()` moved into `forge.orchestration.artifacts` and is
exported through `forge.orchestration`. It preserves ordered cell enumeration,
empty-cell filtering, all-empty row `None` output, newline-joined cell text,
stable `#sqlite-row-{object}-{index}` member naming, cell renderer callback
injection, and legacy private wrapper names while keeping SQLite cell text
formatting in the processor. Verification: compile/Ruff for the SQLite
row-rendering slice passed; SQLite row-rendering/export selector passed (`2
passed, 194 deselected`); full artifact orchestration helper suite passed (`196
passed`); exact Phase 1 row-cell wrapper regression passed (`1 passed`);
adjacent Phase 1 SQLite wrapper regressions passed (`9 passed`); `git diff
--check` only reported the existing CRLF normalization warning for
`forge/engagement_orchestrator.py`.
SQLite row-cell line formatting now lives there too:
`extract_sqlite_row_cell_line()` moved into `forge.orchestration.artifacts` and
is exported through `forge.orchestration`. It preserves rendered-value empty
filtering, named-column selection, fallback `col_N` naming for missing or
out-of-range columns, `column=value` formatting, SQLite cell text callback
injection, and legacy private wrapper names. Verification: compile/Ruff for the
SQLite row-cell slice passed; SQLite row-cell/export selector passed (`2 passed,
195 deselected`); full artifact orchestration helper suite passed (`197
passed`); exact Phase 1 row-cell wrapper regression passed (`1 passed`);
adjacent Phase 1 SQLite wrapper regressions passed (`9 passed`); `git diff
--check` only reported the existing CRLF normalization warning for
`forge/engagement_orchestrator.py`.
Email message payload coordination now lives there too:
`extract_email_message_payloads()` moved into `forge.orchestration.artifacts`
and is exported through `forge.orchestration`. It preserves depth/empty-data
short-circuiting, parser-failure raw text fallback with bounded bytes, metadata
extraction, leaf-part selection, fixed summary/parts family order,
tuple-batch filtering, and legacy private wrapper names while keeping email
parser policy and concrete family rendering injected by the processor.
Verification: compile/Ruff for the email payload slice passed;
email-payload/export selector passed (`2 passed, 196 deselected`); full artifact
orchestration helper suite passed (`198 passed`); exact Phase 1 summary/parts
wrapper regressions passed (`2 passed`); adjacent Phase 1 email artifact
regressions passed (`5 passed`); `git diff --check` only reported the existing
CRLF normalization warning for `forge/engagement_orchestrator.py`.
Email message payload family dispatch now lives there too:
`extract_email_message_payload_family()` moved into
`forge.orchestration.artifacts` and is exported through `forge.orchestration`.
It preserves the summary/parts branch contract, unknown-family empty output,
metadata/leaf-part/depth argument forwarding, and legacy private wrapper names
while keeping concrete summary and part rendering injected by the processor.
Verification: compile/Ruff for the email family slice passed;
email-family/export selector passed (`2 passed, 197 deselected`); full artifact
orchestration helper suite passed (`199 passed`); exact Phase 1 email family
wrapper regressions passed (`2 passed`); adjacent Phase 1 email artifact
regressions passed (`5 passed`); `git diff --check` only reported the existing
CRLF normalization warning for `forge/engagement_orchestrator.py`.
Email message summary payload rendering now lives there too:
`extract_email_message_summary_payloads()` moved into
`forge.orchestration.artifacts` and is exported through `forge.orchestration`.
It preserves empty-metadata empty output, stable `#message-meta` member naming,
newline-joined metadata text, and legacy private wrapper names. Verification:
compile/Ruff for the email summary slice passed; email-summary/export selector
passed (`2 passed, 198 deselected`); full artifact orchestration helper suite
passed (`200 passed`); exact Phase 1 email family wrapper regressions passed
(`2 passed`); adjacent Phase 1 email artifact regressions passed (`5 passed`);
`git diff --check` only reported the existing CRLF normalization warning for
`forge/engagement_orchestrator.py`.
Email message part-payload coordination now lives there too:
`extract_email_message_part_payloads()` moved into
`forge.orchestration.artifacts` and is exported through `forge.orchestration`.
It preserves one-based part enumeration, ordered part planning, immediate
payload ordering, deferred extraction placeholders, malformed extraction-result
skips, ordered tuple-batch filtering, final flattening, and legacy private
wrapper names while keeping concrete `EmailPartPlanningEntry`/
`EmailPartExtractionJob` ownership injected by the processor. Verification:
compile/Ruff for the email part-payload slice passed; email
part-payload/export selector passed (`2 passed, 199 deselected`); full artifact
orchestration helper suite passed (`201 passed`); exact Phase 1 part-planning/
payload wrapper regressions passed (`2 passed`); adjacent Phase 1 email
artifact regressions passed (`6 passed`); `git diff --check` only reported the
existing CRLF normalization warning for `forge/engagement_orchestrator.py`.
Email part-job payload entry adaptation now lives there too:
`extract_email_part_job_payload_entry()` moved into
`forge.orchestration.artifacts` and is exported through `forge.orchestration`.
It preserves negative-result-index skips, valid result-index retention,
extraction callback delegation, and legacy private wrapper names while keeping
actual part extraction in the processor. Verification: compile/Ruff for the
email part-job adapter slice passed; email part-job adapter/export selector
passed (`2 passed, 200 deselected`); full artifact orchestration helper suite
passed (`202 passed`); exact Phase 1 part-payload/attachment wrapper regressions
passed (`2 passed`); adjacent Phase 1 email artifact regressions passed (`6
passed`); `git diff --check` only reported the existing CRLF normalization
warning for `forge/engagement_orchestrator.py`.
Nested email message job normalization now lives there too:
`nested_email_message_job()` moved into `forge.orchestration.artifacts` and is
exported through `forge.orchestration`. It preserves nested-name trimming,
empty-name and empty-payload skips, byte bounding to the configured artifact
member limit, and legacy private wrapper names while keeping the limit injected
by the processor. Verification: compile/Ruff for the nested email job slice
passed; nested-email job/export selector passed (`2 passed, 201 deselected`);
full artifact orchestration helper suite passed (`203 passed`); exact Phase 1
nested-email wrapper regressions passed (`2 passed`); adjacent Phase 1 email
artifact regressions passed (`8 passed`); `git diff --check` only reported the
existing CRLF normalization warning for `forge/engagement_orchestrator.py`.
Email part extraction job coordination now lives there too:
`extract_email_part_job()` moved into `forge.orchestration.artifacts` and is
exported through `forge.orchestration`. It preserves nested-message expansion,
ordered nested payload flattening, empty payload-byte skips, member payload
extraction delegation, and legacy private wrapper names while keeping concrete
message and member extraction callbacks injected by the processor. Verification:
compile/Ruff for the email part extraction job slice passed; helper/export
selector passed (`4 passed, 201 deselected`); full artifact orchestration helper
suite passed (`205 passed`); exact Phase 1 nested-message and payload-entry
wrapper regressions passed (`2 passed`); adjacent Phase 1 email artifact
regressions passed (`9 passed`).
Mbox message-job normalization and summary payload shaping now live there too:
`mbox_message_job()` and `extract_mbox_summary_payloads()` moved into
`forge.orchestration.artifacts` and are exported through `forge.orchestration`.
They preserve message index validation, artifact member byte bounding,
empty-message skips, positive message-count metadata formatting, and legacy
private wrapper names. Verification: compile/Ruff for the mbox job/summary
slice passed; mbox job/summary/export selector passed (`3 passed, 204
deselected`); full artifact orchestration helper suite passed (`207 passed`);
focused Phase 1 mbox wrapper regressions passed (`6 passed`).
Mbox payload-family dispatch now lives there too:
`extract_mbox_payload_family()` moved into `forge.orchestration.artifacts` and
is exported through `forge.orchestration`. It preserves summary/message family
selection, unknown-family empty results, injected summary/message callbacks, and
legacy private wrapper names. Verification: compile/Ruff for the mbox family
slice passed; mbox family/job/summary/export selector passed (`4 passed, 204
deselected`); full artifact orchestration helper suite passed (`208 passed`);
focused Phase 1 mbox wrapper regressions passed (`6 passed`).
Mbox message-payload extraction coordination now lives there too:
`extract_mbox_message_payloads()` moved into `forge.orchestration.artifacts` and
is exported through `forge.orchestration`. It preserves ordered message
extraction, deterministic `.message-N.eml` member naming, injected email-message
parsing, ordered tuple-batch flattening, and legacy private wrapper names.
Verification: compile/Ruff for the mbox message-payload slice passed; mbox
message/family/job/summary/export selector passed (`5 passed, 204 deselected`);
full artifact orchestration helper suite passed (`209 passed`); focused Phase 1
mbox wrapper regressions passed (`6 passed`).
Mbox raw message parsing now lives there too:
`mbox_raw_message_jobs()` and `MboxRawMessageJobsResult` moved into
`forge.orchestration.artifacts` and are exported through `forge.orchestration`.
They preserve artifact member byte bounding, temp mailbox parsing,
message-count tracking, ordered raw message job extraction, parse-failure
fallback signaling, and the processor's downstream batching behavior.
Verification: compile/Ruff for the mbox raw parser slice passed; mbox raw/
message/family/job/summary/export selector passed (`6 passed, 204 deselected`);
full artifact orchestration helper suite passed (`210 passed`); focused Phase 1
mbox wrapper regressions passed (`6 passed`).
Mbox byte-payload coordination now lives there too:
`extract_mbox_bytes_payloads()` moved into `forge.orchestration.artifacts` and
is exported through `forge.orchestration`. It preserves depth/data guards, raw
parser fallback text payloads, ordered message-job normalization,
summary/message family extraction, ordered family flattening, summary-only
fallback, plain text fallback, and legacy private wrapper names while keeping
processor callbacks injected. Verification: compile/Ruff for the mbox byte
coordinator slice passed; mbox byte/raw/message/family/job/summary/export
selector passed (`8 passed, 204 deselected`); full artifact orchestration helper
suite passed (`212 passed`); focused Phase 1 mbox wrapper regressions passed (`6
passed`).
Email part decode coordination now lives there too:
`decode_email_part_entry()` and `decode_email_part_text()` moved into
`forge.orchestration.artifacts` and are exported through `forge.orchestration`.
They preserve invalid charset skips, ordered charset fallback attempts, static
worker-pool delegation, first-success selection, bounded fallback decoding, and
legacy private wrapper names. Verification: compile/Ruff for the email decode
slice passed; decode/export selector passed (`3 passed, 211 deselected`); full
artifact orchestration helper suite passed (`214 passed`); exact Phase 1 decode
wrapper regression passed (`1 passed`).
RTF payload-family dispatch now lives there too:
`extract_rtf_payload_family()` moved into `forge.orchestration.artifacts` and is
exported through `forge.orchestration`. It preserves text vs embedded-archive
family selection, unknown-family empty results, injected text/archive callbacks,
and legacy private wrapper names. Verification: compile/Ruff for the RTF family
slice passed; RTF/export selector passed (`2 passed, 213 deselected`); full
artifact orchestration helper suite passed (`215 passed`); focused Phase 1 RTF
wrapper regression passed (`1 passed`).
RTF text payload shaping and embedded-archive depth gating now live there too:
`extract_rtf_text_payloads()` and `extract_rtf_embedded_archive_payloads()`
moved into `forge.orchestration.artifacts` and are exported through
`forge.orchestration`. They preserve blank-text skips, `#rtf-text` member
naming, depth >= 2 archive skips, injected embedded-archive extraction, and
legacy private wrapper names. Verification: compile/Ruff for the RTF leaf slice
passed; RTF/export selector passed (`4 passed, 213 deselected`); full artifact
orchestration helper suite passed (`217 passed`); focused Phase 1 RTF wrapper
regression passed (`1 passed`).
RTF byte-payload coordination now lives there too:
`extract_rtf_bytes_payloads()` moved into `forge.orchestration.artifacts` and is
exported through `forge.orchestration`. It preserves RTF-to-text conversion,
nonblank-text family dispatch, ordered family flattening, blank-text legacy
binary fallback, injected callbacks, and legacy private wrapper names.
Verification: compile/Ruff for the RTF byte coordinator slice passed; RTF/export
selector passed (`6 passed, 213 deselected`); full artifact orchestration helper
suite passed (`219 passed`); focused Phase 1 RTF wrapper regression passed (`1
passed`).
Legacy binary payload-family dispatch now lives there too:
`extract_legacy_binary_payload_family()` moved into
`forge.orchestration.artifacts` and is exported through `forge.orchestration`.
It preserves strings vs embedded-archive vs OLE family selection, unknown-family
empty results, injected family callbacks, and legacy private wrapper names.
Verification: compile/Ruff for the legacy binary family slice passed;
legacy-binary/export selector passed (`2 passed, 218 deselected`); full artifact
orchestration helper suite passed (`220 passed`); focused Phase 1 legacy binary
wrapper regressions passed (`2 passed`).
Legacy binary byte-payload coordination now lives there too:
`extract_legacy_binary_payloads()` moved into `forge.orchestration.artifacts`
and is exported through `forge.orchestration`. It preserves
strings/embedded-archive/OLE family scheduling, ordered family flattening,
injected family/tuple callbacks, and legacy private wrapper names.
Verification: compile/Ruff for the legacy binary byte coordinator slice passed;
legacy-binary/export selector passed (`3 passed, 218 deselected`); full artifact
orchestration helper suite passed (`221 passed`); focused Phase 1 legacy binary
wrapper regressions passed (`2 passed`).
OLE stream payload coordination now lives there too:
`extract_ole_metadata_payloads()`, `extract_ole_stream_payload_family()`,
`extract_ole_stream_payloads()`, and `extract_ole_stream_job_payloads()` moved
into `forge.orchestration.artifacts` and are exported through
`forge.orchestration`. They preserve summary payload assembly,
strings/nested-archive/embedded-archive stream family scheduling, ordered stream
flattening, injected callbacks, and legacy private wrapper names. Verification:
compile/Ruff for the OLE stream coordinator slice passed; OLE/export selector
passed (`6 passed, 219 deselected`); full artifact orchestration helper suite
passed (`225 passed`); focused Phase 1 legacy/OLE wrapper regressions passed (`2
passed`).
OLE stream leaf payload helpers now live there too:
`extract_ole_stream_string_payloads()`,
`extract_ole_stream_nested_archive_payloads()`, and
`extract_ole_stream_embedded_archive_payloads()` moved into
`forge.orchestration.artifacts` and are exported through `forge.orchestration`.
They preserve binary-string payload labeling, depth/archive checks for nested
archive streams, embedded-archive/image payload combination, injected callbacks,
and legacy private wrapper names. Verification: compile/Ruff for the OLE stream
leaf slice passed; OLE/export selector passed (`9 passed, 219 deselected`);
full artifact orchestration helper suite passed (`228 passed`); focused Phase 1
legacy/OLE wrapper regressions passed (`2 passed`).
OLE stream entry/job normalization and payload-family dispatch now live there
too: `ole_stream_entry()`, `ole_stream_job()`, and
`extract_ole_payload_family()` moved into `forge.orchestration.artifacts` and
are exported through `forge.orchestration`. They preserve stream-part
normalization, injected job construction, summary-vs-streams dispatch, injected
callbacks, and legacy private wrapper names. Verification: compile/Ruff for the
OLE stream entry/job slice passed; OLE/export selector passed (`12 passed, 219
deselected`); full artifact orchestration helper suite passed (`231 passed`);
focused Phase 1 legacy/OLE wrapper regressions passed (`2 passed`).
OLE stream finalization now lives there too:
`extract_ole_payloads_from_stream_entries()` moved into
`forge.orchestration.artifacts` and is exported through `forge.orchestration`.
It preserves raw stream-entry normalization, injected OLE stream job
construction, summary/streams family scheduling, ordered payload-family
flattening, injected tuple filtering, and legacy private wrapper names while
keeping `olefile` I/O in the processor wrapper. Verification: compile/Ruff for
the OLE stream finalization slice passed; OLE/export selector passed (`13
passed, 219 deselected`); direct finalization selector passed (`1 passed, 231
deselected`); full artifact orchestration helper suite passed (`232 passed`);
focused Phase 1 legacy/OLE wrapper regressions passed (`2 passed`).
Raw OLE stream collection now lives there too: `ole_raw_stream_entries()` moved
into `forge.orchestration.artifacts` and is exported through
`forge.orchestration`. It preserves bounded stream reads, failed-stream skips,
tuple stream-part normalization for downstream stages, and legacy private wrapper
behavior while keeping `olefile` import/open lifecycle in the processor wrapper.
Verification: compile/Ruff for the raw OLE stream slice passed; OLE/export
selector passed (`14 passed, 219 deselected`); full artifact orchestration
helper suite passed (`233 passed`); focused Phase 1 legacy/OLE wrapper
regressions passed (`2 passed`).
Legacy binary leaf payload helpers now live there too:
`extract_legacy_binary_string_payloads()`,
`extract_legacy_binary_embedded_archive_payloads()`, and
`extract_legacy_binary_ole_payloads()` moved into
`forge.orchestration.artifacts` and are exported through `forge.orchestration`.
They preserve binary-string labeling, embedded archive/image combination, OLE
magic gating, injected callbacks, and legacy private wrapper names.
Verification: compile/Ruff for the legacy binary leaf slice passed; legacy/OLE
export selector passed (`19 passed, 217 deselected`); full artifact
orchestration helper suite passed (`236 passed`); focused Phase 1 legacy/OLE
wrapper regressions passed (`2 passed`) after rerun of the known
timing-sensitive concurrency assertion.
Parquet summary formatting now lives there too: `parquet_cell_text()`,
`parquet_interesting_value()`, `parquet_table_lines()`, and
`parquet_summary_lines()` moved into `forge.orchestration.artifacts` and are
exported through `forge.orchestration`. They preserve metadata rendering,
interesting-value filtering, row-group/table caps, byte decoding, JSON fallback
formatting, and legacy private wrapper names while keeping `pyarrow` import/open
lifecycle in the processor wrapper. Verification: compile/Ruff for the Parquet
helper slice passed; Parquet/legacy export selector passed (`9 passed, 230
deselected`); full artifact orchestration helper suite passed (`239 passed`);
focused Phase 1 Parquet/legacy selector passed (`1 passed, 782 deselected`).
Parquet byte payload coordination now lives there too:
`extract_parquet_bytes_payloads()` moved into `forge.orchestration.artifacts`
and is exported through `forge.orchestration`. It preserves parse-error
fallback to bounded legacy binary payload extraction, successful table-summary
payload emission, appended legacy binary payload extraction, injected Parquet
factory/summary callbacks, and legacy private wrapper names while keeping
`pyarrow` import/open lifecycle in the processor wrapper. Verification:
compile/Ruff for the Parquet byte coordinator slice passed; Parquet/legacy
export selector passed (`11 passed, 230 deselected`); full artifact
orchestration helper suite passed (`241 passed`); focused Phase 1 Parquet/legacy
selector passed (`1 passed, 782 deselected`).
Parquet path payload coordination now lives there too:
`extract_parquet_path_payloads()` moved into `forge.orchestration.artifacts` and
is exported through `forge.orchestration`. It preserves bounded size checks,
normal file-read dispatch into the byte coordinator,
oversized/read-error/missing-file fallback to legacy binary extraction, injected
parser/legacy callbacks, and legacy private wrapper names. Verification:
compile/Ruff for the Parquet path coordinator slice passed; Parquet/legacy
export selector passed (`13 passed, 230 deselected`); full artifact
orchestration helper suite passed (`243 passed`); focused Phase 1 Parquet/legacy
selector passed (`1 passed, 782 deselected`).
RTF text normalization now lives there too: `rtf_to_text()` moved into
`forge.orchestration.artifacts` and is exported through `forge.orchestration`.
It preserves latin-1 decoding, escaped hex decoding, RTF control-word whitespace
handling, paragraph/line/tab/dash/bullet/unicode fallback handling, NUL
stripping, and legacy private wrapper names. Verification: compile/Ruff for the
RTF text normalizer slice passed; RTF/legacy export selector passed (`12 passed,
232 deselected`); full artifact orchestration helper suite passed (`244
passed`); focused Phase 1 RTF/legacy selector passed (`4 passed, 779
deselected`).
Image payload family dispatch now lives there too:
`extract_image_payload_family()` and `extract_image_member_payload_family()`
moved into `forge.orchestration.artifacts` and are exported through
`forge.orchestration`. They preserve OCR, barcode, metadata, missing-file,
unknown-family, bounded metadata-read, member suffix, and legacy private wrapper
behavior. Verification: compile/Ruff for the image family dispatcher slice
passed; image/export selector passed (`13 passed, 233 deselected`); full
artifact orchestration helper suite passed (`246 passed`); focused Phase 1 image
OCR/metadata regressions passed (`3 passed`).
PDF OCR page planning/retention helpers now live there too:
`pdf_ocr_page_job()` and `retained_pdf_ocr_image_path()` moved into
`forge.orchestration.artifacts` and are exported through `forge.orchestration`.
They preserve positive page index filtering, `Path` normalization, retained
temp-file suffix/content copying, missing-source handling, and legacy private
wrapper names. Verification: compile/Ruff for the PDF OCR helper slice passed;
PDF OCR/image/export selector passed (`14 passed, 233 deselected`); full
artifact orchestration helper suite passed (`247 passed`); focused Phase 1 PDF
OCR planning/retention regressions passed (`3 passed`).
PDF OCR path coordination now lives there too:
`extract_pdf_ocr_payloads_from_path()` moved into
`forge.orchestration.artifacts` and is exported through `forge.orchestration`.
It preserves raster-availability and missing-path guards, ordered page-job
planning, OCR/barcode page payload shaping, rendered-page cleanup, payload
flattening, and legacy private wrapper names. Verification: compile/Ruff for
the PDF OCR path coordinator slice passed; PDF OCR/PDF payload/image/export
selector passed (`17 passed, 231 deselected`); full artifact orchestration
helper suite passed (`248 passed`); focused Phase 1 PDF OCR path regressions
passed (`5 passed`).
Embedded PDF byte OCR coordination now lives there too:
`extract_pdf_bytes_ocr_payloads()` moved into `forge.orchestration.artifacts`
and is exported through `forge.orchestration`. It preserves raster/data guards,
bounded temp `embedded.pdf` writes, delegation into the PDF OCR path coordinator,
exception fallback, and legacy private wrapper names. Verification: compile/Ruff
for the embedded PDF OCR byte coordinator slice passed; PDF OCR/PDF
payload/image/export selector passed (`17 passed, 232 deselected`); full
artifact orchestration helper suite passed (`249 passed`); focused Phase 1 PDF
OCR path regressions passed (`5 passed`).
PDF raster page rendering coordination now lives there too:
`render_pdf_pages_for_ocr()` moved into `forge.orchestration.artifacts` and is
exported through `forge.orchestration`. It preserves raster
binary/missing-path guards, `pdftoppm` command construction, timeout/check
flags, sorted page discovery, max-page retention capping, retained-path
filtering, temp-dir cleanup, failed-raster fallback, and legacy private wrapper
names. Verification: compile/Ruff for the PDF raster render coordinator slice
passed; render/PDF OCR/PDF payload/image selector passed (`19 passed, 232
deselected`); full artifact orchestration helper suite passed (`251 passed`);
focused Phase 1 PDF OCR render/retention regressions passed (`2 passed`).
Image metadata/barcode payload adapters now live there too:
`image_metadata_payload()`, `barcode_image_path_payload()`, and
`barcode_image_bytes_payload()` moved into `forge.orchestration.artifacts` and
are exported through `forge.orchestration`. They preserve binary-string metadata
delegation, path barcode newline joining with max-byte forwarding, byte barcode
bounded slicing, legacy barcode callback call shapes, and private wrapper names.
Verification: compile/Ruff for the image metadata/barcode adapter slice passed;
barcode/image/PDF OCR/PDF payload selector passed (`20 passed, 232 deselected`);
full artifact orchestration helper suite passed (`252 passed`); focused Phase 1
image OCR/metadata regressions passed (`3 passed`).
OCR image execution adapters now live there too: `ocr_image_path()` and
`ocr_image_bytes()` moved into `forge.orchestration.artifacts` and are exported
through `forge.orchestration`. They preserve OCR binary/missing-path guards,
tesseract command construction, timeout/check flags, nonzero/exception
fallback, form-feed cleanup, text trimming/limits, bounded temp image writes,
suffix fallback, temp-file cleanup, and legacy private wrapper names.
Verification: compile/Ruff for the OCR adapter slice passed; OCR/barcode/image/
PDF payload selector passed (`23 passed, 231 deselected`); full artifact
orchestration helper suite passed (`254 passed`); focused Phase 1 OCR/image/PDF
regressions passed (`4 passed`).
XML member payload coordinators now live there too: `xml_text_payload()`,
`xml_property_payload()`, and `relationship_payload()` moved into
`forge.orchestration.artifacts` and are exported through `forge.orchestration`.
They preserve invalid XML fallback, ordered text extraction, Office metadata
member gating, property-line dedupe/capping, relationship target/type
formatting, ordered line filtering, and legacy private wrapper names.
Verification: compile/Ruff for the XML coordinator slice passed; XML/
ordered-line/export selector passed (`6 passed, 249 deselected`); full artifact
orchestration helper suite passed (`255 passed`); focused Phase 1 XML/
relationship ordering regressions passed (`3 passed`) after rerunning one
timing-sensitive peak-concurrency assertion that passed on the exact-test rerun.
Artifact seed lookup now delegates through `lookup_artifact_seed_id()` too,
removing duplicate engagement-seed SQL from `ArtifactQueueProcessor` while
preserving the private `_lookup_seed_id()` compatibility method and existing
callers. Verification: compile/Ruff for the seed lookup delegation slice passed;
seed-depth/source-seed/lookup/export selector passed (`6 passed, 249
deselected`); full artifact orchestration helper suite passed (`255 passed`);
focused Phase 1 artifact URL/source-seed caller regressions passed (`2 passed,
781 deselected`).
Local artifact path resolution now lives there too as
`resolve_local_artifact_path()`, preserving the legacy local-path-first,
source-url-fallback, existing-path-only behavior while keeping
`ArtifactQueueProcessor._resolve_local_path()` as a compatibility wrapper for
dispatch and parse callers. Verification: compile/Ruff for the local path
resolver slice passed; local-artifact/dispatch/export selector passed (`17
passed, 239 deselected`); full artifact orchestration helper suite passed (`256
passed`); exact Phase 1 unchanged parsed local-artifact regression passed (`1
passed`).
Remote artifact request acquisition now lives there too as
`download_remote_artifact_request()`, preserving non-HTTP no-op results,
cache-hit reuse, header-aware filename selection, content metadata, inferred
artifact type fallback, rate-limit cooldown/retry behavior, request pacing,
max-byte failure shaping, and the legacy empty-file side effect on oversized
downloads. `ArtifactQueueProcessor._download_remote_artifact_request()` is now a
compatibility adapter that forwards the current rate-limit hooks and
`time.sleep` so monkeypatch-based callers still observe pacing. Verification:
compile/Ruff for the remote request slice passed; remote-download/export
selector passed (`14 passed, 244 deselected`); full artifact orchestration
helper suite passed (`258 passed`); Phase 1 remote acquisition/progress
compatibility passed (`2 passed`); Phase 1 rate-limit/header filename
compatibility passed (`2 passed`).
Dispatch-row result adaptation now lives in
`artifact_queue_dispatch_result_from_row()`, which shapes SQLite queue rows into
local work items, remote download requests, or skipped-row tuples. The
processor's private `_artifact_queue_dispatch_entry()` remains as a thin
compatibility delegate for existing monkeypatch tests.
Local filesystem artifact ingest coordination now lives there too:
`local_artifact_candidate_paths()` owns root traversal and file filtering, and
`ingest_local_artifacts_for_engagement()` owns ordered record building, queue
insert/update/skip application, queued-count aggregation, and the injected final
commit while `ArtifactQueueProcessor.ingest_local_artifacts()` keeps DB setup
and close.
Remote-download reconciliation result adaptation now lives there too:
`artifact_remote_download_reconciliation_result_from_item()` shapes downloaded,
failed, and skipped remote results into the legacy failed-row/skipped-row/
local-path-update/ready-item tuple while the processor's private
`_remote_download_reconciliation_entry()` remains a thin compatibility delegate.
Remote-download legacy wrapper coordination now lives there too:
`apply_remote_artifact_download_result()` owns failure/local-path side-effect
selection, and `download_remote_artifact_for_queue_record()` owns request
construction plus result application while `_download_remote_artifact()` remains
a callback-backed compatibility delegate.
Local parse dispatch now lives there too:
`parse_artifact_work_item()` routes APK/IPA artifacts to mobile scanning,
config/document/archive artifacts to text scanning, and unsupported artifact
types to the zero-payload metadata fallback while `_parse_local_artifact()`
remains the processor compatibility delegate.
Artifact local ordered-batch execution now lives there too:
`run_ordered_local_artifact_batch()` owns max-worker-bounded ordered worker-pool
execution, serial fallback for disabled worker limits, and per-item default
results when callbacks fail while `_run_ordered_local_batch()` remains the
processor compatibility delegate. Verified with compile/Ruff, the
ordered-batch/scan/parse selector (`6 passed, 254 deselected`), the full
artifact helper suite (`260 passed`), and focused Phase 1 direct mobile/text
scan compatibility tests (`2 passed`).
Direct mobile-bundle text payload acquisition now lives there too:
`extract_mobile_bundle_text_payloads()` owns ZIP/TAR detection and archive
opening for local mobile bundles before delegating member extraction through
callbacks while `_extract_mobile_bundle_text_payloads()` remains the processor
compatibility delegate. Verified with compile/Ruff, the mobile-bundle/
ordered-batch selector (`5 passed, 256 deselected`), the full artifact helper
suite (`261 passed`), and focused Phase 1 direct/nested mobile scan
compatibility tests (`2 passed`).
Nested-mobile ZIP archive adaptation now lives there too:
`extract_nested_mobile_configs_from_zip()` owns nested mobile ZIP member
selection, byte reads, member-job normalization, and delegation into the
existing nested-member merge stage while `_extract_nested_mobile_configs_from_zip()`
remains the processor compatibility delegate. Verified with compile/Ruff, the
nested-mobile ZIP selector (`4 passed, 258 deselected`), the full artifact
helper suite (`262 passed`), and the focused Phase 1 nested-mobile ZIP
compatibility selector (`1 passed, 782 deselected`).
Nested-mobile TAR archive adaptation now lives there too:
`extract_nested_mobile_configs_from_tar()` owns nested mobile TAR member
selection, safe `extractfile()` handling, byte reads, member-job normalization,
and delegation into the existing nested-member merge stage while
`_extract_nested_mobile_configs_from_tar()` remains the processor compatibility
delegate. Verified with compile/Ruff, the nested-mobile ZIP/TAR selector
(`4 passed, 259 deselected`), the full artifact helper suite (`263 passed`),
and the focused Phase 1 nested-mobile archive compatibility selector
(`1 passed, 782 deselected`).
Nested-mobile 7z archive adaptation now lives there too:
`extract_nested_mobile_configs_from_7z()` owns optional dependency and magic
gating, password skipping, selected-member extraction into a temporary
directory, path-containment checks, byte-size bounds, member-job normalization,
and delegation into the existing nested-member merge stage while
`_extract_nested_mobile_configs_from_7z()` remains the processor compatibility
delegate. Verified with compile/Ruff, the nested-mobile 7z/ZIP/TAR selector
(`5 passed, 260 deselected`), the full artifact helper suite (`265 passed`),
and the focused Phase 1 nested-mobile 7z compatibility selector
(`2 passed, 781 deselected`).
Nested-mobile member-byte processing now lives there too:
`extract_mobile_configs_from_member_bytes()` owns member suffix routing, bounded
temp-file materialization, archive-vs-direct mobile scan selection,
exception-to-empty fallback, and provenance rebasing through injected callbacks
while `_extract_mobile_configs_from_member_bytes()` remains the processor
compatibility delegate. Verified with compile/Ruff, the nested mobile
member-byte selector (`4 passed, 263 deselected`), the full artifact helper
suite (`267 passed`), and the focused Phase 1 member-byte compatibility
selector (`2 passed, 781 deselected`).
Nested-mobile archive dispatch now lives there too:
`extract_nested_mobile_bundle_configs()` owns the archive guard and ZIP/7z/TAR
dispatch for archive-style text artifacts while preserving no-op/fallback
behavior and optional 7z gating; `_extract_nested_mobile_bundle_configs()`
remains the processor compatibility delegate. Verified with compile/Ruff, the
nested mobile dispatcher/member selector (`7 passed, 261 deselected`), the full
artifact helper suite (`268 passed`), and the focused Phase 1 nested-mobile
archive/member compatibility selector (`3 passed, 780 deselected`).
Mobile bundle family dispatch now lives there too:
`extract_mobile_bundle_family()` owns payload/APK/IPA family branch selection
through injected extractor callbacks, while `_extract_mobile_bundle_family()`
remains the processor compatibility delegate. Verified with py_compile, Ruff,
the focused mobile bundle family selector (`3 passed, 266 deselected`), the full
artifact helper suite (`269 passed`), and the focused Phase 1 direct/nested
mobile compatibility selector (`2 passed, 781 deselected`).
Cloud config family dispatch now lives there too:
`extract_cloud_config_family()` owns Firebase/Supabase/unknown-family branch
selection through injected extractor callbacks, while
`_extract_cloud_config_family()` remains the processor compatibility delegate.
Verified with py_compile, Ruff, the focused cloud/mobile artifact selector
(`5 passed, 265 deselected`), the full artifact helper suite (`270 passed`),
and the focused Phase 1 direct/nested mobile compatibility selector
(`2 passed, 781 deselected`).
Structured discovery payload fragment dispatch now lives there too:
`build_artifact_structured_discovery_payload_fragment()` owns source-hint
preprocessing, storage/tunnel public-text normalization, family routing, joined
candidate-list families, Starlark image dedupe, raw passthrough, and unknown
fallback through injected callbacks. `_build_structured_discovery_payload_fragment()`
remains the processor compatibility delegate. Verified with py_compile, Ruff,
the focused structured-discovery selector (`9 passed, 264 deselected`), the full
artifact helper suite (`273 passed`), and the representative Phase 1 structured
artifact selector (`5 passed, 778 deselected`).
Simple text discovery families now live there too:
`collect_artifact_simple_text_discovery_family()` owns the email, phone, and IP
generic text-discovery family handling with injected regexes/normalizers, while
`_collect_generic_text_discovery_family()` falls through unchanged for
network-host, URL, identity, key, and cloud-asset families. Verified with
py_compile, Ruff, the focused text-discovery selector (`6 passed, 269
deselected`), the full artifact helper suite (`275 passed`), and a
representative Phase 1 text/config artifact selector (`4 passed, 779
deselected`).
Network-host text discovery now lives there too:
`collect_artifact_network_host_text_discovery_family()` owns the generic
network-host family branch, including base endpoint seeds, GitReview host
fields, MTA-STS MX hosts, Matrix delegation, DID web hosts, Nostr relays,
Terraform DNS record hosts, and host-seed dedupe through injected callbacks.
`_collect_generic_text_discovery_family()` now falls through unchanged only for
URL, identity, key, and cloud-asset families. Verified with py_compile, Ruff,
the focused network/simple text-discovery selector (`8 passed, 270
deselected`), the full artifact helper suite (`278 passed`), and a
representative Phase 1 network/config artifact selector (`5 passed, 778
deselected`).
URL text discovery now lives there too:
`ARTIFACT_TEXT_URL_DISCOVERY_FAMILIES` and
`collect_artifact_url_text_discovery_family()` own the ordered generic URL
subfamily list plus merge/dedupe behavior through an injected URL-candidate
callback. `_collect_generic_text_discovery_family()` now falls through unchanged
only for identity, key, and cloud-asset families. Verified with py_compile,
Ruff, the focused URL/network/simple text-discovery selector (`11 passed, 270
deselected`), the full artifact helper suite (`281 passed`), and a
representative Phase 1 URL/artifact selector (`5 passed, 778 deselected`).
Identity text discovery now lives there too:
`collect_artifact_identity_text_discovery_family()` owns the generic
contact-identity family branch through an injected candidate callback.
`_collect_generic_text_discovery_family()` now falls through unchanged only for
key and cloud-asset families. Verified with py_compile, Ruff, the focused
identity/URL/network/simple text-discovery selector (`13 passed, 270
deselected`), the full artifact helper suite (`283 passed`), and a
representative Phase 1 identity/text artifact selector (`4 passed, 779
deselected`).
Key text discovery now lives there too:
`collect_artifact_key_text_discovery_family()` owns generic key pattern
eligibility, ordered finding collection, pattern-name dedupe, redaction,
Azure storage account-domain extraction, encryption detail shaping, and
key-finding payload construction through injected callbacks. `_collect_generic_text_discovery_family()`
now falls through unchanged only for the cloud-asset family. Verified with
py_compile, Ruff, the focused key/identity/URL/network/simple text-discovery
selector (`16 passed, 270 deselected`), the full artifact helper suite (`286
passed`), and a representative Phase 1 key/config artifact selector (`4 passed,
779 deselected`).
Cloud-asset text discovery now lives there too:
`ARTIFACT_TEXT_CLOUD_ASSET_DISCOVERY_FAMILIES` and
`collect_artifact_cloud_asset_text_discovery_family()` own the ordered generic
cloud-asset subfamily list, candidate callback dispatch, merge ordering, and
cloud-asset dedupe. `_collect_generic_text_discovery_family()` is now a
compatibility delegate across the generic text-discovery families and no longer
keeps a local family implementation branch. Verified with py_compile, Ruff, the
focused cloud/key/identity/URL/network/simple text-discovery selector (`19
passed, 270 deselected`), the full artifact helper suite (`289 passed`), and a
representative Phase 1 cloud-asset artifact selector (`5 passed, 778
deselected`).
Skipped-row status action shaping now lives there too:
`ArtifactQueueStatusWriteAction` and
`artifact_queue_skipped_status_actions()` own skipped status, notes, metadata
patch, and skipped-summary delta shaping while the processor applies the
SQLite update. Skipped-status action application now lives there too:
`apply_artifact_queue_status_actions()` owns skipped status callback
application and skipped-count summary deltas while the processor injects the
SQLite callback. Skipped-stage orchestration now lives there too:
`ArtifactQueueSkippedStageResult` and `process_artifact_queue_skipped_stage()`
own skipped-row action shaping, skipped status application, and skipped-summary
deltas while the processor injects the SQLite callback. Parsed-result action
application now lives there too:
`apply_artifact_parsed_result_actions()` owns parsed status callback
application and `ArtifactProcessingSummary` delta aggregation while the
processor injects the SQLite callback and merges the returned counts.
Parse-stage orchestration now lives there too: `ArtifactQueueParseStageResult`
and `process_artifact_queue_parse_stage()` own parse invocation, parsed-result
action shaping, parsed status application, and parsed-summary deltas while the
processor injects parser, persistence, and SQLite callbacks. Summary-delta
aggregation now lives behind `merge_artifact_processing_summary()`, so the
processor no longer copies per-stage counters field by field after remote,
skipped, and parse stages. Local
artifact ingest insert/update/skip decisions and metadata merge JSON shaping are
extracted there too. Default local artifact root planning, artifact progress
snapshot metrics, and artifact progress stage-label shaping are extracted there
too. Artifact queue DTO/state contracts (`ArtifactProcessingSummary`,
`ArtifactWorkItem`, `ArtifactDownloadRequest`, `ArtifactDownloadResult`, and
`ParsedArtifact`) are extracted there too while remaining legacy-importable from
`forge.engagement_orchestrator`. Artifact queue DB persistence helpers for
local artifact source-seed upserts, local-path/download metadata updates, and
status/notes metadata updates are extracted there too. Artifact provenance DB
helpers for source-seed provenance loading, target seed metadata merge,
relation-evidence merge, relation upsert, seed lookup, and source-seed linking
are extracted there too. Artifact-derived seed/email DB helpers for seed
insert/update, child-depth calculation, source-seed URL/APK lookup, and email
normalization/persistence are extracted there too. Artifact key-finding DB
persistence, including repo-name fallback and insert-or-ignore behavior, is
extracted there too. Artifact cloud-asset reference DB persistence, including
provider-identifier preservation, metadata merge, and first-insert lineage
audit behavior, is extracted there too. Artifact text-discovered URL queue
insertion, idempotence, and queued/scope-denied audit behavior are extracted
there too. Local filesystem artifact queue insert/update/unchanged-skip DB
application is extracted there too. Artifact queue processing-row selection and
attempt-count marking are extracted there too. Artifact lineage audit-log
insertion, field bounding, and SQLite-error tolerance are extracted there too.
Artifact relation-context DB loading from `artifact_queue.metadata_json` is
extracted there too, reusing the existing sanitized context builder for parsed
artifact persistence. Generic artifact metadata-to-seed DB merge/update is
extracted there too. Artifact URL social-pivot seed/relation persistence and
URL-derived cloud-asset reference store orchestration are extracted there too.
The high-level artifact URL seed persistence orchestrator is extracted there
too, coordinating URL seed upsert, source linking, social pivots, related seeds,
cloud assets, and recursive artifact URL queueing through legacy-compatible
callbacks. The generic artifact-text discovery persistence orchestrator is
extracted there too, coordinating email/phone/IP/host/URL/identity/key/cloud
persistence through legacy-compatible callbacks. Parsed-artifact persistence
coordination is extracted there too, wiring artifact context, source-seed
resolution, structured discovery batches, generic text persistence, and
Firebase/Supabase config storage through legacy-compatible callbacks.
Firebase and Supabase mobile-config persistence loops are extracted there too,
including cloud asset reference storage, child seed/source linking, URL
promotion, and encrypted key-finding persistence through legacy-compatible
callbacks.
Payload-level Firebase/Supabase cloud-config job planning, per-payload family
dispatch, and ordered result merging are extracted there too.
Nested mobile archive member eligibility, member job normalization, ordered
member-result merging, and outer-archive provenance rebasing are extracted
there too. Per-member mobile artifact-type routing, ordered direct mobile
bundle family extraction, and batched member-discovery rebasing are extracted
there too.
Top-level text artifact scan-stage coordination, payload-summary shaping, base
payload cloud-config merging, nested mobile result merging, and final mobile
config de-dupe are extracted there too.
Direct mobile bundle scan coordination is extracted there too, reusing the
ordered family extraction, base-payload cloud-config merge, payload summary, and
dedupe helpers through legacy-compatible callbacks.
Text archive member name normalization and ZIP/TAR/7z member planning helpers
are extracted there too, along with the shared member-payload extraction and
flattening coordinator now reused by ZIP/TAR/7z plus CPIO/ASAR payload paths,
preserving legacy method delegates for worker-pool ordering tests.
Archive-byte family dispatch, WARC/PCAP short-circuiting, ordered archive
family probing, and first-nonempty family precedence are extracted there too.
Archive payload-family callback dispatch is extracted there too, preserving the
legacy `_extract_archive_payload_family()` wrapper.
CRX2/CRX3 header stripping and CRX-to-ZIP archive coordination are extracted
there too, preserving the legacy CRX wrapper methods.
SAZ raw-session member classification, paired request/response payload synthesis,
request-origin derivation, and relative redirect extraction are extracted there
too, preserving the legacy Fiddler `.saz` wrapper methods.
`ArtifactQueueProcessor` preserves legacy methods as delegates for worker-pool
and monkeypatch-order tests. Verification passed for
direct synthesis module tests (`14 passed`), narrow synthesis-stage rule tests
(`36 passed`), targeted phase1 platform/identity regressions (`4 passed`),
targeted handle/related-host ordering regressions (`5 passed`), targeted
social-profile pivot regressions (`6 passed`), targeted domain-alias/Bluesky
behavior regressions (`3 passed`), direct artifact helper tests (`115 passed`),
targeted phase1 artifact URL social/cloud wrapper regressions (`3 passed`),
targeted phase1 artifact-text job/collection/merge regressions (`6 passed`),
targeted artifact-text discovery merge/persistence regressions (`4 passed`),
targeted phase1 structured-discovery wrapper regressions (`5 passed`), and
targeted phase1 Firebase/Supabase persistence-prep wrapper regressions (`2
passed`), and targeted SVG embedded data-URI OCR compatibility regression (`1
passed`), targeted source-relative child seed depth regression (`1 passed`),
targeted mobile-config feedback-seed regression (`1 passed`), and focused
artifact recursive queue regressions (`3 passed`). Targeted unchanged local
artifact requeue regression passed (`1 passed`).
Targeted remote artifact scope-denial regression passed (`1 passed`).
Targeted artifact stage-progress regression passed (`1 passed`). Targeted
default local artifact-root integration passed (`1 passed`) with an explicit
scope manifest for the expected Firebase validation URL. Targeted remote
download reconciliation parallelism regression passed (`1 passed`).
Targeted local artifact no-requeue regression passed (`1 passed`), artifact
provenance regressions passed (`4 passed`), and artifact recursive queue
regressions passed (`3 passed`).
Targeted artifact text/Firebase/Supabase persistence-prep wrapper regressions
passed (`3 passed`).
Full artifact cloud-reference detection regressions passed (`3 passed`).
Targeted recursive artifact queue regressions passed (`3 passed`) and the
remote Helm index queue recursion regression passed (`1 passed`).
Targeted local artifact ingest/no-requeue processor regressions passed (`2
passed`).
Targeted artifact queue dispatch/remote acquisition/stage-progress regressions
passed (`3 passed`), direct dispatch action regressions passed (`4 passed`),
remote download batch helper/scope/reconciliation regressions passed (`7
passed`), direct parse/remote/progress helper
regressions passed (`5 passed`), focused phase1 remote/parse progress
regressions passed (`4 passed`), direct remote reconciliation action
regressions passed (`5 passed`), focused phase1 reconciliation/acquisition/
progress/scope regressions passed (`4 passed`), direct parsed-result action/
dispatch/reconciliation helper regressions passed (`5 passed`), focused phase1
parse-stage/progress/no-requeue regressions passed (`3 passed`), direct
parsed-artifact persistence callback regression passed (`1 passed`), and
artifact retry-state regressions passed (`2 passed`).
Targeted audit callback-path regressions passed (`5 passed`). Targeted
relation-context provenance/recursive regressions passed (`5 passed`).
Targeted generic text-discovery persistence regressions passed (`2 passed`).
Targeted artifact URL/cloud persistence wrapper regressions passed (`2 passed`)
and the slow source-artifact cloud provenance regression passed (`1 passed`).
Targeted recursive artifact queue regressions passed again after URL-seed
persistence extraction (`3 passed`).
Targeted generic artifact-text persistence wrapper/adjacent regressions passed
after persistence-orchestrator extraction (`4 passed` total across two
commands).
Targeted parsed-artifact persistence/mobile-config/cloud-provenance regressions
passed after parsed-artifact coordinator extraction (`4 passed` total across two
commands).
Targeted Firebase/Supabase mobile-config persistence regressions passed after
mobile-config persistence extraction (`4 passed` total across three commands).
Targeted payload cloud-config wrapper regressions passed after payload
coordination extraction (`3 passed`), and the mobile-config feedback-seed
regression still passes (`1 passed`).
Targeted nested mobile member planning/result/rebase wrapper regressions passed
after nested-mobile helper extraction (`8 passed` total across two commands),
and adjacent real zip/tar nested mobile extraction regressions passed (`3
passed`).
Targeted per-member direct-family/rebase wrapper regressions passed after
member-routing extraction (`2 passed`), and adjacent archive/APKM/zip/tar
nested mobile regressions passed (`4 passed`).
Targeted top-level text artifact scan coordinator and adjacent mobile summary
regressions passed after scan-stage extraction (`3 passed` total across three
commands).
Targeted direct mobile bundle scan coordinator regressions passed after mobile
scan extraction (`2 passed` total across two commands).
Targeted ZIP/TAR/7z text archive member planning and payload regressions passed
after archive-member helper extraction (`7 passed` total across three
commands).
The same ZIP/TAR/7z text archive regressions passed after shared member-payload
coordinator extraction (`7 passed` total across three commands).
Targeted CPIO/ASAR archive regressions passed after reusing the shared
member-payload coordinator there too (`3 passed`).
Targeted archive-family precedence regression and WARC fixture passed after
archive-byte dispatcher extraction (`2 passed` total across two commands).
Targeted archive-family precedence regression and WARC fixture still passed
after archive payload-family dispatcher extraction (`2 passed` total across two
commands).
Targeted browser extension CRX/XPI package regression passed after CRX helper
extraction (`1 passed`), and archive-family precedence still passed (`1
passed`).
Targeted SAZ transcript/archive regressions passed after SAZ pairing helper
extraction (`2 passed` total across two commands).
The broad
`tests\phase1\test_engagement_orchestrator.py -k "synthesis_engine and not slow"`
selector previously timed out after 5 minutes and is not completion evidence.
Report history payload construction is now extracted to
`forge.reporting.report_history`: export ordering/descriptors, report-family
grouping, history payloads, latest-summary/count helpers, validation-inventory
summary fields, Markdown preview payloads, and latest-family file selection now live behind a public
reporting module. `forge.reporting.dashboard` keeps private compatibility
wrappers, and `forge.webui.app` imports the public helpers directly. Static
report summary/callout HTML rendering is now extracted to
`forge.reporting.report_rendering`, with dashboard compatibility wrappers
preserved. Verification: direct helper and dashboard preview-wrapper tests
passed (`4 passed`), direct report-rendering and wrapper tests passed (`3
passed`), static dashboard raw-export and family-history regressions passed (`2
passed` across separate long-running nodes before preview/rendering
extractions), live engagement API report-family history regression passed (`1
passed`). Report artifact finalization is now extracted to
`forge.orchestration.report_finalization`: planned/companion artifact
selection, non-empty checks, deterministic template fallback, raw-export
companion fallback, audit event shaping, and finalization metadata now live
outside `forge.cli`, while the CLI supplies its existing log/audit callbacks.
Verification: direct report-finalization helper tests passed (`6 passed`),
existing kill-chain report fallback regressions passed (`3 passed`), and
py_compile/Ruff passed for touched Python files. Terminal engagement-run
completion decisioning is now extracted to `engagement_run_terminal_entry()` in
`forge.orchestration.run_tracking`: report-ready/pending-work success checks,
failed-run error text, final phase, prereq metadata precedence,
elapsed/report/finalization metadata shaping, and pending-total calculation now
live outside the CLI while the CLI keeps DB/audit/cleanup/review side effects.
`terminal_artifact_queue_summary()` now owns deterministic
`artifact_queue_terminal_metrics` result formatting for queued/downloaded/
parsed/failed/skipped counts plus pending work total, while the CLI still writes
the audit row. `engagement_progress_counts()` and
`engagement_progress_queue_metrics()` now own DB-backed live-run progress counts
for cloud assets, cloud validations, vulnerability findings, artifact queue
depth, artifact status groups, cloud-validation status groups, and normalized
transient batch metric groups, while the CLI keeps the mutable
`run_progress_state` update wrapper. `record_run_progress_queue_group()` now
also owns repeated fanout/artifact/validation/finalization queue-group metric
shaping and active-stage ETA fields, leaving `forge.cli` with only the
DB/websocket flush side effect. Verification: direct run-tracking tests passed
(`15 passed`); the kill-chain recent-run telemetry regression passed when
ambient AWS provider env vars were cleared for the subprocess; existing
kill-chain report fallback completion regressions previously passed (`3
passed`).
Latest architecture checkpoint: `forge.orchestration.artifact_queue` now owns
artifact queue candidate dedupe/insert behavior, crawl-result seed promotion,
artifact-text-discovered URL queue entries, scope-denied queue audit shaping,
and idempotent `artifact_queue` writes. `forge.orchestration.artifacts`,
`forge.orchestration`, and legacy orchestrator imports keep compatibility
wrappers/re-exports. Verification: py_compile/Ruff for the new module,
compatibility modules, and artifact tests; queue-specific orchestration tests
(`8 passed, 141 deselected`); Phase 1 artifact queue processor dispatch
regression (`1 passed`).
Latest follow-up: the same `artifact_queue` module now also owns
status/local-path metadata shaping, downloaded local-path writes, and bounded
status/notes updates. `artifacts.py`, `forge.orchestration`, and the legacy
orchestrator aliases still re-export the moved helpers. Verification:
py_compile/Ruff for queue/compatibility/test files; focused
queue/status/local-path orchestration tests (`11 passed, 138 deselected`);
compatibility identity checks for the real legacy aliases returned true; Phase
1 artifact queue processor dispatch regression (`1 passed`).
Latest parsed-artifact split: `forge.orchestration.artifact_persistence` now
owns parsed-artifact DTOs, processing-summary counters, parsed-result
status/counter action shaping, and action application. `artifacts.py`,
`forge.orchestration`, and existing legacy DTO imports keep compatibility
re-exports. Verification: py_compile/Ruff for the persistence module,
compatibility modules, and artifact tests; focused persistence/queue parse tests
(`8 passed, 142 deselected`); Phase 1 artifact queue processor dispatch
regression (`1 passed`).
Follow-up: the same module now also owns the parsed-artifact DB persistence
coordinator, while low-level Firebase/Supabase/generic discovery store adapters
remain in `artifacts.py` behind injected callbacks. Verification:
py_compile/Ruff for persistence/compatibility/test files; focused
persistence/store/queue parse tests (`10 passed, 140 deselected`); Phase 1
queue dispatch and parse-stage regressions (`2 passed`).
Run-finalization follow-up: the report-finalization module now owns kill-chain
finalization report-path/argument construction, HIBP/credential-validation
specs, static active-validation specs, dry-run network-skip accounting, and
ordered pregraph/graph/report plan shaping. `forge.cli` still owns execution,
progress, audit writes, and DB-derived active-validation target discovery.
Verification: py_compile/Ruff for CLI/finalization/test files; direct
finalization-plan tests (`9 passed`); finalization dry-run/report-fallback
kill-chain regressions with ambient AWS env cleared (`3 passed`).
Run-tracking follow-up: `forge.orchestration.run_tracking` now owns the terminal
completion action bundle, including run status/error, final metadata, and
artifact-queue terminal audit summary. `forge.cli` still performs the audit
write, tracker finish call, marker cleanup, dashboard refresh, and
manifest-writing side effects. Verification: py_compile/Ruff for
CLI/run-tracking/test files; direct run-tracking tests (`17 passed`); terminal
telemetry/report-fallback kill-chain regressions with ambient AWS env cleared
(`3 passed`).
Manifest follow-up: `run_tracking` now also owns engagement-run audit-manifest
write/commit/rollback handling through an injectable helper/result, while
`EngagementRunTracker.finish_run()` keeps the run-row update and finalizer
lifecycle. Verification: py_compile/Ruff for run-tracking/export/test files;
direct run-tracking tests (`19 passed`).
Report-side-effect follow-up: `forge.orchestration.report_finalization` now also
owns the provider-key validation sweep and aggregate-stats JSON sidecar write
helpers, with injected dependencies for deterministic tests. `forge.cli` only
invokes those post-report side effects. Verification: py_compile/Ruff for
CLI/finalization/export/test files; direct report-finalization tests
(`13 passed`); terminal telemetry and report-fallback kill-chain regressions
with ambient AWS env cleared (`2 passed`).
Parsed-artifact adapter follow-up: `artifact_persistence.py` now owns the
Firebase/Supabase mobile-config and generic text-discovery persistence-entry
shapers; `artifacts.py`, `forge.orchestration`, and legacy processor wrappers
keep compatibility re-exports. Verification: py_compile/Ruff for
persistence/artifacts/export/legacy/test files; direct artifact-persistence
tests (`8 passed, 142 deselected`); legacy Phase 1 generic text, Firebase, and
Supabase persistence-prep regressions (`3 passed`).
Store-adapter follow-up: `artifact_persistence.py` now also owns the
Firebase/Supabase mobile-config store coordinators that write cloud refs,
derived seeds, source links, and key findings through injected callbacks;
`artifacts.py`, `forge.orchestration`, and legacy processor wrappers keep
compatibility re-exports. Verification: py_compile/Ruff for persistence/
artifacts/export/legacy/test files; focused artifact store tests (`4 passed,
146 deselected`); legacy Phase 1 Firebase/Supabase persistence-prep regressions
(`2 passed`).
Generic-text follow-up: `artifact_persistence.py` now owns
`ArtifactTextDiscoveryBatch` and the generic text-discovery persistence
coordinator that writes extracted emails, phones, IPs, hosts, URLs, identity
seeds, key findings, and cloud refs through injected callbacks; `artifacts.py`,
`forge.orchestration`, and legacy processor wrappers keep compatibility
re-exports. Verification: py_compile/Ruff for persistence/artifacts/export/
legacy/test files; direct generic-text persistence tests (`3 passed, 147
deselected`); legacy Phase 1 generic text persistence-prep regression
(`1 passed`).
Key/cloud store follow-up: `artifact_persistence.py` now owns
`store_artifact_key_finding`, `store_artifact_cloud_asset_reference`, and the
shared seed-metadata merge helper; `artifacts.py`, `forge.orchestration`, and
legacy wrappers keep compatibility re-exports. Verification: py_compile/Ruff
for persistence/artifacts/export/legacy/test files; focused key/cloud
persistence tests (`7 passed, 143 deselected`); legacy Phase 1 generic text,
Firebase, and Supabase persistence-prep regressions (`3 passed`).
URL-store follow-up: `artifact_persistence.py` now owns
`store_artifact_url_seed`, while `artifacts.py`, `forge.orchestration`, and
legacy processor wrappers keep compatibility re-exports. Verification:
py_compile/Ruff for persistence/artifacts/export/legacy/test files; focused
URL-store persistence tests (`5 passed, 145 deselected`); legacy Phase 1
generic text, Firebase, and Supabase persistence-prep regressions (`3 passed`).
Report-rendering follow-up: `forge.reporting.report_rendering` now owns the
report-history, report-preview, table, artifact-card, graph-summary,
graph-stage, audit-timeline, and operational-timeline HTML renderers while
`dashboard.py` keeps compatibility wrappers. Verification: py_compile/Ruff for
report rendering, dashboard, and focused report-rendering tests; direct
report-rendering tests (`11 passed`); prior-report, graph, and operational web
UI contracts (`3 passed`); report-family, graph, and timeline dashboard
regressions passed from a temp CWD to avoid local `.forge_data` legacy
engagement bleed-through (`10 passed`). Timeline event-shaper follow-up:
`forge.reporting.timeline` now owns operational timeline event construction
while `dashboard.py` keeps a compatibility wrapper. Verification: py_compile/
Ruff for timeline, dashboard, and focused tests; timeline/report-rendering tests
(`13 passed`); operational web UI contract (`1 passed`); monitoring review
dashboard regression passed from a temp CWD (`1 passed`). Evidence-provenance
follow-up: `forge.reporting.evidence_provenance` now owns dashboard
evidence-provenance summary row construction while `dashboard.py` keeps a
compatibility wrapper. Verification: py_compile/Ruff passed for evidence
provenance, timeline, dashboard, and focused tests; evidence/timeline tests
(`4 passed`); operational web UI contract (`1 passed`); monitoring review
dashboard regression passed from a temp CWD (`1 passed`). Next architecture
split should target dashboard page-composition boundaries if a clean boundary is
available.
Keep the default lane deterministic authorized ASM/CTEM. Use
free/no-key/open-source/local integrations first; paid APIs remain optional
adapters. Active validation must stay ROE/scope gated, observable,
non-destructive by default, and fail closed.

Previous checkpoint (2026-08-08): target-specific live-scope guard work landed in
the working tree. Live kill-chain and direct target helpers now reject
world-authorizing scope manifests before target matching or attack-mode
automation env vars are set. Blocked patterns include `authorized_seeds:
["*"]`, `0.0.0.0/0`, and `::/0`. `manifests/default.json` is now a safe
template instead of a global allowlist, and README/daily-use docs tell
operators to copy it per engagement. Verification: py_compile passed for
`forge/cli.py` and `forge/cli_helpers.py`; the full direct live-scope module
plus manifest-loader hardening tests passed (`40 passed`); Ruff passed for
touched Python files; `git diff --check` passed with only existing
CRLF-normalization warnings.

Previous checkpoint (2026-08-08): slow synthesis-test rewrite work landed in
the working tree. Eight social-profile synthesis tests that were previously
marked slow now assert candidate generation, metadata, reserved-handle
filtering, and relation intent directly through `EngagementSynthesisEngine`
helpers instead of bootstrapping SQLite engagements and running full synthesis.
The old "6 remaining slow synthesis-engine tests" handoff count is stale: four
broad persistence/backfill synthesis integration guards remain marked slow on
purpose. GitHub Dependabot alerts for `pytest<9.0.3` and `vcrpy<8.2.1` are
reported fixed. Verification: py_compile for the touched phase1 test file
passed; focused pytest node run for the eight rewritten tests passed
(`8 passed`). Collection still imports the monolithic phase1 test file, so the
focused run remains slow at collection time even though the rewritten tests no
longer do full DB synthesis runs.

Previous checkpoint (2026-08-08): cross-platform local-operator runnable work
landed in the working tree. macOS/Linux now have POSIX launcher parity for
setup, menu, kill-chain prompts, status, report generation, hydration/local
workspace verification, and the dev/evidence Docker stack. Windows
`tools/forge-stack.ps1` now points at the actual
`docker/docker-compose.dev.yml` path. Active goal docs now point to existing
source-of-truth files only. Verification: focused launcher/setup/helper tests
passed (`23 passed`), Ruff passed for touched Python files, shell syntax checks
passed for all POSIX scripts, and `git diff --check` passed with only existing
CRLF-normalization warnings.

Latest checkpoint (2026-08-05): 24-task post-audit hardening arc landed on
`origin/main` up to `ea57716`. 8 tasks shipped this iteration:

- Task 12 — 134 bare `sqlite3.connect()` sites migrated to `direct_connect`
  helper (`forge/db/direct_connect.py`, [`59a5a93`](../../commit/59a5a93)).
- Task 17 — 12 slowest synthesis-engine tests marked `@pytest.mark.slow`
  (`tests/phase1/test_engagement_orchestrator.py`,
  [`d5e0c0b`](../../commit/d5e0c0b)).
- Task 18 — 9 new safe passive artifact parsers
  (`forge/phase4/artifact_parsers.py`, [`7c408a5`](../../commit/7c408a5)).
- Task 19 — 9 provider key validators with strict payload-shape checks
  (`forge/phase4/provider_key_validators.py`,
  [`896b1d8`](../../commit/896b1d8)).
- Task 20 — 6 identity normalizers with aggressive dedup
  (`forge/utils/intel/identity_normalization.py`,
  [`f1fcd8e`](../../commit/f1fcd8e)).
- Task 21 — mixed-provider e2e fixture combining tasks 18+19+20
  (`tests/integration/test_mixed_provider_e2e.py`,
  [`58e1965`](../../commit/58e1965)).
- Task 22 — richer report aggregate stats across MD + dashboard + JSON sidecar
  (`forge/phase6/aggregate_stats.py`, [`aa5bd3b`](../../commit/aa5bd3b)).
- Task 23 — HTMX server-rendered engagement detail tabs at
  `/engagements/{ref}/htmx` (`forge/webui/app.py` +
  `forge/webui/templates/htmx/*.html`, [`8d0ece5`](../../commit/8d0ece5) +
  [`ea57716`](../../commit/ea57716)).

Verification: 327 session tests green across HTMX (13), phase4 parsers +
validators, intel normalizers, phase6 aggregate stats, and the mixed-provider
e2e fixture. Nothing above breaks the deterministic gate chain in
`docs/deterministic_engagement_contract.md`; every shipped item is passive,
scope-gated, and audit-logged.

Companion work already on `origin/main` from earlier in the arc: cloud_ref
seed rollout (4 slices [`582703b`](../../commit/582703b) →
[`042c8db`](../../commit/042c8db)), bounded worker-pool primitive
([`208b8c5`](../../commit/208b8c5)), PyJWT swap
([`b347cd8`](../../commit/b347cd8)), Bandit + Semgrep SAST workflows
([`9bf521d`](../../commit/9bf521d) + [`90199d8`](../../commit/90199d8)),
Dependabot ecosystem grouping ([`a1cd662`](../../commit/a1cd662)), 2 batches
of P1/P2/P3 audit-pipeline fixes ([`2dbad66`](../../commit/2dbad66) +
[`51c17ad`](../../commit/51c17ad)), Python-side stale rebuild filter
([`83f85d4`](../../commit/83f85d4)), autouse permissive scope-manifest fixture
([`d5feba8`](../../commit/d5feba8)), and closure of the 2026-07-09 audit's 6
P2/P3 UX drift items ([`203ad86`](../../commit/203ad86),
[`7c24b88`](../../commit/7c24b88), [`498cf12`](../../commit/498cf12),
[`c0e2cd5`](../../commit/c0e2cd5), [`9a8de32`](../../commit/9a8de32),
[`11d76b5`](../../commit/11d76b5), [`a6ea92d`](../../commit/a6ea92d)).

Next-agent focus: (a) reduce the four remaining slow synthesis integration
guards only if their persistence/backfill assertions can be preserved as narrow
unit coverage; (b) keep expanding provider-specific validation depth only where
a concrete long-tail low-signal proof gap is found; (c) continue safe passive
parser coverage only for concrete missing artifact/source shapes. Older resume
notes below remain accurate for pre-2026-08-05 context.

---

Previous checkpoint (2026-07-25): compact canonical raw-export all-surface E2E
is complete.

`tests/integration/test_canonical_release_e2e.py` creates a multi-seed
engagement through the live API, launches mocked non-dry-run `kill-chain` with
explicit ROE/scope manifest, proves recursive web/identity/artifact/cloud
pivots, runs real static APK/config parsing, synthesis, deterministic
validation/finding gates, graph/MTGX export, template-to-raw JSON/CSV fallback,
dashboard/API/download parity, report history/checksums,
`report_findings_included` audit receipt, verified run audit manifest, cleanup
helper scoping, and no ID reuse after deleting the numeric DB. Verification:
canonical E2E passed (`1 passed`), focused fallback/API/cleanup bundle passed
(`9 passed`), existing dashboard smoke passed (`1 passed`), Ruff passed, and
py_compile passed. `SPEC.md` T1 is now closed.

Next checkpoint: add first-class `cloud_ref` seed support if still
product-required. Current schema/API classifiers persist HTTP cloud refs as
`url` and non-HTTP provider refs as `other`; implementing `cloud_ref` requires a
schema/migration update, API classifier/canonicalizer changes, seed validation
rules, synthesis/dispatcher routing, dashboard labels, and focused tests proving
cloud refs remain ROE/scope-gated and cannot bypass validation-before-reporting.

Previous checkpoint: OCI/Docker-save kill-chain review parity is complete. Local
static OCI image-layout and Docker-save archives now have an engagement-backed
parity regression proving only referenced configs/layers are parsed,
unreferenced decoy layers and path-traversal members do not create seeds/assets,
discovered refs feed validation inventory and deterministic finding gates, and
sanitized `#oci-layer/` / `#docker-layer/` provenance reaches seed relations,
recursive seed metadata, cloud-asset metadata, Phase 4 graph gates, dashboard
detail payloads, Phase 6 Markdown, JSON, CSV, and raw export rows. Non-HTTP
local artifacts now get a synthetic completed `artifact://queue/{id}` source
seed so derived seeds have graph lineage without exposing local paths as
recursive live targets. Verification: OCI/Docker review parity regression
passed (`1 passed`), adjacent OCI/container artifact suites passed (`10
passed`), Phase 4 cloud/artifact graph selectors passed (`12 passed, 100
deselected`), Phase 6 cloud/report-artifact suites passed (`2 passed`),
dashboard cloud/artifact selectors passed (`19 passed, 13 deselected`), Ruff
passed, py_compile passed, and `git diff --check` passed with only the repo's
known LF-to-CRLF warning.

Previous checkpoint: remote Helm repository recursion is complete. Mocked
scoped Helm `index.yaml` processing now queues only safe in-scope chart
archives, parses the later `.tgz/.tar.gz`, preserves
`helm-index -> chart -> values.yaml` provenance via `helm_index_url`, and
promotes chart-derived hosts, emails, Firebase refs, and S3 refs into recursive
seeds/cloud assets with relation and audit evidence. Generic direct URL
extraction no longer bypasses Helm index safety filters for chart archives, and
queue-time scope rejection keeps out-of-scope chart packages out of
`artifact_queue` when a scope checker is configured. Verification: focused Helm
recursion suite passed (`6 passed, 2 deselected`), adjacent artifact
provenance/cloud/remote-download suites passed (`15 passed`), adjacent
dashboard artifact/cloud slices passed (`9 passed, 23 deselected`), adjacent
Phase 6 report/raw-export slices passed (`15 passed, 95 deselected`), Ruff
passed, py_compile passed, and `git diff --check` passed with only the repo's
known LF-to-CRLF warnings.

Previous checkpoint: legacy cloud-audit reportability is complete. Legacy
`FIREBASE_MISCONFIG`, `FIREBASE_CREDENTIAL_STATUS`, `AWS_MISCONFIG`, and
`AZURE_MISCONFIG` rows now fail closed across Phase 6 report context,
Markdown/JSON/CSV exports, dashboard finding tables/severity summaries, and
attack-graph VULN nodes unless they have a latest linked reportable validation
row or a stable explicit authenticated-audit receipt. Firebase, AWS, and Azure
audit writers now persist compact non-secret receipts for new authenticated
audit output. Verification: focused helper/report/dashboard/graph regressions
passed (`19 passed`), adjacent graph/dashboard/report selectors passed (`36
passed, 217 deselected`), Ruff passed, py_compile passed, and `git diff
--check` passed.

Previous checkpoint: artifact processor worker-cap is complete. Static artifact
queue processing no longer inherits full global `--parallel-fanout` by default.
`FORGE_ARTIFACT_PROCESSOR_MAX_WORKERS` provides a bounded `1..4` cap, the
effective artifact worker count is `min(parallel_fanout, cap)`, and run
metadata records both the effective worker count and configured cap outside
transient queue metrics. Verification: artifact processor cap helper test
passed (`1 passed`), focused remote APK kill-chain artifact regression passed
(`1 passed`), adjacent worker-cap selector passed (`6 passed, 26 deselected`),
Ruff passed, and py_compile passed.

Previous checkpoint: audit-manifest report-family parity is complete. Run audit
manifests now treat deterministic report `.html` and report `.csv` companions
as first-class report-family artifacts alongside `.md`, `.json`, and `.pdf`.
Manifest hashing remains whitelist-based, signed bundle exports now verify
manifests containing the full report family, and HTML/CSV tamper is detected as
a manifest hash mismatch. Verification: run audit manifest suite passed (`11
passed`), run audit manifest bundle suite passed (`7 passed`), Ruff passed, and
py_compile passed.

Previous checkpoint: scope-boundary denial reviewability is complete. Dashboard
static exports and the live engagement detail API now surface scheduled,
recursive-seed, remote-artifact, cloud-validation, key-validation, and
automation scope denials in one dedicated `scope_denials` review section even
after those audit rows fall out of the recent audit timeline. Scope-manifest
payload assignments and URLs in denial result text are redacted before
truncation. Verification: full static dashboard suite passed (`31 passed`),
focused live API scope-denial/scope-preflight slice passed (`4 passed, 49
deselected`), focused live denial test passed (`1 passed`), Ruff passed, and
py_compile passed.

Previous checkpoint: provider-proof identity source-of-truth is complete. Phase
4 provider identifier extraction now delegates to
`parse_provider_validation_identity()`, which first applies the same
`parse_validated_detail()` reportability gates used by report/dashboard/graph
surfaces. Provider proof decisions for AWS, GitHub, GitLab, Hugging Face,
Vercel, Netlify, Notion, PostHog, Sentry, SendGrid, Stripe, Twilio, Slack,
Discord, Telegram, Cloudflare, and known validation-inventory-only providers
now have a parity contract instead of a duplicated parser. Verification:
provider/core proof suites passed (`129 passed`), Phase 4 provider-active
slice passed (`2 passed, 134 deselected`), dashboard proof gate slice passed
(`2 passed, 29 deselected`), attack-path proof gate slice passed (`6 passed,
105 deselected`), Phase 6 linked-proof slice passed (`2 passed`), Ruff passed,
py_compile passed, and `git diff --check` passed.

Previous checkpoint: modern image/favicon artifact route recursion is complete.
Artifact-side HTML/CSS route extraction now treats common passive image and
favicon assets (`.avif`, `.bmp`, `.heic`, `.heif`, `.ico`, `.tif`, `.tiff`) as
useful static route suffixes. Modern image pivots flow into recursive URL
seeds and queue as document artifacts where classification already supports
them; favicon ICOs become recursive URL seeds without forcing binary parsing.
Verification: focused CSS/HTML artifact route suite passed (`3 passed`),
adjacent route/classification/recursive queue suite passed (`25 passed`),
adjacent SPA route and same-iteration URL seed E2E slice passed (`2 passed`),
Ruff passed, py_compile passed, and `git diff --check` passed.

Previous checkpoint: Hugging Face profile-proof hash gate is complete.
Hugging Face token validation now emits a non-sensitive `profile_hash` from
stable whoami profile-presence fields, and both core proof parsing and Phase 4
identifier extraction require that hash before treating `whoami` success as
reportable. Hashless `user_profile_present=true` details now downgrade to
validation inventory only. Verification: focused Hugging Face validator test
passed (`1 passed`), core profile-provider proof slice passed (`80 passed, 30
deselected`), Phase 4 identifier test passed (`1 passed`), Phase 4 provider
active downgrade slices passed (`2 passed`), Hugging Face secret finder slice
passed (`7 passed, 167 deselected`), Ruff passed, py_compile passed, and
`git diff --check` passed.

Previous checkpoint: barcode cloud-asset provenance parity is complete.
Artifact-derived cloud assets now preserve non-zero passive payload proof
counts, including `barcode_payload_count`, while omitting zero-value noise that
can crowd out source provenance in dashboard previews. QR/barcode discovered
Firebase references keep their passive artifact origin through cloud asset
storage and attack-graph metadata. Verification: focused barcode-to-cloud
provenance test passed (`1 passed`), full artifact cloud reference suite passed
(`3 passed`), adjacent artifact barcode/review slice passed (`9 passed`), Ruff
passed, py_compile passed, and `git diff --check` passed.

Previous checkpoint: barcode recursive provenance parity is complete.
QR/barcode-derived recursive seeds now preserve `barcode_payload_count`
provenance in seed metadata and artifact relation context, matching the
artifact-level parse summary already stored on queued artifacts. This keeps
barcode pivots reviewable as passive artifact-derived recursion rather than
anonymous secondary seeds. Verification: focused artifact barcode suite passed
(`8 passed`), adjacent artifact provenance/review surface slice passed
(`13 passed`), Ruff passed, py_compile passed, and `git diff --check` passed.

Previous checkpoint: bare HTML artifact asset recursion is complete. Static
artifact parsing now resolves bare same-directory HTML asset references such as
`src=app.js`, `href=style.css`, manifest links, image sources, and meta-refresh
URLs against the remote source HTML URL. The existing safe resolver still
rejects unsafe schemes and only promotes useful static route suffixes into
recursive URL seeds and queued artifacts. Verification: focused CSS/HTML
artifact route suite passed (`3 passed`), adjacent artifact recursive queue and
JS runtime suites passed (`12 passed`), adjacent SPA route and same-iteration
URL seed E2E slice passed (`2 passed`), Ruff passed, py_compile passed, and
`git diff --check` passed.

Previous checkpoint: bare CSS artifact asset recursion is complete. Static
artifact parsing now resolves common bare same-directory CSS dependencies such
as `@import "theme.css"`, `@import url(print.css)`, and `url(hero.png)` against
the remote source stylesheet URL. Those dependencies flow through the existing
safe route resolver, seed persistence, and queued artifact path without
enabling unsafe schemes. Verification: focused CSS/HTML artifact route suite
passed (`2 passed`), adjacent artifact recursive queue and JS runtime suites
passed (`11 passed`), adjacent SPA route and same-iteration URL seed E2E slice
passed (`2 passed`), Ruff passed, and py_compile passed.

Previous checkpoint: linked Slack bot-token proof gates are complete. Slack
bot-token key rows and deterministic key-exposure findings can no longer become
report/dashboard/graph/deterministic findings from standalone legacy
`VALIDATED:slack_auth_test` strings. Fresh Slack provider validation remains
reportable when the latest linked `cloud_validation_results` row is
proof-stable and bound to the `team_id/actor_id` provider identifier.
Verification: focused Phase 6/dashboard/deterministic/attack-graph Slack gate
slice passed (`6 passed`), full Phase 6 report synthesizer suite passed
(`108 passed`), full dashboard suite passed (`31 passed`), deterministic
findings plus attack graph suites passed (`130 passed`), adjacent cloud
validation/stable-proof slice passed (`3 passed`), and Ruff passed.

Previous checkpoint: CSS/HTML artifact route recursion is complete. Static
artifact parsing now extracts common CSS `url(...)` dependencies and HTML route
attributes, `srcset`, and meta-refresh targets from remote artifact payloads,
resolving them against the source artifact URL through the existing safe route
resolver. This promotes stylesheet, bundle, image/font, manifest, and route
pivots into recursive URL seeds and queued artifacts without relying on the live
crawler path. Verification: focused CSS/HTML artifact route suite passed
(`2 passed`), adjacent artifact recursive queue and JS runtime suites passed
(`9 passed`), adjacent SPA route and same-iteration URL seed E2E slice passed
(`2 passed`), Ruff passed, and py_compile passed.

Previous checkpoint: archived-PDF barcode recursion and linked bot-token proof
gates are complete. Static archive parsing no longer requires Tesseract before
extracting barcode pivots from embedded rendered PDF pages, so ZIP-contained
scanned PDFs can feed QR URLs back into recursive URL seeds when a rasterizer is
available. Discord/Telegram bot-token key rows can no longer become
report/dashboard/graph/deterministic findings from standalone legacy
`VALIDATED:*` strings; fresh provider validation remains reportable only when a
latest linked `cloud_validation_results` row is reportable and proof-bound to
the provider bot ID. Verification: focused gate slice passed (`32 passed`),
artifact/deterministic focused suites passed (`27 passed`), full Phase 6 report
synthesizer suite passed (`108 passed`), full dashboard suite passed
(`31 passed`), full attack graph suite passed (`110 passed`), full cloud
validation suite passed (`136 passed`), stable-proof integration/core slice
passed (`111 passed`), Ruff passed, py_compile passed, and `git diff --check`
passed.

Previous checkpoint: seed-to-report audit traceability is complete. The
service-worker/precache kill-chain E2E now proves one reportable Supabase
finding from derived seed relation and parsed artifact through cloud
validation, deterministic rule-engine `HIGH` severity, report JSON/checksum
inclusion, attack-graph nodes, dashboard review rows, and audit receipts.
Production now writes per-finding deterministic rule applied/skipped receipts,
batch `deterministic_finding_synthesis` receipts, and Phase 6
`report_findings_included` receipts with provider lineage, finding count,
checksum, and included targets. Verification: focused service-worker/precache
E2E passed (`1 passed`), deterministic finding suite passed (`18 passed`),
full Phase 6 report synthesizer suite passed (`108 passed`), adjacent Phase
6/latest-validation gate slice passed (`3 passed`), Ruff passed, and
py_compile passed.

Previous checkpoint: validation/reportability matrix parity is complete. The
stable-proof integration fixture proves the shared reportability gate across
`VALIDATED`, weak-effective `UNVERIFIED`, raw `DEAD`, `HONEYPOT_SUSPECTED`, and
`ACCESSIBLE_BUT_NO_DATA` rows. Stale deterministic findings for
dead/accessible resources remain validation inventory only across Phase 6
report/JSON/CSV, cloud asset inventory/raw asset rows, attack graph,
dashboard/API detail, live `/api/engagements/{id}/assets`, vuln summary, helper
gates, and deterministic finding cleanup. Verification: expanded stable-proof
integration fixture passed (`1 passed`), adjacent Phase 6/latest-validation
gate slice passed (`2 passed`), Ruff passed, and py_compile passed.

Previous checkpoint: recursive discovery E2E seed-run proof is complete. The
service-worker/precache kill-chain E2E now launches with explicit ROE/scope
manifest, mocks RDAP/archive/API URL paths to converge deterministically, and
proves newly discovered secondary seeds are processed through audit-visible
`seed_runs`: derived email E-chain, derived username fan-out, derived URL D5
fetch, and over-depth skip receipts. Dashboard detail JSON also proves the
completed/skipped recursive seed-run rows are reviewable. Verification: focused
service-worker/precache E2E passed (`1 passed`), adjacent depth-limit and
pending-work retry-state slice passed (`2 passed`), Ruff passed, and py_compile
passed.

Previous checkpoint: non-graph cloud asset inventory metadata sanitization is
complete. Live `/api/engagements/{id}/assets`, Phase 6 cloud asset inventory,
report JSON/raw CSV, and static dashboard cloud asset tables now reuse the
shared allowlisted cloud-asset metadata sanitizer. Arbitrary nested/raw
metadata, variant secret keys, URL userinfo, and sensitive URL query parameters
from `cloud_assets.metadata_json` are stripped while artifact provenance remains
reviewable. Verification: focused live/API/report/dashboard sanitizer
regressions passed (`3 passed`), full Phase 6 report synthesizer suite passed
(`108 passed`), adjacent dashboard/API cloud asset tests passed (`2 passed`),
stable-proof integration fixture passed (`1 passed`), Ruff passed, and
py_compile passed.

Previous checkpoint: dashboard/API fallback graph cloud metadata sanitization is
complete. Fallback graph cloud nodes now use the same shared allowlisted
cloud-asset graph metadata sanitizer as saved attack-graph snapshots, so
variant secret keys, raw config blobs, URL userinfo, and sensitive URL query
parameters from `cloud_assets.metadata_json` do not enter static dashboard
graph payloads or live engagement detail API graph payloads. Verification:
static/live fallback graph regressions passed (`2 passed`), artifact graph
provenance plus fallback graph slice passed (`3 passed`), Phase 4
cloud/snapshot selector passed (`16 passed, 93 deselected`), Ruff passed,
py_compile passed, and `git diff --check` passed.

Previous checkpoint: max-iteration pending-work finalization is complete.
Kill-chain finalization now fails the engagement run when a report artifact
exists but `pending_work_total > 0`, records
`max iterations exhausted with pending recursive work: <count>` as the run
error, and avoids console wording that claims full completion when retryable
work remains. Verification: root-keyscan pending-work status regression passed
(`1 passed`), full retry-state suite passed (`17 passed`),
report-finalization fallback slice passed (`4 passed`), Ruff passed,
py_compile passed, and `git diff --check` passed.

Previous checkpoint: Phase 6 raw-validation reportability is complete. Phase 6
now trusts the raw-derived `validation_reportable` flag attached from the
latest cloud validation row before falling back to summary re-parsing for
legacy evidence. This prevents sanitized/truncated summaries from dropping a
genuinely validated deterministic cloud exposure from report context, JSON, and
raw CSV finding rows. Verification: focused summary-redaction regression plus
adjacent S3 validation report test passed (`2 passed`), full Phase 6 report
synthesizer suite passed (`108 passed`), stable-proof integration fixture
passed (`1 passed`), Ruff passed, py_compile passed, and `git diff --check`
passed.

Previous checkpoint: attack-graph artifact cloud provenance is complete.
AttackGraphBuilder now loads scrubbed `cloud_assets.metadata_json` into
allowlisted CLOUD node provenance, so saved `attack_graph_snapshots` preserve
artifact provenance fields such as `artifact_source_seed_id`, `source_url`,
`source_file`, `extract_rule`, and `format` when the dashboard prefers a
snapshot over its fallback graph. Sensitive metadata keys such as `apiKey`,
`accessToken`, `clientSecret`, `api-key`, and `refreshToken` are stripped, raw
config blobs are dropped, and URL provenance is sanitized before graph snapshot
persistence. Verification: focused artifact cloud provenance regression passed
(`1 passed`), adjacent artifact review/cloud-reference suite passed
(`3 passed`), Ruff passed, py_compile passed, and `git diff --check` passed.

Previous checkpoint: cloud-key provider exception receipts are complete. Cloud
key validation worker exceptions now persist non-reportable
`UNVERIFIED / provider_exception` receipts, update key row `validation_detail`
and `validated_at`, release validation claims, and keep raw exception text out
of API/persisted notes. A second `only_unattempted=True` sweep no longer
reclaims the same failed rows. Verification: focused cloud-key
exception/claim/progress slice passed (`5 passed`), key runtime suite passed
(`5 passed`), broader cloud validation sweep slice passed
(`46 passed, 90 deselected`), Ruff passed, and py_compile passed.

Previous checkpoint: GitHub-org keyscan fresh-resume retrying is complete.
Failed `fanout_f_keyscan` composite org targets now reload from failed seed-run
rows, stay constrained to current scoped root domains, count toward
`github_orgs` pending work, and schedule through the existing scoped keyscan
path even when already-completed host-surface parsing is skipped and no GitHub
links are rediscovered. Verification: focused keyscan resume/retry slice passed
(`4 passed`), full retry-state suite passed (`17 passed`), Ruff passed,
py_compile passed, and a sidecar patch review approved with no blocking
findings.

Previous checkpoint: root-domain keyscan pending-work accounting is complete.
Failed root-domain `fanout_f_keyscan` work now contributes
`root_keyscan_domains` to kill-chain pending-work metadata, so a stable
snapshot cannot terminate as complete while the root keyscan remains retryable.
Verification: focused keyscan retry/per-root slice passed (`3 passed`), full
retry-state suite passed (`16 passed`), Ruff passed, and py_compile passed for
touched files.

Previous checkpoint: cloud-asset validation claim alias gating is complete.
Active validation claims now compare normalized cloud asset types and
case-normalized identifiers, so a live `s3/shared-assets` claim blocks
concurrent canonical `aws_s3/shared-assets` validation attempts until the claim
expires or is released. Verification: cloud-validation asset alias suite passed
(`3 passed`), and Ruff plus py_compile passed for touched files.

Previous checkpoint: host-surface resume retry fairness is complete. Pending
`fanout_d_host_surface` rows that were attempted before but not completed now
run before never-attempted known hosts, so abandoned/recovered hosts are retried
in the next resumed D-stage batch while new-host backlog remains visible in
pending-work metadata. Verification: focused host-surface retry/backlog slice
passed (`2 passed`), adjacent stale-running recovery regression passed
(`1 passed`), and Ruff plus py_compile passed for touched files.

Previous checkpoint: legacy validation-inventory finding gates are hardened.
`vulnerability_findings` rows tagged as validation inventory, or generic rows
whose evidence parses to non-reportable validation detail such as
`validation=UNVERIFIED:*`, no longer appear in Phase 6 reports, report JSON,
raw CSV exports, static dashboard finding sections/counts, live detail severity
summaries, or `/vuln-summary`. Verification: focused Phase 6/dashboard/API
regressions passed (`3 passed`), adjacent report gate slice passed
(`5 passed`), adjacent dashboard gate slice passed (`7 passed`), and Ruff plus
py_compile passed for touched files.

Previous checkpoint: bounded artifact retry and cloud-reference resume
stability are complete. `artifact_queue` now has deterministic `attempt_count`
/ `max_attempts` state, retryable failed rows remain pending until exhausted,
and Fan-out J cloud refs use one normalized `service:ref` key across
current-run, pending-count, skipped-row, and resume paths while keeping
original refs in command/audit/provider metadata. Verification: focused
retry/cloud slice passed (`5 passed`); adjacent artifact retry/cloud alias
tests passed (`2 passed`); Ruff and py_compile passed for touched backend/test
files.

Previous checkpoint: Terraform DNS record extraction now works from archive
members. Generic artifact discovery carries a parser-only member-aware
`source_hint` through the bounded worker-pool path, so `terraform/main.tf`
inside zip/OCI/Docker-style archive members promotes recursive host seeds while
persisted `source_file`/`source_url` provenance remains the outer artifact.
Verification: Terraform/archive/OCI focused slice passed (`8 passed`); Ruff and
py_compile passed for touched files.

Previous checkpoint: static dashboard and live web API report summaries now
carry Phase 6 `render_path` lineage in addition to requested/rendered/backend
provider fields, and the static dashboard backend summary renders the path for
review. Verification: focused static dashboard/API lineage tests passed
(`3 passed`); Ruff, py_compile, and `git diff --check` passed.

Previous checkpoint: static dashboard and live web API report-family discovery now
include deterministic `.html` Phase 6 report companions alongside Markdown,
PDF, JSON, and CSV. Report history/export descriptors label HTML explicitly,
and engagement detail artifacts expose the HTML download link. Verification:
focused static dashboard/API report-family tests passed (`3 passed`); Ruff,
py_compile, and `git diff --check` passed.

Previous checkpoint: Phase 6 now emits a deterministic `.html` report-family
artifact from the exact decorated Markdown, and report JSON/CSV/raw-export
lineage carries explicit `render_backend` plus `render_path`. Cloud asset
validation batches now persist non-reportable
`UNVERIFIED / validator_exception` receipts for per-asset validator exceptions
instead of aborting the batch, and kill-chain cloud validation pending counts
use the same alias-normalized asset-type join as validation claims. Verification:
Phase 6 fallback HTML/lineage slice passed (`6 passed`); Phase 4
exception/mixed batch slice passed (`3 passed`); Phase 1 cloud retry/alias
metadata slice passed (`2 passed`); engagement-pipeline fallback slice passed
(`3 passed`); dashboard/API raw-export lineage slice passed (`3 passed`);
Ruff, py_compile, and `git diff --check` passed; `.forge_data/engagements` was
empty after tests.

Current verification: reporting fallback and Fan-out J unsupported-cloud
receipt behavior are re-verified on current `main`. Phase 6 fallback slice
passed (`10 passed`), engagement-pipeline fallback slice passed (`2 passed`),
dashboard/API raw-export lineage slice passed (`3 passed`), and
`test_kill_chain_retries_failed_executable_cloud_scan_refs_only` passed
(`1 passed`). No code changes were needed for these two verification items.

Previous checkpoint: dashboard/API key-scanner findings now require the parsed
stable-proof gate. Raw or legacy `VALIDATED:` validation-detail prefixes no
longer bypass `_key_row_is_reportable`, so stale/bare
Firebase/Supabase/Sentry-style key rows stay out of reportable engagement
detail key findings while validation review inventory remains available
elsewhere. Verification: stable-proof surface integration passed (`1 passed`);
focused dashboard key/validation slice passed (`13 passed, 16 deselected`);
focused report-synthesizer key exclusion tests passed (`2 passed`); Ruff,
py_compile, and `git diff --check` passed.

Previous checkpoint: Fan-out F GitHub-org keyscan scope was re-verified.
Current `main` already routes discovered GitHub orgs as root-attributed
`osint keyscan --domain <in-scope-root> --org <github_org>` work items using
composite target keys (`<root>::github_org::<org>`), deterministic dedupe, and
seed-run metadata containing `origin=keyscan_org`, `query_domain`, and
`github_org`. The stale unchecked backlog item was verified rather than
reimplemented. Verification: focused retry/per-root org keyscan tests passed
(`2 passed`), root child scope-manifest propagation test passed (`1 passed`),
Ruff passed for `forge/cli.py` plus focused keyscan tests, and py_compile
passed for the same files.

Previous checkpoint: recursive depth-limit persisted-seed coverage is complete.
Existing kill-chain code already filters over-depth persisted URL, email,
username, phone, IP, name, and company seeds before executable dispatch and
records auditable skipped seed-run receipts with
`synthesis_depth_limit_exceeded`. Added a focused dry-run regression proving
over-limit persisted seeds remain stored at their original depth while each
major recursive fan-out writes only a skipped receipt and no completed
follow-on run. Verification: Ruff and py_compile passed for
`tests/phase1/test_engagement_orchestrator.py`; focused depth-limit test passed
(`1 passed in 21.89s`).

Previous checkpoint: scoped cloud-reference inventory and deterministic finding
finalization are complete. HTML/passive-text cloud refs that pass scope now
persist into `cloud_assets` before Fan-out J validation, and a final
deterministic finding synthesis pass runs after final cloud validation before
graph/report generation. The mocked recursive E2E validation stub mirrors
production conflict updates by replacing evidence/notes and writing stable
proof strings for validated Firebase/Supabase rows. Dashboard detail pages now
pick representative vulnerability finding titles before filling the section
limit, so duplicate recent rows do not hide another validated finding class
from review. Verification: Ruff, py_compile, and `git diff --check` passed for
touched files; focused dashboard tests passed; artifact/static adjacent tests
passed (`13 passed`); cloud validation focused slice passed (`5 passed, 128
deselected`); the mocked recursive kill-chain E2E passed (`1 passed in
280.80s`); no workspace `.forge_data/engagements` leftovers were listed.

Previous checkpoint: AndroidManifest attribute-aware static extraction is
complete. `AndroidManifest.xml` is now a first-class static artifact label.
Direct XML manifests and archive members preserve raw XML attributes instead of
being stripped through generic `itertext()` extraction. The parser inventories
valid Android package names as `mobile_android_package` assets and emits only
safe HTTP(S) BROWSABLE/VIEW deep-link URL seeds while rejecting custom schemes,
templated values, localhost/private hosts, wildcard hosts, and malformed
packages. No APK execution, dynamic analysis, live probing, credential
validation, or scope relaxation was added. Verification: focused
AndroidManifest tests passed (`3 passed`), adjacent Android/mobile metadata
tests passed (`6 passed`), py_compile passed for touched files, Ruff passed for
touched files, `git diff --check` passed, and no `.forge_data/engagements`
leftovers were present.

Previous checkpoint: Sanity runtime public-env static extraction is complete.
Public runtime JavaScript config extraction now derives passive Sanity API
pivots from public env maps containing both a valid Sanity project ID and a
dataset (`NEXT_PUBLIC_SANITY_*`, `VITE_SANITY_*`, and adjacent public naming
variants). The derived `https://<project>.api.sanity.io` URL feeds the existing
recursive seed path, while project-only values are ignored to reduce false
positives. No Sanity API calls, dataset reads, credential validation, service
probing, or scope relaxation were added. Verification: focused Sanity/runtime JS
config tests passed (`9 passed`), broader current artifact regression slice
passed (`21 passed`), py_compile passed for touched files, Ruff passed for
touched files, `git diff --check` passed, and no `.forge_data/engagements`
leftovers were present.

Previous checkpoint: Cloud Run provider-shape support is complete. Qualified
`*.run.app` URLs are now treated as managed provider hosts rather than generic
domains/subdomains. Artifact URL extraction maps them to `gcp_cloud_run` cloud
assets with the qualified hostname as identifier, and the cloud validation
registry wires `gcp_cloud_run` through the existing managed-hosting reachability
contract. No new probing logic, credential use, or scope relaxation was added.
Verification: direct Cloud Run mapping check passed, focused
managed-hosting/registry tests passed (`3 passed, 132 deselected`), adjacent
managed-hosting reachability/registry tests passed (`3 passed`), py_compile
passed for touched files, Ruff passed for touched files, `git diff --check`
passed, and no `.forge_data/engagements` leftovers were present.

Previous checkpoint: Sanity CMS config static artifact discovery is complete.
`sanity.config.*`, `sanity.cli.*`, and `sanity.json` are now first-class static
config artifacts. Static `projectId` plus `dataset` context is parsed from
JavaScript/TypeScript, JSON, or YAML-like files and emitted as the passive
`https://<project>.api.sanity.io` recursive URL seed. No Sanity API calls,
dataset reads, credential validation, service probing, or scope relaxation were
added. Verification: focused Sanity/Supabase/Redocly tests passed (`6 passed`),
broader current artifact regression slice passed (`14 passed`), py_compile
passed for touched files, Ruff passed for touched files, `git diff --check`
passed, and no `.forge_data/engagements` leftovers were present.

Previous checkpoint: Supabase CLI config static artifact discovery is complete.
`supabase/config.toml` is now a first-class static config artifact. Bare
`project_id`, `project_ref`, or `ref` values are parsed from TOML or bounded
key-value fallback and emitted as passive `https://<ref>.supabase.co`
recursive URL seeds; the existing cloud-asset persistence then records the
Supabase project reference. No Supabase API calls, credential validation,
service probing, or scope relaxation were added. Verification: focused
Supabase/Redocly/Backstage tests passed (`6 passed`), broader current artifact
regression slice passed (`12 passed`), py_compile passed for touched files,
Ruff passed for touched files, `git diff --check` passed, and no
`.forge_data/engagements` leftovers were present.

Previous checkpoint: Redocly API-docs config static artifact discovery is
complete. `.redocly.yaml`, `.redocly.yml`, `.redocly.json`, `redocly.yaml`,
`redocly.yml`, `redocly.json`, and `redocly.config.*` are now first-class
static config artifacts. Redocly API roots, definitions, URL fields, and
`extends` entries are resolved through a source-aware parser so remote configs
such as `https://docs.acme.example/reference/redocly.yaml` can turn relative
`root: ./openapi.yaml` values into recursive URL seeds. No Redocly API calls,
spec fetching, service probing, credential validation, or scope relaxation were
added. Verification: focused Redocly/API metadata tests passed (`4 passed`),
combined Redocly/Backstage/Buf/interface artifact regression slice passed (`8
passed`), py_compile passed for touched files, Ruff passed for touched files,
`git diff --check` passed, and no `.forge_data/engagements` leftovers were
present.

Previous checkpoint: Backstage service-catalog static artifact discovery is
complete. `catalog-info.yaml`, `catalog-info.yml`, and `catalog-info.json` are
now first-class static config artifacts. Backstage component/API catalog
mappings pass through the existing bounded YAML structured-discovery path and
extract passive recursive URL seeds from repository annotations,
source/view/edit and TechDocs locations, metadata links, and URL-backed API
definitions. No Backstage API calls, repository fetches, service probing,
credential validation, or scope relaxation were added. Verification: focused
Backstage/API metadata tests passed (`4 passed`), combined
Buf/interface/Backstage/API metadata artifact regression slice passed (`8 passed`),
py_compile passed for touched files, Ruff passed for touched files,
`git diff --check` passed, and no `.forge_data/engagements` leftovers were
present.

Previous checkpoint: Buf/Protobuf registry config static artifact discovery is
complete. `buf.yaml`, `buf.yml`, `buf.gen.yaml`, `buf.gen.yml`,
`buf.work.yaml`, `buf.work.yml`, and `buf.lock` are now first-class static
config artifacts. The interface-definition structured discovery path extracts
passive Buf Schema Registry pivots such as `buf.build/org/repo`, Pro-host
`*.buf.dev/org/repo` refs, plugin remotes, custom Buf registry FQDNs, and split
lock tuples (`remote`/`owner`/`repository`) into recursive URL seeds. No Buf CLI
execution, registry fetch, schema resolution, credential validation, or live
probing was added. Verification: focused Buf/interface worker and pipeline tests passed
(`4 passed`), adjacent API-format/interface ingestion tests passed (`2 passed`),
py_compile passed for touched files, Ruff passed for touched files,
`git diff --check` passed, and no `.forge_data/engagements` leftovers were
present.

Previous checkpoint: offensive scheduled-task queue-source hardening is
complete. Playbook scheduling, automation `_next_steps`, breach-triggered
zero-to-DA, RCE-triggered automation, direct `/api/tasks/enqueue`, and
`TaskScheduler.schedule()` now share a fail-closed denied scheduled-task policy
for `spray`, `safe_check`, and `weaponize`. Denied task types are blocked
before distributed-task insertion or queue publish, web/API denial records
sanitized audit rows, and automation execute remains limited to the existing
passive/recon allowlist. Verification: py_compile passed for touched
backend/test files, Ruff passed for touched files, distributed
scheduler/runnable admission suite passed (`30 passed`), focused playbook
trigger/admission selector passed (`10 passed, 19 deselected`), web enqueue
preflight suite passed (`7 passed`), automation execute API selector passed (`6
passed, 47 deselected`), full playbook integration suite passed (`29 passed`),
full distributed suite passed (`35 passed`), full web engagement API suite
passed (`53 passed`), `git diff --check` passed, and no
`.forge_data/engagements` leftovers were present.

Previous checkpoint: scheduled offensive task fail-closed hardening is complete.
`run_scheduled_task()` now explicitly denies scheduled `spray`, `safe_check`,
and `weaponize` tasks before ROE/scope checks or handler dispatch. The legacy
scheduler imports and dispatch branches for those offensive stubs were removed,
unsupported attempts write sanitized `scheduled_task_denied` audit rows, and
regression coverage proves monkeypatched handlers are not called even when the
payload carries valid-looking ROE and scope context. Verification: focused
distributed scheduler scope suite passed (`22 passed`), full distributed suite
passed (`32 passed`), py_compile passed for touched files, Ruff passed for
touched files, and `git diff --check` passed.

Previous checkpoint: current-user provider proof-hash hardening is complete.
Vercel, Netlify, Notion, and PostHog validation details now include a
deterministic `profile_hash` derived from already accepted non-secret profile
proof fields, and report/validation-inventory parsers require that stable hash
before treating current-user API results as validated proof. Bare
`user_profile_present=true` current-user details now downgrade to `UNVERIFIED`,
closing a report-gate false-positive path while preserving private profile
values out of persisted validation details. Verification: focused
validation-proof selector passed (`95 passed, 15 deselected`), focused
current-user validator selector passed (`5 passed, 169 deselected`), adjacent
proof/secret-finder selector passed (`134 passed, 150 deselected`), cloud
validation provider-proof slice passed (`53 passed, 80 deselected`), Phase 6
report synthesizer suite passed (`106 passed`), py_compile passed for touched
files, and Ruff passed for touched files. Slow Phase 1 long-tail kill-chain
graph/report regression was attempted with `-m slow` but stopped at the current
ROE/scope guard before this proof path; the guard was not weakened.

Previous checkpoint: embedded raster image carving is complete. Legacy binary
artifacts and OLE stream payloads now carve bounded embedded
PNG/JPEG/GIF/WebP/TIFF raster candidates and route them through the existing
image-member OCR/barcode/metadata pipeline. This lets screenshots and QR-like
evidence buried inside dumped binary or legacy Office/OLE streams feed recursive
email/URL/cloud pivots without executing artifacts, mounting images,
authenticating, or adding live probes. Candidate discovery is capped,
offset-ordered, and reuses existing barcode URL sanitization before seed
persistence. Verification: focused embedded-image carving regressions passed
(`3 passed`), adjacent embedded-image/barcode/columnar slice passed (`12
passed`), relevant legacy/OLE orchestrator selector passed (`4 passed, 778
deselected`), adjacent recursive/static artifact slice passed (`23 passed`),
py_compile passed for touched files, and Ruff passed for touched files.

Previous checkpoint: Bruno API-client passive recursion is complete. Bruno
`.bru` request artifacts now resolve static same-file URL-ish variables such as
`{{baseUrl}}/v1/users` before the existing URL safety normalization. Resolved
Bruno request URLs and their base URLs feed the API-client structured discovery
path as recursive URL seeds, while unresolved templates continue to be rejected
by the shared template guard. Verification: focused API-client family regression
passed (`7 passed`), adjacent API-client/document/format slice passed (`19
passed`), py_compile passed for touched files, and Ruff passed for touched
files.

Previous checkpoint: pause/cancel dashboard-review refresh is complete.
Interrupted kill-chain exits now refresh the same static dashboard/detail review
surface as normal completion. `_maybe_interrupt_run()` finishes cancelled and
paused runs with terminal metadata, clears run-control markers, emits a
`dashboard_review_refresh` audit row, and writes `reports/dashboard.html` plus
per-engagement detail JSON so operators can review the partial run without
pretending it completed successfully. Normal completion uses the same shared
refresh helper. Verification: pause/cancel lifecycle regressions passed (`2
passed`), adjacent paused-dashboard and report-finalization regressions passed
(`3 passed`), py_compile passed for touched files, and Ruff passed for touched
files.

Previous checkpoint: over-depth recursive seed resume is complete. Persisted
`engagement_seeds` rows deeper than `synthesis_depth_limit` stay in inventory
but no longer execute recursive fan-outs after resume. URL D5, email E,
username K, phone L, IP O, name M, and company N all apply a shared depth gate
before dispatch, emit deterministic skipped seed-run receipts with
`synthesis_depth_limit_exceeded` metadata, and update in-run processed sets so
stable-loop `pending_work_counts` does not treat over-depth inventory as
executable work. Phone/IP/name/company now use the prioritized depth-carrying
seed loader instead of the removed depthless loader. Verification: py_compile
passed for touched files; Ruff passed for touched files; focused over-depth
regression passed (`1 passed`); full recursive retry-state suite passed (`10
passed`); relevant orchestrator recursive route slice passed (`5 passed, 1
deselected`). Read-only sidecar audit confirmed the original over-depth
execution/pending-count gap. Claude CLI reviewer could not run because the
local OAuth session was expired.

Previous checkpoint: known-host surface backlog is complete. Fan-out D no
longer re-fetches the same first 20 known hosts every iteration. Known-host
D/D2 surface mining now selects a deterministic normalized host backlog,
excludes completed/skipped `fanout_d_host_surface` seed-run targets,
prioritizes never-attempted hosts before retryable attempted hosts, and records
one host-surface seed-run receipt per selected hostname. Empty but completed
fetch attempts are recorded with `fetch_status=empty`, while payload-bearing
hosts record payload counts. `pending_work_counts` now includes
`host_surfaces`, so resumable known-host inventory is visible to the stable-loop
gate. Verification: recursive retry-state suite passed (`9 passed`), focused
known-host backlog regression passed, adjacent D/D2 HTML batching test passed
(`1 passed` with explicit test ROE/scope env), root child scope propagation plus
root retry-state tests passed (`2 passed`), Ruff passed, `py_compile` passed,
and `git diff --check` passed. Read-only sidecar audit confirmed the original
starvation risk and recommended the durable seed-run state model before
implementation.

Previous checkpoint: recursive non-root fan-out retry semantics are verified
and hardened. Social handle, phone, IP, name, company, and executable cloud-ref
child fan-outs now have focused regression proof that failed outcomes are not
added to processed sets and remain visible through `pending_work_counts` /
`last_iteration_stable` metadata for later retry within `max_iter`. Persisted
`seed_runs` assertions now cover failed username/phone, IP/name/company,
social-handle, and cloud-scan rows. Unsupported cloud-service refs now emit an
explicit skipped `fanout_j_cloud_scan` seed-run receipt with
`unsupported_cloud_service` metadata instead of silently disappearing from the
audit trail. Verification: recursive retry-state suite passed (`8 passed`),
cloud scope-manifest regression passed (`1 passed`), Ruff passed for
`forge/cli.py` and the retry-state tests, `py_compile` passed for touched
files, and `git diff --check` passed. Built-in read-only sidecar audits
independently confirmed the retry semantics and highlighted the unsupported
cloud audit-receipt gap before implementation.

Previous checkpoint: GitHub org keyscan attribution/scope is complete. Fan-out
F no longer treats discovered GitHub org names as standalone `--domain <org>`
keyscan targets. Root-domain scans still run as `--domain <root>` and carry
`--scope-manifest`; discovered org scans now use composite seed-run keys
(`<root>::github_org::<org>`) while dispatching `osint keyscan --domain <root>
--org <org> --scope-manifest <manifest>`. Resume/pending state tracks those
composite keys, so multi-root engagements do not globally suppress one root's
org-restricted scan after another root completes. Seed-run metadata records
`origin=keyscan_org`, `query_domain`, and `github_org` for dashboard/audit
review. Direct `osint keyscan` still denies the old unscoped `--domain <org>`
shape under a domain-only manifest, while allowing scoped `--domain <root>
--org <org>`. Verification: recursive retry-state suite passed (`8 passed`),
convergence suite passed (`3 passed`), direct live-scope suite passed (`34
passed`), root child scope propagation regression passed (`1 passed`), focused
org retry/direct/convergence/multi-root tests passed, Ruff passed for touched
files, and `py_compile` passed for touched files. Built-in read-only sidecar
audits confirmed the original bug and recommended the composite key shape
before implementation.

Previous checkpoint: root child scope-manifest propagation is complete. A, B,
B2, D3, D4, and F child dispatch argv now carries the active
`--scope-manifest` from kill-chain launches. `recon subdomains`, `osint
harvest`, `osint linkedin`, and `osint keyscan` all accept direct
`--scope-manifest`; harvest/linkedin/keyscan validate their direct target via
the existing direct CLI scope loader before outbound work.

Previous checkpoint: synthesized root-domain scope gating is complete.
`_refresh_root_domains()` now gates every synthesized
`synthesis_summary.root_domains` value before appending it to the runtime
`root_domains` list used by A/B/B2/D3/D4/G/H/I scheduling and stable-loop
pending counts. Live runs reuse the existing scope-manifest validator with
`seed_type=domain`; denied synthesized roots are audited once as
`root_domain_scope_denied` and never dispatched or shown in run metadata.
Authorized synthesized roots still enter normal root fan-outs, and dry-run
no-manifest previews can still include synthesized roots without denial audit.

Previous checkpoint: B2/D3/D4 bounded retry scheduling is complete. B2
LinkedIn, D3 Shodan, and D4 URLScan no longer have first-iteration-only
dispatch gates. They now partition pending root domains every iteration, rely
on existing completed-domain sets for terminal completed/skipped outcomes, and
retry failed non-zero subprocess runs only inside the existing `max_iter`
budget. Stable-loop pending counts now include `root_linkedin_domains`,
`root_shodan_domains`, and `root_urlscan_domains` because those stages now have
a later-iteration dispatch path. D3/D4 command arguments, provider endpoints,
and provider pacing remain unchanged; D passive dispatch uses the existing
provider-bounded worker count directly.

Previous checkpoint: stable-loop retry budgeting is complete for A/B/G/H/I. The
spider stability gate now counts root-domain fan-outs A, B, G, H, and I as
pending work whenever a root domain is not in that fan-out's completed set.
This fixes the confirmed gap where failed seed-runs were retryable in state but
the loop exited as stable because `_snapshot()` does not count `seed_runs`.
Completed/skipped true no-data outcomes remain terminal; `dry_run_all` and
rootless engagements contribute zero root pending work.

Previous checkpoint: DNS/RDAP/Wayback provider-status gating is complete. DNS
record lookup, RDAP, Wayback, and Common Crawl results now carry status/error
metadata through G/H/I seed-run finalization. Transient provider/network
failures finalize as `failed`; RDAP 404/no-data and test DNS suppression remain
intentional terminal skips; true empty DNS/archive results remain terminal
completed no-data. Fan-out I records per-provider archive statuses and partial
provider errors while keeping useful URLs if one archive provider succeeds.
Failed G/H/I rows are not added to completed-domain sets, so they are
retryable on resumed kill-chain runs.

Previous checkpoint: D5 URL/root-domain same-run retry gating is complete. D5
URL seed fetches with empty/failed payloads now finalize as failed with
`empty_url_fetch` and `fetch_status=empty`, so those URL seeds remain retryable
across recursive iterations and resume. D5 dry-run and scope-denied URLs remain
intentional terminal skips, and successful URL payloads still enter
`processed_url_seeds`. Root-domain fan-outs A/B/B2/D3/D4 now update
completed-domain sets from zero-returncode module dispatches, and G/H/I update
completed-domain sets from completed/skipped finalization statuses, preventing
same-run reruns while preserving retries for failures.

Previous checkpoint: email/keyscan retry-state gating plus dashboard task-error
redaction is complete. Failed `email` engagement seed rows are reloadable by
the E-chain, failed `fanout_e_chain` rows do not enter `processed_emails`, and
email-localpart username processed-state follows successful/skipped Sherlock
localpart dispatches. Keyscan targets and discovered GitHub orgs now enter
processed sets only after an existing completed target or a zero-returncode
keyscan dispatch, so failed org/target keyscans remain retryable across
recursive iterations. Dashboard distributed task errors are redacted before
detail rendering. Verification: focused retry-state suite passed (`6 passed`),
dashboard detail contract passed (`1 passed`), adjacent resume/module/cloud
checks passed (`3 passed`), adjacent email batching path passed with explicit
ROE/scope env (`1 passed`), Ruff passed, py_compile passed, and
`git diff --check` was whitespace-clean.

Previous checkpoint: recursive processed-state retry gating is complete.
Recursive E5 social-handle chains, username, phone, IP, name, company, and
executable cloud scan refs now enter processed sets only after completed or
intentional skipped outcomes. Failed subprocesses remain pending for later
iterations, failed engagement seed rows are reloadable, scope-denied cloud refs
still persist as skipped, and no-executable cloud refs are intentional skips to
avoid infinite loops. Verification: focused retry regressions passed (`4
passed`), adjacent cloud/seed fan-out slice passed (`8 passed`), Ruff passed,
py_compile passed, and `git diff --check` was whitespace-clean.

Previous checkpoint: final report finalization fallback is complete. Kill-chain
finalization now verifies the report family after subprocess-backed
`report generate`; failed or artifact-less report subprocesses force direct
`provider="template"` synthesis, raw JSON/CSV fallback artifacts are accepted,
fallback audit/run metadata is recorded, and no-artifact terminal runs finish as
`failed` rather than plain `completed`. Verification: focused report
fallback/telemetry/raw-export tests passed (`5 passed`), including
fallback-failure and empty-artifact negative regressions; Ruff touched files,
py_compile touched files, and `git diff --check`.

Previous checkpoint: scheduled scope-denial reviewability is complete. Static
dashboard detail JSON/HTML and the live engagement detail API expose old
`scheduled_task_scope_denied` rows through a dedicated `scope_denials` review
section even when the row is outside the recent audit timeline. React labels the
section, and regressions prove visible denial reasons do not leak raw task
`scope_manifest` payloads or sentinels.

Previous checkpoint: remaining scheduled dispatcher scope propagation is complete.
Scheduled `passive` and `auth-bypass` now receive manifest/DB URL-fetch scope
options downstream instead of relying on stale DB reloads after scheduler
preflight. Passive collection accepts explicit scope options and can run under
manifest scope even when DB scope is empty/stale. Scheduled `searxng_passive`
now rejects caller-controlled provider base URLs unless they are default-local
or explicitly allowlisted via environment. The crawler no longer follows
redirects automatically; it checks redirect `Location` against same-host URL
prefix scope before enqueueing, so an in-prefix seed cannot fetch an
out-of-prefix redirect first. `safe_check` and `weaponize` remain
ROE/target-scoped scheduler entries with no downstream provider/network
implementation. Verification: Ruff and compile passed for dispatcher/passive/
crawler changes; focused regression set passed (`6 passed`); broader
crawler/distributed/passive suite passed (`43 passed`). Read-only subagent
audit identified the crawl redirect and SearXNG provider URL gaps and verified
`crawl_stealth`, `passive`, `auth-bypass`, `safe_check`, and `weaponize` status.

Previous checkpoint: scheduled stealth/browser URL-prefix propagation is complete.
Scheduled `crawl_stealth` now receives the same manifest/DB scope options as
scheduled crawl. Playwright stealth navigation installs a route guard that
aborts out-of-prefix HTTP(S) resources before fetch, rejects out-of-prefix final
browser URLs, closes the browser in denial paths, and the scheduler audits
runtime browser scope denials as scheduled task scope denials. Verification:
Ruff and compile passed for stealth/scheduler changes; focused
stealth/scheduler regression set passed (`6 passed`); full distributed scope
plus stealth unit suite passed (`16 passed`). Read-only subagent audit
independently confirmed the original `crawl_stealth` gap and final redirect
risk before the patch.

Previous checkpoint: URL-scope host-vs-prefix semantics are complete.
Host-level gates may treat a URL scope entry as authorizing that host, while
path-sensitive gates must treat URL prefixes as same-host path constraints
before fetch/provider execution. Explicit domain/IP scope still authorizes its
own host. Scheduled URL tasks, passive HTTP collection, Firebase web config
extraction, login probe, legacy Supabase extraction, and scheduled crawl
recursion now deny same-host path drift when DB or manifest scope declares a URL
prefix. Scheduled crawl also propagates manifest-derived `url_prefixes` into the
crawler so an allowed `/app/` seed cannot recursively fetch `/admin` under
broader DB host scope. Verification: focused URL-scope regression set passed
(`12 passed`); broader touched scheduler/passive/login/Firebase/Supabase/
governance/OPSEC selector passed (`171 passed`), covering scheduler
preflight/recursion, passive xray, Firebase, login-probe, legacy Supabase,
shared OPSEC URL assertions, OPSEC host authorization, and governance prefix
enforcement.

Previous checkpoint: scope-json reader audit is complete.
Remaining engagement `scope_json` readers now use the shared
`scope_entries_from_payload()` manifest flattener or an explicit dict-aware
helper. Patched readers include OPSEC scope loading, passive xray fallback
target selection, report synthesizer fallback scope, static dashboard detail
scope display, live web API list/detail/scope-edit flows, Phase 2 email
enrichers, query/scavenger/keyscan gates, Phase 5 boundary checks, and TUI
engagement labels. Email OSINT scope checks now share exact-email/domain/
wildcard semantics, paste monitoring filters flattened scope to domain terms
only, and Phase 5 URL scope entries normalize to host as documented.
Verification: Ruff passed for changed files; focused manifest/email/boundary/
xray/report regressions passed (`18 passed`); broader touched Phase 2/opsec/
xray suite passed (`68 passed`); adjacent social/boundary/report selector
passed (`13 passed`). Read-only subagent audit found no remaining app-code
list-only `scope_json` reader after the patches.

Previous checkpoint: dict-shaped scope seed backfill is complete.
`_backfill_scope_seeds()` now accepts the same manifest object shape used by
live scope manifests (`domains`, `domain_allowlist`, `urls`, `url_prefixes`,
`authorized_seeds`, `allowed_seeds`, `targets`, etc.) while preserving legacy
list scopes. Scope-domain promotion remains narrower: only `domains` and
`domain_allowlist` contribute root-domain evidence, so URL-only scope entries
backfill exact URL seeds without widening into root fan-out. Verification:
compile passed; Ruff passed; focused dict/list scope and URL-only narrowing
tests passed (`4 passed`); combined scope/root/email selector passed (`10
passed, 768 deselected`); `.forge_data/engagements` contained `0` non-master
engagement DBs after the run.

Previous checkpoint: non-email root promotion is complete.
Generic discovered third-party `domain`/`subdomain` seeds from weak
URL/artifact/social pivots no longer become A/G/H/I root-domain fan-out targets
solely because they exist. Root fan-out now allows non-email domain rows only
when they are explicit scope/operator seeds or are marked corroborated by
synthesis. URL/artifact-derived hosts remain graph seeds but do not expand into
root-domain fan-out without that proof. Verification: compile passed; Ruff
passed; focused weak-root synthesis and CLI dry-run routing regressions passed;
adjacent live URL/cloud fixtures passed; affected selector passed (`16 passed,
760 deselected`); `.forge_data/engagements` contained `0` non-master engagement
DBs after the run.

Previous checkpoint: email-domain root promotion is complete.
Email domains discovered from unrelated third-party addresses no longer
automatically become promoted domain seeds or root-domain fan-out targets.
Promotion now requires explicit scope/operator roots, dict/list scope manifest
domain evidence including wildcards, observed non-email host/crawl/artifact
evidence, or an explicitly corroborated `email_domain` seed. Generic discovered
seed rows are not promotion proof. Verification: compile passed; Ruff passed;
focused email-domain/wildcard/generic-seed/root policy tests passed (`4
passed`); broader synthesis candidate/root selector passed (`11 passed, 761
deselected`).

Previous checkpoint: URL-surface recursive child depth is complete.
D5 crawl URL children and public-profile URL children now preserve
parent-relative depth via source metadata instead of resetting to `1`, so depth
budgets and scheduling priority cannot be bypassed by same-iteration URL surface
recursion. Fake-live regressions now carry explicit ROE/scope fixtures under the
uniform live authorization policy. Verification: compile passed; Ruff passed;
focused URL-surface recursion test passed (`1 passed`); adjacent
artifact-depth/local-graph/URL-depth/public-profile checkpoint set passed (`4 passed`);
`.forge_data/engagements` contained `0` non-master engagement DBs after the run.

Previous checkpoint: uniform live authorization policy is complete.
CLI and WebUI kill-chain launches now require both ROE ID and scope manifest for
every non-dry-run run, not only attack-mode or auto-run follow-ups. Live
remote-artifact, cloud-validation, and key-validation scope callbacks fail
closed with `scope_manifest_required` if invoked without a loaded manifest.
Dry-run preview remains available without ROE/scope. Verification: compile
passed; Ruff passed; focused CLI/WebUI live-launch rejection tests passed (`8
passed`); WebUI launch selector passed (`8 passed, 43 deselected`); adjacent CLI
scope selector passed (`11 passed, 758 deselected`).

Previous checkpoint: artifact-derived child seed depth is complete.
`ArtifactQueueProcessor` now preserves source-relative recursion depth for
artifact-derived emails, phones, IPs, hosts, URLs, social pivots, Firebase
project/storage/RTDB seeds, and Supabase project URL/ref seeds. Existing seeds
keep the shortest known depth on conflict, and artifact provenance relations
remain intact. Verification: compile passed; Ruff passed; focused artifact
depth/mobile/persistence tests passed (`3 passed`); slow local kill-chain
artifact graph smoke passed with slow filtering disabled (`1 passed`);
`.forge_data/engagements` contained `0` non-master engagement DBs after the run.

Previous checkpoint: report-state overview filtering is complete.
Static dashboard overview rows and React overview cards can now be filtered by
deterministic report state: prior report generations, raw-export fallback,
fallback reason, and write-degraded report families. Static filters persist
through `forge.overviewFilters`; React uses the same persisted overview filter
store. Verification: compile passed; Ruff passed; frontend build passed;
focused report-state filter contracts passed (`4 passed`); full dashboard/API/UI
contract set passed (`84 passed`); `.forge_data/engagements` contained `0`
non-master engagement DBs after the run.

Previous checkpoint: report-history aggregate review is complete.
Static dashboard and live API list/detail payloads now include
`report_family_count`, `latest_report_family`,
`latest_report_export_count`, and `has_prior_report_generations`. Static
overview HTML, static detail HTML, and React overview/detail surfaces render
report-generation counts so operators can identify engagements with multiple
report families without opening every report artifact. Verification: compile
passed; Ruff passed; frontend build passed; focused report-history aggregate
contracts passed (`5 passed`); full dashboard/API/UI contract set passed (`84
passed`); `.forge_data/engagements` contained `0` non-master engagement DBs
after the run.

Previous checkpoint: report overview render/export parity is complete.
Static dashboard overview JSON, static overview HTML, live `/api/engagements`
list payloads, and React overview cards now surface the latest `report_summary`
render/export state instead of only `report_count`. Raw-export UI labels now
distinguish final `rendered_provider=raw_export` from upstream
`render_backend=template`, preventing dashboard review from misreading raw
fallback output as a template-rendered report. Verification: compile passed;
Ruff passed; frontend build passed; focused dashboard/API report-route
contracts passed (`4 passed`); full static dashboard plus web engagement API
suites passed (`79 passed`); `.forge_data/engagements` contained `0`
non-master engagement DBs after the run.

Previous checkpoint: distributed task dashboard/API review is complete.
Engagement detail counts/sections for static dashboard JSON, static dashboard
HTML, live web API list/detail review, and React detail labels now expose
`distributed_tasks` scheduling inventory using only safe fields: task key,
status, priority, worker ID, error, timestamps, task type, and boolean
ROE/scope-manifest presence. Full task payloads and scope manifest contents
remain omitted and are covered by sentinel non-leak assertions. Verification:
compile passed; Ruff passed; frontend build passed; focused dashboard/API route
contracts passed (`2 passed`); full static dashboard plus web engagement API
suites passed (`79 passed`); `.forge_data/engagements` contained `0`
non-master engagement DBs after the run.

Previous checkpoint: explicit cloud-leak validation scheduling is complete.
`PlaybookEngine.run_cloud_leak_loop()` now fails closed without ROE/scope
context and, when explicitly invoked with an authorized key finding ID, queues
the existing distributed `validate` worker task with `require_roe` and
`require_scope_manifest` set. This replaces a silent skip in the direct playbook
method without enabling cloud resource enumeration, sensitive-file extraction,
event-loop cloud-secret triggers, breach-credential escalation, provider-call
expansion, scope relaxation, or destructive behavior. Verification: compile
passed; Ruff passed; focused cloud-leak playbook selector passed (`6 passed, 17
deselected`); full playbook plus distributed runnable scope suites passed (`32
passed`).

Previous checkpoint: report-summary validation inventory parity is complete.
`report_summary` and every `report_history` item now include compact validation
review fields derived from the generated report JSON context: cloud validation
inventory count, cloud asset inventory count, reportable/unreportable
validation counts, and validation status summary. Static dashboard HTML and the
React report panel display the same compact validation inventory signal so
operators can verify report validation context without opening the report JSON
artifact. Verification: compile passed; Ruff passed; frontend build passed;
exact changed tests passed (`3 passed`); full static dashboard plus web
engagement API suites passed (`79 passed`).

Previous checkpoint: generic scheduler and Command Center ROE/scope preflight is
complete. `/api/tasks/enqueue` now requires `roe_id` and `scope_manifest`,
validates submitted targets before queue insertion, preserves authorized
context in `distributed_tasks.payload`, and writes `scheduled_task_scope_denied`
audit rows on missing/denied context. Command Center execute/approve now
accepts the same ROE/scope context, refuses manual dispatch before queueing
without it, validates action targets before scheduling, records
`command_center_scope_denied` audit evidence, and fails autonomous dispatch
closed with a timeline event rather than silently queuing. Verification:
compile passed; Ruff passed; dedicated preflight file passed (`6 passed`); full
adjacent web/scheduler scope suite passed (`86 passed`).

Previous checkpoint: automation API scope preflight is complete.
`/api/automation/execute` and `/api/automation/playbook` now validate the
requested target against the submitted ROE scope manifest before queue
insertion. Out-of-scope targets return `scope_manifest_denied`, enqueue no
distributed task, and write an `automation_scope_denied` audit-log row for
dashboard review. The helper lives in `forge.webui.automation_scope` and reuses
the same manifest loader and entry validator as distributed/cloud validation
gates. Verification: compile passed; Ruff passed; focused web automation
selector passed (`11 passed, 39 deselected`); full engagement API integration
file passed (`50 passed`).

Previous checkpoint: scheduled validation ROE/scope gating is complete.
Distributed `validate` tasks now require non-empty `roe_id` and
`scope_manifest` before `run_cloud_validate()` can execute. Missing ROE,
missing manifest, and ROE/manifest mismatch all fail before provider
validation, while existing scope-manifest key-row allow/deny behavior remains
intact once both controls are present. Verification: compile passed; Ruff
passed; full distributed runnable scope file passed (`9 passed`); focused
scheduled key-validation selector passed (`2 passed, 3 deselected`); full
key-validation runtime file passed (`5 passed`).

Previous checkpoint: automation/playbook ROE gating is complete.
`PlaybookEngine` now refuses to schedule playbooks unless the payload carries
both non-empty `roe_id` and `scope_manifest`; automation event handlers suppress
chained, WAF-evasion, RCE-hunter, and zero-to-DA follow-ups without inherited
ROE/scope context; `/api/automation/execute` and `/api/automation/playbook`
reject scheduling before queue insertion unless that context is present. This
only gates/suppresses scheduling and does not add proxy/Tor/WAF-evasion
expansion, scope relaxation, or new live execution behavior. Verification:
compile passed; Ruff passed; focused playbook/API selectors passed (`5 passed,
15 deselected`; `9 passed, 39 deselected`); full playbook integration file
passed (`21 passed`); full engagement API integration file passed (`48
passed`).

Previous checkpoint: Web API cloud artifact provenance parity is complete.
`/api/engagements/{id}/assets` now includes `cloud_assets` inventory rows with
latest deterministic validation status/reportability, artifact source seed ID,
source URL/file, extract rule, format, bounded provenance text, and scrubbed
safe metadata. The route uses `forge.webui.cloud_assets` so `app.py` stays
thin, casts cloud timestamps to text, and strips credential-like metadata keys
before API serialization. Verification: compile passed; Ruff passed; focused
cloud asset API provenance/validation selector passed (`2 passed, 43
deselected`); full engagement API integration file passed (`45 passed`).

Previous checkpoint: skipped seed-run status cleanup is complete.
`SeedRunTracker.finish_run(..., status='skipped')` now clears a parent seed
stuck in `running` to `ignored`, while preserving completed/failed states. The
tracker regression proves skipped completion clears running seed status, and
the dry-run kill-chain regression proves terminal skipped fan-outs leave zero
`engagement_seeds.status='running'` rows. Verification: compile passed; Ruff
passed; focused tracker/dry-run tests passed (`2 passed, 765 deselected`);
adjacent seed-run/resume selector passed (`5 passed, 762 deselected`).

Previous checkpoint: Phase 6 artifact cloud provenance export parity is complete.
The fresh deterministic audit found that artifact-derived cloud provenance
reached dashboard/graph review but not Phase 6 report/export surfaces.
`ContextBuilder` now loads scrubbed `cloud_assets.metadata_json` into
`cloud_asset_inventory`, companion JSON/raw JSON preserve artifact source seed
ID, source URL/file, extract rule, format, and safe metadata, raw CSV
cloud-asset rows include the same provenance fields, and deterministic template
reports show a bounded provenance column without leaking secret metadata.
Verification: compile passed; Ruff passed; focused Phase 6 provenance export
test passed (`1 passed`); adjacent Phase 6 provenance/raw export selector
passed (`21 passed, 84 deselected`).

Previous checkpoint: artifact-derived cloud asset provenance is complete.
`cloud_assets` now stores scrubbed `metadata_json` provenance, including source
artifact seed ID, source URL/file, extract rule, format, artifact type,
provider/source metadata, and bounded parser context when cloud refs are
discovered from artifacts. Generic text, Firebase, Supabase, and URL-derived
artifact cloud refs all pass provenance into the shared cloud-asset storage
path. Dashboard cloud-asset sections expose a provenance preview, fallback
graph CLOUD nodes carry the same metadata, and unvalidated artifact refs remain
inventory-only/non-reportable. Verification: compile passed; Ruff passed;
focused artifact provenance test passed (`1 passed`); full artifact
cloud-reference file passed (`2 passed`); dashboard graph/raw-export selector
passed (`12 passed, 17 deselected`); full static dashboard suite passed (`29
passed`).

Previous checkpoint: raw-export fallback orphan report cleanup is complete.
Phase 6 now removes partial `.md/.json/.pdf/.csv` report-family artifacts if
companion export persistence fails after Markdown writing, then emits the
raw-export JSON/CSV fallback as the authoritative report family. Dashboard
report-family grouping now prefers JSON-backed families over Markdown-only
orphans, so a newer orphan Markdown cannot outrank the raw-export family in
`report_summary`. Verification: compile passed; Ruff passed; focused Phase 6
orphan cleanup test passed (`1 passed`); focused dashboard raw-export selection
test passed (`1 passed`); adjacent reporting selector passed (`2 passed, 131
deselected`).

Previous checkpoint: stale running seed-run recovery is complete.
`SeedRunTracker` now marks abandoned `seed_runs.status='running'` rows as
`failed` with `completed_at` and `abandoned before explicit completion` before
resumed kill-chain work loads completed/skipped suppression sets. The
regression seeds one stale running row plus completed/skipped controls, then
proves resume retries only the stale row and leaves no running seed-run rows.
Verification: compile passed; Ruff passed; focused recovery test passed (`1
passed`); adjacent seed-run/resume selector passed (`4 passed, 763
deselected`).

Previous checkpoint: Fan-out J denied cloud seed-run persistence is complete.
Cloud references denied by the scope manifest before Fan-out J validation now
persist as skipped `fanout_j_cloud_scan` seed runs with service, ref, deny
reason, scope gate/source, candidate count, iteration, and
`denied_before_scan=true` metadata. Existing `cloud_validation_scope_denied`
audit evidence and unverified validation inventory remain intact, and resume
treats the skipped J run as terminal so reruns do not duplicate validation.
Verification: compile passed; Ruff passed; focused cloud scope-manifest
denial/resume test passed (`1 passed`); adjacent cloud scheduling selector
passed (`4 passed, 762 deselected`). Handoff:
`.claude/handoffs/2026-07-24-j-denied-cloud-seed-runs.md`.

Previous checkpoint: API-created engagement cleanup and monotonic sequence
coverage is complete. The API create sequence regression now proves deleting a
test-owned engagement DB leaves no numeric DB debris while preserving the
`master.db` monotonic sequence. It verifies `1002.db` deletion does not allow ID
reuse, `1003.db` can be cleaned up, and the sequence remains at `1003` for the
next allocation. No production code change was needed. Verification: compile
passed; Ruff passed; focused cleanup/sequence test passed (`1 passed`); full
web UI engagement API file passed (`44 passed`); `.forge_data/engagements`
contained `0` entries after the run. Handoff:
`.claude/handoffs/2026-07-24-api-create-cleanup-sequence.md`.

Previous checkpoint: audit manifest bundle availability is complete.
Dashboard/API run summaries now annotate audit manifests with explicit
`artifact_count`, `artifact_available`, `artifact_name`, and `artifact_href`
fields when materialized manifest artifacts exist. Overview JSON, detail JSON,
and web API detail/list payloads now make chain-of-custody artifact
availability directly visible instead of requiring consumers to infer it from
the artifacts list. Verification: compile passed; Ruff passed; focused manifest
bundle tests passed (`2 passed`); full web UI engagement API file passed (`44
passed`); full static dashboard suite passed (`29 passed`);
`.forge_data/engagements` contained `0` entries after the run. Handoff:
`.claude/handoffs/2026-07-24-audit-manifest-bundle-availability.md`.

Previous checkpoint: API auxiliary-route validation/reportability parity is
complete. `/api/engagements/{id}/assets` now filters false-positive passive
vulnerabilities the same way host context and vulnerability summary routes
already do. The integration regression proves stale/unreportable deterministic
cloud findings do not inflate `vuln-summary`, false-positive passive critical
rows do not surface through assets, and `asset-tree` remains a neutral
asset-only review surface without finding/severity rollups. Verification:
compile passed; Ruff passed; focused route parity tests passed (`2 passed`);
full web UI engagement API file passed (`44 passed`); `.forge_data/engagements`
contained `0` entries after the run. Handoff:
`.claude/handoffs/2026-07-24-api-aux-route-reportability-parity.md`.

Previous checkpoint: Fan-out J cloud validation target prep worker migration is
complete. `kill_chain()` now prepares `(service, ref)` validation target tuples
through `_run_inprocess_batch()` before calling
`run_cloud_asset_validate_batch()`. The validator call, scope checker,
validation execution, persistence, and final log/result ordering remain
unchanged and bounded. Verification: compile passed; Ruff passed; focused cloud
target batching regression passed (`1 passed`); adjacent cloud batching
selector passed (`2 passed, 764 deselected`); `.forge_data/engagements`
contained `0` entries after the run. Handoff:
`.claude/handoffs/2026-07-24-cloud-validation-target-worker-prep.md`.

Previous checkpoint: D5 denied recursive URL seed-run persistence is complete.
D5 URL seed scope decisions now persist deterministic denied-before-fetch URLs
as skipped `fanout_d5_url_seed_html` seed runs, including deny reason,
hostname, scope gate/source, iteration, and `denied_before_fetch=true`
metadata. Existing no-fetch behavior and `audit_log`
`recursive_seed_scope_denied` review evidence are preserved. The in-memory
processed URL set is updated after the skipped run is written, and resume treats
the skipped D5 run as terminal so reruns do not duplicate it. Verification:
compile passed; Ruff passed; focused scope-manifest denial/resume test passed
(`1 passed`); adjacent D5 URL selector passed (`5 passed, 761 deselected`);
related remote artifact scope-manifest denial test passed (`1 passed`);
`.forge_data/engagements` contained `0` entries after the run. Handoff:
`.claude/handoffs/2026-07-24-d5-denied-url-seed-runs.md`.

Previous checkpoint: web/API seed URL canonicalization and fallback graph
validation parity are complete.
Live web/API engagement create/add/update seed routes now canonicalize `url` and
`apk_url` seed values before dedupe, scope updates, upserts, and patch
persistence. Equivalent default-port, fragment, and host-case URL variants
collapse to one canonical seed in API-created engagements. Dashboard graph
generation now applies the same validation metadata refresh/filtering to
seed-generated fallback graphs as it already did for graph snapshots and graph
artifacts. Stale Firebase test fixtures were updated to use stable proof text
required by the deterministic validator. Verification: compile passed; Ruff
passed; focused graph/API tests passed (`2 passed`); full web UI engagement API
file passed (`44 passed`); focused dashboard provider/fallback selector passed
(`3 passed`). Handoff:
`.claude/handoffs/2026-07-24-web-api-seed-dashboard-graph-parity.md`.

Previous checkpoint: legacy ReportingAgent fallback lineage is complete.
Legacy `ReportingAgent` deterministic fallback output now includes payload-only
`report_lineage` metadata with `requested_provider`, `rendered_provider`,
`render_backend`, `format`, and sanitized `fallback_reason` codes for no-LLM,
`ProviderUnavailableError`, and generic exception fallback branches. Requested
provider remains `llm` when an LLM was configured but failed. The
`/reports/{workflow_id}` API route now has explicit legacy-agent lineage
coverage for nested `report_md` payloads. Markdown content, findings,
provenance footers, severity rules, provider behavior, live probing, report
rendering, dashboard, and frontend behavior are unchanged. Verification:
compile passed; Ruff passed; focused fallback/API route set passed (`7
passed`); full reporting property file passed (`13 passed`);
`.forge_data/engagements` contained `0` entries after the run. Handoff:
`.claude/handoffs/2026-07-24-legacy-reporting-fallback-lineage.md`.

Previous checkpoint: initial URL seed canonicalization is complete.
Operator-supplied initial `url` and `apk_url` seeds now canonicalize before
initial seed dedupe and persistence, using the same HTTP canonicalizer as
recursive URL persistence. Equivalent raw variants such as
`HTTPS://ACME.EXAMPLE:443/login#top` plus `https://acme.example/login`, and
mobile bundle variants with default ports/fragments, persist as one canonical
seed each and produce one dry-run URL fan-out row. Verification: compile
passed; Ruff passed; focused URL seed regression passed (`1 passed, 765
deselected`); adjacent initial seed canonicalization selector passed (`2
passed, 764 deselected`); `.forge_data/engagements` contained `0` entries after
the run. Handoff:
`.claude/handoffs/2026-07-24-initial-url-seed-canonicalization.md`.

Previous checkpoint: recursive discovered URL seed persistence canonicalization
is complete.
Recursive discovered URL persistence now uses a shared CLI HTTP URL canonicalizer
before archive-provider dedupe, URL metadata keying, crawl row insertion, URL
seed insertion, existing crawl/seed duplicate checks, URL seed resume keys,
scope decisions, and Playwright eligibility checks. Raw historical/provider
variants like `HTTPS://archive.acme.example:443/config.js#bundle` and
`https://shared.acme.example/app.js#wayback` collapse to canonical HTTP(S) URLs
while preserving archive/provider metadata merging and existing `robots.txt` /
`sitemap.xml`, artifact URL, root-domain, and scope-manifest gates.
Verification: compile passed; Ruff passed; focused archive-source regression
passed (`1 passed`); adjacent Wayback persistence selector passed (`2 passed,
763 deselected`); reviewer subagent found no blocking findings;
`.forge_data/engagements` contained `0` entries after the run. Handoff:
`.claude/handoffs/2026-07-24-recursive-url-seed-canonicalization.md`.

Previous checkpoint: crawler URL canonicalization recursion is complete.
`_crawl_http()` now canonicalizes seed, fetched final, and extracted URLs
before recursive queue/fetch decisions. It drops fragments, lowercases
scheme/host, removes default `:80`/`:443` ports, rejects non-HTTP(S) URLs, and
marks canonical links as queued before enqueueing so fragment variants do not
create duplicate crawl work or dashboard rows. Reviewer audit found a
default-port origin-equivalence blocker; that is fixed and covered for both
HTTPS `:443` seeds and HTTP `:80` extracted links. Verification: compile
passed; Ruff passed; focused canonicalization selector passed (`3 passed, 5
deselected`); focused href selector passed (`1 passed, 5 deselected`); full
crawler unit file passed (`8 passed`); `.forge_data/engagements` contained `0`
entries after the run. Handoff:
`.claude/handoffs/2026-07-24-crawler-url-canonicalization.md`.

Previous checkpoint: dashboard cloud asset validation alias is complete.
Static engagement detail cloud-asset rows now normalize both sides of the
latest-validation join, so assets stored as aliases such as `s3` pick up
canonical validation rows stored as `aws_s3` for the same identifier.
Verification: compile passed; Ruff passed; focused alias dashboard test passed
(`1 passed`); adjacent dashboard cloud-validation slice passed (`4 passed, 24
deselected`); full static dashboard suite passed (`28 passed`);
`.forge_data/engagements` contained `0` entries after the run. Handoff:
`.claude/handoffs/2026-07-24-dashboard-cloud-asset-alias-validation.md`.

Previous checkpoint: crawler href parser recursion is complete.
`_extract_links()` now uses `HTMLParser` so `_crawl_http()` follows same-origin
hrefs regardless of attribute case or quote style while continuing to ignore
empty, fragment, and `javascript:` links. Verification: compile passed; Ruff
passed; focused href parser test passed (`1 passed, 4 deselected`); full
crawler unit file passed (`5 passed`); `.forge_data/engagements` contained `0`
entries after the run. Handoff:
`.claude/handoffs/2026-07-24-crawler-href-parser-recursion.md`.

Previous checkpoint: report route unknown-workflow 404 is complete.
`GET /reports/{workflow_id}` now catches `WorkflowEngine.get_status()`
`KeyError` and returns deterministic `404` with
`workflow_not_found:{workflow_id}` before loading report state. Verification:
compile passed; Ruff passed; focused missing-report workflow test passed (`1
passed`); full `TestApiReportRoute` class passed (`3 passed`);
`.forge_data/engagements` contained `0` entries after the run. Handoff:
`.claude/handoffs/2026-07-24-report-route-unknown-404.md`.

Previous checkpoint: workflow status unknown-ID 404 is complete.
`GET /workflows/{workflow_id}/status` now catches
`WorkflowEngine.get_status()` `KeyError` and returns deterministic `404` with
`workflow_not_found:{workflow_id}` instead of relying on the dead `result is
None` branch. Verification: compile passed; Ruff passed; focused
unknown-status test passed (`1 passed`); full history/status route suite passed
(`10 passed`); `.forge_data/engagements` contained `0` entries after the run.
Handoff: `.claude/handoffs/2026-07-24-workflow-status-unknown-404.md`.

Previous checkpoint: Playwright screenshot scope gate is complete.
`crawl_target(..., screenshot=True)` now installs a Playwright route guard
before navigation and aborts off-scope HTTP(S) requests using the same
`scope_filter` as the crawler. It also checks the browser final URL before
writing `root.png`, so an in-scope URL that redirects off-scope cannot capture
or associate an off-scope screenshot. Verification: compile passed; Ruff
passed; focused screenshot scope test passed (`1 passed`); full crawler unit
file passed (`4 passed`); `.forge_data/engagements` contained `0` entries after
the run. Handoff:
`.claude/handoffs/2026-07-24-playwright-screenshot-scope-gate.md`.

Previous checkpoint: workflow history limit validation is complete.
`GET /workflows/{workflow_id}/history` now validates optional `limit` with
FastAPI `Query(ge=1)`, so `limit=0` and negative limits return 422 instead of
falling through to an unbounded state-store history query. Verification:
compile passed; Ruff passed; focused non-positive limit test passed (`2
passed`); full history route suite passed (`9 passed`); `.forge_data/engagements`
contained `0` entries after the run. Handoff:
`.claude/handoffs/2026-07-24-workflow-history-limit-bounds.md`.

Previous checkpoint: crawler off-scope redirect final-URL gate is complete.
`_crawl_http()` now validates the final redirected response URL against the same
scope filter used for requested URLs before recording crawl output or extracting
links. This prevents an in-scope URL that redirects off-scope from persisting an
off-scope `final_url` that later passive automation could queue before worker
denial. Verification: compile passed; Ruff passed; focused off-scope redirect
test passed (`1 passed`); full crawler unit file passed (`3 passed`);
`.forge_data/engagements` contained `0` entries after the run. Handoff:
`.claude/handoffs/2026-07-24-crawler-redirect-scope-gate.md`.

Previous checkpoint: workflow report API nested Phase 6 lineage is complete.
Legacy `GET /reports/{workflow_id}` now preserves Phase 6 report lineage when
`report_lineage` is nested under
`intermediate_results["report"]["report_lineage"]`, matching the companion JSON
shape written by Phase 6 exports. Top-level workflow metadata still wins because
nested lineage is merged only for missing keys. Verification: compile passed;
Ruff passed; focused nested plus raw-export route tests passed (`2 passed`);
full `TestApiReportRoute` class passed (`2 passed`); `.forge_data/engagements`
contained `0` entries after the run. Handoff:
`.claude/handoffs/2026-07-24-workflow-report-nested-lineage.md`.

Previous checkpoint: Phase 6 artifact inventory export parity is complete.
Phase 6 now includes scrubbed `artifact_queue` inventory in companion JSON
context and raw CSV exports as `record_type=artifact`. The new helper is
`forge.phase6.artifact_inventory` and the focused regression is
`tests/phase6/test_report_artifact_inventory_export.py`. Artifact exports
preserve source URL, type, status, hash, notes, parser/format/count metadata,
and timestamps while omitting local paths and secret-bearing metadata. No live
execution, validation gate, severity rule, LLM provider, retry, proxy, or scope
behavior changed. Verification: compile passed; Ruff passed; focused artifact
export test passed (`1 passed`); adjacent artifact seed-relation/archive
provenance selector passed (`3 passed, 102 deselected`). Handoff:
`.claude/handoffs/2026-07-24-phase6-artifact-inventory-export.md`.

Previous checkpoint: compact mocked kill-chain/report/dashboard smoke is
complete.
Added `tests/phase1/test_kill_chain_dashboard_smoke.py`, a focused mocked
`kill_chain()` run proving homepage HTML can discover a remote APK, static
artifact parsing can feed Firebase/Supabase/AWS/Slack/Mailchimp/Azure
validation inventory, recursive email/URL seeds reach the engagement detail
surface, graph payload metadata keeps validation status/method, `provider=auto`
falls back to deterministic template on LLM failure, and generated dashboard
detail JSON exposes report lineage plus validation inventory without leaking
raw secrets. Verification: compile passed; Ruff passed; smoke passed (`1
passed in 27.46s` with `-m "slow or not slow"`); dashboard validation selector
passed (`5 passed, 22 deselected`); Phase 6 fallback/proof/raw-export selector
passed (`20 passed, 84 deselected`). Handoff:
`.claude/handoffs/2026-07-24-compact-kill-chain-dashboard-smoke.md`.

Previous checkpoint: long-tail and non-promoted validator proof reviewability
is complete.
Phase 6 standalone reportable key-scanner proof exports now have a
parameterized regression covering Cloudflare, Discord, GitLab, HuggingFace,
Netlify, Notion, PostHog, SendGrid, Sentry, Stripe, Telegram, Twilio, and
Vercel. Datadog remains non-promoted (`UNVERIFIED` with empty
`validation_proof`), but its read-only `/validate` proof detail is preserved in
review/export surfaces. Verification: compile passed; Ruff passed; shared proof
parser suite passed (`106 passed`); focused parser/report dashboard suite
passed (`121 passed`); broader Phase 6 validation/export selector passed (`22
passed, 82 deselected`); cloud-gating/alias suite passed (`2 passed`);
dashboard validation selector passed (`5 passed, 22 deselected`). Handoff:
`.claude/handoffs/2026-07-24-long-tail-validator-proof-reviewability.md`.

Previous checkpoint: compact cleanup/regression sweep is complete.
After the dashboard graph and Phase 6 proof-export parity commits, the repo was
clean at `89cc545`, `.forge_data/engagements` contained `0` entries, and the
focused review/export smoke set stayed green. Verification: Phase 6
validation/export selector passed (`8 passed, 83 deselected`); dashboard/API
graph review selector passed (`4 passed`); cloud-gating/alias suite passed (`2
passed`). Handoff:
`.claude/handoffs/2026-07-24-compact-review-export-regression-sweep.md`.

Previous checkpoint: Phase 6 raw export validation-proof parity is complete.
Phase 6 now exposes explicit `validation_proof` fields alongside existing
backward-compatible `validation_notes` fields for findings, cloud validation
inventory, cloud asset inventory, companion JSON context, raw JSON fallback, and
raw CSV exports. Standalone reportable `key_scanner_findings` now also appear
as non-finding review/export inventory (`record_type=key_finding`) with
method/proof/detail when no duplicate `vulnerability_findings` row exists. This
removes ambiguity where proof was preserved only as notes while dashboard/graph
surfaces used `validation_proof`. Verification: Ruff passed; compile passed;
focused standalone key/proof/cloud export tests passed (`3 passed`); broader
Phase 6 validation/export selector passed (`8 passed, 83 deselected`);
cloud-gating/alias suite passed (`2 passed`). Handoff:
`.claude/handoffs/2026-07-24-phase6-validation-proof-export-parity.md`.

Previous checkpoint: graph snapshot latest cloud validation metadata is
complete.
Static dashboard and live API graph payload filtering now refresh retained
CLOUD node validation metadata from the latest matching
`cloud_validation_results` row. Stale graph snapshots can still keep CLOUD
nodes for analyst traceability, but their metadata now shows latest effective
validation status, stored status, method, reportability, checked timestamp, and
scrubbed evidence/notes summaries instead of old artifact metadata.
Verification: Ruff passed; compile passed; focused static/API stale cloud node
tests passed (`2 passed`); adjacent static graph-validation slice passed (`3
passed`); adjacent live API graph-validation slice passed (`3 passed`).
Handoff:
`.claude/handoffs/2026-07-24-graph-cloud-latest-validation-metadata.md`.

Previous checkpoint: imported graph validation-proof parity is complete.
Imported GraphML/MTGX payloads now normalize `validation_detail` into
`validation_status`, `validation_method`, and scrubbed `validation_proof`
metadata for returned graph nodes/edges. This aligns imported analyst graph
artifacts with generated graph JSON and report/raw-export proof surfaces
instead of requiring dashboard/API consumers to reverse-parse free-form detail
strings. Static dashboard and live API regressions use local MTGX fixtures only;
no live provider calls are made. Verification: Ruff passed; compile passed;
focused static/API MTGX graph parity tests passed (`2 passed`). Handoff:
`.claude/handoffs/2026-07-24-imported-graph-validation-proof-parity.md`.

Previous checkpoint: Slack validation proof finding-row parity is complete.
Dashboard/API vulnerability finding rows now expose parsed validation status,
method, and scrubbed proof from method-tagged deterministic finding evidence.
This closes the Slack gap where Phase 4/Phase 6 preserved
`VALIDATED:slack_auth_test:Slack auth ok: actor_id=... team_id=...`, but
`_detail_sections()` showed only severity/type/title/target/timestamp for the
finding. Static dashboard and live API regressions use local deterministic
Slack evidence only; no Slack or other live provider calls are made.
Verification: Ruff passed; compile passed; focused Slack dashboard test passed
(`1 passed`); focused Slack API test passed (`1 passed`); combined static
dashboard validation/proof slice passed (`4 passed, 23 deselected`); combined
live API validation/proof slice passed (`4 passed, 39 deselected`). Handoff:
`.claude/handoffs/2026-07-24-slack-validation-proof-finding-row-parity.md`.

Previous checkpoint: cloud asset latest-validation review parity is complete.
Static dashboard and live engagement-detail API cloud asset sections now join
each asset to only the latest validation row for the same `(engagement_id,
asset_type, identifier)`, ordered by `checked_at` then row id. This prevents
legacy/non-unique validation-history tables from duplicating one asset row or
showing stale proof beside a newer validation result while preserving the
existing validation inventory ordering. Verification: Ruff passed; compile
passed; focused static dashboard validation-order slice passed (`2 passed, 24
deselected`); focused live API validation-order slice passed (`2 passed, 40
deselected`). Handoff:
`.claude/handoffs/2026-07-24-cloud-asset-latest-validation-parity.md`.

Previous checkpoint: Shodan provider contract and D3/D4 dry-run parity are
complete. Shodan domain enrichment is now documented and tested as the current
`/dns/resolve` plus capped `/shodan/host/{ip}` enrichment model; stale
`/dns/domain` and incorrect free-domain-endpoint wording was removed from the
module and CLI docs. Dry-run kill-chain runs now persist skipped
`fanout_d3_shodan` and `fanout_d4_urlscan` seed-run rows for root domains
without dispatching Shodan or URLScan provider modules. Verification: Ruff
passed; compile passed; focused D3/D4 dry-run orchestrator tests passed (`2
passed, 763 deselected`); focused Shodan lookup contract/pacing tests passed
(`2 passed, 6 deselected`). Handoff:
`.claude/handoffs/2026-07-24-shodan-dry-run-provider-parity.md`.

Previous checkpoint: kill-chain child scope-manifest propagation is complete.
Explicit `scope_manifest` values now propagate into live-capable child dispatch
argv for `recon ports`, domain Shodan D3, URLScan D4, and IP Shodan fan-out.
The child commands already support `--scope-manifest`; `--roe-id` was not added
to those argv lists because those child signatures do not accept it. Focused
regressions prove active port scan, domain provider fan-outs, and IP Shodan
fan-out carry the manifest path even when direct child commands could otherwise
fall back to broader DB scope. Verification: focused child propagation selector
passed (`3 passed, 761 deselected`); broader engagement scope-manifest selector
passed (`11 passed, 753 deselected`); direct/distributed scope suites passed
(`38 passed`); Ruff/compile passed for touched files. Handoff:
`.claude/handoffs/2026-07-24-child-scope-manifest-propagation.md`.

Previous checkpoint: LLM/provider adapter fallback hardening is complete.
Phase 6 local llama inference now normalizes backend exceptions, malformed
response shapes, and per-call timeouts into `ProviderUnavailableError`, so the
existing report pipeline deterministically falls back to template/raw export
instead of crashing or hanging. Real OpenAI-compatible provider cascade tests
now prove 401, 403, 429, and HTTP timeout failures fail over through
`FallbackChainProvider`. Verification: local adapter focused slice passed (`6
passed, 85 deselected`); full Phase 6 synthesizer suite passed (`91 passed`);
combined Phase 6/provider adapter suite passed (`157 passed`);
provider/fallback/property slice passed (`82 passed`); LLM validation plus
cloud report-gating slice passed (`16 passed`); Ruff/compile passed for touched
files. Handoff:
`.claude/handoffs/2026-07-24-llm-provider-adapter-fallback-hardening.md`.

Previous checkpoint: LLM validation non-convergence fallback is complete.
Phase 6 now treats failed LLM validation/correction convergence as a hard
report gate. If the LLM repeatedly introduces unsupported findings such as a
hallucinated CVE and final approval remains false after the configured
correction loop budget, `ReportSynthesizer.generate()` switches to the
deterministic template backend before writing report artifacts. Feedback
telemetry still records the failed LLM response hash and hallucination score,
while Markdown/JSON/CSV/PDF outputs carry template lineage and fallback reason.
The stale managed-cloud seed summary fixture was also updated to use current
strict validation methods and stable storage proofs. Verification: the new TDD
regression failed before the production fix; full Phase 6 synthesizer suite
passed (`88 passed`); provider/fallback/property slice passed (`78 passed`);
LLM validation plus cloud report-gating slice passed (`16 passed`);
Ruff/compile passed for touched files. Handoff:
`.claude/handoffs/2026-07-24-llm-validation-nonconvergence-fallback.md`.

Previous checkpoint: scope-gate unification is complete.
`forge/opsec/scope_gate.py` now matches the governance gate: missing or empty
scope fails closed, bare domains authorize only exact apex matches, wildcard
entries authorize subdomains only, and CIDR matching uses Python's `ipaddress`
implementation. Stale login-probe fixtures now express subdomain authorization
explicitly with `*.acme.local` instead of relying on broad bare-domain
matching. Verification: opsec/governance scope suite passed (`37 passed`);
Phase 2 scope selector passed (`7 passed, 137 deselected`); direct CLI and
distributed scope suites passed (`38 passed`); engagement ID plus scope gate
suite passed (`40 passed`); FastAPI live scope-manifest selector passed (`3
passed, 38 deselected`); Ruff/compile passed for touched files. Handoff:
`.claude/handoffs/2026-07-24-scope-gate-unification.md`.

Previous checkpoint: cleanup inventory is complete. Stale local test/backup
artifacts were removed from `.forge_data`: old Phase 3 template files under
`.forge_data/engagements/1` and `.forge_data/engagements/5010`, the zero-byte
allocator scratch `.forge_data/engagements/master.db`, and
`.forge_data/tmp_attack_backup_20260426.db`. Empty OneDrive/read-only
placeholder directories were removed after clearing the read-only attribute.
Final inventory: `.forge_data/engagements` has no entries; the backup DB is
gone. Verification: `tests/scripts/test_run_phase1_orchestrator_partitions.py`
passed (`6 passed`); `tests/phase1/test_engagement_ids.py` passed (`3 passed`).
Handoff: `.claude/handoffs/2026-07-24-cleanup-inventory.md`.

Previous checkpoint: compact regression sweep and live asset-context route parity
are complete. Artifact recursion/scope/review parity, dashboard cloud/detail
paths, cloud stable-proof gates, and report synthesis metadata all remained
green. During the direct API route audit, `/api/assets/{host}/context` was
hardened so `passive_vulns.false_positive=1` rows no longer become
operator-facing `latest_findings` or critical host status, while raw
`/api/engagements/{id}/assets` inventory remains reviewable. The same route now
casts timestamp columns to text so ISO `T` timestamps from engagement DB rows do
not crash SQLite timestamp conversion. Verification: artifact
recursive/scope/parity sweep passed (`5 passed`); dashboard cloud/graph/detail
selector passed (`11 passed, 14 deselected`); validation-proof cloud
listing/legacy slice passed (`22 passed, 83 deselected`); report synthesizer
metadata slice passed (`3 passed, 83 deselected`); focused asset-context
regression passed (`1 passed`); adjacent API reportability slice passed (`3
passed, 38 deselected`); compile/Ruff passed for touched route/test files.
Handoff: `.claude/handoffs/2026-07-24-live-asset-context-reportability.md`.

Previous checkpoint: dashboard storage stable-proof fixture is complete. The
stale dashboard storage-validation fixture now uses the current strict proof
formats: S3/Spaces XML object listings and GCS storage JSON object inventory.
The dashboard cloud/graph/detail selector is green without weakening validation
gates or changing production code. Verification: Ruff/compile passed; dashboard
cloud/graph/detail selector passed (`11 passed, 14 deselected`);
validation-proof cloud listing/legacy slice passed (`22 passed, 83
deselected`); stable-proof surface integration passed (`1 passed`); dashboard
cloud-alias graph test passed (`1 passed`). Handoff:
`.claude/handoffs/2026-07-24-dashboard-storage-stable-proof-fixture.md`.

Earlier checkpoint: artifact queue/cloud inventory audit-lineage is complete.
`ArtifactQueueProcessor` now writes bounded non-sensitive audit rows when
artifact text queues a follow-on artifact URL (`artifact_text_url_queued`) and
when artifact parsing stores a new cloud inventory row
(`artifact_cloud_asset_inventoried`). Focused assertions prove the trace from
discovered artifact text -> queued remote artifact -> parsed cloud inventory,
without promoting inventory into findings. Verification: compile/Ruff passed;
focused recursive queue tests passed (`3 passed`); artifact
recursive/remote-scope/review parity slice passed (`5 passed`); artifact
provenance/cloud/contact slice passed (`7 passed`); cleanup inventory unchanged
(`1`, `5010`, `master.db`). Handoff:
`.claude/handoffs/2026-07-24-artifact-audit-lineage.md`.

Previous checkpoint: recursive artifact queue second-pass convergence is complete.
Focused coverage now proves artifact-text-discovered artifact URLs are not
fetched in the same `ArtifactQueueProcessor.process()` call, remain queued, and
converge on the next `process()` pass by downloading/parsing the queued artifact
and feeding discovered email, URL, and Firebase cloud pivots onward.
Verification: focused recursive queue tests passed (`3 passed`); adjacent
recursive/RN/remote-classification artifact suite passed (`23 passed`);
adjacent cloud/parity slice passed (`2 passed`); Ruff passed. Handoff:
`.claude/handoffs/2026-07-24-artifact-queue-second-pass-convergence.md`.

Previous checkpoint: remote artifact parallel attribution is complete. The
parallel remote-artifact downloader now stores `(result_index, request)` in its
future map so exception handling uses the exact allowed request object after
scope-denied rows are skipped. Inspection showed the prior index was already the
original result slot, but the explicit mapping prevents future compact-list
mistakes. Verification: compile/Ruff passed; focused parallel scope attribution
test passed (`1 passed`); existing kill-chain scope-denied remote artifact E2E
passed (`1 passed`). Handoff:
`.claude/handoffs/2026-07-24-remote-artifact-parallel-attribution.md`.

Previous checkpoint: artifact review surface parity is complete. Newly recursive
artifact pivots are now visible across review/export surfaces. Static dashboard
detail payloads include a `cloud_assets` inventory section, summary count, and
fallback graph `CLOUD` nodes even when no attack-graph snapshot exists.
Deterministic reports now carry `cloud_asset_inventory`, render a "Cloud Asset
Inventory (Not Findings)" template table, and export `record_type=cloud_asset`
rows in raw CSV without promoting unvalidated ARN inventory into findings or
risk scoring. Focused fixture covers React Native bundle email pivots,
source-map artifact queueing, AWS Lambda ARN inventory, and vCard contact
identity seeds across `AttackGraphBuilder`, `ContextBuilder`, template
Markdown, raw CSV, dashboard sections, and fallback graph payload.
Verification: compile/Ruff passed; focused parity test passed (`1 passed`);
artifact provenance/recursive/RN/contact/cloud/parity suite passed (`11
passed`); report synthesizer adjacent slice passed (`3 passed, 83
deselected`); artifact cloud plus parity slice passed (`2 passed`). Known
unrelated residual: dashboard selector `tests/reporting/test_dashboard.py -k
"cloud or graph or detail"` has one stale stable-proof fixture expecting
`VALIDATED`; current strict gate renders `UNVERIFIED`. Handoff:
`.claude/handoffs/2026-07-24-artifact-review-surface-parity.md`.

Previous checkpoint: calendar/vCard explicit identity enrichment is complete.
Calendar and vCard artifact parsing now promotes only explicit contact identity
fields into the existing seed graph: `FN`/`N` become `name` seeds and `ORG`
becomes `company` seeds. `TITLE` is preserved as `contact_title` provenance
metadata on promoted seeds, not as a recursive `other`/title seed. Names or
companies that appear only in `SUMMARY`, `DESCRIPTION`, or `ORGANIZER;CN` are
ignored, preserving the no free-text identity inference boundary.
Verification: focused TDD failed first with only email seed promotion;
compile/Ruff passed; focused contact identity tests passed (`2 passed`);
adjacent calendar/contact orchestrator slice passed (`11 passed, 751
deselected`); adjacent static artifact suite passed (`14 passed`); selected
name/company fanout slice passed (`2 passed, 760 deselected`);
social-profile URL parser passed (`1 passed`); cleanup inventory found only
`.forge_data/engagements` `1`, `5010`, and `master.db`. Handoff:
`.claude/handoffs/2026-07-24-calendar-contact-identity.md`.

Previous checkpoint: generic artifact-text AWS ARN inventory is complete.
Generic artifact text cloud-reference parsing now inventories allowlisted AWS
ARNs beyond S3/KMS without resolving, reading, or validating resources.
Supported inventory-only families are IAM role/user/policy, Lambda function/
layer, SQS queue, SNS topic, ECR repository, CloudFront distribution, and
Execute API/API Gateway route ARNs. Unsupported services, malformed account
IDs, and unknown resource subtypes are skipped instead of stored as generic AWS
rows. Persistence lowercases deterministic identifiers while preserving
first-seen exact ARN casing in `provider_identifier`, and this checkpoint
creates no `cloud_validation_results` rows. Verification: focused TDD failed
first with only existing KMS rows; compile/Ruff passed; focused AWS ARN
inventory test passed (`1 passed`); adjacent cloud/artifact static suite passed
(`12 passed`); adjacent AWS artifact parser suite passed (`16 passed`);
selected artifact queue/route orchestrator slice passed (`20 passed, 742
deselected`); cleanup inventory found only `.forge_data/engagements` `1`,
`5010`, and `master.db`. Residual: the broad
`test_engagement_orchestrator.py -k "cloud_assets ..."` selector reached a
managed-hosting live reachability-sensitive test unrelated to ARN parsing and
failed once because `vercel` classified `DEAD` instead of
`ACCESSIBLE_BUT_NO_DATA`. Handoff:
`.claude/handoffs/2026-07-24-generic-aws-arn-inventory.md`.

Previous checkpoint: artifact text discovered-artifact queueing is complete.
Artifact text URL persistence now immediately queues artifact-like HTTP(S) URLs
using the existing passive remote artifact classifier, without fetching those
URLs in the same processing pass. Source maps, static manifests, and nested
archives discovered inside already-parsed artifacts therefore move into
`artifact_queue` with `discovered_from='artifact_text'` and `status='queued'`,
while non-artifact API URLs remain seeds only. Existing queue rows are
preserved by `(engagement_id, source_url)` conflict handling, so parsed,
downloaded, and failed rows are not reset. Verification: focused TDD failed
first with no queued artifact rows; compile/Ruff passed; focused recursive
queue tests passed (`2 passed`); recursive queue plus React Native and remote
static classification tests passed (`22 passed`); selected artifact
queue/route orchestrator slice passed (`20 passed, 742 deselected`); selected
extensionless remote download wrappers passed (`3 passed, 759 deselected`);
cleanup inventory found only `.forge_data/engagements` `1`, `5010`, and
`master.db`. Handoff:
`.claude/handoffs/2026-07-24-artifact-text-recursive-queue.md`.

Previous checkpoint: React Native bundle member recursion is complete. Passive
archive/member and remote route discovery now recognize React Native
JavaScript bundles (`.jsbundle`, `index.android.bundle`, `index.ios.bundle`)
plus Hermes bytecode bundles (`.hbc`). JS bundles route through existing text
extraction; Hermes bundles route through bounded binary-string extraction, so
embedded emails, URLs, Firebase/Supabase/S3/GCS references, and follow-on
static artifact URLs can feed recursive discovery without executing mobile
code. Verification: focused TDD failed first on missing `.jsbundle` remote
classification and missing Hermes member string extraction; compile/Ruff
passed; focused React Native route/member tests passed (`2 passed`); adjacent
remote classification/model/Realm/React Native tests passed (`22 passed`);
selected route/mobile-bundle/binary-string orchestrator slice passed (`33
passed, 729 deselected`); adjacent HAR/Parquet/OCI slice passed (`10 passed`);
cleanup inventory found only `.forge_data/engagements` `1`, `5010`, and
`master.db`.
Handoff:
`.claude/handoffs/2026-07-24-react-native-bundle-member-recursion.md`.

Previous checkpoint: remote Android AAR route discovery is complete. Passive
web/JS route mining now recognizes linked Android `.aar` library archives, and
safe AAR MIME types infer `.aar` remote artifact filenames. Existing
local/archive AAR parsing can therefore run when a page or bundle links
`/libs/mobile-sdk.aar`, preserving recursive email/URL/cloud pivots from
Android library resources. Verification: focused TDD failed first on missing
AAR MIME mapping; compile/Ruff passed; focused AAR route/MIME/classification
tests passed (`2 passed`); adjacent remote classification/model/Realm tests
passed (`20 passed`); selected route/mobile-bundle orchestrator slice passed
(`18 passed, 744 deselected`); adjacent HAR/Parquet/OCI slice passed (`10
passed`); cleanup inventory found no new pytest/test-like engagement DBs.
Handoff: `.claude/handoffs/2026-07-24-android-aar-route-discovery.md`.

Previous checkpoint: static ML model binary artifact recursion is complete.
Passive TensorFlow Lite/CoreML/protobuf model artifacts (`.tflite`,
`.mlmodel`, `.mlmodelc`, `.pb`, `.pbtxt`) now classify as document/static
binary artifacts, route-discovered model URLs can enter artifact queueing, and
safe model MIME types infer bounded binary artifact suffixes. A local fixture
proves discovered model files feed recursive email/URL/Firebase/Supabase/S3/GCS
pivots through existing binary-string extraction only. Verification: focused
TDD failed first on local ingestion returning `0`, missing remote
classification, and missing model MIME mappings; compile/Ruff passed; focused
model tests passed (`3 passed`); model plus full remote classification passed
(`18 passed`); selected orchestrator route/binary slice passed (`33 passed, 729
deselected`); adjacent Realm/Parquet/HAR/OCI slice passed (`11 passed`);
cleanup inventory found no new pytest/test-like engagement DBs. Handoff:
`.claude/handoffs/2026-07-24-static-ml-model-artifact-recursion.md`.

Previous checkpoint: Realm mobile DB artifact recursion is complete. Passive
`.realm` mobile database artifacts now classify as document/static dump
artifacts for local discovery and remote artifact MIME/suffix inference, then
route through the existing bounded binary-string extraction path. A local
fixture proves discovered Realm files can feed recursive email/URL/subdomain/
Firebase/Supabase/S3/GCS pivots without executing the database or adding
provider calls. Verification: focused TDD failed first on local ingestion
returning `0` and missing Realm MIME mappings; compile/Ruff passed; focused
Realm/classification tests passed (`3 passed`); adjacent
Realm/classification/Parquet tests passed (`19 passed`); selected orchestrator
binary/columnar slice passed (`18 passed, 744 deselected`); adjacent
HAR/OCI/classification slice passed (`24 passed`); cleanup inventory found no
new pytest/test-like engagement DBs. Handoff:
`.claude/handoffs/2026-07-24-realm-mobile-db-artifact-recursion.md`.

Previous checkpoint: Parquet columnar artifact parsing is complete. Passive
`.parquet` artifacts now run through a bounded pyarrow-backed parser before
generic binary string carving. The parser emits a `#parquet-table` payload with
schema metadata and bounded string cell values from the first row groups, so
encoded columnar exports can feed existing recursive email/URL/cloud discovery.
If pyarrow is unavailable or parsing fails, artifacts fall back to the existing
bounded binary-string path. Verification: parser-marker TDD failed first;
compile/Ruff passed; focused Parquet parser/fallback tests passed (`2 passed`);
Parquet plus remote static classification passed (`18 passed`); selected
existing orchestrator columnar/binary/archive slice passed (`24 passed, 738
deselected`); adjacent HAR/OCI/classification slice passed (`24 passed`);
cleanup inventory found no new pytest/test-like engagement DBs. Handoff:
`.claude/handoffs/2026-07-24-parquet-columnar-artifact-parser.md`.

Previous checkpoint: Instagram business-contact recursion is complete. Public
Instagram `business_email` and `business_phone_number`/alias fields from
`web_profile_info` are now normalized into lookup results and persisted in
`social_profiles`, so the existing synthesis engine can promote them into
recursive email and phone seeds. Verification: focused TDD failed first on
missing `business_email`; compile/Ruff passed; focused lookup plus synthesis
regressions passed (`2 passed`); full identity pacing file passed (`6 passed`);
adjacent social-profile synthesis slice passed (`4 passed`); cleanup inventory
found no new pytest/test-like engagement DBs. Handoff:
`.claude/handoffs/2026-07-24-instagram-business-contact-recursion.md`.

Previous checkpoint: HAR WebSocket message alias support is complete. Passive HAR
parsing now accepts both Chrome-style `_webSocketMessages[]` and unprefixed
`webSocketMessages[]` arrays, so exporter variants do not drop captured message
payloads before recursive artifact discovery. Verification: focused alias TDD
failed first on missing `ws-alias@acme.example`; compile/Ruff passed; focused
HAR suite passed (`6 passed`); adjacent HAR/public-metadata/Charles parser
slice passed (`10 passed`); mocked service-worker kill-chain E2E passed (`1
passed`); pytest engagement cleanup reported `removed=4 remaining=0`. Handoff:
`.claude/handoffs/2026-07-24-har-websocket-message-alias.md`.

Previous checkpoint: HAR WebSocket message static recursion is complete.
Passive HAR parsing now reads bounded `_webSocketMessages[]` payloads and feeds
message type/time/opcode/data lines through the existing recursive artifact
text discovery path. A local fixture proves WebSocket message data can surface
emails, URLs, Firebase, Supabase, S3, and GCS references without browser replay,
live probing, credential use, or scope relaxation. Verification: TDD fixture
failed first with `discovered_seeds=0`; compile/Ruff passed; focused HAR suite
passed (`6 passed`); packaged Helm/API-label/orchestration parser slice passed
(`8 passed`); HAR plus adjacent public metadata/Charles parser slice passed
(`10 passed`); artifact helper/static-classification/container slice passed
(`31 passed`); mocked service-worker kill-chain E2E passed (`1 passed`);
pytest engagement cleanup reported `removed=3 remaining=0`. Handoff:
`.claude/handoffs/2026-07-24-har-websocket-message-recursion.md`.

Current next gate: run a compact regression sweep across artifact recursion,
cloud stable-proof gates, dashboard detail, report context/raw export, and
cleanup inventory before opening the next implementation slice. Do not add live
target probing without explicit ROE/scope manifest and mocked tests.

Previous checkpoint: dashboard/API key-section proof gating is complete. Static
dashboard and live engagement detail API section payloads now reuse the shared
latest-validation proof gate for key-scanner findings. Stale ACTIVE key rows
with embedded `VALIDATED` detail no longer leak into
`sections.key_scanner_findings` when newer cloud validation inventory marks the
linked resource unreportable. This matches counts, graph nodes, reports, and
API summaries. Verification: compile/Ruff passed; stable-proof integration
passed (`1 passed`); adjacent reportability/attack-path slice passed (`29
passed`); cloud exposure and validation-proof suites passed (`119 passed`);
report cloud-validation metadata slice passed (`1 passed`); pytest engagement
cleanup reported `removed=2 remaining=0`. Handoff:
`.claude/handoffs/2026-07-24-dashboard-key-section-proof-gate.md`.

Previous checkpoint: packaged Helm chart values recursion is complete. Passive
archive extraction now recognizes packaged Helm chart member paths such as
`acme-portal-1.2.3.tgz/acme-portal/values.yaml` as `helm-values` without
broadening arbitrary `*/values.yaml` files. Extracted chart values now run
through the existing orchestration structured parser, so host-only ingress
values feed recursive discovery from chart archives discovered via Helm indexes
or other static artifact paths. Verification: compile/Ruff passed; full
affected label/orchestration/Helm-index parser files passed (`8 passed`).
Pytest engagement cleanup reported `removed=0 remaining=0`.
Handoff:
`.claude/handoffs/2026-07-24-packaged-helm-values-recursion.md`.

Previous checkpoint: storage metadata validation proof-gating is complete.
Shared
cloud exposure reportability now downgrades `VALIDATED` storage metadata probes
such as `gcs_http_probe` and `s3_head_probe` when evidence/notes contain
placeholder, honeypot, sample, synthetic, or low-signal markers. Concrete
bounded metadata probes can still remain LOW/reviewable, but placeholder
metadata stays validation inventory only and projects as `UNVERIFIED` under
report/dashboard stable-proof gates. Verification: compile/Ruff passed;
focused cloud exposure gate and Phase 6 report gating tests passed (`15
passed`); adjacent deterministic findings, stable-proof surface, and
attack-path validation slices passed (`16 passed`); pytest engagement cleanup
reported `removed=3 remaining=0`. Handoff:
`.claude/handoffs/2026-07-24-storage-metadata-proof-gate.md`.

Previous checkpoint: run launch/control response reviewability is complete.
Live
launch/resume/restart route responses now echo normalized execution switches as
structured fields: `max_iter`, `skip_cloud`, and `skip_keyscan`. This matches
the progress-event metadata and keeps operators/dashboard clients from parsing
`command_preview` to review the requested kill-chain shape. Verification:
compile/Ruff passed; focused launch/restart/resume integration slice passed (`9
passed`). Claude review could not run because OAuth was expired; Codex CLI
fallback rejected `gpt-5.2` for this account, so the fix was locally audited
and tested. Handoff:
`.claude/handoffs/2026-07-24-run-launch-response-reviewability.md`.

Previous checkpoint: live API audit-manifest verification parity is complete.
Live `/api/engagements` summaries now use the same verified latest-run audit
manifest default as static dashboard/detail payloads, and
`/api/engagements/{ref}/runs` verifies manifests by default. Operators can
still request the cheaper non-verifying run list with
`?verify_manifests=false`, which returns `not_checked` explicitly instead of
silently drifting from dashboard review semantics. Verification:
compile/Ruff passed; focused web API route contract passed (`1 passed`);
adjacent static slug/detail dashboard contract passed (`1 passed`); pytest
engagement cleanup reported `removed=3 remaining=0`. Handoff:
`.claude/handoffs/2026-07-24-live-api-audit-manifest-parity.md`.

Previous checkpoint: canonical graph artifact isolation is complete. Static
dashboard and live web API graph artifact discovery now only accept
manifest-defined graph filenames for each engagement:
`{id}_attack_graph.json`, `.graphml`, `.mtgx`, `_nodes.csv`, and `_edges.csv`.
Noncanonical names such as `1001_attack_graph-extra.json` no longer appear in
engagement artifacts, cannot win graph payload selection, and cannot be
downloaded through the live artifact endpoint. Verification: compile/Ruff
passed; focused dashboard/API graph/report prefix collision slice passed (`5
passed`); pytest engagement cleanup reported `removed=2 remaining=0`. Handoff:
`.claude/handoffs/2026-07-24-canonical-graph-artifact-isolation.md`.

Previous checkpoint: report artifact/API isolation is complete. Static
dashboard and live web API report/audit discovery now require ID-delimited
artifact stems, so engagement `1001` no longer sees or downloads
`engagement_10010_*` report artifacts. Live
`/api/engagements/{id}/vuln-summary` now excludes passive false positives the
same way dashboard severity summaries do. Verification: compile/Ruff passed;
focused dashboard/API report prefix-collision, report-history, and vuln-summary
tests passed (`5 passed`); pytest engagement cleanup reported
`removed=3 remaining=0`. Handoff:
`.claude/handoffs/2026-07-24-report-artifact-api-isolation.md`.

Previous checkpoint: validation inventory/raw-export parity is complete. Phase
6 raw CSV finding rows preserve structured validation notes/evidence/check
metadata from the same context used by JSON/template reports. Stable
key-provider validations such as `aws_sts_get_caller_identity` display as
`VALIDATED` in Phase 6, dashboard, and API inventory while
`validation_reportable` remains false for cloud-exposure gates. Handoff:
`.claude/handoffs/2026-07-24-validation-inventory-raw-export-parity.md`.

Previous checkpoint: imported graph legacy edge-shape filtering is complete.
Imported dashboard/API graph payload filtering now understands both canonical
`source_node_id` / `target_node_id` edges and legacy `source` / `target` edges.
Validation filtering and cloud-alias dedupe share the endpoint helper, so
removed or merged deterministic cloud/key nodes cannot leave dangling stale
graph edges in engagement review payloads. Handoff:
`.claude/handoffs/2026-07-24-imported-graph-legacy-edge-filtering.md`.

Previous checkpoint: downgraded provider validation reviewability is complete.
Method-tagged key-validation details now parse non-reportable statuses such as
`UNVERIFIED:<method>:<detail>` for structured review surfaces without promoting
them to reportable proof. Downgraded Datadog validation inventory now exposes
`UNVERIFIED` plus `datadog_api_key_validate` in dashboard detail rows and Phase
6 raw-export metadata while keeping `validation_proof` empty and key-finding
counts at zero. Handoff:
`.claude/handoffs/2026-07-24-downgraded-provider-validation-reviewability.md`.

Previous checkpoint: effective cloud validation status projection is complete.
Canonicalized cloud-validation alias ordering now uses canonical asset type,
identifier, checked timestamp, and row ID before choosing latest validation
state, so stale alias rows cannot override newer canonical rows. Phase 6 report
metadata, raw CSV exports, and dashboard/API validation inventory now expose
both stored status and effective report-gated status; low-proof `VALIDATED`
rows stay reviewable inventory but project as `UNVERIFIED` and
`validation_reportable=False`. Deterministic cloud findings use the same
canonical latest-row ordering. Verification: compile/Ruff passed; cloud
stable-proof/latest/dashboard/API slice passed (`5 passed`); dashboard
cloud/key selector slice passed (`8 passed, 13 deselected`); engagement API
graph/cloud selector slice passed (`5 passed, 32 deselected`); focused Phase 6
and attack-path slices passed. Handoff:
`.claude/handoffs/2026-07-24-effective-cloud-validation-status.md`.

Previous checkpoint: dashboard graph alias parity is complete. Imported/stale
dashboard graph payloads now merge duplicate CLOUD review nodes sharing the
same canonical cloud asset key; alias/canonical pairs such as `CLOUD::s3::*`
and `CLOUD::aws_s3::*` collapse before detail JSON export. Edges and
critical-path IDs are rewired, and original aliases are retained in
`asset_type_aliases`. Verification: compile/Ruff passed; focused dashboard
cloud-alias graph test passed (`1 passed`); adjacent dashboard graph/cloud
validation slice passed (`8 passed, 13 deselected`); web UI graph/cloud
validation slice passed (`5 passed, 32 deselected, 6 warnings`). Handoff:
`.claude/handoffs/2026-07-24-dashboard-cloud-alias-graph-parity.md`.

Previous checkpoint: cloud asset alias validation/graph handoff is complete.
Legacy cloud asset aliases (`s3`, `digitalocean_spaces`,
`google_cloud_storage`, `azure_blob_storage`) now normalize before pending
validation claim selection, suppressing repeat alias probes when canonical
validation rows already exist. Attack graph cloud nodes now key by canonical
cloud asset type while preserving original alias metadata for review.
Verification: compile/Ruff passed; focused claim alias file passed (`2
passed`); broader cloud asset validation sweep slice passed (`16 passed, 117
deselected`); focused attack graph alias/latest-validation slice passed (`4
passed, 105 deselected`); registry contract passed (`1 passed`). Handoff:
`.claude/handoffs/2026-07-24-cloud-asset-alias-validation-graph.md`.

Previous checkpoint: HTML data aggregation worker audit is closed with no runtime
change. `_extract_html_data()` was inspected after the URL-family worker
migration; the remaining extraction is low-cost local aggregation and the only
clearly heavy subpath is already `_extract_html_surface_urls()`. Do not split
DB apply/merge/write/finalization barriers or add nested worker pools here.
Subagent attempts were made: Claude failed because OAuth is expired, and Codex
read-only sandbox could not spawn PowerShell. Handoff:
`.claude/handoffs/2026-07-24-html-data-aggregation-worker-audit.md`.

Previous checkpoint: HTML surface URL-family worker migration is complete.
`_extract_html_surface_urls()` now splits passive HTML URL extraction into
ordered families (`literal`, `attribute`, `meta_refresh`, `srcset`, `css_url`,
`css_import`, `js`) and can dispatch them through `_run_inprocess_batch()` for
the single-payload D1/D2/D5 parse path. Final first-seen URL dedupe remains
serial. Outer D1/D2/D5 parse batches keep inner URL workers at one when multiple
payloads are already parallel. Verification: compile/Ruff passed; focused
passive/HTML URL extraction tests passed (`3 passed, 28 deselected`); full CLI
parallel dispatch suite passed (`31 passed`); D1/D2/D5 scheduling slice passed
(`3 passed`); compact HTML-mining plus service-worker/precache smoke passed
(`2 passed`); cleanup reported `removed=4 remaining=0`. Handoff:
`.claude/handoffs/2026-07-24-html-surface-url-family-worker.md`.

Previous checkpoint: social-profile pivot worker migration is complete.
Identity/social-profile recursive pivot construction now routes handle, email,
phone, Matrix homeserver, federated-host, and domain pivot-entry shaping through
the existing bounded ordered local worker helper while preserving deterministic
family order and serial persistence. Verification: compile/Ruff passed; focused
social-profile worker slice passed (`5 passed, 757 deselected`); broader
social-profile synthesis cluster passed (`81 passed, 681 deselected`).
Handoff: `.claude/handoffs/2026-07-24-social-profile-pivot-worker.md`.

Previous checkpoint: broader validation/reportability regression gate is
complete. Latest linked cloud validation now wins for deterministic
key-exposure rows across deterministic synthesis, Phase 6 key/report context,
attack graph VULN nodes, dashboard/API finding tables, key-scanner counts, and
imported graph payload filtering. Handoff:
`.claude/handoffs/2026-07-24-key-exposure-latest-validation-gates.md`.

Earlier checkpoint: stable-proof validator surface gates are complete. Phase 6
deterministic-cloud report filtering now requires stable proof for proof-bound
cloud methods, matching deterministic findings, graph, dashboard, and API
gates. Phase 6 raw CSV finding rows include non-sensitive target identity
fields (`target_url`, `parameter`, `cloud_provider`, `resource_id`). Handoff:
`.claude/handoffs/2026-07-24-stable-proof-surface-gates.md`.

Previous checkpoint: runtime frontend config JS recursion is complete. Explicit
public runtime config files such as `runtime-env.js`, `env-config.js`, and
`runtime-config.js`, plus public/static/build-path `config.js`, now get the
`runtime-js-config` label. Uppercase env-style `API_HOST`, `API_BASE`,
`FIREBASE_PROJECT_ID`, and `NEXT_PUBLIC_SUPABASE_PROJECT_REF` assignments feed
recursive URL seeds and Firebase/Supabase cloud assets through the existing
artifact queue path. Arbitrary `notes.js` and root generic `config.js` stay
outside JS-runtime structured parsing.

Runtime config handoff:
`.claude/handoffs/2026-07-24-runtime-js-config-recursion.md`.

Recon-output double-check: no code change was needed.
`_recon_tool_output_structured_payload_text` already preserves family order and
uses ordered bounded candidate normalization; existing focused worker regression
and persisted recon-output artifact slice both passed.

Previous checkpoint: kill-chain dry-run finalization contract is complete.
`forge kill-chain --dry-run` no longer schedules network-capable prereport
`vuln passive` or `exploit correlate` finalizers, HIBP finalization carries
`--dry-run`, and skipped labels are audited.

Fallback next-gate rule: use `docs/engagement_overhaul_tasklist.md` ->
`## Compact active backlog` and pick the next proven deterministic acceptance
gap. Prefer a focused audit or mocked regression over broad retesting unless a
specific failing behavior is known.

This file is intentionally historical and large. Future agents should read only
the header/current checkpoint sections needed for resume, then use
`docs/engagement_overhaul_tasklist.md` -> `## Compact active backlog` as the
actual continuation order. Do not full-load this file when context is tight.

Historical deep entries that say `No SPEC.md exists` are stale after 2026-07-20.
New invariant or bug-contract notes should update `SPEC.md` plus current
handoff docs.

## End Goal To Preserve

FORGE must converge on one deterministic authorized engagement pipeline:
scoped multi-seed intake, bounded recursive discovery, passive artifact/provider
enrichment, proof-bound non-destructive validation, rule-engine severity,
graph/dashboard/report/audit review, LLM cascade only for narrative,
template/raw export fallback when LLM/API narrative providers fail, hit quota,
have no key, or exceed token limits, and automated test-data cleanup. Before
starting work, map the task to one of the acceptance stages in
`docs/end_goal.md`: intake, discovery, recursion, artifact analysis, validation,
scoring, review, fallback, or testing/cleanup. Do not move the goal to UI-only
polish or provider breadth without proving the end-to-end kill-chain path.
If no stage matches the next task, stop and re-scope before editing. Use
subagents for independent review or disjoint work only when it saves time
without creating competing source-of-truth docs. If thread or turn caps block
delegation, continue locally against the locked goal and record the limitation.

Continuation decision rule: before editing, state the deterministic gate being
advanced. Valid gates are intake, discovery, recursion, artifact analysis,
validation, scoring, review, fallback, and testing/cleanup. If none applies,
stop and pick a smaller verified kill-chain or determinism gap.

## Operator Notes

- [x] Automation unsupported-suggestion parity checkpoint completed:
  `AutomationEngine` no longer emits `osint:dehashed` or `report:generate`
  suggestions through the web automation review surface until explicit
  supported route actions exist. The executable action allowlist is shared by
  `/api/automation/execute` and suggestion parity tests. Backprop: `SPEC.md`
  `B20`; existing `V3`/`V6`/`V10`/`V12`/`V13` cover the gate. Verification:
  failing TDD first showed unsupported actions `osint:dehashed` and
  `report:generate`; focused parity regression; compile/Ruff; full playbook
  suggestion suite (`18 passed`); automation execute API admission slice
  (`6 passed`). Handoff:
  `.claude/handoffs/2026-07-23-automation-suggestion-route-parity.md`.
- [x] Automation execute action-admission checkpoint completed:
  `/api/automation/execute` now rejects unsupported or sensitive action names
  before queue writes and only schedules currently supported passive/recon
  automation actions: `recon:ports`, `recon:crawl`, and `vuln:passive`.
  Backprop: `SPEC.md` `B19`; existing `V3`/`V6`/`V10`/`V12`/`V13` cover the
  gate. Verification: failing API TDD first showed unsupported/sensitive
  actions queued (`exploit:correlate`, `exploit:safe_check`, `post:lateral`,
  `auth:spray`, `unknown:thing`); focused API regression passed (`6 passed`);
  compile/Ruff; full web UI engagement API suite (`34 passed`); adjacent
  playbook suggestion suite (`17 passed`); cleanup
  `test_owned_engagement_db_count=0`. Handoff:
  `.claude/handoffs/2026-07-23-automation-execute-action-admission.md`.
- [x] Legacy exploit-correlation suggestion guardrail completed:
  `AutomationEngine` no longer emits `exploit:correlate` suggestions from
  passive service version strings by default. The web automation executor has no
  scoped passive correlation task handler for that legacy action, so the review
  surface now suppresses it until an explicit vulnerability/exposure correlation
  task model exists. Backprop: `SPEC.md` `B18`; existing
  `V3`/`V6`/`V10`/`V13` cover the gate. Verification: failing TDD first showed
  `exploit:correlate`; focused guardrail regression; compile/Ruff; full
  playbook integration suite (`17 passed`); cleanup
  `test_owned_engagement_db_count=0`. Handoff:
  `.claude/handoffs/2026-07-23-exploit-correlation-suggestion-guardrail.md`.
- [x] Legacy credential-validation suggestion guardrail completed:
  `AutomationEngine` no longer emits `osint:validate` suggestions from
  unvalidated credential rows plus exposed services by default. Backprop:
  `SPEC.md` `B17`; existing `V3`/`V6`/`V10`/`V12` cover the gate.
  Verification: failing TDD first showed `osint:validate`; focused guardrail
  regression; compile/Ruff; full playbook integration suite (`16 passed`);
  cleanup `test_owned_engagement_db_count=0`. Handoff:
  `.claude/handoffs/2026-07-23-credential-validation-suggestion-guardrail.md`.
- [x] Legacy post-exploitation suggestion guardrail completed:
  `AutomationEngine` no longer emits `post:lateral` suggestions from validated
  credential rows. Backprop: `SPEC.md` `B16`; existing
  `V3`/`V6`/`V10`/`V12` cover the gate. Verification: failing TDD first showed
  `post:lateral` in suggestions; focused guardrail regression; compile/Ruff;
  full playbook integration suite (`15 passed`); adjacent API parity regression
  (`1 passed`); cleanup `test_owned_engagement_db_count=0`. Handoff:
  `.claude/handoffs/2026-07-23-lateral-suggestion-guardrail.md`.
- [x] Legacy cloud-leak key proof gate completed:
  `run_cloud_leak_playbook()` no longer trusts
  `key_scanner_findings.validation_state='ACTIVE'` by itself. Existing active
  key rows must pass the stable proof parser or link to reportable cloud
  validation before validation/enumeration flow proceeds. The auto-trigger
  remains disabled, and linked reportable cloud validation still permits dry-run
  review. Backprop: `SPEC.md` `B15`; existing `V3`/`V6`/`V7`/`V8` cover the
  gate. Verification: failing TDD first showed stale active key dry-run
  enumeration; focused negative and positive cloud-leak regressions;
  compile/Ruff; full playbook integration suite (`14 passed`);
  validation-proof parser (`104 passed`); dashboard key gate slice (`3
  passed`); Phase 6 key selectors (`2 passed, 80 deselected`). Handoff:
  `.claude/handoffs/2026-07-23-cloud-leak-key-proof-gate.md`.
- [x] Operational automation reportability gates completed:
  `AutomationEngine` report suggestions now count only shared reportable
  deterministic findings plus non-false-positive passive findings. The RCE
  auto-trigger now requires shared reportable `HIGH`/`CRITICAL` rows,
  RCE-specific finding text, and engagement-matched host metadata before
  scheduling, and skips safely when canonical findings lack legacy `host_id`.
  Backprop: `SPEC.md` `B14`; existing `V3`/`V6`/`V7`/`V8` cover the gate.
  Verification: failing TDD first for stale report suggestion
  (`{'report-generate'}`) and RCE trigger schema failure (`no such column:
  host_id`); focused operational regressions; compile/Ruff; full playbook
  integration suite (`12 passed`); adjacent API/detail parity slice (`2
  passed`); dashboard cloud/key gate slice (`4 passed`); Phase 6 validation
  selectors (`2 passed, 80 deselected`). Handoff:
  `.claude/handoffs/2026-07-23-automation-reportability-gates.md`.
- [x] Live API vulnerability-summary reportability parity completed:
  `/api/engagements/{id}/vuln-summary` now builds active finding severity counts
  from `_reportable_vulnerability_rows` instead of grouping
  `vulnerability_findings` directly from SQLite. Stale deterministic cloud
  findings with non-reportable validation methods no longer reappear as active
  `HIGH` API summary counts after dashboard/detail/report gates suppress them.
  Backprop: `SPEC.md` `B13`; existing `V6`/`V7`/`V8` cover the gate.
  Verification: failing TDD first on `/vuln-summary` (`{'HIGH': 1}`); focused
  route regression; compile/Ruff; full web UI engagement API suite (`28
  passed`); adjacent API/detail/graph route slice (`3 passed`); dashboard
  cloud/key gate slice (`4 passed`); Phase 6 validation selectors (`2 passed,
  80 deselected`); cleanup `test_owned_engagement_db_count=0`. Handoff:
  `.claude/handoffs/2026-07-23-live-api-vuln-summary-parity.md`.
- [x] Deterministic key exposure dashboard parity completed: dashboard
  `key_scanner_findings` counts now require stable key proof or linked
  reportable cloud validation before counting a key as reportable, while stale
  active key rows remain visible as downgraded inventory. Imported dashboard
  graph payloads now remove stale `APIKEY` nodes whose validation detail fails
  `parse_validated_detail`; dangling edges and critical-path refs are dropped.
  Backprop: `SPEC.md` `B12`; existing `V6`/`V7`/`V8` cover the gate.
  Verification: failing TDD first for stale count and stale graph leakage;
  focused dashboard regressions; compile/Ruff; full dashboard (`20 passed`);
  Phase 6 key selectors (`3 passed, 79 deselected`); attack-path API key
  selectors (`7 passed, 101 deselected`); validation-proof parser (`104
  passed`); integration smoke (`2 passed`); cleanup
  `test_owned_engagement_db_count=0`. Handoff:
  `.claude/handoffs/2026-07-23-key-exposure-dashboard-parity.md`.
- [x] Validation/review parity for unknown validation methods completed:
  shared reportable cloud validation-method policy now gates deterministic
  synthesis, Phase 6 report/raw exports, graph vulnerability nodes, dashboard
  severity/finding tables, and imported dashboard graph payloads. Unknown
  `VALIDATED` methods such as `manual_validated_note` remain validation
  inventory only. Backprop: `SPEC.md` `B11`; `T3`/`T4` are marked in progress.
  Verification: failing Phase 6 TDD first; focused Phase 6/dashboard/graph
  regressions; compile/Ruff; combined deterministic findings, Phase 6,
  dashboard, and attack-path suite (`145 passed`); representative integration
  smoke (`2 passed`); cleanup `test_owned_engagement_db_count=0`. Handoff:
  `.claude/handoffs/2026-07-23-validation-review-method-parity.md`.
- [x] Deterministic validation-method report-gate completed:
  `DeterministicFindingEngine` now rejects `VALIDATED` cloud rows with unknown
  validation methods and requires linked key confirmations to pass the stable
  proof parser before they keep or create deterministic findings. Backprop:
  `SPEC.md` `B10`. Verification included failing TDD first, focused regression,
  compile/Ruff, full deterministic findings (`17 passed`), Phase 6 report-gate
  slice (`3 passed`), representative integration validation/fallback (`3
  passed`), orchestrator kill-chain slice (`2 passed, 757 deselected`), and
  attack-path proof slice (`2 passed, 106 deselected`). Handoff:
  `.claude/handoffs/2026-07-23-deterministic-validation-method-report-gate.md`.
- [x] Web App Manifest relative-URL passive-recursion completed: source-gated
  `manifest.json`/`webmanifest` artifacts now resolve relative `start_url`,
  `scope`, shortcut, share-target, protocol-handler, icon, and screenshot URLs
  via `web_manifest_urls`, wired into the existing orchestrator URL-family path
  as a thin adapter. Generic JSON lookalikes remain excluded. Verification
  included failing TDD first, focused manifest plus adjacent format/label checks
  (`4 passed`), compile/Ruff, exact local and remote engagement-backed
  manifest/root metadata tests (`2 passed`), compact smoke (`7 passed, 1
  deselected`), and cleanup with no test-owned engagement DBs remaining.
  Handoff:
  `.claude/handoffs/2026-07-23-web-manifest-relative-url-recursion.md`.
- [x] JWKS metadata passive-recursion completed: source-gated
  `.well-known/jwks.json` now resolves concrete `x5u` and `jku` certificate or
  key-set URL pivots through `forge.utils.artifact_jwks_metadata`, wired into
  the existing orchestrator URL-family path as a thin adapter. Generic JSON
  lookalikes remain excluded. Verification included failing TDD first, JWKS plus
  adjacent OAuth/well-known slices (`10 passed`), compile/Ruff, existing remote
  OpenID/OAuth engagement-backed regressions (`3 passed, 756 deselected`),
  compact smoke (`7 passed, 1 deselected`), and cleanup with no test-owned
  engagement DBs remaining. Handoff:
  `.claude/handoffs/2026-07-23-jwks-metadata-passive-recursion.md`.
- [x] OAuth/OpenID metadata passive-recursion completed: source-gated
  `.well-known` OAuth/OIDC metadata now resolves concrete relative URL pivots
  through `forge.utils.artifact_oauth_metadata`, wired into the existing
  orchestrator URL-family path as a thin adapter. Generic JSON lookalikes remain
  excluded. Verification included failing TDD first, focused helper/integration
  plus adjacent well-known slices (`8 passed`), compile/Ruff, existing remote
  OpenID/OAuth engagement-backed regressions (`3 passed, 756 deselected`),
  compact smoke (`5 passed, 1 deselected`), and cleanup with no test-owned
  engagement DBs remaining. Handoff:
  `.claude/handoffs/2026-07-23-oauth-metadata-passive-recursion.md`.
- [x] React audit artifact and kill-chain raw CSV parity completed: React
  detail types/offline samples now include `audit_count`, audit manifest
  artifacts, and an `Audit` quick export link. The Phase 1 kill-chain raw-export
  fallback test now proves CSV checksum/provider/fallback/write-error lineage
  at the E2E boundary and treats honeypot-suspected resources as validation
  inventory, not reportable findings. Verification included failing React TDD
  first, focused React contract, kill-chain fallback, React build/lint,
  compile/Ruff, dashboard/API/report/webui slice, compact smoke, cleanup
  `remaining_pytest_engagement_dirs=0`, persistent DB inventory `1`, `5010`,
  `master.db`, and no Python/pytest process remains. Handoff:
  `.claude/handoffs/2026-07-23-webui-audit-raw-csv-e2e-parity.md`.
- [x] Raw-export CSV lineage parity completed: Phase 6 raw/companion CSV
  exports now include findings checksum and report-lineage fields matching the
  JSON export, including fallback reason and write error for last-resort raw
  export. Verification included failing TDD first (`KeyError:
  'findings_checksum'`), compile/Ruff, focused Phase 6 fallback/raw-export
  selectors, cloud-exposure raw fallback gate, dashboard/API raw-export detail
  checks, compact cross-phase smoke, cleanup
  `remaining_pytest_engagement_dirs=0`, persistent DB inventory `1`, `5010`,
  `master.db`, and no Python/pytest process remains. Handoff:
  `.claude/handoffs/2026-07-23-raw-export-csv-lineage.md`.
- [x] Dashboard/API audit-artifact review parity completed: static dashboard
  detail JSON/HTML and live web API detail payloads now expose audit exports as
  `kind: "audit"` artifacts with separate `audit_count`, while `report_count`
  remains report-only. Slug artifact download works for audit JSON. Verification
  included failing TDD first (`2 failed`), compile/Ruff, focused dashboard/API
  slices, compact cross-phase smoke, cleanup
  `remaining_pytest_engagement_dirs=0`, persistent DB inventory `1`, `5010`,
  `master.db`, and no Python/pytest process remains. Handoff:
  `.claude/handoffs/2026-07-23-dashboard-audit-artifact-parity.md`.
- [x] End-goal source-of-truth refresh completed: the active product target is
  explicitly locked to `FORGE-DETERMINISTIC-ASM-PIPELINE-v1` even when runtime
  `/goal` text is stale. `END_GOAL.md`, `docs/end_goal.md`,
  `docs/deterministic_engagement_contract.md`,
  `docs/engagement_overhaul_tasklist.md`, and
  `docs/claude_continue_checklist.md` now all point to the same deterministic
  authorized engagement pipeline target. Backprop added `SPEC.md` `B8`.
  Handoff:
  `.claude/handoffs/2026-07-20-end-goal-source-of-truth-refresh.md`.
- [x] Yarn Berry `.yarnrc.yml` passive package-config completed:
  `.yarnrc.yml` and cached `*.yarnrc-yml` names now classify as `yarnrc-yml`
  instead of generic YAML, while non-dot `yarnrc.yml` remains excluded. Yarn
  registry URLs, scoped registry URLs, owner emails, and Firebase refs recurse
  through the passive artifact path while embedded npm auth tokens stay
  stripped. Verification: TDD helper regression failed before implementation
  (`4 failed, 52 passed`) then passed, focused helper suite (`56 passed`),
  compile/Ruff, adjacent package-manager/runtime-config slice (`61 passed, 754
  deselected`), compact slice (`4 passed, 1 deselected`), cleanup
  `remaining_pytest_engagement_dirs=0`; persistent DB inventory remains `1`,
  `5010`, `master.db`; no Python/pytest process remains. Handoff:
  `.claude/handoffs/2026-07-20-yarnrc-yml-passive-recursion.md`.
- [x] Python Poetry global config/auth passive package-config completed:
  source-aware `pypoetry/config.toml` now classifies as `poetry-config`, and
  `pypoetry/auth.toml` plus cached `*.poetry-auth` names now classify as
  `poetry-auth`, while generic `config.toml` and `auth.toml` remain excluded.
  Poetry auth repository URLs, owner emails, and Supabase refs recurse through
  the passive artifact path while embedded repository credentials stay stripped.
  Verification: TDD helper regression failed before implementation (`5 failed,
  47 passed`) then passed, focused helper suite (`52 passed`), compile/Ruff,
  adjacent package-manager/orchestrator slice (`53 passed, 758 deselected`),
  compact slice (`4 passed, 1 deselected`), cleanup
  `remaining_pytest_engagement_dirs=0`; persistent DB inventory remains `1`,
  `5010`, `master.db`; no Python/pytest process remains. Handoff:
  `.claude/handoffs/2026-07-20-poetry-global-auth-config-passive-recursion.md`.
- [x] Python Poetry passive package-config completed: `poetry.toml` now
  classifies as `poetry-config`, including cached `*.poetry-config` remote
  names, allowing Poetry repository URLs, owner emails, and cloud refs to
  recurse through the passive artifact path while embedded repository
  credentials stay stripped. Verification: TDD helper regression failed before
  implementation (`4 failed, 43 passed`) then passed, focused helper suite (`47
  passed`), compile/Ruff, adjacent package-manager/orchestrator slice (`48
  passed, 758 deselected`), compact slice (`4 passed, 1 deselected`), cleanup
  `remaining_pytest_engagement_dirs=0`; persistent DB inventory remains `1`,
  `5010`, `master.db`; no Python/pytest process remains. Handoff:
  `.claude/handoffs/2026-07-20-poetry-config-passive-recursion.md`.
- [x] Python PDM passive package-config completed: `pdm.toml` and `.pdm.toml`
  now classify as `pdm-config`, and `pdm.lock` now classifies as `pdm-lock`,
  allowing package index URLs, owner emails, Firebase/Supabase refs, and S3
  archive refs to recurse through the passive artifact path while embedded
  package-index credentials stay stripped. Verification: regression failed
  before implementation then passed, compile/Ruff, focused package-manager
  regression (`1 passed`), package/Python/SBOM slice (`11 passed, 748
  deselected`), Terraform/IaC-adjacent slice (`6 passed, 753 deselected`),
  compact slice (`4 passed, 1 deselected`), cleanup
  `remaining_pytest_engagement_dirs=0`; persistent DB inventory remains `1`,
  `5010`, `master.db`; no Python/pytest process remains. Handoff:
  `.claude/handoffs/2026-07-20-pdm-config-passive-recursion.md`.
- [x] Python `uv.toml` passive package-config completed: `uv.toml` and
  `.uv.toml` now classify as `uv-config`, allowing package index URLs, owner
  emails, Firebase refs, and Supabase refs to recurse through the passive
  artifact path while embedded package-index credentials stay stripped.
  Verification: focused regression failed before implementation then passed,
  compile/Ruff, package-manager/Python config slice (`2 passed, 757
  deselected`), artifact label/package/SBOM slice (`10 passed, 749
  deselected`), compact slice (`4 passed, 1 deselected`), cleanup
  `remaining_pytest_engagement_dirs=0`; persistent DB inventory remains `1`,
  `5010`, `master.db`. Handoff:
  `.claude/handoffs/2026-07-20-uv-config-passive-recursion.md`.
- [x] MTGX provenance analyst-property completed: native Maltego workspace
  exports now expose safe provenance metadata as first-class `forge.*` analyst
  properties, including `provider_sources`, `root_domain`, `format`,
  source/discovery fields, seed hints, and passive artifact/download context.
  Verification: focused MTGX regression failed before implementation then
  passed, compile/Ruff, adjacent graph export slice (`2 passed, 106
  deselected`), dashboard MTGX/provider-matrix slice (`4 passed, 13
  deselected`), compact smoke (`5 passed, 1 deselected`), cleanup
  `remaining_pytest_engagement_dirs=0`; persistent DB inventory remains `1`,
  `5010`, `master.db`. Handoff:
  `.claude/handoffs/2026-07-20-mtgx-provenance-analyst-properties.md`.
- [x] End-goal anchor and Report Section 5 boundary completed: `END_GOAL.md`
  and `docs/end_goal.md` now state the pinned product end state explicitly for
  future agents, and Phase 6 report-facing Section 5 wording now uses
  `Vulnerability & Exposure Correlation` instead of legacy exploit correlation.
  Backprop added `SPEC.md` `V13` and `B7`. Handoff:
  `.claude/handoffs/2026-07-20-end-goal-section5-boundary.md`.
- [x] Report Section 6 boundary completed: Phase 6 mandatory sections, fallback
  prompts, Jinja template instructions, and deterministic template output now
  use `Validation Boundaries & Evidence Handling` instead of forcing legacy
  post-exploitation activity into authorized ASM reports. Backprop added
  `SPEC.md` `V12` and `B6`. Verification: focused regressions failed before
  implementation then passed, compile/Ruff, report synthesizer (`80 passed`),
  cloud exposure report gating (`1 passed`), provider fallback chain
  (`10 passed`), dashboard report-summary/raw-export slice (`1 passed, 16
  deselected`), final combined adjacent slice (`12 passed, 16 deselected`),
  compact smoke (`5 passed, 1 deselected`), cleanup
  `remaining_pytest_engagement_dirs=0`; persistent DB inventory remains `1`,
  `5010`, `master.db`, and no pytest/Python process remains. Handoff:
  `.claude/handoffs/2026-07-20-report-section6-boundary.md`.
- [x] Pytest engagement cleanup safety completed: Phase 1 partition cleanup now
  treats `pytest-of-*` as an owner container and removes only nested `pytest-*`
  run directories containing `engagement.db`. Backprop added `SPEC.md` `V11`
  and `B5`. Verification: focused regression failed before implementation then
  passed, compile/Ruff, cleanup script tests (`5 passed`), engagement-ID tests
  (`3 passed`), compact smoke (`5 passed, 1 deselected`), real temp cleanup
  left `remaining_pytest_engagement_dirs=0`; persistent workspace DB inventory
  remains `1`, `5010`, `master.db`, and no pytest/Python process remains.
  Handoff:
  `.claude/handoffs/2026-07-20-pytest-engagement-cleanup-safety.md`.
- [x] Package URL helper extraction completed: core package-url ecosystem
  mapping and package path parsing now live in `forge.utils.artifact_package_url`
  instead of the oversized orchestrator; JSR runtime specifier parsing uses the
  shared parser. Verification: direct helper regression failed before
  implementation then passed (`3 passed`), compile/Ruff, adjacent package/SBOM
  suite (`50 passed`), representative SBOM queue regression (`1 passed`),
  cleanup unchanged (`1`, `5010`, `master.db`). Claude CLI read-only review
  found no confirmed defects; its requested grep/import checks passed. Subagent
  spawn was attempted for read-only doc/task audit but blocked by agent-thread
  limit. Handoff:
  `.claude/handoffs/2026-07-20-package-url-helper-extraction.md`.
- [x] Long-tail SBOM package URL recursion completed: CycloneDX/SPDX package
  URLs for Swift, CocoaPods, pub.dev, Hex.pm, CRAN, and Hugging Face now become
  deterministic recursive URL seeds through `forge.utils.artifact_package_url`.
  Verification: regression failed before implementation, compile/Ruff, focused
  package URL regression (`2 passed`), adjacent package/SBOM suite
  (`49 passed`), cleanup unchanged (`1`, `5010`, `master.db`). Handoff:
  `.claude/handoffs/2026-07-20-long-tail-package-url-recursion.md`.
- [x] SBOM label helper extraction completed: multi-suffix SBOM label logic now
  lives in `forge.utils.artifact_sbom`, with `engagement_orchestrator.py` kept
  as a thin caller. Verification: compile/Ruff and focused SBOM plus adjacent
  artifact format/security metadata tests (`5 passed`). Handoff:
  `.claude/handoffs/2026-07-20-sbom-label-helper-extraction.md`.
- [x] SBOM multi-suffix artifact-label checkpoint completed:
  `bom.cyclonedx.json`, `bom.cdx.json`, `bom.spdx.json`, `bom.spdx.yaml`, and
  `bom.syft.json` now retain deterministic SBOM format labels, and explicit
  SBOM labels outrank broad inventory heuristics such as `inventory.spdx.json`.
  Verification: focused regression failed before implementation then passed
  (`2 passed`), compile/Ruff, adjacent artifact format/security metadata slice
  (`5 passed`), cleanup unchanged (`1`, `5010`, `master.db`). Handoff:
  `.claude/handoffs/2026-07-20-sbom-multisuffix-format-labels.md`.
- [x] React web UI graph/report parity completed: the engagement graph
  explorer now preserves backend edge metadata in selected-node edge evidence,
  and offline fallback samples include CSV report companions/counts/artifacts
  in line with backend report families. Verification: TDD source contract
  failed before implementation then passed (`2 passed`), React/Vite build
  passed, `oxlint` exited 0 with existing hook warnings, focused dashboard/web
  UI parity slice (`4 passed, 15 deselected`), cleanup unchanged (`1`, `5010`,
  `master.db`). Handoff:
  `.claude/handoffs/2026-07-20-webui-graph-edge-csv-parity.md`.
- [x] MTGX dashboard analyst-metadata fidelity completed: `.mtgx`-only
  dashboard graph fallback now retains safe non-control `forge.*` node
  properties such as `validation_detail` and safe edge metadata from
  `forge.metadata_json`, while sensitive keys such as `key_enc` stay scrubbed.
  Verification: TDD regression failed before implementation, compile/Ruff,
  focused MTGX/GraphML/graph JSON parser contracts (`3 passed`), broader
  MTGX/GraphML subset (`3 passed, 14 deselected`), cleanup unchanged (`1`,
  `5010`, `master.db`). Handoff:
  `.claude/handoffs/2026-07-20-mtgx-dashboard-analyst-property-parity.md`.
- [x] Dashboard/API CSV report-family parity completed: static dashboard and
  live engagement-detail API fixtures now include CSV report companions and
  assert four exports for current/historical report families. Verification:
  compile/Ruff, static dashboard contracts (`2 passed`), live web API contracts
  (`2 passed, 11 warnings`), cleanup unchanged (`1`, `5010`, `master.db`).
  Handoff:
  `.claude/handoffs/2026-07-20-dashboard-api-csv-report-parity.md`.
- [x] Normal report-family raw CSV companion completed: Phase 6 successful
  Markdown/JSON/PDF report families now also include mirrored `.csv` raw export
  companions. The representative provider-failure E2E asserts validated-only
  finding CSV rows while preserving `UNVERIFIED` dead cloud assets as
  non-finding validation inventory. Verification: TDD mirror regression failed
  then passed, compile/Ruff, focused Phase 6 slice (`3 passed, 75 deselected`),
  representative E2E (`1 passed in 45.45s`), cleanup unchanged (`1`, `5010`,
  `master.db`). Handoff:
  `.claude/handoffs/2026-07-20-report-family-csv-companion.md`.
- [x] Representative multi-seed provider-failure fallback proof completed:
  `tests/phase1/test_kill_chain_multiseed_recursive_e2e.py` now exercises
  final report generation via `provider=auto`, forces a deterministic
  `ProviderUnavailableError("mock quota exhausted")`, and asserts template
  fallback lineage in Markdown/JSON/PDF companions. Verification: compile,
  Ruff, focused E2E (`1 passed in 44.60s`), adjacent Phase 6 fallback slice
  (`4 passed, 74 deselected`), and cleanup inventory (`1`, `5010`,
  `master.db`). Handoff:
  `.claude/handoffs/2026-07-20-multiseed-provider-failure-fallback.md`.
- [x] Current workspace Git status checked on 2026-07-20: this checkout is a Git repo on `main` tracking `origin/main`. Any deep historical checklist lines saying the workspace was intentionally not a Git repo are stale context only; do not use them to skip commits.
- [x] Defender/impacket status checked: `C:\Program Files\Python312\Lib\site-packages\impacket\smbconnection.py` is currently absent/quarantined, while the project venv copy exists and Forge imports impacket from `.venv`. `Get-MpThreatDetection` shows repeated successful actions against only the global `Program Files` path. Do not add a broad Defender exclusion for `C:\Program Files`; keep launchers venv-bound and only consider a narrow project-scoped exclusion if Defender starts quarantining the verified `.venv` dependency.
- [x] Web manifest related-application passive inventory completed: source-aware Web App Manifest `related_applications` now promotes valid Android package IDs and iTunes/App Store IDs into `mobile_android_package` / `mobile_ios_app_store_id` resource inventory, preserves existing manifest email/URL/Supabase recursion, and validation registry marks the mobile resource types terminal `UNSUPPORTED` with no provider calls or findings. Handoff: `.claude/handoffs/2026-07-20-web-manifest-related-app-inventory.md`.
- [x] Ads.txt/app-ads.txt publisher-account passive inventory completed:
  source-aware root ad metadata now promotes valid ad-system domain plus
  publisher-account declarations into `ad_publisher_account` resource inventory,
  preserves existing email/URL/Supabase recursion, filters malformed/assignment
  lines and unsupported relationships, and validation registry marks the new
  type terminal `UNSUPPORTED` with no provider calls or findings. Handoff:
  `.claude/handoffs/2026-07-20-ad-metadata-publisher-inventory.md`.
- [x] Sellers.json seller-account passive inventory completed: source-aware
  sellers metadata now promotes non-confidential seller entries with valid
  `seller_id`, public domain, and accepted seller type into
  `ad_seller_account` resource inventory, preserves existing
  email/URL/Supabase recursion, and validation registry marks the new type
  terminal `UNSUPPORTED` with no provider calls or findings. Handoff:
  `.claude/handoffs/2026-07-20-sellers-json-seller-inventory.md`.
- [x] AI plugin manifest passive inventory completed: source-aware
  `ai-plugin.json` now promotes valid `name_for_model` plus HTTP(S) `api.url`
  host into `ai_plugin_manifest` resource inventory, preserves existing
  email/URL/Firebase recursion, excludes generic JSON lookalikes, and validation
  registry marks the new type terminal `UNSUPPORTED` with no provider calls or
  findings. Handoff:
  `.claude/handoffs/2026-07-20-ai-plugin-manifest-inventory.md`.
- [x] Public metadata document-link recursion completed: source-aware
  `llms.txt`, `ai.txt`, `humans.txt`, `security.txt`, and `trust.txt` parsing
  now promotes Markdown/document field links such as
  `[OpenAPI](./openapi.yaml)` and `Policy: ./ai-policy.txt` into recursive URL
  seeds when the artifact source URL is HTTP(S), while generic `notes.txt`
  Markdown remains excluded. Handoff:
  `.claude/handoffs/2026-07-20-public-metadata-links-recursion.md`.
- [x] Matrix server delegated-host recursion completed: source-aware
  `.well-known/matrix/server` metadata now promotes valid `m.server`
  homeserver delegation values into recursive subdomain/root-domain seeds while
  excluding generic JSON lookalikes. Handoff:
  `.claude/handoffs/2026-07-20-matrix-server-host-recursion.md`.
- [x] Templated artifact URL persistence hardening completed: artifact URL seed
  persistence now rejects raw or URL-decoded template markers, preventing
  malformed host-meta/WebFinger fragments like `resource=%7Buri` from becoming
  recursive URL or related-host seeds. Handoff:
  `.claude/handoffs/2026-07-20-templated-url-seed-hardening.md`.
- [x] Standards namespace artifact URL suppression completed: artifact URL seed
  persistence now rejects known OASIS/W3C `ns` namespace references such as
  `docs.oasis-open.org/ns/xri` and `www.w3.org/ns/did`, preventing standards
  schema docs from becoming recursive attack-surface seeds. Handoff:
  `.claude/handoffs/2026-07-20-standards-namespace-url-suppression.md`.
- [x] DID web identifier host recursion completed: source-aware `did.json` and
  `did-configuration.json` now promote valid `did:web:` identifiers into
  recursive subdomain/root-domain seeds while excluding generic JSON lookalikes.
  Handoff: `.claude/handoffs/2026-07-20-did-web-host-recursion.md`.
- [x] ATProto DID web host recursion completed: source-aware
  `.well-known/atproto-did` now promotes line-oriented `did:web:` identifiers
  into recursive subdomain/root-domain seeds while excluding generic text
  lookalikes. Handoff:
  `.claude/handoffs/2026-07-20-atproto-did-web-host-recursion.md`.
- [x] Nostr relay host recursion completed: source-aware `.well-known/nostr.json`
  now promotes valid `ws://` and `wss://` relay endpoint hosts into recursive
  subdomain/root-domain seeds while excluding generic JSON lookalikes. Handoff:
  `.claude/handoffs/2026-07-20-nostr-relay-host-recursion.md`.
- [x] Nostr relay key-map recursion completed: source-aware
  `.well-known/nostr.json` now also promotes relay endpoint URLs used as map
  keys into recursive subdomain/root-domain seeds. Handoff:
  `.claude/handoffs/2026-07-20-nostr-relay-key-map-recursion.md`.
- [x] Passkey endpoint relative-URL recursion completed: source-aware
  `.well-known/passkey-endpoints` now resolves relative endpoint fields against
  the remote artifact `source_url` into recursive URL seeds while excluding
  generic JSON lookalikes. Handoff:
  `.claude/handoffs/2026-07-20-passkey-relative-endpoint-recursion.md`.
- [x] Agent Card relative-URL recursion completed: source-aware
  `.well-known/agent-card.json` now resolves relative URL fields against the
  remote artifact `source_url` into recursive URL seeds while excluding generic
  JSON lookalikes. Handoff:
  `.claude/handoffs/2026-07-20-agent-card-relative-url-recursion.md`.
- [x] Open Resource Discovery relative-resource recursion completed:
  source-aware `.well-known/open-resource-discovery` now resolves relative
  resource values against the remote artifact `source_url` into recursive URL
  seeds while excluding generic JSON lookalikes. Handoff:
  `.claude/handoffs/2026-07-20-open-resource-discovery-relative-recursion.md`.
- [x] Mercure relative-field URL recursion completed: source-aware
  `.well-known/mercure` now resolves relative `hub`, `subscribe`, and `publish`
  field values against the remote artifact `source_url` into recursive URL seeds
  while excluding generic text lookalikes. Handoff:
  `.claude/handoffs/2026-07-20-mercure-relative-field-recursion.md`.
- [x] JMAP relative URL-field recursion completed: source-aware
  `.well-known/jmap` now resolves concrete relative JSON `*Url` fields against
  the remote artifact `source_url` into recursive URL seeds while excluding
  templated download URLs and generic JSON lookalikes. Handoff:
  `.claude/handoffs/2026-07-20-jmap-relative-url-recursion.md`.
- [x] WebWeaver relative URL-field recursion completed: source-aware
  `.well-known/webweaver.json` now resolves concrete relative endpoint and URL
  fields against the remote artifact `source_url` into recursive URL seeds while
  excluding templated callback URLs and generic JSON lookalikes. Handoff:
  `.claude/handoffs/2026-07-20-webweaver-relative-url-recursion.md`.
- [x] API catalog relative URL-field recursion completed: source-aware
  `.well-known/api-catalog` now resolves concrete relative URL and endpoint
  fields against the remote artifact `source_url` into recursive URL seeds while
  excluding templated callback URLs and generic JSON lookalikes. Handoff:
  `.claude/handoffs/2026-07-20-api-catalog-relative-url-recursion.md`.
- [x] Well-known JSON link relative-href recursion completed: source-aware
  `nodeinfo`, `webfinger`, and `host-meta.json` now resolve concrete relative
  `href` / `url` values against the remote artifact `source_url` into recursive
  URL seeds while suppressing NodeInfo schema namespace `rel` URLs and excluding
  templated links/generic JSON lookalikes. Handoff:
  `.claude/handoffs/2026-07-20-well-known-link-relative-href-recursion.md`.
- [x] Host-meta XML relative-href recursion completed: source-aware
  `.well-known/host-meta` now resolves concrete relative `<Link href="...">`
  values against the remote artifact `source_url` into recursive URL seeds while
  excluding LRDD templates and generic XML lookalikes. Handoff:
  `.claude/handoffs/2026-07-20-host-meta-relative-href-recursion.md`.
- [x] MTA-STS MX host recursion completed: source-aware `mta-sts.txt` now
  promotes valid `mx:` hosts, including wildcard patterns normalized without
  `*.`, into recursive domain/subdomain seeds while preserving existing
  contact/policy/cloud recursion and excluding generic text `mx:` lookalikes.
  Handoff: `.claude/handoffs/2026-07-20-mta-sts-mx-recursion.md`.
- [x] Apple app-site-association iOS app passive inventory completed: source-aware AASA now promotes valid `TEAMID.bundle.id` values from `appID`/`appIDs`/`apps` into `mobile_ios_app` resource inventory, preserves existing email/URL/Supabase recursion, and the validation registry marks the new type terminal `UNSUPPORTED` with no provider call or finding. Handoff: `.claude/handoffs/2026-07-20-aasa-ios-app-inventory.md`.
- [x] Assetlinks Android package passive inventory completed: source-aware `assetlinks.json` now promotes valid Android `target.package_name` values into `mobile_android_package` resource inventory, preserves existing email/URL/Supabase recursion, and the validation registry marks the new type terminal `UNSUPPORTED` with no provider call or finding. Handoff: `.claude/handoffs/2026-07-20-assetlinks-android-package-inventory.md`.
- [x] Microsoft identity-association metadata recursion completed: `/.well-known/microsoft-identity-association.json` and extensionless fallback route now keep source-aware labels, and `associatedApplications[].applicationId` GUIDs feed passive `azure_ad_app` cloud-asset inventory. Handoff: `.claude/handoffs/2026-07-20-microsoft-identity-association-metadata.md`.
- [x] API-client host/path URL-object recursion completed: source-aware Postman/API-client URL objects with `host`/`hostname` plus `path`/`pathname` and no explicit protocol now default to HTTPS recursive URL pivots, while host-only/local values remain suppressed and string `url` fields avoid duplicate candidates. Handoff: `.claude/handoffs/2026-07-20-api-client-host-path-url-objects.md`.
- [x] Multi-seed recursive fallback-lineage proof completed: the compact multi-seed kill-chain E2E fixture now asserts Markdown/JSON/PDF report companions, template render lineage, checksum continuity, and validated-only structured finding context. Handoff: `.claude/handoffs/2026-07-20-multiseed-fallback-lineage.md`.
- [x] Well-known security/supply-chain metadata target completed: `/.well-known/csaf`, `/.well-known/csaf-aggregator`, `/.well-known/sbom`, `/.well-known/passkey-endpoints`, `/.well-known/ssh-known-hosts`, `/.well-known/sshfp`, and `/.well-known/pki-validation` now classify as passive source-aware metadata and feed email/URL/cloud pivots through artifact recursion. Handoff: `.claude/handoffs/2026-07-20-well-known-security-metadata.md`.
- [x] Well-known privacy/vendor metadata target completed: `/.well-known/gpc.json`, `/.well-known/tdmrep.json`, `/.well-known/pubvendors.json`, `/.well-known/trust.txt`, `/.well-known/dnt-policy.txt`, and `/.well-known/privacy-sandbox-attestations.json` now preserve source-aware labels and feed email/URL/cloud pivots through artifact recursion. Handoff: `.claude/handoffs/2026-07-20-well-known-privacy-metadata.md`.
- [x] Well-known API/application metadata target completed: `/.well-known/agent-card.json`, `/.well-known/api-catalog`, `/.well-known/open-resource-discovery`, `/.well-known/mercure`, and `/.well-known/webweaver.json` now classify as passive source-aware metadata and feed email/URL/cloud pivots through artifact recursion. Handoff: `.claude/handoffs/2026-07-20-well-known-api-metadata.md`.
- [x] Well-known service metadata target completed: `/.well-known/did-configuration.json`, `/.well-known/keybase.txt`, `/.well-known/smart-configuration`, and `/.well-known/terraform.json` now classify as passive source-aware metadata and feed email/URL/cloud pivots through artifact recursion. Handoff: `.claude/handoffs/2026-07-20-well-known-service-metadata.md`.
- [x] Well-known identity metadata target completed: `/.well-known/nostr.json`, `/.well-known/atproto-did`, and `/.well-known/jmap` now classify as passive source-aware identity metadata and feed email/URL/cloud pivots through artifact recursion. Handoff: `.claude/handoffs/2026-07-20-well-known-identity-metadata.md`.
- [x] Local web manifest source-label target completed: local `manifest.json` artifacts now keep source-aware format metadata instead of generic `json`, and tracked docs now route future agents to the deterministic goal chain instead of stale handoff/source-of-truth wording. Handoff: `.claude/handoffs/2026-07-20-manifest-local-source-label.md`.
- [x] Local public metadata source-label target completed: local `assetlinks.json`, `browserconfig.xml`, `jwks.json`, `mta-sts.txt`, and `security.txt` artifacts now keep source-aware formats instead of generic suffix labels while preserving existing recursion. Handoff: `.claude/handoffs/2026-07-20-public-metadata-labels.md`.
- [x] Apple merchant domain-association metadata target completed: `/.well-known/apple-developer-merchantid-domain-association` now routes as passive config metadata and can feed URL/email/cloud pivots through artifact recursion. Handoff: `.claude/handoffs/2026-07-20-apple-merchant-well-known-recursion.md`.
- [x] Matrix client well-known metadata target completed: `/.well-known/matrix/client` now routes as `matrix-client` passive config metadata and feeds Matrix homeserver/identity-server URLs, contact email, and Supabase refs through artifact recursion. Handoff: `.claude/handoffs/2026-07-20-matrix-client-well-known-recursion.md`.
- [x] OIDC claim contact/userinfo target completed: `claims.email`, `claims.phone_number`, `userinfo.email`, `userinfo.phone_number`, `userinfo.profile`, and `userinfo.website` now stay on the enclosing provider row as recursive evidence; scalar/token claims stay suppressed. Handoff: `.claude/handoffs/2026-07-20-oidc-userinfo-claim-contact-recursion.md`.
- [x] OIDC claim URL recursion target completed: Epieos/userinfo-style `claims.profile` and `claims.website` now stay on the existing provider row as recursive URL evidence; scalar/token claims stay suppressed. Handoff: `.claude/handoffs/2026-07-20-oidc-claim-url-recursion.md`.
- [x] Nested StackExchange user-profile target completed: provider-scoped Epieos StackExchange/StackOverflow `user` payloads now become safe public profile pivots when they include numeric `user_id`, normalized handle, and accepted/no site hint. Bad site hints are rejected. Handoff: `.claude/handoffs/2026-07-20-stackexchange-nested-user-profile.md`.
- [ ] Immediate next code target: audit live API route/detail parity for
  deterministic key exposure and cloud reportability gates. Focus on
  non-dashboard routes that return engagement detail, graph payloads, report
  summaries, or key/finding counts directly from SQLite instead of
  dashboard-generated JSON. Add the smallest failing route/contract test first,
  then harden only that surface.
- [ ] Code-size discipline is now a hard continuation rule: do not add new feature logic directly into `forge/engagement_orchestrator.py`, `forge/cli.py`, `forge/utils/intel/social_scraper.py`, or mega test files unless it is a thin adapter/regression hook. HAR helpers live in `forge/utils/artifact_har.py`, and Epieos/social host guards now live in `forge/utils/intel/social_profile_hosts.py`; next refactor target is splitting newly added mega-file tests where imports allow it.

## Current green checkpoint

- [x] Microsoft identity-association metadata recursion is green:
  Microsoft-documented `/.well-known/microsoft-identity-association.json` and
  extensionless fallback route now preserve source-aware labels, and
  `associatedApplications[].applicationId` GUIDs feed passive `azure_ad_app`
  cloud-asset inventory through the bounded artifact cloud-asset family path.
  Local fixtures also prove email, URL, and Supabase pivots continue to recurse
  from the same payload. Verification: TDD focused regression failed before
  implementation, then passed -> `2 passed`; compile/Ruff for touched
  parser/test files; adjacent well-known/public metadata slice -> `17 passed`;
  adjacent orchestrator metadata selector -> `21 passed, 738 deselected`;
  cleanup check found no new persistent pytest DBs. Review: Claude sidecar
  identified the payload-shape gap after delayed output; IANA search did not
  verify an IANA registration, so this is documented as Microsoft-documented.
  Safety: passive static metadata parsing/inventory only. No Microsoft Graph,
  Entra, Azure API, app verification, provider call, live probing, credential
  use, scope relaxation, proxy/IP rotation, rate-limit bypass,
  validation/report-gate change, or persistent non-test engagement DB mutation
  changed. Handoff:
  `.claude/handoffs/2026-07-20-microsoft-identity-association-metadata.md`.

- [x] API-client host/path URL-object recursion is green:
  Source-aware API-client artifacts now accept Postman-style URL objects with
  `host`/`hostname` plus `path`/`pathname` and no explicit `raw`/`protocol`,
  defaulting concrete host/path pivots to HTTPS while suppressing host-only and
  localhost values. Direct string `url` fields still use the existing path, so
  duplicate raw/normalized candidates are avoided. Verification: TDD focused
  regression failed before the fix and passed afterward; compile/Ruff for
  `forge/engagement_orchestrator.py` and
  `tests/phase1/test_artifact_api_client_workers.py`; adjacent worker/label
  suite -> `8 passed`; adjacent orchestrator API-client selector -> `13
  passed, 746 deselected`; cleanup check found no new persistent pytest DBs.
  Claude sidecar review was attempted, produced no output file, and was
  terminated. Safety: passive static parser hardening only. No provider call,
  live probing, credential use, scope relaxation, proxy/IP rotation,
  rate-limit bypass, validation/report-gate change, or persistent non-test
  engagement DB mutation changed. Handoff:
  `.claude/handoffs/2026-07-20-api-client-host-path-url-objects.md`.

- [x] Multi-seed recursive fallback-lineage proof is green:
  The compact multi-seed kill-chain E2E fixture now asserts Markdown, JSON, and
  PDF report companions, template render metadata, checksum lineage, and
  structured validated-only finding context from the same mocked/offline
  recursive engagement run. Verification: compile/Ruff for
  `tests/phase1/test_kill_chain_multiseed_recursive_e2e.py`; focused test ->
  `1 passed in 43.12s`. Safety: test-only assertion hardening. No production
  behavior change, provider call, live probing, credential use, scope
  relaxation, proxy/IP rotation, rate-limit bypass, validation/report-gate
  change, or persistent non-test engagement DB mutation changed. Handoff:
  `.claude/handoffs/2026-07-20-multiseed-fallback-lineage.md`.

- [x] Well-known security/supply-chain metadata recursion checkpoint is green:
  IANA-listed passive routes `/.well-known/csaf`,
  `/.well-known/csaf-aggregator`, `/.well-known/sbom`,
  `/.well-known/passkey-endpoints`, `/.well-known/ssh-known-hosts`,
  `/.well-known/sshfp`, and `/.well-known/pki-validation` now classify as
  source-aware config artifacts with stable route/cache/local format labels.
  Local static fixtures prove CSAF, SBOM, passkey endpoint, SSH known-hosts,
  SSHFP, and PKI validation metadata can feed recursive email, URL, and
  Supabase cloud pivots through the existing artifact queue.
  Verification: compile/Ruff for touched orchestrator/test files; focused
  well-known security metadata test -> `2 passed`; combined well-known/public
  metadata slice -> `23 passed`; adjacent orchestrator `.well-known` / metadata
  selector -> `21 passed, 738 deselected`; cleanup check found no new pytest
  engagement DBs.
  Safety: passive static metadata classification/parsing only. No CSAF
  aggregator fetch, SBOM fetch, passkey endpoint call, SSH key validation, SSHFP
  DNS lookup, PKI validation request, provider call, live probing, credential
  use, scope relaxation, proxy/IP rotation, rate-limit bypass,
  validation/report-gate change, or persistent non-test engagement DB mutation
  changed.
  Handoff: `.claude/handoffs/2026-07-20-well-known-security-metadata.md`.

- [x] Well-known privacy/vendor metadata recursion checkpoint is green:
  IANA-listed passive metadata routes `/.well-known/gpc.json`,
  `/.well-known/tdmrep.json`, `/.well-known/pubvendors.json`,
  `/.well-known/trust.txt`, `/.well-known/dnt-policy.txt`, and
  `/.well-known/privacy-sandbox-attestations.json` now preserve source-aware
  route/cache/local format labels instead of generic `json` / `txt`. Local
  static fixtures prove privacy, text/data-mining, publisher-vendor, trust,
  DNT, and privacy-sandbox metadata can feed recursive email, URL, and Supabase
  cloud pivots through the existing artifact queue.
  Verification: compile/Ruff for touched orchestrator/test files; focused
  well-known privacy metadata test -> `2 passed`; combined well-known/public
  metadata slice -> `21 passed`; adjacent orchestrator `.well-known` / metadata
  selector -> `21 passed, 738 deselected`; cleanup check found no new pytest
  engagement DBs.
  Safety: passive static metadata labeling/parsing only. No policy/vendor API
  call, browser privacy sandbox behavior, provider call, live probing,
  credential use, scope relaxation, proxy/IP rotation, rate-limit bypass,
  validation/report-gate change, or persistent non-test engagement DB mutation
  changed.
  Handoff: `.claude/handoffs/2026-07-20-well-known-privacy-metadata.md`.

- [x] Well-known API/application metadata recursion checkpoint is green:
  IANA-listed passive metadata routes `/.well-known/agent-card.json`,
  `/.well-known/api-catalog`, `/.well-known/open-resource-discovery`,
  `/.well-known/mercure`, and `/.well-known/webweaver.json` now classify as
  source-aware config artifacts with stable route/cache/local format labels.
  Local static fixtures prove agent-card, API catalog, open-resource-discovery,
  Mercure hub, and WebWeaver metadata can feed recursive email, URL, and
  Supabase cloud pivots through the existing artifact queue.
  Verification: compile/Ruff for touched orchestrator/test files; focused
  well-known API metadata test -> `2 passed`; combined well-known/public
  metadata slice -> `19 passed`; adjacent orchestrator `.well-known` / metadata
  selector -> `21 passed, 738 deselected`; cleanup check found no new pytest
  engagement DBs.
  Safety: passive static metadata classification and parsing only. No A2A agent
  call, API catalog fetch, open-resource-discovery call, Mercure subscription,
  WebWeaver call, provider call, live probing, credential use, scope relaxation,
  proxy/IP rotation, rate-limit bypass, validation/report-gate change, or
  persistent non-test engagement DB mutation changed.
  Handoff: `.claude/handoffs/2026-07-20-well-known-api-metadata.md`.

- [x] Well-known service metadata recursion checkpoint is green:
  IANA-listed passive metadata routes `/.well-known/did-configuration.json`,
  `/.well-known/keybase.txt`, `/.well-known/smart-configuration`, and
  `/.well-known/terraform.json` now classify as source-aware config artifacts
  with stable route/cache/local format labels. Local static fixtures prove DID
  configuration, Keybase proof, SMART discovery, and Terraform remote service
  discovery metadata can feed recursive email, URL, and Supabase cloud pivots
  through the existing artifact queue.
  Verification: compile/Ruff for touched orchestrator/test files; focused
  well-known service metadata test -> `2 passed`; adjacent well-known/public
  metadata helper slice -> `17 passed`; adjacent orchestrator `.well-known` /
  metadata selector -> `21 passed, 738 deselected`; cleanup check found no new
  pytest engagement DBs.
  Safety: passive static metadata classification and parsing only. No DID
  verification, Keybase lookup, SMART/FHIR call, Terraform service
  call/execution, provider call, live probing, credential use, scope relaxation,
  proxy/IP rotation, rate-limit bypass, validation/report-gate change, or
  persistent non-test engagement DB mutation changed.
  Handoff: `.claude/handoffs/2026-07-20-well-known-service-metadata.md`.

- [x] Well-known identity metadata recursion checkpoint is green:
  Passive public identity routes `/.well-known/nostr.json`,
  `/.well-known/atproto-did`, and `/.well-known/jmap` now classify as
  source-aware config artifacts with stable route/cache/local format labels.
  Local static fixtures prove Nostr NIP-05, AT Protocol DID, and JMAP discovery
  metadata can feed recursive email, URL, and Supabase cloud pivots through the
  existing artifact queue.
  Verification: compile/Ruff for touched orchestrator/test files; focused
  well-known identity metadata test -> `2 passed`; adjacent well-known/public
  metadata helper slice -> `15 passed`; adjacent orchestrator `.well-known` /
  metadata selector -> `21 passed, 738 deselected`; cleanup check found no new
  pytest engagement DBs.
  Safety: passive static metadata classification and parsing only. No Nostr
  relay connection, AT Protocol resolution, JMAP call, provider call, live
  probing, credential use, scope relaxation, proxy/IP rotation, rate-limit
  bypass, validation/report-gate change, or persistent non-test engagement DB
  mutation changed.
  Handoff: `.claude/handoffs/2026-07-20-well-known-identity-metadata.md`.

- [x] Local web manifest source-label checkpoint is green:
  Direct local/top-level `manifest.json` artifacts now preserve source-aware
  `metadata_json.format` labels instead of generic `json`, matching existing
  remote root public metadata route/cache behavior while preserving recursive
  URL/email/cloud extraction.
  Verification: compile/Ruff for touched artifact files; focused public
  metadata label test -> `1 passed`; adjacent artifact helper/public metadata
  slice -> `9 passed`; adjacent orchestrator public metadata/manifest selector
  -> `14 passed, 745 deselected`; cleanup check found no new pytest engagement
  DBs.
  Review: explorer `Planck the 2nd` confirmed the core goal docs are
  discoverable and flagged stale source-of-truth wording in older docs; tracked
  docs now point to the deterministic goal chain, and ignored archive notes were
  clarified locally but left out of the commit.
  Safety: source-aware local artifact labeling and tracked documentation
  clarification only. No route discovery, live probing, provider call, scope
  relaxation, proxy/IP rotation, rate-limit bypass, validation/report-gate
  change, or persistent non-test engagement DB mutation changed.
  Handoff: `.claude/handoffs/2026-07-20-manifest-local-source-label.md`.

- [x] Local public metadata source-label checkpoint is green:
  Local/top-level `assetlinks.json`, `browserconfig.xml`, `jwks.json`,
  `mta-sts.txt`, and `security.txt` artifacts now keep source-aware
  `metadata_json.format` labels instead of generic suffix labels while
  preserving existing recursive URL/email/cloud extraction.
  Verification: compile/Ruff for touched orchestrator/helper and validation
  tests; focused public metadata label test -> `1 passed`; adjacent
  helper/static classification plus validation object-filter suite -> `33
  passed`; adjacent orchestrator metadata selector -> `21 passed, 738
  deselected`; cleanup check found no new pytest engagement DBs.
  Review: explorer `Pascal` independently identified the direct local
  `jwks.json` suffix-label gap, which is included in this checkpoint.
  Safety: exact local artifact metadata labeling only. No new route discovery,
  live probing, provider call, scope relaxation, proxy/IP rotation,
  rate-limit bypass, validation/report-gate change, or persistent non-test
  engagement DB mutation changed.
  Handoff: `.claude/handoffs/2026-07-20-public-metadata-labels.md`.

- [x] Apple merchant domain-association metadata recursion checkpoint is green:
  `/.well-known/apple-developer-merchantid-domain-association` now routes as a
  first-class passive config artifact with source-aware format/cache labels,
  matching the storage false-positive metadata treatment already used for this
  public ownership-proof file. A focused DB-backed regression proves discovered
  Apple merchant metadata can feed recursive URL/email/cloud pivots through the
  artifact queue.
  Verification: compile/Ruff for touched orchestrator/helper and validation
  tests; focused Apple merchant metadata tests -> `2 passed`; adjacent
  helper/static classification plus validation object-filter suite -> `32
  passed`; adjacent `.well-known`/Matrix/merchant orchestrator selector -> `4
  passed, 755 deselected`; cleanup check found no new pytest engagement DBs.
  Safety: passive static domain-verification metadata routing only. No Apple Pay
  validation, merchant validation request, authentication, provider call, scope
  relaxation, proxy/IP rotation, rate-limit bypass, validation/report-gate
  change, or persistent non-test engagement DB mutation changed.
  Handoff: `.claude/handoffs/2026-07-20-apple-merchant-well-known-recursion.md`.

- [x] Matrix client well-known metadata recursion checkpoint is green:
  `/.well-known/matrix/client` now routes as a first-class passive config
  artifact with `matrix-client` format/cache labels, matching the existing
  Matrix server route and storage false-positive metadata treatment. A focused
  DB-backed regression proves Matrix homeserver and identity-server URLs,
  contact email, and Supabase refs feed recursive URL/email/cloud pivots through
  the artifact queue.
  Verification: compile/Ruff for touched orchestrator/helper tests; focused
  Matrix metadata tests -> `2 passed`; adjacent helper/static classification
  suite -> `26 passed`; adjacent `.well-known`/Matrix orchestrator selector ->
  `4 passed, 755 deselected`; cleanup check found no new pytest engagement DBs.
  Safety: passive static metadata routing only. No Matrix federation call,
  homeserver probing, authentication, provider call, scope relaxation, proxy/IP
  rotation, rate-limit bypass, validation/report-gate change, or persistent
  non-test engagement DB mutation changed.
  Handoff: `.claude/handoffs/2026-07-20-matrix-client-well-known-recursion.md`.

- [x] OIDC claim contact and userinfo recursion checkpoint is green:
  Epieos/userinfo-style `claims.email`, `claims.phone_number`,
  `userinfo.email`, `userinfo.phone_number`, `userinfo.profile`, and
  `userinfo.website` now stay on the existing provider row as recursive
  contact/URL evidence instead of being dropped or becoming a fake `userinfo`
  platform row. Token/scalar claims such as `access_token` and `sub` remain
  suppressed.
  Verification: compile/Ruff for touched social parser/tests; full Phase 2
  social scraper suite -> `79 passed`; Phase 1 social-profile recursion selector
  -> `80 passed, 679 deselected`; cleanup check found no new pytest engagement
  DBs.
  Review: explorer `Kierkegaard` identified the `userinfo` gap.
  Safety: passive parser-only identity enrichment. No provider calls,
  userinfo/JWKS fetches, token validation, live probing, scope relaxation,
  generic claim flattening, proxy/IP rotation, rate-limit bypass,
  validation/report-gate change, or persistent non-test engagement DB mutation
  changed.
  Handoff: `.claude/handoffs/2026-07-20-oidc-userinfo-claim-contact-recursion.md`.

- [x] OIDC claim URL recursion checkpoint is green:
  Epieos/userinfo-style nested `claims.profile` and `claims.website` values now
  stay on the existing provider row as recursive URL evidence instead of being
  dropped. The parser does not create a separate `claims` platform row and does
  not persist scalar/token claims such as `sub` or `access_token` as URL
  evidence.
  Verification: compile/Ruff for touched social parser/tests; full Phase 2
  social scraper suite -> `78 passed`; Phase 1 social-profile recursion selector
  -> `80 passed, 679 deselected`; cleanup check found no new pytest engagement
  DBs.
  Review: explorer `Euclid` identified the gap.
  Safety: passive parser-only identity enrichment. No provider calls,
  userinfo/JWKS fetches, token validation, live probing, scope relaxation,
  generic claim flattening, proxy/IP rotation, rate-limit bypass,
  validation/report-gate change, or persistent non-test engagement DB mutation
  changed.
  Handoff: `.claude/handoffs/2026-07-20-oidc-claim-url-recursion.md`.

- [x] Nested StackExchange user-profile recursion checkpoint is green:
  Provider-scoped Epieos StackExchange/StackOverflow `user` payloads now become
  safe public profile pivots when they include a numeric `user_id`, a normalized
  handle, and either no site override or an accepted StackExchange network host.
  Invalid site hints such as `not-stackexchange.example` are rejected instead of
  defaulting to fake StackOverflow URLs. Pure payload shaping lives in
  `forge/utils/intel/social_profile_hosts.py`; `social_scraper.py` only adapts it
  through the existing handle/profile parser.
  Verification: compile/Ruff for touched identity parser/helper files; Phase 2
  social helper/scraper suite -> `84 passed`; Phase 1 social-profile recursion
  selector -> `80 passed, 679 deselected`; cleanup check found no new pytest
  engagement DBs.
  Safety: passive provider-payload normalization only. No provider calls, live
  probing, auth, scope relaxation, generic nested-user flattening,
  validation/report-gate change, rate-limit bypass, proxy/IP rotation, or
  persistent non-test engagement DB mutation changed.
  Handoff: `.claude/handoffs/2026-07-20-stackexchange-nested-user-profile.md`.

- [x] Helm index absolute chart URL recursion checkpoint is green:
  Helm `index.yaml` parsing now preserves safe absolute HTTP(S) chart archive URLs in `entries[].urls[]` in addition to relative chart paths, so authorized chart indexes that point at CDN/object-storage `.tgz` / `.tar.gz` packages feed recursive artifact URL pivots instead of being silently dropped. Unsafe values remain suppressed: protocol-relative URLs, non-HTTP(S) schemes, non-chart suffixes, templated strings, userinfo-bearing URLs, localhost, and private/reserved IP hosts.
  Verification: compile/Ruff for touched Helm parser/tests; focused Helm index suite -> `4 passed`; adjacent artifact helper/API-client/HTTP/package-manager/Helm suite -> `64 passed`; cleanup check found no new pytest engagement DBs.
  Review: subagent `Singer` identified the missed absolute chart URL gap.
  Safety: passive static Helm index parsing only. No Helm execution, chart download, provider call, live probing expansion, credential use, scope relaxation, rate-limit bypass, proxy/IP rotation, validation/report-gate change, or persistent non-test engagement DB mutation changed.
  Handoff: `.claude/handoffs/2026-07-20-helm-index-absolute-chart-urls.md`.

- [x] Remote mobile-bundle regression modularization checkpoint is green:
  XAPK, APKM, and APKS seed-URL dry-run kill-chain regressions now share a compact focused helper in `tests/phase1/remote_artifact_download_cases.py`, with original mega-test node IDs retained as thin wrappers. This removes 430 more inline lines from `tests/phase1/test_engagement_orchestrator.py` while preserving local-only kill-chain coverage for queued remote mobile bundles, nested APK static extraction, Firebase/Supabase cloud asset recursion, derived seed relations, and recursive email/URL seed creation.
  Verification: compile/Ruff for touched Phase 1 files; remote mobile-bundle wrapper set -> `3 passed`; cleanup check found no new pytest engagement DBs.
  Safety: test modularization only. No production mobile parsing behavior, live probing, provider calls, credential use, scope changes, validation/report gates, or persistent non-test engagement DB mutation changed.
  Handoff: `.claude/handoffs/2026-07-20-remote-mobile-bundle-test-modularization.md`.

- [x] Remote artifact download regression modularization checkpoint is green:
  Rate-limited remote artifact retry/backoff, extensionless remote image filename inference from `Content-Disposition`, and extensionless AVIF content-type inference moved into focused `tests/phase1/remote_artifact_download_cases.py`, with original mega-test node IDs retained as thin wrappers. This removes 268 more inline lines from `tests/phase1/test_engagement_orchestrator.py` while preserving local-only remote artifact coverage for respectful `Retry-After` pacing, OCR payload recursion, downloaded filename metadata, image format detection, and recursive email/URL seed extraction.
  Verification: compile/Ruff for touched Phase 1 files; remote-download wrapper set -> `4 passed`; cleanup check found no new pytest engagement DBs.
  Safety: test modularization only. No production downloader behavior, live probing, provider calls, credential use, scope changes, pacing/backoff behavior, report gates, or persistent non-test engagement DB mutation changed.
  Handoff: `.claude/handoffs/2026-07-20-remote-artifact-download-test-modularization.md`.

- [x] Remote artifact download and CodeBuild regression modularization checkpoint is green:
  Extensionless remote DEX content-type download recursion moved into focused `tests/phase1/remote_artifact_download_cases.py`, and the inline CodeBuild buildspec secret/reference regression moved into `tests/phase1/ci_workflow_artifact_cases.py`; original mega-test node IDs remain thin wrappers. This removes 231 more inline lines from `tests/phase1/test_engagement_orchestrator.py` while preserving artifact-analysis coverage for remote binary content-type inference, provenance, recursive email/URL/cloud assets, CodeBuild Parameter Store/Secrets Manager refs, ECR URL pivots, Firebase refs, and S3 refs.
  Verification: compile/Ruff for touched Phase 1 files; focused DEX+CodeBuild wrappers -> `2 passed`; adjacent CI workflow wrappers -> `4 passed`; cleanup check found no new pytest engagement DBs.
  Review: subagent `Socrates` identified the CI block; only the inline CodeBuild case was moved because the other CI tests were already shims.
  Safety: test modularization only. No production parser behavior, live probing, provider calls, credential use, scope changes, report-gate behavior, or persistent non-test engagement DB mutation changed.
  Handoff: `.claude/handoffs/2026-07-20-remote-artifact-codebuild-test-modularization.md`.

- [x] Cloud-validation key-runtime regression split checkpoint is green:
  Basic `run_cloud_validate` persistence, rate-limit preflight, key scope denial, scheduled scope-manifest denial, and unsupported-key regressions moved from the Phase 4 mega validation suite into focused `tests/phase4/test_cloud_validation_key_runtime.py` (12KB), removing 311 more lines from `tests/phase4/test_cloud_validate.py` without runtime behavior changes.
  Verification: compile/Ruff for touched validation test files; focused runtime/split files -> `10 passed`; adjacent Stripe sweep slice -> `4 passed`; full cloud-validation suite including all split files and managed-hosting reachability -> `145 passed`; cleanup check found no new pytest engagement DBs.
  Safety: test-only refactor. No provider calls, live probing, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, deterministic severity change, validation-gate change, or report-gate change.
  Handoff: `.claude/handoffs/2026-07-20-cloud-validation-key-runtime-test-split.md`.

- [x] Cloud-validation object-filter regression split checkpoint is green:
  Pure static-site, repository-metadata, filesystem-metadata, and API-documentation object-name filter regressions moved from the Phase 4 mega validation suite into focused `tests/phase4/test_cloud_validation_object_filters.py` (15KB), removing 304 more lines from `tests/phase4/test_cloud_validate.py` without runtime behavior changes.
  Verification: compile/Ruff for touched validation test files; focused split files -> `5 passed`; full cloud-validation suite including both split files and managed-hosting reachability -> `145 passed`; cleanup check found no new pytest engagement DBs.
  Safety: test-only refactor. No provider calls, live probing, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, deterministic severity change, validation-gate change, or report-gate change.
  Handoff: `.claude/handoffs/2026-07-20-cloud-validation-object-filter-test-split.md`.

- [x] Cloud-validation identifier regression split checkpoint is green:
  The pure `_validated_identifier_from_detail` low-signal proof regression moved from the Phase 4 mega validation suite into focused `tests/phase4/test_cloud_validation_identifiers.py` (26KB), removing 623 lines from `tests/phase4/test_cloud_validate.py` without runtime behavior changes.
  Verification: compile/Ruff for touched test files; focused identifier test -> `1 passed`; adjacent proof/sweep slice -> `3 passed`; full cloud-validation suite including managed-hosting reachability -> `145 passed`; cleanup check found no new pytest engagement DBs.
  Review: Claude read-only next-gap audit was attempted and hit `max turns (5)` without usable findings.
  Safety: test-only refactor. No provider calls, live probing, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, deterministic severity change, validation-gate change, or report-gate change.
  Handoff: `.claude/handoffs/2026-07-20-cloud-validation-identifier-test-split.md`.

- [x] Managed-hosting empty-HEAD proof checkpoint is green:
  Managed-hosting reachability validators now follow an empty successful `HEAD` with one paced read-only `GET` before deciding `ACCESSIBLE_BUT_NO_DATA`, so placeholder/synthetic Vercel, Netlify, Cloudflare Pages/Workers, R2, and similar managed-hosting bodies cannot be missed just because `HEAD` returned no body. Body-bearing `HEAD` responses still avoid the extra `GET`.
  Verification: compile/Ruff for touched validator/test files; focused managed-hosting tests -> `2 passed`; adjacent direct/batch/sweep managed-hosting tests -> `4 passed`; cleanup check found no new pytest engagement DBs.
  Safety: validation proof hardening only. No credential use, provider expansion, write operation, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate weakening.
  Handoff: `.claude/handoffs/2026-07-20-managed-hosting-empty-head-proof.md`.

- [x] Framework service-endpoint artifact recursion checkpoint is green:
  Source-aware framework configs now extract sanitized Redis, Celery/AMQP, Kafka, Elasticsearch, OpenSearch, and Memcached endpoint payloads from static host/url fields, including `REDIS_HOST`, `spring.data.redis.url`, `CELERY_BROKER_HOST`, `kafka.bootstrap-servers`, and `ELASTICSEARCH_HOSTS`. These feed recursive host seeds without preserving credentials or template placeholders; bare framework `host:port` values now normalize to host-only candidates.
  Verification: compile/Ruff for touched framework/orchestrator/test files; focused framework/client-config worker tests -> `5 passed`; adjacent orchestrator framework/network selector -> `3 passed, 756 deselected`; cleanup check found no new pytest engagement DBs.
  Review: Claude CLI was attempted; `-k` is unsupported in this local build and `--print` timed out, so local tests are the evidence.
  Safety: passive static parser coverage only. No service connection, credential use, provider call, live probing, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change.
  Handoff: `.claude/handoffs/2026-07-20-framework-service-endpoints.md`.

- [x] Remote/static artifact classification helper-test split checkpoint is green:
  Package/archive, safe download metadata, firmware/binary dump, browser-profile, Git metadata, OAuth well-known, model, JVM, keystore, certificate, dump, calendar, and vCard classification regressions moved from `tests/phase1/test_artifact_helpers.py` into focused `tests/phase1/test_artifact_remote_static_classification.py` (242 lines). The broad helper file dropped from 446 to 214 lines.
  Verification: compile/Ruff for touched helper/API/static test files; focused static classification suite -> `16 passed`; remaining artifact helper suite -> `8 passed`; combined helper/API/Electron/static slice -> `29 passed`.
  Safety: test-only refactor. No runtime behavior change, provider calls, live probing, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change.
  Handoff: `.claude/handoffs/2026-07-20-remote-static-classification-test-split.md`.

- [x] API artifact format-label helper-test split checkpoint is green:
  The large API spec/client collection content-type and artifact-label regression moved from `tests/phase1/test_artifact_helpers.py` into focused `tests/phase1/test_artifact_api_format_labels.py` (209 lines). The broad helper file dropped from 647 to 446 lines.
  Verification: compile/Ruff for touched helper/API/Pact test files; focused API label test -> `1 passed`; remaining artifact helper suite -> `24 passed`; adjacent API-client/Pact suite -> `7 passed`.
  Safety: test-only refactor. No runtime behavior change, provider calls, live probing, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change.
  Handoff: `.claude/handoffs/2026-07-20-api-format-label-test-split.md`.

- [x] Electron update metadata helper-test split checkpoint is green:
  Four Electron update metadata / ASAR helper regressions moved from `tests/phase1/test_artifact_helpers.py` into focused `tests/phase1/test_artifact_electron_update_metadata.py` (87 lines). The broad helper file dropped from 726 to 647 lines, and queue-backed Electron recursion coverage remains in `tests/phase1/test_artifact_electron_update_metadata_queue.py`.
  Verification: compile/Ruff for touched helper/Electron test files; focused Electron helper plus queue tests -> `5 passed`; remaining artifact helper suite -> `25 passed`.
  Safety: test-only refactor. No runtime behavior change, provider calls, live probing, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change.
  Handoff: `.claude/handoffs/2026-07-20-electron-helper-test-split.md`.

- [x] Pact protocol-relative endpoint coverage checkpoint is green:
  Focused coverage now proves Pact contract `provider.baseUrl`, `request.url`, and URL-ish provider-state callback fields such as `//pact-provider.acme.example/api`, `//pact-cdn.acme.example/v1/status`, and `//pact-callback.acme.example/hook` normalize to `https://...` recursive URL pivots through the artifact processor path.
  Verification: compile/Ruff for touched Pact helper/orchestrator/test files; focused Pact test -> `1 passed`; adjacent API-client worker suite -> `6 passed`; existing orchestrator Pact selector -> `3 passed, 756 deselected`.
  Review: subagent `Anscombe` found the missing regression; Claude CLI review found the initial provider-base fixture was bare host+path rather than protocol-relative, and the fixture/docs were corrected.
  Safety: passive parser/test coverage only. No provider calls, Pact broker calls, live probing, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change.
  Handoff: `.claude/handoffs/2026-07-20-pact-protocol-relative-endpoints.md`.

- [x] Social profile colon-scheme host guard checkpoint is green:
  Scheme-less profile host fallback now requires an empty parsed URL scheme, so `github.com/acme` and `//github.com/acme` still match known hosts while colon-scheme identifiers such as `mailto:alice@github.com`, `urn:github:alice`, and `github:alice` no longer become fake profile hosts.
  Verification: compile/Ruff for touched host helper/tests; focused host/alias/app-link suite -> `11 passed`; full adjacent social scraper suite -> `87 passed`; direct host-match probe confirmed the boundary.
  Safety: passive identity host-guard hardening only. No provider calls, live probing, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change.
  Handoff: `.claude/handoffs/2026-07-20-social-profile-colon-scheme-host-guard.md`.

- [x] LinkedIn non-web alias fallback checkpoint is green:
  Epieos LinkedIn parser now ignores non-web explicit profile aliases such as `urn:li:fsd_profile:alice-example` and falls back to valid `publicIdentifier` / handle reconstruction. HTTP(S) and scheme-less web host mismatches such as `https://notlinkedin.com/in/alice` still block fallback.
  Verification: compile/Ruff for touched parser/test files; focused alias/app-link suite -> `6 passed`; full adjacent social scraper suite -> `82 passed`; direct parser probe confirmed `urn:li` and `linkedin://` fallback while HTTP and scheme-less host mismatches stay blocked.
  Review: explorer `Mencius` found the gap.
  Safety: passive parser-only identity normalization. No network, provider call, auth probing, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change.
  Handoff: `.claude/handoffs/2026-07-20-linkedin-non-web-alias-fallback.md`.

- [x] Remote-access artifact test split checkpoint is green:
  RDP/Citrix static artifact recursion coverage moved out of the Phase 1 mega test into focused `tests/phase1/test_artifact_remote_access.py` (134 lines). The regression still proves `.rdp` and `.ica` local artifacts plus remote content-type classification feed emails, URL seeds, host/subdomain/domain pivots, Firebase/Supabase/S3/GCS cloud assets, and artifact format metadata without executing remote-access clients.
  Verification: compile/Ruff for the focused and mega tests; focused remote-access test -> `1 passed`; adjacent artifact helper/connection-client suites -> `68 passed`.
  Safety: test-only refactor. No runtime behavior change, RDP/Citrix execution, authentication, provider call, live probing, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change.
  Handoff: `.claude/handoffs/2026-07-20-remote-access-artifact-test-split.md`.

- [x] Scheme-less social profile URL recursion checkpoint is green:
  Epieos/social profile host guards now accept known profile URLs without a scheme, such as `github.com/acmeops` and `www.github.com/acmeops`. Provider payloads with scheme-less `profileUrl` values now preserve platform aliases and recursive handle pivots instead of being rejected by host matching.
  Verification: compile/Ruff for touched helper/focused parser tests; focused helper/parser/social scraper suite -> `83 passed`.
  Review: explorer `Linnaeus` found the gap.
  Safety: passive identity parsing only. No provider calls, live probing, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change.
  Handoff: `.claude/handoffs/2026-07-20-scheme-less-profile-url-recursion.md`.

- [x] Remmina connection-profile passive-recursion checkpoint is green:
  `.remmina` profiles now keep source-aware `remmina-config` labels, remote `.remmina` URLs enter artifact recursion, and Remmina host fields such as `server=rdp.acme.example:3389` plus `ssh_tunnel_server=bastion.acme.example` produce normalized recursive host seeds without port suffixes. Existing connection-client parsing still extracts owner emails, dashboard URLs, and Firebase refs through the passive artifact path.
  Verification: compile/Ruff for touched helper/focused tests; full connection-client artifact suite -> `39 passed`.
  Safety: passive static connection-profile parsing only. No Remmina execution, RDP/SSH connection, authentication, credential use, provider calls, live probing, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change.
  Handoff: `.claude/handoffs/2026-07-20-remmina-connection-profile-recursion.md`.

- [x] Gradle wrapper properties passive-recursion checkpoint is green:
  `gradle-wrapper.properties` now keeps source-aware `gradle-wrapper-properties` format and static `distributionUrl=...` / repository URL properties feed sanitized recursive URL seeds, including escaped Gradle schemes such as `https\://...`. Remote wrapper downloads preserve source labels; owner emails and Firebase refs still flow through the existing passive artifact path; sensitive URL query values stay out of persisted DB text.
  Verification: compile/Ruff for touched helper/orchestrator/focused tests; focused Gradle config suite -> `12 passed`; adjacent JVM/Maven/Gradle orchestrator selector -> `3 passed, 757 deselected`.
  Safety: passive static Gradle properties parsing only. No Gradle wrapper execution, dependency download, repository authentication, provider calls, live probing, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change.
  Handoff: `.claude/handoffs/2026-07-20-gradle-wrapper-properties-recursion.md`.

- [x] Pixi/Conda environment passive-recursion checkpoint is green:
  Exact `pixi.toml`, `pixi.lock`, `environment.yml`, `environment.yaml`, `conda-lock.yml`, and `conda-lock.yaml` artifacts now keep source-aware `pixi-manifest`, `pixi-lock`, `conda-environment`, and `conda-lock` formats instead of generic extension labels. Package/channel URLs and owner emails still recurse into engagement seeds, while embedded URL credentials stay out of persisted DB text. Broad lookalikes such as `runtime-environment.yml` and `pixi-notes.toml` remain generic.
  Verification: compile/Ruff for touched helper/orchestrator tests; focused package-manager config suite -> `45 passed`; existing Conda/package-index orchestrator selector -> `2 passed, 758 deselected`; direct classifier probe confirmed exact labels and generic lookalikes.
  Safety: passive static package-manager/environment parsing only. No Pixi/Conda execution, package install/lock use, channel authentication, provider calls, live probing, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change.
  Handoff: `.claude/handoffs/2026-07-20-pixi-conda-environment-recursion.md`.

- [x] Conda/Mamba config passive-recursion checkpoint is green:
  `.condarc`, `condarc`, `.mambarc`, `mambarc`, and cached remote `*.conda-config` / `*.mamba-config` artifacts now keep source-aware `conda-config` / `mamba-config` formats instead of generic basename labels. Channel URLs and owner emails still recurse into engagement seeds, while embedded channel credentials stay out of persisted DB text.
  Verification: compile/Ruff for touched helper/orchestrator tests; focused package-manager config suite -> `35 passed`; existing Conda/package-index orchestrator selector -> `2 passed, 758 deselected`.
  Safety: passive static package-manager config parsing only. No Conda/Mamba execution, package install/restore, channel authentication, provider calls, live probing, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change.
  Handoff: `.claude/handoffs/2026-07-20-conda-mamba-config-recursion.md`.

- [x] NuGet config passive-recursion checkpoint is green:
  `nuget.config`, `.nuget/NuGet.Config`, and cached remote `*.nuget-config` artifacts now keep a source-aware `nuget-config` format instead of generic `config`. Package feed URLs and owner emails still recurse into engagement seeds, while cleartext package-source passwords stay out of persisted DB text. Remote `.nuget/NuGet.Config` sources keep the NuGet filename for artifact review.
  Verification: compile/Ruff for touched helper/orchestrator tests; focused package-manager config suite -> `27 passed`; existing engagement-backed package-manager/NuGet selector -> `2 passed, 758 deselected`.
  Safety: passive static package-manager config parsing only. No NuGet client execution, package restore, feed authentication, provider calls, live probing, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change.
  Handoff: `.claude/handoffs/2026-07-20-nuget-config-recursion.md`.

- [x] OpenAI-compatible report-provider normalization checkpoint is green:
  OpenAI-compatible chat responses now accept block-style `message.content` arrays by concatenating text/output_text blocks while fail-closing when no text blocks exist. Phase 6 direct and auto `openai_compatible` provider construction now passes `model=` instead of invalid `model_id=`.
  Verification: compile/Ruff for touched provider/report/test files; focused OpenAI-compatible plus Phase 6 report synthesizer suite -> `113 passed`; adjacent providers suite -> `161 passed`.
  Review: explorer `Nietzsche` found the gap and constructor mismatch.
  Safety: report-provider parsing/configuration only. No provider endpoint expansion, automatic provider calls, credential use, live probing, scope relaxation, proxy/IP rotation, rate-limit bypass, deterministic severity change, or report-gate weakening.
  Handoff: `.claude/handoffs/2026-07-20-openai-compatible-block-content.md`.

- [x] Visio package passive-recursion checkpoint is green:
  `.vsdx`, `.vsdm`, `.vstx`, `.vstm`, `.vssx`, and `.vssm` now enter the existing zip-backed document parser, so Visio architecture diagrams can passively extract XML text, relationship targets, owner emails, URLs, Firebase/Supabase refs, and cloud pivots into recursive seeds/assets. Visio content types now select Visio suffixes for extensionless remote artifacts.
  Verification: compile/Ruff for touched orchestrator/test files; focused Visio suite -> `2 passed`; full artifact helper suite -> `29 passed`; adjacent document/diagram/OpenDocument/EPUB artifact slice -> `4 passed`.
  Safety: passive static ZIP/XML parsing only. No Visio rendering, macro execution, Office automation, provider calls, credential use, live probing, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change.
  Handoff: `.claude/handoffs/2026-07-20-visio-package-recursion.md`.
  Next concrete task from explorer `Nietzsche`: OpenAI-compatible provider normalization for block-style chat content plus Phase 6 provider-load smoke.

- [x] Social profile URL-valued handle recursion checkpoint is green:
  Direct profile handle fields such as `handle`, `username`, and `custom_url` now fall back to the existing social profile URL parser when bare handle normalization fails, so provider payloads like `{"handle": "https://www.youtube.com/@acmeops"}` and `{"username": "https://github.com/acmeops"}` produce recursive username seeds. Reserved routes such as GitHub settings pages and YouTube feeds remain filtered by the existing platform guards.
  Verification: compile/Ruff for touched orchestrator/test files; focused URL-valued handle suite -> `2 passed`; full social profile URL parser suite -> `16 passed`; adjacent orchestrator social-handle selector -> `3 passed, 757 deselected`.
  Review: sidecar `Descartes` found the gap. Claude CLI retry reached `max turns (4)` without usable findings.
  Safety: passive identity synthesis only. No provider calls, live probing, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change.
  Handoff: `.claude/handoffs/2026-07-20-social-profile-url-valued-handles.md`.

- [x] Helm index relative chart recursion checkpoint is green:
  Remote/source-gated Helm `index.yaml` / `index.yml` payloads with Helm index shape now resolve relative chart package URLs such as `charts/api-1.2.3.tgz` and `../archive/api-1.2.3.tar.gz` against the index URL, feeding those chart archives into the existing recursive URL/artifact path. Absolute URLs remain handled by existing direct URL parsing; templated, non-chart, non-Helm, local-base, userinfo, and non-HTTP values stay suppressed.
  Verification: compile/Ruff for touched orchestrator/helper/test files; focused Helm index suite -> `4 passed`; adjacent artifact helper/API-client/HTTP-request slice -> `40 passed`; broader structured-discovery selector -> `4 passed, 756 deselected`.
  Review: sidecar `Locke` found the gap.
  Safety: passive static parsing only. No Helm execution, chart install, repository fetch beyond existing scoped artifact download behavior, provider call, live probing expansion, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change.
  Handoff: `.claude/handoffs/2026-07-20-helm-index-chart-recursion.md`.

- [x] Epieos envelope regression hardening checkpoint is green:
  List-valued provider envelopes such as `github.result[]` now preserve the outer provider context, and nested account wrappers no longer duplicate identical platform/profile rows.
  Verification: compile/Ruff for touched parser/test files; targeted envelope regressions -> `3 passed, 73 deselected`; full social scraper suite -> `76 passed`; focused Epieos synthesis slice -> `10 passed, 751 deselected`.
  Review: sidecar `Lovelace` found both regressions after the prior checkpoint.
  Safety: passive parser hardening only. No provider calls, live probing, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change.
  Handoff: `.claude/handoffs/2026-07-20-epieos-envelope-regression-hardening.md`.

- [x] Epieos platform-envelope recursion checkpoint is green:
  Platform-scoped Epieos envelopes such as `github.result.profileUrl` now preserve the outer provider context instead of becoming fake `result` platforms or being dropped. Parsed rows retain recursive username, email, URL, subdomain, and root-domain pivots for synthesis, while direct provider/org payloads still reconstruct their existing profile URLs.
  Verification: compile/Ruff for touched parser/test files; full social scraper suite -> `74 passed`; focused Epieos synthesis slice including the new focused Phase 1 file -> `10 passed, 751 deselected`; direct parser probe confirmed the payload parses as a GitHub row with `envelopedops`, `ops@acme.example`, and `https://ops.acme.example`.
  Review: explorer `Franklin` recommended the focused Phase 1 synthesis regression. Claude CLI retry reached `max turns (8)` without usable findings.
  Safety: passive identity parsing/synthesis only. No Epieos provider call expansion, live probing, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change.
  Handoff: `.claude/handoffs/2026-07-20-epieos-platform-envelope-recursion.md`.

- [x] Docker-save layer recursion checkpoint is green:
  Passive Docker `docker save` tar archives now parse `manifest.json`, config JSON, and manifest-referenced layer tar members, so `.env`/config content inside referenced layers feeds existing recursive email/URL/cloud discovery. Unreferenced layers remain ignored, and referenced layer tar members may exceed the generic 1 MiB member cap only up to the existing remote artifact cap.
  Verification: compile/Ruff for touched OCI/orchestrator/test files; focused OCI/Docker-save suite -> `2 passed`; adjacent artifact/container/helper suite -> `38 passed`; broader archive/container slice -> `117 passed, 643 deselected`.
  Review: explorer `Heisenberg` found the gap.
  Safety: static archive parsing only. No container execution, image loading, Docker invocation, registry pull/push, provider call, live probing, credential use/validation, scope relaxation, proxy/IP rotation, rate-limit bypass, report-gate change, exploitation, or destructive behavior.
  Handoff: `.claude/handoffs/2026-07-20-docker-save-layer-recursion.md`.

- [x] Bun scope parser stale-value checkpoint is green:
  Passive Bun/Deno JS-runtime config parsing no longer reuses the previous registry candidate when a non-assignment/comment-only line appears inside `[install.scopes]`, preventing duplicate/noisy recursive URL candidates from static `bunfig.toml` artifacts.
  Verification: compile/Ruff for touched parser/test files; focused JS-runtime parser slice -> `2 passed, 759 deselected`.
  Safety: passive static parser correctness only. No Bun/Deno execution, package install, registry access, provider call, live probing, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, report-gate change, exploitation, or destructive behavior.
  Handoff: `.claude/handoffs/2026-07-20-bun-scope-parser-stale-value.md`.

- [x] Validation proof boundary checkpoint is green:
  Proof parsing now rejects bare embedded `; VALIDATED:` fragments inside unverified/free-form notes and only accepts top-level `VALIDATED:<method>:<proof>` or explicit `validation=VALIDATED:<method>:<proof>` evidence fields. Shared compact-placeholder detection now also rejects placeholder+role compounds with short numeric suffixes such as `usr_testuser123` and `ph_testuser123`.
  Verification: compile/Ruff for touched proof/report files; core validation identifier/proof suite -> `116 passed`; full Phase 6 report synthesizer -> `76 passed`; full secret-finder -> `174 passed`; full cloud-validation -> `143 passed`; dashboard proof slice -> `6 passed, 11 deselected`.
  Review: explorer `Nash` found the embedded proof-boundary gap.
  Safety: report-gate/parser hardening only. No provider endpoint expansion, provider-call increase, credential disclosure, live probing expansion, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or deterministic finding weakening.
  Handoff: `.claude/handoffs/2026-07-20-validation-proof-boundaries.md`.

- [x] Orchestration routing-rule worker checkpoint is green:
  `_orchestration_document_url_candidates()` now normalizes routing-rule strings through the existing bounded ordered local worker helper while keeping traversal, caps, dedupe, and appending serial.
  Verification: compile/Ruff for touched orchestrator/test files; focused orchestration worker/helper slice -> `3 passed, 27 deselected`; broad orchestration/parallelization slice -> `278 passed, 482 deselected`.
  Review: explorer `Copernicus` identified the safe worker migration candidate.
  Safety: pure local parsing/prep only. No provider call, DB write, network I/O, validation, live probing, scope relaxation, pacing/backoff change, proxy/IP rotation, rate-limit bypass, report-gate change, exploitation, or destructive behavior.
  Handoff: `.claude/handoffs/2026-07-20-orchestration-routing-worker.md`.

- [x] Vault HCL config passive-recursion checkpoint is green:
  Explicit HashiCorp Vault config artifacts such as `vault/config.hcl`, `.vault.d/config.hcl`, and `vault.hcl` now keep `hashicorp-vault-config` labels and run through a compact helper, `forge/utils/artifact_hashicorp_config.py`. Static endpoint assignments such as `api_addr`, `cluster_addr`, `redirect_addr`, and `VAULT_ADDR` promote public host-only values into recursive HTTPS URL seeds.
  Generic `.hcl`, Consul configs, Terraform policy files, templated values, localhost/IP-only values, wildcards, and userinfo-bearing URLs stay suppressed.
  Verification: compile/Ruff for touched helper/orchestrator/test files; focused Vault artifact suite -> `3 passed`; full artifact helper suite -> `29 passed`; broad structured-discovery slice -> `305 passed, 455 deselected`.
  Safety: passive static parsing only. No Vault execution, token use, authentication, validation, provider call, live probing, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change.
  Handoff: `.claude/handoffs/2026-07-20-vault-hcl-config-recursion.md`.

- [x] Run audit manifest portable-export checkpoint is green:
  `forge.audit.manifest_bundle` writes deterministic ZIP bundles for external archival outside the mutable engagement DB. Bundles contain `manifest.json`, `verification.json`, `checksums.sha256`, and `README.md`; ZIP member order and timestamps are deterministic, and checksums cover the payload files. `forge audit manifest-export --engagement <id> [--run-id <id>] [--output <zip>] [--json]` exports the bundle and exits `2` if export-time verification fails while still preserving a failed verification receipt.
  Optional HMAC signing is available via `--sign --signing-key-env <ENV>`, which writes `signature.json` over canonical payload file checksums without writing the signing key to disk. `forge audit manifest-bundle-verify --bundle <zip> --signing-key-env <ENV>` verifies signed bundles offline without the engagement DB and fails closed for missing keys, malformed signatures, duplicate ZIP entries, unsigned extra files, and signature mismatches.
  The command implementation now lives in `forge/audit/cli.py`, keeping `forge/cli.py` as a thin audit Typer registrar.
  Verification: compile/Ruff over touched audit/CLI/test files; `tests\audit\test_run_audit_manifest_bundle.py tests\audit\test_run_audit_manifest_cli.py tests\audit\test_run_audit_manifest.py` -> `15 passed`; audit help smoke confirmed `manifest-verify`, `manifest-export`, and `manifest-bundle-verify` remain registered.
  Review: Claude read-only review at `%TEMP%\forge-claude-manifest-sign-review.txt` returned only `Reached max turns (4)` with no usable findings.
  Safety: offline evidence export only. No provider calls, live probing, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, report-gate changes, exploitation, persistence, lateral movement, or post-exploitation behavior was added.
  Handoff: `.claude/handoffs/2026-07-20-run-manifest-export-bundle.md`.

- [x] Run audit manifest visibility checkpoint is green:
  `forge/audit/manifest.py` now exposes `summarize_run_audit_manifest()` for dashboard-safe hash/status summaries without returning `manifest_json`. Static dashboard JSON/HTML and live engagement detail/run APIs expose `audit_manifest`; web list/run endpoints default to `not_checked` to avoid repeated artifact hashing, while detail views and `verify_manifests=true` recompute hashes. The React dashboard renders short hash plus verification state, and `forge audit manifest-verify --engagement <id> [--run-id <id>] [--json]` gives operators a manual integrity check.
  Verification: compile/Ruff over touched backend/test files; focused audit/static/API tests -> `19 passed, 40 deselected`; combined focused audit/static/API tests -> `10 passed`; `npm run build` passed; `npm run lint` returned existing hook dependency warnings only.
  Review: the prior explorer recommended the `audit_manifest` contract and no `manifest_json` leakage. Claude retry hit `Reached max turns (5)` with no usable findings.
  Safety: evidence visibility/auditability only. No provider calls, live probing, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, report-gate changes, exploitation, persistence, lateral movement, or post-exploitation behavior was added.
  Handoff: `.claude/handoffs/2026-07-20-run-manifest-visibility.md`.

- [x] Run audit manifest checkpoint is green:
  Completed `EngagementRunTracker.finish_run()` calls now write immutable `run_audit_manifests` rows chained by previous manifest hash. `forge/audit/manifest.py` snapshots root engagement metadata, per-run captured DB row refs/hashes, and bounded report/graph artifact SHA-256 hashes without storing raw rows, secret-shaped columns, arbitrary local paths, or oversized artifact bytes. `verify_run_audit_manifest()` verifies stored manifest JSON integrity and captured-row state without breaking old manifests when later runs append new rows. Canonical schema/migration target is now v21.
  Verification: compile/Ruff over touched backend/test files; focused manifest/schema tests -> `11 passed`; audit hash-chain plus run-manifest tests -> `12 passed`; schema plus full cloud-validation suite -> `146 passed`; distributed/playbook/engagement-pipeline/multi-seed recursive slice -> `33 passed`; tracker-focused orchestrator tests -> `4 passed`.
  Review: Claude first hit `Reached max turns`; the narrower retry was blocked by Anthropic's real-time cyber safeguard for cybersecurity content. Multi-agent explorer `Planck` found five real issues: manifest JSON tamper, old-run invalidation by later rows, missing root engagement metadata coverage, arbitrary artifact path leakage, and pre-commit hook latency. All were fixed with regressions.
  Safety: evidence/auditability only. No provider endpoint expansion, live probing, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, report-gate change, exploitation, persistence, lateral movement, or post-exploitation behavior was added.
  Handoff: `.claude/handoffs/2026-07-20-run-audit-manifest.md`.

- [x] Validation-sweep leasing checkpoint is green:
  Pending key and cloud-asset validation sweeps now claim rows before any provider validation work. `validation_claims` is a canonical schema/migration table with short-lived key/asset leases, stale-lease purge, owner-scoped release, and atomic `BEGIN IMMEDIATE` claim selection. `sweep_pending_cloud_validations()` and `sweep_pending_cloud_asset_validations()` now skip already-claimed rows, preventing parallel workers from selecting the same pending rows and duplicating provider calls before persistence. Claim helpers live in `forge/phase4/validation_claims.py` to keep `cloud_validate.py` as a thin orchestration caller.
  Verification: compile/Ruff over schema, cloud validation, claim helpers, and tests; schema plus full cloud-validation suite -> `146 passed`; distributed/playbook/engagement-pipeline/multi-seed recursive slice -> `33 passed`.
  Review: Claude still returned `Reached max turns`; explicit Codex GPT model retries were unsupported by the local ChatGPT-backed CLI; default Codex reviewer could not inspect because its Windows sandbox could not launch `pwsh.exe` (`CreateProcessAsUserW failed: 5`). No external code findings were available, so local tests and manual diff review are the evidence.
  Safety: concurrency/audit-state hardening only. No new provider endpoints, live probing expansion, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive validation, report-gate change, exploitation, persistence, lateral movement, or post-exploitation behavior was added.
  Commit: `3eb8b3f fix(cloud): lease pending validation sweeps`.

- [x] Distributed worker claim/shared admission checkpoint is green:
  Distributed task execution now treats Redis/pub-sub messages as wakeups only; workers must atomically claim the matching queued DB row before running a handler. `claim_next()` and message-driven `claim_task()` use a guarded `BEGIN IMMEDIATE` claim by row id, completion/failure only succeeds for the owning running worker, and stale running rows can be requeued by an operator-tunable lease threshold. The distributed `RateLimiter` now uses one Redis Lua admission script, a thread-safe local fallback only when no Redis URL is configured, and fail-closed behavior when Redis is configured but unavailable. Scheduled `run_cloud_validate()` now honors its existing `rate_limit_bucket` / `max_requests_per_minute` before provider validation.
  Verification: compile/Ruff over touched distributed/cloud files; focused new worker/limiter/cloud admission tests -> `9 passed`; broader distributed/playbook/full cloud-validation slice -> `163 passed`.
  Review: sidecar explorer `Pauli` found the duplicate-claim/pub-sub/rate-limit gaps that drove this patch. Claude read-only and diff-only attempts both hit `Reached max turns` with no usable findings.
  Safety: queue/admission control only. No new provider endpoints, live probe expansion, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive validation, report-gate change, or post-exploitation behavior was added.

- [x] Latest kill-chain convergence and multi-seed E2E checkpoint is green:
  `kill_chain()` now preserves capped recursive backlog metadata instead of stopping on stable row counts, discovered GitHub-org keyscan targets use the schema-allowed `cross_reference` seed source with keyscan-origin metadata, and `tests/phase1/test_kill_chain_multiseed_recursive_e2e.py` proves mocked multi-seed recursion through web, Fan-out E, artifact queue, Firebase/Supabase validation, graph export, audit logging, and template report fallback.
  Verification: focused convergence tests -> `3 passed`; keyscan/cloud/report gate plus multi-seed E2E slice -> `7 passed`; broader affected graph/report/cloud suite -> `201 passed`; Ruff over touched kill-chain files -> `All checks passed`.
  Review: Claude diff review found no blockers on the E2E change and noted keyscan validation gating remains covered by adjacent phase4/phase6 tests.
  Commits: `634d44d fix(kill-chain): use valid keyscan seed source`, `de5c183 test(kill-chain): harden recursive multi-seed e2e`.

- [x] Scheduled worker/playbook bounds checkpoint is green:
  Distributed workers now execute task handlers behind `FORGE_TASK_TIMEOUT` with a default 3600s deadline and mark timed-out tasks failed instead of hanging the queue indefinitely. Playbook `_next_steps`, triggered zero-to-DA, triggered RCE hunter, and WAF-evasion recovery now preserve ROE/scope metadata into child scheduled tasks.
  Verification: compile/Ruff over worker/playbook/automation tests; `tests\distributed\test_worker_timeouts.py tests\integration\test_playbooks.py` -> `11 passed`.
  Safety: scheduling/control-plane hardening only. No new live probes, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change.
  Commit: `478d995 fix(distributed): bound scheduled task handlers`.

- [x] Rate-limit safety checkpoint is green:
  `forge/opsec/rate_limiter.py` no longer rotates Tor circuits on HTTP 429 by default. The default behavior is to increase per-domain backoff and wait; Tor rotation requires explicit constructor opt-in for legacy tooling.
  Follow-up compatibility fix preserves the old positional `AdaptiveRateLimiter(..., adjustment_factor)` call shape.
  Verification: compile/Ruff over rate-limiter files; focused rate-limiter/playbook tests -> `4 passed`; focused rate-limiter file after compatibility fix -> `4 passed`.
  Safety: closes implicit IP-rotation behavior. No proxy/IP bypass, live probing expansion, scope relaxation, destructive behavior, or report-gate change.
  Commits: `bc95829 fix(opsec): avoid implicit tor rotation on rate limits`, `05aee28 fix(opsec): preserve adaptive limiter argument order`.

- [x] Validation-registry terminal-state checkpoint is green:
  Pending cloud-asset sweeps no longer filter to a fixed allowlist. Every persisted artifact-emitted cloud asset either uses a registered validator or receives an explicit terminal `UNSUPPORTED` row, so references do not remain pending/UNVALIDATED forever.
  Verification: compile/Ruff over `forge\phase4\cloud_validate.py` and `tests\phase4\test_cloud_validation_registry_contract.py`; `tests\phase4\test_cloud_validation_registry_contract.py tests\phase4\test_cloud_validate.py` -> `140 passed`.
  Safety: validation-state/auditability hardening only. Unsupported types do not trigger provider calls and do not create deterministic findings.
  Commit: `4955108 fix(cloud-validation): terminate unsupported asset types`.

- [x] Artifact helper test split checkpoint is green:
  25 pure artifact helper/classification tests moved out of `tests\phase1\test_engagement_orchestrator.py` into `tests\phase1\test_artifact_helpers.py`, reducing the mega test to `89644` lines while keeping the new focused file at `560` lines.
  Verification: compile/Ruff over both test files; `tests\phase1\test_artifact_helpers.py` -> `25 passed`.
  Safety: test-only refactor. No runtime behavior change.
  Commit: `2b84b3f refactor(tests): split artifact helper tests`.

- [x] Kill-chain recursion-budget parity checkpoint is green:
  CLI and web launch paths now share `normalize_kill_chain_max_iter()` and reject `max_iter < 1` or `> 10` before starting a run, closing the direct CLI bypass of the web launch budget.
  Verification: compile/Ruff over CLI/web/helper/tests; focused CLI range/help tests -> `2 passed`; focused web launch/range tests -> `2 passed`.
  Safety: option validation only. No fan-out expansion, provider calls, live probing, scope relaxation, proxy/IP rotation, rate-limit bypass, or report-gate change.
  Commit: `24306e1 fix(kill-chain): enforce recursion budget parity`.
  Follow-up drift repair restored the shared helper cap to `1..10`, aligned CLI help/defaults to `7`/`10`, and kept `--go-hard` as the explicit `20`-iteration override.

- [x] Package-manager config source-label checkpoint is green:
  Source-aware labels now distinguish `.npmrc`, `.pnpmrc`, `.yarnrc`, `.pypirc`, `.gemrc`, `.netrc`, pip configs, and `.cargo` configs/credentials from generic `ini`/`toml`/`credentials` artifacts. Generic `credentials` and `config.toml` stay unclassified unless package-manager source context is present.
  Verification in `main`: compile/Ruff over touched files; `tests\phase1\test_artifact_package_manager_config.py` -> `24 passed`; cargo mega regression -> `1 passed`; pip credential mega regression -> `1 passed`.
  Review: worker `Dirac` implemented and verified the slice in `FORGE-wt-package-labels` before cherry-pick. Commit: `6329b0f feat(artifacts): label package manager configs`.
  Safety: passive source labeling and artifact routing only. No package-manager execution, registry calls, credential use, live probing, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change.

- [x] Passive QR/barcode artifact-recursion checkpoint is green:
  Raster image artifacts, embedded archive/document image members, rendered PDF page images, and SVG/data-URI image payloads now run a bounded local barcode family alongside OCR/metadata. Optional local decoders (`pyzbar` or OpenCV) are declared in the `artifacts` extra, reported in artifact metadata, and otherwise no-op safely. Decoded payloads feed existing recursive text discovery with sensitive URL query/userinfo stripping; `otpauth://`, `WIFI:`, vCard/MECARD, and common crypto-wallet payloads are suppressed before persistence.
  Verification: compile/Ruff over touched files; `tests\phase1\test_artifact_barcode.py` -> `7 passed`; existing remote image OCR regression -> `1 passed`.
  Review: sidecar `Erdos` identified the missing QR/barcode extraction gap. Claude found dependency/suppression/test gaps in `%TEMP%\forge-claude-barcode-review.txt`; follow-up commit fixed them.
  Safety: passive local parsing only. No QR decode API, provider call, credential validation/use, live probing, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change.
  Commits: `60950ee feat(artifacts): decode passive barcode payloads`, `cf9d055 fix(artifacts): harden barcode extraction defaults`.

- [x] Storage/DB client artifact-recursion checkpoint is green:
  `.s3cfg`, `.boto`, and `boto.cfg` are now source-gated config artifacts with passive endpoint-only extraction in `forge/utils/artifact_storage_client_config.py`; credential keys are suppressed, templated bucket URLs are sanitized before raw discovery, and endpoints feed the existing bounded structured-discovery path. DB client configs now preserve sanitized explicit DSNs and reconstruct split-field endpoints with detected schemes such as `mysql://host:port/db` instead of always emitting `postgres://`; host-only/no-driver configs retain a documented legacy fallback solely for recursive host discovery.
  Verification: compile/Ruff over touched storage/DB/orchestrator/test files; storage helper/processor tests -> `15 passed`; adjacent parser slice -> `71 passed`; DB helper tests -> `22 passed`; selected orchestrator regressions -> `26 passed`.
  Review: sidecar `Bernoulli` identified the missing storage-client parser; sidecar `Chandrasekhar` identified the DB scheme-loss gap. Claude CLI reviews at `%TEMP%\forge-claude-storage-client-review.txt` and `%TEMP%\forge-claude-db-client-review.txt` returned only `Reached max turns (4)` with no usable findings.
  Safety: passive static parsing only. No DB connections, provider calls, credential use, live probing expansion, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change.
  Commits pushed to `main`: `a13c683 feat(kill-chain): parse storage client config endpoints`, `1d29b47 fix(kill-chain): preserve database client endpoint schemes`.

- [x] Test mega-file split checkpoint started:
  DB-client and connection-client artifact processor regressions were moved from `tests/phase1/test_engagement_orchestrator.py` into focused feature test files. `tests/phase1/artifact_test_support.py` now owns the shared engagement bootstrap for focused artifact tests. The mega file dropped from about `90496` lines to `90195`; this is not enough by itself, but it establishes the pattern and avoided adding new bulk while implementing kill-chain parser work.
  Verification: compile/Ruff; DB+storage focused tests -> `38 passed`; connection+DB+storage focused tests -> `73 passed`; old mega node lookups correctly fail.
  Commits pushed to `main`: `74caea8 refactor(tests): move database client artifact regression`, `5747249 refactor(tests): move connection client artifact regression`.

- [x] Legacy Firebase/Supabase proof hardening checkpoint is green:
  Bare persisted `VALIDATED:firebase_database_*` details and generic `VALIDATED:supabase_rest_root:Supabase REST endpoint responded successfully.` details now downgrade to `UNVERIFIED`. Explicit live-data wording or linked `cloud_validation_results=VALIDATED` is required before those rows can affect deterministic key findings, Phase 6 exposed-key counts, dashboard validation proof fields, or API-key graph nodes.
  Verification: compile/Ruff over touched parser/report/test files; focused parser/findings/graph/dashboard/report tests -> `86 passed`; `tests\integration\test_engagement_pipeline.py` -> `9 passed`.
  Review: sidecar `Feynman` found the bare legacy proof gap. Claude CLI maintainability review at `%TEMP%\forge-claude-maintainability-review.txt` returned only `Reached max turns (8)`.
  Safety: proof parsing and report/graph gating only. No new provider calls, no live probing expansion, no credential use, no scope relaxation, no proxy/IP rotation, no rate-limit bypass, and no report-gate weakening.
  Commit: `369e852 fix(reporting): require live data legacy cloud proof`.

- [x] Sentry provider-proof hardening checkpoint is green:
  Sentry token validation now stores a stable org id plus a non-private `org_slug_hash`; `parse_validated_detail()` and Phase 4 cloud identifier parsing now require that hash and reject repeated/placeholder hashes before any Sentry key row can drive validated reports, deterministic findings, or graph identifiers.
  Verification: `.venv\Scripts\python.exe -m py_compile forge\utils\intel\secret_finder.py forge\utils\validation_proof.py forge\phase4\cloud_validate.py tests\core\test_validation_proof.py tests\phase2\test_secret_finder.py tests\phase4\test_cloud_validate.py tests\phase1\test_deterministic_findings.py tests\reporting\test_dashboard.py tests\phase1\test_engagement_orchestrator.py`; Ruff over the same files; focused Sentry/dashboard/cloud sweep proof tests -> `12 passed, 237 deselected`; graph integration -> `1 passed`.
  Review: sidecar `Hume` found the original boolean-only Sentry proof promotion gap; sidecar `Maxwell` found a 64-character repeated-hash edge case in Phase 4 parsing; both were fixed. Claude CLI read-only review at `%TEMP%\forge-claude-sentry-proof-review.txt` returned `Reached max turns (4)` with no useful review content.
  Safety: validation proof formatting and report/graph gating only. No new Sentry endpoints, no extra provider calls, no credential use beyond existing validator behavior, no scope relaxation, no proxy/IP rotation, no rate-limit bypass, and no report-gate weakening.
  Commit: `2bd7d0c fix(cloud): require sentry org slug proof hash`.

- [x] CLI URL-with-`@` seed classifier checkpoint is green:
  The `kill-chain` CLI seed classifier now matches the canonical orchestrator order by parsing HTTP(S) URLs before applying the email regex. WebFinger/OIDC/OAuth-style URLs such as `https://acme.example/.well-known/webfinger?resource=acct:alice@acme.example` now persist as `seed_type=url`, do not enter the email table, and remain eligible for URL/artifact recursion paths.
  Verification: TDD regression failed before the fix with `('email',) != ('url',)`; `.venv\Scripts\python.exe -m py_compile forge\cli.py tests\phase1\test_cli_parallel_dispatch.py`; `.venv\Scripts\python.exe -m ruff check forge\cli.py tests\phase1\test_cli_parallel_dispatch.py` -> `All checks passed!`; `.venv\Scripts\python.exe -m pytest tests\phase1\test_cli_parallel_dispatch.py::test_kill_chain_url_seed_with_at_query_stays_url tests\phase1\test_engagement_orchestrator.py::test_kill_chain_discovered_url_seeds_reenter_same_iteration_surface_mining tests\phase1\test_engagement_orchestrator.py::test_kill_chain_passive_text_mining_promotes_robots_and_sitemap_urls_without_live_network -q --color=no -m "slow or not slow"` -> `3 passed`.
  Review: multi-agent explorer `Dewey` found the classifier drift and exact affected code path. Claude CLI review could not be used because the local Claude account's cyber safeguard blocked the read-only review prompt.
  Safety: classifier ordering only. No live probing expansion, provider call expansion, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, report-gate change, or post-exploitation behavior was added.

- [x] Cloudflare D1/KV pending-validation checkpoint is green:
  Discovered `cloudflare_d1` and `cloudflare_kv` assets from Wrangler/Cloudflare config now enter the pending cloud-validation sweep and persist terminal `UNSUPPORTED` rows through the existing registry lookup path. This fixes a kill-chain auditability gap where passive D1/KV references were stored but could remain pending forever because no safe no-auth validator exists.
  Verification: `.venv\Scripts\python.exe -m py_compile forge\phase4\cloud_validate.py tests\phase4\test_cloud_validate.py`; `.venv\Scripts\python.exe -m ruff check forge\phase4\cloud_validate.py tests\phase4\test_cloud_validate.py` -> `All checks passed!`; `.venv\Scripts\python.exe -m pytest tests\phase4\test_cloud_validate.py -k "managed_hosting_assets or pages_managed_hosting_assets" -q --color=no -m "slow or not slow"` -> `1 passed, 138 deselected`.
  Review: Claude CLI read-only review was relaunched at `%TEMP%\forge-claude-killchain-review.txt`; output was not available before this checkpoint.
  Safety: audit-state completion only. No Cloudflare API call, D1 query, KV read, token use, live auth behavior, rate-limit bypass, proxy/IP rotation, scope relaxation, destructive validation, report-gate weakening, or deterministic finding creation was added.

- [x] Latest execution checkpoint is green:
  Kill-chain child module dispatch is bounded by `FORGE_MODULE_SUBPROCESS_TIMEOUT_SECONDS` (default 900s) and returns exit code `124` on timeout. Detected cloud prereq auto-runs inherit `--roe-id`/`--scope-manifest` where applicable, and AWS/Azure have explicit `--yes` for non-interactive auto-run while still requiring ROE. Social host/federated guard logic was extracted to `forge/utils/intel/social_profile_hosts.py`, shrinking `social_scraper.py` by 219 lines. Deterministic key findings, Phase 6 report findings/counts, and attack-graph API-key nodes now require stable `VALIDATED:<method>:<proof>` or linked `cloud_validation_results=VALIDATED`; legacy `Active exposed ...` rows are skipped from reports, stale rows are removed by deterministic synthesis, and raw dashboard key tables still show unverified rows as analyst evidence.
  Verification: CLI scope suite (`32 passed`), social helper/full parser (`75 passed`), identity/social synthesis slice (`101 passed, 710 deselected`), deterministic/cloud/report suites (`226 passed`), Phase 6 suite after aggregate hardening (`74 passed`), attack-path suite (`104 passed`), and engagement pipeline integration (`9 passed`). Commits on `main`: `9f36003 fix(kill-chain): bound live auto-run dispatch`, `3b14494 refactor(identity): extract social profile host guards`.
  Review: OpenAI sidecar `Carver` confirmed the ACTIVE-key report-gating bug and the same minimal patch strategy. Direct Claude CLI review should be retried if needed; earlier background file was absent and previous direct Claude attempts hit local session limits.
  Safety: no IP rotation/rate-limit bypass, destructive exploitation, auth bypass expansion, post-exploitation automation, or report-gate weakening was added.

- [x] HAR + Epieos/social recursive-discovery guard checkpoint is green:
  `forge/utils/artifact_har.py` now owns HAR scalar/content/image helper logic, `tests/phase1/test_artifact_har.py` owns HAR regressions, and HAR files use a bounded 16 MiB parse cap before falling back to generic text extraction. Epieos parsing now handles provider-key arrays and rejects federated identities on known non-federated social/platform hosts; synthesis blocks persisted bad federated accounts from recursive seeding.
  Verification: compile and Ruff passed for touched files; focused regressions passed (`8 passed`); full social scraper passed (`72 passed`); HAR/image slice passed (`21 passed, 790 deselected`); identity/social synthesis slice passed (`101 passed, 710 deselected`); compact kill-chain/report/dashboard smoke passed (`6 passed`); scoped `.forge_data/engagements` cleanup found `remaining_test_like_engagement_dbs=0`.
  Review: OpenAI sidecar reviewer `019f79fd-b3c9-7b00-b4e3-722e35947e4c` found federated-host, large-HAR, and provider-array gaps; all three were fixed and covered by regressions. Claude CLI review was attempted but local Claude returned `You've hit your session limit - resets 6:50pm (Asia/Singapore)`.
  Safety: passive static parsing and bounded local test validation only. No credential use, auth attempts, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change was added.

- [x] AWS client-reference validation checkpoint is green:
  `.venv\Scripts\python.exe -m py_compile forge\phase4\cloud_validate.py tests\phase4\test_cloud_validate.py`
  `.venv\Scripts\python.exe -m ruff check forge\phase4\cloud_validate.py tests\phase4\test_cloud_validate.py` -> `All checks passed!`
  `.venv\Scripts\python.exe -m pytest tests\phase4\test_cloud_validate.py::test_run_cloud_asset_validate_preserves_case_sensitive_provider_identifier tests\phase4\test_cloud_validate.py::test_run_cloud_asset_validate_batch_processes_aws_client_references_without_findings tests\phase4\test_cloud_validate.py::test_sweep_pending_cloud_asset_validations_processes_aws_client_references -q --color=no` -> `3 passed`
  `.venv\Scripts\python.exe -m pytest tests\phase4\test_cloud_validate.py -q --color=no -k "aws_cognito or aws_appsync or aws_pinpoint or provider_identifier or cloud_asset_validate or sweep_pending_cloud_asset_validations" -m "slow or not slow"` -> `86 passed, 53 deselected`
  `.venv\Scripts\python.exe -m pytest tests\phase4\test_cloud_validate.py -q --color=no -m "slow or not slow"` -> `139 passed`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_amplify_client_config.py tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_amplify_client_config_artifacts -q --color=no` -> `5 passed`
  Notes: `aws_cognito_user_pool`, `aws_cognito_app_client`, and `aws_appsync_api` now have passive validators behind the existing bounded cloud-validation path. Cognito uses public OIDC discovery metadata, app clients only validate the associated user-pool metadata without auth, and AppSync only checks endpoint reachability without GraphQL POST/introspection/query execution. `aws_cognito_identity_pool` and `aws_pinpoint_app` now get explicit `UNSUPPORTED` rows during pending sweeps instead of staying pending forever. AWS probe redirects are disabled, and tests reject query/body/auth kwargs on the fake AWS client.
  Review: multi-agent reviewer `019f79c8-e517-7c22-8d38-2d51810169af` found no Critical/Important issues. Its three Minor hardening suggestions were fixed. Claude CLI review was attempted, but local Claude returned `You've hit your session limit - resets 6:50pm (Asia/Singapore)`; rerun `%TEMP%\forge-claude-aws-client-reference-review.txt` after reset if a Claude-branded audit is still required.
  Safety: these AWS client-reference checks return audit evidence only (`ACCESSIBLE_BUT_NO_DATA` or `UNSUPPORTED`) and do not create deterministic vulnerability findings. No token exchange, Cognito identity-pool `GetId`, AppSync GraphQL query/introspection, Pinpoint API call, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate weakening was added.
  Cleanup/commit: temp/test engagement DB cleanup left `remaining_test_like_engagement_dbs=0`. This workspace is not a git repo, so no commit is possible.
  Handoff: `.claude/handoffs/2026-07-19-173416-aws-client-reference-validation.md`.
  Next audit target: continue moving remaining safe sequential enrichers under bounded worker-pool execution, or add the next passive artifact parser gap only if it feeds recursive discovery without expanding live auth/exploitation behavior.

- [x] Case-sensitive cloud asset identifier storage checkpoint is green:
  `.venv\Scripts\python.exe -m py_compile forge\db\schema.py forge\db\migrations.py forge\db\validation.py forge\engagement_orchestrator.py forge\phase4\cloud_validate.py forge\phase4\mobile_config_parse.py forge\phase4\cloud_audit.py forge\phase4\api_policy_check.py forge\phase4\aws_audit.py forge\phase4\azure_audit.py forge\phase4\attack_path.py forge\phase6\report_synthesizer.py forge\reporting\dashboard.py forge\cli.py tests\phase1\test_multi_seed_schema.py tests\phase1\test_engagement_orchestrator.py tests\phase4\test_cloud_validate.py tests\phase4\test_firebase_agneyastra.py`
  `.venv\Scripts\python.exe -m ruff check forge\db\schema.py forge\db\migrations.py forge\db\validation.py forge\engagement_orchestrator.py forge\phase4\cloud_validate.py forge\phase4\mobile_config_parse.py forge\phase4\cloud_audit.py forge\phase4\api_policy_check.py forge\phase4\aws_audit.py forge\phase4\azure_audit.py forge\phase4\attack_path.py forge\phase6\report_synthesizer.py forge\reporting\dashboard.py forge\cli.py tests\phase1\test_multi_seed_schema.py tests\phase1\test_engagement_orchestrator.py tests\phase4\test_cloud_validate.py tests\phase4\test_firebase_agneyastra.py` -> `All checks passed!`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_multi_seed_schema.py tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_amplify_client_config_artifacts tests\phase4\test_cloud_validate.py::test_run_cloud_asset_validate_preserves_case_sensitive_provider_identifier tests\phase4\test_cloud_validate.py::test_run_cloud_asset_validate_persists_direct_asset_result tests\phase4\test_firebase_agneyastra.py::TestDryRun::test_dry_run_no_db_writes -q --color=no` -> `8 passed`
  `.venv\Scripts\python.exe -m pytest tests\phase4\test_cloud_validate.py::test_run_cloud_asset_validate_batch_persists_mixed_results tests\phase4\test_cloud_validate.py::test_sweep_pending_cloud_asset_validations_processes_unvalidated_assets tests\phase4\test_cloud_validate.py::test_sweep_pending_cloud_asset_validations_scope_checker_skips_denied_assets tests\phase4\test_attack_path.py::TestGraphBuildArtifacts::test_graph_build_all_writes_native_mtgx_workspace tests\reporting\test_dashboard.py::test_generate_dashboard_emits_slug_routes_and_json_contract tests\phase6\test_report_synthesizer.py::test_synthesizer_runtime_provider_failure_falls_back_to_template -q --color=no -m "slow or not slow"` -> `6 passed`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_multi_seed_schema.py tests\phase1\test_engagement_orchestrator.py tests\phase4\test_cloud_validate.py tests\phase4\test_attack_path.py tests\phase4\test_firebase_agneyastra.py tests\reporting\test_dashboard.py tests\phase6\test_report_synthesizer.py -q --color=no -k "provider_identifier or amplify_client_config or cloud_asset_validate or sweep_pending_cloud_asset_validations or cloud_assets or cloud_validation_results or dashboard or fallback" -m "slow or not slow"` -> `122 passed, 1043 deselected`
  Notes: canonical `identifier` columns remain lowercase and unique; nullable `provider_identifier` columns preserve exact first-seen provider IDs on `cloud_assets` and `cloud_validation_results`. Amplify/Cognito mixed-case IDs now survive storage, direct/batch/pending validation uses exact provider IDs for validator calls while persisting canonical keys, and graph/dashboard/report metadata can display the exact ID. Standalone Firebase/Supabase/AWS/Azure scanner shims were updated for column compatibility.
  Review: two OpenAI sidecar reviewers recommended the canonical/exact split; both were closed after implementation. Claude CLI read-only review was attempted at `%TEMP%\forge-claude-provider-identifier-review.txt` but returned `You've hit your session limit - resets 6:50pm (Asia/Singapore)`, so rerun after reset if external Claude audit is required.
  Safety: storage/read-path fidelity only. No new provider validators, live probing, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change was added.
  Cleanup/commit: temp/test engagement DB cleanup left `remaining_test_like_engagement_dbs=0`. This workspace is not a git repo, so no commit is possible.
  Next audit target was closed by the AWS client-reference validation checkpoint above.

- [x] Amplify/Cognito/AppSync client-config artifact-recursion checkpoint is green:
  `.venv\Scripts\python.exe -m py_compile forge\utils\artifact_amplify_client_config.py forge\engagement_orchestrator.py tests\phase1\test_artifact_amplify_client_config.py tests\phase1\test_engagement_orchestrator.py`
  `.venv\Scripts\python.exe -m ruff check forge\utils\artifact_amplify_client_config.py forge\engagement_orchestrator.py tests\phase1\test_artifact_amplify_client_config.py tests\phase1\test_engagement_orchestrator.py` -> `All checks passed!`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_amplify_client_config.py tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_amplify_client_config_artifacts tests\phase1\test_engagement_orchestrator.py::test_amplify_client_config_artifact_format_labels_are_source_aware -q --color=no` -> `6 passed`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_amplify_client_config.py tests\phase1\test_artifact_ecs_task_definition.py tests\phase1\test_artifact_lambda_config.py tests\phase1\test_engagement_orchestrator.py -q --color=no -k "amplify_client_config or amplify_config or ecs_task_definition or lambda_config or deploy_platform_config_artifacts or structured_json_config_cloud_assets or structured_key_value_config_cloud_assets or package_registry or container_image"` -> `25 passed, 793 deselected`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py::test_kill_chain_artifact_extracted_assets_validate_and_seed_next_iteration_under_scope tests\phase6\test_report_synthesizer.py::test_synthesizer_runtime_provider_failure_falls_back_to_template tests\reporting\test_dashboard.py::test_generate_dashboard_emits_slug_routes_and_json_contract tests\reporting\test_dashboard.py::test_generate_dashboard_surfaces_provider_matrix_artifacts_and_validation_evidence tests\phase4\test_cloud_validate.py::test_sweep_pending_cloud_asset_validations_scope_checker_skips_denied_assets tests\phase4\test_attack_path.py::TestGraphBuildArtifacts::test_graph_build_all_writes_native_mtgx_workspace -q --color=no -m "slow or not slow"` -> `6 passed`
  Notes: `forge/utils/artifact_amplify_client_config.py` adds passive parsing for `aws-exports.*`, `amplifyconfiguration.*`, and `amplify_outputs.*`. It emits Cognito user-pool/identity-pool/app-client refs, AppSync endpoint/API refs, S3 buckets, and Pinpoint app refs; URLs are stripped of query/fragment before becoming recursive seeds. `engagement_orchestrator.py` now recognizes these artifact names locally/remotely, routes text/JSON/YAML/env-list extraction through bounded workers, and persists AWS identity/API refs with source `artifact_amplify_client_config`.
  Reviewer: OpenAI sidecar reviewer found env-list, provenance, case, false-positive, and URL-query risks; fixes are incorporated and covered by tests. Claude CLI read-only review was attempted but hit the local session limit until 6:50pm Asia/Singapore; output is `%TEMP%\forge-claude-amplify-review.txt`.
  Residual task: decide global cloud-asset identifier case semantics before adding exact Cognito/AppSync validators, because current persistence still lowercases identifiers even though the helper preserves case before handoff.
  Safety: passive static parsing only. No AWS/Cognito/AppSync API calls, auth attempts, credential use, live probing, provider calls, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change was added.
  Cleanup/commit: temp/test engagement DB cleanup left `remaining_test_like_engagement_dbs=0`. This workspace is not a git repo, so no commit is possible.
  Handoff: `.claude/handoffs/2026-07-19-164532-amplify-client-config-artifact-recursion.md`.
  Next audit target: continue concrete backend kill-chain gaps only: case-sensitive cloud-asset storage contract, provider-proof hardening, identity normalization/provider-shape coverage, passive parser/container/OCR coverage where a real scraped-artifact gap exists, or bounded-worker migration.

- [x] AWS Lambda config artifact-recursion checkpoint is green:
  `.venv\Scripts\python.exe -m py_compile forge\utils\artifact_lambda_config.py forge\engagement_orchestrator.py tests\phase1\test_artifact_lambda_config.py tests\phase1\test_engagement_orchestrator.py`
  `.venv\Scripts\python.exe -m ruff check forge\utils\artifact_lambda_config.py forge\engagement_orchestrator.py tests\phase1\test_artifact_lambda_config.py tests\phase1\test_engagement_orchestrator.py` -> `All checks passed!`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_lambda_config.py tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_lambda_config_artifacts tests\phase1\test_engagement_orchestrator.py::test_lambda_config_artifact_format_labels_are_source_aware -q --color=no` -> `5 passed`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_ecs_task_definition.py tests\phase1\test_artifact_lambda_config.py tests\phase1\test_engagement_orchestrator.py -q --color=no -k "ecs_task_definition or lambda_config or codebuild_buildspec_secret_refs or non_terraform_iac_artifacts or structured_json_config_cloud_assets or structured_key_value_config_cloud_assets or package_registry or container_image or secret_provider_class"` -> `22 passed, 790 deselected`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py::test_kill_chain_artifact_extracted_assets_validate_and_seed_next_iteration_under_scope tests\phase6\test_report_synthesizer.py::test_synthesizer_runtime_provider_failure_falls_back_to_template tests\reporting\test_dashboard.py::test_generate_dashboard_emits_slug_routes_and_json_contract tests\reporting\test_dashboard.py::test_generate_dashboard_surfaces_provider_matrix_artifacts_and_validation_evidence tests\phase4\test_cloud_validate.py::test_sweep_pending_cloud_asset_validations_scope_checker_skips_denied_assets tests\phase4\test_attack_path.py::TestGraphBuildArtifacts::test_graph_build_all_writes_native_mtgx_workspace -q --color=no -m "slow or not slow"` -> `6 passed`
  Notes: `forge/utils/artifact_lambda_config.py` adds passive Lambda function configuration and function URL parsing for JSON/YAML/wrapped/list exports. It emits reviewable `aws-lambda-function://...`, function URL seeds, explicit private registry URLs from image package configs, environment email/URL/provider refs, and AWS role/layer/KMS/EFS/SQS/SNS refs. The existing structured JSON/YAML parser routes these through the bounded worker-pool path, and the cloud-asset path persists the corresponding `aws_*` rows.
  Claude review: attempted read-only Claude review, but the local Claude CLI hit the session limit until 6:50pm Asia/Singapore. Rerun `%TEMP%\forge-claude-lambda-review.txt` after reset if external review is required.
  Safety: passive static parsing only. No Lambda/AWS API calls, function execution, provider calls, credential use, live probing, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change was added.
  Cleanup/commit: temp/test engagement DB cleanup left `remaining_test_like_engagement_dbs=0`. This workspace is not a git repo, so no commit is possible.
  Handoff: `.claude/handoffs/2026-07-19-162123-lambda-config-artifact-recursion.md`.
  Next audit target: continue only concrete backend kill-chain gaps: Phase 1 runtime reduction, passive parser/container/OCR coverage where a real scraped-artifact gap exists, provider-proof hardening, identity normalization/provider-shape coverage, or bounded-worker migration.

- [x] AWS ECS task-definition artifact-recursion checkpoint is green:
  `.venv\Scripts\python.exe -m py_compile forge\utils\artifact_ecs_task_definition.py forge\engagement_orchestrator.py tests\phase1\test_artifact_ecs_task_definition.py tests\phase1\test_engagement_orchestrator.py`
  `.venv\Scripts\python.exe -m ruff check forge\utils\artifact_ecs_task_definition.py forge\engagement_orchestrator.py tests\phase1\test_artifact_ecs_task_definition.py tests\phase1\test_engagement_orchestrator.py` -> `All checks passed!`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_ecs_task_definition.py tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_ecs_task_definition_artifacts tests\phase1\test_engagement_orchestrator.py::test_ecs_task_definition_artifact_format_labels_are_source_aware -q --color=no` -> `5 passed`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_ecs_task_definition.py tests\phase1\test_engagement_orchestrator.py -q --color=no -k "ecs_task_definition or non_terraform_iac_artifacts or structured_json_config_cloud_assets or structured_key_value_config_cloud_assets or package_registry or container_image or secret_provider_class"` -> `16 passed, 791 deselected`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py::test_kill_chain_artifact_extracted_assets_validate_and_seed_next_iteration_under_scope tests\phase6\test_report_synthesizer.py::test_synthesizer_runtime_provider_failure_falls_back_to_template tests\reporting\test_dashboard.py::test_generate_dashboard_emits_slug_routes_and_json_contract tests\reporting\test_dashboard.py::test_generate_dashboard_surfaces_provider_matrix_artifacts_and_validation_evidence tests\phase4\test_cloud_validate.py::test_sweep_pending_cloud_asset_validations_scope_checker_skips_denied_assets tests\phase4\test_attack_path.py::TestGraphBuildArtifacts::test_graph_build_all_writes_native_mtgx_workspace -q --color=no -m "slow or not slow"` -> `6 passed`
  Notes: `forge/utils/artifact_ecs_task_definition.py` adds passive ECS task-definition parsing for JSON/YAML/wrapped exports. It emits reviewable `aws-ecs-task-definition://...`, explicit private registry URLs from container images, environment email/URL/provider refs, AWS Secrets Manager/Parameter Store refs from `secrets.valueFrom`, and repository credential secret refs. The existing structured JSON/YAML parser now routes these through the bounded worker-pool path, and the cloud-asset path persists `aws_ecs_task_definition` plus AWS secret/parameter refs.
  Claude review: attempted read-only Claude review. This Claude CLI rejected the documented `-C` flag, then hit the session limit until 6:50pm Asia/Singapore when retried from the project cwd. Rerun `%TEMP%\forge-claude-ecs-review.txt` after reset if external review is required.
  Safety: passive static parsing only. No ECS/AWS API calls, container execution, provider calls, credential use, live probing, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change was added.
  Cleanup/commit: temp/test engagement DB cleanup left `remaining_test_like_engagement_dbs=0`. This workspace is not a git repo, so no commit is possible.
  Handoff: `.claude/handoffs/2026-07-19-161417-ecs-task-definition-artifact-recursion.md`.
  Next audit target: continue only concrete backend kill-chain gaps: Phase 1 runtime reduction, passive parser/container/OCR coverage where a real scraped-artifact gap exists, provider-proof hardening, identity normalization/provider-shape coverage, or bounded-worker migration.

- [x] Kubernetes SecretProviderClass artifact-recursion checkpoint is green:
  `.venv\Scripts\python.exe -m py_compile forge\utils\artifact_secret_provider_class.py forge\engagement_orchestrator.py tests\phase1\test_artifact_secret_provider_class.py tests\phase1\test_engagement_orchestrator.py`
  `.venv\Scripts\python.exe -m ruff check forge\utils\artifact_secret_provider_class.py forge\engagement_orchestrator.py tests\phase1\test_artifact_secret_provider_class.py tests\phase1\test_engagement_orchestrator.py` -> `All checks passed!`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_secret_provider_class.py tests\phase1\test_engagement_orchestrator.py::test_secret_provider_class_artifact_format_labels_are_source_aware tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_secret_provider_class_artifacts -q --color=no` -> `4 passed`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_secret_provider_class.py tests\phase1\test_engagement_orchestrator.py -q --color=no -k "secret_provider_class or yaml_config or structured_yaml or kubernetes_secret or dockerconfigjson or orchestration_config_artifacts or non_terraform_iac_artifacts"` -> `7 passed, 797 deselected`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py::test_kill_chain_artifact_extracted_assets_validate_and_seed_next_iteration_under_scope tests\phase6\test_report_synthesizer.py::test_synthesizer_runtime_provider_failure_falls_back_to_template tests\reporting\test_dashboard.py::test_generate_dashboard_emits_slug_routes_and_json_contract tests\reporting\test_dashboard.py::test_generate_dashboard_surfaces_provider_matrix_artifacts_and_validation_evidence tests\phase4\test_cloud_validate.py::test_sweep_pending_cloud_asset_validations_scope_checker_skips_denied_assets tests\phase4\test_attack_path.py::TestGraphBuildArtifacts::test_graph_build_all_writes_native_mtgx_workspace -q --color=no -m "slow or not slow"` -> `6 passed`
  Notes: `forge/utils/artifact_secret_provider_class.py` adds passive Secrets Store CSI `SecretProviderClass` parsing. It emits reviewable `secret-provider-class://namespace/name`, Azure Key Vault URLs, AWS Secrets Manager/Parameter Store URIs, GCP Secret Manager URIs, and HashiCorp Vault URLs/URIs. The existing Kubernetes secret-manifest cloud-asset path now persists `secret_provider_class` plus provider refs and promotes generated URLs into recursive discovery.
  Claude review: attempted read-only Claude review, but local Claude CLI hit the session limit until 6:50pm Asia/Singapore. Rerun the narrow review after reset if external review is required; local compile/Ruff/focused/adjacent/smoke verification is green.
  Safety: passive static parsing only. No `kubectl`, cluster API, provider API, DB/network calls, secret fetching, credential use, live probing, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change was added.
  Cleanup/commit: temp/test engagement DB cleanup left `remaining_test_like_engagement_dbs=0`. This workspace is not a git repo, so no commit is possible.
  Handoff: `.claude/handoffs/2026-07-19-160057-secret-provider-class-artifact-recursion.md`.
  Next audit target: continue only concrete backend kill-chain gaps: Phase 1 runtime reduction, passive parser/container/OCR coverage where a real scraped-artifact gap exists, provider-proof hardening, identity normalization/provider-shape coverage, or bounded-worker migration.

- [x] Framework database config artifact-recursion checkpoint is green:
  `.venv\Scripts\python.exe -m py_compile forge\utils\artifact_framework_config.py forge\engagement_orchestrator.py tests\phase1\test_artifact_framework_config.py tests\phase1\test_engagement_orchestrator.py`
  `.venv\Scripts\python.exe -m ruff check forge\utils\artifact_framework_config.py forge\engagement_orchestrator.py tests\phase1\test_artifact_framework_config.py tests\phase1\test_engagement_orchestrator.py` -> `All checks passed!`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_framework_config.py tests\phase1\test_engagement_orchestrator.py::test_framework_config_artifact_format_labels_are_source_aware tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_framework_config_artifacts -q --color=no` -> `4 passed`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_orm_config.py tests\phase1\test_engagement_orchestrator.py -q --color=no -k "framework_config or orm_config or database_client_configs or network_dsn_hosts_without_credentials or backend_source_text_artifacts or structured_key_value_config_cloud_assets or structured_yaml_cloud_assets"` -> `32 passed, 789 deselected`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py::test_kill_chain_artifact_extracted_assets_validate_and_seed_next_iteration_under_scope tests\phase6\test_report_synthesizer.py::test_synthesizer_runtime_provider_failure_falls_back_to_template tests\reporting\test_dashboard.py::test_generate_dashboard_emits_slug_routes_and_json_contract tests\reporting\test_dashboard.py::test_generate_dashboard_surfaces_provider_matrix_artifacts_and_validation_evidence tests\phase4\test_cloud_validate.py::test_sweep_pending_cloud_asset_validations_scope_checker_skips_denied_assets tests\phase4\test_attack_path.py::TestGraphBuildArtifacts::test_graph_build_all_writes_native_mtgx_workspace -q --color=no -m "slow or not slow"` -> `6 passed`
  Notes: `forge/utils/artifact_framework_config.py` adds passive source-gated Rails, Spring, .NET, Alembic, Laravel, and Django database config labeling plus explicit DB host extraction. Structured payloads emit sanitized `postgres://host` pivots so existing discovery can recurse without persisting DB passwords/userinfo. Generic root `database.yml`, root `application.properties`, root `settings.py`, `offspring/application.properties`, and `djangonaut/settings.py` stay unclassified/generic; env/template placeholders stay filtered.
  Claude review: first read-only Claude pass found a real source-gating bug (`spring`/`django` substring matching). `_has_segment` now requires exact path segments and negative tests cover `offspring`/`djangonaut`; follow-up Claude confirmed the Important finding is fixed with no remaining Critical/Important issues in that narrow area.
  Safety: passive static parsing only. No framework CLI execution, database connection, credential use, migration execution, live probing, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change was added.
  Cleanup/commit: temp/test engagement DB cleanup left `remaining_test_like_engagement_dbs=0`. This workspace is not a git repo, so no commit is possible.
  Handoff: `.claude/handoffs/2026-07-19-155002-framework-config-artifact-recursion.md`.
  Next audit target: continue only concrete backend kill-chain gaps: Phase 1 runtime reduction, passive parser/container/OCR coverage where a real scraped-artifact gap exists, provider-proof hardening, identity normalization/provider-shape coverage, or bounded-worker migration.

- [x] ORM/database migration config artifact-recursion checkpoint is green:
  `.venv\Scripts\python.exe -m py_compile forge\utils\artifact_orm_config.py forge\engagement_orchestrator.py tests\phase1\test_artifact_orm_config.py tests\phase1\test_engagement_orchestrator.py`
  `.venv\Scripts\python.exe -m ruff check forge\utils\artifact_orm_config.py forge\engagement_orchestrator.py tests\phase1\test_artifact_orm_config.py tests\phase1\test_engagement_orchestrator.py` -> `All checks passed!`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_orm_config.py tests\phase1\test_engagement_orchestrator.py::test_orm_config_artifact_format_labels_are_source_aware tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_orm_config_artifacts -q --color=no` -> `23 passed`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_orm_config.py tests\phase1\test_engagement_orchestrator.py -q --color=no -k "orm_config or network_dsn_hosts_without_credentials or database_client_configs or structured_key_value_config_cloud_assets or structured_json_config_cloud_assets or non_terraform_iac_artifacts"` -> `29 passed, 790 deselected`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py::test_kill_chain_artifact_extracted_assets_validate_and_seed_next_iteration_under_scope tests\phase6\test_report_synthesizer.py::test_synthesizer_runtime_provider_failure_falls_back_to_template tests\reporting\test_dashboard.py::test_generate_dashboard_emits_slug_routes_and_json_contract tests\reporting\test_dashboard.py::test_generate_dashboard_surfaces_provider_matrix_artifacts_and_validation_evidence tests\phase4\test_cloud_validate.py::test_sweep_pending_cloud_asset_validations_scope_checker_skips_denied_assets tests\phase4\test_attack_path.py::TestGraphBuildArtifacts::test_graph_build_all_writes_native_mtgx_workspace -q --color=no -m "slow or not slow"` -> `6 passed`
  Notes: `forge/utils/artifact_orm_config.py` adds passive source-gated Prisma, Drizzle, TypeORM, Sequelize, Knex, MikroORM, Liquibase, and Flyway config labeling plus explicit DB host extraction. Structured payloads emit sanitized `postgres://host` pivots so existing network endpoint extraction can recurse without persisting DB passwords/userinfo. Generic `config.json`, bare `data-source.ts`, `sequelize-theme.js`, `schema.sql`, and unrelated changelogs stay unclassified.
  Claude review: read-only Claude returned `No findings`. Residual risk is intentional: private/RFC1918 DB hosts remain eligible seeds, matching database-client behavior and preserving internal DB pivots when they are in scope.
  Safety: passive static parsing only. No ORM/migration CLI execution, DB connection, credential use, migration execution, live probing, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change was added.
  Cleanup/commit: temp/test engagement DB cleanup deleted 9 pytest DBs and left `remaining_test_like_engagement_dbs=0`. This workspace is not a git repo, so no commit is possible.
  Handoff: `.claude/handoffs/2026-07-19-152843-orm-config-artifact-recursion.md`.
  Next audit target: continue only concrete backend kill-chain gaps: Phase 1 runtime reduction, passive parser/container/OCR coverage where a real scraped-artifact gap exists, provider-proof hardening, identity normalization/provider-shape coverage, or bounded-worker migration.

- [x] Tunnel-config artifact-recursion checkpoint is green:
  `.venv\Scripts\python.exe -m py_compile forge\utils\artifact_tunnel_config.py forge\engagement_orchestrator.py tests\phase1\test_artifact_tunnel_config.py tests\phase1\test_engagement_orchestrator.py`
  `.venv\Scripts\python.exe -m ruff check forge\utils\artifact_tunnel_config.py forge\engagement_orchestrator.py tests\phase1\test_artifact_tunnel_config.py tests\phase1\test_engagement_orchestrator.py` -> `All checks passed!`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_tunnel_config.py tests\phase1\test_engagement_orchestrator.py::test_artifact_tunnel_config_structured_payload_uses_bounded_workers_and_preserves_order tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_tunnel_config_artifacts -q --color=no` -> `19 passed`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_tunnel_config.py tests\phase1\test_engagement_orchestrator.py -q --color=no -k "tunnel_config or vpn_endpoint_artifacts or edge_proxy or orchestration_structured_payload or structured_key_value_config_cloud_assets"` -> `21 passed, 792 deselected`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py::test_kill_chain_artifact_extracted_assets_validate_and_seed_next_iteration_under_scope tests\phase6\test_report_synthesizer.py::test_synthesizer_runtime_provider_failure_falls_back_to_template tests\reporting\test_dashboard.py::test_generate_dashboard_emits_slug_routes_and_json_contract tests\reporting\test_dashboard.py::test_generate_dashboard_surfaces_provider_matrix_artifacts_and_validation_evidence tests\phase4\test_cloud_validate.py::test_sweep_pending_cloud_asset_validations_scope_checker_skips_denied_assets tests\phase4\test_attack_path.py::TestGraphBuildArtifacts::test_graph_build_all_writes_native_mtgx_workspace -q --color=no -m "slow or not slow"` -> `6 passed`
  Notes: `forge/utils/artifact_tunnel_config.py` adds passive source-gated ngrok, cloudflared, Tailscale serve/funnel, and localtunnel config parsing. Explicit public endpoint fields promote recursive URL seeds, while tunnel origin endpoints such as `localhost`, loopback/private/link-local IPs, and templated hosts are filtered before generic structured/raw discovery can re-seed them. Remote/cache labels preserve analyst-visible formats such as `config.yml.cloudflared-config`.
  Claude review: first read-only Claude pass found a multi-line XML/plist redaction issue plus two dead-code branches; fixes now drop every line overlapped by invalid endpoint matches and remove the dead branches. Final read-only Claude pass returned `No findings`; residual risk is fail-safe over-redaction if public and private values share one physical line.
  Safety: passive static parsing only. No tunnel client execution, public tunnel creation, HTTP probing, credential use, auth, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change was added.
  Cleanup/commit: temp/test engagement DB cleanup deleted 3 pytest DBs and left `remaining_test_like_engagement_dbs=0`. This workspace is not a git repo, so no commit is possible.
  Handoff: `.claude/handoffs/2026-07-19-151410-tunnel-config-artifact-recursion.md`.
  Next audit target: continue only concrete backend kill-chain gaps: Phase 1 runtime reduction, passive parser/container/OCR coverage where a real scraped-artifact gap exists, provider-proof hardening, identity normalization/provider-shape coverage, or bounded-worker migration.

- [x] Database-client config artifact-recursion checkpoint is green:
  `.venv\Scripts\python.exe -m py_compile forge\utils\artifact_database_client.py forge\engagement_orchestrator.py tests\phase1\test_artifact_database_client.py tests\phase1\test_engagement_orchestrator.py`
  `.venv\Scripts\python.exe -m ruff check forge\utils\artifact_database_client.py forge\engagement_orchestrator.py tests\phase1\test_artifact_database_client.py tests\phase1\test_engagement_orchestrator.py` -> `All checks passed!`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_database_client.py tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_database_client_configs -q --color=no` -> `19 passed`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_database_client.py tests\phase1\test_engagement_orchestrator.py -q --color=no -k "database_client_configs or structured_network_dsn or database_url or sqlite_database_findings or structured_json_config_cloud_assets or structured_key_value_config_cloud_assets"` -> `4 passed, 808 deselected`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py::test_kill_chain_artifact_extracted_assets_validate_and_seed_next_iteration_under_scope tests\phase6\test_report_synthesizer.py::test_synthesizer_runtime_provider_failure_falls_back_to_template tests\reporting\test_dashboard.py::test_generate_dashboard_emits_slug_routes_and_json_contract tests\reporting\test_dashboard.py::test_generate_dashboard_surfaces_provider_matrix_artifacts_and_validation_evidence tests\phase4\test_cloud_validate.py::test_sweep_pending_cloud_asset_validations_scope_checker_skips_denied_assets tests\phase4\test_attack_path.py::TestGraphBuildArtifacts::test_graph_build_all_writes_native_mtgx_workspace -q --color=no -m "slow or not slow"` -> `6 passed`
  Notes: `forge/utils/artifact_database_client.py` adds passive source-gated DBeaver, JetBrains/DataGrip, TablePlus, SQL Developer, pgAdmin, HeidiSQL, and DbVisualizer config parsing. Host extraction preserves source order across JSON, key/value text, XML, and plist fields; validates IPv4/bare IPv6/bracketed IPv6 through `ipaddress`; strips valid host-port suffixes; accepts internal single-label and underscore service hosts; and rejects loopback, unspecified, multicast, malformed IP, numeric-only, and malformed-host seeds. Generic `data-sources.json`, `dataSources.xml`, `connections.xml`, `servers.json`, `Bookmarks/prod.duck`, and `notes/tableplus-connections.txt` stay unclassified.
  Claude review: read-only Claude found and drove fixes for DBeaver workspace paths, source-order extraction, raw XML archive-member preservation, bracketed IPv6 validation, malformed bracket rejection, single-label hosts, IPv4 octet validation, loopback/unspecified/multicast filtering, bare IPv6, host-port fields, and underscore hostnames. Final no-tool Claude pass returned `No findings`.
  Safety: passive static parsing only. No DB-client execution, database connection, credential use, auth, live probing expansion, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change was added.
  Cleanup/commit: temp/test engagement DB cleanup deleted 7 pytest DBs and left `remaining_test_like_engagement_dbs=0`. This workspace is not a git repo, so no commit is possible.
  Handoff: `.claude/handoffs/2026-07-19-144634-database-client-artifact-recursion.md`.
  Next audit target: continue only concrete backend kill-chain gaps: passive parser/container/OCR coverage, provider-proof hardening, identity normalization/provider-shape coverage, or bounded-worker migration where a real recursive-discovery gap is found.

- [x] File-transfer client config artifact-recursion checkpoint is green:
  `.venv\Scripts\python.exe -m py_compile forge\utils\artifact_connection_client.py forge\engagement_orchestrator.py tests\phase1\test_artifact_connection_client.py tests\phase1\test_engagement_orchestrator.py`
  `.venv\Scripts\python.exe -m ruff check forge\utils\artifact_connection_client.py forge\engagement_orchestrator.py tests\phase1\test_artifact_connection_client.py tests\phase1\test_engagement_orchestrator.py` -> `All checks passed!`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_connection_client.py tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_connection_client_configs -q --color=no` -> `35 passed`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_connection_client.py tests\phase1\test_engagement_orchestrator.py -q --color=no -k "connection_client_configs or remote_access_config_artifacts or ssh_static_artifacts or vpn_profile or shortcut_link_artifacts or windows_registry_export_artifacts"` -> `4 passed, 823 deselected`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py::test_kill_chain_artifact_extracted_assets_validate_and_seed_next_iteration_under_scope tests\phase6\test_report_synthesizer.py::test_synthesizer_runtime_provider_failure_falls_back_to_template tests\reporting\test_dashboard.py::test_generate_dashboard_emits_slug_routes_and_json_contract tests\reporting\test_dashboard.py::test_generate_dashboard_surfaces_provider_matrix_artifacts_and_validation_evidence tests\phase4\test_cloud_validate.py::test_sweep_pending_cloud_asset_validations_scope_checker_skips_denied_assets tests\phase4\test_attack_path.py::TestGraphBuildArtifacts::test_graph_build_all_writes_native_mtgx_workspace -q --color=no -m "slow or not slow"` -> `6 passed`
  Notes: `forge/utils/artifact_connection_client.py` now also covers passive FileZilla, Cyberduck, Transmit, lftp, and ncftp config/bookmark artifacts. Source-gated XML/plist host fields and FTP/SFTP/SCP command-style entries promote recursive domain/IP seeds, including archive-contained Cyberduck bookmarks. Remote FileZilla paths preserve source context through cache names such as `sitemanager.xml.filezilla-config`. Generic `sitemanager.xml`, `recentservers.xml`, `Bookmarks/prod.duck`, `Transmit/theme.xml`, and `lftp-bookmarks.txt` stay unclassified.
  Claude review: read-only Claude found and drove fixes for command-parser false positives around hyphenated tools, scp remote specs, trailing args, scp `-p`/`-P`, SSH/SFTP/SCP option values, SSH `-D`, and quoted `ProxyCommand` values. Final read-only Claude pass returned `No findings`. Output: `%TEMP%\forge-claude-transfer-client-review-final8.txt`.
  Safety: passive static parsing only. No FileZilla/Cyberduck/Transmit/lftp/ncftp execution, FTP/SFTP/SCP/SSH connection, credential use, auth, live probing expansion, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change was added.
  Cleanup/commit: temp/test engagement DB cleanup deleted 6 pytest DBs and left `remaining_test_like_engagement_dbs=0`. This workspace is not a git repo, so no commit is possible.
  Next audit target: continue safe passive parser coverage, provider-proof hardening, identity normalization, or bounded-worker migration only where a concrete recursive-discovery gap is found.

- [x] Connection-client config artifact-recursion checkpoint is green:
  `.venv\Scripts\python.exe -m py_compile forge\utils\artifact_connection_client.py forge\engagement_orchestrator.py tests\phase1\test_artifact_connection_client.py tests\phase1\test_engagement_orchestrator.py`
  `.venv\Scripts\python.exe -m ruff check forge\utils\artifact_connection_client.py forge\engagement_orchestrator.py tests\phase1\test_artifact_connection_client.py tests\phase1\test_engagement_orchestrator.py` -> `All checks passed!`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_connection_client.py tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_connection_client_configs -q --color=no` -> `17 passed`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_connection_client.py tests\phase1\test_engagement_orchestrator.py -q --color=no -k "connection_client_configs or remote_access_config_artifacts or ssh_static_artifacts or vpn_profile or shortcut_link_artifacts or windows_registry_export_artifacts"` -> `4 passed, 805 deselected`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py::test_kill_chain_artifact_extracted_assets_validate_and_seed_next_iteration_under_scope tests\phase6\test_report_synthesizer.py::test_synthesizer_runtime_provider_failure_falls_back_to_template tests\reporting\test_dashboard.py::test_generate_dashboard_emits_slug_routes_and_json_contract tests\reporting\test_dashboard.py::test_generate_dashboard_surfaces_provider_matrix_artifacts_and_validation_evidence tests\phase4\test_cloud_validate.py::test_sweep_pending_cloud_asset_validations_scope_checker_skips_denied_assets tests\phase4\test_attack_path.py::TestGraphBuildArtifacts::test_graph_build_all_writes_native_mtgx_workspace -q --color=no -m "slow or not slow"` -> `6 passed`
  Notes: connection-client config support was modularized into `forge/utils/artifact_connection_client.py` (106 lines). It recognizes WinSCP, PuTTY/KiTTY, MobaXterm, SecureCRT, and SuperPuTTY configs, including archive-contained member paths and remote SecureCRT-style paths cached as labels such as `prod.ini.securecrt-session`. Host fields and command-style `ssh`/`sftp`/`scp`/`telnet`/`rlogin` session lines promote recursive domain/IP seeds; existing generic extraction still handles emails, URLs, Firebase/Supabase refs, S3 buckets, and GCS buckets.
  Claude review: read-only Claude pass found one actionable false-positive issue in the SuperPuTTY path classifier. The rule now only accepts direct `Sessions.xml` or files under a `Sessions` path segment, and regression negatives cover generic `SuperPuTTY/theme.xml` and `SuperPuTTY/misc.settings`. A post-fix reviewer process did not emit output within the timeout and was stopped; rely on the fixed finding plus green local tests.
  Safety: passive static parsing only. No connection-client execution, SSH/SFTP/RDP/Telnet connections, registry import, credential use, auth, live probing expansion, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change was added.
  Cleanup/commit: temp/test engagement DB cleanup deleted 6 pytest DBs and left `remaining_test_like_engagement_dbs=0`. This workspace is not a git repo, so no commit is possible.
  Next audit target: continue safe passive parser coverage or bounded worker migrations only when they map to a concrete recursive-discovery gap; do not move the goal into UI-only work.

- [x] Windows registry hive artifact-recursion checkpoint is green:
  `.venv\Scripts\python.exe -m py_compile forge\utils\artifact_windows_registry.py forge\engagement_orchestrator.py tests\phase1\test_artifact_windows_registry.py tests\phase1\test_engagement_orchestrator.py`
  `.venv\Scripts\python.exe -m ruff check forge\utils\artifact_windows_registry.py forge\engagement_orchestrator.py tests\phase1\test_artifact_windows_registry.py tests\phase1\test_engagement_orchestrator.py` -> `All checks passed!`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_windows_registry.py tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_windows_registry_hive_artifacts -q --color=no` -> `18 passed`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_windows_registry.py tests\phase1\test_engagement_orchestrator.py -q --color=no -k "windows_registry_hive_artifacts or windows_registry_export_artifacts or windows_event_trace_artifacts or windows_execution_history_artifacts or browser_webcache_artifacts or browser_navigation_artifacts"` -> `5 passed, 804 deselected`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py::test_kill_chain_artifact_extracted_assets_validate_and_seed_next_iteration_under_scope tests\phase6\test_report_synthesizer.py::test_synthesizer_runtime_provider_failure_falls_back_to_template tests\reporting\test_dashboard.py::test_generate_dashboard_emits_slug_routes_and_json_contract tests\reporting\test_dashboard.py::test_generate_dashboard_surfaces_provider_matrix_artifacts_and_validation_evidence tests\phase4\test_cloud_validate.py::test_sweep_pending_cloud_asset_validations_scope_checker_skips_denied_assets tests\phase4\test_attack_path.py::TestGraphBuildArtifacts::test_graph_build_all_writes_native_mtgx_workspace -q --color=no -m "slow or not slow"` -> `6 passed`
  Notes: Windows registry hive artifact support was modularized into `forge/utils/artifact_windows_registry.py`. It recognizes `NTUSER.DAT`, `UsrClass.dat`, `Amcache.hve`, source-gated `Windows/System32/config/{SOFTWARE,SYSTEM,SAM,SECURITY,DEFAULT,COMPONENTS}`, and `Boot/BCD`; generic `SOFTWARE`, `SYSTEM`, `config/SOFTWARE`, browser `History`, and `settings.dat` stay unclassified. Extensionless remote system hives preserve label/extraction through `.reghive`.
  Claude review: read-only Claude pass reported `No findings`. Output: `%TEMP%\forge-claude-windows-registry-review.txt`.
  Safety: passive binary string carving only. No live Windows registry APIs, hive mounting/loading, credential use, auth, live probing expansion, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change was added.
  Cleanup/commit: temp/test engagement DB cleanup left `remaining_test_like_engagement_dbs=0`. This workspace is not a git repo, so no commit was possible.
  Next audit target: reduce Phase 1 runtime or continue concrete backend kill-chain gaps: passive artifact/container/OCR coverage, provider-proof hardening, identity normalization, bounded worker migrations, and release/milestone test bundles.

- [x] Shell-history artifact-recursion checkpoint is green:
  `.venv\Scripts\python.exe -m py_compile forge\utils\artifact_shell_history.py forge\engagement_orchestrator.py tests\phase1\test_artifact_shell_history.py tests\phase1\test_engagement_orchestrator.py`
  `.venv\Scripts\python.exe -m ruff check forge\utils\artifact_shell_history.py forge\engagement_orchestrator.py tests\phase1\test_artifact_shell_history.py tests\phase1\test_engagement_orchestrator.py` -> `All checks passed!`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_artifact_shell_history.py tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_shell_history_artifacts -q --color=no` -> `31 passed`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py -q --color=no -k "shell_history_artifacts or shortcut_link_artifacts or windows_execution_history_artifacts or browser_navigation_artifacts"` -> `3 passed, 788 deselected`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py::test_kill_chain_artifact_extracted_assets_validate_and_seed_next_iteration_under_scope tests\phase6\test_report_synthesizer.py::test_synthesizer_runtime_provider_failure_falls_back_to_template tests\reporting\test_dashboard.py::test_generate_dashboard_emits_slug_routes_and_json_contract tests\reporting\test_dashboard.py::test_generate_dashboard_surfaces_provider_matrix_artifacts_and_validation_evidence tests\phase4\test_cloud_validate.py::test_sweep_pending_cloud_asset_validations_scope_checker_skips_denied_assets tests\phase4\test_attack_path.py::TestGraphBuildArtifacts::test_graph_build_all_writes_native_mtgx_workspace -q --color=no -m "slow or not slow"` -> `6 passed`
  Notes: shell-history artifact support was modularized into `forge/utils/artifact_shell_history.py`. It recognizes shell/REPL history artifacts such as `.bash_history`, `.zsh_history`, `ConsoleHost_history.txt`, PowerShell history cache names, MySQL, PostgreSQL, Redis, Mongo, SQLite, Python, Node, IRB, fish, ash, ksh, and sh histories. Existing bounded text extraction handles recursive URL/email/cloud promotion. Browser `History` remains generic `history`, and substring-style false positives stay unclassified.
  Claude review: first read-only Claude pass found missing helper coverage for DB/client REPL names; `tests/phase1/test_artifact_shell_history.py` was added. Final read-only Claude pass reported `No findings`. Output: `%TEMP%\forge-claude-shell-history-review.txt`.
  Safety: passive static parsing only. No shell command execution, shell-history replay, auth, live probing expansion, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change was added.
  Cleanup/commit: temp/test engagement DB cleanup left `remaining_test_like_engagement_dbs=0`. This workspace is not a git repo, so no commit was possible.
  Next audit target: reduce Phase 1 runtime, then continue concrete backend kill-chain gaps: passive artifact/container/OCR coverage, provider-proof hardening, identity normalization, bounded worker migrations, and release/milestone test bundles.

- [x] Pact-contract passive recursion checkpoint is green:
  `.venv\Scripts\python.exe -m py_compile forge\utils\artifact_pact.py forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `.venv\Scripts\python.exe -m ruff check forge\utils\artifact_pact.py forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py` -> `All checks passed!`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py::test_api_spec_and_client_collection_content_types_map_to_config_artifact_suffixes tests\phase1\test_engagement_orchestrator.py::test_artifact_pact_contract_payload_depth_guard_skips_deep_url_values tests\phase1\test_engagement_orchestrator.py::test_artifact_pact_contract_api_client_text_structured_payload_uses_bounded_workers_and_preserves_order tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_pact_contract_artifacts -q --color=no` -> `4 passed`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py -q --color=no -k "pact_contract or pactum or pyresttest or dredd or schemathesis or api_client_text_structured_payload or api_spec_and_client_collection_content_types"` -> `16 passed, 774 deselected`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_api_spec_and_client_collection_artifacts -q --color=no` -> `1 passed`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py::test_kill_chain_artifact_extracted_assets_validate_and_seed_next_iteration_under_scope tests\phase6\test_report_synthesizer.py::test_synthesizer_runtime_provider_failure_falls_back_to_template tests\reporting\test_dashboard.py::test_generate_dashboard_emits_slug_routes_and_json_contract tests\reporting\test_dashboard.py::test_generate_dashboard_surfaces_provider_matrix_artifacts_and_validation_evidence tests\phase4\test_cloud_validate.py::test_sweep_pending_cloud_asset_validations_scope_checker_skips_denied_assets tests\phase4\test_attack_path.py::TestGraphBuildArtifacts::test_graph_build_all_writes_native_mtgx_workspace -q --color=no -m "slow or not slow"` -> `6 passed`
  Notes: Pact contract artifact support was modularized into `forge/utils/artifact_pact.py`. It handles exact Pact filenames, Pact MIME aliases, scoped Pact directories, extensionless broker exports, provider/broker/interaction/message URL extraction, URL-like provider-state params, emails, and cloud refs while filtering templated URLs and known false positives.
  Claude review: final read-only Claude pass reported no findings after fixes for overbroad substring matching, generic `pacts/LICENSE`, depth guard coverage, and message/negative tests. Output: `%TEMP%\forge-claude-pact-review-final.txt`. A follow-up checkpoint/doc review also reported `No findings`; output: `%TEMP%\forge-claude-pact-doc-review-final.txt`.
  Safety: passive static parsing only. No Pact execution, broker calls, auth, live probing, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change was added.
  Cleanup/commit: temp/test engagement DB cleanup left `remaining_test_like_engagement_dbs=0`. This workspace is not a git repo, so no commit was possible.
  Next audit target: reduce Phase 1 runtime, then continue only concrete backend kill-chain gaps: passive artifact/container/OCR coverage, provider-proof hardening, identity normalization, bounded worker migrations, and release/milestone test bundles.

- [x] Stripe stored-proof parity checkpoint is green:
  `.venv\Scripts\python.exe -m py_compile forge\utils\validation_proof.py tests\core\test_validation_proof.py`
  `.venv\Scripts\python.exe -m ruff check forge\utils\validation_proof.py tests\core\test_validation_proof.py` -> `All checks passed!`
  `.venv\Scripts\python.exe -m pytest tests\core\test_validation_proof.py -q --color=no -k "stripe or stable_profile_provider_proofs or downgrades_low_signal"` -> `62 passed, 10 deselected`
  `.venv\Scripts\python.exe -m pytest tests\core\test_validation_proof.py -q --color=no` -> `72 passed`
  `.venv\Scripts\python.exe -m pytest tests\phase4\test_cloud_validate.py -q --color=no -k "stripe or validation_identifier"` -> `5 passed, 131 deselected`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py::test_kill_chain_artifact_extracted_assets_validate_and_seed_next_iteration_under_scope tests\phase6\test_report_synthesizer.py::test_synthesizer_runtime_provider_failure_falls_back_to_template tests\reporting\test_dashboard.py::test_generate_dashboard_emits_slug_routes_and_json_contract tests\reporting\test_dashboard.py::test_generate_dashboard_surfaces_provider_matrix_artifacts_and_validation_evidence tests\phase4\test_cloud_validate.py::test_sweep_pending_cloud_asset_validations_scope_checker_skips_denied_assets tests\phase4\test_attack_path.py::TestGraphBuildArtifacts::test_graph_build_all_writes_native_mtgx_workspace -q --color=no -m "slow or not slow"` -> `6 passed`
  Notes: shared stored `VALIDATED:stripe_balance_api` parsing now matches Phase 4 and requires `mode=live`, stable currencies, and explicit `balances=available:X,pending:Y`. Stale `mode=test` and live-without-balance details now downgrade to `UNVERIFIED`.
  Safety: deterministic stored-proof parity only. No new Stripe endpoint, validation-call expansion, proxy/IP rotation, rate-limit bypass, scope relaxation, or severity-rule change was added.
  Next audit target: continue concrete provider-proof hardening or switch to passive artifact/container parser coverage or Phase 1 runtime trimming.

- [x] SendGrid scope-proof hardening checkpoint is green:
  `.venv\Scripts\python.exe -m py_compile forge\utils\intel\secret_finder.py forge\phase4\cloud_validate.py forge\utils\validation_proof.py tests\phase2\test_secret_finder.py tests\phase2\test_key_scanner.py tests\phase4\test_cloud_validate.py tests\core\test_validation_proof.py tests\integration\test_engagement_pipeline.py`
  `.venv\Scripts\python.exe -m ruff check forge\utils\intel\secret_finder.py forge\phase4\cloud_validate.py forge\utils\validation_proof.py tests\phase2\test_secret_finder.py tests\phase2\test_key_scanner.py tests\phase4\test_cloud_validate.py tests\core\test_validation_proof.py tests\integration\test_engagement_pipeline.py` -> `All checks passed!`
  `.venv\Scripts\python.exe -m pytest tests\phase4\test_cloud_validate.py::test_non_cloud_validation_identifier_parser_rejects_low_signal_success_details tests\core\test_validation_proof.py -q --color=no -k "sendgrid or stable_profile_provider_proofs or rejects_low_signal" tests\phase2\test_secret_finder.py::test_sendgrid_validator_non_empty_scope_list_is_active_without_scope_names` -> `27 passed, 44 deselected`
  `.venv\Scripts\python.exe -m pytest tests\phase2\test_secret_finder.py tests\phase2\test_key_scanner.py tests\phase4\test_cloud_validate.py tests\core\test_validation_proof.py -q --color=no -k "sendgrid or slack or proof or validation_identifier"` -> `125 passed, 312 deselected`
  `.venv\Scripts\python.exe -m pytest tests\integration\test_engagement_pipeline.py::test_end_to_end_engagement_pipeline_mixes_key_validators_cloud_asset_and_template_fallback -q --color=no` -> `1 passed`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py::test_kill_chain_artifact_extracted_assets_validate_and_seed_next_iteration_under_scope tests\phase6\test_report_synthesizer.py::test_synthesizer_runtime_provider_failure_falls_back_to_template tests\reporting\test_dashboard.py::test_generate_dashboard_emits_slug_routes_and_json_contract tests\reporting\test_dashboard.py::test_generate_dashboard_surfaces_provider_matrix_artifacts_and_validation_evidence tests\phase4\test_cloud_validate.py::test_sweep_pending_cloud_asset_validations_scope_checker_skips_denied_assets tests\phase4\test_attack_path.py::TestGraphBuildArtifacts::test_graph_build_all_writes_native_mtgx_workspace -q --color=no -m "slow or not slow"` -> `6 passed`
  Notes: SendGrid scope validation now emits `scope_hash=<16 hex>` instead of accepting count-only scope proof. Phase 4 and shared report/dashboard proof parsing require that hash, so stale `SendGrid scopes accessible: count=2` details downgrade to `UNVERIFIED`; scope names are still not exposed. A stale positive Slack fixture now uses current mixed-ID proof.
  Safety: deterministic proof gating only. No new provider endpoint, validation-call expansion, scope relaxation, proxy/IP rotation, rate-limit bypass, severity-rule change, or credential exposure was added.
  Cleanup/commit: only persistent workspace artifacts were observed in `.forge_data`; no pytest temp engagement DB was deleted. This workspace is not a git repo, so no commit was attempted.
  Next audit target: continue provider-proof hardening where concrete low-signal gaps exist, or switch to passive artifact/container parser coverage or Phase 1 runtime trimming.

- [x] Cron/scheduler artifact-recursion checkpoint is green:
  `.venv\Scripts\python.exe -m py_compile forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `.venv\Scripts\python.exe -m ruff check forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py` -> `All checks passed!`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_scheduler_cron_artifacts -q --color=no` -> `1 passed`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py -q --color=no -k "scheduler_cron_artifacts or procfile_variant_artifacts or script_and_infra_config_artifacts or ci_cd_workflow_metadata_artifacts or source_control_ignore_artifacts"` -> `5 passed, 782 deselected`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py -q --color=no -k "scheduler_cron_artifacts or classify_remote_artifact_url or content_types_map_to"` -> `19 passed, 768 deselected`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_ide_workspace_metadata_artifacts tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_parallelizes_per_payload_structured_extractors_and_preserves_order tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_parallelizes_structured_discovery_payload_entries_and_preserves_order -q --color=no` -> `3 passed`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py --collect-only -q --color=no` -> `752/787 tests collected (35 deselected)`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py -q --color=no --durations=20` -> `752 passed, 35 deselected in 831.88s`
  Notes: `crontab`, `anacrontab`, `*.cron`, `cron.d/<job>`, `cron.daily/<job>`, and `spool/cron/<user>` now classify as passive `cron-config` artifacts. Remote `/etc/cron.d/<job>` downloads keep a `.cron` filename so metadata stays reviewable. Existing static extraction promotes embedded owner emails, sanitized URLs, Firebase/Supabase refs, S3 buckets, and GCS buckets into recursive seeds/cloud assets.
  Safety: passive static parsing only. No cron execution, service start, authentication, provider call, live probing, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change was added.
  Runtime caveat: full default Phase 1 is green now, but still slow at 13:51. Keep runtime reduction open.
  Cleanup/commit: no pytest temp engagement DB was created by this pass. Persistent `.forge_data\tmp_attack_backup_20260426.db` was observed but not deleted because it predates this run and is not clearly a temp pytest DB. This workspace is not a git repo, so no commit was attempted.
  Next audit target: reduce Phase 1 runtime or continue another concrete passive parser/provider-proof/identity normalization gap with focused tests.

- [x] OSINT dependency isolation checkpoint is green:
  `.venv\Scripts\python.exe -m py_compile bootstrap.py forge\utils\intel\tool_paths.py forge\utils\intel\handle_finder.py forge\utils\intel\google_account.py forge\utils\intel\phone_lookup.py tests\phase2\test_tool_paths.py tests\core\test_bootstrap_osint_isolation.py tests\phase2\test_name_search.py`
  `.venv\Scripts\python.exe -m ruff check bootstrap.py forge\utils\intel\tool_paths.py forge\utils\intel\handle_finder.py forge\utils\intel\google_account.py forge\utils\intel\phone_lookup.py tests\phase2\test_tool_paths.py tests\core\test_bootstrap_osint_isolation.py tests\phase2\test_name_search.py` -> `All checks passed!`
  `.venv\Scripts\python.exe -m pytest tests\phase2 -q --color=no` -> `695 passed in 164.53s`
  `python bootstrap.py --venv-mode project setup --check-only` -> dependency preflight passed
  `.venv\Scripts\python.exe -m pip check` -> `No broken requirements found.`
  Notes: GHunt, Maigret, theHarvester, Sherlock, and Holehe resolve from isolated per-tool venvs by default. This avoids incompatible CLI dependency pins in the main Forge runtime while keeping command discovery operator-friendly through PATH and `FORGE_<TOOL>_VENV` overrides.
  Defender: `C:\Program Files\Python312\Lib\site-packages\impacket\smbconnection.py` remains absent/quarantined, but Forge's `.venv` Impacket copy exists and imports. Do not add a broad Defender exclusion for global Python.
  Safety: dependency/path isolation only. No provider calls, live probing, target expansion, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, report-gate change, or Defender exclusion was added.
  Cleanup/commit: pytest temp engagement data is clean; persistent `.forge_data\1001_backup_20260705T015420.db` and `.forge_data\engagements\1|5010` were inspected but not deleted because they are workspace artifacts, not temp pytest DBs. This workspace is not a git repo, so no commit was attempted.
  Next audit target: continue concrete backend kill-chain gaps: provider-specific proof depth, identity/provider normalization, passive artifact/container parser coverage, safe bounded-worker migrations, and broader end-to-end fixtures.

- [x] Artifact optional dependency/setup reliability checkpoint is green:
  `.venv\Scripts\python.exe -m py_compile bootstrap.py tests\phase1\test_engagement_orchestrator.py`
  `.venv\Scripts\python.exe -m ruff check bootstrap.py tests\phase1\test_engagement_orchestrator.py` -> `All checks passed!`
  `.venv\Scripts\python.exe -m pip install -e ".[artifacts]"` -> installed/confirmed `py7zr`, `zstandard`, `brotli`, and `lz4`
  `.venv\Scripts\python.exe -c "import zstandard, brotli, lz4.frame, py7zr; print('artifact_optional_imports_ok')"` -> `artifact_optional_imports_ok`
  `.venv\Scripts\python.exe -m pytest tests\phase1\test_engagement_orchestrator.py -q --color=no -k "bzip2_txz_and_buried_xz or zstd_tzst_and_buried_zst or brotli_and_tar_brotli or lz4_config"` -> `4 passed, 782 deselected`
  `python bootstrap.py --venv-mode project setup --check-only` -> dependency preflight passed
  Notes: `pyproject.toml` now exposes an `artifacts` extra, `bootstrap.py` falls back to pyproject editable installs when legacy requirements files are absent, and `setup.bat` targets the project `.venv` used by Windows launchers. The stdlib bzip2/xz regression no longer depends on optional zstd availability.
  Safety: passive artifact dependency/setup reliability only. No live probing, provider calls, tool execution, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, Defender exclusion, or report-gate change was added.
  Cleanup/commit: temp `.forge_data` is absent/clean, scoped workspace test engagement DB scan returned `remaining_test_engagement_dbs=0`, and this workspace is intentionally not a git repo, so no commit was attempted.
  Follow-up resolved by the OSINT dependency isolation checkpoint above.

- [x] Epieos Discord identity normalization checkpoint is green:
  `python -m py_compile forge\utils\intel\social_scraper.py tests\phase2\test_social_scraper.py`
  `python -m ruff check forge\utils\intel\social_scraper.py tests\phase2\test_social_scraper.py` -> `All checks passed!`
  `python -m pytest tests\phase2\test_social_scraper.py -q --color=no -k "discord_user_and_invite"` -> `1 passed, 68 deselected`
  `python -m pytest tests\phase2\test_social_scraper.py -q --color=no -k "discord_user_and_invite or additional_profile_urls or host_checked_profile_url_aliases or root_profile_containers or app_profile"` -> `4 passed, 65 deselected`
  `python -m pytest tests\phase1\test_engagement_orchestrator.py -q --color=no -k "discord_social_hosts or social_profile_platform_hint or app_link_aliases"` -> `3 passed, 782 deselected`
  `python -m pytest tests\phase2\test_social_scraper.py -q --color=no` -> `69 passed`
  Notes: `_parse_epieos_response()` now preserves Discord user/invite/community payloads as conservative profile evidence: `discord.com/users/<numeric snowflake>` from stable user IDs and `discord.gg` / `discord.com/invite` URLs from explicit invite codes or URLs. It does not fabricate Discord public URLs from plain usernames, and invite/community rows do not become username pivots.
  Safety: no Discord API call, provider call, live probing, scope relaxation, proxy/IP rotation, rate-limit bypass, provider pacing change, destructive behavior, or report-gate change was added.
  Cleanup/commit: temp `.forge_data` is absent/clean, scoped workspace test engagement DB scan returned `remaining_test_engagement_dbs=0`, and this workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue identity normalization only for concrete missing provider payload shapes, otherwise move to provider-proof hardening, passive parser coverage, or Phase 1 runtime reduction.

- [x] Windows report launcher venv/runtime reliability checkpoint is green:
  `python -m py_compile tests\core\test_windows_launchers.py`
  `python -m ruff check tests\core\test_windows_launchers.py`
  `python -m pytest tests\core\test_windows_launchers.py -q --color=no` -> `2 passed`
  `.venv\Scripts\python.exe -c "from pathlib import Path; import sys; pattern='engagement_' + sys.argv[1] + '_report_*.md'; reports=sorted(Path('reports').glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True); [print(p.name) for p in reports[:3]]" "1001"` -> listed `engagement_1001_report_20260704T161714.md`
  Notes: `forge-report.bat` no longer uses Unix-only `head`; it uses the project venv Python to list newest reports after generation. Regression coverage proves root Windows launchers stay `.venv\Scripts\...` bound and report listing does not reintroduce `head`.
  Safety: no Defender exclusion, global Python dependency, provider call, live probing, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, or report-gate change was added.
  Cleanup/commit: temp `.forge_data` cleanup and workspace engagement DB scan are clean, and this workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue safe artifact/parser coverage, provider-proof hardening, identity normalization, or Phase 1 runtime reduction based on concrete evidence.

- [x] Social-profile app-link alias recursion checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests\phase1\test_engagement_orchestrator.py::test_synthesis_engine_promotes_social_profile_app_link_aliases_to_identity_pivots -q --color=no` -> `1 passed`
  `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "app_link_aliases or linkedin_app_links_to_identity_pivots or social_app_profile_uri_handles or url_parser_supports_linkedin_company" -q --color=no` -> `3 passed, 782 deselected`
  `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "social_profile_url_parser or promotes_confirmed_username_profiles or social_profile_anchor or derives_social_profile_seeds or infers_social_profile_platforms_from_url_alias_fields" -q --color=no` -> `18 passed, 767 deselected`
  `python -m pytest tests\phase2\test_social_scraper.py -k "explicit_profile_urls_reuse_recursive_handle_rules or direct_handle_fields_are_normalized or linkedin_company" -q --color=no` -> `3 passed, 65 deselected`
  Notes: `social_profiles.profile_data` now treats app/deep-link aliases such as `deep_link`, `appUrl`, `nativeUrl`, and list forms like `app_links` as URL hints for platform inference, handle extraction, raw-link traversal, nested link containers, and LinkedIn/Facebook-style name derivation. App URIs still are not persisted as URL seeds.
  Safety: no app execution, provider call, extra live probing, app URI URL seed persistence, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, provider pacing change, or report-gate change was added.
  Cleanup/commit: temp `.forge_data` cleanup and workspace engagement DB scan are clean, and this workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue identity normalization/provider coverage only for concrete missing source shapes, otherwise move to provider-proof hardening, bounded-worker migration, or Phase 1 runtime reduction.

- [x] Confirmed username-profile app URI recursion checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests\phase1\test_engagement_orchestrator.py::test_synthesis_engine_uses_social_app_profile_uri_handles_for_confirmed_username_profiles -q --color=no` -> `1 passed`
  `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "confirmed_username_profiles or social_app_profile_uri_handles or linkedin_app_links_to_identity_pivots or url_parser_supports_linkedin_company" -q --color=no` -> `3 passed, 781 deselected`
  `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "social_profile_url_parser or promotes_confirmed_username_profiles or social_profile_anchor or derives_social_profile_seeds" -q --color=no` -> `17 passed, 767 deselected`
  `python -m pytest tests\phase2\test_social_scraper.py -k "explicit_profile_urls_reuse_recursive_handle_rules or direct_handle_fields_are_normalized or linkedin_company" -q --color=no` -> `3 passed, 65 deselected`
  Notes: confirmed `username_profiles` rows now derive handles from recognized social app/deep-link profile URIs when an HTTP profile URL is unavailable. Known app routes without a profile handle are skipped instead of promoting stale/generic row usernames.
  Safety: no app execution, provider call, extra live probing, app URI URL seed persistence, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, provider pacing change, or report-gate change was added.
  Cleanup/commit: removed three pytest temp `.forge_data` directories, workspace engagement DB scan is clean, and this workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue identity normalization/provider coverage only for concrete missing source shapes, otherwise move to provider-proof hardening, bounded-worker migration, or Phase 1 runtime reduction.

- [x] Static-hosting control-file recursion checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py forge\phase4\cloud_validate.py tests\phase1\test_engagement_orchestrator.py tests\phase4\test_cloud_validate.py`
  `python -m ruff check forge\engagement_orchestrator.py forge\phase4\cloud_validate.py tests\phase1\test_engagement_orchestrator.py tests\phase4\test_cloud_validate.py`
  `python -m pytest tests\phase1\test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_static_hosting_control_files -q --color=no` -> `1 passed`
  `python -m pytest tests\phase1\test_engagement_orchestrator.py::test_classify_seed_value_recognizes_archive_style_mobile_bundle_urls tests\phase1\test_engagement_orchestrator.py::test_api_spec_and_client_collection_content_types_map_to_config_artifact_suffixes -q --color=no` -> `2 passed`
  `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "static_hosting_control_files or classify_seed_value_recognizes_archive_style_mobile_bundle_urls or api_spec_and_client_collection_content_types_map_to_config_artifact_suffixes or heroku_static_deploy_config_artifacts or deploy_platform_config_artifacts" -q --color=no` -> `5 passed, 778 deselected`
  `python -m pytest tests\phase4\test_cloud_validate.py::test_static_site_helper_recognizes_framework_build_artifacts -q --color=no` -> `1 passed`
  `python -m pytest tests\phase4\test_cloud_validate.py -k "framework_build_artifacts or hosting_config_static_site_listing or static_site_only_listing" -q --color=no` -> `6 passed, 130 deselected`
  Notes: `_redirects`, `_headers`, and `_routes.json` now classify as passive config artifacts and keep source-aware labels. Source-gated parsing resolves redirect/header/route entries into recursive URL seeds against remote source URLs, strips sensitive query parameters, and preserves Firebase cloud-asset extraction.
  Safety: passive static parsing only. No hosting-rule execution, app deployment, provider calls, redirect replay, authentication, unscoped probing, proxy/IP rotation, rate-limit bypass, scope relaxation, destructive behavior, or report-gate change was added.
  Cleanup/commit: pytest temp `.forge_data` cleanup is green; this workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue passive parser coverage only for a concrete missing source shape, otherwise move to provider-proof hardening, bounded-worker migration, or Phase 1 runtime reduction.

- [x] Heroku/static deploy config recursion checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py forge\phase4\cloud_validate.py tests\phase1\test_engagement_orchestrator.py tests\phase4\test_cloud_validate.py`
  `python -m ruff check forge\engagement_orchestrator.py forge\phase4\cloud_validate.py tests\phase1\test_engagement_orchestrator.py tests\phase4\test_cloud_validate.py`
  `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "heroku_static_deploy_config_artifacts or deploy_platform_config_artifacts or bare_managed_hosting_config_hosts" -q --color=no` -> `3 passed, 779 deselected`
  `python -m pytest tests\phase1\test_engagement_orchestrator.py::test_api_spec_and_client_collection_content_types_map_to_config_artifact_suffixes -q --color=no` -> `1 passed`
  `python -m pytest tests\phase4\test_cloud_validate.py -k "framework_build_artifacts or pages_managed_hosting_assets or managed_hosting" -q --color=no` -> `2 passed, 134 deselected`
  Notes: explicit Heroku manifests (`heroku.yml|yaml`, source-gated `heroku/app.json`, `heroku-app.json`) and `static.json` now keep source-aware labels. Heroku app JSON nested `env.KEY.value` maps now feed bounded recursive extraction. `*.herokuapp.com` URLs persist as `heroku` cloud assets and route into scoped non-intrusive managed-hosting validation without creating findings.
  Safety: passive static parsing plus existing read-only managed-hosting reachability validation only. No Heroku CLI/buildpack execution, app deployment, secret loading, authentication, provider calls in tests, unscoped probing, proxy/IP rotation, rate-limit bypass, scope relaxation, destructive behavior, or report-gate change was added.
  Cleanup/commit: pytest temp `.forge_data` cleanup is green; this workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue passive parser coverage only for a concrete missing source shape, otherwise move to provider-proof hardening, bounded-worker migration, or Phase 1 runtime reduction.

- [x] Deploy-platform managed-hosting config recursion checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py forge\phase4\cloud_validate.py tests\phase1\test_engagement_orchestrator.py tests\phase4\test_cloud_validate.py`
  `python -m ruff check forge\engagement_orchestrator.py forge\phase4\cloud_validate.py tests\phase1\test_engagement_orchestrator.py tests\phase4\test_cloud_validate.py`
  `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "deploy_platform_config_artifacts or bare_managed_hosting_config_hosts or frontend_framework_config" -q --color=no` -> `3 passed, 778 deselected`
  `python -m pytest tests\phase4\test_cloud_validate.py::test_static_site_helper_recognizes_framework_build_artifacts tests\phase4\test_cloud_validate.py::test_sweep_pending_cloud_asset_validations_processes_pages_managed_hosting_assets -q --color=no` -> `2 passed`
  `python -m pytest tests\phase4\test_cloud_validate.py -k "pages_managed_hosting_assets or framework_build_artifacts or managed_hosting" -q --color=no` -> `2 passed, 134 deselected`
  Notes: Render, Fly.io, Railway, Azure Static Web Apps, Firebase App Hosting, and Amplify deployment config artifacts now keep source-aware labels. YAML env-list parsing accepts `key/value` and `variable/value` forms. Render/Fly/Railway/Azure Static Web Apps URLs persist as provider-specific cloud assets and route into scoped non-intrusive managed-hosting validation without creating findings.
  Safety: passive static parsing plus existing read-only managed-hosting reachability validation only. No deploy CLI execution, app deployment, secret loading, authentication, provider calls in tests, unscoped probing, proxy/IP rotation, rate-limit bypass, scope relaxation, destructive behavior, or report-gate change was added.
  Cleanup/commit: pytest temp `.forge_data` cleanup is green; this workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue passive parser coverage only for a concrete missing source shape, otherwise move to provider-proof hardening, bounded-worker migration, or Phase 1 runtime reduction.

- [x] Developer env/secret-manager config artifact-recursion checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "developer_env_secret_manager" -q --color=no` -> `1 passed, 779 deselected`
  `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "structured_yaml_cloud_assets or structured_key_value_config_cloud_assets or developer_env_secret_manager or structured_json_config_cloud_assets" -q --color=no` -> `4 passed, 776 deselected`
  `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "parallelizes_key_value or key_value_structured" -q --color=no` -> `6 passed, 774 deselected`
  Notes: `.envrc`/`envrc`, mise, Doppler, and Infisical config artifacts now retain source-aware labels (`direnv`, `mise-config`, `doppler-config`, `infisical-config`). `.envrc` `export KEY=value` assignments now feed the existing bounded key-value parser. Regression coverage proves these artifacts promote Firebase, Supabase, S3, GCS, Azure Blob, DigitalOcean Spaces, email, and sanitized URL pivots without preserving URL userinfo or sensitive `token` query values.
  Safety: passive static parsing only. No direnv/mise/Doppler/Infisical execution, secret loading, authentication, provider calls, live probing, proxy/IP rotation, rate-limit bypass, scope relaxation, destructive behavior, or report-gate change was added.
  Cleanup/commit: pytest temp `.forge_data` cleanup is green; this workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue passive parser coverage only for a concrete missing source shape, otherwise move to provider-proof hardening or Phase 1 runtime reduction. Slow kill-chain tests are deselected by default through pyproject `-m "not chaos and not slow"` unless explicitly overridden.

- [x] Gitpod workspace config artifact-recursion checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "build_system" -q --color=no` -> `1 passed, 778 deselected`
  `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "build_system or devcontainer or docker_bake or cloudbuild or circleci or workflow_manifest or container_image" -q --color=no` -> `6 passed, 773 deselected`
  Notes: `.gitpod.yml`, `.gitpod.yaml`, `gitpod.yml`, and `gitpod.yaml` artifacts now retain `gitpod` source labels. Source-gated parsing promotes explicit-registry `image:` values and `additionalRepositories` GitHub/GitLab/Bitbucket refs into recursive URL seeds; existing passive YAML/raw extraction still handles owner emails, sanitized URLs, Firebase, Supabase, and S3 refs.
  Safety: passive static parsing only. No Gitpod workspace launch, task execution, container build/pull, repo clone, authentication, provider call, live probing, proxy/IP rotation, rate-limit bypass, scope relaxation, destructive behavior, report-gate change, or persistent non-test DB mutation was added.
  Cleanup/commit: pytest temp `.forge_data` cleanup is green; this workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue passive parser coverage only for a concrete missing source shape, otherwise move to provider-proof hardening or Phase 1 runtime reduction.

- [x] Shared provider-ID stored-proof parser parity checkpoint is green:
  `python -m py_compile forge\utils\validation_proof.py tests\core\test_validation_proof.py`
  `python -m ruff check forge\utils\validation_proof.py tests\core\test_validation_proof.py`
  `python -m pytest tests\core\test_validation_proof.py -q --color=no` -> `66 passed`
  `python -m pytest tests\phase1\test_deterministic_findings.py tests\reporting\test_dashboard.py tests\phase6\test_report_synthesizer.py -k "validation or proof or deterministic_findings or dashboard or synthesizer" -q --color=no` -> `100 passed`
  Notes: shared stored validation-detail parsing now rejects tokenized placeholders and sequential numeric provider-ID tokens such as `user_test`, `netlify-placeholder`, `demo-user`, `test-user`, `usr_123456`, and sequential UUID-like Notion IDs, matching scanner/Phase 4 parity.
  Safety: stored-proof parser hardening only. No endpoint expansion, extra live validation calls, provider calls, proxy/IP rotation, rate-limit bypass, scope relaxation, destructive behavior, or severity-rule changes were added.
  Cleanup/commit: pytest temp `.forge_data` cleanup is green; this workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue stored-proof parity review where scanner/Phase 4 are stricter than shared report/dashboard parsing, otherwise continue passive artifact/container parsing or Phase 1 runtime reduction.

- [x] Slack stored-proof parser parity checkpoint is green:
  `python -m py_compile forge\utils\validation_proof.py tests\core\test_validation_proof.py`
  `python -m ruff check forge\utils\validation_proof.py tests\core\test_validation_proof.py`
  `python -m pytest tests\core\test_validation_proof.py -q --color=no` -> `60 passed`
  `python -m pytest tests\phase1\test_deterministic_findings.py tests\reporting\test_dashboard.py tests\phase6\test_report_synthesizer.py -k "validation or proof or deterministic_findings or dashboard or synthesizer" -q --color=no` -> `100 passed`
  Notes: shared stored `VALIDATED:slack_auth_test` parsing now rejects sequential numeric actor/team IDs such as `U1234567` and `T7654321`, matching scanner/Phase 4 proof hardening. Mixed alphanumeric Slack IDs remain valid.
  Safety: stored-proof parser hardening only. No endpoint expansion, extra live validation calls, provider calls, proxy/IP rotation, rate-limit bypass, scope relaxation, destructive behavior, or severity-rule changes were added.
  Cleanup/commit: pytest temp `.forge_data` cleanup is green; this workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: keep tightening provider-specific stored-proof parity where scanner/Phase 4 are stricter than shared report/dashboard parsing, otherwise continue passive artifact/container parsing or Phase 1 runtime reduction.

- [x] Datadog stored-proof parser parity checkpoint is green:
  `python -m py_compile forge\utils\validation_proof.py tests\core\test_validation_proof.py`
  `python -m ruff check forge\utils\validation_proof.py tests\core\test_validation_proof.py`
  `python -m pytest tests\core\test_validation_proof.py -q --color=no` -> `59 passed`
  `python -m pytest tests\phase1\test_deterministic_findings.py tests\reporting\test_dashboard.py tests\phase6\test_report_synthesizer.py -k "validation or proof or deterministic_findings or dashboard or synthesizer" -q --color=no` -> `100 passed`
  Notes: shared stored `VALIDATED:datadog_api_key_validate` parsing now requires `proof=valid_true` plus an allowed Datadog site, matching Phase 4 sweep parsing. Stale site-only Datadog proof downgrades to `UNVERIFIED` for dashboard/report/deterministic finding consumers.
  Safety: stored-proof parser hardening only. No endpoint expansion, extra live validation calls, provider calls, proxy/IP rotation, rate-limit bypass, scope relaxation, destructive behavior, or severity-rule changes were added.
  Cleanup/commit: pytest temp `.forge_data` cleanup is green; this workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: keep tightening provider-specific proof/decoy heuristics where a concrete low-signal success gap is found, otherwise continue passive artifact/container parsing or Phase 1 runtime reduction.

- [x] Google/Gemini model-list proof hardening checkpoint is green:
  `python -m py_compile forge\utils\intel\secret_finder.py forge\utils\validation_proof.py forge\phase4\cloud_validate.py tests\phase2\test_secret_finder.py tests\phase4\test_cloud_validate.py tests\core\test_validation_proof.py`
  `python -m ruff check forge\utils\intel\secret_finder.py forge\utils\validation_proof.py forge\phase4\cloud_validate.py tests\phase2\test_secret_finder.py tests\phase4\test_cloud_validate.py tests\core\test_validation_proof.py`
  `python -m pytest tests\phase2\test_secret_finder.py tests\phase4\test_cloud_validate.py tests\core\test_validation_proof.py -k "google_api_key_validator or model_list_proof or google_generative_language_models_list or parse_validated_detail_preserves_stable_profile_provider_proofs or parse_validated_detail_downgrades_low_signal_profile_provider_proofs" -q --color=no` -> `52 passed, 310 deselected`
  `python -m pytest tests\phase2\test_secret_finder.py -q --color=no` -> `168 passed`
  `python -m pytest tests\core\test_validation_proof.py -q --color=no` -> `58 passed`
  `python -m pytest tests\phase4\test_cloud_validate.py -k "google or model_list or provider_family" -q --color=no` -> `2 passed, 134 deselected`
  Notes: Google/Gemini model-list proof now requires a stable `models/<known-google-family>` sample across scanner-time validation, Phase 4 sweep parsing, and stored-detail proof parsing. Arbitrary `models/vendor-model-alpha` proof stays `UNCONFIRMED`/`UNVERIFIED` and does not create deterministic report findings.
  Safety: proof-shape hardening only. No endpoint expansion, extra live validation calls, provider calls in tests, proxy/IP rotation, rate-limit bypass, scope relaxation, destructive behavior, or severity-rule changes were added.
  Cleanup/commit: pytest temp `.forge_data` cleanup is green; this workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: keep tightening provider-specific proof/decoy heuristics where a concrete low-signal success gap is found, otherwise continue passive artifact/container parsing or Phase 1 runtime reduction.

- [x] Browser storage-state artifact recursion checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "browser_state or browser_text_config or api_spec_and_client_collection_content_types" -q` -> `4 passed, 775 deselected`
  `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "browser_state or browser_text_config or json_structured or yaml_structured or structured_document_lines or browser_profile_artifact or WebCache" -q` -> `11 passed, 768 deselected`
  Notes: Playwright/Cypress/browser storage-state artifacts now keep `playwright-storage-state`, `cypress-env`, or `browser-storage-state` labels. Source-gated extraction promotes cookie domains, origins, URL/API host fields, and decoded local/sessionStorage JSON into recursive URL/email/cloud discovery while avoiding cookie/token value promotion.
  Safety: passive static parsing only. No browser replay, request execution, authentication, provider calls, probing, proxy/IP rotation, rate-limit bypass, scope relaxation, destructive behavior, or report-gate changes were added.
  Cleanup/commit: pytest temp `.forge_data` cleanup is green; this workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue passive parser coverage only for a concrete missing artifact/source shape, otherwise inspect passive-to-live validator handoff with mocks or reduce Phase 1 runtime.

- [x] CMS scanner output passive-recursion checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest -p no:rerunfailures tests\phase1\test_engagement_orchestrator.py -k "recon_tool_output_artifact_format_labels_are_source_aware or cms_scanner_outputs" -q` -> `2 passed, 774 deselected`
  `python -m pytest -p no:rerunfailures tests\phase1\test_engagement_orchestrator.py -k "recon_tool_output or dns_resolver_and_takeover_outputs or tech_waf_tls_scanner_outputs or cms_scanner_outputs or imported_scanner_json_outputs or screenshot_tool_outputs or passive_scan_output_artifacts or sarif_scan_artifacts or sbom_and_security_tool_output_artifacts" -q` -> `11 passed, 765 deselected`
  Notes: WPScan, CMSmap, Droopescan, JoomScan, and CMSeeK imported report outputs now keep source-aware labels. The recon-output extractor also accepts targetUrl/target_url, siteUrl/site_url, baseUrl/base_url, and scanUrl/scan_url style fields so CMS reports feed sanitized recursive URL/contact seeds.
  Safety: passive static parsing only. No CMS scanner execution, HTTP probing, authentication, provider calls, live probing, proxy/IP rotation, rate-limit bypass, scope relaxation, destructive behavior, or report-gate changes were added.
  Cleanup/commit: pytest temp `.forge_data` cleanup was completed separately; this workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue passive parser coverage only for a concrete missing tool/report shape, otherwise return to provider-proof hardening, bounded-worker migration, or Phase 1 runtime reduction.

- [x] Tech/WAF/TLS scanner output passive-recursion checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest -p no:rerunfailures tests\phase1\test_engagement_orchestrator.py -k "recon_tool_output_artifact_format_labels_are_source_aware or tech_waf_tls_scanner_outputs" -q` -> `2 passed, 773 deselected`
  `python -m pytest -p no:rerunfailures tests\phase1\test_engagement_orchestrator.py -k "recon_tool_output or dns_resolver_and_takeover_outputs or tech_waf_tls_scanner_outputs or imported_scanner_json_outputs or screenshot_tool_outputs or passive_scan_output_artifacts or sarif_scan_artifacts or sbom_and_security_tool_output_artifacts" -q` -> `10 passed, 765 deselected`
  Notes: WhatWeb, Wafw00f, SSLScan, testssl.sh, SSLyze, and RustScan imported report outputs now keep source-aware labels. The recon-output extractor also accepts target/targetHost/targetHostname/targets/uri keys so these passive reports can feed sanitized recursive URL/contact seeds.
  Safety: passive static parsing only. No scanner execution, HTTP/TLS probing, DNS queries, traffic replay, provider calls, authentication, live probing, proxy/IP rotation, rate-limit bypass, scope relaxation, destructive behavior, or report-gate changes were added.
  Cleanup/commit: pytest temp `.forge_data` cleanup was completed separately; this workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue passive parser coverage only for a concrete missing tool/report shape, otherwise return to provider-proof hardening or bounded-worker migration.

- [x] Recon-output bounded-worker normalization checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest -p no:rerunfailures tests\phase1\test_engagement_orchestrator.py::test_artifact_recon_tool_output_structured_payload_uses_bounded_workers_and_preserves_order -q` -> `1 passed`
  `python -m pytest -p no:rerunfailures tests\phase1\test_engagement_orchestrator.py -k "recon_tool_output or dns_resolver_and_takeover_outputs or imported_scanner_json_outputs or screenshot_tool_outputs or passive_scan_output_artifacts or sarif_scan_artifacts or sbom_and_security_tool_output_artifacts" -q` -> `9 passed, 765 deselected`
  `python -m pytest -p no:rerunfailures tests\phase1\test_engagement_orchestrator.py -k "structured_payload_uses_bounded_workers_and_preserves_order or recon_tool_output" -q` -> `25 passed, 749 deselected`
  Notes: `_recon_tool_output_structured_payload_text` now collects raw source-gated host/URL candidates and normalizes them through `_run_ordered_local_batch` via `_recon_tool_output_candidate_entry`, then dedupes in source order. This moves passive recon/scanner/DNS output normalization onto the same bounded worker path used by Maven/Gradle/API-client structured parsers.
  Safety: local static normalization only. No recon/scanner/DNS tool execution, traffic replay, provider calls, authentication, live probing, proxy/IP rotation, pacing change, scope relaxation, destructive behavior, or report-gate changes were added.
  Cleanup/commit: pytest temp `.forge_data` cleanup was completed separately; this workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue bounded-worker migration only for proven pure-local parsing/prep loops, otherwise switch to a concrete provider-proof hardening or passive parser gap.

- [x] DNS resolver/takeover output passive-recursion checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest -p no:rerunfailures tests\phase1\test_engagement_orchestrator.py -k "recon_tool_output or dns_resolver_and_takeover_outputs" -q` -> `3 passed, 770 deselected`
  `python -m pytest -p no:rerunfailures tests\phase1\test_engagement_orchestrator.py -k "recon_tool_output or dns_resolver_and_takeover_outputs or imported_scanner_json_outputs or screenshot_tool_outputs or passive_scan_output_artifacts or sarif_scan_artifacts or sbom_and_security_tool_output_artifacts" -q` -> `8 passed, 765 deselected`
  Notes: passive MassDNS, PureDNS, DNSRecon, DNSenum, Subjack, Subzy, and TKO-subs output files now keep source-aware labels. Source-gated structured extraction promotes JSON host/name/url fields, plain resolver host lines, and allowed XML tag values such as DNSenum `<url>` entries into recursive seeds while preserving DNS host-only lines as subdomain/IP pivots, sensitive-query stripping, and cloud-ref extraction.
  Safety: passive static parsing only. No DNS resolver execution, DNS queries, takeover scanner execution, traffic replay, provider calls, authentication, live probing, proxy/IP rotation, rate-limit bypass, scope relaxation, destructive behavior, or report-gate changes were added.
  Cleanup/commit: pytest temp `.forge_data` cleanup was completed separately; this workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue safe passive artifact/parser coverage only when a concrete missing source shape is found, otherwise switch to provider-proof hardening or Phase 1 runtime trimming.

- [x] Azure scanner-time account-proof parity checkpoint is green:
  `python -m py_compile forge\utils\intel\secret_finder.py tests\phase2\test_secret_finder.py`
  `python -m ruff check forge\utils\intel\secret_finder.py tests\phase2\test_secret_finder.py`
  `python -m pytest -p no:rerunfailures tests\phase2\test_secret_finder.py -k "azure_storage_connection_string_validator" -q` -> `4 passed, 163 deselected`
  `python -m pytest -p no:rerunfailures tests\phase4\test_cloud_validate.py -k "azure_placeholder_account_proof or azure_storage" -q` -> `1 passed, 135 deselected`
  `python -m pytest -p no:rerunfailures tests\phase2\test_secret_finder.py -q` -> `167 passed`
  Notes: `AzureStorageConnectionStringValidator` now rejects repeated/placeholder storage account names before signing or sending validation requests, matching the existing Phase 4 placeholder Azure proof downgrade.
  Safety: deterministic proof hardening only. No Azure endpoint expansion, provider-flow expansion, authentication expansion, live probing expansion, proxy/IP rotation, pacing changes, scope relaxation, destructive behavior, or report-gate relaxation was added.
  Cleanup/commit: pytest temp `.forge_data` cleanup was completed separately; this workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue provider-proof hardening only where a concrete low-signal proof gap is found, otherwise return to safe passive parser coverage or Phase 1 runtime trimming.

- [x] Screenshot-tool output passive-recursion checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest -p no:rerunfailures tests\phase1\test_engagement_orchestrator.py -k "recon_tool_output or imported_scanner_json_outputs or screenshot_tool_outputs" -q` -> `4 passed, 768 deselected`
  `python -m pytest -p no:rerunfailures tests\phase1\test_engagement_orchestrator.py -k "recon_tool_output or imported_scanner_json_outputs or screenshot_tool_outputs or passive_scan_output_artifacts or sarif_scan_artifacts or sbom_and_security_tool_output_artifacts" -q` -> `7 passed, 765 deselected`
  Notes: passive browser-screenshot/recon exports such as `gowitness-report.json`, `eyewitness-results.json`, and `aquatone-urls.txt` now keep source-aware labels. Their explicit URL/host fields and plain URL lines feed recursive URL seeds through the existing source-gated recon-output extractor.
  Safety: passive static parsing only. No screenshot tool execution, browser launch, traffic replay, provider calls, authentication, live probing, proxy/IP rotation, rate-limit bypass, scope relaxation, destructive behavior, or report-gate changes were added.
  Cleanup/commit: pytest temp `.forge_data` cleanup was completed separately; this workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue safe passive artifact/parser coverage only when a concrete missing source shape is found, otherwise switch to provider-proof hardening or Phase 1 runtime trimming.

- [x] Imported scanner JSON/JSONL passive-recursion checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest -p no:rerunfailures tests\phase1\test_engagement_orchestrator.py -k "recon_tool_output or imported_scanner_json_outputs" -q` -> `3 passed, 768 deselected`
  `python -m pytest -p no:rerunfailures tests\phase1\test_engagement_orchestrator.py -k "recon_tool_output or imported_scanner_json_outputs or passive_scan_output_artifacts or sarif_scan_artifacts or sbom_and_security_tool_output_artifacts" -q` -> `6 passed, 765 deselected`
  Notes: passive imported scanner report filenames such as `nuclei-results.jsonl`, `naabu-output.jsonl`, `ffuf-report.json`, `feroxbuster-results.json`, `dirsearch-report.json`, and `zap-scan.json` now keep source-aware labels. Their explicit matched/url/host/path/request/response fields feed recursive URL seeds through the existing source-gated recon-output extractor.
  Safety: passive static parsing only. No scanner execution, traffic replay, provider calls, authentication, live probing, proxy/IP rotation, rate-limit bypass, scope relaxation, destructive behavior, or report-gate changes were added.
  Cleanup/commit: pytest temp `.forge_data` cleanup was completed separately; this workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue safe passive artifact/parser coverage only when a concrete missing source shape is found, otherwise switch to provider-proof hardening or Phase 1 runtime trimming.

- [x] Recon-tool output passive-recursion checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest -p no:rerunfailures tests\phase1\test_engagement_orchestrator.py -k "recon_tool_output or passive_scan_output_artifacts" -q` -> `3 passed, 767 deselected`
  `python -m pytest -p no:rerunfailures tests\phase1\test_engagement_orchestrator.py -k "recon_tool_output or passive_scan_output_artifacts or sarif_scan_artifacts or sbom_and_security_tool_output_artifacts" -q` -> `5 passed, 765 deselected`
  Notes: passive Subfinder, Assetfinder, Findomain, Amass, dnsx, shuffledns, httpx, Katana, Gau, waybackurls, Hakrawler, and Gobuster output files now keep source-aware labels. Source-gated structured extraction promotes explicit host/url/endpoint fields and plain host/URL lines into recursive URL seeds while preserving sensitive-query stripping and existing cloud-ref extraction.
  Safety: passive static parsing only. No recon tool execution, traffic replay, provider calls, authentication, live probing, proxy/IP rotation, rate-limit bypass, scope relaxation, destructive behavior, or report-gate changes were added.
  Cleanup/commit: pytest temp `.forge_data` cleanup was completed separately; this workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue safe passive artifact/parser coverage only when a concrete missing source shape is found, otherwise switch to provider-proof hardening or Phase 1 runtime trimming.

- [x] SendGrid profile/scope proof hardening checkpoint is green:
  `python -m py_compile forge\utils\intel\secret_finder.py tests\phase2\test_secret_finder.py`
  `python -m ruff check forge\utils\intel\secret_finder.py tests\phase2\test_secret_finder.py`
  `python -m pytest -p no:rerunfailures tests\phase2\test_secret_finder.py -k "sendgrid_validator" -q` -> `11 passed, 153 deselected`
  `python -m pytest -p no:rerunfailures tests\phase2\test_secret_finder.py -q` -> `164 passed`
  `python -m pytest -p no:rerunfailures tests\phase4\test_cloud_validate.py -k "sendgrid or non_cloud_validation_identifier_parser_rejects_low_signal_success_details" -q` -> `3 passed, 133 deselected`
  `python -m pytest -p no:rerunfailures tests\phase4\test_cloud_validate.py -q` -> `136 passed`
  Notes: `SendgridKeyValidator` now rejects low-signal profile proof such as reserved/example emails and placeholder usernames before returning `ACTIVE`; profile proof hashes/flags are derived only from stable profile fields. The scope-list fallback now also requires at least one stable scope-shaped value internally while still omitting scope names from detail.
  Safety: deterministic proof hardening only. No endpoint expansion, provider-flow expansion, authentication expansion, live probing expansion, proxy/IP rotation, pacing changes, scope relaxation, destructive behavior, or report-gate relaxation was added.
  Cleanup/commit: pytest temp `.forge_data` cleanup was completed separately; this workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue provider-proof hardening only where a concrete low-signal proof gap is found, otherwise switch to Phase 1 runtime trimming or safe passive parser coverage.

- [x] Security scanner policy-config passive-recursion checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest -p no:rerunfailures tests\phase1\test_engagement_orchestrator.py -k "security_scanner_config_artifact_format_labels_are_source_aware or security_scanner_policy_configs" -q` -> `2 passed, 766 deselected`
  `python -m pytest -p no:rerunfailures tests\phase1\test_engagement_orchestrator.py -k "security_scanner_control_files or detect_secrets_baseline or security_scanner_policy_configs" -q` -> `3 passed, 765 deselected`
  `python -m pytest -p no:rerunfailures tests\phase1\test_engagement_orchestrator.py -k "security_scanner_control_files or repo_maintenance_config_artifacts or dependabot or renovate_json5 or sbom_and_security_tool_output_artifacts or security_scanner_policy_configs" -q` -> `4 passed, 764 deselected`
  Notes: passive CodeQL, Sonar, pre-commit, Trivy, Gitleaks, Semgrep, OSV Scanner, TruffleHog config, detect-secrets config, Secretlint config, Checkov, tfsec, Terrascan, KICS, and Nuclei config artifacts now keep source-aware labels. Scanner-config endpoint/repository host-only values, JSON config URL keys, and GCS/storage refs become recursive URL/cloud seeds through a source-gated static extractor.
  Safety: passive static parsing only. No scanner execution, hook execution, registry/provider calls, authentication, live probing, proxy/IP rotation, rate-limit bypass, scope relaxation, destructive behavior, or report-gate changes were added.
  Cleanup/commit: pytest temp `.forge_data` cleanup was completed separately; this workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue safe passive artifact/container/OCR parser coverage if a concrete missing source shape is found, otherwise switch to provider-proof hardening or Phase 1 runtime trimming.

- [x] Sequential provider-proof identifier hardening checkpoint is green:
  `python -m py_compile forge\utils\intel\secret_finder.py forge\phase4\cloud_validate.py tests\phase2\test_secret_finder.py tests\phase4\test_cloud_validate.py`
  `python -m ruff check forge\utils\intel\secret_finder.py forge\phase4\cloud_validate.py tests\phase2\test_secret_finder.py tests\phase4\test_cloud_validate.py`
  `python -m pytest -p no:rerunfailures tests\phase2\test_secret_finder.py::test_notion_token_validator_200_with_sequential_uuid_stays_unconfirmed tests\phase2\test_secret_finder.py::test_posthog_personal_api_key_validator_sequential_uuid_stays_unconfirmed tests\phase4\test_cloud_validate.py::test_non_cloud_validation_identifier_parser_rejects_low_signal_success_details -q` -> `3 passed`
  `python -m pytest -p no:rerunfailures tests\phase2\test_secret_finder.py tests\phase4\test_cloud_validate.py -q` -> `296 passed`
  Notes: shared provider-proof helpers now reject obviously sequential numeric UUID/opaque identifiers such as `12345678-9012-3456-7890-123456789012` before returning `ACTIVE` or upgrading stale validation detail to `VALIDATED`. This hardens Notion users/me proof, PostHog users/@me proof, and generic opaque-provider detail parsing used by Cloudflare/Vercel/Netlify-style IDs.
  Safety: deterministic proof parsing only. No provider calls, endpoint expansion, proxy/IP rotation, pacing changes, scope relaxation, destructive behavior, or report-gate changes were added.
  Cleanup/commit: pytest temp `.forge_data` cleanup was completed separately; this workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue provider-proof hardening if another concrete low-signal proof gap is found, otherwise continue safe local worker-pool conversions or Phase 1 runtime trimming.

- [x] Single-entry social-profile handle worker-pool checkpoint is green:
  `python -m py_compile forge\cli.py tests\phase1\test_engagement_orchestrator.py`
  `python -m ruff check forge\cli.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest -p no:rerunfailures tests\phase1\test_engagement_orchestrator.py::test_kill_chain_parallel_batches_social_profile_handle_parse tests\phase1\test_engagement_orchestrator.py::test_kill_chain_parallel_batches_single_row_social_profile_entry_parse tests\phase1\test_engagement_orchestrator.py::test_kill_chain_parallel_batches_single_entry_social_profile_handle_parse -q` -> `3 passed`
  `python -m pytest -p no:rerunfailures tests\phase1\test_engagement_orchestrator.py::test_kill_chain_multi_iteration_recurses_social_profile_seeds_without_live_network tests\phase1\test_engagement_orchestrator.py::test_kill_chain_multi_iteration_recurses_name_search_social_profiles_without_live_network tests\phase1\test_engagement_orchestrator.py::test_kill_chain_parallel_batches_social_profile_handle_parse tests\phase1\test_engagement_orchestrator.py::test_kill_chain_parallel_batches_single_row_social_profile_entry_parse tests\phase1\test_engagement_orchestrator.py::test_kill_chain_parallel_batches_single_entry_social_profile_handle_parse -q` -> `5 passed`
  `python -m pytest -p no:rerunfailures -m slow tests\phase1\test_engagement_orchestrator.py::test_kill_chain_social_handle_recursion_reads_encrypted_canonical_social_profiles -q` -> `1 passed`
  Notes: Fan-out E5 social-profile handle loading now uses bounded local workers for single-row/multi-entry payload parsing and single-row/single-entry/multi-handle normalization. Multi-row or multi-entry nested levels stay serial at the deeper level to avoid multiplying worker pools. Ordered merges, dedupe, seed-run finalization, provider dispatch caps, scope gates, dry-run behavior, and live authorization gates are unchanged.
  Safety: local parse scheduling only. No provider calls, proxy/IP rotation, rate-limit bypass, scope relaxation, destructive behavior, or report-gate changes were added.
  Cleanup/commit: pytest temp `.forge_data` cleanup was completed separately; this workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue safe bounded-worker conversions only where the work is pure local parsing/prep, or switch to provider-proof hardening if a concrete validator gap is found.

- [x] Single-row social-profile entry worker-pool checkpoint is green:
  `python -m py_compile forge\cli.py tests\phase1\test_engagement_orchestrator.py`
  `python -m ruff check forge\cli.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest -p no:rerunfailures tests\phase1\test_engagement_orchestrator.py::test_kill_chain_parallel_batches_social_profile_handle_parse tests\phase1\test_engagement_orchestrator.py::test_kill_chain_parallel_batches_single_row_social_profile_entry_parse -q` -> `2 passed`
  `python -m pytest -p no:rerunfailures tests\phase1\test_engagement_orchestrator.py::test_kill_chain_multi_iteration_recurses_social_profile_seeds_without_live_network tests\phase1\test_engagement_orchestrator.py::test_kill_chain_multi_iteration_recurses_name_search_social_profiles_without_live_network tests\phase1\test_engagement_orchestrator.py::test_kill_chain_social_handle_recursion_reads_encrypted_canonical_social_profiles tests\phase1\test_engagement_orchestrator.py::test_kill_chain_parallel_batches_social_profile_handle_parse tests\phase1\test_engagement_orchestrator.py::test_kill_chain_parallel_batches_single_row_social_profile_entry_parse -q` -> `4 passed, 1 deselected`
  `python -m pytest -p no:rerunfailures -m slow tests\phase1\test_engagement_orchestrator.py::test_kill_chain_social_handle_recursion_reads_encrypted_canonical_social_profiles -q` -> `1 passed`
  Notes: Fan-out E5 social-profile handle loading now uses bounded local workers for per-entry parsing only when one DB row contains multiple profile/provider entries. Multi-row loads remain row-parallel and entry-serial to avoid nested worker-pool multiplication. Ordered merges, dedupe, seed-run finalization, provider dispatch caps, scope gates, dry-run behavior, and live probing authorization are unchanged.
  Safety: local parse scheduling only. No provider calls were added, no proxy/IP rotation or rate-limit bypass was added, and no scope relaxation or destructive behavior was added.
  Cleanup/commit: pytest temp `.forge_data` cleanup was completed separately; this workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue safe bounded-worker conversions only where the work is pure local parsing/prep, or move to provider-proof hardening if a concrete validation gap is found.

- [x] Compact full-contract smoke checkpoint is green:
  `python -m py_compile forge\cli.py forge\engagement_orchestrator.py forge\phase4\cloud_validate.py forge\phase4\attack_path.py forge\phase6\report_synthesizer.py forge\reporting\dashboard.py tests\phase1\test_engagement_orchestrator.py tests\phase4\test_cloud_validate.py tests\phase4\test_attack_path.py tests\phase6\test_report_synthesizer.py tests\reporting\test_dashboard.py`
  `python -m ruff check forge\cli.py forge\engagement_orchestrator.py forge\phase4\cloud_validate.py forge\phase4\attack_path.py forge\phase6\report_synthesizer.py forge\reporting\dashboard.py tests\phase1\test_engagement_orchestrator.py tests\phase4\test_cloud_validate.py tests\phase4\test_attack_path.py tests\phase6\test_report_synthesizer.py tests\reporting\test_dashboard.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_kill_chain_artifact_extracted_assets_validate_and_seed_next_iteration_under_scope tests/phase6/test_report_synthesizer.py::test_synthesizer_runtime_provider_failure_falls_back_to_template tests/reporting/test_dashboard.py::test_generate_dashboard_emits_slug_routes_and_json_contract tests/reporting/test_dashboard.py::test_generate_dashboard_surfaces_provider_matrix_artifacts_and_validation_evidence tests/phase4/test_cloud_validate.py::test_sweep_pending_cloud_asset_validations_scope_checker_skips_denied_assets tests/phase4/test_attack_path.py::TestGraphBuildArtifacts::test_graph_build_all_writes_native_mtgx_workspace -q --color=no` -> `6 passed in 107.11s`
  Notes: compact smoke ties together recursive kill-chain artifact handoff, deterministic LLM-to-template fallback, dashboard slug/detail graph/report JSON, dashboard cloud validation evidence, cloud scope-gate denial, and native graph/MTGX export. No code changes were required by this checkpoint.
  Safety: all validation/probing in this smoke is mocked/local. No live external probing, proxy/IP rotation, rate-limit bypass, scope relaxation, destructive validation, or persistent engagement DB mutation was added.
  Cleanup/commit: removed 4 pytest temp `.forge_data/engagements` directories after verification; `remaining_pytest_engagement_dirs=0`. This workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: inspect one concrete remaining gap instead of broad retesting. Best candidates: reconcile historical unchecked “next audit” breadcrumbs into a short active backlog, then audit either MTGX/GraphML analyst fidelity or passive-to-live validator proof details with mocked read-only endpoints.

- [x] Artifact-extracted validation/recursive handoff checkpoint is green:
  `python -m py_compile tests\phase1\test_engagement_orchestrator.py forge\cli.py forge\engagement_orchestrator.py`
  `python -m ruff check tests\phase1\test_engagement_orchestrator.py forge\cli.py forge\engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_kill_chain_artifact_extracted_assets_validate_and_seed_next_iteration_under_scope -q --color=no` -> `1 passed in 112.91s`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_kill_chain_framework_manifest_artifact_recurses_into_second_iteration_chunk tests/phase1/test_engagement_orchestrator.py::test_kill_chain_artifact_extracted_assets_validate_and_seed_next_iteration_under_scope -q --color=no` -> `2 passed in 178.63s`
  Notes: added an end-to-end regression proving a D5-discovered APK is queued at K2, statically parsed at K3, artifact-extracted Firebase assets are handled by K3.5 cloud validation, out-of-scope cloud assets are persisted as `UNVERIFIED/scope_manifest` without live probing, and artifact-extracted URL/APK seeds are consumed in iteration 2 without a manual command.
  Backprop note: first run failed because the test scope manifest did not explicitly authorize `followup.acme.example`; this was a fixture authorization gap, not a runtime bug. There is no `SPEC.md`, so the backprop conclusion is recorded here instead of §B/§V.
  Safety: mocked validation endpoints and local artifact downloads only. No live external probing, proxy/IP rotation, rate-limit bypass, scope relaxation, destructive validation, or persistent engagement DB mutation was added.
  Cleanup/commit: removed 4 pytest temp `.forge_data/engagements` directories after verification; `remaining_pytest_engagement_dirs=0`. This workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: completed by the Compact full-contract smoke checkpoint above.

- [x] Provider-origin artifact static extraction provenance checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_artifact_source_seed_relation_preserves_provenance_and_extract_rule tests/phase1/test_engagement_orchestrator.py::test_provider_origin_artifact_static_extraction_preserves_provenance_for_graph_and_report -q --color=no` -> `2 passed in 7.90s`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_mobile_configs_and_feedback_seeds tests/phase1/test_engagement_orchestrator.py::test_provider_origin_artifact_static_extraction_preserves_provenance_for_graph_and_report tests/phase4/test_attack_path.py::TestGraphBuildArtifacts::test_graph_build_all_writes_native_mtgx_workspace tests/reporting/test_dashboard.py::test_generate_dashboard_falls_back_to_seed_graph_payload_when_no_graph_artifact_exists -q --color=no` -> `4 passed in 2.70s`
  `python -m pytest tests/phase2/test_passive_host_persistence.py::test_persist_shodan_findings_promotes_web_services_to_recursive_url_seeds tests/phase2/test_passive_host_persistence.py::test_persist_urlscan_findings_marks_synthetic_placeholder_rows_explicitly tests/phase1/test_engagement_orchestrator.py::test_kill_chain_d5_consumes_provider_url_seeds_and_preserves_provenance tests/phase1/test_engagement_orchestrator.py::test_provider_origin_artifact_static_extraction_preserves_provenance_for_graph_and_report -q --color=no` -> `4 passed in 132.43s`
  Notes: `ArtifactQueueProcessor` now copies safe D5/provider source metadata (`source_url`, `source_seed_url`, host, scan domain/id, scheme, port, provider/source fields) from the source artifact seed into artifact-derived relation evidence, and mirrors non-secret artifact provenance into derived seed `metadata_json`. The new regression queues a URLScan/Shodan-origin APK, parses static Firebase config and text pivots, then proves provider provenance survives into extracted seed metadata, `seed_relations`, Phase 4 graph edge metadata, and Phase 6 report context evidence with `key_enc` scrubbed.
  Safety: static artifact provenance only. No live external probing, provider concurrency increase, proxy/IP rotation, rate-limit bypass, scope relaxation, destructive validation, report gate relaxation, or persistent engagement DB mutation was added. Rate-limit handling remains bounded/paced; no IP bypass mechanism was added.
  Cleanup/commit: removed 3 pytest temp `.forge_data/engagements` directories after verification; persistent workspace `.forge_data/engagements` DBs were not deleted because they are not proven test artifacts. This workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: completed by the Artifact-extracted validation/recursive handoff checkpoint above.

- [x] Provider URL D5 consumption checkpoint is green:
  `python -m py_compile forge\cli.py tests\phase1\test_engagement_orchestrator.py`
  `python -m ruff check tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_kill_chain_d5_consumes_provider_url_seeds_and_preserves_provenance -q --color=no` -> `1 passed in 136.92s`
  `python -m py_compile forge\cli.py forge\utils\intel\provider_urls.py forge\utils\intel\shodan_lookup.py forge\utils\intel\urlscan_lookup.py tests\phase2\test_passive_host_persistence.py tests\phase1\test_engagement_orchestrator.py`
  `python -m ruff check forge\cli.py forge\utils\intel\provider_urls.py forge\utils\intel\shodan_lookup.py forge\utils\intel\urlscan_lookup.py tests\phase2\test_passive_host_persistence.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests/phase2/test_passive_host_persistence.py::test_persist_shodan_findings_promotes_web_services_to_recursive_url_seeds tests/phase2/test_passive_host_persistence.py::test_persist_urlscan_findings_marks_synthetic_placeholder_rows_explicitly tests/phase1/test_engagement_orchestrator.py::test_kill_chain_d5_consumes_provider_url_seeds_and_preserves_provenance -q --color=no` -> `3 passed in 131.57s`
  Notes: D5 now carries source URL seed provenance into child URL crawl/seed metadata and artifact queue metadata. Regression coverage proves provider-style URL seeds with Shodan/URLScan metadata are fetched through the bounded URL surface path, complete `fanout_d5_url_seed_html` seed runs, preserve original provider provenance, and persist second-order email, URL, APK URL, crawl rows, and queued artifact provenance for the next recursive iteration.
  Safety: runtime metadata propagation only. No live external probing, provider concurrency increase, proxy/IP rotation, rate-limit bypass, scope relaxation, destructive validation, report gate relaxation, or persistent engagement DB mutation was added.
  Cleanup/commit: removed pytest temp `.forge_data/engagements` directories after verification; `remaining_pytest_engagement_dirs=0`, and no pytest process was left running. Persistent workspace `.forge_data/engagements` DBs were not deleted because they are not proven test artifacts from this run. This workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: completed by the Provider-origin artifact static extraction provenance checkpoint above.

- [x] Provider URL graph-review checkpoint is green:
  `python -m py_compile forge\reporting\dashboard.py forge\phase4\attack_path.py tests\reporting\test_dashboard.py tests\integration\test_webui_engagement_api.py tests\phase4\test_attack_path.py`
  `python -m ruff check forge\reporting\dashboard.py forge\phase4\attack_path.py tests\reporting\test_dashboard.py tests\integration\test_webui_engagement_api.py tests\phase4\test_attack_path.py`
  `python -m pytest tests/reporting/test_dashboard.py::test_generate_dashboard_falls_back_to_seed_graph_payload_when_no_graph_artifact_exists -q --color=no` -> `1 passed`
  `python -m pytest tests/integration/test_webui_engagement_api.py::test_engagement_api_falls_back_to_seed_graph_payload_without_attack_graph_artifacts -q --color=no` -> `1 passed`
  `python -m pytest tests/phase4/test_attack_path.py::TestGraphBuildArtifacts::test_graph_build_all_writes_native_mtgx_workspace -q --color=no` -> `1 passed`
  `python -m pytest tests/phase2/test_passive_host_persistence.py tests/reporting/test_dashboard.py::test_generate_dashboard_falls_back_to_seed_graph_payload_when_no_graph_artifact_exists tests/integration/test_webui_engagement_api.py::test_engagement_api_falls_back_to_seed_graph_payload_without_attack_graph_artifacts tests/phase4/test_attack_path.py::TestGraphBuildArtifacts::test_graph_build_all_writes_native_mtgx_workspace -q --color=no` -> `8 passed, 1 warning`
  Notes: fallback engagement seed graphs now merge safe seed `metadata_json` into node metadata, preserving provider provenance such as `provider_sources`, `discovery_source`, host, port, scheme, scan id, and source URL. Seed relation evidence is scrubbed before graph edge metadata. Native attack graph exports now preserve the same safe seed provenance in JSON, GraphML, CSV, and MTGX/manifest output.
  Backprop note: one test retry was needed because the provider URL fixture was first inserted into a graph-artifact parser test instead of the fallback seed-graph test. There is no `SPEC.md`; the invariant is documented here: fallback graph tests must delete snapshots/artifacts and assert recursive seed provenance plus secret scrubbing from the generated payload.
  Safety: dashboard/API/graph export metadata only. No live external probing, provider concurrency increase, proxy/IP rotation, rate-limit bypass, scope relaxation, destructive validation, report gate relaxation, or persistent engagement DB mutation was added.
  Cleanup/commit: removed 16 pytest temp `.forge_data/engagements` directories; `remaining_pytest_engagement_dirs=0`, and no pytest process was left running. Persistent workspace `.forge_data/engagements` DBs were not deleted because they are not proven test artifacts from this run. This workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: completed by the Provider URL D5 consumption checkpoint above.

- [x] Passive provider URL recursion checkpoint is green:
  `python -m py_compile forge\utils\intel\provider_urls.py forge\utils\intel\shodan_lookup.py forge\utils\intel\urlscan_lookup.py tests\phase2\test_passive_host_persistence.py`
  `python -m ruff check forge\utils\intel\provider_urls.py forge\utils\intel\shodan_lookup.py forge\utils\intel\urlscan_lookup.py tests\phase2\test_passive_host_persistence.py`
  `python -m pytest tests/phase2/test_passive_host_persistence.py -q --color=no` -> `5 passed`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_engagement_provider_matrix_recursion_preserves_caps_and_exports -q --color=no` -> `1 passed`
  `python -m pytest tests/phase2/test_passive_host_persistence.py tests/phase2/test_commoncrawl_lookup.py tests/phase2/test_wayback_lookup.py tests/phase1/test_subdomain_enum.py -k "paces or commoncrawl or wayback or crtsh or shodan or urlscan" -q --color=no` -> `10 passed, 4 deselected`
  Notes: Shodan HTTP(S) service evidence and URLScan page URLs now persist into `crawl_results` plus recursive `engagement_seeds` through `forge.utils.intel.provider_urls`, so D5 URL mining can fetch pages/static/assets/artifacts in later scoped kill-chain iterations. Shodan only promotes in-scope hostnames on observed web ports and URLScan only promotes in-scope page URLs.
  Safety: passive provider persistence only. No live external probing was run, no provider concurrency increase, no proxy/IP rotation, no rate-limit bypass, no scope relaxation, no destructive validation, no report gate relaxation, and no persistent engagement DB mutation was added.
  Cleanup/commit: no pytest temp `.forge_data/engagements` folders were present, no pytest process was left running, and this workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: completed by the Provider URL graph-review checkpoint above.

- [x] Alternate storage URL recursion checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_artifact_queue_processor_promotes_alternate_storage_url_forms -q --color=no` -> `1 passed`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_document_and_archive_findings tests/phase1/test_engagement_orchestrator.py::test_artifact_queue_processor_promotes_alternate_storage_url_forms tests/phase1/test_engagement_orchestrator.py::test_kill_chain_dry_run_queues_seed_brotli_config_url_and_processes_remote_artifact tests/phase1/test_engagement_orchestrator.py::test_kill_chain_dry_run_queues_seed_lz4_config_url_and_processes_remote_artifact -q --color=no` -> `4 passed`
  Notes: artifact recursion now has explicit coverage for S3 website URLs, `storage.cloud.google.com` GCS URLs, DigitalOcean Spaces path-style URLs, Firebase Storage media URLs, and Azure Blob URLs. The test proves they persist URL seeds and the correct `cloud_assets` without creating noisy managed-provider domain/subdomain seeds.
  Safety: passive local/static artifact parsing and local remote fixtures only. No live external probing, provider concurrency increase, proxy/IP rotation, rate-limit bypass, scope relaxation, destructive validation, report gate relaxation, or persistent engagement DB mutation was added.
  Cleanup/commit: removed 2 pytest temp `.forge_data/engagements` folders; `remaining_pytest_engagement_dirs=0`, and no pytest process was left running. This workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: inspect remaining recursive discovery gaps in compressed/container artifacts, identity-to-domain pivots, or graph/export proof before adding runtime code.

- [x] Storage validation dashboard-review checkpoint is green:
  `python -m py_compile forge\reporting\dashboard.py tests\reporting\test_dashboard.py`
  `python -m ruff check forge\reporting\dashboard.py tests\reporting\test_dashboard.py`
  `python -m pytest tests/reporting/test_dashboard.py::test_generate_dashboard_surfaces_storage_validation_evidence_in_detail_graph tests/reporting/test_dashboard.py::test_generate_dashboard_surfaces_provider_matrix_artifacts_and_validation_evidence tests/reporting/test_dashboard.py::test_generate_dashboard_emits_slug_routes_and_json_contract tests/reporting/test_dashboard.py::test_generate_dashboard_prefers_graph_json_artifact_over_graphml_when_snapshot_missing -q --color=no` -> `4 passed`
  `python -m pytest tests/reporting/test_dashboard.py -q --color=no` -> `12 passed`
  Notes: engagement detail dashboard JSON now has explicit regression coverage proving S3, GCS, Azure Blob, and DigitalOcean Spaces validation evidence is reviewable in both `graph_payload` node metadata and the `cloud_validation_results` section. The test covers `VALIDATED` storage rows and `ACCESSIBLE_BUT_NO_DATA` Azure metadata-only rows.
  Safety: dashboard/reporting test coverage only. No live probing, validator behavior change, provider concurrency increase, proxy/IP rotation, rate-limit bypass, scope relaxation, destructive validation, report gate relaxation, or persistent engagement DB mutation was added.
  Cleanup/commit: removed 16 pytest temp `.forge_data/engagements` folders; `remaining_pytest_engagement_dirs=0`, and no pytest process was left running. This workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: inspect recursive discovery persistence from extracted cloud/storage references into graph/export artifacts, or another concrete kill-chain recursion gap before adding runtime code.

- [x] Storage cloud-asset scope-denial checkpoint is green:
  `python -m py_compile forge\phase4\cloud_validate.py tests\phase4\test_cloud_validate.py`
  `python -m ruff check forge\phase4\cloud_validate.py tests\phase4\test_cloud_validate.py`
  `python -m pytest tests/phase4/test_cloud_validate.py::test_sweep_pending_cloud_asset_validations_scope_checker_skips_denied_assets tests/phase4/test_cloud_validate.py::test_sweep_pending_cloud_asset_validations_denies_storage_assets_without_probe_or_findings tests/phase4/test_cloud_validate.py::test_sweep_pending_cloud_asset_validations_parallelizes_scope_gate_and_preserves_order tests/phase4/test_cloud_validate.py::test_run_cloud_asset_validate_batch_scope_checker_skips_denied_assets -q --color=no` -> `4 passed`
  `python -m pytest tests/phase4/test_cloud_validate.py::test_sweep_pending_cloud_asset_validations_processes_unvalidated_assets tests/phase4/test_cloud_validate.py::test_sweep_pending_cloud_asset_validations_processes_unvalidated_digitalocean_spaces_assets tests/phase4/test_cloud_validate.py::test_run_cloud_asset_validate_persists_gcs_bucket_result tests/phase4/test_cloud_validate.py::test_run_cloud_asset_validate_persists_digitalocean_spaces_bucket_result tests/phase4/test_cloud_validate.py::test_run_cloud_asset_validate_persists_azure_blob_result -q --color=no` -> `5 passed`
  `python -m pytest tests/phase1/test_deterministic_findings.py::test_deterministic_findings_support_additional_storage_providers tests/phase1/test_deterministic_findings.py::test_deterministic_findings_keep_storage_metadata_only_probes_low tests/phase1/test_deterministic_findings.py::test_deterministic_findings_keep_static_site_only_storage_listings_low tests/phase4/test_cloud_validate.py -k "cloud_asset_validations or scope_checker_skips_denied_assets or denies_storage_assets or processes_unvalidated_digitalocean_spaces_assets" -q --color=no` -> `6 passed, 104 deselected`
  Notes: S3, GCS, Azure Blob, and DigitalOcean Spaces `cloud_assets` now have sweep-level regression coverage proving scope-denied assets never reach provider validation, are persisted as `UNVERIFIED:scope_manifest`, preserve denial callbacks/order, and produce no deterministic findings.
  Backprop note: one verification retry was needed because stale deterministic-finding test names were used; no product test failed, and no `SPEC.md` exists for §B/§V logging.
  Safety: mocked/scope-denied validation path only. No live external probing, provider concurrency increase, proxy/IP rotation, rate-limit bypass, scope relaxation, destructive validation, report gate relaxation, or persistent engagement DB mutation was added.
  Cleanup/commit: no pytest engagement temp DBs remained; `remaining_pytest_engagement_dirs=0`, and no pytest process was left running. This workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: inspect kill-chain recursive discovery from newly discovered cloud assets into dashboard/report graph evidence, or another concrete recursive discovery gap before adding runtime code.

- [x] Newer provider low-signal validation handoff checkpoint is green:
  `python -m py_compile forge\phase4\cloud_validate.py tests\phase4\test_cloud_validate.py`
  `python -m ruff check forge\phase4\cloud_validate.py tests\phase4\test_cloud_validate.py`
  `python -m pytest tests/phase4/test_cloud_validate.py::test_non_cloud_validation_identifier_parser_rejects_low_signal_success_details tests/phase4/test_cloud_validate.py::test_sweep_pending_cloud_validations_processes_social_messaging_and_collaboration_provider_tokens_without_cloud_finding tests/phase4/test_cloud_validate.py::test_sweep_pending_cloud_validations_downgrades_newer_provider_active_results_without_stable_proof -q --color=no` -> `3 passed`
  `python -m pytest tests/phase2/test_secret_finder.py::test_cloudflare_api_token_validator_active_uses_verify_without_private_detail tests/phase2/test_secret_finder.py::test_cloudflare_api_token_validator_inactive_token_is_revoked tests/phase2/test_secret_finder.py::test_vercel_token_validator_active_uses_current_user_without_private_detail tests/phase2/test_secret_finder.py::test_netlify_token_validator_active_uses_current_user_without_private_detail tests/phase2/test_secret_finder.py::test_posthog_personal_api_key_validator_active_checks_documented_hosts tests/phase2/test_secret_finder.py::test_posthog_personal_api_key_validator_all_auth_failures_are_revoked tests/phase2/test_secret_finder.py::test_sentry_auth_token_validator_active_uses_orgs_without_private_detail tests/phase2/test_secret_finder.py::test_sentry_auth_token_validator_forbidden_stays_unconfirmed tests/phase2/test_secret_finder.py::test_sentry_auth_token_validator_unauthorized_is_revoked -q --color=no` -> `9 passed`
  `python -m pytest tests/phase4/test_cloud_validate.py tests/phase2/test_secret_finder.py -k "cloudflare or vercel or netlify or posthog or sentry or low_signal_success_details or newer_provider_active or provider_tokens" -q --color=no` -> `12 passed, 157 deselected`
  Notes: Cloudflare, Vercel, Netlify, PostHog, and Sentry key-validation handoff now has negative regression coverage. Even if a provider validator returns `ACTIVE`, the sweep keeps the result `UNVERIFIED`, keeps the key row `UNCONFIRMED`, and generates no deterministic finding unless stable provider-specific proof can derive an identifier.
  Safety: mocked validator responses only. No runtime code change was needed, and no live external probing, provider concurrency increase, proxy/IP rotation, rate-limit bypass, scope relaxation, destructive validation, report gate relaxation, or persistent engagement DB mutation was added.
  Cleanup/commit: no pytest engagement temp DBs remained; `remaining_pytest_engagement_dirs=0`, and no pytest process was left running. This workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: inspect scoped live cloud-asset validation handoff for storage providers or another concrete recursive discovery gap before adding runtime code.

- [x] Remote APKS split-bundle recursion checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_kill_chain_dry_run_queues_seed_mobile_bundle_urls_and_processes_remote_apks -q --color=no` -> `1 passed`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_kill_chain_dry_run_queues_seed_artifact_urls_and_processes_remote_apk tests/phase1/test_engagement_orchestrator.py::test_kill_chain_dry_run_queues_seed_mobile_bundle_urls_and_processes_remote_xapk tests/phase1/test_engagement_orchestrator.py::test_kill_chain_dry_run_queues_seed_mobile_bundle_urls_and_processes_remote_apkm tests/phase1/test_engagement_orchestrator.py::test_kill_chain_dry_run_queues_seed_mobile_bundle_urls_and_processes_remote_apks -q --color=no` -> `4 passed`
  Notes: `.apks` URL seeds now have explicit kill-chain regression coverage proving local HTTP acquisition, archive-style mobile parsing, nested APK Firebase/Supabase extraction, recursive email/URL/cloud seed persistence, derived relations, and artifact metadata format plus `nested_mobile_member_count`.
  Safety: local HTTP fixture and passive static extraction only. No runtime code change was needed, and no artifact execution, live external probing, provider concurrency increase, proxy/IP rotation, rate-limit bypass, scope relaxation, destructive validation, or persistent engagement DB mutation was added.
  Cleanup/commit: removed 5 pytest temp `.forge_data/engagements` folders; `remaining_pytest_engagement_dirs=0`, and no pytest process was left running. This workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: inspect another concrete recursive discovery gap, preferably passive-to-live validator handoff coverage with mocked read-only proof endpoints, before adding runtime code.

- [x] 7z nested mobile static-analysis checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_nested_mobile_configs_from_7z_archive tests/phase1/test_engagement_orchestrator.py::test_artifact_queue_processor_parallelizes_nested_7z_mobile_member_extraction_and_preserves_order -q --color=no` -> `2 passed`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_7z_archive_static_artifacts tests/phase1/test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_nested_mobile_configs_from_archive_bundles tests/phase1/test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_nested_archive_style_mobile_bundle_from_outer_archive tests/phase1/test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_nested_mobile_configs_from_7z_archive tests/phase1/test_engagement_orchestrator.py::test_artifact_queue_processor_parallelizes_nested_zip_mobile_member_extraction_and_preserves_order tests/phase1/test_engagement_orchestrator.py::test_artifact_queue_processor_parallelizes_nested_7z_mobile_member_extraction_and_preserves_order tests/phase1/test_engagement_orchestrator.py::test_artifact_queue_processor_parallelizes_nested_tar_mobile_member_extraction_and_preserves_order tests/phase1/test_engagement_orchestrator.py::test_artifact_queue_processor_parallelizes_7z_member_payload_extraction_and_preserves_order -q --color=no` -> `8 passed`
  Notes: 7z archives now use the same dedicated nested mobile extraction path as ZIP/TAR when they contain APK, IPA, AAB, XAPK, or APKM members. The path skips encrypted archives, rejects unsafe/symlink/oversized members, preserves member order, records `nested_mobile_member_count`, and feeds extracted Firebase, Supabase, email, URL, S3, and GCS pivots into the existing recursive seed/cloud-asset pipeline.
  Safety: passive static extraction only. No artifact execution, live probing endpoint changes, provider concurrency increase, proxy/IP rotation, rate-limit bypass, scope relaxation, destructive validation, or persistent engagement DB mutation was added.
  Cleanup/commit: no pytest engagement temp DBs remained; `remaining_pytest_engagement_dirs=0`, and no pytest process was left running. This workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: switch to passive-to-live validator handoff coverage with mocked read-only proof endpoints, or close another distinct archive/container parser gap only if code inspection identifies one.

- [x] Firmware image suffix recursion checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_classify_remote_artifact_url_recognizes_firmware_binary_artifacts tests/phase1/test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_firmware_binary_string_artifacts tests/phase1/test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_firmware_image_binary_string_artifacts -q --color=no` -> `3 passed`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "firmware_binary_artifacts or firmware_binary_string_artifacts or firmware_image_binary_string_artifacts or extracts_wasm_binary_string_artifacts or extracts_native_binary_string_artifacts or 7z_archive_static_artifacts or parallelizes_7z_member_payload" -q --color=no` -> `7 passed, 469 deselected`
  Notes: `.fw`, `.rom`, and `.img` artifacts now route through the same bounded binary-string extractor as `.bin` and `.elf`. Firmware image drops can now emit recursive email, URL, Firebase, Supabase, S3, and GCS pivots without executing firmware or mounting disk images.
  Safety: passive static string carving only. No artifact execution, image mounting, live probing endpoint changes, provider concurrency increase, proxy/IP rotation, rate-limit bypass, scope relaxation, destructive validation, or persistent engagement DB mutation was added.
  Cleanup/commit: no pytest engagement temp DBs remained; `remaining_pytest_engagement_dirs=0`. This workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue with a distinct embedded-object/container parser gap or switch to passive-to-live validator handoff coverage with mocked read-only proof endpoints.

- [x] Firmware/native binary string recursion checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_classify_remote_artifact_url_recognizes_firmware_binary_artifacts tests/phase1/test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_firmware_binary_string_artifacts -q --color=no` -> `2 passed`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "firmware_binary_artifacts or firmware_binary_string_artifacts or extracts_wasm_binary_string_artifacts or extracts_native_binary_string_artifacts or 7z_archive_static_artifacts or parallelizes_7z_member_payload" -q --color=no` -> `6 passed, 469 deselected`
  Notes: `.bin` and `.elf` artifacts now route through the existing bounded binary-string extractor. Hardcoded emails, URLs, Firebase, Supabase, S3, and GCS refs embedded in firmware/native binary drops can now feed recursive seeds/cloud assets instead of being ignored.
  Safety: passive static string carving only. No artifact execution, live probing endpoint changes, provider concurrency increase, proxy/IP rotation, rate-limit bypass, scope relaxation, destructive validation, or persistent engagement DB mutation was added.
  Cleanup/commit: no pytest engagement temp DBs remained; `remaining_pytest_engagement_dirs=0`. This workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue artifact/container resilience with another concrete embedded-object/parser gap, or audit passive-to-live validator handoff coverage with mocked read-only proof endpoints.

- [x] 7z static-artifact recursion checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_classify_remote_artifact_url_recognizes_7z_archives tests/phase1/test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_7z_archive_static_artifacts tests/phase1/test_engagement_orchestrator.py::test_artifact_queue_processor_parallelizes_7z_member_payload_extraction_and_preserves_order -q --color=no` -> `3 passed`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "classify_remote_artifact_url_recognizes_7z_archives or 7z_archive_static_artifacts or parallelizes_7z_member_payload or remote_brotli or remote_lz4 or extracts_wasm_binary_string_artifacts or extracts_native_binary_string_artifacts or parallelizes_tar_member_payload_extraction" -q --color=no` -> `6 passed, 467 deselected`
  Notes: `.7z` URLs and local files now classify as archive artifacts. Static 7z extraction is optional on `py7zr`, skips encrypted archives, rejects symlink/path-traversal/oversized members, preserves member order, and runs member payload parsing through the bounded local worker path. Extracted emails, URLs, Firebase, Supabase, S3, and GCS refs feed the existing recursive seed/cloud-asset pipeline.
  Safety: passive static parsing only. No live probing endpoint changes, provider concurrency increase, proxy/IP rotation, rate-limit bypass, scope relaxation, destructive validation, artifact execution, or persistent engagement DB mutation was added.
  Cleanup/commit: no pytest engagement temp DBs remained; `remaining_pytest_engagement_dirs=0`. This workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue artifact/container resilience with another concrete passive parser gap, or audit passive-to-live validator handoff coverage with mocked read-only proof endpoints.

- [x] MTGX analyst properties plus Bluesky custom-domain recursion checkpoint is green:
  `python -m py_compile forge\cli.py tests\phase4\test_attack_path.py`
  `python -m ruff check forge\cli.py tests\phase4\test_attack_path.py`
  `python -m pytest tests/phase4/test_attack_path.py::TestGraphBuildArtifacts::test_graph_build_all_writes_native_mtgx_workspace -q --color=no` -> `1 passed`
  `python -m pytest tests/phase4/test_attack_path.py -q --color=no` -> `100 passed`
  `python -m py_compile forge\cli.py forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m ruff check forge\cli.py forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_synthesis_engine_promotes_bluesky_custom_domain_handles_as_domain_pivots -q --color=no` -> `1 passed`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_kill_chain_dry_run_promotes_operator_social_url_seeds_into_recursive_identity_fanouts -q --color=no` -> `1 passed`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_synthesis_engine_derives_social_profile_seeds_and_relations tests/phase1/test_engagement_orchestrator.py::test_social_profile_url_parser_supports_twitter_intent_links_and_skips_github_reserved_paths tests/phase1/test_engagement_orchestrator.py::test_synthesis_engine_promotes_bluesky_custom_domain_handles_as_domain_pivots tests/phase1/test_engagement_orchestrator.py::test_artifact_queue_processor_parallelizes_social_profile_url_pivot_entries_and_preserves_order tests/phase1/test_engagement_orchestrator.py::test_kill_chain_dry_run_promotes_operator_social_url_seeds_into_recursive_identity_fanouts -q --color=no` -> `5 passed`
  Notes: MTGX manifest and native GraphML workspace exports now carry analyst-facing properties like `forge.identifier`, `forge.validation_detail`, and `forge.source_url`. Direct operator Bluesky profile URLs with DNS-backed handles now create domain seeds as well as username pivots, closing a recursive identity-to-domain discovery gap.
  Backprop/cleanup: the broad `-k "social_profile or public_profile or operator_social or bluesky"` selector timed out and left orphaned pytest PID `21624`; it was stopped. Removed 7 pytest temp `.forge_data/engagements` folders total; `remaining_pytest_engagement_dirs=0`.
  Safety: passive parsing/export recursion only. No live probing endpoint changes, provider concurrency increase, proxy/IP rotation, rate-limit bypass, validation bypass, scope relaxation, destructive validation, or persistent engagement DB mutation was added.
  Next audit target: continue concrete kill-chain reliability work by auditing passive-to-live handoffs with mocked read-only validators, then move only proven safe sequential enrichers under bounded worker-pool execution.

- [x] Graph/report validation-proof export parity checkpoint is green:
  `python -m py_compile forge\cli.py tests\phase4\test_attack_path.py tests\integration\test_webui_engagement_api.py`
  `python -m ruff check forge\cli.py tests\phase4\test_attack_path.py tests\integration\test_webui_engagement_api.py`
  `python -m py_compile tests\phase6\test_report_synthesizer.py`
  `python -m ruff check tests\phase6\test_report_synthesizer.py`
  `python -m pytest tests/phase4/test_attack_path.py::TestLoadApiKeys::test_active_apikey_node_carries_validation_proof_metadata tests/phase4/test_attack_path.py::TestGraphBuildArtifacts::test_graph_build_all_writes_native_mtgx_workspace -q --color=no` -> `2 passed`
  `python -m pytest tests/integration/test_webui_engagement_api.py::test_engagement_api_prefers_snapshot_graph_over_report_artifacts -q --color=no` -> `1 passed`
  `python -m pytest tests/integration/test_webui_engagement_api.py -k "attack_graph_snapshot or graph_payload or graphml or mtgx" -q --color=no` -> `3 passed, 22 deselected`
  `python -m pytest tests/phase6/test_report_synthesizer.py::test_synthesizer_template_and_exports_preserve_key_validation_proof tests/phase6/test_report_synthesizer.py::test_synthesizer_template_renders_cloud_validation_metadata -q --color=no` -> `2 passed`
  `python -m pytest tests/phase1/test_deterministic_findings.py -q --color=no` -> `9 passed`
  `python -m pytest tests/phase4/test_attack_path.py -q --color=no` -> `100 passed`
  `python -m pytest tests/integration/test_webui_engagement_api.py -q --color=no` -> `25 passed`
  `python -m pytest tests/phase6/test_report_synthesizer.py -q --color=no` -> `72 passed`
  Notes: `graph_build --format all` node CSV now includes sanitized `MetadataJSON`, so analyst CSV imports keep API-key validation proof. Graph tests now assert the method-tagged `VALIDATED:<validator_method>:<provider_detail>` shape across JSON/GraphML/MTGX/CSV, and report tests assert template Markdown, JSON companion export, and raw CSV keep proof/source context without `key_enc` or raw key material.
  Safety: export/test coverage only. No live probing endpoint changes, provider concurrency increase, proxy/IP rotation, rate-limit bypass, validation bypass, scope relaxation, destructive validation, or persistent engagement DB mutation was added.
  Cleanup/commit: removed 2 pytest temp `.forge_data/engagements` folders; `remaining_pytest_engagement_dirs=0`. This workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: run a fresh MTGX/GraphML analyst-workflow audit for entity typing/layout fidelity, then broaden passive parser/provider fixtures or safe bounded-worker conversions only where a concrete gap is found.

- [x] Legacy keyscan validation-method proof parity checkpoint is green:
  `python -m py_compile forge\phase2\key_scanner.py tests\phase2\test_key_scanner.py`
  `python -m ruff check forge\phase2\key_scanner.py tests\phase2\test_key_scanner.py`
  `python -m pytest tests/phase2/test_key_scanner.py::TestPatternFile::test_legacy_phase2_validation_detail_records_method_prefix tests/phase2/test_key_scanner.py::TestPatternFile::test_legacy_phase2_run_keyscan_uses_gitlab_token -q --color=no` -> `2 passed`
  `python -m pytest tests/phase2/test_key_scanner.py -q --color=no` -> `57 passed`
  `python -m pytest tests/phase2/test_key_validation_pacing.py -q --color=no` -> `5 passed`
  `python -m pytest tests/phase2 -q --color=no` -> `490 passed`
  `python -m pytest tests/phase1/test_deterministic_findings.py tests/phase6/test_report_synthesizer.py -q --color=no` -> `80 passed`
  `python -m pytest tests/phase4/test_attack_path.py::TestGraphBuildArtifacts::test_graph_build_all_writes_native_mtgx_workspace tests/phase4/test_attack_path.py::TestLoadApiKeys::test_active_apikey_node_carries_validation_proof_metadata -q --color=no` -> `2 passed`
  Notes: legacy `forge.phase2.key_scanner` validators now expose `result_validation_method`, and legacy ACTIVE validation details are stored as `VALIDATED:<validator_method>:<provider_detail>`, preserving parity with canonical keyscan and cloud validation sweeps.
  Safety: proof metadata enrichment only. No live probing endpoint changes, provider concurrency increase, proxy/IP rotation, rate-limit bypass, validation bypass, scope relaxation, destructive validation, or persistent engagement DB mutation was added.
  Cleanup/commit: removed 4 pytest temp `.forge_data/engagements` folders; `remaining_pytest_engagement_dirs=0`. This workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue attack-graph/report parity for validation proof metadata, then safe bounded-worker conversions where they improve real kill-chain reliability.

- [x] Direct keyscan validation-method proof checkpoint is green:
  `python -m py_compile forge\utils\intel\secret_finder.py tests\phase2\test_key_scanner.py`
  `python -m ruff check forge\utils\intel\secret_finder.py tests\phase2\test_key_scanner.py`
  `python -m pytest tests/phase2/test_key_scanner.py::TestKeyStorage::test_direct_validation_detail_records_method_prefix tests/phase2/test_key_scanner.py::TestKeyStorage::test_slack_bot_token_hit_validates_and_persists tests/phase2/test_key_scanner.py::TestGitLabKeyScan -q --color=no` -> `5 passed`
  `python -m pytest tests/phase2/test_key_scanner.py tests/phase2/test_secret_finder.py tests/phase2/test_key_validation_pacing.py -q --color=no` -> `124 passed`
  `python -m pytest tests/phase1/test_deterministic_findings.py tests/integration/test_engagement_pipeline.py tests/phase6/test_report_synthesizer.py -q --color=no` -> `89 passed`
  `python -m pytest tests/reporting/test_dashboard.py::test_generate_dashboard_surfaces_key_validation_proof_rows -q --color=no` -> `1 passed`
  `python -m pytest tests/phase2 -q --color=no` -> `489 passed`
  Notes: direct canonical `run_key_scanner()` validation now stores ACTIVE validation details as `VALIDATED:<validator_method>:<provider_detail>`, matching the method-tagged shape already produced by cloud validation sweeps. Deterministic scoring/report evidence can now distinguish which read-only proof endpoint confirmed the credential without relying on vague free text.
  Safety: proof metadata enrichment only. No live probing endpoint changes, provider concurrency increase, proxy/IP rotation, rate-limit bypass, validation bypass, scope relaxation, destructive validation, or persistent engagement DB mutation was added.
  Cleanup/commit: removed 3 pytest temp `.forge_data/engagements` folders; `remaining_pytest_engagement_dirs=0`. This workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue provider proof/detail reviewability and attack-graph/report parity, then safe bounded-worker conversions where they improve real kill-chain reliability.

- [x] Deterministic key-finding source fidelity checkpoint is green:
  `python -m py_compile forge\deterministic_findings.py tests\phase1\test_deterministic_findings.py`
  `python -m ruff check forge\deterministic_findings.py tests\phase1\test_deterministic_findings.py`
  `python -m pytest tests/phase1/test_deterministic_findings.py -q --color=no` -> `9 passed`
  `python -m pytest tests/integration/test_engagement_pipeline.py -q --color=no` -> `9 passed`
  `python -m pytest tests/phase6/test_report_synthesizer.py -q --color=no` -> `71 passed`
  `python -m pytest tests/reporting/test_dashboard.py::test_generate_dashboard_surfaces_key_validation_proof_rows -q --color=no` -> `1 passed`
  Notes: deterministic `DETERMINISTIC_KEY_EXPOSURE` findings now include scrubbed source context in `evidence`: redacted key, source backend, source URL, repo, and validation proof. This makes downstream reports and exports more auditable without reading or rendering `key_enc`.
  Safety: report/evidence enrichment only. No live probing change, provider concurrency increase, proxy/IP rotation, rate-limit bypass, validation bypass, scope relaxation, destructive validation, or persistent engagement DB mutation was added.
  Cleanup/commit: removed 3 pytest temp `.forge_data/engagements` folders; `remaining_pytest_engagement_dirs=0`. This workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue provider proof/detail reviewability, then safe bounded-worker conversions where they improve real kill-chain reliability.

- [x] Legacy keyscan GitLab parity checkpoint is green:
  `python -m py_compile forge\phase2\key_scanner.py tests\phase2\test_key_scanner.py`
  `python -m ruff check forge\phase2\key_scanner.py tests\phase2\test_key_scanner.py`
  `python -m pytest tests/phase2/test_key_scanner.py::TestPatternFile::test_legacy_phase2_run_keyscan_extracts_real_source_content tests/phase2/test_key_scanner.py::TestPatternFile::test_legacy_phase2_run_keyscan_uses_gitlab_token -q --color=no` -> `2 passed`
  `python -m pytest tests/phase2/test_key_scanner.py -q --color=no` -> `55 passed`
  `python -m pytest tests/phase2/test_key_validation_pacing.py -q --color=no` -> `5 passed`
  `python -m pytest tests/phase2 -q --color=no` -> `488 passed`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_kill_chain_parallel_batches_keyscan_targets -q --color=no` -> `1 passed`
  Notes: legacy `forge.phase2.key_scanner.run_keyscan()` now uses `gitlab_token` when provided. It runs sequential GitLab blob search, carries GitLab raw-file metadata, fetches raw content with `PRIVATE-TOKEN` plus `ref`, falls back to search snippets, and stores extracted real matches with `source_backend='gitlab'`.
  Safety: no provider concurrency increase, proxy/IP rotation, rate-limit bypass, validation bypass, scope relaxation, destructive validation, or persistent engagement DB mutation was added.
  Cleanup/commit: removed 2 pytest temp `.forge_data/engagements` folders; `remaining_pytest_engagement_dirs=0`. This workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: audit dashboard/report source fidelity for key findings and provider proof details, then continue safe bounded-worker conversions where they improve real kill-chain reliability.

- [x] Legacy keyscan placeholder removal checkpoint is green:
  `python -m py_compile forge\phase2\key_scanner.py tests\phase2\test_key_scanner.py`
  `python -m ruff check forge\phase2\key_scanner.py tests\phase2\test_key_scanner.py`
  `python -m pytest tests/phase2/test_key_scanner.py::TestPatternFile::test_legacy_phase2_run_keyscan_extracts_real_source_content tests/phase2/test_key_scanner.py::TestGitLabKeyScan -q --color=no` -> `4 passed`
  `python -m pytest tests/phase2/test_key_scanner.py -q --color=no` -> `54 passed`
  `python -m pytest tests/phase2/test_key_validation_pacing.py -q --color=no` -> `5 passed`
  `python -m pytest tests/phase2 -q --color=no` -> `487 passed`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_kill_chain_parallel_batches_keyscan_targets -q --color=no` -> `1 passed`
  Notes: legacy `forge.phase2.key_scanner.run_keyscan()` no longer persists or validates the placeholder `"[extracted-from-file]"`. GitHub code-search hits now carry raw-file metadata, the legacy runner fetches source content, extracts real regex/group matches with dedupe, and only then redacts/encrypts/stores or optionally validates the actual candidate. Compatibility pattern loaders and validator maps remain intact for existing playbook/test imports.
  Safety: sequential/rate-limited search behavior is unchanged. No provider concurrency increase, proxy/IP rotation, rate-limit bypass, validation bypass, scope relaxation, destructive validation, or persistent engagement DB mutation was added.
  Cleanup/commit: removed 2 pytest temp `.forge_data/engagements` folders; `remaining_pytest_engagement_dirs=0`. This workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue closing real kill-chain correctness gaps before more micro-optimization; candidate areas are keyscan GitLab legacy parity, dashboard/report source fidelity for key findings, and provider-specific proof details.

- [x] Canonical keyscan GitLab source-search checkpoint is green:
  `python -m py_compile forge\utils\intel\secret_finder.py tests\phase2\test_key_scanner.py tests\phase2\test_theharvester.py`
  `python -m ruff check forge\utils\intel\secret_finder.py tests\phase2\test_key_scanner.py tests\phase2\test_theharvester.py`
  `python -m pytest tests/phase2/test_key_scanner.py::TestGitLabKeyScan tests/phase2/test_key_scanner.py::TestKeyStorage::test_finding_written_to_db tests/phase2/test_secret_finder.py -q --color=no` -> `67 passed`
  `python -m pytest tests/phase2/test_key_scanner.py -q --color=no` -> `53 passed`
  `python -m pytest tests/phase2/test_theharvester.py::TestToolVersionCheck -q --color=no` -> `4 passed`
  `python -m pytest tests/phase2 -q --color=no` -> `486 passed`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_kill_chain_parallel_batches_keyscan_targets -q --color=no` -> `1 passed`
  Notes: canonical `forge.utils.intel.secret_finder` now actually honors `gitlab_token`/`FORGE_GITLAB_TOKEN`: GitLab blob search is token-gated, sequential, delay-paced, fetches raw file content when available, falls back to search snippets, extracts real pattern/group matches through the same helper as GitHub, and persists `source_backend='gitlab'` findings through the existing encrypted/redacted storage path. The active scanner already extracted real GitHub keys; the placeholder behavior found in `forge/phase2/key_scanner.py` is legacy/non-orchestrated for the CLI path.
  Backprop note: the first all-Phase-2 run failed in `tests/phase2/test_theharvester.py` because the unit tests mocked `subprocess.run` but not tool discovery, so missing local `theHarvester` leaked into tests. Fixed by mocking `forge.utils.intel.handle_finder._find_tool` in the version-check tests; no production behavior change.
  Safety: no provider concurrency increase, no proxy/IP rotation, no rate-limit bypass, no validation bypass, no scope relaxation, no destructive validation, and no persistent engagement DB mutation was added. GitLab search runs only when a token is configured and uses the existing validation/storage gates.
  Cleanup/commit: removed 3 pytest temp `.forge_data/engagements` folders; `remaining_pytest_engagement_dirs=0`. This workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue auditing real kill-chain correctness gaps before micro-optimizing more local loops; good candidates are GitLab/GitHub keyscan result fidelity, provider-specific source URL/display reviewability, and remaining safe in-process enrichers under bounded ordered workers.

- [x] Bounded validation scope-gate prep checkpoint is green:
  `python -m py_compile forge\phase4\cloud_validate.py tests\phase4\test_cloud_validate.py`
  `python -m ruff check forge\phase4\cloud_validate.py tests\phase4\test_cloud_validate.py`
  `python -m pytest tests/phase4/test_cloud_validate.py::test_sweep_pending_cloud_validations_scope_checker_skips_denied_key_rows tests/phase4/test_cloud_validate.py::test_sweep_pending_cloud_validations_parallelizes_scope_gate_and_preserves_order tests/phase4/test_cloud_validate.py::test_run_cloud_asset_validate_batch_scope_checker_skips_denied_assets tests/phase4/test_cloud_validate.py::test_run_cloud_asset_validate_batch_parallelizes_scope_gate_and_preserves_order tests/phase4/test_cloud_validate.py::test_sweep_pending_cloud_asset_validations_scope_checker_skips_denied_assets tests/phase4/test_cloud_validate.py::test_sweep_pending_cloud_asset_validations_parallelizes_scope_gate_and_preserves_order -q --color=no` -> `6 passed`
  `python -m pytest tests/phase4/test_cloud_validate.py -q --color=no` -> `105 passed`
  Notes: `sweep_pending_cloud_validations`, `run_cloud_asset_validate_batch`, and `sweep_pending_cloud_asset_validations` now run local scope checks through an ordered bounded worker helper before provider/cloud validation dispatch. Denial callbacks, DB writes, validation result ordering, and actual provider/cloud proof concurrency remain deterministic and governed by the existing validation `max_workers` path.
  Safety: local scope-prep throughput only. No live provider concurrency increase beyond configured validation workers, no proxy/IP rotation, no rate-limit bypass, no scope relaxation, no destructive validation, and no persistent engagement DB mutation was added.
  Cleanup/commit: pytest temp `.forge_data/engagements` folders were already clean; `remaining_pytest_engagement_dirs=0`. This workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue auditing the next safe sequential enrichers in artifact/provider/static-analysis fan-outs, preserving scope gates, provider caps, paced/backoff behavior, and deterministic ordered persistence.

- [x] Artifact-derived relation source provenance export checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py forge\reporting\dashboard.py forge\phase6\report_synthesizer.py tests\phase1\test_engagement_orchestrator.py tests\reporting\test_dashboard.py tests\phase4\test_attack_path.py tests\phase6\test_report_synthesizer.py`
  `python -m ruff check forge\engagement_orchestrator.py forge\reporting\dashboard.py forge\phase6\report_synthesizer.py tests\phase1\test_engagement_orchestrator.py tests\reporting\test_dashboard.py tests\phase4\test_attack_path.py tests\phase6\test_report_synthesizer.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_artifact_source_seed_relation_preserves_provenance_and_extract_rule tests/reporting/test_dashboard.py::test_generate_dashboard_emits_slug_routes_and_json_contract tests/phase4/test_attack_path.py::TestGraphBuildArtifacts::test_graph_build_all_writes_native_mtgx_workspace tests/phase6/test_report_synthesizer.py::test_synthesizer_template_and_raw_export_include_artifact_seed_relations -q --color=no` -> `4 passed`
  `python -m pytest tests/reporting/test_dashboard.py -q --color=no` -> `11 passed`
  `python -m pytest tests/phase4/test_attack_path.py -q --color=no` -> `100 passed`
  `python -m pytest tests/phase6/test_report_synthesizer.py -q --color=no` -> `71 passed`
  `python -m pytest -p no:rerunfailures tests/phase1/test_engagement_orchestrator.py::test_artifact_source_seed_relation_preserves_provenance_and_extract_rule tests/phase1/test_engagement_orchestrator.py::test_kill_chain_wayback_commoncrawl_preserves_url_level_archive_source -q --color=no` -> `2 passed`
  Notes: `_link_artifact_source_seed` now merges whitelisted artifact source seed provenance into `seed_relations.evidence_json`, including `archive_sources`, `provider_sources`, `root_domain`, and `discovered_from`. Duplicate relation insertion now merges newer evidence instead of silently preserving stale partial metadata. Dashboard and deterministic report evidence summaries expose compact `sources=` and `root=` values, while graph JSON/GraphML/MTGX and raw report exports carry scrubbed relation metadata.
  Safety: provenance storage/export only. No live external probing expansion, proxy/IP rotation, rate-limit bypass, scope relaxation, destructive validation, or persistent engagement DB mutation was added.
  Cleanup/commit: removed 4 pytest temp `.forge_data/engagements` folders; `remaining_pytest_engagement_dirs=0`. This workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue moving the remaining safe sequential enrichers under the bounded worker-pool path beyond the current D1/D2/D5 parsing coverage, preserving scope gates, ROE checks, and respectful backoff.

- [x] Artifact queue archive/source provenance inheritance checkpoint is green:
  `python -m py_compile forge\cli.py forge\reporting\dashboard.py tests\phase1\test_engagement_orchestrator.py tests\reporting\test_dashboard.py`
  `python -m ruff check forge\cli.py forge\reporting\dashboard.py tests\phase1\test_engagement_orchestrator.py tests\reporting\test_dashboard.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_kill_chain_wayback_commoncrawl_preserves_url_level_archive_source tests/reporting/test_dashboard.py::test_generate_dashboard_surfaces_archive_url_source_in_crawl_rows -q --color=no` -> `2 passed`
  `python -m pytest tests/reporting/test_dashboard.py -q --color=no` -> `11 passed`
  `python -m pytest -p no:rerunfailures tests/phase1/test_engagement_orchestrator.py::test_kill_chain_parallel_batches_wayback_host_parse tests/phase1/test_engagement_orchestrator.py::test_engagement_provider_matrix_recursion_preserves_caps_and_exports tests/phase1/test_engagement_orchestrator.py::test_kill_chain_wayback_commoncrawl_preserves_url_level_archive_source -q --color=no` -> `3 passed`
  Notes: `_queue_discovered_artifacts` now inherits safe crawl/archive provenance from `crawl_results.tech_stack_json` and URL seed `metadata_json` into `artifact_queue.metadata_json` for remote artifacts, including `archive_sources`, `provider_sources`, `root_domain`, and `discovered_from`. Artifact URL seeds created by the queue also keep this metadata. Dashboard artifact queue rows now expose a `Source` column for analyst review.
  Safety: provenance storage/display only. No live external probing expansion, proxy/IP rotation, rate-limit bypass, scope relaxation, destructive validation, or persistent engagement DB mutation was added.
  Cleanup/commit: removed 16 pytest temp `.forge_data/engagements` folders; `remaining_pytest_engagement_dirs=0`. This workspace is intentionally not a git repo, so no commit was attempted.
  Completed next audit target: artifact queue inherited provider/archive source now reaches artifact-derived seed relation evidence and graph/report edge metadata.

- [x] Exact archive URL source provenance checkpoint is green:
  `python -m py_compile forge\cli.py forge\reporting\dashboard.py forge\phase6\report_synthesizer.py tests\phase1\test_engagement_orchestrator.py tests\reporting\test_dashboard.py tests\phase6\test_report_synthesizer.py`
  `python -m ruff check forge\cli.py forge\reporting\dashboard.py forge\phase6\report_synthesizer.py tests\phase1\test_engagement_orchestrator.py tests\reporting\test_dashboard.py tests\phase6\test_report_synthesizer.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_kill_chain_wayback_commoncrawl_preserves_url_level_archive_source tests/reporting/test_dashboard.py::test_generate_dashboard_surfaces_archive_url_source_in_crawl_rows tests/phase6/test_report_synthesizer.py::test_synthesizer_template_and_raw_export_include_archive_url_provenance -q --color=no` -> `3 passed`
  `python -m pytest tests/phase6/test_report_synthesizer.py -q --color=no` -> `71 passed`
  `python -m pytest tests/reporting/test_dashboard.py -q --color=no` -> `11 passed`
  `python -m pytest -p no:rerunfailures tests/phase1/test_engagement_orchestrator.py::test_kill_chain_parallel_batches_wayback_host_parse tests/phase1/test_engagement_orchestrator.py::test_engagement_provider_matrix_recursion_preserves_caps_and_exports tests/phase1/test_engagement_orchestrator.py::test_kill_chain_wayback_commoncrawl_preserves_url_level_archive_source -q --color=no` -> `3 passed`
  Notes: Fan-out I now preserves URL-level Wayback vs CommonCrawl source before deduping historical archive results. `crawl_results.tech_stack_json` and URL seed `metadata_json` carry `archive_sources`, `provider_sources`, `root_domain`, and `discovered_from`. Dashboard crawl rows expose a `Source` column. Phase 6 `ReconContext.archive_urls`, deterministic Markdown, companion JSON context, and raw CSV fallback now include bounded archive URL provenance with URL queries stripped from report display.
  Safety: provenance storage/export only. No live external probing expansion, proxy/IP rotation, rate-limit bypass, scope relaxation, destructive validation, or persistent engagement DB mutation was added.
  Cleanup/commit: removed 16 pytest temp `.forge_data/engagements` folders; `remaining_pytest_engagement_dirs=0`. This workspace is intentionally not a git repo, so no commit was attempted.
  Completed next audit target: artifact queue provenance now inherits crawl/archive source metadata for remote artifacts.

- [x] Provider-source host graph metadata checkpoint is green:
  `python -m py_compile forge\phase4\attack_path.py tests\phase4\test_attack_path.py tests\phase1\test_engagement_orchestrator.py`
  `python -m ruff check forge\phase4\attack_path.py tests\phase4\test_attack_path.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests/phase4/test_attack_path.py::TestLoadHosts::test_host_context_provider_metadata_exported_and_scrubbed -q --color=no` -> `1 passed`
  `python -m pytest -p no:rerunfailures tests/phase1/test_engagement_orchestrator.py::test_engagement_provider_matrix_recursion_preserves_caps_and_exports -q --color=no` -> `1 passed`
  `python -m pytest tests/phase4/test_attack_path.py -q --color=no` -> `100 passed`
  `python -m pytest tests/reporting/test_dashboard.py::test_generate_dashboard_surfaces_provider_matrix_artifacts_and_validation_evidence -q --color=no` -> `1 passed`
  Notes: `hosts.host_context` is now parsed, scrubbed, and exported on graph host nodes as nested `host_context` plus compact provenance keys. Shodan, urlscan, and merged historical archive discoveries now emit `provider_sources` into attack graph JSON, portable GraphML, native MTGX GraphML, and MTGX manifest node metadata. The provider-matrix kill-chain fixture proves this through the real graph closeout path.
  Backprop note: the first focused run failed because the new SQL query missed the comma before its parameter tuple; fixed in `forge/phase4/attack_path.py`. This was a mechanical patch typo, so no new invariant was added.
  Safety: metadata export only. No live external probing, proxy/IP rotation, rate-limit bypass, scope relaxation, destructive validation, or persistent engagement DB mutation was added.
  Cleanup/commit: removed 3 pytest temp `.forge_data/engagements` folders; `remaining_pytest_engagement_dirs=0`. This workspace is intentionally not a git repo, so no commit was attempted.
  Completed next audit target: exact Wayback versus CommonCrawl URL-level source is now preserved before the `historical_cdx` merge and exposed in dashboard/report exports.

- [x] Passive robots/sitemap recursive artifact queue checkpoint is green:
  `python -m py_compile tests\phase1\test_engagement_orchestrator.py tests\integration\test_webui_engagement_api.py`
  `python -m ruff check tests\phase1\test_engagement_orchestrator.py tests\integration\test_webui_engagement_api.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_kill_chain_passive_text_mining_promotes_robots_and_sitemap_urls_without_live_network -q --color=no` -> `1 passed`
  `python -m pytest tests/integration/test_webui_engagement_api.py::test_engagement_api_prefers_snapshot_graph_over_report_artifacts -q --color=no` -> `1 passed, 2 warnings`
  Notes: no production code change was needed for this path. The existing D2 passive text mining plus K2 artifact queue already supports robots/sitemap discovered static artifacts; the regression now proves sitemap-discovered JavaScript is persisted as crawl data, queued and parsed as a remote `config` artifact, promotes a Firebase cloud asset, and records artifact-derived seed relation provenance. Stale graph edge CSV test fixtures were updated to the current `MetadataJSON` header introduced by the graph metadata export.
  Safety: mocked/local fixtures only. No live external probing, proxy/IP rotation, rate-limit bypass, scope relaxation, destructive validation, or persistent engagement DB mutation was added.
  Cleanup/commit: removed 2 pytest temp `.forge_data/engagements` folders; `remaining_pytest_engagement_dirs=0`. This workspace is intentionally not a git repo, so no commit was attempted.
  Completed next audit target: provider-source host provenance now reaches graph exports via the provider-source host graph metadata checkpoint above.

- [x] Artifact-derived relation graph/report export and crawler backoff checkpoint is green:
  `python -m py_compile forge\models\attack_graph_models.py forge\phase4\attack_path.py forge\cli.py forge\phase6\report_synthesizer.py forge\phase1\crawler.py tests\phase4\test_attack_path.py tests\phase6\test_report_synthesizer.py tests\phase1\test_crawler.py tests\reporting\test_dashboard.py`
  `python -m ruff check forge\models\attack_graph_models.py forge\phase4\attack_path.py forge\cli.py forge\phase6\report_synthesizer.py forge\phase1\crawler.py tests\phase4\test_attack_path.py tests\phase6\test_report_synthesizer.py tests\phase1\test_crawler.py tests\reporting\test_dashboard.py`
  `python -m pytest tests/phase4/test_attack_path.py -q --color=no` -> `99 passed`
  `python -m pytest tests/phase6/test_report_synthesizer.py -q --color=no` -> `70 passed`
  `python -m pytest tests/reporting/test_dashboard.py -q --color=no` -> `10 passed`
  `python -m pytest tests/phase1/test_crawler.py -q --color=no` -> `2 passed`
  `python -m pytest tests/cli/test_direct_live_scope.py::test_crawler_filters_out_of_prefix_links_before_fetch tests/cli/test_direct_live_scope.py::test_direct_recon_crawl_passes_scope_to_crawler -q --color=no` -> `2 passed`
  Notes: artifact-derived `seed_relations` now survive attack graph JSON, portable GraphML, native MTGX link properties, MTGX manifest edges, edge CSV, deterministic Markdown reports, report JSON context, and raw CSV fallback. Relation evidence is scrubbed for forbidden keys before graph/report export. First-party crawler now honors bounded `Retry-After`/429/503 backoff with `FORGE_WEB_FETCH_RATE_LIMIT_RETRIES` and `FORGE_WEB_FETCH_RATE_LIMIT_BACKOFF_SECONDS`, without proxy/IP rotation or bypass behavior.
  Safety: export/report fidelity and respectful backoff only. No live target was contacted, no proxy/IP rotation, no rate-limit bypass, no destructive validation, and no persistent engagement DB mutation was added.
  Cleanup/commit: pytest temp `.forge_data/engagements` dirs are `remaining=0`. This workspace is intentionally not a git repo, so no commit was attempted.
  Completed next audit target: mocked/local robots/sitemap expansion into the artifact queue is now covered by the passive text static artifact checkpoint above.

- [x] Artifact-derived seed relation reviewability checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py forge\reporting\dashboard.py tests\phase1\test_engagement_orchestrator.py tests\reporting\test_dashboard.py`
  `python -m ruff check forge\engagement_orchestrator.py forge\reporting\dashboard.py tests\phase1\test_engagement_orchestrator.py tests\reporting\test_dashboard.py`
  `python -m pytest tests/reporting/test_dashboard.py -q --color=no` -> `10 passed`
  `python -m pytest -p no:rerunfailures tests/phase1/test_engagement_orchestrator.py -k "artifact_source_seed_relation_preserves_provenance_and_extract_rule or remote_well_known_metadata_seeds or remote_openid_configuration_seed or remote_apple_app_site_association_seed or web_app_manifest_artifacts" -q --color=no` -> `5 passed, 463 deselected`
  Notes: artifact-derived `seed_relations` now preserve `rule=artifact_seed_provenance` and move parser/source rules into `extract_rule`, so recursive pivots remain auditable. The engagement detail dashboard preview now prioritizes compact artifact evidence facts (`extract_rule`, parser/format, payload counts) before long URLs.
  Backprop note: the first dashboard contract run failed because long source URLs could truncate `payload_count`; the preview now orders compact audit facts before long source/file paths.
  Safety: storage/display fidelity only. No live probing, artifact parsing semantics, proxy/IP rotation, rate-limit bypass, provider-limit bypass, destructive validation, or persistent engagement DB mutation was added.
  Cleanup/commit: removed 42 pytest temp `.forge_data/engagements` folders; `remaining_pytest_engagement_dirs=0`. This workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: broaden another non-live recursive discovery fixture, or audit report/graph surfacing for artifact-derived seed relations.

- [x] Engagement ID auto-increment re-verification is green:
  `python -m py_compile forge\engagement_ids.py forge\webui\app.py tests\phase1\test_engagement_ids.py tests\integration\test_webui_engagement_api.py`
  `python -m ruff check forge\engagement_ids.py forge\webui\app.py tests\phase1\test_engagement_ids.py tests\integration\test_webui_engagement_api.py`
  `python -m pytest tests/phase1/test_engagement_ids.py tests/integration/test_webui_engagement_api.py::test_engagement_create_and_seed_crud_routes tests/integration/test_webui_engagement_api.py::test_engagement_create_uses_monotonic_sequence_after_deleted_db -q --color=no` -> `5 passed, 12 warnings`
  Notes: no code change was needed. The current shared allocator uses `.forge_data/engagements/master.db`, seeds from existing numeric DB files, serializes allocation, skips control DBs, and prevents ID reuse after deleted engagement DBs.
  Cleanup/commit: removed 5 pytest temp `.forge_data/engagements` folders; `remaining_pytest_engagement_dirs=0`. This workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue dashboard/report reviewability for artifact-derived seeds, or broaden another non-live recursive discovery fixture.

- [x] Dashboard artifact provenance checkpoint is green:
  `python -m py_compile forge\reporting\dashboard.py tests\reporting\test_dashboard.py`
  `python -m ruff check forge\reporting\dashboard.py tests\reporting\test_dashboard.py`
  `python -m pytest tests/reporting/test_dashboard.py::test_generate_dashboard_emits_slug_routes_and_json_contract -q --color=no` -> `1 passed`
  `python -m pytest tests/reporting/test_dashboard.py -q --color=no` -> `10 passed`
  `python -m py_compile forge\engagement_orchestrator.py forge\webui\app.py forge\reporting\dashboard.py tests\phase1\test_engagement_orchestrator.py tests\reporting\test_dashboard.py`
  `python -m ruff check forge\engagement_orchestrator.py forge\webui\app.py forge\reporting\dashboard.py tests\phase1\test_engagement_orchestrator.py tests\reporting\test_dashboard.py`
  Notes: the engagement detail dashboard artifact queue section now surfaces optional `discovered_from` as `Origin` and `local_path` as `Local` when those columns exist. This makes artifact-derived pivots reviewable from the dashboard without breaking older DBs that lack those columns.
  Safety: dashboard/reporting visibility only. No live probing, artifact parsing semantics, proxy/IP rotation, rate-limit bypass, provider-limit bypass, destructive validation, or persistent engagement DB mutation was added.
  Cleanup/commit: removed 11 pytest temp `.forge_data/engagements` folders; `remaining_pytest_engagement_dirs=0`. This workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue dashboard/report reviewability for artifact-derived seeds, or broaden another non-live recursive discovery fixture.

- [x] Remote `.well-known` metadata kill-chain recursion checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py forge\webui\app.py tests\phase1\test_engagement_orchestrator.py`
  `python -m ruff check forge\engagement_orchestrator.py forge\webui\app.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest -p no:rerunfailures tests/phase1/test_engagement_orchestrator.py::test_classify_seed_value_recognizes_archive_style_mobile_bundle_urls tests/phase1/test_engagement_orchestrator.py::test_kill_chain_dry_run_processes_remote_well_known_metadata_seeds -q --color=no` -> `2 passed`
  `python -m pytest -p no:rerunfailures tests/phase1/test_engagement_orchestrator.py -k "classify_seed_value or remote_well_known_metadata_seeds or remote_openid_configuration_seed or remote_apple_app_site_association_seed or apple_app_site_association_artifacts or extensionless_seed_image_url or header_filename" -q --color=no` -> `7 passed, 460 deselected`
  Notes: WebFinger, Matrix server discovery, and change-password URLs now work through the real dry-run seed path as no-extension `.well-known` config artifacts. Backprop note: the initial regression caught URL seeds with `acct:user@example.com` query values being misclassified as email; backend and web UI seed classifiers now prioritize valid `http(s)` URLs before email matching.
  Safety: local HTTP fixtures and dry-run only. No live external probing, proxy/IP rotation, rate-limit bypass, provider-limit bypass, destructive validation, or persistent engagement DB mutation was added.
  Cleanup/commit: removed 6 pytest temp `.forge_data/engagements` folders; `remaining_pytest_engagement_dirs=0`. This workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: broaden a non-live recursive discovery fixture beyond `.well-known` metadata, or audit dashboard/report surfacing for these artifact-derived pivots.

- [x] Remote OpenID/OAuth discovery kill-chain recursion checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest -p no:rerunfailures tests/phase1/test_engagement_orchestrator.py::test_kill_chain_dry_run_processes_remote_openid_configuration_seed -q --color=no` -> `1 passed`
  `python -m pytest -p no:rerunfailures tests/phase1/test_engagement_orchestrator.py -k "remote_apple_app_site_association_seed or remote_openid_configuration_seed or apple_app_site_association_artifacts or web_app_manifest_artifacts or extensionless_seed_image_url or header_filename" -q --color=no` -> `6 passed, 460 deselected`
  Notes: `/.well-known/openid-configuration` is now a first-class no-extension config artifact. The dry-run fixture proves related seed -> artifact queue -> remote download -> cache-prefix type/format inference -> parse -> OAuth endpoint URLs, owner email, Supabase cloud asset, and provenance relation creation.
  Safety: local HTTP fixture and dry-run only. No live external probing, proxy/IP rotation, rate-limit bypass, provider-limit bypass, destructive validation, or persistent engagement DB mutation was added.
  Cleanup/commit: removed 4 pytest temp `.forge_data/engagements` folders; `remaining_pytest_engagement_dirs=0`. This workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue with another concrete no-extension `.well-known` parser gap or broaden a non-live recursion fixture.

- [x] Remote AASA kill-chain recursion checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest -p no:rerunfailures tests/phase1/test_engagement_orchestrator.py::test_kill_chain_dry_run_processes_remote_apple_app_site_association_seed -q --color=no` -> `1 passed`
  `python -m pytest -p no:rerunfailures tests/phase1/test_engagement_orchestrator.py -k "remote_apple_app_site_association_seed or remote_ocr_artifact or extensionless_seed_image_url or rate_limited_remote_artifact or header_filename" -q --color=no` -> `5 passed, 460 deselected`
  Notes: no-extension AASA URLs now work through the real dry-run seed path: related seed -> artifact queue as `config` -> remote download -> cache-prefix type/format inference -> parse -> recursive email, URL, Supabase cloud asset, and provenance relation creation.
  Safety: local HTTP fixture and dry-run only. No live external probing, proxy/IP rotation, rate-limit bypass, provider-limit bypass, destructive validation, or persistent engagement DB mutation was added.
  Cleanup/commit: removed 4 pytest temp `.forge_data/engagements` folders; `remaining_pytest_engagement_dirs=0`. This workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue with another concrete no-extension `.well-known` parser gap, such as OpenID/OAuth discovery metadata.

- [x] Apple app site association recursion checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_apple_app_site_association_artifacts -q --color=no` -> `1 passed`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "spa_manifest_relative_routes or framework_route_manifest_declarations or web_app_manifest_artifacts or apple_app_site_association_artifacts or document_and_archive_findings" -q --color=no` -> `5 passed, 459 deselected`
  Notes: `/.well-known/apple-app-site-association` is now route-discoverable despite lacking an extension, and local no-extension `apple-app-site-association` files are parsed as config artifacts. The regression proves AASA content can feed emails, URLs, and Supabase cloud refs back into recursive discovery while `.git` paths remain skipped.
  Safety: passive static parsing and route-seed promotion only. No live probing breadth, proxy/IP rotation, rate-limit bypass, provider-limit bypass, destructive validation, or persistent engagement DB mutation was added.
  Cleanup/commit: removed 0 pytest temp `.forge_data/engagements` folders; `remaining_pytest_engagement_dirs=0`. This workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue with another concrete passive parser/container gap or broaden a non-live recursion fixture; avoid adding live provider behavior unless official read-only proof endpoints and mocked fixtures are available.

- [x] Web app manifest artifact recursion checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_web_app_manifest_artifacts -q --color=no` -> `1 passed`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "source_map_artifacts or spa_manifest_relative_routes or framework_route_manifest_declarations or web_app_manifest_artifacts or document_and_archive_findings" -q --color=no` -> `5 passed, 458 deselected`
  Notes: `.webmanifest` files are now first-class passive config/text artifacts for both top-level ingestion and nested archive members, and `application/manifest+json` maps back to `.webmanifest` on remote downloads. The regression proves web app manifests can feed emails, URLs, and Supabase cloud refs back into recursive discovery.
  Safety: passive static parsing only. No live probing breadth, proxy/IP rotation, rate-limit bypass, provider-limit bypass, destructive validation, or persistent engagement DB mutation was added.
  Cleanup/commit: removed 0 pytest temp `.forge_data/engagements` folders; `remaining_pytest_engagement_dirs=0`. This workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue with another concrete passive parser/container gap or broaden a non-live recursion fixture; avoid adding live provider behavior unless official read-only proof endpoints and mocked fixtures are available.

- [x] Mixed-provider kill-chain graph-family proof checkpoint is green:
  `python -m py_compile tests\phase1\test_engagement_orchestrator.py forge\phase4\attack_path.py forge\reporting\dashboard.py`
  `python -m ruff check tests\phase1\test_engagement_orchestrator.py forge\phase4\attack_path.py forge\reporting\dashboard.py`
  `$env:FORGE_KEY_VALIDATION_REQUEST_DELAY_SECONDS='0'; $env:FORGE_KEY_VALIDATION_RATE_LIMIT_BACKOFF_SECONDS='1'; python -m pytest -p no:rerunfailures tests/phase1/test_engagement_orchestrator.py::test_kill_chain_local_generic_secret_artifacts_feed_mixed_key_validation -q --color=no` -> `1 passed`; exit code `0` with the known Windows access-violation shutdown trace after the pass.
  Notes: the engagement-backed mixed-provider kill-chain fixture now proves provider validation proof metadata survives the real closeout path into `1001_attack_graph.json`, portable GraphML, native MTGX GraphML, and MTGX `manifest.json`. It asserts Sentry, Cloudflare, and PostHog proof strings are visible for analysts while full Slack, PostHog, and Azure secret material is not exported; Azure connection-string account context remains visible only with `AccountKey=<redacted>`.
  Safety: this is test/graph fidelity coverage over existing mocked provider validators and static artifacts. No live probing breadth, proxy/IP rotation, rate-limit bypass, provider-limit bypass, destructive validation, or persistent engagement DB mutation was added.
  Cleanup/commit: removed 3 pytest temp `.forge_data/engagements` folders; `remaining_pytest_engagement_dirs=0`. This workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue with another concrete passive parser/container gap or broaden a non-live recursion fixture; avoid adding live provider behavior unless official read-only proof endpoints and mocked fixtures are available.

- [x] API-key validation proof graph/dashboard fidelity checkpoint is green:
  `python -m py_compile forge\phase4\attack_path.py forge\reporting\dashboard.py tests\phase4\test_attack_path.py tests\reporting\test_dashboard.py`
  `python -m ruff check forge\phase4\attack_path.py forge\reporting\dashboard.py tests\phase4\test_attack_path.py tests\reporting\test_dashboard.py`
  `python -m pytest tests/phase4/test_attack_path.py::TestLoadApiKeys::test_active_apikey_node_carries_validation_proof_metadata tests/phase4/test_attack_path.py::TestGraphBuildArtifacts::test_graph_build_all_writes_native_mtgx_workspace tests/reporting/test_dashboard.py::test_generate_dashboard_surfaces_key_validation_proof_rows -q --color=no` -> `3 passed`
  `python -m pytest tests/phase4/test_attack_path.py -q --color=no` -> `99 passed`
  `python -m pytest tests/reporting/test_dashboard.py -q --color=no` -> `10 passed`
  Notes: active `key_scanner_findings` graph nodes now preserve sanitized validation proof metadata: `validation_state`, `validation_detail`, `validated_at`, `source_backend`, and `repo_name`, alongside the existing service/pattern/domain/source URL metadata. JSON, GraphML, native MTGX `forge.metadata_json`, and MTGX `manifest.json` now expose that proof for analyst review without raw/encrypted key fields. The static dashboard's `Recent Key Findings` section also shows backend, source, repository, proof, and validated timestamp.
  Safety: no raw key, `key_enc`, `key_raw`, password, hash, exploitation, live probing breadth, proxy/IP rotation, rate-limit bypass, provider-limit bypass, or persistent engagement DB mutation was added.
  Cleanup/commit: removed 13 pytest temp `.forge_data/engagements` folders; `remaining_pytest_engagement_dirs=0`. This workspace is intentionally not a git repo, so no commit was attempted.
  Next audit target: continue with another concrete passive parser/container gap or a larger mixed-provider recursion fixture; avoid adding live provider behavior unless official read-only proof endpoints and mocked fixtures are available.

- [x] Image artifact metadata fallback checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_artifact_queue_processor_extracts_image_metadata_without_ocr -q --color=no` -> `1 passed`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "ocrs_image_and_embedded_media_payloads or extracts_image_metadata_without_ocr or ocrs_scanned_pdf_pages or remote_ocr_artifact or extensionless_seed_image_url or rate_limited_remote_artifact or header_filename" -q --color=no` -> `7 passed, 455 deselected`
  Notes: raster image artifacts now emit passive `#image-metadata` payloads by carving bounded ASCII/UTF-16 strings from EXIF/XMP/PNG text-style bytes in addition to optional OCR. This lets screenshots/posters with embedded metadata, or operators without Tesseract installed, still feed email, URL, and Supabase/cloud pivots back into recursive discovery. Top-level images and embedded OOXML/archive image members share the same ordered local worker-pool path, and existing OCR behavior remains covered.
  Safety: this is passive local static analysis only. No live probing breadth, proxy/IP rotation, rate-limit bypass, provider-limit bypass, destructive validation, or persistent engagement DB mutation was added.
  Cleanup/commit: removed 2 pytest temp `.forge_data/engagements` folders; `remaining_pytest_engagement_dirs=0`. `git status --short` still fails because this workspace is not a git repository, so no commit can be created.
  Next audit target: continue artifact/container resilience with another concrete parser gap, or audit graph/dashboard fidelity for newly validated non-cloud key proof rows before adding more live provider behavior.

- [x] Edge/deploy/product-analytics/error-monitoring provider key validation checkpoint is green:
  `python -m py_compile forge\utils\intel\secret_finder.py forge\phase2\key_scanner.py forge\phase4\cloud_validate.py tests\phase2\test_secret_finder.py tests\phase2\test_key_scanner.py tests\phase4\test_cloud_validate.py tests\phase1\test_engagement_orchestrator.py`
  `python -m ruff check forge\utils\intel\secret_finder.py forge\phase2\key_scanner.py forge\phase4\cloud_validate.py tests\phase2\test_secret_finder.py tests\phase2\test_key_scanner.py tests\phase4\test_cloud_validate.py tests\phase1\test_engagement_orchestrator.py`
  `$env:FORGE_KEY_VALIDATION_REQUEST_DELAY_SECONDS='0'; python -m pytest tests/phase2/test_secret_finder.py -k "collaboration_observability or cloudflare or vercel or netlify or posthog or sentry" -q --color=no` -> `10 passed, 53 deselected`
  `$env:FORGE_KEY_VALIDATION_REQUEST_DELAY_SECONDS='0'; python -m pytest tests/phase2/test_key_scanner.py -k "collaboration_observability" -q --color=no` -> `1 passed, 49 deselected`
  `$env:FORGE_KEY_VALIDATION_REQUEST_DELAY_SECONDS='0'; python -m pytest tests/phase4/test_cloud_validate.py -k "social_messaging_and_collaboration_provider_tokens" -q --color=no` -> `1 passed, 101 deselected`
  `$env:FORGE_KEY_VALIDATION_REQUEST_DELAY_SECONDS='0'; $env:FORGE_KEY_VALIDATION_RATE_LIMIT_BACKOFF_SECONDS='1'; python -m pytest tests/phase2/test_secret_finder.py -q --color=no` -> `63 passed`
  `$env:FORGE_KEY_VALIDATION_REQUEST_DELAY_SECONDS='0'; $env:FORGE_KEY_VALIDATION_RATE_LIMIT_BACKOFF_SECONDS='1'; python -m pytest tests/phase2/test_key_scanner.py -q --color=no` -> `50 passed`
  `$env:FORGE_KEY_VALIDATION_REQUEST_DELAY_SECONDS='0'; $env:FORGE_KEY_VALIDATION_RATE_LIMIT_BACKOFF_SECONDS='1'; python -m pytest tests/phase4/test_cloud_validate.py -q --color=no` -> `102 passed`
  `$env:FORGE_KEY_VALIDATION_REQUEST_DELAY_SECONDS='0'; $env:FORGE_KEY_VALIDATION_RATE_LIMIT_BACKOFF_SECONDS='1'; python -m pytest -p no:rerunfailures tests/phase1/test_engagement_orchestrator.py::test_kill_chain_local_generic_secret_artifacts_feed_mixed_key_validation -q --color=no` -> `1 passed`; exit code `0` with the known Windows access-violation shutdown trace after the pass.
  JSON sanity: canonical, legacy, and generic pattern files load successfully with 30, 30, and 26 patterns respectively.
  Notes: Cloudflare, Vercel, Netlify, PostHog, and Sentry credentials discovered in static artifacts now flow through shared/legacy detection, read-only provider proof, Phase 4 proof parsing, deterministic `HIGH` key-exposure findings, graph/report finalization, and dashboard-reviewable DB rows. Vercel/Netlify credential services now bypass the Firebase cloud-asset alias only in key-validation proof parsing, preserving existing Vercel/Netlify static-hosting cloud probes.
  Safety: validators use only read-only official proof endpoints: Cloudflare `GET /user/tokens/verify`, Vercel `GET /v2/user`, Netlify `GET /api/v1/user`, PostHog `GET /api/users/@me/` on documented cloud hosts, and Sentry `GET /api/0/organizations/`. HTTP 429, malformed responses, missing proof IDs, scoped/inconclusive PostHog failures, and scoped/inconclusive Sentry 403s do not become validated findings. No proxy/IP rotation, rate-limit bypass, provider-limit bypass, scope relaxation, destructive validation, or persistent engagement DB mutation was added.
  Cleanup/commit: removed 1 pytest temp `.forge_data/engagements` folder; `remaining_pytest_engagement_dirs=0`. `git status --short` still fails because this workspace is not a git repository, so no commit can be created.
  Next audit target: continue artifact/container/OCR coverage, graph fidelity, and larger mixed-provider recursion fixtures; add more provider validators only when official read-only proof endpoints and mocked fixtures are available.

- [x] Collaboration/observability provider key validation checkpoint is green:
  `python -m py_compile forge\utils\intel\secret_finder.py forge\phase2\key_scanner.py forge\phase4\cloud_validate.py tests\phase2\test_secret_finder.py tests\phase2\test_key_scanner.py tests\phase4\test_cloud_validate.py tests\phase1\test_engagement_orchestrator.py`
  `python -m ruff check forge\utils\intel\secret_finder.py forge\phase2\key_scanner.py forge\phase4\cloud_validate.py tests\phase2\test_secret_finder.py tests\phase2\test_key_scanner.py tests\phase4\test_cloud_validate.py tests\phase1\test_engagement_orchestrator.py`
  `$env:FORGE_KEY_VALIDATION_REQUEST_DELAY_SECONDS='0'; python -m pytest tests/phase2/test_secret_finder.py -k "collaboration_observability or notion or datadog" -q --color=no`
  `$env:FORGE_KEY_VALIDATION_REQUEST_DELAY_SECONDS='0'; python -m pytest tests/phase2/test_key_scanner.py -k "collaboration_observability" -q --color=no`
  `$env:FORGE_KEY_VALIDATION_REQUEST_DELAY_SECONDS='0'; python -m pytest tests/phase4/test_cloud_validate.py -k "social_messaging_and_collaboration_provider_tokens" -q --color=no`
  `$env:FORGE_KEY_VALIDATION_REQUEST_DELAY_SECONDS='0'; $env:FORGE_KEY_VALIDATION_RATE_LIMIT_BACKOFF_SECONDS='1'; python -m pytest tests/phase2/test_secret_finder.py -q --color=no`
  `$env:FORGE_KEY_VALIDATION_REQUEST_DELAY_SECONDS='0'; $env:FORGE_KEY_VALIDATION_RATE_LIMIT_BACKOFF_SECONDS='1'; python -m pytest tests/phase2/test_key_scanner.py -q --color=no`
  `$env:FORGE_KEY_VALIDATION_REQUEST_DELAY_SECONDS='0'; $env:FORGE_KEY_VALIDATION_RATE_LIMIT_BACKOFF_SECONDS='1'; python -m pytest tests/phase4/test_cloud_validate.py -q --color=no`
  `$env:FORGE_KEY_VALIDATION_REQUEST_DELAY_SECONDS='0'; $env:FORGE_KEY_VALIDATION_RATE_LIMIT_BACKOFF_SECONDS='1'; python -m pytest -p no:rerunfailures tests/phase1/test_engagement_orchestrator.py::test_kill_chain_local_generic_secret_artifacts_feed_mixed_key_validation -q --color=no`
  Result: Ruff clean; focused validator slices `6 passed, 48 deselected`, `1 passed, 49 deselected`, `1 passed, 101 deselected`; adjacent full suites `54 passed`, `50 passed`, `102 passed`; kill-chain fixture assertion passed. The Windows pytest process emitted the known access-violation trace after the kill-chain pass while still exiting `0`.
  Cleanup: removed 1 pytest temp `.forge_data/engagements` folder; `remaining_pytest_engagement_dirs=0`. Persistent workspace `.forge_data/engagements` DBs were not deleted because they are not proven test artifacts from this run.
  Notes: Notion and Datadog credentials are now detected by shared and legacy key scanners plus generic secret patterns. Validators use only read-only proof endpoints: Notion `GET /v1/users/me` and Datadog `GET /api/v1/validate` across documented Datadog sites. They route through existing key-validation pacing/backoff, persist non-secret proof identifiers, and feed validated artifact-discovered keys into deterministic `HIGH` key-exposure findings. No workspace/user listing, Datadog data reads, proxy/IP rotation, rate-limit bypass, provider-limit bypass, scope relaxation, destructive validation, or persistent engagement DB mutation was added. `git status --short` still fails because this workspace is not a git repository.
  Completed next audit target: safe read-only validators added for Notion and Datadog credentials discovered from static artifacts.
  Next audit target: add only similarly safe read-only validators for remaining high-value providers such as Cloudflare, Vercel/Netlify, Sentry, and PostHog where official proof endpoints and mocked fixtures are available; continue artifact/container/OCR coverage and graph fidelity audits.

- [x] Social/messaging provider key validation checkpoint is green:
  `python -m py_compile forge\utils\intel\secret_finder.py forge\phase2\key_scanner.py forge\phase4\cloud_validate.py tests\phase2\test_secret_finder.py tests\phase2\test_key_scanner.py tests\phase4\test_cloud_validate.py tests\phase1\test_engagement_orchestrator.py`
  `python -m ruff check forge\utils\intel\secret_finder.py forge\phase2\key_scanner.py forge\phase4\cloud_validate.py tests\phase2\test_secret_finder.py tests\phase2\test_key_scanner.py tests\phase4\test_cloud_validate.py tests\phase1\test_engagement_orchestrator.py`
  `$env:FORGE_KEY_VALIDATION_REQUEST_DELAY_SECONDS='0'; python -m pytest tests/phase2/test_secret_finder.py -k "social_messaging or huggingface or discord or telegram" -q --color=no`
  `$env:FORGE_KEY_VALIDATION_REQUEST_DELAY_SECONDS='0'; python -m pytest tests/phase2/test_key_scanner.py -k "social_messaging" -q --color=no`
  `$env:FORGE_KEY_VALIDATION_REQUEST_DELAY_SECONDS='0'; python -m pytest tests/phase4/test_cloud_validate.py -k "social_messaging_provider_tokens" -q --color=no`
  `$env:FORGE_KEY_VALIDATION_REQUEST_DELAY_SECONDS='0'; $env:FORGE_KEY_VALIDATION_RATE_LIMIT_BACKOFF_SECONDS='1'; python -m pytest tests/phase2/test_secret_finder.py -q --color=no`
  `$env:FORGE_KEY_VALIDATION_REQUEST_DELAY_SECONDS='0'; $env:FORGE_KEY_VALIDATION_RATE_LIMIT_BACKOFF_SECONDS='1'; python -m pytest tests/phase2/test_key_scanner.py -q --color=no`
  `$env:FORGE_KEY_VALIDATION_REQUEST_DELAY_SECONDS='0'; $env:FORGE_KEY_VALIDATION_RATE_LIMIT_BACKOFF_SECONDS='1'; python -m pytest tests/phase4/test_cloud_validate.py -q --color=no`
  `$env:FORGE_KEY_VALIDATION_REQUEST_DELAY_SECONDS='0'; $env:FORGE_KEY_VALIDATION_RATE_LIMIT_BACKOFF_SECONDS='1'; python -m pytest -p no:rerunfailures tests/phase1/test_engagement_orchestrator.py::test_kill_chain_local_generic_secret_artifacts_feed_mixed_key_validation -q --color=no`
  Result: Ruff clean; focused validator slices `7 passed, 41 deselected`, `1 passed, 48 deselected`, `1 passed, 101 deselected`; adjacent full suites `49 passed`, `48 passed`, `102 passed`; kill-chain fixture assertion passed. The Windows pytest process emitted the same access-violation trace after the kill-chain pass while still exiting `0`; treat as the existing local shutdown issue unless it becomes non-zero or reproduces outside this fixture.
  Cleanup: removed 1 pytest temp `.forge_data/engagements` folder; `remaining_pytest_engagement_dirs=0`. Persistent workspace `.forge_data/engagements` DBs were not deleted because they are not proven test artifacts from this run.
  Notes: Hugging Face, Discord bot, and Telegram bot tokens are now detected by shared and legacy key scanners plus generic secret patterns. Validators use only read-only proof endpoints: Hugging Face `whoami-v2`, Discord current bot user, and Telegram `getMe`. They route through the existing key-validation pacing/backoff wrapper, persist non-secret proof identifiers, and feed validated artifact-discovered keys into deterministic `HIGH` key-exposure findings. No messaging, channel/group enumeration, inference call, proxy/IP rotation, rate-limit bypass, provider-limit bypass, scope relaxation, destructive validation, or persistent engagement DB mutation was added. `git status --short` still fails because this workspace is not a git repository.
  Completed next audit target: safe read-only validators added for Hugging Face, Discord, and Telegram credentials discovered from static artifacts.
  Next audit target: add only similarly safe read-only validators for remaining high-value providers such as Cloudflare, Vercel/Netlify, Sentry, and PostHog where official proof endpoints and mocked fixtures are available; continue artifact/container/OCR coverage and graph fidelity audits.

- [x] AI-provider key validation checkpoint is green:
  `python -m py_compile forge\utils\intel\secret_finder.py forge\phase2\key_scanner.py forge\phase4\cloud_validate.py tests\phase2\test_secret_finder.py tests\phase2\test_key_scanner.py tests\phase4\test_cloud_validate.py tests\phase1\test_engagement_orchestrator.py`
  `python -m ruff check forge\utils\intel\secret_finder.py forge\phase2\key_scanner.py forge\phase4\cloud_validate.py tests\phase2\test_secret_finder.py tests\phase2\test_key_scanner.py tests\phase4\test_cloud_validate.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests/phase2/test_secret_finder.py -k "ai_provider or openai or anthropic" -q --color=no`
  `python -m pytest tests/phase2/test_key_scanner.py -k "ai_provider or openai or anthropic" -q --color=no`
  `$env:FORGE_KEY_VALIDATION_REQUEST_DELAY_SECONDS='0'; python -m pytest tests/phase4/test_cloud_validate.py -k "validatable_openai or validatable_anthropic" -q --color=no`
  `$env:FORGE_KEY_VALIDATION_REQUEST_DELAY_SECONDS='0'; $env:FORGE_KEY_VALIDATION_RATE_LIMIT_BACKOFF_SECONDS='1'; python -m pytest tests/phase2/test_secret_finder.py -q --color=no`
  `$env:FORGE_KEY_VALIDATION_REQUEST_DELAY_SECONDS='0'; $env:FORGE_KEY_VALIDATION_RATE_LIMIT_BACKOFF_SECONDS='1'; python -m pytest tests/phase2/test_key_scanner.py -q --color=no`
  `$env:FORGE_KEY_VALIDATION_REQUEST_DELAY_SECONDS='0'; $env:FORGE_KEY_VALIDATION_RATE_LIMIT_BACKOFF_SECONDS='1'; python -m pytest tests/phase4/test_cloud_validate.py -q --color=no`
  `$env:FORGE_KEY_VALIDATION_REQUEST_DELAY_SECONDS='0'; $env:FORGE_KEY_VALIDATION_RATE_LIMIT_BACKOFF_SECONDS='1'; python -m pytest -p no:rerunfailures tests/phase1/test_engagement_orchestrator.py::test_kill_chain_local_generic_secret_artifacts_feed_mixed_key_validation -q --color=no`
  Result: Ruff clean; focused validator slices `6 passed, 35 deselected`, `1 passed, 47 deselected`, `2 passed, 99 deselected`; adjacent full suites `41 passed`, `48 passed`, `101 passed`; kill-chain fixture assertion passed. The Windows pytest process emitted an access-violation trace after the kill-chain pass while still exiting `0`; treat as a local NetworkX/importlib shutdown issue to investigate only if it becomes non-zero or reproducible outside this fixture.
  Cleanup: removed 2 pytest temp `.forge_data/engagements` folders; `remaining_pytest_engagement_dirs=0`. Persistent workspace `.forge_data/engagements` DBs were not deleted because they are not proven test artifacts from this run.
  Notes: OpenAI and Anthropic keys are now detected by shared and legacy key scanners plus generic secret patterns. Validators use read-only model-list endpoints only, route through the existing key-validation pacing/backoff wrapper, persist non-secret proof identifiers, and feed validated artifact-discovered keys into deterministic `HIGH` key-exposure findings. No inference/completion call, proxy/IP rotation, rate-limit bypass, provider-limit bypass, scope relaxation, destructive validation, or persistent engagement DB mutation was added. `git status --short` still fails because this workspace is not a git repository.
  Completed next audit target: provider-specific proof depth improved for AI-provider credentials found in static artifacts.
  Next audit target: add only similarly safe read-only validators for remaining high-value providers such as Cloudflare, Vercel/Netlify, Sentry, and PostHog where official proof endpoints and mocked fixtures are available; continue artifact/container/OCR coverage and graph fidelity audits.

- [x] Non-200 storage structured-error false-positive checkpoint is green:
  `python -m py_compile forge\phase4\cloud_validate.py tests\phase4\test_cloud_validate.py`
  `python -m ruff check forge\phase4\cloud_validate.py tests\phase4\test_cloud_validate.py`
  `python -m pytest tests/phase4/test_cloud_validate.py -k "non_200_s3_structured_not_found_dead or non_200_gcs_structured_not_found_dead or non_200_azure_structured_not_found_dead or classifies_structured_s3_error_payload or classifies_structured_gcs_error_payload or classifies_structured_azure_error_payload" -q --color=no`
  `python -m pytest tests/phase4/test_cloud_validate.py -k "s3_ or gcs_ or azure_blob" -q --color=no`
  `python -m pytest tests/phase4/test_cloud_validate.py -q --color=no`
  Result: Ruff clean; focused structured-error slice `6 passed, 93 deselected`; adjacent storage subset `42 passed, 57 deselected`; full cloud validation suite `99 passed`.
  Cleanup: no pytest temp `.forge_data/engagements` folders were present; `remaining_pytest_engagement_dirs=0`.
  Notes: S3/DO-style bucket validation, GCS, and Azure Blob now classify explicit structured not-found/error bodies before generic 401/403/409 inaccessible fallbacks. This prevents non-200 bodies such as `NoSuchBucket`, JSON `NOT_FOUND`, and `ContainerNotFound` from being treated as proof that the storage resource exists. Access-denied bodies still downgrade to `ACCESSIBLE_BUT_NO_DATA`; validated findings still require real listing data. No live probing breadth, scope gates, provider caps, pacing/backoff, or persistent engagement DB behavior changed.
  Next audit target: keep tightening provider-specific proof/decoy heuristics and mixed-provider fixtures, with live service validation explicit, scoped, paced, and mocked before real target use.

- [x] Explicit organization public-profile recursion checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py forge\cli.py tests\phase1\test_engagement_orchestrator.py`
  `python -m ruff check forge\engagement_orchestrator.py forge\cli.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_social_profile_url_parser_supports_twitter_intent_links_and_skips_github_reserved_paths -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_kill_chain_html_public_profile_urls_feed_recursive_identity_and_company_fanouts -q --color=no`
  Result: Ruff clean; parser regression `1 passed`; live HTML-recursion regression `1 passed`.
  Cleanup: removed 3 pytest temp `.forge_data/engagements` folders; `remaining_pytest_engagement_dirs=0`. Persistent workspace `.forge_data/engagements` DBs were not deleted because they are not proven test artifacts from this run.
  Notes: explicit org-page URL shapes now promote company pivots without becoming username pivots: GitHub `/orgs/{org}`, GitLab `/groups/{group}`, Hugging Face `/organizations/{org}`, DockerHub/npm/PyPI org pages, and Facebook `/pages/{name}/{id}`. HTML mining also records GitHub `/orgs/{org}` as a GitHub org candidate for the existing keyscan path. Ambiguous `github.com/{name}` / `gitlab.com/{name}` URLs still stay user-handle shaped to avoid false company pivots. No proxy/IP rotation, rate-limit bypass, provider-limit bypass, scope relaxation, destructive validation, or persistent engagement DB mutation was added.
  Next audit target: continue identity/provider normalization with additional explicit public-profile shapes and provider-proof details, preserving ROE/scope gates and paced/backoff behavior.

- [x] Python 3.11 static-check compatibility checkpoint is green:
  `python -m py_compile forge\cli.py tests\phase1\test_engagement_orchestrator.py forge\webui\app.py forge\engagement_orchestrator.py`
  `python -m ruff check forge\cli.py tests\phase1\test_engagement_orchestrator.py forge\webui\app.py forge\engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_kill_chain_dns_cname_persists_subdomain_seed_even_when_host_insert_collides tests/phase1/test_engagement_orchestrator.py::test_kill_chain_parallel_batches_dns_rdap_result_parse -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "parallelizes_nested_zip_mobile_member or parallelizes_nested_tar_mobile_member or nested_mobile_member_result" -q --color=no`
  `python -m pytest tests/integration/test_webui_engagement_api.py::test_engagement_create_and_seed_crud_routes tests/integration/test_webui_engagement_api.py::test_engagement_create_uses_monotonic_sequence_after_deleted_db -q --color=no`
  `python -m pytest tests/phase1/test_cli_parallel_dispatch.py -q --color=no`
  Result: Ruff clean; DNS tests `2 passed`; nested artifact selector `7 passed, 454 deselected`; web auto-increment tests `2 passed, 12 warnings`; dispatch suite `21 passed`.
  Cleanup: removed 2 pytest temp `.forge_data/engagements` folders; `remaining_pytest_engagement_dirs=0`. Persistent workspace `.forge_data/engagements` DBs were not deleted because they pre-existed and are not proven test artifacts from this run.
  Notes: fixed a Python 3.12-only f-string in `ArtifactQueueProcessor._sqlite_identifier()` while preserving SQLite identifier escaping behavior. No scan scope, provider caps, validation gates, or DB persistence behavior changed.

- [x] Bounded DNS host-record enrichment checkpoint is green:
  `python -m py_compile forge\cli.py tests\phase1\test_engagement_orchestrator.py`
  `python -m ruff check forge\cli.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_kill_chain_dns_cname_persists_subdomain_seed_even_when_host_insert_collides -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_kill_chain_parallel_batches_dns_rdap_result_parse -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_engagement_provider_matrix_recursion_preserves_caps_and_exports -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "dns_cname_persists or parallel_batches_dns_rdap_result_parse or provider_matrix_recursion_preserves_caps_and_exports" -q --color=no`
  `python -m pytest tests/phase1/test_cli_parallel_dispatch.py -q --color=no`
  Result: Ruff clean; focused DNS CNAME test `1 passed`; DNS/RDAP parse test `1 passed`; provider-matrix recursion fixture `1 passed`; combined selector `3 passed, 458 deselected`; dispatch suite `21 passed`.
  Notes: root-domain DNS enrichment already batched root domains; the remaining serial MX/TXT/NS/CNAME lookups for each candidate host now run through `_run_callable_batch` with `parallel_fanout` bounds and a `1.G DNS record lookup` label. The test uses temp DB roots and a fake resolver, and proves in-scope known hosts are queried under the bounded worker pool while preserving CNAME seed persistence and SaaS TXT signal extraction. No proxy/IP rotation, rate-limit bypass, provider-limit bypass, scope relaxation, destructive validation, or persistent engagement DB mutation was added.
  Completed next audit target: one remaining safe sequential kill-chain enricher moved under the bounded worker-pool path.
  Next audit target: continue auditing the next safe sequential enrichers in artifact/provider/static-analysis fan-outs, preserving scope gates, provider caps, and paced/backoff behavior.

- [x] Verification-only checkpoint: engagement ID auto-increment and nested artifact worker pools are already covered:
  `python -m pytest tests/integration/test_webui_engagement_api.py::test_engagement_create_and_seed_crud_routes tests/integration/test_webui_engagement_api.py::test_engagement_create_uses_monotonic_sequence_after_deleted_db -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "parallelizes_nested_zip_mobile_member or parallelizes_nested_tar_mobile_member or nested_mobile_member_result" -q --color=no`
  Result: API create/monotonic sequence `2 passed, 12 warnings`; nested mobile artifact worker-pool selector `7 passed, 454 deselected`.
  Notes: no code change needed here. `engagements.id` is `INTEGER PRIMARY KEY AUTOINCREMENT`, and web/CLI create paths use the master monotonic allocator so deleted DB files do not cause ID reuse. Artifact static-analysis paths already parallelize remote downloads, parses, nested mobile extraction, and ordered result merging under bounded workers.

- [x] Provider-matrix dashboard/API/static visibility checkpoint is green:
  `python -m py_compile forge\reporting\dashboard.py tests\integration\test_webui_engagement_api.py tests\reporting\test_dashboard.py`
  `python -m ruff check forge\reporting\dashboard.py tests\integration\test_webui_engagement_api.py tests\reporting\test_dashboard.py`
  `python -m pytest tests/reporting/test_dashboard.py::test_generate_dashboard_surfaces_provider_matrix_artifacts_and_validation_evidence tests/integration/test_webui_engagement_api.py::test_engagement_detail_surfaces_provider_matrix_outputs_for_dashboard_review -q --color=no`
  `python -m pytest tests/reporting/test_dashboard.py -q --color=no`
  `python -m pytest tests/integration/test_webui_engagement_api.py -k "engagement_list_and_detail_routes or provider_matrix_outputs or graph_payload or parses_graphml or parses_mtgx or prefers_snapshot_graph or raw_export_report_family or latest_report_family" -q --color=no`
  `npm run build` from `forge\reporting\webui`
  Result: Ruff clean; focused live/static provider-matrix visibility `2 passed`; static dashboard suite `9 passed`; live API detail slice `8 passed, 17 deselected`; React production build passed.
  Notes: `cloud_validation_results` dashboard rows now include bounded evidence and notes, and both the authenticated engagement API plus generated static dashboard JSON prove provider-matrix graph/report artifacts, seed-run provider loops, and validation proof metadata are analyst-visible. No scope/ROE/provider caps were weakened.
  Completed next audit target: dashboard/API engagement detail routes and static dashboard exports surface provider-matrix graph/report artifacts plus validation metadata.
  Later checkpoint completed: bounded DNS host-record enrichment now covers one remaining safe sequential kill-chain enricher; see current checkpoint above.

- [x] Provider-matrix engagement export fixture checkpoint is green:
  `python -m py_compile tests\phase1\test_engagement_orchestrator.py`
  `python -m ruff check tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py::test_engagement_provider_matrix_recursion_preserves_caps_and_exports -q --color=no`
  `python -m pytest tests/phase1/test_cli_parallel_dispatch.py -q --color=no`
  `python -m pytest tests/phase2/test_passive_host_persistence.py -q --color=no`
  `python -m pytest tests/phase2/test_commoncrawl_lookup.py tests/phase2/test_wayback_lookup.py tests/phase1/test_subdomain_enum.py tests/phase1/test_crawler.py -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "provider_matrix_recursion_preserves_caps_and_exports or fanout_d3_shodan or fanout_d4_urlscan or wayback" -q --color=no`
  Result: Ruff clean; focused fixture `1 passed`; provider dispatch `21 passed`; passive provider persistence `4 passed`; archive/crawler suite `10 passed`; orchestrator selector `2 passed, 459 deselected`.
  Notes: added a fast DB-backed provider-matrix fixture that exercises real provider-aware `_run_module_batch` caps for Shodan/URLScan specs, real passive archive worker caps for Wayback/Common Crawl, synthesis, graph JSON/GraphML/MTGX export, and deterministic report artifacts. This is test coverage only; no production kill-chain behavior, proxy/IP rotation, rate-limit bypass, provider-limit bypass, destructive validation, or persistent engagement DB mutation was added.
  Completed next audit target: engagement-backed mixed-recursion coverage now includes a larger passive provider matrix plus export assertions under the current provider caps.
  Later checkpoint completed: dashboard/API engagement detail routes and static dashboard exports now surface these provider-matrix graph/report artifacts and validation metadata; see current checkpoint above.

- [x] Provider-bounded recursive fan-out checkpoint is green:
  `python -m py_compile forge\cli.py tests\phase1\test_cli_parallel_dispatch.py`
  `python -m ruff check forge\cli.py tests\phase1\test_cli_parallel_dispatch.py`
  `python -m pytest tests/phase1/test_cli_parallel_dispatch.py -q --color=no`
  `python -m pytest tests/phase2/test_passive_host_persistence.py -q --color=no`
  `python -m pytest tests/phase2/test_commoncrawl_lookup.py tests/phase2/test_wayback_lookup.py tests/phase1/test_subdomain_enum.py tests/phase1/test_crawler.py -q --color=no`
  `python -m pytest tests/cli/test_direct_live_scope.py -q --color=no`
  `python -m pytest tests/distributed/test_runnable_scope.py -q --color=no`
  `python -m pytest tests/phase1/test_port_scanner.py -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "scope_manifest or live_sensitive_modes_require_roe or fanout_d3_shodan or fanout_d4_urlscan or wayback" -q --color=no`
  `python -m pytest tests/integration/test_webui_engagement_api.py -k "scope_manifest or launch_engagement_kill_chain_route" -q --color=no`
  Result: Ruff clean; `21 passed`; `4 passed`; `10 passed`; `28 passed`; `6 passed`; `5 passed`; `10 passed, 450 deselected`; `6 passed, 18 deselected, 6 warnings`
  Notes: recursive module dispatch now applies provider-aware worker caps before launching external OSINT providers. Shodan, URLScan, crt.sh, web-fetch, and identity provider modules default to one worker, with explicit bounded env overrides such as `FORGE_SHODAN_MAX_WORKERS=2`. The D3/D4 passive-enricher and IP Shodan fan-outs now report provider-bounded workers, and Wayback/Common Crawl domain batches use the strictest provider cap. No proxy/IP rotation, rate-limit bypass, provider-limit bypass, or scope relaxation was added.
  Completed next audit target: outbound discovery/provider scheduling is bounded at the orchestration layer in addition to existing per-request pacing/backoff.
  Later checkpoint completed: engagement-backed mixed-recursion coverage now includes the provider-matrix export fixture above.

- [x] Local collector ROE gate checkpoint is green:
  `python -m py_compile forge\utils\post\collectors\filesystem.py forge\utils\post\collectors\ssh_aws_keys.py forge\utils\post\collectors\kubernetes_collector.py forge\utils\post\transfer_util.py tests\phase5\test_exfiltration.py tests\phase5\test_collectors_new_families.py tests\phase5\test_kubernetes_collector.py`
  `python -m ruff check forge\utils\post\collectors\filesystem.py forge\utils\post\collectors\ssh_aws_keys.py forge\utils\post\collectors\kubernetes_collector.py forge\utils\post\transfer_util.py tests\phase5\test_exfiltration.py tests\phase5\test_collectors_new_families.py tests\phase5\test_kubernetes_collector.py`
  `python -m pytest tests/phase5/test_exfiltration.py -q --color=no`
  `python -m pytest tests/phase5/test_collectors_new_families.py -q --color=no`
  `python -m pytest tests/phase5/test_kubernetes_collector.py -q --color=no`
  `python -m pytest tests/phase5/test_lateral_movement.py -q --color=no`
  `python -m pytest tests/integration/test_exfiltration.py -q --color=no`
  `python -m pytest tests/integration/test_playbooks.py -q --color=no`
  `python -m pytest tests/cli/test_direct_live_scope.py -q --color=no`
  `python -m pytest tests/distributed/test_runnable_scope.py -q --color=no`
  `python -m pytest tests/phase1/test_port_scanner.py -q --color=no`
  `python -m pytest tests/phase4/test_cloud_validate.py -k "scope_checker_skips_denied_key_row or scheduled_validate_task_scope_manifest_denies_out_of_scope_key_row or scope_checker_skips_denied_assets" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "scope_manifest or live_sensitive_modes_require_roe" -q --color=no`
  `python -m pytest tests/integration/test_webui_engagement_api.py -k "scope_manifest or launch_engagement_kill_chain_route" -q --color=no`
  Result: Ruff clean; `26 passed`; `9 passed`; `8 passed`; `39 passed`; `10 passed`; `7 passed`; `28 passed`; `6 passed`; `5 passed`; `5 passed, 91 deselected`; `9 passed, 451 deselected`; `6 passed, 18 deselected, 6 warnings`
  Notes: every `BaseCollector` subclass now requires `roe_id` / `FORGE_ROE_ID` before `discover()` or `collect()` by default, closing direct collector bypasses. `Exfiltrator` passes its validated ROE into collectors for authorized live runs and still disables collector ROE only for the existing dry-run path. `SshAwsKeyCollector` propagates ROE to its child collectors. Kubernetes tests now redirect service-account discovery to a temp path instead of touching the real `/var/run/...` path.
  Completed next audit target: independent local credential/artifact collectors are gated at the base class.
  Later checkpoint completed: outbound discovery/provider scheduling is now bounded at the orchestration layer; see the current provider-bounded recursive fan-out checkpoint above.

- [x] Module-level Phase 5 ROE/scope checkpoint is green:
  `python -m py_compile forge\phase5\__init__.py forge\phase5\lateral_movement.py forge\utils\post\transfer_util.py forge\utils\playbooks\zero_to_da.py tests\phase5\test_lateral_movement.py tests\phase5\test_exfiltration.py tests\integration\test_exfiltration.py`
  `python -m ruff check forge\phase5\__init__.py forge\phase5\lateral_movement.py forge\utils\post\transfer_util.py forge\utils\playbooks\zero_to_da.py tests\phase5\test_lateral_movement.py tests\phase5\test_exfiltration.py tests\integration\test_exfiltration.py`
  `python -m pytest tests/phase5/test_lateral_movement.py -q --color=no`
  `python -m pytest tests/phase5/test_exfiltration.py -q --color=no`
  `python -m pytest tests/integration/test_exfiltration.py -q --color=no`
  `python -m pytest tests/integration/test_playbooks.py -q --color=no`
  `python -m pytest tests/cli/test_direct_live_scope.py -q --color=no`
  `python -m pytest tests/phase1/test_port_scanner.py -q --color=no`
  `python -m pytest tests/distributed/test_runnable_scope.py -q --color=no`
  `python -m pytest tests/phase4/test_cloud_validate.py -k "scope_checker_skips_denied_key_row or scheduled_validate_task_scope_manifest_denies_out_of_scope_key_row or scope_checker_skips_denied_assets" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "scope_manifest or live_sensitive_modes_require_roe" -q --color=no`
  `python -m pytest tests/integration/test_webui_engagement_api.py -k "scope_manifest or launch_engagement_kill_chain_route" -q --color=no`
  Result: Ruff clean; `39 passed`; `25 passed`; `10 passed`; `7 passed`; `28 passed`; `5 passed`; `6 passed`; `5 passed, 91 deselected`; `9 passed, 451 deselected`; `6 passed, 18 deselected, 6 warnings`
  Notes: module-level `phase5.lateral_movement.spray_credentials()` now requires `roe_id` / `FORGE_ROE_ID` before live spraying, checks target hosts against engagement scope before approval/login attempts, and classifies non-dry-run approval as destructive. `utils.post.transfer_util.Exfiltrator.run()` now requires ROE before non-dry-run collection/upload. `zero_to_da` passes ROE through to spraying. `forge.phase5` import is resilient when optional post channels fail to import on this Windows/impacket path.
  Completed next audit target slice: `spray_credentials` and `Exfiltrator` are gated/fixed without disabling authorized live execution.
  Superseded by current checkpoint above: independent local collectors are now gated at `BaseCollector`.

- [x] Residual post/Phase 5 direct CLI scope/ROE checkpoint is green:
  `python -m py_compile forge\cli.py forge\phase4\param_probe.py forge\phase4\api_policy_check.py forge\phase4\cloud_audit.py forge\utils\post\boundary_check.py tests\cli\test_direct_live_scope.py`
  `python -m ruff check forge\cli.py forge\phase4\param_probe.py forge\phase4\api_policy_check.py forge\phase4\cloud_audit.py forge\utils\post\boundary_check.py tests\cli\test_direct_live_scope.py`
  `python -m pytest tests/cli/test_direct_live_scope.py -q --color=no`
  `python -m pytest tests/phase4/test_idor_scanner.py -q --color=no`
  `python -m pytest tests/phase2/test_xray_runner.py -q --color=no`
  `python -m pytest tests/phase4/test_supabase_scanner.py -q --color=no`
  `python -m pytest tests/phase4/test_firebase_agneyastra.py -q --color=no`
  `python -m pytest tests/integration/test_playbooks.py -q --color=no`
  `python -m pytest tests/phase1/test_port_scanner.py -q --color=no`
  `python -m pytest tests/distributed/test_runnable_scope.py -q --color=no`
  `python -m pytest tests/phase4/test_cloud_validate.py -k "scope_checker_skips_denied_key_row or scheduled_validate_task_scope_manifest_denies_out_of_scope_key_row or scope_checker_skips_denied_assets" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "scope_manifest or live_sensitive_modes_require_roe" -q --color=no`
  `python -m pytest tests/integration/test_webui_engagement_api.py -k "scope_manifest or launch_engagement_kill_chain_route" -q --color=no`
  Result: Ruff clean; `28 passed`; `25 passed`; `7 passed`; `38 passed`; `24 passed`; `7 passed`; `5 passed`; `6 passed`; `5 passed, 91 deselected`; `9 passed, 451 deselected`; `6 passed, 18 deselected, 6 warnings`
  Notes: direct `post shell` and `post beacon` now require `--roe-id` / `FORGE_ROE_ID` before payload generation. Direct `post lateral` now requires ROE and validates target scope before operator prompt and `run_lateral()`. Phase 5 boundary checks now read the current `engagements.scope_json` schema as well as older scope columns. No proxy/IP rotation, rate-limit bypass, provider-limit bypass, destructive validation, new post-exploitation execution behavior, or persistent engagement DB mutation was added.
  Completed next audit target: direct post CLI surfaces and Phase 5 boundary-check schema drift are gated/fixed.
  Superseded by current checkpoint above: module-level `spray_credentials` and `Exfiltrator` gates are complete, and local collectors are now gated at `BaseCollector`.

- [x] Lower-level vuln and Phase 4 module scope checkpoint is green:
  `python -m py_compile forge\cli.py forge\phase4\param_probe.py forge\phase4\api_policy_check.py forge\phase4\cloud_audit.py tests\cli\test_direct_live_scope.py`
  `python -m ruff check forge\cli.py forge\phase4\param_probe.py forge\phase4\api_policy_check.py forge\phase4\cloud_audit.py tests\cli\test_direct_live_scope.py`
  `python -m pytest tests/cli/test_direct_live_scope.py -q --color=no`
  `python -m pytest tests/phase4/test_idor_scanner.py -q --color=no`
  `python -m pytest tests/phase2/test_xray_runner.py -q --color=no`
  `python -m pytest tests/phase4/test_supabase_scanner.py -q --color=no`
  `python -m pytest tests/phase4/test_firebase_agneyastra.py -q --color=no`
  `python -m pytest tests/phase1/test_port_scanner.py -q --color=no`
  `python -m pytest tests/distributed/test_runnable_scope.py -q --color=no`
  `python -m pytest tests/integration/test_playbooks.py -q --color=no`
  `python -m pytest tests/phase4/test_cloud_validate.py -k "scope_checker_skips_denied_key_row or scheduled_validate_task_scope_manifest_denies_out_of_scope_key_row or scope_checker_skips_denied_assets" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "scope_manifest or live_sensitive_modes_require_roe" -q --color=no`
  `python -m pytest tests/integration/test_webui_engagement_api.py -k "scope_manifest or launch_engagement_kill_chain_route" -q --color=no`
  Result: Ruff clean; `24 passed`; `25 passed`; `7 passed`; `38 passed`; `24 passed`; `5 passed`; `6 passed`; `7 passed`; `5 passed, 91 deselected`; `9 passed, 451 deselected`; `6 passed, 18 deselected, 6 warnings`
  Notes: direct `vuln idor` now validates scope and requires `--roe-id` / `FORGE_ROE_ID` before live probes; `vuln passive --target` validates scope before HTTP collection. `IDORScanner`, `SupabaseScanner`, and `FirebaseAuditor` now enforce DB/manifest-backed scope at module level when scope exists or `require_scope=True`, while preserving existing no-op compatibility for offline/unit fixtures. CLI cloud Firebase/Supabase passes the validated scope through to the module for defense-in-depth. No proxy/IP rotation, rate-limit bypass, destructive validation, new exploit/post-exploitation behavior, or persistent engagement DB mutation was added.
  Completed next audit target: lower-level module/direct command bypasses for `vuln idor`, `vuln passive`, `SupabaseScanner`, and `FirebaseAuditor` now have scope/ROE gates where live outbound work can occur.
  Completed next audit target: direct post CLI surfaces and Phase 5 boundary-check schema drift are gated/fixed; continue with module-level Phase 5 callable APIs.

- [x] Standalone provider/subdomain direct-entrypoint scope/ROE checkpoint is green:
  `python -m py_compile forge\cli.py tests\cli\test_direct_live_scope.py`
  `python -m ruff check forge\cli.py tests\cli\test_direct_live_scope.py`
  `python -m pytest tests/cli/test_direct_live_scope.py -q --color=no`
  `python -m pytest tests/phase1/test_port_scanner.py -q --color=no`
  `python -m pytest tests/distributed/test_runnable_scope.py -q --color=no`
  `python -m pytest tests/integration/test_playbooks.py -q --color=no`
  `python -m pytest tests/phase4/test_cloud_validate.py -k "scope_checker_skips_denied_key_row or scheduled_validate_task_scope_manifest_denies_out_of_scope_key_row or scope_checker_skips_denied_assets" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "scope_manifest or live_sensitive_modes_require_roe" -q --color=no`
  `python -m pytest tests/integration/test_webui_engagement_api.py -k "scope_manifest or launch_engagement_kill_chain_route" -q --color=no`
  Result: Ruff clean; `18 passed`; `5 passed`; `6 passed`; `7 passed`; `5 passed, 91 deselected`; `9 passed, 451 deselected`; `6 passed, 18 deselected, 6 warnings`
  Notes: direct `recon subdomains`, `osint urlscan`, `osint shodan`, `auth brute`, `cloud firebase`, `cloud aws`, `cloud azure`, `cloud firebase-extract --target-url`, and `cloud supabase` now gate live-capable direct execution. Domain/provider lookups validate engagement or manifest scope before provider calls. Direct auth brute and live cloud audits require `--roe-id` / `FORGE_ROE_ID`; target-addressed Firebase/Supabase paths also validate scope. Dry-run/offline paths remain usable. Tests used temp pytest DB roots only; no persistent engagement DB mutation was intended. No proxy/IP rotation, rate-limit bypass, provider-limit bypass, destructive validation, password attack automation beyond existing gated code, or post-exploitation behavior was added.
  Completed next audit target: remaining direct provider/subdomain/cloud/auth CLI paths from the prior checkpoint now have scope/ROE gates where direct outbound work can occur.
  Completed next audit target: lower-level `vuln idor`, `vuln passive`, `SupabaseScanner`, and `FirebaseAuditor` paths now have scope/ROE gates where live outbound work can occur.

- [x] Direct CLI live-entrypoint scope/ROE checkpoint is green:
  `python -m ruff check forge\cli.py forge\phase1\crawler.py forge\phase4\auth_bypass.py tests\cli\test_direct_live_scope.py`
  `python -m py_compile forge\cli.py forge\phase1\crawler.py forge\phase4\auth_bypass.py tests\cli\test_direct_live_scope.py`
  `python -m pytest tests/cli/test_direct_live_scope.py -q --color=no`
  `python -m pytest tests/phase1/test_port_scanner.py -q --color=no`
  `python -m pytest tests/distributed/test_runnable_scope.py -q --color=no`
  `python -m pytest tests/integration/test_playbooks.py -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "scope_manifest or live_sensitive_modes_require_roe" -q --color=no`
  Result: `8 passed`; `5 passed`; `6 passed`; `7 passed`; `9 passed, 451 deselected`
  Notes: direct `recon crawl`, `recon ports`, and `auth bypass` now enforce engagement scope before direct live work. `auth bypass` also requires `--roe-id` / `FORGE_ROE_ID`. DB-backed scope now validates the initial direct target, URL entries in `scope_json` are treated as URL prefixes plus host authorization, crawlers filter out-of-prefix discovered links before fetch, and port scans receive `scope_override` for per-host rechecks. Tests used temp pytest roots only; persistent `.forge_data/engagements/*.db` timestamps were unchanged. No proxy/IP rotation, rate-limit bypass, provider-limit bypass, destructive validation, password attack automation, or post-exploitation behavior was added.
  Completed next audit target: direct CLI/module live entrypoints for `recon crawl`, `recon ports`, and `auth bypass` now have equivalent scope/ROE gates outside both `kill_chain()` and the distributed scheduler.
  Completed next audit target: remaining standalone provider/subdomain/cloud/auth direct CLI paths now have scope/ROE gates where direct outbound work can occur.

- [x] Scheduled live-task scope/ROE checkpoint is green:
  `python -m py_compile forge\distributed\runnable.py forge\phase1\port_scanner.py tests\distributed\test_runnable_scope.py`
  `python -m pytest tests/distributed/test_runnable_scope.py -q --color=no`
  `python -m pytest tests/phase1/test_port_scanner.py -q --color=no`
  `python -m pytest tests/integration/test_playbooks.py -q --color=no`
  `python -m pytest tests/phase4/test_cloud_validate.py -k "scheduled_validate_task_scope_manifest_denies_out_of_scope_key_row or scope_checker_skips_denied_key_row or scope_checker_skips_denied_assets" -q --color=no`
  `python -m pytest tests/integration/test_webui_engagement_api.py -q --color=no`
  `python -m pytest tests/phase4/test_cloud_validate.py -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "scope_manifest or live_sensitive_modes_require_roe" -q --color=no`
  Result: `6 passed`; `5 passed`; `7 passed`; `5 passed, 91 deselected`; `24 passed, 48 warnings`; `96 passed`; `9 passed, 451 deselected`
  Notes: `run_scheduled_task()` now centrally gates scheduled outbound task types before live work. Targeted scheduled tasks (`crawl`, `crawl_stealth`, `searxng_passive`, `passive`, `safe_check`, `weaponize`, `auth-bypass`) must be authorized by a supplied scope manifest or non-empty engagement `scope_json`; `FORGE_REQUIRE_SCOPE_MANIFEST=1` still forces a manifest. Sensitive scheduled tasks (`auth-bypass`, `safe_check`, `weaponize`, `spray`) require a `roe_id`. Scheduled `ports` requires declared network scope and passes it to `scan_engagement_enhanced()`, which now re-checks each host row through `scope_override` before probing. All tests are mocked/local; no proxy/IP rotation, provider-limit bypass, destructive validation, post-exploitation implementation, or persistent engagement DB mutation was added.
  Completed next audit target: direct CLI/module live entrypoints for `recon crawl`, `recon ports`, and `auth bypass` now have equivalent scope/ROE gates without breaking documented dry-run/offline workflows.

- [x] Direct/manual cloud validation scope checkpoint is green:
  `python -m py_compile forge\phase4\cloud_validate.py forge\distributed\runnable.py tests\phase4\test_cloud_validate.py`
  `python -m pytest tests/phase4/test_cloud_validate.py -k "scope_checker_skips_denied_key_row or scheduled_validate_task_scope_manifest_denies_out_of_scope_key_row or scope_checker_skips_denied_assets" -q --color=no`
  `python -m pytest tests/phase4/test_cloud_validate.py -k "run_cloud_validate or run_cloud_asset_validate_batch or sweep_pending_cloud_validations or sweep_pending_cloud_asset_validations" -q --color=no`
  `python -m pytest tests/phase4/test_cloud_validate.py -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "scope_manifest or live_sensitive_modes_require_roe" -q --color=no`
  `python -m pytest tests/integration/test_webui_engagement_api.py -k "scope_manifest or launch_engagement_kill_chain_route" -q --color=no`
  `python -m pytest tests/integration/test_playbooks.py -q --color=no`
  Result: `5 passed, 91 deselected`; `30 passed, 66 deselected`; `96 passed`; `9 passed, 451 deselected`; `6 passed, 18 deselected, 6 warnings`; `7 passed`
  Notes: `run_cloud_validate()`, `run_cloud_asset_validate()`, and `run_cloud_asset_validate_batch()` now accept optional scope callbacks, and direct denied rows/assets persist deterministic `UNVERIFIED` / `scope_manifest` validation records without provider calls. `forge.distributed.runnable` scheduled `validate` tasks now honor `scope_manifest` / `scope_manifest_json` / `scope_manifest_payload`, optional `roe_id` match checks, and `require_scope_manifest`. Default behavior without a manifest/callback remains unchanged. All tests are mocked/local; no proxy/IP rotation, provider-limit bypass, destructive validation, post-exploitation behavior, or persistent engagement DB mutation was added.
  Completed next audit target: scheduled non-validation live task types now enforce scope/ROE before live work.

- [x] Key-backed provider validation source-scope checkpoint is green:
  `python -m py_compile forge\cli.py forge\phase4\cloud_validate.py tests\phase1\test_engagement_orchestrator.py tests\phase4\test_cloud_validate.py`
  `python -m pytest tests/phase4/test_cloud_validate.py -k "scope_checker_skips_denied_key_rows" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "scope_manifest_denies_out_of_scope_key_validation_source" -q --color=no`
  `python -m pytest tests/phase4/test_cloud_validate.py -k "sweep_pending_cloud_validations" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "scope_manifest_denies_out_of_scope_recursive_url_without_fetch or scope_manifest_denies_out_of_scope_remote_artifact_download or scope_manifest_denies_out_of_scope_cloud_validation_pivot or scope_manifest_denies_out_of_scope_key_validation_source" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "parallel_batches_cloud or drains_multiple_pending_cloud_validation_batches or mixed_cloud_validation_gates_decoys_from_report" -q --color=no`
  `python -m pytest tests/phase4/test_cloud_validate.py -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "scope_manifest or live_sensitive_modes_require_roe" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "framework_manifest_artifact_recurses_into_second_iteration_chunk or discovered_url_seeds_reenter_same_iteration_surface_mining" -q --color=no`
  `python -m pytest tests/integration/test_webui_engagement_api.py -k "scope_manifest or launch_engagement_kill_chain_route" -q --color=no`
  Result: `1 passed, 92 deselected`; `1 passed, 459 deselected`; `19 passed, 74 deselected`; `4 passed, 456 deselected`; `4 passed, 456 deselected`; `93 passed`; `9 passed, 451 deselected`; `2 passed, 458 deselected` in `0:06:29`; `6 passed, 18 deselected, 6 warnings`
  Notes: pending key-backed provider validation now accepts optional source-scope callbacks, and `kill_chain()` supplies a scope-manifest policy. In manifest-backed live runs, keys are validated only when their evidence source URL/domain is in scope, or when they came from an operator-local artifact source. Denied key rows are marked `UNCONFIRMED` with `validation_detail=UNVERIFIED:scope_manifest:...`, get a `cloud_validation_results` row with `validation_method=scope_manifest`, emit `key_validation_scope_denied`, and are not passed to provider validators. Runs without a scope manifest keep existing behavior. All tests are mocked/local; no proxy/IP rotation, provider-limit bypass, destructive validation, or persistent engagement DB mutation was added.
  Completed next audit target: direct/manual cloud key and asset validation entrypoints now support equivalent scope callbacks, and scheduled `validate` tasks can enforce a scope manifest before provider validation.

- [x] Recursive cloud-validation scope-manifest pivot gate checkpoint is green:
  `python -m py_compile forge\cli.py forge\phase4\cloud_validate.py tests\phase1\test_engagement_orchestrator.py tests\phase4\test_cloud_validate.py`
  `python -m pytest tests/phase4/test_cloud_validate.py -k "scope_checker_skips_denied_assets" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "scope_manifest_denies_out_of_scope_cloud_validation_pivot" -q --color=no`
  `python -m pytest tests/phase4/test_cloud_validate.py -k "sweep_pending_cloud_asset_validations" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "scope_manifest_denies_out_of_scope_recursive_url_without_fetch or scope_manifest_denies_out_of_scope_remote_artifact_download or scope_manifest_denies_out_of_scope_cloud_validation_pivot" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "scope_manifest or live_sensitive_modes_require_roe" -q --color=no`
  `python -m pytest tests/phase4/test_cloud_validate.py -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "framework_manifest_artifact_recurses_into_second_iteration_chunk or discovered_url_seeds_reenter_same_iteration_surface_mining" -q --color=no`
  `python -m pytest tests/integration/test_webui_engagement_api.py -k "scope_manifest or launch_engagement_kill_chain_route" -q --color=no`
  Result: `1 passed, 91 deselected`; `1 passed, 458 deselected`; `3 passed, 89 deselected`; `3 passed, 456 deselected`; `8 passed, 451 deselected`; `92 passed`; `2 passed, 457 deselected` in `0:06:29`; `6 passed, 18 deselected, 6 warnings`
  Notes: immediate Fan-out J and pending `cloud_assets` sweeps now enforce the active scope manifest before live cloud asset validation. Denied managed-resource refs are recorded as `UNVERIFIED` with `validation_method=scope_manifest`, audit action `cloud_validation_scope_denied`, and are not passed to provider validators. Runs without a manifest keep existing behavior. ScopeGate semantics remain strict: managed cloud URLs must satisfy both host/domain scope and URL-prefix scope when URL prefixes are present. All tests are mocked/local; no proxy/IP rotation, provider-limit bypass, destructive validation, or persistent engagement DB mutation was added.
  Completed next audit target: key-backed provider validation rows now use source-scope gating in `kill_chain()` before provider validators are called.

- [x] Recursive remote-artifact scope-manifest download gate checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py forge\cli.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "scope_manifest_denies_out_of_scope_remote_artifact_download" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "dry_run_queues_seed_artifact_urls_and_processes_remote_apk" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "scope_manifest_denies_out_of_scope_recursive_url_without_fetch or scope_manifest_denies_out_of_scope_remote_artifact_download" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "rate_limited_remote_artifact or artifact_queue_processor_parallelizes_remote_acquisition_stage_while_preserving_processing or dry_run_queues_seed_artifact_urls_and_processes_remote_apk" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "scope_manifest or live_sensitive_modes_require_roe" -q --color=no`
  Result: `1 passed, 457 deselected`; `1 passed, 457 deselected`; `2 passed, 456 deselected`; `3 passed, 455 deselected`; `7 passed, 451 deselected`
  Notes: `ArtifactQueueProcessor` now supports an optional remote URL scope gate, and `kill_chain()` wires it to the active scope manifest before remote artifact acquisition. In a scoped non-dry-run fixture, `https://acme.example/app/config.json` is downloaded and parsed, while same-host out-of-prefix `https://acme.example/admin/secrets.json` is marked `skipped`, records `skip_reason=scope_manifest_denied_remote_artifact`, writes `remote_artifact_scope_denied` audit evidence, and is never passed to the downloader. Runs without a scope manifest keep existing remote artifact behavior, preserving the localhost dry-run APK recursion fixture. All tests are mocked/local; no live probing, proxy/IP rotation, provider-limit bypass, artifact execution, or persistent engagement DB mutation was added.
  Completed next audit target: immediate Fan-out J and pending `cloud_assets` cloud-validation pivots now use the active scope manifest gate before provider validation.

- [x] Recursive live-mode scope-manifest URL-prefix gate checkpoint is green:
  `python -m py_compile forge\cli.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "scope_manifest_denies_out_of_scope_recursive_url_without_fetch or scope_manifest_authorizes_network_and_exact_initial_seeds or scope_manifest_rejects_unlisted_initial_seed" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "scope_manifest or live_sensitive_modes_require_roe" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "discovered_url_seeds_reenter_same_iteration_surface_mining or framework_manifest_artifact_recurses_into_second_iteration_chunk" -q --color=no`
  `python -m pytest tests/integration/test_webui_engagement_api.py -k "scope_manifest or launch_engagement_kill_chain_route" -q --color=no`
  Result: `3 passed, 454 deselected`; `6 passed, 451 deselected`; `2 passed, 455 deselected` in `0:06:29`; `6 passed, 18 deselected, 6 warnings`
  Notes: recursive D5 URL scheduling now enforces scope-manifest URL prefixes when a manifest declares `urls`/`url_prefixes`. A same-host URL such as `https://acme.example/admin` is denied when only `https://acme.example/app/` is authorized, is not fetched, gets no `fanout_d5_url_seed_html` seed-run row, and writes a `recursive_seed_scope_denied` audit row with the manifest source. Initial seed validation uses the same tightened URL-prefix semantics. All tests are mocked/local; no live probing, proxy/IP rotation, or provider-limit bypass was added.

- [x] Multi-provider second-order artifact-derived cloud validation/report-gating checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py forge\cli.py forge\phase4\cloud_validate.py forge\deterministic_findings.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "framework_manifest_artifact_recurses_into_second_iteration_chunk" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "source_map_artifacts or spa_manifest_relative_routes or framework_route_manifest_declarations" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "framework_manifest_artifact_recurses_into_second_iteration_chunk or discovered_url_seeds_reenter_same_iteration_surface_mining" -q --color=no`
  `python -m pytest tests/phase4/test_cloud_validate.py -q --color=no`
  Result: `1 passed, 455 deselected` in `0:01:16`; `3 passed, 453 deselected`; `2 passed, 454 deselected` in `0:06:29`; `91 passed`
  Notes: the two-iteration framework-manifest fixture now keeps cloud validation enabled and mocks second-order artifact-derived Firebase, Supabase, and S3 probes. It proves validated Firebase/Supabase/S3 resources become deterministic findings and template-report content, while `ACCESSIBLE_BUT_NO_DATA`, `HONEYPOT_SUSPECTED`, and `DEAD` S3 resources remain graph/audit-visible but excluded from findings/reports. All network, artifact downloads, and validation probes are mocked; no live probing behavior, proxy/IP rotation, provider-limit bypass, or production code path changed in this checkpoint.

- [x] Two-iteration artifact recursion graph/report checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "framework_manifest_artifact_recurses_into_second_iteration_chunk" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "source_map_artifacts or spa_manifest_relative_routes or framework_route_manifest_declarations" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "framework_manifest_artifact_recurses_into_second_iteration_chunk or discovered_url_seeds_reenter_same_iteration_surface_mining" -q --color=no`
  Result: `1 passed, 455 deselected` in `0:01:12`; `3 passed, 453 deselected`; `2 passed, 454 deselected` in `0:06:26`
  Notes: the two-iteration framework-manifest fixture now invokes real graph/report generation from the fake subprocess. It proves second-order artifact-derived email/API/cloud nodes appear in JSON GraphML, native MTGX graph/manifest, and deterministic template report output. All network and artifact downloads are mocked; no live probing behavior changed.

- [x] Two-iteration framework-manifest artifact recursion checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "framework_manifest_artifact_recurses_into_second_iteration_chunk" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "framework_manifest_artifact_recurses_into_second_iteration_chunk or discovered_url_seeds_reenter_same_iteration_surface_mining" -q --color=no`
  Result: `1 passed, 455 deselected` in `0:01:12`; `2 passed, 454 deselected` in `0:06:25`
  Notes: a local two-iteration kill-chain fixture now proves recursive deepening beyond seed persistence: iteration 1 scrapes a JS manifest artifact, artifact parsing extracts a static chunk URL, iteration 2 queues/parses that chunk, and the second-order chunk produces email, API URL, and Firebase cloud seeds. Network calls are fully mocked; this remains passive, scoped artifact parsing plus existing loop automation.

- [x] Passive framework route-manifest declaration extraction checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "spa_manifest_relative_routes or framework_route_manifest_declarations" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "source_map_artifacts or spa_manifest_relative_routes or framework_route_manifest_declarations" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "discovered_url_seeds_reenter_same_iteration_surface_mining" -q --color=no`
  Result: `2 passed, 453 deselected`; `3 passed, 452 deselected`; `1 passed, 454 deselected` in `0:05:19`
  Notes: artifact text discovery now parses route object keys, route declaration fields (`id`, `page`, `path`, `pathname`, `route`, `source`), and route-list fields (`sortedPages`, `routeNames`, `routes`) in framework manifests. This captures custom Next/Nuxt/SvelteKit/React-Router style routes such as `/clients/:clientId` without broadening generic arbitrary-string scraping. Rootless `_nuxt/` and `_app/` assets are normalized from the site root. No live probing behavior, proxy/IP rotation, or rate-limit bypass changed.

- [x] Passive SPA manifest/source-map route extraction checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "spa_manifest_relative_routes or discovered_url_seeds_reenter_same_iteration_surface_mining" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "source_map_artifacts or spa_manifest_relative_routes" -q --color=no`
  Result: `2 passed, 452 deselected` in `0:05:23`; `2 passed, 452 deselected`
  Notes: downloaded remote artifact payloads are now rebased to their original artifact `source_url` for generic text discovery, so conservative relative route strings in Next/Vite/SPA manifests, chunk-loader tables, and `sourceMappingURL=` comments resolve into HTTP(S) URL seeds. The parser accepts route/static prefixes and known web artifact suffixes, skips source internals such as `/src/` and `/node_modules/`, and does not fetch by itself. The D-to-D5 kill-chain regression fakes a scraped JS artifact and proves the generated manifest/source-map routes become next-iteration URL seeds. No live probing behavior, proxy/IP rotation, or rate-limit bypass changed; tests used temp data dirs only.

- [x] Passive inline-JS URL extraction checkpoint is green:
  `python -m py_compile forge\cli.py tests\phase1\test_cli_parallel_dispatch.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_cli_parallel_dispatch.py -k "extract_html_surface_urls" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "discovered_url_seeds_reenter_same_iteration_surface_mining" -q --color=no`
  `python -m pytest tests/phase1/test_cli_parallel_dispatch.py -k "html_fetch or extract_html_surface_urls" -q --color=no`
  Result: `1 passed, 16 deselected`; `1 passed, 452 deselected` in `0:05:23`; `4 passed, 13 deselected`
  Notes: passive HTML mining now extracts conservative JavaScript URL-bearing calls/constructors (`fetch`, dynamic `import`, `importScripts`, `sendBeacon`, `Worker`, `SharedWorker`, `EventSource`, `WebSocket`, and axios/http/client-style method calls). The D-to-D5 fixture proves JS-discovered route URLs persist into crawl results, and file-like JS bundle/worker URLs enter the artifact/static-analysis queue. `data:`, `javascript:`, `mailto:`, and `tel:` values remain filtered. No live probing behavior, proxy/IP rotation, or rate-limit bypass changed; tests used temp data dirs only.

- [x] Passive object/form/meta-refresh/CSS-import extraction checkpoint is green:
  `python -m py_compile forge\cli.py tests\phase1\test_cli_parallel_dispatch.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_cli_parallel_dispatch.py -k "extract_html_surface_urls" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "discovered_url_seeds_reenter_same_iteration_surface_mining" -q --color=no`
  `python -m pytest tests/phase1/test_cli_parallel_dispatch.py -k "html_fetch or extract_html_surface_urls" -q --color=no`
  Result: `1 passed, 16 deselected`; `1 passed, 452 deselected`; `4 passed, 13 deselected`
  Notes: passive HTML mining now extracts object/embed-style `data=`, `formaction`, selected lazy-load `data-*` URL attributes, meta-refresh `content="...url=..."`, and CSS `@import` references. Existing scheme filters still drop `data:`, `javascript:`, `mailto:`, and `tel:` values. The D-to-D5 fixture proves these URLs persist into crawl results, page-like URLs continue through URL-surface recursion, and file-like URLs enter the artifact/static-analysis queue. No live probing behavior changed.

- [x] Passive HTML static/page URL extraction checkpoint is green:
  `python -m py_compile forge\cli.py tests\phase1\test_cli_parallel_dispatch.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_cli_parallel_dispatch.py -k "extract_html_surface_urls" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "discovered_url_seeds_reenter_same_iteration_surface_mining" -q --color=no`
  `python -m pytest tests/phase1/test_cli_parallel_dispatch.py -k "html_fetch or extract_html_surface_urls" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "passive_text_mining_promotes_robots_and_sitemap_urls_without_live_network" -q --color=no`
  Result: `1 passed, 16 deselected`; `1 passed, 452 deselected`; `4 passed, 13 deselected`; `1 passed, 452 deselected`
  Notes: passive HTML mining now extracts `srcset` entries and CSS `url(...)` references in addition to literal URLs and simple attributes. `data:`, `javascript:`, `mailto:`, and `tel:` values remain filtered, including `data:` payload fragments inside `srcset`. The D-to-D5 regression proves a discovered page URL still re-enters URL-surface mining while file-like `.html/.css` URLs are queued into artifact/static analysis. No live target probing or rate-limit behavior changed.

- [x] Epieos provider-handle normalization checkpoint is green:
  `python -m py_compile forge\utils\intel\social_scraper.py tests\phase2\test_social_scraper.py forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests/phase2/test_social_scraper.py -k "explicit_profile_urls_reuse_recursive_handle_rules_and_skip_reserved_routes or direct_handle_fields_are_normalized_before_profile_url_construction or constructs_additional_profile_urls" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "dry_run_promotes_operator_social_url_seeds_into_recursive_identity_fanouts" -q --color=no`
  Result: `3 passed, 20 deselected`; `1 passed, 452 deselected`
  Notes: Epieos direct handle fields are now normalized before profile URL construction. URL-shaped fields such as `custom_url=https://github.com/acmeurl` are parsed into `acmeurl`, invalid direct handles can fall back to the explicit profile URL, and YouTube channel IDs render as `/channel/UC...` instead of malformed `@UC...` profile URLs. This keeps imported provider payloads from poisoning recursive username seeds.

- [x] Instagram/social-profile recursion checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py forge\utils\intel\social_scraper.py tests\phase1\test_engagement_orchestrator.py tests\phase2\test_social_scraper.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "social_profile_url_parser_supports_twitter_intent_links_and_skips_github_reserved_paths or dry_run_promotes_operator_social_url_seeds_into_recursive_identity_fanouts" -q --color=no`
  `python -m pytest tests/phase2/test_social_scraper.py -k "explicit_profile_urls_reuse_recursive_handle_rules_and_skip_reserved_routes" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "html_public_profile_urls_feed_recursive_identity_and_company_fanouts" -q --color=no`
  Result: `2 passed, 451 deselected`; `1 passed, 21 deselected`; `1 passed, 452 deselected`
  Notes: Instagram URL normalization now has an explicit branch before the generic social-host fallback. Direct profile URLs such as `instagram.com/rootinsta/reels/` and story URLs such as `instagram.com/stories/rootstory/...` promote the real username into recursive identity fan-out, while content/index routes such as `/reels/audio/...` and `/reel/...` are blocked from becoming bogus `reels`/`reel` username seeds. The dry-run operator-recursion test now also proves YouTube, TikTok, link-in-bio, npm, PyPI, Hugging Face, and Carrd profile URLs enter the recursive username path. Tests used temp data dirs only; no persistent engagement DBs were created or deleted.

- [x] Shared engagement ID allocator checkpoint is green:
  `python -m py_compile forge\engagement_ids.py forge\webui\app.py forge\cli.py tests\phase1\test_engagement_ids.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_ids.py -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "auto_engagement_id_uses_shared_sequence" -q --color=no`
  `python -m pytest tests/integration/test_webui_engagement_api.py -k "engagement_create" -q --color=no`
  `python -m pytest tests/phase1/test_cli_parallel_dispatch.py -q --color=no`
  `python -m pytest tests/integration/test_webui_engagement_api.py -k "engagement_create or engagement_detail or seed" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_ids.py tests/phase1/test_engagement_orchestrator.py -k "engagement_id" -q --color=no`
  Result: `3 passed`; `1 passed, 451 deselected`; `2 passed, 22 deselected, 12 warnings`; `17 passed`; `6 passed, 18 deselected, 19 warnings`; `4 passed, 451 deselected`
  Notes: `forge.engagement_ids.allocate_engagement_id()` is now the shared monotonic SQLite-backed allocator for both web API creation and CLI `kill-chain` auto-ID creation. It seeds from existing numeric engagement DB filenames, serializes allocation in `.forge_data/engagements/master.db`, skips nonnumeric DBs during enumeration, and prevents ID reuse after deleted engagement DB files. Tests used temp data dirs only; persistent engagement DBs were inventoried read-only and not deleted.

- [x] Remote artifact acquisition 429 pacing checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "rate_limited_remote_artifact" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "rate_limited_remote_artifact or header_filename or remote_brotli or remote_lz4 or remote_ocr_artifact or extensionless_seed_image_url" -q --color=no`
  `python -m pytest tests/phase2/test_identity_provider_pacing.py tests/phase2/test_passive_host_persistence.py -k "web_fetch_get or shodan_domain_paces" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "artifact_queue_processor_parallelizes_remote_acquisition_stage_while_preserving_processing or dry_run_queues_seed_artifact_urls_and_processes_remote_apk" -q --color=no`
  Result: `1 passed, 452 deselected`; `4 passed, 449 deselected`; `2 passed, 6 deselected`; `2 passed, 451 deselected`
  Notes: remote artifact downloads now reuse the `web_fetch` pacing family for configurable request delay, bounded 429 retry, capped `Retry-After`, and same-host cooldown reuse before downloading recursive APK/document/image/config artifacts. This is slow-and-steady acquisition only; no proxy/IP rotation, rate-limit bypass, artifact execution, or persistent test engagement DB mutation was added.

- [x] Target-side web-fetch 429 cooldown checkpoint is green:
  `python -m py_compile forge\utils\intel\http_pacing.py forge\cli.py tests\phase2\test_identity_provider_pacing.py tests\phase1\test_cli_parallel_dispatch.py`
  `python -m pytest tests/phase2/test_identity_provider_pacing.py -q --color=no`
  `python -m pytest tests/phase1/test_cli_parallel_dispatch.py -k "html_fetch or web_fetch_host_cooldown" -q --color=no`
  `python -m pytest tests/phase2/test_key_validation_pacing.py tests/phase2/test_identity_provider_pacing.py -q --color=no`
  `python -m pytest tests/phase1/test_cli_parallel_dispatch.py -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "recursive_seed_and_instagram_fanouts or parallel_batches or url_surface or artifact_queue or multi_iteration_mixes_local_artifacts_social_recursion_and_auto_template_fallback" -q --color=no`
  `python -m pytest tests/phase4/test_cloud_validate.py -q --color=no`
  `python -m pytest tests/integration/test_engagement_pipeline.py -k "mixed_provider or mixes_key_validators_cloud_asset_and_template_fallback" -q --color=no`
  `python -m pytest tests/integration/test_webui_engagement_api.py -k "engagement_create or seed or detail or run" -q --color=no`
  `python -m pytest tests/opsec/test_evasion_assertions.py -q --color=no`
  Result: `4 passed`; `3 passed, 14 deselected`; `9 passed`; `17 passed`; `296 passed, 155 deselected`; `91 passed`; `1 passed, 8 deselected`; `11 passed, 13 deselected, 32 warnings`; `23 passed, 1 warning`
  Notes: recursive rendered/HTML fallback fetches now share a `web_fetch` 429 cooldown/backoff family. This is slow-and-steady pacing only; no proxy/IP rotation or rate-limit bypass was added. No current-run persistent test engagement DBs were created or modified.

- [x] Non-cloud key validation proof-gating checkpoint is green:
  `python -m py_compile forge\phase4\cloud_validate.py tests\phase4\test_cloud_validate.py`
  `python -m pytest tests/phase4/test_cloud_validate.py -k "non_cloud_validation_identifier_parser or active_key_without_provider_proof or validatable_azure_connection_string or validatable_slack_token" -q --color=no`
  `python -m pytest tests/phase4/test_cloud_validate.py -q --color=no`
  `python -m pytest tests/phase2/test_secret_finder.py tests/phase2/test_key_scanner.py -q --color=no`
  `python -m pytest tests/integration/test_engagement_pipeline.py -k "mixed_provider or mixes_key_validators_cloud_asset_and_template_fallback" -q --color=no`
  `python -m pytest tests/phase1/test_deterministic_findings.py -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "local_generic_secret_artifacts_feed_mixed_key_validation or multi_iteration_mixes_local_artifacts_social_recursion_and_auto_template_fallback" -q --color=no`
  `python -m pytest tests/opsec/test_evasion_assertions.py -q --color=no`
  Result: `4 passed, 87 deselected`; `91 passed`; `82 passed`; `1 passed, 8 deselected`; `9 passed`; `2 passed, 449 deselected` in `0:04:01`; `23 passed, 1 warning`
  Notes: Phase 4 no longer upgrades non-cloud key-provider validation to `VALIDATED` solely because a validator returned `ACTIVE`; the validator detail must now contain provider-specific proof that can be parsed into a stable identifier. Stale low-signal details such as `Slack auth ok: token accepted` stay `UNVERIFIED`/`UNCONFIRMED` and do not generate deterministic key findings. Azure shared-key details now require `account=...` plus `containers=...` proof before deriving the storage account identifier.

- [x] LZ4 artifact/container parsing checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "lz4" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "bzip2_txz or brotli or lz4 or compressed_warc or buried_gzip" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "remote_ocr_artifact or extensionless_seed_image_url or header_filename or remote_lz4 or remote_brotli" -q --color=no`
  `python -m pytest tests/integration/test_engagement_pipeline.py -k "mixed_provider or mixes_key_validators_cloud_asset_and_template_fallback" -q --color=no`
  `python -m pytest tests/opsec/test_evasion_assertions.py -q --color=no`
  `python -m pytest tests/integration/test_webui_engagement_api.py -k "create or seed_crud or engagement_list_and_detail_routes or kill_chain_run" -q --color=no`
  `python -m pytest tests/reporting/test_dashboard.py -k "engagement or dashboard" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "local_generic_secret_artifacts_feed_mixed_key_validation or multi_iteration_mixes_local_artifacts_social_recursion_and_auto_template_fallback" -q --color=no`
  Result: `2 passed, 449 deselected`; `6 passed, 445 deselected`; `3 passed, 448 deselected`; `1 passed, 8 deselected`; `23 passed, 1 warning`; `3 passed, 21 deselected, 19 warnings`; `8 passed`; `2 passed, 449 deselected` in `0:04:04`
  Notes: local/remote artifact classification now treats `.lz4`, `.tlz4`, and `.tar.lz4` as passive compressed artifacts. LZ4 payloads are decompressed only when optional `lz4.frame` support is available and are fed through the existing text/archive extraction path. Tests prove local LZ4 JSON, nested tar-LZ4, carved embedded LZ4, and a remote `.json.lz4` seed URL all promote emails, URLs, GCS/S3/Supabase refs, seed relations, and cloud assets without executing content.

- [x] Passive provider/static-page discovery rerun is green:
  `python -m pytest tests/phase2/test_passive_host_persistence.py tests/phase2/test_commoncrawl_lookup.py tests/phase2/test_wayback_lookup.py tests/phase1/test_subdomain_enum.py -k "paces or commoncrawl or wayback or crtsh or shodan or urlscan" -q --color=no` -> `9 passed, 4 deselected`
  `python -m pytest tests/phase1/test_html_fetch_batch.py tests/phase2/test_passive_host_persistence.py -q --color=no` -> `5 passed`
  `python -m pytest tests/phase1/test_port_scanner.py -k "shodan or synthetic" -q --color=no` -> `2 passed, 3 deselected`
  Notes: Shodan-backed enrichment, public index helpers, subdomain discovery, and HTML/static fetch batching remain green with pacing/backoff behavior and without IP rotation or provider-limit bypass.

- [x] Brotli artifact/container parsing checkpoint is green:
  `python -m py_compile forge\engagement_orchestrator.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "brotli_config_url or extracts_brotli" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "bzip2_txz or brotli or compressed_warc or buried_gzip" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "remote_ocr_artifact or extensionless_seed_image_url or header_filename" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "local_generic_secret_artifacts_feed_mixed_key_validation or multi_iteration_mixes_local_artifacts_social_recursion_and_auto_template_fallback" -q --color=no`
  `python -m pytest tests/integration/test_engagement_pipeline.py -k "mixed_provider or mixes_key_validators_cloud_asset_and_template_fallback" -q --color=no`
  Result: `2 passed, 447 deselected`; `4 passed, 445 deselected`; `3 passed, 445 deselected`; `2 passed, 447 deselected`; `1 passed, 8 deselected`
  Notes: local/remote artifact classification now treats `.br`, `.tbr`, and `.tar.br` as passive compressed artifacts. Brotli payloads are decompressed only when optional `brotli`/`brotlicffi` support is available, then fed through the existing text/archive extraction path so compressed web configs can promote emails, URLs, S3 buckets, Supabase refs, and recursive seeds without executing content. A dry-run localhost fixture now proves a remote `.json.br` URL seed is queued, downloaded, parsed, and promoted into engagement seeds/cloud assets.

- [x] Stripe/SendGrid/Mailchimp/Twilio/Slack weak-success guard checkpoint is green:
  `python -m py_compile forge\utils\intel\secret_finder.py forge\phase4\cloud_validate.py tests\phase2\test_secret_finder.py tests\phase2\test_key_scanner.py tests\phase4\test_cloud_validate.py`
  `python -m pytest tests/phase2/test_secret_finder.py -k "stripe or sendgrid or mailchimp or twilio" -q --color=no`
  `python -m pytest tests/phase2/test_key_scanner.py -k "SlackTokenValidator or StripeKeyValidator" -q --color=no`
  `python -m pytest tests/phase4/test_cloud_validate.py -k "non_cloud_validation_identifier_parser or stripe or sendgrid or mailchimp or slack or twilio" -q --color=no`
  `python -m pytest tests/phase2/test_secret_finder.py tests/phase2/test_key_scanner.py -q --color=no`
  `python -m pytest tests/phase4/test_cloud_validate.py -q --color=no`
  `python -m pytest tests/integration/test_engagement_pipeline.py -k "mixed_provider or mixes_key_validators_cloud_asset_and_template_fallback" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "local_generic_secret_artifacts_feed_mixed_key_validation or multi_iteration_mixes_local_artifacts_social_recursion_and_auto_template_fallback" -q --color=no`
  Result: `9 passed, 26 deselected`; `6 passed, 41 deselected`; `8 passed, 82 deselected`; `82 passed`; `90 passed`; `1 passed, 8 deselected`; `2 passed, 445 deselected`
  Notes: Stripe, SendGrid, Mailchimp, Twilio, and Slack validators now require provider-specific proof fields on `200 OK` before returning `ACTIVE`. Phase 4 identifier derivation rejects stale low-signal legacy details such as Stripe `mode=unknown`, SendGrid profile/scopes without proof counts, Mailchimp region-only ping, and Slack `token accepted`.

- [x] AWS/Azure provider-validation weak-success guard checkpoint is green:
  `python -m py_compile forge\utils\intel\secret_finder.py tests\phase2\test_secret_finder.py tests\phase2\test_key_scanner.py tests\phase4\test_cloud_validate.py`
  `python -m pytest tests/phase2/test_secret_finder.py -k "aws_validator" -q --color=no`
  `python -m pytest tests/phase2/test_key_scanner.py -k "AzureStorageConnectionStringValidator" -q --color=no`
  `python -m pytest tests/phase4/test_cloud_validate.py -k "non_cloud_validation_identifier_parser" -q --color=no`
  `python -m pytest tests/phase2/test_secret_finder.py tests/phase2/test_key_scanner.py -q --color=no`
  `python -m pytest tests/phase4/test_cloud_validate.py -q --color=no`
  Result: `2 passed, 29 deselected`; `4 passed, 42 deselected`; `1 passed, 89 deselected`; `77 passed`; `90 passed`
  Notes: AWS STS validation now requires a parseable response with a 12-digit AccountId before returning `ACTIVE`. Azure storage connection-string validation now requires a parseable `EnumerationResults` container-list response; valid zero-container listings still prove the key works, while malformed or generic `200 OK` success bodies stay `UNCONFIRMED`.

- [x] Low-signal provider-validation proof guard checkpoint is green:
  `python -m py_compile forge\utils\intel\secret_finder.py forge\phase4\cloud_validate.py tests\phase2\test_secret_finder.py tests\phase2\test_key_scanner.py tests\phase4\test_cloud_validate.py`
  `python -m pytest tests/phase2/test_secret_finder.py -k "github or gitlab or google" -q --color=no`
  `python -m pytest tests/phase2/test_key_scanner.py -k "GithubPatValidator" -q --color=no`
  `python -m pytest tests/phase4/test_cloud_validate.py -k "non_cloud_validation_identifier_parser or github or gitlab or google" -q --color=no`
  `python -m pytest tests/phase2/test_secret_finder.py tests/phase2/test_key_scanner.py -q --color=no`
  `python -m pytest tests/phase4/test_cloud_validate.py -q --color=no`
  `python -m pytest tests/integration/test_engagement_pipeline.py -k "mixed_provider or mixes_key_validators_cloud_asset_and_template_fallback" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "local_generic_secret_artifacts_feed_mixed_key_validation or multi_iteration_mixes_local_artifacts_social_recursion_and_auto_template_fallback" -q --color=no`
  Result: `12 passed, 18 deselected`; `6 passed, 38 deselected`; `4 passed, 86 deselected`; `74 passed`; `90 passed`; `1 passed, 8 deselected`; `2 passed, 445 deselected`
  Notes: GitHub/GitLab/Google validators now require provider-specific proof fields before returning `ACTIVE` (`login`, `username/login`, and non-empty model list). Cloud-validation identifier parsing now rejects legacy low-signal `unknown` and `models=0` details so they cannot become deterministic report rows.

- [x] SendGrid/Slack credential-validation evidence hygiene checkpoint is green:
  `python -m py_compile forge\utils\intel\secret_finder.py forge\phase4\cloud_validate.py tests\phase2\test_secret_finder.py tests\phase2\test_key_scanner.py tests\phase4\test_cloud_validate.py tests\integration\test_engagement_pipeline.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests/phase2/test_secret_finder.py -k "sendgrid or slack or mailchimp or google or twilio" -q --color=no`
  `python -m pytest tests/phase4/test_cloud_validate.py -k "sendgrid or slack" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "local_generic_secret_artifacts_feed_mixed_key_validation or multi_iteration_mixes_local_artifacts_social_recursion_and_auto_template_fallback" -q --color=no`
  Result: `8 passed, 19 deselected`; `3 passed, 86 deselected`; `2 passed, 445 deselected`
  Notes: SendGrid validation no longer persists raw account email/username as proof or cloud identifiers; Slack validation now prefers actor/team IDs over workspace names.

- [x] Shared provider-host cooldown checkpoint is green:
  `python -m py_compile forge\utils\intel\http_pacing.py tests\phase2\test_key_validation_pacing.py tests\phase2\test_identity_provider_pacing.py tests\phase4\test_cloud_validate.py`
  `python -m pytest tests/phase2/test_key_validation_pacing.py tests/phase2/test_identity_provider_pacing.py -q --color=no`
  `$env:FORGE_KEY_VALIDATION_REQUEST_DELAY_SECONDS='0'; python -m pytest tests/phase4/test_cloud_validate.py -q --color=no`
  `python -m pytest tests/phase2/test_secret_finder.py tests/phase2/test_key_scanner.py -q --color=no`
  Result: `8 passed`; `89 passed`; `69 passed`
  Notes: identity-provider and key/cloud validation wrappers now remember same-host HTTP 429 cooldowns across subsequent requests in the same process, keyed separately by pacing family. This is pacing/backoff only, not IP rotation, proxy cycling, account/session evasion, or provider-limit bypass.

- [x] Passive discovery provider-host cooldown checkpoint is green:
  `python -m py_compile forge\utils\intel\http_pacing.py forge\utils\intel\shodan_lookup.py forge\utils\intel\urlscan_lookup.py forge\utils\intel\wayback_lookup.py forge\utils\intel\commoncrawl_lookup.py forge\phase1\subdomain_enum.py tests\phase2\test_passive_host_persistence.py tests\phase2\test_commoncrawl_lookup.py tests\phase2\test_wayback_lookup.py tests\phase1\test_subdomain_enum.py`
  `python -m pytest tests/phase2/test_passive_host_persistence.py tests/phase2/test_commoncrawl_lookup.py tests/phase2/test_wayback_lookup.py tests/phase1/test_subdomain_enum.py -k "paces or commoncrawl or wayback or crtsh or shodan or urlscan" -q --color=no`
  `python -m pytest tests/phase2/test_passive_host_persistence.py tests/phase2/test_commoncrawl_lookup.py tests/phase2/test_wayback_lookup.py tests/phase1/test_subdomain_enum.py -q --color=no`
  Result: `9 passed, 4 deselected`; `13 passed`
  Notes: Shodan, URLScan, Wayback, Common Crawl, and crt.sh now reuse shared same-host 429 cooldown hooks after their existing per-provider retry handling.

- [x] Storage build-config metadata false-positive hardening checkpoint is green:
  `python -m py_compile forge\phase4\cloud_validate.py tests\phase4\test_cloud_validate.py`
  `$env:FORGE_KEY_VALIDATION_REQUEST_DELAY_SECONDS='0'; python -m pytest tests/phase4/test_cloud_validate.py -k "repository_metadata_helper or package_metadata_only_listing or gcs_json_metadata_only" -q --color=no`
  `$env:FORGE_KEY_VALIDATION_REQUEST_DELAY_SECONDS='0'; python -m pytest tests/phase4/test_cloud_validate.py -q --color=no`
  `python -m pytest tests/phase1/test_deterministic_findings.py -q --color=no`
  Result: `5 passed, 84 deselected`; `89 passed`; `9 passed`
  Notes: storage listings containing only common non-secret frontend/build metadata such as `tsconfig*.json`, `vite.config.*`, `tailwind.config.*`, `postcss.config.*`, `webpack.config.*`, and adjacent build-tool config files now remain audit-only as `ACCESSIBLE_BUT_NO_DATA`. `.env`, secret JSON, uploads, reports, backups, and application data files remain meaningful.

- [x] Storage static-chunk false-positive hardening checkpoint is green:
  `python -m py_compile forge\phase4\cloud_validate.py tests\phase4\test_cloud_validate.py`
  `$env:FORGE_KEY_VALIDATION_REQUEST_DELAY_SECONDS='0'; python -m pytest tests/phase4/test_cloud_validate.py -k "static_site_helper_recognizes_framework_build_artifacts or downgrades_s3_framework_static_site_listing" -q --color=no`
  `$env:FORGE_KEY_VALIDATION_REQUEST_DELAY_SECONDS='0'; python -m pytest tests/phase4/test_cloud_validate.py -q --color=no`
  `python -m pytest tests/phase1/test_deterministic_findings.py -q --color=no`
  Result: `2 passed, 87 deselected`; `89 passed`; `9 passed`
  Notes: storage listings containing only common generated static chunk/build assets such as `static/chunks/*.js`, root `chunks/*.js`, `static/assets/*`, and `public/build/*` now remain audit-only as `ACCESSIBLE_BUT_NO_DATA` instead of becoming validated public-storage findings.

- [x] Key/cloud validation pacing checkpoint is green:
  `python -m py_compile forge\utils\intel\http_pacing.py forge\utils\intel\secret_finder.py forge\phase4\cloud_validate.py forge\cli.py tests\phase2\test_key_validation_pacing.py tests\phase2\test_key_scanner.py tests\phase2\test_secret_finder.py tests\phase4\test_cloud_validate.py`
  `python -m pytest tests/phase2/test_key_validation_pacing.py -q --color=no`
  `python -m pytest tests/phase2/test_key_scanner.py tests/phase2/test_secret_finder.py tests/phase4/test_cloud_validate.py -k "GithubPatValidator or StripeKeyValidator or github_pat_validator or stripe_validator or github_pat or google_api_key or gitlab_pat or mailchimp_key" -q --color=no`
  `$env:FORGE_KEY_VALIDATION_REQUEST_DELAY_SECONDS='0'; python -m pytest tests/phase4/test_cloud_validate.py -q --color=no`
  `python -m pytest tests/phase1/test_cli_parallel_dispatch.py -k "validation_worker_cap or gravatar_parallelizes or google_parallelizes" -q --color=no`
  Result: `4 passed`; `25 passed, 132 deselected`; `89 passed`; `3 passed, 13 deselected`
  Notes: GitHub/GitLab/Stripe/SendGrid/Mailchimp/Google/Twilio/Slack/AWS/Azure key validation plus Firebase/Supabase/S3/DO/GCS/Azure Blob cloud-asset validation now route provider calls through `FORGE_KEY_VALIDATION_*` delay/backoff/429 retry wrappers; recursive kill-chain key/cloud validation sweeps honor `FORGE_VALIDATION_MAX_WORKERS` default `1`, max `4`. This is pacing/backoff only, not IP rate-limit bypass.

- [x] Provider credential false-positive hardening checkpoint is green:
  `python -m py_compile forge\utils\intel\secret_finder.py tests\phase2\test_key_scanner.py`
  `python -m pytest tests/phase2/test_key_scanner.py -k "GithubPatValidator or StripeKeyValidator" -q --color=no`
  `python -m pytest tests/phase2/test_secret_finder.py -k "github_pat_validator or stripe_validator" -q --color=no`
  `python -m pytest tests/phase4/test_cloud_validate.py -k "github_pat or google_api_key or gitlab_pat or mailchimp_key" -q --color=no`
  Result: `8 passed, 35 deselected`; `3 passed, 23 deselected`; `4 passed, 84 deselected`
  Notes: shared GitHub and Stripe validators no longer turn placeholder-looking strings such as `fake`/`revoked` into deterministic ACTIVE/REVOKED states without a provider response. This reduces report-gating false positives; tests now mock provider responses explicitly.

- [x] Direct identity-provider pacing checkpoint is green:
  `python -m py_compile forge\utils\intel\http_pacing.py forge\utils\intel\gravatar_lookup.py forge\utils\intel\instagram_lookup.py forge\utils\intel\phone_lookup.py tests\phase2\test_identity_provider_pacing.py tests\phase2\test_phone_lookup.py`
  `python -m pytest tests/phase2/test_identity_provider_pacing.py tests/phase2/test_phone_lookup.py -q --color=no`
  Result: `8 passed`
  Notes: Gravatar/Instagram/phone-account GETs now use shared delay/backoff/429 retry via `FORGE_IDENTITY_LOOKUP_*`; this is pacing, not IP/rate-limit bypass.

- [x] Direct identity-provider worker-cap checkpoint is green:
  `python -m py_compile forge\cli.py tests\phase1\test_cli_parallel_dispatch.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_cli_parallel_dispatch.py tests/phase1/test_engagement_orchestrator.py -k "gravatar_parallelizes or google_parallelizes or email_fanouts or recursive_seed_and_instagram_fanouts or social_handle" -q --color=no`
  Result: `6 passed, 456 deselected`
  Notes: `FORGE_IDENTITY_LOOKUP_MAX_WORKERS` now caps Gravatar/Ghunt/Instagram direct-provider lanes separately from the general recursive fan-out.

- [x] Combined identity/API checkpoint is green:
  `python -m pytest tests/phase2/test_identity_provider_pacing.py tests/phase2/test_phone_lookup.py tests/phase1/test_cli_parallel_dispatch.py tests/phase1/test_engagement_orchestrator.py tests/integration/test_webui_engagement_api.py -k "identity_provider_pacing or phone_lookup or gravatar_parallelizes or google_parallelizes or email_fanouts or recursive_seed_and_instagram_fanouts or social_handle or engagement_create" -q --color=no`
  Result: `16 passed, 478 deselected, 12 warnings`

- [x] Passive discovery recursion checkpoint is green:
  `python -m pytest tests/phase2/test_passive_host_persistence.py tests/phase2/test_commoncrawl_lookup.py tests/phase2/test_wayback_lookup.py -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "parallel_batches_wayback_host_parse or discovered_url_seeds_reenter_same_iteration_surface_mining" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "html_remote_artifact_drives_validation_findings_and_second_iteration_email_fanout or html_remote_mobile_bundle_drives_validation_findings_and_second_iteration_email_fanout" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "passive_text_mining_promotes_robots_and_sitemap_urls_without_live_network" -q --color=no`
  Result: `8 passed`; `2 passed, 445 deselected`; `2 passed, 445 deselected`; `1 passed, 446 deselected in 181.69s`

- [x] Shodan env compatibility checkpoint is green:
  `python -m py_compile forge\config.py forge\cli.py tests\test_platform_config.py`
  `python -m pytest tests/test_platform_config.py tests/phase2/test_linkedin_scraper.py tests/phase2/test_name_search.py tests/phase2/test_phone_lookup.py tests/phase1/test_port_scanner.py tests/phase2/test_passive_host_persistence.py -q --color=no`
  Result: `62 passed`
  Notes: `ForgeConfig.load()` now prefers `FORGE_SHODAN_API_KEY` and falls back to legacy `FORGE_SHODAN_KEY`; CLI health text uses the documented env var.

- [x] Public search-dork pacing checkpoint is green:
  `python -m py_compile forge\utils\intel\linkedin_scraper.py forge\utils\intel\name_search.py forge\utils\intel\phone_lookup.py tests\phase2\test_linkedin_scraper.py tests\phase2\test_name_search.py tests\phase2\test_phone_lookup.py`
  `python -m pytest tests/phase2/test_linkedin_scraper.py tests/phase2/test_name_search.py tests/phase2/test_phone_lookup.py tests/phase1/test_subdomain_enum.py tests/phase1/test_crawler.py tests/phase1/test_port_scanner.py tests/phase1/test_html_fetch_batch.py tests/phase2/test_passive_host_persistence.py -q --color=no`
  Result: `30 passed`
  Notes: LinkedIn, full-name, and phone dork mining now honor `FORGE_SEARCH_DORK_REQUEST_DELAY_SECONDS` while preserving bounded concurrency and ordered result merging.

- [x] crt.sh CT-log pacing checkpoint is green:
  `python -m py_compile forge\phase1\subdomain_enum.py forge\phase1\crawler.py forge\phase1\port_scanner.py tests\phase1\test_subdomain_enum.py tests\phase1\test_crawler.py tests\phase1\test_port_scanner.py`
  `python -m pytest tests/phase1/test_subdomain_enum.py tests/phase1/test_crawler.py tests/phase1/test_port_scanner.py tests/phase1/test_html_fetch_batch.py tests/phase2/test_passive_host_persistence.py -q --color=no`
  Result: `16 passed`
  Notes: crt.sh lookup now supports `FORGE_CRTSH_REQUEST_DELAY_SECONDS`, `FORGE_CRTSH_RATE_LIMIT_BACKOFF_SECONDS`, `FORGE_CRTSH_MAX_RETRY_AFTER_SECONDS`, and `FORGE_CRTSH_RATE_LIMIT_RETRIES`; unit tests no longer call live crt.sh.

- [x] Standalone crawler + active port-scan pacing checkpoint is green:
  `python -m py_compile forge\phase1\crawler.py forge\phase1\port_scanner.py tests\phase1\test_crawler.py tests\phase1\test_port_scanner.py`
  `python -m pytest tests/phase1/test_crawler.py tests/phase1/test_port_scanner.py tests/phase1/test_html_fetch_batch.py tests/phase2/test_passive_host_persistence.py -q --color=no`
  Result: `11 passed`
  Notes: `recon crawl` now honors `FORGE_WEB_FETCH_REQUEST_DELAY_SECONDS`; active port scans now have `FORGE_PORT_SCAN_HOST_DELAY_SECONDS`, `FORGE_PORT_SCAN_PORT_DELAY_SECONDS`, and `FORGE_PORT_SCAN_PORT_CONCURRENCY`, skip explicit synthetic/placeholder host rows instead of probing RFC-2544 placeholder IPs, and reuse Shodan pacing/backoff for enhanced service lookups.

- [x] Historical CDX URL recursion checkpoint is green:
  `python -m py_compile forge\cli.py tests\phase1\test_engagement_orchestrator.py forge\utils\intel\commoncrawl_lookup.py forge\utils\intel\wayback_lookup.py tests\phase2\test_commoncrawl_lookup.py tests\phase2\test_wayback_lookup.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "parallel_batches_wayback_host_parse" -q --color=no`
  `python -m pytest tests/phase2/test_commoncrawl_lookup.py tests/phase2/test_wayback_lookup.py tests/phase1/test_html_fetch_batch.py tests/phase2/test_passive_host_persistence.py tests/phase1/test_engagement_orchestrator.py -k "commoncrawl or wayback_lookup or html_fetch or passive_host_persistence or parallel_batches_wayback_host_parse" -q --color=no`
  Result: `1 passed, 446 deselected`; `10 passed, 446 deselected`
  Notes: scoped Wayback/Common-Crawl historical URLs now persist to `crawl_results` and URL/apk URL seeds so pages/static files/artifacts can re-enter recursion.

- [x] Common Crawl CDXJ passive URL enrichment checkpoint is green:
  `python -m py_compile forge\utils\intel\commoncrawl_lookup.py forge\utils\intel\wayback_lookup.py forge\cli.py tests\phase2\test_commoncrawl_lookup.py tests\phase2\test_wayback_lookup.py tests\phase1\test_html_fetch_batch.py tests\phase2\test_passive_host_persistence.py`
  `python -m pytest tests/phase2/test_commoncrawl_lookup.py tests/phase2/test_wayback_lookup.py tests/phase1/test_html_fetch_batch.py tests/phase2/test_passive_host_persistence.py -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "parallel_batches_wayback_host_parse" -q --color=no`
  Result: `9 passed`; `1 passed, 446 deselected`
  Notes: Fan-out I now combines Wayback with paced recent Common Crawl CDXJ URL discovery; it is index-only and does not download WARC payloads.

- [x] Wayback/CDX domain-wide historical discovery checkpoint is green:
  `python -m py_compile forge\utils\intel\wayback_lookup.py tests\phase2\test_wayback_lookup.py forge\cli.py tests\phase1\test_html_fetch_batch.py tests\phase2\test_passive_host_persistence.py`
  `python -m pytest tests/phase2/test_wayback_lookup.py tests/phase1/test_html_fetch_batch.py tests/phase2/test_passive_host_persistence.py -q --color=no`
  Result: `7 passed`
  Notes: Wayback/CDX now uses `matchType=domain` in capped and full-paginated modes, improving historical subdomain/static/page/artifact discovery.

- [x] Target-side HTML/rendered-page fetch pacing checkpoint is green:
  `python -m py_compile forge\cli.py tests\phase1\test_html_fetch_batch.py`
  `python -m pytest tests/phase1/test_html_fetch_batch.py tests/phase2/test_wayback_lookup.py tests/phase2/test_passive_host_persistence.py -q --color=no`
  Result: `7 passed`
  Notes: `FORGE_WEB_FETCH_REQUEST_DELAY_SECONDS` now delays each in-scope rendered/fallback fetch; default is `0.0`, so set it explicitly for slow live runs.

- [x] Wayback/CDX historical URL discovery pacing checkpoint is green:
  `python -m py_compile forge\utils\intel\wayback_lookup.py forge\cli.py tests\phase2\test_wayback_lookup.py tests\phase1\test_engagement_orchestrator.py`
  `python -m pytest tests/phase2/test_wayback_lookup.py tests/phase1/test_engagement_orchestrator.py -k "wayback_lookup or parallel_batches_wayback_host_parse" -q --color=no`
  Result: `3 passed, 446 deselected`
  Notes: Fan-out I now uses `forge.utils.intel.wayback_lookup.search_wayback_urls()` with delay/backoff/retry controls and preserves old capped/full CDX behavior.

- [x] URLScan passive-provider pacing checkpoint is green:
  `python -m py_compile forge\utils\intel\urlscan_lookup.py tests\phase2\test_passive_host_persistence.py`
  `python -m pytest tests/phase2/test_passive_host_persistence.py -q --color=no`
  Result: `4 passed`
  Notes: `FORGE_URLSCAN_REQUEST_DELAY_SECONDS`, `FORGE_URLSCAN_RATE_LIMIT_BACKOFF_SECONDS`, `FORGE_URLSCAN_MAX_RETRY_AFTER_SECONDS`, and `FORGE_URLSCAN_RATE_LIMIT_RETRIES` are documented in `.env.example`, `README.md`, and `DAILY_USE.md`. This is pacing/backoff, not IP-based rate-limit bypass.

- [x] OCI image-layout artifact + Shodan pacing checkpoint is green:
  `python -m py_compile forge/engagement_orchestrator.py forge/utils/intel/shodan_lookup.py tests/phase1/test_engagement_orchestrator.py tests/phase2/test_passive_host_persistence.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "oci_image_layout_metadata_artifacts or container_orchestration_metadata_artifacts or structured_terraform_state_cloud_assets" -q --color=no`
  `python -m pytest tests/phase2/test_passive_host_persistence.py -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "multi_iteration_recurses_social_profile_seeds_without_live_network or multi_iteration_mixes_local_artifacts_social_recursion_and_auto_template_fallback" -q --color=no`
  `python -m pytest tests/reporting/test_dashboard.py -k "emits_slug_routes_and_json_contract or parses_graphml_into_detail_graph_payload or prefers_graph_json_artifact_over_graphml_when_snapshot_missing" -q --color=no`
  `python -m pytest tests/integration/test_webui_engagement_api.py -k "engagement_list_and_detail_routes or engagement_create_and_seed_crud_routes" -q --color=no`
  `python -m pytest tests/phase4/test_cloud_validate.py -q --color=no`
  `python -m pytest tests/phase1/test_deterministic_findings.py -q --color=no`
  Result: `3 passed, 443 deselected`; `3 passed`; `2 passed, 444 deselected`; `3 passed, 5 deselected`; `2 passed, 21 deselected, 16 warnings`; `86 passed`; `9 passed`
- [x] Persistent test DB cleanup done:
  Deleted `.forge_data/engagements/1002.db`, `1006.db`, `1007.db`, `1008.db`, and `1012.db`; kept ambiguous historical/audit engagement DBs.
- [x] Historical next audit target completed by later provider-proof and broad-suite checkpoints below.
  Current next audit target is listed at the top: extend equivalent ROE/scope enforcement to direct/manual validation entrypoints outside `kill_chain()`.

- [x] Broad backend/orchestration/reporting/dashboard checkpoint is green:
  `python -m pytest tests/phase1/test_cli_parallel_dispatch.py tests/phase1/test_engagement_orchestrator.py tests/phase1/test_deterministic_findings.py tests/phase2/test_key_scanner.py tests/phase2/test_secret_finder.py tests/phase2/test_xray_runner.py tests/phase4/test_attack_path.py tests/phase4/test_cloud_validate.py tests/phase4/test_firebase_extract.py tests/phase6/test_report_synthesizer.py tests/providers/test_fallback_chain.py tests/reporting/test_dashboard.py tests/integration/test_engagement_pipeline.py tests/integration/test_webui_engagement_api.py -q --color=no`
  Result: `478 passed, 34 warnings`
- [x] Graph/export finalization checkpoint is green:
  `python -m py_compile forge/phase4/attack_path.py tests/phase4/test_attack_path.py tests/phase1/test_engagement_orchestrator.py`
  `python -m pytest tests/phase4/test_attack_path.py -k "graph_build_all_writes_native_mtgx_workspace or missing_optional_exploit_table_does_not_break_build or snapshot_write_recreates_snapshot_table_if_missing" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "html_discovery_builds_graph_family_and_template_report" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "discovered_url_seeds_reenter_same_iteration_surface_mining or html_discovery_builds_graph_family_and_template_report" -q --color=no`
  Result: `3 passed, 92 deselected`; `1 passed, 111 deselected`; `2 passed, 110 deselected`
- [x] New mixed-provider engagement-pipeline slice is green:
  `python -m pytest tests/integration/test_engagement_pipeline.py -k "mixes_key_validators_cloud_asset_and_template_fallback or mixes_rtf_social_profile_and_template_fallback or validates_artifact_discovered_azure_connection_string or validates_key_only_supabase_and_falls_back_to_template" -q --color=no`
  Result: `4 passed, 5 deselected`
- [x] New combined live HTML -> remote artifact -> graph/report slice is green:
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "html_discovery_builds_graph_family_and_template_report or html_remote_artifact_drives_validation_findings_and_second_iteration_email_fanout or html_url_surface_remote_artifact_builds_graph_family_and_template_report" -q --color=no`
  Result: `3 passed, 110 deselected`
- [x] New mixed-provider live remote-artifact -> graph/report slice is green:
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "html_discovery_builds_graph_family_and_template_report or html_remote_artifact_drives_validation_findings_and_second_iteration_email_fanout or html_url_surface_remote_artifact_builds_graph_family_and_template_report or html_remote_artifact_mixed_key_validation_builds_graph_family_and_template_report" -q --color=no`
  Result: `4 passed, 110 deselected`
- [x] New combined local+remote artifact live kill-chain slice is green:
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "combines_local_and_remote_artifacts_for_validation_graph_and_template_report or html_remote_artifact_mixed_key_validation_builds_graph_family_and_template_report or local_generic_secret_artifacts_feed_mixed_key_validation or default_local_artifact_roots_include_artifacts_directory" -q --color=no`
  Result: `4 passed, 111 deselected`
- [x] Expanded multi-artifact combined-source live kill-chain slice is green:
  `python -m py_compile tests/phase1/test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "combines_multiple_local_and_remote_artifacts_in_one_engagement" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "combines_multiple_local_and_remote_artifacts_in_one_engagement or combines_local_and_remote_artifacts_for_validation_graph_and_template_report or html_remote_artifact_mixed_key_validation_builds_graph_family_and_template_report or default_local_artifact_roots_include_artifacts_directory" -q --color=no`
  Result: `1 passed, 115 deselected, 1 warning`; `4 passed, 112 deselected, 1 warning`
- [x] Passive HTTP scope fallback / bounded-worker checkpoint is green:
  `python -m pytest tests/phase2/test_xray_runner.py -k "falls_back_to_scope_entries or parallelizes_in_scope_targets or skips_out_of_scope_drifted_targets" -q --color=no`
  Result: `3 passed, 4 deselected`
- [x] Artifact progress telemetry checkpoint is green:
  `python -m py_compile forge/cli.py tests/integration/test_webui_engagement_api.py tests/phase1/test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "combines_local_and_remote_artifacts_for_validation_graph_and_template_report" -q --color=no`
  `python -m pytest tests/integration/test_webui_engagement_api.py -k "run_progress_bridge_publishes_live_kill_chain_metadata or run_progress_bridge_republishes_when_queue_metrics_change_without_step_change" -q --color=no`
  Result: `1 passed, 114 deselected`; `1 passed, 14 deselected`
- [x] Auto-run-detected prereq automation checkpoint is green:
  `python -m py_compile forge/cli.py tests/phase1/test_engagement_orchestrator.py tests/phase1/test_cli_parallel_dispatch.py`
  `python -m pytest tests/phase1/test_cli_parallel_dispatch.py -k "kill_chain_help_exposes_auto_run_detected_option" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "parallel_batches_detected_prereqs_when_auto_run_enabled or parallel_batches_credential_validation_services or parallel_batches_prereport_finalization_modules" -q --color=no`
  `python -m pytest tests/phase1/test_cli_parallel_dispatch.py -q --color=no`
  Result: `1 passed, 14 deselected`; `3 passed, 114 deselected`; `15 passed`
- [x] New validator-identifier checkpoint is green:
  `python -m py_compile forge/phase4/cloud_validate.py tests/phase4/test_cloud_validate.py`
  `python -m pytest tests/phase4/test_cloud_validate.py -k "github_pat_rows_without_cloud_finding or stripe_secret_key_rows_without_cloud_finding or mailchimp_key_rows_without_cloud_finding or slack_token_rows_without_cloud_finding or colocated_twilio_pair_without_cloud_finding or colocated_aws_pair_without_cloud_finding or validatable_azure_connection_string_without_cloud_finding" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "local_generic_secret_artifacts_feed_mixed_key_validation" -q --color=no`
  `python -m pytest tests/integration/test_engagement_pipeline.py -k "mixes_key_validators_cloud_asset_and_template_fallback" -q --color=no`
  Result: `7 passed, 51 deselected`; `1 passed, 116 deselected`; `1 passed, 8 deselected`
- [x] Focused deterministic report-fallback checkpoint is green:
  `python -m py_compile forge/phase6/report_synthesizer.py tests/phase6/test_report_synthesizer.py tests/providers/test_fallback_chain.py tests/integration/test_engagement_pipeline.py`
  `python -m pytest tests/phase6/test_report_synthesizer.py tests/providers/test_fallback_chain.py -k "fallback or auto_" -q --color=no`
  `python -m pytest tests/integration/test_engagement_pipeline.py -k "template_report or actual_template_backend or raw_export_when_report_family_write_fails" -q --color=no`
  Result: `14 passed, 57 deselected`; `3 passed, 6 deselected`
- [x] Report-audit detail payload checkpoint is green:
  `python -m py_compile forge/reporting/dashboard.py forge/webui/app.py tests/reporting/test_dashboard.py tests/integration/test_webui_engagement_api.py`
  `python -m pytest tests/reporting/test_dashboard.py -k "slug_routes_and_json_contract" -q --color=no`
  `python -m pytest tests/integration/test_webui_engagement_api.py -k "engagement_list_and_detail_routes" -q --color=no`
  `python -m pytest tests/integration/test_webui_engagement_api.py -k "root" -q --color=no`
  `npm run build`
  Result: `1 passed, 5 deselected`; `1 passed, 14 deselected`; `1 passed, 14 deselected`; frontend build succeeded
- [x] Overview recency-filter parity checkpoint is green:
  `python -m py_compile forge/reporting/dashboard.py tests/reporting/test_dashboard.py`
  `python -m pytest tests/reporting/test_dashboard.py -q --color=no`
  `python -m pytest tests/integration/test_webui_engagement_api.py -k "engagement_list_and_detail_routes or root" -q --color=no`
  `npm run build`
  Result: `6 passed`; `2 passed, 13 deselected`; frontend build succeeded
- [x] Engagement-tag metadata/filter checkpoint is green:
  `python -m py_compile forge/db/schema.py forge/db/validation.py forge/db/migrations.py forge/reporting/dashboard.py forge/webui/app.py tests/phase1/test_multi_seed_schema.py tests/reporting/test_dashboard.py tests/integration/test_webui_engagement_api.py`
  `python -m pytest tests/phase1/test_multi_seed_schema.py tests/reporting/test_dashboard.py tests/integration/test_webui_engagement_api.py -q --color=no`
  `npm run build`
  Result: `24 passed, 34 warnings`; frontend build succeeded
- [x] Overview date-range filter checkpoint is green:
  `python -m py_compile forge/reporting/dashboard.py tests/reporting/test_dashboard.py`
  `python -m pytest tests/reporting/test_dashboard.py -q --color=no`
  `python -m pytest tests/integration/test_webui_engagement_api.py -k "engagement_list_and_detail_routes or root or engagement_create_and_seed_crud_routes" -q --color=no`
  `npm run build`
  Result: `6 passed`; `3 passed, 12 deselected, 15 warnings`; frontend build succeeded
- [x] Detail-route engagement-metadata editor checkpoint is green:
  `python -m pytest tests/integration/test_webui_engagement_api.py -k "engagement_list_and_detail_routes or engagement_create_and_seed_crud_routes" -q --color=no`
  `npm run build`
  Result: `2 passed, 13 deselected, 15 warnings`; frontend build succeeded
- [x] Overview saved-filter persistence checkpoint is green:
  `python -m py_compile forge/reporting/dashboard.py tests/reporting/test_dashboard.py`
  `python -m pytest tests/reporting/test_dashboard.py -q --color=no`
  `python -m pytest tests/integration/test_webui_engagement_api.py -k "engagement_list_and_detail_routes or root or engagement_create_and_seed_crud_routes" -q --color=no`
  `npm run build`
  Result: `6 passed`; `3 passed, 12 deselected, 15 warnings`; frontend build succeeded
- [x] Outlook `.msg` artifact parser checkpoint is green:
  `python -m py_compile forge/engagement_orchestrator.py tests/phase1/test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "extracts_mhtml_findings or extracts_eml_bodies_and_nested_attachments or extracts_emlx_bodies_and_nested_attachments or extracts_mbox_messages_and_nested_attachments or extracts_msg_bodies_and_nested" -q --color=no`
  Result: `6 passed, 112 deselected`
- [x] Remote Outlook `.msg` kill-chain checkpoint is green:
  `python -m py_compile forge/engagement_orchestrator.py tests/phase1/test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "extracts_mhtml_findings or extracts_eml_bodies_and_nested_attachments or extracts_emlx_bodies_and_nested_attachments or extracts_mbox_messages_and_nested_attachments or extracts_msg_bodies_and_nested or html_remote_artifact_drives_validation_findings_and_second_iteration_email_fanout or html_remote_artifact_mixed_key_validation_builds_graph_family_and_template_report or html_remote_msg_artifact_builds_validation_graph_and_template_report" -q --color=no`
  Result: `9 passed, 110 deselected`
- [x] Android App Bundle (`.aab`) mobile-artifact checkpoint is green:
  `python -m py_compile forge/engagement_orchestrator.py forge/cli.py forge/phase4/mobile_config_parse.py tests/phase1/test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "android_app_bundle_findings or html_remote_aab_bundle_drives_validation_findings_and_second_iteration_email_fanout" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "extracts_nested_mobile_configs_from_apkm_bundle or html_remote_mobile_bundle_drives_validation_findings_and_second_iteration_email_fanout or html_remote_apkm_bundle_drives_validation_findings_and_second_iteration_email_fanout or html_remote_aab_bundle_drives_validation_findings_and_second_iteration_email_fanout" -q --color=no`
  Result: `2 passed, 119 deselected`; `4 passed, 117 deselected`
- [x] Archive-style mobile bundle seed checkpoint is green:
  `python -m py_compile forge/engagement_orchestrator.py forge/cli.py tests/phase1/test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "classify_seed_value_recognizes_archive_style_mobile_bundle_urls or kill_chain_html_remote_mobile_bundle_drives_validation_findings_and_second_iteration_email_fanout or kill_chain_dry_run_queues_seed_mobile_bundle_urls_and_processes_remote_xapk or kill_chain_dry_run_queues_seed_mobile_bundle_urls_and_processes_remote_apkm" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "html_remote_aab_bundle_drives_validation_findings_and_second_iteration_email_fanout or android_app_bundle_findings" -q --color=no`
  Result: `4 passed, 118 deselected`; `2 passed, 120 deselected`
- [x] Nested archive-style mobile bundle checkpoint is green:
  `python -m py_compile forge/engagement_orchestrator.py tests/phase1/test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "nested_archive_style_mobile_bundle_from_outer_archive or html_remote_archive_with_nested_mobile_bundle_drives_validation_findings_and_second_iteration_email_fanout or html_remote_mobile_bundle_drives_validation_findings_and_second_iteration_email_fanout or kill_chain_dry_run_queues_seed_mobile_bundle_urls_and_processes_remote_xapk or kill_chain_dry_run_queues_seed_mobile_bundle_urls_and_processes_remote_apkm or android_app_bundle_findings" -q --color=no`
  Result: `6 passed, 118 deselected`
- [x] Standalone archive-style mobile extractor checkpoint is green:
  `python -m py_compile forge/phase4/mobile_config_parse.py forge/cli.py tests/phase4/test_firebase_extract.py tests/phase1/test_engagement_orchestrator.py`
  `python -m pytest tests/phase4/test_firebase_extract.py -k "archive_style_android_bundle or extracts_project_id or extract_supabase_apk" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "parallel_batches_detected_prereqs_when_auto_run_enabled or android_app_bundle_findings or html_remote_mobile_bundle_drives_validation_findings_and_second_iteration_email_fanout or dry_run_queues_seed_mobile_bundle_urls_and_processes_remote_apkm" -q --color=no`
  Result: `5 passed, 22 deselected`; `4 passed, 120 deselected`
- [x] Standalone mobile Supabase persistence checkpoint is green:
  `python -m py_compile forge/phase4/mobile_config_parse.py forge/cli.py tests/phase4/test_firebase_extract.py`
  `python -m pytest tests/phase4/test_firebase_extract.py -k "store_supabase_configs or emit_mobile_config_json or archive_style_android_bundle or cloud_firebase_extract_cli_persists_supabase" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "parallel_batches_detected_prereqs_when_auto_run_enabled" -q --color=no`
  Result: `5 passed, 25 deselected`; `1 passed, 123 deselected`
- [x] Live mobile-bundle parity checkpoint is green:
  `python -m py_compile forge/webui/app.py forge/phase4/api_policy_check.py tests/integration/test_webui_engagement_api.py tests/phase4/test_supabase_scanner.py`
  `python -m pytest tests/integration/test_webui_engagement_api.py -q --color=no`
  `python -m pytest tests/phase4/test_supabase_scanner.py -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "classify_seed_value_recognizes_archive_style_mobile_bundle_urls" -q --color=no`
  Result: `15 passed, 35 warnings`; `38 passed`; `1 passed, 123 deselected`
- [x] Report companion-export/raw-export CSV parity checkpoint is green:
  `python -m py_compile forge/reporting/dashboard.py forge/webui/app.py tests/reporting/test_dashboard.py tests/integration/test_webui_engagement_api.py`
  `python -m pytest tests/reporting/test_dashboard.py tests/integration/test_webui_engagement_api.py -q --color=no`
  `npm run build`
  Result: `23 passed, 37 warnings`; frontend build succeeded
- [x] Latest-report-family/report-history checkpoint is green:
  `python -m py_compile forge/reporting/dashboard.py forge/webui/app.py tests/reporting/test_dashboard.py tests/integration/test_webui_engagement_api.py`
  `python -m pytest tests/reporting/test_dashboard.py tests/integration/test_webui_engagement_api.py -q --color=no`
  `npm run build`
  Result: `25 passed, 39 warnings`; frontend build succeeded
- [x] Broader ODF artifact-suite checkpoint is green:
  `python -m py_compile tests/phase1/test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "extracts_opendocument_findings or extracts_opendocument_spreadsheet_and_presentation_findings" -q --color=no`
  Result: `2 passed, 123 deselected`
- [x] Local ODF kill-chain graph/report checkpoint is green:
  `python -m py_compile tests/phase1/test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "local_opendocument_artifacts_feed_validation_graph_and_template_report" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "extracts_opendocument_findings or extracts_opendocument_spreadsheet_and_presentation_findings or local_opendocument_artifacts_feed_validation_graph_and_template_report" -q --color=no`
  `python -m pytest tests/phase4/test_cloud_validate.py -k "marks_public_supabase_rest_data_validated_without_secret or does_not_treat_supabase_settings_metadata_as_validated_access" -q --color=no`
  Result: `1 passed, 125 deselected`; `3 passed, 123 deselected`; `2 passed, 57 deselected`
- [x] Bounded-parallel mailbox artifact checkpoint is green:
  `python -m py_compile forge/engagement_orchestrator.py tests/phase1/test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "parallelizes_mbox_messages_and_preserves_order or extracts_mbox_messages_and_nested_attachments" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "extracts_mhtml_findings or extracts_eml_bodies_and_nested_attachments or extracts_emlx_bodies_and_nested_attachments or extracts_mbox_messages_and_nested_attachments or parallelizes_mbox_messages_and_preserves_order or extracts_msg_bodies_and_nested_attachments" -q --color=no`
  Result: `2 passed, 125 deselected`; `6 passed, 121 deselected`
- [x] Bounded-parallel zip/tar archive-member checkpoint is green:
  `python -m py_compile forge/engagement_orchestrator.py tests/phase1/test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "parallelizes_zip_member_payload_extraction_and_preserves_order or parallelizes_tar_member_payload_extraction_and_preserves_order or parallelizes_mbox_messages_and_preserves_order" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "extracts_document_and_archive_findings or extracts_zip_backed_bundle_archives or extracts_bzip2_txz_and_buried_xz_artifacts or parallelizes_zip_member_payload_extraction_and_preserves_order or parallelizes_tar_member_payload_extraction_and_preserves_order" -q --color=no`
  Result: `3 passed, 126 deselected`; `5 passed, 124 deselected`
- [x] Bounded-parallel nested mobile-member archive checkpoint is green:
  `python -m py_compile forge/engagement_orchestrator.py tests/phase1/test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "parallelizes_nested_zip_mobile_member_extraction_and_preserves_order or parallelizes_nested_tar_mobile_member_extraction_and_preserves_order or extracts_nested_mobile_configs_from_archive_bundles or extracts_nested_archive_style_mobile_bundle_from_outer_archive" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "parallelizes_nested_zip_mobile_member_extraction_and_preserves_order or parallelizes_nested_tar_mobile_member_extraction_and_preserves_order or parallelizes_zip_member_payload_extraction_and_preserves_order or parallelizes_tar_member_payload_extraction_and_preserves_order or extracts_nested_mobile_configs_from_apkm_bundle" -q --color=no`
  Result: `4 passed, 127 deselected`; `5 passed, 126 deselected`
- [x] Bounded-parallel payload cloud-config extraction checkpoint is green:
  `python -m py_compile forge/engagement_orchestrator.py tests/phase1/test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "parallelizes_payload_cloud_config_extraction_and_preserves_order or extracts_document_and_archive_findings or extracts_zip_backed_bundle_archives or extracts_nested_mobile_configs_from_archive_bundles or extracts_nested_archive_style_mobile_bundle_from_outer_archive" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "parallelizes_payload_cloud_config_extraction_and_preserves_order or parallelizes_nested_zip_mobile_member_extraction_and_preserves_order or parallelizes_nested_tar_mobile_member_extraction_and_preserves_order or extracts_nested_mobile_configs_from_apkm_bundle" -q --color=no`
  Result: `5 passed, 127 deselected`; `4 passed, 128 deselected`
- [x] Bounded-parallel payload text-discovery collection checkpoint is green:
  `python -m py_compile forge/engagement_orchestrator.py tests/phase1/test_engagement_orchestrator.py`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py -k "parallelizes_payload_text_discovery_collection_and_preserves_order or extracts_document_and_archive_findings or extracts_script_and_infra_config_artifacts or extracts_structured_yaml_cloud_assets or decodes_yaml_secret_data_env_maps" -q --color=no`
  `python -m pytest tests/phase1/test_engagement_orchestrator.py tests/integration/test_engagement_pipeline.py -k "parallelizes_payload_text_discovery_collection_and_preserves_order or local_generic_secret_artifacts_feed_mixed_key_validation or local_yaml_secret_artifacts_feed_validation_and_email_fanout or mixes_key_validators_cloud_asset_and_template_fallback" -q --color=no`
  Result: `5 passed, 128 deselected`; `4 passed, 138 deselected`

## Newly completed

- [x] Backlog-aware kill-chain convergence is complete: `kill_chain()` now requires both an unchanged row-count snapshot and zero pending recursive work before declaring the spider stable. The guard covers capped URL, email, social-handle, GitHub-org, username, phone, IP, name, company, cloud-ref, artifact-queue, and cloud-asset validation backlogs, and stores compact `pending_work_counts` / `pending_work_total` metadata only when the snapshot is otherwise stable. Final metadata also refreshes pending backlog before `finish_run()` so max-iteration exhaustion is visible to the dashboard/API. Discovered GitHub-org keyscan targets now use schema-allowed `cross_reference` seed source with `origin=keyscan_target` in seed-run metadata. Green evidence: compile, Ruff, focused capped-email drain/exhaustion plus keyscan-source regressions (`3 passed`), representative kill-chain slice (`3 passed`), and combined graph/report/cloud regression suite (`198 passed`). Review: Claude diff-only review reported no blockers and its efficiency suggestion was applied; GPT sidecar reviewer later found max-iteration metadata/log gaps, and those were fixed. Safety: orchestration/metadata only; no live probing expansion, provider call expansion, credential use, scope relaxation, proxy/IP rotation, rate-limit bypass, destructive behavior, report-gate weakening, or post-exploitation behavior was added. Handoff: `.claude/handoffs/2026-07-19-235500-backlog-aware-convergence.md`.
- [x] Epieos root-container identity recursion is stronger now too: root-level `profiles`, `accounts`, `results`, `data`, and related account/profile containers now flatten into the existing provider-specific profile parser, so array-shaped Epieos/public identity payloads can produce recursive GitHub/LinkedIn/Hacker News/GitLab profile rows instead of being skipped. This does not change live Epieos request behavior, pacing, proxy handling, provider calls, scope gates, Sherlock dispatch caps, report gates, or probing. Green evidence: compile, Ruff, focused parser slice (`51 passed`), full social scraper suite (`68 passed`), engagement social-profile recursion slice (`103 passed`), and full Phase 2 (`689 passed in 167.76s`).
- [x] Phase 2 validator-fixture drift is fixed: hardened proof validators were already correct, but stale tests used sequential placeholder GitHub/Slack IDs that now properly stay `UNCONFIRMED`. Fixtures now use stable non-placeholder GitHub and Slack IDs; no production validator was weakened. Green evidence: `py_compile tests/phase2/test_key_scanner.py`, Ruff on `tests/phase2/test_key_scanner.py`, focused GitHub/Slack validator slice (`13 passed`), and full `tests/phase2` (`688 passed in 180.71s`).
- [x] urlscan/provider URL recursion is safer and broader now too: urlscan search results now preserve submitted `task.url` as a recursive URL candidate in addition to `page.url`, provider URL persistence supports page/task/observed URL roles, and the shared provider URL normalizer strips URL userinfo plus sensitive query parameters before writing crawl rows or engagement seeds. This does not call urlscan `/result`, add endpoints, increase request volume, probe targets, authenticate, rotate IPs, bypass rate limits, relax scope, or change report gates. Compile, Ruff, focused Shodan/urlscan persistence regressions, and full passive-host persistence module are green.
- [x] Shodan live-provider recursion is stronger now too: host-detail persistence now promotes in-scope service-level `http.host`, service hostname/domain fields, TLS/SNI names, certificate subject CN, and certificate SAN/DNS names into recursive URL seeds for the existing D5 URL-surface mining stage. This does not add Shodan endpoints, increase request volume, probe targets, authenticate, rotate IPs, bypass rate limits, relax scope, or change report gates. Compile, Ruff, focused Shodan persistence regressions, and full passive-host Shodan/urlscan persistence module are green.
- [x] Search/recon provider export passive-recursion is broader now too: local static urlscan/Shodan/Censys/Fofa/ZoomEye/SecurityTrails/BinaryEdge/BuiltWith/crt.sh/LeakIX/Netlas/Criminal IP exports now keep source-aware labels, common provider result containers feed sanitized recursive URL seeds/contact pivots/cloud refs, and bare email-looking row values no longer become misleading auth-style URL seeds. This is passive import only; it does not run provider queries, contact providers, probe targets, authenticate, rotate IPs, bypass rate limits, relax scope, or change report gates. Compile, Ruff, focused provider-export/recon-label regression, and adjacent passive-output/recon/DNS/CMS/tech-WAF-TLS/imported-scanner/screenshot/SARIF/SBOM slice are green.
- [x] Added one self-contained engagement-pipeline fixture proving artifact-discovered AWS, Slack, Mailchimp, and Azure keys plus a discovered Firebase asset can flow through artifact intake, direct cloud validation, pending key validation, deterministic findings, and `provider=auto` -> template fallback.
- [x] Hardened attack-graph finalization so missing optional evidence tables do not break live engagement closeout, and snapshot writes recreate the schema they need before persisting `attack_graph_snapshots`.
- [x] Fixed the graph export edge CSV so the `Relation` column is populated from the real edge label/type instead of silently exporting blank relations.
- [x] Hardened graph node rendering for long cloud/key identifiers so engagement closeout no longer crashes when validated non-cloud credential rows persist path-like identifiers into `cloud_assets`.
- [x] Added one live `kill_chain()` regression proving HTML discovery -> URL-surface mining -> Firebase validation -> graph family (`json` / `graphml` / `mtgx` / CSV) -> template report in one engagement-backed run.
- [x] Added one deeper live `kill_chain()` regression proving homepage HTML -> discovered page -> remote APK intake -> Firebase/Supabase validation -> second-iteration email fanout -> graph family -> template report in one engagement-backed run.
- [x] Added one deeper mixed-provider live `kill_chain()` regression proving homepage HTML -> discovered page -> remote APK intake -> Firebase/Supabase plus AWS/Slack/Mailchimp/Azure validation -> second-iteration email fanout -> graph family -> template report in one engagement-backed run.
- [x] Added one deeper combined-source live `kill_chain()` regression proving one engagement can ingest a local artifact root plus a homepage-discovered remote APK, validate local Firebase plus remote Firebase/Supabase plus AWS/Slack/Mailchimp/Azure key material, recurse discovered emails/URLs, and still emit the graph family plus deterministic template report in the same run.
- [x] Added one larger mixed-artifact live `kill_chain()` regression proving a single engagement can ingest two local artifacts plus two homepage-discovered remote APKs, validate four Firebase assets plus two Supabase projects plus AWS/Slack/Mailchimp/Azure evidence, recurse the discovered email/url pivots, and still emit the graph family plus deterministic template report in one run.
- [x] Hardened passive HTTP collection for tiny engagement-backed target sets so one or two in-scope URLs run deterministically in order, while larger target sets still fan out through the bounded worker pool.
- [x] Run-progress telemetry is more useful now too: engagement metadata and the live progress API now carry a cumulative `queue_metrics.artifact_processor_cumulative` block so mixed local+remote artifact runs expose total queued local intake, processing passes, processed items, skips/failures, cloud-config hits, and discovered seed counts without losing the existing per-stage snapshot.
- [x] `kill_chain --auto-run-detected` is real again now: the CLI flag is exposed in help, the unreachable hardcoded-off path is gone, and explicit auto mode batches runnable detected follow-on modules through the bounded executor instead of running them one-by-one.
- [x] Validator-backed non-cloud evidence is more analyst-usable now: when a deterministic key validator proves a better service identifier, the pending sweep persists that identifier instead of a weak source filename. AWS rows now keep the validated `AccountId`, Twilio rows keep the real SID, GitHub PAT rows keep the validated login, and the GitHub pending-sweep path now has explicit regression coverage.
- [x] Re-verified the mixed-provider kill-chain slice, focused cloud-validation slice, and focused report-fallback slice against that new integration fixture.
- [x] Report fallback/export auditability is better now too: engagement detail payloads from both the static dashboard generator and the live web API now surface companion report metadata such as requested provider, rendered backend, exported backend, fallback reason, checksum, and raw-export status, and the React report panel now shows that render path instead of burying it inside the JSON artifact only.
- [x] Dashboard overview filtering is more operator-usable now too: the generated static dashboard and the live React overview both expose real status, severity, and recency window filters, and the static dashboard contract test now asserts those controls plus row-level recency/finding metadata.
- [x] Engagement metadata is less underpowered now too: the canonical schema and migrations now include engagement-level `metadata_json`, the live API and static dashboard payloads expose normalized `tags`, the overview routes can filter by tags, and live engagement creation/update flows can persist tags instead of forcing that context into names or scope entries.
- [x] Overview quick-filter parity is stronger now too: both dashboard modes now support an explicit updated-date range in addition to status, severity, tag, and recency filtering, and the live React overview now uses one shared activity timestamp path for filter/sort/footer behavior.
- [x] The detail-route metadata editor is less lossy now too: operators can edit engagement tags from the live detail route, and the local draft for name/status/operator/tags is no longer reinitialized on every live snapshot refresh while the user is typing.
- [x] Overview operator-state continuity is better now too: both the static dashboard and the live React overview now persist search plus status/severity/tag/date/recency filters across reloads through the shared `forge.overviewFilters` local-storage key.
- [x] Outlook mail-artifact coverage is stronger now too: `.msg` files and nested `.msg` members no longer rely only on generic OLE string scraping, and now emit message metadata, body/html payloads, and attachment-derived pivots through the automated artifact queue.
- [x] The live kill-chain is broader now too: HTML-discovered remote `.msg` evidence can now flow through remote artifact intake, message-aware parsing, deterministic Firebase/Supabase validation, second-iteration email fanout, graph export, dashboard refresh, and template report generation in one engagement-backed run.
- [x] Android App Bundles are first-class mobile artifacts now too: top-level `.aab` files classify through the same mobile static-analysis path as APKs, archive-contained `.aab` members reuse the same nested mobile extraction path, direct/operator `.aab` URLs normalize as `apk_url`, and one live engagement-backed regression now proves `homepage HTML -> remote .aab queue -> Firebase/Supabase validation -> iteration-2 email fanout -> graph/report closeout`.
- [x] Archive-style mobile bundle URLs are first-class mobile seeds now too: direct and discovered `.xapk`, `.apkm`, and `.apks` URLs now normalize as `apk_url`, still route through the archive-backed nested-mobile parser instead of the direct APK extractor, legacy `url` rows still preserve artifact provenance links, and the live HTML `.xapk` regression now asserts the discovered seed is stored as `apk_url`.
- [x] Nested archive-style mobile bundles are broader now too: larger outer archives such as `.zip` can now recurse into embedded `.xapk/.apkm/.apks` members, extract the inner APK Firebase/Supabase configs plus email/URL pivots, and the live engagement path now proves `homepage HTML -> remote .zip queue -> nested .xapk parse -> validation -> iteration-2 email fanout`.
- [x] The standalone mobile extractor path is aligned now too: `forge cloud firebase-extract --apk ...` and the local auto-detected `cloud firebase-extract` prereq now support archive-style Android bundles such as `.xapk/.apkm/.apks`, recursively extracting nested Firebase and Supabase config from inner APK members instead of lagging behind the engagement pipeline.
- [x] The standalone command now persists Supabase evidence too: `cloud firebase-extract` no longer stops at Firebase-only console output for mobile bundles, and when an engagement DB is present it now stores Supabase project refs in `cloud_assets`, redacted `supabase_mobile_config` rows in `key_scanner_findings`, and combined Firebase+Supabase JSON output for operator workflows.
- [x] The live web/API seed path is aligned with the orchestrator now too: engagement creation and live seed CRUD no longer misclassify `.aab`, `.xapk`, `.apkm`, or `.apks` URLs as generic `url` seeds, and now auto-detect them as `apk_url` the same way the CLI/orchestrator already do.
- [x] The Supabase mobile key path is aligned now too: the Phase 4 Supabase scanner no longer limits mobile anon-key recovery to `.apk` / `.ipa` rows, and now also consumes `.aab`, `.xapk`, `.apkm`, and `.apks` evidence persisted by the artifact/mobile extraction pipeline.
- [x] Report-family visibility is tighter now too: the dashboard generator and live API both include `.csv` raw-export artifacts, `report_summary` now exposes `available_exports` plus `export_count`, and the React detail/export UI now labels/report companion artifacts correctly instead of hiding raw CSV fallback behind a single JSON file.
- [x] Multi-generation report handling is tighter now too: the newest report family now drives `report_summary`, previews, and export links, older families are preserved as ordered `report_history`, and the static dashboard no longer mislabels report `.json`/`.csv` artifacts as graph artifacts.
- [x] OpenDocument verification is broader now too: in addition to the older `.odt` proof point, focused artifact-queue regressions now prove `.ods` and `.odp` containers surface emails, URLs, and cloud references into the deterministic seed/cloud path.
- [x] OpenDocument verification is engagement-backed now too: one live local-artifact `kill_chain()` regression now proves `.ods` plus `.odp` artifacts can survive deterministic cloud validation, recursive email seed runs, attack-graph export/snapshot closeout, and template report generation in one engagement-backed run.
- [x] Mail-container parsing is less serialized now too: `.mbox` artifact extraction still preserves message ordering and meta-first payload layout, but the per-message extraction stage now uses the bounded worker pool instead of processing each mailbox entry serially.
- [x] Archive/container parsing is less serialized now too: zip/tar member payload extraction now uses the bounded worker pool while preserving original member order, so larger nested archives no longer serialize their post-read payload parsing.
- [x] Nested mobile bundle extraction is less serialized now too: outer archive members containing `.apk` / `.ipa` / `.aab` / `.xapk` / `.apkm` / `.apks` now use the bounded worker pool while preserving original member order, so mobile static-analysis pivots inside larger archive drops no longer serialize member-by-member.
- [x] Payload-level cloud-config extraction is less serialized now too: once artifact/mobile text payloads are extracted, Firebase plus Supabase static extraction now uses the bounded worker pool while preserving payload order, so larger text-heavy artifacts and mobile bundles no longer bottleneck on per-payload config scanning.
- [x] Payload-level text discovery collection is less serialized now too: once artifact/mobile text payloads are extracted, generic discovery precomputation for emails, phones, URLs, cloud refs, and key evidence now uses the bounded worker pool while preserving payload order, so larger config-heavy artifacts no longer bottleneck on per-payload regex/context extraction before deterministic persistence.
- [x] Google/Gemini API key validation is covered now: `google_api_key` maps to the shared `GoogleApiKeyValidator`, and the legacy Phase 2 scanner can instantiate it. Read-only Gemini model-list success now stays as `UNVERIFIED` validation inventory only; it does not create deterministic findings or report content because model catalogs are not account/project-bound identity proof.
- [x] OpenAI, Anthropic, and Google/Gemini model-list-only proofs are downgraded at report gates now: Phase 4 stores them as unverified validation inventory, shared proof parsing rejects them as reportable, Phase 6 excludes stale key-exposure rows, and the mixed-key kill-chain E2E confirms they stay out of APIKEY graph nodes.
- [x] GitLab PAT validation is covered now: `gitlab_pat` maps to the shared `GitlabPatValidator`, the legacy Phase 2 duplicate pattern file uses it, and Phase 4 pending sweeps persist only a sanitized username after the read-only current-user API confirms the token works. Non-200 responses remain unconfirmed.
- [x] Legacy scanner Slack drift is fixed now: the duplicate Phase 2 pattern file marks Slack bot/user tokens as validatable through the shared `SlackTokenValidator` and uses the same token-width tolerance as the canonical pattern file.
- [x] Generic config/text artifacts no longer silently drop key evidence when encryption is unavailable: missing `FORGE_ENGAGEMENT_KEY` now yields redacted `UNCONFIRMED` key rows with `key_enc=NULL` and an explicit validation prerequisite instead of losing the scanner output.
- [x] Engagement creation now uses a shared monotonic SQLite sequence in `.forge_data/engagements/master.db` for both API/dashboard creation and CLI `kill-chain` auto-ID creation; API/dashboard enumeration skips `master.db`, and regressions prove deleting a just-created engagement DB does not cause ID reuse.
- [x] The combined local+remote artifact/social-recursion/auto-template fallback kill-chain path is already covered and green, but slow: the main combined fixture passed in 188.76s, and the second-hop multiple-remote-APK fixture passed in 163.43s. Both are now marked `slow`.
- [x] Social-profile URL/host pivot enrichment now uses the bounded ordered worker-pool path inside `_social_profile_pivot_family()` instead of serial per-entry loops. Ordering and output semantics are preserved for stored profile URL/host recursion. Verification: compile/Ruff for `forge/engagement_orchestrator.py` and focused social-profile pivot tests (`11 passed, 773 deselected`). Commit: `655ad36 perf(identity): batch social profile pivot entries`.
- [x] Attack graph cloud resources are now keyed by `(asset_type, identifier)` instead of identifier alone, so same-name resources from different providers do not collapse into one CLOUD node or misroute validation/finding edges. Verification: compile/Ruff for `forge/phase4/attack_path.py` and focused cloud graph tests (`6 passed, 100 deselected`). Commit: `317817a fix(phase4): key cloud graph nodes by asset type`.
- [x] Phase 6 deterministic cloud-exposure report gate is complete: stale `DETERMINISTIC_CLOUD_EXPOSURE` findings are excluded from report context, markdown, JSON, forced raw JSON, and raw CSV unless the latest matching cloud validation status is `VALIDATED`. Validation-result ordering now follows the graph/dashboard latest-row convention. Verification: compile/Ruff and Phase 6 report suites (`75 passed`). Commit: `b0e44f2 fix(reporting): gate cloud exposure exports`.
- [x] Phase 4 deterministic cloud-exposure graph gate is complete: stale `DETERMINISTIC_CLOUD_EXPOSURE` rows no longer create VULN graph nodes unless the latest matching cloud validation status is `VALIDATED`; underlying CLOUD nodes remain visible with latest validation metadata for analyst review. Verification: compile/Ruff and combined graph/report suites (`182 passed`).
- [x] Cloud validation auditability is stronger: Phase 4 CLOUD nodes and Phase 6 JSON/CSV exports now carry scrubbed latest validation notes/evidence summaries, and Phase 6 emits non-finding `cloud_validation` inventory rows so unsupported/dead/suspect assets remain reviewable without entering findings. Verification: compile/Ruff, focused inventory slice (`3 passed, 105 deselected`), and combined graph/report suites (`182 passed`).
- [x] Shared cloud-exposure gate and validation sanitizer are in place: Phase 4 graph and Phase 6 report paths use one deterministic cloud-exposure helper, and validation notes/evidence summaries use one stronger sanitizer for credential assignments, presigned URL params, cookies, authorization headers, JWTs, AWS key IDs, and long token-shaped strings. Verification: compile/Ruff and helper/graph/report suites (`192 passed`).
- [x] Compact mocked kill-chain/report/dashboard smoke is now covered in
  `tests/phase1/test_kill_chain_dashboard_smoke.py`: one mocked `kill_chain()`
  run proves homepage HTML -> remote APK -> static Firebase/Supabase/key
  extraction -> recursive email/URL seeds -> Firebase/Supabase/AWS/Slack/Azure
  validated inventory plus Mailchimp `UNVERIFIED` inventory -> graph metadata ->
  `provider=auto` deterministic template fallback -> dashboard detail JSON
  review surface. Verification: compile/Ruff, focused smoke (`1 passed in
  27.46s` with `-m "slow or not slow"`), dashboard validation selector (`5
  passed, 22 deselected`), Phase 6 fallback/proof/raw-export selector (`20
  passed, 84 deselected`), and workspace `.forge_data/engagements` count `0`.
  Handoff: `.claude/handoffs/2026-07-24-compact-kill-chain-dashboard-smoke.md`.
- [x] Scheduled scope-denial reviewability is now covered in dashboard/API:
  `sections.scope_denials` keeps old `scheduled_task_scope_denied` rows visible
  even after they fall out of the recent audit timeline, without exposing raw
  distributed-task `scope_manifest` payloads. Verification: focused static/API
  tests (`2 passed`), Python ruff, frontend lint/build, and `git diff --check`.
  Handoff:
  `.claude/handoffs/2026-07-24-scheduled-scope-denial-review.md`.
- [x] `forge doctor` is now the operator-ready setup path rather than a small
  dependency smoke check inside `forge/cli.py`. Readiness logic lives in
  `forge.doctor`, stays testable without Typer, and reports free/local baseline
  coverage, ProjectDiscovery/secrets CLI availability, KB/data-dir state, web
  auth posture, optional paid/keyed providers, paid backend gating, active
  validation live-gate posture, monitoring schedule state, remediation
  ticket-event ledger shape, remediation review-queue attention, and static LLM
  provider readiness without reading `.env` or printing secret values. The
  remediation review-queue check reports aggregate unowned/missing-ticket/SLA/
  accepted-risk/retest counts only, not item titles, ticket URLs, or metadata.
  Live LLM provider HTTP/model-list
  probes are disabled by default and require `forge doctor
  --live-provider-probes` or `FORGE_DOCTOR_LIVE_PROVIDER_PROBES=1`.
  `forge doctor --json` now emits
  `forge.doctor.v1` machine-readable checks with status counts and remediation
  hints for missing free/local tools, setup gaps, connector catalog readiness,
  and provider readiness. Verification: py_compile, Ruff, focused
  doctor/connectors plus hardening tests, and a real
  `python -m forge.cli doctor` render.
- [x] `forge demo proof-pack` now generates a repeatable local/no-key proof
  engagement from production code instead of relying on test-only fixtures. The
  generated pack includes the engagement DB, sanitized local artifact fixture,
  monitoring snapshots/diffs/alerts/trends, remediation owner/SLA/retest rows,
  secret lifecycle routing from a redacted key finding, standards-enriched
  vulnerability metadata, offline active-validation dry-run/lab evidence,
  synced asset graph entities/relationships/ownership, graph exports, template
  report family, local STIX/TAXII standards exchange artifacts, isolated static
  dashboard, audit manifest bundle, and JSON proof manifest. Latest update:
  the proof manifest now carries `proof_assertions` for continuous monitoring,
  asset graph, remediation workflow, active validation, secrets lifecycle,
  standards exchange, dashboard evidence, audit bundle coverage, and
  free-local/no-secret safety. The focused regression inspects graph JSON,
  monitoring/remediation/active-validation/secret lifecycle DB rows, STIX/TAXII
  CVSS v4.0/EPSS/KEV/CWE/CPE/ATT&CK/CVE markers, dashboard provenance, and the
  run audit manifest artifact list. Demo run metadata now feeds explicit
  dashboard and standards artifact paths into the audit manifest so those files
  are covered by the verified bundle. Verification: py_compile, Ruff, focused
  demo generator plus CLI tests (`3 passed`), and a real temp CLI generation
  run.
- [x] Generated static dashboard detail JSON/HTML now includes an
  `evidence_provenance` section before the raw evidence tables. It summarizes
  artifact/crawl, cloud validation, cloud assets, reportable findings, secrets,
  monitoring, remediation, active validation, and asset graph rows into a
  records/tables/provenance/validation/reportability/workflow matrix using
  already-sanitized section rows. Verification: py_compile/Ruff for
  `forge/reporting/dashboard.py` and `tests/reporting/test_dashboard.py`; the
  focused monitoring/review dashboard regression passed (`1 passed`, slow
  fixture around 179s).
- [x] Attack graph export is no longer trapped inside the CLI command.
  `forge.graph.export.export_attack_graph` now owns JSON, Mermaid, DOT,
  GraphML, MTGX, node CSV, edge CSV, and optional snapshot writing, returning a
  typed `AttackGraphExportResult`. `forge graph build` delegates to the service,
  and demo proof-pack generation calls it directly with the known DB path.
  Verification: py_compile, Ruff, focused export service tests (`3 passed`),
  and existing phase4 GraphML/MTGX CLI artifact regressions (`2 passed, 110
  deselected`).
- [x] Run tracking is no longer embedded in `forge.engagement_orchestrator`.
  `forge.orchestration.run_tracking` now owns `SeedRunHandle`,
  `EngagementRunHandle`, `SeedRunTracker`, and `EngagementRunTracker`, while
  legacy orchestrator imports remain compatible. Verification: py_compile,
  Ruff, direct-module/import-compatibility plus audit-manifest tests (`21
  passed`), and focused phase1 tracker regressions (`4 passed, 779
  deselected`).
- [x] Module seed-run finalization payload handling is no longer fully inline
  in `forge.cli`: `forge.orchestration.run_tracking` now owns
  `seed_run_finalization_entry()` and `apply_seed_run_finalization_entry()`.
  The CLI keeps thin compatibility wrappers so existing D5/G/H/I and generic
  module-finalization branches preserve their callable shape, batching labels,
  and ordered apply behavior. Verification: direct run-tracking tests passed
  (`4 passed`), exact dry-run and success/failure finalization regressions
  passed, and compile/Ruff passed for touched Python files.
- [x] Seed-promotion persistence is no longer embedded in
  `forge.engagement_orchestrator`. `forge.orchestration.synthesis` now owns
  `SeedCandidate`, `SynthesisSummary`, seed source priority, metadata merge,
  email seed mirroring, seed upsert, and seed relation insertion. The synthesis
  engine delegates those mutations while retaining legacy imports and candidate
  derivation in place. Verification: py_compile, Ruff, direct synthesis module
  tests (`3 passed`), synthesis-stage rule tests (`36 passed`), and exact
  phase1 synthesis integration tests (`5 passed`). The broad phase1 synthesis
  selector timed out after 5 minutes.
- [x] K2 artifact queue candidate persistence is no longer inline in
  `forge.cli`: `forge.orchestration.artifacts` now owns
  `artifact_queue_candidate_entry()` for de-dupe/apply and
  `queue_artifact_candidate()` for DB insert/duplicate/halt handling. The CLI
  still injects its crawl-result seed-upsert policy, preserving mobile-bundle
  `apk_url` promotion and existing queue-total halt semantics. Verification:
  py_compile and Ruff for touched Python files; focused artifact queue helper
  selector passed (`6 passed, 112 deselected`).
- [x] React dashboard operational timeline is now wired: the detail route
  renders a merged event stream for audit events, monitoring trends, asset
  changes, alerts, reportable findings, cloud/key validation inventory,
  active-validation runs, remediation updates, and report history. Event chips
  show provenance, validation method, and reportable/non-reportable state, and
  React-side redaction protects active-run errors, graph metadata values,
  timeline fields, and raw detail JSON preview. Verification:
  `python -m pytest tests\reporting\test_webui_contract.py -q --color=no` ->
  `9 passed`; `npm run build` in `forge/reporting/webui` passed.
- [x] Static dashboard operational timeline parity is now wired too: generated
  detail JSON includes `operational_timeline`, and static engagement HTML renders
  the merged audit/monitoring/validation/finding/remediation/report timeline with
  source, status, severity, method, and reportability chips using sanitized
  dashboard section rows.
- [x] Target-feed canonical multi-seed import is wired: `forge targets import`
  accepts canonical seed types beyond `domain`/`url`, including `subdomain`,
  `apk_url`, `email`, `phone`, `username`, `name`, `company`, `ipv4`, `ipv6`,
  and `cloud_ref`, plus common feed aliases such as `auto`, `artifact_url`,
  `host`, `ip`, `handle`, `telephone`, `person`, and `organization`. Provider
  URLs and literal S3/GCS/Azure-style refs canonicalize as `cloud_ref`,
  duplicate literal forms dedupe, and generated passive-start manifests preserve
  exact `authorized_seeds` plus exact IP ranges. Imported engagements also get
  the default `Target import seed exposure` passive monitoring policy and an
  initial baseline snapshot, making scheduled imports continuous-diff ready.
  Verification: py_compile and Ruff passed for `forge/targets_import.py` and
  `tests/cli/test_targets_import.py`; focused target-import tests passed
  (`9 passed`, sqlite timestamp-converter deprecation warnings only).
- [x] Scheduled TPH feed-reachability diagnostics are wired:
  `scripts/import_tph_targets.ps1` keeps the parent watchdog unchanged but now
  bounds each target-feed probe to the remaining wait budget, logs probe
  attempts, and on timeout reports local TCP reachability plus whether the
  expected TPH `.env` and `docker-compose.yml` files exist. Verification:
  PowerShell parse checks passed for the import wrapper and scheduled-task
  runner; Windows launcher regression tests passed (`12 passed`).
- [x] Scheduled TPH watchdog popup root cause is fixed: the visible
  PowerShell/Python popup came from Task Scheduler task
  `\FORGE Import theprawnhunter Targets`, not Docker or a custom Windows
  service. The launcher no longer sends watchdog Python through inline
  `python -c`, so Task Scheduler/PowerShell quoting cannot strip Python string
  literals and trigger `NameError` on `message = "scheduled ..."`. Files:
  `scripts/run_tph_target_import_task.ps1`,
  `scripts/install_tph_target_import_task.ps1`,
  `tests/core/test_windows_launchers.py`. Verification: launcher tests
  (`12 passed`); parser checks for both launcher scripts; watchdog self-test
  exit `0` with `scheduled import watchdog self-test; quotes preserved`; task is
  `Ready` with no stale watchdog temp files.
- [x] Scheduled TPH target-import downstream unpack failure is fixed:
  `forge.targets_import` now catches item-level normalization `ValueError`
  during feed item coercion and skips the malformed item instead of aborting the
  whole CLI import with Typer's `Invalid value: not enough values to unpack`.
  Verification: target-import CLI tests (`11 passed`); py_compile/Ruff passed
  for `forge/targets_import.py`, `forge/targets_import_cli.py`, and focused
  tests. Let the next scheduled task run verify the operational log is clear.
- [x] TPH target-import doctor readiness is wired: `forge doctor` now reports
  an optional `TPH Target Import Bridge` row, checking script presence, target
  feed URL, TPH `.env`/compose presence, `TPH_MONITOR_KEY` presence, and bounded
  Windows scheduled-task state without reading `.env` secret values or probing
  the API by default. Verification: py_compile/Ruff passed for doctor/test
  files; focused doctor suite passed (`32 passed`).

## Still partial

Status semantics: these unchecked items are candidate/risk notes, not the
canonical active queue. Use `docs/engagement_overhaul_tasklist.md` ->
`## Compact active backlog` for current continuation order.

- [ ] Provider coverage is still selective rather than exhaustive. The strongest deterministic coverage is Firebase, Supabase, S3/GCS/Azure/DO, Google/Gemini API keys, Hugging Face, Discord bot tokens, Telegram bot tokens, Notion tokens, Datadog API keys, GitHub, GitLab, Mailchimp, Stripe, SendGrid, Slack, Azure Storage connection strings, and co-located Twilio/AWS key-pair validation.
- [ ] The engagement detail UI is sectioned, not literally tabbed. Treat that as a polish decision unless product now requires strict tabs.
- [x] MTGX/GraphML analyst-workflow fidelity audit is reconciled in the
  canonical backlog: portable GraphML and MTGX exports carry analyst entity
  hints, deterministic layout, primary values, property JSON, edge typing, and
  critical-path metadata. Future graph work should come from a concrete parity
  gap in the active backlog.
## Best next tasks

- [x] Add append-only remote storage for exported run-manifest bundles only if scoped customer storage is explicitly configured. Implemented as `forge audit manifest-export --remote-store` using `FORGE_AUDIT_BUNDLE_REMOTE_URI` + `FORGE_AUDIT_BUNDLE_REMOTE_SCOPE`, mounted/file URI storage, exclusive-create writes, receipts, doctor readiness, and focused audit/CLI/doctor tests.
- [ ] Broaden engagement-backed end-to-end fixtures beyond the now-verified local+remote+second-hop artifact/social/fallback paths with richer provider matrices and export assertions, without widening live service-validation scope.
- [ ] Keep improving deterministic report/export auditability and overview parity beyond the now-covered degraded fallback lineage: richer aggregate stats, clearer dashboard review of render history, and provider/export parity gaps found by current-code audit.
- [x] Initial report rendering/presentation split landed for report-history,
  report-preview, table, artifact-card, graph-summary, graph-stage,
  audit-timeline, and operational-timeline HTML rendering, with dashboard
  wrappers preserved.
- [x] Extract static overview page composition into
  `forge.reporting.page_composition`, with the dashboard wrapper preserved.
- [x] Extract engagement detail evidence-section ordering/composition into
  `forge.reporting.page_composition`, with the dashboard table-renderer wrapper
  preserved.
- [x] Extract the remaining engagement detail static HTML shell into
  `forge.reporting.page_composition`; dashboard still prepares artifact/report/
  timeline blocks and calls the renderer.
- [x] Extract engagement detail artifact/report block preparation into
  `forge.reporting.engagement_detail_blocks`, with dashboard wrappers preserved.
- [x] Extract engagement detail metadata and seed/scope chip block preparation
  into `forge.reporting.engagement_detail_blocks`, with dashboard wrappers
  preserved.
- [x] Extract engagement detail graph stage/summary block preparation into
  `forge.reporting.engagement_detail_blocks`, with dashboard wrappers preserved.
- [x] Extract engagement detail operational/audit timeline block preparation
  into `forge.reporting.engagement_detail_blocks`, with dashboard wrappers
  preserved.
- [x] Extract overview/index JSON payload assembly into
  `forge.reporting.engagement_payloads`, with dashboard wrapper preserved.
- [x] Extract engagement detail JSON payload assembly into
  `forge.reporting.engagement_payloads`, with dashboard callbacks/wrapper
  preserved.
- [x] Extract dashboard generation orchestration into
  `forge.reporting.dashboard_generation`, including static site path setup,
  route assignment, detail HTML/JSON writes, and overview HTML/index JSON writes.
- [x] Extract engagement enrichment orchestration into
  `forge.reporting.engagement_enrichment`, including engagement DB discovery,
  artifact/graph/audit file enrichment, graph-state loading orchestration,
  report summary/review-count attachment, and audit-manifest annotation payload
  shaping.
- [x] Extract monitoring/distributed-task/retention detail-section row shaping
  into `forge.reporting.detail_section_rows`, with dashboard wrappers and
  sanitizer/formatting callbacks preserved.
- [x] Extract distributed-task, monitoring configuration, and retention
  detail-section DB query assembly into `forge.reporting.detail_section_queries`,
  behind injectable table/fetch helpers and row builders.
- [x] Extract monitoring snapshot, trend, change, and alert history query
  assembly into `forge.reporting.detail_section_queries`.
- [x] Extract remediation item and remediation review-queue query/loading
  assembly into `forge.reporting.detail_section_queries`, preserving legacy
  `remediation_items` tables without `risk_acceptance_expires_at`.
- [x] Extract asset graph entity, relationship, ownership, conflict, attack-path,
  choke-point, and fix-candidate query/loading assembly into
  `forge.reporting.detail_section_queries`.
- [x] Extract active-validation coverage, job, and run section query/loading
  assembly into `forge.reporting.detail_section_queries`.
- [x] Extract recent audit-log and scope-denial section query assembly into
  `forge.reporting.detail_section_queries`.
- [x] Extract engagement seed inventory, seed relation, and seed run query
  assembly into `forge.reporting.detail_section_queries`.
- [x] Extract services, crawl results, social profiles, port scan results,
  passive vulnerabilities, and auth test result query assembly into
  `forge.reporting.detail_section_queries`.
- [x] Extract email-intelligence and account-existence query assembly into
  `forge.reporting.detail_section_queries`.
- [x] Extract artifact queue query assembly into
  `forge.reporting.detail_section_queries`.
- [x] Extract cloud asset inventory and cloud validation result query assembly
  into `forge.reporting.detail_section_queries`.
- [x] Extract key scanner, secret lifecycle, and vulnerability finding query
  assembly into `forge.reporting.detail_section_queries`.
- [x] Extract merged host/email inventory and engagement-run/manifest query
  assembly into `forge.reporting.detail_section_queries`.
- [x] Extract dashboard summary/count aggregation into
  `forge.reporting.engagement_summary`.
- [x] Extract seed graph and asset graph summary aggregation into
  `forge.reporting.graph_summaries`.
- [x] Extract GraphML/MTGX graph artifact discovery/parsing into
  `forge.reporting.graph_artifacts`.
- [x] Extract JSON graph payload normalization/filtering and source precedence
  into `forge.reporting.graph_payloads`.
- [x] Extract seed graph payload synthesis into
  `forge.reporting.seed_graph_payloads`.
- [x] Extract latest-run/audit annotation helpers into
  `forge.reporting.run_summaries`.
- [x] Extract engagement-run detail row formatting into
  `forge.reporting.run_summaries`.
- [x] Extract artifact/report payload helpers into
  `forge.reporting.artifact_payloads`.
- [x] Extract audit manifest artifact discovery/materialization into
  `forge.reporting.audit_manifest_artifacts`.
- [x] Deduplicate live Web UI report/audit artifact discovery and audit-manifest
  materialization onto `forge.reporting.audit_manifest_artifacts`.
- [x] Extract Web UI-specific artifact API payload/link builders into
  `forge.webui.artifacts`.
- [x] Extract Web UI log payload/tail helpers into `forge.webui.logs`.
- [x] Extract Web UI run-control marker and launch-log setup helpers into
  `forge.webui.run_control`.
- [x] Extract Web UI kill-chain launch command assembly and option parsing into
  `forge.webui.kill_chain_launch`.
- [x] Extract Web UI launch process execution and progress payload publication
  into `forge.webui.kill_chain_launch`.
- [x] Extract Web UI engagement-run DB row status/progress summarization into
  `forge.webui.run_status`.
- [x] Extract Web UI stop/pause control metadata mutation and progress
  publication into `forge.webui.run_control`.
- [x] Extract Web UI engagement seed mutation/canonicalization helpers into
  `forge.webui.seeds`.
- [x] Extract Web UI engagement create/update workspace/indexing helpers into
  `forge.webui.engagement_lifecycle`.
- [x] Extract Web UI engagement discovery/resolution/index-cache helpers into
  `forge.webui.engagement_discovery`.
- [x] Extract Web UI automation execute/playbook route helpers into
  `forge.webui.automation_routes`.
- [x] Extract Web UI engagement assets/vulnerability-summary/asset-tree payload
  helpers into `forge.webui.engagement_data`.
- [x] Extract Web UI command-center/action/sentry/timeline route helpers into
  `forge.webui.command_center_routes`.
- [x] Extract Web UI task/queue/scan route helpers into
  `forge.webui.task_routes`.
- [x] Extract Web UI numeric engagement authorization wrapper into
  `forge.webui.route_authorization`.
- [x] Extract Web UI active-validation route helpers into
  `forge.webui.active_validation_routes`.
- [x] Extract Web UI monitoring route helpers into
  `forge.webui.monitoring_routes`.
- [x] Extract Web UI remediation route helpers into
  `forge.webui.remediation_routes`.
- [x] Extract kill-chain cloud-scan summary closeout into
  `forge.orchestration.report_finalization`: final cloud key validation,
  finding synthesis, and `cloud_scan_summary` audit result formatting now live
  behind `emit_kill_chain_cloud_scan_summary`, preserving provider label order
  and aliases while giving the summary string direct unit coverage. Verification:
  py_compile passed for CLI/finalization/test files; Ruff passed; direct
  report-finalization tests passed (`24 passed`).
- [x] Extract kill-chain dry-run finalization skipped closeout into
  `forge.orchestration.report_finalization`: `emit_kill_chain_dry_run_finalization_skip`
  now owns the dry-run-only `finalization dry-run` log and
  `dry_run_finalization_skipped` audit payload while live mode remains a no-op.
  Verification: py_compile passed for CLI/finalization/test files; Ruff passed;
  direct report-finalization tests passed (`26 passed`).
- [x] Extract kill-chain final sidecar runner into
  `forge.orchestration.report_finalization`: `run_kill_chain_final_sidecars`
  now coordinates the provider-key validation sweep and aggregate stats sidecar
  generation, preserving reports-dir/logger/log-callback forwarding while
  returning both result objects for direct tests. Verification: py_compile
  passed for CLI/finalization/test files; Ruff passed; direct
  report-finalization tests passed (`27 passed`).
- [x] Extract kill-chain completion audit emission into
  `forge.orchestration.report_finalization`: `emit_kill_chain_complete_audit`
  now owns `kill_chain_complete` audit result formatting and callback emission,
  preserving `elapsed_s={:.1f}` and `emails_chained` count semantics.
  Verification: py_compile passed for CLI/finalization/test files; Ruff passed;
  direct report-finalization tests passed (`29 passed`).
- [x] Extract kill-chain report-artifact audit wrapper into
  `forge.orchestration.report_finalization`: `ensure_kill_chain_report_artifact`
  now wraps `ensure_report_artifact` with the fixed
  `orchestrator`/`kill_chain` audit context, removing the nested CLI adapter
  while preserving fallback audit payloads. Verification: py_compile passed for
  CLI/finalization/test files; Ruff passed; direct report-finalization tests
  passed (`30 passed`).
- [x] Extract kill-chain progress-backed final summary into
  `forge.orchestration.report_finalization`:
  `emit_kill_chain_final_summary_from_progress` now derives
  `pending_work_total`, delegates rendering to the existing summary helper, and
  returns the pending count for completion metadata while preserving
  sidecar-before-summary ordering. Verification: py_compile passed for
  CLI/finalization/test files; Ruff passed; direct report-finalization tests
  passed (`31 passed`).
- [x] Extract kill-chain completion report kwargs into
  `forge.orchestration.report_finalization`:
  `kill_chain_completion_report_kwargs` now shapes report path/readiness,
  provider loop values, finalization failure count, and copied
  report-finalization metadata before forwarding into engagement-run completion.
  Verification: py_compile passed for CLI/finalization/test files; Ruff passed;
  direct report-finalization tests passed (`33 passed`).
- [x] Extract engagement-run completion callback factory into
  `forge.orchestration.run_tracking`: `engagement_run_completion_callback`
  now builds `_complete_engagement_run` for the kill-chain tail, preserving
  the one-shot guard, pending/progress refresh, terminal audit, tracker finish,
  cleanup, review-surface refresh, and prereq metadata forwarding without a
  local CLI closure. Verification: py_compile passed for CLI/run-tracking/test
  files; Ruff passed; focused run-tracking tests passed (`21 passed`).
- [x] Extract kill-chain terminal closeout into
  `forge.orchestration.report_finalization`:
  `finalize_kill_chain_closeout` now wraps report artifact verification,
  terminal completion audit, provider-key/stats sidecars, and final summary
  emission, returning report metadata plus final pending/sidecar results without
  an inline CLI closeout block. Verification: py_compile passed for
  CLI/finalization/test files; Ruff passed; direct report-finalization tests
  passed (`35 passed`).
- [x] Extract closeout-to-completion kwargs adapter into
  `forge.orchestration.report_finalization`:
  `kill_chain_completion_report_kwargs_from_closeout` now derives
  engagement-run completion report kwargs directly from `KillChainCloseoutResult`,
  removing CLI unpack/repack wiring while preserving fallback path/readiness and
  copied metadata behavior. Verification: py_compile passed for
  CLI/finalization/test files; Ruff passed; direct report-finalization tests
  passed (`38 passed`).
- [x] Extract timestamped kill-chain report-path construction into
  `forge.orchestration.report_finalization`:
  `kill_chain_finalization_report_path_now` now owns UTC timestamp formatting
  and delegates to the deterministic report-path formatter, with an injected
  clock for tests. Verification: py_compile passed for CLI/finalization/test
  files; Ruff passed; direct report-finalization tests passed (`39 passed`).
- [x] Extract kill-chain finalization execution pipeline into
  `forge.orchestration.report_finalization`:
  `run_kill_chain_finalization_execution` now owns credential-validation
  execution, final cloud-scan summary, pregraph parallel finalizers, sequential
  graph/report finalizers, and report return-code detection. It preserves
  existing labels, dispatch-spec construction, progress snapshots, cloud-summary
  audit output, failure accounting, and returns a typed execution result.
  Verification: py_compile passed for CLI/finalization/test files; Ruff passed;
  direct report-finalization tests passed (`36 passed`).
- [x] Extract kill-chain finalization preparation into
  `forge.orchestration.report_finalization`:
  `prepare_kill_chain_finalization` now owns data-driven active-validation
  finalizer discovery, finalization plan construction, and dry-run finalizer
  skip logging/auditing, returning a typed preparation result. Verification:
  py_compile passed for CLI/finalization/test files; Ruff passed; direct
  report-finalization tests passed (`37 passed`).
- [x] Extract kill-chain finalization dispatch-spec factory into
  `forge.orchestration.report_finalization`: credential-validation and pregraph
  finalization dispatch construction now uses
  `kill_chain_finalization_dispatch_spec_factory(ModuleDispatchSpec)`, removing
  two inline CLI lambdas while keeping the dispatch-spec class injectable.
  Verification: py_compile passed for CLI/prereq/finalization/test files; Ruff
  passed; focused prerequisite plus report-finalization tests passed (`44
  passed`).
- [x] Extract kill-chain prerequisite audit wiring into
  `forge.kill_chain_prereqs`: detection-result formatting and the auto-run /
  prompted audit callback factory now live beside prerequisite flow handling,
  preserving the fixed `orchestrator`/`kill_chain` audit context and
  `prereq_detection`, `prereq_auto_run`, and `prereq_prompted` actions.
  Verification: py_compile passed for CLI/prereq/test files; Ruff passed;
  focused prerequisite tests passed (`8 passed`).
- [x] Extract kill-chain prerequisite detect-and-audit coordination into
  `forge.kill_chain_prereqs`: `detect_and_audit_kill_chain_prerequisites` now
  owns prerequisite detection plus the fixed `prereq_detection` audit emission,
  removing the separate detect-then-audit block from `forge kill-chain`.
  Verification: py_compile passed for CLI/prereq/test files; Ruff passed;
  focused prerequisite tests passed (`13 passed`).
- [x] Extract kill-chain prerequisite audit callback pair into
  `forge.kill_chain_prereqs`: `kill_chain_prereq_audit_callbacks` now returns
  typed auto-run/prompted callbacks for the shared CLI audit context, removing
  two separate callback construction blocks from `forge kill-chain` while
  preserving `prereq_auto_run` and `prereq_prompted` actions. Verification:
  py_compile passed for CLI/prereq/test files; Ruff passed; focused
  prerequisite tests passed (`12 passed`).
- [x] Extract kill-chain prerequisite child-argv hardener into
  `forge.kill_chain_prereqs`: ROE/scope binding for auto-run prerequisite child
  commands now uses `kill_chain_prereq_child_argv_hardener`, removing the inline
  CLI lambda while preserving `_detected_prereq_child_argv` forwarding behavior.
  Verification: py_compile passed for CLI/prereq/test files; Ruff passed;
  focused prerequisite tests passed (`9 passed`).
- [x] Extract kill-chain prerequisite dispatch-spec factory into
  `forge.kill_chain_prereqs`: auto-run prerequisite dispatch construction now
  uses `kill_chain_prereq_dispatch_spec_factory(ModuleDispatchSpec)`, removing
  the inline CLI lambda while keeping the dispatch-spec class injectable.
  Verification: py_compile passed for CLI/prereq/test files; Ruff passed;
  focused prerequisite tests passed (`10 passed`).
- [x] Extract kill-chain prerequisite interactivity helper into
  `forge.kill_chain_prereqs`: prereq prompting now uses
  `kill_chain_prereq_is_interactive(sys.stdin, sys.stdout)`, removing the inline
  `stdin.isatty() and stdout.isatty()` expression and local `sys` import from
  the kill-chain tail block. Verification: py_compile passed for
  CLI/prereq/test files; Ruff passed; focused prerequisite tests passed (`11
  passed`).
- [x] Extract kill-chain prerequisite flow runtime into
  `forge.kill_chain_prereqs`: `KillChainPrereqFlowRuntime` plus
  `handle_kill_chain_prerequisite_flow_with_runtime` now adapt CLI runtime hooks
  into the existing prereq flow, removing the long inline flow adapter block
  from `forge kill-chain` while preserving dispatch construction, ROE/scope
  hardening, interactivity detection, progress, and audit callbacks.
  Verification: py_compile passed for CLI/prereq/test files; Ruff passed;
  focused prerequisite tests passed (`14 passed`).
- [x] Extract kill-chain prerequisite high-level runner into
  `forge.kill_chain_prereqs`: `run_kill_chain_prerequisites_with_runtime` now
  owns detect-and-audit, audit callback construction, and runtime-backed flow
  invocation, reducing the `forge kill-chain` tail to one prerequisite runner
  call plus runtime object construction. Verification: py_compile passed for
  CLI/prereq/test files; Ruff passed; focused prerequisite tests passed (`15
  passed`).
- [x] Extract kill-chain prerequisite runtime factory into
  `forge.kill_chain_prereqs`: `kill_chain_prereq_flow_runtime` now packages the
  CLI runtime callbacks into `KillChainPrereqFlowRuntime`, removing direct
  dataclass construction from `forge kill-chain`. Verification: py_compile
  passed for CLI/prereq/test files; Ruff passed; focused prerequisite tests
  passed (`16 passed`).
- [x] Extract kill-chain prerequisite CLI-hook runner wrapper into
  `forge.kill_chain_prereqs`: `run_kill_chain_prerequisites_with_cli_hooks`
  now packages CLI callbacks into the runtime and invokes the existing high-level
  prerequisite runner, removing nested runtime construction from `forge
  kill-chain`. Verification: py_compile passed for CLI/prereq/test files; Ruff
  passed; focused prerequisite tests passed (`17 passed`).
- [x] Close remediation owner-review workflow gap: remediation items now carry
  `owner_approval` state, `review_remediation_owner_assignment` records
  approve/reject/needs-review metadata and audit history, the live
  `/remediation/{item}/review-owner` route refreshes items/summary/review queue,
  and the React selected-item command card exposes Approve owner, Reject owner,
  and Needs review actions. Verification: remediation route tests passed (`7
  passed`); React contract tests passed (`12 passed`); py_compile/Ruff passed
  for touched Python/test files; web UI `npm run build` passed.
- [x] Extract workspace route payload logic out of `create_app()`:
  `forge.webui.workspace_routes` now owns workspace ID validation, metadata and
  member-permission coercion, workspace list/upsert payloads, member
  list/upsert/delete payloads, audit payloads, and control-audit writes.
  `create_app()` keeps auth, permission checks, control DB ownership, and HTTP
  400/403 mapping. Verification: py_compile/Ruff passed for app/helper files;
  workspace/RBAC integration tests passed (`4 passed`); auth plus route
  authorization helper tests passed (`20 passed`).
- [x] Extract connector route payload logic out of `create_app()`:
  `forge.webui.connector_routes` now owns connector catalog payload construction,
  plugin-manifest validation mapping, connector-secret list/store payloads, and
  redacted secret summaries. `create_app()` keeps auth, permission checks,
  engagement DB ownership, and HTTP 400/404 mapping. Verification: py_compile
  passed for app/helper files; Ruff passed; connector RBAC/secret-redaction and
  invalid plugin-manifest route tests passed (`2 passed`).
- [x] Extract audit-review route payload logic out of `create_app()`:
  `forge.webui.audit_review_routes` now owns audit-review list/record payload
  construction, request normalization, summary assembly, and route-local
  400/404 error classes. `create_app()` keeps auth, permission checks,
  engagement DB ownership, and HTTP mapping. Verification: py_compile passed
  for app/helper files; Ruff passed; audit-review route integration test passed
  (`1 passed`).
- [x] Extract retention route payload logic out of `create_app()`:
  `forge.webui.retention_routes` now owns retention overview, policy upsert,
  preview/apply request shaping, confirm enforcement, and retention-day parsing.
  `create_app()` keeps auth, permission checks, engagement DB ownership, and
  HTTP mapping. Verification: py_compile passed for app/helper files; Ruff
  passed; retention route integration tests passed (`3 passed`).
- [x] Extract asset-graph route payload logic out of `create_app()`:
  `forge.webui.asset_graph_routes` now owns graph read/rebuild, ownership-claim
  upsert, attribution import, ownership-conflict resolution, audit receipts, and
  route-local 400/404 error classes. `create_app()` keeps auth, permission
  checks, engagement DB ownership, and HTTP mapping. Verification: py_compile
  passed for app/helper files; Ruff passed; asset-graph API route test passed
  (`1 passed`).
- [x] Extract engagement index response helpers out of `create_app()`:
  `forge.webui.engagement_index_routes` now owns engagement list envelopes,
  detail-not-found mapping, tombstone envelopes, and generated dashboard
  engagement JSON response shaping. `create_app()` keeps auth, permission
  checks, discovery, data-file serving, and HTTP mapping. Verification:
  py_compile passed for app/helper files; Ruff passed; focused engagement list,
  workspace-boundary, and tombstone tests passed (`4 passed`).
- [x] Extract HTMX rendering helpers out of `create_app()`:
  `forge.webui.htmx_routes` now owns valid tab names, full-page/fragment
  template selection, no-store headers, and HTMX not-found mapping.
  `create_app()` keeps auth, discovery, template object ownership, and HTTP
  mapping. Verification also tightened legacy pre-membership engagement access:
  original operators can read only when their workspace has no membership rows.
  Ruff passed; HTMX plus workspace-boundary tests passed (`20 passed`).
- [x] Extract run/log route payload logic out of `create_app()`:
  `forge.webui.run_log_routes` now owns run list payloads, stop/pause
  request shaping, log list payloads, safe log resolution, and bounded log-tail
  responses. `create_app()` keeps auth, permission checks, engagement
  resolution, connection ownership, and `FileResponse` mapping. Verification:
  py_compile passed for app/helper files; Ruff passed; focused run/log/stop,
  pause-progress, and pause/resume tests passed (`3 passed`).
- [x] Extract seed route payload dispatch out of `create_app()`:
  `forge.webui.seed_routes` now owns seed list/create/update/delete payload
  dispatch around the existing seed mutation helpers. `create_app()` keeps
  auth, permission checks, engagement resolution, DB connection ownership, and
  HTTP error mapping. Verification: py_compile passed for app/helper files;
  Ruff passed; seed helper tests plus seed CRUD/canonicalization route tests
  passed (`8 passed`).
- [x] Extract kill-chain launch route orchestration out of `create_app()`:
  `forge.webui.kill_chain_launch` now owns launchable seed ordering,
  active-run/no-seed checks, launch option/spec construction, process spawn,
  response payloads, and progress event publishing. `create_app()` keeps auth,
  permission checks, engagement resolution, DB connection ownership, and HTTP
  status mapping. Verification: py_compile passed for app/helper files; Ruff
  passed; launch helper tests plus run/stop and pause/resume route tests passed
  (`11 passed`).
- [x] Extract task/queue/scan route wrapper logic out of `create_app()`:
  `forge.webui.task_routes` now owns start-scan mutation/event construction and
  task-enqueue scheduling/event construction, alongside the existing
  queue/worker/metrics/progress payload helpers. `create_app()` keeps auth,
  permission checks, engagement resolution, DB connection ownership, broker
  publishing, and HTTP mapping. Verification: py_compile passed for app/helper
  files; Ruff passed; task helper tests plus authorized task/queue/scan route
  tests passed (`6 passed`).
- [x] Extract active-validation route wrapper logic out of `create_app()`:
  `forge.webui.active_validation_routes` now owns approval/live permission
  escalation helpers and list/preview/create/approve/run route dispatch helpers.
  `create_app()` keeps auth, engagement resolution, DB connection ownership, and
  HTTP mapping. Verification: py_compile passed for app/helper files; Ruff
  passed; active-validation helper tests passed (`7 passed`), and integration
  permission coverage passed (`2 passed, 63 deselected`).
- [x] Extract continuous-monitoring route wrapper logic out of `create_app()`:
  `forge.webui.monitoring_routes` now owns overview, policy, alert-route,
  suppression, snapshot, due-policy-run, alert-update, and remediation-escalation
  route dispatch helpers. `create_app()` keeps auth, permission checks,
  engagement resolution, DB connection ownership, and HTTP mapping. Verification:
  py_compile passed for app/helper files; Ruff passed; monitoring helper tests
  plus continuous-monitoring integration coverage passed (`6 passed`).
- [x] Extract remediation route wrapper logic out of `create_app()`:
  `forge.webui.remediation_routes` now owns remediation list, review queue,
  export payload, owner propagation, asset-graph draft, create/update,
  owner-review, retest, ticket-sync dispatch, and multi-permission helper
  tuples. `create_app()` keeps auth, permission checks, engagement resolution,
  DB connection ownership, export response construction, and HTTP mapping.
  Verification: py_compile passed for app/helper files; Ruff passed;
  remediation helper plus route integration tests passed (`11 passed`).
- [x] Extract automation route wrapper logic out of `create_app()`:
  `forge.webui.automation_routes` now owns suggestion, action queue, and
  playbook route dispatch helpers. `create_app()` keeps auth, permission checks,
  engagement resolution, DB path ownership, progress publisher wiring, and HTTP
  mapping. Verification: Ruff passed; automation helper tests passed
  (`8 passed`), and focused automation integration route coverage passed
  (`13 passed`).
- [x] Extract shell/static/generated-data route wrapper logic out of
  `create_app()`: `forge.webui.shell_routes` now owns SPA entry fallback,
  frontend SVG asset lookup, generated engagement collection/detail JSON, and
  generated data-asset boundary checks. `create_app()` keeps auth, permission
  checks, response class wiring, and HTTP mapping. Verification: compile/Ruff
  passed; shell helper plus focused integration coverage passed (`10 passed`).
- [x] Extract engagement index route wrapper logic out of `create_app()`:
  `forge.webui.engagement_index_routes` now owns engagement collection,
  missing-index tombstone, and detail route dispatch helpers. `create_app()`
  keeps auth, permission checks, generated timestamps, retention env lookup,
  and HTTP mapping. Verification: compile/Ruff passed; index helper plus
  focused list/detail/tombstone integration coverage passed (`8 passed`).
- [x] Extract workspace route wrapper logic out of `create_app()`:
  `forge.webui.workspace_routes` now owns workspace list/upsert, member
  list/upsert/delete, and audit route dispatch helpers. `create_app()` keeps
  auth, permission checks, control DB lifecycle, and HTTP mapping. Verification:
  compile/Ruff passed; workspace helper plus focused RBAC integration coverage
  passed (`3 passed`).
- [x] Extract engagement lifecycle route wrapper logic out of `create_app()`:
  `forge.webui.engagement_lifecycle` now owns create/update record dispatch and
  control-index refresh helpers. `create_app()` keeps auth, permission checks,
  workspace access checks, ID allocation, DB lifecycle, and HTTP mapping.
  Verification: compile/Ruff passed; lifecycle helper plus focused create/update
  integration coverage passed (`12 passed`).
- [x] Fix mixed indexed/unindexed engagement discovery:
  `forge.webui.engagement_discovery.iter_engagement_payloads` now scans numeric
  DBs missing from the control index even when other fresh indexed items were
  returned. This keeps the fresh-index fast path but restores surviving
  unindexed DBs in `/api/engagements`. Verification: compile/Ruff passed;
  targeted discovery tests plus
  `test_engagement_create_uses_monotonic_sequence_after_deleted_db` passed
  (`3 passed`), and adjacent lifecycle/create/update coverage passed
  (`13 passed`).
- [x] Extract command-center route wrapper logic out of `create_app()`:
  `forge.webui.command_center_routes` now owns host context/actions,
  execute/approve, sentry toggle, emergency stop, and timeline route dispatch
  helpers. `create_app()` keeps auth, permission checks, engagement
  authorization, service construction, and HTTP mapping. Verification:
  compile/Ruff passed; command-center helper plus focused permission/scope
  integration coverage passed (`9 passed`).
- [x] Extract engagement data route wrapper logic out of `create_app()`:
  `forge.webui.engagement_data` now owns engagement assets, vulnerability
  summary, and asset-tree route dispatch helpers. `create_app()` keeps auth,
  permission checks, engagement authorization, and DB lifecycle. Verification:
  compile/Ruff passed; engagement data helper plus focused integration coverage
  passed (`9 passed`).
- [x] Extract run/log route wrapper logic out of `create_app()`:
  `forge.webui.run_log_routes` now owns run listing, stop/pause run-control
  dispatch, log listing, log download, and log-tail route dispatch helpers.
  `create_app()` keeps auth, permission checks, engagement authorization, DB
  lifecycle, `FileResponse`, and HTTP mapping. Verification: compile/Ruff
  passed; run/log helper coverage passed (`21 passed`) and focused webui
  integration coverage passed (`5 passed, 60 deselected`).
- [x] Extract task/queue route wrapper logic out of `create_app()`:
  `forge.webui.task_routes` now owns scan-start, task enqueue, task list,
  worker list, queue metrics, and scan-progress route dispatch helpers.
  `create_app()` keeps auth, permission checks, engagement authorization, DB
  lifecycle, queue/coordinator ownership, broker publishing, and HTTP mapping.
  Verification: compile/Ruff passed; task helper plus focused webui integration
  coverage passed (`11 passed, 59 deselected`).
- [x] Extract artifact download route wrapper logic out of `create_app()`:
  `forge.webui.artifacts` now owns artifact download route resolution and
  missing-artifact mapping. `create_app()` keeps auth, `artifacts:read`,
  `FileResponse`, and HTTP 404 mapping. Verification: compile/Ruff passed;
  artifact helper plus focused discovery/integration coverage passed (`12
  passed, 59 deselected`).
- [x] Extract progress WebSocket state helpers out of `create_app()`:
  `forge.webui.state` now owns progress socket subprotocol selection and event
  JSON shaping. `create_app()` keeps WebSocket auth, engagement authorization,
  socket lifecycle, broker subscription, engagement filtering, and unsubscribe
  cleanup. Verification: compile/Ruff passed; state helper plus focused HTMX
  socket coverage passed (`7 passed, 15 deselected`).
- [x] Extract progress event construction helpers out of `create_app()`:
  `forge.webui.state` now owns progress event construction, sync publish
  adaptation, queued-event validation, and run-progress event shaping.
  `create_app()` keeps queue/run bridge loops, broker publishing, lifecycle,
  and fingerprint tracking. Verification: compile/Ruff passed; state helper
  plus focused HTMX socket coverage passed (`9 passed, 15 deselected`).
- [x] Extract CLI command registration wiring out of `forge.cli`:
  `forge.cli_registry.register_extracted_cli_commands()` now owns
  root/web/kb/recon/evasion/exploit/clean/vuln/auth registration wiring.
  `forge.cli` keeps callback setup, compatibility adapters, and kill-chain
  handler registration. Verification: compile/Ruff passed; CLI registry
  coverage passed (`16 passed`).
- [x] Extract CLI root runtime guard logic out of `forge.cli`:
  `forge.cli_runtime` now owns offline socket guarding, `--no-tor` proxy
  cleanup, Tor start gating, stop registration, and failed bootstrap mapping.
  `forge.cli` keeps version output, resilient parsing, config loading, and
  Typer exit mapping. Verification: compile/Ruff passed; CLI runtime plus
  registry coverage passed (`21 passed`).
- [x] Extract CLI compatibility adapters out of `forge.cli`:
  `forge.cli_compat` now owns exploit/vuln/auth/clean direct-import adapters,
  and `forge.cli` re-exports those names for legacy imports. Verification:
  compile/Ruff passed; CLI registry/runtime coverage passed (`22 passed`).
- [x] Extract artifact queue runtime-service adapter binding out of
  `forge.engagement_orchestrator`: `artifact_processor_runtime_services()` now
  lives in `forge.orchestration.artifact_processor_runtime`, is exported through
  `forge.orchestration`, and `ArtifactQueueProcessor._runtime_services()`
  delegates to it. Verification: compile/Ruff passed; artifact processor
  runtime coverage passed (`8 passed`).
- [x] Extract artifact queue progress-emission adapter logic out of
  `forge.engagement_orchestrator`: `artifact_processor_progress_stage_label()`
  and `emit_artifact_processor_stage_progress()` now live in
  `forge.orchestration.artifact_processor_runtime`; processor compatibility
  wrappers delegate to them. Verification: compile/Ruff passed; artifact
  processor runtime coverage passed (`8 passed`).
- [x] Extract artifact queue processor entrypoint adapter wiring out of
  `forge.engagement_orchestrator`: `ingest_local_artifacts_for_processor()`
  and `process_artifact_queue_for_processor()` now live in
  `forge.orchestration.artifact_processor_runtime`; processor public
  entrypoints delegate to them. Verification: compile/Ruff passed; artifact
  processor runtime coverage passed (`9 passed`).
- [x] Extract artifact queue row-callback adapter wiring out of
  `forge.engagement_orchestrator`: `artifact_processor_callbacks_for_processor()`
  now lives in `forge.orchestration.artifact_processor_runtime`; processor
  callback compatibility wrapper delegates to it. Verification: compile/Ruff
  passed; artifact processor runtime coverage passed (`10 passed`).
- [x] Extract artifact queue local artifact record/metadata adapter wiring out
  of `forge.engagement_orchestrator`:
  `artifact_processor_local_artifact_record()`,
  `artifact_processor_local_artifact_metadata()`, and
  `artifact_processor_local_artifact_metadata_matches()` now live in
  `forge.orchestration.artifact_processor_runtime`; processor compatibility
  wrappers delegate to them. Verification: compile/Ruff passed; artifact
  processor runtime coverage passed (`11 passed`).
- [x] Extract artifact queue dispatch adapter wiring out of
  `forge.engagement_orchestrator`: `artifact_processor_dispatch_entry()` now
  lives in `forge.orchestration.artifact_processor_runtime`; processor
  compatibility wrapper delegates to it. Verification: compile/Ruff passed;
  artifact processor runtime coverage passed (`12 passed`).
- [x] Extract artifact queue remote download reconciliation adapter wiring out
  of `forge.engagement_orchestrator`:
  `artifact_processor_remote_download_reconciliation_entry()` now lives in
  `forge.orchestration.artifact_processor_runtime`; processor compatibility
  wrapper delegates to it. Verification: compile/Ruff passed; artifact
  processor runtime coverage passed (`12 passed`).
- [x] Extract artifact queue parse/download batch adapter wiring out of
  `forge.engagement_orchestrator`: `parse_local_artifacts_for_processor()` and
  `download_remote_artifacts_for_processor()` now live in
  `forge.orchestration.artifact_processor_runtime`; processor compatibility
  wrappers delegate to them while preserving max-worker, progress, remote-scope,
  denial, and download-one bindings. Verification: compile/Ruff passed;
  artifact processor runtime coverage passed (`14 passed`).
- [x] Extract artifact queue single work-item parser adapter wiring out of
  `forge.engagement_orchestrator`: `parse_artifact_work_item_for_processor()`
  now lives in `forge.orchestration.artifact_processor_runtime`; the processor
  compatibility wrapper delegates to it while preserving mobile/text scan
  callback binding and artifact-format label propagation. Verification:
  compile/Ruff passed; artifact processor runtime coverage passed (`15 passed`).
- [x] Extract artifact queue mobile/text scan adapter wiring out of
  `forge.engagement_orchestrator`: `scan_mobile_bundle_artifact_for_processor()`
  and `scan_text_artifact_for_processor()` now live in
  `forge.orchestration.artifact_processor_runtime`; processor compatibility
  wrappers delegate to them while preserving ordered batch binding,
  extraction-stage callbacks, cloud-config extraction, payload summaries, and
  Firebase/Supabase dedupe. Verification: compile/Ruff passed; artifact
  processor runtime coverage passed (`17 passed`).
- [x] Extract artifact queue extraction-stage adapter wiring out of
  `forge.engagement_orchestrator`:
  `extract_mobile_bundle_family_for_processor()` and
  `extract_text_artifact_stage_for_processor()` now live in
  `forge.orchestration.artifact_processor_runtime`; processor compatibility
  wrappers delegate to them while preserving APK/IPA extractor selection, text
  payload extraction, and nested-mobile stage binding. Verification:
  compile/Ruff passed; artifact processor runtime coverage passed
  (`19 passed`).
- [x] Extract artifact queue archive-payload and ordered-batch adapter wiring
  out of `forge.engagement_orchestrator`:
  `extract_mobile_bundle_text_payloads_for_processor()` and
  `run_ordered_local_batch_for_processor()` now live in
  `forge.orchestration.artifact_processor_runtime`; processor compatibility
  wrappers delegate to them while preserving ZIP/TAR payload callbacks,
  default factory propagation, worker invocation, and max-worker binding.
  Verification: compile/Ruff passed; artifact processor runtime coverage passed
  (`21 passed`, with `PROCESSOR_IDENTIFIER` set to avoid a Windows WMI timeout
  in pytest metadata collection).
- [x] Extract artifact queue cloud-config payload adapter wiring out of
  `forge.engagement_orchestrator`:
  `extract_cloud_configs_from_payloads_for_processor()`,
  `payload_cloud_config_job_for_processor()`, and
  `payload_cloud_config_result_entry_for_processor()` now live in
  `forge.orchestration.artifact_processor_runtime`; processor compatibility
  wrappers delegate to them while preserving blank-payload filtering, ordered
  batch execution, per-payload Firebase/Supabase extraction, result-entry
  normalization, and accumulated cloud config returns. Verification:
  compile/Ruff passed; artifact processor runtime coverage passed (`23 passed`,
  with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue single-payload cloud-config adapter wiring out of
  `forge.engagement_orchestrator`:
  `extract_cloud_configs_from_payload_for_processor()` and
  `extract_cloud_config_family_for_processor()` now live in
  `forge.orchestration.artifact_processor_runtime`; processor compatibility
  wrappers delegate to them while preserving Firebase/Supabase family ordering,
  ordered batch defaults, source/extract-path/text propagation, and extractor
  binding. Verification: compile/Ruff passed; artifact processor runtime
  coverage passed (`25 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue nested-mobile archive adapter wiring out of
  `forge.engagement_orchestrator`:
  `extract_nested_mobile_bundle_configs_for_processor()`,
  `nested_mobile_zip_member_entry_for_processor()`,
  `nested_mobile_tar_member_entry_for_processor()`, and
  `nested_mobile_7z_member_entry_for_processor()` now live in
  `forge.orchestration.artifact_processor_runtime`; processor compatibility
  wrappers delegate to them while preserving archive handler dispatch, `py7zr`
  availability, member filtering, safe archive names, suffix gates, and size
  limits. Verification: compile/Ruff passed; artifact processor runtime
  coverage passed (`27 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue nested-mobile ZIP/TAR adapter wiring out of
  `forge.engagement_orchestrator`:
  `extract_nested_mobile_configs_from_zip_for_processor()` and
  `extract_nested_mobile_configs_from_tar_for_processor()` now live in
  `forge.orchestration.artifact_processor_runtime`; processor compatibility
  wrappers delegate to them while preserving ordered member filtering, member
  job normalization, source path propagation, and member-job processing
  callbacks. Verification: compile/Ruff passed; artifact processor runtime
  coverage passed (`29 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue nested-mobile 7z/member-job adapter wiring out of
  `forge.engagement_orchestrator`:
  `extract_nested_mobile_configs_from_7z_for_processor()`,
  `nested_mobile_member_job_for_processor()`,
  `extract_nested_mobile_configs_from_member_jobs_for_processor()`, and
  `nested_mobile_member_result_entry_for_processor()` now live in
  `forge.orchestration.artifact_processor_runtime`; processor compatibility
  wrappers delegate to them while preserving 7z factory/size binding, ordered
  batching, member job normalization, member byte processing, and result-entry
  normalization. Verification: compile/Ruff passed; artifact processor runtime
  coverage passed (`32 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue nested-mobile member-byte/rebase adapter wiring out
  of `forge.engagement_orchestrator`:
  `extract_mobile_configs_from_member_bytes_for_processor()`,
  `rebased_mobile_member_payload_entry_for_processor()`,
  `rebased_mobile_member_project_entry_for_processor()`, and
  `rebased_mobile_member_config_entry_for_processor()` now live in
  `forge.orchestration.artifact_processor_runtime`; processor compatibility
  wrappers delegate to them while preserving suffix/size gates, ordered batch
  binding, text scan/mobile bundle callbacks, source/member rebasing, and
  Firebase/Supabase type-specific return behavior. Verification: compile/Ruff
  passed; artifact processor runtime coverage passed (`34 passed`, with
  `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue relation-context adapter wiring out of
  `forge.engagement_orchestrator`:
  `safe_artifact_relation_context_for_processor()`,
  `merge_artifact_relation_context_for_processor()`,
  `artifact_cloud_asset_metadata_for_processor()`, and
  `artifact_relation_context_for_processor()` now live in
  `forge.orchestration.artifact_processor_runtime`; processor compatibility
  wrappers delegate to them while preserving parse/artifact metadata filtering,
  relation metadata precedence, source-seed provenance binding, engagement-id
  queue lookup, and cloud asset artifact-provenance metadata behavior.
  Verification: compile/Ruff passed; artifact processor runtime coverage
  passed (`35 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue parsed-artifact persistence adapter wiring out of
  `forge.engagement_orchestrator`: `persist_parsed_artifact_for_processor()`
  now lives in `forge.orchestration.artifact_processor_runtime`; processor
  compatibility wrapper delegates to it while preserving relation context,
  source-seed fallback creation, structured discovery expansion, generic
  discovery seed counts, Firebase/Supabase dedupe/store callbacks, source URL
  propagation, artifact context propagation, and parse metadata return behavior.
  Verification: compile/Ruff passed; artifact processor runtime coverage
  passed (`36 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue structured discovery adapter wiring out of
  `forge.engagement_orchestrator`:
  `artifact_discovery_payloads_for_processor()`,
  `expand_structured_discovery_jobs_for_processor()`,
  `structured_discovery_payload_job_for_processor()`,
  `structured_discovery_result_entry_for_processor()`,
  `structured_discovery_jobs_for_payload_for_processor()`, and
  `structured_discovery_payload_entry_for_processor()` now live in
  `forge.orchestration.artifact_processor_runtime`; processor compatibility
  wrappers delegate to them while preserving source URL payload rebasing, blank
  payload filtering, ordered batch/default behavior, structured discovery
  family ordering, source-hint construction, fragment-builder callback binding,
  payload-entry callback binding, and result flattening. Verification:
  compile/Ruff passed; artifact processor runtime coverage passed (`39
  passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue data-URI structured discovery adapter wiring out
  of `forge.engagement_orchestrator`:
  `decode_data_uri_bytes_for_processor()`,
  `data_uri_payload_entry_for_processor()`,
  `data_uri_structured_payload_text_for_processor()`,
  `data_uri_image_payload_entry_for_processor()`, and
  `data_uri_image_structured_payload_text_for_processor()` now live in
  `forge.orchestration.artifact_processor_runtime`; processor compatibility
  wrappers delegate to them while preserving base64/URL decoding, text decode
  size limits, ordered batch/default behavior, data-URI regex limits, OCR image
  suffix/size filtering, content-type suffix selection, OCR/barcode/image
  metadata callback binding, and structured payload text return behavior.
  Verification: compile/Ruff passed; artifact processor runtime coverage
  passed (`40 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue IaC structured discovery adapter wiring out of
  `forge.engagement_orchestrator`:
  `iac_text_structured_payload_text_for_processor()` and
  `iac_text_structured_payload_family_for_processor()` now live in
  `forge.orchestration.artifact_processor_runtime`; processor compatibility
  wrappers delegate to them while preserving IaC family ordering, source-hint
  propagation, ordered batch/default behavior, case-insensitive duplicate-line
  suppression, Terraform/Bicep callback binding, candidate-function dispatch,
  joined candidate return formatting, and unknown-family empty results.
  Verification: compile/Ruff passed; artifact processor runtime coverage
  passed (`42 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue mobile config storage adapter wiring out of
  `forge.engagement_orchestrator`:
  `store_firebase_projects_for_processor()`,
  `store_supabase_configs_for_processor()`,
  `firebase_project_persistence_entry_for_processor()`, and
  `supabase_config_persistence_entry_for_processor()` now live in
  `forge.orchestration.artifact_processor_runtime`; processor compatibility
  wrappers delegate to them while preserving Firebase/Supabase storage callback
  wiring, source seed/source URL/artifact context propagation, child-depth
  binding, ordered batch/default behavior, cloud asset/key finding persistence,
  relation merge behavior, and Supabase secret redaction/encryption behavior.
  Verification: compile/Ruff passed; artifact processor runtime coverage
  passed (`44 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue generic text discovery adapter wiring out of
  `forge.engagement_orchestrator`:
  `collect_generic_text_discovery_batches_for_processor()`,
  `generic_text_discovery_job_for_processor()`,
  `collect_generic_text_discovery_job_result_for_processor()`,
  `collect_generic_text_discoveries_for_processor()`, and
  `artifact_text_discovery_family_entry_for_processor()` now live in
  `forge.orchestration.artifact_processor_runtime`; processor compatibility
  wrappers delegate to them while preserving blank discovery-job filtering,
  source hint fallback, ordered batch/default behavior, exception-safe discovery
  job results, per-family discovery callback binding, family batch cloning,
  merge-entry cloning, merge callback behavior, and discovery batch return
  shape. Verification: compile/Ruff passed; artifact processor runtime coverage passed (`47 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue generic text discovery family adapter wiring out
  of `forge.engagement_orchestrator`:
  `collect_generic_text_discovery_family_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor
  compatibility wrapper delegates to it while preserving source-label fallback,
  simple/network/URL/identity/key/cloud family ordering, ordered batch binding,
  URL/contact/key/cloud candidate callbacks, key pattern/redaction/Azure
  parsing/encryption callbacks, and unknown-family empty batch behavior.
  Verification: compile/Ruff passed; artifact processor runtime coverage
  passed (`48 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue generic text key-pattern finding adapter wiring
  out of `forge.engagement_orchestrator`:
  `artifact_text_key_pattern_findings_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor
  compatibility wrapper delegates to it while preserving no-match behavior,
  invalid regex group suppression, base finding shape, source/repo/file/backend
  metadata, key value string coercion, contextual finding callback invocation,
  and contextual finding append order. Verification: compile/Ruff passed;
  artifact processor runtime coverage passed (`50 passed`, with
  `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue generic text URL-family adapter wiring out of
  `forge.engagement_orchestrator`:
  `artifact_text_url_family_candidates_for_processor()` and
  `artifact_text_direct_url_candidate_for_processor()` now live in
  `forge.orchestration.artifact_processor_runtime`; the processor
  compatibility wrappers delegate to them while preserving ordered direct URL
  normalization, HTTP/HTTPS/netloc filtering, manifest fragment stripping,
  duplicate suppression, Helm chart archive suppression for Helm-index sources,
  label-gated metadata families, open metadata families, package/container
  candidate callbacks, and unknown-family empty results. Verification:
  compile/Ruff passed; artifact processor runtime coverage passed (`54 passed`,
  with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue generic text contact identity adapter wiring out
  of `forge.engagement_orchestrator`:
  `artifact_text_contact_identity_candidates_for_processor()`,
  `calendar_contact_identity_line_entry_for_processor()`,
  `calendar_contact_title_line_value_for_processor()`,
  `calendar_contact_identity_value_for_processor()`, and
  `clean_calendar_contact_identity_value_for_processor()` now live in
  `forge.orchestration.artifact_processor_runtime`; the processor
  compatibility wrappers delegate to them while preserving vCard/calendar
  marker fallback, source-label allowlist behavior, title extraction,
  `FN`/`N`/`ORG` parsing, person-name gate binding, cleanup rejection rules,
  dedupe behavior, and the 40-candidate cap. Verification: compile/Ruff
  passed; artifact processor runtime coverage passed (`58 passed`, with
  `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue AWS cloud asset candidate adapter wiring out of
  `forge.engagement_orchestrator`:
  `artifact_text_aws_cloud_asset_family_candidates_for_processor()` now lives
  in `forge.orchestration.artifact_processor_runtime`; the processor cloud
  candidate wrapper delegates AWS subfamilies before the remaining non-AWS
  branches while preserving S3 URI/ARN ordering, S3 bucket lowercasing, KMS ARN
  lowercasing, KMS dedupe, generic AWS ARN callback dispatch, and `None`
  fallthrough for non-AWS cloud families. Verification: compile/Ruff passed;
  artifact processor runtime coverage passed (`59 passed`, with
  `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue GCP cloud asset candidate adapter wiring out of
  `forge.engagement_orchestrator`:
  `artifact_text_gcp_cloud_asset_family_candidates_for_processor()` now lives
  in `forge.orchestration.artifact_processor_runtime`; the processor cloud
  candidate wrapper delegates GCP subfamilies after AWS and before the
  remaining Azure/manifest branches while preserving GCS URI/resource ordering,
  GCS bucket lowercasing, GCP KMS resource string preservation, KMS dedupe, and
  `None` fallthrough for non-GCP cloud families. Verification: compile/Ruff
  passed; artifact processor runtime coverage passed (`60 passed`, with
  `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue Azure cloud asset candidate adapter wiring out of
  `forge.engagement_orchestrator`:
  `artifact_text_azure_cloud_asset_family_candidates_for_processor()` now lives
  in `forge.orchestration.artifact_processor_runtime`; the processor cloud
  candidate wrapper delegates Azure subfamilies after AWS/GCP and before the
  remaining manifest branches while preserving Azure Blob account/container
  lowercasing, Key Vault vault/family/name lowercasing, URL-decoded Key Vault
  object names, Key Vault/app ID dedupe, Microsoft identity app ID lowercasing,
  and `None` fallthrough for non-Azure cloud families. Verification:
  compile/Ruff passed; artifact processor runtime coverage passed (`61 passed`,
  with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue app/mobile manifest candidate adapter wiring out
  of `forge.engagement_orchestrator`:
  `artifact_text_app_manifest_family_candidates_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor cloud
  candidate wrapper delegates ads.txt, app-ads.txt, sellers.json,
  ai-plugin.json, Android assetlinks, Android manifest, Apple app site
  association, and web manifest families after AWS/GCP/Azure and before
  Kubernetes/GitOps/workflow manifest branches while preserving source-format
  gates, app-ads mode forwarding, Android package candidate source labels,
  Android manifest inline `<manifest` fallback, iOS app ID wrapping,
  webmanifest/manifest.json allowlist behavior, callback dispatch, and `None`
  fallthrough for non-app manifest families. Verification: compile/Ruff passed;
  artifact processor runtime coverage passed (`62 passed`, with
  `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue orchestration manifest candidate adapter wiring out
  of `forge.engagement_orchestrator`:
  `artifact_text_orchestration_manifest_family_candidates_for_processor()` now
  lives in `forge.orchestration.artifact_processor_runtime`; the processor cloud
  candidate wrapper delegates Kubernetes secret manifest, GitOps manifest, and
  workflow manifest URI families after app/mobile manifests and before
  Cloudflare while preserving Kubernetes asset type mapping, Amplify identifier
  case preservation/source labeling, non-Amplify lowercasing, URL-decoded
  identifiers, slash trimming, GitOps/workflow source labels, dedupe behavior,
  and `None` fallthrough for non-orchestration manifest families. Verification:
  compile/Ruff passed; artifact processor runtime coverage passed (`63 passed`,
  with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue Cloudflare asset candidate adapter wiring out of
  `forge.engagement_orchestrator`:
  `artifact_text_cloudflare_asset_family_candidates_for_processor()` now lives
  in `forge.orchestration.artifact_processor_runtime`; the processor cloud
  candidate wrapper delegates Cloudflare R2/D1/KV/Worker/Pages structured URI
  families after orchestration manifests while preserving structured URI
  matching, `cloudflare_{service}` asset type construction, identifier
  lowercasing, `artifact_cloudflare_config` source labeling, ordering, and
  `None` fallthrough for non-Cloudflare families. Verification: compile/Ruff
  passed; artifact processor runtime coverage passed (`64 passed`, with
  `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue generic text discovery persistence adapter wiring
  out of `forge.engagement_orchestrator`:
  `persist_generic_text_discovery_batch_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor generic text
  persistence wrapper delegates source seed/artifact context forwarding,
  child-depth callback binding, ordered-batch binding, per-family persistence
  entries, email/seed/url/key/cloud store callbacks, relation metadata merge,
  metadata merge, cloud-asset metadata, and cloud-reference store wiring while
  preserving return-count behavior. Verification: compile/Ruff passed; artifact
  processor runtime coverage passed (`65 passed`, with `PROCESSOR_IDENTIFIER`
  set).
- [x] Extract artifact queue generic text discovery store coordinator out of
  `forge.engagement_orchestrator`:
  `store_generic_text_discoveries_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates text/source-file forwarding to collection, discovered batch handoff
  to persistence, source seed forwarding, and inserted-count return behavior.
  Verification: compile/Ruff passed; artifact processor runtime coverage passed
  (`66 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue URL seed persistence entry adapter wiring out of
  `forge.engagement_orchestrator`:
  `artifact_url_seed_persistence_entry_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor URL seed
  persistence wrapper delegates relation metadata forwarding,
  templated/standards/mobile classifier callback binding, ordered-batch callback
  binding, URL seed family-entry callback binding, family-merge callback
  binding, return entry shape, and lower-helper invalid URL suppression.
  Verification: compile/Ruff passed; artifact processor runtime coverage passed
  (`67 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue URL seed family entry adapter wiring out of
  `forge.engagement_orchestrator`:
  `artifact_url_seed_family_entry_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor URL seed
  family wrapper delegates social pivot relation metadata forwarding, related
  seed hostname forwarding, cloud asset URL forwarding, `artifact_url_extract`
  source labeling, empty dict behavior for unknown families, and returned
  family-entry keys. Verification: compile/Ruff passed; artifact processor
  runtime coverage passed (`68 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue URL related-seed adapter wiring out of
  `forge.engagement_orchestrator`:
  `artifact_url_related_seed_entries_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor related-seed
  wrapper delegates host normalization, social-platform host suppression,
  managed-cloud host suppression, root-domain normalization, domain vs
  subdomain entry behavior, confidence values, and empty-list suppression.
  Verification: compile/Ruff passed; artifact processor runtime coverage passed
  (`69 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue URL social-pivot adapter wiring out of
  `forge.engagement_orchestrator`:
  `artifact_url_social_pivot_entries_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor social-pivot
  wrapper delegates relation metadata forwarding, `artifact_social_url_extract`
  rule override behavior, platform callback binding, handle extraction, Bluesky
  domain-handle promotion, company/name pivot entries, confidence values, and
  callback ordering. Verification: compile/Ruff passed; artifact processor
  runtime coverage passed (`70 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue URL cloud-asset entry adapter wiring out of
  `forge.engagement_orchestrator`:
  `artifact_url_cloud_asset_entries_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor cloud-asset
  wrapper delegates ordered-family execution callback binding, URL forwarding,
  hostname normalization, source forwarding, default empty-list factory behavior,
  flattened family-entry output, and cloud-asset family callback dispatch.
  Verification: compile/Ruff passed; artifact processor runtime coverage passed
  (`71 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue URL cloud-asset family adapter wiring out of
  `forge.engagement_orchestrator`:
  `artifact_url_cloud_asset_family_entries_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor cloud-asset
  family wrapper delegates family dispatch, URL/hostname/source forwarding, AWS
  S3 matcher tuple binding, DigitalOcean/GCS/Azure matcher tuple binding, Azure
  static website/key vault regex binding, Cloudflare worker/pages/R2 regex
  binding, identifier normalization, and empty-list fallthrough behavior.
  Verification: compile/Ruff passed; artifact processor runtime coverage passed
  (`72 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue social-profile URL pivot storage adapter wiring out
  of `forge.engagement_orchestrator`:
  `store_social_profile_url_pivots_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor storage wrapper
  delegates lookup-miss suppression before pivot extraction, relation metadata
  forwarding for generated pivots, supplied pivot-entry passthrough, depth
  forwarding, ordered pivot normalization, seed insertion, second lookup behavior
  inherited from the lower helper, and relation insertion metadata. Verification:
  compile/Ruff passed; artifact processor runtime coverage passed (`74 passed`,
  with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue cloud URL asset storage adapter wiring out of
  `forge.engagement_orchestrator`:
  `store_cloud_assets_from_url_entries_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor storage wrapper
  delegates generated vs supplied cloud entry behavior, source forwarding, source
  seed forwarding, relation metadata forwarding, ordered normalization, default
  `None` handling, metadata construction with `artifact_context=None`, and cloud
  asset reference storage. Verification: compile/Ruff passed; artifact processor
  runtime coverage passed (`75 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue URL entry normalizer adapter wiring out of
  `forge.engagement_orchestrator`:
  `artifact_social_profile_url_pivot_entry_for_processor()` and
  `artifact_cloud_asset_url_entry_for_processor()` now live in
  `forge.orchestration.artifact_processor_runtime`; the processor normalizer
  wrappers delegate social pivot field stripping, confidence coercion, metadata
  dict copying, non-dict suppression, cloud asset type/identifier/source
  stripping, missing-field suppression, and returned entry shapes. Verification:
  compile/Ruff passed; artifact processor runtime coverage passed (`77 passed`,
  with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue cloud asset reference storage adapter wiring out of
  `forge.engagement_orchestrator`:
  `store_artifact_cloud_asset_reference_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor storage wrapper
  delegates engagement id forwarding, asset type/identifier/source forwarding,
  optional metadata forwarding, audit callback action/target/result forwarding,
  and database connection reuse. Verification: compile/Ruff passed; artifact
  processor runtime coverage passed (`78 passed`, with `PROCESSOR_IDENTIFIER`
  set).
- [x] Extract artifact queue Firebase match-entry adapter wiring out of
  `forge.engagement_orchestrator`:
  `firebase_match_entry_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor match wrapper
  delegates project id stripping/lowercasing, empty project suppression, RTDB URL
  retention for `.firebaseio.com` matches, non-RTDB URL suppression, and returned
  entry shape. Verification: compile/Ruff passed; artifact processor runtime
  coverage passed (`79 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue Firebase text extraction adapter wiring out of
  `forge.engagement_orchestrator`:
  `extract_firebase_from_text_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor Firebase text
  wrapper delegates Firebase URL pattern binding, API key regex/encryption
  callback binding, storage bucket regex/normalizer binding, ordered match-entry
  callback execution, project id dedupe, RTDB URL carry-forward behavior, source
  file/extract path forwarding, `bundle_id=None`, storage bucket forwarding, and
  project factory construction. Verification: compile/Ruff passed; artifact
  processor runtime coverage passed (`80 passed`, with `PROCESSOR_IDENTIFIER`
  set).
- [x] Extract artifact queue Terraform state payload-family adapter wiring out
  of `forge.engagement_orchestrator`:
  `terraform_state_payload_family_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor Terraform
  state payload family wrapper delegates structured payload callback forwarding,
  text payload callback forwarding, text/source-file/member-name argument
  forwarding, returned payload tuple lists, and empty-list behavior for unknown
  families. Verification: compile/Ruff passed; artifact processor runtime
  coverage passed (`81 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue Terraform state text payload adapter wiring out of
  `forge.engagement_orchestrator`:
  `terraform_state_text_payloads_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor Terraform
  state text payload wrapper delegates blank-text suppression, source file
  forwarding, member name forwarding, raw text preservation, and returned payload
  tuple shape. Verification: compile/Ruff passed; artifact processor runtime
  coverage passed (`82 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue Terraform state structured payload adapter wiring
  out of `forge.engagement_orchestrator`:
  `terraform_state_structured_payloads_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor Terraform
  state structured payload wrapper delegates structured payload text callback
  forwarding, empty payload suppression, source file forwarding,
  `#tfstate-structured` member-name suffixing, structured payload forwarding,
  and returned payload tuple shape. Verification: compile/Ruff passed; artifact
  processor runtime coverage passed (`83 passed`, with `PROCESSOR_IDENTIFIER`
  set).
- [x] Extract artifact queue Terraform state structured payload text adapter
  wiring out of `forge.engagement_orchestrator`:
  `terraform_state_structured_payload_text_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor Terraform state
  structured payload text wrapper delegates non-object JSON suppression,
  resource-value iterator callback binding, ordered resource candidate callback
  execution, structured candidate entry callback execution, invalid entry
  suppression, dedupe by lowered value, insertion ordering, newline joining, and
  empty output behavior. Verification: compile/Ruff passed; artifact processor
  runtime coverage passed (`85 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue Terraform block assignments adapter wiring out of
  `forge.engagement_orchestrator`:
  `terraform_block_assignments_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor Terraform block
  assignments wrapper delegates block text string coercion, splitline
  enumeration, assignment-line parser callback binding, ordered batch callback
  execution, invalid entry suppression, later duplicate-key overwrite behavior,
  empty input behavior, and returned assignment dictionary shape. Verification:
  compile/Ruff passed; artifact processor runtime coverage passed (`87 passed`,
  with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue Terraform assignment line parser wiring out of
  `forge.engagement_orchestrator`:
  `terraform_assignment_line_entry_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor Terraform
  assignment line wrapper delegates blank/comment line suppression,
  `#`/`//`/`/*`/`*` comment-prefix handling, quoted-value-only assignment
  matching, key lowercasing, surrounding value whitespace stripping, empty
  key/value suppression, non-assignment suppression, and returned `(key, value)`
  tuple shape. Verification: compile/Ruff passed; artifact processor runtime
  coverage passed (`89 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue Terraform text block iterator wiring out of
  `forge.engagement_orchestrator`:
  `iter_terraform_text_blocks_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor Terraform text
  block iterator wrapper delegates injected block-start regex binding, text
  string coercion, splitline scanning, skipped non-block lines, lowercased
  resource type extraction, brace-depth accounting, nested brace handling, block
  text newline joining, unclosed block retention, multiple block ordering, and
  returned `(resource_type, block_text)` tuple list shape. Verification:
  compile/Ruff passed; artifact processor runtime coverage passed (`91 passed`,
  with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue Terraform structured candidate entry wiring out of
  `forge.engagement_orchestrator`:
  `terraform_structured_candidate_entry_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor Terraform
  structured candidate wrapper delegates candidate string coercion, surrounding
  whitespace trimming, empty candidate suppression, lowered value generation,
  original-trimmed candidate retention, returned `(candidate, lowered)` tuple
  shape, and compatibility with both Terraform state/text ordered batch
  normalization callers. Verification: compile/Ruff passed; artifact processor
  runtime coverage passed (`93 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue Terraform text structured payload coordinator
  wiring out of `forge.engagement_orchestrator`:
  `terraform_text_structured_payload_text_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor Terraform text
  structured payload wrapper delegates text-block iterator callback binding,
  text-block candidate callback binding, backend config candidate callback
  binding, terragrunt remote-state callback binding, source-hint predicate
  callback binding, ordered batch execution for block candidates and final
  candidate normalization, backend candidate inclusion for backend/terragrunt
  hints, terragrunt candidate inclusion for terragrunt hints only, invalid entry
  suppression, first-seen dedupe by lowered value, candidate ordering, newline
  joining, empty output behavior, and compatibility with existing Terraform text
  payload callers. Verification: compile/Ruff passed; artifact processor
  runtime coverage passed (`95 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue Terraform text block candidate wiring out of
  `forge.engagement_orchestrator`:
  `terraform_text_block_candidate_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor Terraform text
  block candidate wrapper delegates Terraform block assignment callback binding,
  empty assignment suppression, AWS S3 bucket normalization and validation,
  DigitalOcean Spaces bucket/region normalization and validation, GCS
  name/bucket fallback and validation, Firebase project/project_id/name fallback
  and validation, Azure container/account validation, unknown resource
  suppression, invalid candidate suppression, and returned URL candidate shapes.
  Verification: compile/Ruff passed; artifact processor runtime coverage passed
  (`98 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue DigitalOcean Spaces endpoint URL wiring out of
  `forge.engagement_orchestrator`:
  `digitalocean_spaces_url_from_endpoint_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor DigitalOcean
  Spaces endpoint wrapper delegates injected endpoint-host regex binding, bucket
  lowercasing/trimming, bucket validation, endpoint trimming and trailing slash
  stripping, implicit `https://` parsing for schemeless endpoints, hostname
  lowercasing/trailing-dot stripping, non-matching endpoint suppression,
  empty-region suppression, invalid input suppression, and returned
  `https://{bucket}.{region}.digitaloceanspaces.com` URL shape. Verification:
  compile/Ruff passed; artifact processor runtime coverage passed (`100 passed`,
  with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue Terraform backend config candidate wiring out of
  `forge.engagement_orchestrator`:
  `terraform_backend_config_candidates_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor Terraform
  backend config wrapper delegates Terraform assignment callback binding, empty
  assignment suppression, bucket normalization and validation, DigitalOcean
  endpoint callback binding and priority, S3 fallback key detection, GCS key
  detection, Azure account/container fallback handling, Azure URL callback
  binding, invalid bucket suppression, candidate ordering, empty output
  behavior, and returned candidate list shape. Verification: compile/Ruff
  passed; artifact processor runtime coverage passed (`103 passed`, with
  `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue Terragrunt remote state block scanner wiring out of
  `forge.engagement_orchestrator`:
  `iter_terragrunt_remote_state_blocks_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor Terragrunt
  remote state block wrapper delegates string coercion, splitline scanning,
  case-insensitive `remote_state` block matching, non-block line skipping,
  brace-depth accounting, nested brace handling, newline joining, unclosed block
  retention, multiple block ordering, and returned block text list shape.
  Verification: compile/Ruff passed; artifact processor runtime coverage passed
  (`105 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue Terragrunt remote state backend candidate wiring
  out of `forge.engagement_orchestrator`:
  `terragrunt_remote_state_backend_candidates_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor Terragrunt
  remote state backend wrapper delegates remote-state block iterator callback
  binding, Terraform backend candidate callback binding, ordered batch
  execution, default empty-list factory behavior, candidate string
  coercion/trimming, empty candidate suppression, first-seen case-insensitive
  dedupe, batch flattening, candidate ordering, empty block behavior, and
  returned candidate list shape. Verification: compile/Ruff passed; artifact
  processor runtime coverage passed (`107 passed`, with `PROCESSOR_IDENTIFIER`
  set).
- [x] Extract artifact queue Bicep text block scanner wiring out of
  `forge.engagement_orchestrator`:
  `iter_bicep_text_blocks_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor Bicep block
  scanner wrapper delegates injected Bicep resource-start regex binding, text
  string coercion, splitline scanning, skipped non-block lines, lowercased
  resource type extraction, brace-depth accounting, nested brace handling, block
  text newline joining, unclosed block retention, multiple block ordering, and
  returned `(resource_type, block_text)` tuple list shape. Verification:
  compile/Ruff passed; artifact processor runtime coverage passed (`109 passed`,
  with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue Bicep block assignment wiring out of
  `forge.engagement_orchestrator`:
  `bicep_block_assignments_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor Bicep block
  assignment wrapper delegates block text string coercion, splitline
  enumeration, Bicep assignment-line parser callback binding, ordered batch
  callback execution, invalid entry suppression, later duplicate-key overwrite
  behavior, empty input behavior, and returned assignment dictionary shape.
  Verification: compile/Ruff passed; artifact processor runtime coverage passed
  (`111 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue Bicep assignment-line parser out of
  `forge.engagement_orchestrator`:
  `bicep_assignment_line_entry_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor Bicep
  assignment-line wrapper delegates blank line suppression, `//`/`/*`/`*`
  comment-prefix handling, quoted-value-only assignment matching, key
  lowercasing, surrounding value whitespace stripping, empty key/value
  suppression, non-assignment suppression, and returned `(key, value)` tuple
  shape. Verification: compile/Ruff passed; artifact processor runtime coverage
  passed (`113 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue Bicep text structured payload coordinator out of
  `forge.engagement_orchestrator`:
  `bicep_text_structured_payload_text_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor Bicep text
  payload wrapper delegates text-block iterator callback binding, text-block
  candidate callback binding, structured candidate normalization callback
  binding, ordered batch execution for block candidates and final candidate
  normalization, invalid entry suppression, first-seen dedupe by lowered value,
  candidate ordering, newline joining, empty output behavior, and compatibility
  with existing Bicep text payload callers. Verification: compile/Ruff passed;
  artifact processor runtime coverage passed (`115 passed`, with
  `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue Bicep text block candidate conversion out of
  `forge.engagement_orchestrator`:
  `bicep_text_block_candidate_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor Bicep text
  block candidate wrapper delegates Bicep assignment callback binding,
  resource-type/block-text unpacking, empty assignment suppression,
  `type`/`properties` mapping construction, assignment flattening into the
  mapping, YAML normalization callback binding, IaC resource candidate callback
  binding, first-candidate return behavior, no-candidate empty output behavior,
  and compatibility with existing Bicep text structured payload callers.
  Verification: compile/Ruff passed; artifact processor runtime coverage passed
  (`117 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue Azure Blob URL helper out of
  `forge.engagement_orchestrator`:
  `azure_blob_url_from_parts_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor Azure Blob
  URL wrapper delegates account/container string coercion, trimming,
  lowercasing, `[a-z0-9-]{3,24}` account validation, `[^/?#]+` container
  validation, invalid account/container suppression, and returned
  `https://{account}.blob.core.windows.net/{container}` URL shape.
  Verification: compile/Ruff passed; artifact processor runtime coverage passed
  (`119 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract artifact queue Azure Blob composite-name helper out of
  `forge.engagement_orchestrator`:
  `azure_blob_parts_from_composite_name_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor Azure Blob
  composite-name wrapper delegates composite value string coercion,
  slash-separated segment parsing, whitespace trimming, empty segment filtering,
  lowercasing, first/last segment return behavior for three-or-more parts,
  short-value suppression, and returned `(account, container)` tuple shape.
  Verification: compile/Ruff passed; artifact processor runtime coverage passed
  (`121 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor IaC Azure Blob candidate branch out of
  `forge.engagement_orchestrator`:
  `iac_resource_azure_blob_candidate_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor IaC resource
  candidate method delegates Azure type-hint gating,
  `storageAccountName`/`accountName`/`account` lookup ordering,
  `containerName`/`container`/`name` lookup ordering, account/container
  lowercasing, Azure Blob URL callback binding, composite `name` fallback
  callback binding, no-candidate empty output behavior, and compatibility with
  existing IaC resource candidate callers. Verification: compile/Ruff passed;
  artifact processor runtime coverage passed (`124 passed`, with
  `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor IaC Firebase candidate branch out of
  `forge.engagement_orchestrator`:
  `iac_resource_firebase_candidate_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor IaC resource
  candidate method delegates Firebase type-hint gating,
  `projectId`/`project-id`/`project_id`/`project`/`name` lookup ordering,
  project-ref validation callback binding, invalid project suppression, returned
  `https://{project_ref}.firebaseio.com` URL shape, and compatibility with
  existing IaC resource candidate callers. Verification: compile/Ruff passed;
  artifact processor runtime coverage passed (`126 passed`, with
  `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor IaC Supabase candidate branch out of
  `forge.engagement_orchestrator`:
  `iac_resource_supabase_candidate_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor IaC resource
  candidate method delegates Supabase type-hint gating,
  `projectRef`/`project-ref`/`project_ref`/`ref`/`name` lookup ordering,
  project-ref validation callback binding, invalid project suppression, returned
  `https://{project_ref}.supabase.co` URL shape, and compatibility with existing
  IaC resource candidate callers. Verification: compile/Ruff passed; artifact
  processor runtime coverage passed (`128 passed`, with `PROCESSOR_IDENTIFIER`
  set).
- [x] Extract ArtifactQueueProcessor IaC AWS S3 candidate branch out of
  `forge.engagement_orchestrator`:
  `iac_resource_s3_candidate_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor IaC resource
  candidate method delegates `aws::s3::bucket`/`aws:s3`/`aws.s3` type-hint
  gating, `bucketName`/`bucket-name`/`bucket_name`/`bucket`/`name` lookup
  ordering, bucket validation callback binding, `[a-z0-9.-]{3,63}` regex
  validation, invalid bucket suppression, returned `s3://{bucket}` URL shape,
  and compatibility with existing IaC resource candidate callers. Verification:
  compile/Ruff passed; artifact processor runtime coverage passed (`130 passed`,
  with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor IaC GCS candidate branch out of
  `forge.engagement_orchestrator`:
  `iac_resource_gcs_candidate_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor IaC resource
  candidate method delegates
  `gcp:storage`/`google.storage`/`google::cloud::storage`/`google_storage_bucket`
  type-hint gating, `bucketName`/`bucket-name`/`bucket_name`/`bucket`/`name`
  lookup ordering, bucket validation callback binding, invalid bucket
  suppression, returned `gs://{bucket}` URL shape, and compatibility with
  existing IaC resource candidate callers. Verification: compile/Ruff passed;
  artifact processor runtime coverage passed (`132 passed`, with
  `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor IaC DigitalOcean Spaces candidate branch
  out of `forge.engagement_orchestrator`:
  `iac_resource_digitalocean_spaces_candidate_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor IaC resource
  candidate method delegates DigitalOcean/space type-hint gating,
  `bucketName`/`bucket-name`/`bucket_name`/`bucket`/`name` lookup ordering,
  bucket validation callback binding,
  `region`/`spaceRegion`/`space-region`/`space_region` lookup ordering,
  `[a-z0-9-]{2,32}` region validation, invalid bucket/region suppression,
  returned `https://{bucket}.{region}.digitaloceanspaces.com` URL shape, and
  compatibility with existing IaC resource candidate callers. Verification:
  compile/Ruff passed; artifact processor runtime coverage passed (`134 passed`,
  with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor IaC resource structured candidates
  coordinator out of `forge.engagement_orchestrator`:
  `iac_resource_structured_candidates_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor IaC resource
  candidate method delegates type/resource/kind lookup ordering, empty type-hint
  suppression, `properties`/`config`/`inputs` child lookup, normalized property
  override behavior, AWS S3/GCS/DigitalOcean/Firebase/Supabase/Azure provider
  ordering, provider callback binding, non-empty candidate collection semantics,
  and compatibility with existing IaC resource candidate callers. Verification:
  compile/Ruff passed; artifact processor runtime coverage passed (`136 passed`,
  with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor key-value scalar parsing out of
  `forge.engagement_orchestrator`: `parse_key_value_scalar_for_processor()` now
  lives in `forge.orchestration.artifact_processor_runtime`; the processor
  key-value scalar wrapper delegates single/double quote stripping, triple quote
  stripping, inline `#`/`;`/`//` comment suffix removal for unquoted values,
  trailing comma removal, whitespace trimming, empty-value suppression, and
  compatibility with existing artifact key-value parser callers. Verification:
  compile/Ruff passed; artifact processor runtime coverage passed (`137 passed`,
  with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor key-value section path normalization out
  of `forge.engagement_orchestrator`:
  `key_value_section_path_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor key-value
  section path wrapper delegates bracket stripping, single/double quote removal,
  dot/slash path splitting, lowercasing, `[^a-z0-9_-]` character stripping,
  empty-part suppression, empty-input behavior, tuple return shape, and
  compatibility with existing artifact key-value line parser callers.
  Verification: compile/Ruff passed; artifact processor runtime coverage passed
  (`138 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor key-value line classification out of
  `forge.engagement_orchestrator`: `key_value_line_entry_for_processor()` now
  lives in `forge.orchestration.artifact_processor_runtime`; the processor
  key-value line wrapper delegates blank/comment/JSON-ish structural-line
  suppression, single/double bracket section parsing, assignment/export regex
  behavior, section-path callback binding, scalar parser callback binding, empty
  raw key/value/path suppression, returned section tuple shape, returned
  assignment tuple shape, and compatibility with existing key-value entry
  aggregation callers. Verification: compile/Ruff passed; artifact processor
  runtime coverage passed (`140 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor key-value entries aggregation out of
  `forge.engagement_orchestrator`: `parse_key_value_entries_for_processor()` now
  lives in `forge.orchestration.artifact_processor_runtime`; the processor
  key-value entries wrapper delegates ordered batch callback binding, line-entry
  callback binding, default `None` factory behavior, current section-path
  tracking, malformed line-entry suppression, assignment tuple coercion, input
  line ordering, empty-text behavior, and compatibility with existing key-value
  structured payload callers. Verification: compile/Ruff passed; artifact
  processor runtime coverage passed (`142 passed`, with
  `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor key-value structured input building out of
  `forge.engagement_orchestrator`:
  `key_value_structured_inputs_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the key-value payload method
  delegates env/section/direct input construction while preserving env key
  uppercasing, hyphen-to-underscore env aliases, section map insertion order,
  normalized and fingerprinted section keys, section-prefixed env aliases,
  direct `http`/`https`/`s3`/`gs` URL capture, lowercased email capture,
  case-insensitive direct dedupe, returned input tuple shape, and compatibility
  with the existing key-value payload candidate pipeline. Verification:
  compile/Ruff passed; artifact processor runtime coverage passed (`144 passed`,
  with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor key-value structured payload output
  assembly out of `forge.engagement_orchestrator`:
  `key_value_structured_payload_lines_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the key-value payload method
  delegates structured candidate job callback binding, candidate validation
  callback binding, batch callback binding, family/direct preparation callbacks,
  append-entry callback binding, ordered batch default factories, malformed
  append-entry suppression, case-insensitive first-seen dedupe, final line
  ordering, empty input behavior, newline-joined return shape, and compatibility
  with the existing key-value payload pipeline. Verification: compile/Ruff
  passed; artifact processor runtime coverage passed (`146 passed`, with
  `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor key-value structured payload coordinator
  out of `forge.engagement_orchestrator`:
  `key_value_structured_payload_text_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the key-value payload method
  delegates config-name gating callback binding, parse-entry callback binding,
  empty-entry suppression, structured input callback binding, structured line
  callback binding, returned text shape, non-config empty behavior, and
  compatibility with existing artifact structured payload dispatch.
  Verification: compile/Ruff passed; artifact processor runtime coverage passed
  (`148 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor JSONC comment stripping out of
  `forge.engagement_orchestrator`: `strip_jsonc_comments_for_processor()` now
  lives in `forge.orchestration.artifact_processor_runtime`; the processor
  wrapper delegates line comment removal, block comment removal, newline
  preservation, string literal protection, escape handling, unterminated block
  behavior, returned text shape, and compatibility with existing JSONC document
  parsing callers. Verification: compile/Ruff passed; artifact processor
  runtime coverage passed (`150 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor JSON line document parsing out of
  `forge.engagement_orchestrator`: `json_document_from_line_for_processor()`
  now lives in `forge.orchestration.artifact_processor_runtime`; the processor
  wrapper delegates safe loader callback binding, whitespace trimming before
  parsing, empty-line suppression, object/list return behavior,
  scalar/non-container suppression, invalid-line suppression, and compatibility
  with existing JSON document parsing callers. Verification: compile/Ruff
  passed; artifact processor runtime coverage passed (`152 passed`, with
  `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor JSON documents-from-text coordination out
  of `forge.engagement_orchestrator`: `json_documents_from_text_for_processor()`
  now lives in `forge.orchestration.artifact_processor_runtime`; the processor
  wrapper delegates config/container-image source gating callback binding,
  whitespace trimming, empty-text suppression, JSONC suffix detection, JSONC
  comment stripping callback binding, direct safe JSON parse priority,
  object/list direct parse return behavior, JSONL ordered batch callback
  binding, per-line parser callback binding, object/list line filtering, empty
  fallback behavior, and compatibility with existing JSON structured payload
  callers. Verification: compile/Ruff passed; artifact processor runtime
  coverage passed (`155 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor JSON structured payload coordination out
  of `forge.engagement_orchestrator`:
  `json_structured_payload_text_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates JSON document callback binding, Docker auth predicate/candidate
  callback binding, ECS task callback binding, Lambda callback binding, Amplify
  callback/source-hint binding, generic structured document line callback
  binding, ordered line batch callback binding, ordered batch default factories,
  case-insensitive first-seen dedupe, final line ordering, empty-document
  behavior, newline-joined return shape, and compatibility with existing
  artifact structured payload dispatch. Verification: compile/Ruff passed;
  artifact processor runtime coverage passed (`157 passed`, with
  `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor Docker auth JSON predicate out of
  `forge.engagement_orchestrator`:
  `json_document_looks_like_docker_auth_config_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates dict-only suppression, source-name normalization,
  `.dockercfg`/`.dockerconfigjson` filename matches, YAML-normalized mapping
  callback binding, `auths`/`credhelpers`/`credsstore`/`credstore` key
  detection, no-match false behavior, and compatibility with existing JSON
  structured payload Docker auth dispatch. Verification: compile/Ruff passed;
  artifact processor runtime coverage passed (`159 passed`, with
  `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor `.firebaserc` project URL conversion out
  of `forge.engagement_orchestrator`:
  `firebaserc_project_ref_url_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates string coercion, YAML project-ref validator callback binding,
  invalid-ref suppression, realtime database URL formatting, and compatibility
  with existing `.firebaserc` structured payload extraction. Verification:
  compile/Ruff passed; artifact processor runtime coverage passed (`161
  passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor `.firebaserc` structured payload
  coordinator out of `forge.engagement_orchestrator`:
  `firebaserc_structured_payload_text_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates `.firebaserc` filename gating, safe JSON loader callback binding,
  dict-only payload handling, `projects` values traversal, existing `targets`
  key traversal behavior, ordered project URL callback binding, ordered batch
  default factory binding, first-seen duplicate suppression, invalid URL
  suppression, newline-joined return shape, and compatibility with artifact
  structured payload dispatch. Verification: compile/Ruff passed; artifact
  processor runtime coverage passed (`164 passed`, with `PROCESSOR_IDENTIFIER`
  set).
- [x] Extract ArtifactQueueProcessor observability document candidate
  normalization out of `forge.engagement_orchestrator`:
  `observability_structured_document_candidates_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates label discard behavior, observability node callback binding,
  inherited `http` scheme, worker-enabled traversal flag, string coercion,
  whitespace trimming, case-insensitive first-seen dedupe, empty candidate
  suppression, final candidate ordering, and compatibility with existing
  observability structured payload extraction. Verification: compile/Ruff
  passed; artifact processor runtime coverage passed (`166 passed`, with
  `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor observability child candidate dispatch out
  of `forge.engagement_orchestrator`:
  `observability_child_candidate_values_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates child index discard behavior, child payload propagation, inherited
  scheme callback binding, `use_workers=False` recursion guard, returned list
  passthrough, and compatibility with existing observability dict/list
  traversal. Verification: compile/Ruff passed; artifact processor runtime
  coverage passed (`167 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor observability endpoint job flattening out
  of `forge.engagement_orchestrator`:
  `observability_endpoint_jobs_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates `str`/`int`/`float` endpoint collection, nested list recursion,
  per-list slice cap, total job cap, tuple shape `(raw_value, scheme)`,
  inherited scheme propagation, dict/non-scalar suppression, first-seen
  traversal order, and compatibility with existing observability target URL
  conversion. Verification: compile/Ruff passed; artifact processor runtime
  coverage passed (`170 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor observability scheme normalization out of
  `forge.engagement_orchestrator`:
  `observability_scheme_candidate_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates string coercion, whitespace trimming, lowercase normalization,
  allowed `http`/`https` return values, empty fallback for unsupported values,
  and compatibility with observability inherited-scheme and target URL callers.
  Verification: compile/Ruff passed; artifact processor runtime coverage passed
  (`172 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor observability target URL conversion out of
  `forge.engagement_orchestrator`:
  `observability_target_url_candidate_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates URL normalizer callback binding, seed classifier callback binding,
  scheme candidate callback binding, explicit URL handling, host normalization,
  invalid target suppression, `localhost`/`example.com` filtering, port range
  checks, fallback `http` scheme behavior, path preservation, and compatibility
  with existing observability endpoint discovery. Verification: compile/Ruff
  passed; artifact processor runtime coverage passed (`175 passed`, with
  `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor observability structured payload
  coordinator out of `forge.engagement_orchestrator`:
  `observability_structured_payload_text_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates label callback binding, structured-label collection binding, YAML
  loader callback binding, document candidate callback binding, ordered line
  batch callback binding, ordered batch callback binding, YAML unavailable
  behavior, parse-error fallback, first-seen dedupe, final candidate ordering,
  newline-joined return shape, and compatibility with artifact structured
  payload dispatch. Verification: compile/Ruff passed; artifact processor
  runtime coverage passed (`178 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor edge proxy structured payload coordinator
  out of `forge.engagement_orchestrator`:
  `edge_proxy_structured_payload_text_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates edge proxy label callback binding, structured-label collection
  binding, line candidate callback binding, ordered line batch callback binding,
  ordered batch callback binding, line slicing, first-seen dedupe, final
  candidate ordering, newline-joined return shape, and compatibility with
  artifact structured payload dispatch. Verification: compile/Ruff passed;
  artifact processor runtime coverage passed (`181 passed`, with
  `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor edge proxy endpoint URL normalization out
  of `forge.engagement_orchestrator`:
  `edge_proxy_endpoint_url_candidate_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates API-spec URL candidate callback binding, default scheme validation,
  unsupported protocol suppression, relative target suppression, grpc/grpcs/h2c
  scheme translation, schemeless host handling, returned URL shape, and
  compatibility with edge proxy, orchestration, and API client endpoint parsing
  callers. Verification: compile/Ruff passed; artifact processor runtime
  coverage passed (`184 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor edge proxy line URL parsing out of
  `forge.engagement_orchestrator`:
  `edge_proxy_line_url_candidates_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates injected regex pattern binding, endpoint URL callback binding, Host
  rule parsing, keyed-value parsing, marker suppression, fallback line scanning,
  YAML value trimming, first-seen dedupe, returned list shape, and compatibility
  with edge proxy, orchestration, and API structured payload callers.
  Verification: compile/Ruff passed; artifact processor runtime coverage passed
  (`187 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor orchestration annotation endpoint key
  classification out of `forge.engagement_orchestrator`:
  `orchestration_annotation_endpointish_key_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates marker matching, suffix matching, false behavior for unrelated
  keys, and compatibility with orchestration annotation endpoint discovery.
  Verification: compile/Ruff passed; artifact processor runtime coverage passed
  (`189 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor orchestration endpoint value flattening out
  of `forge.engagement_orchestrator`:
  `orchestration_endpoint_values_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates scalar coercion, list-only recursion, cap behavior, empty filtering,
  returned list shape, and compatibility with orchestration endpoint URL
  candidate extraction. Verification: compile/Ruff passed; artifact processor
  runtime coverage passed (`192 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor orchestration text value flattening out of
  `forge.engagement_orchestrator`:
  `orchestration_text_values_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates string preservation, list/dict traversal, cap behavior, empty
  filtering, returned list shape, and compatibility with orchestration manifest
  text extraction. Verification target: compile/Ruff plus artifact processor
  runtime coverage (`195 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor Kopia structured payload parsing out of
  `forge.engagement_orchestrator`:
  `kopia_structured_payload_text_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates source-name gating, safe JSON loading, storage/config merging,
  endpoint extraction, S3/GCS/Azure bucket URL derivation, dedupe, empty
  suppression, and newline-joined return shape. Verification target:
  compile/Ruff plus artifact processor runtime coverage (`198 passed`, with
  `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor Duplicacy preferences parsing out of
  `forge.engagement_orchestrator`:
  Duplicacy preferences helpers now live in
  `forge.orchestration.artifact_processor_runtime`; the processor wrappers
  delegate source gating, hinted entry detection, JSON entry selection, storage
  URL extraction, S3/GCS/Azure URL normalization, cloud endpoint preservation,
  nested storage context merging, dedupe, and newline-joined return shape.
  Verification target: compile/Ruff plus artifact processor runtime coverage
  (`202 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor Borg repository candidate parsing out of
  `forge.engagement_orchestrator`:
  Borg repository helpers now live in
  `forge.orchestration.artifact_processor_runtime`; the processor wrappers
  delegate template/whitespace suppression, S3 endpoint and bucket extraction,
  GCS bucket extraction, Azure Blob URL derivation from context, SSH/SFTP
  userinfo stripping, SCP-style repository normalization, Windows local path
  suppression, and candidate dedupe. Verification target: compile/Ruff plus
  artifact processor runtime coverage (`206 passed`, with
  `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor Borg structured payload parsing out of
  `forge.engagement_orchestrator`:
  Borg structured payload and env-map helpers now live in
  `forge.orchestration.artifact_processor_runtime`; the processor wrappers
  delegate source-kind gating, raw location line extraction, key-value parsing,
  context/env-map construction, repository-key detection, ordered candidate
  expansion, `BORG_*` env repository fallback, final dedupe, and newline-joined
  return shape. Verification target: compile/Ruff plus artifact processor
  runtime coverage (`210 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor Duplicati target URL parsing out of
  `forge.engagement_orchestrator`:
  Duplicati target URL helpers now live in
  `forge.orchestration.artifact_processor_runtime`; the processor wrappers
  delegate target key selection from env maps, HTTP managed URL preservation,
  S3 endpoint and bucket extraction, GCS bucket extraction, Azure Blob URL
  derivation from auth/account context, empty target suppression, and bucket
  parsing. Verification target: compile/Ruff plus artifact processor runtime
  coverage (`214 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor Duplicati structured payload parsing out
  of `forge.engagement_orchestrator`:
  Duplicati structured payload helpers now live in
  `forge.orchestration.artifact_processor_runtime`; the processor wrappers
  delegate key-value parsing, nested settings/options/metadata parameter
  expansion, env-map normalization, Duplicati/SQLite source gating, target
  candidate expansion, final dedupe, and newline-joined return shape.
  Verification target: compile/Ruff plus artifact processor runtime coverage
  (`219 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor AppVeyor CI payload parsing out of
  `forge.engagement_orchestrator`:
  AppVeyor CI text, document candidate, and mapping-detection helpers now live
  in `forge.orchestration.artifact_processor_runtime`; the processor wrappers
  delegate source-label gating, optional YAML dependency suppression, safe YAML
  document loading, AppVeyor mapping detection, pipeline name normalization,
  fallback pipeline naming, ordered candidate processing, dedupe, and
  newline-joined return shape. Verification target: compile/Ruff plus artifact
  processor runtime coverage (`223 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor Gitpod payload wrapper parsing out of
  `forge.engagement_orchestrator`:
  Gitpod structured text, document wrapper, and mapping-detection helpers now
  live in `forge.orchestration.artifact_processor_runtime`; the processor
  wrappers delegate source-label gating, optional YAML dependency suppression,
  safe YAML document loading, document type suppression, Gitpod mapping
  detection, ordered candidate batch processing, dedupe, and newline-joined
  return shape. Verification target: compile/Ruff plus artifact processor
  runtime coverage (`227 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor Gitpod config candidate parsing out of
  `forge.engagement_orchestrator`:
  Gitpod config candidate and repository URL normalization helpers now live in
  `forge.orchestration.artifact_processor_runtime`; the processor wrappers
  delegate Gitpod mapping detection, explicit-registry image extraction,
  `additionalRepositories` string/dict handling, GitOps repository delegate
  precedence, GitHub/GitLab/Bitbucket host-path fallback normalization,
  repository suffix stripping, ordered candidate processing, and dedupe.
  Verification target: compile/Ruff plus artifact processor runtime coverage
  (`231 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor GoReleaser scalar/blob helper parsing out
  of `forge.engagement_orchestrator`:
  GoReleaser scalar flattening, templated image callback binding, and blob
  bucket URL normalization helpers now live in
  `forge.orchestration.artifact_processor_runtime`; the processor wrappers
  delegate bounded scalar traversal, explicit-registry image template
  extraction, S3/GCS provider handling, bucket validation callbacks, and
  empty/unsupported suppression. Verification: compile/Ruff passed; artifact
  processor runtime coverage passed (`234 passed`, with
  `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor GoReleaser config classification out of
  `forge.engagement_orchestrator`:
  `yaml_mapping_looks_like_goreleaser_config_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates root marker matching, docker/blob marker pairing, path-hint
  fallback behavior, and unrelated-map suppression. Verification: compile/Ruff
  passed; artifact processor runtime coverage passed (`235 passed`, with
  `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor GoReleaser structured-candidate
  coordination out of `forge.engagement_orchestrator`:
  `yaml_goreleaser_config_structured_candidates_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates classifier gating, root traversal with `use_workers=True`,
  candidate trimming, first-seen ordering, case-insensitive dedupe, and
  empty/unrelated config suppression. Verification: compile/Ruff passed;
  artifact processor runtime coverage passed (`236 passed`, with
  `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor GoReleaser child-node dispatch out of
  `forge.engagement_orchestrator`:
  `yaml_goreleaser_child_candidate_values_for_node_for_processor()` now lives
  in `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates key fingerprint callback binding, docker/dockers/dockermanifests
  image-template gating, image candidate ordering, child-path propagation,
  recursive traversal with `use_workers=False`, and non-docker image
  suppression. Verification: compile/Ruff passed; artifact processor runtime
  coverage passed (`238 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor GoReleaser recursive candidate walker out
  of `forge.engagement_orchestrator`:
  `yaml_goreleaser_candidate_values_for_node_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates blob-path candidate ordering, ordered child-job payload shape,
  worker versus local traversal behavior, list item cap, recursive
  `use_workers=False` behavior, and scalar empty results. Verification:
  compile/Ruff passed; artifact processor runtime coverage passed
  (`240 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor GoReleaser child-job adapter out of
  `forge.engagement_orchestrator`:
  `yaml_goreleaser_child_candidate_values_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates ignored index behavior, `(key, child, path)` unpacking, and
  child-node callback binding. Verification: compile/Ruff passed; artifact
  processor runtime coverage passed (`241 passed`, with
  `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor Git repository suffix stripping out of
  `forge.engagement_orchestrator`:
  `strip_git_repository_suffix_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor static
  wrapper delegates string coercion, whitespace trimming, trailing slash
  stripping, case-insensitive `.git` suffix removal, and no-suffix passthrough.
  Verification: compile/Ruff passed; artifact processor runtime coverage
  passed (`242 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor GitOps repository child-job adapter out of
  `forge.engagement_orchestrator`:
  `yaml_gitops_repository_child_values_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates ignored index behavior, child extraction, and recursive repository
  value traversal with `use_workers=False`. Verification: compile/Ruff passed;
  artifact processor runtime coverage passed (`243 passed`, with
  `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor GitOps repository candidate normalization
  out of `forge.engagement_orchestrator`:
  `yaml_gitops_repository_candidates_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates quoted-value cleanup, HTTP(S) normalization, OCI/docker image
  candidate handling, git shorthand conversion, SSH/git URL conversion,
  repository suffix stripping, unsupported-value suppression, and
  case-insensitive dedupe through injected callbacks. Verification:
  compile/Ruff passed; artifact processor runtime coverage passed (`245
  passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor GitOps repository mapping candidate
  coordination out of `forge.engagement_orchestrator`:
  `yaml_gitops_repository_candidates_from_mapping_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates worker-enabled repository value collection, ordered candidate batch
  conversion, first-seen ordering, empty batch handling, and case-insensitive
  cross-value dedupe through injected callbacks. Verification: compile/Ruff
  passed; artifact processor runtime coverage passed (`246 passed`, with
  `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor GitOps repository value walker out of
  `forge.engagement_orchestrator`:
  `yaml_gitops_repository_values_for_node_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates direct repo key extraction, repository `name`/`value` source URL
  hints, dict/list child job construction, worker traversal, and local
  recursion through injected YAML/callback helpers. Verification: compile/Ruff
  passed; artifact processor runtime coverage passed (`248 passed`, with
  `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor Flux source-ref candidate mapping out of
  `forge.engagement_orchestrator`:
  `yaml_flux_source_ref_candidates_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates Flux kind-to-family mapping, optional namespace/name identifier
  formatting, and missing/unknown reference suppression through injected YAML
  helpers. Verification: compile/Ruff passed; artifact processor runtime
  coverage passed (`250 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor Flux bucket structured candidate mapping
  out of `forge.engagement_orchestrator`:
  `yaml_flux_bucket_structured_candidates_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates empty-spec/bucket suppression, GCP `gs://`, Azure Blob,
  DigitalOcean Spaces, and S3 fallback behavior through injected YAML, bucket,
  segment, and endpoint-regex callbacks. Verification: compile/Ruff passed;
  artifact processor runtime coverage passed (`252 passed`, with
  `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor Crossplane manifest detector out of
  `forge.engagement_orchestrator`:
  `yaml_manifest_looks_like_crossplane_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor static
  wrapper delegates API group splitting, lowercasing, `crossplane.io`
  detection, `.upbound.io` suffix detection, and unrelated/empty API
  suppression. Verification: compile/Ruff passed; artifact processor runtime
  coverage passed (`254 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor Crossplane provider-family normalization
  out of `forge.engagement_orchestrator`:
  `crossplane_provider_family_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor static
  wrapper delegates API group splitting, lowercasing,
  AWS/GCP/Azure/Kubernetes/DigitalOcean/Cloudflare precedence, dotted-group
  hyphen fallback, and empty `crossplane` fallback. Verification: compile/Ruff
  passed; artifact processor runtime coverage passed (`256 passed`, with
  `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor Crossplane external-name annotation
  extraction out of `forge.engagement_orchestrator`:
  `yaml_crossplane_external_name_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates metadata/annotations lookup, stripped/lowercase
  `crossplane.io/external-name` key matching, formatted value return, and
  missing/non-matching annotation suppression through injected callbacks.
  Verification: compile/Ruff passed; artifact processor runtime coverage
  passed (`258 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor Crossplane cloud candidate mapping out of
  `forge.engagement_orchestrator`:
  `yaml_crossplane_cloud_candidates_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates AWS S3 bucket candidates, GCP storage bucket candidates, Azure Blob
  container candidates, resource-name fallback, and unsupported/invalid
  suppression through injected YAML/bucket callbacks. Verification:
  compile/Ruff passed; artifact processor runtime coverage passed (`260
  passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor Crossplane structured candidate
  coordination out of `forge.engagement_orchestrator`:
  `yaml_crossplane_structured_candidates_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates provider config, composition/XRD, provider ref, resource, and cloud
  candidate ordering through injected provider/YAML/cloud callbacks.
  Verification: compile/Ruff passed; artifact processor runtime coverage
  passed (`262 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor Kubernetes object identifier formatting
  out of `forge.engagement_orchestrator`:
  `yaml_kubernetes_object_identifier_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates metadata lookup, safe name/namespace segment formatting,
  missing metadata/name suppression, name-only identifiers, and namespaced
  `namespace/name` identifiers through injected YAML callbacks. Verification:
  compile/Ruff passed; artifact processor runtime coverage passed (`264
  passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor ExternalSecret store reference formatting
  out of `forge.engagement_orchestrator`:
  `yaml_external_secret_store_refs_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates ignored object identifier behavior, missing store/name suppression,
  `secret-store://` defaults, and `cluster-secret-store://` handling through
  injected YAML/key callbacks. Verification: compile/Ruff passed; artifact
  processor runtime coverage passed (`266 passed`, with
  `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor ExternalSecret remote-ref entry parsing
  out of `forge.engagement_orchestrator`:
  `yaml_external_secret_remote_ref_entry_keys_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates `data.remoteRef`, `data.remote_ref`, and `dataFrom.extract/find`
  key lookup through injected YAML callbacks while preserving extract/find
  ordering, unknown-family suppression, and missing remote-ref suppression.
  Verification: compile/Ruff passed; artifact processor runtime coverage passed
  (`268 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor ExternalSecret remote-ref key
  coordination out of `forge.engagement_orchestrator`:
  `yaml_external_secret_remote_ref_keys_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates data/dataFrom job collection, ordered batch execution,
  quote/whitespace trimming, case-insensitive dedupe, and first-seen key
  ordering through injected batch and entry-key callbacks. Verification:
  compile/Ruff passed; artifact processor runtime coverage passed (`270
  passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor ExternalSecret provider candidate mapping
  out of `forge.engagement_orchestrator`:
  `yaml_external_secret_provider_candidates_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates AWS/GCP/Azure/Vault/webhook/gitlab candidate emission through
  injected YAML, segment, project, Vault, and URL callbacks while preserving
  candidate ordering and empty-provider suppression. Verification:
  compile/Ruff passed; artifact processor runtime coverage passed (`272
  passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor ExternalSecret reference segment
  sanitization out of `forge.engagement_orchestrator`:
  `yaml_external_secret_ref_segment_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the static processor
  wrapper delegates quote/slash trimming, empty/oversized/whitespace/template
  suppression, and `%` encoding with `/._:@+=-` safe characters. Verification:
  compile/Ruff passed; artifact processor runtime coverage passed (`274
  passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor SOPS section entry selection out of
  `forge.engagement_orchestrator`:
  `yaml_sops_section_entries_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates section alias matching, dict-as-single-entry handling, list dict
  filtering, unsupported-value suppression, and missing-section suppression
  through injected key-fingerprint callbacks. Verification: compile/Ruff
  passed; artifact processor runtime coverage passed (`276 passed`, with
  `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor SOPS metadata entry candidate mapping out
  of `forge.engagement_orchestrator`:
  `yaml_sops_metadata_entry_candidate_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates AWS KMS, GCP KMS, Azure Key Vault, and HashiCorp Vault candidate
  validation through injected reference, regex, URL, and Vault callbacks.
  Verification: compile/Ruff passed; artifact processor runtime coverage
  passed (`278 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor SOPS metadata structured-candidate
  coordination out of `forge.engagement_orchestrator`:
  `yaml_sops_metadata_structured_candidates_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor wrapper
  delegates direct/nested SOPS metadata selection, section job construction,
  ordered candidate batching, quote trimming, dedupe, and first-seen ordering
  through injected SOPS callbacks. Verification: compile/Ruff passed; artifact
  processor runtime coverage passed (`280 passed`, with
  `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor Vault address candidate normalization out
  of `forge.engagement_orchestrator`:
  `yaml_vault_address_candidate_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the static processor
  wrapper delegates URL passthrough and bare-host fallback policy through
  injected URL normalization while preserving invalid-value suppression.
  Verification: compile/Ruff passed; artifact processor runtime coverage
  passed (`282 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor Cloudflare reference validation out of
  `forge.engagement_orchestrator`:
  `cloudflare_valid_ref_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the static processor
  wrapper delegates quote trimming, lowercase normalization, Cloudflare-safe
  identifier syntax, length bounds, and invalid-value suppression.
  Verification: compile/Ruff passed; artifact processor runtime coverage
  passed (`284 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor Cloudflare URI candidate assembly out of
  `forge.engagement_orchestrator`:
  `cloudflare_uri_candidate_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the class processor
  wrapper delegates injected reference validation, invalid-ref suppression,
  and family-specific `cloudflare-{family}://{ref}` formatting.
  Verification: compile/Ruff passed; artifact processor runtime coverage
  passed (`286 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor Cloudflare URI tuple adapter out of
  `forge.engagement_orchestrator`:
  `cloudflare_uri_candidate_entry_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the class processor
  wrapper delegates tuple unpacking, blank-value coercion, injected URI
  candidate formatting, and ordered-batch call behavior.
  Verification: compile/Ruff passed; artifact processor runtime coverage
  passed (`288 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor Cloudflare URI candidate-entry batch
  merge out of `forge.engagement_orchestrator`:
  `cloudflare_uri_candidate_entries_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the structured Cloudflare
  parser delegates ordered local batch invocation, empty-candidate filtering,
  duplicate suppression, and first-seen output order.
  Verification: compile/Ruff passed; artifact processor runtime coverage
  passed (`290 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor Cloudflare structured marker detection
  out of `forge.engagement_orchestrator`:
  `yaml_cloudflare_structured_marker_flags_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the structured Cloudflare
  parser delegates path-hint matching, Worker marker keys, and
  R2/D1/KV/Worker/Pages key-family flags.
  Verification: compile/Ruff passed; artifact processor runtime coverage
  passed (`292 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor Cloudflare R2 candidate-ref selection
  out of `forge.engagement_orchestrator`:
  `yaml_cloudflare_r2_candidate_ref_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the structured Cloudflare
  parser delegates explicit R2 key lookup, Cloudflare-hinted generic
  bucket/name fallback, unhinted generic bucket suppression, and `r2`
  candidate append behavior.
  Verification: compile/Ruff passed; artifact processor runtime coverage
  passed (`295 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor Cloudflare D1 candidate-ref selection
  out of `forge.engagement_orchestrator`:
  `yaml_cloudflare_d1_candidate_ref_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the structured Cloudflare
  parser delegates explicit D1 key lookup, Cloudflare-hinted generic
  database/name fallback, unhinted generic database suppression, and `d1`
  candidate append behavior.
  Verification: compile/Ruff passed; artifact processor runtime coverage
  passed (`298 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor Cloudflare KV candidate-ref selection
  out of `forge.engagement_orchestrator`:
  `yaml_cloudflare_kv_candidate_ref_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the structured Cloudflare
  parser delegates explicit KV namespace lookup, Cloudflare-hinted generic
  namespace/id/name fallback, unhinted generic namespace suppression, and `kv`
  candidate append behavior.
  Verification: compile/Ruff passed; artifact processor runtime coverage
  passed (`301 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor Cloudflare Worker candidate-ref selection
  out of `forge.engagement_orchestrator`:
  `yaml_cloudflare_worker_candidate_ref_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the structured Cloudflare
  parser delegates explicit Worker key lookup, Cloudflare/Worker marker `name`
  fallback, worker/workers/wrangler path-hint gating, ungated generic worker
  suppression, and `worker` candidate append behavior.
  Verification: compile/Ruff passed; artifact processor runtime coverage
  passed (`305 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor Cloudflare Pages candidate-ref selection
  out of `forge.engagement_orchestrator`:
  `yaml_cloudflare_pages_candidate_ref_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the structured Cloudflare
  parser delegates explicit Pages project lookup, Pages path-hint `name`
  fallback, Pages build-output marker fallback, ungated generic project
  suppression, and `pages` candidate append behavior.
  Verification: compile/Ruff passed; artifact processor runtime coverage
  passed (`309 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor Cloudflare structured-candidates
  coordinator out of `forge.engagement_orchestrator`:
  `yaml_cloudflare_structured_candidates_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor method is a
  compatibility wrapper that delegates marker detection, R2/D1/KV/Worker/Pages
  ref ordering, generic-config suppression, and ordered URI candidate batching.
  Verification: compile/Ruff passed; artifact processor runtime coverage
  passed (`311 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor generic YAML candidate merge helpers out
  of `forge.engagement_orchestrator`:
  `yaml_candidate_batch_entries_for_processor()`,
  `yaml_candidate_family_entries_for_processor()`, and
  `yaml_candidate_merge_entry_for_processor()` now live in
  `forge.orchestration.artifact_processor_runtime`; the processor methods are
  compatibility wrappers that preserve batch/family order, candidate string
  stripping, empty-value suppression, and existing ordered local batch call
  sites. Verification: compile/Ruff passed; artifact processor runtime
  coverage passed (`314 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor Restic repository candidate parsing out
  of `forge.engagement_orchestrator`:
  `restic_repository_candidates_from_env_map_for_processor()`,
  `restic_repository_candidates_for_processor()`,
  `restic_s3_repository_candidates_for_processor()`, and
  `restic_bucket_from_pathish_for_processor()` now live in
  `forge.orchestration.artifact_processor_runtime`; the processor methods are
  compatibility wrappers that preserve Restic env lookup, REST URL
  normalization, S3 endpoint/bucket extraction, GCS bucket extraction, Azure
  account/container URL assembly, dedupe, and existing call sites.
  Verification: compile/Ruff passed; artifact processor runtime coverage
  passed (`318 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor environment candidate-family coordinator
  out of `forge.engagement_orchestrator`:
  `yaml_env_candidate_family_for_processor()` now lives in
  `forge.orchestration.artifact_processor_runtime`; the processor method is a
  compatibility wrapper that preserves Firebase/Supabase/S3/GCS/DigitalOcean
  Spaces/Azure env extraction, managed-hosting dedupe, Cloudflare normalization
  delegation, Amplify/Sanity/Docker auth/Restic/Borg/Duplicati delegation,
  env-value filtering, source hints, and existing ordered local batch call
  sites. Verification: compile/Ruff passed; artifact processor runtime
  coverage passed (`322 passed`, with `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor env-entry candidate helpers out of
  `forge.engagement_orchestrator`:
  `yaml_managed_hosting_env_entry_for_processor()` and
  `yaml_env_value_candidate_entry_for_processor()` now live in
  `forge.orchestration.artifact_processor_runtime`; the processor methods are
  compatibility wrappers that preserve managed-hosting marker checks, injected
  cloud URL normalization, email candidate lowering, URL/URI/endpoint/portal/
  base marker handling, direct `http`/`https`/`s3`/`gs` URI preservation, and
  existing env-family call sites. Verification: compile/Ruff passed; artifact
  processor runtime coverage passed (`325 passed`, with
  `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor Docker auth registry/principal helpers
  out of `forge.engagement_orchestrator`:
  `docker_registry_url_candidate_for_processor()`,
  `docker_auth_principal_candidate_for_processor()`,
  `docker_auth_principal_from_auth_field_for_processor()`,
  `docker_auth_entry_principals_for_processor()`,
  `docker_auth_config_auth_entry_candidates_for_processor()`,
  `docker_auth_config_cred_helper_candidates_for_processor()`, and
  `docker_auth_config_legacy_entry_candidates_for_processor()` now live in
  `forge.orchestration.artifact_processor_runtime`; the processor methods are
  compatibility wrappers that preserve registry scheme/host/path normalization,
  wildcard/invalid scheme suppression, email principal lowering, padded base64
  auth decoding, cred-helper registry extraction, metadata-key suppression, and
  existing Docker auth config call sites. Verification: compile/Ruff passed;
  artifact processor runtime coverage passed (`329 passed`, with
  `PROCESSOR_IDENTIFIER` set).
- [x] Extract ArtifactQueueProcessor Docker auth env/config aggregation out of
  `forge.engagement_orchestrator`:
  `docker_auth_structured_candidates_from_env_map_for_processor()`,
  `docker_auth_structured_env_entry_candidates_for_processor()`,
  `env_value_may_hold_docker_auth_for_processor()`, and
  `docker_auth_config_candidates_for_processor()` now live in
  `forge.orchestration.artifact_processor_runtime`; the processor methods are
  compatibility wrappers that preserve Docker/CONTAINER_REGISTRY env detection,
  inline JSON `auths` detection, safe JSON loading, ordered auth and
  cred-helper processing, legacy fallback when `auths` is absent, metadata
  suppression through injected legacy helpers, first-seen dedupe, and existing
  Docker auth call sites. Verification: compile/Ruff passed; artifact
  processor runtime coverage passed (`334 passed`, with
  `PROCESSOR_IDENTIFIER` set).
- [ ] Continue the architecture split by extracting remaining non-route
  `create_app()` helpers or moving to CLI/orchestrator monolith seams.
- [x] MTGX entity typing/layout audit was completed and reconciled; do not
  reopen it from historical handoff text unless a new graph parity gap is proven
  with current code evidence.
- [ ] Expand safe parser coverage for additional passive artifact formats and nested text containers.

## Guardrails

- [ ] Do not expand this workflow into authenticated exploitation, password attacks, or post-exploitation.
- [ ] Keep changes inside discovery, static analysis, non-intrusive validation, deterministic scoring, and resilient reporting.
- [ ] Do not add new third-party credential-validation or real-service access flows beyond what is already present; prefer auditability, reporting, UI, and passive parsing work next.
