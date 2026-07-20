# Claude Quick Handoff

Last updated: 2026-07-20

Use this file first for short resume context, then verify current continuation
order in `docs/engagement_overhaul_tasklist.md` -> `## Compact active backlog`;
that section wins if task/status details differ. Fast goal entry point:
`END_GOAL.md`; compact workflow contract:
`docs/deterministic_engagement_contract.md`; normative end goal:
`docs/end_goal.md`; acceptance criteria:
`docs/engagement_overhaul_tasklist.md` -> `## Canonical End Goal`.

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
without creating competing source-of-truth docs.

## Operator Notes

- [x] Current workspace Git status checked on 2026-07-20: this checkout is a Git repo on `main` tracking `origin/main`. Any deep historical checklist lines saying the workspace was intentionally not a Git repo are stale context only; do not use them to skip commits.
- [x] Defender/impacket status checked: `C:\Program Files\Python312\Lib\site-packages\impacket\smbconnection.py` is currently absent/quarantined, while the project venv copy exists and Forge imports impacket from `.venv`. `Get-MpThreatDetection` shows repeated successful actions against only the global `Program Files` path. Do not add a broad Defender exclusion for `C:\Program Files`; keep launchers venv-bound and only consider a narrow project-scoped exclusion if Defender starts quarantining the verified `.venv` dependency.
- [x] Local public metadata source-label target completed: local `assetlinks.json`, `browserconfig.xml`, `jwks.json`, `mta-sts.txt`, and `security.txt` artifacts now keep source-aware formats instead of generic suffix labels while preserving existing recursion. Handoff: `.claude/handoffs/2026-07-20-public-metadata-labels.md`.
- [x] Apple merchant domain-association metadata target completed: `/.well-known/apple-developer-merchantid-domain-association` now routes as passive config metadata and can feed URL/email/cloud pivots through artifact recursion. Handoff: `.claude/handoffs/2026-07-20-apple-merchant-well-known-recursion.md`.
- [x] Matrix client well-known metadata target completed: `/.well-known/matrix/client` now routes as `matrix-client` passive config metadata and feeds Matrix homeserver/identity-server URLs, contact email, and Supabase refs through artifact recursion. Handoff: `.claude/handoffs/2026-07-20-matrix-client-well-known-recursion.md`.
- [x] OIDC claim contact/userinfo target completed: `claims.email`, `claims.phone_number`, `userinfo.email`, `userinfo.phone_number`, `userinfo.profile`, and `userinfo.website` now stay on the enclosing provider row as recursive evidence; scalar/token claims stay suppressed. Handoff: `.claude/handoffs/2026-07-20-oidc-userinfo-claim-contact-recursion.md`.
- [x] OIDC claim URL recursion target completed: Epieos/userinfo-style `claims.profile` and `claims.website` now stay on the existing provider row as recursive URL evidence; scalar/token claims stay suppressed. Handoff: `.claude/handoffs/2026-07-20-oidc-claim-url-recursion.md`.
- [x] Nested StackExchange user-profile target completed: provider-scoped Epieos StackExchange/StackOverflow `user` payloads now become safe public profile pivots when they include numeric `user_id`, normalized handle, and accepted/no site hint. Bad site hints are rejected. Handoff: `.claude/handoffs/2026-07-20-stackexchange-nested-user-profile.md`.
- [ ] Immediate next code target: audit another concrete identity-provider payload shape or passive artifact/parser source shape before writing code. If no missing recursive pivot is found, switch to release-level mocked E2E/report-fallback tests or safe mega-test/module splits.
- [ ] Code-size discipline is now a hard continuation rule: do not add new feature logic directly into `forge/engagement_orchestrator.py`, `forge/cli.py`, `forge/utils/intel/social_scraper.py`, or mega test files unless it is a thin adapter/regression hook. HAR helpers live in `forge/utils/artifact_har.py`, and Epieos/social host guards now live in `forge/utils/intel/social_profile_hosts.py`; next refactor target is splitting newly added mega-file tests where imports allow it.

## Current green checkpoint

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

## Still partial

Status semantics: these unchecked items are candidate/risk notes, not the
canonical active queue. Use `docs/engagement_overhaul_tasklist.md` ->
`## Compact active backlog` for current continuation order.

- [ ] Provider coverage is still selective rather than exhaustive. The strongest deterministic coverage is Firebase, Supabase, S3/GCS/Azure/DO, Google/Gemini API keys, Hugging Face, Discord bot tokens, Telegram bot tokens, Notion tokens, Datadog API keys, GitHub, GitLab, Mailchimp, Stripe, SendGrid, Slack, Azure Storage connection strings, and co-located Twilio/AWS key-pair validation.
- [ ] The engagement detail UI is sectioned, not literally tabbed. Treat that as a polish decision unless product now requires strict tabs.
- [ ] MTGX/GraphML export exists, but the analyst-workflow fidelity audit is still open.
## Best next tasks

- [ ] Add append-only remote storage for exported run-manifest bundles only if scoped customer storage is explicitly configured.
- [ ] Broaden engagement-backed end-to-end fixtures beyond the now-verified local+remote+second-hop artifact/social/fallback paths with richer provider matrices and export assertions, without widening live service-validation scope.
- [ ] Keep improving deterministic report/export auditability and overview parity beyond the newly fixed companion-export/raw-export parity and latest-family/history split: richer aggregate stats, clearer generation lineage, and deeper degraded-export regression coverage.
- [ ] Audit MTGX entity typing/layout against the intended Maltego-first workflow before changing more graph UI.
- [ ] Expand safe parser coverage for additional passive artifact formats and nested text containers.

## Guardrails

- [ ] Do not expand this workflow into authenticated exploitation, password attacks, or post-exploitation.
- [ ] Keep changes inside discovery, static analysis, non-intrusive validation, deterministic scoring, and resilient reporting.
- [ ] Do not add new third-party credential-validation or real-service access flows beyond what is already present; prefer auditability, reporting, UI, and passive parsing work next.
