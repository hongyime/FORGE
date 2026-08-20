# Agent State

Current task: stop local FORGE scheduled execution, research `ukr.pw`/CTI/OSINT sources as unsafe text, and integrate a safe production-ready CTI/OSINT observation slice into FORGE.

Progress:
- `FORGE Import theprawnhunter Targets` scheduled task was disabled; no active FORGE/telegramhunter/theprawnhunter process was found.
- Three subagents completed read-only research. No commands from external links were run, cloned, or installed.
- Implemented catalog-only CTI connector entries and local CTI/OSINT observation normalization/redaction tests.
- Updated `SPEC.md` with checkpoint B515. Remote `main` removed the old `docs/` handoff files during rebase, so ongoing shared state now lives here under `.agents/`.
- Pushed B515 as `7b14720 feat: add safe cti osint observations`.
- Implemented offline `forge connectors import-cti` for normalized CTI/OSINT observation JSON, durable `cti_observations` storage, audit logging, duplicate handling, and explicit scope-gated seed promotion.
- Updated README public connector command list for `forge connectors import-cti`.
- Pushed B516 as `6b3bd9f feat: import offline cti observations`.
- Exposed CTI observations as non-reportable inventory in Phase 6 context/export/template reports and dashboard detail JSON.
- Hardened CTI source/provenance redaction and changed fallback raw-artifact hashes to sanitized canonical observation fields only.
- Pushed B517 as `3755cd8 feat: surface cti observation inventory`.
- Added offline provider-shape adapters for common ThreatFox, URLHaus, and STIX indicator JSON exports so `forge connectors import-cti` can ingest real downloaded/exported data without live provider calls.
- Pushed B518 as `30cf1fc feat: accept provider cti export shapes`.
- Documented offline CTI import support in README next to the public command list.
- Pushed README checkpoint as `bfbda54 docs: document offline cti imports`.
- Added `forge connectors import-cti --dry-run` to parse/sanitize offline CTI files and scope-check promotion candidates without writing observations, seeds, or audit rows.
- Pushed B519 as `b6314f0 feat: add cti import dry run`.
- Hardened CTI dry-run preview to distinguish existing/in-file duplicate observations from new observations without creating tables or writing rows.
- Pushed B520 as `eaf0343 feat: preview cti import duplicates`.
- Added `forge connectors import-cti --limit N` and result item-count metadata so large offline CTI exports can be processed in bounded batches.
- Pushed B521 as `c90fbeb feat: bound cti import items`.
- Added `forge connectors import-cti --min-confidence F` to skip low-confidence offline CTI observations before persistence or dry-run would-persist counts.
- Pushed B522 as `af505aa feat: filter cti import confidence`.
- Added `forge connectors import-cti --max-tlp LEVEL` to skip observations above an allowed TLP level before persistence or dry-run preview counts.
- Pushed B523 as `cdb0e42 feat: filter cti import tlp`.
- Added `forge connectors import-cti --since ISO --until ISO` to bound offline CTI imports and dry-runs by observation time.
- Pushed B524 as `6abfd45 feat: filter cti import observed window`.
- Added local CSV fallback parsing for offline `forge connectors import-cti --report-file` inputs so ThreatFox and URLHaus CSV exports flow through the same sanitized import path.
- Verified B525 with focused CTI tests, broader connector sanity tests, Ruff, py_compile, and `git diff --check`.
- Pushed B525 as `fb5aa26 feat: import offline cti csv`.

Next steps:
- Continue CTI/OSINT production-readiness planning for live provider fetchers only after explicit approval; current path remains offline import plus non-reportable inventory.
