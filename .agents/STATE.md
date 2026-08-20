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

Next steps:
- Commit and push the CTI dry-run duplicate-preview checkpoint.
