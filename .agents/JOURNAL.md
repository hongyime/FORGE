# Agent Journal

- 2026-08-20: Disabled the local scheduled FORGE target-import task on request and chose a safe CTI/OSINT integration path: passive/catalog-only providers plus normalized observations, provenance, redaction, budgets, and no third-party command execution.
- 2026-08-20: Added offline CTI observation import as the first wired CTI workflow path; seed promotion is explicit and scope-gated, while raw provider bodies and secrets remain out of persistent records.
- 2026-08-20: Surfaced CTI observations only as non-reportable analyst inventory in report/dashboard exports; source/provenance strings are redacted and fallback artifact hashes use sanitized canonical observation fields instead of raw provider objects.
- 2026-08-20: Extended CTI offline import to normalize common ThreatFox, URLHaus, and STIX indicator export shapes locally; live provider fetching remains out of scope until explicitly approved.
- 2026-08-20: Added CTI import dry-run preview semantics with no observation, seed, or audit writes; real write counters stay zero and preview counts use `would_*` fields.
- 2026-08-20: CTI dry-run previews now read existing observation keys and track in-file repeats so `would_persist_count` excludes duplicates without creating tables or writing audit rows.
- 2026-08-20: Added explicit CTI import item limits for large offline exports; result metadata reports total, processed, and limited item counts.
- 2026-08-20: Added CTI min-confidence filtering as an operator noise-control gate before persistence or dry-run would-persist accounting; it does not change reportability.
- 2026-08-20: Added CTI max-TLP filtering as an operator data-handling gate before persistence or dry-run preview accounting; it does not change validation/reportability.
- 2026-08-20: Added CTI observed-time window filtering for offline imports and dry-runs; out-of-window rows are filtered before persistence or promotion preview.
- 2026-08-20: Added CSV as an offline CTI import format for provider exports; malformed JSON remains a hard JSON error and live provider fetching stays out of scope.
- 2026-08-20: Added CTI import summary counts for indicator types, TLP levels, target-feed types, and skipped reasons so operators can triage offline imports without raw-provider inspection.
- 2026-08-20: Added an opt-in CTI fail-on-empty automation gate that rejects files with no accepted observations while allowing duplicate-only re-imports.
- 2026-08-20: Added local `.gz` CTI report-file support so compressed offline exports are decompressed before the same sanitized JSON/CSV import path.
- 2026-08-20: Added constrained local `.zip` CTI report-file support with deterministic supported-member selection and no archive extraction to disk.
