# Agent Journal

- 2026-08-20: Disabled the local scheduled FORGE target-import task on request and chose a safe CTI/OSINT integration path: passive/catalog-only providers plus normalized observations, provenance, redaction, budgets, and no third-party command execution.
- 2026-08-20: Added offline CTI observation import as the first wired CTI workflow path; seed promotion is explicit and scope-gated, while raw provider bodies and secrets remain out of persistent records.
- 2026-08-20: Surfaced CTI observations only as non-reportable analyst inventory in report/dashboard exports; source/provenance strings are redacted and fallback artifact hashes use sanitized canonical observation fields instead of raw provider objects.
