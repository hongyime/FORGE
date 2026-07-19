# Legacy Cloud Proof Live-Data Gate Handoff

Date: 2026-07-19
Commit: `369e852 fix(reporting): require live data legacy cloud proof`

## What Changed

- `parse_validated_detail()` no longer accepts bare legacy Firebase/Supabase validation details as reportable proof.
- Generic Supabase `responded successfully` proof now downgrades to `UNVERIFIED`; explicit live-data wording is required.
- Deterministic key findings, Phase 6 exposed-key counts, dashboard validation proof fields, and API-key graph nodes inherit the stricter parser.
- Existing positive integration paths now use explicit Firebase live-data wording; linked `cloud_validation_results=VALIDATED` still drives actual cloud exposure findings.

## Verification

- `.venv\Scripts\python.exe -m py_compile forge\utils\validation_proof.py tests\core\test_validation_proof.py tests\phase1\test_deterministic_findings.py tests\phase4\test_attack_path.py tests\reporting\test_dashboard.py tests\integration\test_engagement_pipeline.py tests\phase6\test_report_synthesizer.py`
- `.venv\Scripts\python.exe -m ruff check forge\utils\validation_proof.py tests\core\test_validation_proof.py tests\phase1\test_deterministic_findings.py tests\phase4\test_attack_path.py tests\reporting\test_dashboard.py tests\integration\test_engagement_pipeline.py tests\phase6\test_report_synthesizer.py`
- Focused parser/findings/graph/dashboard/report tests -> `86 passed`
- `tests\integration\test_engagement_pipeline.py` -> `9 passed`

## Review

- Sidecar `Feynman` found the bare legacy proof promotion gap.
- Claude CLI maintainability review at `%TEMP%\forge-claude-maintainability-review.txt` returned only `Reached max turns (8)`.

## Safety

This checkpoint only tightens proof parsing and downstream report/graph gates. It adds no provider calls, no live probing expansion, no credential use, no scope relaxation, no proxy/IP rotation, no rate-limit bypass, and no report-gate weakening.
