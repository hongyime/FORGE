# Dashboard Key Section Proof Gate

Date: 2026-07-24
Branch: `main`
Goal lock: `FORGE-DETERMINISTIC-ASM-PIPELINE-v1`

## Current State Summary

Static dashboard JSON and live engagement detail API sections now use the same
latest cloud validation proof gate as counts, graph filtering, and report
surfaces for key-scanner findings.

Before this checkpoint, stale `key_scanner_findings` rows with
`validation_state='ACTIVE'` and embedded `VALIDATED` detail could still appear
under `sections.key_scanner_findings`, even when newer
`cloud_validation_results` rows made the linked cloud resource unreportable.

## Files Changed

- `forge/reporting/dashboard.py`
- `tests/integration/test_cloud_validation_stable_proof_surfaces.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- `python -m py_compile forge\reporting\dashboard.py tests\integration\test_cloud_validation_stable_proof_surfaces.py`
- `python -m ruff check forge\reporting\dashboard.py tests\integration\test_cloud_validation_stable_proof_surfaces.py`
- `python -m pytest tests\integration\test_cloud_validation_stable_proof_surfaces.py -q` -> `1 passed`
- `python -m pytest tests\phase6\test_report_cloud_exposure_gating.py tests\integration\test_latest_validation_reportability.py tests\phase4\test_attack_path.py -k "validation or cloud or key or reportability" -q` -> `29 passed`
- `python -m pytest tests\test_cloud_exposure_gate.py tests\core\test_validation_proof.py -q` -> `119 passed`
- `python -m pytest tests\phase6\test_report_cloud_alias_latest.py tests\phase6\test_report_synthesizer.py -k "key_scanner or cloud_validation or validation_metadata or template_renders_cloud" -q` -> `1 passed`
- Pytest engagement DB cleanup -> `removed=2 remaining=0`

## Important Context

Subagent `Kant` found the exact bypass: `_reportable_key_scanner_rows()` already
used `latest_cloud_validation_reportability_index(..., require_stable_proof=True)`,
but `_detail_sections()` queried raw `key_scanner_findings` directly.

The fix expands `_reportable_key_scanner_rows()` to select the section fields
and makes `_detail_sections()` render only those reportable rows.

## Immediate Next Step

Subagent `Hegel` found the next concrete backend gap: HAR `_webSocketMessages[]`
payloads are not statically parsed. Implement bounded passive parsing in
`ArtifactQueueProcessor._har_entry_lines()` / `_har_entry_family_lines()` and
add a fixture in `tests/phase1/test_artifact_har.py` proving recursive
emails, URLs, and cloud references flow from WebSocket message data.

Safety boundary: passive static parsing only. Do not add browser replay, live
target probing, credential use, scope relaxation, proxy/IP rotation, or
rate-limit bypass.
