# Latest Validation Linked-Proof Parity

Date: 2026-07-24

## Completed

- Added `latest_cloud_validation_reportability_index()` in `forge/utils/cloud_exposure_gate.py`.
- Deterministic key synthesis, Phase 6 linked-key report gates, dashboard/API key counts, and cloud-leak playbook admission now use latest matching cloud validation state rather than any historical reportable row.
- Direct key-validator proof stored on `key_scanner_findings.validation_detail` still authorizes that exact key when the stable proof parser accepts it.
- Deterministic cloud validation replay now orders by `asset_type`, `identifier`, `checked_at`, and `id` so imported legacy rows with out-of-order IDs converge deterministically.

## Files Changed

- `forge/utils/cloud_exposure_gate.py`
- `forge/deterministic_findings.py`
- `forge/phase6/report_synthesizer.py`
- `forge/reporting/dashboard.py`
- `forge/utils/playbooks/cloud_leak.py`
- `tests/integration/test_latest_validation_reportability.py`
- `tests/integration/test_playbooks.py`
- `SPEC.md`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- `python -m py_compile forge\utils\cloud_exposure_gate.py forge\deterministic_findings.py forge\phase6\report_synthesizer.py forge\reporting\dashboard.py forge\utils\playbooks\cloud_leak.py tests\integration\test_latest_validation_reportability.py tests\integration\test_playbooks.py`
- `python -m ruff check forge\utils\cloud_exposure_gate.py forge\deterministic_findings.py forge\phase6\report_synthesizer.py forge\reporting\dashboard.py forge\utils\playbooks\cloud_leak.py tests\integration\test_latest_validation_reportability.py tests\integration\test_playbooks.py`
- `python -m pytest -q tests\integration\test_latest_validation_reportability.py`
- `python -m pytest -q tests\integration\test_playbooks.py::test_cloud_leak_playbook_uses_latest_linked_validation_status tests\integration\test_playbooks.py::test_cloud_leak_playbook_allows_active_key_with_linked_reportable_validation tests\integration\test_playbooks.py::test_cloud_leak_playbook_rejects_active_key_without_stable_proof`
- `python -m pytest -q tests\phase1\test_deterministic_findings.py`
- `python -m pytest -q tests\phase6\test_report_cloud_exposure_gating.py tests\phase6\test_report_synthesizer.py::test_context_builder_counts_only_reportable_key_findings`
- `python -m pytest -q tests\reporting\test_dashboard.py`
- `python -m pytest -q tests\integration\test_webui_engagement_api.py`
- `python -m pytest -q tests\integration\test_playbooks.py`

## Review

- Sidecar reviewer `Wegener` independently confirmed stale linked-key indexes in deterministic findings and Phase 6 and recommended a shared latest-row helper.

## Next Gate

Fix kill-chain dry-run finalization contract. `forge kill-chain --dry-run` should not schedule finalization commands that can perform network-capable vulnerability/exploit correlation without explicit dry-run/scope arguments. Add a regression first, then either pass explicit dry-run/scope flags to finalizers or skip network-capable finalizers in dry-run mode.
