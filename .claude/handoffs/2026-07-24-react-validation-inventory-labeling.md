# React Validation Inventory Labeling

Date: 2026-07-24

## Checkpoint

Closed the engagement-detail reviewability gap where non-reportable key/cloud
validation rows were counted with reportable findings.

## Code Changes

- `forge/reporting/webui/src/App.tsx`
  - Renamed the findings panel to "Reportable validated findings".
  - Counts only `vulnerability_findings` plus `passive_vulns` in that panel.
  - Added a separate "Validation inventory" panel for key scanner and cloud
    validation rows.
- `tests/reporting/test_webui_contract.py`
  - Added a source contract assertion that rejects the old combined count and
    requires the inventory panel labels.
- `SPEC.md` and active handoff docs
  - Recorded B24 and advanced the next gate to deterministic `conflicts_with`
    seed relations.

## Verification

- `python -m pytest tests\reporting\test_webui_contract.py -q`
  - Result: `5 passed`

## Next Gate

Implement deterministic `conflicts_with` seed relations for obvious
identity/entity collisions, such as the same email/phone tied to incompatible
names or organizations.
