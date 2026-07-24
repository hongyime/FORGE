# Packaged Helm Values Recursion

Date: 2026-07-24

## Summary

Packaged Helm chart archives now feed `values.yaml` into the existing
orchestration structured parser.

Before this checkpoint, a chart member like
`acme-portal-1.2.3.tgz/acme-portal/values.yaml` was labeled generic YAML. That
skipped `helm-values` orchestration parsing, so host-only values such as
`ingress.hosts[].host` could fail to become recursive URL/host discovery
candidates.

The fix is source-shape-specific: packaged chart archive hints ending in
`.tgz` or `.tar.gz` can promote their nested `values.yaml`/`values.yml` member
to `helm-values`, while arbitrary `acme-portal/values.yaml` remains generic
YAML.

## Changed Files

- `forge/engagement_orchestrator.py`
- `tests/phase1/test_artifact_api_format_labels.py`
- `tests/phase1/test_artifact_orchestration_workers.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- `python -m compileall forge\engagement_orchestrator.py tests\phase1\test_artifact_api_format_labels.py tests\phase1\test_artifact_orchestration_workers.py`
- `python -m ruff check forge\engagement_orchestrator.py tests\phase1\test_artifact_api_format_labels.py tests\phase1\test_artifact_orchestration_workers.py`
- `python -m pytest tests\phase1\test_artifact_api_format_labels.py tests\phase1\test_artifact_orchestration_workers.py tests\phase1\test_artifact_helm_index.py -q`

Result: `8 passed`.

## Next Suggested Gate

Continue concrete backend kill-chain gaps only: verified passive
parser/container/OCR coverage, provider-proof hardening, identity/provider
normalization where a source shape is missing, or bounded-worker migration for
a proven pure-local sequential enricher.
