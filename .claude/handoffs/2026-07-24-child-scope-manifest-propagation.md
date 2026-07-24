# Child Scope Manifest Propagation

Date: 2026-07-24

## Checkpoint

Explicit `scope_manifest` values now propagate into live-capable kill-chain
child dispatch argv for:

- `recon ports`
- domain Shodan D3
- URLScan D4
- IP Shodan fan-out

The child commands already support `--scope-manifest`. `--roe-id` was not added
to these child argv lists because their command signatures do not currently
accept it.

## Files Changed

- `forge/cli.py`
- `tests/phase1/test_engagement_orchestrator.py`
- `docs/engagement_overhaul_tasklist.md`
- `docs/claude_continue_checklist.md`
- `docs/claude_quick_handoff.md`

## Verification

- `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "active_port_child_receives_scope_manifest or ip_shodan_child_receives_scope_manifest or parallel_batches_passive_domain_prep" -q`
  -> `3 passed, 761 deselected`
- `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "scope_manifest or active_port_child_receives_scope_manifest or ip_shodan_child_receives_scope_manifest or parallel_batches_passive_domain_prep" -q`
  -> `11 passed, 753 deselected`
- `python -m pytest tests\cli\test_direct_live_scope.py tests\distributed\test_runnable_scope.py -q`
  -> `38 passed`
- `python -m ruff check forge\cli.py tests\phase1\test_engagement_orchestrator.py`
  -> passed
- `python -m py_compile forge\cli.py tests\phase1\test_engagement_orchestrator.py`
  -> passed

## Safety Notes

No new scanner behavior, provider calls, live probing, rate-limit bypass,
scope relaxation, exploitation, credential use, or post-exploitation behavior
was added. The change only forwards an already-validated explicit manifest to
child commands so they cannot silently fall back to broader DB scope.

## Next

Fix Shodan provider contract/dry-run parity:

- either align implementation with the documented `/dns/domain` credit-free path
  or document/test the current `/dns/resolve` plus capped host-enrichment cost
  model;
- add dry-run evidence that D3/D4 intended provider fan-outs are recorded
  without outbound calls.
