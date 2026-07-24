# Shodan Provider Contract + Dry-Run Parity Handoff

Date: 2026-07-24

## Goal Stage

Discovery + testing/cleanup. This checkpoint makes passive provider fan-outs
deterministic and auditable without expanding live provider behavior.

## Completed

- `forge/utils/intel/shodan_lookup.py` now documents the implemented Shodan
  domain path as `/dns/resolve` plus capped `/shodan/host/{ip}` enrichment.
- Removed stale `/dns/domain` free-endpoint and unreachable fallback wording.
- `forge/cli.py` Shodan command docs now match the same contract.
- `forge kill-chain --dry-run` now records skipped `fanout_d3_shodan` and
  `fanout_d4_urlscan` seed runs for root domains without dispatching provider
  modules.
- Added regression coverage proving D3/D4 provider dry-run rows are persisted
  and Shodan/URLScan dispatch is not attempted during dry-run.
- Added regression coverage proving `lookup_shodan_domain()` calls
  `/dns/resolve`, performs at most three `/shodan/host/{ip}` enrichments, and
  never calls `/dns/domain`.

## Verification

- `python -m ruff check forge\cli.py forge\utils\intel\shodan_lookup.py tests\phase1\test_engagement_orchestrator.py tests\phase2\test_passive_host_persistence.py` -> passed
- `python -m py_compile forge\cli.py forge\utils\intel\shodan_lookup.py tests\phase1\test_engagement_orchestrator.py tests\phase2\test_passive_host_persistence.py` -> passed
- `python -m pytest tests\phase1\test_engagement_orchestrator.py -k "dry_run_populates_seed_runs_for_seeded_fanouts or dry_run_records_d3_d4_provider_skips_without_dispatch" -q` -> `2 passed, 763 deselected`
- `python -m pytest tests\phase2\test_passive_host_persistence.py -k "lookup_shodan_domain_uses_dns_resolve_and_caps_host_enrichment or lookup_shodan_domain_paces_requests_and_respects_retry_after" -q` -> `2 passed, 6 deselected`

## Next

Continue with the active backlog top item: audit another concrete
passive-to-live validation/report/API parity gap. Good candidates are
provider-specific proof/detail reviewability for long-tail validators or
imported graph/raw-export shape mismatches. Keep live provider calls mocked
unless an explicit ROE/scope manifest and target are supplied.
