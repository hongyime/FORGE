# HTML Data Aggregation Worker Audit

Date: 2026-07-24

## Result

No runtime code change.

`forge/cli.py::_extract_html_data()` was reviewed after the HTML surface
URL-family worker migration. The remaining logic is local aggregation over
emails, phones, IP seeds, GitHub hints, social-profile hints, and crawl URL set
construction. The only clearly heavy subpath is already
`_extract_html_surface_urls()`, which now has bounded ordered family dispatch
for the single-payload D1/D2/D5 path.

Adding another worker split inside `_extract_html_data()` is not recommended
right now. It would add nested scheduling and code size without a concrete
kill-chain correctness gain.

## Boundary

Keep these serial unless a future bug proves otherwise:

- DB apply/merge/write/finalization barriers
- report and graph closeout
- ordered persistence reductions
- validation/reportability gates

## Subagent Attempts

- Claude Code was attempted first and failed because the OAuth session is
  expired.
- Codex was attempted as fallback in read-only sandbox mode. The first run used
  an unsupported model for this account. The retry used the default model but
  the sandbox could not spawn PowerShell (`CreateProcessAsUserW failed: 5`), so
  it could not inspect the repo.

## Verification Baseline

No new tests were required for this docs-only audit. The prior HTML URL-family
checkpoint remains the relevant runtime verification baseline:

- compile/Ruff passed
- focused passive/HTML URL extraction tests passed (`3 passed, 28 deselected`)
- full CLI parallel dispatch suite passed (`31 passed`)
- D1/D2/D5 worker scheduling slice passed (`3 passed`)
- compact HTML-mining plus service-worker/precache smoke passed (`2 passed`)
- pytest engagement cleanup reported zero remaining test engagement DBs after
  cleanup

## Next Gate

Resume real kill-chain correctness work by auditing passive-to-live validator
handoff coverage with mocked read-only proof endpoints and provider-specific
proof details.

Prioritize deterministic validation, report, graph, and dashboard parity over
additional micro-optimization. Do not add live target probing without explicit
ROE/scope manifest and local/mocked regression coverage.
