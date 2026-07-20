# End Goal Contract Handoff

Acceptance stages advanced: testing/cleanup and review handoff clarity.

The FORGE end goal is now stated through a small, linked documentation chain:

- `END_GOAL.md` is the fast entry point.
- `docs/deterministic_engagement_contract.md` is the compact pipeline-gate map.
- `docs/end_goal.md` remains the normative source of truth.
- `docs/engagement_overhaul_tasklist.md` -> `## Compact active backlog` remains
  the canonical current task order.

Clarifications made:

- README no longer frames FORGE primarily as a single-seed passive OSINT spider;
  it now opens as a deterministic authorized ASM pipeline.
- Live `--attack-mode` and `--auto-run-detected` wording now says ROE plus scope
  manifest are required, not merely carried when available.
- Fallback wording is aligned around LLM/API narrative provider failure, quota,
  missing key, or token-limit exhaustion.
- The compact contract defers task order to the existing engagement overhaul
  tasklist so it does not become a competing backlog.
- The immediate next code target is recorded as the narrow nested
  StackExchange/StackOverflow provider payload normalization regression in
  `tests/phase2/test_social_scraper.py` and `forge/utils/intel/social_scraper.py`.

Subagent review:

- Explorer `Herschel` performed a read-only docs consistency audit and identified
  the stale README framing, live-scope ambiguity, fallback wording drift, and
  potential compact-contract source-of-truth ambiguity. Those findings were
  addressed in this checkpoint.

Verification:

- `rg` consistency scans for the corrected goal/fallback/scope wording.
- `git diff --check` returned only expected line-ending warnings.

Next:

- Implement the focused nested StackExchange/StackOverflow user-payload parser
  fix, then run compile, Ruff, focused social scraper test, adjacent social
  scraper suite, and pytest engagement cleanup check.
