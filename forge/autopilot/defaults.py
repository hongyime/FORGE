"""Autopilot defaults — sensible values that work without any config file.

These defaults mirror the operator-tunable settings normally pulled from
``imports/autostart.local.json`` but are chosen to be safe for the
no-config, run-it-and-walk-away use case:

- Resource floors are low enough to run on a laptop (512 MB RAM, 2 GB
  disk) while still catching obviously overloaded hosts.
- Resume parallelism is 2 to balance throughput against the SQLite lock
  contention that happens when more than a handful of kill-chain runs
  share a data dir.
- Max runtime per started target is 120 minutes to match the requested
  autopilot engagement budget.
- Kill-chain max-iter 7 matches the ``forge kill-chain`` default.
- Feed source selector is ``all`` so every available source — db,
  reports, cti, connectors, supabase — contributes to the daily feed.
- ``default_roe_id`` and ``default_engagement_start`` exist so the
  autopilot has a non-empty ROE/engagement handle when no explicit
  ROE is set in the environment. Live kill-chain execution still
  requires a scope manifest declaring the actual targets.
- ``permitted_modules`` lists the exploitation modules enabled by
  default when the scope manifest/ROE grants them. Scope-manifest
  permission blocks are still enforced on a per-engagement basis.

Nothing here reads from disk. Operators who want to override any value
can pass it through the ``forge autopilot`` CLI or construct a
``AutopilotDefaults`` instance directly.
"""

from __future__ import annotations

from dataclasses import dataclass

from forge.utils.kill_chain_options import (
    DEFAULT_KILL_CHAIN_MAX_RUNTIME_MINUTES,
    DEFAULT_KILL_CHAIN_PARALLEL_FANOUT,
)

AUTOPILOT_MAX_RUNTIME_MINUTES = DEFAULT_KILL_CHAIN_MAX_RUNTIME_MINUTES
AUTOPILOT_PARALLEL_FANOUT = DEFAULT_KILL_CHAIN_PARALLEL_FANOUT
AUTOPILOT_MAX_TIMEOUT_RETRIES = 2

# Cycle 5 proof: two healthy, progressing targets hit return_code 124 at
# 3720s (engagement 3 email recon; engagement 49 gmail.com). 120 minutes
# doubles that budget while retaining a hard bound.


@dataclass(frozen=True)
class AutopilotDefaults:
    """Immutable defaults for :class:`forge.autopilot.ForgeAutopilot`.

    All fields have sensible fallbacks that keep the autopilot usable
    with zero configuration. Override individual fields via the CLI or
    by constructing a new instance with ``dataclasses.replace``.
    """

    #: Maximum feed items selected per cycle after merging and dedupe.
    import_limit: int = 25_000
    #: Maximum new kill-chain runs launched by one import pass.
    start_limit: int = 20
    #: Minimum independent source count required before --start may
    #: launch a live kill-chain run.
    min_start_source_count: int = 1
    #: Kill-chain iteration budget passed through to each started run.
    max_iter: int = 7
    #: Soft runtime budget (minutes) per started kill-chain run.
    max_runtime_minutes: int = AUTOPILOT_MAX_RUNTIME_MINUTES
    #: Bounded worker fanout for each started kill-chain.
    parallel_fanout: int = AUTOPILOT_PARALLEL_FANOUT
    #: Maximum resume candidates processed per cycle.
    resume_limit: int = 10
    #: Resume parallelism cap. Keep low to avoid SQLite lock contention.
    max_parallel: int = 2
    #: Maximum due monitoring policies run per cycle.
    monitor_limit: int = 10
    #: Minutes to sleep between loop iterations when running in a loop.
    cooldown_minutes: int = 30
    #: Feed sources considered during feed-build.
    feed_sources: tuple[str, ...] = ("all",)
    #: Minimum free memory before considering the host healthy for
    #: live work.
    min_free_memory_mb: int = 512
    #: Minimum free disk before considering the host healthy for
    #: live work.
    min_free_disk_gb: int = 2
    #: Default ROE reference used when ``FORGE_ROE_ID`` is not set.
    #: Keeps the autopilot in apply mode out of the box; scope-manifest
    #: enforcement still gates actual live kill-chain execution.
    default_roe_id: str = "ROE-1"
    #: Starting engagement id when the autopilot needs to allocate one
    #: without an existing ID assigned by the operator.
    default_engagement_start: int = 1
    #: Exploitation modules permitted by default when the scope manifest
    #: and ROE allow them. The scope manifest permission blocks remain
    #: the authority for live execution; this tuple only records the
    #: default enabled set at the autopilot layer.
    permitted_modules: tuple[str, ...] = (
        "reverse_proxy",
        "post_login_automation",
        "autonomous_exploit",
        "goal_targets",
    )


#: Dict-form of :data:`AutopilotDefaults`, convenient for serialization.
AUTOPILOT_DEFAULTS: dict[str, object] = {
    "import_limit": 25_000,
    "start_limit": 20,
    "min_start_source_count": 1,
    "max_iter": 7,
    "max_runtime_minutes": AUTOPILOT_MAX_RUNTIME_MINUTES,
    "parallel_fanout": AUTOPILOT_PARALLEL_FANOUT,
    "resume_limit": 10,
    "max_parallel": 2,
    "monitor_limit": 10,
    "cooldown_minutes": 30,
    "feed_sources": ["all"],
    "min_free_memory_mb": 512,
    "min_free_disk_gb": 2,
    "default_roe_id": "ROE-1",
    "default_engagement_start": 1,
    "permitted_modules": [
        "reverse_proxy",
        "post_login_automation",
        "autonomous_exploit",
        "goal_targets",
    ],
}


__all__ = ["AUTOPILOT_DEFAULTS", "AutopilotDefaults"]
