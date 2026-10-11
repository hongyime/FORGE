"""Autopilot defaults — sensible values that work without any config file.

These defaults mirror the operator-tunable settings normally pulled from
``imports/autostart.local.json`` but are chosen to be safe for the
no-config, run-it-and-walk-away use case:

- Resource floors are low enough to run on a laptop (512 MB RAM, 2 GB
  disk) while still catching obviously overloaded hosts.
- Resume parallelism is 2 to balance throughput against the SQLite lock
  contention that happens when more than a handful of kill-chain runs
  share a data dir.
- Max runtime per started target is 25 minutes to match the kill-chain
  default soft budget documented in README.md.
- Kill-chain max-iter 7 matches the ``forge kill-chain`` default.
- Feed source selector is ``all`` so every available source — db,
  reports, cti, connectors, supabase — contributes to the daily feed.

Nothing here reads from disk. Operators who want to override any value
can pass it through the ``forge autopilot`` CLI or construct a
``AutopilotDefaults`` instance directly.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class AutopilotDefaults:
    """Immutable defaults for :class:`forge.autopilot.ForgeAutopilot`.

    All fields have sensible fallbacks that keep the autopilot usable
    with zero configuration. Override individual fields via the CLI or
    by constructing a new instance with ``dataclasses.replace``.
    """

    #: Maximum feed items imported per cycle (before dedupe).
    import_limit: int = 100
    #: Maximum new kill-chain runs launched by one import pass.
    start_limit: int = 5
    #: Minimum independent source count required before --start may
    #: launch a live kill-chain run.
    min_start_source_count: int = 1
    #: Kill-chain iteration budget passed through to each started run.
    max_iter: int = 7
    #: Soft runtime budget (minutes) per started kill-chain run.
    max_runtime_minutes: int = 25
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


#: Dict-form of :data:`AutopilotDefaults`, convenient for serialization.
AUTOPILOT_DEFAULTS: dict[str, object] = {
    "import_limit": 100,
    "start_limit": 5,
    "min_start_source_count": 1,
    "max_iter": 7,
    "max_runtime_minutes": 25,
    "resume_limit": 10,
    "max_parallel": 2,
    "monitor_limit": 10,
    "cooldown_minutes": 30,
    "feed_sources": ["all"],
    "min_free_memory_mb": 512,
    "min_free_disk_gb": 2,
}


__all__ = ["AUTOPILOT_DEFAULTS", "AutopilotDefaults"]
