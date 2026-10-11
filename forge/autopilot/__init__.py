"""FORGE autopilot — self-running loop with no config file required.

This package wires existing automation primitives into a single operator
command that works out of the box:

- Feed build auto-seeds from local imports/, CTI drops, previous
  engagement discoveries, and configured Supabase projects.
- Target import auto-creates engagements and starts kill-chain runs
  when a ROE is present.
- Resume candidates auto-resume ready paused/failed runs.
- Scheduled monitoring auto-refreshes due policies.
- Static dashboard auto-rebuilds for operator review.

Live execution still requires an explicit ROE/scope manifest; dry-run
is the fail-closed default when either is missing or
``FORGE_SAFE_MODE=1`` is set.
"""

from forge.autopilot.defaults import AUTOPILOT_DEFAULTS, AutopilotDefaults
from forge.autopilot.loop import (
    AUTOPILOT_SCHEMA_VERSION,
    AutopilotPhaseResult,
    ForgeAutopilot,
)

__all__ = [
    "AUTOPILOT_DEFAULTS",
    "AUTOPILOT_SCHEMA_VERSION",
    "AutopilotDefaults",
    "AutopilotPhaseResult",
    "ForgeAutopilot",
]
