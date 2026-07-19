"""
forge/phase5 — Post-Exploitation

Implementation lives in forge.utils.post. This package re-exports the
public API to match the path structure specified in forge_spec.md.
"""
from forge.utils.post import (  # noqa: F401
    session_manager,
    remote_exec,
    schedule_builder,
    template_engine,
    transfer_util,
    boundary_check,
)
from forge.utils.post import collectors  # noqa: F401

try:
    from forge.utils.post import channels  # noqa: F401
except (ImportError, OSError):
    channels = None  # type: ignore[assignment]
