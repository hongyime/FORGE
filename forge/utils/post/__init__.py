"""
forge/utils/post — Phase 5: Post-Exploitation (obfuscated path)
Canonical: forge/phase5/

Module mapping (obfuscated → canonical):
  boundary_check.py  → scope_gate.py     (shared scope enforcement)
  template_engine.py → reverse_shell.py  (Module 5-F)
  session_manager.py → c2_generator.py   (Module 5-G)
  channels/          → c2 channel backends
  transfer_util.py   → exfiltration.py   (Module 5-H)
  collectors/        → data collector implementations
  schedule_builder.py → persistence.py   (Module 5-I)
  remote_exec.py     → lateral_movement.py (Module 5-J)
  staging/           → exfiltrated_data/

All remote actions enforce:
  1. Scope gate (boundary_check.assert_in_scope) — first call, always.
  2. Engagement-status guard (ACTIVE only).
  3. questionary.confirm() — operator confirmation, non-bypassable.
  4. Audit log write before and after action.
  5. cleanup.py registration for every artifact written to disk.

FORGE_OFFLINE_STRICT=1 disables all outbound network activity in this package.
"""

from __future__ import annotations

__all__ = [
    "ReverseShellGenerator",
    "C2Generator",
    "Exfiltrator",
    "PersistenceGenerator",
    "LateralMovementExecutor",
]

_OFFENSIVE_MODULES = frozenset(__all__)


def __getattr__(name: str):  # noqa: ANN001
    if name in _OFFENSIVE_MODULES:
        from forge.config import SafeModeError, is_offensive_enabled

        if not is_offensive_enabled():
            raise SafeModeError(name)

    if name == "ReverseShellGenerator":
        from forge.utils.post.template_engine import ReverseShellGenerator

        return ReverseShellGenerator
    if name == "C2Generator":
        from forge.utils.post.session_manager import C2Generator

        return C2Generator
    if name == "Exfiltrator":
        from forge.utils.post.transfer_util import Exfiltrator

        return Exfiltrator
    if name == "PersistenceGenerator":
        from forge.utils.post.schedule_builder import PersistenceGenerator

        return PersistenceGenerator
    if name == "LateralMovementExecutor":
        from forge.utils.post.remote_exec import LateralMovementExecutor

        return LateralMovementExecutor
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
