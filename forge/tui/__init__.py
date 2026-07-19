"""forge.tui — terminal UI package for FORGE Toolkit.

Interactive menu implementations that render cleanly on 120-char terminals.
The default entry point is :func:`forge.tui.main_menu.run_menu`, wired into
``forge menu`` in :mod:`forge.cli`. The legacy questionary-based menu remains
at :mod:`forge.menu_shell` and is reachable via ``forge menu --advanced``.
"""

from forge.tui.main_menu import run_menu

__all__ = ["run_menu"]
