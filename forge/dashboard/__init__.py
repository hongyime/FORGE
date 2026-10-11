"""forge.dashboard — Cairn-style goal progress dashboard surfaces.

Separate from :mod:`forge.reporting.dashboard` which renders the main
engagement overview + per-engagement detail pages. This module adds the
goal-directed engagement execution view (Explore #16).

Public functions:

- :func:`forge.dashboard.goal_progress.get_goal_progress`
- :func:`forge.dashboard.goal_progress.get_exploitation_summary`
- :func:`forge.dashboard.goal_progress.generate_goal_dashboard_json`
- :func:`forge.dashboard.goal_progress.generate_goal_dashboard_html`
"""

from __future__ import annotations

from forge.dashboard.goal_progress import (
    generate_goal_dashboard_html,
    generate_goal_dashboard_json,
    get_exploitation_summary,
    get_goal_progress,
)

__all__ = [
    "generate_goal_dashboard_html",
    "generate_goal_dashboard_json",
    "get_exploitation_summary",
    "get_goal_progress",
]
