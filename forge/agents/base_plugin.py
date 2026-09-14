"""Base class for all FORGE collaboration plugins (Explore #14).

Every plugin must:
  - Declare a ``capability_manifest`` class attribute.
  - Implement ``handle_event()`` and ``run_task()`` abstract methods.
  - Never bypass the ROE/scope check in ``execute_task``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from forge.agents.capability_manifest import CapabilityManifest
from forge.agents.event_bus import AgentEvent

__all__ = [
    "ForgePlugin",
    "TaskSpec",
    "TaskResult",
    "TaskState",
]


class TaskState:
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class TaskSpec:
    """Work item routed to a plugin by the TaskCoordinator."""

    task_id: str
    engagement_id: int
    capability: str
    target: str
    roe_id: str
    scope: list[str]
    params: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(
        default_factory=lambda: datetime.now(tz=timezone.utc).isoformat()
    )


@dataclass
class TaskResult:
    """Outcome produced by a plugin after running a task."""

    task_id: str
    plugin_id: str
    status: str
    payload: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    completed_at: str = field(
        default_factory=lambda: datetime.now(tz=timezone.utc).isoformat()
    )


class ForgePlugin(ABC):
    """Abstract base for all FORGE collaboration plugins.

    Concrete plugins must:
    1. Set ``capability_manifest`` as a class attribute of type
       ``CapabilityManifest``.
    2. Implement ``handle_event`` and ``run_task``.

    The public ``execute_task`` wrapper enforces ROE + scope before calling
    the plugin's ``run_task``; this check cannot be bypassed.
    """

    capability_manifest: CapabilityManifest  # set on every concrete subclass

    async def execute_task(self, task: TaskSpec) -> TaskResult:
        """Public entry point — enforces ROE/scope gate, then calls run_task.

        Never override this method; override ``run_task`` instead.
        """
        self._assert_roe_and_scope(task)
        return await self.run_task(task)

    # ------------------------------------------------------------------
    # Invariant: gate cannot be bypassed

    def _assert_roe_and_scope(self, task: TaskSpec) -> None:
        if not task.roe_id or not task.roe_id.strip():
            raise ValueError(
                f"Task {task.task_id!r}: ROE ID is required before any plugin executes"
            )
        if not task.scope:
            raise ValueError(
                f"Task {task.task_id!r}: at least one scope entry is required"
            )

    # ------------------------------------------------------------------
    # Abstract interface

    @abstractmethod
    async def handle_event(self, event: AgentEvent) -> None:
        """Process an incoming event from the EventBus."""

    @abstractmethod
    async def run_task(self, task: TaskSpec) -> TaskResult:
        """Execute work for *task* and return a TaskResult.

        Only called after ROE + scope have been validated by execute_task.
        """
