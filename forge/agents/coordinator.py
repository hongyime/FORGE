"""Task coordinator for FORGE agent collaboration (Explore #14).

Routes task requests to registered plugins by capability, tracks
task lifecycle, and publishes results to the EventBus.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from forge.agents.base_plugin import ForgePlugin, TaskResult, TaskSpec, TaskState
from forge.agents.capability_manifest import CapabilityManifest
from forge.agents.event_bus import AgentEvent, EventBus

__all__ = ["TaskCoordinator", "TaskRecord"]


@dataclass
class TaskRecord:
    """Mutable lifecycle state for a submitted task."""

    task_id: str
    state: str = TaskState.PENDING
    plugin_id: str | None = None
    result: TaskResult | None = None
    error: str | None = None
    created_at: str = field(
        default_factory=lambda: datetime.now(tz=timezone.utc).isoformat()
    )
    updated_at: str = field(
        default_factory=lambda: datetime.now(tz=timezone.utc).isoformat()
    )

    def _touch(self) -> None:
        self.updated_at = datetime.now(tz=timezone.utc).isoformat()


class TaskCoordinator:
    """Routes tasks to plugins and tracks lifecycle state.

    Usage::

        bus = EventBus()
        coordinator = TaskCoordinator(bus)
        coordinator.register_plugin(my_plugin)
        result = await coordinator.submit(task_spec)
    """

    def __init__(self, event_bus: EventBus) -> None:
        self._bus = event_bus
        self._plugins: dict[str, ForgePlugin] = {}
        self._tasks: dict[str, TaskRecord] = {}

    # ------------------------------------------------------------------
    # Registration

    def register_plugin(self, plugin: ForgePlugin) -> None:
        """Register *plugin* and publish a ``plugin.registered`` event."""
        manifest: CapabilityManifest = plugin.capability_manifest
        pid = manifest.plugin_id
        if pid in self._plugins:
            raise ValueError(f"Plugin {pid!r} is already registered")
        self._plugins[pid] = plugin

        self._bus.publish(
            AgentEvent(
                topic="plugin.registered",
                source_plugin_id=pid,
                engagement_id=0,  # registration is engagement-agnostic
                payload=manifest.to_dict(),
            )
        )

    # ------------------------------------------------------------------
    # Submission

    async def submit(self, task: TaskSpec) -> TaskResult:
        """Route *task* to a capable plugin and return the result.

        Publishes ``task.created``, ``task.updated``, ``task.completed``,
        and ``result.ready`` events to the EventBus.
        """
        record = TaskRecord(task_id=task.task_id)
        self._tasks[task.task_id] = record

        plugin = self._route(task)
        if plugin is None:
            record.state = TaskState.FAILED
            record.error = (
                f"No plugin registered for capability {task.capability!r}"
            )
            record._touch()
            return TaskResult(
                task_id=task.task_id,
                plugin_id="coordinator",
                status=TaskState.FAILED,
                error=record.error,
            )

        record.plugin_id = plugin.capability_manifest.plugin_id
        record._touch()

        self._bus.publish(
            AgentEvent(
                topic="task.created",
                source_plugin_id="coordinator",
                engagement_id=task.engagement_id,
                payload={
                    "task_id": task.task_id,
                    "capability": task.capability,
                },
            )
        )

        record.state = TaskState.RUNNING
        record._touch()
        self._bus.publish(
            AgentEvent(
                topic="task.updated",
                source_plugin_id="coordinator",
                engagement_id=task.engagement_id,
                payload={
                    "task_id": task.task_id,
                    "state": TaskState.RUNNING,
                },
            )
        )

        try:
            result = await plugin.execute_task(task)
            record.state = TaskState.COMPLETED
            record.result = result
        except Exception as exc:  # noqa: BLE001
            record.state = TaskState.FAILED
            record.error = str(exc)
            result = TaskResult(
                task_id=task.task_id,
                plugin_id=record.plugin_id or "unknown",
                status=TaskState.FAILED,
                error=record.error,
            )

        record._touch()

        self._bus.publish(
            AgentEvent(
                topic="task.completed",
                source_plugin_id="coordinator",
                engagement_id=task.engagement_id,
                payload={
                    "task_id": task.task_id,
                    "state": record.state,
                },
            )
        )
        self._bus.publish(
            AgentEvent(
                topic="result.ready",
                source_plugin_id=record.plugin_id or "coordinator",
                engagement_id=task.engagement_id,
                payload={
                    "task_id": task.task_id,
                    "status": result.status,
                },
            )
        )

        return result

    # ------------------------------------------------------------------
    # Read-only queries

    def task_status(self, task_id: str) -> TaskRecord | None:
        """Return the current TaskRecord for *task_id*, or None."""
        return self._tasks.get(task_id)

    def list_plugins(self) -> list[dict[str, Any]]:
        """Return manifest dicts for all registered plugins."""
        return [p.capability_manifest.to_dict() for p in self._plugins.values()]

    # ------------------------------------------------------------------
    # Internal routing

    def _route(self, task: TaskSpec) -> ForgePlugin | None:
        for plugin in self._plugins.values():
            if task.capability in plugin.capability_manifest.capabilities:
                return plugin
        return None
