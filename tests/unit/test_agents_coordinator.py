"""Unit tests for forge.agents.coordinator (Explore #14)."""

from __future__ import annotations

import pytest

from forge.agents.base_plugin import ForgePlugin, TaskResult, TaskSpec, TaskState
from forge.agents.capability_manifest import CapabilityManifest, load_manifest
from forge.agents.coordinator import TaskCoordinator, TaskRecord
from forge.agents.event_bus import AgentEvent, EventBus


# ---------------------------------------------------------------------------
# Fixtures

_MANIFEST_DICT = {
    "schema": "forge.agent.capability.v1",
    "plugin_id": "plugin_test_coord",
    "version": "1.0.0",
    "capabilities": ["passive_discovery"],
    "subscribes": ["task.created"],
    "publishes": ["result.ready"],
}


class _PassiveDiscoveryPlugin(ForgePlugin):
    capability_manifest = load_manifest(_MANIFEST_DICT)

    async def handle_event(self, event: AgentEvent) -> None:
        pass

    async def run_task(self, task: TaskSpec) -> TaskResult:
        return TaskResult(
            task_id=task.task_id,
            plugin_id=self.capability_manifest.plugin_id,
            status=TaskState.COMPLETED,
            payload={"discovered": ["host.example"]},
        )


def _make_task(**overrides) -> TaskSpec:
    defaults = dict(
        task_id="task-001",
        engagement_id=1001,
        capability="passive_discovery",
        target="host.example",
        roe_id="ROE-TEST",
        scope=["host.example", "*.host.example"],
    )
    defaults.update(overrides)
    return TaskSpec(**defaults)


# ---------------------------------------------------------------------------
# Registration


def test_register_plugin_succeeds():
    bus = EventBus()
    coord = TaskCoordinator(bus)
    plugin = _PassiveDiscoveryPlugin()
    coord.register_plugin(plugin)
    plugins = coord.list_plugins()
    assert len(plugins) == 1
    assert plugins[0]["plugin_id"] == "plugin_test_coord"


def test_register_plugin_publishes_event():
    bus = EventBus()
    coord = TaskCoordinator(bus)
    plugin = _PassiveDiscoveryPlugin()
    coord.register_plugin(plugin)
    assert bus.queue_size("plugin.registered") == 1


def test_register_same_plugin_twice_raises():
    bus = EventBus()
    coord = TaskCoordinator(bus)
    plugin = _PassiveDiscoveryPlugin()
    coord.register_plugin(plugin)
    with pytest.raises(ValueError, match="already registered"):
        coord.register_plugin(plugin)


# ---------------------------------------------------------------------------
# Submission


@pytest.mark.asyncio
async def test_submit_routes_to_capable_plugin():
    bus = EventBus()
    coord = TaskCoordinator(bus)
    coord.register_plugin(_PassiveDiscoveryPlugin())
    task = _make_task()
    result = await coord.submit(task)
    assert result.status == TaskState.COMPLETED
    assert "discovered" in result.payload


@pytest.mark.asyncio
async def test_submit_no_matching_plugin_returns_failed():
    bus = EventBus()
    coord = TaskCoordinator(bus)
    # No plugins registered
    task = _make_task(capability="passive_discovery")
    result = await coord.submit(task)
    assert result.status == TaskState.FAILED
    assert result.error
    assert "passive_discovery" in result.error


@pytest.mark.asyncio
async def test_submit_publishes_lifecycle_events():
    bus = EventBus()
    coord = TaskCoordinator(bus)
    coord.register_plugin(_PassiveDiscoveryPlugin())
    task = _make_task()
    await coord.submit(task)
    # plugin.registered + task.created + task.updated + task.completed + result.ready
    assert bus.queue_size("task.created") == 1
    assert bus.queue_size("task.updated") == 1
    assert bus.queue_size("task.completed") == 1
    assert bus.queue_size("result.ready") == 1


# ---------------------------------------------------------------------------
# task_status


@pytest.mark.asyncio
async def test_task_status_returns_record_after_submit():
    bus = EventBus()
    coord = TaskCoordinator(bus)
    coord.register_plugin(_PassiveDiscoveryPlugin())
    task = _make_task(task_id="t-status-01")
    await coord.submit(task)
    record = coord.task_status("t-status-01")
    assert record is not None
    assert record.state == TaskState.COMPLETED


def test_task_status_unknown_task_returns_none():
    bus = EventBus()
    coord = TaskCoordinator(bus)
    assert coord.task_status("no-such-task") is None


# ---------------------------------------------------------------------------
# ROE/scope gate (enforced by ForgePlugin.execute_task)


@pytest.mark.asyncio
async def test_submit_fails_without_roe_id():
    bus = EventBus()
    coord = TaskCoordinator(bus)
    coord.register_plugin(_PassiveDiscoveryPlugin())
    task = _make_task(roe_id="")
    result = await coord.submit(task)
    assert result.status == TaskState.FAILED
    assert "ROE" in (result.error or "")


@pytest.mark.asyncio
async def test_submit_fails_without_scope():
    bus = EventBus()
    coord = TaskCoordinator(bus)
    coord.register_plugin(_PassiveDiscoveryPlugin())
    task = _make_task(scope=[])
    result = await coord.submit(task)
    assert result.status == TaskState.FAILED
    assert "scope" in (result.error or "")
