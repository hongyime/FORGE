"""Unit tests for forge.agents.base_plugin (Explore #14)."""

from __future__ import annotations

import pytest

from forge.agents.base_plugin import ForgePlugin, TaskResult, TaskSpec, TaskState
from forge.agents.capability_manifest import load_manifest
from forge.agents.event_bus import AgentEvent


# ---------------------------------------------------------------------------
# Fixtures

_MANIFEST = load_manifest(
    {
        "schema": "forge.agent.capability.v1",
        "plugin_id": "plugin_test_base",
        "version": "1.0.0",
        "capabilities": ["artifact_parsing"],
        "subscribes": [],
        "publishes": ["result.ready"],
    }
)


class _ConcretePlugin(ForgePlugin):
    capability_manifest = _MANIFEST
    _events: list[AgentEvent]

    def __init__(self) -> None:
        self._events = []

    async def handle_event(self, event: AgentEvent) -> None:
        self._events.append(event)

    async def run_task(self, task: TaskSpec) -> TaskResult:
        return TaskResult(
            task_id=task.task_id,
            plugin_id=self.capability_manifest.plugin_id,
            status=TaskState.COMPLETED,
            payload={"parsed": True},
        )


def _make_task(**kwargs) -> TaskSpec:
    defaults = dict(
        task_id="t-base-01",
        engagement_id=1001,
        capability="artifact_parsing",
        target="https://example.invalid/file.apk",
        roe_id="ROE-BASE-TEST",
        scope=["example.invalid"],
    )
    defaults.update(kwargs)
    return TaskSpec(**defaults)


# ---------------------------------------------------------------------------
# execute_task passes through to run_task when gate is clear


@pytest.mark.asyncio
async def test_execute_task_succeeds_with_valid_roe_and_scope():
    plugin = _ConcretePlugin()
    task = _make_task()
    result = await plugin.execute_task(task)
    assert result.status == TaskState.COMPLETED
    assert result.plugin_id == "plugin_test_base"


# ---------------------------------------------------------------------------
# ROE gate cannot be bypassed


@pytest.mark.asyncio
async def test_execute_task_rejects_empty_roe_id():
    plugin = _ConcretePlugin()
    task = _make_task(roe_id="")
    with pytest.raises(ValueError, match="ROE ID"):
        await plugin.execute_task(task)


@pytest.mark.asyncio
async def test_execute_task_rejects_whitespace_roe_id():
    plugin = _ConcretePlugin()
    task = _make_task(roe_id="   ")
    with pytest.raises(ValueError, match="ROE ID"):
        await plugin.execute_task(task)


@pytest.mark.asyncio
async def test_execute_task_rejects_empty_scope():
    plugin = _ConcretePlugin()
    task = _make_task(scope=[])
    with pytest.raises(ValueError, match="scope"):
        await plugin.execute_task(task)


# ---------------------------------------------------------------------------
# handle_event stores events


@pytest.mark.asyncio
async def test_handle_event_stores_incoming_events():
    plugin = _ConcretePlugin()
    ev = AgentEvent(
        topic="task.created",
        source_plugin_id="plugin_other",
        engagement_id=99,
        payload={"task_id": "t-x"},
    )
    await plugin.handle_event(ev)
    assert len(plugin._events) == 1
    assert plugin._events[0].engagement_id == 99


# ---------------------------------------------------------------------------
# Capability manifest is accessible on the class


def test_capability_manifest_accessible_on_class():
    assert _ConcretePlugin.capability_manifest.plugin_id == "plugin_test_base"
    assert "artifact_parsing" in _ConcretePlugin.capability_manifest.capabilities


def test_capability_manifest_accessible_on_instance():
    plugin = _ConcretePlugin()
    assert plugin.capability_manifest.version == "1.0.0"


# ---------------------------------------------------------------------------
# Abstract plugin cannot be instantiated without implementing abstract methods


def test_abstract_plugin_cannot_be_instantiated():
    with pytest.raises(TypeError):
        ForgePlugin()  # type: ignore[abstract]
