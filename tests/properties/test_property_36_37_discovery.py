"""
tests/properties/test_property_36_37_discovery.py
Properties 36-37: Discovery agent
Validates Requirements 11.3, 11.5.

The Discovery agent runs a list of plugins against a list of in-scope
targets and aggregates their outputs into a single AssetInventory dict.

Properties:

* Property 36 - Discovery fault tolerance (Req 11.5) — a plugin failure
  does NOT abort discovery; the failure is recorded in coverage_gaps and
  remaining plugins continue.
* Property 37 - Discovery inventory structure (Req 11.3) — the published
  inventory always contains the documented top-level keys: hosts,
  services, ports, endpoints, identities, coverage_gaps.
"""

from __future__ import annotations

import pytest

from forge.agents.discovery import (
    INBOUND_TOPIC,
    OUTBOUND_TOPIC,
    ROLE,
    DiscoveryAgent,
)
from forge.audit.logger import AuditLogger
from forge.core.base_agent import Agent
from forge.core.message_models import AgentMessage
from forge.governance.scope_gate import EngagementScope, ScopeGate
from forge.plugins.base import (
    ExecutionMode,
    PluginMetadata,
    PluginResult,
    RiskLevel,
)
from forge.plugins.executor import PluginExecutor
from forge.plugins.loader import PluginLoader


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class _StaticPlugin:
    """A plugin that returns a fixed PluginResult."""

    def __init__(
        self,
        name: str,
        output: dict[str, object],
        success: bool = True,
    ) -> None:
        self._name = name
        self._output = output
        self._success = success

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name=self._name,
            version="1.0.0",
            capabilities=["enumerate"],
            execution_mode=ExecutionMode.IN_PROCESS,
            timeout_seconds=5,
            risk_level=RiskLevel.LOW,
        )

    async def execute(self, params: dict) -> PluginResult:
        return PluginResult(
            success=self._success,
            output=self._output,
            error=None if self._success else "synthetic plugin failure",
        )

    async def health_check(self) -> bool:
        return True


class _ExplodingPlugin:
    """A plugin that always raises."""

    def __init__(self, name: str) -> None:
        self._name = name

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name=self._name,
            version="1.0.0",
            capabilities=["enumerate"],
            execution_mode=ExecutionMode.IN_PROCESS,
            timeout_seconds=5,
            risk_level=RiskLevel.LOW,
        )

    async def execute(self, params: dict) -> PluginResult:
        raise RuntimeError(f"deliberate failure from {self._name}")

    async def health_check(self) -> bool:
        return False


class _StubLoader:
    """A PluginLoader stand-in for tests, indexed by tool name."""

    def __init__(self, plugins: dict[str, object]) -> None:
        self._plugins = dict(plugins)

    def resolve(self, name: str):  # type: ignore[no-untyped-def]
        if name not in self._plugins:
            raise KeyError(f"No plugin registered with name {name!r}")
        return self._plugins[name]

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and name in self._plugins


def _make_agent(
    *,
    plugins: dict[str, object],
    scope_targets: list[str],
) -> tuple[DiscoveryAgent, AuditLogger]:
    audit = AuditLogger()
    loader = _StubLoader(plugins)
    executor = PluginExecutor(audit=audit)
    scope = ScopeGate(
        EngagementScope(domains=scope_targets, ip_ranges=[], urls=[]),
        audit_logger=audit,
    )
    agent = DiscoveryAgent(
        plugin_loader=loader,  # type: ignore[arg-type]
        executor=executor,
        scope_gate=scope,
        audit=audit,
    )
    return agent, audit


def _msg(payload: dict, cid: str = "cid-disc") -> AgentMessage:
    return AgentMessage(topic=INBOUND_TOPIC, payload=payload, correlation_id=cid)


# ---------------------------------------------------------------------------
# Static contract
# ---------------------------------------------------------------------------


class TestDiscoveryAgentSurface:
    def test_role_topic(self) -> None:
        agent, _ = _make_agent(plugins={}, scope_targets=["example.com"])
        assert agent.role == ROLE == "discovery"
        assert agent.subscribed_topics == [INBOUND_TOPIC]

    def test_protocol_conformance(self) -> None:
        agent, _ = _make_agent(plugins={}, scope_targets=["example.com"])
        assert isinstance(agent, Agent)


# ---------------------------------------------------------------------------
# Property 37 - Inventory structure
# ---------------------------------------------------------------------------


class TestProperty37InventoryStructure:
    """Inventory always contains the six documented top-level keys."""

    REQUIRED_KEYS = {
        "hosts",
        "services",
        "ports",
        "endpoints",
        "identities",
        "coverage_gaps",
    }

    @pytest.mark.asyncio
    async def test_empty_run_still_produces_complete_inventory(self) -> None:
        agent, _ = _make_agent(plugins={}, scope_targets=["example.com"])
        outputs = await agent.receive_message(
            _msg(
                {
                    "scope_targets": ["example.com"],
                    "plugins": [],
                    "params": {},
                }
            )
        )
        assert len(outputs) == 1
        assert outputs[0].topic == OUTBOUND_TOPIC
        inventory_obj = outputs[0].payload.get("asset_inventory")
        assert isinstance(inventory_obj, dict)
        assert self.REQUIRED_KEYS.issubset(inventory_obj.keys())

    @pytest.mark.asyncio
    async def test_inventory_keys_are_lists(self) -> None:
        plugin = _StaticPlugin(
            "host_scanner",
            output={
                "hosts": [{"ip": "10.0.0.1"}],
                "services": [{"name": "ssh", "port": 22}],
            },
        )
        agent, _ = _make_agent(plugins={"host_scanner": plugin}, scope_targets=["example.com"])
        outputs = await agent.receive_message(
            _msg(
                {
                    "scope_targets": ["example.com"],
                    "plugins": ["host_scanner"],
                }
            )
        )
        inventory = outputs[0].payload["asset_inventory"]
        assert isinstance(inventory, dict)
        for k in self.REQUIRED_KEYS:
            assert isinstance(inventory[k], list), (
                f"Inventory[{k!r}] must be a list, got {type(inventory[k]).__name__}"
            )


# ---------------------------------------------------------------------------
# Property 36 - Fault tolerance
# ---------------------------------------------------------------------------


class TestProperty36FaultTolerance:
    """A failing plugin does not abort discovery."""

    @pytest.mark.asyncio
    async def test_one_plugin_fails_others_continue(self) -> None:
        ok_plugin = _StaticPlugin(
            "ok",
            output={"hosts": [{"ip": "10.0.0.1"}]},
        )
        bad_plugin = _ExplodingPlugin("bad")

        agent, _audit = _make_agent(
            plugins={"ok": ok_plugin, "bad": bad_plugin},
            scope_targets=["example.com"],
        )

        outputs = await agent.receive_message(
            _msg(
                {
                    "scope_targets": ["example.com"],
                    "plugins": ["bad", "ok"],
                }
            )
        )
        # Discovery still completes
        assert len(outputs) == 1
        inventory = outputs[0].payload["asset_inventory"]
        assert isinstance(inventory, dict)

        # Successful plugin's output is included
        hosts = inventory.get("hosts", [])
        assert isinstance(hosts, list)
        assert any("10.0.0.1" in str(h) for h in hosts)

        # Failed plugin recorded as a coverage gap
        gaps = inventory.get("coverage_gaps", [])
        assert isinstance(gaps, list)
        assert len(gaps) >= 1
        assert any("bad" in str(gap) for gap in gaps)

    @pytest.mark.asyncio
    async def test_plugin_resolution_failure_recorded_as_gap(self) -> None:
        """Asking for a non-existent plugin yields a coverage gap, not a crash."""
        agent, _ = _make_agent(plugins={}, scope_targets=["example.com"])
        outputs = await agent.receive_message(
            _msg(
                {
                    "scope_targets": ["example.com"],
                    "plugins": ["does_not_exist"],
                }
            )
        )
        inventory = outputs[0].payload["asset_inventory"]
        gaps = inventory.get("coverage_gaps", [])
        assert isinstance(gaps, list)
        assert any("does_not_exist" in str(g) for g in gaps)

    @pytest.mark.asyncio
    async def test_out_of_scope_target_recorded_as_gap(self) -> None:
        """Targets outside the EngagementScope are not dispatched."""
        plugin = _StaticPlugin("scanner", output={"hosts": [{"ip": "10.0.0.1"}]})
        agent, _ = _make_agent(plugins={"scanner": plugin}, scope_targets=["example.com"])
        outputs = await agent.receive_message(
            _msg(
                {
                    "scope_targets": ["example.com", "evil.com"],
                    "plugins": ["scanner"],
                }
            )
        )
        inventory = outputs[0].payload["asset_inventory"]
        gaps = inventory.get("coverage_gaps", [])
        assert isinstance(gaps, list)
        # Out-of-scope target appears in coverage_gaps
        assert any("evil.com" in str(g) for g in gaps)
