"""
forge/agents/discovery.py — Asset discovery agent.

The Discovery agent enumerates the engagement attack surface by running a
configured list of discovery plugins (port scanners, subdomain enumerators,
endpoint crawlers, IAM principal listers, …) against the operator-declared
scope targets. Plugin outputs are merged into a single :class:`AssetInventory`
dict that downstream agents (Analysis, Reporting) consume.

Inbound topic:
    ``agent.discovery.run`` — payload must contain:

    * ``scope_targets``: ``list[str]`` of in-scope domains, IPs, URLs.
    * ``plugins``: ``list[str]`` of plugin tool names to dispatch.
    * ``params`` *(optional)*: ``dict[str, object]`` of extra parameters
      merged into every plugin call (e.g. credentials, depth limits).

Outbound topic:
    ``agent.discovery.complete`` — payload contains:

    * ``asset_inventory``: aggregated :class:`AssetInventory` dict with
      keys ``hosts``, ``services``, ``ports``, ``endpoints``, ``identities``,
      ``coverage_gaps`` (Req 11.3).
    * ``plugins_invoked``: list of plugin names that were dispatched.
    * ``plugins_succeeded`` / ``plugins_failed``: per-plugin status counts.

Scope enforcement (Req 11.1):
    Every target is validated through :class:`ScopeGate.is_in_scope` before
    plugin dispatch. Out-of-scope targets are silently dropped and recorded
    in ``coverage_gaps``; no plugin ever sees an out-of-scope target.

Fault isolation (Req 11.5):
    A plugin failure (resolution failure, ``PluginResult.success=False``,
    timeout, or any other exception) does NOT abort discovery. The failure
    is recorded in ``coverage_gaps`` with a reason string and discovery
    proceeds with the next plugin. This satisfies the partial-results
    contract: incomplete coverage MUST be visible, never silently dropped.

Identity inventory (Req 11.2):
    Plugins that surface IAM principals MUST emit them under an
    ``identities`` key in :attr:`PluginResult.output`. The discovery agent
    aggregates these without interpretation; classification belongs to the
    Analysis agent.

Requirements: 11.1, 11.2, 11.3, 11.4, 11.5
"""

from __future__ import annotations

import logging
import uuid
from typing import TYPE_CHECKING, cast

from forge.audit.models import AuditEntry, AuditEventType
from forge.core.message_models import AgentMessage

if TYPE_CHECKING:  # pragma: no cover - type-hint only imports
    from forge.audit.logger import AuditLogger
    from forge.governance.scope_gate import ScopeGate
    from forge.plugins.executor import PluginExecutor
    from forge.plugins.loader import PluginLoader

__all__ = ["DiscoveryAgent", "AssetInventory"]

_LOG = logging.getLogger(__name__)

#: Topic the discovery agent consumes from.
INBOUND_TOPIC: str = "agent.discovery.run"

#: Topic the discovery agent publishes its aggregated inventory on.
OUTBOUND_TOPIC: str = "agent.discovery.complete"

#: Stable agent role identifier registered with the AgentRegistry.
ROLE: str = "discovery"

#: Inventory keys that plugin outputs may contribute to. Any unknown key in
#: ``PluginResult.output`` is preserved under a per-plugin sub-dict so no
#: tool-specific data is silently dropped.
_INVENTORY_KEYS: tuple[str, ...] = (
    "hosts",
    "services",
    "ports",
    "endpoints",
    "identities",
)


# Type alias for the aggregated inventory dict shape returned to downstream
# agents. We use a plain dict rather than a Pydantic model so the structure
# stays cheaply mergeable across heterogeneous plugin outputs.
AssetInventory = dict[str, object]


class DiscoveryAgent:
    """Run discovery plugins and aggregate their outputs into one inventory.

    The agent is stateful only through its injected dependencies (loader,
    executor, scope gate, audit). Each invocation is independent: it reads
    the targets and plugin list from the inbound message, dispatches the
    plugins serially, and emits a single completion message.

    Args:
        plugin_loader: Resolves plugin tool names to :class:`Plugin`
            instances. ``KeyError`` from :meth:`PluginLoader.resolve`
            is caught and recorded as a coverage gap.
        executor: Dispatches each resolved plugin under its declared
            execution mode and timeout.
        scope_gate: Filters ``scope_targets`` so out-of-scope addresses
            are never forwarded to plugins (Req 11.1, 8.1).
        audit: Audit sink for ``STATE_TRANSITION`` and ``WARNING``
            entries describing the run outcome.

    Requirements: 11.1, 11.2, 11.3, 11.4, 11.5.
    """

    def __init__(
        self,
        plugin_loader: "PluginLoader",
        executor: "PluginExecutor",
        scope_gate: "ScopeGate",
        audit: "AuditLogger",
    ) -> None:
        self._loader = plugin_loader
        self._executor = executor
        self._scope = scope_gate
        self._audit = audit

    # ------------------------------------------------------------------
    # Agent protocol
    # ------------------------------------------------------------------

    @property
    def role(self) -> str:
        """Stable role identifier (``"discovery"``)."""
        return ROLE

    @property
    def subscribed_topics(self) -> list[str]:
        """Topics consumed by the discovery agent."""
        return [INBOUND_TOPIC]

    async def receive_message(
        self, message: AgentMessage
    ) -> list[AgentMessage]:
        """Run the configured plugins and emit one completion message.

        Args:
            message: Inbound :class:`AgentMessage` whose payload contains
                ``scope_targets`` and ``plugins`` keys.

        Returns:
            A single-element list containing the completion message
            published on :data:`OUTBOUND_TOPIC`.

        Raises:
            ValueError: When the payload is missing required keys.
        """
        payload = message.payload or {}

        targets_raw = payload.get("scope_targets")
        if not isinstance(targets_raw, list):
            raise ValueError(
                "DiscoveryAgent: payload['scope_targets'] must be a list, got "
                f"{type(targets_raw).__name__}"
            )
        plugins_raw = payload.get("plugins")
        if not isinstance(plugins_raw, list):
            raise ValueError(
                "DiscoveryAgent: payload['plugins'] must be a list, got "
                f"{type(plugins_raw).__name__}"
            )

        scope_targets: list[str] = [str(t) for t in targets_raw if t]
        plugin_names: list[str] = [str(n) for n in plugins_raw if n]

        extra_params_obj = payload.get("params", {})
        extra_params: dict[str, object] = (
            dict(extra_params_obj) if isinstance(extra_params_obj, dict) else {}
        )

        cid = message.correlation_id

        # ---- 1. Scope-filter the target list (Req 11.1, 8.1) ------------
        in_scope, out_of_scope = self._partition_targets(scope_targets, cid)

        # ---- 2. Initialise the aggregated inventory ---------------------
        inventory: AssetInventory = {key: [] for key in _INVENTORY_KEYS}
        coverage_gaps: list[dict[str, object]] = []
        for dropped in out_of_scope:
            coverage_gaps.append(
                {
                    "kind": "out_of_scope_target",
                    "target": dropped,
                    "reason": "Target rejected by ScopeGate",
                }
            )

        # ---- 3. Dispatch plugins, recording every failure --------------
        succeeded = 0
        failed = 0
        for plugin_name in plugin_names:
            ok = await self._run_plugin(
                plugin_name=plugin_name,
                targets=in_scope,
                extra_params=extra_params,
                inventory=inventory,
                coverage_gaps=coverage_gaps,
                correlation_id=cid,
            )
            if ok:
                succeeded += 1
            else:
                failed += 1

        inventory["coverage_gaps"] = coverage_gaps

        # ---- 4. Emit a single state-transition audit entry --------------
        await self._audit.log(
            AuditEntry(
                correlation_id=cid,
                event_type=AuditEventType.STATE_TRANSITION,
                agent_role=ROLE,
                output_summary=(
                    f"discovery_complete plugins_invoked={len(plugin_names)} "
                    f"succeeded={succeeded} failed={failed} "
                    f"in_scope_targets={len(in_scope)} "
                    f"out_of_scope_targets={len(out_of_scope)}"
                ),
                success=failed == 0,
            )
        )

        # ---- 5. Publish the inventory ----------------------------------
        out_payload: dict[str, object] = {
            "asset_inventory": inventory,
            "plugins_invoked": list(plugin_names),
            "plugins_succeeded": succeeded,
            "plugins_failed": failed,
        }
        return [
            AgentMessage(
                topic=OUTBOUND_TOPIC,
                payload=out_payload,
                correlation_id=cid,
                source_agent=ROLE,
            )
        ]

    async def report_status(self) -> dict[str, object]:
        """Return the agent's current status snapshot."""
        return {
            "role": ROLE,
            "subscribed_topics": list(self.subscribed_topics),
            "stateful": False,
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _partition_targets(
        self, targets: list[str], correlation_id: str
    ) -> tuple[list[str], list[str]]:
        """Split *targets* into ``(in_scope, out_of_scope)`` lists.

        Each call to :meth:`ScopeGate.is_in_scope` is wrapped in
        ``try/except`` so a malformed entry (e.g. an unparseable URL) only
        drops that single target rather than aborting the run.
        """
        in_scope: list[str] = []
        out_of_scope: list[str] = []
        for target in targets:
            try:
                allowed = self._scope.is_in_scope(target)
            except Exception:  # noqa: BLE001 - defensive isolation
                _LOG.warning(
                    "DiscoveryAgent[%s]: ScopeGate raised on target %r; "
                    "treating as out-of-scope",
                    correlation_id,
                    target,
                    exc_info=True,
                )
                out_of_scope.append(target)
                continue
            (in_scope if allowed else out_of_scope).append(target)
        return in_scope, out_of_scope

    async def _run_plugin(
        self,
        *,
        plugin_name: str,
        targets: list[str],
        extra_params: dict[str, object],
        inventory: AssetInventory,
        coverage_gaps: list[dict[str, object]],
        correlation_id: str,
    ) -> bool:
        """Resolve, invoke, and merge one plugin's output into *inventory*.

        Returns:
            True when the plugin completed with ``PluginResult.success=True``;
            False on any failure mode (resolution miss, timeout, ``success=False``,
            unexpected exception). Failures append a structured gap record
            rather than raising.
        """
        # ---- Resolution -------------------------------------------------
        try:
            plugin = self._loader.resolve(plugin_name)
        except KeyError as exc:
            coverage_gaps.append(
                {
                    "kind": "plugin_unavailable",
                    "plugin": plugin_name,
                    "reason": str(exc),
                }
            )
            await self._record_warning(
                tool_name=plugin_name,
                reason=f"Plugin not registered: {exc}",
                correlation_id=correlation_id,
            )
            return False

        # ---- Invocation -------------------------------------------------
        params: dict[str, object] = {**extra_params, "targets": list(targets)}
        sub_cid = f"{correlation_id}:{plugin_name}:{uuid.uuid4().hex[:8]}"
        try:
            result = await self._executor.execute(
                plugin, params=params, correlation_id=sub_cid
            )
        except Exception as exc:  # noqa: BLE001 - never abort discovery
            coverage_gaps.append(
                {
                    "kind": "plugin_exception",
                    "plugin": plugin_name,
                    "reason": f"{exc.__class__.__name__}: {exc}",
                }
            )
            await self._record_warning(
                tool_name=plugin_name,
                reason=f"Plugin raised: {exc.__class__.__name__}: {exc}",
                correlation_id=correlation_id,
            )
            return False

        if not result.success:
            coverage_gaps.append(
                {
                    "kind": "plugin_failed",
                    "plugin": plugin_name,
                    "reason": result.error or "plugin reported success=False",
                }
            )
            return False

        # ---- Merge ------------------------------------------------------
        self._merge_output(inventory, plugin_name, result.output)
        return True

    @staticmethod
    def _merge_output(
        inventory: AssetInventory,
        plugin_name: str,
        output: dict[str, object],
    ) -> None:
        """Merge a single plugin's ``output`` dict into *inventory*.

        Known inventory keys (``hosts``, ``services``, ``ports``, ``endpoints``,
        ``identities``) are flattened into the top-level inventory lists so
        downstream agents see one unified asset view. Any other keys are
        preserved under a ``per_plugin[<plugin>]`` sub-dict so tool-specific
        outputs (raw scan blobs, banner text, …) remain available without
        polluting the canonical inventory shape.
        """
        per_plugin_obj = inventory.setdefault("per_plugin", {})
        per_plugin: dict[str, object]
        if isinstance(per_plugin_obj, dict):
            per_plugin = cast("dict[str, object]", per_plugin_obj)
        else:  # pragma: no cover - defensive
            per_plugin = {}
            inventory["per_plugin"] = per_plugin

        extras: dict[str, object] = {}
        for key, value in output.items():
            if key in _INVENTORY_KEYS:
                bucket_obj = inventory.get(key)
                bucket: list[object]
                if isinstance(bucket_obj, list):
                    bucket = cast("list[object]", bucket_obj)
                else:  # pragma: no cover - defensive
                    bucket = []
                    inventory[key] = bucket
                if isinstance(value, list):
                    bucket.extend(value)
                else:
                    bucket.append(value)
            else:
                extras[key] = value
        if extras:
            per_plugin[plugin_name] = extras

    async def _record_warning(
        self, *, tool_name: str, reason: str, correlation_id: str
    ) -> None:
        """Emit a WARNING audit entry for a plugin-level failure."""
        await self._audit.log(
            AuditEntry(
                correlation_id=correlation_id,
                event_type=AuditEventType.WARNING,
                agent_role=ROLE,
                tool_name=tool_name,
                output_summary=f"discovery_plugin_failure: {reason}",
                success=False,
                error_detail=reason,
            )
        )
