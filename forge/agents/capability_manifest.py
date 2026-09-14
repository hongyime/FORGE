"""Capability manifest loader and validator for FORGE plugins (Explore #14).

Each plugin declares a ``forge.agent.capability.v1`` JSON manifest.
Unknown capabilities or topics are rejected on registration.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from forge.agents.event_bus import ALLOWED_TOPICS

__all__ = [
    "CapabilityManifest",
    "ALLOWED_CAPABILITIES",
    "validate_plugin_id",
    "load_manifest",
]

_PLUGIN_ID_RE = re.compile(r"^plugin_[a-z0-9][a-z0-9_.\\-]{2,63}$")

ALLOWED_CAPABILITIES: frozenset[str] = frozenset(
    {
        "passive_discovery",
        "identity_pivot",
        "artifact_parsing",
        "graph_enrichment",
        "report_generation",
        "monitoring",
        "credential_analysis",
        "active_validation",
    }
)

_SCHEMA = "forge.agent.capability.v1"


def validate_plugin_id(plugin_id: str) -> None:
    """Raise ValueError if *plugin_id* does not match the required pattern."""
    if not re.match(r"^plugin_[a-z0-9][a-z0-9_.\-]{2,63}$", plugin_id):
        raise ValueError(
            f"Invalid plugin_id {plugin_id!r}. "
            "Must start with 'plugin_' followed by 3-64 lowercase alnum/._- chars."
        )


@dataclass(frozen=True)
class CapabilityManifest:
    """Validated capability declaration for a ForgePlugin."""

    plugin_id: str
    version: str
    capabilities: frozenset[str]
    subscribes: frozenset[str]
    publishes: frozenset[str]
    schema: str = field(default=_SCHEMA)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "plugin_id": self.plugin_id,
            "version": self.version,
            "capabilities": sorted(self.capabilities),
            "subscribes": sorted(self.subscribes),
            "publishes": sorted(self.publishes),
        }


def load_manifest(raw: dict[str, Any]) -> CapabilityManifest:
    """Parse and validate a raw manifest dict.

    Raises ValueError on any schema or field violation.
    """
    schema = raw.get("schema", "")
    if schema != _SCHEMA:
        raise ValueError(
            f"Unsupported manifest schema {schema!r}; expected {_SCHEMA!r}"
        )

    plugin_id = str(raw.get("plugin_id", "")).strip()
    validate_plugin_id(plugin_id)

    version = str(raw.get("version", "")).strip()
    if not version:
        raise ValueError("version must not be empty")

    capabilities: frozenset[str] = frozenset(raw.get("capabilities", []))
    unknown_caps = capabilities - ALLOWED_CAPABILITIES
    if unknown_caps:
        raise ValueError(
            f"Unknown capabilities: {sorted(unknown_caps)}. "
            f"Allowed: {sorted(ALLOWED_CAPABILITIES)}"
        )

    subscribes: frozenset[str] = frozenset(raw.get("subscribes", []))
    unknown_subs = subscribes - ALLOWED_TOPICS
    if unknown_subs:
        raise ValueError(
            f"Unknown subscribe topics: {sorted(unknown_subs)}. "
            f"Allowed: {sorted(ALLOWED_TOPICS)}"
        )

    publishes: frozenset[str] = frozenset(raw.get("publishes", []))
    unknown_pubs = publishes - ALLOWED_TOPICS
    if unknown_pubs:
        raise ValueError(
            f"Unknown publish topics: {sorted(unknown_pubs)}. "
            f"Allowed: {sorted(ALLOWED_TOPICS)}"
        )

    return CapabilityManifest(
        plugin_id=plugin_id,
        version=version,
        capabilities=capabilities,
        subscribes=subscribes,
        publishes=publishes,
    )
