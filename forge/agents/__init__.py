"""Specialised agents: Planner, Discovery, Analysis, Reporting, Governance.

Explore #14 adds the agent collaboration layer:
  EventBus, CapabilityManifest, TaskCoordinator, ForgePlugin base class.
"""

from __future__ import annotations

from forge.agents.analysis import AnalysisAgent
from forge.agents.base_plugin import ForgePlugin, TaskResult, TaskSpec, TaskState
from forge.agents.capability_manifest import (
    ALLOWED_CAPABILITIES,
    CapabilityManifest,
    load_manifest,
)
from forge.agents.coordinator import TaskCoordinator
from forge.agents.discovery import DiscoveryAgent
from forge.agents.event_bus import ALLOWED_TOPICS, AgentEvent, EventBus
from forge.agents.governance import GovernanceAgent
from forge.agents.planner import PlannerAgent
from forge.agents.reporting import ReportingAgent

__all__ = [
    # Existing domain agents
    "AnalysisAgent",
    "DiscoveryAgent",
    "GovernanceAgent",
    "PlannerAgent",
    "ReportingAgent",
    # Explore #14 collaboration layer
    "AgentEvent",
    "ALLOWED_CAPABILITIES",
    "ALLOWED_TOPICS",
    "CapabilityManifest",
    "EventBus",
    "ForgePlugin",
    "TaskCoordinator",
    "TaskResult",
    "TaskSpec",
    "TaskState",
    "load_manifest",
]
