"""
forge/workflow/mvp_workflow.py — Default discovery -> analysis -> report pipeline.

Canonical MVP workflow shipped with the platform: a three-stage sequence
that runs discovery, hands its output to the analysis agent, then renders
a markdown report. Used by the agent loop on first start when no other
workflow definition is configured.

Requirements: 5.1, 5.2
"""

from __future__ import annotations

from forge.workflow.definitions import WorkflowDefinition, WorkflowStage

MVP_WORKFLOW: WorkflowDefinition = WorkflowDefinition(
    name="mvp_discovery_analysis_report",
    version="1.0.0",
    stages=[
        WorkflowStage(
            name="discovery",
            agent_role="discovery",
            topic="agent.discovery.run",
            payload_template={"scope": "from_engagement"},
            max_attempts=3,
        ),
        WorkflowStage(
            name="analysis",
            agent_role="analysis",
            topic="agent.analysis.run",
            payload_template={"input": "discovery.output"},
            max_attempts=3,
        ),
        WorkflowStage(
            name="report",
            agent_role="reporting",
            topic="agent.reporting.run",
            payload_template={"input": "analysis.output", "format": "markdown"},
            max_attempts=2,
        ),
    ],
)
