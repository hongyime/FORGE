"""Workflow engine: orchestration, state persistence, and resumability.

Public API:

* :class:`WorkflowDefinition`, :class:`WorkflowStage` — declarative recipe.
* :class:`StateStore`, :class:`WorkflowStateRow` — persistent checkpoints.
* :class:`WorkflowEngine` — async orchestrator.
* :data:`MVP_WORKFLOW` — default discovery -> analysis -> report pipeline.
* :data:`MAX_INTERMEDIATE_RESULTS_BYTES` — hard cap on persisted state size.

Status sentinels (``STATUS_PENDING``, ``STATUS_IN_PROGRESS``,
``STATUS_COMPLETED``, ``STATUS_FAILED``) are also re-exported for callers
introspecting checkpoint dictionaries.
"""

from forge.workflow.definitions import WorkflowDefinition, WorkflowStage
from forge.workflow.engine import WorkflowEngine
from forge.workflow.mvp_workflow import MVP_WORKFLOW
from forge.workflow.state_store import (
    MAX_INTERMEDIATE_RESULTS_BYTES,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_IN_PROGRESS,
    STATUS_PENDING,
    StateStore,
    WorkflowStateRow,
)

__all__ = [
    "MAX_INTERMEDIATE_RESULTS_BYTES",
    "MVP_WORKFLOW",
    "STATUS_COMPLETED",
    "STATUS_FAILED",
    "STATUS_IN_PROGRESS",
    "STATUS_PENDING",
    "StateStore",
    "WorkflowDefinition",
    "WorkflowEngine",
    "WorkflowStage",
    "WorkflowStateRow",
]
