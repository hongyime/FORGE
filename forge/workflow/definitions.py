"""
forge/workflow/definitions.py — Workflow stage and definition models.

Declarative description of a multi-stage agent pipeline. A
:class:`WorkflowDefinition` is an immutable, versioned recipe consumed by
:class:`forge.workflow.engine.WorkflowEngine`. Each :class:`WorkflowStage`
maps an agent role to a bus topic plus a payload template merged with the
runtime workflow context, and may carry an optional transition condition
that is evaluated against the previous stage's result before advancing.

Requirements: 5.1, 5.2
"""

from __future__ import annotations

import warnings
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


class WorkflowStage(BaseModel):
    """Single ordered step within a workflow.

    Attributes:
        name: Stage identifier, unique within the parent workflow.
        agent_role: Logical role of the agent expected to handle this stage.
        topic: Message bus topic the engine publishes to when the stage runs.
        payload_template: Static parameters merged with the runtime workflow
            context to form the published :class:`AgentMessage` payload.
        max_attempts: Maximum number of attempts (initial + retries) before
            the workflow stage is failed. ``max_attempts=2`` means at most 2
            total attempts (Requirement 5.5).
        transition_condition: Optional Python expression evaluated against
            the previous stage's result. The stage advances only when the
            expression returns truthy. ``None`` means unconditional advance.

    Note:
        The legacy keyword ``retry_limit`` is still accepted for backward
        compatibility and emits a :class:`DeprecationWarning`. Prefer
        ``max_attempts`` in new code.
    """

    name: str
    agent_role: str
    topic: str
    payload_template: dict[str, object] = Field(default_factory=dict)
    max_attempts: int = 3
    transition_condition: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _accept_retry_limit_alias(cls, data: Any) -> Any:
        """Accept the legacy ``retry_limit`` field as an alias for ``max_attempts``.

        P2-1 backward-compat shim: callers using the old name still work
        but receive a :class:`DeprecationWarning` so the deprecation is
        visible in test logs and CI output. If both names are supplied the
        new name wins; we still warn about the legacy field.
        """
        if not isinstance(data, dict):
            return data
        if "retry_limit" in data:
            warnings.warn(
                "WorkflowStage.retry_limit is deprecated; use max_attempts instead.",
                DeprecationWarning,
                stacklevel=2,
            )
            legacy_value = data.pop("retry_limit")
            data.setdefault("max_attempts", legacy_value)
        return data

    @property
    def retry_limit(self) -> int:
        """Backward-compatible alias for :attr:`max_attempts`.

        Some legacy callers read ``stage.retry_limit`` directly. Keep the
        attribute reachable so they continue to compile, while new code
        and the engine use :attr:`max_attempts`.
        """
        return self.max_attempts


class WorkflowDefinition(BaseModel):
    """Versioned, ordered collection of stages.

    Attributes:
        name: Human-readable workflow identifier.
        version: Semantic version string (e.g. ``"1.0.0"``).
        stages: Ordered list of :class:`WorkflowStage`; must be non-empty
            and contain unique stage names.
    """

    name: str
    version: str
    stages: list[WorkflowStage]

    @field_validator("stages")
    @classmethod
    def _stages_must_be_non_empty(cls, v: list[WorkflowStage]) -> list[WorkflowStage]:
        """A workflow with zero stages cannot make progress; reject early."""
        if not v:
            raise ValueError("WorkflowDefinition.stages must contain at least one stage")
        return v

    @field_validator("stages")
    @classmethod
    def _stages_must_have_unique_names(cls, v: list[WorkflowStage]) -> list[WorkflowStage]:
        """Duplicate stage names break status lookup and resumption."""
        seen: set[str] = set()
        for stage in v:
            if stage.name in seen:
                raise ValueError(f"Duplicate stage name {stage.name!r} in WorkflowDefinition")
            seen.add(stage.name)
        return v
