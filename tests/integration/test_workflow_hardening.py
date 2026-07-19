"""
tests/integration/test_workflow_hardening.py — Integration smoke tests for
P0/P1/P2 hardening fixes against the workflow subsystem.

Verifies that the audit-flagged hostile transition expression
``().__class__.__base__.__subclasses__()`` is now rejected end-to-end
(not just at the module-level evaluator) when it appears in a real
:class:`WorkflowStage`.

Other hardening properties (size cap, optimistic concurrency, resume
idempotency, restart, OOB stage index, JSON decode recovery) are covered
exhaustively in
``tests/properties/test_property_14_to_21_workflow.py``; this module
exists to anchor the regression on the exact attack string captured in
the audit.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from forge.audit.logger import AuditLogger
from forge.audit.models import AuditEventType
from forge.bus.memory_bus import InMemoryMessageBus
from forge.core.errors import UnsafeTransitionConditionError
from forge.workflow import (
    StateStore,
    WorkflowDefinition,
    WorkflowEngine,
    WorkflowStage,
)
from forge.workflow.engine import _safe_eval_condition


# Hostile expressions captured from real-world sandbox-escape attempts.
# These are exactly the sort of strings an attacker would inject if a
# transition condition were sourced from untrusted input.
_HOSTILE_EXPRESSIONS: list[str] = [
    "().__class__.__base__.__subclasses__()",
    "result.__class__.__init__.__globals__",
    "[c for c in ().__class__.__base__.__subclasses__()]",
    "open('/etc/passwd')",
    "exec('import os')",
    "lambda: 1",
    "__import__('os')",
]


@pytest.mark.parametrize("hostile", _HOSTILE_EXPRESSIONS)
def test_module_level_evaluator_rejects_hostile(hostile: str) -> None:
    """The audit-flagged hostile string is rejected at the evaluator."""
    with pytest.raises(UnsafeTransitionConditionError):
        _safe_eval_condition(hostile, {})


@pytest.mark.asyncio
async def test_engine_advance_with_hostile_condition_raises(
    tmp_path: Path,
) -> None:
    """End-to-end: a workflow with a hostile transition_condition fails fast.

    Wires up a real :class:`StateStore` + :class:`WorkflowEngine` and tries
    to advance through a stage whose ``transition_condition`` is the
    classic ``().__class__.__base__.__subclasses__()`` sandbox-escape
    expression. The engine must raise
    :class:`UnsafeTransitionConditionError` and emit an ERROR audit entry
    rather than letting the expression evaluate.
    """
    db_url = f"sqlite:///{tmp_path / 'hardening.db'}"
    store = StateStore(db_url=db_url)
    await store.init_schema()
    bus = InMemoryMessageBus()
    audit = AuditLogger()
    engine = WorkflowEngine(bus=bus, state_store=store, audit=audit)
    try:
        wf = WorkflowDefinition(
            name="hostile_transition",
            version="1.0.0",
            stages=[
                WorkflowStage(
                    name="alpha",
                    agent_role="a",
                    topic="topic.alpha",
                    transition_condition=(
                        "().__class__.__base__.__subclasses__()"
                    ),
                ),
                WorkflowStage(
                    name="beta",
                    agent_role="b",
                    topic="topic.beta",
                ),
            ],
        )
        wid = await engine.start_workflow(wf)
        with pytest.raises(UnsafeTransitionConditionError):
            await engine.advance_stage(wid, {"out": "anything"})

        # Audit captures the rejection as ERROR.
        unsafe_errors = [
            e
            for e in audit.entries
            if e.event_type == AuditEventType.ERROR
            and e.output_summary == "unsafe transition_condition rejected"
        ]
        assert any(e.correlation_id == wid for e in unsafe_errors)
    finally:
        await store.close()
