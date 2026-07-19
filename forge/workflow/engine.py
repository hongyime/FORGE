"""
forge/workflow/engine.py — Multi-stage workflow orchestration.

The :class:`WorkflowEngine` drives a :class:`WorkflowDefinition` through
its ordered stages. Each transition is checkpointed via the
:class:`StateStore` so an interrupted run can be resumed without
re-executing completed stages (Requirements 5.3, 6.1, 6.5). Stage
execution is delegated to agents via the :class:`MessageBus`: the engine
publishes an :class:`AgentMessage` on the stage's topic and waits for the
caller to invoke :meth:`advance_stage` (success) or :meth:`fail_stage`
(failure) once a result is observed.

Retry accounting lives in ``intermediate_results["_retries"]`` keyed by
stage name. When a stage exceeds its configured ``max_attempts`` the
workflow is marked failed and :class:`WorkflowFailedError` is raised
(Requirement 5.5).

Resumption (Requirement 6.4) consults the state store for incomplete
rows. Rows whose ``checkpoint_valid`` flag is ``False`` fall back to the
last valid checkpoint; if none exists,
:class:`CheckpointCorruptedError` is raised after auditing the failure.

Hardening (P0/P1/P2 fixes):

* P0-1 - optimistic concurrency control: every read-modify-write goes
  through a bounded retry loop using ``save_checkpoint(expected_version=...)``;
  the loser of a race surfaces :class:`ConcurrentCheckpointError`.
* P0-2 - safe AST whitelist evaluator replaces the prior ``eval`` call.
* P0-5 - resume-idempotency claim via :meth:`StateStore.try_claim_for_resume`.
* P1-8 - oversized checkpoints are caught and the workflow is marked failed
  rather than letting :class:`CheckpointTooLargeError` propagate uncaught.
* P2-7 - stage-index out-of-bounds invariant violations end the workflow
  cleanly with an audit trail rather than a stack trace.
* P2-8 - JSON decode failures on the persisted columns trigger
  ``mark_corrupted`` and audit ERROR with safe defaults.
* P2-11 - :meth:`restart_workflow` resets a finished/failed workflow back
  to its first stage and re-publishes the initial message.

Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 6.1, 6.4, 6.5
"""

from __future__ import annotations

import ast
import asyncio
import copy
import json
import logging
import random
import time
import uuid
from typing import TYPE_CHECKING, Any

from forge.audit.models import AuditEntry, AuditEventType
from forge.core.errors import (
    CheckpointCorruptedError,
    CheckpointTooLargeError,
    ConcurrentCheckpointError,
    UnsafeTransitionConditionError,
    WorkflowFailedError,
)
from forge.core.message_models import AgentMessage
from forge.workflow.definitions import WorkflowDefinition, WorkflowStage
from forge.workflow.state_store import (
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_IN_PROGRESS,
    STATUS_PENDING,
    StateStore,
    WorkflowStateRow,
)

if TYPE_CHECKING:
    from forge.audit.logger import AuditLogger
    from forge.bus.base import MessageBus

_LOG = logging.getLogger(__name__)

_RETRIES_KEY = "_retries"

# P0-1: optimistic-concurrency retry budget. Three attempts is a sane
# default for a single-process race; multi-host contention is bounded by
# the database's own locking.
_CONCURRENCY_MAX_ATTEMPTS = 3
_CONCURRENCY_BASE_BACKOFF_S = 0.005


# ---------------------------------------------------------------------------
# Safe AST evaluator for transition conditions (P0-2)
# ---------------------------------------------------------------------------

# Whitelist of AST node types that are SAFE to evaluate inside a workflow
# transition condition. Anything outside this set (in particular Attribute,
# Call, Lambda, comprehensions) is rejected with
# :class:`UnsafeTransitionConditionError`.
_ALLOWED_AST_NODES: tuple[type[ast.AST], ...] = (
    ast.Expression,
    ast.Constant,
    ast.Name,
    ast.Load,
    ast.Compare,
    ast.BoolOp,
    ast.UnaryOp,
    ast.BinOp,
    ast.Subscript,
    ast.Slice,
    ast.Tuple,
    ast.List,
    ast.Dict,
    ast.IfExp,
    # Operators
    ast.Eq,
    ast.NotEq,
    ast.Lt,
    ast.LtE,
    ast.Gt,
    ast.GtE,
    ast.In,
    ast.NotIn,
    ast.Is,
    ast.IsNot,
    ast.And,
    ast.Or,
    ast.Not,
    ast.USub,
    ast.UAdd,
    ast.Add,
    ast.Sub,
    ast.Mult,
    ast.Div,
    ast.Mod,
    ast.FloorDiv,
)

# The single name the evaluator binds. Any other Name reference is rejected.
_ALLOWED_NAMES: frozenset[str] = frozenset({"result"})


def _safe_eval_condition(condition: str, last_result: dict[str, object]) -> bool:
    """Evaluate ``condition`` against ``last_result`` in a strict sandbox.

    The expression is parsed, every AST node is checked against
    :data:`_ALLOWED_AST_NODES`, and only the bound name ``result`` is
    permitted. Attribute access (``.foo``), function calls, lambdas, and
    comprehensions are forbidden — these were the escape hatches that
    made the prior ``eval``-based implementation a sandbox bypass risk
    (P0-2).

    The bound ``result`` value is deep-copied before evaluation so even
    if the expression managed to mutate a dict (e.g. via subscript
    assignment, which we also forbid) the caller's original dict cannot
    be touched.

    Args:
        condition: Python expression. ``None`` is handled by the caller.
        last_result: Mapping bound to the name ``result``.

    Returns:
        Truthiness of the evaluated expression.

    Raises:
        UnsafeTransitionConditionError: The expression contains a node
            type or name reference outside the whitelist, or fails to
            parse at all.
    """
    try:
        tree = ast.parse(condition, mode="eval")
    except SyntaxError as exc:
        raise UnsafeTransitionConditionError(
            condition, f"syntax error: {exc.msg}"
        ) from exc

    for node in ast.walk(tree):
        if isinstance(node, _ALLOWED_AST_NODES):
            if isinstance(node, ast.Name) and node.id not in _ALLOWED_NAMES:
                raise UnsafeTransitionConditionError(
                    condition,
                    f"reference to disallowed name {node.id!r} "
                    f"(only {sorted(_ALLOWED_NAMES)} allowed)",
                )
            continue
        # Explicitly reject the most common attack vectors with helpful
        # error messages for whoever wrote the workflow.
        if isinstance(node, ast.Attribute):
            raise UnsafeTransitionConditionError(
                condition,
                "attribute access (`obj.attr`) is forbidden; use bracket "
                "indexing like result['key']",
            )
        if isinstance(node, ast.Call):
            raise UnsafeTransitionConditionError(
                condition, "function calls are forbidden"
            )
        if isinstance(node, ast.Lambda):
            raise UnsafeTransitionConditionError(
                condition, "lambdas are forbidden"
            )
        if isinstance(
            node,
            (
                ast.ListComp,
                ast.SetComp,
                ast.DictComp,
                ast.GeneratorExp,
            ),
        ):
            raise UnsafeTransitionConditionError(
                condition, "comprehensions and generator expressions are forbidden"
            )
        raise UnsafeTransitionConditionError(
            condition, f"AST node {type(node).__name__} is not in the whitelist"
        )

    code = compile(tree, "<workflow-condition>", "eval")
    sandbox_globals: dict[str, Any] = {"__builtins__": {}}
    sandbox_locals: dict[str, Any] = {"result": copy.deepcopy(last_result)}
    # Strict no-builtin no-name evaluation. Any leftover identifier in the
    # expression triggers NameError, which we re-raise as
    # UnsafeTransitionConditionError for a uniform error surface.
    try:
        # AST already whitelisted above; bracket access + comparisons only.
        value = eval(code, sandbox_globals, sandbox_locals)  # noqa: S307 # nosec B307
    except NameError as exc:
        raise UnsafeTransitionConditionError(
            condition, f"unknown name: {exc}"
        ) from exc
    return bool(value)


class WorkflowEngine:
    """Async orchestrator for declarative workflow definitions.

    Args:
        bus: Message bus used to publish per-stage :class:`AgentMessage`
            envelopes to the appropriate agent.
        state_store: Persistence layer for checkpoints; the engine writes
            after every state transition (Requirement 5.3).
        audit: Append-only audit logger; receives ``STATE_TRANSITION`` and
            ``ERROR`` events for every workflow lifecycle change.

    The engine is stateless beyond its constructor injectables: each
    workflow's execution state is stored in the state store, identified
    by the UUID returned from :meth:`start_workflow`.
    """

    def __init__(
        self,
        bus: "MessageBus",
        state_store: StateStore,
        audit: "AuditLogger",
    ) -> None:
        self._bus = bus
        self._store = state_store
        self._audit = audit
        # In-memory registry of definitions keyed by (name, version) so the
        # engine can resolve the right stages during resumption without
        # requiring callers to re-pass the definition.
        self._definitions: dict[tuple[str, str], WorkflowDefinition] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register_definition(self, definition: WorkflowDefinition) -> None:
        """Register a definition so it is available for resumption lookups."""
        self._definitions[(definition.name, definition.version)] = definition

    async def start_workflow(
        self,
        definition: WorkflowDefinition,
        params: dict[str, object] | None = None,
    ) -> str:
        """Create a workflow instance and publish its first stage message.

        Args:
            definition: The workflow recipe to instantiate.
            params: Optional initial workflow context merged into every
                stage's payload template.

        Returns:
            The newly minted workflow UUID, used as the correlation id for
            all subsequent bus messages and audit entries.
        """
        self.register_definition(definition)
        workflow_id = str(uuid.uuid4())
        params = dict(params) if params else {}

        stage_statuses: dict[str, str] = {s.name: STATUS_PENDING for s in definition.stages}
        first_stage = definition.stages[0]
        stage_statuses[first_stage.name] = STATUS_IN_PROGRESS

        intermediate_results: dict[str, object] = {
            "_params": params,
            _RETRIES_KEY: {},
        }

        await self._store.save_checkpoint(
            workflow_id=workflow_id,
            current_stage_index=0,
            stage_statuses=stage_statuses,
            intermediate_results=intermediate_results,
            is_complete=False,
            failure_reason=None,
            definition_name=definition.name,
            definition_version=definition.version,
        )

        await self._publish_stage_message(workflow_id, first_stage, params)

        await self._audit.log(
            AuditEntry(
                correlation_id=workflow_id,
                event_type=AuditEventType.STATE_TRANSITION,
                tool_name="workflow_engine",
                input_params={
                    "action": "start",
                    "definition": definition.name,
                    "version": definition.version,
                    "stage": first_stage.name,
                },
                output_summary=f"workflow started: {definition.name}@{definition.version}",
                success=True,
            )
        )
        return workflow_id

    async def advance_stage(
        self, workflow_id: str, stage_result: dict[str, object]
    ) -> None:
        """Mark the current stage completed and advance to the next.

        Persists after the transition (Requirement 5.3). Evaluates the
        outgoing stage's ``transition_condition``; if it returns falsy the
        workflow halts at the current index without advancing. Publishes
        the next stage's message on success, or marks the workflow
        complete when the final stage finishes.

        The read-modify-write cycle runs inside an optimistic-concurrency
        retry loop (P0-1). If the row's version moves under us we retry
        up to :data:`_CONCURRENCY_MAX_ATTEMPTS` times with small
        randomised backoff before re-raising
        :class:`ConcurrentCheckpointError`.
        """
        last_exc: Exception | None = None
        for attempt in range(_CONCURRENCY_MAX_ATTEMPTS):
            try:
                await self._advance_stage_once(workflow_id, stage_result)
                return
            except ConcurrentCheckpointError as exc:
                last_exc = exc
                if attempt < _CONCURRENCY_MAX_ATTEMPTS - 1:
                    await asyncio.sleep(
                        _CONCURRENCY_BASE_BACKOFF_S * (1 + random.random())
                        * (attempt + 1)
                    )
                    continue
                await self._audit.log(
                    AuditEntry(
                        correlation_id=workflow_id,
                        event_type=AuditEventType.ERROR,
                        tool_name="workflow_engine",
                        input_params={"action": "advance_stage", "attempts": attempt + 1},
                        output_summary="advance_stage concurrency conflict exhausted",
                        success=False,
                        error_detail=str(exc),
                    )
                )
                raise
        # Unreachable, but the type checker wants a definite return path.
        if last_exc is not None:  # pragma: no cover
            raise last_exc

    async def fail_stage(self, workflow_id: str, error: str) -> None:
        """Record a stage failure; retry or fail the workflow.

        Increments the retry counter for the current stage. When the count
        reaches the stage's ``max_attempts`` the workflow is marked failed
        and :class:`WorkflowFailedError` is raised (Requirement 5.5). For
        recoverable failures the engine re-publishes the stage's message
        and the caller may try again.

        Wrapped in the same optimistic-concurrency retry loop as
        :meth:`advance_stage` (P0-1).
        """
        last_exc: Exception | None = None
        for attempt in range(_CONCURRENCY_MAX_ATTEMPTS):
            try:
                await self._fail_stage_once(workflow_id, error)
                return
            except ConcurrentCheckpointError as exc:
                last_exc = exc
                if attempt < _CONCURRENCY_MAX_ATTEMPTS - 1:
                    await asyncio.sleep(
                        _CONCURRENCY_BASE_BACKOFF_S * (1 + random.random())
                        * (attempt + 1)
                    )
                    continue
                await self._audit.log(
                    AuditEntry(
                        correlation_id=workflow_id,
                        event_type=AuditEventType.ERROR,
                        tool_name="workflow_engine",
                        input_params={"action": "fail_stage", "attempts": attempt + 1},
                        output_summary="fail_stage concurrency conflict exhausted",
                        success=False,
                        error_detail=str(exc),
                    )
                )
                raise
        if last_exc is not None:  # pragma: no cover
            raise last_exc

    async def _advance_stage_once(
        self, workflow_id: str, stage_result: dict[str, object]
    ) -> None:
        """Single attempt at advancing the stage; raises on version mismatch."""
        row = await self._load_or_raise(workflow_id)
        definition = self._resolve_definition(row)
        stages = definition.stages

        current_index = row.current_stage_index

        # P2-7: stage index past the end of the definition while the row
        # is still marked incomplete is an invariant violation. Mark the
        # workflow failed and audit; do not raise so the caller's
        # retry-loop is not derailed.
        if current_index >= len(stages) and not row.is_complete:
            await self._handle_stage_index_oob(row, len(stages))
            return

        if current_index >= len(stages):
            _LOG.warning("advance_stage on already-complete workflow %s", workflow_id)
            return

        current_stage = stages[current_index]
        stage_statuses = self._decode_statuses(row, workflow_id, definition)
        results = self._decode_results(row, workflow_id)

        stage_statuses[current_stage.name] = STATUS_COMPLETED
        results[current_stage.name] = stage_result
        version = row.version

        # Evaluate optional transition condition before advancing. The
        # safe AST evaluator raises UnsafeTransitionConditionError for
        # hostile expressions; callers see that surface directly and the
        # workflow stays at the current stage so an operator can fix the
        # definition.
        try:
            should_advance = self._evaluate_transition(
                current_stage.transition_condition, stage_result
            )
        except UnsafeTransitionConditionError:
            await self._audit.log(
                AuditEntry(
                    correlation_id=workflow_id,
                    event_type=AuditEventType.ERROR,
                    tool_name="workflow_engine",
                    input_params={
                        "stage": current_stage.name,
                        "condition": current_stage.transition_condition,
                    },
                    output_summary="unsafe transition_condition rejected",
                    success=False,
                )
            )
            raise

        if not should_advance:
            await self._save_with_size_guard(
                workflow_id=workflow_id,
                current_stage_index=current_index,
                stage_statuses=stage_statuses,
                intermediate_results=results,
                is_complete=True,
                failure_reason="transition_condition_false",
                expected_version=version,
            )
            await self._audit.log(
                AuditEntry(
                    correlation_id=workflow_id,
                    event_type=AuditEventType.STATE_TRANSITION,
                    tool_name="workflow_engine",
                    output_summary=(
                        f"workflow halted at {current_stage.name}: condition false"
                    ),
                    success=True,
                )
            )
            return

        next_index = current_index + 1
        if next_index >= len(stages):
            await self._save_with_size_guard(
                workflow_id=workflow_id,
                current_stage_index=next_index,
                stage_statuses=stage_statuses,
                intermediate_results=results,
                is_complete=True,
                failure_reason=None,
                expected_version=version,
            )
            await self._audit.log(
                AuditEntry(
                    correlation_id=workflow_id,
                    event_type=AuditEventType.STATE_TRANSITION,
                    tool_name="workflow_engine",
                    output_summary=f"workflow completed after {current_stage.name}",
                    success=True,
                )
            )
            return

        next_stage = stages[next_index]
        stage_statuses[next_stage.name] = STATUS_IN_PROGRESS
        await self._save_with_size_guard(
            workflow_id=workflow_id,
            current_stage_index=next_index,
            stage_statuses=stage_statuses,
            intermediate_results=results,
            is_complete=False,
            failure_reason=None,
            expected_version=version,
        )

        params = self._extract_params(results)
        await self._publish_stage_message(workflow_id, next_stage, params, results)

        await self._audit.log(
            AuditEntry(
                correlation_id=workflow_id,
                event_type=AuditEventType.STATE_TRANSITION,
                tool_name="workflow_engine",
                input_params={
                    "from_stage": current_stage.name,
                    "to_stage": next_stage.name,
                },
                output_summary=f"advanced {current_stage.name} -> {next_stage.name}",
                success=True,
            )
        )

    async def _fail_stage_once(self, workflow_id: str, error: str) -> None:
        """Single attempt at failing the stage; raises on version mismatch."""
        row = await self._load_or_raise(workflow_id)
        definition = self._resolve_definition(row)
        stages = definition.stages

        current_index = row.current_stage_index

        # P2-7: bounds invariant
        if current_index >= len(stages) and not row.is_complete:
            await self._handle_stage_index_oob(row, len(stages))
            return

        if current_index >= len(stages):
            _LOG.warning("fail_stage on already-complete workflow %s", workflow_id)
            return

        current_stage = stages[current_index]
        stage_statuses = self._decode_statuses(row, workflow_id, definition)
        results = self._decode_results(row, workflow_id)
        version = row.version

        retries_obj = results.get(_RETRIES_KEY, {})
        retries: dict[str, int] = {}
        if isinstance(retries_obj, dict):
            for k, v in retries_obj.items():
                try:
                    retries[str(k)] = int(v)
                except (TypeError, ValueError):
                    continue
        attempts = retries.get(current_stage.name, 0) + 1
        retries[current_stage.name] = attempts
        results[_RETRIES_KEY] = retries

        if attempts >= current_stage.max_attempts:
            stage_statuses[current_stage.name] = STATUS_FAILED
            await self._save_with_size_guard(
                workflow_id=workflow_id,
                current_stage_index=current_index,
                stage_statuses=stage_statuses,
                intermediate_results=results,
                is_complete=True,
                failure_reason=f"stage {current_stage.name!r} retries exhausted: {error}",
                expected_version=version,
            )
            await self._audit.log(
                AuditEntry(
                    correlation_id=workflow_id,
                    event_type=AuditEventType.ERROR,
                    tool_name="workflow_engine",
                    input_params={"stage": current_stage.name, "attempts": attempts},
                    output_summary=f"workflow failed at {current_stage.name}",
                    success=False,
                    error_detail=error,
                )
            )
            raise WorkflowFailedError(
                f"workflow {workflow_id} failed at stage {current_stage.name!r}: {error}"
            )

        # Recoverable: persist retry state, re-publish, audit warning.
        stage_statuses[current_stage.name] = STATUS_IN_PROGRESS
        await self._save_with_size_guard(
            workflow_id=workflow_id,
            current_stage_index=current_index,
            stage_statuses=stage_statuses,
            intermediate_results=results,
            is_complete=False,
            failure_reason=None,
            expected_version=version,
        )
        params = self._extract_params(results)
        await self._publish_stage_message(workflow_id, current_stage, params, results)

        await self._audit.log(
            AuditEntry(
                correlation_id=workflow_id,
                event_type=AuditEventType.WARNING,
                tool_name="workflow_engine",
                input_params={
                    "stage": current_stage.name,
                    "attempt": attempts,
                    "max_attempts": current_stage.max_attempts,
                },
                output_summary=f"retrying {current_stage.name} (attempt {attempts})",
                success=False,
                error_detail=error,
            )
        )

    async def get_status(self, workflow_id: str) -> dict[str, object]:
        """Return a snapshot of the workflow's progress.

        The dict contains: ``current_stage`` (name or ``None`` when
        complete), ``elapsed_time`` seconds since start,
        ``completion_percentage`` (0-100), ``is_complete`` boolean, and
        ``failure_reason`` (Requirement 5.6).
        """
        row = await self._load_or_raise(workflow_id)
        definition = self._resolve_definition(row)
        stages = definition.stages
        total = len(stages)

        if row.is_complete:
            current_stage_name: str | None = None
            completed = sum(
                1
                for status in self._decode_statuses(row, workflow_id, definition).values()
                if status == STATUS_COMPLETED
            )
        else:
            idx = min(row.current_stage_index, total - 1)
            current_stage_name = stages[idx].name
            completed = row.current_stage_index

        completion_pct = (completed / total) * 100.0 if total else 100.0
        elapsed = max(0.0, time.time() - row.started_at)

        return {
            "current_stage": current_stage_name,
            "elapsed_time": elapsed,
            "completion_percentage": completion_pct,
            "is_complete": row.is_complete,
            "failure_reason": row.failure_reason,
        }

    async def resume_incomplete_workflows(self) -> list[str]:
        """Resume every interrupted workflow found in the state store.

        For each row returned by
        :meth:`StateStore.load_incomplete_workflows`:

        * If ``checkpoint_valid`` is ``False`` the engine consults
          :meth:`StateStore.get_last_valid_checkpoint`. When no valid
          checkpoint exists the corruption is audited and
          :class:`CheckpointCorruptedError` is raised for the operator to
          handle (Requirement 6.4).
        * Otherwise the engine attempts an atomic claim via
          :meth:`StateStore.try_claim_for_resume` (P0-5). If another
          worker has already claimed the row within the claim window the
          attempt is skipped and audited. Workflows whose stage index has
          run past the definition (P2-7) are marked failed.
        * Successful claims re-publish the in-progress stage's bus
          message; completed stages are skipped (Requirement 6.5).

        Returns:
            The list of workflow ids successfully re-published.
        """
        rows = await self._store.load_incomplete_workflows()
        resumed: list[str] = []
        for row in rows:
            workflow_id = row.id
            if not row.checkpoint_valid:
                fallback = await self._store.get_last_valid_checkpoint(workflow_id)
                if fallback is None:
                    await self._audit.log(
                        AuditEntry(
                            correlation_id=workflow_id,
                            event_type=AuditEventType.ERROR,
                            tool_name="workflow_engine",
                            output_summary="checkpoint corrupted; no fallback",
                            success=False,
                            error_detail="checkpoint_corrupted",
                        )
                    )
                    raise CheckpointCorruptedError(
                        f"workflow {workflow_id} checkpoint corrupted with no recoverable "
                        "prior checkpoint"
                    )
                row = fallback

            try:
                definition = self._resolve_definition(row)
            except KeyError:
                _LOG.warning(
                    "skip resume for %s: definition %s@%s not registered",
                    workflow_id,
                    row.definition_name,
                    row.definition_version,
                )
                continue

            stages = definition.stages
            idx = row.current_stage_index

            # P2-7 - bounds invariant on resume.
            if idx >= len(stages):
                await self._handle_stage_index_oob(row, len(stages))
                continue

            # P0-5: atomic claim. Skip if someone else already grabbed
            # this row inside the claim window or completed it under us.
            claimed = await self._store.try_claim_for_resume(workflow_id)
            if not claimed:
                await self._audit.log(
                    AuditEntry(
                        correlation_id=workflow_id,
                        event_type=AuditEventType.STATE_TRANSITION,
                        tool_name="workflow_engine",
                        output_summary="workflow_resume_skipped",
                        success=True,
                    )
                )
                continue

            stage = stages[idx]
            results = self._decode_results(row, workflow_id)
            params = self._extract_params(results)
            await self._publish_stage_message(workflow_id, stage, params, results)

            await self._audit.log(
                AuditEntry(
                    correlation_id=workflow_id,
                    event_type=AuditEventType.STATE_TRANSITION,
                    tool_name="workflow_engine",
                    input_params={"resumed_stage": stage.name, "stage_index": idx},
                    output_summary=f"resumed workflow at {stage.name}",
                    success=True,
                )
            )
            resumed.append(workflow_id)
        return resumed

    async def restart_workflow(
        self, workflow_id: str, *, reset_retries: bool = True
    ) -> None:
        """Reset and re-run a previously failed or completed workflow (P2-11).

        Loads the existing row, resets ``is_complete`` to ``False``,
        clears the ``failure_reason``, rewinds the stage index to ``0``,
        marks every stage status back to ``STATUS_PENDING`` (with the
        first stage flipped to ``STATUS_IN_PROGRESS``), optionally clears
        the retry bookkeeping in ``intermediate_results["_retries"]``,
        bumps ``version``, persists, and re-publishes the first stage's
        bus message. An audit ``STATE_TRANSITION`` entry is emitted with
        ``output_summary="workflow_restarted"``.

        Args:
            workflow_id: Identifier of the workflow to restart.
            reset_retries: When ``True`` (default) the retry counters are
                wiped so the restarted run gets a full retry budget. Set
                to ``False`` to preserve the existing counters across the
                restart, e.g. when restarting a transiently-failed
                workflow without granting more attempts.

        Raises:
            KeyError: ``workflow_id`` does not exist in the state store.
            ConcurrentCheckpointError: A concurrent writer changed the
                row between the read and the write.
        """
        row = await self._load_or_raise(workflow_id)
        definition = self._resolve_definition(row)
        stages = definition.stages
        version = row.version

        # Rebuild status map from the definition so newly-added stages in
        # an updated definition are also reset to pending.
        new_statuses: dict[str, str] = {s.name: STATUS_PENDING for s in stages}
        new_statuses[stages[0].name] = STATUS_IN_PROGRESS

        results = self._decode_results(row, workflow_id)
        if reset_retries:
            results[_RETRIES_KEY] = {}

        await self._save_with_size_guard(
            workflow_id=workflow_id,
            current_stage_index=0,
            stage_statuses=new_statuses,
            intermediate_results=results,
            is_complete=False,
            failure_reason=None,
            expected_version=version,
        )

        params = self._extract_params(results)
        await self._publish_stage_message(workflow_id, stages[0], params, results)

        await self._audit.log(
            AuditEntry(
                correlation_id=workflow_id,
                event_type=AuditEventType.STATE_TRANSITION,
                tool_name="workflow_engine",
                input_params={
                    "action": "restart",
                    "reset_retries": reset_retries,
                    "stage": stages[0].name,
                },
                output_summary="workflow_restarted",
                success=True,
            )
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _publish_stage_message(
        self,
        workflow_id: str,
        stage: WorkflowStage,
        params: dict[str, object],
        results: dict[str, object] | None = None,
    ) -> None:
        """Build and publish the :class:`AgentMessage` for ``stage``.

        The payload is the stage's ``payload_template`` shallow-merged with
        the runtime params dict; runtime params win on key collision.
        Prior stage results are exposed under the ``_results`` key so a
        downstream stage's payload template can reference them.
        """
        payload: dict[str, object] = dict(stage.payload_template)
        payload.update(params)
        if results is not None:
            payload["_results"] = {
                k: v for k, v in results.items() if not k.startswith("_")
            }
        message = AgentMessage(
            topic=stage.topic,
            payload=payload,
            correlation_id=workflow_id,
            source_agent="workflow_engine",
        )
        result = self._bus.publish(stage.topic, message)
        if asyncio.iscoroutine(result):
            await result

    async def _save_with_size_guard(
        self,
        *,
        workflow_id: str,
        current_stage_index: int,
        stage_statuses: dict[str, str],
        intermediate_results: dict[str, object],
        is_complete: bool,
        failure_reason: str | None,
        expected_version: int | None,
    ) -> None:
        """Wrap ``save_checkpoint`` to handle :class:`CheckpointTooLargeError`.

        On size-cap breach (P1-8) the workflow is marked failed via a
        secondary save (with empty results to ensure the failure record
        itself fits) and an ERROR audit entry is emitted before the error
        propagates to the caller.
        """
        try:
            await self._store.save_checkpoint(
                workflow_id=workflow_id,
                current_stage_index=current_stage_index,
                stage_statuses=stage_statuses,
                intermediate_results=intermediate_results,
                is_complete=is_complete,
                failure_reason=failure_reason,
                expected_version=expected_version,
            )
        except CheckpointTooLargeError as exc:
            failure_msg = (
                f"checkpoint_too_large:{exc.size_bytes} bytes > "
                f"{exc.limit_bytes} bytes"
            )
            # Best-effort failure record: drop the oversized payload so the
            # failure marker itself fits. A separate read-modify-write to
            # avoid recursing into the size guard.
            try:
                await self._store.save_checkpoint(
                    workflow_id=workflow_id,
                    current_stage_index=current_stage_index,
                    stage_statuses=stage_statuses,
                    intermediate_results={
                        "_size_cap_exceeded": True,
                        "_size_bytes": exc.size_bytes,
                        "_limit_bytes": exc.limit_bytes,
                    },
                    is_complete=True,
                    failure_reason=failure_msg,
                )
            except Exception as inner:  # pragma: no cover - best effort
                _LOG.error(
                    "failed to record size-cap failure for %s: %s",
                    workflow_id,
                    inner,
                )
            await self._audit.log(
                AuditEntry(
                    correlation_id=workflow_id,
                    event_type=AuditEventType.ERROR,
                    tool_name="workflow_engine",
                    output_summary=failure_msg,
                    success=False,
                    error_detail=str(exc),
                )
            )
            raise

    async def _handle_stage_index_oob(
        self, row: WorkflowStateRow, total_stages: int
    ) -> None:
        """Mark a workflow failed when ``current_stage_index >= len(stages)`` (P2-7).

        The caller has already verified that ``row.is_complete`` is
        ``False``. This method writes a terminal checkpoint with
        ``failure_reason="stage_index_out_of_bounds:idx>=n"`` and audits
        ERROR. Uses a non-conditional save (``expected_version=None``) so
        we cannot fail to record the invariant violation.
        """
        idx = row.current_stage_index
        failure_reason = f"stage_index_out_of_bounds:{idx}>={total_stages}"
        # Reuse current statuses if decodable; otherwise empty dict so the
        # failure record itself does not depend on JSON validity.
        try:
            statuses = json.loads(row.stage_statuses) if row.stage_statuses else {}
            if not isinstance(statuses, dict):
                statuses = {}
        except json.JSONDecodeError:
            statuses = {}
        await self._store.save_checkpoint(
            workflow_id=row.id,
            current_stage_index=idx,
            stage_statuses={str(k): str(v) for k, v in statuses.items()},
            intermediate_results={"_stage_index_out_of_bounds": True},
            is_complete=True,
            failure_reason=failure_reason,
        )
        await self._audit.log(
            AuditEntry(
                correlation_id=row.id,
                event_type=AuditEventType.ERROR,
                tool_name="workflow_engine",
                output_summary=failure_reason,
                success=False,
                error_detail=failure_reason,
            )
        )

    @staticmethod
    def _evaluate_transition(
        condition: str | None, last_result: dict[str, object]
    ) -> bool:
        """Evaluate a transition condition with the safe AST whitelist (P0-2).

        ``None`` is treated as unconditional advance. Hostile or
        malformed expressions raise
        :class:`UnsafeTransitionConditionError`; the caller surfaces this
        directly so an operator sees the rejection rather than the
        workflow advancing on a swallowed exception.
        """
        if condition is None:
            return True
        return _safe_eval_condition(condition, last_result)

    async def _load_or_raise(self, workflow_id: str) -> WorkflowStateRow:
        row = await self._store.load_workflow(workflow_id)
        if row is None:
            raise KeyError(f"workflow {workflow_id!r} not found in state store")
        return row

    def _resolve_definition(self, row: WorkflowStateRow) -> WorkflowDefinition:
        key = (row.definition_name, row.definition_version)
        try:
            return self._definitions[key]
        except KeyError as exc:
            raise KeyError(
                f"WorkflowDefinition {row.definition_name}@{row.definition_version} "
                "is not registered with the engine"
            ) from exc

    def _decode_statuses(
        self,
        row: WorkflowStateRow,
        workflow_id: str,
        definition: WorkflowDefinition | None = None,
    ) -> dict[str, str]:
        """Decode stage_statuses with corruption recovery (P2-8).

        On :class:`json.JSONDecodeError` we mark the row corrupted, audit
        ERROR, and return all-pending defaults so the caller can keep
        making forward progress (or fail cleanly) instead of crashing.
        """
        try:
            decoded = json.loads(row.stage_statuses) if row.stage_statuses else {}
        except json.JSONDecodeError as exc:
            asyncio.ensure_future(self._mark_corrupt_and_audit(workflow_id, exc))
            if definition is not None:
                return {s.name: STATUS_PENDING for s in definition.stages}
            return {}
        if not isinstance(decoded, dict):
            return {}
        return {str(k): str(v) for k, v in decoded.items()}

    def _decode_results(
        self, row: WorkflowStateRow, workflow_id: str
    ) -> dict[str, object]:
        """Decode intermediate_results with corruption recovery (P2-8)."""
        try:
            decoded = (
                json.loads(row.intermediate_results) if row.intermediate_results else {}
            )
        except json.JSONDecodeError as exc:
            asyncio.ensure_future(self._mark_corrupt_and_audit(workflow_id, exc))
            return {}
        if not isinstance(decoded, dict):
            return {}
        return {str(k): v for k, v in decoded.items()}

    async def _mark_corrupt_and_audit(
        self, workflow_id: str, exc: json.JSONDecodeError
    ) -> None:
        """Persist the corruption flag and emit an ERROR audit entry (P2-8)."""
        try:
            await self._store.mark_corrupted(workflow_id)
        except Exception as inner:  # pragma: no cover - best effort
            _LOG.error(
                "failed to mark %s corrupted after decode failure: %s",
                workflow_id,
                inner,
            )
        await self._audit.log(
            AuditEntry(
                correlation_id=workflow_id,
                event_type=AuditEventType.ERROR,
                tool_name="workflow_engine",
                output_summary="checkpoint_corrupt_decode_failed",
                success=False,
                error_detail=str(exc),
            )
        )

    @staticmethod
    def _extract_params(results: dict[str, object]) -> dict[str, object]:
        params_obj = results.get("_params", {})
        if isinstance(params_obj, dict):
            return {str(k): v for k, v in params_obj.items()}
        return {}
