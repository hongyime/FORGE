"""
tests/properties/test_property_14_to_21_workflow.py
Properties 14-21: Workflow engine and state store
Validates Requirements 5.1, 5.2, 5.3, 5.5, 5.6, 6.1, 6.2, 6.4, 6.5.

Bundled into one file because all eight properties share the same async
StateStore + WorkflowEngine fixtures and exercise the same orchestration
surface.

Properties covered:

- Property 14 - Workflow definition acceptance (Req 5.1)
- Property 15 - Workflow instance uniqueness (Req 5.2)
- Property 16 - Workflow stage transitions (Req 5.3)
- Property 17 - Workflow failure handling (Req 5.5)
- Property 18 - Workflow status completeness (Req 5.6)
- Property 19 - State persistence completeness (Req 6.1)
- Property 20 - Workflow resumption correctness (Req 6.2, 6.5)
- Property 21 - Corrupted checkpoint recovery (Req 6.4)
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from forge.audit.logger import AuditLogger
from forge.audit.models import AuditEventType
from forge.bus.memory_bus import InMemoryMessageBus
from forge.core.errors import (
    CheckpointCorruptedError,
    CheckpointTooLargeError,
    ConcurrentCheckpointError,
    UnsafeTransitionConditionError,
    WorkflowFailedError,
)
from forge.core.message_models import AgentMessage
from forge.workflow import (
    MAX_INTERMEDIATE_RESULTS_BYTES,
    MVP_WORKFLOW,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_IN_PROGRESS,
    STATUS_PENDING,
    StateStore,
    WorkflowDefinition,
    WorkflowEngine,
    WorkflowStage,
)
from forge.workflow.engine import _safe_eval_condition


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def db_url(tmp_path: Path) -> str:
    """Return a fresh sqlite URL inside the test's tmp_path."""
    return f"sqlite:///{tmp_path / 'wf.db'}"


@pytest.fixture
async def state_store(db_url: str) -> StateStore:
    store = StateStore(db_url=db_url)
    await store.init_schema()
    yield store
    await store.close()


@pytest.fixture
async def engine(state_store: StateStore) -> WorkflowEngine:
    bus = InMemoryMessageBus()
    audit = AuditLogger()
    return WorkflowEngine(bus=bus, state_store=state_store, audit=audit)


@pytest.fixture
def two_stage_workflow() -> WorkflowDefinition:
    return WorkflowDefinition(
        name="two_stage_test",
        version="1.0.0",
        stages=[
            WorkflowStage(
                name="alpha",
                agent_role="agent_a",
                topic="topic.alpha",
                payload_template={"x": 1},
                max_attempts=2,
            ),
            WorkflowStage(
                name="beta",
                agent_role="agent_b",
                topic="topic.beta",
                payload_template={"x": 2},
                max_attempts=1,
            ),
        ],
    )


# ---------------------------------------------------------------------------
# Property 14 - Workflow definition acceptance (Req 5.1)
# ---------------------------------------------------------------------------


class TestProperty14DefinitionAcceptance:
    """WorkflowEngine.start_workflow accepts well-formed definitions."""

    @pytest.mark.asyncio
    async def test_well_formed_definition_accepted(
        self,
        engine: WorkflowEngine,
        two_stage_workflow: WorkflowDefinition,
    ) -> None:
        wid = await engine.start_workflow(two_stage_workflow)
        assert isinstance(wid, str)
        assert len(wid) > 0

    @pytest.mark.asyncio
    async def test_mvp_workflow_accepted(self, engine: WorkflowEngine) -> None:
        wid = await engine.start_workflow(MVP_WORKFLOW)
        assert isinstance(wid, str)

    def test_empty_stages_rejected_at_definition_time(self) -> None:
        with pytest.raises(ValidationError):
            WorkflowDefinition(name="empty", version="1.0.0", stages=[])

    def test_duplicate_stage_names_rejected(self) -> None:
        with pytest.raises(ValidationError):
            WorkflowDefinition(
                name="dup",
                version="1.0.0",
                stages=[
                    WorkflowStage(name="x", agent_role="a", topic="t1"),
                    WorkflowStage(name="x", agent_role="b", topic="t2"),
                ],
            )


# ---------------------------------------------------------------------------
# Property 15 - Workflow instance uniqueness (Req 5.2)
# ---------------------------------------------------------------------------


class TestProperty15InstanceUniqueness:
    """Each start_workflow yields a distinct, persistent workflow id."""

    @pytest.mark.asyncio
    async def test_two_starts_produce_distinct_ids(
        self,
        engine: WorkflowEngine,
        two_stage_workflow: WorkflowDefinition,
    ) -> None:
        wid_a = await engine.start_workflow(two_stage_workflow)
        wid_b = await engine.start_workflow(two_stage_workflow)
        assert wid_a != wid_b

    @pytest.mark.asyncio
    async def test_initial_state_persisted(
        self,
        engine: WorkflowEngine,
        state_store: StateStore,
        two_stage_workflow: WorkflowDefinition,
    ) -> None:
        wid = await engine.start_workflow(two_stage_workflow)
        row = await state_store.load_workflow(wid)
        assert row is not None
        assert row.id == wid
        assert row.definition_name == "two_stage_test"
        assert row.is_complete is False
        assert row.current_stage_index == 0


# ---------------------------------------------------------------------------
# Property 16 - Workflow stage transitions (Req 5.3)
# ---------------------------------------------------------------------------


class TestProperty16StageTransitions:
    """advance_stage marks current stage completed and progresses."""

    @pytest.mark.asyncio
    async def test_advance_marks_stage_completed(
        self,
        engine: WorkflowEngine,
        state_store: StateStore,
        two_stage_workflow: WorkflowDefinition,
    ) -> None:
        wid = await engine.start_workflow(two_stage_workflow)
        await engine.advance_stage(wid, {"output": "alpha-done"})

        row = await state_store.load_workflow(wid)
        assert row is not None
        statuses = json.loads(row.stage_statuses)
        assert statuses["alpha"] == STATUS_COMPLETED
        assert statuses["beta"] == STATUS_IN_PROGRESS
        assert row.current_stage_index == 1

    @pytest.mark.asyncio
    async def test_advancing_through_all_stages_completes_workflow(
        self,
        engine: WorkflowEngine,
        state_store: StateStore,
        two_stage_workflow: WorkflowDefinition,
    ) -> None:
        wid = await engine.start_workflow(two_stage_workflow)
        await engine.advance_stage(wid, {"alpha_result": True})
        await engine.advance_stage(wid, {"beta_result": True})

        row = await state_store.load_workflow(wid)
        assert row is not None
        assert row.is_complete is True
        statuses = json.loads(row.stage_statuses)
        assert statuses["alpha"] == STATUS_COMPLETED
        assert statuses["beta"] == STATUS_COMPLETED


# ---------------------------------------------------------------------------
# Property 17 - Workflow failure handling (Req 5.5)
# ---------------------------------------------------------------------------


class TestProperty17FailureHandling:
    """fail_stage raises WorkflowFailedError after retries exhausted."""

    @pytest.mark.asyncio
    async def test_failure_within_retry_budget_does_not_raise(
        self,
        engine: WorkflowEngine,
        two_stage_workflow: WorkflowDefinition,
    ) -> None:
        wid = await engine.start_workflow(two_stage_workflow)
        # alpha has retry_limit=2 -> first failure recoverable
        await engine.fail_stage(wid, "transient error")
        # No exception means the engine is willing to retry

    @pytest.mark.asyncio
    async def test_failure_after_retry_exhaustion_raises(
        self,
        engine: WorkflowEngine,
        state_store: StateStore,
        two_stage_workflow: WorkflowDefinition,
    ) -> None:
        wid = await engine.start_workflow(two_stage_workflow)
        # alpha retry_limit=2 means up to 2 total attempts; the 2nd
        # failure exhausts the budget and raises WorkflowFailedError.
        await engine.fail_stage(wid, "fail #1")

        with pytest.raises(WorkflowFailedError):
            await engine.fail_stage(wid, "fail #2 -- exhausted")

        # Workflow row marked failed
        row = await state_store.load_workflow(wid)
        assert row is not None
        assert row.is_complete is True
        assert row.failure_reason is not None


# ---------------------------------------------------------------------------
# Property 18 - Workflow status completeness (Req 5.6)
# ---------------------------------------------------------------------------


class TestProperty18StatusCompleteness:
    """get_status returns the documented dict shape."""

    REQUIRED_KEYS = {
        "current_stage",
        "elapsed_time",
        "completion_percentage",
        "is_complete",
        "failure_reason",
    }

    @pytest.mark.asyncio
    async def test_status_dict_has_required_keys(
        self,
        engine: WorkflowEngine,
        two_stage_workflow: WorkflowDefinition,
    ) -> None:
        wid = await engine.start_workflow(two_stage_workflow)
        status = await engine.get_status(wid)
        assert status is not None
        assert set(status.keys()).issuperset(self.REQUIRED_KEYS)

    @pytest.mark.asyncio
    async def test_status_progress_advances(
        self,
        engine: WorkflowEngine,
        two_stage_workflow: WorkflowDefinition,
    ) -> None:
        wid = await engine.start_workflow(two_stage_workflow)
        s0 = await engine.get_status(wid)
        await engine.advance_stage(wid, {"r": 1})
        s1 = await engine.get_status(wid)

        assert s0 is not None and s1 is not None
        # Completion percentage is monotonic non-decreasing across advance.
        assert s1["completion_percentage"] >= s0["completion_percentage"]
        assert s1["current_stage"] != s0["current_stage"]


# ---------------------------------------------------------------------------
# Property 19 - State persistence completeness (Req 6.1)
# ---------------------------------------------------------------------------


class TestProperty19StatePersistence:
    """Every checkpoint is persisted so a fresh process can read it back."""

    @pytest.mark.asyncio
    async def test_checkpoint_round_trip(
        self,
        db_url: str,
        two_stage_workflow: WorkflowDefinition,
    ) -> None:
        # Phase 1: start workflow, advance one stage, close store.
        bus = InMemoryMessageBus()
        audit = AuditLogger()
        store_a = StateStore(db_url=db_url)
        await store_a.init_schema()
        engine_a = WorkflowEngine(bus=bus, state_store=store_a, audit=audit)
        wid = await engine_a.start_workflow(two_stage_workflow)
        await engine_a.advance_stage(wid, {"alpha_result": True})
        await store_a.close()

        # Phase 2: open a fresh store at the same URL, observe state.
        store_b = StateStore(db_url=db_url)
        row = await store_b.load_workflow(wid)
        assert row is not None
        assert row.id == wid
        statuses = json.loads(row.stage_statuses)
        assert statuses["alpha"] == STATUS_COMPLETED
        await store_b.close()


# ---------------------------------------------------------------------------
# Property 20 - Workflow resumption correctness (Req 6.2, 6.5)
# ---------------------------------------------------------------------------


class TestProperty20WorkflowResumption:
    """resume_incomplete_workflows picks up where the prior process left off."""

    @pytest.mark.asyncio
    async def test_resume_finds_incomplete_workflows(
        self,
        db_url: str,
        two_stage_workflow: WorkflowDefinition,
    ) -> None:
        # Run engine A, leave one workflow mid-flight.
        bus_a = InMemoryMessageBus()
        audit_a = AuditLogger()
        store_a = StateStore(db_url=db_url)
        await store_a.init_schema()
        engine_a = WorkflowEngine(bus=bus_a, state_store=store_a, audit=audit_a)
        wid_active = await engine_a.start_workflow(two_stage_workflow)
        wid_done = await engine_a.start_workflow(two_stage_workflow)
        await engine_a.advance_stage(wid_done, {"a": 1})
        await engine_a.advance_stage(wid_done, {"b": 2})  # complete this one
        await store_a.close()

        # Engine B in the same process resumes:
        bus_b = InMemoryMessageBus()
        audit_b = AuditLogger()
        store_b = StateStore(db_url=db_url)
        engine_b = WorkflowEngine(
            bus=bus_b, state_store=store_b, audit=audit_b
        )
        engine_b.register_definition(two_stage_workflow)
        resumed = await engine_b.resume_incomplete_workflows()

        # Only the in-flight workflow is resumed; the completed one is not.
        assert wid_active in resumed
        assert wid_done not in resumed
        await store_b.close()

    @pytest.mark.asyncio
    async def test_completed_stages_not_re_executed(
        self,
        db_url: str,
        two_stage_workflow: WorkflowDefinition,
    ) -> None:
        # Start, advance once (alpha done), persist, resume.
        bus = InMemoryMessageBus()
        audit = AuditLogger()
        store = StateStore(db_url=db_url)
        await store.init_schema()
        engine = WorkflowEngine(bus=bus, state_store=store, audit=audit)
        engine.register_definition(two_stage_workflow)

        wid = await engine.start_workflow(two_stage_workflow)
        await engine.advance_stage(wid, {"alpha_result": True})

        # Resume - the engine should re-publish only the in-progress stage
        # (beta), not the completed stage (alpha).
        resumed = await engine.resume_incomplete_workflows()
        assert wid in resumed

        row = await store.load_workflow(wid)
        assert row is not None
        statuses = json.loads(row.stage_statuses)
        # Alpha stays completed; beta still in progress.
        assert statuses["alpha"] == STATUS_COMPLETED
        assert statuses["beta"] == STATUS_IN_PROGRESS
        await store.close()


# ---------------------------------------------------------------------------
# Property 21 - Corrupted checkpoint recovery (Req 6.4)
# ---------------------------------------------------------------------------


class TestProperty21CorruptedCheckpointRecovery:
    """When checkpoint_valid is False, resume falls back or raises."""

    @pytest.mark.asyncio
    async def test_corrupted_without_fallback_raises(
        self,
        db_url: str,
        two_stage_workflow: WorkflowDefinition,
    ) -> None:
        bus = InMemoryMessageBus()
        audit = AuditLogger()
        store = StateStore(db_url=db_url)
        await store.init_schema()
        engine = WorkflowEngine(bus=bus, state_store=store, audit=audit)
        engine.register_definition(two_stage_workflow)

        wid = await engine.start_workflow(two_stage_workflow)
        # Mark the only checkpoint as corrupted.
        await store.mark_corrupted(wid)

        # No prior valid checkpoint -> CheckpointCorruptedError on resume.
        with pytest.raises(CheckpointCorruptedError):
            await engine.resume_incomplete_workflows()

        # ERROR audit entry was emitted
        errors = [
            e for e in audit.entries if e.event_type == AuditEventType.ERROR
        ]
        assert any(wid in (e.correlation_id or "") for e in errors)
        await store.close()

    @pytest.mark.asyncio
    async def test_corrupted_does_not_resume_completed(
        self,
        db_url: str,
        two_stage_workflow: WorkflowDefinition,
    ) -> None:
        bus = InMemoryMessageBus()
        audit = AuditLogger()
        store = StateStore(db_url=db_url)
        await store.init_schema()
        engine = WorkflowEngine(bus=bus, state_store=store, audit=audit)
        engine.register_definition(two_stage_workflow)

        wid = await engine.start_workflow(two_stage_workflow)
        await engine.advance_stage(wid, {"a": 1})
        await engine.advance_stage(wid, {"b": 2})

        # mark_corrupted on a completed workflow -> resume skips it because
        # it is already complete, regardless of checkpoint_valid flag.
        await store.mark_corrupted(wid)
        resumed = await engine.resume_incomplete_workflows()
        assert wid not in resumed
        await store.close()


# ---------------------------------------------------------------------------
# Property 22 - Optimistic concurrency control (P0-1)
# ---------------------------------------------------------------------------


class TestProperty22ConcurrentAdvance:
    """P0-1: Concurrent advance_stage must NOT silently drop one writer.

    Two coroutines racing to advance the same workflow stage must end with
    either (a) both succeeding because the engine internally retried the
    loser of the race, or (b) one succeeding and one raising
    :class:`ConcurrentCheckpointError`. Silent loss of one writer is the
    failure mode this regression test guards against.
    """

    @pytest.mark.asyncio
    async def test_concurrent_advance_one_succeeds_or_raises(
        self,
        engine: WorkflowEngine,
        two_stage_workflow: WorkflowDefinition,
    ) -> None:
        wid = await engine.start_workflow(two_stage_workflow)
        results = await asyncio.gather(
            engine.advance_stage(wid, {"out": "A"}),
            engine.advance_stage(wid, {"out": "B"}),
            return_exceptions=True,
        )
        successes = [r for r in results if r is None]
        errors = [r for r in results if isinstance(r, BaseException)]
        # At least one writer must have succeeded.
        assert len(successes) >= 1, (
            f"both concurrent writers failed: {errors!r}"
        )
        # If only one succeeded, the other must have surfaced a
        # ConcurrentCheckpointError -- never silently dropped.
        if len(successes) == 1:
            assert any(
                isinstance(e, ConcurrentCheckpointError) for e in errors
            ), (
                f"second writer was silently dropped; errors={errors!r}"
            )

    @pytest.mark.asyncio
    async def test_save_checkpoint_with_stale_version_raises(
        self,
        state_store: StateStore,
        two_stage_workflow: WorkflowDefinition,
    ) -> None:
        """Direct StateStore-level test of optimistic concurrency."""
        wid = "wf-version-test"
        await state_store.save_checkpoint(
            workflow_id=wid,
            current_stage_index=0,
            stage_statuses={"alpha": STATUS_IN_PROGRESS},
            intermediate_results={},
            definition_name=two_stage_workflow.name,
            definition_version=two_stage_workflow.version,
        )
        row = await state_store.load_workflow(wid)
        assert row is not None
        good_version = row.version

        # First writer succeeds with the correct expected_version.
        await state_store.save_checkpoint(
            workflow_id=wid,
            current_stage_index=1,
            stage_statuses={"alpha": STATUS_COMPLETED},
            intermediate_results={"alpha": {"ok": True}},
            expected_version=good_version,
        )

        # Second writer with the stale version raises.
        with pytest.raises(ConcurrentCheckpointError):
            await state_store.save_checkpoint(
                workflow_id=wid,
                current_stage_index=1,
                stage_statuses={"alpha": STATUS_COMPLETED},
                intermediate_results={"alpha": {"ok": False}},
                expected_version=good_version,
            )


# ---------------------------------------------------------------------------
# Property 23 - Safe AST evaluator for transition conditions (P0-2)
# ---------------------------------------------------------------------------


class TestProperty23EvalSandbox:
    """P0-2: hostile transition_condition expressions must be rejected."""

    @pytest.mark.parametrize(
        "hostile",
        [
            "().__class__.__base__.__subclasses__()",
            "result.__class__.__init__.__globals__",
            "[c for c in ().__class__.__base__.__subclasses__()]",
            "open('/etc/passwd')",
            "exec('import os')",
            "lambda: 1",
            "__import__('os')",
            "result.get('count', 0) > 0",  # .get is Attribute access
            "len(result) > 0",  # len() is a Call
        ],
    )
    def test_unsafe_conditions_rejected(self, hostile: str) -> None:
        with pytest.raises(UnsafeTransitionConditionError):
            _safe_eval_condition(hostile, {})

    @pytest.mark.parametrize(
        "safe,result_value,expected",
        [
            ("result['ok'] == True", {"ok": True}, True),
            ("result['ok'] == True", {"ok": False}, False),
            (
                "result['count'] > 5 and result['status'] == 'done'",
                {"count": 10, "status": "done"},
                True,
            ),
            (
                "result['count'] > 5 and result['status'] == 'done'",
                {"count": 1, "status": "done"},
                False,
            ),
            ("result['n'] + 1 == 4", {"n": 3}, True),
            ("not result['fail']", {"fail": False}, True),
        ],
    )
    def test_safe_conditions_evaluate(
        self,
        safe: str,
        result_value: dict[str, Any],
        expected: bool,
    ) -> None:
        assert _safe_eval_condition(safe, result_value) is expected

    def test_evaluator_does_not_mutate_caller_dict(self) -> None:
        """Deep-copy guarantee: caller's dict cannot be touched by eval."""
        original: dict[str, Any] = {"nested": {"value": 1}}
        snapshot = json.loads(json.dumps(original))
        # A safe expression that touches the dict.
        _safe_eval_condition("result['nested']['value'] == 1", original)
        assert original == snapshot


# ---------------------------------------------------------------------------
# Property 24 - resume_incomplete_workflows idempotency (P0-5)
# ---------------------------------------------------------------------------


class TestProperty24ResumeIdempotency:
    """P0-5: resume called twice does not re-publish the workflow twice."""

    @pytest.mark.asyncio
    async def test_resume_twice_publishes_once(
        self,
        db_url: str,
        two_stage_workflow: WorkflowDefinition,
    ) -> None:
        # Phase 1: start a workflow, leave it mid-flight.
        bus_a = InMemoryMessageBus()
        audit_a = AuditLogger()
        store_a = StateStore(db_url=db_url)
        await store_a.init_schema()
        engine_a = WorkflowEngine(bus=bus_a, state_store=store_a, audit=audit_a)
        wid = await engine_a.start_workflow(two_stage_workflow)
        await store_a.close()

        # Phase 2: open a fresh store, resume twice in the same process.
        bus_b = InMemoryMessageBus()
        publish_count = {"n": 0}
        original_publish = bus_b.publish

        async def counting_publish(topic, message):  # type: ignore[no-untyped-def]
            if topic.startswith("topic."):
                publish_count["n"] += 1
            r = original_publish(topic, message)
            if asyncio.iscoroutine(r):
                await r

        bus_b.publish = counting_publish  # type: ignore[assignment,method-assign]
        audit_b = AuditLogger()
        store_b = StateStore(db_url=db_url)
        engine_b = WorkflowEngine(bus=bus_b, state_store=store_b, audit=audit_b)
        engine_b.register_definition(two_stage_workflow)

        first = await engine_b.resume_incomplete_workflows()
        second = await engine_b.resume_incomplete_workflows()

        # First resume picks the workflow up; second resume sees it as
        # already-claimed within the window and skips it.
        assert wid in first
        assert wid not in second
        # Exactly one publish on the workflow's stage topic.
        assert publish_count["n"] == 1, (
            f"expected 1 publish, got {publish_count['n']}"
        )
        # Audit captures the skip event.
        skips = [
            e
            for e in audit_b.entries
            if e.output_summary == "workflow_resume_skipped"
        ]
        assert any(e.correlation_id == wid for e in skips)
        await store_b.close()

    @pytest.mark.asyncio
    async def test_try_claim_for_resume_atomic(
        self,
        state_store: StateStore,
        two_stage_workflow: WorkflowDefinition,
    ) -> None:
        """StateStore-level atomicity test: only one of N concurrent claims wins."""
        wid = "wf-claim-race"
        await state_store.save_checkpoint(
            workflow_id=wid,
            current_stage_index=0,
            stage_statuses={"alpha": STATUS_IN_PROGRESS},
            intermediate_results={},
            definition_name=two_stage_workflow.name,
            definition_version=two_stage_workflow.version,
        )
        outcomes = await asyncio.gather(
            *[state_store.try_claim_for_resume(wid) for _ in range(5)]
        )
        # Exactly one True, the rest False.
        assert outcomes.count(True) == 1, f"outcomes={outcomes!r}"
        assert outcomes.count(False) == 4


# ---------------------------------------------------------------------------
# Property 25 - Checkpoint size cap (P1-8)
# ---------------------------------------------------------------------------


class TestProperty25CheckpointSizeCap:
    """P1-8: oversized intermediate_results triggers CheckpointTooLargeError."""

    @pytest.mark.asyncio
    async def test_oversized_save_raises(
        self,
        state_store: StateStore,
        two_stage_workflow: WorkflowDefinition,
    ) -> None:
        # Build a payload guaranteed to exceed the 10 MiB cap.
        big_blob = "x" * (MAX_INTERMEDIATE_RESULTS_BYTES + 1024)
        with pytest.raises(CheckpointTooLargeError) as ei:
            await state_store.save_checkpoint(
                workflow_id="wf-too-big",
                current_stage_index=0,
                stage_statuses={"alpha": STATUS_IN_PROGRESS},
                intermediate_results={"blob": big_blob},
                definition_name=two_stage_workflow.name,
                definition_version=two_stage_workflow.version,
            )
        assert ei.value.workflow_id == "wf-too-big"
        assert ei.value.size_bytes > MAX_INTERMEDIATE_RESULTS_BYTES
        assert ei.value.limit_bytes == MAX_INTERMEDIATE_RESULTS_BYTES

    @pytest.mark.asyncio
    async def test_engine_marks_workflow_failed_on_oversize(
        self,
        engine: WorkflowEngine,
        state_store: StateStore,
        two_stage_workflow: WorkflowDefinition,
    ) -> None:
        wid = await engine.start_workflow(two_stage_workflow)
        big_blob = "y" * (MAX_INTERMEDIATE_RESULTS_BYTES + 2048)
        with pytest.raises(CheckpointTooLargeError):
            await engine.advance_stage(wid, {"big": big_blob})
        # The workflow is marked failed with a size-cap reason.
        row = await state_store.load_workflow(wid)
        assert row is not None
        assert row.is_complete is True
        assert row.failure_reason is not None
        assert "checkpoint_too_large" in row.failure_reason


# ---------------------------------------------------------------------------
# Property 26 - Stage index out-of-bounds invariant (P2-7)
# ---------------------------------------------------------------------------


class TestProperty26StageIndexOutOfBounds:
    """P2-7: corrupt rows where current_stage_index >= len(stages) end cleanly."""

    @pytest.mark.asyncio
    async def test_oob_index_marks_workflow_failed_on_resume(
        self,
        state_store: StateStore,
        two_stage_workflow: WorkflowDefinition,
    ) -> None:
        wid = "wf-oob"
        # Hand-craft a row with an index past the end of the definition.
        await state_store.save_checkpoint(
            workflow_id=wid,
            current_stage_index=99,  # only 2 stages defined
            stage_statuses={"alpha": STATUS_COMPLETED, "beta": STATUS_COMPLETED},
            intermediate_results={},
            is_complete=False,
            definition_name=two_stage_workflow.name,
            definition_version=two_stage_workflow.version,
        )
        bus = InMemoryMessageBus()
        audit = AuditLogger()
        engine = WorkflowEngine(bus=bus, state_store=state_store, audit=audit)
        engine.register_definition(two_stage_workflow)

        resumed = await engine.resume_incomplete_workflows()
        assert wid not in resumed
        row = await state_store.load_workflow(wid)
        assert row is not None
        assert row.is_complete is True
        assert row.failure_reason is not None
        assert "stage_index_out_of_bounds" in row.failure_reason
        # ERROR audit captures the invariant violation.
        oob_errors = [
            e
            for e in audit.entries
            if e.event_type == AuditEventType.ERROR
            and e.output_summary is not None
            and "stage_index_out_of_bounds" in e.output_summary
        ]
        assert any(e.correlation_id == wid for e in oob_errors)


# ---------------------------------------------------------------------------
# Property 27 - JSON decode failure recovery (P2-8)
# ---------------------------------------------------------------------------


class TestProperty27JsonDecodeRecovery:
    """P2-8: corrupted JSON columns trigger mark_corrupted + ERROR audit."""

    @pytest.mark.asyncio
    async def test_corrupt_intermediate_results_marks_corrupted(
        self,
        engine: WorkflowEngine,
        state_store: StateStore,
        two_stage_workflow: WorkflowDefinition,
    ) -> None:
        wid = await engine.start_workflow(two_stage_workflow)
        # Reach into the underlying SQL row and corrupt the JSON column.
        sm = state_store._ensure_engine()  # type: ignore[attr-defined]
        from forge.workflow.state_store import WorkflowStateRow
        async with sm() as session:
            async with session.begin():
                row = await session.get(WorkflowStateRow, wid)
                assert row is not None
                row.intermediate_results = "{not valid json::::"
        # Decoding now raises but is recovered: returns empty dict and
        # schedules mark_corrupted + audit ERROR.
        row = await state_store.load_workflow(wid)
        assert row is not None
        decoded = engine._decode_results(row, wid)
        assert decoded == {}
        # Wait briefly for the asyncio.ensure_future side-effect.
        await asyncio.sleep(0.05)
        # The mark_corrupted call may have completed by now.
        row_after = await state_store.load_workflow(wid)
        assert row_after is not None
        assert row_after.checkpoint_valid is False


# ---------------------------------------------------------------------------
# Property 28 - restart_workflow (P2-11)
# ---------------------------------------------------------------------------


class TestProperty28RestartWorkflow:
    """P2-11: restart_workflow rewinds a failed workflow to its first stage."""

    @pytest.mark.asyncio
    async def test_restart_resets_to_first_stage(
        self,
        engine: WorkflowEngine,
        state_store: StateStore,
        two_stage_workflow: WorkflowDefinition,
    ) -> None:
        wid = await engine.start_workflow(two_stage_workflow)
        # Burn through alpha's retry budget to fail the workflow.
        await engine.fail_stage(wid, "oops")
        with pytest.raises(WorkflowFailedError):
            await engine.fail_stage(wid, "oops 2")
        row = await state_store.load_workflow(wid)
        assert row is not None
        assert row.is_complete is True
        assert row.failure_reason is not None
        old_version = row.version

        await engine.restart_workflow(wid)
        row2 = await state_store.load_workflow(wid)
        assert row2 is not None
        assert row2.is_complete is False
        assert row2.failure_reason is None
        assert row2.current_stage_index == 0
        assert row2.version > old_version
        statuses = json.loads(row2.stage_statuses)
        assert statuses["alpha"] == STATUS_IN_PROGRESS
        assert statuses["beta"] == STATUS_PENDING
        # _retries should be cleared by default.
        results = json.loads(row2.intermediate_results)
        assert results.get("_retries") == {}
        # Audit captures the restart.
        # The engine fixture's audit logger is in scope via engine._audit.
        audit_entries = engine._audit.entries  # type: ignore[attr-defined]
        assert any(
            e.output_summary == "workflow_restarted"
            and e.correlation_id == wid
            for e in audit_entries
        )

    @pytest.mark.asyncio
    async def test_restart_preserves_retries_when_flag_off(
        self,
        engine: WorkflowEngine,
        state_store: StateStore,
        two_stage_workflow: WorkflowDefinition,
    ) -> None:
        wid = await engine.start_workflow(two_stage_workflow)
        await engine.fail_stage(wid, "first try")
        with pytest.raises(WorkflowFailedError):
            await engine.fail_stage(wid, "final")

        await engine.restart_workflow(wid, reset_retries=False)
        row = await state_store.load_workflow(wid)
        assert row is not None
        results = json.loads(row.intermediate_results)
        retries = results.get("_retries", {})
        # alpha should still have its 2 retries on file.
        assert retries.get("alpha", 0) == 2


# ---------------------------------------------------------------------------
# Property 29 - Backward-compat retry_limit alias (P2-1)
# ---------------------------------------------------------------------------


class TestProperty29RetryLimitAlias:
    """P2-1: legacy ``retry_limit`` keyword still works and warns."""

    def test_retry_limit_alias_emits_deprecation_warning(self) -> None:
        import warnings as _warnings
        with _warnings.catch_warnings(record=True) as captured:
            _warnings.simplefilter("always")
            stage = WorkflowStage(  # type: ignore[call-arg]
                name="legacy",
                agent_role="role",
                topic="topic",
                retry_limit=7,
            )
        assert stage.max_attempts == 7
        assert stage.retry_limit == 7  # property alias for read access
        assert any(
            issubclass(w.category, DeprecationWarning)
            and "retry_limit" in str(w.message)
            for w in captured
        )

    def test_max_attempts_no_warning(self) -> None:
        import warnings as _warnings
        with _warnings.catch_warnings(record=True) as captured:
            _warnings.simplefilter("always")
            stage = WorkflowStage(
                name="new",
                agent_role="role",
                topic="topic",
                max_attempts=5,
            )
        assert stage.max_attempts == 5
        assert not any(
            issubclass(w.category, DeprecationWarning)
            and "retry_limit" in str(w.message)
            for w in captured
        )
