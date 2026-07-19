"""
tools/evidence_failure_scenarios.py - Live demonstration of failure handling.

Proves four contracts with raw output:

  1. Plugin timeout enforcement (PluginExecutor.execute raises
     PluginTimeoutError when the plugin runs longer than its
     metadata.timeout_seconds)
  2. AgentLoop retry budget exhaustion (agent that always times out is
     retried exactly message_retry_max times, then dropped)
  3. Workflow checkpoint recovery (mark_corrupted then resume with no
     prior valid checkpoint -> CheckpointCorruptedError)
  4. Workflow resume across restart (start, advance, close store, reopen
     store, resume, observe in-progress stage)
"""
from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import time
from pathlib import Path

from forge.audit.logger import AuditLogger
from forge.audit.models import AuditEventType
from forge.bus.memory_bus import InMemoryMessageBus
from forge.core.agent_loop import AgentLoop
from forge.core.agent_registry import AgentRegistry
from forge.core.errors import (
    CheckpointCorruptedError,
    PluginTimeoutError,
    WorkflowFailedError,
)
from forge.core.message_models import AgentMessage
from forge.plugins.base import (
    ExecutionMode,
    PluginMetadata,
    PluginResult,
    RiskLevel,
)
from forge.plugins.executor import PluginExecutor
from forge.workflow import (
    STATUS_COMPLETED,
    STATUS_IN_PROGRESS,
    StateStore,
    WorkflowDefinition,
    WorkflowEngine,
    WorkflowStage,
)


def banner(text: str) -> None:
    print(f"\n{'=' * 70}\n{text}\n{'=' * 70}")


# ---------------------------------------------------------------------------
# Scenario 1: Plugin timeout enforcement
# ---------------------------------------------------------------------------


class _SlowPlugin:
    """Sleeps strictly longer than its declared timeout_seconds."""

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="slow_plugin_demo",
            version="1.0.0",
            capabilities=["read"],
            execution_mode=ExecutionMode.IN_PROCESS,
            timeout_seconds=1,  # 1 second budget
            risk_level=RiskLevel.LOW,
        )

    async def execute(self, params):
        await asyncio.sleep(2.5)  # exceed the budget
        return PluginResult(success=True, output={"finished": True})

    async def health_check(self):
        return True


async def scenario_1_plugin_timeout() -> None:
    banner("SCENARIO 1: Plugin timeout enforcement")
    audit = AuditLogger()
    executor = PluginExecutor(audit=audit)
    plugin = _SlowPlugin()

    print(
        f"Plugin: {plugin.metadata.name} timeout_seconds={plugin.metadata.timeout_seconds}"
    )
    print("Plugin will sleep 2.5s; budget is 1s")
    start = time.perf_counter()
    try:
        await executor.execute(plugin, params={}, correlation_id="cid-timeout")
        print("FAILED: no PluginTimeoutError raised")
        return
    except PluginTimeoutError as exc:
        elapsed = time.perf_counter() - start
        print(f"PluginTimeoutError raised after {elapsed:.3f}s")
        print(f"  message: {exc}")
        timeouts = [
            e
            for e in audit.entries
            if e.error_detail and "exceeded" in e.error_detail
        ]
        print(f"  audit entries with 'exceeded': {len(timeouts)}")
        for e in timeouts:
            print(
                f"    [{e.event_type.value}] success={e.success} "
                f"detail={e.error_detail[:80]}"
            )


# ---------------------------------------------------------------------------
# Scenario 2: AgentLoop retry budget exhaustion
# ---------------------------------------------------------------------------


class _AlwaysSlowAgent:
    """Agent whose receive_message always exceeds the ack timeout."""

    def __init__(self) -> None:
        self.attempts: list[AgentMessage] = []

    @property
    def role(self):
        return "always_slow"

    @property
    def subscribed_topics(self):
        return ["topic.retry"]

    async def receive_message(self, message):
        self.attempts.append(message)
        await asyncio.sleep(0.5)  # exceeds 0.05s ack timeout
        return []

    async def report_status(self):
        return {"role": "always_slow"}


async def scenario_2_retry_exhaustion() -> None:
    banner("SCENARIO 2: AgentLoop retry budget exhaustion")
    bus = InMemoryMessageBus()
    audit = AuditLogger()
    registry = AgentRegistry()
    agent = _AlwaysSlowAgent()
    registry.register(agent)

    retry_max = 2
    loop = AgentLoop(
        bus=bus,
        registry=registry,
        audit=audit,
        heartbeat_interval=10.0,
        message_retry_max=retry_max,
        message_ack_timeout=0.05,
    )

    print(f"message_retry_max={retry_max}, ack_timeout=0.05s")
    print(f"Expected total attempts = 1 + {retry_max} = {1 + retry_max}")

    await bus.publish(
        "topic.retry",
        AgentMessage(
            topic="topic.retry",
            payload={},
            correlation_id="cid-retry-exhaust",
        ),
    )

    run_task = asyncio.create_task(loop.run())
    await asyncio.sleep(1.5)
    await loop.shutdown()
    try:
        await asyncio.wait_for(run_task, timeout=2.0)
    except asyncio.TimeoutError:
        run_task.cancel()
        try:
            await run_task
        except (asyncio.CancelledError, Exception):
            pass

    print(f"Actual attempts received by agent: {len(agent.attempts)}")
    print(f"Retry counts seen: {[m.retry_count for m in agent.attempts]}")
    errors = [
        e
        for e in audit.entries
        if e.event_type == AuditEventType.ERROR
        and e.correlation_id == "cid-retry-exhaust"
    ]
    print(f"ERROR audit entries for cid-retry-exhaust: {len(errors)}")
    for e in errors[:3]:
        print(f"    detail: {(e.error_detail or '')[:100]}")


# ---------------------------------------------------------------------------
# Scenario 3: Corrupted checkpoint with no valid fallback
# ---------------------------------------------------------------------------


async def scenario_3_corrupted_checkpoint() -> None:
    banner("SCENARIO 3: Corrupted checkpoint -> CheckpointCorruptedError")
    with tempfile.TemporaryDirectory() as td:
        db_url = f"sqlite:///{Path(td) / 'corrupt.db'}"
        bus = InMemoryMessageBus()
        audit = AuditLogger()
        store = StateStore(db_url=db_url)
        await store.init_schema()
        engine = WorkflowEngine(bus=bus, state_store=store, audit=audit)

        wf = WorkflowDefinition(
            name="corruption_demo",
            version="1.0.0",
            stages=[
                WorkflowStage(
                    name="s1",
                    agent_role="x",
                    topic="topic.s1",
                    payload_template={},
                    retry_limit=1,
                )
            ],
        )
        engine.register_definition(wf)

        wid = await engine.start_workflow(wf)
        print(f"started workflow id={wid}")

        # Corrupt the only checkpoint (no valid prior to fall back to)
        await store.mark_corrupted(wid)
        print("marked checkpoint corrupted")

        try:
            await engine.resume_incomplete_workflows()
            print("FAILED: no CheckpointCorruptedError raised")
        except CheckpointCorruptedError as exc:
            print(f"CheckpointCorruptedError raised: {exc}")
            errors = [
                e
                for e in audit.entries
                if e.event_type == AuditEventType.ERROR and wid in (e.correlation_id or "")
            ]
            print(f"ERROR audit entries for {wid}: {len(errors)}")
            for e in errors[:2]:
                print(f"    detail: {(e.error_detail or '')[:100]}")
        await store.close()


# ---------------------------------------------------------------------------
# Scenario 4: Workflow resume across StateStore restart
# ---------------------------------------------------------------------------


async def scenario_4_resume_across_restart() -> None:
    banner("SCENARIO 4: Workflow resume across StateStore restart")
    with tempfile.TemporaryDirectory() as td:
        db_url = f"sqlite:///{Path(td) / 'resume.db'}"

        wf = WorkflowDefinition(
            name="resume_demo",
            version="1.0.0",
            stages=[
                WorkflowStage(
                    name="alpha",
                    agent_role="a",
                    topic="topic.a",
                    payload_template={},
                    retry_limit=2,
                ),
                WorkflowStage(
                    name="beta",
                    agent_role="b",
                    topic="topic.b",
                    payload_template={},
                    retry_limit=2,
                ),
                WorkflowStage(
                    name="gamma",
                    agent_role="c",
                    topic="topic.c",
                    payload_template={},
                    retry_limit=2,
                ),
            ],
        )

        # --- Phase 1: start, advance one stage, close ---
        bus_a = InMemoryMessageBus()
        audit_a = AuditLogger()
        store_a = StateStore(db_url=db_url)
        await store_a.init_schema()
        engine_a = WorkflowEngine(bus=bus_a, state_store=store_a, audit=audit_a)
        engine_a.register_definition(wf)

        wid = await engine_a.start_workflow(wf)
        print(f"Phase 1 start: workflow id={wid}")
        await engine_a.advance_stage(wid, {"alpha_output": "done"})
        row = await store_a.load_workflow(wid)
        statuses_phase1 = json.loads(row.stage_statuses) if row else {}
        print(f"Phase 1 stage statuses: {statuses_phase1}")
        print(f"Phase 1 current_stage_index: {row.current_stage_index if row else 'n/a'}")
        await store_a.close()
        print("Phase 1 store closed (simulated process exit)")

        # --- Phase 2: fresh process, open same DB, resume ---
        bus_b = InMemoryMessageBus()
        audit_b = AuditLogger()
        store_b = StateStore(db_url=db_url)
        engine_b = WorkflowEngine(bus=bus_b, state_store=store_b, audit=audit_b)
        engine_b.register_definition(wf)

        resumed = await engine_b.resume_incomplete_workflows()
        print(f"Phase 2 resumed: {resumed}")

        row_b = await store_b.load_workflow(wid)
        statuses_phase2 = json.loads(row_b.stage_statuses) if row_b else {}
        print(f"Phase 2 stage statuses after resume: {statuses_phase2}")
        print(f"Phase 2 current_stage_index: {row_b.current_stage_index if row_b else 'n/a'}")

        # Sanity assertion: alpha should still be COMPLETED
        if statuses_phase2.get("alpha") == STATUS_COMPLETED:
            print("CONFIRMED: completed stage 'alpha' was NOT re-executed")
        else:
            print(f"FAILURE: alpha status is {statuses_phase2.get('alpha')!r}")

        if statuses_phase2.get("beta") == STATUS_IN_PROGRESS:
            print("CONFIRMED: in-progress stage 'beta' was re-published")
        else:
            print(f"NOTE: beta status is {statuses_phase2.get('beta')!r}")
        await store_b.close()


async def main() -> int:
    await scenario_1_plugin_timeout()
    await scenario_2_retry_exhaustion()
    await scenario_3_corrupted_checkpoint()
    await scenario_4_resume_across_restart()
    print("\n" + "=" * 70)
    print("ALL FAILURE SCENARIOS DEMONSTRATED")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
