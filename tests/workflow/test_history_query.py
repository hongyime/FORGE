"""
tests/workflow/test_history_query.py - load_history + replay_workflow tests.

Covers:
    * load_history returns rows in chronological order
    * load_history with limit caps row count
    * load_history with since filters out earlier rows
    * load_history for unknown workflow returns empty list
    * replay_workflow returns dicts with elapsed_seconds_since_start
    * replay_workflow handles failed workflows (event_type='failed')
    * No interference between workflows (filtering by workflow_id)
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

import pytest

from forge.workflow.state_store import StateStore


@pytest.fixture
async def store(db_url: str) -> StateStore:
    s = StateStore(db_url=db_url)
    await s.init_schema()
    yield s
    await s.close()


async def _drive_workflow(
    store: StateStore,
    *,
    workflow_id: str,
    stages: int = 3,
    fail_at: int | None = None,
) -> None:
    await store.save_checkpoint(
        workflow_id=workflow_id,
        current_stage_index=0,
        stage_statuses={"s0": "in_progress"},
        intermediate_results={},
        is_complete=False,
        failure_reason=None,
        definition_name="recon",
        definition_version="1.0.0",
        expected_version=None,
    )
    for i in range(1, stages):
        is_complete = i == stages - 1 and fail_at is None
        failure_reason = None
        if fail_at is not None and i == fail_at:
            is_complete = True
            failure_reason = "simulated failure"
        await store.save_checkpoint(
            workflow_id=workflow_id,
            current_stage_index=i,
            stage_statuses={f"s{j}": "completed" for j in range(i)},
            intermediate_results={},
            is_complete=is_complete,
            failure_reason=failure_reason,
            expected_version=i,
        )
        if is_complete and failure_reason:
            break


@pytest.mark.asyncio
async def test_load_history_returns_chronological_rows(store: StateStore) -> None:
    await _drive_workflow(store, workflow_id="wf-1", stages=3)
    rows = await store.load_history("wf-1")
    assert len(rows) == 3
    assert [r.event_type for r in rows] == ["created", "advanced", "completed"]
    assert [r.to_version for r in rows] == [1, 2, 3]
    # Strictly increasing timestamps.
    assert all(rows[i].recorded_at <= rows[i + 1].recorded_at for i in range(len(rows) - 1))


@pytest.mark.asyncio
async def test_load_history_limit(store: StateStore) -> None:
    await _drive_workflow(store, workflow_id="wf-2", stages=4)
    rows = await store.load_history("wf-2", limit=2)
    assert len(rows) == 2
    # Limit takes the EARLIEST rows (chronological order ascending).
    assert rows[0].event_type == "created"


@pytest.mark.asyncio
async def test_load_history_since_filter(store: StateStore) -> None:
    await _drive_workflow(store, workflow_id="wf-3", stages=4)
    all_rows = await store.load_history("wf-3")
    midpoint = all_rows[2].recorded_at
    later = await store.load_history("wf-3", since=midpoint)
    assert all(r.recorded_at >= midpoint for r in later)
    assert len(later) <= len(all_rows)


@pytest.mark.asyncio
async def test_load_history_unknown_workflow_returns_empty(store: StateStore) -> None:
    rows = await store.load_history("does-not-exist")
    assert rows == []


@pytest.mark.asyncio
async def test_history_isolated_per_workflow(store: StateStore) -> None:
    await _drive_workflow(store, workflow_id="wf-a", stages=2)
    await _drive_workflow(store, workflow_id="wf-b", stages=4)
    rows_a = await store.load_history("wf-a")
    rows_b = await store.load_history("wf-b")
    assert all(r.workflow_id == "wf-a" for r in rows_a)
    assert all(r.workflow_id == "wf-b" for r in rows_b)
    assert len(rows_a) == 2
    assert len(rows_b) == 4


@pytest.mark.asyncio
async def test_replay_workflow_includes_elapsed_seconds(store: StateStore) -> None:
    await _drive_workflow(store, workflow_id="wf-replay", stages=3)
    timeline = await store.replay_workflow("wf-replay")
    assert len(timeline) == 3
    assert timeline[0]["elapsed_seconds_since_start"] == 0.0
    # Subsequent entries' elapsed should be >= 0.
    assert all(t["elapsed_seconds_since_start"] >= 0 for t in timeline)
    # Each entry has the documented keys.
    expected_keys = {
        "id", "timestamp", "elapsed_seconds_since_start", "event_type",
        "from_stage_index", "to_stage_index", "from_version", "to_version",
        "actor", "detail",
    }
    for t in timeline:
        assert expected_keys <= set(t.keys()), f"missing keys in {t}"


@pytest.mark.asyncio
async def test_replay_workflow_unknown_returns_empty(store: StateStore) -> None:
    assert await store.replay_workflow("not-found") == []


@pytest.mark.asyncio
async def test_replay_failed_workflow_marks_failed(store: StateStore) -> None:
    await _drive_workflow(store, workflow_id="wf-failed", stages=4, fail_at=2)
    timeline = await store.replay_workflow("wf-failed")
    assert any(t["event_type"] == "failed" for t in timeline)
    failed_event = next(t for t in timeline if t["event_type"] == "failed")
    assert failed_event["detail"] == "simulated failure"
