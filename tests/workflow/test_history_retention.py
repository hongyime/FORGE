"""
tests/workflow/test_history_retention.py - purge_history() tests.

Verifies the B2 retention API on real Postgres:

    * purge_history(workflow_id=X) deletes ALL rows for that workflow
    * purge_history(older_than_seconds=N) deletes rows older than the cutoff
    * Both filters combine (workflow + age)
    * keep_last_n preserves the most recent N rows for a workflow
    * Calling without any filter raises ValueError
    * Other workflows' history is never touched
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator

import pytest

from forge.workflow.state_store import StateStore


@pytest.fixture
async def store(db_url: str) -> AsyncIterator[StateStore]:
    s = StateStore(db_url=db_url)
    await s.init_schema()
    yield s
    await s.close()


async def _drive(store: StateStore, *, wid: str, stages: int = 4) -> None:
    await store.save_checkpoint(
        workflow_id=wid,
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
        await store.save_checkpoint(
            workflow_id=wid,
            current_stage_index=i,
            stage_statuses={f"s{j}": "completed" for j in range(i)},
            intermediate_results={},
            is_complete=(i == stages - 1),
            failure_reason=None,
            expected_version=i,
        )


@pytest.mark.asyncio
async def test_purge_by_workflow_id_deletes_all_for_that_workflow(
    store: StateStore,
) -> None:
    await _drive(store, wid="wf-a", stages=3)
    await _drive(store, wid="wf-b", stages=2)
    deleted = await store.purge_history(workflow_id="wf-a")
    assert deleted == 3
    assert await store.load_history("wf-a") == []
    # wf-b still intact.
    assert len(await store.load_history("wf-b")) == 2


@pytest.mark.asyncio
async def test_purge_by_age_deletes_only_old_rows(store: StateStore) -> None:
    await _drive(store, wid="wf-old", stages=3)
    # Sleep > older_than_seconds threshold; then write more rows.
    await asyncio.sleep(0.5)
    await _drive(store, wid="wf-new", stages=2)
    # Anything older than 0.3s -> wf-old's 3 rows AND any wf-new rows
    # written before the cutoff. Use 0.4 to be conservative.
    deleted = await store.purge_history(older_than_seconds=0.4)
    assert deleted >= 3
    # wf-old fully purged.
    assert await store.load_history("wf-old") == []
    # wf-new mostly intact (most recent rows survived).
    assert len(await store.load_history("wf-new")) >= 1


@pytest.mark.asyncio
async def test_purge_combined_workflow_and_age(store: StateStore) -> None:
    await _drive(store, wid="wf-x", stages=4)
    await asyncio.sleep(0.5)
    await _drive(store, wid="wf-y", stages=4)
    # Only wf-x rows older than 0.4s.
    deleted = await store.purge_history(workflow_id="wf-x", older_than_seconds=0.4)
    assert deleted == 4
    # wf-y untouched.
    assert len(await store.load_history("wf-y")) == 4


@pytest.mark.asyncio
async def test_purge_keep_last_n_preserves_recent(store: StateStore) -> None:
    await _drive(store, wid="wf-keep", stages=6)
    deleted = await store.purge_history(workflow_id="wf-keep", keep_last_n=2)
    assert deleted == 4
    remaining = await store.load_history("wf-keep")
    assert len(remaining) == 2
    # The two SURVIVORS must be the most recent (last two events).
    events = [r.event_type for r in remaining]
    assert events[-1] == "completed"


@pytest.mark.asyncio
async def test_purge_no_filter_raises(store: StateStore) -> None:
    with pytest.raises(ValueError):
        await store.purge_history()


@pytest.mark.asyncio
async def test_purge_unknown_workflow_returns_zero(store: StateStore) -> None:
    deleted = await store.purge_history(workflow_id="nonexistent")
    assert deleted == 0
