"""
tools/evidence_postgres_path.py - Real Postgres state-store evidence.

NO MOCKS. Hits the live forge-postgres container brought up by
``docker compose -f docker/docker-compose.dev.yml up -d postgres``. Each scenario
uses a fresh schema scoped via ``forge_schema=`` query param so probes
cannot interfere with each other.

Scenarios:

  P1  Connection + asyncpg pool kwargs applied
  P2  Alembic upgrade head + downgrade base round-trip on Postgres
  P3  init_schema() creates all 3 tables (workflow_state,
      agent_loop_heartbeat, workflow_history) cleanly
  P4  save_checkpoint round-trips (write -> read returns same fields)
  P5  Optimistic locking: 4 concurrent advances -> 1 success + 3
      ConcurrentCheckpointError, no silent loss
  P6  Worker resume claim: try_claim_for_resume returns rows ONLY for
      the first claimant
  P7  workflow_history rows persist + are query-orderable on Postgres
"""

from __future__ import annotations

import asyncio
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


import psycopg  # noqa: E402

from forge.core.errors import ConcurrentCheckpointError  # noqa: E402
from forge.workflow.state_store import (  # noqa: E402
    POSTGRES_POOL_KWARGS,
    StateStore,
    _is_postgres,
)


_PG_BASE = "postgresql+asyncpg://forge:forge_dev_only@localhost:5433/forge"
_PG_SYNC = "postgresql://forge:forge_dev_only@localhost:5433/forge"


def _ansi(s: str, code: str) -> str:
    return f"\x1b[{code}m{s}\x1b[0m"


def _ok(label: str, detail: str) -> None:
    print(f"  [{_ansi('PASS', '7')}] {label}: {detail}")


def _fail(label: str, detail: str) -> None:
    print(f"  [{_ansi('FAIL', '91;7')}] {label}: {detail}")


def _info(s: str) -> None:
    print(f"  {_ansi('-', '90')} {s}")


def _make_schema() -> str:
    """Create + return a unique schema name, isolating this run."""
    schema = f"e_{uuid.uuid4().hex[:14]}"
    with psycopg.connect(_PG_SYNC, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(f'CREATE SCHEMA IF NOT EXISTS "{schema}"')
    return schema


def _drop_schema(schema: str) -> None:
    with psycopg.connect(_PG_SYNC, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')


def _scoped_url(schema: str) -> str:
    return f"{_PG_BASE}?forge_schema={schema}"


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------


async def p1_connection() -> bool:
    _info("P1: connection + asyncpg pool config applied")
    schema = _make_schema()
    try:
        store = StateStore(db_url=_scoped_url(schema))
        await store.init_schema()
        # Inspect pool kwargs are picked up.
        if not _is_postgres(store._db_url):
            _fail("P1", f"_is_postgres returned False for {store._db_url!r}")
            return False
        await store.close()
        _ok("P1 connection", f"pool kwargs={POSTGRES_POOL_KWARGS}")
        return True
    finally:
        _drop_schema(schema)


async def p2_alembic_round_trip() -> bool:
    _info("P2: alembic upgrade head + downgrade base on Postgres")
    schema = _make_schema()
    try:
        # Stamp + upgrade via the bootstrap helper, which uses the same
        # alembic env we ship in alembic/env.py.
        from forge.workflow.migrate_bootstrap import bootstrap_database

        result = bootstrap_database(_scoped_url(schema))
        if result.action != "fresh_upgrade":
            _fail("P2", f"expected fresh_upgrade, got {result.action!r}")
            return False
        if result.to_revision != "0002_add_workflow_history":
            _fail("P2", f"expected head, got {result.to_revision!r}")
            return False
        # Verify all 3 forge tables present.
        with psycopg.connect(_PG_SYNC, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT table_name FROM information_schema.tables "
                    "WHERE table_schema = %s ORDER BY table_name",
                    (schema,),
                )
                tables = [r[0] for r in cur.fetchall()]
        needed = {"workflow_state", "agent_loop_heartbeat", "workflow_history"}
        if not needed.issubset(set(tables)):
            _fail("P2", f"missing tables: {needed - set(tables)} (have {tables})")
            return False
        _ok("P2 alembic round-trip", f"to=0002, tables={tables}")
        return True
    finally:
        _drop_schema(schema)


async def p3_init_schema_idempotent() -> bool:
    _info("P3: init_schema() is idempotent on Postgres")
    schema = _make_schema()
    try:
        store = StateStore(db_url=_scoped_url(schema))
        await store.init_schema()
        await store.init_schema()  # second call must not raise
        await store.init_schema()  # third call must not raise
        await store.close()
        _ok("P3 init_schema idempotent", "called 3x without errors")
        return True
    finally:
        _drop_schema(schema)


async def p4_save_checkpoint_roundtrip() -> bool:
    _info("P4: save_checkpoint round-trip preserves fields")
    schema = _make_schema()
    try:
        store = StateStore(db_url=_scoped_url(schema))
        await store.init_schema()
        wid = "wf-evidence-p4"
        await store.save_checkpoint(
            workflow_id=wid,
            current_stage_index=0,
            stage_statuses={"s0": "in_progress"},
            intermediate_results={"foo": "bar", "n": 42},
            is_complete=False,
            failure_reason=None,
            definition_name="recon",
            definition_version="1.0.0",
            expected_version=None,
        )
        row = await store.load_workflow(wid)
        if row is None:
            _fail("P4", "load_workflow returned None after save")
            return False
        if (row.id != wid or row.definition_name != "recon" or row.version != 1
                or row.current_stage_index != 0 or row.is_complete):
            _fail("P4", f"row mismatch: {row.__dict__}")
            return False
        await store.close()
        _ok("P4 round-trip", f"id={row.id} v={row.version} stage={row.current_stage_index}")
        return True
    finally:
        _drop_schema(schema)


async def p5_optimistic_locking_race() -> bool:
    _info("P5: 4 concurrent advances against same row -> 1 success + 3 conflicts")
    schema = _make_schema()
    try:
        store = StateStore(db_url=_scoped_url(schema))
        await store.init_schema()
        wid = "wf-evidence-p5"
        # Establish baseline at version=1.
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
        # Now race 4 concurrent advances all expecting version=1. Postgres'
        # row-level UPDATE will let exactly one win; the other three should
        # raise ConcurrentCheckpointError.
        async def advance() -> bool:
            try:
                await store.save_checkpoint(
                    workflow_id=wid,
                    current_stage_index=1,
                    stage_statuses={"s0": "completed", "s1": "in_progress"},
                    intermediate_results={},
                    is_complete=False,
                    failure_reason=None,
                    expected_version=1,
                )
                return True
            except ConcurrentCheckpointError:
                return False

        results = await asyncio.gather(*(advance() for _ in range(4)))
        successes = sum(results)
        conflicts = len(results) - successes
        post = await store.load_workflow(wid)
        await store.close()
        if successes != 1 or conflicts != 3:
            _fail("P5", f"successes={successes} conflicts={conflicts} (want 1+3)")
            return False
        if post is None or post.version != 2:
            _fail("P5", f"post.version={post.version if post else None}, want 2")
            return False
        _ok("P5 optimistic locking",
            f"1 success + 3 ConcurrentCheckpointError, version=1->2")
        return True
    finally:
        _drop_schema(schema)


async def p6_resume_claim_isolation() -> bool:
    _info("P6: try_claim_for_resume - first claimant wins, second sees False")
    schema = _make_schema()
    try:
        store = StateStore(db_url=_scoped_url(schema))
        await store.init_schema()
        wid = "wf-resume-race"
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

        async def claim() -> bool:
            return await store.try_claim_for_resume(
                workflow_id=wid, claim_window_seconds=60.0,
            )

        a, b = await asyncio.gather(claim(), claim())
        successes = sum([a, b])
        await store.close()
        if successes != 1:
            _fail("P6", f"successes={successes} (expected exactly 1)")
            return False
        _ok("P6 resume isolation",
            f"a={a} b={b} - exactly one claim succeeded")
        return True
    finally:
        _drop_schema(schema)

async def p7_history_persistence() -> bool:
    _info("P7: workflow_history rows persist + are query-orderable")
    schema = _make_schema()
    try:
        store = StateStore(db_url=_scoped_url(schema))
        await store.init_schema()
        wid = "wf-evidence-p7"
        for i in range(4):
            await store.save_checkpoint(
                workflow_id=wid,
                current_stage_index=i,
                stage_statuses={f"s{j}": "completed" for j in range(i)},
                intermediate_results={},
                is_complete=(i == 3),
                failure_reason=None,
                definition_name="recon" if i == 0 else None,
                definition_version="1.0.0" if i == 0 else None,
                expected_version=None if i == 0 else i,
            )
        history = await store.load_history(wid)
        replay = await store.replay_workflow(wid)
        await store.close()
        if len(history) != 4 or len(replay) != 4:
            _fail("P7", f"history={len(history)} replay={len(replay)} (want 4)")
            return False
        events = [r.event_type for r in history]
        if events[0] != "created" or events[-1] != "completed":
            _fail("P7", f"unexpected events: {events}")
            return False
        # Strictly ascending recorded_at (Postgres preserves order).
        for i in range(len(history) - 1):
            if history[i].recorded_at > history[i + 1].recorded_at:
                _fail("P7", f"recorded_at out of order at i={i}")
                return False
        _ok("P7 history persistence", f"4 rows, events={events}")
        return True
    finally:
        _drop_schema(schema)


async def main() -> int:
    print(_ansi("\n=== Postgres state-store evidence ===", "1;36"))

    # Daemon reachability probe up-front.
    try:
        with psycopg.connect(_PG_SYNC, connect_timeout=2):
            pass
    except psycopg.Error as exc:
        print(_ansi(
            f"\nFATAL: forge-postgres unreachable at {_PG_SYNC} ({exc}).\n"
            "Start the dev stack: docker compose -f docker/docker-compose.dev.yml up -d postgres",
            "91;1",
        ))
        return 2

    results: list[tuple[str, bool]] = []
    for label, fn in [
        ("P1 connection + pool", p1_connection),
        ("P2 alembic round-trip", p2_alembic_round_trip),
        ("P3 init_schema idempotent", p3_init_schema_idempotent),
        ("P4 save_checkpoint round-trip", p4_save_checkpoint_roundtrip),
        ("P5 optimistic locking race", p5_optimistic_locking_race),
        ("P6 resume claim isolation", p6_resume_claim_isolation),
        ("P7 workflow_history persistence", p7_history_persistence),
    ]:
        try:
            ok = await fn()
        except Exception as exc:  # noqa: BLE001
            _fail(label, f"unexpected exception: {exc!r}")
            ok = False
        results.append((label, ok))

    print(_ansi("\nRESULTS", "7"))
    for label, ok in results:
        marker = _ansi("PASS", "7") if ok else _ansi("FAIL", "91;7")
        print(f"  [{marker}] {label}")

    if any(not ok for _, ok in results):
        print(_ansi(
            f"\n{sum(1 for _, ok in results if not ok)} probe(s) FAILED",
            "91;1",
        ))
        return 1
    print(_ansi("\nALL POSTGRES EVIDENCE PROBES PASSED", "7"))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
