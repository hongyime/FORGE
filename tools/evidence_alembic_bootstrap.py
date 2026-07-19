"""
tools/evidence_alembic_bootstrap.py - Migration bootstrap evidence harness.

Three real scenarios, raw output. NO MOCKS.

  B1. Fresh DB        -> bootstrap creates all tables + alembic_version row
  B2. Pre-alembic DB  -> bootstrap stamps + upgrades, pre-existing data survives
  B3. Already-managed -> bootstrap is a no-op the second time

Run: python tools/evidence_alembic_bootstrap.py
"""

from __future__ import annotations

import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from forge.workflow.migrate_bootstrap import (  # noqa: E402
    BASELINE_REVISION,
    bootstrap_database,
)


def _ansi(s: str, code: str) -> str:
    return f"\x1b[{code}m{s}\x1b[0m"


def _ok(label: str, detail: str) -> None:
    print(f"  [{_ansi('PASS', '7')}] {label}: {detail}")


def _fail(label: str, detail: str) -> None:
    print(f"  [{_ansi('FAIL', '91;7')}] {label}: {detail}")


def _info(s: str) -> None:
    print(f"  {_ansi('-', '90')} {s}")


def _list_tables(db: Path) -> list[str]:
    conn = sqlite3.connect(db)
    try:
        return sorted(
            r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        )
    finally:
        conn.close()


def _alembic_version(db: Path) -> str | None:
    conn = sqlite3.connect(db)
    try:
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name='alembic_version'"
        )
        if cur.fetchone() is None:
            return None
        cur = conn.execute("SELECT version_num FROM alembic_version")
        row = cur.fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def b1_fresh_db() -> bool:
    _info("B1: fresh DB -> full upgrade chain")
    td = Path(tempfile.mkdtemp(prefix="forge_evbs_b1_"))
    db = td / "fresh.db"
    result = bootstrap_database(f"sqlite:///{db}")
    print(f"      action={result.action} from={result.from_revision} to={result.to_revision}")
    print(f"      tables_after={result.tables_after}")
    if result.action != "fresh_upgrade":
        _fail("B1", f"expected action=fresh_upgrade, got {result.action!r}")
        return False
    if result.to_revision != "0002_add_workflow_history":
        _fail("B1", f"expected head, got {result.to_revision!r}")
        return False
    needed = {"workflow_state", "agent_loop_heartbeat", "workflow_history", "alembic_version"}
    have = set(_list_tables(db))
    if not needed.issubset(have):
        _fail("B1", f"missing tables: {needed - have}")
        return False
    _ok("B1 fresh DB", f"head={_alembic_version(db)}, all 4 tables present")
    return True


def b2_pre_alembic_db() -> bool:
    _info("B2: pre-alembic DB -> stamp + upgrade preserves existing data")
    td = Path(tempfile.mkdtemp(prefix="forge_evbs_b2_"))
    db = td / "preexisting.db"
    # Simulate historical init_schema() output: workflows + heartbeat only.
    conn = sqlite3.connect(db)
    try:
        conn.executescript(
            """
            CREATE TABLE workflow_state (
                id VARCHAR(64) PRIMARY KEY,
                definition_name VARCHAR(255) NOT NULL,
                definition_version VARCHAR(64) NOT NULL,
                current_stage_index INTEGER NOT NULL,
                stage_statuses TEXT NOT NULL,
                intermediate_results TEXT NOT NULL,
                started_at FLOAT NOT NULL,
                updated_at FLOAT NOT NULL,
                is_complete BOOLEAN NOT NULL,
                failure_reason TEXT,
                checkpoint_valid BOOLEAN NOT NULL,
                version INTEGER NOT NULL,
                resumed_at FLOAT
            );
            CREATE TABLE agent_loop_heartbeat (
                id VARCHAR(32) PRIMARY KEY,
                timestamp FLOAT NOT NULL
            );
            INSERT INTO workflow_state VALUES (
                'wf-evidence', 'recon', '1.0.0', 0, '{}', '{}',
                1700000000.0, 1700000000.0, 0, NULL, 1, 0, NULL
            );
            """
        )
        conn.commit()
    finally:
        conn.close()

    print(f"      tables before: {_list_tables(db)}")
    print(f"      alembic_version before: {_alembic_version(db)!r}")
    result = bootstrap_database(f"sqlite:///{db}")
    print(f"      action={result.action} from={result.from_revision} to={result.to_revision}")
    print(f"      tables after: {_list_tables(db)}")

    if result.action != "stamp_then_upgrade":
        _fail("B2", f"expected stamp_then_upgrade, got {result.action!r}")
        return False
    # Pre-existing data survived?
    conn = sqlite3.connect(db)
    try:
        row = conn.execute(
            "SELECT id, definition_name FROM workflow_state WHERE id='wf-evidence'"
        ).fetchone()
    finally:
        conn.close()
    if row is None or row[0] != "wf-evidence":
        _fail("B2", f"pre-existing workflow row lost: {row!r}")
        return False
    if "workflow_history" not in _list_tables(db):
        _fail("B2", "workflow_history not added")
        return False
    _ok("B2 pre-alembic", f"stamped at {BASELINE_REVISION}, upgraded to head, data preserved")
    return True


def b3_idempotent() -> bool:
    _info("B3: already-managed DB -> bootstrap is no-op")
    td = Path(tempfile.mkdtemp(prefix="forge_evbs_b3_"))
    db = td / "managed.db"
    url = f"sqlite:///{db}"
    first = bootstrap_database(url)
    second = bootstrap_database(url)
    print(f"      first:  action={first.action} to={first.to_revision}")
    print(f"      second: action={second.action} to={second.to_revision}")
    if first.action != "fresh_upgrade":
        _fail("B3", f"first run wrong action: {first.action!r}")
        return False
    if second.action != "upgrade_existing":
        _fail("B3", f"second run wrong action: {second.action!r}")
        return False
    if first.to_revision != second.to_revision:
        _fail("B3", "head revision changed between runs")
        return False
    _ok("B3 idempotent", f"both runs end at {second.to_revision}")
    return True


def main() -> int:
    print(_ansi("\n=== Alembic bootstrap evidence ===", "1;36"))
    results: list[tuple[str, bool]] = []
    for label, fn in [
        ("B1 fresh DB", b1_fresh_db),
        ("B2 pre-alembic DB", b2_pre_alembic_db),
        ("B3 idempotent", b3_idempotent),
    ]:
        try:
            ok = fn()
        except Exception as exc:  # noqa: BLE001
            _fail(label, f"unexpected exception: {exc!r}")
            ok = False
        results.append((label, ok))

    print(_ansi("\nRESULTS", "7"))
    for label, ok in results:
        marker = _ansi("PASS", "7") if ok else _ansi("FAIL", "91;7")
        print(f"  [{marker}] {label}")

    if any(not ok for _, ok in results):
        print(_ansi("\nALEMBIC BOOTSTRAP EVIDENCE: FAILED", "91;1"))
        return 1
    print(_ansi("\nALL BOOTSTRAP PROBES PASSED", "7"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
