"""tests/autopilot/test_scheduler.py — Unit and integration tests for Autopilot Scheduler.

Covers the 12 design tests specified in Iteration 5a (Plan 2.2):
1. test_lease_acquire_and_release: acquire returns acquired=True + lease; release marks it released; frees slots/target.
2. test_stale_lease_reaping_expired_ttl: lease past expires_at is reaped; slots/target freed.
3. test_stale_lease_reaping_dead_pid: lease with dead owner_pid reaped even before TTL expiry.
4. test_lease_heartbeat_extends_ttl: heartbeat advances heartbeat_at and extends expires_at.
5. test_budget_gating_slots_exhausted: acquire rejected with slots_exhausted when total_slots leased.
6. test_active_target_limit_enforced: acquire rejected with max_active_targets_reached when target limit hit.
7. test_duplicate_target_acquire_rejected: acquire rejected with target_already_active for active target.
8. test_partial_slot_allocation: partial grant when available slots < requested slots.
9. test_resume_shares_budget_with_import: kind="resume" and kind="start" share unified slot pool and target limits.
10. test_kill_switch_sentinel_blocks_acquisition: sentinel file autopilot.stop halts acquisitions until removed.
11. test_import_targets_skips_when_budget_exhausted_without_error: import_targets handles budget exhaustion cleanly.
12. test_budget_formula_edge_cases: zero/negative slots, unmeasured p95, MemAvailable below reserve threshold.
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from forge.autopilot.scheduler import (
    acquire_lease,
    compute_child_memory_p95,
    compute_worker_budget,
    ensure_child_memory_schema,
    get_budget_snapshot,
    heartbeat,
    is_kill_switch_active,
    list_active_leases,
    provider_inflight_count,
    read_recorded_worker_memory_p95,
    record_child_memory_sample,
    record_worker_memory_p95,
    resolve_p95_worker_memory_mb,
    reap_stale_leases,
    release_lease,
    sample_process_resources,
    scheduler_db_path,
)
from forge.targets_import import import_targets
from forge.targets_resume_candidates import _execute_resume_item


@pytest.fixture(autouse=True)
def _noop_targets_import_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("forge.targets_import._DEFAULT_SLEEP", lambda _: None)


class _FakeConfig:
    def __init__(
        self,
        data_dir: Path,
        roe_strictness: str | None = None,
        autopilot_global_slots: int = 4,
        autopilot_max_active_targets: int = 2,
        autopilot_lease_ttl_seconds: int = 600,
        autopilot_memory_reserve_mb: int = 4096,
        autopilot_p95_worker_memory_mb: int = 0,
        autopilot_kill_switch_file: Path | None = None,
    ) -> None:
        self.data_dir = data_dir
        self.operator = "tester"
        self.roe_strictness = roe_strictness or "strict"
        self.autopilot_global_slots = autopilot_global_slots
        self.autopilot_max_active_targets = autopilot_max_active_targets
        self.autopilot_lease_ttl_seconds = autopilot_lease_ttl_seconds
        self.autopilot_memory_reserve_mb = autopilot_memory_reserve_mb
        self.autopilot_p95_worker_memory_mb = autopilot_p95_worker_memory_mb
        self.autopilot_kill_switch_file = autopilot_kill_switch_file

    def engagement_db_path(self, engagement_id: str) -> Path:
        p = self.data_dir / "engagements" / f"{engagement_id}.db"
        p.parent.mkdir(parents=True, exist_ok=True)
        return p


def _write_simple_feed(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": "target-feed.v1",
                "generated_at": "2026-10-15T00:00:00Z",
                "items": [
                    {
                        "target_type": "domain",
                        "target_value": "target-alpha.corp-target.io",
                        "source_kind": "telemetry",
                        "confidence": 0.9,
                        "source_count": 2,
                        "first_seen_at": "2026-10-14T00:00:00Z",
                        "provenance": "network_domain",
                    },
                    {
                        "target_type": "domain",
                        "target_value": "target-beta.corp-target.io",
                        "source_kind": "telemetry",
                        "confidence": 0.9,
                        "source_count": 2,
                        "first_seen_at": "2026-10-14T00:00:00Z",
                        "provenance": "network_domain",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# 1. Lease acquire and release
# ---------------------------------------------------------------------------


def test_lease_acquire_and_release(tmp_path: Path) -> None:
    """acquire returns acquired=True + lease; release marks it released; a released lease frees its slots/target."""
    cfg = _FakeConfig(tmp_path, autopilot_global_slots=4, autopilot_max_active_targets=2)

    res = acquire_lease(
        target_key="domain:example.com",
        target_value="example.com",
        target_type="domain",
        engagement_id=1,
        requested_slots=2,
        data_dir=tmp_path,
        config=cfg,  # type: ignore[arg-type]
    )

    assert res.acquired is True
    assert res.reason == "ok"
    assert res.allocated_slots == 2
    assert res.lease is not None
    lease = res.lease
    assert lease.target_key == "domain:example.com"
    assert lease.target_value == "example.com"
    assert lease.target_type == "domain"
    assert lease.engagement_id == 1
    assert lease.slot_count == 2
    assert lease.status == "active"
    assert lease.released_at is None
    assert lease.release_reason is None

    # Verify utilization reflected in snapshot
    snap1 = get_budget_snapshot(data_dir=tmp_path, config=cfg)  # type: ignore[arg-type]
    assert snap1.leased_slots == 2
    assert snap1.available_slots == 2
    assert snap1.active_targets_count == 1
    assert snap1.active_leases_count == 1

    active_leases = list_active_leases(data_dir=tmp_path)
    assert len(active_leases) == 1
    assert active_leases[0].lease_id == lease.lease_id

    # Release lease
    released = release_lease(lease.lease_id, reason="completed", data_dir=tmp_path)
    assert released is True

    # Re-releasing returns False (already released)
    assert release_lease(lease.lease_id, reason="completed", data_dir=tmp_path) is False

    # Snapshot shows slots and target freed
    snap2 = get_budget_snapshot(data_dir=tmp_path, config=cfg)  # type: ignore[arg-type]
    assert snap2.leased_slots == 0
    assert snap2.available_slots == 4
    assert snap2.active_targets_count == 0
    assert snap2.active_leases_count == 0

    assert list_active_leases(data_dir=tmp_path) == []

    # Verify SQLite row fields
    db_path = scheduler_db_path(tmp_path)
    with sqlite3.connect(db_path) as con:
        row = con.execute(
            "SELECT status, release_reason, released_at FROM leases WHERE lease_id = ?",
            (lease.lease_id,),
        ).fetchone()
        assert row is not None
        assert row[0] == "released"
        assert row[1] == "completed"
        assert row[2] is not None


# ---------------------------------------------------------------------------
# 2. Stale-lease reaping via TTL
# ---------------------------------------------------------------------------


def test_stale_lease_reaping_expired_ttl(tmp_path: Path) -> None:
    """A lease past expires_at is reaped; its slots/target freed."""
    cfg = _FakeConfig(tmp_path, autopilot_global_slots=4, autopilot_max_active_targets=2)

    res = acquire_lease(
        target_key="domain:ttl-stale.com",
        target_value="ttl-stale.com",
        target_type="domain",
        engagement_id=1,
        requested_slots=2,
        ttl_seconds=10,
        data_dir=tmp_path,
        config=cfg,  # type: ignore[arg-type]
    )
    assert res.acquired is True
    assert res.lease is not None
    lease_id = res.lease.lease_id

    # Simulate time advancing beyond expires_at
    future_now = datetime.now(timezone.utc) + timedelta(seconds=60)
    reaped = reap_stale_leases(data_dir=tmp_path, now=future_now)
    assert lease_id in reaped

    # Direct database check
    db_path = scheduler_db_path(tmp_path)
    with sqlite3.connect(db_path) as con:
        row = con.execute(
            "SELECT status, release_reason FROM leases WHERE lease_id = ?",
            (lease_id,),
        ).fetchone()
        assert row is not None
        assert row[0] == "reaped"
        assert row[1] == "expired_no_heartbeat"

    # Slots and target freed in snapshot
    snap = get_budget_snapshot(data_dir=tmp_path, config=cfg)  # type: ignore[arg-type]
    assert snap.leased_slots == 0
    assert snap.available_slots == 4
    assert snap.active_targets_count == 0

    # Acquiring the same target again succeeds now that the stale lease is reaped
    reacquire = acquire_lease(
        target_key="domain:ttl-stale.com",
        target_value="ttl-stale.com",
        target_type="domain",
        engagement_id=1,
        requested_slots=2,
        data_dir=tmp_path,
        config=cfg,  # type: ignore[arg-type]
    )
    assert reacquire.acquired is True
    assert reacquire.reason == "ok"


# ---------------------------------------------------------------------------
# 3. Stale-lease reaping via dead PID
# ---------------------------------------------------------------------------


def test_stale_lease_reaping_dead_pid(tmp_path: Path) -> None:
    """A lease whose owner_pid does not exist is reaped even if TTL not expired."""
    cfg = _FakeConfig(tmp_path, autopilot_global_slots=4, autopilot_max_active_targets=2)

    res = acquire_lease(
        target_key="domain:dead-pid.com",
        target_value="dead-pid.com",
        target_type="domain",
        engagement_id=1,
        requested_slots=2,
        ttl_seconds=3600,
        data_dir=tmp_path,
        config=cfg,  # type: ignore[arg-type]
    )
    assert res.acquired is True
    assert res.lease is not None
    lease_id = res.lease.lease_id

    # Find a PID guaranteed not to exist without killing any real process
    dead_pid = 4194300
    for _ in range(500):
        try:
            os.kill(dead_pid, 0)
            dead_pid += 1
        except ProcessLookupError:
            break
        except Exception:
            dead_pid += 1

    # Overwrite owner_pid in scheduler DB to the verified dead PID
    db_path = scheduler_db_path(tmp_path)
    with sqlite3.connect(db_path) as con:
        con.execute(
            "UPDATE leases SET owner_pid = ? WHERE lease_id = ?",
            (dead_pid, lease_id),
        )

    # Reaping with current timestamp reaps the dead-PID lease even though TTL is 3600s in the future
    reaped = reap_stale_leases(data_dir=tmp_path)
    assert lease_id in reaped

    with sqlite3.connect(db_path) as con:
        row = con.execute(
            "SELECT status, release_reason FROM leases WHERE lease_id = ?",
            (lease_id,),
        ).fetchone()
        assert row is not None
        assert row[0] == "reaped"
        assert row[1] == "owner_pid_dead"

    snap = get_budget_snapshot(data_dir=tmp_path, config=cfg)  # type: ignore[arg-type]
    assert snap.leased_slots == 0
    assert snap.active_targets_count == 0


# ---------------------------------------------------------------------------
# 4. Heartbeat extends TTL
# ---------------------------------------------------------------------------


def test_lease_heartbeat_extends_ttl(tmp_path: Path) -> None:
    """Heartbeat advances heartbeat_at and pushes expires_at forward."""
    res = acquire_lease(
        target_key="domain:heartbeat.com",
        target_value="heartbeat.com",
        target_type="domain",
        engagement_id=1,
        ttl_seconds=100,
        data_dir=tmp_path,
    )
    assert res.acquired is True
    assert res.lease is not None
    initial_lease = res.lease
    initial_exp = initial_lease.expires_at

    # Call heartbeat with larger TTL
    ok = heartbeat(initial_lease.lease_id, ttl_seconds=1200, data_dir=tmp_path)
    assert ok is True

    active = list_active_leases(data_dir=tmp_path)
    assert len(active) == 1
    updated_lease = active[0]
    assert updated_lease.lease_id == initial_lease.lease_id
    assert updated_lease.heartbeat_at >= initial_lease.heartbeat_at
    assert updated_lease.expires_at > initial_exp

    # Heartbeat on unknown lease returns False
    assert heartbeat("non-existent-lease-uuid", data_dir=tmp_path) is False

    # Heartbeat on released lease returns False
    assert release_lease(initial_lease.lease_id, data_dir=tmp_path) is True
    assert heartbeat(initial_lease.lease_id, data_dir=tmp_path) is False


# ---------------------------------------------------------------------------
# 5. Budget gating — slots exhausted
# ---------------------------------------------------------------------------


def test_budget_gating_slots_exhausted(tmp_path: Path) -> None:
    """With total_slots=4, after leasing 4 slots, a further acquire returns acquired=False, reason='slots_exhausted'."""
    cfg = _FakeConfig(tmp_path, autopilot_global_slots=4, autopilot_max_active_targets=5)

    # Target 1 takes 2 slots
    r1 = acquire_lease(
        target_key="domain:slot1.com",
        target_value="slot1.com",
        target_type="domain",
        engagement_id=1,
        requested_slots=2,
        data_dir=tmp_path,
        config=cfg,  # type: ignore[arg-type]
    )
    assert r1.acquired is True
    assert r1.allocated_slots == 2

    # Target 2 takes 2 slots (total = 4 slots leased)
    r2 = acquire_lease(
        target_key="domain:slot2.com",
        target_value="slot2.com",
        target_type="domain",
        engagement_id=1,
        requested_slots=2,
        data_dir=tmp_path,
        config=cfg,  # type: ignore[arg-type]
    )
    assert r2.acquired is True
    assert r2.allocated_slots == 2

    # Target 3 requests 1 slot -> rejected due to slots_exhausted
    r3 = acquire_lease(
        target_key="domain:slot3.com",
        target_value="slot3.com",
        target_type="domain",
        engagement_id=1,
        requested_slots=1,
        data_dir=tmp_path,
        config=cfg,  # type: ignore[arg-type]
    )
    assert r3.acquired is False
    assert r3.reason == "slots_exhausted"
    assert r3.lease is None
    assert r3.allocated_slots == 0

    # Free 2 slots
    assert r1.lease is not None
    assert release_lease(r1.lease.lease_id, data_dir=tmp_path) is True

    # Now target 3 can acquire
    r3_retry = acquire_lease(
        target_key="domain:slot3.com",
        target_value="slot3.com",
        target_type="domain",
        engagement_id=1,
        requested_slots=1,
        data_dir=tmp_path,
        config=cfg,  # type: ignore[arg-type]
    )
    assert r3_retry.acquired is True
    assert r3_retry.reason == "ok"
    assert r3_retry.allocated_slots == 1


# ---------------------------------------------------------------------------
# 6. Active-target limit
# ---------------------------------------------------------------------------


def test_active_target_limit_enforced(tmp_path: Path) -> None:
    """With max_active_targets=2 and total_slots=4, 2 distinct targets holding slots, a 3rd distinct target acquire returns acquired=False, reason='max_active_targets_reached'."""
    cfg = _FakeConfig(tmp_path, autopilot_global_slots=4, autopilot_max_active_targets=2)

    # Target 1 takes 1 slot
    r1 = acquire_lease(
        target_key="domain:target1.com",
        target_value="target1.com",
        target_type="domain",
        engagement_id=1,
        requested_slots=1,
        data_dir=tmp_path,
        config=cfg,  # type: ignore[arg-type]
    )
    assert r1.acquired is True

    # Target 2 takes 1 slot
    r2 = acquire_lease(
        target_key="domain:target2.com",
        target_value="target2.com",
        target_type="domain",
        engagement_id=1,
        requested_slots=1,
        data_dir=tmp_path,
        config=cfg,  # type: ignore[arg-type]
    )
    assert r2.acquired is True

    # 2 of 4 slots used, but active_targets limit (2) is reached
    snap = get_budget_snapshot(data_dir=tmp_path, config=cfg)  # type: ignore[arg-type]
    assert snap.active_targets_count == 2
    assert snap.available_slots == 2

    # Target 3 rejected with max_active_targets_reached
    r3 = acquire_lease(
        target_key="domain:target3.com",
        target_value="target3.com",
        target_type="domain",
        engagement_id=1,
        requested_slots=1,
        data_dir=tmp_path,
        config=cfg,  # type: ignore[arg-type]
    )
    assert r3.acquired is False
    assert r3.reason == "max_active_targets_reached"
    assert r3.lease is None

    # Release target 1
    assert r1.lease is not None
    assert release_lease(r1.lease.lease_id, data_dir=tmp_path) is True

    # Target 3 now succeeds
    r3_retry = acquire_lease(
        target_key="domain:target3.com",
        target_value="target3.com",
        target_type="domain",
        engagement_id=1,
        requested_slots=1,
        data_dir=tmp_path,
        config=cfg,  # type: ignore[arg-type]
    )
    assert r3_retry.acquired is True
    assert r3_retry.reason == "ok"


# ---------------------------------------------------------------------------
# 7. Duplicate target acquire rejected
# ---------------------------------------------------------------------------


def test_duplicate_target_acquire_rejected(tmp_path: Path) -> None:
    """A target that already has an active lease returns acquired=False, reason='target_already_active'."""
    r1 = acquire_lease(
        target_key="domain:duplicate.com",
        target_value="duplicate.com",
        target_type="domain",
        engagement_id=1,
        requested_slots=1,
        data_dir=tmp_path,
    )
    assert r1.acquired is True
    assert r1.lease is not None

    # Second acquisition on the same target_key while active fails
    r2 = acquire_lease(
        target_key="domain:duplicate.com",
        target_value="duplicate.com",
        target_type="domain",
        engagement_id=2,
        requested_slots=1,
        data_dir=tmp_path,
    )
    assert r2.acquired is False
    assert r2.reason == "target_already_active"
    assert r2.lease is None

    # Once released, the target can be acquired again
    assert release_lease(r1.lease.lease_id, data_dir=tmp_path) is True

    r3 = acquire_lease(
        target_key="domain:duplicate.com",
        target_value="duplicate.com",
        target_type="domain",
        engagement_id=3,
        requested_slots=1,
        data_dir=tmp_path,
    )
    assert r3.acquired is True
    assert r3.reason == "ok"


# ---------------------------------------------------------------------------
# 8. Partial slot allocation
# ---------------------------------------------------------------------------


def test_partial_slot_allocation(tmp_path: Path) -> None:
    """If 1 slot remains and a candidate requests 4, the scheduler grants slot_count=1."""
    cfg = _FakeConfig(tmp_path, autopilot_global_slots=4, autopilot_max_active_targets=4)

    # First target occupies 3 slots
    r1 = acquire_lease(
        target_key="domain:partial1.com",
        target_value="partial1.com",
        target_type="domain",
        engagement_id=1,
        requested_slots=3,
        data_dir=tmp_path,
        config=cfg,  # type: ignore[arg-type]
    )
    assert r1.acquired is True
    assert r1.allocated_slots == 3

    # Second candidate requests 4 slots, but available_slots == 1
    r2 = acquire_lease(
        target_key="domain:partial2.com",
        target_value="partial2.com",
        target_type="domain",
        engagement_id=1,
        requested_slots=4,
        data_dir=tmp_path,
        config=cfg,  # type: ignore[arg-type]
    )
    assert r2.acquired is True
    assert r2.reason == "ok"
    assert r2.allocated_slots == 1
    assert r2.lease is not None
    assert r2.lease.slot_count == 1

    snap = get_budget_snapshot(data_dir=tmp_path, config=cfg)  # type: ignore[arg-type]
    assert snap.leased_slots == 4
    assert snap.available_slots == 0


# ---------------------------------------------------------------------------
# 9. Resume shares budget
# ---------------------------------------------------------------------------


def test_resume_shares_budget_with_import(tmp_path: Path) -> None:
    """A lease with kind='resume' consumes from the same slot pool and target limit as kind='start'."""
    cfg = _FakeConfig(tmp_path, autopilot_global_slots=4, autopilot_max_active_targets=2)

    # Resume lease 1 consumes 2 slots
    r_resume1 = acquire_lease(
        target_key="target:resume_alpha",
        target_value="resume_alpha",
        target_type="domain",
        engagement_id=10,
        requested_slots=2,
        kind="resume",
        data_dir=tmp_path,
        config=cfg,  # type: ignore[arg-type]
    )
    assert r_resume1.acquired is True
    assert r_resume1.lease is not None
    assert r_resume1.lease.kind == "resume"

    # Resume lease 2 consumes 2 slots
    r_resume2 = acquire_lease(
        target_key="target:resume_beta",
        target_value="resume_beta",
        target_type="domain",
        engagement_id=11,
        requested_slots=2,
        kind="resume",
        data_dir=tmp_path,
        config=cfg,  # type: ignore[arg-type]
    )
    assert r_resume2.acquired is True
    assert r_resume2.lease is not None
    assert r_resume2.lease.kind == "resume"

    # Total 4 slots and 2 targets consumed by resumes
    snap = get_budget_snapshot(data_dir=tmp_path, config=cfg)  # type: ignore[arg-type]
    assert snap.leased_slots == 4
    assert snap.active_targets_count == 2
    assert snap.available_slots == 0

    # Fresh start attempt is gated
    r_start = acquire_lease(
        target_key="target:start_gamma",
        target_value="start_gamma",
        target_type="domain",
        engagement_id=12,
        requested_slots=1,
        kind="start",
        data_dir=tmp_path,
        config=cfg,  # type: ignore[arg-type]
    )
    assert r_start.acquired is False
    assert r_start.reason in ("max_active_targets_reached", "slots_exhausted")

    # Release one resume lease -> frees 2 slots and 1 target slot
    assert release_lease(r_resume1.lease.lease_id, data_dir=tmp_path) is True

    # Now start acquire succeeds from the released pool
    r_start2 = acquire_lease(
        target_key="target:start_gamma",
        target_value="start_gamma",
        target_type="domain",
        engagement_id=12,
        requested_slots=2,
        kind="start",
        data_dir=tmp_path,
        config=cfg,  # type: ignore[arg-type]
    )
    assert r_start2.acquired is True
    assert r_start2.lease is not None
    assert r_start2.lease.kind == "start"
    assert r_start2.allocated_slots == 2


# ---------------------------------------------------------------------------
# 10. Kill switch sentinel blocks acquisition
# ---------------------------------------------------------------------------


def test_kill_switch_sentinel_blocks_acquisition(tmp_path: Path) -> None:
    """When autopilot.stop exists in data_dir, is_kill_switch_active returns True and acquire_lease returns acquired=False, reason='kill_switch_active'; removing allows acquisition."""
    assert is_kill_switch_active(data_dir=tmp_path) is False

    sentinel = tmp_path / "autopilot.stop"
    sentinel.write_text('{"reason": "operator_hold"}', encoding="utf-8")

    assert is_kill_switch_active(data_dir=tmp_path) is True

    res = acquire_lease(
        target_key="domain:blocked.com",
        target_value="blocked.com",
        target_type="domain",
        engagement_id=1,
        data_dir=tmp_path,
    )
    assert res.acquired is False
    assert res.reason == "kill_switch_active"
    assert res.lease is None
    assert res.allocated_slots == 0

    # Remove sentinel file
    sentinel.unlink()
    assert is_kill_switch_active(data_dir=tmp_path) is False

    res_resumed = acquire_lease(
        target_key="domain:blocked.com",
        target_value="blocked.com",
        target_type="domain",
        engagement_id=1,
        data_dir=tmp_path,
    )
    assert res_resumed.acquired is True
    assert res_resumed.reason == "ok"


# ---------------------------------------------------------------------------
# 11. import_targets skips when budget exhausted without error
# ---------------------------------------------------------------------------


def test_import_targets_skips_when_budget_exhausted_without_error(
    tmp_path: Path,
) -> None:
    """When scheduler returns slots_exhausted or max_active_targets_reached, import_targets records start_skipped_reason and returns ok results."""
    # Sub-case A: slots_exhausted gating
    data_dir_a = tmp_path / "data_slots"
    cfg_a = _FakeConfig(
        data_dir_a,
        autopilot_global_slots=4,
        autopilot_max_active_targets=4,
    )

    # Pre-fill scheduler DB to consume all 4 slots
    pre_lease_a = acquire_lease(
        target_key="seed:prefilled_slots",
        target_value="prefilled-slots.com",
        target_type="domain",
        engagement_id=901,
        requested_slots=4,
        data_dir=data_dir_a,
        config=cfg_a,  # type: ignore[arg-type]
    )
    assert pre_lease_a.acquired is True

    feed_a = tmp_path / "feed_a.json"
    _write_simple_feed(feed_a)

    results_a = import_targets(
        feed_url=None,
        feed_file=feed_a,
        auth_header_env=None,
        roe_id="ROE-TEST-2026",
        start=True,
        dry_run=False,
        limit=2,
        max_iter=3,
        config=cfg_a,  # type: ignore[arg-type]
        sleep_fn=lambda _: None,
    )

    assert len(results_a) >= 1
    assert results_a[0].started is False
    assert results_a[0].start_skipped_reason == "slots_exhausted"
    assert results_a[0].start_stop_reason == "slots_exhausted"

    # Sub-case B: max_active_targets_reached gating
    data_dir_b = tmp_path / "data_targets"
    cfg_b = _FakeConfig(
        data_dir_b,
        autopilot_global_slots=4,
        autopilot_max_active_targets=2,
    )

    # Pre-fill 2 distinct targets (consuming max_active_targets limit)
    pre_lease_b1 = acquire_lease(
        target_key="seed:prefilled_target_1",
        target_value="prefilled-target-1.com",
        target_type="domain",
        engagement_id=902,
        requested_slots=1,
        data_dir=data_dir_b,
        config=cfg_b,  # type: ignore[arg-type]
    )
    assert pre_lease_b1.acquired is True

    pre_lease_b2 = acquire_lease(
        target_key="seed:prefilled_target_2",
        target_value="prefilled-target-2.com",
        target_type="domain",
        engagement_id=903,
        requested_slots=1,
        data_dir=data_dir_b,
        config=cfg_b,  # type: ignore[arg-type]
    )
    assert pre_lease_b2.acquired is True

    feed_b = tmp_path / "feed_b.json"
    _write_simple_feed(feed_b)

    results_b = import_targets(
        feed_url=None,
        feed_file=feed_b,
        auth_header_env=None,
        roe_id="ROE-TEST-2026",
        start=True,
        dry_run=False,
        limit=2,
        max_iter=3,
        config=cfg_b,  # type: ignore[arg-type]
        sleep_fn=lambda _: None,
    )

    assert len(results_b) >= 1
    assert results_b[0].started is False
    assert results_b[0].start_skipped_reason == "max_active_targets_reached"
    assert results_b[0].start_stop_reason == "max_active_targets_reached"


def test_import_targets_engaged_progress_includes_scheduler_telemetry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = _FakeConfig(tmp_path, autopilot_global_slots=4, autopilot_max_active_targets=2)
    feed = tmp_path / "telemetry-feed.json"
    _write_simple_feed(feed)
    feed_data = json.loads(feed.read_text(encoding="utf-8"))
    feed_data["items"][0]["first_seen_at"] = "2026-01-01T00:00:00+00:00"
    feed.write_text(json.dumps(feed_data), encoding="utf-8")
    events: list[tuple[str, dict[str, object]]] = []
    monkeypatch.setattr("forge.targets_import._start_kill_chain", lambda **_kwargs: None)

    import_targets(
        feed_url=None,
        feed_file=feed,
        auth_header_env=None,
        roe_id="ROE-TEST",
        roe_scope="target-alpha.corp-target.io",
        start=True,
        dry_run=False,
        limit=1,
        max_iter=1,
        config=cfg,  # type: ignore[arg-type]
        progress_callback=lambda event, details: events.append((event, details)),
        sleep_fn=lambda _seconds: None,
    )
    details = next(details for event, details in events if event == "target_engaged")
    assert isinstance(details["queue_seconds"], float) and details["queue_seconds"] >= 0
    for key in ("requested_slots", "effective_slots", "active_targets", "leased_slots", "total_slots"):
        assert isinstance(details[key], int)
    assert isinstance(details["memory_peak_kb"], int) and details["memory_peak_kb"] >= 0
    for key in ("cpu_user_seconds", "cpu_sys_seconds"):
        assert isinstance(details[key], float) and details[key] >= 0
    assert isinstance(details["provider"], str) and details["provider"]
    assert isinstance(details["provider_paused"], bool)
    assert isinstance(details["global_paused"], bool)
    assert isinstance(details["provider_inflight"], int) and details["provider_inflight"] >= 1
    assert isinstance(details["scheduling_delay_seconds"], float)
    assert details["scheduling_delay_seconds"] > 0
    completed = next(details for event, details in events if event == "target_completed")
    assert completed["exit_status"] == "completed"


def test_import_targets_failed_progress_includes_exit_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = _FakeConfig(tmp_path, autopilot_global_slots=4, autopilot_max_active_targets=2)
    feed = tmp_path / "failed-telemetry-feed.json"
    _write_simple_feed(feed)
    events: list[tuple[str, dict[str, object]]] = []

    def fail_start(**_kwargs: object) -> None:
        raise RuntimeError("stubbed failure")

    monkeypatch.setattr("forge.targets_import._start_kill_chain", fail_start)
    import_targets(
        feed_url=None, feed_file=feed, auth_header_env=None, roe_id="ROE-TEST",
        roe_scope="target-alpha.corp-target.io", start=True, dry_run=False,
        limit=1, max_iter=1, config=cfg,  # type: ignore[arg-type]
        progress_callback=lambda event, details: events.append((event, details)),
        sleep_fn=lambda _seconds: None,
    )
    failed = next(details for event, details in events if event == "target_failed")
    assert failed["exit_status"] == "failed"
    assert failed["error_type"] == "RuntimeError"


def test_resume_item_progress_carries_scheduler_telemetry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "forge.targets_resume_candidates._refresh_plan_item",
        lambda item: {**item, "status": "ready"},
    )
    item = {
        "db_path": str(tmp_path / "data" / "engagement-1.db"),
        "seed_value": "resume-target.example.com",
        "seed_type": "domain",
        "engagement_id": 7,
        "run_id": 3,
        "parallel_fanout": 2,
        "command": ["true"],
        "max_runtime_minutes": 1,
        "sequence": 1,
        "timeout_retry_attempt": 0,
        "timeout_retry_budget": 0,
    }
    captured: list[tuple[str, dict]] = []
    callback = lambda event, details: captured.append((event, details))
    runner = lambda command, timeout_seconds: subprocess.CompletedProcess(
        args=command, returncode=0, stdout="", stderr=""
    )

    _execute_resume_item(
        item,
        batch="batch-1",
        ledger_path=tmp_path / "ledger.jsonl",
        ledger_lock=threading.Lock(),
        runner=runner,
        progress_callback=callback,
        data_dir=tmp_path / "data",
        config=None,
    )

    engaged = next(details for event, details in captured if event == "target_engaged")
    assert engaged["target_value"] == "resume-target.example.com"
    assert engaged["target_type"] == "domain"
    assert isinstance(engaged["queue_seconds"], float) and engaged["queue_seconds"] >= 0
    assert engaged["requested_slots"] == 2
    assert engaged["effective_slots"] == 2
    assert engaged["active_targets"] >= 1
    assert engaged["leased_slots"] >= 2
    assert engaged["total_slots"] >= engaged["leased_slots"]
    assert engaged["total_slots"] > 0
    assert isinstance(engaged["memory_peak_kb"], int) and engaged["memory_peak_kb"] >= 0
    for key in ("cpu_user_seconds", "cpu_sys_seconds"):
        assert isinstance(engaged[key], float) and engaged[key] >= 0
    assert isinstance(engaged["provider"], str) and engaged["provider"]
    assert isinstance(engaged["provider_paused"], bool)
    assert isinstance(engaged["global_paused"], bool)
    assert isinstance(engaged["provider_inflight"], int) and engaged["provider_inflight"] >= 1
    assert "scheduling_delay_seconds" not in engaged
    completed = next(details for event, details in captured if event == "target_completed")
    assert completed["exit_status"] == "completed"
    assert completed["return_code"] == 0


def test_process_resource_and_provider_lease_helpers(tmp_path: Path) -> None:
    resources = sample_process_resources()
    assert isinstance(resources["memory_peak_kb"], int) and resources["memory_peak_kb"] >= 0
    for key in ("cpu_user_seconds", "cpu_sys_seconds"):
        assert isinstance(resources[key], float) and resources[key] >= 0

    lease_result = acquire_lease(
        target_key="domain:provider-count.example.com",
        target_value="provider-count.example.com",
        target_type="domain",
        engagement_id=1,
        data_dir=tmp_path,
    )
    assert lease_result.lease is not None
    provider = lease_result.lease.provider
    assert provider_inflight_count(provider, data_dir=tmp_path) == 1
    assert release_lease(lease_result.lease.lease_id, data_dir=tmp_path) is True
    assert provider_inflight_count(provider, data_dir=tmp_path) == 0
    assert provider_inflight_count("unknown-provider", data_dir=tmp_path) == 0


# ---------------------------------------------------------------------------
# 12. Budget formula edge cases
# ---------------------------------------------------------------------------


def test_budget_formula_edge_cases(tmp_path: Path) -> None:
    """Validate zero/negative slots, unmeasured p95 fallback, and MemAvailable below reserve threshold."""
    # 1. Zero configured slots
    assert compute_worker_budget(0) == 0
    assert (
        compute_worker_budget(
            0,
            p95_worker_memory_mb=512,
            mem_available_mb=16384,
            effective_cpu_count=8,
        )
        == 0
    )

    # 2. Negative configured slots
    assert compute_worker_budget(-1) == 0
    assert (
        compute_worker_budget(
            -8,
            p95_worker_memory_mb=512,
            mem_available_mb=16384,
            effective_cpu_count=8,
        )
        == 0
    )

    # 3. Unmeasured p95 worker memory fallback to configured slots
    assert compute_worker_budget(4, p95_worker_memory_mb=0) == 4
    assert compute_worker_budget(6, p95_worker_memory_mb=-100) == 6

    # 4. Host MemAvailable below or equal to reserve threshold
    assert (
        compute_worker_budget(
            4,
            p95_worker_memory_mb=512,
            memory_reserve_mb=4096,
            mem_available_mb=2048,
            effective_cpu_count=8,
        )
        == 0
    )
    assert (
        compute_worker_budget(
            4,
            p95_worker_memory_mb=512,
            memory_reserve_mb=4096,
            mem_available_mb=4096,
            effective_cpu_count=8,
        )
        == 0
    )

    # 5. Host MemAvailable above reserve allows memory-based slot count
    assert (
        compute_worker_budget(
            10,
            p95_worker_memory_mb=512,
            memory_reserve_mb=4096,
            mem_available_mb=4096 + (3 * 512),
            effective_cpu_count=8,
        )
        == 3
    )

    # 6. CPU limiting factor: effective_cpu_count * 0.75
    assert (
        compute_worker_budget(
            10,
            p95_worker_memory_mb=100,
            memory_reserve_mb=1000,
            mem_available_mb=50000,
            effective_cpu_count=4,  # 4 * 0.75 = 3
        )
        == 3
    )

    # 7. acquire_lease fallback to 1 slot when requested_slots <= 0
    res_zero = acquire_lease(
        target_key="domain:zero-req.com",
        target_value="zero-req.com",
        target_type="domain",
        engagement_id=1,
        requested_slots=0,
        data_dir=tmp_path,
    )
    assert res_zero.acquired is True
    assert res_zero.allocated_slots == 1

    res_neg = acquire_lease(
        target_key="domain:neg-req.com",
        target_value="neg-req.com",
        target_type="domain",
        engagement_id=1,
        requested_slots=-5,
        data_dir=tmp_path,
    )
    assert res_neg.acquired is True
    assert res_neg.allocated_slots == 1


def test_child_memory_p95_record_read_and_empty_state(tmp_path: Path) -> None:
    for value in range(100, 2001, 100):
        assert record_child_memory_sample(value, data_dir=tmp_path)
    computed = compute_child_memory_p95(data_dir=tmp_path)
    assert computed is not None
    assert computed["p95_worker_memory_kb"] == 1900
    assert computed["p95_worker_memory_mb"] == pytest.approx(1900 / 1024.0)
    assert computed["samples"] == 20
    stored = record_worker_memory_p95(data_dir=tmp_path)
    assert stored is not None
    read = read_recorded_worker_memory_p95(data_dir=tmp_path)
    assert read is not None
    assert read["p95_worker_memory_mb"] == stored["p95_worker_memory_mb"]
    assert read["samples"] == stored["samples"] == 20

    empty_dir = tmp_path / "empty"
    assert compute_child_memory_p95(data_dir=empty_dir) is None
    assert record_worker_memory_p95(data_dir=empty_dir) is None
    assert read_recorded_worker_memory_p95(data_dir=empty_dir) is None
    with sqlite3.connect(scheduler_db_path(empty_dir)) as con:
        assert con.execute("SELECT COUNT(*) FROM worker_memory_stats").fetchone()[0] == 0


def test_child_memory_invalid_samples_and_pruning(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for peak in (None, 0, -5, "x", True):
        assert record_child_memory_sample(peak, data_dir=tmp_path) is False
    db_path = scheduler_db_path(tmp_path)
    with sqlite3.connect(db_path) as con:
        ensure_child_memory_schema(con)
        assert con.execute("SELECT COUNT(*) FROM child_memory_samples").fetchone()[0] == 0

    monkeypatch.setattr("forge.autopilot.scheduler._MAX_CHILD_MEMORY_SAMPLES", 5)
    for peak in range(1, 8):
        assert record_child_memory_sample(peak, data_dir=tmp_path)
    with sqlite3.connect(db_path) as con:
        rows = con.execute("SELECT peak_rss_kb FROM child_memory_samples ORDER BY id").fetchall()
    assert rows == [(3,), (4,), (5,), (6,), (7,)]


def test_resolve_p95_worker_memory_precedence(tmp_path: Path) -> None:
    from types import SimpleNamespace

    for value in range(102_400, 102_501):
        assert record_child_memory_sample(value, data_dir=tmp_path)
    recorded = record_worker_memory_p95(data_dir=tmp_path)
    assert recorded is not None
    assert recorded["p95_worker_memory_mb"] == pytest.approx(102_495 / 1024.0)

    assert resolve_p95_worker_memory_mb(
        SimpleNamespace(autopilot_p95_worker_memory_mb=512), data_dir=tmp_path
    ) == 512
    assert resolve_p95_worker_memory_mb(
        SimpleNamespace(autopilot_p95_worker_memory_mb=0), data_dir=tmp_path
    ) == 100

    empty_dir = tmp_path / "empty"
    assert resolve_p95_worker_memory_mb(
        SimpleNamespace(autopilot_p95_worker_memory_mb=0), data_dir=empty_dir
    ) == 0
    assert resolve_p95_worker_memory_mb(None, data_dir=tmp_path) == 100
    assert resolve_p95_worker_memory_mb(
        SimpleNamespace(autopilot_p95_worker_memory_mb=-5), data_dir=tmp_path
    ) == 100
    assert resolve_p95_worker_memory_mb(
        SimpleNamespace(autopilot_p95_worker_memory_mb="abc"), data_dir=tmp_path
    ) == 100


def test_recorded_p95_tightens_budget_snapshot(tmp_path: Path) -> None:
    cfg = _FakeConfig(tmp_path, autopilot_global_slots=4, autopilot_p95_worker_memory_mb=0)
    without_recorded = get_budget_snapshot(data_dir=tmp_path, config=cfg).total_slots  # type: ignore[arg-type]
    assert without_recorded == min(4, max(1, int((os.cpu_count() or 1) * 0.75)))

    for _ in range(20):
        assert record_child_memory_sample(1_000_000_000, data_dir=tmp_path)
    assert record_worker_memory_p95(data_dir=tmp_path) is not None
    with_recorded = get_budget_snapshot(data_dir=tmp_path, config=cfg).total_slots  # type: ignore[arg-type]
    assert with_recorded == 0
    assert with_recorded < without_recorded


def test_small_recorded_p95_does_not_tighten_budget_snapshot(tmp_path: Path) -> None:
    cfg = _FakeConfig(tmp_path, autopilot_global_slots=4, autopilot_p95_worker_memory_mb=0)
    without_recorded = get_budget_snapshot(data_dir=tmp_path, config=cfg).total_slots  # type: ignore[arg-type]
    for _ in range(20):
        assert record_child_memory_sample(1024, data_dir=tmp_path)
    assert record_worker_memory_p95(data_dir=tmp_path) is not None
    with_recorded = get_budget_snapshot(data_dir=tmp_path, config=cfg).total_slots  # type: ignore[arg-type]
    assert with_recorded == without_recorded


def test_acquire_lease_uses_recorded_p95_budget(tmp_path: Path) -> None:
    cfg = _FakeConfig(tmp_path, autopilot_global_slots=4, autopilot_p95_worker_memory_mb=0)
    without_recorded = acquire_lease(
        target_key="domain:unmeasured.test",
        target_value="unmeasured.test",
        target_type="domain",
        engagement_id=1,
        requested_slots=1,
        data_dir=tmp_path,
        config=cfg,  # type: ignore[arg-type]
    )
    assert without_recorded.acquired is True
    assert without_recorded.lease is not None
    assert release_lease(without_recorded.lease.lease_id, data_dir=tmp_path)

    for _ in range(20):
        assert record_child_memory_sample(1_000_000_000, data_dir=tmp_path)
    assert record_worker_memory_p95(data_dir=tmp_path) is not None
    with_recorded = acquire_lease(
        target_key="domain:measured.test",
        target_value="measured.test",
        target_type="domain",
        engagement_id=2,
        requested_slots=1,
        data_dir=tmp_path,
        config=cfg,  # type: ignore[arg-type]
    )
    assert with_recorded.acquired is False
    assert with_recorded.reason == "slots_exhausted"


def test_start_kill_chain_records_child_memory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from forge.config import ForgeConfig
    from forge.targets_import import _start_kill_chain

    data_dir = tmp_path / "data"
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    config = ForgeConfig.load()
    proc = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
    proc.peak_rss_kb = 123456  # type: ignore[attr-defined]
    monkeypatch.setattr("forge.targets_import.run_contained_subprocess", lambda *_a, **_k: proc)
    _start_kill_chain(
        engagement_id=1,
        seed="wiring-test.example.com",
        roe_id="ROE-TEST",
        scope_manifest=tmp_path / "manifest.json",
        max_iter=1,
        max_runtime_minutes=1,
        parallel_fanout=1,
        engagement_db_path=tmp_path / "e.db",
        config=config,
        sleep_fn=lambda _seconds: None,
    )
    with sqlite3.connect(data_dir / "scheduler.db") as con:
        assert con.execute("SELECT peak_rss_kb FROM child_memory_samples").fetchall() == [(123456,)]


def test_resume_child_records_memory_sample(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    monkeypatch.setattr(
        "forge.targets_resume_candidates._refresh_plan_item",
        lambda item: {**item, "status": "ready"},
    )
    item = {
        "db_path": str(tmp_path / "engagements" / "1.db"),
        "seed_value": "resume-memory.example.com",
        "seed_type": "domain",
        "engagement_id": 1,
        "run_id": 1,
        "parallel_fanout": 1,
        "command": [sys.executable, "-c", "import time; time.sleep(0.3)"],
        "max_runtime_minutes": 1,
        "sequence": 1,
        "timeout_retry_attempt": 0,
        "timeout_retry_budget": 0,
    }
    _execute_resume_item(
        item,
        batch="memory-test",
        ledger_path=tmp_path / "state" / "resume" / "ledger.jsonl",
        ledger_lock=threading.Lock(),
        runner=None,
        data_dir=tmp_path / "data",
        config=None,
    )
    with sqlite3.connect(tmp_path / "data" / "scheduler.db") as con:
        assert con.execute("SELECT COUNT(*) FROM child_memory_samples").fetchone()[0] >= 1
