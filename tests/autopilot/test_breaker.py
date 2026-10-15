"""tests/autopilot/test_breaker.py — Unit and integration tests for Circuit Breakers.

Covers the 10 design specifications from Iteration 6a (Plan 2.4):
1. test_provider_breaker_trips_after_three_in_ten_minutes
2. test_provider_breaker_does_not_trip_after_two
3. test_breaker_window_slides_old_events_expire
4. test_fifteen_minute_pause_enforced_and_expires
5. test_global_breaker_trips_on_multi_provider_rate_limits
6. test_retry_after_pause_enforced_and_longer_of_two_wins
7. test_per_provider_inflight_limit_blocks_third_concurrent
8. test_breaker_state_survives_restart
9. test_acquire_lease_respects_circuit_breaker
10. test_import_targets_skips_paused_provider_continues_others
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from forge.autopilot.breaker import (
    canonical_provider,
    check_resource_pressure,
    is_global_paused,
    is_provider_paused,
    record_global_rate_limit,
    record_rate_limit,
    record_child_failure,
    remaining_global_pause,
    remaining_pause,
    set_retry_after,
)
from forge.autopilot.scheduler import (
    acquire_lease,
    scheduler_db_path,
)
from forge.db.direct_connect import direct_connect
from forge.targets_import import import_targets


@pytest.fixture(autouse=True)
def _noop_targets_import_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("forge.targets_import._DEFAULT_SLEEP", lambda _: None)


class _FakeConfig:
    def __init__(
        self,
        data_dir: Path,
        roe_strictness: str | None = None,
        autopilot_global_slots: int = 10,
        autopilot_max_active_targets: int = 10,
        autopilot_lease_ttl_seconds: int = 600,
        autopilot_memory_reserve_mb: int = 4096,
        autopilot_p95_worker_memory_mb: int = 0,
        autopilot_kill_switch_file: Path | None = None,
        breaker_rate_limit_window_s: int = 600,
        breaker_rate_limit_threshold: int = 3,
        breaker_pause_s: int = 900,
        breaker_global_provider_threshold: int = 3,
        breaker_global_event_threshold: int = 10,
        provider_max_inflight: int = 2,
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
        self.breaker_rate_limit_window_s = breaker_rate_limit_window_s
        self.breaker_rate_limit_threshold = breaker_rate_limit_threshold
        self.breaker_pause_s = breaker_pause_s
        self.breaker_global_provider_threshold = breaker_global_provider_threshold
        self.breaker_global_event_threshold = breaker_global_event_threshold
        self.provider_max_inflight = provider_max_inflight

    def engagement_db_path(self, engagement_id: str) -> Path:
        p = self.data_dir / "engagements" / f"{engagement_id}.db"
        p.parent.mkdir(parents=True, exist_ok=True)
        return p


# ---------------------------------------------------------------------------
# 1. test_provider_breaker_trips_after_three_in_ten_minutes
# ---------------------------------------------------------------------------


def test_provider_breaker_trips_after_three_in_ten_minutes(tmp_path: Path) -> None:
    """Recording 3 rate-limit events for 'shodan' in 10 minutes trips breaker for 15 minutes."""
    t0 = datetime(2026, 10, 15, 10, 0, 0, tzinfo=timezone.utc)
    assert is_provider_paused("shodan", data_dir=tmp_path, now=t0) is False

    r1 = record_rate_limit("shodan", data_dir=tmp_path, now=t0)
    assert r1 is False
    assert is_provider_paused("shodan", data_dir=tmp_path, now=t0) is False

    t1 = t0 + timedelta(seconds=60)
    r2 = record_rate_limit("shodan", data_dir=tmp_path, now=t1)
    assert r2 is False
    assert is_provider_paused("shodan", data_dir=tmp_path, now=t1) is False

    t2 = t0 + timedelta(seconds=120)
    r3 = record_rate_limit("shodan", data_dir=tmp_path, now=t2)
    assert r3 is True
    assert is_provider_paused("shodan", data_dir=tmp_path, now=t2) is True

    rem = remaining_pause("shodan", data_dir=tmp_path, now=t2)
    assert 890.0 <= rem <= 900.0


# ---------------------------------------------------------------------------
# 2. test_provider_breaker_does_not_trip_after_two
# ---------------------------------------------------------------------------


def test_provider_breaker_does_not_trip_after_two(tmp_path: Path) -> None:
    """Recording only 2 rate-limit events leaves provider unpaused."""
    t0 = datetime(2026, 10, 15, 10, 0, 0, tzinfo=timezone.utc)
    record_rate_limit("shodan", data_dir=tmp_path, now=t0)

    t1 = t0 + timedelta(seconds=100)
    record_rate_limit("shodan", data_dir=tmp_path, now=t1)

    assert is_provider_paused("shodan", data_dir=tmp_path, now=t1) is False
    assert remaining_pause("shodan", data_dir=tmp_path, now=t1) == 0.0


# ---------------------------------------------------------------------------
# 3. test_breaker_window_slides_old_events_expire
# ---------------------------------------------------------------------------


def test_breaker_window_slides_old_events_expire(tmp_path: Path) -> None:
    """Events older than the 10-minute window do not count toward threshold."""
    t0 = datetime(2026, 10, 15, 10, 0, 0, tzinfo=timezone.utc)
    record_rate_limit("shodan", data_dir=tmp_path, now=t0)
    record_rate_limit("shodan", data_dir=tmp_path, now=t0 + timedelta(seconds=10))

    # Advance time past the 600s window (601 seconds)
    t1 = t0 + timedelta(seconds=601)
    r = record_rate_limit("shodan", data_dir=tmp_path, now=t1)
    assert r is False
    assert is_provider_paused("shodan", data_dir=tmp_path, now=t1) is False


# ---------------------------------------------------------------------------
# 4. test_fifteen_minute_pause_enforced_and_expires
# ---------------------------------------------------------------------------


def test_fifteen_minute_pause_enforced_and_expires(tmp_path: Path) -> None:
    """Breaker pause remains active until 15 minutes have elapsed, then unpauses."""
    t0 = datetime(2026, 10, 15, 10, 0, 0, tzinfo=timezone.utc)
    record_rate_limit("shodan", data_dir=tmp_path, now=t0)
    record_rate_limit("shodan", data_dir=tmp_path, now=t0)
    record_rate_limit("shodan", data_dir=tmp_path, now=t0)
    assert is_provider_paused("shodan", data_dir=tmp_path, now=t0) is True

    # At T + 899s (1 second before 15m expiry), pause is still active
    t_before = t0 + timedelta(seconds=899)
    assert is_provider_paused("shodan", data_dir=tmp_path, now=t_before) is True
    assert remaining_pause("shodan", data_dir=tmp_path, now=t_before) > 0.0

    # At T + 901s (1 second after 15m expiry), pause has expired
    t_after = t0 + timedelta(seconds=901)
    assert is_provider_paused("shodan", data_dir=tmp_path, now=t_after) is False
    assert remaining_pause("shodan", data_dir=tmp_path, now=t_after) == 0.0


# ---------------------------------------------------------------------------
# 5. test_global_breaker_trips_on_multi_provider_rate_limits
# ---------------------------------------------------------------------------


def test_global_breaker_trips_on_multi_provider_rate_limits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Global breaker trips when >=3 distinct providers rate-limit in 10 minutes."""
    monkeypatch.setattr("forge.autopilot.breaker.check_resource_pressure", lambda: (False, ""))
    t0 = datetime(2026, 10, 15, 10, 0, 0, tzinfo=timezone.utc)

    # Provider 1
    record_rate_limit("shodan", data_dir=tmp_path, now=t0)
    assert is_global_paused(data_dir=tmp_path, now=t0) is False

    # Provider 2
    t1 = t0 + timedelta(seconds=10)
    record_rate_limit("urlscan", data_dir=tmp_path, now=t1)
    assert is_global_paused(data_dir=tmp_path, now=t1) is False

    # Provider 3
    t2 = t0 + timedelta(seconds=20)
    record_rate_limit("target.com", data_dir=tmp_path, now=t2)
    assert is_global_paused(data_dir=tmp_path, now=t2) is True
    rem = remaining_global_pause(data_dir=tmp_path, now=t2)
    assert 880.0 <= rem <= 900.0


def test_global_breaker_trips_after_five_child_failures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("forge.autopilot.breaker.check_resource_pressure", lambda: (False, ""))
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for index in range(4):
        assert record_child_failure("provider-a", "exit_1", data_dir=tmp_path, now=now + timedelta(seconds=index)) is False
    assert is_global_paused(data_dir=tmp_path, now=now + timedelta(seconds=4)) is False
    assert record_child_failure("provider-b", "timeout", data_dir=tmp_path, now=now + timedelta(seconds=5)) is True
    assert is_global_paused(data_dir=tmp_path, now=now + timedelta(seconds=5)) is True


def test_resource_pressure_checks_memory_and_cpu() -> None:
    assert check_resource_pressure(mem_available_mb=500, load1=0.1, cpu_count=4) == (True, "memory_pressure")
    assert check_resource_pressure(mem_available_mb=8000, load1=13, cpu_count=4) == (True, "cpu_pressure")
    assert check_resource_pressure(mem_available_mb=8000, load1=12, cpu_count=4) == (False, "")


def test_resource_pressure_blocks_admission_with_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("forge.autopilot.breaker.check_resource_pressure", lambda: (True, "memory_pressure"))
    result = acquire_lease(
        target_key="pressure-test",
        target_value="pressure-test.example",
        target_type="domain",
        engagement_id=1,
        data_dir=tmp_path,
    )
    assert result.acquired is False
    assert result.reason == "memory_pressure"


# ---------------------------------------------------------------------------
# 6. test_retry_after_pause_enforced_and_longer_of_two_wins
# ---------------------------------------------------------------------------


def test_retry_after_pause_enforced_and_longer_of_two_wins(tmp_path: Path) -> None:
    """Retry-After pauses admission, and between breaker and Retry-After, longer pause wins."""
    t0 = datetime(2026, 10, 15, 10, 0, 0, tzinfo=timezone.utc)

    # (a) set_retry_after pauses provider even with 0 prior events
    delay = set_retry_after("api.com", 120, data_dir=tmp_path, now=t0)
    assert delay == 120.0
    assert is_provider_paused("api.com", data_dir=tmp_path, now=t0) is True
    assert remaining_pause("api.com", data_dir=tmp_path, now=t0) == 120.0

    # (b) Provider on 15m (900s) pause receives shorter Retry-After (60s) -> stays 900s
    prov = "longer-wins.com"
    record_rate_limit(prov, data_dir=tmp_path, now=t0)
    record_rate_limit(prov, data_dir=tmp_path, now=t0)
    record_rate_limit(prov, data_dir=tmp_path, now=t0)
    assert remaining_pause(prov, data_dir=tmp_path, now=t0) == 900.0

    set_retry_after(prov, 60, data_dir=tmp_path, now=t0)
    assert remaining_pause(prov, data_dir=tmp_path, now=t0) == 900.0

    # (c) Provider has 100s remaining on pause, receives longer Retry-After (1800s) -> extends to 1800s
    t_later = t0 + timedelta(seconds=800)  # 900 - 800 = 100s left
    assert remaining_pause(prov, data_dir=tmp_path, now=t_later) == 100.0

    set_retry_after(prov, 1800, data_dir=tmp_path, now=t_later)
    assert remaining_pause(prov, data_dir=tmp_path, now=t_later) == 1800.0


# ---------------------------------------------------------------------------
# 7. test_per_provider_inflight_limit_blocks_third_concurrent
# ---------------------------------------------------------------------------


def test_per_provider_inflight_limit_blocks_third_concurrent(tmp_path: Path) -> None:
    """With max_inflight=2, a 3rd lease for the same provider is rejected, while another provider succeeds."""
    cfg = _FakeConfig(
        tmp_path,
        autopilot_global_slots=10,
        autopilot_max_active_targets=10,
        provider_max_inflight=2,
    )

    l1 = acquire_lease(
        target_key="seed:ex1",
        target_value="https://example.com/item1",
        target_type="url",
        engagement_id=101,
        requested_slots=1,
        data_dir=tmp_path,
        config=cfg,  # type: ignore[arg-type]
    )
    assert l1.acquired is True

    l2 = acquire_lease(
        target_key="seed:ex2",
        target_value="https://example.com/item2",
        target_type="url",
        engagement_id=102,
        requested_slots=1,
        data_dir=tmp_path,
        config=cfg,  # type: ignore[arg-type]
    )
    assert l2.acquired is True

    # 3rd concurrent lease for example.com fails with provider_inflight_limit
    l3 = acquire_lease(
        target_key="seed:ex3",
        target_value="https://example.com/item3",
        target_type="url",
        engagement_id=103,
        requested_slots=1,
        data_dir=tmp_path,
        config=cfg,  # type: ignore[arg-type]
    )
    assert l3.acquired is False
    assert l3.reason == "provider_inflight_limit"

    # Concurrently, a lease for a different provider succeeds
    l_other = acquire_lease(
        target_key="seed:other1",
        target_value="https://other.com/item1",
        target_type="url",
        engagement_id=104,
        requested_slots=1,
        data_dir=tmp_path,
        config=cfg,  # type: ignore[arg-type]
    )
    assert l_other.acquired is True


# ---------------------------------------------------------------------------
# 8. test_breaker_state_survives_restart
# ---------------------------------------------------------------------------


def test_breaker_state_survives_restart(tmp_path: Path) -> None:
    """Breaker state persisted in SQLite survives connection closure and restart."""
    t0 = datetime(2026, 10, 15, 10, 0, 0, tzinfo=timezone.utc)
    record_rate_limit("shodan", data_dir=tmp_path, now=t0)
    record_rate_limit("shodan", data_dir=tmp_path, now=t0)
    record_rate_limit("shodan", data_dir=tmp_path, now=t0)

    # Verify state via a completely new connection
    t1 = t0 + timedelta(seconds=60)
    assert is_provider_paused("shodan", data_dir=tmp_path, now=t1) is True

    con = direct_connect(scheduler_db_path(tmp_path))
    try:
        cur = con.execute("SELECT COUNT(*) FROM provider_events WHERE provider = 'shodan'")
        assert cur.fetchone()[0] == 3
        cur = con.execute("SELECT paused_until FROM provider_breakers WHERE provider = 'shodan'")
        row = cur.fetchone()
        assert row is not None and row[0] is not None
    finally:
        con.close()


# ---------------------------------------------------------------------------
# 9. test_acquire_lease_respects_circuit_breaker
# ---------------------------------------------------------------------------


def test_acquire_lease_respects_circuit_breaker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """acquire_lease checks global and provider circuit breakers before granting leases."""
    monkeypatch.setattr("forge.autopilot.breaker.check_resource_pressure", lambda: (False, ""))
    cfg = _FakeConfig(
        tmp_path,
        autopilot_global_slots=10,
        autopilot_max_active_targets=10,
    )
    # acquire_lease evaluates pauses against the real clock, so create a fresh
    # pause and use the same explicit config when recording its trigger events.
    t0 = datetime.now(timezone.utc)

    # 1. Provider circuit breaker check
    record_rate_limit("shodan", data_dir=tmp_path, now=t0, config=cfg)  # type: ignore[arg-type]
    record_rate_limit("shodan", data_dir=tmp_path, now=t0, config=cfg)  # type: ignore[arg-type]
    record_rate_limit("shodan", data_dir=tmp_path, now=t0, config=cfg)  # type: ignore[arg-type]

    res_prov = acquire_lease(
        target_key="seed:shodan1",
        target_value="shodan",
        target_type="service",
        engagement_id=201,
        data_dir=tmp_path,
        config=cfg,  # type: ignore[arg-type]
    )
    assert res_prov.acquired is False
    assert res_prov.reason == "provider_circuit_breaker_active"

    # 2. Global circuit breaker check
    record_global_rate_limit(reason="manual", pause_seconds=900, data_dir=tmp_path, now=t0)
    res_global = acquire_lease(
        target_key="seed:healthy1",
        target_value="healthy-provider.com",
        target_type="domain",
        engagement_id=202,
        data_dir=tmp_path,
        config=cfg,  # type: ignore[arg-type]
    )
    assert res_global.acquired is False
    assert res_global.reason == "global_circuit_breaker_active"


# ---------------------------------------------------------------------------
# 10. test_import_targets_skips_paused_provider_continues_others
# ---------------------------------------------------------------------------


def test_import_targets_skips_paused_provider_continues_others(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """In import_targets, a paused provider target is skipped while other providers are engaged."""
    cfg = _FakeConfig(
        tmp_path,
        autopilot_global_slots=10,
        autopilot_max_active_targets=10,
    )
    t0 = datetime.now(timezone.utc)

    # Pause target-alpha's provider (target-alpha.corp-target.io)
    prov_alpha = canonical_provider("target-alpha.corp-target.io")
    record_rate_limit(prov_alpha, data_dir=tmp_path, now=t0)
    record_rate_limit(prov_alpha, data_dir=tmp_path, now=t0)
    record_rate_limit(prov_alpha, data_dir=tmp_path, now=t0)
    assert is_provider_paused(prov_alpha, data_dir=tmp_path, now=t0) is True

    # Target-beta is unpaused
    prov_beta = canonical_provider("target-beta.corp-target.io")
    assert is_provider_paused(prov_beta, data_dir=tmp_path, now=t0) is False

    feed_file = tmp_path / "feed.json"
    feed_file.write_text(
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

    started_targets: list[str] = []

    def fake_start_kill_chain(*args: Any, **kwargs: Any) -> None:
        started_targets.append(kwargs.get("seed", ""))

    monkeypatch.setattr("forge.targets_import._start_kill_chain", fake_start_kill_chain)

    results = import_targets(
        feed_url=None,
        feed_file=feed_file,
        auth_header_env=None,
        roe_id="ROE-TEST-2026",
        start=True,
        dry_run=False,
        limit=5,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
        sleep_fn=lambda _: None,
    )

    assert len(results) == 2
    # First target skipped due to circuit breaker
    assert results[0].target_value == "target-alpha.corp-target.io"
    assert results[0].started is False
    assert results[0].start_skipped_reason == "provider_circuit_breaker_active"

    # Second target engaged successfully
    assert results[1].target_value == "target-beta.corp-target.io"
    assert results[1].started is True
    assert results[1].start_skipped_reason == ""
    assert "target-beta.corp-target.io" in started_targets
