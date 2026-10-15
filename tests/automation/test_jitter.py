"""tests/automation/test_jitter.py — Unit and wiring tests for autopilot jitter.

Tests:
(a) start_delay_seconds ranges: strict in [30,60], standard in [10,30], permissive in [2,10].
(b) unknown/missing strictness fails closed to strict range.
(c) retry_after_delay: int/float seconds, HTTP-date strings, None for absent/garbage, 0.0 for past, caps at 3600.
(d) burst_pause_seconds in [60,180].
(e) wiring: _start_kill_chain calls injected sleep_fn with delay in strict range when strictness is strict.
(f) wiring: import_targets applies burst pause after 5 successful starts.
"""

from __future__ import annotations

import json
import random
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from forge.autopilot.jitter import (
    MAX_RETRY_AFTER_SECONDS,
    burst_size,
    burst_pause_seconds,
    effective_start_delay,
    retry_after_delay,
    start_delay_seconds,
)
from forge.targets_import import _start_kill_chain, import_targets


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


class _FakeConfig:
    def __init__(self, data_dir: Path, roe_strictness: str | None = None) -> None:
        self.data_dir = data_dir
        self.operator = "tester"
        if roe_strictness is not None:
            self.roe_strictness = roe_strictness

    def engagement_db_path(self, engagement_id: str) -> Path:
        return self.data_dir / "engagements" / f"{engagement_id}.db"


# ---------------------------------------------------------------------------
# (a) start_delay_seconds ranges
# ---------------------------------------------------------------------------


def test_start_delay_seconds_ranges() -> None:
    """Test start_delay_seconds produces values in expected strictness ranges."""
    rng = random.Random(42)
    sample_count = 200

    # strict: [30.0, 60.0]
    strict_samples = [start_delay_seconds("strict", rng=rng) for _ in range(sample_count)]
    assert all(30.0 <= val <= 60.0 for val in strict_samples)
    assert min(strict_samples) >= 30.0
    assert max(strict_samples) <= 60.0
    assert len(set(strict_samples)) > 1

    # standard: [10.0, 30.0]
    standard_samples = [start_delay_seconds("standard", rng=rng) for _ in range(sample_count)]
    assert all(10.0 <= val <= 30.0 for val in standard_samples)
    assert min(standard_samples) >= 10.0
    assert max(standard_samples) <= 30.0
    assert len(set(standard_samples)) > 1

    # permissive: [2.0, 10.0]
    permissive_samples = [start_delay_seconds("permissive", rng=rng) for _ in range(sample_count)]
    assert all(2.0 <= val <= 10.0 for val in permissive_samples)
    assert min(permissive_samples) >= 2.0
    assert max(permissive_samples) <= 10.0
    assert len(set(permissive_samples)) > 1

    # Default RNG also produces valid values
    val = start_delay_seconds("strict")
    assert 30.0 <= val <= 60.0


# ---------------------------------------------------------------------------
# (b) unknown/missing strictness fails closed to strict
# ---------------------------------------------------------------------------


def test_start_delay_seconds_unknown_or_missing_fails_closed_to_strict() -> None:
    """Test missing or invalid strictness values fail closed to the strict range [30, 60]."""
    rng = random.Random(1337)
    sample_count = 100

    for invalid_val in [None, "", "   ", "unknown", "invalid", "loose", "default"]:
        samples = [start_delay_seconds(invalid_val, rng=rng) for _ in range(sample_count)]
        assert all(30.0 <= val <= 60.0 for val in samples), f"Failed for {invalid_val!r}"


# ---------------------------------------------------------------------------
# (c) retry_after_delay parsing, boundary capping, and fallback
# ---------------------------------------------------------------------------


def test_retry_after_delay_parses_seconds_and_caps() -> None:
    """Test numeric retry_after parsing, negative values, and max_delay capping."""
    # Direct numeric
    assert retry_after_delay(0) == 0.0
    assert retry_after_delay(30) == 30.0
    assert retry_after_delay(120) == 120.0
    assert retry_after_delay(45.5) == 45.5

    # String numeric
    assert retry_after_delay("0") == 0.0
    assert retry_after_delay("120") == 120.0
    assert retry_after_delay(" 120 ") == 120.0
    assert retry_after_delay("45.5") == 45.5

    # Non-positive values return 0.0
    assert retry_after_delay(-1) == 0.0
    assert retry_after_delay(-100.0) == 0.0
    assert retry_after_delay("-5") == 0.0
    assert retry_after_delay("-0.5") == 0.0

    # Capped at default MAX_RETRY_AFTER_SECONDS (3600.0)
    assert retry_after_delay(3600) == 3600.0
    assert retry_after_delay(7200) == MAX_RETRY_AFTER_SECONDS
    assert retry_after_delay("10000") == MAX_RETRY_AFTER_SECONDS

    # Custom max_delay
    assert retry_after_delay(500, max_delay=120.0) == 120.0


def test_retry_after_delay_parses_http_date_strings() -> None:
    """Test HTTP-date format parsing, past dates, and future capping."""
    now = datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc)

    # Future date: 120 seconds ahead
    future_date = "Thu, 15 Oct 2026 12:02:00 GMT"
    delay = retry_after_delay(future_date, now=now)
    assert delay == pytest.approx(120.0)

    # Past date returns 0.0
    past_date = "Thu, 15 Oct 2026 11:59:00 GMT"
    assert retry_after_delay(past_date, now=now) == 0.0

    # Exactly current date returns 0.0
    exact_date = "Thu, 15 Oct 2026 12:00:00 GMT"
    assert retry_after_delay(exact_date, now=now) == 0.0

    # Far future date capped at 3600.0
    far_future = "Thu, 15 Oct 2026 14:00:00 GMT"  # 7200s ahead
    assert retry_after_delay(far_future, now=now) == MAX_RETRY_AFTER_SECONDS

    # Passing now as a timestamp float
    now_ts = now.timestamp()
    assert retry_after_delay(future_date, now=now_ts) == pytest.approx(120.0)


def test_retry_after_delay_absent_and_garbage_returns_none() -> None:
    """Test None, empty string, and unparseable values return None."""
    assert retry_after_delay(None) is None
    assert retry_after_delay("") is None
    assert retry_after_delay("   ") is None
    assert retry_after_delay("invalid-date-or-number") is None
    assert retry_after_delay("2026-99-99T99:99:99") is None
    assert retry_after_delay(float("nan")) is None
    assert retry_after_delay(float("inf")) is None
    assert retry_after_delay(float("-inf")) is None


# ---------------------------------------------------------------------------
# (d) burst_pause_seconds range
# ---------------------------------------------------------------------------


def test_burst_pause_seconds_range() -> None:
    """Test strictness specific pause ranges."""
    rng = random.Random(9999)
    for level, bounds in (("strict", (300, 600)), ("standard", (120, 300)), ("permissive", (60, 180))):
        values = [burst_pause_seconds(level, rng=rng) for _ in range(40)]
        assert all(bounds[0] <= val <= bounds[1] for val in values)
        assert burst_size(level) == {"strict": 1, "standard": 2, "permissive": 4}[level]


def test_delay_overrides_and_environment_ranges(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("forge.autopilot.jitter.start_delay_seconds", lambda *_args, **_kwargs: 5.0)
    assert effective_start_delay("strict", retry_after_seconds=120) == 120
    monkeypatch.setattr("forge.autopilot.jitter.start_delay_seconds", lambda *_args, **_kwargs: 200.0)
    assert effective_start_delay("strict", retry_after_seconds=60) == 200
    monkeypatch.setattr("forge.autopilot.jitter.start_delay_seconds", lambda *_args, **_kwargs: 10.0)
    assert effective_start_delay("strict", roe_minimum_delay_seconds=300) == 300
    monkeypatch.setenv("FORGE_AUTOPILOT_START_DELAY_STANDARD_SECONDS", "41-42")
    assert 41 <= start_delay_seconds("standard") <= 42
    monkeypatch.setenv("FORGE_AUTOPILOT_BURST_SIZE_STANDARD", "3")
    monkeypatch.setenv("FORGE_AUTOPILOT_BURST_PAUSE_SECONDS_STANDARD", "71-72")
    assert burst_size("standard") == 3
    assert 71 <= burst_pause_seconds("standard") <= 72


# ---------------------------------------------------------------------------
# (e) wiring: _start_kill_chain calls injected sleep_fn
# ---------------------------------------------------------------------------


def test_start_kill_chain_calls_injected_sleep_fn_in_strict_range(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test _start_kill_chain invokes injected sleep_fn with start_delay_seconds."""
    sleep_calls: list[float] = []

    def fake_sleep(duration: float) -> None:
        sleep_calls.append(duration)

    def _fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr("forge.targets_import.run_contained_subprocess", _fake_run)

    manifest_file = tmp_path / "scope.json"
    manifest_file.write_text("{}", encoding="utf-8")
    engagement_db = tmp_path / "engagements" / "1.db"
    engagement_db.parent.mkdir(parents=True, exist_ok=True)

    _start_kill_chain(
        engagement_id=1,
        seed="target.example.org",
        target_type="domain",
        roe_id="ROE-TEST",
        scope_manifest=manifest_file,
        max_iter=3,
        max_runtime_minutes=60,
        parallel_fanout=4,
        engagement_db_path=engagement_db,
        roe_strictness="strict",
        sleep_fn=fake_sleep,
    )

    assert len(sleep_calls) == 1
    assert 30.0 <= sleep_calls[0] <= 60.0


def test_start_kill_chain_respects_different_strictness_levels(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test _start_kill_chain respects permissive, standard, and default strictness."""
    sleep_calls: list[float] = []

    def fake_sleep(duration: float) -> None:
        sleep_calls.append(duration)

    monkeypatch.setattr(
        "forge.targets_import.run_contained_subprocess",
        lambda command, **_: subprocess.CompletedProcess(command, 0, stdout="", stderr=""),
    )

    manifest_file = tmp_path / "scope.json"
    manifest_file.write_text("{}", encoding="utf-8")
    engagement_db = tmp_path / "engagements" / "1.db"
    engagement_db.parent.mkdir(parents=True, exist_ok=True)

    # Permissive strictness
    _start_kill_chain(
        engagement_id=1,
        seed="target1.example.org",
        target_type="domain",
        roe_id="ROE-TEST",
        scope_manifest=manifest_file,
        max_iter=3,
        max_runtime_minutes=60,
        parallel_fanout=4,
        engagement_db_path=engagement_db,
        roe_strictness="permissive",
        sleep_fn=fake_sleep,
    )
    assert len(sleep_calls) == 1
    assert 2.0 <= sleep_calls[0] <= 10.0

    # Standard strictness
    _start_kill_chain(
        engagement_id=1,
        seed="target2.example.org",
        target_type="domain",
        roe_id="ROE-TEST",
        scope_manifest=manifest_file,
        max_iter=3,
        max_runtime_minutes=60,
        parallel_fanout=4,
        engagement_db_path=engagement_db,
        roe_strictness="standard",
        sleep_fn=fake_sleep,
    )
    assert len(sleep_calls) == 2
    assert 10.0 <= sleep_calls[1] <= 30.0

    # None strictness (fails closed to strict)
    _start_kill_chain(
        engagement_id=1,
        seed="target3.example.org",
        target_type="domain",
        roe_id="ROE-TEST",
        scope_manifest=manifest_file,
        max_iter=3,
        max_runtime_minutes=60,
        parallel_fanout=4,
        engagement_db_path=engagement_db,
        roe_strictness=None,
        sleep_fn=fake_sleep,
    )
    assert len(sleep_calls) == 3
    assert 30.0 <= sleep_calls[2] <= 60.0


# ---------------------------------------------------------------------------
# (f) wiring: import_targets applies burst pause after 5 starts
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("strictness", "burst", "pause_low", "pause_high"),
    [("strict", 1, 300.0, 600.0), ("standard", 2, 120.0, 300.0), ("permissive", 4, 60.0, 180.0)],
)
def test_import_targets_applies_strictness_burst_pacing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    strictness: str, burst: int, pause_low: float, pause_high: float,
) -> None:
    feed_path = tmp_path / "feed.json"
    feed_path.write_text(json.dumps({"schema_version": "target-feed.v1", "generated_at": "2026-08-08T00:00:00Z", "items": [
        {"target_type": "domain", "target_value": f"target-{i}.acme-targets.net", "confidence": 0.9, "source_kind": "telemetry"} for i in range(burst * 2 + 1)
    ]}), encoding="utf-8")
    cfg = _FakeConfig(tmp_path / "data", strictness)
    sleep_calls: list[float] = []
    monkeypatch.setattr("forge.targets_import.run_contained_subprocess", lambda command, **_: subprocess.CompletedProcess(command, 0, stdout="", stderr=""))
    results = import_targets(feed_url=None, feed_file=feed_path, auth_header_env=None, roe_id="ROE-ACME-2026-08", start=True, dry_run=False, limit=None, max_iter=3, config=cfg, sleep_fn=sleep_calls.append)
    assert len(results) == burst * 2 + 1
    pauses = [value for value in sleep_calls if pause_low <= value <= pause_high]
    assert len(pauses) == 2
    assert len(sleep_calls) == len(results) + 2


def test_import_targets_burst_pause_counter_only_increments_on_successful_starts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test failed start attempts do not increment the burst counter toward the burst pause."""
    feed_path = tmp_path / "feed.json"
    feed_path.write_text(
        json.dumps(
            {
                "schema_version": "target-feed.v1",
                "generated_at": "2026-08-08T00:00:00Z",
                "items": [
                    {
                        "target_type": "domain",
                        "target_value": f"target-{i}.acme-targets.net",
                        "confidence": 0.9,
                        "source_kind": "telemetry",
                    }
                    for i in range(5)
                ],
            }
        ),
        encoding="utf-8",
    )
    cfg = _FakeConfig(tmp_path / "data")
    sleep_calls: list[float] = []

    def fake_sleep(duration: float) -> None:
        sleep_calls.append(duration)

    call_index = 0

    def _fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        nonlocal call_index
        call_index += 1
        if call_index == 1:
            # First item fails
            raise subprocess.CalledProcessError(2, command)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr("forge.targets_import.run_contained_subprocess", _fake_run)

    results = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=True,
        dry_run=False,
        limit=None,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
        sleep_fn=fake_sleep,
    )

    assert len(results) == 5
    assert results[0].started is False
    assert results[0].start_failed is True
    assert all(r.started is True for r in results[1:])

    # Three strict bursts complete before another item remains to start.
    assert len(sleep_calls) == 8
    assert sum(300.0 <= val <= 600.0 for val in sleep_calls) == 3


def test_import_targets_burst_counter_is_local_to_invocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test that the burst counter resets between import_targets invocations."""
    feed_path = tmp_path / "feed.json"
    feed_path.write_text(
        json.dumps(
            {
                "schema_version": "target-feed.v1",
                "generated_at": "2026-08-08T00:00:00Z",
                "items": [
                    {
                        "target_type": "domain",
                        "target_value": f"target-{i}.acme-targets.net",
                        "confidence": 0.9,
                        "source_kind": "telemetry",
                    }
                    for i in range(3)
                ],
            }
        ),
        encoding="utf-8",
    )
    cfg = _FakeConfig(tmp_path / "data")
    sleep_calls: list[float] = []

    def fake_sleep(duration: float) -> None:
        sleep_calls.append(duration)

    monkeypatch.setattr(
        "forge.targets_import.run_contained_subprocess",
        lambda command, **_: subprocess.CompletedProcess(command, 0, stdout="", stderr=""),
    )

    # First invocation: 3 starts
    results1 = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=True,
        dry_run=False,
        limit=None,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
        sleep_fn=fake_sleep,
    )
    assert len(results1) == 3
    assert len(sleep_calls) == 5  # 3 start delays and 2 strict burst pauses

    # Second invocation with a new feed of 3 items (different targets)
    feed_path2 = tmp_path / "feed2.json"
    feed_path2.write_text(
        json.dumps(
            {
                "schema_version": "target-feed.v1",
                "generated_at": "2026-08-08T00:00:00Z",
                "items": [
                    {
                        "target_type": "domain",
                        "target_value": f"new-target-{i}.acme-targets.net",
                        "confidence": 0.9,
                        "source_kind": "telemetry",
                    }
                    for i in range(3)
                ],
            }
        ),
        encoding="utf-8",
    )
    results2 = import_targets(
        feed_url=None,
        feed_file=feed_path2,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=True,
        dry_run=False,
        limit=None,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
        sleep_fn=fake_sleep,
    )
    assert len(results2) == 3
    # Each invocation resets its strictness bucket; each three-start run pauses twice.
    assert len(sleep_calls) == 10
    assert sum(300.0 <= val <= 600.0 for val in sleep_calls) == 4
