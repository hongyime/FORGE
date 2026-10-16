"""Tests for shared connected-services HTTP backoff behavior."""

from __future__ import annotations

from typing import Any

from forge.autopilot.scheduler_db import scheduler_db_path
from forge.db.direct_connect import direct_connect
from forge.onboard.rate_limit import request_with_rate_limit_backoff


def _rate_limit_event_count(data_dir: Any, provider: str) -> int:
    con = direct_connect(scheduler_db_path(data_dir))
    try:
        return int(
            con.execute(
                "SELECT COUNT(*) FROM provider_events "
                "WHERE provider = ? AND event_type = 'rate_limit' AND phase = 'discovery'",
                (provider,),
            ).fetchone()[0]
        )
    finally:
        con.close()


def test_429_honors_retry_after_header() -> None:
    responses = iter(
        [
            {"status": 429, "headers": {"Retry-After": "7"}},
            {"status": 200, "headers": {}},
        ]
    )
    sleeps: list[float] = []

    result = request_with_rate_limit_backoff(
        lambda: next(responses),
        context="github:repos",
        sleep_fn=sleeps.append,
    )

    assert result.response["status"] == 200
    assert sleeps == [7.0]
    assert result.events[0]["wait_seconds"] == 7.0


def test_403_with_exhausted_quota_waits_until_reset() -> None:
    responses: list[dict[str, Any]] = [
        {
            "status": 403,
            "headers": {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1045"},
        },
        {"status": 200, "headers": {}},
    ]
    sleeps: list[float] = []

    result = request_with_rate_limit_backoff(
        lambda: responses.pop(0),
        context="github:quota",
        sleep_fn=sleeps.append,
        now_fn=lambda: 1000.0,
    )

    assert result.response["status"] == 200
    assert sleeps == [45.0]


def test_retry_count_is_bounded_and_records_one_breaker_event(tmp_path) -> None:
    calls = 0
    sleeps: list[float] = []

    def _limited() -> dict[str, Any]:
        nonlocal calls
        calls += 1
        return {"status": 429, "headers": {"Retry-After": "1"}}

    result = request_with_rate_limit_backoff(
        _limited,
        context="supabase:query",
        max_retries=2,
        max_total_wait_seconds=60,
        sleep_fn=sleeps.append,
        data_dir=tmp_path,
    )

    assert calls == 3
    assert sleeps == [1.0, 1.0]
    assert result.skipped is True
    assert result.skip_reason == "retry_limit"
    assert result.events[-1]["skipped"] is True
    assert _rate_limit_event_count(tmp_path, "supabase") == 1


def test_recovered_rate_limit_records_one_breaker_event(tmp_path) -> None:
    responses = iter(
        [
            {"status": 429, "headers": {"Retry-After": "1"}},
            {"status": 200, "headers": {}},
        ]
    )

    result = request_with_rate_limit_backoff(
        lambda: next(responses),
        context="github:repos",
        sleep_fn=lambda _seconds: None,
        data_dir=tmp_path,
    )

    assert result.response["status"] == 200
    assert len(result.events) == 1
    assert _rate_limit_event_count(tmp_path, "github") == 1


def test_non_rate_limit_response_records_no_breaker_event(tmp_path) -> None:
    result = request_with_rate_limit_backoff(
        lambda: {"status": 500, "headers": {}},
        context="github:repos",
        data_dir=tmp_path,
    )

    assert result.response["status"] == 500
    assert result.events == []
    assert _rate_limit_event_count(tmp_path, "github") == 0


def test_normal_success_response_records_no_rate_limit_event(tmp_path) -> None:
    result = request_with_rate_limit_backoff(
        lambda: {"status": 200, "headers": {}},
        context="github:repos",
        data_dir=tmp_path,
    )

    assert result.response["status"] == 200
    assert result.events == []
    assert _rate_limit_event_count(tmp_path, "github") == 0


def test_total_wait_cap_skips_without_exceeding_budget() -> None:
    calls = 0
    sleeps: list[float] = []

    def _limited() -> dict[str, Any]:
        nonlocal calls
        calls += 1
        return {"status": 429, "headers": {"Retry-After": "11"}}

    result = request_with_rate_limit_backoff(
        _limited,
        context="supabase:query",
        max_retries=5,
        max_total_wait_seconds=10,
        sleep_fn=sleeps.append,
    )

    assert calls == 1
    assert sleeps == []
    assert result.total_wait_seconds == 0
    assert result.skipped is True
    assert result.skip_reason == "total_wait_cap"
    assert result.events[-1]["reason"] == "total_wait_cap"
