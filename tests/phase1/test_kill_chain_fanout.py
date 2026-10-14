from __future__ import annotations

import logging
from urllib.error import HTTPError

import pytest

from forge.onboard.rate_limit import request_with_rate_limit_backoff
from forge.opsec.rate_limiter import AdaptiveRateLimiter
from forge.orchestration.artifacts import (
    ArtifactDownloadRequest,
    download_remote_artifact_request,
)
from forge.utils.kill_chain_fanout import (
    CLEAN_SUCCESSES_TO_INCREASE_CAP,
    AdaptiveFanoutCap,
    baseline_cap,
    cap_fanout,
    clear_active_fanout_controller,
)
from forge.utils.intel import http_pacing
from forge.utils.kill_chain_options import (
    DEFAULT_KILL_CHAIN_PARALLEL_FANOUT,
    MAX_KILL_CHAIN_PARALLEL_FANOUT,
    MIN_KILL_CHAIN_PARALLEL_FANOUT,
    normalize_kill_chain_parallel_fanout,
)
from forge.utils.kill_chain_runtime import normalize_kill_chain_runtime_options


@pytest.fixture(autouse=True)
def _clear_active_controller_between_tests():
    clear_active_fanout_controller()
    http_pacing._clear_rate_limit_cooldowns_for_tests()
    yield
    clear_active_fanout_controller()
    http_pacing._clear_rate_limit_cooldowns_for_tests()


def test_baseline_cap_uses_seed_type_surface_and_roe() -> None:
    assert baseline_cap(
        "example.com",
        target_type="domain",
        estimated_surface=100,
        roe_strictness="permissive",
    ) == MAX_KILL_CHAIN_PARALLEL_FANOUT
    assert baseline_cap(
        "operator@example.com",
        target_type="email",
        roe_strictness="standard",
    ) == 2
    assert baseline_cap(
        "203.0.113.7",
        target_type="ip",
        roe_strictness="strict",
    ) == 1


def test_adaptive_controller_increases_after_clean_streak() -> None:
    controller = AdaptiveFanoutCap(per_target_cap=8, backoff_events=1)
    assert controller.current_cap == 4

    for _ in range(CLEAN_SUCCESSES_TO_INCREASE_CAP):
        controller.record_success()

    assert controller.current_cap == 5
    assert controller.snapshot()["backoff_events"] == 1


def test_registered_runtime_controller_still_increases_after_clean_streak() -> None:
    options = _runtime_options(
        seed="example.com",
        target_type="domain",
        estimated_surface=100,
        roe_strictness="permissive",
        parallel_fanout=8,
    )

    for _ in range(CLEAN_SUCCESSES_TO_INCREASE_CAP):
        options.fanout_controller.record_success()

    assert options.fanout_controller.current_cap == 8


def test_http_pacing_429_and_applied_retry_wait_reach_runtime_controller(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    options = _runtime_options(
        seed="example.com",
        target_type="domain",
        estimated_surface=100,
        roe_strictness="permissive",
        parallel_fanout=8,
    )
    sleeps: list[float] = []
    monkeypatch.setattr(http_pacing, "web_fetch_rate_limit_retries", lambda: 1)
    monkeypatch.setattr(http_pacing, "web_fetch_request_delay_seconds", lambda: 0.0)
    monkeypatch.setattr(http_pacing, "web_fetch_retry_after_seconds", lambda _response: 5.0)
    monkeypatch.setattr(
        http_pacing.time,
        "sleep",
        lambda seconds: sleeps.append(float(seconds)),
    )

    class _Response:
        def __init__(self, status_code: int) -> None:
            self.status_code = status_code
            self.headers = {"Retry-After": "5"}

    class _Client:
        def __init__(self) -> None:
            self.responses = [_Response(429), _Response(200)]

        def get(self, _url: str, **_kwargs):
            return self.responses.pop(0)

    response = http_pacing.web_fetch_get(
        _Client(),
        "https://portal.example.test/index.html",
    )

    snapshot = options.fanout_controller.snapshot()
    assert response.status_code == 200
    assert sleeps == [5.0]
    assert snapshot["rate_limit_events"] == 1
    assert snapshot["backoff_events"] == 0
    assert snapshot["current_cap"] == 4
    assert AdaptiveFanoutCap(
        per_target_cap=8,
        rate_limit_events=snapshot["rate_limit_events"],
        backoff_events=snapshot["backoff_events"],
    ).current_cap == 4


def test_http_pacing_two_429_events_each_reduce_fanout_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    options = _runtime_options(
        seed="example.com",
        target_type="domain",
        estimated_surface=100,
        roe_strictness="permissive",
        parallel_fanout=8,
    )
    sleeps: list[float] = []
    monkeypatch.setattr(http_pacing, "web_fetch_rate_limit_retries", lambda: 2)
    monkeypatch.setattr(http_pacing, "web_fetch_request_delay_seconds", lambda: 0.0)
    monkeypatch.setattr(http_pacing, "web_fetch_retry_after_seconds", lambda _response: 5.0)
    monkeypatch.setattr(
        http_pacing.time,
        "sleep",
        lambda seconds: sleeps.append(float(seconds)),
    )

    class _Response:
        def __init__(self, status_code: int) -> None:
            self.status_code = status_code
            self.headers = {"Retry-After": "5"}

    class _Client:
        def __init__(self) -> None:
            self.responses = [_Response(429), _Response(429), _Response(200)]

        def get(self, _url: str, **_kwargs):
            return self.responses.pop(0)

    response = http_pacing.web_fetch_get(
        _Client(),
        "https://portal.example.test/index.html",
    )

    snapshot = options.fanout_controller.snapshot()
    assert response.status_code == 200
    assert sleeps == [5.0, 5.0]
    assert snapshot["rate_limit_events"] == 2
    assert snapshot["backoff_events"] == 0
    assert snapshot["current_cap"] == 2


def test_applied_rate_limiter_cooldown_reports_backoff_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    options = _runtime_options(
        seed="example.com",
        target_type="domain",
        estimated_surface=100,
        roe_strictness="permissive",
        parallel_fanout=8,
    )
    monkeypatch.setattr("forge.opsec.rate_limiter._interruptible_sleep_local", lambda _seconds: None)
    limiter = AdaptiveRateLimiter(base_delay=0.5, max_delay=30.0, jitter=0.0)
    limiter.record_failure("https://portal.example.test/", status_code=503)

    limiter.wait("https://portal.example.test/")

    snapshot = options.fanout_controller.snapshot()
    assert snapshot["rate_limit_events"] == 0
    assert snapshot["backoff_events"] == 1
    assert snapshot["current_cap"] == 4


def test_adaptive_rate_limiter_429_reports_rate_limit() -> None:
    options = _runtime_options(
        seed="example.com",
        target_type="domain",
        estimated_surface=100,
        roe_strictness="permissive",
        parallel_fanout=8,
    )
    limiter = AdaptiveRateLimiter(base_delay=0.5, max_delay=30.0, jitter=0.0)

    limiter.record_failure("https://portal.example.test/", status_code=429)

    snapshot = options.fanout_controller.snapshot()
    assert snapshot["rate_limit_events"] == 1
    assert snapshot["backoff_events"] == 0
    assert snapshot["current_cap"] == 4


def test_adaptive_rate_limiter_429_and_its_wait_halve_once_per_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    options = _runtime_options(
        seed="example.com",
        target_type="domain",
        estimated_surface=100,
        roe_strictness="permissive",
        parallel_fanout=8,
    )
    monkeypatch.setattr("forge.opsec.rate_limiter._interruptible_sleep_local", lambda _seconds: None)
    limiter = AdaptiveRateLimiter(base_delay=0.5, max_delay=30.0, jitter=0.0)

    for _ in range(2):
        limiter.record_failure("https://portal.example.test/", status_code=429)
        limiter.wait("https://portal.example.test/")

    snapshot = options.fanout_controller.snapshot()
    assert snapshot["rate_limit_events"] == 2
    assert snapshot["backoff_events"] == 0
    assert snapshot["current_cap"] == 2


def test_artifact_429_reports_rate_limit_and_applied_backoff(
    tmp_path,
) -> None:
    options = _runtime_options(
        seed="example.com",
        target_type="domain",
        estimated_surface=100,
        roe_strictness="permissive",
        parallel_fanout=8,
    )
    sleeps: list[float] = []

    def _raise_rate_limit(_request, timeout):
        del timeout
        raise HTTPError(
            "https://cdn.example.test/artifact",
            429,
            "rate limited",
            {"Retry-After": "3"},
            None,
        )

    result = download_remote_artifact_request(
        ArtifactDownloadRequest(
            artifact_id=55,
            source_url="https://cdn.example.test/artifact",
            artifact_type="document",
        ),
        cache_dir=tmp_path,
        select_remote_artifact_filename=lambda *_args, **_kwargs: "artifact.bin",
        classify_artifact=lambda _path: None,
        remote_artifact_max_bytes=1024,
        rate_limit_retries=lambda: 0,
        sleep_rate_limit_cooldown=http_pacing.sleep_rate_limit_cooldown,
        web_fetch_request_delay_seconds=lambda: 0.0,
        web_fetch_retry_after_seconds=lambda _exc: 3.0,
        record_rate_limit_cooldown=http_pacing.record_rate_limit_cooldown,
        sleep=lambda seconds: sleeps.append(float(seconds)),
        urlopen_fn=_raise_rate_limit,
    )

    snapshot = options.fanout_controller.snapshot()
    assert result.error is not None
    assert sleeps == [3.0]
    assert snapshot["rate_limit_events"] == 1
    assert snapshot["backoff_events"] == 0
    assert snapshot["current_cap"] == 4


def test_bounded_retry_429_and_its_applied_wait_halve_once() -> None:
    options = _runtime_options(
        seed="example.com",
        target_type="domain",
        estimated_surface=100,
        roe_strictness="permissive",
        parallel_fanout=8,
    )
    responses = [
        {"status": 429, "headers": {"Retry-After": "1"}},
        {"status": 200, "headers": {}},
    ]
    sleeps: list[float] = []

    result = request_with_rate_limit_backoff(
        lambda: responses.pop(0),
        context="test-rate-limit",
        sleep_fn=sleeps.append,
    )

    snapshot = options.fanout_controller.snapshot()
    assert result.response["status"] == 200
    assert sleeps == [1.0]
    assert snapshot["rate_limit_events"] == 1
    assert snapshot["backoff_events"] == 0
    assert snapshot["current_cap"] == 4


def test_bounded_retry_helper_only_marks_identified_rate_limit_403() -> None:
    generic_options = _runtime_options(
        seed="example.com",
        target_type="domain",
        estimated_surface=100,
        roe_strictness="permissive",
        parallel_fanout=8,
    )
    request_with_rate_limit_backoff(
        lambda: {"status": 403, "headers": {}},
        context="test-generic-forbidden",
        max_retries=0,
    )
    assert generic_options.fanout_controller.snapshot()["rate_limit_events"] == 0

    quota_options = _runtime_options(
        seed="example.com",
        target_type="domain",
        estimated_surface=100,
        roe_strictness="permissive",
        parallel_fanout=8,
    )
    request_with_rate_limit_backoff(
        lambda: {
            "status": 403,
            "headers": {"X-RateLimit-Remaining": "0"},
        },
        context="test-known-quota",
        max_retries=0,
    )
    assert quota_options.fanout_controller.snapshot()["rate_limit_events"] == 1


def test_adaptive_controller_reduces_for_distinct_pressure_signals_and_error() -> None:
    controller = AdaptiveFanoutCap(per_target_cap=8)

    assert controller.record_observation(429) == 4
    assert controller.record_observation(403, rate_limit_403=True) == 2
    # This backoff has no associated 429, so it remains a separate reduction.
    assert controller.record_backoff() == 1
    assert controller.record_error() == 1
    assert controller.snapshot()["rate_limit_events"] == 2
    assert controller.snapshot()["backoff_events"] == 1
    assert controller.snapshot()["error_events"] == 1


def test_controller_never_leaves_global_bounds() -> None:
    controller = AdaptiveFanoutCap(per_target_cap=100)
    assert controller.current_cap == MAX_KILL_CHAIN_PARALLEL_FANOUT

    for _ in range(20):
        controller.record_rate_limit()
    assert controller.current_cap == MIN_KILL_CHAIN_PARALLEL_FANOUT

    controller.record_success()
    assert MIN_KILL_CHAIN_PARALLEL_FANOUT <= controller.current_cap <= MAX_KILL_CHAIN_PARALLEL_FANOUT


def test_capped_request_returns_decision_and_logs(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger="forge.utils.kill_chain_fanout")

    decision = cap_fanout(
        8,
        seed="user@example.com",
        target_type="email",
        requested_by="test",
    )

    assert decision.requested == 8
    assert decision.effective == 2
    assert decision.cap == 2
    assert decision.reason == "per-target cap"
    assert decision.target_type == "email"
    assert decision.roe_strictness == "standard"
    assert decision.was_capped is True
    assert "effective=2" in caplog.text
    assert "reason=per-target cap" in caplog.text


def test_prior_distinct_rate_limit_and_standalone_backoff_lower_resume_cap() -> None:
    # These prior counts are two separate events: one 429 and one standalone backoff.
    decision = cap_fanout(
        8,
        seed="example.com",
        target_type="domain",
        estimated_surface=100,
        roe_strictness="permissive",
        rate_limit_events=1,
        backoff_events=1,
    )

    assert decision.cap == 2
    assert decision.effective == 2
    assert decision.reason == "reduced by prior rate-limit/backoff signals"


def test_normalizer_preserves_context_free_ceiling_and_floor() -> None:
    assert normalize_kill_chain_parallel_fanout("100") == MAX_KILL_CHAIN_PARALLEL_FANOUT
    assert normalize_kill_chain_parallel_fanout("0") == MIN_KILL_CHAIN_PARALLEL_FANOUT
    assert normalize_kill_chain_parallel_fanout(3, seed="user@example.com") == 2


def test_runtime_options_apply_target_cap_and_keep_requested_default() -> None:
    options = _runtime_options(
        seed="user@example.com",
        target_type="email",
        parallel_fanout=DEFAULT_KILL_CHAIN_PARALLEL_FANOUT,
    )
    assert options.parallel_fanout == 2
    assert options.parallel_workers == 2

    generic = _runtime_options()
    assert generic.parallel_fanout == DEFAULT_KILL_CHAIN_PARALLEL_FANOUT


def test_go_hard_requests_global_ceiling() -> None:
    options = _runtime_options(go_hard=True)

    assert options.parallel_fanout == MAX_KILL_CHAIN_PARALLEL_FANOUT
    assert options.parallel_workers == MAX_KILL_CHAIN_PARALLEL_FANOUT


def _runtime_options(**overrides: object):
    values: dict[str, object] = {
        "related_seed": None,
        "engagement": None,
        "resume": True,
        "max_iter": 7,
        "tor": False,
        "dry_run": True,
        "attack_mode": True,
        "roe_id": None,
        "scope_manifest": None,
        "skip_cloud": False,
        "skip_keyscan": False,
        "parallel_fanout": DEFAULT_KILL_CHAIN_PARALLEL_FANOUT,
        "report_provider": None,
        "report_max_loops": None,
        "auto_run_detected": True,
        "go_hard": False,
        "include_offensive_prereqs": False,
        "env": {},
    }
    values.update(overrides)
    return normalize_kill_chain_runtime_options(**values)
