from __future__ import annotations

import threading
import time

from typer.testing import CliRunner

from forge.cli import (
    HtmlFetchSpec,
    ModuleDispatchSpec,
    app,
    osint_emailrep,
    osint_google,
    osint_gravatar,
    _extract_html_surface_urls,
    _extract_passive_text_urls,
    _passive_archive_lookup_max_workers,
    _provider_limited_worker_count,
    _validation_max_workers,
    _run_callable_batch,
    _run_html_fetch_batch,
    _run_module_batch,
    _run_ptr_lookup_batch,
)


def test_run_module_batch_preserves_submission_order_under_parallel_completion() -> None:
    codes = {"first": 11, "second": 22, "third": 33}
    delays = {"first": 0.06, "second": 0.01, "third": 0.03}
    seen: list[str] = []

    def fake_run_module(cmd_argv, label, **kwargs) -> int:  # noqa: ANN001
        del cmd_argv, kwargs
        time.sleep(delays[label])
        seen.append(label)
        return codes[label]

    specs = [
        ModuleDispatchSpec(cmd_argv=["mod", "first"], label="first"),
        ModuleDispatchSpec(cmd_argv=["mod", "second"], label="second"),
        ModuleDispatchSpec(cmd_argv=["mod", "third"], label="third"),
    ]

    results = _run_module_batch(specs, fake_run_module, max_workers=3)

    assert results == [11, 22, 33]
    assert set(seen) == {"first", "second", "third"}


def test_run_module_batch_honors_parallel_worker_cap() -> None:
    active = 0
    peak = 0
    lock = threading.Lock()

    def fake_run_module(cmd_argv, label, **kwargs) -> int:  # noqa: ANN001
        del cmd_argv, label, kwargs
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.03)
            return 0
        finally:
            with lock:
                active -= 1

    specs = [ModuleDispatchSpec(cmd_argv=["mod", str(idx)], label=f"task-{idx}") for idx in range(5)]

    results = _run_module_batch(specs, fake_run_module, max_workers=2)

    assert results == [0, 0, 0, 0, 0]
    assert peak == 2


def test_run_module_batch_serializes_external_osint_providers_by_default(
    monkeypatch,
) -> None:
    monkeypatch.delenv("FORGE_SHODAN_MAX_WORKERS", raising=False)
    active = 0
    peak = 0
    lock = threading.Lock()

    def fake_run_module(cmd_argv, label, **kwargs) -> int:  # noqa: ANN001
        del cmd_argv, label, kwargs
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.02)
            return 0
        finally:
            with lock:
                active -= 1

    specs = [
        ModuleDispatchSpec(cmd_argv=["osint", "shodan", "--target", f"203.0.113.{idx}"], label=f"shodan-{idx}")
        for idx in range(4)
    ]

    assert _provider_limited_worker_count(specs, requested_workers=4) == 1
    results = _run_module_batch(specs, fake_run_module, max_workers=4)

    assert results == [0, 0, 0, 0]
    assert peak == 1
    assert all("--proxy" not in spec.cmd_argv for spec in specs)


def test_run_module_batch_allows_explicit_bounded_provider_worker_raise(
    monkeypatch,
) -> None:
    monkeypatch.setenv("FORGE_SHODAN_MAX_WORKERS", "2")
    active = 0
    peak = 0
    lock = threading.Lock()

    def fake_run_module(cmd_argv, label, **kwargs) -> int:  # noqa: ANN001
        del cmd_argv, label, kwargs
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.02)
            return 0
        finally:
            with lock:
                active -= 1

    specs = [
        ModuleDispatchSpec(cmd_argv=["osint", "shodan", "--target", f"203.0.113.{idx}"], label=f"shodan-{idx}")
        for idx in range(4)
    ]

    assert _provider_limited_worker_count(specs, requested_workers=4) == 2
    results = _run_module_batch(specs, fake_run_module, max_workers=4)

    assert results == [0, 0, 0, 0]
    assert peak == 2


def test_run_module_batch_staggers_same_provider_launches_when_configured(
    monkeypatch,
) -> None:
    monkeypatch.setenv("FORGE_SHODAN_MAX_WORKERS", "3")
    monkeypatch.setenv("FORGE_SHODAN_BATCH_STAGGER_SECONDS", "0.5")
    sleeps: list[float] = []
    monkeypatch.setattr("forge.cli.time.sleep", lambda seconds: sleeps.append(float(seconds)))

    def fake_run_module(cmd_argv, label, **kwargs) -> int:  # noqa: ANN001
        del cmd_argv, label, kwargs
        return 0

    specs = [
        ModuleDispatchSpec(cmd_argv=["osint", "shodan", "--target", f"203.0.113.{idx}"], label=f"shodan-{idx}")
        for idx in range(3)
    ]

    results = _run_module_batch(specs, fake_run_module, max_workers=3)

    assert results == [0, 0, 0]
    assert sorted(sleeps) == [0.5, 1.0]


def test_run_module_batch_staggers_mixed_providers_independently(
    monkeypatch,
) -> None:
    monkeypatch.setenv("FORGE_SHODAN_MAX_WORKERS", "2")
    monkeypatch.setenv("FORGE_URLSCAN_MAX_WORKERS", "2")
    monkeypatch.setenv("FORGE_PROVIDER_BATCH_STAGGER_SECONDS", "0.4")
    monkeypatch.setenv("FORGE_URLSCAN_BATCH_STAGGER_SECONDS", "0.1")
    sleeps: list[float] = []
    monkeypatch.setattr("forge.cli.time.sleep", lambda seconds: sleeps.append(float(seconds)))

    def fake_run_module(cmd_argv, label, **kwargs) -> int:  # noqa: ANN001
        del cmd_argv, label, kwargs
        return 0

    specs = [
        ModuleDispatchSpec(cmd_argv=["osint", "shodan", "--target", "alpha.example"], label="shodan-1"),
        ModuleDispatchSpec(cmd_argv=["osint", "urlscan", "--hostname", "alpha.example"], label="urlscan-1"),
        ModuleDispatchSpec(cmd_argv=["osint", "shodan", "--target", "beta.example"], label="shodan-2"),
        ModuleDispatchSpec(cmd_argv=["osint", "urlscan", "--hostname", "beta.example"], label="urlscan-2"),
    ]

    results = _run_module_batch(specs, fake_run_module, max_workers=4)

    assert results == [0, 0, 0, 0]
    assert sorted(sleeps) == [0.1, 0.4]


def test_run_module_batch_does_not_stagger_local_non_provider_modules(
    monkeypatch,
) -> None:
    monkeypatch.setenv("FORGE_PROVIDER_BATCH_STAGGER_SECONDS", "0.5")
    sleeps: list[float] = []
    monkeypatch.setattr("forge.cli.time.sleep", lambda seconds: sleeps.append(float(seconds)))

    def fake_run_module(cmd_argv, label, **kwargs) -> int:  # noqa: ANN001
        del cmd_argv, label, kwargs
        return 0

    specs = [
        ModuleDispatchSpec(cmd_argv=["report", "generate", "--engagement", str(idx)], label=f"report-{idx}")
        for idx in range(3)
    ]

    results = _run_module_batch(specs, fake_run_module, max_workers=3)

    assert results == [0, 0, 0]
    assert sleeps == []


def test_mixed_shodan_urlscan_batch_uses_strictest_provider_cap(monkeypatch) -> None:
    monkeypatch.setenv("FORGE_SHODAN_MAX_WORKERS", "2")
    monkeypatch.delenv("FORGE_URLSCAN_MAX_WORKERS", raising=False)
    specs = [
        ModuleDispatchSpec(cmd_argv=["osint", "shodan", "--target", "acme.example"], label="shodan"),
        ModuleDispatchSpec(cmd_argv=["osint", "urlscan", "--hostname", "acme.example"], label="urlscan"),
    ]

    assert _provider_limited_worker_count(specs, requested_workers=4) == 1


def test_passive_archive_lookup_worker_cap_uses_wayback_and_commoncrawl_env(monkeypatch) -> None:
    monkeypatch.setenv("FORGE_WAYBACK_MAX_WORKERS", "3")
    monkeypatch.setenv("FORGE_COMMONCRAWL_MAX_WORKERS", "2")

    assert _passive_archive_lookup_max_workers(4) == 2
    assert _passive_archive_lookup_max_workers(1) == 1


def test_run_module_batch_reports_batch_progress_metrics() -> None:
    progress_updates: list[tuple[str, dict[str, object]]] = []
    delays = {"first": 0.05, "second": 0.01, "third": 0.03}
    codes = {"first": 0, "second": 7, "third": 0}

    def fake_run_module(cmd_argv, label, **kwargs) -> int:  # noqa: ANN001
        del cmd_argv, kwargs
        time.sleep(delays[label])
        return codes[label]

    specs = [
        ModuleDispatchSpec(cmd_argv=["mod", "first"], label="first"),
        ModuleDispatchSpec(cmd_argv=["mod", "second"], label="second"),
        ModuleDispatchSpec(cmd_argv=["mod", "third"], label="third"),
    ]

    results = _run_module_batch(
        specs,
        fake_run_module,
        max_workers=2,
        progress_label="1.E email fan-out",
        progress_callback=lambda label, metrics: progress_updates.append((label, dict(metrics))),
    )

    assert results == [0, 7, 0]
    assert progress_updates
    assert progress_updates[0][0] == "1.E email fan-out"
    assert progress_updates[0][1]["running"] == 2
    assert progress_updates[0][1]["pending"] == 1
    assert progress_updates[0][1]["completed"] == 0
    assert any(
        isinstance(item[1].get("eta_seconds"), float) and float(item[1]["eta_seconds"]) >= 0.0
        for item in progress_updates[1:]
    )
    assert progress_updates[-1][1]["completed"] == 3
    assert progress_updates[-1][1]["failed"] == 1
    assert progress_updates[-1][1]["running"] == 0
    assert progress_updates[-1][1]["pending"] == 0


def test_run_callable_batch_preserves_submission_order_under_parallel_completion() -> None:
    delays = {1: 0.06, 2: 0.01, 3: 0.03}
    seen: list[int] = []

    def fake_worker(value: int) -> int:
        time.sleep(delays[value])
        seen.append(value)
        return value * 10

    results = _run_callable_batch([1, 2, 3], fake_worker, max_workers=3)

    assert results == [10, 20, 30]
    assert set(seen) == {1, 2, 3}


def test_run_callable_batch_honors_parallel_worker_cap() -> None:
    active = 0
    peak = 0
    lock = threading.Lock()

    def fake_worker(value: int) -> int:
        del value
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.03)
            return 7
        finally:
            with lock:
                active -= 1

    results = _run_callable_batch([0, 1, 2, 3, 4], fake_worker, max_workers=2)

    assert results == [7, 7, 7, 7, 7]
    assert peak == 2


def test_validation_worker_cap_defaults_serial_and_caps_high_values(monkeypatch) -> None:
    monkeypatch.delenv("FORGE_VALIDATION_MAX_WORKERS", raising=False)
    assert _validation_max_workers() == 1

    monkeypatch.setenv("FORGE_VALIDATION_MAX_WORKERS", "8")
    assert _validation_max_workers() == 4

    monkeypatch.setenv("FORGE_VALIDATION_MAX_WORKERS", "0")
    assert _validation_max_workers() == 1


def test_osint_gravatar_parallelizes_lookups_but_persists_in_input_order(
    monkeypatch,
    tmp_path,
) -> None:
    import forge.utils.intel.gravatar_lookup as gravatar_lookup

    class _DummyCfg:
        def engagement_db_path(self, engagement_id: str):  # noqa: ANN001
            return tmp_path / f"{engagement_id}.db"

    monkeypatch.setenv("FORGE_IDENTITY_LOOKUP_MAX_WORKERS", "4")
    monkeypatch.setattr("forge.cli.ForgeConfig.load", staticmethod(lambda: _DummyCfg()))

    delays = {
        "alpha@acme.example": 0.05,
        "bravo@acme.example": 0.01,
        "charlie@acme.example": 0.04,
        "delta@acme.example": 0.02,
        "echo@acme.example": 0.03,
    }
    active = 0
    peak = 0
    lock = threading.Lock()
    persist_order: list[str] = []

    def fake_lookup(email: str, eng_id: int, db_path) -> dict:  # noqa: ANN001
        del eng_id, db_path
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(delays[email])
            return {
                "found": True,
                "profile": {
                    "display_name": email,
                    "preferred_username": email.split("@", 1)[0],
                    "accounts": [],
                },
            }
        finally:
            with lock:
                active -= 1

    def fake_persist(email: str, eng_id: int, db_path, profile: dict) -> int:  # noqa: ANN001
        del eng_id, db_path, profile
        persist_order.append(email)
        return 1

    monkeypatch.setattr(gravatar_lookup, "lookup_gravatar", fake_lookup)
    monkeypatch.setattr(gravatar_lookup, "persist_gravatar_findings", fake_persist)

    emails = ",".join(delays.keys())
    osint_gravatar(engagement="1001", emails=emails)

    assert persist_order == list(delays.keys())
    assert peak == 4


def test_osint_google_parallelizes_lookups_but_persists_in_input_order(
    monkeypatch,
    tmp_path,
) -> None:
    import forge.utils.intel.google_account as google_account

    class _DummyCfg:
        def engagement_db_path(self, engagement_id: str):  # noqa: ANN001
            return tmp_path / f"{engagement_id}.db"

    monkeypatch.setenv("FORGE_IDENTITY_LOOKUP_MAX_WORKERS", "2")
    monkeypatch.setattr("forge.cli.ForgeConfig.load", staticmethod(lambda: _DummyCfg()))

    delays = {
        "alpha@acme.example": 0.05,
        "bravo@acme.example": 0.01,
        "charlie@acme.example": 0.04,
        "delta@acme.example": 0.02,
    }
    active = 0
    peak = 0
    lock = threading.Lock()
    persist_order: list[str] = []

    def fake_lookup(email: str, eng_id: int, db_path) -> dict:  # noqa: ANN001
        del eng_id, db_path
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(delays[email])
            return {
                "found": True,
                "profile": {
                    "gaia_id": f"gaia-{email}",
                    "apps": ["Maps"],
                },
            }
        finally:
            with lock:
                active -= 1

    def fake_persist(email: str, eng_id: int, db_path, profile: dict) -> int:  # noqa: ANN001
        del eng_id, db_path, profile
        persist_order.append(email)
        return 2

    monkeypatch.setattr(google_account, "_ghunt_creds_available", lambda: True)
    monkeypatch.setattr(google_account, "lookup_google_account", fake_lookup)
    monkeypatch.setattr(google_account, "persist_google_findings", fake_persist)

    emails = ",".join(delays.keys())
    osint_google(engagement="1001", emails=emails)

    assert persist_order == list(delays.keys())
    assert peak == 2


def test_kill_chain_help_exposes_auto_run_detected_option() -> None:
    runner = CliRunner()

    result = runner.invoke(app, ["kill-chain", "--help"])

    assert result.exit_code == 0
    assert "--auto-run-detected" in result.stdout
    assert "--roe-id" in result.stdout


def test_osint_emailrep_forwards_batch_arguments_to_reputation_lookup(
    monkeypatch,
    tmp_path,
) -> None:
    captured: dict[str, object] = {}

    class _DummyCfg:
        operator = "tester"

        def engagement_db_path(self, engagement_id: str):  # noqa: ANN001
            return tmp_path / f"{engagement_id}.db"

    def fake_run_reputation_lookup(**kwargs):  # noqa: ANN003
        captured.update(kwargs)
        return None

    monkeypatch.setattr("forge.cli.ForgeConfig.load", staticmethod(lambda: _DummyCfg()))
    monkeypatch.setattr(
        "forge.utils.intel.reputation_lookup.run_reputation_lookup",
        fake_run_reputation_lookup,
    )

    osint_emailrep(
        engagement="1001",
        emails="alpha@acme.example, bravo@acme.example",
        api_key="rep-key",
        cache_ttl=12,
        dry_run=True,
    )

    assert captured["db_path"] == tmp_path / "1001.db"
    assert captured["engagement_id"] == 1001
    assert captured["api_key"] == "rep-key"
    assert captured["emails"] == ["alpha@acme.example", "bravo@acme.example"]
    assert captured["cache_ttl"] == 12
    assert captured["dry_run"] is True
    assert captured["operator"] == "tester"


def test_run_html_fetch_batch_preserves_submission_order_and_falls_back() -> None:
    play_delays = {
        "https://alpha.example": 0.05,
        "http://alpha.example": 0.01,
        "https://beta.example": 0.03,
    }
    play_seen: list[str] = []
    http_seen: list[str] = []

    def fake_playwright(url: str, timeout: float) -> str:
        del timeout
        time.sleep(play_delays[url])
        play_seen.append(url)
        if url == "http://alpha.example":
            return ""
        return f"PLAY:{url}"

    def fake_http(url: str, timeout: float) -> str:
        del timeout
        http_seen.append(url)
        return f"HTTP:{url}"

    specs = [
        HtmlFetchSpec(url="https://alpha.example"),
        HtmlFetchSpec(url="http://alpha.example"),
        HtmlFetchSpec(url="https://beta.example"),
    ]

    results = _run_html_fetch_batch(specs, fake_playwright, fake_http, max_workers=3)

    assert results == [
        "PLAY:https://alpha.example",
        "HTTP:http://alpha.example",
        "PLAY:https://beta.example",
    ]
    assert set(play_seen) == {
        "https://alpha.example",
        "http://alpha.example",
        "https://beta.example",
    }
    assert http_seen == ["http://alpha.example"]


def test_run_html_fetch_batch_skips_playwright_when_disabled() -> None:
    play_calls: list[str] = []
    http_calls: list[str] = []

    def fake_playwright(url: str, timeout: float) -> str:
        del timeout
        play_calls.append(url)
        return f"PLAY:{url}"

    def fake_http(url: str, timeout: float) -> str:
        del timeout
        http_calls.append(url)
        return f"HTTP:{url}"

    specs = [
        HtmlFetchSpec(url="https://alpha.example", use_playwright=False),
        HtmlFetchSpec(url="http://alpha.example", use_playwright=False),
    ]

    results = _run_html_fetch_batch(specs, fake_playwright, fake_http, max_workers=2)

    assert results == [
        "HTTP:https://alpha.example",
        "HTTP:http://alpha.example",
    ]
    assert play_calls == []
    assert http_calls == ["https://alpha.example", "http://alpha.example"]


def test_run_html_fetch_batch_honors_web_fetch_host_cooldown(monkeypatch) -> None:
    from forge.utils.intel import http_pacing

    sleeps: list[float] = []
    http_pacing._clear_rate_limit_cooldowns_for_tests()
    monkeypatch.delenv("FORGE_WEB_FETCH_REQUEST_DELAY_SECONDS", raising=False)
    monkeypatch.setattr(http_pacing.time, "sleep", lambda seconds: sleeps.append(float(seconds)))
    http_pacing.record_rate_limit_cooldown(
        "web_fetch",
        "https://alpha.example/throttled",
        2.0,
    )
    play_calls: list[str] = []
    http_calls: list[str] = []

    def fake_playwright(url: str, timeout: float) -> str:
        del timeout
        play_calls.append(url)
        return f"PLAY:{url}"

    def fake_http(url: str, timeout: float) -> str:
        del timeout
        http_calls.append(url)
        return f"HTTP:{url}"

    results = _run_html_fetch_batch(
        [HtmlFetchSpec(url="https://alpha.example/next")],
        fake_playwright,
        fake_http,
        max_workers=1,
    )

    assert results == ["PLAY:https://alpha.example/next"]
    assert play_calls == ["https://alpha.example/next"]
    assert http_calls == []
    assert sleeps and sleeps[0] > 0
    http_pacing._clear_rate_limit_cooldowns_for_tests()


def test_run_ptr_lookup_batch_preserves_submission_order_and_handles_failures() -> None:
    delays = {
        "203.0.113.10": 0.05,
        "203.0.113.11": 0.01,
        "2001:db8::10": 0.03,
    }
    seen: list[str] = []

    def fake_gethostbyaddr(ip: str) -> tuple[str, object, object]:
        time.sleep(delays[ip])
        seen.append(ip)
        if ip == "203.0.113.11":
            raise OSError(ip)
        return f"host-{ip.replace(':', '-')}.example", [], [ip]

    results = _run_ptr_lookup_batch(
        ["203.0.113.10", "203.0.113.11", "2001:db8::10"],
        fake_gethostbyaddr,
        max_workers=3,
    )

    assert results == [
        ("203.0.113.10", "host-203.0.113.10.example"),
        ("203.0.113.11", ""),
        ("2001:db8::10", "host-2001-db8--10.example"),
    ]
    assert set(seen) == {"203.0.113.10", "203.0.113.11", "2001:db8::10"}


def test_run_ptr_lookup_batch_honors_parallel_worker_cap() -> None:
    active = 0
    peak = 0
    lock = threading.Lock()

    def fake_gethostbyaddr(ip: str) -> tuple[str, object, object]:
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.03)
            return f"{ip}.example", [], [ip]
        finally:
            with lock:
                active -= 1

    results = _run_ptr_lookup_batch(
        ["203.0.113.10", "203.0.113.11", "203.0.113.12", "203.0.113.13"],
        fake_gethostbyaddr,
        max_workers=2,
    )

    assert results == [
        ("203.0.113.10", "203.0.113.10.example"),
        ("203.0.113.11", "203.0.113.11.example"),
        ("203.0.113.12", "203.0.113.12.example"),
        ("203.0.113.13", "203.0.113.13.example"),
    ]
    assert peak == 2


def test_extract_passive_text_urls_expands_robots_directives_and_dedupes_literals() -> None:
    payload = """
    User-agent: *
    Disallow: /admin
    Allow: /reports
    Sitemap: https://portal.acme.example/sitemap.xml
    https://portal.acme.example/reports
    https://portal.acme.example/reports,
    """

    extracted = _extract_passive_text_urls(
        payload,
        base_url="https://acme.example/robots.txt",
    )

    assert extracted == [
        "https://portal.acme.example/sitemap.xml",
        "https://portal.acme.example/reports",
        "https://acme.example/admin",
        "https://acme.example/reports",
    ]


def test_extract_html_surface_urls_resolves_relative_links_and_dedupes_literals() -> None:
    payload = """
    <html><body>
    <a href="/downloads/client.apk?download=1">APK</a>
    <form formaction="/submit-contact"></form>
    <img src="//cdn.acme.example/assets/logo.png" />
    <img data-src="/lazy/profile-card.html" data-url="javascript:void(0)" />
    <object data="/docs/public-overview.pdf"></object>
    <meta http-equiv="refresh" content="0; url=/redirected/onboarding">
    <img srcset="/assets/logo-small.png 1x, /assets/logo-large.png 2x, data:image/png;base64,aaa 3x" />
    <source srcset="//cdn.acme.example/hero.avif 1x, https://static.acme.example/hero@2x.avif 2x">
    <div style="background-image: url('/assets/bg.svg')"></div>
    <style>@import "/styles/print.css"; .hero { background: url(../static/hero.css); } .bad { background: url(data:image/png;base64,aaa); }</style>
    <script>
    fetch('/api/status');
    import('/assets/app.chunk.js');
    importScripts('/sw-cache.js');
    navigator.sendBeacon('/rum');
    new Worker('/workers/app.js');
    new EventSource('/events');
    axios.get('/api/users');
    fetch('data:text/plain,ignore');
    fetch('javascript:alert(1)');
    </script>
    https://portal.acme.example/login
    https://portal.acme.example/login,
    <a href="javascript:void(0)">Ignore</a>
    </body></html>
    """

    extracted = _extract_html_surface_urls(
        payload,
        base_url="https://acme.example/start",
    )

    assert extracted == [
        "https://static.acme.example/hero@2x.avif",
        "https://portal.acme.example/login",
        "https://acme.example/downloads/client.apk?download=1",
        "https://acme.example/submit-contact",
        "https://cdn.acme.example/assets/logo.png",
        "https://acme.example/lazy/profile-card.html",
        "https://acme.example/docs/public-overview.pdf",
        "https://acme.example/redirected/onboarding",
        "https://acme.example/assets/logo-small.png",
        "https://acme.example/assets/logo-large.png",
        "https://cdn.acme.example/hero.avif",
        "https://acme.example/assets/bg.svg",
        "https://acme.example/static/hero.css",
        "https://acme.example/styles/print.css",
        "https://acme.example/api/status",
        "https://acme.example/assets/app.chunk.js",
        "https://acme.example/sw-cache.js",
        "https://acme.example/rum",
        "https://acme.example/workers/app.js",
        "https://acme.example/events",
        "https://acme.example/api/users",
    ]
