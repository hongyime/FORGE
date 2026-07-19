from __future__ import annotations

import threading
import time
from pathlib import Path

from forge.utils.intel import linkedin_scraper
from forge.utils.intel.linkedin_scraper import enumerate_linkedin_employees


def test_enumerate_linkedin_employees_parallelizes_dork_queries_but_preserves_query_order(
    monkeypatch,
    tmp_path: Path,
) -> None:
    queries_seen: list[str] = []
    active = 0
    peak = 0
    lock = threading.Lock()

    responses = {
        'site:linkedin.com/in "acme.example"': (
            0.05,
            "https://www.linkedin.com/in/alice-example",
        ),
        'site:linkedin.com/in "@acme.example"': (
            0.01,
            "https://www.linkedin.com/in/bob-sample",
        ),
        'site:linkedin.com/company "acme.example"': (
            0.03,
            "https://www.linkedin.com/company/acme-corp",
        ),
    }

    def fake_run_dork(query: str, proxy=None, timeout: float = 15.0) -> str:  # noqa: ANN001
        del proxy, timeout
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            delay, body = responses[query]
            time.sleep(delay)
            queries_seen.append(query)
            return body
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(
        "forge.utils.intel.linkedin_scraper._run_dork",
        fake_run_dork,
    )

    result = enumerate_linkedin_employees(
        domain="acme.example",
        engagement_id=1001,
        db_path=tmp_path / "engagement.db",
        max_dorks=3,
        max_concurrency=2,
    )

    assert set(queries_seen) == set(responses)
    assert peak == 2
    assert result["linkedin_slugs"] == ["alice-example", "bob-sample"]
    assert result["company_slugs"] == ["acme-corp"]
    assert result["raw_hits"] == 2
    assert result["candidate_emails"][:4] == [
        "alice.example@acme.example",
        "aliceexample@acme.example",
        "alice_example@acme.example",
        "alice-example@acme.example",
    ]


def test_enumerate_linkedin_employees_honors_concurrency_cap_of_one(
    monkeypatch,
    tmp_path: Path,
) -> None:
    active = 0
    peak = 0
    lock = threading.Lock()

    def fake_run_dork(query: str, proxy=None, timeout: float = 15.0) -> str:  # noqa: ANN001
        del query, proxy, timeout
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.02)
            return "https://www.linkedin.com/in/alice-example"
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(
        "forge.utils.intel.linkedin_scraper._run_dork",
        fake_run_dork,
    )

    result = enumerate_linkedin_employees(
        domain="acme.example",
        engagement_id=1001,
        db_path=tmp_path / "engagement.db",
        max_dorks=3,
        max_concurrency=1,
    )

    assert peak == 1
    assert result["linkedin_slugs"] == ["alice-example"]


def test_enumerate_linkedin_employees_defaults_to_sequential_public_dorks(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.delenv("FORGE_LINKEDIN_DORK_MAX_CONCURRENCY", raising=False)
    active = 0
    peak = 0
    lock = threading.Lock()

    def fake_run_dork(query: str, proxy=None, timeout: float = 15.0) -> str:  # noqa: ANN001
        del query, proxy, timeout
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.01)
            return "https://www.linkedin.com/in/alice-example"
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(
        "forge.utils.intel.linkedin_scraper._run_dork",
        fake_run_dork,
    )

    result = enumerate_linkedin_employees(
        domain="acme.example",
        engagement_id=1001,
        db_path=tmp_path / "engagement.db",
        max_dorks=3,
    )

    assert peak == 1
    assert result["linkedin_slugs"] == ["alice-example"]


def test_linkedin_default_concurrency_can_be_raised_by_env(monkeypatch) -> None:
    monkeypatch.setenv("FORGE_LINKEDIN_DORK_MAX_CONCURRENCY", "2")

    assert linkedin_scraper._linkedin_dork_max_concurrency_default() == 2


def test_run_dork_applies_search_dork_delay(monkeypatch) -> None:
    monkeypatch.setenv("FORGE_SEARCH_DORK_REQUEST_DELAY_SECONDS", "0.4")
    sleeps: list[float] = []
    monkeypatch.setattr(linkedin_scraper.time, "sleep", lambda seconds: sleeps.append(float(seconds)))
    monkeypatch.setattr(linkedin_scraper, "_ddg_html_search", lambda *_args, **_kwargs: "x" * 600)
    monkeypatch.setattr(
        linkedin_scraper,
        "_bing_html_search",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("fallback not expected")),
    )

    result = linkedin_scraper._run_dork("site:linkedin.com/in acme")

    assert result == "x" * 600
    assert sleeps == [0.4]
