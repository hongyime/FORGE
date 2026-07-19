from __future__ import annotations

from forge import cli
from forge.cli import HtmlFetchSpec
from forge.cli import _run_html_fetch_batch


def test_run_html_fetch_batch_applies_operator_delay(monkeypatch) -> None:
    monkeypatch.setenv("FORGE_WEB_FETCH_REQUEST_DELAY_SECONDS", "0.25")
    sleeps: list[float] = []
    monkeypatch.setattr(cli.time, "sleep", lambda seconds: sleeps.append(float(seconds)))
    playwright_calls: list[str] = []
    fallback_calls: list[str] = []

    def _playwright(url: str, _timeout: float) -> str:
        playwright_calls.append(url)
        return "<html>rendered</html>" if url.endswith("/rendered") else ""

    def _fallback(url: str, _timeout: float) -> str:
        fallback_calls.append(url)
        return "<html>fallback</html>"

    results = _run_html_fetch_batch(
        [
            HtmlFetchSpec("https://acme.example/rendered", use_playwright=True),
            HtmlFetchSpec("https://acme.example/static", use_playwright=True),
            HtmlFetchSpec("https://acme.example/plain", use_playwright=False),
        ],
        _playwright,
        _fallback,
        max_workers=1,
    )

    assert sleeps == [0.25, 0.25, 0.25]
    assert playwright_calls == [
        "https://acme.example/rendered",
        "https://acme.example/static",
    ]
    assert fallback_calls == [
        "https://acme.example/static",
        "https://acme.example/plain",
    ]
    assert results == [
        "<html>rendered</html>",
        "<html>fallback</html>",
        "<html>fallback</html>",
    ]
