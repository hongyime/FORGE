from __future__ import annotations

import sqlite3

from forge.phase4 import supabase_scanner


def _online(monkeypatch) -> None:
    monkeypatch.setattr(supabase_scanner, "wait_for_internet", lambda: True)
    monkeypatch.setattr(
        supabase_scanner,
        "with_internet_retry",
        lambda func, *args, **kwargs: func(*args, **kwargs),
    )
    monkeypatch.delenv("FORGE_SUPABASE_ANON_KEY", raising=False)


def test_scan_supabase_denies_db_url_scope_path_drift_before_fetch(monkeypatch):
    _online(monkeypatch)
    monkeypatch.setattr(
        supabase_scanner,
        "_fetch_text",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("scope-denied target must not be fetched")
        ),
    )
    con = sqlite3.connect(":memory:")

    findings = supabase_scanner.scan_supabase(
        1001,
        ["https://allowed.example/app/"],
        con,
        target_url="https://allowed.example/admin",
    )

    assert findings == []


def test_scan_supabase_skips_out_of_prefix_js_before_fetch(monkeypatch):
    _online(monkeypatch)
    target_url = "https://allowed.example/app/index.html"
    calls: list[str] = []

    def _fetch(url: str, _cfg=None) -> str:
        calls.append(url)
        if url == target_url:
            return '<script src="/admin/app.js"></script>'
        raise AssertionError(f"out-of-prefix JS must not be fetched: {url}")

    monkeypatch.setattr(supabase_scanner, "_fetch_text", _fetch)
    con = sqlite3.connect(":memory:")

    findings = supabase_scanner.scan_supabase(
        1001,
        ["https://allowed.example/app/"],
        con,
        target_url=target_url,
    )

    assert findings == []
    assert calls == [target_url]
