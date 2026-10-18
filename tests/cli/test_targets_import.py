from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
import typer
from typer.testing import CliRunner

from forge.config import normalize_roe_strictness, resolve_roe_strictness
from forge.db.session import get_engagement_db
import forge.targets_resume_candidates as resume_candidates
from forge.targets_import import (
    TargetImportResult,
    _coerce_feed_item,
    _canonical_domain_value,
    _normalize_target_value,
    _start_kill_chain,
    import_targets,
    load_target_feed,
)
from forge.targets_import_cli import register_target_import_commands
from forge.targets_resume_candidates import (
    _run_resume_child,
    backfill_target_resume_scope_manifests,
    collect_target_resume_candidates,
    collect_target_resume_lock_status,
    collect_target_resume_plan,
    execute_target_resume_plan,
    redact_target_resume_candidate_payload,
)


@pytest.fixture(autouse=True)
def _noop_targets_import_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("forge.targets_import._DEFAULT_SLEEP", lambda _: None)


class _FakeConfig:
    def __init__(self, data_dir: Path, roe_strictness: str | None = None) -> None:
        self.data_dir = data_dir
        self.operator = "tester"
        if roe_strictness is not None:
            self.roe_strictness = roe_strictness

    def engagement_db_path(self, engagement_id: str) -> Path:
        return self.data_dir / "engagements" / f"{engagement_id}.db"


def _write_feed(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": "target-feed.v1",
                "generated_at": "2026-08-08T00:00:00Z",
                "items": [
                    {
                        "target_type": "domain",
                        "target_value": "Corp-Target.IO",
                        "source_kind": "telemetry",
                        "confidence": 0.9,
                        "first_seen_at": "2026-08-07T00:00:00Z",
                        "provenance": "network_domain",
                        "token": "must-not-persist",
                    },
                    {
                        "target_type": "domain",
                        "target_value": "corp-target.io",
                        "source_kind": "duplicate",
                        "confidence": 0.1,
                        "first_seen_at": "2026-08-07T00:00:00Z",
                        "provenance": "duplicate",
                    },
                    {
                        "target_type": "url",
                        "target_value": "HTTPS://App.Corp-Target.IO/Login?secret=drop",
                        "source_kind": "webhook",
                        "confidence": 0.8,
                        "first_seen_at": "2026-08-07T00:00:00Z",
                        "provenance": "webhook_url",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )


def _write_dispatch_feed(path: Path, count: int = 3) -> list[str]:
    values = [f"target-{index}.corp-target.io" for index in range(count)]
    path.write_text(json.dumps({
        "schema_version": "target-feed.v1",
        "generated_at": "2026-10-15T00:00:00Z",
        "items": [
            {
                "target_type": "domain",
                "target_value": value,
                "source_kind": "dispatcher_test",
                "confidence": 0.9,
                "first_seen_at": "2026-10-14T00:00:00Z",
                "provenance": "dispatcher_test_fixture",
            }
            for value in values
        ],
    }), encoding="utf-8")
    return values


def _dispatch_result(kwargs: dict[str, object]) -> TargetImportResult:
    item = kwargs["item"]
    return TargetImportResult(
        engagement_id=None, target_type=item.target_type, target_value=item.canonical_value,
        target_key=item.target_key, scope_manifest=None, created=False, started=True,
        dry_run=False,
    )


def _dispatch_import(feed_path: Path, cfg: _FakeConfig, *, max_active_targets: int = 2) -> list[TargetImportResult]:
    return import_targets(
        feed_url=None, feed_file=feed_path, auth_header_env=None, roe_id="ROE-TEST",
        start=True, dry_run=False, limit=None, max_iter=1, config=cfg, max_active_targets=max_active_targets,
    )


def test_import_dispatcher_runs_two_targets_concurrently(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    feed = tmp_path / "feed.json"
    _write_dispatch_feed(feed, 2)
    barrier = threading.Barrier(2, timeout=3)
    cfg = _FakeConfig(tmp_path / "data", roe_strictness="standard")

    def run(**kwargs: object) -> TargetImportResult:
        barrier.wait()
        return _dispatch_result(kwargs)

    monkeypatch.setattr("forge.targets_import._external_target_engagement_index", lambda _: {})
    monkeypatch.setattr("forge.targets_import._run_one_import_target", run)
    results = _dispatch_import(feed, cfg)
    assert len(results) == 2
    assert all(result.started for result in results)


def test_import_dispatcher_respects_active_target_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    feed = tmp_path / "feed.json"
    _write_dispatch_feed(feed, 4)
    lock = threading.Lock()
    active = peak = 0

    def run(**kwargs: object) -> TargetImportResult:
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        time.sleep(0.03)
        with lock:
            active -= 1
        return _dispatch_result(kwargs)

    monkeypatch.setattr("forge.targets_import._external_target_engagement_index", lambda _: {})
    monkeypatch.setattr("forge.targets_import._run_one_import_target", run)
    _dispatch_import(
        feed,
        _FakeConfig(tmp_path / "data", roe_strictness="standard"),
        max_active_targets=2,
    )
    assert peak == 2


def test_import_dispatcher_serializes_with_single_slot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    feed = tmp_path / "feed.json"
    values = _write_dispatch_feed(feed, 2)
    first_finished = threading.Event()
    cfg = _FakeConfig(tmp_path / "data", roe_strictness="strict")

    def run(**kwargs: object) -> TargetImportResult:
        item = kwargs["item"]
        if item.canonical_value == values[0]:
            first_finished.set()
        else:
            assert first_finished.wait(timeout=3), "second target started before the first finished"
        return _dispatch_result(kwargs)

    monkeypatch.setattr("forge.targets_import._external_target_engagement_index", lambda _: {})
    monkeypatch.setattr("forge.targets_import._run_one_import_target", run)
    results = _dispatch_import(feed, cfg, max_active_targets=1)
    assert len(results) == 2


def test_import_dispatcher_strict_burst_is_serial_and_pauses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed = tmp_path / "feed.json"
    values = _write_dispatch_feed(feed, 3)
    lock = threading.Lock()
    active = peak = 0
    starts: list[str] = []
    pause_count = 0
    events: list[tuple[str, str | None]] = []

    def sleep(_: float) -> None:
        nonlocal pause_count
        with lock:
            pause_count += 1
            events.append(("pause", None))

    def run(**kwargs: object) -> TargetImportResult:
        nonlocal active, peak
        item = kwargs["item"]
        with lock:
            starts.append(item.canonical_value)
            events.append(("start", item.canonical_value))
            active += 1
            peak = max(peak, active)
        time.sleep(0.02)
        with lock:
            active -= 1
        return _dispatch_result(kwargs)

    monkeypatch.setattr("forge.targets_import._DEFAULT_SLEEP", sleep)
    monkeypatch.setattr("forge.targets_import._external_target_engagement_index", lambda _: {})
    monkeypatch.setattr("forge.targets_import._run_one_import_target", run)
    results = _dispatch_import(
        feed, _FakeConfig(tmp_path / "data", roe_strictness="strict"),
        max_active_targets=2,
    )

    assert all(result.started for result in results)
    assert peak == 1
    assert starts == values
    assert pause_count == 2
    assert events == [
        ("start", values[0]), ("pause", None),
        ("start", values[1]), ("pause", None),
        ("start", values[2]),
    ]


def test_import_dispatcher_releases_scheduler_leases(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from forge.autopilot.scheduler_db import scheduler_db_path

    feed = tmp_path / "feed.json"
    _write_dispatch_feed(feed, 2)
    cfg = _FakeConfig(tmp_path / "data")
    cfg.autopilot_global_slots = 2
    cfg.autopilot_max_active_targets = 2
    monkeypatch.setattr("forge.targets_import._external_target_engagement_index", lambda _: {})
    monkeypatch.setattr("forge.targets_import._create_or_reuse_engagement", lambda *_: (1, False))
    monkeypatch.setattr("forge.targets_import._ensure_target_import_monitoring", lambda **_: None)
    monkeypatch.setattr("forge.targets_import._write_scope_manifest", lambda *_: tmp_path / "scope.json")
    monkeypatch.setattr("forge.targets_import._has_kill_chain_run", lambda *_: False)
    monkeypatch.setattr("forge.targets_import._start_kill_chain", lambda **_: None)

    results = _dispatch_import(feed, cfg, max_active_targets=2)

    assert len(results) == 2
    with sqlite3.connect(scheduler_db_path(cfg.data_dir)) as con:
        active_leases = con.execute("SELECT lease_id FROM leases WHERE status = 'active'").fetchall()
    assert active_leases == []


def test_import_dispatcher_preserves_input_result_order(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    feed = tmp_path / "feed.json"
    values = _write_dispatch_feed(feed, 3)

    def run(**kwargs: object) -> TargetImportResult:
        item = kwargs["item"]
        if item.canonical_value == values[0]:
            time.sleep(0.05)
        return _dispatch_result(kwargs)

    monkeypatch.setattr("forge.targets_import._external_target_engagement_index", lambda _: {})
    monkeypatch.setattr("forge.targets_import._run_one_import_target", run)
    results = _dispatch_import(feed, _FakeConfig(tmp_path / "data", roe_strictness="standard"))
    assert [result.target_value for result in results] == values


def test_import_dispatcher_kill_switch_stops_admission(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    feed = tmp_path / "feed.json"
    _write_dispatch_feed(feed, 2)
    loaded_items = load_target_feed(
        feed_url=None, feed_file=feed, auth_header_env=None, limit=None,
    )
    assert len(loaded_items) == 2
    cfg = _FakeConfig(tmp_path / "data", roe_strictness="strict")
    launched: list[str] = []
    monkeypatch.setattr("forge.targets_import._external_target_engagement_index", lambda _: {})
    monkeypatch.setattr("forge.targets_import.is_kill_switch_active", lambda **_: True)
    monkeypatch.setattr("forge.targets_import._run_one_import_target", lambda **kw: launched.append(kw["item"].canonical_value))
    assert _dispatch_import(feed, cfg) == []
    assert launched == []


def _write_multi_seed_feed(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": "target-feed.v1",
                "generated_at": "2026-08-08T00:00:00Z",
                "items": [
                    {"target_type": "email", "target_value": "Security@Corp-Target.IO"},
                    {"target_type": "telephone", "target_value": "00 1 555 123 4567"},
                    {"target_type": "handle", "target_value": "Forge_Handle"},
                    {"target_type": "organization", "target_value": "Example Holdings Inc"},
                    {"target_type": "person", "target_value": "Jane Doe"},
                    {"target_type": "ip", "target_value": "203.0.113.7"},
                    {"target_type": "ipv6", "target_value": "2001:db8::1"},
                    {"target_type": "cloud_ref", "target_value": "s3://Acme-Artifacts/mobile"},
                    {"target_type": "cloud_ref", "target_value": "aws_s3:acme-artifacts"},
                    {
                        "target_type": "auto",
                        "target_value": "https://files.corp-target.io/releases/app.apk?token=drop",
                    },
                    {
                        "target_type": "url",
                        "target_value": "https://demo.supabase.co:443/rest/v1?apikey=drop",
                    },
                    {"target_type": "password", "target_value": "must-not-import"},
                ],
            }
        ),
        encoding="utf-8",
    )


def _write_unpack_error_feed(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": "target-feed.v1",
                "generated_at": "2026-08-08T00:00:00Z",
                "items": [
                    {"target_type": "auto", "target_value": "malformed delegated target"},
                    {"target_type": "domain", "target_value": "corp-target.io"},
                ],
            }
        ),
        encoding="utf-8",
    )


def test_load_target_feed_drops_placeholder_hosts_and_subdomains(
    tmp_path: Path,
) -> None:
    feed_path = tmp_path / "placeholder-feed.json"
    feed_path.write_text(
        json.dumps(
            {
                "schema_version": "target-feed.v1",
                "generated_at": "2026-10-13T00:00:00Z",
                "items": [
                    {"target_type": "domain", "target_value": "company.com"},
                    {"target_type": "domain", "target_value": "api.example.org"},
                    {"target_type": "url", "target_value": "https://ui.test.com/login"},
                    {"target_type": "domain", "target_value": "api.localhost"},
                    {"target_type": "domain", "target_value": "portal.corp-target.io"},
                ],
            }
        ),
        encoding="utf-8",
    )

    items = load_target_feed(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        limit=None,
    )

    assert [item.canonical_value for item in items] == ["portal.corp-target.io"]


def test_load_target_feed_coerces_only_top_ranked_unique_items(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import forge.targets_import as targets_import

    feed_path = tmp_path / "large-feed.json"
    feed_path.write_text(json.dumps({
        "schema_version": "target-feed.v1",
        "items": [
            {"target_type": "domain", "target_value": f"host-{index}.corp-target.io",
             "priority": index, "source_count": 1}
            for index in range(250)
        ],
    }), encoding="utf-8")
    coerced: list[str] = []
    original = targets_import._coerce_feed_item

    def spy(raw: object):
        coerced.append(str(raw.get("target_value")))  # type: ignore[union-attr]
        return original(raw)

    monkeypatch.setattr(targets_import, "_coerce_feed_item", spy)
    items = load_target_feed(
        feed_url=None, feed_file=feed_path, auth_header_env=None, limit=10
    )

    assert len(coerced) == 10
    assert len(items) == 10
    assert items[0].canonical_value == "host-100.corp-target.io"


def test_load_target_feed_stops_coercing_at_time_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    import forge.targets_import as targets_import

    feed_path = tmp_path / "budget-feed.json"
    feed_path.write_text(json.dumps({
        "schema_version": "target-feed.v1",
        "items": [
            {"target_type": "domain", "target_value": f"host-{index}.corp-target.io"}
            for index in range(3)
        ],
    }), encoding="utf-8")
    ticks = iter((0.0, 0.0, 121.0))
    monkeypatch.setattr(targets_import.time, "monotonic", lambda: next(ticks))

    items = load_target_feed(
        feed_url=None, feed_file=feed_path, auth_header_env=None, limit=3
    )

    assert len(items) == 1
    assert "exceeded 120 second budget" in caplog.text


def test_import_targets_keeps_unknown_mega_domain_signals_eligible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    feed_path = tmp_path / "unknown-signals.json"
    feed_path.write_text(json.dumps({
        "schema_version": "target-feed.v1",
        "items": [{"target_type": "domain", "target_value": "ordinary.corp-target.io"}],
    }), encoding="utf-8")

    def no_network(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Phase 5 must use cached signals and never fetch them")

    monkeypatch.setattr("forge.onboard.mega_domain.mega_domain_signals", no_network)
    results = import_targets(
        feed_url=None, feed_file=feed_path, auth_header_env=None, roe_id=None,
        start=False, dry_run=True, limit=1, max_iter=1,
        config=_FakeConfig(tmp_path / "data"),
    )

    assert len(results) == 1
    assert results[0].scan_eligible is True
    assert results[0].scan_eligibility_reason == "eligible"


def test_load_target_feed_rejects_code_identifiers_as_domains(
    tmp_path: Path,
) -> None:
    feed_path = tmp_path / "code-identifiers.json"
    feed_path.write_text(
        json.dumps(
            {
                "schema_version": "target-feed.v1",
                "items": [
                    {"target_type": "domain", "target_value": "os.environ"},
                    {"target_type": "subdomain", "target_value": "process.env"},
                    {"target_type": "auto", "target_value": "os.path"},
                    {"target_type": "auto", "target_value": "sys.argv"},
                    {
                        "target_type": "domain",
                        "target_value": "process.env.NODE_ENV",
                    },
                    {"target_type": "domain", "target_value": "bareidentifier"},
                    {"target_type": "domain", "target_value": ".leading.io"},
                    {"target_type": "domain", "target_value": "trailing.io."},
                    {"target_type": "domain", "target_value": "bad-.io"},
                    {"target_type": "domain", "target_value": "bad..io"},
                    {"target_type": "domain", "target_value": "bad_name.io"},
                    {"target_type": "domain", "target_value": "bad host.io"},
                    {"target_type": "domain", "target_value": " spaced.io "},
                    {"target_type": "domain", "target_value": "corp-target.io"},
                    {
                        "target_type": "subdomain",
                        "target_value": "sub.example.co.uk",
                    },
                    {"target_type": "auto", "target_value": "api.example.io"},
                ],
            }
        ),
        encoding="utf-8",
    )

    items = load_target_feed(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        limit=None,
    )

    assert {item.canonical_value for item in items} == {
        "corp-target.io",
        "sub.example.co.uk",
        "api.example.io",
    }


def test_domain_canonicalizer_rejects_common_filename_extensions() -> None:
    filename_values = ("image.png", "worker.py", "config.yml")
    for value in filename_values:
        assert _canonical_domain_value(value) == ""
        for target_type in ("domain", "subdomain", "auto"):
            assert _normalize_target_value(target_type, value) is None


def test_domain_canonicalizer_keeps_common_and_colliding_real_tlds() -> None:
    accepted_values = (
        "example.com",
        "www.example.org",
        "api.example.io",
        "example.dev",
        "shop.example.co.uk",
        "example.app",
        "edge.api.example.com",
        # Preserve real TLDs that also commonly appear as file suffixes.
        "example.md",
        "example.rs",
        "example.sh",
        "example.ai",
        "example.so",
        "example.zip",
        "example.xn--p1ai",
    )
    for value in accepted_values:
        assert _canonical_domain_value(value) == value
        assert _normalize_target_value("domain", value) == ("domain", value)


def test_feed_normalizer_requires_delegated_hostname_suffixes() -> None:
    for value in ("package.json", "module.os.environ"):
        assert _coerce_feed_item({"target_type": "domain", "target_value": value}) is None

    assert _coerce_feed_item(
        {"target_type": "domain", "target_value": "valid.corp-target.io"}
    ) is not None
    assert _coerce_feed_item(
        {"target_type": "ipv4", "target_value": "8.8.8.8"}
    ) is not None
    assert _coerce_feed_item(
        {"target_type": "url", "target_value": "https://example.invalid/path"}
    ) is None
    assert _coerce_feed_item(
        {"target_type": "email", "target_value": "user@example.invalid"}
    ) is None
    assert _coerce_feed_item(
        {"target_type": "email", "target_value": "user@corp-target.io"}
    ) is not None


def test_load_target_feed_drops_filename_values_for_domain_subdomain_and_auto(
    tmp_path: Path,
) -> None:
    feed_path = tmp_path / "filename-values.json"
    values = ("image.png", "worker.py", "config.yml")
    feed_path.write_text(
        json.dumps(
            {
                "schema_version": "target-feed.v1",
                "items": [
                    {"target_type": target_type, "target_value": value}
                    for value in values
                    for target_type in ("domain", "subdomain", "auto")
                ]
                + [
                    {"target_type": "domain", "target_value": "corp-target.io"},
                    {"target_type": "subdomain", "target_value": "api.example.io"},
                    {"target_type": "auto", "target_value": "shop.example.co.uk"},
                ],
            }
        ),
        encoding="utf-8",
    )

    items = load_target_feed(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        limit=None,
    )

    assert {item.canonical_value for item in items} == {
        "corp-target.io",
        "api.example.io",
        "shop.example.co.uk",
    }


def test_import_start_never_launches_denylisted_placeholder_targets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "placeholder-launch-feed.json"
    feed_path.write_text(
        json.dumps(
            {
                "schema_version": "target-feed.v1",
                "items": [
                    {"target_type": "domain", "target_value": "company.com"},
                    {"target_type": "domain", "target_value": "api.company.com"},
                    {
                        "target_type": "url",
                        "target_value": "https://ui.test.com/login",
                    },
                    {"target_type": "email", "target_value": "ops@company.com"},
                    {
                        "target_type": "domain",
                        "target_value": "portal.corp-target.io",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    cfg = _FakeConfig(tmp_path / "data")
    calls: list[list[str]] = []

    def _fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr("forge.targets_import.run_contained_subprocess", _fake_run)

    results = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-TEST",
        start=True,
        dry_run=False,
        limit=None,
        max_iter=3,
        start_limit=20,
        config=cfg,  # type: ignore[arg-type]
        sleep_fn=lambda _: None,
    )

    assert [result.target_value for result in results] == ["portal.corp-target.io"]
    assert [result.started for result in results] == [True]
    assert len(calls) == 1
    assert calls[0][4] == "portal.corp-target.io"
    assert not any(
        placeholder in calls[0]
        for placeholder in ("company.com", "api.company.com", "ui.test.com")
    )


def _write_candidate_run(
    db_path: Path,
    *,
    engagement_id: int,
    status: str,
    error: str = "",
    metadata: dict[str, object] | None = None,
    seed_value: str = "corp-target.io",
    updated_at: str = "2026-08-08T00:00:00Z",
) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = get_engagement_db(db_path)
    try:
        conn.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator, metadata_json)
            VALUES (?, ?, '{}', 'ACTIVE', 'tester', '{}')
            """,
            (engagement_id, f"engagement {engagement_id}"),
        )
        conn.execute(
            """
            INSERT INTO engagement_runs (
                engagement_id, run_kind, status, seed_value, seed_type,
                max_iterations, current_iteration, resume_enabled, dry_run,
                attack_mode, error, metadata_json, started_at, completed_at, updated_at
            )
            VALUES (?, 'kill_chain', ?, ?, 'domain', 3, 3, 1, 0, 0, ?, ?, ?, ?, ?)
            """,
            (
                engagement_id,
                status,
                seed_value,
                error,
                json.dumps(metadata or {}),
                "2026-08-08T00:00:00Z",
                "2026-08-08T00:30:00Z",
                updated_at,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def test_import_feed_file_creates_deduped_engagements_and_manifests(tmp_path: Path) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")

    results = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=False,
        dry_run=False,
        limit=None,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
    )

    assert len(results) == 2
    assert [result.created for result in results] == [True, True]
    domain_result = results[0]
    assert domain_result.engagement_id == 1
    assert domain_result.target_value == "corp-target.io"
    assert domain_result.scope_manifest is not None
    manifest = json.loads(domain_result.scope_manifest.read_text(encoding="utf-8"))
    assert manifest["roe_id"] == "ROE-ACME-2026-08"
    assert manifest["domains"] == ["corp-target.io"]
    assert manifest["urls"] == []
    assert manifest["policy"] == {
        "destructive_actions_allowed": True,
        "post_exploitation_allowed": True,
    }

    db_path = cfg.engagement_db_path("1")
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute("SELECT scope_json, metadata_json FROM engagements").fetchone()
    finally:
        conn.close()
    metadata = json.loads(row[1])
    assert metadata["external_feed"] == "target-feed.v1"
    assert metadata["external_target_key"] == domain_result.target_key
    assert metadata["source_kind"] == "telemetry"
    assert metadata["source_groups"] == ["telemetry"]
    assert metadata["source_count"] == 1
    assert metadata["scan_priority"] == 60
    assert metadata["provenance_summary"] == "network_domain"
    persisted = json.dumps(metadata)
    assert "must-not-persist" not in persisted
    assert json.loads(row[0]) == {"domains": ["corp-target.io"], "urls": []}
    monitoring_row = sqlite3.connect(db_path)
    try:
        policy = monitoring_row.execute(
            """
            SELECT name, enabled, schedule_interval_minutes, mode,
                   last_snapshot_id, metadata_json
            FROM monitoring_policies
            """
        ).fetchone()
        snapshot_count = monitoring_row.execute(
            "SELECT COUNT(*) FROM monitoring_snapshots"
        ).fetchone()[0]
        trend_count = monitoring_row.execute(
            "SELECT COUNT(*) FROM monitoring_trend_points"
        ).fetchone()[0]
    finally:
        monitoring_row.close()
    assert policy[0] == "Target import seed exposure"
    assert policy[1] == 1
    assert policy[2] == 60
    assert policy[3] == "passive"
    assert policy[4] == 1
    policy_metadata = json.loads(policy[5])
    assert policy_metadata["refresh"] == {"type": "seed_exposure"}
    assert policy_metadata["source"] == "target_import"
    assert snapshot_count == 1
    assert trend_count == 1

    control_db = cfg.data_dir / "control.db"
    assert control_db.is_file()
    control_con = sqlite3.connect(control_db)
    try:
        index_rows = control_con.execute(
            """
            SELECT engagement_id, workspace_id, slug, summary_json
            FROM engagement_index
            ORDER BY engagement_id
            """
        ).fetchall()
    finally:
        control_con.close()
    assert [row[0] for row in index_rows] == [1, 2]
    assert index_rows[0][1] == "default"
    assert index_rows[0][2].startswith("engagement-1-external-target-")
    summary = json.loads(index_rows[0][3])
    assert summary["id"] == 1
    assert summary["workspace_id"] == "default"
    assert summary["seeds"] == ["corp-target.io"]
    assert "must-not-persist" not in json.dumps(summary)


def test_import_targets_prioritizes_multi_source_feed_items_before_limit(
    tmp_path: Path,
) -> None:
    feed_path = tmp_path / "feed.json"
    feed_path.write_text(
        json.dumps(
            {
                "schema_version": "target-feed.v1",
                "items": [
                    {
                        "target_type": "domain",
                        "target_value": "single.corp-target.io",
                        "source_kind": "db",
                        "source_group": "db",
                        "source_groups": ["db"],
                        "source_count": 1,
                        "priority": 60,
                    },
                    {
                        "target_type": "domain",
                        "target_value": "shared.corp-target.io",
                        "source_kind": "reports",
                        "source_group": "report_family:shared",
                        "source_groups": ["db", "report_family:shared"],
                        "source_count": 2,
                        "priority": 90,
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    cfg = _FakeConfig(tmp_path / "data")

    results = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id=None,
        start=False,
        dry_run=True,
        limit=1,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
    )

    assert [item.target_value for item in results] == ["shared.corp-target.io"]
    assert results[0].source_count == 2
    assert results[0].priority == 90
    assert results[0].scan_eligible is True


def test_import_targets_dry_run_start_does_not_require_roe(
    tmp_path: Path,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")

    results = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id=None,
        start=True,
        dry_run=True,
        limit=1,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
    )

    assert len(results) == 1
    assert results[0].dry_run is True
    assert results[0].started is False
    assert results[0].start_skipped_reason == "dry_run"
    assert not (cfg.data_dir / "engagements").exists()


def test_import_feed_skips_allocator_id_with_existing_engagement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")

    existing_db = cfg.engagement_db_path("1")
    existing_db.parent.mkdir(parents=True, exist_ok=True)
    conn = get_engagement_db(existing_db)
    try:
        conn.execute(
            """
            INSERT INTO engagements (id, name, scope_json, status, operator, metadata_json)
            VALUES (1, 'existing', '{}', 'ACTIVE', 'tester', '{}')
            """
        )
        conn.commit()
    finally:
        conn.close()

    allocated = iter([1, 2, 3])
    monkeypatch.setattr(
        "forge.targets_import.allocate_engagement_id",
        lambda _data_dir: next(allocated),
    )

    results = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=False,
        dry_run=False,
        limit=1,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
    )

    assert len(results) == 1
    assert results[0].engagement_id == 2
    assert cfg.engagement_db_path("2").exists()


def test_import_feed_accepts_canonical_multi_seed_targets(tmp_path: Path) -> None:
    feed_path = tmp_path / "multi-seed-feed.json"
    _write_multi_seed_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")

    results = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=False,
        dry_run=False,
        limit=None,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
    )

    assert [(result.target_type, result.target_value) for result in results] == [
        ("email", "security@corp-target.io"),
        ("phone", "+15551234567"),
        ("username", "@forge_handle"),
        ("company", "Example Holdings Inc"),
        ("name", "Jane Doe"),
        ("cloud_ref", "aws_s3:acme-artifacts"),
        ("apk_url", "https://files.corp-target.io/releases/app.apk"),
        ("cloud_ref", "https://demo.supabase.co:443/rest/v1"),
        ("ipv4", "203.0.113.7"),
        ("ipv6", "2001:db8::1"),
    ]
    assert len(results) == 10
    assert all(result.scope_manifest is not None for result in results)

    email_manifest = json.loads(results[0].scope_manifest.read_text(encoding="utf-8"))
    assert email_manifest["authorized_seeds"] == ["security@corp-target.io"]
    assert email_manifest["domains"] == []
    assert email_manifest["ip_ranges"] == []
    assert email_manifest["urls"] == []

    by_target = {result.target_value: result for result in results}
    ipv4_manifest = json.loads(
        by_target["203.0.113.7"].scope_manifest.read_text(encoding="utf-8")
    )
    assert ipv4_manifest["authorized_seeds"] == ["203.0.113.7"]
    assert ipv4_manifest["ip_ranges"] == ["203.0.113.7/32"]

    apk_manifest = json.loads(
        by_target["https://files.corp-target.io/releases/app.apk"].scope_manifest.read_text(
            encoding="utf-8"
        )
    )
    assert apk_manifest["domains"] == ["files.corp-target.io"]
    assert apk_manifest["urls"] == ["https://files.corp-target.io/releases/app.apk"]
    assert apk_manifest["authorized_seeds"] == ["https://files.corp-target.io/releases/app.apk"]

    cloud_url_manifest = json.loads(
        by_target["https://demo.supabase.co:443/rest/v1"].scope_manifest.read_text(
            encoding="utf-8"
        )
    )
    assert cloud_url_manifest["domains"] == ["demo.supabase.co"]
    assert cloud_url_manifest["urls"] == ["https://demo.supabase.co:443/rest/v1"]
    assert cloud_url_manifest["metadata"]["target_type"] == "cloud_ref"

    db_path = cfg.engagement_db_path("1")
    conn = sqlite3.connect(db_path)
    try:
        seed_row = conn.execute(
            "SELECT seed_value, seed_type FROM engagement_seeds"
        ).fetchone()
        scope_row = conn.execute("SELECT scope_json FROM engagements").fetchone()
    finally:
        conn.close()
    assert seed_row == ("security@corp-target.io", "email")
    assert json.loads(scope_row[0]) == {
        "authorized_seeds": ["security@corp-target.io"],
        "domains": [],
        "urls": [],
    }
    assert "must-not-import" not in json.dumps([result.target_value for result in results])


def test_reimport_reuses_existing_engagement_ids(tmp_path: Path) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")

    first = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id=None,
        start=False,
        dry_run=False,
        limit=1,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
    )
    db_path = cfg.engagement_db_path("1")
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            UPDATE monitoring_policies
            SET next_run_at='2026-08-08T00:00:00Z'
            """
        )
        conn.commit()
    finally:
        conn.close()
    second = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id=None,
        start=False,
        dry_run=False,
        limit=1,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
    )

    assert first[0].engagement_id == second[0].engagement_id == 1
    assert first[0].created is True
    assert second[0].created is False
    conn = sqlite3.connect(db_path)
    try:
        policy_rows = conn.execute(
            "SELECT next_run_at FROM monitoring_policies"
        ).fetchall()
        snapshot_count = conn.execute("SELECT COUNT(*) FROM monitoring_snapshots").fetchone()[0]
    finally:
        conn.close()
    assert policy_rows == [("2026-08-08T00:00:00Z",)]
    assert snapshot_count == 1


def test_resume_candidates_reports_latest_failed_runs_without_sensitive_metadata(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    scope_path = data_dir / "target_imports" / "scope_1_demo.json"
    scope_path.parent.mkdir(parents=True, exist_ok=True)
    scope_path.write_text("{}", encoding="utf-8")
    _write_candidate_run(
        data_dir / "engagements" / "1.db",
        engagement_id=1,
        status="failed",
        error="max iterations exhausted with pending recursive work: 12",
        metadata={
            "roe_id": "ROE-ACME-2026",
            "scope_manifest": str(scope_path),
            "pending_counts": {"artifact_queue": 7, "cloud_assets": 5},
            "api_token": "must-not-appear",
        },
    )
    _write_candidate_run(
        data_dir / "engagements" / "2.db",
        engagement_id=2,
        status="cancelled",
        error="watchdog timeout after 45 minutes",
        metadata={"password": "must-not-appear"},
    )
    _write_candidate_run(
        data_dir / "engagements" / "3.db",
        engagement_id=3,
        status="completed",
        error="",
        metadata={},
    )

    payload = collect_target_resume_candidates(data_dir=data_dir)

    assert payload["schema_version"] == "forge.targets.resume_candidates.v1"
    assert payload["execution_policy"] == (
        "read_only_resume_candidate_inventory_no_commands_executed"
    )
    assert payload["total_count"] == 2
    assert payload["selected_count"] == 2
    assert payload["omitted_count"] == 0
    assert payload["candidate_count"] == 2
    assert payload["resume_ready_count"] == 1
    assert payload["resume_blocker_counts"] == {
        "roe_id_missing": 1,
        "scope_manifest_missing": 1,
    }
    assert payload["reason_counts"] == {
        "pending_recursive_work": 1,
        "watchdog_timeout": 1,
    }
    first = payload["items"][0]
    assert first["engagement_id"] == 1
    assert first["scope_manifest_exists"] is True
    assert first["resume_ready"] is True
    assert first["resume_blockers"] == []
    assert first["resume_command"] == [
        "forge",
        "kill-chain",
        "corp-target.io",
        "--engagement",
        "1",
        "--roe-id",
        "ROE-ACME-2026",
        "--scope-manifest",
        str(scope_path),
        "--resume",
        "--max-iter",
        "3",
    ]
    assert first["pending_work_total"] == 12
    second = payload["items"][1]
    assert second["resume_ready"] is False
    assert second["resume_blockers"] == ["roe_id_missing", "scope_manifest_missing"]
    assert second["resume_command"] == []
    serialized = json.dumps(payload)
    assert "must-not-appear" not in serialized


def test_resume_candidates_redaction_hides_local_paths(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    scope_path = tmp_path / "scope.json"
    report_path = tmp_path / "reports" / "engagement_1_report.md"
    scope_path.write_text("{}", encoding="utf-8")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("# report", encoding="utf-8")
    _write_candidate_run(
        data_dir / "engagements" / "1.db",
        engagement_id=1,
        status="failed",
        error="max iterations exhausted with pending recursive work: 1",
        metadata={
            "roe_id": "ROE-ACME-2026",
            "scope_manifest": str(scope_path),
            "report_path": str(report_path),
        },
    )

    payload = collect_target_resume_candidates(data_dir=data_dir)
    redacted = redact_target_resume_candidate_payload(payload)

    serialized = json.dumps(redacted)
    assert redacted["data_dir"] == "<redacted>"
    assert redacted["path_redaction"] == "local_paths_redacted"
    item = redacted["items"][0]
    assert item["db_path"] == ""
    assert item["db_ref"] == "1.db"
    assert item["scope_manifest"] == ""
    assert item["scope_manifest_ref"] == "scope.json"
    assert item["report_path"] == ""
    assert item["report_path_ref"] == "engagement_1_report.md"
    assert "<scope-manifest:scope.json>" in item["resume_command"]
    assert str(data_dir) not in serialized
    assert str(scope_path) not in serialized
    assert str(report_path) not in serialized


def test_resume_candidates_reason_filter_and_limit(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    _write_candidate_run(
        data_dir / "engagements" / "1.db",
        engagement_id=1,
        status="failed",
        error="abandoned before explicit completion",
    )
    _write_candidate_run(
        data_dir / "engagements" / "2.db",
        engagement_id=2,
        status="failed",
        error="stale-run recovery marked this run failed",
    )

    payload = collect_target_resume_candidates(
        data_dir=data_dir,
        reason="stale_run_recovery",
        limit=1,
    )

    assert payload["candidate_count"] == 1
    assert payload["total_count"] == 1
    assert payload["selected_count"] == 1
    assert payload["omitted_count"] == 0
    assert payload["items"][0]["engagement_id"] == 2
    assert payload["items"][0]["reason"] == "stale_run_recovery"


def test_resume_candidates_reports_total_and_omitted_counts_when_limited(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    for engagement_id in (1, 2, 3):
        _write_candidate_run(
            data_dir / "engagements" / f"{engagement_id}.db",
            engagement_id=engagement_id,
            status="failed",
            error="abandoned before explicit completion",
        )

    payload = collect_target_resume_candidates(data_dir=data_dir, limit=2)

    assert payload["total_count"] == 3
    assert payload["selected_count"] == 2
    assert payload["omitted_count"] == 1
    assert payload["candidate_count"] == 2
    assert payload["skipped_counts"]["limited_candidates"] == 1


def test_resume_candidates_default_includes_legacy_dashboard_dbs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configured_data_dir = tmp_path / "configured"
    legacy_data_dir = tmp_path / ".forge_data"
    _write_candidate_run(
        configured_data_dir / "engagements" / "1.db",
        engagement_id=1,
        status="completed",
        error="",
    )
    _write_candidate_run(
        legacy_data_dir / "engagements" / "2.db",
        engagement_id=2,
        status="failed",
        error="abandoned before explicit completion",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(configured_data_dir))

    payload = collect_target_resume_candidates()

    assert payload["data_dir"] == str(configured_data_dir)
    assert payload["include_legacy"] is True
    assert payload["scanned_engagements"] == 2
    assert payload["candidate_count"] == 1
    assert payload["items"][0]["engagement_id"] == 2
    assert payload["items"][0]["reason"] == "abandoned"


def test_resume_candidates_explicit_data_dir_stays_narrow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configured_data_dir = tmp_path / "configured"
    explicit_data_dir = tmp_path / "explicit"
    legacy_data_dir = tmp_path / ".forge_data"
    _write_candidate_run(
        explicit_data_dir / "engagements" / "1.db",
        engagement_id=1,
        status="failed",
        error="max iterations exhausted with pending recursive work: 1",
    )
    _write_candidate_run(
        legacy_data_dir / "engagements" / "2.db",
        engagement_id=2,
        status="failed",
        error="abandoned before explicit completion",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FORGE_DATA_DIR", str(configured_data_dir))

    payload = collect_target_resume_candidates(data_dir=explicit_data_dir)

    assert payload["data_dir"] == str(explicit_data_dir)
    assert payload["include_legacy"] is False
    assert payload["scanned_engagements"] == 1
    assert payload["candidate_count"] == 1
    assert payload["items"][0]["engagement_id"] == 1


def test_backfill_scope_manifests_dry_run_reports_recoverable_candidate(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    _write_candidate_run(
        data_dir / "engagements" / "1.db",
        engagement_id=1,
        status="failed",
        error="max iterations exhausted with pending recursive work: 1",
        metadata={"roe_id": "ROE-ACME-2026"},
        seed_value="https://app.corp-target.io/login",
    )

    payload = backfill_target_resume_scope_manifests(data_dir=data_dir, apply=False)

    assert payload["schema_version"] == "forge.targets.scope_manifest_backfill.v1"
    assert payload["dry_run"] is True
    assert payload["action_counts"] == {"would_update": 1}
    item = payload["items"][0]
    assert item["status"] == "would_update"
    assert item["blockers"] == []
    manifest_path = Path(item["planned_scope_manifest"])
    assert manifest_path.name == "scope_1_recovered.json"
    assert not manifest_path.exists()


def test_backfill_scope_manifests_apply_updates_latest_run_metadata(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    db_path = data_dir / "engagements" / "1.db"
    _write_candidate_run(
        db_path,
        engagement_id=1,
        status="failed",
        error="max iterations exhausted with pending recursive work: 1",
        metadata={"roe_id": "ROE-ACME-2026"},
        seed_value="https://app.corp-target.io/login",
    )

    payload = backfill_target_resume_scope_manifests(data_dir=data_dir, apply=True)

    assert payload["action_counts"] == {"updated": 1}
    manifest_path = Path(payload["items"][0]["planned_scope_manifest"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["roe_id"] == "ROE-ACME-2026"
    assert manifest["domains"] == ["app.corp-target.io"]
    assert manifest["urls"] == ["https://app.corp-target.io/login"]
    candidates = collect_target_resume_candidates(data_dir=data_dir)
    assert candidates["resume_ready_count"] == 1
    item = candidates["items"][0]
    assert item["scope_manifest"] == str(manifest_path)
    assert item["scope_manifest_exists"] is True
    assert item["resume_ready"] is True
    assert item["resume_command"][:6] == [
        "forge",
        "kill-chain",
        "https://app.corp-target.io/login",
        "--engagement",
        "1",
        "--roe-id",
    ]


def test_resume_plan_reports_sequential_ready_commands_without_execution(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    scope_path = tmp_path / "scope.json"
    scope_path.write_text("{}", encoding="utf-8")
    _write_candidate_run(
        data_dir / "engagements" / "1.db",
        engagement_id=1,
        status="failed",
        error="max iterations exhausted with pending recursive work: 12",
        metadata={
            "roe_id": "ROE-ACME-2026",
            "scope_manifest": str(scope_path),
            "pending_counts": {"artifact_queue": 12},
        },
    )
    _write_candidate_run(
        data_dir / "engagements" / "2.db",
        engagement_id=2,
        status="cancelled",
        error="watchdog timeout after 45 minutes",
    )

    payload = collect_target_resume_plan(
        data_dir=data_dir,
        max_iter=5,
        max_runtime_minutes=17,
    )

    assert payload["schema_version"] == "forge.targets.resume_plan.v1"
    assert payload["execution_policy"] == "plan_only_no_commands_executed"
    assert payload["path_redaction"] == "none"
    assert payload["concurrency"] == "sequential"
    assert payload["total_count"] == 2
    assert payload["selected_count"] == 2
    assert payload["omitted_count"] == 0
    assert payload["candidate_count"] == 2
    assert payload["resume_ready_count"] == 1
    assert payload["total_resume_ready_count"] == 1
    assert payload["planned_count"] == 1
    assert payload["skipped_count"] == 1
    assert payload["skipped_blocker_counts"] == {
        "roe_id_missing": 1,
        "scope_manifest_missing": 1,
    }
    assert payload["estimated_serial_runtime_minutes"] == 17
    item = payload["items"][0]
    assert item["sequence"] == 1
    assert item["engagement_id"] == 1
    assert item["expected_execution"] == "manual_sequential"
    assert item["pending_work_total"] == 12
    assert item["command"] == [
        "forge",
        "kill-chain",
        "corp-target.io",
        "--engagement",
        "1",
        "--roe-id",
        "ROE-ACME-2026",
        "--scope-manifest",
        str(scope_path),
        "--resume",
        "--max-iter",
        "5",
        "--target-type",
        "domain",
        "--prior-rate-limit-events",
        "0",
        "--prior-backoff-events",
        "0",
        "--max-runtime-minutes",
        "17",
        "--parallel-fanout",
        "4",
    ]
    assert item["max_runtime_minutes"] == 17
    assert item["parallel_fanout"] == 4

    redacted = collect_target_resume_plan(
        data_dir=data_dir,
        max_iter=5,
        max_runtime_minutes=17,
        redact_paths=True,
    )
    assert redacted["path_redaction"] == "local_paths_redacted"
    assert redacted["data_dir"] == "<redacted>"
    redacted_item = redacted["items"][0]
    assert redacted_item["db_path"] == ""
    assert redacted_item["db_ref"] == "1.db"
    assert redacted_item["scope_manifest_ref"] == "scope.json"
    assert str(scope_path) not in json.dumps(redacted)
    assert str(data_dir) not in json.dumps(redacted)
    assert "<scope-manifest:scope.json>" in redacted_item["command"]
    assert redacted_item["parallel_fanout"] == 4


def test_planned_resume_command_replaces_runtime_and_fanout_options() -> None:
    command = [
        "forge",
        "kill-chain",
        "corp-target.io",
        "--max-runtime-minutes",
        "13",
        "--parallel-fanout",
        "2",
    ]

    planned = resume_candidates._planned_resume_command(
        command,
        max_iter=None,
        max_runtime_minutes=25,
        parallel_fanout=4,
    )

    assert planned[-4:] == [
        "--max-runtime-minutes",
        "25",
        "--parallel-fanout",
        "4",
    ]
    assert planned.count("--max-runtime-minutes") == 1
    assert planned.count("--parallel-fanout") == 1


def test_resume_plan_carries_forward_prior_fanout_signal_counts(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    scope_path = tmp_path / "scope.json"
    scope_path.write_text("{}", encoding="utf-8")
    _write_candidate_run(
        data_dir / "engagements" / "1.db",
        engagement_id=1,
        status="failed",
        error="max iterations exhausted with pending recursive work: 1",
        metadata={
            "roe_id": "ROE-ACME-2026",
            "scope_manifest": str(scope_path),
            "rate_limit_events": 1,
            "backoff_events": 1,
        },
    )

    plan = collect_target_resume_plan(data_dir=data_dir)
    item = plan["items"][0]
    assert item["rate_limit_events"] == 1
    assert item["backoff_events"] == 1
    assert item["parallel_fanout"] == 1
    assert item["fanout_cap_decision"]["reason"] == (
        "reduced by prior rate-limit/backoff signals"
    )
    command = item["command"]
    assert command[command.index("--prior-rate-limit-events") + 1] == "1"
    assert command[command.index("--prior-backoff-events") + 1] == "1"

    overridden = collect_target_resume_plan(
        data_dir=data_dir,
        rate_limit_events=0,
        backoff_events=0,
    )["items"][0]
    assert overridden["rate_limit_events"] == 0
    assert overridden["backoff_events"] == 0
    assert overridden["parallel_fanout"] == 4


def test_resume_plan_reports_total_and_omitted_counts_when_limited(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    scope_path = tmp_path / "scope.json"
    scope_path.write_text("{}", encoding="utf-8")
    for engagement_id in range(1, 4):
        _write_candidate_run(
            data_dir / "engagements" / f"{engagement_id}.db",
            engagement_id=engagement_id,
            status="failed",
            error="max iterations exhausted with pending recursive work: 1",
            metadata={
                "roe_id": "ROE-ACME-2026",
                "scope_manifest": str(scope_path),
                "pending_counts": {"artifact_queue": 1},
            },
        )

    payload = collect_target_resume_plan(data_dir=data_dir, limit=2)

    assert payload["total_count"] == 3
    assert payload["selected_count"] == 2
    assert payload["omitted_count"] == 1
    assert payload["candidate_count"] == 2
    assert payload["resume_ready_count"] == 2
    assert payload["total_resume_ready_count"] == 3
    assert payload["planned_count"] == 2
    assert len(payload["items"]) == 2


def test_targets_backfill_scope_manifests_cli_outputs_json(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    _write_candidate_run(
        data_dir / "engagements" / "1.db",
        engagement_id=1,
        status="failed",
        error="max iterations exhausted with pending recursive work: 1",
        metadata={"roe_id": "ROE-ACME-2026"},
    )

    app = typer.Typer()
    targets_app = typer.Typer()
    register_target_import_commands(targets_app)
    app.add_typer(targets_app, name="targets")

    result = CliRunner().invoke(
        app,
        [
            "targets",
            "backfill-scope-manifests",
            "--data-dir",
            str(data_dir),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["dry_run"] is True
    assert payload["action_counts"] == {"would_update": 1}


def test_targets_resume_plan_cli_outputs_json_without_running(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    scope_path = tmp_path / "scope.json"
    scope_path.write_text("{}", encoding="utf-8")
    _write_candidate_run(
        data_dir / "engagements" / "1.db",
        engagement_id=1,
        status="failed",
        error="max iterations exhausted with pending recursive work: 1",
        metadata={"roe_id": "ROE-ACME-2026", "scope_manifest": str(scope_path)},
    )

    app = typer.Typer()
    targets_app = typer.Typer()
    register_target_import_commands(targets_app)
    app.add_typer(targets_app, name="targets")

    result = CliRunner().invoke(
        app,
        [
            "targets",
            "resume-plan",
            "--data-dir",
            str(data_dir),
            "--max-runtime-minutes",
            "19",
            "--redact-paths",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["execution_policy"] == "plan_only_no_commands_executed"
    assert payload["path_redaction"] == "local_paths_redacted"
    assert payload["planned_count"] == 1
    assert payload["items"][0]["command"][-4:] == [
        "--max-runtime-minutes",
        "19",
        "--parallel-fanout",
        "4",
    ]
    assert payload["items"][0]["parallel_fanout"] == 4
    assert str(scope_path) not in result.output


def test_targets_resume_run_cli_outputs_executor_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    captured_kwargs: dict[str, object] = {}

    def fake_execute(**kwargs: object) -> dict[str, object]:
        captured_kwargs.update(kwargs)
        return {
            "schema_version": "forge.targets.resume_run.v1",
            "execution_policy": "dry_run_no_commands_executed",
            "batch_id": kwargs["batch_id"],
            "planned_count": 0,
            "items": [],
        }

    monkeypatch.setattr(
        "forge.targets_import_cli.execute_target_resume_plan",
        fake_execute,
    )
    app = typer.Typer()
    targets_app = typer.Typer()
    register_target_import_commands(targets_app)
    app.add_typer(targets_app, name="targets")

    result = CliRunner().invoke(
        app,
        [
            "targets",
            "resume-run",
            "--batch-id",
            "cli-test",
            "--dry-run",
            "--redact-paths",
            "--break-stale-lock",
            "--stale-lock-minutes",
            "7",
            "--redact-paths",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schema_version"] == "forge.targets.resume_run.v1"
    assert payload["batch_id"] == "cli-test"
    assert captured_kwargs["dry_run"] is True
    assert captured_kwargs["redact_paths"] is True
    assert captured_kwargs["break_stale_lock"] is True
    assert captured_kwargs["stale_lock_minutes"] == 7
    assert captured_kwargs["parallel_fanout"] == 6

    captured_kwargs.clear()
    override_result = CliRunner().invoke(
        app,
        ["targets", "resume-run", "--parallel-fanout", "6", "--dry-run"],
    )
    assert override_result.exit_code == 0, override_result.output
    assert captured_kwargs["parallel_fanout"] == 6


def test_targets_resume_lock_status_cli_outputs_json(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    app = typer.Typer()
    targets_app = typer.Typer()
    register_target_import_commands(targets_app)
    app.add_typer(targets_app, name="targets")

    result = CliRunner().invoke(
        app,
        [
            "targets",
            "resume-lock-status",
            "--data-dir",
            str(data_dir),
            "--stale-lock-minutes",
            "7",
            "--redact-paths",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schema_version"] == "forge.targets.resume_lock_status.v1"
    assert payload["execution_policy"] == "read_only_resume_lock_status_no_commands_executed"
    assert payload["exists"] is False
    assert payload["stale_lock_minutes"] == 7
    assert payload["path_redaction"] == "local_paths_redacted"
    assert payload["data_dir"] == "<redacted>"
    assert payload["lock_path"] == ""
    assert payload["lock_ref"] == "resume_batch.lock"


def test_resume_run_executes_sequentially_and_writes_ledger(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    scope_path = tmp_path / "scope.json"
    scope_path.write_text("{}", encoding="utf-8")
    _write_candidate_run(
        data_dir / "engagements" / "1.db",
        engagement_id=1,
        status="failed",
        error="max iterations exhausted with pending recursive work: 1",
        metadata={"roe_id": "ROE-ACME-2026", "scope_manifest": str(scope_path)},
    )
    calls: list[tuple[list[str], int]] = []

    def fake_runner(command: list[str], timeout_seconds: int) -> subprocess.CompletedProcess[str]:
        calls.append((command, timeout_seconds))
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    payload = execute_target_resume_plan(
        data_dir=data_dir,
        batch_id="unit-test",
        max_runtime_minutes=13,
        parallel_fanout=6,
        runner=fake_runner,
    )

    assert payload["schema_version"] == "forge.targets.resume_run.v1"
    assert payload["execution_policy"] == "executes_child_processes_sequentially"
    assert payload["status"] == "completed"
    assert payload["total_count"] == 1
    assert payload["selected_count"] == 1
    assert payload["omitted_count"] == 0
    assert payload["total_resume_ready_count"] == 1
    assert payload["result_counts"] == {"completed": 1}
    assert len(calls) == 1
    assert calls[0][0][-4:] == [
        "--max-runtime-minutes",
        "13",
        "--parallel-fanout",
        "4",
    ]
    assert calls[0][1] == 13 * 60 + 120
    ledger_path = Path(payload["ledger_path"])
    lines = [json.loads(line) for line in ledger_path.read_text(encoding="utf-8").splitlines()]
    assert [line["event"] for line in lines] == [
        "batch_started",
        "item_started",
        "item_completed",
        "batch_completed",
    ]
    assert not Path(payload["lock_path"]).exists()


def test_resume_child_uses_contained_subprocess_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[list[str], int, str]] = []

    def fake_contained_runner(
        command: list[str],
        *,
        timeout_seconds: int,
        timeout_stderr: str,
    ) -> subprocess.CompletedProcess[str]:
        calls.append((command, timeout_seconds, timeout_stderr))
        return subprocess.CompletedProcess(command, 124, stdout="", stderr=timeout_stderr)

    monkeypatch.setattr(
        "forge.targets_resume_candidates.run_contained_subprocess",
        fake_contained_runner,
    )

    result = _run_resume_child(
        ["forge", "kill-chain", "corp-target.io"],
        timeout_seconds=42,
        runner=None,
    )

    assert result.returncode == 124
    assert calls == [
        (
            ["forge", "kill-chain", "corp-target.io"],
            42,
            "resume child exceeded timeout_seconds=42",
        )
    ]


def test_resume_command_fanout_is_clamped_to_granted_lease() -> None:
    command = resume_candidates._command_with_granted_fanout(
        ["forge", "kill-chain", "corp-target.io", "--parallel-fanout", "6"],
        2,
    )
    calls: list[list[str]] = []

    def runner(argv: list[str], _timeout: int) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    _run_resume_child(command, timeout_seconds=10, runner=runner)
    assert calls[0][-2:] == ["--parallel-fanout", "2"]


def test_resume_run_dry_run_does_not_call_runner_or_write_ledger(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    scope_path = tmp_path / "scope.json"
    scope_path.write_text("{}", encoding="utf-8")
    _write_candidate_run(
        data_dir / "engagements" / "1.db",
        engagement_id=1,
        status="failed",
        error="max iterations exhausted with pending recursive work: 1",
        metadata={"roe_id": "ROE-ACME-2026", "scope_manifest": str(scope_path)},
    )
    calls: list[list[str]] = []

    def fake_runner(command: list[str], timeout_seconds: int) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 1, stdout="should-not-run", stderr="")

    payload = execute_target_resume_plan(
        data_dir=data_dir,
        batch_id="dry-run-test",
        max_runtime_minutes=13,
        dry_run=True,
        runner=fake_runner,
    )

    assert payload["schema_version"] == "forge.targets.resume_run.v1"
    assert payload["execution_policy"] == "dry_run_no_commands_executed"
    assert payload["dry_run"] is True
    assert payload["status"] == "dry_run"
    assert payload["total_count"] == 1
    assert payload["selected_count"] == 1
    assert payload["omitted_count"] == 0
    assert payload["total_resume_ready_count"] == 1
    assert payload["result_counts"] == {"dry_run": 1}
    assert payload["items"][0]["status"] == "dry_run"
    assert payload["items"][0]["returncode"] is None
    assert payload["items"][0]["command"][-4:] == [
        "--max-runtime-minutes",
        "13",
        "--parallel-fanout",
        "4",
    ]
    assert payload["items"][0]["parallel_fanout"] == 4
    assert calls == []
    assert not (data_dir / "target_imports" / "resume_batches").exists()


def test_resume_run_dry_run_reports_parallelism_without_execution(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    scope_path = tmp_path / "scope.json"
    scope_path.write_text("{}", encoding="utf-8")
    _write_candidate_run(
        data_dir / "engagements" / "1.db",
        engagement_id=1,
        status="failed",
        error="max iterations exhausted with pending recursive work: 1",
        metadata={"roe_id": "ROE-ACME-2026", "scope_manifest": str(scope_path)},
    )
    calls: list[list[str]] = []

    def fake_runner(command: list[str], timeout_seconds: int) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0)

    payload = execute_target_resume_plan(
        data_dir=data_dir,
        batch_id="dry-run-parallel",
        dry_run=True,
        max_parallel=4,
        runner=fake_runner,
    )

    assert payload["execution_policy"] == "dry_run_no_commands_executed"
    assert payload["concurrency"] == "parallel"
    assert payload["max_parallel"] == 4
    assert payload["result_counts"] == {"dry_run": 1}
    assert calls == []
    assert not (data_dir / "target_imports" / "resume_batches").exists()


def test_resume_run_can_execute_in_parallel_with_threadsafe_ledger(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    scope_path = tmp_path / "scope.json"
    scope_path.write_text("{}", encoding="utf-8")
    suffixes = {1: "a", 2: "b", 3: "c"}
    for engagement_id in range(1, 4):
        _write_candidate_run(
            data_dir / "engagements" / f"{engagement_id}.db",
            engagement_id=engagement_id,
            status="failed",
            error="max iterations exhausted with pending recursive work: 1",
            metadata={"roe_id": "ROE-ACME-2026", "scope_manifest": str(scope_path)},
            seed_value=f"target-{engagement_id}.acme-{suffixes[engagement_id]}.net",
        )
    active = 0
    max_seen = 0
    guard = threading.Lock()

    def fake_runner(command: list[str], timeout_seconds: int) -> subprocess.CompletedProcess[str]:
        nonlocal active, max_seen
        with guard:
            active += 1
            max_seen = max(max_seen, active)
        time.sleep(0.05)
        with guard:
            active -= 1
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    resume_cfg = _FakeConfig(data_dir)
    resume_cfg.autopilot_max_active_targets = 3
    resume_cfg.autopilot_global_slots = 16
    payload = execute_target_resume_plan(
        data_dir=data_dir,
        batch_id="parallel-test",
        max_parallel=3,
        runner=fake_runner,
        config=resume_cfg,  # type: ignore[arg-type]
    )

    assert payload["execution_policy"] == "executes_child_processes_in_parallel"
    assert payload["concurrency"] == "parallel"
    assert payload["max_parallel"] == 3
    assert payload["status"] == "completed"
    assert payload["result_counts"] == {"completed": 3}
    assert max_seen > 1
    assert [item["sequence"] for item in payload["items"]] == [1, 2, 3]
    lines = [
        json.loads(line)
        for line in Path(payload["ledger_path"]).read_text(encoding="utf-8").splitlines()
    ]
    assert lines[0]["event"] == "batch_started"
    assert lines[0]["concurrency"] == "parallel"
    assert lines[0]["max_parallel"] == 3
    assert lines[-1]["event"] == "batch_completed"
    assert not Path(payload["lock_path"]).exists()


def test_resume_run_parallel_stops_scheduling_after_failure(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    scope_path = tmp_path / "scope.json"
    scope_path.write_text("{}", encoding="utf-8")
    suffixes = {1: "a", 2: "b", 3: "c", 4: "d"}
    for engagement_id in range(1, 5):
        _write_candidate_run(
            data_dir / "engagements" / f"{engagement_id}.db",
            engagement_id=engagement_id,
            status="failed",
            error="max iterations exhausted with pending recursive work: 1",
            metadata={"roe_id": "ROE-ACME-2026", "scope_manifest": str(scope_path)},
            seed_value=f"target-{engagement_id}.acme-{suffixes[engagement_id]}.net",
        )
    calls: list[list[str]] = []

    def fake_runner(command: list[str], timeout_seconds: int) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="failed")

    resume_cfg = _FakeConfig(data_dir)
    resume_cfg.autopilot_max_active_targets = 3
    resume_cfg.autopilot_global_slots = 16
    payload = execute_target_resume_plan(
        data_dir=data_dir,
        batch_id="parallel-stop-test",
        max_parallel=2,
        stop_on_failure=True,
        runner=fake_runner,
        config=resume_cfg,  # type: ignore[arg-type]
    )

    assert payload["status"] == "failed"
    assert payload["concurrency"] == "parallel"
    assert payload["result_counts"] == {"failed": 2}
    assert len(calls) == 2
    assert payload["selected_count"] == 4
    assert len(payload["items"]) == 2
    assert not Path(payload["lock_path"]).exists()


def test_resume_run_dry_run_can_redact_local_paths(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    scope_path = tmp_path / "scope.json"
    scope_path.write_text("{}", encoding="utf-8")
    for engagement_id in range(1, 4):
        _write_candidate_run(
            data_dir / "engagements" / f"{engagement_id}.db",
            engagement_id=engagement_id,
            status="failed",
            error="max iterations exhausted with pending recursive work: 1",
            metadata={"roe_id": "ROE-ACME-2026", "scope_manifest": str(scope_path)},
        )

    payload = execute_target_resume_plan(
        data_dir=data_dir,
        batch_id="dry-run-redacted",
        limit=1,
        dry_run=True,
        redact_paths=True,
    )

    serialized = json.dumps(payload)
    assert payload["execution_policy"] == "dry_run_no_commands_executed"
    assert payload["path_redaction"] == "local_paths_redacted"
    assert payload["total_count"] == 3
    assert payload["selected_count"] == 1
    assert payload["omitted_count"] == 2
    assert payload["candidate_count"] == 1
    assert payload["resume_ready_count"] == 1
    assert payload["total_resume_ready_count"] == 3
    assert payload["total_reason_counts"] == {"pending_recursive_work": 3}
    assert payload["ledger_path"] == ""
    assert payload["ledger_ref"] == "dry-run-redacted.jsonl"
    assert payload["lock_path"] == ""
    assert payload["lock_ref"] == "resume_batch.lock"
    item = payload["items"][0]
    assert item["status"] == "dry_run"
    assert item["db_path"] == ""
    assert item["db_ref"] == "1.db"
    assert "<scope-manifest:scope.json>" in item["command"]
    assert str(data_dir) not in serialized
    assert str(scope_path) not in serialized
    assert not (data_dir / "target_imports" / "resume_batches").exists()


def test_resume_run_redact_paths_blocks_live_execution(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    scope_path = tmp_path / "scope.json"
    scope_path.write_text("{}", encoding="utf-8")
    _write_candidate_run(
        data_dir / "engagements" / "1.db",
        engagement_id=1,
        status="failed",
        error="max iterations exhausted with pending recursive work: 1",
        metadata={"roe_id": "ROE-ACME-2026", "scope_manifest": str(scope_path)},
    )

    payload = execute_target_resume_plan(
        data_dir=data_dir,
        batch_id="blocked-redacted-live",
        dry_run=False,
        redact_paths=True,
    )

    assert payload["status"] == "blocked"
    assert payload["execution_policy"] == "blocked_redacted_live_resume_output"
    assert payload["result_counts"] == {"blocked": 1}
    assert not (data_dir / "target_imports" / "resume_batches").exists()


def test_resume_run_skips_no_longer_resumable_latest_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_dir = tmp_path / "data"
    db_path = data_dir / "engagements" / "1.db"
    _write_candidate_run(
        db_path,
        engagement_id=1,
        status="completed",
        error="",
    )
    monkeypatch.setattr(
        "forge.targets_resume_candidates.collect_target_resume_plan",
        lambda **_kwargs: {
            "data_dir": str(data_dir),
            "planned_count": 1,
            "items": [
                {
                    "sequence": 1,
                    "engagement_id": 1,
                    "run_id": 1,
                    "db_path": str(db_path),
                    "command": ["forge", "kill-chain", "corp-target.io"],
                    "max_runtime_minutes": 25,
                }
            ],
        },
    )
    calls: list[list[str]] = []

    def fake_runner(command: list[str], timeout_seconds: int) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0)

    payload = execute_target_resume_plan(
        data_dir=data_dir,
        batch_id="skip-test",
        runner=fake_runner,
    )

    assert payload["planned_count"] == 1
    assert payload["result_counts"] == {"skipped": 1}
    assert payload["items"][0]["skip_reason"] == "latest_run_not_resumable"
    assert calls == []


def test_resume_run_existing_lock_blocks_without_removing_lock(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    lock_dir = data_dir / "target_imports" / "resume_batches"
    lock_dir.mkdir(parents=True)
    lock_path = lock_dir / "resume_batch.lock"
    lock_path.write_text("active", encoding="utf-8")

    payload = execute_target_resume_plan(data_dir=data_dir, batch_id="locked")

    assert payload["status"] == "blocked"
    assert payload["execution_policy"] == "blocked_existing_resume_batch_lock"
    assert payload["total_count"] == 0
    assert payload["selected_count"] == 0
    assert payload["omitted_count"] == 0
    assert lock_path.read_text(encoding="utf-8") == "active"


def test_resume_lock_status_reports_missing_lock(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"

    payload = collect_target_resume_lock_status(data_dir=data_dir)

    assert payload["schema_version"] == "forge.targets.resume_lock_status.v1"
    assert payload["execution_policy"] == "read_only_resume_lock_status_no_commands_executed"
    assert payload["exists"] is False
    assert payload["breakable"] is False
    assert payload["reason"] == "lock_missing"
    assert payload["path_redaction"] == "none"
    assert payload["lock_ref"] == "resume_batch.lock"


def test_resume_lock_status_marks_old_unparsed_lock_stale(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    lock_dir = data_dir / "target_imports" / "resume_batches"
    lock_dir.mkdir(parents=True)
    lock_path = lock_dir / "resume_batch.lock"
    lock_path.write_text("active", encoding="utf-8")
    old = time.time() - 3600
    os.utime(lock_path, (old, old))

    payload = collect_target_resume_lock_status(data_dir=data_dir, stale_lock_minutes=1)

    assert payload["exists"] is True
    assert payload["stale"] is True
    assert payload["breakable"] is True
    assert payload["reason"] == "stale_age"
    assert payload["age_seconds"] >= 60


def test_resume_lock_status_keeps_recent_unparsed_lock_active(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    lock_dir = data_dir / "target_imports" / "resume_batches"
    lock_dir.mkdir(parents=True)
    lock_path = lock_dir / "resume_batch.lock"
    lock_path.write_text("active", encoding="utf-8")

    payload = collect_target_resume_lock_status(data_dir=data_dir, stale_lock_minutes=120)

    assert payload["exists"] is True
    assert payload["metadata"] == {}
    assert payload["stale"] is False
    assert payload["breakable"] is False
    assert payload["reason"] == "unparsed_lock"


def test_resume_lock_status_keeps_current_pid_lock_active(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    lock_dir = data_dir / "target_imports" / "resume_batches"
    lock_dir.mkdir(parents=True)
    lock_path = lock_dir / "resume_batch.lock"
    lock_path.write_text(
        json.dumps({"pid": os.getpid(), "created_at": "2999-01-01T00:00:00+00:00"}),
        encoding="utf-8",
    )

    payload = collect_target_resume_lock_status(data_dir=data_dir, stale_lock_minutes=120)

    assert payload["exists"] is True
    assert payload["pid"] == os.getpid()
    assert payload["pid_alive"] is True
    assert payload["stale"] is False
    assert payload["breakable"] is False
    assert payload["reason"] == "active_lock"


def test_resume_lock_status_keeps_old_live_pid_lock_active(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    lock_dir = data_dir / "target_imports" / "resume_batches"
    lock_dir.mkdir(parents=True)
    lock_path = lock_dir / "resume_batch.lock"
    lock_path.write_text(
        json.dumps(
            {
                "pid": os.getpid(),
                "created_at": "2000-01-01T00:00:00+00:00",
            }
        ),
        encoding="utf-8",
    )
    old = time.time() - 3600
    os.utime(lock_path, (old, old))

    payload = collect_target_resume_lock_status(data_dir=data_dir, stale_lock_minutes=1)

    assert payload["exists"] is True
    assert payload["pid"] == os.getpid()
    assert payload["pid_alive"] is True
    assert payload["stale"] is False
    assert payload["breakable"] is False
    assert payload["reason"] == "active_lock"


def test_resume_lock_status_redacts_untrusted_metadata(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    lock_dir = data_dir / "target_imports" / "resume_batches"
    lock_dir.mkdir(parents=True)
    lock_path = lock_dir / "resume_batch.lock"
    secret_value = "super-secret-token"
    local_path = str(tmp_path / "private" / "scope.json")
    lock_path.write_text(
        json.dumps(
            {
                "batch_id": "batch-1",
                "created_at": "2999-01-01T00:00:00+00:00",
                "owner_token": "owner-secret",
                "pid": os.getpid(),
                "api_token": secret_value,
                "scope_manifest": local_path,
            }
        ),
        encoding="utf-8",
    )

    payload = collect_target_resume_lock_status(
        data_dir=data_dir,
        redact_paths=True,
    )
    serialized = json.dumps(payload)

    assert payload["data_dir"] == "<redacted>"
    assert payload["lock_path"] == ""
    assert payload["metadata"]["batch_id"] == "batch-1"
    assert payload["metadata"]["pid"] == os.getpid()
    assert "owner_token_hash" in payload["metadata"]
    assert "owner_token" not in payload["metadata"]
    assert secret_value not in serialized
    assert local_path not in serialized


def test_resume_lock_status_marks_dead_pid_stale(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_dir = tmp_path / "data"
    lock_dir = data_dir / "target_imports" / "resume_batches"
    lock_dir.mkdir(parents=True)
    lock_path = lock_dir / "resume_batch.lock"
    lock_path.write_text(
        json.dumps({"pid": 999999, "created_at": "2999-01-01T00:00:00+00:00"}),
        encoding="utf-8",
    )
    monkeypatch.setattr(resume_candidates, "_pid_alive", lambda pid: False)

    payload = collect_target_resume_lock_status(data_dir=data_dir, stale_lock_minutes=120)

    assert payload["exists"] is True
    assert payload["pid"] == 999999
    assert payload["pid_alive"] is False
    assert payload["stale"] is True
    assert payload["breakable"] is True
    assert payload["reason"] == "dead_pid"


def test_resume_lock_status_uses_file_mtime_for_malformed_created_at(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    lock_dir = data_dir / "target_imports" / "resume_batches"
    lock_dir.mkdir(parents=True)
    lock_path = lock_dir / "resume_batch.lock"
    lock_path.write_text(
        json.dumps({"pid": 0, "created_at": "not-a-timestamp"}),
        encoding="utf-8",
    )
    old = time.time() - 3600
    os.utime(lock_path, (old, old))

    payload = collect_target_resume_lock_status(data_dir=data_dir, stale_lock_minutes=1)

    assert payload["exists"] is True
    assert payload["stale"] is True
    assert payload["breakable"] is True
    assert payload["reason"] == "stale_age"
    assert payload["age_seconds"] >= 60


def test_resume_run_breaks_only_stale_lock_before_execution(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    scope_path = tmp_path / "scope.json"
    scope_path.write_text("{}", encoding="utf-8")
    _write_candidate_run(
        data_dir / "engagements" / "1.db",
        engagement_id=1,
        status="failed",
        error="max iterations exhausted with pending recursive work: 1",
        metadata={"roe_id": "ROE-ACME-2026", "scope_manifest": str(scope_path)},
    )
    lock_dir = data_dir / "target_imports" / "resume_batches"
    lock_dir.mkdir(parents=True)
    lock_path = lock_dir / "resume_batch.lock"
    lock_path.write_text("active", encoding="utf-8")
    old = time.time() - 3600
    os.utime(lock_path, (old, old))
    calls: list[list[str]] = []

    def fake_runner(command: list[str], timeout_seconds: int) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0)

    payload = execute_target_resume_plan(
        data_dir=data_dir,
        batch_id="break-stale",
        break_stale_lock=True,
        stale_lock_minutes=1,
        runner=fake_runner,
    )

    assert payload["status"] == "completed"
    assert payload["result_counts"] == {"completed": 1}
    assert calls
    assert not lock_path.exists()


def test_resume_run_dry_run_reports_stale_lock_decision(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    lock_dir = data_dir / "target_imports" / "resume_batches"
    lock_dir.mkdir(parents=True)
    lock_path = lock_dir / "resume_batch.lock"
    lock_path.write_text("active", encoding="utf-8")
    old = time.time() - 3600
    os.utime(lock_path, (old, old))

    payload = execute_target_resume_plan(
        data_dir=data_dir,
        batch_id="dry-run-stale-lock",
        dry_run=True,
        break_stale_lock=True,
        stale_lock_minutes=1,
    )

    assert payload["status"] == "dry_run"
    assert payload["would_break_stale_lock"] is True
    assert payload["lock_status"]["breakable"] is True
    assert payload["lock_status"]["reason"] == "stale_age"
    assert lock_path.exists()


def test_resume_run_blocks_when_stale_lock_changes_before_break(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_dir = tmp_path / "data"
    lock_dir = data_dir / "target_imports" / "resume_batches"
    lock_dir.mkdir(parents=True)
    lock_path = lock_dir / "resume_batch.lock"
    lock_path.write_text("active", encoding="utf-8")
    old = time.time() - 3600
    os.utime(lock_path, (old, old))
    calls = 0
    original_fingerprint = resume_candidates._resume_lock_fingerprint

    def changing_fingerprint(path: Path) -> dict[str, object]:
        nonlocal calls
        calls += 1
        if calls == 2:
            path.write_text(
                json.dumps(
                    {
                        "batch_id": "other",
                        "created_at": "2999-01-01T00:00:00+00:00",
                        "pid": os.getpid(),
                    }
                ),
                encoding="utf-8",
            )
        return original_fingerprint(path)

    monkeypatch.setattr(resume_candidates, "_resume_lock_fingerprint", changing_fingerprint)

    payload = execute_target_resume_plan(
        data_dir=data_dir,
        batch_id="break-changed-lock",
        break_stale_lock=True,
        stale_lock_minutes=1,
    )

    assert payload["status"] == "blocked"
    assert payload["execution_policy"] == "blocked_existing_resume_batch_lock_changed"
    assert payload["lock_status"]["breakable"] is False
    assert json.loads(lock_path.read_text(encoding="utf-8"))["batch_id"] == "other"


def test_resume_run_break_stale_lock_tolerates_lock_removed_during_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_dir = tmp_path / "data"
    scope_path = tmp_path / "scope.json"
    scope_path.write_text("{}", encoding="utf-8")
    _write_candidate_run(
        data_dir / "engagements" / "1.db",
        engagement_id=1,
        status="failed",
        error="max iterations exhausted with pending recursive work: 1",
        metadata={"roe_id": "ROE-ACME-2026", "scope_manifest": str(scope_path)},
    )
    lock_dir = data_dir / "target_imports" / "resume_batches"
    lock_dir.mkdir(parents=True)
    lock_path = lock_dir / "resume_batch.lock"
    lock_path.write_text("active", encoding="utf-8")
    old = time.time() - 3600
    os.utime(lock_path, (old, old))
    original_unlink = Path.unlink

    def racing_unlink(path: Path, *args: object, **kwargs: object) -> None:
        if path == lock_path and path.exists():
            original_unlink(path)
            raise FileNotFoundError(str(path))
        original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", racing_unlink)
    calls: list[list[str]] = []

    def fake_runner(command: list[str], timeout_seconds: int) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0)

    payload = execute_target_resume_plan(
        data_dir=data_dir,
        batch_id="break-stale-race",
        break_stale_lock=True,
        stale_lock_minutes=1,
        runner=fake_runner,
    )

    assert payload["status"] == "completed"
    assert payload["result_counts"] == {"completed": 1}
    assert calls
    assert not lock_path.exists()


def test_resume_run_cleanup_preserves_replacement_lock(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    scope_path = tmp_path / "scope.json"
    scope_path.write_text("{}", encoding="utf-8")
    _write_candidate_run(
        data_dir / "engagements" / "1.db",
        engagement_id=1,
        status="failed",
        error="max iterations exhausted with pending recursive work: 1",
        metadata={"roe_id": "ROE-ACME-2026", "scope_manifest": str(scope_path)},
    )
    lock_path = data_dir / "target_imports" / "resume_batches" / "resume_batch.lock"

    def fake_runner(command: list[str], timeout_seconds: int) -> subprocess.CompletedProcess[str]:
        lock_path.write_text(
            json.dumps(
                {
                    "batch_id": "other",
                    "created_at": "2999-01-01T00:00:00+00:00",
                    "pid": os.getpid(),
                    "owner_token": "other-owner",
                }
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0)

    payload = execute_target_resume_plan(
        data_dir=data_dir,
        batch_id="replacement-lock",
        runner=fake_runner,
    )

    assert payload["status"] == "completed"
    assert json.loads(lock_path.read_text(encoding="utf-8"))["batch_id"] == "other"


def test_resume_run_refuses_to_break_active_lock(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    lock_dir = data_dir / "target_imports" / "resume_batches"
    lock_dir.mkdir(parents=True)
    lock_path = lock_dir / "resume_batch.lock"
    lock_path.write_text(
        json.dumps({"pid": os.getpid(), "created_at": "2999-01-01T00:00:00+00:00"}),
        encoding="utf-8",
    )

    payload = execute_target_resume_plan(
        data_dir=data_dir,
        batch_id="active-lock",
        break_stale_lock=True,
        stale_lock_minutes=120,
    )

    assert payload["status"] == "blocked"
    assert payload["execution_policy"] == "blocked_existing_resume_batch_lock_not_stale"
    assert payload["lock_status"]["breakable"] is False
    assert lock_path.exists()


def test_start_launches_scoped_kill_chain_with_scope_and_roe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")
    calls: list[list[str]] = []

    def _fake_run(
        command: list[str],
        *,
        timeout_seconds: int,
        timeout_stderr: str,
        **_kwargs: object,
    ) -> object:
        calls.append(command)
        assert timeout_seconds == 480 * 60 + 120
        assert timeout_stderr == "target import child exceeded timeout_seconds=28920"
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr("forge.targets_import.run_contained_subprocess", _fake_run)

    results = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=True,
        dry_run=False,
        limit=1,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
        sleep_fn=lambda _: None,
    )

    assert results[0].started is True
    assert results[0].start_stop_reason == "no_more_candidates"
    command = calls[0]
    assert command[2:4] == ["forge.cli", "kill-chain"]
    assert "--roe-id" in command
    assert "--scope-manifest" in command
    assert "--max-iter" in command
    assert command[-4:] == [
        "--max-runtime-minutes",
        "480",
        "--parallel-fanout",
        "2",
    ]
    assert command[command.index("--target-type") + 1] == "domain"
    assert "--no-attack-mode" not in command
    assert "--no-auto-run-detected" not in command
    assert "--attack-mode" not in command
    assert "--auto-run-detected" not in command


def test_start_skips_non_global_ip_without_consuming_start_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    feed_path.write_text(
        json.dumps(
            {
                "schema_version": "target-feed.v1",
                "items": [
                    {
                        "target_type": "ip",
                        "target_value": "0.0.0.0",
                        "source_groups": ["db", "report_family:noise"],
                        "source_count": 2,
                        "priority": 90,
                    },
                    {
                        "target_type": "domain",
                        "target_value": "shared.corp-target.io",
                        "source_groups": ["db", "report_family:shared"],
                        "source_count": 2,
                        "priority": 90,
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    cfg = _FakeConfig(tmp_path / "data")
    calls: list[list[str]] = []

    def _fake_run(command: list[str], **_: object) -> object:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0)

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
        start_limit=1,
        config=cfg,  # type: ignore[arg-type]
        sleep_fn=lambda _: None,
    )

    assert [result.target_value for result in results] == ["shared.corp-target.io", "0.0.0.0"]
    assert results[0].started is True
    assert results[1].started is False
    assert results[1].start_skipped_reason == "non_global_ip"
    assert len(calls) == 1
    assert "shared.corp-target.io" in calls[0]


def test_start_uses_configured_kill_chain_runtime_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")
    calls: list[tuple[list[str], int]] = []

    def _fake_run(command: list[str], **kwargs: object) -> object:
        calls.append((command, int(kwargs["timeout_seconds"])))
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr("forge.targets_import.run_contained_subprocess", _fake_run)

    results = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=True,
        dry_run=False,
        limit=1,
        max_iter=3,
        max_runtime_minutes=13,
        config=cfg,  # type: ignore[arg-type]
        sleep_fn=lambda _: None,
    )

    assert results[0].started is True
    assert calls[0][0][-4:] == [
        "--max-runtime-minutes",
        "13",
        "--parallel-fanout",
        "2",
    ]
    assert calls[0][1] == 13 * 60 + 120


def test_start_does_not_treat_exit_two_output_as_completed_without_completed_db_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")
    progress_events: list[tuple[str, dict[str, object]]] = []

    def _fake_run(command: list[str], **_: object) -> object:
        db_path = cfg.engagement_db_path("1")
        db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                """
                CREATE TABLE engagement_runs (
                    id INTEGER PRIMARY KEY,
                    engagement_id INTEGER,
                    run_kind TEXT,
                    status TEXT,
                    seed_value TEXT
                )
                """
            )
            conn.execute(
                "INSERT INTO engagement_runs VALUES (1, 1, 'kill_chain', 'completed', 'corp-target.io')"
            )
            conn.execute(
                "INSERT INTO engagement_runs VALUES (2, 1, 'kill_chain', 'failed', 'corp-target.io')"
            )
        return subprocess.CompletedProcess(
            command,
            2,
            stdout="Kill-chain complete in 10.0s\nReport: reports/demo.md\n",
            stderr="Non-TTY invocation - not prompting.\n",
        )

    monkeypatch.setattr("forge.targets_import.run_contained_subprocess", _fake_run)

    results = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=True,
        dry_run=False,
        limit=1,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
        sleep_fn=lambda _: None,
        progress_callback=lambda event, details: progress_events.append((event, details)),
    )

    assert results[0].started is False
    assert results[0].start_failed is True
    assert [event for event, _details in progress_events].count("target_failed") == 1
    assert "target_completed" not in [event for event, _details in progress_events]
    from forge.autopilot.scheduler_db import scheduler_db_path

    with sqlite3.connect(scheduler_db_path(cfg.data_dir)) as conn:
        lease = conn.execute(
            "SELECT status, release_reason FROM leases WHERE engagement_id=1"
        ).fetchone()
    assert lease == ("released", "failed")


def test_start_does_not_treat_zero_exit_as_completed_when_db_run_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")

    def _fake_run(command: list[str], **_: object) -> object:
        db_path = cfg.engagement_db_path("1")
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(db_path)
        try:
            conn.execute(
                """
                CREATE TABLE engagement_runs (
                    engagement_id INTEGER, run_kind TEXT, status TEXT, seed_value TEXT
                )
                """
            )
            conn.execute(
                "INSERT INTO engagement_runs VALUES (1, 'kill_chain', 'failed', 'corp-target.io')"
            )
            conn.commit()
        finally:
            conn.close()
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr("forge.targets_import.run_contained_subprocess", _fake_run)

    results = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=True,
        dry_run=False,
        limit=1,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
        sleep_fn=lambda _: None,
    )

    assert results[0].started is False
    assert results[0].start_failed is True


def test_start_treats_exit_two_with_completed_db_run_as_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")

    def _fake_run(command: list[str], **_: object) -> object:
        db_path = cfg.engagement_db_path("1")
        conn = sqlite3.connect(db_path)
        try:
            conn.execute(
                """
                INSERT INTO engagement_runs
                    (engagement_id, run_kind, status, seed_value, seed_type)
                VALUES (1, 'kill_chain', 'completed', 'corp-target.io', 'domain')
                """
            )
            conn.commit()
        finally:
            conn.close()
        return subprocess.CompletedProcess(
            command,
            2,
            stdout="",
            stderr=(
                "Usage: python -m forge.cli targets import [OPTIONS]\n"
                "Invalid value: not enough values to unpack (expected 2, got 1)\n"
            ),
        )

    monkeypatch.setattr("forge.targets_import.run_contained_subprocess", _fake_run)

    results = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=True,
        dry_run=False,
        limit=1,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
        sleep_fn=lambda _: None,
    )

    assert results[0].started is True


def test_start_treats_timeout_with_completed_db_run_as_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")

    def _fake_run(command: list[str], **_: object) -> object:
        db_path = cfg.engagement_db_path("1")
        conn = sqlite3.connect(db_path)
        try:
            conn.execute(
                """
                INSERT INTO engagement_runs
                    (engagement_id, run_kind, status, seed_value, seed_type)
                VALUES (1, 'kill_chain', 'completed', 'corp-target.io', 'domain')
                """
            )
            conn.commit()
        finally:
            conn.close()
        return subprocess.CompletedProcess(
            command,
            124,
            stdout="Kill-chain complete in 1200.0s\n",
            stderr="target import child exceeded timeout_seconds=1320",
        )

    monkeypatch.setattr("forge.targets_import.run_contained_subprocess", _fake_run)

    results = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=True,
        dry_run=False,
        limit=1,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
        sleep_fn=lambda _: None,
    )

    assert results[0].started is True


def test_start_failure_records_and_continues_without_consuming_start_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")
    attempts: list[str] = []
    events: list[tuple[str, dict[str, object]]] = []

    def _fake_start(**kwargs: object) -> None:
        seed = str(kwargs["seed"])
        attempts.append(seed)
        if len(attempts) == 1:
            raise subprocess.CalledProcessError(2, ["kill-chain", seed])

    def _progress(event_type: str, details: dict[str, object]) -> None:
        events.append((event_type, details))

    monkeypatch.setattr("forge.targets_import._start_kill_chain", _fake_start)

    results = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=True,
        dry_run=False,
        limit=None,
        max_iter=3,
        start_limit=1,
        config=cfg,  # type: ignore[arg-type]
        progress_callback=_progress,
        sleep_fn=lambda _: None,
    )

    assert len(attempts) == 2
    assert results[0].start_failed is True
    assert results[0].start_error_type == "CalledProcessError"
    assert results[0].started is False
    assert results[1].started is True
    assert results[1].start_failed is False
    assert [event for event, _ in events].count("target_failed") == 1
    assert [event for event, _ in events].count("target_completed") == 1
    failed_event = next(details for event, details in events if event == "target_failed")
    assert failed_event["error_type"] == "CalledProcessError"
    assert results[1].start_stop_reason == "start_limit_reached"


def test_candidate_evaluation_progress_is_batched_with_skip_counts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")
    events: list[tuple[str, dict[str, object]]] = []
    monkeypatch.setattr("forge.targets_import.TARGET_IMPORT_PROGRESS_EVENT_CANDIDATES", 2)
    monkeypatch.setattr("forge.targets_import.TARGET_IMPORT_PROGRESS_EVENT_SECONDS", 60.0)
    results = import_targets(
        feed_url=None, feed_file=feed_path, auth_header_env=None,
        roe_id=None, start=False, dry_run=True, limit=None, max_iter=3,
        config=cfg, progress_callback=lambda event, details: events.append((event, details)),
        _monotonic=lambda: 0.0,
    )
    progress = [details for event, details in events if event == "candidate_evaluation_progress"]
    assert len(results) == 2
    assert len(progress) == 1
    assert progress[0]["evaluated"] == 2
    reasons = progress[0]["skip_reason_counts"]
    assert isinstance(reasons, dict)
    assert sum(reasons.values()) == 2


def test_candidate_evaluation_time_threshold_surfaces_long_skip_stretch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_dispatch_feed(feed_path, count=5)
    cfg = _FakeConfig(tmp_path / "data")
    events: list[tuple[str, dict[str, object]]] = []
    ticks = iter([0.0, 61.0, 122.0, 183.0, 244.0, 305.0])
    monkeypatch.setattr("forge.targets_import.TARGET_IMPORT_PROGRESS_EVENT_CANDIDATES", 100)
    results = import_targets(
        feed_url=None, feed_file=feed_path, auth_header_env=None,
        roe_id=None, start=False, dry_run=True, limit=None, max_iter=3,
        config=cfg, progress_callback=lambda event, details: events.append((event, details)),
        _monotonic=lambda: next(ticks),
    )
    progress = [details for event, details in events if event == "candidate_evaluation_progress"]
    assert len(results) == 5
    assert progress
    assert [item["evaluated"] for item in progress] == [1, 2, 3, 4, 5]


def test_start_timeout_marks_running_kill_chain_failed_for_resume(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")
    events: list[tuple[str, dict[str, object]]] = []

    def _fake_start(**kwargs: object) -> None:
        db_path = Path(str(kwargs["engagement_db_path"]))
        conn = get_engagement_db(db_path)
        try:
            conn.execute(
                """
                INSERT INTO engagement_runs (
                    engagement_id, run_kind, status, seed_value, seed_type,
                    max_iterations, current_iteration, resume_enabled, dry_run,
                    attack_mode, metadata_json, started_at, updated_at
                ) VALUES (?, 'kill_chain', 'running', ?, 'domain', 3, 1, 1, 0, 0, ?, ?, ?)
                """,
                (
                    kwargs["engagement_id"],
                    kwargs["seed"],
                    json.dumps(
                        {
                            "roe_id": kwargs["roe_id"],
                            "scope_manifest": str(kwargs["scope_manifest"]),
                        }
                    ),
                    "2026-10-13T00:00:00Z",
                    "2026-10-13T00:00:00Z",
                ),
            )
            conn.commit()
        finally:
            conn.close()
        raise subprocess.CalledProcessError(
            124,
            ["kill-chain", str(kwargs["seed"])],
            stderr="target import child exceeded timeout_seconds=28920",
        )

    monkeypatch.setattr("forge.targets_import._start_kill_chain", _fake_start)

    results = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=True,
        dry_run=False,
        limit=1,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
        progress_callback=lambda event, details: events.append((event, details)),
        sleep_fn=lambda _: None,
    )

    db_path = cfg.engagement_db_path(str(results[0].engagement_id))
    conn = sqlite3.connect(db_path)
    try:
        run = conn.execute(
            "SELECT status, error, completed_at FROM engagement_runs "
            "WHERE engagement_id=? AND seed_value=? ORDER BY id DESC LIMIT 1",
            (results[0].engagement_id, results[0].target_value),
        ).fetchone()
    finally:
        conn.close()
    timeout_event = next(details for event, details in events if event == "target_failed")
    assert results[0].start_failed is True
    assert run[0] == "failed"
    assert "watchdog timeout" in run[1]
    assert run[2]
    assert timeout_event["return_code"] == 124


def test_consecutive_start_failures_stop_feed_early_and_report_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    targets = [f"host{index}.corp-target.io" for index in range(10)]
    feed_path.write_text(
        json.dumps(
            {
                "schema_version": "target-feed.v1",
                "items": [
                    {"target_type": "domain", "target_value": target}
                    for target in targets
                ],
            }
        ),
        encoding="utf-8",
    )
    cfg = _FakeConfig(tmp_path / "data")
    attempts: list[str] = []
    created_targets: list[str] = []

    def _fake_create(_cfg: object, item: object, _existing: object) -> tuple[int, bool]:
        target = str(getattr(item, "canonical_value"))
        created_targets.append(target)
        return len(created_targets), True

    def _fake_start(**kwargs: object) -> None:
        attempts.append(str(kwargs["seed"]))
        raise subprocess.CalledProcessError(2, ["kill-chain", str(kwargs["seed"])])

    monkeypatch.setattr("forge.targets_import._external_target_engagement_index", lambda _cfg: {})
    monkeypatch.setattr("forge.targets_import._create_or_reuse_engagement", _fake_create)
    monkeypatch.setattr("forge.targets_import._ensure_target_import_monitoring", lambda **_: None)
    monkeypatch.setattr("forge.targets_import._write_scope_manifest", lambda *_args: None)
    monkeypatch.setattr("forge.targets_import._has_kill_chain_run", lambda *_args: False)
    monkeypatch.setattr("forge.targets_import._start_kill_chain", _fake_start)

    results = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=True,
        dry_run=False,
        limit=None,
        max_iter=3,
        start_limit=20,
        config=cfg,  # type: ignore[arg-type]
        sleep_fn=lambda _: None,
    )

    assert len(attempts) == 3
    assert len(created_targets) == 3
    assert len(results) == 3
    assert all(result.start_failed for result in results)
    assert results[-1].start_error_type == "CalledProcessError"
    assert results[-1].start_stop_reason == "consecutive_failure_budget_exhausted"
    assert results[-1].unprocessed_count == 7


def test_start_limit_caps_scoped_kill_chain_launches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")
    calls: list[list[str]] = []

    def _fake_run(
        command: list[str],
        *,
        timeout_seconds: int,
        timeout_stderr: str,
        **_kwargs: object,
    ) -> object:
        calls.append(command)
        assert timeout_seconds == 480 * 60 + 120
        assert timeout_stderr == "target import child exceeded timeout_seconds=28920"
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr("forge.targets_import.run_contained_subprocess", _fake_run)

    results = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=True,
        dry_run=False,
        limit=2,
        max_iter=3,
        start_limit=1,
        config=cfg,  # type: ignore[arg-type]
        sleep_fn=lambda _: None,
    )

    assert [result.started for result in results] == [True, False]
    assert results[0].start_stop_reason == "start_limit_reached"
    assert results[1].start_skipped_reason == "start_limit_reached"
    assert len(calls) == 1
    assert calls[0][-4:] == [
        "--max-runtime-minutes",
        "480",
        "--parallel-fanout",
        "2",
    ]


def test_start_min_source_count_skips_single_source_without_consuming_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    feed_path.write_text(
        json.dumps(
            {
                "schema_version": "target-feed.v1",
                "items": [
                    {
                        "target_type": "domain",
                        "target_value": "single.corp-target.io",
                        "source_groups": ["connector:single"],
                        "source_count": 1,
                        "priority": 100,
                    },
                    {
                        "target_type": "domain",
                        "target_value": "shared.corp-target.io",
                        "source_groups": ["db", "report_family:shared"],
                        "source_count": 2,
                        "priority": 90,
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    cfg = _FakeConfig(tmp_path / "data")
    calls: list[list[str]] = []

    def _fake_run(command: list[str], **_: object) -> object:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0)

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
        start_limit=1,
        min_start_source_count=2,
        config=cfg,  # type: ignore[arg-type]
        sleep_fn=lambda _: None,
    )

    assert [result.target_value for result in results] == [
        "single.corp-target.io",
        "shared.corp-target.io",
    ]
    assert results[0].started is False
    assert results[0].start_skipped_reason == "source_count_below_min_start_threshold:1<2"
    assert results[1].started is True
    assert len(calls) == 1
    assert "shared.corp-target.io" in calls[0]


def test_monitoring_seed_failure_does_not_block_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")
    calls: list[list[str]] = []

    def _fake_monitoring_seed(*_args: object, **_kwargs: object) -> None:
        raise ValueError("not enough values to unpack (expected 2, got 1)")

    def _fake_run(command: list[str], **_: object) -> object:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(
        "forge.targets_import._ensure_target_import_monitoring",
        _fake_monitoring_seed,
    )
    monkeypatch.setattr("forge.targets_import.run_contained_subprocess", _fake_run)

    results = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=True,
        dry_run=False,
        limit=1,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
        sleep_fn=lambda _: None,
    )

    captured = capsys.readouterr()
    assert results[0].started is True
    assert len(calls) == 1
    assert "target import monitoring seed skipped" in captured.err


@pytest.mark.parametrize("status", ["running", "completed", "cancelled"])
def test_start_skips_engagement_with_existing_kill_chain_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status: str,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")
    first = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=False,
        dry_run=False,
        limit=1,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
    )
    db_path = cfg.engagement_db_path("1")
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO engagement_runs
                (engagement_id, run_kind, status, seed_value, seed_type)
            VALUES (?, 'kill_chain', ?, ?, ?)
            """,
            (1, status, first[0].target_value, first[0].target_type),
        )
        conn.commit()
    finally:
        conn.close()

    calls: list[str] = []
    monkeypatch.setattr(
        "forge.targets_import._start_kill_chain",
        lambda **kwargs: calls.append(str(kwargs["seed"])),
    )

    second = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=True,
        dry_run=False,
        limit=2,
        start_limit=1,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
        sleep_fn=lambda _: None,
    )

    assert second[0].created is False
    assert second[0].started is False
    assert second[1].started is True
    assert calls == [second[1].target_value]


def test_failed_target_is_resumed_with_reason_not_started_fresh(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")
    initial = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=False,
        dry_run=False,
        limit=1,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
    )
    assert initial[0].engagement_id is not None
    assert initial[0].scope_manifest is not None
    db_path = cfg.engagement_db_path(str(initial[0].engagement_id))
    conn = get_engagement_db(db_path)
    try:
        conn.execute(
            """
            INSERT INTO engagement_runs (
                engagement_id, run_kind, status, seed_value, seed_type,
                max_iterations, current_iteration, resume_enabled, dry_run,
                attack_mode, error, metadata_json, started_at, completed_at, updated_at
            )
            VALUES (?, 'kill_chain', 'failed', ?, 'domain', 3, 3, 1, 0, 0,
                    ?, ?, '2026-08-08T00:00:00Z', '2026-08-08T00:30:00Z',
                    '2026-08-08T00:30:00Z')
            """,
            (
                initial[0].engagement_id,
                initial[0].target_value,
                "max iterations exhausted with pending recursive work: 1",
                json.dumps(
                    {
                        "roe_id": "ROE-ACME-2026-08",
                        "scope_manifest": str(initial[0].scope_manifest),
                    }
                ),
            ),
        )
        conn.commit()
    finally:
        conn.close()

    fresh_start_calls: list[str] = []

    def fake_start(**kwargs: object) -> None:
        fresh_start_calls.append(str(kwargs["seed"]))

    monkeypatch.setattr("forge.targets_import._start_kill_chain", fake_start)
    imported = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-ACME-2026-08",
        start=True,
        dry_run=False,
        limit=1,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
        sleep_fn=lambda _: None,
    )

    assert imported[0].engagement_id == initial[0].engagement_id
    assert imported[0].started is False
    assert fresh_start_calls == []

    resume_calls: list[list[str]] = []

    def fake_resume(command: list[str], timeout_seconds: int) -> subprocess.CompletedProcess[str]:
        resume_calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="resumed", stderr="")

    resumed = execute_target_resume_plan(
        data_dir=cfg.data_dir,
        batch_id="failed-target-retry",
        runner=fake_resume,
    )

    assert resumed["result_counts"] == {"completed": 1}
    assert resumed["items"][0]["engagement_id"] == initial[0].engagement_id
    assert resumed["items"][0]["reason"] == "pending_recursive_work"
    assert "--resume" in resume_calls[0]


def test_start_requires_roe_before_engagement_write(tmp_path: Path) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")

    with pytest.raises(ValueError, match="--start requires --roe-id"):
        import_targets(
            feed_url=None,
            feed_file=feed_path,
            auth_header_env=None,
            roe_id=None,
            start=True,
            dry_run=False,
            limit=1,
            max_iter=3,
            config=cfg,  # type: ignore[arg-type]
        )

    assert not (cfg.data_dir / "engagements").exists()


def test_feed_url_uses_monitor_key_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    class _Response:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return {
                "schema_version": "target-feed.v1",
                "generated_at": "2026-08-08T00:00:00Z",
                "items": [
                    {
                        "target_type": "domain",
                        "target_value": "corp-target.io",
                        "source_kind": "telemetry",
                        "confidence": 1,
                        "first_seen_at": "2026-08-08T00:00:00Z",
                        "provenance": "network_domain",
                    }
                ],
            }

    def _fake_get(url: str, *, headers: dict[str, str], timeout: float) -> _Response:
        observed.update({"url": url, "headers": headers, "timeout": timeout})
        return _Response()

    monkeypatch.setenv("TPH_MONITOR_KEY", "secret-value")
    monkeypatch.setattr("forge.targets_import.httpx.get", _fake_get)

    items = load_target_feed(
        feed_url="http://127.0.0.1:8011/monitor/targets/export",
        feed_file=None,
        auth_header_env="TPH_MONITOR_KEY",
        limit=None,
    )

    assert len(items) == 1
    assert observed["headers"] == {"X-Monitor-Key": "secret-value"}


def test_load_target_feed_skips_item_level_unpack_value_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_unpack_error_feed(feed_path)

    def _raise_unpack_error(value: str) -> str:
        raise ValueError("not enough values to unpack (expected 2, got 1)")

    monkeypatch.setattr("forge.targets_import._classify_target_value", _raise_unpack_error)

    items = load_target_feed(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        limit=None,
    )

    assert [(item.target_type, item.canonical_value) for item in items] == [
        ("domain", "corp-target.io")
    ]


def test_load_target_feed_accepts_daily_feed_over_legacy_two_mib_cap(tmp_path: Path) -> None:
    feed_path = tmp_path / "large-feed.json"
    feed_path.write_text(
        json.dumps(
            {
                "schema_version": "target-feed.v1",
                "generated_at": "2026-08-28T00:00:00Z",
                "padding": "x" * (2_097_152 + 1),
                "items": [
                    {
                        "target_type": "domain",
                        "target_value": "large-feed.corp-target.io",
                        "source_kind": "reports",
                        "confidence": 1,
                        "first_seen_at": "2026-08-28T00:00:00Z",
                        "provenance": "test",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    items = load_target_feed(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        limit=None,
    )

    assert len(items) == 1
    assert items[0].canonical_value == "large-feed.corp-target.io"


def test_targets_import_cli_registration_supports_dry_run(tmp_path: Path) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)

    app = typer.Typer()
    targets_app = typer.Typer()
    register_target_import_commands(targets_app)
    app.add_typer(targets_app, name="targets")

    result = CliRunner().invoke(
        app,
        [
            "targets",
            "import",
            "--feed-file",
            str(feed_path),
            "--dry-run",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "DRY RUN" in result.output
    assert "2 target(s) parsed and deduped" in result.output


def test_targets_import_cli_supports_json_output(tmp_path: Path) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)

    app = typer.Typer()
    targets_app = typer.Typer()
    register_target_import_commands(targets_app)
    app.add_typer(targets_app, name="targets")

    result = CliRunner().invoke(
        app,
        [
            "targets",
            "import",
            "--feed-file",
            str(feed_path),
            "--dry-run",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schema_version"] == "forge.targets_import.v1"
    assert payload["execution_policy"] == "dry_run_no_engagement_writes_or_starts"
    assert payload["total_count"] == 2
    assert payload["started_count"] == 0
    assert payload["results"][0]["dry_run"] is True


def test_targets_import_cli_json_reports_per_target_start_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    monkeypatch.setattr(
        "forge.targets_import_cli.import_targets",
        lambda **_: [
            SimpleNamespace(
                engagement_id=7,
                target_type="domain",
                target_value="target.corp-target.io",
                target_key="domain:target.corp-target.io",
                scope_manifest=None,
                created=True,
                started=False,
                dry_run=False,
                start_failed=True,
                start_error_type="CalledProcessError",
                start_stop_reason="consecutive_failure_budget_exhausted",
                unprocessed_count=5,
            )
        ],
    )

    app = typer.Typer()
    targets_app = typer.Typer()
    register_target_import_commands(targets_app)
    app.add_typer(targets_app, name="targets")

    result = CliRunner().invoke(
        app,
        [
            "targets",
            "import",
            "--feed-file",
            str(feed_path),
            "--start",
            "--roe-id",
            "ROE-TEST",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["failed_count"] == 1
    assert payload["results"][0]["started"] is False
    assert payload["results"][0]["start_failed"] is True
    assert payload["results"][0]["start_error_type"] == "CalledProcessError"
    assert payload["start_stop_reason"] == "consecutive_failure_budget_exhausted"
    assert payload["unprocessed_count"] == 5
    assert payload["total_count"] == 6
    assert payload["omitted_count"] == 5
    assert payload["results"][0]["start_stop_reason"] == "consecutive_failure_budget_exhausted"


def test_targets_import_cli_passes_max_runtime_minutes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    captured_kwargs: dict[str, object] = {}

    def fake_import_targets(**kwargs: object) -> list[object]:
        captured_kwargs.update(kwargs)
        return []

    monkeypatch.setattr("forge.targets_import_cli.import_targets", fake_import_targets)

    app = typer.Typer()
    targets_app = typer.Typer()
    register_target_import_commands(targets_app)
    app.add_typer(targets_app, name="targets")

    result = CliRunner().invoke(
        app,
        [
            "targets",
            "import",
            "--feed-file",
            str(feed_path),
            "--start",
            "--roe-id",
            "ROE-ACME-2026-08",
            "--max-runtime-minutes",
            "13",
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured_kwargs["max_runtime_minutes"] == 13
    assert captured_kwargs["parallel_fanout"] == 6


def test_targets_import_cli_defaults_timeout_and_fanout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    captured_kwargs: dict[str, object] = {}

    def fake_import_targets(**kwargs: object) -> list[object]:
        captured_kwargs.update(kwargs)
        return []

    monkeypatch.setattr("forge.targets_import_cli.import_targets", fake_import_targets)

    app = typer.Typer()
    targets_app = typer.Typer()
    register_target_import_commands(targets_app)
    app.add_typer(targets_app, name="targets")

    result = CliRunner().invoke(
        app,
        [
            "targets",
            "import",
            "--feed-file",
            str(feed_path),
            "--start",
            "--roe-id",
            "ROE-ACME-2026-08",
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured_kwargs["max_runtime_minutes"] == 480
    assert captured_kwargs["parallel_fanout"] == 6


def test_targets_import_cli_passes_min_start_source_count(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    captured_kwargs: dict[str, object] = {}

    def fake_import_targets(**kwargs: object) -> list[object]:
        captured_kwargs.update(kwargs)
        return []

    monkeypatch.setattr("forge.targets_import_cli.import_targets", fake_import_targets)

    app = typer.Typer()
    targets_app = typer.Typer()
    register_target_import_commands(targets_app)
    app.add_typer(targets_app, name="targets")

    result = CliRunner().invoke(
        app,
        [
            "targets",
            "import",
            "--feed-file",
            str(feed_path),
            "--start",
            "--roe-id",
            "ROE-ACME-2026-08",
            "--min-start-source-count",
            "2",
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured_kwargs["min_start_source_count"] == 2


def test_targets_import_cli_dry_run_skips_item_level_unpack_value_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_unpack_error_feed(feed_path)

    def _raise_unpack_error(value: str) -> str:
        raise ValueError("not enough values to unpack (expected 2, got 1)")

    monkeypatch.setattr("forge.targets_import._classify_target_value", _raise_unpack_error)

    app = typer.Typer()
    targets_app = typer.Typer()
    register_target_import_commands(targets_app)
    app.add_typer(targets_app, name="targets")

    result = CliRunner().invoke(
        app,
        [
            "targets",
            "import",
            "--feed-file",
            str(feed_path),
            "--dry-run",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "DRY RUN" in result.output
    assert "1 target(s) parsed and deduped" in result.output
    assert "not enough values to unpack" not in result.output


def test_targets_resume_candidates_cli_outputs_json(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    _write_candidate_run(
        data_dir / "engagements" / "1.db",
        engagement_id=1,
        status="failed",
        error="max iterations exhausted with pending recursive work: 1",
    )

    app = typer.Typer()
    targets_app = typer.Typer()
    register_target_import_commands(targets_app)
    app.add_typer(targets_app, name="targets")

    result = CliRunner().invoke(
        app,
        [
            "targets",
            "resume-candidates",
            "--data-dir",
            str(data_dir),
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["candidate_count"] == 1
    assert payload["resume_ready_count"] == 0
    assert payload["resume_blocker_counts"] == {
        "roe_id_missing": 1,
        "scope_manifest_missing": 1,
    }
    assert payload["items"][0]["reason"] == "pending_recursive_work"
    assert payload["items"][0]["resume_ready"] is False
    assert payload["items"][0]["resume_command"] == []


def test_targets_resume_candidates_cli_accepts_json_flag(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    _write_candidate_run(
        data_dir / "engagements" / "1.db",
        engagement_id=1,
        status="failed",
        error="max iterations exhausted with pending recursive work: 1",
    )

    app = typer.Typer()
    targets_app = typer.Typer()
    register_target_import_commands(targets_app)
    app.add_typer(targets_app, name="targets")

    result = CliRunner().invoke(
        app,
        [
            "targets",
            "resume-candidates",
            "--data-dir",
            str(data_dir),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["candidate_count"] == 1
    assert payload["items"][0]["reason"] == "pending_recursive_work"


def test_normalize_roe_strictness_fail_closed_to_strict() -> None:
    # Known valid values
    assert normalize_roe_strictness("strict") == "strict"
    assert normalize_roe_strictness("STRICT") == "strict"
    assert normalize_roe_strictness(" standard ") == "standard"
    assert normalize_roe_strictness("Permissive") == "permissive"

    # Missing / empty / unknown values fail-closed to "strict"
    assert normalize_roe_strictness(None) == "strict"
    assert normalize_roe_strictness("") == "strict"
    assert normalize_roe_strictness("   ") == "strict"
    assert normalize_roe_strictness("unknown") == "strict"
    assert normalize_roe_strictness("BOGUS") == "strict"
    assert normalize_roe_strictness(12345) == "strict"


def test_resolve_roe_strictness_precedence(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg_strict = _FakeConfig(tmp_path, roe_strictness="strict")
    cfg_standard = _FakeConfig(tmp_path, roe_strictness="standard")
    cfg_permissive = _FakeConfig(tmp_path, roe_strictness="permissive")
    cfg_missing = _FakeConfig(tmp_path)

    # 1. Explicit parameter takes precedence over config and env
    monkeypatch.setenv("FORGE_ROE_STRICTNESS", "permissive")
    assert resolve_roe_strictness("standard", config=cfg_strict) == "standard"
    assert resolve_roe_strictness("permissive", config=cfg_strict) == "permissive"
    assert resolve_roe_strictness("strict", config=cfg_permissive) == "strict"
    assert resolve_roe_strictness("invalid_val", config=cfg_standard) == "strict"

    # 2. Config takes precedence over env when parameter is None
    assert resolve_roe_strictness(None, config=cfg_standard) == "standard"
    assert resolve_roe_strictness(None, config=cfg_permissive) == "permissive"
    cfg_invalid = _FakeConfig(tmp_path, roe_strictness="bad")
    assert resolve_roe_strictness(None, config=cfg_invalid) == "strict"

    # 3. Environment variable used when config is None or has no roe_strictness attribute
    assert resolve_roe_strictness(None, config=cfg_missing) == "permissive"
    assert resolve_roe_strictness(None, config=None) == "permissive"
    monkeypatch.setenv("FORGE_ROE_STRICTNESS", "standard")
    assert resolve_roe_strictness(None, config=cfg_missing) == "standard"
    assert resolve_roe_strictness(None, config=None) == "standard"
    monkeypatch.setenv("FORGE_ROE_STRICTNESS", "not_a_valid_mode")
    assert resolve_roe_strictness(None, config=cfg_missing) == "strict"
    assert resolve_roe_strictness(None, config=None) == "strict"

    # 4. Defaults to strict when env is unset
    monkeypatch.delenv("FORGE_ROE_STRICTNESS", raising=False)
    assert resolve_roe_strictness(None, config=cfg_missing) == "strict"
    assert resolve_roe_strictness(None, config=None) == "strict"


def test_import_targets_strict_roe_gives_strict_caps(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Proves (a) strict ROE gives strict caps (effective fanout 2 for domain)."""
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data", roe_strictness="strict")
    calls: list[list[str]] = []

    def _fake_run(command: list[str], **_: object) -> object:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr("forge.targets_import.run_contained_subprocess", _fake_run)
    monkeypatch.setattr("forge.autopilot.breaker.check_resource_pressure", lambda: (False, ""))

    # Via explicit parameter
    results = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-TEST",
        start=True,
        dry_run=False,
        limit=1,
        max_iter=3,
        parallel_fanout=8,
        roe_strictness="strict",
        config=cfg,  # type: ignore[arg-type]
    )
    assert results[0].started is True
    assert calls[0][-4:] == ["--max-runtime-minutes", "480", "--parallel-fanout", "2"]


def test_import_targets_unknown_missing_strictness_fail_closed_to_strict(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Proves (b) unknown/missing strictness fails-closed to strict (fanout 2)."""
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg_no_attr = _FakeConfig(tmp_path / "data")
    calls: list[list[str]] = []

    def _fake_run(command: list[str], **_: object) -> object:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr("forge.targets_import.run_contained_subprocess", _fake_run)
    monkeypatch.setattr("forge.autopilot.breaker.check_resource_pressure", lambda: (False, ""))

    # Case 1: missing parameter, config without roe_strictness, env unset
    monkeypatch.delenv("FORGE_ROE_STRICTNESS", raising=False)
    import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-TEST",
        start=True,
        dry_run=False,
        limit=1,
        max_iter=3,
        parallel_fanout=8,
        config=cfg_no_attr,  # type: ignore[arg-type]
    )
    assert calls[0][-4:] == ["--max-runtime-minutes", "480", "--parallel-fanout", "2"]

    # Case 2: unknown/garbage parameter
    calls.clear()
    import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-TEST",
        start=True,
        dry_run=False,
        limit=1,
        max_iter=3,
        parallel_fanout=8,
        roe_strictness="bogus_mode",
        config=cfg_no_attr,  # type: ignore[arg-type]
    )
    assert calls[0][-4:] == ["--max-runtime-minutes", "480", "--parallel-fanout", "2"]

    # Case 3: invalid env var fails closed
    calls.clear()
    monkeypatch.setenv("FORGE_ROE_STRICTNESS", "unsupported_level")
    import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-TEST",
        start=True,
        dry_run=False,
        limit=1,
        max_iter=3,
        parallel_fanout=8,
        config=cfg_no_attr,  # type: ignore[arg-type]
    )
    assert calls[0][-4:] == ["--max-runtime-minutes", "480", "--parallel-fanout", "2"]


def test_import_targets_standard_and_permissive_behave_as_before(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Proves (c) standard and permissive explicit configurations behave as before (caps 4 and 6 for domain)."""
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg_standard = _FakeConfig(tmp_path / "data", roe_strictness="standard")
    cfg_permissive = _FakeConfig(tmp_path / "data", roe_strictness="permissive")
    cfg_standard.autopilot_global_slots = 8
    cfg_permissive.autopilot_global_slots = 8
    calls: list[list[str]] = []

    def _fake_run(command: list[str], **_: object) -> object:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr("forge.targets_import.run_contained_subprocess", _fake_run)
    monkeypatch.setattr("forge.autopilot.breaker.check_resource_pressure", lambda: (False, ""))

    # 1. Explicit standard config -> cap 4
    import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-TEST",
        start=True,
        dry_run=False,
        limit=1,
        max_iter=3,
        parallel_fanout=8,
        config=cfg_standard,  # type: ignore[arg-type]
    )
    assert calls[0][-4:] == ["--max-runtime-minutes", "480", "--parallel-fanout", "4"]

    # 2. Explicit permissive config -> cap 6 for medium surface domain
    calls.clear()
    import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-TEST",
        start=True,
        dry_run=False,
        limit=1,
        max_iter=3,
        parallel_fanout=8,
        config=cfg_permissive,  # type: ignore[arg-type]
    )
    assert calls[0][-4:] == ["--max-runtime-minutes", "480", "--parallel-fanout", "6"]

    # 3. Explicit standard via parameter overriding config
    calls.clear()
    import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-TEST",
        start=True,
        dry_run=False,
        limit=1,
        max_iter=3,
        parallel_fanout=8,
        roe_strictness="standard",
        config=cfg_permissive,  # type: ignore[arg-type]
    )
    assert calls[0][-4:] == ["--max-runtime-minutes", "480", "--parallel-fanout", "4"]

    # 4. Standard via FORGE_ROE_STRICTNESS environment variable
    calls.clear()
    cfg_plain = _FakeConfig(tmp_path / "data")
    monkeypatch.setenv("FORGE_ROE_STRICTNESS", "standard")
    import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-TEST",
        start=True,
        dry_run=False,
        limit=1,
        max_iter=3,
        parallel_fanout=8,
        config=cfg_plain,  # type: ignore[arg-type]
    )
    assert calls[0][-4:] == ["--max-runtime-minutes", "480", "--parallel-fanout", "4"]


def test_targets_import_cli_roe_strictness_option(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    def _fake_import_targets(**kwargs: object) -> list[object]:
        captured.update(kwargs)
        return []

    monkeypatch.setattr("forge.targets_import_cli.import_targets", _fake_import_targets)
    app = typer.Typer()
    targets_app = typer.Typer()
    register_target_import_commands(targets_app)
    app.add_typer(targets_app, name="targets")

    feed_file = tmp_path / "feed.json"
    feed_file.write_text("{}", encoding="utf-8")

    result = CliRunner().invoke(
        app,
        [
            "targets",
            "import",
            "--feed-file",
            str(feed_file),
            "--roe-strictness",
            "standard",
        ],
    )
    assert result.exit_code == 0, result.output
    assert captured["roe_strictness"] == "standard"
