from __future__ import annotations

import json
import sqlite3
import subprocess
from pathlib import Path

import pytest

from forge.targets_import import import_targets, load_target_feed


class _FakeConfig:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.operator = "tester"

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
                        "target_value": "Example.COM",
                        "source_kind": "telemetry",
                        "confidence": 0.9,
                        "first_seen_at": "2026-08-07T00:00:00Z",
                        "provenance": "network_domain",
                        "token": "must-not-persist",
                    },
                    {
                        "target_type": "domain",
                        "target_value": "example.com",
                        "source_kind": "duplicate",
                        "confidence": 0.1,
                        "first_seen_at": "2026-08-07T00:00:00Z",
                        "provenance": "duplicate",
                    },
                    {
                        "target_type": "url",
                        "target_value": "HTTPS://App.Example.COM/Login?secret=drop",
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
    assert domain_result.target_value == "example.com"
    assert domain_result.scope_manifest is not None
    manifest = json.loads(domain_result.scope_manifest.read_text(encoding="utf-8"))
    assert manifest["roe_id"] == "ROE-ACME-2026-08"
    assert manifest["domains"] == ["example.com"]
    assert manifest["urls"] == []

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
    assert metadata["provenance_summary"] == "network_domain"
    persisted = json.dumps(metadata)
    assert "must-not-persist" not in persisted
    assert json.loads(row[0]) == {"domains": ["example.com"], "urls": []}


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


def test_start_launches_passive_kill_chain_with_scope_and_roe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _FakeConfig(tmp_path / "data")
    calls: list[list[str]] = []

    def _fake_run(command: list[str], *, check: bool) -> object:
        calls.append(command)
        assert check is True
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr("forge.targets_import.subprocess.run", _fake_run)

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
    )

    assert results[0].started is True
    command = calls[0]
    assert command[2:4] == ["forge.cli", "kill-chain"]
    assert "--roe-id" in command
    assert "--scope-manifest" in command
    assert "--max-iter" in command
    assert "--no-attack-mode" in command
    assert "--no-auto-run-detected" in command
    assert "--attack-mode" not in command
    assert "--auto-run-detected" not in command


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
                        "target_value": "example.com",
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
