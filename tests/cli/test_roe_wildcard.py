from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from forge.governance.scope_gate import EngagementScope, ScopeGate, is_roe_wildcard
from forge.cli_helpers import (
    _direct_cli_load_scope_lists,
    _load_scope_manifest,
    _scope_manifest_broad_reasons,
    _validate_scope_manifest_seed_values,
)
from forge.onboard.auto_scope import expand_scope_from_feeds
from forge.opsec.scope_gate import assert_in_scope, assert_url_in_scope
from forge.targets_import import import_targets, target_scan_eligible
from forge.targets_import_cli import register_target_import_commands
from forge.targets_resume_candidates import (
    _engagement_scope_json,
    _recovered_scope_manifest_payload,
)
from forge.utils.post.boundary_check import is_in_scope as boundary_is_in_scope


@pytest.mark.parametrize(
    "scope",
    [
        {"roe_scope": "*"},
        {"scope": "*"},
        {"domains": ["*"]},
        {"urls": ["*"]},
        {"authorized_seeds": ["*"]},
        {"exact_seeds": ["*"]},
        {"ip_ranges": ["0.0.0.0/0"]},
        {"ip_ranges": ["::/0"]},
    ],
)
def test_canonical_detector_recognizes_roe_wildcard(scope: dict[str, object]) -> None:
    assert is_roe_wildcard(scope)


def test_governance_scope_gate_allows_every_target_under_roe_wildcard() -> None:
    gate = ScopeGate(EngagementScope(roe_scope="*"))

    assert gate.is_in_scope("thirdparty.example")
    assert gate.is_in_scope("https://unrelated.example/path")
    assert gate.is_in_scope("192.0.2.1")


def test_cli_scope_loader_accepts_exact_seed_and_scope_alias_wildcards(
    tmp_path: Path,
) -> None:
    exact_seed_manifest = _load_scope_manifest(json.dumps({"exact_seeds": ["*"]}))
    assert _scope_manifest_broad_reasons(exact_seed_manifest)
    validation = _validate_scope_manifest_seed_values(
        exact_seed_manifest,
        [{"value": "thirdparty.example.net", "seed_type": "domain"}],
    )
    assert validation["authorized"]

    scope, urls = _direct_cli_load_scope_lists(
        engagement_id=1001,
        db_path=tmp_path / "engagement.db",
        scope_manifest=json.dumps({"scope": "*"}),
        target="thirdparty.example.net",
        seed_type="domain",
    )
    assert "*" in scope
    assert urls == []


def test_opsec_scope_gate_and_match_helper_allow_roe_wildcard() -> None:
    assert_in_scope("thirdparty.example", ["*"])
    assert_in_scope("192.168.1.20", ["0.0.0.0/0"])
    assert_url_in_scope("https://unrelated.example/admin", ["*"])


def test_post_boundary_gate_reads_wildcard_scope_json(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE engagements (id INTEGER PRIMARY KEY, scope_json TEXT)")
        conn.execute(
            "INSERT INTO engagements (id, scope_json) VALUES (?, ?)",
            (1001, json.dumps({"roe_scope": "*"})),
        )

    assert boundary_is_in_scope("https://thirdparty.example/path", 1001, db_path)


class _TestConfig:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.operator = "test-operator"

    def engagement_db_path(self, engagement_id: str) -> Path:
        return self.data_dir / "engagements" / f"{engagement_id}.db"


def _write_feed(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": "target-feed.v1",
                "items": [{"target_type": "domain", "target_value": "portal.corp-target.io"}],
            }
        ),
        encoding="utf-8",
    )


def test_target_import_writes_wildcard_manifest_and_engagement_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _TestConfig(tmp_path / "data")
    monkeypatch.setenv("FORGE_ROE_SCOPE", "*")
    monkeypatch.setattr("forge.targets_import._ensure_target_import_monitoring", lambda *_a, **_k: None)

    results = import_targets(
        feed_url=None,
        feed_file=feed_path,
        auth_header_env=None,
        roe_id="ROE-TEST",
        start=False,
        dry_run=False,
        limit=None,
        max_iter=3,
        config=cfg,  # type: ignore[arg-type]
    )

    assert len(results) == 1
    manifest = json.loads(Path(str(results[0].scope_manifest)).read_text(encoding="utf-8"))
    assert manifest["roe_scope"] == "*"
    assert manifest["domains"] == ["*"]
    assert manifest["authorized_seeds"] == ["*"]
    assert manifest["ip_ranges"] == ["0.0.0.0/0", "::/0"]
    assert manifest["urls"] == ["*"]

    db_path = cfg.engagement_db_path(str(results[0].engagement_id))
    with sqlite3.connect(db_path) as conn:
        scope_json = json.loads(
            conn.execute("SELECT scope_json FROM engagements WHERE id=?", (results[0].engagement_id,)).fetchone()[0]
        )
    assert is_roe_wildcard(scope_json)
    assert scope_json["domains"] == ["*"]


def test_target_import_cli_accepts_roe_scope_option(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    calls: list[dict[str, object]] = []

    def _fake_import_targets(**kwargs: object) -> list[object]:
        calls.append(kwargs)
        return []

    monkeypatch.setattr("forge.targets_import_cli.import_targets", _fake_import_targets)
    app = typer.Typer()
    register_target_import_commands(app)

    result = CliRunner().invoke(
        app,
        ["import", "--feed-file", str(feed_path), "--dry-run", "--roe-scope", "*"],
    )

    assert result.exit_code == 0, result.output
    assert calls[0]["roe_scope"] == "*"


def test_resume_manifest_backfill_preserves_roe_wildcard(tmp_path: Path) -> None:
    db_path = tmp_path / "engagements" / "1001.db"
    db_path.parent.mkdir(parents=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE engagements (id INTEGER PRIMARY KEY, scope_json TEXT)")
        conn.execute(
            "INSERT INTO engagements (id, scope_json) VALUES (?, ?)",
            (1001, json.dumps({"roe_scope": "*", "domains": ["*"]})),
        )

    assert is_roe_wildcard(_engagement_scope_json(db_path))
    recovered = _recovered_scope_manifest_payload(
        db_path,
        engagement_id=1001,
        seed_value="thirdparty.example.org",
        seed_type="domain",
        roe_id="ROE-TEST",
    )
    assert recovered["roe_scope"] == "*"
    assert recovered["domains"] == ["*"]
    assert "thirdparty.example.org" in recovered["authorized_seeds"]


def test_auto_scope_accepts_third_party_candidates_under_roe_wildcard(tmp_path: Path) -> None:
    manifest_path = tmp_path / "scope.json"
    manifest_path.write_text(json.dumps({"roe_scope": "*"}), encoding="utf-8")

    expansion = expand_scope_from_feeds(
        manifest_path,
        [
            "portal.corp-target.io",
            "company.com",
            "http://[::1",
        ],
        apply=False,
    )

    assert [item.value for item in expansion.accepted] == ["portal.corp-target.io"]
    assert not expansion.review_required


def test_target_scan_import_still_rejects_private_ip_addresses() -> None:
    assert target_scan_eligible("ipv4", "192.168.1.20") == (False, "non_global_ip")
    assert target_scan_eligible("url", "http://127.0.0.1/private") == (
        False,
        "non_global_url_host",
    )


def test_default_manifest_declares_roe_wildcard_and_import_safety_note() -> None:
    manifest_path = Path(__file__).parents[2] / "manifests" / "default.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert manifest["roe_scope"] == "*"
    assert manifest["domains"] == ["*"]
    assert manifest["authorized_seeds"] == ["*"]
    assert manifest["ip_ranges"] == ["0.0.0.0/0", "::/0"]
    assert manifest["urls"] == ["*"]
    assert "private/reserved IPs" in manifest["_note"]
    assert "no scope gate" in manifest["_note"]
