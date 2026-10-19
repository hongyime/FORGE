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
from forge.opsec.scope_gate import ScopeViolationError, assert_in_scope, assert_url_in_scope
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


def test_governance_scope_gate_never_authorizes_roe_wildcard() -> None:
    gate = ScopeGate(EngagementScope(roe_scope="*"))

    assert not gate.is_in_scope("thirdparty.example")
    assert not gate.is_in_scope("https://unrelated.example/path")
    assert not gate.is_in_scope("192.0.2.1")


def test_cli_scope_loader_rejects_wildcard_authorization(
    tmp_path: Path,
) -> None:
    exact_seed_manifest = _load_scope_manifest(json.dumps({"exact_seeds": ["*"]}))
    assert _scope_manifest_broad_reasons(exact_seed_manifest)
    validation = _validate_scope_manifest_seed_values(
        exact_seed_manifest,
        [{"value": "thirdparty.example.net", "seed_type": "domain"}],
    )
    assert not validation["authorized"]

    with pytest.raises(typer.BadParameter, match="wildcard scope entries do not authorize"):
        _direct_cli_load_scope_lists(
            engagement_id=1001,
            db_path=tmp_path / "engagement.db",
            scope_manifest=json.dumps({"scope": "*"}),
            target="thirdparty.example.net",
            seed_type="domain",
        )


def test_opsec_scope_gate_rejects_broad_wildcards() -> None:
    with pytest.raises(ScopeViolationError):
        assert_in_scope("thirdparty.example", ["*"])
    with pytest.raises(ScopeViolationError):
        assert_in_scope("192.168.1.20", ["0.0.0.0/0"])
    with pytest.raises(ScopeViolationError):
        assert_url_in_scope("https://unrelated.example/admin", ["*"])


def test_post_boundary_gate_reads_wildcard_scope_json(tmp_path: Path) -> None:
    db_path = tmp_path / "engagement.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE engagements (id INTEGER PRIMARY KEY, scope_json TEXT)")
        conn.execute(
            "INSERT INTO engagements (id, scope_json) VALUES (?, ?)",
            (1001, json.dumps({"roe_scope": "*"})),
        )

    assert not boundary_is_in_scope("https://thirdparty.example/path", 1001, db_path)


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


def test_target_import_rejects_wildcard_authorization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "feed.json"
    _write_feed(feed_path)
    cfg = _TestConfig(tmp_path / "data")
    monkeypatch.setenv("FORGE_ROE_SCOPE", "*")
    with pytest.raises(ValueError, match="human-set specific FORGE_SCOPE_JSON"):
        import_targets(
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


def test_resume_manifest_replaces_wildcard_with_specific_seed_scope(tmp_path: Path) -> None:
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
    assert "roe_scope" not in recovered
    assert recovered["domains"] == ["thirdparty.example.org"]
    assert "thirdparty.example.org" in recovered["authorized_seeds"]


def test_auto_scope_requires_human_review_for_wildcard_scope_candidates(tmp_path: Path) -> None:
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

    assert not expansion.accepted
    assert expansion.review_required
    assert expansion.review_required[0].reason == "unrelated_to_scope"


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
