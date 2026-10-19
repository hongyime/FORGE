"""Tests for the autopilot ``auto_scope`` phase.

Verifies the new phase is wired after ``feed_build`` / before
``import_targets``, that it is skipped when no scope manifest is
configured, that it expands scope for subdomains of already-scoped
domains, and that dry-run leaves the on-disk manifest untouched.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from forge.autopilot import AutopilotDefaults, ForgeAutopilot


@dataclass
class _FakeConfig:
    data_dir: Path
    safe_mode: bool = False
    operator: str = "tester"


def _mk_autopilot(
    tmp_path: Path,
    *,
    scope_manifest: Path | None = None,
    safe_mode: bool = False,
) -> ForgeAutopilot:
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    imports_dir = tmp_path / "imports"
    imports_dir.mkdir(parents=True, exist_ok=True)
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    return ForgeAutopilot(
        data_dir=data_dir,
        imports_dir=imports_dir,
        reports_dir=reports_dir,
        feed_file=imports_dir / "target-feed.json",
        roe_id="ROE-TEST",
        scope_manifest=scope_manifest,
        safe_mode=safe_mode,
        defaults=AutopilotDefaults(),
        config=_FakeConfig(data_dir=data_dir),  # type: ignore[arg-type]
    )


def _write_feed(
    path: Path,
    items: list[dict] | None = None,
) -> None:
    payload = {
        "schema_version": "target-feed.v1",
        "generated_at": "2026-10-11T00:00:00+00:00",
        "items": items or [],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_auto_scope_phase_is_wired_after_feed_build(tmp_path: Path) -> None:
    autopilot = _mk_autopilot(tmp_path)
    phases = list(autopilot._PHASE_DISPATCH.keys())
    assert phases.index("auto_scope") == phases.index("feed_build") + 1
    assert phases.index("auto_scope") < phases.index("import_targets")


def test_auto_scope_skipped_without_scope_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    autopilot = _mk_autopilot(tmp_path, scope_manifest=None)
    result = autopilot._phase_auto_scope(dry_run=False)
    assert result.status == "skipped"
    assert "no_scope_manifest_configured" in result.detail


def test_auto_scope_skipped_without_feed_file(tmp_path: Path) -> None:
    manifest = tmp_path / "manifests" / "default.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        json.dumps({"domains": ["corp-target.io"], "urls": [], "ip_ranges": []}),
        encoding="utf-8",
    )
    autopilot = _mk_autopilot(tmp_path, scope_manifest=manifest)
    result = autopilot._phase_auto_scope(dry_run=False)
    assert result.status == "skipped"
    assert "no_feed_file_present" in result.detail


def test_auto_scope_queues_subdomain_for_human_review(tmp_path: Path) -> None:
    manifest = tmp_path / "manifests" / "default.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        json.dumps(
            {
                "domains": ["corp-target.io"],
                "urls": [],
                "ip_ranges": [],
                "authorized_seeds": [],
            }
        ),
        encoding="utf-8",
    )
    autopilot = _mk_autopilot(tmp_path, scope_manifest=manifest)
    _write_feed(
        autopilot.feed_file,
        items=[
            {"target_type": "domain", "target_value": "api.corp-target.io"},
            {"target_type": "domain", "target_value": "unrelated.net"},
        ],
    )
    result = autopilot._phase_auto_scope(dry_run=False)
    assert result.status == "ok"
    assert result.data["accepted_count"] == 0
    assert result.data["review_required_count"] == 2
    stored = json.loads(manifest.read_text(encoding="utf-8"))
    assert stored["domains"] == ["corp-target.io"]


def test_auto_scope_skips_placeholder_hosts_from_stale_feed(tmp_path: Path) -> None:
    manifest = tmp_path / "manifests" / "default.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        json.dumps({"domains": ["corp-target.io"], "urls": [], "ip_ranges": []}),
        encoding="utf-8",
    )
    autopilot = _mk_autopilot(tmp_path, scope_manifest=manifest)
    _write_feed(
        autopilot.feed_file,
        items=[
            {"target_type": "domain", "target_value": "company.com"},
            {"target_type": "domain", "target_value": "api.company.com"},
        ],
    )

    result = autopilot._phase_auto_scope(dry_run=False)

    assert result.status == "ok"
    assert result.data["accepted_count"] == 0
    stored = json.loads(manifest.read_text(encoding="utf-8"))
    assert stored["domains"] == ["corp-target.io"]


def test_auto_scope_dry_run_does_not_write(tmp_path: Path) -> None:
    manifest = tmp_path / "manifests" / "default.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        json.dumps({"domains": ["corp-target.io"]}),
        encoding="utf-8",
    )
    pre_mtime = manifest.stat().st_mtime_ns
    autopilot = _mk_autopilot(tmp_path, scope_manifest=manifest)
    _write_feed(
        autopilot.feed_file,
        items=[{"target_type": "domain", "target_value": "api.corp-target.io"}],
    )
    result = autopilot._phase_auto_scope(dry_run=True)
    assert result.status == "ok"
    assert result.data["dry_run"] is True
    assert manifest.stat().st_mtime_ns == pre_mtime
    stored = json.loads(manifest.read_text(encoding="utf-8"))
    assert stored["domains"] == ["corp-target.io"]


def test_auto_scope_in_full_pass_appears_after_feed_build(tmp_path: Path) -> None:
    """``run_once`` should emit ``auto_scope`` between feed_build and import_targets."""
    manifest = tmp_path / "manifests" / "default.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        json.dumps({"domains": ["corp-target.io"]}),
        encoding="utf-8",
    )
    autopilot = _mk_autopilot(tmp_path, scope_manifest=manifest, safe_mode=True)
    _write_feed(
        autopilot.feed_file,
        items=[{"target_type": "domain", "target_value": "api.corp-target.io"}],
    )
    payload = autopilot.run_once()  # safe_mode forces dry-run
    phase_names = [p["name"] for p in payload["phases"]]
    assert phase_names.index("auto_scope") == phase_names.index("feed_build") + 1
    assert phase_names.index("auto_scope") < phase_names.index("import_targets")
