"""Tests for the autopilot ``connected_services_scan`` phase.

Verifies the phase is wired after ``feed_fetch`` / before ``feed_build``,
is skipped when no connections are stored, invokes the deep scanner
with the stored credentials, writes seed drops to ``imports/``, and
contains per-service failures rather than aborting the whole loop.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from forge.autopilot import AutopilotDefaults, ForgeAutopilot


@dataclass
class _FakeConfig:
    data_dir: Path
    safe_mode: bool = False
    operator: str = "tester"


def _mk_autopilot(tmp_path: Path) -> ForgeAutopilot:
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
        scope_manifest=None,
        safe_mode=False,
        defaults=AutopilotDefaults(),
        config=_FakeConfig(data_dir=data_dir),  # type: ignore[arg-type]
    )


def _store_github_connection(data_dir: Path, token: str = "ghp_token") -> None:
    from forge.onboard.service_connections import ServiceConnectionManager

    manager = ServiceConnectionManager(data_dir)
    manager.add_connection(
        "github",
        token=token,
        orgs=["myorg"],
        users=["myuser"],
        credential_sources={"token": "env:FORGE_GITHUB_TOKEN"},
    )


def _store_supabase_connection(
    data_dir: Path,
    *,
    project_ref: str = "abc123",
    key: str | None = "anon-key",
    management_pat: str | None = None,
) -> None:
    from forge.onboard.service_connections import ServiceConnectionManager

    manager = ServiceConnectionManager(data_dir)
    fields: dict[str, Any] = {"project_ref": project_ref}
    sources: dict[str, str] = {}
    if key:
        fields["key"] = key
        sources["key"] = "env:FORGE_SUPABASE_KEY"
    if management_pat:
        fields["management_pat"] = management_pat
        sources["management_pat"] = "env:FORGE_SUPABASE_PAT"
    manager.add_connection("supabase", credential_sources=sources, **fields)


# ---------------------------------------------------------------------------
# Phase ordering
# ---------------------------------------------------------------------------


def test_connected_services_scan_phase_is_registered(tmp_path: Path) -> None:
    auto = _mk_autopilot(tmp_path)
    assert "connected_services_scan" in auto._PHASE_DISPATCH


def test_connected_services_scan_runs_after_feed_fetch(tmp_path: Path) -> None:
    auto = _mk_autopilot(tmp_path)
    phases = list(auto._PHASE_DISPATCH.keys())
    assert phases.index("connected_services_scan") == phases.index("feed_fetch") + 1
    assert phases.index("connected_services_scan") < phases.index("feed_build")


# ---------------------------------------------------------------------------
# No-op when no connections stored
# ---------------------------------------------------------------------------


def test_phase_skipped_without_connections(tmp_path: Path) -> None:
    auto = _mk_autopilot(tmp_path)
    result = auto._phase_connected_services_scan(dry_run=False)
    assert result.status == "skipped"
    assert "no_service_connections_stored" in result.detail


# ---------------------------------------------------------------------------
# Dry-run never spiders
# ---------------------------------------------------------------------------


def test_phase_dry_run_skips_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _store_github_connection(tmp_path / "data")

    def _boom(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("GitHubDeepScanner must not be invoked in dry-run")

    monkeypatch.setattr(
        "forge.onboard.github_spider.GitHubDeepScanner",
        _boom,
    )
    auto = _mk_autopilot(tmp_path)
    result = auto._phase_connected_services_scan(dry_run=True)
    assert result.status == "ok"
    assert result.data["dry_run"] is True
    github_entry = next(
        s for s in result.data["services"] if s["service"] == "github"
    )
    assert github_entry["status"] == "skipped"
    assert "dry_run_skips_network_scan" in github_entry["detail"]


# ---------------------------------------------------------------------------
# Apply: GitHub + Supabase scanning
# ---------------------------------------------------------------------------


def test_phase_apply_runs_github_scanner_and_writes_seed_drop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _store_github_connection(tmp_path / "data")

    class _FakeScanner:
        def __init__(self, token: str, **kwargs: Any) -> None:
            self.token = token
            self.kwargs = kwargs

        def scan_all(self, *, orgs=None, users=None) -> Any:  # noqa: ANN001
            from forge.onboard.github_spider import GitHubSpiderResult

            return GitHubSpiderResult(
                repos_scanned=3,
                repos_total=5,
                orgs_scanned=list(orgs or []),
                users_scanned=list(users or []),
                seeds=[
                    {
                        "target_type": "domain",
                        "target_value": "corp-target.io",
                        "type": "domain",
                        "value": "corp-target.io",
                        "confidence": "medium",
                        "source_kind": "github_spider",
                        "source_group": "github_spider",
                        "provenance": "myorg/webapp:readme",
                        "first_seen_at": "2026-10-11T00:00:00+00:00",
                        "source_detail": "",
                    }
                ],
                secret_hits=[
                    {
                        "label": "aws_access_key",
                        "redacted_sample": "AKIA...MPLE",
                        "repo": "myorg/webapp",
                        "source": "readme",
                    }
                ],
            )

    monkeypatch.setattr(
        "forge.onboard.github_spider.GitHubDeepScanner",
        _FakeScanner,
    )
    auto = _mk_autopilot(tmp_path)
    result = auto._phase_connected_services_scan(dry_run=False)
    assert result.status == "ok"

    github_entry = next(
        s for s in result.data["services"] if s["service"] == "github"
    )
    assert github_entry["status"] == "ok"
    assert github_entry["seeds"] == 1
    assert github_entry["secret_hits"] == 1
    assert github_entry["repos_scanned"] == 3

    seed_drop = tmp_path / "imports" / "connected-services-github-seeds.local.json"
    assert seed_drop.is_file()
    payload = json.loads(seed_drop.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "forge.connected_services_scan.v1"
    assert payload["connector_id"] == "github_deep_spider"
    assert len(payload["seeds"]) == 1
    assert payload["seeds"][0]["target_value"] == "corp-target.io"
    # Secret-hit redaction preserved end-to-end.
    assert payload["secret_hits"][0]["redacted_sample"] == "AKIA...MPLE"
    assert "AKIAIOSFODNN7EXAMPLE" not in seed_drop.read_text(encoding="utf-8")


def test_phase_apply_runs_supabase_scanner_and_writes_seed_drop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _store_supabase_connection(tmp_path / "data")

    class _FakeScanner:
        def __init__(self, project_ref: str, api_key: str, **kwargs: Any) -> None:
            self.project_ref = project_ref
            self.api_key = api_key
            self.kwargs = kwargs

        def scan_all(self) -> Any:
            from forge.onboard.supabase_scanner import (
                SupabaseScanResult,
                SupabaseTableSummary,
            )

            return SupabaseScanResult(
                project_ref=self.project_ref,
                base_url=f"https://{self.project_ref}.supabase.co",
                tables_total=1,
                tables_scanned=1,
                rows_scanned=50,
                seeds=[
                    {
                        "target_type": "email",
                        "target_value": "admin@corp-target.io",
                        "type": "email",
                        "value": "admin@corp-target.io",
                        "confidence": "high",
                        "source_kind": "supabase_scanner",
                        "source_group": "supabase_scanner",
                        "provenance": "supabase:abc123:users:row_1:email",
                        "first_seen_at": "2026-10-11T00:00:00+00:00",
                        "source_detail": "",
                    }
                ],
                tables=[
                    SupabaseTableSummary(
                        name="users",
                        rows_scanned=50,
                        seeds_added=1,
                        secret_hits=0,
                    )
                ],
            )

    monkeypatch.setattr(
        "forge.onboard.supabase_scanner.SupabaseDeepScanner",
        _FakeScanner,
    )
    auto = _mk_autopilot(tmp_path)
    result = auto._phase_connected_services_scan(dry_run=False)
    assert result.status == "ok"

    supabase_entry = next(
        s for s in result.data["services"] if s["service"] == "supabase"
    )
    assert supabase_entry["status"] == "ok"
    assert supabase_entry["tables_scanned"] == 1
    assert supabase_entry["rows_scanned"] == 50
    assert supabase_entry["seeds"] == 1

    seed_drop = tmp_path / "imports" / "connected-services-supabase-seeds.local.json"
    assert seed_drop.is_file()
    payload = json.loads(seed_drop.read_text(encoding="utf-8"))
    assert payload["connector_id"] == "supabase_deep_scanner"
    assert payload["project_ref"] == "abc123"
    assert payload["transport"] == "postgrest"
    assert len(payload["seeds"]) == 1


def test_phase_supabase_uses_management_pat_from_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _store_supabase_connection(tmp_path / "data", key=None)
    monkeypatch.setenv("FORGE_SUPABASE_PAT", "sbp_test_placeholder")
    captured: dict[str, Any] = {}

    class _FakeScanner:
        def __init__(
            self,
            project_ref: str,
            api_key: str | None,
            *,
            management_pat: str | None = None,
            **_kwargs: Any,
        ) -> None:
            captured.update(
                {
                    "project_ref": project_ref,
                    "api_key": api_key,
                    "management_pat": management_pat,
                }
            )

        def scan_all(self) -> Any:
            from forge.onboard.supabase_scanner import SupabaseScanResult

            return SupabaseScanResult(
                project_ref="abc123",
                tables_scanned=1,
                rows_scanned=1,
                seeds=[{"target_type": "email", "target_value": "ops@corp-target.io"}],
            )

    monkeypatch.setattr(
        "forge.onboard.supabase_scanner.SupabaseDeepScanner", _FakeScanner
    )
    result = _mk_autopilot(tmp_path)._phase_connected_services_scan(dry_run=False)
    supabase_entry = next(
        service for service in result.data["services"] if service["service"] == "supabase"
    )
    assert supabase_entry["status"] == "ok"
    assert supabase_entry["seeds"] == 1
    assert captured == {
        "project_ref": "abc123",
        "api_key": None,
        "management_pat": "sbp_test_placeholder",
    }
    payload = json.loads(
        (tmp_path / "imports" / "connected-services-supabase-seeds.local.json").read_text(
            encoding="utf-8"
        )
    )
    assert payload["transport"] == "management_api"


# ---------------------------------------------------------------------------
# Isolation between services
# ---------------------------------------------------------------------------


def test_phase_one_bad_service_does_not_block_others(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A GitHub failure must not prevent the Supabase scan from running."""
    _store_github_connection(tmp_path / "data")
    _store_supabase_connection(tmp_path / "data")

    class _BoomScanner:
        def __init__(self, *_a: Any, **_kw: Any) -> None:
            raise RuntimeError("github auth revoked")

    class _OKScanner:
        def __init__(self, project_ref: str, api_key: str, **_kw: Any) -> None:
            self.project_ref = project_ref
            self.api_key = api_key

        def scan_all(self) -> Any:
            from forge.onboard.supabase_scanner import SupabaseScanResult

            return SupabaseScanResult(
                project_ref=self.project_ref,
                base_url=f"https://{self.project_ref}.supabase.co",
                tables_total=0,
                tables_scanned=0,
                rows_scanned=0,
            )

    monkeypatch.setattr(
        "forge.onboard.github_spider.GitHubDeepScanner", _BoomScanner
    )
    monkeypatch.setattr(
        "forge.onboard.supabase_scanner.SupabaseDeepScanner", _OKScanner
    )

    auto = _mk_autopilot(tmp_path)
    result = auto._phase_connected_services_scan(dry_run=False)
    # Overall status is "error" because one service failed, but the
    # Supabase scanner still ran.
    assert result.status == "error"
    github_entry = next(
        s for s in result.data["services"] if s["service"] == "github"
    )
    supabase_entry = next(
        s for s in result.data["services"] if s["service"] == "supabase"
    )
    assert github_entry["status"] == "error"
    assert "github auth revoked" in github_entry["detail"]
    assert supabase_entry["status"] == "ok"


# ---------------------------------------------------------------------------
# Services without a deep scanner are reported, not crashed
# ---------------------------------------------------------------------------


def test_phase_unknown_service_reports_no_deep_scanner(tmp_path: Path) -> None:
    from forge.onboard.service_connections import ServiceConnectionManager

    manager = ServiceConnectionManager(tmp_path / "data")
    manager.add_connection(
        "shodan",
        key="shodan-key",
        credential_sources={"key": "env:FORGE_SHODAN_API_KEY"},
    )
    auto = _mk_autopilot(tmp_path)
    result = auto._phase_connected_services_scan(dry_run=False)
    assert result.status == "ok"
    shodan_entry = next(
        s for s in result.data["services"] if s["service"] == "shodan"
    )
    assert shodan_entry["status"] == "skipped"
    assert "no_deep_scanner_for_service" in shodan_entry["detail"]


# ---------------------------------------------------------------------------
# Service with missing config fields is skipped, not crashed
# ---------------------------------------------------------------------------


def test_phase_github_without_token_is_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A github connection with an empty token value is noisily skipped."""
    from forge.onboard.service_connections import (
        ServiceConnection,
        ServiceConnectionManager,
    )

    manager = ServiceConnectionManager(tmp_path / "data")
    # Hand-write a connection with an empty token to simulate corruption.
    connection = ServiceConnection(
        service="github",
        added_at="2026-10-11T00:00:00+00:00",
        config={"token": "", "orgs": ["myorg"]},
        credential_sources={"token": "env:FORGE_GITHUB_TOKEN"},
    )
    manager._write_connections([connection])  # type: ignore[attr-defined]

    auto = _mk_autopilot(tmp_path)
    result = auto._phase_connected_services_scan(dry_run=False)
    github_entry = next(
        s for s in result.data["services"] if s["service"] == "github"
    )
    assert github_entry["status"] == "skipped"
    assert "no_token_in_connection" in github_entry["detail"]
