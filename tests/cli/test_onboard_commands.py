"""CLI tests for ``forge connect`` / ``forge scope`` / ``forge targets add``.

The tests build the full Typer app via :func:`forge.cli_registry.build_forge_cli_apps`
so this exercises command registration end-to-end. Credentials are
provided through monkey-patched environment variables and
``input=...``-fed stdin so no plaintext secrets travel through CLI
arguments.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from forge.cli_registry import build_forge_cli_apps


runner = CliRunner()


def _invoke(args: list[str], *, env: dict[str, str] | None = None, input_text: str | None = None):
    apps = build_forge_cli_apps(root_help="FORGE onboarding test")
    return runner.invoke(apps.app, args, env=env, input=input_text)


# ---------------------------------------------------------------------------
# forge connect
# ---------------------------------------------------------------------------


def test_forge_connect_github_stores_from_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FORGE_GITHUB_TOKEN", "ghp_test_token_value")
    result = _invoke(
        [
            "connect",
            "github",
            "--token-env",
            "FORGE_GITHUB_TOKEN",
            "--org",
            "myorg",
            "--data-dir",
            str(tmp_path),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["service"] == "github"
    assert payload["credential_sources"]["token"] == "env:FORGE_GITHUB_TOKEN"
    stored = json.loads((tmp_path / "connections.json").read_text(encoding="utf-8"))
    assert stored["connections"][0]["config"]["token"] == "ghp_test_token_value"
    assert stored["connections"][0]["config"]["orgs"] == ["myorg"]


def test_forge_connect_shodan_requires_credential_flag(tmp_path: Path) -> None:
    result = _invoke(
        [
            "connect",
            "shodan",
            "--data-dir",
            str(tmp_path),
            "--json",
        ],
    )
    assert result.exit_code == 1
    assert "key" in result.output.lower()


def test_forge_connect_supabase_stores_management_pat_without_data_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FORGE_SUPABASE_PAT", "sbp_test_placeholder")
    result = _invoke(
        [
            "connect",
            "supabase",
            "--project-ref",
            "abc123",
            "--pat-env",
            "FORGE_SUPABASE_PAT",
            "--data-dir",
            str(tmp_path),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "sbp_test_placeholder" not in result.output
    stored = json.loads((tmp_path / "connections.json").read_text(encoding="utf-8"))
    entry = stored["connections"][0]
    assert entry["config"] == {
        "project_ref": "abc123",
        "management_pat": "sbp_test_placeholder",
    }
    assert entry["credential_sources"]["management_pat"] == (
        "env:FORGE_SUPABASE_PAT"
    )


def test_forge_connect_supabase_reads_management_pat_from_stdin(
    tmp_path: Path,
) -> None:
    result = _invoke(
        [
            "connect",
            "supabase",
            "--project-ref",
            "abc123",
            "--pat-stdin",
            "--data-dir",
            str(tmp_path),
            "--json",
        ],
        input_text="sbp_test_placeholder\n",
    )
    assert result.exit_code == 0, result.output
    assert "sbp_test_placeholder" not in result.output
    stored = json.loads((tmp_path / "connections.json").read_text(encoding="utf-8"))
    assert stored["connections"][0]["credential_sources"]["management_pat"] == "stdin"


def test_forge_connect_supabase_requires_key_or_management_pat(
    tmp_path: Path,
) -> None:
    result = _invoke(
        [
            "connect",
            "supabase",
            "--project-ref",
            "abc123",
            "--data-dir",
            str(tmp_path),
            "--json",
        ],
    )
    assert result.exit_code == 1
    assert (
        "supabase requires --key-env/--key-stdin or --pat-env/--pat-stdin"
        in result.output
    )


def test_forge_connect_list_reports_redacted_credentials(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FORGE_SHODAN_KEY", "shodan-secret-key")
    assert _invoke(
        [
            "connect",
            "shodan",
            "--key-env",
            "FORGE_SHODAN_KEY",
            "--data-dir",
            str(tmp_path),
            "--json",
        ],
    ).exit_code == 0

    result = _invoke(
        ["connect", "list", "--data-dir", str(tmp_path), "--json"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["connections"][0]["config"]["key"] == "<redacted>"
    assert payload["connections"][0]["credential_sources"]["key"] == "env:FORGE_SHODAN_KEY"


def test_forge_connect_remove_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FORGE_SHODAN_KEY", "shodan-secret-key")
    _invoke(
        [
            "connect",
            "shodan",
            "--key-env",
            "FORGE_SHODAN_KEY",
            "--data-dir",
            str(tmp_path),
            "--json",
        ],
    )
    result = _invoke(
        ["connect", "remove", "shodan", "--data-dir", str(tmp_path), "--json"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["removed"] is True
    # Second remove reports False, exit 0.
    result2 = _invoke(
        ["connect", "remove", "shodan", "--data-dir", str(tmp_path), "--json"]
    )
    assert result2.exit_code == 0
    assert json.loads(result2.output)["removed"] is False


def test_forge_connect_stdin_credential(tmp_path: Path) -> None:
    result = _invoke(
        [
            "connect",
            "shodan",
            "--key-stdin",
            "--data-dir",
            str(tmp_path),
            "--json",
        ],
        input_text="shodan-stdin-value\n",
    )
    assert result.exit_code == 0, result.output
    stored = json.loads((tmp_path / "connections.json").read_text(encoding="utf-8"))
    assert stored["connections"][0]["config"]["key"] == "shodan-stdin-value"
    assert stored["connections"][0]["credential_sources"]["key"] == "stdin"


# ---------------------------------------------------------------------------
# forge scope
# ---------------------------------------------------------------------------


def test_forge_scope_show_blank_when_missing(tmp_path: Path) -> None:
    result = _invoke(
        [
            "scope",
            "show",
            "--manifest",
            str(tmp_path / "missing.json"),
            "--json",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["domains"] == []


def test_forge_scope_add_domain(tmp_path: Path) -> None:
    manifest = tmp_path / "default.json"
    manifest.write_text(json.dumps({"domains": []}), encoding="utf-8")
    result = _invoke(
        [
            "scope",
            "add-domain",
            "Example.COM",
            "--manifest",
            str(manifest),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["added"] is True
    stored = json.loads(manifest.read_text(encoding="utf-8"))
    assert "example.com" in stored["domains"]


def test_forge_scope_add_ip_cidr(tmp_path: Path) -> None:
    manifest = tmp_path / "default.json"
    manifest.write_text(json.dumps({"ip_ranges": []}), encoding="utf-8")
    result = _invoke(
        [
            "scope",
            "add-ip",
            "10.0.0.0/24",
            "--manifest",
            str(manifest),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    stored = json.loads(manifest.read_text(encoding="utf-8"))
    assert "10.0.0.0/24" in stored["ip_ranges"]


def test_forge_scope_auto_expand_preview(tmp_path: Path) -> None:
    manifest = tmp_path / "default.json"
    manifest.write_text(
        json.dumps({"domains": ["corp-target.io"], "urls": [], "ip_ranges": [], "authorized_seeds": []}),
        encoding="utf-8",
    )
    feed = tmp_path / "feed.json"
    feed.write_text(
        json.dumps(
            {
                "schema_version": "target-feed.v1",
                "items": [
                    {"target_type": "domain", "target_value": "api.corp-target.io"},
                    {"target_type": "domain", "target_value": "unrelated.net"},
                ],
            }
        ),
        encoding="utf-8",
    )
    result = _invoke(
        [
            "scope",
            "auto-expand",
            "--manifest",
            str(manifest),
            "--feed",
            str(feed),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["accepted"]
    assert payload["review_required"]
    # Preview — on-disk manifest unchanged.
    assert "api.corp-target.io" not in json.loads(manifest.read_text(encoding="utf-8"))["domains"]


def test_forge_scope_auto_expand_apply(tmp_path: Path) -> None:
    manifest = tmp_path / "default.json"
    manifest.write_text(
        json.dumps({"domains": ["corp-target.io"], "urls": [], "ip_ranges": [], "authorized_seeds": []}),
        encoding="utf-8",
    )
    feed = tmp_path / "feed.json"
    feed.write_text(
        json.dumps(
            {
                "schema_version": "target-feed.v1",
                "items": [
                    {"target_type": "domain", "target_value": "api.corp-target.io"},
                ],
            }
        ),
        encoding="utf-8",
    )
    result = _invoke(
        [
            "scope",
            "auto-expand",
            "--manifest",
            str(manifest),
            "--feed",
            str(feed),
            "--apply",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    stored = json.loads(manifest.read_text(encoding="utf-8"))
    assert "api.corp-target.io" in stored["domains"]


# ---------------------------------------------------------------------------
# forge targets add
# ---------------------------------------------------------------------------


def test_forge_targets_add_single_domain(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    manifest = tmp_path / "manifests" / "default.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        json.dumps({"domains": [], "urls": [], "ip_ranges": [], "authorized_seeds": []}),
        encoding="utf-8",
    )
    data_dir = tmp_path / "data"
    data_dir.mkdir()

    # Avoid real engagement allocation by pointing at a scratch dir.
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))

    result = _invoke(
        [
            "targets",
            "add",
            "example.com",
            "--manifest",
            str(manifest),
            "--data-dir",
            str(data_dir),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["results"][0]["status"] == "ok"
    assert payload["results"][0]["seed_type"] == "domain"
    assert payload["results"][0]["manifest_updated"] is True

    stored = json.loads(manifest.read_text(encoding="utf-8"))
    assert "example.com" in stored["domains"]


def test_forge_targets_add_from_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    manifest = tmp_path / "manifests" / "default.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        json.dumps({"domains": [], "urls": [], "ip_ranges": [], "authorized_seeds": []}),
        encoding="utf-8",
    )
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    seeds_file = tmp_path / "targets.txt"
    seeds_file.write_text(
        "example.com\n# comment\napi.example.com\nhttps://portal.example.com\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))

    result = _invoke(
        [
            "targets",
            "add",
            "--from-file",
            str(seeds_file),
            "--manifest",
            str(manifest),
            "--data-dir",
            str(data_dir),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert len(payload["results"]) == 3
    assert {r["seed_type"] for r in payload["results"]} == {"domain", "url"}

    stored = json.loads(manifest.read_text(encoding="utf-8"))
    assert "example.com" in stored["domains"]
    assert "api.example.com" in stored["domains"]
    assert "portal.example.com" in stored["domains"]


def test_forge_targets_add_no_scope_leaves_manifest_untouched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = tmp_path / "manifests" / "default.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(json.dumps({"domains": []}), encoding="utf-8")
    data_dir = tmp_path / "data"
    data_dir.mkdir()

    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))

    result = _invoke(
        [
            "targets",
            "add",
            "example.com",
            "--manifest",
            str(manifest),
            "--data-dir",
            str(data_dir),
            "--no-scope",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    stored = json.loads(manifest.read_text(encoding="utf-8"))
    assert stored["domains"] == []


def test_forge_targets_add_requires_a_value(tmp_path: Path) -> None:
    result = _invoke(["targets", "add", "--json"])
    assert result.exit_code != 0
    assert "no target supplied" in result.output.lower() or "error" in result.output.lower()
