"""CLI tests for ``forge connect`` / ``forge scope`` / ``forge targets add``.

The tests build the full Typer app via :func:`forge.cli_registry.build_forge_cli_apps`
so this exercises command registration end-to-end. Credentials are
provided through monkey-patched environment variables and
``input=...``-fed stdin so no plaintext secrets travel through CLI
arguments.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from forge.cli_registry import build_forge_cli_apps


runner = CliRunner()

CONNECT_SERVICES = (
    "github",
    "supabase",
    "shodan",
    "virustotal",
    "replit",
    "urlscan",
    "censys",
    "dehashed",
)

CONNECT_SERVICE_FLAGS = {
    "github": {"--token-env", "--token-stdin", "--org", "--user"},
    "supabase": {
        "--key-env",
        "--key-stdin",
        "--pat-env",
        "--pat-stdin",
        "--project-ref",
        "--url",
    },
    "shodan": {"--key-env", "--key-stdin"},
    "virustotal": {"--key-env", "--key-stdin"},
    "replit": {"--username", "--url"},
    "urlscan": {"--key-env", "--key-stdin"},
    "censys": {
        "--api-id-env",
        "--api-id-stdin",
        "--secret-env",
        "--secret-stdin",
    },
    "dehashed": {"--email", "--key-env", "--key-stdin"},
}

CONNECT_FOREIGN_HELP_FLAGS = {
    "github": {"--key-env", "--project-ref", "--username"},
    "supabase": {"--token-env", "--org", "--api-id-env"},
    "shodan": {
        "--org",
        "--user",
        "--project-ref",
        "--url",
        "--email",
        "--username",
        "--api-id-env",
        "--secret-env",
    },
    "virustotal": {"--org", "--project-ref", "--username"},
    "replit": {"--key-env", "--project-ref", "--email"},
    "urlscan": {"--org", "--project-ref", "--username"},
    "censys": {"--org", "--project-ref", "--email"},
    "dehashed": {"--org", "--project-ref", "--api-id-env"},
}


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


@pytest.mark.parametrize(
    (
        "service",
        "service_args",
        "env",
        "input_text",
        "expected_config",
        "expected_sources",
    ),
    [
        pytest.param(
            "github",
            ["--token-env", "TEST_GITHUB_TOKEN", "--org", "myorg"],
            {"TEST_GITHUB_TOKEN": "ghp_canonical_test"},
            None,
            {"token": "ghp_canonical_test", "orgs": ["myorg"]},
            {"token": "env:TEST_GITHUB_TOKEN"},
            id="github-env",
        ),
        pytest.param(
            "github",
            ["--token-stdin"],
            None,
            "ghp_canonical_stdin_test\n",
            {"token": "ghp_canonical_stdin_test"},
            {"token": "stdin"},
            id="github-stdin",
        ),
        pytest.param(
            "supabase",
            ["--project-ref", "abc123", "--key-stdin"],
            None,
            "sb_anon_canonical_test\n",
            {"project_ref": "abc123", "key": "sb_anon_canonical_test"},
            {"key": "stdin"},
            id="supabase-key-stdin",
        ),
        pytest.param(
            "supabase",
            ["--project-ref", "abc123", "--pat-stdin"],
            None,
            "sbp_canonical_test\n",
            {"project_ref": "abc123", "management_pat": "sbp_canonical_test"},
            {"management_pat": "stdin"},
            id="supabase-stdin",
        ),
        pytest.param(
            "shodan",
            ["--key-stdin"],
            None,
            "shodan_canonical_test\n",
            {"key": "shodan_canonical_test"},
            {"key": "stdin"},
            id="shodan-stdin",
        ),
        pytest.param(
            "censys",
            ["--api-id-env", "TEST_CENSYS_ID", "--secret-stdin"],
            {"TEST_CENSYS_ID": "censys_id_test"},
            "censys_secret_test\n",
            {"api_id": "censys_id_test", "api_secret": "censys_secret_test"},
            {"api_id": "env:TEST_CENSYS_ID", "api_secret": "stdin"},
            id="censys-secret-stdin",
        ),
        pytest.param(
            "censys",
            ["--api-id-stdin", "--secret-env", "TEST_CENSYS_SECRET"],
            {"TEST_CENSYS_SECRET": "censys_secret_test"},
            "censys_id_test\n",
            {"api_id": "censys_id_test", "api_secret": "censys_secret_test"},
            {"api_id": "stdin", "api_secret": "env:TEST_CENSYS_SECRET"},
            id="censys-api-id-stdin",
        ),
        pytest.param(
            "dehashed",
            ["--email", "operator@example.com", "--key-stdin"],
            None,
            "dehashed_canonical_test\n",
            {"email": "operator@example.com", "key": "dehashed_canonical_test"},
            {"key": "stdin"},
            id="dehashed-stdin",
        ),
    ],
)
def test_forge_connect_add_stores_service_configuration(
    service: str,
    service_args: list[str],
    env: dict[str, str] | None,
    input_text: str | None,
    expected_config: dict[str, str | list[str]],
    expected_sources: dict[str, str],
    tmp_path: Path,
) -> None:
    result = _invoke(
        [
            "connect",
            "add",
            service,
            *service_args,
            "--data-dir",
            str(tmp_path),
            "--json",
        ],
        env=env,
        input_text=input_text,
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["service"] == service
    stored = json.loads((tmp_path / "connections.json").read_text(encoding="utf-8"))
    entry = stored["connections"][0]
    assert entry["service"] == service
    assert entry["config"] == expected_config
    assert entry["credential_sources"] == expected_sources


@pytest.mark.parametrize(
    ("service", "service_args", "input_text"),
    [
        ("github", ["--token-env", "TEST_GITHUB_TOKEN"], None),
        ("supabase", ["--project-ref", "abc123", "--pat-stdin"], "supabase-pat\n"),
        ("shodan", ["--key-stdin"], "shodan-key\n"),
        ("virustotal", ["--key-stdin"], "virustotal-key\n"),
        ("replit", ["--username", "operator"], None),
        ("urlscan", ["--key-stdin"], "urlscan-key\n"),
        (
            "censys",
            ["--api-id-env", "TEST_CENSYS_ID", "--secret-stdin"],
            "censys-secret\n",
        ),
        ("dehashed", ["--email", "operator@example.com", "--key-stdin"], "dehashed-key\n"),
    ],
)
def test_forge_connect_service_aliases_still_work(
    service: str,
    service_args: list[str],
    input_text: str | None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if service == "github":
        monkeypatch.setenv("TEST_GITHUB_TOKEN", "ghp_alias_test")
    elif service == "censys":
        monkeypatch.setenv("TEST_CENSYS_ID", "censys-id")
    result = _invoke(
        [
            "connect",
            service,
            *service_args,
            "--data-dir",
            str(tmp_path),
            "--json",
        ],
        input_text=input_text,
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["service"] == service
    stored = json.loads((tmp_path / "connections.json").read_text(encoding="utf-8"))
    assert stored["connections"][0]["service"] == service


@pytest.mark.parametrize("service", CONNECT_SERVICES)
@pytest.mark.parametrize("route", ("add", "alias"))
def test_forge_connect_service_help_is_service_specific(service: str, route: str) -> None:
    args = ["connect", "add", service, "--help"]
    if route == "alias":
        args = ["connect", service, "--help"]
    result = _invoke(args)
    assert result.exit_code == 0, result.output
    for flag in CONNECT_SERVICE_FLAGS[service]:
        assert flag in result.output
    for flag in CONNECT_FOREIGN_HELP_FLAGS[service]:
        assert flag not in result.output
    assert "--data-dir" in result.output
    assert "--json" in result.output
    assert "--help" in result.output


def test_forge_connect_add_help_lists_services() -> None:
    result = _invoke(["connect", "add", "--help"])
    assert result.exit_code == 0, result.output
    for service in CONNECT_SERVICES:
        assert service in result.output


def test_forge_connect_help_lists_only_add_list_remove() -> None:
    result = _invoke(["connect", "--help"])
    assert result.exit_code == 0, result.output
    commands_section = result.output.split("Commands", maxsplit=1)[1]
    visible_commands = re.findall(r"│\s+([a-z][a-z0-9-]*)\s{2,}", commands_section)
    assert visible_commands == ["add", "list", "remove"]


def test_forge_connect_add_rejects_foreign_flags_unknown_and_missing_services() -> None:
    foreign_flag = _invoke(["connect", "add", "shodan", "--org", "x"])
    assert foreign_flag.exit_code != 0
    assert "No such option: --org" in foreign_flag.output

    unknown_service = _invoke(["connect", "add", "unknown"])
    assert unknown_service.exit_code != 0
    assert "Valid services" in unknown_service.output
    for service in CONNECT_SERVICES:
        assert service in unknown_service.output

    missing_service = _invoke(["connect", "add"])
    assert missing_service.exit_code != 0
    assert "Missing argument 'SERVICE'" in missing_service.output


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


def test_forge_scope_add_domain_and_duplicate(tmp_path: Path) -> None:
    manifest = tmp_path / "default.json"
    manifest.write_text(json.dumps({"domains": []}), encoding="utf-8")
    result = _invoke(
        [
            "scope",
            "add",
            "Example.COM",
            "--manifest",
            str(manifest),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["added"] is True
    original_content = manifest.read_text(encoding="utf-8")
    stored = json.loads(manifest.read_text(encoding="utf-8"))
    assert "example.com" in stored["domains"]

    duplicate = _invoke(
        [
            "scope",
            "add",
            "example.com",
            "--manifest",
            str(manifest),
            "--json",
        ],
    )
    assert duplicate.exit_code == 0, duplicate.output
    assert json.loads(duplicate.output) == {
        "added": False,
        "manifest_path": str(manifest),
        "value": "example.com",
    }
    assert manifest.read_text(encoding="utf-8") == original_content


def test_forge_scope_add_plain_ip(tmp_path: Path) -> None:
    manifest = tmp_path / "default.json"
    manifest.write_text(json.dumps({"ip_ranges": []}), encoding="utf-8")
    result = _invoke(
        ["scope", "add", "192.0.2.7", "--manifest", str(manifest), "--json"],
    )
    assert result.exit_code == 0, result.output
    stored = json.loads(manifest.read_text(encoding="utf-8"))
    assert "192.0.2.7/32" in stored["ip_ranges"]


def test_forge_scope_add_cidr(tmp_path: Path) -> None:
    manifest = tmp_path / "default.json"
    manifest.write_text(json.dumps({"ip_ranges": []}), encoding="utf-8")
    result = _invoke(
        [
            "scope",
            "add",
            "10.0.0.0/24",
            "--manifest",
            str(manifest),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    stored = json.loads(manifest.read_text(encoding="utf-8"))
    assert "10.0.0.0/24" in stored["ip_ranges"]


@pytest.mark.parametrize(
    "value",
    [
        "https://example.com/path",
        "user@example.com",
        "garbage",
        "localhost",
        "10.0.0.0/99",
        "example .com",
        "",
        "   ",
    ],
)
def test_forge_scope_add_rejects_invalid_values(tmp_path: Path, value: str) -> None:
    result = _invoke(
        ["scope", "add", value, "--manifest", str(tmp_path / "scope.json"), "--json"],
    )
    assert result.exit_code != 0
    error = json.loads(result.output)["error"]
    assert repr(value) in error
    if "://" in value or "@" in value:
        assert "targets add" in error


def test_forge_scope_hidden_add_aliases_still_work(tmp_path: Path) -> None:
    manifest = tmp_path / "default.json"
    manifest.write_text(json.dumps({"domains": [], "ip_ranges": []}), encoding="utf-8")

    domain_result = _invoke(
        [
            "scope",
            "add-domain",
            "Alias.Example",
            "--manifest",
            str(manifest),
            "--json",
        ],
    )
    assert domain_result.exit_code == 0, domain_result.output
    assert json.loads(domain_result.output)["added"] is True

    ip_result = _invoke(
        [
            "scope",
            "add-ip",
            "198.51.100.0/24",
            "--manifest",
            str(manifest),
            "--json",
        ],
    )
    assert ip_result.exit_code == 0, ip_result.output
    assert json.loads(ip_result.output)["added"] is True
    stored = json.loads(manifest.read_text(encoding="utf-8"))
    assert "alias.example" in stored["domains"]
    assert "198.51.100.0/24" in stored["ip_ranges"]


def test_forge_scope_help_hides_compatibility_aliases() -> None:
    result = _invoke(["scope", "--help"])
    assert result.exit_code == 0, result.output
    assert "show" in result.output
    assert "add" in result.output
    assert "auto-expand" in result.output
    assert "add-domain" not in result.output
    assert "add-ip" not in result.output


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
