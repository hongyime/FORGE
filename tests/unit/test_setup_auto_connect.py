"""Tests for :func:`forge.setup.first_run.auto_connect_services_from_env`.

The auto-connect step scans the operator-supplied env mapping for
service credentials and stores them as plaintext connections for the
autopilot's connected-services phase to consume. Existing connections
are preserved; missing-required-fields entries are reported but never
crash the setup pipeline.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from forge.setup.first_run import (
    AUTO_CONNECT_SERVICES,
    auto_connect_services_from_env,
)


# ---------------------------------------------------------------------------
# Table-driven invariants
# ---------------------------------------------------------------------------


def test_auto_connect_table_declares_github_and_supabase() -> None:
    services = {entry["service"] for entry in AUTO_CONNECT_SERVICES}
    assert "github" in services
    assert "supabase" in services
    assert "shodan" in services
    assert "virustotal" in services
    assert "urlscan" in services
    assert "censys" in services
    assert "dehashed" in services


# ---------------------------------------------------------------------------
# GitHub auto-connect
# ---------------------------------------------------------------------------


def test_auto_connect_wires_github_token_from_env(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    env = {
        "FORGE_GITHUB_TOKEN": "ghp_" + "x" * 40,
        "FORGE_GITHUB_ORGS": "myorg,other-org",
    }
    actions = auto_connect_services_from_env(data_dir=data_dir, env=env)
    github_action = next(a for a in actions if a.name == "auto_connect:github")
    assert github_action.status == "created"
    # The on-disk connection file must contain the stored token.
    config = json.loads((data_dir / "connections.json").read_text("utf-8"))
    github_entry = next(
        c for c in config["connections"] if c["service"] == "github"
    )
    assert github_entry["config"]["token"].startswith("ghp_")
    assert github_entry["credential_sources"]["token"] == "env:FORGE_GITHUB_TOKEN"
    assert "myorg" in github_entry["config"]["orgs"]


def test_auto_connect_skips_github_when_token_missing(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    actions = auto_connect_services_from_env(
        data_dir=data_dir, env={}
    )
    github_action = next(
        (a for a in actions if a.name == "auto_connect:github"), None
    )
    # No credential => no action recorded for github.
    assert github_action is None


# ---------------------------------------------------------------------------
# Supabase auto-connect
# ---------------------------------------------------------------------------


def test_auto_connect_wires_supabase_with_project_ref(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    env = {
        "FORGE_SUPABASE_KEY": "anon-key-value",
        "FORGE_SUPABASE_PROJECT_REF": "abc123",
    }
    actions = auto_connect_services_from_env(data_dir=data_dir, env=env)
    supabase_action = next(a for a in actions if a.name == "auto_connect:supabase")
    assert supabase_action.status == "created"
    config = json.loads((data_dir / "connections.json").read_text("utf-8"))
    supabase_entry = next(
        c for c in config["connections"] if c["service"] == "supabase"
    )
    assert supabase_entry["config"]["project_ref"] == "abc123"
    assert supabase_entry["config"]["key"] == "anon-key-value"


def test_auto_connect_skips_supabase_when_project_ref_missing(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    env = {"FORGE_SUPABASE_KEY": "anon-key"}
    actions = auto_connect_services_from_env(data_dir=data_dir, env=env)
    supabase_action = next(
        (a for a in actions if a.name == "auto_connect:supabase"), None
    )
    assert supabase_action is not None
    assert supabase_action.status == "skipped"
    assert "FORGE_SUPABASE_PROJECT_REF" in supabase_action.detail


# ---------------------------------------------------------------------------
# Scalar key services
# ---------------------------------------------------------------------------


def test_auto_connect_wires_shodan_key(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    env = {"FORGE_SHODAN_API_KEY": "shodan-key-value"}
    actions = auto_connect_services_from_env(data_dir=data_dir, env=env)
    shodan_action = next(a for a in actions if a.name == "auto_connect:shodan")
    assert shodan_action.status == "created"


def test_auto_connect_wires_virustotal_key(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    env = {"FORGE_VIRUSTOTAL_API_KEY": "vt-key"}
    actions = auto_connect_services_from_env(data_dir=data_dir, env=env)
    vt_action = next(a for a in actions if a.name == "auto_connect:virustotal")
    assert vt_action.status == "created"


def test_auto_connect_wires_urlscan_key(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    env = {"FORGE_URLSCAN_API_KEY": "us-key"}
    actions = auto_connect_services_from_env(data_dir=data_dir, env=env)
    us_action = next(a for a in actions if a.name == "auto_connect:urlscan")
    assert us_action.status == "created"


# ---------------------------------------------------------------------------
# Censys (requires both api_id + api_secret)
# ---------------------------------------------------------------------------


def test_auto_connect_wires_censys_with_both_fields(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    env = {
        "FORGE_CENSYS_API_ID": "censys-id",
        "FORGE_CENSYS_API_SECRET": "censys-secret",
    }
    actions = auto_connect_services_from_env(data_dir=data_dir, env=env)
    censys_action = next(a for a in actions if a.name == "auto_connect:censys")
    assert censys_action.status == "created"
    config = json.loads((data_dir / "connections.json").read_text("utf-8"))
    censys_entry = next(
        c for c in config["connections"] if c["service"] == "censys"
    )
    assert censys_entry["config"]["api_id"] == "censys-id"
    assert censys_entry["config"]["api_secret"] == "censys-secret"


def test_auto_connect_skips_censys_when_api_id_missing(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    env = {"FORGE_CENSYS_API_SECRET": "censys-secret"}
    actions = auto_connect_services_from_env(data_dir=data_dir, env=env)
    censys_action = next(a for a in actions if a.name == "auto_connect:censys")
    assert censys_action.status == "skipped"
    assert "FORGE_CENSYS_API_ID" in censys_action.detail


# ---------------------------------------------------------------------------
# DeHashed
# ---------------------------------------------------------------------------


def test_auto_connect_wires_dehashed_with_email_and_key(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    env = {
        "FORGE_DEHASHED_API_KEY": "dh-key",
        "FORGE_DEHASHED_EMAIL": "admin@corp-target.io",
    }
    actions = auto_connect_services_from_env(data_dir=data_dir, env=env)
    dh_action = next(a for a in actions if a.name == "auto_connect:dehashed")
    assert dh_action.status == "created"
    config = json.loads((data_dir / "connections.json").read_text("utf-8"))
    dh_entry = next(c for c in config["connections"] if c["service"] == "dehashed")
    assert dh_entry["config"]["email"] == "admin@corp-target.io"


# ---------------------------------------------------------------------------
# Replit (no credential field, just a username)
# ---------------------------------------------------------------------------


def test_auto_connect_wires_replit_from_username(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    env = {"FORGE_REPLIT_USERNAME": "operator"}
    actions = auto_connect_services_from_env(data_dir=data_dir, env=env)
    replit_action = next(a for a in actions if a.name == "auto_connect:replit")
    assert replit_action.status == "created"


# ---------------------------------------------------------------------------
# Idempotence: existing connections are preserved
# ---------------------------------------------------------------------------


def test_auto_connect_preserves_existing_connections(tmp_path: Path) -> None:
    from forge.onboard.service_connections import ServiceConnectionManager

    data_dir = tmp_path / "data"
    manager = ServiceConnectionManager(data_dir)
    manager.add_connection(
        "github",
        token="existing_token",
        orgs=["already-wired"],
        credential_sources={"token": "env:FORGE_GITHUB_TOKEN"},
    )

    env = {
        "FORGE_GITHUB_TOKEN": "newer_token",
        "FORGE_GITHUB_ORGS": "would-overwrite",
    }
    actions = auto_connect_services_from_env(data_dir=data_dir, env=env)
    github_action = next(a for a in actions if a.name == "auto_connect:github")
    assert github_action.status == "exists"
    # Verify the stored token did NOT change.
    config = json.loads((data_dir / "connections.json").read_text("utf-8"))
    github_entry = next(
        c for c in config["connections"] if c["service"] == "github"
    )
    assert github_entry["config"]["token"] == "existing_token"
    assert github_entry["config"]["orgs"] == ["already-wired"]


# ---------------------------------------------------------------------------
# Empty env is a no-op (not an error)
# ---------------------------------------------------------------------------


def test_auto_connect_with_empty_env_is_noop(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    actions = auto_connect_services_from_env(data_dir=data_dir, env={})
    # No required credentials were present → no actions recorded.
    created = [a for a in actions if a.status == "created"]
    assert created == []


# ---------------------------------------------------------------------------
# Non-echoing: credential values never appear in action details
# ---------------------------------------------------------------------------


def test_auto_connect_actions_never_echo_credential_values(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    env = {
        "FORGE_GITHUB_TOKEN": "ghp_" + "SENSITIVE_VALUE_SHOULD_NEVER_APPEAR_IN_LOGS",
        "FORGE_SHODAN_API_KEY": "SHODAN_SENSITIVE_SECRET_VALUE",
    }
    actions = auto_connect_services_from_env(data_dir=data_dir, env=env)
    for action in actions:
        assert "SENSITIVE_VALUE_SHOULD_NEVER_APPEAR_IN_LOGS" not in action.detail
        assert "SHODAN_SENSITIVE_SECRET_VALUE" not in action.detail


# ---------------------------------------------------------------------------
# full run_first_run_setup also auto-connects
# ---------------------------------------------------------------------------


def test_run_first_run_setup_auto_connects_github(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``forge setup`` wires detected service credentials end-to-end."""
    from forge.setup.first_run import run_first_run_setup

    monkeypatch.setattr(
        "forge.setup.first_run.run_feeds_fetch",
        lambda **kwargs: _no_op_feed_fetch(),
    )
    monkeypatch.setattr(
        "forge.setup.first_run._run_doctor_summary", lambda: None
    )
    (tmp_path / ".env.example").write_text("# empty\n", encoding="utf-8")
    env = {
        "FORGE_GITHUB_TOKEN": "ghp_" + "y" * 40,
        "FORGE_GITHUB_ORGS": "myorg",
    }
    data_dir = tmp_path / ".forge_data"
    result = run_first_run_setup(
        root=tmp_path,
        data_dir=data_dir,
        skip_doctor=True,
        skip_feeds_fetch=True,
        env=env,
    )
    names = [a.name for a in result.actions]
    assert "auto_connect:github" in names
    github_action = next(
        a for a in result.actions if a.name == "auto_connect:github"
    )
    assert github_action.status == "created"


def _no_op_feed_fetch():
    from forge.setup.first_run import SetupAction

    return SetupAction(
        name="feeds_fetch",
        status="skipped",
        detail="test override",
    )