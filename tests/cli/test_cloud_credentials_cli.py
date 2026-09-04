"""MEDIUM 8 — forge cloud credentials CLI regression tests.

Covers:
  1. CLI command is registered and importable (no NameError on _cli_audit).
  2. ROE gate: live run without --roe-id raises BadParameter / SystemExit(1).
  3. Engagement scope check: _direct_cli_load_scope_lists called on live run.
  4. Audit logging: _cli_audit called at start and completion.
  5. Safe defaults: --include-metadata defaults to False (metadata disabled).
  6. Dry-run: skips ROE gate, scope check, harvest; still calls audit.
  7. Provider validation: rejects unknown --provider values.
  8. Output format validation: rejects unknown --output-format values.

Patching strategy: ForgeConfig, harvest_aws_credentials, and
harvest_gcp_credentials are imported lazily inside cloud_credentials(), so
we patch them at their canonical source modules, not at forge.cli_cloud.
_cli_audit and _direct_cli_load_scope_lists are module-level imports in
forge.cli_cloud, so those are patched at forge.cli_cloud.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import click
import pytest
import typer
import typer.main

from forge import cli as forge_cli


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _click_command_for(subcommand: str) -> click.Command:
    """Compile cloud_app and return the concrete Click subcommand."""
    click_group = typer.main.get_command(forge_cli.cloud_app)
    assert hasattr(click_group, "get_command"), type(click_group)
    resolved = click_group.get_command(click.Context(click_group), subcommand)
    assert resolved is not None, f"no cloud subcommand named {subcommand!r}"
    return resolved


def _flag_names(cmd: click.Command) -> set[str]:
    flags: set[str] = set()
    for param in cmd.params:
        if hasattr(param, "opts"):
            flags.update(param.opts)
            flags.update(param.secondary_opts)
    return flags


def _make_engagement_db(tmp_path: Path, engagement_id: int = 1001) -> Path:
    """Create a minimal engagement SQLite DB with audit_log + scope_json tables."""
    db_path = tmp_path / f"engagement_{engagement_id}.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER,
            phase TEXT,
            module TEXT,
            action TEXT,
            target TEXT,
            result TEXT,
            operator TEXT,
            logged_at TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scope_json (
            engagement_id INTEGER,
            scope_json TEXT
        )
        """
    )
    conn.execute(
        "INSERT INTO scope_json (engagement_id, scope_json) VALUES (?, ?)",
        (engagement_id, json.dumps(["example.com"])),
    )
    conn.commit()
    conn.close()
    return db_path


def _fake_config(tmp_path: Path, db_path: Path) -> Any:
    """Return a minimal ForgeConfig-like object."""

    class _FakeCfg:
        data_dir = tmp_path

        def engagement_db_path(self, _: Any) -> Path:
            return db_path

    return _FakeCfg()


# ---------------------------------------------------------------------------
# 1. Command registration — no NameError on _cli_audit import
# ---------------------------------------------------------------------------

def test_cloud_credentials_command_registered() -> None:
    """forge cloud credentials is registered in cloud_app."""
    cmd = _click_command_for("credentials")
    assert cmd is not None
    assert cmd.name == "credentials"


def test_cloud_credentials_importable_no_name_error() -> None:
    """Importing cli_cloud must not raise NameError for _cli_audit."""
    import forge.cli_cloud as cli_cloud  # noqa: PLC0415

    assert hasattr(cli_cloud, "cloud_credentials"), (
        "cloud_credentials function must be defined in forge.cli_cloud"
    )


# ---------------------------------------------------------------------------
# 2. Safe defaults — metadata disabled by default
# ---------------------------------------------------------------------------

def test_cloud_credentials_metadata_disabled_by_default() -> None:
    """--include-metadata must default to False (safe default)."""
    cmd = _click_command_for("credentials")
    for param in cmd.params:
        if hasattr(param, "opts") and "--include-metadata" in param.opts:
            assert param.default is False, (
                f"--include-metadata default must be False (safe), got {param.default!r}"
            )
            return
    pytest.fail("--include-metadata option not found in cloud credentials command")


def test_cloud_credentials_has_no_metadata_flag() -> None:
    """--no-include-metadata flag must exist (explicit opt-in pattern)."""
    cmd = _click_command_for("credentials")
    flags = _flag_names(cmd)
    assert "--no-include-metadata" in flags, (
        f"--no-include-metadata must be present. Got: {sorted(flags)}"
    )


# ---------------------------------------------------------------------------
# 3. ROE gate — live run without --roe-id must fail
# ---------------------------------------------------------------------------

def test_cloud_credentials_roe_required_for_live_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Live run without --roe-id must raise typer.BadParameter or SystemExit(1)."""
    db_path = _make_engagement_db(tmp_path)
    monkeypatch.setenv("FORGE_ROE_ID", "")  # ensure env var is empty

    import forge.cli_cloud as cli_cloud  # noqa: PLC0415

    with patch("forge.config.ForgeConfig.load", return_value=_fake_config(tmp_path, db_path)):
        with pytest.raises((typer.BadParameter, SystemExit)) as exc_info:
            cli_cloud.cloud_credentials(
                engagement="1001",
                provider="all",
                include_metadata=False,
                output_format="json",
                output_path=None,
                dry_run=False,
                roe_id=None,          # no ROE — must be rejected
                scope_manifest=None,
            )
    if isinstance(exc_info.value, SystemExit):
        assert exc_info.value.code != 0


def test_cloud_credentials_roe_accepted_for_live_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Live run with a valid --roe-id must pass the ROE gate."""
    db_path = _make_engagement_db(tmp_path)

    import forge.cli_cloud as cli_cloud  # noqa: PLC0415

    aws_cred = MagicMock()
    aws_cred.to_dict.return_value = {
        "type": "env",
        "source": "env:AWS_ACCESS_KEY_ID",
        "access_key_hash": "sha256:abc",
    }

    with (
        patch("forge.config.ForgeConfig.load", return_value=_fake_config(tmp_path, db_path)),
        patch("forge.cli_cloud._direct_cli_load_scope_lists", return_value=(["example.com"], [])),
        patch(
            "forge.collection.cloud.aws_credentials.harvest_aws_credentials",
            return_value=[aws_cred],
        ),
        patch(
            "forge.collection.cloud.gcp_credentials.harvest_gcp_credentials",
            return_value=[],
        ),
        patch("forge.cli_cloud._cli_audit"),
    ):
        # Should not raise — ROE is provided
        cli_cloud.cloud_credentials(
            engagement="1001",
            provider="aws",
            include_metadata=False,
            output_format="json",
            output_path=str(tmp_path / "out.json"),
            dry_run=False,
            roe_id="ROE-TEST-001",
            scope_manifest=None,
        )


# ---------------------------------------------------------------------------
# 4. Engagement scope check — _direct_cli_load_scope_lists called on live run
# ---------------------------------------------------------------------------

def test_cloud_credentials_scope_check_called_on_live_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_direct_cli_load_scope_lists must be called during a live run."""
    db_path = _make_engagement_db(tmp_path)

    import forge.cli_cloud as cli_cloud  # noqa: PLC0415

    scope_calls: list[dict[str, Any]] = []

    def _fake_scope(**kwargs: Any) -> tuple[list[str], list[str]]:
        scope_calls.append(kwargs)
        return (["example.com"], [])

    with (
        patch("forge.config.ForgeConfig.load", return_value=_fake_config(tmp_path, db_path)),
        patch("forge.cli_cloud._direct_cli_load_scope_lists", side_effect=_fake_scope),
        patch(
            "forge.collection.cloud.aws_credentials.harvest_aws_credentials",
            return_value=[],
        ),
        patch(
            "forge.collection.cloud.gcp_credentials.harvest_gcp_credentials",
            return_value=[],
        ),
        patch("forge.cli_cloud._cli_audit"),
    ):
        cli_cloud.cloud_credentials(
            engagement="1001",
            provider="all",
            include_metadata=False,
            output_format="json",
            output_path=str(tmp_path / "out.json"),
            dry_run=False,
            roe_id="ROE-SCOPE-TEST",
            scope_manifest=None,
        )

    assert len(scope_calls) == 1, (
        f"_direct_cli_load_scope_lists must be called exactly once on live run, "
        f"got {len(scope_calls)} calls"
    )
    assert scope_calls[0]["engagement_id"] == 1001


def test_cloud_credentials_scope_check_skipped_on_dry_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_direct_cli_load_scope_lists must NOT be called during dry-run."""
    db_path = _make_engagement_db(tmp_path)

    import forge.cli_cloud as cli_cloud  # noqa: PLC0415

    scope_calls: list[Any] = []

    def _fake_scope(**kwargs: Any) -> tuple[list[str], list[str]]:
        scope_calls.append(kwargs)
        return ([], [])

    with (
        patch("forge.config.ForgeConfig.load", return_value=_fake_config(tmp_path, db_path)),
        patch("forge.cli_cloud._direct_cli_load_scope_lists", side_effect=_fake_scope),
        patch("forge.cli_cloud._cli_audit"),
    ):
        cli_cloud.cloud_credentials(
            engagement="1001",
            provider="all",
            include_metadata=False,
            output_format="json",
            output_path=None,
            dry_run=True,
            roe_id=None,
            scope_manifest=None,
        )

    assert len(scope_calls) == 0, (
        f"_direct_cli_load_scope_lists must NOT be called on dry-run, "
        f"got {len(scope_calls)} calls"
    )


# ---------------------------------------------------------------------------
# 5. Audit logging — _cli_audit called at start and completion
# ---------------------------------------------------------------------------

def test_cloud_credentials_audit_called_at_start_and_completion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_cli_audit must be called at least twice: start + complete."""
    db_path = _make_engagement_db(tmp_path)

    import forge.cli_cloud as cli_cloud  # noqa: PLC0415

    audit_calls: list[dict[str, Any]] = []

    def _fake_audit(**kwargs: Any) -> None:
        audit_calls.append(kwargs)

    with (
        patch("forge.config.ForgeConfig.load", return_value=_fake_config(tmp_path, db_path)),
        patch("forge.cli_cloud._direct_cli_load_scope_lists", return_value=(["example.com"], [])),
        patch(
            "forge.collection.cloud.aws_credentials.harvest_aws_credentials",
            return_value=[],
        ),
        patch(
            "forge.collection.cloud.gcp_credentials.harvest_gcp_credentials",
            return_value=[],
        ),
        patch("forge.cli_cloud._cli_audit", side_effect=_fake_audit),
    ):
        cli_cloud.cloud_credentials(
            engagement="1001",
            provider="all",
            include_metadata=False,
            output_format="json",
            output_path=str(tmp_path / "out.json"),
            dry_run=False,
            roe_id="ROE-AUDIT-TEST",
            scope_manifest=None,
        )

    assert len(audit_calls) >= 2, (
        f"_cli_audit must be called at least twice (start + complete), "
        f"got {len(audit_calls)} calls: {audit_calls}"
    )
    actions = [c.get("action") for c in audit_calls]
    assert "start" in actions, f"audit 'start' action missing. Got: {actions}"
    assert "complete" in actions, f"audit 'complete' action missing. Got: {actions}"


def test_cloud_credentials_audit_called_on_dry_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_cli_audit must also be called during dry-run (records intent)."""
    db_path = _make_engagement_db(tmp_path)

    import forge.cli_cloud as cli_cloud  # noqa: PLC0415

    audit_calls: list[dict[str, Any]] = []

    def _fake_audit(**kwargs: Any) -> None:
        audit_calls.append(kwargs)

    with (
        patch("forge.config.ForgeConfig.load", return_value=_fake_config(tmp_path, db_path)),
        patch("forge.cli_cloud._cli_audit", side_effect=_fake_audit),
    ):
        cli_cloud.cloud_credentials(
            engagement="1001",
            provider="all",
            include_metadata=False,
            output_format="json",
            output_path=None,
            dry_run=True,
            roe_id=None,
            scope_manifest=None,
        )

    assert len(audit_calls) >= 1, (
        f"_cli_audit must be called at least once even on dry-run, "
        f"got {len(audit_calls)} calls"
    )
    results = [c.get("result", "") for c in audit_calls]
    assert any("dry_run" in str(r) for r in results), (
        f"At least one audit call must record dry_run result. Got: {results}"
    )


# ---------------------------------------------------------------------------
# 6. Provider validation
# ---------------------------------------------------------------------------

def test_cloud_credentials_rejects_invalid_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unknown --provider value must exit with code 1."""
    db_path = _make_engagement_db(tmp_path)

    import forge.cli_cloud as cli_cloud  # noqa: PLC0415


    with (
        pytest.raises((typer.Exit, SystemExit)),
    ):
        cli_cloud.cloud_credentials(
            engagement="1001",
            provider="azure",   # not in {aws, gcp, all}
            include_metadata=False,
            output_format="json",
            output_path=None,
            dry_run=True,
            roe_id=None,
            scope_manifest=None,
        )



def test_cloud_credentials_rejects_invalid_output_format(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unknown --output-format value must exit with code 1."""
    db_path = _make_engagement_db(tmp_path)

    import forge.cli_cloud as cli_cloud  # noqa: PLC0415


    with (
        pytest.raises((typer.Exit, SystemExit)),
    ):
        cli_cloud.cloud_credentials(
            engagement="1001",
            provider="all",
            include_metadata=False,
            output_format="sarif",   # not in {json, csv}
            output_path=None,
            dry_run=True,
            roe_id=None,
            scope_manifest=None,
        )



# ---------------------------------------------------------------------------
# 7. Metadata disabled by default — harvest functions not called with metadata
# ---------------------------------------------------------------------------

def test_cloud_credentials_metadata_not_queried_by_default(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With default include_metadata=False, harvest functions must receive
    include_ec2_metadata=False and include_metadata=False."""
    db_path = _make_engagement_db(tmp_path)

    import forge.cli_cloud as cli_cloud  # noqa: PLC0415

    aws_calls: list[dict[str, Any]] = []
    gcp_calls: list[dict[str, Any]] = []

    def _fake_aws(**kwargs: Any) -> list:
        aws_calls.append(kwargs)
        return []

    def _fake_gcp(**kwargs: Any) -> list:
        gcp_calls.append(kwargs)
        return []

    with (
        patch("forge.config.ForgeConfig.load", return_value=_fake_config(tmp_path, db_path)),
        patch("forge.cli_cloud._direct_cli_load_scope_lists", return_value=(["example.com"], [])),
        patch(
            "forge.collection.cloud.aws_credentials.harvest_aws_credentials",
            side_effect=_fake_aws,
        ),
        patch(
            "forge.collection.cloud.gcp_credentials.harvest_gcp_credentials",
            side_effect=_fake_gcp,
        ),
        patch("forge.cli_cloud._cli_audit"),
    ):
        cli_cloud.cloud_credentials(
            engagement="1001",
            provider="all",
            include_metadata=False,   # safe default
            output_format="json",
            output_path=str(tmp_path / "out.json"),
            dry_run=False,
            roe_id="ROE-META-TEST",
            scope_manifest=None,
        )

    assert len(aws_calls) == 1
    assert aws_calls[0].get("include_ec2_metadata") is False, (
        f"include_ec2_metadata must be False by default. Got: {aws_calls[0]}"
    )
    assert aws_calls[0].get("include_ecs_metadata") is False, (
        f"include_ecs_metadata must be False by default. Got: {aws_calls[0]}"
    )
    assert len(gcp_calls) == 1
    assert gcp_calls[0].get("include_metadata") is False, (
        f"GCP include_metadata must be False by default. Got: {gcp_calls[0]}"
    )


# ---------------------------------------------------------------------------
# 8. Output written — JSON file created with hashed secrets only
# ---------------------------------------------------------------------------

def test_cloud_credentials_output_written_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Output JSON file must be written and contain cloud_provider field."""
    db_path = _make_engagement_db(tmp_path)

    import forge.cli_cloud as cli_cloud  # noqa: PLC0415

    aws_cred = MagicMock()
    aws_cred.to_dict.return_value = {
        "type": "env",
        "source": "env:AWS_ACCESS_KEY_ID",
        "access_key_hash": "sha256:deadbeef",
        "secret_hash": "sha256:cafebabe",
        "session_token_hash": None,
    }

    out_path = tmp_path / "creds.json"

    with (
        patch("forge.config.ForgeConfig.load", return_value=_fake_config(tmp_path, db_path)),
        patch("forge.cli_cloud._direct_cli_load_scope_lists", return_value=(["example.com"], [])),
        patch(
            "forge.collection.cloud.aws_credentials.harvest_aws_credentials",
            return_value=[aws_cred],
        ),
        patch(
            "forge.collection.cloud.gcp_credentials.harvest_gcp_credentials",
            return_value=[],
        ),
        patch("forge.cli_cloud._cli_audit"),
    ):
        cli_cloud.cloud_credentials(
            engagement="1001",
            provider="aws",
            include_metadata=False,
            output_format="json",
            output_path=str(out_path),
            dry_run=False,
            roe_id="ROE-OUTPUT-TEST",
            scope_manifest=None,
        )

    assert out_path.exists(), "Output JSON file must be created"
    data = json.loads(out_path.read_text(encoding="utf-8"))
    assert isinstance(data, list), "Output must be a JSON array"
    assert len(data) == 1
    row = data[0]
    assert row.get("cloud_provider") == "aws", (
        f"cloud_provider field must be 'aws'. Got: {row}"
    )
    # Raw secrets must never appear — only hashes
    assert "sha256:" in str(row.get("access_key_hash", "")), (
        "access_key_hash must be a sha256 hash"
    )
    # Raw key values must not be present
    for key in ("access_key", "secret_access_key", "secret_key", "password"):
        assert key not in row, f"Raw secret field {key!r} must not appear in output"


def test_cloud_credentials_all_provider_failures_exit_nonzero_and_audit(
    tmp_path: Path,
) -> None:
    """A failed selected provider must never be reported as a successful empty run."""
    db_path = _make_engagement_db(tmp_path)
    out_path = tmp_path / "should-not-exist.json"
    audit = MagicMock()

    import forge.cli_cloud as cli_cloud  # noqa: PLC0415

    with (
        patch("forge.config.ForgeConfig.load", return_value=_fake_config(tmp_path, db_path)),
        patch(
            "forge.cli_cloud._direct_cli_load_scope_lists",
            return_value=(["example.com"], []),
        ),
        patch(
            "forge.collection.cloud.aws_credentials.harvest_aws_credentials",
            side_effect=RuntimeError("sensitive provider detail"),
        ),
        patch("forge.cli_cloud._cli_audit", audit),
        pytest.raises(typer.Exit) as exc_info,
    ):
        cli_cloud.cloud_credentials(
            engagement="1001",
            provider="aws",
            include_metadata=False,
            output_format="json",
            output_path=str(out_path),
            dry_run=False,
            roe_id="ROE-FAIL-TEST",
            scope_manifest=None,
        )

    assert exc_info.value.exit_code == 1
    assert not out_path.exists()
    completion = [
        call.kwargs for call in audit.call_args_list if call.kwargs["action"] == "complete"
    ]
    assert completion
    assert completion[-1]["result"].startswith("failed providers=aws")
    assert "sensitive provider detail" not in completion[-1]["result"]


def test_cloud_credentials_partial_failure_writes_results_but_exits_nonzero(
    tmp_path: Path,
) -> None:
    db_path = _make_engagement_db(tmp_path)
    out_path = tmp_path / "partial.json"
    audit = MagicMock()
    aws_cred = MagicMock()
    aws_cred.to_dict.return_value = {
        "type": "env",
        "source": "env:AWS_ACCESS_KEY_ID",
        "access_key_hash": "sha256:abc",
    }

    import forge.cli_cloud as cli_cloud  # noqa: PLC0415

    with (
        patch("forge.config.ForgeConfig.load", return_value=_fake_config(tmp_path, db_path)),
        patch(
            "forge.cli_cloud._direct_cli_load_scope_lists",
            return_value=(["example.com"], []),
        ),
        patch(
            "forge.collection.cloud.aws_credentials.harvest_aws_credentials",
            return_value=[aws_cred],
        ),
        patch(
            "forge.collection.cloud.gcp_credentials.harvest_gcp_credentials",
            side_effect=OSError("provider unavailable"),
        ),
        patch("forge.cli_cloud._cli_audit", audit),
        pytest.raises(typer.Exit) as exc_info,
    ):
        cli_cloud.cloud_credentials(
            engagement="1001",
            provider="all",
            include_metadata=False,
            output_format="json",
            output_path=str(out_path),
            dry_run=False,
            roe_id="ROE-PARTIAL-TEST",
            scope_manifest=None,
        )

    assert exc_info.value.exit_code == 1
    assert json.loads(out_path.read_text(encoding="utf-8"))[0]["cloud_provider"] == "aws"
    completion = [
        call.kwargs for call in audit.call_args_list if call.kwargs["action"] == "complete"
    ]
    assert completion[-1]["result"].startswith("partial failed_providers=gcp")
