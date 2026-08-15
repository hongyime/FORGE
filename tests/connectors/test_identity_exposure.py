from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import typer
from typer.testing import CliRunner

from forge.connectors.cli import register_connector_commands
from forge.connectors.identity import IdentityExposureRunConfig, run_identity_exposure_connector
from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.db.validation import validate_canonical_schema

_PASSWORD_SHA1 = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"


def _build_identity_db(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    apply_schema(con)
    run_migrations(con)
    validate_canonical_schema(con)
    con.execute(
        """
        INSERT INTO engagements (id, name, scope_json, status, operator)
        VALUES (
            1001,
            'Acme Identity',
            '["acme.example","*.acme.example"]',
            'ACTIVE',
            'connector-test'
        )
        """
    )
    con.commit()
    return con


def _insert_sha1_credential(con: sqlite3.Connection, email: str = "user@acme.example") -> None:
    con.execute(
        """
        INSERT INTO credentials
            (engagement_id, email, password_hash, hash_type, breach_name, source, confidence)
        VALUES (1001, ?, ?, 'sha1', 'fixture', 'breach_db', 'confirmed')
        """,
        (email, _PASSWORD_SHA1),
    )
    con.commit()


def test_hibp_pwned_passwords_offline_corpus_updates_credentials_and_remediation(
    tmp_path: Path,
) -> None:
    con = _build_identity_db(tmp_path / "engagement.db")
    _insert_sha1_credential(con)
    corpus_path = tmp_path / "pwned-sha1.txt"
    corpus_path.write_text(f"{_PASSWORD_SHA1}:3303003\n0000000000000000000000000000000000000000:1\n", encoding="utf-8")

    try:
        result = run_identity_exposure_connector(
            con,
            IdentityExposureRunConfig(
                connector_id="hibp_pwned_passwords",
                engagement_id=1001,
                domain="acme.example",
                offline_corpus_path=corpus_path,
                operator="identity-test",
            ),
        )
        credential = con.execute(
            """
            SELECT enrichment_data
            FROM credentials
            WHERE engagement_id=1001
            """
        ).fetchone()
        remediation = con.execute(
            """
            SELECT finding_table, finding_ref, title, severity, metadata_json
            FROM remediation_items
            WHERE engagement_id=1001
            """
        ).fetchone()
        audit_rows = [
            dict(row)
            for row in con.execute(
                """
                SELECT module, action, target, result
                FROM audit_log
                WHERE engagement_id=1001 AND phase='connectors'
                """
            ).fetchall()
        ]
    finally:
        con.close()

    blob = json.dumps(
        {
            "result": result,
            "credential": dict(credential),
            "remediation": dict(remediation),
            "audit": audit_rows,
        },
        sort_keys=True,
    )
    enrichment = json.loads(credential["enrichment_data"])["hibp_pwned_passwords"]
    remediation_metadata = json.loads(remediation["metadata_json"])
    assert result["status"] == "completed"
    assert result["checked_count"] == 1
    assert result["exposed_count"] == 1
    assert result["persisted_count"] == 1
    assert result["remediation_count"] == 1
    assert result["matches"] == [
        {
            "credential_id": 1,
            "email": "user@acme.example",
            "domain": "acme.example",
            "hash_type": "sha1",
            "pwned_count": 3303003,
        }
    ]
    assert enrichment["status"] == "pwned"
    assert enrichment["pwned_count"] == 3303003
    assert remediation["finding_table"] == "manual"
    assert remediation["finding_ref"] == "identity_exposure:hibp_pwned_passwords:1"
    assert remediation["severity"] == "HIGH"
    assert remediation_metadata["pwned_count"] == 3303003
    assert audit_rows[0]["module"] == "hibp_pwned_passwords"
    assert "exposed=1" in audit_rows[0]["result"]
    assert _PASSWORD_SHA1 not in blob


def test_hibp_pwned_passwords_range_api_uses_prefix_only_and_padding(
    tmp_path: Path,
) -> None:
    con = _build_identity_db(tmp_path / "engagement.db")
    _insert_sha1_credential(con)
    calls: list[dict[str, object]] = []

    def fake_range_fetcher(
        prefix: str,
        hash_type: str,
        timeout_seconds: float,
        use_padding: bool,
    ) -> str:
        calls.append(
            {
                "prefix": prefix,
                "hash_type": hash_type,
                "timeout_seconds": timeout_seconds,
                "use_padding": use_padding,
            }
        )
        assert prefix == _PASSWORD_SHA1[:5]
        assert _PASSWORD_SHA1 not in prefix
        return f"{_PASSWORD_SHA1[5:]}:42\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0\n"

    try:
        result = run_identity_exposure_connector(
            con,
            IdentityExposureRunConfig(
                connector_id="hibp_pwned_passwords",
                engagement_id=1001,
                domain="acme.example",
                timeout_seconds=7,
            ),
            range_fetcher=fake_range_fetcher,
        )
    finally:
        con.close()

    blob = json.dumps(result, sort_keys=True)
    assert calls == [
        {
            "prefix": _PASSWORD_SHA1[:5],
            "hash_type": "sha1",
            "timeout_seconds": 7.0,
            "use_padding": True,
        }
    ]
    assert result["source"] == "hibp_range_api"
    assert result["exposed_count"] == 1
    assert result["matches"][0]["pwned_count"] == 42
    assert _PASSWORD_SHA1 not in blob


def test_hibp_pwned_passwords_dry_run_does_not_fetch_or_persist(tmp_path: Path) -> None:
    con = _build_identity_db(tmp_path / "engagement.db")
    _insert_sha1_credential(con)

    def forbidden_fetcher(_prefix: str, _hash_type: str, _timeout: float, _padding: bool) -> str:
        raise AssertionError("dry-run must not call HIBP")

    try:
        result = run_identity_exposure_connector(
            con,
            IdentityExposureRunConfig(
                connector_id="hibp_pwned_passwords",
                engagement_id=1001,
                domain="acme.example",
                dry_run=True,
            ),
            range_fetcher=forbidden_fetcher,
        )
        enrichment_data = con.execute(
            "SELECT enrichment_data FROM credentials WHERE engagement_id=1001"
        ).fetchone()[0]
    finally:
        con.close()

    assert result["status"] == "planned"
    assert result["checked_count"] == 1
    assert result["queried_prefix_count"] == 1
    assert json.loads(enrichment_data or "{}") == {}


def test_connector_cli_run_identity_invokes_runner_with_operator_config(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / ".forge_data"
    con = _build_identity_db(data_dir / "engagements" / "1001.db")
    con.close()
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    corpus_path = tmp_path / "pwned-sha1.txt"
    corpus_path.write_text(f"{_PASSWORD_SHA1}:7\n", encoding="utf-8")
    captured: dict[str, object] = {}

    def fake_run_identity_exposure_connector(_con, config):
        captured["config"] = config
        return {
            "connector_id": config.connector_id,
            "engagement_id": config.engagement_id,
            "domain": config.domain,
            "source": "offline_corpus",
            "status": "planned",
            "dry_run": config.dry_run,
            "checked_count": 0,
            "exposed_count": 0,
            "persisted_count": 0,
            "remediation_count": 0,
            "skipped_count": 0,
            "queried_prefix_count": 0,
            "hash_types": [],
            "matches": [],
            "skipped": [],
            "privacy": "full hash omitted",
        }

    monkeypatch.setattr(
        "forge.connectors.cli.run_identity_exposure_connector",
        fake_run_identity_exposure_connector,
    )
    app = typer.Typer()
    connectors_app = typer.Typer()
    register_connector_commands(connectors_app)
    app.add_typer(connectors_app, name="connectors")

    result = CliRunner().invoke(
        app,
        [
            "connectors",
            "run-identity",
            "--engagement",
            "1001",
            "--connector",
            "hibp_pwned_passwords",
            "--domain",
            "acme.example",
            "--offline-corpus",
            str(corpus_path),
            "--dry-run",
            "--operator",
            "cli-test",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    config = captured["config"]
    assert isinstance(config, IdentityExposureRunConfig)
    assert config.connector_id == "hibp_pwned_passwords"
    assert config.engagement_id == 1001
    assert config.domain == "acme.example"
    assert config.offline_corpus_path == corpus_path
    assert config.dry_run is True
    assert config.operator == "cli-test"
    assert payload["connector_id"] == "hibp_pwned_passwords"
