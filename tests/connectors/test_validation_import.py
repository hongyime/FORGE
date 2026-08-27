from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import typer
from typer.testing import CliRunner

from forge.active_validation.runner import active_validation_control_coverage
from forge.connectors.cli import register_connector_commands
from forge.connectors.validation_import import (
    ValidationArtifactImportConfig,
    import_validation_artifact,
)
from forge.db.migrations import run_migrations
from forge.db.schema import apply_schema
from forge.db.validation import validate_canonical_schema


def _build_validation_db(path: Path) -> sqlite3.Connection:
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
            'Acme Validation',
            '["acme.example","*.acme.example"]',
            'ACTIVE',
            'connector-test'
        )
        """
    )
    con.commit()
    return con


def test_burp_issue_xml_import_persists_scoped_active_validation_evidence(
    tmp_path: Path,
) -> None:
    con = _build_validation_db(tmp_path / "engagement.db")
    report = """
    <issues burpVersion="2026">
      <issue>
        <serialNumber>123</serialNumber>
        <type>524288</type>
        <name>Missing security header</name>
        <host ip="198.51.100.10">https://app.acme.example</host>
        <path>/login?token=secret-never-store&amp;ok=1</path>
        <location>https://app.acme.example/login?session=secret&amp;ok=1</location>
        <severity>High</severity>
        <confidence>Certain</confidence>
        <requestresponse>
          <request base64="true">c2VjcmV0</request>
          <response base64="true">c2VjcmV0</response>
        </requestresponse>
      </issue>
      <issue>
        <name>Outside scope</name>
        <host>https://outside.example</host>
        <path>/admin</path>
        <severity>High</severity>
      </issue>
    </issues>
    """

    try:
        result = import_validation_artifact(
            con,
            ValidationArtifactImportConfig(
                connector_id="burp_dast_xml",
                engagement_id=1001,
                operator="validation-test",
            ),
            report_text=report,
        )
        job = con.execute(
            """
            SELECT target_ref, target_kind, method, mode, status, metadata_json
            FROM active_validation_jobs
            WHERE engagement_id=1001
            """
        ).fetchone()
        run = con.execute(
            """
            SELECT status, result, operator, evidence_json
            FROM active_validation_runs
            WHERE engagement_id=1001
            """
        ).fetchone()
        audit = con.execute(
            """
            SELECT module, action, result
            FROM audit_log
            WHERE engagement_id=1001 AND phase='connectors'
            """
        ).fetchone()
        coverage = active_validation_control_coverage(
            con,
            engagement_id=1001,
            now="2026-07-20T00:00:00Z",
        )
    finally:
        con.close()

    blob = json.dumps(
        {
            "result": result,
            "job": dict(job),
            "run": dict(run),
            "audit": dict(audit),
        },
        sort_keys=True,
    )
    metadata = json.loads(job["metadata_json"])
    evidence = json.loads(run["evidence_json"])
    assert result["schema_version"] == "forge.connector.validation_artifact_import.v1"
    assert result["execution_policy"] == "writes_active_validation_artifact_evidence"
    assert result["parsed_count"] == 2
    assert result["persisted_job_count"] == 1
    assert result["persisted_run_count"] == 1
    assert result["skipped_count"] == 1
    assert result["skipped"][0]["reason"] == "target_url_out_of_scope"
    assert tuple(job)[:5] == (
        "https://app.acme.example/login?ok=1",
        "service",
        "fixture_replay",
        "lab",
        "completed",
    )
    assert metadata["connector_id"] == "burp_dast_xml"
    assert metadata["proof_type"] == "burp_issue_xml"
    assert metadata["request_response_captured"] is False
    assert run["status"] == "completed"
    assert run["result"] == "evidence_imported"
    assert run["operator"] == "validation-test"
    assert evidence["network_execution"] is False
    assert evidence["job"]["target_ref"] == "https://app.acme.example/login?ok=1"
    assert evidence["job"]["method"] == "fixture_replay"
    assert evidence["job"]["mode"] == "lab"
    assert evidence["finding"]["severity"] == "high"
    assert audit["module"] == "burp_dast_xml"
    assert audit["action"] == "validation_artifact_import"
    assert "jobs=1" in audit["result"]
    assert coverage["summary"]["proof_types"] == {"burp_issue_xml": 1}
    assert coverage["summary"]["proof_freshness"] == {"fresh": 1}
    assert coverage["methods"][0]["proof_types"] == {"burp_issue_xml": 1}
    assert "secret-never-store" not in blob
    assert "session=secret" not in blob
    assert "c2VjcmV0" not in blob


def test_validation_xml_import_is_idempotent(tmp_path: Path) -> None:
    con = _build_validation_db(tmp_path / "engagement.db")
    report = """
    <issues>
      <issue>
        <name>Missing security header</name>
        <host>https://app.acme.example</host>
        <path>/login</path>
        <severity>High</severity>
      </issue>
    </issues>
    """

    try:
        first = import_validation_artifact(
            con,
            ValidationArtifactImportConfig(
                connector_id="burp_dast_xml",
                engagement_id=1001,
            ),
            report_text=report,
        )
        second = import_validation_artifact(
            con,
            ValidationArtifactImportConfig(
                connector_id="burp_dast_xml",
                engagement_id=1001,
            ),
            report_text=report,
        )
        job_count = con.execute("SELECT COUNT(*) FROM active_validation_jobs").fetchone()[0]
        run_count = con.execute("SELECT COUNT(*) FROM active_validation_runs").fetchone()[0]
    finally:
        con.close()

    assert first["persisted_run_count"] == 1
    assert first["duplicate_count"] == 0
    assert second["persisted_run_count"] == 0
    assert second["duplicate_count"] == 1
    assert job_count == 1
    assert run_count == 1


def test_junit_validation_xml_dry_run_writes_nothing(tmp_path: Path) -> None:
    con = _build_validation_db(tmp_path / "engagement.db")
    report = """
    <testsuite name="burp-dast">
      <testcase classname="burp" name="GET https://app.acme.example/login">
        <failure message="Medium: missing header at https://app.acme.example/login?token=secret&amp;ok=1" />
      </testcase>
    </testsuite>
    """

    try:
        result = import_validation_artifact(
            con,
            ValidationArtifactImportConfig(
                connector_id="burp_dast_xml",
                engagement_id=1001,
                dry_run=True,
            ),
            report_text=report,
        )
        job_count = con.execute("SELECT COUNT(*) FROM active_validation_jobs").fetchone()[0]
        run_count = con.execute("SELECT COUNT(*) FROM active_validation_runs").fetchone()[0]
    finally:
        con.close()

    assert result["execution_policy"] == "dry_run_no_validation_evidence_written"
    assert result["parsed_count"] == 1
    assert result["would_persist_count"] == 1
    assert result["persisted_count"] == 0
    assert job_count == 0
    assert run_count == 0


def test_validation_xml_import_rejects_entity_declarations(tmp_path: Path) -> None:
    con = _build_validation_db(tmp_path / "engagement.db")
    try:
        try:
            import_validation_artifact(
                con,
                ValidationArtifactImportConfig(
                    connector_id="burp_dast_xml",
                    engagement_id=1001,
                ),
                report_text="<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo/>",
            )
        except ValueError as exc:
            assert "DOCTYPE/ENTITY" in str(exc)
        else:
            raise AssertionError("unsafe XML was accepted")
    finally:
        con.close()


def test_connector_cli_import_validation_invokes_importer_with_config(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / ".forge_data"
    con = _build_validation_db(data_dir / "engagements" / "1001.db")
    con.close()
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    report_file = tmp_path / "burp.xml"
    report_file.write_text("<issues />", encoding="utf-8")
    captured: dict[str, object] = {}

    def fake_import_validation_artifact(_con, config):
        captured["config"] = config
        return {
            "schema_version": "forge.connector.validation_artifact_import.v1",
            "execution_policy": "dry_run_no_validation_evidence_written",
            "connector_id": config.connector_id,
            "engagement_id": config.engagement_id,
            "target": config.target,
            "status": "completed",
            "parsed_count": 0,
            "persisted_count": 0,
            "persisted_job_count": 0,
            "persisted_run_count": 0,
            "would_persist_count": 0,
            "skipped_count": 0,
            "skipped": [],
            "source": "validation_artifact_import",
            "privacy": "report body omitted",
        }

    monkeypatch.setattr(
        "forge.connectors.cli.import_validation_artifact",
        fake_import_validation_artifact,
    )
    app = typer.Typer()
    connectors_app = typer.Typer()
    register_connector_commands(connectors_app)
    app.add_typer(connectors_app, name="connectors")

    result = CliRunner().invoke(
        app,
        [
            "connectors",
            "import-validation",
            "--engagement",
            "1001",
            "--connector",
            "burp_dast_xml",
            "--report-file",
            str(report_file),
            "--target",
            "https://app.acme.example/",
            "--dry-run",
            "--limit",
            "5",
            "--operator",
            "cli-test",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    config = captured["config"]
    assert isinstance(config, ValidationArtifactImportConfig)
    assert config.connector_id == "burp_dast_xml"
    assert config.engagement_id == 1001
    assert config.report_path == report_file
    assert config.target == "https://app.acme.example/"
    assert config.dry_run is True
    assert config.limit == 5
    assert config.operator == "cli-test"
    assert payload["source"] == "validation_artifact_import"
