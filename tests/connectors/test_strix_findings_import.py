"""Tests for the Strix findings JSON import connector.

Backlog item: Do Next #18 — ``strix_findings_import`` connector.

Mirrors the Burp DAST XML tests in ``test_validation_import.py`` so the
same acceptance contract applies: scoped evidence persistence, idempotent
re-imports, dry-run writes nothing, out-of-scope rows skipped with a
reason, and no raw secret material survives into stored evidence.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from forge.connectors.cli import register_connector_commands
from forge.connectors.registry import connector_statuses
from forge.connectors.strix_findings import (
    SUPPORTED_STRIX_IMPORT_CONNECTORS,
    StrixFindingsImportConfig,
    import_strix_findings,
    parse_strix_findings_json,
)
from forge.connectors.validation_import import ValidationArtifactImportConfig, import_validation_artifact
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
            'Acme Strix',
            '["acme.example","*.acme.example"]',
            'ACTIVE',
            'connector-test'
        )
        """
    )
    con.commit()
    return con


def _sample_report() -> str:
    return json.dumps(
        {
            "schema": "strix.findings.v1",
            "findings": [
                {
                    "id": "strix-001",
                    "title": "SQL injection in /search",
                    "severity": "critical",
                    "description": "Payload bypassed input validation.",
                    "proof": "payload=' OR 1=1 --; see https://a.acme.example/search?token=secret-never-store&q=1",
                    "cvss_score": 9.2,
                    "owasp_category": "A03:2021 - Injection",
                    "affected_url": "https://api.acme.example/search?token=secret-never-store&q=1",
                    "references": [
                        "https://cwe.mitre.org/data/definitions/89.html",
                        "https://owasp.org/Top10/A03_2021-Injection/",
                    ],
                    "tags": ["sql", "injection", "critical"],
                },
                {
                    "id": "strix-002",
                    "title": "Reflected XSS",
                    "severity": "medium",
                    "description": "Reflected input in /login response.",
                    "proof": "<script>alert(1)</script>",
                    "cvss_score": 5.4,
                    "owasp_category": "A03:2021 - Injection",
                    "affected_url": "https://app.acme.example/login",
                },
                {
                    "id": "strix-outside",
                    "title": "Outside scope finding",
                    "severity": "high",
                    "affected_url": "https://outside.example/admin",
                },
                {
                    "id": "strix-no-url",
                    "title": "No url finding",
                    "severity": "high",
                },
            ],
        }
    )


# ---------------------------------------------------------------------------
# Parser contract
# ---------------------------------------------------------------------------


class TestStrixParser:
    def test_parses_findings_array_and_strips_secret_query_params(self) -> None:
        rows = parse_strix_findings_json(_sample_report())
        # Parser keeps all URL-bearing rows (scope filter runs in the
        # import pipeline, not in the parser). The ``no-url`` row is
        # dropped because ``affected_url`` cannot be normalised.
        assert len(rows) == 3
        titles = {row.title for row in rows}
        assert titles == {
            "SQL injection in /search",
            "Reflected XSS",
            "Outside scope finding",
        }
        # Secret-looking tokens must never survive into stored metadata.
        for row in rows:
            metadata_blob = json.dumps(dict(row.metadata))
            assert "secret-never-store" not in metadata_blob

    def test_bare_array_payload_is_accepted(self) -> None:
        text = json.dumps(
            [
                {"title": "T1", "affected_url": "https://a.example/x", "severity": "low"},
                {"title": "T2", "affected_url": "https://b.example/y", "severity": "info"},
            ]
        )
        rows = parse_strix_findings_json(text)
        assert len(rows) == 2
        assert {r.title for r in rows} == {"T1", "T2"}

    def test_results_alias_key_is_accepted_for_forward_compat(self) -> None:
        text = json.dumps(
            {"results": [{"title": "T", "affected_url": "https://a.example/x", "severity": "low"}]}
        )
        rows = parse_strix_findings_json(text)
        assert len(rows) == 1

    def test_cvss_derives_severity_when_missing(self) -> None:
        text = json.dumps(
            {
                "findings": [
                    {"title": "Crit", "affected_url": "https://a.example/1", "cvss_score": 9.5},
                    {"title": "High", "affected_url": "https://a.example/2", "cvss_score": 7.1},
                    {"title": "Med", "affected_url": "https://a.example/3", "cvss_score": 5.0},
                    {"title": "Low", "affected_url": "https://a.example/4", "cvss_score": 2.0},
                    {"title": "Info", "affected_url": "https://a.example/5", "cvss_score": 0.0},
                ]
            }
        )
        rows = parse_strix_findings_json(text)
        by_title = {r.title: r.severity for r in rows}
        assert by_title == {
            "Crit": "critical",
            "High": "high",
            "Med": "medium",
            "Low": "low",
            "Info": "info",
        }

    def test_cvss_coercion_bounds(self) -> None:
        text = json.dumps(
            {
                "findings": [
                    {"title": "Over", "affected_url": "https://a.example/1", "cvss_score": 15.0},
                    {"title": "Under", "affected_url": "https://a.example/2", "cvss_score": -3.0},
                    {"title": "Bad", "affected_url": "https://a.example/3", "cvss_score": "oops"},
                ]
            }
        )
        rows = parse_strix_findings_json(text)
        by_title = {r.title: dict(r.metadata).get("cvss_score") for r in rows}
        assert by_title["Over"] == 10.0
        assert by_title["Under"] == 0.0
        # "oops" cannot be coerced; metadata filter drops None/empty.
        assert by_title["Bad"] is None

    def test_rejects_non_json_payload(self) -> None:
        with pytest.raises(ValueError):
            parse_strix_findings_json("<not>json</not>")

    def test_duplicate_rows_are_deduped(self) -> None:
        text = json.dumps(
            {
                "findings": [
                    {"title": "Dup", "affected_url": "https://a.example/x", "severity": "low"},
                    {"title": "Dup", "affected_url": "https://a.example/x", "severity": "low"},
                ]
            }
        )
        rows = parse_strix_findings_json(text)
        assert len(rows) == 1


# ---------------------------------------------------------------------------
# Import pipeline
# ---------------------------------------------------------------------------


class TestStrixImport:
    def test_persists_scoped_findings_as_active_validation_evidence(
        self, tmp_path: Path
    ) -> None:
        con = _build_validation_db(tmp_path / "engagement.db")
        try:
            result = import_strix_findings(
                con,
                StrixFindingsImportConfig(
                    connector_id="strix_findings_import",
                    engagement_id=1001,
                    operator="strix-test",
                ),
                report_text=_sample_report(),
            )
            jobs = con.execute(
                """
                SELECT target_ref, target_kind, method, mode, status, metadata_json
                FROM active_validation_jobs
                WHERE engagement_id=1001
                ORDER BY id
                """
            ).fetchall()
            runs = con.execute(
                """
                SELECT status, result, operator, evidence_json
                FROM active_validation_runs
                WHERE engagement_id=1001
                ORDER BY id
                """
            ).fetchall()
            audits = con.execute(
                """
                SELECT module, action, result
                FROM audit_log
                WHERE engagement_id=1001 AND phase='connectors'
                """
            ).fetchall()
        finally:
            con.close()

        assert result["schema_version"] == "forge.connector.strix_findings_import.v1"
        assert result["execution_policy"] == "writes_active_validation_artifact_evidence"
        assert result["connector_id"] == "strix_findings_import"
        assert result["source"] == "strix_findings_import"
        # Parser keeps the 3 URL-bearing rows; the no-url row is dropped.
        # Scope filter keeps 2 (api.acme.example + app.acme.example),
        # ``outside.example`` is skipped with ``target_url_out_of_scope``.
        assert result["parsed_count"] == 3
        assert result["persisted_job_count"] == 2
        assert result["persisted_run_count"] == 2
        assert result["duplicate_count"] == 0
        skipped_reasons = {entry["reason"] for entry in result["skipped"]}
        assert "target_url_out_of_scope" in skipped_reasons

        # Jobs: both share method='fixture_replay', mode='lab'
        assert len(jobs) == 2
        for job in jobs:
            assert job["method"] == "fixture_replay"
            assert job["mode"] == "lab"
            assert job["status"] == "completed"
            metadata = json.loads(job["metadata_json"])
            assert metadata["connector_id"] == "strix_findings_import"
            assert metadata["proof_type"] == "strix_findings_json"
            assert metadata["request_response_captured"] is False

        # Runs: evidence shape matches the Burp pattern.
        assert len(runs) == 2
        blob = json.dumps([dict(run) for run in runs], sort_keys=True)
        assert "secret-never-store" not in blob

        for run in runs:
            evidence = json.loads(run["evidence_json"])
            assert evidence["network_execution"] is False
            # Evidence persistence reuses the active-validation artifact
            # pipeline, so the ``source`` field is the shared pipeline
            # name. ``connector_id`` captures the strix-specific origin.
            assert evidence["source"] == "validation_artifact_import"
            assert evidence["connector_id"] == "strix_findings_import"
            assert evidence["method"] == "fixture_replay"
            assert evidence["proof_type"] == "strix_findings_json"

        # Audit row for the import.
        assert any(audit["module"] == "strix_findings_import" for audit in audits)
        assert any(audit["action"] == "validation_artifact_import" for audit in audits)

    def test_dry_run_writes_nothing(self, tmp_path: Path) -> None:
        con = _build_validation_db(tmp_path / "engagement.db")
        try:
            result = import_strix_findings(
                con,
                StrixFindingsImportConfig(
                    connector_id="strix_findings_import",
                    engagement_id=1001,
                    dry_run=True,
                ),
                report_text=_sample_report(),
            )
            job_count = con.execute(
                "SELECT COUNT(*) FROM active_validation_jobs"
            ).fetchone()[0]
            run_count = con.execute(
                "SELECT COUNT(*) FROM active_validation_runs"
            ).fetchone()[0]
            audit_count = con.execute(
                "SELECT COUNT(*) FROM audit_log WHERE engagement_id=1001 AND phase='connectors'"
            ).fetchone()[0]
        finally:
            con.close()

        assert result["execution_policy"] == "dry_run_no_validation_evidence_written"
        assert result["persisted_count"] == 0
        assert result["would_persist_count"] >= 1
        assert job_count == 0
        assert run_count == 0
        assert audit_count == 0

    def test_import_is_idempotent(self, tmp_path: Path) -> None:
        con = _build_validation_db(tmp_path / "engagement.db")
        text = _sample_report()
        try:
            first = import_strix_findings(
                con,
                StrixFindingsImportConfig(
                    connector_id="strix_findings_import",
                    engagement_id=1001,
                ),
                report_text=text,
            )
            second = import_strix_findings(
                con,
                StrixFindingsImportConfig(
                    connector_id="strix_findings_import",
                    engagement_id=1001,
                ),
                report_text=text,
            )
            job_count = con.execute(
                "SELECT COUNT(*) FROM active_validation_jobs"
            ).fetchone()[0]
            run_count = con.execute(
                "SELECT COUNT(*) FROM active_validation_runs"
            ).fetchone()[0]
        finally:
            con.close()

        assert first["persisted_run_count"] == 2
        assert first["duplicate_count"] == 0
        assert second["persisted_run_count"] == 0
        assert second["duplicate_count"] == 2
        assert job_count == 2
        assert run_count == 2

    def test_target_filter_skips_non_matching_prefix(self, tmp_path: Path) -> None:
        con = _build_validation_db(tmp_path / "engagement.db")
        try:
            result = import_strix_findings(
                con,
                StrixFindingsImportConfig(
                    connector_id="strix_findings_import",
                    engagement_id=1001,
                    target="https://api.acme.example/",
                ),
                report_text=_sample_report(),
            )
        finally:
            con.close()

        assert result["persisted_run_count"] == 1
        reasons = {entry["reason"] for entry in result["skipped"]}
        assert "target_url_not_matched" in reasons

    def test_limit_bounds_selected_count(self, tmp_path: Path) -> None:
        con = _build_validation_db(tmp_path / "engagement.db")
        try:
            result = import_strix_findings(
                con,
                StrixFindingsImportConfig(
                    connector_id="strix_findings_import",
                    engagement_id=1001,
                    limit=1,
                ),
                report_text=_sample_report(),
            )
        finally:
            con.close()

        assert result["selected_count"] == 1
        assert result["omitted_by_limit_count"] >= 1
        assert result["persisted_run_count"] <= 1

    def test_rejects_wrong_connector_id(self, tmp_path: Path) -> None:
        con = _build_validation_db(tmp_path / "engagement.db")
        try:
            with pytest.raises(ValueError):
                import_strix_findings(
                    con,
                    StrixFindingsImportConfig(
                        connector_id="burp_dast_xml",
                        engagement_id=1001,
                    ),
                    report_text=_sample_report(),
                )
        finally:
            con.close()

    def test_rejects_malformed_json(self, tmp_path: Path) -> None:
        con = _build_validation_db(tmp_path / "engagement.db")
        try:
            with pytest.raises(ValueError):
                import_strix_findings(
                    con,
                    StrixFindingsImportConfig(
                        connector_id="strix_findings_import",
                        engagement_id=1001,
                    ),
                    report_text="not-json",
                )
        finally:
            con.close()


# ---------------------------------------------------------------------------
# Dispatch via import_validation_artifact
# ---------------------------------------------------------------------------


class TestValidationDispatch:
    def test_import_validation_artifact_routes_strix_connector_id(
        self, tmp_path: Path
    ) -> None:
        """``import-validation`` CLI delegates to the strix path for JSON."""

        con = _build_validation_db(tmp_path / "engagement.db")
        try:
            result = import_validation_artifact(
                con,
                ValidationArtifactImportConfig(
                    connector_id="strix_findings_import",
                    engagement_id=1001,
                ),
                report_text=_sample_report(),
            )
        finally:
            con.close()

        assert result["schema_version"] == "forge.connector.strix_findings_import.v1"
        assert result["connector_id"] == "strix_findings_import"
        assert result["persisted_run_count"] == 2


# ---------------------------------------------------------------------------
# Catalog registration
# ---------------------------------------------------------------------------


class TestCatalogRegistration:
    def test_connector_appears_in_catalog_with_offline_safety(self) -> None:
        rows = connector_statuses(env={}, which=lambda _n: None, include_paid=True)
        strix = next((row for row in rows if row["id"] == "strix_findings_import"), None)
        assert strix is not None
        assert strix["domain"] == "validation"
        assert strix["cost_profile"] == "free_local"
        assert strix["safety"] == "passive_offline"
        assert strix["execution_paths"] == ["forge connectors import-validation"]
        assert "active_validation_jobs" in strix["outputs"]
        assert "active_validation_runs" in strix["outputs"]
        assert "strix_findings_json" in strix["input_formats"]

    def test_supported_strix_connectors_constant_is_stable(self) -> None:
        assert SUPPORTED_STRIX_IMPORT_CONNECTORS == ("strix_findings_import",)


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


class TestCliIntegration:
    def test_connector_cli_import_validation_routes_strix_connector(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        data_dir = tmp_path / ".forge_data"
        con = _build_validation_db(data_dir / "engagements" / "1001.db")
        con.close()
        monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
        report_file = tmp_path / "strix.json"
        report_file.write_text(_sample_report(), encoding="utf-8")

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
                "strix_findings_import",
                "--report-file",
                str(report_file),
                "--dry-run",
                "--json",
            ],
        )

        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout.strip().splitlines()[-1])
        assert payload["schema_version"] == "forge.connector.strix_findings_import.v1"
        assert payload["connector_id"] == "strix_findings_import"
        assert payload["execution_policy"] == "dry_run_no_validation_evidence_written"
