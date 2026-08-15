from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import httpx
import typer
from typer.testing import CliRunner

from forge.active_validation.cli import register_active_validation_commands
from forge.active_validation.methods import list_active_validation_methods
from forge.active_validation.runner import (
    active_validation_control_coverage,
    approve_active_validation_job,
    create_active_validation_job,
    preview_active_validation_job,
    run_active_validation_job,
)
from forge.db.migrations import TARGET_VERSION, run_migrations
from forge.db.schema import apply_schema
from forge.db.validation import validate_canonical_schema
from forge.reporting.dashboard import (
    _engagement_detail_payload,
    _engagement_summary,
    _render_engagement_page,
)
from forge.remediation.workflow import request_active_validation_retest


def _build_db(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    apply_schema(con)
    run_migrations(con)
    validate_canonical_schema(con)
    con.execute(
        """
        INSERT INTO engagements (id, name, scope_json, status, operator)
        VALUES (1001, 'Acme Example', '["acme.example"]', 'ACTIVE', 'delta-one')
        """
    )
    con.commit()
    return con


def _install_reachability_http_client(monkeypatch, responses):
    records = {"init_kwargs": [], "requests": []}
    queued_responses = list(responses)

    class _Response:
        def __init__(self, status_code: int, headers: dict[str, str]) -> None:
            self.status_code = status_code
            self.headers = headers

    class _Client:
        def __init__(self, *args, **kwargs) -> None:
            records["init_kwargs"].append(kwargs)

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

        def request(self, method: str, url: str, *, headers=None):
            records["requests"].append(
                {"method": method, "url": url, "headers": dict(headers or {})}
            )
            next_response = queued_responses.pop(0)
            if isinstance(next_response, BaseException):
                raise next_response
            status_code, response_headers = next_response
            return _Response(status_code, response_headers)

    monkeypatch.setattr("forge.active_validation.runner.httpx.Client", _Client)
    return records


def test_active_validation_method_registry_documents_safe_modes() -> None:
    methods = {item["id"]: item for item in list_active_validation_methods()}

    assert {
        "fixture_replay",
        "control_simulation",
        "http_reachability",
        "http_security_headers",
        "fix_verification",
    } <= set(methods)
    assert methods["fixture_replay"]["implemented_modes"] == ["dry_run", "lab"]
    assert methods["fixture_replay"]["safety_profile"] == "non_destructive"
    assert methods["http_reachability"]["implementation_status"] == "implemented_read_only_live"
    assert methods["http_reachability"]["implemented_modes"] == [
        "dry_run",
        "lab",
        "read_only_live",
    ]
    assert "read_only_live" in methods["http_reachability"]["supported_modes"]
    assert "TA0001" in methods["http_reachability"]["attack_mappings"]
    assert methods["http_security_headers"]["implementation_status"] == "implemented_read_only_live"
    assert methods["http_security_headers"]["proof_kind"] == "security_header_observation"
    assert "OWASP Secure Headers" in methods["http_security_headers"]["control_families"]
    assert methods["fix_verification"]["implementation_status"] == "implemented_read_only_live"
    assert methods["fix_verification"]["implemented_modes"] == [
        "dry_run",
        "lab",
        "read_only_live",
    ]
    assert "read_only_live" in methods["fix_verification"]["supported_modes"]


def test_active_validation_migration_adds_v39_tables(tmp_path: Path) -> None:
    con = sqlite3.connect(tmp_path / "legacy.db")
    try:
        con.executescript(
            """
            CREATE TABLE _schema_version (
                version INTEGER NOT NULL,
                applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO _schema_version (version) VALUES (38);

            CREATE TABLE engagements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                scope_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                operator TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )

        run_migrations(con)
        tables = {
            row[0]
            for row in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        version = con.execute("SELECT MAX(version) FROM _schema_version").fetchone()[0]
        job_columns = {
            row[1]
            for row in con.execute("PRAGMA table_info(active_validation_jobs)").fetchall()
        }
    finally:
        con.close()

    assert int(version) == TARGET_VERSION
    assert {"active_validation_jobs", "active_validation_runs"} <= tables
    assert {"approved", "roe_id", "scope_manifest_ref", "safe_profile"} <= job_columns


def test_active_validation_migration_v48_expands_method_constraint(
    tmp_path: Path,
) -> None:
    con = sqlite3.connect(tmp_path / "legacy-v47.db")
    try:
        con.executescript(
            """
            CREATE TABLE _schema_version (
                version INTEGER NOT NULL,
                applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO _schema_version (version) VALUES (47);

            CREATE TABLE engagements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                scope_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                operator TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO engagements (id, name, scope_json, status, operator)
            VALUES (1001, 'Acme Example', '["acme.example"]', 'ACTIVE', 'delta-one');

            CREATE TABLE active_validation_jobs (
                id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id      INTEGER NOT NULL REFERENCES engagements(id),
                target_ref         TEXT    NOT NULL,
                target_kind        TEXT    NOT NULL DEFAULT 'asset'
                                   CHECK (target_kind IN (
                                       'asset',
                                       'host',
                                       'service',
                                       'cloud',
                                       'identity',
                                       'finding',
                                       'fixture',
                                       'other'
                                   )),
                method             TEXT    NOT NULL
                                   CHECK (method IN (
                                       'fixture_replay',
                                       'control_simulation',
                                       'http_reachability',
                                       'fix_verification'
                                   )),
                mode               TEXT    NOT NULL DEFAULT 'dry_run'
                                   CHECK (mode IN ('dry_run','lab','read_only_live')),
                status             TEXT    NOT NULL DEFAULT 'queued'
                                   CHECK (status IN (
                                       'queued',
                                       'approved',
                                       'running',
                                       'completed',
                                       'blocked',
                                       'failed',
                                       'cancelled'
                                   )),
                approved           INTEGER NOT NULL DEFAULT 0 CHECK (approved IN (0,1)),
                roe_id             TEXT    NOT NULL DEFAULT '',
                scope_manifest_ref TEXT    NOT NULL DEFAULT '',
                scope_manifest_hash TEXT   NOT NULL DEFAULT '',
                safe_profile       TEXT    NOT NULL DEFAULT 'non_destructive',
                max_steps          INTEGER NOT NULL DEFAULT 1
                                   CHECK (max_steps >= 1 AND max_steps <= 50),
                requested_by       TEXT    NOT NULL DEFAULT '',
                approved_by        TEXT    NOT NULL DEFAULT '',
                approval_note      TEXT    NOT NULL DEFAULT '',
                metadata_json      TEXT    NOT NULL DEFAULT '{}',
                created_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                approved_at        TIMESTAMP,
                updated_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX idx_active_validation_jobs_engagement
                ON active_validation_jobs (engagement_id, status, mode, updated_at DESC);

            CREATE TABLE active_validation_runs (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL REFERENCES engagements(id),
                job_id        INTEGER NOT NULL REFERENCES active_validation_jobs(id),
                status        TEXT    NOT NULL
                              CHECK (status IN ('running','completed','blocked','failed')),
                result        TEXT    NOT NULL DEFAULT '',
                operator      TEXT    NOT NULL DEFAULT '',
                evidence_json TEXT    NOT NULL DEFAULT '{}',
                error         TEXT    NOT NULL DEFAULT '',
                started_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                completed_at  TIMESTAMP,
                created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX idx_active_validation_runs_job
                ON active_validation_runs (engagement_id, job_id, created_at DESC);

            INSERT INTO active_validation_jobs (
                id, engagement_id, target_ref, target_kind, method, mode,
                status, approved, safe_profile, max_steps, metadata_json
            )
            VALUES (
                1, 1001, 'https://app.acme.example/health', 'service',
                'http_reachability', 'dry_run', 'completed', 0,
                'non_destructive', 1, '{}'
            );
            INSERT INTO active_validation_runs (
                id, engagement_id, job_id, status, result, operator, evidence_json
            )
            VALUES (1, 1001, 1, 'completed', 'planned', 'delta-one', '{}');
            """
        )

        run_migrations(con)
        con.execute(
            """
            INSERT INTO active_validation_jobs (
                engagement_id, target_ref, target_kind, method, mode,
                status, approved, safe_profile, max_steps, metadata_json
            )
            VALUES (
                1001, 'https://app.acme.example/health', 'service',
                'http_security_headers', 'dry_run', 'queued', 0,
                'non_destructive', 1, '{}'
            )
            """
        )
        con.commit()
        version = con.execute("SELECT MAX(version) FROM _schema_version").fetchone()[0]
        job_count = con.execute("SELECT COUNT(*) FROM active_validation_jobs").fetchone()[0]
        run_count = con.execute("SELECT COUNT(*) FROM active_validation_runs").fetchone()[0]
        run_fk_targets = {
            str(row[2])
            for row in con.execute("PRAGMA foreign_key_list(active_validation_runs)").fetchall()
        }
    finally:
        con.close()

    assert int(version) == TARGET_VERSION
    assert job_count == 2
    assert run_count == 1
    assert "active_validation_jobs" in run_fk_targets


def test_active_validation_dry_run_and_lab_jobs_are_offline(tmp_path: Path) -> None:
    con = _build_db(tmp_path / "engagement.db")
    try:
        dry_job = create_active_validation_job(
            con,
            engagement_id=1001,
            target_ref="host:app.acme.example",
            target_kind="host",
            method="http_reachability",
            mode="dry_run",
            requested_by="delta-one",
        )
        dry_run = run_active_validation_job(
            con,
            engagement_id=1001,
            job_id=int(dry_job["id"]),
            operator="delta-one",
        )
        lab_job = create_active_validation_job(
            con,
            engagement_id=1001,
            target_ref="fixture://nodezero-style/safe-proof",
            target_kind="fixture",
            method="fixture_replay",
            mode="lab",
            approved=True,
            requested_by="delta-one",
            approved_by="lead",
        )
        lab_run = run_active_validation_job(
            con,
            engagement_id=1001,
            job_id=int(lab_job["id"]),
            operator="delta-one",
        )
        audit_actions = [
            row["action"]
            for row in con.execute(
                """
                SELECT action
                FROM audit_log
                WHERE engagement_id=1001 AND phase='active_validation'
                ORDER BY id
                """
            ).fetchall()
        ]
    finally:
        con.close()

    assert dry_job["status"] == "queued"
    assert dry_job["method_config"]["id"] == "http_reachability"
    assert dry_job["method_config"]["implementation_status"] == "implemented_read_only_live"
    assert dry_run["status"] == "completed"
    assert dry_run["result"] == "planned"
    assert dry_run["evidence"]["method"]["proof_kind"] == "reachability_observation"
    assert dry_run["evidence"]["network_execution"] is False
    assert dry_run["evidence"]["destructive_actions"] is False
    assert dry_run["evidence"]["gates"] == [
        {"id": "method_supported", "required": True, "status": "passed"},
        {"id": "safe_profile", "required": True, "status": "passed"},
        {"id": "step_budget", "required": True, "status": "bounded"},
        {"id": "approval", "required": False, "status": "not_required"},
    ]
    assert dry_run["evidence"]["budgets"]["live_network_request_budget"] == 0
    assert lab_run["status"] == "completed"
    assert lab_run["result"] == "simulated_pass"
    assert lab_run["evidence"]["fixture"]["target_ref"] == "fixture://nodezero-style/safe-proof"
    assert lab_run["evidence"]["network_execution"] is False
    assert {gate["id"]: gate["status"] for gate in lab_run["evidence"]["gates"]} == {
        "method_supported": "passed",
        "safe_profile": "passed",
        "step_budget": "bounded",
        "approval": "passed",
        "offline_fixture": "passed",
    }
    assert audit_actions == [
        "active_validation_job_create",
        "active_validation_run",
        "active_validation_job_create",
        "active_validation_run",
    ]


def test_active_validation_preview_is_state_free_and_scope_gated(tmp_path: Path) -> None:
    con = _build_db(tmp_path / "engagement.db")
    try:
        before = {
            "jobs": con.execute("SELECT COUNT(*) FROM active_validation_jobs").fetchone()[0],
            "runs": con.execute("SELECT COUNT(*) FROM active_validation_runs").fetchone()[0],
            "audit": con.execute(
                """
                SELECT COUNT(*)
                FROM audit_log
                WHERE engagement_id=1001 AND phase='active_validation'
                """
            ).fetchone()[0],
        }
        dry_preview = preview_active_validation_job(
            engagement_id=1001,
            target_ref="https://app.acme.example/health?token=preview-token&ok=1",
            target_kind="service",
            method="http_reachability",
            mode="dry_run",
            requested_by="delta-one",
            max_steps=7,
            metadata={
                "source": "unit-test",
                "authorization": "Bearer never-render",
                "notes": "see https://app.acme.example/path?secret=never&ok=1",
            },
        )
        target = "https://app.acme.example/health?token=preview-token&ok=1"
        scope_manifest = json.dumps(
            {
                "roe_id": "ROE-1001",
                "authorized_seeds": [target],
            }
        )
        missing_scope_error = ""
        try:
            preview_active_validation_job(
                engagement_id=1001,
                target_ref=target,
                target_kind="service",
                method="http_reachability",
                mode="read_only_live",
                requested_by="delta-one",
                roe_id="ROE-1001",
            )
        except ValueError as exc:
            missing_scope_error = str(exc)
        live_preview = preview_active_validation_job(
            engagement_id=1001,
            target_ref=target,
            target_kind="service",
            method="http_reachability",
            mode="read_only_live",
            approved=True,
            requested_by="delta-one",
            roe_id="ROE-1001",
            scope_manifest_ref=scope_manifest,
        )
        after = {
            "jobs": con.execute("SELECT COUNT(*) FROM active_validation_jobs").fetchone()[0],
            "runs": con.execute("SELECT COUNT(*) FROM active_validation_runs").fetchone()[0],
            "audit": con.execute(
                """
                SELECT COUNT(*)
                FROM audit_log
                WHERE engagement_id=1001 AND phase='active_validation'
                """
            ).fetchone()[0],
        }
    finally:
        con.close()

    assert dry_preview["schema"] == "forge.active_validation.preview.v1"
    assert dry_preview["status"] == "planned"
    assert dry_preview["plan"] == {
        "will_create_job": False,
        "will_create_run": False,
        "will_execute_network": False,
        "will_store_response_body": False,
        "requires_runtime_live_gate": False,
    }
    assert dry_preview["budgets"] == {
        "concurrency": 1,
        "depth": 0,
        "queue_items": 1,
        "max_steps": 7,
        "preview_network_requests": 0,
        "live_network_request_budget": 0,
    }
    assert dry_preview["job"]["target_ref"] == "https://app.acme.example/health?ok=1"
    assert dry_preview["evidence"]["network_execution"] is False
    assert "preview-token" not in json.dumps(dry_preview, sort_keys=True)
    assert "Bearer never-render" not in json.dumps(dry_preview, sort_keys=True)
    assert "secret=never" not in json.dumps(dry_preview, sort_keys=True)
    assert missing_scope_error == "read_only_live preview requires explicit roe_id and scope_manifest."
    assert live_preview["status"] == "planned"
    assert live_preview["job"]["scope_manifest_ref"] == "inline_json"
    assert live_preview["job"]["scope_manifest_hash"].startswith("sha256:")
    gate_status = {gate["id"]: gate["status"] for gate in live_preview["gates"]}
    assert gate_status["approval"] == "passed"
    assert gate_status["scope_manifest"] == "passed"
    assert gate_status["live_gate"] == "required_at_run"
    assert live_preview["plan"]["requires_runtime_live_gate"] is True
    assert live_preview["budgets"]["live_network_request_budget"] == 2
    assert "authorized_seeds" not in json.dumps(live_preview, sort_keys=True)
    assert before == after


def test_active_validation_control_simulation_lab_records_control_outcomes(
    tmp_path: Path,
) -> None:
    con = _build_db(tmp_path / "engagement.db")
    try:
        passed_job = create_active_validation_job(
            con,
            engagement_id=1001,
            target_ref="fixture://edr/command-execution",
            target_kind="fixture",
            method="control_simulation",
            mode="lab",
            approved=True,
            requested_by="delta-one",
            approved_by="lead",
            metadata={
                "expected_control_result": "detected",
                "observed_control_result": "alerted",
                "control_name": "EDR command execution alert",
                "attack_step": "T1059 command execution",
                "detection_source": "local_fixture",
                "detection_signal": "https://siem.acme.example/event?token=never-store&ok=1",
            },
        )
        passed_run = run_active_validation_job(
            con,
            engagement_id=1001,
            job_id=int(passed_job["id"]),
            operator="delta-one",
        )
        failed_job = create_active_validation_job(
            con,
            engagement_id=1001,
            target_ref="fixture://edr/credential-access",
            target_kind="fixture",
            method="control_simulation",
            mode="lab",
            approved=True,
            requested_by="delta-one",
            approved_by="lead",
            metadata={
                "expected_control_result": "blocked",
                "observed_control_result": "allowed",
                "control_name": "Credential access prevention",
                "attack_step": "T1003 credential dumping",
                "detection_source": "local_fixture",
            },
        )
        failed_run = run_active_validation_job(
            con,
            engagement_id=1001,
            job_id=int(failed_job["id"]),
            operator="delta-one",
        )
        coverage = active_validation_control_coverage(con, engagement_id=1001)
    finally:
        con.close()

    payload = json.dumps(
        {"passed": passed_run, "failed": failed_run, "coverage": coverage},
        sort_keys=True,
    )
    passed_control = passed_run["evidence"]["control_validation"]
    failed_control = failed_run["evidence"]["control_validation"]
    assert passed_run["status"] == "completed"
    assert passed_run["result"] == "control_passed"
    assert passed_control["expected_result"] == "detected"
    assert passed_control["observed_result"] == "detected"
    assert passed_control["matched"] is True
    assert "control expected=detected observed=detected matched=yes" in (
        passed_run["evidence"]["proof_summary"]["evidence"]
    )
    assert failed_run["status"] == "completed"
    assert failed_run["result"] == "control_failed"
    assert failed_control["expected_result"] == "blocked"
    assert failed_control["observed_result"] == "allowed"
    assert failed_control["matched"] is False
    assert "control expected=blocked observed=allowed matched=no" in (
        failed_run["evidence"]["proof_summary"]["evidence"]
    )
    controls = {row["id"]: row for row in coverage["control_families"]}
    methods = {row["id"]: row for row in coverage["methods"]}
    assert controls["MITRE ATT&CK control coverage"]["states"] == {
        "failed": 1,
        "passed": 1,
    }
    assert methods["control_simulation"]["states"] == {"failed": 1, "passed": 1}
    assert "network_execution" in passed_run["evidence"]
    assert passed_run["evidence"]["network_execution"] is False
    assert "never-store" not in payload


def test_active_validation_control_coverage_groups_methods_and_states(
    tmp_path: Path,
) -> None:
    con = _build_db(tmp_path / "engagement.db")
    try:
        planned_job = create_active_validation_job(
            con,
            engagement_id=1001,
            target_ref="host:queued.acme.example",
            target_kind="host",
            method="control_simulation",
            mode="dry_run",
            requested_by="delta-one",
        )
        lab_job = create_active_validation_job(
            con,
            engagement_id=1001,
            target_ref="fixture://safe/control",
            target_kind="fixture",
            method="fixture_replay",
            mode="lab",
            approved=True,
            requested_by="delta-one",
            approved_by="lead",
        )
        lab_run = run_active_validation_job(
            con,
            engagement_id=1001,
            job_id=int(lab_job["id"]),
            operator="delta-one",
        )
        blocked_job = create_active_validation_job(
            con,
            engagement_id=1001,
            target_ref="https://app.acme.example/",
            target_kind="service",
            method="http_reachability",
            mode="read_only_live",
            requested_by="delta-one",
        )
        blocked_run = run_active_validation_job(
            con,
            engagement_id=1001,
            job_id=int(blocked_job["id"]),
            operator="delta-one",
            allow_env_live=False,
        )
        failed_job = create_active_validation_job(
            con,
            engagement_id=1001,
            target_ref="https://fixed.acme.example/",
            target_kind="service",
            method="fix_verification",
            mode="read_only_live",
            approved=True,
            requested_by="delta-one",
            approved_by="lead",
            roe_id="ROE-1",
            scope_manifest_ref='{"roe_id":"ROE-1","urls":["https://fixed.acme.example/"]}',
            metadata={"retest_expected_result": "dead"},
        )
        con.execute(
            """
            INSERT INTO active_validation_runs
                (engagement_id, job_id, status, result, operator, evidence_json)
            VALUES (?, ?, 'completed', 'reachable', 'delta-one', ?)
            """,
            (
                1001,
                int(failed_job["id"]),
                json.dumps(
                    {
                        "fix_verification": {
                            "expected_result": "dead",
                            "observed_result": "reachable",
                            "matched": False,
                        }
                    }
                ),
            ),
        )
        con.commit()

        coverage = active_validation_control_coverage(con, engagement_id=1001)
    finally:
        con.close()

    assert planned_job["method"] == "control_simulation"
    assert lab_run["result"] == "simulated_pass"
    assert blocked_run["status"] == "blocked"
    assert coverage["schema"] == "forge.active_validation.coverage.v1"
    assert coverage["summary"]["job_count"] == 4
    assert coverage["summary"]["run_count"] == 3
    assert coverage["summary"]["states"] == {
        "blocked": 1,
        "failed": 1,
        "passed": 1,
        "planned": 1,
    }
    attack = {row["id"]: row for row in coverage["attack_mappings"]}
    controls = {row["id"]: row for row in coverage["control_families"]}
    methods = {row["id"]: row for row in coverage["methods"]}
    assert attack["TA0043"]["states"] == {"blocked": 1, "failed": 1, "passed": 1}
    assert attack["TA0007"]["states"] == {"passed": 1, "planned": 1}
    assert controls["MITRE ATT&CK control coverage"]["states"] == {"planned": 1}
    assert controls["Remediation retest"]["states"] == {"failed": 1}
    assert methods["fix_verification"]["states"] == {"failed": 1}


def test_active_validation_coverage_cli_outputs_json(tmp_path: Path, monkeypatch) -> None:
    data_dir = tmp_path / ".forge_data"
    con = _build_db(data_dir / "engagements" / "1001.db")
    try:
        job = create_active_validation_job(
            con,
            engagement_id=1001,
            target_ref="fixture://coverage/pass",
            target_kind="fixture",
            method="fixture_replay",
            mode="lab",
            approved=True,
            requested_by="delta-one",
            approved_by="lead",
        )
        run_active_validation_job(
            con,
            engagement_id=1001,
            job_id=int(job["id"]),
            operator="delta-one",
        )
    finally:
        con.close()
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))
    app = typer.Typer()
    active_validation_app = typer.Typer()
    register_active_validation_commands(active_validation_app)
    app.add_typer(active_validation_app, name="active-validation")

    result = CliRunner().invoke(
        app,
        ["active-validation", "coverage", "--engagement", "1001", "--json"],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["summary"]["job_count"] == 1
    assert payload["summary"]["states"] == {"passed": 1}
    assert payload["attack_mappings"][0]["methods"] == ["fixture_replay"]


def test_remediation_retest_request_links_active_validation_job_and_safe_lab_pass(
    tmp_path: Path,
) -> None:
    con = _build_db(tmp_path / "engagement.db")
    try:
        con.execute(
            """
            INSERT INTO remediation_items
                (id, engagement_id, finding_table, finding_ref, title, severity,
                 owner, status)
            VALUES
                (10, 1001, 'monitoring_alerts', '42', 'Added exposed VPN', 'HIGH',
                 'appsec', 'assigned')
            """
        )
        con.commit()
        request = request_active_validation_retest(
            con,
            engagement_id=1001,
            remediation_item_id=10,
            operator="appsec",
            target_ref="fixture://proof-packs/vpn-fixed",
            target_kind="fixture",
            method="fix_verification",
            mode="lab",
            approved=True,
            requested_by="appsec",
            approved_by="lead",
        )
        run = run_active_validation_job(
            con,
            engagement_id=1001,
            job_id=int(request["active_validation_job"]["id"]),
            operator="appsec",
        )
        item = con.execute(
            """
            SELECT status, retest_status, retest_requested_at, retested_at, metadata_json
            FROM remediation_items
            WHERE engagement_id=1001 AND id=10
            """
        ).fetchone()
        audit_actions = [
            row["action"]
            for row in con.execute(
                """
                SELECT action
                FROM audit_log
                WHERE engagement_id=1001
                ORDER BY id
                """
            ).fetchall()
        ]
    finally:
        con.close()

    metadata = json.loads(item["metadata_json"])
    retest = metadata["active_validation_retest"]
    assert request["remediation_item"]["retest_status"] == "pending"
    assert request["remediation_item"]["status"] == "retest_pending"
    assert request["active_validation_job"]["metadata"]["source"] == "remediation_retest"
    assert run["status"] == "completed"
    assert run["result"] == "simulated_pass"
    assert run["remediation_retest"]["linked"] is True
    assert item["status"] == "resolved"
    assert item["retest_status"] == "passed"
    assert item["retest_requested_at"]
    assert item["retested_at"]
    assert retest["latest_job_id"] == request["active_validation_job"]["id"]
    assert retest["latest_run_id"] == run["id"]
    assert retest["latest_retest_status"] == "passed"
    assert [entry["job_id"] for entry in retest["jobs"]] == [request["active_validation_job"]["id"]]
    assert [entry["run_id"] for entry in retest["runs"]] == [run["id"]]
    assert "remediation_retest_requested" in audit_actions
    assert "remediation_retest_result" in audit_actions


def test_remediation_retest_live_reachability_fails_closed_when_exposure_remains(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _install_reachability_http_client(monkeypatch, [(200, {"content-type": "text/plain"})])
    con = _build_db(tmp_path / "engagement.db")
    target = "https://vpn.acme.example/health"
    scope_manifest = json.dumps({"roe_id": "ROE-1001", "authorized_seeds": [target]})
    try:
        con.execute(
            """
            INSERT INTO remediation_items
                (id, engagement_id, finding_table, finding_ref, title, severity,
                 owner, status)
            VALUES
                (11, 1001, 'monitoring_alerts', '43', 'Internet reachable VPN', 'HIGH',
                 'netops', 'assigned')
            """
        )
        con.commit()
        request = request_active_validation_retest(
            con,
            engagement_id=1001,
            remediation_item_id=11,
            operator="netops",
            target_ref=target,
            target_kind="service",
            method="http_reachability",
            mode="read_only_live",
            approved=True,
            requested_by="netops",
            approved_by="lead",
            roe_id="ROE-1001",
            scope_manifest_ref=scope_manifest,
        )
        run = run_active_validation_job(
            con,
            engagement_id=1001,
            job_id=int(request["active_validation_job"]["id"]),
            operator="netops",
            allow_live=True,
        )
        item = con.execute(
            """
            SELECT status, retest_status, metadata_json
            FROM remediation_items
            WHERE engagement_id=1001 AND id=11
            """
        ).fetchone()
    finally:
        con.close()

    metadata = json.loads(item["metadata_json"])
    assert run["status"] == "completed"
    assert run["result"] == "reachable"
    assert run["remediation_retest"]["retest_status"] == "failed"
    assert item["status"] == "in_progress"
    assert item["retest_status"] == "failed"
    assert metadata["active_validation_retest"]["latest_result"] == "reachable"


def test_remediation_retest_live_fix_verification_passes_when_target_not_reachable(
    tmp_path: Path,
    monkeypatch,
) -> None:
    records = _install_reachability_http_client(
        monkeypatch,
        [
            httpx.ConnectError(
                "connection refused https://vpn.acme.example/health?token=never-store&view=ok"
            )
        ],
    )
    con = _build_db(tmp_path / "engagement.db")
    target = "https://vpn.acme.example/health?token=never-store&view=ok"
    scope_manifest = json.dumps({"roe_id": "ROE-1001", "authorized_seeds": [target]})
    try:
        con.execute(
            """
            INSERT INTO remediation_items
                (id, engagement_id, finding_table, finding_ref, title, severity,
                 owner, status)
            VALUES
                (12, 1001, 'monitoring_alerts', '44', 'Internet reachable VPN', 'HIGH',
                 'netops', 'assigned')
            """
        )
        con.commit()
        request = request_active_validation_retest(
            con,
            engagement_id=1001,
            remediation_item_id=12,
            operator="netops",
            target_ref=target,
            target_kind="service",
            method="fix_verification",
            mode="read_only_live",
            approved=True,
            requested_by="netops",
            approved_by="lead",
            roe_id="ROE-1001",
            scope_manifest_ref=scope_manifest,
        )
        run = run_active_validation_job(
            con,
            engagement_id=1001,
            job_id=int(request["active_validation_job"]["id"]),
            operator="netops",
            allow_live=True,
        )
        item = con.execute(
            """
            SELECT status, retest_status, metadata_json
            FROM remediation_items
            WHERE engagement_id=1001 AND id=12
            """
        ).fetchone()
    finally:
        con.close()

    metadata = json.loads(item["metadata_json"])
    live = run["evidence"]["live_validation"]
    verification = live["fix_verification"]
    reachability = live["http_reachability"]
    assert run["status"] == "completed"
    assert run["result"] == "not_reachable"
    assert run["remediation_retest"]["retest_status"] == "passed"
    assert item["status"] == "resolved"
    assert item["retest_status"] == "passed"
    assert metadata["active_validation_retest"]["latest_result"] == "not_reachable"
    assert verification == {
        "expected_result": "not_reachable",
        "observed_result": "not_reachable",
        "matched": True,
    }
    assert reachability["request"]["allowed_methods"] == ["HEAD", "GET"]
    assert reachability["request"]["follow_redirects"] is False
    assert reachability["body_captured"] is False
    assert reachability["network_error"]["type"] == "ConnectError"
    assert records["requests"][0]["method"] == "HEAD"
    assert records["init_kwargs"][0]["follow_redirects"] is False
    assert records["init_kwargs"][0]["trust_env"] is False
    assert "never-store" not in json.dumps(run, sort_keys=True)


def test_active_validation_rejects_unsupported_method_mode(tmp_path: Path) -> None:
    con = _build_db(tmp_path / "engagement.db")
    try:
        try:
            create_active_validation_job(
                con,
                engagement_id=1001,
                target_ref="https://app.acme.example/health",
                target_kind="service",
                method="fixture_replay",
                mode="read_only_live",
                requested_by="delta-one",
            )
        except ValueError as exc:
            error = str(exc)
        else:
            error = ""
    finally:
        con.close()

    assert "fixture_replay supports modes: dry_run, lab" in error


def test_active_validation_public_payload_redacts_target_url_userinfo_and_query(
    tmp_path: Path,
) -> None:
    con = _build_db(tmp_path / "engagement.db")
    try:
        job = create_active_validation_job(
            con,
            engagement_id=1001,
            target_ref="https://user:pass@app.acme.example/health?token=never&view=ok",
            target_kind="service",
            method="http_reachability",
            mode="dry_run",
            requested_by="delta-one",
        )
        run = run_active_validation_job(
            con,
            engagement_id=1001,
            job_id=int(job["id"]),
            operator="delta-one",
        )
        audit_targets = [
            row["target"]
            for row in con.execute(
                """
                SELECT target
                FROM audit_log
                WHERE engagement_id=1001 AND phase='active_validation'
                ORDER BY id
                """
            ).fetchall()
        ]
    finally:
        con.close()

    expected = "https://app.acme.example/health?view=ok"
    assert job["target_ref"] == expected
    assert run["evidence"]["job"]["target_ref"] == expected
    assert run["job"]["target_ref"] == expected
    assert audit_targets == [expected, expected]
    assert "user:pass" not in json.dumps(run, sort_keys=True)
    assert "never" not in json.dumps(run, sort_keys=True)


def test_active_validation_graph_scenario_metadata_persists_scrubbed_lineage(
    tmp_path: Path,
) -> None:
    con = _build_db(tmp_path / "engagement.db")
    try:
        job = create_active_validation_job(
            con,
            engagement_id=1001,
            target_ref="cloud:aws:s3:public",
            target_kind="cloud",
            method="control_simulation",
            mode="lab",
            requested_by="delta-one",
            metadata={
                "source": "asset_graph",
                "reason": "restrict_public_sensitive_data_asset",
                "expected_result": "expected_control_blocks_or_alerts",
                "graph": {
                    "path_id": "path:1",
                    "entity_key": "cloud:aws:s3:public",
                    "summary": "https://app.acme.example/path?token=never reaches cloud data",
                    "secret": "do-not-store",
                },
                "token": "never-store",
            },
        )
    finally:
        con.close()

    assert job["metadata"]["source"] == "asset_graph"
    assert job["metadata"]["reason"] == "restrict_public_sensitive_data_asset"
    assert job["metadata"]["expected_result"] == "expected_control_blocks_or_alerts"
    assert job["metadata"]["graph"]["path_id"] == "path:1"
    assert job["metadata"]["graph"]["entity_key"] == "cloud:aws:s3:public"
    blob = json.dumps(job, sort_keys=True)
    assert "token=never" not in blob
    assert "never-store" not in blob
    assert "do-not-store" not in blob
    assert "secret" not in job["metadata"]["graph"]
    assert "token" not in job["metadata"]


def test_active_validation_live_http_reachability_requires_gates_and_records_sanitized_proof(
    tmp_path: Path,
    monkeypatch,
) -> None:
    records = _install_reachability_http_client(
        monkeypatch,
        [
            (
                204,
                {
                    "content-type": "text/plain",
                    "content-length": "0",
                    "location": "https://app.acme.example/next?token=do-not-store&ok=1",
                },
            )
        ],
    )
    con = _build_db(tmp_path / "engagement.db")
    target = "https://app.acme.example/health?token=never-store&view=ready"
    scope_manifest = json.dumps(
        {
            "roe_id": "ROE-1001",
            "authorized_seeds": [target],
        }
    )
    try:
        job = create_active_validation_job(
            con,
            engagement_id=1001,
            target_ref=target,
            target_kind="service",
            method="http_reachability",
            mode="read_only_live",
            requested_by="delta-one",
        )
        blocked_unapproved = run_active_validation_job(
            con,
            engagement_id=1001,
            job_id=int(job["id"]),
            operator="delta-one",
        )
        approved = approve_active_validation_job(
            con,
            engagement_id=1001,
            job_id=int(job["id"]),
            approved_by="lead",
            roe_id="ROE-1001",
            scope_manifest_ref=scope_manifest,
        )
        blocked_disabled = run_active_validation_job(
            con,
            engagement_id=1001,
            job_id=int(job["id"]),
            operator="delta-one",
        )
        blocked_unimplemented = run_active_validation_job(
            con,
            engagement_id=1001,
            job_id=int(job["id"]),
            operator="delta-one",
            allow_live=True,
        )
    finally:
        con.close()

    assert blocked_unapproved["status"] == "blocked"
    assert blocked_unapproved["result"] == "approval_required"
    assert {gate["id"]: gate["status"] for gate in blocked_unapproved["evidence"]["gates"]} == {
        "method_supported": "passed",
        "safe_profile": "passed",
        "step_budget": "bounded",
        "approval": "blocked",
        "roe_id": "blocked",
        "scope_manifest": "blocked",
        "live_gate": "not_evaluated",
    }
    assert blocked_unapproved["evidence"]["budgets"]["live_network_request_budget"] == 0
    assert approved["approved"] is True
    assert approved["scope_manifest_hash"].startswith("sha256:")
    assert blocked_disabled["status"] == "blocked"
    assert blocked_disabled["result"] == "live_disabled"
    assert blocked_disabled["evidence"]["network_execution"] is False
    assert {gate["id"]: gate["status"] for gate in blocked_disabled["evidence"]["gates"]} == {
        "method_supported": "passed",
        "safe_profile": "passed",
        "step_budget": "bounded",
        "approval": "passed",
        "roe_id": "passed",
        "scope_manifest": "passed",
        "live_gate": "blocked",
    }
    assert blocked_disabled["evidence"]["budgets"]["live_network_request_budget"] == 0
    assert blocked_unimplemented["status"] == "completed"
    assert blocked_unimplemented["result"] == "reachable"
    assert blocked_unimplemented["evidence"]["network_execution"] is True
    assert {gate["id"]: gate["status"] for gate in blocked_unimplemented["evidence"]["gates"]} == {
        "method_supported": "passed",
        "safe_profile": "passed",
        "step_budget": "bounded",
        "approval": "passed",
        "roe_id": "passed",
        "scope_manifest": "passed",
        "live_gate": "passed",
    }
    assert blocked_unimplemented["evidence"]["budgets"]["live_network_request_budget"] == 2
    live = blocked_unimplemented["evidence"]["live_validation"]
    assert live["target_url"] == "https://app.acme.example/health?view=ready"
    assert live["request"]["method"] == "HEAD"
    assert live["request"]["follow_redirects"] is False
    assert live["response"]["status_code"] == 204
    assert live["response"]["redirect_location"] == "https://app.acme.example/next?ok=1"
    assert live["body_captured"] is False
    assert records["requests"] == [
        {
            "method": "HEAD",
            "url": target,
            "headers": {
                "Accept": "*/*",
                "User-Agent": "Forge-ActiveValidation/1.0",
            },
        }
    ]
    assert records["init_kwargs"][0]["follow_redirects"] is False
    assert records["init_kwargs"][0]["trust_env"] is False
    assert "never-store" not in json.dumps(blocked_unimplemented, sort_keys=True)
    assert "do-not-store" not in json.dumps(blocked_unimplemented, sort_keys=True)


def test_active_validation_live_http_reachability_blocks_out_of_scope_before_request(
    tmp_path: Path,
    monkeypatch,
) -> None:
    records = _install_reachability_http_client(
        monkeypatch,
        [(200, {"content-type": "text/plain"})],
    )
    con = _build_db(tmp_path / "engagement.db")
    target = "https://outside.acme.example/health?token=never-store&view=ready"
    scope_manifest = json.dumps(
        {
            "roe_id": "ROE-1001",
            "authorized_seeds": ["https://app.acme.example/health"],
        }
    )
    try:
        job = create_active_validation_job(
            con,
            engagement_id=1001,
            target_ref=target,
            target_kind="service",
            method="http_reachability",
            mode="read_only_live",
            approved=True,
            requested_by="delta-one",
            approved_by="lead",
            roe_id="ROE-1001",
            scope_manifest_ref=scope_manifest,
        )
        run = run_active_validation_job(
            con,
            engagement_id=1001,
            job_id=int(job["id"]),
            operator="delta-one",
            allow_live=True,
        )
    finally:
        con.close()

    gates = {gate["id"]: gate for gate in run["evidence"]["gates"]}
    assert run["status"] == "blocked"
    assert run["result"] == "scope_manifest_denied"
    assert run["evidence"]["network_execution"] is False
    assert gates["approval"]["status"] == "passed"
    assert gates["roe_id"]["status"] == "passed"
    assert gates["scope_manifest"]["status"] == "blocked"
    assert gates["scope_manifest"]["reason"] == "scope_manifest_denied"
    assert gates["live_gate"]["status"] == "not_evaluated"
    assert run["evidence"]["budgets"]["live_network_request_budget"] == 0
    assert records["requests"] == []
    assert "never-store" not in json.dumps(run, sort_keys=True)


def test_active_validation_live_http_reachability_uses_range_get_when_head_is_unsupported(
    tmp_path: Path,
    monkeypatch,
) -> None:
    records = _install_reachability_http_client(
        monkeypatch,
        [
            (405, {"content-type": "text/plain"}),
            (200, {"content-type": "text/html", "content-length": "128"}),
        ],
    )
    con = _build_db(tmp_path / "engagement.db")
    scope_manifest = json.dumps(
        {
            "roe_id": "ROE-1001",
            "authorized_seeds": ["https://app.acme.example/health"],
        }
    )
    try:
        job = create_active_validation_job(
            con,
            engagement_id=1001,
            target_ref="https://app.acme.example/health",
            target_kind="service",
            method="http_reachability",
            mode="read_only_live",
            approved=True,
            requested_by="delta-one",
            approved_by="lead",
            roe_id="ROE-1001",
            scope_manifest_ref=scope_manifest,
        )
        run = run_active_validation_job(
            con,
            engagement_id=1001,
            job_id=int(job["id"]),
            operator="delta-one",
            allow_live=True,
        )
    finally:
        con.close()

    assert run["status"] == "completed"
    assert run["result"] == "reachable"
    assert run["evidence"]["live_validation"]["request"]["method"] == "GET"
    assert [item["method"] for item in records["requests"]] == ["HEAD", "GET"]
    assert records["requests"][1]["headers"]["Range"] == "bytes=0-0"


def test_active_validation_live_http_security_headers_observes_headers_without_body(
    tmp_path: Path,
    monkeypatch,
) -> None:
    records = _install_reachability_http_client(
        monkeypatch,
        [
            (
                200,
                {
                    "strict-transport-security": "max-age=31536000; includeSubDomains",
                    "content-security-policy": (
                        "default-src 'self'; frame-ancestors 'none'; "
                        "report-uri https://reports.acme.example/csp?token=never-store"
                    ),
                    "x-content-type-options": "nosniff",
                    "referrer-policy": "no-referrer",
                    "permissions-policy": "geolocation=(), camera=(), microphone=()",
                    "set-cookie": "session=never-store",
                    "location": "https://app.acme.example/next?token=never-store&ok=1",
                },
            )
        ],
    )
    con = _build_db(tmp_path / "engagement.db")
    target = "https://app.acme.example/health?token=never-store&view=ready"
    scope_manifest = json.dumps(
        {
            "roe_id": "ROE-1001",
            "authorized_seeds": [target],
        }
    )
    try:
        job = create_active_validation_job(
            con,
            engagement_id=1001,
            target_ref=target,
            target_kind="service",
            method="http_security_headers",
            mode="read_only_live",
            approved=True,
            requested_by="delta-one",
            approved_by="lead",
            roe_id="ROE-1001",
            scope_manifest_ref=scope_manifest,
        )
        run = run_active_validation_job(
            con,
            engagement_id=1001,
            job_id=int(job["id"]),
            operator="delta-one",
            allow_live=True,
        )
        coverage = active_validation_control_coverage(con, engagement_id=1001)
    finally:
        con.close()

    assert run["status"] == "completed"
    assert run["result"] == "headers_strong"
    assert run["evidence"]["network_execution"] is True
    live = run["evidence"]["live_validation"]
    assert live["target_url"] == "https://app.acme.example/health?view=ready"
    assert live["request"]["method"] == "HEAD"
    assert live["request"]["follow_redirects"] is False
    assert live["response"]["status_code"] == 200
    assert live["response"]["redirect_location"] == "https://app.acme.example/next?ok=1"
    headers = live["security_headers"]
    assert headers["body_captured"] is False
    assert headers["missing"] == []
    assert headers["weak"] == []
    assert "Strict-Transport-Security" in headers["observed"]
    assert "Set-Cookie" not in headers["observed"]
    assert "never-store" not in json.dumps(run, sort_keys=True)
    assert "headers observed=" in run["evidence"]["proof_summary"]["live_proof"]
    assert records["requests"] == [
        {
            "method": "HEAD",
            "url": target,
            "headers": {
                "Accept": "*/*",
                "User-Agent": "Forge-ActiveValidation/1.0",
            },
        }
    ]
    method_rows = {row["id"]: row for row in coverage["methods"]}
    control_rows = {row["id"]: row for row in coverage["control_families"]}
    assert method_rows["http_security_headers"]["states"] == {"passed": 1}
    assert control_rows["HTTP security headers"]["states"] == {"passed": 1}


def test_active_validation_inline_scope_redaction_does_not_overwrite_stored_scope(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _install_reachability_http_client(monkeypatch, [(200, {"content-type": "text/plain"})])
    con = _build_db(tmp_path / "engagement.db")
    scope_manifest = json.dumps(
        {
            "roe_id": "ROE-1001",
            "authorized_seeds": ["https://app.acme.example/health"],
        }
    )
    try:
        job = create_active_validation_job(
            con,
            engagement_id=1001,
            target_ref="https://app.acme.example/health",
            target_kind="service",
            method="http_reachability",
            mode="read_only_live",
            requested_by="delta-one",
            roe_id="ROE-1001",
            scope_manifest_ref=scope_manifest,
        )
        approved = approve_active_validation_job(
            con,
            engagement_id=1001,
            job_id=int(job["id"]),
            approved_by="lead",
        )
        raw_scope = con.execute(
            "SELECT scope_manifest_ref FROM active_validation_jobs WHERE id=?",
            (int(job["id"]),),
        ).fetchone()[0]
        live_run = run_active_validation_job(
            con,
            engagement_id=1001,
            job_id=int(job["id"]),
            operator="delta-one",
            allow_live=True,
        )
    finally:
        con.close()

    assert job["scope_manifest_ref"] == "inline_json"
    assert approved["scope_manifest_ref"] == "inline_json"
    assert str(raw_scope).startswith("{")
    assert live_run["status"] == "completed"
    assert live_run["result"] == "reachable"
    assert live_run["evidence"]["network_execution"] is True


def test_active_validation_cli_create_run_and_list_outputs_json(
    tmp_path: Path,
    monkeypatch,
) -> None:
    data_dir = tmp_path / ".forge_data"
    con = _build_db(data_dir / "engagements" / "1001.db")
    con.close()
    monkeypatch.setenv("FORGE_DATA_DIR", str(data_dir))

    app = typer.Typer()
    active_app = typer.Typer()
    register_active_validation_commands(active_app)
    app.add_typer(active_app, name="active-validation")
    runner = CliRunner()

    preview = runner.invoke(
        app,
        [
            "active-validation",
            "preview",
            "--engagement",
            "1001",
            "--target",
            "https://app.acme.example/health?token=cli-never&ok=1",
            "--target-kind",
            "service",
            "--method",
            "http_reachability",
            "--mode",
            "dry_run",
            "--max-steps",
            "3",
            "--json",
        ],
    )
    assert preview.exit_code == 0, preview.output
    preview_payload = json.loads(preview.output)
    assert preview_payload["status"] == "planned"
    assert preview_payload["plan"]["will_create_job"] is False
    assert preview_payload["job"]["target_ref"] == "https://app.acme.example/health?ok=1"
    assert "cli-never" not in preview.output

    create = runner.invoke(
        app,
        [
            "active-validation",
            "create",
            "--engagement",
            "1001",
            "--target",
            "lab://fixture/http-control",
            "--target-kind",
            "fixture",
            "--method",
            "fixture_replay",
            "--mode",
            "lab",
            "--approve",
            "--approved-by",
            "lead",
            "--json",
        ],
    )
    assert create.exit_code == 0, create.output
    job = json.loads(create.output)
    run = runner.invoke(
        app,
        [
            "active-validation",
            "run",
            "--engagement",
            "1001",
            "--job-id",
            str(job["id"]),
            "--operator",
            "cli-test",
            "--json",
        ],
    )
    listing = runner.invoke(
        app,
        [
            "active-validation",
            "list",
            "--engagement",
            "1001",
            "--json",
        ],
    )

    assert run.exit_code == 0, run.output
    run_payload = json.loads(run.output)
    assert run_payload["status"] == "completed"
    assert run_payload["result"] == "simulated_pass"
    assert listing.exit_code == 0, listing.output
    listed = json.loads(listing.output)
    assert listed["jobs"][0]["status"] == "completed"

    methods = runner.invoke(app, ["active-validation", "methods", "--json"])

    assert methods.exit_code == 0, methods.output
    method_payload = json.loads(methods.output)
    assert method_payload["methods"][0]["safety_profile"] == "non_destructive"
    assert any(item["id"] == "control_simulation" for item in method_payload["methods"])


def test_active_validation_static_dashboard_sections(tmp_path: Path, monkeypatch) -> None:
    records = _install_reachability_http_client(
        monkeypatch,
        [
            (
                302,
                {
                    "content-type": "text/plain",
                    "content-length": "0",
                    "location": (
                        "https://app.acme.example/login?"
                        "token=dashboard-token-never-render&ok=1"
                    ),
                },
            ),
            httpx.ConnectError(
                "could not connect to "
                "https://app.acme.example/fixed?token=dashboard-token-never-render"
            ),
        ],
    )
    data_dir = tmp_path / ".forge_data"
    reports_dir = tmp_path / "reports"
    con = _build_db(data_dir / "engagements" / "1001.db")
    try:
        live_target = "https://app.acme.example/health?token=dashboard-token-never-render"
        fix_target = "https://app.acme.example/fixed?token=dashboard-token-never-render"
        scope_manifest = json.dumps(
            {
                "roe_id": "ROE-1001",
                "authorized_seeds": [live_target, fix_target],
            }
        )
        dry_job = create_active_validation_job(
            con,
            engagement_id=1001,
            target_ref="host:app.acme.example",
            target_kind="host",
            method="http_reachability",
            mode="dry_run",
            requested_by="delta-one",
            metadata={"source": "dashboard-test", "token": "dashboard-token-never-render"},
        )
        run_active_validation_job(
            con,
            engagement_id=1001,
            job_id=int(dry_job["id"]),
            operator="delta-one",
        )
        lab_job = create_active_validation_job(
            con,
            engagement_id=1001,
            target_ref="lab://fixture/fix-verification",
            target_kind="fixture",
            method="fix_verification",
            mode="lab",
            approved=True,
            requested_by="delta-one",
            approved_by="lead",
        )
        run_active_validation_job(
            con,
            engagement_id=1001,
            job_id=int(lab_job["id"]),
            operator="delta-one",
        )
        live_job = create_active_validation_job(
            con,
            engagement_id=1001,
            target_ref=live_target,
            target_kind="service",
            method="http_reachability",
            mode="read_only_live",
            approved=True,
            requested_by="delta-one",
            approved_by="lead",
            roe_id="ROE-1001",
            scope_manifest_ref=scope_manifest,
        )
        run_active_validation_job(
            con,
            engagement_id=1001,
            job_id=int(live_job["id"]),
            operator="delta-one",
            allow_live=True,
        )
        fix_job = create_active_validation_job(
            con,
            engagement_id=1001,
            target_ref=fix_target,
            target_kind="finding",
            method="fix_verification",
            mode="read_only_live",
            approved=True,
            requested_by="delta-one",
            approved_by="lead",
            roe_id="ROE-1001",
            scope_manifest_ref=scope_manifest,
            metadata={"retest_expected_result": "not_reachable"},
        )
        run_active_validation_job(
            con,
            engagement_id=1001,
            job_id=int(fix_job["id"]),
            operator="delta-one",
            allow_live=True,
        )
    finally:
        con.close()

    summary = _engagement_summary(data_dir / "engagements" / "1001.db")
    slug = str(summary["slug"])
    summary.update(
        {
            "audit_files": [],
            "detail_data": f"data/engagements/{slug}.json",
            "detail_route": f"engagements/{slug}/",
            "graph_files": [],
            "graph_summary": {},
            "graph_payload": None,
            "graph_snapshot_at": "",
            "report_files": [],
            "report_history": [],
            "report_summary": None,
        }
    )
    index_path = reports_dir / "dashboard" / "index.html"
    detail_path = (
        reports_dir
        / "dashboard"
        / "engagements"
        / slug
        / "index.html"
    )
    payload = _engagement_detail_payload(summary, index_path)
    detail_html = _render_engagement_page(summary, index_path, detail_path)

    assert payload["counts"]["active_validation_jobs"] == 4
    assert payload["counts"]["active_validation_runs"] == 4
    assert payload["counts"]["active_validation_coverage"] >= 6
    coverage_rows = payload["sections"]["active_validation_coverage"]
    assert any(
        row["Type"] == "ATT&CK"
        and row["Coverage"] == "TA0043"
        and "planned=1" in row["States"]
        and "passed=3" in row["States"]
        for row in coverage_rows
    )
    assert any(
        row["Type"] == "Control"
        and row["Coverage"] == "Remediation retest"
        and "passed=2" in row["States"]
        for row in coverage_rows
    )
    assert any(
        row["Type"] == "Method"
        and row["Coverage"] == "Fix Verification"
        and row["Jobs"] == "2"
        and row["Runs"] == "2"
        for row in coverage_rows
    )
    assert any(
        row["Mode"] in {"dry_run", "lab"}
        for row in payload["sections"]["active_validation_jobs"]
    )
    assert any(
        row["Method Status"] == "implemented_read_only_live"
        for row in payload["sections"]["active_validation_jobs"]
    )
    assert any(
        row["Proof"] == "retest_evidence"
        for row in payload["sections"]["active_validation_jobs"]
    )
    assert any(
        row["Result"] == "simulated_pass"
        for row in payload["sections"]["active_validation_runs"]
    )
    assert any(
        row["Safety"] == "net=no, destructive=no, lateral=no, post-ex=no"
        for row in payload["sections"]["active_validation_runs"]
    )
    assert any(
        row["Live Proof"].startswith("HEAD 302")
        and "redirect=https://app.acme.example/login" in row["Live Proof"]
        and "body=no" in row["Live Proof"]
        for row in payload["sections"]["active_validation_runs"]
    )
    assert any(
        row["Fix Match"] == "expected=not_reachable observed=not_reachable matched=yes"
        for row in payload["sections"]["active_validation_runs"]
    )
    assert any(
        "network_error=ConnectError" in row["Live Proof"]
        for row in payload["sections"]["active_validation_runs"]
    )
    assert any(
        "expected=not_reachable" in row["Evidence"]
        and "network_error=ConnectError" in row["Evidence"]
        for row in payload["sections"]["active_validation_runs"]
    )
    assert [item["method"] for item in records["requests"]] == ["HEAD", "HEAD"]
    assert "Active Validation Coverage" in detail_html
    assert "Remediation retest" in detail_html
    assert "planned=1" in detail_html
    assert "passed=3" in detail_html
    assert "Active Validation Jobs" in detail_html
    assert "Active Validation Runs" in detail_html
    assert "dashboard-token-never-render" not in json.dumps(payload, sort_keys=True)
    assert "dashboard-token-never-render" not in detail_html
